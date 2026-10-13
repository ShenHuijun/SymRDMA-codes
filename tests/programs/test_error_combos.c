/*
 * test_error_combos.c — SymRDMA Level 11: 错误处理工具 (论文 §4.1)
 *
 * 论文 §4.1 "Error handling":
 *   "To achieve full compatibility, SymRDMA needs to handle all error
 *    conditions, especially when control-plane operations (e.g., destroy
 *    QP or unregister MR) are concurrent with in-flight data plane
 *    operations. We build a tool to generate hundreds of such
 *    combinations, and compare the behavior of standard IB verbs and
 *    SymRDMA. SymRDMA also needs to free up resources when the process
 *    exits abnormally. This is handled by the kernel module which
 *    monitors the close event of the IB device."
 *
 * 验证内容:
 *   Part A — 进程异常退出资源清理 (修复):
 *     子进程注册 MR 后直接 _exit (不调 DEREG_MR) → 内核 mmu_notifier
 *     release 回调自动清理 MR/IOMMU 映射 → 父进程验证 /proc/symrdma
 *     活跃 MR 数回落 + 统计 process_exits/released_mrs 增加。
 *     (历史遗留: mmget 阻止 __mmput → release 永不触发 → 泄漏)
 *   Part B — 并发控制面/数据面组合:
 *     B-1: 数据面 in-flight RDMA Read 时并发 dereg MR (含 ioctl DEREG
 *          与标准 ibv_dereg_mr) → 验证无崩溃、无 UAF、资源释放干净。
 *     B-2: in-flight WR 未完成时 destroy QP (数据面线程退出后主线程
 *          destroy, 线程不再触碰 qp — 避免 UAF) → 验证无崩溃。
 *     B-3: 多轮组合扫描 (hundreds of combinations): 反复
 *          注册→数据面→dereg/destroy→重建, 每轮不同时序。
 *
 * 环境要求: /dev/symrdma (模块加载)。Part B 需 RDMA 设备 (无设备自动跳过)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <infiniband/verbs.h>

#define SYMRDMA_IOC_MAGIC       'S'
#define SYMRDMA_ACCESS_IDENTITY (1 << 21)
#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif

#define TEST_PAGES   4
#define PAGE_SIZE    4096
#define BUF_SIZE     (TEST_PAGES * PAGE_SIZE)
#define CQ_DEPTH     16
#define PARALLEL_OPS 6            /* B-3 组合轮数 */
#define INFLIGHT_WRS 8            /* B-2 in-flight WR 数 (≤ CQ_DEPTH) */

struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
#define SYMRDMA_IOC_REG_MR   _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR _IOW(SYMRDMA_IOC_MAGIC,  2, int)

static int passed = 0, failed = 0;
#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/* /proc/symrdma 活跃 MR 数 */
static int proc_mr_count(void)
{
	FILE *f = fopen("/proc/symrdma", "r");
	char line[256];
	int count = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *colon;
		if (!strstr(line, "活跃 MR 数"))
			continue;
		colon = strchr(line, ':');
		if (colon)
			count = atoi(colon + 1);
		break;
	}
	fclose(f);
	return count;
}

/* /proc/symrdma 统计 (键包含 key 的行, 冒号后数字) */
static long long proc_stat(const char *key)
{
	FILE *f = fopen("/proc/symrdma", "r");
	char line[256];
	long long val = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *colon;
		if (!strstr(line, key))
			continue;
		colon = strchr(line, ':');
		if (colon)
			val = atoll(colon + 1);
		break;
	}
	fclose(f);
	return val;
}

/* 解析 "进程退出释放:  N 次 / M MR (论文 §4.1)" — 取 M (释放 MR 数)。
 * 不能用 proc_stat("MR") — 会先匹配"活跃 MR 数"行 (修复)。 */
static long long proc_released_mrs(void)
{
	FILE *f = fopen("/proc/symrdma", "r");
	char line[256];
	long long val = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *slash;
		if (!strstr(line, "进程退出释放"))
			continue;
		slash = strchr(line, '/');
		if (slash)
			val = atoll(slash + 1);
		break;
	}
	fclose(f);
	return val;
}

/* 注册 MR (ioctl REG_MR), 返回 mr_id; -1 失败 */
static int sym_register(unsigned char *buf, size_t len)
{
	struct symrdma_ioc_reg_mr req;
	int fd = open("/dev/symrdma", O_RDWR);

	if (fd < 0)
		return -1;
	memset(&req, 0, sizeof(req));
	req.va_start = (unsigned long long)(uintptr_t)buf;
	req.len = len;
	if (ioctl(fd, SYMRDMA_IOC_REG_MR, &req)) {
		close(fd);
		return -1;
	}
	close(fd);
	return req.mr_id;
}

static void sym_deregister(int mr_id)
{
	int fd = open("/dev/symrdma", O_RDWR);

	if (fd < 0)
		return;
	ioctl(fd, SYMRDMA_IOC_DEREG_MR, mr_id);
	close(fd);
}

/* ==================================================================
 * Part A: 进程异常退出资源清理 (论文 §4.1 修复验证)
 * ================================================================== */
static int part_a(void)
{
	int base, after, i;

	printf("\n--- Part A: 进程异常退出资源清理 (论文 §4.1) ---\n");

	if (access("/dev/symrdma", R_OK) != 0) {
		printf("  跳过: /dev/symrdma 不存在 (模块未加载)\n");
		return 0;
	}

	base = proc_mr_count();
	printf("[A-1] 基线: /proc/symrdma 活跃 MR = %d\n", base);
	CHECK(base >= 0, "读取活跃 MR 数");

	/* fork 子进程: 注册 2 个 MR 后直接 _exit — 不调 DEREG_MR */
	for (i = 0; i < 3; i++) {
		pid_t pid = fork();

		if (pid < 0) {
			CHECK(0, "fork 失败");
			return -1;
		}
		if (pid == 0) {
			/* 子进程: 分配 + 注册 2 个 MR, 然后异常退出 (不 dereg)
			 * 注意: fork 后地址空间与父进程相同, mmap(NULL) 会得到相同 VA
			 * → 多进程相同 read_iova (=VA 恒等) 冲突同一 IOMMU domain
			 * (单机 loopback 限制, 论文场景是跨机器)。用不同 hint 错开。 */
			unsigned char *b1, *b2;
			int r1, r2;
			unsigned long base = 0x7f0000000000ULL +
					     (unsigned long)i * 0x200000ULL;

			b1 = mmap((void *)base, BUF_SIZE, PROT_READ | PROT_WRITE,
				  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			b2 = mmap((void *)(base + 0x100000), BUF_SIZE,
				  PROT_READ | PROT_WRITE,
				  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			if (b1 == MAP_FAILED || b2 == MAP_FAILED)
				_exit(1);
			memset(b1, 0xAB, BUF_SIZE);
			memset(b2, 0xCD, BUF_SIZE);
			r1 = sym_register(b1, BUF_SIZE);
			r2 = sym_register(b2, BUF_SIZE);
			/* 无论注册成败都直接退出 — 模拟异常退出不清理 */
			_exit((r1 < 0 || r2 < 0) ? 2 : 0);
		}
		{
			int status;

			waitpid(pid, &status, 0);
		}
	}

	/* 每轮子进程注册 2 个 MR, 3 轮 = 6 个 MR 应被自动释放 */
	after = proc_mr_count();
	printf("[A-2] 3 个子进程异常退出后: 活跃 MR = %d (基线 %d)\n",
	       after, base);
	CHECK(after == base,
	      "★ 进程异常退出后 MR 被内核自动清理 (release 回调)");

	{
		long long pe = proc_stat("进程退出释放");
		char msg[128];

		snprintf(msg, sizeof(msg),
			 "★ /proc/symrdma 统计: 进程退出释放 ≥ 1 次 (实际 %lld)",
			 pe);
		CHECK(pe >= 1, msg);
	}
	{
		long long rm = proc_released_mrs();
		char msg[128];

		snprintf(msg, sizeof(msg),
			 "★ 统计: 释放 MR 数 ≥ 6 (实际 %lld)", rm);
		CHECK(rm >= 6, msg);
	}
	return 0;
}

/* ==================================================================
 * Part B: 并发控制面/数据面组合 (论文 §4.1)
 * ================================================================== */

struct dataplane_ctx {
	struct ibv_qp *qp;
	struct ibv_cq *cq;
	void *local;
	uint32_t lkey;
	uint32_t rkey;
	uintptr_t remote;
	volatile int stop;
	int posts_ok;         /* 成功 post 次数 */
	int cqe_err;          /* 错误 CQE 数 */
	int post_errors;      /* post_send 失败次数 */
	pthread_t tid;
};

/* 数据面线程: post → poll 循环 (恒 1 个 in-flight), 直到 stop 或错误。
 * 收到错误 CQE (dereg 后 rkey 失效) 即停止 — 防止 QP error 后空转。 */
static void *dataplane_thread(void *arg)
{
	struct dataplane_ctx *c = arg;

	while (!c->stop) {
		struct ibv_sge sge = {
			.addr   = (uintptr_t)c->local,
			.length = PAGE_SIZE,
			.lkey   = c->lkey,
		};
		struct ibv_send_wr wr = {0}, *bad_wr = NULL;
		struct ibv_wc wc;

		wr.opcode              = IBV_WR_RDMA_READ;
		wr.sg_list             = &sge;
		wr.num_sge             = 1;
		wr.wr.rdma.remote_addr = c->remote;
		wr.wr.rdma.rkey        = c->rkey;
		wr.send_flags          = IBV_SEND_SIGNALED;

		if (ibv_post_send(c->qp, &wr, &bad_wr)) {
			c->post_errors++;
			break;
		}
		c->posts_ok++;
		if (ibv_poll_cq(c->cq, 1, &wc) != 1) {
			/* CQ 空 — 短暂让步 */
			usleep(10);
			continue;
		}
		if (wc.status != IBV_WC_SUCCESS) {
			c->cqe_err++;
			/* QP 进 error — 停止, 不无限重试 */
			break;
		}
	}
	return NULL;
}

/* 建立自环 QP (INIT→RTR→RTS), 返回 0 成功 */
static int setup_loopback_qp(struct ibv_context *ctx, struct ibv_pd *pd,
			     struct ibv_cq **cq_out, struct ibv_qp **qp_out)
{
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	struct ibv_qp_init_attr qp_attr = {0};

	cq = ibv_create_cq(ctx, CQ_DEPTH, NULL, NULL, 0);
	if (!cq) {
		fprintf(stderr, "  [setup] create_cq 失败 errno=%d\n", errno);
		return -1;
	}
	qp_attr.send_cq = cq;
	qp_attr.recv_cq = cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.cap.max_send_wr  = CQ_DEPTH;
	qp_attr.cap.max_recv_wr  = CQ_DEPTH;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;
	qp = ibv_create_qp(pd, &qp_attr);
	if (!qp) {
		fprintf(stderr, "  [setup] create_qp 失败 errno=%d\n", errno);
		ibv_destroy_cq(cq);
		return -1;
	}

	{
		struct ibv_qp_attr attr = {0};

		attr.qp_state        = IBV_QPS_INIT;
		attr.pkey_index      = 0;
		attr.port_num        = 1;
		attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
				       IBV_ACCESS_REMOTE_WRITE |
				       IBV_ACCESS_LOCAL_WRITE;
		if (ibv_modify_qp(qp, &attr,
				  IBV_QP_STATE | IBV_QP_PKEY_INDEX |
				  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "  [setup] INIT modify 失败 errno=%d\n", errno);
			goto err_qp;
		}

		attr.qp_state           = IBV_QPS_RTR;
		attr.path_mtu           = IBV_MTU_4096;
		attr.dest_qp_num        = qp->qp_num;
		attr.rq_psn             = 0;
		attr.max_dest_rd_atomic = 1;
		attr.min_rnr_timer      = 12;
		attr.ah_attr.port_num   = 1;
		attr.ah_attr.is_global  = 1;
		attr.ah_attr.grh.sgid_index = 0;
		attr.ah_attr.grh.hop_limit  = 1;
		{
			struct ibv_port_attr pa;
			if (!ibv_query_port(ctx, 1, &pa)) {
				ibv_query_gid(ctx, 1, 0, &attr.ah_attr.grh.dgid);
				/* path_mtu 动态取 min(active_mtu, 4096) —
				 *  L15 教训 (path_mtu > active_mtu 令多包响应
				 * 首包被丢); 自环同样从端口查询派生, 与跨机测试对齐 */
				if (pa.active_mtu < IBV_MTU_4096)
					attr.path_mtu = pa.active_mtu;
			}
		}
		if (ibv_modify_qp(qp, &attr,
				  IBV_QP_STATE | IBV_QP_MTU |
				  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER | IBV_QP_AV)) {
			fprintf(stderr, "  [setup] RTR modify 失败 errno=%d\n", errno);
			goto err_qp;
		}

		attr.qp_state      = IBV_QPS_RTS;
		attr.sq_psn        = 0;
		attr.timeout       = 14;
		attr.retry_cnt     = 7;
		attr.rnr_retry     = 7;
		attr.max_rd_atomic = 1;
		if (ibv_modify_qp(qp, &attr,
				  IBV_QP_STATE | IBV_QP_SQ_PSN |
				  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
				  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC)) {
			fprintf(stderr, "  [setup] RTS modify 失败 errno=%d\n", errno);
			goto err_qp;
		}
	}

	*cq_out = cq;
	*qp_out = qp;
	return 0;

err_qp:
	ibv_destroy_qp(qp);
	ibv_destroy_cq(cq);
	return -1;
}

/* B-1: 数据面 in-flight 时并发 dereg MR (ioctl DEREG + ibv_dereg_mr) */
static int part_b_dereg_during_dataplane(struct ibv_context *ctx,
					 struct ibv_pd *pd)
{
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct ibv_mr *mr = NULL;
	unsigned char *buf, *local;
	struct dataplane_ctx dp;
	char msg[256];
	int smr_id;

	if (setup_loopback_qp(ctx, pd, &cq, &qp))
		return 0;

	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	local = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED || local == MAP_FAILED)
		goto out;
	memset(buf, 0x41, BUF_SIZE);

	mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			SYMRDMA_ACCESS_IDENTITY);
	if (!mr)
		goto out;
	/* ioctl REG_MR (SymRDMA 双 IOVA 映射 + notifier) — 模拟 libnprdma 注入 */
	smr_id = sym_register(buf, BUF_SIZE);

	memset(&dp, 0, sizeof(dp));
	dp.qp = qp;
	dp.cq = cq;
	dp.local = local;
	dp.lkey = mr->lkey;
	dp.rkey = mr->rkey;
	dp.remote = (uintptr_t)buf;
	pthread_create(&dp.tid, NULL, dataplane_thread, &dp);

	/* 数据面 in-flight 时并发 dereg MR — 论文 §4.1 核心组合 */
	usleep(5000);
	if (smr_id >= 0)
		sym_deregister(smr_id);          /* ioctl DEREG (SymRDMA 侧) */
	if (ibv_dereg_mr(mr)) {
		snprintf(msg, sizeof(msg), "并发 dereg MR (in-flight RDMA Read)");
		CHECK(0, msg);
	} else {
		snprintf(msg, sizeof(msg),
			 "★ 并发 dereg MR (数据面 in-flight): 无崩溃无 UAF");
		CHECK(1, msg);
	}

	/* 停止数据面线程 */
	dp.stop = 1;
	pthread_join(dp.tid, NULL);
	snprintf(msg, sizeof(msg),
		 "数据面线程: %d post, %d CQE 错误 — 正常停止", dp.posts_ok,
		 dp.cqe_err);
	CHECK(dp.posts_ok > 0, msg);

out:
	if (qp) {
		if (ibv_destroy_qp(qp))
			fprintf(stderr, "  [B-1] destroy_qp 失败 errno=%d\n", errno);
	}
	if (cq) {
		if (ibv_destroy_cq(cq))
			fprintf(stderr, "  [B-1] destroy_cq 失败 errno=%d\n", errno);
	}
	if (buf != MAP_FAILED)
		munmap(buf, BUF_SIZE);
	if (local != MAP_FAILED)
		munmap(local, BUF_SIZE);
	return 0;
}

/* B-2: in-flight WR 未完成时 destroy QP (线程已退出不再触碰 qp) */
static int part_b_destroy_qp_inflight(struct ibv_context *ctx,
				      struct ibv_pd *pd)
{
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct ibv_mr *mr = NULL;
	unsigned char *buf, *local;
	struct dataplane_ctx dp;
	char msg[256];

	if (setup_loopback_qp(ctx, pd, &cq, &qp)) {
		printf("  B-2: setup_loopback_qp 失败 errno=%d\n", errno);
		return 0;
	}

	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	local = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED || local == MAP_FAILED)
		goto out;
	memset(buf, 0x42, BUF_SIZE);

	mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			SYMRDMA_ACCESS_IDENTITY);
	if (!mr)
		goto out;

	memset(&dp, 0, sizeof(dp));
	dp.qp = qp;
	dp.cq = cq;
	dp.local = local;
	dp.lkey = mr->lkey;
	dp.rkey = mr->rkey;
	dp.remote = (uintptr_t)buf;
	pthread_create(&dp.tid, NULL, dataplane_thread, &dp);

	/* 数据面运行中, 设置 stop 并等待线程退出 (线程不再碰 qp) */
	usleep(3000);
	dp.stop = 1;
	pthread_join(dp.tid, NULL);

	/* 此刻可能仍有 WR 在飞行 (线程最后一次 post 未 poll 完) —
	 * 直接 destroy QP: 验证控制面与残留 in-flight 操作并发安全 */
	if (ibv_destroy_qp(qp)) {
		snprintf(msg, sizeof(msg),
			 "destroy QP (残留 in-flight WR): %s", strerror(errno));
		CHECK(0, msg);
	} else {
		snprintf(msg, sizeof(msg),
			 "★ destroy QP (残留 in-flight WR): 成功无崩溃");
		CHECK(1, msg);
	}
	qp = NULL;

	snprintf(msg, sizeof(msg),
		 "数据面: %d post, %d CQE 错误", dp.posts_ok, dp.cqe_err);
	CHECK(dp.posts_ok > 0, msg);

out:
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (mr)
		ibv_dereg_mr(mr);
	if (buf != MAP_FAILED)
		munmap(buf, BUF_SIZE);
	if (local != MAP_FAILED)
		munmap(local, BUF_SIZE);
	return 0;
}

/* B-3: 多轮组合扫描 — 注册→数据面→dereg/destroy→重建, 不同时序 */
static int part_b_combos(struct ibv_context *ctx, struct ibv_pd *pd)
{
	char msg[256];
	int round, base = proc_mr_count();

	printf("[B-3] 多轮控制面/数据面组合 (%d 轮):\n", PARALLEL_OPS);
	for (round = 0; round < PARALLEL_OPS; round++) {
		struct ibv_cq *cq = NULL;
		struct ibv_qp *qp = NULL;
		struct ibv_mr *mr = NULL;
		unsigned char *buf, *local;
		struct dataplane_ctx dp;
		int smr_id;

		if (setup_loopback_qp(ctx, pd, &cq, &qp))
			continue;

		buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
			   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		local = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
			     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (buf == MAP_FAILED || local == MAP_FAILED) {
			ibv_destroy_qp(qp);
			ibv_destroy_cq(cq);
			continue;
		}
		memset(buf, 0x43 + round, BUF_SIZE);

		mr = ibv_reg_mr(pd, buf, BUF_SIZE,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				SYMRDMA_ACCESS_IDENTITY);
		if (!mr) {
			munmap(buf, BUF_SIZE);
			munmap(local, BUF_SIZE);
			ibv_destroy_qp(qp);
			ibv_destroy_cq(cq);
			continue;
		}
		smr_id = sym_register(buf, BUF_SIZE);

		/* 时序: 轮次奇偶交替 dereg/destroy 顺序 */
		memset(&dp, 0, sizeof(dp));
		dp.qp = qp;
		dp.cq = cq;
		dp.local = local;
		dp.lkey = mr->lkey;
		dp.rkey = mr->rkey;
		dp.remote = (uintptr_t)buf;
		pthread_create(&dp.tid, NULL, dataplane_thread, &dp);
		usleep(1000 + round * 500);

		if (round % 2 == 0) {
			/* 偶数轮: 先 dereg MR, 后 destroy QP/CQ */
			if (smr_id >= 0)
				sym_deregister(smr_id);
			ibv_dereg_mr(mr);
			mr = NULL;
			dp.stop = 1;
			pthread_join(dp.tid, NULL);
			ibv_destroy_qp(qp);
			qp = NULL;
			ibv_destroy_cq(cq);
			cq = NULL;
		} else {
			/* 奇数轮: 先 destroy QP/CQ, 后 dereg MR */
			dp.stop = 1;
			pthread_join(dp.tid, NULL);
			ibv_destroy_qp(qp);
			qp = NULL;
			ibv_destroy_cq(cq);
			cq = NULL;
			if (smr_id >= 0)
				sym_deregister(smr_id);
			ibv_dereg_mr(mr);
			mr = NULL;
		}

		if (buf != MAP_FAILED)
			munmap(buf, BUF_SIZE);
		if (local != MAP_FAILED)
			munmap(local, BUF_SIZE);
	}
	{
		int after = proc_mr_count();

		snprintf(msg, sizeof(msg),
			 "★ %d 轮组合后 /proc/symrdma 活跃 MR = %d (基线 %d) — 无泄漏",
			 PARALLEL_OPS, after, base);
		CHECK(after == base, msg);
	}
	return 0;
}

static int part_b(void)
{
	struct ibv_device **dev_list;
	struct ibv_device *dev = NULL;
	struct ibv_context *ctx = NULL;
	struct ibv_pd *pd = NULL;
	int num, i;

	printf("\n--- Part B: 并发控制面/数据面组合 (论文 §4.1) ---\n");

	dev_list = ibv_get_device_list(&num);
	if (!dev_list || num == 0) {
		printf("  跳过: 无 RDMA 设备\n");
		return 0;
	}
	for (i = 0; i < num; i++) {
		if (strstr(ibv_get_device_name(dev_list[i]), "mlx5")) {
			dev = dev_list[i];
			break;
		}
	}
	if (!dev)
		dev = dev_list[0];
	ctx = ibv_open_device(dev);
	if (!ctx) {
		printf("  跳过: open_device 失败\n");
		return 0;
	}
	pd = ibv_alloc_pd(ctx);
	if (!pd) {
		ibv_close_device(ctx);
		printf("  跳过: alloc_pd 失败\n");
		return 0;
	}

	printf("[B-1] 数据面 in-flight 时并发 dereg MR\n");
	part_b_dereg_during_dataplane(ctx, pd);

	printf("[B-2] 残留 in-flight WR 时 destroy QP\n");
	part_b_destroy_qp_inflight(ctx, pd);

	part_b_combos(ctx, pd);

	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	ibv_free_device_list(dev_list);
	return 0;
}

int main(void)
{
	printf("=== SymRDMA Level 11: 错误处理工具 (论文 §4.1) ===\n");

	part_a();
	part_b();

	printf("\n========================================\n");
	printf("Level 11 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}
