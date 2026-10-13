/*
 * test_race_stress.c — SymRDMA Level 14: 并发缺页竞态压测 (论文 §3.1 Host-Remote Race)
 *
 * 动机 (TESTING §7.4 缺口 #1): 既有套件对 "换出/换入与在飞 RDMA 操作并发"
 * 仅有单线程顺序覆盖 (L4/L5/L9), 论文核心卖点 "transparently and
 * efficiently handling race conditions on unpinned memory" 缺并发压测。
 *
 * 设计 (单进程多线程, 忠实复现 Host-Remote Race 的对抗结构):
 *   - 数据页分区: [0,NREAD) 只读验证页 / [NREAD,NPAGES) 写者专属页
 *   - reader × NREADER:  随机选只读页 → symrdma_read_p(4KB 哨兵路径;
 *     v0.25.0: recv 页在飞 pin 屏障) → 全 4KB 逐字与页模式比对 —
 *     任何不一致 = 数据损坏 (FAIL)
 *   - writer × NWRITER:  随机选写页 → 填充带序号新模式 → symrdma_write_p
 *     (写验证路径, 论文图 5b; src/recv 页在飞 pin) → symrdma_read_p 回读 →
 *     逐字比对 — 检测静默丢写 / 哨兵泄漏 / 部分写
 *   - swapper × 1:  循环随机 madvise(MADV_PAGEOUT) + 随机 touch 换入 —
 *     与 reader/writer 的在飞 DMA 全程对抗 (换出→哨兵→REPAIR→换入→重映射)
 *
 * 判定: 数据损坏 > 0 → FAIL (rc=1); EAGAIN (重试耗尽) 仅计数不算失败
 * (论文允许乐观重试耗尽报错), 但报告比率供评估。
 *
 * 用法: test_race_stress [秒数=10] [op字节数=4096]
 *   op ≤ 4096: 哨兵路径; > 4096: seqlock 路径 (写侧 >4KB 依赖
 *   flush-before-unmap 屏障, 该竞态为已知遗留, 大
 *   尺寸属实验性, 默认 4096 即已知良好路径)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <infiniband/verbs.h>

#include "../lib/libsymrdma.h"

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
/* 旧版 verbs 标志名兼容 (同 L9) */
#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif

#define NPAGES     64
#define NREAD      48          /* [0,48) 只读验证页 */
#define NWRITER_P  (NPAGES - NREAD)   /* [48,64) 写者页 */
#define NREADER    2
#define NWRITER    1
#define NTHREAD    (NREADER + NWRITER)
#define CQ_DEPTH   16
#define DEFAULT_SEC 10
#define DEFAULT_OP  4096

static const char *role_name[] = { "reader", "writer" };

struct thread_arg {
	int idx;                    /* 线程编号 */
	int role;                   /* 0=reader 1=writer */
	struct symrdma_ctx *ctx;
	struct ibv_context *ibctx;
	struct ibv_pd *pd;
	unsigned char *buf;         /* 共享数据区 */
	struct symrdma_mr *smr;     /* 共享 SymRDMA MR (本地) */
	struct symrdma_mr_write *wmr;   /* 共享写区 MR */
	size_t op;                  /* 单操作字节数 */

	struct ibv_cq *cq;
	struct ibv_qp *qp;
	unsigned char *recv;        /* 本线程接收 buffer (DMA 目标) */
	struct ibv_mr *recv_mr;
	int recv_mr_id;
	struct symrdma_mr recv_lmr; /* v0.25.0: recv 的本地 MR 视图 (pin 屏障) */
	unsigned char *src;         /* 本线程写源 buffer (DMA 源) */
	struct ibv_mr *src_mr;
	int src_mr_id;
	struct symrdma_mr src_lmr;  /* v0.25.0: src 的本地 MR 视图 (pin 屏障) */

	unsigned long long ops, eagain, corrupt, access_err;
};

struct thread_arg targs[NTHREAD];
static pthread_t tids[NTHREAD];
static pthread_t swapper_tid;
static volatile sig_atomic_t stop_flag;
static unsigned char *g_buf;
static unsigned long long g_read_err;   /* 读失败限流计数 */
static unsigned long long g_access_err; /* REM_ACCESS_ERR 总计 (IOMMU 翻转窗口) */

/* ---- 复用 L9 帮助函数 (套件自包含约定) ---- */

static uint64_t now_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
}

static long long proc_stat(const char *key)
{
	FILE *f = fopen("/proc/symrdma", "r");
	char line[256];
	long long v = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char *colon;
		if (!strstr(line, key))
			continue;
		colon = strchr(line, ':');
		if (colon)
			v = atoll(colon + 1);
		break;
	}
	fclose(f);
	return v;
}

static int identity_mtt_active(void)
{
	FILE *f = fopen("/sys/module/mlx5_ib/parameters/identity_mtt", "r");
	int c;
	if (!f)
		return 0;
	c = fgetc(f);
	fclose(f);
	return c == 'Y';
}


/* 环境适配 (host-a/host-b 双口卡实测): 机器按 PCI function 枚举出多个 mlx5
 * 设备, 取第一个可能命中 DOWN 口 (mlx5_0 DOWN / mlx5_1 ACTIVE) — QP 建在
 * 死口上 DMA 走错 IOMMU domain (DMAR fault reason 06, 读回全 0xff)。
 * 优先选 port1 状态 ACTIVE 的设备; 查询失败保持原行为 (取第一个)。 */
static int mlx5_port_active(const char *name)
{
	char path[256];
	char buf[64];
	FILE *f;

	snprintf(path, sizeof(path),
		 "/sys/class/infiniband/%s/ports/1/state", name);
	f = fopen(path, "r");
	if (!f)
		return 1;
	if (!fgets(buf, sizeof(buf), f)) {
		fclose(f);
		return 1;
	}
	fclose(f);
	return strstr(buf, "ACTIVE") != NULL;
}

static struct ibv_device *find_rdma_device(void)
{
	struct ibv_device **dev_list;
	struct ibv_device *dev = NULL;
	int num, i;

	dev_list = ibv_get_device_list(&num);
	if (!dev_list || num == 0)
		return NULL;
	for (i = 0; i < num; i++) {
		const char *name = ibv_get_device_name(dev_list[i]);
		if (strstr(name, "mlx5")) {
			if (mlx5_port_active(name)) {
				dev = dev_list[i];
				break;
			}
			/* 非 ACTIVE 的 mlx5 仅作回退, 继续找 ACTIVE 口 */
			if (!dev)
				dev = dev_list[i];
			continue;
		}
		if (!dev)
			dev = dev_list[i];
	}
	return dev;
}

/* RoCEv2 GID 软自环 QP (同 L9: dest_qp_num=自己, dgid=本机端口 GID) */
static int setup_loopback_qp(struct ibv_context *ctx, struct ibv_pd *pd,
			     struct ibv_cq **cq_out, struct ibv_qp **qp_out)
{
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	struct ibv_qp_init_attr qp_attr = {0};

	cq = ibv_create_cq(ctx, CQ_DEPTH, NULL, NULL, 0);
	if (!cq)
		return -1;
	qp_attr.send_cq = cq;
	qp_attr.recv_cq = cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.cap.max_send_wr = CQ_DEPTH;
	qp_attr.cap.max_recv_wr = CQ_DEPTH;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;
	qp = ibv_create_qp(pd, &qp_attr);
	if (!qp) {
		ibv_destroy_cq(cq);
		return -1;
	}
	{
		struct ibv_qp_attr attr = {0};

		attr.qp_state = IBV_QPS_INIT;
		attr.pkey_index = 0;
		attr.port_num = 1;
		attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
				       IBV_ACCESS_REMOTE_WRITE |
				       IBV_ACCESS_LOCAL_WRITE;
		if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
				  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
			goto err;
		attr.qp_state = IBV_QPS_RTR;
		attr.path_mtu = IBV_MTU_4096;
		attr.dest_qp_num = qp->qp_num;
		attr.rq_psn = 0;
		attr.max_dest_rd_atomic = 1;
		attr.min_rnr_timer = 12;
		attr.ah_attr.port_num = 1;
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.sgid_index = 0;
		attr.ah_attr.grh.hop_limit = 1;
		{
			struct ibv_port_attr port_attr;

			if (ibv_query_port(ctx, 1, &port_attr) ||
			    ibv_query_gid(ctx, 1, 0, &attr.ah_attr.grh.dgid))
				goto err;
			/* v0.33.1: path_mtu 动态取 min(active_mtu, 4096) —
			 * v0.29.2 L15 教训 (path_mtu > active_mtu 令多包响应首包
			 * 被丢); 自环同样从端口查询派生, 与跨机测试对齐 */
			if (port_attr.active_mtu < IBV_MTU_4096)
				attr.path_mtu = port_attr.active_mtu;
		}
		if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_MTU |
				  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER | IBV_QP_AV))
			goto err;
		attr.qp_state = IBV_QPS_RTS;
		attr.sq_psn = 0;
		attr.timeout = 14;
		attr.retry_cnt = 7;
		attr.rnr_retry = 7;
		attr.max_rd_atomic = 1;
		if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN |
				  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
				  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))
			goto err;
	}
	*cq_out = cq;
	*qp_out = qp;
	return 0;
err:
	ibv_destroy_qp(qp);
	ibv_destroy_cq(cq);
	return -1;
}

/* 双注册: ioctl REG_MR (IOMMU 映射) + ibv_reg_mr identity 位 */
static int register_pair(struct symrdma_ctx *ctx, struct ibv_pd *pd,
			 void *va, size_t len, int access,
			 struct ibv_mr **mr_out, int *mr_id_out)
{
	struct symrdma_ioc_reg_mr reg = {
		.va_start = (unsigned long long)va,
		.len = len,
	};

	if (ioctl(ctx->fd, SYMRDMA_IOC_REG_MR, &reg))
		return -1;
	*mr_id_out = reg.mr_id;
	*mr_out = ibv_reg_mr(pd, va, len, access);
	if (!*mr_out) {
		ioctl(ctx->fd, SYMRDMA_IOC_DEREG_MR, *mr_id_out);
		*mr_id_out = -1;
		return -1;
	}
	return 0;
}

/* 页内第 word 个 u32 的期望值: 页号/字偏移/魔数尾 — 任何字节错位或
 * 页串扰都会失配。读页 seq 固定 0xAB; 写页 seq 每次写入递增 (检测旧数据)。 */
static inline uint32_t word_expect(int page, int word)
{
	return ((uint32_t)(page & 0xFF) << 24) |
	       ((uint32_t)(word & 0xFF) << 16) | 0xABABu;
}

static inline uint32_t word_expect_w(int page, int word, uint8_t seq)
{
	return ((uint32_t)(page & 0xFF) << 24) |
	       ((uint32_t)(word & 0xFF) << 16) |
	       ((uint32_t)seq << 8) | 0xCDu;
}

static void fill_pattern(unsigned char *dst, int page, size_t op)
{
	uint32_t *w = (uint32_t *)dst;
	size_t i, nw = op / 4;

	for (i = 0; i < nw; i++)
		w[i] = word_expect(page, (int)i);
}

static void fill_pattern_w(unsigned char *dst, int page, size_t op, uint8_t seq)
{
	uint32_t *w = (uint32_t *)dst;
	size_t i, nw = op / 4;

	for (i = 0; i < nw; i++)
		w[i] = word_expect_w(page, (int)i, seq);
}

/* 全量逐字比对; 返回失配数, 首批差异打印 (限 4 条/次) */
static int verify_words(const unsigned char *got, int page, size_t op,
			uint8_t seq, const char *tag, int tid)
{
	const uint32_t *w = (const uint32_t *)got;
	size_t i, nw = op / 4;
	int bad = 0;

	for (i = 0; i < nw; i++) {
		uint32_t exp = seq ? word_expect_w(page, (int)i, seq)
				   : word_expect(page, (int)i);
		if (w[i] != exp) {
			if (bad < 4)
				fprintf(stderr,
					"  [损坏] %s 线程%d 页%d 偏移%zu: got 0x%08x exp 0x%08x\n",
					tag, tid, page, i * 4, w[i], exp);
			bad++;
		}
	}
	return bad;
}

/* reader 线程: 随机只读页 symrdma_read_p + 全量验证。
 * v0.25.0: 改用 _p 变体 — recv 页在飞 pin (屏障) + 本地预检,
 * 消除失效窗口内接收页被哨兵化 → DMA 写被吸收 → 整页零的静默损坏
 * (v0.24.6 A/B 实锤的 host-b L14 corrupt 根因)。 */
static void *reader_fn(void *arg)
{
	struct thread_arg *t = arg;
	unsigned int seed = 0x1234u + (unsigned int)t->idx;

	while (!stop_flag) {
		int page = rand_r(&seed) % NREAD;
		int ret;

		ret = symrdma_read_p(t->ctx, t->qp, t->cq, t->smr,
				     (unsigned long)page, t->op, t->recv,
				     t->recv_mr->lkey, &t->recv_lmr);
		if (ret) {
			if (errno == EAGAIN) {
				t->eagain++;
			} else {
				t->access_err++;
				__atomic_add_fetch(&g_access_err, 1, __ATOMIC_RELAXED);
				if (++g_read_err <= 3)
					fprintf(stderr,
						"  [reader%d] symrdma_read 失败 ret=%d errno=%d (后续限流)\n",
						t->idx, ret, errno);
			}
			continue;
		}
		if (verify_words(t->recv, page, t->op, 0, "read", t->idx))
			t->corrupt++;
		t->ops++;
	}
	return NULL;
}

/* writer 线程: 随机写页 → 写 → 回读 → 验证 (seq 递增检测旧数据)。
 * v0.25.0: 改用 _p 变体 — src (写源) 与 recv (回读目标) 页在飞 pin。 */
static void *writer_fn(void *arg)
{
	struct thread_arg *t = arg;
	unsigned int seed = 0x9abcu + (unsigned int)t->idx;
	uint8_t seq = 1;

	while (!stop_flag) {
		int page = NREAD + rand_r(&seed) % NWRITER_P;
		int ret;

		fill_pattern_w(t->src, page, t->op, seq);
		ret = symrdma_write_p(t->ctx, t->qp, t->cq, t->smr, t->wmr,
				      (unsigned long)page, t->op, t->src,
				      t->src_mr->lkey, &t->src_lmr);
		if (ret) {
			if (errno == EAGAIN) {
				t->eagain++;
			} else {
				t->access_err++;
				__atomic_add_fetch(&g_access_err, 1, __ATOMIC_RELAXED);
				if (g_read_err <= 3)
					fprintf(stderr,
						"  [writer%d] symrdma_write 失败 ret=%d errno=%d\n",
						t->idx, ret, errno);
			}
			continue;
		}
		/* 回读: 换出竞态由 symrdma_read_p 自动修复 (recv 页在飞 pin);
		 * 内容必须是刚写入的 seq 模式 (旧 seq/初始 0xAB = 丢写/串扰) */
		ret = symrdma_read_p(t->ctx, t->qp, t->cq, t->smr,
				     (unsigned long)page, t->op, t->recv,
				     t->recv_mr->lkey, &t->recv_lmr);
		if (ret) {
			if (errno == EAGAIN)
				t->eagain++;
			continue;
		}
		if (verify_words(t->recv, page, t->op, seq, "write", t->idx))
			t->corrupt++;
		t->ops++;
		/* seq 回绕防护: 0 保留给读模式 (verify_words 语义) */
		seq = (uint8_t)(seq % 255 + 1);
	}
	return NULL;
}

/* swapper 线程: 随机换出 + 偶尔 touch 换入, 与数据面全程对抗 */
static void *swapper_fn(void *arg)
{
	unsigned long long *nswap = arg;
	unsigned int seed = 0xf00du;
	unsigned long long n = 0;

	while (!stop_flag) {
		int page = rand_r(&seed) % NPAGES;

		madvise(g_buf + (size_t)page * SYMRDMA_PAGE_SIZE,
			SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
		n++;
		if (n % 4 == 0) {
			/* touch 换入 (触发换入 + notifier 驻留重映射路径) */
			int p2 = rand_r(&seed) % NPAGES;

			(void)g_buf[(size_t)p2 * SYMRDMA_PAGE_SIZE];
		}
		usleep(100 + rand_r(&seed) % 700);
	}
	*nswap = n;
	return NULL;
}

int main(int argc, char **argv)
{
	struct symrdma_ctx ctx;
	struct symrdma_mr smr = {0};
	struct symrdma_mr_write wmr = {0};
	struct ibv_device *dev;
	struct ibv_context *ibctx = NULL;
	struct ibv_pd *pd = NULL;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova iova_req;
	size_t op = DEFAULT_OP;
	int sec = DEFAULT_SEC;
	unsigned long long nswap = 0, repair_delta;
	long long repair_base;
	uint64_t t0 = 0, elapsed = 0;
	int i, rc = 0, buf_mr_id = -1;
	long long nsent;

	smr.mr_id = -1;
	if (argc > 1)
		sec = atoi(argv[1]);
	if (argc > 2)
		op = (size_t)atol(argv[2]);
	if (op < 4 || op % 4 || op > 64 * 1024) {
		fprintf(stderr, "op 必须是 4 的倍数且 ≤ 64KB\n");
		return 2;
	}

	printf("=== SymRDMA Level 14: 并发缺页竞态压测 (论文 §3.1) ===\n");
	printf("identity_mtt: %s | 线程: %d reader + %d writer + 1 swapper | "
	       "页: %d (%d 读验证 + %d 写验证) | op=%zu B | 时长=%ds\n",
	       identity_mtt_active() ? "Y" : "N", NREADER, NWRITER,
	       NPAGES, NREAD, NWRITER_P, op, sec);

	if (symrdma_open(&ctx)) {
		fprintf(stderr, "[dbg] /dev/symrdma 打开失败\n");
		return 1;
	}

	/* 数据区: mmap 匿名页 (不 pin — 可被换出是前提) */
	g_buf = mmap(NULL, (size_t)NPAGES * SYMRDMA_PAGE_SIZE,
		     PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (g_buf == MAP_FAILED) {
		fprintf(stderr, "[dbg] mmap buf 失败\n");
		rc = 1;
		goto err_out;
	}
	for (i = 0; i < NPAGES; i++)
		fill_pattern(g_buf + (size_t)i * SYMRDMA_PAGE_SIZE, i,
			     SYMRDMA_PAGE_SIZE);

	dev = find_rdma_device();
	if (!dev) { fprintf(stderr, "[dbg] no rdma dev\n"); rc = 1; goto err_out; }
	ibctx = ibv_open_device(dev);
	if (!ibctx) { fprintf(stderr, "[dbg] open_device fail\n"); rc = 1; goto err_out; }
	pd = ibv_alloc_pd(ibctx);
	if (!pd) { fprintf(stderr, "[dbg] alloc_pd fail\n"); rc = 1; goto err_out; }

	/* 数据 MR (REMOTE_READ|REMOTE_WRITE|LOCAL_WRITE + identity) */
	reg.va_start = (unsigned long long)g_buf;
	reg.len = (size_t)NPAGES * SYMRDMA_PAGE_SIZE;
	if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg)) {
		fprintf(stderr, "[dbg] REG_MR buf fail errno=%d\n", errno);
		rc = 1;
		goto err_out;
	}
	buf_mr_id = reg.mr_id;
	smr.mr_id = buf_mr_id;
	smr.buf = g_buf;
	smr.len = (size_t)NPAGES * SYMRDMA_PAGE_SIZE;
	iova_req.mr_id = buf_mr_id;
	iova_req.page_idx = 0;
	if (ioctl(ctx.fd, SYMRDMA_IOC_GET_IOVA, &iova_req)) {
		fprintf(stderr, "[dbg] GET_IOVA fail\n");
		rc = 1;
		goto err_out;
	}
	smr.read_iova = iova_req.read_iova;
	smr.write_iova = iova_req.write_iova;
	smr.ibv_mr = ibv_reg_mr(pd, g_buf, smr.len,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE |
				SYMRDMA_ACCESS_IDENTITY);
	if (!smr.ibv_mr) { fprintf(stderr, "[dbg] ibv_reg_mr buf fail\n"); rc = 1; goto err_out; }

	/* Version MR 绑定 (本地直读版本表, 零 ioctl; 多线程并发读安全) */
	if (symrdma_mr_bind_version(&ctx, pd, &smr)) {
		fprintf(stderr, "[dbg] bind_version fail\n");
		rc = 1;
		goto err_out;
	}
	/* 版本表页 (bind_version 已在库内 SET_VERSION_PAGE): 防御性 mlock,
	 * 防版本表自身被换出干扰并发版本读 (读路径 seqlock/GET_VERSION 依赖) */
	if (smr.version_buf && mlock(smr.version_buf, SYMRDMA_PAGE_SIZE))
		fprintf(stderr, "  [warn] 版本表 mlock 失败\n");

	/* 写区 MR (REMOTE_WRITE 无 REMOTE_READ → MTT=VA+32GB, 论文写侧黑洞) */
	if (symrdma_write_mr_register(pd, g_buf, smr.len, &wmr)) {
		fprintf(stderr, "[dbg] write_mr_register fail\n");
		rc = 1;
		goto err_out;
	}

	/* 每线程: QP/CQ + 接收 buffer (DMA 目标) + 写源 buffer (DMA 源) —
	 * 全部双注册 (identity 下无 IOMMU 映射的 DMA 会 fault, L9 教训) */
	for (i = 0; i < NTHREAD; i++) {
		struct thread_arg *t = &targs[i];

		t->idx = i;
		t->role = (i < NREADER) ? 0 : 1;
		t->ctx = &ctx;
		t->ibctx = ibctx;
		t->pd = pd;
		t->buf = g_buf;
		t->smr = &smr;
		t->wmr = &wmr;
		t->op = op;
		if (setup_loopback_qp(ibctx, pd, &t->cq, &t->qp)) {
			fprintf(stderr, "[dbg] 线程%d QP 失败\n", i);
			rc = 1;
			goto err_out;
		}
		t->recv = mmap(NULL, op, PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (t->recv == MAP_FAILED) { rc = 1; goto err_out; }
		memset(t->recv, 0x5A, op);
		if (mlock(t->recv, op))
			fprintf(stderr, "  [warn] recv mlock 失败\n");
		if (register_pair(&ctx, pd, t->recv, op,
				  IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY,
				  &t->recv_mr, &t->recv_mr_id)) {
			fprintf(stderr, "[dbg] 线程%d recv 注册失败\n", i);
			rc = 1;
			goto err_out;
		}
		/* v0.25.0: recv 本地 MR 视图 (pin 屏障 + 预检定位) */
		memset(&t->recv_lmr, 0, sizeof(t->recv_lmr));
		t->recv_lmr.mr_id = t->recv_mr_id;
		t->recv_lmr.buf = t->recv;
		t->recv_lmr.len = op;
		if (t->role == 1) {
			t->src = mmap(NULL, op, PROT_READ | PROT_WRITE,
				      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
			if (t->src == MAP_FAILED) { rc = 1; goto err_out; }
			memset(t->src, 0x5A, op);
			if (mlock(t->src, op))
				fprintf(stderr, "  [warn] src mlock 失败\n");
			if (register_pair(&ctx, pd, t->src, op,
					  IBV_ACCESS_LOCAL_WRITE |
					  SYMRDMA_ACCESS_IDENTITY,
					  &t->src_mr, &t->src_mr_id)) {
				fprintf(stderr, "[dbg] 线程%d src 注册失败\n", i);
				rc = 1;
				goto err_out;
			}
			/* v0.25.0: src 本地 MR 视图 (pin 屏障 + 预检定位) */
			memset(&t->src_lmr, 0, sizeof(t->src_lmr));
			t->src_lmr.mr_id = t->src_mr_id;
			t->src_lmr.buf = t->src;
			t->src_lmr.len = op;
		} else {
			t->src = NULL;
			t->src_mr = NULL;
			t->src_mr_id = -1;
		}
	}

	/* REPAIR 基线 + 启动 */
	repair_base = proc_stat("REPAIR 成功");
	if (repair_base < 0)
		repair_base = 0;
	stop_flag = 0;
	t0 = now_us();
	if (pthread_create(&swapper_tid, NULL, swapper_fn, &nswap)) {
		fprintf(stderr, "[dbg] swapper 启动失败\n");
		rc = 1;
		goto err_out;
	}
	for (i = 0; i < NTHREAD; i++) {
		void *(*fn)(void *) = (targs[i].role == 0) ? reader_fn : writer_fn;

		if (pthread_create(&tids[i], NULL, fn, &targs[i])) {
			fprintf(stderr, "[dbg] 线程%d 启动失败\n", i);
			stop_flag = 1;
			rc = 1;
			goto join_out;
		}
	}

	/* 每秒进度: ops/s + 累计损坏 (损坏即提前停止 — 快速失败) */
	for (i = 0; i < sec; i++) {
		sleep(1);
		{
			unsigned long long c = 0, o = 0;
			int j;

			for (j = 0; j < NTHREAD; j++) {
				o += targs[j].ops;
				c += targs[j].corrupt;
			}
			printf("  [%2ds] ops=%llu (%llu ops/s) corrupt=%llu\n",
			       i + 1, o, o / (unsigned long long)(i + 1), c);
			fflush(stdout);
			if (c > 0) {
				printf("  检测到数据损坏, 提前终止\n");
				break;
			}
		}
	}
	stop_flag = 1;

join_out:
	pthread_join(swapper_tid, NULL);
	for (i = 0; i < NTHREAD; i++)
		if (tids[i])
			pthread_join(tids[i], NULL);
	elapsed = now_us() - t0;

	/* 静止后全量复核只读页 (swapper 已停, 页面可安全换回) */
	for (i = 0; i < NPAGES; i++)
		(void)g_buf[(size_t)i * SYMRDMA_PAGE_SIZE];
	{
		int static_corrupt = 0;

		for (i = 0; i < NREAD; i++) {
			if (verify_words(g_buf + (size_t)i * SYMRDMA_PAGE_SIZE,
					 i, SYMRDMA_PAGE_SIZE, 0, "static", -1))
				static_corrupt++;
		}
		if (static_corrupt)
			printf("  ★ 静止复核: %d 个只读页模式损坏\n", static_corrupt);
		else
			printf("  静止复核: %d 个只读页模式完好\n", NREAD);
		rc |= (static_corrupt > 0);
	}

	repair_delta = proc_stat("REPAIR 成功") - repair_base;
	nsent = repair_delta;
	printf("\n[结果] 时长 %llu ms\n", (unsigned long long)(elapsed / 1000));
	{
		unsigned long long to = 0, te = 0, tc = 0, tw = 0, ta = 0;

		for (i = 0; i < NTHREAD; i++) {
			struct thread_arg *t = &targs[i];

			printf("  %s%d: ops=%llu eagain=%llu corrupt=%llu access_err=%llu\n",
			       role_name[t->role], t->idx, t->ops, t->eagain,
			       t->corrupt, t->access_err);
			to += t->ops;
			te += t->eagain;
			tc += t->corrupt;
			ta += t->access_err;
			if (t->role == 1)
				tw += t->ops;
		}
		printf("  swapper: pageout=%llu\n", nswap);
		printf("  合计: 数据面 ops=%llu (读 %llu / 写 %llu), "
		       "eagain=%llu (%.3f%%), 损坏=%llu, access_err=%llu, REPAIR Δ=%lld\n",
		       to, to - tw, tw, te,
		       to + te ? 100.0 * te / (to + te) : 0.0, tc, ta, nsent);
		rc |= (tc > 0);
		if (ta > 0)
			printf("  [warn] access_err=%llu — IOMMU 映射翻转 vs 在飞 DMA 窗口 "
			       "(v0.25.0 屏障已落地: 未 pin 页/远端发起写仍可能命中; "
			       "数据零损坏时 WARN 不 FAIL)\n", ta);
	}
	printf("\n[判定] %s\n", rc ? "FAIL (数据损坏)" :
	       "PASS (并发缺页竞态下零数据损坏)");

err_out:
	for (i = 0; i < NTHREAD; i++) {
		struct thread_arg *t = &targs[i];

		if (t->src_mr)
			ibv_dereg_mr(t->src_mr);
		if (t->src_mr_id >= 0)
			ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, t->src_mr_id);
		if (t->recv_mr)
			ibv_dereg_mr(t->recv_mr);
		if (t->recv_mr_id >= 0)
			ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, t->recv_mr_id);
		if (t->qp)
			ibv_destroy_qp(t->qp);
		if (t->cq)
			ibv_destroy_cq(t->cq);
		if (t->recv && t->recv != MAP_FAILED)
			munmap(t->recv, op);
		if (t->src && t->src != MAP_FAILED)
			munmap(t->src, op);
	}
	symrdma_write_mr_deregister(&wmr);
	/* 统一清理: version MR/版本表/ibv_mr/ioctl DEREG (lib 全套) */
	symrdma_mr_deregister(&ctx, &smr);
	if (pd)
		ibv_dealloc_pd(pd);
	if (ibctx)
		ibv_close_device(ibctx);
	if (g_buf && g_buf != MAP_FAILED)
		munmap(g_buf, (size_t)NPAGES * SYMRDMA_PAGE_SIZE);
	symrdma_close(&ctx);
	return rc;
}
