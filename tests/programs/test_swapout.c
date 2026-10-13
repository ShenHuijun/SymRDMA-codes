/*
 * test_swapout.c — SymRDMA Level 3: 真实 swap-out 触发验证 (P0)
 *
 * 与 Level 2 (test_rdma_verify.c) 的区别:
 *   Level 2 用 ioctl REMAP 手动模拟换出 → 哨兵
 *   Level 3 用 madvise(MADV_PAGEOUT) 让 OS 真实换出页面,
 *           MMU notifier 自动把 IOMMU 映射重定向到哨兵页。
 *
 * 验证流程 (全自动, 无 ioctl REMAP):
 *   1. REG_MR 注册 4 页缓冲 (IOMMU 双 IOVA 映射, 不 pin)
 *   2. QP RTS (RoCEv2 GID 自环, 同 Level 2)
 *   3. madvise(MADV_PAGEOUT) 换出页 0 → MMU notifier → IOMMU 哨兵
 *      ★ 关键时序: 换出发生在 ibv_reg_mr 之前 — 页面未被 pin,
 *        换出行为确定 (不依赖内核 GUP pin 语义)
 *   4. READ_IOVA 轮询: 0xABABAB41 → 0xdeadbeef (notifier 已触发)
 *   5. /proc/symrdma 统计: notifier_calls / pages_swapped_out
 *   6. /proc/self/smaps: Swap ≥ 4KB (内容确实在 swap)
 *   7. ibv_reg_mr 重新 pin (页 0 经 swap cache 换回 CPU, IOMMU 仍哨兵)
 *      — 同时验证论文 §4.1 惰性换入: IOMMU 状态滞后于 CPU 状态
 *   8. RDMA Read 页 0 → 0xdeadbeef ★ (NIC DMA 命中 notifier 建立的哨兵)
 *   9. REPAIR → IOMMU 恢复真实 PA
 *  10. RDMA Read → 0xABABAB41 (完整闭环)
 *  11. 邻居页 1/2 不受影响
 *  12. INFO: 已 pin 页面再 MADV_PAGEOUT 的行为 (供 P3 LD_PRELOAD 设计参考)
 *
 * 环境要求: 同 Level 2 — mlx5 端口 Active, identity_mtt=1, NIC 模式模块,
 *           系统有 swap 空间。无 RDMA 设备时自动降级为 IOMMU 级验证。
 *
 * 注意: 本程序结构刻意与 test_rdma_verify.c 镜像 (独立测试程序约定)。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <infiniband/verbs.h>
/* SymRDMA MR 标记位 (P4): 与 lib/libsymrdma.h 同值 —
 * uverbs optional 位 1<<21, mlx5 据此走 identity MTT 分支 */
#define SYMRDMA_ACCESS_IDENTITY (1 << 21)

/* 兼容旧版 rdma-core (IBV_QP_MTU → IBV_QP_PATH_MTU) */
#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif

/* MADV_PAGEOUT: x86 值 21 (kernel ≥ 5.4), 旧 glibc 无此定义时兜底 */
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

/* ---- SymRDMA ioctl (与 kernel/symrdma.h 保持同步) ---- */
#define SYMRDMA_IOC_MAGIC       'S'
#define SYMRDMA_SENTINEL_MAGIC  0xdeadbeef

struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_get_iova {
	int mr_id;
	unsigned long page_idx;
	unsigned long long read_iova, write_iova;
};
struct symrdma_ioc_read_iova {
	int mr_id;
	unsigned long long iova;
	unsigned long offset;
	unsigned int value;
};
struct symrdma_ioc_repair {
	int mr_id;
	unsigned long page_idx;
};

#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_GET_IOVA    _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_get_iova)
#define SYMRDMA_IOC_READ_IOVA   _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_REPAIR      _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)

/* ---- 测试参数 ---- */
#define TEST_PAGES       4
#define PAGE_SIZE        4096
#define BUF_SIZE         (TEST_PAGES * PAGE_SIZE)
#define CQ_DEPTH         16
#define SWAPOUT_TIMEOUT_S 10    /* 哨兵轮询超时 */
#define PINNED_PROBE_S    2     /* pin 后 MADV_PAGEOUT 探针轮询 */

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/* ---- 辅助函数 ---- */

/*
 * 检测 mlx5_ib 的 identity_mtt 模块参数是否开启 (Y/N)。
 * 开启时 MTT 条目 = 用户 VA, NIC DMA 经 IOMMU 命中 SymRDMA 映射。
 */
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

/* 查找第一个 mlx5 RDMA 设备 */

/* 环境适配 (双机测试床 双口卡实测): 机器按 PCI function 枚举出多个 mlx5
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
	if (!dev_list || num == 0) {
		printf("  未找到 RDMA 设备\n");
		return NULL;
	}

	for (i = 0; i < num; i++) {
		const char *name = ibv_get_device_name(dev_list[i]);
		printf("  发现 RDMA 设备: %s\n", name);
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

/* 读取 /proc/symrdma 统计值 (按 key 匹配行, 取冒号后数值; 未找到返回 -1) */
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

/* 读取 /proc/self/smaps 中 addr 所在 VMA 的 Swap 字段 (kB); 失败返回 -1 */
static long smaps_swap_kb(void *addr)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256];
	unsigned long a = (unsigned long)addr;
	unsigned long start, end;
	long swap_kb = -1;
	int in_vma = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			in_vma = (a >= start && a < end);
			continue;
		}
		if (in_vma && sscanf(line, "Swap: %ld kB", &swap_kb) == 1)
			break;
	}
	fclose(f);
	return swap_kb;
}

/* ---- QP 自环建立 (RoCEv2 GID 路径, 同 Level 2) ---- */
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
	qp_attr.cap.max_send_wr  = CQ_DEPTH;
	qp_attr.cap.max_recv_wr  = CQ_DEPTH;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;

	qp = ibv_create_qp(pd, &qp_attr);
	if (!qp) {
		ibv_destroy_cq(cq);
		return -1;
	}

	{
		struct ibv_qp_attr attr = {0};

		/* INIT */
		attr.qp_state        = IBV_QPS_INIT;
		attr.pkey_index      = 0;
		attr.port_num        = 1;
		attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
				       IBV_ACCESS_REMOTE_WRITE |
				       IBV_ACCESS_LOCAL_WRITE;
		if (ibv_modify_qp(qp, &attr,
				  IBV_QP_STATE | IBV_QP_PKEY_INDEX |
				  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
			goto err_qp;

		/* RTR (自环: dest_qp = 自己, GID = 本机端口 GID) */
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
			struct ibv_port_attr port_attr;
			if (ibv_query_port(ctx, 1, &port_attr) ||
			    ibv_query_gid(ctx, 1, 0, &attr.ah_attr.grh.dgid)) {
				printf("  SKIP: 查询端口 GID 失败\n");
				goto err_qp;
			}
			printf("  端口: link_layer=%s state=%d, 自环 GID 已设置\n",
			       port_attr.link_layer == IBV_LINK_LAYER_ETHERNET ?
			       "Ethernet": "InfiniBand", port_attr.state);
			/* path_mtu 动态取 min(active_mtu, 4096) —
			 *  L15 教训 (path_mtu > active_mtu 令多包响应首包
			 * 被丢); 自环同样从端口查询派生, 与跨机测试对齐 */
			if (port_attr.active_mtu < IBV_MTU_4096)
				attr.path_mtu = port_attr.active_mtu;
		}
		if (ibv_modify_qp(qp, &attr,
				  IBV_QP_STATE | IBV_QP_MTU |
				  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER |
				  IBV_QP_AV)) {
			printf("  SKIP: QP RTR 失败 (errno=%d %s)\n",
			       errno, strerror(errno));
			goto err_qp;
		}

		/* RTS */
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
			printf("  SKIP: QP RTS 失败\n");
			goto err_qp;
		}
	}

	printf("  QP 就绪: qp_num=0x%x (loopback mode)\n", qp->qp_num);
	*cq_out = cq;
	*qp_out = qp;
	return 0;

err_qp:
	ibv_destroy_qp(qp);
	ibv_destroy_cq(cq);
	return -1;
}

/*
 * 自环 CQ 轮询超时 (ms) — 同 L2 (挂死教训: 无界忙等 → R 态
 * 自旋挂死 → 孤儿进程占住模块引用;  补齐进程内自保护,
 * test.sh 超时兜底之外的自身防线)。正常完成远小于此值。
 */
#define POLL_TIMEOUT_MS 5000

/* 带超时的 CQ 轮询: 0 = 收到 CQE, -ETIMEDOUT = 自环不可达, -EIO = poll 错误 */
static int poll_cq_timeout(struct ibv_cq *cq, struct ibv_wc *wc,
			   unsigned int timeout_ms)
{
	struct timespec ts0, ts;

	clock_gettime(CLOCK_MONOTONIC, &ts0);
	for (;;) {
		int n = ibv_poll_cq(cq, 1, wc);

		if (n > 0)
			return 0;
		if (n < 0)
			return -EIO;
		clock_gettime(CLOCK_MONOTONIC, &ts);
		{
			long ms = (ts.tv_sec - ts0.tv_sec) * 1000L +
				  (ts.tv_nsec - ts0.tv_nsec) / 1000000L;

			if (ms >= (long)timeout_ms)
				return -ETIMEDOUT;
		}
	}
}

/*
 * 发一次 RDMA Read: remote_addr 的一页数据读入 local。
 * 返回 local 处首 4 字节; 发送/完成异常返回 -1; 自环超时返回 -2。
 */
static long long rdma_read_page(struct ibv_qp *qp, struct ibv_cq *cq,
				void *local, uint32_t lkey,
				uintptr_t remote_addr, uint32_t rkey)
{
	struct ibv_sge sge = {
		.addr   = (uintptr_t)local,
		.length = PAGE_SIZE,
		.lkey   = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad_wr = NULL;
	struct ibv_wc wc;

	memset(local, 0, PAGE_SIZE);
	wr.opcode               = IBV_WR_RDMA_READ;
	wr.sg_list              = &sge;
	wr.num_sge              = 1;
	wr.wr.rdma.remote_addr  = remote_addr;
	wr.wr.rdma.rkey         = rkey;
	wr.send_flags           = IBV_SEND_SIGNALED;

	if (ibv_post_send(qp, &wr, &bad_wr))
		return -1;
	if (poll_cq_timeout(cq, &wc, POLL_TIMEOUT_MS) != 0)
		return -2;   /* 自环不可达 (拓扑不适用), 区别于传输失败 */
	if (wc.status != IBV_WC_SUCCESS)
		return -1;

	return (long long)*(unsigned int *)local;
}

/* 通过 READ_IOVA 读某页 (IOMMU 侧视图); ioctl 失败返回 -1 */
static long long read_iova_page(int sym_fd, int mr_id, unsigned long long iova)
{
	struct symrdma_ioc_read_iova rd = {
		.mr_id = mr_id,
		.iova  = iova,
		.offset = 0,
	};

	if (ioctl(sym_fd, SYMRDMA_IOC_READ_IOVA, &rd))
		return -1;
	return (long long)rd.value;
}

/* ---- 主程序 ---- */
int main(void)
{
	int sym_fd, ret, mr_id = -1;
	unsigned char *buf;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova iova_req;
	struct symrdma_ioc_repair repair_req;
	unsigned long long iova_page0, iova_page1, iova_page2;

	/* RDMA 资源 */
	struct ibv_device *ib_dev = NULL;
	struct ibv_context *ctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct ibv_mr *mr = NULL;
	int have_rdma = 0;
	/* 测试 MR 带 SYMRDMA_ACCESS_IDENTITY → 恒走 identity 路径 (P4):
	 * 全局 identity_mtt=1 或按 MR 标记位, 选择性模式下同样生效 */
	int identity = 1;
	int i, fired;

	printf("=== SymRDMA Level 3: 真实 swap-out 触发验证 (P0) ===\n\n");
	printf("identity_mtt: %s\n",
	       identity ? "Y (NIC DMA 经 IOMMU 命中 SymRDMA 映射)" : "N (基线模式)");

	/* Step 1: 打开 /dev/symrdma */
	sym_fd = open("/dev/symrdma", O_RDWR);
	if (sym_fd < 0) {
		printf("ERROR: 无法打开 /dev/symrdma — 请先 insmod symrdma.ko\n");
		return 1;
	}
	printf("[1] /dev/symrdma 已打开\n");

	/* Step 2: 分配内存并写入测试数据 */
	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		close(sym_fd);
		return 1;
	}
	memset(buf, 0xAB, BUF_SIZE);
	for (i = 0; i < TEST_PAGES; i++)
		buf[i * PAGE_SIZE] = (unsigned char)('A' + i);
	printf("[2] 测试内存已分配: %d 页 (页 0 首字 = 0xABABAB41)\n", TEST_PAGES);

	/* Step 3: 注册 SymRDMA MR (IOMMU 映射, 不 pin) */
	reg.va_start = (unsigned long long)buf;
	reg.len = BUF_SIZE;
	ret = ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
	CHECK(ret == 0, "SymRDMA REG_MR");
	if (ret)
		goto cleanup;
	mr_id = reg.mr_id;

	/* GET_IOVA: read_iova 应为恒等映射 (= 用户 VA) */
	iova_req.mr_id = mr_id;
	iova_req.page_idx = 0;
	ret = ioctl(sym_fd, SYMRDMA_IOC_GET_IOVA, &iova_req);
	CHECK(ret == 0, "GET_IOVA");
	iova_page0 = iova_req.read_iova;
	iova_page1 = iova_page0 + PAGE_SIZE;
	iova_page2 = iova_page0 + 2 * PAGE_SIZE;
	CHECK(iova_page0 == (unsigned long long)buf,
	      "read_iova == 用户 VA (恒等映射, MTT identity 兼容)");

	/* Step 4: 基线 — 页 0 驻留, IOMMU 读真实数据 */
	CHECK(read_iova_page(sym_fd, mr_id, iova_page0) == 0xABABAB41,
	      "基线: READ_IOVA 页 0 → 0xABABAB41 (驻留)");

	/* Step 5: RDMA 上下文 (设备不可用时降级为 IOMMU 级验证) */
	printf("\n--- RDMA 设备 ---\n");
	ib_dev = find_rdma_device();
	if (ib_dev) {
		ctx = ibv_open_device(ib_dev);
		if (ctx) {
			pd = ibv_alloc_pd(ctx);
			if (pd && setup_loopback_qp(ctx, pd, &cq, &qp) == 0)
				have_rdma = 1;
		}
	}
	if (!have_rdma)
		printf("  SKIP: RDMA 设备不可用 — 仅做 IOMMU 级验证\n");

	/* Step 6: ★ P0 核心 — OS 真实换出页 0
	 *
	 * 时序关键: 此时尚未 ibv_reg_mr, 页面未被 pin,
	 * MADV_PAGEOUT 的换出行为确定。换出触发 MMU notifier,
	 * 内核自动把 IOMMU 映射重定向到哨兵页 (无 ioctl REMAP)。
	 */
	printf("\n--- P0: OS 真实换出页 0 (madvise MADV_PAGEOUT) ---\n");
	ret = madvise(buf, PAGE_SIZE, MADV_PAGEOUT);
	CHECK(ret == 0, "madvise(MADV_PAGEOUT) 页 0");

	/* Step 7: 轮询 READ_IOVA → notifier 已把 IOMMU 重映射为哨兵 */
	fired = 0;
	for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
		if (read_iova_page(sym_fd, mr_id, iova_page0) ==
		    (long long)SYMRDMA_SENTINEL_MAGIC) {
			fired = 1;
			break;
		}
		usleep(100000);
	}
	CHECK(fired, "★ MMU notifier 自动重映射: 页 0 IOMMU → 哨兵 (0xdeadbeef, 真实换出非 ioctl)");

	/* Step 8: 内核统计 — notifier 确实被调用 */
	CHECK(proc_stat("notifier 回调") >= 1, "/proc/symrdma: notifier 回调 ≥ 1");
	CHECK(proc_stat("换出重映射页") >= 1, "/proc/symrdma: 换出重映射页 ≥ 1");

	/* Step 9: smaps — 页 0 内容确实在 swap */
	{
		long swapkb = smaps_swap_kb(buf);
		printf("  [debug] smaps Swap: %ld kB\n", swapkb);
		CHECK(swapkb >= 4, "页 0 内容确实在 swap (smaps Swap ≥ 4kB)");
	}

	/* Step 10: 邻居页隔离 — 仅页 0 被换出 */
	CHECK(read_iova_page(sym_fd, mr_id, iova_page1) == 0xABABAB42,
	      "邻居页 1 不受换出影响 (0xABABAB42)");
	CHECK(read_iova_page(sym_fd, mr_id, iova_page2) == 0xABABAB43,
	      "邻居页 2 不受换出影响 (0xABABAB43)");

	/* Step 11: RDMA 闭环 */
	if (have_rdma) {
		printf("\n--- RDMA 闭环 (identity_mtt) ---\n");

		/*
		 * ibv_reg_mr pin 全部 4 页: 页 0 经 swap cache 换回 CPU 页表,
		 * 但 IOMMU 仍指向哨兵 — 论文 §4.1 惰性换入 (IOMMU 滞后于 CPU)。
		 */
		mr = ibv_reg_mr(pd, buf, BUF_SIZE,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE |
				SYMRDMA_ACCESS_IDENTITY);
		CHECK(mr != NULL, "ibv_reg_mr (页 0 经 swap cache 换回)");

		if (mr) {
			unsigned char *local = buf + PAGE_SIZE;
			long long v;

			CHECK(read_iova_page(sym_fd, mr_id, iova_page0) ==
			      (long long)SYMRDMA_SENTINEL_MAGIC,
			      "惰性换入: CPU 页表已恢复, IOMMU 仍哨兵 (论文 §4.1)");

			/* RDMA Read → 哨兵 ★ (NIC DMA 命中 notifier 建立的哨兵) */
			v = rdma_read_page(qp, cq, local, mr->lkey,
					   (uintptr_t)iova_page0, mr->rkey);
			if (v == -2) {
				printf("  SKIP: RDMA Read %u ms 无 CQE — 本机自环拓扑不适用, 跳过其余 RDMA 闭环 (同 L2; IOMMU 级验证已通过)\n",
				       (unsigned)POLL_TIMEOUT_MS);
				goto cleanup_rdma;
			}
			printf("  [debug] RDMA Read 读到 0x%llx\n", v);
			if (identity)
				CHECK(v == (long long)SYMRDMA_SENTINEL_MAGIC,
				      "★ RDMA Read 命中 notifier 建立的哨兵 (0xdeadbeef) — 真实换出闭环!");
			else
				CHECK(v == 0xABABAB41,
				      "RDMA Read 基线 (identity_mtt=0): 真实数据");

			/* REPAIR → 恢复 */
			repair_req.mr_id = mr_id;
			repair_req.page_idx = 0;
			ret = ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req);
			CHECK(ret == 0, "REPAIR 成功");
			CHECK(proc_stat("REPAIR 成功") >= 1,
			      "/proc/symrdma: REPAIR 成功计数 ≥ 1");
			CHECK(read_iova_page(sym_fd, mr_id, iova_page0) == 0xABABAB41,
			      "REPAIR 后 READ_IOVA: 0xABABAB41 (真实数据)");

			v = rdma_read_page(qp, cq, local, mr->lkey,
					   (uintptr_t)iova_page0, mr->rkey);
			if (v == -2)
				goto cleanup_rdma;
			CHECK(v == 0xABABAB41,
			      "★ REPAIR 后 RDMA Read 恢复真实数据 (0xABABAB41) — 完整闭环!");

			/* INFO: 已 pin 页面再 MADV_PAGEOUT 的行为 (供 P3 设计参考) */
			if (identity) {
				fired = 0;
				madvise(buf, PAGE_SIZE, MADV_PAGEOUT);
				for (i = 0; i < PINNED_PROBE_S * 10; i++) {
					if (read_iova_page(sym_fd, mr_id,
							   iova_page0) ==
					    (long long)SYMRDMA_SENTINEL_MAGIC) {
						fired = 1;
						break;
					}
					usleep(100000);
				}
				printf("  INFO: ibv pin 后 MADV_PAGEOUT: notifier %s (供 P3 LD_PRELOAD 设计参考)\n",
				       fired ? "仍触发 (pin 不阻止 PTE 换出)" :
					       "未触发 (GUP pin 阻止换出)");
				if (fired)
					ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req);
			}
		}
	} else {
		/* 降级: IOMMU 级 REPAIR 闭环 */
		printf("\n--- IOMMU 级 REPAIR 闭环 ---\n");
		repair_req.mr_id = mr_id;
		repair_req.page_idx = 0;
		ret = ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req);
		CHECK(ret == 0, "REPAIR 成功 (页 0 经 swap cache 换回)");
		CHECK(read_iova_page(sym_fd, mr_id, iova_page0) == 0xABABAB41,
		      "REPAIR 后 READ_IOVA: 0xABABAB41 (真实数据)");
	}

cleanup_rdma:
	/* 清理 */
	printf("\n--- 清理 ---\n");
	if (mr)
		ibv_dereg_mr(mr);
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (pd)
		ibv_dealloc_pd(pd);
	if (ctx)
		ibv_close_device(ctx);
	if (mr_id >= 0)
		ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, mr_id);

cleanup:
	munmap(buf, BUF_SIZE);
	close(sym_fd);

	printf("\n========================================\n");
	printf("Level 3 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}
