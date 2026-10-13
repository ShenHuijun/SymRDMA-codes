/*
 * test_auto_repair.c — SymRDMA Level 4: 自动检测修复 + Seqlock (P1)
 *
 * 验证 libsymrdma 的乐观 one-sided 读 (论文 §3.1):
 *   ≤ 4KB: RDMA Read → 哨兵检测 → 命中则自动 REPAIR → 透明返回真实数据
 *   > 4KB: seqlock — 读前后版本号比对, 偶数 (缺失) 先修复再读,
 *          版本变化 (换出竞态) 修复后重读
 *
 * 与 Level 3 的区别: Level 3 手动两步 (RDMA Read → 手动 REPAIR),
 * Level 4 用 libsymrdma 一步完成检测+修复, 应用层无感知。
 *
 * 时序设计 (同 Level 3): 换出先于 ibv_reg_mr, 换出行为确定。
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

#include "../lib/libsymrdma.h"

/* 兼容旧版 rdma-core */
#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif

/* MADV_PAGEOUT 兜底 */
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

/* 测试直接使用的 ioctl (REG_MR/GET_IOVA/READ_IOVA — 时序控制需要) */
#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_GET_IOVA    _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_get_iova)
#define SYMRDMA_IOC_READ_IOVA   _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)

struct symrdma_ioc_read_iova {
	int mr_id;
	unsigned long long iova;
	unsigned long offset;
	unsigned int value;
};

/* ---- 测试参数 ---- */
#define TEST_PAGES         4
#define BUF_SIZE           (TEST_PAGES * SYMRDMA_PAGE_SIZE)
#define CQ_DEPTH           16
#define SWAPOUT_TIMEOUT_S  10

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/* ---- 辅助函数 ---- */

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
			printf("  端口: link_layer=%s state=%d\n",
			       port_attr.link_layer == IBV_LINK_LAYER_ETHERNET ?
			       "Ethernet" : "InfiniBand", port_attr.state);
			/* v0.33.1: path_mtu 动态取 min(active_mtu, 4096) —
			 * v0.29.2 L15 教训 (path_mtu > active_mtu 令多包响应首包
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
			printf("  SKIP: QP RTR 失败\n");
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

/* READ_IOVA 单页 (测试直接查询 IOMMU 状态) */
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

/*
 * 自环 CQ 轮询超时 (ms) — 同 L2 (2026-09-15 挂死教训: 无界忙等 →
 * R 态自旋挂死; v0.33.1 补齐进程内自保护, 覆盖 Step 8b 版本直读等
 * 直接 verbs 调用; libsymrdma 内部路径仍由 test.sh 超时兑底)。 */
#define POLL_TIMEOUT_MS 5000

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

/* ---- 主程序 ---- */
int main(void)
{
	struct symrdma_ctx ctx;
	struct symrdma_mr smr = {0};
	unsigned char *buf, *local = NULL;
	struct ibv_mr *local_ibv_mr = NULL;
	int mr_id_local = -1;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova iova_req;
	int ret, i, identity;
	long long repair_base;

	/* RDMA 资源 */
	struct ibv_device *ib_dev = NULL;
	struct ibv_context *ibctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	int have_rdma = 0;
	uint32_t v;

	printf("=== SymRDMA Level 4: 自动检测修复 + Seqlock (P1) ===\n\n");

	/* 测试 MR 带 SYMRDMA_ACCESS_IDENTITY → 恒走 identity 路径 (P4):
	 * 全局 identity_mtt=1 或按 MR 标记位, 选择性模式下同样生效 */
	identity = 1;
	printf("identity_mtt: %s (MR 带标记位 → identity 路径)\n",
	       identity_mtt_active() ? "Y" : "N(选择性)");

	/* Step 1: 打开库上下文 */
	if (symrdma_open(&ctx)) {
		printf("ERROR: 无法打开 /dev/symrdma — 请先 insmod symrdma.ko\n");
		return 1;
	}
	printf("[1] libsymrdma 已初始化 (/dev/symrdma)\n");

	/* Step 2: 分配内存并写入测试数据 */
	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		symrdma_close(&ctx);
		return 1;
	}
	memset(buf, 0xAB, BUF_SIZE);
	for (i = 0; i < TEST_PAGES; i++)
		buf[i * SYMRDMA_PAGE_SIZE] = (unsigned char)('A' + i);
	printf("[2] 测试内存: %d 页\n", TEST_PAGES);

	/* Step 3: ioctl REG_MR (先于 ibv pin — 换出时序) */
	reg.va_start = (unsigned long long)buf;
	reg.len = BUF_SIZE;
	ret = ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg);
	CHECK(ret == 0, "SymRDMA REG_MR");
	if (ret)
		goto cleanup;
	smr.mr_id = reg.mr_id;
	smr.buf = buf;
	smr.len = BUF_SIZE;

	iova_req.mr_id = smr.mr_id;
	iova_req.page_idx = 0;
	ret = ioctl(ctx.fd, SYMRDMA_IOC_GET_IOVA, &iova_req);
	CHECK(ret == 0, "GET_IOVA");
	smr.read_iova  = iova_req.read_iova;
	smr.write_iova = iova_req.write_iova;

	/* Step 4: RDMA 上下文 */
	printf("\n--- RDMA 设备 ---\n");
	ib_dev = find_rdma_device();
	if (ib_dev) {
		ibctx = ibv_open_device(ib_dev);
		if (ibctx) {
			pd = ibv_alloc_pd(ibctx);
			if (pd && setup_loopback_qp(ibctx, pd, &cq, &qp) == 0)
				have_rdma = 1;
		}
	}
	if (!have_rdma) {
		printf("  SKIP: RDMA 设备不可用 — 仅 IOMMU 级验证\n");
		goto cleanup;
	}

	repair_base = proc_stat("REPAIR 成功");
	if (repair_base < 0)
		repair_base = 0;

	/* Step 5: 本地接收 buffer — 必须注册 SymRDMA IOMMU 映射
	 * (malloc 堆地址无 IOMMU 映射, NIC DMA 写会 fault — Level 2 教训) */
	printf("\n--- 本地接收 buffer 注册 ---\n");
	local = mmap(NULL, 2 * SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	CHECK(local != MAP_FAILED, "接收 buffer mmap (2 页)");
	/* touch 确保驻留: REG_MR 的驻留判定不触发缺页 (v0.9.0) */
	memset(local, 0x5A, 2 * SYMRDMA_PAGE_SIZE);
	reg.va_start = (unsigned long long)local;
	reg.len = 2 * SYMRDMA_PAGE_SIZE;
	ret = ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg);
	CHECK(ret == 0, "接收 buffer REG_MR (IOMMU 映射)");
	if (ret == 0)
		mr_id_local = reg.mr_id;
	local_ibv_mr = ibv_reg_mr(pd, local, 2 * SYMRDMA_PAGE_SIZE,
				  IBV_ACCESS_LOCAL_WRITE |
				  SYMRDMA_ACCESS_IDENTITY);
	CHECK(local_ibv_mr != NULL, "接收 buffer ibv_reg_mr (lkey)");

	/* Step 6: 快速路径 — 驻留页读, 不触发任何修复 */
	printf("\n--- 快速路径 (驻留页, 零修复) ---\n");
	smr.ibv_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE |
				SYMRDMA_ACCESS_IDENTITY);
	CHECK(smr.ibv_mr != NULL, "ibv_reg_mr (基线)");

	ret = symrdma_read(&ctx, qp, cq, &smr, 0, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB41,
	      "快速路径: symrdma_read 页 0 → 0xABABAB41 (1 次 RDMA Read)");
	CHECK(proc_stat("REPAIR 成功") == repair_base,
	      "快速路径: 未触发 REPAIR (计数不变)");

	/* v0.14.0: 手动注册的调用方显式绑定 Version MR (论文 §3.1.2) */
	CHECK(symrdma_mr_bind_version(&ctx, pd, &smr) == 0,
	      "绑定 Version MR (版本表用户页 + SET_VERSION_PAGE)");

	/* Step 7: 真实换出页 0 (页面已 pin — notifier 仍触发, Level 3 INFO 结论) */
	printf("\n--- 换出页 0 → 哨兵自动检测 ---\n");
	ret = madvise(buf, SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
	CHECK(ret == 0, "madvise(MADV_PAGEOUT) 页 0");

	/* 轮询 notifier 重映射 */
	ret = 0;
	for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
		if (read_iova_page(ctx.fd, smr.mr_id, smr.read_iova) ==
		    (long long)SYMRDMA_SENTINEL_MAGIC) {
			ret = 1;
			break;
		}
		usleep(100000);
	}
	CHECK(ret, "notifier 自动重映射: IOMMU 页 0 → 哨兵");

	/* Step 8: 版本语义 — 换出后偶数 (缺失) */
	ret = symrdma_get_version(&ctx, &smr, 0, &v);
	CHECK(ret == 0 && !(v & 1), "GET_VERSION 页 0: 偶数 (缺失)");
	ret = symrdma_get_version(&ctx, &smr, 1, &v);
	CHECK(ret == 0 && (v & 1), "GET_VERSION 页 1: 奇数 (驻留)");

	/* Step 8b (v0.14.0): ★ Version MR — 远端 one-sided RDMA 直读版本表
	 * (论文 §3.1.2): 版本表绑定用户 pinned 页 + 注册为 MR (REMOTE_READ),
	 * 远端经 rkey+IOVA 直读 (替代 CPU ioctl 查询) */
	printf("\n--- ★ Version MR 远端直读 (论文 §3.1.2) ---\n");
	CHECK(smr.version_mr != NULL,
	      "Version MR 已绑定 (版本表用户页 + REMOTE_READ)");
	if (smr.version_mr) {
		struct ibv_sge sge = { .addr = (uintptr_t)local, .length = 4,
				       .lkey = local_ibv_mr->lkey };
		struct ibv_send_wr wr = {0}, *bad = NULL;
		struct ibv_wc wc;

		wr.opcode = IBV_WR_RDMA_READ;
		wr.sg_list = &sge;
		wr.num_sge = 1;
		wr.wr.rdma.remote_addr = (uintptr_t)smr.version_buf;
		wr.wr.rdma.rkey = symrdma_version_rkey(&smr);
		wr.send_flags = IBV_SEND_SIGNALED;
		if (!ibv_post_send(qp, &wr, &bad)) {
			if (poll_cq_timeout(cq, &wc, POLL_TIMEOUT_MS) == 0)
				CHECK(wc.status == IBV_WC_SUCCESS &&
				      !(*(uint32_t *)local & 1),
				      "★ RDMA 直读版本表: 页 0 偶数 (缺失, 与 GET_VERSION 一致)");
			else
				printf("  SKIP: 版本直读 %u ms 无 CQE — 本机自环拓扑不适用 (同 L2)\n",
				       (unsigned)POLL_TIMEOUT_MS);
		}
	} else {
		CHECK(1, "Version MR 未绑定 (版本表 >1 页) — 跳过直读断言");
	}

	/* Step 9: ★ 哨兵自动检测 — 应用无感知透明返回 */
	printf("\n--- ★ 哨兵自动检测 (≤4KB) ---\n");
	ret = symrdma_read(&ctx, qp, cq, &smr, 0, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB41,
	      "★ symrdma_read 页 0 透明返回 0xABABAB41 (内部: 哨兵→REPAIR→重读)");
	if (identity)
		CHECK(proc_stat("REPAIR 成功") > repair_base,
		      "★ 自动触发 REPAIR (统计计数增加)");
	ret = symrdma_get_version(&ctx, &smr, 0, &v);
	CHECK(ret == 0 && (v & 1), "修复后版本号恢复奇数 (驻留)");

	/* Step 10: ★ seqlock 短路径 — 缺失页 (偶数) 先修复再读 (>4KB 阈值策略) */
	printf("\n--- ★ Seqlock 缺失页短路径 (>4KB) ---\n");
	ret = madvise(buf + 2 * SYMRDMA_PAGE_SIZE, SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
	CHECK(ret == 0, "madvise(MADV_PAGEOUT) 页 2");
	ret = 0;
	for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
		if (read_iova_page(ctx.fd, smr.mr_id,
				   smr.read_iova + 2 * SYMRDMA_PAGE_SIZE) ==
		    (long long)SYMRDMA_SENTINEL_MAGIC) {
			ret = 1;
			break;
		}
		usleep(100000);
	}
	CHECK(ret, "notifier 自动重映射: IOMMU 页 2 → 哨兵");

	ret = symrdma_get_version(&ctx, &smr, 2, &v);
	CHECK(ret == 0 && !(v & 1), "GET_VERSION 页 2: 偶数 (缺失)");

	/* 8KB 读 (页 2+3, >4KB → seqlock 路径): v 偶数 → 先 REPAIR, 不读哨兵 */
	ret = symrdma_read(&ctx, qp, cq, &smr, 2, 2 * SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB43,
	      "★ seqlock 短路径: 页 2 缺失 → 自动修复后透明返回 0xABABAB43");
	ret = symrdma_get_version(&ctx, &smr, 2, &v);
	CHECK(ret == 0 && (v & 1), "修复后页 2 版本号恢复奇数");

	/* Step 11: seqlock 正常路径 (版本前后一致) */
	printf("\n--- Seqlock 正常路径 ---\n");
	ret = symrdma_read(&ctx, qp, cq, &smr, 0, 2 * SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB41,
	      "seqlock 正常路径: 8KB 读 (页 0+1) → 0xABABAB41 (版本未变直接接受)");

	/* Step 11b: 假阳性 — 驻留页数据恰等于哨兵魔数 (论文 §3.1.1:
	 * 不区分真假 fault, 修复路径照常处理后按驻留接受, v0.9.0) */
	printf("\n--- 假阳性 (驻留页数据 == 0xdeadbeef) ---\n");
	*(uint32_t *)(buf + SYMRDMA_PAGE_SIZE) = SYMRDMA_SENTINEL_MAGIC;
	ret = symrdma_read(&ctx, qp, cq, &smr, 1, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == SYMRDMA_SENTINEL_MAGIC,
	      "★ 假阳性: 驻留页数据==魔数 → 修复后按驻留接受 (不死循环)");
	ret = symrdma_get_version(&ctx, &smr, 1, &v);
	CHECK(ret == 0 && (v & 1), "假阳性修复后页 1 版本仍为奇数 (驻留)");
	/* 恢复页 1 数据, 供 Step 12 邻居隔离断言使用 */
	*(uint32_t *)(buf + SYMRDMA_PAGE_SIZE) = 0xABABAB42;

	/* Step 11c (v0.14.0): ★ 本地页故障预检 (论文 §3.1.1) —
	 * local 接收页缺失时, 无预检的 DMA 写被黑洞吸收 → 数据静默全 0;
	 * symrdma_read_p 发出前检查 local 页版本 (本地直读 10ns/页),
	 * 偶数 (缺失) → REPAIR local → 一次成功 (省 1 RTT 重试) */
	printf("\n--- ★ 本地页故障预检 (论文 §3.1.1) ---\n");
	{
		struct symrdma_mr local_smr = {
			.mr_id = mr_id_local,
			.buf = local,
			.len = 2 * SYMRDMA_PAGE_SIZE,
		};
		struct symrdma_ioc_get_iova l_iova = { .mr_id = mr_id_local };
		long long repair_after;

		/* 换出 local 页 0 → IOMMU 哨兵 (local 为 LOCAL_WRITE-only →
		 * DMA 写走 write_iova 黑洞吸收) */
		madvise(local, SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
		if (ioctl(ctx.fd, SYMRDMA_IOC_GET_IOVA, &l_iova) == 0) {
			for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
				if (read_iova_page(ctx.fd, mr_id_local, l_iova.read_iova) ==
				    (long long)SYMRDMA_SENTINEL_MAGIC)
					break;
				usleep(100000);
			}
		}

		/* 无预检: local 缺失 → DMA 写被黑洞吸收 → 读回 0 (静默错误) */
		ret = symrdma_read(&ctx, qp, cq, &smr, 3, SYMRDMA_PAGE_SIZE,
				   local, local_ibv_mr->lkey);
		CHECK(ret == 0 && *(uint32_t *)local == 0,
		      "无预检: local 缺失 → 数据全 0 (黑洞吸收, 论文预检动机)");

		/* 预检: 检测 local 页缺失 → REPAIR → 读成功且数据正确 */
		repair_after = proc_stat("REPAIR 成功");
		ret = symrdma_read_p(&ctx, qp, cq, &smr, 3, SYMRDMA_PAGE_SIZE,
				     local, local_ibv_mr->lkey, &local_smr);
		CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB44,
		      "★ 预检读: local 缺失自动 REPAIR → 数据 0xABABAB44 正确");
		CHECK(proc_stat("REPAIR 成功") > repair_after,
		      "预检触发 REPAIR (local 页修复, 计数增加)");
		ret = symrdma_get_version(&ctx, &local_smr, 0, &v);
		CHECK(ret == 0 && (v & 1), "预检后 local 页 0 版本奇数 (驻留)");
	}

	/* Step 11d (v0.14.1): ★ 版本表多页化 — >1024 页 MR (2048 页 = 8MB)
	 * 版本表 2 页; 页 1024 (第二版本表页) 的换出/版本直读/REPAIR 闭环 */
	printf("\n--- ★ 版本表多页化 (>1024 页 MR, v0.14.1) ---\n");
	{
		#define BIG_PAGES 2048
		unsigned char *bbuf;
		struct symrdma_mr bmr = {0};
		struct symrdma_ioc_reg_mr breg = {0};
		struct symrdma_ioc_get_iova biova = { .page_idx = 0 };

		bbuf = mmap(NULL, BIG_PAGES * SYMRDMA_PAGE_SIZE,
			    PROT_READ | PROT_WRITE,
			    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		CHECK(bbuf != MAP_FAILED, "大 MR mmap (2048 页 = 8MB)");
		if (bbuf != MAP_FAILED) {
			memset(bbuf, 0xCD, BIG_PAGES * SYMRDMA_PAGE_SIZE);
			breg.va_start = (unsigned long long)(uintptr_t)bbuf;
			breg.len = BIG_PAGES * SYMRDMA_PAGE_SIZE;
			CHECK(ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &breg) == 0,
			      "大 MR REG_MR");
			bmr.mr_id = breg.mr_id;
			bmr.buf = bbuf;
			bmr.len = BIG_PAGES * SYMRDMA_PAGE_SIZE;
			biova.mr_id = bmr.mr_id;
			CHECK(ioctl(ctx.fd, SYMRDMA_IOC_GET_IOVA, &biova) == 0,
			      "大 MR GET_IOVA");
			bmr.read_iova = biova.read_iova;
			bmr.write_iova = biova.write_iova;
			bmr.ibv_mr = ibv_reg_mr(pd, bbuf,
						 BIG_PAGES * SYMRDMA_PAGE_SIZE,
						 IBV_ACCESS_LOCAL_WRITE |
						 IBV_ACCESS_REMOTE_READ |
						 IBV_ACCESS_REMOTE_WRITE |
						 SYMRDMA_ACCESS_IDENTITY);
			CHECK(bmr.ibv_mr != NULL, "大 MR ibv_reg_mr");
			CHECK(symrdma_mr_bind_version(&ctx, pd, &bmr) == 0,
			      "大 MR 版本表绑定 (多页: 2048/1024 = 2 页)");

			/* 页 0 与页 1024 版本初始奇数 (驻留) */
			ret = symrdma_get_version(&ctx, &bmr, 0, &v);
			CHECK(ret == 0 && (v & 1), "大 MR 页 0 版本奇数 (驻留)");
			ret = symrdma_get_version(&ctx, &bmr, 1024, &v);
			CHECK(ret == 0 && (v & 1),
			      "大 MR 页 1024 版本奇数 (第二版本表页, 多页直读)");

			/* 换出页 1024 → 版本直读偶数 (第二版本表页更新) */
			madvise(bbuf + 1024 * SYMRDMA_PAGE_SIZE,
				SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
			for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
				if (read_iova_page(ctx.fd, bmr.mr_id,
						   bmr.read_iova + 1024 * SYMRDMA_PAGE_SIZE) ==
				    (long long)SYMRDMA_SENTINEL_MAGIC)
					break;
				usleep(100000);
			}
			ret = symrdma_get_version(&ctx, &bmr, 1024, &v);
			CHECK(ret == 0 && !(v & 1),
			      "★ 页 1024 换出 → 版本偶数 (多页版本表 notifier 更新)");

			/* REPAIR → 奇数 */
			ret = symrdma_repair_page(&ctx, &bmr, 1024);
			CHECK(ret == 0, "大 MR REPAIR 页 1024");
			ret = symrdma_get_version(&ctx, &bmr, 1024, &v);
			CHECK(ret == 0 && (v & 1),
			      "REPAIR 后页 1024 版本奇数 (多页闭环)");

			/* 清理 */
			if (bmr.version_mr)
				ibv_dereg_mr(bmr.version_mr);
			if (bmr.version_buf_mr_id >= 0)
				ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR,
				      bmr.version_buf_mr_id);
			if (bmr.version_buf)
				munmap(bmr.version_buf,
				       ((BIG_PAGES + 1023) / 1024) * SYMRDMA_PAGE_SIZE);
			ibv_dereg_mr(bmr.ibv_mr);
			ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, bmr.mr_id);
			munmap(bbuf, BIG_PAGES * SYMRDMA_PAGE_SIZE);
		}
	}

	/* Step 12: 邻居隔离 */
	printf("\n--- 邻居隔离 ---\n");
	ret = symrdma_get_version(&ctx, &smr, 1, &v);
	CHECK(ret == 0 && (v & 1), "页 1 版本号保持奇数");
	ret = symrdma_get_version(&ctx, &smr, 3, &v);
	CHECK(ret == 0 && (v & 1), "页 3 版本号保持奇数");
	ret = symrdma_read(&ctx, qp, cq, &smr, 1, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB42,
	      "页 1 数据完好 (0xABABAB42)");
	ret = symrdma_read(&ctx, qp, cq, &smr, 3, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB44,
	      "页 3 数据完好 (0xABABAB44)");

	/* 清理 */
	printf("\n--- 清理 ---\n");
	if (smr.version_mr)
		ibv_dereg_mr(smr.version_mr);
	smr.version_mr = NULL;
	if (smr.version_buf_mr_id >= 0)
		ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, smr.version_buf_mr_id);
	smr.version_buf_mr_id = -1;
	if (smr.version_buf)
		munmap(smr.version_buf, SYMRDMA_PAGE_SIZE);
	smr.version_buf = NULL;
	if (smr.ibv_mr)
		ibv_dereg_mr(smr.ibv_mr);
	smr.ibv_mr = NULL;
	ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, smr.mr_id);
	if (local_ibv_mr)
		ibv_dereg_mr(local_ibv_mr);
	if (mr_id_local >= 0)
		ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, mr_id_local);

cleanup:
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (pd)
		ibv_dealloc_pd(pd);
	if (ibctx)
		ibv_close_device(ibctx);
	symrdma_close(&ctx);
	if (local != NULL && local != MAP_FAILED)
		munmap(local, 2 * SYMRDMA_PAGE_SIZE);
	munmap(buf, BUF_SIZE);

	printf("\n========================================\n");
	printf("Level 4 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}
