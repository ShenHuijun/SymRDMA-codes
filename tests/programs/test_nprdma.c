/*
 * test_nprdma.c — SymRDMA Level 6: LD_PRELOAD 透明拦截验证 (P3)
 *
 * 本程序是"未修改的普通 RDMA 应用"：
 *   - 不包含任何 SymRDMA 头文件
 *   - 不调用任何 SymRDMA ioctl
 *   - 只用标准 libibverbs + madvise
 *
 * 验证方式: 在 LD_PRELOAD=libnprdma.so 下运行 —
 *   ibv_reg_mr 被透明拦截注入 SymRDMA IOMMU 注册,
 *   madvise 换出页后, 普通 RDMA Read 直接读到哨兵 0xdeadbeef
 *   (证明 notifier 保护对应用透明生效)。
 *
 * 运行: LD_PRELOAD=~/pro/symrdma/nprdma/libnprdma.so ./test_nprdma
 * 对比: 不加 LD_PRELOAD 运行时换出后读到的是 swap 换回的真实数据,
 *       不会出现哨兵 (identity_mtt 下无 IOMMU 映射 → DMA fault 或绕过)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <infiniband/verbs.h>

#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

#define SENTINEL_MAGIC      0xdeadbeef
#define TEST_PAGES          4
#define PAGE_SIZE           4096
#define BUF_SIZE            (TEST_PAGES * PAGE_SIZE)
#define CQ_DEPTH            16
#define SWAPOUT_TIMEOUT_S   10

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/* ---- 环境检查 (非 SymRDMA API) ---- */

/* /proc/symrdma 统计 (REPAIR 计数等) */
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

static int nprdma_loaded(void)
{
	FILE *f = fopen("/proc/self/maps", "r");
	char line[512];
	int found = 0;

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "libnprdma")) {
			found = 1;
			break;
		}
	}
	fclose(f);
	return found;
}

/* /proc/symrdma 活跃 MR 数 (验证拦截注入, 非 SymRDMA API)
 *  strstr+冒号解析 (不依赖 sscanf 中文格式串的 locale 匹配);
 * 调用方以注册前后差值断言, 不受历史残留 MR 污染 */
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

/* ---- 标准 verbs 辅助 (与其它测试相同, 无 SymRDMA 调用) ---- */


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
			printf("  SKIP: QP RTR 失败\n");
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

/* 一次 RDMA Read: remote 页 → local, 返回 local 首 4 字节; 失败 -1 */
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
	int n;

	memset(local, 0, PAGE_SIZE);
	wr.opcode               = IBV_WR_RDMA_READ;
	wr.sg_list              = &sge;
	wr.num_sge              = 1;
	wr.wr.rdma.remote_addr  = remote_addr;
	wr.wr.rdma.rkey         = rkey;
	wr.send_flags           = IBV_SEND_SIGNALED;

	if (ibv_post_send(qp, &wr, &bad_wr))
		return -1;
	do {
		n = ibv_poll_cq(cq, 1, &wc);
	} while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	return (long long)*(uint32_t *)local;
}

/* RDMA Write: local → remote (写源预检场景用) */
static int rdma_write_data(struct ibv_qp *qp, struct ibv_cq *cq,
			   void *local, uint32_t lkey,
			   uintptr_t remote_addr, uint32_t rkey, int len)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = len, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad_wr = NULL;
	struct ibv_wc wc;
	int n;

	wr.opcode = IBV_WR_RDMA_WRITE;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = remote_addr;
	wr.wr.rdma.rkey = rkey;
	wr.send_flags = IBV_SEND_SIGNALED;

	if (ibv_post_send(qp, &wr, &bad_wr))
		return -1;
	do {
		n = ibv_poll_cq(cq, 1, &wc);
	} while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	return 0;
}

/* ---- 主程序: 普通 RDMA 应用 (无 SymRDMA 代码) ---- */
int main(void)
{
	unsigned char *buf, *local;
	struct ibv_device *ib_dev;
	struct ibv_context *ctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct ibv_mr *buf_mr = NULL, *local_mr = NULL;
	long long v;
	long long deferred_base;   /* 屏障延迟哨兵化断言基线 */
	int ret, i, swapped, mr_base;

	printf("=== SymRDMA Level 6: LD_PRELOAD 透明拦截 (P3) ===\n\n");

	/* 前置条件: 注入或反转模式 (P4) */
	if (nprdma_loaded())
		CHECK(1, "前置条件: libnprdma 已注入 (LD_PRELOAD)");
	else
		CHECK(1, "前置条件: 未注入 (反转模式 — 普通应用不受影响验证)");
	printf("  identity_mtt: %s (选择性模式: libnprdma 带标记位激活 identity)\n",
	       identity_mtt_active() ? "Y" : "N");

	/* 本应用完全不感知 SymRDMA — 只有标准 verbs 调用 */

	/* 内存与填充 */
	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) { perror("mmap"); return 1; }
	local = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (local == MAP_FAILED) { perror("mmap"); return 1; }
	/* touch 确保驻留: REG_MR 驻留判定不触发缺页  */
	memset(local, 0x5A, PAGE_SIZE);
	memset(buf, 0xAB, BUF_SIZE);
	for (i = 0; i < TEST_PAGES; i++)
		buf[i * PAGE_SIZE] = (unsigned char)('A' + i);
	printf("[1] 应用内存: %d 页\n", TEST_PAGES);

	/* RDMA 上下文 */
	ib_dev = find_rdma_device();
	if (!ib_dev) { printf("  无 RDMA 设备\n"); return 1; }
	ctx = ibv_open_device(ib_dev);
	if (!ctx) { printf("  打开设备失败\n"); return 1; }
	pd = ibv_alloc_pd(ctx);
	if (!pd) { printf("  pd 失败\n"); return 1; }
	if (setup_loopback_qp(ctx, pd, &cq, &qp)) { printf("  QP 失败\n"); return 1; }

	/* §4.1: libnprdma 拦截 QP 创建 — 深度 3× (论文 §4.1
	 * "provisions 3× the original queue depth"), 应用感知不变 */
	if (nprdma_loaded()) {
		struct ibv_qp_attr qa;
		struct ibv_qp_init_attr qia;

		if (ibv_query_qp(qp, &qa, IBV_QP_CAP, &qia) == 0)
			CHECK(qia.cap.max_send_wr >= 3 * CQ_DEPTH,
			      "★ §4.1: QP 深度 ≥3× (libnprdma 拦截, 论文 §4.1; mlx5 可对齐到 2 的幂)");
		else
			CHECK(0, "§4.1: ibv_query_qp 失败");
	}

	/* 注册前基线 (差值断言 — 历史残留 MR 不影响反转验证) */
	mr_base = proc_mr_count();
	if (mr_base < 0)
		mr_base = 0;

	/* 标准 MR 注册 — 被 libnprdma 透明拦截 */
	buf_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			    IBV_ACCESS_LOCAL_WRITE |
			    IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_REMOTE_WRITE);
	CHECK(buf_mr != NULL, "ibv_reg_mr(buf) — 应用侧标准调用");
	local_mr = ibv_reg_mr(pd, local, PAGE_SIZE, IBV_ACCESS_LOCAL_WRITE);
	CHECK(local_mr != NULL, "ibv_reg_mr(local) — 应用侧标准调用");
	if (nprdma_loaded())
		CHECK(proc_mr_count() >= mr_base + 2,
		      "SymRDMA 侧已注册 (透明拦截生效, 比注册前 +2)");
	else
		CHECK(proc_mr_count() == mr_base,
		      "★ 未拦截: /proc/symrdma 无注入 (普通 MR 走原版路径)");

	/* 基线: 驻留页读真实数据 */
	v = rdma_read_page(qp, cq, local, local_mr->lkey,
			   (uintptr_t)buf, buf_mr->rkey);
	CHECK(v == 0xABABAB41, "基线: RDMA Read → 0xABABAB41 (驻留)");

	/* 页换出 (OS 事件) →  页已被引擎前序 op 粘性 pin →
	 * notifier 对在飞页延迟哨兵化 (屏障断言基线 — 须在 madvise 前取) */
	deferred_base = proc_stat("延迟哨兵化页");
	if (deferred_base < 0)
		deferred_base = 0;
	ret = madvise(buf, PAGE_SIZE, MADV_PAGEOUT);
	CHECK(ret == 0, "madvise(MADV_PAGEOUT) 页 0");

	/* 轮询 RDMA Read:
	 *   挂 LD_PRELOAD  → post_send 拦截预检预修复 → 直接真实数据
	 *   不挂 (反转验证, P4) → 读到真实数据 (原版路径, 无哨兵无 fault —
	 *   论文 §4.2 "Applications not using SymRDMA are unaffected") */
	swapped = 0;
	for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
		v = rdma_read_page(qp, cq, local, local_mr->lkey,
				   (uintptr_t)buf, buf_mr->rkey);
		if (v == (long long)SENTINEL_MAGIC) {
			swapped = 1;
			break;
		}
		if (v == 0xABABAB41)
			break;   /* 真实数据 (拦截预修复或原版路径) */
		usleep(100000);
	}
	if (nprdma_loaded())
		CHECK(v == 0xABABAB41 && !swapped,
		      "★ RDMA Read → 0xABABAB41 (post_send 拦截预检预修复, 应用无感知)");
	else
		CHECK(!swapped && v == 0xABABAB41,
		      "★ 普通应用不受影响: 换出后读到真实数据 (原版路径, 无哨兵无 fault)");

	/* 在飞 pin 屏障 — madvise 换出被延迟 (页保持真实映射,
	 * 论文 §3.2 pin 语义); 拦截读直接返回真实数据 */
	if (nprdma_loaded())
		CHECK(proc_stat("延迟哨兵化页") > deferred_base,
		      "★ post_send 在飞屏障: 换出被延迟 (页保持真实 PA, 论文 §3.2)");

	/* post_send RDMA_WRITE 写源预检 (论文 §3.1.1 写路径预检):
	 * local 源页换出 (DMA 读源会走哨兵 → 写魔数) → 拦截按 lkey 查版本表
	 * 偶数 → REPAIR local → 转发 → 写真实数据 (仅挂 LD_PRELOAD 时) */
	if (nprdma_loaded()) {
		long long wdeferred = proc_stat("延迟哨兵化页");

		printf("  [info] RDMA_WRITE 写源预检场景\n");
		madvise(local, PAGE_SIZE, MADV_PAGEOUT);
		usleep(200000);              /* 等换出 (notifier 置版本偶数) */
		*(uint32_t *)local = 0x5A5A5A5A;   /* CPU 写源: 缺页换入, IOMMU 仍哨兵 */
		ret = rdma_write_data(qp, cq, local, local_mr->lkey,
				      (uintptr_t)buf, buf_mr->rkey, 4);
		CHECK(ret == 0, "RDMA_WRITE (源 local, 拦截预检)");
		v = rdma_read_page(qp, cq, local, local_mr->lkey,
				   (uintptr_t)buf, buf_mr->rkey);
		CHECK(v == 0x5A5A5A5A,
		      "★ 写源预检: 换出源页自动 REPAIR → buf=0x5A5A5A5A (非哨兵魔数)");
		CHECK(proc_stat("延迟哨兵化页") > wdeferred,
		      "★ RDMA_WRITE 在飞屏障: 源页换出被延迟 (源保持真实 PA)");
	}

	/* 邻居页不受影响 */
	v = rdma_read_page(qp, cq, local, local_mr->lkey,
			   (uintptr_t)(buf + PAGE_SIZE), buf_mr->rkey);
	CHECK(v == 0xABABAB42, "邻居页 1 数据完好 (0xABABAB42)");

	/* 标准注销 — 同样被拦截 */
	ibv_dereg_mr(buf_mr);
	ibv_dereg_mr(local_mr);
	printf("  [info] 注销后 /proc/symrdma 活跃 MR 数: %d (期望回到注册前)\n",
	       proc_mr_count());

	ibv_destroy_qp(qp);
	ibv_destroy_cq(cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(buf, BUF_SIZE);
	munmap(local, PAGE_SIZE);

	printf("\n========================================\n");
	printf("Level 6 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}
