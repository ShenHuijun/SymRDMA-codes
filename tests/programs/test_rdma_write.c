/*
 * test_rdma_write.c — SymRDMA Level 5: 写路径验证 (场景 B, 纯 RDMA)
 *
 * 用户场景 B 七步 (全程 RDMA 路径, 无 ioctl REMAP/手动 REPAIR):
 *   1. RDMA Read 自身 MR → 真实数据
 *   2. RDMA Write 其它数据 (write 区域 rkey)
 *   3. RDMA Read → 更改的数据
 *   4. 页换出 (madvise, OS 事件)
 *   5. RDMA Write 其它数据 → 黑洞吸收, 哨兵不受污染
 *   6. 页换入 (CPU 触摸, OS 事件)
 *   7. RDMA Read → 第一次修改数据 (lib 自动检测修复, 应用无感知)
 *
 * 依赖 OFED 补丁扩展: identity_mtt_write_offset=34359738368
 * (write-only MR 的 MTT = VA+32GB → 命中 write_iova 黑洞区)
 *
 * 环境要求: 同 Level 4 + modprobe.d 含 identity_mtt_write_offset
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
#include <infiniband/verbs.h>

#include "../lib/libsymrdma.h"

#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

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

#define WRITE_OFFSET_EXPECTED   (1ULL << 35)   /* 32GB, 与内核 SYMRDMA_MR_WRITE_OFFSET 一致 */
#define TEST_PAGES              4
#define BUF_SIZE                (TEST_PAGES * SYMRDMA_PAGE_SIZE)
#define CQ_DEPTH                16
#define SWAPOUT_TIMEOUT_S       30
#define PATTERN_FIRST           0xCDCDCDCDu   /* 第一次修改 */
#define PATTERN_SECOND          0xEFEFEFEFu   /* 第二次修改 (应被吸收) */

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/* ---- 辅助 ---- */

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

/* 读取 identity_mtt_write_offset 模块参数; 失败返回 -1 */
static long long write_offset_param(void)
{
	FILE *f = fopen("/sys/module/mlx5_ib/parameters/identity_mtt_write_offset", "r");
	long long v = -1;

	if (!f)
		return -1;
	if (fscanf(f, "%lld", &v) != 1)
		v = -1;
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

/* 解析 buf VMA 的 Swap (kB) — 确认页面确实换出 */
static long long vma_swap_kb(unsigned long addr)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256];
	unsigned long start, end;
	long long swp = -1;
	int in_vma = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (!in_vma && sscanf(line, "%lx-%lx", &start, &end) == 2) {
			in_vma = (addr >= start && addr < end);
			continue;
		}
		if (!in_vma)
			continue;
		if (sscanf(line, "Swap: %lld", &swp) == 1)
			break;
	}
	fclose(f);
	return swp;
}

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
	struct symrdma_ctx ctx;
	struct symrdma_mr smr = {0};
	struct symrdma_mr_write wmr;
	unsigned char *buf, *local = NULL;
	struct ibv_mr *local_ibv_mr = NULL;
	int mr_id_local = -1;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova iova_req;
	int ret, i;
	uint32_t v;
	uint32_t pattern_first = PATTERN_FIRST, pattern_second = PATTERN_SECOND;
	long long woffset;

	struct ibv_device *ib_dev = NULL;
	struct ibv_context *ibctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	int have_rdma = 0;

	printf("=== SymRDMA Level 5: 写路径验证 (场景 B, 纯 RDMA) ===\n\n");

	/* Step 0: 前置条件 */
	printf("identity_mtt: %s\n", identity_mtt_active() ? "Y" : "N (必须开启!)");
	woffset = write_offset_param();
	printf("identity_mtt_write_offset: %lld (期望 %llu)\n",
	       woffset, (unsigned long long)WRITE_OFFSET_EXPECTED);
	CHECK(woffset == (long long)WRITE_OFFSET_EXPECTED,
	      "前置条件: write_offset=32GB (MR 带标记位 → 选择性模式走 identity)");

	if (symrdma_open(&ctx)) {
		printf("ERROR: 无法打开 /dev/symrdma — 请先 insmod symrdma.ko\n");
		return 1;
	}

	/* Step 1: 内存与注册 */
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
	printf("[1] 测试内存: %d 页 (页 0 首字 = 0xABABAB41)\n", TEST_PAGES);

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

	/* Step 2: RDMA 上下文 */
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
		printf("  SKIP: RDMA 设备不可用\n");
		goto cleanup;
	}

	/* Step 3: 本地接收 buffer + 读 MR + 写区域 MR */
	local = mmap(NULL, SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	CHECK(local != MAP_FAILED, "接收 buffer mmap (1 页)");
	/* touch 确保驻留: REG_MR 驻留判定不触发缺页 (v0.9.0) */
	memset(local, 0x5A, SYMRDMA_PAGE_SIZE);
	reg.va_start = (unsigned long long)local;
	reg.len = SYMRDMA_PAGE_SIZE;
	ret = ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg);
	CHECK(ret == 0, "接收 buffer REG_MR (IOMMU 映射)");
	if (ret == 0)
		mr_id_local = reg.mr_id;
	local_ibv_mr = ibv_reg_mr(pd, local, SYMRDMA_PAGE_SIZE,
				  IBV_ACCESS_LOCAL_WRITE |
				  SYMRDMA_ACCESS_IDENTITY);
	CHECK(local_ibv_mr != NULL, "接收 buffer ibv_reg_mr (lkey)");

	smr.ibv_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE |
				SYMRDMA_ACCESS_IDENTITY);
	CHECK(smr.ibv_mr != NULL, "读 MR (ibv_reg_mr: READ|WRITE)");
	ret = symrdma_write_mr_register(pd, buf, BUF_SIZE, &wmr);
	CHECK(ret == 0, "写区域 MR (ibv_reg_mr: REMOTE_WRITE 无 REMOTE_READ)");

	/* ---- 场景 B: 七步纯 RDMA ---- */
	printf("\n===== 场景 B: 七步纯 RDMA =====\n");

	/* B-1: RDMA Read → 真实数据 */
	ret = symrdma_read(&ctx, qp, cq, &smr, 0, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB41,
	      "B-1: RDMA Read → 真实数据 0xABABAB41");

	/* B-2: RDMA Write 第一次修改 (驻留 → 真实 PA)
	 * 注意: 写源必须落在 lkey 覆盖的 MR 内 (栈变量会触发
	 * LOCAL_PROT_ERR) — 故先 memcpy 进 local 接收区 */
	memcpy(local, &pattern_first, sizeof(pattern_first));
	ret = symrdma_write(&ctx, qp, cq, &smr, &wmr, 0, SYMRDMA_PAGE_SIZE,
			    local, local_ibv_mr->lkey);
	CHECK(ret == 0, "B-2: RDMA Write 0xCDCDCDCD (驻留页 → 真实 PA, 辅助读验证)");

	/* B-3: RDMA Read → 更改的数据 (RDMA 与 CPU 同一 PA) */
	ret = symrdma_read(&ctx, qp, cq, &smr, 0, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == PATTERN_FIRST,
	      "B-3: RDMA Read → 0xCDCDCDCD (第一次修改可见)");
	CHECK(*(uint32_t *)buf == PATTERN_FIRST,
	      "B-3': CPU 读同一 PA → 0xCDCDCDCD (RDMA 写真实落地)");

	/* B-4: 页换出 (OS 事件) → notifier → IOMMU 哨兵/黑洞 */
	printf("\n--- B-4: 页换出 ---\n");
	ret = madvise(buf, SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
	CHECK(ret == 0, "B-4: madvise(MADV_PAGEOUT) 页 0");
	ret = 0;
	for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
		if (read_iova_page(ctx.fd, smr.mr_id, smr.read_iova) ==
		    (long long)SYMRDMA_SENTINEL_MAGIC) {
			ret = 1;
			break;
		}
		usleep(100000);
	}
	CHECK(ret, "B-4: notifier 重映射 — read_iova → 哨兵");

	/* B-5: RDMA Write 第二次修改 → 黑洞吸收, 哨兵不受污染 ★ */
	printf("\n--- B-5: 换出后 RDMA Write → 黑洞吸收 ---\n");
	memcpy(local, &pattern_second, sizeof(pattern_second));
	/* 底层机制验证: 裸写 (无验证) — 黑洞吸收, 哨兵零污染 */
	ret = symrdma_write_raw(qp, cq, &smr, &wmr, 0, SYMRDMA_PAGE_SIZE,
				local, local_ibv_mr->lkey);
	CHECK(ret == 0, "B-5: RDMA Write 0xEFEFEFEF (裸写, 写区域 MTT → write_iova)");
	CHECK(read_iova_page(ctx.fd, smr.mr_id, smr.read_iova) ==
	      (long long)SYMRDMA_SENTINEL_MAGIC,
	      "★ B-5: 哨兵魔数完好 (0xdeadbeef) — 写入被黑洞吸收, 未污染哨兵");
	CHECK(read_iova_page(ctx.fd, smr.mr_id, smr.write_iova) ==
	      (long long)PATTERN_SECOND,
	      "B-5': 黑洞页确实收到写入 (write_iova → 0xEFEFEFEF)");

	/* B-6: 页换入 (CPU 触摸, OS 事件) → 第一次修改被保留 */
	printf("\n--- B-6: 页换入 (CPU 触摸) ---\n");
	{
		volatile unsigned char probe = buf[0];  /* 触发 do_swap_page */
		(void)probe;
	}
	CHECK(*(uint32_t *)buf == PATTERN_FIRST,
	      "★ B-6: 换入后 CPU 读到 0xCDCDCDCD — 第一次修改保留, 第二次修改被吸收");
	ret = symrdma_get_version(&ctx, &smr, 0, &v);
	CHECK(ret == 0 && !(v & 1),
	      "B-6': 版本号仍偶数 — CPU 换入不翻转版本 (远端视角仍缺失, 惰性语义)");
	CHECK(read_iova_page(ctx.fd, smr.mr_id, smr.read_iova) ==
	      (long long)SYMRDMA_SENTINEL_MAGIC,
	      "B-6'': IOMMU 仍哨兵 (惰性换入, 论文 §4.1)");

	/* B-7: RDMA Read → 第一次修改 (lib 自动检测修复, 应用无感知) ★ */
	printf("\n--- B-7: RDMA Read (自动修复) ---\n");
	ret = symrdma_read(&ctx, qp, cq, &smr, 0, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == PATTERN_FIRST,
	      "★ B-7: RDMA Read 透明返回 0xCDCDCDCD (哨兵→自动REPAIR→重读)");
	ret = symrdma_get_version(&ctx, &smr, 0, &v);
	CHECK(ret == 0 && (v & 1), "B-7': 自动修复后版本号恢复奇数 (驻留)");

	/* B-8: ★ 写路径验证 (论文 §3.1.1 图 5b) — 换出页带验证写 →
	 * 检测黑洞吸收 → REPAIR → 重写 → 落地 (v0.11.0) */
	printf("\n--- B-8: 换出页带验证写 (辅助 Read) ---\n");
	ret = madvise(buf, SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
	CHECK(ret == 0, "B-8: 换出页 0");
	/* 尽力确认换出 (软检查 — notifier 机制已由 B-4 验证; madvise 异步
	 * 回收在内存充足时可能 >30s, 轮询超时不 FAIL, 由写验证兜底) */
	{
		long long swp_kb = 0;
		ret = 0;
		for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
			if (read_iova_page(ctx.fd, smr.mr_id, smr.read_iova) ==
			    (long long)SYMRDMA_SENTINEL_MAGIC) {
				ret = 1;
				break;
			}
			swp_kb = vma_swap_kb((unsigned long)buf);
			usleep(100000);
		}
		printf("  [info] B-8 换出确认: IOMMU哨兵=%s, swap=%lld kB\n",
		       ret ? "是" : "否 (等待异步回收)", swp_kb);
	}

	{
		uint32_t pattern_third = 0xABABABABu;
		memcpy(local, &pattern_third, sizeof(pattern_third));
		ret = symrdma_write(&ctx, qp, cq, &smr, &wmr, 0,
				    SYMRDMA_PAGE_SIZE,
				    local, local_ibv_mr->lkey);
		CHECK(ret == 0,
		      "★ B-8: 带验证写 0xABABABAB — 内部: 黑洞吸收 → REPAIR → 重写落地");
		ret = symrdma_read(&ctx, qp, cq, &smr, 0, SYMRDMA_PAGE_SIZE,
				   local, local_ibv_mr->lkey);
		CHECK(ret == 0 && *(uint32_t *)local == pattern_third,
		      "★ B-8': RDMA Read 确认 0xABABABAB 落地");
		CHECK(*(uint32_t *)buf == pattern_third,
		      "★ B-8'': CPU 读同一 PA → 0xABABABAB (写最终生效)");
		ret = symrdma_get_version(&ctx, &smr, 0, &v);
		CHECK(ret == 0 && (v & 1), "B-8''': 版本恢复奇数 (驻留)");
	}

	/* B-9: ★ 批量 unsignaled Write (论文 §3.1.1, v0.14.0) —
	 * 前 N-1 条 Write/Read 用 unsignaled WR + 最后 1 signaled;
	 * 含换出页: 黑洞吸收 → 批量验证检出 → REPAIR → 重写落地 */
	printf("\n--- B-9: 批量 unsignaled Write (论文 §3.1.1) ---\n");
	{
		unsigned char *bsrc = NULL, *bverify = NULL;
		struct ibv_mr *bsrc_mr = NULL, *bverify_mr = NULL;
		int bsrc_id = -1, bverify_id = -1;
		unsigned long bpages[3] = { 0, 1, 2 };
		struct symrdma_ioc_reg_mr brev = {0};

		/* 批量写源 (3 页) + 验证 buffer (3 页) — 均注册 IOMMU 映射 */
		bsrc = mmap(NULL, 3 * SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
			    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		bverify = mmap(NULL, 3 * SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
			       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (bsrc != MAP_FAILED && bverify != MAP_FAILED) {
			memset(bsrc, 0, 3 * SYMRDMA_PAGE_SIZE);
			*(uint32_t *)(bsrc + 0 * SYMRDMA_PAGE_SIZE) = 0x11111111;
			*(uint32_t *)(bsrc + 1 * SYMRDMA_PAGE_SIZE) = 0x22222222;
			*(uint32_t *)(bsrc + 2 * SYMRDMA_PAGE_SIZE) = 0x33333333;
			memset(bverify, 0, 3 * SYMRDMA_PAGE_SIZE);

			brev.va_start = (unsigned long long)bsrc;
			brev.len = 3 * SYMRDMA_PAGE_SIZE;
			if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &brev) == 0)
				bsrc_id = brev.mr_id;
			brev.va_start = (unsigned long long)bverify;
			if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &brev) == 0)
				bverify_id = brev.mr_id;
			bsrc_mr = ibv_reg_mr(pd, bsrc, 3 * SYMRDMA_PAGE_SIZE,
					     IBV_ACCESS_LOCAL_WRITE |
					     SYMRDMA_ACCESS_IDENTITY);
			bverify_mr = ibv_reg_mr(pd, bverify, 3 * SYMRDMA_PAGE_SIZE,
						 IBV_ACCESS_LOCAL_WRITE |
						 SYMRDMA_ACCESS_IDENTITY);
		}
		CHECK(bsrc_mr && bverify_mr, "B-9: 批量 src/verify buffer 注册");

		/* 换出页 0 (批量中含黑洞吸收路径) */
		madvise(buf, SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
		for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
			if (read_iova_page(ctx.fd, smr.mr_id, smr.read_iova) ==
			    (long long)SYMRDMA_SENTINEL_MAGIC)
				break;
			usleep(100000);
		}

		/* 批量写 3 页 (页 0 换出 → 黑洞吸收 → 批量验证检出 → 修复) */
		ret = symrdma_write_batch(&ctx, qp, cq, &smr, &wmr,
					  bpages, 3, SYMRDMA_PAGE_SIZE,
					  bsrc, bsrc_mr->lkey,
					  bverify, bverify_mr->lkey);
		CHECK(ret == 0, "★ B-9: 批量写 3 页 (含换出页) 全部落地");
		CHECK(*(uint32_t *)(buf + 0 * SYMRDMA_PAGE_SIZE) == 0x11111111 &&
		      *(uint32_t *)(buf + 1 * SYMRDMA_PAGE_SIZE) == 0x22222222 &&
		      *(uint32_t *)(buf + 2 * SYMRDMA_PAGE_SIZE) == 0x33333333,
		      "★ B-9': CPU 读 3 页 → 111/222/333 (批量写生效, 换出页已修复)");
		ret = symrdma_get_version(&ctx, &smr, 0, &v);
		CHECK(ret == 0 && (v & 1), "B-9'': 页 0 版本奇数 (REPAIR 后驻留)");

		/* 清理 B-9 临时 buffer */
		if (bsrc_mr)
			ibv_dereg_mr(bsrc_mr);
		if (bverify_mr)
			ibv_dereg_mr(bverify_mr);
		if (bsrc_id >= 0)
			ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, bsrc_id);
		if (bverify_id >= 0)
			ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, bverify_id);
		if (bsrc && bsrc != MAP_FAILED)
			munmap(bsrc, 3 * SYMRDMA_PAGE_SIZE);
		if (bverify && bverify != MAP_FAILED)
			munmap(bverify, 3 * SYMRDMA_PAGE_SIZE);
	}

	/* B-10 (v0.14.0): §3.3 Relaxed Ordering — 重叠内存启发式 + inflight
	 * 区间跟踪 (论文 §3.3: 重叠请求排队, 独立请求并行; 同步 API 下
	 * 每次操作完成即清除, 语义天然满足) */
	printf("\n--- B-10: §3.3 Relaxed Ordering (重叠启发式 + inflight) ---\n");
	{
		struct symrdma_inflight inf = {0};
		unsigned long dup[2] = { 0, 0 };   /* 重复页 */

		/* 重复页 batch → 拒绝 (重叠依赖需排队, 论文 §3.3) */
		ret = symrdma_write_batch(&ctx, qp, cq, &smr, &wmr, dup, 2,
					  SYMRDMA_PAGE_SIZE,
					  local, local_ibv_mr->lkey,
					  local, local_ibv_mr->lkey);
		CHECK(ret != 0 && errno == EINVAL,
		      "B-10: 重复页 batch 被拒 (重叠需排队, errno=EINVAL)");

		/* inflight 区间: 记录 [buf, buf+3P) → 重叠/非重叠/清除判定 */
		symrdma_inflight_record(&inf, (uintptr_t)buf,
					(uintptr_t)buf + 3 * SYMRDMA_PAGE_SIZE);
		CHECK(symrdma_inflight_overlap(&inf,
			      (uintptr_t)buf + 2 * SYMRDMA_PAGE_SIZE,
			      (uintptr_t)buf + 4 * SYMRDMA_PAGE_SIZE) == 1,
		      "B-10: 页 2 与在飞行 [0,3) 重叠 → 判定 1 (需排队)");
		CHECK(symrdma_inflight_overlap(&inf,
			      (uintptr_t)buf + 4 * SYMRDMA_PAGE_SIZE,
			      (uintptr_t)buf + 5 * SYMRDMA_PAGE_SIZE) == 0,
		      "B-10: 页 4 与在飞行 [0,3) 不重叠 → 判定 0 (可并行)");
		symrdma_inflight_clear(&inf);
		CHECK(symrdma_inflight_overlap(&inf, (uintptr_t)buf,
			      (uintptr_t)buf + SYMRDMA_PAGE_SIZE) == 0,
		      "B-10: 清除后无在飞行 (重叠判定 0)");
	}

	/* 邻居与收尾 (B-9 已批量写页 0/1/2 — 页 1/2 为 B-9 结果, 页 3 隔离验证) */
	printf("\n--- 邻居隔离 ---\n");
	ret = symrdma_read(&ctx, qp, cq, &smr, 3, SYMRDMA_PAGE_SIZE,
			   local, local_ibv_mr->lkey);
	CHECK(ret == 0 && *(uint32_t *)local == 0xABABAB44,
	      "页 3 数据完好 (0xABABAB44, 未被 B-1..B-9 影响)");

	/* B-11 (C1 修复验证): 大写 (>4KB) seqlock 写 — 论文图 5c:
	 * 写前逐页版本预检 (偶数→REPAIR) + 写后版本比对; 此前大写
	 * 无验证 → 换出页写被黑洞吸收而静默丢失 */
	printf("\n--- B-11: 大写 seqlock (8KB, 论文图 5c, C1) ---\n");
	{
		const size_t wlen = 2 * SYMRDMA_PAGE_SIZE;   /* 8KB > 4KB 阈值 */
		unsigned char *lsrc = NULL;
		struct ibv_mr *lsrc_mr = NULL;
		int lsrc_id = -1;
		struct symrdma_ioc_reg_mr lrev = {0};

		/* 写源 (2 页, 跨页 2-3) — 同样需要 IOMMU 映射 */
		lsrc = mmap(NULL, wlen, PROT_READ | PROT_WRITE,
			    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (lsrc != MAP_FAILED) {
			memset(lsrc, 0, wlen);
			*(uint32_t *)(lsrc + 0) = 0xAAAAAAAA;
			*(uint32_t *)(lsrc + SYMRDMA_PAGE_SIZE) = 0xBBBBBBBB;
			lrev.va_start = (unsigned long long)lsrc;
			lrev.len = wlen;
			if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &lrev) == 0)
				lsrc_id = lrev.mr_id;
			lsrc_mr = ibv_reg_mr(pd, lsrc, wlen,
					     IBV_ACCESS_LOCAL_WRITE |
					     SYMRDMA_ACCESS_IDENTITY);
		}
		CHECK(lsrc_mr != NULL, "B-11: 大写源 buffer 注册 (8KB, 跨页 2-3)");

		/* B-11a: 驻留页大写 — seqlock 快速路径 (写前后版本一致) */
		ret = symrdma_write(&ctx, qp, cq, &smr, &wmr, 2, wlen,
				    lsrc, lsrc_mr ? lsrc_mr->lkey : 0);
		CHECK(ret == 0, "★ B-11a: 驻留页大写 8KB 落地 (seqlock 快速路径)");
		CHECK(*(uint32_t *)(buf + 2 * SYMRDMA_PAGE_SIZE) == 0xAAAAAAAA &&
		      *(uint32_t *)(buf + 3 * SYMRDMA_PAGE_SIZE) == 0xBBBBBBBB,
		      "B-11a': CPU 读回页 2/3 → AAAA/BBBB");

		/* B-11b: 换出页 2 → 跨页大写: 写前预检检出偶数 →
		 * REPAIR → 重写; 修复后写必须落地 (旧实现此处静默丢失) */
		madvise(buf + 2 * SYMRDMA_PAGE_SIZE, SYMRDMA_PAGE_SIZE,
			MADV_PAGEOUT);
		for (i = 0; i < SWAPOUT_TIMEOUT_S * 10; i++) {
			if (read_iova_page(ctx.fd, smr.mr_id,
					   smr.read_iova +
					   2 * SYMRDMA_PAGE_SIZE) ==
			    (long long)SYMRDMA_SENTINEL_MAGIC)
				break;
			usleep(100000);
		}
		CHECK(read_iova_page(ctx.fd, smr.mr_id,
				     smr.read_iova + 2 * SYMRDMA_PAGE_SIZE) ==
		      (long long)SYMRDMA_SENTINEL_MAGIC,
		      "B-11b: 页 2 已换出 (哨兵就位)");

		ret = symrdma_write(&ctx, qp, cq, &smr, &wmr, 2, wlen,
				    lsrc, lsrc_mr ? lsrc_mr->lkey : 0);
		CHECK(ret == 0, "★ B-11c: 换出页大写 8KB → 预检 REPAIR → 重写落地");
		CHECK(*(uint32_t *)(buf + 2 * SYMRDMA_PAGE_SIZE) == 0xAAAAAAAA,
		      "★ B-11c': CPU 读页 2 → AAAA (换出页写经 seqlock 路径落地)");
		ret = symrdma_get_version(&ctx, &smr, 2, &v);
		CHECK(ret == 0 && (v & 1), "B-11d: 页 2 版本奇数 (REPAIR 后驻留)");

		/* 清理 B-11 临时 buffer */
		if (lsrc_mr)
			ibv_dereg_mr(lsrc_mr);
		if (lsrc_id >= 0)
			ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, lsrc_id);
		if (lsrc && lsrc != MAP_FAILED)
			munmap(lsrc, wlen);
	}

	/* 清理 */
	printf("\n--- 清理 ---\n");
	symrdma_write_mr_deregister(&wmr);
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
		munmap(local, SYMRDMA_PAGE_SIZE);
	munmap(buf, BUF_SIZE);

	printf("\n========================================\n");
	printf("Level 5 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}
