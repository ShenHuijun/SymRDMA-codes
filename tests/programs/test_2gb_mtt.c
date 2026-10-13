/*
 * test_2gb_mtt.c — O-1-E1 门禁补充: 跨 2GB MTT 条目边界的多条目验证
 *
 * 背景: O-1 修复 (reg_create start_addr 保持注册原值, MTT 从 2GB 对齐
 * 基址铺) 之后, 现有测试均为 <2GB 单条目 MR — MTT 第 2 条及以后的
 * 索引语义 (硬件按 (va - mtt_base)/2G 取条目) 未被覆盖。
 *
 * 本测试: 3GB 匿名 mmap (跨 1 个 2GB 边界 → 2 条 MTT), identity 注册,
 * loopback QP 对边界前后四点做 RDMA Write + RDMA Read 双向验证:
 *   off0 = 0, off1 = 2G-4K (条目 0 尾), off2 = 2G (条目 1 首), off3 = 3G-4K (尾)
 *
 * 环境要求: mlx5_ib (E1/O-1 版) + symrdma 模块已载 (identity bit 注册)。
 * 不挂 LD_PRELOAD — 直接验证 mlx5_ib identity 路径 (同 test_nopin)。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <infiniband/verbs.h>

/* SymRDMA ioctl (与 kernel/symrdma.h 同步, 同 test_rdma_verify) —
 * ioctl REG_MR 负责建 IOMMU 页表映射; ibv_reg_mr(identity bit) 负责
 * NIC identity MTT — 两者缺一不可 (缺 ioctl 则 DMA 全部落未映射 IOVA) */
struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
#define SYMRDMA_IOC_MAGIC       'S'
#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)

#define SYMRDMA_ACCESS_IDENTITY (1 << 21)
#ifndef IBV_QP_MTU
#define IBV_QP_MTU IBV_QP_PATH_MTU
#endif

#define MR_SIZE   (3ULL << 30)          /* 3GB — 跨 1 个 2GB 边界 */
#define OFF0      0ULL
#define OFF1      ((1ULL << 31) - 4096) /* 2G - 4K: 条目 0 尾 */
#define OFF2      (1ULL << 31)          /* 2G: 条目 1 首 */
#define OFF3      (MR_SIZE - 4096)      /* 3G - 4K: 末 */
#define PATTERN_A 0x5A
#define PATTERN_B 0xC3

static int passed = 0, failed = 0;
#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s\n", msg); failed++; } \
} while (0)

static int find_rdma_device(struct ibv_device **out)
{
	struct ibv_device **list = ibv_get_device_list(NULL);
	int i;
	if (!list)
		return -1;
	for (i = 0; list[i]; i++) {
		char path[256];
		struct ibv_context *c = ibv_open_device(list[i]);
		struct ibv_port_attr p;
		if (!c)
			continue;
		if (!ibv_query_port(c, 1, &p) &&
		    p.state == IBV_PORT_ACTIVE) {
			snprintf(path, sizeof(path), "/sys/class/infiniband/%s",
				 ibv_get_device_name(list[i]));
			/* 排除 DOWN 口所在设备 (mlx5_0): 检查 node 是否有 ACTIVE 口 */
			ibv_close_device(c);
			*out = list[i];
			return 0;
		}
		ibv_close_device(c);
	}
	return -1;
}

static int poll_wc(struct ibv_cq *cq, struct ibv_wc *wc)
{
	int n, spins = 0;
	while ((n = ibv_poll_cq(cq, 1, wc)) == 0) {
		if (++spins > 100000000)
			return -1;
	}
	return n;
}

/* post 一个 RDMA Write 或 Read, 等完成, 返回 0/失败 -1 */
static int do_rdma(struct ibv_qp *qp, struct ibv_cq *cq, struct ibv_mr *mr,
		   int is_write, unsigned long long off,
		   void *scratch, uint32_t scratch_lkey,
		   unsigned long long scratch_off)
{
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_sge sge = {0};
	struct ibv_wc wc;

	sge.addr   = (uintptr_t)scratch + scratch_off;
	sge.length = 4096;
	sge.lkey   = scratch_lkey;

	wr.wr_id      = 1;
	wr.sg_list    = &sge;
	wr.num_sge    = 1;
	wr.opcode     = is_write ? IBV_WR_RDMA_WRITE : IBV_WR_RDMA_READ;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr.rdma.remote_addr = (uintptr_t)mr->addr + off;
	wr.wr.rdma.rkey        = mr->rkey;

	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	if (poll_wc(cq, &wc) != 1)
		return -1;
	if (wc.status != IBV_WC_SUCCESS) { printf("    [wc] status=%d (%s)\n", wc.status, ibv_wc_status_str(wc.status)); return -1; }
	return 0;
}

int main(void)
{
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_mr *mr = NULL, *scratch_mr;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	void *buf, *scratch;
	unsigned long long offs[4] = {OFF0, OFF1, OFF2, OFF3};
	const char *names[4] = {"0 (条目0首)", "2G-4K (条目0尾)",
				"2G (条目1首)", "3G-4K (末)"};
	int i, rc = 1;

	if (find_rdma_device(&dev)) {
		printf("SKIP: 无 ACTIVE RDMA 设备\n");
		return 77;
	}
	ctx = ibv_open_device(dev);
	if (!ctx) { printf("FAIL: open_device\n"); return 1; }
	pd = ibv_alloc_pd(ctx);
	if (!pd) { printf("FAIL: alloc_pd\n"); return 1; }

	/* 3GB 匿名 mmap — VA 4K 对齐但非 2G 对齐 (E1 前提) */
	buf = mmap(NULL, MR_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) { printf("SKIP: 3GB mmap 失败 (%s)\n", strerror(errno)); return 77; }
	printf("buf=%p (VA%%2G=%llu — 非对齐前提 %s)\n", buf,
	       (unsigned long long)((uintptr_t)buf & ((1ULL << 31) - 1)),
	       ((uintptr_t)buf & ((1ULL << 31) - 1)) ? "成立" : "✗ 巧对齐!");

	int sym_fd = -1, mr_id = -1;
	struct symrdma_ioc_reg_mr reg = {0};

	sym_fd = open("/dev/symrdma", O_RDWR);
	if (sym_fd < 0) { printf("FAIL: open /dev/symrdma (%s)\n", strerror(errno)); return 1; }
	reg.va_start = (unsigned long long)(uintptr_t)buf;
	reg.len = MR_SIZE;
	if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg)) {
		printf("FAIL: SymRDMA ioctl REG_MR (%s)\n", strerror(errno));
		return 1;
	}
	mr_id = reg.mr_id;
	printf("SymRDMA REG_MR ok: mr_id=%d (IOMMU 映射已建)\n", mr_id);

	mr = ibv_reg_mr(pd, buf, MR_SIZE,
			IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ |
			IBV_ACCESS_REMOTE_WRITE | SYMRDMA_ACCESS_IDENTITY);
	if (!mr) {
		printf("FAIL: 3GB identity 注册失败 (errno=%d %s) — "
		       "固件拒绝非对齐 start 或多条件目\n",
		       errno, strerror(errno));
		return 1;
	}
	printf("MR: rkey=0x%x addr=%p len=3GB (2 条 2GB MTT)\n",
	       mr->rkey, mr->addr);

	scratch = mmap(NULL, 16384, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (scratch == MAP_FAILED) { printf("FAIL: scratch mmap\n"); return 1; }
	memset(scratch, PATTERN_A, 16384);
	scratch_mr = ibv_reg_mr(pd, scratch, 16384,
				IBV_ACCESS_LOCAL_WRITE);
	if (!scratch_mr) { printf("FAIL: scratch reg_mr\n"); return 1; }

	cq = ibv_create_cq(ctx, 16, NULL, NULL, 0);
	if (!cq) { printf("FAIL: create_cq\n"); return 1; }
	{
		struct ibv_qp_init_attr qa = {0};
		struct ibv_qp_attr attr = {0};
		qa.send_cq = cq; qa.recv_cq = cq;
		qa.qp_type = IBV_QPT_RC;
		qa.cap.max_send_wr = 16; qa.cap.max_recv_wr = 16;
		qa.cap.max_send_sge = 1; qa.cap.max_recv_sge = 1;
		qp = ibv_create_qp(pd, &qa);
		if (!qp) { printf("FAIL: create_qp\n"); return 1; }

		attr.qp_state = IBV_QPS_INIT;
		attr.pkey_index = 0; attr.port_num = 1;
		attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
				       IBV_ACCESS_REMOTE_WRITE |
				       IBV_ACCESS_LOCAL_WRITE;
		if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
				  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
			printf("FAIL: QP INIT (%s)\n", strerror(errno)); return 1;
		}
		memset(&attr, 0, sizeof(attr));
		attr.qp_state = IBV_QPS_RTR;
		attr.path_mtu = IBV_MTU_1024;
		attr.dest_qp_num = qp->qp_num;
		attr.rq_psn = 0;
		attr.max_dest_rd_atomic = 1;
		attr.min_rnr_timer = 12;
		attr.ah_attr.port_num = 1;
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.sgid_index = 0;
		attr.ah_attr.grh.hop_limit = 1;
		{
			struct ibv_port_attr pa;
			if (ibv_query_port(ctx, 1, &pa) ||
			    ibv_query_gid(ctx, 1, 0, &attr.ah_attr.grh.dgid)) {
				printf("FAIL: 查询端口/GID\n"); return 1;
			}
			if (pa.active_mtu < IBV_MTU_1024)
				attr.path_mtu = pa.active_mtu;
		}
		if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_MTU |
				  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				  IBV_QP_MAX_DEST_RD_ATOMIC |
				  IBV_QP_MIN_RNR_TIMER | IBV_QP_AV)) {
			printf("FAIL: QP RTR (%s)\n", strerror(errno)); return 1;
		}
		memset(&attr, 0, sizeof(attr));
		attr.qp_state = IBV_QPS_RTS;
		attr.sq_psn = 0; attr.timeout = 14;
		attr.retry_cnt = 7; attr.rnr_retry = 7;
		attr.max_rd_atomic = 1;
		if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN |
				  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
				  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC)) {
			printf("FAIL: QP RTS (%s)\n", strerror(errno)); return 1;
		}
	}

	/* CPU 预填四点参考值 */
	for (i = 0; i < 4; i++)
		memset((char *)buf + offs[i], PATTERN_A, 4096);

	/* 1) RDMA Read 四点 → scratch → CPU 比对 (NIC 读各 MTT 条目) */
	for (i = 0; i < 4; i++) {
		char msg[128];
		memset(scratch, 0, 4096);
		if (do_rdma(qp, cq, mr, 0 /*read*/, offs[i], scratch,
			    scratch_mr->lkey, 4096)) {
			printf("  FAIL: RDMA Read @%s WC 错误\n", names[i]);
			failed++;
			continue;
		}
		snprintf(msg, sizeof(msg),
			 "RDMA Read @off%s 数据正确 (条目 %d)",
			 names[i], i < 2 ? 0 : 1);
		CHECK(*(unsigned char *)scratch == PATTERN_A &&
		      ((unsigned char *)scratch)[4095] == PATTERN_A, msg);
	}

	/* 2) RDMA Write 四点 (scratch 中段 B 图案 → MR) → CPU 读回比对 */
	memset((char *)scratch + 8192, PATTERN_B, 4096);
	for (i = 0; i < 4; i++) {
		char msg[128];
		memset((char *)buf + offs[i], 0, 4096);
		if (do_rdma(qp, cq, mr, 1 /*write*/, offs[i], scratch,
			    scratch_mr->lkey, 8192)) {
			printf("  FAIL: RDMA Write @%s WC 错误\n", names[i]);
			failed++;
			continue;
		}
		snprintf(msg, sizeof(msg),
			 "RDMA Write @off%s 落地正确 (条目 %d)",
			 names[i], i < 2 ? 0 : 1);
		CHECK(*(unsigned char *)((char *)buf + offs[i]) == PATTERN_B &&
		      ((unsigned char *)buf + offs[i])[4095] == PATTERN_B, msg);
	}

	printf("\n结果: %d 通过, %d 失败\n", passed, failed);
	rc = failed ? 1 : 0;

	ibv_destroy_qp(qp); ibv_destroy_cq(cq);
	ibv_dereg_mr(scratch_mr); ibv_dereg_mr(mr);
	ibv_dealloc_pd(pd); ibv_close_device(ctx);
	munmap(buf, MR_SIZE); munmap(scratch, 16384);
	return rc;
}
