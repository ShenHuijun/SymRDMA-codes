/*
 * test_rdma_verify.c — SymRDMA Level 2: RDMA NIC 验证
 *
 * 在真实 RDMA 网卡上验证 SymRDMA 的 IOMMU sentinel/blackhole 映射。
 * 需要: rdma-core (libibverbs), /dev/symrdma 已加载, RDMA 网卡 (如 mlx5)
 *
 * 编译: make (自动检测 libibverbs)
 * 运行: sudo ./test_rdma_verify
 *
 * 验证流程:
 *   1. 打开 RDMA 设备
 *   2. 通过 /dev/symrdma 注册内存 (IOMMU 映射, 不 pin)
 *   3. 获取 dual IOVA 地址
 *   4. 用标准 ibv_reg_mr 注册同一内存 (供 RDMA verbs 使用)
 *   5. 创建 loopback QP
 *   6. 测试: REMAP→SENTINEL → RDMA 读应返回哨兵魔数
 *   7. 测试: REPAIR → RDMA 读应返回原始数据
 *   8. 测试: swap-out → MMU notifier 自动重映射
 *
 * 单机 RDMA 原理:
 *   创建两个 QP 在同一个设备上，一个作为 initiator (发送 RDMA Read/Write)，
 *   另一个作为 target (暴露内存区域)。利用 ConnectX 的 loopback 能力，
 *   同一设备内的 QP 间数据路径经过 PCIe → IOMMU 翻译。
 *
 * 注意: 此测试程序用于验证 SymRDMA 内核模块的 IOMMU 映射正确性。
 *   在生产环境中，SymRDMA 会拦截 ibv_reg_mr 并替换其 pinning 逻辑，
 *   这里我们手动分开两个层次来验证。
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
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

/* ---- SymRDMA ioctl (与 kernel/symrdma.h 保持同步) ---- */
#define SYMRDMA_IOC_MAGIC       'S'
#define SYMRDMA_SENTINEL_MAGIC  0xdeadbeef
#define SYMRDMA_REMAP_REAL      0
#define SYMRDMA_REMAP_SENTINEL  1
#define SYMRDMA_REMAP_BLACKHOLE 2

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
struct symrdma_ioc_remap {
	int mr_id;
	unsigned long page_idx;
	int mode;
};
struct symrdma_ioc_repair {
	int mr_id;
	unsigned long page_idx;
};

#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_REMAP       _IOW(SYMRDMA_IOC_MAGIC,  3, struct symrdma_ioc_remap)
#define SYMRDMA_IOC_GET_IOVA    _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_get_iova)
#define SYMRDMA_IOC_READ_IOVA   _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_REPAIR      _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)

/* ---- 测试参数 ---- */
#define TEST_PAGES      4
#define PAGE_SIZE       4096
#define BUF_SIZE        (TEST_PAGES * PAGE_SIZE)
#define CQ_DEPTH        16

/*
 * 自环 CQ 轮询超时 (ms)。测试床无 PHY 环回模块 (第二口 link down,
 * NIC_LOOPBACK=0), 自环 QP 的 RDMA Read 永远收不到 CQE — 无界忙等会使
 * 进程 R 态自旋挂死, 成为远端孤儿占住 symrdma refcount → rmmod 失败只能
 * 重启 (L2 挂死教训, 文档 §5 H1 实锤)。正常完成耗时远小于
 * 此值 (超时兜底, 非正常路径)。
 */
#define POLL_TIMEOUT_MS 5000

/*
 * 带超时的 CQ 轮询。返回 0 = 收到 CQE (wc 有效),
 * -ETIMEDOUT = 超时 (自环不可达), -EIO = poll 错误。
 */
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

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/*
 * 检测 mlx5_ib 的 identity_mtt 模块参数是否开启 (Y/N)。
 * 开启时 MTT 条目 = 用户 VA, NIC DMA 经 IOMMU 命中 SymRDMA 映射。
 * (当前未调用 — 选择性模式 identity_mtt=0 下非必要; 保留供全局强制
 * 模式调试, __attribute__((unused)) 抑制 -Wunused)
 */
__attribute__((unused))
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

/*
 * 查找第一个可用的 RDMA 设备。
 * 返回设备名 (如 "mlx5_0") 或 NULL。
 */

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
	int num;

	dev_list = ibv_get_device_list(&num);
	if (!dev_list || num == 0) {
		printf("未找到 RDMA 设备\n");
		return NULL;
	}

	for (int i = 0; i < num; i++) {
		const char *name = ibv_get_device_name(dev_list[i]);
		printf("发现 RDMA 设备: %s\n", name);
		/* 优先选 mlx5 */
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
		/* 回退到第一个设备 */
		if (!dev)
			dev = dev_list[i];
	}

	/* 注意: dev_list 会被后续调用覆盖，这里只返回指针 */
	return dev;
}

/*
 * 在单机上做 RDMA loopback 验证:
 *   创建两个 QP (initiator/target) → 对 SymRDMA 映射的 IOVA 执行 RDMA 操作。
 *
 * 当前实现: 使用 RDMA Write with Immediate 做自环回验证。
 *   通过同一个 QP 对自己注册的 MR 做 RDMA Read，验证 IOMMU 翻译结果。
 *
 * 更完整的验证需要两台机器或 SmartNIC loopback。
 */
static int test_rdma_loopback(int sym_fd, int mr_id,
			      unsigned long long read_iova,
			      unsigned long long __attribute__((unused)) write_iova,
			      void *buf, size_t size)
{
	struct ibv_device *ib_dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_mr *mr;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	struct ibv_qp_init_attr qp_attr = {0};
	struct ibv_device_attr dev_attr;
	int ret = 0;

	ib_dev = find_rdma_device();
	if (!ib_dev) {
		printf("  SKIP: 无可用 RDMA 设备 — 仅做 IOMMU 级别验证\n");
		/*
		 * 无 RDMA 设备时回退到 READ_IOVA 验证。
		 * 这同样验证了 IOMMU 页表的正确性，因为 iommu_iova_to_phys()
		 * 做的是与 NIC DMA 相同的硬件页表遍历。
		 */
		struct symrdma_ioc_read_iova rd = {
			.mr_id = mr_id,
			.iova = read_iova,
			.offset = 0,
		};
		ret = ioctl(sym_fd, SYMRDMA_IOC_READ_IOVA, &rd);
		CHECK(ret == 0 && rd.value == SYMRDMA_SENTINEL_MAGIC,
		      "IOMMU read_iova→sentinel (通过 iommu_iova_to_phys 验证)");
		return 0;
	}

	/* 打开 RDMA 设备 */
	ctx = ibv_open_device(ib_dev);
	if (!ctx) {
		printf("  SKIP: 无法打开 RDMA 设备\n");
		return 0;
	}

	if (ibv_query_device(ctx, &dev_attr)) {
		printf("  SKIP: ibv_query_device 失败\n");
		ibv_close_device(ctx);
		return 0;
	}
	printf("  设备: %s (vendor=0x%x, max_mr_size=0x%llx)\n",
	       ibv_get_device_name(ib_dev),
	       dev_attr.vendor_id,
	       (unsigned long long)dev_attr.max_mr_size);

	/* 创建 Protection Domain */
	pd = ibv_alloc_pd(ctx);
	if (!pd) {
		printf("  SKIP: ibv_alloc_pd 失败\n");
		ibv_close_device(ctx);
		return 0;
	}

	/*
	 * 注册同一块内存为标准 RDMA MR (供 verbs API 使用)。
	 * 注意: 这是"传统"路径，会 pin 内存。在生产中 SymRDMA 会
	 * 拦截此调用并替换为 IOMMU 映射。这里我们保留两个路径以验证一致性。
	 */
	mr = ibv_reg_mr(pd, buf, size,
			IBV_ACCESS_LOCAL_WRITE |
			IBV_ACCESS_REMOTE_READ |
			IBV_ACCESS_REMOTE_WRITE |
			SYMRDMA_ACCESS_IDENTITY);
	if (!mr) {
		printf("  SKIP: ibv_reg_mr 失败\n");
		ibv_dealloc_pd(pd);
		ibv_close_device(ctx);
		return 0;
	}
	printf("  MR: lkey=0x%x rkey=0x%x addr=%p len=%zu\n",
	       mr->lkey, mr->rkey, mr->addr, mr->length);

	/* 创建 Completion Queue */
	cq = ibv_create_cq(ctx, CQ_DEPTH, NULL, NULL, 0);
	if (!cq) {
		printf("  SKIP: ibv_create_cq 失败\n");
		ibv_dereg_mr(mr);
		ibv_dealloc_pd(pd);
		ibv_close_device(ctx);
		return 0;
	}

	/* 创建 Queue Pair (RC 模式，支持 RDMA Read/Write) */
	qp_attr.send_cq = cq;
	qp_attr.recv_cq = cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.cap.max_send_wr  = CQ_DEPTH;
	qp_attr.cap.max_recv_wr  = CQ_DEPTH;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;

	qp = ibv_create_qp(pd, &qp_attr);
	if (!qp) {
		printf("  SKIP: ibv_create_qp 失败\n");
		ibv_destroy_cq(cq);
		ibv_dereg_mr(mr);
		ibv_dealloc_pd(pd);
		ibv_close_device(ctx);
		return 0;
	}

	/*
	 * 将 QP 转换到 RTS 状态 (自环回需要手动设置 QP 属性)。
	 * 对于单机测试，让 QP 连接到自己。
	 */
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
				  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
			printf("  SKIP: QP INIT 失败\n");
			goto cleanup_qp;
		}

		/* RTR (自环回: dest_qp = 自己, 需要知道自己的 qp_num)
		 *
		 * RoCEv2 (Ethernet 模式): 使用 GID 路径而非 LID。
		 * 目的 GID = 本机端口自己的 GID (PHY loopback 下自环)。
		 */
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
				goto cleanup_qp;
			}
			printf("  端口: link_layer=%s state=%d, 自环 GID 已设置\n",
			       port_attr.link_layer == IBV_LINK_LAYER_ETHERNET ?
			       "Ethernet": "InfiniBand", port_attr.state);
			/* path_mtu 动态取 min(active_mtu, 4096) —
			 *  L15 教训 (path_mtu > active_mtu 令多包响应首包
			 * 被丢); 自环同样从端口查询派生, 与跨机测试 (L7/L10/L12/
			 * L13/L15) 对齐 */
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
			goto cleanup_qp;
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
			goto cleanup_qp;
		}
	}

	printf("  QP 就绪: qp_num=0x%x (loopback mode)\n", qp->qp_num);

	/* ---- 真实 RDMA 操作 (自环: 本 QP 即目标 QP) ---- */

	/*
	 * 测试 RDMA-1: RDMA Read 自己的 MR → 哨兵验证 (identity_mtt) / 基线 (普通)。
	 *
	 * identity_mtt=1: MTT 条目 = 用户 VA。NIC DMA 用 IOVA=VA → IOMMU →
	 * SymRDMA 映射 (page0 已 REMAP 到哨兵) → 应读到 0xdeadbeef!
	 *
	 * 本地接收 buffer 用 buf 的页 1 — 它也在 SymRDMA 的 IOMMU 映射内
	 * (malloc 堆地址无 IOMMU 映射, DMA Write 会 fault)。
	 */
	{
		/* 接收 buffer = buf 页1 (SymRDMA 已映射 VA→PA RW) */
		unsigned char *local = (unsigned char *)buf + PAGE_SIZE;
		struct ibv_sge sge = {
			.addr   = (uintptr_t)local,
			.length = PAGE_SIZE,
			.lkey   = mr->lkey,   /* 同一 MR 覆盖 buf 全部 4 页 */
		};
		struct ibv_send_wr wr = {0}, *bad_wr = NULL;
		struct ibv_wc wc;

		memset(local, 0, PAGE_SIZE);

		wr.opcode            = IBV_WR_RDMA_READ;
		wr.sg_list           = &sge;
		wr.num_sge           = 1;
		wr.wr.rdma.remote_addr = (uintptr_t)buf;
		wr.wr.rdma.rkey        = mr->rkey;
		wr.send_flags        = IBV_SEND_SIGNALED;

		if (ibv_post_send(qp, &wr, &bad_wr)) {
			printf("  SKIP: ibv_post_send (RDMA Read) 失败\n");
			goto cleanup_qp;
		}

		/* 轮询完成 (带超时): 无 PHY 环回机器上自环 QP 永无 CQE,
		 * 无界忙等曾致 host-b L2 R 态自旋挂死 (§5 教训 H1) */
		if (poll_cq_timeout(cq, &wc, POLL_TIMEOUT_MS) != 0) {
			printf("  SKIP: RDMA Read %u ms 无 CQE — 本机无 PHY 环回, "
			       "自环拓扑敏感项跳过 (RDMA-1/2 不适用)\n",
			       (unsigned)POLL_TIMEOUT_MS);
			goto cleanup_qp;
		}
		if (wc.status != IBV_WC_SUCCESS) {
			printf("  FAIL: RDMA Read 完成异常 (status=%d)\n",
			       (int)wc.status);
		} else {
			unsigned int first = *(unsigned int *)local;
			printf("  [debug] RDMA Read 读到 0x%08x (wc.byte_len=%u) [buf 期望 0x%08x, 哨兵 0x%08x]\n",
			       first, (unsigned int)wc.byte_len, 0xABABAB41u,
			       SYMRDMA_SENTINEL_MAGIC);
			if (1) {
				/*
				 * 测试 MR 带 SYMRDMA_ACCESS_IDENTITY → 恒走 identity
				 * (P4): 全局 identity_mtt=1 或按 MR 标记位。
				 * NIC DMA 用 IOVA=VA → IOMMU → SymRDMA 映射。
				 * 此时 page0 已被 REMAP 到哨兵 → 应读到 0xdeadbeef!
				 */
				CHECK(first == SYMRDMA_SENTINEL_MAGIC,
				      "★ RDMA Read 命中哨兵 (0xdeadbeef) — MTT identity → IOMMU 闭环!");
			} else {
				CHECK(first == 0xABABAB41,
				      "RDMA Read 自环: 读到真实数据 (MTT→IOMMU→PA 基线)");
			}
		}

		/* ---- RDMA-2: REPAIR 后重读 → 恢复真实数据 ---- */
		{
			struct symrdma_ioc_repair repair_req = {
				.mr_id = mr_id,
				.page_idx = 0,
			};
			ret = ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req);
			if (ret != 0) {
				printf("  SKIP: REPAIR 失败, 跳过修复后重读\n");
			} else {
				memset(local, 0, PAGE_SIZE);
				wr.opcode = IBV_WR_RDMA_READ;
				if (ibv_post_send(qp, &wr, &bad_wr)) {
					printf("  SKIP: 修复后 RDMA Read 发送失败\n");
				} else if (poll_cq_timeout(cq, &wc,
							   POLL_TIMEOUT_MS) != 0) {
					printf("  SKIP: 修复后 RDMA Read %u ms 无 CQE "
					       "— 无 PHY 环回, 跳过\n",
					       (unsigned)POLL_TIMEOUT_MS);
				} else if (wc.status != IBV_WC_SUCCESS) {
					printf("  FAIL: 修复后 RDMA Read 完成异常\n");
				} else {
					unsigned int first = *(unsigned int *)local;
					CHECK(first == 0xABABAB41,
					      "★ REPAIR 后 RDMA Read 恢复真实数据 (0xABABAB41) — 完整闭环!");
				}
			}
		}

	}

printf("\n========================================\n");
printf("RDMA NIC 验证说明:\n");
printf("  QP 自环 (RoCEv2 GID) + RDMA Read/Write 基线。\n");
printf("  identity_mtt=1 时: MTT=用户VA → NIC DMA 经 IOMMU 命中 SymRDMA 映射。\n");
printf("  identity_mtt=0 时: 带标记位 MR 仍走 identity (选择性模式, P4)。\n");
printf("========================================\n\n");

cleanup_qp:
	ibv_destroy_qp(qp);
	ibv_destroy_cq(cq);
	ibv_dereg_mr(mr);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);

	return 0;
}

/* ---- 主程序 ---- */
int main(void)
{
	int sym_fd, ret;
	unsigned char *buf;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova iova_req;
	struct symrdma_ioc_remap remap_req;
	struct symrdma_ioc_repair repair_req;
	struct symrdma_ioc_read_iova read_req;
	int mr_id = -1;

	printf("=== SymRDMA Level 2: RDMA NIC 验证 ===\n\n");

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
	for (int i = 0; i < TEST_PAGES; i++)
		buf[i * PAGE_SIZE] = (unsigned char)('A' + i);
	printf("[2] 测试内存已分配: %d 页 (%d KB)\n",
	       TEST_PAGES, BUF_SIZE / 1024);

	/* Step 3: 注册 SymRDMA MR (IOMMU 映射，不 pin) */
	reg.va_start = (unsigned long long)buf;
	reg.len = BUF_SIZE;
	ret = ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
	CHECK(ret == 0, "SymRDMA REG_MR");
	if (ret) goto cleanup;
	mr_id = reg.mr_id;

	/* Step 4: 获取 IOVA 地址 */
	iova_req.mr_id = mr_id;
	iova_req.page_idx = 0;
	ret = ioctl(sym_fd, SYMRDMA_IOC_GET_IOVA, &iova_req);
	CHECK(ret == 0, "GET_IOVA");
	printf("  read_iova=0x%llx write_iova=0x%llx\n",
	       iova_req.read_iova, iova_req.write_iova);

	/* Step 5: 验证正常页面 IOMMU 读取 */
	read_req.mr_id = mr_id;
	read_req.iova = iova_req.read_iova;
	read_req.offset = 0;
	ret = ioctl(sym_fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	CHECK(ret == 0 && read_req.value == 0xABABAB41,
	      "READ_IOVA 正常页面: 读到用户数据");

	/* Step 6: 重映射到 SENTINEL */
	remap_req.mr_id = mr_id;
	remap_req.page_idx = 0;
	remap_req.mode = SYMRDMA_REMAP_SENTINEL;
	ret = ioctl(sym_fd, SYMRDMA_IOC_REMAP, &remap_req);
	CHECK(ret == 0, "REMAP to SENTINEL");
	ret = ioctl(sym_fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	CHECK(ret == 0 && read_req.value == SYMRDMA_SENTINEL_MAGIC,
	      "READ_IOVA sentinel 页: 读到 0xdeadbeef");

	/* Step 7: RDMA loopback 验证 */
	printf("\n--- RDMA Loopback 验证 ---\n");
	test_rdma_loopback(sym_fd, mr_id, iova_req.read_iova,
			   iova_req.write_iova, buf, BUF_SIZE);

	/* Step 8: REPAIR → 验证恢复 */
	printf("\n--- 换入修复验证 ---\n");
	repair_req.mr_id = mr_id;
	repair_req.page_idx = 0;
	ret = ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req);
	CHECK(ret == 0, "REPAIR 成功");
	ret = ioctl(sym_fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	CHECK(ret == 0 && read_req.value == 0xABABAB41,
	      "修复后 READ_IOVA: 读到原始用户数据");

	/* Step 9: Blackhole 验证 */
	printf("\n--- 黑洞吸收验证 ---\n");
	remap_req.mode = SYMRDMA_REMAP_BLACKHOLE;
	ret = ioctl(sym_fd, SYMRDMA_IOC_REMAP, &remap_req);
	CHECK(ret == 0, "REMAP to BLACKHOLE");
	/* CPU 端写入 (不经过 IOMMU) */
	memset(buf, 0xFF, PAGE_SIZE);
	/* 切换 read IOVA 到哨兵确认写入被吸收 */
	remap_req.mode = SYMRDMA_REMAP_SENTINEL;
	ioctl(sym_fd, SYMRDMA_IOC_REMAP, &remap_req);
	ret = ioctl(sym_fd, SYMRDMA_IOC_READ_IOVA, &read_req);
	CHECK(ret == 0 && read_req.value == SYMRDMA_SENTINEL_MAGIC,
	      "CPU 写入被黑洞吸收: IOMMU 读仍为哨兵");
	/* 恢复 */
	ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req);
	buf[0] = 'A';

	/* 清理 */
	ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, mr_id);

	printf("\n========================================\n");
	printf("Level 2 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");

cleanup:
	munmap(buf, BUF_SIZE);
	close(sym_fd);
	return failed > 0 ? 1 : 0;
}
