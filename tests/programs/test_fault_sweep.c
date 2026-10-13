/*
 * test_fault_sweep.c — SymRDMA Level 9: 故障比例扫描实验
 *
 * 审稿人 Q4: 扫描 RDMA 操作遭遇非驻留页的比例 (0% → 100%),
 * 测量平均延迟随故障比例的变化 — 对应论文 §5.2.1 故障成本曲线。
 *
 * 方法: 分配 NPAGES 页 MR (全驻留), 按 fault_frac 预先换出选定页
 * (固定种子, 可复现), 对全部页各执行一次 symrdma_read (4KB 哨兵路径),
 * 统计平均/中位/最大延迟 + 实际哨兵命中率 + REPAIR 次数。
 *
 * 预期:  avg_lat(frac) ≈ (1-frac)·L_res + frac·(L_res + L_fault)
 *        L_fault = 哨兵检测 + REPAIR (换入+IOMMU 重映射) + 重读 ≈ 几十 µs
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
#include <sys/time.h>
#include <infiniband/verbs.h>

#include "../lib/libsymrdma.h"

#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

#define NPAGES   256
#define BUF_SIZE (NPAGES * SYMRDMA_PAGE_SIZE)
#define CQ_DEPTH 32
#define FRACS    {0, 10, 25, 50, 75, 100}

static uint64_t now_us(void)
{
	struct timeval tv;
	gettimeofday(&tv, NULL);
	return (uint64_t)tv.tv_sec * 1000000 + tv.tv_usec;
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
	struct ibv_cq *cq = ibv_create_cq(ctx, CQ_DEPTH, NULL, NULL, 0);
	struct ibv_qp *qp;
	struct ibv_qp_init_attr qp_attr = {0};

	if (!cq) { fprintf(stderr, "[dbg] create_cq fail\n"); return -1; }
	qp_attr.send_cq = cq;
	qp_attr.recv_cq = cq;
	qp_attr.qp_type = IBV_QPT_RC;
	qp_attr.cap.max_send_wr = CQ_DEPTH;
	qp_attr.cap.max_recv_wr = CQ_DEPTH;
	qp_attr.cap.max_send_sge = 1;
	qp_attr.cap.max_recv_sge = 1;
	qp = ibv_create_qp(pd, &qp_attr);
	if (!qp) {
		fprintf(stderr, "[dbg] create_qp fail errno=%d\n", errno);
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
		if (ibv_modify_qp(qp, &attr,
				  IBV_QP_STATE | IBV_QP_PKEY_INDEX |
				  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
			fprintf(stderr, "[dbg] INIT modify fail errno=%d\n", errno);
			goto err;
		}
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
			    ibv_query_gid(ctx, 1, 0, &attr.ah_attr.grh.dgid)) {
				fprintf(stderr, "[dbg] query_port/gid fail errno=%d\n", errno);
				goto err;
			}
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
				  IBV_QP_MIN_RNR_TIMER | IBV_QP_AV)) {
			fprintf(stderr, "[dbg] RTR modify fail errno=%d\n", errno);
			goto err;
		}
		attr.qp_state = IBV_QPS_RTS;
		attr.sq_psn = 0;
		attr.timeout = 14;
		attr.retry_cnt = 7;
		attr.rnr_retry = 7;
		attr.max_rd_atomic = 1;
		if (ibv_modify_qp(qp, &attr,
				  IBV_QP_STATE | IBV_QP_SQ_PSN |
				  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
				  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC)) {
			fprintf(stderr, "[dbg] RTS modify fail errno=%d\n", errno);
			goto err;
		}
	}
	*cq_out = cq;
	*qp_out = qp;
	return 0;
err:
	ibv_destroy_qp(qp);
	ibv_destroy_cq(cq);
	return -1;
}

/* READ_IOVA ioctl (libsymrdma.h 未含 — 本地定义) */
struct symrdma_ioc_read_iova_l9 {
	int mr_id;
	unsigned long long iova;
	unsigned long offset;
	unsigned int value;
};
#define SYMRDMA_IOC_READ_IOVA_L9 _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova_l9)

/* READ_IOVA: 经 IOMMU 读指定 IOVA 首 4 字节 (换出就位检查) */
static long long read_iova_page(int sym_fd, int mr_id, unsigned long long iova)
{
	struct symrdma_ioc_read_iova_l9 rd = {
		.mr_id = mr_id,
		.iova  = iova,
		.offset = 0,
	};

	if (ioctl(sym_fd, SYMRDMA_IOC_READ_IOVA_L9, &rd))
		return -1;
	return (long long)rd.value;
}

/* /proc/symrdma 统计值 (按 key 匹配, 取冒号后数值; 未找到返回 -1) */
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

/* 每 256B TLP chunk 检查哨兵 (与 libsymrdma.c buf_is_sentinel 一致,
 * 论文 §3.1.1: 只查首 4 字节会漏检读期间换出) */

/* L9 就位失败诊断: 未就位目标页的 IOMMU 值 + smaps Swap 分类 */
static void sweep_dump_not_ready(int fd, int mr_id, unsigned long long riova,
				 const unsigned char *buf, const int *targets)
{
	int i, pi;
	long swapk[NPAGES];
	unsigned long rs = 0, re = 0;
	char line[256];
	FILE *f;

	for (i = 0; i < NPAGES; i++)
		swapk[i] = -2;                 /* -2 = 未采集 */
	f = fopen("/proc/self/smaps", "r");
	if (f) {
		while (fgets(line, sizeof(line), f)) {
			if (sscanf(line, "%lx-%lx", &rs, &re) == 2)
				continue;
			long sv;
			if (sscanf(line, "Swap: %ld", &sv) == 1 &&
			    (unsigned long)buf >= rs &&
			    (unsigned long)buf < re) {
				pi = ((unsigned long)buf - rs) / SYMRDMA_PAGE_SIZE;
				if (pi >= 0 && pi < NPAGES && swapk[pi] == -2)
					swapk[pi] = sv;
			}
		}
		fclose(f);
	}
	for (i = 0; i < NPAGES; i++) {
		long long v;
		if (!targets[i])
			continue;
		v = read_iova_page(fd, mr_id, riova + (unsigned long long)i * SYMRDMA_PAGE_SIZE);
		if (v != (long long)SYMRDMA_SENTINEL_MAGIC)
			fprintf(stderr,
				"    页 %d: IOMMU=0x%llx smaps_Swap=%ld kB%s\n",
				i, (unsigned long long)v, swapk[i],
				swapk[i] > 0 ? " ← OS已换出但IOMMU未哨兵 (notifier漏)" :
				(swapk[i] == 0 ? " ← OS未换出" : ""));
	}
}
static int page_is_sentinel(const void *data, size_t len)
{
	size_t off;

	for (off = 0; off + 4 <= len; off += SYMRDMA_TLP_CHUNK_SIZE) {
		const uint32_t *p = (const uint32_t *)((const char *)data + off);
		if (*p == SYMRDMA_SENTINEL_MAGIC)
			return 1;
	}
	return 0;
}

/* 固定种子选 nswap 个不重复目标页 (rand()%256 有重复,
 * fault=100% 时唯一页仅 ~162 而非 256 — 曲线对标不准确) */
static void pick_targets(int *targets, int nswap, unsigned int seed)
{
	int picked = 0;

	memset(targets, 0, NPAGES * sizeof(int));
	srand(seed);
	while (picked < nswap) {
		int p = rand() % NPAGES;
		if (!targets[p]) {
			targets[p] = 1;
			picked++;
		}
	}
}

int legacy_main(void)
{
	static const int fracs[] = FRACS;
	struct symrdma_ctx ctx;
	struct symrdma_mr smr = {0};
	unsigned char *buf = NULL, *local = NULL;
	struct ibv_mr *local_mr = NULL;
	struct ibv_device *dev;
	struct ibv_context *ibctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_get_iova iova_req;
	uint64_t lat[NPAGES], sum, max;
	unsigned int seed = 42;
	int i, f, nsentinel, nbad = 0, local_mr_id = -1, rc = 0;
	long long repair_base, repair_delta;

	smr.mr_id = -1;		/* 提前退出清理时防止误 DEREG  */

	printf("=== SymRDMA Level 9: 故障比例扫描 (论文 §5.2.1) ===\n");
	printf("identity_mtt: %s (MR 带标记位 → 选择性模式)\n",
	       identity_mtt_active() ? "Y" : "N");

	if (symrdma_open(&ctx)) {
		rc = 1;
		goto err_out;
	}

	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		buf = NULL;
		rc = 1;
		goto err_out;
	}
	memset(buf, 0xAB, BUF_SIZE);

	local = mmap(NULL, SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (local == MAP_FAILED) {
		local = NULL;
		rc = 1;
		goto err_out;
	}
	memset(local, 0x5A, SYMRDMA_PAGE_SIZE);   /* touch: 驻留判定不触发缺页 */
	if (mlock(local, SYMRDMA_PAGE_SIZE))
		fprintf(stderr, "  [warn] local mlock 失败\n");

	dev = find_rdma_device();
	if (!dev) { fprintf(stderr, "[dbg] no rdma dev\n"); rc = 1; goto err_out; }
	ibctx = ibv_open_device(dev);
	if (!ibctx) { fprintf(stderr, "[dbg] open_device fail errno=%d\n", errno); rc = 1; goto err_out; }
	pd = ibv_alloc_pd(ibctx);
	if (!pd) { fprintf(stderr, "[dbg] alloc_pd fail errno=%d\n", errno); rc = 1; goto err_out; }
	if (setup_loopback_qp(ibctx, pd, &cq, &qp)) { fprintf(stderr, "[dbg] setup_qp fail\n"); rc = 1; goto err_out; }

	reg.va_start = (unsigned long long)buf;
	reg.len = BUF_SIZE;
	if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg)) { fprintf(stderr, "[dbg] REG_MR fail errno=%d\n", errno); rc = 1; goto err_out; }
	smr.mr_id = reg.mr_id;
	smr.buf = buf;
	smr.len = BUF_SIZE;
	iova_req.mr_id = smr.mr_id;
	iova_req.page_idx = 0;
	if (ioctl(ctx.fd, SYMRDMA_IOC_GET_IOVA, &iova_req)) { fprintf(stderr, "[dbg] GET_IOVA fail\n"); rc = 1; goto err_out; }
	smr.read_iova = iova_req.read_iova;
	smr.write_iova = iova_req.write_iova;

	smr.ibv_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
				IBV_ACCESS_LOCAL_WRITE |
				IBV_ACCESS_REMOTE_READ |
				IBV_ACCESS_REMOTE_WRITE |
				SYMRDMA_ACCESS_IDENTITY);
	if (!smr.ibv_mr) { fprintf(stderr, "[dbg] ibv_reg_mr fail errno=%d\n", errno); rc = 1; goto err_out; }
	/* ★ local 接收 buffer 必须先 ioctl REG_MR 建立 IOMMU 映射 :
	 * identity MTT 下 DMA 写 local 的 IOVA = local VA, 无映射则 VT-d
	 * fault → 数据不落地 → 读回恒为 memset 后的 0 → 哨兵检测永远失败
	 * (L9 历史遗留: 曾见 data=0x0 + 零哨兵命中 + 全 fault% 延迟一致,
	 * 与已验证的 L4 差异即此处缺 REG_MR; mlock 不解决 IOMMU 映射)。 */
	reg.va_start = (unsigned long long)local;
	reg.len = SYMRDMA_PAGE_SIZE;
	if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg)) {
		fprintf(stderr, "[dbg] local REG_MR fail errno=%d\n", errno);
		rc = 1;
		goto err_out;
	}
	local_mr_id = reg.mr_id;
	local_mr = ibv_reg_mr(pd, local, SYMRDMA_PAGE_SIZE,
			      IBV_ACCESS_LOCAL_WRITE |
			      SYMRDMA_ACCESS_IDENTITY);
	if (!local_mr) { fprintf(stderr, "[dbg] local ibv_reg_mr fail\n"); rc = 1; goto err_out; }

	/* REPAIR 计数基线 (fault% 循环内用增量验证修复发生) */
	repair_base = proc_stat("REPAIR 成功");
	if (repair_base < 0)
		repair_base = 0;

	/* 基准: 全驻留延迟 (fault 比例 0 的对照) */
	{
		uint64_t t0 = now_us();
		for (i = 0; i < NPAGES; i++) {
			if (symrdma_read(&ctx, qp, cq, &smr, i, SYMRDMA_PAGE_SIZE,
					 local, local_mr->lkey)) {
				rc = 1;
				goto err_out;
			}
		}
		printf("全驻留 256 次读总耗时: %llu µs (单次均值 %llu µs)\n",
		       (unsigned long long)(now_us() - t0),
		       (unsigned long long)((now_us() - t0) / NPAGES));
	}

	printf("\n| fault%% | 平均延迟 µs | 中位 µs | 最大 µs | 目标页 | 哨兵命中(REPAIR) |\n");
	printf("|--------|------------|---------|---------|--------|------------------|\n");
	for (f = 0; f < (int)(sizeof(fracs) / sizeof(fracs[0])); f++) {
		int nswap = NPAGES * fracs[f] / 100;
		unsigned long long t;
		int targets[NPAGES];

		/* 恢复: 触摸全部页 (换入) */
		for (i = 0; i < NPAGES; i++)
			buf[i * SYMRDMA_PAGE_SIZE] = 0xAB;

		/* 固定种子选 nswap 个不重复页 (可复现) + 换出 */
		{
			pick_targets(targets, nswap, seed);
			for (i = 0; i < NPAGES; i++)
				if (targets[i])
					madvise(buf + i * SYMRDMA_PAGE_SIZE,
						SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
			/* 等待目标页全部就位 (READ_IOVA → 哨兵, madvise 异步, 上限 5s) */
			{
				int tries, ready = 0;
				/* 50×100ms(5s)→200×100ms(20s) — HDD swap 写回偶发
				 * >5s (实测 flaky, 页最终全部就位、notifier 无漏), 超时收紧
				 * 误报非系统 bug; 防假阴性不变式保留 (20s×6 轮仍入 L9 的
				 * 180s 远端超时预算)。
				 * 另: 每 20 次 (2s) 对未就位页重发 madvise — REPAIR (GUP)
				 * 换回的页可能仍在 per-CPU pagevec 未入 LRU, 本次 madvise
				 * isolate 失败被静默跳过 (内核侧 lru_add_drain 修复后仅剩
				 * 兕底); 重发后页入 LRU 即可正常换出。 */
				for (tries = 0; tries < 200; tries++) {
					int all = 1;
					int reissue = (tries > 0 && tries % 20 == 0);
					for (i = 0; i < NPAGES; i++) {
						if (!targets[i])
							continue;
						if (read_iova_page(ctx.fd, smr.mr_id,
								   smr.read_iova + i * SYMRDMA_PAGE_SIZE) !=
						    (long long)SYMRDMA_SENTINEL_MAGIC) {
							all = 0;
							if (reissue)
								madvise(buf + i * SYMRDMA_PAGE_SIZE,
									SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
							else
								break;
						}
					}
					if (all) {
						ready = 1;
						break;
					}
					usleep(100000);
				}
				/* ready 必须检查 — 5s 超时说明换出未就位,
				 * 静默继续会让 fault% 全读驻留数据 (假阴性) */
				if (!ready) {
					fprintf(stderr,
						"  [fault-sweep] fault=%d%%: 目标页 5s 未全部就位 (换出失败?)\n",
						fracs[f]);
					sweep_dump_not_ready(ctx.fd, smr.mr_id,
							     smr.read_iova, buf,
							     targets);
					rc = 1;
					goto err_out;
				}
			}
		}

		/* 逐页读, 计时 + 数据校验 (哨兵命中以 REPAIR 增量为准 —
		 * symrdma_read 命中哨兵后已在内部 REPAIR+重读, 读后数据是真实
		 * 数据而非哨兵模式, 按读回数据判定必然为 0; 数据异常 (0x0 等)
		 * 仍显式报告) */
		sum = 0;
		max = 0;
		nsentinel = 0;
		for (i = 0; i < NPAGES; i++) {
			uint32_t head;
			uint64_t t0 = now_us();
			int ret = symrdma_read(&ctx, qp, cq, &smr, i,
					       SYMRDMA_PAGE_SIZE,
					       local, local_mr->lkey);
			lat[i] = now_us() - t0;
			if (ret) {
				rc = 1;
				goto err_out;
			}

			sum += lat[i];
			if (lat[i] > max)
				max = lat[i];

			/* 非哨兵 → 应为驻留数据 0xABABABAB; 异常值 (0x0 等) 计入
			 * FAIL (旧仅告警 — 与 --matrix 模式判定不一致,
			 * 静默损坏不会 FAIL; 哨兵形态数据排除 — 读路径修复耗尽
			 * 时 libsymrdma 已以错误返回而非交付哨兵) */
			head = *(uint32_t *)local;
			if (head != 0xABABABAB &&
			    !page_is_sentinel(local, SYMRDMA_PAGE_SIZE)) {
				nbad++;
				fprintf(stderr,
					"  [fault-sweep] 数据异常: fault=%d%% 页 %d 读回 0x%08x (延迟 %llu µs)\n",
					fracs[f], i, (unsigned)head,
					(unsigned long long)lat[i]);
			}
		}
		/* REPAIR 增量: 每次哨兵命中对应一次 REPAIR (论文 §5.2.1 故障成本) */
		repair_delta = proc_stat("REPAIR 成功") - repair_base;
		repair_base += repair_delta;
		nsentinel = (int)repair_delta;
		printf("  [info] fault=%d%%: 哨兵命中(REPAIR) %lld 页, 目标 %d 页\n",
		       fracs[f], (long long)repair_delta, nswap);
		/* 中位 */
		{
			int j, k;
			for (j = 0; j < NPAGES; j++)
				for (k = j + 1; k < NPAGES; k++)
					if (lat[k] < lat[j]) {
						uint64_t tmp = lat[j];
						lat[j] = lat[k];
						lat[k] = tmp;
					}
		}
		printf("| %3d%% | %10llu | %7llu | %7llu | %6d | %18d |\n",
		       fracs[f],
		       (unsigned long long)(sum / NPAGES),
		       (unsigned long long)(lat[NPAGES / 2]),
		       (unsigned long long)max, nswap, nsentinel);
		fflush(stdout);
		t = now_us();   /* 防止未用警告 */
		(void)t;
	}

	/* 数据异常计入 rc (与 --matrix 模式判定对齐) */
	if (nbad) {
		fprintf(stderr,
			"  [fault-sweep] 共 %d 处数据异常 — FAIL\n", nbad);
		rc = 1;
	}

	/* 清理 (正常 + 异常统一: 提前退出也释放 MR — 防 /proc 残留
	 * 污染其它 Level 的计数断言, L6r 实测教训) */
err_out:
	if (local_mr)
		ibv_dereg_mr(local_mr);
	if (local_mr_id >= 0)
		ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, local_mr_id);
	if (smr.ibv_mr)
		ibv_dereg_mr(smr.ibv_mr);
	if (smr.mr_id >= 0)
		ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, smr.mr_id);
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (pd)
		ibv_dealloc_pd(pd);
	if (ibctx)
		ibv_close_device(ibctx);
	if (ctx.fd >= 0)
		symrdma_close(&ctx);
	if (local && local != MAP_FAILED)
		munmap(local, SYMRDMA_PAGE_SIZE);
	if (buf && buf != MAP_FAILED)
		munmap(buf, BUF_SIZE);
	return rc;
}

/* ==================== --matrix 模式 (论文 Fig 11 对照) ====================
 * fault 类型 (minor/major) × 消息尺寸 (256B..256KB) 延迟矩阵:
 *   minor: 从未触摸的 MAP_NORESERVE 页 — 注册时即哨兵映射 (L1 T7 语义),
 *          每片只读一次; 有意不用 MADV_DONTNEED 重臂 (resident→unmap 窗口
 *          对在飞 DMA 的竞态是已知遗留, 不进默认门禁
 *   major: 驻留 0xAB 页 madvise(PAGEOUT) → READ_IOVA 就位等待 → 读
 *          (REPAIR 从 swap 换入, 真实 major fault)
 *   驻留基线: 同尺寸全驻留 (论文 Fig 13 no-PF 对照, 同一 QP 可比)
 * 判定: REPAIR Δ ≥ 样本数×片页数 (修复确实发生); 数据失配 = FAIL
 */

#define MAT_MAX_SAMPLES 200
static const size_t mat_sizes[] = { 256, 1024, 4096, 8192, 65536, 262144 };

/* 双注册一个 region (ioctl REG_MR + GET_IOVA + ibv_reg_mr identity + 版本表) */
static int mat_region_register(struct symrdma_ctx *ctx, struct ibv_pd *pd,
			       unsigned char *buf, size_t len,
			       struct symrdma_mr *smr)
{
	struct symrdma_ioc_reg_mr reg = {
		.va_start = (unsigned long long)buf,
		.len = len,
	};
	struct symrdma_ioc_get_iova iova_req;

	if (ioctl(ctx->fd, SYMRDMA_IOC_REG_MR, &reg))
		return -1;
	smr->mr_id = reg.mr_id;
	smr->buf = buf;
	smr->len = len;
	iova_req.mr_id = reg.mr_id;
	iova_req.page_idx = 0;
	if (ioctl(ctx->fd, SYMRDMA_IOC_GET_IOVA, &iova_req))
		return -1;
	smr->read_iova = iova_req.read_iova;
	smr->write_iova = iova_req.write_iova;
	smr->ibv_mr = ibv_reg_mr(pd, buf, len,
				 IBV_ACCESS_LOCAL_WRITE |
				 IBV_ACCESS_REMOTE_READ |
				 IBV_ACCESS_REMOTE_WRITE |
				 SYMRDMA_ACCESS_IDENTITY);
	if (!smr->ibv_mr)
		return -1;
	return symrdma_mr_bind_version(ctx, pd, smr);
}

static void mat_region_release(struct symrdma_ctx *ctx, struct symrdma_mr *smr,
			       unsigned char *buf, size_t len)
{
	symrdma_mr_deregister(ctx, smr);
	memset(smr, 0, sizeof(*smr));
	smr->mr_id = -1;
	if (buf)
		munmap(buf, len);
}

/* 数据校验: ≤4KB 全量逐字; 更大做首/尾/各页首 spot check */
static int mat_verify(const unsigned char *got, size_t len, uint32_t expect)
{
	const uint32_t *w = (const uint32_t *)got;
	size_t i, nw = len / 4;

	if (len <= SYMRDMA_SENTINEL_THRESHOLD) {
		for (i = 0; i < nw; i++)
			if (w[i] != expect)
				return 1;
		return 0;
	}
	/* spot: 首 4 字 + 每页首 4 字 + 尾 4 字 */
	if (w[0] != expect)
		return 1;
	for (i = 0; i < len; i += SYMRDMA_PAGE_SIZE)
		if (*(const uint32_t *)(got + i) != expect)
			return 1;
	if (w[nw - 1] != expect)
		return 1;
	return 0;
}

static void mat_stats(const uint64_t *lat, int n, uint64_t *avg,
		      uint64_t *med, uint64_t *max)
{
	uint64_t sum = 0, hi = 0;
	uint64_t tmp[MAT_MAX_SAMPLES];
	int i, j, k;

	for (i = 0; i < n; i++) {
		sum += lat[i];
		if (lat[i] > hi)
			hi = lat[i];
		tmp[i] = lat[i];
	}
	for (j = 0; j < n; j++)
		for (k = j + 1; k < n; k++)
			if (tmp[k] < tmp[j]) {
				uint64_t t = tmp[j];
				tmp[j] = tmp[k];
				tmp[k] = t;
			}
	*avg = sum / (unsigned)n;
	*med = tmp[n / 2];
	*max = hi;
}

/* 就位等待: 片内全部页 READ_IOVA = 哨兵 (每 2s 重发 madvise 兕底, 同 L9) */
static int mat_wait_sentinel(struct symrdma_ctx *ctx, struct symrdma_mr *smr,
			     unsigned char *buf, unsigned long first_page,
			     int npages)
{
	int tries, i;

	for (tries = 0; tries < 200; tries++) {
		int all = 1;
		int reissue = (tries > 0 && tries % 20 == 0);

		for (i = 0; i < npages; i++) {
			if (read_iova_page(ctx->fd, smr->mr_id,
					   smr->read_iova +
					   (unsigned long long)(first_page + i) *
					   SYMRDMA_PAGE_SIZE) !=
			    (long long)SYMRDMA_SENTINEL_MAGIC) {
				all = 0;
				if (reissue)
					madvise(buf + (size_t)(first_page + i) *
						SYMRDMA_PAGE_SIZE,
						SYMRDMA_PAGE_SIZE, MADV_PAGEOUT);
				else
					break;
			}
		}
		if (all)
			return 0;
		usleep(100000);
	}
	return -1;
}

static int matrix_main(void)
{
	struct symrdma_ctx ctx;
	struct ibv_device *dev;
	struct ibv_context *ibctx = NULL;
	struct ibv_pd *pd = NULL;
	struct ibv_cq *cq = NULL;
	struct ibv_qp *qp = NULL;
	struct symrdma_mr smr_a = { .mr_id = -1 }, smr_b = { .mr_id = -1 };
	unsigned char *reg_a = NULL, *reg_b = NULL, *local = NULL;
	struct ibv_mr *local_mr = NULL;
	struct symrdma_ioc_reg_mr reg = {0};
	int local_ioctl_mr_id = -1;
	size_t max_size = 262144, local_len;
	long long repair_base, rep;
	uint64_t lat[MAT_MAX_SAMPLES];
	int i, rc = 0;
	unsigned int seed = 42;

	printf("=== SymRDMA Level 9M: fault 类型 × 尺寸矩阵 (论文 Fig 11) ===\n");
	printf("identity_mtt: %s\n", identity_mtt_active() ? "Y" : "N");

	if (symrdma_open(&ctx)) {
		fprintf(stderr, "[dbg] /dev/symrdma 打开失败\n");
		return 1;
	}
	dev = find_rdma_device();
	if (!dev || !(ibctx = ibv_open_device(dev)) ||
	    !(pd = ibv_alloc_pd(ibctx)) ||
	    setup_loopback_qp(ibctx, pd, &cq, &qp)) {
		fprintf(stderr, "[dbg] 设备/QP 初始化失败\n");
		rc = 1;
		goto err_out;
	}

	/* 本地接收 buffer: 最大尺寸, mlock + 双注册 */
	local_len = max_size;
	local = mmap(NULL, local_len, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (local == MAP_FAILED) { rc = 1; goto err_out; }
	memset(local, 0x5A, local_len);
	if (mlock(local, local_len))
		fprintf(stderr, "  [warn] local mlock 失败\n");
	reg.va_start = (unsigned long long)local;
	reg.len = local_len;
	if (ioctl(ctx.fd, SYMRDMA_IOC_REG_MR, &reg)) {
		fprintf(stderr, "[dbg] local REG_MR fail errno=%d\n", errno);
		rc = 1;
		goto err_out;
	}
	local_ioctl_mr_id = reg.mr_id;
	local_mr = ibv_reg_mr(pd, local, local_len,
			      IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	if (!local_mr) {
		ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, local_ioctl_mr_id);
		local_ioctl_mr_id = -1;
		fprintf(stderr, "[dbg] local ibv_reg_mr fail\n");
		rc = 1;
		goto err_out;
	}

	repair_base = proc_stat("REPAIR 成功");
	if (repair_base < 0)
		repair_base = 0;

	printf("\n| size | 驻留 avg/med µs | minor avg/med/max µs | "
	       "major avg/med/max µs | REPAIR b/mi/ma |\n");
	printf("|------|-----------------|----------------------|"
	       "----------------------|----------------|\n");

	for (i = 0; i < (int)(sizeof(mat_sizes) / sizeof(mat_sizes[0])); i++) {
		size_t size = mat_sizes[i];
		int slice_pages = (int)((size + SYMRDMA_PAGE_SIZE - 1) /
					SYMRDMA_PAGE_SIZE);
		size_t slice = (size_t)slice_pages * SYMRDMA_PAGE_SIZE;
		int n_fault = (slice_pages <= 1) ? 100 :
			      (size <= 65536 ? 30 : 10);
		int n_base = MAT_MAX_SAMPLES;
		int npages = n_fault + 4;   /* a 区页数 (基线+major) */
		size_t len_a = (size_t)npages * slice;
		size_t len_b = (size_t)n_fault * slice;
		uint64_t b_avg, b_med, b_max, mi_avg, mi_med, mi_max;
		uint64_t ma_avg, ma_med, ma_max;
		long long base0 = repair_base;
		int s, bad = 0;

		/* region_a: 基线 + major (驻留 0xAB) */
		reg_a = mmap(NULL, len_a, PROT_READ | PROT_WRITE,
			     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (reg_a == MAP_FAILED) { rc = 1; goto err_out; }
		memset(reg_a, 0xAB, len_a);
		if (mat_region_register(&ctx, pd, reg_a, len_a, &smr_a)) {
			fprintf(stderr, "[dbg] region_a 注册失败\n");
			rc = 1;
			goto err_out;
		}
		/* region_b: minor 专用 — MAP_NORESERVE 从不触摸 */
		reg_b = mmap(NULL, len_b, PROT_READ | PROT_WRITE,
			     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (reg_b == MAP_FAILED) { rc = 1; goto err_out; }
		if (mat_region_register(&ctx, pd, reg_b, len_b, &smr_b)) {
			fprintf(stderr, "[dbg] region_b 注册失败\n");
			rc = 1;
			goto err_out;
		}

		/* --- 驻留基线 --- */
		srand(seed);
		for (s = 0; s < n_base; s++) {
			int pg = (int)((unsigned)rand() % npages) * slice_pages;
			uint64_t t0 = now_us();

			if (symrdma_read(&ctx, qp, cq, &smr_a, (unsigned long)pg,
					 size, local, local_mr->lkey)) {
				fprintf(stderr, "  [base] size=%zu 读失败\n", size);
				rc = 1;
				goto err_out;
			}
			lat[s] = now_us() - t0;
		}
		rep = proc_stat("REPAIR 成功") - base0;
		repair_base += rep;
		mat_stats(lat, n_base, &b_avg, &b_med, &b_max);

		/* --- minor: 每片从未触摸, 只读一次 --- */
		rep = proc_stat("REPAIR 成功");
		for (s = 0; s < n_fault; s++) {
			unsigned long pg = (unsigned long)s * slice_pages;
			uint64_t t0 = now_us();

			if (symrdma_read(&ctx, qp, cq, &smr_b, pg, size,
					 local, local_mr->lkey)) {
				fprintf(stderr, "  [minor] size=%zu 片%d 读失败\n",
					size, s);
				rc = 1;
				goto err_out;
			}
			lat[s] = now_us() - t0;
			if (mat_verify(local, size, 0)) {
				fprintf(stderr,
					"  [minor] size=%zu 片%d 数据异常 (期望全零)\n",
					size, s);
				bad = 1;
			}
		}
		rep = proc_stat("REPAIR 成功") - rep;
		repair_base += rep;
		mat_stats(lat, n_fault, &mi_avg, &mi_med, &mi_max);
		if (rep < n_fault) {
			fprintf(stderr,
				"  [minor] size=%zu: REPAIR Δ=%lld < 样本 %d — 缺页未生效\n",
				size, rep, n_fault);
			bad = 1;
		}

		/* --- major: 驻留 0xAB → PAGEOUT → 就位 → 读 --- */
		rep = proc_stat("REPAIR 成功");
		for (s = 0; s < n_fault; s++) {
			int pg0 = (s % 4) * slice_pages;   /* 4 片轮转 */
			unsigned long pg = (unsigned long)pg0;
			uint64_t t0;

			madvise(reg_a + (size_t)pg0 * SYMRDMA_PAGE_SIZE,
				slice, MADV_PAGEOUT);
			if (mat_wait_sentinel(&ctx, &smr_a, reg_a, pg,
					      slice_pages)) {
				fprintf(stderr,
					"  [major] size=%zu 片%d 换出未就位\n",
					size, s);
				bad = 1;
				break;
			}
			t0 = now_us();
			if (symrdma_read(&ctx, qp, cq, &smr_a, pg, size,
					 local, local_mr->lkey)) {
				fprintf(stderr, "  [major] size=%zu 片%d 读失败\n",
					size, s);
				rc = 1;
				goto err_out;
			}
			lat[s] = now_us() - t0;
			if (mat_verify(local, size, 0xABABABABu)) {
				fprintf(stderr,
					"  [major] size=%zu 片%d 数据异常 (期望 0xAB)\n",
					size, s);
				bad = 1;
			}
		}
		rep = proc_stat("REPAIR 成功") - rep;
		repair_base += rep;
		mat_stats(lat, n_fault, &ma_avg, &ma_med, &ma_max);
		if (rep < n_fault) {
			fprintf(stderr,
				"  [major] size=%zu: REPAIR Δ=%lld < 样本 %d\n",
				size, rep, n_fault);
			bad = 1;
		}

		printf("| %6zu | %6llu/%6llu | %7llu/%6llu/%6llu | "
		       "%7llu/%6llu/%6llu | %2lld/%2lld/%2lld %s |\n",
		       size,
		       (unsigned long long)b_avg, (unsigned long long)b_med,
		       (unsigned long long)mi_avg, (unsigned long long)mi_med,
		       (unsigned long long)mi_max,
		       (unsigned long long)ma_avg, (unsigned long long)ma_med,
		       (unsigned long long)ma_max,
		       (long long)0, rep, rep, bad ? "✗" : " ");
		fflush(stdout);
		(void)b_max;

		mat_region_release(&ctx, &smr_b, reg_b, len_b);
		reg_b = NULL;
		mat_region_release(&ctx, &smr_a, reg_a, len_a);
		reg_a = NULL;
		rc |= bad;
	}
	printf("\n[判定] %s\n", rc ? "FAIL" : "PASS (矩阵完成, 数据/REPAIR 完整性通过)");

err_out:
	if (local_mr)
		ibv_dereg_mr(local_mr);
	if (local_ioctl_mr_id >= 0)
		ioctl(ctx.fd, SYMRDMA_IOC_DEREG_MR, local_ioctl_mr_id);
	mat_region_release(&ctx, &smr_b, reg_b, 0);
	mat_region_release(&ctx, &smr_a, reg_a, 0);
	if (qp)
		ibv_destroy_qp(qp);
	if (cq)
		ibv_destroy_cq(cq);
	if (pd)
		ibv_dealloc_pd(pd);
	if (ibctx)
		ibv_close_device(ibctx);
	if (local && local != MAP_FAILED)
		munmap(local, local_len);
	symrdma_close(&ctx);
	return rc;
}

int main(int argc, char **argv)
{
	if (argc > 1 && strcmp(argv[1], "--matrix") == 0)
		return matrix_main();
	return legacy_main();
}
