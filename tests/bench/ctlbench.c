/* ctlbench.c — 控制面开销基准 (论文 Tables 1/2 复现,)
 *
 * 同一二进制两种相位 (由脚本控制环境, 程序仅检测并报告):
 *   vanilla: 无 preload — 全部 verbs 走原生路径 (注册 = GUP pin + dma_map)
 *   sym:     NPRDMA_INTERCEPT=all + LD_PRELOAD=libnprdma.so — reg/cq/qp 经
 *            拦截层 (no-pin 注册 + IOMMU 双映射 + 用户态版本表 + 3× QP 深度)
 *
 * 测量行 (输出 "RESULT <row> <value> <unit>", 供 run_ctl_bench.sh 解析):
 *   lib_init     ms  open_device+alloc_pd+query_port+query_gid (进程内一次;
 *                    两相位均不拦截, 差值 ≈ preload .so 装载, 见口径)
 *   mr_first     µs  进程首次 reg_mr(1 页)+dereg (sym 相位含模块功能探测
 *                    REG/DEREG ioctl 往返, 论文 "Library init" 语义的近似)
 *   mr_base      µs  稳态 reg_mr(1 页)+dereg 中位数 (默认 200 轮)
 *   mr_reg_<M>MB µs  触碰后的 M-MB 匿名缓冲注册 (默认 64/128/256/512;
 *                    上限默认 512MB — 内核 REG_MR 页数组 kcalloc 16B/页,
 *                    2GB 需 8MB 连续内核内存, 超 KMALLOC_MAX(4MB) 必败)
 *   mr_slope     ms/GB  对成功点做最小二乘斜率 (论文 "Create MR 400/20 ms/GB")
 *   cq_create    µs  create_cq+destroy 中位数 (200 轮; sym 含用户态 CQ)
 *   qp_create    µs  create_qp(RC)+destroy 中位数 (200 轮; sym 为 3× 深度)
 *   qp_rts       µs  INIT→RTR→RTS 三次 modify_qp 序列中位数 (200 轮;
 *                    dgid=本端 GID[g] / dest_qp_num=自身 — 仅编程状态转移
 *                    不发包; MTU=min(active_mtu,4096) L15 教训)
 *   swap_out     µs/页  memset(弄脏) → madvise(MADV_PAGEOUT) 计时, 随后
 *                    mincore 轮询至实际回收 (不计时 —  教训: 单次
 *                    PAGEOUT 是 best-effort); 64 页 × 5 轮取中位数。
 *                    口径: 论文 "Swap out 75µs" 为内核换出路径同步成本,
 *                    本基准计时 madvise 批量 syscall (64 页摊销), 异步回写
 *                    完成等待不计入 — 与论文同测同步部分。
 *   swap_notifier_delta 页  (仅 --mr) /proc/symrdma 「换出重映射页 + 确认真
 *                    缺失」前后差 — 门禁: >0 证明换出真实触发了 notifier
 *
 * --mr: swap 缓冲先注册 (sym 相位 → 经拦截成为 SymRDMA MR, notifier 附加;
 *       vanilla 相位脚本不传 --mr — 原生注册会 pin 住页, PAGEOUT 无法回收)。
 *       注册访问位用混合 LOCAL_WRITE|REMOTE_READ (npfbw 教训: LOCAL_WRITE-only
 *       触发 identity_womr 写区误判; 本基准不走数据面, 保守取混合)。
 *
 * 用法:
 *   ctlbench [-d dev] [-g gid_index] [--mr] [--swap] [-b base_iters]
 *            [-r swap_rounds] [-m "64 128 256 512"]
 * 退出码: 出现任何 FAIL 行 → 1
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <sys/mman.h>
#include <infiniband/verbs.h>

#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif

#define PAGE_SZ     4096UL
#define ACC_MIXED   (IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ)
#define QP_CQ_DEPTH 128
#define SWAP_PAGES  64
#define DEF_BASE_ITERS 200
#define DEF_SWAP_ROUNDS 5

static struct ibv_context *ctx;
static struct ibv_pd     *pd;
static struct ibv_cq     *g_cq_for_qp;   /* QP 创建用共享 CQ (成本归 cq_create) */
static int    g_port = 1;
static int    g_gid  = 5;
static int    g_fail;
static uint8_t g_mtu_flag = IBV_MTU_4096;
static union ibv_gid g_gid_raw;

static double now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static void result(const char *row, double v, const char *unit)
{
	printf("RESULT %s %.2f %s\n", row, v, unit);
}

static void fail(const char *row, const char *why)
{
	printf("FAIL %s %s\n", row, why ? why : "");
	g_fail = 1;
}

static int cmp_d(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

static double median(double *a, int n)
{
	qsort(a, n, sizeof(double), cmp_d);
	return a[n / 2];
}

/* /proc/symrdma 计数器读取: 在某行内找 key 子串, 取冒号后的长整数。
 * 失败 (文件不存在/键缺失) 返回 -1。 */
static long long proc_counter(const char *key)
{
	FILE *fp = fopen("/proc/symrdma", "r");
	char line[512];
	long long v = -1;

	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		char *p;
		if (!strstr(line, key))
			continue;
		p = strchr(line, ':');
		if (!p)
			continue;
		v = strtoll(p + 1, NULL, 10);
		break;
	}
	fclose(fp);
	return v;
}

static void *map_anon(size_t len)
{
	void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	return p == MAP_FAILED ? NULL : p;
}

/* ---- 测量: MR 注册 ---- */

/* 注册 + 计时 (µs); 失败返回 -1 且不写 out。 */
static double reg_timed(void *buf, size_t len, struct ibv_mr **out)
{
	double t0 = now_us();
	struct ibv_mr *m = ibv_reg_mr(pd, buf, len, ACC_MIXED);
	double t1 = now_us();

	if (!m)
		return -1;
	*out = m;
	return t1 - t0;
}

static void measure_mr_first(void)
{
	void *buf = map_anon(PAGE_SZ);
	struct ibv_mr *m = NULL;
	double t;

	if (!buf) {
		fail("mr_first", "mmap");
		return;
	}
	memset(buf, 0x5A, PAGE_SZ);   /* 页就位 (sym: 探测后注册即映射) */
	t = reg_timed(buf, PAGE_SZ, &m);
	if (t < 0) {
		fail("mr_first", "reg_mr");
		munmap(buf, PAGE_SZ);
		return;
	}
	ibv_dereg_mr(m);
	munmap(buf, PAGE_SZ);
	result("mr_first", t, "us");
}

static void measure_mr_base(int iters)
{
	void *buf = map_anon(PAGE_SZ);
	double *s = malloc(sizeof(double) * iters);
	int n = 0, i;

	if (!buf || !s) {
		fail("mr_base", "alloc");
		free(s);
		if (buf)
			munmap(buf, PAGE_SZ);
		return;
	}
	memset(buf, 0x5A, PAGE_SZ);
	for (i = 0; i < iters; i++) {
		struct ibv_mr *m = NULL;
		double t = reg_timed(buf, PAGE_SZ, &m);

		if (t < 0) {
			fail("mr_base", "reg_mr");
			break;
		}
		ibv_dereg_mr(m);
		s[n++] = t;
	}
	if (n > 0)
		result("mr_base", median(s, n), "us");
	free(s);
	munmap(buf, PAGE_SZ);
}

/* 触碰后注册 M-MB 缓冲; 成功返回 µs 并已 dereg+munmap, 失败 -1。 */
static double measure_mr_reg_mb(int mb)
{
	size_t len = (size_t)mb << 20;
	void *buf = map_anon(len);
	struct ibv_mr *m = NULL;
	double t;

	if (!buf) {
		fail("mr_reg", "mmap");
		return -1;
	}
	memset(buf, 0x5A, len);       /* 物理页就位: vanilla pin 真实页
	                               * (零页 COW 会虚增 GUP 成本), sym 无
	                               * pin 但保持同页状态对齐口径 */
	t = reg_timed(buf, len, &m);
	if (t < 0) {
		fail("mr_reg", "reg_mr (ENOMEM/EBUSY?)");
		munmap(buf, len);
		return -1;
	}
	ibv_dereg_mr(m);
	munmap(buf, len);
	return t;
}

static void measure_mr_slope(const int *mbs, int n)
{
	double sx = 0, sy = 0, sxx = 0, sxy = 0;
	int i, k = 0;

	for (i = 0; i < n; i++) {
		char row[32];
		double t = measure_mr_reg_mb(mbs[i]);

		if (t < 0)
			continue;
		snprintf(row, sizeof(row), "mr_reg_%dMB", mbs[i]);
		result(row, t, "us");
		/* 最小二乘累加 (x=GB, y=µs) */
		sx += mbs[i] / 1024.0;
		sy += t;
		sxx += (mbs[i] / 1024.0) * (mbs[i] / 1024.0);
		sxy += (mbs[i] / 1024.0) * t;
		k++;
	}
	if (k >= 2) {
		double den = k * sxx - sx * sx;
		if (den > 0) {
			double slope_us_per_gb = (k * sxy - sx * sy) / den;
			result("mr_slope", slope_us_per_gb / 1000.0, "ms/gb");
		}
	}
}

/* ---- 测量: CQ / QP ---- */

static void measure_cq(int iters)
{
	double *s = malloc(sizeof(double) * iters);
	int n = 0, i;

	if (!s) {
		fail("cq_create", "alloc");
		return;
	}
	for (i = 0; i < iters; i++) {
		double t0 = now_us();
		struct ibv_cq *cq = ibv_create_cq(ctx, QP_CQ_DEPTH, NULL,
						  NULL, 0);
		double t1 = now_us();

		if (!cq) {
			fail("cq_create", "ibv_create_cq");
			break;
		}
		ibv_destroy_cq(cq);
		s[n++] = t1 - t0;
	}
	if (n > 0)
		result("cq_create", median(s, n), "us");
	free(s);
}

static struct ibv_qp *create_rc_qp(void)
{
	struct ibv_qp_init_attr ia = {
		.qp_type    = IBV_QPT_RC,
		.sq_sig_all = 0,
		.cap = {
			.max_send_wr    = 16,
			.max_recv_wr    = 16,
			.max_send_sge   = 1,
			.max_recv_sge   = 1,
		},
	};
	ia.send_cq = ia.recv_cq = g_cq_for_qp;

	return ibv_create_qp(pd, &ia);
}

static void measure_qp_create(int iters)
{
	double *s = malloc(sizeof(double) * iters);
	int n = 0, i;

	if (!s) {
		fail("qp_create", "alloc");
		return;
	}
	for (i = 0; i < iters; i++) {
		double t0 = now_us();
		struct ibv_qp *qp = create_rc_qp();
		double t1 = now_us();

		if (!qp) {
			fail("qp_create", "ibv_create_qp");
			break;
		}
		ibv_destroy_qp(qp);
		s[n++] = t1 - t0;
	}
	if (n > 0)
		result("qp_create", median(s, n), "us");
	free(s);
}

/* INIT→RTR→RTS 转移序列计时 (create/destroy 不计入)。
 * dgid = 本端 GID[g] (自指 — 仅编程状态, 无对端不发包), dest_qp_num = 自身。 */
static double qp_transitions_timed(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	double t0, t1;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state        = IBV_QPS_INIT;
	attr.pkey_index      = 0;
	attr.port_num        = g_port;
	attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE |
			       IBV_ACCESS_LOCAL_WRITE;
	t0 = now_us();
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
		return -1;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state           = IBV_QPS_RTR;
	attr.path_mtu           = g_mtu_flag;   /* min(active_mtu,4096) */
	attr.dest_qp_num        = qp->qp_num;
	attr.rq_psn             = 1;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer      = 12;
	attr.ah_attr.port_num   = g_port;
	attr.ah_attr.is_global  = 1;
	attr.ah_attr.grh.sgid_index = (uint8_t)g_gid;
	attr.ah_attr.grh.hop_limit  = 1;
	memcpy(&attr.ah_attr.grh.dgid, &g_gid_raw, sizeof(g_gid_raw));
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_MTU |
			  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER | IBV_QP_AV))
		return -1;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state      = IBV_QPS_RTS;
	attr.sq_psn        = 2;
	attr.timeout       = 14;
	attr.retry_cnt     = 7;
	attr.rnr_retry     = 7;
	attr.max_rd_atomic = 1;
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN |
			  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))
		return -1;
	t1 = now_us();
	return t1 - t0;
}

static void measure_qp_rts(int iters)
{
	double *s = malloc(sizeof(double) * iters);
	int n = 0, i;

	if (!s) {
		fail("qp_rts", "alloc");
		return;
	}
	for (i = 0; i < iters; i++) {
		struct ibv_qp *qp = create_rc_qp();
		double t;

		if (!qp) {
			fail("qp_rts", "ibv_create_qp");
			break;
		}
		t = qp_transitions_timed(qp);
		ibv_destroy_qp(qp);
		if (t < 0) {
			fail("qp_rts", "modify_qp");
			break;
		}
		s[n++] = t;
	}
	if (n > 0)
		result("qp_rts", median(s, n), "us");
	free(s);
}

/* ---- 测量: swap-out ---- */

/* 换出就位判据: /proc/self/smaps 目标 VMA 的 Swap: 字段 ≥ len/1024 kB。
 * ⚠ mincore 不可用作就位判据 — PTE 已换出但 folio 留 swap cache 时恒报
 * resident (odp_compare L3 注记同款); 空闲大内存机器上 swapcache 长期
 * 不释放, mincore 轮询永不收敛 (本轮 host-a/8 实测: 首次 madvise 后
 * smaps Swap=256kB 即全部换出, 而 mincore 64/64 "resident")。
 * 轮询内反复 madvise 保留 (best-effort 场景: 刚被修复 GUP 换入
 * 的页单次 PAGEOUT 可能不回收)。 */
static long vma_swap_kb(const void *addr)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256];
	unsigned long rs = 0, re = 0;
	long v = -1;
	int in = 0;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%lx-%lx", &rs, &re) == 2) {
			in = ((unsigned long)addr >= rs &&
			      (unsigned long)addr < re);
			continue;
		}
		if (in && sscanf(line, "Swap: %ld", &v) == 1)
			break;
	}
	fclose(f);
	return v;
}

/* 轮询至实际换出 (≤2s, 200×10ms; 不计入换出计时)。返回 0 = 全部换出。 */
static int wait_swapped(void *buf, size_t len)
{
	const long need = (long)(len / 1024);
	int r;

	for (r = 0; r < 200; r++) {
		if (vma_swap_kb(buf) >= need)
			return 0;
		madvise(buf, len, MADV_PAGEOUT);
		usleep(10000);
	}
	return -1;
}

static void measure_swap(int rounds, int with_mr)
{
	const size_t len = SWAP_PAGES * PAGE_SZ;
	void *buf = map_anon(len);
	double *s = malloc(sizeof(double) * rounds);
	int n = 0, r;
	long long c0 = 0, c0b = 0;

	if (!buf || !s) {
		fail("swap_out", "alloc");
		free(s);
		if (buf)
			munmap(buf, len);
		return;
	}
	if (with_mr) {
		struct ibv_mr *m = NULL;
		double t = reg_timed(buf, len, &m);

		if (t < 0) {
			fail("swap_out", "reg_mr");
			free(s);
			munmap(buf, len);
			return;
		}
		result("swap_mr_reg", t, "us");
		c0  = proc_counter("换出重映射页");
		c0b = proc_counter("确认真缺失");
	}
	r = 0;
	while (n < rounds && r < rounds * 4) {
		double t0, t1;
		long sw_after;

		r++;
		memset(buf, 0xA5, len);      /* 弄脏 + 确保驻留 (换入) */
		t0 = now_us();
		if (madvise(buf, len, MADV_PAGEOUT) != 0) {
			fail("swap_out", "madvise");
			break;
		}
		t1 = now_us();
		sw_after = vma_swap_kb(buf);   /* 计时 madvise 后的立即换出量 */
		/* 实际换出确认不计时 (判据 smaps Swap, 见 wait_swapped 注记) */
		if (wait_swapped(buf, len) != 0) {
			fail("swap_out", "smaps Swap 超时 (换出未完成)");
			break;
		}
		/* 有效轮判据: 计时 madvise 自身完成了换出 (t1 时 Swap 已满)。
		 * 实测存在 walk-noop 轮 (madvise 跳过回收, 换出发生在不计时
		 * 循环, ≈0.7µs/页假值) 与真换出轮交替 — 无效轮不计入统计,
		 * 否则中位数被污染。 */
		printf("INFO round=%d valid=%d madvise=%.2fus/page t1_swap=%ldkB/%ldkB\n",
		       r - 1, sw_after >= (long)(len / 1024),
		       (t1 - t0) / SWAP_PAGES, sw_after, (long)(len / 1024));
		if (sw_after >= (long)(len / 1024))
			s[n++] = (t1 - t0) / SWAP_PAGES;
	}
	if (n > 0)
		result("swap_out", median(s, n), "us/page");
	if (with_mr) {
		long long c1  = proc_counter("换出重映射页");
		long long c1b = proc_counter("确认真缺失");

		if (c0 >= 0 && c1 >= 0 && c0b >= 0 && c1b >= 0)
			result("swap_notifier_delta",
			       (double)(c1 - c0) + (c1b - c0b), "pages");
		else
			fail("swap_notifier_delta", "/proc/symrdma 不可读");
	}
	free(s);
	munmap(buf, len);
}

/* ---- main ---- */

int main(int argc, char **argv)
{
	const char *devname = NULL;
	int base_iters = DEF_BASE_ITERS, swap_rounds = DEF_SWAP_ROUNDS;
	int with_mr = 0, do_swap = 0;
	int mbs[16], nmbs = 0, i;
	struct ibv_device **list = NULL, *dev = NULL;
	int ndev = 0;
	double t0, t1;
	const char *ic = getenv("NPRDMA_INTERCEPT");
	const char *pl = getenv("LD_PRELOAD");
	static const int def_mbs[] = { 64, 128, 256, 512 };

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-d") && i + 1 < argc) {
			devname = argv[++i];
		} else if (!strcmp(argv[i], "-g") && i + 1 < argc) {
			g_gid = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--mr")) {
			with_mr = 1;
		} else if (!strcmp(argv[i], "--swap")) {
			do_swap = 1;
		} else if (!strcmp(argv[i], "-b") && i + 1 < argc) {
			base_iters = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "-r") && i + 1 < argc) {
			swap_rounds = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "-m") && i + 1 < argc) {
			char *tok, *end = NULL, *s = argv[++i];
			for (tok = strtok_r(s, " ,", &end); tok && nmbs < 16;
			     tok = strtok_r(NULL, " ,", &end))
				mbs[nmbs++] = atoi(tok);
		} else {
			fprintf(stderr, "未知参数: %s\n", argv[i]);
			return 2;
		}
	}
	if (nmbs == 0) {
		memcpy(mbs, def_mbs, sizeof(def_mbs));
		nmbs = 4;
	}

	/* 相位报告 (检测仅供参考, 权威相位由脚本注入的环境决定) */
	if (ic && !strcmp(ic, "all"))
		printf("MODE sym (NPRDMA_INTERCEPT=all)\n");
	else if (pl && strstr(pl, "libnprdma"))
		printf("MODE sym? (libnprdma 已 preload 但 INTERCEPT=%s — 非 all 相位请检查脚本)\n",
		       ic ? ic : "(未设)");
	else
		printf("MODE vanilla\n");

	list = ibv_get_device_list(&ndev);
	if (!list || ndev == 0) {
		fail("lib_init", "无 RDMA 设备");
		return 1;
	}
	for (i = 0; i < ndev; i++) {
		if (devname && strcmp(ibv_get_device_name(list[i]), devname))
			continue;
		dev = list[i];
		break;
	}
	if (!dev)
		dev = list[0];

	/* lib_init: 设备打开 + PD + 端口/GID 查询 (论文 "Library init" 口径
	 * 的核心序列; 两相位均无拦截, 差值 = preload .so 装载/初始化) */
	t0 = now_us();
	ctx = ibv_open_device(dev);
	if (!ctx) {
		fail("lib_init", "ibv_open_device");
		return 1;
	}
	pd = ibv_alloc_pd(ctx);
	if (!pd) {
		fail("lib_init", "ibv_alloc_pd");
		return 1;
	}
	{
		struct ibv_port_attr pa;

		if (ibv_query_port(ctx, g_port, &pa)) {
			fail("lib_init", "ibv_query_port");
			return 1;
		}
		g_mtu_flag = pa.active_mtu < IBV_MTU_4096 ?
			     pa.active_mtu: IBV_MTU_4096;
		printf("INFO dev=%s port=%d active_mtu=%u state=%d\n",
		       ibv_get_device_name(dev), g_port, pa.active_mtu,
		       pa.state);
	}
	if (ibv_query_gid(ctx, g_port, g_gid, &g_gid_raw)) {
		fail("lib_init", "ibv_query_gid");
		return 1;
	}
	t1 = now_us();
	printf("INFO gid_index=%d mtu_flag=%d page=%ldKB\n",
	       g_gid, g_mtu_flag, PAGE_SZ / 1024);
	result("lib_init", (t1 - t0) / 1000.0, "ms");

	measure_mr_first();
	measure_mr_base(base_iters);
	measure_mr_slope(mbs, nmbs);
	measure_cq(base_iters);

	/* QP 共用 CQ: 建一个留在全程 (其创建成本归 cq_create 统计) */
	g_cq_for_qp = ibv_create_cq(ctx, QP_CQ_DEPTH, NULL, NULL, 0);
	if (!g_cq_for_qp) {
		fail("qp_create", "ibv_create_cq");
		return 1;
	}
	measure_qp_create(base_iters);
	measure_qp_rts(base_iters);
	ibv_destroy_cq(g_cq_for_qp);

	if (do_swap)
		measure_swap(swap_rounds, with_mr);

	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	ibv_free_device_list(list);

	printf("DONE fail=%d\n", g_fail);
	return g_fail;
}
