/*
 * atomicbench.c — 原子操作基准 (论文 §5.2.4 Fig 14,)
 *
 * 复现论文三种原子实现的延迟/吞吐对照:
 *   pinned  — Pinned Native: 硬件 RDMA 原子 (IBV_WR_ATOMIC_FETCH_AND_ADD/CAS) 打在
 *             server 的普通 (GUP pin) MR 上, 页恒驻留
 *   odp     — ODP Native: 同样硬件原子, 打在 ON_DEMAND MR 上; 延迟轮前
 *             server 换出全部计数页 (major fault) — 复现论文 "低密度下
 *             延迟尖峰达数百 µs" (NIC 停顿 + 重传超时, §5.2.4/A.6)
 *   sym     — SymRDMA 双端路径 (论文 §3.4): 控制 QP 上的 RPC — client 发
 *             (offset, op, 操作数), server CPU 执行 lock cmpxchg/xadd
 *             (经正常 MMU 路径, 缺页自动换入), 回旧值
 *
 * 两族测量 (论文 Fig 14):
 *   lat — 延迟 vs 计数密度 (计数/页 ∈ {4,16,64,256}; 总计数 256 恒定 →
 *         密度越低跨页越多): 同步单发 N_LAT 次, 取 avg/p50/p99/max。
 *         Fig 14a = FAA, Fig 14b = CAS。驻留条件: pinned/sym 驻留
 *         (论文 "+1–2µs 恒定" 口径), odp 每轮前换出 (论文失稳口径)。
 *   thr — 吞吐 vs 流水深度 (2^1..2^7): 每批 depth 个在飞请求, 计
 *         N_THR 次总耗时 → M ops/s。Fig 14c = FAA, Fig 14d = CAS。
 *         驻留条件: 全部预热驻留 (纯流水效率对照; 硬件侧并发受
 *         max_rd_atomic=16 上限 — 正是论文所述 NIC 资源约束)。
 *
 * CAS 口径: compare==swap 的成功无副作用 CAS (硬件与 CPU cmpxchg 语义
 * 一致、可重复、可校验旧值) — 每轮前 server 把计数区清零, client 恒用
 * CAS(0,0); FAA 恒 +1 (旧值可校验递增)。
 *
 * 计数布局 (三配置一致): 总计数 256 个, 密度 d → 计数 c 位于页 c/d 的
 * (c%d)*8 偏移 (密度低 → 跨页多 → 缺页概率高, 对应论文 A.6 "每页访问
 * 频率更低更可能非驻留")。
 *
 * 会合: 自管 TCP (run_atomic_bench.sh 编排, run_odp_compare 同款):
 *   server -p PORT  — 监听, 交换 QP/rkey/addr, 打 "ready" 后入控制循环
 *   client -c IP -p PORT — 连接, 交换, 跑全部轮次, 打 RESULT/DONE 行
 * 输出行: "RESULT <row> <value> <unit>" (脚本解析 CSV) + markdown 表
 * 退出码: 0=全过 1=有 FAIL 2=ODP 不可用 (跳过)。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif
#ifndef IBV_ACCESS_ON_DEMAND
#define IBV_ACCESS_ON_DEMAND (1 << 6)
#endif

/* ---- SymRDMA ioctl (REG_MR/DEREG_MR; 同 test_atomic.c, 与内核 UAPI 一致) ---- */
#define SYMRDMA_IOC_MAGIC 'S'
struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
#define SYMRDMA_IOC_REG_MR   _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR _IOW(SYMRDMA_IOC_MAGIC,  2, int)

/* SymRDMA MR 标记位 (与 lib/libsymrdma.h 同值) — sym 区经 OFED 补丁驱动
 * 走 no-pin/identity 注册 (notifier 附加, 可换出), 论文 §4.1/§4.2 语义 */
#define SYMRDMA_ACCESS_IDENTITY (1 << 21)

/* ---- 常量 ---- */
#define PAGE_SZ    4096
#define REGION_PAGES 256
#define REGION_SZ  (REGION_PAGES * PAGE_SZ)   /* 1 MB/区 */
#define TOTAL_COUNTERS 256                    /* 总计数恒定; 密度决定跨页数 */
#define NSLOT      256                        /* 收发池槽位数 ≥ 最大深度 128 */
#define MSG_SZ     PAGE_SZ                    /* 控制 buffer 注册粒度整页 (页粒度教训) */
#define MSG_WIRE   64                         /* 线上消息长度: ab_msg 56B 对齐 64 —
					      控制通道小消息 (论文 §3.2); 整页 SEND
					      会让原子 RPC 被线速卡死 (首跑实测) */
#define N_LAT      512                        /* 延迟轮操作数 */
#define N_THR      4096                       /* 吞吐轮操作数 */
#define OP_TIMEOUT_US  30000000ULL              /* 单操作/单轮看门狗 30s */
#define SWAP_DEADLINE_US 2000000ULL            /* 换出就位确认窗口 2s */

static const int dens[]   = { 4, 16, 64, 256 };           /* 计数/页 (2^2..2^8) */
#define NDENS ((int)(sizeof(dens) / sizeof(dens[0])))
static const int depths[] = { 2, 4, 8, 16, 32, 64, 128 }; /* 流水深度 2^1..2^7 */
#define NDEPTH ((int)(sizeof(depths) / sizeof(depths[0])))

static const char *cfg_name[] = { "pinned", "odp", "sym" };
#define CFG_PIN 0
#define CFG_ODP 1
#define CFG_SYM 2

/* ---- 控制协议 (控制 QP SEND/RECV, 同 test_atomic 二进制消息;
 * 线上长度 MSG_WIRE, buffer 注册整页 MSG_SZ) ---- */
#define AB_MAGIC     0x41424F4D   /* 'ABOM' */
#define AB_OP_FAA    1
#define AB_OP_CAS    2
#define AB_OP_SYNC   0x100        /* 轮屏障: 清零 + 驻留预备 (WARM/SWAP) */
#define AB_OP_QUIT   0x200
#define AB_SYNC_WARM 1
#define AB_SYNC_SWAP 2

struct ab_msg {
	uint32_t magic;
	uint32_t op;
	uint32_t region;      /* CFG_PIN/CFG_ODP/CFG_SYM */
	uint32_t density;     /* SYNC: 计数密度 (记录用) */
	uint32_t mode;        /* SYNC: WARM/SWAP */
	uint32_t ok;          /* 响应: 是否成功 */
	uint64_t offset;      /* FAA/CAS: 区内字节偏移 (页对齐 + 页内 8B) */
	uint64_t cmp;         /* CAS expected */
	uint64_t swap;        /* CAS new / FAA delta */
	uint64_t old;         /* 响应: 旧值 / SYNC 响应: 实际换出页数 */
};

/* ---- 全局 ---- */
_Static_assert(sizeof(struct ab_msg) <= MSG_WIRE, "ab_msg 超过线上长度");
static int    g_gid  = 5;                 /* 测试床规程: GID index 5 */
static int    g_fail;
static long   g_anomalies;
static int    g_odp_ok = 1;
static uint8_t g_peer_gid[16];
static int    g_have_peer_gid;

static double now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (double)ts.tv_sec * 1e6 + (double)ts.tv_nsec / 1e3;
}

static void result(const char *row, double v, const char *unit)
{
	printf("RESULT %s %.3f %s\n", row, v, unit);
}

static void fail(const char *why)
{
	printf("FAIL %s\n", why ? why : "");
	g_fail = 1;
}

/* ---- 计数布局: 计数 c (密度 d) → 区内字节偏移 ---- */
static inline uint64_t counter_off(int c, int d)
{
	return (uint64_t)(c / d) * PAGE_SZ + (uint64_t)(c % d) * 8;
}

/* ---- 有界 CQ 轮询: 1 条; 超时返回 -2, 错误返回 -1 ---- */
static int poll_wc_deadline(struct ibv_cq *cq, struct ibv_wc *wc,
			    double deadline)
{
	int n;

	do {
		n = ibv_poll_cq(cq, 1, wc);
		if (n == 0 && now_us() > deadline)
			return -2;
	} while (n == 0);
	if (n < 0 || wc->status != IBV_WC_SUCCESS)
		return -1;
	return 0;
}

/* ---- 统计 ---- */
static int cmp_d(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;

	return (x > y) - (x < y);
}

struct stats {
	double avg, p50, p99, max;
	int    n;
};

static void stats_calc(struct stats *st, double *a, int n)
{
	double sum = 0;
	int i;

	for (i = 0; i < n; i++)
		sum += a[i];
	st->n   = n;
	st->avg = sum / n;
	qsort(a, n, sizeof(double), cmp_d);
	st->p50 = a[n / 2];
	st->p99 = a[(int)(n * 0.99) < n ? (int)(n * 0.99) : n - 1];
	st->max = a[n - 1];
}

/* ---- 设备 / QP 辅助 (同 L7/L15 模式) ---- */
static struct ibv_device *find_rdma_device(const char *prefer)
{
	struct ibv_device **l;
	int n, i;
	struct ibv_device *d = NULL;

	l = ibv_get_device_list(&n);
	if (!l || !n)
		return NULL;
	for (i = 0; i < n; i++) {
		const char *name = ibv_get_device_name(l[i]);

		if ((prefer && strstr(name, prefer)) ||
		    (!prefer && strstr(name, "mlx5"))) {
			d = l[i];
			break;
		}
		if (!d)
			d = l[i];
	}
	return d;
}

static struct ibv_qp *make_qp(struct ibv_pd *pd, struct ibv_cq *cq,
			      int send_wr, int recv_wr)
{
	struct ibv_qp_init_attr a = {0};

	a.send_cq = cq;
	a.recv_cq = cq;
	a.qp_type = IBV_QPT_RC;
	a.cap.max_send_wr  = send_wr;
	a.cap.max_recv_wr  = recv_wr;
	a.cap.max_send_sge = 1;
	a.cap.max_recv_sge = 1;
	return ibv_create_qp(pd, &a);
}

/* INIT→RTR→RTS; mtu=min(active_mtu,4096) (教训);
 * rd_atomic 参数化: 数据 QP 16 (硬件原子流水上限), 控制 QP 1 */
static int qp_to_rts(struct ibv_qp *qp, uint32_t dest_qpn,
		     int max_rd, int max_dest_rd)
{
	struct ibv_qp_attr attr = {0};
	struct ibv_port_attr pa;
	uint8_t mtu = IBV_MTU_4096;

	attr.qp_state        = IBV_QPS_INIT;
	attr.pkey_index      = 0;
	attr.port_num        = 1;
	attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE |
			       IBV_ACCESS_REMOTE_ATOMIC |
			       IBV_ACCESS_LOCAL_WRITE;
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
		return -1;

	if (!ibv_query_port(qp->context, 1, &pa) && pa.active_mtu < IBV_MTU_4096)
		mtu = pa.active_mtu;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state           = IBV_QPS_RTR;
	attr.path_mtu           = mtu;
	attr.dest_qp_num        = dest_qpn;
	attr.rq_psn             = 0;
	attr.max_dest_rd_atomic = max_dest_rd;
	attr.min_rnr_timer      = 12;
	attr.ah_attr.port_num   = 1;
	attr.ah_attr.is_global  = 1;
	attr.ah_attr.grh.sgid_index = (uint8_t)g_gid;
	attr.ah_attr.grh.hop_limit  = 1;
	if (g_have_peer_gid) {
		memcpy(&attr.ah_attr.grh.dgid, g_peer_gid, 16);
	} else if (ibv_query_gid(qp->context, 1, 0, &attr.ah_attr.grh.dgid)) {
		return -1;
	}
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_MTU |
			  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER | IBV_QP_AV))
		return -1;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state      = IBV_QPS_RTS;
	attr.sq_psn        = 0;
	attr.timeout       = 14;
	attr.retry_cnt     = 7;
	attr.rnr_retry     = 7;
	attr.max_rd_atomic = max_rd;
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN |
			  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))
		return -1;
	return 0;
}

static void gid_to_hex(const union ibv_gid *g, char *out)
{
	int i;

	for (i = 0; i < 16; i++)
		sprintf(out + i * 2, "%02x", g->raw[i]);
	out[32] = 0;
}

static int gid_from_hex(const char *hex, uint8_t *out)
{
	int i;

	if (strlen(hex) < 32)
		return 0;
	for (i = 0; i < 16; i++) {
		unsigned v;

		if (sscanf(hex + i * 2, "%2x", &v) != 1)
			return 0;
		out[i] = (uint8_t)v;
	}
	return 1;
}

/* ---- TCP 会合 (自管; run_odp_compare 同款) ---- */
static int tcp_listen(int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0), one = 1;
	struct sockaddr_in a = {0};

	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
	a.sin_family = AF_INET;
	a.sin_addr.s_addr = INADDR_ANY;
	a.sin_port = htons((uint16_t)port);
	if (bind(fd, (struct sockaddr *)&a, sizeof(a)) || listen(fd, 1)) {
		close(fd);
		return -1;
	}
	return fd;
}

static int tcp_connect(const char *ip, int port)
{
	int fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = {0};

	a.sin_family = AF_INET;
	a.sin_port = htons((uint16_t)port);
	if (inet_pton(AF_INET, ip, &a.sin_addr) != 1) {
		close(fd);
		return -1;
	}
	if (connect(fd, (struct sockaddr *)&a, sizeof(a))) {
		close(fd);
		return -1;
	}
	return fd;
}

static int xfer_all(int fd, void *buf, size_t len, int wr)
{
	char *p = buf;
	size_t left = len;

	while (left) {
		ssize_t n = wr ? send(fd, p, left, MSG_NOSIGNAL)
			      : recv(fd, p, left, 0);

		if (n <= 0)
			return -1;
		p += n;
		left -= n;
	}
	return 0;
}

/* 参数交换: 固定 512B 文本块 (行式, 空 gid 用 "-") */
struct peer_params {
	uint32_t data_qp_num, ctl_qp_num;
	uint32_t rkey_pin, rkey_odp;
	uint64_t addr_pin, addr_odp;
	int      odp_ok;
	char     gid[40];
};

static int pp_send(int fd, const struct peer_params *p)
{
	char buf[512];
	int n = snprintf(buf, sizeof(buf),
			 "dataqp %u\nctlqp %u\nrkey_pin %u\naddr_pin %llu\n"
			 "rkey_odp %u\naddr_odp %llu\nodp_ok %d\ngid %s\n",
			 p->data_qp_num, p->ctl_qp_num,
			 p->rkey_pin, (unsigned long long)p->addr_pin,
			 p->rkey_odp, (unsigned long long)p->addr_odp,
			 p->odp_ok, p->gid[0] ? p->gid : "-");

	memset(buf + n, 0, sizeof(buf) - n);
	return xfer_all(fd, buf, sizeof(buf), 1);
}

static int pp_recv(int fd, struct peer_params *p)
{
	char buf[512], line[128];
	char *s = buf;
	size_t left = sizeof(buf);

	memset(p, 0, sizeof(*p));
	if (xfer_all(fd, buf, sizeof(buf), 0))
		return -1;
	while (left > 0 && *s) {
		char *nl = memchr(s, '\n', left);
		size_t l;

		if (!nl)
			break;
		l = (size_t)(nl - s);
		if (l >= sizeof(line))
			l = sizeof(line) - 1;
		memcpy(line, s, l);
		line[l] = 0;
		left -= nl + 1 - s;
		s = nl + 1;

		if (!strncmp(line, "dataqp ", 7))
			p->data_qp_num = (uint32_t)strtoul(line + 7, NULL, 10);
		else if (!strncmp(line, "ctlqp ", 6))
			p->ctl_qp_num = (uint32_t)strtoul(line + 6, NULL, 10);
		else if (!strncmp(line, "rkey_pin ", 9))
			p->rkey_pin = (uint32_t)strtoul(line + 9, NULL, 10);
		else if (!strncmp(line, "addr_pin ", 9))
			p->addr_pin = strtoull(line + 9, NULL, 10);
		else if (!strncmp(line, "rkey_odp ", 9))
			p->rkey_odp = (uint32_t)strtoul(line + 9, NULL, 10);
		else if (!strncmp(line, "addr_odp ", 9))
			p->addr_odp = strtoull(line + 9, NULL, 10);
		else if (!strncmp(line, "odp_ok ", 7))
			p->odp_ok = atoi(line + 7);
		else if (!strncmp(line, "gid ", 4) && line[4] != '-') {
			if (gid_from_hex(line + 4, g_peer_gid))
				g_have_peer_gid = 1;
		}
	}
	return (p->data_qp_num && p->ctl_qp_num) ? 0 : -1;
}

/* ================= server ================= */

/* /proc/self/smaps: addr 所在 VMA 的 Swap: 字段合计 (KB → 页数)。
 * mincore 不可用 (教训: swapcache 页恒报 resident)。 */
static long smaps_swapped_pages(const void *addr)
{
	FILE *fp = fopen("/proc/self/smaps", "r");
	unsigned long target = (unsigned long)addr;
	unsigned long start, end;
	char line[256];
	int in = 0;
	long kb = 0, v;

	if (!fp)
		return -1;
	while (fgets(line, sizeof(line), fp)) {
		if (sscanf(line, "%lx-%lx", &start, &end) == 2) {
			if (in)
				break;                 /* 已离开目标 VMA */
			in = (target >= start && target < end);
		} else if (in && sscanf(line, "Swap: %ld", &v) == 1) {
			kb += v;
		}
	}
	fclose(fp);
	return kb * 1024 / PAGE_SZ;
}

/* munlock (若曾 WARM mlock — 否则后续 SWAP 无法回收) + madvise(PAGEOUT)
 * + smaps 就位确认 (重试至 ≥90% 或 2s); 返回实际换出页数 */
static long swap_out_region(char *base)
{
	double deadline = now_us() + SWAP_DEADLINE_US;
	long sw = -1;

	munlock(base, REGION_SZ);   /* WARM 预热可能已 mlock; EINVAL 忽略 */
	madvise(base, REGION_SZ, MADV_PAGEOUT);
	for (;;) {
		sw = smaps_swapped_pages(base);
		if (sw < 0 || sw >= REGION_PAGES - REGION_PAGES / 10)
			break;
		if (now_us() > deadline)
			break;
		madvise(base, REGION_SZ, MADV_PAGEOUT);
		usleep(20000);
	}
	return sw;
}

static int run_server(int port, const char *devname)
{
	struct peer_params mine = {0}, peer = {0};
	unsigned char *pin_buf, *odp_buf, *sym_buf;
	unsigned char *recv_pool, *resp_pool;
	struct ibv_mr *pin_mr, *odp_mr = NULL, *sym_mr, *recv_mr, *resp_mr;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *ctl_cq, *data_cq;
	struct ibv_qp *ctl_qp, *data_qp;
	struct symrdma_ioc_reg_mr reg = {0};
	int sym_fd = -1, sym_mr_id = -1;
	int listen_fd = -1, conn_fd = -1;
	int resp_free[NSLOT], resp_top = NSLOT;
	int i, rc = 1;
	long rounds = 0;

	setvbuf(stdout, NULL, _IOLBF, 0);   /* 重定向到文件也能看到进度 (pkill 不丢日志) */
	printf("=== atomicbench server (port=%d gid=%d) ===\n", port, g_gid);

	sym_fd = open("/dev/symrdma", O_RDWR);
	if (sym_fd < 0) { printf("无法打开 /dev/symrdma\n"); return 2; }

	pin_buf = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	odp_buf = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	sym_buf = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	recv_pool = mmap(NULL, (size_t)NSLOT * MSG_SZ, PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	resp_pool = mmap(NULL, (size_t)NSLOT * MSG_SZ, PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (pin_buf == MAP_FAILED || odp_buf == MAP_FAILED ||
	    sym_buf == MAP_FAILED || recv_pool == MAP_FAILED ||
	    resp_pool == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	memset(pin_buf, 0, REGION_SZ);
	memset(sym_buf, 0, REGION_SZ);          /* sym 区 REG_MR 前须有页 (映射走页表) */
	/* odp 区不触碰 (MAP_NORESERVE 未驻留 = minor fault 源) */

	reg.va_start = (unsigned long long)(uintptr_t)sym_buf;
	reg.len = REGION_SZ;
	if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg)) {
		printf("REG_MR(sym) 失败 errno=%d\n", errno);
		return 1;
	}
	sym_mr_id = reg.mr_id;

	dev = find_rdma_device(devname);
	if (!dev) { printf("无 mlx5 设备\n"); return 2; }
	ctx = ibv_open_device(dev);
	pd  = ibv_alloc_pd(ctx);
	ctl_cq  = ibv_create_cq(ctx, 512, NULL, NULL, 0);
	data_cq = ibv_create_cq(ctx, 64,  NULL, NULL, 0);
	ctl_qp  = make_qp(pd, ctl_cq,  256, 256);
	data_qp = make_qp(pd, data_cq, 16, 1);
	if (!pd || !ctl_cq || !data_cq || !ctl_qp || !data_qp) {
		printf("verbs 资源创建失败\n");
		return 1;
	}

	recv_mr = ibv_reg_mr(pd, recv_pool, (size_t)NSLOT * MSG_SZ,
			     IBV_ACCESS_LOCAL_WRITE);
	resp_mr = ibv_reg_mr(pd, resp_pool, (size_t)NSLOT * MSG_SZ,
			     IBV_ACCESS_LOCAL_WRITE);
	sym_mr = ibv_reg_mr(pd, sym_buf, REGION_SZ,
			    IBV_ACCESS_LOCAL_WRITE |
			    IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_REMOTE_WRITE |
			    SYMRDMA_ACCESS_IDENTITY);
	pin_mr = ibv_reg_mr(pd, pin_buf, REGION_SZ,
			    IBV_ACCESS_LOCAL_WRITE |
			    IBV_ACCESS_REMOTE_ATOMIC);
	odp_mr = g_odp_ok ? ibv_reg_mr(pd, odp_buf, REGION_SZ,
				   IBV_ACCESS_LOCAL_WRITE |
				   IBV_ACCESS_REMOTE_ATOMIC |
				   IBV_ACCESS_ON_DEMAND): NULL;
	if (!recv_mr || !resp_mr || !sym_mr || !pin_mr ||
		    (g_odp_ok && !odp_mr)) {
		printf("MR 注册失败 (odp_ok=%d odp_mr=%p)\n", g_odp_ok,
		       (void *)odp_mr);
		g_odp_ok = 0;
		if (!recv_mr || !resp_mr || !sym_mr || !pin_mr)
			return 1;
	}

	listen_fd = tcp_listen(port);
	if (listen_fd < 0) { perror("listen"); return 1; }
	printf("ready: 等待 client (port %d)\n", port);
	fflush(stdout);

	conn_fd = accept(listen_fd, NULL, NULL);
	if (conn_fd < 0) { perror("accept"); return 1; }

	{
		union ibv_gid g;

		if (!ibv_query_gid(ctx, 1, g_gid, &g))
			gid_to_hex(&g, mine.gid);
	}
	mine.data_qp_num = data_qp->qp_num;
	mine.ctl_qp_num  = ctl_qp->qp_num;
	mine.rkey_pin    = pin_mr->rkey;
	mine.addr_pin    = (uint64_t)(uintptr_t)pin_buf;
	mine.rkey_odp    = odp_mr ? odp_mr->rkey : 0;
	mine.addr_odp    = (uint64_t)(uintptr_t)odp_buf;
	mine.odp_ok      = odp_mr ? 1 : 0;
	if (pp_send(conn_fd, &mine) || pp_recv(conn_fd, &peer)) {
		printf("参数交换失败\n");
		goto out;
	}
	if (qp_to_rts(data_qp, peer.data_qp_num, 16, 16) ||
	    qp_to_rts(ctl_qp,  peer.ctl_qp_num,  1, 1)) {
		printf("QP→RTS 失败\n");
		goto out;
	}
	printf("linked: data=0x%x ctl=0x%x odp_ok=%d\n",
	       peer.data_qp_num, peer.ctl_qp_num, mine.odp_ok);
	fflush(stdout);

	/* 预挂全部 recv (client 深度 ≤128 < NSLOT) */
	for (i = 0; i < NSLOT; i++) {
		struct ibv_sge sge = {
			.addr = (uintptr_t)(recv_pool + (size_t)i * MSG_SZ),
			.length = MSG_WIRE, .lkey = recv_mr->lkey,
		};
		struct ibv_recv_wr wr = {0}, *bad = NULL;

		wr.wr_id = (uintptr_t)i;
		wr.sg_list = &sge;
		wr.num_sge = 1;
		if (ibv_post_recv(ctl_qp, &wr, &bad)) {
			printf("post_recv 失败 slot=%d\n", i);
			goto out;
		}
	}
	for (i = 0; i < NSLOT; i++)
		resp_free[i] = NSLOT - 1 - i;   /* 栈: 顶=0 起弹出 */

	for (;;) {
		struct ibv_wc wcs[32];
		int n = ibv_poll_cq(ctl_cq, 32, wcs), k;

		if (n < 0) { printf("poll_cq 错误\n"); goto out; }
		for (k = 0; k < n; k++) {
			struct ibv_wc *wc = &wcs[k];

			if (wc->opcode == IBV_WC_RECV) {
				struct ab_msg req, resp;
				int slot = (int)wc->wr_id;
				int rslot;

				if (wc->status != IBV_WC_SUCCESS) {
					printf("recv 异常 status=%d\n",
					       wc->status);
					goto out;
				}
				memcpy(&req, recv_pool + (size_t)slot * MSG_SZ,
				       sizeof(req));
				if (req.magic != AB_MAGIC) {
					printf("协议 magic 错\n");
					goto out;
				}
				memset(&resp, 0, sizeof(resp));
				resp.magic = AB_MAGIC;
				resp.op = req.op;

				if (req.op == AB_OP_FAA ||
				    req.op == AB_OP_CAS) {
					uint64_t *t = (uint64_t *)
						(sym_buf + req.offset);

					if (req.op == AB_OP_FAA) {
						resp.old = __atomic_fetch_add(
							t, req.swap,
							__ATOMIC_SEQ_CST);
						resp.ok = 1;
					} else {
						uint64_t exp = req.cmp;

						resp.ok = __atomic_compare_exchange_n(
							t, &exp, req.swap, 0,
							__ATOMIC_SEQ_CST,
							__ATOMIC_SEQ_CST);
						resp.old = exp;
					}
					rounds++;
				} else if (req.op == AB_OP_SYNC) {
					char *base = req.region == CFG_PIN ?
						(char *)pin_buf :
						req.region == CFG_ODP ?
						(char *)odp_buf :
						(char *)sym_buf;
					long sw = 0;

					/* 清零 (触页 → 驻留) 恒先做 */
					memset(base, 0, REGION_SZ);
					if (req.mode == AB_SYNC_SWAP) {
						sw = swap_out_region(base);
						printf("[sync] region=%s "
						       "swap: %ld/%d 页\n",
						       cfg_name[req.region],
						       sw, REGION_PAGES);
					} else if (req.region == CFG_ODP) {
						if (mlock(odp_buf, REGION_SZ))
							printf("[sync] odp "
							       "mlock 失败 "
							       "errno=%d\n",
							       errno);
					}
					resp.ok = 1;
					resp.old = (uint64_t)sw;
					rounds++;
				} else if (req.op == AB_OP_QUIT) {
					printf("[quit] rounds=%ld "
					       "anomalies=%ld\n",
					       rounds, g_anomalies);
					resp.ok = 1;
					if (resp_top <= 0)
						goto out;
					rslot = resp_free[--resp_top];
					resp.old = 0;
					{
						struct ibv_sge sge = {
							.addr = (uintptr_t)
							(resp_pool +
							 (size_t)rslot *
							 MSG_SZ),
							.length = MSG_WIRE,
							.lkey = resp_mr->lkey,
						};
						struct ibv_send_wr wr = {0},
							*bad = NULL;

						resp.magic = AB_MAGIC;
						memcpy(resp_pool +
						       (size_t)rslot * MSG_SZ,
						       &resp, sizeof(resp));
						wr.opcode = IBV_WR_SEND;
						wr.wr_id = (uintptr_t)rslot;
						wr.sg_list = &sge;
						wr.num_sge = 1;
						wr.send_flags =
							IBV_SEND_SIGNALED;
						if (ibv_post_send(ctl_qp, &wr,
								  &bad))
							goto out;
					}
					/* 等该响应发出后干净退出 */
					for (;;) {
						struct ibv_wc wq;
						int m = ibv_poll_cq(ctl_cq, 1,
								    &wq);

						if (m > 0 &&
						    wq.opcode == IBV_WC_SEND &&
						    (int)wq.wr_id == rslot)
							break;
					}
					rc = g_fail ? 1 : 0;
					goto out;
				} else {
					printf("未知 op %u\n", req.op);
					resp.ok = 0;
				}

				/* 响应: 弹 resp 槽 → 发送 (signaled);
				 * 深度 ≤128 < NSLOT, 槽必可得 */
				if (resp_top <= 0) {
					printf("resp 池耗尽\n");
					goto out;
				}
				rslot = resp_free[--resp_top];
				{
					struct ibv_sge sge = {
						.addr = (uintptr_t)(resp_pool +
							(size_t)rslot * MSG_SZ),
						.length = MSG_WIRE,
						.lkey = resp_mr->lkey,
					};
					struct ibv_send_wr wr = {0}, *bad = NULL;

					memcpy(resp_pool +
					       (size_t)rslot * MSG_SZ,
					       &resp, sizeof(resp));
					wr.opcode = IBV_WR_SEND;
					wr.wr_id = (uintptr_t)rslot;
					wr.sg_list = &sge;
					wr.num_sge = 1;
					wr.send_flags = IBV_SEND_SIGNALED;
					if (ibv_post_send(ctl_qp, &wr, &bad)) {
						printf("post_send(resp) 失败\n");
						resp_top++;
						goto out;
					}
				}
				/* recv 槽立即可复用: 请求已拷出 → 重挂 */
				{
					struct ibv_sge sge = {
						.addr = (uintptr_t)(recv_pool +
							(size_t)slot * MSG_SZ),
						.length = MSG_WIRE,
						.lkey = recv_mr->lkey,
					};
					struct ibv_recv_wr wr = {0}, *bad = NULL;

					wr.wr_id = (uintptr_t)slot;
					wr.sg_list = &sge;
					wr.num_sge = 1;
					if (ibv_post_recv(ctl_qp, &wr, &bad)) {
						printf("post_recv 重挂失败\n");
						goto out;
					}
				}
			} else if (wc->opcode == IBV_WC_SEND) {
				if (wc->status != IBV_WC_SUCCESS) {
					printf("send(resp) 异常 status=%d\n",
					       wc->status);
					goto out;
				}
				resp_free[resp_top++] = (int)wc->wr_id;
			}
		}
	}

out:
	printf("DONE fail=%d\n", g_fail);
	fflush(stdout);
	if (conn_fd >= 0)
		close(conn_fd);
	if (listen_fd >= 0)
		close(listen_fd);
	if (odp_mr)
		ibv_dereg_mr(odp_mr);
	if (pin_mr)
		ibv_dereg_mr(pin_mr);
	if (sym_mr)
		ibv_dereg_mr(sym_mr);
	if (recv_mr)
		ibv_dereg_mr(recv_mr);
	if (resp_mr)
		ibv_dereg_mr(resp_mr);
	if (sym_mr_id >= 0)
		ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, sym_mr_id);
	ibv_destroy_qp(ctl_qp);
	ibv_destroy_qp(data_qp);
	ibv_destroy_cq(ctl_cq);
	ibv_destroy_cq(data_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(pin_buf, REGION_SZ);
	munmap(odp_buf, REGION_SZ);
	munmap(sym_buf, REGION_SZ);
	munmap(recv_pool, (size_t)NSLOT * MSG_SZ);
	munmap(resp_pool, (size_t)NSLOT * MSG_SZ);
	close(sym_fd);
	(void)peer;
	return rc;
}

/* ================= client ================= */

/* 控制 QP 上的 RPC: 发请求 (signaled) → 收响应。
 * recv 池启动时预挂 NSLOT; 消费后立即重挂同槽 (锁步与吞吐共用)。
 * send CQE 与响应 recv CQE 到达顺序不保证 — 循环收集两者。 */
static int post_recv_slot(struct ibv_qp *qp, struct ibv_mr *recv_mr, int slot);

static int rpc_roundtrip(struct ibv_qp *qp, struct ibv_cq *cq,
			 struct ibv_mr *send_mr, struct ibv_mr *recv_mr,
			 int send_slot, const struct ab_msg *req,
			 struct ab_msg *resp)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)((char *)(uintptr_t)send_mr->addr +
				    (size_t)send_slot * MSG_SZ),
		.length = MSG_WIRE, .lkey = send_mr->lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	double deadline = now_us() + OP_TIMEOUT_US;
	int got_send = 0, got_recv = 0, rc = 0;

	memcpy((void *)(uintptr_t)sge.addr, req, sizeof(*req));
	wr.opcode = IBV_WR_SEND;
	wr.wr_id = (uintptr_t)send_slot;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	while ((!got_send || !got_recv) && !rc) {
		int r = poll_wc_deadline(cq, &wc, deadline);

		if (r) {
			if (r == -1)
				fprintf(stderr,
					"  [rpc] wc status=%d opcode=%d\n",
					wc.status, wc.opcode);
			return -1;
		}
		if (wc.opcode == IBV_WC_SEND && (int)wc.wr_id == send_slot) {
			got_send = 1;
		} else if (wc.opcode == IBV_WC_RECV) {
			memcpy(resp, (void *)(uintptr_t)recv_mr->addr +
			       (size_t)wc.wr_id * MSG_SZ, sizeof(*resp));
			/* 重挂消费掉的 recv 槽 (池永不耗尽) */
			if (post_recv_slot(qp, recv_mr, (int)wc.wr_id))
				rc = -1;
			got_recv = 1;
		}
		/* 其他 CQE (异常残余) 忽略继续 */
	}
	return rc ? rc : ((resp->magic == AB_MAGIC && resp->op == req->op)
			  ? 0 : -1);
}

/* 预挂一个 recv (控制 QP) */
static int post_recv_slot(struct ibv_qp *qp, struct ibv_mr *recv_mr, int slot)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)((char *)(uintptr_t)recv_mr->addr +
				    (size_t)slot * MSG_SZ),
		.length = MSG_WIRE, .lkey = recv_mr->lkey,
	};
	struct ibv_recv_wr wr = {0}, *bad = NULL;

	wr.wr_id = (uintptr_t)slot;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	return ibv_post_recv(qp, &wr, &bad);
}

/* SYNC 轮屏障 (锁步; 响应 old = 实际换出页数) */
static long sync_round(struct ibv_qp *qp, struct ibv_cq *cq,
		       struct ibv_mr *send_mr, struct ibv_mr *recv_mr,
		       int region, int mode, int density)
{
	struct ab_msg req = {0}, resp = {0};

	req.magic = AB_MAGIC;
	req.op = AB_OP_SYNC;
	req.region = region;
	req.mode = mode;
	req.density = density;
	if (rpc_roundtrip(qp, cq, send_mr, recv_mr, 0, &req, &resp)) {
		fail("SYNC 失败");
		return -1;
	}
	return (long)resp.old;
}

/* 硬件原子单发 (pinned/odp): 返回 0 = OK */
static int hw_atomic(struct ibv_qp *qp, struct ibv_cq *cq,
		     struct ibv_mr *res_mr, int slot, int op,
		     uint64_t remote_addr, uint32_t rkey)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)((char *)(uintptr_t)res_mr->addr +
				    (size_t)slot * 8),
		.length = 8, .lkey = res_mr->lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	double deadline = now_us() + OP_TIMEOUT_US;
	int r;

	wr.opcode = op == AB_OP_FAA ? IBV_WR_ATOMIC_FETCH_AND_ADD : IBV_WR_ATOMIC_CMP_AND_SWP;
	wr.wr.atomic.remote_addr = remote_addr;
	wr.wr.atomic.rkey = rkey;
	wr.wr.atomic.compare_add = 0;   /* FAA: addend=1 下面覆写; CAS: expected=0 */
	wr.wr.atomic.swap = 0;          /* CAS: new=0 (compare==swap 成功无副作用) */
	if (op == AB_OP_FAA)
		wr.wr.atomic.compare_add = 1;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.wr_id = (uintptr_t)slot;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	r = poll_wc_deadline(cq, &wc, deadline);
	if (r == -1)
		fprintf(stderr, "  [hw] 原子 wc status=%d vendor=0x%x\n",
			wc.status, wc.vendor_err);
	return r;
}

/* QP 状态快照 (诊断用) */
static int qp_state_of(struct ibv_qp *qp)
{
	struct ibv_qp_attr attr;
	struct ibv_qp_init_attr init;

	if (!qp || ibv_query_qp(qp, &attr, IBV_QP_STATE, &init))
		return -1;
	return attr.qp_state;
}

/* 延迟轮: 同步 N_LAT 次单发; cfg 见 cfg_name */
static int bench_latency(struct ibv_qp *ctl_qp, struct ibv_cq *ctl_cq,
			 struct ibv_qp *data_qp, struct ibv_cq *data_cq,
			 struct ibv_mr *send_mr, struct ibv_mr *recv_mr,
			 struct ibv_mr *res_mr,
			 const struct peer_params *sp, int cfg, int op,
			 int density, struct stats *st)
{
	double lat[N_LAT];
	char row[64];
	int i;

	/* 轮屏障: odp → 换出 (major fault 口径); pinned/sym → 驻留预热 */
	{
		long sw = sync_round(ctl_qp, ctl_cq, send_mr, recv_mr, cfg,
				     cfg == CFG_ODP ? AB_SYNC_SWAP : AB_SYNC_WARM,
				     density);

		if (sw < 0)
			return -1;
		if (cfg == CFG_ODP) {
			snprintf(row, sizeof(row), "meta_swap_odp_d%d",
				 density);
			result(row, (double)sw, "pages");
		}
	}

	for (i = 0; i < N_LAT; i++) {
		int c = i % TOTAL_COUNTERS;
		uint64_t off = counter_off(c, density);
		double t0, t1;
		int r;

		t0 = now_us();
		if (cfg == CFG_SYM) {
			struct ab_msg req = {0}, resp = {0};

			req.magic = AB_MAGIC;
			req.op = op;
			req.offset = off;
			if (op == AB_OP_FAA)
				req.swap = 1;
			else {
				req.cmp = 0;
				req.swap = 0;
			}
			r = rpc_roundtrip(ctl_qp, ctl_cq, send_mr, recv_mr,
					  i % NSLOT, &req, &resp);
			if (!r && op == AB_OP_CAS && !resp.ok)
				g_anomalies++;
		} else {
			uint32_t rkey = cfg == CFG_ODP ? sp->rkey_odp
						      : sp->rkey_pin;
			uint64_t base = cfg == CFG_ODP ? sp->addr_odp
						      : sp->addr_pin;

			r = hw_atomic(data_qp, data_cq, res_mr, i % NSLOT,
				      op, base + off, rkey);
		}
		t1 = now_us();
		if (r) {
			fail("原子操作失败/超时");
			return -1;
		}
		lat[i] = t1 - t0;
	}
	stats_calc(st, lat, N_LAT);
	snprintf(row, sizeof(row), "lat_%s_%s_d%d", cfg_name[cfg],
		 op == AB_OP_FAA ? "faa" : "cas", density);
	result(row, st->avg, "us");
	snprintf(row, sizeof(row), "lat99_%s_%s_d%d", cfg_name[cfg],
		 op == AB_OP_FAA ? "faa" : "cas", density);
	result(row, st->p99, "us");
	return 0;
}

/* 吞吐轮: 批深 depth 在飞, 共 N_THR 次 */
static int bench_throughput(struct ibv_qp *ctl_qp, struct ibv_cq *ctl_cq,
			    struct ibv_qp *data_qp, struct ibv_cq *data_cq,
			    struct ibv_mr *send_mr, struct ibv_mr *recv_mr,
			    struct ibv_mr *res_mr,
			    const struct peer_params *sp, int cfg, int op,
			    int depth, struct stats *st)
{
	double deadline;
	uint64_t done = 0;
	double t0, t1;
	int r = 0;

	/* 驻留预热 (全部配置; 纯流水效率对照) */
	if (sync_round(ctl_qp, ctl_cq, send_mr, recv_mr, cfg, AB_SYNC_WARM,
		       0) < 0)
		return -1;

	t0 = now_us();
	deadline = t0 + OP_TIMEOUT_US;

	/* (recv 池启动时已预挂 NSLOT ≥ 2×depth; 每响应消费后立即重挂) */

	while (done < N_THR && !r) {
		int batch = depth, j;

		if (cfg == CFG_SYM) {
			for (j = 0; j < batch; j++) {
				int c = (int)((done + j) % TOTAL_COUNTERS);
				uint64_t off = counter_off(c, dens[NDENS - 1]);
				struct ibv_sge sge = {
					.addr = (uintptr_t)
						((char *)(uintptr_t)send_mr->addr +
						 (size_t)((done + j) % NSLOT) *
						 MSG_SZ),
					.length = MSG_WIRE,
					.lkey = send_mr->lkey,
				};
				struct ab_msg req = {0};
				struct ibv_send_wr wr = {0}, *bad = NULL;

				req.magic = AB_MAGIC;
				req.op = op;
				req.offset = off;
				if (op == AB_OP_FAA)
					req.swap = 1;
				memcpy((void *)(uintptr_t)sge.addr, &req,
				       sizeof(req));
				wr.opcode = IBV_WR_SEND;
				wr.sg_list = &sge;
				wr.num_sge = 1;
				/* unsignaled 省一半 CQE; 但 mlx5 SQ 槽位回收靠轮询到
				 * 本 QP 的 send CQE — 每批末笔必须 signaled (否则
				 * 发满 256 后 post_send ENOMEM, 首跑实测);
				 * 其 send CQE 由下方 j-- stray 路径消化 */
				wr.send_flags = (j == batch - 1) ?
					IBV_SEND_SIGNALED: 0;
				if (ibv_post_send(ctl_qp, &wr, &bad)) {
					fprintf(stderr,
						"thr post_send 失败 j=%d "
						"errno=%d (%s) QP_state=%d\n",
						j, errno, strerror(errno),
						qp_state_of(ctl_qp));
					fail("thr post_send 失败");
					r = -1;
					break;
				}
			}
			/* 收 batch 个响应 → 重挂 recv */
			for (j = 0; j < batch && !r; j++) {
				struct ibv_wc wc;
				struct ab_msg resp;

				if (poll_wc_deadline(ctl_cq, &wc, deadline)) {
					fail("thr 响应超时");
					r = -1;
					break;
				}
				if (wc.opcode != IBV_WC_RECV) {
					j--;   /* send 残余 CQE (异常路径) */
					continue;
				}
				memcpy(&resp,
				       (void *)(uintptr_t)recv_mr->addr +
				       (size_t)wc.wr_id * MSG_SZ,
				       sizeof(resp));
				if (op == AB_OP_CAS && !resp.ok)
					g_anomalies++;
				if (post_recv_slot(ctl_qp, recv_mr,
						   (int)wc.wr_id)) {
					fail("thr post_recv 重挂失败");
					r = -1;
				}
			}
		} else {
			uint32_t rkey = cfg == CFG_ODP ? sp->rkey_odp
						      : sp->rkey_pin;
			uint64_t base = cfg == CFG_ODP ? sp->addr_odp
						      : sp->addr_pin;

			for (j = 0; j < batch; j++) {
				int c = (int)((done + j) % TOTAL_COUNTERS);
				uint64_t off = counter_off(c, dens[NDENS - 1]);
				struct ibv_sge sge = {
					.addr = (uintptr_t)
						((char *)(uintptr_t)res_mr->addr +
						 (size_t)((done + j) % NSLOT) *
						 8),
					.length = 8,
					.lkey = res_mr->lkey,
				};
				struct ibv_send_wr wr = {0}, *bad = NULL;

				wr.opcode = op == AB_OP_FAA ?
					IBV_WR_ATOMIC_FETCH_AND_ADD: IBV_WR_ATOMIC_CMP_AND_SWP;
				wr.wr.atomic.remote_addr = base + off;
				wr.wr.atomic.rkey = rkey;
				wr.wr.atomic.compare_add =
					op == AB_OP_FAA ? 1 : 0;
				wr.wr.atomic.swap = 0;
				wr.sg_list = &sge;
				wr.num_sge = 1;
				wr.send_flags = IBV_SEND_SIGNALED;
				wr.wr_id = (uintptr_t)((done + j) % NSLOT);
				if (ibv_post_send(data_qp, &wr, &bad)) {
					fail("thr 原子 post_send 失败");
					r = -1;
					break;
				}
			}
			for (j = 0; j < batch && !r; j++) {
				struct ibv_wc wc;

				if (poll_wc_deadline(data_cq, &wc, deadline)) {
					fail("thr 原子完成超时/错误");
					r = -1;
					break;
				}
				if (op == AB_OP_CAS) {
					uint64_t oldv = *(uint64_t *)
						((char *)(uintptr_t)res_mr->addr +
						 (size_t)wc.wr_id * 8);

					if (oldv != 0)
						g_anomalies++;
				}
			}
		}
		done += batch;
		if (now_us() > deadline) {
			fail("thr 轮超时");
			r = -1;
		}
	}
	if (r)
		return -1;
	t1 = now_us();
	{
		char row[64];
		double mops = (double)N_THR / (t1 - t0);

		snprintf(row, sizeof(row), "thr_%s_%s_p%d", cfg_name[cfg],
			 op == AB_OP_FAA ? "faa" : "cas", depth);
		result(row, mops, "mops");
		st->avg = mops;
		st->n = 1;
	}
	return 0;
}

static int run_client(const char *ip, int port, const char *devname)
{
	struct peer_params mine = {0}, sp = {0};
	unsigned char *send_pool, *recv_pool;
	uint64_t *res_buf;
	struct ibv_mr *send_mr, *recv_mr, *res_mr;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *ctl_cq, *data_cq;
	struct ibv_qp *ctl_qp, *data_qp;
	int conn_fd, op, i, rc = 1;
	int odp_skip = 0;

	printf("=== atomicbench client → %s:%d (gid=%d) ===\n", ip, port,
	       g_gid);

	conn_fd = tcp_connect(ip, port);
	if (conn_fd < 0) { perror("connect"); return 1; }

	dev = find_rdma_device(devname);
	if (!dev) { printf("无 mlx5 设备\n"); return 2; }
	ctx = ibv_open_device(dev);
	pd  = ibv_alloc_pd(ctx);
	ctl_cq  = ibv_create_cq(ctx, 512, NULL, NULL, 0);
	data_cq = ibv_create_cq(ctx, 512, NULL, NULL, 0);
	ctl_qp  = make_qp(pd, ctl_cq,  256, 256);
	data_qp = make_qp(pd, data_cq, 256, 1);
	send_pool = mmap(NULL, (size_t)NSLOT * MSG_SZ, PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	recv_pool = mmap(NULL, (size_t)NSLOT * MSG_SZ, PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	res_buf = mmap(NULL, (size_t)NSLOT * 8, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (!pd || !ctl_cq || !data_cq || !ctl_qp || !data_qp ||
	    send_pool == MAP_FAILED || recv_pool == MAP_FAILED ||
	    res_buf == MAP_FAILED) {
		printf("client 资源创建失败\n");
		return 1;
	}
	memset(send_pool, 0, (size_t)NSLOT * MSG_SZ);
	memset(recv_pool, 0, (size_t)NSLOT * MSG_SZ);

	send_mr = ibv_reg_mr(pd, send_pool, (size_t)NSLOT * MSG_SZ,
			     IBV_ACCESS_LOCAL_WRITE);
	recv_mr = ibv_reg_mr(pd, recv_pool, (size_t)NSLOT * MSG_SZ,
			     IBV_ACCESS_LOCAL_WRITE);
	res_mr  = ibv_reg_mr(pd, res_buf, (size_t)NSLOT * 8,
			     IBV_ACCESS_LOCAL_WRITE);
	if (!send_mr || !recv_mr || !res_mr) {
		printf("client MR 注册失败\n");
		return 1;
	}

	if (pp_recv(conn_fd, &sp)) { printf("收 server 参数失败\n"); return 1; }
	{
		union ibv_gid g;

		if (!ibv_query_gid(ctx, 1, g_gid, &g))
			gid_to_hex(&g, mine.gid);
	}
	mine.data_qp_num = data_qp->qp_num;
	mine.ctl_qp_num  = ctl_qp->qp_num;
	mine.odp_ok = 1;
	if (pp_send(conn_fd, &mine)) { printf("发 client 参数失败\n"); return 1; }
	if (qp_to_rts(data_qp, sp.data_qp_num, 16, 16) ||
	    qp_to_rts(ctl_qp,  sp.ctl_qp_num,  1, 1)) {
		printf("QP→RTS 失败\n");
		return 1;
	}
	printf("linked: server data=0x%x ctl=0x%x odp_ok=%d\n",
	       sp.data_qp_num, sp.ctl_qp_num, sp.odp_ok);
	if (!sp.odp_ok) {
		printf("!! server ODP MR 不可用 — odp 配置跳过 (rc=2)\n");
		odp_skip = 1;
	}

	/* 预挂全部 recv (锁步 RPC 复用槽位; 吞吐轮自管重挂) */
	for (i = 0; i < NSLOT; i++)
		if (post_recv_slot(ctl_qp, recv_mr, i)) {
			printf("post_recv 失败\n");
			return 1;
		}

	for (op = AB_OP_FAA; op <= AB_OP_CAS && !g_fail; op++) {

		/* ---- 延迟 vs 密度 (Fig 14a/b) ---- */
		printf("\n=== [lat] %s — 计数密度扫描 (Fig 14%s) ===\n",
		       op == AB_OP_FAA ? "FAA" : "CAS",
		       op == AB_OP_FAA ? "a" : "b");
		printf("| 密度(计数/页) | pinned avg/p99 (µs) | odp avg/p99 (µs)"
		       " | sym avg/p99 (µs) | sym−pinned (µs) |\n");
		printf("|------|------|------|------|------|\n");
		for (i = 0; i < NDENS; i++) {
			struct stats sp1 = {0}, so = {0}, ss = {0};
			int r;

			r = bench_latency(ctl_qp, ctl_cq, data_qp, data_cq,
					  send_mr, recv_mr, res_mr, &sp,
					  CFG_PIN, op, dens[i], &sp1);
			if (!r && !odp_skip)
				r = bench_latency(ctl_qp, ctl_cq, data_qp,
						  data_cq, send_mr, recv_mr,
						  res_mr, &sp, CFG_ODP, op,
						  dens[i], &so);
			if (!r)
				r = bench_latency(ctl_qp, ctl_cq, data_qp,
						  data_cq, send_mr, recv_mr,
						  res_mr, &sp, CFG_SYM, op,
						  dens[i], &ss);
			if (r)
				goto out;
			printf("| %d | %.2f / %.2f | %s%.2f / %.2f%s | "
			       "%.2f / %.2f | %.2f |\n",
			       dens[i], sp1.avg, sp1.p99,
			       odp_skip ? "(" : "", so.avg, so.p99,
			       odp_skip ? ")" : "",
			       ss.avg, ss.p99, ss.avg - sp1.avg);
			fflush(stdout);
		}

		/* ---- 吞吐 vs 流水深度 (Fig 14c/d) ---- */
		printf("\n=== [thr] %s — 流水深度扫描 (Fig 14%s) ===\n",
		       op == AB_OP_FAA ? "FAA" : "CAS",
		       op == AB_OP_FAA ? "c" : "d");
		printf("| 深度 | pinned (Mops/s) | odp (Mops/s) | sym (Mops/s) |\n");
		printf("|------|------|------|------|\n");
		for (i = 0; i < NDEPTH; i++) {
			struct stats sp1 = {0}, so = {0}, ss = {0};
			int r;

			r = bench_throughput(ctl_qp, ctl_cq, data_qp,
					     data_cq, send_mr, recv_mr,
					     res_mr, &sp, CFG_PIN, op,
					     depths[i], &sp1);
			if (!r && !odp_skip)
				r = bench_throughput(ctl_qp, ctl_cq, data_qp,
						     data_cq, send_mr,
						     recv_mr, res_mr, &sp,
						     CFG_ODP, op, depths[i],
						     &so);
			if (!r)
				r = bench_throughput(ctl_qp, ctl_cq, data_qp,
						     data_cq, send_mr, recv_mr,
						     res_mr, &sp, CFG_SYM, op,
						     depths[i], &ss);
			if (r)
				goto out;
			printf("| %d | %.3f | %s%.3f%s | %.3f |\n",
			       depths[i], sp1.avg, odp_skip ? "(" : "",
			       so.avg, odp_skip ? ")" : "", ss.avg);
			fflush(stdout);
		}
	}

	printf("\n========================================\n");
	printf("atomicbench: FAIL=%d anomalies=%ld\n", g_fail, g_anomalies);
	printf("========================================\n");
	rc = g_fail ? 1 : (odp_skip ? 2 : 0);

out:
	/* QUIT (尽力) */
	{
		struct ab_msg req = {0}, resp = {0};

		req.magic = AB_MAGIC;
		req.op = AB_OP_QUIT;
		if (rpc_roundtrip(ctl_qp, ctl_cq, send_mr, recv_mr, 0,
				  &req, &resp))
			printf("(QUIT 无响应 — server 可能已退出)\n");
	}
	ibv_dereg_mr(res_mr);
	ibv_dereg_mr(send_mr);
	ibv_dereg_mr(recv_mr);
	ibv_destroy_qp(ctl_qp);
	ibv_destroy_qp(data_qp);
	ibv_destroy_cq(ctl_cq);
	ibv_destroy_cq(data_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(send_pool, (size_t)NSLOT * MSG_SZ);
	munmap(recv_pool, (size_t)NSLOT * MSG_SZ);
	munmap(res_buf, (size_t)NSLOT * 8);
	close(conn_fd);
	printf("DONE fail=%d\n", g_fail);
	return rc;
}

int main(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		fprintf(stderr,
			"用法: %s server [-p port] [-g gid] | "
			"client -c IP [-p port] [-g gid] [--no-odp]\n",
			argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "server")) {
		int port = 18716;
		const char *devname = NULL;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "-p") && i + 1 < argc)
				port = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-g") && i + 1 < argc)
				g_gid = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-d") && i + 1 < argc)
				devname = argv[++i];
		}
		return run_server(port, devname);
	}
	if (!strcmp(argv[1], "client")) {
		const char *ip = NULL;
		int port = 18716;
		const char *devname = NULL;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "-c") && i + 1 < argc)
				ip = argv[++i];
			else if (!strcmp(argv[i], "-p") && i + 1 < argc)
				port = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-g") && i + 1 < argc)
				g_gid = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-d") && i + 1 < argc)
				devname = argv[++i];
			else if (!strcmp(argv[i], "--no-odp"))
				g_odp_ok = 0;
		}
		if (!ip) {
			fprintf(stderr, "client 需要 -c IP\n");
			return 1;
		}
		return run_client(ip, port, devname);
	}
	fprintf(stderr, "未知模式 %s\n", argv[1]);
	return 1;
}
