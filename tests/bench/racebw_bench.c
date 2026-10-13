/*
 * racebw_bench.c — Host-Remote Race 吞吐基准 (论文 §5.2.1 Fig 12,)
 *
 * 复现论文 Fig 12 (race 场景吞吐曲线): 消息尺寸 2B..4MB × 四条曲线
 *   sym minor/major  — SymRDMA 远端乐观路径 (libsymrdma: ≤4KB 哨兵检测 /
 *                      >4KB remote seqlock + run 合并区间修复) 打 server
 *                      的 SymRDMA MR (unpinned, IOMMU 哨兵/黑洞)
 *   odp minor/major  — 硬件 ODP (ON_DEMAND MR, 裸 verbs)
 *
 * 故障态口径 (每 batch 重置, PREP 在测量窗外执行):
 *   minor — span 页 MADV_DONTNEED (匿名页销毁, 次访问零页分配 = minor);
 *           sym 区不触摸注册 (全哨兵) → DONTNEED 触发 notifier 哨兵化
 *   major — memset 弄脏 + MADV_PAGEOUT + smaps Swap 就位确认 (≥90%)
 *           (弄脏保证真实换出; 干净页 PAGEOUT 仅弃 swap-cache 退化为 minor)
 *
 * 测量: 每 batch = 一次 span 扫过 (共享页游标按 op 页粒度步进 — 小消息
 * 也保证每 op 缺一页, 论文 per-message fault 口径); batch 间 PREP。
 * 累计 timed ≥ TARGET_TIME 且 batch ≥ 2 (或 ≥ HARD_TIME) 停。
 * 吞吐 = Σbytes / Σtimed。线程数 -t (默认 1 = 论文同步单发口径)。
 *
 * sanity (计时前, FAIL 门禁): 每配置 minor 写读回 + major 读 (0xA5) 写
 * 读回; sym 侧以 /proc/symrdma REPAIR 计数差断言修复路径真实触发
 * (兼验证 DONTNEED→notifier→哨兵化→修复 链路)。
 *
 * 会合: 自管 TCP (参数交换 + 控制通道, run_atomic_bench 同款) + 库级
 * SIR TCP (SYMRDMA_SIR_TCP, 修复通道; L12/L13 同源, 端口 = 数据 + 1)。
 * 输出: "RESULT <row> <value> <unit>" (脚本解析) + markdown 表。
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
#include <pthread.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <infiniband/verbs.h>

#include "libsymrdma.h"
#include "sir.h"

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef MADV_NOHUGEPAGE
#define MADV_NOHUGEPAGE 15
#endif
#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif
#ifndef IBV_ACCESS_ON_DEMAND
#define IBV_ACCESS_ON_DEMAND (1 << 6)
#endif

/* ---- 布局常量 ---- */
#define PAGE_SZ      4096
#define SPAN_BYTES   (16 * 1024 * 1024)                  /* 16MB/span */
#define SPAN_PAGES   (SPAN_BYTES / PAGE_SZ)              /* 4096 页 */
#define REGION_SZ    (2 * SPAN_BYTES)                    /* minor+major */
#define LOCAL_SZ     (4 * 1024 * 1024)                   /* 本地 buf = 最大消息 */
#define MAX_MSG      LOCAL_SZ
#define NSIZE        8
#define NTHREAD_MAX  8
#define PATTERN_A    0xA5                                 /* major PREP 弄脏值 */
#define PATTERN_B    0x5A                                 /* sanity 写入值 */

/* 测量节奏 */
#define TARGET_TIME_S 1.5    /* 单点 timed 目标 (且 batch ≥ MIN_BATCHES) */
#define HARD_TIME_S   6.0    /* 单点 timed 硬顶 — ODP 小消息单 batch ≈8.6s
			      * (4096 op × 2ms 超时) 已超目标, 第二 batch 纯
			      * 冗余 (10→6s 砍掉, 单点时长减半) */
#define MIN_BATCHES   2
#define MAX_BATCHES   1024
#define MIN_OPS       32     /* 单点最少操作数 (大尺寸稳定性) */
#define OP_TIMEOUT_US 60000000ULL  /* 单 op 看门狗 60s (ODP 大消息可极慢) */
#define SWAP_DEADLINE_S 5    /* major 换出就位确认窗口 */
#define SWAP_CONFIRM_PCT 90

static const size_t sizes[NSIZE] = {
	2, 16, 128, 1024, 8192, 65536, 524288, 4194304
};
static const char *size_lab[NSIZE] = {
	"2", "16", "128", "1K", "8K", "64K", "512K", "4M"
};

static const char *cfg_name[]   = { "sym", "odp" };
static const char *fault_name[] = { "minor", "major" };
#define CFG_SYM 0
#define CFG_ODP 1

static const char *g_size_filter;   /* -z "2,8K,4M" (调试定点, L15 教训) */

#define OP_TRIES 8            /* 单 op 瞬态重试 (EAGAIN 风暴容忍) */
#define OP_RETRY_US 2000      /* 重试退避 2ms */

static int size_enabled(int si)
{
	const char *s = g_size_filter;
	const char *p;
	size_t l;

	if (!s)
		return 1;
	while (*s) {
		p = strchr(s, ',');
		l = p ? (size_t)(p - s) : strlen(s);
		if (l && strlen(size_lab[si]) == l &&
		    !strncmp(size_lab[si], s, l))
			return 1;
		s = p ? p + 1 : s + strlen(s);
	}
	return 0;
}

static int    g_gid = 5;          /* 测试床规程: GID index 5 */
static int    g_threads = 1;
static int    g_fail;
static struct symrdma_ctx *g_sctx;   /* client 库上下文 (do_op 用) */
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

/* ---- /proc/symrdma 计数器 (ctlbench 同款解析) ---- */
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

/* /proc/self/smaps: addr 所在 VMA 的 Swap: 字节合计。
 * mincore 对 swapcache 页恒报 resident — 不可作就位判据 (教训) */
static long smaps_swap_bytes(const void *addr)
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
	return kb * 1024;
}

/* ---- 设备 / QP 辅助 (atomicbench 同款) ---- */
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

static struct ibv_qp *make_qp(struct ibv_pd *pd, struct ibv_cq *cq)
{
	struct ibv_qp_init_attr a = {0};

	a.send_cq = cq;
	a.recv_cq = cq;
	a.qp_type = IBV_QPT_RC;
	a.cap.max_send_wr  = 16;
	a.cap.max_recv_wr  = 16;
	a.cap.max_send_sge = 1;
	a.cap.max_recv_sge = 1;
	return ibv_create_qp(pd, &a);
}

/* INIT→RTR→RTS; mtu=min(active_mtu,4096) (教训); one-sided 16/16 */
static int qp_to_rts(struct ibv_qp *qp, uint32_t dest_qpn)
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
	attr.max_dest_rd_atomic = 16;
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
	attr.max_rd_atomic = 16;
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

/* ---- TCP 会合 + 控制通道 (自管; atomicbench 同款) ---- */
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
	struct timeval tv = { .tv_sec = 60, .tv_usec = 0 };

	/* 60s 收发超时 — server 卡死时 client 不至永久阻塞 */
	setsockopt(fd, SOL_SOCKET, wr ? SO_SNDTIMEO : SO_RCVTIMEO,
		   &tv, sizeof(tv));
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

/* 参数交换: 固定 1KB 文本块 (行式; 空 gid 用 "-")。
 * server 发 sym/odp 描述 + sqpn 列表; client 发 gid + cqpn 列表。 */
struct peer_params {
	uint32_t sqpn[NTHREAD_MAX];
	uint32_t cqpn[NTHREAD_MAX];
	int      nsqpn, ncqpn;
	uint32_t sym_rkey, sym_wkey, sym_vrkey;
	uint64_t sym_addr, sym_vaddr;
	uint32_t sym_len;
	uint32_t odp_rkey;
	uint64_t odp_addr;
	uint32_t odp_len;
	int      odp_ok;
	char     gid[40];
};

static int pp_pack(char *buf, size_t cap, const struct peer_params *p,
		   int is_server)
{
	int n = 0, i;

	if (is_server) {
		n += snprintf(buf + n, cap - n,
			      "sym_rkey %u\nsym_wkey %u\nsym_vrkey %u\n"
			      "sym_addr %llu\nsym_vaddr %llu\nsym_len %u\n"
			      "odp_rkey %u\nodp_addr %llu\nodp_len %u\n"
			      "odp_ok %d\ngid %s\nsqpn",
			      p->sym_rkey, p->sym_wkey, p->sym_vrkey,
			      (unsigned long long)p->sym_addr,
			      (unsigned long long)p->sym_vaddr, p->sym_len,
			      p->odp_rkey, (unsigned long long)p->odp_addr,
			      p->odp_len, p->odp_ok,
			      p->gid[0] ? p->gid : "-");
		for (i = 0; i < p->nsqpn; i++)
			n += snprintf(buf + n, cap - n, " %u", p->sqpn[i]);
		n += snprintf(buf + n, cap - n, "\n");
	} else {
		n += snprintf(buf + n, cap - n, "gid %s\ncqpn",
			      p->gid[0] ? p->gid : "-");
		for (i = 0; i < p->ncqpn; i++)
			n += snprintf(buf + n, cap - n, " %u", p->cqpn[i]);
		n += snprintf(buf + n, cap - n, "\n");
	}
	memset(buf + n, 0, cap - n);
	return 0;
}

/* 把 "key v1 v2..." 形式的列表行解析进数组 */
static int pp_parse_list(const char *line, uint32_t *arr, int cap)
{
	char tmp[128];
	char *tok;
	int n = 0;

	snprintf(tmp, sizeof(tmp), "%s", line);
	tok = strtok(tmp, " ");          /* 跳过 key */
	while ((tok = strtok(NULL, " ")) && n < cap)
		arr[n++] = (uint32_t)strtoul(tok, NULL, 10);
	return n;
}

static int pp_apply(struct peer_params *p, const char *buf)
{
	char line[256];
	const char *s = buf;

	memset(p, 0, sizeof(*p));
	while (*s && s < buf + 1024) {
		const char *nl = strchr(s, '\n');
		size_t l = nl ? (size_t)(nl - s) : strlen(s);
		int nl_missing = (nl == NULL);

		if (l >= sizeof(line))
			l = sizeof(line) - 1;
		memcpy(line, s, l);
		line[l] = 0;
		s = nl ? nl + 1 : s + l;
		if (nl_missing && !l)
			break;
		if (!strncmp(line, "sym_rkey ", 9))
			p->sym_rkey = (uint32_t)strtoul(line + 9, NULL, 10);
		else if (!strncmp(line, "sym_wkey ", 9))
			p->sym_wkey = (uint32_t)strtoul(line + 9, NULL, 10);
		else if (!strncmp(line, "sym_vrkey ", 10))
			p->sym_vrkey = (uint32_t)strtoul(line + 10, NULL, 10);
		else if (!strncmp(line, "sym_addr ", 9))
			p->sym_addr = strtoull(line + 9, NULL, 10);
		else if (!strncmp(line, "sym_vaddr ", 10))
			p->sym_vaddr = strtoull(line + 10, NULL, 10);
		else if (!strncmp(line, "sym_len ", 8))
			p->sym_len = (uint32_t)strtoul(line + 8, NULL, 10);
		else if (!strncmp(line, "odp_rkey ", 9))
			p->odp_rkey = (uint32_t)strtoul(line + 9, NULL, 10);
		else if (!strncmp(line, "odp_addr ", 9))
			p->odp_addr = strtoull(line + 9, NULL, 10);
		else if (!strncmp(line, "odp_len ", 8))
			p->odp_len = (uint32_t)strtoul(line + 8, NULL, 10);
		else if (!strncmp(line, "odp_ok ", 7))
			p->odp_ok = atoi(line + 7);
		else if (!strncmp(line, "gid ", 4) && line[4] != '-') {
			if (gid_from_hex(line + 4, g_peer_gid))
				g_have_peer_gid = 1;
		} else if (!strncmp(line, "sqpn ", 5)) {
			p->nsqpn = pp_parse_list(line, p->sqpn, NTHREAD_MAX);
		} else if (!strncmp(line, "cqpn ", 5)) {
			p->ncqpn = pp_parse_list(line, p->cqpn, NTHREAD_MAX);
		}
	}
	return 0;
}

/* 控制 TCP: 定长帧 (128B) — 请求/响应两侧同长, 避免变长 recv 阻塞;
 * 行协议语义保留 (服务端按 '\n' 截断) */
static int ctrl_roundtrip(int fd, const char *req, char *resp)
{
	char out[128];
	size_t n;

	n = strlen(req);
	if (n >= sizeof(out))
		return -1;
	memset(out, 0, sizeof(out));
	memcpy(out, req, n);
	out[n] = '\n';
	if (xfer_all(fd, out, sizeof(out), 1))
		return -1;
	if (xfer_all(fd, resp, 128, 0))
		return -1;
	resp[127] = 0;
	return 0;
}

/* server 侧 /proc/symrdma REPAIR 计数 (经 STAT 命令; 修复 ioctl 发生在
 * owner = server, client 本机计数与本基准无关) */
static int server_repair_stats(int fd, long long *ok, long long *fail)
{
	char resp[128];

	if (ctrl_roundtrip(fd, "STAT", resp))
		return -1;
	return sscanf(resp, "OK %lld %lld", ok, fail) == 2 ? 0 : -1;
}

/* ================= server ================= */

/* PREP: 重置 cfg 区指定 span 的故障态 (测量窗外执行)。
 * 返回: minor → -1; major → 就位换出页数 (≥0) */
static long server_prep(unsigned char *region, int minor)
{
	unsigned char *span = region + (minor ? 0 : SPAN_BYTES);

	if (minor) {
		madvise(span, SPAN_BYTES, MADV_DONTNEED);
		return -1;
	}
	/* major: 弄脏 (干净页 PAGEOUT 仅弃 swap-cache → 次访问 minor)
	 * + PAGEOUT + smaps 就位确认 (重试至 ≥90% 或超时) */
	{
		/* 修复: 确认按 PREP 前后差值 (VMA 级 Swap 含其他
		 * span/历史换出贡献, 绝对值判据过宽 → 未换出也放行)。
		 * 基线必须取在 memset/PAGEOUT **之前** — 首版误取在首次
		 * PAGEOUT 之后, 换出已发生 → 差值恒 0 (就位误报)。 */
		double deadline = now_us() + SWAP_DEADLINE_S * 1e6;
		long want = (long)SPAN_BYTES;
		long base, sw = -1;
		double t0 = now_us();

		base = smaps_swap_bytes(region);
		if (base < 0)
			return -2;
		memset(span, PATTERN_A, SPAN_BYTES);
		madvise(span, SPAN_BYTES, MADV_PAGEOUT);
		fprintf(stderr, "[prep] major memset+PAGEOUT %.1f ms\n",
			(now_us() - t0) / 1000.0);
		for (;;) {
			sw = smaps_swap_bytes(region);
			if (sw < 0)
				return -2;
			if ((sw - base) * 100 >= want * SWAP_CONFIRM_PCT)
				break;
			if (now_us() > deadline)
				break;
			madvise(span, SPAN_BYTES, MADV_PAGEOUT);
			usleep(20000);
		}
		return (sw - base) / (long)PAGE_SZ;
	}
}

static int run_server(int port, const char *devname)
{
	struct peer_params mine = {0}, peer = {0};
	unsigned char *sym_buf, *odp_buf;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *cq;
	struct ibv_qp *qps[NTHREAD_MAX];
	struct ibv_mr *odp_mr = NULL;
	struct symrdma_ctx sctx;
	struct symrdma_mr smr;
	struct symrdma_mr_write wmr;
	struct sir_export exp;
	int listen_fd = -1, conn_fd = -1;
	char buf[1024], resp[128];
	int i, rc = 1;

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("=== racebw server (port=%d gid=%d threads=%d) ===\n",
	       port, g_gid, g_threads);

	/* SIR TCP 会合 env (库级修复通道; 端口 = 数据端口 + 1) */
	{
		char sp[32], sg[16];

		snprintf(sp, sizeof(sp), "listen:%d", port + 1);
		snprintf(sg, sizeof(sg), "%d", g_gid);
		setenv("SYMRDMA_PEER", "racebw", 1);
		setenv("SYMRDMA_SIR_TCP", sp, 1);
		setenv("SYMRDMA_SIR_GID", sg, 1);
	}

	if (symrdma_open(&sctx)) {
		printf("/dev/symrdma 打开失败\n");
		return 2;
	}

	dev = find_rdma_device(devname);
	if (!dev) { printf("无 mlx5 设备\n"); return 2; }
	ctx = ibv_open_device(dev);
	pd  = ibv_alloc_pd(ctx);
	cq  = ibv_create_cq(ctx, 64, NULL, NULL, 0);
	if (!ctx || !pd || !cq) { printf("verbs 资源创建失败\n"); return 1; }

	sym_buf = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	odp_buf = mmap(NULL, REGION_SZ, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE | MAP_NORESERVE, -1, 0);
	if (sym_buf == MAP_FAILED || odp_buf == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	madvise(sym_buf, REGION_SZ, MADV_NOHUGEPAGE);
	madvise(odp_buf, REGION_SZ, MADV_NOHUGEPAGE);
	/* 两区均不触摸注册: sym 全哨兵 (follow_page_nofault 无副作用),
	 * odp 全缺席 — minor 故障源; major 由 PREP 现场制造 */

	if (symrdma_mr_register(&sctx, pd, sym_buf, REGION_SZ, &smr)) {
		printf("symrdma_mr_register 失败\n");
		return 1;
	}
	if (!smr.version_mr) {
		printf("Version MR 绑定失败 — 远端 seqlock (>4KB) 路径不可用\n");
		return 1;
	}
	if (symrdma_write_mr_register(pd, sym_buf, REGION_SZ, &wmr)) {
		printf("symrdma_write_mr_register 失败\n");
		return 1;
	}

	for (i = 0; i < g_threads; i++) {
		qps[i] = make_qp(pd, cq);
		if (!qps[i]) {
			printf("server QP %d 创建失败\n", i);
			return 1;
		}
	}

	/* ODP MR (可写 ODP: LOCAL_WRITE + REMOTE_READ/WRITE + ON_DEMAND) */
	odp_mr = ibv_reg_mr(pd, odp_buf, REGION_SZ,
			    IBV_ACCESS_LOCAL_WRITE |
			    IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_REMOTE_WRITE |
			    IBV_ACCESS_ON_DEMAND);

	memset(&exp, 0, sizeof(exp));
	exp.data_rkey  = smr.ibv_mr->rkey;
	exp.write_rkey = wmr.ibv_mr->rkey;
	exp.addr  = (uint64_t)(uintptr_t)sym_buf;
	exp.len   = REGION_SZ;
	exp.mr_id = smr.mr_id;
	if (smr.version_mr) {
		exp.v_rkey = smr.version_mr->rkey;
		exp.v_addr = (uint64_t)(uintptr_t)smr.version_buf;
	}
	if (sir_init(ctx, pd, "racebw", sctx.fd)) {
		printf("sir_init 失败\n");
		return 1;
	}
	if (sir_export_add(&exp)) {
		printf("sir_export_add 失败\n");
		return 1;
	}

	listen_fd = tcp_listen(port);
	if (listen_fd < 0) { perror("listen"); return 1; }
	printf("ready: 等待 client (port %d, sir %d)\n", port, port + 1);
	fflush(stdout);

	conn_fd = accept(listen_fd, NULL, NULL);
	if (conn_fd < 0) { perror("accept"); return 1; }

	mine.sym_rkey  = smr.ibv_mr->rkey;
	mine.sym_wkey  = wmr.ibv_mr->rkey;
	mine.sym_vrkey = smr.version_mr ? smr.version_mr->rkey : 0;
	mine.sym_vaddr = smr.version_mr ?
		(uint64_t)(uintptr_t)smr.version_buf: 0;
	mine.sym_addr  = (uint64_t)(uintptr_t)sym_buf;
	mine.sym_len   = REGION_SZ;
	mine.odp_rkey  = odp_mr ? odp_mr->rkey : 0;
	mine.odp_addr  = (uint64_t)(uintptr_t)odp_buf;
	mine.odp_len   = REGION_SZ;
	mine.odp_ok    = odp_mr ? 1 : 0;
	mine.nsqpn     = g_threads;
	for (i = 0; i < g_threads; i++)
		mine.sqpn[i] = qps[i]->qp_num;
	{
		union ibv_gid g;

		if (!ibv_query_gid(ctx, 1, g_gid, &g))
			gid_to_hex(&g, mine.gid);
	}
	if (pp_pack(buf, sizeof(buf), &mine, 1) ||
	    xfer_all(conn_fd, buf, sizeof(buf), 1) ||
	    xfer_all(conn_fd, buf, sizeof(buf), 0) ||
	    pp_apply(&peer, buf)) {
		printf("参数交换失败\n");
		goto out;
	}
	printf("linked: client %d QP, odp_ok=%d\n", peer.ncqpn, mine.odp_ok);
	if (!mine.odp_ok)
		printf("!! ODP MR 不可用 — odp 配置不可测\n");

	/* 数据 QP 重走 RTR/RTS 指向对端 */
	for (i = 0; i < g_threads && i < peer.ncqpn; i++)
		if (qp_to_rts(qps[i], peer.cqpn[i])) {
			printf("server QP %d RTS 失败\n", i);
			goto out;
		}
	fflush(stdout);

	/* 控制循环: PREP <sym|odp> <minor|major> / STAT / QUIT */
	for (;;) {
		char cmd[128];
		char *nl;

		/* 定长帧读入 (客户端 ctrl_roundtrip 恒发 128B) */
		if (xfer_all(conn_fd, cmd, sizeof(cmd), 0))
			break;
		cmd[sizeof(cmd) - 1] = 0;
		nl = strchr(cmd, '\n');
		if (nl)
			*nl = 0;
		memset(resp, 0, sizeof(resp));   /* 定长帧发送, 尾部补零 */
		if (!strncmp(cmd, "PREP ", 5)) {
			char cfgs[16], kinds[16];
			long v;

			if (sscanf(cmd + 5, "%15s %15s", cfgs, kinds) != 2) {
				snprintf(resp, sizeof(resp), "ERR parse");
			} else {
				unsigned char *region =
					!strcmp(cfgs, "sym") ? sym_buf :
							       odp_buf;
				v = server_prep(region,
						!strcmp(kinds, "minor"));
				snprintf(resp, sizeof(resp), "OK %ld", v);
			}
		} else if (!strcmp(cmd, "STAT")) {
			snprintf(resp, sizeof(resp), "OK %lld %lld",
				 proc_counter("REPAIR 成功"),
				 proc_counter("REPAIR 失败"));
		} else if (!strcmp(cmd, "QUIT")) {
			snprintf(resp, sizeof(resp), "OK");
			xfer_all(conn_fd, resp, sizeof(resp), 1);
			break;
		} else {
			snprintf(resp, sizeof(resp), "ERR unknown");
		}
		if (xfer_all(conn_fd, resp, sizeof(resp), 1))
			break;
	}
	rc = 0;

out:
	printf("DONE fail=%d\n", g_fail);
	fflush(stdout);
	if (conn_fd >= 0)
		close(conn_fd);
	if (listen_fd >= 0)
		close(listen_fd);
	sir_fini();
	symrdma_write_mr_deregister(&wmr);
	symrdma_mr_deregister(&sctx, &smr);
	if (odp_mr)
		ibv_dereg_mr(odp_mr);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(sym_buf, REGION_SZ);
	munmap(odp_buf, REGION_SZ);
	symrdma_close(&sctx);
	return rc;
}

/* ================= client ================= */

/* 每线程执行上下文 (QP/CQ/本地缓冲/sym 远端视图 独立) */
struct thr_ctx {
	int              idx;
	struct ibv_qp   *qp;
	struct ibv_cq   *cq;
	unsigned char   *local;        /* LOCAL_SZ, mlock */
	uint32_t         lkey;
	struct symrdma_mr lmr;         /* 本地 SymRDMA MR (DMA 目标/源) */
	struct symrdma_mr rmr;         /* 远端 sym 视图 (per-thread scratch) */
	int              rc;
};

/* 原子页游标 (batch 内共享; 页粒度步进) */
static unsigned long g_cursor;
/* 当前 batch 参数 */
static unsigned long g_bpp;      /* bytes per op */
static unsigned long g_ppo;      /* pages per op */
static int           g_bcfg;     /* CFG_SYM / CFG_ODP */
static int           g_bop;      /* 0=read 1=write */
static int           g_bfault;   /* 0=minor 1=major (span 基址选择) */
static uint64_t      g_odp_base;
static uint32_t      g_odp_rkey;

/* 单 op (线程内串行); buf = 读目标 / 写源 (须属 tc->lmr 注册区);
 * 返回 0 成功 */
static int do_op(struct thr_ctx *tc, unsigned long page_idx, size_t len,
		 void *buf)
{
	if (g_bcfg == CFG_SYM) {
		int r;

		if (g_bop == 0)
			r = symrdma_read_p(g_sctx, tc->qp, tc->cq,
					   &tc->rmr, page_idx, len,
					   buf, tc->lkey, &tc->lmr);
		else
			r = symrdma_write_p(g_sctx, tc->qp, tc->cq,
					    &tc->rmr, NULL, page_idx, len,
					    buf, tc->lkey, &tc->lmr);
		return r;
	} else {
		struct ibv_sge sge = {
			.addr   = (uintptr_t)buf,
			.length = (uint32_t)len,
			.lkey   = tc->lkey,
		};
		struct ibv_send_wr wr = {0}, *bad = NULL;
		struct ibv_wc wc;
		double deadline = now_us() + OP_TIMEOUT_US;
		int n;

		wr.opcode = g_bop ? IBV_WR_RDMA_WRITE : IBV_WR_RDMA_READ;
		wr.sg_list = &sge;
		wr.num_sge = 1;
		wr.wr.rdma.remote_addr = g_odp_base +
			(uint64_t)page_idx * PAGE_SZ;
		wr.wr.rdma.rkey = g_odp_rkey;
		wr.send_flags = IBV_SEND_SIGNALED;
		if (ibv_post_send(tc->qp, &wr, &bad))
			return -1;
		do {
			n = ibv_poll_cq(tc->cq, 1, &wc);
			if (n == 0 && now_us() > deadline)
				return -2;           /* 超时 */
		} while (n == 0);
		if (n < 0 || wc.status != IBV_WC_SUCCESS)
			return -1;
		return 0;
	}
}

/* 线程主体: 消费共享游标直至 span 耗尽; 返回完成 ops 数。
 * 测量路径读/写共用 tc->local (内容与时序无关)。
 * 瞬态容错: 单 op 失败 (r=-1, 如修复 EAGAIN / 对端表刷新窗口)
 * 重试至 3 次 (1ms 退避) — 乐观模型检测→修复→重试语义; 超时 (r=-2)
 * 恒致命。 */
static unsigned long thr_run(struct thr_ctx *tc)
{
	unsigned long done = 0;

	tc->rc = 0;
	for (;;) {
		unsigned long cur = __atomic_fetch_add(&g_cursor, g_ppo,
						       __ATOMIC_RELAXED);
		unsigned long page;
		int r = 0, tries;

		if (cur + g_ppo > SPAN_PAGES)
			break;                    /* span 耗尽 */
		/* 修复: major 点必须在 major span (基址 SPAN_PAGES)
		 * 上操作 — 首版漏加基址, major 点实际测的是驻留 minor span
		 * (数据无效, 线速假象)。 */
		page = (g_bfault ? SPAN_PAGES : 0) + cur;
		for (tries = 0; tries < OP_TRIES; tries++) {
			if (tries) {
				fprintf(stderr,
					"  [thr%d] op 重试 %d/%d page=%lu "
					"errno=%d (%s)\n",
					tc->idx, tries, OP_TRIES, page,
					errno, strerror(errno));
				usleep(OP_RETRY_US);
			}
			r = do_op(tc, page, (size_t)g_bpp, tc->local);
			if (r == 0 || r == -2)
				break;
		}
		if (r) {
			fprintf(stderr,
				"  [thr%d] op 失败 r=%d page=%lu len=%lu "
				"errno=%d (%s)\n",
				tc->idx, r, page, g_bpp, errno,
				strerror(errno));
			tc->rc = r;
			break;
		}
		done++;
	}
	return done;
}

struct thr_arg {
	struct thr_ctx *tc;
	unsigned long   done;
};

static void *thr_trampoline(void *arg)
{
	struct thr_arg *ta = arg;

	ta->done = thr_run(ta->tc);
	return NULL;
}

/* 单次写读回 sanity helper (读目标 = local+PAGE_SZ, 不覆写写源) */
static int sanity_wr(struct thr_ctx *t, unsigned long page, const char *tag)
{
	unsigned char pat[PAGE_SZ], *rd = t->local + PAGE_SZ;
	int r;

	memset(t->local, PATTERN_B, PAGE_SZ);        /* 写源 = 注册区 */
	r = symrdma_write_p(g_sctx, t->qp, t->cq, &t->rmr, NULL, page,
			    PAGE_SZ, t->local, t->lkey, &t->lmr);
	if (r) {
		printf("FAIL sanity: %s write 失败 r=%d\n", tag, r);
		g_fail = 1;
		return -1;
	}
	memset(rd, 0, PAGE_SZ);
	r = symrdma_read_p(g_sctx, t->qp, t->cq, &t->rmr, page,
			   PAGE_SZ, rd, t->lkey, &t->lmr);
	if (r) {
		printf("FAIL sanity: %s read 失败 r=%d\n", tag, r);
		g_fail = 1;
		return -1;
	}
	memset(pat, PATTERN_B, sizeof(pat));
	if (memcmp(rd, pat, PAGE_SZ)) {
		printf("FAIL sanity: %s 写读回不匹配\n", tag);
		g_fail = 1;
		return -1;
	}
	return 0;
}

/* 单次读 sanity helper (期望全 exp 字节) */
static int sanity_rd(struct thr_ctx *t, unsigned long page,
		     unsigned char expb, const char *tag)
{
	unsigned char *rd = t->local + PAGE_SZ;
	int r;

	memset(rd, 0, PAGE_SZ);
	r = symrdma_read_p(g_sctx, t->qp, t->cq, &t->rmr, page,
			   PAGE_SZ, rd, t->lkey, &t->lmr);
	if (r) {
		printf("FAIL sanity: %s read 失败 r=%d\n", tag, r);
		g_fail = 1;
		return -1;
	}
	{
		unsigned char exp2[PAGE_SZ];

		memset(exp2, expb, sizeof(exp2));
		if (memcmp(rd, exp2, PAGE_SZ)) {
			printf("FAIL sanity: %s 读非 0x%02x\n", tag, expb);
			g_fail = 1;
			return -1;
		}
	}
	return 0;
}

static int run_client(const char *ip, int port, const char *devname)
{
	struct peer_params mine = {0}, sp = {0};
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *cq[NTHREAD_MAX];
	struct ibv_qp *qp[NTHREAD_MAX];
	struct thr_ctx tc[NTHREAD_MAX];
	struct symrdma_ctx sctx;
	unsigned char *local_pool;
	int conn_fd, cfg, op, fl, si, i, rc = 1;
	int odp_skip = 0;
	char buf[1024], resp[128];
	long long repair_ok0 = -1, repair_fail0 = -1;

	setvbuf(stdout, NULL, _IOLBF, 0);
	printf("=== racebw client → %s:%d (gid=%d threads=%d) ===\n",
	       ip, port, g_gid, g_threads);

	/* SIR TCP 会合 env (修复通道) */
	{
		char sp2[32], sg[16];

		snprintf(sp2, sizeof(sp2), "%s:%d", ip, port + 1);
		snprintf(sg, sizeof(sg), "%d", g_gid);
		setenv("SYMRDMA_PEER", "racebw", 1);
		setenv("SYMRDMA_SIR_TCP", sp2, 1);
		setenv("SYMRDMA_SIR_GID", sg, 1);
	}

	conn_fd = tcp_connect(ip, port);
	if (conn_fd < 0) { perror("connect"); return 1; }

	if (symrdma_open(&sctx)) {
		printf("/dev/symrdma 打开失败\n");
		return 2;
	}
	dev = find_rdma_device(devname);
	if (!dev) { printf("无 mlx5 设备\n"); return 2; }
	ctx = ibv_open_device(dev);
	pd  = ibv_alloc_pd(ctx);
	if (!ctx || !pd) { printf("verbs 资源创建失败\n"); return 1; }

	/* 本地缓冲池: 每线程 LOCAL_SZ (mlock 防换出 — DMA 目标稳定性) */
	local_pool = mmap(NULL, (size_t)g_threads * LOCAL_SZ,
			  PROT_READ | PROT_WRITE,
			  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (local_pool == MAP_FAILED) { perror("mmap"); return 1; }
	memset(local_pool, PATTERN_B, (size_t)g_threads * LOCAL_SZ);
	mlock(local_pool, (size_t)g_threads * LOCAL_SZ);

	for (i = 0; i < g_threads; i++) {
		struct thr_ctx *t = &tc[i];
		double t0 = now_us();

		memset(t, 0, sizeof(*t));
		t->idx = i;
		cq[i] = ibv_create_cq(ctx, 64, NULL, NULL, 0);
		qp[i] = cq[i] ? make_qp(pd, cq[i]) : NULL;
		if (!cq[i] || !qp[i]) {
			printf("client QP/CQ %d 创建失败\n", i);
			return 1;
		}
		t->cq = cq[i];
		t->qp = qp[i];
		t->local = local_pool + (size_t)i * LOCAL_SZ;
		/* 本地缓冲注册为 SymRDMA MR (DMA 读/写目标均需 IOMMU 映射;
		 * lkey 同时供 odp 裸 verbs 用) */
		if (symrdma_mr_register(&sctx, pd, t->local, LOCAL_SZ,
					&t->lmr)) {
			printf("client 本地 MR %d 注册失败\n", i);
			return 1;
		}
		t->lkey = t->lmr.ibv_mr->lkey;
		printf("  [thr%d] 本地 MR 就绪 (%.1f ms)\n", i,
		       (now_us() - t0) / 1000.0);
	}
	{
		union ibv_gid g;

		if (!ibv_query_gid(ctx, 1, g_gid, &g))
			gid_to_hex(&g, mine.gid);
	}

	/* 交换参数: client 先收 server (sym 描述) → import → 发 cqpn */
	if (xfer_all(conn_fd, buf, sizeof(buf), 0) || pp_apply(&sp, buf)) {
		printf("收 server 参数失败\n");
		return 1;
	}
	if (!sp.sym_rkey || !sp.sym_len) {
		printf("server sym 参数缺失\n");
		return 1;
	}
	if (!sp.odp_ok) {
		printf("!! server ODP MR 不可用 — odp 配置跳过 (rc=2)\n");
		odp_skip = 1;
	}
	for (i = 0; i < g_threads; i++) {
		if (symrdma_mr_import_remote(&sctx, pd, &tc[i].rmr,
					     sp.sym_rkey, sp.sym_wkey,
					     sp.sym_addr, sp.sym_len,
					     sp.sym_vrkey, sp.sym_vaddr)) {
			printf("client import %d 失败\n", i);
			return 1;
		}
	}
	mine.ncqpn = g_threads;
	for (i = 0; i < g_threads; i++)
		mine.cqpn[i] = qp[i]->qp_num;
	if (pp_pack(buf, sizeof(buf), &mine, 0) ||
	    xfer_all(conn_fd, buf, sizeof(buf), 1)) {
		printf("发 client 参数失败\n");
		return 1;
	}
	for (i = 0; i < g_threads && i < sp.nsqpn; i++)
		if (qp_to_rts(qp[i], sp.sqpn[i])) {
			printf("client QP %d RTS 失败\n", i);
			return 1;
		}
	printf("linked: server sym=0x%llx/%u odp_ok=%d\n",
	       (unsigned long long)sp.sym_addr, sp.sym_len, sp.odp_ok);
	printf("  地址核查: local=%p scratch=%p (不得与 sym 重叠)\n",
	       tc[0].local, (void *)(uintptr_t)tc[0].rmr.scratch ?
	       tc[0].rmr.scratch->buf: NULL);
	fflush(stdout);

	g_sctx = &sctx;
	g_odp_base = sp.odp_addr;
	g_odp_rkey = sp.odp_rkey;

	/* ---- sanity (FAIL 门禁; 计时外) ---- */
	printf("\n=== sanity (写读回 / 修复链路断言) ===\n");
	{
		unsigned long page;
		struct thr_ctx *t = &tc[0];
		int r = 0;

		/* sym minor: PREP → REPAIR 计数 c0 → 写读回 → c1 (delta > 0) */
		if (ctrl_roundtrip(conn_fd, "PREP sym minor", resp)) {
			fail("sanity: PREP sym minor 通信失败");
			goto points;
		}
		if (server_repair_stats(conn_fd, &repair_ok0,
					&repair_fail0)) {
			fail("sanity: STAT 通信失败");
			goto points;
		}
		page = SPAN_PAGES - 1;
		r = sanity_wr(t, page, "sym minor");
		if (!r) {
			long long c1 = -1, f1 = -1;

			if (server_repair_stats(conn_fd, &c1, &f1)) {
				fail("sanity: STAT 通信失败");
				goto points;
			}

			printf("  sym minor: 写读回 OK (REPAIR %lld→%lld"
			       " 失败 %lld→%lld)\n",
			       repair_ok0, c1, repair_fail0, f1);
			if (repair_ok0 >= 0 && c1 >= 0 && c1 == repair_ok0) {
				fail("sanity: sym minor REPAIR 计数未增 "
				     "(DONTNEED→notifier 链路未触发?)");
				goto points;
			}
		} else {
			goto points;
		}

		/* sym major: PREP → 读 0xA5 (换出就位 → 修复路径) → 写读回 */
		if (ctrl_roundtrip(conn_fd, "PREP sym major", resp)) {
			fail("sanity: PREP sym major 通信失败");
			goto points;
		}
		printf("  sym major: %s\n", resp);
		page = SPAN_PAGES + 1;
		if (sanity_rd(t, page, PATTERN_A, "sym major") ||
		    sanity_wr(t, page, "sym major"))
			goto points;
		printf("  sym major: 读 0xA5 + 写读回 OK\n");

		if (odp_skip)
			goto points;

		/* odp minor/major: PREP → 写读回 / 读 0xA5 + 写读回 */
		if (ctrl_roundtrip(conn_fd, "PREP odp minor", resp)) {
			fail("sanity: PREP odp minor 通信失败");
			goto points;
		}
		g_bcfg = CFG_ODP;
		page = SPAN_PAGES - 1;
		memset(t->local, PATTERN_B, PAGE_SZ);
		g_bop = 1;
		if (do_op(t, page, PAGE_SZ, t->local)) {
			fail("sanity: odp minor write 失败");
			goto points;
		}
		memset(t->local + PAGE_SZ, 0, PAGE_SZ);
		g_bop = 0;
		if (do_op(t, page, PAGE_SZ, t->local + PAGE_SZ) ||
		    memcmp(t->local + PAGE_SZ, t->local, PAGE_SZ)) {
			fail("sanity: odp minor 写读回不匹配");
			goto points;
		}
		printf("  odp minor: 写读回 OK\n");

		if (ctrl_roundtrip(conn_fd, "PREP odp major", resp)) {
			fail("sanity: PREP odp major 通信失败");
			goto points;
		}
		printf("  odp major: %s\n", resp);
		page = SPAN_PAGES + 1;
		memset(t->local + PAGE_SZ, 0, PAGE_SZ);
		g_bop = 0;
		if (do_op(t, page, PAGE_SZ, t->local + PAGE_SZ)) {
			fail("sanity: odp major read 失败");
			goto points;
		}
		{
			unsigned char exp2[PAGE_SZ];

			memset(exp2, PATTERN_A, sizeof(exp2));
			if (memcmp(t->local + PAGE_SZ, exp2, PAGE_SZ)) {
				fail("sanity: odp major 读非 0xA5");
				goto points;
			}
		}
		memset(t->local, PATTERN_B, PAGE_SZ);
		g_bop = 1;
		if (do_op(t, page, PAGE_SZ, t->local)) {
			fail("sanity: odp major write 失败");
			goto points;
		}
		memset(t->local + PAGE_SZ, 0, PAGE_SZ);
		g_bop = 0;
		if (do_op(t, page, PAGE_SZ, t->local + PAGE_SZ) ||
		    memcmp(t->local + PAGE_SZ, t->local, PAGE_SZ)) {
			fail("sanity: odp major 写读回不匹配");
			goto points;
		}
		printf("  odp major: 读 0xA5 + 写读回 OK\n");
	}

points:
	/* ---- 测量点阵: cfg × fault × op × size ---- */
	for (cfg = 0; cfg < 2 && !g_fail; cfg++) {
		if (cfg == CFG_ODP && odp_skip)
			continue;
		for (fl = 0; fl < 2 && !g_fail; fl++) {
			for (op = 0; op < 2 && !g_fail; op++) {
				int any = 0, k;

				for (k = 0; k < NSIZE; k++)
					if (size_enabled(k))
						any = 1;
				if (!any)
					continue;
				g_bfault = fl;
				printf("\n=== [%s %s %s] (Fig 12%s) ===\n",
				       cfg_name[cfg], fault_name[fl],
				       op ? "write" : "read",
				       op ? "b" : "a");
				printf("| 尺寸 | 吞吐 (MB/s) | ops | timed (s) |\n"
				       "|------|------|------|------|\n");
				for (si = 0; si < NSIZE && !g_fail; si++) {
					double timed = 0, mbs;

					if (!size_enabled(si))
						continue;
					unsigned long ops = 0, bytes = 0;
					int batch = 0, r = 0;
					char row[64], line[128];

					g_bcfg = cfg;
					g_bop = op;
					g_bpp = sizes[si];
					g_ppo = (sizes[si] + PAGE_SZ - 1) /
						PAGE_SZ;
					if (g_ppo > SPAN_PAGES)
						g_ppo = SPAN_PAGES;

					while (!r) {
						double t0, t1;
						unsigned long done = 0;

						/* PREP (测量外): 重置故障态 */
						snprintf(line, sizeof(line),
							 "PREP %s %s",
							 cfg_name[cfg],
							 fault_name[fl]);
						if (ctrl_roundtrip(conn_fd,
								   line,
								   resp)) {
							fail("PREP 通信失败");
							r = -1;
							break;
						}
						if (!strncmp(resp, "ERR", 3)) {
							fail("PREP 被拒");
							r = -1;
							break;
						}
						t0 = now_us();
						g_cursor = 0;
						if (g_threads == 1) {
							done = thr_run(&tc[0]);
							if (tc[0].rc)
								r = tc[0].rc;
						} else {
							pthread_t th[NTHREAD_MAX];
							struct thr_arg ta[NTHREAD_MAX];
							int k, nth = 0;

							for (k = 0; k < g_threads;
							     k++) {
								ta[nth].tc = &tc[k];
								ta[nth].done = 0;
								if (pthread_create(
								    &th[nth], NULL,
								    thr_trampoline,
								    &ta[nth])) {
									fprintf(stderr,
										"pthread_create "
										"失败\n");
									r = -1;
									break;
								}
								nth++;
							}
							for (k = 0; k < nth; k++) {
								pthread_join(th[k], NULL);
								done += ta[k].done;
								if (tc[k].rc)
									r = tc[k].rc;
							}
						}
						t1 = now_us();
						batch++;
						ops += done;
						bytes += done * g_bpp;
						timed += t1 - t0;
						if (r)
							break;
						if (done == 0) {
							fail("batch 零操作");
							r = -1;
							break;
						}
						/* 停止规则: 达标 (timed≥TARGET 且 batch≥2
						 * 且 ops≥MIN_OPS) / 硬顶 / 安全上限 */
						if ((timed / 1e6 >= TARGET_TIME_S &&
						     batch >= MIN_BATCHES &&
						     ops >= MIN_OPS) ||
						    timed / 1e6 >= HARD_TIME_S ||
						    batch >= MAX_BATCHES ||
						    ops >= 200000)
							break;
					}
					if (r || g_fail) {
						snprintf(row, sizeof(row),
							 "thr_%s_%s_%s_s%s",
							 cfg_name[cfg],
							 fault_name[fl],
							 op ? "write" : "read",
							 size_lab[si]);
						fail(row);
						break;
					}
					mbs = (double)bytes / timed;
					snprintf(row, sizeof(row),
						 "thr_%s_%s_%s_s%s",
						 cfg_name[cfg],
						 fault_name[fl],
						 op ? "write" : "read",
						 size_lab[si]);
					result(row, mbs, "mbps");
					printf("| %s | %.3f | %lu | %.2f |\n",
					       size_lab[si], mbs, ops,
					       timed / 1e6);
					fflush(stdout);
				}
			}
		}
	}

	printf("\n========================================\n");
	printf("racebw: FAIL=%d\n", g_fail);
	printf("========================================\n");
	rc = g_fail ? 1 : (odp_skip ? 2 : 0);

	/* QUIT (尽力) */
	if (ctrl_roundtrip(conn_fd, "QUIT", resp))
		printf("(QUIT 无响应 — server 可能已退出)\n");
	for (i = 0; i < g_threads; i++) {
		symrdma_mr_deregister(&sctx, &tc[i].lmr);
		ibv_destroy_qp(qp[i]);
		ibv_destroy_cq(cq[i]);
	}
	munlock(local_pool, (size_t)g_threads * LOCAL_SZ);
	munmap(local_pool, (size_t)g_threads * LOCAL_SZ);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	symrdma_close(&sctx);
	close(conn_fd);
	printf("DONE fail=%d\n", g_fail);
	return rc;
}

int main(int argc, char **argv)
{
	int i;

	if (argc < 2) {
		fprintf(stderr,
			"用法: %s server [-p port] [-g gid] [-d dev] | "
			"client -c IP [-p port] [-g gid] [-d dev] "
			"[-t threads]\n", argv[0]);
		return 1;
	}
	if (!strcmp(argv[1], "server")) {
		int port = 18777;
		const char *devname = NULL;

		for (i = 2; i < argc; i++) {
			if (!strcmp(argv[i], "-p") && i + 1 < argc)
				port = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-g") && i + 1 < argc)
				g_gid = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-d") && i + 1 < argc)
				devname = argv[++i];
			else if (!strcmp(argv[i], "-t") && i + 1 < argc)
				g_threads = atoi(argv[++i]);
		}
		if (g_threads < 1)
			g_threads = 1;
		if (g_threads > NTHREAD_MAX)
			g_threads = NTHREAD_MAX;
		return run_server(port, devname);
	}
	if (!strcmp(argv[1], "client")) {
		const char *ip = NULL;
		int port = 18777;
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
			else if (!strcmp(argv[i], "-t") && i + 1 < argc)
				g_threads = atoi(argv[++i]);
			else if (!strcmp(argv[i], "-z") && i + 1 < argc)
				g_size_filter = argv[++i];
		}
		if (!ip) {
			fprintf(stderr, "client 需要 -c IP\n");
			return 1;
		}
		if (g_threads < 1)
			g_threads = 1;
		if (g_threads > NTHREAD_MAX)
			g_threads = NTHREAD_MAX;
		return run_client(ip, port, devname);
	}
	fprintf(stderr, "未知模式 %s\n", argv[1]);
	return 1;
}
