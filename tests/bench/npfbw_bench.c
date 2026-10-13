/* npfbw_bench.c — 双机 no-page-fault 分类带宽基准 (scripts/run_nopf_bw.sh 专用)
 * 对照论文 §5.2.2 Fig 13(b): RDMA Read/Write (裸) vs SymRDMA Read/Write (透明)
 *
 * 为何不用 perftest (实测结论):
 *   1. 系统 perftest 4.5-0.18 默认走 ibv_wr* 直发 API — 绕过 libnprdma 的
 *      post_send/poll_cq 拦截, 透明引擎不在数据路径上, 测的只是 identity-MTT
 *      注册本身;
 *   2. 更严重: perftest 源 buffer 注册为 LOCAL_WRITE-only, OFED 补丁的
 *      identity_womr 启发式 (无 REMOTE_READ ⇒ "DMA 写目标") 把它误判为写区域
 *      MR (MTT=VA+32GB) — NIC 读写 payload 源数据走写区 IOVA, 驻留页 RW 可读
 *      (短跑无恙), 但任一页被 notifier 翻入黑洞 (只写) 后读被拒 →
 *      LOC_PROT_ERR 0x51 → QP 死 (400K 迭代 3 跑 2 挂; dmesg:
 *      [DMA Read] fault reason 06 "PTE Read access is not set")。
 *
 * 本工具对策: MR 注册为混合访问 (LOCAL_WRITE|REMOTE_READ|REMOTE_WRITE) —
 *   womr=false → MTT=VA (读区), 页翻哨兵后 NIC 读仍可读 (哨兵数据, 带宽测试
 *   不校验内容); 且走标准 ibv_post_send — 透明引擎拦截路径真实生效
 *   (本地预检/poll 直通), 测得即论文 SymRDMA 透明形态的真实开销。
 *
 * 点级 QP 重建重试: 测试床存在外部页失效源 (host-a EDR 代理嫌疑, mlocked
 *   匿名页仍被周期性 invalidate ~5次/s) → 引擎预检修复的 IOMMU unmap→map
 *   窗口可能与在飞大消息 DMA 读相撞 → LOC_PROT (4MB 点实测)。QP 死亡后
 *   经 TCP 会合通道重建双方 QP 并重试该点 (≤3 次); 修复后的页重试必存活。
 *
 *  L18 工作集扫描模式 (-W):
 *   server: -W <ws> -T <on|off> → 分配/触碰/注册 <ws> 工作集 (2MB 对齐,
 *     madvise HUGEPAGE/NOHUGEPAGE, smaps 验证 AnonHugePages 实际覆盖)
 *   client: -W <ws> --pattern <seq|rand> [-n iters] → 固定 4KB RDMA Read
 *     按序/随机访问整个工作集 → ATC/IOTLB 容量曲线。
 *   对照组: raw (无 LD_PRELOAD, OFED DMA-API 映射形态, 可到大 WS) vs
 *   sym (引擎拦截, SymRDMA IOMMU 逐页形态; Phase 2 组模型后 thp=on
 *   变 2MB PTE 形态)。注: 当前  内核 sym 形态注册上限 ~682MB
 *   (pages[] kcalloc, 见 L17) — 大 WS sym 点需组模型落地后补测。
 *   输出: WSRESULT,thp=,pattern=,ws_mb=,msg=,iters=,bw_MB_s= (client stdout)
 *         WSTHP thp=<on|off> anon_huge_mb=<n> ws_mb=<n> (server stdout)
 *
 * 用法:
 *   server: npfbw_bench -s [-W <ws>] [-T on|off] [-d mlx5_0] [-g 5] [-p 18526]
 *   client: npfbw_bench -c <server_ip> [-W <ws>] [--pattern seq|rand] [-n iters]
 *                 [-T on|off (仅报告用)] [-d mlx5_0] [-g 5] [-p 18526] [-P]
 *   -P: 预热模式 (短大消息洪水, 供脚本吸收 EDR 扫描窗口)
 * 输出 (client stdout, 供 run_nopf_bw.sh 解析):
 *   RESULT <write|read> <size_bytes> <iters> <bw_MB_s>   成功
 *   FAILED <write|read> <size_bytes>                      3 次重试后仍失败
 *   WSRESULT,thp=,pattern=,ws_mb=,msg=,iters=,bw_MB_s=   工作集扫描点成功
 *   WSFAILED,thp=,pattern=,ws_mb=                        工作集扫描点失败
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
#include <getopt.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <infiniband/verbs.h>

#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU   /* 旧版 verbs.h 兼容 (同 test_sir.c) */
#endif

#define BUF_LEN   (8UL << 20)          /* 8MB: 写源 [0,4MB) / 读目的 [4MB,8MB) */
#define HPAGE     (2UL << 20)          /* 2MB 大页 */
#define TX_DEPTH  256
#define CQ_DEPTH  1024
#define DEF_PORT  18526
#define DEF_GID   5
#define PT_RETRY  3                    /* 点级 QP 重建重试上限 */

/* 4MB 点不扫: 写向在测试床外部页失效源下触发引擎预检修复与在飞 DMA 读
 * 的竞态 (QP LOC_PROT, 见 run_nopf_bw.sh 头注/); 1MB 已达线速 */
static const long sizes[] = { 64, 256, 1024, 2048, 4096,
			      16384, 65536, 262144, 1048576 };
#define NSIZES ((int)(sizeof(sizes) / sizeof(sizes[0])))

static int preheat = 0;   /* -P: 预热模式 (短大消息洪水, 供脚本吸收 EDR 扫描窗口) */

/* ----  L18 工作集扫描模式 (见文件头) ---- */
static unsigned long g_ws = 0;       /* -W 工作集字节; >0 → ws 模式 */
static unsigned long g_buflen = BUF_LEN;  /* 本端注册缓冲长度 (ws 模式 server 侧 = WS) */
static int g_ws_thp = 0;             /* -T on|off (server: madvise; 双端: 报告用) */
static int g_ws_rand = 1;            /* --pattern rand(默认)|seq */
static unsigned long g_ws_iters = 0; /* -n 迭代数; 0 = 按页数自适应 */
static unsigned long g_ws_msg = 4096;/* 工作集扫描消息尺寸 (固定 4KB) */
static char *g_ws_raw;               /* ws 模式 mmap 原始指针 (清理用) */

static unsigned long parse_ws_size(const char *s)
{
	unsigned long v;
	char *end;

	v = strtoul(s, &end, 0);
	if (end == s)
		return 0;
	if (*end == 'k' || *end == 'K')
		v <<= 10;
	else if (*end == 'm' || *end == 'M')
		v <<= 20;
	else if (*end == 'g' || *end == 'G')
		v <<= 30;
	return v;
}

/* xorshift64 — 确定性可重现随机访问序列 */
static uint64_t g_prng = 0x9e3779b97f4a7c15ULL;

static inline uint64_t prng_next(void)
{
	uint64_t x = g_prng;

	x ^= x << 13;
	x ^= x >> 7;
	x ^= x << 17;
	g_prng = x;
	return x;
}

/* server 侧: 读取缓冲所在 VMA 的 AnonHugePages (THP 实际覆盖验证) */
static void report_thp(const void *buf, unsigned long len)
{
	FILE *f = fopen("/proc/self/smaps", "r");
	char line[256];
	unsigned long kb = 0;
	int in = 0;

	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		unsigned long s, e, v;

		if (sscanf(line, "%lx-%lx", &s, &e) == 2) {
			in = ((uintptr_t)buf >= s && (uintptr_t)buf + len <= e);
			if (in)
				in = 1;
		} else if (in && sscanf(line, "AnonHugePages: %lu", &v) == 1) {
			kb += v;
		}
	}
	fclose(f);
	printf("WSTHP thp=%s anon_huge_mb=%lu ws_mb=%lu\n",
	       g_ws_thp ? "on" : "off", kb >> 10, len >> 20);
	fflush(stdout);
}

static long iter_for(long s)
{
	if (s <= 4096)
		return 50000;
	if (s <= 65536)
		return 20000;
	return 5000;
}

static void die(const char *msg)
{
	fprintf(stderr, "[npfbw_bench] %s: %s\n", msg, strerror(errno));
	exit(1);
}

/* ---- TCP 会合 (行协议: 首条 C/S 参数行 + READY/GO/DONEALL/RESET) ---- */

static int recv_line(int fd, char *buf, size_t cap)
{
	size_t n = 0;

	while (n + 1 < cap) {
		char c;
		ssize_t r = recv(fd, &c, 1, 0);

		if (r <= 0)
			return -1;
		if (c == '\n') {
			buf[n] = 0;
			return (int)n;
		}
		buf[n++] = c;
	}
	buf[n] = 0;
	return (int)n;
}

struct peer_params {
	uint32_t qpn, rkey;
	uint64_t vaddr, len;
	uint8_t gid[16];
};

static void params_to_line(const char tag, const struct peer_params *p,
			   char *buf, size_t cap)
{
	int i, off = snprintf(buf, cap, "%c qpn=%u rkey=%u vaddr=%llu len=%llu gid=",
			      tag, p->qpn, p->rkey,
			      (unsigned long long)p->vaddr,
			      (unsigned long long)p->len);
	for (i = 0; i < 16; i++)
		off += snprintf(buf + off, cap - off, "%02x", p->gid[i]);
	snprintf(buf + off, cap - off, "\n");
}

static int line_to_params(struct peer_params *p, const char *buf)
{
	char gidhex[33] = {0};

	return sscanf(buf, "%*c qpn=%u rkey=%u vaddr=%llu len=%llu gid=%32s",
		      &p->qpn, &p->rkey, (unsigned long long *)&p->vaddr,
		      (unsigned long long *)&p->len, gidhex) == 5 &&
	       sscanf(gidhex, "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx"
		      "%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx%2hhx",
		      &p->gid[0], &p->gid[1], &p->gid[2], &p->gid[3],
		      &p->gid[4], &p->gid[5], &p->gid[6], &p->gid[7],
		      &p->gid[8], &p->gid[9], &p->gid[10], &p->gid[11],
		      &p->gid[12], &p->gid[13], &p->gid[14], &p->gid[15]) == 16;
}

/* ---- verbs ---- */

static struct ibv_context *open_dev(const char *want)
{
	struct ibv_device **list;
	struct ibv_context *ctx = NULL;
	int n, i;

	list = ibv_get_device_list(&n);
	if (!list || n <= 0)
		die("无 RDMA 设备");
	for (i = 0; i < n; i++) {
		if ((want && !strcmp(ibv_get_device_name(list[i]), want)) ||
		    (!want && strstr(ibv_get_device_name(list[i]), "mlx5"))) {
			ctx = ibv_open_device(list[i]);
			break;
		}
	}
	if (!ctx)
		die("打开设备失败");
	return ctx;
}

/* INIT→RTR→RTS (RoCEv2, 强制 GID index; 对端参数经 TCP 交换) */
static void qp_up(struct ibv_qp *qp, int gid_idx,
		  const struct peer_params *peer)
{
	struct ibv_qp_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_INIT;
	attr.pkey_index = 0;
	attr.port_num = 1;
	attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
			       IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE;
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
		die("QP INIT");

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTR;
	attr.path_mtu = IBV_MTU_1024;
	attr.dest_qp_num = peer->qpn;
	attr.rq_psn = 0;
	attr.max_dest_rd_atomic = 8;
	attr.min_rnr_timer = 12;
	attr.ah_attr.port_num = 1;
	attr.ah_attr.is_global = 1;
	attr.ah_attr.grh.sgid_index = gid_idx;
	attr.ah_attr.grh.hop_limit = 1;
	memcpy(attr.ah_attr.grh.dgid.raw, peer->gid, 16);
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_MTU |
			  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
			  IBV_QP_MAX_DEST_RD_ATOMIC | IBV_QP_MIN_RNR_TIMER |
			  IBV_QP_AV))
		die("QP RTR");

	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.sq_psn = 0;
	attr.timeout = 14;
	attr.retry_cnt = 3;
	attr.rnr_retry = 3;
	attr.max_rd_atomic = 8;
	if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_SQ_PSN |
			  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))
		die("QP RTS");
}

static double now_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1e6 + ts.tv_nsec / 1e3;
}

/* ---- 全局资源 (QP 重建时保持不变) ---- */

static struct ibv_context *g_ctx;
static struct ibv_pd *g_pd;
static struct ibv_cq *g_cq;
static struct ibv_mr *g_mr;
static void *g_buf;
static struct ibv_qp *g_qp;
static int g_gid_idx = DEF_GID;
static struct peer_params g_peer;      /* 对端 (rkey/vaddr/gid 不随重建变) */

static struct ibv_qp *create_qp_init(void)
{
	struct ibv_qp_init_attr qia;
	struct ibv_qp *qp;

	memset(&qia, 0, sizeof(qia));

	qia.send_cq = g_cq;
	qia.recv_cq = g_cq;
	qia.qp_type = IBV_QPT_RC;
	qia.cap.max_send_wr = TX_DEPTH;
	qia.cap.max_recv_wr = 1;
	qia.cap.max_send_sge = 1;
	qia.cap.max_recv_sge = 1;
	qp = ibv_create_qp(g_pd, &qia);
	if (!qp)
		die("ibv_create_qp");
	/* 仅 INIT — RTR/RTS 由 qp_up 在拿到对端新 qpn 后做 */
	{
		struct ibv_qp_attr attr;

		memset(&attr, 0, sizeof(attr));
		attr.qp_state = IBV_QPS_INIT;
		attr.pkey_index = 0;
		attr.port_num = 1;
		attr.qp_access_flags = IBV_ACCESS_LOCAL_WRITE |
				       IBV_ACCESS_REMOTE_READ |
				       IBV_ACCESS_REMOTE_WRITE;
		if (ibv_modify_qp(qp, &attr, IBV_QP_STATE | IBV_QP_PKEY_INDEX |
				  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
			die("QP INIT");
	}
	return qp;
}

/* 点级 QP 重建 (client 侧): 发新 qpn → 收 server 新 qpn → 重建 RTR/RTS。
 * rkey/vaddr/gid 不变 — 同一 MR。 */
static void reset_qp(int fd)
{
	struct peer_params self;
	char line[128];

	ibv_destroy_qp(g_qp);
	g_qp = create_qp_init();
	self.qpn = g_qp->qp_num;
	self.rkey = g_mr->rkey;
	self.vaddr = (uintptr_t)g_buf;
	self.len = g_buflen;   /* ws 模式 server 通告 WS, client 8MB */
	memcpy(self.gid, g_peer.gid, 16);   /* 仅占位 (对端 gid 用 g_peer 原值) */

	params_to_line('R', &self, line, sizeof(line));
	snprintf(line, sizeof(line), "RESET qpn=%u\n", self.qpn);
	if (send(fd, line, strlen(line), 0) < 0)
		die("send R");
	if (recv_line(fd, line, sizeof(line)) < 0 ||
	    sscanf(line, "RESET qpn=%u", &g_peer.qpn) != 1)
		die("等 RESET 应答");
	qp_up(g_qp, g_gid_idx, &g_peer);
}

/* 单点测量: 0=成功; -1=传输层错误 (QP 已死, 需重建重试) */
static int run_point(int is_read, long size, long iters, double *bw)
{
	struct ibv_sge sge;
	struct ibv_send_wr wr, *bad = NULL;
	struct ibv_wc wc[64];
	long scnt = 0, ccnt = 0;
	int k, n;
	double t0, t1;

	memset(&wr, 0, sizeof(wr));
	wr.num_sge = 1;
	wr.sg_list = &sge;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.opcode = is_read ? IBV_WR_RDMA_READ : IBV_WR_RDMA_WRITE;
	sge.length = size;
	sge.lkey = g_mr->lkey;
	sge.addr = is_read ? (uintptr_t)g_buf + BUF_LEN / 2 : (uintptr_t)g_buf;
	wr.wr.rdma.remote_addr = g_peer.vaddr;
	wr.wr.rdma.rkey = g_peer.rkey;

	t0 = now_us();
	while (ccnt < iters) {
		while (scnt < iters && scnt - ccnt < TX_DEPTH) {
			wr.wr_id = scnt++;
			if (ibv_post_send(g_qp, &wr, &bad))
				return -1;
		}
		n = ibv_poll_cq(g_cq, 64, wc);
		if (n < 0)
			return -1;
		for (k = 0; k < n; k++) {
			if (wc[k].status != IBV_WC_SUCCESS) {
				fprintf(stderr,
					"[npfbw_bench] CQE 错误 status=%d "
					"opcode=%d (dir=%s size=%ld)\n",
					wc[k].status, wc[k].opcode,
					is_read ? "read" : "write", size);
				return -1;
			}
			ccnt++;
		}
	}
	t1 = now_us();
	*bw = (double)iters * size / (t1 - t0);
	return 0;
}

/* L18: 工作集扫描单点 — 读向固定 4KB, 每次访问依 pattern
 * 重算对端偏移 (rand: xorshift64 % pages; seq: 环形递增)。
 * 0=成功; -1=传输层错误 (QP 已死, 需重建重试) */
static int run_point_ws(long iters, double *bw)
{
	struct ibv_sge sge;
	struct ibv_send_wr wr, *bad = NULL;
	struct ibv_wc wc[64];
	unsigned long pages = g_peer.len / g_ws_msg;   /* 消息粒度页数 (rand 偏移单位) */
	uint64_t seq = 0;
	long scnt = 0, ccnt = 0;
	int k, n;
	double t0, t1;

	memset(&wr, 0, sizeof(wr));
	wr.num_sge = 1;
	wr.sg_list = &sge;
	wr.send_flags = IBV_SEND_SIGNALED;
	wr.opcode = IBV_WR_RDMA_READ;
	sge.length = g_ws_msg;
	sge.lkey = g_mr->lkey;
	sge.addr = (uintptr_t)g_buf + BUF_LEN / 2;   /* 读目的: 本端 [4MB,8MB) */
	wr.wr.rdma.rkey = g_peer.rkey;

	t0 = now_us();
	while (ccnt < iters) {
		while (scnt < iters && scnt - ccnt < TX_DEPTH) {
			unsigned long off;

			if (g_ws_rand)
				off = (unsigned long)(prng_next() % pages) * g_ws_msg;
			else
				off = (seq++ % pages) * g_ws_msg;
			wr.wr_id = scnt++;
			wr.wr.rdma.remote_addr = g_peer.vaddr + off;
			if (ibv_post_send(g_qp, &wr, &bad))
				return -1;
		}
		n = ibv_poll_cq(g_cq, 64, wc);
		if (n < 0)
			return -1;
		for (k = 0; k < n; k++) {
			if (wc[k].status != IBV_WC_SUCCESS) {
				fprintf(stderr,
					"[npfbw_bench] CQE 错误 status=%d opcode=%d "
					"(ws %s %luMB)\n",
					wc[k].status, wc[k].opcode,
					g_ws_rand ? "rand" : "seq", g_peer.len >> 20);
				return -1;
			}
			ccnt++;
		}
	}
	t1 = now_us();
	*bw = (double)iters * g_ws_msg / (t1 - t0);
	return 0;
}

static void sweep(int fd)
{
	static const char *dirs[] = { "write", "read" };
	/* 预热: 1MB/4MB 大消息短扫描 (~4.6s 持续洪水, 匹配实测查杀时点) */
	static const long ph_sz[2] = { 1048576, 4194304 };
	static const long ph_it[2] = { 3000, 800 };
	const long *sz = preheat ? ph_sz : sizes;
	const long *itv = preheat ? ph_it : NULL;
	const int npt = preheat ? 2 : NSIZES;
	int d, i;

	/* L18: 工作集扫描模式 — 单点 (读向, -m 消息尺寸默认 4KB),
	 * 迭代数自适应: 数据量目标 ~2GB (20000 下限确保稳定 / 500K 上限) */
	if (g_ws) {
		unsigned long vol_target = 2UL << 30;   /* 2GB 数据量目标 */
		unsigned long vol_it = vol_target / g_ws_msg;
		long iters = g_ws_iters ? (long)g_ws_iters :
			(vol_it < 20000 ? 20000 :
			 (vol_it > 500000 ? 500000 : vol_it));
		double bw = 0;
		int attempt, ok = 0;

		for (attempt = 0; attempt < PT_RETRY && !ok; attempt++) {
			if (attempt > 0) {
				fprintf(stderr, "[npfbw_bench] ws %s: QP 重建重试 %d/%d\n",
					g_ws_rand ? "rand" : "seq", attempt, PT_RETRY - 1);
				reset_qp(fd);
			}
			if (run_point_ws(iters, &bw) == 0)
				ok = 1;
		}
		if (ok)
			printf("WSRESULT,thp=%s,pattern=%s,ws_mb=%lu,msg=%lu,iters=%ld,bw_MB_s=%.2f\n",
			       g_ws_thp ? "on" : "off", g_ws_rand ? "rand" : "seq",
			       g_peer.len >> 20, g_ws_msg, iters, bw);
		else
			printf("WSFAILED,thp=%s,pattern=%s,ws_mb=%lu\n",
			       g_ws_thp ? "on" : "off", g_ws_rand ? "rand" : "seq",
			       g_peer.len >> 20);
		fflush(stdout);
		return;
	}

	for (d = 0; d < 2; d++) {
		for (i = 0; i < npt; i++) {
			long s = sz[i];
			long iters = preheat ? itv[i] : iter_for(s);
			double bw = 0;
			int attempt, ok = 0;

			for (attempt = 0; attempt < PT_RETRY && !ok; attempt++) {
				if (attempt > 0) {
					fprintf(stderr,
						"[npfbw_bench] %s %ld: QP 重建重试 %d/%d\n",
						dirs[d], s, attempt, PT_RETRY - 1);
					reset_qp(fd);
				}
				if (run_point(d, s, iters, &bw) == 0)
					ok = 1;
			}
			if (preheat)
				printf("PREHEAT %s %ld %ld %.2f\n", dirs[d], s,
				       iters, bw);
			else if (ok)
				printf("RESULT %s %ld %ld %.2f\n", dirs[d], s,
				       iters, bw);
			else
				printf("FAILED %s %ld\n", dirs[d], s);
			fflush(stdout);
		}
	}
}

/* server 侧: GO 后服务 RESET (重建 QP) 直至 DONEALL */
static void server_service(int fd)
{
	char line[128];

	for (;;) {
		if (recv_line(fd, line, sizeof(line)) < 0)
			die("server 会合通道断开");
		if (!strncmp(line, "DONEALL", 7))
			return;
		if (!strncmp(line, "RESET qpn=", 10)) {
			struct peer_params self;
			union ibv_gid g;
			uint32_t peer_qpn;

			if (sscanf(line, "RESET qpn=%u", &peer_qpn) != 1)
				die("RESET 解析");
			ibv_destroy_qp(g_qp);
			g_qp = create_qp_init();
			if (ibv_query_gid(g_ctx, 1, g_gid_idx, &g))
				die("ibv_query_gid");
			self.qpn = g_qp->qp_num;
			self.rkey = g_mr->rkey;
			self.vaddr = (uintptr_t)g_buf;
			self.len = g_buflen;   /* ws 模式 server 通告 WS, client 8MB */
			memcpy(self.gid, g.raw, 16);
			g_peer.qpn = peer_qpn;
			qp_up(g_qp, g_gid_idx, &g_peer);
			snprintf(line, sizeof(line), "RESET qpn=%u\n", self.qpn);
			if (send(fd, line, strlen(line), 0) < 0)
				die("send R");
		}
	}
}

int main(int argc, char **argv)
{
	const char *dev_name = "mlx5_0", *server_ip = NULL;
	int is_server = 0, port = DEF_PORT, opt, gid_idx = DEF_GID;
	char line[256];
	int fd, cfd;
	struct sockaddr_in addr;
	union ibv_gid g;
	struct peer_params self;

	while ((opt = getopt_long(argc, argv, "sc:d:g:p:PW:T:n:m:",
			  (const struct option[]){
				{ "pattern", required_argument, NULL, 'z' },
				{ NULL, 0, NULL, 0 },
			  }, NULL)) != -1) {
		switch (opt) {
		case 's': is_server = 1; break;
		case 'c': server_ip = optarg; break;
		case 'd': dev_name = optarg; break;
		case 'g': gid_idx = atoi(optarg); g_gid_idx = gid_idx; break;
		case 'p': port = atoi(optarg); break;
		case 'P': preheat = 1; break;
		case 'W':
			g_ws = parse_ws_size(optarg);
			if (!g_ws || g_ws < HPAGE || (g_ws % 4096)) {
				fprintf(stderr, "-W 须 ≥2MB 且 4KB 对齐 (K/M/G 后缀)\n");
				return 1;
			}
			break;
		case 'T': g_ws_thp = !strcmp(optarg, "on"); break;
		case 'n': g_ws_iters = strtoul(optarg, NULL, 0); break;
		case 'm':
			g_ws_msg = parse_ws_size(optarg);
			if (!g_ws_msg || g_ws_msg < 64 || (g_ws_msg % 4096)) {
				fprintf(stderr, "-m 须 ≥64B 且 4KB 对齐\n");
				return 1;
			}
			if (g_ws_msg > (1UL << 20)) {
				fprintf(stderr, "-m 上限 1MB (时长控制)\n");
				return 1;
			}
			break;
		case 'z':
			if (!strcmp(optarg, "seq"))
				g_ws_rand = 0;
			else if (strcmp(optarg, "rand")) {
				fprintf(stderr, "--pattern 须为 seq 或 rand\n");
				return 1;
			}
			break;
		default: fprintf(stderr, "用法: %s -s | -c <ip> "
					 "[-d dev] [-g gid] [-p port] [-P] \\\n"
					 "      [-W <ws[K|M|G]> -T <on|off> --pattern seq|rand -n iters]\n",
					 argv[0]);
			 return 1;
		}
	}

	g_ctx = open_dev(dev_name);
	g_pd = ibv_alloc_pd(g_ctx);
	if (!g_pd)
		die("ibv_alloc_pd");
	/* L18: ws 模式 server 侧 — 2MB 对齐 MAP_NORESERVE 工作集,
	 * madvise THP, 逐页触碰 (全部驻留: 带宽图不应含缺页路径), smaps 验证。
	 * client 侧仍用 8MB 本地缓冲 (读目的 + 引擎拦截注册), 工作集只在对端。 */
	if (g_ws && is_server) {
		char *raw = mmap(NULL, g_ws + HPAGE, PROT_READ | PROT_WRITE,
				 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
		unsigned long off;

		if (raw == MAP_FAILED)
			die("mmap ws");
		g_ws_raw = raw;
		g_buf = (void *)(((uintptr_t)raw + HPAGE - 1) & ~(HPAGE - 1));
		if (madvise(g_buf, g_ws,
			    g_ws_thp ? MADV_HUGEPAGE : MADV_NOHUGEPAGE))
			die("madvise");
		for (off = 0; off < g_ws; off += 4096)
			((char *)g_buf)[off] = 0xAB;
		report_thp(g_buf, g_ws);
		g_buflen = g_ws;
		fprintf(stderr, "[npfbw_bench] ws %luMB 已触碰驻留 (thp=%s)\n",
			g_ws >> 20, g_ws_thp ? "on" : "off");
	} else {
		g_buf = aligned_alloc(4096, BUF_LEN);
		if (!g_buf)
			die("alloc");
		memset(g_buf, 0xAB, BUF_LEN);
	}
	/* 混合访问: womr=false → MTT=VA (读区) — 见文件头注释 */
	g_mr = ibv_reg_mr(g_pd, g_buf, g_buflen, IBV_ACCESS_LOCAL_WRITE |
			  IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE);
	if (!g_mr)
		die("ibv_reg_mr");

	/* 诊断门控: NPFBW_REG_DELAY=<秒> — reg_mr 后暂停, 供采样 /proc/symrdma
	 * 逐页初始状态 (判别 "注册即哨兵" vs "运行期翻页") */
	{
		const char *rd = getenv("NPFBW_REG_DELAY");

		if (rd) {
			fprintf(stderr, "[npfbw_bench] reg 完成, 休眠 %ss 供采样\n", rd);
			sleep(atoi(rd));
		}
	}

	g_cq = ibv_create_cq(g_ctx, CQ_DEPTH, NULL, NULL, 0);
	if (!g_cq)
		die("ibv_create_cq");
	g_qp = create_qp_init();

	if (ibv_query_gid(g_ctx, 1, g_gid_idx, &g))
		die("ibv_query_gid");
	self.qpn = g_qp->qp_num;
	self.rkey = g_mr->rkey;
	self.vaddr = (uintptr_t)g_buf;
	self.len = g_buflen;   /* ws 模式 server 通告 WS, client 8MB */
	memcpy(self.gid, g.raw, 16);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (is_server) {
		int yes = 1;

		fd = socket(AF_INET, SOCK_STREAM, 0);
		setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
		if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)))
			die("bind");
		if (listen(fd, 1))
			die("listen");
		printf("SERVER waiting\n");
		fflush(stdout);
		cfd = accept(fd, NULL, NULL);
		if (cfd < 0)
			die("accept");
		if (recv_line(cfd, line, sizeof(line)) < 0 ||
		    !line_to_params(&g_peer, line))
			die("解析 client 参数");
		params_to_line('S', &self, line, sizeof(line));
		if (send(cfd, line, strlen(line), 0) < 0)
			die("send S");
		qp_up(g_qp, g_gid_idx, &g_peer);
		if (recv_line(cfd, line, sizeof(line)) < 0 ||
		    strncmp(line, "READY", 5))
			die("等 READY");
		if (send(cfd, "GO\n", 3, 0) < 0)
			die("send GO");
		server_service(cfd);
		printf("SERVER done\n");
		close(cfd);
		close(fd);
	} else {
		if (!server_ip)
			die("缺 -c <server_ip>");
		fd = socket(AF_INET, SOCK_STREAM, 0);
		inet_pton(AF_INET, server_ip, &addr.sin_addr);
		if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)))
			die("connect");
		params_to_line('C', &self, line, sizeof(line));
		if (send(fd, line, strlen(line), 0) < 0)
			die("send C");
		if (recv_line(fd, line, sizeof(line)) < 0 ||
		    !line_to_params(&g_peer, line))
			die("解析 server 参数");
		qp_up(g_qp, g_gid_idx, &g_peer);
		if (send(fd, "READY\n", 6, 0) < 0)
			die("send READY");
		if (recv_line(fd, line, sizeof(line)) < 0 ||
		    strncmp(line, "GO", 2))
			die("等 GO");
		sweep(fd);
		if (send(fd, "DONEALL\n", 8, 0) < 0)
			die("send DONEALL");
		close(fd);
	}

	ibv_destroy_qp(g_qp);
	ibv_destroy_cq(g_cq);
	ibv_dereg_mr(g_mr);
	if (g_ws_raw)
		munmap(g_ws_raw, g_ws + HPAGE);
	else
		free(g_buf);
	ibv_dealloc_pd(g_pd);
	ibv_close_device(g_ctx);
	return 0;
}
