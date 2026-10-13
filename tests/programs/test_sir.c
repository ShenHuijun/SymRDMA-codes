/*
 * test_sir.c — SymRDMA Level 7: Server-Initiated Repair 双进程验证 (P2)
 *
 * 两个进程经 PHY loopback 互联, 复现论文 §3.2 双向控制协议的核心语义。
 *
 * QP 设计 (论文 §3.2 的控制 QP 独立于数据 QP):
 *   - 数据 QP:  client → RDMA Read (server 只做 responder)
 *   - 控制 QP:  client → SEND "SWAP/REPAIR/QUIT", server → SEND "DONE"
 *   两类流量分 QP 走, 避免混合流量的 RQ PSN 序列失步 (SEND 被丢弃)。
 *
 *   server (SymRDMA 服务): 持有数据页, 注册双 IOVA + notifier;
 *                          收控制请求 (SWAP/REPAIR), 执行后回 DONE。
 *   client (纯 RDMA 应用): 零 SymRDMA 代码、零 ioctl — 只做 RDMA Read +
 *                          控制 QP SEND。经 LD_PRELOAD 自动获得自身
 *                          buffer 的 IOMMU 映射。
 *
 * 流程:
 *   1. client 基线 RDMA Read → 真实数据
 *   2. client SEND "SWAP 0"  → server madvise 换出 (OS 事件模拟)
 *   3. client RDMA Read → 哨兵 0xdeadbeef ★
 *   4. client SEND "REPAIR 0" → server ioctl REPAIR → DONE
 *   5. client RDMA Read → 真实数据 ★ (client 全程零 ioctl)
 *
 * 连接参数交换 (双形态):
 *   单机: /tmp/symrdma_sir.* 文件 (原形态)
 *   跨机: netcoord.h TCP (env SYMRDMA_TEST_TCP, run_sir_cross.sh 编排) —
 *         参数 blob 含本侧 GID (对端作 dgid) + 动态 MTU min(active_mtu,4096)
 *
 * 用法:
 *   ./test_sir server          # 先启动 (可后台)
 *   env LD_PRELOAD=libnprdma.so ./test_sir client   # 后启动 (前台, 做断言)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include "netcoord.h"   /* 跨机测试协调 (env SYMRDMA_TEST_TCP) */
/* SymRDMA MR 标记位 (P4): 与 lib/libsymrdma.h 同值 —
 * uverbs optional 位 1<<21, mlx5 据此走 identity MTT 分支 */
#define SYMRDMA_ACCESS_IDENTITY (1 << 21)

#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

#define SENTINEL_MAGIC   0xdeadbeef
#define MARKER           0xCDCDCDCD  /* client 写入的标记数据 (应被黑洞吸收) */
#define INLINE_LEN       4           /* SIR 内联小消息长度 (论文 §3.2 ≤1KB) */
#define TEST_PAGES       4
#define PAGE_SIZE        4096
#define BUF_SIZE         (TEST_PAGES * PAGE_SIZE)
#define CQ_DEPTH         16
/* 控制消息 buffer 用整页: SymRDMA IOMMU 注册以页为粒度 (小 buffer 无法注册) */
#define MSG_SIZE         4096

#define SERVER_PARAMS    "/tmp/symrdma_sir.server"
#define CLIENT_PARAMS    "/tmp/symrdma_sir.client"

/* server 侧 ioctl (client 不使用任何 SymRDMA 调用) */
#define SYMRDMA_IOC_MAGIC 'S'
struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_repair {
	int mr_id;
	unsigned long page_idx;
};
#define SYMRDMA_IOC_REG_MR   _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_REPAIR   _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)

static int passed = 0, failed = 0;

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (%s)\n", msg, strerror(errno)); failed++; } \
} while (0)

/* ---- 环境检查 ---- */

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

/* ---- 连接参数 (双形态: 单机文件 / 跨机 netcoord TCP) ---- */

struct conn_params {
	uint32_t data_qp_num;
	uint32_t ctl_qp_num;
	uint32_t rkey;
	uint32_t wkey;   /* write-only MR rkey (MTT=VA+32GB → 黑洞) */
	uint64_t addr;
	uint64_t len;
	char     gid[33];   /* 本侧 GID hex (跨机 dgid; 空/"-"=单机形态) */
};

/* 对端 GID 解析结果 (qp_to_rts 动态 dgid/MTU 用; 同 test_auto_sir ) */
static uint8_t g_peer_gid[16];
static int g_have_peer_gid;
static int g_sgid;

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
		return -1;
	for (i = 0; i < 16; i++) {
		unsigned v;

		if (sscanf(hex + i * 2, "%2x", &v) != 1)
			return -1;
		out[i] = (uint8_t)v;
	}
	return 0;
}

/* 行解析 (file / fmemopen 两形态共用); 返回非 gid 字段命中数 */
static int parse_params_lines(FILE *f, struct conn_params *p)
{
	char line[256];
	int ok = 0;

	while (fgets(line, sizeof(line), f)) {
		unsigned long long v;

		if (sscanf(line, "dataqp %llu", &v) == 1) {
			p->data_qp_num = (uint32_t)v;
			ok++;
		} else if (sscanf(line, "ctlqp %llu", &v) == 1) {
			p->ctl_qp_num = (uint32_t)v;
			ok++;
		} else if (sscanf(line, "rkey %llu", &v) == 1) {
			p->rkey = (uint32_t)v;
			ok++;
		} else if (sscanf(line, "wkey %llu", &v) == 1) {
			p->wkey = (uint32_t)v;
			ok++;
		} else if (sscanf(line, "addr %llu", &v) == 1) {
			p->addr = v;
			ok++;
		} else if (sscanf(line, "len %llu", &v) == 1) {
			p->len = v;
			ok++;
		} else if (!strncmp(line, "gid ", 4)) {
			if (line[4] != '-' && !gid_from_hex(line + 4, g_peer_gid)) {
				g_have_peer_gid = 1;
				snprintf(p->gid, sizeof(p->gid), "%s", line + 4);
				{
					size_t l = strlen(p->gid);

					while (l && (p->gid[l-1] == '\n' ||
							     p->gid[l-1] == '\r'))
						p->gid[--l] = 0;
				}
			}
		}
	}
	return ok;
}

static int write_server_params(const struct conn_params *p)
{
	char blob[512];
	int n = snprintf(blob, sizeof(blob),
			 "dataqp %u\nctlqp %u\nrkey %u\nwkey %u\naddr %llu\nlen %llu\ngid %s\n",
			 p->data_qp_num, p->ctl_qp_num, p->rkey, p->wkey,
			 (unsigned long long)p->addr, (unsigned long long)p->len,
			 p->gid[0] ? p->gid : "-");

	if (nc_active())
		return nc_put(SERVER_PARAMS, blob, (size_t)n + 1);
	{
		FILE *f = fopen(SERVER_PARAMS, "w");

		if (!f)
			return -1;
		fwrite(blob, 1, (size_t)n, f);
		fclose(f);
	}
	return 0;
}

static int read_server_params(struct conn_params *p)
{
	int ok;

	if (nc_active()) {
		char blob[512];
		int n = nc_get(SERVER_PARAMS, blob, sizeof(blob) - 1, 30);
		FILE *f;

		if (n <= 0)
			return -1;
		blob[n] = 0;
		f = fmemopen(blob, (size_t)n, "r");
		if (!f)
			return -1;
		ok = parse_params_lines(f, p);
		fclose(f);
	} else {
		FILE *f = fopen(SERVER_PARAMS, "r");

		if (!f)
			return -1;
		ok = parse_params_lines(f, p);
		fclose(f);
	}
	return ok == 6 ? 0 : -1;
}

static int read_client_params(struct conn_params *p)
{
	int ok;

	if (nc_active()) {
		char blob[512];
		int n = nc_get(CLIENT_PARAMS, blob, sizeof(blob) - 1, 30);
		FILE *f;

		if (n <= 0)
			return -1;
		blob[n] = 0;
		f = fmemopen(blob, (size_t)n, "r");
		if (!f)
			return -1;
		ok = parse_params_lines(f, p);
		fclose(f);
	} else {
		FILE *f = fopen(CLIENT_PARAMS, "r");

		if (!f)
			return -1;
		ok = parse_params_lines(f, p);
		fclose(f);
	}
	return (ok == 2 && p->data_qp_num && p->ctl_qp_num) ? 0 : -1;
}

static int write_client_params(const struct conn_params *p)
{
	char blob[512];
	int n = snprintf(blob, sizeof(blob),
			 "dataqp %u\nctlqp %u\ngid %s\n",
			 p->data_qp_num, p->ctl_qp_num,
			 p->gid[0] ? p->gid : "-");

	if (nc_active())
		return nc_put(CLIENT_PARAMS, blob, (size_t)n + 1);
	{
		FILE *f = fopen(CLIENT_PARAMS, "w");

		if (!f)
			return -1;
		fwrite(blob, 1, (size_t)n, f);
		fclose(f);
	}
	return 0;
}

static int wait_client_params(struct conn_params *p)
{
	int i, n = nc_active() ? 2 : 300;   /* TCP 形态 nc_get 内部阻塞 30s/次 */

	for (i = 0; i < n; i++) {
		if (read_client_params(p) == 0)
			return 0;
		if (!nc_active())
			usleep(100000);
	}
	return -1;
}

/* ---- verbs 辅助 ---- */


/* 环境适配 (双机测试床 双口卡实测): 机器按 PCI function 枚举出多个 mlx5
 * 设备, 取第一个可能命中 DOWN 口 — QP 建在死口上 DMA 走错 IOMMU domain
 * (DMAR fault reason 06)。优先选 port1 状态 ACTIVE 的设备; 查询失败保持
 * 原行为 (取第一个)。 */
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
	struct ibv_device **l;
	int n, i;
	struct ibv_device *d = NULL;

	l = ibv_get_device_list(&n);
	if (!l || !n)
		return NULL;
	for (i = 0; i < n; i++) {
		if (strstr(ibv_get_device_name(l[i]), "mlx5")) {
			if (mlx5_port_active(ibv_get_device_name(l[i]))) {
				d = l[i];
				break;
			}
			if (!d)
				d = l[i];   /* 非 ACTIVE 的 mlx5 仅作回退 */
		}
	}
	return d;
}

/* 建 QP 到 INIT; recv_needed=0 时 max_recv_wr 最小化 (纯 responder) */
static struct ibv_qp *create_qp(struct ibv_pd *pd, struct ibv_cq **cq_out,
				int recv_needed)
{
	struct ibv_cq *cq = ibv_create_cq(pd->context, CQ_DEPTH, NULL, NULL, 0);
	struct ibv_qp_init_attr a = {0};
	struct ibv_qp *qp;

	if (!cq)
		return NULL;
	a.send_cq = cq;
	a.recv_cq = cq;
	a.qp_type = IBV_QPT_RC;
	a.cap.max_send_wr  = CQ_DEPTH;
	a.cap.max_recv_wr  = recv_needed ? CQ_DEPTH : 1;
	a.cap.max_send_sge = 1;
	a.cap.max_recv_sge = 1;
	qp = ibv_create_qp(pd, &a);
	if (!qp) {
		ibv_destroy_cq(cq);
		return NULL;
	}
	*cq_out = cq;
	return qp;
}

/* INIT → RTS (跨机形态 dgid=对端 GID + 动态 MTU; 单机自环原语义) */
static int qp_to_rts(struct ibv_qp *qp, uint32_t dest_qp_num)
{
	struct ibv_qp_attr attr = {0};
	struct ibv_context *ctx = qp->pd->context;

	attr.qp_state        = IBV_QPS_INIT;
	attr.pkey_index      = 0;
	attr.port_num        = 1;
	attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE |
			       IBV_ACCESS_LOCAL_WRITE;
	if (ibv_modify_qp(qp, &attr,
			  IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS)) {
		printf("  QP INIT 失败\n");
		return -1;
	}

	attr.qp_state           = IBV_QPS_RTR;
	/* 跨机形态 (有对端 GID) 动态 MTU = min(active_mtu, 4096)
	 * (L15 教训: 测试床 active_mtu=1024, 硬编码 4096 令多包
	 * 消息首包被丢); 单机自环形态 (无对端 GID) 4096 不变 */
	attr.path_mtu           = IBV_MTU_4096;
	if (g_have_peer_gid) {
		struct ibv_port_attr pa;

		if (!ibv_query_port(ctx, 1, &pa) &&
		    pa.active_mtu < IBV_MTU_4096)
			attr.path_mtu = pa.active_mtu;
	}
	attr.dest_qp_num        = dest_qp_num;
	attr.rq_psn             = 0;
	attr.max_dest_rd_atomic = 1;
	attr.min_rnr_timer      = 12;
	attr.ah_attr.port_num   = 1;
	attr.ah_attr.is_global  = 1;
	attr.ah_attr.grh.sgid_index = (uint8_t)g_sgid;
	attr.ah_attr.grh.hop_limit  = 1;
	/* 跨机: dgid = 对端 GID (RoCEv2 必需); 单机自环: 本地 GID 0 (原语义) */
	if (g_have_peer_gid) {
		memcpy(&attr.ah_attr.grh.dgid, g_peer_gid, 16);
	} else if (ibv_query_gid(ctx, 1, 0, &attr.ah_attr.grh.dgid)) {
		printf("  查询 GID 失败\n");
		return -1;
	}
	if (ibv_modify_qp(qp, &attr,
			  IBV_QP_STATE | IBV_QP_MTU |
			  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER |
			  IBV_QP_AV)) {
		printf("  QP RTR 失败\n");
		return -1;
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
		printf("  QP RTS 失败\n");
		return -1;
	}
	return 0;
}

/* SEND 一条控制消息 */
static int send_msg(struct ibv_qp *qp, struct ibv_cq *cq, const char *msg,
		    uint32_t lkey, char *buf)
{
	struct ibv_sge sge = { .addr = (uintptr_t)buf, .length = MSG_SIZE, .lkey = lkey };
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	int n;

	/* 支持 msg==buf (RREPI 内联回复: 头部与数据同 buffer,
	 * 头部覆盖 buf[0..] 不碰 +64 数据区; 否则 snprintf 重叠未定义) */
	if ((char *)msg != buf)
		snprintf(buf, MSG_SIZE, "%s", msg);

	wr.opcode = IBV_WR_SEND;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr,
			"  [sir] SEND 失败: n=%d status=%d vendor_err=0x%x\n",
			n, n > 0 ? (int)wc.status : -1,
			n > 0 ? wc.vendor_err : 0);
		return -1;
	}
	return 0;
}

/* post 一个 recv (乒乓协议: 同一时刻最多一个在途 recv) */
static int post_recv(struct ibv_qp *qp, char *buf, uint32_t lkey)
{
	struct ibv_sge sge = { .addr = (uintptr_t)buf, .length = MSG_SIZE, .lkey = lkey };
	struct ibv_recv_wr wr = {0}, *bad = NULL;

	wr.sg_list = &sge;
	wr.num_sge = 1;
	return ibv_post_recv(qp, &wr, &bad) ? -1 : 0;
}

/* 等一个完成 */
static int wait_comp(struct ibv_cq *cq, int timeout_s)
{
	struct ibv_wc wc;
	int i, n;

	for (i = 0; i < timeout_s * 100; i++) {
		n = ibv_poll_cq(cq, 1, &wc);
		if (n > 0) {
			if (wc.status != IBV_WC_SUCCESS)
				fprintf(stderr,
					"  [sir] 完成异常: status=%d vendor_err=0x%x\n",
					(int)wc.status, wc.vendor_err);
			return (wc.status == IBV_WC_SUCCESS) ? 0 : -1;
		}
		usleep(10000);
	}
	fprintf(stderr, "  [sir] 等待完成超时 (%ds)\n", timeout_s);
	return -1;
}

/* 一次 RDMA Read 到 local, 返回首 4 字节; 失败 -1 */
static long long rdma_read_page(struct ibv_qp *qp, struct ibv_cq *cq,
				void *local, uint32_t lkey,
				uintptr_t remote_addr, uint32_t rkey)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = PAGE_SIZE, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad_wr = NULL;
	struct ibv_wc wc;
	int n;

	memset(local, 0, PAGE_SIZE);
	wr.opcode              = IBV_WR_RDMA_READ;
	wr.sg_list             = &sge;
	wr.num_sge             = 1;
	wr.wr.rdma.remote_addr = remote_addr;
	wr.wr.rdma.rkey        = rkey;
	wr.send_flags          = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad_wr))
		return -1;
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	return (long long)*(uint32_t *)local;
}

/* 一次 RDMA Write (源 local, len 字节); 0 成功 -1 失败 */
static int rdma_write_data(struct ibv_qp *qp, struct ibv_cq *cq,
			   void *local, uint32_t lkey,
			   uintptr_t remote_addr, uint32_t rkey, uint32_t len)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = len, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad_wr = NULL;
	struct ibv_wc wc;
	int n;

	wr.opcode              = IBV_WR_RDMA_WRITE;
	wr.sg_list             = &sge;
	wr.num_sge             = 1;
	wr.wr.rdma.remote_addr = remote_addr;
	wr.wr.rdma.rkey        = rkey;
	wr.send_flags          = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad_wr))
		return -1;
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	return 0;
}

/* 一次 RDMA Read (remote → local, len 字节); 0 成功 -1 失败 */
static int rdma_read_data(struct ibv_qp *qp, struct ibv_cq *cq,
			  void *local, uint32_t lkey,
			  uintptr_t remote_addr, uint32_t rkey, uint32_t len)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = len, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad_wr = NULL;
	struct ibv_wc wc;
	int n;

	wr.opcode              = IBV_WR_RDMA_READ;
	wr.sg_list             = &sge;
	wr.num_sge             = 1;
	wr.wr.rdma.remote_addr = remote_addr;
	wr.wr.rdma.rkey        = rkey;
	wr.send_flags          = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad_wr))
		return -1;
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	return 0;
}

/* ---- server: SymRDMA 服务进程 ---- */

static int server_main(void)
{
	struct conn_params params = {0}, peer = {0};
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_repair repair_req;
	unsigned char *buf, *ctl_in, *ctl_out;
	struct ibv_mr *buf_mr, *write_mr, *in_mr, *out_mr, *tmp_mr = NULL;
	unsigned char *tmp = NULL;   /* SIR 反向 Read 的拉取目标  */
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *data_cq, *ctl_cq;
	struct ibv_qp *data_qp, *ctl_qp;
	int sym_fd, mr_id, in_mr_id, out_mr_id;
	int i, round, nreq = 0;

	printf("=== Level 7 server (SymRDMA 服务) ===\n");

	/* 数据页 + 注册 */
	sym_fd = open("/dev/symrdma", O_RDWR);
	if (sym_fd < 0) { printf("无法打开 /dev/symrdma\n"); return 1; }
	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) { perror("mmap"); return 1; }
	memset(buf, 0xAB, BUF_SIZE);
	for (i = 0; i < TEST_PAGES; i++)
		buf[i * PAGE_SIZE] = (unsigned char)('A' + i);

	reg.va_start = (unsigned long long)buf;
	reg.len = BUF_SIZE;
	if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg)) {
		printf("REG_MR 失败\n");
		return 1;
	}
	mr_id = reg.mr_id;
	printf("数据页已注册: mr_id=%d VA=%p\n", mr_id, buf);

	/* RDMA 上下文 + 双 QP (数据/控制) */
	dev = find_rdma_device();
	if (!dev) return 1;
	ctx = ibv_open_device(dev);
	pd = ibv_alloc_pd(ctx);
	data_qp = create_qp(pd, &data_cq, 0);
	ctl_qp  = create_qp(pd, &ctl_cq, 1);
	if (!data_qp || !ctl_qp) return 1;
	printf("server QP: data=0x%x ctl=0x%x\n",
	       data_qp->qp_num, ctl_qp->qp_num);

	/* 控制消息 buffer (identity_mtt 下 DMA 收/发也需 IOMMU 映射) */
	ctl_in  = mmap(NULL, MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ctl_out = mmap(NULL, MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	/* touch 确保驻留: REG_MR 驻留判定不触发缺页  */
	memset(ctl_in, 0x5A, MSG_SIZE);
	memset(ctl_out, 0x5A, MSG_SIZE);
	reg.va_start = (unsigned long long)ctl_in;
	reg.len = MSG_SIZE;
	ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
	in_mr_id = reg.mr_id;
	reg.va_start = (unsigned long long)ctl_out;
	ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
	out_mr_id = reg.mr_id;
	in_mr  = ibv_reg_mr(pd, ctl_in,  MSG_SIZE,
			    IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	out_mr = ibv_reg_mr(pd, ctl_out, MSG_SIZE,
			    IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	buf_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			    IBV_ACCESS_LOCAL_WRITE |
			    IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_REMOTE_WRITE |
			    SYMRDMA_ACCESS_IDENTITY);
	/* 写区域 MR: REMOTE_WRITE 无 REMOTE_READ → MTT=VA+32GB →
	 * RDMA Write 走 write_iova (换出页 → 黑洞吸收) */
	write_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			      IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
			      SYMRDMA_ACCESS_IDENTITY);
	if (!write_mr) {
		printf("write-only MR 注册失败\n");
		return 1;
	}
	printf("[log] no-pin MR 已注册 (identity_mtt 全局生效): rkey=0x%x wkey=0x%x\n",
	       buf_mr->rkey, write_mr->rkey);

	/* SIR 数据面: 反向 RDMA Read 的拉取目标 (论文 §3.2 phase 3) */
	tmp = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (tmp == MAP_FAILED) { printf("tmp mmap 失败\n"); return 1; }
	memset(tmp, 0x5A, PAGE_SIZE);
	reg.va_start = (unsigned long long)tmp;
	reg.len = PAGE_SIZE;
	ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
	tmp_mr = ibv_reg_mr(pd, tmp, PAGE_SIZE,
			    IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	if (!tmp_mr) { printf("tmp ibv_reg_mr 失败\n"); return 1; }

	/* 发布参数, 等待 client */
	params.data_qp_num = data_qp->qp_num;
	params.ctl_qp_num  = ctl_qp->qp_num;
	params.rkey   = buf_mr->rkey;
	params.wkey   = write_mr->rkey;
	params.addr   = (uint64_t)(uintptr_t)buf;
	params.len    = BUF_SIZE;
	{
		union ibv_gid g;   /* 本侧 GID 入参数 (跨机 dgid) */

		if (!ibv_query_gid(ctx, 1, g_sgid, &g))
			gid_to_hex(&g, params.gid);
	}
	write_server_params(&params);
	printf("参数已发布, 等待 client...\n");
	if (wait_client_params(&peer)) {
		printf("等待 client 超时\n");
		return 1;
	}
	if (qp_to_rts(data_qp, peer.data_qp_num)) return 1;
	if (qp_to_rts(ctl_qp, peer.ctl_qp_num)) return 1;
	printf("QP RTS (data dest=0x%x, ctl dest=0x%x)\n",
	       peer.data_qp_num, peer.ctl_qp_num);

	/* §4.1 辅助 MR rkey 经控制 QP 同步 (论文: 首次使用多 1 RTT,
	 * 后续新 MR 捎带同一 QP) — 推 KEYMAP <data_rkey> <write_rkey> 给 client,
	 * 替代带外参数文件传递辅助 rkey (参数文件仍含, 兼容; KEYMAP 为论文形态) */
	usleep(500000);   /* 等 client post_recv (RNR 重试兜底) */
	{
		char km[128];
		snprintf(km, sizeof(km), "KEYMAP %u %u", params.rkey, params.wkey);
		if (send_msg(ctl_qp, ctl_cq, km, out_mr->lkey, (char *)ctl_out)) {
			printf("KEYMAP 推送失败\n");
			return 1;
		}
		printf("  [log] KEYMAP 已推: rkey=0x%x wkey=0x%x (控制 QP, 论文 §4.1)\n",
		       params.rkey, params.wkey);
	}

	/* 预 post 一个 recv (乒乓协议) */
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);

	/* 控制循环: SWAP i / REPAIR i / RREP / WREP / RREPI / WREPI / QUIT */
	printf("进入控制循环...\n");
	for (round = 0; round < 100; round++) {
		int replied = 0;

		if (wait_comp(ctl_cq, 60)) {
			printf("  等待请求超时\n");
			break;
		}
		nreq++;
		printf("  收: %s\n", ctl_in);
		if (!strncmp((char *)ctl_in, "SWAP", 4)) {
			unsigned long idx = strtoul((char *)ctl_in + 5, NULL, 0);
			madvise(buf + idx * PAGE_SIZE, PAGE_SIZE, MADV_PAGEOUT);
		} else if (!strncmp((char *)ctl_in, "REPAIR", 6)) {
			unsigned long idx = strtoul((char *)ctl_in + 7, NULL, 0);
			repair_req.mr_id = mr_id;
			repair_req.page_idx = idx;
			if (ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req))
				printf("  REPAIR 失败 (errno=%d)\n", errno);
		} else if (!strncmp((char *)ctl_in, "RREPI", 5)) {
			/* SIR 小消息内联读修复 (论文 §3.2: ≤1KB 数据经
			 * 控制通道内联, 避免反向 RDMA Write 的额外 RTT) */
			char *p = (char *)ctl_in + 6;
			unsigned long idx = strtoul(p, &p, 0);

			repair_req.mr_id = mr_id;
			repair_req.page_idx = idx;
			if (ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req)) {
				printf("  RREPI REPAIR 失败\n");
				snprintf((char *)ctl_out, 64, "RREPI-FAIL %lu", idx);
			} else {
				/* 内联: 数据 (≤1KB) 写入控制 buffer +64 偏移,
				 * 头部格式串覆盖 buf[0..] 不碰数据区 */
				memcpy((char *)ctl_out + 64, buf + idx * PAGE_SIZE,
				       INLINE_LEN);
				snprintf((char *)ctl_out, 64, "RREPI-OK %lu %d",
					 idx, INLINE_LEN);
				printf("  [log] RREPI: REPAIR + 内联回 %d B (控制通道)\n",
				       INLINE_LEN);
			}
			post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);
			send_msg(ctl_qp, ctl_cq, (char *)ctl_out, out_mr->lkey,
				 (char *)ctl_out);
			replied = 1;
		} else if (!strncmp((char *)ctl_in, "WREPI", 5)) {
			/* SIR 小消息内联写修复 (论文 §3.2): client
			 * 数据内联在请求 (控制 buffer +64), server REPAIR 后
			 * 直接写入真实页 — 避免反向 RDMA Read 的额外 RTT */
			char *p = (char *)ctl_in + 6;
			unsigned long idx = strtoul(p, &p, 0);
			unsigned long clen = strtoul(p, &p, 0);

			repair_req.mr_id = mr_id;
			repair_req.page_idx = idx;
			if (ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req)) {
				printf("  WREPI REPAIR 失败\n");
			} else if (clen > INLINE_LEN) {
				printf("  WREPI 数据过长 (%lu > %d)\n", clen,
				       INLINE_LEN);
			} else {
				memcpy(buf + idx * PAGE_SIZE, (char *)ctl_in + 64,
				       clen);
				printf("  [log] WREPI: REPAIR + 内联写入 %lu B (控制通道)\n",
				       clen);
			}
		} else if (!strncmp((char *)ctl_in, "RREP", 4)) {
			/* SIR 数据面 (论文 §3.2 phase 3): server REPAIR 后
			 * 反向 RDMA Write 推数据到 client 接收 buffer */
			char *p = (char *)ctl_in + 5;
			unsigned long idx = strtoul(p, &p, 0);
			uintptr_t caddr = (uintptr_t)strtoull(p, &p, 0);
			uint32_t crkey = (uint32_t)strtoull(p, &p, 0);
			repair_req.mr_id = mr_id;
			repair_req.page_idx = idx;
			if (ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req)) {
				printf("  RREP REPAIR 失败 (errno=%d)\n", errno);
			} else if (rdma_write_data(data_qp, data_cq,
						   buf + idx * PAGE_SIZE, buf_mr->lkey,
						   caddr, crkey, PAGE_SIZE)) {
				printf("  RREP 反向 Write 失败\n");
			} else {
				printf("  [log] RREP: REPAIR + 反向 Write 推数据到 client (0x%lx)\n",
				       idx);
			}
		} else if (!strncmp((char *)ctl_in, "WREP", 4)) {
			/* SIR 数据面: server REPAIR 后反向 RDMA Read
			 * 从 client 拉数据 → 写真实页 */
			char *p = (char *)ctl_in + 5;
			unsigned long idx = strtoul(p, &p, 0);
			uintptr_t caddr = (uintptr_t)strtoull(p, &p, 0);
			uint32_t crkey = (uint32_t)strtoull(p, &p, 0);
			uint32_t clen = (uint32_t)strtoull(p, &p, 0);
			repair_req.mr_id = mr_id;
			repair_req.page_idx = idx;
			if (ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &repair_req)) {
				printf("  WREP REPAIR 失败 (errno=%d)\n", errno);
			} else if (rdma_read_data(data_qp, data_cq, tmp, tmp_mr->lkey,
						  caddr, crkey, clen)) {
				printf("  WREP 反向 Read 失败\n");
			} else {
				memcpy(buf + idx * PAGE_SIZE, tmp, clen);
				printf("  [log] WREP: REPAIR + 反向 Read 拉数据 (%u B) 落地\n",
				       clen);
			}
		} else if (!strncmp((char *)ctl_in, "QUIT", 4)) {
			printf("  收到 QUIT\n");
			break;
		}
		/* 先补 recv 再回 DONE, 消除 RNR 窗口 (RREPI 已自行回复) */
		if (!replied) {
			post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);
			send_msg(ctl_qp, ctl_cq, "DONE", out_mr->lkey,
				 (char *)ctl_out);
		}
	}

	printf("处理请求 %d 条, 清理退出\n", nreq);
	ibv_dereg_mr(buf_mr);
	ibv_dereg_mr(write_mr);
	ibv_dereg_mr(in_mr);
	ibv_dereg_mr(out_mr);
	if (tmp_mr)
		ibv_dereg_mr(tmp_mr);
	ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, mr_id);
	ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, in_mr_id);
	ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, out_mr_id);
	ibv_destroy_qp(data_qp);
	ibv_destroy_qp(ctl_qp);
	ibv_destroy_cq(data_cq);
	ibv_destroy_cq(ctl_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(buf, BUF_SIZE);
	munmap(ctl_in, MSG_SIZE);
	munmap(ctl_out, MSG_SIZE);
	if (tmp != NULL)
		munmap(tmp, PAGE_SIZE);
	close(sym_fd);
	unlink(SERVER_PARAMS);
	return 0;
}

/* ---- client: 纯 RDMA 应用 (零 SymRDMA 代码, 经 LD_PRELOAD) ---- */

static int client_main(void)
{
	struct conn_params sp = {0}, mine = {0};
	unsigned char *local, *ctl_in, *ctl_out;
	struct ibv_mr *local_mr, *in_mr, *out_mr;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *data_cq, *ctl_cq;
	struct ibv_qp *data_qp, *ctl_qp;
	long long v;
	int i, ret;

	printf("=== Level 7 client (纯 RDMA 应用, 零 SymRDMA 代码) ===\n");

	CHECK(nprdma_loaded(), "前置: libnprdma 已注入 (client buffer 自动 IOMMU 映射)");

	/* 等 server 参数 (TCP 形态 nc_get 内部阻塞 30s/次, 2 次即可) */
	{
		int n = nc_active() ? 2 : 300;

		for (i = 0; i < n; i++) {
			if (read_server_params(&sp) == 0)
				break;
			if (!nc_active())
				usleep(100000);
		}
	}
	CHECK(i < 300, "取得 server 连接参数 (qpnum/rkey/addr)");
	if (i >= 300)
		return 1;
	printf("  server: data_qp=0x%x ctl_qp=0x%x rkey=0x%x addr=%p\n",
	       sp.data_qp_num, sp.ctl_qp_num, sp.rkey, (void *)(uintptr_t)sp.addr);

	/* RDMA 上下文 + 双 QP */
	dev = find_rdma_device();
	if (!dev) return 1;
	ctx = ibv_open_device(dev);
	pd = ibv_alloc_pd(ctx);
	data_qp = create_qp(pd, &data_cq, 0);
	ctl_qp  = create_qp(pd, &ctl_cq, 1);
	if (!data_qp || !ctl_qp) return 1;
	mine.data_qp_num = data_qp->qp_num;
	mine.ctl_qp_num  = ctl_qp->qp_num;
	{
		union ibv_gid g;   /* 本侧 GID 入参数 (跨机 dgid) */

		if (!ibv_query_gid(ctx, 1, g_sgid, &g))
			gid_to_hex(&g, mine.gid);
	}
	write_client_params(&mine);
	if (qp_to_rts(data_qp, sp.data_qp_num)) return 1;
	if (qp_to_rts(ctl_qp, sp.ctl_qp_num)) return 1;
	printf("  client QP RTS (data dest=0x%x, ctl dest=0x%x)\n",
	       sp.data_qp_num, sp.ctl_qp_num);

	/* 本地 buffer — 经 LD_PRELOAD 自动获得 SymRDMA IOMMU 映射 */
	local = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ctl_in  = mmap(NULL, MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ctl_out = mmap(NULL, MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	/* touch 确保驻留: REG_MR 驻留判定不触发缺页  */
	memset(local, 0x5A, PAGE_SIZE);
	memset(ctl_in, 0x5A, MSG_SIZE);
	memset(ctl_out, 0x5A, MSG_SIZE);
	/* SIR 数据面: local 接收/数据 buffer 开放反向访问 —
	 * server 反向 RDMA Write 推数据 / Read 拉数据 */
	local_mr = ibv_reg_mr(pd, local, PAGE_SIZE,
			      IBV_ACCESS_LOCAL_WRITE |
			      IBV_ACCESS_REMOTE_READ |
			      IBV_ACCESS_REMOTE_WRITE |
			      SYMRDMA_ACCESS_IDENTITY);
	in_mr    = ibv_reg_mr(pd, ctl_in,  MSG_SIZE,
			      IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	out_mr   = ibv_reg_mr(pd, ctl_out, MSG_SIZE,
			      IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);

	/* §4.1 辅助 MR rkey 经控制 QP 同步 — 收 server 推来的
	 * KEYMAP (data rkey + write wkey), 替代带外参数文件 (论文 §4.1
	 * "synchronizes key mappings between initiator and target via
	 * control QP; first key mapping takes one additional RTT") */
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);
	CHECK(wait_comp(ctl_cq, 30) == 0 &&
	      !strncmp((char *)ctl_in, "KEYMAP", 6),
	      "★ 收到 KEYMAP (控制 QP 同步辅助 MR rkey, 论文 §4.1)");
	if (!strncmp((char *)ctl_in, "KEYMAP", 6)) {
		unsigned int kr = 0, kw = 0;
		sscanf((char *)ctl_in + 7, "%u %u", &kr, &kw);
		printf("  [log] KEYMAP: rkey=0x%x wkey=0x%x\n", kr, kw);
		CHECK(kr == sp.rkey && kw == sp.wkey,
		      "KEYMAP rkey/wkey 与参数文件一致 (双通道交叉验证)");
		sp.wkey = kw;   /* 后续写标记场景用 KEYMAP 的 wkey */
	}
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);

	printf("\n===== 场景: client 全程零 ioctl =====\n");

	/* 1. 基线读 */
	v = rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
			   (uintptr_t)sp.addr, sp.rkey);
	CHECK(v == 0xABABAB41, "基线: RDMA Read → 0xABABAB41 (真实数据)");

	/* 2. 请求 server 换出 (OS 事件模拟, server 侧 madvise) */
	ret = send_msg(ctl_qp, ctl_cq, "SWAP 0", out_mr->lkey, (char *)ctl_out);
	CHECK(ret == 0, "SEND SWAP 0");
	ret = wait_comp(ctl_cq, 30);
	CHECK(ret == 0 && !strncmp((char *)ctl_in, "DONE", 4),
	      "SWAP 请求 → server 已换出 (DONE)");
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);

	/* 3. 读 → 哨兵 ★ */
	v = 0;
	for (i = 0; i < 100; i++) {
		v = rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
				   (uintptr_t)sp.addr, sp.rkey);
		if (v == (long long)SENTINEL_MAGIC)
			break;
		usleep(100000);
	}
	CHECK(v == (long long)SENTINEL_MAGIC,
	      "★ 换出后 RDMA Read → 哨兵 0xdeadbeef (server notifier 生效)");

	/* 3.5 ★ 写标记数据到换出页 (write rkey → write_iova → 黑洞吸收) */
	*(uint32_t *)local = MARKER;
	ret = rdma_write_data(data_qp, data_cq, local, local_mr->lkey,
			      (uintptr_t)sp.addr, sp.wkey, 4);
	CHECK(ret == 0,
	      "★ RDMA Write 标记 0xCDCDCDCD (write rkey, WC 成功)");
	printf("  [log] 标记已写入换出页 (预期被黑洞吸收)\n");

	/* 3.6 写后读 — 哨兵魔数必须完好 (写入未污染哨兵页) */
	v = rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
			   (uintptr_t)sp.addr, sp.rkey);
	CHECK(v == (long long)SENTINEL_MAGIC,
	      "★ 写后 Read → 仍 0xdeadbeef (黑洞吸收, 哨兵零污染)");

	/* 3.7 ★ L7-4/L7-5 (论文 §3.2 基本流 恢复): SEND
	 * "REPAIR 0" → server ioctl REPAIR → 重读 = 初始数据 —
	 * client 全程零 ioctl 完成闭环。该步骤曾从套件流程中遗失
	 * (server 端 REPAIR 命令一直保留, 测试规格 L7-4/L7-5 行无覆盖);
	 * 插入在黑洞吸收验证之后 — 页 0 处于换出态, 无需重新换出
	 * (避免 GUP 换回页的 best-effort 回收竞态); 修复后读到的
	 * 0xABABAB41 同时满足 L7-5b 的 "修复后读到初始数据"。 */
	ret = send_msg(ctl_qp, ctl_cq, "REPAIR 0", out_mr->lkey, (char *)ctl_out);
	CHECK(ret == 0, "SEND REPAIR 0 (修复请求, 论文 §3.2)");
	ret = wait_comp(ctl_cq, 30);
	CHECK(ret == 0 && !strncmp((char *)ctl_in, "DONE", 4),
	      "REPAIR 请求 → server 已修复 (DONE)");
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);
	v = rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
			   (uintptr_t)sp.addr, sp.rkey);
	CHECK(v == 0xABABAB41,
	      "★ REPAIR 后 RDMA Read → 0xABABAB41 (client 零 ioctl 完成闭环)");

	/* 4. ★ SIR 数据面读修复 (论文 §3.2 phase 3):
	 *    请求 "RREP" — server REPAIR 后反向 RDMA Write 推数据到
	 *    client 接收 buffer (无需 client 重读) */
	{
		char req[128];
		snprintf(req, sizeof(req), "RREP 0 %llu %u",
			 (unsigned long long)(uintptr_t)local, local_mr->rkey);
		ret = send_msg(ctl_qp, ctl_cq, req, out_mr->lkey, (char *)ctl_out);
		CHECK(ret == 0, "SEND RREP 0 (数据面修复请求)");
		ret = wait_comp(ctl_cq, 30);
		CHECK(ret == 0 && !strncmp((char *)ctl_in, "DONE", 4),
		      "RREP 请求 → server 已修复 (DONE)");
		post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);
	}

	/* 5. ★ 数据已在本地接收 buffer (server 反向 Write 推来) —
	 *    client 零数据读、零 ioctl 拿到真实数据 */
	CHECK(*(uint32_t *)local == 0xABABAB41,
	      "★★ 接收 buffer = 0xABABAB41 — 数据由 server 反向 RDMA Write 推来 (SIR 数据面)");

	/* 邻居 */
	v = rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
			   (uintptr_t)sp.addr + PAGE_SIZE, sp.rkey);
	CHECK(v == 0xABABAB42, "邻居页 1 数据完好");

	/* 6. ★ SIR 数据面写修复 (论文 §3.2 phase 3):
	 *    换出页 → client 裸写标记 (黑洞吸收) → "WREP" → server
	 *    REPAIR + 反向 RDMA Read 从 client 拉数据 → 写真实页 */
	printf("\n--- WREP: 写修复 (server 反向 Read 拉数据) ---\n");
	ret = send_msg(ctl_qp, ctl_cq, "SWAP 0", out_mr->lkey, (char *)ctl_out);
	CHECK(ret == 0, "SEND SWAP 0 (再次换出)");
	ret = wait_comp(ctl_cq, 30);
	CHECK(ret == 0 && !strncmp((char *)ctl_in, "DONE", 4),
	      "SWAP 请求 → server 已换出 (DONE)");
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);

	*(uint32_t *)local = MARKER;
	ret = rdma_write_data(data_qp, data_cq, local, local_mr->lkey,
			      (uintptr_t)sp.addr, sp.wkey, 4);
	CHECK(ret == 0, "裸写标记 0xCDCDCDCD (黑洞吸收)");

	{
		char req[128];
		snprintf(req, sizeof(req), "WREP 0 %llu %u 4",
			 (unsigned long long)(uintptr_t)local, local_mr->rkey);
		ret = send_msg(ctl_qp, ctl_cq, req, out_mr->lkey, (char *)ctl_out);
		CHECK(ret == 0, "SEND WREP 0 (写修复请求)");
		ret = wait_comp(ctl_cq, 30);
		CHECK(ret == 0 && !strncmp((char *)ctl_in, "DONE", 4),
		      "WREP 请求 → server 已修复 (DONE)");
		post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);
	}

	/* 验证: 标记经 server 反向 Read 拉取后落地真实页 */
	v = rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
			   (uintptr_t)sp.addr, sp.rkey);
	CHECK(v == (long long)MARKER,
	      "★★ 修复后 Read → 0xCDCDCDCD — 写数据由 server 反向 Read 拉取落地 (SIR 数据面)");

	/* 7. ★ SIR 小消息内联读修复 (论文 §3.2):
	 *    请求 "RREPI" — server REPAIR 后 ≤1KB 数据经控制通道内联回,
	 *    避免反向 RDMA Write 的额外 RTT (client 零额外操作) */
	printf("\n--- RREPI: 内联读修复 (论文 §3.2, ≤1KB 经控制通道) ---\n");
	/* 恢复页 0 数据 (前场景 WREP 写成 MARKER; 驻留页直接 RDMA 写真实 PA) */
	*(uint32_t *)local = 0xABABAB41;
	rdma_write_data(data_qp, data_cq, local, local_mr->lkey,
			(uintptr_t)sp.addr, sp.wkey, 4);
	CHECK(rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
			     (uintptr_t)sp.addr, sp.rkey) == 0xABABAB41,
	      "RREPI: 页 0 已恢复 0xABABAB41");
	ret = send_msg(ctl_qp, ctl_cq, "SWAP 0", out_mr->lkey, (char *)ctl_out);
	CHECK(ret == 0, "RREPI: SEND SWAP 0 (再次换出)");
	ret = wait_comp(ctl_cq, 30);
	CHECK(ret == 0 && !strncmp((char *)ctl_in, "DONE", 4),
	      "RREPI: SWAP 完成 (DONE)");
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);

	ret = send_msg(ctl_qp, ctl_cq, "RREPI 0", out_mr->lkey, (char *)ctl_out);
	CHECK(ret == 0, "RREPI: SEND RREPI 0 (内联读修复请求)");
	ret = wait_comp(ctl_cq, 30);
	CHECK(ret == 0 && !strncmp((char *)ctl_in, "RREPI-OK", 8),
	      "RREPI: 回复 RREPI-OK (数据内联在控制通道)");
	CHECK(*(uint32_t *)((char *)ctl_in + 64) == 0xABABAB41,
	      "★★ RREPI: 控制通道内联数据 = 0xABABAB41 (零额外 RTT)");
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);

	/* 8. ★ SIR 小消息内联写修复 (论文 §3.2):
	 *    数据内联在请求 (控制 buffer +64) → server REPAIR 后直接写
	 *    真实页 — 避免反向 RDMA Read 的额外 RTT */
	printf("\n--- WREPI: 内联写修复 (论文 §3.2, ≤1KB 经控制通道) ---\n");
	ret = send_msg(ctl_qp, ctl_cq, "SWAP 0", out_mr->lkey,
		       (char *)ctl_out);
	CHECK(ret == 0, "WREPI: SEND SWAP 0 (再次换出)");
	ret = wait_comp(ctl_cq, 30);
	CHECK(ret == 0 && !strncmp((char *)ctl_in, "DONE", 4),
	      "WREPI: SWAP 完成 (DONE)");
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);

	/* 内联数据: 控制 buffer +64 填 0xEEEEEEEE, 头部 "WREPI 0 4" */
	*(uint32_t *)((char *)ctl_out + 64) = 0xEEEEEEEE;
	ret = send_msg(ctl_qp, ctl_cq, "WREPI 0 4", out_mr->lkey,
		       (char *)ctl_out);
	CHECK(ret == 0, "WREPI: SEND WREPI 0 4 (数据内联在请求)");
	ret = wait_comp(ctl_cq, 30);
	CHECK(ret == 0 && !strncmp((char *)ctl_in, "DONE", 4),
	      "WREPI: server REPAIR + 内联写入 (DONE)");
	post_recv(ctl_qp, (char *)ctl_in, in_mr->lkey);

	v = rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
			   (uintptr_t)sp.addr, sp.rkey);
	CHECK(v == 0xEEEEEEEE,
	      "★★ WREPI: 修复后 Read → 0xEEEEEEEE — 内联数据经控制通道落地真实页");

	/* 收尾 */
	send_msg(ctl_qp, ctl_cq, "QUIT", out_mr->lkey, (char *)ctl_out);
	ibv_dereg_mr(local_mr);
	ibv_dereg_mr(in_mr);
	ibv_dereg_mr(out_mr);
	ibv_destroy_qp(data_qp);
	ibv_destroy_qp(ctl_qp);
	ibv_destroy_cq(data_cq);
	ibv_destroy_cq(ctl_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(local, PAGE_SIZE);
	munmap(ctl_in, MSG_SIZE);
	munmap(ctl_out, MSG_SIZE);
	unlink(CLIENT_PARAMS);

	printf("\n========================================\n");
	printf("Level 7 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}

int main(int argc, char *argv[])
{
	int is_server = argc > 1 && !strcmp(argv[1], "server");
	const char *g = getenv("SYMRDMA_TEST_GID");
	int rc;

	g_sgid = (g && g[0]) ? atoi(g) : 0;
	if (nc_init(is_server)) {
		fprintf(stderr, "netcoord 初始化失败 (SYMRDMA_TEST_TCP=%s)\n",
			getenv("SYMRDMA_TEST_TCP"));
		return 1;
	}
	rc = is_server ? server_main() : client_main();
	return rc;
}
