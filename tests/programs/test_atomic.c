/*
 * test_atomic.c — SymRDMA Level 10: 非 pin 原子操作 (论文 §3.4)
 *
 * 论文 §3.4: 原子操作 (CAS/FAA) 非幂等, 乐观路径 (幂等重放) 不适用 —
 * 走专用双端路径: initiator 发 RPC (目标地址 + 操作数) → 远端 CPU
 * 执行 lock cmpxchg (CAS) / lock xadd (FAA) → 返回旧值。
 * CPU 经正常 MMU 路径访问 → 非驻留页自动触发缺页换入, 无部分执行风险。
 *
 * 本测试 (双进程, 复用 L7 SIR 架构;  起双机跨机形态):
 *   server: 数据 MR (SymRDMA) + 数据 QP + 控制 QP; 收原子请求 →
 *           CPU 执行原子 → 回旧值; 支持 SWAP/REPAIR 控制命令
 *   client: 纯 RDMA 应用, 发原子 RPC / SWAP / REPAIR, 断言旧值与语义
 *
 * 场景 (对齐论文 §3.4 + §4.1 惰性语义):
 *   T1 FAA 驻留页: 连续 +1, 旧值序列正确, RDMA Read 可见新值
 *   T2 CAS 成功:   期望匹配 → 修改 + 返回旧值
 *   T3 CAS 失败:   期望不匹配 → 不修改 + 返回当前值
 *   T4 换出页 FAA: CPU 原子触发缺页换入 → 返回旧值 (非驻留仍正确)
 *   T5 惰性语义:   换出页原子后 IOMMU 仍哨兵 (CPU 换入不更新 IOMMU)
 *                  → REPAIR → RDMA Read 见原子结果
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
#include "netcoord.h"   /* 跨机测试协调 (env SYMRDMA_TEST_TCP) */

/* SymRDMA MR 标记位 (与 lib/libsymrdma.h 同值) */
#define SYMRDMA_ACCESS_IDENTITY (1 << 21)
#ifndef IBV_QP_MTU
#define IBV_QP_MTU  IBV_QP_PATH_MTU
#endif
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

#define SENTINEL_MAGIC   0xdeadbeef
#define SENTINEL_MAGIC64 0xdeadbeefdeadbeefULL   /* 64 位读时哨兵页连续 8B */
#define TEST_PAGES     4
#define PAGE_SIZE      4096
#define BUF_SIZE       (TEST_PAGES * PAGE_SIZE)
#define CQ_DEPTH       16
#define MSG_SIZE       4096            /* 控制 buffer 整页 (页粒度教训) */

#define SERVER_PARAMS  "/tmp/symrdma_atomic.server"
#define CLIENT_PARAMS  "/tmp/symrdma_atomic.client"

/* ---- SymRDMA ioctl (REG_MR/DEREG_MR/REPAIR/READ_IOVA) ---- */
#define SYMRDMA_IOC_MAGIC 'S'
struct symrdma_ioc_reg_mr {
	unsigned long long va_start, len;
	int mr_id;
};
struct symrdma_ioc_repair { int mr_id; unsigned long page_idx; };
struct symrdma_ioc_read_iova {
	int mr_id; unsigned long long iova; unsigned long offset; unsigned int value;
};
#define SYMRDMA_IOC_REG_MR    _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR  _IOW(SYMRDMA_IOC_MAGIC,  2, int)
#define SYMRDMA_IOC_READ_IOVA _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_read_iova)
#define SYMRDMA_IOC_REPAIR    _IOWR(SYMRDMA_IOC_MAGIC,  6, struct symrdma_ioc_repair)

/* ---- 控制协议 (控制 QP, 二进制消息) ---- */
#define ATOM_MAGIC     0x41544F4D   /* 'ATOM' */
#define ATOM_OP_FAA    1
#define ATOM_OP_CAS    2
#define ATOM_OP_SWAP   0x100        /* server: madvise 换出页 (模拟 OS) */
#define ATOM_OP_REPAIR 0x101        /* server: ioctl REPAIR */
#define ATOM_OP_QUIT   0x200

struct atom_msg {
	uint32_t magic;
	uint32_t op;
	uint32_t offset;      /* 目标 = buf + offset (页内偏移) */
	uint32_t ok;          /* 响应: CAS 是否成功 / 命令是否完成 */
	uint64_t cmp;         /* CAS expected */
	uint64_t swap;        /* CAS new / FAA delta */
	uint64_t old;         /* 响应: 原子旧值 */
};

/* ---- 连接参数 (双形态: 单机文件 / 跨机 netcoord TCP) ---- */
struct conn_params {
	uint32_t data_qp_num;
	uint32_t ctl_qp_num;
	uint32_t rkey;
	uint64_t addr;
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
		} else if (sscanf(line, "addr %llu", &v) == 1) {
			p->addr = v;
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
			 "dataqp %u\nctlqp %u\nrkey %u\naddr %llu\ngid %s\n",
			 p->data_qp_num, p->ctl_qp_num, p->rkey,
			 (unsigned long long)p->addr,
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
	return ok == 4 ? 0 : -1;
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
	int n = snprintf(blob, sizeof(blob), "dataqp %u\nctlqp %u\ngid %s\n",
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

/* ---- verbs 辅助 (同 L7) ---- */

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
			  IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
		return -1;

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
		return -1;
	}
	if (ibv_modify_qp(qp, &attr,
			  IBV_QP_STATE | IBV_QP_MTU |
			  IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
			  IBV_QP_MAX_DEST_RD_ATOMIC |
			  IBV_QP_MIN_RNR_TIMER | IBV_QP_AV))
		return -1;

	attr.qp_state      = IBV_QPS_RTS;
	attr.sq_psn        = 0;
	attr.timeout       = 14;
	attr.retry_cnt     = 7;
	attr.rnr_retry     = 7;
	attr.max_rd_atomic = 1;
	if (ibv_modify_qp(qp, &attr,
			  IBV_QP_STATE | IBV_QP_SQ_PSN |
			  IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			  IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))
		return -1;
	return 0;
}

/* SEND 消息 (整个控制 buffer) */
static int send_msg(struct ibv_qp *qp, struct ibv_cq *cq,
		    const void *msg, uint32_t lkey, char *buf)
{
	struct ibv_sge sge = { .addr = (uintptr_t)buf, .length = MSG_SIZE, .lkey = lkey };
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	int n;

	memcpy(buf, msg, sizeof(struct atom_msg));
	wr.opcode = IBV_WR_SEND;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad)) {
		fprintf(stderr, "  [dbg] send post_send 失败 errno=%d\n", errno);
		return -1;
	}
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr, "  [dbg] send 完成异常: n=%d status=%d vendor=0x%x\n",
			n, n > 0 ? (int)wc.status : -1, n > 0 ? wc.vendor_err : 0);
		return -1;
	}
	return 0;
}

/* RECV 一条消息 (预 post 后轮询) */
static int recv_msg(struct ibv_qp *qp, struct ibv_cq *cq,
		    uint32_t lkey, char *buf, struct atom_msg *out)
{
	struct ibv_sge sge = { .addr = (uintptr_t)buf, .length = MSG_SIZE, .lkey = lkey };
	struct ibv_recv_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	int n;

	wr.sg_list = &sge;
	wr.num_sge = 1;
	if (ibv_post_recv(qp, &wr, &bad)) {
		fprintf(stderr, "  [dbg] recv post_recv 失败 errno=%d\n", errno);
		return -1;
	}
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr, "  [dbg] recv 完成异常: n=%d status=%d vendor=0x%x\n",
			n, n > 0 ? (int)wc.status : -1, n > 0 ? wc.vendor_err : 0);
		return -1;
	}
	memcpy(out, buf, sizeof(struct atom_msg));
	return 0;
}

/* RDMA Read 4KB: server buf 页 → local */
static long long rdma_read_page(struct ibv_qp *qp, struct ibv_cq *cq,
				void *local, uint32_t lkey,
				uintptr_t remote_addr, uint32_t rkey)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = PAGE_SIZE, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	int n;

	memset(local, 0, PAGE_SIZE);
	wr.opcode = IBV_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = remote_addr;
	wr.wr.rdma.rkey = rkey;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS) {
		fprintf(stderr, "  [dbg] rdma_read 完成异常: n=%d status=%d vendor=0x%x\n",
			n, n > 0 ? (int)wc.status : -1, n > 0 ? wc.vendor_err : 0);
		return -1;
	}
	return *(long long *)local;
}

/* READ_IOVA: 经 IOMMU 读 4 字节 (检查哨兵/真实) — T5 用 RDMA Read 验证,
 * 此函数保留供未来原子+IOMMU 状态联合调试使用 (当前未引用) */
#if 0
static long long read_iova_page(int sym_fd, int mr_id, unsigned long long iova)
{
	struct symrdma_ioc_read_iova rd = { .mr_id = mr_id, .iova = iova };

	if (ioctl(sym_fd, SYMRDMA_IOC_READ_IOVA, &rd))
		return -1;
	return (long long)rd.value;
}
#endif

/* ---- 原子执行 (论文 §3.4: 远端 CPU, lock cmpxchg/xadd) ---- */
static uint64_t do_atomic(uint64_t *target, int op,
			  uint64_t cmp, uint64_t swap, uint32_t *ok)
{
	uint64_t old;

	if (op == ATOM_OP_FAA) {
		/* lock xadd — 返回旧值 (论文 §3.4) */
		old = __atomic_fetch_add(target, swap, __ATOMIC_SEQ_CST);
		*ok = 1;
	} else {
		/* lock cmpxchg — 成功返回旧值; 失败 expected 更新为当前值 */
		uint64_t expected = cmp;
		*ok = __atomic_compare_exchange_n(target, &expected, swap,
						 0, __ATOMIC_SEQ_CST,
						 __ATOMIC_SEQ_CST);
		old = expected;
	}
	return old;
}

static int passed = 0, failed = 0;
#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (errno=%d %s)\n", msg, errno, strerror(errno)); failed++; } \
} while (0)

/* ================= server ================= */
static int run_server(void)
{
	struct conn_params params = {0};
	unsigned char *buf, *ctl_in, *ctl_out;
	struct ibv_mr *buf_mr, *in_mr, *out_mr;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *data_cq, *ctl_cq;
	struct ibv_qp *data_qp, *ctl_qp;
	struct symrdma_ioc_reg_mr reg = {0};
	struct symrdma_ioc_repair rep = {0};
	struct atom_msg req, resp;
	int sym_fd, mr_id, i;
	long long iova0;

	printf("=== Level 10 server (SymRDMA 服务, 论文 §3.4 原子执行端) ===\n");

	sym_fd = open("/dev/symrdma", O_RDWR);
	if (sym_fd < 0) { printf("无法打开 /dev/symrdma\n"); return 1; }

	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) { perror("mmap"); return 1; }
	memset(buf, 0xAB, BUF_SIZE);
	for (i = 0; i < TEST_PAGES; i++)
		buf[i * PAGE_SIZE] = (unsigned char)('A' + i);
	/* 页 0 首 8 字节 = 0xABABABABABABAB41 (FAA 递增的初始值) */
	*(uint64_t *)(buf + 0 * PAGE_SIZE) = 0xABABABABABABAB41ULL;

	reg.va_start = (unsigned long long)buf;
	reg.len = BUF_SIZE;
	if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg)) { printf("REG_MR 失败\n"); return 1; }
	mr_id = reg.mr_id;

	dev = find_rdma_device();
	if (!dev) return 1;
	ctx = ibv_open_device(dev);
	pd = ibv_alloc_pd(ctx);
	data_qp = create_qp(pd, &data_cq, 0);
	ctl_qp  = create_qp(pd, &ctl_cq, 1);
	if (!data_qp || !ctl_qp) return 1;

	ctl_in  = mmap(NULL, MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ctl_out = mmap(NULL, MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	memset(ctl_in, 0, MSG_SIZE);
	memset(ctl_out, 0, MSG_SIZE);
	reg.va_start = (unsigned long long)ctl_in;
	reg.len = MSG_SIZE;
	ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
	reg.va_start = (unsigned long long)ctl_out;
	ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &reg);
	in_mr  = ibv_reg_mr(pd, ctl_in,  MSG_SIZE,
			    IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	out_mr = ibv_reg_mr(pd, ctl_out, MSG_SIZE,
			    IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	buf_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			    IBV_ACCESS_LOCAL_WRITE |
			    IBV_ACCESS_REMOTE_READ |
			    IBV_ACCESS_REMOTE_WRITE |
			    SYMRDMA_ACCESS_IDENTITY);
	if (!buf_mr || !in_mr || !out_mr) return 1;

	params.data_qp_num = data_qp->qp_num;
	params.ctl_qp_num  = ctl_qp->qp_num;
	params.rkey        = buf_mr->rkey;
	params.addr        = (uint64_t)(uintptr_t)buf;
	{
		union ibv_gid g;   /* 本侧 GID 入参数 (跨机 dgid) */

		if (!ibv_query_gid(ctx, 1, g_sgid, &g))
			gid_to_hex(&g, params.gid);
	}
	write_server_params(&params);
	if (wait_client_params(&params)) { printf("等待 client 超时\n"); return 1; }
	if (qp_to_rts(data_qp, params.data_qp_num)) return 1;
	if (qp_to_rts(ctl_qp, params.ctl_qp_num)) return 1;
	printf("QP RTS (data=0x%x ctl=0x%x), buf mr_id=%d\n",
	       params.data_qp_num, params.ctl_qp_num, mr_id);

	iova0 = (long long)(uintptr_t)buf;

	/* 控制循环: FAA/CAS/SWAP/REPAIR/QUIT */
	for (;;) {
		uint64_t *target;

		if (recv_msg(ctl_qp, ctl_cq, in_mr->lkey, (char *)ctl_in, &req))
			return 1;
		if (req.magic != ATOM_MAGIC) { printf("协议 magic 错\n"); return 1; }

		memset(&resp, 0, sizeof(resp));
		resp.magic = ATOM_MAGIC;
		resp.op    = req.op;
		resp.offset = req.offset;

		switch (req.op) {
		case ATOM_OP_FAA:
		case ATOM_OP_CAS:
			target = (uint64_t *)(buf + req.offset);
			resp.old = do_atomic(target, req.op,
					     req.cmp, req.swap, &resp.ok);
			printf("  [log] CPU 原子 %s @+0x%x: old=0x%llx ok=%d\n",
			       req.op == ATOM_OP_FAA ? "FAA" : "CAS",
			       req.offset, (unsigned long long)resp.old, resp.ok);
			break;
		case ATOM_OP_SWAP:
			if (madvise(buf + req.offset, PAGE_SIZE, MADV_PAGEOUT)) {
				printf("  SWAP madvise 失败 errno=%d\n", errno);
				resp.ok = 0;
			} else {
				resp.ok = 1;
				printf("  [log] 换出页 @+0x%x\n", req.offset);
			}
			break;
		case ATOM_OP_REPAIR:
			rep.mr_id = mr_id;
			rep.page_idx = req.offset / PAGE_SIZE;
			resp.ok = ioctl(sym_fd, SYMRDMA_IOC_REPAIR, &rep) == 0;
			printf("  [log] REPAIR 页 %lu → %s\n",
			       rep.page_idx, resp.ok ? "OK" : "FAIL");
			break;
		case ATOM_OP_QUIT:
			printf("  收到 QUIT, 退出\n");
			if (send_msg(ctl_qp, ctl_cq, &resp, out_mr->lkey,
				     (char *)ctl_out))
				return 1;
			goto cleanup;
		default:
			printf("  未知 op %u\n", req.op);
			resp.ok = 0;
			break;
		}

		if (send_msg(ctl_qp, ctl_cq, &resp, out_mr->lkey, (char *)ctl_out))
			return 1;
	}

cleanup:
	ibv_dereg_mr(buf_mr);
	ibv_dereg_mr(in_mr);
	ibv_dereg_mr(out_mr);
	ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, mr_id);
	ibv_destroy_qp(data_qp);
	ibv_destroy_qp(ctl_qp);
	ibv_destroy_cq(data_cq);
	ibv_destroy_cq(ctl_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(ctl_in, MSG_SIZE);
	munmap(ctl_out, MSG_SIZE);
	munmap(buf, BUF_SIZE);
	close(sym_fd);
	(void)iova0;
	return 0;
}

/* ================= client ================= */
static int run_client(void)
{
	struct conn_params sp = {0}, mine = {0};
	unsigned char *ctl_in, *ctl_out, *local;
	struct ibv_mr *in_mr, *out_mr, *local_mr;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *ctl_cq, *data_cq;
	struct ibv_qp *ctl_qp, *data_qp;
	struct atom_msg req, resp;
	int rc = 0;

	printf("=== Level 10 client (纯 RDMA 应用, 原子 RPC 发起端) ===\n");

	/* 参数文件由 test.sh 的 server 后台 + client 前台保证 */
	if (read_server_params(&sp)) { printf("无 server 参数\n"); return 1; }

	dev = find_rdma_device();
	if (!dev) return 1;
	ctx = ibv_open_device(dev);
	pd = ibv_alloc_pd(ctx);
	ctl_qp  = create_qp(pd, &ctl_cq, 1);
	data_qp = create_qp(pd, &data_cq, 0);
	if (!ctl_qp || !data_qp) return 1;

	ctl_in  = mmap(NULL, MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	ctl_out = mmap(NULL, MSG_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	local   = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		       MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	memset(ctl_in, 0, MSG_SIZE);
	memset(ctl_out, 0, MSG_SIZE);
	memset(local, 0, PAGE_SIZE);
	mlock(local, PAGE_SIZE);
	in_mr  = ibv_reg_mr(pd, ctl_in,  MSG_SIZE,
			    IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	out_mr = ibv_reg_mr(pd, ctl_out, MSG_SIZE,
			    IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	local_mr = ibv_reg_mr(pd, local, PAGE_SIZE,
			      IBV_ACCESS_LOCAL_WRITE | SYMRDMA_ACCESS_IDENTITY);
	if (!in_mr || !out_mr || !local_mr) return 1;

	/* 自身 QP 号写入 client 参数 (供 server 回连); dest 用 server 的 (sp) */
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

	/* 原子 RPC 助手: 发请求 → 收响应 */
#define ATOM_RPC(_op, _off, _cmp, _swap) do { \
	memset(&req, 0, sizeof(req)); \
	req.magic = ATOM_MAGIC; req.op = (_op); req.offset = (_off); \
	req.cmp = (_cmp); req.swap = (_swap); \
	if (send_msg(ctl_qp, ctl_cq, &req, out_mr->lkey, (char *)ctl_out)) { rc = 1; goto out; } \
	if (recv_msg(ctl_qp, ctl_cq, in_mr->lkey, (char *)ctl_in, &resp)) { rc = 1; goto out; } \
	if (resp.magic != ATOM_MAGIC || resp.op != (_op)) { printf("响应协议错\n"); rc = 1; goto out; } \
} while (0)

	/* T1: FAA 驻留页 (页 0, 初始 0xABABABABABABAB41) — 连续 3 次 +1 */
	printf("\n--- T1: FAA 驻留页 (论文 §3.4) ---\n");
	ATOM_RPC(ATOM_OP_FAA, 0, 0, 1);
	CHECK(resp.old == 0xABABABABABABAB41ULL, "FAA #1 返回旧值 0x...41");
	ATOM_RPC(ATOM_OP_FAA, 0, 0, 1);
	CHECK(resp.old == 0xABABABABABABAB42ULL, "FAA #2 返回旧值 0x...42");
	ATOM_RPC(ATOM_OP_FAA, 0, 0, 1);
	CHECK(resp.old == 0xABABABABABABAB43ULL, "FAA #3 返回旧值 0x...43");
	{
		unsigned long long v = (unsigned long long)
			rdma_read_page(data_qp, data_cq, local,
				       local_mr->lkey,
				       (uintptr_t)sp.addr, sp.rkey);
		CHECK(v == 0xABABABABABABAB44ULL,
		      "RDMA Read 可见 FAA 结果 0x...44 (驻留直读)");
	}

	/* T2: CAS 成功 (期望 0x...44 → 0x12345678) */
	printf("\n--- T2: CAS 成功 ---\n");
	ATOM_RPC(ATOM_OP_CAS, 0, 0xABABABABABABAB44ULL, 0x12345678);
	CHECK(resp.ok == 1 && resp.old == 0xABABABABABABAB44ULL,
	      "CAS 成功: 返回旧值 0x...44");
	{
		long long v = rdma_read_page(data_qp, data_cq, local,
					     local_mr->lkey,
					     (uintptr_t)sp.addr, sp.rkey);
		CHECK(v == 0x12345678LL, "CAS 后 RDMA Read → 0x12345678");
	}

	/* T3: CAS 失败 (期望错误值 → 不修改, 返回当前值) */
	printf("\n--- T3: CAS 失败 ---\n");
	ATOM_RPC(ATOM_OP_CAS, 0, 0xDEADBEEFULL, 0x99999999);
	CHECK(resp.ok == 0 && resp.old == 0x12345678ULL,
	      "CAS 失败: ok=0, 返回当前值 0x12345678 (数据未改)");
	{
		long long v = rdma_read_page(data_qp, data_cq, local,
					     local_mr->lkey,
					     (uintptr_t)sp.addr, sp.rkey);
		CHECK(v == 0x12345678LL, "CAS 失败后数据不变 (0x12345678)");
	}

	/* T4: 换出页 FAA (论文 §3.4: 非驻留页 CPU 走正常 MMU 路径) */
	printf("\n--- T4: 换出页原子 (CPU 缺页换入) ---\n");
	{
		/* server 换出页 1 (offset = 1*PAGE + 0) */
		ATOM_RPC(ATOM_OP_SWAP, 1 * PAGE_SIZE, 0, 0);
		CHECK(resp.ok == 1, "server 换出页 1");

		/* 页 1 首 8 字节初始 = 0xABABABABABABAB42 (buf 0xAB + 'B') */
		ATOM_RPC(ATOM_OP_FAA, 1 * PAGE_SIZE, 0, 5);
		CHECK(resp.old == 0xABABABABABABAB42ULL,
		      "换出页 FAA 返回旧值 (CPU 缺页换入后执行)");
	}

	/* T5: 惰性语义 — 换出页原子后 IOMMU 仍哨兵, REPAIR 后 RDMA 可见 */
	printf("\n--- T5: 原子后惰性 IOMMU + REPAIR ---\n");
	{
		/* client 先 RDMA Read 页 1 → 应读到哨兵 (IOMMU 未更新, 惰性) */
		unsigned long long v = (unsigned long long)
			rdma_read_page(data_qp, data_cq, local,
				       local_mr->lkey,
				       (uintptr_t)sp.addr + PAGE_SIZE,
				       sp.rkey);
		CHECK(v == SENTINEL_MAGIC64,
		      "RDMA Read 页 1 → 哨兵 0xdeadbeef… (CPU 原子换入不更新 IOMMU, 论文 §4.1 惰性)");

		ATOM_RPC(ATOM_OP_REPAIR, 1 * PAGE_SIZE, 0, 0);
		CHECK(resp.ok == 1, "server REPAIR 页 1");

		v = rdma_read_page(data_qp, data_cq, local, local_mr->lkey,
				   (uintptr_t)sp.addr + PAGE_SIZE,
				   sp.rkey);
		CHECK(v == 0xABABABABABABAB47ULL,
		      "REPAIR 后 RDMA Read → 0x...47 (换出页 FAA+5 结果)");
	}

	/* QUIT */
	ATOM_RPC(ATOM_OP_QUIT, 0, 0, 0);

out:
	printf("\n========================================\n");
	printf("Level 10 结果: %d 通过, %d 失败, %d 总计\n",
	       passed, failed, passed + failed);
	printf("========================================\n");
	ibv_dereg_mr(local_mr);
	ibv_dereg_mr(in_mr);
	ibv_dereg_mr(out_mr);
	ibv_destroy_qp(ctl_qp);
	ibv_destroy_qp(data_qp);
	ibv_destroy_cq(ctl_cq);
	ibv_destroy_cq(data_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(local, PAGE_SIZE);
	munmap(ctl_in, MSG_SIZE);
	munmap(ctl_out, MSG_SIZE);
	return rc;
}

int main(int argc, char **argv)
{
	int is_server = argc > 1 && !strcmp(argv[1], "server");
	const char *g = getenv("SYMRDMA_TEST_GID");

	g_sgid = (g && g[0]) ? atoi(g) : 0;
	if (nc_init(is_server)) {
		fprintf(stderr, "netcoord 初始化失败 (SYMRDMA_TEST_TCP=%s)\n",
			getenv("SYMRDMA_TEST_TCP"));
		return 1;
	}
	if (argc > 1 && !strcmp(argv[1], "server"))
		return run_server();
	if (argc > 1 && !strcmp(argv[1], "client"))
		return run_client();
	fprintf(stderr, "用法: %s [server|client]\n", argv[0]);
	return 1;
}
