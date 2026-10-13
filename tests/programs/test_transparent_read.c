/*
 * test_transparent_read.c — SymRDMA Level 12-B (M2):
 * libnprdma 透明引擎 — 纯 verbs 双进程, 零 SymRDMA 代码, 零 ioctl。
 *
 *   server: mmap buffer + ibv_reg_mr (REMOTE_READ, LD_PRELOAD 自动
 *           ioctl REG_MR + owner 自动导出/服务) + data QP (responder)
 *   client: ibv_reg_mr (LOCAL_WRITE) + data QP, 原生 ibv_post_send
 *           RDMA Read / RDMA Write + ibv_poll_cq
 *
 * 场景 (client 无任何修复代码 — 引擎在 poll_cq 内验证/修复/重放):
 *   1. 基线读 → 真实数据
 *   2. server 换出页 0 → client 裸读 → 哨兵数据被引擎拦截 →
 *      SIR 自动修复 (owner REPAIR) → 重放 → 应用拿到真实数据 ★
 *   3. 再次换出 → client 裸写标记 (signaled) → 黑洞吸收被引擎
 *      辅助回读发现 → SIR 内联 WR 修复 → 应用 WC 成功; 读回 = 标记 ★★
 *   4. 透明原子: IBV_WR_ATOMIC_CAS/FAA → SIR 双端 RPC
 *      (远端 CPU 执行, 换出页缺页换入) → 旧值写回 + 合成 WC ★
 *   5. 透传写 rkey 重写: unsignaled 远端写 (混合 MR) →
 *      write 区域落地 (驻留) / 黑洞吸收 (换出) → 哨兵零污染 ★★
 *
 * 用法: SYMRDMA_PEER=l13 ./test_transparent_read server | client
 *       (test.sh level13; 需 LD_PRELOAD=libnprdma.so)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <infiniband/verbs.h>
#include "netcoord.h"   /* 跨机测试协调 (env SYMRDMA_TEST_TCP) */

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#ifndef IBV_QP_MTU
#define IBV_QP_MTU IBV_QP_PATH_MTU
#endif

#define PAGE_SIZE       4096
#define TEST_PAGES      2
#define BUF3_PAGES      4                       /* 跨页修复测试缓冲 */
#define BUF_SIZE        (TEST_PAGES * PAGE_SIZE)
#define BUF3_SIZE       (BUF3_PAGES * PAGE_SIZE)
#define CQ_DEPTH        16
#define MARKER          0xEEDDEE11u
#define MARKER2         0x1122334455667788ull   /* unsignaled 驻留写 */
#define MARKER3         0x99AABBCCDDEEFF00ull   /* unsignaled 换出写 (应被吸收) */
#define CANARY8         0xABABABABABABABABull   /* buf2 金丝雀 (未污染) */

#define PARAMS_S        "/tmp/symrdma_l13.server"
#define PARAMS_C        "/tmp/symrdma_l13.client"
#define EVT_READY       "/tmp/symrdma_l13.ready"
#define EVT_BASELINE    "/tmp/symrdma_l13.baseline"
#define EVT_SWAPED1     "/tmp/symrdma_l13.swaped1"
#define EVT_WREQ        "/tmp/symrdma_l13.wreq"
#define EVT_SWAPED2     "/tmp/symrdma_l13.swaped2"
#define EVT_AREQ        "/tmp/symrdma_l13.areq"
#define EVT_AREADY      "/tmp/symrdma_l13.aready"
#define EVT_ASWAP_REQ   "/tmp/symrdma_l13.aswap_req"
#define EVT_ASWAPED     "/tmp/symrdma_l13.aswaped"
#define EVT_MREQ        "/tmp/symrdma_l13.mreq"
#define EVT_MSWAPED     "/tmp/symrdma_l13.mswaped"
#define EVT_X1REQ       "/tmp/symrdma_l13.x1req"   /* T1 换页 1 */
#define EVT_X1SWAP      "/tmp/symrdma_l13.x1swap"
#define EVT_X2REQ       "/tmp/symrdma_l13.x2req"   /* T2 换页 0 */
#define EVT_X2SWAP      "/tmp/symrdma_l13.x2swap"
#define EVT_X3REQ       "/tmp/symrdma_l13.x3req"   /* T3 换页 2 */
#define EVT_X3SWAP      "/tmp/symrdma_l13.x3swap"
#define EVT_X5REQ       "/tmp/symrdma_l13.x5req"   /* T5 换全部页 */
#define EVT_X5SWAP      "/tmp/symrdma_l13.x5swap"
#define EVT_F6REQ       "/tmp/symrdma_l13.f6req"   /* T6 换页 0 (读 fail-closed) */
#define EVT_F6SWAP      "/tmp/symrdma_l13.f6swap"
#define EVT_F7REQ       "/tmp/symrdma_l13.f7req"   /* T7 换页 3 (写 fail-closed) */
#define EVT_F7SWAP      "/tmp/symrdma_l13.f7swap"
#define EVT_DONE        "/tmp/symrdma_l13.done"

static int passed, failed;

/* 跨机形态: 对端 GID (params 交换) + 本侧 sgid_index (env
 * SYMRDMA_TEST_GID, 默认 0。
 * g_have_peer_gid=0 (单机文件形态) 时 qp_to_rts 保持原有自环语义。 */
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

#define CHECK(cond, msg) do { \
	if (cond) { printf("  PASS: %s\n", msg); passed++; } \
	else      { printf("  FAIL: %s (errno=%d)\n", msg, errno); failed++; } \
} while (0)

static void evt_set(const char *p)
{
	if (nc_active()) {
		nc_evt_set(p);
		return;
	}
	{
		FILE *f = fopen(p, "w");

		if (f)
			fclose(f);
	}
}
static int evt_wait(const char *p, int sec)
{
	int i;

	if (nc_active())
		return nc_evt_wait(p, sec);
	for (i = 0; i < sec * 10; i++) {
		if (access(p, F_OK) == 0)
			return 0;
		usleep(100000);
	}
	return -1;
}
static void evt_clear(const char *p)
{
	if (nc_active()) {
		nc_evt_clear(p);
		return;
	}
	unlink(p);
}

/* ---- verbs 辅助 (同 test_sir) ---- */

/* 环境适配 (双机测试床 双口卡实测): 机器按 PCI function 枚举出多个 mlx5
 * 设备, 取第一个可能命中 DOWN 口 — QP 建在死口上 GID 全零 (RTR ENODATA)。
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

static struct ibv_device *find_mlx5(void)
{
	struct ibv_device **l;
	struct ibv_device *dev_fallback = NULL;
	int n, i;

	l = ibv_get_device_list(&n);
	if (!l || !n)
		return NULL;
	for (i = 0; i < n; i++)
		if (strstr(ibv_get_device_name(l[i]), "mlx5")) {
			if (mlx5_port_active(ibv_get_device_name(l[i])))
				return l[i];
			if (!dev_fallback)
				dev_fallback = l[i];
		}
	return dev_fallback ? dev_fallback : NULL;
}

static struct ibv_qp *create_qp(struct ibv_pd *pd, struct ibv_cq **cq_out)
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
	a.cap.max_recv_wr  = 1;
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
	 * (L15 教训); 单机自环形态 4096 不变 */
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
		{ int e=errno; printf("  QP RTR 失败 (errno=%d %s)\n", e, strerror(e)); return -1; }
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

/* 一次 RDMA Read (remote → local, len); 0 成功 -1 失败 */
static int rdma_read(struct ibv_qp *qp, struct ibv_cq *cq, void *local,
		     uint32_t lkey, uintptr_t remote, uint32_t rkey,
		     uint32_t len)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = len, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	int n;

	memset(local, 0, len);
	wr.opcode = IBV_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = remote;
	wr.wr.rdma.rkey = rkey;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	return 0;
}

/* 一次 RDMA Write (signaled); 0 成功 -1 失败 */
static int rdma_write(struct ibv_qp *qp, struct ibv_cq *cq, const void *src,
		      uint32_t lkey, uintptr_t remote, uint32_t rkey,
		      uint32_t len)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)src, .length = len, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	int n;

	wr.opcode = IBV_WR_RDMA_WRITE;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = remote;
	wr.wr.rdma.rkey = rkey;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	return 0;
}

/* 一次 IBV 原子 (signaled, 8B; cas=1: CAS[compare_add=compare,swap=swap]
 *  cas=0: FAA[compare_add=addend]); 旧值写入 local, *old_out 返回。
 *   引擎拦截远端原子 → SIR 双端 RPC (应用零修复代码)。 */
static int rdma_atomic(struct ibv_qp *qp, struct ibv_cq *cq, void *local,
		       uint32_t lkey, uintptr_t remote, uint32_t rkey,
		       int cas, uint64_t compare, uint64_t swap_or_add,
		       uint64_t *old_out)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = 8, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	int n;

	memset(local, 0, 8);
	wr.opcode = cas ? IBV_WR_ATOMIC_CMP_AND_SWP :
			  IBV_WR_ATOMIC_FETCH_AND_ADD;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.atomic.remote_addr = remote;
	wr.wr.atomic.compare_add = cas ? compare : swap_or_add;
	wr.wr.atomic.swap        = cas ? swap_or_add : 0;
	wr.wr.atomic.rkey = rkey;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	do { n = ibv_poll_cq(cq, 1, &wc); } while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	if (old_out)
		memcpy(old_out, local, 8);
	return 0;
}

/* 一次 unsignaled RDMA Write (引擎不跟踪 → 透传 + rkey 重写路径);
 * 不等 WC (应用语义: 靠后续 signaled 操作栅栏)。0 成功 -1 失败 */
static int rdma_write_unsignaled(struct ibv_qp *qp, const void *src,
				 uint32_t lkey, uintptr_t remote, uint32_t rkey,
				 uint32_t len)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)src, .length = len, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;

	wr.opcode = IBV_WR_RDMA_WRITE;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = remote;
	wr.wr.rdma.rkey = rkey;
	wr.send_flags = 0;                      /* unsignaled */
	return ibv_post_send(qp, &wr, &bad) ? -1 : 0;
}

/* 一次 signaled RDMA Read, 返回实际收到的首个 WC (供 wr_id 配对断言);
 * 0 成功 -1 失败 */
static int rdma_read_wc(struct ibv_qp *qp, struct ibv_cq *cq, void *local,
			uint32_t lkey, uintptr_t remote, uint32_t rkey,
			uint32_t len, uint64_t wr_id, struct ibv_wc *wc_out)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)local, .length = len, .lkey = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	int n;

	memset(local, 0, len);
	wr.opcode = IBV_WR_RDMA_READ;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = remote;
	wr.wr.rdma.rkey = rkey;
	wr.wr_id = wr_id;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (ibv_post_send(qp, &wr, &bad))
		return -1;
	do { n = ibv_poll_cq(cq, 1, wc_out); } while (n == 0);
	if (n < 0 || wc_out->status != IBV_WC_SUCCESS)
		return -1;
	return 0;
}

/* ---- 连接参数 ---- */
struct conn_params {
	uint32_t qp_num;
	uint32_t rkey, wkey;
	uint64_t addr, len;
	uint32_t mrkey;                 /* 混合 MR rkey (R+RW) */
	uint64_t maddr;                 /* 混合 MR 基址 (2 页 buf2) */
	uint32_t rkey3;                 /* buf3 混合 MR rkey */
	uint64_t addr3;                 /* buf3 基址 (4 页) */
	char     gid[33];   /* 本侧 GID hex (跨机 dgid; 空=单机形态) */
};

static int write_params(const char *p, const struct conn_params *c)
{
	char blob[768];
	int n;

	/* TCP 协调: 同一文本格式经 PARAM 消息交换 */
	if (nc_active()) {
		n = snprintf(blob, sizeof(blob),
			     "qp %u\nrkey %u\nwkey %u\naddr %llu\nlen %llu\n"
			     "mrkey %u\nmaddr %llu\nrkey3 %u\naddr3 %llu\ngid %s\n",
			     c->qp_num, c->rkey, c->wkey,
			     (unsigned long long)c->addr,
			     (unsigned long long)c->len,
			     c->mrkey, (unsigned long long)c->maddr,
			     c->rkey3, (unsigned long long)c->addr3,
			     c->gid[0] ? c->gid : "-");
		return nc_put(p, blob, (size_t)n + 1);
	}
	{
		FILE *f = fopen(p, "w");

		if (!f)
			return -1;
		fprintf(f, "qp %u\nrkey %u\nwkey %u\naddr %llu\nlen %llu\n"
			   "mrkey %u\nmaddr %llu\nrkey3 %u\naddr3 %llu\n",
			   c->qp_num, c->rkey, c->wkey,
			   (unsigned long long)c->addr, (unsigned long long)c->len,
			   c->mrkey, (unsigned long long)c->maddr,
			   c->rkey3, (unsigned long long)c->addr3);
		fclose(f);
	}
	return 0;
}

/* 精确 key 匹配 — sscanf 前缀会误配 ("rkey" 吃掉 "rkey3 2104903"
 * 的 '3' → rkey=3 → 远端 rkey 无效 → QP REMOTE_ACCESS_ERR → 后续全部
 * FLUSH_ERR 级联, 实测教训)。按空白切分 key 后整串比较。 */
static int read_params(const char *p, struct conn_params *c)
{
	FILE *f = NULL;
	char line[256];
	int ok = 0;

	if (nc_active()) {
		char blob[768];
		int n = nc_get(p, blob, sizeof(blob) - 1, 30);

		if (n <= 0)
			return -1;
		blob[n] = 0;
		f = fmemopen(blob, (size_t)n, "r");
		if (!f)
			return -1;
	} else {
		f = fopen(p, "r");
		if (!f)
			return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		char key[32];
		unsigned long long v;

		if (sscanf(line, "%31s %llu", key, &v) != 2 &&
		    strncmp(line, "gid ", 4))
			continue;
		if (!strncmp(line, "gid ", 4)) {
			if (line[4] != '-' &&
			    !gid_from_hex(line + 4, g_peer_gid)) {
				g_have_peer_gid = 1;
				snprintf(c->gid, sizeof(c->gid), "%s", line + 4);
				{
					size_t l = strlen(c->gid);

					while (l && (c->gid[l-1] == '\n' ||
						     c->gid[l-1] == '\r'))
						c->gid[--l] = 0;
				}
			}
			continue;
		}
		if (!strcmp(key, "qp")) {
			c->qp_num = (uint32_t)v; ok++;
		} else if (!strcmp(key, "rkey")) {
			c->rkey = (uint32_t)v; ok++;
		} else if (!strcmp(key, "wkey")) {
			c->wkey = (uint32_t)v; ok++;
		} else if (!strcmp(key, "addr")) {
			c->addr = v; ok++;
		} else if (!strcmp(key, "len")) {
			c->len = v; ok++;
		} else if (!strcmp(key, "mrkey")) {
			c->mrkey = (uint32_t)v; ok++;
		} else if (!strcmp(key, "maddr")) {
			c->maddr = v; ok++;
		} else if (!strcmp(key, "rkey3")) {
			c->rkey3 = (uint32_t)v; ok++;
		} else if (!strcmp(key, "addr3")) {
			c->addr3 = v; ok++;
		}
	}
	fclose(f);
	return ok == 9 ? 0 : -1;
}

/* ================= server (owner; LD_PRELOAD 自动服务) ================= */

static int server_main(void)
{
	struct conn_params sp = {0}, cp = {0};
	unsigned char *buf, *buf2, *buf3;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *data_cq;
	struct ibv_qp *data_qp;
	struct ibv_mr *read_mr, *write_mr, *mixed_mr, *mixed_mr3;
	int i;

	printf("=== Level 12-B server (纯 verbs + LD_PRELOAD, owner 自动服务) ===\n");

	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	memset(buf, 0xAB, BUF_SIZE);
	for (i = 0; i < TEST_PAGES; i++)
		buf[i * PAGE_SIZE] = (unsigned char)('A' + i);

	/* 混合 MR 缓冲 (2 页, 透传写 rkey 重写验证):
	 * 页 0 = 金丝雀 (哨兵污染检测), 页 1 = unsignaled 写目标 */
	buf2 = mmap(NULL, 2 * PAGE_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf2 == MAP_FAILED) {
		perror("mmap buf2");
		return 1;
	}
	memset(buf2, 0xAB, 2 * PAGE_SIZE);

	/* 跨页修复测试缓冲 (4 页, 每页独立填充 0xB0+i) */
	buf3 = mmap(NULL, BUF3_SIZE, PROT_READ | PROT_WRITE,
		    MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf3 == MAP_FAILED) {
		perror("mmap buf3");
		return 1;
	}
	for (i = 0; i < BUF3_PAGES; i++)
		memset(buf3 + i * PAGE_SIZE, 0xB0 + i, PAGE_SIZE);

	dev = find_mlx5();
	if (!dev)
		return 1;
	ctx = ibv_open_device(dev);
	pd = ibv_alloc_pd(ctx);

	/* 数据 MR (REMOTE_READ → 自动导出) + 写 MR (REMOTE_WRITE only →
	 * 合并 write_rkey; 同 VA 二次注册由 libnprdma ioctl 去重) */
	read_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			     IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
	write_mr = ibv_reg_mr(pd, buf, BUF_SIZE,
			      IBV_ACCESS_LOCAL_WRITE |
			      IBV_ACCESS_REMOTE_WRITE);
	/* 混合 MR (REMOTE_READ+REMOTE_WRITE 单 MR): libnprdma 自动注册
	 * 写区域辅助 MR (MTT=VA+32GB) 并导出 write_rkey (论文 §3.1.1) */
	mixed_mr = ibv_reg_mr(pd, buf2, 2 * PAGE_SIZE,
			      IBV_ACCESS_LOCAL_WRITE |
			      IBV_ACCESS_REMOTE_READ |
			      IBV_ACCESS_REMOTE_WRITE);
	/* buf3 混合 MR (引擎自动导出 data_rkey + write_rkey) */
	mixed_mr3 = ibv_reg_mr(pd, buf3, BUF3_SIZE,
			       IBV_ACCESS_LOCAL_WRITE |
			       IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE);
	if (!read_mr || !write_mr || !mixed_mr || !mixed_mr3) {
		printf("  MR 注册失败\n");
		return 1;
	}
	printf("  [log] rkey=0x%x wkey=0x%x mrkey=0x%x mrkey3=0x%x (LD_PRELOAD 自动 IOMMU 注册 + 导出)\n",
	       read_mr->rkey, write_mr->rkey, mixed_mr->rkey, mixed_mr3->rkey);

	data_qp = create_qp(pd, &data_cq);
	if (!data_qp)
		return 1;
	sp.qp_num = data_qp->qp_num;
	sp.rkey = read_mr->rkey;
	sp.wkey = write_mr->rkey;
	sp.addr = (uint64_t)(uintptr_t)buf;
	sp.len = BUF_SIZE;
	sp.mrkey = mixed_mr->rkey;
	sp.maddr = (uint64_t)(uintptr_t)buf2;
	sp.rkey3 = mixed_mr3->rkey;
	sp.addr3 = (uint64_t)(uintptr_t)buf3;
	{
		union ibv_gid g;   /* 本侧 GID 入参数 (跨机 dgid) */

		if (!ibv_query_gid(ctx, 1, g_sgid, &g))
			gid_to_hex(&g, sp.gid);
	}
	write_params(PARAMS_S, &sp);

	for (i = 0; i < 100 && read_params(PARAMS_C, &cp); i++)
		usleep(100000);
	CHECK(cp.qp_num != 0, "取得 client 连接参数");
	if (!cp.qp_num)
		return 1;
	if (qp_to_rts(data_qp, cp.qp_num)) {
		{int e=errno; printf("  data QP RTS 失败 (errno=%d %s)\n", e, strerror(e));}
		return 1;
	}
	evt_set(EVT_READY);

	/* ---- 读方向: 换出页 0 (client 引擎自动修复) ---- */
	printf("\n--- 读方向: 等待 client 基线完成 ---\n");
	CHECK(evt_wait(EVT_BASELINE, 30) == 0, "收到基线完成 (换出请求)");
	evt_clear(EVT_BASELINE);
	if (madvise(buf, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_SWAPED1);
	printf("  [log] 页 0 已换出 (MADV_PAGEOUT)\n");

	/* ---- 写方向: 再次换出 ---- */
	printf("\n--- 写方向: 等待再次换出请求 ---\n");
	CHECK(evt_wait(EVT_WREQ, 30) == 0, "收到写测试换出请求");
	evt_clear(EVT_WREQ);
	if (madvise(buf, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_SWAPED2);
	printf("  [log] 页 0 再次换出\n");

	/* ---- 原子方向: 预备页 1 前 8B (远端 CPU 执行, 论文 §3.4) ---- */
	printf("\n--- 原子方向: 等待预备请求 ---\n");
	CHECK(evt_wait(EVT_AREQ, 30) == 0, "收到原子测试预备请求");
	evt_clear(EVT_AREQ);
	memset(buf + PAGE_SIZE, 0, 8);          /* 页 1 前 8B 清零 (原子目标) */
	evt_set(EVT_AREADY);
	printf("  [log] 页 1 前 8B 清零 (原子目标)\n");

	/* ---- 原子换出: 页 1 换出 (原子将走远端 CPU 缺页换入) ---- */
	printf("\n--- 原子方向: 等待换出请求 ---\n");
	CHECK(evt_wait(EVT_ASWAP_REQ, 30) == 0, "收到原子换出请求");
	evt_clear(EVT_ASWAP_REQ);
	if (madvise(buf + PAGE_SIZE, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_ASWAPED);
	printf("  [log] 页 1 已换出 (MADV_PAGEOUT)\n");

	/* ---- 透传写方向: buf2 两页换出 (rkey 重写 → 黑洞吸收) ---- */
	printf("\n--- 透传写方向: 等待换出请求 ---\n");
	CHECK(evt_wait(EVT_MREQ, 30) == 0, "收到透传写换出请求");
	evt_clear(EVT_MREQ);
	if (madvise(buf2, 2 * PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_MSWAPED);
	printf("  [log] buf2 两页已换出 (MADV_PAGEOUT)\n");

	/* ----  跨页/非对齐/多缺失页修复 (buf3) ---- */
	printf("\n--- T1 跨页读 (页 1 缺失): 等待换出请求 ---\n");
	CHECK(evt_wait(EVT_X1REQ, 30) == 0, "T1 收到换出请求 (页 1)");
	evt_clear(EVT_X1REQ);
	if (madvise(buf3 + PAGE_SIZE, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_X1SWAP);

	printf("\n--- T2 跨页读 (页 0 缺失): 等待换出请求 ---\n");
	CHECK(evt_wait(EVT_X2REQ, 30) == 0, "T2 收到换出请求 (页 0)");
	evt_clear(EVT_X2REQ);
	if (madvise(buf3, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_X2SWAP);

	printf("\n--- T3 跨页写 (页 2 缺失): 等待换出请求 ---\n");
	CHECK(evt_wait(EVT_X3REQ, 30) == 0, "T3 收到换出请求 (页 2)");
	evt_clear(EVT_X3REQ);
	if (madvise(buf3 + 2 * PAGE_SIZE, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_X3SWAP);

	printf("\n--- T5 多缺失页读 (全部页): 等待换出请求 ---\n");
	CHECK(evt_wait(EVT_X5REQ, 30) == 0, "T5 收到换出请求 (全部页)");
	evt_clear(EVT_X5REQ);
	if (madvise(buf3, BUF3_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	{
		/* (同 T6/T7  教训): madvise PAGEOUT 是
		 * best-effort — 刚被 T1-T3 修复 GUP 换入的页在紧凑时序下单次
		 * madvise 可能不回收; 轮询至全部页实际回收 (≤2s), 保证
		 * "全缺失" 前提 (bug 6 repair-all 路径确定性)。超时则维持
		 * 旧行为 (读命中驻留页时断言仍成立, 仅少覆盖 repair-all)。 */
		int r;

		for (r = 0; r < 200; r++) {
			unsigned char vec[BUF3_PAGES];
			int i2, resident = 0;

			if (mincore(buf3, BUF3_SIZE, vec) == 0) {
				for (i2 = 0; i2 < BUF3_PAGES; i2++)
					resident += (vec[i2] & 1);
				if (!resident)
					break;
			}
			madvise(buf3, BUF3_SIZE, MADV_PAGEOUT);
			usleep(10000);
		}
	}
	evt_set(EVT_X5SWAP);

	/* ----  修复耗尽 fail-closed (T6/T7, 故障注入由 client 置位) ---- */
	printf("\n--- T6 读 fail-closed (页 0 缺失 + 修复注入): 等待换出请求 ---\n");
	CHECK(evt_wait(EVT_F6REQ, 30) == 0, "T6 收到换出请求 (页 0)");
	evt_clear(EVT_F6REQ);
	if (madvise(buf3, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	{
		/* madvise PAGEOUT 是 best-effort — 刚被修复 GUP 换入的
		 * 页在紧凑时序下单次 madvise 可能不回收 (TCP 会合形态实测:
		 * mincore 仍驻留 → 读回真实数据 → 注入断言误报)。轮询至实际
		 * 回收 (≤2s)。 */
		int r;

		for (r = 0; r < 200; r++) {
			unsigned char vec = 9;

			if (mincore(buf3, PAGE_SIZE, &vec) == 0 && !(vec & 1))
				break;
			madvise(buf3, PAGE_SIZE, MADV_PAGEOUT);
			usleep(10000);
		}
	}
	evt_set(EVT_F6SWAP);

	printf("\n--- T7 写 fail-closed (页 3 缺失 + 修复注入): 等待换出请求 ---\n");
	CHECK(evt_wait(EVT_F7REQ, 30) == 0, "T7 收到换出请求 (页 3)");
	evt_clear(EVT_F7REQ);
	if (madvise(buf3 + 3 * PAGE_SIZE, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	{
		/* 同 T6 — 轮询至实际回收 (≤2s) */
		int r;

		for (r = 0; r < 200; r++) {
			unsigned char vec = 9;

			if (mincore(buf3 + 3 * PAGE_SIZE, PAGE_SIZE, &vec) == 0 &&
			    !(vec & 1))
				break;
			madvise(buf3 + 3 * PAGE_SIZE, PAGE_SIZE, MADV_PAGEOUT);
			usleep(10000);
		}
	}
	evt_set(EVT_F7SWAP);

	evt_wait(EVT_DONE, 120);
	evt_clear(EVT_DONE);
	/* 读回验证 (server 侧直接 CPU 读 — 修复应已落地) */
	printf("  [log] server 读回页 0 首 4B = 0x%08x (期望 MARKER 0x%08x)\n",
	       *(uint32_t *)buf, MARKER);

	ibv_dereg_mr(read_mr);
	ibv_dereg_mr(write_mr);
	ibv_dereg_mr(mixed_mr);
	ibv_dereg_mr(mixed_mr3);
	ibv_destroy_qp(data_qp);
	ibv_destroy_cq(data_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(buf, BUF_SIZE);
	munmap(buf2, 2 * PAGE_SIZE);
	munmap(buf3, BUF3_SIZE);
	unlink(PARAMS_S);

	printf("\n========================================\n");
	printf("Level 12-B server: %d 通过, %d 失败\n", passed, failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}

/* ============ client (纯 verbs; 引擎在 LD_PRELOAD 内) ============ */

static int client_main(void)
{
	struct conn_params sp = {0}, mine = {0};
	unsigned char *local;
	struct ibv_device *dev;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_cq *data_cq;
	struct ibv_qp *data_qp;
	struct ibv_mr *lmr;
	int i;

	printf("=== Level 12-B client (纯 verbs, 零修复代码, 引擎透明) ===\n");

	for (i = 0; i < 100 && read_params(PARAMS_S, &sp); i++)
		usleep(100000);
	CHECK(i < 100, "取得 server 参数 (rkey/wkey/addr)");
	if (i >= 100)
		return 1;

	dev = find_mlx5();
	if (!dev)
		return 1;
	ctx = ibv_open_device(dev);
	pd = ibv_alloc_pd(ctx);

	data_qp = create_qp(pd, &data_cq);
	if (!data_qp)
		return 1;
	mine.qp_num = data_qp->qp_num;
	{
		union ibv_gid g;   /* 本侧 GID 入参数 (跨机 dgid) */

		if (!ibv_query_gid(ctx, 1, g_sgid, &g))
			gid_to_hex(&g, mine.gid);
	}
	write_params(PARAMS_C, &mine);
	if (qp_to_rts(data_qp, sp.qp_num)) {
		{int e=errno; printf("  data QP RTS 失败 (errno=%d %s)\n", e, strerror(e));}
		return 1;
	}

	local = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (local == MAP_FAILED)
		return 1;
	memset(local, 0, PAGE_SIZE);
	lmr = ibv_reg_mr(pd, local, PAGE_SIZE, IBV_ACCESS_LOCAL_WRITE);
	if (!lmr) {
		printf("  local MR 注册失败\n");
		return 1;
	}

	CHECK(evt_wait(EVT_READY, 30) == 0, "server 就绪");

	/* 1. 基线读 */
	CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
			(uintptr_t)sp.addr, sp.rkey, PAGE_SIZE) == 0,
	      "基线: 裸 RDMA Read 页 0");
	CHECK(*(uint32_t *)local == 0xABABAB41, "基线数据 0xABABAB41");

	/* 2. ★ 读方向: 换出后裸读 → 引擎拦截哨兵 → 自动修复 */
	evt_set(EVT_BASELINE);
	CHECK(evt_wait(EVT_SWAPED1, 30) == 0, "server 已换出页 0");
	evt_clear(EVT_SWAPED1);
	CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
			(uintptr_t)sp.addr, sp.rkey, PAGE_SIZE) == 0,
	      "★ 换出后裸 RDMA Read → 引擎自动修复 (哨兵拦截, 透明)");
	CHECK(*(uint32_t *)local == 0xABABAB41,
	      "★ 引擎修复后数据 = 0xABABAB41 (真实, 哨兵被隐藏)");

	/* 3. ★★ 写方向: 再次换出后裸写标记 → 引擎辅助回读 → 内联 WR 修复 */
	evt_set(EVT_WREQ);
	CHECK(evt_wait(EVT_SWAPED2, 30) == 0, "server 再次换出页 0");
	evt_clear(EVT_SWAPED2);
	*(uint32_t *)local = MARKER;
	CHECK(rdma_write(data_qp, data_cq, local, lmr->lkey,
			 (uintptr_t)sp.addr, sp.wkey, 4) == 0,
	      "★ 换出后裸 RDMA Write 标记 → 引擎自动写修复 (WC 成功)");
	CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
			(uintptr_t)sp.addr, sp.rkey, PAGE_SIZE) == 0 &&
	      *(uint32_t *)local == MARKER,
	      "★★ 修复后读回 = MARKER (写数据经引擎修复落地真实页)");

	/* 4. 邻居页不受影响 */
	CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
			(uintptr_t)sp.addr + PAGE_SIZE, sp.rkey,
			PAGE_SIZE) == 0 &&
	      *(uint32_t *)local == 0xABABAB42,
	      "邻居页 1 数据完好 (0xABABAB42)");

	/* ----  透明原子 (IBV_WR_ATOMIC_* → SIR 双端 RPC) ---- */
	{
		uint64_t old = 0, want = 0xAABBCCDD11223344ull;

		/* 5. ★ CAS (compare=0 → swap): 远端 CPU 执行 */
		evt_set(EVT_AREQ);
		CHECK(evt_wait(EVT_AREADY, 30) == 0, "server 原子目标已清零");
		evt_clear(EVT_AREADY);
		CHECK(rdma_atomic(data_qp, data_cq, local, lmr->lkey,
				  (uintptr_t)sp.addr + PAGE_SIZE, sp.rkey,
				  1, 0, want, &old) == 0,
			      "★ 远端原子 CAS WC 成功 (SIR RPC, 零修复代码)");
		CHECK(old == 0, "★ CAS 旧值 = 0");
		CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
				(uintptr_t)sp.addr + PAGE_SIZE, sp.rkey, 8) == 0 &&
		      *(uint64_t *)local == want,
		      "★ CAS 落地读回 = 0xAABBCCDD11223344");

		/* 6. FAA (+1) */
		CHECK(rdma_atomic(data_qp, data_cq, local, lmr->lkey,
				  (uintptr_t)sp.addr + PAGE_SIZE, sp.rkey,
				  0, 0, 1, &old) == 0,
			      "★ 远端原子 FAA (+1) WC 成功");
		CHECK(old == want, "★ FAA 旧值 = swap 值");
		CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
				(uintptr_t)sp.addr + PAGE_SIZE, sp.rkey, 8) == 0 &&
		      *(uint64_t *)local == want + 1,
		      "★ FAA 落地读回 = +1");

		/* 7. CAS miss (compare=0 ≠ 当前值): 旧值返回, 目标不变 */
		CHECK(rdma_atomic(data_qp, data_cq, local, lmr->lkey,
				  (uintptr_t)sp.addr + PAGE_SIZE, sp.rkey,
				  1, 0, 0, &old) == 0,
			      "★ 远端原子 CAS-miss WC 成功");
		CHECK(old == want + 1, "★ CAS-miss 旧值 = 当前值");
		CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
				(uintptr_t)sp.addr + PAGE_SIZE, sp.rkey, 8) == 0 &&
		      *(uint64_t *)local == want + 1,
		      "★ CAS-miss 不落地 (值不变)");

		/* 8. ★★ 换出页上的原子: 远端 CPU 缺页换入执行 + REPAIR */
		evt_set(EVT_ASWAP_REQ);
		CHECK(evt_wait(EVT_ASWAPED, 30) == 0, "server 已换出页 1");
		evt_clear(EVT_ASWAPED);
		CHECK(rdma_atomic(data_qp, data_cq, local, lmr->lkey,
				  (uintptr_t)sp.addr + PAGE_SIZE, sp.rkey,
				  0, 0, 0x100, &old) == 0,
			      "★★ 换出页 FAA (+0x100) → 远端 CPU 缺页换入执行");
		CHECK(old == want + 1, "★★ 换出页 FAA 旧值正确");
		CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
				(uintptr_t)sp.addr + PAGE_SIZE, sp.rkey, 8) == 0 &&
		      *(uint64_t *)local == want + 1 + 0x100,
		      "★★ 换出页原子落地读回 (+0x100)");
	}

	/* ----  透传写 rkey 重写 (unsignaled 远端写, 混合 MR) ---- */
	{
		uint64_t *src1 = (uint64_t *)(local + 64);   /* 源在 local MR 内 */
		uint64_t *src2 = (uint64_t *)(local + 128);

		*src1 = MARKER2;
		*src2 = MARKER3;

		/* 9. 驻留页 unsignaled 写: 重写 write_rkey → write_iova 落地真实页 */
		CHECK(rdma_write_unsignaled(data_qp, src1, lmr->lkey,
					    (uintptr_t)sp.maddr + PAGE_SIZE,
					    sp.mrkey, 8) == 0,
			      "unsignaled 远端写 (驻留) post_send 成功");
		/* signaled 读栅栏 (QP 序: 读到的是写后值) */
		CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
				(uintptr_t)sp.maddr + PAGE_SIZE, sp.mrkey,
				8) == 0 &&
		      *(uint64_t *)local == MARKER2,
		      "★ unsignaled 驻留写经 write 区域落地 (读回 = MARKER2)");

		/* 10. buf2 两页换出 → unsignaled 写被黑洞吸收, 哨兵零污染 */
		evt_set(EVT_MREQ);
		CHECK(evt_wait(EVT_MSWAPED, 30) == 0, "server 已换出 buf2 两页");
		evt_clear(EVT_MSWAPED);
		CHECK(rdma_write_unsignaled(data_qp, src2, lmr->lkey,
					    (uintptr_t)sp.maddr + PAGE_SIZE,
					    sp.mrkey, 8) == 0,
			      "换出页 unsignaled 远端写 post_send 成功 (黑洞吸收)");
		/* 金丝雀: 读页 0 — 若污染则返回 MARKER3 而非魔数 (修复读回真实数据) */
		CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
				(uintptr_t)sp.maddr, sp.mrkey, 8) == 0 &&
		      *(uint64_t *)local == CANARY8,
		      "★★ 金丝雀页未污染 (哨兵仍魔数, 引擎修复读回 0xAB)");
		/* 写目标页: 吸收 = MARKER3 未落地; 步骤 9 的 MARKER2 随页换出/
		 * 换入持久化 — 读回 MARKER2 同时证明吸收与数据不丢 */
		CHECK(rdma_read(data_qp, data_cq, local, lmr->lkey,
				(uintptr_t)sp.maddr + PAGE_SIZE, sp.mrkey,
				8) == 0 &&
		      *(uint64_t *)local == MARKER2,
		      "★★ 换出页 unsignaled 写被吸收 (MARKER3 未落地, 读回仍 MARKER2)");
	}

	/* ----  跨页/非对齐修复 + unsignaled 读 CQE 语义 (buf3) ---- */
	{
		unsigned char *local2;
		struct ibv_mr *lmr2;

		local2 = mmap(NULL, BUF3_SIZE, PROT_READ | PROT_WRITE,
			      MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
		if (local2 == MAP_FAILED)
			return 1;
		memset(local2, 0, BUF3_SIZE);
		lmr2 = ibv_reg_mr(pd, local2, BUF3_SIZE, IBV_ACCESS_LOCAL_WRITE);
		if (!lmr2) {
			printf("  local2 MR 注册失败\n");
			return 1;
		}

		/* T1 (bug 2): 非对齐跨页读 [页0+3840, +512) */
		evt_set(EVT_X1REQ);
		CHECK(evt_wait(EVT_X1SWAP, 30) == 0, "T1: server 已换出页 1");
		evt_clear(EVT_X1SWAP);
		CHECK(rdma_read(data_qp, data_cq, local2, lmr2->lkey,
				sp.addr3 + 3840, sp.rkey3, 512) == 0,
			      "T1: 跨页读 post 成功 (头驻留页 0 + 尾缺失页 1)");
		CHECK(local2[0] == 0xB0 && local2[255] == 0xB0,
			      "T1: 头段 [0,256) = 页 0 填充 0xB0 (DMA 直写保留)");
		CHECK(local2[256] == 0xB1 && local2[511] == 0xB1,
			      "T1: 尾段 [256,512) = 页 1 填充 0xB1 (内联回取对齐)");

		/* T2 (bug 1): 跨页读 [页0+3585, +1024) — 内联不可行 → repair-all */
		evt_set(EVT_X2REQ);
		CHECK(evt_wait(EVT_X2SWAP, 30) == 0, "T2: server 已换出页 0");
		evt_clear(EVT_X2SWAP);
		CHECK(rdma_read(data_qp, data_cq, local2, lmr2->lkey,
				sp.addr3 + 3585, sp.rkey3, 1024) == 0,
			      "T2: 跨页读 post 成功 (页 0 缺失, 内联不可行)");
		printf("  [dbg] T2 head=[%d %d %d %d] tail=[%d %d]\n",
		       local2[0], local2[1], local2[2], local2[3],
		       local2[511], local2[1023]);
		CHECK(local2[0] == 0xB0 && local2[510] == 0xB0,
			      "T2: 头段 [0,511) = 页 0 填充 0xB0 (修复重放取回, 非哨兵)");
		CHECK(local2[511] == 0xB1 && local2[1023] == 0xB1,
			      "T2: 尾段 [511,1024) = 页 1 填充 0xB1");

		/* T3 (bug 3): 跨页写 [7168, 9216) (页 1 尾 1KB + 页 2 头 1KB;
		 *  修正: 旧区间 [4096,6144) 完全落在驻留页 1 内未跨页,
		 * bug 3 场景从未被覆盖) — 页 1 尾驻留落地 + 页 2 头缺失黑洞吸收 →
		 * 写验证扫描回读定位**真实缺失页** (页 2; 旧: 恒首页 → 静默
		 * 部分写丢失, 复现签名 = 读回页 2 头 0xB2 原始填充) →
		 * len>1KB 走 repair-all + 重放落地 */
		evt_set(EVT_X3REQ);
		CHECK(evt_wait(EVT_X3SWAP, 30) == 0, "T3: server 已换出页 2");
		evt_clear(EVT_X3SWAP);
		memset(local2, 0x5A, 2048);
		CHECK(rdma_write(data_qp, data_cq, local2, lmr2->lkey,
					 sp.addr3 + 2 * PAGE_SIZE - 1024, sp.rkey3,
					 2048) == 0,
			      "T3: 跨页写 post 成功 (页 1 尾驻留 + 页 2 缺失)");
		CHECK(rdma_read(data_qp, data_cq, local2, lmr2->lkey,
				sp.addr3 + 2 * PAGE_SIZE - 1024, sp.rkey3,
				2048) == 0 &&
			      local2[0] == 0x5A && local2[1023] == 0x5A &&
			      local2[1024] == 0x5A && local2[2047] == 0x5A,
			      "T3: 页 1 尾+页 2 头全部落地 (写验证定位真实缺失页 = 页 2)");

		/* T4 (bug 5): unsignaled 远端读 — 引擎强制 signaled 验证,
		 * CQE 必须吞掉 (旧: 泄漏一个 CQE → 完成计数错位/wr_id 顶替)。 */
		{
			struct ibv_sge sge = {
				.addr = (uintptr_t)local2, .length = 8,
				.lkey = lmr2->lkey,
			};
			struct ibv_send_wr wr = {0}, *bad = NULL;
			struct ibv_wc wc;
			int n;

			wr.opcode = IBV_WR_RDMA_READ;
			wr.sg_list = &sge;
			wr.num_sge = 1;
			wr.wr.rdma.remote_addr = sp.addr3;
			wr.wr.rdma.rkey = sp.rkey3;
			wr.wr_id = 0xDEAD0001;
			wr.send_flags = 0;               /* unsignaled */
			CHECK(ibv_post_send(data_qp, &wr, &bad) == 0,
				      "T4: unsignaled 远端读 post 成功");
			n = ibv_poll_cq(data_cq, 1, &wc);
			CHECK(n == 0,
				      "T4: unsignaled 读零 CQE (引擎吞掉验证用强制完成)");
			wr.wr_id = 0x51D00002;
			wr.send_flags = IBV_SEND_SIGNALED;
			CHECK(rdma_read_wc(data_qp, data_cq, local2, lmr2->lkey,
						   sp.addr3, sp.rkey3, 8,
						   0x51D00002, &wc) == 0,
				      "T4: 后续 signaled 读完成成功");
			CHECK(wc.wr_id == 0x51D00002,
				      "T4: signaled 完成 wr_id 正确配对 (无顶替)");
		}

		/* T5 (bug 6): 全缺失多页读 — repair-all 单轮收敛 (旧: 3 次上限
		 * 截断)。期望内容 (随 T3 区间修正): 页 0=0xB0,
		 * 页 1=0xB1 但尾 1KB [7168,8192)=0x5A (T3), 页 2=0xB2 但头 1KB
		 * [8192,9216)=0x5A (T3), 页 3=0xB3。 */
		evt_set(EVT_X5REQ);
		CHECK(evt_wait(EVT_X5SWAP, 30) == 0, "T5: server 已换出全部页");
		evt_clear(EVT_X5SWAP);
		CHECK(rdma_read(data_qp, data_cq, local2, lmr2->lkey,
				sp.addr3, sp.rkey3, BUF3_SIZE) == 0,
			      "T5: 全缺失读 post 成功");
		printf("  [dbg] T5 p0=[%d %d] p1=[%d %d] T3=[%d %d] p2=[%d %d] p3=[%d %d]\n",
		       local2[0], local2[4095], local2[4096], local2[7167],
		       local2[7168], local2[9215], local2[9216], local2[12287],
		       local2[12288], local2[16383]);
		CHECK(local2[0] == 0xB0 && local2[4095] == 0xB0 &&
			      local2[4096] == 0xB1 && local2[7167] == 0xB1 &&
			      local2[7168] == 0x5A && local2[8191] == 0x5A &&
			      local2[8192] == 0x5A && local2[9215] == 0x5A &&
			      local2[9216] == 0xB2 && local2[12287] == 0xB2 &&
			      local2[12288] == 0xB3 && local2[16383] == 0xB3,
			      "T5: 各页内容全部正确 (repair-all 单轮收敛; [7168,9216)=0x5A 为 T3 写覆盖)");

		/* ----  T6/T7 修复耗尽 fail-closed ----
		 * 故障注入 (NPRDMA_FAULT_REPAIR_FAIL=1) 使所有 SIR 修复失败:
		 * 旧引擎在哨兵缓冲态以 SUCCESS 交付 (读: 哨兵魔数当数据;
		 * 写: WC SUCCESS 而数据被黑洞吸收静默丢失) — 新语义: 错误 WC。 */
		{
			struct ibv_sge sge;
			struct ibv_send_wr wr = {0}, *bad = NULL;
			struct ibv_wc wc;
			int n;

			/* T6: 换出页读 + 修复注入 → 错误 WC (不再 SUCCESS 交付哨兵) */
			setenv("NPRDMA_FAULT_REPAIR_FAIL", "1", 1);
			evt_set(EVT_F6REQ);
			CHECK(evt_wait(EVT_F6SWAP, 30) == 0,
				      "T6: server 已换出页 0 (修复注入已置位)");
			evt_clear(EVT_F6SWAP);
			memset(&sge, 0, sizeof(sge));
			sge.addr = (uintptr_t)local2;
			sge.length = 8;
			sge.lkey = lmr2->lkey;
			wr.opcode = IBV_WR_RDMA_READ;
			wr.sg_list = &sge;
			wr.num_sge = 1;
			wr.wr.rdma.remote_addr = sp.addr3;
			wr.wr.rdma.rkey = sp.rkey3;
			wr.wr_id = 0x51D00006;
			wr.send_flags = IBV_SEND_SIGNALED;
			CHECK(ibv_post_send(data_qp, &wr, &bad) == 0,
				      "T6: 换出页读 post 成功 (修复全部被注入拒绝)");
			do { n = ibv_poll_cq(data_cq, 1, &wc); } while (n == 0);
			printf("  [dbg] T6 wc.status=%d data=%02x%02x%02x%02x%02x%02x%02x%02x\n",
			       (int)wc.status, local2[0], local2[1], local2[2],
			       local2[3], local2[4], local2[5], local2[6],
			       local2[7]);
			CHECK(n > 0 && wc.status != IBV_WC_SUCCESS,
				      "★★ T6: 修复耗尽 → 错误 WC (fail-closed, 不以 SUCCESS 交付哨兵)");
			CHECK(wc.wr_id == 0x51D00006,
				      "T6: 错误 WC wr_id 正确配对 (0x51D00006)");

			/* 恢复: 注入关闭 → 引擎正常修复 → 真实数据 */
			setenv("NPRDMA_FAULT_REPAIR_FAIL", "0", 1);
			CHECK(rdma_read(data_qp, data_cq, local2, lmr2->lkey,
						sp.addr3, sp.rkey3, 8) == 0 &&
				      local2[0] == 0xB0,
				      "T6: 注入关闭后恢复读 = 0xB0 (引擎正常修复)");

			/* T7: 换出页写 + 修复注入 → 错误 WC (不再静默丢写) */
			setenv("NPRDMA_FAULT_REPAIR_FAIL", "1", 1);
			evt_set(EVT_F7REQ);
			CHECK(evt_wait(EVT_F7SWAP, 30) == 0,
				      "T7: server 已换出页 3");
			evt_clear(EVT_F7SWAP);
			memset(local2, 0x77, 8);
			memset(&sge, 0, sizeof(sge));
			sge.addr = (uintptr_t)local2;
			sge.length = 8;
			sge.lkey = lmr2->lkey;
			memset(&wr, 0, sizeof(wr));
			wr.opcode = IBV_WR_RDMA_WRITE;
			wr.sg_list = &sge;
			wr.num_sge = 1;
			wr.wr.rdma.remote_addr = sp.addr3 + 3 * PAGE_SIZE;
			wr.wr.rdma.rkey = sp.rkey3;
			wr.wr_id = 0x51D00007;
			wr.send_flags = IBV_SEND_SIGNALED;
			CHECK(ibv_post_send(data_qp, &wr, &bad) == 0,
				      "T7: 换出页写 post 成功 (黑洞吸收 + 修复注入)");
			do { n = ibv_poll_cq(data_cq, 1, &wc); } while (n == 0);
			CHECK(n > 0 && wc.status != IBV_WC_SUCCESS,
				      "★★ T7: 写修复耗尽 → 错误 WC (fail-closed, 不静默丢写)");

			/* 恢复: 注入关闭 → 重写落地 → 读回验证 */
			setenv("NPRDMA_FAULT_REPAIR_FAIL", "0", 1);
			memset(local2, 0x77, 8);
			CHECK(rdma_write(data_qp, data_cq, local2, lmr2->lkey,
						 sp.addr3 + 3 * PAGE_SIZE,
						 sp.rkey3, 8) == 0,
				      "T7: 注入关闭后重写落地 (WC 成功)");
			CHECK(rdma_read(data_qp, data_cq, local2, lmr2->lkey,
						sp.addr3 + 3 * PAGE_SIZE,
						sp.rkey3, 8) == 0 &&
				      local2[0] == 0x77,
				      "T7: 重写后读回 = 0x77 (数据真实落地)");
		}

		ibv_dereg_mr(lmr2);
		munmap(local2, BUF3_SIZE);
	}

	evt_set(EVT_DONE);
	ibv_dereg_mr(lmr);
	ibv_destroy_qp(data_qp);
	ibv_destroy_cq(data_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ctx);
	munmap(local, PAGE_SIZE);
	unlink(PARAMS_C);

	printf("\n========================================\n");
	printf("Level 12-B client: %d 通过, %d 失败\n", passed, failed);
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
