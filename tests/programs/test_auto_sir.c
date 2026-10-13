/*
 * test_auto_sir.c — SymRDMA Level 12-A: 库内建自动双向修复 
 *
 * 双进程经 PHY loopback (同 L7), 但 SIR 全部在库内:
 *   - server (owner): libsymrdma 注册 MR + sir_export_add → 库自动建
 *     控制通道/服务线程 (owner 侧 ioctl REPAIR);
 *   - client       : 导入远端 MR 视图 (symrdma_mr_import_remote) →
 *                     普通 symrdma_read/symrdma_write 透明自动修复
 *                     (零 SIR / 零 ioctl 代码)。
 *
 * 场景:
 *   1. 基线读 → 真实数据
 *   2. server 换出页 0 → client symrdma_read → 内部哨兵 → 库内 SIR
 *      (owner REPAIR) → 重放 → 真实数据                ★ 读方向自动修复
 *   3. 再次换出 → client symrdma_write 标记 → 黑洞吸收 → 库内
 *      内联 WR 修复 (≤1KB) → owner REPAIR + 落地 → 读回 = 标记
 *                                                        ★ 写方向自动修复
 * 断言: 数据正确 + server 库内服务计数 (sir_service_count) ≥2。
 *
 * 用法: SYMRDMA_PEER=l12 ./test_auto_sir server | client (test.sh level12)
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
#include "libsymrdma.h"
#include "sir.h"
#include "netcoord.h"   /* 跨机测试协调 (env SYMRDMA_TEST_TCP) */

#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif

/* OFED 用 IBV_QP_MTU, rdma-core 用 IBV_QP_PATH_MTU (同 test_sir) */
#ifndef IBV_QP_MTU
#define IBV_QP_MTU IBV_QP_PATH_MTU
#endif

#define PAGE_SIZE       4096
#define TEST_PAGES      2
#define BUF_SIZE        (TEST_PAGES * PAGE_SIZE)
#define CQ_DEPTH        16
#define MARKER          0xEEDDEE11u

#define PARAMS_S        "/tmp/symrdma_l12.server"
#define PARAMS_C        "/tmp/symrdma_l12.client"
#define EVT_READY       "/tmp/symrdma_l12.ready"    /* S→C: 通道+QP 就绪 */
#define EVT_BASELINE    "/tmp/symrdma_l12.baseline" /* C→S: 基线完成, 请换出 */
#define EVT_SWAPED1     "/tmp/symrdma_l12.swaped1"  /* S→C: 页0 已换出 */
#define EVT_WREQ        "/tmp/symrdma_l12.wreq"     /* C→S: 请再次换出 */
#define EVT_SWAPED2     "/tmp/symrdma_l12.swaped2"  /* S→C: 再次换出 */
#define EVT_RSREQ       "/tmp/symrdma_l12.rsreq"    /* C→S: 2b 请求 (换出+注入) */
#define EVT_RSSWAPED    "/tmp/symrdma_l12.rsswaped" /* S→C: 2b 已换出+注入武装 */
#define EVT_DONE        "/tmp/symrdma_l12.done"     /* C→S: 完成 */

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

/* ---- 连接参数 ---- */
struct conn_params {
	uint32_t qp_num;
	uint32_t rkey, wkey;
	uint64_t addr, len;
	uint32_t v_rkey;
	uint64_t v_addr;
	char     gid[33];   /* 本侧 GID hex (跨机 dgid; 空串=单机形态) */
};

static int write_params(const char *p, const struct conn_params *c)
{
	char blob[512];
	int n;

	/* TCP 协调: 同一文本格式经 PARAM 消息交换 */
	if (nc_active())
		goto tcp;
	{
		FILE *f = fopen(p, "w");

		if (!f)
			return -1;
		fprintf(f, "qp %u\nrkey %u\nwkey %u\naddr %llu\nlen %llu\nvkey %u\nvaddr %llu\n",
			c->qp_num, c->rkey, c->wkey,
			(unsigned long long)c->addr, (unsigned long long)c->len,
			c->v_rkey, (unsigned long long)c->v_addr);
		fclose(f);
		return 0;
	}
tcp:
	n = snprintf(blob, sizeof(blob),
		     "qp %u\nrkey %u\nwkey %u\naddr %llu\nlen %llu\nvkey %u\nvaddr %llu\ngid %s\n",
		     c->qp_num, c->rkey, c->wkey,
		     (unsigned long long)c->addr, (unsigned long long)c->len,
		     c->v_rkey, (unsigned long long)c->v_addr,
		     c->gid[0] ? c->gid : "-");
	return nc_put(p, blob, (size_t)n + 1);
}

static int read_params(const char *p, struct conn_params *c)
{
	char line[256];
	int ok = 0;
	FILE *f = NULL;

	if (nc_active()) {
		char blob[512];
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
		unsigned long long v;
		if (sscanf(line, "qp %llu", &v) == 1) {
			c->qp_num = (uint32_t)v;
			ok++;
		} else if (sscanf(line, "rkey %llu", &v) == 1) {
			c->rkey = (uint32_t)v;
			ok++;
		} else if (sscanf(line, "wkey %llu", &v) == 1) {
			c->wkey = (uint32_t)v;
			ok++;
		} else if (sscanf(line, "addr %llu", &v) == 1) {
			c->addr = v;
			ok++;
		} else if (sscanf(line, "len %llu", &v) == 1) {
			c->len = v;
			ok++;
		} else if (sscanf(line, "vkey %llu", &v) == 1) {
			c->v_rkey = (uint32_t)v;
			ok++;
		} else if (sscanf(line, "vaddr %llu", &v) == 1) {
			c->v_addr = v;
			ok++;
		} else if (!strncmp(line, "gid ", 4)) {
			if (line[4] != '-' && !gid_from_hex(line + 4, g_peer_gid)) {
				g_have_peer_gid = 1;
				snprintf(c->gid, sizeof(c->gid), "%s", line + 4);
				{
					size_t l = strlen(c->gid);

					while (l && (c->gid[l-1] == '\n' ||
						     c->gid[l-1] == '\r'))
						c->gid[--l] = 0;
				}
			}
		}
	}
	fclose(f);
	return ok == 7 ? 0 : -1;
}

/* ================= server (owner) ================= */

static int server_main(void)
{
	struct conn_params sp = {0}, cp = {0};
	struct symrdma_ctx ctx;
	struct symrdma_mr smr;
	struct symrdma_mr_write wmr;
	unsigned char *buf;
	struct ibv_device *dev;
	struct ibv_context *ictx;
	struct ibv_pd *pd;
	struct ibv_cq *data_cq;
	struct ibv_qp *data_qp;
	struct sir_export exp = {0};
	int i, t;

	printf("=== Level 12-A server (owner, SIR 库内建) ===\n");

	if (symrdma_open(&ctx)) {
		printf("  /dev/symrdma 打开失败\n");
		return 1;
	}
	buf = mmap(NULL, BUF_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	memset(buf, 0xAB, BUF_SIZE);
	for (i = 0; i < TEST_PAGES; i++)
		buf[i * PAGE_SIZE] = (unsigned char)('A' + i);

	dev = find_mlx5();
	if (!dev)
		return 1;
	ictx = ibv_open_device(dev);
	pd = ibv_alloc_pd(ictx);

	/* libsymrdma 注册: ioctl 双 IOVA + 自动 Version MR 绑定 */
	if (symrdma_mr_register(&ctx, pd, buf, BUF_SIZE, &smr)) {
		printf("  symrdma_mr_register 失败\n");
		return 1;
	}
	if (symrdma_write_mr_register(pd, buf, BUF_SIZE, &wmr)) {
		printf("  write MR 注册失败\n");
		return 1;
	}

	/* SIR owner 服务: 导出 MR (库自动建通道/服务线程) */
	exp.data_rkey  = smr.ibv_mr->rkey;
	exp.write_rkey = wmr.ibv_mr->rkey;
	exp.addr  = (uint64_t)(uintptr_t)buf;
	exp.len   = BUF_SIZE;
	exp.mr_id = smr.mr_id;
	if (smr.version_mr) {
		exp.v_rkey = smr.version_mr->rkey;
		exp.v_addr = (uint64_t)(uintptr_t)smr.version_buf;
	}
	CHECK(sir_init(ictx, pd, "l12", ctx.fd) == 0, "sir_init (会合键 l12)");
	CHECK(sir_export_add(&exp) == 0,
	      "sir_export_add — owner 服务自动就绪");

	data_qp = create_qp(pd, &data_cq);
	if (!data_qp)
		return 1;
	sp.qp_num = data_qp->qp_num;
	sp.rkey = smr.ibv_mr->rkey;
	sp.wkey = wmr.ibv_mr->rkey;
	sp.addr = (uint64_t)(uintptr_t)buf;
	sp.len = BUF_SIZE;
	sp.v_rkey = exp.v_rkey;
	sp.v_addr = exp.v_addr;
	{
		union ibv_gid g;   /* 本侧 GID 入参数 (跨机 dgid) */

		if (!ibv_query_gid(ictx, 1, g_sgid, &g))
			gid_to_hex(&g, sp.gid);
	}
	write_params(PARAMS_S, &sp);

	for (t = 0; t < 100 && read_params(PARAMS_C, &cp); t++)
		usleep(100000);
	CHECK(cp.qp_num != 0, "取得 client 连接参数");
	if (!cp.qp_num)
		return 1;
	if (qp_to_rts(data_qp, cp.qp_num)) {
		{int e=errno; printf("  data QP RTS 失败 (errno=%d %s)\n", e, strerror(e));}
		return 1;
	}
	/* 等 SIR 通道自动建立 (库内会合握手, 双向) */
	for (t = 0; t < 150 && !sir_is_connected(); t++)
		usleep(100000);
	CHECK(sir_is_connected(), "SIR 通道自动建立 (库内会合握手)");

	evt_set(EVT_READY);

	/* ---- 读方向: 换出页 0, 服务 client 的自动读修复 ---- */
	printf("\n--- 读方向: 等待 client 基线完成 ---\n");
	CHECK(evt_wait(EVT_BASELINE, 30) == 0, "收到基线完成 (换出请求)");
	evt_clear(EVT_BASELINE);
	if (madvise(buf, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_SWAPED1);
	printf("  [log] 页 0 已换出 (MADV_PAGEOUT)\n");
	for (t = 0; t < 100 && sir_service_count() < 1; t++)
		usleep(100000);
	CHECK(sir_service_count() >= 1,
	      "库内服务: 已应答远端读修复 (owner ioctl REPAIR)");

	/* ---- 2b: P1-1 回归注入 — 修复→重放窗口二次换出  ----
	 * client 4KB 读 (>1KB 非内联分支): 首次修复应答后 owner 把该页
	 * REMAP→SENTINEL (确定性复现二次换出竞态) → 旧 libsymrdma 以
	 * SUCCESS 交付哨兵魔数; 新代码版本奇偶判定 + 重试收敛。 */
	printf("\n--- 2b: 等待二次换出注入请求 (P1-1 回归) ---\n");
	CHECK(evt_wait(EVT_RSREQ, 30) == 0, "收到 2b 注入请求");
	evt_clear(EVT_RSREQ);
	setenv("SYMRDMA_SIR_FAULT_RESENTINEL", "1", 1);
	if (madvise(buf, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_RSSWAPED);
	printf("  [log] 页 0 已换出 + RESENTINEL 注入武装\n");
	for (t = 0; t < 200 && sir_service_count() < 3; t++)
		usleep(100000);
	CHECK(sir_service_count() >= 3,
	      "2b 库内服务: 注入轮 + 收敛轮共 2 次读修复");

	/* ---- 写方向: 再次换出, 服务 client 的自动写修复 ---- */
	printf("\n--- 写方向: 等待再次换出请求 ---\n");
	CHECK(evt_wait(EVT_WREQ, 30) == 0, "收到写测试换出请求");
	evt_clear(EVT_WREQ);
	if (madvise(buf, PAGE_SIZE, MADV_PAGEOUT))
		printf("  madvise 失败 errno=%d\n", errno);
	evt_set(EVT_SWAPED2);
	printf("  [log] 页 0 再次换出\n");
	for (t = 0; t < 100 && sir_service_count() < 2; t++)
		usleep(100000);
	CHECK(sir_service_count() >= 2,
	      "库内服务: 已应答远端写修复 (内联 WR REPAIR)");

	evt_wait(EVT_DONE, 30);
	evt_clear(EVT_DONE);

	symrdma_write_mr_deregister(&wmr);
	symrdma_mr_deregister(&ctx, &smr);
	ibv_destroy_qp(data_qp);
	ibv_destroy_cq(data_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ictx);
	symrdma_close(&ctx);
	munmap(buf, BUF_SIZE);
	unlink(PARAMS_S);

	printf("\n========================================\n");
	printf("Level 12-A server: %d 通过, %d 失败\n", passed, failed);
	printf("========================================\n");
	return failed > 0 ? 1 : 0;
}

/* ================= client (透明 API) ================= */

static int client_main(void)
{
	struct conn_params sp = {0}, mine = {0};
	struct symrdma_ctx ctx;
	struct symrdma_mr rmr, lmr;
	unsigned char *local;
	struct ibv_device *dev;
	struct ibv_context *ictx;
	struct ibv_pd *pd;
	struct ibv_cq *data_cq;
	struct ibv_qp *data_qp;
	uint32_t lkey;
	int i;

	printf("=== Level 12-A client (透明 API, 零 SIR/ioctl 代码) ===\n");

	for (i = 0; i < 100 && read_params(PARAMS_S, &sp); i++)
		usleep(100000);
	CHECK(i < 100, "取得 server 参数 (rkey/wkey/addr/版本表)");
	if (i >= 100)
		return 1;

	dev = find_mlx5();
	if (!dev)
		return 1;
	ictx = ibv_open_device(dev);
	pd = ibv_alloc_pd(ictx);

	data_qp = create_qp(pd, &data_cq);
	if (!data_qp)
		return 1;
	mine.qp_num = data_qp->qp_num;
	{
		union ibv_gid g;   /* 本侧 GID 入参数 (跨机 dgid) */

		if (!ibv_query_gid(ictx, 1, g_sgid, &g))
			gid_to_hex(&g, mine.gid);
	}
	write_params(PARAMS_C, &mine);
	if (qp_to_rts(data_qp, sp.qp_num)) {
		{int e=errno; printf("  data QP RTS 失败 (errno=%d %s)\n", e, strerror(e));}
		return 1;
	}

	/* local buffer: 注册为 SymRDMA MR (DMA 读/写目标均需 IOMMU 映射) */
	local = mmap(NULL, PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (local == MAP_FAILED)
		return 1;
	memset(local, 0, PAGE_SIZE);
	if (symrdma_open(&ctx)) {
		printf("  /dev/symrdma 打开失败\n");
		return 1;
	}
	if (symrdma_mr_register(&ctx, pd, local, PAGE_SIZE, &lmr)) {
		printf("  local MR 注册失败\n");
		return 1;
	}
	lkey = lmr.ibv_mr->lkey;

	/* ★ 透明 API: 导入远端 MR 视图 */
	CHECK(symrdma_mr_import_remote(&ctx, pd, &rmr, sp.rkey, sp.wkey,
				       sp.addr, (size_t)sp.len,
				       sp.v_rkey, sp.v_addr) == 0,
	      "symrdma_mr_import_remote (远端 MR 视图)");

	CHECK(evt_wait(EVT_READY, 30) == 0, "server 就绪 (SIR 通道已连)");

	/* 1. 基线读 */
	CHECK(symrdma_read(&ctx, data_qp, data_cq, &rmr, 0, PAGE_SIZE,
			   local, lkey) == 0, "基线: symrdma_read 页 0");
	CHECK(*(uint32_t *)local == 0xABABAB41, "基线数据 0xABABAB41");

	/* 2. ★ 读方向自动修复 */
	evt_set(EVT_BASELINE);          /* 请 server 换出 */
	CHECK(evt_wait(EVT_SWAPED1, 30) == 0, "server 已换出页 0");
	evt_clear(EVT_SWAPED1);
	CHECK(symrdma_read(&ctx, data_qp, data_cq, &rmr, 0, PAGE_SIZE,
			   local, lkey) == 0,
	      "★ 换出后 symrdma_read → 自动远端修复 (透明)");
	CHECK(*(uint32_t *)local == 0xABABAB41,
	      "★ 修复后数据 = 0xABABAB41 (哨兵隐藏, 真实数据返回)");

	/* 2b. ★ P1-1 回归: 修复→重放窗口二次换出 (owner 确定性
	 *     注入 RESENTINEL) — 旧代码以 SUCCESS 交付哨兵魔数 0xdeadbeef,
	 *     新代码版本奇偶判定 + 重试收敛后交付真实数据。 */
	evt_set(EVT_RSREQ);
	CHECK(evt_wait(EVT_RSSWAPED, 30) == 0, "2b server 已换出 (注入已武装)");
	evt_clear(EVT_RSSWAPED);
	CHECK(symrdma_read(&ctx, data_qp, data_cq, &rmr, 0, PAGE_SIZE,
			   local, lkey) == 0,
	      "2b 注入下 symrdma_read 重试收敛 (返回成功)");
	CHECK(*(uint32_t *)local == 0xABABAB41,
	      "2b ★ 交付真实数据而非哨兵魔数 (P1-1: 旧代码 = 0xdeadbeef)");

	/* 3. ★ 写方向自动修复 */
	evt_set(EVT_WREQ);              /* 请再次换出 */
	CHECK(evt_wait(EVT_SWAPED2, 30) == 0, "server 再次换出页 0");
	evt_clear(EVT_SWAPED2);
	*(uint32_t *)local = MARKER;
	CHECK(symrdma_write(&ctx, data_qp, data_cq, &rmr, NULL, 0, 4,
			    local, lkey) == 0,
	      "★ 换出后 symrdma_write 标记 → 自动内联 WR 修复");
	CHECK(symrdma_read(&ctx, data_qp, data_cq, &rmr, 0, PAGE_SIZE,
			   local, lkey) == 0 &&
	      *(uint32_t *)local == MARKER,
	      "★★ 修复后读回 = MARKER (写数据经库内修复落地真实页)");

	/* 4. 邻居页不受影响 */
	CHECK(symrdma_read(&ctx, data_qp, data_cq, &rmr, 1, PAGE_SIZE,
			   local, lkey) == 0 &&
	      *(uint32_t *)local == 0xABABAB42,
	      "邻居页 1 数据完好 (0xABABAB42)");

	evt_set(EVT_DONE);
	symrdma_mr_deregister(&ctx, &lmr);
	symrdma_mr_deregister(&ctx, &rmr);
	ibv_destroy_qp(data_qp);
	ibv_destroy_cq(data_cq);
	ibv_dealloc_pd(pd);
	ibv_close_device(ictx);
	symrdma_close(&ctx);
	munmap(local, PAGE_SIZE);
	unlink(PARAMS_C);

	printf("\n========================================\n");
	printf("Level 12-A client: %d 通过, %d 失败\n", passed, failed);
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
