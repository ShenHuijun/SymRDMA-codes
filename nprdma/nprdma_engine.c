/* SPDX-License-Identifier: GPL-2.0 */
/*
 * nprdma_engine.c — libnprdma 透明引擎 (v0.18.0 M2; v0.24.6 自 nprdma.c 拆分)
 *
 * 远端 MR one-sided 读/写验证 + SIR 自动修复 + outq 保序 CQE 交付。
 * 设计/串行化模型/降级策略见 nprdma.c 文件头与 nprdma_internal.h;
 * 本文件只含引擎 (分类、跟踪、验证、修复、重放), verbs 拦截层在 nprdma.c。
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <infiniband/verbs.h>
#include "nprdma_internal.h"

/* ================================================================
 * v0.18.0 (M2): 透明引擎 — 远端 MR one-sided 读/写验证 + SIR 自动修复
 *
 * 分类 (post_send): 本地 MR (mr_list rkey/lkey 命中) → 既有本地预检;
 * 远端 (rkey 命中对端导出表, 且地址落在导出区) → 验证路径; 其余透传。
 *
 * 跟踪模型 (每 QP 单活动 op): 提交新远端 op 前同步解析上一活动 op
 * (验证 → 修复 → 重放), 保证重放 WQE 先于后续应用 WQE (重放顺序正确),
 * 完成序 = 提交序。活动 op 解析时机: 下一 post_send / 本 CQ poll_cq。
 *
 * poll_cq 拦截: ①先交付 outq (解析产生的合成/缓存 WC, 保序);
 * ②有活动 op → 同步解析 (真实 CQ 轮询: 途经的更早/其它 QP 完成入
 * outq 保序透传; 活动 op 的 WC → 验证 → 修复/重放 → 合成 WC 入 outq);
 * ③outq 继续; ④真实 CQ 直取 (untracked 完成)。
 * 应用可见 CQE 数量/顺序不变; 原 unsignaled 远端 op 强制 signaled 供
 * 验证, 其 CQE 由引擎吞掉 (应用本就不期望)。
 *
 * 降级: SIR 禁用 (未设 SYMRDMA_PEER) / 未知 rkey / 多 SGE / 地址越出
 * 导出区 / unsignaled 远端写 / >4KB 远端写 → 透传 (与无引擎一致);
 * 解析超时/真实错误 → 该 CQ 漂移退化 (后续透传), 已缓存 WC 先交付。
 * ================================================================ */


/* v0.22.0 (bug 9): 引擎惰性链表插入锁 — 两线程并发为同一 CQ/QP/context
 * 建条目 → 双条目 (outq 分裂 → WC 丢失 → 应用轮询死转) 或插入丢失。
 * 命中路径保持无锁 (条目永不释放, x86 TSO 下插入后读安全)。 */
static pthread_mutex_t list_mu = PTHREAD_MUTEX_INITIALIZER;

/* per-context 引擎表头 (nprdma.c 拦截层只读遍历; 定义在此) */
struct npr_ctx_entry *npr_ctx_list;

static void npr_outq_push(struct npr_cq_entry *ce, const struct ibv_wc *wc)
{
	struct npr_wc_node *n = malloc(sizeof(*n));

	if (!n)
		return;   /* 丢节点仅影响该 WC 交付 — 内存紧张场景降级 */
	n->wc = *wc;
	n->next = NULL;
	if (ce->outq_tail)
		ce->outq_tail->next = n;
	else
		ce->outq_head = n;
	ce->outq_tail = n;
}

int npr_outq_pop(struct npr_cq_entry *ce, struct ibv_wc *wc)
{
	struct npr_wc_node *n = ce->outq_head;

	if (!n)
		return 0;
	*wc = n->wc;
	ce->outq_head = n->next;
	if (!ce->outq_head)
		ce->outq_tail = NULL;
	free(n);
	return 1;
}

struct npr_cq_entry *npr_cq_get(struct npr_ctx_entry *ce,
				       struct ibv_cq *cq)
{
	struct npr_cq_entry *e;

	for (e = ce->cqs; e; e = e->next)
		if (e->cq == cq)
			return e;
	pthread_mutex_lock(&list_mu);
	for (e = ce->cqs; e; e = e->next) {
		if (e->cq == cq) {
			pthread_mutex_unlock(&list_mu);
			return e;
		}
	}
	e = calloc(1, sizeof(*e));
	if (e) {
		e->cq = cq;
		e->next = ce->cqs;
		ce->cqs = e;
	}
	pthread_mutex_unlock(&list_mu);
	return e;
}

static struct npr_qp_state *npr_qp_get(struct npr_ctx_entry *ce,
				       struct ibv_qp *qp)
{
	struct npr_qp_state *q;

	for (q = ce->qps; q; q = q->next)
		if (q->qp == qp)
			return q;
	pthread_mutex_lock(&list_mu);
	for (q = ce->qps; q; q = q->next) {
		if (q->qp == qp) {
			pthread_mutex_unlock(&list_mu);
			return q;
		}
	}
	q = calloc(1, sizeof(*q));
	if (q) {
		q->qp = qp;
		q->next = ce->qps;
		ce->qps = q;
	}
	pthread_mutex_unlock(&list_mu);
	return q;
}

struct npr_ctx_entry *npr_ctx_get(struct ibv_context *ctx)
{
	struct npr_ctx_entry *e;

	for (e = npr_ctx_list; e; e = e->next)
		if (e->ctx == ctx)
			return e;
	pthread_mutex_lock(&list_mu);
	for (e = npr_ctx_list; e; e = e->next) {
		if (e->ctx == ctx) {
			pthread_mutex_unlock(&list_mu);
			return e;
		}
	}
	e = calloc(1, sizeof(*e));
	if (e) {
		e->ctx = ctx;
		e->next = npr_ctx_list;
		npr_ctx_list = e;
	}
	pthread_mutex_unlock(&list_mu);
	return e;
}

/* 哨兵魔数相位比对 + 256B TLP chunk 扫描原语 (R2, v0.29.0): 收敛至
 * sir/sentinel.h (sentinel_expect / sentinel_is_hit / sentinel_first_page /
 * sentinel_repair_all) — 引擎 3 份循环 + npr_write_check 内联第 4 份 +
 * lib 2 份单一实现。相位语义 (v0.22.0 bug 10: 读偏移 3585 实测
 * [BE AD DE EF], 固定相位漏检 → 哨兵魔数当真实数据交付) 与 len<4
 * 前缀路径 ( C2) 的实现随迁共享头, 溯源注释见彼处。 */

/* v0.24.8 辅助前置声明 — 定义在 npr_deliver/write_check 之后
 * (R5: npr_poll_for 前置声明删除 — 定义先于全部使用点);
 * v0.38.2: npr_fault_scratch_mmap 同前 (npr_scratch_get 在文件前段) */
static int npr_fault_repair_fail(void);
static int npr_fault_scratch_mmap(void);
static int npr_wc_fatal(const struct ibv_wc *wc);
static void npr_fail_closed(struct npr_cq_entry *cqe, struct ibv_wc *wc,
			    int forced_sig, const char *what);

/* 首个哨兵 chunk → 其缺失页号 + 页边界相对偏移 (用于修复请求)。
 *
 * v0.22.0 语义修正 (bug 2/4): 缺失粒度是页而非 chunk — 哨兵区域从缺失
 * 页起始 (绝对页边界) 开始, 而非首个哨兵 chunk (256B 相对步进)。
 * miss_off = 首个缺失页起点相对 remote_addr 的偏移 (非负):
 *   - 读/写头段 [0, miss_off) 由驻留页 DMA 正确落地, 保留;
 *   - 尾段 [miss_off, len) 落在缺失页 → 内联修复只取回/重放尾段。
 * 未扫到哨兵 (len<4 前缀命中等) → 兜底首页 (miss_off=0, 旧行为)。
 * 扫描收敛至 sir/sentinel.h sentinel_first_page (R2, v0.29.0)。 */
static void npr_sentinel_loc(const struct npr_track *t,
			     unsigned long *page, uint32_t *miss_off)
{
	uint64_t first = t->remote_addr;

	if (t->is_read && t->sge.addr)
		first = sentinel_first_page(
			(const void *)(uintptr_t)t->sge.addr,
			t->len, t->remote_addr);
	*page = (unsigned long)((first - t->exp_addr) / SYMRDMA_PAGE_SIZE);
	*miss_off = first > t->remote_addr ?
		    (uint32_t)(first - t->remote_addr) : 0;
}

/* v0.22.0 (bug 6): 修复缓冲区内 **所有** 缺失页 — 扫描 [remote_addr,+len)
 * 镜像 (读=应用接收缓冲 / 写=scratch 回读), 每个哨兵 chunk 定位其缺失页,
 * 连续同页 chunk 去重 (256B chunk 不跨 4KB 页边界, 连续去重 = 页去重),
 * 逐页 SIR REPAIR。一次收敛替代「每次重放修一页」— 跨多缺失页的大读
 * 不再受 3 次尝试上限截断。
 * 返回 0 = 至少修复一页且全部成功; -1 = 无哨兵 (调用方误用) 或修复失败。
 * 扫描收敛至 sir/sentinel.h sentinel_repair_all (R2, v0.29.0)。
 */

/* R2: sentinel_repair_all 逐命中页回调 — 单页 SIR REPAIR (无内联数据) */
struct npr_sir_repair {
	uint32_t rkey;
	int dir;
};

static int npr_sir_repair_cb(void *ud, unsigned long pg)
{
	struct npr_sir_repair *r = ud;

	return sir_remote_repair(r->rkey, pg, r->dir, 0, 0, NULL);
}

static int npr_repair_all_missing(const struct npr_track *t, int dir,
				  const void *scanbuf)
{
	struct npr_sir_repair r = { t->repair_rkey, dir };
	int n;

	/* v0.24.8: 故障注入门 (L13 T6/T7 — 确定性触发 fail-closed 路径) */
	if (npr_fault_repair_fail())
		return -1;

	n = sentinel_repair_all(scanbuf, t->len, t->remote_addr, t->exp_addr,
				npr_sir_repair_cb, &r);
	return n > 0 ? 0 : -1;
}

/* ================================================================
 * R5 重构: 引擎忙等轮询谓词化 — 原三处手写忙等循环收敛于此
 * (npr_write_check 辅助 WC 等待 :371 / npr_poll_for 末次就地等待 :489 /
 * npr_resolve 主循环 WC 等待 :555; 魔数 200000/50 提为常量)。
 * ================================================================ */
#define NPR_POLL_SPIN_MAX 200000   /* 忙等上限 (原三处内联魔数) */
#define NPR_POLL_SLEEP_US 50       /* 忙等间隔 us */

/* on_wc 分类返回值 */
enum {
	NPR_WC_PASS     = 0,   /* 途经他人完成 — 入 outq 保序后继续轮询 */
	NPR_WC_MATCH    = 1,   /* 目标 WC — 轮询结束 (*out 为该 WC) */
	NPR_WC_TERMINAL = 2,   /* 本 QP 致命 WC (bug 8) — helper 按序入
				* outq 后结束; 调用方执行终局副作用 */
};

/* 忙等轮询 (R5): 每轮 poll 1 个 WC 交 on_wc 分类; PASS → helper 入该
 * CQ 的 outq 继续; MATCH/TERMINAL → 结束 (TERMINAL 的 WC 已按序交付
 * outq — 保序 push 统一在此, 分类器不得自行 push)。
 * 返回 on_wc 返回值, 或 -1 (real_poll_cq 失败 / 忙等超时 — 与原三处
 * `++spins > 200000 → 返回错误` 语义一致)。 */
static int npr_poll_wc(struct npr_ctx_entry *ce, struct ibv_cq *cq,
		       int (*on_wc)(const struct ibv_wc *wc, void *arg),
		       void *arg, struct ibv_wc *out)
{
	struct npr_cq_entry *cqe = npr_cq_get(ce, cq);
	int spins = 0;

	for (;;) {
		int n = ce->real_poll_cq(cq, 1, out);

		if (n < 0)
			return -1;
		if (n > 0) {
			int rc = on_wc(out, arg);

			if (rc == NPR_WC_TERMINAL)
				npr_outq_push(cqe, out);
			if (rc != NPR_WC_PASS)
				return rc;
			npr_outq_push(cqe, out);
			continue;
		}
		if (++spins > NPR_POLL_SPIN_MAX)
			return -1;
		usleep(NPR_POLL_SLEEP_US);
	}
}

/* on_wc 分类实参: 活动 op 跟踪 + 可选 debug 标签 (NULL = 静默 —
 * poll_for 路径原无非匹配打印; resolve 主循环有, 文案原样保留) */
struct npr_poll_arg {
	struct npr_track *t;
	const char *dbg;
};

/* 活动 op WC 分类 (poll_for / resolve 主循环共用; bug 8 语义):
 * 本 QP + 指定方向 + SUCCESS → MATCH; 本 QP 致命 → TERMINAL;
 * 其余 (含 debug 打印, 在 fatal 判定前 — 与原顺序一致) → PASS。 */
static int npr_poll_match_active(const struct ibv_wc *wc, void *argp)
{
	const struct npr_poll_arg *pa = argp;
	const struct npr_track *t = pa->t;

	if (wc->qp_num == t->qp->qp_num &&
	    wc->opcode == (t->is_read ? IBV_WC_RDMA_READ :
			   IBV_WC_RDMA_WRITE) &&
	    wc->status == IBV_WC_SUCCESS)
		return NPR_WC_MATCH;
	if (pa->dbg && debug_on())
		fprintf(stderr,
			"[nprdma] %s 非匹配 WC: opcode=%d status=%d qp=%u wr_id=0x%lx (等待 %s)\n",
			pa->dbg, wc->opcode, wc->status, wc->qp_num,
			wc->wr_id, t->is_read ? "READ" : "WRITE");
	if (wc->qp_num == t->qp->qp_num && npr_wc_fatal(wc))
		return NPR_WC_TERMINAL;
	return NPR_WC_PASS;
}

/* 写验证辅助回读 WC 分类 (write_check 原语义: 仅 qp+opcode 匹配,
 * 不看 status — 错误 WC 的 status 检查在取回后降级; 无 fatal 分支)。 */
static int npr_write_check_wc(const struct ibv_wc *wc, void *arg)
{
	const struct npr_track *t = arg;

	return (wc->qp_num == t->qp->qp_num &&
		wc->opcode == IBV_WC_RDMA_READ) ? NPR_WC_MATCH : NPR_WC_PASS;
}

/* 写路径 scratch (辅助回读目标; 惰性, 每 ctx 4KB)。
 * v0.22.0 (bug 7): 创建加锁 — 两线程并发首次写验证会双建 scratch
 * (fd/MR 泄漏) 且 symrdma_open_locked 无锁调用与 reg 路径不一致。 */
static pthread_mutex_t scratch_mu = PTHREAD_MUTEX_INITIALIZER;

static int npr_scratch_get(struct npr_ctx_entry *ce, struct ibv_qp *qp)
{
	static struct ibv_mr *(*regfn)(struct ibv_pd *, void *, size_t,
				       uint64_t, unsigned int);
	void *buf;

	if (ce->scratch_mr || ce->no_scratch)
		return ce->scratch_mr ? 0 : -1;

	pthread_mutex_lock(&scratch_mu);
	if (ce->scratch_mr || ce->no_scratch) {
		pthread_mutex_unlock(&scratch_mu);
		return ce->scratch_mr ? 0 : -1;
	}
	if (!regfn)
		regfn = dlvsym(RTLD_NEXT, "ibv_reg_mr_iova2", "IBVERBS_1.8");
	if (npr_fault_scratch_mmap()) {
		/* v0.38.2 (P1-2): mmap 失败注入 — 同真实 MAP_FAILED 语义:
		 * no_scratch 闩锁 + **必须解锁** (旧代码在此路径持锁返回,
		 * 之后任何写验证进入 scratch_mu 永久死锁)。 */
		ce->no_scratch = 1;
		pthread_mutex_unlock(&scratch_mu);
		return -1;
	}
	buf = mmap(NULL, SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		/* v0.38.2 (P1-2 修复): 真实 MAP_FAILED 路径 — 旧代码持
		 * scratch_mu 返回 (mmap 失败后任何写验证死锁, 单次 ENOMEM
		 * 即挂死进程); 补解锁。 */
		ce->no_scratch = 1;
		pthread_mutex_unlock(&scratch_mu);
		return -1;
	}
	memset(buf, 0, SYMRDMA_PAGE_SIZE);
	if (symrdma_open_locked() == 0) {
		struct symrdma_ioc_reg_mr req = {
			.va_start = (unsigned long long)(uintptr_t)buf,
			.len = SYMRDMA_PAGE_SIZE,
		};
		if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &req) == 0)
			ce->scratch_mr_id = req.mr_id;
	}
	if (regfn && qp->pd)
		ce->scratch_mr = regfn(qp->pd, buf, SYMRDMA_PAGE_SIZE,
				       (uint64_t)(uintptr_t)buf,
				       IBV_ACCESS_LOCAL_WRITE |
				       SYMRDMA_ACCESS_IDENTITY);
	if (!ce->scratch_mr) {
		if (debug_on())
			fprintf(stderr, "[nprdma] scratch 创建失败 — 远端写验证禁用\n");
		ce->no_scratch = 1;
		munmap(buf, SYMRDMA_PAGE_SIZE);
		pthread_mutex_unlock(&scratch_mu);
		return -1;
	}
	ce->scratch_buf = buf;
	/* v0.25.0: scratch 页在飞 pin (一次性) — 辅助回读目标被换出时
	 * 哨兵数据误入验证比对的假阳性窗口消除 */
	npr_pin_once(ce->scratch_mr_id, (uint64_t)(uintptr_t)buf,
		     SYMRDMA_PAGE_SIZE);
	pthread_mutex_unlock(&scratch_mu);
	return 0;
}

/* 远端写验证 (signaled ≤4KB): 辅助 RDMA Read 回读目标 → 与快照比对。
 * 返回 0=已落地; 1=需修复 (*pg=首个缺失页号, *miss_off=该页边界相对
 * remote_addr 的偏移 — v0.22.0 bug 3: 旧行为恒返回写首地址所在页,
 * 多页写后页缺失时修复目标错 → 静默部分写丢失); -1=验证不可用 (降级)。
 *  F5 (v0.19.0): asge 初始化器原在 scratch 保护判断之前 —
 * 首个跟踪写时 scratch_mr==NULL → 必然空指针段错误 (写验证路径
 * 从未跑通过, L13 gdb 定位)。修复: 先建 scratch 再初始化 asge。 */
static int npr_write_check(struct npr_ctx_entry *ce, struct npr_track *t,
			   unsigned long *pg, uint32_t *miss_off)
{
	struct ibv_send_wr awr = {0}, *bad = NULL;
	struct ibv_sge asge;
	struct ibv_wc wc;

	if (!t->read_rkey || npr_scratch_get(ce, t->qp))
		return -1;
	asge.addr   = (uintptr_t)ce->scratch_buf;
	asge.length = t->len;
	asge.lkey   = ce->scratch_mr->lkey;
	awr.opcode = IBV_WR_RDMA_READ;
	awr.sg_list = &asge;
	awr.num_sge = 1;
	awr.wr.rdma.remote_addr = t->remote_addr;
	awr.wr.rdma.rkey = t->read_rkey;
	awr.send_flags = IBV_SEND_SIGNALED;
	if (ce->real_post_send(t->qp, &awr, &bad))
		return -1;
	/* 等 aux WC (吞掉, 不交付); 途经他人完成入 outq 保序
	 * (R5: 忙等循环谓词化 — 无 fatal 分支, 匹配仅看 qp+opcode,
	 * status 检查在取回后, 原语义) */
	if (npr_poll_wc(ce, t->send_cq, npr_write_check_wc, t, &wc) !=
	    NPR_WC_MATCH)
		return -1;
	if (wc.status != IBV_WC_SUCCESS)
		return -1;
	if (memcmp(ce->scratch_buf, t->src, t->len) == 0)
		return 0;   /* 已落地 */
	/* bug 3 修复: 扫描回读缓冲定位首个哨兵 chunk → 缺失页的绝对页
	 * 起点 (缺失粒度是页, 同 npr_sentinel_loc); 无哨兵但数据不匹配
	 * (并发修改) → 保守取首页 (与旧行为一致)。
	 * R2 (v0.29.0): 扫描收敛至 sir/sentinel.h sentinel_first_page
	 * (原 npr_sentinel_loc 复制品 — bug 3 修复时复制的手写循环)。 */
	{
		uint64_t first = sentinel_first_page(ce->scratch_buf, t->len,
						     t->remote_addr);

		*pg = (unsigned long)((first - t->exp_addr) / SYMRDMA_PAGE_SIZE);
		*miss_off = first > t->remote_addr ?
			    (uint32_t)(first - t->remote_addr) : 0;
	}
	return 1;
}

/* WC 交付 (v0.22.0 bug 5): 引擎为验证强制 signaled 的 WR (原 unsignaled
 * 远端读) — 应用不期望任何 CQE, 验证完成的 WC 必须吞掉; 否则应用完成
 * 计数错位 (多出一个 wr_id 为 unsignaled op 的 CQE, 后续 signaled 完成
 * 被顶替 → 应用误配对)。 */
static void npr_deliver(struct npr_cq_entry *cqe, const struct ibv_wc *wc,
			int forced_sig)
{
	if (forced_sig)
		return;
	npr_outq_push(cqe, wc);
}

/* QP 致命状态判定 (v0.22.0 bug 8) — 定义见下方 npr_deliver 之后 */
static int npr_wc_fatal(const struct ibv_wc *wc);

/* ---- v0.24.8: 修复耗尽 fail-closed (关闭 v0.22.0 降级路径的残余缺口) ----
 *
 * 旧行为: 修复失败/末次尝试仍缺页时, 把**修复前仍含哨兵魔数的缓冲**以
 * SUCCESS 交付 (读: 应用拿到 0xdeadbeef 当真实数据; 写: WC SUCCESS 而
 * 数据被黑洞吸收静默丢失) — 与论文 §3.1.1 "corrupted reads are detected
 * and safely retried" 及 v0.24.6 libsymrdma_remote 的 fail-closed 原则
 * (重试耗尽返回 EIO, 不交付哨兵) 不一致。
 *
 * 新语义:
 *   - signaled op (应用期望本 CQE): 合成错误 WC (GENERAL_ERR, 保留原
 *     wr_id/opcode) — 诚实失败, 应用可重试;
 *   - forced_sig (unsignaled 读): 无带内上报通道 — 硬件 verbs 语义下
 *     unsignaled 错误同样不产生直接 CQE; 吞掉 WC 保完成计数 (bug 5),
 *     接收缓冲数据不可信, 响亮 stderr 告警 (残余限制, 见 IMPLEMENTATION)。
 */
static void npr_fail_closed(struct npr_cq_entry *cqe, struct ibv_wc *wc,
			    int forced_sig, const char *what)
{
	if (forced_sig) {
		fprintf(stderr,
			"[nprdma] %s — 修复耗尽 fail-closed: unsignaled 读无上报通道, "
			"接收缓冲数据不可信 (吞 CQE 保完成计数)\n", what);
		return;
	}
	fprintf(stderr,
		"[nprdma] %s — 修复耗尽 fail-closed: 交付错误 WC "
		"(不再以 SUCCESS 交付哨兵数据/静默丢写)\n", what);
	wc->status = IBV_WC_GENERAL_ERR;
	npr_outq_push(cqe, wc);
}

/* 故障注入 (L13 T6/T7): NPRDMA_FAULT_REPAIR_FAIL=1 → 所有 SIR 修复请求
 * 直接失败 — 确定性触发 fail-closed 路径。live getenv (修复路径本身罕见,
 * 开销可忽略; 支持测试中途 setenv 切换)。未设置时零影响。 */
static int npr_fault_repair_fail(void)
{
	const char *m = getenv("NPRDMA_FAULT_REPAIR_FAIL");

	return m && *m && *m != '0';
}

/* v0.38.2 (P1-2 回归注入): NPRDMA_FAULT_SCRATCH_MMAP=1 → scratch mmap
 * 视为失败 — 确定性触发 npr_scratch_get 的失败退出路径 (旧代码持
 * scratch_mu 返回 → 任何后续写验证死锁; 白盒单测 test_engine_scratch
 * 以 trylock 检测锁纪律)。live getenv, 同 npr_fault_repair_fail 惯例。 */
static int npr_fault_scratch_mmap(void)
{
	const char *m = getenv("NPRDMA_FAULT_SCRATCH_MMAP");

	return m && *m && *m != '0';
}

/* 就地等待本 QP 指定方向的 WC (v0.24.8 末次尝试就地重读/重写用):
 * strays 入 outq 保序; 本 QP 致命 WC → 终局交付 + drift (bug 8 同语义)。
 * R5: 忙等循环谓词化 — 循环体收敛至 npr_poll_wc, 匹配/致命分类与
 * resolve 主循环共用 npr_poll_match_active (is_read 形参删除: 原调用点
 * 传参与 t->is_read 恒等, 分类器直读跟踪字段)。
 * 返回 0 = *out 为匹配的成功 WC; -1 = drift/超时 (调用方 goto drift)。 */
static int npr_poll_for(struct npr_ctx_entry *ce, struct npr_qp_state *qs,
			struct npr_cq_entry *cqe, struct npr_track *t,
			struct ibv_wc *out)
{
	int rc = npr_poll_wc(ce, t->send_cq, npr_poll_match_active, t, out);

	if (rc == NPR_WC_MATCH)
		return 0;
	if (rc == NPR_WC_TERMINAL) {
		qs->has_active = 0;
		cqe->drift = 1;
	}
	return -1;
}

/* QP 致命状态判定 (v0.22.0 bug 8): 同 QP 出现任一致命 WC (WR_FLUSH_ERR
 * 或其它非 SUCCESS 错误) 意味着 QP 已脱离正常完成流 — 被跟踪 op 的
 * "匹配" WC (flush 后 opcode 可能是垃圾 32764) 永远不会以 SUCCESS 形态
 * 到来, 继续等待只会超时漂移并把 WC 困在 outq (drift 路径不交付 →
 * 应用轮询死转)。fatal=true 时按终局处理: 当前 WC 直接按序交付。 */
static int npr_wc_fatal(const struct ibv_wc *wc)
{
	return wc->status != IBV_WC_SUCCESS;
}

/* ================================================================
 * R1 重构: npr_resolve 读/写路径拆分 — 原单函数 (~215 行) 把读路径
 * (哨兵检测 → 定位 → 内联修复 / repair-all → 重放) 与写路径 (辅助
 * 回读 → 定位 → 内联 WR / repair-all → 重写) 交织在同一 3 次重试
 * 循环内; 拆分后主函数只留重试循环 + WC 匹配/fatal 分发 + drift
 * 收尾。行为逐字节不变 — 本节是 v0.22.0 十项修复 (bug 1/2/3/4/5/6/8)
 * + v0.24.8 fail-closed 的载体, 全部版本溯源注释原样保留。
 * ================================================================ */

/* npr_resolve 读/写 handler 返回协议 */
enum {
	NPR_RES_DONE  = 0,   /* 已交付/终局 (deliver 或 fail-closed) — 退出重试 */
	NPR_RES_RETRY = 1,   /* 修复完成待重放 — 主循环重发后进入下一轮 */
	NPR_RES_DRIFT = -1,  /* 提交/轮询失败 — 主循环 goto drift */
};

/* 内联修复谓词 (R1): 「≤1KB 且尾段 [miss_off, len) 不跨页」收敛 —
 * 原读/写两处逐字重复判定 (仅 dir 与 data 实参不同)。
 * 溯源: bug 1/2 (读: 条件从「len ≤ 1KB」收紧为「尾段不跨页」, 数据
 * 偏移对齐 miss_off — 头段已由 DMA 正确写入) / bug 4 (写: 同偏移
 * 语义)。v0.24.8: 故障注入门 (T6/T7) — 修复失败走 fail-closed。 */
static int npr_inline_repair_ok(const struct npr_track *t, uint32_t miss_off)
{
	return !npr_fault_repair_fail() &&
	       t->len <= SIR_INLINE_MAX &&
	       (uint32_t)((t->remote_addr + miss_off) &
			  (SYMRDMA_PAGE_SIZE - 1)) +
		       (t->len - miss_off) <= SYMRDMA_PAGE_SIZE;
}

/* 读路径解析 (R1, 自 npr_resolve 拆出): 哨兵检测 → 定位 → 内联修复 /
 * repair-all → 重放。
 * v0.22.0 修复: bug 1 (≤1KB 跨页读零修复 → 哨兵数据交付),
 * bug 2 (内联修复数据偏移), bug 6 (重放前修复所有缺失页, 不再受
 * 3 次上限截断)。返回 NPR_RES_*, 见枚举。 */
static int npr_resolve_read(struct npr_ctx_entry *ce, struct npr_qp_state *qs,
			    struct npr_cq_entry *cqe, struct npr_track *t,
			    struct ibv_wc *wc, int attempt)
{
	void *lbuf = (void *)(uintptr_t)t->sge.addr;

	if (!sentinel_is_hit(lbuf, t->len, t->remote_addr)) {
		npr_deliver(cqe, wc, t->forced_sig);   /* 干净 */
		return NPR_RES_DONE;
	}
	{
		unsigned long page;
		uint32_t miss_off;

		npr_sentinel_loc(t, &page, &miss_off);
		if (debug_on())
			fprintf(stderr,
				"[nprdma] READ 哨兵命中 page=%lu miss_off=%u → SIR 修复\n",
				page, miss_off);
		/* ≤1KB 且尾段单页: owner 修复后内联回取尾段 (免重放)。
		 * bug 1/2: 条件从「len ≤ 1KB」收紧为「尾段不跨页」, 数据
		 * 偏移对齐 miss_off (头段已由 DMA 正确写入); 跨页/超限走
		 * 下方 repair-all。v0.24.8: 故障注入门 (T6)。 */
		if (npr_inline_repair_ok(t, miss_off) &&
		    sir_remote_repair(t->repair_rkey, page,
				      SIR_F_READ,
				      (uint32_t)((t->remote_addr + miss_off) &
						 (SYMRDMA_PAGE_SIZE - 1)),
				      t->len - miss_off,
				      (char *)lbuf + miss_off) == 0) {
			npr_deliver(cqe, wc, t->forced_sig);
			return NPR_RES_DONE;
		}
		/* bug 1/6: 跨页/内联失败 → 修复 **所有** 缺失页 → 重放一次
		 * 收敛。v0.24.8: 修复失败 → fail-closed (旧: 修复前哨兵缓冲
		 * 以 SUCCESS 透传 = 数据损坏)。 */
		if (npr_repair_all_missing(t, SIR_F_READ, lbuf) != 0) {
			npr_fail_closed(cqe, wc, t->forced_sig,
					"SIR 修复失败 (读)");
			return NPR_RES_DONE;
		}
	}
	/* 最后一次尝试: 修复成功后就地重读一次 (重放 + 就地等待其 WC,
	 * 不留无人解析的完成 — 原推迟重放的理由消除); 干净才交付, 仍哨兵
	 * → fail-closed。v0.24.8 修复: 旧代码此处交付**修复前**的哨兵缓冲
	 * (修复结果被丢弃), signaled 读以 SUCCESS 交付 0xdeadbeef、
	 * unsignaled 读静默损坏。 */
	if (attempt >= 2) {
		struct ibv_send_wr *bad = NULL;
		struct ibv_wc wc2;

		if (ce->real_post_send(t->qp, &t->wr, &bad))
			return NPR_RES_DRIFT;
		if (npr_poll_for(ce, qs, cqe, t, &wc2))
			return NPR_RES_DRIFT;
		if (!sentinel_is_hit(lbuf, t->len, t->remote_addr)) {
			npr_deliver(cqe, &wc2, t->forced_sig);
			return NPR_RES_DONE;
		}
		npr_fail_closed(cqe, &wc2, t->forced_sig,
				"修复 3 次仍缺页 (读)");
		return NPR_RES_DONE;
	}
	return NPR_RES_RETRY;
}

/* 写路径解析 (R1, 自 npr_resolve 拆出): 辅助回读验证 → 定位 → 内联
 * WR / repair-all → 重写。
 * v0.22.0 修复: bug 3 (回读定位首个缺失页), bug 4 (内联修复数据偏移),
 * bug 6 (重放前修复所有缺失页)。返回 NPR_RES_*, 见枚举。 */
static int npr_resolve_write(struct npr_ctx_entry *ce, struct npr_qp_state *qs,
			     struct npr_cq_entry *cqe, struct npr_track *t,
			     struct ibv_wc *wc, int attempt)
{
	unsigned long page;
	uint32_t miss_off;
	int rc = npr_write_check(ce, t, &page, &miss_off);

	if (rc == 0) {
		npr_deliver(cqe, wc, t->forced_sig);   /* 已落地 */
		return NPR_RES_DONE;
	}
	if (rc < 0) {
		npr_deliver(cqe, wc, t->forced_sig);   /* 验证不可用, 降级 */
		return NPR_RES_DONE;
	}
	if (debug_on())
		fprintf(stderr,
			"[nprdma] WRITE 未落地 page=%lu miss_off=%u (黑洞吸收) → SIR 修复\n",
			page, miss_off);
	/* ≤1KB 且尾段单页: 内联 WR 修复 (bug 4: 数据偏移对齐 miss_off —
	 * 头段已由驻留页 DMA 落地)。v0.24.8: 故障注入门 (T7)。 */
	if (npr_inline_repair_ok(t, miss_off) &&
	    sir_remote_repair(t->repair_rkey, page, SIR_F_WRITE,
			      (uint32_t)((t->remote_addr + miss_off) &
					 (SYMRDMA_PAGE_SIZE - 1)),
			      t->len - miss_off,
			      t->src + miss_off) == 0) {
		npr_deliver(cqe, wc, t->forced_sig);
		return NPR_RES_DONE;
	}
	/* >1KB / 内联失败: 修复所有缺失页 → 重写 (bug 3/6)。v0.24.8:
	 * 修复失败 → fail-closed (旧: WC SUCCESS 而数据已被黑洞吸收 =
	 * 静默丢写)。 */
	if (npr_repair_all_missing(t, SIR_F_WRITE, ce->scratch_buf) != 0) {
		npr_fail_closed(cqe, wc, t->forced_sig, "SIR 写修复失败");
		return NPR_RES_DONE;
	}
	/* 最后一次尝试: 修复成功后就地重写 + 就地验证 (先消费重写 WC 再跑
	 * 辅助回读, 防双重交付); 仍未落地 → fail-closed。v0.24.8 修复:
	 * 旧代码此处不重写直接 SUCCESS 交付 — 写数据被黑洞吸收静默丢失。 */
	if (attempt >= 2) {
		struct ibv_send_wr *bad = NULL;
		struct ibv_wc wc2;
		unsigned long pg2;
		uint32_t mo2;
		int rc2;

		if (ce->real_post_send(t->qp, &t->wr, &bad))
			return NPR_RES_DRIFT;
		if (npr_poll_for(ce, qs, cqe, t, &wc2))
			return NPR_RES_DRIFT;
		rc2 = npr_write_check(ce, t, &pg2, &mo2);
		if (rc2 == 0 || rc2 < 0) {
			/* 落地 / 验证不可用 (启动期降级, 保持原语义) */
			npr_deliver(cqe, &wc2, t->forced_sig);
			return NPR_RES_DONE;
		}
		npr_fail_closed(cqe, &wc2, t->forced_sig,
				"写修复 3 次仍未落地");
		return NPR_RES_DONE;
	}
	return NPR_RES_RETRY;
}

/* 解析活动 op (验证 → 修复 → 重放; 途经完成入 outq 保序)。
 * v0.22.0 修复: bug 5 (forced_sig CQE 泄漏), bug 8 (本 QP 致命 WC
 * 终局交付), bug 6 (重放前修复所有缺失页, 不再受 3 次上限截断)。
 * R1: 读/写路径拆至 npr_resolve_read/npr_resolve_write, 主函数只留
 * 重试循环 + WC 匹配/fatal 分发 + 重放 + drift 收尾。
 * 返回 0 正常; -1 漂移 (调用方退化透传)。 */
int npr_resolve(struct npr_ctx_entry *ce, struct npr_qp_state *qs)
{
	struct npr_track *t = &qs->active;
	struct npr_cq_entry *cqe = npr_cq_get(ce, t->send_cq);
	struct ibv_wc wc;
	int attempt;

	for (attempt = 0; attempt < 3; attempt++) {
		int rc;

		/* 轮询真实 CQ 直到本 op 的 WC (R5: 忙等循环谓词化;
		 * 非匹配 WC debug 打印文案原样保留) */
		{
			struct npr_poll_arg pa = { t, "resolve" };

			rc = npr_poll_wc(ce, t->send_cq,
					 npr_poll_match_active, &pa, &wc);
		}
		if (rc == NPR_WC_TERMINAL) {
			/* bug 8: 本 QP 致命 (flush/错误) — 匹配 WC 永不到来;
			 * 保留原始错误按序交付应用 (helper 已入 outq),
			 * QP 语义交给应用/后续透传。退出跟踪并 drift
			 * (QP 已不可用)。 */
			fprintf(stderr,
				"[nprdma] QP %u 致命错误 status=%d — 终局交付 (退出跟踪)\n",
				wc.qp_num, wc.status);
			goto drift;
		}
		if (rc != NPR_WC_MATCH)
			goto drift;
		if (wc.status != IBV_WC_SUCCESS) {
			npr_deliver(cqe, &wc, t->forced_sig);   /* 真实错误 */
			break;
		}

		rc = t->is_read ?
		     npr_resolve_read(ce, qs, cqe, t, &wc, attempt) :
		     npr_resolve_write(ce, qs, cqe, t, &wc, attempt);
		if (rc == NPR_RES_DONE)
			break;
		if (rc == NPR_RES_DRIFT)
			goto drift;
		/* NPR_RES_RETRY: 重放 (同 WR 拷贝, 强制 signaled) */
		{
			struct ibv_send_wr *bad = NULL;

			if (ce->real_post_send(t->qp, &t->wr, &bad))
				goto drift;
		}
	}
	qs->has_active = 0;
	return 0;
drift:
	qs->has_active = 0;
	if (cqe)
		cqe->drift = 1;
	return -1;
}

/* 引擎提交: 远端 one-sided op → 拷贝跟踪 + 强制 signaled + 提交。
 * 返回 1 = 引擎已提交; 0 = 透传 (调用方按普通 WR 提交)。
 * R6: exp_out/have_out 出参 (可均为 NULL) — 透传路径上已成功完成
 * sir_remote_lookup 时带回快照 (*have_out=1), 供 post_send 的 write
 * rkey 重写复用, 免二次全价 lookup (每次含会合文件 stat 刷新检查)。
 * lookup 未执行/未成功时 *have_out=0 — 调用方回退自行 lookup。 */
int npr_engine_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
			     struct ibv_send_wr *w,
			     struct sir_export *exp_out, int *have_out)
{
	struct sir_export exp;
	int is_read = (w->opcode == IBV_WR_RDMA_READ);
	struct npr_qp_state *qs;
	struct npr_track *t;
	uint64_t addr = w->wr.rdma.remote_addr;
	uint32_t len;

	if (have_out)
		*have_out = 0;
	if (w->num_sge != 1 || !w->sg_list)
		return 0;                          /* 多 SGE: 透传 */
	if (!ce->real_post_send)
		return 0;                          /*  F3 防御: 引擎未就绪 → 透传 */
	len = w->sg_list[0].length;
	if (sir_remote_lookup(w->wr.rdma.rkey, &exp))
		return 0;                          /* 非远端 (本地/未知) */
	/* R6: lookup 已成功 — 快照带出供透传路径 rkey 重写复用 */
	if (exp_out)
		*exp_out = exp;
	if (have_out)
		*have_out = 1;
	if (addr < exp.addr || addr + len > exp.addr + exp.len)
		return 0;                          /* 地址越出导出区: 透传 */
	if (!is_read) {
		static int warned;

		if (!(w->send_flags & IBV_SEND_SIGNALED)) {
			if (!warned++)
				fprintf(stderr,
					"[nprdma] unsignaled 远端写 — 无法安全验证, 透传\n");
			return 0;
		}
		if (len > NPR_SRC_MAX) {
			if (!warned++)
				fprintf(stderr,
					"[nprdma] >4KB 远端写 — 下一增量, 透传\n");
			return 0;
		}
	}

	qs = npr_qp_get(ce, qp);
	if (!qs)
		return 0;
	if (qs->has_active && npr_resolve(ce, qs))
		return 0;                          /* 漂移: 本 WR 也透传 */

	t = &qs->active;
	memset(t, 0, sizeof(*t));
	t->qp = qp;
	t->send_cq = qp->send_cq;
	t->is_read = is_read;
	t->wr = *w;
	t->sge = w->sg_list[0];
	t->wr.sg_list = &t->sge;
	t->wr.next = NULL;
	if (!(t->wr.send_flags & IBV_SEND_SIGNALED)) {
		t->wr.send_flags |= IBV_SEND_SIGNALED;
		t->forced_sig = 1;
	}
	t->repair_rkey = w->wr.rdma.rkey;
	t->read_rkey = exp.data_rkey;
	/* v0.19.0 (论文 §3.1.1 Read/Write MR 分离): 写路径重定向 write 区域
	 * MKEY (MTT=VA+32GB → write_iova) — 缺失页 DMA 写被黑洞吸收, 消除
	 * identity MTT 下写穿 RW 哨兵页的全局魔数污染。repair_rkey 保持
	 * 原始 rkey (SIR 导出表查找键, data/write 均可匹配); 回读验证用
	 * read_rkey=数据 rkey (read_iova: 驻留→真实/缺失→哨兵≠快照)。 */
	if (!is_read && exp.write_rkey)
		t->wr.wr.rdma.rkey = exp.write_rkey;
	t->exp_addr = exp.addr;
	t->remote_addr = addr;
	t->len = len;
	if (!is_read)
		memcpy(t->src, (void *)(uintptr_t)w->sg_list[0].addr, len);

	{
		struct ibv_send_wr *bad = NULL;

		if (ce->real_post_send(qp, &t->wr, &bad))
			return 0;                  /* 提交失败 → 调用方重试透传 */
	}
	qs->has_active = 1;
	if (debug_on())
		fprintf(stderr,
			"[nprdma] 引擎跟踪 %s rkey=0x%x addr=0x%llx len=%u\n",
			is_read ? "READ" : "WRITE", w->wr.rdma.rkey,
			(unsigned long long)addr, len);
	return 1;
}

/* v0.20.0 (偏差 1 补全): 引擎未跟踪的远端写 (unsignaled / >4KB /
 * 多 SGE / 漂移) 提交前重写 rkey → write_rkey (MTT=VA+32GB):
 * 缺失页 DMA 写落黑洞被吸收, 消除 identity MTT 下透传写写穿 RW
 * 哨兵页的全局魔数污染 (论文 §3.1.1 Read/Write MR 分离对全写
 * 路径生效)。本地/未知 rkey / 无 write_rkey / 地址越出导出区不改写。
 * 注: 透传写仍无落地验证 (黑洞吸收 = 静默丢失, 与 v0.19.0 前的
 * 数据丢失风险等价) — 验证仅覆盖被跟踪的 signaled ≤4KB 写。
 * R6: exp_have 非空时复用 npr_engine_submit 已取的导出快照 (同一
 * WR 同线程紧邻调用, 判定基于同一快照, 免二次 stat); NULL 时回退
 * 自行 lookup (多 SGE 等未达 lookup 的透传路径)。 */
void npr_write_rkey_rewrite(const struct ibv_send_wr *w,
				   struct ibv_send_wr *one,
				   const struct sir_export *exp_have)
{
	struct sir_export exp;
	uint64_t total = 0;
	int i;

	if (w->opcode != IBV_WR_RDMA_WRITE)
		return;
	if (!w->sg_list || w->num_sge <= 0)
		return;                    /* 形态异常: 交真实路径报错 */
	for (i = 0; i < (int)w->num_sge; i++)
		total += w->sg_list[i].length;
	if (exp_have) {
		exp = *exp_have;           /* R6: 复用 submit 的 lookup 快照 */
	} else if (sir_remote_lookup(w->wr.rdma.rkey, &exp)) {
		return;                    /* 非远端 (本地/未知): 不改写 */
	}
	if (!exp.write_rkey)
		return;                    /* owner 无写区域辅助 MR */
	if (w->wr.rdma.remote_addr < exp.addr ||
	    w->wr.rdma.remote_addr + total > exp.addr + exp.len)
		return;                    /* 越出导出区: 保持原语义报错 */
	one->wr.rdma.rkey = exp.write_rkey;
	if (debug_on())
		fprintf(stderr,
			"[nprdma] 透传写 rkey 重写 0x%x → 0x%x (write 区域, addr=0x%llx len=%llu)\n",
			w->wr.rdma.rkey, exp.write_rkey,
			(unsigned long long)w->wr.rdma.remote_addr,
			(unsigned long long)total);
}

/* v0.20.0 (论文 §3.4): 远端原子经 SIR 双端 RPC — 远端 CPU 执行
 * (lock cmpxchg/xadd, 经正常 MMU 路径, 换出页自动缺页换入, 无部分
 * 执行风险), 旧值写回本地 buffer, signaled WR 合成 WC 经 outq 保序
 * 交付 (poll_cq 拦截交付)。
 * 返回 1 = 已处理; 0 = 透传 (本地 MR / 未知 rkey / 形态异常 /
 * 漂移); -1 = 拒绝该 WR (远端 MR 但 RPC 失败 — 不可安全下发 NIC:
 * identity MTT 下换出页原子会读改写哨兵页)。 */
int npr_atomic_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
			     struct ibv_send_wr *w)
{
	struct sir_export exp;
	struct npr_qp_state *qs;
	uint64_t old = 0, cmp = 0, arg = 0;
	int op, rc;

	if (w->num_sge != 1 || !w->sg_list || w->sg_list[0].length != 8 ||
	    !w->sg_list[0].addr)
		return 0;                  /* 形态异常: 交真实路径报错 */
	if (sir_remote_lookup(w->wr.atomic.rkey, &exp))
		return 0;                  /* 本地 MR: 真实 NIC 原子 (原行为) */
	if (w->wr.atomic.remote_addr < exp.addr ||
	    w->wr.atomic.remote_addr + 8 > exp.addr + exp.len)
		return 0;                  /* 越出导出区: 透传 (远端访问错误) */
	if (w->opcode == IBV_WR_ATOMIC_CMP_AND_SWP) {
		op  = SIR_F_ATOMIC_CAS;
		cmp = w->wr.atomic.compare_add;
		arg = w->wr.atomic.swap;
	} else {
		op  = SIR_F_ATOMIC_FAA;
		arg = w->wr.atomic.compare_add;    /* addend */
	}
	/* QP 序: 先解析本 QP 活动 op (原子 RPC 在其后同步执行) */
	qs = npr_qp_get(ce, qp);
	if (!qs)
		return 0;
	if (qs->has_active && npr_resolve(ce, qs))
		return 0;                  /* 漂移: 透传 */
	rc = sir_remote_atomic(w->wr.atomic.rkey, w->wr.atomic.remote_addr,
			       op, cmp, arg, &old);
	if (rc) {
		fprintf(stderr,
			"[nprdma] 远端原子失败 (rkey=0x%x): %s — 拒绝 WR\n",
			w->wr.atomic.rkey, strerror(errno));
		return -1;
	}
	memcpy((void *)(uintptr_t)w->sg_list[0].addr, &old, 8);
	if (w->send_flags & IBV_SEND_SIGNALED) {
		struct ibv_wc wc;

		memset(&wc, 0, sizeof(wc));
		wc.wr_id    = w->wr_id;
		wc.status   = IBV_WC_SUCCESS;
		wc.opcode   = (op == SIR_F_ATOMIC_CAS) ? IBV_WC_COMP_SWAP :
							 IBV_WC_FETCH_ADD;
		wc.qp_num   = qp->qp_num;
		wc.byte_len = 8;
		npr_outq_push(npr_cq_get(ce, qp->send_cq), &wc);
	}
	if (debug_on())
		fprintf(stderr,
			"[nprdma] 远端原子 %s rkey=0x%x addr=0x%llx → old=0x%llx (SIR RPC)\n",
			op == SIR_F_ATOMIC_CAS ? "CAS" : "FAA",
			w->wr.atomic.rkey,
			(unsigned long long)w->wr.atomic.remote_addr,
			(unsigned long long)old);
	return 1;
}
