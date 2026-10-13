/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sir.c — SIR 核心 (自单文件拆分; 通道建立见 sir_channel.c,
 * owner 服务见 sir_service.c)
 *
 * 进程级单例状态与全局锁 + 调试开关 + 公共 API:
 *   sir_init          — 惰性初始化 (env SYMRDMA_PEER / SYMRDMA_SIR_DIR)
 *   sir_export_*      — owner 导出表管理 (合并/撤销 + 会合文件发布)
 *   sir_remote_*      — requester 客户端 (远端修复 / 原子 RPC; 排队 +
 *                       等待服务线程代发: 超时清 pending 防 UAF)
 *   sir_is_connected / sir_service_count / sir_fini
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <infiniband/verbs.h>
#include "sir.h"
#include "sir_internal.h"

int sir_dbg(void)   /* internal.h 声明 */
{
	static int on = -1;
	if (on < 0)
		on = getenv("SYMRDMA_SIR_DEBUG") != NULL;
	return on;
}

/* ---- 全局单例与锁 (sir_internal.h 声明; 通道/服务单元经 extern 共享) ---- */
struct sir_state *S;
pthread_mutex_t g_mu = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t  g_cv  = PTHREAD_COND_INITIALIZER;

/* ---- 公共 API ---- */

int sir_init(struct ibv_context *ctx, struct ibv_pd *pd,
	     const char *key, int sym_fd)
{
	const char *envdir, *k, *tcp;

	pthread_mutex_lock(&g_mu);
	if (!S) {
		S = calloc(1, sizeof(*S));
		if (!S) {
			pthread_mutex_unlock(&g_mu);
			return -1;
		}
		S->in_id = -1;
		S->out_id = -1;
		S->sym_fd = -1;
		S->tcp_fd = -1;
	}
	if (!S->inited) {
		S->inited = 1;
		S->sym_fd = sym_fd;
		k = (key && key[0]) ? key : getenv("SYMRDMA_PEER");
		if (k && k[0])
			snprintf(S->key, sizeof(S->key), "%s", k);
		envdir = getenv("SYMRDMA_SIR_DIR");
		snprintf(S->path, sizeof(S->path), "%s",
			 envdir && envdir[0] ? envdir : SIR_DIR_DEFAULT);
		if (S->key[0])
			S->enabled = 1;
		/* TCP 网络会合: SYMRDMA_SIR_TCP = "listen:<port>" |
		 * "<host>:<port>"。设置后角色由 listen/connect 决定 (a/b 粘性,
		 * sir_elect_role 直接返回), 会合/导出表交换走 TCP 而非文件;
		 * SYMRDMA_SIR_GID = 控制 QP sgid_index (默认 0; 双机测试床 5,
		 * TCP 配置本身即启用开关 —
		 * key 为空时也 enabled (显式网络会合语义)。 */
		tcp = getenv("SYMRDMA_SIR_TCP");
		if (tcp && tcp[0]) {
			const char *colon = strrchr(tcp, ':');

			if (colon && colon != tcp) {
				S->tcp_port = atoi(colon + 1);
				if (!strncmp(tcp, "listen:", 7)) {
				S->use_tcp = 1;
					S->tcp_listen = 1;
					S->role = 'a';
					S->enabled = 1;
					sir_load_fns();   /* TCP blob 构建需真实 query_gid
							   * (此前仅在 ensure_channel 加载,
							   * 首次 export_add 早于建连 → 段错误) */
					sir_log("会合模式: TCP listen:%d (role a)",
						S->tcp_port);
				} else if (S->tcp_port > 0) {
					size_t hl = (size_t)(colon - tcp);

					if (hl >= sizeof(S->tcp_host))
						hl = sizeof(S->tcp_host) - 1;
					memcpy(S->tcp_host, tcp, hl);
					S->tcp_host[hl] = 0;
					S->use_tcp = 1;
					S->tcp_listen = 0;
					S->role = 'b';
					S->enabled = 1;
					sir_load_fns();   /* 同左: 首次导出早于建连 */
					sir_log("会合模式: TCP %s:%d (role b)",
						S->tcp_host, S->tcp_port);
				}
			}
			if (!S->use_tcp)
				sir_log("SYMRDMA_SIR_TCP='%s' 无法解析 — 回退文件会合",
					tcp);
		}
		{
			const char *g = getenv("SYMRDMA_SIR_GID");

			S->sgid_index = (g && g[0]) ? atoi(g) : 0;
		}
		/* 运维/二分开关 — SYMRDMA_NO_RANGE_IOCTL=1 强制走逐页
		 * REPAIR 回退路径 (不依赖 ENOTTY 探测); 未设置时零影响 */
		{
			const char *n = getenv("SYMRDMA_NO_RANGE_IOCTL");

			if (n && n[0] && n[0] != '0') {
				S->no_range_ioctl = 1;
				sir_log("SYMRDMA_NO_RANGE_IOCTL=1 — 强制逐页回退");
			}
		}
	}
	/* sym_fd 迟绑定 (alloc_pd 早于首次 reg_mr 打开 /dev/symrdma)。
	 *  控制 buffer 已改普通 pinned MR (不再需要模块 IOMMU
	 * 映射 — 见 sir_channel.c 同版注记), 迟绑定补映射块移除;
	 * in_id/out_id 恒 -1, 注销路径自然跳过。 */
	if (sym_fd >= 0 && S->sym_fd < 0)
		S->sym_fd = sym_fd;
	if (ctx)
		S->ctx = ctx;
	if (pd)
		S->pd = pd;
	pthread_mutex_unlock(&g_mu);
	return 0;
}

int sir_export_add(const struct sir_export *e)
{
	struct sir_export *n;
	int rc;

	if (!e || (e->data_rkey == 0 && e->write_rkey == 0)) {
		errno = EINVAL;
		return -1;
	}
	pthread_mutex_lock(&g_mu);
	if (!S || !S->enabled) {
		pthread_mutex_unlock(&g_mu);
		errno = ENOTCONN;
		return -1;
	}
	/* 写 MR 合并: 同地址区间已有数据导出 (data_rkey≠0) 且本条仅 wkey
	 * (写区域 MR, 同 VA 二次注册) → 并入已有条目 (免重复导出/双表) */
	if (e->data_rkey == 0 && e->write_rkey != 0) {
		struct sir_export *x;
		for (x = S->exports; x; x = x->next) {
			if (x->data_rkey && x->addr == e->addr &&
			    x->len == e->len && !x->write_rkey) {
				x->write_rkey = e->write_rkey;
				rc = sir_write_own_info();
				pthread_mutex_unlock(&g_mu);
				sir_log("导出合并 wkey=0x%x → rkey=0x%x",
					e->write_rkey, x->data_rkey);
				if (rc == 0)
					sir_start_connector();
				return rc;
			}
		}
	}
	/* 反向合并: 数据导出晚于纯写导出 (注册顺序 write→read)
	 * — 已有独立 wkey 条目 (data_rkey==0) 同区间时, 把 data/v/mr_id
	 * 补入该条目而非另建第二条 (保证导出表每区间一条) */
	if (e->data_rkey != 0 && e->write_rkey == 0) {
		struct sir_export *x;
		for (x = S->exports; x; x = x->next) {
			if (!x->data_rkey && x->write_rkey &&
			    x->addr == e->addr && x->len == e->len) {
				x->data_rkey = e->data_rkey;
				x->v_rkey    = e->v_rkey;
				x->v_addr    = e->v_addr;
				x->mr_id     = e->mr_id;
				rc = sir_write_own_info();
				pthread_mutex_unlock(&g_mu);
				sir_log("导出反向合并 rkey=0x%x → wkey=0x%x",
						e->data_rkey, x->write_rkey);
				if (rc == 0)
					sir_start_connector();
				return rc;
			}
		}
	}
	n = calloc(1, sizeof(*n));
	if (!n) {
		pthread_mutex_unlock(&g_mu);
		return -1;
	}
	*n = *e;
	{
		struct sir_export **pp = &S->exports;
		while (*pp)
			pp = &(*pp)->next;
		*pp = n;
	}
	rc = sir_write_own_info();
	pthread_mutex_unlock(&g_mu);
	sir_log("导出 rkey=0x%x wkey=0x%x addr=%p len=%llu mr_id=%d",
		e->data_rkey, e->write_rkey, (void *)(uintptr_t)e->addr,
		(unsigned long long)e->len, e->mr_id);
	/* 服务就绪: 异步自动建连 (不阻塞调用方; 对端晚到则重试) */
	if (rc == 0)
		sir_start_connector();
	return rc;
}

void sir_export_del(uint32_t data_rkey)
{
	if (!S)
		return;
	pthread_mutex_lock(&g_mu);
	{
		struct sir_export **pp = &S->exports;
		while (*pp) {
			struct sir_export *t = *pp;
			if (t->data_rkey == data_rkey) {
				*pp = t->next;
				free(t);
				sir_write_own_info();
				break;
			}
			pp = &(*pp)->next;
		}
	}
	pthread_mutex_unlock(&g_mu);
}

/* 撤销 write_rkey 导出 — 已合并条目仅清 wkey 位;
 * 独立 wkey 条目 (data_rkey==0, 未发生反向合并) 整条移除 */
void sir_export_del_wkey(uint32_t write_rkey)
{
	if (!S || !write_rkey)
		return;
	pthread_mutex_lock(&g_mu);
	{
		struct sir_export **pp = &S->exports;
		while (*pp) {
			struct sir_export *t = *pp;
			if (t->write_rkey == write_rkey) {
				if (t->data_rkey) {
					t->write_rkey = 0;
					sir_write_own_info();
				} else {
					*pp = t->next;
					free(t);
					sir_write_own_info();
				}
				break;
			}
			pp = &(*pp)->next;
		}
	}
	pthread_mutex_unlock(&g_mu);
}

/* 锁内拷出快照 — 见 sir.h 契约变更说明 (旧形态返回内部
 * 链表指针, 解锁后被并发刷新 free → UAF) */
int sir_remote_lookup(uint32_t data_rkey, struct sir_export *out)
{
	struct sir_export *e;
	int found = 0, i;

	if (out)
		memset(out, 0, sizeof(*out));
	pthread_mutex_lock(&g_mu);
	if (!S || !S->enabled) {
		pthread_mutex_unlock(&g_mu);
		errno = ENOTCONN;
		return -1;
	}
	/* 对端表为空且通道未连: 建连/握手可能尚未完成 — 引擎
	 * 修复路径的 lookup 单次调用不会重试, 而连接线程 300ms tick 可能
	 * 晚于整个短测试进程 (L13 跨机实测) — 此处等待 (≤3.5s, 同 repair)
	 * 而非立即 ENXIO。已连/已有表则零开销。 */
	if (!S->peers && !S->connected) {
		pthread_mutex_unlock(&g_mu);
		sir_start_connector();
		for (i = 0; i < 350 && !sir_is_connected(); i++)
			usleep(10000);
		pthread_mutex_lock(&g_mu);
	}
	sir_read_peer_info_locked();
	for (e = S->peers; e; e = e->next)
		if (e->data_rkey == data_rkey || e->write_rkey == data_rkey) {
			if (out)
				*out = *e;
			found = 1;
			break;
		}
	pthread_mutex_unlock(&g_mu);
	if (!found) {
		errno = ENXIO;
		return -1;
	}
	return 0;
}

/* 公共体前置声明 (实现在下方 wrappers 之后) */
static int repair_common(uint32_t data_rkey, unsigned long page_idx,
			 unsigned long npages, int dir,
			 uint32_t off, uint32_t len, void *data);

int sir_remote_repair(uint32_t data_rkey, unsigned long page_idx, int dir,
		      uint32_t off, uint32_t len, void *data)
{
	return repair_common(data_rkey, page_idx, 1, dir, off, len, data);
}

int sir_remote_repair_range(uint32_t data_rkey, unsigned long page_idx,
			    unsigned long npages, int dir,
			    uint32_t off, uint32_t len, void *data)
{
	if (npages == 0)
		npages = 1;
	if (npages > 1 && (off || len)) {
		errno = EINVAL;   /* 内联数据仅单页语义 */
		return -1;
	}
	return repair_common(data_rkey, page_idx, npages, dir, off, len, data);
}

/* 公共体 (自 sir_remote_repair 提出; range 变体共用):
 * 排队 → 服务线程代发 → 等应答 (5s) → 拷出内联数据。
 * npages 放入 msg.mlen (REPAIR 类型原未用字段, 向后兼容:
 * 旧对端发 0 → owner 侧按单页处理)。 */
static int repair_common(uint32_t data_rkey, unsigned long page_idx,
			 unsigned long npages, int dir,
			 uint32_t off, uint32_t len, void *data)
{
	struct sir_req *rq, **pp;
	int i, ret = -1;

	if (len > SIR_INLINE_MAX || off + len > SIR_PAGE_SIZE) {
		errno = EINVAL;
		return -1;
	}
	if (sir_remote_lookup(data_rkey, NULL)) {
		sir_log("repair: rkey 0x%x 不在对端导出表 (errno=%d)",
			data_rkey, errno);
		return -1;
	}
	/* 通道未就绪: 异步建连 + 等待 (≤3.5s) */
	sir_start_connector();
	for (i = 0; i < 350 && !sir_is_connected(); i++)
		usleep(10000);
	if (!sir_is_connected()) {
		errno = ENOTCONN;
		return -1;
	}

	rq = calloc(1, sizeof(*rq));
	if (!rq)
		return -1;
	rq->rkey = data_rkey;
	rq->page_idx = page_idx;
	rq->npages = npages ? npages : 1;
	rq->dir = dir;
	rq->off = off;
	rq->len = len;
	if (len && data)
		memcpy(rq->data, data, len);

	pthread_mutex_lock(&g_mu);
	if (!S->connected) {
		pthread_mutex_unlock(&g_mu);
		free(rq);
		errno = ENOTCONN;
		return -1;
	}
	rq->tag = S->tag_hi | (S->next_tag++ & 0x7fffffffu);
	rq->next = NULL;
	if (S->req_tail)
		S->req_tail->next = rq;
	else
		S->req_head = rq;
	S->req_tail = rq;
	S->requested++;

	/* 等待服务线程处理 (注释 ≤5s — 实为 500×1s, 改为
	 * 50×100ms 真实 5s; 应答丢失时应用线程不再被扣住 8 分钟) */
	for (i = 0; i < 50 && !rq->done; i++) {
		struct timespec ts;
		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += 100 * 1000 * 1000;
		if (ts.tv_nsec >= 1000 * 1000 * 1000) {
			ts.tv_sec += 1;
			ts.tv_nsec -= 1000 * 1000 * 1000;
		}
		pthread_cond_timedwait(&g_cv, &g_mu, &ts);
		if (!rq->done)
			sir_log("等待应答: tag=0x%x pending=%u (%d/50)",
				rq->tag, S->pending_tag, i + 1);
	}
	if (!rq->done) {
		errno = ETIMEDOUT;
	} else if (rq->ret != 0) {
		errno = (int)rq->reply.status ? (int)rq->reply.status : EIO;
	} else {
		ret = 0;
		if ((dir & SIR_F_READ) && rq->len && data &&
		    rq->reply.type == SIR_MSG_REPAIR_OK && rq->reply.len)
			memcpy(data, rq->reply.data,
			       rq->reply.len < rq->len ? rq->reply.len :
							 rq->len);
	}
	/* 摘除 (正常已被服务线程出队; 兑底)。
	 *  超时路径若该请求正是 pending 中的, 必须同锁清除
	 * S->pending_tag/pending_req — 否则迟到的应答会经 process_msg
	 * 写已释放的 rq (UAF), 且残留的 pending_tag 令后续请求永不
	 * 被代发 (通道卡死至对端重发同 tag)。 */
	if (S->pending_req == rq) {
		S->pending_req = NULL;
		S->pending_tag = 0;
	}
	for (pp = &S->req_head; *pp; pp = &(*pp)->next)
		if (*pp == rq) {
			*pp = rq->next;
			if (!*pp)
				S->req_tail = NULL;
			break;
		}
	pthread_mutex_unlock(&g_mu);
	free(rq);
	return ret;
}

/* requester: 阻塞式远端原子 (论文 §3.4 双端 RPC).
 * 排队/等待模式与 sir_remote_repair 同 (不复用以隔离已验证路径):
 * 服务线程代发 SIR_MSG_ATOMIC → owner 远端 CPU 执行 → ATOMIC_OK
 * 旧值内联回。CAS 操作数 16B (compare+swap), FAA 8B (addend)。 */
int sir_remote_atomic(uint32_t data_rkey, uint64_t va, int op,
		      uint64_t compare, uint64_t swap_or_add, uint64_t *old_out)
{
	struct sir_req *rq, **pp;
	int i, ret = -1;

	if (op != SIR_F_ATOMIC_CAS && op != SIR_F_ATOMIC_FAA) {
		errno = EINVAL;
		return -1;
	}
	if (sir_remote_lookup(data_rkey, NULL)) {
		sir_log("atomic: rkey 0x%x 不在对端导出表 (errno=%d)",
			data_rkey, errno);
		return -1;
	}
	/* 通道未就绪: 异步建连 + 等待 (≤3.5s) — 同 repair */
	sir_start_connector();
	for (i = 0; i < 350 && !sir_is_connected(); i++)
		usleep(10000);
	if (!sir_is_connected()) {
		errno = ENOTCONN;
		return -1;
	}

	rq = calloc(1, sizeof(*rq));
	if (!rq)
		return -1;
	rq->rkey = data_rkey;
	rq->va   = va;
	rq->dir  = op;
	if (op == SIR_F_ATOMIC_CAS) {
		rq->len = 16;
		memcpy(rq->data, &compare, 8);
		memcpy(rq->data + 8, &swap_or_add, 8);
	} else {
		rq->len = 8;
		memcpy(rq->data, &swap_or_add, 8);
	}

	pthread_mutex_lock(&g_mu);
	if (!S->connected) {
		pthread_mutex_unlock(&g_mu);
		free(rq);
		errno = ENOTCONN;
		return -1;
	}
	rq->tag = S->tag_hi | (S->next_tag++ & 0x7fffffffu);
	rq->next = NULL;
	if (S->req_tail)
		S->req_tail->next = rq;
	else
		S->req_head = rq;
	S->req_tail = rq;
	S->requested++;

	/* 等待服务线程处理 (同 repair: 50×100ms = 5s) */
	for (i = 0; i < 50 && !rq->done; i++) {
		struct timespec ts;

		clock_gettime(CLOCK_REALTIME, &ts);
		ts.tv_nsec += 100 * 1000 * 1000;
		if (ts.tv_nsec >= 1000 * 1000 * 1000) {
			ts.tv_sec += 1;
			ts.tv_nsec -= 1000 * 1000 * 1000;
		}
		pthread_cond_timedwait(&g_cv, &g_mu, &ts);
	}
	if (!rq->done) {
		errno = ETIMEDOUT;
	} else if (rq->ret != 0) {
		errno = (int)rq->reply.status ? (int)rq->reply.status : EIO;
	} else {
		ret = 0;
		if (old_out && rq->reply.type == SIR_MSG_ATOMIC_OK)
			memcpy(old_out, rq->reply.data, 8);
	}
	/* 摘除 (正常已被服务线程出队; 兜底) — 同 repair: 清 pending 防 UAF */
	if (S->pending_req == rq) {
		S->pending_req = NULL;
		S->pending_tag = 0;
	}
	for (pp = &S->req_head; *pp; pp = &(*pp)->next)
		if (*pp == rq) {
			*pp = rq->next;
			if (!*pp)
				S->req_tail = NULL;
			break;
		}
	pthread_mutex_unlock(&g_mu);
	free(rq);
	return ret;
}

int sir_is_connected(void)
{
	int c;
	pthread_mutex_lock(&g_mu);
	c = S && S->connected;
	pthread_mutex_unlock(&g_mu);
	return c;
}
long sir_service_count(void)
{
	long c;
	pthread_mutex_lock(&g_mu);
	c = S ? S->served : 0;
	pthread_mutex_unlock(&g_mu);
	return c;
}

void sir_fini(void)
{
	if (!S)
		return;
	pthread_mutex_lock(&g_mu);
	S->quit = 1;
	if (S->serving) {
		pthread_mutex_unlock(&g_mu);
		pthread_join(S->thread, NULL);
		pthread_mutex_lock(&g_mu);
		S->serving = 0;
	}
	sir_tcp_close_locked();
	pthread_mutex_unlock(&g_mu);
	sir_log("sir_fini: 服务线程已停");
}
