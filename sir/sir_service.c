/* SPDX-License-Identifier: GPL-2.0 */
/*
 * sir_service.c — SIR owner 服务 (v0.24.7 自 sir.c 拆分)
 *
 * 控制通道收发原语 (post_recv/ensure_recv/send_raw — SEND 完成与对端
 * 应答乱序到达的缓存处理) + REPAIR/ATOMIC 请求处理 (owner 侧 ioctl
 * REPAIR / 远端 CPU 原子) + 服务线程 (独占控制 CQ, 单点消费, 代发
 * requester 排队请求)。角色与协议详见 sir/sir.h 与 sir_internal.h。
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/ioctl.h>
#include <poll.h>
#include <infiniband/verbs.h>
#include "sir.h"
#include "sir_internal.h"

/* ---- 控制通道原语 (调用方持 g_mu) ---- */

/* v0.38.2: P1-1 回归注入 (单发) — env live 读取 (同引擎
 * NPRDMA_FAULT_REPAIR_FAIL 惯例, 修复路径罕见, 开销可忽略)。
 * SYMRDMA_SIR_FAULT_RESENTINEL=1 时首次命中后熔断 (fire once)。 */
static int sir_fault_resentinel_once(void)
{
	static int fired;
	const char *m;

	if (fired)
		return 0;
	m = getenv("SYMRDMA_SIR_FAULT_RESENTINEL");
	if (!m || !*m || *m == '0')
		return 0;
	fired = 1;
	return 1;
}

static int sir_post_recv(void)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)S->ctl_in, .length = SIR_MSG_SIZE,
		.lkey = S->in_mr->lkey,
	};
	struct ibv_recv_wr wr = {0}, *bad = NULL;
	int (*post_recv)(struct ibv_qp *, struct ibv_recv_wr *,
			 struct ibv_recv_wr **) =
		S->ctl_qp->context->ops.post_recv;

	if (!post_recv)
		return -1;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	if (post_recv(S->ctl_qp, &wr, &bad))
		return -1;
	S->have_recv = 1;
	return 0;
}

/* 只在无在途 recv 时补一个 (乒乓不变式) */
static void sir_ensure_recv(void)
{
	if (!S->have_recv)
		sir_post_recv();
}

/* 同步发送并等 SEND 完成; 期间到达的 RECV (对端应答/请求) 缓存到
 * S->saved 由主循环单点处理 (SEND/RECV 完成序不保证) */
static int sir_send_raw(const struct sir_msg *m)
{
	struct ibv_sge sge = {
		.addr = (uintptr_t)S->ctl_out, .length = SIR_MSG_SIZE,
		.lkey = S->out_mr->lkey,
	};
	struct ibv_send_wr wr = {0}, *bad = NULL;
	struct ibv_wc wc;
	int (*post_send)(struct ibv_qp *, struct ibv_send_wr *,
			 struct ibv_send_wr **) =
		S->ctl_qp->context->ops.post_send;
	int (*poll_cq)(struct ibv_cq *, int, struct ibv_wc *) =
		S->ctl_cq->context->ops.poll_cq;
	int n, spins = 0;

	if (!post_send || !poll_cq)
		return -1;
	memcpy(S->ctl_out, m, sizeof(*m));
	wr.opcode = IBV_WR_SEND;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
	if (post_send(S->ctl_qp, &wr, &bad)) {
		sir_log("SEND 失败 errno=%d", errno);
		return -1;
	}
	for (;;) {
		n = poll_cq(S->ctl_cq, 1, &wc);
		if (n < 0) {
			sir_log("poll_cq 错误 %d", n);
			return -1;
		}
		if (n > 0) {
			if (wc.status != IBV_WC_SUCCESS) {
				sir_log("SEND WC 异常 status=%d",
					(int)wc.status);
				return -1;
			}
			if (wc.opcode == IBV_WC_SEND)
				return 0;
			/* RECV 完成 (对端应答提前到达): 缓存, 补 recv */
			S->have_recv = 0;
			if (!S->saved_valid && S->ctl_in) {
				memcpy(&S->saved, S->ctl_in,
				       sizeof(struct sir_msg));
				S->saved_valid = 1;
			}
			sir_post_recv();
			continue;
		}
		if (++spins > 20000) {      /* ~2s 超时 */
			sir_log("SEND 等完成超时");
			errno = ETIMEDOUT;
			return -1;
		}
		usleep(100);
	}
}

/* ---- owner 服务: 处理远端 REPAIR 请求 (调用方持 g_mu) ---- */

static void sir_serve_repair(const struct sir_msg *m)
{
	struct sir_msg reply;
	struct sir_export *e;
	int found = 0;
	/* 区间修复 (v0.36.0, 论文 §3.2): mlen>1 → 整段区间修复 (v0.37.0 起
	 * owner 侧单次内核区间批量 ioctl, 不再逐页); SIR_RANGE_MAX 防御恶意
	 * /损坏消息; mlen 0/1 = 单页 (旧请求方兼容)。内联数据仅单页语义。 */
	unsigned long npages = m->mlen ? m->mlen : 1;
	unsigned long repaired = 0;

	if (npages > SIR_RANGE_MAX)
		npages = SIR_RANGE_MAX;
	if (npages > 1 && (m->off || m->len)) {
		/* 区间请求不允许内联数据 (发起方 sir_remote_repair_range
		 * 已拒; 双重防御) */
		npages = 1;
	}

	memset(&reply, 0, sizeof(reply));
	reply.magic = SIR_MAGIC;
	reply.tag   = m->tag;
	reply.type  = SIR_MSG_REPAIR_FAIL;

	for (e = S->exports; e; e = e->next)
		if (e->data_rkey == m->rkey || e->write_rkey == m->rkey) {
			found = 1;
			break;
		}
	if (!found || S->sym_fd < 0 || e->mr_id < 0) {
		reply.status = ENOENT;
		goto out;
	}
	{
		/* 区间批量 ioctl (v0.37.0): 单次 REPAIR_RANGE 整段修复 — 内核
		 * 批量 GUP + 分块 gather 批量 flush (取代 v0.36.0 逐页 ioctl,
		 * ~7-10µs/页, 大消息 race 吞吐被 ODP 反超的主导开销)。
		 * out npages = 实际修复页数: 部分成功即停 (fail-closed 保留前缀,
		 * 剩余页由请求方乐观路径重检再触发 — 与旧逐页循环停机语义兼容,
		 * 区别仅在失败前的前缀不再丢弃); 首次调用即失败则整请求 FAIL。 */
		struct symrdma_ioc_repair_range rr = {
			.mr_id = e->mr_id,
			.page_idx = m->page_idx,
		};
		unsigned long total = 0, remaining = npages;

		if (S->no_range_ioctl)
			goto legacy_loop;   /* 旧模块 (无 cmd 11) → 逐页降级 */
		while (remaining) {
			unsigned long want = remaining;

			rr.page_idx = m->page_idx + total;
			rr.npages   = want;
			if (ioctl(S->sym_fd, SYMRDMA_IOC_REPAIR_RANGE, &rr)) {
				if (errno == ENOTTY && total == 0) {
					/* 旧内核模块未升级 — 一次性降级缓存 */
					S->no_range_ioctl = 1;
					sir_log("REPAIR_RANGE ENOTTY — "
						"降级逐页 REPAIR (旧模块)");
					goto legacy_loop;
				}
				if (total == 0) {
					reply.status = (uint32_t)errno;
					goto out;
				}
				break;   /* 前缀已修复, 保留 */
			}
			if (rr.npages == 0 || rr.npages > want) {
				/* 防御: ret==0 保证 ≥1 页 (内核契约) */
				break;
			}
			total    += rr.npages;
			remaining = want - rr.npages;
			if (rr.npages < want)
				break;   /* 部分成功 — GUP 前缀语义 */
		}
		repaired = total;
		goto repair_done;
	}
legacy_loop: {
		/* v0.36.0 逐页回退 (旧模块兼容路径): 每页 ioctl REPAIR (GUP +
		 * IOMMU 重映射 + 版本翻转; 幂等 — 已驻留页恒等不翻转)。
		 * 任一页失败即停; 已成功前缀保留 (同新区间语义)。 */
		struct symrdma_ioc_repair rp = {
			.mr_id = e->mr_id,
		};
		unsigned long k;

		for (k = 0; k < npages; k++) {
			rp.page_idx = m->page_idx + k;
			if (ioctl(S->sym_fd, SYMRDMA_IOC_REPAIR, &rp)) {
				if (repaired == 0) {
					reply.status = (uint32_t)errno;
					goto out;
				}
				break;
			}
			repaired++;
		}
	}
repair_done:
	/* v0.38.2 P1-1 回归注入 (L12 子测 2b): SYMRDMA_SIR_FAULT_RESENTINEL=1
	 * — 首次非内联读修复成功后把该页 REMAP→SENTINEL (IOMMU 回哨兵 +
	 * 版本翻偶, 与真实换出语义一致), 确定性复现 "owner REPAIR → 应答
	 * → 客户端重放" 窗口内的二次换出竞态 — 旧 libsymrdma 小读 >1KB
	 * 分支以 SUCCESS 交付哨兵魔数的根因场景。
	 * 触发面收紧: 仅 SIR_F_READ 且非内联 (m->len==0) = 唯一漏网分支
	 * 的调用形态; 单发 (sir_fault_resentinel_once); 默认关闭。 */
	if ((m->flags & SIR_F_READ) && m->len == 0 && repaired >= 1 &&
	    S->sym_fd >= 0 && e->mr_id >= 0 &&
	    sir_fault_resentinel_once()) {
		struct symrdma_ioc_remap rm = {
			.mr_id     = e->mr_id,
			.page_idx  = m->page_idx,
			.mode      = 1,   /* SENTINEL */
		};

		if (!ioctl(S->sym_fd, SYMRDMA_IOC_REMAP, &rm))
			sir_log("FAULT 注入: REPAIR 后重哨兵化 page=%lu "
				"(P1-1 二次换出竞态复现)", m->page_idx);
	}
	/* 内联数据 (≤1KB, 不跨页): WR=落地真实页; RD=从真实页取回 */
	if (m->len && m->len <= SIR_INLINE_MAX &&
	    m->off + m->len <= SIR_PAGE_SIZE) {
		void *page = (void *)(uintptr_t)(e->addr +
				      m->page_idx * SIR_PAGE_SIZE);

		if (m->flags & SIR_F_WRITE)
			memcpy((char *)page + m->off, m->data, m->len);
		else
			memcpy(reply.data, (char *)page + m->off, m->len);
	}
	reply.type   = SIR_MSG_REPAIR_OK;
	reply.flags  = m->flags;
	reply.off    = m->off;
	reply.len    = m->len;
	reply.mlen   = repaired;
	S->served++;
out:
	sir_log("服务 REPAIR rkey=0x%x page=%lu npages=%lu (%s) → %s (修复 %lu)",
		m->rkey, m->page_idx, npages,
		(m->flags & SIR_F_WRITE) ? "WR" : "RD",
		reply.type == SIR_MSG_REPAIR_OK ? "OK" : "FAIL", repaired);
	sir_send_raw(&reply);
}

/* ---- owner 服务: 处理远端原子请求 (v0.20.0, 论文 §3.4; 持 g_mu) ----
 *
 * 远端 CPU 执行 (lock cmpxchg / lock xadd, 同 test_atomic): 经正常
 * MMU 路径访问 — 缺失页触发 OS 缺页换入, 无 NIC 部分执行风险。
 * 执行后 ioctl REPAIR 刷新双 IOVA 映射 + 版本翻转 (惰性换入语义:
 * CPU 缺页换入后 IOMMU 可能仍指哨兵, 后续远端 one-sided 访问需真实页)。
 */
static void sir_serve_atomic(const struct sir_msg *m)
{
	struct sir_msg reply;
	struct sir_export *e;
	volatile uint64_t *p;
	uint64_t old = 0;
	int found = 0;

	memset(&reply, 0, sizeof(reply));
	reply.magic = SIR_MAGIC;
	reply.tag   = m->tag;
	reply.type  = SIR_MSG_REPAIR_FAIL;

	for (e = S->exports; e; e = e->next)
		if (e->data_rkey == m->rkey) {
			found = 1;
			break;
		}
	if (!found) {
		reply.status = ENOENT;
		goto out;
	}
	if (m->addr < e->addr || m->addr + 8 > e->addr + e->len ||
	    (m->addr & 7)) {
		/* v0.24.6: 对齐检查 — 非齐 8B 目标会令远端 CPU 原子指令
		 * SIGBUS 击杀 owner 进程 (lock cmpxchg/xadd 要求对齐) */
		reply.status = EFAULT;
		goto out;
	}
	p = (volatile uint64_t *)(uintptr_t)m->addr;
	if (m->flags & SIR_F_ATOMIC_CAS) {
		uint64_t cmp, swp;

		if (m->len != 16) {
			reply.status = EINVAL;
			goto out;
		}
		memcpy(&cmp, m->data, 8);
		memcpy(&swp, m->data + 8, 8);
		old = __sync_val_compare_and_swap(p, cmp, swp);
	} else if (m->flags & SIR_F_ATOMIC_FAA) {
		uint64_t add;

		if (m->len != 8) {
			reply.status = EINVAL;
			goto out;
		}
		memcpy(&add, m->data, 8);
		old = __sync_fetch_and_add(p, add);
	} else {
		reply.status = EINVAL;
		goto out;
	}
	/* 惰性换入: 刷新 IOMMU (幂等 — 驻留页修复不翻转版本) */
	if (S->sym_fd >= 0 && e->mr_id >= 0) {
		struct symrdma_ioc_repair rp = {
			.mr_id = e->mr_id,
			.page_idx = (unsigned long)((m->addr - e->addr) /
						    SIR_PAGE_SIZE),
		};
		ioctl(S->sym_fd, SYMRDMA_IOC_REPAIR, &rp);
	}
	reply.type = SIR_MSG_ATOMIC_OK;
	reply.len  = 8;
	memcpy(reply.data, &old, 8);
	S->served++;
out:
	sir_log("服务 ATOMIC rkey=0x%x addr=0x%llx (%s) → %s old=0x%llx",
		m->rkey, (unsigned long long)m->addr,
		(m->flags & SIR_F_ATOMIC_CAS) ? "CAS" : "FAA",
		reply.type == SIR_MSG_ATOMIC_OK ? "OK" : "FAIL",
		(unsigned long long)old);
	sir_send_raw(&reply);
}

/* 消息处理 (调用方持 g_mu) */
static void sir_process_msg(const struct sir_msg *m)
{
	if (m->magic != SIR_MAGIC) {
		/* v0.36.0 诊断增强: 转储头部 24B (定位污染源 — racebw 实测
		 * 控制通道偶发收到哨兵魔数 0xdeadbeef) */
		sir_log("坏消息 magic=0x%x type=0x%x tag=0x%x rkey=0x%x "
			"hdr=%02x %02x %02x %02x %02x %02x %02x %02x",
			m->magic, m->type, m->tag, m->rkey,
			((const unsigned char *)m)[0], ((const unsigned char *)m)[1],
			((const unsigned char *)m)[2], ((const unsigned char *)m)[3],
			((const unsigned char *)m)[4], ((const unsigned char *)m)[5],
			((const unsigned char *)m)[6], ((const unsigned char *)m)[7]);
		return;
	}
	if (m->type == SIR_MSG_REPAIR) {
		sir_serve_repair(m);
	} else if (m->type == SIR_MSG_ATOMIC) {
		sir_serve_atomic(m);
	} else if (m->type == SIR_MSG_QUIT) {
		S->quit = 1;
	} else if ((m->type == SIR_MSG_REPAIR_OK ||
		    m->type == SIR_MSG_ATOMIC_OK ||
		    m->type == SIR_MSG_REPAIR_FAIL) &&
		   S->pending_tag && m->tag == S->pending_tag) {
		struct sir_req *rq = S->pending_req;

		if (rq) {
			rq->reply = *m;
			rq->ret = (m->type == SIR_MSG_REPAIR_FAIL) ? -1 : 0;
			rq->done = 1;
			sir_log("应答匹配: tag=0x%x type=%u → 唤醒 requester",
				m->tag, m->type);
			pthread_cond_broadcast(&g_cv);
			/* 从队头移除 (FIFO: 待应答的必是队头) */
			if (S->req_head == rq) {
				S->req_head = rq->next;
				if (!S->req_head)
					S->req_tail = NULL;
			}
		}
		S->pending_tag = 0;
		S->pending_req = NULL;
	} else {
		sir_log("未知消息 type=%u tag=0x%x", m->type, m->tag);
	}
}

/* ---- 服务线程 (独占控制 CQ; 单点消费) ---- */

void *sir_thread_main(void *arg)   /* internal.h 声明; ensure_channel 建线程 */
{
	int (*poll_cq)(struct ibv_cq *, int, struct ibv_wc *) = NULL;
	int idle = 0;

	(void)arg;
	pthread_mutex_lock(&g_mu);
	poll_cq = S->ctl_cq->context->ops.poll_cq;
	if (!poll_cq) {
		pthread_mutex_unlock(&g_mu);
		return NULL;
	}
	sir_ensure_recv();

	while (!S->quit) {
		struct ibv_wc wc;
		int n;

		/* 1. 缓存消息优先 */
		if (S->saved_valid) {
			struct sir_msg m = S->saved;

			S->saved_valid = 0;
			sir_process_msg(&m);
			sir_ensure_recv();
			idle = 0;
			continue;
		}
		n = poll_cq(S->ctl_cq, 1, &wc);
		if (n > 0) {
			idle = 0;
			if (wc.status != IBV_WC_SUCCESS) {
				sir_log("控制 CQ WC 异常 status=%d",
					(int)wc.status);
				S->have_recv = 0;
				sir_ensure_recv();
				continue;
			}
			if (wc.opcode != IBV_WC_RECV)
				continue;          /* SEND 完成, 忽略 */
			S->have_recv = 0;
			{
				struct sir_msg m;

				memcpy(&m, S->ctl_in, sizeof(m));
				sir_process_msg(&m);
				sir_ensure_recv();
			}
			continue;
		}
		if (n < 0) {
			sir_log("poll_cq 错误 %d (线程退出)", n);
			break;
		}

		/* 2. 无完成: 代发排队请求 (一次一条) */
		if (!S->pending_tag && S->req_head) {
			struct sir_req *rq = S->req_head;
			struct sir_msg m = {0};

			m.magic = SIR_MAGIC;
			if (rq->dir == SIR_F_ATOMIC_CAS ||
			    rq->dir == SIR_F_ATOMIC_FAA) {
				/* v0.20.0: 远端原子 (addr=目标 VA, 操作数内联) */
				m.type  = SIR_MSG_ATOMIC;
				m.flags = (uint32_t)rq->dir;
				m.addr  = rq->va;
				m.len   = rq->len;
				memcpy(m.data, rq->data, rq->len);
			} else {
				m.type  = SIR_MSG_REPAIR;
				m.flags = (rq->dir == SIR_F_WRITE) ?
						  SIR_F_WRITE : SIR_F_READ;
				m.page_idx = rq->page_idx;
				m.mlen  = rq->npages;   /* 区间修复 (v0.36.0);
							 * 1/0 = 单页 (向后兼容) */
				m.off   = rq->off;
				m.len   = rq->len;
				if (rq->len && rq->len <= SIR_INLINE_MAX)
					memcpy(m.data, rq->data, rq->len);
			}
			m.tag   = rq->tag;
			m.rkey  = rq->rkey;
			pthread_mutex_unlock(&g_mu);
			if (sir_send_raw(&m) == 0) {
				S->pending_tag = rq->tag;
				S->pending_req = rq;
			}
			pthread_mutex_lock(&g_mu);
			if (S->pending_tag != rq->tag) {
				/* SEND 失败: 出队并失败该请求 */
				if (S->req_head == rq) {
					S->req_head = rq->next;
					if (!S->req_head)
						S->req_tail = NULL;
				}
				rq->ret = -1;
				rq->done = 1;
				pthread_cond_broadcast(&g_cv);
			}
			continue;
		}
		/* 3. TCP 会合 (v0.32.0): 机遇式服务对端积压 GET — owner 侧无主动
		 * pull, 若不消费则对端拉取永久超时且对端导出变更不可见。持锁
		 * poll(0) 非阻塞探测; 读一条完整行 (对端整行发送, 4 字节 GET 实际
		 * 不阻塞) 后应答 INFO — 单锁 I/O 纪律不变。 */
		if (S->use_tcp && S->tcp_fd >= 0)
			sir_tcp_opportunistic_locked();

		if (++idle > 100) {
			idle = 0;
			pthread_mutex_unlock(&g_mu);
			/* v0.36.0: 空闲停饥 1ms→200µs — 论文 §3.2 "共享轮询线程"
			 * 设计取向; 1ms 停饥在锁步修复链上两端叠加, 修复 RTT 膨胀至
			 * ~3ms (racebw Fig 12 实测小消息吞吐被支配)。200µs 唤醒率
			 * 对 CPU 开销可忽略 (仅完全空闲时)。 */
			usleep(200);
			pthread_mutex_lock(&g_mu);
		}
	}
	pthread_mutex_unlock(&g_mu);
	return NULL;
}
