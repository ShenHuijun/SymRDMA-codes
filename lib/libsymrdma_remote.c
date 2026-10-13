/* SPDX-License-Identifier: GPL-2.0 */
/*
 * libsymrdma_remote.c — SymRDMA 远端 MR 路径 (;  自
 * libsymrdma.c 拆分独立编译单元)
 *
 * 目标 MR 属对端进程 (owner): 本进程无 ioctl/版本表。缺页修复经
 * SIR 通道 (sir/sir.c) 请求 owner 在其进程内 ioctl REPAIR; 版本号经
 * 调用方数据 QP 远端 RDMA 直读 owner Version MR (4B/页)。
 * 修复数据面: ≤1KB 内联 (论文 §3.2), >1KB → owner REPAIR + 重放。
 * 共享原语 (哨兵检测/单次 Read) 见 libsymrdma_internal.h。
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include "libsymrdma.h"
#include "libsymrdma_internal.h"
#include "sir.h"
#include "sentinel.h"   /* 哨兵扫描原语 (R2: 与引擎单一实现) */

/* seqlock 路径单次覆盖的最大页数 (64→1024 = 4MB, 论文 Fig 12
 * 大消息尺寸上限; v1/v2 数组堆分配, 版本块 = 1024×4B = scratch 页大小) */
#define SYMRDMA_MAX_SEQLOCK_PAGES 1024

/* ================================================================
 *  远端 MR (透明 API 远端形态, SIR 自动修复)
 *
 * 目标 MR 属对端进程 (owner): 本进程无 ioctl/版本表。缺页修复经
 * SIR 通道 (sir/sir.c) 请求 owner 在其进程内 ioctl REPAIR; 版本号经
 * 调用方数据 QP 远端 RDMA 直读 owner Version MR (4B/页)。
 * 修复数据面: ≤1KB 内联 (论文 §3.2), >1KB → owner REPAIR + 重放。
 * ================================================================ */

/* 远端 REPAIR (SIR 通道; 仅 owner 页) */
static int remote_repair(struct symrdma_mr *mr, unsigned long page_idx,
			 int dir, uint32_t off, uint32_t len, void *data)
{
	return sir_remote_repair(mr->rkey, page_idx, dir, off, len, data);
}

/* R2: sentinel_repair_all 逐命中页回调 — 大读无版本表路径,
 * 单页 SIR REPAIR (SIR_F_READ; 与引擎 npr_sir_repair_cb 同构) */
static int remote_repair_cb(void *ud, unsigned long pg)
{
	return remote_repair(ud, pg, SIR_F_READ, 0, 0, NULL);
}

/* 批量版本读 (论文 §3.1.2 版本表连续内存语义): 一次 RDMA Read
 * 拉 npages×4B (而非逐页一 RTT) — 版本检查开销 = 带宽 4B/页 + 常数
 * RTT, 大消息 seqlock 形态的关键 (论文 "the read overhead is 8 bytes
 * per page" 的批量读实现)。npages 超过 scratch 容量时内部分块。
 *  加固: 版本值含哨兵魔数 → scratch 页被外部失效源 (NUMA/迁移)
 * 哨兵化 (远端读到的"版本"是哨兵页内容) → 本地 ioctl 修复 scratch 后
 * 重读一次 (Scratch 是 SymRDMA MR, 可经本地 REPAIR 恢复)。
 * 返回 0 成功; -1 失败。 */
static int remote_version_range_get(struct symrdma_ctx *ctx,
				    struct ibv_qp *qp, struct ibv_cq *cq,
				    struct symrdma_mr *mr,
				    unsigned long page_idx,
				    unsigned long npages, uint32_t *out)
{
	unsigned long chunk_max, done = 0;

	if (!mr->v_rkey || !mr->scratch) {
		errno = ENOTSUP;
		return -1;
	}
	chunk_max = mr->scratch->len / sizeof(uint32_t);
	if (!chunk_max)
		chunk_max = 1;
	while (done < npages) {
		unsigned long chunk = npages - done;
		unsigned long i, hits = 0;

		if (chunk > chunk_max)
			chunk = chunk_max;
		if (rdma_read_once(qp, cq, mr->scratch->buf,
				   mr->scratch->ibv_mr->lkey,
				   mr->v_addr + 4u * (page_idx + done),
				   mr->v_rkey,
				   chunk * sizeof(uint32_t)))
			return -1;
		memcpy(out + done, mr->scratch->buf,
		       chunk * sizeof(uint32_t));
		for (i = 0; i < chunk; i++)
			if (out[done + i] == SYMRDMA_SENTINEL_MAGIC)
				hits++;
		if (hits) {
			/* scratch 哨兵化 → 本地修复 + 重读一次 */
			fprintf(stderr,
				"  [libsymrdma] scratch 版本块含哨兵 (%lu/%lu) "
				"→ 本地 REPAIR scratch\n",
				hits, chunk);
			if (symrdma_repair_page(ctx, mr->scratch, 0))
				return -1;
			if (rdma_read_once(qp, cq, mr->scratch->buf,
					   mr->scratch->ibv_mr->lkey,
					   mr->v_addr + 4u * (page_idx + done),
					   mr->v_rkey,
					   chunk * sizeof(uint32_t)))
				return -1;
			memcpy(out + done, mr->scratch->buf,
			       chunk * sizeof(uint32_t));
		}
		done += chunk;
	}
	return 0;
}

/* 连续偶数 (缺失) 页 run 合并 → 区间修复: 全跨度缺失
 * (minor/major 基准口径) 时整段一次 SIR RTT, 取代逐页 RTT。
 * 返回 0 全部 run 修复成功; -1 失败 (fail-fast)。 */
static int repair_even_runs(struct symrdma_mr *mr, unsigned long page_idx,
			    const uint32_t *v, unsigned long npages, int dir)
{
	unsigned long p = 0;

	while (p < npages) {
		unsigned long s;

		if (v[p] & 1) {
			p++;
			continue;
		}
		s = p;
		while (p < npages && !(v[p] & 1))
			p++;
		if (sir_remote_repair_range(mr->rkey, page_idx + s, p - s,
					    dir, 0, 0, NULL))
			return -1;
	}
	return 0;
}

/* 远端裸 RDMA Write (rkey = owner wkey, 目标 = owner VA, 恒等) */
static int remote_write_raw(struct ibv_qp *qp, struct ibv_cq *cq,
			    struct symrdma_mr *mr, unsigned long page_idx,
			    size_t len, const void *local, uint32_t lkey,
			    int signaled)
{
	struct ibv_sge sge = {
		.addr   = (uintptr_t)local,
		.length = (uint32_t)len,
		.lkey   = lkey,
	};
	struct ibv_send_wr wr = {0}, *bad_wr = NULL;
	struct ibv_wc wc;
	int n;

	wr.opcode              = IBV_WR_RDMA_WRITE;
	wr.sg_list             = &sge;
	wr.num_sge             = 1;
	wr.wr.rdma.remote_addr = (uintptr_t)mr->buf + page_idx * SYMRDMA_PAGE_SIZE;
	wr.wr.rdma.rkey        = mr->wkey;
	wr.send_flags          = signaled ? IBV_SEND_SIGNALED : 0;

	if (ibv_post_send(qp, &wr, &bad_wr))
		return -1;
	if (!signaled)
		return 0;
	do {
		n = ibv_poll_cq(cq, 1, &wc);
	} while (n == 0);
	if (n < 0 || wc.status != IBV_WC_SUCCESS)
		return -1;
	return 0;
}

/* ---- 远端乐观读 ---- */

int symrdma_read_remote(struct symrdma_ctx *ctx, struct ibv_qp *qp,
			       struct ibv_cq *cq, struct symrdma_mr *mr,
			       unsigned long page_idx, size_t len,
			       void *local, uint32_t lkey)
{
	uintptr_t remote;
	unsigned long npages =
		(len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	int attempt, p;

	/* 越界防护 (同本地) */
	if (len == 0 || !mr->buf || page_idx >= mr->len / SYMRDMA_PAGE_SIZE ||
	    npages > mr->len / SYMRDMA_PAGE_SIZE - page_idx) {
		errno = EINVAL;
		return -1;
	}
	if (npages > SYMRDMA_MAX_SEQLOCK_PAGES) {
		errno = E2BIG;
		return -1;
	}
	remote = (uintptr_t)mr->buf + page_idx * SYMRDMA_PAGE_SIZE;

	/* ---- 小读 (<4KB, 单页): 哨兵检测 → SIR 修复 ----
	 * 论文口径 "<4KB 走哨兵, ≥4KB 走 seqlock",
	 * 原 len <= 4096 使 4KB 整页读走哨兵, 与 seqlock 路径 (remote.c:550
	 * len > THRESHOLD) 形成两可边界 — 统一为半开区间 [4096, ∞) → seqlock */
	if (len < SYMRDMA_SENTINEL_THRESHOLD) {
		for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
			if (rdma_read_once(qp, cq, local, lkey, remote,
					   mr->rkey, len))
				return -1;
			if (!buf_is_sentinel(local, len, remote))
				return 0;
			fprintf(stderr,
				"  [libsymrdma] remote sentinel: 页 %lu → SIR REPAIR\n",
				page_idx);
			if (len <= SIR_INLINE_MAX) {
				/* ≤1KB: owner 修复后内联回数据, 免重放 */
				if (remote_repair(mr, page_idx, SIR_F_READ, 0,
						  (uint32_t)len, local))
					return -1;
				return 0;
			}
			/* >1KB: owner REPAIR → 重放 → 复验 (P1-1 修复:
			 * 旧代码修复+重放后无条件接受 — 修复与重放窗口内页被
			 * 二次换出时, 重放读回整页哨兵仍以 SUCCESS 交付 0xdeadbeef。
			 * 同类路径均已闭环 (本地小读版本奇偶校验 / 引擎循环复验 /
			 *  大读末次复验 fail-closed), 本分支为唯一漏网) */
			if (remote_repair(mr, page_idx, SIR_F_READ, 0, 0, NULL))
				return -1;
			if (rdma_read_once(qp, cq, local, lkey, remote,
					   mr->rkey, len))
				return -1;
			if (!buf_is_sentinel(local, len, remote))
				return 0;   /* 修复后干净 */
			/* 仍哨兵: (a) 修复→重放窗口二次换出 (真缺页, notifier
			 *     已把版本翻偶); (b) 真·假阳性 (驻留页数据恰=魔数,
			 *     版本仍奇)。
			 * 有版本表 → 奇偶判定 (本地路径 L4-7 同语义: 奇=驻留,
			 * 魔数即真实数据); 偶 → 下一轮再修复+重放。
			 * 无版本表 → 重试; 末次仍哨兵 → fail-closed EIO
			 * (大读无版本路径  同款 — 不以 SUCCESS 交付
			 * 可能为哨兵的数据)。 */
			if (mr->v_rkey && mr->scratch) {
				uint32_t v2 = 0;

				if (remote_version_range_get(ctx, qp, cq, mr,
							     page_idx, 1, &v2))
					return -1;
				if (v2 & 1)
					return 0;   /* 假阳性: 版本证驻留 */
				continue;   /* 二次换出 → 下一轮 */
			}
			if (attempt >= SYMRDMA_MAX_RETRIES - 1) {
				errno = EIO;
				return -1;
			}
			continue;
		}
		errno = EAGAIN;
		return -1;
	}

	/* ---- 大读 (>4KB): remote seqlock (owner Version MR 直读) ----
	 *  版本读批量化 (一次 RDMA Read 拉 npages×4B, 论文 §3.1.2
	 * "8 bytes per page" 连续表语义) + 连续缺失页 run 合并区间修复
	 * (§3.2 全跨度修复) — 大消息故障路径从 O(npages) 控制 RTT 降为
	 * O(runs) RTT, 论文 Fig 12 大消息形态的前提。
	 * 语义不变: 读前缺失页修复 + 读后版本比对 (变化/偶数 → 修复 →
	 * 整轮重试, ≤SYMRDMA_MAX_RETRIES)。 */
	if (mr->v_rkey && mr->scratch) {
		uint32_t *v1 = malloc(npages * sizeof(*v1));
		uint32_t *v2 = malloc(npages * sizeof(*v2));

		if (!v1 || !v2) {
			free(v1);
			free(v2);
			errno = ENOMEM;
			return -1;
		}
		for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
			int changed = 0, dirty = 0;

			if (remote_version_range_get(ctx, qp, cq, mr,
						     page_idx, npages, v1))
				goto out_fail;
			for (p = 0; p < (int)npages; p++)
				if (!(v1[p] & 1)) {
					dirty = 1;
					break;
				}
			/* 读前缺失页: run 合并区间修复 → 就地重取版本
			 * (同轮继续读, 免整轮重试的重复数据读) */
			if (dirty) {
				if (repair_even_runs(mr, page_idx, v1, npages,
						     SIR_F_READ))
					goto out_fail;
				if (remote_version_range_get(ctx, qp, cq, mr,
							     page_idx, npages,
							     v1))
					goto out_fail;
			}
			if (rdma_read_once(qp, cq, local, lkey, remote,
					   mr->rkey, len))
				goto out_fail;
			if (remote_version_range_get(ctx, qp, cq, mr,
						     page_idx, npages, v2))
				goto out_fail;
			for (p = 0; p < (int)npages; p++) {
				if (v2[p] != v1[p] || !(v2[p] & 1)) {
					changed = 1;
					break;
				}
			}
			if (!changed) {
				free(v1);
				free(v2);
				return 0;
			}
			/* 读期间换出竞态: run 合并修复后整轮重试 */
			if (repair_even_runs(mr, page_idx, v2, npages,
					     SIR_F_READ))
				goto out_fail;
		}
		errno = EAGAIN;
		goto out_fail;
	out_fail:
		free(v1);
		free(v2);
		return -1;
	}

	/* ---- 大读无版本表: 哨兵 chunk 扫描 + 逐命中页 SIR 修复 ----
	 * R2: 逐页双层 chunk 循环收敛至 sir/sentinel.h
	 * sentinel_repair_all (与引擎 npr_repair_all_missing 单一实现;
	 * 页号 = 命中 chunk 绝对地址相对导出基址 mr->buf, 与原
	 * page_idx + off/页大小 恒等; 升序/页去重/失败即停语义不变)。 */
	for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
		if (rdma_read_once(qp, cq, local, lkey, remote, mr->rkey, len))
			return -1;
		if (!buf_is_sentinel(local, len, remote))
			return 0;
		if (sentinel_repair_all(local, len, remote, (uintptr_t)mr->buf,
						remote_repair_cb, mr) < 0)
			return -1;
	}
	/* 修复后最终一次重放 —  必须再验哨兵; 修复不可达时
	 * (对端消失/竞态) 不得把哨兵魔数当真实数据交付 (fail closed) */
	if (rdma_read_once(qp, cq, local, lkey, remote, mr->rkey, len))
		return -1;
	if (buf_is_sentinel(local, len, remote)) {
		errno = EIO;
		return -1;
	}
	return 0;
}

/* ---- 远端乐观写 ---- */

/* 大写 (>4KB) 路径: remote seqlock — 写后逐页版本校验 (owner 版本表
 * 直读); 偶数 (写期间换出/黑洞吸收) → SIR 修复 → 整轮重写。
 * 语义依据: 版本懒同步 (换出→偶, 仅显式 REPAIR 翻奇) — 写后版本为奇
 * ⇔ 写期间无换出 ⇔ 全部 TLP 落地真实页 (owner 侧无自发 REPAIR)。 */
static int symrdma_write_remote_seqlock(struct symrdma_ctx *ctx,
					struct ibv_qp *qp, struct ibv_cq *cq,
					struct symrdma_mr *mr,
					unsigned long page_idx, size_t len,
					const void *local, uint32_t lkey)
{
	unsigned long npages = (len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	unsigned long mr_pages = mr->len / SYMRDMA_PAGE_SIZE;
	uint32_t *v1, *v2;
	int attempt, p;

	if (!mr->v_rkey || !mr->scratch) {
		errno = ENOTSUP;   /* 大写远端写需 owner Version MR */
		return -1;
	}
	if (page_idx >= mr_pages || npages > mr_pages - page_idx) {
		errno = EINVAL;
		return -1;
	}
	/* 版本读批量化 (一次 RDMA Read 拉 npages×4B) + 缺失页 run
	 * 合并区间修复 (§3.2 全跨度修复) — 同大读路径注记。 */
	v1 = malloc(npages * sizeof(*v1));
	v2 = malloc(npages * sizeof(*v2));
	if (!v1 || !v2) {
		free(v1);
		free(v2);
		errno = ENOMEM;
		return -1;
	}

	for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
		int changed = 0;

		/* 写前: 任一覆盖页缺失 → run 合并 SIR 区间修复 → 重取版本 */
		if (remote_version_range_get(ctx, qp, cq, mr, page_idx,
					     npages, v1))
			goto out;
		if (repair_even_runs(mr, page_idx, v1, npages, SIR_F_WRITE))
			goto out;
		if (remote_version_range_get(ctx, qp, cq, mr, page_idx,
					     npages, v1))
			goto out;

		if (remote_write_raw(qp, cq, mr, page_idx, len, local, lkey, 1))
			goto out;

		/* 写后: 版本比对 (变化/偶数 → run 合并修复 → 整轮重写) */
		if (remote_version_range_get(ctx, qp, cq, mr, page_idx,
					     npages, v2))
			goto out;
		for (p = 0; p < (int)npages; p++) {
			if (v2[p] != v1[p] || !(v2[p] & 1)) {
				changed = 1;
				break;
			}
		}
		if (changed) {
			if (repair_even_runs(mr, page_idx, v2, npages,
					     SIR_F_WRITE))
				goto out;
			continue;
		}
		free(v1);
		free(v2);
		return 0;
	}
	free(v1);
	free(v2);
	errno = EAGAIN;
	return -1;
out:
	free(v1);
	free(v2);
	errno = EAGAIN;
	return -1;
}

int symrdma_write_remote(struct symrdma_ctx *ctx, struct ibv_qp *qp,
				struct ibv_cq *cq, struct symrdma_mr *mr,
				unsigned long page_idx, size_t len,
				const void *local, uint32_t lkey)
{
	uint8_t snapshot[SYMRDMA_SENTINEL_THRESHOLD];
	unsigned long npages = (len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	int attempt;

	(void)ctx;
	if (len == 0 || !mr->buf || page_idx >= mr->len / SYMRDMA_PAGE_SIZE ||
	    npages > mr->len / SYMRDMA_PAGE_SIZE - page_idx) {
		errno = EINVAL;
		return -1;
	}
	if (len > sizeof(snapshot))
		return symrdma_write_remote_seqlock(ctx, qp, cq, mr, page_idx,
						    len, local, lkey);

	memcpy(snapshot, local, len);
	for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
		if (remote_write_raw(qp, cq, mr, page_idx, len, local, lkey, 1))
			return -1;
		/* 辅助 Read 读回 (owner 数据 MR) 比对快照 */
		if (rdma_read_once(qp, cq, (void *)local, lkey,
				   (uintptr_t)mr->buf + page_idx * SYMRDMA_PAGE_SIZE,
				   mr->rkey, len))
			return -1;
		if (!memcmp(local, snapshot, len))
			return 0;   /* 落地成功 */

		if (len <= SIR_INLINE_MAX) {
			/* ≤1KB: 内联 WR 修复 — owner REPAIR 后落地内联数据 */
			fprintf(stderr,
				"  [libsymrdma] remote write 页 %lu 未落地 → SIR 内联 WR\n",
				page_idx);
			memcpy((void *)local, snapshot, len);   /* 恢复源 */
			if (remote_repair(mr, page_idx, SIR_F_WRITE, 0,
					  (uint32_t)len, snapshot))
				return -1;
			return 0;
		}
		fprintf(stderr,
			"  [libsymrdma] remote write 页 %lu 未落地 → SIR REPAIR → 重写\n",
			page_idx);
		memcpy((void *)local, snapshot, len);   /* 恢复源 */
		if (remote_repair(mr, page_idx, SIR_F_WRITE, 0, 0, NULL))
			return -1;
	}
	errno = EAGAIN;
	return -1;
}

/* ---- 远端 MR 导入 (透明 API 远端形态) ---- */

int symrdma_mr_import_remote(struct symrdma_ctx *ctx, struct ibv_pd *pd,
			     struct symrdma_mr *mr,
			     uint32_t rkey, uint32_t wkey,
			     uint64_t addr, size_t len,
			     uint32_t v_rkey, uint64_t v_addr)
{
	struct symrdma_mr *scr;
	struct symrdma_mr stmp;
	void *spage;

	memset(mr, 0, sizeof(*mr));
	mr->mr_id = -1;
	mr->remote = 1;
	mr->rkey = rkey;
	mr->wkey = wkey;
	mr->buf = (void *)(uintptr_t)addr;
	mr->len = len;
	mr->v_rkey = v_rkey;
	mr->v_addr = v_addr;

	/* 惰性 SIR 初始化 (会合键 = env SYMRDMA_PEER; 通道建立推迟到首次修复) */
	(void)sir_init(pd->context, pd, NULL, ctx->fd);
	/* 提前建连: import 即触发自动通道建立 (对端晚到由后台重试兜底) */
	(void)sir_ensure_start();

	/* 本端 scratch 页 (版本读目标; 需注册为 LOCAL_WRITE MR —
	 * RDMA Read 的本地 SGE 须可 DMA 写) */
	spage = mmap(NULL, SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
		     MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (spage == MAP_FAILED)
		return -1;
	memset(spage, 0, SYMRDMA_PAGE_SIZE);
	mlock(spage, SYMRDMA_PAGE_SIZE);   /* 防回收哨兵化
					    * (NUMA 迁移残余窗口由
					    * 版本块哨兵检测 + 本地
					    * REPAIR 兑底) */
	scr = calloc(1, sizeof(*scr));
	if (!scr) {
		munmap(spage, SYMRDMA_PAGE_SIZE);
		return -1;
	}
	scr->mr_id = -1;
	scr->buf = spage;
	scr->len = SYMRDMA_PAGE_SIZE;
	if (symrdma_mr_register(ctx, pd, spage, SYMRDMA_PAGE_SIZE, &stmp) == 0) {
		*scr = stmp;
		scr->buf = spage;   /* register 保存 spage */
		mr->scratch = scr;
	} else {
		/* scratch 不可用 (如无 /dev/symrdma): 大读/大写降级,
		 * 小读哨兵路径不受影响 */
		free(scr);
		munmap(spage, SYMRDMA_PAGE_SIZE);
		mr->scratch = NULL;
	}
	return 0;
}

int symrdma_read(struct symrdma_ctx *ctx, struct ibv_qp *qp,
		 struct ibv_cq *cq, struct symrdma_mr *mr,
		 unsigned long page_idx, size_t len,
		 void *local, uint32_t lkey)
{
	uintptr_t remote = mr->read_iova + page_idx * SYMRDMA_PAGE_SIZE;
	/* ≥4KB 走 seqlock (半开区间, 与 remote.c
	 * 读路径的 len < THRESHOLD → 哨兵 配套) */
	int seqlock = len >= SYMRDMA_SENTINEL_THRESHOLD;
	unsigned long npages =
		(len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	uint32_t v1[SYMRDMA_MAX_SEQLOCK_PAGES];
	int attempt, p, changed;

	/* 远端 MR — 自动远端修复 (见 symrdma_read_remote) */
	if (mr->remote)
		return symrdma_read_remote(ctx, qp, cq, mr, page_idx, len,
					   local, lkey);

	/* (读侧): 页范围越界防护 (写侧已随 C1 加固) */
	if (len == 0 || page_idx >= mr->len / SYMRDMA_PAGE_SIZE ||
	    npages > mr->len / SYMRDMA_PAGE_SIZE - page_idx) {
		errno = EINVAL;
		return -1;
	}

	if (seqlock && npages > SYMRDMA_MAX_SEQLOCK_PAGES) {
		fprintf(stderr,
			"  [libsymrdma] seqlock: %lu 页超过上限 %d\n",
			npages, SYMRDMA_MAX_SEQLOCK_PAGES);
		return -1;
	}

	for (attempt = 0; attempt < SYMRDMA_MAX_RETRIES; attempt++) {
		uint32_t v2;

		if (seqlock) {
			/* 读前逐页版本号: 任一页偶数 (缺失) → 先修复再重试。
			 * 论文 §3.1.2: 8 bytes per page, 逐页校验 。 */
			changed = 0;
			for (p = 0; p < (int)npages; p++) {
				if (symrdma_get_version(ctx, mr,
							page_idx + p, &v1[p]))
					return -1;
				if (!(v1[p] & 1)) {
					fprintf(stderr,
						"  [libsymrdma] seqlock: 页 %lu 缺失 (v=%u) → REPAIR\n",
						page_idx + p, v1[p]);
					if (symrdma_repair_page(ctx, mr,
								page_idx + p))
						return -1;
					changed = 1;
				}
			}
			if (changed)
				continue;
		}

		if (rdma_read_once(qp, cq, local, lkey, remote,
				   mr->ibv_mr->rkey, len))
			return -1;

		if (!seqlock) {
			/* 哨兵检测: 每 256B chunk 检查 (论文 §3.1.1) —
			 * 读期间换出时前段 TLP 可能是真实数据, 首 4 字节会漏检 */
			if (!buf_is_sentinel(local, len, remote))
				return 0;
			fprintf(stderr,
				"  [libsymrdma] sentinel: 页 %lu 命中哨兵 → REPAIR\n",
				page_idx);
			if (symrdma_repair_page(ctx, mr, page_idx))
				return -1;
			/* 假阳性处理 (论文 §3.1.1: 数据恰等于魔数按修复路径
			 * 处理): 修复后以版本号为真实驻留依据 — 奇数即驻留,
			 * 避免"仍是魔数→再修复"死循环 (v0.9.0)。
			 * seqlock 语义: 重读前后版本相等且奇数才接受, 否则回退
			 * 重试循环 (continue → 外层重读 + 哨兵检测)。 */
			if (symrdma_get_version(ctx, mr, page_idx, &v2))
				return -1;
			if (v2 & 1) {
				uint32_t v3;

				if (rdma_read_once(qp, cq, local, lkey, remote,
							   mr->ibv_mr->rkey, len))
					return -1;
				if (symrdma_get_version(ctx, mr, page_idx,
							&v3))
					return -1;
				if (v3 == v2 && (v3 & 1))
					return 0;
				continue;
			}
			continue;
		}

		/* 读后逐页版本号: 任一页版本变化或偶数 → 修复该页 → 重试 */
		changed = 0;
		for (p = 0; p < (int)npages; p++) {
			if (symrdma_get_version(ctx, mr, page_idx + p, &v2))
				return -1;
			if (v2 != v1[p] || !(v2 & 1)) {
				fprintf(stderr,
					"  [libsymrdma] seqlock: 页 %lu 版本变化 %u→%u → REPAIR\n",
					page_idx + p, v1[p], v2);
				if (symrdma_repair_page(ctx, mr, page_idx + p))
					return -1;
				changed = 1;
				break;
			}
		}
		if (!changed)
			return 0;
	}

	errno = EAGAIN;
	return -1;
}
