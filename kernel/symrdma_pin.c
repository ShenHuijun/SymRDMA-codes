// SPDX-License-Identifier: GPL-2.0
/*
 * symrdma_pin.c — flush-before-unmap 屏障: 在飞页 pin 
 *
 * 论文 §3.2 临时 pin 语义 + §3.1.1 "IOMMU flush before reclaim" 的
 * 结构化实现。问题 (L14 实锤):
 *   notifier 在 invalidate_range_start 内 unmap(真实 PA)→map(哨兵) 的
 *   非原子窗口与在飞 DMA 相撞 → REM_ACCESS_ERR (L14 瞬态 57%);
 *   换出后 RDMA Read 目标页 / Write 源页被哨兵(只读)/黑洞吸收 →
 *   静默数据损坏 (L14 corrupt "整页零")。
 *
 * 机制: 用户态 (P1 库 _p 变体 / libnprdma 引擎) 在本地缓冲参与 DMA 前
 * 调 PIN_PAGES; 本文件 GUP 取页引用并逐页标记 pages[i].inflight++。
 * GUP 引用保证物理页在 pin 期间不被回收/复用 (PTE 仍可被 OS 换出,
 * 页留在 swap cache/page cache, PA 恒定 — L3-10 INFO 探针语义), 因此:
 *   - notifier (symrdma_notifier.c) 对 inflight>0 的页跳过哨兵化/
 *     版本翻转/orig_pa 清零 (延迟) — IOMMU 保持真实 PA;
 *   - UNPIN_PAGES / MR 拆卸时释放引用, 并对 PTE 已换出的页补完延迟
 *     转换 (哨兵/黑洞 + 版本翻转, 与 notifier 语义一致);
 *   - pin 期间若发生 COW-break/迁移类 PA 变化, unpin 探测到后直接
 *     重映射新 PA (在飞 DMA 已完成 — pin 由用户态在 WC 后释放;
 *     粘性 pin 场景重映射仅是 IOMMU 状态对齐, 内容竞争属应用层
 *     Host-Remote Race 既有语义)。
 *
 * pin 以 MR 为域粘性保持 (SYMRDMA_PIN_BUDGET_PAGES 封顶), 用户态以
 * 位图缓存镜像内核状态 → 稳态零 syscall。预算满返回 -ENOSPC, 由用户
 * 态 UNPIN(len=0) 全量释放后重试 — 内核绝不在用户态背后自动淘汰
 * (缓存一致性归用户态)。
 *
 * 锁序: st->lock (自旋) 保护 pin_list/pinned_pages/inflight — 与
 * notifier/REPAIR/驻留恢复工作项同锁串行化 (历史 A8 同族)。GUP、
 * follow_page 探测、put_page 等可睡眠/较重操作一律在锁外。
 * mmap 读锁仅在 UNPIN 探测路径使用 (属主进程上下文, 阻塞式 — 与
 * 驻留恢复工作项 b 取向一致)。
 *
 * 历史: 本文件原为预留 pfn 引用计数哈希表 (历史 注记 "无调用方,
 * 若 SIR 需要跨请求 pin 保持则接入, 切勿删除") —  由区间制
 * pin 实现承接该预留需求, 哈希表删除 (无调用方, dev->pin_lock 同步
 * 移除)。
 */
#include "symrdma.h"

/* 计算 [va, va+len) 的 MR 页区间; 返回 0 合法, 负值非法。
 * len 向上取整到页, 末尾裁剪到 MR 边界 (与注册取整语义一致)。 */
static int pin_span_idx(const struct symrdma_mr *mr, u64 va, u64 len,
			unsigned long *idx0, unsigned long *nr)
{
	u64 start, end;

	if (len == 0 || va < mr->va_start)
		return -EINVAL;
	/* 手写溢出防护 (check_add_overflow 的可移植写法) */
	end = va + len;
	if (end < va || end > mr->va_end)
		end = mr->va_end;
	if (end <= va)
		return -EINVAL;

	start = round_down(va, PAGE_SIZE);
	if (start < mr->va_start)
		start = mr->va_start;
	*idx0 = (start - mr->va_start) / PAGE_SIZE;
	*nr   = (end - start + PAGE_SIZE - 1) / PAGE_SIZE;
	if (*nr == 0 || *idx0 >= mr->npages)
		return -EINVAL;
	if (*idx0 + *nr > mr->npages)
		*nr = mr->npages - *idx0;
	return 0;
}

/* 单页延迟转换补完 (notifier 语义的 unpin 版): 读 IOVA → 哨兵 (只读),
 * 写 IOVA → 黑洞, 版本翻转 (仅状态转换), orig_pa 清零。
 * 调用方持 st->lock; 仅对仍处于 RESIDENT 的页生效 (并发 notifier/
 * REMAP 可能已转换 — 幂等)。 */
static void pin_complete_transition(struct symrdma_dev *dev,
				    struct symrdma_mr *mr, unsigned long i)
{
	if (mr->pages[i].read_state != PAGE_RESIDENT)
		return;
	symrdma_version_inc(mr, i);
	symrdma_remap_to_sentinel(dev, mr, i, i);
	symrdma_remap_to_blackhole(dev, mr, i, i);
	mr->pages[i].orig_pa = 0;
	atomic64_inc(&dev->stats.pin_transitions);
}

/* 单页 pin 就位: IOMMU 与真实驻留状态对齐 (PIN 自带 repair 语义 —
 * GUP 已把缺失页换入)。调用方持 st->lock; pa 由锁外 GUP 解析
 * (页引用已持有, PA 稳定)。
 * 记账 (b): read 态缺失→驻留的真实状态转换计入 repair_ok —
 * 与 REPAIR ioctl 同等工作 (swap-in + 重映射 + 版本恢复), L4 预检/
 * L6 post_send 预修复的“计数增加”断言随屏障语义成立; RESIDENT 态
 * 的陈旧 PA 对齐不算修复 (状态纠正)。 */
static int pin_align_page(struct symrdma_dev *dev, struct symrdma_mr *mr,
			   unsigned long i, phys_addr_t pa)
{
	struct symrdma_page_entry *pe = &mr->pages[i];
	u32 cur;

	if (pe->read_state == PAGE_RESIDENT &&
	    pe->write_state == PAGE_RESIDENT &&
	    pe->orig_pa == pa)
		return 0;   /* 已对齐 (热路径) */

	if (pe->read_state != PAGE_RESIDENT) {
		/* 哨兵 → 真实: 状态转换 (修复等价) — 版本恢复奇数 +
		 * 计入 repair_ok。
		 * 先重映射、后发布版本 — 反序会让远端在
		 * 窗口内看到 "奇版本 + 哨兵数据" (seqlock 误接受)。
		 * 重映射失败 (IOMMU 回滚哨兵态) → 不得发
		 * 布版本, 返回错误由调用方中止。 */
		if (symrdma_remap_to_real(dev, mr, i, pa))
			return -EIO;
		cur = symrdma_version_read(mr, i);
		if (!(cur & 1))
			symrdma_version_set(mr, i, cur + 1);
		pe->probe_fail = 0;   /* v0.26.0: 恢复可探测态 */
		atomic64_inc(&dev->stats.repair_ok);
	} else {
		/* 驻留态陈旧 PA / 写区黑洞残留 — 对齐修正 (非状态转换) */
		if (symrdma_remap_to_real(dev, mr, i, pa))
			return -EIO;
	}
	return 0;
}

int symrdma_pin_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
		      u64 va, u64 len)
{
	struct symrdma_pin_node *pn;
	struct symrdma_mm_state *st;
	unsigned long idx0, nr, i;
	struct page **pages;
	u64 cur_va;
	int ret;

	ret = pin_span_idx(mr, va, len, &idx0, &nr);
	if (ret)
		return ret;

	/* G1: MR 已拆卸 (DEREG/release detach 置 NULL) 时拒绝 —
	 * pin 引用已由拆卸路径的 pin_release_all 释放, 无可钉区间; 同时
	 * 避免对已拆卸 MR 的 pin_align 真实 PA 重映射 (拆卸 unmap 后遗留
	 * PTE)。并发拆卸窗口由锁内所有权复查兑底。
	 * G2: st 临时引用替代入口裸读 (原 GUP 前后两次裸读
	 * mm_state, 第二段加锁前窗口可遇 kfree_rcu(st)) — 引用持有至出口,
	 * GUP (可睡眠) 期间 st 不会释放; put 均在无 mmap 锁/自旋锁的
	 * 进程上下文。 */
	st = symrdma_mm_state_get(mr);
	if (!st)
		return -ENOENT;

	/* 单段大于预算永远放不下 → 快速拒绝 (用户态降级该 op 不 pin) */
	if (nr > SYMRDMA_PIN_BUDGET_PAGES) {
		atomic64_inc(&dev->stats.pin_enospc);
		ret = -ENOSPC;
		goto out_put;
	}

	pages = kvcalloc(nr, sizeof(*pages), GFP_KERNEL);
	if (!pages) {
		ret = -ENOMEM;
		goto out_put;
	}

	/* GUP 锁外 (可睡眠): FOLL_WRITE 优先 (历史 — 无写标志时未写
	 * 过的匿名页返回全局 zero_page, write_iova(RW) 映射到零页 → 远端
	 * RDMA Write 写穿零页全系统污染); 只读 VMA (REMOTE_READ-only 导出
	 * MR) 回退无写标志。GUP 对缺失页自动 swap-in — pin 自带 repair
	 * 语义, 不依赖前置 REPAIR。
	 * R4: 原 pin_gup_try (fast→slow, 部分成功整段放弃) ×2 flags
	 * 收敛至 symrdma_gup_write_first (whole_span=true), 调用序列
	 * 逐字节不变。 */
	ret = symrdma_gup_write_first(va, nr, pages, true);
	/* ret 为 int、nr 为 unsigned long — 原 `ret < nr` 中
	 * 负错误码经整型提升被转换成极大无符号数, 判定为成功, 后续拿全
	 * NULL 页数组运行 (持锁 NULL 解引用)。先判负再比较。 */
	if (ret < 0 || (unsigned long)ret != nr) {
		kvfree(pages);
		ret = (ret < 0) ? ret : -EFAULT;
		goto out_put;
	}

	pn = kzalloc(sizeof(*pn), GFP_KERNEL);
	if (!pn) {
		for (i = 0; i < nr; i++)
			put_page(pages[i]);
		kvfree(pages);
		ret = -ENOMEM;
		goto out_put;
	}
	pn->idx0  = idx0;
	pn->nr    = nr;
	pn->pages = pages;

	spin_lock(&st->lock);

	/* G1: 所有权复查 — MR 已拆卸 (mm_state NULL, DEREG/
	 * release detach 同锁置位) 或并发拆卸已接管时拒绝: pin_align 的
	 * 真实 PA 重映射会在拆卸 unmap 之后建立 PTE → 遗留 (G1 泄漏面 ②)。
	 * 复查通过则拆卸尚未达此 MR, 其后续 unmap 必然覆盖本映射。 */
	if (mr->mm_state != st) {
		spin_unlock(&st->lock);
		kfree(pn);
		for (i = 0; i < nr; i++)
			put_page(pages[i]);
		kvfree(pages);
		ret = -ENOENT;
		goto out_put;
	}

	if (mr->pinned_pages + nr > SYMRDMA_PIN_BUDGET_PAGES) {
		spin_unlock(&st->lock);
		kfree(pn);
		for (i = 0; i < nr; i++)
			put_page(pages[i]);
		kvfree(pages);
		atomic64_inc(&dev->stats.pin_enospc);
		ret = -ENOSPC;
		goto out_put;
	}

	/* 逐页: 对齐 IOMMU + 标记在飞。cur_va 供 va_to_pa 计算大页内
	 * 偏移 (历史 A1)。
	 * 对齐失败 (IOMCU 映射 EIO, 状态已回滚哨兵态)
	 * → 整段 PIN 失败: 已对齐的前缀页状态一致 (等价于已修复页, 后续
	 * 换出由 notifier 正常哨兵化), 页引用全部释放, 不登记 pin 节点。 */
	cur_va = mr->va_start + idx0 * PAGE_SIZE;
	for (i = 0; i < nr; i++) {
		ret = pin_align_page(dev, mr, idx0 + i,
				     symrdma_va_to_pa(pages[i], cur_va));
		if (ret) {
			spin_unlock(&st->lock);
			kfree(pn);
			for (i = 0; i < nr; i++)
				put_page(pages[i]);
			kvfree(pages);
			atomic64_inc(&dev->stats.repair_fail);
			goto out_put;
		}
		mr->pages[idx0 + i].inflight++;
		cur_va += PAGE_SIZE;
	}
	mr->pinned_pages += nr;
	list_add_tail(&pn->node, &mr->pin_list);

	spin_unlock(&st->lock);

	atomic64_add(nr, &dev->stats.pin_pages);
	atomic64_inc(&dev->stats.pin_ok);
	return 0;

out_put:
	symrdma_mm_state_put(st);
	return ret;
}

int symrdma_unpin_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
			u64 va, u64 len)
{
	struct symrdma_pin_node *pn, *tmp;
	struct symrdma_mm_state *st;
	unsigned long idx0 = 0, nr = 0;
	bool all = (len == 0);
	long freed = 0;
	LIST_HEAD(dead);
	int ret;

	if (!all) {
		ret = pin_span_idx(mr, va, len, &idx0, &nr);
		if (ret)
			return ret;
	}

	/* G1: MR 已拆卸时拒绝 — pin 引用已由拆卸路径的
	 * pin_release_all 释放 (无可解绑区间), 且避免无锁触碰 pin_list
	 * (与并发拆卸的释放竞态); 延迟转换由拆卸 unmap 兑底。
	 * G2: st 临时引用 — 立案的最宽窗口 (锁内摘链 → 锁外
	 * 探测段 mmap_read_lock + 逐页 follow_page, 大 span 毫秒级可跨
	 * RCU 宽限期 → 补完转换第二段加锁) 全程闭合。put 在
	 * mmap_read_unlock 之后 — st_release 的 cancel_work_sync 会等待
	 * 驻留恢复工作项 (其取 mmap 读锁), 持锁 put 有自死锁风险。 */
	st = symrdma_mm_state_get(mr);
	if (!st)
		return -ENOENT;

	spin_lock(&st->lock);

	/* G1 复查 (补强): 已拆卸/并发拆卸接管 → fail-closed —
	 * pin 引用已由拆卸路径释放, 摘链后延迟转换由拆卸 unmap 兑底。 */
	if (mr->mm_state != st) {
		spin_unlock(&st->lock);
		symrdma_mm_state_put(st);
		return -ENOENT;
	}

	/* 锁内: 摘链匹配区间 + 递减在飞计数 (归零页成为延迟转换候选,
	 * 探测在锁外 — 此窗口内并发 notifier 可能先行转换, 候选补完
	 * 逻辑对已转换页幂等) */
	list_for_each_entry_safe(pn, tmp, &mr->pin_list, node) {
		unsigned long i;

		if (!all && (pn->idx0 != idx0 || pn->nr != nr))
			continue;

		list_move_tail(&pn->node, &dead);
		mr->pinned_pages -= pn->nr;
		freed += pn->nr;
		for (i = 0; i < pn->nr; i++) {
			u16 c = mr->pages[pn->idx0 + i].inflight;

			mr->pages[pn->idx0 + i].inflight =
				(c > 0) ? (u16)(c - 1) : 0;
		}
		if (!all)
			break;
	}

	spin_unlock(&st->lock);

	if (list_empty(&dead)) {
		symrdma_mm_state_put(st);
		return -ENOENT;
	}

	/* 锁外: 候选页补完延迟转换。探测 (follow_page_nofault) 需 mmap
	 * 读锁稳定 PTE (b 同款); UNPIN 在属主进程上下文执行,
	 * mr->mm 即 current->mm, 阻塞读锁无死锁。探测先于 put_page —
	 * 本方页引用仍持有, PA/内容稳定。
	 *
	 * 安全性 (评审修正): PA 变化 (COW-break/迁移/munmap 后
	 * VA 复用) 一律走延迟转换 (哨兵/黑洞 + 版本翻转) 而非重映射新
	 * PA — munmap+VA 复用场景下重映射会把 IOMMU 指向另一个映射的
	 * 页 (跨映射数据暴露); 哨兵化永远安全, 下次访问经 REPAIR GUP
	 * 解析真实当前页。 */
	if (mr->mm == current->mm)
		mmap_read_lock(mr->mm);

	list_for_each_entry_safe(pn, tmp, &dead, node) {
		unsigned long i;

		for (i = 0; i < pn->nr; i++) {
			unsigned long idx = pn->idx0 + i;
			u64 pva = mr->va_start + idx * PAGE_SIZE;
			struct page *page;
			phys_addr_t pa;

			if (mr->pages[idx].inflight > 0)
				continue;   /* 仍被其他 pin 区间覆盖 */

			page = symrdma_follow_page_nofault(mr->mm, pva);
			pa = page ? symrdma_va_to_pa(page, pva) : 0;
			if (page)
				put_page(page);

			if (!page || pa != mr->pages[idx].orig_pa) {
				/* PTE 已换出/清除, 或 PA 变化 (COW/迁移/VA
				 * 复用) — 补完延迟转换 (幂等, 安全)。
				 * G1: 所有权复查 — MR 已拆卸/并发拆卸
				 * 时不转换 (拆卸 unmap 兑底; 拆卸后的哨兵/黑洞
				 * 映射会遗留 PTE, G1 泄漏面 ② 实测形态)。 */
				spin_lock(&st->lock);
				if (mr->mm_state == st)
					pin_complete_transition(dev, mr, idx);
				spin_unlock(&st->lock);
			}
		}

		/* 释放本区间 GUP 引用 (锁外) */
		for (i = 0; i < pn->nr; i++)
			put_page(pn->pages[i]);
		kvfree(pn->pages);
		list_del(&pn->node);
		kfree(pn);
	}

	if (mr->mm == current->mm)
		mmap_read_unlock(mr->mm);

	/* G2: put 在 mmap_read_unlock 之后 (自死锁风险见入口注释) */
	symrdma_mm_state_put(st);

	atomic64_sub(freed, &dev->stats.pin_pages);
	return 0;
}

/* MR 拆卸 (DEREG/release) 时释放全部 pin 引用 — 不做探测/转换
 * (IOMMU 映射随拆卸 unmap, 页随引用释放归 OS)。
 * 调用时序契约 (G2): DEREG 路径须先于 mn_detach 调用 — 此时
 * mr->mm_state 非 NULL, pin_list 手术在 st->lock 内, 与在飞 UNPIN ioctl
 * (持 st 临时引用, 锁内摘链) 串行化; 旧序 (detach 先行) 读到 NULL 后
 * 无锁遍历, 与该 ioctl 并发 → list 撕裂。release 阶段 2 的调用
 * (detach 已由阶段 1 完成) 读到 NULL 走无锁遍历 — 进程退出
 * (mm_users==0) 排除在飞 pin/unpin ioctl, 安全。 */
void symrdma_pin_release_all(struct symrdma_mr *mr)
{
	struct symrdma_pin_node *pn, *tmp;
	struct symrdma_mm_state *st = mr->mm_state;
	long freed = 0;
	LIST_HEAD(dead);
	unsigned long i;

	if (st)
		spin_lock(&st->lock);
	list_for_each_entry_safe(pn, tmp, &mr->pin_list, node) {
		list_move_tail(&pn->node, &dead);
		mr->pinned_pages -= pn->nr;
		for (i = 0; i < pn->nr; i++)
			mr->pages[pn->idx0 + i].inflight = 0;
		freed += pn->nr;
	}
	if (st)
		spin_unlock(&st->lock);

	list_for_each_entry_safe(pn, tmp, &dead, node) {
		for (i = 0; i < pn->nr; i++)
			put_page(pn->pages[i]);
		kvfree(pn->pages);
		list_del(&pn->node);
		kfree(pn);
	}

	if (freed > 0)
		atomic64_sub(freed, &mr->dev->stats.pin_pages);
}
