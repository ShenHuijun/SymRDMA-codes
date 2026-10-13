/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma_notifier.c — per-mm MMU notifier (一个 mm 只注册一个 notifier)
 *
 * 论文 §4.1: 当 OS 即将回收/换出一个页面时，MMU notifier 回调遍历该 mm
 * 下的所有 MR，对 VA 范围内的页面做:
 *   1. Read IOVA  → 哨兵页 (IOMMU_READ —  只读加固: DMA 写被 IOMMU 丢弃)
 *   2. Write IOVA → 黑洞页 (IOMMU_WRITE) — 不同 IOVA，不覆盖!
 *   3. orig_pa 置零 (换出后原 PA 已释放，防止 REMAP REAL 用 stale PA)
 *   4. version++ (奇→偶翻转)
 *
 *  (外部页失效源调查 + 驻留重映射,):
 *   - 取证: 每次 invalidate_range_start 记录 (comm/pid/range/调用栈)
 *     到 dev->notif_ring, /proc/symrdma 可读 — 定位外部失效源调用者;
 *   - 驻留重映射 (论文 §3.1.1 语义修正: 只对 non-resident 重定向):
 *     start 仍立即哨兵化 (防 stale PA DMA), range 记入 pending;
 *     invalidate_range_end 排空并调度工作项 — follow_page_nofault
 *     探测 (绝不触发缺页/swap-in): 页仍驻留 (迁移/COW/NUMA/mprotect)
 *     → 直接重映射新真实 PA + 版本恢复奇数, 不再制造哨兵-修复循环;
 *     真换出 (探测失败) 保持哨兵, REPAIR 兑底。同时消除驻留失效
 *     "翻转+修复"两轮 unmap→map 窗口与在飞 DMA 的相撞源。
 *
 * 优化: 同一个 (dev, mm) 只注册一个 notifier，而非每个 MR 注册一个。
 *
 * 论文 §4.1 错误处理: release 回调 (进程退出时清理) —
 *   mm 销毁 (__mmput) 时 mmu_notifier_release() 遍历调用本回调，释放该
 *   mm 下所有 MR (IOMMU 映射 + 版本表 + idr 条目)。这保证进程异常退出
 *   (不调 DEREG_MR) 时资源不泄漏。
 *    移除 mmget/mmput — mmget 增加 mm_users 阻止 __mmput 执行,
 *   使 release 回调永不触发 (历史遗留泄漏)。mmu_notifier_register 内部
 *   已管理 mm 引用 (mmgrab/mmdrop), 此处无需也不应再持 mm_users 引用。
 */
#include "symrdma.h"
#include <linux/rcupdate.h>   /* kfree_rcu (§4.1 release 延迟释放) */
#include <linux/sched/mm.h>   /* mmdrop (release 归还 mm_count) */

/* ---- mmu_notifier 摘除/注销 (5.9+ 语义) ----
 * 5.9+ (free_notifier 重构; 实测 5.15.0-138 configure 探到
 * HAVE_MMU_NOTIFIER_OPS_HAS_FREE_NOTIFIER):
 *   - mmu_notifier_subscriptions 结构定义移入 kernel/mmu_notifier.c (对模块
 *     不透明, 不能再手工锁/摘 hlist);
 *   - mmu_notifier_unregister() 不再调用 ops->release (仅摘 hlist + mmdrop)
 *     → detach 直接用它;
 *   - __mmu_notifier_release 在调用 release 回调前内核已自行摘除节点
 *     → release 回调内无需 (也不可) 手工摘 hlist。
 * 历史注记: 5.4 的 unregister 会重入 ops->release,
 * 曾需手工 hlist 摘除等价 (A10) — 5.4 分支随 host-c 基准机支持移除
 * unregister 语义存在跨版本差异。 */

/* ---- per-mm notifier 回调 ---- */

/* 取证: 记录一次 invalidate_range_start (调用者/范围/调用栈)。
 * 始终开启 — 事件量级 ≈ 失效频率 (测试床 ≈5/s), 开销可忽略。 */
static void symrdma_notif_record(struct symrdma_dev *dev,
				 const struct mmu_notifier_range *range)
{
	struct symrdma_notif_event *ev;
	unsigned long flags;

	spin_lock_irqsave(&dev->notif_lock, flags);
	ev = &dev->notif_ring[dev->notif_head];
	dev->notif_head =
		(dev->notif_head + 1) & (SYMRDMA_NOTIF_RING_SIZE - 1);
	memset(ev, 0, sizeof(*ev));
	ev->jiffies = jiffies;
	ev->start = range->start;
	ev->end = range->end;
	ev->npages = (u32)((range->end - range->start) >> PAGE_SHIFT);
	ev->pid = current->pid;
	ev->tgid = current->tgid;
	memcpy(ev->comm, current->comm, sizeof(ev->comm) - 1);
	ev->nr_stack = stack_trace_save(ev->stack, SYMRDMA_NOTIF_STACK_DEPTH,
					1);
	spin_unlock_irqrestore(&dev->notif_lock, flags);
	atomic64_inc(&dev->stats.notif_events);
}

/* 驻留重映射: 探测单页驻留并恢复真实映射。
 * b: 调用方 (驻留重映射工作项) 已持 mmap 读锁 + mm 引用 —
 * PTE 读取在锁内无撕裂/释放窗口 (消除旧无锁遍历的 UAF 风险)。
 * 阻塞式读锁语义是必须的: trylock 在 NUMA 扫描风暴 (change_protection
 * 持写锁) 下会持续失败 → 驻留页长期停留在只读哨兵映射 → 后续 RDMA
 * Read 写入本端接收页被 IOMMU 静默丢弃 → 应用读到陈旧内容 (L14
 * corrupt=got 0x00000000 实测); 阻塞读锁保证恢复及时性与旧实现相当。
 *  absent 页 probe_fail++ (饱和后不再被工作项探测); 恢复成功
 * 清零 — 真换出页本就不是工作项可恢复的对象 (换入无 notifier 事件),
 * REPAIR/PIN 是其兑底路径。 */
static void symrdma_restore_page_locked(struct symrdma_mm_state *st,
					struct symrdma_mr *mr, unsigned long i)
{
	unsigned long va = mr->va_start + i * PAGE_SIZE;
	struct page *page;
	phys_addr_t pa;
	u32 cur;

	page = symrdma_follow_page_nofault(st->mm, va);
	if (!page) {
		/* 确认非驻留 (真换出/未映射) — 保持哨兵, REPAIR 兑底。
		 * follow_page_nofault 绝不触发缺页/swap-in,
		 * 不会与缺页语义 (L9 PAGEOUT) 打架。 */
		spin_lock(&st->lock);
		if (mr->pages[i].probe_fail < SYMRDMA_PROBE_FAIL_MAX)
			mr->pages[i].probe_fail++;
		spin_unlock(&st->lock);
		atomic64_inc(&st->dev->stats.resident_absent);
		return;
	}

	pa = symrdma_va_to_pa(page, va);

	/* 重映射与 notifier/REPAIR 串行化 (历史 A8 同锁) */
	spin_lock(&st->lock);
	/* G1: 所有权复查 — kref_get 与本锁之间 MR 可能已被 DEREG
	 * 的 detach 摘除 (mm_state 置 NULL); 拆卸路径将 unmap 全部 PTE,
	 * 之后重映射真实 PA 会遗留 PTE (G1 泄漏面 ②)。复查通过则拆卸尚
	 * 未达此 MR, 其后续 unmap 必然覆盖本映射。 */
	if (mr->pages[i].read_state == PAGE_SENTINEL && mr->mm_state == st) {
		/* 重映射失败 (状态已回滚哨兵) → 不发布版本,
		 * probe_fail++ 留待下轮重试 */
		if (symrdma_remap_to_real(st->dev, mr, i, pa)) {
			spin_unlock(&st->lock);
			put_page(page);
			return;
		}
		cur = symrdma_version_read(mr, i);
		if (!(cur & 1))
			symrdma_version_set(mr, i, cur + 1);   /* 恢复奇数 */
		mr->pages[i].probe_fail = 0;   /* 恢复可探测态 */
		atomic64_inc(&st->dev->stats.resident_restored);
	}
	spin_unlock(&st->lock);
	put_page(page);
}

/* 工作项: 排空 pending 区间, 恢复其中仍驻留的页。
 * 遍历模式: 锁内找首个 SENTINEL 候选取 kref → 锁外探测恢复 →
 * put 并重头扫描 (避免跨解锁窗口继续 list 遍历踩毒指针,
 * detached/list_del_init 语义, 历史 A10 同源)。 */
static void symrdma_resident_work_fn(struct work_struct *w)
{
	struct symrdma_mm_state *st =
		container_of(w, struct symrdma_mm_state, resident_work);
	struct symrdma_pending_range local[SYMRDMA_PENDING_NR];
	struct symrdma_mr *mr;
	int n, i;
	unsigned long flags;

	spin_lock_irqsave(&st->lock, flags);
	n = st->pending_head;
	if (n > 0)
		memcpy(local, st->pending, n * sizeof(*local));
	st->pending_head = 0;
	st->work_queued = false;
	spin_unlock_irqrestore(&st->lock, flags);

	if (n <= 0)
		return;
	/* 进程退出中 (mm_users==0) → release 路径负责清理, 跳过探测 */
	if (!mmget_not_zero(st->mm))
		return;

	/* b: 全程持 mmap 读锁 — PTE 探测在锁内无撕裂/释放窗口;
	 * 阻塞式获取保证驻留恢复及时性 (trylock 在 NUMA 扫描风暴下会
	 * 持续失败 → 恢复无期限延迟 → 驻留页长期停在只读哨兵映射 →
	 * RDMA Read 写入本端接收页被静默丢弃, L14 corrupt 实测)。
	 * 可睡眠上下文 (kworker); 锁序 mmap_lock → st->lock 与 notifier
	 * 回调 (内核持写锁时回调内取 st->lock) 同向, 无死锁环。 */
	mmap_read_lock(st->mm);

	for (i = 0; i < n; i++) {
		unsigned long probed = 0;
		bool again = true;

		while (again && probed < 4096) {
			struct symrdma_mr *found = NULL;
			unsigned long found_idx = 0;

			again = false;
			spin_lock_irqsave(&st->lock, flags);
			list_for_each_entry(mr, &st->mr_list, mm_node) {
				u64 s, e;
				unsigned long idx0, idx1, j;
				bool hit = false;

				if (local[i].start >= mr->va_end ||
				    local[i].end <= mr->va_start)
					continue;
				/* 手写钳位 — 内核 max/min 宏对混合类型会报
				 * __builtin_choose_expr 编译错 (Werror) */
				s = local[i].start;
				if (s < mr->va_start)
					s = mr->va_start;
				e = local[i].end;
				if (e > mr->va_end)
					e = mr->va_end;
				idx0 = (s - mr->va_start) / PAGE_SIZE;
				idx1 = (e - mr->va_start - 1) / PAGE_SIZE;

				for (j = idx0; j <= idx1 && j < mr->npages;
				     j++) {
					if (mr->pages[j].read_state !=
					    PAGE_SENTINEL)
						continue;
					/* 探测失败饱和页跳过 —
					 * absent 页反复重探是工作项的
					 * 主要空转源 (L14 10s 4.3M 次);
					 * 饱和页由 REPAIR/PIN 兑底 */
					if (mr->pages[j].probe_fail >=
					    SYMRDMA_PROBE_FAIL_MAX)
						continue;
					if (!kref_get_unless_zero(&mr->ref))
						break;
					found = mr;
					found_idx = j;
					hit = true;
					break;
				}
				if (hit)
					break;
			}
			spin_unlock_irqrestore(&st->lock, flags);

			if (found) {
				symrdma_restore_page_locked(st, found, found_idx);
				kref_put(&found->ref, symrdma_mr_release);
				probed++;
				again = true;   /* 从头重扫, 防节点被摘 */
			}
		}
	}
	mmap_read_unlock(st->mm);
	/* mmput → mmput_async — 本工作项可能持有最后一个 mm_users
	 * 引用 (所有线程已退出、仅探测引用残留): 内联 mmput 会在本工作项
	 * 上下文触发 __mmput → exit_mmap → mmu_notifier_release →
	 * symrdma_mm_release → cancel_work_sync(本工作项) → 等待自身 →
	 * 自死锁 (kworker D 态持有全局 SRCU 读锁 → 全系统 DEREG/退出清理
	 * 在 synchronize_srcu 堆积, L9+ 全挂实测)。异步化后 __mmput 在另
	 * 一 kworker 展开, 本工作项已无后续动作, cancel_work_sync 立即
	 * 返回。mmput_async 为 4.13+ 导出符号 (项目基线 5.11)。 */
	mmput_async(st->mm);
}

static int symrdma_mm_invalidate(struct mmu_notifier *mn,
				 const struct mmu_notifier_range *range)
{
	struct symrdma_mm_state *st = container_of(mn, struct symrdma_mm_state, mn);
	struct symrdma_mr *mr;
	unsigned long i, idx_start, idx_end;
	long swapped = 0;

	atomic64_inc(&st->dev->stats.notifier_calls);
	/* 取证: 无论是否命中 MR 都记录 (外部源可能触碰非 MR 页) */
	symrdma_notif_record(st->dev, range);

	/* (G4): 保护性失效事件 (MMU_NOTIFY_PROTECTION_VMA —
	 * NUMA balancing 的 change_prot_numa 标记 / 应用 mprotect) 页面
	 * 不会被释放, IOMMU 真实 PA 映射仍有效 — 哨兵化 + 版本翻转是
	 * **假失效**: 远端 seqlock 前后版本不一致 → 修复风暴 (每次 NUMA
	 * 扫描全区域 32MB 逐页翻转, DMA-only 热区被反复打断, racebw
	 * Fig 12 基准实测 seqlock EAGAIN 风暴 + 版本持续翻转)。
	 * 保护性变更不释放页 → 跳过转换 (真换出仍走 UNMAP/CLEAR 事件,
	 * 语义不变; 若后续 munmap 会另发 UNMAP 事件正常处理)。 */
	if (range->event == MMU_NOTIFY_PROTECTION_VMA)
		return 0;

	/*
	 * 注意: 此处 iommu_unmap/map 在自旋锁下执行。Intel VT-d 的 map
	 * 仅在页表层级缺失时才 GFP_KERNEL 分配 (不可在原子上下文睡眠)。
	 * 由于换出是逐页 unmap→map，相邻页仍占用 L1 页表 (512 项/2MB)，
	 * 表页不会被释放，故实际路径不会触发分配。若未来 MR 覆盖整个
	 * 2MB L1 范围并整段换出，需改为延迟到锁外处理。
	 */
	spin_lock(&st->lock);
	st->notif_depth++;

	list_for_each_entry(mr, &st->mr_list, mm_node) {
		/* 裁剪到 MR 范围 */
		if (range->start >= mr->va_end || range->end <= mr->va_start)
			continue;

		idx_start = (max((u64)range->start, mr->va_start) - mr->va_start)
			    / PAGE_SIZE;
		idx_end   = (min((u64)range->end, mr->va_end) - mr->va_start - 1)
			    / PAGE_SIZE;

		if (idx_start > idx_end || idx_end >= mr->npages)
			continue;

		for (i = idx_start; i <= idx_end; i++) {
			u64 riova = mr->read_iova + i * PAGE_SIZE;
			u64 wiova = mr->write_iova + i * PAGE_SIZE;

			/* 已是哨兵/黑洞的页跳过 — 不重复翻转版本,
			 * 不产生冗余 unmap→map 窗口 (窗口是在飞 DMA 相撞源,
			 * 外部源高频失效时尤其关键) */
			if (mr->pages[i].read_state != PAGE_RESIDENT)
				continue;

			/* 在飞页延迟转换 (flush-before-unmap 屏障)。
			 * GUP pin 引用保证 PA 不被回收/复用 → IOMMU 保持真实
			 * PA 是安全的: 无 unmap→map 窗口 (L14 access_err 根因),
			 * 无哨兵/黑洞吸收 (L14 corrupt 根因), 无版本翻转 (远端
			 * seqlock 无假失效)。延迟转换在 UNPIN 时探测 PTE 补完
			 * (symrdma_pin.c pin_complete_transition)。 */
			if (mr->pages[i].inflight) {
				atomic64_inc(&st->dev->stats.pin_deferred);
				continue;
			}

			/* 组感知前置 — 页所在组若为 2MB 超页先降级
			 * (512 逐页重建, iommu_map_atomic GFP_ATOMIC 锁内安全;
			 * 纯映射变换不动状态/版本, 组内 RESIDENT 页的转换与版本
			 * 翻转在下方逐页照常)。置于两个 skip 检查之后: ABSENT 组
			 * 的哨兵跳过不触发降级 (EDR 周期性失效不打扰提升组),
			 * 在飞页跳过不触发降级 (pin 语义; 组内其余页转换时才降)。
			 * 上方 "整段 2MB 换出需延迟锁外" 的  顾虑由降级解除:
			 * 组内每页恒有映射, L1 释放后由 GFP_ATOMIC 重分配。 */
			symrdma_group_ensure_split_locked(mr->dev, mr, i);

			/*
			 * 版本号只在状态转换时翻转: 仅当该页
			 * 此前驻留 (奇数) 才递增 → 偶数 (缺失)。若页面
			 * 本来就缺失 (如 DONTNEED 未 touch 页), 递增会把
			 * 偶数翻成奇数, 破坏"奇数=驻留"语义。
			 */
			symrdma_version_inc(mr, i);

			symrdma_iommu_unmap_page(mr->dev, riova);
			symrdma_iommu_map_page(mr->dev, riova,
					       mr->dev->sentinel_pa,
					       IOMMU_READ);
			mr->pages[i].read_state = PAGE_SENTINEL;
			/* 换出后原 PA 已释放, 置零防止 REMAP REAL 用 stale PA */
			mr->pages[i].orig_pa = 0;

			symrdma_iommu_unmap_page(mr->dev, wiova);
			symrdma_iommu_map_page(mr->dev, wiova,
					       mr->dev->blackhole_pa, IOMMU_WRITE);
			mr->pages[i].write_state = PAGE_BLACKHOLE;

			swapped++;
		}
	}

	/* 记录 pending 区间 → end 排空后工作项驻留重映射。
	 * 与翻转同锁; 溢出时放弃恢复 (保持哨兵, REPAIR 兑底)。 */
	if (st->pending_head >= SYMRDMA_PENDING_NR) {
		atomic64_inc(&st->dev->stats.pending_overflow);
	} else {
		st->pending[st->pending_head].start = range->start;
		st->pending[st->pending_head].end = range->end;
		st->pending_head++;
	}

	spin_unlock(&st->lock);

	atomic64_add(swapped, &st->dev->stats.pages_swapped_out);
	return 0;
}

/* end 回调 — 排空时机。schedule_work 与 work_queued 置位在
 * st->lock 内原子完成 (与 release/detach 的 cancel_work_sync 竞态闭合:
 * 要么 cancel 观察到已排队的 work 并等待完成, 要么 end 看到被
 * release 置回的 work_queued=false 不再排队)。 */
static void symrdma_mm_invalidate_end(struct mmu_notifier *mn,
				      const struct mmu_notifier_range *range)
{
	struct symrdma_mm_state *st = container_of(mn, struct symrdma_mm_state, mn);
	unsigned long flags;

	/* start 回调对 PROTECTION_VMA 在 notif_depth++ 之前
	 * 返回 (G4 假失效抑制), end 须对称跳过, 否则每次 mprotect/NUMA
	 * 扫描使深度净减 1, `notif_depth <= 0` 排空闸门失效 */
	if (range->event == MMU_NOTIFY_PROTECTION_VMA)
		return;

	spin_lock_irqsave(&st->lock, flags);
	st->notif_depth--;
	if (st->notif_depth <= 0 && st->pending_head > 0 &&
	    !st->work_queued) {
		st->work_queued = true;
		schedule_work(&st->resident_work);
	}
	spin_unlock_irqrestore(&st->lock, flags);
}

/* ---- 进程退出清理 (论文 §4.1 错误处理: release 回调) ----
 *
 * mm 销毁时 (mm_users 归零 → __mmput → mmu_notifier_release) 由内核遍历
 * 调用。此时该 mm 下所有 MR 不再被任何进程访问 (进程已死), 直接清理:
 *   1. 从 dev->mm_states 移除 mm_state (防止 ioctl 经 idr 误用)
 *   2. 遍历 mr_list: 从 dev->mr_list + idr 移除, unmap 双 IOVA, 释放版本表
 *   3. G2: 阶段 1 是全部 MR 的 unlink 执行者 — 逐 MR 归还
 *      mm_state 附着引用; 归零 → symrdma_mm_state_release
 *      (cancel_work_sync + kfree_rcu 延迟释放 — release 回调运行在
 *      mmu_notifier_release 的遍历中, 不能立即 kfree, RCU 宽限期保证
 *      hlist 遍历结束后释放)。
 *
 * 注意: 不调用 mmu_notifier_unregister (mmu_notifier_release 流程自己
 * 会处理 hlist 移除); 也不调用 symrdma_dereg_mr 的 notifier 部分。
 */
static void symrdma_mm_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct symrdma_mm_state *st = container_of(mn, struct symrdma_mm_state, mn);
	struct symrdma_dev *dev = st->dev;
	struct symrdma_mr *mr, *tmp;
	LIST_HEAD(dead);
	unsigned long cleaned = 0;
	unsigned long moved = 0;   /* G2: unlink 计数 = 待归还附着引用数 */

	/* 重入守卫 (历史 A10 的 5.11 变体): 5.11/5.12 的
	 * mmu_notifier_unregister 在注销时会重入本回调 — detach 已在同一
	 * 临界区完成全部清理并置 detached, 本回调 no-op, 防双重
	 * mmdrop/kfree_rcu → SLUB 损坏。
	 *  守卫与阶段 1 合并为单一双锁临界区 (mm_state_lock →
	 * st->lock, 与 mn_detach 同序) — 原实现“单持 st->lock 查守卫 →
	 * 单持 mm_state_lock 摘链”两临界区之间插入的并发 detach 会造成
	 * 已摘链/已释放 st 的二次手术 (双重 list_del/mmdrop/kfree_rcu,
	 * soft lockup 同族)。 */
	/* idr 不自带同步, 阶段 1 的 idr_remove 须持
	 * dev->mr_lock (与 REG/DEREG/rmmod 一致)。锁序 mm_state_lock →
	 * mr_lock → st->lock 与 symrdma_proc.c 读侧同向, 不引入 ABBA。 */
	spin_lock(&dev->mm_state_lock);
	spin_lock(&dev->mr_lock);
	spin_lock(&st->lock);
	if (st->detached) {
		spin_unlock(&st->lock);
		spin_unlock(&dev->mr_lock);
		spin_unlock(&dev->mm_state_lock);
		return;
	}
	list_del_init(&st->node);

	pr_info("symrdma: 进程退出 (mm=%p), 自动清理 %d 个 MR\n",
		mm, st->mr_count);

	/* 阶段 1 (同一临界区): 把全部 MR 从 st->mr_list 移入本地 dead
	 * 列表并置 mr->mm_state=NULL — mm_state 所有权协议: 此后任何
	 * mn_detach 对这些 MR 锁内复查即放弃, st 手术归本路径。
	 * idr 条目在此移除 (idr 内部自同步); dev->mr_list 摘除延后到
	 * 阶段 2 的 teardown_begin 仲裁 — 避免在 st->lock 内嵌套
	 * dev->mr_lock (proc 读侧存在反向序 mr_lock→st->lock, ABBA)。 */
	list_for_each_entry_safe(mr, tmp, &st->mr_list, mm_node) {
		list_del_init(&mr->mm_node);
		list_add_tail(&mr->mm_node, &dead);
		mr->mm_state = NULL;
		st->mr_count--;
		moved++;

		idr_remove(&dev->mr_idr, mr->mr_id);
	}
	spin_unlock(&st->lock);
	spin_unlock(&dev->mr_lock);
	spin_unlock(&dev->mm_state_lock);

	/* 阶段 2 (无锁): 逐 MR 仲裁拆卸所有权 — 并发 DEREG/rmmod 的
	 * teardown_begin 先到者赢; 落败方 (含 unmap/put) 全部跳过,
	 * 不再触碰任何列表 (其 dev->mr_list 摘除由胜者完成)。
	 * (kref_put 供还 idr 初始引用 — 版本表/页表/mr 的最终
	 * 释放延迟到引用归零, 不再 UAF。 */
	list_for_each_entry_safe(mr, tmp, &dead, mm_node) {
		bool owner;

		list_del(&mr->mm_node);
		owner = symrdma_mr_teardown_begin(dev, mr);
		if (owner) {
			symrdma_pin_release_all(mr);   /* 释放在飞 pin 引用 */
			symrdma_unmap_mr_pages(dev, mr, mr->npages);   /* R3: 收敛 */
			kref_put(&mr->ref, symrdma_mr_release);
			cleaned++;
		}
		/* G2: 阶段 1 是本 MR 的 unlink 执行者 (mm_state=NULL) — 附着
		 * 引用由本路径归还 (并发 DEREG 的 mn_detach 锁内复查 mm_state
		 * 已置 NULL 而放弃, 不 put)。put 可睡眠 (cancel_work_sync) —
		 * 阶段 2 无锁进程上下文, 安全。计数从 moved 递减, 归零仅在
		 * 末次 put — 循环内不存在后续 st 访问 (kfree_rcu 延迟释放)。 */
		kref_put(&st->ref, symrdma_mm_state_release);
	}

	atomic64_inc(&dev->stats.process_exits);
	atomic64_add(cleaned, &dev->stats.released_mrs);

	/* 归还注册时占用的 mm_count 引用 (配对 __mmu_notifier_register
	 * 的 mmgrab)。旧代码漏做 → mm_count 泄漏, 退出进程的 mm 永不释放。
	 * 5.9+: 内核已在调用本回调前自行摘除 hlist 节点 (见文件头注释),
	 * 这里只归还 mm_count; exit_mmap 自身持有一个 mm_count, 此处 mmdrop
	 * 不会触发 mm 释放; 摘除后内核 __mmu_notifier_release 的清理循环
	 * 跳过本节点。
	 * (5.4 手工 hlist 摘除分支随 host-c 支持移除) */
	mmdrop(mm);

	/* G2: st 生命周期终结移入 symrdma_mm_state_release (引用归零:
	 * cancel_work_sync + kfree_rcu) — 阶段 2 的 moved 次 put 归还全部
	 * 附着引用; 在飞 ioctl 临时引用 (owner 进程退出时不可达: mm_users==0)
	 * 仅理论存在, 若有则释放延迟到其 put。 */
	WARN_ON(moved == 0);   /* release ⇒ mr_count ≥ 1 ⇒ 必有 unlink */
}

static const struct mmu_notifier_ops symrdma_mn_ops = {
	.invalidate_range_start = symrdma_mm_invalidate,
	.invalidate_range_end   = symrdma_mm_invalidate_end,  /* */
	.release                = symrdma_mm_release,  /* §4.1 进程退出清理 */
};

/* ---- 查找或创建 mm_state ---- */

static struct symrdma_mm_state *
symrdma_find_mm_state(struct symrdma_dev *dev, struct mm_struct *mm)
{
	struct symrdma_mm_state *st;

	list_for_each_entry(st, &dev->mm_states, node) {
		if (st->mm == mm)
			return st;
	}
	return NULL;
}

/* ---- 对外接口 ---- */

/* ---- 历史: mm_state 生命周期引用 ----
 *
 * A6 的 kref 只护 mr 不护 st: DEREG 摘走最后一个 MR (mr_count==0) 时
 * mn_detach → kfree_rcu(st), 而同进程另一线程的在飞 ioctl (find_mr 已
 * 持 mr kref) 之后仍解引用 st (st->lock / st->mm / st->dev) — UNPIN 的
 * 锁外探测段 (mmap_read_lock + 逐页 follow_page, 大 span 毫秒级) 可跨
 * RCU 宽限期, REPAIR/PIN/REMAP/GET_VERSION 为 µs 级窗口。
 *
 * 引用模型:
 *   - 附着引用: 每个 attached MR 持 1 份 (attach 时 init/get); 拆卸时
 *     由 unlink 执行者 (mn_detach / mm_release 阶段 1) put — 所有权协议
 *     保证 unlink 恰一次, 故 put 恰一次;
 *   - 临时引用: ioctl 数据路径经 symrdma_mm_state_get 原子获取, 用毕
 *     symrdma_mm_state_put。关键不变式: unlink (mr->mm_state = NULL)
 *     一律在 dev->mm_state_lock 内完成且其 put 随后 — 故持 mm_state_lock
 *     读到非 NULL mm_state 时该 MR 的附着引用必未 put (refcount ≥ 1),
 *     kref_get_unless_zero 必成功; get 成功后拆卸的 put 不再能归零;
 *   - 归零 → symrdma_mm_state_release: cancel_work_sync + kfree_rcu
 *     (SRCU/遍历保护, 与旧 destroy/release 语义一致)。
 * 驻留恢复工作项不经引用 (cancel_work_sync 覆盖, 立案原文); notifier
 * 回调由内核注册生命周期保证。
 * 约束: put 可经 cancel_work_sync 睡眠 — 不得持自旋锁/mmap 锁调用
 * (UNPIN 探测段持 mmap 读锁, 其 put 在 unlock 之后)。 */
void symrdma_mm_state_release(struct kref *ref)
{
	struct symrdma_mm_state *st =
		container_of(ref, struct symrdma_mm_state, ref);

	/* kfree_rcu(st) 前等待在飞驻留重映射工作项完成 (原 destroy/release
	 * 路径的内联 cancel_work_sync 语义随迁; 已等待过则立即返回) */
	cancel_work_sync(&st->resident_work);
	kfree_rcu(st, rcu);
}

/* 获取 st 临时引用 (拆卸后返回 NULL — 调用方 fail-closed)。
 * 须在未持 st->lock / 未持 mmap 锁的进程上下文调用 (锁序
 * mm_state_lock → st->lock 与 attach/detach/release 同向, 可嵌套)。 */
struct symrdma_mm_state *symrdma_mm_state_get(struct symrdma_mr *mr)
{
	struct symrdma_dev *dev = mr->dev;
	struct symrdma_mm_state *st;

	spin_lock(&dev->mm_state_lock);
	st = mr->mm_state;
	if (st && !kref_get_unless_zero(&st->ref))
		st = NULL;   /* 防御分支 (不可达): unlink 未发生时附着引用必在 */
	spin_unlock(&dev->mm_state_lock);

	return st;
}

void symrdma_mm_state_put(struct symrdma_mm_state *st)
{
	kref_put(&st->ref, symrdma_mm_state_release);
}

int symrdma_mn_attach(struct symrdma_mr *mr)
{
	struct symrdma_dev *dev = mr->dev;
	struct mm_struct *mm = mr->mm;
	struct symrdma_mm_state *st, *new_st;
	int ret;

	if (!mm)
		return -EINVAL;

	/* (崩溃修复): 预分配在自旋锁外 — 旧代码持 dev->mm_state_lock
	 * 期间 kzalloc(GFP_KERNEL), 分配慢路径 (direct reclaim/compaction)
	 * 可睡眠数十秒;  新增的 release 回调使每次进程退出都自旋
	 * 等待此锁 → soft lockup 挂死 (历史内核日志复盘定位)。 */
	new_st = kzalloc(sizeof(*new_st), GFP_KERNEL);
	if (!new_st)
		return -ENOMEM;

	/* (串行化"查找/创建 + 注册"全流程 — 原实现先把 st 链入
	 * dev->mm_states 再注册 notifier，注册失败清理前的窗口内，同 mm
	 * 的并发 attach 可找到 st 并把 MR 挂入 → 错误路径 kfree(st) 后
	 * 那个 MR 的 mm_state 悬空 (UAF)。互斥锁下错误路径干净；同 mm
	 * 双线程 attach 时一个阻塞，创建者完成 (成功或失败) 后重查找。 */
	mutex_lock(&dev->attach_lock);

	spin_lock(&dev->mm_state_lock);

	st = symrdma_find_mm_state(dev, mm);
	if (st) {
		/* 已有 notifier — 仅链入 MR, 释放预分配 (kfree 不睡眠) */
		kfree(new_st);
		spin_lock(&st->lock);
		list_add_tail(&mr->mm_node, &st->mr_list);
		st->mr_count++;
		spin_unlock(&st->lock);
		/* G2: 本 MR 的附着引用 — st 可见 ⇒ mr_count ≥ 1 ⇒ 至少 1 份
		 * 附着引用在, kref_get 安全 (mm_state_lock 内原子) */
		kref_get(&st->ref);
		mr->mm_state = st;
		spin_unlock(&dev->mm_state_lock);
		mutex_unlock(&dev->attach_lock);
		return 0;
	}

	/* 新 mm — 创建 mm_state 并注册 notifier (使用预分配) */
	st = new_st;

	st->mm = mm;
	st->dev = dev;
	spin_lock_init(&st->lock);
	INIT_LIST_HEAD(&st->mr_list);
	st->mr_count = 1;
	kref_init(&st->ref);   /* G2: 首个 MR 的附着引用 */

	list_add_tail(&mr->mm_node, &st->mr_list);
	mr->mm_state = st;

	/* 先链入 dev->mm_states，再注册 notifier (回调可能立即触发) */
	list_add_tail(&st->node, &dev->mm_states);
	spin_unlock(&dev->mm_state_lock);

	st->mn.ops = &symrdma_mn_ops;
	INIT_WORK(&st->resident_work, symrdma_resident_work_fn);
	ret = mmu_notifier_register(&st->mn, mm);
	if (ret) {
		pr_err("symrdma: mmu_notifier_register 失败: %d\n", ret);
		spin_lock(&dev->mm_state_lock);
		list_del(&st->node);
		spin_unlock(&dev->mm_state_lock);
		list_del(&mr->mm_node);
		mr->mm_state = NULL;
		/* G2: 直接 kfree — refcount=1 (init) 且无其他引用可达:
		 * 本 MR 无 idr 条目 (REG_MR 的 assign_mr_id 在 reg 返回后才
		 * 发生), 同 mm 并发 attach 被 attach_lock 串行化, 同 mm 无
		 * 其他 attached MR (首个) ⇒ 无临时引用来源 */
		kfree(st);
		mutex_unlock(&dev->attach_lock);
		return ret;
	}

	mutex_unlock(&dev->attach_lock);
	return 0;
}

void symrdma_mn_detach(struct symrdma_mr *mr)
{
	struct symrdma_dev *dev = mr->dev;
	struct symrdma_mm_state *st;

	/* G2: 入口读置于 mm_state_lock 内 — unlink (detach/
	 * release 阶段 1) 一律同锁, 读到非 NULL 时本 MR 附着引用必未 put
	 * (st 存活), 随后的 st->lock 获取安全; 旧形态锁外读 + 加锁前的
	 * 窗口与 release 阶段 1+2 + kfree_rcu 竞态 (非属主 DEREG × 进程
	 * 退出边缘场景), 同族闭合。 */
	spin_lock(&dev->mm_state_lock);
	st = mr->mm_state;
	if (!st) {
		spin_unlock(&dev->mm_state_lock);
		return;
	}

	spin_lock(&st->lock);
	/* mm_state 所有权复查 — release 阶段 1 在同一锁对内置
	 * mm_state=NULL 并把节点移入其本地 dead 列表; 若已发生, 本函数
	 * 放弃 (st 摘链/计数由 release 负责; 入口读到的 st 可能已过时,
	 * 必须以锁内值为准, 防对 release dead 列表节点二次手术)。
	 * G2 后入口读已入锁内, 复查恒过 — 保留作防御。 */
	if (st != mr->mm_state) {
		spin_unlock(&st->lock);
		spin_unlock(&dev->mm_state_lock);
		return;
	}

	list_del_init(&mr->mm_node);
	mr->mm_state = NULL;
	st->mr_count--;

	if (st->mr_count == 0) {
		/* 最后一个 MR — 注销 notifier 并释放 mm_state。
		 * (必须先在 mm_state_lock 内摘除 st->node 再解锁 —
		 * 并发 attach 在同一把锁下查找, 摘除后不可见, 不会把新 MR
		 * 挂入即将销毁的 st (UAF); 同一 mm 的后续 attach 会创建新
		 * mm_state 并注册新 notifier (mm 支持挂多个 notifier)。
		 *
		 * (运行时实测发现, soft lockup): 不能调
		 * mmu_notifier_unregister — 5.4 内核会调用 ops->release,
		 * 使 release 回调对本 st 再跑一遍 → mmdrop 双次 +
		 * kfree_rcu(st) 与 kfree(st) 双重释放 → SLUB 损坏 →
		 * 自旋锁死循环 (两个 test 进程互卡, 负载 8.0)。
		 * 5.4 无 unregister_no_release, 手工等价 (与 release 回调
		 * 同模式): hlist 摘除 + mmdrop 归还 mm_count, 不再触发
		 * release; 摘除后内核退出清理循环跳过本节点。 */
		/* (5.11 实测, 同 A10 同族): 5.11/5.12 的
		 * mmu_notifier_unregister 同样会调用 ops->release (语义变更
		 * 在 5.13+, 5.15 才不调) → release 重入时对已 list_del(投毒)
		 * 的 st->node 再 list_del + 双重 mmdrop/kfree_rcu → SLUB 损坏
		 * → soft lockup (栈顶 symrdma_mm_release+0x65, load 8)。
		 * 防御: ① list_del_init 代替 list_del (毒指针写不可重入安全);
		 * ② detached 标志在同一临界区内置位, release 重入时 no-op —
		 * 清理由本路径负责, mm_count 由 unregister 的 mmdrop 归还。 */
		list_del_init(&st->node);
		st->detached = true;
		spin_unlock(&st->lock);
		spin_unlock(&dev->mm_state_lock);

		/* 5.9+ 导出的 unregister 不调用 ops->release
		 * (free_notifier 重构语义), 内核自行持订阅锁摘 hlist + mmdrop。
		 * (5.4 手工等价分支随 host-c 支持移除; 重入 release 的
		 */
		mmu_notifier_unregister(&st->mn, st->mm);
		/* SRCU 保护: 在飞的 invalidate_range_start 可能仍持有本 st
		 * 的引用 (内核经 SRCU 遍历 hlist), unregister 已等待; 先等待
		 * 在飞驻留重映射工作项 */
		cancel_work_sync(&st->resident_work);
		/* G2: 归还本 MR 的附着引用 — 在飞 ioctl 持临时引用时释放
		 * 延迟到其 put (release 回调内 cancel_work_sync + kfree_rcu);
		 * 否则在此归零释放 */
		kref_put(&st->ref, symrdma_mm_state_release);
	} else {
		spin_unlock(&st->lock);
		spin_unlock(&dev->mm_state_lock);
		/* G2: 归还本 MR 的附着引用 — 其余 MR 各持 1 份, st 存活 */
		kref_put(&st->ref, symrdma_mm_state_release);
	}
}
