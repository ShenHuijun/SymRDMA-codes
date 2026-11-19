/* SPDX-License-Identifier: GPL-2.0 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"
#include <linux/rcupdate.h>

#define SYMRDMA_NOTIF_CONV_MAX 64
#include <linux/sched/mm.h>

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

/*
 * The restore direction (the restore rule): a page that is merely back where we left it
 * is realigned in place; a page that moved, or a page nobody has faulted in
 * yet, is left to REPAIR.  Undoing an invalidation the GUP has not yet
 * finished would publish a translation nothing verified.
 */
static void symrdma_realign_page(struct symrdma_mm_state *st,
				 struct symrdma_mr *mr, unsigned long i)
{
	struct symrdma_obs obs;
	enum symrdma_backing bk = SBK_ERROR;
	u8 reason = SPB_R_NONE;
	int ret;

	ret = symrdma_backing_probe(mr, i, SPB_HINT, &obs, &bk, &reason);
	if (ret)
		return;

	spin_lock(&st->lock);
	if (mr->mm_state != st)
		goto out;
	mr->pages[i].probe_gen = obs.gen + 1;
	if (bk == SBK_ABSENT)
		atomic64_inc(&st->dev->stats.resident_absent);
	if (bk != SBK_REAL || mr->pages[i].gen != obs.gen)
		goto out;
	if (mr->pages[i].rmap == SYMRDMA_MAP_SENTINEL &&
	    !symrdma_page_promote_locked(mr, i, &obs, SYMRDMA_TRANS_REALIGN))
		atomic64_inc(&st->dev->stats.resident_restored);
out:
	spin_unlock(&st->lock);
}

static void symrdma_hint_work_fn(struct work_struct *w)
{
	struct symrdma_mm_state *st =
		container_of(w, struct symrdma_mm_state, hint_work);
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
	if (!mmget_not_zero(st->mm))
		return;

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
					if (mr->pages[j].rmap !=
					    SYMRDMA_MAP_SENTINEL)
						continue;
					/*
					 * One hint per gen: an observation
					 * recorded at the current gen is not
					 * worth repeating (the hint rule).
					 */
					if (mr->pages[j].probe_gen &&
					    mr->pages[j].probe_gen ==
					    mr->pages[j].gen + 1)
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
				symrdma_realign_page(st, found, found_idx);
				kref_put(&found->ref, symrdma_mr_release);
				probed++;
				again = true;
			}
		}
	}
	mmap_read_unlock(st->mm);

	mmput_async(st->mm);
}

static int symrdma_mm_invalidate(struct mmu_notifier *mn,
				 const struct mmu_notifier_range *range)
{
	struct symrdma_mm_state *st = container_of(mn, struct symrdma_mm_state, mn);
	struct symrdma_mr *mr;
	unsigned long idx_start, idx_end;
	long swapped = 0;

	atomic64_inc(&st->dev->stats.notifier_calls);
	symrdma_notif_record(st->dev, range);

	if (range->event == MMU_NOTIFY_PROTECTION_VMA)
		return 0;

	spin_lock(&st->lock);
	st->notif_depth++;

	list_for_each_entry(mr, &st->mr_list, mm_node) {
		if (range->start >= mr->va_end || range->end <= mr->va_start)
			continue;

		idx_start = (max((u64)range->start, mr->va_start) - mr->va_start)
			    / PAGE_SIZE;
		idx_end   = (min((u64)range->end, mr->va_end) - mr->va_start - 1)
			    / PAGE_SIZE;

		if (idx_start > idx_end || idx_end >= mr->npages)
			continue;

		{
			unsigned long conv[SYMRDMA_NOTIF_CONV_MAX];
			unsigned long nconv, i2;
			unsigned long next = idx_start;

			/*
			 * Pick the candidates here (the notifier knows which part
			 * of the MR the range covers); the demote verb owns the
			 * barrier, the ordering and the accounting of what it
			 * refused.
			 */
			while (next <= idx_end) {
				unsigned long done = 0, deferred = 0;

				nconv = 0;
				for (i2 = next; i2 <= idx_end; i2++) {
					if (mr->pages[i2].rmap !=
					    SYMRDMA_MAP_REAL)
						continue;
					conv[nconv++] = i2;
					if (nconv == SYMRDMA_NOTIF_CONV_MAX) {
						i2++;
						break;
					}
				}
				next = i2;
				if (!nconv)
					break;

				symrdma_pages_demote_locked(mr, conv, nconv,
							    SYMRDMA_MAP_SENTINEL,
							    SYMRDMA_MAP_BLACKHOLE,
							    SYMRDMA_TRANS_NOTIFIER,
							    &done, &deferred);
				swapped += done;
				atomic64_add(deferred,
					     &st->dev->stats.pin_deferred);
			}
		}
	}

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

static void symrdma_mm_invalidate_end(struct mmu_notifier *mn,
				      const struct mmu_notifier_range *range)
{
	struct symrdma_mm_state *st = container_of(mn, struct symrdma_mm_state, mn);
	unsigned long flags;

	if (range->event == MMU_NOTIFY_PROTECTION_VMA)
		return;

	spin_lock_irqsave(&st->lock, flags);
	st->notif_depth--;
	if (st->notif_depth <= 0 && st->pending_head > 0 &&
	    !st->work_queued) {
		st->work_queued = true;
		schedule_work(&st->hint_work);
	}
	spin_unlock_irqrestore(&st->lock, flags);
}

static void symrdma_mm_release(struct mmu_notifier *mn, struct mm_struct *mm)
{
	struct symrdma_mm_state *st = container_of(mn, struct symrdma_mm_state, mn);
	struct symrdma_dev *dev = st->dev;
	struct symrdma_mr *mr, *tmp;
	LIST_HEAD(dead);
	unsigned long cleaned = 0;
	unsigned long moved = 0;

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

	pr_debug("process exit (mm=%p), auto-cleaning %d MRs\n",
		mm, st->mr_count);

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

	list_for_each_entry_safe(mr, tmp, &dead, mm_node) {
		bool owner;

		list_del(&mr->mm_node);
		owner = symrdma_mr_teardown_begin(dev, mr);
		if (owner) {
			symrdma_pin_release_all(mr);
			symrdma_unmap_mr_pages(dev, mr, mr->npages);
			kref_put(&mr->ref, symrdma_mr_release);
			cleaned++;
		}

		kref_put(&st->ref, symrdma_mm_state_release);
	}

	atomic64_inc(&dev->stats.process_exits);
	atomic64_add(cleaned, &dev->stats.released_mrs);

	mmdrop(mm);

	WARN_ON(moved == 0);
}

static const struct mmu_notifier_ops symrdma_mn_ops = {
	.invalidate_range_start = symrdma_mm_invalidate,
	.invalidate_range_end   = symrdma_mm_invalidate_end,
	.release                = symrdma_mm_release,
};

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

void symrdma_mm_state_release(struct kref *ref)
{
	struct symrdma_mm_state *st =
		container_of(ref, struct symrdma_mm_state, ref);

	cancel_work_sync(&st->hint_work);
	kfree_rcu(st, rcu);
}

struct symrdma_mm_state *symrdma_mm_state_get(struct symrdma_mr *mr)
{
	struct symrdma_dev *dev = mr->dev;
	struct symrdma_mm_state *st;

	spin_lock(&dev->mm_state_lock);
	st = mr->mm_state;
	if (st && !kref_get_unless_zero(&st->ref))
		st = NULL;
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

	new_st = kzalloc(sizeof(*new_st), GFP_KERNEL);
	if (!new_st)
		return -ENOMEM;

	mutex_lock(&dev->attach_lock);

	spin_lock(&dev->mm_state_lock);

	st = symrdma_find_mm_state(dev, mm);
	if (st) {
		kfree(new_st);
		spin_lock(&st->lock);
		list_add_tail(&mr->mm_node, &st->mr_list);
		st->mr_count++;
		spin_unlock(&st->lock);

		kref_get(&st->ref);
		mr->mm_state = st;
		spin_unlock(&dev->mm_state_lock);
		mutex_unlock(&dev->attach_lock);
		return 0;
	}

	st = new_st;

	st->mm = mm;
	st->dev = dev;
	spin_lock_init(&st->lock);
	INIT_LIST_HEAD(&st->mr_list);
	st->mr_count = 1;
	kref_init(&st->ref);

	list_add_tail(&mr->mm_node, &st->mr_list);
	mr->mm_state = st;

	list_add_tail(&st->node, &dev->mm_states);
	spin_unlock(&dev->mm_state_lock);

	st->mn.ops = &symrdma_mn_ops;
	INIT_WORK(&st->hint_work, symrdma_hint_work_fn);
	ret = mmu_notifier_register(&st->mn, mm);
	if (ret) {
		pr_err("mmu_notifier_register failed: %d\n", ret);
		spin_lock(&dev->mm_state_lock);
		list_del(&st->node);
		spin_unlock(&dev->mm_state_lock);
		list_del(&mr->mm_node);
		mr->mm_state = NULL;

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

	spin_lock(&dev->mm_state_lock);
	st = mr->mm_state;
	if (!st) {
		spin_unlock(&dev->mm_state_lock);
		return;
	}

	spin_lock(&st->lock);

	if (st != mr->mm_state) {
		spin_unlock(&st->lock);
		spin_unlock(&dev->mm_state_lock);
		return;
	}

	list_del_init(&mr->mm_node);
	mr->mm_state = NULL;
	st->mr_count--;

	if (st->mr_count == 0) {

		list_del_init(&st->node);
		st->detached = true;
		spin_unlock(&st->lock);
		spin_unlock(&dev->mm_state_lock);

		mmu_notifier_unregister(&st->mn, st->mm);

		cancel_work_sync(&st->hint_work);

		kref_put(&st->ref, symrdma_mm_state_release);
	} else {
		spin_unlock(&st->lock);
		spin_unlock(&dev->mm_state_lock);
		kref_put(&st->ref, symrdma_mm_state_release);
	}
}
