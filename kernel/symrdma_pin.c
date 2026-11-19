// SPDX-License-Identifier: GPL-2.0

#include "symrdma.h"

static int pin_span_idx(const struct symrdma_mr *mr, u64 va, u64 len,
			unsigned long *idx0, unsigned long *nr)
{
	u64 start, end;

	if (len == 0 || va < mr->va_start)
		return -EINVAL;
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

/*
 * The page moved (or went away) while it was pinned: the real translation is
 * no longer what the version claims, so walk it out.  The demote verb refuses
 * while dma_ref is non-zero, which is exactly the flush-before-unmap barrier.
 */
static void pin_complete_transition(struct symrdma_mr *mr, unsigned long i)
{
	struct symrdma_dev *dev = mr->dev;

	if (mr->pages[i].rmap != SYMRDMA_MAP_REAL)
		return;
	if (symrdma_page_demote_locked(mr, i, SYMRDMA_MAP_SENTINEL,
				       SYMRDMA_MAP_BLACKHOLE, SYMRDMA_TRANS_PIN))
		return;
	atomic64_inc(&dev->stats.pin_transitions);
}

static int pin_align_page(struct symrdma_mr *mr, unsigned long i,
			  phys_addr_t pa, u32 gen)
{
	struct symrdma_page *pe = &mr->pages[i];
	struct symrdma_obs obs = { .gen = gen, .pa = pa };
	bool was_real = pe->rmap == SYMRDMA_MAP_REAL;
	int ret;

	if (was_real && pe->wmap == SYMRDMA_MAP_REAL && pe->pa == pa)
		return 0;

	ret = symrdma_page_promote_locked(mr, i, &obs, SYMRDMA_TRANS_PIN);
	if (ret)
		return ret;
	if (!was_real)
		atomic64_inc(&mr->dev->stats.repair_ok);
	return 0;
}

int symrdma_pin_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
		      u64 va, u64 len)
{
	struct symrdma_pin_node *pn;
	struct symrdma_mm_state *st;
	struct symrdma_obs *obs;
	unsigned long idx0, nr, i;
	struct page **pages;
	u64 cur_va;
	int ret;

	ret = pin_span_idx(mr, va, len, &idx0, &nr);
	if (ret)
		return ret;

	st = symrdma_mm_state_get(mr);
	if (!st)
		return -ENOENT;

	if (nr > SYMRDMA_PIN_BUDGET_PAGES) {
		atomic64_inc(&dev->stats.pin_enospc);
		ret = -ENOSPC;
		goto out_put;
	}

	pages = kvcalloc(nr, sizeof(*pages), GFP_KERNEL);
	obs = kvcalloc(nr, sizeof(*obs), GFP_KERNEL);
	if (!pages || !obs) {
		kvfree(pages);
		kvfree(obs);
		ret = -ENOMEM;
		goto out_put;
	}

	ret = symrdma_gup_for_pin(va, nr, pages);
	if (ret) {
		atomic64_inc(&dev->stats.gup_pin_fail);
		kvfree(pages);
		kvfree(obs);
		goto out_put;
	}

	pn = kzalloc(sizeof(*pn), GFP_KERNEL);
	if (!pn) {
		for (i = 0; i < nr; i++)
			put_page(pages[i]);
		kvfree(pages);
		kvfree(obs);
		ret = -ENOMEM;
		goto out_put;
	}
	/* the observation follows the GUP: breaking COW demotes the page */
	cur_va = mr->va_start + idx0 * PAGE_SIZE;
	for (i = 0; i < nr; i++, cur_va += PAGE_SIZE)
		obs[i].gen = symrdma_page_gen(mr, idx0 + i);
	pn->idx0  = idx0;
	pn->nr    = nr;
	pn->pages = pages;

	spin_lock(&st->lock);

	if (mr->mm_state != st) {
		spin_unlock(&st->lock);
		kfree(pn);
		for (i = 0; i < nr; i++)
			put_page(pages[i]);
		kvfree(pages);
		kvfree(obs);
		ret = -ENOENT;
		goto out_put;
	}

	if (mr->pinned_pages + nr > SYMRDMA_PIN_BUDGET_PAGES) {
		spin_unlock(&st->lock);
		kfree(pn);
		for (i = 0; i < nr; i++)
			put_page(pages[i]);
		kvfree(pages);
		kvfree(obs);
		atomic64_inc(&dev->stats.pin_enospc);
		ret = -ENOSPC;
		goto out_put;
	}

	cur_va = mr->va_start + idx0 * PAGE_SIZE;
	for (i = 0; i < nr; i++) {
		ret = pin_align_page(mr, idx0 + i,
				     symrdma_va_to_pa(pages[i], cur_va),
				     obs[i].gen);
		if (ret) {
			unsigned long k;

			for (k = 0; k < i; k++)
				if (mr->pages[idx0 + k].dma_ref)
					mr->pages[idx0 + k].dma_ref--;
			spin_unlock(&st->lock);
			kfree(pn);
			for (k = 0; k < nr; k++)
				put_page(pages[k]);
			kvfree(pages);
			kvfree(obs);
			atomic64_inc(&dev->stats.repair_fail);
			goto out_put;
		}
		mr->pages[idx0 + i].dma_ref++;
		cur_va += PAGE_SIZE;
	}
	kvfree(obs);
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

	st = symrdma_mm_state_get(mr);
	if (!st)
		return -ENOENT;

	spin_lock(&st->lock);

	if (mr->mm_state != st) {
		spin_unlock(&st->lock);
		symrdma_mm_state_put(st);
		return -ENOENT;
	}

	list_for_each_entry_safe(pn, tmp, &mr->pin_list, node) {
		unsigned long i;

		if (!all && (pn->idx0 != idx0 || pn->nr != nr))
			continue;

		list_move_tail(&pn->node, &dead);
		mr->pinned_pages -= pn->nr;
		freed += pn->nr;
		for (i = 0; i < pn->nr; i++) {
			u16 c = mr->pages[pn->idx0 + i].dma_ref;

			mr->pages[pn->idx0 + i].dma_ref =
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

	if (mr->mm == current->mm)
		mmap_read_lock(mr->mm);

	list_for_each_entry_safe(pn, tmp, &dead, node) {
		unsigned long i;

		for (i = 0; i < pn->nr; i++) {
			unsigned long idx = pn->idx0 + i;
			struct symrdma_obs pobs;
			enum symrdma_backing pbk = SBK_ERROR;
			u8 preason = SPB_R_NONE;
			int pr;

			if (mr->pages[idx].dma_ref > 0)
				continue;

			pr = symrdma_backing_probe(mr, idx, SPB_HINT, &pobs,
						   &pbk, &preason);
			if (pr == -EAGAIN)
				continue;
			if (!pr && pbk == SBK_REAL)
				continue;

			spin_lock(&st->lock);
			if (mr->mm_state == st)
				pin_complete_transition(mr, idx);
			spin_unlock(&st->lock);
		}

		for (i = 0; i < pn->nr; i++)
			put_page(pn->pages[i]);
		kvfree(pn->pages);
		list_del(&pn->node);
		kfree(pn);
	}

	if (mr->mm == current->mm)
		mmap_read_unlock(mr->mm);

	symrdma_mm_state_put(st);

	atomic64_sub(freed, &dev->stats.pin_pages);
	return 0;
}

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
			mr->pages[pn->idx0 + i].dma_ref = 0;
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
