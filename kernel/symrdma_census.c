// SPDX-License-Identifier: GPL-2.0

/*
 * Census: the page-state judgement, one visible row per page.
 *
 * Why this exists: every "no fault was injected, so there must be no repair"
 * style criterion needs an answer to "was this page actually missing, and if it
 * was, did the repair succeed?".  Counting repair verbs cannot answer that - a
 * verb's own report says what the caller tried, not what the page was.  So the
 * judgement is made here, by the same probe the runtime uses, and reported with
 * the evidence that makes it checkable: the gen the verdict was taken at, the
 * two mapping targets, the last transition's cause and its sequence number.
 *
 * What "absent" means here: the page is not serving real bytes.  That is a
 * property of the page's two mappings AND of its backing - a page can be parked
 * on the sentinel with its backing perfectly intact (that is exactly the state a
 * forced demote, a swap-out storm or a failed promote leaves behind), and a
 * verdict that only asked the page tables would call it fine.  So the mappings
 * are read first, and a parked mapping is absent whatever the backing says.
 *
 * Two modes, and the difference matters:
 *   mode 0 decides only.  A reader may run it as often as it likes: no
 *          side effects, no version moves, no repair.
 *   mode 1 decides and repairs.  A page it decides is absent (or stale) is
 *          handed to the repair verb; the row then says whether the repair
 *          succeeded.  "Absent" and "repair failed" are different facts, and a
 *          criterion that folds them together cannot tell a correct system from
 *          a broken one.
 *
 * `cookie` closes the interval: it is mr->trans_seq after the pass, so a gate
 * can assert "no transition inside the window has a cause_seq beyond the cookie
 * I took at its start" - an interval, not a sampling artefact.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"

/* The wire values are the authority's own: one definition, checked here. */
static_assert(SYMRDMA_MAP_UNMAPPED == 0, "map kind on the wire");
static_assert(SYMRDMA_MAP_REAL == 1, "map kind on the wire");
static_assert(SYMRDMA_MAP_SENTINEL == 2, "map kind on the wire");
static_assert(SYMRDMA_MAP_BLACKHOLE == 3, "map kind on the wire");

static u8 verdict_from_backing(enum symrdma_backing bk)
{
	switch (bk) {
	case SBK_REAL:
		return SYMRDMA_CV_OK;
	case SBK_REALIGN:
		return SYMRDMA_CV_STALE;
	case SBK_ABSENT:
		return SYMRDMA_CV_ABSENT;
	case SBK_UNMAPPABLE:
		return SYMRDMA_CV_UNMAPPABLE;
	case SBK_SPECIAL:
		return SYMRDMA_CV_SPECIAL;
	case SBK_ERROR:
	default:
		return SYMRDMA_CV_ERROR;
	}
}

/* Is this verdict one the repair verb can act on? */
static bool verdict_repairable(u8 v)
{
	return v == SYMRDMA_CV_ABSENT || v == SYMRDMA_CV_STALE;
}

static u8 verdict_after_repair(u8 v, bool ok)
{
	if (v == SYMRDMA_CV_STALE)
		return ok ? SYMRDMA_CV_STALE_REPAIRED
			  : SYMRDMA_CV_STALE_REPAIR_FAILED;

	return ok ? SYMRDMA_CV_ABSENT_REPAIRED
		  : SYMRDMA_CV_ABSENT_REPAIR_FAILED;
}

int symrdma_census_run(struct symrdma_dev *dev, struct symrdma_mr *mr,
		       unsigned long page_idx, unsigned long npages, u32 mode,
		       struct symrdma_census_page *rows, u32 *nrows,
		       u64 *cookie)
{
	struct symrdma_mm_state *st;
	unsigned long i;

	if (mode > 1)
		return -EINVAL;

	st = symrdma_mm_state_get(mr);
	if (!st)
		return -ENOENT;

	for (i = 0; i < npages; i++) {
		unsigned long idx = page_idx + i;
		struct symrdma_census_page *row = &rows[i];
		struct symrdma_obs obs = {};
		enum symrdma_backing bk = SBK_ERROR;
		enum symrdma_probe_intent intent = mode ? SPB_DMA_RW : SPB_HINT;
		u8 reason = 0;
		int ret;

		/* the state as it stands before any decision (under the lock) */
		spin_lock(&st->lock);
		row->gen = mr->pages[idx].gen;
		row->rmap = mr->pages[idx].rmap;
		row->wmap = mr->pages[idx].wmap;
		row->cause = mr->pages[idx].cause;
		row->cause_seq = mr->pages[idx].cause_seq;
		spin_unlock(&st->lock);

		ret = symrdma_backing_probe(mr, idx, intent, &obs, &bk, &reason);
		if (ret == -EAGAIN) {
			/* the page moved while it was being judged: say so rather
			 * than report a verdict taken across the move */
			row->verdict = SYMRDMA_CV_ERROR;
			continue;
		}
		if (ret) {
			row->verdict = SYMRDMA_CV_ERROR;
			continue;
		}

		if (row->rmap != SYMRDMA_MAP_REAL || row->wmap != SYMRDMA_MAP_REAL) {
			/* parked: the IOVA does not serve the page, whatever the
			 * page tables say */
			row->verdict = SYMRDMA_CV_ABSENT;
		} else {
			row->verdict = verdict_from_backing(bk);
		}
		if (mode && verdict_repairable(row->verdict)) {
			int rep = symrdma_repair_page(dev, mr, idx);

			row->verdict = verdict_after_repair(row->verdict,
							    rep == 0);
		}
	}

	*nrows = (u32)npages;
	*cookie = READ_ONCE(mr->trans_seq);
	symrdma_mm_state_put(st);
	return 0;
}
