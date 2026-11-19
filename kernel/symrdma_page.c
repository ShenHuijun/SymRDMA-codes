/* SPDX-License-Identifier: GPL-2.0 */

/*
 * The single state authority for SymRDMA page state (the single-authority rule).
 *
 * mr->pages[] is the only page state and the version table is its mirror.
 * Every transition goes through one of the verbs below; nothing else writes
 * rmap/wmap/pa/gen/cause_seq, and nothing else writes a version slot.
 *
 * The verbs own what a call site must not be able to get wrong:
 *   - ordering, which is opposite for the two directions
 *       demote : version first, then unmap/map, then one sync per domain
 *       promote: map, sync, then bump the version
 *   - IOMMU permissions, which follow from the target alone
 *   - the dma_ref barrier (the flush-before-unmap barrier): a demote of a page with in-flight DMA is
 *     refused, never forced
 *   - the version mirror: a transition is never published without it
 *   - gen validation for promote: a stale observation changes nothing
 *
 * gen parity: the read IOVA points at a real page exactly when gen is odd.
 * A transition flips the parity, and a parity flip is the only thing that
 * bumps gen (+1).  Registration publishes a shape without bumping (it is not
 * a transition: nothing was ever visible before it).
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"
#include <asm/pgtable.h>
#include <linux/scatterlist.h>
#include <linux/ktime.h>

#define SYMRDMA_REPAIR_SYNC_TARGET_US 100

/* ------------------------------------------------------------------ */
/* gather accounting                                                   */
/* ------------------------------------------------------------------ */

static void sync_track(struct symrdma_dev *dev, struct iommu_iotlb_gather *g)
{
	u64 t0, us, prev;

	if (!g->pgsize)
		return;
	t0 = ktime_get_ns();
	iommu_iotlb_sync(dev->iommu_domain, g);
	us = div_u64(ktime_get_ns() - t0, 1000);
	atomic64_set(&dev->stats.repair_sync_us_last, us);
	prev = atomic64_read(&dev->stats.repair_sync_us_max);
	while (us > prev) {
		u64 old = atomic64_cmpxchg(&dev->stats.repair_sync_us_max,
					   prev, us);

		if (old == prev)
			break;
		prev = old;
	}
}

/* ------------------------------------------------------------------ */
/* slot primitives                                                     */
/* ------------------------------------------------------------------ */

/*
 * Point one IOVA slot at the target.  A map failure never leaves the slot
 * empty: it is parked on the fail-closed page of its own domain, so a stale
 * translation can only ever leak sentinel magic or swallow a write.
 */
static int slot_set_locked(struct symrdma_dev *dev, u64 iova, bool write,
			   u8 target, phys_addr_t pa,
			   struct iommu_iotlb_gather *g)
{
	phys_addr_t want;
	u8 prot;

	switch (target) {
	case SYMRDMA_MAP_REAL:
		want = pa;
		prot = IOMMU_READ | IOMMU_WRITE;
		break;
	case SYMRDMA_MAP_SENTINEL:
		want = dev->sentinel_pa;
		prot = IOMMU_READ;
		break;
	case SYMRDMA_MAP_BLACKHOLE:
		want = dev->blackhole_pa;
		prot = IOMMU_WRITE;
		break;
	default:
		iommu_unmap_fast(dev->iommu_domain, iova, PAGE_SIZE, g);
		return 0;
	}

	iommu_unmap_fast(dev->iommu_domain, iova, PAGE_SIZE, g);
	if (!iommu_map_atomic(dev->iommu_domain, iova, want, PAGE_SIZE, prot))
		return 0;

	pr_err_ratelimited("iommu map failed iova=0x%llx target=%u, parked fail-closed\n",
			   iova, target);
	if (write)
		iommu_map_atomic(dev->iommu_domain, iova, dev->blackhole_pa,
				 PAGE_SIZE, IOMMU_WRITE);
	else
		iommu_map_atomic(dev->iommu_domain, iova, dev->sentinel_pa,
				 PAGE_SIZE, IOMMU_READ);
	return -EIO;
}

/*
 * Flip the gen parity (the only thing that bumps gen) and mirror it into the
 * version table in the same critical section.  A missing slot is reported,
 * never papered over: the caller decides whether that is fail-closed.
 */
static u32 gen_flip_locked(struct symrdma_mr *mr, unsigned long idx,
			   bool target_odd, int *err)
{
	struct symrdma_page *pe = &mr->pages[idx];
	u32 gen = pe->gen;

	if ((bool)(gen & 1) == target_odd)
		return gen;

	pe->gen = ++gen;
	if (symrdma_version_write(mr, idx, gen))
		*err = -EIO;
	return gen;
}

/* Publish the shape of a transitioned page and record it for forensics. */
static void page_note_locked(struct symrdma_mr *mr, unsigned long idx,
			     u8 rmap, u8 wmap, phys_addr_t pa, u8 cause)
{
	struct symrdma_page *pe = &mr->pages[idx];

	pe->rmap = rmap;
	pe->wmap = wmap;
	/*
	 * The recorded PA only moves when a promote names one: a write-only
	 * demote keeps a real read target and knows nothing about its PA, so
	 * it must not clear what the promote recorded (the restore direction
	 * and the REMAP real branch both read it back).
	 */
	if (rmap == SYMRDMA_MAP_REAL && pa)
		pe->pa = pa;
	else if (rmap == SYMRDMA_MAP_REAL && wmap == SYMRDMA_MAP_REAL)
		WARN_ON_ONCE(1);	/* a fully real publish must name its PA */
	pe->cause = cause;
	pe->cause_seq = ++mr->trans_seq;
	symrdma_trans_record(mr, idx, cause);
}

/*
 * Park one page on the fail-closed targets.  Used when a mapping step failed:
 * the state must describe what the IOMMU now holds, never what was intended.
 */
static void page_park_locked(struct symrdma_mr *mr, unsigned long idx,
			     u8 cause, int *err)
{
	struct symrdma_dev *dev = mr->dev;
	struct iommu_iotlb_gather gr, gw;

	iommu_iotlb_gather_init(&gr);
	iommu_iotlb_gather_init(&gw);
	slot_set_locked(dev, mr->read_iova + idx * PAGE_SIZE, false,
			SYMRDMA_MAP_SENTINEL, 0, &gr);
	slot_set_locked(dev, mr->write_iova + idx * PAGE_SIZE, true,
			SYMRDMA_MAP_BLACKHOLE, 0, &gw);
	sync_track(dev, &gr);
	sync_track(dev, &gw);
	gen_flip_locked(mr, idx, false, err);
	page_note_locked(mr, idx, SYMRDMA_MAP_SENTINEL,
			 SYMRDMA_MAP_BLACKHOLE, 0, cause);
}

/* Registration publish: no gen bump, no cause, no trans_seq (not a transition). */
static void page_setup_locked(struct symrdma_mr *mr, unsigned long idx,
			      u8 rmap, u8 wmap, phys_addr_t pa)
{
	struct symrdma_page *pe = &mr->pages[idx];
	u32 gen = (rmap == SYMRDMA_MAP_REAL) ? SYMRDMA_VERSION_INIT_RESIDENT
					     : SYMRDMA_VERSION_INIT_ABSENT;

	pe->gen = gen;
	pe->rmap = rmap;
	pe->wmap = wmap;
	pe->pa = (rmap == SYMRDMA_MAP_REAL) ? pa : 0;
	pe->probe_gen = 0;
	pe->cause = SYMRDMA_TRANS_SETUP;
	pe->cause_seq = 0;
	if (symrdma_version_write(mr, idx, gen))
		pr_err_ratelimited("version slot missing at registration mr=%d idx=%lu\n",
				   mr->mr_id, idx);
}

u32 symrdma_page_gen(const struct symrdma_mr *mr, unsigned long idx)
{
	if (!mr->pages || idx >= mr->npages)
		return 0;
	return READ_ONCE(mr->pages[idx].gen);
}

/* ------------------------------------------------------------------ */
/* single-page verbs                                                   */
/* ------------------------------------------------------------------ */

int symrdma_page_demote_locked(struct symrdma_mr *mr, unsigned long idx,
			       u8 rmap, u8 wmap, u8 cause)
{
	struct symrdma_mm_state *st = mr->mm_state;
	struct symrdma_dev *dev = mr->dev;
	struct iommu_iotlb_gather gr, gw;
	struct symrdma_page *pe;
	int err = 0;

	if (!st)
		return -ENOENT;
	lockdep_assert_held(&st->lock);
	if (!mr->dev->iommu_domain || idx >= mr->npages)
		return -EINVAL;

	symrdma_group_ensure_split_locked(mr, idx);

	pe = &mr->pages[idx];
	if (pe->rmap == rmap && pe->wmap == wmap)
		return 0;
	if (pe->dma_ref)
		return -EBUSY;

	/*
	 * The version says "gone" before the mapping is rerouted.  The target
	 * parity follows the read target: a write-only demote leaves the read
	 * IOVA pointing at a real page, so it must leave an odd gen alone.
	 */
	gen_flip_locked(mr, idx, rmap == SYMRDMA_MAP_REAL, &err);

	iommu_iotlb_gather_init(&gr);
	iommu_iotlb_gather_init(&gw);
	if (pe->rmap != rmap &&
	    slot_set_locked(dev, mr->read_iova + idx * PAGE_SIZE, false, rmap,
			    0, &gr))
		err = -EIO;
	if (pe->wmap != wmap &&
	    slot_set_locked(dev, mr->write_iova + idx * PAGE_SIZE, true, wmap,
			    0, &gw))
		err = -EIO;
	sync_track(dev, &gr);
	sync_track(dev, &gw);

	if (err) {
		page_park_locked(mr, idx, cause, &err);
		symrdma_state_assert(mr, idx);
		return err;
	}
	page_note_locked(mr, idx, rmap, wmap, 0, cause);
	symrdma_state_assert(mr, idx);
	return 0;
}

int symrdma_page_promote_locked(struct symrdma_mr *mr, unsigned long idx,
				struct symrdma_obs *obs, u8 cause)
{
	struct symrdma_mm_state *st = mr->mm_state;
	struct symrdma_dev *dev = mr->dev;
	struct iommu_iotlb_gather gr, gw;
	struct symrdma_page *pe;
	phys_addr_t pa;
	int err = 0, mret = 0;

	if (!st)
		return -ENOENT;
	lockdep_assert_held(&st->lock);
	if (!mr->dev->iommu_domain || !obs || idx >= mr->npages)
		return -EINVAL;

	symrdma_group_ensure_split_locked(mr, idx);

	pe = &mr->pages[idx];
	if (obs->gen != pe->gen)
		return -EAGAIN;
	if (symrdma_version_slot_ok(mr, idx))
		return -EIO;

	/*
	 * A real page that the observation sees at a different PA was moved
	 * under us without a demote.  Repointing it in place would publish a
	 * mapping change with an unchanged version, so walk the page out
	 * through a demote first and take the observation's PA as the new
	 * epoch: two transitions, +2, parity back to odd.
	 */
	if (pe->rmap == SYMRDMA_MAP_REAL && pe->pa != obs->pa) {
		int ret = symrdma_page_demote_locked(mr, idx,
						     SYMRDMA_MAP_SENTINEL,
						     SYMRDMA_MAP_BLACKHOLE,
						     cause);

		if (ret)
			return ret;
		obs->gen = pe->gen;
	}

	pa = obs->pa;
	iommu_iotlb_gather_init(&gr);
	iommu_iotlb_gather_init(&gw);
	mret = slot_set_locked(dev, mr->read_iova + idx * PAGE_SIZE, false,
			       SYMRDMA_MAP_REAL, pa, &gr);
	if (slot_set_locked(dev, mr->write_iova + idx * PAGE_SIZE, true,
			    SYMRDMA_MAP_REAL, pa, &gw))
		mret = -EIO;
	sync_track(dev, &gr);
	sync_track(dev, &gw);
	if (mret) {
		page_park_locked(mr, idx, cause, &err);
		symrdma_state_assert(mr, idx);
		return -EIO;
	}
	/* the promote-order rule: never let the version say "real" before DMA can land. */
	sync_track(dev, &gr);
	sync_track(dev, &gw);

	gen_flip_locked(mr, idx, true, &err);
	page_note_locked(mr, idx, SYMRDMA_MAP_REAL, SYMRDMA_MAP_REAL, pa,
			 cause);
	symrdma_state_assert(mr, idx);
	return err;
}

/* ------------------------------------------------------------------ */
/* batch verbs                                                         */
/* ------------------------------------------------------------------ */

int symrdma_pages_demote_locked(struct symrdma_mr *mr,
				const unsigned long *idx, unsigned long n,
				u8 rmap, u8 wmap, u8 cause,
				unsigned long *done, unsigned long *deferred)
{
	struct symrdma_mm_state *st = mr->mm_state;
	struct symrdma_dev *dev = mr->dev;
	DECLARE_BITMAP(badmask, SYMRDMA_BATCH_MAX);
	struct iommu_iotlb_gather gr, gw;
	unsigned long k, ndone = 0, ndef = 0;
	int err = 0;

	if (done)
		*done = 0;
	if (deferred)
		*deferred = 0;
	if (!st)
		return -ENOENT;
	lockdep_assert_held(&st->lock);
	if (!mr->dev->iommu_domain || !n)
		return -EINVAL;
	if (WARN_ON_ONCE(n > SYMRDMA_BATCH_MAX))
		n = SYMRDMA_BATCH_MAX;

	symrdma_group_ensure_split_range_locked(mr, idx[0], idx[n - 1]);

	bitmap_zero(badmask, SYMRDMA_BATCH_MAX);
	iommu_iotlb_gather_init(&gr);
	iommu_iotlb_gather_init(&gw);

	/* demote: versions first, then the mappings, then one sync per domain */
	for (k = 0; k < n; k++) {
		struct symrdma_page *pe = &mr->pages[idx[k]];
		bool bad = false;

		if (pe->rmap == rmap && pe->wmap == wmap)
			continue;
		if (pe->dma_ref) {
			ndef++;
			continue;
		}
		gen_flip_locked(mr, idx[k], rmap == SYMRDMA_MAP_REAL, &err);
		if (pe->rmap != rmap &&
		    slot_set_locked(dev, mr->read_iova + idx[k] * PAGE_SIZE,
				    false, rmap, 0, &gr))
			bad = true;
		if (pe->wmap != wmap &&
		    slot_set_locked(dev, mr->write_iova + idx[k] * PAGE_SIZE,
				    true, wmap, 0, &gw))
			bad = true;
		if (bad)
			__set_bit(k, badmask);
	}
	sync_track(dev, &gr);
	sync_track(dev, &gw);

	for (k = 0; k < n; k++) {
		struct symrdma_page *pe = &mr->pages[idx[k]];

		if (pe->rmap == rmap && pe->wmap == wmap)
			continue;
		if (pe->dma_ref)
			continue;
		if (test_bit(k, badmask)) {
			/* only this page parks, and its state follows */
			page_park_locked(mr, idx[k], cause, &err);
		} else {
			page_note_locked(mr, idx[k], rmap, wmap, 0, cause);
		}
		symrdma_state_assert(mr, idx[k]);
		ndone++;
	}

	if (done)
		*done = ndone;
	if (deferred)
		*deferred = ndef;
	if (ndef && !ndone)
		return -EBUSY;
	return err;
}

/*
 * Promote a contiguous range.  obs[i] belongs to first+i; a page whose gen
 * moved on is skipped untouched (-EAGAIN for that page, never a silent
 * normalisation).  sg != NULL selects the sg-run hardware path (the chunked-repair rule); the
 * caller picks it from the repair_sg kill-switch, the verb owns both.
 */
int symrdma_pages_promote_locked(struct symrdma_mr *mr, unsigned long first,
				 unsigned long n, struct symrdma_obs *obs,
				 u8 cause, struct scatterlist *sg,
				 unsigned long *mapped)
{
	struct symrdma_mm_state *st = mr->mm_state;
	struct symrdma_dev *dev = mr->dev;
	DECLARE_BITMAP(okmask, SYMRDMA_BATCH_MAX);
	struct iommu_iotlb_gather gr, gw;
	unsigned long k, nmapped = 0;
	unsigned int nents = 0;
	bool sg_read = false, sg_write = false;
	size_t expect;
	int err = 0;

	if (mapped)
		*mapped = 0;
	if (!st)
		return -ENOENT;
	lockdep_assert_held(&st->lock);
	if (!mr->dev->iommu_domain || !n || !obs || first + n > mr->npages)
		return -EINVAL;
	if (WARN_ON_ONCE(n > SYMRDMA_BATCH_MAX))
		n = SYMRDMA_BATCH_MAX;

	symrdma_group_ensure_split_range_locked(mr, first, first + n - 1);

	bitmap_zero(okmask, SYMRDMA_BATCH_MAX);
	for (k = 0; k < n; k++) {
		struct symrdma_page *pe = &mr->pages[first + k];

		if (obs[k].gen != pe->gen)
			continue;
		if (symrdma_version_slot_ok(mr, first + k))
			continue;
		/*
		 * A real page seen at another PA: walk it out and adopt the
		 * observation as the new epoch (+2, parity preserved).
		 */
		if (pe->rmap == SYMRDMA_MAP_REAL && pe->pa != obs[k].pa) {
			if (symrdma_page_demote_locked(mr, first + k,
						       SYMRDMA_MAP_SENTINEL,
						       SYMRDMA_MAP_BLACKHOLE,
						       cause))
				continue;
			obs[k].gen = pe->gen;
		}
		__set_bit(k, okmask);
	}
	if (bitmap_empty(okmask, n))
		return -EAGAIN;

	expect = n * PAGE_SIZE;
	iommu_iotlb_gather_init(&gr);
	iommu_iotlb_gather_init(&gw);

	if (sg && bitmap_full(okmask, n)) {
		unsigned long i = 0;
		unsigned int nent = 0;

		/* sg-run path: one unmap + one map_sg per domain */
		while (i < n) {
			unsigned long run = 1;
			struct page *p;

			while (i + run < n && run < SYMRDMA_GROUP_PAGES &&
			       obs[i + run].pa == obs[i].pa + run * PAGE_SIZE)
				run++;
			if (!pfn_valid(PHYS_PFN(obs[i].pa)))
				break;
			p = pfn_to_page(PHYS_PFN(obs[i].pa));
			sg_set_page(&sg[nent], p, run * PAGE_SIZE, 0);
			sg[nent].page_link &= ~(SG_CHAIN | SG_END);
			nent++;
			i += run;
		}
		if (i == n) {
			sg_mark_end(&sg[nent - 1]);
			nents = nent;
			iommu_unmap_fast(dev->iommu_domain,
					 mr->read_iova + first * PAGE_SIZE,
					 expect, &gr);
			if (iommu_map_sg_atomic(dev->iommu_domain,
						mr->read_iova +
							first * PAGE_SIZE,
						sg, nents,
						IOMMU_READ | IOMMU_WRITE) ==
			    expect)
				sg_read = true;
			else
				iommu_unmap_fast(dev->iommu_domain,
						 mr->read_iova +
							first * PAGE_SIZE,
						 expect, &gr);
		}
	}

	if (!sg_read) {
		/* per-page interleaved path */
		for (k = 0; k < n; k++) {
			if (!test_bit(k, okmask))
				continue;
			if (slot_set_locked(dev,
					    mr->read_iova +
						(first + k) * PAGE_SIZE,
					    false, SYMRDMA_MAP_REAL,
					    obs[k].pa, &gr))
				__clear_bit(k, okmask);
		}
	}

	if (sg && bitmap_full(okmask, n) && nents) {
		iommu_unmap_fast(dev->iommu_domain,
				 mr->write_iova + first * PAGE_SIZE, expect, &gw);
		if (iommu_map_sg_atomic(dev->iommu_domain,
					mr->write_iova + first * PAGE_SIZE,
					sg, nents,
					IOMMU_READ | IOMMU_WRITE) == expect)
			sg_write = true;
		else
			iommu_unmap_fast(dev->iommu_domain,
					 mr->write_iova + first * PAGE_SIZE,
					 expect, &gw);
	}
	if (!sg_write) {
		for (k = 0; k < n; k++) {
			if (!test_bit(k, okmask))
				continue;
			if (slot_set_locked(dev,
					    mr->write_iova +
						(first + k) * PAGE_SIZE,
					    true, SYMRDMA_MAP_REAL,
					    obs[k].pa, &gw))
				__clear_bit(k, okmask);
		}
	}

	/* the sync happens before the version is allowed to say "real" */
	sync_track(dev, &gr);
	sync_track(dev, &gw);

	for (k = 0; k < n; k++) {
		struct symrdma_page *pe = &mr->pages[first + k];

		if (test_bit(k, okmask)) {
			gen_flip_locked(mr, first + k, true, &err);
			page_note_locked(mr, first + k, SYMRDMA_MAP_REAL,
					 SYMRDMA_MAP_REAL, obs[k].pa, cause);
			nmapped++;
		} else if (obs[k].gen == pe->gen &&
			   (pe->rmap == SYMRDMA_MAP_REAL ||
			    pe->wmap == SYMRDMA_MAP_REAL)) {
			/* a real page that could not be remapped: park it */
			gen_flip_locked(mr, first + k, false, &err);
			page_note_locked(mr, first + k, SYMRDMA_MAP_SENTINEL,
					 SYMRDMA_MAP_BLACKHOLE, 0, cause);
		} else {
			continue;
		}
		symrdma_state_assert(mr, first + k);
	}

	if (mapped)
		*mapped = nmapped;
	if (!nmapped)
		return -EAGAIN;
	return err;
}

/* ------------------------------------------------------------------ */
/* group verbs (IOMMU 2MB groups; groups[] is only written here)        */
/* ------------------------------------------------------------------ */

static unsigned long mr_group_count(const struct symrdma_mr *mr)
{
	return DIV_ROUND_UP(mr->npages, SYMRDMA_GROUP_PAGES);
}

/*
 * Split one 2MB group into 512 per-page mappings without changing what the
 * pages mean: a resident group keeps pointing at the same real pages, an
 * absent group keeps pointing at the fail-closed pages.  This is a mapping
 * granularity change, not a transition, so no version moves.
 */
static int group_rebuild_per_page_locked(struct symrdma_mr *mr,
					 unsigned long grp, bool resident)
{
	struct symrdma_dev *dev = mr->dev;
	struct iommu_iotlb_gather gr, gw;
	DECLARE_BITMAP(bad, SYMRDMA_GROUP_PAGES);
	unsigned long base = grp * SYMRDMA_GROUP_PAGES;
	unsigned long k, n = min(SYMRDMA_GROUP_PAGES, mr->npages - base);
	bool inject = symrdma_test_demote_should_fail(grp);
	int err = 0;

	if (!mr->groups || grp >= mr_group_count(mr))
		return -EINVAL;

	bitmap_zero(bad, SYMRDMA_GROUP_PAGES);

	iommu_iotlb_gather_init(&gr);
	iommu_unmap_fast(dev->iommu_domain, mr->read_iova + base * PAGE_SIZE,
			 n * PAGE_SIZE, &gr);
	for (k = 0; k < n; k++) {
		struct symrdma_page *pe = &mr->pages[base + k];
		phys_addr_t pa = resident ? pe->pa : 0;
		u8 target = resident ? SYMRDMA_MAP_REAL : SYMRDMA_MAP_SENTINEL;

		if (inject && k == 0) {
			atomic64_inc(&dev->stats.demote_fail);
			slot_set_locked(dev,
					mr->read_iova + (base + k) * PAGE_SIZE,
					false, SYMRDMA_MAP_SENTINEL, 0, &gr);
			__set_bit(k, bad);
			err = -EIO;
			continue;
		}
		if (slot_set_locked(dev, mr->read_iova + (base + k) * PAGE_SIZE,
				    false, target, pa, &gr)) {
			atomic64_inc(&dev->stats.demote_fail);
			__set_bit(k, bad);
			err = -EIO;
		}
	}
	sync_track(dev, &gr);

	iommu_iotlb_gather_init(&gw);
	iommu_unmap_fast(dev->iommu_domain, mr->write_iova + base * PAGE_SIZE,
			 n * PAGE_SIZE, &gw);
	for (k = 0; k < n; k++) {
		phys_addr_t pa = resident ? mr->pages[base + k].pa : 0;
		u8 target = (resident && !test_bit(k, bad))
			  ? SYMRDMA_MAP_REAL : SYMRDMA_MAP_BLACKHOLE;

		if (slot_set_locked(dev, mr->write_iova + (base + k) * PAGE_SIZE,
				    true, target, pa, &gw)) {
			atomic64_inc(&dev->stats.demote_fail);
			__set_bit(k, bad);
			err = -EIO;
		}
	}
	sync_track(dev, &gw);

	/*
	 * A shape change is not a transition: on the success path no version
	 * moves and no field changes.  Only a page whose map failed changes
	 * meaning, and it is already parked on the fail-closed pages, so the
	 * version flip cannot expose a wrong translation.
	 */
	for_each_set_bit(k, bad, n) {
		gen_flip_locked(mr, base + k, false, &err);
		page_note_locked(mr, base + k, SYMRDMA_MAP_SENTINEL,
				 SYMRDMA_MAP_BLACKHOLE, 0, SYMRDMA_TRANS_PARK);
	}

	mr->groups[grp].state = GRP_NONE;
	mr->groups[grp].base_pa = 0;
	atomic64_inc(&dev->stats.group_demotes);
	return err;
}

int symrdma_group_materialize_locked(struct symrdma_mr *mr, unsigned long grp)
{
	struct symrdma_mm_state *st = mr->mm_state;
	bool resident;

	if (!st)
		return -ENOENT;
	lockdep_assert_held(&st->lock);
	if (!mr->groups || grp >= mr_group_count(mr))
		return -EINVAL;
	if (mr->groups[grp].state == GRP_NONE)
		return 0;

	resident = mr->groups[grp].state == GRP_RESIDENT;
	return group_rebuild_per_page_locked(mr, grp, resident);
}

int symrdma_group_collapse_2m_locked(struct symrdma_mr *mr, unsigned long grp,
				     phys_addr_t base_pa)
{
	struct symrdma_dev *dev = mr->dev;
	struct symrdma_mm_state *st = mr->mm_state;
	struct iommu_iotlb_gather g;
	unsigned long base = grp * SYMRDMA_GROUP_PAGES;
	unsigned long k, n;
	u64 riova, wiova;
	int err = 0;

	if (!st)
		return -ENOENT;
	lockdep_assert_held(&st->lock);
	if (!mr->groups || grp >= mr_group_count(mr) || !base_pa)
		return -EINVAL;

	n = min(SYMRDMA_GROUP_PAGES, mr->npages - base);
	if (n != SYMRDMA_GROUP_PAGES)
		return -EINVAL;
	if (!IS_ALIGNED(base_pa, SYMRDMA_GROUP_SIZE))
		return -EINVAL;

	if (mr->groups[grp].state == GRP_RESIDENT &&
	    mr->groups[grp].base_pa == base_pa) {
		atomic64_inc(&dev->stats.group_repromote);
		return 0;
	}

	/* a 2MB mapping cannot overlap a per-page one: drop the shape first */
	mr->groups[grp].state = GRP_NONE;
	mr->groups[grp].base_pa = 0;

	riova = mr->read_iova + base * PAGE_SIZE;
	wiova = mr->write_iova + base * PAGE_SIZE;

	iommu_iotlb_gather_init(&g);
	iommu_unmap_fast(dev->iommu_domain, riova, SYMRDMA_GROUP_SIZE, &g);
	if (iommu_map_atomic(dev->iommu_domain, riova, base_pa,
			     SYMRDMA_GROUP_SIZE, IOMMU_READ | IOMMU_WRITE)) {
		sync_track(dev, &g);
		return -EIO;
	}
	sync_track(dev, &g);

	iommu_iotlb_gather_init(&g);
	iommu_unmap_fast(dev->iommu_domain, wiova, SYMRDMA_GROUP_SIZE, &g);
	if (iommu_map_atomic(dev->iommu_domain, wiova, base_pa,
			     SYMRDMA_GROUP_SIZE, IOMMU_READ | IOMMU_WRITE)) {
		sync_track(dev, &g);
		iommu_unmap_fast(dev->iommu_domain, riova,
				 SYMRDMA_GROUP_SIZE, &g);
		sync_track(dev, &g);
		return -EIO;
	}
	sync_track(dev, &g);

	/* DMA can land now; only here may the versions say "real" */
	for (k = 0; k < n; k++) {
		gen_flip_locked(mr, base + k, true, &err);
		page_note_locked(mr, base + k, SYMRDMA_MAP_REAL,
				 SYMRDMA_MAP_REAL, base_pa + k * PAGE_SIZE,
				 SYMRDMA_TRANS_REPAIR);
		symrdma_state_assert(mr, base + k);
	}

	mr->groups[grp].base_pa = base_pa;
	mr->groups[grp].state = GRP_RESIDENT;
	atomic64_inc(&dev->stats.group_repromote);
	return err;
}

/*
 * The group overlay is a cache of mr->pages[]: every reader checks it
 * against the 512 entries it claims to describe.  A mismatch is reported and
 * the caller falls back to the per-page shape; it is never silently trusted.
 */
int symrdma_group_verify_locked(struct symrdma_mr *mr, unsigned long grp)
{
	struct symrdma_dev *dev = mr->dev;
	unsigned long base = grp * SYMRDMA_GROUP_PAGES;
	unsigned long k, n;
	u8 state;

	if (!mr->groups || grp >= mr_group_count(mr))
		return 0;

	state = mr->groups[grp].state;
	if (state == GRP_NONE)
		return 0;

	n = min(SYMRDMA_GROUP_PAGES, mr->npages - base);
	for (k = 0; k < n; k++) {
		struct symrdma_page *pe = &mr->pages[base + k];

		if (state == GRP_RESIDENT) {
			if (pe->rmap != SYMRDMA_MAP_REAL ||
			    pe->pa != mr->groups[grp].base_pa + k * PAGE_SIZE ||
			    !(pe->gen & 1))
				goto inconsistent;
		} else {
			if (pe->rmap != SYMRDMA_MAP_SENTINEL ||
			    pe->wmap != SYMRDMA_MAP_BLACKHOLE || (pe->gen & 1))
				goto inconsistent;
		}
	}
	return 0;

inconsistent:
	atomic64_inc(&dev->stats.group_inconsistent);
	WARN_ON_ONCE(1);
	pr_err_ratelimited("group overlay inconsistent: mr=%d grp=%lu state=%u idx=%lu\n",
			   mr->mr_id, grp, state, base + k);
	return -EIO;
}

void symrdma_group_ensure_split_locked(struct symrdma_mr *mr,
				       unsigned long page_idx)
{
	unsigned long grp;

	if (!mr->groups || page_idx >= mr->npages)
		return;
	grp = page_idx >> SYMRDMA_GROUP_SHIFT;
	if (grp >= mr_group_count(mr))
		return;
	if (mr->groups[grp].state == GRP_NONE)
		return;
	if (symrdma_group_verify_locked(mr, grp))
		WARN_ON_ONCE(1);
	symrdma_group_materialize_locked(mr, grp);
}

void symrdma_group_ensure_split_range_locked(struct symrdma_mr *mr,
					     unsigned long start_idx,
					     unsigned long end_idx)
{
	unsigned long grp, last;

	if (!mr->groups || start_idx >= mr->npages)
		return;
	if (end_idx >= mr->npages)
		end_idx = mr->npages - 1;
	if (start_idx > end_idx)
		return;
	last = min(end_idx >> SYMRDMA_GROUP_SHIFT, mr_group_count(mr) - 1);
	for (grp = start_idx >> SYMRDMA_GROUP_SHIFT; grp <= last; grp++) {
		if (mr->groups[grp].state == GRP_NONE)
			continue;
		if (symrdma_group_verify_locked(mr, grp))
			WARN_ON_ONCE(1);
		symrdma_group_materialize_locked(mr, grp);
	}
}

/* ------------------------------------------------------------------ */
/* backing observation                                                 */
/* ------------------------------------------------------------------ */

phys_addr_t symrdma_va_to_pa(struct page *page, unsigned long va)
{
	phys_addr_t pa = page_to_phys(page);

	if (PageCompound(page))
		pa += va & (page_size(page) - 1);
	return pa;
}

enum symrdma_group_probe {
	GRP_PROBE_ABSENT = 0,
	GRP_PROBE_HUGE,
	GRP_PROBE_TABLE,
};

static int group_probe(struct mm_struct *mm, unsigned long va,
		       struct page **page_out)
{
	pgd_t *pgd = pgd_offset(mm, va);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	*page_out = NULL;
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return GRP_PROBE_TABLE;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		return GRP_PROBE_TABLE;
	pud = pud_offset(p4d, va);
	if (pud_none(*pud))
		return GRP_PROBE_ABSENT;
	if (unlikely(pud_trans_huge(*pud))) {
		struct page *page;

		if (!pud_write(*pud))
			return GRP_PROBE_TABLE;
		page = pud_page(*pud);
		get_page(page);
		*page_out = page;
		return GRP_PROBE_HUGE;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
		return GRP_PROBE_ABSENT;
	if (unlikely(pmd_trans_huge(*pmd))) {
		struct page *page;

		if (!pmd_write(*pmd))
			return GRP_PROBE_TABLE;
		page = pmd_page(*pmd);
		get_page(page);
		*page_out = page;
		return GRP_PROBE_HUGE;
	}
	return GRP_PROBE_TABLE;
}

/*
 * Read the CPU page tables for one MR page without touching them.  A page
 * whose gen moved during the walk yields -EAGAIN and no observation: that is
 * the whole point of the gen token.
 */
int symrdma_backing_probe(struct symrdma_mr *mr, unsigned long idx,
			  enum symrdma_probe_intent intent,
			  struct symrdma_obs *obs, enum symrdma_backing *bk,
			  u8 *reason)
{
	struct symrdma_page *pe;
	struct mm_struct *mm = mr->mm;
	unsigned long va;
	phys_addr_t pa = 0;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	u32 gen0, gen1;
	u8 why = SPB_R_NONE;
	int verdict;

	if (!mr->pages || idx >= mr->npages || !mm)
		return -EINVAL;

	pe = &mr->pages[idx];
	va = mr->va_start + idx * PAGE_SIZE;
	gen0 = READ_ONCE(pe->gen);

	pgd = pgd_offset(mm, va);
	if (pgd_none(*pgd)) {
		verdict = SBK_ABSENT;
		why = SPB_R_NO_PTE;
		goto out;
	}
	if (unlikely(pgd_bad(*pgd))) {
		verdict = SBK_ERROR;
		why = SPB_R_BAD_TABLE;
		goto out;
	}
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d)) {
		verdict = SBK_ABSENT;
		why = SPB_R_NO_PTE;
		goto out;
	}
	if (unlikely(p4d_bad(*p4d))) {
		verdict = SBK_ERROR;
		why = SPB_R_BAD_TABLE;
		goto out;
	}
	pud = pud_offset(p4d, va);
	if (pud_none(*pud)) {
		verdict = SBK_ABSENT;
		why = SPB_R_NO_PTE;
		goto out;
	}
	if (unlikely(pud_trans_huge(*pud))) {
		if (!pud_write(*pud)) {
			verdict = intent == SPB_DMA_RW ? SBK_REALIGN
						       : SBK_UNMAPPABLE;
			why = SPB_R_READONLY;
			goto out;
		}
		pa = symrdma_va_to_pa(pud_page(*pud), va);
		verdict = SBK_REAL;
		goto out;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd)) {
		verdict = SBK_ABSENT;
		why = SPB_R_NO_PTE;
		goto out;
	}
	if (unlikely(pmd_trans_huge(*pmd))) {
		if (!pmd_write(*pmd)) {
			verdict = intent == SPB_DMA_RW ? SBK_REALIGN
						       : SBK_UNMAPPABLE;
			why = SPB_R_READONLY;
			goto out;
		}
		pa = symrdma_va_to_pa(pmd_page(*pmd), va);
		verdict = SBK_REAL;
		goto out;
	}
	if (!pmd_present(*pmd)) {
		verdict = SBK_UNMAPPABLE;
		why = SPB_R_PROTNONE;
		goto out;
	}
	ptep = pte_offset_map(pmd, va);
	if (!ptep) {
		verdict = SBK_ERROR;
		why = SPB_R_BAD_TABLE;
		goto out;
	}
	if (pte_none(*ptep)) {
		verdict = SBK_ABSENT;
		why = SPB_R_NO_PTE;
	} else if (!pte_present(*ptep) && !pte_protnone(*ptep)) {
		/* a swap or migration entry: nothing is resident here */
		verdict = SBK_ABSENT;
		why = SPB_R_SWAPPED;
	} else if (pte_protnone(*ptep)) {
		verdict = SBK_UNMAPPABLE;
		why = SPB_R_PROTNONE;
	} else if (!pte_present(*ptep)) {
		verdict = SBK_UNMAPPABLE;
		why = SPB_R_PROTNONE;
	} else if (is_zero_pfn(pte_pfn(*ptep))) {
		verdict = SBK_UNMAPPABLE;
		why = SPB_R_ZERO;
	} else if (!pte_write(*ptep)) {
		verdict = intent == SPB_DMA_RW ? SBK_REALIGN
					       : SBK_UNMAPPABLE;
		why = SPB_R_READONLY;
	} else if (!pfn_valid(pte_pfn(*ptep))) {
		verdict = SBK_SPECIAL;
		why = SPB_R_SPECIAL_PFN;
	} else {
		pa = symrdma_va_to_pa(pte_page(*ptep), va);
		verdict = SBK_REAL;
	}
	pte_unmap(ptep);

out:
	gen1 = READ_ONCE(pe->gen);
	if (gen1 != gen0)
		return -EAGAIN;

	if (verdict == SBK_REAL && pa != pe->pa && pe->gen != 0) {
		/* a page is here, but it is not the one we recorded */
		verdict = SBK_REALIGN;
	}

	if (obs) {
		obs->gen = gen0;
		obs->pa = pa;
	}
	if (reason)
		*reason = why;

	switch (verdict) {
	case SBK_ABSENT:
		atomic64_inc(&mr->dev->stats.probe_absent);
		break;
	case SBK_REALIGN:
		atomic64_inc(&mr->dev->stats.probe_stale);
		break;
	case SBK_UNMAPPABLE:
		atomic64_inc(&mr->dev->stats.probe_unmappable);
		break;
	case SBK_SPECIAL:
		atomic64_inc(&mr->dev->stats.probe_special);
		break;
	default:
		break;
	}
	if (bk)
		*bk = verdict;
	return 0;
}

/* ------------------------------------------------------------------ */
/* GUP                                                                 */
/* ------------------------------------------------------------------ */

/*
 * Pin semantics: either every page is there (COW broken for write targets)
 * or the whole span is refused.  No unflagged second pass: a read-only page
 * is a verdict, not something to paper over with the zero page.
 */
int symrdma_gup_for_pin(unsigned long va, unsigned long nr,
			struct page **pages)
{
	unsigned long i;
	int r;

	r = get_user_pages_fast(va, nr, FOLL_WRITE, pages);
	if (r == nr)
		return 0;
	if (r > 0)
		for (i = 0; i < r; i++)
			put_page(pages[i]);

	r = get_user_pages_unlocked(va, nr, pages, FOLL_WRITE);
	if (r == nr)
		return 0;
	if (r > 0)
		for (i = 0; i < r; i++)
			put_page(pages[i]);

	return r < 0 ? r : -EFAULT;
}

/* Repair semantics: a short run is a prefix, and it is counted. */
unsigned long symrdma_gup_for_repair(unsigned long va, unsigned long nr,
				     struct page **pages)
{
	unsigned long done, i;
	int r;

	r = get_user_pages_fast(va, nr, FOLL_WRITE, pages);
	done = (r > 0) ? (unsigned long)r : 0;
	for (i = done; i < nr; i++) {
		r = get_user_pages_unlocked(va + i * PAGE_SIZE, 1, &pages[i],
					    FOLL_WRITE);
		if (r < 1)
			break;
		done = i + 1;
	}
	return done;
}

/* ------------------------------------------------------------------ */
/* registration                                                        */
/* ------------------------------------------------------------------ */

/* Sleepable mapping for the registration path (no lock, may allocate). */
static int map_region(struct symrdma_dev *dev, u64 iova, phys_addr_t pa,
		      size_t size, int prot)
{
	int ret;

	if (!dev->iommu_domain)
		return -ENODEV;
	ret = iommu_map(dev->iommu_domain, iova, pa, size, prot);
	if (ret)
		pr_err("iommu_map(0x%llx -> 0x%llx, %zu) failed: %d\n",
		       iova, (u64)pa, size, ret);
	return ret;
}

static int register_group_locked(struct symrdma_mr *mr, unsigned long idx,
				 phys_addr_t pa, bool resident)
{
	unsigned long k, g = idx >> SYMRDMA_GROUP_SHIFT;

	for (k = 0; k < SYMRDMA_GROUP_PAGES; k++) {
		unsigned long i = idx + k;

		if (resident)
			page_setup_locked(mr, i, SYMRDMA_MAP_REAL,
					  SYMRDMA_MAP_REAL,
					  pa + k * PAGE_SIZE);
		else
			page_setup_locked(mr, i, SYMRDMA_MAP_SENTINEL,
					  SYMRDMA_MAP_BLACKHOLE, 0);
	}
	mr->groups[g].base_pa = resident ? pa : 0;
	mr->groups[g].state = resident ? GRP_RESIDENT : GRP_ABSENT;
	atomic64_inc(resident ? &mr->dev->stats.huge_resident
			      : &mr->dev->stats.huge_absent);
	return 1;
}

/*
 * Try to take a whole 2MB group in one mapping at registration.  Returns
 * >0 when the group was handled (512 pages published), 0 when the caller
 * should fall back to per-page work, <0 on a hard IOMMU failure.
 */
static int map_mr_group(struct symrdma_dev *dev, struct symrdma_mr *mr,
			struct mm_struct *mm, unsigned long idx)
{
	unsigned long k;
	struct page *page = NULL;
	phys_addr_t pa = 0;
	bool resident;
	int probe, ret;

	probe = group_probe(mm, mr->va_start + idx * PAGE_SIZE, &page);
	resident = (probe == GRP_PROBE_HUGE);
	if (resident) {
		pa = symrdma_va_to_pa(page, mr->va_start + idx * PAGE_SIZE);
		if (!IS_ALIGNED(pa, SYMRDMA_GROUP_SIZE))
			resident = false;
	}
	if (probe != GRP_PROBE_ABSENT && !resident) {
		if (page)
			put_page(page);
		return 0;
	}
	if (page) {
		put_page(page);
		page = NULL;
	}

	for (k = 0; k < SYMRDMA_GROUP_PAGES; k++)
		if (mr->pages[idx + k].rmap != SYMRDMA_MAP_UNMAPPED)
			return 0;

	if (resident) {
		if (map_region(dev, mr->read_iova + idx * PAGE_SIZE, pa,
			       SYMRDMA_GROUP_SIZE, IOMMU_READ | IOMMU_WRITE))
			return -EIO;
		if (map_region(dev, mr->write_iova + idx * PAGE_SIZE, pa,
			       SYMRDMA_GROUP_SIZE, IOMMU_READ | IOMMU_WRITE)) {
			iommu_unmap(dev->iommu_domain,
				    mr->read_iova + idx * PAGE_SIZE,
				    SYMRDMA_GROUP_SIZE);
			return -EIO;
		}
	} else {
		if (map_region(dev, mr->read_iova + idx * PAGE_SIZE,
			       dev->sentinel_region_pa, SYMRDMA_GROUP_SIZE,
			       IOMMU_READ))
			return -EIO;
		if (map_region(dev, mr->write_iova + idx * PAGE_SIZE,
			       dev->blackhole_region_pa, SYMRDMA_GROUP_SIZE,
			       IOMMU_WRITE)) {
			iommu_unmap(dev->iommu_domain,
				    mr->read_iova + idx * PAGE_SIZE,
				    SYMRDMA_GROUP_SIZE);
			return -EIO;
		}
	}

	spin_lock(&mr->mm_state->lock);
	ret = register_group_locked(mr, idx, pa, resident);
	spin_unlock(&mr->mm_state->lock);
	return ret;
}

int symrdma_mr_map_pages(struct symrdma_dev *dev, struct symrdma_mr *mr,
			 struct mm_struct *mm)
{
	struct symrdma_mm_state *st = mr->mm_state;
	unsigned long va, end;
	bool group_mode = mr->groups &&
			  IS_ALIGNED(mr->read_iova, SYMRDMA_GROUP_SIZE);
	int ret;

	if (!st)
		return -ENOENT;

	va = mr->va_start;
	end = mr->va_end;

	for (; va < end; va += PAGE_SIZE) {
		unsigned long idx = (va - mr->va_start) / PAGE_SIZE;
		struct symrdma_obs obs;
		enum symrdma_backing bk;
		u8 reason;
		u8 rmap, wmap;
		int try;

		if (group_mode &&
		    (idx & (SYMRDMA_GROUP_PAGES - 1)) == 0 &&
		    idx + SYMRDMA_GROUP_PAGES <= mr->npages) {
			ret = map_mr_group(dev, mr, mm, idx);
			if (ret < 0)
				return ret;
			if (ret > 0) {
				va += SYMRDMA_GROUP_SIZE - PAGE_SIZE;
				continue;
			}
		}

		/*
		 * Registration never faults a page in: it maps what is there.
		 * A probe that raced a transition is retried a bounded number
		 * of times and then published fail-closed.
		 */
		for (try = 0; ; try++) {
			ret = symrdma_backing_probe(mr, idx, SPB_HINT, &obs,
						    &bk, &reason);
			if (ret != -EAGAIN || try >= 2)
				break;
		}
		if (ret == -EAGAIN)
			bk = SBK_ABSENT;
		else if (ret)
			return ret;

		if (bk == SBK_REAL || bk == SBK_REALIGN) {
			rmap = SYMRDMA_MAP_REAL;
			wmap = SYMRDMA_MAP_REAL;
		} else {
			obs.pa = 0;
			rmap = SYMRDMA_MAP_SENTINEL;
			wmap = SYMRDMA_MAP_BLACKHOLE;
		}

		if (map_region(dev, mr->read_iova + idx * PAGE_SIZE,
			       rmap == SYMRDMA_MAP_REAL ? obs.pa
							: dev->sentinel_pa,
			       PAGE_SIZE,
			       rmap == SYMRDMA_MAP_REAL
					? (IOMMU_READ | IOMMU_WRITE)
					: IOMMU_READ))
			return -EIO;
		if (map_region(dev, mr->write_iova + idx * PAGE_SIZE,
			       wmap == SYMRDMA_MAP_REAL ? obs.pa
							: dev->blackhole_pa,
			       PAGE_SIZE,
			       wmap == SYMRDMA_MAP_REAL
					? (IOMMU_READ | IOMMU_WRITE)
					: IOMMU_WRITE)) {
			iommu_unmap(dev->iommu_domain,
				    mr->read_iova + idx * PAGE_SIZE,
				    PAGE_SIZE);
			return -EIO;
		}

		spin_lock(&st->lock);
		page_setup_locked(mr, idx, rmap, wmap, obs.pa);
		spin_unlock(&st->lock);
	}

	pr_debug("registration mapping done: %lu pages\n", mr->npages);
	return 0;
}

/*
 * Forced state change: the shape only a test needs.
 *
 * This is the body of the test face's forcing verb, and it is the only door
 * into the authority that is not a production path.  It resolves the MR by id
 * and checks that the caller owns its mm, so a test module's ioctl cannot
 * reach another process's pages.  Each target is one authority verb; asking
 * for REAL on a page that was never published falls back to a repair (the
 * page is not there to promote), exactly as the retired remap ioctl did.
 */
int symrdma_page_force_state(struct symrdma_dev *dev, int mr_id,
			     unsigned long page_idx, int target)
{
	struct symrdma_mr *mr;
	struct symrdma_mm_state *st;
	int ret = 0;

	mr = symrdma_find_mr(dev, mr_id);
	if (!mr)
		return -ENOENT;

	if (page_idx >= mr->npages) {
		ret = -EINVAL;
		goto out_put_mr;
	}
	if (mr->mm != current->mm) {
		ret = -EPERM;
		goto out_put_mr;
	}
	if (target < SYMRDMA_TGT_REAL || target > SYMRDMA_TGT_BLACKHOLE) {
		ret = -EINVAL;
		goto out_put_mr;
	}

	st = symrdma_mm_state_get(mr);
	if (!st) {
		ret = -ENOENT;
		goto out_put_mr;
	}

	if (target == SYMRDMA_TGT_REAL && mr->pages[page_idx].pa == 0) {
		ret = symrdma_repair_page(dev, mr, page_idx);
		goto out_put_st;
	}

	spin_lock(&st->lock);
	if (mr->mm_state != st) {
		spin_unlock(&st->lock);
		ret = -ENOENT;
		goto out_put_st;
	}

	switch (target) {
	case SYMRDMA_TGT_SENTINEL:
		/* one domain only: the write target stays */
		ret = symrdma_page_demote_locked(mr, page_idx,
						 SYMRDMA_MAP_SENTINEL,
						 mr->pages[page_idx].wmap,
						 SYMRDMA_TRANS_FORCED);
		break;
	case SYMRDMA_TGT_BLACKHOLE:
		ret = symrdma_page_demote_locked(mr, page_idx,
						 mr->pages[page_idx].rmap,
						 SYMRDMA_MAP_BLACKHOLE,
						 SYMRDMA_TRANS_FORCED);
		break;
	default: {
		struct symrdma_obs obs = {
			.gen = mr->pages[page_idx].gen,
			.pa  = mr->pages[page_idx].pa,
		};

		ret = symrdma_page_promote_locked(mr, page_idx, &obs,
						  SYMRDMA_TRANS_FORCED);
		break;
	}
	}

	spin_unlock(&st->lock);

out_put_st:
	symrdma_mm_state_put(st);
out_put_mr:
	kref_put(&mr->ref, symrdma_mr_release);
	return ret;
}
