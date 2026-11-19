/* SPDX-License-Identifier: GPL-2.0 */

/*
 * IOMMU domain plumbing and the repair policy.
 *
 * The page state itself does not live here: this file only chooses what to
 * transition and hands the choice to symrdma_page.c (the single-authority rule).  It keeps the
 * domain lifecycle, the two special 2MB regions, the forensics ring, the
 * repair budget and the read-side helper.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"
#include <asm/pgtable.h>
#include <linux/scatterlist.h>
#include <linux/bitmap.h>
#include <linux/ktime.h>

#define SYMRDMA_REPAIR_SYNC_TARGET_US 100

static struct iommu_domain *symrdma_get_device_domain(struct device *dev);
static bool symrdma_assert_busy;

static struct iommu_domain *symrdma_get_device_domain(struct device *dev)
{
	struct iommu_domain *domain;
	struct iommu_group *group;

	group = iommu_group_get(dev);
	if (!group) {
		pr_err("Device %s not in any IOMMU group\n",
		       dev_name(dev));
		return ERR_PTR(-ENODEV);
	}

	domain = iommu_get_domain_for_dev(dev);

	iommu_group_put(group);

	if (!domain) {
		pr_err("Device %s has no IOMMU domain\n", dev_name(dev));
		pr_err("ensure intel_iommu=on or iommu=on is set\n");
		return ERR_PTR(-ENODEV);
	}

	return domain;
}

int symrdma_iommu_init(struct symrdma_dev *dev, int mode)
{
	struct iommu_domain *domain;

	dev->domain_mode = mode;

	if (mode == SYMRDMA_DOMAIN_VERIFY) {
		domain = iommu_domain_alloc(&pci_bus_type);
		if (!domain) {
			pr_err("iommu_domain_alloc failed\n");
			pr_err("ensure IOMMU is enabled (intel_iommu=on)\n");
			return -ENODEV;
		}
		dev->iommu_domain = domain;
		dev->dev = NULL;

		pr_info("VERIFY mode — own IOMMU domain %p\n", domain);
	} else {
		if (!dev->dev) {
			pr_err("NIC mode requires dev->dev set first\n");
			return -ENODEV;
		}
		domain = symrdma_get_device_domain(dev->dev);
		if (IS_ERR(domain))
			return PTR_ERR(domain);

		dev->iommu_domain = domain;
		pr_info("NIC mode — using existing domain %p\n", domain);
	}

	dev->iommu_pgsize = domain->pgsize_bitmap
		? (1UL << __ffs(domain->pgsize_bitmap))
		: PAGE_SIZE;

	pr_info("IOMMU domain=%p pgsize=%lu\n",
		domain, dev->iommu_pgsize);

	return 0;
}

void symrdma_iommu_cleanup(struct symrdma_dev *dev)
{
	if (dev->domain_mode == SYMRDMA_DOMAIN_VERIFY && dev->iommu_domain) {
		iommu_domain_free(dev->iommu_domain);
		pr_info("VERIFY domain released\n");
	}
	dev->iommu_domain = NULL;
}

static DEFINE_STATIC_KEY_FALSE(symrdma_state_assert_key);

bool symrdma_state_assert_on(void)
{
	return static_key_enabled(&symrdma_state_assert_key);
}

void symrdma_state_assert_set(bool on)
{
	if (on)
		static_branch_enable(&symrdma_state_assert_key);
	else
		static_branch_disable(&symrdma_state_assert_key);
}

/*
 * Debug-only consistency check: the model (pages[]) against the translations
 * the IOMMU actually holds.  A divergence is parked through the authority
 * (never by writing pages[] here), which is why the recursion guard exists.
 */
void symrdma_state_assert(struct symrdma_mr *mr, unsigned long idx)
{
	struct symrdma_dev *dev = mr->dev;
	u64 riova = mr->read_iova + idx * PAGE_SIZE;
	u64 wiova = mr->write_iova + idx * PAGE_SIZE;
	phys_addr_t rpa, wpa, exp_r = 0, exp_w = 0;
	struct symrdma_page *pe;
	bool bad = false, grouped = false;
	u32 gen;

	if (!static_branch_unlikely(&symrdma_state_assert_key))
		return;
	if (!dev->iommu_domain || !mr->pages || idx >= mr->npages)
		return;
	if (symrdma_assert_busy)
		return;

	pe = &mr->pages[idx];
	rpa = iommu_iova_to_phys(dev->iommu_domain, riova);
	wpa = iommu_iova_to_phys(dev->iommu_domain, wiova);

	if (mr->groups) {
		unsigned long g = idx >> SYMRDMA_GROUP_SHIFT;
		u8 gstate = mr->groups[g].state;

		if (gstate != GRP_NONE) {
			if (symrdma_group_verify_locked(mr, g))
				return;
			grouped = true;
			if (gstate == GRP_RESIDENT) {
				exp_r = mr->groups[g].base_pa +
					(idx & (SYMRDMA_GROUP_PAGES - 1)) *
						PAGE_SIZE;
				exp_w = exp_r;
			} else {
				exp_r = dev->sentinel_region_pa;
				exp_w = dev->blackhole_region_pa;
			}
		}
	}

	if (!grouped) {
		switch (pe->rmap) {
		case SYMRDMA_MAP_REAL:
			exp_r = pe->pa;
			break;
		case SYMRDMA_MAP_SENTINEL:
			exp_r = dev->sentinel_pa;
			break;
		default:
			bad = true;
			break;
		}
		switch (pe->wmap) {
		case SYMRDMA_MAP_REAL:
			exp_w = pe->pa;
			break;
		case SYMRDMA_MAP_BLACKHOLE:
			exp_w = dev->blackhole_pa;
			break;
		default:
			bad = true;
			break;
		}
	}

	gen = symrdma_version_read(mr, idx);
	if (rpa != exp_r || wpa != exp_w)
		bad = true;
	if (((pe->rmap == SYMRDMA_MAP_REAL) != 0) != ((gen & 1) != 0))
		bad = true;
	if (!bad)
		return;

	atomic64_inc(&dev->stats.state_divergence);
	pr_err_ratelimited("state_assert mismatch: mr=%d idx=%lu model r=%d w=%d gen=%u actual rpa=0x%llx wpa=0x%llx\n",
			   mr->mr_id, idx, (int)pe->rmap, (int)pe->wmap, gen,
			   (u64)rpa, (u64)wpa);

	symrdma_assert_busy = true;
	if (symrdma_page_demote_locked(mr, idx, SYMRDMA_MAP_SENTINEL,
				       SYMRDMA_MAP_BLACKHOLE,
				       SYMRDMA_TRANS_PARK))
		pr_err_ratelimited("state_assert park failed: mr=%d idx=%lu\n",
				   mr->mr_id, idx);
	symrdma_assert_busy = false;
}

void symrdma_trans_record(struct symrdma_mr *mr, unsigned long idx, u8 cause)
{
	struct symrdma_dev *dev = mr->dev;
	struct symrdma_trans_event *ev;
	unsigned long flags;

	if (!dev || !mr->pages || idx >= mr->npages)
		return;
	spin_lock_irqsave(&dev->trans_lock, flags);
	ev = &dev->trans_ring[dev->trans_head];
	dev->trans_head = (dev->trans_head + 1) &
			  (SYMRDMA_TRANS_RING_SIZE - 1);
	ev->jiffies = jiffies;
	ev->mr_id = mr->mr_id;
	ev->page_idx = (u32)idx;
	ev->cause_seq = mr->pages[idx].cause_seq;
	ev->gen = mr->pages[idx].gen;
	ev->cause = cause;
	ev->rmap = mr->pages[idx].rmap;
	ev->wmap = mr->pages[idx].wmap;
	spin_unlock_irqrestore(&dev->trans_lock, flags);
}

int symrdma_iommu_map_page(struct symrdma_dev *dev, unsigned long iova,
			   phys_addr_t pa, int prot)
{
	int ret;

	if (!dev->iommu_domain) {
		pr_err("no IOMMU domain\n");
		return -ENODEV;
	}

	ret = iommu_map(dev->iommu_domain, iova, pa, PAGE_SIZE, prot);
	if (ret) {
		pr_err("iommu_map(0x%lx -> 0x%llx) failed: %d\n",
		       iova, (u64)pa, ret);
	}
	return ret;
}

void symrdma_iommu_unmap_page(struct symrdma_dev *dev, unsigned long iova)
{
	if (!dev->iommu_domain)
		return;

	iommu_unmap(dev->iommu_domain, iova, PAGE_SIZE);
}

/* Teardown: drop the mapping a group claims, or the two per-page slots. */
static void unmap_page_slots(struct symrdma_dev *dev, struct symrdma_mr *mr,
			     unsigned long i)
{
	struct symrdma_page *pe = &mr->pages[i];

	if (pe->rmap != SYMRDMA_MAP_UNMAPPED)
		symrdma_iommu_unmap_page(dev, mr->read_iova + i * PAGE_SIZE);
	if (pe->wmap != SYMRDMA_MAP_UNMAPPED)
		symrdma_iommu_unmap_page(dev, mr->write_iova + i * PAGE_SIZE);
}

void symrdma_unmap_mr_pages(struct symrdma_dev *dev, struct symrdma_mr *mr,
			    unsigned long npages)
{
	unsigned long i = 0;

	while (i < npages) {
		unsigned long grp = i >> SYMRDMA_GROUP_SHIFT;

		if (mr->groups &&
		    (grp + 1) * SYMRDMA_GROUP_PAGES <= npages &&
		    mr->groups[grp].state != GRP_NONE) {
			iommu_unmap(dev->iommu_domain,
				    mr->read_iova + grp * SYMRDMA_GROUP_SIZE,
				    SYMRDMA_GROUP_SIZE);
			iommu_unmap(dev->iommu_domain,
				    mr->write_iova + grp * SYMRDMA_GROUP_SIZE,
				    SYMRDMA_GROUP_SIZE);
			i += SYMRDMA_GROUP_PAGES;
			continue;
		}
		unmap_page_slots(dev, mr, i);
		i++;
	}
}

void symrdma_unmap_mr_pages_touched(struct symrdma_dev *dev,
				    struct symrdma_mr *mr)
{
	unsigned long i = 0;

	while (i < mr->npages) {
		unsigned long grp = i >> SYMRDMA_GROUP_SHIFT;

		if (mr->groups &&
		    (grp + 1) * SYMRDMA_GROUP_PAGES <= mr->npages &&
		    mr->groups[grp].state != GRP_NONE) {
			iommu_unmap(dev->iommu_domain,
				    mr->read_iova + grp * SYMRDMA_GROUP_SIZE,
				    SYMRDMA_GROUP_SIZE);
			iommu_unmap(dev->iommu_domain,
				    mr->write_iova + grp * SYMRDMA_GROUP_SIZE,
				    SYMRDMA_GROUP_SIZE);
			i += SYMRDMA_GROUP_PAGES;
			continue;
		}
		unmap_page_slots(dev, mr, i);
		i++;
	}
}

int symrdma_iommu_read_iova(struct symrdma_dev *dev, struct symrdma_mr *mr,
			    u64 iova, size_t offset, u32 *out)
{
	phys_addr_t pa;
	void *vaddr;
	struct page *page;
	struct symrdma_mm_state *st;
	unsigned long pg;
	bool promoted = false;

	if (!dev->iommu_domain)
		return -ENODEV;

	if (offset > PAGE_SIZE - sizeof(u32))
		return -EINVAL;

	st = symrdma_mm_state_get(mr);
	if (st) {
		u64 r_end = mr->read_iova + (u64)mr->npages * PAGE_SIZE;
		u64 w_end = mr->write_iova + (u64)mr->npages * PAGE_SIZE;

		spin_lock(&st->lock);
		if (mr->mm_state == st && mr->groups) {
			if (iova >= mr->read_iova && iova < r_end)
				pg = (iova - mr->read_iova) >> PAGE_SHIFT;
			else if (iova >= mr->write_iova && iova < w_end)
				pg = (iova - mr->write_iova) >> PAGE_SHIFT;
			else
				pg = mr->npages;
			if (pg < mr->npages) {
				unsigned long g = pg >> SYMRDMA_GROUP_SHIFT;

				/*
				 * The group overlay is only a cache: 5.11's
				 * iova_to_phys reports the 2MB base, so the
				 * base+offset arithmetic is only trusted when
				 * the 512 entries behind it agree.
				 */
				if (mr->groups[g].state != GRP_NONE &&
				    !symrdma_group_verify_locked(mr, g) &&
				    mr->groups[g].state == GRP_RESIDENT) {
					pa = mr->groups[g].base_pa +
					     (iova & (SYMRDMA_GROUP_SIZE - 1));
					promoted = true;
				}
			}
		}
		spin_unlock(&st->lock);
		symrdma_mm_state_put(st);
	}
	if (!promoted) {
		pa = iommu_iova_to_phys(dev->iommu_domain, iova);
		if (!pa) {
			pr_debug("READ_IOVA 0x%llx → no mapping\n", iova);
			return -EFAULT;
		}
	}

	if (pfn_valid(PHYS_PFN(pa))) {
		page = pfn_to_page(PHYS_PFN(pa));
		vaddr = kmap_atomic(page);
		*out = *(u32 *)(vaddr + offset);
		kunmap_atomic(vaddr);
	} else {
		vaddr = phys_to_virt(pa);
		*out = *(u32 *)(vaddr + offset);
	}

	return 0;
}

int symrdma_repair_page(struct symrdma_dev *dev, struct symrdma_mr *mr,
			unsigned long page_idx)
{
	unsigned long va;
	struct symrdma_mm_state *st;
	struct page *page = NULL;
	struct symrdma_obs obs;
	int ret;

	if (page_idx >= mr->npages)
		return -EINVAL;
	if (!mr->mm) {
		pr_err("repair page[%lu] failed: mr->mm is NULL\n", page_idx);
		return -EINVAL;
	}

	va = mr->va_start + page_idx * PAGE_SIZE;
	pr_debug("repair page[%lu] VA=0x%lx\n", page_idx, va);

	ret = symrdma_gup_for_pin(va, 1, &page);
	if (ret) {
		atomic64_inc(&dev->stats.repair_fail);
		atomic64_inc(&dev->stats.gup_pin_fail);
		pr_debug("repair page[%lu] failed: gup=%d\n", page_idx, ret);
		return -EAGAIN;
	}
	obs.pa = symrdma_va_to_pa(page, va);
	/*
	 * The gen is read after the GUP, not before: a FOLL_WRITE GUP can break
	 * COW, and that invalidation demotes the page.  Taking the gen first
	 * would make every such repair observe a dead generation and refuse,
	 * which is a livelock, not a race detection.
	 */
	obs.gen = symrdma_page_gen(mr, page_idx);

	st = symrdma_mm_state_get(mr);
	if (!st) {
		put_page(page);
		pr_debug("repair page[%lu] rejected: MR already torn down\n",
			 page_idx);
		return -ENOENT;
	}
	spin_lock(&st->lock);
	if (mr->mm_state != st) {
		spin_unlock(&st->lock);
		symrdma_mm_state_put(st);
		put_page(page);
		pr_debug("repair page[%lu] rejected: concurrent teardown\n",
			 page_idx);
		return -ENOENT;
	}

	ret = symrdma_page_promote_locked(mr, page_idx, &obs,
					  SYMRDMA_TRANS_REPAIR);
	spin_unlock(&st->lock);
	symrdma_mm_state_put(st);
	put_page(page);

	if (ret) {
		atomic64_inc(&dev->stats.repair_fail);
		pr_debug("repair page[%lu] not promoted: %d\n", page_idx, ret);
		return ret == -EBUSY ? -EBUSY : -EAGAIN;
	}

	atomic64_inc(&dev->stats.repair_ok);
	pr_debug("repair page[%lu]: VA 0x%lx → PA 0x%llx\n",
		 page_idx, va, (u64)obs.pa);
	return 0;
}

int symrdma_repair_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
			 unsigned long page_idx, unsigned long npages,
			 struct symrdma_repair_outcome *out)
{
	unsigned long va, i, n, done, remapped, mapped;
	struct symrdma_mm_state *st;
	struct page **pages;
	struct symrdma_obs *obs;
	struct scatterlist *sg;
	u64 budget_start;
	int ret = 0;

	bool group_mode = mr->groups &&
			  IS_ALIGNED(mr->read_iova, SYMRDMA_GROUP_SIZE);

	memset(out, 0, sizeof(*out));
	out->cause = SYMRDMA_TRANS_REPAIR;
	if (page_idx >= mr->npages || npages == 0)
		return -EINVAL;
	n = min3(npages, (unsigned long)SYMRDMA_REPAIR_RANGE_MAX,
		 mr->npages - page_idx);

	va = mr->va_start + page_idx * PAGE_SIZE;

	pages = kvcalloc(n, sizeof(*pages), GFP_KERNEL);
	obs = kvcalloc(n, sizeof(*obs), GFP_KERNEL);
	if (!pages || !obs) {
		kvfree(pages);
		kvfree(obs);
		return -ENOMEM;
	}

	done = symrdma_gup_for_repair(va, n, pages);
	if (done == 0) {
		atomic64_inc(&dev->stats.repair_fail);
		atomic64_inc(&dev->stats.gup_repair_short);
		pr_debug("range repair failed [%lu,+%lu): gup=0\n",
			 page_idx, n);
		kvfree(pages);
		kvfree(obs);
		return -EAGAIN;
	}
	if (done < n)
		atomic64_inc(&dev->stats.gup_repair_short);
	for (i = 0; i < done; i++) {
		obs[i].pa = symrdma_va_to_pa(pages[i], va + i * PAGE_SIZE);
		/* after the GUP: breaking COW demotes the page (see repair_page) */
		obs[i].gen = symrdma_page_gen(mr, page_idx + i);
	}

	st = symrdma_mm_state_get(mr);
	if (!st) {
		ret = -ENOENT;
		goto out_pages;
	}
	sg = kvcalloc(SYMRDMA_REPAIR_SEG, sizeof(*sg), GFP_KERNEL);
	if (!sg) {
		symrdma_mm_state_put(st);
		ret = -ENOMEM;
		goto out_pages;
	}
	sg_init_table(sg, SYMRDMA_REPAIR_SEG);

	remapped = 0;
	budget_start = ktime_get_ns();
	for (i = 0; i < done && !ret; ) {
		unsigned long c;
		bool promote = false;

		if (group_mode &&
		    !((page_idx + i) & (SYMRDMA_GROUP_PAGES - 1)) &&
		    i + SYMRDMA_GROUP_PAGES <= done &&
		    page_idx + i + SYMRDMA_GROUP_PAGES <= mr->npages)
			promote = true;

		if (promote) {
			unsigned long g = (page_idx + i) >>
					  SYMRDMA_GROUP_SHIFT;
			unsigned long k;

			/* only a contiguous, aligned run may take a 2MB mapping */
			for (k = 1; k < SYMRDMA_GROUP_PAGES; k++)
				if (obs[i + k].pa !=
				    obs[i].pa + k * PAGE_SIZE)
					promote = false;
			if (promote &&
			    !IS_ALIGNED(obs[i].pa, SYMRDMA_GROUP_SIZE))
				promote = false;
			if (!promote)
				goto per_page;

			spin_lock(&st->lock);
			if (mr->mm_state != st) {
				spin_unlock(&st->lock);
				ret = -ENOENT;
				break;
			}
			ret = symrdma_group_collapse_2m_locked(mr, g,
							       obs[i].pa);
			spin_unlock(&st->lock);
			if (!ret) {
				remapped += SYMRDMA_GROUP_PAGES;
				i += SYMRDMA_GROUP_PAGES;
				cond_resched();
				continue;
			}
			/* the group refused: fall back to per-page chunks */
			ret = 0;
		}
per_page:
		c = min(done - i, (unsigned long)SYMRDMA_BATCH_MAX);
		if (dev->repair_sg)
			c = min(c, dev->repair_chunk);
		if (!promote)
			c = min(c, (unsigned long)SYMRDMA_BATCH_MAX);

		spin_lock(&st->lock);
		if (mr->mm_state != st) {
			spin_unlock(&st->lock);
			ret = -ENOENT;
			break;
		}
		ret = symrdma_pages_promote_locked(mr, page_idx + i, c,
						   &obs[i],
						   SYMRDMA_TRANS_REPAIR,
						   dev->repair_sg ? sg : NULL,
						   &mapped);
		spin_unlock(&st->lock);
		if (ret && ret != -EAGAIN)
			break;
		if (ret == -EAGAIN)
			ret = 0;
		remapped += mapped;
		i += c;

		cond_resched();

		if (!promote && dev->repair_sg) {
			u64 sync_us = atomic64_read(
					&dev->stats.repair_sync_us_last);

			if (sync_us >
			    2 * SYMRDMA_REPAIR_SYNC_TARGET_US)
				dev->repair_chunk = max(
					dev->repair_chunk / 2,
					(unsigned long)
					SYMRDMA_REPAIR_CHUNK_MIN);
			else if (sync_us &&
				 sync_us < SYMRDMA_REPAIR_SYNC_TARGET_US / 2)
				dev->repair_chunk = min(
					dev->repair_chunk * 2,
					(unsigned long)SYMRDMA_REPAIR_SEG);
		}

		if (dev->repair_budget_us > 0 && i < done &&
		    ktime_get_ns() - budget_start >
		    (u64)dev->repair_budget_us * 1000) {
			atomic64_inc(&dev->stats.repair_budget_stop);
			break;
		}
	}
	kvfree(sg);
	symrdma_mm_state_put(st);

out_pages:
	for (i = 0; i < done; i++)
		put_page(pages[i]);
	kvfree(pages);
	kvfree(obs);

	if (ret)
		return ret;

	atomic64_add(remapped, &dev->stats.repair_ok);
	out->repaired = remapped;
	out->gen_before_lo = mr->pages[page_idx].gen;
	if (done)
		out->gen_after_hi = mr->pages[page_idx + done - 1].gen;
	/* the caller compares `repaired` against its own chunk; here the invariant
	 * is "the range this call was able to consider is fully re-mapped" */
	if (remapped < n)
		atomic64_inc(&dev->stats.repair_partial);
	pr_debug("range repair [%lu,+%lu) → %lu pages (GUP %lu, requested %lu)%s\n",
		 page_idx, n, remapped, done, npages,
		 remapped < done ? " [budget stop]" : "");
	return 0;
}
