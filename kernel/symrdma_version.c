/* SPDX-License-Identifier: GPL-2.0 */

/*
 * Version table = the DMA-visible mirror of pages[].gen (the generation-token rule).
 *
 * This file owns the storage only: allocation, the two carriers (a kernel
 * table and a user page the NIC writes) and slot access.  Writing a version
 * is reserved for the state authority in symrdma_page.c; nothing here decides
 * when a value changes.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"
#include <linux/highmem.h>

static u32 *symrdma_version_slot(struct symrdma_mr *mr, unsigned long idx)
{
	unsigned long pg = idx / SYMRDMA_VERS_PER_PAGE;
	unsigned long off = (idx % SYMRDMA_VERS_PER_PAGE) * sizeof(u32);

	if (mr->version_pages) {
		void *kaddr;

		if (pg >= mr->version_vt_pages || idx >= mr->version_npages)
			return NULL;
		kaddr = kmap_atomic(mr->version_pages[pg]);
		return (u32 *)((char *)kaddr + off);
	}
	if (!mr->version_table || idx >= mr->npages)
		return NULL;
	return &mr->version_table[idx];
}

u32 symrdma_version_read(struct symrdma_mr *mr, unsigned long page_idx)
{
	u32 *slot = symrdma_version_slot(mr, page_idx);
	u32 val;

	BUILD_BUG_ON(PAGE_SIZE / sizeof(u32) != SYMRDMA_VERS_PER_PAGE);

	if (!slot)
		return 0;
	val = READ_ONCE(*slot);
	if (mr->version_pages)
		kunmap_atomic(slot - (page_idx % SYMRDMA_VERS_PER_PAGE));
	return val;
}

/* A publisher must know beforehand whether the mirror can be written. */
int symrdma_version_slot_ok(struct symrdma_mr *mr, unsigned long page_idx)
{
	u32 *slot = symrdma_version_slot(mr, page_idx);
	int ret = slot ? 0 : -EIO;

	if (slot && mr->version_pages)
		kunmap_atomic(slot - (page_idx % SYMRDMA_VERS_PER_PAGE));
	return ret;
}

int symrdma_version_write(struct symrdma_mr *mr, unsigned long page_idx, u32 val)
{
	u32 *slot = symrdma_version_slot(mr, page_idx);

	if (!slot)
		return -EIO;
	WRITE_ONCE(*slot, val);
	if (mr->version_pages)
		kunmap_atomic(slot - (page_idx % SYMRDMA_VERS_PER_PAGE));
	return 0;
}

int symrdma_version_alloc(struct symrdma_mr *mr)
{
	unsigned long size = mr->npages * sizeof(u32);

	mr->version_table = kvzalloc(size, GFP_KERNEL);
	if (!mr->version_table)
		return -ENOMEM;
	return 0;
}

void symrdma_version_free(struct symrdma_mr *mr)
{
	if (mr->version_pages) {
		unsigned long i;

		for (i = 0; i < mr->version_vt_pages; i++)
			put_page(mr->version_pages[i]);
		kfree(mr->version_pages);
		mr->version_pages = NULL;
		mr->version_npages = 0;
		mr->version_vt_pages = 0;
	}
	kvfree(mr->version_table);
	mr->version_table = NULL;
}

/*
 * Rebind the DMA-visible version table onto a user page.  The current values
 * move across (a rebind is not a transition, and it must never reset a
 * generation: a reader comparing before/after would lose the change), and
 * every probe_gen is cleared so the hint layer re-observes.
 */
int symrdma_version_bind_user_page(struct symrdma_dev *dev,
				   struct symrdma_mr *mr,
				   unsigned long version_va,
				   unsigned long version_len)
{
	struct mm_struct *mm = current->mm;
	struct symrdma_mm_state *st;
	struct page **pages;
	unsigned long vt_pages, i, nvalid = 0, va, idx;
	int ret = 0;

	if (mr->version_pages)
		return -EINVAL;
	if (version_va == 0 || !mm)
		return -EINVAL;

	vt_pages = version_len ?
		version_len :
		DIV_ROUND_UP(mr->npages, SYMRDMA_VERS_PER_PAGE);

	pages = kcalloc(vt_pages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	for (i = 0; i < vt_pages; i++) {
		void *kaddr;

		va = version_va + i * PAGE_SIZE;
		ret = symrdma_gup_for_pin(va, 1, &pages[i]);
		if (ret)
			goto err_put;
		nvalid = i + 1;
		if (PageCompound(pages[i])) {
			put_page(pages[i]);
			nvalid = i;
			ret = -EFAULT;
			goto err_put;
		}
		kaddr = kmap_atomic(pages[i]);
		memset(kaddr, 0, PAGE_SIZE);
		kunmap_atomic(kaddr);
	}

	st = symrdma_mm_state_get(mr);
	if (!st) {
		ret = -ENOENT;
		goto err_put;
	}
	spin_lock(&st->lock);

	if (mr->mm_state != st) {
		spin_unlock(&st->lock);
		symrdma_mm_state_put(st);
		ret = -ENOENT;
		goto err_put;
	}
	kvfree(mr->version_table);
	mr->version_table = NULL;
	mr->version_pages = pages;
	mr->version_vt_pages = vt_pages;
	mr->version_npages = mr->npages;

	/* move the current generations across, one table page per kmap */
	for (i = 0; i < vt_pages; i++) {
		u32 *kaddr = kmap_atomic(pages[i]);
		unsigned long off;

		for (off = 0; off < SYMRDMA_VERS_PER_PAGE; off++) {
			idx = i * SYMRDMA_VERS_PER_PAGE + off;
			if (idx >= mr->npages)
				break;
			kaddr[off] = mr->pages[idx].gen;
			mr->pages[idx].probe_gen = 0;
		}
		kunmap_atomic(kaddr);
	}
	spin_unlock(&st->lock);
	symrdma_mm_state_put(st);

	pr_debug("MR VA=0x%llx bound version table to user page VA=0x%lx (%lu page versions, %lu table pages)\n",
		 mr->va_start, version_va, mr->npages, vt_pages);
	return 0;

err_put:
	while (nvalid-- > 0)
		put_page(pages[nvalid]);
	kfree(pages);
	return ret;
}
