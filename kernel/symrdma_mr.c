/* SPDX-License-Identifier: GPL-2.0 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"

int symrdma_reg_mr(struct symrdma_dev *dev, struct mm_struct *mm,
		   u64 va_start, u64 len, struct symrdma_mr **out_mr)
{
	struct symrdma_mr *mr;
	unsigned long npages;
	int ret;

	if (!dev->iommu_domain)
		return -ENODEV;

	if (!mm)
		return -EINVAL;

	len = round_up(len, PAGE_SIZE);

	if (len > SYMRDMA_MR_WRITE_OFFSET)
		return -EINVAL;
	if (va_start & (PAGE_SIZE - 1))
		return -EINVAL;
	npages = len / PAGE_SIZE;
	if (npages == 0)
		return -EINVAL;

	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr)
		return -ENOMEM;

	kref_init(&mr->ref);

	mr->pages = kvcalloc(npages, sizeof(struct symrdma_page), GFP_KERNEL);
	if (!mr->pages) {
		ret = -ENOMEM;
		goto err_free_mr;
	}

	if (dev->huge_ok) {
		mr->groups = kvcalloc(DIV_ROUND_UP(npages,
						   SYMRDMA_GROUP_PAGES),
				      sizeof(struct symrdma_group_entry),
				      GFP_KERNEL);
		if (!mr->groups)
			pr_warn("MR group table alloc failed (npages=%lu), group mechanism off\n",
				npages);
	}

	mr->dev      = dev;
	mr->va_start = va_start;
	mr->va_end   = va_start + len;
	mr->npages   = npages;
	mr->mm       = mm;
	mr->mr_id    = -1;

	INIT_LIST_HEAD(&mr->pin_list);

	mr->read_iova         = va_start;
	mr->write_iova_offset = SYMRDMA_MR_WRITE_OFFSET;
	mr->write_iova        = va_start + SYMRDMA_MR_WRITE_OFFSET;

	ret = symrdma_version_alloc(mr);
	if (ret)
		goto err_free_pages;

	ret = symrdma_mn_attach(mr);
	if (ret)
		goto err_free_version;

	mmap_write_lock(mm);
	ret = symrdma_mr_map_pages(dev, mr, mm);
	mmap_write_unlock(mm);
	if (ret)
		goto err_detach;

	spin_lock(&dev->mr_lock);
	list_add_tail(&mr->list, &dev->mr_list);
	dev->mr_count++;
	spin_unlock(&dev->mr_lock);

	*out_mr = mr;

	pr_debug("MR registered VA=0x%llx len=%lu npages=%lu\n",
		va_start, (unsigned long)len, npages);
	pr_debug("  Read  IOVA: 0x%llx → 0x%llx\n",
		mr->read_iova, mr->read_iova + len);
	pr_debug("  Write IOVA: 0x%llx → 0x%llx\n",
		mr->write_iova, mr->write_iova + len);

	return 0;

err_detach:

	symrdma_mn_detach(mr);
	symrdma_unmap_mr_pages_touched(dev, mr);
err_free_version:
	symrdma_version_free(mr);
err_free_pages:
	kvfree(mr->pages);
	kvfree(mr->groups);
err_free_mr:
	kfree(mr);
	return ret;
}

void symrdma_mr_release(struct kref *ref)
{
	struct symrdma_mr *mr = container_of(ref, struct symrdma_mr, ref);

	symrdma_version_free(mr);
	kvfree(mr->pages);
	kvfree(mr->groups);
	kfree(mr);
}

bool symrdma_mr_teardown_begin(struct symrdma_dev *dev, struct symrdma_mr *mr)
{
	bool owner = false;

	spin_lock(&dev->mr_lock);
	if (!mr->torn_down) {
		mr->torn_down = true;
		list_del(&mr->list);
		dev->mr_count--;
		owner = true;
	}
	spin_unlock(&dev->mr_lock);
	return owner;
}

void symrdma_dereg_mr(struct symrdma_dev *dev, struct symrdma_mr *mr)
{

	if (!mr)
		return;

	if (!symrdma_mr_teardown_begin(dev, mr))
		return;

	symrdma_pin_release_all(mr);

	symrdma_mn_detach(mr);

	symrdma_unmap_mr_pages(dev, mr, mr->npages);

	kref_put(&mr->ref, symrdma_mr_release);

	pr_debug("MR unregistered\n");
}
