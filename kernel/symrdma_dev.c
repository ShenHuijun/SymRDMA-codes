/* SPDX-License-Identifier: GPL-2.0 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"

/* Shared with the state authority: the test face's forcing verb resolves a
 * request's MR by id (symrdma_page.c calls this through its registered verb). */
struct symrdma_mr *symrdma_find_mr(struct symrdma_dev *dev, int mr_id)
{
	struct symrdma_mr *mr;

	spin_lock(&dev->mr_lock);
	mr = idr_find(&dev->mr_idr, mr_id);
	if (mr && !kref_get_unless_zero(&mr->ref))
		mr = NULL;
	spin_unlock(&dev->mr_lock);

	return mr;
}

static struct symrdma_mr *symrdma_take_mr(struct symrdma_dev *dev, int mr_id)
{
	struct symrdma_mr *mr;

	spin_lock(&dev->mr_lock);

	mr = idr_find(&dev->mr_idr, mr_id);
	if (mr && mr->mm != current->mm) {
		spin_unlock(&dev->mr_lock);
		return ERR_PTR(-EPERM);
	}
	if (mr)
		idr_remove(&dev->mr_idr, mr_id);
	spin_unlock(&dev->mr_lock);

	return mr;
}

static int symrdma_assign_mr_id(struct symrdma_dev *dev, struct symrdma_mr *mr)
{
	int id;

	idr_preload(GFP_KERNEL);
	spin_lock(&dev->mr_lock);
	id = idr_alloc(&dev->mr_idr, mr, dev->mr_id_counter,
		       dev->mr_id_counter + 1, GFP_ATOMIC);
	if (id >= 0)
		dev->mr_id_counter = id + 1;
	spin_unlock(&dev->mr_lock);
	idr_preload_end();

	if (id >= 0)
		mr->mr_id = id;

	return id;
}

static void symrdma_remove_mr_id(struct symrdma_dev *dev, int mr_id)
{
	spin_lock(&dev->mr_lock);
	idr_remove(&dev->mr_idr, mr_id);
	spin_unlock(&dev->mr_lock);
}

static int symrdma_dev_open(struct inode *inode, struct file *filp)
{
	struct symrdma_dev *dev = container_of(filp->private_data,
					       struct symrdma_dev, miscdev);
	struct symrdma_file *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return -ENOMEM;

	/* the census rows a read() hands back; nothing persists across opens */
	f->rows = kvmalloc_array(SYMRDMA_CENSUS_MAX, sizeof(*f->rows),
				 GFP_KERNEL);
	if (!f->rows) {
		kfree(f);
		return -ENOMEM;
	}
	f->dev = dev;
	filp->private_data = f;
	return 0;
}

static int symrdma_dev_release(struct inode *inode, struct file *filp)
{
	struct symrdma_file *f = filp->private_data;

	if (f) {
		kvfree(f->rows);
		kfree(f);
	}
	return 0;
}

/*
 * The census rows of the last SYMRDMA_IOC_CENSUS on this open file, oldest
 * page first.  A read drains them: the rows describe one chunk, and a second
 * read without a new census has nothing to say (-ENODATA), which is a clearer
 * answer than repeating a stale chunk.
 */
static ssize_t symrdma_dev_read(struct file *filp, char __user *ubuf,
				size_t count, loff_t *ppos)
{
	struct symrdma_file *f = filp->private_data;
	size_t n;

	if (!f)
		return -ENODEV;
	if (!f->len)
		return -ENODATA;

	n = min(count, (size_t)f->len);
	if (copy_to_user(ubuf, f->rows, n))
		return -EFAULT;

	if (n < f->len) {
		memmove(f->rows, (u8 *)f->rows + n, f->len - n);
		f->len -= (u32)n;
	} else {
		f->len = 0;
	}
	return (ssize_t)n;
}

static long symrdma_dev_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct symrdma_file *file = filp->private_data;
	struct symrdma_dev *dev = file ? file->dev : NULL;
	struct symrdma_mr *held = NULL;
	struct symrdma_mm_state *held_st = NULL;
	int ret = 0;

	if (!dev)
		return -ENODEV;

	switch (cmd) {

	case SYMRDMA_IOC_REG_MR: {
		struct symrdma_ioc_reg_mr req;
		struct symrdma_mr *mr;
		int mr_id;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		if (req.va_start == 0 || req.len == 0)
			return -EINVAL;
		if (!access_ok((void __user *)(uintptr_t)req.va_start, req.len))
			return -EINVAL;

		ret = symrdma_reg_mr(dev, current->mm, req.va_start,
				     req.len, &mr);
		if (ret)
			return ret;

		mr_id = symrdma_assign_mr_id(dev, mr);
		if (mr_id < 0) {
			symrdma_dereg_mr(dev, mr);
			return mr_id;
		}

		req.mr_id = mr_id;
		if (copy_to_user((void __user *)arg, &req, sizeof(req))) {

			symrdma_remove_mr_id(dev, mr_id);
			symrdma_dereg_mr(dev, mr);
			return -EFAULT;
		}

		pr_debug("REG_MR mr_id=%d VA=0x%llx len=%llu\n",
			mr_id, req.va_start, req.len);
		break;
	}

	case SYMRDMA_IOC_DEREG_MR: {
		int mr_id = (int)arg;
		struct symrdma_mr *mr = symrdma_take_mr(dev, mr_id);

		if (IS_ERR(mr))
			return PTR_ERR(mr);
		if (!mr)
			return -ENOENT;

		symrdma_dereg_mr(dev, mr);

		pr_debug("DEREG_MR mr_id=%d\n", mr_id);
		return 0;

	}

	case SYMRDMA_IOC_GET_IOVA: {
		struct symrdma_ioc_get_iova req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (mr->mm != current->mm) {
			ret = -EPERM;
			goto out_put;
		}
		if (req.page_idx >= mr->npages) {
			ret = -EINVAL;
			goto out_put;
		}

		req.read_iova  = mr->read_iova + req.page_idx * PAGE_SIZE;
		req.write_iova = mr->write_iova + req.page_idx * PAGE_SIZE;

		if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
			ret = -EFAULT;
			goto out_put;
		}
		break;
	}

	case SYMRDMA_IOC_READ_IOVA: {
		struct symrdma_ioc_read_iova req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (mr->mm != current->mm) {
			ret = -EPERM;
			goto out_put;
		}
		if (req.offset > PAGE_SIZE - sizeof(u32)) {
			ret = -EINVAL;
			goto out_put;
		}

		if (!((req.iova >= mr->read_iova &&
		       req.iova < mr->read_iova + mr->npages * PAGE_SIZE) ||
		      (req.iova >= mr->write_iova &&
		       req.iova < mr->write_iova + mr->npages * PAGE_SIZE))) {
			ret = -EINVAL;
			goto out_put;
		}

		ret = symrdma_iommu_read_iova(dev, mr, req.iova,
					      req.offset, &req.value);
		if (ret)
			goto out_put;

		if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
			ret = -EFAULT;
			goto out_put;
		}
		break;
	}

	case SYMRDMA_IOC_REPAIR: {
		struct symrdma_ioc_repair req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		pr_debug("REPAIR ioctl mr_id_in=%d\n",
			(int)req.mr_id);

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr) {
			pr_debug("REPAIR mr_id=%d not found\n",
				(int)req.mr_id);
			return -ENOENT;
		}
		held = mr;
		if (mr->mm != current->mm) {
			pr_debug("REPAIR mr_id=%d denied (not owner)\n",
				(int)req.mr_id);
			ret = -EPERM;
			goto out_put;
		}

		pr_debug("REPAIR calling repair_page mr=%d page=%lu\n",
			(int)req.mr_id, (unsigned long)req.page_idx);
		ret = symrdma_repair_page(dev, mr, req.page_idx);
		if (ret) {
			pr_debug("REPAIR failed ret=%d\n", ret);
			goto out_put;
		}
		pr_debug("REPAIR done\n");
		break;
	}

	case SYMRDMA_IOC_REPAIR_RANGE: {
		struct symrdma_ioc_repair_range req;
		struct symrdma_repair_outcome oc;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (mr->mm != current->mm) {
			pr_debug("REPAIR_RANGE mr_id=%d denied (not owner)\n",
				(int)req.mr_id);
			ret = -EPERM;
			goto out_put;
		}

		ret = symrdma_repair_range(dev, mr, req.page_idx, req.npages,
					   &oc);
		if (ret && oc.repaired == 0) {
			pr_debug("REPAIR_RANGE mr=%d [%lu,+%lu) failed ret=%d\n",
				(int)req.mr_id, (unsigned long)req.page_idx,
				(unsigned long)req.npages, ret);
			goto out_put;
		}
		/* The request fields stay the request; what happened is reported in
		 * its own fields. A partial repair is visible to the caller as
		 * `repaired < npages` and counted in repair_partial — it must never
		 * be inferable only from a reused in/out field. */
		req.cause = oc.cause;
		req.gen_before_lo = oc.gen_before_lo;
		req.gen_after_hi = oc.gen_after_hi;
		req.reserved = 0;
		req.repaired = oc.repaired;
		if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
			ret = -EFAULT;
			goto out_put;
		}
		break;
	}

	case SYMRDMA_IOC_CENSUS: {
		struct symrdma_ioc_census req;
		struct symrdma_mr *mr;
		u32 nrows = 0;
		u64 cookie = 0;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		if (req.abi != SYMRDMA_ABI_VERSION)
			return -EPROTO;
		if (req.npages == 0 || req.npages > SYMRDMA_CENSUS_MAX)
			return -EINVAL;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (mr->mm != current->mm) {
			ret = -EPERM;
			goto out_put;
		}
		if (req.page_idx >= mr->npages ||
		    req.npages > mr->npages - req.page_idx) {
			ret = -EINVAL;
			goto out_put;
		}

		ret = symrdma_census_run(dev, mr, req.page_idx, req.npages,
					 req.mode, file->rows, &nrows, &cookie);
		if (ret)
			goto out_put;

		file->len = nrows * sizeof(*file->rows);
		req.nread = nrows;
		req.cookie = cookie;
		if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
			file->len = 0;
			ret = -EFAULT;
			goto out_put;
		}
		break;
	}

	case SYMRDMA_IOC_STATS: {
		struct symrdma_ioc_stats req;
		unsigned int k = 0;

		memset(&req, 0, sizeof(req));
		req.abi = SYMRDMA_ABI_VERSION;
		req.magic = SYMRDMA_STATS_MAGIC;
#define SYMRDMA_STAT_ROW(e, f) req.v[k++] = atomic64_read(&dev->stats.f);
		SYMRDMA_STAT_TABLE(SYMRDMA_STAT_ROW)
#undef SYMRDMA_STAT_ROW
		req.count = k;
		BUILD_BUG_ON(k > SYMRDMA_STATS_MAX);

		if (copy_to_user((void __user *)arg, &req, sizeof(req)))
			return -EFAULT;
		break;
	}

	case SYMRDMA_IOC_GET_VERSION: {
		struct symrdma_ioc_get_version req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (req.page_idx >= mr->npages) {
			ret = -EINVAL;
			goto out_put;
		}

		{
			struct symrdma_mm_state *st = symrdma_mm_state_get(mr);

			if (st) {
				spin_lock(&st->lock);
				req.version = symrdma_version_read(mr, req.page_idx);
				spin_unlock(&st->lock);
				symrdma_mm_state_put(st);
			} else {
				req.version = symrdma_version_read(mr, req.page_idx);
			}
		}

		if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
			ret = -EFAULT;
			goto out_put;
		}
		break;
	}

	case SYMRDMA_IOC_SET_VERSION_PAGE: {
		struct symrdma_ioc_set_version_page req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		if (!access_ok((void __user *)(uintptr_t)req.version_va,
			       req.version_len ? req.version_len * PAGE_SIZE
					       : PAGE_SIZE))
			return -EINVAL;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (mr->mm != current->mm) {
			ret = -EPERM;
			goto out_put;
		}

		ret = symrdma_version_bind_user_page(dev, mr,
						      (unsigned long)req.version_va,
						      req.version_len);
		if (ret)
			goto out_put;

		pr_debug("SET_VERSION_PAGE mr=%d va=0x%llx\n",
			req.mr_id, req.version_va);
		break;
	}

	case SYMRDMA_IOC_PIN_PAGES:
	case SYMRDMA_IOC_UNPIN_PAGES: {
		struct symrdma_ioc_pin req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (mr->mm != current->mm) {
			ret = -EPERM;
			goto out_put;
		}
		if (!access_ok((void __user *)(uintptr_t)req.va, req.len)) {
			ret = -EINVAL;
			goto out_put;
		}

		if (cmd == SYMRDMA_IOC_PIN_PAGES)
			ret = symrdma_pin_range(dev, mr, req.va, req.len);
		else
			ret = symrdma_unpin_range(dev, mr, req.va, req.len);
		if (ret)
			goto out_put;
		break;
	}

	default:
		return -ENOTTY;
	}

out_put:
	if (held)
		kref_put(&held->ref, symrdma_mr_release);

	if (held_st)
		symrdma_mm_state_put(held_st);
	return ret;
}

static const struct file_operations symrdma_dev_fops = {
	.owner          = THIS_MODULE,
	.open           = symrdma_dev_open,
	.release        = symrdma_dev_release,
	.read           = symrdma_dev_read,
	.unlocked_ioctl = symrdma_dev_ioctl,
};

int symrdma_dev_init(struct symrdma_dev *dev)
{
	int ret;

	dev->miscdev.minor = MISC_DYNAMIC_MINOR;
	dev->miscdev.name  = "symrdma";
	dev->miscdev.fops  = &symrdma_dev_fops;
	dev->miscdev.mode  = 0666;

	ret = misc_register(&dev->miscdev);
	if (ret)
		pr_err("failed to register /dev/symrdma: %d\n", ret);
	else
		pr_info("/dev/symrdma registered\n");

	return ret;
}

void symrdma_dev_cleanup(struct symrdma_dev *dev)
{
	misc_deregister(&dev->miscdev);
	pr_info("/dev/symrdma deregistered\n");
}
