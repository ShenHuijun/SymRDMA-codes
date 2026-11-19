/* SPDX-License-Identifier: GPL-2.0 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"
#include <linux/debugfs.h>

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("SymRDMA Reproduction");
MODULE_DESCRIPTION("Optimistic IOMMU-based RDMA to unpinned memory (SymRDMA)");
MODULE_VERSION("0.3");

static int mode = SYMRDMA_DOMAIN_VERIFY;
module_param(mode, int, 0444);
MODULE_PARM_DESC(mode, "Domain mode: 0=VERIFY (standalone), 1=NIC (attach to mlx5)");

static char pci_bdf[16];
module_param_string(pci_bdf, pci_bdf, sizeof(pci_bdf), 0444);
MODULE_PARM_DESC(pci_bdf, "mlx5 PCI BDF (NIC mode), e.g. 0000:3b:00.0");

static int iommu_huge = 1;
module_param(iommu_huge, int, 0444);
MODULE_PARM_DESC(iommu_huge, "IOMMU 2MB group mapping: 0=per-4KB only, 1=hybrid (default)");

static int repair_sg = 1;
module_param(repair_sg, int, 0444);
MODULE_PARM_DESC(repair_sg, "REPAIR segment sg batch: 0=per-page interleave, 1=sg segment (default)");

static int repair_budget_us = 8000;
module_param(repair_budget_us, int, 0444);
MODULE_PARM_DESC(repair_budget_us, "REPAIR_RANGE remap-phase time budget in us (0=unlimited, default 8000; stop at segment boundary, prefix contract; GUP excluded)");

static struct dentry *symrdma_dbg_dir;

static int dbg_state_assert_get(void *data, u64 *val)
{
	*val = symrdma_state_assert_on() ? 1 : 0;
	return 0;
}

static int dbg_state_assert_set(void *data, u64 val)
{
	symrdma_state_assert_set(val != 0);
	return 0;
}
DEFINE_DEBUGFS_ATTRIBUTE(dbg_state_assert_fops, dbg_state_assert_get,
			 dbg_state_assert_set, "%llu\n");

static struct symrdma_dev *g_dev;

/*
 * The one collaboration point with a test module (symrdma_test_hook.h).
 *
 * The test face is a separate module, so exactly two things cross: the test
 * module publishes its injection predicate here, and this module hands back one
 * verb that forces one page's state.  Both directions are RCU-published; with
 * no test module loaded every read is a NULL check and reports "no injection".
 * Nothing here is reachable from user space - a kernel module has to be loaded
 * first, and the verb it gets still resolves MRs by id and refuses one whose mm
 * is not the caller's.
 */
struct symrdma_test_ops __rcu *symrdma_test_ops_active;

static int test_force_page_state(int mr_id, unsigned long page_idx, int target)
{
	struct symrdma_dev *dev = READ_ONCE(g_dev);

	if (!dev)
		return -ENODEV;

	return symrdma_page_force_state(dev, mr_id, page_idx, target);
}

int symrdma_test_register(struct symrdma_test_ops *ops)
{
	if (!ops || !ops->demote_should_fail)
		return -EINVAL;
	if (rcu_access_pointer(symrdma_test_ops_active))
		return -EBUSY;

	ops->force_page_state = test_force_page_state;
	rcu_assign_pointer(symrdma_test_ops_active, ops);
	pr_info("test face attached: fault injection is possible until it detaches\n");
	return 0;
}
EXPORT_SYMBOL_GPL(symrdma_test_register);

void symrdma_test_unregister(void)
{
	if (!rcu_access_pointer(symrdma_test_ops_active))
		return;

	RCU_INIT_POINTER(symrdma_test_ops_active, NULL);
	synchronize_rcu();
	pr_info("test face detached\n");
}
EXPORT_SYMBOL_GPL(symrdma_test_unregister);

static int alloc_special_regions(struct symrdma_dev *dev)
{
	u32 *p;
	int i, k;

	dev->sentinel_region = alloc_pages(GFP_KERNEL, 9);
	if (!dev->sentinel_region)
		return -ENOMEM;
	for (k = 0; k < 512; k++) {
		p = kmap(nth_page(dev->sentinel_region, k));
		for (i = 0; i < PAGE_SIZE / sizeof(u32); i++)
			p[i] = SYMRDMA_SENTINEL_MAGIC;
		kunmap(nth_page(dev->sentinel_region, k));
	}
	dev->sentinel_region_pa = page_to_phys(dev->sentinel_region);

	dev->blackhole_region = alloc_pages(GFP_KERNEL, 9);
	if (!dev->blackhole_region) {
		__free_pages(dev->sentinel_region, 9);
		dev->sentinel_region = NULL;
		return -ENOMEM;
	}
	dev->blackhole_region_pa = page_to_phys(dev->blackhole_region);
	pr_info("2MB sentinel region PA=0x%llx blackhole PA=0x%llx\n",
		dev->sentinel_region_pa, dev->blackhole_region_pa);
	return 0;
}

static void free_special_regions(struct symrdma_dev *dev)
{
	if (dev->sentinel_region)
		__free_pages(dev->sentinel_region, 9);
	if (dev->blackhole_region)
		__free_pages(dev->blackhole_region, 9);
}

static int alloc_special_pages(struct symrdma_dev *dev)
{
	u32 *p;
	int i;

	dev->sentinel_page = alloc_page(GFP_KERNEL);
	if (!dev->sentinel_page) {
		pr_err("sentinel page alloc failed\n");
		return -ENOMEM;
	}
	p = kmap(dev->sentinel_page);
	for (i = 0; i < PAGE_SIZE / sizeof(u32); i++)
		p[i] = SYMRDMA_SENTINEL_MAGIC;
	kunmap(dev->sentinel_page);
	dev->sentinel_pa = page_to_phys(dev->sentinel_page);
	pr_info("sentinel page PA=0x%llx\n", dev->sentinel_pa);

	dev->blackhole_page = alloc_page(GFP_KERNEL);
	if (!dev->blackhole_page) {
		pr_err("blackhole page alloc failed\n");
		__free_page(dev->sentinel_page);
		return -ENOMEM;
	}
	dev->blackhole_pa = page_to_phys(dev->blackhole_page);
	pr_info("blackhole page PA=0x%llx\n", dev->blackhole_pa);

	return 0;
}

static void free_special_pages(struct symrdma_dev *dev)
{
	if (dev->sentinel_page)
		__free_page(dev->sentinel_page);
	if (dev->blackhole_page)
		__free_page(dev->blackhole_page);
}

static int __init symrdma_init(void)
{
	struct symrdma_dev *dev;
	int ret;

	pr_info("initializing (mode=%d, pci_bdf=%s)...\n",
		mode, pci_bdf[0] ? pci_bdf : "none");

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	spin_lock_init(&dev->mr_lock);
	spin_lock_init(&dev->mm_state_lock);
	spin_lock_init(&dev->notif_lock);
	spin_lock_init(&dev->trans_lock);
	mutex_init(&dev->attach_lock);
	INIT_LIST_HEAD(&dev->mr_list);
	INIT_LIST_HEAD(&dev->mm_states);
	idr_init(&dev->mr_idr);
	dev->mr_id_counter = 0;

	dev->domain_mode = mode;
	dev->repair_sg = repair_sg;
	dev->repair_budget_us = repair_budget_us;
	dev->repair_chunk = SYMRDMA_REPAIR_SEG;

	ret = alloc_special_pages(dev);
	if (ret)
		goto err_free_dev;

	symrdma_dbg_dir = debugfs_create_dir("symrdma", NULL);
	if (IS_ERR(symrdma_dbg_dir))
		symrdma_dbg_dir = NULL;
	if (symrdma_dbg_dir)
		debugfs_create_file("state_assert", 0644, symrdma_dbg_dir,
				    NULL, &dbg_state_assert_fops);

	dev->huge_ok = 0;
	if (iommu_huge) {
		if (alloc_special_regions(dev) == 0)
			dev->huge_ok = 1;
		else
			pr_warn("2MB special region alloc failed (fragmentation), group mapping off\n");
	}

	if (mode == SYMRDMA_DOMAIN_NIC) {
		struct pci_dev *pdev = symrdma_find_mlx5_by_bdf(pci_bdf);

		if (!pdev) {
			pr_err("mlx5 device not found (pci_bdf=%s)\n",
			       pci_bdf[0] ? pci_bdf : "auto");
			ret = -ENODEV;
			goto err_free_pages;
		}
		ret = symrdma_attach_nic_domain(dev, pdev);
		if (ret) {
			pci_dev_put(pdev);
			goto err_free_pages;
		}
	} else {
		ret = symrdma_iommu_init(dev, dev->domain_mode);
		if (ret) {
			pr_err("IOMMU init failed: %d\n", ret);
			goto err_free_pages;
		}
	}

	ret = symrdma_proc_init(dev);
	if (ret) {
		pr_err("failed to create /proc/symrdma\n");
		goto err_iommu_cleanup;
	}

	ret = symrdma_dev_init(dev);
	if (ret) {
		pr_err("failed to register /dev/symrdma\n");
		goto err_proc_cleanup;
	}

	g_dev = dev;
	pr_info("init ok (mode=%s)\n",
		dev->domain_mode == SYMRDMA_DOMAIN_VERIFY ?
		"VERIFY" : "NIC");
	return 0;

err_proc_cleanup:
	symrdma_proc_cleanup(dev);
err_iommu_cleanup:
	symrdma_iommu_cleanup(dev);
err_free_pages:
	free_special_regions(dev);
	free_special_pages(dev);
err_free_dev:
	kfree(dev);
	return ret;
}

static void __exit symrdma_exit(void)
{
	struct symrdma_dev *dev = g_dev;

	pr_info("exiting...\n");

	debugfs_remove_recursive(symrdma_dbg_dir);
	symrdma_dbg_dir = NULL;

	if (dev) {
		struct symrdma_mr *mr, *tmp;

		list_for_each_entry_safe(mr, tmp, &dev->mr_list, list) {
			spin_lock(&dev->mr_lock);
			idr_remove(&dev->mr_idr, mr->mr_id);
			spin_unlock(&dev->mr_lock);
			symrdma_dereg_mr(dev, mr);
		}

		symrdma_dev_cleanup(dev);
		symrdma_proc_cleanup(dev);
		if (dev->domain_mode == SYMRDMA_DOMAIN_NIC)
			symrdma_detach_nic_domain(dev);
		else
			symrdma_iommu_cleanup(dev);
		free_special_regions(dev);
		free_special_pages(dev);

		idr_destroy(&dev->mr_idr);
		kfree(dev);
		g_dev = NULL;
	}

	pr_info("exited\n");
}

module_init(symrdma_init);
module_exit(symrdma_exit);
