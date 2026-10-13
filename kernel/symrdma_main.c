/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma_main.c — SymRDMA 内核模块入口
 *
 * 负责:
 * - 模块加载/卸载
 * - 哨兵页 & 黑洞页 分配/释放
 * - IOMMU domain 初始化
 * - 委托: /proc/symrdma (symrdma_proc.c), /dev/symrdma (symrdma_dev.c)
 */

#include "symrdma.h"

MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("SymRDMA Reproduction");
MODULE_DESCRIPTION("Optimistic IOMMU-based RDMA to unpinned memory (SymRDMA)");
MODULE_VERSION("0.3");

/* ---- 模块参数 ---- */
static int mode = SYMRDMA_DOMAIN_VERIFY;  /* 0=VERIFY, 1=NIC */
module_param(mode, int, 0444);
MODULE_PARM_DESC(mode, "Domain mode: 0=VERIFY (standalone), 1=NIC (attach to mlx5)");

static char pci_bdf[16];  /* e.g. "0000:3b:00.0" (12 字符 + NUL) */
module_param_string(pci_bdf, pci_bdf, sizeof(pci_bdf), 0444);
MODULE_PARM_DESC(pci_bdf, "mlx5 PCI BDF (NIC mode), e.g. 0000:3b:00.0");

/* v0.38.0: IOMMU 组粒度 (2MB) 映射开关 (docs/PLAN_IOMMU_HUGEPAGE.md)。
 * 1=启用 (区域分配失败自动降级逐页); 0=强制逐页 (现状形态, 回归对照)。 */
static int iommu_huge = 1;
module_param(iommu_huge, int, 0444);
MODULE_PARM_DESC(iommu_huge, "IOMMU 2MB group mapping: 0=per-4KB only, 1=hybrid (default)");

/* v0.38.0: REPAIR 段批 sg 路径 kill-switch (方案 Phase 1 门禁 —
 * SYMRDMA_NO_SG 的模块参数形态)。1=段批 (整段 unmap_fast +
 * iommu_map_sg_atomic run 合并, 默认); 0=v0.37 逐页交错形态
 * (16 页/块, 回归对照)。与 iommu_huge 正交: 组提升路径不经 sg。 */
static int repair_sg = 1;
module_param(repair_sg, int, 0444);
MODULE_PARM_DESC(repair_sg, "REPAIR segment sg batch: 0=v0.37 per-page interleave, 1=sg segment (default)");

/* v0.38.0: 组降级 fail-closed 路径注入 (L19) — 该组号降级时首页
 * 重映射模拟 GFP_ATOMIC 失败 → 哨兵/黑洞兑底分支。仅测试形态,
 * 默认 -1 关 (自然触发窗口极窄)。 */
static int demote_fail_grp = -1;
module_param(demote_fail_grp, int, 0444);
MODULE_PARM_DESC(demote_fail_grp, "inject demote fail for one group (-1=off, group index for L19 fail-closed test)");

static struct symrdma_dev *g_dev;

/* ---- Sentinel & Blackhole 页分配 ---- */

/* v0.38.0: order-9 连续区 (512 页) — 哨兵区全填魔数, 黑洞区任意内容;
 * 失败返回 -ENOMEM 由调用方决定降级 (huge_ok=0, 组机制整体关闭)。 */
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
	pr_info("symrdma: 2MB 哨兵区 PA=0x%llx 黑洞区 PA=0x%llx\n",
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

	/* 哨兵页: 每 4 字节填充 0xdeadbeef */
	dev->sentinel_page = alloc_page(GFP_KERNEL);
	if (!dev->sentinel_page) {
		pr_err("symrdma: 分配哨兵页失败\n");
		return -ENOMEM;
	}
	p = kmap(dev->sentinel_page);
	for (i = 0; i < PAGE_SIZE / sizeof(u32); i++)
		p[i] = SYMRDMA_SENTINEL_MAGIC;
	kunmap(dev->sentinel_page);
	dev->sentinel_pa = page_to_phys(dev->sentinel_page);
	pr_info("symrdma: 哨兵页 PA=0x%llx\n", dev->sentinel_pa);

	/* 黑洞页: 写入被吸收，永不读取 */
	dev->blackhole_page = alloc_page(GFP_KERNEL);
	if (!dev->blackhole_page) {
		pr_err("symrdma: 分配黑洞页失败\n");
		__free_page(dev->sentinel_page);
		return -ENOMEM;
	}
	dev->blackhole_pa = page_to_phys(dev->blackhole_page);
	pr_info("symrdma: 黑洞页 PA=0x%llx\n", dev->blackhole_pa);

	return 0;
}

static void free_special_pages(struct symrdma_dev *dev)
{
	if (dev->sentinel_page)
		__free_page(dev->sentinel_page);
	if (dev->blackhole_page)
		__free_page(dev->blackhole_page);
}

/* ---- 模块初始化 ---- */

static int __init symrdma_init(void)
{
	struct symrdma_dev *dev;
	int ret;

	pr_info("symrdma: 初始化中 (mode=%d, pci_bdf=%s)...\n",
		mode, pci_bdf[0] ? pci_bdf : "none");

	dev = kzalloc(sizeof(*dev), GFP_KERNEL);
	if (!dev)
		return -ENOMEM;

	/* 初始化锁和数据结构 */
	spin_lock_init(&dev->mr_lock);
	spin_lock_init(&dev->mm_state_lock);
	spin_lock_init(&dev->notif_lock);   /* v0.23.1 取证环形缓冲 */
	mutex_init(&dev->attach_lock);   /* A4: attach 全程持有 */
	INIT_LIST_HEAD(&dev->mr_list);
	INIT_LIST_HEAD(&dev->mm_states);
	idr_init(&dev->mr_idr);
	dev->mr_id_counter = 0;

	/* 设置运行模式 */
	dev->domain_mode = mode;
	dev->repair_sg = repair_sg;   /* v0.38.0: NO_SG kill-switch (静态参数 → 任意 MR 可读) */
	dev->demote_fail_grp = demote_fail_grp; /* v0.38.0: L19 降级 fail-closed 注入 */

	/* Step 1: 分配哨兵/黑洞页 */
	ret = alloc_special_pages(dev);
	if (ret)
		goto err_free_dev;

	/* v0.38.0: 2MB 特殊区 (组粒度映射前提) — 失败仅关闭组机制,
	 * 不阻断模块加载 (全逐页 = 既有形态, kill-switch 天然成立) */
	dev->huge_ok = 0;
	if (iommu_huge) {
		if (alloc_special_regions(dev) == 0)
			dev->huge_ok = 1;
		else
			pr_warn("symrdma: 2MB 特殊区分配失败 (碎片化), 组粒度映射关闭\n");
	}

	/* Step 2: 初始化 IOMMU domain */
	if (mode == SYMRDMA_DOMAIN_NIC) {
		/* NIC 模式: 发现 mlx5 设备并附加到其 IOMMU domain */
		struct pci_dev *pdev = symrdma_find_mlx5_by_bdf(pci_bdf);

		if (!pdev) {
			pr_err("symrdma: 未找到 mlx5 设备 (pci_bdf=%s)\n",
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
			pr_err("symrdma: IOMMU 初始化失败: %d\n", ret);
			goto err_free_pages;
		}
	}

	/* Step 3: 创建 /proc/symrdma */
	ret = symrdma_proc_init(dev);
	if (ret) {
		pr_err("symrdma: 创建 /proc/symrdma 失败\n");
		goto err_iommu_cleanup;
	}

	/* Step 4: 注册 /dev/symrdma */
	ret = symrdma_dev_init(dev);
	if (ret) {
		pr_err("symrdma: 注册 /dev/symrdma 失败\n");
		goto err_proc_cleanup;
	}

	g_dev = dev;
	pr_info("symrdma: 初始化成功 (模式=%s)\n",
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

	pr_info("symrdma: 退出中...\n");

	if (dev) {
		struct symrdma_mr *mr, *tmp;

		/* 清理所有活跃 MR (A6: 先从 idr 取走所有权再注销,
		 * 否则 kref_put 永不归零 → 模块退出泄漏) */
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

	pr_info("symrdma: 已退出\n");
}

module_init(symrdma_init);
module_exit(symrdma_exit);
