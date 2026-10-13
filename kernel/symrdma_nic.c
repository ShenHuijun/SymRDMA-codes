/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma_nic.c — mlx5 NIC 发现与 IOMMU domain 附加
 *
 * 论文 §4.1: SymRDMA 在 NIC 模式下将自身 IOMMU 映射注入 mlx5 NIC
 * 已有的 IOMMU domain 中。RDMA 网卡做 DMA 时硬件遍历的 IOMMU 页表
 * 即为 SymRDMA 修改的同一张表。
 *
 * 两种子模式:
 *   NIC_SHARED — 使用 iommu_get_domain_for_dev() 获取 NIC 已有 domain，
 *                 向其中添加 SymRDMA 映射。要求 IOMMU 为非 passthrough 模式。
 *   NIC_OWN    — 分配新 domain 替换 NIC 的 domain (iommu=pt 时需要)。
 *                 警告: 此操作会导致 mlx5 驱动已有 DMA 映射失效。
 *
 * 当前仅实现 NIC_SHARED，即在启动时使用 intel_iommu=on (非 pt) 的系统。
 */
#include "symrdma.h"

#define MLX5_VENDOR_ID  0x15b3
/* ConnectX-4/5/6/7 系列 device ID */
static const u16 mlx5_device_ids[] = {
	0x1011, /* ConnectX-6 Dx */
	0x1013, /* ConnectX-6 Lx */
	0x1015, /* ConnectX-6 */
	0x1017, /* ConnectX-5 */
	0x1019, /* ConnectX-5 Ex */
	0x101b, /* ConnectX-4 */
	0x101d, /* ConnectX-4 Lx */
	0x1021, /* ConnectX-7 */
	0
};

/**
 * symrdma_find_mlx5 - 发现系统中的 mlx5 网卡
 *
 * 遍历所有 PCI 设备，匹配 Mellanox vendor ID 和已知 device ID。
 * 返回第一个匹配设备的 pci_dev 指针 (引用计数已增加)，
 * 调用者负责 pci_dev_put()。
 *
 * 若未找到则返回 NULL。
 */
struct pci_dev *symrdma_find_mlx5(void)
{
	struct pci_dev *pdev = NULL;
	const u16 *dev_id;

	while ((pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev)) != NULL) {
		if (pdev->vendor != MLX5_VENDOR_ID)
			continue;

		for (dev_id = mlx5_device_ids; *dev_id; dev_id++) {
			if (pdev->device == *dev_id) {
				pr_info("symrdma: 发现 mlx5 设备 %s (vendor=0x%x device=0x%x)\n",
					pci_name(pdev), pdev->vendor, pdev->device);
				return pdev;
			}
		}
	}

	return NULL;
}

/**
 * symrdma_find_mlx5_by_bdf - 按 PCI BDF 查找 mlx5 设备
 * @bdf: PCI BDF 字符串，如 "0000:3b:00.0"
 *
 * 返回匹配设备的 pci_dev 指针或 NULL。
 */
struct pci_dev *symrdma_find_mlx5_by_bdf(const char *bdf)
{
	struct pci_dev *pdev;
	unsigned int domain, bus, devfn_slot, devfn_func;

	if (!bdf || !bdf[0])
		return symrdma_find_mlx5();

	/* 解析 BDF: "DDDD:BB:SS.F" 格式 */
	if (sscanf(bdf, "%04x:%02x:%02x.%1u",
		   &domain, &bus, &devfn_slot, &devfn_func) != 4) {
		pr_err("symrdma: 无效的 PCI BDF: %s (需格式 0000:3b:00.0)\n", bdf);
		return NULL;
	}

	pdev = pci_get_domain_bus_and_slot(domain, bus,
			PCI_DEVFN(devfn_slot, devfn_func));
	if (!pdev) {
		pr_err("symrdma: 未找到 PCI 设备 %s\n", bdf);
		return NULL;
	}

	if (pdev->vendor != MLX5_VENDOR_ID) {
		pr_err("symrdma: 设备 %s vendor=0x%x, 不是 Mellanox 设备\n",
		       bdf, pdev->vendor);
		pci_dev_put(pdev);
		return NULL;
	}

	pr_info("symrdma: 按 BDF 找到 mlx5 设备 %s\n", pci_name(pdev));
	return pdev;
}

/**
 * symrdma_nic_is_passthrough - 检测 IOMMU 是否为 passthrough 模式
 *
 * 在 intel_iommu=pt (或 iommu=pt) 下, IOMMU 使用 identity domain,
 * 不做任何地址翻译。此时向 domain 添加映射无意义。
 *
 * 返回 true 表示 passthrough 模式, SymRDMA 的 NIC_SHARED 模式不可用。
 */
bool symrdma_nic_is_passthrough(struct pci_dev *pdev)
{
	struct iommu_domain *domain;

	if (!pdev)
		return true;

	domain = iommu_get_domain_for_dev(&pdev->dev);
	if (!domain) {
		pr_info("symrdma: 设备 %s 无 IOMMU domain (可能是 passthrough)\n",
			pci_name(pdev));
		return true;
	}

	/*
	 * 检查 domain 类型。Identity/blocked domain 不支持 iommu_map()。
	 * pgsize_bitmap 为 0 通常表示 passthrough domain。
	 */
	if (domain->pgsize_bitmap == 0) {
		pr_info("symrdma: 设备 %s 的 domain pgsize_bitmap=0 (passthrough)\n",
			pci_name(pdev));
		return true;
	}

	return false;
}

/**
 * symrdma_attach_nic_domain - 附加到 mlx5 NIC 的 IOMMU domain
 * @dev:   SymRDMA 设备
 * @pdev:  mlx5 PCI 设备
 *
 * NIC_SHARED 模式: 获取 NIC 已有的 IOMMU domain，保存引用。
 * 此后 SymRDMA 的 iommu_map/iommu_unmap 操作直接修改此 domain
 * 的页表——这正是 RDMA NIC 做 DMA 时硬件遍历的表。
 *
 * 返回: 0 成功, -ENODEV 无 domain, -ENOTSUPP passthrough 模式
 */
int symrdma_attach_nic_domain(struct symrdma_dev *dev, struct pci_dev *pdev)
{
	struct iommu_domain *domain;
	struct iommu_group *group;

	if (!pdev) {
		pr_err("symrdma: NIC 模式需要有效的 pci_dev\n");
		return -ENODEV;
	}

	/* 检测 passthrough */
	if (symrdma_nic_is_passthrough(pdev)) {
		pr_err("symrdma: NIC 处于 IOMMU passthrough 模式\n");
		pr_err("symrdma: 请使用 intel_iommu=on (不加 pt) 启动内核\n");
		return -ENOTSUPP;
	}

	group = iommu_group_get(&pdev->dev);
	if (!group) {
		pr_err("symrdma: 设备 %s 不在任何 IOMMU group 中\n",
		       pci_name(pdev));
		return -ENODEV;
	}

	domain = iommu_get_domain_for_dev(&pdev->dev);
	iommu_group_put(group);

	if (!domain) {
		pr_err("symrdma: 设备 %s 没有 IOMMU domain\n", pci_name(pdev));
		return -ENODEV;
	}

	/* 使用 NIC 的现有 domain — 不创建新的 */
	dev->iommu_domain = domain;
	dev->pdev = pdev;
	dev->dev = &pdev->dev;
	dev->domain_mode = SYMRDMA_DOMAIN_NIC;

	/* 获取 IOMMU 页大小 */
	dev->iommu_pgsize = domain->pgsize_bitmap
		? (1UL << __ffs(domain->pgsize_bitmap))
		: PAGE_SIZE;

	pr_info("symrdma: 已附加到 NIC domain %p (pgsize=%lu, type=%d)\n",
		domain, dev->iommu_pgsize, domain->type);

	return 0;
}

/**
 * symrdma_detach_nic_domain - 从 NIC domain 断开
 * @dev: SymRDMA 设备
 *
 * NIC_SHARED 模式下仅清除引用——不释放 domain (它属于 mlx5 驱动)。
 */
void symrdma_detach_nic_domain(struct symrdma_dev *dev)
{
	if (dev->pdev) {
		pci_dev_put(dev->pdev);
		dev->pdev = NULL;
	}
	dev->dev = NULL;
	dev->iommu_domain = NULL;
	pr_info("symrdma: 已从 NIC domain 断开\n");
}
