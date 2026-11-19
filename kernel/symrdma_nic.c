/* SPDX-License-Identifier: GPL-2.0 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include "symrdma.h"

#define MLX5_VENDOR_ID  0x15b3
static const u16 mlx5_device_ids[] = {
	0x1011,
	0x1013,
	0x1015,
	0x1017,
	0x1019,
	0x101b,
	0x101d,
	0x1021,
	0
};

struct pci_dev *symrdma_find_mlx5(void)
{
	struct pci_dev *pdev = NULL;
	const u16 *dev_id;

	while ((pdev = pci_get_device(PCI_ANY_ID, PCI_ANY_ID, pdev)) != NULL) {
		if (pdev->vendor != MLX5_VENDOR_ID)
			continue;

		for (dev_id = mlx5_device_ids; *dev_id; dev_id++) {
			if (pdev->device == *dev_id) {
				pr_info("found mlx5 device %s (vendor=0x%x device=0x%x)\n",
					pci_name(pdev), pdev->vendor, pdev->device);
				return pdev;
			}
		}
	}

	return NULL;
}

struct pci_dev *symrdma_find_mlx5_by_bdf(const char *bdf)
{
	struct pci_dev *pdev;
	unsigned int domain, bus, devfn_slot, devfn_func;

	if (!bdf || !bdf[0])
		return symrdma_find_mlx5();

	if (sscanf(bdf, "%04x:%02x:%02x.%1u",
		   &domain, &bus, &devfn_slot, &devfn_func) != 4) {
		pr_err("invalid PCI BDF: %s (need 0000:3b:00.0 format)\n", bdf);
		return NULL;
	}

	pdev = pci_get_domain_bus_and_slot(domain, bus,
			PCI_DEVFN(devfn_slot, devfn_func));
	if (!pdev) {
		pr_err("PCI device %s not found\n", bdf);
		return NULL;
	}

	if (pdev->vendor != MLX5_VENDOR_ID) {
		pr_err("device %s vendor=0x%x is not a Mellanox device\n",
		       bdf, pdev->vendor);
		pci_dev_put(pdev);
		return NULL;
	}

	pr_info("found mlx5 device by BDF: %s\n", pci_name(pdev));
	return pdev;
}

bool symrdma_nic_is_passthrough(struct pci_dev *pdev)
{
	struct iommu_domain *domain;

	if (!pdev)
		return true;

	domain = iommu_get_domain_for_dev(&pdev->dev);
	if (!domain) {
		pr_warn("device %s has no IOMMU domain (likely passthrough)\n",
			pci_name(pdev));
		return true;
	}

	if (domain->pgsize_bitmap == 0) {
		pr_warn("device %s domain pgsize_bitmap=0 (passthrough)\n",
			pci_name(pdev));
		return true;
	}

	return false;
}

int symrdma_attach_nic_domain(struct symrdma_dev *dev, struct pci_dev *pdev)
{
	struct iommu_domain *domain;
	struct iommu_group *group;

	if (!pdev) {
		pr_err("NIC mode requires a valid pci_dev\n");
		return -ENODEV;
	}

	if (symrdma_nic_is_passthrough(pdev)) {
		pr_err("NIC is in IOMMU passthrough mode\n");
		pr_err("boot the kernel with intel_iommu=on (without pt)\n");
		return -ENOTSUPP;
	}

	group = iommu_group_get(&pdev->dev);
	if (!group) {
		pr_err("device %s is not in any IOMMU group\n",
		       pci_name(pdev));
		return -ENODEV;
	}

	domain = iommu_get_domain_for_dev(&pdev->dev);
	iommu_group_put(group);

	if (!domain) {
		pr_err("device %s has no IOMMU domain\n", pci_name(pdev));
		return -ENODEV;
	}

	dev->iommu_domain = domain;
	dev->pdev = pdev;
	dev->dev = &pdev->dev;
	dev->domain_mode = SYMRDMA_DOMAIN_NIC;

	dev->iommu_pgsize = domain->pgsize_bitmap
		? (1UL << __ffs(domain->pgsize_bitmap))
		: PAGE_SIZE;

	pr_info("attached to NIC domain %p (pgsize=%lu, type=%d)\n",
		domain, dev->iommu_pgsize, domain->type);

	return 0;
}

void symrdma_detach_nic_domain(struct symrdma_dev *dev)
{
	if (dev->pdev) {
		pci_dev_put(dev->pdev);
		dev->pdev = NULL;
	}
	dev->dev = NULL;
	dev->iommu_domain = NULL;
	pr_info("detached from NIC domain\n");
}
