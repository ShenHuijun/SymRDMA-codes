/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 Mellanox Technologies. All rights reserved.
 * Copyright (c) 2020 Intel Corporation. All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/sched/signal.h>
#include <linux/sched/mm.h>
#include <linux/export.h>
#include <linux/slab.h>
#include <linux/scatterlist.h>
#include <linux/pagemap.h>
#include <linux/count_zeros.h>
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
#include <rdma/ib_umem_odp.h>
#endif

#include "uverbs.h"

#include "ib_peer_mem.h"

/*
 * SymRDMA 补丁说明: 本文件为 OFED 5.8-3.0.7.0 umem.c 的修改
 * 快照, 仅面向项目基线内核 5.11 (测试床 host-a/8, 5.11.0-46)。
 * 全部多内核版本兼容分支 (HAVE_SG_APPEND_TABLE / HAVE_ATOMIC_PINNED_VM /
 * 旧 GUP 变体 / DMA_ATTR / vma_list-hugetlb 跟踪等) 已按 5.11 configure
 * 实测取值解析为单一路径 — 5.12+ (sgt_append 世界) 不再可编译 (5.15
 * 支持移除, 与  移除 5.4 同族)。
 * SymRDMA 实际改动: IB_UMEM_NOPIN no-pin 路径 + is_nopin + 空 sg 守卫
 * (ib_umem_find_best_pgsz) + nopin 释放/限额记账。
 */

static void __ib_umem_release(struct ib_device *dev, struct ib_umem *umem, int dirty)
{
	struct sg_page_iter sg_iter;
	struct page *page;

	if (umem->nmap > 0)
		ib_dma_unmap_sg(dev, umem->sg_head.sgl, umem->sg_nents,
				DMA_BIDIRECTIONAL);

	for_each_sg_page(umem->sg_head.sgl, &sg_iter, umem->sg_nents, 0) {
		page = sg_page_iter_page(&sg_iter);
		unpin_user_pages_dirty_lock(&page, 1, umem->writable && dirty);
	}

	sg_free_table(&umem->sg_head);
}

/**
 * ib_umem_find_best_pgsz - Find best HW page size to use for this MR
 *
 * @umem: umem struct
 * @pgsz_bitmap: bitmap of HW supported page sizes
 * @virt: IOVA
 *
 * This helper is intended for HW that support multiple page
 * sizes but can do only a single page size in an MR.
 *
 * Returns 0 if the umem requires page sizes not supported by
 * the driver to be mapped. Drivers always supporting PAGE_SIZE
 * or smaller will never see a 0 result.
 */
unsigned long ib_umem_find_best_pgsz(struct ib_umem *umem,
				     unsigned long pgsz_bitmap,
				     unsigned long virt)
{
	struct scatterlist *sg;
	unsigned long va, pgoff;
	dma_addr_t mask;
	int i;

#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	if (umem->is_odp) {
		unsigned int page_size = BIT(to_ib_umem_odp(umem)->page_shift);

		/* ODP must always be self consistent. */
		if (!(pgsz_bitmap & page_size))
			return 0;
		return page_size;
	}
#endif

	/* rdma_for_each_block() has a bug if the page size is smaller than the
	 * page size used to build the umem. For now prevent smaller page sizes
	 * from being returned.
	 */
	pgsz_bitmap &= GENMASK(BITS_PER_LONG - 1, PAGE_SHIFT);
	umem->iova = va = virt;

	/* SymRDMA no-pin umem: sg 为空, 无 dma 地址约束 — 返回系统页大小
	 * (identity MTT 的粒度), 防下方 sg 解引用崩溃 。
	 * 空表判据 = nmap == 0 (fresh kzalloc 即 0, nopin 路径从不填充;
	 *  起单一 nmap 路径, HAVE_SG_APPEND_TABLE 分支随 5.15 支持
	 * 移除)。is_odp 守卫保留 — CONFIG_INFINIBAND_ON_DEMAND_PAGING
	 * 未定义时上方无 odp 早退, 此处兜底。 */
	if (!umem->nmap && !umem->is_odp)
		return pgsz_bitmap & PAGE_SIZE ? PAGE_SIZE : 0;

	/* The best result is the smallest page size that results in the minimum
	 * number of required pages. Compute the largest page size that could
	 * work based on VA address bits that don't change.
	 */
	mask = pgsz_bitmap &
	       GENMASK(BITS_PER_LONG - 1,
		       bits_per((umem->length - 1 + virt) ^ virt));
	/* offset into first SGL */
	pgoff = umem->address & ~PAGE_MASK;

	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, i) {

		/* Walk SGL and reduce max page size if VA/PA bits differ
		 * for any address.
		 */
		mask |= (sg_dma_address(sg) + pgoff) ^ va;
		va += sg_dma_len(sg) - pgoff;
		/* Except for the last entry, the ending iova alignment sets
		 * the maximum possible page size as the low bits of the iova
		 * must be zero when starting the next chunk.
		 */
		if (i != (umem->nmap - 1))
			mask |= va;
		pgoff = 0;
	}

	/* The mask accumulates 1's in each position where the VA and physical
	 * address differ, thus the length of trailing 0 is the largest page
	 * size that can pass the VA through to the physical.
	 */
	if (mask)
		pgsz_bitmap &= GENMASK(count_trailing_zeros(mask), 0);
	return pgsz_bitmap ? rounddown_pow_of_two(pgsz_bitmap) : 0;
}
EXPORT_SYMBOL(ib_umem_find_best_pgsz);

/**
 * __ib_umem_get - Pin and DMA map userspace memory.
 *
 * @device: IB device to connect UMEM
 * @addr: userspace virtual address to start at
 * @size: length of region to pin
 * @access: IB_ACCESS_xxx flags for memory being pinned
 * @peer_mem_flags: IB_PEER_MEM_xxx flags for memory being used
 */
static struct ib_umem *__ib_umem_get(struct ib_device *device,
				     unsigned long addr, size_t size, int access,
				     unsigned long peer_mem_flags)
{
	struct ib_umem *umem;
	struct page **page_list;
	unsigned long lock_limit;
	unsigned long new_pinned;
	unsigned long cur_base;
	struct mm_struct *mm;
	unsigned long npages;
	int ret;
	struct scatterlist *sg = NULL;
	unsigned int gup_flags = FOLL_WRITE;

	/*
	 * If the combination of the addr and size requested for this memory
	 * region causes an integer overflow, return error.
	 */
	if (((addr + size) < addr) ||
	    PAGE_ALIGN(addr + size) < (addr + size)) {
		pr_err("%s: integer overflow, size=%zu\n", __func__, size);
 		return ERR_PTR(-EINVAL);
	}

	if (access & IB_ACCESS_ON_DEMAND)
		return ERR_PTR(-EOPNOTSUPP);

	umem = kzalloc(sizeof(*umem), GFP_KERNEL);
	if (!umem)
		return ERR_PTR(-ENOMEM);
	umem->ibdev      = device;
	umem->length     = size;
	umem->address    = addr;
	/*
	 * Drivers should call ib_umem_find_best_pgsz() to set the iova
	 * correctly.
	 */
	umem->iova = addr;
	umem->writable   = ib_access_writable(access);
	umem->owning_mm = mm = current->mm;
	mmgrab(mm);

	page_list = (struct page **) __get_free_page(GFP_KERNEL);
	if (!page_list) {
		ret = -ENOMEM;
		goto umem_kfree;
	}
	npages = ib_umem_num_pages(umem);
	if (npages == 0 || npages > UINT_MAX) {
		ret = -EINVAL;
		goto out;
	}

	/*
	 * SymRDMA no-pin 路径 (IB_UMEM_NOPIN): 不 GUP (不 pin, 不占
	 * locked_vm 额度)、不 dma_map (sg 留空, nmap=0)。调用方必须
	 * 只用 ib_umem_num_pages()/length/address — MTT identity 模式下
	 * 翻译由 IOMMU 页表完成, dma IOVA 无用。空 sg 的 umem 由
	 * ib_umem_release 整体跳过 __ib_umem_release 。
	 * 注意: 必须在 can_do_mlock/限额检查之前 — no-pin 不需要
	 * mlock 权限 (RLIMIT_MEMLOCK=0 下 pin 版必失败, no-pin 必成功,
	 *  实测教训)。
	 */
	if (peer_mem_flags & IB_UMEM_NOPIN) {
		/* 标记 no-pin — ib_umem_release 据此跳过 pinned_vm
		 * 减法 (注册时未增加, 无条件减会下溢成负数, 破坏后续
		 * create_cq/正常 MR 的 mlock 限额检查 → ENOMEM)。 */
		umem->is_nopin = 1;
		/* 勿在此 free page_list — out: 出口本来就
		 * free_page(page_list), 此处先放是双重 free
		 * (第二次 put_page_testzero 对 refcount-0 页为 no-op,
		 * DEBUG_VM=y 时 VM_BUG_ON)。交由 out: 统一单次释放。 */
		ret = 0;
		goto out;
	}

	if (!can_do_mlock()) {
		pr_err("%s: no mlock permission\n", __func__);
		ret = -EPERM;
		goto out;
	}

	lock_limit = rlimit(RLIMIT_MEMLOCK) >> PAGE_SHIFT;

	new_pinned = atomic64_add_return(npages, &mm->pinned_vm);
	if (new_pinned > lock_limit && !capable(CAP_IPC_LOCK)) {
		atomic64_sub(npages, &mm->pinned_vm);
		ret = -ENOMEM;
		goto out;
	}

	cur_base = addr & PAGE_MASK;

	if (!umem->writable)
		gup_flags |= FOLL_FORCE;

	while (npages) {
		cond_resched();
		ret = pin_user_pages_fast(cur_base,
					  min_t(unsigned long, npages,
						PAGE_SIZE /
						sizeof(struct page *)),
					  gup_flags | FOLL_LONGTERM, page_list);
		if (ret < 0)
			goto umem_release;

		cur_base += ret * PAGE_SIZE;
		npages -= ret;
		sg = __sg_alloc_table_from_pages(
				&umem->sg_head, page_list, ret, 0, ret << PAGE_SHIFT,
				dma_get_max_seg_size(device->dma_device),
				sg, npages,
				GFP_KERNEL);
		umem->sg_nents = umem->sg_head.nents;
		if (IS_ERR(sg)) {
			unpin_user_pages_dirty_lock(page_list, ret, 0);
			ret = PTR_ERR(sg);
			goto umem_release;
		}
	}

	umem->nmap = ib_dma_map_sg(device,
				   umem->sg_head.sgl,
				   umem->sg_nents,
				   DMA_BIDIRECTIONAL);

	if (!umem->nmap) {
		pr_err("%s: failed to map scatterlist, npages=%lu\n", __func__,
		       npages);
		ret = -ENOMEM;
		goto umem_release;
	}

	ret = 0;
	goto out;


umem_release:
	__ib_umem_release(device, umem, 0);

	/*
	 * If the address belongs to peer memory client, then the first
	 * call to get_user_pages will fail. In this case, try to get
	 * these pages from the peers.
	 */
	//FIXME: this placement is horrible
	if (ret < 0 && peer_mem_flags & IB_PEER_MEM_ALLOW) {
		struct ib_umem *new_umem;

		new_umem = ib_peer_umem_get(umem, ret, peer_mem_flags);
		if (IS_ERR(new_umem)) {
			ret = PTR_ERR(new_umem);
			goto vma;
		}
		umem = new_umem;
		ret = 0;
		goto out;
	}
vma:
	atomic64_sub(ib_umem_num_pages(umem), &mm->pinned_vm);
out:
	free_page((unsigned long) page_list);
umem_kfree:
	if (ret) {
		mmdrop(umem->owning_mm);
		kfree(umem);
	}
	return ret ? ERR_PTR(ret) : umem;
}

struct ib_umem *ib_umem_get(struct ib_device *device, unsigned long addr,
			    size_t size, int access)
{
	return __ib_umem_get(device, addr, size, access, 0);
}
EXPORT_SYMBOL(ib_umem_get);

struct ib_umem *ib_umem_get_peer(struct ib_device *device, unsigned long addr,
				 size_t size, int access,
				 unsigned long peer_mem_flags)
{
	return __ib_umem_get(device, addr, size, access,
			     IB_PEER_MEM_ALLOW | peer_mem_flags);
}
EXPORT_SYMBOL(ib_umem_get_peer);

/*
 * SymRDMA: ib_umem_get_nopin — 不 pin 不 dma_map 的 umem。
 * 语义见 __ib_umem_get 的 IB_UMEM_NOPIN 分支。
 */
struct ib_umem *ib_umem_get_nopin(struct ib_device *device,
				  unsigned long addr, size_t size, int access)
{
	return __ib_umem_get(device, addr, size, access, IB_UMEM_NOPIN);
}
EXPORT_SYMBOL(ib_umem_get_nopin);

/**
 * ib_umem_release - release memory pinned with ib_umem_get
 * @umem: umem struct to release
 */
void ib_umem_release(struct ib_umem *umem)
{
	if (!umem)
		return;
	if (umem->is_dmabuf)
		return ib_umem_dmabuf_release(to_ib_umem_dmabuf(umem));
#ifdef CONFIG_INFINIBAND_ON_DEMAND_PAGING
	if (umem->is_odp)
		return ib_umem_odp_release(to_ib_umem_odp(umem));
#endif

	if (umem->is_peer)
		return ib_peer_umem_release(umem);
	/* no-pin umem 的 sg 为空 — 跳过 __ib_umem_release
	 * (nmap>0 守卫使跳过亦等价; 页未 pin、无 sg, 无资源需释放)。 */
	if (!umem->is_nopin)
		__ib_umem_release(umem->ibdev, umem, 1);

	if (!umem->is_nopin)
		atomic64_sub(ib_umem_num_pages(umem),
			     &umem->owning_mm->pinned_vm);
	mmdrop(umem->owning_mm);
	kfree(umem);
}
EXPORT_SYMBOL(ib_umem_release);

/*
 * Copy from the given ib_umem's pages to the given buffer.
 *
 * umem - the umem to copy from
 * offset - offset to start copying from
 * dst - destination buffer
 * length - buffer length
 *
 * Returns 0 on success, or an error code.
 */
int ib_umem_copy_from(void *dst, struct ib_umem *umem, size_t offset,
		      size_t length)
{
	size_t end = offset + length;
	int ret;

	if (offset > umem->length || length > umem->length - offset) {
		pr_err("%s not in range. offset: %zd umem length: %zd end: %zd\n",
		       __func__, offset, umem->length, end);
		return -EINVAL;
	}

	ret = sg_pcopy_to_buffer(umem->sg_head.sgl, umem->sg_nents, dst, length,
				 offset + ib_umem_offset(umem));

	if (ret < 0)
		return ret;
	else if (ret != length)
		return -EINVAL;
	else
		return 0;
}
EXPORT_SYMBOL(ib_umem_copy_from);
