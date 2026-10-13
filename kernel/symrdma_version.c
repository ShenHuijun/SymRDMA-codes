/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma_version.c — Version MR 管理
 *
 * 论文 §3.1.2: 每页一个 4 字节版本号，resident 为奇数 (1)，absent 起始为偶数 (0)。
 * swap-out 时原子递增，使版本号在奇偶间翻转，让远端 seqlock 检测变化。
 *
 *  版本表支持两种存储:
 *   - 默认: 内核 kzalloc (旧行为, ioctl GET_VERSION 查询)
 *   - SET_VERSION_PAGE 绑定用户 pinned 页 (version_pages): 内核经
 *     kmap_atomic 写入, 用户侧注册为普通 MR (REMOTE_READ) → 远端
 *     one-sided RDMA 直读 (论文 Version MR)。用户页须 mlock。
 *  多页版本表 (每页 1024 个 4B 版本, 支持 >1024 页 MR;
 *   论文 128GB MR 需 128MB 版本表 = 32768 页)。
 */
#include "symrdma.h"
#include <linux/highmem.h>

/* 每页版本数 (4KB / 4B) */
#define SYMRDMA_VERS_PER_PAGE  (PAGE_SIZE / sizeof(u32))

/* ---- 用户页 vs 内核内存的统一读写 (原子上下文安全) ---- */

/* 版本表页内映射: 页数组 vs kzalloc 单指针。
 * 调用约定: 所有读写方 (notifier/REPAIR/ioctl) 串行于 st->lock;
 * 本函数不自行加锁 (kmap_atomic 原子上下文安全)。
 *  bind 切换表指针亦纳入 st->lock — 防止 kswapd/NUMA 平衡
 * 等内核线程上下文的 notifier 在 kzalloc 表已释放、页数组未就位的
 * 窗口解引用悬空指针 (UAF)。 */
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

	if (!slot)
		return 0;
	val = READ_ONCE(*slot);
	if (mr->version_pages)
		kunmap_atomic(slot - (page_idx % SYMRDMA_VERS_PER_PAGE));
	return val;
}

void symrdma_version_set(struct symrdma_mr *mr, unsigned long page_idx, u32 val)
{
	u32 *slot = symrdma_version_slot(mr, page_idx);

	if (!slot)
		return;
	WRITE_ONCE(*slot, val);
	if (mr->version_pages)
		kunmap_atomic(slot - (page_idx % SYMRDMA_VERS_PER_PAGE));
}

void symrdma_version_inc(struct symrdma_mr *mr, unsigned long page_idx)
{
	u32 cur = symrdma_version_read(mr, page_idx);

	/* Atomic increment — flips between odd (resident) and even (absent) */
	symrdma_version_set(mr, page_idx, cur + 1);
}

int symrdma_version_alloc(struct symrdma_mr *mr)
{
	unsigned long size = mr->npages * sizeof(u32);

	/* 版本表内存 — 先于 notifier 附加分配: 回调可能在注册完成前
	 * 触发, version_inc 假定表已分配。取值由 version_init 设置。 */
	mr->version_table = kvzalloc(size, GFP_KERNEL);   /* 大 MR (1GB+ = 4MB+) 超 kmalloc 上限 */
	if (!mr->version_table)
		return -ENOMEM;
	return 0;
}

/* 按逐页最终驻留状态初始化版本值: 必须在页表遍历之后调用 —
 * 先于遍历会因 pages[] 全零 (PAGE_RESIDENT=0) 把所有页 (含缺失页)
 * 误置为奇数 → seqlock 偶数短路失效, 哨兵数据被当作有效数据。 */
void symrdma_version_init(struct symrdma_mr *mr)
{
	int i;

	for (i = 0; i < mr->npages; i++) {
		if (mr->pages[i].read_state == PAGE_RESIDENT)
			symrdma_version_set(mr, i, SYMRDMA_VERSION_INIT_RESIDENT);  /* 1 */
		else
			symrdma_version_set(mr, i, SYMRDMA_VERSION_INIT_ABSENT);    /* 0 */
	}
}

void symrdma_version_free(struct symrdma_mr *mr)
{
	if (mr->version_pages) {
		unsigned long i;

		/* 用户页: 释放内核引用; 内存由用户 munmap/释放 */
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
 * SET_VERSION_PAGE: 把版本表绑定到用户 pinned 页 (论文 §3.1.2 Version MR)。
 * 调用者 (用户库) 已 mlock 该页 (防换出); 内核 follow_page 取 page 引用,
 * 后续 notifier/REPAIR 经 kmap_atomic 写入。旧 kzalloc 版本表被释放。
 *
 * version_len: 版本表页数 (0 = 按 npages 自动计算 ceil/1024)。
 *  多页支持 (>1024 页 MR)。
 */
int symrdma_version_bind_user_page(struct symrdma_dev *dev,
				   struct symrdma_mr *mr,
				   unsigned long version_va,
				   unsigned long version_len)
{
	struct mm_struct *mm = current->mm;
	struct symrdma_mm_state *st;
	struct page **pages;
	unsigned long vt_pages, i, va;
	int ret = 0;

	if (mr->version_pages)
		return -EINVAL;             /* 已绑定 */
	if (version_va == 0 || !mm)
		return -EINVAL;

	vt_pages = version_len ?
		version_len :
		DIV_ROUND_UP(mr->npages, SYMRDMA_VERS_PER_PAGE);

	pages = kcalloc(vt_pages, sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return -ENOMEM;

	/* 逐页 follow_page (无副作用) + 清零 + 持引用。
	 * (页表遍历须持 mmap 读锁 — 并发 munmap/THP split 期间
	 * 无锁遍历会触碰悬空 PTE (REG_MR 路径持写锁, 本路径 
	 * 引入时漏加)。 */
	mmap_read_lock(mm);
	va = version_va;
	for (i = 0; i < vt_pages; i++, va += PAGE_SIZE) {
		struct page *pg = symrdma_follow_page_nofault(mm, va);

		if (!pg) {
			ret = -EFAULT;
			goto err_unlock;
		}
		if (PageCompound(pg)) {
			/* THP/大页: 版本表按 4KB 页粒度 kmap + 索引，
			 * 复合页会使多槽位映射同一头页 → 版本互相覆盖
			 * (历史 A1)。拒绝绑定，调用方回退 ioctl 通道。 */
			put_page(pg);
			ret = -EFAULT;
			goto err_unlock;
		}
		{
			void *kaddr = kmap_atomic(pg);
			memset(kaddr, 0, PAGE_SIZE);
			kunmap_atomic(kaddr);
		}
		pages[i] = pg;
	}
	mmap_read_unlock(mm);

	/* 表指针切换 + 重新初始化与 notifier (kswapd/NUMA 平衡
	 * 等内核线程可并发触发) 串行化 — version_slot 的解引用窗口内
	 * 两张表都有效。st->lock 与 version_slot 所有调用方同锁。
	 * G2: st 临时引用经 mm_state_lock 原子获取; MR 已拆卸
	 * (NULL) fail-closed — 对将亡 MR 换表无意义, 且闭合"拆卸后无锁
	 * 切换 vs GET_VERSION 拆卸态无锁读"的表指针 kfree 竞态 (本检查
	 * 后 version_table 冻结, mr kref 保证内存存活)。 */
	st = symrdma_mm_state_get(mr);
	if (!st) {
		while (vt_pages-- > 0)
			put_page(pages[vt_pages]);
		kfree(pages);
		return -ENOENT;
	}
	spin_lock(&st->lock);
	/* G1 复查: 并发拆卸接管 → fail-closed (同上) */
	if (mr->mm_state != st) {
		spin_unlock(&st->lock);
		symrdma_mm_state_put(st);
		while (vt_pages-- > 0)
			put_page(pages[vt_pages]);
		kfree(pages);
		return -ENOENT;
	}
	kvfree(mr->version_table);
	mr->version_table = NULL;
	mr->version_pages = pages;
	mr->version_vt_pages = vt_pages;
	mr->version_npages = mr->npages;

	/* 用当前驻留状态初始化版本值 (锁内: 与并发 version_inc 互斥) */
	symrdma_version_init(mr);
	spin_unlock(&st->lock);
	symrdma_mm_state_put(st);

	pr_info("symrdma: MR VA=0x%llx 版本表绑定用户页 VA=0x%lx (%lu 页版本, %lu 表页)\n",
		mr->va_start, version_va, mr->npages, vt_pages);
	return 0;

err_unlock:
	mmap_read_unlock(mm);
	/* 剩余引用释放: pages[0..i-1] 已持引用; 失败页自身已在调用点归还 */
	while (i-- > 0)
		put_page(pages[i]);
	kfree(pages);
	return ret;
}
