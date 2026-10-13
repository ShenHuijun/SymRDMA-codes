/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma_iommu.c — IOMMU 页表管理
 *
 * 论文 §4.1 核心逻辑:
 * - 验证模式: 自建 IOMMU domain (iommu_domain_alloc)，不绑定 PCI 设备
 * - NIC 模式: 获取 mlx5 NIC 的 IOMMU domain
 * - 双 IOVA 映射: Read MR IOVA 和 Write MR IOVA 分别映射
 * - 运行时重映射: 哨兵/黑洞/真实
 * - READ_IOVA: 通过 IOMMU 页表读取数据 (Level 1 验证)
 * - REPAIR: 重新解析 VA，若驻留则重映射到真实 PA
 */
#include "symrdma.h"
#include <asm/pgtable.h>   /* pgd_offset / pte_offset_map (驻留判定) */
#include <linux/scatterlist.h>   /* iommu_map_sg_atomic 段批 */
#include <linux/bitmap.h>        /* remap okmask (128 位) */
#include <linux/ktime.h>         /* MAPBENCH 计时 */

static struct iommu_domain *symrdma_get_device_domain(struct device *dev);

/* ---- IOMMU domain 获取 (NIC 模式) ---- */
static struct iommu_domain *symrdma_get_device_domain(struct device *dev)
{
	struct iommu_domain *domain;
	struct iommu_group *group;

	group = iommu_group_get(dev);
	if (!group) {
		pr_err("symrdma: 设备 %s 不在任何 IOMMU group 中\n",
		       dev_name(dev));
		return ERR_PTR(-ENODEV);
	}

	domain = iommu_get_domain_for_dev(dev);

	iommu_group_put(group);

	if (!domain) {
		pr_err("symrdma: 设备 %s 没有 IOMMU domain\n", dev_name(dev));
		pr_err("symrdma: 请确保设置了 intel_iommu=on 或 iommu=on\n");
		return ERR_PTR(-ENODEV);
	}

	return domain;
}

/* ---- IOMMU domain 初始化 ---- */
int symrdma_iommu_init(struct symrdma_dev *dev, int mode)
{
	struct iommu_domain *domain;

	dev->domain_mode = mode;

	if (mode == SYMRDMA_DOMAIN_VERIFY) {
		/*
		 * 验证模式: 分配独立的 IOMMU domain。
		 * 此 domain 不绑定任何 PCI 设备，仅用于验证 IOMMU 映射逻辑。
		 * 通过 READ_IOVA ioctl 可以查询/验证页表正确性。
		 */
		domain = iommu_domain_alloc(&pci_bus_type);
		if (!domain) {
			pr_err("symrdma: iommu_domain_alloc 失败\n");
			pr_err("symrdma: 请确保 IOMMU 已启用 (intel_iommu=on)\n");
			return -ENODEV;
		}
		dev->iommu_domain = domain;
		dev->dev = NULL;

		pr_info("symrdma: VERIFY 模式 — 自建 IOMMU domain %p\n", domain);
	} else {
		/* NIC 模式: 使用 mlx5 设备的 IOMMU domain */
		if (!dev->dev) {
			pr_err("symrdma: NIC 模式需要先设置 dev->dev\n");
			return -ENODEV;
		}
		domain = symrdma_get_device_domain(dev->dev);
		if (IS_ERR(domain))
			return PTR_ERR(domain);

		dev->iommu_domain = domain;
		pr_info("symrdma: NIC 模式 — 使用已有 domain %p\n", domain);
	}

	/* 获取 IOMMU 支持的最小页大小 */
	dev->iommu_pgsize = domain->pgsize_bitmap
		? (1UL << __ffs(domain->pgsize_bitmap))
		: PAGE_SIZE;

	pr_info("symrdma: IOMMU domain=%p pgsize=%lu\n",
		domain, dev->iommu_pgsize);

	return 0;
}

void symrdma_iommu_cleanup(struct symrdma_dev *dev)
{
	if (dev->domain_mode == SYMRDMA_DOMAIN_VERIFY && dev->iommu_domain) {
		iommu_domain_free(dev->iommu_domain);
		pr_info("symrdma: VERIFY domain 已释放\n");
	}
	dev->iommu_domain = NULL;
}

/* ---- 基础 IOMMU 页映射 ---- */

int symrdma_iommu_map_page(struct symrdma_dev *dev, unsigned long iova,
			   phys_addr_t pa, int prot)
{
	int ret;

	if (!dev->iommu_domain) {
		pr_err("symrdma: 无 IOMMU domain\n");
		return -ENODEV;
	}

	ret = iommu_map(dev->iommu_domain, iova, pa, PAGE_SIZE, prot);
	if (ret) {
		pr_err("symrdma: iommu_map(0x%lx -> 0x%llx) 失败: %d\n",
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

/* R3 重构: 双 IOVA (read/write) 逐页 unmap — 原三处手写同循环收敛
 * (dereg_mr / mm_release 阶段 2 / map_mr_pages err 回滚)。
 * npages 为显式参数而非恒取 mr->npages: 回滚路径只回滚**已映射前缀**
 * [0, fail_idx) (suffix 从未 map 过, 行为逐字节保持)。 */
void symrdma_unmap_mr_pages(struct symrdma_dev *dev, struct symrdma_mr *mr,
			    unsigned long npages)
{
	unsigned long i = 0;

	while (i < npages) {
		unsigned long grp = i >> SYMRDMA_GROUP_SHIFT;

		/* 提升组整组单条超页 — 一次 2MB unmap (1 walk +
		 * 1 flush) 取代 512×2 逐页。未提升/残组逐页 (原语义)。
		 * (grp+1)*512<=npages 守护: 回滚前缀可能止于组中间 — 残组
		 * 不可能处于提升态 (提升要求整组), 防御性退回逐页。 */
		if (mr->groups &&
		    (grp + 1) * SYMRDMA_GROUP_PAGES <= npages &&
		    mr->groups[grp].state != GRP_NONE) {
			iommu_unmap(dev->iommu_domain,
				    mr->read_iova +
				    grp * SYMRDMA_GROUP_SIZE,
				    SYMRDMA_GROUP_SIZE);
			iommu_unmap(dev->iommu_domain,
				    mr->write_iova +
				    grp * SYMRDMA_GROUP_SIZE,
				    SYMRDMA_GROUP_SIZE);
			i += SYMRDMA_GROUP_PAGES;
			continue;
		}
		symrdma_iommu_unmap_page(dev,
			mr->read_iova + i * PAGE_SIZE);
		symrdma_iommu_unmap_page(dev,
			mr->write_iova + i * PAGE_SIZE);
		i++;
	}
}

/* G1: 注册失败路径的全范围 PTE 清理。
 *
 * REG_MR 失败时, notifier 可能已在 pages[] 上建立哨兵/黑洞映射
 * (attach 先于遍历 + 遍历期间 rmap 类失效源不经 mmap_lock — 详见
 * symrdma_map_mr_pages 的 G1 注释); 旧实现只回滚遍历自映射的前缀,
 * notifier 映射的 PTE 永久遗留 → 同 VA 重注册永远 -EBUSY (实测 G1:
 * "PTE already set" 旧值全为哨兵 0x1/黑洞 0x3)。
 *
 * 只清理"本 MR 曾建立过映射"的页 (read/write state != RESIDENT 或
 * orig_pa != 0); 未触碰页 (三值全零) 的 IOVA 上若存在 PTE, 属于跨进程
 * identity IOVA 冲突或历史遗留, 不是本 MR 的产物, 不得触碰 — 否则
 * 会偷掉活跃 MR 的映射 (历史 G1 修复方向 ②"盲 unmap-before-map"
 * 因此否决)。调用前须先 mn_detach (终止 notifier 活动, 状态冻结;
 * 本 MR 无 idr 条目无并发 ioctl, 锁外读状态安全)。 */
void symrdma_unmap_mr_pages_touched(struct symrdma_dev *dev,
				    struct symrdma_mr *mr)
{
	unsigned long i = 0;

	while (i < mr->npages) {
		unsigned long grp = i >> SYMRDMA_GROUP_SHIFT;

		/* 提升组整组单条超页 — 按值认定 (组基址对
		 * GRP_RESIDENT / 哨兵、黑洞区对 GRP_ABSENT; 单页 sentinel_pa
		 * 判据对区域超页不命中), 单次 2MB unmap 撤整组。npages 全量
		 * (touched 无前缀截断), (grp+1)*512<=npages 守护同前。
		 * 语义等价: 组提升是纯映射变换, pages[]/orig_pa 不变 — 提升后
		 * 组内页三值仍满足 “本 MR 产物” 判据, 超页必为本方所建。 */
		if (mr->groups &&
		    (grp + 1) * SYMRDMA_GROUP_PAGES <= mr->npages &&
		    mr->groups[grp].state != GRP_NONE) {
			u64 riova = mr->read_iova +
				    grp * SYMRDMA_GROUP_SIZE;
			u64 wiova = mr->write_iova +
				    grp * SYMRDMA_GROUP_SIZE;
			phys_addr_t rpa = iommu_iova_to_phys(dev->iommu_domain,
							   riova);
			phys_addr_t wpa = iommu_iova_to_phys(dev->iommu_domain,
							   wiova);

			if (rpa == dev->sentinel_region_pa ||
			    (mr->groups[grp].state == GRP_RESIDENT &&
			     rpa == mr->groups[grp].base_pa))
				iommu_unmap(dev->iommu_domain, riova,
				    SYMRDMA_GROUP_SIZE);
			if (wpa == dev->blackhole_region_pa ||
			    (mr->groups[grp].state == GRP_RESIDENT &&
			     wpa == mr->groups[grp].base_pa))
				iommu_unmap(dev->iommu_domain, wiova,
				    SYMRDMA_GROUP_SIZE);
			i += SYMRDMA_GROUP_PAGES;
			continue;
		}

		{
			u64 riova = mr->read_iova + i * PAGE_SIZE;
			u64 wiova = mr->write_iova + i * PAGE_SIZE;
			phys_addr_t rpa = iommu_iova_to_phys(dev->iommu_domain,
							   riova);
			phys_addr_t wpa = iommu_iova_to_phys(dev->iommu_domain,
							   wiova);

			/* 按值认定本 MR 产物: 哨兵/黑洞 (遍历自映射或 notifier 哨兵化)
			 * 或与 orig_pa 一致的真实映射 (注册遍历所建; 他 MR 无法覆盖 —
			 * 其注册会在本方 PTE 在位时 -EBUSY 失败)。跨进程 identity
			 * 冲突的他 MR/历史 PTE 一律跳过 (防偷映射)。
			 * 注: pages[] 状态不可作清理判据 — 冲突页状态可能已被本方置
			 * SENTINEL 而 PTE 属于他 MR (map 失败不回写状态); 反之 notifier
			 * 哨兵化页的状态会被遍历采纳分支保持。按值判定与状态无关。 */
			if (rpa == dev->sentinel_pa ||
			    (mr->pages[i].orig_pa != 0 &&
			     rpa == mr->pages[i].orig_pa))
				symrdma_iommu_unmap_page(dev, riova);
			if (wpa == dev->blackhole_pa ||
			    (mr->pages[i].orig_pa != 0 &&
			     wpa == mr->pages[i].orig_pa))
				symrdma_iommu_unmap_page(dev, wiova);
		}
		i++;
	}
}

/* ---- 无副作用驻留判定 ---- */

/*
 * VA 对应的物理地址（处理 THP/复合页偏移，(）。
 *
 * follow_page/GUP 对 THP 返回复合头页，page_to_phys(head) 是 2MB/1GB
 * 对齐的大页基址；4KB 页映射必须补 VA 在大页内的偏移，否则同一 THP
 * 内所有页都映射到基址 PA → RDMA 读写错位。
 * 普通页（非复合）偏移为 0。
 */
phys_addr_t symrdma_va_to_pa(struct page *page, unsigned long va)
{
	phys_addr_t pa = page_to_phys(page);

	if (PageCompound(page))
		pa += va & (page_size(page) - 1);
	return pa;
}

/*
 * 仅查询页表判断 VA 是否驻留 (调用者持 mmap 写锁): 不触发缺页、
 * 不分配、不 swap-in。返回持引用的 page 或 NULL (缺失)。
 *
 * 替代方案为何不可用 (实测):
 *   - follow_page: Ubuntu 5.4.0-150 未导出 (modpost undefined)
 *   - get_user_pages_fast: 缺失页会 fallback 到 slow path → 缺页分配
 *     (缺失页被误变驻留, 破坏哨兵初始映射语义) + down_read(mmap_sem)
 *     与写锁自死锁
 */
struct page *symrdma_follow_page_nofault(struct mm_struct *mm,
					unsigned long va)
{
	/* #2 (K-C2): 零页/COW 共享页/只读页被 READ|WRITE 映射
	 * 进 IOMMU → 远端 RDMA Write 写穿全局零页 (全系统污染) / COW 父子
	 * 互踩。本函数增加可写性判定: 非可写 PTE/大页与零页一律视为
	 * "缺失" (返回 NULL) → 哨兵/黑洞, 首访走 REPAIR — GUP FOLL_WRITE
	 * 完成 COW (私有匿名) 或失败 (只读 VMA, fail-closed, 不再静默污
	 * 染 page cache)。与 pin 路径的 FOLL_WRITE 两档策略 (历史) 对
	 * 齐。注: REG_MR 无 access flags, 所有 MR 均双 IOVA (读+写) 导出,
	 * 不存在只读导出形态, 无需按 MR 权限分支。 */
	pgd_t *pgd = pgd_offset(mm, va);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *ptep;
	struct page *page = NULL;

	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return NULL;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		return NULL;
	pud = pud_offset(p4d, va);
	if (pud_none(*pud))
		return NULL;
	if (unlikely(pud_trans_huge(*pud))) {
		if (!pud_write(*pud))
			return NULL;   /* #2: 只读/COW 巨页 → 哨兵 */
		/* 1GB 大页: 同 THP, 返回复合头页 (PA 偏移由
		 * symrdma_va_to_pa 统一处理, 历史 A1) */
		page = pud_page(*pud);
		get_page(page);
		return page;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
		return NULL;
	if (unlikely(pmd_trans_huge(*pmd))) {
		if (!pmd_write(*pmd))
			return NULL;   /* #2: 只读/COW THP → 哨兵 */
		/* THP 大页: 整页驻留 (复合头页, PA 偏移由
		 * symrdma_va_to_pa 统一处理, 历史 A1) */
		page = pmd_page(*pmd);
		get_page(page);
		return page;
	}
	if (!pmd_present(*pmd))
		return NULL;   /* 大页 swap entry / 无映射 */
	ptep = pte_offset_map(pmd, va);
	if (likely(ptep) && pte_present(*ptep) && pte_write(*ptep) &&
	    !is_zero_pfn(pte_pfn(*ptep))) {
		page = pte_page(*ptep);
		if (!pfn_valid(page_to_pfn(page)))
			page = NULL;   /* special/IO 页无 struct page */
		else
			get_page(page);
	}
	if (ptep)
		pte_unmap(ptep);
	return page;
}

/* ----  IOMMU 组粒度 (2MB) 混合映射 ----
 *
 * pages[] 始终为逐页逻辑状态
 * (引擎/G1/notifier 语义不变), groups[] 是映射形态 overlay: 组提升 =
 * 512 逐页映射折叠为单条 2MB 超页映射, 组降级 = 反向展开。降级是纯
 * 映射变换 (不动 pages[]/版本号/orig_pa)。 */

/* PMD 粒度探测结果 */
enum symrdma_group_probe {
	GRP_PROBE_ABSENT = 0,   /* pud_none/pmd_none: 整组 2MB 无映射 */
	GRP_PROBE_HUGE,         /* pmd/pud trans-huge: 整组驻留复合页 */
	GRP_PROBE_TABLE,        /* PTE 表/迁移项/异常: 逐页判定 */
};

/*
 * 组首 VA 的页表顶层形态 (调用者持 mmap 写锁 — 页表遍历与
 * symrdma_follow_page_nofault 同构, 止步于 PMD 层)。
 * follow_page_nofault 单点探测无法区分 "pmd_none (整组无映射)" 与
 * "PTE 表混合形态" (两者都返回 NULL), 而 GRP_ABSENT 提升只接受整组
 * 确无映射的窗口 — A 轴注册吞吐的关键路径 (128GB MAP_NORESERVE 空间
 * 0.2s vs 逐页 11s)。
 * HUGE 返回的 page 为复合头页并持引用 (put_page 由调用方负责)。
 */
static int group_probe(struct mm_struct *mm, unsigned long va,
		       struct page **page_out)
{
	pgd_t *pgd = pgd_offset(mm, va);
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;

	*page_out = NULL;
	if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
		return GRP_PROBE_TABLE;
	p4d = p4d_offset(pgd, va);
	if (p4d_none(*p4d) || unlikely(p4d_bad(*p4d)))
		return GRP_PROBE_TABLE;
	pud = pud_offset(p4d, va);
	if (pud_none(*pud))
		return GRP_PROBE_ABSENT;   /* 整 1GB 窗口无映射 ⊇ 组 */
	if (unlikely(pud_trans_huge(*pud))) {
		struct page *page;

		/* #2: 只读/COW 巨页不提升 — 回退逐页 (判哨兵) */
		if (!pud_write(*pud))
			return GRP_PROBE_TABLE;
		page = pud_page(*pud);

		get_page(page);
		*page_out = page;
		return GRP_PROBE_HUGE;
	}
	pmd = pmd_offset(pud, va);
	if (pmd_none(*pmd))
		return GRP_PROBE_ABSENT;   /* 整 2MB 窗口无映射 */
	if (unlikely(pmd_trans_huge(*pmd))) {
		struct page *page;

		/* #2: 只读/COW THP 不提升 — 回退逐页 (判哨兵) */
		if (!pmd_write(*pmd))
			return GRP_PROBE_TABLE;
		page = pmd_page(*pmd);

		get_page(page);
		*page_out = page;
		return GRP_PROBE_HUGE;
	}
	return GRP_PROBE_TABLE;
}

/*
 * 注册期组提升: 对满 512 页且 2MB 对齐的组 (调用方已验证
 * group_mode + 组首 + 组完整), 探测页表形态并整组映射。
 * 返回 1 = 已提升 (调用方跳过整组); 0 = 不适用 (回退逐页)。
 *
 * 竞态闭合: PMD 探测持 mmap 写锁, 但 rmap 类失效源 (reclaim, 不经
 * mmap_lock) 仍可并发哨兵化组内页 — 提升在 st->lock 内复查全组
 * 512 页状态仍全零 (= RESIDENT, 未被 notifier 触碰); 复查不过 →
 * 回退逐页 (其 G1 raced-adopt 逻辑处理被触碰页)。THP 分裂 (mprotect,
 * 不改 PA) 后状态仍 uniform — 2MB 映射的 PA 连续性与分裂前等价,
 * 提升仍正确; 分裂+迁移会先经 notifier 状态转换 → 复查捕获。
 *
 * 映射用 iommu_map_atomic (GFP_ATOMIC, spinlock 安全 — 全新 IOVA 窗口
 * 的中间级页表分配不可睡眠); 失败回退逐页 (锁外 GFP_KERNEL 重试)。
 * write 域失败时回滚 read 域 2MB, 保持 "全组或无" 原子性 (残留半组
 * 超页会令后续逐页 unmap 撞硬件红线)。GRP_ABSENT 用哨兵/黑洞**区**
 * (2MB order-9 单条映射; 降级后逐页回落单页 sentinel_pa/blackhole_pa,
 * 等值检查保持命中 — 见 symrdma.h 区域注释)。
 */
static int try_map_mr_group(struct symrdma_dev *dev, struct symrdma_mr *mr,
			    struct mm_struct *mm, unsigned long idx)
{
	/* attach 已完成恒非 NULL — 同 map_mr_pages 的 G2 论证 (MR 尚无
	 * idr 条目, 无并发 DEREG/release) */
	struct symrdma_mm_state *st = mr->mm_state;
	unsigned long g, k;
	unsigned long va = mr->va_start + idx * PAGE_SIZE;
	u64 riova = mr->read_iova + idx * PAGE_SIZE;
	u64 wiova = mr->write_iova + idx * PAGE_SIZE;
	struct page *page = NULL;
	phys_addr_t pa = 0;
	bool resident;
	int probe, ret = 1;

	probe = group_probe(mm, va, &page);
	resident = (probe == GRP_PROBE_HUGE);
	if (resident) {
		pa = symrdma_va_to_pa(page, va);
		/* pmd THP: 组首即复合基址 (PMD 窗口本身 2MB 对齐);
		 * PUD THP: 偏移为 2MB 倍数。防御性显式校验 — 不满足按
		 * 逐页处理 (va_to_pa 复合偏移语义不受影响) */
		if (!IS_ALIGNED(pa, SYMRDMA_GROUP_SIZE))
			resident = false;
	}
	if (probe != GRP_PROBE_ABSENT && !resident) {
		if (page)
			put_page(page);
		return 0;   /* PTE 表 — 逐页 */
	}

	spin_lock(&st->lock);
	for (k = 0; k < SYMRDMA_GROUP_PAGES; k++) {
		if (mr->pages[idx + k].read_state != PAGE_RESIDENT ||
		    mr->pages[idx + k].write_state != PAGE_RESIDENT)
			break;   /* notifier 已触碰 — 混合形态, 逐页 */
	}
	if (k < SYMRDMA_GROUP_PAGES) {
		ret = 0;
		goto out_unlock;
	}

	if (resident) {
		if (iommu_map_atomic(dev->iommu_domain, riova, pa,
				     SYMRDMA_GROUP_SIZE,
				     IOMMU_READ | IOMMU_WRITE)) {
			ret = 0;
			goto out_unlock;
		}
		if (iommu_map_atomic(dev->iommu_domain, wiova, pa,
				     SYMRDMA_GROUP_SIZE,
				     IOMMU_READ | IOMMU_WRITE)) {
			iommu_unmap(dev->iommu_domain, riova,
				    SYMRDMA_GROUP_SIZE);
			ret = 0;
			goto out_unlock;
		}
		for (k = 0; k < SYMRDMA_GROUP_PAGES; k++) {
			mr->pages[idx + k].orig_pa = pa + k * PAGE_SIZE;
			mr->pages[idx + k].read_state = PAGE_RESIDENT;
			mr->pages[idx + k].write_state = PAGE_RESIDENT;
		}
		g = idx >> SYMRDMA_GROUP_SHIFT;
		mr->groups[g].base_pa = pa;
		mr->groups[g].state = GRP_RESIDENT;
		atomic64_inc(&dev->stats.huge_resident);
	} else {
		/* 整组缺失: read 2MB → 哨兵区 (只读), write 2MB → 黑洞区
		 * (只写) — 单条超页; pages[] 语义与逐页缺失逐字节一致 */
		if (iommu_map_atomic(dev->iommu_domain, riova,
				     dev->sentinel_region_pa,
				     SYMRDMA_GROUP_SIZE, IOMMU_READ)) {
			ret = 0;
			goto out_unlock;
		}
		if (iommu_map_atomic(dev->iommu_domain, wiova,
				     dev->blackhole_region_pa,
				     SYMRDMA_GROUP_SIZE, IOMMU_WRITE)) {
			iommu_unmap(dev->iommu_domain, riova,
				    SYMRDMA_GROUP_SIZE);
			ret = 0;
			goto out_unlock;
		}
		for (k = 0; k < SYMRDMA_GROUP_PAGES; k++) {
			mr->pages[idx + k].orig_pa = 0;
			mr->pages[idx + k].read_state = PAGE_SENTINEL;
			mr->pages[idx + k].write_state = PAGE_BLACKHOLE;
		}
		g = idx >> SYMRDMA_GROUP_SHIFT;
		mr->groups[g].base_pa = 0;
		mr->groups[g].state = GRP_ABSENT;
		atomic64_inc(&dev->stats.huge_absent);
	}
out_unlock:
	spin_unlock(&st->lock);
	if (page)
		put_page(page);
	return ret;
}

/*
 * 组降级: 2MB 超页 → 512 逐页映射 (调用者持 st->lock)。
 * 纯映射变换: 不动 pages[] 状态/版本号/orig_pa — 提升时写入的语义在
 * 逐页形态下继续成立 (GRP_RESIDENT 组全 RESIDENT; GRP_ABSENT 组全
 * SENTINEL/BLACKHOLE)。降级后 state=GRP_NONE, 逐页路径接管。
 *
 * 顺序: unmap_fast (2MB 一次到位, gather 累积不 flush) → 逐页 map_atomic
 * 重建 → iotlb_sync。窗口期 stale IOTLB 仍翻译旧映射 — 降级两侧映射
 * 目标内容等价 (RESIDENT: 同基址逐页展开; ABSENT: 同魔数哨兵/同吸收
 * 黑洞), 无可见性差异。
 *
 * 逐页重建目标: RESIDENT 组取 base_pa + k*4K; ABSENT 组统一单页
 * 哨兵/黑洞 (非区域基址 — 与逐页路径同 PA, unmap_mr_pages_touched
 * 的按值等值检查对降级页保持命中)。
 *
 * 失败兜底 (仅新中间级 GFP_ATOMIC 分配可致, 窗口内 L1 已被 unmap
 * 释放时): fail-closed — read 侧哨兵只读 + 状态置缺失语义 + 版本翻转
 * (RESIDENT→SENTINEL 真状态转换, 奇→偶; ABSENT 组本就偶数不翻转)
 * → 引擎魔数检测 → REPAIR 兑底; write 侧黑洞只写 (write 路径无
 * seqlock, 状态同步置 BLACKHOLE 防语义漂移)。双失败留无映射
 * (硬 access_err, 不可静默)。
 */
int symrdma_group_demote_locked(struct symrdma_dev *dev,
				struct symrdma_mr *mr, unsigned long grp)
{
	struct iommu_iotlb_gather g;
	unsigned long i, base = grp * SYMRDMA_GROUP_PAGES;
	u64 riova = mr->read_iova + base * PAGE_SIZE;
	u64 wiova = mr->write_iova + base * PAGE_SIZE;
	bool resident = mr->groups[grp].state == GRP_RESIDENT;
	/* L19 fail-closed 注入 (demote_fail_grp 模块参数): 该组首页
	 * 重映射跳过真实调用、直接模拟 GFP_ATOMIC 失败 → 走下方兜底
	 * 分支 (哨兵/黑洞 + 状态翻转), 使不可自然触发的降级失败路径
	 * 可被 test_group_mapping 实测验证 (仅测试, 默认 -1 关) */
	bool inject = dev->demote_fail_grp == (int)grp;
	phys_addr_t rpa = resident ? mr->groups[grp].base_pa
				  : dev->sentinel_pa;
	phys_addr_t wpa = resident ? mr->groups[grp].base_pa
				  : dev->blackhole_pa;
	int rprot = resident ? (IOMMU_READ | IOMMU_WRITE) : IOMMU_READ;
	int wprot = resident ? (IOMMU_READ | IOMMU_WRITE) : IOMMU_WRITE;

	mr->groups[grp].state = GRP_NONE;
	mr->groups[grp].base_pa = 0;

	/* read 域 */
	iommu_iotlb_gather_init(&g);
	iommu_unmap_fast(dev->iommu_domain, riova, SYMRDMA_GROUP_SIZE, &g);
	for (i = 0; i < SYMRDMA_GROUP_PAGES; i++) {
		u64 iov = riova + i * PAGE_SIZE;

		if (inject && i == 0) {
			atomic64_inc(&dev->stats.demote_fail);
			if (!iommu_map_atomic(dev->iommu_domain, iov,
					      dev->sentinel_pa,
					      PAGE_SIZE, IOMMU_READ)) {
				mr->pages[base + i].read_state = PAGE_SENTINEL;
				mr->pages[base + i].orig_pa = 0;
				if (resident)
					symrdma_version_inc(mr, base + i);
			}
			continue;
		}
		if (iommu_map_atomic(dev->iommu_domain, iov,
				     rpa + (resident ? i * PAGE_SIZE : 0),
				     PAGE_SIZE, rprot)) {
			atomic64_inc(&dev->stats.demote_fail);
			if (!iommu_map_atomic(dev->iommu_domain, iov,
					      dev->sentinel_pa,
					      PAGE_SIZE, IOMMU_READ)) {
				mr->pages[base + i].read_state = PAGE_SENTINEL;
				mr->pages[base + i].orig_pa = 0;
				if (resident)
					symrdma_version_inc(mr, base + i);
			}
		}
	}
	if (g.pgsize)
		iommu_iotlb_sync(dev->iommu_domain, &g);

	/* write 域 (独立 gather 周期 — read/write IOVA 相距 32GB,
	 * 同一 gather 的离散区间会隐式 sync, 约束 ②) */
	iommu_iotlb_gather_init(&g);
	iommu_unmap_fast(dev->iommu_domain, wiova, SYMRDMA_GROUP_SIZE, &g);
	for (i = 0; i < SYMRDMA_GROUP_PAGES; i++) {
		u64 iov = wiova + i * PAGE_SIZE;

		if (inject && i == 0) {
			atomic64_inc(&dev->stats.demote_fail);
			if (!iommu_map_atomic(dev->iommu_domain, iov,
					      dev->blackhole_pa,
					      PAGE_SIZE, IOMMU_WRITE))
				mr->pages[base + i].write_state =
					PAGE_BLACKHOLE;
			continue;
		}
		if (iommu_map_atomic(dev->iommu_domain, iov,
				     wpa + (resident ? i * PAGE_SIZE : 0),
				     PAGE_SIZE, wprot)) {
			atomic64_inc(&dev->stats.demote_fail);
			if (!iommu_map_atomic(dev->iommu_domain, iov,
					      dev->blackhole_pa,
					      PAGE_SIZE, IOMMU_WRITE))
				mr->pages[base + i].write_state =
					PAGE_BLACKHOLE;
		}
	}
	if (g.pgsize)
		iommu_iotlb_sync(dev->iommu_domain, &g);

	atomic64_inc(&dev->stats.group_demotes);
	return 0;
}

/*
 * 组感知前置: 页所在组若为超页形态, 先降级 — 硬件红线:
 * 逐页 unmap 撞超页 PTE 会静默整片解除 512 页映射 (状态机崩坏),
 * 故这是一切逐页转换路径 (notifier 循环 / remap_to_* / 修复) 的统一
 * 入口。幂等: GRP_NONE 无操作。调用者持 st->lock。
 */
void symrdma_group_ensure_split_locked(struct symrdma_dev *dev,
				       struct symrdma_mr *mr,
				       unsigned long page_idx)
{
	unsigned long grp;

	if (!mr->groups || page_idx >= mr->npages)
		return;
	grp = page_idx >> SYMRDMA_GROUP_SHIFT;
	if (mr->groups[grp].state != GRP_NONE)
		symrdma_group_demote_locked(dev, mr, grp);
}

/* 区间形态 (remap_to_sentinel/blackhole 的 [start,end] 闭区间):
 * 覆盖的每个提升组先降级。调用者持 st->lock。 */
void symrdma_group_ensure_split_range_locked(struct symrdma_dev *dev,
					     struct symrdma_mr *mr,
					     unsigned long start_idx,
					     unsigned long end_idx)
{
	unsigned long grp, last;

	if (!mr->groups || start_idx >= mr->npages)
		return;
	if (end_idx >= mr->npages)
		end_idx = mr->npages - 1;
	if (start_idx > end_idx)
		return;
	last = end_idx >> SYMRDMA_GROUP_SHIFT;
	for (grp = start_idx >> SYMRDMA_GROUP_SHIFT; grp <= last; grp++)
		if (mr->groups[grp].state != GRP_NONE)
			symrdma_group_demote_locked(dev, mr, grp);
}

/* ---- 双 IOVA 映射: MR 注册时的初始映射 ---- */

/*
 * 哨兵页映射权限: IOMMU_READ (只读)。
 *
 * 论文图 4(b): 哨兵页只服务 DMA 读 (返回魔数); 缺失页的写属于黑洞。
 * 若映射为 RW, 任何经读 IOVA 的 DMA 写 (identity_mtt_write_offset 未配
 * 32GB 的写区域 MR / 应用误用读 rkey 写 / 引擎重写盲区) 会把数据写进
 * 哨兵页本身 — 全局唯一单页被污染后, 所有 MR 的哨兵检测失效 (读到写
 * 入数据而非 0xdeadbeef, 换出页被当驻留 → 数据损坏且无报错; 实测
 * host-a/8 因 write_offset=0 污染为 0x11111111, L1/L3/L5 全线失败)。
 * 只读后, 该类写被 IOMMU 丢弃 (posted write 无响应, RC 传输层无感知),
 * 观测语义等价黑洞吸收, 哨兵永不污染。
 */

/*
 * 遍历 mm 的页表，为 MR 建立双 IOVA 映射。
 *
 * 对每个页面：
 *   - 驻留: Read IOVA → 真实 PA (IOMMU_READ|IOMMU_WRITE)
 *           Write IOVA → 真实 PA (IOMMU_READ|IOMMU_WRITE)
 *   - 缺失: Read IOVA → 哨兵页 (IOMMU_READ, 见上文权限说明)
 *           Write IOVA → 黑洞页 (IOMMU_WRITE)
 *
 * 调用者须持 mmap_write_lock(mm) (symrdma_reg_mr 持有): 阻止遍历
 * 期间换出造成 stale PA。notifier 已先附加 (mn_attach 在遍历之前),
 * 遍历前的换出由回调处理、遍历按当前真实状态覆盖映射 。
 *
 * 论文 §4.1: 这是 MR 注册优化，替代传统的 pre-pinning。
 * 论文使用 2GB MTT identity mapping + 4KB IOMMU 粒度。
 *
 * G1  — 与 notifier 的注册期竞态: attach 后 pages[] 全零
 * (= PAGE_RESIDENT), 遍历期间 rmap 类失效源 (reclaim 等, 不经
 * mmap_lock, 持写锁也无法排除) 可对尚未遍历的页先行哨兵化; 随后
 * 遍历的 iommu_map 撞 "PTE already set" (-EBUSY) → REG_MR 失败 →
 * 旧错误路径只回滚自映射前缀, notifier 的 PTE 永久遗留 (泄漏源头,
 * 实测同 VA 重注册连续失败)。处置:
 *   ① 逐页预检 (st->lock 内): 状态已被 notifier 处理 (SENTINEL/
 *      BLACKHOLE) 的页直接采纳其映射 (含 version_inc 的奇偶语义 —
 *      由 Step 4 version_init 按最终状态重初始化闭合);
 *   ② map 失败复查 (st->lock 内 + 哨兵/黑洞 PA 验证): notifier 在
 *      预检与映射之间的窗口内抢先 → 采纳, 不再令 REG_MR 失败;
 *   ③ 真冲突 (跨进程 identity IOVA 撞车/历史遗留 PTE) 保持响亮
 *      失败, 由调用方 err 路径 detach 后全量清理本 MR 的 PTE
 *      (symrdma_unmap_mr_pages_touched)。
 * 注: 映射本体在锁外执行 — 新 VA 区间的 L1 页表缺失时 iommu_map
 * 会 GFP_KERNEL 分配 (不可睡眠上下文限制, notifier 回调内同理由
 * "相邻页保表" 论证豁免; 此处大 MR 新区间不满足, 不可持锁映射)。
 */
int symrdma_map_mr_pages(struct symrdma_dev *dev, struct symrdma_mr *mr,
			 struct mm_struct *mm)
{
	unsigned long va, end;
	/* attach 已完成, 恒非 NULL; G2: 此处裸读安全 — MR 尚无
	 * idr 条目 (assign_mr_id 在 REG_MR ioctl 内、reg 返回后才发生),
	 * 属主进程存活 (其线程正执行本调用) ⇒ 无并发 DEREG/release detach */
	struct symrdma_mm_state *st = mr->mm_state;
	struct page *page;
	phys_addr_t pa;
	int ret;
	/* 组模式 — groups[] 在位且 read IOVA 2MB 对齐 (write 侧
	 * 常差 32GB, %2MB==0 随之对齐); 头尾残组/不对齐 MR 恒逐页
	 * (与现状一致, 逐页体逐字节保持) */
	bool group_mode = mr->groups &&
			  IS_ALIGNED(mr->read_iova, SYMRDMA_GROUP_SIZE);

	va  = mr->va_start;
	end = mr->va_end;

	pr_info("symrdma: 映射 VA 0x%lx-0x%lx (%lu 页) → 双 IOVA\n",
		va, end, mr->npages);
	pr_info("symrdma:   Read  IOVA base: 0x%llx\n", mr->read_iova);
	pr_info("symrdma:   Write IOVA base: 0x%llx\n", mr->write_iova);

	for (; va < end; va += PAGE_SIZE) {
		unsigned long idx = (va - mr->va_start) / PAGE_SIZE;
		u64 riova = mr->read_iova + idx * PAGE_SIZE;
		u64 wiova = mr->write_iova + idx * PAGE_SIZE;
		bool raced, ours_riova = false, ours_wiova = false;

		/* 组首快速路径: 满组 + 组首对齐时先试整组提升 —
		 * THP/PUD 驻留 → 单条 2MB 真实映射 (GRP_RESIDENT);
		 * pmd_none 整组缺失 → 单条 2MB 哨兵区/黑洞区 (GRP_ABSENT)。
		 * 不适用 (PTE 表混合/对齐或分配失败/notifier 竞态哨兵化)
		 * 返回 0, 落入下方逐页路径 (G1 语义逐字节保持)。 */
		if (group_mode &&
		    (idx & (SYMRDMA_GROUP_PAGES - 1)) == 0 &&
		    idx + SYMRDMA_GROUP_PAGES <= mr->npages &&
		    try_map_mr_group(dev, mr, mm, idx) > 0) {
			/* 组尾 — 循环自增 1 页即下一组首 */
			va += SYMRDMA_GROUP_SIZE - PAGE_SIZE;
			continue;
		}

		/* 驻留判定: 无副作用 PTE 查询 (见函数注释) */
		page = symrdma_follow_page_nofault(mm, va);
		pa = page ? symrdma_va_to_pa(page, va) : 0;

		/* G1 ①: 锁内预检 — notifier 已处理此页则采纳 */
		spin_lock(&st->lock);
		raced = mr->pages[idx].read_state != PAGE_RESIDENT;
		spin_unlock(&st->lock);
		if (raced) {
			if (page)
				put_page(page);
			continue;
		}

		if (!page) {
			/* 页面缺失 — Read IOVA → 哨兵 (只读), Write IOVA → 黑洞 */
			mr->pages[idx].orig_pa = 0;
			mr->pages[idx].read_state = PAGE_SENTINEL;
			mr->pages[idx].write_state = PAGE_BLACKHOLE;

			ret = symrdma_iommu_map_page(dev, riova,
						     dev->sentinel_pa,
						     IOMMU_READ);
			if (ret)
				goto err_check;
			ours_riova = true;

			ret = symrdma_iommu_map_page(dev, wiova,
						     dev->blackhole_pa,
						     IOMMU_WRITE);
			if (ret)
				goto err_check;
			ours_wiova = true;
		} else {
			/* 页面驻留 — 双映射到真实 PA (大页偏移由
			 * symrdma_va_to_pa 处理, 历史 A1) */
			mr->pages[idx].orig_pa = pa;
			mr->pages[idx].read_state = PAGE_RESIDENT;
			mr->pages[idx].write_state = PAGE_RESIDENT;

			ret = symrdma_iommu_map_page(dev, riova, pa,
						     IOMMU_READ | IOMMU_WRITE);
			if (ret)
				goto err_check;
			ours_riova = true;

			/* 写区域驻留映射 READ|WRITE: write-only MR (MTT=VA+32GB)
			 * 的 SEND 源数据也经 IOMMU 读出 (perftest 实测) */
			ret = symrdma_iommu_map_page(dev, wiova, pa,
						     IOMMU_READ | IOMMU_WRITE);
			if (ret)
				goto err_check;
			ours_wiova = true;

			put_page(page);
			page = NULL;
		}
		continue;

err_check:
		/* G1 ②: 失败复查 — notifier 可在预检与映射之间抢先哨兵化此页
		 * (其 unmap 会撤掉本方已建立的 PTE 后统一重映射哨兵/黑洞)。
		 * 锁内复查状态 + 按值验证哨兵/黑洞映射确实在位 (排除"真冲突
		 * 但 notifier 恰好也碰了此页且其 map 失败"的残留旧 PTE 形态 —
		 * notifier 不检查 map 返回值, 状态可能虚置 SENTINEL), 在位才
		 * 采纳 (此时本方 PTE 已被 notifier unmap 撤除, 无需回滚);
		 * 否则按真冲突响亮失败, 仅回收本方已建立的 PTE。 */
		spin_lock(&st->lock);
		raced = mr->pages[idx].read_state != PAGE_RESIDENT;
		spin_unlock(&st->lock);
		if (raced &&
		    iommu_iova_to_phys(dev->iommu_domain, riova) ==
						    dev->sentinel_pa &&
		    iommu_iova_to_phys(dev->iommu_domain, wiova) ==
						    dev->blackhole_pa) {
			if (page)
				put_page(page);
			continue;
		}
		if (ours_riova)
			symrdma_iommu_unmap_page(dev, riova);
		if (ours_wiova)
			symrdma_iommu_unmap_page(dev, wiova);
		if (page)
			put_page(page);
		pr_err("symrdma: 映射失败 (ret=%d) idx=%lu, 本方 PTE 已回收,\n"
		       "由注册错误路径全量清理\n", ret, idx);
		return ret;
	}

	pr_info("symrdma: 双 IOVA 映射完成: %lu 页\n", mr->npages);
	return 0;
}

/* ---- 运行时重映射 (MMU notifier 或修复路径调用) ---- */

/* 哨兵页只读映射 (IOMMU_READ): 防止经读 IOVA 的 DMA 写污染全局哨兵页
 * (详见 symrdma_map_mr_pages 上方权限说明)。 */
void symrdma_remap_to_sentinel(struct symrdma_dev *dev,
			       struct symrdma_mr *mr,
			       unsigned long start_idx,
			       unsigned long end_idx)
{
	unsigned long i;

	/* 组感知前置 — 区间覆盖的提升组先降级 (硬件红线;
	 * 调用方持 st->lock — REMAP ioctl / notifier / pin 路径均然) */
	symrdma_group_ensure_split_range_locked(dev, mr, start_idx, end_idx);

	for (i = start_idx; i <= end_idx && i < mr->npages; i++) {
		u64 riova = mr->read_iova + i * PAGE_SIZE;
		symrdma_iommu_unmap_page(dev, riova);
		symrdma_iommu_map_page(dev, riova, dev->sentinel_pa,
				       IOMMU_READ);
		mr->pages[i].read_state = PAGE_SENTINEL;
		mr->pages[i].orig_pa = 0;
	}
}

void symrdma_remap_to_blackhole(struct symrdma_dev *dev,
				struct symrdma_mr *mr,
				unsigned long start_idx,
				unsigned long end_idx)
{
	unsigned long i;

	/* 组感知前置 (同 remap_to_sentinel) */
	symrdma_group_ensure_split_range_locked(dev, mr, start_idx, end_idx);

	for (i = start_idx; i <= end_idx && i < mr->npages; i++) {
		u64 wiova = mr->write_iova + i * PAGE_SIZE;
		symrdma_iommu_unmap_page(dev, wiova);
		symrdma_iommu_map_page(dev, wiova, dev->blackhole_pa,
				       IOMMU_WRITE);
		mr->pages[i].write_state = PAGE_BLACKHOLE;
	}
}

/*
 * 将单个页的两个 IOVA 都重映射到真实 PA。
 * 用于修复路径和 ioctl(REMAP, REAL)。
 *
 * 原实现 void + 忽略 iommu_map 返回值 — unmap 后
 * map 失败会遗留无映射 IOVA 却发布 RESIDENT+奇版本 → seqlock 接受
 * 垃圾数据。改为 fail-closed: 任一 map 失败即回滚到哨兵/黑洞态
 * (状态与映射一致), 返回 -EIO, 调用方不得发布版本。
 * 返回: 0 成功, -EIO 映射失败 (状态已回滚)
 */
int symrdma_remap_to_real(struct symrdma_dev *dev,
			  struct symrdma_mr *mr,
			  unsigned long page_idx,
			  phys_addr_t pa)
{
	u64 riova = mr->read_iova + page_idx * PAGE_SIZE;
	u64 wiova = mr->write_iova + page_idx * PAGE_SIZE;
	int ret;

	/* 组感知前置 — 页所在组若为超页先降级 (单页 real 重映射
	 * 的逐页 unmap 撞超页 PTE 会静默整片解除) */
	symrdma_group_ensure_split_locked(dev, mr, page_idx);

	symrdma_iommu_unmap_page(dev, riova);
	ret = symrdma_iommu_map_page(dev, riova, pa, IOMMU_READ | IOMMU_WRITE);
	if (ret)
		goto err_rio;

	symrdma_iommu_unmap_page(dev, wiova);
	ret = symrdma_iommu_map_page(dev, wiova, pa, IOMMU_READ | IOMMU_WRITE);
	if (ret)
		goto err_wio;

	mr->pages[page_idx].read_state = PAGE_RESIDENT;
	mr->pages[page_idx].write_state = PAGE_RESIDENT;
	mr->pages[page_idx].orig_pa = pa;
	return 0;

err_wio:
	symrdma_iommu_unmap_page(dev, wiova);
err_rio:
	/* 回滚: 映射与状态保持一致 (哨兵/黑洞), 调用方不发布版本 */
	symrdma_iommu_map_page(dev, riova, dev->sentinel_pa, IOMMU_READ);
	symrdma_iommu_map_page(dev, wiova, dev->blackhole_pa, IOMMU_WRITE);
	mr->pages[page_idx].read_state = PAGE_SENTINEL;
	mr->pages[page_idx].write_state = PAGE_BLACKHOLE;
	mr->pages[page_idx].orig_pa = 0;
	return -EIO;
}

/* ---- READ_IOVA: Level 1 验证核心接口 ---- */

/*
 * 通过 IOMMU 页表将 IOVA 翻译为物理地址，然后读取数据。
 *
 * 这是 Level 1 验证的核心: 不需要 RDMA 网卡即可验证 IOMMU 映射正确性。
 * 原理: iommu_iova_to_phys() 查询 IOMMU 页表，这张表正是 RDMA NIC 做 DMA
 * 时硬件遍历的同一张表。此处读到的结果即 NIC 会读到的结果。
 *
 * 返回: 0 成功 (out 中为读取的 4 字节), -EFAULT IOVA 无映射
 */
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

	/* 减法形式, 防 offset 接近 SIZE_MAX 时加法回绕 */
	if (offset > PAGE_SIZE - sizeof(u32))
		return -EINVAL;

	/* 组感知翻译 — 5.11 intel_iommu_iova_to_phys 对 2MB 超页
	 * PTE 返回的是超页基址 (组内偏移丢失, 与 NIC 硬件行为不同);
	 * 组提升 (GRP_RESIDENT) 时按 base_pa + 组内偏移自行翻译, 使本
	 * ioctl 亦即 NIC 视角。GRP_ABSENT (哨兵/黑洞超页) 全组同页, 基址
	 * 读取即为正确值。GRP_NONE 仍走 iova_to_phys (逐页 PTE 无歧义)。
	 * 组状态在 st->lock 下读 — 与降级/提升串行化 (demote 期间不快照)。 */
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
				pg = mr->npages;   /* 越界 → 走回退 */
			if (pg < mr->npages &&
			    mr->groups[pg >> SYMRDMA_GROUP_SHIFT].state ==
					GRP_RESIDENT) {
				pa = mr->groups[pg >> SYMRDMA_GROUP_SHIFT].base_pa +
				    (iova & (SYMRDMA_GROUP_SIZE - 1));
				promoted = true;
			}
		}
		spin_unlock(&st->lock);
		symrdma_mm_state_put(st);
	}
	if (!promoted) {
		pa = iommu_iova_to_phys(dev->iommu_domain, iova);
		if (!pa) {
			pr_info("symrdma: READ_IOVA 0x%llx → 无映射\n", iova);
			return -EFAULT;
		}
	}

	/*
	 * 将物理地址映射到内核虚拟地址空间。
	 * 哨兵/黑洞页和用户页通常在直接映射区域 (lowmem)，
	 * 可以使用 phys_to_virt。对于高内存页使用 pfn_to_kaddr。
	 */
	if (pfn_valid(PHYS_PFN(pa))) {
		page = pfn_to_page(PHYS_PFN(pa));
		vaddr = kmap_atomic(page);
		*out = *(u32 *)(vaddr + offset);
		kunmap_atomic(vaddr);
	} else {
		/* 回退: 尝试 phys_to_virt (仅对直接映射有效) */
		vaddr = phys_to_virt(pa);
		*out = *(u32 *)(vaddr + offset);
	}

	return 0;
}

/* ---- REPAIR: 换入修复 ---- */

/* R4 重构: GUP "fast→slow × 2 flags" 公共策略 (历史 单点化 —
 * 原 symrdma_repair_page 单页四连 GUP 与 symrdma_pin.c pin_gup_try
 * 整段两档两份手写收敛于此)。
 *
 * 两档 flags: FOLL_WRITE 优先 — 无写标志时从未写过的匿名页返回全局
 * zero_page, write_iova(RW) 映射零页 → 远端 RDMA Write 写穿全局零页
 * (全系统污染); FOLL_WRITE 触发 COW 分配真实私有页 (全零数据语义不变)。
 * 失败 (只读 VMA 的纯读修复/pin 场景) 回退无写标志: 此类 MR 无 wkey
 * (REMOTE_WRITE 需 LOCAL_WRITE → 可写 VMA), 不存在 DMA 写路径,
 * zero_page/pagecache 页映射只读安全。
 * 每档内部: fast gup → slow path (处理 swap cache 等边界情况;
 * 内部 down_read mmap_lock — 调用方必须不持 mmap 锁,
 * 死锁分析见 symrdma_repair_page)。
 *
 * whole_span (pin 语义): 部分成功整段放弃 — 释放已 pin 页后重试/
 * 返回, pin 结果不允许残缺段 (symrdma_pin_range 要求整段同时生效)。
 * whole_span=false (修复单页语义): 直接返回最后一次 GUP 的返回值
 * (nr=1 时无部分成功形态, 与原逐级回退逐字节等价)。
 *
 * 返回: nr (全成功), 0..nr-1 (whole_span=false 部分成功) 或负错误码。 */
int symrdma_gup_write_first(unsigned long va, unsigned long nr,
			    struct page **pages, bool whole_span)
{
	unsigned long i;
	int pass, r = -EFAULT;

	for (pass = 0; pass < 2; pass++) {
		unsigned int flags = pass ? 0 : FOLL_WRITE;

		r = get_user_pages_fast(va, nr, flags, pages);
		if (r == nr)
			return r;
		if (r > 0 && whole_span) {
			/* pin 必须 whole-span: 部分成功整段放弃 */
			for (i = 0; i < r; i++)
				put_page(pages[i]);
		}
		/* 5.x 的 get_user_pages() 要求调用者持
		 * mmap 锁 (内部 mmap_assert_locked), 锁外调用与 munmap/
		 * mremap 竞态遍历 VMA (UAF, lockdep 直接告警)。改用
		 * unlocked 变体: 内部自取/自放锁, 语义与作者意图一致。 */
		r = get_user_pages_unlocked(va, nr, pages, flags);
		if (r == nr)
			return r;
		if (r > 0 && whole_span) {
			for (i = 0; i < r; i++)
				put_page(pages[i]);
		}
	}
	return r;
}

/*
 * 重新解析用户 VA 的当前物理页，如果已驻留则重映射两个 IOVA。
 *
 * 论文 §4.1 "Lazy State Synchronization on Swap-in":
 *   IOMMU 可能仍然指向哨兵页，第一次 RDMA 访问检测到魔数，
 *   触发修复路径（此函数），更新 IOMMU 映射为真实 PA。
 *
 * 修复要点:
 *   - 不使用 FOLL_WRITE: 我们只需要读 PA，不需要写权限
 *   - fast gup 失败时回退到 slow path (get_user_pages)，处理 swap cache 中的页面
 *   - 全程不持 mmap 锁: gup_fast 缺失页会 fallback 到 slow
 *     path (内部 down_read mmap_sem)，持锁调用死锁 (见函数体注释)
 *   - 版本号: (cur & ~1U) + 1 — 缺失 (偶数) → 下一个奇数 (翻转);
 *     驻留 (奇数) → 恒等 (修复不改变状态, 假阳性场景, 无需翻转)
 *
 * 返回: 0 修复成功, -EAGAIN 页面仍未驻留
 */
int symrdma_repair_page(struct symrdma_dev *dev, struct symrdma_mr *mr,
			unsigned long page_idx)
{
	unsigned long va = mr->va_start + page_idx * PAGE_SIZE;
	struct symrdma_mm_state *st;
	struct page *page = NULL;
	phys_addr_t pa;
	u32 new_ver_out = 0;
	int ret = 0;

	if (page_idx >= mr->npages)
		return -EINVAL;

	pr_info("symrdma: 尝试修复 page[%lu] VA=0x%lx\n", page_idx, va);

	if (!mr->mm) {
		pr_err("symrdma: 修复 page[%lu] 失败: mr->mm 为 NULL\n", page_idx);
		return -EINVAL;
	}

	/*
	 * 全程不持 mmap 锁: gup_fast 失败会 fallback 到 slow
	 * path (get_user_pages 内部 down_read mmap_sem) — 持锁调用
	 * 要么自死锁 (写锁) 要么递归读 (有 writer 排队时死锁)。
	 * gup 自带同步; 重映射与 notifier 的竞态由惰性修复语义兜底。
	 *
	 * Step 1: 优先带 FOLL_WRITE 的 gup (历史): 无写标志时
	 * 从未写过的匿名页返回全局 zero_page — write_iova(RW) 映射到
	 * zero_page PA 后, 远端 RDMA Write 会 DMA 写穿全局零页 (全系统
	 * 污染)。FOLL_WRITE 触发 COW 分配真实私有页 (全零数据语义不变)。
	 * REMOTE_WRITE MR 必有 LOCAL_WRITE → VMA 可写 → 可成功。
	 * 失败 (只读 VMA 的纯读修复场景) 回退无写标志: 此类 MR 无 wkey
	 * (REMOTE_WRITE 需 LOCAL_WRITE → 可写 VMA), 不存在 DMA 写路径,
	 * zero_page/pagecache 页映射只读安全。
	 * 页面可能在进程页表中不可见 (PTE 已清除)，
	 * 但物理页仍在 swap cache 中。
	 * R4: 两档四连 GUP 收敛至 symrdma_gup_write_first (策略/注释
	 * 随迁; 单页 = nr=1 + whole_span=false, 调用序列逐字节不变)。
	 */
	ret = symrdma_gup_write_first(va, 1, &page, false);
	if (ret < 1) {
		atomic64_inc(&dev->stats.repair_fail);
		pr_info("symrdma: 修复 page[%lu] 失败: gup=%d\n", page_idx, ret);
		return -EAGAIN;
	}

	/* Step 3+4: 重映射 + 版本翻转，与 notifier 同锁串行化 (历史 A8:
	 * notifier 的 version_inc/状态变更持同一把 st->lock，消除
	 * 读-改-写竞态与中间态窗口)。GUP 阶段不持锁 (可睡眠)。
	 * 大页偏移由 symrdma_va_to_pa 处理 (历史 A1)。
	 * G1: 所有权复查 — mr->mm_state == NULL 即已拆卸
	 * (DEREG/release 的 detach 同锁置 NULL), 拆卸路径将/已 unmap 全部
	 * PTE, 此处再映射真实 PA 会遗留 PTE (G1 泄漏面 ②); 旧实现
	 * "mm_state 为 NULL 时直接更新"正是该泄漏形态, 改为 fail-closed。 */
	pa = symrdma_va_to_pa(page, va);
	/* G2: st 临时引用替代裸读 — GUP (可睡眠, ms 级) 与加锁
	 * 之间 DEREG 可完成 unlink + kfree_rcu(st), 原裸读窗口内加锁即 UAF;
	 * 引用闭合 (mm_state_lock 内原子 get, 拆卸后 NULL → fail-closed)。
	 * G1: 所有权复查 — mr->mm_state == NULL 即已拆卸
	 * (DEREG/release 的 detach 同锁置 NULL), 拆卸路径将/已 unmap 全部
	 * PTE, 此处再映射真实 PA 会遗留 PTE (G1 泄漏面 ②); 旧实现
	 * "mm_state 为 NULL 时直接更新"正是该泄漏形态, 改为 fail-closed。 */
	st = symrdma_mm_state_get(mr);
	if (!st) {
		put_page(page);
		pr_info("symrdma: 修复 page[%lu] 拒绝: MR 已拆卸\n", page_idx);
		return -ENOENT;
	}
	spin_lock(&st->lock);
	if (mr->mm_state != st) {
		/* 锁内复查: 并发 DEREG 的 detach 在同锁下置 NULL — 已接管 */
		spin_unlock(&st->lock);
		put_page(page);
		symrdma_mm_state_put(st);
		pr_info("symrdma: 修复 page[%lu] 拒绝: 并发拆卸\n", page_idx);
		return -ENOENT;
	}
	/* remap 失败 → 状态已回滚哨兵/黑洞, 不得发布
	 * RESIDENT/奇版本 (seqlock 会接受垃圾数据) */
	if (symrdma_remap_to_real(dev, mr, page_idx, pa)) {
		spin_unlock(&st->lock);
		symrdma_mm_state_put(st);
		put_page(page);
		atomic64_inc(&dev->stats.repair_fail);
		pr_info("symrdma: 修复 page[%lu] 失败: IOMMU 重映射\n", page_idx);
		return -EIO;
	}
	mr->pages[page_idx].probe_fail = 0;   /* v0.26.0: 恢复可探测态 */
	if (mr->version_table || mr->version_pages) {
		u32 cur = symrdma_version_read(mr, page_idx);
		u32 new_ver = (cur & ~1U) + 1;
		symrdma_version_set(mr, page_idx, new_ver);
		new_ver_out = new_ver;
	}
	spin_unlock(&st->lock);
	symrdma_mm_state_put(st);

	put_page(page);

	atomic64_inc(&dev->stats.repair_ok);
	pr_info("symrdma: 修复 page[%lu]: VA 0x%lx → PA 0x%llx ver=%u\n",
		page_idx, va, (u64)pa, new_ver_out);

	return 0;
}

/* ---- REPAIR_RANGE: 区间批量修复 (改进方向) ----
 *
 *  owner 侧逐页 ioctl REPAIR 实测 ~7-10µs/页 (ctlbench/A.2 同口
 * 径), 大消息 (≥512KB) race 吞吐被 ODP 反超 (0.32-0.78×): 主导开销是
 * 逐页 remap 的 strict unmap flush (每页 2 次, iommu_unmap 每次调用末尾
 * 一次 iommu_iotlb_sync)。5.11 提供 iommu_unmap_fast (已导出) +
 * iommu_iotlb_gather/sync (static inline): unmap 只累积 gather, flush
 * 集中到段尾一次 — flush 开销从 2 次/页降到 2 次/块。
 *
 * 正确性设计 (三个不能省的约束):
 *   ① 逐页 unmap_fast+map 交错, 不能整段 unmap 后再 map — intel unmap
 *      会释放空中间级页表 (gather->freelist), 整段窗口内 L1 可能全空,
 *      后续 iommu_map 需重分配 (GFP_KERNEL → spinlock 内睡眠 BUG);
 *      交错形态任一时刻至多一页未映射, 中间级永不空 (MR 每页恒有映射:
 *      驻留=真实/缺失=哨兵或黑洞)。
 *   ② read/write IOVA 域相距 32GB (SYMRDMA_MR_WRITE_OFFSET),
 *      iommu_iotlb_gather_add_page 对离散区间会隐式 sync — 必须分两个
 *      gather 周期 (先全部 read 后全部 write), 否则退化回逐页 flush。
 *   ③ sync 必须在锁内、版本翻转之前 — 写路径若先发布版本 (奇数=驻留)
 *      后 flush, 陈旧 IOTLB 会把远端写投递到旧黑洞/真实映射 (黑洞吸收
 *      = 静默丢失, 版本却已通过), 哨兵魔数检查救不了写路径。
 *
 * 块大小权衡: st->lock 持锁时长 (notifier 等待上界 — 换出/迁移回调
 * 在此自旋) vs flush 摊薄 (2 次/块)。
 *
 *  (段批量化 + 组提升):
 *   - 块大小 16 → SYMRDMA_REPAIR_SEG=128: 段级整段 unmap_fast (1 walk)
 *     + iommu_map_sg_atomic run 合并映射 (连续 run 单条目 — 5.11
 *     __iommu_map 按条目 size 选最大合法页尺寸, 511 页内 run 为 4KB
 *     PTE 形态由 intel __domain_mapping 单次页表遍历连填) + 段尾单次
 *     sync; 持锁上界 ~2×128 原子映射 + 2 flush ≈ 100-200µs (与 16
 *     页块同量级), flush 摊薄到 2/128。
 *   - 整组 (512 页) pa 连续且基址 2MB 对齐 → group_promote_repair_
 *     locked 单条 2MB 超页 (Phase 2 组粒度模型在修复路径的延伸)。
 *   - 约束 ① 的例外: 段级 unmap 整段清除后 map_sg 立即重建 — 空窗口
 *     内 L1 若空表由 GFP_ATOMIC 重分配 (map_sg_atomic 不睡眠); sg
 *     失败回退路径仍保持逐页交错形态。 */

/* 单次锁内重映射段大小 (页); 组提升批 = 512 页单独路径 */
#define SYMRDMA_REPAIR_SEG    128

/* NO_SG 路径 (repair_sg=0) 锁内块大小 (页) —  逐页交错形态的
 * 16 页取放锁节奏 (每块 2 flush/域, 中间级页表恒在) */
#define SYMRDMA_REPAIR_CHUNK  16

/* sg run 构建上限 (页): 512 页连续 run 会令 5.11 __iommu_map 对
 * (对齐 iova,pa,size) 选 2MB 超页页尺寸 — 破坏逐页状态模型 (硬件
 * 红线); 511 页上限强制 4KB PTE 连填形态 */
#define SYMRDMA_SG_RUN_MAX    (SYMRDMA_GROUP_PAGES - 1)

/*
 * 修复路径批量 GUP — 前缀语义 (返回成功页数; 0 = 无页可修, 负值仅当
 * 首页即失败且为便于诊断保留错误码时才会出现 — 见 pass 0 注释, 常规
 * 返回 0..nr)。
 *
 * 5.11 get_user_pages_fast 语义 (internal_get_user_pages_fast): fast
 * 前缀 + 仅对剩余段慢路径; 慢路径失败但已有前缀时返回前缀计数 (不返回
 * 错误、不泄漏引用) — 天然前缀语义。
 *
 * 两档 flags 策略对齐 symrdma_gup_write_first (历史):
 *   pass 0 — FOLL_WRITE 整段批量 (可写 VMA 页触发 COW, 防 zero_page
 *           经 write_iova(RW) 写穿全局零页); 整段可写/整段只读两类常见
 *           形态在此完成。
 *   残余段 — 逐页两档回退 (FOLL_WRITE 失败 → 无写标志重试): 只读 VMA
 *           页 (无 DMA 写路径, 零页/页缓存页只读映射安全) 或不可修页
 *           (fail-closed, 与逐页循环 "任一页失败即停" 语义一致)。混合
 *           VMA 权限场景保持逐页语义 — 批量无写标志段会把可写 VMA 的
 *           未写过页解析到零页 (逐页则先试 FOLL_WRITE)。
 */
static int repair_gup_range(unsigned long va, unsigned long nr,
			    struct page **pages)
{
	unsigned long done, i;
	int r;

	r = get_user_pages_fast(va, nr, FOLL_WRITE, pages);
	done = (r > 0) ? (unsigned long)r : 0;

	for (i = done; i < nr; i++) {
		r = symrdma_gup_write_first(va + i * PAGE_SIZE, 1, &pages[i],
					    false);
		if (r < 1)
			break;
		done = i + 1;
	}
	return done;
}

/*
 * sg run 构建 (Phase 1): pa[] 相邻连续页合并为 sg 条目 —
 * 5.11 __iommu_map 按对齐选择页尺寸: 511 页内的连续 run 以 4KB PTE
 * 形态由 intel __domain_mapping 单次页表遍历连填 (每 run 1 walk,
 * 取代逐页 1 walk)。条目页取 pfn_to_page(pa_i): sg 只做物理地址
 * 算术 (sg_phys = page_to_phys + offset, offset 须 < PAGE_SIZE), GUP
 * 对 THP 返回复合头页 — 复合头页 + 0 偏移只能表达 2MB 基址, 组内
 * 页基址+4K 无法直接表达, 故取物理页帧的真 4KB 页 + offset 0。
 * 返回条目数; 0 = 不可用 (存在无 struct page 的 PA — 罕见, 调用方
 * 回退逐页路径)。sg 表须已 sg_init_table。
 */
static unsigned int sg_build_runs(struct scatterlist *sg,
				  const phys_addr_t *pa,
				  unsigned long n)
{
	unsigned long i = 0, run;
	unsigned int nents = 0;

	while (i < n) {
		struct page *p;

		if (!pfn_valid(PHYS_PFN(pa[i])))
			return 0;
		run = 1;
		while (i + run < n && run < SYMRDMA_SG_RUN_MAX &&
		       pa[i + run] == pa[i] + run * PAGE_SIZE)
			run++;
		p = pfn_to_page(PHYS_PFN(pa[i]));
		sg_set_page(&sg[nents], p, run * PAGE_SIZE, 0);
		/* 修复 (L1d host-b 停机根因): sg_assign_page 会保留
		 * SG_END/SG_CHAIN 标志位 — 本函数在 REPAIR_RANGE 段循环/
		 * promote 回退中复用同一 sg 表, 前段 nents=1 时
		 * sg_mark_end(&sg[0]) 遗留的 SG_END 残留到本段首条目:
		 * 本段 nents≥2 时 5.11 __iommu_map_sg 循环在 i=0 后
		 * sg_next(sg[0]) 因假 END 返回 NULL, i=1 循环体
		 * sg_phys(NULL) → Oops → 修复任务持 st->lock 死亡 →
		 * resident_work_fn kworker 死锁自旋 → 机器半死 (已三同
		 * 签名单机复现)。建条目后显式清位, 真末尾由下方
		 * sg_mark_end(&sg[nents-1]) 重打。 */
		sg[nents].page_link &= ~(SG_CHAIN | SG_END);
		nents++;
		i += run;
	}
	sg_mark_end(&sg[nents - 1]);
	return nents;
}

/* 修复前缀内 [off, off+512) 的整组连续性: 基址 2MB 对齐 + 全组 pa
 * 连续 (锁外预判, pa[] 为本地数组; 锁内 group_promote_repair_locked
 * 复核组状态)。 */
static bool repair_contig_group(const phys_addr_t *pa, unsigned long off)
{
	unsigned long k;

	if (!IS_ALIGNED(pa[off], SYMRDMA_GROUP_SIZE))
		return false;
	for (k = 1; k < SYMRDMA_GROUP_PAGES; k++)
		if (pa[off + k] != pa[off] + k * PAGE_SIZE)
			return false;
	return true;
}

/*
 * 锁内段重映射: [page_idx+off, page_idx+off+n) 双 IOVA → 真实
 * PA + 状态/版本更新。n ≤ SYMRDMA_REPAIR_SEG; off 为 pa[] 相对下标,
 * page_idx+off+i 为绝对页号 (IOVA/pages[]/版本表索引)。调用方持
 * st->lock 且已作所有权复查 (同 symrdma_repair_page)。
 *
 * 三段式 (每域): ① 段级 unmap_fast (单 walk, gather 累积不 flush);
 * ② iommu_map_sg_atomic — pa run 合并条目 (连续 run 一条目一 walk;
 * 离散页退化为逐条目 4KB 映射, walk 数与  逐页等价但单次调用);
 * ③ iotlb_sync (单次 flush)。sg 不可用 (无 struct page 的 PA) 或
 * map_sg 部分失败 → 整段回退  逐页交错形态 (段已全 unmap —
 * unmap_fast 幂等重做无副作用; 交错保持约束 ① 的中间级恒在论证)。
 * read 域先全成, write 域只处理 okmask 命中页 (约束 ② 两域独立
 * gather 周期; 约束 ③ sync 后才发布状态/版本)。
 *
 * 映射失败兑底 (GFP_ATOMIC): 哨兵/黑洞 fail-closed (语义),
 * okmask 不置位 → 状态/版本不动, 请求方乐观路径重检再触发。
 */
static void remap_real_range_locked(struct symrdma_dev *dev,
				    struct symrdma_mr *mr,
				    unsigned long page_idx,
				    unsigned long off, unsigned long n,
				    const phys_addr_t *pa,
				    struct scatterlist *sg)
{
	DECLARE_BITMAP(okmask, SYMRDMA_REPAIR_SEG);
	struct iommu_iotlb_gather gr, gw;
	unsigned long i;
	unsigned int nents = 0;
	bool write_sg = false;
	u64 base_iova;
	size_t expect;

	/* okmask 位图宽 = 段上限 (调用方保证 n ≤ SEG) */
	if (WARN_ON_ONCE(n > SYMRDMA_REPAIR_SEG))
		n = SYMRDMA_REPAIR_SEG;
	bitmap_zero(okmask, n);
	expect = n * PAGE_SIZE;

	/* 等价跳过: 批次整体位于 GRP_RESIDENT 组内且 pa 与组基址一致 —
	 * 重复修复/假阳性 (状态/版本/映射已正确, 避免无谓降级重做) */
	if (mr->groups) {
		unsigned long gidx = (page_idx + off) >>
						SYMRDMA_GROUP_SHIFT;
		unsigned long gin = (page_idx + off) -
					    gidx * SYMRDMA_GROUP_PAGES;

		if (gin + n <= SYMRDMA_GROUP_PAGES &&
		    mr->groups[gidx].state == GRP_RESIDENT) {
			phys_addr_t gb = mr->groups[gidx].base_pa +
					 gin * PAGE_SIZE;

			for (i = 0; i < n && pa[off + i] ==
					gb + i * PAGE_SIZE; i++)
				;
			if (i == n)
				return;
		}
	}

	/* 组感知前置: 段覆盖的提升组先降级 — 段级 unmap_fast 整段清除
	 * 撞超页 PTE 同样触发静默整片解除 (硬件红线) */
	symrdma_group_ensure_split_range_locked(dev, mr, page_idx + off,
						page_idx + off + n - 1);

	/* NO_SG kill-switch (Phase 1):  逐页交错形态 —
	 * 每页 unmap_fast+map_atomic 交错 (中间级页表恒在, 2 flush/块/域),
	 * 调用方按 SYMRDMA_REPAIR_CHUNK=16 分块取锁。与 sg 路径共享
	 * okmask 与尾部的状态/版本发布循环。 */
	if (!dev->repair_sg) {
		base_iova = mr->read_iova + (page_idx + off) * PAGE_SIZE;
		iommu_iotlb_gather_init(&gr);
		for (i = 0; i < n; i++) {
			u64 riova = base_iova + i * PAGE_SIZE;

			iommu_unmap_fast(dev->iommu_domain, riova,
					 PAGE_SIZE, &gr);
			if (iommu_map_atomic(dev->iommu_domain, riova,
					     pa[off + i], PAGE_SIZE,
					     IOMMU_READ | IOMMU_WRITE)) {
				pr_err("symrdma: 区间修复 map(read) 失败 idx=%lu\n",
				       page_idx + off + i);
				iommu_map_atomic(dev->iommu_domain, riova,
						 dev->sentinel_pa,
						 PAGE_SIZE, IOMMU_READ);
				continue;   /* okmask 不置位 — 状态/版本不动 */
			}
			__set_bit(i, okmask);
		}
		if (gr.pgsize)
			iommu_iotlb_sync(dev->iommu_domain, &gr);

		base_iova = mr->write_iova + (page_idx + off) * PAGE_SIZE;
		iommu_iotlb_gather_init(&gw);
		for (i = 0; i < n; i++) {
			u64 wiova = base_iova + i * PAGE_SIZE;

			if (!test_bit(i, okmask))
				continue;   /* 读侧已回滚 — 写侧不再触碰 */
			iommu_unmap_fast(dev->iommu_domain, wiova,
					 PAGE_SIZE, &gw);
			if (iommu_map_atomic(dev->iommu_domain, wiova,
					     pa[off + i], PAGE_SIZE,
					     IOMMU_READ | IOMMU_WRITE)) {
				pr_err("symrdma: 区间修复 map(write) 失败 idx=%lu\n",
				       page_idx + off + i);
				iommu_map_atomic(dev->iommu_domain, wiova,
						 dev->blackhole_pa,
						 PAGE_SIZE, IOMMU_WRITE);
				__clear_bit(i, okmask);
			}
		}
		if (gw.pgsize)
			iommu_iotlb_sync(dev->iommu_domain, &gw);
		goto publish;
	}

	/* ---- read 域: 段级 unmap → sg run 合并映射 → 单次 sync ---- */
	base_iova = mr->read_iova + (page_idx + off) * PAGE_SIZE;
	iommu_iotlb_gather_init(&gr);
	iommu_unmap_fast(dev->iommu_domain, base_iova, expect, &gr);
	nents = sg_build_runs(sg, pa + off, n);
	if (nents &&
	    iommu_map_sg_atomic(dev->iommu_domain, base_iova, sg, nents,
				IOMMU_READ | IOMMU_WRITE) == expect) {
		bitmap_fill(okmask, n);
	} else {
		/* 逐页交错回退 (段已整段 unmap — 幂等) */
		for (i = 0; i < n; i++) {
			u64 riova = base_iova + i * PAGE_SIZE;

			iommu_unmap_fast(dev->iommu_domain, riova,
					 PAGE_SIZE, &gr);
			if (iommu_map_atomic(dev->iommu_domain, riova,
					     pa[off + i], PAGE_SIZE,
					     IOMMU_READ | IOMMU_WRITE)) {
				pr_err("symrdma: 区间修复 map(read) 失败 idx=%lu\n",
				       page_idx + off + i);
				iommu_map_atomic(dev->iommu_domain, riova,
						 dev->sentinel_pa,
						 PAGE_SIZE, IOMMU_READ);
				continue;   /* okmask 不置位 — 状态/版本不动 */
			}
			__set_bit(i, okmask);
		}
	}
	if (gr.pgsize)
		iommu_iotlb_sync(dev->iommu_domain, &gr);

	/* ---- write 域 (独立 gather 周期 — 约束 ②) ---- */
	base_iova = mr->write_iova + (page_idx + off) * PAGE_SIZE;
	iommu_iotlb_gather_init(&gw);
	if (bitmap_full(okmask, n)) {
		/* read 域 sg 整段成功 ⇒ 全命中 — write 域同构批量 (整段
		 * unmap + map_sg; okmask 全置位故不误伤缺失页黑洞 PTE) */
		iommu_unmap_fast(dev->iommu_domain, base_iova, expect, &gw);
		write_sg = (iommu_map_sg_atomic(dev->iommu_domain, base_iova,
						sg, nents,
						IOMMU_READ | IOMMU_WRITE)
							== expect);
		/* 失败 (部分/全部): 已成部分由下方逐页重做收口 — 段已
		 * 整段 unmap, unmap_fast 幂等 */
	}
	if (!write_sg) {
		for (i = 0; i < n; i++) {
			u64 wiova = base_iova + i * PAGE_SIZE;

			if (!test_bit(i, okmask))
				continue;   /* 读侧已回滚 — 写侧不再触碰 */
			iommu_unmap_fast(dev->iommu_domain, wiova,
					 PAGE_SIZE, &gw);
			if (iommu_map_atomic(dev->iommu_domain, wiova,
					     pa[off + i], PAGE_SIZE,
					     IOMMU_READ | IOMMU_WRITE)) {
				pr_err("symrdma: 区间修复 map(write) 失败 idx=%lu\n",
				       page_idx + off + i);
				iommu_map_atomic(dev->iommu_domain, wiova,
						 dev->blackhole_pa,
						 PAGE_SIZE, IOMMU_WRITE);
				__clear_bit(i, okmask);
			}
		}
	}
	if (gw.pgsize)
		iommu_iotlb_sync(dev->iommu_domain, &gw);

publish:
	/* 状态/版本发布 (sync 后 — 约束 ③; 与 NO_SG 路径共享) */
	for_each_set_bit(i, okmask, n) {
		mr->pages[page_idx + off + i].read_state  = PAGE_RESIDENT;
		mr->pages[page_idx + off + i].write_state = PAGE_RESIDENT;
		mr->pages[page_idx + off + i].orig_pa      = pa[off + i];
		mr->pages[page_idx + off + i].probe_fail  = 0;   /* 恢复可探测态 */
		if (mr->version_table || mr->version_pages) {
			u32 cur = symrdma_version_read(mr, page_idx + off + i);

			/* 缺失 (偶) → 下一个奇数 (翻转); 驻留 (奇) → 恒等
			 * (修复不改变状态 — 假阳性场景, 同 repair_page) */
			symrdma_version_set(mr, page_idx + off + i,
					    (cur & ~1U) + 1);
		}
	}
}

/*
 * 修复路径组提升 (Phase 2): 512 页连续对齐组 → 单条 2MB 超页。
 * 调用方持 st->lock + 所有权复查已过 (repair_range 阶段 ③); off 为
 * pa[] 相对下标且 page_idx+off 为组首绝对页号, 512 页在修复前缀内。
 *   - 组已 GRP_RESIDENT 且基址一致: 等价跳过 (重复修复/假阳性 —
 *     状态/版本/映射已正确)。
 *   - 其余 (未提升/GRP_ABSENT/基址变化): 双域 2MB 撤销 → 单条 2MB
 *     真实映射 → 512 页状态/版本发布。
 * map 失败 (GFP_ATOMIC): 撤销已成部分, 整组交回 remap_real_range_
 * locked 逐页/sg 段重建 (组状态已置 GRP_NONE, 幂等) — 重建失败仍有
 * 哨兵/黑洞兜底 (fail-closed 语义在段路径内)。 */
static void group_promote_repair_locked(struct symrdma_dev *dev,
					struct symrdma_mr *mr,
					unsigned long page_idx,
					unsigned long off,
					const phys_addr_t *pa,
					struct scatterlist *sg)
{
	struct iommu_iotlb_gather g;
	unsigned long gidx = (page_idx + off) >> SYMRDMA_GROUP_SHIFT;
	unsigned long base = gidx * SYMRDMA_GROUP_PAGES;
	u64 riova = mr->read_iova + base * PAGE_SIZE;
	u64 wiova = mr->write_iova + base * PAGE_SIZE;
	phys_addr_t pa0 = pa[off];
	unsigned long k;
	int fail = 0;

	if (mr->groups[gidx].state == GRP_RESIDENT &&
	    mr->groups[gidx].base_pa == pa0) {
		atomic64_inc(&dev->stats.group_repromote);
		return;   /* 等价跳过 */
	}

	/* read 域: 2MB 撤销 (超页或逐页 PTE 一律整段清除) → 单条超页 */
	iommu_iotlb_gather_init(&g);
	iommu_unmap_fast(dev->iommu_domain, riova, SYMRDMA_GROUP_SIZE, &g);
	/* 映射已撤销 — 组状态立即失效 (下方任一失败分支不再回头读它) */
	mr->groups[gidx].state = GRP_NONE;
	mr->groups[gidx].base_pa = 0;
	if (iommu_map_atomic(dev->iommu_domain, riova, pa0,
			     SYMRDMA_GROUP_SIZE,
			     IOMMU_READ | IOMMU_WRITE))
		fail = 1;
	if (g.pgsize)
		iommu_iotlb_sync(dev->iommu_domain, &g);

	/* write 域 (独立 gather — 约束 ②) */
	iommu_iotlb_gather_init(&g);
	iommu_unmap_fast(dev->iommu_domain, wiova, SYMRDMA_GROUP_SIZE, &g);
	if (!fail && iommu_map_atomic(dev->iommu_domain, wiova, pa0,
				      SYMRDMA_GROUP_SIZE,
				      IOMMU_READ | IOMMU_WRITE))
		fail = 2;
	if (g.pgsize)
		iommu_iotlb_sync(dev->iommu_domain, &g);

	if (fail) {
		if (fail == 2)
			/* 撤已成部分 (带 flush) — 下方逐段重建覆盖 */
			iommu_unmap(dev->iommu_domain, riova,
				    SYMRDMA_GROUP_SIZE);
		/* 整组交回段重建 (组已 GRP_NONE — remap 的组感知前置
		 * 为无操作, 直落段批路径); 512 页 = 4 段 */
		for (k = 0; k < SYMRDMA_GROUP_PAGES;
		     k += SYMRDMA_REPAIR_SEG)
			remap_real_range_locked(dev, mr, page_idx,
						off + k, SYMRDMA_REPAIR_SEG,
						pa, sg);
		return;
	}

	/* 状态/版本发布 (sync 后 — 约束 ③) */
	mr->groups[gidx].base_pa = pa0;
	mr->groups[gidx].state = GRP_RESIDENT;
	for (k = 0; k < SYMRDMA_GROUP_PAGES; k++) {
		unsigned long idx = base + k;

		mr->pages[idx].orig_pa = pa0 + k * PAGE_SIZE;
		mr->pages[idx].read_state = PAGE_RESIDENT;
		mr->pages[idx].write_state = PAGE_RESIDENT;
		mr->pages[idx].probe_fail = 0;
		if (mr->version_table || mr->version_pages) {
			u32 cur = symrdma_version_read(mr, idx);

			/* 缺失 (偶) → 翻转; 驻留 (奇) → 恒等 */
			symrdma_version_set(mr, idx, (cur & ~1U) + 1);
		}
	}
	atomic64_inc(&dev->stats.group_repromote);
}

/*
 * 区间批量修复入口: 修复 [page_idx, page_idx+npages)。
 *
 * 阶段: ① 参数校验 + 数组分配 (npages 裁剪到 SYMRDMA_REPAIR_RANGE_MAX
 * 与 MR 边界); ② 批量 GUP (锁外, 可睡眠 — 换入即修复, 论文 §3.2
 * "target pins the corresponding remote buffer" 的内核形态); ③ 分块
 * 锁内 remap + 版本翻转 (所有权复查同 repair_page — G1 fail-closed);
 * ④ 释放引用。
 *
 * 返回: 0 = ≥1 页修复 (*repaired = 实际页数, 可 < npages — 部分成功,
 * 剩余页由请求方乐观路径重检再触发); -EAGAIN = 0 页修复; -ENOENT =
 * MR 已拆卸; -EINVAL = 参数越界。
 */
int symrdma_repair_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
			 unsigned long page_idx, unsigned long npages,
			 unsigned long *repaired)
{
	unsigned long va, i, n, done;
	struct symrdma_mm_state *st;
	struct page **pages;
	phys_addr_t *pa;
	struct scatterlist *sg;
	int ret = 0;
	/* 组模式 — groups[] 在位且 read IOVA 2MB 对齐 (写侧随
	 * 之对齐); 否则恒段批/逐页 (与  一致) */
	bool group_mode = mr->groups &&
			  IS_ALIGNED(mr->read_iova, SYMRDMA_GROUP_SIZE);

	*repaired = 0;
	if (page_idx >= mr->npages || npages == 0)
		return -EINVAL;
	n = min3(npages, (unsigned long)SYMRDMA_REPAIR_RANGE_MAX,
		 mr->npages - page_idx);

	va = mr->va_start + page_idx * PAGE_SIZE;

	pages = kvcalloc(n, sizeof(*pages), GFP_KERNEL);
	pa = kvcalloc(n, sizeof(*pa), GFP_KERNEL);
	if (!pages || !pa) {
		kvfree(pages);
		kvfree(pa);
		return -ENOMEM;
	}

	/* 阶段 ②: 批量 GUP (锁外 — 可睡眠; 一次调用内建 fast 前缀 + 剩余段
	 * 慢路径, mmap_lock 至多取一次) */
	done = repair_gup_range(va, n, pages);
	if (done == 0) {
		atomic64_inc(&dev->stats.repair_fail);
		pr_info("symrdma: 区间修复失败 [%lu,+%lu): gup=0\n",
			page_idx, n);
		kvfree(pages);
		kvfree(pa);
		return -EAGAIN;
	}
	for (i = 0; i < done; i++)
		pa[i] = symrdma_va_to_pa(pages[i], va + i * PAGE_SIZE);

	/* 阶段 ③: 段批锁内重映射 (G2: st 临时引用 — GUP 毫秒级窗口内
	 * DEREG 可完成 unlink + kfree_rcu(st); G1: 所有权复查 fail-closed,
	 * 拆卸 MR 的重映射会在拆卸 unmap 之后遗留 PTE)。
	 *  整组连续对齐 → 组提升 512 页单批; 否则 SEG 段批
	 * (sg run 合并映射 + 段级 unmap/flush 摊薄) */
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

	for (i = 0; i < done && !ret; ) {
		unsigned long c;
		bool promote = false;

		/* 整组提升候选 (锁外预判 — pa[] 本地数组; 锁内 promote
		 * 自行复核组状态): 批起点为组首 && 组完整在修复前缀与 MR
		 * 内 && pa 全组连续且基址 2MB 对齐 */
		if (group_mode &&
		    !((page_idx + i) & (SYMRDMA_GROUP_PAGES - 1)) &&
		    i + SYMRDMA_GROUP_PAGES <= done &&
		    page_idx + i + SYMRDMA_GROUP_PAGES <= mr->npages &&
		    repair_contig_group(pa, i))
			promote = true;

		c = promote ? SYMRDMA_GROUP_PAGES
			   : min(done - i, dev->repair_sg ?
				  (unsigned long)SYMRDMA_REPAIR_SEG :
				  (unsigned long)SYMRDMA_REPAIR_CHUNK);

		spin_lock(&st->lock);
		if (mr->mm_state != st) {
			/* 锁内复查: 并发 DEREG 的 detach 同锁置 NULL — 已接管 */
			spin_unlock(&st->lock);
			ret = -ENOENT;
			break;
		}
		/* page_idx + i = 绝对页号 (IOVA/状态/版本索引); i = pa[] 相对下标 */
		if (promote)
			group_promote_repair_locked(dev, mr, page_idx, i,
						    pa, sg);
		else
			remap_real_range_locked(dev, mr, page_idx, i, c,
						pa, sg);
		spin_unlock(&st->lock);
		i += c;
	}
	kvfree(sg);
	symrdma_mm_state_put(st);

out_pages:
	for (i = 0; i < done; i++)
		put_page(pages[i]);
	kvfree(pages);
	kvfree(pa);

	if (ret)
		return ret;

	atomic64_add(done, &dev->stats.repair_ok);
	*repaired = done;
	pr_info("symrdma: 区间修复 [%lu,+%lu) → %lu 页 (请求 %lu)\n",
		page_idx, n, done, npages);
	return 0;
}

/* ---- MAPBENCH (cmd 12): 组粒度映射微基准 (L19 B 轴) ----
 *
 * 对单个 512 页组 (要求全 RESIDENT + orig_pa 在位 — 由 THP 注册提升
 * 或 REPAIR_RANGE 获得) 计时三种映射/撤销形态:
 *   mode 0 (PERPAGE):  逐页形态 — 16 页/块交错 unmap+map, 2 flush/
 *     块 (基线, 与 repair_range  等价形态);
 *   mode 1 (SG):      Phase 1 段批 — 整组 unmap_fast (1 walk) +
 *     iommu_map_sg_atomic run 合并 + 单次 sync/域;
 *   mode 2 (SUPER):   Phase 2 超页 — 整组 2MB 撤销 + 单条 2MB 超页映射
 *     (计时), 随后**不计时**恢复为逐页形态 (sg) — 不留组提升状态
 *     (groups[] 恒 GRP_NONE, 状态机不感知基准)。
 *
 * 全程持 st->lock (基准窗口独占 — 阻塞该 mm 的 notifier/修复, iters
 * 上界 1e6 约 100ms/组, 仅测试用途); 迭代内 map 失败即中止返回 -EIO。
 * 恢复 (SUPER 模式) 不计时: 计时口径 = unmap+map+sync (双域)。
 */
int symrdma_iommu_mapbench(struct symrdma_dev *dev, struct symrdma_mr *mr,
			   struct symrdma_ioc_mapbench *req)
{
	struct symrdma_mm_state *st;
	struct scatterlist *sg;
	phys_addr_t *pa;
	u64 riova, wiova, t_total = 0;
	unsigned long ops = 0, it = 0, i;
	unsigned int nents = 0;
	int ret = 0;

	if (req->iters == 0 || req->iters > 1000000)
		return -EINVAL;
	if (req->mode < SYMRDMA_MB_PERPAGE || req->mode > SYMRDMA_MB_SUPER)
		return -EINVAL;
	if (!mr->groups)
		return -EINVAL;   /* 组机制关闭 (iommu_huge=0/区域分配失败) */
	if ((req->page_idx & (SYMRDMA_GROUP_PAGES - 1)) ||
	    req->page_idx + SYMRDMA_GROUP_PAGES > mr->npages)
		return -EINVAL;   /* 须为组首且组完整 */

	st = symrdma_mm_state_get(mr);
	if (!st)
		return -ENOENT;

	pa = kvcalloc(SYMRDMA_GROUP_PAGES, sizeof(*pa), GFP_KERNEL);
	sg = kvcalloc(SYMRDMA_GROUP_PAGES, sizeof(*sg), GFP_KERNEL);
	if (!pa || !sg) {
		kvfree(pa);
		kvfree(sg);
		symrdma_mm_state_put(st);
		return -ENOMEM;
	}
	sg_init_table(sg, SYMRDMA_GROUP_PAGES);

	spin_lock(&st->lock);
	if (mr->mm_state != st) {
		/* 锁内复查: 并发 DEREG 的 detach 同锁置 NULL — 已接管 */
		ret = -ENOENT;
		goto out_unlock;
	}

	/* 形态归一: 组若提升先降级 (512 页逐页形态, 状态不变 — 降级是纯
	 * 映射变换); 512 页须全 RESIDENT 且 orig_pa 在位 */
	if (mr->groups[req->page_idx >> SYMRDMA_GROUP_SHIFT].state !=
								GRP_NONE)
		symrdma_group_demote_locked(dev, mr,
					    req->page_idx >>
							SYMRDMA_GROUP_SHIFT);
	for (i = 0; i < SYMRDMA_GROUP_PAGES; i++) {
		if (mr->pages[req->page_idx + i].read_state !=
							PAGE_RESIDENT ||
		    mr->pages[req->page_idx + i].orig_pa == 0) {
			ret = -EINVAL;
			goto out_unlock;
		}
		pa[i] = mr->pages[req->page_idx + i].orig_pa;
	}
	nents = sg_build_runs(sg, pa, SYMRDMA_GROUP_PAGES);
	if (!nents) {
		ret = -EINVAL;   /* 罕见: PA 无 struct page */
		goto out_unlock;
	}
	if (req->mode == SYMRDMA_MB_SUPER &&
	    !IS_ALIGNED(pa[0], SYMRDMA_GROUP_SIZE)) {
		/* 2MB 超页映射须基址对齐 (misaligned 会静默退化为 512×4KB
		 * 循环 — 计时口径失真) */
		ret = -EINVAL;
		goto out_unlock;
	}

	riova = mr->read_iova + req->page_idx * PAGE_SIZE;
	wiova = mr->write_iova + req->page_idx * PAGE_SIZE;

	for (it = 0; it < req->iters && !ret; it++) {
		u64 t0 = ktime_get_ns();

		switch (req->mode) {
		case SYMRDMA_MB_PERPAGE: {
			struct iommu_iotlb_gather g;
			unsigned long c, k;

			/* 逐页形态: 16 页/块交错 + 2 flush/块 */
			for (c = 0; c < SYMRDMA_GROUP_PAGES; c += 16) {
				iommu_iotlb_gather_init(&g);
				for (k = c; k < c + 16; k++) {
					u64 iov = riova + k * PAGE_SIZE;

					iommu_unmap_fast(dev->iommu_domain,
							 iov, PAGE_SIZE, &g);
					if (iommu_map_atomic(dev->iommu_domain,
							     iov, pa[k],
							     PAGE_SIZE,
							     IOMMU_READ |
							     IOMMU_WRITE))
						ret = -EIO;
				}
				if (g.pgsize)
					iommu_iotlb_sync(dev->iommu_domain,
							 &g);
			}
			for (c = 0; c < SYMRDMA_GROUP_PAGES; c += 16) {
				iommu_iotlb_gather_init(&g);
				for (k = c; k < c + 16; k++) {
					u64 iov = wiova + k * PAGE_SIZE;

					iommu_unmap_fast(dev->iommu_domain,
							 iov, PAGE_SIZE, &g);
					if (iommu_map_atomic(dev->iommu_domain,
							     iov, pa[k],
							     PAGE_SIZE,
							     IOMMU_READ |
							     IOMMU_WRITE))
						ret = -EIO;
				}
				if (g.pgsize)
					iommu_iotlb_sync(dev->iommu_domain,
							 &g);
			}
			break;
		}

		case SYMRDMA_MB_SG: {
			struct iommu_iotlb_gather g;

			/* Phase 1 段批: 整组 unmap_fast + sg run 合并映射 +
			 * 单次 sync/域 */
			iommu_iotlb_gather_init(&g);
			iommu_unmap_fast(dev->iommu_domain, riova,
					 SYMRDMA_GROUP_SIZE, &g);
			if (iommu_map_sg_atomic(dev->iommu_domain, riova,
						sg, nents,
						IOMMU_READ | IOMMU_WRITE) !=
							SYMRDMA_GROUP_SIZE)
				ret = -EIO;
			if (g.pgsize)
				iommu_iotlb_sync(dev->iommu_domain, &g);

			iommu_iotlb_gather_init(&g);
			iommu_unmap_fast(dev->iommu_domain, wiova,
					 SYMRDMA_GROUP_SIZE, &g);
			if (!ret &&
			    iommu_map_sg_atomic(dev->iommu_domain, wiova,
						sg, nents,
						IOMMU_READ | IOMMU_WRITE) !=
							SYMRDMA_GROUP_SIZE)
				ret = -EIO;
			if (g.pgsize)
				iommu_iotlb_sync(dev->iommu_domain, &g);
			break;
		}

		case SYMRDMA_MB_SUPER: {
			struct iommu_iotlb_gather g;
			int fail = 0;

			/* 计时: 整组 2MB 撤销 + 单条超页映射 (双域) */
			iommu_iotlb_gather_init(&g);
			iommu_unmap_fast(dev->iommu_domain, riova,
					 SYMRDMA_GROUP_SIZE, &g);
			if (iommu_map_atomic(dev->iommu_domain, riova,
					     pa[0], SYMRDMA_GROUP_SIZE,
					     IOMMU_READ | IOMMU_WRITE))
				fail = 1;
			iommu_iotlb_sync(dev->iommu_domain, &g);
			iommu_iotlb_gather_init(&g);
			iommu_unmap_fast(dev->iommu_domain, wiova,
					 SYMRDMA_GROUP_SIZE, &g);
			if (!fail &&
			    iommu_map_atomic(dev->iommu_domain, wiova,
					     pa[0], SYMRDMA_GROUP_SIZE,
					     IOMMU_READ | IOMMU_WRITE))
				fail = 1;
			iommu_iotlb_sync(dev->iommu_domain, &g);
			if (fail) {
				ret = -EIO;
				break;
			}

			/* 恢复 (不计时): 超页 → sg 逐页形态 (组状态不感知) */
			iommu_iotlb_gather_init(&g);
			iommu_unmap_fast(dev->iommu_domain, riova,
					 SYMRDMA_GROUP_SIZE, &g);
			if (iommu_map_sg_atomic(dev->iommu_domain, riova,
						sg, nents,
						IOMMU_READ | IOMMU_WRITE) !=
							SYMRDMA_GROUP_SIZE)
				ret = -EIO;
			iommu_iotlb_sync(dev->iommu_domain, &g);
			iommu_iotlb_gather_init(&g);
			iommu_unmap_fast(dev->iommu_domain, wiova,
					 SYMRDMA_GROUP_SIZE, &g);
			if (!ret &&
			    iommu_map_sg_atomic(dev->iommu_domain, wiova,
						sg, nents,
						IOMMU_READ | IOMMU_WRITE) !=
							SYMRDMA_GROUP_SIZE)
				ret = -EIO;
			iommu_iotlb_sync(dev->iommu_domain, &g);
			break;
		}
		}
		t_total += ktime_get_ns() - t0;
		if (!ret)
			ops++;
	}

	req->ns_total = t_total;
	req->map_ops = ops;
out_unlock:
	spin_unlock(&st->lock);
	kvfree(pa);
	kvfree(sg);
	symrdma_mm_state_put(st);
	if (ret == -EIO)
		pr_err("symrdma: MAPBENCH 迭代失败 (mode=%d it=%lu)\n",
		       req->mode, it);
	return ret;
}
