/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma_mr.c — SymRDMA MR 注册/注销
 *
 * 论文 §4.1: 每个应用 MR 使用双 IOVA 范围:
 *   - Read MR:  read_iova  → IOMMU (驻留→真实PA, 缺失→哨兵)
 *   - Write MR: write_iova → IOMMU (驻留→真实PA, 缺失→黑洞)
 *   - Version MR: pinned 内核内存，每页 4 字节版本号
 *
 * 论文 §4.2: MTT 配置为 identity mapping (IOVA == VA)，
 * 实际翻译由 IOMMU 动态完成。
 */
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

	/* (注册以页为粒度 — 非页对齐 len 向上取整 (原实现截断,
	 * 尾部不足一页的部分无映射无保护; 拦截层已取整, ioctl API 自洽) */
	len = round_up(len, PAGE_SIZE);

	/* K-M8 (2026-10-13): ① len 不得超过写偏移量 — write_iova
	 * = va_start + SYMRDMA_MR_WRITE_OFFSET, len 超过偏移量时 read 区间
	 * [va, va+len) 与自身 write IOVA 区间重叠, 黑洞/哨兵语义静默失效;
	 * ② va_start 须页对齐 — 非对齐首页映射偏移 (拦截层已保证, ioctl
	 * 直调者也 fail-closed)。超 32GB 的大堆需分多次注册 (≤32GB/MR)。 */
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

	/* (初始引用 — 注册成功后由 idr 持有 (DEREG/release 移出
	 * idr 后 put)；失败路径由创建者持有 (dereg put) */
	kref_init(&mr->ref);

	/* kvcalloc — npages×sizeof(entry) 可超 kmalloc 上限
	 * (order-11 ≈ 4MB; 1GB MR ≈ 1M 页 × 32B = 32MB →  大 MR
	 * 注册 -ENOMEM, L17 基线实测 1GB+ 失败) */
	mr->pages = kvcalloc(npages, sizeof(struct symrdma_page_entry),
			     GFP_KERNEL);
	if (!mr->pages) {
		ret = -ENOMEM;
		goto err_free_mr;
	}

	/* 组粒度模型 — npages/512 个组槽 (kvcalloc 同上理由;
	 * kzalloc 零化 = 全 GRP_NONE)。分配失败不致命: 组机制对该 MR
	 * 关闭 (groups=NULL → 恒段批/逐页 行为; mapbench/组提升
	 * 统计降级) — 先于 attach 分配, notifier 的组感知前置方可安全
	 * 读取。 */
	if (dev->huge_ok) {
		mr->groups = kvcalloc(DIV_ROUND_UP(npages,
						   SYMRDMA_GROUP_PAGES),
				      sizeof(struct symrdma_group_entry),
				      GFP_KERNEL);
		if (!mr->groups)
			pr_warn("symrdma: MR 组表分配失败 (npages=%lu), 该 MR 组机制关闭\n",
				npages);
	}

	mr->dev      = dev;
	mr->va_start = va_start;
	mr->va_end   = va_start + len;
	mr->npages   = npages;
	mr->mm       = mm;
	mr->mr_id    = -1;    /* §4.1: idr 分配后写回 (release 清理用) */
	/* 在飞 pin 区间链表 — kzalloc 零化 head 直接 list_add_tail
	 * 会 NULL 解引用 (持 st->lock oops → 锁永不释放 → 全局挂死,
	 * host-a L14 首跑实测); 必须显式初始化 */
	INIT_LIST_HEAD(&mr->pin_list);

	/*
	 * 双 IOVA 范围:
	 *   read_iova  = va_start (恒等映射，兼容 MTT)
	 *   write_iova = va_start + SYMRDMA_MR_WRITE_OFFSET (32GB 偏移)
	 */
	mr->read_iova         = va_start;
	mr->write_iova_offset = SYMRDMA_MR_WRITE_OFFSET;
	mr->write_iova        = va_start + SYMRDMA_MR_WRITE_OFFSET;

	/* Step 1: 分配版本表内存 — 先于 notifier 附加: 回调可能在注册
	 * 完成前触发, version_inc 假定表已分配; 取值见 Step 4。 */
	ret = symrdma_version_alloc(mr);
	if (ret)
		goto err_free_pages;

	/*
	 * Step 2: 附加 per-mm notifier — 先于页表遍历, 堵住"遍历完成、
	 * notifier 未附加"的换出竞态窗口 (换出无回调 → stale PA)。
	 * 注意: 不能持 mmap 锁调用 mmu_notifier_register — 本内核
	 * (5.4.0-150) 实测持锁调用死锁 (test 进程 D 态挂死)。
	 */
	ret = symrdma_mn_attach(mr);
	if (ret)
		goto err_free_version;

	/* Step 3: 遍历页表 & 建立双 IOMMU 映射。持写锁: 遍历期间换出
	 * 被阻塞; 附加后、遍历前的换出由 notifier 处理, 遍历按当前
	 * 真实状态覆盖映射。 */
	mmap_write_lock(mm);
	ret = symrdma_map_mr_pages(dev, mr, mm);
	mmap_write_unlock(mm);
	if (ret)
		goto err_detach;

	/* Step 4: 版本表按最终驻留状态初始化 (加固): 必须在
	 * 遍历之后 — 缺失页=偶数 (0), 驻留页=奇数 (1)。
	 *  纳入 st->lock — mn_attach 后回调可并发触发,
	 * version_inc 与 init 的读写需互斥。
	 * G2: 此处 mm_state 裸读安全 — MR 尚无 idr 条目
	 * (assign_mr_id 在 REG_MR ioctl 内、reg 返回后才发生), 属主进程
	 * 存活 (其线程正执行本调用) ⇒ 无并发 DEREG/release detach。 */
	if (mr->mm_state)
		spin_lock(&mr->mm_state->lock);
	symrdma_version_init(mr);
	if (mr->mm_state)
		spin_unlock(&mr->mm_state->lock);

	/* Step 5: 加入全局 MR 列表 */
	spin_lock(&dev->mr_lock);
	list_add_tail(&mr->list, &dev->mr_list);
	dev->mr_count++;
	spin_unlock(&dev->mr_lock);

	*out_mr = mr;

	pr_info("symrdma: 注册 MR VA=0x%llx len=%lu npages=%lu\n",
		va_start, (unsigned long)len, npages);
	pr_info("symrdma:   Read  IOVA: 0x%llx → 0x%llx\n",
		mr->read_iova, mr->read_iova + len);
	pr_info("symrdma:   Write IOVA: 0x%llx → 0x%llx\n",
		mr->write_iova, mr->write_iova + len);

	return 0;

err_detach:
	/* G1: 先摘除 notifier (终止其对本 MR 的哨兵化, 此后
	 * pages[] 状态冻结; 本 MR 无 idr 条目无并发 ioctl) 再清理 PTE。
	 * 注册失败时 notifier 可能已在 pages[] 上建立哨兵/黑洞映射
	 * (attach 先于遍历 + 遍历期间的 rmap 类失效源), 旧回滚只覆盖
	 * 遍历自映射的前缀 → notifier PTE 永久遗留 → 同 VA 重注册
	 * 连续 -EBUSY ("PTE already set" 实测, 历史 G1)。清理按值认定
	 * 本 MR 产物 (哨兵/黑洞/orig_pa 一致的真实映射), 不触碰他 MR
	 * 的冲突 PTE。map_mr_pages 失败时本方已建立映射已在其 err_check
	 * 内回收, 此处兜底清理 notifier 窗口内建立的映射。 */
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

/*
 * (引用计数归零回调 — 释放版本表/页表/mr。
 * DEREG/release/注销路径移出 idr 并拆链后 kref_put 到此；若仍有
 * ioctl 持引用 (find_mr 获取)，释放延迟到其 put。
 */
void symrdma_mr_release(struct kref *ref)
{
	struct symrdma_mr *mr = container_of(ref, struct symrdma_mr, ref);

	symrdma_version_free(mr);
	kvfree(mr->pages);
	kvfree(mr->groups);
	kfree(mr);
}

/*
 *  并发拆卸仲裁 — 三条拆卸路径 (进程退出 release 回调 /
 * DEREG ioctl / 模块退出) 可能并发到达同一 MR。首个持 dev->mr_lock
 * 置位 torn_down 的是唯一清理者，独占:
 *   - dev->mr_list 摘除 (双重 list_del → 毒指针写 → SLUB 损坏)
 *   - IOMMU 双 IOVA unmap
 *   - kref_put (双重 put → 引用下溢 → 释放后使用)
 * 落败路径不得再触碰任何列表，也不得 put (初始引用只有一份，由
 * 清理者的 put 归还)。调用序: 本函数先于一切列表手术，且均在
 * 无锁上下文调用 (release 阶段 2 / dereg 开头); 调用方保证本 MR
 * 已完成 Step 5 (dev->mr_list 链入) — 两条拆卸路径均只在 ioctl
 * 返回后可达, REG_MR 中途错误路径不经过本函数。
 */
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

	/* 拆卸仲裁 — 进程退出 release 回调并发时，仅首个到者
	 * 清理 (列表摘除/unmap/put)；落败者直接返回，初始引用由清理者
	 * 的 put 归还 (清理者同时负责 idr_remove，见 dev.c/release)。 */
	if (!symrdma_mr_teardown_begin(dev, mr))
		return;

	/* 释放在飞 pin 引用 (探测/转换不需要 — IOMMU 映射
	 * 随拆卸 unmap, 页随引用释放归 OS)。
	 * G2: 先于 mn_detach — detach 置 mr->mm_state=NULL 后
	 * 本函数只能无锁遍历 pin_list, 与在飞 UNPIN ioctl (持 st 临时
	 * 引用, 锁内摘链) 并发 → list 撕裂; detach 前释放则 pin_list
	 * 手术在 st->lock 内串行化 (时序契约见 symrdma_pin_release_all)。 */
	symrdma_pin_release_all(mr);

	/* 从 per-mm notifier 中移除 */
	symrdma_mn_detach(mr);

	/* 取消映射所有页面的双 IOVA (R3: 收敛到 symrdma_unmap_mr_pages) */
	symrdma_unmap_mr_pages(dev, mr, mr->npages);

	/* (归还调用者持有的引用 (idr 移除/创建者所有权) —
	 * 版本表/页表/mr 释放延迟到引用归零 (并发 ioctl 持引用时) */
	kref_put(&mr->ref, symrdma_mr_release);

	pr_info("symrdma: 注销 MR 完成\n");
}
