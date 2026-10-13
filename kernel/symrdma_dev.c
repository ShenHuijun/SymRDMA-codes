/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma_dev.c — /dev/symrdma 字符设备
 *
 * 提供 ioctl 接口用于 IOMMU 级别的 MR 管理和验证:
 *   REG_MR      — 注册 IOMMU MR，创建双 IOVA 映射 (Read + Write)
 *   DEREG_MR    — 注销 MR，清理所有 IOMMU 映射
 *   REMAP       — 重映射单个页面 (哨兵/黑洞/真实)
 *   GET_IOVA    — 获取某页的读写 IOVA 地址 (供 RDMA 测试程序使用)
 *   READ_IOVA   — 通过 IOMMU 读取 4 字节 (Level 1 验证核心)
 *   REPAIR      — 换入修复: 重新解析 VA，若驻留则重映射到真实 PA
 */
#include "symrdma.h"

/* ---- IDR 辅助: MR id 管理 ---- */

/*
 * (查找 + 取引用 — 返回后调用者持有一份引用，保护后续
 * 解引用不被并发 DEREG/release 释放；用毕必须
 * kref_put(&mr->ref, symrdma_mr_release)。
 */
static struct symrdma_mr *symrdma_find_mr(struct symrdma_dev *dev, int mr_id)
{
	struct symrdma_mr *mr;

	spin_lock(&dev->mr_lock);
	mr = idr_find(&dev->mr_idr, mr_id);
	if (mr && !kref_get_unless_zero(&mr->ref))
		mr = NULL;   /* 引用已归零, 正在等待最后释放 */
	spin_unlock(&dev->mr_lock);

	return mr;
}

/*
 * (DEREG 取走所有权 — idr_remove 自身返回指针，"查找 + 移除"
 * 原子完成，消除两个并发 DEREG 同 id 都 find 成功的双重释放。
 * 返回的 mr 携带 idr 持有的引用，由 symrdma_dereg_mr 内 kref_put 归还。
 */
static struct symrdma_mr *symrdma_take_mr(struct symrdma_dev *dev, int mr_id)
{
	struct symrdma_mr *mr;

	spin_lock(&dev->mr_lock);
	/* 仅 MR 属主进程可注销 (同 REMAP/REPAIR 的属主
	 * 检查)。属主检查与 idr_remove 同在 mr_lock 内, 检查与摘除之间
	 * 无窗口。属主不符返回 -EPERM 错误指针, 调用方用 IS_ERR 判别
	 * 透传 (与 NULL=不存在区分) */
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

	/* §4.1: mr_id 写回 MR — 进程退出 release 回调从 idr 移除需要 */
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

/* ---- 文件操作 ---- */

static int symrdma_dev_open(struct inode *inode, struct file *filp)
{
	filp->private_data = container_of(filp->private_data,
					  struct symrdma_dev, miscdev);
	return 0;
}

static int symrdma_dev_release(struct inode *inode, struct file *filp)
{
	return 0;
}

/* ---- ioctl 处理器 ---- */

static long symrdma_dev_ioctl(struct file *filp, unsigned int cmd,
			      unsigned long arg)
{
	struct symrdma_dev *dev = filp->private_data;
	struct symrdma_mr *held = NULL;   /* (find_mr 取到的引用, 出口统一 put */
	struct symrdma_mm_state *held_st = NULL;   /* G2: mm_state_get 取到的引用, 出口统一 put */
	int ret = 0;

	if (!dev)
		return -ENODEV;

	switch (cmd) {

	/* REG_MR: 注册 IOMMU MR */
	case SYMRDMA_IOC_REG_MR: {
		struct symrdma_ioc_reg_mr req;
		struct symrdma_mr *mr;
		int mr_id;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		if (req.va_start == 0 || req.len == 0)
			return -EINVAL;
		/* 仅接受本进程用户地址空间 — 页表遍历按传入 VA
			 * 走 current->mm, 内核地址/跨界范围会被误遍历并映射进
			 * IOMMU domain (DMA 可读写内核内存)。access_ok 检查
			 * 用户段 + 溢出。 */
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
			/* (先移除 idr (取走所有权) 再注销 — 顺序颠倒
			 * 会在 put 之后、remove 之前留窗口，并发 find 可拿到
			 * 已释放的指针 (kref_get_unless_zero 读已释放内存) */
			symrdma_remove_mr_id(dev, mr_id);
			symrdma_dereg_mr(dev, mr);
			return -EFAULT;
		}

		pr_info("symrdma: REG_MR mr_id=%d VA=0x%llx len=%llu\n",
			mr_id, req.va_start, req.len);
		break;
	}

	/* DEREG_MR: 注销 IOMMU MR */
	case SYMRDMA_IOC_DEREG_MR: {
		int mr_id = (int)arg;
		struct symrdma_mr *mr = symrdma_take_mr(dev, mr_id);

		/* 属主不符时 take_mr 返回 -EPERM 错误指针 */
		if (IS_ERR(mr))
			return PTR_ERR(mr);
		if (!mr)
			return -ENOENT;

		symrdma_dereg_mr(dev, mr);

		pr_info("symrdma: DEREG_MR mr_id=%d\n", mr_id);
		return 0;

	}

	/* REMAP: 重映射单个页面 (哨兵/黑洞/真实) */
	case SYMRDMA_IOC_REMAP: {
		struct symrdma_ioc_remap req;
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
		/* 状态变更仅限 MR 属主进程 — REMAP/REPAIR 按属主 mm
		 * 遍历页表, 跨进程调用属于误用/探测 */
		if (mr->mm != current->mm) {
			ret = -EPERM;
			goto out_put;
		}

		{
			/* (+ G1: 版本/状态/映射变更与 notifier 同锁
			 * 串行化, 且锁内复查所有权 — MR 已拆卸 (mm_state=NULL) 或
			 * 并发拆卸已接管时拒绝, 防拆卸 unmap 之后的重映射遗留 PTE
			 * (G1 泄漏面 ②)。修复路径 (orig_pa==0) 由 repair_page 内部
			 * 自持锁 + 同等复查。 orig_pa 读入锁内 (消除锁外读 TOCTOU:
			 * notifier 可在判定与映射之间清零 orig_pa)。
			 * G2: st 临时引用经 symrdma_mm_state_get 原子获取
			 * (拆卸后 NULL → fail-closed, 同原 !st 检查) — 引用保证
			 * st->lock 获取安全; G1 所有权复查语义不变。 */
			struct symrdma_mm_state *st = symrdma_mm_state_get(mr);

			held_st = st;
			if (!st) {
				ret = -ENOENT;
				goto out_put;
			}

			if (req.mode == SYMRDMA_REMAP_REAL &&
			    mr->pages[req.page_idx].orig_pa == 0) {
				/* 缺失页修复: GUP + 锁内重映射/版本翻转
				 * (repair_page 自取临时引用, 本路径不持锁) */
				ret = symrdma_repair_page(dev, mr, req.page_idx);
				if (ret)
					goto out_put;
				goto remap_done;
			}

			spin_lock(&st->lock);
			if (mr->mm_state != st) {
				spin_unlock(&st->lock);
				ret = -ENOENT;
				goto out_put;
			}

			switch (req.mode) {
			case SYMRDMA_REMAP_SENTINEL:
				/* 版本仅在状态转换时翻转 (与 notifier 一致) */
				if (mr->pages[req.page_idx].read_state == PAGE_RESIDENT)
					symrdma_version_inc(mr, req.page_idx);
				symrdma_remap_to_sentinel(dev, mr,
							  req.page_idx, req.page_idx);
				break;
			case SYMRDMA_REMAP_BLACKHOLE:
				symrdma_remap_to_blackhole(dev, mr,
							   req.page_idx, req.page_idx);
				/* 黑洞不改变版本号 — write 路径无 seqlock */
				break;
			case SYMRDMA_REMAP_REAL:
				/* orig_pa 已知 (手动 remap 来回切换场景) → 直接恢复;
				 * 锁内重读 (notifier 同锁清零 orig_pa 的窗口已排除)
				 * 仅状态转换时递增版本 — 对已驻留
				 * 页无条件 inc 会奇变偶, 后续换出再 inc 变奇 → seqlock
				 * 接受哨兵数据。与 SENTINEL 分支对称。 */
				if (mr->pages[req.page_idx].orig_pa != 0) {
					bool was_resident =
						mr->pages[req.page_idx].read_state ==
						PAGE_RESIDENT;

					if (symrdma_remap_to_real(dev, mr,
							req.page_idx,
							mr->pages[req.page_idx].orig_pa)) {
						spin_unlock(&st->lock);
						ret = -EIO;
						goto out_put;
					}
					if (!was_resident)
						symrdma_version_inc(mr, req.page_idx);
				} else {
					/* 判定后、加锁前被 notifier 清零 → 走修复路径;
					 * 先放锁 (repair_page 自持同锁, 不可重入) */
					spin_unlock(&st->lock);
					ret = symrdma_repair_page(dev, mr,
								  req.page_idx);
					if (ret)
						goto out_put;
					goto remap_done;
				}
				break;
			default:
				spin_unlock(&st->lock);
				ret = -EINVAL;
				goto out_put;
			}
			spin_unlock(&st->lock);
		}

remap_done:

		pr_info("symrdma: REMAP mr=%d page=%lu mode=%d\n",
			req.mr_id, (unsigned long)req.page_idx, req.mode);
		break;
	}

	/* GET_IOVA: 获取某页的读写 IOVA (供 RDMA 测试) */
	case SYMRDMA_IOC_GET_IOVA: {
		struct symrdma_ioc_get_iova req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		/* IOVA 布局仅向 MR 属主进程暴露 (否则任意本地
		 * 进程可按小整数 mr_id 探测他人 MR 的地址映射) */
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

	/* READ_IOVA: 通过 IOMMU 读取 4 字节 (Level 1 验证核心)
	 *
	 * 原理: iommu_iova_to_phys(domain, iova) 查询 IOMMU 页表，
	 *       这张表正是 RDMA NIC 做 DMA 时硬件遍历的同一张表。
	 *       此 ioctl 返回的结果即 NIC 会读到的结果。
	 */
	case SYMRDMA_IOC_READ_IOVA: {
		struct symrdma_ioc_read_iova req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		/* 读 MR 内容仅限属主进程 (否则任意本地进程可按
		 * 小整数 mr_id 读取他人 MR 数据) */
		if (mr->mm != current->mm) {
			ret = -EPERM;
			goto out_put;
		}
		/* offset 为 size_t, `offset + 4 > PAGE_SIZE` 在
		 * offset 接近 SIZE_MAX 时加法回绕绕过检查 — 改为减法形式 */
		if (req.offset > PAGE_SIZE - sizeof(u32)) {
			ret = -EINVAL;
			goto out_put;
		}
		/* IOVA 须落在本 MR 的 Read/Write 区间内 — 该接口按
		 * MR 查询 IOMMU 页表, 无界 iova 可读同 domain 内其他 MR 的
		 * 内容 (跨进程信息泄露) */
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

	/* REPAIR: 换入修复
	 *
	 * 重新解析用户 VA → 获取当前物理页 → 重映射两个 IOVA。
	 * 返回 -EAGAIN 表示页面仍被换出。
	 */
	case SYMRDMA_IOC_REPAIR: {
		struct symrdma_ioc_repair req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		pr_info("symrdma: REPAIR ioctl mr_id_in=%d\n",
			(int)req.mr_id);

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr) {
			pr_info("symrdma: REPAIR mr_id=%d 未找到\n",
				(int)req.mr_id);
			return -ENOENT;
		}
		held = mr;
		/* REPAIR 按 mr->mm 做 GUP + 重映射, 仅属主进程合法
		 * (SIR 服务线程运行在 owner 进程内, 同 mm, 不受影响) */
		if (mr->mm != current->mm) {
			pr_info("symrdma: REPAIR mr_id=%d 拒绝 (非属主进程)\n",
				(int)req.mr_id);
			ret = -EPERM;
			goto out_put;
		}

		pr_info("symrdma: REPAIR 调用 repair_page mr=%d page=%lu\n",
			(int)req.mr_id, (unsigned long)req.page_idx);
		ret = symrdma_repair_page(dev, mr, req.page_idx);
		if (ret) {
			pr_info("symrdma: REPAIR 失败 ret=%d\n", ret);
			goto out_put;
		}
		pr_info("symrdma: REPAIR 完成\n");
		break;
	}

	/* REPAIR_RANGE: 区间批量修复 (改进方向)
	 *
	 * 单次 ioctl 修复 [page_idx, page_idx+npages): 整段批量 GUP + 分块
	 * gather 批量 flush (owner 侧逐页 ioctl ~7-10µs/页, 主导开销
	 * 是每页 2 次 strict unmap flush)。out: npages = 实际修复页数 — 部分
	 * 成功 (< 入参) 时仍返回 0, 剩余页由请求方乐观路径重检再触发。
	 * 属主检查同 REPAIR (按 mr->mm GUP)。 */
	case SYMRDMA_IOC_REPAIR_RANGE: {
		struct symrdma_ioc_repair_range req;
		struct symrdma_mr *mr;
		unsigned long repaired = 0;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (mr->mm != current->mm) {
			pr_info("symrdma: REPAIR_RANGE mr_id=%d 拒绝 (非属主进程)\n",
				(int)req.mr_id);
			ret = -EPERM;
			goto out_put;
		}

		ret = symrdma_repair_range(dev, mr, req.page_idx, req.npages,
					   &repaired);
		if (ret && repaired == 0) {
			pr_info("symrdma: REPAIR_RANGE mr=%d [%lu,+%lu) 失败 ret=%d\n",
				(int)req.mr_id, (unsigned long)req.page_idx,
				(unsigned long)req.npages, ret);
			goto out_put;
		}
		/* 成功 (含部分成功) → 回写实际修复页数 */
		req.npages = repaired;
		if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
			ret = -EFAULT;
			goto out_put;
		}
		break;
	}

	/* MAPBENCH (cmd 12, L19 B 轴): 组粒度映射微基准 —
	 *  逐页 vs Phase 1 段批 vs Phase 2 超页三形态计时。
	 * 属主校验同 REPAIR_RANGE; 结果回写 ns_total/map_ops。 */
	case SYMRDMA_IOC_MAPBENCH: {
		struct symrdma_ioc_mapbench req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;

		mr = symrdma_find_mr(dev, req.mr_id);
		if (!mr)
			return -ENOENT;
		held = mr;
		if (mr->mm != current->mm) {
			pr_info("symrdma: MAPBENCH mr_id=%d 拒绝 (非属主进程)\n",
				(int)req.mr_id);
			ret = -EPERM;
			goto out_put;
		}

		ret = symrdma_iommu_mapbench(dev, mr, &req);
		if (ret) {
			pr_info("symrdma: MAPBENCH mr=%d mode=%d 失败 ret=%d\n",
				(int)req.mr_id, req.mode, ret);
			goto out_put;
		}
		if (copy_to_user((void __user *)arg, &req, sizeof(req))) {
			ret = -EFAULT;
			goto out_put;
		}
		break;
	}

	/* GET_VERSION: 读取版本号 (论文 §3.1.2 remote seqlock)
	 *
	 * 奇数=驻留, 偶数=缺失。P1: 用户态 seqlock 检查通道。
	 */
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

		/* 读表与 bind 切换 (st->lock 内) 互斥 — 防止读
		 * 悬空 kzalloc 表指针 (bind 在同锁下释放旧表)
		 * G2: st 临时引用替代裸读 — 锁获取安全。
		 * st==NULL (已拆卸) 退化无锁读: bind 对拆卸 MR fail-closed
		 * (本版同步闭合), notifier/repair/UNPIN 补完对拆卸 MR 均不可达
		 * ⇒ 表指针冻结, mr 存活 (kref) ⇒ version_table 稳定。 */
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

	/* SET_VERSION_PAGE (论文 §3.1.2 Version MR):
	 * 版本表绑定用户 pinned 页 — 用户侧注册为普通 MR (REMOTE_READ)
	 * → 远端 RDMA 直读版本表 (替代 CPU ioctl 查询)。 */
	case SYMRDMA_IOC_SET_VERSION_PAGE: {
		struct symrdma_ioc_set_version_page req;
		struct symrdma_mr *mr;

		if (copy_from_user(&req, (void __user *)arg, sizeof(req)))
			return -EFAULT;
		/* 版本表 VA 须属本进程用户空间 (绑定按 current->mm
		 * follow 页表); 属主校验同 REMAP/REPAIR */
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

		pr_info("symrdma: SET_VERSION_PAGE mr=%d va=0x%llx\n",
			req.mr_id, req.version_va);
		break;
	}

	/* PIN_PAGES (flush-before-unmap 屏障): 本地缓冲 DMA 在飞
	 * pin — GUP 取页引用 + IOMMU 保持真实 PA + 在飞标记。notifier 对
	 * 在飞页延迟哨兵化 (论文 §3.2 临时 pin 语义的粘性实现)。 */
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
		/* pin/探测按属主页表进行 (GUP/follow_page 按 current->mm) —
		 * 跨进程调用属误用 (同 REPAIR 属主检查) */
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
	/* (归还 find_mr 获取的引用 */
	if (held)
		kref_put(&held->ref, symrdma_mr_release);
	/* G2: 归还 mm_state 临时引用 (REMAP/GET_VERSION 成功 get 的路径;
	 * put 可睡眠 — ioctl 进程上下文, 无锁持有) */
	if (held_st)
		symrdma_mm_state_put(held_st);
	return ret;
}

static const struct file_operations symrdma_dev_fops = {
	.owner          = THIS_MODULE,
	.open           = symrdma_dev_open,
	.release        = symrdma_dev_release,
	.unlocked_ioctl = symrdma_dev_ioctl,
};

/* ---- 设备初始化 / 清理 ---- */

int symrdma_dev_init(struct symrdma_dev *dev)
{
	int ret;

	dev->miscdev.minor = MISC_DYNAMIC_MINOR;
	dev->miscdev.name  = "symrdma";
	dev->miscdev.fops  = &symrdma_dev_fops;
	dev->miscdev.mode  = 0666;

	ret = misc_register(&dev->miscdev);
	if (ret)
		pr_err("symrdma: 注册 /dev/symrdma 失败: %d\n", ret);
	else
		pr_info("symrdma: /dev/symrdma 已注册\n");

	return ret;
}

void symrdma_dev_cleanup(struct symrdma_dev *dev)
{
	misc_deregister(&dev->miscdev);
	pr_info("symrdma: /dev/symrdma 已注销\n");
}
