/* SPDX-License-Identifier: GPL-2.0 */
/*
 * symrdma_proc.c — /proc/symrdma 调试接口
 *
 * 提供模块状态、活跃 MR 列表、逐页状态的查看。
 */
#include "symrdma.h"

static int symrdma_proc_show(struct seq_file *m, void *v)
{
	struct symrdma_dev *dev = m->private;
	struct symrdma_mr *mr;
	int count;

	if (!dev) {
		seq_puts(m, "symrdma: 未初始化\n");
		return 0;
	}

	seq_puts(m, "=== SymRDMA 设备状态 ===\n");
	seq_printf(m, "  PCI 设备:      %s\n",
		   dev->pdev ? pci_name(dev->pdev) : "无 (VERIFY 模式)");
	seq_printf(m, "  Domain 模式:   %s\n",
		   dev->domain_mode == SYMRDMA_DOMAIN_VERIFY ?
		   "VERIFY (自建 domain)" : "NIC (mlx5 domain)");
	seq_printf(m, "  IOMMU domain:  %p\n", dev->iommu_domain);
	seq_printf(m, "  IOMMU pgsize:  %lu\n", dev->iommu_pgsize);
	seq_printf(m, "  哨兵页 PA:     0x%llx\n", dev->sentinel_pa);
	seq_printf(m, "  黑洞页 PA:     0x%llx\n", dev->blackhole_pa);

	spin_lock(&dev->mr_lock);
	count = dev->mr_count;
	spin_unlock(&dev->mr_lock);
	seq_printf(m, "  活跃 MR 数:    %d\n", count);

	seq_puts(m, "\n--- 统计 (swap-out 验证) ---\n");
	seq_printf(m, "  notifier 回调:  %lld\n",
		   (long long)atomic64_read(&dev->stats.notifier_calls));
	seq_printf(m, "  换出重映射页:   %lld\n",
		   (long long)atomic64_read(&dev->stats.pages_swapped_out));
	seq_printf(m, "  REPAIR 成功:    %lld\n",
		   (long long)atomic64_read(&dev->stats.repair_ok));
	seq_printf(m, "  REPAIR 失败:    %lld\n",
		   (long long)atomic64_read(&dev->stats.repair_fail));
	seq_printf(m, "  进程退出释放:   %lld 次 / %lld MR (论文 §4.1)\n",
		   (long long)atomic64_read(&dev->stats.process_exits),
		   (long long)atomic64_read(&dev->stats.released_mrs));
	seq_puts(m, "\n--- 统计 (v0.23.1 外部页失效源调查) ---\n");
	seq_printf(m, "  失效事件记录:   %lld\n",
		   (long long)atomic64_read(&dev->stats.notif_events));
	seq_printf(m, "  驻留失效恢复:   %lld (迁移/COW/NUMA 等, 已直接重映射)\n",
		   (long long)atomic64_read(&dev->stats.resident_restored));
	seq_printf(m, "  确认真缺失:     %lld (保持哨兵, REPAIR 兑底)\n",
		   (long long)atomic64_read(&dev->stats.resident_absent));
	seq_printf(m, "  pending 溢出:   %lld\n",
		   (long long)atomic64_read(&dev->stats.pending_overflow));
	seq_puts(m, "\n--- 统计 (v0.25.0 flush-before-unmap 屏障) ---\n");
	seq_printf(m, "  在飞 pin 页:    %lld (预算 %d 页/MR)\n",
		   (long long)atomic64_read(&dev->stats.pin_pages),
		   SYMRDMA_PIN_BUDGET_PAGES);
	seq_printf(m, "  PIN 成功区间:   %lld\n",
		   (long long)atomic64_read(&dev->stats.pin_ok));
	seq_printf(m, "  PIN 预算拒绝:   %lld\n",
		   (long long)atomic64_read(&dev->stats.pin_enospc));
	seq_printf(m, "  延迟哨兵化页:   %lld (notifier 对在飞页跳过)\n",
		   (long long)atomic64_read(&dev->stats.pin_deferred));
	seq_printf(m, "  unpin 补完转换: %lld (换出/PA 变化补完)\n",
		   (long long)atomic64_read(&dev->stats.pin_transitions));

	seq_puts(m, "\n--- 统计 (v0.38.0 组粒度映射) ---\n");
	seq_printf(m, "  组机制:         %s (iommu_huge 参数 + 2MB 特殊区)\n",
		   dev->huge_ok ? "开" : "关");
	seq_printf(m, "  注册提升驻留组: %lld (THP/PUD 2MB 真实超页)\n",
		   (long long)atomic64_read(&dev->stats.huge_resident));
	seq_printf(m, "  注册提升缺失组: %lld (哨兵区/黑洞区超页)\n",
		   (long long)atomic64_read(&dev->stats.huge_absent));
	seq_printf(m, "  组降级:         %lld (2MB→512×4KB)\n",
		   (long long)atomic64_read(&dev->stats.group_demotes));
	seq_printf(m, "  降级失败:       %lld (fail-closed 单页兑底)\n",
		   (long long)atomic64_read(&dev->stats.demote_fail));
	seq_printf(m, "  修复路径组提升: %lld (含等价跳过)\n",
		   (long long)atomic64_read(&dev->stats.group_repromote));

	if (!list_empty(&dev->mr_list)) {
		unsigned long i;
		seq_puts(m, "\n--- 活跃内存区域 ---\n");
		/* G2 (v0.31.0): mm_state_lock 全程持有 — 阻塞 unlink
		 * (mm_state 置 NULL) 与拆卸路径的附着引用 put, mr->mm_state
		 * 读取与 st->lock 获取之间 st 不可能归零释放 (附着引用 ≥ 1);
		 * 同时 dev->mr_list/mm_states 稳定 (attach/dereg 均需 mr_lock
		 * 或 mm_state_lock)。锁序 mr_lock → mm_state_lock → st->lock
		 * 与 attach/detach/release 同向, 无反向路径 (release 刻意不在
		 * st->lock 内取 mr_lock — A8 注记)。 */
		spin_lock(&dev->mm_state_lock);
		spin_lock(&dev->mr_lock);
		list_for_each_entry(mr, &dev->mr_list, list) {
			seq_printf(m, "  MR: VA 0x%llx-0x%llx npages=%lu\n",
				   mr->va_start, mr->va_end, mr->npages);
			seq_printf(m, "       Read  IOVA: 0x%llx\n", mr->read_iova);
			seq_printf(m, "       Write IOVA: 0x%llx\n", mr->write_iova);

			/* 逐页状态 (最多显示 8 页) — v0.24.6: 读表与 bind 切换
			 * 同锁 (st->lock), 防悬空 kzalloc 表指针 */
			seq_puts(m, "       页状态 [idx] read write:\n");
			if (mr->mm_state)
				spin_lock(&mr->mm_state->lock);
			for (i = 0; i < min_t(unsigned long, mr->npages, 8); i++) {
				u32 ver = symrdma_version_read(mr, i);
				seq_printf(m, "         [%lu] %s / %s  (ver=%u %s)\n",
					   i,
					   mr->pages[i].read_state == PAGE_RESIDENT ?
					   "驻留" : "哨兵",
					   mr->pages[i].write_state == PAGE_RESIDENT ?
					   "驻留" : "黑洞",
					   ver, (ver & 1) ? "奇数(有效)" : "偶数(无效)");
			}
			if (mr->mm_state)
				spin_unlock(&mr->mm_state->lock);
			if (mr->npages > 8)
				seq_printf(m, "         ... (%lu 页省略)\n",
					   mr->npages - 8);
		}
		spin_unlock(&dev->mr_lock);
		spin_unlock(&dev->mm_state_lock);
	}

	/* v0.23.1: notifier 取证环形缓冲 (外部页失效源定位:
	 * comm/pid/range/调用栈 — 栈顶符号即失效源, 如
	 * change_prot_numa=NUMA 均衡 / collapse_huge_page=THP /
	 * access_remote_vm=proc/mem 读取 (EDR 嫌疑) 等) */
	{
		unsigned int k, idx;
		bool shown = false;

		spin_lock(&dev->notif_lock);
		for (k = 0; k < SYMRDMA_NOTIF_RING_SIZE; k++) {
			const struct symrdma_notif_event *ev;
			unsigned int f;

			idx = (dev->notif_head + k) &
			      (SYMRDMA_NOTIF_RING_SIZE - 1);
			ev = &dev->notif_ring[idx];
			if (ev->jiffies == 0)
				continue;
			if (!shown) {
				seq_puts(m, "\n--- notifier 取证 (最近 64 次, 老→新) ---\n");
				seq_printf(m, "%-12s %-8s %-24s %8s  %s\n",
					   "age(ms)", "pid", "comm",
					   "pages", "range / 调用栈");
				shown = true;
			}
			seq_printf(m, "%-12u %-8u %-24s %8u  [0x%lx-0x%lx]",
				   jiffies_to_msecs(jiffies - ev->jiffies),
				   ev->pid, ev->comm, ev->npages,
				   ev->start, ev->end);
			for (f = 0; f < ev->nr_stack; f++)
				seq_printf(m, " %pS", (void *)ev->stack[f]);
			seq_putc(m, '\n');
		}
		spin_unlock(&dev->notif_lock);
	}

	return 0;
}

static int symrdma_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, symrdma_proc_show, PDE_DATA(inode));
}

static const struct proc_ops symrdma_proc_fops = {
	.proc_open    = symrdma_proc_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

int symrdma_proc_init(struct symrdma_dev *dev)
{
	dev->proc_entry = proc_create_data("symrdma", 0444, NULL,
					   &symrdma_proc_fops, dev);
	if (!dev->proc_entry)
		return -ENOMEM;
	return 0;
}

void symrdma_proc_cleanup(struct symrdma_dev *dev)
{
	if (dev->proc_entry)
		proc_remove(dev->proc_entry);
}
