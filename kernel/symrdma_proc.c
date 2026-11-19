/* SPDX-License-Identifier: GPL-2.0 */

#include "symrdma.h"

static int symrdma_proc_show(struct seq_file *m, void *v)
{
	struct symrdma_dev *dev = m->private;
	struct symrdma_mr *mr;
	int count;

	if (!dev) {
		seq_puts(m, "symrdma: not initialized\n");
		return 0;
	}

	seq_puts(m, "=== SymRDMA device state ===\n");
	seq_printf(m, "  PCI device:    %s\n",
		   dev->pdev ? pci_name(dev->pdev) : "none (VERIFY mode)");
	seq_printf(m, "  Domain mode:   %s\n",
		   dev->domain_mode == SYMRDMA_DOMAIN_VERIFY ?
		   "VERIFY (own domain)" : "NIC (mlx5 domain)");
	seq_printf(m, "  IOMMU domain:  %p\n", dev->iommu_domain);
	seq_printf(m, "  IOMMU pgsize:  %lu\n", dev->iommu_pgsize);
	seq_printf(m, "  Sentinel page PA:  0x%llx\n", dev->sentinel_pa);
	seq_printf(m, "  Blackhole page PA: 0x%llx\n", dev->blackhole_pa);

	spin_lock(&dev->mr_lock);
	count = dev->mr_count;
	spin_unlock(&dev->mr_lock);
	seq_printf(m, "  active MRs:  %d\n", count);

	seq_puts(m, "\n--- stats (swap-out verification) ---\n");
	seq_printf(m, "  notifier callbacks: %lld\n",
		   (long long)atomic64_read(&dev->stats.notifier_calls));
	seq_printf(m, "  pages swapped out:  %lld\n",
		   (long long)atomic64_read(&dev->stats.pages_swapped_out));
	seq_printf(m, "  REPAIR ok:      %lld\n",
		   (long long)atomic64_read(&dev->stats.repair_ok));
	seq_printf(m, "  REPAIR fail:    %lld\n",
		   (long long)atomic64_read(&dev->stats.repair_fail));
	seq_printf(m, "  REPAIR partial: %lld\n",
		   (long long)atomic64_read(&dev->stats.repair_partial));
	seq_printf(m, "  process exits:  %lld / %lld MRs (paper §4.1)\n",
		   (long long)atomic64_read(&dev->stats.process_exits),
		   (long long)atomic64_read(&dev->stats.released_mrs));
	seq_puts(m, "\n--- stats (external invalidation sources) ---\n");
	seq_printf(m, "  invalidation events: %lld\n",
		   (long long)atomic64_read(&dev->stats.notif_events));
	seq_printf(m, "  resident restored:  %lld (migration/COW/NUMA, remapped in place)\n",
		   (long long)atomic64_read(&dev->stats.resident_restored));
	seq_printf(m, "  truly absent:   %lld (kept sentinel, REPAIR fallback)\n",
		   (long long)atomic64_read(&dev->stats.resident_absent));
	seq_printf(m, "  pending overflow: %lld\n",
		   (long long)atomic64_read(&dev->stats.pending_overflow));
	seq_puts(m, "\n--- stats (flush-before-unmap barrier) ---\n");
	seq_printf(m, "  pinned in-flight:   %lld (budget %d pages/MR)\n",
		   (long long)atomic64_read(&dev->stats.pin_pages),
		   SYMRDMA_PIN_BUDGET_PAGES);
	seq_printf(m, "  PIN spans ok:   %lld\n",
		   (long long)atomic64_read(&dev->stats.pin_ok));
	seq_printf(m, "  PIN budget rejects: %lld\n",
		   (long long)atomic64_read(&dev->stats.pin_enospc));
	seq_printf(m, "  deferred sentinel:  %lld (notifier skips in-flight pages)\n",
		   (long long)atomic64_read(&dev->stats.pin_deferred));
	seq_printf(m, "  unpin completions:  %lld (swap-out / PA change)\n",
		   (long long)atomic64_read(&dev->stats.pin_transitions));

	seq_puts(m, "\n--- stats (group-granularity mapping) ---\n");
	seq_printf(m, "  group mode:     %s (iommu_huge param + 2MB regions)\n",
		   dev->huge_ok ? "on" : "off");
	seq_printf(m, "  register-promoted resident groups: %lld (real THP/PUD 2MB pages)\n",
		   (long long)atomic64_read(&dev->stats.huge_resident));
	seq_printf(m, "  register-promoted absent groups:  %lld (sentinel/blackhole huge pages)\n",
		   (long long)atomic64_read(&dev->stats.huge_absent));
	seq_printf(m, "  group demotes:  %lld (2MB→512x4KB)\n",
		   (long long)atomic64_read(&dev->stats.group_demotes));
	seq_printf(m, "  demote failures: %lld (fail-closed per-page fallback)\n",
		   (long long)atomic64_read(&dev->stats.demote_fail));
	seq_printf(m, "  repair-path group re-promotes: %lld (incl. equivalent skips)\n",
		   (long long)atomic64_read(&dev->stats.group_repromote));
	seq_printf(m, "  budget stops:   %lld (per-range budget, prefix at segment edge)\n",
		   (long long)atomic64_read(&dev->stats.repair_budget_stop));
	seq_printf(m, "  repair sync time: last %lld µs / max %lld µs\n",
		   (long long)atomic64_read(&dev->stats.repair_sync_us_last),
		   (long long)atomic64_read(&dev->stats.repair_sync_us_max));

	seq_puts(m, "\n--- stats (diagnostics, off by default, always 0) ---\n");
	seq_printf(m, "  state divergence: %lld (recheck when state_assert on; parks the page fail-closed)\n",
		   (long long)atomic64_read(&dev->stats.state_divergence));
	seq_puts(m, "\n--- stats (backing observations, hint layer) ---\n");
	seq_printf(m, "  absent:      %lld (no page / swapped out)\n",
		   (long long)atomic64_read(&dev->stats.probe_absent));
	seq_printf(m, "  not ours:    %lld (a page is back, but not the one recorded)\n",
		   (long long)atomic64_read(&dev->stats.probe_stale));
	seq_printf(m, "  unmappable:  %lld (read-only / protnone / zero page)\n",
		   (long long)atomic64_read(&dev->stats.probe_unmappable));
	seq_printf(m, "  special pfn: %lld\n",
		   (long long)atomic64_read(&dev->stats.probe_special));
	seq_printf(m, "  group overlay inconsistent: %lld\n",
		   (long long)atomic64_read(&dev->stats.group_inconsistent));
	seq_printf(m, "  GUP refusals: pin %lld / repair short %lld\n",
		   (long long)atomic64_read(&dev->stats.gup_pin_fail),
		   (long long)atomic64_read(&dev->stats.gup_repair_short));

	if (!list_empty(&dev->mr_list)) {
		unsigned long i;
		seq_puts(m, "\n--- active memory regions ---\n");

		spin_lock(&dev->mm_state_lock);
		spin_lock(&dev->mr_lock);
		list_for_each_entry(mr, &dev->mr_list, list) {
			seq_printf(m, "  MR: VA 0x%llx-0x%llx npages=%lu\n",
				   mr->va_start, mr->va_end, mr->npages);
			seq_printf(m, "       Read  IOVA: 0x%llx\n", mr->read_iova);
			seq_printf(m, "       Write IOVA: 0x%llx\n", mr->write_iova);

			seq_puts(m, "       page state [idx] read write:\n");
			if (mr->mm_state)
				spin_lock(&mr->mm_state->lock);
			for (i = 0; i < min_t(unsigned long, mr->npages, 8); i++) {
				const struct symrdma_page *pe = &mr->pages[i];

				seq_printf(m, "         [%lu] %s / %s  (gen=%u cause=%u seq=%llu %s)\n",
					   i,
					   symrdma_map_name(pe->rmap),
					   symrdma_map_name(pe->wmap),
					   pe->gen, pe->cause,
					   (unsigned long long)pe->cause_seq,
					   (pe->gen & 1) ? "odd(real)"
							 : "even(no real)");
			}
			if (mr->mm_state)
				spin_unlock(&mr->mm_state->lock);
			if (mr->npages > 8)
				seq_printf(m, "         ... (%lu pages omitted)\n",
					   mr->npages - 8);
		}
		spin_unlock(&dev->mr_lock);
		spin_unlock(&dev->mm_state_lock);
	}

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
				seq_puts(m, "\n--- notifier forensics (last 64, oldest→newest) ---\n");
				seq_printf(m, "%-12s %-8s %-24s %8s  %s\n",
					   "age(ms)", "pid", "comm",
					   "pages", "range / call stack");
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

	{
		static const char *const cause_names[] = {
			"notifier", "realign", "repair", "pin", "park", "setup",
			"forced",
		};
		unsigned int k, idx;
		bool shown = false;

		spin_lock(&dev->trans_lock);
		for (k = 0; k < SYMRDMA_TRANS_RING_SIZE; k++) {
			const struct symrdma_trans_event *ev;
			u8 c, r, w;

			idx = (dev->trans_head + k) &
				      (SYMRDMA_TRANS_RING_SIZE - 1);
			ev = &dev->trans_ring[idx];
			if (ev->jiffies == 0)
				continue;
			if (!shown) {
				seq_puts(m, "\n--- transition forensics (last 256, oldest→newest) ---\n");
				seq_printf(m, "%-10s %-6s %-10s %-9s %-10s %s\n",
					   "age(ms)", "mr", "page", "cause",
					   "gen/seq", "rmap/wmap");
				shown = true;
			}
			c = ev->cause;
			r = ev->rmap;
			w = ev->wmap;
			seq_printf(m, "%-10u %-6d %-10u %-9s %u/%-10llu %s/%s\n",
				   jiffies_to_msecs(jiffies - ev->jiffies),
				   ev->mr_id, ev->page_idx,
				   c < ARRAY_SIZE(cause_names) ?
					   cause_names[c] : "?",
				   ev->gen,
				   (unsigned long long)ev->cause_seq,
				   symrdma_map_name(r),
				   symrdma_map_name(w));
		}
		spin_unlock(&dev->trans_lock);
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
