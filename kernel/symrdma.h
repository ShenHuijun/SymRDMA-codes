/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _SYMRDMA_H
#define _SYMRDMA_H

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/slab.h>
#include <linux/miscdevice.h>
#include <linux/uaccess.h>
#include <uapi/asm-generic/ioctl.h>
#include <linux/fs.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/version.h>
#include <linux/iommu.h>
#include <linux/pci.h>
#include <linux/mmu_notifier.h>
#include <linux/hashtable.h>
#include <linux/spinlock.h>
#include <linux/workqueue.h>
#include <linux/stacktrace.h>
#include <linux/sched.h>
#include <linux/mutex.h>
#include <linux/kref.h>
#include <linux/atomic.h>
#include <linux/idr.h>
#include <linux/jump_label.h>
#include <asm/page.h>

#include "../common/symrdma_abi.h"
#include "symrdma_test_hook.h"

enum symrdma_domain_mode {
	SYMRDMA_DOMAIN_VERIFY = 0,
	SYMRDMA_DOMAIN_NIC    = 1,
};

struct symrdma_dev;
struct symrdma_mr;
struct symrdma_page;
struct scatterlist;
struct symrdma_mm_state;

#define SYMRDMA_NOTIF_RING_SIZE  64
#define SYMRDMA_NOTIF_STACK_DEPTH 6

struct symrdma_notif_event {
	u64           jiffies;
	u32           pid;
	u32           tgid;
	u32           npages;
	u32           nr_stack;
	unsigned long start;
	unsigned long end;
	unsigned long stack[SYMRDMA_NOTIF_STACK_DEPTH];
	char          comm[TASK_COMM_LEN];
};

#define SYMRDMA_PENDING_NR 16
struct symrdma_pending_range {
	unsigned long start, end;
};

#define SYMRDMA_TRANS_RING_SIZE 256
struct symrdma_trans_event {
	u64 jiffies;
	int mr_id;
	u32 page_idx;
	u64 cause_seq;
	u32 gen;
	u8  cause;
	u8  rmap;
	u8  wmap;
	u8  pad0;
};

struct symrdma_pin_node {
	unsigned long           idx0;
	unsigned long           nr;
	struct page             **pages;
	struct list_head        node;
};

struct symrdma_mm_state {
	struct mmu_notifier     mn;
	struct symrdma_dev      *dev;
	struct mm_struct        *mm;
	struct list_head        mr_list;
	spinlock_t              lock;
	struct list_head        node;
	int                     mr_count;

	struct kref             ref;
	bool                    detached;

	struct symrdma_pending_range pending[SYMRDMA_PENDING_NR];
	int                     pending_head;
	int                     notif_depth;
	bool                    work_queued;
	struct work_struct      hint_work;
	struct rcu_head         rcu;
};

/*
 * One open file. The device answers census rows through read(), so an open
 * file owns the pending rows; nothing is carried across opens and no cursor
 * lives in the kernel (the caller iterates chunks).
 */
struct symrdma_file {
	struct symrdma_dev          *dev;
	struct symrdma_census_page  *rows;
	u32                          len;   /* bytes pending in rows */
};

struct symrdma_dev {
	struct pci_dev          *pdev;
	struct iommu_domain     *iommu_domain;
	struct device           *dev;
	int                     domain_mode;

	struct page             *sentinel_page;
	u64                     sentinel_pa;

	struct page             *blackhole_page;
	u64                     blackhole_pa;

	struct page             *sentinel_region;
	u64                     sentinel_region_pa;
	struct page             *blackhole_region;
	u64                     blackhole_region_pa;
	int                     huge_ok;
	int                     repair_sg;

	int                     repair_budget_us;
	unsigned long           repair_chunk;

#define SYMRDMA_REPAIR_SEG             128
#define SYMRDMA_REPAIR_CHUNK           16
#define SYMRDMA_REPAIR_CHUNK_MIN       16

	struct list_head        mr_list;
	spinlock_t              mr_lock;
	int                     mr_count;

	struct list_head        mm_states;
	spinlock_t              mm_state_lock;

	struct idr              mr_idr;
	int                     mr_id_counter;

	struct mutex            attach_lock;

	struct miscdevice       miscdev;

	struct proc_dir_entry   *proc_entry;

	struct {
		atomic64_t notifier_calls;
		atomic64_t pages_swapped_out;
		atomic64_t repair_ok;
		atomic64_t repair_fail;
		atomic64_t process_exits;
		atomic64_t released_mrs;
		atomic64_t notif_events;
		atomic64_t resident_restored;
		atomic64_t resident_absent;
		atomic64_t pending_overflow;
		atomic64_t pin_pages;
		atomic64_t pin_ok;
		atomic64_t pin_enospc;
		atomic64_t pin_deferred;
		atomic64_t pin_transitions;
		atomic64_t huge_resident;
		atomic64_t huge_absent;
		atomic64_t group_demotes;
		atomic64_t demote_fail;
		atomic64_t group_repromote;
		atomic64_t repair_budget_stop;
		atomic64_t repair_partial;
		atomic64_t repair_sync_us_last;
		atomic64_t repair_sync_us_max;
		atomic64_t state_divergence;
		atomic64_t probe_absent;
		atomic64_t probe_stale;
		atomic64_t probe_unmappable;
		atomic64_t probe_special;
		atomic64_t group_inconsistent;
		atomic64_t gup_pin_fail;
		atomic64_t gup_repair_short;
	} stats;

	struct symrdma_notif_event notif_ring[SYMRDMA_NOTIF_RING_SIZE];
	unsigned int              notif_head;
	spinlock_t                notif_lock;

	struct symrdma_trans_event trans_ring[SYMRDMA_TRANS_RING_SIZE];
	unsigned int               trans_head;
	spinlock_t                 trans_lock;

	unsigned long           iommu_pgsize;
};

struct symrdma_mr {
	struct list_head        list;
	struct list_head        mm_node;
	struct symrdma_dev      *dev;

	u64                     va_start;
	u64                     va_end;

	u64                     read_iova;
	u64                     write_iova;
	u64                     write_iova_offset;

	unsigned long           npages;

	u32                     *version_table;
	struct page             **version_pages;
	unsigned long           version_npages;
	unsigned long           version_vt_pages;

	struct mm_struct        *mm;

	int                     mr_id;

	struct kref             ref;

	struct symrdma_mm_state *mm_state;

	bool                    torn_down;

	/* MR-level transition counter; pages[].cause_seq is its snapshot */
	u64                     trans_seq;

	struct symrdma_page    *pages;

	struct symrdma_group_entry *groups;

	struct list_head        pin_list;
	unsigned long           pinned_pages;
};

#define SYMRDMA_GROUP_SHIFT  9
#define SYMRDMA_GROUP_PAGES  (1UL << SYMRDMA_GROUP_SHIFT)
#define SYMRDMA_GROUP_SIZE   (SYMRDMA_GROUP_PAGES << PAGE_SHIFT)

enum symrdma_group_state {
	GRP_NONE     = 0,
	GRP_RESIDENT = 1,
	GRP_ABSENT   = 2,
};

struct symrdma_group_entry {
	phys_addr_t             base_pa;
	enum symrdma_group_state state;
};

/*
 * Mapping target of one IOVA slot.  This is the target of the mapping, not
 * "the state of the page"; SYMRDMA_MAP_UNMAPPED is the zero value, so a
 * freshly zeroed pages[] says "nothing published yet" and never looks like a
 * resident page.
 */
static inline const char *symrdma_map_name(u8 m)
{
	switch (m) {
	case SYMRDMA_MAP_REAL:
		return "real";
	case SYMRDMA_MAP_SENTINEL:
		return "sentinel";
	case SYMRDMA_MAP_BLACKHOLE:
		return "blackhole";
	default:
		return "unmapped";
	}
}

/* One page's entry in the single state authority (mr->pages[]). */
struct symrdma_page {
	phys_addr_t             pa;        /* last published real PA (kept by demote) */
	u64                     cause_seq; /* mr->trans_seq at the last transition */
	u32                     gen;       /* parity: read IOVA points at REAL */
	u32                     probe_gen; /* gen of the last observation, +1 (0 = never) */
	u16                     dma_ref;   /* in-flight DMA references (demote barrier) */
	u8                      rmap;      /* enum symrdma_map, read IOVA */
	u8                      wmap;      /* enum symrdma_map, write IOVA */
	u8                      cause;     /* enum symrdma_trans_cause */
};

/* A lock-free observation of one page, stamped with the gen it was taken at. */
struct symrdma_obs {
	u32                     gen;
	phys_addr_t             pa;
};

/* What the CPU page tables say about a page (backing_probe() output). */
enum symrdma_backing {
	SBK_REAL       = 0,  /* present, writable, same PA as the last real one */
	SBK_REALIGN    = 1,  /* present but not the page we recorded */
	SBK_ABSENT     = 2,  /* no page at all (swapped out / never populated) */
	SBK_UNMAPPABLE = 3,  /* present but no DMA can reach it (RO/protnone/zero) */
	SBK_SPECIAL    = 4,  /* a mapping no ordinary page backs */
	SBK_ERROR      = 5,
};

enum symrdma_probe_reason {
	SPB_R_NONE = 0,
	SPB_R_NO_PTE,
	SPB_R_SWAPPED,
	SPB_R_PROTNONE,
	SPB_R_READONLY,
	SPB_R_ZERO,
	SPB_R_SPECIAL_PFN,
	SPB_R_BAD_TABLE,
};

/* Intent of a probe: HINT has no side effects, DMA_RW may break COW. */
enum symrdma_probe_intent {
	SPB_HINT   = 0,
	SPB_DMA_RW = 1,
};

/* The largest index array a batch verb accepts (stack bookkeeping). */
#define SYMRDMA_BATCH_MAX 128

int  symrdma_iommu_init(struct symrdma_dev *dev, int mode);
void symrdma_iommu_cleanup(struct symrdma_dev *dev);
int  symrdma_iommu_map_page(struct symrdma_dev *dev, unsigned long iova,
			    phys_addr_t pa, int prot);
void symrdma_iommu_unmap_page(struct symrdma_dev *dev, unsigned long iova);
void symrdma_unmap_mr_pages(struct symrdma_dev *dev, struct symrdma_mr *mr,
			    unsigned long npages);
void symrdma_unmap_mr_pages_touched(struct symrdma_dev *dev,
				    struct symrdma_mr *mr);
int  symrdma_iommu_read_iova(struct symrdma_dev *dev, struct symrdma_mr *mr,
			     u64 iova, size_t offset, u32 *out);
int  symrdma_repair_page(struct symrdma_dev *dev, struct symrdma_mr *mr,
			 unsigned long page_idx);
/* What a range repair actually did. `repaired < npages` means the range is NOT
 * fully re-mapped (budget stop / chunk give-up / GUP short) and the caller must
 * not hand the range on as if it were: the delivery invariant is "never deliver
 * sentinel bytes as SUCCESS". gens are observations of the first/last page of the
 * requested range — an observation, not an authority. */
struct symrdma_repair_outcome {
	unsigned long repaired;
	unsigned int  cause;
	unsigned int  gen_before_lo;
	unsigned int  gen_after_hi;
};

int  symrdma_repair_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
			  unsigned long page_idx, unsigned long npages,
			  struct symrdma_repair_outcome *out);

/*
 * State authority (kernel/symrdma_page.c): the only code that writes
 * mr->pages[] or the version table.  Every verb below requires the caller to
 * hold mr->mm_state->lock; the ordering, the permissions per target, the
 * dma_ref barrier and the version mirror all live inside the verb, not at the
 * call site.
 */
int  symrdma_mr_map_pages(struct symrdma_dev *dev, struct symrdma_mr *mr,
			  struct mm_struct *mm);
u32  symrdma_page_gen(const struct symrdma_mr *mr, unsigned long idx);
int  symrdma_page_demote_locked(struct symrdma_mr *mr, unsigned long idx,
				u8 rmap, u8 wmap, u8 cause);
int  symrdma_page_promote_locked(struct symrdma_mr *mr, unsigned long idx,
				 struct symrdma_obs *obs, u8 cause);
int  symrdma_pages_demote_locked(struct symrdma_mr *mr,
				 const unsigned long *idx, unsigned long n,
				 u8 rmap, u8 wmap, u8 cause,
				 unsigned long *done, unsigned long *deferred);
int  symrdma_pages_promote_locked(struct symrdma_mr *mr, unsigned long first,
				  unsigned long n, struct symrdma_obs *obs,
				  u8 cause, struct scatterlist *sg,
				  unsigned long *mapped);
int  symrdma_group_materialize_locked(struct symrdma_mr *mr, unsigned long grp);
int  symrdma_group_collapse_2m_locked(struct symrdma_mr *mr, unsigned long grp,
				     phys_addr_t base_pa);
int  symrdma_group_verify_locked(struct symrdma_mr *mr, unsigned long grp);
void symrdma_group_ensure_split_locked(struct symrdma_mr *mr,
				       unsigned long page_idx);
void symrdma_group_ensure_split_range_locked(struct symrdma_mr *mr,
					     unsigned long start_idx,
					     unsigned long end_idx);
int  symrdma_backing_probe(struct symrdma_mr *mr, unsigned long idx,
			   enum symrdma_probe_intent intent,
			   struct symrdma_obs *obs, enum symrdma_backing *bk,
			   u8 *reason);
int  symrdma_gup_for_pin(unsigned long va, unsigned long nr,
			 struct page **pages);
unsigned long symrdma_gup_for_repair(unsigned long va, unsigned long nr,
				     struct page **pages);
phys_addr_t symrdma_va_to_pa(struct page *page, unsigned long va);

/*
 * What a forced state change asks for.  The enum and the ops structure live in
 * symrdma_test_hook.h: they are the collaboration surface with the test-only
 * module, and this module is the provider side of it.
 */

/* Resolve by id, check the caller owns the mm, run the authority's verbs. */
int  symrdma_page_force_state(struct symrdma_dev *dev, int mr_id,
			      unsigned long page_idx, int target);

/* Find an MR by id and take a reference (the caller puts it). */
struct symrdma_mr *symrdma_find_mr(struct symrdma_dev *dev, int mr_id);

int  symrdma_reg_mr(struct symrdma_dev *dev, struct mm_struct *mm,
		    u64 va_start, u64 len, struct symrdma_mr **out_mr);
bool symrdma_mr_teardown_begin(struct symrdma_dev *dev,
			       struct symrdma_mr *mr);
void symrdma_dereg_mr(struct symrdma_dev *dev, struct symrdma_mr *mr);
void symrdma_mr_release(struct kref *ref);

int  symrdma_mn_attach(struct symrdma_mr *mr);
void symrdma_mn_detach(struct symrdma_mr *mr);

struct symrdma_mm_state *symrdma_mm_state_get(struct symrdma_mr *mr);
void symrdma_mm_state_put(struct symrdma_mm_state *st);
void symrdma_mm_state_release(struct kref *ref);

int  symrdma_pin_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
		       u64 va, u64 len);
int  symrdma_unpin_range(struct symrdma_dev *dev, struct symrdma_mr *mr,
			 u64 va, u64 len);
void symrdma_pin_release_all(struct symrdma_mr *mr);

int  symrdma_version_alloc(struct symrdma_mr *mr);
void symrdma_version_free(struct symrdma_mr *mr);
u32  symrdma_version_read(struct symrdma_mr *mr, unsigned long page_idx);
int  symrdma_version_slot_ok(struct symrdma_mr *mr, unsigned long page_idx);
int  symrdma_version_write(struct symrdma_mr *mr, unsigned long page_idx, u32 val);
int  symrdma_version_bind_user_page(struct symrdma_dev *dev,
				    struct symrdma_mr *mr,
				    unsigned long version_va,
				    unsigned long version_len);

/* Census: decide (and optionally repair) one chunk, filling caller rows. */
int  symrdma_census_run(struct symrdma_dev *dev, struct symrdma_mr *mr,
			unsigned long page_idx, unsigned long npages, u32 mode,
			struct symrdma_census_page *rows, u32 *nrows,
			u64 *cookie);

int  symrdma_proc_init(struct symrdma_dev *dev);
void symrdma_proc_cleanup(struct symrdma_dev *dev);

void symrdma_state_assert(struct symrdma_mr *mr, unsigned long idx);
bool symrdma_state_assert_on(void);
void symrdma_state_assert_set(bool on);

void symrdma_trans_record(struct symrdma_mr *mr, unsigned long idx, u8 cause);

struct pci_dev *symrdma_find_mlx5(void);
struct pci_dev *symrdma_find_mlx5_by_bdf(const char *bdf);
bool symrdma_nic_is_passthrough(struct pci_dev *pdev);
int  symrdma_attach_nic_domain(struct symrdma_dev *dev, struct pci_dev *pdev);
void symrdma_detach_nic_domain(struct symrdma_dev *dev);

int  symrdma_dev_init(struct symrdma_dev *dev);
void symrdma_dev_cleanup(struct symrdma_dev *dev);

static inline int page_is_sentinel(const void *data, size_t offset)
{
	u32 val;
	memcpy(&val, data + offset, sizeof(val));
	return val == SYMRDMA_SENTINEL_MAGIC;
}

#endif
