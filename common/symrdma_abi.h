/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SYMRDMA_ABI_H
#define SYMRDMA_ABI_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/ioctl.h>
#else
#include <linux/types.h>
#include <stddef.h>
#include <sys/ioctl.h>
#endif

#define SYMRDMA_PAGE_SIZE           4096

#define SYMRDMA_SENTINEL_MAGIC      0xdeadbeef

#define SYMRDMA_TLP_CHUNK_SIZE      256

#define SYMRDMA_SENTINEL_THRESHOLD  4096

#define SYMRDMA_VERSION_INIT_RESIDENT   1
#define SYMRDMA_VERSION_INIT_ABSENT     0
#define SYMRDMA_VERS_PER_PAGE           1024

#define SYMRDMA_MR_WRITE_OFFSET     (1UL << 35)

#define NPRDMA_MR_SYMRDMA           (1 << 21)

#define SYMRDMA_ACCESS_WREG         (1 << 22)

/*
 * The ioctl layout version. It moves when a command is released or
 * renumbered, a structure changes shape, or the stats table changes meaning.
 * A reader compares it against the version it was compiled with (the STATS
 * snapshot carries it) instead of growing per-field compatible-reader rules:
 * there is no old/new tolerance to maintain.
 */
#define SYMRDMA_ABI_VERSION 3

#define SYMRDMA_IOC_MAGIC           'S'

/*
 * What a page's two mappings point at, and why it last changed. Census reports
 * both, so these are wire values: the kernel's state authority and the reader
 * share one definition (a second copy would drift silently).
 */
enum symrdma_map {
	SYMRDMA_MAP_UNMAPPED  = 0,
	SYMRDMA_MAP_REAL      = 1,
	SYMRDMA_MAP_SENTINEL  = 2,
	SYMRDMA_MAP_BLACKHOLE = 3,
};

enum symrdma_trans_cause {
	SYMRDMA_TRANS_NOTIFIER = 0,
	SYMRDMA_TRANS_REALIGN  = 1,
	SYMRDMA_TRANS_REPAIR   = 2,
	SYMRDMA_TRANS_PIN      = 3,
	SYMRDMA_TRANS_PARK     = 4,
	SYMRDMA_TRANS_SETUP    = 5,
	SYMRDMA_TRANS_FORCED   = 6,
};

/*
 * The production command set, one number per legitimate consumer. Commands
 * with no production consumer are not carried "for later" and old numbers are
 * not kept alive: a released command's number disappears with it. A test face,
 * when a tree carries one, answers on its own device under its own magic and
 * never adds a number here.
 */
#define SYMRDMA_IOC_REG_MR      _IOWR(SYMRDMA_IOC_MAGIC, 1, struct symrdma_ioc_reg_mr)
#define SYMRDMA_IOC_DEREG_MR    _IOW(SYMRDMA_IOC_MAGIC,  2, int)

#define SYMRDMA_IOC_GET_IOVA    _IOWR(SYMRDMA_IOC_MAGIC, 3, struct symrdma_ioc_get_iova)

#define SYMRDMA_IOC_READ_IOVA   _IOWR(SYMRDMA_IOC_MAGIC, 4, struct symrdma_ioc_read_iova)

#define SYMRDMA_IOC_REPAIR      _IOWR(SYMRDMA_IOC_MAGIC, 5, struct symrdma_ioc_repair)

#define SYMRDMA_IOC_GET_VERSION _IOWR(SYMRDMA_IOC_MAGIC, 6, struct symrdma_ioc_get_version)

#define SYMRDMA_IOC_SET_VERSION_PAGE _IOW(SYMRDMA_IOC_MAGIC, 7, struct symrdma_ioc_set_version_page)

#define SYMRDMA_IOC_PIN_PAGES   _IOWR(SYMRDMA_IOC_MAGIC, 8, struct symrdma_ioc_pin)
#define SYMRDMA_IOC_UNPIN_PAGES _IOWR(SYMRDMA_IOC_MAGIC, 9, struct symrdma_ioc_pin)

#define SYMRDMA_IOC_REPAIR_RANGE _IOWR(SYMRDMA_IOC_MAGIC, 10, struct symrdma_ioc_repair_range)

#define SYMRDMA_IOC_STATS _IOWR(SYMRDMA_IOC_MAGIC, 11, struct symrdma_ioc_stats)

#define SYMRDMA_IOC_CENSUS _IOWR(SYMRDMA_IOC_MAGIC, 12, struct symrdma_ioc_census)

struct symrdma_ioc_reg_mr {
	__u64           va_start;
	__u64           len;
	int             mr_id;
};

struct symrdma_ioc_get_iova {
	int             mr_id;
	unsigned long   page_idx;
	__u64           read_iova;
	__u64           write_iova;
};

struct symrdma_ioc_read_iova {
	int             mr_id;
	__u64           iova;
	size_t          offset;
	__u32           value;
};

struct symrdma_ioc_repair {
	int             mr_id;
	unsigned long   page_idx;
};

struct symrdma_ioc_get_version {
	int             mr_id;
	unsigned long   page_idx;
	unsigned int    version;
};

struct symrdma_ioc_set_version_page {
	int             mr_id;
	__u64           version_va;
	unsigned long   version_len;
};

struct symrdma_ioc_pin {
	int             mr_id;
	__u64           va;
	__u64           len;
};

/* REPAIR_RANGE. In: the range. Out: what the verb actually did — never reuse an
 * in field for an out fact (the partial-repair evidence used to ride `npages`,
 * which is how a half-repaired range could be served as repaired). */
struct symrdma_ioc_repair_range {
	int             mr_id;
	unsigned long   page_idx;      /* in: first page */
	unsigned long   npages;        /* in: pages requested */
	unsigned int    cause;         /* out: enum symrdma_trans_cause of the transitions */
	unsigned int    gen_before_lo; /* out: gen of page_idx before the repair */
	unsigned int    gen_after_hi;  /* out: gen of the last repaired page after it */
	unsigned int    reserved;      /* out: 0 (keeps the struct naturally aligned) */
	unsigned long   repaired;      /* out: pages the verb really promoted */
};

#define SYMRDMA_REPAIR_RANGE_MAX  4096

#define SYMRDMA_PIN_BUDGET_PAGES  8192

/*
 * The stats counters' single source: one row per counter, in STATS array
 * order. Every consumer derives its face from this one table - the SYMSTAT_*
 * enum below, the kernel's STATS ioctl assembly (each row names the counter
 * it reads), and any table walk a reader needs. Renaming or reordering a
 * counter is editing this table; the layout change is published by bumping
 * SYMRDMA_ABI_VERSION, not by a freeze rule on the tail.
 */
#define SYMRDMA_STAT_TABLE(X)                                                     \
	X(SYMSTAT_NOTIFIER_CALLS,     notifier_calls)                             \
	X(SYMSTAT_PAGES_SWAPPED_OUT,  pages_swapped_out)                          \
	X(SYMSTAT_REPAIR_OK,          repair_ok)                                  \
	X(SYMSTAT_REPAIR_FAIL,        repair_fail)                                \
	X(SYMSTAT_PROCESS_EXITS,      process_exits)                              \
	X(SYMSTAT_RELEASED_MRS,       released_mrs)                               \
	X(SYMSTAT_NOTIF_EVENTS,       notif_events)                               \
	X(SYMSTAT_RESIDENT_RESTORED,  resident_restored)                          \
	X(SYMSTAT_RESIDENT_ABSENT,    resident_absent)                            \
	X(SYMSTAT_PENDING_OVERFLOW,   pending_overflow)                           \
	X(SYMSTAT_PIN_PAGES,          pin_pages)                                  \
	X(SYMSTAT_PIN_OK,             pin_ok)                                     \
	X(SYMSTAT_PIN_ENOSPC,         pin_enospc)                                 \
	X(SYMSTAT_PIN_DEFERRED,       pin_deferred)                               \
	X(SYMSTAT_PIN_TRANSITIONS,    pin_transitions)                            \
	X(SYMSTAT_HUGE_RESIDENT,      huge_resident)                              \
	X(SYMSTAT_HUGE_ABSENT,        huge_absent)                                \
	X(SYMSTAT_GROUP_DEMOTES,      group_demotes)                              \
	X(SYMSTAT_DEMOTE_FAIL,        demote_fail)                                \
	X(SYMSTAT_GROUP_REPROMOTE,    group_repromote)                            \
	X(SYMSTAT_REPAIR_BUDGET_STOP, repair_budget_stop)                         \
	X(SYMSTAT_REPAIR_SYNC_US_LAST, repair_sync_us_last)                       \
	X(SYMSTAT_REPAIR_SYNC_US_MAX, repair_sync_us_max)                         \
	X(SYMSTAT_STATE_DIVERGENCE,   state_divergence)                           \
	X(SYMSTAT_PROBE_ABSENT,       probe_absent)                               \
	X(SYMSTAT_PROBE_STALE,        probe_stale)                                \
	X(SYMSTAT_PROBE_UNMAPPABLE,   probe_unmappable)                           \
	X(SYMSTAT_PROBE_SPECIAL,      probe_special)                              \
	X(SYMSTAT_GROUP_INCONSISTENT, group_inconsistent)                         \
	X(SYMSTAT_GUP_PIN_FAIL,       gup_pin_fail)                               \
	X(SYMSTAT_GUP_REPAIR_SHORT,   gup_repair_short)                           \
	X(SYMSTAT_REPAIR_PARTIAL,     repair_partial)

enum symrdma_stat_idx {
#define SYMRDMA_STAT_ENUM(e, f) e,
	SYMRDMA_STAT_TABLE(SYMRDMA_STAT_ENUM)
#undef SYMRDMA_STAT_ENUM
	SYMSTAT_COUNT
};

/* Derived from the table, not asserted beside it: the array bound and the
 * counter set cannot drift apart by construction. */
#define SYMRDMA_STATS_MAX ((int)SYMSTAT_COUNT)

#define SYMRDMA_STATS_MAGIC  0x53545331u

/*
 * Census: the page-state judgement, per page, with the evidence a gate needs.
 *
 * One call covers a chunk (the kernel keeps no cursor; the caller iterates).
 * The per-page rows come back through the device's read(), one 16-byte row per
 * page, up to SYMRDMA_CENSUS_MAX rows per call - a fixed ioctl structure plus a
 * bounded read, instead of a variable-length ioctl nobody can size.
 *
 * mode 0 decides only (no side effects); mode 1 also repairs what it decided is
 * absent or stale, and says which of the two happened per page - "the verdict
 * was ABSENT" and "the repair failed" are different facts and a gate that
 * confuses them cannot tell a correct system from a broken one.
 */
#define SYMRDMA_CENSUS_MAX 256

struct symrdma_ioc_census {
	__u32           abi;      /* in: SYMRDMA_ABI_VERSION */
	int             mr_id;    /* in */
	unsigned long   page_idx; /* in: first page of the chunk */
	unsigned long   npages;   /* in: 1..SYMRDMA_CENSUS_MAX */
	__u32           mode;     /* in: 0 = decide, 1 = decide and repair */
	__u32           nread;    /* out: rows written to the read() buffer */
	__u64           cookie;   /* out: trans_seq upper bound of this call */
};

enum symrdma_census_verdict {
	SYMRDMA_CV_OK                    = 0,
	SYMRDMA_CV_ABSENT                = 1,
	SYMRDMA_CV_STALE                 = 2,
	SYMRDMA_CV_ABSENT_REPAIRED       = 3,
	SYMRDMA_CV_STALE_REPAIRED        = 4,
	SYMRDMA_CV_ABSENT_REPAIR_FAILED  = 5,
	SYMRDMA_CV_STALE_REPAIR_FAILED   = 6,
	SYMRDMA_CV_UNMAPPABLE            = 7,
	SYMRDMA_CV_SPECIAL               = 8,
	SYMRDMA_CV_ERROR                 = 9,
};

/* One row per page, 16 bytes. */
struct symrdma_census_page {
	__u32 gen;        /* gen when the verdict was taken */
	__u8  rmap;       /* enum symrdma_map, read IOVA */
	__u8  wmap;       /* enum symrdma_map, write IOVA */
	__u8  verdict;    /* enum symrdma_census_verdict */
	__u8  cause;      /* enum symrdma_trans_cause, last transition */
	__u64 cause_seq;  /* mr->trans_seq at that transition */
};

struct symrdma_ioc_stats {
	__u32  abi;      /* SYMRDMA_ABI_VERSION this layout was built with */
	__u32  magic;    /* SYMRDMA_STATS_MAGIC: "this struct really is ours" */
	__u32  count;    /* how many entries this snapshot filled */
	__u32  reserved; /* 0 */
	__u64  v[SYMRDMA_STATS_MAX];
};

#endif
