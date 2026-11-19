/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SYMRDMA_REPAIR_POLICY_H
#define SYMRDMA_REPAIR_POLICY_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include "symrdma_abi.h"
#include "repair_span.h"

#define REPAIR_POLICY_MAX_ATTEMPTS 3

#define REPAIR_POLICY_BACKOFF_US   1000

typedef enum {
	REPAIR_VERDICT_CLEAN = 0,
	REPAIR_VERDICT_MISSING = 1,
	REPAIR_VERDICT_UNAVAILABLE = 2,
} repair_verdict;

enum repair_policy_escalate_why {
	REPAIR_POLICY_ESC_BUDGET = 0,
	REPAIR_POLICY_ESC_REPAIR_FAIL = 1,
};

struct repair_policy_ops {

	repair_verdict (*detect)(void *ud, uint8_t *page_missing,
				 int attempt);

	int (*repair)(void *ud, struct sir_repair_span *spans, uint32_t n);

	void (*escalate)(void *ud, int why);
	void *ud;
};

struct repair_policy_cfg {
	unsigned long npages;
	const unsigned long *abs_pages;

	unsigned long page0;
	uint64_t region_base;

	uint64_t op_off;

	uint64_t op_len;
	uint32_t dir;
	uint8_t *page_missing;

	struct sir_repair_span *spans;
};

static inline int repair_policy_version_resident(uint32_t v)
{
	return v & 1;
}

static inline int repair_policy_version_changed(uint32_t v1, uint32_t v2)
{
	return v2 != v1 || !repair_policy_version_resident(v2);
}

static inline uint32_t
repair_policy_runs(const uint8_t *page_missing, unsigned long npages,
		   const unsigned long *abs_pages, unsigned long page0,
		   uint64_t region_base, uint64_t op_off, uint64_t op_len,
		   uint32_t dir, struct sir_repair_span *spans,
		   unsigned long *cursor)
{
	uint32_t k = 0;
	unsigned long i = *cursor;
	unsigned long region_pg = region_base / SYMRDMA_PAGE_SIZE;

	while (i < npages) {
		unsigned long pg, run_len;
		uint64_t run_abs, a, b;

		if (!page_missing[i]) {
			i++;
			continue;
		}
		pg = abs_pages ? abs_pages[i] : page0 + i;
		run_len = 1;
		i++;
		while (i < npages && page_missing[i]) {
			unsigned long nxt = abs_pages ? abs_pages[i]
						      : page0 + i;

			if (nxt != pg + run_len)
				break;
			run_len++;
			i++;
		}

		run_abs = (uint64_t)pg * SYMRDMA_PAGE_SIZE;
		{
			uint64_t win_lo = (uint64_t)page0 * SYMRDMA_PAGE_SIZE
					  + op_off;
			uint64_t win_hi = op_len >= ~(uint64_t)0 - win_lo
					  ? ~(uint64_t)0
					  : win_lo + op_len;

			a = run_abs > win_lo ? run_abs : win_lo;
			b = run_abs + (uint64_t)run_len * SYMRDMA_PAGE_SIZE;
			if (b > win_hi)
				b = win_hi;
		}
		if (b <= a)
			continue;
		spans[k].page_idx = pg - region_pg;
		spans[k].npages   = (uint32_t)run_len;
		spans[k].dir      = dir;
		spans[k].xaddr    = 0;
		spans[k].xrkey    = 0;
		spans[k].xoff     = (uint32_t)(a - run_abs);
		spans[k].xlen     = (uint32_t)(b - a);
		spans[k].rsv      = 0;
		k++;
		if (k == SIR_REPAIR_BATCH_MAX)
			break;
	}
	*cursor = i;
	return k;
}

static inline int repair_policy_loop(const struct repair_policy_ops *ops,
				     const struct repair_policy_cfg *cfg)
{
	uint8_t *page_missing = cfg->page_missing;
	int attempt;

	for (attempt = 0;; attempt++) {
		repair_verdict v;
		unsigned long cursor = 0;
		uint32_t k;

		memset(page_missing, 0, cfg->npages);

		v = ops->detect(ops->ud, page_missing, attempt);
		if (v == REPAIR_VERDICT_CLEAN)
			return 0;
		if (v == REPAIR_VERDICT_UNAVAILABLE)
			return 1;
		if (attempt >= REPAIR_POLICY_MAX_ATTEMPTS) {
			ops->escalate(ops->ud, REPAIR_POLICY_ESC_BUDGET);
			return -1;
		}

		while ((k = repair_policy_runs(page_missing, cfg->npages,
					       cfg->abs_pages, cfg->page0,
					       cfg->region_base, cfg->op_off,
					       cfg->op_len, cfg->dir,
					       cfg->spans, &cursor)) > 0) {
			if (ops->repair(ops->ud, cfg->spans, k)) {
				if (errno == EAGAIN) {
					usleep(REPAIR_POLICY_BACKOFF_US);
					break;
				}
				ops->escalate(ops->ud,
					      REPAIR_POLICY_ESC_REPAIR_FAIL);
				return -1;
			}
		}
	}
}

#endif
