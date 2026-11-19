/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SYMRDMA_DETECT_H
#define SYMRDMA_DETECT_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "repair_policy.h"
#include "sentinel.h"

/* The automatic route's boundary: a window of 4KiB or more is judged by
 * the version axis (seqlock), anything smaller by the sentinel sample. One
 * predicate, because the boundary had drifted between the explicit library
 * (> versus >=) and the transparent engine; it is a *policy* boundary, never a
 * resource limit (`NPR_WINDOW_SLOT_SIZE` is one) and never the explicit
 * small-write batch API's own length contract.
 */
static inline int detect_route_seqlock(uint64_t len)
{
	return len >= (uint64_t)SYMRDMA_SENTINEL_THRESHOLD;
}

/* ---- write ambiguity ------------------------------------------------------
 *
 * A small write is delivered optimistically and then judged by reading the target
 * back: equal bytes mean the write landed, the sentinel pattern means it was
 * dropped. That judge is blind to exactly one input - expected data that *is* the
 * sentinel pattern at its target address. Such a write is absorbed by the
 * black hole, the readback returns the pattern, and the comparison reports the
 * op clean although nothing landed.
 *
 * Content cannot separate the two outcomes, so the routing has to know before
 * posting: scan the *expected* bytes with the same fragment kernel that judges
 * readbacks, in the target's address space. A hit means the optimistic lane
 * cannot prove landing and the write has to be moved by the carrier (a PIN'd
 * owner page written by CPU / reverse write) instead.
 *
 * The scan is a conservative superset of the dangerous inputs: a readback judge
 * compares whole windows, so it can only be fooled when the expected bytes equal
 * the sentinel pattern over the window - and then every touched fragment hits.
 * Over-routing a legitimate near-collision to the carrier is the safe direction;
 * under-routing is a silent data loss.
 */
static inline int detect_write_ambiguous(const void *want, size_t len,
					 uint64_t target_addr)
{
	return sentinel_is_hit(want, len, target_addr);
}

static inline int detect_page_window(unsigned long p, uint64_t off,
				     uint64_t len, uint64_t *rel,
				     uint64_t *abs_rel, uint64_t *n)
{
	uint64_t ps = SYMRDMA_PAGE_SIZE;
	uint64_t a = (uint64_t)p * ps > off ? (uint64_t)p * ps : off;
	uint64_t b = (uint64_t)(p + 1) * ps < off + len ?
		     (uint64_t)(p + 1) * ps : off + len;

	if (b <= a)
		return 0;
	*rel = a - off;
	*abs_rel = a;
	*n = b - a;
	return 1;
}

static inline void detect_versions_changed(const uint32_t *v1,
					   const uint32_t *v2,
					   unsigned long np, uint8_t *miss,
					   int merge)
{
	unsigned long p;

	if (!v1 || !v2 || !miss)
		return;
	for (p = 0; p < np; p++) {
		uint8_t v = (uint8_t)repair_policy_version_changed(v1[p],
								   v2[p]);

		miss[p] = merge ? (uint8_t)(miss[p] | v) : v;
	}
}

static inline void detect_sentinel_pages(const void *op_buf,
					 uint64_t page0_base, uint64_t off,
					 uint64_t len, unsigned long np,
					 uint8_t *miss, int merge)
{
	unsigned long p;

	if (!op_buf || !miss)
		return;
	for (p = 0; p < np; p++) {
		uint64_t rel, abs_rel, n, a;
		uint8_t v;

		if (!detect_page_window(p, off, len, &rel, &abs_rel, &n))
			continue;
		a = page0_base + abs_rel;
		v = (uint8_t)sentinel_is_hit((const char *)op_buf + rel,
					     (size_t)n, a);
		miss[p] = merge ? (uint8_t)(miss[p] | v) : v;
	}
}

/* The local sink verdict, in one place: a page of the initiator's own receive
 * buffer is missing when its read IOVA still sits on the sentinel page at
 * delivery (parity even - the NIC's write was dropped) or when it moved inside
 * the op window (the write may have been dropped although the page came back).
 * Full 32-bit gen compare, not parity.
 *
 * v1/v2 are indexed from the sink page that holds the op's first byte, so
 * sink_off (that byte's page offset) shifts the window into them; op_off/op_len
 * are the op's window in its own address space, exactly as the other detect
 * primitives take them. A page's window can straddle two sink pages, so both are
 * judged. absent/changed may be NULL.
 */
static inline unsigned long detect_local_sink_pages(const uint32_t *v1,
						    const uint32_t *v2,
						    unsigned long np_sink,
						    uint64_t sink_off,
						    uint64_t op_off,
						    uint64_t op_len,
						    unsigned long np_pages,
						    uint8_t *miss,
						    unsigned long *absent,
						    unsigned long *changed)
{
	uint64_t ps = SYMRDMA_PAGE_SIZE;
	unsigned long p, n_hit = 0;

	if (!v1 || !v2 || !miss)
		return 0;
	for (p = 0; p < np_pages; p++) {
		uint64_t rel, abs_rel, n, s0, s1, s;

		if (!detect_page_window(p, op_off, op_len, &rel, &abs_rel, &n))
			continue;
		s0 = (sink_off + rel) / ps;
		s1 = (sink_off + rel + n - 1) / ps;
		for (s = s0; s <= s1 && s < np_sink; s++) {
			if (!(v2[s] & 1U)) {
				miss[p] = 1;
				if (absent)
					(*absent)++;
			} else if (v2[s] != v1[s]) {
				miss[p] = 1;
				if (changed)
					(*changed)++;
			} else {
				continue;
			}
			n_hit++;
			break;
		}
	}
	return n_hit;
}

struct detect_window {
	uint64_t off;
	uint64_t len;
};

/* The batched shape: only the members' own windows are scanned. The span's holes
 * carry no expected bytes and are never written, judged or repaired, so folding
 * them into the decision would invent a verdict about bytes nobody wrote. */
static inline int detect_write_ambiguous_windows(const void *want, uint64_t base,
						 const struct detect_window *win,
						 unsigned n_win)
{
	unsigned k;

	if (!want || !win)
		return 0;
	for (k = 0; k < n_win; k++)
		if (sentinel_is_hit((const char *)want + win[k].off, win[k].len,
				    base + win[k].off))
			return 1;
	return 0;
}

static inline void detect_memcmp_pages(const void *got, const void *want,
				       uint64_t off, uint64_t len,
				       unsigned long np, uint8_t *miss,
				       int merge)
{
	unsigned long p;

	if (!got || !want || !miss)
		return;
	for (p = 0; p < np; p++) {
		uint64_t rel, abs_rel, n;
		uint8_t v;

		if (!detect_page_window(p, off, len, &rel, &abs_rel, &n))
			continue;
		v = (uint8_t)(memcmp((const char *)got + rel,
				     (const char *)want + rel,
				     (size_t)n) != 0);
		miss[p] = merge ? (uint8_t)(miss[p] | v) : v;
	}
}

static inline void detect_memcmp_windows(const void *got, const void *want,
					 uint64_t off, uint64_t len,
					 const struct detect_window *win,
					 unsigned n_win, unsigned long np,
					 uint8_t *miss, int merge)
{
	unsigned long p;
	unsigned k;

	if (!got || !want || !miss || !win)
		return;
	for (p = 0; p < np; p++) {
		uint64_t rel, abs_rel, n;
		uint8_t v = 0;

		if (!detect_page_window(p, off, len, &rel, &abs_rel, &n))
			continue;
		for (k = 0; k < n_win && !v; k++) {
			uint64_t lo = win[k].off > rel ? win[k].off : rel;
			uint64_t hi = win[k].off + win[k].len < rel + n ?
				      win[k].off + win[k].len : rel + n;

			if (hi <= lo)
				continue;
			v = (uint8_t)(memcmp((const char *)got + lo,
					     (const char *)want + lo,
					     (size_t)(hi - lo)) != 0);
		}
		miss[p] = merge ? (uint8_t)(miss[p] | v) : v;
	}
}

static inline int detect_any_missing(const uint8_t *miss, unsigned long np)
{
	unsigned long p;

	if (!miss)
		return 0;
	for (p = 0; p < np; p++)
		if (miss[p])
			return 1;
	return 0;
}

#endif
