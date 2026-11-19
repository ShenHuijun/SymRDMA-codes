/* SPDX-License-Identifier: GPL-2.0 */

#ifndef SYMRDMA_SENTINEL_H
#define SYMRDMA_SENTINEL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "symrdma_abi.h"

/* The sentinel page holds the phase-rotated magic: the byte at absolute address
 * a is (MAGIC >> ((a & 3) * 8)) & 0xff, so a 4-byte word read at a compares
 * equal to sentinel_expect(a). Rotation is by *absolute* address, never by the
 * buffer's own offset.
 */
static inline uint32_t sentinel_expect(uint64_t addr)
{
	unsigned int sh = (addr & 3) * 8;

	return (SYMRDMA_SENTINEL_MAGIC >> sh) |
	       (sh ? (SYMRDMA_SENTINEL_MAGIC << (32 - sh)) : 0);
}

static inline unsigned char sentinel_byte(uint64_t addr)
{
	return (unsigned char)(SYMRDMA_SENTINEL_MAGIC >> ((addr & 3) * 8));
}

/* ---- the fragment model ----------------------------------------------------
 *
 * A dropped DMA is dropped per 256B TLP chunk, so the judged unit is the
 * intersection of the op window with a 256B absolute-aligned chunk - one
 * *fragment*:
 *
 *	[base+off, min(next 256B boundary, base+len))
 *
 * base is the target absolute address of buf[0] and off is an offset inside the
 * operation. Fragments are judged one at a time, each on its own span of bytes,
 * and a fragment is never read past its own end: the first fragment of an op can
 * be shorter than a chunk (unaligned start) and so can the last one, and both
 * are real inputs to the mechanism - a same-page 1..3 byte tail left on the
 * sentinel mapping is exactly the hole this model closes.
 *
 * A fragment of 4 bytes or more contributes one 4-byte sample at its first byte
 * (one sample per TLP chunk, the paper's shape). A shorter fragment cannot carry
 * a sample, so every one of its bytes is compared at its own absolute phase: a
 * conservative superset of the old behaviour (a short fragment raises the
 * false-positive rate, it never lowers the detection).
 */
struct sentinel_fragment {
	size_t off;	/* offset inside the buffer */
	size_t len;	/* 1..SYMRDMA_TLP_CHUNK_SIZE */
};

/* Next fragment of the window, or 0 when off has reached len. The phase is
 * computed from base and off in chunk-relative terms, so a window that ends at
 * the top of the address space cannot wrap the boundary arithmetic. */
static inline int sentinel_fragment_next(uint64_t base, size_t len, size_t off,
					 struct sentinel_fragment *f)
{
	size_t phase, room;

	if (!f || off >= len)
		return 0;
	phase = (size_t)((base % SYMRDMA_TLP_CHUNK_SIZE +
			  (uint64_t)off % SYMRDMA_TLP_CHUNK_SIZE) %
			 SYMRDMA_TLP_CHUNK_SIZE);
	room = SYMRDMA_TLP_CHUNK_SIZE - phase;
	if (room > len - off)
		room = len - off;
	f->off = off;
	f->len = room;
	return 1;
}

/* Is this fragment the sentinel? n is the fragment's own length; abs_addr is
 * the absolute address of its first byte. n == 0 touches nothing. */
static inline int sentinel_fragment_hit(const void *data, size_t n,
					uint64_t abs_addr)
{
	const unsigned char *b = data;
	size_t k;

	if (!n || !data)
		return 0;
	if (n >= 4) {
		/* one 4-byte sample, assembled little-endian - the order
		 * sentinel_expect's rotation is written for. Reading exactly four
		 * bytes states the sample's width: the fragment may be longer, and
		 * the bytes past the sample are not part of the judgement. */
		uint32_t v = (uint32_t)b[0] | ((uint32_t)b[1] << 8) |
			     ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);

		return v == sentinel_expect(abs_addr);
	}
	for (k = 0; k < n; k++)
		if (b[k] != sentinel_byte(abs_addr + k))
			return 0;
	return 1;
}

static inline size_t sentinel_first_hit(const void *data, size_t len,
					uint64_t base)
{
	struct sentinel_fragment f;
	size_t off = 0;

	if (!data)
		return (size_t)-1;
	while (sentinel_fragment_next(base, len, off, &f)) {
		if (sentinel_fragment_hit((const char *)data + f.off, f.len,
					  base + f.off))
			return f.off;
		off = f.off + f.len;
	}
	return (size_t)-1;
}

static inline int sentinel_is_hit(const void *data, size_t len, uint64_t base)
{
	return sentinel_first_hit(data, len, base) != (size_t)-1;
}

/* The page the first hit lives on; the window's own start page when nothing
 * hit. */
static inline uint64_t sentinel_first_page(const void *data, size_t len,
					   uint64_t base)
{
	size_t off = sentinel_first_hit(data, len, base);

	if (off == (size_t)-1)
		return base / SYMRDMA_PAGE_SIZE * SYMRDMA_PAGE_SIZE;
	return (base + off) / SYMRDMA_PAGE_SIZE * SYMRDMA_PAGE_SIZE;
}

#endif
