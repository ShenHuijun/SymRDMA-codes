/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_RING_H
#define CONTROL_RING_H

#include <errno.h>
#include <sched.h>
#include <stdint.h>
#include <string.h>

#define CRT_RING_SLOT_HDR  8u
#define CRT_RING_STRIDE(esz) \
	(CRT_RING_SLOT_HDR + (((uint32_t)(esz) + 7u) & ~7u))
#define CRT_RING_BYTES(cap, esz) ((size_t)(cap) * (size_t)CRT_RING_STRIDE(esz))

struct crt_ring {
	uint32_t cap;
	uint32_t esz;
	uint32_t head;
	uint32_t tail;
	uint8_t *slots;
};

static inline void crt_ring_init(struct crt_ring *rg, void *slots,
				 uint32_t cap, uint32_t esz)
{
	uint32_t i;

	rg->cap = cap;
	rg->esz = esz;
	rg->head = 0;
	rg->tail = 0;
	rg->slots = (uint8_t *)slots;
	memset(slots, 0, (size_t)cap * CRT_RING_STRIDE(esz));
	for (i = 0; i < cap; i++) {
		uint32_t *seq = (uint32_t *)(void *)
			(rg->slots + (size_t)i * CRT_RING_STRIDE(esz));

		__atomic_store_n(seq, i, __ATOMIC_RELAXED);
	}
}

static inline uint8_t *crt_ring_slot(const struct crt_ring *rg, uint32_t ticket)
{
	return rg->slots +
	       (size_t)(ticket % rg->cap) * CRT_RING_STRIDE(rg->esz);
}

static inline uint32_t *crt_ring_seq(uint8_t *slot)
{
	return (uint32_t *)(void *)slot;
}

static inline void *crt_ring_payload(uint8_t *slot)
{
	return (void *)(slot + CRT_RING_SLOT_HDR);
}

static inline int crt_ring_push(struct crt_ring *rg, const void *elem)
{
	uint32_t head, tail, spins = 0;
	uint8_t *slot;
	uint32_t *seq;

	head = __atomic_load_n(&rg->head, __ATOMIC_ACQUIRE);
	for (;;) {
		tail = __atomic_load_n(&rg->tail, __ATOMIC_RELAXED);
		if (tail - head >= rg->cap - 1u)
			return -EBUSY;
		if (__atomic_compare_exchange_n(&rg->tail, &tail, tail + 1u,
						0, __ATOMIC_ACQ_REL,
						__ATOMIC_RELAXED))
			break;
	}
	slot = crt_ring_slot(rg, tail);
	seq = crt_ring_seq(slot);
	while (__atomic_load_n(seq, __ATOMIC_ACQUIRE) != tail) {
		if (!(++spins & 0x3ffu))
			sched_yield();
	}
	memcpy(crt_ring_payload(slot), elem, rg->esz);
	__atomic_store_n(seq, tail + 1u, __ATOMIC_RELEASE);
	return 0;
}

static inline int crt_ring_peek(struct crt_ring *rg, void *elem)
{
	uint32_t h = __atomic_load_n(&rg->head, __ATOMIC_RELAXED);
	uint8_t *slot = crt_ring_slot(rg, h);
	uint32_t *seq = crt_ring_seq(slot);

	if (__atomic_load_n(seq, __ATOMIC_ACQUIRE) != h + 1u)
		return -ENOENT;
	memcpy(elem, crt_ring_payload(slot), rg->esz);
	return 0;
}

static inline void crt_ring_pop(struct crt_ring *rg)
{
	uint32_t h = __atomic_load_n(&rg->head, __ATOMIC_RELAXED);
	uint8_t *slot = crt_ring_slot(rg, h);

	__atomic_store_n(crt_ring_seq(slot), h + rg->cap, __ATOMIC_RELEASE);
	__atomic_store_n(&rg->head, h + 1u, __ATOMIC_RELEASE);
}

static inline int crt_ring_claim(struct crt_ring *rg, void *elem)
{
	for (;;) {
		uint32_t h = __atomic_load_n(&rg->head, __ATOMIC_ACQUIRE);
		uint8_t *slot = crt_ring_slot(rg, h);
		uint32_t *seq = crt_ring_seq(slot);

		if (__atomic_load_n(seq, __ATOMIC_ACQUIRE) != h + 1u)
			return -ENOENT;
		if (!__atomic_compare_exchange_n(&rg->head, &h, h + 1u, 0,
						 __ATOMIC_ACQ_REL,
						 __ATOMIC_ACQUIRE))
			continue;
		memcpy(elem, crt_ring_payload(slot), rg->esz);
		__atomic_store_n(seq, h + rg->cap, __ATOMIC_RELEASE);
		return 0;
	}
}

static inline int crt_ring_empty(struct crt_ring *rg)
{
	uint32_t h = __atomic_load_n(&rg->head, __ATOMIC_RELAXED);
	uint8_t *slot = crt_ring_slot(rg, h);

	return __atomic_load_n(crt_ring_seq(slot), __ATOMIC_ACQUIRE) != h + 1u;
}

static inline uint32_t crt_ring_len(struct crt_ring *rg)
{
	uint32_t t = __atomic_load_n(&rg->tail, __ATOMIC_ACQUIRE);
	uint32_t h = __atomic_load_n(&rg->head, __ATOMIC_ACQUIRE);

	return t - h;
}

#endif
