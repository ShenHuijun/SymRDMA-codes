/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "peer_registry.h"

enum cpeer_slot_state {
	CPEER_SLOT_FREE = 0,
	CPEER_SLOT_READY,
	CPEER_SLOT_RETIRING,
};

#define CPEER_SLOT_NONE 0xffffffffu

struct cpeer {
	struct cpeer_snap slot[CPEER_SNAP_SLOTS];
	uint8_t  state[CPEER_SNAP_SLOTS];
	uint32_t cur;
	uint32_t retiring_n;
	uint64_t gen;
	int      ready;
	uint32_t cnt_free, cnt_ready, cnt_retiring;

	struct cpeer_snap *cur_snap;

	uint64_t readers;
	uint64_t peak_readers;

	uint64_t publishes, busy, reclaims, lookups, lookup_miss;
};

CRT_INTERNAL struct cpeer *cpeer_new(void)
{
	struct cpeer *p = calloc(1, sizeof(*p));

	if (!p)
		return NULL;
	p->cur = CPEER_SLOT_NONE;
	p->cnt_free = CPEER_SNAP_SLOTS;
	return p;
}

CRT_INTERNAL void cpeer_free(struct cpeer *p)
{
	free(p);
}

CRT_INTERNAL uint64_t cpeer_acquire(const struct cpeer *p)
{
	struct cpeer *m = (struct cpeer *)p;
	uint64_t now;

	if (!p)
		return 0;
	now = __atomic_add_fetch(&m->readers, 1, __ATOMIC_ACQ_REL);
	{
		uint64_t peak = __atomic_load_n(&m->peak_readers,
						__ATOMIC_RELAXED);

		while (now > peak) {
			if (__atomic_compare_exchange_n(&m->peak_readers, &peak,
							now, 0,
							__ATOMIC_RELAXED,
							__ATOMIC_RELAXED))
				break;
		}
	}
	return __atomic_load_n(&m->gen, __ATOMIC_ACQUIRE);
}

CRT_INTERNAL void cpeer_release(const struct cpeer *p)
{
	struct cpeer *m = (struct cpeer *)p;

	if (!p)
		return;
	(void)__atomic_sub_fetch(&m->readers, 1, __ATOMIC_ACQ_REL);
}

CRT_INTERNAL int cpeer_lookup(const struct cpeer *p, uint32_t rkey,
			      struct cpeer_ent *out)
{
	struct cpeer *m = (struct cpeer *)p;
	struct cpeer_snap *snap;
	uint32_t i, n;
	int found = 0;

	if (!p || !out || !rkey)
		return -EINVAL;
	(void)cpeer_acquire(p);
	snap = __atomic_load_n(&m->cur_snap, __ATOMIC_ACQUIRE);
	if (!snap) {
		cpeer_release(p);
		__atomic_fetch_add(&m->lookup_miss, 1, __ATOMIC_RELAXED);
		return -ENOENT;
	}

	n = snap->n;
	for (i = 0; i < n; i++) {
		const struct cpeer_ent *e = &snap->entries[i];

		if ((e->app_rkey && e->app_rkey == rkey) || e->data_rkey == rkey ||
		    (e->write_rkey && e->write_rkey == rkey)) {
			*out = *e;
			found = 1;
			break;
		}
	}
	cpeer_release(p);
	__atomic_fetch_add(&m->lookups, 1, __ATOMIC_RELAXED);
	if (!found) {
		__atomic_fetch_add(&m->lookup_miss, 1, __ATOMIC_RELAXED);
		return -ENOENT;
	}
	return 0;
}

CRT_INTERNAL uint64_t cpeer_gen(const struct cpeer *p)
{
	return p ? __atomic_load_n(&p->gen, __ATOMIC_ACQUIRE) : 0;
}

CRT_INTERNAL int cpeer_ready(const struct cpeer *p)
{
	return p ? __atomic_load_n(&p->ready, __ATOMIC_ACQUIRE) : 0;
}

CRT_INTERNAL void cpeer_reclaim(struct cpeer *p)
{
	uint32_t i;

	if (!p || !p->retiring_n)
		return;
	if (__atomic_load_n(&p->readers, __ATOMIC_ACQUIRE))
		return;
	for (i = 0; i < CPEER_SNAP_SLOTS; i++) {
		if (p->state[i] != CPEER_SLOT_RETIRING)
			continue;
		p->state[i] = CPEER_SLOT_FREE;
		if (p->retiring_n)
			p->retiring_n--;
		(void)__atomic_fetch_sub(&p->cnt_retiring, 1, __ATOMIC_RELAXED);
		(void)__atomic_fetch_add(&p->cnt_free, 1, __ATOMIC_RELAXED);
		__atomic_fetch_add(&p->reclaims, 1, __ATOMIC_RELAXED);
	}
}

static uint32_t cpeer_take_free(struct cpeer *p)
{
	uint32_t i;

	for (i = 0; i < CPEER_SNAP_SLOTS; i++)
		if (p->state[i] == CPEER_SLOT_FREE)
			return i;
	return CPEER_SLOT_NONE;
}

CRT_INTERNAL int cpeer_publish(struct cpeer *p, uint64_t generation,
			       const struct cpeer_ent *ents, uint32_t n)
{
	struct cpeer_snap *snap;
	uint32_t idx, i;

	if (!p || (!ents && n) || n > CPEER_ENT_MAX)
		return -EINVAL;
	if (!generation)
		return -EINVAL;
	if (generation <= __atomic_load_n(&p->gen, __ATOMIC_RELAXED))
		return -EPROTO;
	idx = cpeer_take_free(p);
	if (idx == CPEER_SLOT_NONE) {
		cpeer_reclaim(p);
		idx = cpeer_take_free(p);
	}
	if (idx == CPEER_SLOT_NONE) {
		__atomic_fetch_add(&p->busy, 1, __ATOMIC_RELAXED);
		return -EBUSY;
	}
	snap = &p->slot[idx];
	snap->generation = generation;
	snap->rsv = 0;
	for (i = 0; i < n; i++)
		snap->entries[i] = ents[i];
	snap->n = n;
	p->state[idx] = CPEER_SLOT_READY;
	(void)__atomic_fetch_sub(&p->cnt_free, 1, __ATOMIC_RELAXED);
	(void)__atomic_fetch_add(&p->cnt_ready, 1, __ATOMIC_RELAXED);
	if (p->cur != CPEER_SLOT_NONE) {
		p->state[p->cur] = CPEER_SLOT_RETIRING;
		p->retiring_n++;
		(void)__atomic_fetch_sub(&p->cnt_ready, 1, __ATOMIC_RELAXED);
		(void)__atomic_fetch_add(&p->cnt_retiring, 1,
					 __ATOMIC_RELAXED);
	}
	p->cur = idx;
	__atomic_store_n(&p->gen, generation, __ATOMIC_RELEASE);
	__atomic_store_n(&p->ready, 1, __ATOMIC_RELEASE);
	__atomic_store_n(&p->cur_snap, snap, __ATOMIC_RELEASE);
	__atomic_fetch_add(&p->publishes, 1, __ATOMIC_RELAXED);
	return 0;
}

CRT_INTERNAL void cpeer_reset(struct cpeer *p)
{
	if (!p)
		return;
	if (p->cur != CPEER_SLOT_NONE) {

		__atomic_store_n(&p->cur_snap, NULL, __ATOMIC_RELEASE);
		p->state[p->cur] = CPEER_SLOT_RETIRING;
		p->retiring_n++;
		(void)__atomic_fetch_sub(&p->cnt_ready, 1, __ATOMIC_RELAXED);
		(void)__atomic_fetch_add(&p->cnt_retiring, 1,
					 __ATOMIC_RELAXED);
		p->cur = CPEER_SLOT_NONE;
	}
	__atomic_store_n(&p->gen, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&p->ready, 0, __ATOMIC_RELEASE);
}

CRT_INTERNAL void cpeer_stats(const struct cpeer *p, struct cpeer_stats *out)
{
	if (!out)
		return;
	memset(out, 0, sizeof(*out));
	if (!p)
		return;
	out->publishes = __atomic_load_n(&p->publishes, __ATOMIC_RELAXED);
	out->busy = __atomic_load_n(&p->busy, __ATOMIC_RELAXED);
	out->reclaims = __atomic_load_n(&p->reclaims, __ATOMIC_RELAXED);
	out->lookups = __atomic_load_n(&p->lookups, __ATOMIC_RELAXED);
	out->lookup_miss = __atomic_load_n(&p->lookup_miss, __ATOMIC_RELAXED);
	out->readers = __atomic_load_n(&p->readers, __ATOMIC_RELAXED);
	out->peak_readers = __atomic_load_n(&p->peak_readers,
					    __ATOMIC_RELAXED);
	out->generation = __atomic_load_n(&p->gen, __ATOMIC_ACQUIRE);
	out->slots_free = __atomic_load_n(&p->cnt_free, __ATOMIC_RELAXED);
	out->slots_ready = __atomic_load_n(&p->cnt_ready, __ATOMIC_RELAXED);
	out->slots_retiring = __atomic_load_n(&p->cnt_retiring,
					      __ATOMIC_RELAXED);
}
