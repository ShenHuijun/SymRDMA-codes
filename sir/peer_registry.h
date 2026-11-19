/* SPDX-License-Identifier: GPL-2.0 */

#ifndef PEER_REGISTRY_H
#define PEER_REGISTRY_H

#include <stdint.h>

#include "control_log.h"
#include "control_protocol.h"

#define CPEER_SNAP_SLOTS 4u
#define CPEER_ENT_MAX    CPROTO_SNAP_ENTRIES_MAX

struct cpeer_ent {
	uint32_t app_rkey;
	uint32_t app_access;
	uint32_t data_rkey;
	uint32_t write_rkey;
	uint32_t v_rkey;
	uint64_t addr;
	uint64_t len;
	uint64_t v_addr;
};

struct cpeer_snap {
	uint64_t generation;
	uint32_t n;
	uint32_t rsv;
	struct cpeer_ent entries[CPEER_ENT_MAX];
};

struct cpeer_stats {
	uint64_t publishes;
	uint64_t busy;
	uint64_t reclaims;
	uint64_t lookups;
	uint64_t lookup_miss;
	uint64_t readers;
	uint64_t peak_readers;
	uint64_t generation;
	uint32_t slots_free;
	uint32_t slots_ready;
	uint32_t slots_retiring;
};

struct cpeer;

CRT_INTERNAL struct cpeer *cpeer_new(void);
CRT_INTERNAL void cpeer_free(struct cpeer *p);

CRT_INTERNAL int cpeer_publish(struct cpeer *p, uint64_t generation,
			       const struct cpeer_ent *ents, uint32_t n);

CRT_INTERNAL int cpeer_lookup(const struct cpeer *p, uint32_t rkey,
			      struct cpeer_ent *out);

CRT_INTERNAL uint64_t cpeer_acquire(const struct cpeer *p);
CRT_INTERNAL void cpeer_release(const struct cpeer *p);

CRT_INTERNAL uint64_t cpeer_gen(const struct cpeer *p);
CRT_INTERNAL int cpeer_ready(const struct cpeer *p);

CRT_INTERNAL void cpeer_reset(struct cpeer *p);

CRT_INTERNAL void cpeer_reclaim(struct cpeer *p);

CRT_INTERNAL void cpeer_stats(const struct cpeer *p,
			      struct cpeer_stats *out);

#endif
