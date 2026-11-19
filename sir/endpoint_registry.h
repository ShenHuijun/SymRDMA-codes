/* SPDX-License-Identifier: GPL-2.0 */

#ifndef ENDPOINT_REGISTRY_H
#define ENDPOINT_REGISTRY_H

#include <stdint.h>
#include "control_log.h"

#define CONTROL_LEASE_CAP 32u

#define CONTROL_REG_ENTRY_CAP 1024u

#define CONTROL_DRAIN_TIMEOUT_MS 10000u

enum creg_lease_view {
	CREG_LEASE_OWNER_EXPORT = 0,
	CREG_LEASE_INITIATOR_ENDPOINT,
};

enum creg_lease_state {
	CREG_LEASE_FREE = 0,
	CREG_LEASE_ACTIVE,
};

struct creg_lease {
	uint8_t  state;
	uint8_t  taken;
	uint8_t  view;
	uint64_t id;
	uint64_t entry_id;
	uint32_t key;
	uint64_t va;
	uint64_t len;
};

struct creg_registry {
	struct creg_lease lease[CONTROL_LEASE_CAP];
	uint64_t next_id;
	uint32_t active;
	int      fail_closed;
	long     violations;
};

CRT_INTERNAL void creg_init(struct creg_registry *reg);
CRT_INTERNAL int creg_owner_export_acquire(struct creg_registry *reg,
					    uint32_t rkey, uint64_t entry_id,
					    uint64_t *lease_id);
CRT_INTERNAL int creg_initiator_endpoint_acquire(struct creg_registry *reg,
						  uint64_t va, uint64_t len,
						  uint64_t entry_id,
						  uint64_t *lease_id);
CRT_INTERNAL int creg_lease_release(struct creg_registry *reg,
				     uint64_t lease_id);
CRT_INTERNAL int creg_lease_release_entry(struct creg_registry *reg,
					   uint64_t lease_id,
					   uint64_t *entry_id_out);
CRT_INTERNAL uint32_t creg_active_count(const struct creg_registry *reg,
					 enum creg_lease_view view);

enum creg_estate {
	CREG_ES_ACTIVE = 0,
	CREG_ES_CLOSING,
	CREG_ES_DRAINING,
};

struct creg_owner_export {
	uint32_t app_rkey;
	uint32_t app_access;
	uint32_t data_rkey;
	uint32_t write_rkey;
	uint32_t v_rkey;
	uint64_t addr;
	uint64_t len;
	uint64_t v_addr;
	int32_t  mr_id;
	uint32_t lkey;
};

struct creg_owner_view {
	uint32_t app_rkey;
	uint32_t app_access;
	uint32_t data_rkey;
	uint32_t write_rkey;
	uint32_t v_rkey;
	uint64_t addr;
	uint64_t len;
	uint64_t v_addr;
	int32_t  mr_id;
	uint32_t lkey;
	uint64_t entry_id;
};

struct creg_initiator_view {
	uint32_t rkey;
	uint64_t va;
	uint64_t len;
	uint64_t entry_id;
};

CRT_INTERNAL int creg_local_mr_publish(uint64_t va, uint64_t len,
					uint32_t rkey);
CRT_INTERNAL int creg_owner_export_publish(const struct creg_owner_export *m,
					    int *merge_kind
);

CRT_INTERNAL int creg_owner_acquire(uint32_t rkey,
				     struct creg_owner_view *v,
				     uint64_t *lease);
CRT_INTERNAL int creg_initiator_acquire(uint64_t va, uint64_t len,
					 struct creg_initiator_view *v,
					 uint64_t *lease);

CRT_INTERNAL int creg_owner_peek(uint32_t rkey, struct creg_owner_view *v);

CRT_INTERNAL int creg_lease_put(uint64_t lease);

/* Exact registration retirement. Close captures immutable entry identities;
 * reclaim is nonblocking and never touches a later registration at the VA. */
struct creg_mr_retirement { uint64_t local_id,export_id; };
CRT_INTERNAL int creg_mr_close(uint32_t app_rkey,uint64_t va,uint64_t len,struct creg_mr_retirement *);
CRT_INTERNAL int creg_mr_reclaim(struct creg_mr_retirement *);
CRT_INTERNAL int creg_mr_drain(const struct creg_mr_retirement *,uint32_t timeout_ms);
CRT_INTERNAL int creg_mr_reopen(const struct creg_mr_retirement *);
CRT_INTERNAL int creg_region_close(uint64_t va, uint64_t len);
CRT_INTERNAL int creg_region_drain(uint64_t va, uint64_t len,
				    uint32_t timeout_ms);
CRT_INTERNAL int creg_region_reclaim(uint64_t va, uint64_t len);

CRT_INTERNAL int creg_owner_export_close(uint32_t key, uint32_t timeout_ms);
CRT_INTERNAL int creg_owner_export_unpublish_wkey(uint32_t wkey,
						   uint32_t timeout_ms);

CRT_INTERNAL uint32_t creg_owner_snapshot(struct creg_owner_view *out,
					   uint32_t cap, int *truncated);

CRT_INTERNAL uint32_t creg_entry_count(void);
CRT_INTERNAL int      creg_fail_closed(void);
CRT_INTERNAL long     creg_violations(void);

#endif
