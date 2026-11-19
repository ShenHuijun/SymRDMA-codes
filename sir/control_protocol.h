/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_PROTOCOL_H
#define CONTROL_PROTOCOL_H

#include <stdint.h>
#include "control_log.h"
#include "app_qp_binding.h"

#define CONTROL_PROTO_MAGIC      0x53595243ull
#define CONTROL_PROTO_VERSION    7u
#define CONTROL_HEADER_LEN       52u

#define CONTROL_SLOT_CAPACITY    4096u
#define CONTROL_PAYLOAD_MAX      (CONTROL_SLOT_CAPACITY - CONTROL_HEADER_LEN)

#define CONTROL_PAGE_SIZE        4096u

#define CONTROL_RANGE_MAX        65536ull

#define CONTROL_WINDOW_MAX           8u
#define CONTROL_REVERSE_WINDOW_MAX   4u

#define CONTROL_REPAIR_BATCH_MAX 16u

#define CONTROL_SNAPSHOT_CHUNKS_MAX 16u

#define CPROTO_SNAP_HDR_SZ        24u
#define CPROTO_SNAP_ENTRY_SZ      48u
#define CPROTO_SNAP_ENTRIES_CHUNK \
	((CONTROL_PAYLOAD_MAX - CPROTO_SNAP_HDR_SZ) / CPROTO_SNAP_ENTRY_SZ)
#define CPROTO_SNAP_ENTRIES_MAX \
	(CONTROL_SNAPSHOT_CHUNKS_MAX * CPROTO_SNAP_ENTRIES_CHUNK)

#define CPROTO_OFF_MAGIC        0u
#define CPROTO_OFF_VERSION      8u
#define CPROTO_OFF_HEADER_LEN   10u
#define CPROTO_OFF_KIND         12u
#define CPROTO_OFF_FLAGS        14u
#define CPROTO_OFF_PAYLOAD_LEN  16u
#define CPROTO_OFF_SESSION_ID   20u
#define CPROTO_OFF_REQUEST_ID   28u
#define CPROTO_OFF_CREDIT_TOTAL 36u
#define CPROTO_OFF_GENERATION   44u

enum cproto_kind {
	CPROTO_RPC_REQUEST   = 1,
	CPROTO_RPC_RESPONSE  = 2,
	CPROTO_CONTROL_EVENT = 3,
};

enum cproto_op {
	CPROTO_OP_HELLO          = 1,

	CPROTO_OP_PING           = 2,
	CPROTO_OP_REPAIR_INLINE  = 3,
	CPROTO_OP_REPAIR_REVERSE = 4,
	CPROTO_OP_REPAIR_BATCH   = 5,
	CPROTO_OP_ATOMIC         = 6,
	CPROTO_OP_EXPORT_SNAPSHOT= 7,
	CPROTO_OP_CREDIT         = 8,
 CPROTO_OP_KEY_LOOKUP     = 9,
 CPROTO_OP_QP_BIND_INIT = 10,
 CPROTO_OP_QP_BIND_ACK = 11,
 CPROTO_OP_QP_UNBIND = 12,
 CPROTO_OP_RDV_OFFER = 13,
 CPROTO_OP_RDV_WAIT = 14,
 CPROTO_OP_RDV_ACK = 15,
 CPROTO_OP_RDV_CANCEL = 16,
 CPROTO_OP_RDV_CANCEL_ACK = 17,
 CPROTO_OP_RDV_RETIRED = 18,
 CPROTO_OP_RDV_CAPS = 19,
 CPROTO_OP_RDV_CREDIT = 20,
 CPROTO_OP_RDV_CAPS_ACK = 21,
 CPROTO_OP_RDV_WWI_READY = 22,
 CPROTO_OP_RDV_WWI_RESULT = 23,
 CPROTO_OP_RDV_DRAIN_REQUEST = 24,
 CPROTO_OP_RDV_DRAIN_ACK = 25,

};

#define CONTROL_DIR_READ   1u
#define CONTROL_DIR_WRITE  2u
#define CONTROL_ATOMIC_CAS 1u
#define CONTROL_ATOMIC_FAA 2u

struct cproto_header {
	uint64_t magic;
	uint16_t version;
	uint16_t header_len;
	uint16_t kind;
	uint16_t flags;
	uint32_t payload_len;
	uint64_t session_id;
	uint64_t request_id;
	uint64_t credit_total;
	uint64_t generation;
};

CRT_INTERNAL int cproto_header_encode(uint8_t *buf, uint32_t cap,
				       const struct cproto_header *h);

CRT_INTERNAL int cproto_header_decode(const uint8_t *buf, uint32_t byte_len,
				       struct cproto_header *out);

CRT_INTERNAL int cproto_op_get(const uint8_t *payload, uint32_t payload_len,
				uint32_t *op);

#define CPROTO_CAP_QP_BIND (1u << 0)
#define CPROTO_CAP_RDV_DATA (1u << 1)
#define CONTROL_RDV_DATA_ACTIVE 1
#define CONTROL_DATA_FRAME_CREDIT 4u
/* DATA uses the same full-binding authorization and four physical frame credits. */
#define CPROTO_QP_ENDPOINT_SIZE 80u
#define CPROTO_QP_INIT_SIZE 88u
#define CPROTO_QP_PAIR_SIZE 168u
/* Fixed 80-byte internal helpers. Caller validates buffer extent; put also
 * requires endpoint_valid. Shared by binding and RDV; no separate route rules. */
CRT_INTERNAL void cproto_qp_endpoint_put(uint8_t *, const struct sir_app_qp_endpoint *);
CRT_INTERNAL int cproto_qp_endpoint_get(const uint8_t *, struct sir_app_qp_endpoint *);
CRT_INTERNAL int cproto_qp_endpoint_valid(const struct sir_app_qp_endpoint *);
CRT_INTERNAL int cproto_qp_bind_encode(uint8_t *, uint32_t, uint32_t op,
				       uint32_t status,
				       const struct sir_app_qp_endpoint *,
				       const struct sir_app_qp_endpoint *);
CRT_INTERNAL int cproto_qp_bind_decode(const uint8_t *, uint32_t, uint32_t *op,
				       uint32_t *status,
				       struct sir_app_qp_endpoint *,
				       struct sir_app_qp_endpoint *);
struct cproto_caps {
	uint32_t protocol_version;
	uint32_t frame_capacity;
	uint32_t request_credit;

	uint32_t worker_capacity;
	uint32_t reverse_read_credit;

	uint32_t reverse_write_credit;
	uint32_t session_flags;
	uint32_t data_frame_credit;
};

CRT_INTERNAL int cproto_hello_encode(uint8_t *payload, uint32_t cap,
				      const struct cproto_caps *c);
CRT_INTERNAL int cproto_hello_decode(const uint8_t *payload, uint32_t len,
				      struct cproto_caps *c);

CRT_INTERNAL int cproto_rdv_credit_encode(uint8_t *,uint32_t,uint64_t);
CRT_INTERNAL int cproto_rdv_credit_decode(const uint8_t *,uint32_t,uint64_t *);

CRT_INTERNAL int cproto_ping_encode(uint8_t *payload, uint32_t cap,
				     uint64_t nonce);
CRT_INTERNAL int cproto_ping_decode(const uint8_t *payload, uint32_t len,
				     uint64_t *nonce);

struct cproto_repair_inline {
	uint32_t rkey;
	uint32_t dir;
	uint64_t page_idx;
	uint32_t off;
	uint32_t len;
};

CRT_INTERNAL int cproto_repair_inline_req_encode(
	uint8_t *payload, uint32_t cap,
	const struct cproto_repair_inline *r, const uint8_t *data);
CRT_INTERNAL int cproto_repair_inline_req_decode(
	const uint8_t *payload, uint32_t len,
	struct cproto_repair_inline *r, const uint8_t **data);

CRT_INTERNAL int cproto_repair_inline_resp_encode(
	uint8_t *payload, uint32_t cap, int32_t status, uint32_t len,
	const uint8_t *data);
CRT_INTERNAL int cproto_repair_inline_resp_decode(
	const uint8_t *payload, uint32_t len, int32_t *status,
	uint32_t *dlen, const uint8_t **data);

struct cproto_repair_reverse {
	uint32_t rkey;
	uint32_t dir;

	uint64_t page_idx;
	uint64_t npages;
	uint64_t xaddr;
	uint32_t xrkey;
	uint32_t xoff;
	uint32_t xlen;
	uint32_t rsv;
};

CRT_INTERNAL int cproto_repair_reverse_req_encode(
	uint8_t *payload, uint32_t cap,
	const struct cproto_repair_reverse *r);
CRT_INTERNAL int cproto_repair_reverse_req_decode(
	const uint8_t *payload, uint32_t len,
	struct cproto_repair_reverse *r);

CRT_INTERNAL int cproto_repair_resp_encode(uint8_t *payload, uint32_t cap,
					    int32_t status, uint32_t mlen);
CRT_INTERNAL int cproto_repair_resp_decode(const uint8_t *payload,
					    uint32_t len, int32_t *status,
					    uint32_t *mlen);

struct cproto_repair_span {
	uint64_t page_idx;
	uint32_t npages;
	uint32_t dir;
	uint64_t xaddr;
	uint32_t xrkey;
	uint32_t xoff;
	uint32_t xlen;
	uint32_t rsv;
};

CRT_INTERNAL int cproto_repair_batch_req_encode(
	uint8_t *payload, uint32_t cap, uint32_t rkey,
	const struct cproto_repair_span *spans, uint32_t nspan);
CRT_INTERNAL int cproto_repair_batch_req_decode(
	const uint8_t *payload, uint32_t len, uint32_t *rkey,
	struct cproto_repair_span *out, uint32_t max_span, uint32_t *nspan);
CRT_INTERNAL int cproto_repair_batch_resp_encode(
	uint8_t *payload, uint32_t cap, int32_t status,
	const uint32_t *span_status, uint32_t nspan);
CRT_INTERNAL int cproto_repair_batch_resp_decode(
	const uint8_t *payload, uint32_t len, int32_t *status,
	uint32_t *span_status, uint32_t max_span, uint32_t *nspan);

struct cproto_atomic {
	uint32_t rkey;
	uint32_t op;
	uint64_t va;
	uint64_t operand_a;
	uint64_t operand_b;
};

CRT_INTERNAL int cproto_atomic_req_encode(uint8_t *payload, uint32_t cap,
					   const struct cproto_atomic *a);
CRT_INTERNAL int cproto_atomic_req_decode(const uint8_t *payload,
					   uint32_t len,
					   struct cproto_atomic *a);
CRT_INTERNAL int cproto_atomic_resp_encode(uint8_t *payload, uint32_t cap,
					    int32_t status, uint64_t old_val);
CRT_INTERNAL int cproto_atomic_resp_decode(const uint8_t *payload,
					    uint32_t len, int32_t *status,
					    uint64_t *old_val);

struct cproto_snap_chunk {
	uint64_t generation;
	uint32_t chunk_index;
	uint32_t chunk_count;
	uint32_t entry_count;
	uint32_t rsv;
};

struct cproto_export_entry {
	uint32_t app_rkey;
	uint32_t app_access;
	uint32_t data_rkey;
	uint32_t write_rkey;
	uint32_t v_rkey;
	uint32_t rsv;
	uint64_t addr;
	uint64_t len;
	uint64_t v_addr;
};

CRT_INTERNAL int cproto_snapshot_encode(
	uint8_t *payload, uint32_t cap, const struct cproto_snap_chunk *h,
	const struct cproto_export_entry *entries);
CRT_INTERNAL int cproto_snapshot_decode(
	const uint8_t *payload, uint32_t len, struct cproto_snap_chunk *h,
	struct cproto_export_entry *out, uint32_t max_entries,
	uint32_t *n_entries);

/* Correlated owner-authoritative metadata query. status=0 FOUND,
 * ENOENT definitive NOTFOUND; every other positive errno is a query error. */
#define CPROTO_KEY_LOOKUP_REPLY_LEN 64u
CRT_INTERNAL int cproto_key_lookup_req_encode(uint8_t *, uint32_t, uint32_t);
CRT_INTERNAL int cproto_key_lookup_req_decode(const uint8_t *, uint32_t, uint32_t *);
CRT_INTERNAL int cproto_key_lookup_resp_encode(uint8_t *, uint32_t, uint32_t, int32_t, const struct cproto_export_entry *);
CRT_INTERNAL int cproto_key_lookup_resp_decode(const uint8_t *, uint32_t, uint32_t *, int32_t *, struct cproto_export_entry *);

CRT_INTERNAL int cproto_credit_encode(uint8_t *payload, uint32_t cap);
CRT_INTERNAL int cproto_credit_decode(const uint8_t *payload, uint32_t len);

CRT_INTERNAL int cproto_control_op_get(const uint8_t *payload, uint32_t len, uint32_t *op);

#endif
