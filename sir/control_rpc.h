/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_RPC_H
#define CONTROL_RPC_H

#include <pthread.h>
#include <stdint.h>

#include "control_log.h"
#include "control_protocol.h"

enum crpc_op {
	CRPC_OP_REPAIR_INLINE = 1,
	CRPC_OP_REPAIR_REVERSE,
	CRPC_OP_REPAIR_BATCH,
	CRPC_OP_ATOMIC,
	CRPC_OP_PUBLISH_SNAPSHOT,

	CRPC_OP_PING,
 CRPC_OP_KEY_LOOKUP,
};

struct crpc_desc {
	uint8_t  op;
	uint32_t rkey;
	uint32_t dir;
	uint64_t page_idx;
	uint64_t npages;
	uint32_t off;
	uint32_t len;
	uint64_t xaddr;
	uint32_t xrkey;
	uint64_t va;
	uint64_t operand_a;
	uint64_t operand_b;
	uint32_t nspan;
	struct cproto_repair_span span[CONTROL_REPAIR_BATCH_MAX];
	uint32_t inline_len;
	uint8_t  inline_data[CONTROL_PAYLOAD_MAX];
	uint64_t deadline_us;
};

struct crpc_reply {
	int32_t  status;
	uint32_t mlen;
	uint32_t nspan_status;
	uint8_t  data[CONTROL_PAYLOAD_MAX];
	uint64_t old_val;
};

struct crpc_caller {

	uint32_t done;
	uint32_t waiters;
	int32_t  refs;
	int32_t  abandoned;
	int32_t  err;

	struct crpc_reply reply;

	int64_t  trace_submit_ns;
	int64_t  trace_op_ns;
	int64_t  trace_wake_ns;
	uint64_t trace_session_id;
	uint64_t trace_request_id;
};

CRT_INTERNAL struct crpc_caller *crpc_caller_new(void);
CRT_INTERNAL void crpc_caller_free(struct crpc_caller *c);
CRT_INTERNAL void crpc_caller_complete(struct crpc_caller *c, int32_t err,
					const struct crpc_reply *rep);

CRT_INTERNAL void crpc_caller_put(struct crpc_caller *c);

CRT_INTERNAL void crpc_caller_wait_enter(struct crpc_caller *c);
CRT_INTERNAL void crpc_caller_wait_exit(struct crpc_caller *c);
CRT_INTERNAL int  crpc_caller_wait(struct crpc_caller *c, int64_t deadline_ns);
CRT_INTERNAL int  crpc_caller_done_p(const struct crpc_caller *c);

#define CONTROL_RPC_TOMBSTONE_MAX 8u
#define CONTROL_RPC_TABLE_CAP     16u

enum crpc_state {
	CRPC_LOCAL_QUEUED = 0,
	CRPC_IN_FLIGHT,
	CRPC_REPLIED,
	CRPC_CALLER_DONE,
	CRPC_TIMED_OUT_TOMBSTONE,
	CRPC_LATE_REPLIED,
	CRPC_CANCELLING,
	CRPC_SESSION_DEAD,
};

CRT_INTERNAL uint32_t crpc_window_request(uint32_t wmax, uint32_t contexts,
					   uint32_t peer_credit,
					   uint32_t tx_slots, uint32_t rx_slots,
					   uint32_t exec_pending,
					   uint32_t resp_resv);
CRT_INTERNAL int crpc_credit_may_admit(uint64_t admitted_total,
					uint64_t credit_total, uint32_t w);

#define CRPC_NO_SLOT 0xffffffffu

struct crpc_req {
	uint8_t  state;
	uint8_t  has_reverse;

	uint8_t  taken;
	uint8_t  replied_flag;
	uint64_t request_id;
	uint64_t deadline_us;
	int32_t  status;
	struct crpc_caller *caller;
	struct crpc_desc desc;
	uint32_t tx_slot;
	int32_t  terminal_err;

	int64_t  trace_reg_ns;
	int64_t  trace_submit_ns;
	int64_t  trace_op_ns;
	int64_t  trace_push_ns;
	int64_t  trace_efd_ns;
	int64_t  trace_entry_ns;
};

struct crpc_requester {
	uint64_t session_id;
	struct crpc_req req[CONTROL_RPC_TABLE_CAP];
	uint64_t next_request_id;
	uint64_t admitted_total;
	uint64_t peer_credit_total;
	uint32_t window;
	uint32_t tombstones;
	uint32_t inflight;
	uint32_t peak_inflight;

	int      fail_closed;
	long     violations;
};

CRT_INTERNAL void crpc_requester_init(struct crpc_requester *t,
				       uint64_t session_id, uint32_t window);
CRT_INTERNAL int crpc_submit(struct crpc_requester *t, uint32_t *idx);
CRT_INTERNAL int crpc_admit(struct crpc_requester *t, uint32_t idx,
			     uint64_t *request_id);
CRT_INTERNAL int crpc_credit_recv(struct crpc_requester *t,
				   uint64_t credit_total);
CRT_INTERNAL int crpc_response_match(struct crpc_requester *t,
				      uint64_t session_id,
				      uint64_t request_id, int32_t status);
CRT_INTERNAL int crpc_req_timeout(struct crpc_requester *t, uint32_t idx);
CRT_INTERNAL int crpc_caller_done(struct crpc_requester *t, uint32_t idx);

CRT_INTERNAL int crpc_session_fail(struct crpc_requester *t);
CRT_INTERNAL void crpc_attach(struct crpc_requester *t, uint32_t idx,
			       const struct crpc_desc *d,
			       struct crpc_caller *caller);
CRT_INTERNAL const struct crpc_desc *crpc_attach_desc(
				const struct crpc_requester *t, uint32_t idx);
CRT_INTERNAL struct crpc_caller *crpc_attach_take_caller(
				struct crpc_requester *t, uint32_t idx);
CRT_INTERNAL uint32_t crpc_attach_slot(const struct crpc_requester *t,
					uint32_t idx);
CRT_INTERNAL void crpc_attach_set_slot(struct crpc_requester *t,
					uint32_t idx, uint32_t slot);
CRT_INTERNAL int32_t crpc_attach_terminal(const struct crpc_requester *t,
					   uint32_t idx);
CRT_INTERNAL void crpc_attach_set_terminal(struct crpc_requester *t,
					    uint32_t idx, int32_t err);

CRT_INTERNAL void crpc_attach_trace(struct crpc_requester *t, uint32_t idx,
				    int64_t submit_ns, int64_t reg_ns,
				    int64_t op_ns);
CRT_INTERNAL void crpc_attach_trace_sub(struct crpc_requester *t,
					uint32_t idx, int64_t push_ns,
					int64_t efd_ns, int64_t entry_ns);
CRT_INTERNAL void crpc_attach_trace_get(const struct crpc_requester *t,
					uint32_t idx, int64_t *submit_ns,
					int64_t *reg_ns, int64_t *op_ns);
CRT_INTERNAL void crpc_attach_trace_sub_get(const struct crpc_requester *t,
					    uint32_t idx, int64_t *push_ns,
					    int64_t *efd_ns,
					    int64_t *entry_ns);

CRT_INTERNAL uint32_t crpc_peak_inflight(const struct crpc_requester *t);
CRT_INTERNAL uint32_t crpc_inflight(const struct crpc_requester *t);

CRT_INTERNAL int crpc_deadline_scan(const struct crpc_requester *t,
				     uint64_t now_us, uint32_t *out_idx,
				     uint32_t out_max);

struct crpc_owner {
	uint64_t session_id;
	uint64_t admitted_total;
	uint64_t released_total;
	uint64_t last_request_id;
	uint32_t window;
	int      fail_closed;
	long     violations;
};

CRT_INTERNAL void crpc_owner_init(struct crpc_owner *o, uint64_t session_id,
				   uint32_t window);

CRT_INTERNAL int crpc_owner_admit(struct crpc_owner *o);
CRT_INTERNAL int crpc_owner_release(struct crpc_owner *o);
CRT_INTERNAL uint64_t crpc_owner_credit(const struct crpc_owner *o);

CRT_INTERNAL int crpc_owner_check_request_id(struct crpc_owner *o,
					      uint64_t request_id);

#endif
