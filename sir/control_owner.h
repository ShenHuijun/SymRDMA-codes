/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_OWNER_H
#define CONTROL_OWNER_H

#include <stdint.h>

#include "control_log.h"
#include "control_protocol.h"

struct ctrl_reactor;

#define COWN_REQ_CAP (2u * CONTROL_WINDOW_MAX + 4u)
#define COWN_SLOT_NONE 0xffffffffu

enum cown_state {
	COWN_FREE = 0,
	COWN_PENDING,
	COWN_EXEC,
	COWN_REV_WAIT,
	COWN_DONE,
};

struct cown_span {
	uint64_t token;
	int32_t  status;
	uint32_t wc_done;
	/* the span's export range is held by a PIN until this request reaches a
	 * terminal state (reverse write landed, or abandoned) */
	uint32_t pinned;
	int64_t  post_ns;

};

struct cown_req {
	uint8_t  state;
	uint8_t  taken;
	uint8_t  aborted;
	uint8_t  owner_released;
	uint64_t request_id;
	uint32_t op;
	uint32_t dir;
	uint32_t rkey;
	uint64_t page_idx, npages;
	uint32_t off, len;
	uint64_t xaddr;
	uint32_t xrkey;
	uint64_t va, operand_a, operand_b;
	uint32_t nspan;
	struct cproto_repair_span span[CONTROL_REPAIR_BATCH_MAX];
	struct cown_span sp[CONTROL_REPAIR_BATCH_MAX];
	uint8_t  inline_data[CONTROL_PAYLOAD_MAX];
	uint8_t  resp_data[CONTROL_PAYLOAD_MAX];
	uint32_t resp_len;
	uint32_t resp_slot;
 struct cproto_export_entry lookup;
	uint64_t job_id;
	uint64_t lease;
	struct creg_owner_view view;
	uint32_t rev_pending;
	uint32_t rev_fail;
	int32_t  exec_status;
	uint32_t exec_mlen;
	uint32_t exec_done;
	uint64_t exec_old_val;
	uint32_t rev_needed;
	int64_t  trace_admit_ns;

};

struct cown_resp {
 uint32_t lookup_key;
 struct cproto_export_entry lookup;
	uint32_t op;
	int32_t  status;
	uint64_t old_val;
	uint32_t mlen;
	uint32_t nspan;
	uint32_t span_status[CONTROL_REPAIR_BATCH_MAX];
	uint32_t data_len;
	const uint8_t *data;
};

struct cown_rev {
	uint64_t job_id;
	uint32_t si;
	int64_t  t0_ns;

	uint32_t dir;
	uint64_t lkey;
	uint64_t raddr;
	uint64_t xaddr;
	uint32_t xrkey;
	uint32_t xlen;
};

struct cown;

CRT_INTERNAL struct cown *cown_new(struct ctrl_reactor *r);
CRT_INTERNAL void cown_free(struct cown *o);
CRT_INTERNAL int cown_busy(const struct ctrl_reactor *r);
CRT_INTERNAL int cown_stopped_reap(struct ctrl_reactor *r);

CRT_INTERNAL uint64_t cown_credit(const struct cown *o);
CRT_INTERNAL void cown_ledger_reset(struct ctrl_reactor *r);
CRT_INTERNAL int  cown_reset_pending(struct ctrl_reactor *r);

CRT_INTERNAL int cown_rx_request(struct ctrl_reactor *r,
				  const struct cproto_header *h,
				  const uint8_t *payload, uint32_t plen);

CRT_INTERNAL int cown_retry(struct ctrl_reactor *r);

CRT_INTERNAL int cown_on_exec_done(struct ctrl_reactor *r, uint64_t job_id);

CRT_INTERNAL int cown_rev_next(struct ctrl_reactor *r, uint64_t job_id,
				struct cown_rev *out);
CRT_INTERNAL int cown_rev_next_any(struct ctrl_reactor *r,
				    struct cown_rev *out);

CRT_INTERNAL void cown_rev_posted(struct ctrl_reactor *r,
				   const struct cown_rev *rev, uint64_t token);
CRT_INTERNAL int cown_rev_wc(struct ctrl_reactor *r, uint64_t token,
			      uint64_t job_id, int ok);

CRT_INTERNAL int cown_session_abort(struct ctrl_reactor *r);

#endif
