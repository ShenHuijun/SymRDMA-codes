/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "control_err.h"
#include "control_futex.h"
#include "control_rpc.h"
#include "control_trace.h"

static uint32_t min32(uint32_t a, uint32_t b)
{
	return a < b ? a : b;
}

CRT_INTERNAL uint32_t crpc_window_request(uint32_t wmax, uint32_t contexts,
					   uint32_t peer_credit,
					   uint32_t tx_slots, uint32_t rx_slots,
					   uint32_t exec_pending,
					   uint32_t resp_resv)
{
	uint32_t w = wmax;

	w = min32(w, contexts);
	w = min32(w, peer_credit);
	w = min32(w, tx_slots >= 4 ? tx_slots - 4 : 0);
	w = min32(w, rx_slots >= 4 ? (rx_slots - 4) / 2 : 0);
	w = min32(w, exec_pending);
	w = min32(w, resp_resv);
	return w;
}

CRT_INTERNAL int crpc_credit_may_admit(uint64_t admitted_total,
					uint64_t credit_total, uint32_t w)
{
	return admitted_total - credit_total < (uint64_t)w;
}

CRT_INTERNAL struct crpc_caller *crpc_caller_new(void)
{

	return calloc(1, sizeof(struct crpc_caller));
}

CRT_INTERNAL void crpc_caller_free(struct crpc_caller *c)
{
	free(c);
}

CRT_INTERNAL void crpc_caller_complete(struct crpc_caller *c, int32_t err,
					const struct crpc_reply *rep)
{
	uint32_t old;
	int free_c = 0;

	if (!c)
		return;

	c->err = err;
	if (rep && !__atomic_load_n(&c->abandoned, __ATOMIC_ACQUIRE))
		c->reply = *rep;
	if (ctrace_on())
		c->trace_wake_ns = crt_now_ns();
	ctrace_stat_inc(CTRACE_STAT_WAKE_CALLER, 1);
	old = __atomic_exchange_n(&c->done, 1, __ATOMIC_ACQ_REL);
	if (!old) {
		int n = __atomic_load_n(&c->waiters, __ATOMIC_ACQUIRE) > 1 ? 0 : 1;

		(void)crt_futex_wake(&c->done, n);
	}

	if (__atomic_fetch_sub(&c->refs, 1, __ATOMIC_ACQ_REL) <= 1)
		free_c = 1;
	if (free_c)
		crpc_caller_free(c);
}

CRT_INTERNAL void crpc_caller_put(struct crpc_caller *c)
{
	int free_c = 0;

	if (!c)
		return;
	if (__atomic_fetch_sub(&c->refs, 1, __ATOMIC_ACQ_REL) <= 1)
		free_c = 1;
	if (free_c)
		crpc_caller_free(c);
}

CRT_INTERNAL void crpc_caller_wait_enter(struct crpc_caller *c)
{
	__atomic_fetch_add(&c->waiters, 1, __ATOMIC_ACQ_REL);
}

CRT_INTERNAL void crpc_caller_wait_exit(struct crpc_caller *c)
{
	__atomic_fetch_sub(&c->waiters, 1, __ATOMIC_ACQ_REL);
}

CRT_INTERNAL int crpc_caller_done_p(const struct crpc_caller *c)
{
	return c ? (int)__atomic_load_n(&c->done, __ATOMIC_ACQUIRE) : 1;
}

CRT_INTERNAL int crpc_caller_wait(struct crpc_caller *c, int64_t deadline_ns)
{
	if (!c)
		return -EINVAL;
	if (__atomic_load_n(&c->done, __ATOMIC_ACQUIRE))
		return 0;

	return crt_futex_wait(&c->done, 0, deadline_ns);
}

CRT_INTERNAL void crpc_attach(struct crpc_requester *t, uint32_t idx,
			       const struct crpc_desc *d,
			       struct crpc_caller *caller)
{
	struct crpc_req *r;

	if (!t || idx >= CONTROL_RPC_TABLE_CAP || !d)
		return;
	r = &t->req[idx];
	r->caller = caller;
	r->desc = *d;
	r->tx_slot = CRPC_NO_SLOT;
	r->terminal_err = 0;
}

CRT_INTERNAL const struct crpc_desc *crpc_attach_desc(
				const struct crpc_requester *t, uint32_t idx)
{
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return NULL;
	return &t->req[idx].desc;
}

CRT_INTERNAL struct crpc_caller *crpc_attach_take_caller(
				struct crpc_requester *t, uint32_t idx)
{
	struct crpc_caller *c;

	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return NULL;
	c = t->req[idx].caller;
	t->req[idx].caller = NULL;
	return c;
}

CRT_INTERNAL uint32_t crpc_attach_slot(const struct crpc_requester *t,
					uint32_t idx)
{
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return CRPC_NO_SLOT;
	return t->req[idx].tx_slot;
}

CRT_INTERNAL void crpc_attach_set_slot(struct crpc_requester *t,
					uint32_t idx, uint32_t slot)
{
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return;
	t->req[idx].tx_slot = slot;
}

CRT_INTERNAL int32_t crpc_attach_terminal(const struct crpc_requester *t,
					   uint32_t idx)
{
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return 0;
	return t->req[idx].terminal_err;
}

CRT_INTERNAL void crpc_attach_set_terminal(struct crpc_requester *t,
					    uint32_t idx, int32_t err)
{
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return;
	t->req[idx].terminal_err = err;
}

CRT_INTERNAL void crpc_attach_trace(struct crpc_requester *t, uint32_t idx,
				    int64_t submit_ns, int64_t reg_ns,
				    int64_t op_ns)
{
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return;
	t->req[idx].trace_submit_ns = submit_ns;
	t->req[idx].trace_reg_ns = reg_ns;
	t->req[idx].trace_op_ns = op_ns;
}

CRT_INTERNAL void crpc_attach_trace_get(const struct crpc_requester *t,
					uint32_t idx, int64_t *submit_ns,
					int64_t *reg_ns, int64_t *op_ns)
{
	if (submit_ns)
		*submit_ns = 0;
	if (reg_ns)
		*reg_ns = 0;
	if (op_ns)
		*op_ns = 0;
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return;
	if (submit_ns)
		*submit_ns = t->req[idx].trace_submit_ns;
	if (reg_ns)
		*reg_ns = t->req[idx].trace_reg_ns;
	if (op_ns)
		*op_ns = t->req[idx].trace_op_ns;
}
CRT_INTERNAL void crpc_attach_trace_sub(struct crpc_requester *t,
					uint32_t idx, int64_t push_ns,
					int64_t efd_ns, int64_t entry_ns)
{
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return;
	t->req[idx].trace_push_ns = push_ns;
	t->req[idx].trace_efd_ns = efd_ns;
	t->req[idx].trace_entry_ns = entry_ns;
}

CRT_INTERNAL void crpc_attach_trace_sub_get(const struct crpc_requester *t,
					    uint32_t idx, int64_t *push_ns,
					    int64_t *efd_ns,
					    int64_t *entry_ns)
{
	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return;
	if (push_ns)
		*push_ns = t->req[idx].trace_push_ns;
	if (efd_ns)
		*efd_ns = t->req[idx].trace_efd_ns;
	if (entry_ns)
		*entry_ns = t->req[idx].trace_entry_ns;
}

CRT_INTERNAL void crpc_requester_init(struct crpc_requester *t,
				       uint64_t session_id, uint32_t window)
{
	memset(t, 0, sizeof(*t));
	t->session_id = session_id;
	t->window = window;
}

static int crpc_free_slot(const struct crpc_requester *t)
{
	uint32_t i;

	for (i = 0; i < CONTROL_RPC_TABLE_CAP; i++)
		if (!t->req[i].taken)
			return (int)i;
	return -1;
}

CRT_INTERNAL int crpc_submit(struct crpc_requester *t, uint32_t *idx)
{
	int slot;

	if (!t || !idx)
		return -EINVAL;
	if (t->fail_closed)
		return -EPROTO;
	slot = crpc_free_slot(t);
	if (slot < 0)
		return -EBUSY;
	memset(&t->req[slot], 0, sizeof(t->req[slot]));
	t->req[slot].state = CRPC_LOCAL_QUEUED;
	t->req[slot].taken = 1;
	*idx = (uint32_t)slot;
	return 0;
}

CRT_INTERNAL int crpc_admit(struct crpc_requester *t, uint32_t idx,
			     uint64_t *request_id)
{
	struct crpc_req *r;

	if (!t || !request_id || idx >= CONTROL_RPC_TABLE_CAP)
		return -EINVAL;
	r = &t->req[idx];
	if (!r->taken)
		return -EPROTO;
	if (t->fail_closed)
		return -EPROTO;
	if (r->state != CRPC_LOCAL_QUEUED)
		return crt_violation(&t->fail_closed, &t->violations);
	if (t->tombstones >= CONTROL_RPC_TOMBSTONE_MAX)
		return crt_violation(&t->fail_closed, &t->violations);
	if (!crpc_credit_may_admit(t->admitted_total, t->peer_credit_total,
				   t->window))
		return -EBUSY;

	t->admitted_total++;
	t->next_request_id = t->admitted_total;
	r->state = CRPC_IN_FLIGHT;
	r->request_id = t->next_request_id;
	*request_id = r->request_id;
	if (r->caller) {
		r->caller->trace_session_id = t->session_id;
		r->caller->trace_request_id = r->request_id;
	}
	if (++t->inflight > t->peak_inflight)
		t->peak_inflight = t->inflight;
	return 0;
}

CRT_INTERNAL int crpc_credit_recv(struct crpc_requester *t,
				   uint64_t credit_total)
{
	if (!t)
		return -EINVAL;
	if (t->fail_closed)
		return -EPROTO;
	if (credit_total < t->peer_credit_total)
		return crt_violation(&t->fail_closed, &t->violations);

	if (credit_total > t->admitted_total)
		return crt_violation(&t->fail_closed, &t->violations);
	t->peer_credit_total = credit_total;
	return 0;
}

CRT_INTERNAL int crpc_response_match(struct crpc_requester *t,
				      uint64_t session_id,
				      uint64_t request_id, int32_t status)
{
	uint32_t i;

	if (!t)
		return -EINVAL;
	if (t->fail_closed)
		return -EPROTO;

	if (session_id != t->session_id)
		return -EPROTO;
	if (request_id == 0 || request_id > t->next_request_id)
		return crt_violation(&t->fail_closed, &t->violations);

	for (i = 0; i < CONTROL_RPC_TABLE_CAP; i++) {
		struct crpc_req *r = &t->req[i];

		if (!r->taken || r->request_id != request_id)
			continue;
		if (r->replied_flag)
			return crt_violation(&t->fail_closed,
					      &t->violations);
		switch (r->state) {
		case CRPC_IN_FLIGHT:
			r->state = CRPC_REPLIED;
			break;
		case CRPC_TIMED_OUT_TOMBSTONE:

			if (t->tombstones == 0)
				return crt_violation(&t->fail_closed,
						      &t->violations);
			t->tombstones--;
			r->state = CRPC_LATE_REPLIED;
			break;
		case CRPC_CANCELLING:
		case CRPC_SESSION_DEAD:
			return 0;
		default:

			return crt_violation(&t->fail_closed,
					      &t->violations);
		}
		r->replied_flag = 1;
		r->status = status;
		return 0;
	}
	return crt_violation(&t->fail_closed, &t->violations);
}

CRT_INTERNAL int crpc_req_timeout(struct crpc_requester *t, uint32_t idx)
{
	struct crpc_req *r;

	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return -EINVAL;
	r = &t->req[idx];
	if (t->fail_closed)
		return -EPROTO;
	if (!r->taken || r->state != CRPC_IN_FLIGHT)
		return crt_violation(&t->fail_closed, &t->violations);

	if (r->has_reverse) {
		r->state = CRPC_CANCELLING;
		return 0;
	}
	r->state = CRPC_TIMED_OUT_TOMBSTONE;
	r->status = -ETIMEDOUT;
	t->tombstones++;
	if (t->tombstones >= CONTROL_RPC_TOMBSTONE_MAX)
		return crt_violation(&t->fail_closed, &t->violations);
	return 0;
}

CRT_INTERNAL int crpc_caller_done(struct crpc_requester *t, uint32_t idx)
{
	struct crpc_req *r;

	if (!t || idx >= CONTROL_RPC_TABLE_CAP)
		return -EINVAL;
	r = &t->req[idx];
	if (!r->taken)
		return crt_violation(&t->fail_closed, &t->violations);
	if (r->caller)

		return crt_violation(&t->fail_closed, &t->violations);
	switch (r->state) {
	case CRPC_REPLIED:
	case CRPC_LATE_REPLIED:
	case CRPC_SESSION_DEAD:
		break;
	default:

		return crt_violation(&t->fail_closed, &t->violations);
	}
	if (t->inflight)
		t->inflight--;
	memset(r, 0, sizeof(*r));
	return 0;
}

CRT_INTERNAL int crpc_session_fail(struct crpc_requester *t)
{
	uint32_t i, moved = 0;

	if (!t)
		return -EINVAL;
	for (i = 0; i < CONTROL_RPC_TABLE_CAP; i++) {
		struct crpc_req *r = &t->req[i];

		if (!r->taken)
			continue;
		switch (r->state) {
		case CRPC_LOCAL_QUEUED:
		case CRPC_IN_FLIGHT:
		case CRPC_TIMED_OUT_TOMBSTONE:
		case CRPC_CANCELLING:
			if (r->state == CRPC_TIMED_OUT_TOMBSTONE) {
				if (t->tombstones == 0)
					return crt_violation(&t->fail_closed,
							      &t->violations);
				t->tombstones--;
			}
			r->state = CRPC_SESSION_DEAD;
			if (r->status == 0)
				r->status = -ECONNRESET;
			moved++;
			break;
		case CRPC_REPLIED:
		case CRPC_LATE_REPLIED:
		case CRPC_SESSION_DEAD:
		default:
			break;
		}
	}
	return (int)moved;
}

CRT_INTERNAL uint32_t crpc_peak_inflight(const struct crpc_requester *t)
{
	return t ? t->peak_inflight : 0;
}

CRT_INTERNAL uint32_t crpc_inflight(const struct crpc_requester *t)
{
	return t ? t->inflight : 0;
}

CRT_INTERNAL int crpc_deadline_scan(const struct crpc_requester *t,
				     uint64_t now_us, uint32_t *out_idx,
				     uint32_t out_max)
{
	uint32_t i, n = 0;

	if (!t || (!out_idx && out_max > 0))
		return -EINVAL;
	for (i = 0; i < CONTROL_RPC_TABLE_CAP && n < out_max; i++) {
		const struct crpc_req *r = &t->req[i];

		if (r->taken && r->state == CRPC_IN_FLIGHT &&
		    r->deadline_us != 0 && now_us >= r->deadline_us)
			out_idx[n++] = i;
	}
	return (int)n;
}

CRT_INTERNAL void crpc_owner_init(struct crpc_owner *o, uint64_t session_id,
				   uint32_t window)
{
	memset(o, 0, sizeof(*o));
	o->session_id = session_id;
	o->window = window;
}

CRT_INTERNAL int crpc_owner_admit(struct crpc_owner *o)
{
	if (!o)
		return -EINVAL;
	if (o->fail_closed) {
		crt_log("rown violation site=admit (already fail_closed) admin=%llu rel=%llu",
			 (unsigned long long)o->admitted_total,
			 (unsigned long long)o->released_total);
		return -EPROTO;
	}
	o->admitted_total++;
	return 0;
}

CRT_INTERNAL int crpc_owner_release(struct crpc_owner *o)
{
	if (!o)
		return -EINVAL;
	if (o->fail_closed)
		return -EPROTO;

	if (o->released_total >= o->admitted_total) {
		crt_log("rown violation site=release admin=%llu rel=%llu",
			 (unsigned long long)o->admitted_total,
			 (unsigned long long)o->released_total);
		return crt_violation(&o->fail_closed, &o->violations);
	}
	o->released_total++;
	return 0;
}

CRT_INTERNAL uint64_t crpc_owner_credit(const struct crpc_owner *o)
{
	return o ? o->released_total : 0;
}

CRT_INTERNAL int crpc_owner_check_request_id(struct crpc_owner *o,
					      uint64_t request_id)
{
	if (!o)
		return -EINVAL;
	if (o->fail_closed)
		return -EPROTO;
	if (request_id == 0 || request_id <= o->last_request_id) {
		crt_log("rown violation site=request_id id=%llu last=%llu",
			 (unsigned long long)request_id,
			 (unsigned long long)o->last_request_id);
		return crt_violation(&o->fail_closed, &o->violations);
	}
	if (request_id > o->released_total + (uint64_t)o->window) {
		crt_log("rown violation site=window id=%llu rel=%llu w=%u",
			 (unsigned long long)request_id,
			 (unsigned long long)o->released_total, o->window);
		return crt_violation(&o->fail_closed, &o->violations);
	}
	o->last_request_id = request_id;
	return 0;
}
