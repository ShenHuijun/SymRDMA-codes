#include "rdv_bridge.h"
/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>

#include "symrdma_abi.h"

#include "control_reactor.h"
#include "control_owner.h"
#include "control_trace.h"
#include "control_executor.h"
#include "endpoint_registry.h"

struct cown {
	struct ctrl_reactor *r;
	struct crpc_owner rown;
	struct cown_req req[COWN_REQ_CAP];
	uint32_t owner_aborting;
	int      owner_reset_pending;
};

CRT_INTERNAL struct cown *cown_new(struct ctrl_reactor *r)
{
	struct cown *o = calloc(1, sizeof(*o));
	uint32_t i;

	if (!o)
		return NULL;
	o->r = r;
	crpc_owner_init(&o->rown, 0, 0);
	for (i = 0; i < COWN_REQ_CAP; i++)
		o->req[i].resp_slot = COWN_SLOT_NONE;
	return o;
}

static int cown_taken(const struct cown *o)
{
	for (unsigned i = 0; i < COWN_REQ_CAP; i++)
		if (o->req[i].taken)
			return 1;
	return 0;
}
CRT_INTERNAL void cown_free(struct cown *o)
{
	free(o);
}

CRT_INTERNAL uint64_t cown_credit(const struct cown *o)
{
	return o ? crpc_owner_credit(&o->rown) : 0;
}

CRT_INTERNAL void cown_ledger_reset(struct ctrl_reactor *r)
{
	if (!r || !r->own)
		return;
	crpc_owner_init(&r->own->rown, csess_session_id(r->sess),
			csess_window_in(r->sess));
}

CRT_INTERNAL int cown_reset_pending(struct ctrl_reactor *r)
{
	return r && r->own ? r->own->owner_reset_pending : 0;
}

static struct cown_req *cown_alloc(struct cown *o)
{
	uint32_t i;

	for (i = 0; i < COWN_REQ_CAP; i++) {
		struct cown_req *rq = &o->req[i];

		if (!rq->taken) {
			memset(rq, 0, sizeof(*rq));
			rq->taken = 1;
			rq->resp_slot = COWN_SLOT_NONE;
			return rq;
		}
	}
	return NULL;
}

CRT_INTERNAL int cown_rx_request(struct ctrl_reactor *r,
				  const struct cproto_header *h,
				  const uint8_t *payload, uint32_t plen)
{
	struct cown *o = r->own;
	struct cown_req *rq;
	uint32_t op = 0;

	if (cproto_op_get(payload, plen, &op))
		return -EPROTO;
	if (crpc_owner_check_request_id(&o->rown, h->request_id))
		return -EPROTO;
	rq = cown_alloc(o);
	if (!rq) {

		crt_log("owner context table full request_id=%llu — protocol violation",
			 (unsigned long long)h->request_id);
		return -EPROTO;
	}
	rq->request_id = h->request_id;
	rq->op = op;
	switch (op) {
 case CPROTO_OP_KEY_LOOKUP:
  if(cproto_key_lookup_req_decode(payload,plen,&rq->rkey))return -EPROTO;
  break;
	case CPROTO_OP_REPAIR_INLINE: {
		struct cproto_repair_inline ri;
		const uint8_t *data = NULL;

		if (cproto_repair_inline_req_decode(payload, plen, &ri, &data))
			return -EPROTO;
		rq->rkey = ri.rkey;
		rq->dir = ri.dir;
		rq->page_idx = ri.page_idx;
		rq->npages = 1;
		rq->off = ri.off;
		rq->len = ri.len;
		if (ri.len && data)
			memcpy(rq->inline_data, data, ri.len);
		break;
	}
	case CPROTO_OP_REPAIR_REVERSE: {
		struct cproto_repair_reverse rr;

		if (cproto_repair_reverse_req_decode(payload, plen, &rr))
			return -EPROTO;
		rq->rkey = rr.rkey;
		rq->dir = rr.dir;
		rq->page_idx = rr.page_idx;
		rq->npages = rr.npages;
		rq->xaddr = rr.xaddr;
		rq->xrkey = rr.xrkey;
		rq->off = rr.xoff;
		rq->len = rr.xlen;
		rq->nspan = 1;
		rq->span[0].page_idx = rr.page_idx;
		rq->span[0].npages = (uint32_t)rr.npages;
		rq->span[0].dir = rr.dir;
		rq->span[0].xaddr = rr.xaddr;
		rq->span[0].xrkey = rr.xrkey;
		rq->span[0].xoff = rr.xoff;
		rq->span[0].xlen = rr.xlen;
		break;
	}
	case CPROTO_OP_REPAIR_BATCH: {
		struct cproto_repair_span sp[CONTROL_REPAIR_BATCH_MAX];
		uint32_t nspan = 0, i;

		if (cproto_repair_batch_req_decode(payload, plen, &rq->rkey,
						   sp, CONTROL_REPAIR_BATCH_MAX,
						   &nspan))
			return -EPROTO;
		rq->nspan = nspan;
		for (i = 0; i < nspan; i++)
			rq->span[i] = sp[i];
		break;
	}
	case CPROTO_OP_ATOMIC: {
		struct cproto_atomic at;

		if (cproto_atomic_req_decode(payload, plen, &at))
			return -EPROTO;
		rq->rkey = at.rkey;
		rq->dir = at.op;
		rq->va = at.va;
		rq->operand_a = at.operand_a;
		rq->operand_b = at.operand_b;
		break;
	}
	default:
		crt_log("owner RX unknown op=%u — protocol violation", op);
		return -EPROTO;
	}
	rq->state = COWN_PENDING;

	rq->trace_admit_ns = ctrace_ts();
	return cown_retry(r);
}

static int cown_respond(struct ctrl_reactor *,struct cown_req *);
/* Only this owner table can certify absence; ACTIVE aliases share one record.
 * A closing key or registry failure is an error, never a native-key verdict. */
static int cown_lookup_export(uint32_t key,struct cproto_export_entry *entry)
{
 struct creg_owner_view v;uint64_t lease=0;int rc;
 memset(entry,0,sizeof(*entry));rc=creg_owner_acquire(key,&v,&lease);
 if(rc)return rc<0?-rc:EPROTO;
 entry->app_rkey=v.app_rkey;entry->app_access=v.app_access;
 entry->data_rkey=v.data_rkey;entry->write_rkey=v.write_rkey;entry->v_rkey=v.v_rkey;
 entry->addr=v.addr;entry->len=v.len;entry->v_addr=v.v_addr;
 rc=creg_lease_put(lease);return rc?(rc<0?-rc:EPROTO):0;
}

static int cown_admit_step(struct ctrl_reactor *r, struct cown_req *rq)
{
	struct cexec_cmd cmd;
	struct creg_owner_view peek;
	enum cexec_job_kind kind;
	uint64_t base = 0;
	uint64_t range_start, range_len;
	uint64_t job_id = 0;
	int rc;

	if (rq->state != COWN_PENDING)
		return 0;
	if (rq->resp_slot == COWN_SLOT_NONE) {
		rc = ctrans_tx_reserve(&r->tx, CTRANS_TX_RESPONSE,
				       &rq->resp_slot);
		if (rc == -EBUSY)
			return 0;
		if (rc)
			return rc;
	}

 if(rq->op==CPROTO_OP_KEY_LOOKUP){
  if(crpc_owner_admit(&r->own->rown))return -EPROTO;
  rq->exec_status=cown_lookup_export(rq->rkey,&rq->lookup);
  rq->state=COWN_DONE;rc=cown_respond(r,rq);return rc<0?rc:0;
 }
	if (creg_owner_peek(rq->rkey, &peek) == 0)
		base = peek.addr;
	switch (rq->op) {
	case CPROTO_OP_REPAIR_INLINE:
		kind = CEXEC_JOB_INLINE;
		range_start = base + rq->page_idx * CONTROL_PAGE_SIZE +
			      rq->off;
		range_len = rq->len;
		break;
	case CPROTO_OP_REPAIR_REVERSE:
		kind = CEXEC_JOB_REVERSE;
		range_start = base + rq->page_idx * CONTROL_PAGE_SIZE;
		range_len = rq->npages * CONTROL_PAGE_SIZE;
		break;
	case CPROTO_OP_REPAIR_BATCH: {
		uint32_t i;
		uint64_t lo = ~0ull, hi = 0;

		kind = CEXEC_JOB_BATCH;
		for (i = 0; i < rq->nspan; i++) {
			uint64_t s = rq->span[i].page_idx * CONTROL_PAGE_SIZE;
			uint64_t e = s + (uint64_t)rq->span[i].npages *
					   CONTROL_PAGE_SIZE;

			if (s < lo)
				lo = s;
			if (e > hi)
				hi = e;
		}
		range_start = (lo == ~0ull) ? 0 : base + lo;
		range_len = (lo == ~0ull) ? 1 : hi - lo;
		break;
	}
	case CPROTO_OP_ATOMIC:
		kind = CEXEC_JOB_ATOMIC;
		range_start = rq->va;
		range_len = 8;
		break;
	default:
		return -EPROTO;
	}
	rc = cexec_job_admit(&r->exec, kind, rq->dir, rq->rkey, range_start,
			     range_len, &job_id);
	if (rc == -EBUSY)
		return 0;
	if (rc)
		return rc;
	if (crpc_owner_admit(&r->own->rown))
		return -EPROTO;

	ctrace_done(CTRACE_PHASE_ADMIT, csess_session_id(r->sess),
		    rq->request_id, job_id, 0, rq->trace_admit_ns);
	rq->trace_admit_ns = 0;
	memset(&cmd, 0, sizeof(cmd));
	cmd.kind = (uint8_t)kind;
	cmd.op = (uint8_t)rq->op;
	cmd.dir = rq->dir;
	cmd.rkey = rq->rkey;
	cmd.page_idx = rq->page_idx;
	cmd.npages = rq->npages;
	cmd.off = rq->off;
	cmd.len = rq->len;
	cmd.xaddr = rq->xaddr;
	cmd.xrkey = rq->xrkey;
	cmd.va = rq->va;
	cmd.operand_a = rq->operand_a;
	cmd.operand_b = rq->operand_b;
	cmd.nspan = rq->nspan;
	memcpy(cmd.span, rq->span, sizeof(cmd.span));
	if (rq->len && rq->len <= sizeof(cmd.inline_data))
		memcpy(cmd.inline_data, rq->inline_data, rq->len);
	cmd.request_id = rq->request_id;
	cmd.session_id = csess_session_id(r->sess);
	cmd.sym_fd = __atomic_load_n(&r->cfg.sym_fd, __ATOMIC_ACQUIRE);
	if (cexec_job_set_cmd(&r->exec, job_id, &cmd))
		return -EPROTO;
	rq->job_id = job_id;
	rq->state = COWN_EXEC;

	return cexec_schedule(&r->exec);
}

/* Release every hold this request still owns. UNPIN releases the hold; it does
 * not evict and does not move the mapping the repair just established,
 * so this is safe on every terminal path. A flag is cleared only after actual
 * UNPIN success; failed spans retain their owner for retry. One funnel per
 * terminal state: respond after reverse writes complete, or recycle an
 * abandoned request. */
static int cown_pin_release(struct ctrl_reactor *r, struct cown_req *rq)
{
	int fd = __atomic_load_n(&r->cfg.sym_fd, __ATOMIC_ACQUIRE);
	uint32_t i;
	int bad = 0;

	for (i = 0; i < rq->nspan && i < CONTROL_REPAIR_BATCH_MAX; i++) {
		struct symrdma_ioc_pin pin;

		if (!rq->sp[i].pinned)
			continue;
		if (fd < 0 || rq->view.mr_id < 0) {
			bad = 1;
			continue;
		}
		memset(&pin, 0, sizeof(pin));
		pin.mr_id = rq->view.mr_id;
		pin.va = rq->view.addr +
			 rq->span[i].page_idx * CONTROL_PAGE_SIZE;
		pin.len = (uint64_t)rq->span[i].npages * CONTROL_PAGE_SIZE;
		if (ioctl(fd, SYMRDMA_IOC_UNPIN_PAGES, &pin)) {
			crt_log("UNPIN failed mr=%d page=%llu npages=%u errno=%d",
				rq->view.mr_id,
				(unsigned long long)rq->span[i].page_idx,
				rq->span[i].npages, errno);
			bad = 1;
		} else {
			rq->sp[i].pinned = 0;
		}
	}
	return bad ? -EPROTO : 0;
}

static int cown_recycle(struct ctrl_reactor *r, struct cown_req *rq,
			int owner_credit)
{
	struct cown *o = r->own;
	if (cown_pin_release(r, rq))
		return -EPROTO;
	if (owner_credit && !rq->owner_released) {
		if (crpc_owner_release(&o->rown))
			return -EPROTO;
		rq->owner_released = 1;
	}
	if (rq->job_id) {
		if (cexec_job_release(&r->exec, rq->job_id))
			return -EPROTO;
		rq->job_id = 0;
	}
	if (rq->lease) {
		if (creg_lease_put(rq->lease))
			return -EPROTO;
		rq->lease = 0;
	}
	memset(rq, 0, sizeof(*rq));
	rq->resp_slot = COWN_SLOT_NONE;
	return 0;
}
static int cown_respond(struct ctrl_reactor *r, struct cown_req *rq)
{
	struct cown *o = r->own;
	struct cown_resp resp;
	uint64_t request_id = rq->request_id;
	uint32_t slot = rq->resp_slot;
	int32_t status = rq->exec_status;
	uint32_t i;
	int64_t t_post = ctrace_ts();
	int rc;

	/* Every reverse write has completed (this is the only path that answers a
	 * batch), so the holds end here - "WC then UNPIN" is the required ordering
	 * fixes. */
	if (cown_pin_release(r, rq))
		return -EPROTO;

	if (!status) {
		for (i = 0; i < rq->nspan && !status; i++)
			status = rq->sp[i].status;
	}

	if (!rq->owner_released) {
		if (crpc_owner_release(&o->rown))
			return -EPROTO;
		rq->owner_released = 1;
	}
	if (rq->job_id) {
		if (cexec_job_release(&r->exec, rq->job_id))
			return -EPROTO;
		rq->job_id = 0;
	}
	if (rq->lease) {
		creg_lease_put(rq->lease);
		rq->lease = 0;
	}
	memset(&resp, 0, sizeof(resp));
	resp.op = rq->op;
 resp.lookup_key=rq->rkey;resp.lookup=rq->lookup;
	resp.status = status;
	resp.old_val = rq->exec_old_val;
	resp.mlen = rq->exec_mlen;
	resp.nspan = rq->nspan;
	resp.data_len = rq->resp_len;
	resp.data = rq->resp_data;
	for (i = 0; i < rq->nspan && i < CONTROL_REPAIR_BATCH_MAX; i++)
		resp.span_status[i] = (uint32_t)(rq->sp[i].status & 0xffffffffu);

	if (csess_teardown_active(r->sess)) {
		crt_log("response dropped (session teardown) id=%llu",
			 (unsigned long long)request_id);
		rq->state = COWN_FREE;
		rq->taken = 0;
		return 0;
	}
	rc = ctrl_tx_response(r, slot, request_id, &resp);
	ctrace_done(CTRACE_PHASE_RESP_POST, csess_session_id(r->sess),
		    request_id, rq->job_id, rc ? (uint16_t)-rc : 0, t_post);
	if (rc) {
		crt_log("response SEND post failed rc=%d — session invalidated", rc);
		return rc;
	}
	rq->state = COWN_FREE;
	rq->taken = 0;
	return 1;
}

CRT_INTERNAL int cown_on_exec_done(struct ctrl_reactor *r, uint64_t job_id)
{
	struct cown *o = r->own;
	struct cown_req *rq = NULL;
	struct cexec_result res;
	uint32_t i;

	for (i = 0; i < COWN_REQ_CAP; i++) {
		if (o->req[i].taken && o->req[i].job_id == job_id) {
			rq = &o->req[i];
			break;
		}
	}
	if (!rq) {
		crt_log("executor completion unowned job_id=%llu — violation",
			(unsigned long long)job_id);
		return -EPROTO;
	}
	/* Executor result ownership transfers once, including a cleanup retry.
	 */
	if (!rq->exec_done) {
		if (cexec_result(&r->exec, job_id, &res)) {
			crt_log(
			    "executor result missing job_id=%llu — violation",
			    (unsigned long long)job_id);
			return -EPROTO;
		}
		rq->exec_status = res.status;
		rq->exec_mlen = res.mlen;
		rq->exec_old_val = res.old_val;
		rq->rev_needed = res.rev_needed;
		rq->resp_len = res.resp_len;
		if (res.resp_len && res.resp_len <= sizeof(rq->resp_data))
			memcpy(rq->resp_data, res.resp_data, res.resp_len);
		for (i = 0; i < rq->nspan && i < CONTROL_REPAIR_BATCH_MAX;
		     i++) {
			rq->sp[i].status = res.span_status[i];
			rq->sp[i].pinned = res.span_pinned[i];
		}
		if (res.lease) {
			rq->lease = res.lease;
			rq->view = res.view;
		}

		rq->exec_done = 1;
	}

	if (rq->aborted) {
		if (cown_recycle(r, rq, 1))
			return -EPROTO;
		if (o->owner_aborting)
			o->owner_aborting--;
		if (!o->owner_aborting && o->owner_reset_pending && !cown_taken(o)) {
			o->owner_reset_pending = 0;
			cown_ledger_reset(r);
		}
		return 0;
	}
	rq->state = COWN_DONE;
	if (rq->exec_status || !rq->rev_needed)
		return cown_respond(r, rq);
	rq->state = COWN_REV_WAIT;
	rq->rev_pending = 0;
	for (i = 0; i < rq->nspan; i++)
		if (!rq->sp[i].status)
			rq->rev_pending++;
	return 0;
}
static int cown_rev_scan(struct cown_req *rq, struct cown_rev *out)
{
	uint32_t i;

	if (!rq || rq->state != COWN_REV_WAIT)
		return -ENOENT;
	for (i = 0; i < rq->nspan; i++) {
		struct cown_span *sp = &rq->sp[i];

		if (sp->status || sp->token || sp->wc_done)
			continue;
		memset(out, 0, sizeof(*out));
		out->job_id = rq->job_id;
		out->si = i;
		out->t0_ns = ctrace_ts();
		out->dir = rq->span[i].dir;
		out->lkey = rq->view.lkey;
		out->raddr = rq->view.addr + rq->span[i].page_idx *
			     CONTROL_PAGE_SIZE + rq->span[i].xoff;
		out->xaddr = rq->span[i].xaddr;
		out->xrkey = rq->span[i].xrkey;
		out->xlen = rq->span[i].xlen;
		return 0;
	}
	return -ENOENT;
}

CRT_INTERNAL int cown_rev_next(struct ctrl_reactor *r, uint64_t job_id,
				struct cown_rev *out)
{
	struct cown *o = r->own;
	uint32_t i;

	if (!o || !out)
		return -EINVAL;
	for (i = 0; i < COWN_REQ_CAP; i++) {
		if (o->req[i].taken && o->req[i].job_id == job_id)
			return cown_rev_scan(&o->req[i], out);
	}
	return -ENOENT;
}

CRT_INTERNAL int cown_rev_next_any(struct ctrl_reactor *r,
				    struct cown_rev *out)
{
	struct cown *o = r->own;
	uint32_t i;

	if (!o || !out)
		return -EINVAL;
	for (i = 0; i < COWN_REQ_CAP; i++) {
		struct cown_req *rq = &o->req[i];

		if (!rq->taken || rq->state != COWN_REV_WAIT)
			continue;
		if (cown_rev_scan(rq, out) == 0)
			return 0;
	}
	return -ENOENT;
}

CRT_INTERNAL void cown_rev_posted(struct ctrl_reactor *r,
				   const struct cown_rev *rev, uint64_t token)
{
	struct cown *o = r->own;
	struct cown_req *rq = NULL;
	uint32_t i;

	if (!o || !rev || rev->si >= CONTROL_REPAIR_BATCH_MAX)
		return;
	for (i = 0; i < COWN_REQ_CAP; i++) {
		if (o->req[i].taken && o->req[i].job_id == rev->job_id) {
			rq = &o->req[i];
			break;
		}
	}
	if (!rq || rq->state != COWN_REV_WAIT)
		return;
	rq->sp[rev->si].token = token;
	if (ctrace_on()) {
		int64_t now = crt_now_ns();

		rq->sp[rev->si].post_ns = now;
		if (rev->t0_ns)
			ctrace_at(CTRACE_PHASE_REVERSE_POST,
				  csess_session_id(r->sess), rq->request_id,
				  rev->job_id, 0, rev->t0_ns,
				  (uint64_t)(now - rev->t0_ns));
	}
}

CRT_INTERNAL int cown_rev_wc(struct ctrl_reactor *r, uint64_t token,
			      uint64_t job_id, int ok)
{
	struct cown *o = r->own;
	struct cown_req *rq = NULL;
	uint32_t i, k = 0;

	for (i = 0; i < COWN_REQ_CAP; i++) {
		if (o->req[i].taken && o->req[i].job_id == job_id &&
		    o->req[i].state == COWN_REV_WAIT) {
			rq = &o->req[i];
			break;
		}
	}
	if (!rq) {
		crt_log("reverse WC unowned job_id=%llu — violation",
			 (unsigned long long)job_id);
		return -EPROTO;
	}
	for (k = 0; k < rq->nspan; k++)
		if (rq->sp[k].token == token)
			break;
	if (k == rq->nspan) {
		crt_log("reverse WC token unowned — violation");
		return -EPROTO;
	}

	if (rq->sp[k].post_ns) {
		int64_t now = crt_now_ns();

		ctrace_at(CTRACE_PHASE_REVERSE_WC, csess_session_id(r->sess),
			  rq->request_id, job_id,
			  (uint16_t)(ok ? 0 : EIO), now,
			  (uint64_t)(now - rq->sp[k].post_ns));
		rq->sp[k].post_ns = 0;
	}
	rq->sp[k].wc_done = 1;
	rq->sp[k].token = 0;
	if (!ok) {
		rq->sp[k].status = EIO;
		rq->rev_fail++;
	}
	if (rq->rev_pending)
		rq->rev_pending--;
	if (rq->rev_pending)
		return 0;
	rq->state = COWN_DONE;
	return cown_respond(r, rq);
}

CRT_INTERNAL int cown_retry(struct ctrl_reactor *r)
{
	struct cown *o = r->own;
	uint32_t i;

	for (i = 0; i < COWN_REQ_CAP; i++) {
		struct cown_req *rq = &o->req[i];
		int rc;

		if (!rq->taken || rq->state != COWN_PENDING)
			continue;
		rc = cown_admit_step(r, rq);
		if (rc) {
			crt_log("owner admission failed rc=%d (request_id=%llu) "
				 "— session invalidated",
				 rc, (unsigned long long)rq->request_id);
			return -1;
		}
	}
	return r->fatal ? -1 : 0;
}

CRT_INTERNAL int cown_session_abort(struct ctrl_reactor *r)
{
	struct cown *o = r->own;
	uint32_t i;
	int bad = 0;

	o->owner_aborting = 0;
	for (i = 0; i < COWN_REQ_CAP; i++) {
		struct cown_req *rq = &o->req[i];
		uint8_t state;

		if (!rq->taken)
			continue;
		rq->aborted = 1;
		state = rq->state;
		if (state == COWN_EXEC) {
			if (rq->job_id)
				(void)cexec_job_cancel(&r->exec, rq->job_id);
			o->owner_aborting++;
			continue;
		}
		if (cown_recycle(r, rq, state != COWN_PENDING)) {
			crt_log("old-session owner recycle violation — terminal");
			bad = 1;
		}
	}
	o->owner_reset_pending = (o->owner_aborting || cown_taken(o)) ? 1 : 0;
	if (!o->owner_reset_pending)
		cown_ledger_reset(r);
	return bad;
}

/* Explicit ownership handoff after reactor/worker join. This path must never
 * post a response or reverse DMA, including for a result not delivered before
 * the native transport failed. */
CRT_INTERNAL int cown_busy(const struct ctrl_reactor *r)
{
	if (!r || !r->own)
		return 0;
	if (r->own->owner_aborting || r->own->owner_reset_pending)
		return 1;
	for (unsigned i = 0; i < COWN_REQ_CAP; i++)
		if (r->own->req[i].taken)
			return 1;
	return 0;
}
CRT_INTERNAL int cown_stopped_reap(struct ctrl_reactor *r)
{
	if (!r || !r->own)
		return 0;
	if ((r->running && !pthread_equal(pthread_self(), r->thread)) ||
	    r->pv.qp || ctrans_epoch_jobs_busy(&r->pv) || r->exec.nthreads ||
	    __atomic_load_n(&r->exec.run, __ATOMIC_ACQUIRE))
		return -EBUSY;
	if (cown_session_abort(r))
		return -EPROTO;
	/* Drain already published results before releasing a job by direct
	 * lookup; otherwise a stale completion would later point at a retired
	 * job/owner. */
	for (unsigned n = 0; n < CONTROL_EXEC_PENDING_MAX; n++) {
		uint64_t id = 0;
		int rc = cexec_poll(&r->exec, &id);
		if (rc == -ENOENT)
			break;
		if (rc)
			return rc;
  enum cexec_job_kind domain;rc=cexec_job_kind(&r->exec,id,&domain);
  if(rc)return rc;
  if(domain==CEXEC_JOB_RDV_MEMORY){rc=rdv_bridge_on_exec(&r->exec,id);if(rc)return rc;continue;}
		rc = cown_on_exec_done(r, id);
		if (rc)
			return rc < 0 ? rc : -EPROTO;
	}
	for (unsigned i = 0; i < COWN_REQ_CAP; i++) {
		struct cown_req *rq = &r->own->req[i];
		if (!rq->taken)
			continue;
		if (rq->state != COWN_EXEC || !rq->aborted || !rq->job_id)
			return -EBUSY;
		/* A command left ADMITTED when workers joined has no DMA/PIN
		 * result. DONE commands retain their actual lease/PIN result
		 * for normal disposal. */
		int rc = cexec_stopped_cancel(&r->exec, rq->job_id);
		if (rc)
			return rc;
		rc = cown_on_exec_done(r, rq->job_id);
		if (rc)
			return rc < 0 ? rc : -EPROTO;
	}
	int bridge_rc=rdv_bridge_stopped_finish(&r->exec);if(bridge_rc)return bridge_rc;
 return cown_busy(r) || cexec_pending(&r->exec) ? -EBUSY : 0;
}
