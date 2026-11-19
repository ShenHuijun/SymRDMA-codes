/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include "rdv_bridge.h"
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/syscall.h>
#include <sys/timerfd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "control_efd.h"
#include "control_reactor.h"
#include "control_app_qp.h"
#include "control_trace.h"

static void ctrl_timer_arm(struct ctrl_reactor *r);
static void ctrl_process_timer(struct ctrl_reactor *r);
static int ctrl_retry(struct ctrl_reactor *r);
static int ctrl_app_rdv_tx(struct ctrl_reactor *r);

/* Only the actor's own reactor resources cross this adapter. In particular
 * application PD/lkeys and NPR object pointers are never consulted here. */
static int ctrl_rdv_prepare(void *opaque,const struct rdv_bridge_config *cfg,
                            struct rdv_bridge_owner **out)
{struct ctrl_reactor *r=opaque;return rdv_bridge_prepare(&r->pv,&r->exec,cfg,out);}
static int ctrl_rdv_read_prepare(void *opaque,struct rdv_bridge_owner *owner,
                                const struct rdv_bridge_remote *spans,unsigned n)
{struct ctrl_reactor *r=opaque;return rdv_bridge_read_prepare(owner,&r->rev,spans,n);}
CRT_INTERNAL int ctrl_app_rdv_attach(struct ctrl_reactor *r)
{
 static const struct crdv_resource_ops ops={ctrl_rdv_prepare,ctrl_rdv_read_prepare};
 if(!r||!r->cfg.app_rdv_registry)return 0;
 return crdv_actor_new(r->cfg.app_rdv_registry,r,&ops,r,&r->app_rdv);
}
CRT_INTERNAL int ctrl_app_rdv_detach(struct ctrl_reactor *r)
{
 if(!r||!r->app_rdv)return 0;
 int rc=crdv_actor_free(r->app_rdv);if(!rc)r->app_rdv=NULL;return rc;
}
CRT_INTERNAL void ctrl_app_rdv_progress(struct ctrl_reactor *r)
{
 if(!r||!r->app_rdv)return;
 if(!r->fatal&&csess_ready(r->sess)){
  int up=crdv_session_up(r->app_rdv,csess_session_id(r->sess));
  if(up&&up!=EBUSY){csess_fail(r,CSESS_FAIL_ADMISSION);return;}
 }
 crdv_progress(r->app_rdv,(uint64_t)crt_now_us());
 if(!r->fatal&&csess_ready(r->sess)&&ctrl_app_rdv_tx(r))csess_fail(r,CSESS_FAIL_ADMISSION);
}
CRT_INTERNAL void ctrl_app_rdv_down(struct ctrl_reactor *r,int dma_stopped)
{
 if(!r||!r->app_rdv)return;
 crdv_session_down(r->app_rdv,dma_stopped);ctrl_app_rdv_progress(r);
}

static void ctrl_wake_sig(struct ctrl_reactor *r)
{
	pthread_mutex_lock(&r->sig_mu);
	pthread_cond_broadcast(&r->sig_cv);
	pthread_mutex_unlock(&r->sig_mu);
}

static int ctrl_canary_check(const uint8_t *buf, uint32_t idx)
{
	if (buf[0] == 0xA5 && buf[CONTROL_SLOT_CAPACITY - 1] == 0xA5)
		return 0;
	crt_log("canary readback violation idx=%u b0=%02x blast=%02x — suspected in-flight ghost "
		 "WQE write — session invalidated", idx, buf[0],
		 buf[CONTROL_SLOT_CAPACITY - 1]);
	return -1;
}

static int ctrl_rx_repost_now(struct ctrl_reactor *r, uint32_t idx)
{
	int rc;

	if (ctrans_rx_release(&r->rx, idx))
		return -EPROTO;
	if (r->cfg.poison_debug) {

		memset(r->rx.buf[idx], 0xA5, CONTROL_SLOT_CAPACITY);
		if (ctrl_canary_check(r->rx.buf[idx], idx))
			return -EPROTO;
	}
	if (ctrans_rx_give(&r->rx, idx))
		return -EPROTO;
	rc = ctrans_post_recv(&r->pv, r->rx.buf[idx], CONTROL_SLOT_CAPACITY,
			      ctrans_wrid_make(CTRANS_WRID_RX_BASE, idx));
	if (rc)
		return rc;
 if(r->data_rx_sid[idx]){
  uint64_t sid=r->data_rx_sid[idx];r->data_rx_sid[idx]=0;
  if(sid==r->data_credit_sid&&sid==csess_session_id(r->sess)&&
     ctrans_data_reposted(&r->data_credit))return -EPROTO;
 }
	return 0;
}

static int ctrl_rx_hold(struct ctrl_reactor *r, uint32_t idx)
{
	int64_t due = crt_now_us() + (int64_t)r->cfg.test_rnr_hold_us;

	if (r->rx_hold_n >= CTRANS_RX_SLOTS)
		return -EPROTO;
	r->rx_hold_idx[r->rx_hold_n++] = (uint8_t)idx;
	if (!r->rx_hold_due_us || due < r->rx_hold_due_us)
		r->rx_hold_due_us = due;
	return 0;
}

static int ctrl_rx_repost(struct ctrl_reactor *r, uint32_t idx)
{
	if (r->cfg.test_rnr_hold_us)
		return ctrl_rx_hold(r, idx);
	return ctrl_rx_repost_now(r, idx);
}

static void ctrl_rx_hold_drain(struct ctrl_reactor *r)
{
	uint32_t i;

	if (!r->rx_hold_n || !r->rx_hold_due_us ||
	    crt_now_us() < r->rx_hold_due_us)
		return;
	for (i = 0; i < r->rx_hold_n; i++)
		(void)ctrl_rx_repost_now(r, r->rx_hold_idx[i]);
	r->rx_hold_n = 0;
	r->rx_hold_due_us = 0;
}

CRT_INTERNAL int ctrl_tx_control(struct ctrl_reactor *r, uint16_t kind,
			   const uint8_t *payload, uint32_t plen,
			   uint64_t generation, uint64_t trace_request_id)
{
	uint32_t slot;
	struct cproto_header h;
	uint8_t *buf;
	int rc;

	rc = ctrans_tx_reserve(&r->tx, CTRANS_TX_CONTROL, &slot);
	if (rc)
		return rc;
	buf = ctrans_tx_payload(&r->tx, slot);
	if (!buf)
		return -EPROTO;
	memset(&h, 0, sizeof(h));
	h.magic = CONTROL_PROTO_MAGIC;
	h.version = CONTROL_PROTO_VERSION;
	h.header_len = CONTROL_HEADER_LEN;
	h.kind = kind;
	h.payload_len = plen;
	h.session_id = csess_session_id(r->sess);
	h.request_id = 0;
	h.credit_total = cown_credit(r->own);
	h.generation = generation;
	rc = cproto_header_encode(buf, CONTROL_SLOT_CAPACITY, &h);
	if (rc < 0)
		return rc;
	memcpy(buf + CONTROL_HEADER_LEN, payload, plen);
	rc = ctrans_tx_post(&r->tx, slot);
	if (rc)
		return rc;
	rc = ctrans_post_send(&r->pv, buf, CONTROL_HEADER_LEN + plen,
			      ctrans_wrid_make(CTRANS_WRID_TX_BASE, slot));
	if (rc) {
		crt_log("control SEND post failed rc=%d — session invalidated", rc);
		return rc;
	}
	if (ctrace_on() && trace_request_id)

		ctrans_tx_tag_set(&r->tx, slot, CTRACE_PHASE_TX_POST,
				  csess_session_id(r->sess), trace_request_id, 0,
				  crt_now_ns());
	return 0;
}

/* DATA is a physical-frame cumulative credit domain, independent of RPC.
 * CTRL credit reports are coalesced and may progress when DATA is exhausted. */
static int ctrl_app_rdv_tx(struct ctrl_reactor *r)
{
 if(r->data_credit_sid!=csess_session_id(r->sess))return 0;
 if(r->data_credit.rx_retired!=r->data_credit.credit_sent){
  uint8_t payload[12];uint64_t total=r->data_credit.rx_retired;
  if(cproto_rdv_credit_encode(payload,sizeof(payload),total)!=12)return -EPROTO;
  int rc=ctrl_tx_control(r,CPROTO_CONTROL_EVENT,payload,sizeof(payload),0,0);
  if(rc==-EBUSY||rc==-EAGAIN)return 0;
  if(rc)return rc;
  r->data_credit.credit_sent=total;
 }
 for(unsigned n=0;n<CTRANS_DATA_SLOTS&&ctrans_data_can_send(&r->data_credit);n++){
  uint32_t slot;int rc=ctrans_tx_reserve(&r->tx,CTRANS_TX_DATA,&slot);
  if(rc==-EBUSY)return 0;
  if(rc)return rc;
  struct crdv_frame frame;rc=crdv_frame_take(r->app_rdv,&frame);
  if(rc){(void)ctrans_tx_abort(&r->tx,slot);return rc==EAGAIN||rc==-EAGAIN?0:-abs(rc);}
  struct cproto_header h;
  if(frame.length>CONTROL_SLOT_CAPACITY||cproto_header_decode(frame.bytes,(uint32_t)frame.length,&h)||
     h.kind!=CPROTO_CONTROL_EVENT||h.session_id!=r->data_credit_sid){
   (void)ctrans_tx_abort(&r->tx,slot);(void)crdv_tx_result(r->app_rdv,frame.ticket,EPROTO);return -EPROTO;
  }
  /* RPC retirement piggyback is a transport field. Refresh it at the real
   * post boundary; the actor may have queued this full frame earlier. */
  h.credit_total=cown_credit(r->own);
  if(cproto_header_encode(frame.bytes,sizeof(frame.bytes),&h)<0){
   (void)ctrans_tx_abort(&r->tx,slot);(void)crdv_tx_result(r->app_rdv,frame.ticket,EPROTO);return -EPROTO;
  }
  memcpy(ctrans_tx_payload(&r->tx,slot),frame.bytes,frame.length);
  rc=ctrans_tx_post(&r->tx,slot);
  if(!rc)rc=ctrans_post_send(&r->pv,r->tx.buf[slot],(uint32_t)frame.length,ctrans_wrid_make(CTRANS_WRID_TX_BASE,slot));
  if(rc){
   if(r->tx.state[slot]==CTRANS_TX_RESERVED)(void)ctrans_tx_abort(&r->tx,slot);
   else if(r->tx.state[slot]==CTRANS_TX_POSTED)(void)ctrans_tx_release(&r->tx,slot);
   (void)crdv_tx_result(r->app_rdv,frame.ticket,abs(rc));return rc;
  }
  /* Only this actual native acceptance consumes one peer receive credit. */
  if(ctrans_data_sent(&r->data_credit))return -EPROTO;
  rc=crdv_tx_result(r->app_rdv,frame.ticket,0);if(rc)return -abs(rc);
 }
 return 0;
}

static int ctrl_tx_request(struct ctrl_reactor *r, uint32_t slot_idx,
			   uint32_t crpc_idx, uint64_t request_id)
{
	const struct crpc_desc *d = crpc_attach_desc(&r->rreq, crpc_idx);
	struct cproto_header h;
	uint8_t *buf;
	uint8_t *pl;
	int plen, rc;

	if (!d)
		return -EPROTO;
	buf = ctrans_tx_payload(&r->tx, slot_idx);
	if (!buf)
		return -EPROTO;
	pl = buf + CONTROL_HEADER_LEN;
	switch (d->op) {
 case CRPC_OP_KEY_LOOKUP:
  plen=cproto_key_lookup_req_encode(pl,CONTROL_PAYLOAD_MAX,d->rkey);break;
	case CRPC_OP_REPAIR_INLINE: {
		struct cproto_repair_inline ri;

		memset(&ri, 0, sizeof(ri));
		ri.rkey = d->rkey;
		ri.dir = d->dir;
		ri.page_idx = d->page_idx;
		ri.off = d->off;
		ri.len = d->len;
		plen = cproto_repair_inline_req_encode(pl, CONTROL_PAYLOAD_MAX,
						       &ri,
						       d->len ? d->inline_data :
								NULL);
		break;
	}
	case CRPC_OP_REPAIR_REVERSE: {
		struct cproto_repair_reverse rr;

		memset(&rr, 0, sizeof(rr));
		rr.rkey = d->rkey;
		rr.dir = d->dir;
		rr.page_idx = d->page_idx;
		rr.npages = d->npages;
		rr.xaddr = d->xaddr;
		rr.xrkey = d->xrkey;
		rr.xoff = d->off;
		rr.xlen = d->len;
		plen = cproto_repair_reverse_req_encode(pl, CONTROL_PAYLOAD_MAX,
							&rr);
		break;
	}
	case CRPC_OP_REPAIR_BATCH:
		plen = cproto_repair_batch_req_encode(pl, CONTROL_PAYLOAD_MAX,
						      d->rkey, d->span,
						      d->nspan);
		break;
	case CRPC_OP_ATOMIC: {
		struct cproto_atomic at;

		memset(&at, 0, sizeof(at));
		at.rkey = d->rkey;
		at.op = d->dir;
		at.va = d->va;
		at.operand_a = d->operand_a;
		at.operand_b = d->operand_b;
		plen = cproto_atomic_req_encode(pl, CONTROL_PAYLOAD_MAX, &at);
		break;
	}
	default:
		return -EINVAL;
	}
	if (plen < 0)
		return plen;
	memset(&h, 0, sizeof(h));
	h.magic = CONTROL_PROTO_MAGIC;
	h.version = CONTROL_PROTO_VERSION;
	h.header_len = CONTROL_HEADER_LEN;
	h.kind = CPROTO_RPC_REQUEST;
	h.payload_len = (uint32_t)plen;
	h.session_id = csess_session_id(r->sess);
	h.request_id = request_id;
	h.credit_total = cown_credit(r->own);
	h.generation = 0;
	rc = cproto_header_encode(buf, CONTROL_SLOT_CAPACITY, &h);
	if (rc < 0)
		return rc;
	rc = ctrans_tx_post(&r->tx, slot_idx);
	if (rc)
		return rc;
	rc = ctrans_post_send(&r->pv, buf, (uint32_t)(CONTROL_HEADER_LEN + plen),
			      ctrans_wrid_make(CTRANS_WRID_TX_BASE, slot_idx));
	if (!rc && ctrace_on())

		ctrans_tx_tag_set(&r->tx, slot_idx, CTRACE_PHASE_TX_POST,
				  csess_session_id(r->sess), request_id, 0,
				  crt_now_ns());
	if (crt_log_level() >= 2)
		crt_log("TX request id=%llu slot=%u len=%d rc=%d",
			 (unsigned long long)request_id, slot_idx,
			 (int)(CONTROL_HEADER_LEN + plen), rc);
	return rc;
}

CRT_INTERNAL int ctrl_tx_response(struct ctrl_reactor *r, uint32_t slot_idx,
				   uint64_t request_id,
				   const struct cown_resp *resp)
{
	struct cproto_header h;
	uint8_t *buf;
	uint8_t *pl;
	int plen, rc;

	if (!resp)
		return -EINVAL;
	buf = ctrans_tx_payload(&r->tx, slot_idx);
	if (!buf)
		return -EPROTO;
	pl = buf + CONTROL_HEADER_LEN;
	switch (resp->op) {
 case CPROTO_OP_KEY_LOOKUP:
  plen=cproto_key_lookup_resp_encode(pl,CONTROL_PAYLOAD_MAX,resp->lookup_key,resp->status,&resp->lookup);break;
	case CPROTO_OP_REPAIR_INLINE:
		plen = cproto_repair_inline_resp_encode(pl, CONTROL_PAYLOAD_MAX,
							resp->status,
							resp->data_len,
							resp->data_len ?
								resp->data :
								NULL);
		break;
	case CPROTO_OP_REPAIR_REVERSE:
		plen = cproto_repair_resp_encode(pl, CONTROL_PAYLOAD_MAX,
						 resp->status, resp->mlen);
		break;
	case CPROTO_OP_REPAIR_BATCH:
		plen = cproto_repair_batch_resp_encode(pl, CONTROL_PAYLOAD_MAX,
						       resp->status,
						       resp->span_status,
						       resp->nspan);
		break;
	case CPROTO_OP_ATOMIC:
		plen = cproto_atomic_resp_encode(pl, CONTROL_PAYLOAD_MAX,
						 resp->status,
						 resp->old_val);
		break;
	default:
		return -EINVAL;
	}
	if (plen < 0)
		return plen;
	memset(&h, 0, sizeof(h));
	h.magic = CONTROL_PROTO_MAGIC;
	h.version = CONTROL_PROTO_VERSION;
	h.header_len = CONTROL_HEADER_LEN;
	h.kind = CPROTO_RPC_RESPONSE;
	h.payload_len = (uint32_t)plen;
	h.session_id = csess_session_id(r->sess);
	h.request_id = request_id;

	h.credit_total = cown_credit(r->own);
	h.generation = 0;
	rc = cproto_header_encode(buf, CONTROL_SLOT_CAPACITY, &h);
	if (rc < 0)
		return rc;
	rc = ctrans_tx_post(&r->tx, slot_idx);
	if (rc)
		return rc;
	rc = ctrans_post_send(&r->pv, buf, (uint32_t)(CONTROL_HEADER_LEN + plen),
			      ctrans_wrid_make(CTRANS_WRID_TX_BASE, slot_idx));
	if (!rc && ctrace_on())
		ctrans_tx_tag_set(&r->tx, slot_idx, CTRACE_PHASE_RESP_POST,
				  csess_session_id(r->sess), request_id, 0,
				  crt_now_ns());
	if (crt_log_level() >= 2)
		crt_log("TX response id=%llu slot=%u len=%d rc=%d",
			 (unsigned long long)request_id, slot_idx,
			 (int)(CONTROL_HEADER_LEN + plen), rc);
	return rc;
}

static void ctrl_req_trace_admit(struct ctrl_reactor *r, uint32_t ci,
				 uint64_t request_id, int64_t t_admit,
				 uint16_t status)
{
	int64_t t_sub = 0, t_reg = 0, t_op = 0;
	uint64_t sess;

	if (!ctrace_on())
		return;
	crpc_attach_trace_get(&r->rreq, ci, &t_sub, &t_reg, &t_op);
	sess = csess_session_id(r->sess);
	if (t_sub)
		ctrace_at(CTRACE_PHASE_SUBMIT, sess, request_id, 0, status,
			  t_sub, (uint64_t)((t_reg ? t_reg : t_admit) - t_sub));
	if (t_reg && ctrace_sub_on()) {
		int64_t t_push = 0, t_efd = 0, t_entry = 0;

		crpc_attach_trace_sub_get(&r->rreq, ci, &t_push, &t_efd,
					  &t_entry);
		if (t_push && t_push > t_sub)
			ctrace_at(CTRACE_PHASE_SUB_RING, sess, request_id, 0,
				  status, t_sub,
				  (uint64_t)(t_push - t_sub));
		if (t_efd && t_push && t_efd >= t_push)
			ctrace_at(CTRACE_PHASE_SUB_EFD, sess, request_id, 0,
				  status, t_push,
				  (uint64_t)(t_efd - t_push));
		if (t_entry && t_efd && t_entry >= t_efd)
			ctrace_at(CTRACE_PHASE_SUB_WAKE, sess, request_id, 0,
				  status, t_efd,
				  (uint64_t)(t_entry - t_efd));
		if (t_entry && t_reg >= t_entry)
			ctrace_at(CTRACE_PHASE_SUB_REG, sess, request_id, 0,
				  status, t_entry,
				  (uint64_t)(t_reg - t_entry));
	}
	if (t_reg)
		ctrace_at(CTRACE_PHASE_CREDIT_WAIT, sess, request_id, 0,
			  status, t_reg, (uint64_t)(t_admit - t_reg));
	ctrace_op_detect(t_op, t_sub, status);
}

static int ctrl_req_advance(struct ctrl_reactor *r, uint32_t ci)
{
	struct crpc_req *cr = &r->rreq.req[ci];
	uint64_t request_id = 0;
	uint32_t slot;
	int rc;

	if (cr->state != CRPC_LOCAL_QUEUED)
		return 0;

	slot = crpc_attach_slot(&r->rreq, ci);
	if (slot == CRPC_NO_SLOT) {
		rc = ctrans_tx_reserve(&r->tx, CTRANS_TX_REQUEST, &slot);
		if (rc == -EBUSY)
			return 0;
		if (rc)
			return rc;
		crpc_attach_set_slot(&r->rreq, ci, slot);
	}
	rc = crpc_admit(&r->rreq, ci, &request_id);
	if (rc) {
		if (rc == -EBUSY)
			return 0;
		return rc;
	}

	ctrace_stat_max(CTRACE_STAT_PEAK_INFLIGHT, crpc_inflight(&r->rreq));

	if (!cr->deadline_us)
		cr->deadline_us = (uint64_t)crt_now_us() +
			(r->cfg.test_deadline_us ? r->cfg.test_deadline_us :
			 CTRL_RPC_DEADLINE_US);
	{
		int64_t t_tx = ctrace_ts();

		ctrl_req_trace_admit(r, ci, request_id, t_tx, 0);
		rc = ctrl_tx_request(r, slot, ci, request_id);
		if (!rc)
			ctrace_done(CTRACE_PHASE_TX_POST,
				    csess_session_id(r->sess), request_id, 0,
				    0, t_tx);
	}
	if (rc) {
		crt_log("request SEND post failed rc=%d — session invalidated", rc);
		return rc;
	}

	crpc_attach_set_slot(&r->rreq, ci, CRPC_NO_SLOT);
	return 0;
}

static void ctrl_process_submissions(struct ctrl_reactor *r)
{
	if (r->fatal || !csess_ready(r->sess))
		return;
	for (;;) {
		struct ctrl_submit_ent ent;
		uint32_t ci = 0, head;
		int rc;

		pthread_mutex_lock(&r->sub_mu);
		if (r->sub_head == r->sub_tail) {
			pthread_mutex_unlock(&r->sub_mu);
			return;
		}
		head = r->sub_head;
		ent = r->sub[head];
		pthread_mutex_unlock(&r->sub_mu);

		if (ent.d.op != CRPC_OP_PUBLISH_SNAPSHOT &&
		    ent.d.op != CRPC_OP_PING) {
			rc = crpc_submit(&r->rreq, &ci);
			if (rc == -EBUSY)
				return;
			if (rc) {
				csess_fail(r, CSESS_FAIL_CRPC_SUBMIT);
				return;
			}
		}
		pthread_mutex_lock(&r->sub_mu);
		memset(&r->sub[head], 0, sizeof(ent));
		__atomic_store_n(&r->sub_head,
				 (head + 1) % (uint32_t)(sizeof(r->sub) /
							 sizeof(r->sub[0])),
				 __ATOMIC_RELEASE);
		pthread_mutex_unlock(&r->sub_mu);

		switch (ent.d.op) {
		case CRPC_OP_PUBLISH_SNAPSHOT:
			crt_log("local export change → merged generation republish");
			csess_mark_export_dirty(r);
			if (csess_kick(r))
				csess_fail(r, CSESS_FAIL_SNAPSHOT_POST);
			continue;
		case CRPC_OP_PING:
			if (!r->ping_caller) {
				int64_t t_sub = 0, t_tx;
				uint64_t sess = csess_session_id(r->sess);

				r->ping_nonce = ++r->ping_seq;
				r->ping_deadline_us = crt_now_us() +
						      (int64_t)
						      CTRL_RPC_DEADLINE_US;
				r->ping_caller = ent.caller;
				if (ctrace_on() && ent.caller) {
					ent.caller->trace_session_id = sess;
					ent.caller->trace_request_id =
						r->ping_nonce;
					t_sub = ent.caller->trace_submit_ns;
				}
				t_tx = ctrace_ts();
				if (t_sub)
					ctrace_at(CTRACE_PHASE_SUBMIT, sess,
						  r->ping_nonce, 0, 0, t_sub,
						  (uint64_t)(t_tx - t_sub));
				{
					uint8_t pl[12];
					int prc;

					cproto_ping_encode(pl, sizeof(pl),
							   r->ping_nonce);
					prc = ctrl_tx_control(r,
							    CPROTO_CONTROL_EVENT,
							    pl, 12, 0,
							    r->ping_nonce);
					ctrace_done(CTRACE_PHASE_TX_POST, sess,
						    r->ping_nonce, 0,
						    prc ? (uint16_t)-prc : 0,
						    t_tx);
					if (prc) {
						r->ping_caller = NULL;
						crpc_caller_complete(
							ent.caller, -EIO, NULL);
					}
				}
			} else {
				crpc_caller_complete(ent.caller, -EBUSY, NULL);
			}
			continue;
		default:
			break;
		}

		if (ctrace_on()) {
			crpc_attach_trace(&r->rreq, ci,
					  ent.caller ? ent.caller->trace_submit_ns
						     : 0,
					  crt_now_ns(),
					  ent.caller ? ent.caller->trace_op_ns : 0);
			crpc_attach_trace_sub(&r->rreq, ci, ent.t_push_ns,
					      ent.t_efd_ns,
					      r->loop_entry_ns);
		}
		crpc_attach(&r->rreq, ci, &ent.d, ent.caller);
		r->rreq.req[ci].has_reverse =
			(ent.d.op == CRPC_OP_REPAIR_REVERSE ||
			 ent.d.op == CRPC_OP_REPAIR_BATCH) ? 1 : 0;
		r->rreq.req[ci].deadline_us = ent.d.deadline_us;
		ctrace_stat_inc(CTRACE_STAT_REQUESTED, 1);
		if (ctrl_req_advance(r, ci)) {

			csess_fail(r, CSESS_FAIL_REQUEST_POST);
			return;
		}
	}
}

static int ctrl_retry_queued(struct ctrl_reactor *r)
{
	uint32_t i;

	for (i = 0; i < CONTROL_RPC_TABLE_CAP; i++) {
		if (!r->rreq.req[i].taken ||
		    r->rreq.req[i].state != CRPC_LOCAL_QUEUED)
			continue;
		if (ctrl_req_advance(r, i))
			return -1;
	}
	return 0;
}

static int ctrl_rx_response(struct ctrl_reactor *r,
			    const struct cproto_header *h,
			    const uint8_t *payload, uint32_t plen)
{
	struct crpc_caller *caller = NULL;
	struct crpc_reply rep;
	uint32_t op = 0, i;
	int32_t status = 0;
	int64_t t_wake = ctrace_ts();
	int64_t caller_t_sig = 0;
	int rc;

	if (cproto_op_get(payload, plen, &op))
		return -EPROTO;
	memset(&rep, 0, sizeof(rep));
	switch (op) {
 case CPROTO_OP_KEY_LOOKUP:{
  struct cproto_export_entry entry;uint32_t key;
  if(cproto_key_lookup_resp_decode(payload,plen,&key,&status,&entry))return -EPROTO;
  rep.old_val=key;
  if(!status){rep.mlen=sizeof(entry);memcpy(rep.data,&entry,sizeof(entry));}
  break;
 }
	case CPROTO_OP_REPAIR_INLINE: {
		const uint8_t *data = NULL;
		uint32_t dlen = 0;

		if (cproto_repair_inline_resp_decode(payload, plen, &status,
						     &dlen, &data))
			return -EPROTO;
		rep.mlen = dlen;
		if (dlen && data && dlen <= sizeof(rep.data))
			memcpy(rep.data, data, dlen);
		break;
	}
	case CPROTO_OP_REPAIR_REVERSE:
		if (cproto_repair_resp_decode(payload, plen, &status,
					      &rep.mlen))
			return -EPROTO;
		break;
	case CPROTO_OP_REPAIR_BATCH: {
		uint32_t st[CONTROL_REPAIR_BATCH_MAX];
		uint32_t nspan = 0, k;

		if (cproto_repair_batch_resp_decode(payload, plen, &status, st,
						    CONTROL_REPAIR_BATCH_MAX,
						    &nspan))
			return -EPROTO;
		rep.mlen = nspan;
		rep.nspan_status = nspan;
		for (k = 0; k < nspan && k < sizeof(rep.data); k++)
			rep.data[k] = (uint8_t)(st[k] & 0xffu);
		break;
	}
	case CPROTO_OP_ATOMIC:
		if (cproto_atomic_resp_decode(payload, plen, &status,
					      &rep.old_val))
			return -EPROTO;
		break;
	default:
		crt_log("response unknown op=%u — protocol violation", op);
		return -EPROTO;
	}
	rep.status = status;

 /* Validate lookup kind/key before mutating the requester ledger. */
 if(h->session_id==r->rreq.session_id){
  for(i=0;i<CONTROL_RPC_TABLE_CAP;i++){
   const struct crpc_req *pending=&r->rreq.req[i];
   if(!pending->taken||pending->request_id!=h->request_id)continue;
   if((op==CPROTO_OP_KEY_LOOKUP)!=(pending->desc.op==CRPC_OP_KEY_LOOKUP)||
      (op==CPROTO_OP_KEY_LOOKUP&&rep.old_val!=pending->desc.rkey))return -EPROTO;
   break;
  }
 }
	rc = crpc_response_match(&r->rreq, h->session_id, h->request_id,
				 status);
	if (rc) {
		if (rc == -EPROTO)
			return -EPROTO;
		return 0;
	}
	for (i = 0; i < CONTROL_RPC_TABLE_CAP; i++) {
		struct crpc_req *cr = &r->rreq.req[i];

		if (cr->taken && cr->request_id == h->request_id)
			break;
	}
	if (i == CONTROL_RPC_TABLE_CAP) {
		crt_log("response slot lookup failed id=%llu — violation",
			 (unsigned long long)h->request_id);
		return -EPROTO;
	}
	struct crpc_req *cr = &r->rreq.req[i];

	caller = crpc_attach_take_caller(&r->rreq, i);
	switch (cr->state) {
	case CRPC_REPLIED:
		break;
	case CRPC_LATE_REPLIED:
		ctrace_stat_inc(CTRACE_STAT_RESP_LATE, 1);
		caller = NULL;
		break;
	default:
		caller = NULL;
		break;
	}
	{
		int64_t t_sig = ctrace_sub_on() ? ctrace_ts() : 0;

		if (t_sig && t_wake)
			ctrace_at(CTRACE_PHASE_WAKE_MATCH, h->session_id,
				  h->request_id, 0, 0, t_wake,
				  (uint64_t)(t_sig - t_wake));
		caller_t_sig = t_sig;
	}
	if (caller)
		crpc_caller_complete(caller, 0, &rep);

	{

		int64_t t_now = ctrace_ts();
		uint16_t st = (uint16_t)(status ? (uint32_t)status & 0xffffu : 0);

		if (t_now && caller_t_sig && t_now > caller_t_sig)
			ctrace_at(CTRACE_PHASE_WAKE_SIGNAL, h->session_id,
				  h->request_id, 0, st, caller_t_sig,
				  (uint64_t)(t_now - caller_t_sig));
		if (t_now && t_wake && t_now > t_wake)
			ctrace_at(CTRACE_PHASE_CALLER_WAKE, h->session_id,
				  h->request_id, 0, st, t_wake,
				  (uint64_t)(t_now - t_wake));
	}
	if (crpc_caller_done(&r->rreq, i))
		return -EPROTO;
	return 0;
}

static uint64_t ctrl_req_earliest_deadline(const struct ctrl_reactor *r)
{
	uint64_t best = 0;
	uint32_t i;

	for (i = 0; i < CONTROL_RPC_TABLE_CAP; i++) {
		const struct crpc_req *cr = &r->rreq.req[i];

		if (cr->taken && cr->deadline_us &&
		    (!best || cr->deadline_us < best))
			best = cr->deadline_us;
	}
	return best;
}

static void ctrl_req_deadlines(struct ctrl_reactor *r)
{
	uint32_t idx[CONTROL_RPC_TABLE_CAP];
	uint64_t now = (uint64_t)crt_now_us();
	int n, i;

	n = crpc_deadline_scan(&r->rreq, now, idx,
			       (uint32_t)(sizeof(idx) / sizeof(idx[0])));
	for (i = 0; i < n; i++) {
		struct crpc_caller *caller;

		if (crpc_req_timeout(&r->rreq, idx[i]))
			continue;
		if (r->rreq.req[idx[i]].state == CRPC_TIMED_OUT_TOMBSTONE) {
			caller = crpc_attach_take_caller(&r->rreq, idx[i]);
			crpc_caller_complete(caller, -ETIMEDOUT, NULL);
		} else if (r->rreq.req[idx[i]].state == CRPC_CANCELLING) {
			crpc_attach_set_terminal(&r->rreq, idx[i],
						 -ETIMEDOUT);
			csess_fail(r, CSESS_FAIL_REVERSE_TIMEOUT);
			return;
		}
	}
}

static int ctrl_rev_post_span(struct ctrl_reactor *r,
			      const struct cown_rev *rv)
{
	uint64_t token = 0;
	int is_read, rc;

	struct ctrans_epoch_info epoch_info;
 rc=ctrans_epoch_snapshot(r->pv.epoch,&epoch_info);if(rc)return rc;
 rc = ctrans_rev_arm(&r->rev,epoch_info.generation,CTRANS_REV_COWN,rv->job_id,rv->dir,&token);
	if (rc == -EBUSY)
		return 1;
	if (rc)
		return rc;
	rc = cexec_job_bind_reverse(&r->exec, rv->job_id, token);
	if (rc) { (void)ctrans_rev_abort(&r->rev,token); return rc; }
	is_read = (rv->dir == CONTROL_DIR_WRITE);
	rc = ctrans_post_reverse(&r->pv,&r->rev, token, is_read, rv->raddr, rv->lkey,
				 rv->xaddr, rv->xrkey, rv->xlen);
	if (rc) {
		crt_log("reverse WR post failed rc=%d — session invalidated", rc);
		return rc;
	}
	cown_rev_posted(r, rv, token);
	return 0;
}

static int ctrl_rev_post_job(struct ctrl_reactor *r, uint64_t job_id)
{
	uint32_t rounds;

	for (rounds = 0; rounds < COWN_REQ_CAP * CONTROL_REPAIR_BATCH_MAX;
	     rounds++) {
		struct cown_rev rv;
		int rc;

		if (cown_rev_next(r, job_id, &rv))
			return 0;
		rc = ctrl_rev_post_span(r, &rv);
		if (rc)
			return rc < 0 ? rc : 0;
	}
	crt_log("reverse post loop overrun job=%llu — violation",
		 (unsigned long long)job_id);
	return -EPROTO;
}

static void ctrl_process_completions(struct ctrl_reactor *r)
{
	if (r->fatal)
		return;
	for (;;) {
		uint64_t job_id = 0;
		int rc;

		if (cexec_poll(&r->exec, &job_id))
			return;
  enum cexec_job_kind domain;
  rc=cexec_job_kind(&r->exec,job_id,&domain);
  if(rc){csess_fail(r,CSESS_FAIL_OWNER_COMPLETION);return;}
  if(domain==CEXEC_JOB_RDV_MEMORY){if(rdv_bridge_on_exec(&r->exec,job_id))csess_fail(r,CSESS_FAIL_OWNER_COMPLETION);continue;}
		rc = cown_on_exec_done(r, job_id);
		if (rc < 0) {
			csess_fail(r, CSESS_FAIL_OWNER_COMPLETION);
			return;
		}
		if (rc > 0)
			ctrace_stat_inc(CTRACE_STAT_SERVED, 1);
		if (rc == 0) {
			rc = ctrl_rev_post_job(r, job_id);
			if (rc) {
				csess_fail(r, CSESS_FAIL_REVERSE_POST);
				return;
			}
		}

		(void)cexec_schedule(&r->exec);
	}
}

static int ctrl_retry_reverse(struct ctrl_reactor *r)
{
	uint32_t rounds;

	for (rounds = 0; rounds < COWN_REQ_CAP * CONTROL_REPAIR_BATCH_MAX;
	     rounds++) {
		struct cown_rev rv;
		int rc;

		if (cown_rev_next_any(r, &rv))
			return 0;
		rc = ctrl_rev_post_span(r, &rv);
		if (rc)
			return rc < 0 ? rc : 0;
	}
	crt_log("reverse retry loop overrun — violation");
	return -EPROTO;
}

CRT_INTERNAL int ctrl_reverse_wc(struct ctrl_reactor *r,const struct ibv_wc *wc)
{
 struct ctrans_rev_ticket ticket;struct ctrans_epoch_info info;
 int rc=ctrans_rev_lookup(&r->rev,wc->wr_id,&ticket);
 if(rc==-ESTALE)return 0;
 if(rc)return rc;
 if(ctrans_epoch_snapshot(r->pv.epoch,&info)||ticket.epoch_generation!=info.generation)return 0;
 rc=ctrans_rev_release(&r->rev,wc->wr_id,&ticket);
 if(rc==-ESTALE)return 0;
 if(rc)return rc;
 if(ticket.domain==CTRANS_REV_RDV)rc=rdv_bridge_on_read_wc(&r->exec,&ticket,wc->status);
 else rc=cown_rev_wc(r,ticket.token,ticket.owner_token,wc->status==IBV_WC_SUCCESS);
 if(rc<0)return rc;
 if(rc>0)ctrace_stat_inc(CTRACE_STAT_SERVED,1);
 return wc->status==IBV_WC_SUCCESS?0:-EIO;
}
CRT_INTERNAL int ctrl_reverse_stopped(struct ctrl_reactor *r)
{
 if(!r->rev.in_flight)return 0;
 struct ctrans_rev_ticket ticket;int rc;
 while(!(rc=ctrans_epoch_reverse_stopped(r->pv.epoch,&r->rev,&ticket))){
  if(ticket.posted&&!ticket.accounted&&r->pv.sq_outstanding)r->pv.sq_outstanding--;
  if(ticket.domain==CTRANS_REV_RDV&&ticket.posted){int done=rdv_bridge_on_read_stopped(&r->exec,&ticket);if(done&&done!=-ESTALE)return done;}
  /* Legacy cown stop/abort owns its export/endpoint/PIN retirement; do not
   * manufacture a cown response on a destroyed transport. */
 }
 return rc==-ENOENT?0:rc;
}

#define CTRL_CQ_BATCH 32

static int ctrl_rx_frame(struct ctrl_reactor *r, const uint8_t *buf,
			 uint32_t len);

static int ctrl_handle_wc(struct ctrl_reactor *r, const struct ibv_wc *wc)
{
	uint32_t idx;
	uint64_t base = ctrans_wrid_kind(wc->wr_id, &idx);
	int rc;
 if(base==CTRANS_WRID_REV_BASE)return ctrl_reverse_wc(r,wc);

	if (crt_log_level() >= 2)
		crt_log("WC op=%d status=%d wrid=%llx idx=%u bytes=%u",
			 (int)wc->opcode, (int)wc->status,
			 (unsigned long long)wc->wr_id, idx, wc->byte_len);
	if (wc->status != IBV_WC_SUCCESS) {
		switch (base) {
		case CTRANS_WRID_TX_BASE:
			(void)ctrans_tx_release(&r->tx, idx);
			break;
		case CTRANS_WRID_RX_BASE: {
			uint8_t *b = ctrans_rx_take(&r->rx, idx,
						    wc->byte_len);

			if (b)
				(void)ctrans_rx_release(&r->rx, idx);
			break;
		}
		case CTRANS_WRID_REV_BASE:
			rc = ctrl_reverse_wc(r, wc);
			if (rc)
				return rc;
			break;
		default:
			break;
		}
		crt_log("WC error status=%d opcode=%d — session invalidated",
			 (int)wc->status, (int)wc->opcode);
		return -EIO;
	}
	switch (wc->opcode) {
	case IBV_WC_RECV: {
		uint8_t *b;
		int rc;

		if (base != CTRANS_WRID_RX_BASE) {
			crt_log("RECV WC token not a slot — violation");
			return -EPROTO;
		}
		b = ctrans_rx_take(&r->rx, idx, wc->byte_len);
		if (!b)
			return -EPROTO;
		rc = ctrl_rx_frame(r, b, wc->byte_len);
  if(!rc){struct cproto_header h;uint32_t op;
   if(!cproto_header_decode(b,wc->byte_len,&h)&&h.kind==CPROTO_CONTROL_EVENT&&
      !cproto_op_get(b+CONTROL_HEADER_LEN,h.payload_len,&op)&&((op>=CPROTO_OP_RDV_OFFER&&op<=CPROTO_OP_RDV_CAPS)||op==CPROTO_OP_RDV_CAPS_ACK||op==CPROTO_OP_RDV_WWI_READY||op==CPROTO_OP_RDV_WWI_RESULT||op==CPROTO_OP_RDV_DRAIN_REQUEST||op==CPROTO_OP_RDV_DRAIN_ACK)){
    if(h.session_id!=r->data_credit_sid||ctrans_data_received(&r->data_credit))rc=-EPROTO;
    else r->data_rx_sid[idx]=h.session_id;
   }
  }
		if (ctrl_rx_repost(r, idx)) {
			crt_log("RX repost failed — session invalidated");
			return -EIO;
		}
		return rc;
	}
	case IBV_WC_SEND: {
		struct ctrans_tx_tag tag;

		if (ctrace_on() && ctrans_tx_tag_get(&r->tx, idx, &tag) == 0) {
			int64_t now = crt_now_ns();

			if (tag.phase == CTRACE_PHASE_RESP_POST && tag.post_ns)
				ctrace_at(CTRACE_PHASE_RESP_WC, tag.session_id,
					  tag.request_id, tag.job_id,
					  (uint16_t)(wc->status ==
						     IBV_WC_SUCCESS ? 0 : EIO),
					  now, (uint64_t)(now - tag.post_ns));
			else if (tag.phase == CTRACE_PHASE_TX_POST)
				ctrace_at(CTRACE_PHASE_TX_WC, tag.session_id,
					  tag.request_id, tag.job_id,
					  (uint16_t)(wc->status ==
						     IBV_WC_SUCCESS ? 0 : EIO),
					  now, 0);
		}
		if (base != CTRANS_WRID_TX_BASE ||
		    ctrans_tx_release(&r->tx, idx)) {
			crt_log("SEND WC release violation — violation");
			return -EPROTO;
		}
		return 0;
	}
	case IBV_WC_RDMA_READ:
	case IBV_WC_RDMA_WRITE:
		return ctrl_reverse_wc(r, wc);
	default:

		crt_log("unknown WC opcode=%d — protocol violation", (int)wc->opcode);
		return -EPROTO;
	}
}

static int ctrl_on_cq_event(struct ctrl_reactor *r)
{
	void *cq_ctx = NULL;
	struct ibv_wc wc[CTRL_CQ_BATCH];
	int n, i;

	if (ctrans_cq_get_event(&r->pv, &cq_ctx))
		return -EIO;
	ctrans_cq_ack(&r->pv, 1);
	for (;;) {
		n = ctrans_poll(&r->pv, wc, CTRL_CQ_BATCH);
		if (n < 0)
			return -EIO;
		if (n == 0)
			break;
		for (i = 0; i < n; i++) {
			int rc = ctrl_handle_wc(r, &wc[i]);

			if (rc) {
                crt_log("CQ handler failed rc=%d wrid=%llx op=%d status=%d", rc,
                        (unsigned long long)wc[i].wr_id, wc[i].opcode, wc[i].status);
                return rc;
            }
		}
	}
	if (ctrans_cq_notify(&r->pv))
		return -EIO;
	for (;;) {
		n = ctrans_poll(&r->pv, wc, CTRL_CQ_BATCH);
		if (n <= 0)
			return n < 0 ? -EIO : 0;
		for (i = 0; i < n; i++) {
			int rc = ctrl_handle_wc(r, &wc[i]);

			if (rc) {
                crt_log("CQ handler failed rc=%d wrid=%llx op=%d status=%d", rc,
                        (unsigned long long)wc[i].wr_id, wc[i].opcode, wc[i].status);
                return rc;
            }
		}
	}
}

static int ctrl_rx_ping(struct ctrl_reactor *r, const uint8_t *payload,
			uint32_t plen)
{
	uint64_t nonce = 0;
	uint8_t pl[12];

	if (cproto_ping_decode(payload, plen, &nonce))
		return -EPROTO;
	if (cproto_ping_encode(pl, sizeof(pl), nonce))
		(void)ctrl_tx_control(r, CPROTO_CONTROL_EVENT, pl, 12, 0, 0);
	return 0;
}

static int ctrl_rx_control(struct ctrl_reactor *r,
			   const struct cproto_header *h,
			   const uint8_t *payload, uint32_t plen)
{
	uint32_t op = 0;

	if (cproto_op_get(payload, plen, &op))
		return -EPROTO;
	switch (op) {
	case CPROTO_OP_PING: {
		uint64_t nonce = 0;

		if (cproto_ping_decode(payload, plen, &nonce))
			return -EPROTO;
		if (nonce == r->ping_nonce && r->ping_caller) {

			struct crpc_caller *c = r->ping_caller;
			int64_t t_rx = ctrace_ts();

			r->ping_caller = NULL;
			if (t_rx)
				ctrace_at(CTRACE_PHASE_RX_FRAME,
					  csess_session_id(r->sess), nonce, 0,
					  0, t_rx, 0);
			crpc_caller_complete(c, 0, NULL);
			ctrace_done(CTRACE_PHASE_CALLER_WAKE,
				    csess_session_id(r->sess), nonce, 0, 0,
				    t_rx);
			return 0;
		}
		return ctrl_rx_ping(r, payload, plen);
	}
	case CPROTO_OP_QP_BIND_INIT:
	case CPROTO_OP_QP_BIND_ACK:
	case CPROTO_OP_QP_UNBIND:
		return cbind_rx(r,h,payload,plen);
	case CPROTO_OP_RDV_OFFER:
 case CPROTO_OP_RDV_WAIT:
 case CPROTO_OP_RDV_ACK:
 case CPROTO_OP_RDV_CANCEL:
 case CPROTO_OP_RDV_CANCEL_ACK:
 case CPROTO_OP_RDV_RETIRED:
 case CPROTO_OP_RDV_CAPS:
 case CPROTO_OP_RDV_WWI_READY:
 case CPROTO_OP_RDV_DRAIN_REQUEST:
 case CPROTO_OP_RDV_DRAIN_ACK:
 case CPROTO_OP_RDV_WWI_RESULT:
 case CPROTO_OP_RDV_CAPS_ACK:
  if(!r->data_credit.local_initial||r->data_credit_sid!=h->session_id||
     r->data_credit.rx_seen==UINT64_MAX||
     r->data_credit.rx_seen-r->data_credit.rx_retired>=r->data_credit.local_initial)return -EPROTO;
  if(!r->app_rdv)return -EPROTO;
  /* This payload is a slice of the original native receive slot. Preserve
   * request_id/attempt and every outer field; generation is not transportgen. */
  {enum crdv_rx_outcome outcome;
   return crdv_receive(r->app_rdv,payload-CONTROL_HEADER_LEN,
                      CONTROL_HEADER_LEN+plen,(uint64_t)crt_now_us(),&outcome);
  }
 case CPROTO_OP_RDV_CREDIT:{
  uint64_t total;
  if(h->request_id||h->session_id!=r->data_credit_sid||cproto_rdv_credit_decode(payload,plen,&total))return -EPROTO;
  return ctrans_data_credit_recv(&r->data_credit,total);
 }
 case CPROTO_OP_CREDIT:
		return 0;
	case CPROTO_OP_EXPORT_SNAPSHOT:
		return csess_rx_snapshot(r, h, payload, plen);
	default:
		crt_log("unknown CONTROL op=%u — protocol violation", op);
		return -EPROTO;
	}
}

static int ctrl_rx_frame(struct ctrl_reactor *r, const uint8_t *buf,
			 uint32_t len)
{
	struct cproto_header h;
	int64_t t_rx = ctrace_ts();

	ctrace_stat_inc(CTRACE_STAT_WIRE_RX, 1);
	if (cproto_header_decode(buf, len, &h)) {
		crt_log("frame header decode failed byte_len=%u — session invalidated", len);
		return -EPROTO;
	}
	if (h.kind == CPROTO_CONTROL_EVENT) {
		uint32_t op = 0;

        if (cproto_control_op_get(buf + CONTROL_HEADER_LEN, h.payload_len, &op))
            return -EPROTO;
        if (op == CPROTO_OP_HELLO) {

			if (csess_state(r->sess) != CSESS_HANDSHAKE &&
			    csess_rx_hello_gate(r))
				return -EPROTO;
			if (csess_state(r->sess) != CSESS_HANDSHAKE) {
				crt_log("HELLO arrived outside HANDSHAKE state "
					 "(sess=%u) — protocol violation",
					 csess_state(r->sess));
				return -EPROTO;
			}
			return csess_rx_hello(r, &h,
					     buf + CONTROL_HEADER_LEN,
					     h.payload_len);
		}
	}
	if (t_rx && (h.kind == CPROTO_RPC_REQUEST ||
		     h.kind == CPROTO_RPC_RESPONSE))
		ctrace_at(CTRACE_PHASE_RX_FRAME, h.session_id, h.request_id, 0,
			  0, t_rx, 0);

	csess_rx_gate(r);
	if (!csess_session_id(r->sess) ||
	    h.session_id != csess_session_id(r->sess)) {
		crt_log("session mismatch (%llu≠%llu) — invalidated",
			 (unsigned long long)h.session_id,
			 (unsigned long long)csess_session_id(r->sess));
		return -EPROTO;
	}
	if (csess_state(r->sess) != CSESS_READY &&
	    csess_state(r->sess) != CSESS_SNAPSHOT) {

		crt_log("non-HELLO frame in sess=%u (kind=%u) — invalidated",
			 csess_state(r->sess), h.kind);
		return -EPROTO;
	}
	if (h.kind != CPROTO_CONTROL_EVENT && !csess_ready(r->sess)) {
		crt_log("RPC frame while session not READY — protocol violation");
		return -EPROTO;
	}
	if (csess_ready(r->sess) &&
	    crpc_credit_recv(&r->rreq, h.credit_total)) {
		crt_log("credit_total=%llu violation — session invalidated",
			 (unsigned long long)h.credit_total);
		return -EPROTO;
	}
	switch (h.kind) {
	case CPROTO_RPC_REQUEST:
		return cown_rx_request(r, &h, buf + CONTROL_HEADER_LEN,
				       h.payload_len);
	case CPROTO_RPC_RESPONSE:
		return ctrl_rx_response(r, &h, buf + CONTROL_HEADER_LEN,
					h.payload_len);
	case CPROTO_CONTROL_EVENT:
		return ctrl_rx_control(r, &h, buf + CONTROL_HEADER_LEN,
				       h.payload_len);
	default:
		crt_log("unknown kind=%u — protocol violation", h.kind);
		return -EPROTO;
	}
}

static int64_t ctrl_next_deadline_us(const struct ctrl_reactor *r)
{
	int64_t best = 0;
	int64_t cand;

	cand = (int64_t)ctrl_req_earliest_deadline(r);
	if (cand && (!best || cand < best))
		best = cand;
	cand = csess_next_deadline_us(r->sess);
	if (cand && (!best || cand < best))
		best = cand;
	if (r->ping_caller && r->ping_deadline_us) {
		cand = r->ping_deadline_us;
		if (!best || cand < best)
			best = cand;
	}
	if (r->rx_hold_n && r->rx_hold_due_us) {
		cand = r->rx_hold_due_us;
		if (!best || cand < best)
			best = cand;
	}
 if(r->app_rdv){uint64_t rd=crdv_next_deadline(r->app_rdv);
  if(rd!=UINT64_MAX&&rd<=(uint64_t)INT64_MAX){cand=(int64_t)rd;
   if(cand&&(!best||cand<best))best=cand;
  }
 }
	return best;
}

static void ctrl_timer_arm(struct ctrl_reactor *r)
{
	int64_t dl = ctrl_next_deadline_us(r);
	struct itimerspec its;

	if (dl == r->timer_armed_us)
		return;
	memset(&its, 0, sizeof(its));
	if (dl) {
		int64_t rel = dl - crt_now_us();

		if (rel < 1000)
			rel = 1000;
		its.it_value.tv_sec = (time_t)(rel / 1000000);
		its.it_value.tv_nsec = (long)((rel % 1000000) * 1000);
	}
	timerfd_settime(r->timer_fd, 0, &its, NULL);
	r->timer_armed_us = dl;
}

static void ctrl_process_timer(struct ctrl_reactor *r)
{
	uint64_t now = (uint64_t)crt_now_us();

	ctrl_rx_hold_drain(r);

	ctrl_req_deadlines(r);
	if (r->ping_caller && now >= (uint64_t)r->ping_deadline_us) {
		struct crpc_caller *c = r->ping_caller;

		r->ping_caller = NULL;
		crpc_caller_complete(c, -ETIMEDOUT, NULL);
	}
	csess_on_timer(r);
}

static int ctrl_retry(struct ctrl_reactor *r)
{
	if (r->fatal || csess_teardown_active(r->sess))
		return 0;
	if (cown_retry(r)) {
		crt_log("retry: owner admission failed");
		return -1;
	}
	if (ctrl_retry_reverse(r)) {
		crt_log("retry: reverse retry failed");
		return -1;
	}

	if (cexec_schedule(&r->exec)) {
		crt_log("retry: executor schedule failed (fail_closed=%d)",
			 r->exec.fail_closed);
		return -1;
	}
	if (ctrl_retry_queued(r)) {
		crt_log("retry: requester advance failed");
		return -1;
	}
	ctrl_process_submissions(r);
	return r->fatal ? -1 : 0;
}

CRT_INTERNAL void ctrl_mark_fatal(struct ctrl_reactor *r)
{
	r->fatal = 1;
}

CRT_INTERNAL int ctrl_is_fatal(const struct ctrl_reactor *r)
{
	return r->fatal;
}

CRT_INTERNAL void ctrl_mark_qp_broken(struct ctrl_reactor *r)
{
	r->pv.broken = 1;
}

CRT_INTERNAL void ctrl_signal_session(struct ctrl_reactor *r)
{
	ctrl_wake_sig(r);
}

CRT_INTERNAL void ctrl_session_ready_hook(struct ctrl_reactor *r)
{
	ctrl_app_rdv_progress(r);
	ctrl_wake_sig(r);
	ctrl_process_submissions(r);
}

CRT_INTERNAL void ctrl_session_note_failed(struct ctrl_reactor *r)
{
	(void)r;
	ctrace_stat_inc(CTRACE_STAT_SESSIONS_FAILED, 1);
}

CRT_INTERNAL void ctrl_snapshot_note_applied(struct ctrl_reactor *r)
{
	(void)r;
	ctrace_stat_inc(CTRACE_STAT_SNAPSHOT_APPLIED, 1);
}

CRT_INTERNAL void ctrl_requester_reset(struct ctrl_reactor *r,
					uint64_t session_id, uint32_t window)
{
	crpc_requester_init(&r->rreq, session_id, window);
	ctrace_stat_set(CTRACE_STAT_PEAK_INFLIGHT, 0);
}

CRT_INTERNAL void ctrl_fail_pending_submits(struct ctrl_reactor *r)
{
	for (;;) {
		struct ctrl_submit_ent ent;

		pthread_mutex_lock(&r->sub_mu);
		if (r->sub_head == r->sub_tail) {
			pthread_mutex_unlock(&r->sub_mu);
			return;
		}
		ent = r->sub[r->sub_head];
		memset(&r->sub[r->sub_head], 0, sizeof(ent));
		__atomic_store_n(&r->sub_head,
				 (r->sub_head + 1) %
				 (uint32_t)(sizeof(r->sub) / sizeof(r->sub[0])),
				 __ATOMIC_RELEASE);
		pthread_mutex_unlock(&r->sub_mu);
		if (ent.caller)
			crpc_caller_complete(ent.caller, -ECONNRESET, NULL);
	}
}

CRT_INTERNAL void ctrl_fail_requests(struct ctrl_reactor *r)
{
	uint32_t i;
	/* Caller completion releases reverse endpoint leases. Fatal alone is
	 * not evidence that the native responder has stopped DMA. */
	if(r->pv.qp||ctrans_epoch_jobs_busy(&r->pv))return;

	(void)crpc_session_fail(&r->rreq);
	for (i = 0; i < CONTROL_RPC_TABLE_CAP; i++) {
		struct crpc_req *cr = &r->rreq.req[i];
		struct crpc_caller *c;

		if (!cr->taken)
			continue;
		c = crpc_attach_take_caller(&r->rreq, i);
		if (c) {
			struct crpc_reply rep;
			int32_t terr = crpc_attach_terminal(&r->rreq, i) ?
					crpc_attach_terminal(&r->rreq, i) :
					-ECONNRESET;

			memset(&rep, 0, sizeof(rep));
			rep.status = (uint32_t)-terr;
			crpc_caller_complete(c, terr, &rep);
		}
		(void)crpc_caller_done(&r->rreq, i);
	}
	if (r->ping_caller) {
		struct crpc_caller *pc = r->ping_caller;

		r->ping_caller = NULL;
		crpc_caller_complete(pc, -ECONNRESET, NULL);
	}
	ctrl_requester_reset(r, 0, CONTROL_WINDOW_MAX);
}

static inline int ctrl_sub_blocked(struct ctrl_reactor *r)
{
	return r->fatal || !csess_ready(r->sess);
}

CRT_INTERNAL int ctrl_reactor_has_work(struct ctrl_reactor *r)
{
	uint32_t h, t;
	int64_t hint;

	if (crpc_inflight(&r->rreq) > 0)
		return 1;
	hint = __atomic_load_n(&r->op_hot_until_ns, __ATOMIC_ACQUIRE);
	if (hint && hint > crt_now_ns())
		return 1;

	h = __atomic_load_n(&r->sub_head, __ATOMIC_ACQUIRE);
	t = __atomic_load_n(&r->sub_tail, __ATOMIC_ACQUIRE);
	if (h != t && !ctrl_sub_blocked(r))
		return 1;
	if (cexec_pending(&r->exec) > 0)
		return 1;
	return 0;
}

CRT_INTERNAL void ctrl_reactor_op_hint(struct ctrl_reactor *r, int64_t until_ns)
{
	if (!r)
		return;
	__atomic_store_n(&r->op_hot_until_ns, until_ns, __ATOMIC_RELEASE);
}

static inline void ctrl_hot_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#else
	__asm__ __volatile__("" ::: "memory");
#endif
}

static inline int ctrl_sub_pending(struct ctrl_reactor *r)
{
	return __atomic_load_n(&r->sub_head, __ATOMIC_ACQUIRE) !=
	       __atomic_load_n(&r->sub_tail, __ATOMIC_ACQUIRE);
}

static int ctrl_hot_update(struct ctrl_reactor *r, int *hot_l,
			   uint32_t *iters, int64_t *t0)
{
	int work = ctrl_reactor_has_work(r);

	if (!work && *hot_l) {
		__atomic_store_n(&r->hot, 0, __ATOMIC_RELEASE);
		__atomic_fetch_add(&r->hot, 0, __ATOMIC_SEQ_CST);
		work = ctrl_reactor_has_work(r);
		if (!work)
			*hot_l = 0;
	} else if (work && !*hot_l) {
		*hot_l = 1;
		*iters = 0;
		*t0 = crt_now_ns();
		__atomic_store_n(&r->hot, 1, __ATOMIC_RELEASE);
	}
	if (*hot_l && (++(*iters) > CTRL_HOT_MAX_ITERS ||
		       crt_now_ns() - *t0 > (int64_t)CTRL_HOT_MAX_US * 1000)) {
		__atomic_store_n(&r->hot, 0, __ATOMIC_RELEASE);
		__atomic_fetch_add(&r->hot, 0, __ATOMIC_SEQ_CST);
		if (ctrl_reactor_has_work(r)) {
			*iters = 0;
			*t0 = crt_now_ns();
			__atomic_store_n(&r->hot, 1, __ATOMIC_RELEASE);
		} else {
			*hot_l = 0;
		}
	}
	return *hot_l;
}

CRT_INTERNAL void *ctrl_reactor_loop(void *arg)
{
	struct ctrl_reactor *r = arg;
	struct pollfd pfd[8];
	const int NFDS = 8;

	if (r->pv.qp && ctrans_cq_notify(&r->pv))
		csess_fail(r, CSESS_FAIL_CQ_REARM);

	if (csess_kick(r))
		csess_fail(r, CSESS_FAIL_BOOTSTRAP);
	crt_log("reactor loop entered (sub=%d cpl=%d quit=%d timer=%d)",
		 r->sub_efd, cexec_event_fd(&r->exec), r->quit_efd,
		 r->timer_fd);
	{
		int hot_l = 0;
		uint32_t hot_iters = 0;
		int64_t hot_t0 = 0;

	while (1) {
		int n, i, hot;
		struct timespec zero = { 0, 0 };

		if(r->quit)r->fatal=1;
		if(r->fatal&&!r->fatal_cleanup) {
			cexec_stop(&r->exec);r->fatal_cleanup=1;
			csess_fail(r,CSESS_FAIL_SHUTDOWN);
		}
		if(!r->fatal)rdv_bridge_progress_all(&r->exec);
		ctrl_app_rdv_progress(r);
		(void)ctrans_provider_cleanup(&r->pv);
		if(r->fatal)(void)csess_teardown_step(r);
		if(r->quit&&!ctrans_provider_busy(&r->pv)&&!cown_busy(r)&&
		   !cexec_pending(&r->exec)&&!rdv_bridge_busy(&r->exec)&&!r->rreq.inflight) {
			ctrl_fail_pending_submits(r);ctrl_fail_requests(r);break;
		}
		hot = r->fatal?0:ctrl_hot_update(r, &hot_l, &hot_iters, &hot_t0);
		ctrl_timer_arm(r);
		for (i = 0; i < NFDS; i++) {
			pfd[i].fd = -1;
			pfd[i].events = 0;
			pfd[i].revents = 0;
		}
		{
			int k = 0;
			if(r->app_rdv&&r->cfg.app_rdv_wake_fd>=0){
			 pfd[k].fd=r->cfg.app_rdv_wake_fd;pfd[k].events=POLLIN;k++;
			}

			if (!r->fatal && r->pv.ch_fd >= 0) {
				pfd[k].fd = r->pv.ch_fd;
				pfd[k].events = POLLIN;
				k++;
			}
			pfd[k].fd = r->sub_efd;
			pfd[k].events = POLLIN;
			k++;
			pfd[k].fd = cexec_event_fd(&r->exec);
			pfd[k].events = POLLIN;
			k++;
			pfd[k].fd = r->quit_efd;
			pfd[k].events = POLLIN;
			k++;
			pfd[k].fd = r->timer_fd;
			pfd[k].events = POLLIN;
			k++;
			if (!r->fatal && r->rdv.listen_fd >= 0) {
				pfd[k].fd = r->rdv.listen_fd;
				pfd[k].events = POLLIN;
				k++;
			}
			if (!r->fatal && r->rdv.conn_fd >= 0) {
				pfd[k].fd = r->rdv.conn_fd;
				pfd[k].events = POLLIN;
				if (crdv_tcp_want_write(&r->rdv))
					pfd[k].events |= POLLOUT;
				k++;
			}

			int sub_done = 0;

			if (hot && ctrl_sub_pending(r)) {
				r->loop_entry_ns = ctrace_ts();
				ctrl_process_submissions(r);
				sub_done = 1;
			}
			n = hot ? ppoll(pfd, (nfds_t)k, &zero, NULL) :
				  poll(pfd, (nfds_t)k, -1);
			if (hot && n == 0)
				ctrl_hot_relax();
			if (!sub_done)
				r->loop_entry_ns = ctrace_ts();
		}
		if (n < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		for (i = 0; i < NFDS; i++) {
			if (pfd[i].fd < 0 || !pfd[i].revents)
				continue;
			if(r->app_rdv&&pfd[i].fd==r->cfg.app_rdv_wake_fd){
				crt_efd_drain(pfd[i].fd);ctrl_app_rdv_progress(r);continue;
			}
			if (pfd[i].fd == r->quit_efd) {
				crt_efd_drain(r->quit_efd);
				ctrace_stat_inc(CTRACE_STAT_WAKE_QUIT, 1);
				ctrace_stat_inc(CTRACE_STAT_EFD_WRITE, 1);
				r->quit = 1;r->fatal=1;
				continue;
			}
			if (pfd[i].fd == r->sub_efd) {
				crt_efd_drain(r->sub_efd);
				ctrace_stat_inc(CTRACE_STAT_WAKE_SUB, 1);
				if(r->fatal)ctrl_fail_pending_submits(r);else ctrl_process_submissions(r);
				continue;
			}
			if (pfd[i].fd == cexec_event_fd(&r->exec)) {
				crt_efd_drain(cexec_event_fd(&r->exec));
				ctrace_stat_inc(CTRACE_STAT_WAKE_CPL, 1);
				ctrl_process_completions(r);
				continue;
			}
			if (pfd[i].fd == r->timer_fd) {
				crt_efd_drain(r->timer_fd);

				r->timer_armed_us = 0;
				ctrace_stat_inc(CTRACE_STAT_WAKE_TIMER, 1);
				if(r->fatal)csess_on_timer(r);else ctrl_process_timer(r);
				continue;
			}
			if (r->pv.ch_fd >= 0 && pfd[i].fd == r->pv.ch_fd) {
				ctrace_stat_inc(CTRACE_STAT_WAKE_CQ, 1);
				if (csess_teardown_active(r->sess)) {
					void *ctx = NULL;

					if (ctrans_cq_get_event(&r->pv, &ctx))
						r->fatal = 1;
					else
						ctrans_cq_ack(&r->pv, 1);
				} else if (ctrl_on_cq_event(r)) {
					csess_fail(r, CSESS_FAIL_CQ_ERROR);
				}
				continue;
			}
			if (!r->fatal && !csess_teardown_active(r->sess) &&
			    r->rdv.listen_fd >= 0 &&
			    pfd[i].fd == r->rdv.listen_fd) {
				ctrace_stat_inc(CTRACE_STAT_WAKE_RDV, 1);
				if (crdv_tcp_accept(&r->rdv))
					crt_log("accept failed errno=%d",
						 errno);
				continue;
			}
			if (!r->fatal && !csess_teardown_active(r->sess) &&
			    r->rdv.conn_fd >= 0 &&
			    pfd[i].fd == r->rdv.conn_fd) {
				ctrace_stat_inc(CTRACE_STAT_WAKE_RDV, 1);
				if (crdv_tcp_progress(&r->rdv,
						      !!(pfd[i].revents &
							 POLLIN),
						      !!(pfd[i].revents &
							 POLLOUT)))
					csess_fail(r, CSESS_FAIL_TCP_EOF);
				continue;
			}
		}
		if (!hot && crt_log_level() >= 2)
			crt_log("loop wake n=%d (sess=%u armed=%lld)",
				 n, csess_state(r->sess),
				 (long long)r->timer_armed_us);

		cpeer_reclaim(r->peer);
		if (csess_teardown_step(r))
			break;
		if (r->fatal || csess_teardown_active(r->sess))
			continue;
		if (csess_kick(r))
			csess_fail(r, CSESS_FAIL_BOOTSTRAP);
		if (ctrl_retry(r))
			csess_fail(r, CSESS_FAIL_ADMISSION);
		if(cbind_progress(r))csess_fail(r,CSESS_FAIL_ADMISSION);
		ctrl_app_rdv_progress(r);
	}
	}
	__atomic_store_n(&r->hot, 0, __ATOMIC_RELAXED);

	cexec_stop(&r->exec);
	csess_shutdown(r);

	if (ctrl_is_fatal(r) && !r->pv.qp &&
	    !ctrans_epoch_jobs_busy(&r->pv)) {
		ctrl_fail_pending_submits(r);
		ctrl_fail_requests(r);
	}
	return NULL;
}

int ctrl_submit(struct ctrl_reactor *r, const struct crpc_desc *desc,
		struct crpc_caller *caller)
{
	struct ctrl_submit_ent *ent;
	uint32_t tail_next;
	int rc = 0;

	if (!r || !desc || desc->op == 0 ||
	    desc->op > CRPC_OP_KEY_LOOKUP)
		return -EINVAL;
	if (r->fatal)
		return -ENOTCONN;

	if (caller) {
		int64_t t0 = ctrace_ts();

		if (t0)
			caller->trace_submit_ns = t0;
	}
	pthread_mutex_lock(&r->sub_mu);
	if(r->fatal||r->quit){pthread_mutex_unlock(&r->sub_mu);return -ENOTCONN;}
	tail_next = (r->sub_tail + 1) %
		    (uint32_t)(sizeof(r->sub) / sizeof(r->sub[0]));
	if (tail_next == r->sub_head) {
		rc = -EBUSY;
	} else {
		ent = &r->sub[r->sub_tail];
		memset(ent, 0, sizeof(*ent));
		ent->used = 1;
		ent->d = *desc;
		ent->caller = caller;
		ent->t_push_ns = ctrace_ts();
		__atomic_store_n(&r->sub_tail, tail_next, __ATOMIC_RELEASE);
	}
	pthread_mutex_unlock(&r->sub_mu);

	if (!rc && ent) {
		int64_t t_efd;

		__atomic_fetch_add(&r->hot, 0, __ATOMIC_SEQ_CST);
		if (!__atomic_load_n(&r->hot, __ATOMIC_ACQUIRE)) {
			crt_efd_write(r->sub_efd, 1);
			ctrace_stat_inc(CTRACE_STAT_EFD_WRITE, 1);
		} else {
			ctrace_stat_inc(CTRACE_STAT_EFD_HOT_SKIP, 1);
		}
		t_efd = ctrace_ts();
		ent->t_efd_ns = t_efd;
	}
	return rc;
}

CRT_INTERNAL struct cpeer *ctrl_peer_registry(struct ctrl_reactor *r)
{
	return r ? r->peer : NULL;
}

int ctrl_session_ready(const struct ctrl_reactor *r)
{
	return r && !r->fatal && csess_ready(r->sess);
}

int ctrl_session_wait(struct ctrl_reactor *r, uint32_t timeout_ms)
{
	struct timespec ts;
	int64_t dl;
	int rc = 0;

	if (!r)
		return -EINVAL;
	dl = crt_now_us() + (int64_t)timeout_ms * 1000;
	pthread_mutex_lock(&r->sig_mu);
	while (!r->quit && !r->fatal && !csess_ready(r->sess)) {
		ts.tv_sec = (time_t)(dl / 1000000);
		ts.tv_nsec = (long)((dl % 1000000) * 1000);
		if (pthread_cond_timedwait(&r->sig_cv, &r->sig_mu, &ts) ==
		    ETIMEDOUT) {
			rc = -ETIMEDOUT;
			goto out;
		}
	}
	rc = (r->quit || r->fatal) ? -ECONNRESET : 0;
out:
	pthread_mutex_unlock(&r->sig_mu);
	return rc;
}

void ctrl_session_retry(struct ctrl_reactor *r)
{
	if (!r)
		return;
	csess_retry(r);
}
