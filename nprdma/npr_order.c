/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include "nprdma_internal.h"
#include "npr_progress.h"
#include "npr_sendrecv.h"
#include "npr_identity.h"
#include "npr_rendezvous.h"
#include <limits.h>
#include <stdlib.h>
#include <assert.h>

/* The list is logical post order. Completed entries leave the dependency list;
 * their reserved CQ cells remain until the application consumes them. */
struct npr_order_entry {
	struct npr_order_entry *next;
	struct npr_ctx_entry *ce;
	struct ibv_qp *qp;
	uint32_t qp_num;
 uint64_t generation;
	struct npr_op op;
	struct sir_export export;
	unsigned has_export : 1;
	struct npr_gate_item *item;
	struct npr_cq_entry *cqe;
	void *payload;
	void *lease;
	unsigned engine_refs;
 unsigned deferred, batch_open, background_deferred;
 uint64_t blocked_revision;
 enum ibv_wc_status transport_error;
	unsigned before : 1, after : 1, emitted : 1, done : 1, visible : 1, busy : 1;
};
static struct npr_order_entry *entries, **tail = &entries;
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_mutex_t mu;
static unsigned count, pumping;
static uint64_t ordering_revision=1,work_revision=1,last_progress_revision;
static unsigned progress_external_blocked;
static void work_changed(void) {if(!++work_revision){work_revision=1;last_progress_revision=0;}}
static unsigned reap_needed;
/* Fast certificate for a contiguous, sole open-batch prefix of the ledger.
 * Batch borrows keep these entries alive until membership is cleared. */
static struct npr_order_entry *batch_prefix_first,*batch_prefix_last;
static unsigned batch_prefix_members,batch_prefix_compatible;
static void ordering_changed(void) { work_changed();if(!++ordering_revision){ordering_revision=1;for(struct npr_order_entry *e=entries;e;e=e->next)e->blocked_revision=0;} }
static unsigned batch_active;
static pthread_t batch_owner;
static struct npr_order_entry **batch_link;
static unsigned dispatch_failure_logs;
static void init(void)
{
	pthread_mutexattr_t a;
	pthread_mutexattr_init(&a);
	pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&mu, &a);
	pthread_mutexattr_destroy(&a);
}
static int overlap(uint64_t a, uint64_t n, uint64_t b, uint64_t m)
{
	return n && m && a < b + m && b < a + n;
}
static int conflict(const struct npr_op *a, const struct npr_op *b)
{
	unsigned i, j;
	/* Keys name directional views, not different address spaces. A QP fixes
	 * its remote peer; local and remote VAs occupy separate namespaces. */
	if (npr_op_has_remote(a) && npr_op_has_remote(b) &&
     !(npr_op_is_read(a)&&npr_op_is_read(b)) &&
     overlap(a->remote_addr, a->len, b->remote_addr, b->len))
		return 1;
	for (i = 0; i < a->num_sge; i++)
		for (j = 0; j < b->num_sge; j++)
			if ((npr_op_local_sink(a) || npr_op_local_sink(b)) && !a->inline_ &&
			    !b->inline_ &&
			    overlap(a->sge[i].addr, a->sge[i].length, b->sge[j].addr,
				    b->sge[j].length))
				return 1;
	return 0;
}
struct npr_gate_item *npr_order_item(struct npr_order_entry *e) { return e ? e->item : NULL; }
/* A provider/engine owner keeps both the descriptor and its exact MR leases
 * alive across cancellation and across terminal completion publication. */
static void deferred_end(struct npr_order_entry *e)
{
 if(e->deferred){assert(e->cqe&&e->cqe->order_deferred);e->cqe->order_deferred--;if(e->background_deferred){assert(e->cqe->order_background_deferred);e->cqe->order_background_deferred--;e->background_deferred=0;}e->deferred=0;}
}
void npr_order_get(struct npr_order_entry *e)
{
 if(!e) return;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 e->engine_refs++;
 pthread_mutex_unlock(&mu);
}
void npr_order_put(struct npr_order_entry *e)
{
 if(!e) return;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 if(e->engine_refs) {e->engine_refs--;if(!e->engine_refs&&e->done)reap_needed=1;}
 else npr_log_emit("[nprdma] ordering engine borrow underflow\n");
 pthread_mutex_unlock(&mu);
}
void npr_order_note_transport_error(struct npr_order_entry *e,enum ibv_wc_status status)
{
 if(!e || status==IBV_WC_SUCCESS) return;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 if(!e->done && !e->transport_error) e->transport_error=status;
 pthread_mutex_unlock(&mu);
}
static unsigned npr_order_complete_result(struct npr_order_entry *e, const struct ibv_wc *wc,int verification,int inline_clean)
{
 int completed=0,needs_dispatch=0,failed=0;
 struct ibv_cq *completed_cq=NULL;
 struct ibv_wc terminal;
	if (!e)
		return 0;
	pthread_once(&once, init);
	pthread_mutex_lock(&mu);
	if (!e->done) {
  terminal=*wc;
  if((verification||terminal.status==IBV_WC_SUCCESS) && e->transport_error) terminal.status=e->transport_error;
  wc=&terminal;
		e->item->wc = *wc;
		e->item->wc.wr_id = e->op.wr_id;
		e->item->wc.qp_num = e->qp_num;
		/* Error completions are observable even for an unsignaled request. */
		e->item->visible = e->visible || wc->status != IBV_WC_SUCCESS;
		e->item->ready = 1;
		e->done=1;ordering_changed();reap_needed=1;completed=1;completed_cq=e->cqe->cq;needs_dispatch=e->cqe->order_background_deferred!=0;failed=wc->status!=IBV_WC_SUCCESS;
		if (wc->status != IBV_WC_SUCCESS) {
			struct npr_order_entry *p;
			for (p = e->next; p; p = p->next)
				if (p->qp == e->qp && p->generation == e->generation && !p->emitted && !p->done) {
     if(p->op.rdv_owner){
      npr_order_note_transport_error(p,IBV_WC_WR_FLUSH_ERR);
      npr_rdv_source_cancel(p->op.rdv_owner,IBV_WC_WR_FLUSH_ERR,0);
      continue;
     }
					p->item->wc =
					    (struct ibv_wc){.wr_id = p->op.wr_id,
							    .qp_num = p->qp_num,
							    .status = IBV_WC_WR_FLUSH_ERR};
					p->item->ready = p->item->visible = 1;
					p->done=1;ordering_changed();reap_needed=1;
					if (p->cqe->order_wait)
						p->cqe->order_wait--;
				}
		}
		if (e->cqe->order_wait)
			e->cqe->order_wait--;
	}
	pthread_mutex_unlock(&mu);
 if(completed&&inline_clean!=2) {
  /* PIN/carrier completion may produce no provider CQ event. Publish while
   * the producing caller still runs; an event waiter cannot drive an fd
   * which has never become ready. */
  npr_progress_ready(completed_cq);
  if(!inline_clean||needs_dispatch||failed)npr_progress_wake();
 }
 return completed?(1u|((failed||needs_dispatch)?2u:0u)):0;
}
void npr_order_complete(struct npr_order_entry *e,const struct ibv_wc *wc)
{npr_order_complete_result(e,wc,0,0);}
void npr_order_complete_inline_clean(struct npr_order_entry *e,const struct ibv_wc *wc)
{npr_order_complete_result(e,wc,0,1);}
/* A verifier's synthesized result cannot replace the original member's
 * provider error. Native completion callers keep their original precedence. */
void npr_order_complete_verification(struct npr_order_entry *e,const struct ibv_wc *wc)
{npr_order_complete_result(e,wc,1,0);}
void npr_order_complete_batch_clean(struct npr_order_entry **members,unsigned n,const struct ibv_wc *wc)
{
 struct ibv_cq *cq=NULL;unsigned flags=0;
 for(unsigned i=0;i<n;i++){
  if(members[i]->cqe){struct ibv_cq *next=members[i]->cqe->cq;assert(!cq||cq==next);cq=next;}
  flags|=npr_order_complete_result(members[i],wc,1,2);
 }
 if((flags&1)&&cq)npr_progress_ready(cq);
 if(flags&2)npr_progress_wake();
}
static int dispatch(struct npr_order_entry *e)
{
 deferred_end(e);
	int rc;
	struct sir_export now;
	int found;
 if(e->op.rdv_owner)return -npr_rdv_source_dispatch(e->op.rdv_owner);
 if(npr_op_is_send(&e->op)) return -npr_sr_send_submit(e->ce,e->qp,&e->op);
 found = !sir_remote_lookup_cached(e->op.rkey, &now);
	/* A queued request cannot silently switch export identity or permissions. */
	if (found && !e->has_export)
		return -ESTALE;
	if (found &&
	    (now.app_rkey != e->export.app_rkey || now.app_access != e->export.app_access ||
	     now.addr != e->export.addr || now.len != e->export.len ||
	     now.data_rkey != e->export.data_rkey || now.write_rkey != e->export.write_rkey ||
	     now.v_rkey != e->export.v_rkey || now.v_addr != e->export.v_addr))
		return -ESTALE;
	if (e->op.kind == NPR_OP_ATOMIC)
		rc = npr_atomic_submit(e->ce, e->qp, &e->op);
	else if (e->op.kind == NPR_OP_WRITE_IMM)
		rc = npr_wwi_submit(e->ce, e->qp, &e->op);
	else
		rc = npr_engine_submit(e->ce, e->qp, &e->op);
	if (rc)
		return rc > 0 ? 0 : -(errno ? errno : EIO);
	e->op.signaled = 1;
	e->op.flags |= IBV_SEND_SIGNALED;
	rc = npr_order_raw_submit(e->ce, e->qp, &e->op);
	return rc ? -rc : 0;
}
void npr_order_batch_member_set(struct npr_order_entry *e,int open)
{
 if(!e)return;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 if(e->batch_open!=(unsigned)open){
  if(open){
   if(!batch_prefix_members){batch_prefix_first=e;batch_prefix_compatible=!e->after;}
   else if(!batch_prefix_compatible||batch_prefix_last->next!=e||e->after||
           batch_prefix_first->qp!=e->qp||batch_prefix_first->generation!=e->generation||batch_prefix_first->op.rkey!=e->op.rkey)batch_prefix_compatible=0;
   batch_prefix_last=e;batch_prefix_members++;
  }else{
   assert(batch_prefix_members);batch_prefix_members--;batch_prefix_compatible=0;
   if(!batch_prefix_members)batch_prefix_first=batch_prefix_last=NULL;
  }
  e->batch_open=(unsigned)open;ordering_changed();
 }
 pthread_mutex_unlock(&mu);
}
static int allowed(struct npr_order_entry *e)
{
	struct npr_order_entry *p;
 if(e->blocked_revision==ordering_revision)return 0;
 int merge=e->op.kind==NPR_OP_WRITE&&!e->op.signaled&&e->op.len<4096&&e->has_export;
 if(merge&&!e->before&&batch_prefix_compatible&&batch_prefix_first==entries&&
    batch_prefix_last->next==e&&batch_prefix_first->qp==e->qp&&
    batch_prefix_first->generation==e->generation&&batch_prefix_first->op.rkey==e->op.rkey)return 1;
	for (p = entries; p && p != e; p = p->next) {
		if (p->qp != e->qp || p->generation != e->generation || p->done)
			continue;
		/* A blocked tail cannot be skipped, even by an independent request. */
		if (!p->emitted || p->after || e->before ||
      (!(merge&&p->batch_open&&p->op.rkey==e->op.rkey)&&conflict(&p->op,&e->op))){
   e->blocked_revision=ordering_revision;return 0;
  }
	}
	return 1;
}
static void reap(void)
{
 if(!reap_needed)return;
 reap_needed=0;
	struct npr_order_entry **p = &entries, *e;
	while ((e = *p)) {
		if (e->done && !e->busy && !e->engine_refs) {
   deferred_end(e);
			npr_order_lease_release(e->lease);
			e->lease = NULL;
   npr_gate_put(e->item);
			free(e->payload);
			e->payload = NULL;
		}
		if (e->done && !e->busy && !e->engine_refs) {
			*p = e->next;
			free(e);
			count--;
		} else
			p = &e->next;
	}
	tail = p;
}
void npr_order_progress(void)
{
	struct npr_order_entry *e;
 uint64_t pass_revision;
	pthread_once(&once, init);
	pthread_mutex_lock(&mu);
	if (pumping || batch_active) {
		pthread_mutex_unlock(&mu);
		return;
	}
 if(last_progress_revision==work_revision&&!reap_needed&&!progress_external_blocked){pthread_mutex_unlock(&mu);return;}
 pass_revision=work_revision;progress_external_blocked=0;
	pumping = 1;
 for(e=entries;e;e=e->next)if(!e->done&&!e->emitted&&e->ce->closing){progress_external_blocked=1;break;}
	for (e = entries; e; e = e->next)
		if (!e->done && !e->emitted && !e->ce->closing && allowed(e)) {
			int rc, dispatch_errno;
			e->emitted=1;ordering_changed();
			e->busy = 1;
			pthread_mutex_unlock(&mu);
			rc = dispatch(e);
			dispatch_errno = errno;
			pthread_mutex_lock(&mu);
			e->busy = 0;if(e->done)reap_needed=1;
			if (rc) {
				const char *debug = getenv("NPRDMA_DEBUG");
				const char *level = getenv("NPRDMA_DEBUG_LEVEL");
				if (((debug && strcmp(debug, "0")) || (level && atoi(level) > 0)) &&
				    dispatch_failure_logs++ < 32)
					npr_log_emit("[nprdma] deferred dispatch failed wr_id=%llu qp=%u kind=%u rc=%d errno=%d visible=%u (bounded 32)\n",
					             (unsigned long long)e->op.wr_id, e->qp_num,
					             e->op.kind, rc, dispatch_errno, e->visible);
				struct ibv_wc wc = {.wr_id = e->op.wr_id,
						    .qp_num = e->qp_num,
						    .status = IBV_WC_GENERAL_ERR};
				npr_order_complete(e, &wc);
			}
		}
	reap();
 last_progress_revision=pass_revision;
	pumping = 0;
	pthread_mutex_unlock(&mu);
}
int npr_order_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp, struct npr_op *op)
{
	struct npr_order_entry *e;
	const char *strict = getenv("SYMRDMA_STRICT_ORDERING");
	unsigned i;
	size_t bytes = 0;
	int rc = 0;
	if(!ce || ce->closing) return -EBUSY;
	if (strict && strcmp(strict, "0") && strcmp(strict, "1"))
		return -EINVAL;
	if (op->kind > NPR_OP_SEND_IMM || op->num_sge > NPR_OP_MAX_SGE)
		return 0;
	if (op->remote_addr > UINT64_MAX - op->len)
		return -EINVAL;
	for (i = 0; i < op->num_sge; i++) {
		if (op->sge[i].addr > UINT64_MAX - op->sge[i].length)
			return -EINVAL;
		if (SIZE_MAX - bytes < op->sge[i].length)
			return -EINVAL;
		bytes += op->sge[i].length;
	}
	pthread_once(&once, init);
	pthread_mutex_lock(&mu);
	reap();
	if (batch_active && !pthread_equal(batch_owner,pthread_self())) {rc=-EBUSY;goto out;}
 /* A posting loop may fill its window before calling poll. Progress an
  * already queued ordinary READ in this caller; do not recruit the pump. */
 struct npr_cq_entry *caller_cq=NULL;
 if(count<1024&&op->kind==NPR_OP_READ&&!op->rdv_owner&&!pumping&&!batch_active)
  for(struct npr_cq_entry *q=ce->cqs;q;q=q->next)
   if(q->cq==qp->send_cq&&q->order_deferred&&!q->order_background_deferred){caller_cq=q;break;}
 if ((count >= 1024||caller_cq) && !pumping && !batch_active) {
		struct npr_cq_entry *cq;
		pumping++;
		pthread_mutex_unlock(&mu);
  if(caller_cq)npr_order_flush_batches(ce,qp);
		for (cq = ce->cqs; cq; cq = cq->next)
   if(!caller_cq||cq==caller_cq)
			if (npr_drain_cq(ce, cq)) { rc = -EIO; break; }
		pthread_mutex_lock(&mu);
		pumping--;
		if (rc) goto out;
  /* progress may dispatch an RPC and suspend the API gate. Do not retain an
   * outer recursive ledger lock that another terminal verifier then needs. */
  pthread_mutex_unlock(&mu);
  npr_order_progress();
  pthread_mutex_lock(&mu);
	}
	if (count >= 1024) {
		rc = -ENOMEM;
		goto out;
	}
	e = calloc(1, sizeof(*e));
	if (!e) {
		rc = -ENOMEM;
		goto out;
	}
	e->op = *op;
 memset(e->op.local_mr,0,sizeof(e->op.local_mr));e->op.local_bound=0;
	/* Remote authority is resolved only after local leases are retained. */
	e->ce = ce;
	e->qp = qp;
	e->qp_num = qp->qp_num;
 e->generation=npr_identity_qp_generation(qp);
 if(!e->generation) {free(e);rc=-(errno?errno:ENOMEM);goto out;}
	e->visible = op->signaled || npr_qp_sig_all(ce, qp);
	/* sq_sig_all is application policy. Normalize before dispatch chooses
	 * a small unsignaled batch or assigns engine completion slots. */
	e->op.signaled = e->visible;
	if (e->visible)
		e->op.flags |= IBV_SEND_SIGNALED;
	e->before = !!(op->flags & (NPR_ORDER_BEFORE | IBV_SEND_FENCE)) || (strict && !strcmp(strict, "1"));
	e->after = !!(op->flags & NPR_ORDER_AFTER);
	e->op.flags &= ~NPR_ORDER_HINT_MASK;
	/* A private signaled WC retires invisible requests after verification. */
	e->op.order = e;
	if (op->kind != NPR_OP_WRITE || op->len >= SYMRDMA_PAGE_SIZE) {
		e->op.signaled = 1;
		e->op.flags |= IBV_SEND_SIGNALED;
	}
 if (op->inline_ && bytes) {
  char *dst=e->payload=malloc(bytes);
  if(!dst){free(e);rc=-ENOMEM;goto out;}
  for(i=0;i<op->num_sge;i++){
   memcpy(dst,(void*)(uintptr_t)op->sge[i].addr,op->sge[i].length);
   e->op.sge[i].addr=(uintptr_t)dst;dst+=op->sge[i].length;
  }
 }
 /* Required rendezvous captures original MR generations, including immutable
  * invalid markers. Its protection errors are accepted asynchronous WCs;
  * the native-path lease validator must not turn them into bad_wr errors. */
 rc=npr_rdv_source_prepare(ce,qp,&e->op,e,&e->op.rdv_owner);
 if(rc<0)goto prepare_failed;
 if(rc>0)e->before=e->after=1;
 if(!rc){
  rc=npr_order_lease_acquire(qp->pd,&e->op,&e->lease);
  if(rc){rc=-rc;goto prepare_failed;}
 }
 if(npr_op_has_remote(&e->op)) {
  /* The unaccepted descriptor is private but its buffers/inline bytes are
   * retained. A peer query can sleep: never keep the ledger mutex across the
   * API-gate yield, and never link or dispatch half-prepared entries. */
  pthread_mutex_unlock(&mu);
  int resolved=npr_resolve_remote(&e->op);
  pthread_mutex_lock(&mu);
  if(resolved) {rc=-resolved;goto prepare_failed;}
  if(ce->closing||!ce->ctx) {rc=-EBUSY;goto prepare_failed;}
  uint64_t current=npr_identity_qp_generation(qp);
  if(!current) {rc=-(errno?errno:ESTALE);goto prepare_failed;}
  if(current!=e->generation) {rc=-ESTALE;goto prepare_failed;}
  if(batch_active&&!pthread_equal(batch_owner,pthread_self())) {rc=-EBUSY;goto prepare_failed;}
  reap();
  if(count>=1024) {rc=-ENOMEM;goto prepare_failed;}
  e->has_export=e->op.remote_state==NPR_REMOTE_FOUND;
  e->export=e->op.exp;
 }
 if(e->op.rdv_owner){rc=npr_rdv_source_preaccept_validate(e->op.rdv_owner);if(rc){rc=-rc;goto prepare_failed;}}
	e->cqe = npr_cq_get(ce, qp->send_cq);
	/* An unaccepted request hitting CQ capacity is ordinary backpressure,
	 * not lost completion attribution. Do not put the CQ into drift. */
	e->item = e->cqe ? npr_gate_reserve(e->cqe) : NULL;
 if(!e->item){rc=-ENOMEM;goto prepare_failed;}
	npr_gate_get(e->item);
 npr_gate_set_lane(e->item,0);
 e->item->generation=e->generation;
 if(e->op.rdv_owner)e->item->connection_epoch=npr_rdv_source_epoch(e->op.rdv_owner);
 e->item->wc.qp_num = e->qp_num;
	e->cqe->order_wait++;
 e->deferred=1;e->cqe->order_deferred++;
 e->background_deferred=e->op.rdv_owner||(e->op.kind!=NPR_OP_READ&&e->op.kind!=NPR_OP_WRITE);
 if(e->background_deferred)e->cqe->order_background_deferred++;
	*tail = e;
	tail = &e->next;
	count++;work_changed();
 if(batch_active) {rc=1;goto out;}
 if(e->op.rdv_owner)npr_rdv_source_accept(e->op.rdv_owner);
	if (!allowed(e)) {
		/* Closing an old batch can drain completions recursively. Keep this
		 * accepted pending descriptor stable, and never hold the ledger lock
		 * across a provider/control-plane wait. */
		pumping++;
		e->busy = 1;
		pthread_mutex_unlock(&mu);
		npr_order_flush_batches(ce, qp);
		pthread_mutex_lock(&mu);
		e->busy = 0;if(e->done)reap_needed=1;
		pumping--;
	}
	if (!e->done && !e->emitted && allowed(e)) {
		pumping++;
		e->emitted=1;ordering_changed();
		e->busy = 1;
		pthread_mutex_unlock(&mu);
		rc = dispatch(e);
		pthread_mutex_lock(&mu);
		e->busy = 0;if(e->done)reap_needed=1;
		pumping--;
		if (rc) {
			if(e->item) {e->item->ready = 1;
			e->item->visible = 0;}
			if (!e->done && e->cqe && e->cqe->order_wait)
				e->cqe->order_wait--;
			e->done=1;ordering_changed();reap_needed=1;
			reap();
			goto out;
		}
	}
	rc = 1;
 goto out;
prepare_failed:
 if(e->op.rdv_owner){npr_rdv_source_abort(e->op.rdv_owner);e->op.rdv_owner=NULL;}
 npr_order_lease_release(e->lease);
 free(e->payload);free(e);
out:
	pthread_mutex_unlock(&mu);
	return rc;
}

/* Extended verbs expose an atomic posting session: prepare every logical
 * request first, then accept the set. Provider/runtime failures after commit
 * are asynchronous completions, never a synchronous partially posted session. */
int npr_order_batch_begin(void)
{
 int rc=0;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 if(batch_active || pumping) rc=EBUSY;
 else {batch_active=1;batch_owner=pthread_self();batch_link=tail;}
 pthread_mutex_unlock(&mu);return rc;
}
void npr_order_batch_abort(void)
{
 struct npr_order_entry *e;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 if(batch_active && pthread_equal(batch_owner,pthread_self())) {
  for(e=*batch_link;e;e=e->next) {
   if(e->op.rdv_owner){npr_rdv_source_abort(e->op.rdv_owner);e->op.rdv_owner=NULL;}
   e->item->ready=1;e->item->visible=0;e->done=1;ordering_changed();reap_needed=1;
   if(e->cqe->order_wait) e->cqe->order_wait--;
  }
  batch_active=0;batch_link=NULL;reap();
 }
 pthread_mutex_unlock(&mu);
}
int npr_order_batch_commit(void)
{
 int rc=0;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 if(!batch_active || !pthread_equal(batch_owner,pthread_self())) rc=EINVAL;
 else {
  for(struct npr_order_entry *e=*batch_link;e;e=e->next)
   if(e->op.rdv_owner&&(rc=npr_rdv_source_preaccept_validate(e->op.rdv_owner)))break;
  if(rc)npr_order_batch_abort();
  else {
   /* Validate the entire session before its allocation-free accept pass.
    * Concurrent route/RESET changes cannot admit an old connection epoch. */
   for(struct npr_order_entry *e=*batch_link;e;e=e->next)
    if(e->op.rdv_owner)npr_rdv_source_accept(e->op.rdv_owner);
   batch_active=0;batch_link=NULL;
  }
 }
 pthread_mutex_unlock(&mu);
 if(!rc) npr_order_progress();
 return rc;
}

/* Native close has already stopped DMA. Detach every software-CQ pointer
 * before provider/CQ memory disappears, while owner borrows retain MR leases
 * until any retryable cleanup actually finishes. No provider calls here. */
void npr_order_qp_stopped(struct ibv_qp *qp)
{
 struct npr_order_entry *e;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 for(e=entries;e;e=e->next) if(e->qp==qp) {
  if(!e->done) {
   if(e->op.rdv_owner)npr_rdv_source_cancel(e->op.rdv_owner,IBV_WC_WR_FLUSH_ERR,0);
   if(e->engine_refs) npr_order_note_transport_error(e,IBV_WC_WR_FLUSH_ERR);
   else {struct ibv_wc wc={.qp_num=e->qp_num,.status=IBV_WC_WR_FLUSH_ERR};npr_order_complete(e,&wc);}
  }
  e->qp=NULL;
 }
 reap();pthread_mutex_unlock(&mu);
}
void npr_order_entry_discard(struct npr_order_entry *e)
{
 if(!e)return;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 if(!e->done&&e->cqe&&e->cqe->order_wait)e->cqe->order_wait--;
 e->done=1;ordering_changed();reap_needed=1;e->qp=NULL;
 if(e->item){e->item->ready=1;e->item->visible=0;npr_gate_put(e->item);e->item=NULL;}
 deferred_end(e);e->cqe=NULL;
 /* The terminal owner still holds its order borrow. Do not reap or release
  * payload/MR leases until that owner performs its matching put. */
 pthread_mutex_unlock(&mu);
}
/* RESET/destroy native oracle discards both pending and unread completions.
 * Borrowed entries retain their leases until physical cleanup completes. */
void npr_order_qp_discard(struct ibv_qp *qp,uint64_t generation)
{
 struct npr_order_entry *e;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 for(e=entries;e;e=e->next) if(e->qp==qp&&e->generation==generation) {
  if(!e->done&&e->op.rdv_owner)npr_rdv_source_cancel(e->op.rdv_owner,IBV_WC_WR_FLUSH_ERR,1);
  if(!e->done&&e->cqe&&e->cqe->order_wait)e->cqe->order_wait--;
  e->done=1;ordering_changed();reap_needed=1;e->qp=NULL;
  if(e->item){e->item->ready=1;e->item->visible=0;npr_gate_put(e->item);e->item=NULL;}
  deferred_end(e);e->cqe=NULL;
 }
 reap();pthread_mutex_unlock(&mu);
}
void npr_order_context_stopped(struct npr_ctx_entry *ce)
{
 struct npr_order_entry *e;
 pthread_once(&once,init);pthread_mutex_lock(&mu);
 for(e=entries;e;e=e->next) if(e->ce==ce) {
  if(!e->done&&e->op.rdv_owner)npr_rdv_source_cancel(e->op.rdv_owner,IBV_WC_WR_FLUSH_ERR,1);
  if(!e->done && e->cqe && e->cqe->order_wait) e->cqe->order_wait--;
  e->done=1;ordering_changed();reap_needed=1;
  if(e->item) {
   e->item->ready=1;e->item->visible=0;
   npr_gate_put(e->item);e->item=NULL;
  }
  deferred_end(e);e->cqe=NULL;e->qp=NULL;
 }
 reap();
 pthread_mutex_unlock(&mu);
}

/* Teardown never dispatches a queued request. Active owners may be retired
 * only after their engine inflights/provider slots have been detached. */
void npr_order_cancel_qp(struct ibv_qp *qp, int only_pending)
{
	struct npr_order_entry *e;
	pthread_once(&once, init);
	pthread_mutex_lock(&mu);
	for (e = entries; e; e = e->next)
		if (e->qp == qp && !e->done && (!only_pending || !e->emitted)) {
			struct ibv_wc wc = {.qp_num = e->qp_num, .status = IBV_WC_WR_FLUSH_ERR};
   if(e->op.rdv_owner)npr_rdv_source_cancel(e->op.rdv_owner,IBV_WC_WR_FLUSH_ERR,0);
			if(e->engine_refs) npr_order_note_transport_error(e,IBV_WC_WR_FLUSH_ERR);
   else npr_order_complete(e, &wc);
			}
	reap();
	pthread_mutex_unlock(&mu);
}
void npr_order_cancel_cq(struct npr_cq_entry *cqe)
{
	struct npr_order_entry *e;
	pthread_once(&once, init);
	pthread_mutex_lock(&mu);
	for (e = entries; e; e = e->next)
		if (e->cqe == cqe && !e->done) {
			struct ibv_wc wc = {.qp_num = e->qp_num, .status = IBV_WC_WR_FLUSH_ERR};
   if(e->op.rdv_owner)npr_rdv_source_cancel(e->op.rdv_owner,IBV_WC_WR_FLUSH_ERR,0);
			if(e->engine_refs) npr_order_note_transport_error(e,IBV_WC_WR_FLUSH_ERR);
   else npr_order_complete(e, &wc);
		}
	reap();
	pthread_mutex_unlock(&mu);
}
