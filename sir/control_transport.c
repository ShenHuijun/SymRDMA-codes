/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>

#include "control_err.h"
#include "control_transport.h"
#include "control_trace.h"

struct ctrans_epoch {
	struct ctrans_epoch *next;
	struct ctrans_provider *provider;
	struct ibv_pd *pd;
	struct ibv_context *ctx;
	const struct ibv_qp *live_qp;
	const struct ibv_cq *live_cq;
	uint64_t generation, session_id;
	unsigned borrows, jobs, wake_refs;
	struct ctrans_cleanup *cleanup_head, *cleanup_tail;
	unsigned cleanup_n, cleanup_active;
	int reaping;
	int64_t cleanup_retry_us;
	void (*wake)(void *);
	void *wake_arg;
	int ready, closing, qp_stopped;
};
static pthread_mutex_t epoch_mu = PTHREAD_MUTEX_INITIALIZER;
static struct ctrans_epoch *epochs;
static uint64_t epoch_next = 1;

struct ctrans_runtime_guard {
	struct ctrans_runtime_guard *next;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
};
static struct ctrans_runtime_guard *runtime_guards;
CRT_INTERNAL int ctrans_runtime_guard_acquire(struct ibv_context *ctx,
					      struct ibv_pd *pd,
					      struct ctrans_runtime_guard **out)
{
	*out = NULL;
	if (!ctx && !pd)
		return 0;
	struct ctrans_runtime_guard *g = calloc(1, sizeof(*g));
	if (!g)
		return -ENOMEM;
	g->ctx = ctx;
	g->pd = pd;
	pthread_mutex_lock(&epoch_mu);
	g->next = runtime_guards;
	runtime_guards = g;
	pthread_mutex_unlock(&epoch_mu);
	*out = g;
	return 0;
}
CRT_INTERNAL void ctrans_runtime_guard_release(struct ctrans_runtime_guard *g)
{
	if (!g)
		return;
	pthread_mutex_lock(&epoch_mu);
	struct ctrans_runtime_guard **p = &runtime_guards;
	while (*p && *p != g)
		p = &(*p)->next;
	if (*p)
		*p = g->next;
	pthread_mutex_unlock(&epoch_mu);
	free(g);
}

CRT_INTERNAL int ctrans_is_internal_qp(const struct ibv_qp *qp)
{
	if (!qp)
		return 0;
	int found = 0;
	pthread_mutex_lock(&epoch_mu);
	for (struct ctrans_epoch *e = epochs; e; e = e->next)
		if (e->live_qp == qp) {
			found = 1;
			break;
		}
	pthread_mutex_unlock(&epoch_mu);
	return found;
}
CRT_INTERNAL int ctrans_is_internal_cq(const struct ibv_cq *cq)
{
	if (!cq)
		return 0;
	int found = 0;
	pthread_mutex_lock(&epoch_mu);
	for (struct ctrans_epoch *e = epochs; e; e = e->next)
		if (e->live_cq == cq) {
			found = 1;
			break;
		}
	pthread_mutex_unlock(&epoch_mu);
	return found;
}
/* Unpublish before provider destruction can recycle memory. No registry lock
 * spans verbs; failed destruction restores only this same retained epoch. */
static void epoch_qp_identity(struct ctrans_provider *pv,
			      const struct ibv_qp *qp)
{
	pthread_mutex_lock(&epoch_mu);
	if (pv->epoch)
		pv->epoch->live_qp = qp;
	pthread_mutex_unlock(&epoch_mu);
}
static void epoch_cq_identity(struct ctrans_provider *pv,
			      const struct ibv_cq *cq)
{
	pthread_mutex_lock(&epoch_mu);
	if (pv->epoch)
		pv->epoch->live_cq = cq;
	pthread_mutex_unlock(&epoch_mu);
}

int sir_transport_pd_busy(const struct ibv_pd *pd)
{
	int busy = 0;
	pthread_mutex_lock(&epoch_mu);
	for (struct ctrans_epoch *e = epochs; e; e = e->next)
		if (e->pd == pd) {
			busy = 1;
			break;
		}
	for (struct ctrans_runtime_guard *g = runtime_guards; g; g = g->next)
		if (g->pd == pd && pd) {
			busy = 1;
			break;
		}
	pthread_mutex_unlock(&epoch_mu);
	return busy;
}
int sir_transport_ctx_busy(const struct ibv_context *ctx)
{
	int busy = 0;
	pthread_mutex_lock(&epoch_mu);
	for (struct ctrans_epoch *e = epochs; e; e = e->next)
		if (e->ctx == ctx) {
			busy = 1;
			break;
		}
	for (struct ctrans_runtime_guard *g = runtime_guards; g; g = g->next)
		if (g->ctx == ctx && ctx) {
			busy = 1;
			break;
		}
	pthread_mutex_unlock(&epoch_mu);
	return busy;
}
static int epoch_attach(struct ctrans_provider *pv, struct ibv_context *ctx,
			struct ibv_pd *pd)
{
	struct ctrans_epoch *e = calloc(1, sizeof(*e));
	if (!e)
		return -ENOMEM;
	pthread_mutex_lock(&epoch_mu);
	/* Reject reuse by pointer via registry; do not read uninitialized
	 * caller pv. */
	for (struct ctrans_epoch *x = epochs; x; x = x->next)
		if (x->provider == pv) {
			pthread_mutex_unlock(&epoch_mu);
			free(e);
			return -EBUSY;
		}
	if (!epoch_next) {
		pthread_mutex_unlock(&epoch_mu);
		free(e);
		return -EOVERFLOW;
	}
	e->generation = epoch_next++;
	e->provider = pv;
	e->pd = pd;
	e->ctx = ctx;
	e->next = epochs;
	epochs = e;
	pthread_mutex_unlock(&epoch_mu);
	return 0;
}
static void epoch_publish(struct ctrans_provider *pv)
{
	pthread_mutex_lock(&epoch_mu);
	for (struct ctrans_epoch *e = epochs; e; e = e->next)
		if (e->provider == pv) {
			pv->epoch = e;
			e->live_qp = pv->qp;
			e->live_cq = pv->cq;
			break;
		}
	pthread_mutex_unlock(&epoch_mu);
}
static void epoch_wake_locked(struct ctrans_epoch *e, void (**wake)(void *),
			      void **arg)
{
	*wake = e->wake;
	*arg = e->wake_arg;
	if (*wake)
		e->wake_refs++;
}
static void epoch_wake_run(struct ctrans_epoch *e, void (*wake)(void *),
			   void *arg)
{
	if (!wake)
		return;
	wake(arg);
	pthread_mutex_lock(&epoch_mu);
	e->wake_refs--;
	pthread_mutex_unlock(&epoch_mu);
}

CRT_INTERNAL void ctrans_epoch_set_wake(struct ctrans_provider *pv,
					void (*wake)(void *), void *arg)
{
	pthread_mutex_lock(&epoch_mu);
	if (pv->epoch) {
		pv->epoch->wake = wake;
		pv->epoch->wake_arg = arg;
	}
	pthread_mutex_unlock(&epoch_mu);
}
static int64_t epoch_now_us(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return (int64_t)t.tv_sec * 1000000 + t.tv_nsec / 1000;
}
CRT_INTERNAL int64_t
ctrans_epoch_cleanup_deadline_us(const struct ctrans_provider *pv)
{
	pthread_mutex_lock(&epoch_mu);
	struct ctrans_epoch *e = pv->epoch;
	int64_t d = e && e->cleanup_n && !e->closing
			? (e->cleanup_retry_us ? e->cleanup_retry_us
					       : epoch_now_us() + 1)
			: 0;
	pthread_mutex_unlock(&epoch_mu);
	return d;
}
CRT_INTERNAL int ctrans_epoch_cleanup_pending(const struct ctrans_provider *pv)
{
	pthread_mutex_lock(&epoch_mu);
	int n = pv->epoch && pv->epoch->cleanup_n;
	pthread_mutex_unlock(&epoch_mu);
	return n;
}

CRT_INTERNAL int ctrans_epoch_ready(struct ctrans_provider *pv, uint64_t sid)
{
	int rc = 0;
	pthread_mutex_lock(&epoch_mu);
	struct ctrans_epoch *e = pv->epoch;
	if (!e || e->closing || !sid)
		rc = -ENOTCONN;
	else if (e->session_id && e->session_id != sid)
		rc = -ESTALE;
	else {
		e->session_id = sid;
		e->ready = 1;
	}
	pthread_mutex_unlock(&epoch_mu);
	return rc;
}
CRT_INTERNAL int ctrans_epoch_acquire(struct ctrans_provider *pv,
				      struct ctrans_epoch **out)
{
	if (!pv || !out)
		return -EINVAL;
	*out = NULL;
	int rc = 0;
	pthread_mutex_lock(&epoch_mu);
	struct ctrans_epoch *e = pv->epoch;
	if (!e || !e->ready || e->closing)
		rc = -ENOTCONN;
	else if (e->borrows == UINT_MAX)
		rc = -EOVERFLOW;
	else {
		e->borrows++;
		*out = e;
	}
	pthread_mutex_unlock(&epoch_mu);
	return rc;
}
CRT_INTERNAL void ctrans_epoch_release(struct ctrans_epoch *e)
{
	if (!e)
		return;
	pthread_mutex_lock(&epoch_mu);
	if (e->borrows > e->jobs)
		e->borrows--;
	pthread_mutex_unlock(&epoch_mu);
}
CRT_INTERNAL int ctrans_epoch_job_begin(struct ctrans_epoch *e)
{
	int rc = 0;
	pthread_mutex_lock(&epoch_mu);
	if (!e || !e->borrows || !e->ready || e->closing)
		rc = -ENOTCONN;
	else if (e->jobs >= e->borrows)
		rc = -EBUSY;
	else
		e->jobs++;
	pthread_mutex_unlock(&epoch_mu);
	return rc;
}
CRT_INTERNAL void ctrans_epoch_job_end(struct ctrans_epoch *e)
{
	if (!e)
		return;
	void (*wake)(void *) = NULL;
	void *arg = NULL;
	pthread_mutex_lock(&epoch_mu);
	if (e->jobs)
		e->jobs--;
	if (e->closing || e->cleanup_n)
		epoch_wake_locked(e, &wake, &arg);
	pthread_mutex_unlock(&epoch_mu);
	epoch_wake_run(e, wake, arg);
}
CRT_INTERNAL int ctrans_epoch_cleanup_begin(struct ctrans_epoch *e)
{
	int rc = 0;
	pthread_mutex_lock(&epoch_mu);
	if (!e || !e->borrows)
		rc = -EINVAL;
	else if (e->jobs >= e->borrows)
		rc = -EBUSY;
	else
		e->jobs++;
	pthread_mutex_unlock(&epoch_mu);
	return rc;
}
CRT_INTERNAL int ctrans_epoch_defer_cleanup(struct ctrans_epoch *e,
					    struct ctrans_cleanup *c,
					    int (*run)(void *), void *owner)
{
	if (!e || !c || !run)
		return -EINVAL;
	int rc = 0;
	pthread_mutex_lock(&epoch_mu);
	if (!e->borrows)
		rc = -EINVAL;
	else if (c->queued || c->active)
		rc = -EALREADY;
	else if (e->cleanup_n + e->cleanup_active >= 256)
		rc = -ENOSPC;
	else {
		c->epoch = e;
		c->run = run;
		c->owner = owner;
		c->next = NULL;
		c->queued = 1;
		if (e->cleanup_tail)
			e->cleanup_tail->next = c;
		else
			e->cleanup_head = c;
		e->cleanup_tail = c;
		e->cleanup_n++;
	}
	void (*wake)(void *) = NULL;
	void *arg = NULL;
	if (!rc)
		epoch_wake_locked(e, &wake, &arg);
	pthread_mutex_unlock(&epoch_mu);
	epoch_wake_run(e, wake, arg);
	return rc;
}
/* Caller is the sole transport owner, including explicit handoff after join.
 * Detach one finite frontier: callbacks may enqueue but cannot loop this pass.
 */
static int epoch_cleanup_progress(struct ctrans_provider *pv)
{
	pthread_mutex_lock(&epoch_mu);
	struct ctrans_epoch *e = pv->epoch;
	if (!e) {
		pthread_mutex_unlock(&epoch_mu);
		return 0;
	}
	if (e->reaping || (e->closing && !e->qp_stopped)) {
		pthread_mutex_unlock(&epoch_mu);
		return -EBUSY;
	}
	e->reaping = 1;
	unsigned frontier = e->cleanup_n;
	pthread_mutex_unlock(&epoch_mu);
	while (frontier--) {
		pthread_mutex_lock(&epoch_mu);
		struct ctrans_cleanup *c = e->cleanup_head;
		if (!c) {
			pthread_mutex_unlock(&epoch_mu);
			break;
		}
		if (e->borrows == UINT_MAX) {
			e->reaping = 0;
			pthread_mutex_unlock(&epoch_mu);
			return -EOVERFLOW;
		}
		e->cleanup_head = c->next;
		if (!e->cleanup_head)
			e->cleanup_tail = NULL;
		e->cleanup_n--;
		c->next = NULL;
		c->queued = 0;
		c->active = 1;
		e->cleanup_active++;
		e->jobs++;
		e->borrows++;
		int (*run)(void *) = c->run;
		void *owner = c->owner;
		pthread_mutex_unlock(&epoch_mu);
		int rc = run(owner);
		pthread_mutex_lock(&epoch_mu);
		e->cleanup_active--;
		e->jobs--;
		e->borrows--;
		/* On success c itself may have been freed by its owner. */
		if (rc) {
			c->active = 0;
			c->queued = 1;
			if (e->cleanup_tail)
				e->cleanup_tail->next = c;
			else
				e->cleanup_head = c;
			e->cleanup_tail = c;
			e->cleanup_n++;
		}
		pthread_mutex_unlock(&epoch_mu);
	}
	pthread_mutex_lock(&epoch_mu);
	e->reaping = 0;
	int busy = e->cleanup_n != 0;
	pthread_mutex_unlock(&epoch_mu);
	return busy ? -EBUSY : 0;
}

CRT_INTERNAL int ctrans_epoch_job_valid(struct ctrans_epoch *e)
{
	int rc;
	pthread_mutex_lock(&epoch_mu);
	rc = e && e->jobs && !e->closing && e->ready ? 0 : -ENOTCONN;
	pthread_mutex_unlock(&epoch_mu);
	return rc;
}
CRT_INTERNAL struct ibv_pd *ctrans_epoch_pd(struct ctrans_epoch *e)
{
	struct ibv_pd *pd = NULL;
	pthread_mutex_lock(&epoch_mu);
	if (e && e->borrows && e->jobs)
		pd = e->pd;
	pthread_mutex_unlock(&epoch_mu);
	return pd;
}
CRT_INTERNAL int ctrans_epoch_close(struct ctrans_provider *pv)
{
	pthread_mutex_lock(&epoch_mu);
	if (pv->epoch) {
		pv->epoch->closing = 1;
		pv->epoch->ready = 0;
	}
	pthread_mutex_unlock(&epoch_mu);
	return 0;
}
CRT_INTERNAL int ctrans_epoch_jobs_busy(const struct ctrans_provider *pv)
{
	int busy;
	pthread_mutex_lock(&epoch_mu);
	busy = pv->epoch && pv->epoch->jobs;
	pthread_mutex_unlock(&epoch_mu);
	return busy;
}
CRT_INTERNAL int ctrans_epoch_snapshot(struct ctrans_epoch *e,
				       struct ctrans_epoch_info *out)
{
	if (!e || !out)
		return -EINVAL;
	pthread_mutex_lock(&epoch_mu);
	*out = (struct ctrans_epoch_info){
	    e->generation, e->session_id, e->borrows,	e->jobs,
	    e->ready,	   e->closing,	  e->qp_stopped};
	pthread_mutex_unlock(&epoch_mu);
	return 0;
}
static void epoch_stopped(struct ctrans_provider *pv)
{
	pthread_mutex_lock(&epoch_mu);
	if (pv->epoch)
		pv->epoch->qp_stopped = 1;
	pthread_mutex_unlock(&epoch_mu);
}
static int epoch_reap(struct ctrans_provider *pv)
{
	struct ctrans_epoch *e;
	pthread_mutex_lock(&epoch_mu);
	e = pv->epoch;
	if (e && (e->borrows || e->jobs || e->wake_refs || e->cleanup_n ||
		  e->reaping)) {
		pthread_mutex_unlock(&epoch_mu);
		return -EBUSY;
	}
	if (e) {
		struct ctrans_epoch **p = &epochs;
		while (*p && *p != e)
			p = &(*p)->next;
		if (*p)
			*p = e->next;
		pv->epoch = NULL;
	}
	pthread_mutex_unlock(&epoch_mu);
	free(e);
	return 0;
}
CRT_INTERNAL int ctrans_provider_busy(const struct ctrans_provider *pv)
{
	return pv && (pv->epoch || pv->qp || pv->cq || pv->ch || pv->tx_mr ||
		      pv->rx_mr);
}
static uint32_t tmin(uint32_t a, uint32_t b)
{
	return a < b ? a : b;
}

CRT_INTERNAL uint32_t ctrans_window_reverse(uint32_t rmax,
					     uint32_t init_rd_atom,
					     uint32_t dest_rd_atom,
					     uint32_t prov_init_rd_atom,
					     uint32_t prov_resp_rd_atom,
					     uint32_t rev_slots)
{
	uint32_t w = rmax;

	w = tmin(w, init_rd_atom);
	w = tmin(w, dest_rd_atom);
	w = tmin(w, prov_init_rd_atom);
	w = tmin(w, prov_resp_rd_atom);
	w = tmin(w, rev_slots);
	return w;
}

CRT_INTERNAL uint32_t ctrans_cq_depth_min(uint32_t rx_slots, uint32_t tx_slots,
					   uint32_t reverse_slots)
{
	return rx_slots + tx_slots + 2u * reverse_slots + CONTROL_CQ_MARGIN;
}

CRT_INTERNAL void ctrans_tx_init(struct ctrans_tx_pool *p, uint32_t request_cap,
				  uint32_t response_cap)
{
	memset(p, 0, sizeof(*p));
	p->caps[CTRANS_TX_REQUEST] = request_cap;
	p->caps[CTRANS_TX_RESPONSE] = response_cap;
	p->caps[CTRANS_TX_CONTROL] = CTRANS_TX_CTRL_SLOTS;
	p->caps[CTRANS_TX_DATA] = CTRANS_DATA_SLOTS;
}

static int ctrans_tx_class_full(const struct ctrans_tx_pool *p,
				enum ctrans_tx_class cls)
{
	return p->in_flight[cls] >= p->caps[cls];
}

CRT_INTERNAL int ctrans_tx_reserve(struct ctrans_tx_pool *p,
				    enum ctrans_tx_class cls, uint32_t *idx)
{
	uint32_t i;

	if (!p || !idx || cls >= CTRANS_TX_CLASS_N)
		return -EINVAL;
	if (p->fail_closed)
		return -EPROTO;
	if (ctrans_tx_class_full(p, cls))
		return -EBUSY;
	for (i = 0; i < CTRANS_TX_SLOTS; i++) {
		if (p->state[i] != CTRANS_TX_FREE)
			continue;
		p->state[i] = CTRANS_TX_RESERVED;
		p->slot_class[i] = (uint8_t)cls;
		p->in_flight[cls]++;
		p->post_gen[i]++;
		p->used++;
		memset(&p->tag[i], 0, sizeof(p->tag[i]));
		*idx = i;
		return 0;
	}
	return crt_violation(&p->fail_closed, &p->violations);
}

CRT_INTERNAL uint8_t *ctrans_tx_payload(struct ctrans_tx_pool *p, uint32_t idx)
{
	if (!p || idx >= CTRANS_TX_SLOTS)
		return NULL;
	if (p->state[idx] != CTRANS_TX_RESERVED) {
		(void)crt_violation(&p->fail_closed, &p->violations);
		return NULL;
	}
	return p->buf[idx];
}

CRT_INTERNAL int ctrans_tx_abort(struct ctrans_tx_pool *p,uint32_t idx)
{
 if(!p||idx>=CTRANS_TX_SLOTS)return -EINVAL;
 if(p->state[idx]!=CTRANS_TX_RESERVED)return -EBUSY;
 unsigned cls=p->slot_class[idx];p->state[idx]=CTRANS_TX_FREE;p->slot_class[idx]=0;
 p->in_flight[cls]--;p->used--;memset(&p->tag[idx],0,sizeof(p->tag[idx]));return 0;
}
CRT_INTERNAL int ctrans_tx_post(struct ctrans_tx_pool *p, uint32_t idx)
{
	if (!p || idx >= CTRANS_TX_SLOTS)
		return -EINVAL;
	if (p->fail_closed)
		return -EPROTO;
	if (p->state[idx] != CTRANS_TX_RESERVED)
		return crt_violation(&p->fail_closed, &p->violations);
	p->state[idx] = CTRANS_TX_POSTED;
	return 0;
}

CRT_INTERNAL int ctrans_tx_release(struct ctrans_tx_pool *p, uint32_t idx)
{
	uint32_t cls;

	if (!p || idx >= CTRANS_TX_SLOTS)
		return -EINVAL;
	if (p->state[idx] != CTRANS_TX_POSTED)
		return crt_violation(&p->fail_closed, &p->violations);
	cls = p->slot_class[idx];
	p->state[idx] = CTRANS_TX_FREE;
	p->slot_class[idx] = 0;
	p->in_flight[cls]--;
	p->used--;
	memset(&p->tag[idx], 0, sizeof(p->tag[idx]));
	return 0;
}

CRT_INTERNAL void ctrans_tx_tag_set(struct ctrans_tx_pool *p, uint32_t idx,
				    uint16_t phase, uint64_t session_id,
				    uint64_t request_id, uint64_t job_id,
				    int64_t post_ns)
{
	if (!p || idx >= CTRANS_TX_SLOTS) {
		if (p)
			(void)crt_violation(&p->fail_closed, &p->violations);
		return;
	}
	p->tag[idx].phase = phase;
	p->tag[idx].session_id = session_id;
	p->tag[idx].request_id = request_id;
	p->tag[idx].job_id = job_id;
	p->tag[idx].post_ns = post_ns;
	p->tag[idx].status = 0;
}

CRT_INTERNAL int ctrans_tx_tag_get(const struct ctrans_tx_pool *p,
				   uint32_t idx, struct ctrans_tx_tag *out)
{
	if (!p || !out || idx >= CTRANS_TX_SLOTS)
		return -EINVAL;
	*out = p->tag[idx];
	return out->phase ? 0 : -ENOENT;
}

CRT_INTERNAL void ctrans_rx_init(struct ctrans_rx_pool *p)
{
	memset(p, 0, sizeof(*p));
}

CRT_INTERNAL int ctrans_rx_give(struct ctrans_rx_pool *p, uint32_t idx)
{
	if (!p || idx >= CTRANS_RX_SLOTS)
		return -EINVAL;
	if (p->fail_closed)
		return -EPROTO;
	if (p->state[idx] != CTRANS_RX_FREE || p->in_rq[idx])
		return crt_violation(&p->fail_closed, &p->violations);
	p->state[idx] = CTRANS_RX_POSTED;
	p->in_rq[idx] = 1;
	p->outstanding++;
	if (p->outstanding > CTRANS_RX_SLOTS)
		return crt_violation(&p->fail_closed, &p->violations);
	return 0;
}

CRT_INTERNAL uint8_t *ctrans_rx_take(struct ctrans_rx_pool *p, uint32_t idx,
				      uint32_t wc_byte_len)
{
	if (!p || idx >= CTRANS_RX_SLOTS)
		return NULL;
	if (p->state[idx] != CTRANS_RX_POSTED || !p->in_rq[idx]) {
		(void)crt_violation(&p->fail_closed, &p->violations);
		return NULL;
	}
	p->state[idx] = CTRANS_RX_RESERVED;
	p->in_rq[idx] = 0;
	p->outstanding--;
	p->byte_len[idx] = wc_byte_len;
	return p->buf[idx];
}

CRT_INTERNAL int ctrans_rx_release(struct ctrans_rx_pool *p, uint32_t idx)
{
	if (!p || idx >= CTRANS_RX_SLOTS)
		return -EINVAL;
	if (p->state[idx] != CTRANS_RX_RESERVED || p->in_rq[idx])
		return crt_violation(&p->fail_closed, &p->violations);
	p->state[idx] = CTRANS_RX_FREE;
	p->byte_len[idx] = 0;
	return 0;
}

CRT_INTERNAL int ctrans_rx_invariant_ok(const struct ctrans_rx_pool *p)
{
	uint32_t i, sum = 0, posted = 0;

	for (i = 0; i < CTRANS_RX_SLOTS; i++) {
		sum += p->in_rq[i];
		if (p->state[i] == CTRANS_RX_POSTED)
			posted++;
	}
	return sum == p->outstanding && posted == p->outstanding;
}

CRT_INTERNAL void ctrans_rev_init(struct ctrans_rev_pool *p)
{
	memset(p, 0, sizeof(*p));
	p->cap = CTRANS_REV_SLOTS;
}

CRT_INTERNAL int ctrans_rev_set_window(struct ctrans_rev_pool *p, uint32_t rw)
{
	if (!p || rw == 0)
		return -EINVAL;
	if (p->fail_closed)
		return -EPROTO;
	if (p->in_flight)
		return -EBUSY;
	p->cap = rw > CTRANS_REV_SLOTS ? CTRANS_REV_SLOTS : rw;
	return 0;
}

static pthread_mutex_t rev_token_mu=PTHREAD_MUTEX_INITIALIZER;
static uint64_t next_reverse_serial=1;
static struct ctrans_rev_slot *reverse_find(struct ctrans_rev_pool *p,uint64_t token)
{for(unsigned i=0;i<CTRANS_REV_SLOTS;i++)if(p->slot[i].state!=CTRANS_REV_FREE&&p->slot[i].ticket.token==token)return &p->slot[i];return NULL;}
CRT_INTERNAL int ctrans_rev_arm(struct ctrans_rev_pool *p,uint64_t generation,
 enum ctrans_rev_domain domain,uint64_t owner,uint32_t dir,uint64_t *token)
{
 if(!p||!token||!generation||!owner||(domain!=CTRANS_REV_COWN&&domain!=CTRANS_REV_RDV)||(dir!=CONTROL_DIR_READ&&dir!=CONTROL_DIR_WRITE))return -EINVAL;
 *token=0;if(p->fail_closed)return -EPROTO;
 if(p->in_flight>=(p->cap?p->cap:CTRANS_REV_SLOTS))return -EBUSY;
 struct ctrans_rev_slot *s=NULL;for(unsigned i=0;i<CTRANS_REV_SLOTS;i++)if(p->slot[i].state==CTRANS_REV_FREE){s=&p->slot[i];break;}
 if(!s)return crt_violation(&p->fail_closed,&p->violations);
 pthread_mutex_lock(&rev_token_mu);
 if(next_reverse_serial>0xffffffffffull){pthread_mutex_unlock(&rev_token_mu);return -EOVERFLOW;}
 uint64_t id=CTRANS_WRID_REV_BASE|next_reverse_serial++;
 pthread_mutex_unlock(&rev_token_mu);
 s->state=CTRANS_REV_ARMED;s->ticket=(struct ctrans_rev_ticket){.token=id,.epoch_generation=generation,.owner_token=owner,.domain=domain,.dir=dir};p->in_flight++;*token=id;return 0;
}
CRT_INTERNAL int ctrans_rev_lookup(const struct ctrans_rev_pool *p,uint64_t token,struct ctrans_rev_ticket *out)
{
 if(!p||!out)return -EINVAL;
 for(unsigned i=0;i<CTRANS_REV_SLOTS;i++)if(p->slot[i].state!=CTRANS_REV_FREE&&p->slot[i].ticket.token==token){*out=p->slot[i].ticket;return 0;}
 return -ESTALE;
}
CRT_INTERNAL int ctrans_rev_post(struct ctrans_rev_pool *p,uint64_t token)
{
 if(!p)return -EINVAL;
 struct ctrans_rev_slot *s=reverse_find(p,token);
 if(!s||s->state!=CTRANS_REV_ARMED)return -ESTALE;
 s->state=CTRANS_REV_POSTED;s->ticket.posted=1;return 0;
}
CRT_INTERNAL int ctrans_rev_release(struct ctrans_rev_pool *p,uint64_t token,struct ctrans_rev_ticket *out)
{
 if(!p||!out)return -EINVAL;
 struct ctrans_rev_slot *s=reverse_find(p,token);
 if(!s||s->state!=CTRANS_REV_POSTED)return -ESTALE;
 *out=s->ticket;memset(s,0,sizeof(*s));p->in_flight--;return 0;
}
CRT_INTERNAL int ctrans_rev_abort(struct ctrans_rev_pool *p,uint64_t token)
{
 if(!p)return -EINVAL;
 struct ctrans_rev_slot *s=reverse_find(p,token);if(!s)return -ESTALE;
 if(s->state!=CTRANS_REV_ARMED)return -EBUSY;
 memset(s,0,sizeof(*s));p->in_flight--;return 0;
}
CRT_INTERNAL int ctrans_epoch_reverse_stopped(struct ctrans_epoch *e,struct ctrans_rev_pool *p,struct ctrans_rev_ticket *out)
{
 if(!e||!p||!out)return -EINVAL;
 struct ctrans_epoch_info info;int rc=ctrans_epoch_snapshot(e,&info);if(rc)return rc;
 if(!info.qp_stopped)return -EBUSY;
 for(unsigned i=0;i<CTRANS_REV_SLOTS;i++)if(p->slot[i].state!=CTRANS_REV_FREE&&p->slot[i].ticket.epoch_generation==info.generation){*out=p->slot[i].ticket;memset(&p->slot[i],0,sizeof(p->slot[i]));p->in_flight--;return 0;}
 return -ENOENT;
}

#include <dlfcn.h>
#include <errno.h>
#include <infiniband/verbs.h>
#include <string.h>
#include <pthread.h>
#include <stdlib.h>
#include <limits.h>

static void *ctrans_sym(const char *name, const char *ver)
{
	void *p = ver ? dlvsym(RTLD_NEXT, name, ver) : NULL;

	if (!p)
		p = dlsym(RTLD_NEXT, name);
	return p;
}

CRT_INTERNAL void ctrans_ops_load_real(struct ctrans_ops *ops)
{
	static struct ctrans_ops real;
	static int done;

	if (done) {
		*ops = real;
		return;
	}
	memset(&real, 0, sizeof(real));
	*(void **)&real.reg_mr      = ctrans_sym("ibv_reg_mr", "IBVERBS_1.1");
	*(void **)&real.dereg_mr    = ctrans_sym("ibv_dereg_mr", "IBVERBS_1.1");
	*(void **)&real.create_qp   = ctrans_sym("ibv_create_qp", "IBVERBS_1.1");
	*(void **)&real.destroy_qp  = ctrans_sym("ibv_destroy_qp", "IBVERBS_1.1");
	*(void **)&real.create_cq   = ctrans_sym("ibv_create_cq", "IBVERBS_1.1");
	*(void **)&real.destroy_cq  = ctrans_sym("ibv_destroy_cq", "IBVERBS_1.1");
	*(void **)&real.create_comp_channel =
		ctrans_sym("ibv_create_comp_channel", "IBVERBS_1.1");
	*(void **)&real.destroy_comp_channel =
		ctrans_sym("ibv_destroy_comp_channel", "IBVERBS_1.1");
	*(void **)&real.modify_qp   = ctrans_sym("ibv_modify_qp", "IBVERBS_1.1");
	*(void **)&real.get_cq_event =
		ctrans_sym("ibv_get_cq_event", "IBVERBS_1.1");
	*(void **)&real.ack_cq_events =
		ctrans_sym("ibv_ack_cq_events", "IBVERBS_1.1");
	*(void **)&real.query_gid   = ctrans_sym("ibv_query_gid", "IBVERBS_1.1");
	*(void **)&real.query_port  = ctrans_sym("ibv_query_port", "IBVERBS_1.1");
	*(void **)&real.query_device =
		ctrans_sym("ibv_query_device", "IBVERBS_1.1");
	done = 1;
	*ops = real;
}

static int ctrans_provider_create_impl(struct ctrans_provider *pv,
					 struct ibv_context *ctx,
					 struct ibv_pd *pd,
					 void *tx_buf, size_t tx_len,
					 void *rx_buf, size_t rx_len,
					 uint32_t tx_slots, uint32_t rx_slots,
					 uint32_t reverse_slots)
{
	struct ibv_device_attr dev;
	struct ibv_qp_init_attr qa;
	uint32_t cq_depth, send_wr, recv_wr;

	memset(pv, 0, sizeof(*pv));
	ctrans_ops_load_real(&pv->ops);
	if (!ctx || !pd || !tx_buf || !rx_buf || !tx_len || !rx_len ||
	    !pv->ops.reg_mr || !pv->ops.dereg_mr || !pv->ops.create_qp ||
	    !pv->ops.destroy_qp || !pv->ops.create_cq || !pv->ops.destroy_cq ||
	    !pv->ops.create_comp_channel || !pv->ops.destroy_comp_channel ||
	    !pv->ops.modify_qp ||
	    !pv->ops.get_cq_event || !pv->ops.ack_cq_events ||
	    !pv->ops.query_gid || !pv->ops.query_port || !pv->ops.query_device)
		return -ENOSYS;
	pv->ctx = ctx;
	pv->pd = pd;

	memset(&dev, 0, sizeof(dev));
	if (pv->ops.query_device(ctx, &dev))
		return -(errno?errno:EIO);
	pv->dev_max_rd_atom = (uint32_t)dev.max_qp_rd_atom;
	pv->dev_max_init_rd_atom = (uint32_t)dev.max_qp_init_rd_atom;
	{
		struct ibv_port_attr pa;

		if (pv->ops.query_port(ctx, 1, &pa))
			return -(errno?errno:EIO);
		pv->active_mtu = (uint8_t)pa.active_mtu;
		pv->port_num = 1;
	}

	cq_depth = ctrans_cq_depth_min(rx_slots, tx_slots, reverse_slots);
	send_wr  = tx_slots + reverse_slots;
	recv_wr  = rx_slots;
	pv->cq_depth = cq_depth;
	pv->max_send_wr = send_wr;
	pv->max_recv_wr = recv_wr;

	pv->ch = pv->ops.create_comp_channel(ctx);
	if (!pv->ch)
		return -(errno?errno:EIO);
	pv->ch_fd = pv->ch->fd;
	pv->cq = pv->ops.create_cq(ctx, (int)cq_depth, NULL, pv->ch, 0);
	if (!pv->cq) return -(errno?errno:EIO);
	pv->ops.req_notify_cq = pv->cq->context->ops.req_notify_cq;
	if (!pv->ops.req_notify_cq)
		return -ENOSYS;
	memset(&qa, 0, sizeof(qa));
	qa.send_cq = pv->cq;
	qa.recv_cq = pv->cq;
	qa.qp_type = IBV_QPT_RC;
	qa.cap.max_send_wr = send_wr;
	qa.cap.max_recv_wr = recv_wr;
	qa.cap.max_send_sge = 1;
	qa.cap.max_recv_sge = 1;
	pv->qp = pv->ops.create_qp(pd, &qa);
	if (!pv->qp) return -(errno?errno:EIO);
	pv->tx_mr = pv->ops.reg_mr(pd, tx_buf, tx_len, IBV_ACCESS_LOCAL_WRITE);
	if (!pv->tx_mr) return -(errno?errno:EIO);
	pv->rx_mr = pv->ops.reg_mr(pd, rx_buf, rx_len, IBV_ACCESS_LOCAL_WRITE);
	if (!pv->rx_mr) return -(errno?errno:EIO);
	pv->tx_lkey = pv->tx_mr->lkey;
	pv->rx_lkey = pv->rx_mr->lkey;
	pv->ch_fd = pv->ch->fd;
	return 0;
}

/* Optional interposer scope: provider objects created here are control-plane
 * internals even before their identities can be published to the registry. */
extern void npr_progress_internal_begin(void) __attribute__((weak));
extern void npr_progress_internal_end(void) __attribute__((weak));
CRT_INTERNAL int ctrans_provider_create(struct ctrans_provider *pv,
                                      struct ibv_context *ctx,
                                      struct ibv_pd *pd,
                                      void *tx_buf, size_t tx_len,
                                      void *rx_buf, size_t rx_len,
                                      uint32_t tx_slots, uint32_t rx_slots,
                                      uint32_t reverse_slots)
{
 int rc,saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 if(!pv||!ctx||!pd)return -EINVAL;
 rc=epoch_attach(pv,ctx,pd);if(rc)return rc;
 if(scoped) npr_progress_internal_begin();
 rc=ctrans_provider_create_impl(pv,ctx,pd,tx_buf,tx_len,rx_buf,rx_len,
                               tx_slots,rx_slots,reverse_slots);
 saved_errno=errno;
 epoch_publish(pv);
 if(rc) (void)ctrans_provider_destroy(pv);
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
 return rc;
}

static int provider_error(int rc)
{
	return rc > 0 ? -rc : (rc < -1 ? rc : -(errno ? errno : EIO));
}
static int ctrans_provider_destroy_impl(struct ctrans_provider *pv)
{
	int rc;
	if (!pv)
		return -EINVAL;
	ctrans_epoch_close(pv);
	if (ctrans_epoch_jobs_busy(pv))
		return -EBUSY;
	if (pv->qp && (pv->rq_outstanding || pv->sq_outstanding))
		return -EBUSY;
	if (pv->qp) {
		epoch_qp_identity(pv,NULL);
		rc = pv->ops.destroy_qp(pv->qp);
		if (rc){epoch_qp_identity(pv,pv->qp);return provider_error(rc);}
		pv->qp = NULL;
	}
	epoch_stopped(pv);
	rc = epoch_cleanup_progress(pv);
	if (rc)
		return rc;
	if (pv->cq) {
		epoch_cq_identity(pv,NULL);
		rc = pv->ops.destroy_cq(pv->cq);
		if (rc){epoch_cq_identity(pv,pv->cq);return provider_error(rc);}
		pv->cq = NULL;
	}
	if (pv->ch) {
		rc = pv->ops.destroy_comp_channel(pv->ch);
		if (rc)
			return provider_error(rc);
		pv->ch = NULL;
		pv->ch_fd = -1;
	}
	if (pv->rx_mr) {
		rc = pv->ops.dereg_mr(pv->rx_mr);
		if (rc)
			return provider_error(rc);
		pv->rx_mr = NULL;
	}
	if (pv->tx_mr) {
		rc = pv->ops.dereg_mr(pv->tx_mr);
		if (rc)
			return provider_error(rc);
		pv->tx_mr = NULL;
	}
	rc = epoch_reap(pv);
	if (rc)
		return rc;
	pv->pd = NULL;
	pv->ctx = NULL;
 pv->reverse_pool=NULL;
	return 0;
}
CRT_INTERNAL int ctrans_provider_cleanup(struct ctrans_provider *pv)
{
	pthread_mutex_lock(&epoch_mu);
	struct ctrans_epoch *e = pv->epoch;
	int defer = e && (e->closing || (e->cleanup_retry_us &&
					 epoch_now_us() < e->cleanup_retry_us));
	pthread_mutex_unlock(&epoch_mu);
	if (defer)
		return -EAGAIN;
	int scoped = npr_progress_internal_begin && npr_progress_internal_end;
	if (scoped)
		npr_progress_internal_begin();
	int rc = epoch_cleanup_progress(pv), saved = errno;
	pthread_mutex_lock(&epoch_mu);
	e = pv->epoch;
	if (e)
		e->cleanup_retry_us = e->cleanup_n ? epoch_now_us() + 5000 : 0;
	pthread_mutex_unlock(&epoch_mu);
	if (scoped)
		npr_progress_internal_end();
	errno = saved;
	return rc;
}
CRT_INTERNAL int ctrans_provider_force_stop(struct ctrans_provider *pv)
{
	int rc = 0, saved;
	if (!pv)
		return -EINVAL;
	ctrans_epoch_close(pv);
	if (ctrans_epoch_jobs_busy(pv))
		return -EBUSY;
	int scoped = npr_progress_internal_begin && npr_progress_internal_end;
	if (scoped)
		npr_progress_internal_begin();
	if (pv->qp) {
		epoch_qp_identity(pv,NULL);
		rc = pv->ops.destroy_qp(pv->qp);
		if (rc){epoch_qp_identity(pv,pv->qp);rc=provider_error(rc);}
		else pv->qp=NULL;
	}
	if (!rc)
		epoch_stopped(pv);
	saved = errno;
	if (scoped)
		npr_progress_internal_end();
	errno = saved;
	return rc;
}
CRT_INTERNAL int ctrans_provider_destroy(struct ctrans_provider *pv)
{
 int saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 int rc;
 if(scoped) npr_progress_internal_begin();
 rc=ctrans_provider_destroy_impl(pv);
 saved_errno=errno;
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
 return rc;
}


static int ctrans_attr_mtu(struct ctrans_provider *pv)
{
	return pv->active_mtu < IBV_MTU_4096 ? pv->active_mtu : IBV_MTU_4096;
}

CRT_INTERNAL int ctrans_qp_init(struct ctrans_provider *pv)
{
	struct ibv_qp_attr attr;

	if (!pv->qp)
		return -EINVAL;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_INIT;
	attr.pkey_index = 0;
	attr.port_num = pv->port_num;
	attr.qp_access_flags = IBV_ACCESS_REMOTE_READ |
			       IBV_ACCESS_REMOTE_WRITE |
			       IBV_ACCESS_LOCAL_WRITE;
	if (pv->ops.modify_qp(pv->qp, &attr,
			      IBV_QP_STATE | IBV_QP_PKEY_INDEX |
			      IBV_QP_PORT | IBV_QP_ACCESS_FLAGS))
		return -(errno?errno:EIO);
	return 0;
}

CRT_INTERNAL int ctrans_qp_rtr(struct ctrans_provider *pv, uint32_t dest_qp,
				const union ibv_gid *dgid, int sgid_index,
				uint32_t rd_atom_dest)
{
	struct ibv_qp_attr attr;
	static const uint8_t mtu_ladder[] = { IBV_MTU_4096, IBV_MTU_2048,
					      IBV_MTU_1024, IBV_MTU_512,
					      IBV_MTU_256 };
	uint8_t mtu = (__u8)ctrans_attr_mtu(pv);
	unsigned li, start = 0;
	int rc = 0;

	if (!pv->qp || !dgid || !rd_atom_dest)
		return -EINVAL;
	for (li = 0; li < sizeof(mtu_ladder); li++)
		if (mtu_ladder[li] == mtu)
			start = li;
	for (li = start; li < sizeof(mtu_ladder); li++) {
		memset(&attr, 0, sizeof(attr));
		attr.qp_state = IBV_QPS_RTR;
		attr.path_mtu = mtu_ladder[li];
		attr.dest_qp_num = dest_qp;
		attr.rq_psn = 0;

		attr.max_dest_rd_atomic = rd_atom_dest;
		attr.min_rnr_timer = 12;
		attr.ah_attr.port_num = pv->port_num;
		attr.ah_attr.is_global = 1;
		attr.ah_attr.grh.sgid_index = (uint8_t)sgid_index;
		attr.ah_attr.grh.dgid = *dgid;
		attr.ah_attr.grh.hop_limit = 1;
		rc = pv->ops.modify_qp(pv->qp, &attr,
				       IBV_QP_STATE | IBV_QP_MTU |
				       IBV_QP_DEST_QPN | IBV_QP_RQ_PSN |
				       IBV_QP_MAX_DEST_RD_ATOMIC |
				       IBV_QP_MIN_RNR_TIMER | IBV_QP_AV);
		if (!rc)
			break;
		if (errno != EINVAL)
			return -EIO;
	}
	if (rc)
		crt_log("RTR downgrade all rejected dgid=%02x%02x%02x%02x%02x%02x%02x%02x"
			 "%02x%02x%02x%02x%02x%02x%02x%02x sgid=%d dest=0x%x"
			 " rd_atom=%u",
			 dgid->raw[0], dgid->raw[1], dgid->raw[2],
			 dgid->raw[3], dgid->raw[4], dgid->raw[5],
			 dgid->raw[6], dgid->raw[7], dgid->raw[8],
			 dgid->raw[9], dgid->raw[10], dgid->raw[11],
			 dgid->raw[12], dgid->raw[13], dgid->raw[14],
			 dgid->raw[15], sgid_index, dest_qp, rd_atom_dest);
	return rc ? -EIO : 0;
}

CRT_INTERNAL int ctrans_qp_rts(struct ctrans_provider *pv, uint32_t psn,
				uint32_t rd_atom_init)
{
	struct ibv_qp_attr attr;

	if (!pv->qp || !rd_atom_init)
		return -EINVAL;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_RTS;
	attr.sq_psn = psn;
	attr.timeout = 14;
	attr.retry_cnt = 7;
	attr.rnr_retry = 3;
	attr.max_rd_atomic = rd_atom_init;
	if (pv->ops.modify_qp(pv->qp, &attr,
			      IBV_QP_STATE | IBV_QP_SQ_PSN |
			      IBV_QP_TIMEOUT | IBV_QP_RETRY_CNT |
			      IBV_QP_RNR_RETRY | IBV_QP_MAX_QP_RD_ATOMIC))
		return -(errno?errno:EIO);
	return 0;
}

CRT_INTERNAL int ctrans_qp_err(struct ctrans_provider *pv)
{
	struct ibv_qp_attr attr;
	ctrans_epoch_close(pv);
	if(ctrans_epoch_jobs_busy(pv))return -EBUSY;

	if (!pv->qp)
		return -EINVAL;
	if(pv->err_done)return 0;
	memset(&attr, 0, sizeof(attr));
	attr.qp_state = IBV_QPS_ERR;
	if (pv->ops.modify_qp(pv->qp, &attr, IBV_QP_STATE))
		return -(errno?errno:EIO);
	pv->err_done=1;
	return 0;
}

static int epoch_post_allowed(struct ctrans_provider *pv)
{
 int ok;pthread_mutex_lock(&epoch_mu);ok=!pv->epoch||!pv->epoch->closing;pthread_mutex_unlock(&epoch_mu);return ok;
}

static int ctrans_post_recv_impl(struct ctrans_provider *pv, void *buf,
				   uint32_t len, uint64_t wrid)
{
	struct ibv_sge sge;
	struct ibv_recv_wr wr, *bad = NULL;

	if(!epoch_post_allowed(pv))return -ENOTCONN;
	if (!pv->qp || pv->broken)
		return pv->broken ? -EIO : -EINVAL;
	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)buf;
	sge.length = len;
	sge.lkey = pv->rx_lkey;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id = wrid;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	{
		int rc = pv->qp->context->ops.post_recv(pv->qp, &wr, &bad);

		if (rc)
			return rc > 0 ? -rc : -EIO;
	}
	pv->rq_outstanding++;
	return 0;
}

CRT_INTERNAL int ctrans_post_recv(struct ctrans_provider *pv, void *buf,
				   uint32_t len, uint64_t wrid)
{
 int saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 int rc;
 if(scoped) npr_progress_internal_begin();
 rc=ctrans_post_recv_impl(pv,buf,len,wrid);
 saved_errno=errno;
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
 return rc;
}


static int ctrans_post_send_impl(struct ctrans_provider *pv, void *buf,
				   uint32_t len, uint64_t wrid)
{
	struct ibv_sge sge;
	struct ibv_send_wr wr, *bad = NULL;

	if(!epoch_post_allowed(pv))return -ENOTCONN;
	if (!pv->qp || pv->broken)
		return pv->broken ? -EIO : -EINVAL;
	memset(&sge, 0, sizeof(sge));
	sge.addr = (uintptr_t)buf;
	sge.length = len;
	sge.lkey = pv->tx_lkey;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id = wrid;
	wr.opcode = IBV_WR_SEND;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.send_flags = IBV_SEND_SIGNALED;
	{
		int rc = pv->qp->context->ops.post_send(pv->qp, &wr, &bad);

		if (rc)
			return rc > 0 ? -rc : -EIO;
	}
	pv->sq_outstanding++;
	ctrace_stat_inc(CTRACE_STAT_WIRE_TX, 1);
	return 0;
}

CRT_INTERNAL int ctrans_post_send(struct ctrans_provider *pv, void *buf,
				   uint32_t len, uint64_t wrid)
{
 int saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 int rc;
 if(scoped) npr_progress_internal_begin();
 rc=ctrans_post_send_impl(pv,buf,len,wrid);
 saved_errno=errno;
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
 return rc;
}


static int ctrans_post_reverse_impl(struct ctrans_provider *pv,
				      uint64_t wrid, int is_read,
				      uint64_t local_addr, uint32_t lkey,
				      uint64_t remote_addr, uint32_t rkey,
				      uint32_t len)
{
	struct ibv_sge sge;
	struct ibv_send_wr wr, *bad = NULL;

	if(!epoch_post_allowed(pv))return -ENOTCONN;
	if (!pv->qp || pv->broken)
		return pv->broken ? -EIO : -EINVAL;
	if (!len || (uint64_t)len>UINT64_MAX-local_addr || (uint64_t)len>UINT64_MAX-remote_addr)
		return -EINVAL;
	memset(&sge, 0, sizeof(sge));
	sge.addr = local_addr;
	sge.length = len;
	sge.lkey = lkey;
	memset(&wr, 0, sizeof(wr));
	wr.wr_id = wrid;
	wr.opcode = is_read ? IBV_WR_RDMA_READ : IBV_WR_RDMA_WRITE;
	wr.sg_list = &sge;
	wr.num_sge = 1;
	wr.wr.rdma.remote_addr = remote_addr;
	wr.wr.rdma.rkey = rkey;
	wr.send_flags = IBV_SEND_SIGNALED;
	{
		int rc = pv->qp->context->ops.post_send(pv->qp, &wr, &bad);

		if (rc)
			return rc > 0 ? -rc : -EIO;
	}
	pv->sq_outstanding++;
	ctrace_stat_inc(CTRACE_STAT_WIRE_TX, 1);
	return 0;
}

CRT_INTERNAL int ctrans_post_reverse(struct ctrans_provider *pv,struct ctrans_rev_pool *pool,
				      uint64_t wrid, int is_read,
				      uint64_t local_addr, uint32_t lkey,
				      uint64_t remote_addr, uint32_t rkey,
				      uint32_t len)
{
 if(!pv||!epoch_post_allowed(pv))return -ENOTCONN;
 int saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 int rc;
 if(scoped) npr_progress_internal_begin();
 struct ctrans_rev_ticket ticket;struct ctrans_epoch_info info;
 rc=ctrans_rev_lookup(pool,wrid,&ticket);
 if(!rc)rc=ctrans_epoch_snapshot(pv->epoch,&info);
 if(!rc&&ticket.epoch_generation!=info.generation)rc=-ESTALE;
 if(!rc&&pv->reverse_pool&&pv->reverse_pool!=pool)rc=-EINVAL;
 if(!rc)rc=ctrans_rev_post(pool,wrid);
 if(!rc){pv->reverse_pool=pool;rc=ctrans_post_reverse_impl(pv,wrid,is_read,local_addr,lkey,remote_addr,rkey,len);if(rc){struct ctrans_rev_slot *rejected=reverse_find(pool,wrid);if(rejected){/* This exact single WR was rejected by the provider: no DMA ownership transferred. */memset(rejected,0,sizeof(*rejected));pool->in_flight--;}}}
 saved_errno=errno;
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
 return rc;
}


static int ctrans_cq_notify_impl(struct ctrans_provider *pv)
{
	int rc;

	if (!pv->cq)
		return -EINVAL;
	rc = pv->ops.req_notify_cq(pv->cq, 0);
	if (rc) {
		ctrace_stat_inc(CTRACE_STAT_REARM_FAIL, 1);
		pv->broken = 1;
		return -EIO;
	}
	pv->armed = 1;
	return 0;
}

CRT_INTERNAL int ctrans_cq_notify(struct ctrans_provider *pv)
{
 int saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 int rc;
 if(scoped) npr_progress_internal_begin();
 rc=ctrans_cq_notify_impl(pv);
 saved_errno=errno;
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
 return rc;
}


static int ctrans_cq_get_event_impl(struct ctrans_provider *pv,
				      void **cq_ctx)
{
	struct ibv_cq *event_cq = NULL;
	int rc;

	if (!pv->ch || !pv->cq)
		return -EINVAL;
	rc = pv->ops.get_cq_event(pv->ch, &event_cq, cq_ctx);
	if (rc) {
		pv->broken = 1;
		return -EIO;
	}
	if (event_cq != pv->cq) {
		if (event_cq)
			pv->ops.ack_cq_events(event_cq, 1);
		pv->broken = 1;
		return -EPROTO;
	}
	ctrace_stat_inc(CTRACE_STAT_CQ_EVENTS, 1);
	pv->armed = 0;
	return 0;
}

CRT_INTERNAL int ctrans_cq_get_event(struct ctrans_provider *pv,
				      void **cq_ctx)
{
 int saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 int rc;
 if(scoped) npr_progress_internal_begin();
 rc=ctrans_cq_get_event_impl(pv,cq_ctx);
 saved_errno=errno;
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
 return rc;
}


static void ctrans_cq_ack_impl(struct ctrans_provider *pv, unsigned int count)
{
	if (pv->cq && count)
		pv->ops.ack_cq_events(pv->cq, count);
}

CRT_INTERNAL void ctrans_cq_ack(struct ctrans_provider *pv, unsigned int count)
{
 int saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 if(scoped) npr_progress_internal_begin();
 ctrans_cq_ack_impl(pv,count);
 saved_errno=errno;
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
}


static void ctrans_wc_account(struct ctrans_provider *pv,
			      const struct ibv_wc *wc)
{
	uint32_t idx;
	uint64_t base = ctrans_wrid_kind(wc->wr_id, &idx);

	switch (base) {
	case CTRANS_WRID_RX_BASE:
		if (idx >= CTRANS_RX_SLOTS || !pv->rq_outstanding)
			pv->broken = 1;
		else
			pv->rq_outstanding--;
		break;
	case CTRANS_WRID_TX_BASE:
		if (idx >= CTRANS_TX_SLOTS || !pv->sq_outstanding)
			pv->broken = 1;
		else
			pv->sq_outstanding--;
		break;
 case CTRANS_WRID_REV_BASE: {
  struct ctrans_rev_ticket ticket;struct ctrans_epoch_info info;
  struct ctrans_rev_slot *slot=pv->reverse_pool?reverse_find(pv->reverse_pool,wc->wr_id):NULL;
  if(slot&&!slot->ticket.accounted&&!ctrans_rev_lookup(pv->reverse_pool,wc->wr_id,&ticket)&&ticket.posted&&!ctrans_epoch_snapshot(pv->epoch,&info)&&ticket.epoch_generation==info.generation&&pv->sq_outstanding){pv->sq_outstanding--;slot->ticket.accounted=1;}
  break;
 }
	default:
		pv->broken = 1;
		break;
	}
}

static int ctrans_poll_impl(struct ctrans_provider *pv, struct ibv_wc *wc,
			      int cap)
{
	int n, total = 0;

	if (!pv->cq)
		return -EINVAL;
	if (!cap)
		return 0;
	while (total < cap) {
		int i;

		n = pv->cq->context->ops.poll_cq(pv->cq, cap - total,
						 wc + total);
		if (n < 0) {
			pv->broken = 1;
			return -EIO;
		}
		if (n == 0)
			break;
		for (i = 0; i < n; i++) {
			ctrans_wc_account(pv, &wc[total + i]);
			if (wc[total + i].status != IBV_WC_SUCCESS)
				ctrace_stat_inc(CTRACE_STAT_WC_ERR, 1);
		}
		total += n;
		ctrace_stat_inc(CTRACE_STAT_WC_TOTAL, (uint64_t)n);
	}
	return pv->broken ? -EIO : total;
}

CRT_INTERNAL int ctrans_poll(struct ctrans_provider *pv, struct ibv_wc *wc,
			      int cap)
{
 int saved_errno;
 int scoped=npr_progress_internal_begin && npr_progress_internal_end;
 int rc;
 if(scoped) npr_progress_internal_begin();
 rc=ctrans_poll_impl(pv,wc,cap);
 saved_errno=errno;
 if(scoped) npr_progress_internal_end();
 errno=saved_errno;
 return rc;
}


#include <time.h>
static int64_t ctrans_mono_us(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
}

CRT_INTERNAL int ctrans_drain(struct ctrans_provider *pv, struct ibv_wc *wc,
			       int cap, uint32_t timeout_ms, long *drained)
{
	int64_t deadline = ctrans_mono_us() + (int64_t)timeout_ms * 1000;
	long got = 0;

	if (!pv->qp || !pv->cq || !wc || cap <= 0)
		return -EINVAL;
	while (pv->rq_outstanding || pv->sq_outstanding) {
		int n = pv->cq->context->ops.poll_cq(pv->cq, cap, wc);
		int i;

		if (n < 0) {
			pv->broken = 1;
			return -EIO;
		}
		for (i = 0; i < n; i++) {
			ctrans_wc_account(pv, &wc[i]);
			got++;
			ctrace_stat_inc(CTRACE_STAT_WC_TOTAL, 1);
			if (wc[i].status != IBV_WC_SUCCESS)
				ctrace_stat_inc(CTRACE_STAT_WC_ERR, 1);
		}
		if (pv->broken)
			return -EIO;
		if (n == 0 && ctrans_mono_us() >= deadline)
			break;
	}
	if (drained)
		*drained = got;
	if (pv->rq_outstanding || pv->sq_outstanding)
		return -ETIMEDOUT;
	return 0;
}

CRT_INTERNAL int ctrans_tx_set_window(struct ctrans_tx_pool *p,
				       uint32_t request_cap,
				       uint32_t response_cap)
{
	if (!p || request_cap == 0 || response_cap == 0 ||
	    request_cap + response_cap > CTRANS_TX_SLOTS - CTRANS_TX_CTRL_SLOTS - CTRANS_DATA_SLOTS)
		return -EINVAL;
	if (p->in_flight[CTRANS_TX_REQUEST] || p->in_flight[CTRANS_TX_RESPONSE])
		return -EBUSY;
	p->caps[CTRANS_TX_REQUEST] = request_cap;
	p->caps[CTRANS_TX_RESPONSE] = response_cap;
	return 0;
}

CRT_INTERNAL void ctrans_tx_reset(struct ctrans_tx_pool *p)
{
	memset(p->state, 0, sizeof(p->state));
	memset(p->slot_class, 0, sizeof(p->slot_class));
	memset(p->in_flight, 0, sizeof(p->in_flight));
	memset(p->post_gen, 0, sizeof(p->post_gen));
	memset(p->tag, 0, sizeof(p->tag));
	p->used = 0;
	p->fail_closed = 0;
}

CRT_INTERNAL void ctrans_rx_reset(struct ctrans_rx_pool *p)
{
	memset(p->state, 0, sizeof(p->state));
	memset(p->in_rq, 0, sizeof(p->in_rq));
	memset(p->byte_len, 0, sizeof(p->byte_len));
	p->outstanding = 0;
	p->fail_closed = 0;
}

CRT_INTERNAL int ctrans_rev_reset(struct ctrans_rev_pool *p)
{
 if(p->in_flight)return -EBUSY;
 memset(p->slot,0,sizeof(p->slot));p->fail_closed=0;p->cap=CTRANS_REV_SLOTS;return 0;
}

/* The epoch borrow pins provider storage; active jobs exclude native stop.
 * Never hold epoch_mu over a provider operation. */
CRT_INTERNAL int ctrans_epoch_reg_bridge(struct ctrans_epoch *e,void *cpu,size_t len,unsigned access,struct ibv_mr **out)
{
 if(!out)return -EINVAL;
 *out=NULL;
 struct ibv_pd *pd=NULL;struct ibv_mr *(*reg)(struct ibv_pd *,void *,size_t,int)=NULL;
 pthread_mutex_lock(&epoch_mu);
 if(e&&e->borrows&&e->jobs&&e->ready&&!e->closing&&e->provider){pd=e->pd;reg=e->provider->ops.reg_mr;}
 pthread_mutex_unlock(&epoch_mu);
 if(!pd||!reg)return -ENOTCONN;
 int scoped=npr_progress_internal_begin&&npr_progress_internal_end;
 if(scoped)npr_progress_internal_begin();
 errno=0;struct ibv_mr *mr=reg(pd,cpu,len,(int)access);int saved=errno;
 if(scoped)npr_progress_internal_end();
 if(!mr)return -(saved?saved:EIO);
 *out=mr;return 0;
}
CRT_INTERNAL int ctrans_epoch_dereg_bridge(struct ctrans_epoch *e,struct ibv_mr *mr)
{
 int (*dereg)(struct ibv_mr *)=NULL;
 pthread_mutex_lock(&epoch_mu);
 if(e&&e->borrows&&e->jobs&&e->provider)dereg=e->provider->ops.dereg_mr;
 pthread_mutex_unlock(&epoch_mu);
 if(!mr||!dereg)return -EINVAL;
 int scoped=npr_progress_internal_begin&&npr_progress_internal_end;
 if(scoped)npr_progress_internal_begin();
 errno=0;int rc=dereg(mr),saved=errno;
 if(scoped)npr_progress_internal_end();
 return rc?(rc>0?-rc:rc==-1?-(saved?saved:EIO):rc):0;
}

CRT_INTERNAL int ctrans_epoch_post_read(struct ctrans_epoch *e,struct ctrans_rev_pool *pool,uint64_t token,
 uint64_t local,uint32_t lkey,uint64_t remote,uint32_t rkey,uint32_t length)
{
 struct ctrans_provider *pv=NULL;
 pthread_mutex_lock(&epoch_mu);
 if(e&&e->borrows&&e->jobs&&e->ready&&!e->closing)pv=e->provider;
 pthread_mutex_unlock(&epoch_mu);
 if(!pv)return -ENOTCONN;
 return ctrans_post_reverse(pv,pool,token,1,local,lkey,remote,rkey,length);
}

CRT_INTERNAL int ctrans_data_init(struct ctrans_data_credit *c,uint32_t local,uint32_t peer)
{if(!c||local>CTRANS_DATA_SLOTS||peer>CTRANS_DATA_SLOTS)return -EINVAL;memset(c,0,sizeof(*c));c->local_initial=local;c->peer_initial=peer;return 0;}
CRT_INTERNAL int ctrans_data_can_send(const struct ctrans_data_credit *c)
{if(!c||!c->peer_initial)return 0;return c->tx_total!=UINT64_MAX&&c->tx_total-c->peer_retired<c->peer_initial;}
CRT_INTERNAL int ctrans_data_sent(struct ctrans_data_credit *c)
{if(!ctrans_data_can_send(c))return -EAGAIN;c->tx_total++;return 0;}
CRT_INTERNAL int ctrans_data_credit_recv(struct ctrans_data_credit *c,uint64_t total)
{if(!c||!c->peer_initial||total>c->tx_total)return -EPROTO;if(total>c->peer_retired)c->peer_retired=total;return 0;}
CRT_INTERNAL int ctrans_data_received(struct ctrans_data_credit *c)
{if(!c||!c->local_initial||c->rx_seen==UINT64_MAX||c->rx_seen-c->rx_retired>=c->local_initial)return -EPROTO;c->rx_seen++;return 0;}
CRT_INTERNAL int ctrans_data_reposted(struct ctrans_data_credit *c)
{if(!c||c->rx_retired>=c->rx_seen||c->rx_retired==UINT64_MAX)return -EPROTO;c->rx_retired++;return 0;}
