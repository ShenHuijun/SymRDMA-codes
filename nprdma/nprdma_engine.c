/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <endian.h>
#include <infiniband/verbs.h>
#include "nprdma_internal.h"
#include "npr_inject.h"
#include "endpoint_registry.h"

#include "npr_progress.h"
#include "npr_identity.h"
#include "npr_sendrecv.h"
#include "npr_rendezvous.h"
#include <assert.h>
/* State remains borrowed while a control RPC runs. Other independent QPs and
 * CQ consumers may progress under the API gate during this bounded wait. */
static int npr_wait_repair(uint32_t key,unsigned long page,int dir,uint32_t off,uint32_t len,void *data)
{ unsigned depth=npr_progress_wait_begin();int rc=npr_fault_repair_gate_wait(key,page);if(!rc)rc=sir_remote_repair(key,page,dir,off,len,data);int err=errno;npr_progress_wait_end(depth);errno=err;return rc; }
static int npr_wait_repair_batch(uint32_t key,const struct sir_repair_span *sp,uint32_t n,uint8_t *status)
{ unsigned depth=npr_progress_wait_begin();int rc=sir_remote_repair_batch(key,sp,n,status),err=errno;npr_progress_wait_end(depth);errno=err;return rc; }
static int npr_wait_atomic(uint32_t key,uint64_t va,int kind,uint64_t cmp,uint64_t arg,uint64_t *old)
{ unsigned depth=npr_progress_wait_begin();int rc=sir_remote_atomic(key,va,kind,cmp,arg,old),err=errno;npr_progress_wait_end(depth);errno=err;return rc; }

static pthread_mutex_t list_mu = PTHREAD_MUTEX_INITIALIZER;

struct npr_ctx_entry *npr_ctx_list;

enum npr_stat {
#define NPR_ES_ENUM(k, n, d) NPR_STAT_##k,
	NPRDMA_ENGINE_STAT_LIST(NPR_ES_ENUM)
#undef NPR_ES_ENUM
	NPR_STAT_MAX,
};

static unsigned long npr_stats[NPR_STAT_MAX];

static void npr_stat_inc(enum npr_stat s);
static void npr_stat_add(enum npr_stat s, unsigned long v);

/* used before their definitions (the batch lane hands a member to the carrier) */
static int npr_bilateral_run(struct npr_ctx_entry *ce, struct npr_inflight *t);
enum { NPR_CARRIER_REJECTED = -2 }; /* no WC slot: posting face must reject */
static int npr_source_hold(struct npr_inflight *t);
static void npr_bilateral_wc(const struct npr_inflight *t, struct ibv_wc *wc);
static int npr_carrier_deliver(struct npr_ctx_entry *ce, struct npr_inflight *t);
static int npr_write_ambiguous(const struct npr_op *op);
static int npr_carrier_write(struct npr_ctx_entry *ce, struct npr_inflight *t);
static void npr_carrier_fail_invisible(struct npr_qp_state *qs);
static int npr_prehold_pin_inflight(void *ctx, const struct mr_entry *m,
				    uint64_t va, uint64_t len);

/* Cells never move while an order/engine owner holds a pointer. Logical FIFO
 * links are independent of storage, so completed invisible work can retire
 * behind an unconsumed visible completion without exhausting the ring. */
static void npr_gate_init(struct npr_cq_entry *ce)
{
 unsigned i;
 if(ce->gate_initialized) return;
 ce->first=ce->last=NULL;
 ce->free_primary=ce->cap?ce->ring:NULL;
 ce->free_ready=ce->ready_cap?ce->ready_overflow:NULL;
 for(i=0;i<ce->cap;i++) {
  ce->ring[i].cq_owner=ce;
  ce->ring[i].free_next=i+1<ce->cap?&ce->ring[i+1]:NULL;
 }
 for(i=0;i<ce->ready_cap;i++) {
  ce->ready_overflow[i].cq_owner=ce;
  ce->ready_overflow[i].spill=1;
  ce->ready_overflow[i].free_next=i+1<ce->ready_cap?&ce->ready_overflow[i+1]:NULL;
 }
 ce->gate_initialized=1;
}
static void npr_gate_free_cell(struct npr_gate_item *g)
{
 struct npr_cq_entry *ce=g->cq_owner;
 if(!g->allocated || g->linked || g->owner_refs) return;
 g->allocated=0;
 if(g->spill) {g->free_next=ce->free_ready;ce->free_ready=g;ce->ready_n--;}
 else {g->free_next=ce->free_primary;ce->free_primary=g;ce->n--;}
}
static void npr_gate_unlink(struct npr_gate_item *g)
{
 struct npr_cq_entry *ce=g->cq_owner;
 if(!g->linked) return;
 if(g->prev) g->prev->next=g->next;else ce->first=g->next;
 if(g->next) g->next->prev=g->prev;else ce->last=g->prev;
 g->linked=0;g->consumed=1;
 ce->head=ce->first&&!ce->first->spill?(unsigned)(ce->first-ce->ring):0;
 npr_gate_free_cell(g);
}
void npr_gate_get(struct npr_gate_item *g)
{
 if(g && g->allocated) g->owner_refs++;
}
void npr_gate_put(struct npr_gate_item *g)
{
 if(!g) return;
 if(!g->allocated || !g->owner_refs) {
  npr_log_emit("[nprdma] gate owner reference underflow\n");return;
 }
 g->owner_refs--;
 if(!g->owner_refs&&g->linked&&g->ready&&!g->visible) npr_gate_unlink(g);
 else npr_gate_free_cell(g);
}
void npr_gate_set_lane(struct npr_gate_item *g,unsigned lane)
{
 if(g) g->lane=lane;
}
static void npr_gate_retire_hidden(struct npr_cq_entry *ce)
{
 struct npr_gate_item *g,*next;
 npr_gate_init(ce);
 for(g=ce->first;g;g=next) {
  next=g->next;
  if(g->ready&&!g->visible) npr_gate_unlink(g);
 }
}
static int npr_gate_full(const struct npr_cq_entry *ce)
{
 return ce->n>=ce->cap;
}
static int npr_gate_raw_full(const struct npr_cq_entry *ce)
{
 return ce->n>=ce->cap && ce->ready_n>=ce->ready_cap;
}
static int npr_gate_blocked(struct npr_cq_entry *ce,
                           struct npr_gate_item *g,int notification)
{
 struct npr_gate_item *p;
 for(p=ce->first;p&&p!=g;p=p->next)
  if((!notification||!p->ready)&&p->wc.qp_num==g->wc.qp_num&&p->lane==g->lane&&
     (!p->generation||!g->generation||p->generation==g->generation)&&
     (!p->connection_epoch||!g->connection_epoch||p->connection_epoch==g->connection_epoch)) return 1;
 return 0;
}
static struct npr_gate_item *npr_gate_take(struct npr_cq_entry *ce,int spill)
{
 struct npr_gate_item *g,**free_list;
 npr_gate_init(ce);
 free_list=spill?&ce->free_ready:&ce->free_primary;
 g=*free_list;if(!g) return NULL;
 *free_list=g->free_next;
 memset(g,0,sizeof(*g));g->cq_owner=ce;g->spill=spill;
 g->allocated=g->linked=1;g->prev=ce->last;
 if(ce->last) ce->last->next=g;else ce->first=g;
 ce->last=g;
 if(spill) ce->ready_n++;else ce->n++;
 return g;
}
struct npr_gate_item *npr_gate_reserve_raw(struct npr_cq_entry *ce)
{
 if(!ce) return NULL;
 npr_gate_retire_hidden(ce);
 if(npr_gate_raw_full(ce)) return NULL;
 return npr_gate_take(ce,npr_gate_full(ce));
}
int npr_gate_push_wc_lane(struct npr_cq_entry *ce,const struct ibv_wc *wc,unsigned lane)
{
 struct npr_gate_item *g;
 g=npr_gate_reserve_raw(ce);if(!g) return -1;
 g->wc=*wc;g->lane=lane;g->ready=g->visible=1;
 return 0;
}
static int npr_gate_push_wc(struct npr_cq_entry *ce,const struct ibv_wc *wc)
{
 /* Legacy test carriers call this helper only with defined success opcodes.
  * Production typed owners always supply an explicit lane. */
 return npr_gate_push_wc_lane(ce,wc,!!(wc->opcode&IBV_WC_RECV));
}
struct npr_gate_item *npr_gate_reserve(struct npr_cq_entry *ce)
{
 if(!ce) return NULL;
 npr_gate_retire_hidden(ce);
 if(npr_gate_full(ce)) return NULL;
 return npr_gate_take(ce,0);
}
int npr_gate_next_notification(struct npr_cq_entry *ce,struct ibv_wc *wc,unsigned *solicited)
{
 struct npr_gate_item *g;
 npr_gate_retire_hidden(ce);
 for(g=ce->first;g;g=g->next) {
  if(!g->ready||!g->visible||g->notification_seen||npr_gate_blocked(ce,g,1)) continue;
  g->notification_seen=1;*wc=g->wc;if(solicited)*solicited=g->software_solicited;return 1;
 }
 return 0;
}
int npr_gate_pop(struct npr_cq_entry *ce,struct ibv_wc *wc)
{
 struct npr_gate_item *g;
 npr_gate_retire_hidden(ce);
 for(g=ce->first;g;g=g->next) {
  if(!g->ready||npr_gate_blocked(ce,g,0)) continue;
  *wc=g->wc;npr_gate_unlink(g);return 1;
 }
 return 0;
}


struct npr_cq_entry *npr_cq_get(struct npr_ctx_entry *ce,
				       struct ibv_cq *cq)
{
	struct npr_cq_entry *e;

	for (e = ce->cqs; e; e = e->next)
		if (e->cq == cq)
			return e;
	pthread_mutex_lock(&list_mu);
	for (e = ce->cqs; e; e = e->next) {
		if (e->cq == cq) {
			pthread_mutex_unlock(&list_mu);
			return e;
		}
	}
	e = calloc(1, sizeof(*e));
	if (e) {
		e->cq = cq;
		e->cap = NPR_GATE_DEFAULT;
		e->ring = calloc(e->cap, sizeof(*e->ring));
  e->ready_cap=cq->cqe>0?(unsigned)cq->cqe:NPR_GATE_DEFAULT;
  e->ready_overflow=calloc(e->ready_cap,sizeof(*e->ready_overflow));
		if (!e->ring || !e->ready_overflow) {
   free(e->ring);free(e->ready_overflow);
			free(e);
			e = NULL;
		} else {
			e->next = ce->cqs;
			ce->cqs = e;
		}
	}
	pthread_mutex_unlock(&list_mu);
	return e;
}

void npr_cq_note_depth(struct npr_ctx_entry *ce, struct ibv_cq *cq,
		       int app_cqe)
{
	struct npr_cq_entry *e = npr_cq_get(ce, cq);
	unsigned want;
	struct npr_gate_item *ring;

	if (!e || app_cqe <= 0)
		return;
	want = (unsigned)app_cqe * 3 + NPR_GATE_SLACK;
	if (want <= e->cap || e->n || e->ready_n)
		return;
	ring = calloc(want, sizeof(*ring));
	if (!ring)
		return;
	pthread_mutex_lock(&list_mu);
	free(e->ring);
	e->ring = ring;
	e->cap = want;
	e->head = 0;
	e->n = 0;
	e->gate_initialized = 0;
	pthread_mutex_unlock(&list_mu);
}

static unsigned npr_if_capacity(const struct npr_ctx_entry *ce,
				const struct ibv_qp *qp)
{
	unsigned d = 0, cap;

	for (const struct npr_sq_depth *p = ce->depths; p; p = p->next)
		if (p->qp == qp) {
			d = p->app_depth;
			break;
		}
	cap = d;
	if (!cap)
		cap = NPRDMA_INFLIGHT_MAX;
	if (cap > NPRDMA_INFLIGHT_MAX)
		cap = NPRDMA_INFLIGHT_MAX;
	return cap;
}

int npr_qp_sig_all(struct npr_ctx_entry *ce, struct ibv_qp *qp)
{
	struct npr_qp_state *q;
	struct npr_sq_depth *d;

	for (q = ce->qps; q; q = q->next)
		if (q->qp == qp)
			return q->sq_sig_all;
	for (d = ce->depths; d; d = d->next)
		if (d->qp == qp)
			return d->sq_sig_all;
	return 0;
}

void npr_qp_note_sig_all(struct npr_ctx_entry *ce, struct ibv_qp *qp, int all)
{
	struct npr_qp_state *q;
	struct npr_sq_depth *d;

	/* Called after note_depth at QP creation; retain the application policy,
	 * not the private SIGNALED bits used for verification completions. */
	for (d = ce->depths; d; d = d->next)
		if (d->qp == qp) {
			d->sq_sig_all = !!all;
			break;
		}
	for (q = ce->qps; q; q = q->next)
		if (q->qp == qp)
			q->sq_sig_all = !!all;
}

static struct npr_qp_state *npr_qp_get(struct npr_ctx_entry *ce,
				       struct ibv_qp *qp)
{
	struct npr_qp_state *q;

	for (q = ce->qps; q; q = q->next)
		if (q->qp == qp)
			return q;
	pthread_mutex_lock(&list_mu);
	for (q = ce->qps; q; q = q->next) {
		if (q->qp == qp) {
			pthread_mutex_unlock(&list_mu);
			return q;
		}
	}

	{
		struct npr_qp_state **pp;

		for (pp = &ce->dead_qps; *pp; pp = &(*pp)->next) {
			if ((*pp)->lifecycle_refs || (*pp)->if_n || (*pp)->batch_native_refs ||
       (*pp)->batch_drop_pending || (*pp)->bat_pool || (*pp)->ifs)
    continue;
			q = *pp;
			*pp = q->next;
   memset(q,0,sizeof(*q));
   q->qp=qp;q->qp_num=qp->qp_num;q->send_cq=qp->send_cq;
   q->if_cap=npr_if_capacity(ce,qp);
   q->sq_sig_all=npr_qp_sig_all(ce,qp);
			q->ifs = calloc(q->if_cap, sizeof(*q->ifs));
			if (!q->ifs) {
				free(q->ifs);
				free(q);
				pthread_mutex_unlock(&list_mu);
				return NULL;
			}
			npr_stat_inc(NPR_STAT_QP_REBORN);
			q->next = ce->qps;
			ce->qps = q;
			pthread_mutex_unlock(&list_mu);
			return q;
		}
	}
	q = calloc(1, sizeof(*q));
	if (q) {
		q->sq_sig_all = npr_qp_sig_all(ce, qp);
		q->qp = qp;
		q->qp_num = qp->qp_num;
		q->send_cq = qp->send_cq;
		q->if_cap = npr_if_capacity(ce, qp);
		q->ifs = calloc(q->if_cap, sizeof(*q->ifs));
		if (!q->ifs) {

			free(q->ifs);
			free(q);
			pthread_mutex_unlock(&list_mu);
			return NULL;
		}
		q->next = ce->qps;
		ce->qps = q;
	}
	pthread_mutex_unlock(&list_mu);
	return q;
}

struct npr_qp_state *npr_qp_state_find(struct npr_ctx_entry *ce,struct ibv_qp *qp)
{struct npr_qp_state *q;for(q=ce->qps;q;q=q->next)if(q->qp==qp)return q;return NULL;}
struct npr_qp_state *npr_qp_state_reserve(unsigned depth,int sig_all)
{
 struct npr_qp_state *q=calloc(1,sizeof(*q));
 if(!q)return NULL;
 q->if_cap=depth?depth:NPRDMA_INFLIGHT_MAX;
 if(q->if_cap>NPRDMA_INFLIGHT_MAX)q->if_cap=NPRDMA_INFLIGHT_MAX;
 q->ifs=calloc(q->if_cap,sizeof(*q->ifs));
 if(!q->ifs){free(q);return NULL;}
 q->sq_sig_all=!!sig_all;return q;
}
void npr_qp_state_abort(struct npr_qp_state *q)
{ if(q){free(q->ifs);free(q);} }
void npr_qp_state_commit(struct npr_ctx_entry *ce,struct npr_qp_state *q,struct ibv_qp *qp)
{
 q->qp=qp;q->qp_num=qp->qp_num;q->send_cq=qp->send_cq;
 pthread_mutex_lock(&list_mu);q->next=ce->qps;ce->qps=q;pthread_mutex_unlock(&list_mu);
}

void npr_qp_note_depth(struct npr_ctx_entry *ce, struct ibv_qp *qp,
		       unsigned app_depth)
{
	struct npr_sq_depth *d;

	for (d = ce->depths; d; d = d->next)
		if (d->qp == qp) {
			d->app_depth = app_depth;
			return;
		}
	pthread_mutex_lock(&list_mu);
	d = calloc(1, sizeof(*d));
	if (d) {
		d->qp = qp;
		d->app_depth = app_depth;
		d->next = ce->depths;
		ce->depths = d;
	}
	pthread_mutex_unlock(&list_mu);
}

static __attribute__((unused)) struct npr_qp_state *npr_qp_by_num(struct npr_ctx_entry *ce,
					  uint32_t qp_num)
{
	struct npr_qp_state *q;

	for (q = ce->qps; q; q = q->next)

		if (q->qp_num == qp_num && !q->dead)
			return q;
	return NULL;
}

struct npr_ctx_entry *npr_ctx_get(struct ibv_context *ctx)
{
	struct npr_ctx_entry *e;

	for (e = npr_ctx_list; e; e = e->next)
		if (e->ctx == ctx)
			return e;
	pthread_mutex_lock(&list_mu);
	for (e = npr_ctx_list; e; e = e->next) {
		if (e->ctx == ctx) {
			pthread_mutex_unlock(&list_mu);
			return e;
		}
	}
	e = calloc(1, sizeof(*e));
	if (e) {
		e->ctx = ctx;
		e->next = npr_ctx_list;
		npr_ctx_list = e;
	}
	pthread_mutex_unlock(&list_mu);
	return e;
}

static void __attribute__((noinline))
npr_fail_closed(struct npr_inflight *e, const char *what);
static int npr_inline_repair_ok(const struct npr_inflight *t, uint32_t miss_off);
static void npr_poison_mem(void *p, size_t n);
static struct npr_inflight *npr_if_alloc(struct npr_ctx_entry *ce,
					 struct npr_qp_state *qs);
static void npr_if_release(struct npr_inflight *e);
static void npr_batch_close(struct npr_ctx_entry *,struct npr_qp_state *,int,struct npr_inflight *);
static void npr_publish_terminal(struct npr_inflight *);

struct npr_policy_ud {
	struct npr_cq_entry *cqe;
	struct npr_ctx_entry *ce;
	struct npr_inflight *t;
	unsigned long np;
	struct npr_detect_domain *dom;
	struct sir_repair_span spans[SIR_REPAIR_BATCH_MAX];
	int read_repair_all;
	int read_carried;
};

#ifndef NPR_POLL_SPIN_MAX
#define NPR_POLL_SPIN_MAX 200000
#endif
#define NPR_POLL_SLEEP_US 50

static pthread_mutex_t win_mu = PTHREAD_MUTEX_INITIALIZER;

_Static_assert(NPRDMA_WINDOW_SLOTS <= 64, "used bitmap can express at most 64 slots");

static void npr_window_poison(struct npr_window_pool *w, unsigned slot)
{
	static int on = -1;

	if (on < 0) {
		const char *m = getenv("NPRDMA_WINDOW_DEBUG");

		on = (m && *m && *m != '0');
	}
	if (on)
		memset((char *)w->base + (size_t)slot * NPR_WINDOW_SLOT_SIZE,
		       0xA5, NPR_WINDOW_SLOT_SIZE);
}

static int npr_window_invariant(struct npr_window_pool *w)
{
	unsigned n = 0, i;

	for (i = 0; i < NPRDMA_WINDOW_SLOTS; i++)
		if (w->used & (1ULL << i))
			n++;
	if (n == w->n_used && w->mr && w->base)
		return 0;
	npr_log_emit("[nprdma] window pool steady-state invariant violation (bitmap/count/mr inconsistent) —"
		     "channel disabled (fail-closed)\n");
	w->failed = 1;
	return -1;
}

int npr_pd_release_windows(struct ibv_pd *pd)
{
 struct npr_ctx_entry *ce;
 int (*dereg)(struct ibv_mr *) = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
 unsigned i;
 int rc = 0;
 pthread_mutex_lock(&win_mu);
 for (ce = npr_ctx_list; ce; ce = ce->next) {
  for (i = 0; i < ce->npools; i++) {
   struct npr_window_pool *w = ce->pools[i];
   if (!w) continue;
   if (w->pd != pd) continue;
   if (w->used || w->n_used) { rc = EBUSY; goto out; }
   if (w->mr) {
    rc = dereg ? dereg(w->mr) : ENOSYS;
    if (rc) goto out;
    w->mr = NULL;
   }
   if (w->mr_id >= 0 && sym_fd >= 0) {
    if (ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, w->mr_id)) {
     rc = errno ? errno : EIO;
     goto out;
    }
    w->mr_id = -1;
   }
   if (w->base) munmap(w->base, NPR_WINDOW_POOL_SIZE);
   free(w);
   ce->pools[i] = NULL;
  }
 }
 out:
 pthread_mutex_unlock(&win_mu);
 return rc;
}

static struct npr_window_pool *npr_window_for(struct npr_ctx_entry *ce,
					      struct ibv_pd *pd)
{
	struct ibv_mr *(*regfn)(struct ibv_pd *, void *, size_t, uint64_t,
				unsigned int);
	struct npr_window_pool *w = NULL, **na;
	void *buf;
	unsigned i;

	for (i = 0; i < ce->npools; i++)
		if (ce->pools[i] && ce->pools[i]->pd == pd)
			return ce->pools[i];

	w = calloc(1, sizeof(*w));
	if (!w) return NULL;
	w->mr_id = -1;
	na = realloc(ce->pools, (ce->npools + 1) * sizeof(*na));
	if (!na) {
		free(w);
		npr_log_emit("[nprdma] window pool table grow failed — verification degraded\n");
		return NULL;
	}
	ce->pools = na;
	ce->pools[ce->npools++] = w;
	w->pd = pd;

	regfn = g_real_reg_mr_iova2;
	if (!regfn)
		regfn = dlvsym(RTLD_NEXT, "ibv_reg_mr_iova2", "IBVERBS_1.8");
	if (!pd || !regfn || npr_fault_window_mmap()) {

		w->failed = 1;
		return NULL;
	}
	buf = mmap(NULL, NPR_WINDOW_POOL_SIZE, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED) {
		w->failed = 1;
		return NULL;
	}
	memset(buf, 0, NPR_WINDOW_POOL_SIZE);
	if (symrdma_open_locked() == 0) {
		struct symrdma_ioc_reg_mr req = {
			.va_start = (unsigned long long)(uintptr_t)buf,
			.len = NPR_WINDOW_POOL_SIZE,
		};

		if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &req) == 0)
			w->mr_id = req.mr_id;
	}
	w->mr = regfn(pd, buf, NPR_WINDOW_POOL_SIZE,
		      (uint64_t)(uintptr_t)buf,
		      IBV_ACCESS_LOCAL_WRITE | NPRDMA_MR_SYMRDMA);
	if (!w->mr) {
		if (debug_on())
			fprintf(stderr,
				"[nprdma] window pool creation failed (pd=%p) — remote write verification disabled\n",
				(void *)pd);
		w->failed = 1;
		munmap(buf, NPR_WINDOW_POOL_SIZE);
		return NULL;
	}
	w->base = buf;
	w->used = 0;
	w->n_used = 0;
	npr_pin_once(w->mr_id, (uint64_t)(uintptr_t)buf, NPR_WINDOW_POOL_SIZE);
	return w;
}

static int npr_window_get(struct npr_ctx_entry *ce, struct ibv_pd *pd,
			  struct npr_window_pool **pool, unsigned *slot)
{
	struct npr_window_pool *w;
	unsigned i;
	int rc = -1;

	pthread_mutex_lock(&win_mu);
	w = npr_window_for(ce, pd);
	if (!w || w->failed) {
		pthread_mutex_unlock(&win_mu);
		errno = EIO;
		return -1;
	}
	for (i = 0; i < NPRDMA_WINDOW_SLOTS; i++) {
		if (w->used & (1ULL << i))
			continue;
		w->used |= 1ULL << i;
		w->n_used++;
		*slot = i;
		*pool = w;
		rc = npr_window_invariant(w);
		break;
	}
	if (rc != 0) {
  errno = w->failed ? EIO : EAGAIN;
		w->exhausted++;
		if (debug_on())
			fprintf(stderr,
				"[nprdma] window pool has no free slot (%u in flight) — verification degraded\n",
				w->n_used);
	}
	pthread_mutex_unlock(&win_mu);
	return rc;
}

/* Posting may outpace application polling (for example CQ moderation=100).
 * Reap internal completions before rejecting a verification window request. */
static int npr_window_get_progress(struct npr_ctx_entry *ce, struct ibv_pd *pd,
                                  struct npr_window_pool **pool, unsigned *slot)
{
 unsigned tries;
 for (tries = 0; tries < 1024; tries++) {
  struct npr_cq_entry *cq;
  if (!npr_window_get(ce, pd, pool, slot)) return 0;
  for (cq = ce->cqs; cq; cq = cq->next)
   if (npr_drain_cq(ce, cq)) return -1;
  { unsigned depth=npr_progress_wait_begin();usleep(10);npr_progress_wait_end(depth); }
 }
 return -1;
}

static void npr_window_put(struct npr_window_pool *w, unsigned slot)
{
	if (!w || slot == NPR_WINDOW_NONE)
		return;
	pthread_mutex_lock(&win_mu);
	if (slot >= NPRDMA_WINDOW_SLOTS || !(w->used & (1ULL << slot))) {
		npr_log_emit("[nprdma] window slot put of an unallocated slot (double put / wild number) —"
			     "pool disabled (fail-closed)\n");
		w->failed = 1;
		pthread_mutex_unlock(&win_mu);
		return;
	}
	w->used &= ~(1ULL << slot);
	w->n_used--;
	npr_window_poison(w, slot);
	npr_window_invariant(w);
	pthread_mutex_unlock(&win_mu);
}

static char *npr_window_addr(const struct npr_window_pool *w, unsigned slot)
{
	if (!w || slot == NPR_WINDOW_NONE || !w->base)
		return NULL;
	return (char *)w->base + (size_t)slot * NPR_WINDOW_SLOT_SIZE;
}

static int npr_window_take(struct npr_inflight *e)
{
	struct npr_ctx_entry *ce = e->ce;
	struct ibv_qp *qp = e->qp;
	struct npr_window_pool *wp = NULL;
	char *src;

	if (npr_window_get(ce, qp->pd, &wp, &e->src_slot) ||
	    npr_window_get(ce, qp->pd, &e->pool, &e->aux_slot))
		goto fail;
	e->pool = wp;
	src = npr_window_addr(wp, e->src_slot);
	if (!src || e->op.len > (uint64_t)NPR_SMALL_DATA_MAX) {
  errno=EINVAL;goto fail;
 }
 if(npr_sg_copy(&e->op,0,src,(size_t)e->op.len,0)){errno=EINVAL;goto fail;}
	return 0;
fail: {
 int saved=errno;
	npr_window_put(wp, e->src_slot);
	npr_window_put(e->pool, e->aux_slot);
	e->src_slot = NPR_WINDOW_NONE;
	e->aux_slot = NPR_WINDOW_NONE;
 errno=saved;
	return -1;
 }
}

static uint64_t npr_batch_base_of(uint64_t min_addr, uint64_t exp_addr)
{
	uint64_t base = min_addr & ~(uint64_t)(SYMRDMA_PAGE_SIZE - 1);

	return base < exp_addr ? exp_addr : base;
}

static void npr_batch_reset(struct npr_batch *b)
{
 for(unsigned k=0;k<b->n_ops;k++)npr_order_batch_member_set(b->members[k].order,0);
 if(b->revision!=UINT64_MAX)b->revision++;
	memset(b->members, 0xA5, sizeof(b->members));
	memset(&b->exp, 0, sizeof(b->exp));
	b->base = 0;
	b->span = 0;
	b->bytes = 0;
	b->n_ops = 0;
	b->rkey = 0;
}

NPRDMA_INTERNAL struct npr_batch_pool *npr_batch_pool_get(struct npr_qp_state *qs)
{
	struct ibv_mr *(*regfn)(struct ibv_pd *, void *, size_t, uint64_t,
				unsigned int);
	struct npr_batch_pool *bp;
	struct ibv_pd *pd;
	size_t sz = 2 * (size_t)NPRDMA_BATCH_SPAN;
	void *buf;

	if (!qs || !qs->qp || !qs->qp->pd)
		return NULL;
	pd = qs->qp->pd;
	bp = qs->bat_pool;
	if (bp)
		return bp->failed ? NULL : bp;

	bp = calloc(1, sizeof(*bp));
	if (!bp)
		return NULL;
	bp->mr_id = -1;
	qs->bat_pool = bp;
	bp->runs = calloc(NPRDMA_BATCH_OPS, sizeof(*bp->runs));
	if (!bp->runs)
		goto fail;

	regfn = g_real_reg_mr_iova2;
	if (!regfn)
		regfn = dlvsym(RTLD_NEXT, "ibv_reg_mr_iova2", "IBVERBS_1.8");
	if (!regfn)
		goto fail;
	buf = mmap(NULL, sz, PROT_READ | PROT_WRITE,
		   MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (buf == MAP_FAILED)
		goto fail;
	memset(buf, 0, sz);
	if (symrdma_open_locked() == 0) {
		struct symrdma_ioc_reg_mr req = {
			.va_start = (unsigned long long)(uintptr_t)buf,
			.len = sz,
		};

		if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &req) == 0)
			bp->mr_id = req.mr_id;
	}
	bp->mr = regfn(pd, buf, sz, (uint64_t)(uintptr_t)buf,
		       IBV_ACCESS_LOCAL_WRITE | NPRDMA_MR_SYMRDMA);
	if (!bp->mr) {
		if (bp->mr_id >= 0 && sym_fd >= 0) {
			ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, bp->mr_id);
			bp->mr_id = -1;
		}
		munmap(buf, sz);
		goto fail;
	}
	bp->base = buf;

	npr_pin_once(bp->mr_id, (uint64_t)(uintptr_t)buf, sz);
	return bp;
fail:
	bp->failed = 1;
	if (debug_on())
		fprintf(stderr,
			"[nprdma] batch pool creation failed (pd=%p) — unsignaled write batch face disabled\n",
			(void *)pd);
	return NULL;
}

static void npr_batch_pool_release(struct npr_qp_state *qs,int provider_live)
{
	struct npr_batch_pool *bp = qs->bat_pool;
	size_t sz = 2 * (size_t)NPRDMA_BATCH_SPAN;
	int (*dereg)(struct ibv_mr *);

	npr_batch_reset(&qs->bat);
	if (!bp)
		return;
	qs->bat_pool = NULL;
	if (bp->mr && provider_live) {
		dereg = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
		if (dereg)
			dereg(bp->mr);
	}
	if (bp->mr_id >= 0 && sym_fd >= 0)
		ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, bp->mr_id);
	if (bp->base) {
		npr_poison_mem(bp->base, sz);
		munmap(bp->base, sz);
	}
	if (bp->runs) {
		npr_poison_mem(bp->runs,
			       (size_t)NPRDMA_BATCH_OPS * sizeof(*bp->runs));
		free(bp->runs);
		bp->runs = NULL;
	}
	bp->n_runs = 0;
	npr_poison_mem(bp, sizeof(*bp));
	free(bp);
}

static void __attribute__((noinline))
npr_batch_violation(struct npr_qp_state *qs, const char *why)
{
	char line[192];
	size_t o = (size_t)snprintf(line, sizeof(line),
				    "[nprdma] batch invariant violation:");

	o = npr_bnd_add(line, sizeof(line), o, why, 64);
	snprintf(line + o, sizeof(line) - o,
		 "— batch pool disabled + batch dropped (fail-closed)\n");
	npr_log_emit_buf(line, strnlen(line, sizeof(line)));
	npr_stat_inc(NPR_STAT_BATCH_INVARIANT);
	if (qs->bat_pool)
		qs->bat_pool->failed = 1;
	npr_batch_reset(&qs->bat);
}

static int npr_batch_invariant(struct npr_qp_state *qs)
{
	struct npr_batch *b = &qs->bat;
	uint64_t base = 0, end = 0, bytes = 0;
	const char *why = NULL;
	unsigned i;

	if (!b->n_ops) {
		if (b->base || b->span || b->bytes || b->rkey ||
		    b->exp.data_rkey || b->exp.write_rkey || b->exp.addr ||
		    b->exp.len || b->exp.v_rkey || b->exp.v_addr ||
		    b->exp.lkey || b->exp.mr_id)
			why = "empty batch with non-zero accounting (residue after destroy)";
		goto out;
	}
	if (b->n_ops > NPRDMA_BATCH_OPS) {
		why = "batch member count over the cap";
		goto out;
	}
	if (b->bytes > NPRDMA_BATCH_BYTES) {
		why = "batch byte accounting over the cap";
		goto out;
	}
	if (b->span > NPRDMA_BATCH_SPAN) {
		why = "batch span over the cap";
		goto out;
	}
	base = npr_batch_base_of(b->members[0].remote_addr, b->exp.addr);
	end = base;
	for (i = 0; i < b->n_ops; i++) {
		const struct npr_batch_member *m = &b->members[i];
		uint64_t mb = npr_batch_base_of(m->remote_addr, b->exp.addr);
		uint64_t me = m->remote_addr + m->len;

		if (!m->len) {
			why = "batch member length is 0";
			goto out;
		}
		if (m->rkey != b->rkey) {
			why = "batch member crosses exports (rkey mismatch)";
			goto out;
		}
		if (m->remote_addr < b->exp.addr ||
		    me > b->exp.addr + b->exp.len) {
			why = "batch member outside the exported region";
			goto out;
		}

		if (m->remote_addr < b->base ||
		    me > b->base + b->span) {
			why = "shadow offset out of range (member outside the recorded span)";
			goto out;
		}
		if (mb < base)
			base = mb;
		if (me > end)
			end = me;
		bytes += m->len;
	}
	if (b->base != base)
		why = "base ledger disagrees with the member union";
	else if (b->span != end - base)
		why = "span ledger disagrees with the member union";
	else if (b->bytes != bytes)
		why = "bytes ledger disagrees with the member len sum";
	out:
	if (!why)
		return 0;
	npr_batch_violation(qs, why);
	return -1;
}

static int npr_batch_fits(const struct npr_batch *b, uint64_t addr,
			  uint64_t len)
{
	uint64_t nb, ne, lo;

	if (!b->n_ops)
		return 1;
	if (b->n_ops >= NPRDMA_BATCH_OPS)
		return 0;
	if (b->bytes + len > NPRDMA_BATCH_BYTES)
		return 0;
	nb = b->base;
	lo = npr_batch_base_of(addr, b->exp.addr);
	if (lo < nb)
		return 0;
	ne = nb + b->span;
	if (addr + len > ne)
		ne = addr + len;
	return ne - nb <= NPRDMA_BATCH_SPAN;
}

static int npr_batch_pending(const struct npr_qp_state *q)
{
 return q->bat.n_ops || q->batch_native_refs || q->batch_drop_pending ||
        q->bat_busy || q->batch_closing;
}
static int npr_batch_image_wait(struct npr_ctx_entry *ce,struct npr_qp_state *qs)
{
 struct npr_cq_entry *cq;
 unsigned spins=0;
 if(!npr_batch_pending(qs)) return 0;
 npr_stat_inc(NPR_STAT_BATCH_BARRIER);
 cq=qs->send_cq?npr_cq_get(ce,qs->send_cq):NULL;
 while(npr_batch_pending(qs)) {
  if(!cq||npr_drain_cq(ce,cq)) return -1;
  if(!qs->batch_closing) npr_batch_close(ce,qs,0,NULL);
  if(!npr_batch_pending(qs)) break;
  if(++spins>NPR_POLL_SPIN_MAX) return -1;
  {unsigned depth=npr_progress_wait_begin();usleep(NPR_POLL_SLEEP_US);npr_progress_wait_end(depth);}
 }
 return 0;
}

static int npr_batch_aux_emit(struct npr_ctx_entry *ce,
			      struct npr_inflight *e)
{
	const char *shadow = e->span.shadow;
	struct npr_op aux;

	if (!shadow || !e->bpool || !e->bpool->mr || !e->span.exp.data_rkey ||
	    !e->span.len)
		return -1;
	memset(&aux, 0, sizeof(aux));
	aux.kind = NPR_OP_READ;
	aux.remote_addr = e->span.remote_addr;
	aux.rkey = e->span.exp.data_rkey;
	aux.num_sge = 1;
	aux.sge[0].addr = (uint64_t)(uintptr_t)(shadow + NPRDMA_BATCH_SPAN);
	aux.sge[0].length = (uint32_t)e->span.len;
	aux.sge[0].lkey = e->bpool->mr->lkey;
	aux.len = e->span.len;
	aux.signaled = 1;
	if (npr_emit_owned(ce, e->qp, &aux,NPR_ID_AUX,e)) {
		return -1;
	}
	return 0;
}

static uint64_t npr_batch_runs_build(struct npr_batch *b,
				     struct npr_batch_pool *bp)
{
	unsigned i, j, n = 0;
	uint64_t covered = 0;

	if (!bp)
		return 0;
	bp->n_runs = 0;
	if (!bp->runs || !b->n_ops)
		return 0;
	for (i = 1; i < b->n_ops; i++) {
		struct npr_batch_member m = b->members[i];

		for (j = i; j > 0 &&
		     b->members[j - 1].remote_addr > m.remote_addr; j--)
			b->members[j] = b->members[j - 1];
		b->members[j] = m;
	}
	for (i = 0; i < b->n_ops && n < NPRDMA_BATCH_OPS; i++) {
		uint64_t lo = b->members[i].remote_addr;
		uint64_t hi = lo + b->members[i].len;

		if (n && lo <= bp->runs[n - 1].off + bp->runs[n - 1].len) {
			uint64_t end = bp->runs[n - 1].off + bp->runs[n - 1].len;

			if (hi > end)
				bp->runs[n - 1].len = hi - bp->runs[n - 1].off;
			continue;
		}
		bp->runs[n].off = lo;
		bp->runs[n].len = hi - lo;
		n++;
	}
	for (i = 0; i < n; i++) {
		bp->runs[i].off -= b->base;
		covered += bp->runs[i].len;
	}
	bp->n_runs = n;
	return covered;
}

/* Reserve identity before PIN can yield; cleanup observes the in-progress bit. */
static int npr_prehold_pin(struct npr_prehold *ph,const struct mr_entry *m,uint64_t va,uint64_t len)
{
 memset(ph,0,sizeof(*ph));
 if(npr_sr_mr_get(m))return -1;
 ph->mr=m;ph->va=va;ph->len=len;ph->mr_ref=1;ph->pinning=1;
 int rc=npr_local_pin(m,va,len),saved=errno;
 ph->pinned=!rc;ph->pinning=0;
 if(rc){npr_sr_mr_put(m);memset(ph,0,sizeof(*ph));}
 errno=saved;return rc;
}
static int npr_prehold_release(struct npr_prehold *ph)
{
 if(ph->pinning)return -1;
 if(ph->pinned&&npr_sr_unpin(ph->mr,ph->va,ph->len))return -1;
 ph->pinned=0;
 if(ph->mr_ref)npr_sr_mr_put(ph->mr);
 memset(ph,0,sizeof(*ph));return 0;
}
static void npr_batch_drop(struct npr_qp_state *qs)
{
 struct npr_order_entry *owners[NPRDMA_BATCH_OPS];
 unsigned n=0,k;
 if(qs->batch_native_refs) {qs->batch_drop_pending=1;return;}
 if(!qs->bat.n_ops) {qs->batch_drop_pending=0;return;}
 for(k=0;k<qs->bat.n_ops;k++) if(qs->bat.members[k].order) owners[n++]=qs->bat.members[k].order;
 qs->batch_drop_pending=0;
 npr_batch_reset(&qs->bat);
 npr_stat_inc(NPR_STAT_BATCH_DROPPED);
 /* The native batch has retired; publish the member completions. */
 for(k=0;k<n;k++) {
  struct ibv_wc wc={.status=IBV_WC_GENERAL_ERR,.qp_num=qs->qp_num};
  npr_order_complete(owners[k],&wc);npr_order_put(owners[k]);
 }
 npr_log_emit("[nprdma] batch dropped — the batch's writes were not verified (no verified claim)\n");
}

static void npr_batch_close(struct npr_ctx_entry *ce, struct npr_qp_state *qs,
			    int cover_app, struct npr_inflight *cover)
{
	struct npr_batch *b = &qs->bat;
	struct npr_batch_pool *bp = qs->bat_pool;
	struct sir_export exp = b->exp;
	uint64_t base = b->base;
	uint64_t span = b->span;
	uint64_t covered;
	uint32_t rkey = b->rkey;
	struct npr_inflight *e;
	struct npr_order_entry *owners[NPRDMA_BATCH_OPS];
	unsigned owner_n=0,k;

	if(qs->batch_drop_pending) {npr_batch_drop(qs);return;}
	/* The readback is posted after the members on this same SQ. Waiting for
  * their software-consumed CQEs creates a foreground progress cycle and is
  * unnecessary for DMA ordering. Native identities retain member leases. */
 if (!b->n_ops || qs->batch_closing ||
     (qs->batch_native_refs&&(qs->closing||ce->closing)))
		return;
 qs->batch_closing=1;

	for(k=0;k<b->n_ops;k++) if(b->members[k].order) owners[owner_n++]=b->members[k].order;
	if (npr_batch_invariant(qs))
		goto drop;
	covered = npr_batch_runs_build(b, bp);
	if (bp) {
		unsigned k;

		for (k = 0; k < bp->n_runs; k++)
			if (bp->runs[k].off >= span ||
			    bp->runs[k].off + bp->runs[k].len > span) {
				npr_stat_inc(NPR_STAT_BATCH_INVARIANT);
				covered = span + 1;
				break;
			}
	}
	if (bp && covered <= span)
		npr_stat_add(NPR_STAT_BATCH_GAP_BYTES, span - covered);

	if (!qs->qp || !bp || !bp->base || !bp->mr || !bp->runs ||
	    !bp->n_runs || covered > span || qs->bat_busy)
		goto drop;
	e = npr_if_alloc(ce, qs);
	if (!e)
		goto drop;
	e->landing = NPR_LANDING_BATCH;
	memcpy(e->order_batch,owners,owner_n*sizeof(*owners));
	e->order_batch_n=owner_n;
	npr_batch_reset(b);
	owner_n=0; /* The inflight now owns all member borrows. */
	e->bpool = bp;
	e->cover = cover;
 if(cover)cover->cover_refs++;
	e->visible = 0;
	e->aux_want = 1;
	e->span.shadow = (char *)bp->base;
	e->span.readback = (char *)bp->base + NPRDMA_BATCH_SPAN;
	e->span.remote_addr = base;
	e->span.len = span;
	e->span.np = (unsigned long)((span + SYMRDMA_PAGE_SIZE - 1) /
				     SYMRDMA_PAGE_SIZE);
	e->span.rkey = rkey;
	e->span.exp = exp;
	qs->bat_busy = 1;
	if (npr_batch_aux_emit(ce, e)) {
		npr_if_release(e);
		goto drop;
	}
	npr_stat_inc(NPR_STAT_BATCH_CLOSE);
	npr_stat_inc(cover_app ? NPR_STAT_BATCH_COVER_APP :
				 NPR_STAT_BATCH_COVER_AUX);
 qs->batch_closing=0;
	return;
drop:
 qs->batch_closing=0;
 npr_batch_drop(qs);
 if(bp&&!qs->bat_busy) bp->n_runs=0;
}

static int npr_batch_refresh(struct npr_ctx_entry *ce, struct npr_inflight *e)
{
	struct npr_cq_entry *cqe = npr_cq_get(ce, e->send_cq);
	int spins = 0;

	e->aux_done = 0;
	e->aux_ok = 0;
	if (npr_batch_aux_emit(ce, e))
		return -1;
	while (!e->aux_done) {
		if (!cqe || npr_drain_cq(ce, cqe))
			return -1;
		if (e->aux_done)
			break;
		if (++spins > NPR_POLL_SPIN_MAX)
			return -1;
		{ unsigned depth=npr_progress_wait_begin();usleep(NPR_POLL_SLEEP_US);npr_progress_wait_end(depth); }
	}
	return e->aux_ok ? 0 : -1;
}

static repair_verdict npr_batch_detect(void *udp, uint8_t *page_missing,
				       int attempt)
{
	struct npr_policy_ud *u = udp;
	struct npr_inflight *e = u->t;
	const char *shadow = e->span.shadow;
	const char *readback = e->span.readback;
	unsigned long p, nmiss = 0;

	if (!e->aux_ok || !shadow || !readback || !e->bpool)
		return REPAIR_VERDICT_UNAVAILABLE;
	if (attempt > 0 && npr_batch_refresh(u->ce, e))
		return REPAIR_VERDICT_UNAVAILABLE;
	detect_memcmp_windows(readback, shadow, 0, e->span.len,
			      e->bpool->runs, e->bpool->n_runs, u->np,
			      page_missing, 1);
	for (p = 0; p < u->np; p++)
		nmiss += page_missing[p] ? 1 : 0;
	if (nmiss)
		npr_stat_add(NPR_STAT_BATCH_MISS_PAGES, nmiss);
	return detect_any_missing(page_missing, u->np) ?
	       REPAIR_VERDICT_MISSING : REPAIR_VERDICT_CLEAN;
}

static int npr_batch_repair(void *udp, struct sir_repair_span *spans,
			    uint32_t n)
{
	struct npr_policy_ud *u = udp;
	struct npr_inflight *e = u->t;
	const char *shadow = e->span.shadow;
	unsigned long region_pg = e->span.exp.addr / SYMRDMA_PAGE_SIZE;
	uint32_t chunk_max = (uint32_t)sir_inline_max();
	const struct detect_window *runs;
	unsigned nr, i;

	if (npr_fault_repair_fail()) {
		errno = EIO;
		return -1;
	}
	if (!shadow || !chunk_max || !e->bpool) {
		errno = EINVAL;
		return -1;
	}
	runs = e->bpool->runs;
	nr = e->bpool->n_runs;

	for (i = 0; i < n; i++) {
		uint64_t lo = e->span.exp.addr +
			      (uint64_t)spans[i].page_idx * SYMRDMA_PAGE_SIZE +
			      spans[i].xoff;
		uint64_t hi = lo + spans[i].xlen;
		unsigned k;

		for (k = 0; k < nr; k++) {
			uint64_t rl = e->span.remote_addr + runs[k].off;
			uint64_t rh = rl + runs[k].len;
			uint64_t a = lo > rl ? lo : rl;
			uint64_t b = hi < rh ? hi : rh;

			while (a < b) {
				uint32_t in_page = (uint32_t)(a &
						(SYMRDMA_PAGE_SIZE - 1));
				uint32_t chunk = SYMRDMA_PAGE_SIZE - in_page;
				uint64_t room = b - a;

				if (chunk > chunk_max)
					chunk = chunk_max;
				if ((uint64_t)chunk > room)
					chunk = (uint32_t)room;

				if (npr_wait_repair(e->span.rkey,
						(unsigned long)(a / SYMRDMA_PAGE_SIZE) -
						region_pg,
						SIR_F_WRITE, in_page, chunk,
						(void *)(uintptr_t)(shadow +
							(a - e->span.remote_addr))))
					return -1;
				a += chunk;
			}
			if (b >= hi)
				break;
		}
	}
	npr_stat_inc(NPR_STAT_BATCH_REPAIR_OK);
	return 0;
}

static void npr_batch_escalate(void *udp, int why)
{
	struct npr_policy_ud *u = udp;
	struct npr_inflight *e = u->t;

	e->cover_bad=1;
	npr_stat_inc(NPR_STAT_BATCH_REPAIR_FAIL);
	if (e->cover && e->cover->qs == e->qs && !e->cover->delivered) {
		e->cover->cover_bad = 1;
		npr_stat_inc(NPR_STAT_BATCH_COVER_BAD);
		npr_log_emit("[nprdma] batch repair failed (why=%d) — the cover's app WC is delivered as an error\n",
			     why);
		return;
	}
	npr_log_emit("[nprdma] batch repair failed (why=%d) — the batch does not claim verified\n", why);
}

struct npr_batch_prepare {
 struct npr_ctx_entry *ce;
 struct npr_qp_state *qs;
 const struct npr_op *op;
 struct npr_inflight *candidate;
 uint64_t generation;
};
static int npr_batch_prepare_current(const struct npr_batch_prepare *p)
{
 struct npr_gate_item *item=p->op->order?npr_order_item(p->op->order):NULL;
 return !p->ce->closing&&!p->qs->closing&&!p->qs->dead&&
  npr_qp_state_find(p->ce,p->qs->qp)==p->qs&&
  npr_identity_qp_known_generation(p->qs->qp)==p->generation&&
  (!item||(!item->consumed&&!item->ready));
}
/* Source/readback pairs share a bounded PD pool. Temporary exhaustion is
 * posting backpressure, not evidence of failed DMA. Retire completed native
 * work in this caller; never leave half a pair reserved while waiting. */
static int npr_window_take_progress(struct npr_inflight *e,const struct npr_batch_prepare *p)
{
 int rc=-1;
 e->prepare_active=1;
 for(unsigned tries=0;tries<1024;tries++){
  if(!npr_batch_prepare_current(p)){errno=ECANCELED;break;}
  if(!npr_window_take(e)){rc=0;break;}
  if(errno!=EAGAIN)break;
  for(struct npr_cq_entry *cq=p->ce->cqs;cq;cq=cq->next){
   if(npr_drain_cq(p->ce,cq)){errno=EIO;goto out;}
   if(!npr_batch_prepare_current(p)){errno=ECANCELED;goto out;}
  }
  if(!npr_batch_prepare_current(p)){errno=ECANCELED;break;}
  if(!npr_window_take(e)){rc=0;break;}
  if(errno!=EAGAIN)break;
  if(tries+1<1024){
   unsigned depth=npr_progress_wait_begin();usleep(10);npr_progress_wait_end(depth);
  }
 }
out:
 e->prepare_active=0;
 return rc;
}
static int npr_batch_prepare_pin(void *opaque,const struct mr_entry *m,uint64_t va,uint64_t len)
{
 struct npr_batch_prepare *p=opaque;
 if(!npr_batch_prepare_current(p)){errno=ECANCELED;return -1;}
 if(!p->candidate){
  struct npr_inflight *t=npr_if_alloc(p->ce,p->qs);
  if(!t)return -1;
  p->candidate=t;t->op=*p->op;
  if(t->op.rdv_owner)npr_rdv_source_data_hold(t->op.rdv_owner);
  npr_order_get(t->op.order);t->op.signaled=1;t->visible=0;
  if(!npr_batch_prepare_current(p)){errno=ECANCELED;return -1;}
 }
 return npr_prehold_pin_inflight(p->candidate,m,va,len);
}
static void npr_qp_state_borrow_end(struct npr_qp_state **q)
{assert((*q)->lifecycle_refs);(*q)->lifecycle_refs--;}
static int npr_batch_prepare_return(struct npr_qp_state *q,int rc)
{assert(q->lifecycle_refs);q->lifecycle_refs--;return rc;}
static int npr_batch_add(struct npr_ctx_entry *ce, struct npr_qp_state *qs,
			   const struct npr_op *op)
{
 qs->lifecycle_refs++;
 if(ce->closing||qs->closing||qs->dead){errno=ECANCELED;return npr_batch_prepare_return(qs,-1);}
 if(qs->batch_drop_pending||qs->batch_closing) return npr_batch_prepare_return(qs,0);
	struct npr_batch *b = &qs->bat;
	struct npr_batch_pool *bp;
 struct npr_batch_prepare prepare={.ce=ce,.qs=qs,.op=op,.generation=npr_identity_qp_generation(qs->qp)};
 uint64_t revision;
	uint64_t base, off, me, ne;
	char *shadow;

	if (b->n_ops && b->rkey != op->rkey) {
		npr_batch_close(ce, qs, 0, NULL);
  if(npr_batch_image_wait(ce,qs)) goto pass;
		npr_stat_inc(NPR_STAT_BATCH_SPLIT);
	}
	if (b->n_ops && !npr_batch_fits(b, op->remote_addr, op->len)) {
		npr_batch_close(ce, qs, 0, NULL);
  if(npr_batch_image_wait(ce,qs)) goto pass;
		npr_stat_inc(NPR_STAT_BATCH_SPLIT);
	}
	if (!b->n_ops && npr_batch_image_wait(ce, qs))
		goto pass;
	bp = npr_batch_pool_get(qs);
	if (!bp || !bp->mr || !bp->base)
		goto pass;

	if (!op->len)
		goto pass;
 if(!npr_batch_prepare_current(&prepare)){errno=ECANCELED;return npr_batch_prepare_return(qs,-1);}
	/* The delivery invariant: the member's source face is judged even
	 * though the batch has no sink snapshot: a sentinel-mapped source page would ship 0xDEADBEEF as
	 * the payload while the readback compares against the same-member
	 * accounting. A required PIN is owned by an independent inflight before
	 * the call can yield; it never belongs to the mutable batch state.
	 * A member whose source is absent cannot ride the batch - its mirror copy
	 * would be sentinel bytes and every comparison would agree with them - so
	 * the batch closes in place (order) and the member is carried bilaterally
	 * instead (the member is carried, not compared). */
	/* A member whose expected bytes are the sentinel pattern cannot ride the
	 * batch either: the batch's whole judgement is the readback comparison, and
	 * such a member compares equal to its own drop. The scan needs no hold,
	 * so it runs before the pre-check: release the open batch in place (its
	 * verification window is ordered before the carrier by npr_drain_qp_until)
	 * and carry the member, keeping its unsignaled attribute. */
	if (npr_write_ambiguous(op)) {
		struct npr_inflight *t;

		npr_stat_inc(NPR_STAT_CARRIER_AMBIGUOUS_BATCH);
		npr_batch_close(ce, qs, 0, NULL);
  if(npr_batch_image_wait(ce,qs)) goto pass;
		t = npr_if_alloc(ce, qs);
		if (!t)
			goto pass;
		t->op = *op;
 if(t->op.rdv_owner)npr_rdv_source_data_hold(t->op.rdv_owner);
		npr_order_get(t->op.order);
		t->op.signaled = 1;
		t->visible = 0;
		if (!npr_batch_prepare_current(&prepare) || !t->op.exp.data_rkey || npr_carrier_write(ce, t)) {
			/* no carrier channel, or the carrier failed: either way nothing
			 * verifiable is carried, and the member has no WC to say so */
			npr_carrier_fail_invisible(qs);
			npr_if_release(t);
			return npr_batch_prepare_return(qs,1);
		}
		npr_if_release(t);
		return npr_batch_prepare_return(qs,1);
	}
 revision=b->revision;
 {
  struct npr_preholder h={.pin=npr_batch_prepare_pin,.ctx=&prepare};
  int absent=0;
  int rc=npr_precheck(op,&h,&absent);
  if(prepare.candidate){
   struct npr_inflight *t=prepare.candidate;
   if(rc||!absent||!npr_batch_prepare_current(&prepare)){
    npr_carrier_fail_invisible(qs);npr_if_release(t);return npr_batch_prepare_return(qs,1);
   }
   npr_batch_close(ce,qs,0,NULL);
   if(npr_batch_image_wait(ce,qs)||!npr_batch_prepare_current(&prepare)||
      !t->op.exp.data_rkey||npr_bilateral_run(ce,t))npr_carrier_fail_invisible(qs);
   npr_if_release(t);return npr_batch_prepare_return(qs,1);
  }
  if(!npr_batch_prepare_current(&prepare)){errno=ECANCELED;return npr_batch_prepare_return(qs,-1);}
  if(rc)goto pass;
 }
 if(qs->bat_busy||qs->batch_closing||qs->batch_drop_pending||
    b->revision!=revision||revision==UINT64_MAX||
    (b->n_ops&&b->rkey!=op->rkey)||!npr_batch_fits(b,op->remote_addr,op->len))goto pass;

	shadow = (char *)bp->base;
	base = b->n_ops ? b->base :
			   npr_batch_base_of(op->remote_addr, op->exp.addr);
	if (op->remote_addr < base)
		goto pass;
	off = op->remote_addr - base;
	if (off + op->len > (uint64_t)NPRDMA_BATCH_SPAN)
		goto pass;

	if(npr_sg_copy(op,0,shadow+off,(size_t)op->len,0))goto pass;

	if (npr_emit_owned(ce, qs->qp, op,NPR_ID_BATCH_MEMBER,qs)) {
		npr_batch_drop(qs);
		goto pass;
	}
	if (!b->n_ops) {
		b->exp = op->exp;
		b->rkey = op->rkey;
		npr_stat_inc(NPR_STAT_BATCH_OPEN);
	}

	npr_order_get(op->order);
	b->members[b->n_ops].order=op->order;
	b->members[b->n_ops].remote_addr = op->remote_addr;
	b->members[b->n_ops].len = (uint32_t)op->len;
	b->members[b->n_ops].rkey = op->rkey;
	me = op->remote_addr + op->len;
	ne = b->n_ops ? b->base + b->span : base;
	b->base = base;
	if (me > ne)
		ne = me;
	b->span = ne - base;
	b->bytes += op->len;
	b->n_ops++;
 npr_order_batch_member_set(op->order,1);
 b->revision++;
	npr_stat_inc(NPR_STAT_BATCH_OPS);
	npr_stat_add(NPR_STAT_BATCH_BYTES, op->len);
	if (debug_on())
		fprintf(stderr,
			"[nprdma] batch member len=%llu addr=0x%llx (n=%u span=%llu bytes=%llu)\n",
			(unsigned long long)op->len,
			(unsigned long long)op->remote_addr, b->n_ops,
			(unsigned long long)b->span,
			(unsigned long long)b->bytes);
	return npr_batch_prepare_return(qs,1);
pass:
	npr_stat_inc(NPR_STAT_PASS_BATCH_UNAVAILABLE);
	return npr_batch_prepare_return(qs,0);
}

NPRDMA_INTERNAL int npr_batch_write_barrier(struct npr_ctx_entry *ce,
					    struct ibv_qp *qp,
					    uint64_t addr, uint64_t len)
{
	struct npr_qp_state *qs;
	struct npr_batch *b;

	if (!ce || !qp || !len)
		return 0;
	qs = npr_qp_get(ce, qp);
	if (!qs)
		return 0;
	b = &qs->bat;
	if (!npr_batch_pending(qs))
		return 0;
	if (b->n_ops && addr < b->base + b->span && addr + len > b->base) {
		npr_stat_inc(NPR_STAT_BATCH_WRITE_BARRIER);
		npr_batch_close(ce, qs, 0, NULL);
	}
 if(qs->bat_busy || qs->batch_drop_pending || qs->batch_closing ||
    (b->n_ops && addr<b->base+b->span && addr+len>b->base))
  return npr_batch_image_wait(ce,qs);
 return 0;
}

static uint64_t npr_seqlock_base(const struct npr_inflight *e);
static unsigned long npr_op_pages(const struct npr_op *op);

static int npr_seqlock_version_emit(struct npr_ctx_entry *ce,
				    struct npr_inflight *e, int second)
{
	unsigned slot = second ? e->aux2_slot : e->aux_slot;
	const char *dst = npr_window_addr(e->pool, slot);
	unsigned long np = npr_op_pages(&e->op);
	struct npr_op aux;

	if (!dst || !e->pool || !e->pool->mr || !e->op.exp.v_rkey ||
	    np > NPR_DETECT_PAGES_MAX || np > NPR_WINDOW_SLOT_SIZE / sizeof(uint32_t))
		return -1;
	memset(&aux, 0, sizeof(aux));
	aux.kind = NPR_OP_READ;
	aux.remote_addr = npr_seqlock_base(e);
	aux.rkey = e->op.exp.v_rkey;
	aux.num_sge = 1;
	aux.sge[0].addr = (uint64_t)(uintptr_t)dst;
	aux.sge[0].length = (uint32_t)(np * 4);
	aux.sge[0].lkey = e->pool->mr->lkey;
	aux.len = np * 4;
	aux.signaled = 1;
	if (npr_emit_owned(ce, e->qp, &aux,NPR_ID_AUX,e)) {
		return -1;
	}
	return 0;
}

static uint64_t npr_seqlock_base(const struct npr_inflight *e)
{
	uint64_t off = e->op.remote_addr - e->op.exp.addr;

	return e->op.exp.v_addr + (off / SYMRDMA_PAGE_SIZE) * 4;
}

static int npr_seqlock_refresh(struct npr_ctx_entry *ce, struct npr_inflight *e)
{
	struct npr_cq_entry *cqe = npr_cq_get(ce, e->send_cq);
	int spins = 0;

	e->aux_done = e->aux_ok = 0;
	e->aux2_done = e->aux2_ok = 0;
	if (npr_seqlock_version_emit(ce, e, 0) ||
	    npr_seqlock_version_emit(ce, e, 1))
		return -1;
	while (!(e->aux_done && e->aux2_done)) {
		if (!cqe || npr_drain_cq(ce, cqe))
			return -1;
		if (e->aux_done && e->aux2_done)
			break;
		if (++spins > NPR_POLL_SPIN_MAX)
			return -1;
		{ unsigned depth=npr_progress_wait_begin();usleep(NPR_POLL_SLEEP_US);npr_progress_wait_end(depth); }
	}
	return (e->aux_ok && e->aux2_ok) ? 0 : -1;
}

static int npr_aux_emit(struct npr_ctx_entry *ce, struct npr_inflight *t)
{
	const char *dst = npr_window_addr(t->pool, t->aux_slot);
	struct npr_op aux;

	if (!t->op.exp.data_rkey || !dst || !t->pool || !t->pool->mr)
		return -1;
	memset(&aux, 0, sizeof(aux));
	aux.kind = NPR_OP_READ;
	aux.remote_addr = t->op.remote_addr;
	aux.rkey = t->op.exp.data_rkey;
	aux.num_sge = 1;
	aux.sge[0].addr = (uint64_t)(uintptr_t)dst;
	aux.sge[0].length = (uint32_t)t->op.len;
	aux.sge[0].lkey = t->pool->mr->lkey;
	aux.len = t->op.len;
	aux.signaled = 1;

	if (npr_emit_owned(ce, t->qp, &aux,NPR_ID_AUX,t)) {
		return -1;
	}
	t->aux_want = 1;
	return 0;
}

static void npr_aux_degrade(struct npr_inflight *t)
{
	t->aux_want = 1;
	t->aux_done = 1;
	t->aux_ok = 0;
	npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
}

static void __attribute__((noinline))
npr_fail_closed(struct npr_inflight *e, const char *what)
{
	char line[192];
	size_t o = (size_t)snprintf(line, sizeof(line), "[nprdma] ");

	o = npr_bnd_add(line, sizeof(line), o, what, 64);
	if (!e->visible && !e->op.order)
		snprintf(line + o, sizeof(line) - o,
			 "— repair exhausted, fail-closed: unsignaled reads have no reporting channel,"
			 "receive-buffer data is untrustworthy (swallow the CQE to keep completion counting)\n");
	else
		snprintf(line + o, sizeof(line) - o,
			 "— repair exhausted, fail-closed: deliver an error WC"
			 "(never deliver sentinel data as SUCCESS / silently drop writes)\n");
	npr_log_emit_buf(line, strnlen(line, sizeof(line)));
	if (e->visible || e->op.order)
		e->wc.status = IBV_WC_GENERAL_ERR;
}


/* The engine's holder: the inflight's bounded pre-pin array, released by
 * npr_if_release (the single funnel for every submit failure exit and every
 * delivery exit). */
static int npr_prehold_pin_inflight(void *ctx, const struct mr_entry *m,
				    uint64_t va, uint64_t len)
{
	struct npr_inflight *t = ctx;

	if (t->pre_pin_n >= NPR_PREHOLD_MAX)
		return -1;
 unsigned index=t->pre_pin_n++;
 if(npr_prehold_pin(&t->pre_pin[index],m,va,len)){t->pre_pin_n--;return -1;}
	return 0;
}

static int npr_prehold_covers(const struct npr_inflight *e,
			      const struct mr_entry *m, uint64_t va, uint64_t len)
{
	unsigned i;

	for (i = 0; i < e->pre_pin_n; i++)
		if (e->pre_pin[i].pinned && e->pre_pin[i].mr == m && e->pre_pin[i].va <= va &&
		    va + len <= e->pre_pin[i].va + e->pre_pin[i].len)
			return 1;
	return 0;
}

/* The carrier lane reads the write source as the application's live buffer (the
 * optimistic lane snapshots it into a window; the carrier lane never does), so
 * the source has to be held for the whole carrier window. A version parity that
 * happens to be odd is an observation, not a hold. A hold the pre-check already
 * took is reused: one PIN, one UNPIN, one count. */
static int npr_source_hold(struct npr_inflight *t)
{
 if(t->op.inline_)return 0;
 for(unsigned i=0;i<t->op.num_sge;i++) {
  const struct mr_entry *m;
  if(!t->op.sge[i].length)continue;
  m=npr_mr_for_op(&t->op,i);
  if(!m)return -1;
  if(!npr_prehold_covers(t,m,t->op.sge[i].addr,t->op.sge[i].length)&&
     npr_prehold_pin_inflight(t,m,t->op.sge[i].addr,t->op.sge[i].length))return -1;
 }
 return 0;
}

/* The sentinel sample is in logical remote-byte order, including SGE joins. */
static int npr_write_ambiguous(const struct npr_op *op)
{
 unsigned char expected[NPR_SMALL_DATA_MAX];
 if(!npr_op_is_write(op)||!op->len||op->len>NPR_SMALL_DATA_MAX)return 0;
 if(npr_sg_copy(op,0,expected,(size_t)op->len,0))return 1;
 return detect_write_ambiguous(expected,(size_t)op->len,op->remote_addr);
}

/* An invisible carrier has no WC of its own, so its failure would otherwise be a
 * log line nobody reads: it is recorded on the QP and the next signaled
 * completion on that QP reports it, once, fail-closed. The counters keep the fact
 * visible even when the application never posts again. */
static void npr_carrier_fail_invisible(struct npr_qp_state *qs)
{
	qs->sticky_err = 1;
	npr_stat_inc(NPR_STAT_CARRIER_STICKY_ERR);
	npr_log_emit("[nprdma] an unsignaled carrier on this QP failed — the next signaled completion reports it\n");
}

/* The carrier lane's second trigger (the pre-check route): the pre-check
 * found a face absent, or the expected bytes collide with the sentinel sample so
 * the readback lane cannot prove landing. Returns 0 when the carrier landed. */
static int npr_carrier_write(struct npr_ctx_entry *ce, struct npr_inflight *t)
{
	return npr_bilateral_run(ce, t);
}

/* Local sink face. A read's receive buffer is a SymRDMA MR too; while
 * its read IOVA sits on the sentinel page the NIC's write is dropped and the
 * buffer keeps its old bytes - a successful CQE over wrong data. Two facts make
 * that observable: the page sits on the sentinel mapping at delivery (parity
 * even), or it transitioned inside the op window (the DMA may already have been
 * dropped although the page is back). Both are judged on the full 32-bit gen.
 */
static void npr_local_snapshot(struct npr_inflight *e)
{
 e->l1_np=0;e->l1_bad=0;
 memset(e->l1_seg_np,0,sizeof(e->l1_seg_np));
 if(!npr_op_is_read(&e->op))return;
 for(unsigned j=0;j<e->op.num_sge;j++) {
  const struct npr_sge *sg=&e->op.sge[j];
  const struct mr_entry *m;
  unsigned long np;
  if(!sg->length)continue;
  m=npr_mr_for_op(&e->op,j);if(!m)continue;
  np=(sg->addr%SYMRDMA_PAGE_SIZE+sg->length+SYMRDMA_PAGE_SIZE-1)/SYMRDMA_PAGE_SIZE;
  if(np>NPR_SINK_SNAP_PAGES-e->l1_np||
     npr_version_read_mr(m,sg->addr,e->l1_snap+e->l1_np,np)){
   e->l1_bad=1;return;
  }
  if(npr_prehold_covers(e,m,sg->addr,sg->length)) {
   for(unsigned long k=0;k<np;k++)if(!(e->l1_snap[e->l1_np+k]&1u)){
    npr_stat_inc(NPR_STAT_PRE_SNAP_ORDER);e->l1_bad=1;return;
   }
  }
  e->l1_seg_np[j]=(unsigned)np;e->l1_np+=np;
 }
}

static int npr_local_sink_detect(struct npr_inflight *e,unsigned long np,uint8_t *miss)
{
 uint32_t v2[NPR_SINK_SNAP_PAGES];
 unsigned long snap=0,absent=0,changed=0;
 uint64_t logical=0;
 if(!npr_op_is_read(&e->op))return 0;
 if(e->l1_bad)return -1;
 for(unsigned j=0;j<e->op.num_sge;j++) {
  const struct npr_sge *sg=&e->op.sge[j];
  unsigned long count=e->l1_seg_np[j];
  if(count) {
   const struct mr_entry *m=npr_mr_for_op(&e->op,j);
   uint64_t remote=e->op.remote_addr+logical;
   unsigned long first=(remote/SYMRDMA_PAGE_SIZE)-(e->op.remote_addr/SYMRDMA_PAGE_SIZE);
   if(!m||first>=np||count>NPR_SINK_SNAP_PAGES-snap||
      npr_version_read_mr(m,sg->addr,v2,count))return -1;
   detect_local_sink_pages(e->l1_snap+snap,v2,count,sg->addr%SYMRDMA_PAGE_SIZE,
       remote%SYMRDMA_PAGE_SIZE,sg->length,np-first,miss+first,&absent,&changed);
   snap+=count;
  }
  logical+=sg->length;
 }
 if(absent)npr_stat_add(NPR_STAT_LOCAL_SINK_ABSENT,absent);
 if(changed)npr_stat_add(NPR_STAT_LOCAL_SINK_CHANGED,changed);
 return 0;
}

/* Evidence line for the delivery decision (debug only). "clean" is silent in the
 * counters, so a delivery that was never really checked and one that was checked
 * and found fine are indistinguishable without this line. */
static void npr_dbg_verdict(const char *lane, const struct npr_inflight *e,
			    unsigned long np, const uint32_t *v1,
			    const uint32_t *v2, const uint8_t *miss,
			    int verdict, int have_v)
{
	char line[256];
	size_t o;
	unsigned long p;

	if (!debug_on())
		return;
	o = (size_t)snprintf(line, sizeof(line),
			     "[nprdma] detect lane=%s off=%llu len=%u np=%lu have_v=%d ",
			     lane, (unsigned long long)e->op.remote_addr,
			     (unsigned)e->op.len, np, have_v);
	for (p = 0; p < np && p < 4 && o < sizeof(line) - 24; p++)
		o += (size_t)snprintf(line + o, sizeof(line) - o,
				      "v%lu=%08x/%08x ", p,
				      v1 ? v1[p] : 0, v2 ? v2[p] : 0);
	if (miss && o < sizeof(line) - 16)
		o += (size_t)snprintf(line + o, sizeof(line) - o, "miss=%d%d%d%d ",
				      miss[0], np > 1 ? miss[1] : 0,
				      np > 2 ? miss[2] : 0, np > 3 ? miss[3] : 0);
	if (o >= sizeof(line) - 12)
		o = sizeof(line) - 12;
	snprintf(line + o, sizeof(line) - o, "verdict=%d\n", verdict);
	npr_log_emit_buf(line, strnlen(line, sizeof(line)));
}

static repair_verdict npr_read_detect(void *udp, uint8_t *page_missing,
				      int attempt)
{
	struct npr_policy_ud *u = udp;
	struct npr_inflight *t = u->t;
 (void)attempt;
 if(u->read_carried){memset(page_missing,0,u->np);return REPAIR_VERDICT_CLEAN;}
 memset(page_missing,0,u->np);
 uint64_t logical=0;
 for(unsigned j=0;j<t->op.num_sge;j++) {
  const struct npr_sge *sg=&t->op.sge[j];
  uint64_t remote=t->op.remote_addr+logical;
  unsigned long first=remote/SYMRDMA_PAGE_SIZE-t->op.remote_addr/SYMRDMA_PAGE_SIZE;
  if(sg->length)detect_sentinel_pages((const void *)(uintptr_t)sg->addr,
       remote-remote%SYMRDMA_PAGE_SIZE,remote%SYMRDMA_PAGE_SIZE,sg->length,
       u->np-first,page_missing+first,1);
  logical+=sg->length;
 }
	{
		repair_verdict rv;

		if (npr_local_sink_detect(t, u->np, page_missing)) {
			npr_dbg_verdict("read-unavail", t, u->np, NULL,
					NULL, page_missing,
					REPAIR_VERDICT_UNAVAILABLE, 0);
			return REPAIR_VERDICT_UNAVAILABLE;
		}
		rv = detect_any_missing(page_missing, u->np) ?
		     REPAIR_VERDICT_MISSING : REPAIR_VERDICT_CLEAN;
		if (rv == REPAIR_VERDICT_MISSING) {
			/* Resolve the entire small read, including legitimate sentinel
			 * collisions, with the held carrier rather than a content retry. */
			memset(page_missing, 1, u->np);
			u->read_repair_all = 1;
		}
		npr_dbg_verdict("read", t, u->np, NULL, NULL,
				page_missing, (int)rv, 0);
		return rv;
	}
}

static int npr_write_refresh(struct npr_ctx_entry *ce, struct npr_inflight *e)
{
	struct npr_cq_entry *cqe = npr_cq_get(ce, e->send_cq);
	int spins = 0;

	e->aux_done = 0;
	e->aux_ok = 0;
	if (npr_aux_emit(ce, e))
		return -1;
	while (!e->aux_done) {
		if (!cqe || npr_drain_cq(ce, cqe))
			return -1;
		if (e->aux_done)
			break;
		if (++spins > NPR_POLL_SPIN_MAX)
			return -1;
		{ unsigned depth=npr_progress_wait_begin();usleep(NPR_POLL_SLEEP_US);npr_progress_wait_end(depth); }
	}
	return e->aux_ok ? 0 : -1;
}

static repair_verdict npr_write_detect(void *udp, uint8_t *page_missing,
				       int attempt)
{
	struct npr_policy_ud *u = udp;
	struct npr_inflight *t = u->t;
	const char *dst = npr_window_addr(t->pool, t->aux_slot);
	const char *src = npr_window_addr(t->pool, t->src_slot);

	if (attempt > 0 && npr_write_refresh(u->ce, t))
		return REPAIR_VERDICT_UNAVAILABLE;
	if (!dst || !src)
		return REPAIR_VERDICT_UNAVAILABLE;
	detect_memcmp_pages(dst, src, t->op.remote_addr % SYMRDMA_PAGE_SIZE,
			    t->op.len, u->np, page_missing, 0);
	return detect_any_missing(page_missing, u->np) ?
	       REPAIR_VERDICT_MISSING : REPAIR_VERDICT_CLEAN;
}

static repair_verdict npr_seqlock_detect(void *udp, uint8_t *page_missing,
					 int attempt)
{
	struct npr_policy_ud *u = udp;
	struct npr_inflight *e = u->t;
	const uint32_t *v1;
	const uint32_t *v2;

	if (attempt > 0 && npr_seqlock_refresh(u->ce, e))
		return REPAIR_VERDICT_UNAVAILABLE;
	v1 = (const uint32_t *)npr_window_addr(e->pool, e->aux_slot);
	v2 = (const uint32_t *)npr_window_addr(e->pool, e->aux2_slot);
	if (!e->aux_ok || !e->aux2_ok || !v1 || !v2) {
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		return REPAIR_VERDICT_UNAVAILABLE;
	}
	detect_versions_changed(v1, v2, u->np, page_missing, 0);
	if (npr_local_sink_detect(e, u->np, page_missing)) {
		npr_dbg_verdict("seqlock-unavail", e, u->np, v1, v2,
				page_missing, REPAIR_VERDICT_UNAVAILABLE, 1);
		return REPAIR_VERDICT_UNAVAILABLE;
	}
	{
		repair_verdict rv = detect_any_missing(page_missing, u->np) ?
				    REPAIR_VERDICT_MISSING : REPAIR_VERDICT_CLEAN;

		npr_dbg_verdict("seqlock", e, u->np, v1, v2, page_missing,
				(int)rv, 1);
		return rv;
	}
}

/* SGE boundaries are remote-address boundaries for reverse RDMA. Submit
 * bounded span batches under one original inflight owner; no extra app CQEs. */
static int npr_repair_batch(struct npr_inflight *t,
                             struct sir_repair_span *parts,unsigned count,
                             uint64_t *leases)
{
 uint8_t status[SIR_REPAIR_BATCH_MAX];
 int rc=npr_wait_repair_batch(t->op.rkey,parts,count,status),saved=errno;
 for(unsigned i=0;i<count;i++)if(leases[i])creg_lease_put(leases[i]);
 errno=saved;return rc;
}
static int npr_policy_repair(void *udp,struct sir_repair_span *spans,uint32_t n)
{
 struct npr_policy_ud *u=udp;
 struct npr_inflight *t=u->t;
 struct sir_repair_span parts[SIR_REPAIR_BATCH_MAX];
 uint64_t leases[SIR_REPAIR_BATCH_MAX]={0};
 unsigned count=0,start=t->pre_pin_n;
 int rc=-1,saved;
 if(npr_fault_repair_fail()){errno=EIO;return -1;}
 if(!n||n>SIR_REPAIR_BATCH_MAX){errno=EINVAL;return -1;}
 /* One local hold contract for one or many SGEs: a reverse READ consumes
  * the write source, a reverse WRITE fills the read sink. Resident parity
  * is not a hold. Foreign native MRs are already provider-pinned. */
 if(!t->op.inline_)for(unsigned j=0;j<t->op.num_sge;j++) {
  const struct npr_sge *sg=&t->op.sge[j];
  const struct mr_entry *m=npr_mr_for_op(&t->op,j);
  if(!sg->length||!m||npr_prehold_covers(t,m,sg->addr,sg->length))continue;
  if(npr_prehold_pin_inflight(t,m,sg->addr,sg->length)){
   npr_stat_inc(npr_op_is_read(&t->op)?NPR_STAT_LOCAL_SINK_PIN_FAIL:NPR_STAT_CARRIER_SOURCE_PIN_FAIL);errno=EIO;goto out;
  }
 }
 /* The inline optimization depends on logical length/page bounds, not
  * descriptor count. Gather/scatter only the logical tail; a small write's
  * existing snapshot remains its expected data source. */
 uint64_t first=t->op.exp.addr+spans[0].page_idx*SYMRDMA_PAGE_SIZE+spans[0].xoff;
 if(first<t->op.remote_addr||first-t->op.remote_addr>=t->op.len){errno=EINVAL;goto out;}
 uint64_t off=first-t->op.remote_addr;
 if(t->op.len<=NPR_SMALL_DATA_MAX&&npr_inline_repair_ok(t,(uint32_t)off)){
  unsigned char data[NPR_SMALL_DATA_MAX];
  size_t length=(size_t)(t->op.len-off);
  memset(data,0,length);
  if(npr_op_is_write(&t->op)){
   const char *snapshot=npr_window_addr(t->pool,t->src_slot);
   if(snapshot)memcpy(data,snapshot+off,length);
   else if(npr_sg_copy(&t->op,off,data,length,0)){errno=EINVAL;goto out;}
  }
  rc=npr_wait_repair(t->op.rkey,spans[0].page_idx,(int)spans[0].dir,
    (uint32_t)(first%SYMRDMA_PAGE_SIZE),(uint32_t)length,data);
  if(!rc&&npr_op_is_read(&t->op)&&npr_sg_copy(&t->op,off,data,length,1)){rc=-1;errno=EINVAL;}
  goto out;
 }
 for(unsigned i=0;i<n;i++) {
  uint64_t remote=t->op.exp.addr+spans[i].page_idx*SYMRDMA_PAGE_SIZE+spans[i].xoff;
  uint64_t remaining=spans[i].xlen;
  if(remote<t->op.remote_addr||remote-t->op.remote_addr>t->op.len||
     remaining>t->op.len-(remote-t->op.remote_addr)){errno=EINVAL;goto out;}
  while(remaining) {
   struct npr_sg_slice sg;
   struct sir_repair_span *part=&parts[count];
   struct creg_initiator_view view;
   uint32_t key;
   if(npr_sg_at(&t->op,remote-t->op.remote_addr,remaining,&sg)){errno=EINVAL;goto out;}
   memset(part,0,sizeof(*part));leases[count]=0;
   if(t->op.local_mr[sg.index]) {
    if(npr_data_rkey_owned(&t->op,sg.index,npr_op_is_read(&t->op),&key)){
     errno=EACCES;goto out;
    }
   }else{
    if(creg_initiator_acquire(sg.addr,sg.length,&view,&leases[count])){
     errno=EINVAL;goto out;
    }
    key=view.rkey;
    (void)npr_data_rkey_owned(&t->op,sg.index,npr_op_is_read(&t->op),&key);
   }
   part->page_idx=(remote-t->op.exp.addr)/SYMRDMA_PAGE_SIZE;
   part->xoff=(uint32_t)((remote-t->op.exp.addr)%SYMRDMA_PAGE_SIZE);
   part->npages=(uint32_t)((part->xoff+sg.length+SYMRDMA_PAGE_SIZE-1)/SYMRDMA_PAGE_SIZE);
   part->dir=spans[i].dir;part->xaddr=sg.addr;part->xrkey=key;part->xlen=(uint32_t)sg.length;
   count++;remote+=sg.length;remaining-=sg.length;
   if(count==SIR_REPAIR_BATCH_MAX) {
    rc=npr_repair_batch(t,parts,count,leases);count=0;
    if(rc)goto out;
   }
  }
 }
 rc=count?npr_repair_batch(t,parts,count,leases):0;count=0;
 out:
 saved=errno;
 for(unsigned i=0;i<count;i++)if(leases[i])creg_lease_put(leases[i]);
 /* UNPIN observation belongs to each actual sink owner. A failed release
  * remains on the inflight for the existing retry/terminal cleanup funnel. */
 for(unsigned j=t->pre_pin_n;j>start;j--) {
  struct npr_prehold *hold=&t->pre_pin[j-1];
  unsigned long transitions=0;int released=0;
  hold->pinning=1;
  int urc=npr_local_unpin_observed(hold->mr,hold->va,hold->len,&transitions,&released);
  hold->pinning=0;
  if(released){hold->pinned=0;(void)npr_prehold_release(hold);}
  if(urc){rc=-1;saved=EIO;npr_stat_inc(NPR_STAT_LOCAL_SINK_PIN_FAIL);}
  if(transitions){rc=-1;saved=EAGAIN;npr_stat_add(NPR_STAT_LOCAL_SINK_TRANSITION,transitions);}
 }
 while(t->pre_pin_n>start&&!t->pre_pin[t->pre_pin_n-1].pinned&&
       !t->pre_pin[t->pre_pin_n-1].mr_ref)t->pre_pin_n--;
 if(!rc&&u->read_repair_all)u->read_carried=1;
 errno=saved;return rc;
}

static void npr_policy_escalate(void *udp, int why)
{
	struct npr_policy_ud *u = udp;
	const char *what;

	if (why == REPAIR_POLICY_ESC_BUDGET)
		what = npr_op_is_read(&u->t->op) ? "still missing after 3 repair attempts (read)"
						 : "write repair never landed after 3 attempts";
	else
		what = npr_op_is_read(&u->t->op) ? "SIR repair failed (read)"
						 : "SIR write repair failed";
	(void)u->cqe;
	npr_fail_closed(u->t, what);
}

static int npr_wwi_send(struct npr_ctx_entry *ce, struct npr_inflight *t)
{
	struct npr_op nop = t->op;

	nop.kind = NPR_OP_WRITE_IMM;
	nop.imm = t->imm;
	nop.signaled = 1;
	nop.inline_ = 0;
	nop.flags = 0;
	if (npr_emit_owned(ce,t->qp,&nop,NPR_ID_NOTIFY,t)) {
		fprintf(stderr,
			"[nprdma] WWI WRITE_WITH_IMM submit failed errno=%d — imm not delivered (QP broken?)\n",
			errno);
		return -1;
	}
	t->notify_pending = 1;
	if (debug_on())
		fprintf(stderr,
			"[nprdma] WWI imm=0x%08x len=%llu sent (WRITE_WITH_IMM idempotent notification, target side RECV_RDMA_WITH_IMM)\n",
			be32toh(t->imm), (unsigned long long)t->op.len);
	return 0;
}

static int npr_inline_repair_ok(const struct npr_inflight *t, uint32_t miss_off)
{
	return !npr_fault_repair_fail() &&
	       t->op.len <= (uint32_t)sir_inline_max() &&
	       (uint32_t)((t->op.remote_addr + miss_off) &
			  (SYMRDMA_PAGE_SIZE - 1)) +
		       (t->op.len - miss_off) <= SYMRDMA_PAGE_SIZE;
}

static int npr_detect_domain_get(struct npr_detect_domain *dom,
				 unsigned long np)
{
	dom->np = (unsigned)np;
	dom->heap = NULL;
	dom->miss = dom->miss_inline;
	if (np <= NPR_DETECT_INLINE_PAGES)
		return 0;
	if (np > NPR_DETECT_PAGES_MAX)
		return -1;
	dom->heap = malloc(np);
	if (!dom->heap)
		return -1;
	dom->miss = dom->heap;
	return 0;
}

static void npr_detect_domain_put(struct npr_detect_domain *dom)
{
	free(dom->heap);
	dom->heap = NULL;
	dom->miss = dom->miss_inline;
	dom->np = 0;
}

static unsigned long npr_op_pages(const struct npr_op *op)
{
	uint64_t offset = op->remote_addr % SYMRDMA_PAGE_SIZE;
	if (op->len > UINT64_MAX - offset - (SYMRDMA_PAGE_SIZE - 1))
		return NPR_DETECT_PAGES_MAX + 1;
	return (unsigned long)((offset + op->len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE);
}

/* ---- the bilateral lane ----------------------------------------------------
 *
 * A pre-check that found a local face absent routes the op here instead of
 * emitting it. The op's bytes are moved by the carrier facet (the initiator
 * holds its side, the owner pins its export range and reverse-writes / reverse-
 * reads), so the application's WC reports the carrier's outcome and never a
 * data-plane completion that was never posted. The delivery criterion is the
 * carrier's WC plus the window held throughout - there is no byte
 * coverage axis, and no data-plane judgement: the op was not on the wire.
 */

struct npr_bilateral_ud {
	struct npr_policy_ud base;
	/* the carrier completed: its write WC landed while the window was held.
	 * Only a completed carrier lets the next judge answer CLEAN - an op that
	 * never reached this flag is still missing (a retried carrier included). */
	int landed;
};

static repair_verdict npr_bilateral_detect(void *udp, uint8_t *page_missing,
					   int attempt)
{
	struct npr_bilateral_ud *u = udp;

	(void)attempt;
	if (u->landed) {
		memset(page_missing, 0, u->base.np);
		return REPAIR_VERDICT_CLEAN;
	}
	memset(page_missing, 1, u->base.np);
	return REPAIR_VERDICT_MISSING;
}

static int npr_bilateral_repair(void *udp, struct sir_repair_span *spans,
				uint32_t n)
{
	struct npr_bilateral_ud *u = udp;
	int rc = npr_policy_repair(udp, spans, n);

	if (!rc)
		u->landed = 1;
	return rc;
}

static void npr_bilateral_wc(const struct npr_inflight *t, struct ibv_wc *wc)
{
	memset(wc, 0, sizeof(*wc));
	wc->wr_id = t->op.wr_id;
	wc->qp_num = t->qp->qp_num;
	wc->status = IBV_WC_SUCCESS;
	wc->opcode = npr_op_is_read(&t->op) ? IBV_WC_RDMA_READ :
					IBV_WC_RDMA_WRITE;
	wc->byte_len = npr_op_is_read(&t->op) ? (uint32_t)t->op.len : 0;
}

/* Both carrier exits, including pre-transfer failures, use one delivery point. */
static int npr_carrier_deliver(struct npr_ctx_entry *ce, struct npr_inflight *t)
{
	struct npr_cq_entry *cqe;

	if (t->op.order) {
		if(t->cover_bad) t->wc.status=IBV_WC_GENERAL_ERR;
		t->delivered=1; /* npr_if_release publishes after resource detach. */
		return 0;
	}
	if (!t->visible)
		return 0;
	if (t->cover_bad)
		t->wc.status = IBV_WC_GENERAL_ERR;
	cqe = npr_cq_get(ce, t->send_cq);
	if (npr_gate_push_wc(cqe, &t->wc))
		return -1;
	t->sticky_claimed = 0;
	t->cover_bad = 0;
	return 0;
}

/* Run the carrier for one op whose local face the pre-check found absent, then
 * deliver exactly one WC (signaled ops only; an unsignaled op never produces
 * one). The caller owns t's pre-check holds - they are released with the
 * inflight, after the carrier, which is the point of holding them. */
static int npr_bilateral_run(struct npr_ctx_entry *ce, struct npr_inflight *t)
{
	struct npr_detect_domain dom;
	struct npr_bilateral_ud u;
	struct sir_repair_span spans[SIR_REPAIR_BATCH_MAX];
	struct repair_policy_ops ops;
	struct repair_policy_cfg cfg;
	unsigned long np = npr_op_pages(&t->op);
	int rc = -1;	/* the failure exit: nothing landed */

	t->bilateral = 1;
	npr_bilateral_wc(t, &t->wc);
	/* Reject before taking ownership when no application completion can be
	 * queued. A drain may fill the gate too, so check again before transfer. */
	if (t->visible && !t->op.order) {
		struct npr_cq_entry *gate = npr_cq_get(ce, t->send_cq);
		if (!gate || npr_gate_full(gate))
			return NPR_CARRIER_REJECTED;
	}

	/* The application's WC order follows its submit order: nothing older
	 * than this op may still be in flight when this completion lands. The
	 * caller allocated t, so "only t is left" is the barrier condition. */
	if (!t->op.order && npr_drain_qp_until(ce, t->qs, t->qs->if_cap - 1)) {
		npr_fail_closed(t, "carrier could not be ordered behind the older in-flight ops");
		goto deliver;
	}

	if (t->visible && !t->op.order && npr_gate_full(npr_cq_get(ce, t->send_cq)))
		return NPR_CARRIER_REJECTED;
	if (npr_op_is_write(&t->op) && npr_source_hold(t)) {
		npr_stat_inc(NPR_STAT_CARRIER_SOURCE_PIN_FAIL);
		npr_fail_closed(t, "carrier: the write source could not be held");
		goto deliver;
	}
	if (npr_detect_domain_get(&dom, np)) {
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		npr_fail_closed(t, "carrier detect domain unavailable");
		goto deliver;
	}
	memset(&u, 0, sizeof(u));
	u.base.ce = ce;
	u.base.t = t;
	u.base.np = np;
	u.base.dom = &dom;
	memset(&ops, 0, sizeof(ops));
	ops.detect = npr_bilateral_detect;
	ops.repair = npr_bilateral_repair;
	ops.escalate = npr_policy_escalate;
	ops.ud = &u;
	memset(&cfg, 0, sizeof(cfg));
	cfg.npages = np;
	cfg.abs_pages = NULL;
	cfg.page0 = t->op.remote_addr / SYMRDMA_PAGE_SIZE;
	cfg.region_base = t->op.exp.addr;
	cfg.op_off = t->op.remote_addr % SYMRDMA_PAGE_SIZE;
	cfg.op_len = t->op.len;
	cfg.dir = npr_op_is_read(&t->op) ? SIR_F_READ : SIR_F_WRITE;
	cfg.page_missing = dom.miss;
	cfg.spans = spans;
	rc = repair_policy_loop(&ops, &cfg);
	if (rc)
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
	if (debug_on())
		fprintf(stderr,
			"[nprdma] carrier lane op=%c rkey=0x%x addr=0x%llx len=%llu rc=%d landed=%d\n",
			npr_op_is_read(&t->op) ? 'R' : 'W', t->op.rkey,
			(unsigned long long)t->op.remote_addr,
			(unsigned long long)t->op.len, rc, u.landed);
	npr_detect_domain_put(&dom);

deliver:
	if(rc && t->op.order) t->wc.status=IBV_WC_GENERAL_ERR;
	if (npr_carrier_deliver(ce, t))
		return NPR_CARRIER_REJECTED;
	/* rc == 0 is only reachable through a completed carrier (the detect facet
	 * answers CLEAN on nothing else): the caller must not claim landing
	 * otherwise, and an invisible carrier's failure rides the QP's sticky
	 * error because it has no WC of its own. */
	return rc == 0 ? 0 : -1;
}

static int npr_if_check(struct npr_ctx_entry *ce, struct npr_cq_entry *cqe,
			 struct npr_inflight *e,int clean_only)
{
	struct npr_detect_domain dom;
	struct npr_policy_ud u;
	struct sir_repair_span spans[SIR_REPAIR_BATCH_MAX];
	int batch = (e->landing == NPR_LANDING_BATCH);
	int read_path = !batch && npr_op_is_read(&e->op);
	unsigned long np = batch ? e->span.np : npr_op_pages(&e->op);
	struct repair_policy_ops ops;
	struct repair_policy_cfg cfg;
	int rc;

	uint8_t clean_missing[NPR_DETECT_PAGES_MAX];
	e->in_check = 1;
    if(clean_only){
     if(np>NPR_DETECT_PAGES_MAX){e->in_check=0;return 0;}
     memset(&dom,0,sizeof(dom));dom.np=(unsigned)np;dom.miss=clean_missing;
     memset(clean_missing,0,(size_t)np);
    }
	if (!clean_only&&npr_detect_domain_get(&dom, np)) {
		/* the delivery judgement could not be taken: an error WC, never a
		 * claim */
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		npr_fail_closed(e, "delivery detect domain unavailable");
		e->in_check = 0;
		e->state = NPR_IF_READY;
		return 1;
	}
	memset(&u, 0, sizeof(u));
	u.cqe = cqe;
	u.ce = ce;
	u.t = e;
	u.np = np;
	u.dom = &dom;
	memset(&ops, 0, sizeof(ops));
	if (batch) {
		ops.detect = npr_batch_detect;
		ops.repair = npr_batch_repair;
		ops.escalate = npr_batch_escalate;
	} else if (e->seqlock)
		ops.detect = npr_seqlock_detect;
	else
		ops.detect = read_path ? npr_read_detect : npr_write_detect;
	if (e->landing != NPR_LANDING_BATCH) {
		ops.repair = npr_policy_repair;
		ops.escalate = npr_policy_escalate;
	}
	ops.ud = &u;
	memset(&cfg, 0, sizeof(cfg));
	cfg.npages = np;
	cfg.abs_pages = NULL;
	cfg.page0 = (batch ? e->span.remote_addr : e->op.remote_addr) /
		    SYMRDMA_PAGE_SIZE;
	cfg.region_base = batch ? e->span.exp.addr : e->op.exp.addr;
	cfg.op_off = (batch ? e->span.remote_addr : e->op.remote_addr) %
		     SYMRDMA_PAGE_SIZE;
	cfg.op_len = batch ? e->span.len : e->op.len;
	cfg.dir = read_path ? SIR_F_READ : SIR_F_WRITE;
	cfg.page_missing = dom.miss;
	cfg.spans = u.spans;

 if(clean_only){
  if(ops.detect(ops.ud,dom.miss,0)!=REPAIR_VERDICT_CLEAN){
   npr_detect_domain_put(&dom);e->in_check=0;return 0;
  }
  rc=0;
 }else rc = repair_policy_loop(&ops, &cfg);
	if (debug_on()) {
		char lbuf[128];
		int ln = snprintf(lbuf, sizeof(lbuf),
				  "[nprdma] if_check rc=%d errno=%d np=%lu len=%u seqlock=%d\n",
				  rc, errno, np, (unsigned)e->op.len,
				  (int)e->seqlock);

		if (ln > 0)
			npr_log_emit_buf(lbuf, (size_t)ln);
	}
	e->in_check = 0;
	npr_detect_domain_put(&dom);

	if (rc == 1) {
		/* the loop reports UNAVAILABLE without escalating (it is not a
		 * failed repair, it is a judgement that could not be taken):
		 * deliver an error WC, never the app's success. A batch routes
		 * through its cover. */
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		if (batch) {
			u.np = np;
			npr_batch_escalate(&u, -1);
		} else {
			npr_fail_closed(e, "delivery judgement unavailable");
		}
	}
	if (rc == 0 && e->is_wwi && npr_wwi_send(ce, e))
		npr_fail_closed(e, "WWI notification submission failed");
	e->state = NPR_IF_READY;
	(void)spans;
 return 1;
}

static void npr_if_finish(struct npr_ctx_entry *ce, struct npr_cq_entry *cqe,
			  struct npr_inflight *e)
{
	if (e->landing == NPR_LANDING_BATCH) {

		if (!e->aux_ok) {
			/* the batch's readback is its only judge: no readback, no
			 * verdict. The failure rides the batch's own routing face so a
			 * covering application op sees an error WC. */
			struct npr_policy_ud bu;

			npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
			memset(&bu, 0, sizeof(bu));
			bu.ce = ce;
			bu.cqe = cqe;
			bu.t = e;
			npr_batch_escalate(&bu, -1);
			e->state = NPR_IF_READY;
			return;
		}
		(void)npr_if_check(ce, cqe, e,0);
		return;
	}

	if (e->cover_bad && e->app_ok) {
		/* The op was the cover of a completion face that has no WC of its own:
		 * the unsignaled write batch this op closed, or an invisible carrier
		 * that ran before it (the cover rule, sticky across the QP). */
		e->cover_bad = 0;
		npr_fail_closed(e, "an unsignaled write this op covers failed verification");
	}
	if (!e->app_ok) {

		fprintf(stderr,
			"[nprdma] QP %u fatal error status=%d — final delivery (leaving tracking)\n",
			e->wc.qp_num, e->wc.status);
		e->state = NPR_IF_READY;

		if (!e->qs->closing && !e->op.order)
			cqe->drift = 1;
		return;
	}
	if (e->seqlock && (!e->aux_ok || !e->aux2_ok)) {
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		npr_fail_closed(e, "seqlock version read unavailable");
		e->state = NPR_IF_READY;
		return;
	}
	if (!e->seqlock && e->aux_want && !e->aux_ok) {
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		npr_fail_closed(e, "write readback unavailable");
		e->state = NPR_IF_READY;
		return;
	}
	(void)npr_if_check(ce, cqe, e,0);
}

static struct npr_inflight *npr_if_alloc(struct npr_ctx_entry *ce,
					 struct npr_qp_state *qs)
{
	unsigned i;

	if (qs->if_n >= qs->if_cap) {
		qs->inflight_barrier++;
		if (npr_drain_qp_until(ce, qs, 1)) {
			qs->if_n = qs->if_n;
		}
		if (qs->if_n >= qs->if_cap)
			return NULL;
	}
	for (i = 0; i < qs->if_cap; i++)
		if (!qs->ifs[i].qs) {
			struct npr_inflight *e = &qs->ifs[i];

			memset(e, 0, sizeof(*e));
			e->qs = qs;
			e->ce = ce;
			e->qp = qs->qp;
			e->send_cq = qs->qp->send_cq;
			e->src_slot = NPR_WINDOW_NONE;
			e->aux_slot = NPR_WINDOW_NONE;
			e->aux2_slot = NPR_WINDOW_NONE;
			qs->if_n++;
			return e;
		}
	return NULL;
}

static int npr_if_complete(const struct npr_inflight *e)
{
	if (e->notify_pending) return e->notify_done;
	if (e->landing == NPR_LANDING_BATCH)
		return e->aux_done;
	return e->item && e->app_done &&
	       (e->seqlock ? (e->aux_done && e->aux2_done) :
		(!e->aux_want || e->aux_done));
}

static void npr_if_release(struct npr_inflight *e)
{
 if(e->prepare_active){e->release_pending=1;return;}
 if(e->native_refs||e->cover_refs) {e->release_pending=1;return;}
 if(e->cleanup_active) return;
 e->cleanup_active=1;
 struct npr_qp_state *qs=e->qs;
 struct npr_inflight *cover=e->landing==NPR_LANDING_BATCH?e->cover:NULL;
 uint64_t progress_ticket=e->progress_ticket;
 unsigned inline_clean=e->inline_clean;
 struct npr_order_entry *owner=e->op.order;
 struct npr_rdv_owner *rdv_data=e->op.rdv_owner;
 struct npr_gate_item *owned_item=owner?NULL:e->item;
 struct npr_order_entry *owners[NPRDMA_BATCH_OPS];
 unsigned n=e->order_batch_n,oi;
 struct ibv_wc wc=e->wc;
 unsigned item_visible=e->visible;
 struct ibv_wc batch_wc={.status=(e->cover_bad || e->state!=NPR_IF_READY)?IBV_WC_GENERAL_ERR:IBV_WC_SUCCESS,.qp_num=qs?qs->qp_num:0};
 if(!e->delivered) wc.status=IBV_WC_GENERAL_ERR;
 memcpy(owners,e->order_batch,n*sizeof(*owners));

	/* A rejected/unqueued request has not reported the earlier invisible error. */
	if (qs && e->sticky_claimed)
		qs->sticky_err = 1;

	/* The pre-check holds: release the PIN, touch nothing else -
	 * the single funnel for every exit (submit failure, delivery, destroy). */
	while (e->pre_pin_n) {
		struct npr_prehold *ph = &e->pre_pin[e->pre_pin_n-1];

		if(npr_prehold_release(ph)) {e->release_pending=1;e->cleanup_active=0;return;}
  e->pre_pin_n--;
	}
	if (e->landing == NPR_LANDING_BATCH) {
  if(e->state!=NPR_IF_READY) npr_stat_inc(NPR_STAT_BATCH_DROPPED);
		if (e->bpool)
			e->bpool->n_runs = 0;
		e->bpool = NULL;
		e->cover = NULL;
		if (qs)
			qs->bat_busy = 0;
		memset(e, 0, sizeof(*e));
		if (qs && qs->if_n)
			qs->if_n--;
		goto detached;
	}
	npr_window_put(e->pool, e->src_slot);
	npr_window_put(e->pool, e->aux_slot);
	npr_window_put(e->pool, e->aux2_slot);
	e->src_slot = NPR_WINDOW_NONE;
	e->aux_slot = NPR_WINDOW_NONE;
	e->aux2_slot = NPR_WINDOW_NONE;
	memset(e, 0, sizeof(*e));
	if (qs && qs->if_n)
		qs->if_n--;

detached:
 /* The inflight no longer owns a PIN, window, batch image, or provider slot.
  * Borrows keep entries/leases alive even if concurrent cancellation already
  * published their flush WCs. Drop each borrow after the last pointer use. */
 if(rdv_data)npr_rdv_source_data_done(rdv_data,&wc);
 if(owner) {if(!rdv_data){if(inline_clean)npr_order_complete_inline_clean(owner,&wc);else npr_order_complete(owner,&wc);}npr_order_put(owner);}
 if(inline_clean&&batch_wc.status==IBV_WC_SUCCESS)npr_order_complete_batch_clean(owners,n,&batch_wc);
 else for(oi=0;oi<n;oi++)npr_order_complete_verification(owners[oi],&batch_wc);
 for(oi=0;oi<n;oi++)npr_order_put(owners[oi]);
 if(owned_item) {
  owned_item->wc=wc;owned_item->visible=item_visible || wc.status!=IBV_WC_SUCCESS;
  owned_item->ready=1;npr_gate_put(owned_item);
 }
 if(inline_clean)npr_progress_owner_end_inline_clean(progress_ticket);else npr_progress_owner_end(progress_ticket);
 /* A cover can finish its native DMA while a predecessor is being repaired.
  * Keep its state/windows/error route until that batch reaches a verdict. */
 if(cover&&cover->qs==qs&&cover->cover_refs){
  cover->cover_refs--;
  if(batch_wc.status!=IBV_WC_SUCCESS){
   cover->cover_bad=1;
   if(cover->publish_pending&&cover->wc.status==IBV_WC_SUCCESS)cover->wc.status=IBV_WC_GENERAL_ERR;
  }
  if(!cover->cover_refs&&!cover->native_refs){
   if(cover->publish_pending)npr_publish_terminal(cover);
   else if(cover->release_pending)npr_if_release(cover);
  }
 }
}

static void npr_publish_terminal(struct npr_inflight *e)
{
 if(e->notify_pending&&!e->notify_done) return;
 if(e->native_refs||e->cover_refs) {e->publish_pending=1;return;}
 e->delivered=1;e->sticky_claimed=0;
 npr_if_release(e);
 npr_order_progress();
}

#ifdef NPR_PROGRESS_INTEGRATED
struct npr_check_job { struct npr_ctx_entry *ce; struct npr_cq_entry *cq; struct npr_inflight *entry; };
static void npr_finish_job(void *opaque)
{
 struct npr_check_job *j=opaque;
 struct npr_inflight *e=j->entry;
 e->async_check=0;
 npr_if_finish(j->ce,j->cq,e);
 npr_publish_terminal(e);
 free(j);
}

#endif

/* Native resource owners outlive both their WC and a transient UNPIN failure.
 * The cleanup worker owns the identity while the API gate is suspended. */
static void npr_identity_finish_job(void *opaque)
{
 struct npr_identity *id=opaque;
 int canceled=id->state==NPR_ID_CANCELED,rc=0;
 if(!canceled&&id->spec.kind!=NPR_ID_INTERNAL&&!id->spec.order&&!id->item) {
  struct npr_cq_entry *cqe=npr_cq_get(id->ce,id->cq);
  id->item=cqe?npr_gate_reserve_raw(cqe):NULL;
  if(!id->item) {npr_identity_cleanup_retry(id);return;}
  npr_gate_get(id->item);npr_gate_set_lane(id->item,id->spec.lane);id->item->generation=id->generation;id->item->wc=id->wc;
 }
 if(id->spec.resource && id->spec.release) rc=id->spec.release(id->spec.resource);
 if(rc>0) {id->state=canceled?NPR_ID_CANCELED:NPR_ID_CLEANUP;npr_identity_cleanup_retry(id);return;}
 id->spec.resource=NULL;
 if(rc<0) id->wc.status=IBV_WC_GENERAL_ERR;
 if(!canceled) {
  if(id->spec.order) {
   if(!id->spec.rdv_owner)npr_order_complete(id->spec.order,&id->wc);
   npr_order_put(id->spec.order);
  } else if(id->item) {
   id->item->wc=id->wc;
   id->item->visible=id->spec.visible || id->wc.status!=IBV_WC_SUCCESS;
   id->item->ready=1;
   npr_gate_put(id->item);id->item=NULL;
  }
 }
 if(canceled&&id->spec.order) npr_order_put(id->spec.order);
 npr_progress_owner_end(id->progress_ticket);
 npr_identity_retire(id);
 npr_order_progress();
}
void npr_identity_progress(struct npr_ctx_entry *ce)
{
 struct npr_qp_state *q;
 unsigned group;
 for(group=0;group<2;group++) for(q=ce?(group?ce->dead_qps:ce->qps):NULL;q;q=q->next) {
  unsigned i;
  if(q->batch_drop_pending&&!q->batch_native_refs) npr_batch_drop(q);
  for(i=0;i<q->if_cap;i++) {
   struct npr_inflight *e=&q->ifs[i];
   if(e->qs&&e->release_pending&&!e->native_refs&&!e->in_check&&!e->async_check&&!e->cleanup_active&&!e->prepare_active)
    npr_if_release(e);
  }
  if(q->dead&&!q->lifecycle_refs&&!q->if_n&&!q->batch_native_refs&&!q->batch_drop_pending) {
   npr_batch_pool_release(q,ce->ctx&&!ce->closing);
   free(q->ifs);q->ifs=NULL;q->if_cap=0;
  }
 }
 /* Closed contexts skip normal dispatch in the pump; still reap terminal
  * borrowed entries after their last engine cleanup releases the lease. */
 npr_order_progress();
 struct npr_identity *id=npr_identity_pending(ce);
 if(!id) return;
 npr_identity_cleanup_claim(id);
#ifdef NPR_PROGRESS_INTEGRATED
 if(npr_progress_submit_for(id->cq,npr_identity_finish_job,id)) npr_identity_cleanup_retry(id);
#else
 npr_identity_finish_job(id);
#endif
}
static void npr_identity_raw_complete(struct npr_identity *id,struct npr_cq_entry *cqe,
 const struct ibv_wc *wc)
{
 id->wc=*wc;id->wc.wr_id=id->spec.user_wr_id;
 if(wc->status!=IBV_WC_SUCCESS) id->wc.opcode=id->spec.opcode;
 if(!id->progress_ticket) id->progress_ticket=npr_progress_owner_begin(id->cq);
 if(!id->spec.order) {
  id->item=npr_gate_reserve_raw(cqe);
  if(!id->item) {id->state=NPR_ID_CLEANUP;npr_identity_cleanup_retry(id);return;}
  npr_gate_get(id->item);npr_gate_set_lane(id->item,id->spec.lane);id->item->generation=id->generation;
  id->item->wc=id->wc;
 }
 id->state=NPR_ID_CLEANUP;npr_identity_cleanup_claim(id);
 if(!id->spec.resource) {npr_identity_finish_job(id);return;}
#ifdef NPR_PROGRESS_INTEGRATED
 if(npr_progress_submit_for(id->cq,npr_identity_finish_job,id)) npr_identity_cleanup_retry(id);
#else
 npr_identity_finish_job(id);
#endif
}
static void npr_engine_identity_complete(struct npr_ctx_entry *ce,struct npr_cq_entry *cqe,
 struct npr_identity *id,const struct ibv_wc *native)
{
 enum npr_identity_kind kind=id->spec.kind;
 uint64_t generation=id->generation;
 struct npr_inflight *e=id->spec.owner;
 struct ibv_wc wc=*native;
 wc.wr_id=id->spec.user_wr_id;
 if(wc.status!=IBV_WC_SUCCESS) wc.opcode=id->spec.opcode;
 if(kind==NPR_ID_BATCH_MEMBER) {
  struct npr_qp_state *batch_q=id->spec.owner;
  if(batch_q&&batch_q->batch_native_refs) batch_q->batch_native_refs--;
  if(wc.status!=IBV_WC_SUCCESS) npr_order_note_transport_error(id->spec.order,wc.status);
  npr_order_put(id->spec.order);npr_identity_retire(id);
  if(batch_q&&batch_q->batch_drop_pending&&!batch_q->batch_native_refs) npr_batch_drop(batch_q);
  return;
 }
 if(kind==NPR_ID_INTERNAL) {
  id->wc=wc;id->state=NPR_ID_CLEANUP;npr_identity_cleanup_retry(id);return;
 }
 if(kind==NPR_ID_PASS||kind==NPR_ID_ORDER||kind==NPR_ID_SEND||kind==NPR_ID_RECV) {
  npr_identity_raw_complete(id,cqe,&wc);return;
 }
 npr_identity_retire(id);
 if(!e || !e->qs) return;
 if(e->native_refs) e->native_refs--;
 if(e->release_pending||e->publish_pending) {
  if(!e->native_refs) {
   if(e->publish_pending) npr_publish_terminal(e);else npr_if_release(e);
  }
  return;
 }
 if(!e->progress_ticket) e->progress_ticket=npr_progress_owner_begin(cqe->cq);
 if(kind==NPR_ID_NOTIFY) {
  e->notify_done=1;
  if(wc.status!=IBV_WC_SUCCESS) {e->wc.status=wc.status;e->wc.vendor_err=wc.vendor_err;e->app_ok=0;}
 } else if(kind==NPR_ID_AUX) {
  if(e->seqlock&&!e->aux_done&&!e->app_done&&wc.status==IBV_WC_REM_ACCESS_ERR)
   e->leading_remote_error=wc;
  if(!e->aux_done) {e->aux_done=1;e->aux_ok=wc.status==IBV_WC_SUCCESS;}
  else {e->aux2_done=1;e->aux2_ok=wc.status==IBV_WC_SUCCESS;}
  if(e->state<NPR_IF_AUX_DONE) e->state=NPR_IF_AUX_DONE;
 } else {
  e->item=e->op.order?npr_order_item(e->op.order):npr_gate_reserve_raw(cqe);
  if(e->item) {
   if(!e->op.order) npr_gate_get(e->item);
   npr_gate_set_lane(e->item,NPR_LANE_SQ);e->item->generation=generation;e->item->wc.qp_num=wc.qp_num;
  }
  /* A revoked remote version key faults the leading READ and flushes the
   * following APP WQE. Report that remote-access cause on the logical op;
   * later AUX failures and genuine APP errors keep their own semantics. */
  if(wc.status==IBV_WC_WR_FLUSH_ERR&&e->leading_remote_error.status==IBV_WC_REM_ACCESS_ERR){
   wc.status=e->leading_remote_error.status;wc.vendor_err=e->leading_remote_error.vendor_err;
  }
  e->wc=wc;e->app_done=1;e->app_ok=wc.status==IBV_WC_SUCCESS;
  if(e->state<NPR_IF_APP_DONE) e->state=NPR_IF_APP_DONE;
 }
 if(!e->in_check&&!e->async_check&&npr_if_complete(e)) {
#ifdef NPR_PROGRESS_INTEGRATED
  /* Fault-free verdicts only inspect completed DMA windows/version snapshots.
   * No PIN release, RPC, refresh DMA or notification may occur on this path.
   * Non-clean/unavailable verdicts retain the original asynchronous funnel. */
  if(!e->notify_done&&!e->is_wwi&&!e->pre_pin_n&&!e->cover_bad&&(e->landing==NPR_LANDING_BATCH||e->app_ok)&&
     (e->landing==NPR_LANDING_BATCH?e->aux_ok:
       e->seqlock?(e->aux_ok&&e->aux2_ok):(!e->aux_want||e->aux_ok))&&
     npr_if_check(ce,cqe,e,1)){
   e->inline_clean=1;
   npr_publish_terminal(e);return;
  }
  if(!e->notify_done) {
   struct npr_check_job *job=malloc(sizeof(*job));int queued=-ENOMEM;
   if(job) {*job=(struct npr_check_job){ce,cqe,e};e->async_check=1;queued=npr_progress_submit_for(cqe->cq,npr_finish_job,job);}
   if(!queued) return;
   if(getenv("NPRDMA_DEBUG")) fprintf(stderr,"[nprdma] verification enqueue failed wr_id=%llu rc=%d kind=%d\n",(unsigned long long)e->op.wr_id,queued,kind);
   e->async_check=0;free(job);
   /* Verification admission cannot replace an error already reported by the
    * native operation. Only an unverified native success needs synthesis. */
   if(e->wc.status==IBV_WC_SUCCESS)e->wc.status=IBV_WC_GENERAL_ERR;
   e->state=NPR_IF_READY;npr_publish_terminal(e);return;
  }
#endif
  if(!e->notify_done) npr_if_finish(ce,cqe,e);
  if(e->notify_pending&&!e->notify_done) return;
  npr_publish_terminal(e);
 }
}
static int npr_drain_cq_observed(struct npr_ctx_entry *ce,struct npr_cq_entry *cqe,int *observed)
{
 static unsigned long invalid_count;
 struct ibv_wc wc;
 npr_identity_progress(ce);
 for(;;) {
  struct npr_identity *id;
  int n;
  if(npr_gate_raw_full(cqe)) return 0;
  n=ce->real_poll_cq(cqe->cq,1,&wc);
  if(n<0) return -1;
  if(!n) {
#ifdef NPR_PROGRESS_INTEGRATED
   npr_progress_cq_drained(cqe->cq);
#endif
   return 0;
  }
  if(observed)*observed=1;
  id=npr_identity_resolve(ce,cqe->cq,&wc);
  if(!id) {
   invalid_count++;
   if(invalid_count<=32&&getenv("NPRDMA_DEBUG")) fprintf(stderr,"[nprdma] rejected native WC identity token=%llu qp=%u status=%u count=%lu\n",(unsigned long long)wc.wr_id,wc.qp_num,wc.status,invalid_count);
   npr_progress_cq_observed(cqe->cq);continue;
  }
  /* Establish the logical owner's ticket before native event observation. */
  if(id->spec.kind==NPR_ID_APP||id->spec.kind==NPR_ID_AUX||id->spec.kind==NPR_ID_NOTIFY) {
   struct npr_inflight *e=id->spec.owner;
   if(e&&!e->progress_ticket) e->progress_ticket=npr_progress_owner_begin(cqe->cq);
  } else if(id->spec.kind!=NPR_ID_BATCH_MEMBER) id->progress_ticket=npr_progress_owner_begin(cqe->cq);
  npr_engine_identity_complete(ce,cqe,id,&wc);
  npr_progress_cq_observed(cqe->cq);
 }
}
/* A batched posting transaction can queue its cover behind conflicting
 * members. Foreground polling must break that dependency by checking the old
 * batch; it must not depend on an unrelated background pump pass. */
static void npr_foreground_order_barrier(struct npr_ctx_entry *ce,struct npr_cq_entry *cq)
{
 if(!cq->order_deferred)return;
 for(struct npr_qp_state *q=ce->qps;q;q=q->next)
  if(q->qp&&q->send_cq==cq->cq)npr_batch_close(ce,q,0,NULL);
 npr_order_progress();
}
int npr_drain_cq(struct npr_ctx_entry *ce,struct npr_cq_entry *cqe)
{
 int observed=0,rc=npr_drain_cq_observed(ce,cqe,&observed);
 /* The last native identity may release an order borrow after terminal
  * publication. Reap/dispatch here instead of relying on another pump pass. */
 if(observed)npr_order_progress();
 return rc;
}
/* Both application polling and the autonomous pump hold the same API gate.
 * A polling application can consume/verify native completions itself rather
 * than waiting for the pump to run. Existing typed identity/order/event funnels
 * remain authoritative; missing-data checks still enqueue their repair job. */
int npr_poll_verified_cq(struct npr_ctx_entry *ce,struct npr_cq_entry *cq,
 int num_entries,struct ibv_wc *wc)
{
 int delivered=0;
 npr_foreground_order_barrier(ce,cq);
 npr_progress_ready(cq->cq);
 while(delivered<num_entries&&npr_gate_pop(cq,&wc[delivered]))delivered++;
 if(delivered>=num_entries)return delivered;
 int observed=0,rc=npr_drain_cq_observed(ce,cq,&observed);
 if(observed)npr_order_progress();
 /* Native/control cleanup may be queued without producing a public CQE.
  * Wake on that state change; a genuinely empty query has nothing to wake. */
 if(observed&&!npr_progress_cq_caller_driven(cq->cq))npr_progress_wake();
 if(rc<0)return delivered?delivered:-1;
 npr_progress_ready(cq->cq);
 while(delivered<num_entries&&npr_gate_pop(cq,&wc[delivered]))delivered++;
 return delivered;
}
/* The application provider has certified this QP's native DMA stopped. This
 * is not SIR transport stop: callers quiesce outstanding verification jobs
 * before the provider operation, and no internal RPC/bridge is canceled here.
 * Detach every target before cleanup can release the API gate. */
void npr_qp_native_discard(struct npr_ctx_entry *ce,struct ibv_qp *qp,
 uint32_t number,uint64_t generation,struct npr_qp_state *q,int forget)
{
 struct npr_identity *id,*pending=NULL;
 struct npr_cq_entry *cq;
 unsigned i;
 npr_order_qp_discard(qp,generation);
 if(q) {
  q->lifecycle_refs++;
  struct npr_qp_state **pp;
  for(pp=&ce->qps;*pp&&*pp!=q;pp=&(*pp)->next){}
  if(*pp){*pp=q->next;q->next=ce->dead_qps;ce->dead_qps=q;}
  q->qp=NULL;q->closing=1;q->dead=1;
  for(i=0;i<q->if_cap;i++) if(q->ifs[i].qs) {
   struct npr_inflight *e=&q->ifs[i];
   if(e->item&&!e->op.order)npr_gate_put(e->item);
   e->item=NULL;e->qp=NULL;e->is_wwi=0;e->release_pending=1;
  }
 }
 /* Identities have already been quiesced. Mark them all before any UNPIN
  * yields, so new work on a recreated/reinitialized QP cannot join this set. */
 while((id=npr_identity_for_qp_generation(qp,generation))) {
  enum npr_identity_kind kind=id->spec.kind;
  if(kind==NPR_ID_APP||kind==NPR_ID_AUX||kind==NPR_ID_NOTIFY) {
   struct npr_inflight *e=id->spec.owner;
   if(e&&e->native_refs)e->native_refs--;
   npr_identity_retire(id);continue;
  }
  if(kind==NPR_ID_BATCH_MEMBER) {
   struct npr_qp_state *b=id->spec.owner;
   if(b&&b->batch_native_refs)b->batch_native_refs--;
   npr_order_put(id->spec.order);npr_identity_retire(id);continue;
  }
  if(id->item){npr_gate_put(id->item);id->item=NULL;}
  id->qp=NULL;id->state=NPR_ID_CANCELED;npr_identity_cleanup_claim(id);
  id->stop_next=pending;pending=id;
 }
 /* Remove unread software completions too. Cells held by a cleanup owner
  * remain stable but detached until its final put. No later owner republishes. */
 for(cq=ce->cqs;cq;cq=cq->next) {
  struct npr_gate_item *g=cq->first,*next;
  while(g){next=g->next;if(g->generation==generation&&g->wc.qp_num==number){g->visible=0;g->ready=1;npr_gate_unlink(g);}g=next;}
 }
 if(forget)npr_identity_detach_qp_generation(qp,generation);
 while(pending){id=pending;pending=id->stop_next;id->stop_next=NULL;npr_identity_finish_job(id);}
 if(q) {
  npr_batch_drop(q);
  for(i=0;i<q->if_cap;i++)if(q->ifs[i].qs)npr_if_release(&q->ifs[i]);
  q->lifecycle_refs--;
 }
 npr_progress_wake();
}

void npr_identity_qp_stopped(struct npr_ctx_entry *ce,struct ibv_qp *qp,uint32_t number)
{
 struct npr_qp_state *q;
 for(q=ce->qps;q;q=q->next)if(q->qp_num==number&&q->closing)break;
 npr_identity_qp_stopped_state(ce,qp,number,npr_identity_qp_known_generation(qp),q);
}
void npr_identity_qp_stopped_state(struct npr_ctx_entry *ce,struct ibv_qp *qp,uint32_t number,uint64_t generation,struct npr_qp_state *old_state)
{
 struct npr_identity *id;
 struct npr_cq_entry *cq;
 for(cq=ce->cqs;cq;cq=cq->next) (void)npr_drain_cq(ce,cq);
#ifdef NPR_PROGRESS_INTEGRATED
 npr_progress_quiesce();
#endif
 /* Drain already queued real WCs before synthesizing only residual flushes.
  * Native destroy has returned, so no remaining owner may DMA. */
 for(id=npr_identity_for_qp_generation(qp,generation);id;id=npr_identity_for_qp_generation(qp,generation)) {
  struct npr_cq_entry *cqe=npr_cq_get(ce,id->cq);
  struct ibv_wc wc={.wr_id=id->token,.qp_num=number,.status=IBV_WC_WR_FLUSH_ERR,.opcode=id->spec.opcode};
  if(id->state==NPR_ID_PREPARED) {npr_identity_abort(id);continue;}
  if(id->state==NPR_ID_CANCELED||id->state==NPR_ID_CLEANUP) {
   npr_identity_cleanup_claim(id);npr_identity_finish_job(id);
   if(npr_identity_for_qp_generation(qp,generation)==id) break;
   continue;
  }
  if(!cqe) break;
  if(id->state==NPR_ID_ACCEPTED) id->state=NPR_ID_CLAIMED;
  npr_engine_identity_complete(ce,cqe,id,&wc);
 }
#ifdef NPR_PROGRESS_INTEGRATED
 npr_progress_quiesce();
#endif
 if(old_state)npr_batch_drop(old_state);
 npr_identity_detach_qp_generation(qp,generation);
}

/* The caller has stopped native DMA and quiesced cleanup jobs. No provider
 * object is read here: a successful close may already have freed all of them.
 * Order entries are detached by npr_order_context_stopped before this call. */
void npr_identity_context_stopped(struct npr_ctx_entry *ce)
{
 struct npr_identity *id;
 struct npr_qp_state *q;
 unsigned group;
 while((id=npr_identity_for_context(ce))) {
  enum npr_identity_kind kind=id->spec.kind;
  npr_identity_forget_qp(id->qp);
  if(kind==NPR_ID_APP||kind==NPR_ID_AUX||kind==NPR_ID_NOTIFY) {
   struct npr_inflight *e=id->spec.owner;
   if(e&&e->native_refs) e->native_refs--;
   npr_identity_retire(id);continue;
  }
  if(kind==NPR_ID_BATCH_MEMBER) {
   struct npr_qp_state *batch_q=id->spec.owner;
   if(batch_q&&batch_q->batch_native_refs) batch_q->batch_native_refs--;
   npr_order_put(id->spec.order);npr_identity_retire(id);continue;
  }
  if(id->item) {npr_gate_put(id->item);id->item=NULL;}
  if(id->spec.internal_context_stopped)id->spec.internal_context_stopped(id->spec.owner);
  id->state=NPR_ID_CANCELED;id->ce=NULL;id->cq=NULL;id->qp=NULL;
  npr_identity_cleanup_claim(id);npr_identity_finish_job(id);
 }
 for(group=0;group<2;group++) for(q=group?ce->dead_qps:ce->qps;q;q=q->next) {
  unsigned i;
  q->batch_native_refs=0;q->batch_drop_pending=1;
  for(i=0;i<q->if_cap;i++) {
   struct npr_inflight *e=&q->ifs[i];
   if(!e->qs) continue;
   if(e->item&&!e->op.order) npr_gate_put(e->item);
   e->item=NULL;e->native_refs=0;e->release_pending=1;e->is_wwi=0;
  }
 }
 npr_identity_forget_context(ce->ctx);
}

void npr_order_flush_batches(struct npr_ctx_entry *ce, struct ibv_qp *qp)
{
 struct npr_qp_state *q;
 for(q=ce->qps;q;q=q->next) if(!qp || q->qp==qp) npr_batch_close(ce,q,0,NULL);
}

int npr_drain_qp_until(struct npr_ctx_entry *ce, struct npr_qp_state *qs,
		       unsigned min_free)
{
	struct npr_cq_entry *cqe = npr_cq_get(ce, qs->send_cq);
	int spins = 0;

 if(!qs->batch_closing && npr_batch_pending(qs) && npr_batch_image_wait(ce,qs)) return -1;
	while (qs->if_n + min_free > qs->if_cap) {
		if (!cqe || npr_drain_cq(ce, cqe))
			return -1;
		if (++spins > NPR_POLL_SPIN_MAX)
			return -1;
		{ unsigned depth=npr_progress_wait_begin();usleep(NPR_POLL_SLEEP_US);npr_progress_wait_end(depth); }
	}
	return 0;
}

static int npr_qp_invariant(struct npr_qp_state *qs)
{
	unsigned i;

	if (qs->if_n)
		return -1;
	for (i = 0; i < qs->if_cap; i++)
		if (qs->ifs && qs->ifs[i].qs)
			return -1;
	if (qs->bat_pool)
		return -1;
	return npr_batch_invariant(qs);
}

static void npr_poison_mem(void *p, size_t n)
{
	if (p)
		memset(p, 0xA5, n);
}

void npr_qp_destroy_begin(struct npr_ctx_entry *ce, struct ibv_qp *qp)
{
	struct npr_qp_state *q;

	npr_order_cancel_qp(qp, 1);

	for (q = ce->qps; q; q = q->next) {
		unsigned i;

		if (q->qp != qp)
			continue;

		q->closing = 1;

		npr_batch_close(ce, q, 0, NULL);
		q->qp = NULL;
		for (i = 0; i < q->if_cap; i++) {
			if (!q->ifs[i].qs)
				continue;
			q->ifs[i].qp = NULL;
			q->ifs[i].is_wwi = 0;
		}
		return;
	}
}

void npr_qp_destroy_abort(struct npr_ctx_entry *ce, struct ibv_qp *qp)
{
 struct npr_qp_state *q;
 unsigned i;
 for(q=ce->qps;q;q=q->next) if(q->qp_num==qp->qp_num && q->closing) {
  q->qp=qp;q->closing=0;
  for(i=0;i<q->if_cap;i++) if(q->ifs[i].qs) {
   q->ifs[i].qp=qp;
   q->ifs[i].is_wwi=(q->ifs[i].op.kind==NPR_OP_WRITE_IMM);
  }
  return;
 }
}

int npr_qp_destroy_end(struct npr_ctx_entry *ce,uint32_t qp_num)
{
 struct npr_qp_state *q;
 for(q=ce->qps;q;q=q->next)if(q->qp_num==qp_num&&q->closing)break;
 return npr_qp_destroy_end_state(ce,q);
}
int npr_qp_destroy_end_state(struct npr_ctx_entry *ce,struct npr_qp_state *q)
{
 struct npr_cq_entry *cqe = NULL;
 int spins = 0, rc = 0;
 unsigned i;
	if (!q)
		return 0;
	if (q->send_cq)
		cqe = npr_cq_get(ce, q->send_cq);

	while (q->if_n && cqe && spins <= NPR_POLL_SPIN_MAX) {

		if (npr_drain_cq(ce, cqe))
			break;
		spins++;
		if (q->if_n)
			{ unsigned depth=npr_progress_wait_begin();usleep(NPR_POLL_SLEEP_US);npr_progress_wait_end(depth); }
	}
	if (q->if_n) {

		npr_stat_inc(NPR_STAT_QP_FLUSH_TIMEOUT);
		npr_log_emit("[nprdma] QP destroy convergence timed out — dropping residual in-flight entries"
			     "(fail-closed)\n");
		for (i = 0; i < q->if_cap; i++)
			if (q->ifs[i].qs) {
				q->ifs[i].is_wwi = 0;
				npr_if_release(&q->ifs[i]);
			}
		rc = -1;
	}

 if(q->if_n||q->batch_native_refs||q->batch_drop_pending) {
  q->dead=1;rc=-1;goto retain_record;
 }

	npr_batch_pool_release(q,ce->ctx&&!ce->closing);
	if (npr_qp_invariant(q)) {
		npr_log_emit("[nprdma] QP convergence invariant violation — counted as evidence"
			     "(fail-closed)\n");
		rc = -1;
	}
	npr_poison_mem(q->ifs, q->if_cap * sizeof(*q->ifs));
	free(q->ifs);
	q->ifs = NULL;
	q->if_cap = q->if_n = 0;
	q->qp_num = 0;
	q->dead = 1;
retain_record:
 npr_stat_inc(NPR_STAT_QP_DESTROY);
	{
		struct npr_qp_state **pp;

		for (pp = &ce->qps; *pp; pp = &(*pp)->next)
			if (*pp == q)
				break;
		if (*pp) {
			*pp = q->next;
			q->next = ce->dead_qps;
			ce->dead_qps = q;
		}
	}
	return rc;
}

int npr_identity_cq_busy(struct npr_ctx_entry *ce,struct ibv_cq *cq)
{
 struct npr_qp_state *q;
 struct npr_cq_entry *c;
 unsigned group,i;
 if(npr_identity_has_cq(cq)) return 1;
 for(group=0;group<2;group++) for(q=group?ce->dead_qps:ce->qps;q;q=q->next)
  if(q->send_cq==cq&&(q->if_n||q->batch_native_refs||q->bat.n_ops||q->batch_drop_pending)) return 1;
 for(c=ce->cqs;c;c=c->next) if(c->cq==cq) {
  for(i=0;i<c->cap;i++) if(c->ring[i].owner_refs) return 1;
  for(i=0;i<c->ready_cap;i++) if(c->ready_overflow[i].owner_refs) return 1;
 }
 return 0;
}

void npr_cq_destroy(struct npr_ctx_entry *ce, struct ibv_cq *cq)
{
	struct npr_cq_entry **pp;
	struct npr_cq_entry *cqe = NULL;
	struct npr_qp_state *q;
	unsigned i;

	for (pp = &ce->cqs; *pp; pp = &(*pp)->next)
		if ((*pp)->cq == cq) {
			cqe = *pp;
			*pp = cqe->next;
			break;
		}
	if (!cqe)
		return;

	for (q = ce->qps; q; q = q->next) {
		if (q->send_cq != cq)
			continue;
		npr_batch_drop(q);
		for (i = 0; i < q->if_cap; i++)
			if (q->ifs[i].qs) {
				npr_stat_inc(NPR_STAT_CQ_DESTROY_INFLIGHT);
				q->ifs[i].is_wwi = 0;
				npr_if_release(&q->ifs[i]);
			}
	}
	npr_order_cancel_cq(cqe);
	npr_poison_mem(cqe->ring, cqe->cap * sizeof(*cqe->ring));
	free(cqe->ring);
 free(cqe->ready_overflow);
	free(cqe);
}

enum npr_path {
	NPR_PATH_PASSTHROUGH = 0,
	NPR_PATH_SENTINEL,
	NPR_PATH_SEQLOCK,
	NPR_PATH_BATCH_WRITE,
};

struct npr_plan {
	enum npr_path path;
	uint32_t emit_rkey;
	unsigned visible : 1;
	unsigned aux : 1;
	unsigned long np;
};

static void npr_stat_inc(enum npr_stat s)
{
	if ((unsigned)s < NPR_STAT_MAX)
		npr_stats[s]++;
}

void npr_engine_stat_inc(unsigned idx)
{
	if (idx < NPR_STAT_MAX)
		npr_stat_inc((enum npr_stat)idx);
}

static const char *const npr_stat_names[NPR_STAT_MAX] = {
#define NPR_ES_NAME(k, n, d) [NPR_STAT_##k] = n,
	NPRDMA_ENGINE_STAT_LIST(NPR_ES_NAME)
#undef NPR_ES_NAME
};

static const char *const npr_stat_descs[NPR_STAT_MAX] = {
#define NPR_ES_DESC(k, n, d) [NPR_STAT_##k] = d,
	NPRDMA_ENGINE_STAT_LIST(NPR_ES_DESC)
#undef NPR_ES_DESC
};

const char *nprdma_engine_stat_name(enum nprdma_engine_stat s)
{
	if ((unsigned)s >= (unsigned)NPR_STAT_MAX)
		return "?";
	return npr_stat_names[s] ? npr_stat_names[s] : "?";
}

const char *nprdma_engine_stat_desc(enum nprdma_engine_stat s)
{
	if ((unsigned)s >= (unsigned)NPR_STAT_MAX)
		return "";
	return npr_stat_descs[s] ? npr_stat_descs[s] : "";
}

int nprdma_engine_stats_get(struct nprdma_engine_stats *out)
{
	unsigned i;

	if (!out) {
		errno = EINVAL;
		return -EINVAL;
	}

	for (i = 0; i < NPR_STAT_MAX; i++)
		out->v[i] = npr_stats[i];
	return (int)NPR_STAT_MAX;
}

int nprdma_engine_stats_dump(int fd)
{
	char line[256];
	unsigned i;
	int total = 0;
	ssize_t n;
	size_t off, len;

	if (fd < 0) {
		errno = EBADF;
		return -EBADF;
	}
	for (i = 0; i < NPR_STAT_MAX; i++) {
		int k = snprintf(line, sizeof(line), "%s %lu\t# %s\n",
				 npr_stat_names[i] ? npr_stat_names[i] : "?",
				 npr_stats[i],
				 npr_stat_descs[i] ? npr_stat_descs[i] : "");

		if (k < 0 || (size_t)k >= sizeof(line))
			continue;
		off = 0;
		len = (size_t)k;
		while (off < len) {
			n = write(fd, line + off, len - off);
			if (n < 0) {
				if (errno == EINTR)
					continue;
				return -errno;
			}
			off += (size_t)n;
		}
		total += k;
	}
	return total;
}

static void npr_stat_add(enum npr_stat s, unsigned long v)
{
	if ((unsigned)s < NPR_STAT_MAX)
		npr_stats[s] += v;
}

NPRDMA_INTERNAL void npr_ex_count(enum npr_ex_stat s)
{
	static const enum npr_stat map[NPR_EX_STAT_MAX] = {
		NPR_STAT_EX_INSTALL,
		NPR_STAT_EX_REPLAY,
		NPR_STAT_EX_TAKEOVER,
		NPR_STAT_EX_UNSUPPORTED,
		NPR_STAT_EX_OVERFLOW,
	};

	if ((unsigned)s < NPR_EX_STAT_MAX)
		npr_stat_inc(map[s]);
}

static void npr_route_warn(enum npr_stat why, enum npr_op_kind kind)
{
	static int warned_imm_unsig, warned_big;
	int imm_form = (kind == NPR_OP_WRITE_IMM);

	switch (why) {
	case NPR_STAT_PASS_UNSIGNED_WWI:
		if (!warned_imm_unsig++)
			fprintf(stderr,
				"[nprdma] unsignaled remote WITH_IMM — cannot verify the imm timing safely, passing through\n");
		break;
	case NPR_STAT_PASS_UNSIGNED_BIG_WRITE:
		if (!warned_big++)
			fprintf(stderr,
				"[nprdma] ≥4KB unsignaled remote write — no settled repair-carrier plan, passing through\n");
		break;
	case NPR_STAT_PASS_WRITE_TOO_LARGE:
		if (imm_form)
			fprintf(stderr,
				"[nprdma] >4KB remote WITH_IMM — passthrough (same gate as remote writes)\n");
		break;
	default:
		break;
	}
}

static int npr_route(struct npr_ctx_entry *ce, struct npr_op *op,
		     struct npr_plan *pl)
{
	enum npr_stat why = NPR_STAT_MAX;

	memset(pl, 0, sizeof(*pl));
	pl->path = NPR_PATH_PASSTHROUGH;
	pl->visible = op->signaled ? 1 : 0;
	op->wkey = 0;

	if (!ce->real_post_send) {
		why = NPR_STAT_PASS_NO_ENGINE;
		goto pass;
	}
	if (op->remote_state==NPR_REMOTE_FOREIGN ||
     (op->remote_state!=NPR_REMOTE_FOUND && sir_remote_lookup_cached(op->rkey, &op->exp))) {
		why = NPR_STAT_PASS_NO_EXPORT;
		goto pass;
	}

	/* Application permissions are independent of private verification keys.
	 * A denied operation retains its app key and reaches provider protection;
	 * it must never acquire a private view merely because one exists. */
	if (op->exp.app_rkey &&
	    ((npr_op_is_read(op) && !(op->exp.app_access & IBV_ACCESS_REMOTE_READ)) ||
	     (npr_op_is_write(op) && !(op->exp.app_access & IBV_ACCESS_REMOTE_WRITE)))) {
		why = NPR_STAT_PASS_NO_EXPORT;
		goto pass;
	}

	if (npr_op_is_write(op)) {
		uint32_t wk;

		if (npr_write_key(op, &wk)) {
			/* no write key from either path (read-only MR, or the rkey
			 * belongs to no local MR and no published export): the engine
			 * cannot own this write - the posting face rejects it */
			why = NPR_STAT_PASS_NO_WRITE_KEY;
			goto pass;
		}
		/* the key is the resolver's answer, unconditionally: the range
		 * check below gates the takeover decision, not the key - an op
		 * that passes still posts with the write key */
		pl->emit_rkey = wk;
		op->wkey = wk;
	}
	if (!npr_sg_valid(op)) {
		why = NPR_STAT_PASS_MULTI_SGE;
		goto pass;
	}
	if (op->remote_addr < op->exp.addr ||
	    op->remote_addr - op->exp.addr > op->exp.len ||
	    op->len > op->exp.len - (op->remote_addr - op->exp.addr)) {
		why = NPR_STAT_PASS_OUT_OF_RANGE;
		goto pass;
	}
	if (npr_op_is_write(op) && !op->signaled) {
		if (op->kind == NPR_OP_WRITE_IMM) {
			why = NPR_STAT_PASS_UNSIGNED_WWI;
			goto pass;
		}
		if (detect_route_seqlock(op->len)) {
			why = NPR_STAT_PASS_UNSIGNED_BIG_WRITE;
			goto pass;
		}
		pl->path = NPR_PATH_BATCH_WRITE;
		pl->visible = 0;
		pl->aux = 0;
		return 1;
	}
	pl->np = npr_op_pages(op);
	if (op->len > NPR_DATA_LEN_MAX || pl->np > NPR_DETECT_PAGES_MAX) {
		why = npr_op_is_read(op) ? NPR_STAT_PASS_READ_TOO_LARGE :
					   NPR_STAT_PASS_WRITE_TOO_LARGE;
		goto pass;
	}

	if (detect_route_seqlock(op->len)) {
		if (!op->exp.v_rkey || !op->exp.v_addr) {
			why = NPR_STAT_PASS_NO_VERSION;
			goto pass;
		}
		pl->path = NPR_PATH_SEQLOCK;
		pl->aux = 1;
		npr_stat_inc(npr_op_is_read(op) ? NPR_STAT_TAKEN_SEQLOCK_READ :
						 NPR_STAT_TAKEN_SEQLOCK_WRITE);
		return 1;
	}

	pl->path = NPR_PATH_SENTINEL;
	pl->aux = npr_op_is_write(op) ? 1 : 0;
	npr_stat_inc(op->kind == NPR_OP_READ ? NPR_STAT_TAKEN_READ :
		     op->kind == NPR_OP_WRITE_IMM ? NPR_STAT_TAKEN_WWI :
		     NPR_STAT_TAKEN_WRITE);
	return 1;
pass:
	npr_stat_inc(why);
	npr_route_warn(why, op->kind);
	return 0;
}

static void npr_submit_fail_trace(const struct npr_op *op,uint32_t qpn,const char *stage,int rc)
{
 static unsigned logs;
 int saved=errno;
 if(debug_on()&&logs++<32) fprintf(stderr,
  "[nprdma] submit failure stage=%s qp=%u wr_id=%llu kind=%u rc=%d errno=%d lkey=0x%x remote=0x%llx rkey=0x%x len=%llu (bounded32)\n",
  stage,qpn,(unsigned long long)op->wr_id,op->kind,rc,saved,
  op->num_sge?op->sge[0].lkey:0,(unsigned long long)op->remote_addr,op->rkey,(unsigned long long)op->len);
 errno=saved;
}
int npr_engine_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
		      struct npr_op *op)
{
	struct npr_qp_state *qs;
	struct npr_inflight *t;
	struct npr_plan plan;

	if (op->kind != NPR_OP_READ && op->kind != NPR_OP_WRITE)
		return 0;
	if (!npr_route(ce, op, &plan))
		return 0;
	qs = npr_qp_get(ce, qp);
	if (!qs)
		return 0;
 struct npr_qp_state *borrowed __attribute__((cleanup(npr_qp_state_borrow_end)))=qs;
 qs->lifecycle_refs++;
 struct npr_batch_prepare original={.ce=ce,.qs=qs,.op=op,.generation=npr_identity_qp_generation(qp)};
 if(!original.generation||!npr_batch_prepare_current(&original)){errno=ECANCELED;return -1;}
 if(plan.path==NPR_PATH_BATCH_WRITE){
  int rc=npr_batch_add(ce,qs,op);
  if(rc)return rc;
  plan.path=NPR_PATH_SENTINEL;plan.aux=1;plan.np=npr_op_pages(op);
 }


	t = npr_if_alloc(ce, qs);
	if (!t) {
  npr_submit_fail_trace(op,qp->qp_num,"inflight-alloc",-1);
		/* the lane was decided but cannot be tracked: an unverified
		 * post is not an option */
		return -1;
	}

 if(!npr_batch_prepare_current(&original)){npr_if_release(t);errno=ECANCELED;return -1;}

	t->op = *op;
 if(t->op.rdv_owner)npr_rdv_source_data_hold(t->op.rdv_owner);
		npr_order_get(t->op.order);
	t->visible = plan.visible;
	t->op.signaled = 1;
	if (t->visible && qs->sticky_err) {
		/* an earlier unsignaled failure on this QP: this completion is where
		 * the application can learn about it (the cover rule, applied to
		 * the carrier lane) */
		t->cover_bad = 1;
		t->sticky_claimed = 1;
		qs->sticky_err = 0;
	}
	/* The pre-check runs before anything reads a version table - the
	 * PIN flips parity, so every snapshot taken after it must see post-pin
	 * values (npr_local_snapshot asserts that ordering). Its
	 * verdict is a route: a face found absent is held right there
	 * and the op is **not** emitted - the bilateral carrier moves the bytes
	 * and the application's WC reports the carrier's outcome. Without a
	 * carrier channel (no export) the op is not taken at all and the
	 * passthrough face fails it closed. */
	{
		struct npr_preholder h = {
			.pin = npr_prehold_pin_inflight,
			.ctx = t,
		};
		int absent = 0;

		if (npr_precheck(&t->op, &h, &absent)) {
   npr_submit_fail_trace(op,qp->qp_num,"precheck",-1);
			/* a face could not be judged: fail-closed, never a raw
			 * post (the op is not handed back to the posting face,
			 * which would post it unverified) */
			npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
			npr_if_release(t);
			return -1;
		}
		if(!npr_batch_prepare_current(&original)){npr_if_release(t);errno=ECANCELED;return -1;}
		if (absent) {
			if (!t->op.exp.data_rkey) {
    npr_submit_fail_trace(op,qp->qp_num,"absent-no-carrier",-1);
				/* no carrier channel: the op cannot be carried
				 * and must not be emitted - fail-closed */
				npr_if_release(t);
				return -1;
			}
			int carried = npr_bilateral_run(ce, t);
   if(carried==NPR_CARRIER_REJECTED) npr_submit_fail_trace(op,qp->qp_num,"absent-carrier-rejected",carried);
			npr_if_release(t);
			return carried == NPR_CARRIER_REJECTED ? -1 : 1;
		}
	}
	/* The second trigger of the same route: the expected bytes are the
	 * sentinel pattern, so the readback lane below cannot tell a delivered write
	 * from a dropped one. Content cannot separate them, so the write is not
	 * posted optimistically - the carrier moves the bytes from a held source and
	 * its completion is the landing proof. A version-judged write (>=4KiB) has
	 * no such input: the version axis judges the window, not the bytes. */
	if (plan.path != NPR_PATH_SEQLOCK && npr_write_ambiguous(&t->op)) {
		npr_stat_inc(NPR_STAT_CARRIER_AMBIGUOUS_WRITE);
		if (t->op.kind == NPR_OP_WRITE_IMM || !t->op.exp.data_rkey) {
			/* WRITE_IMM reaches this point only through its own entry; if it
			 * ever does, the immediate has no carrier channel and the op must
			 * not go out with an unverifiable write (the imm's own lifecycle
			 * lifecycle), so it fails closed. No carrier channel is the same
			 * answer for a plain write. */
			npr_stat_inc(t->op.kind == NPR_OP_WRITE_IMM ?
				     NPR_STAT_AMBIGUOUS_WWI :
				     NPR_STAT_AUX_UNAVAILABLE);
			npr_fail_closed(t, "ambiguous write without a carrier channel");
			npr_if_release(t);
			return -1;
		}
		int carried = npr_carrier_write(ce, t);
		npr_if_release(t);
		return carried == NPR_CARRIER_REJECTED ? -1 : 1;
	}
	if (plan.path == NPR_PATH_SEQLOCK) {

		t->seqlock = 1;
		if (npr_window_get_progress(ce, qp->pd, &t->pool, &t->aux_slot) ||
		    npr_window_get_progress(ce, qp->pd, &t->pool, &t->aux2_slot)) {
			npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
			npr_if_release(t);
			return -1;
		}
		t->landing = NPR_LANDING_WINDOW;
	} else if (!npr_op_is_read(&t->op)) {
		if (npr_window_take_progress(t,&original)) {
   npr_submit_fail_trace(op,qp->qp_num,"source-window",-1);
			npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
			npr_if_release(t);
			return -1;
		}
		t->landing = NPR_LANDING_WINDOW;
	}

	if (t->seqlock && npr_seqlock_version_emit(ce, t, 0)) {
  npr_submit_fail_trace(op,qp->qp_num,"first-version-emit",-1);
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		npr_if_release(t);
		return -1;
	}

	/* Both lanes: the sink snapshot must predate the posting, otherwise the
	 * dropped write it is meant to expose has already happened. */
	if (npr_op_is_read(&t->op))
		npr_local_snapshot(t);

	if (plan.visible)
		npr_batch_close(ce, qs, 1, t);

	int emit_rc=npr_emit_owned(ce,qp,&t->op,NPR_ID_APP,t);
 if(emit_rc) {
  npr_submit_fail_trace(op,qp->qp_num,"app-emit",emit_rc);
		npr_if_release(t);
		return -1;
	}

	if (t->seqlock) {
		if (npr_seqlock_version_emit(ce, t, 1)) {
			t->aux2_done = 1;
			t->aux2_ok = 0;
			npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		}
	} else if (plan.aux && npr_aux_emit(ce, t)) {
		npr_aux_degrade(t);
	}
	if (debug_on())
		fprintf(stderr,
			"[nprdma] engine tracking op=%c rkey=0x%x addr=0x%llx len=%llu\n",
			npr_op_is_read(&t->op) ? 'R' : 'W', t->op.rkey,
			(unsigned long long)t->op.remote_addr,
			(unsigned long long)t->op.len);
	return 1;
}

int npr_wwi_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
		   struct npr_op *op)
{
	struct npr_qp_state *qs;
	struct npr_inflight *t;
	struct npr_plan plan;

	if (op->kind != NPR_OP_WRITE_IMM)
		return 0;
	if (!npr_route(ce, op, &plan))
		return 0;

	qs = npr_qp_get(ce, qp);
	if (!qs)
		return 0;
	t = npr_if_alloc(ce, qs);
	if (!t)
		return -1;
	t->is_wwi = 1;
	t->visible = 1;
	if (qs->sticky_err) {
		t->cover_bad = 1;
		t->sticky_claimed = 1;
		qs->sticky_err = 0;
	}
	t->imm = op->imm;
	t->op = *op;
 if(t->op.rdv_owner)npr_rdv_source_data_hold(t->op.rdv_owner);
		npr_order_get(t->op.order);

	t->op.kind = NPR_OP_WRITE;
	t->op.imm = 0;
	t->op.signaled = 1;
	t->op.inline_ = 0;
	/* The pre-check, before anything reads a version table (see
	 * npr_engine_submit): the source face of a WWI write is judged here. A face
	 * found absent has no carrier for the immediate, so this face declines the
	 * op and the passthrough pre-check fails it closed. */
	{
		struct npr_preholder h = {
			.pin = npr_prehold_pin_inflight,
			.ctx = t,
		};
		int absent = 0;

		if (npr_precheck(&t->op, &h, &absent) || absent) {
			npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
			npr_if_release(t);
			return -1;
		}
	}
	/* The write below is judged by comparing the readback with the source
	 * snapshot, so expected bytes that are the sentinel pattern would compare
	 * equal to their own drop. The data could be carried but the immediate cannot
	 * (the imm has its own lifecycle), so this op is declined instead of
	 * going out with an unverifiable write. */
	if (npr_write_ambiguous(&t->op)) {
		npr_stat_inc(NPR_STAT_AMBIGUOUS_WWI);
		npr_if_release(t);
		return -1;
	}
	if (npr_window_take(t)) {
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		npr_if_release(t);
		return -1;
	}
	t->landing = NPR_LANDING_WINDOW;

	if (t->seqlock && npr_seqlock_version_emit(ce, t, 0)) {
		npr_stat_inc(NPR_STAT_AUX_UNAVAILABLE);
		npr_if_release(t);
		return -1;
	}

	if (npr_emit_owned(ce,qp,&t->op,NPR_ID_APP,t)) {
		npr_if_release(t);
		return -1;
	}
	if (plan.visible)
		npr_batch_close(ce, qs, 1, t);

	if (npr_aux_emit(ce, t))
		npr_aux_degrade(t);
	if (debug_on())
		fprintf(stderr,
			"[nprdma] engine tracking WWI rkey=0x%x addr=0x%llx len=%llu imm=0x%08x (WRITE+WRITE_WITH_IMM)\n",
			t->op.rkey, (unsigned long long)t->op.remote_addr,
			(unsigned long long)t->op.len, be32toh(t->imm));
	return 1;
}

static int npr_rdv_app_error(struct npr_ctx_entry *,struct ibv_qp *);
static int npr_atomic_error(struct npr_ctx_entry *ce,struct ibv_qp *qp,const struct npr_op *op,enum ibv_wc_status status)
{
 struct ibv_wc wc={.wr_id=op->wr_id,.qp_num=qp->qp_num,.status=status,
  .opcode=op->atom_cas?IBV_WC_COMP_SWAP:IBV_WC_FETCH_ADD};
 if(op->order)npr_order_complete(op->order,&wc);
 else (void)npr_gate_push_wc(npr_cq_get(ce,qp->send_cq),&wc);
 (void)npr_rdv_app_error(ce,qp);return 1;
}
int npr_atomic_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
		      const struct npr_op *op)
{
	struct sir_export exp;
	struct npr_qp_state *qs;
	uint64_t old = 0, cmp = 0, arg = 0;
	int op_kind, rc;

	if (op->kind != NPR_OP_ATOMIC)
		return 0;
	if (op->num_sge != 1 || op->sge[0].length != 8 ||
	    !op->sge[0].addr)
		return 0;
 if(op->remote_state==NPR_REMOTE_FOUND) exp=op->exp;
 else if(op->remote_state==NPR_REMOTE_FOREIGN || sir_remote_lookup_cached(op->rkey,&exp)) return 0;
	if (exp.app_rkey && !(exp.app_access & IBV_ACCESS_REMOTE_ATOMIC)) {
		errno = EACCES;
		return -1;
	}

	if (op->remote_addr < exp.addr ||
	    op->remote_addr + 8 > exp.addr + exp.len)
		return 0;
	if (op->atom_cas) {
		op_kind = SIR_F_ATOMIC_CAS;
		cmp = op->atom_compare_add;
		arg = op->atom_swap;
	} else {
		op_kind = SIR_F_ATOMIC_FAA;
		arg = op->atom_compare_add;
	}

	qs = npr_qp_get(ce, qp);
	if (!qs)
		return 0;
 if(!op->atomic_sink_cpu)return npr_atomic_error(ce,qp,op,IBV_WC_LOC_PROT_ERR);

	rc = npr_wait_atomic(op->rkey, op->remote_addr,
			       op_kind, cmp, arg, &old);
 /* The owner proved that this rkey no longer names an export. The original
  * native atomic must generate the remote-access error on both application
  * QPs; synthesizing only the initiator WC leaves the responder in RTS. */
 if(rc&&errno==ENOENT)return 0;
	if (rc) {
		fprintf(stderr,
			"[nprdma] remote atomic failed (rkey=0x%x): errno=%d — WR rejected\n",
			op->rkey, errno);
		return -1;
	}
	memcpy((void *)(uintptr_t)op->atomic_sink_cpu, &old, 8);
	if (op->signaled) {
		struct ibv_wc wc;
		struct npr_cq_entry *cqe = npr_cq_get(ce, qp->send_cq);

		if (!op->order && cqe && !cqe->drift) {
			if (npr_drain_cq(ce, cqe) ||
			    npr_drain_qp_until(ce, qs, qs->if_cap)) {
				cqe->drift = 1;
				npr_log_emit("[nprdma] atomic order barrier unfinished — this CQ"
					     "drifts (fail-closed)\n");
			}
		}
		memset(&wc, 0, sizeof(wc));
		wc.wr_id    = op->wr_id;
		wc.status   = IBV_WC_SUCCESS;
		wc.opcode   = (op_kind == SIR_F_ATOMIC_CAS) ? IBV_WC_COMP_SWAP :
							 IBV_WC_FETCH_ADD;
		wc.qp_num   = qp->qp_num;
		wc.byte_len = 8;

		if (qs->sticky_err)
			wc.status = IBV_WC_GENERAL_ERR;
		if (op->order) {
			npr_order_complete(op->order, &wc);
			qs->sticky_err = 0;
		} else if (!npr_gate_push_wc(npr_cq_get(ce, qp->send_cq), &wc))
			qs->sticky_err = 0;
	}
	if (debug_on())
		fprintf(stderr,
			"[nprdma] remote atomic op=%c rkey=0x%x addr=0x%llx →"
			"old=0x%llx (SIR RPC)\n",
			op_kind == SIR_F_ATOMIC_CAS ? 'C' : 'F',
			op->rkey,
			(unsigned long long)op->remote_addr,
			(unsigned long long)old);
	return 1;
}

static int npr_rdv_cell_reserve(struct npr_ctx_entry *ce,struct ibv_cq *cq,
 uint32_t number,uint64_t generation,uint64_t epoch,uint64_t wr_id,void **out)
{
 if(!ce||!cq||!out)return EINVAL;
 *out=NULL;struct npr_cq_entry *store=npr_cq_get(ce,cq);if(!store)return ENOMEM;
 struct npr_gate_item *cell=npr_gate_reserve(store);if(!cell)return EAGAIN;
 npr_gate_get(cell);npr_gate_set_lane(cell,NPR_LANE_RQ);
 cell->generation=generation;cell->connection_epoch=epoch;cell->wc.qp_num=number;cell->wc.wr_id=wr_id;
 *out=cell;return 0;
}
static void npr_rdv_cell_discard(void *opaque)
{
 struct npr_gate_item *cell=opaque;if(!cell)return;
 cell->ready=1;cell->visible=0;npr_gate_unlink(cell);
}
static void npr_rdv_cell_complete(void *opaque,const struct ibv_wc *wc,unsigned solicited,int discard)
{
 struct npr_gate_item *cell=opaque;if(!cell)return;
 if(discard||cell->consumed)npr_rdv_cell_discard(cell);
 else {cell->wc=*wc;cell->software_solicited=!!solicited;cell->visible=1;cell->ready=1;npr_progress_ready(cell->cq_owner->cq);}
 npr_gate_put(cell);
}
static void npr_rdv_cells_discard_epoch(struct npr_ctx_entry *ce,struct ibv_cq *cq,
 uint32_t number,uint64_t generation,uint64_t epoch)
{
 if(!ce||!cq||!epoch)return;
 for(struct npr_cq_entry *store=ce->cqs;store;store=store->next)if(store->cq==cq){
  struct npr_gate_item *cell=store->first,*next;
  while(cell){next=cell->next;if(cell->wc.qp_num==number&&cell->generation==generation&&cell->connection_epoch==epoch)npr_rdv_cell_discard(cell);cell=next;}
  break;
 }
}
static void npr_rdv_source_order_done(struct npr_order_entry *order,const struct ibv_wc *wc,int discard)
{if(discard)npr_order_entry_discard(order);else npr_order_complete(order,wc);npr_order_put(order);}
static int npr_rdv_write_data_now(struct npr_ctx_entry *ce,struct ibv_qp *qp,struct npr_op *op)
{
 struct npr_op data=*op;data.kind=NPR_OP_WRITE;data.imm=0;data.signaled=1;
 data.flags=(data.flags|IBV_SEND_SIGNALED)&~IBV_SEND_SOLICITED;
 int rc=npr_engine_submit(ce,qp,&data);
 if(!rc)rc=npr_order_raw_submit(ce,qp,&data)?-1:1;
 return rc;
}
#ifdef NPR_PROGRESS_INTEGRATED
struct npr_rdv_write_job {struct npr_ctx_entry *ce;struct ibv_qp *qp;struct npr_op *op;};
static void npr_rdv_write_job(void *opaque)
{
 struct npr_rdv_write_job *job=opaque;struct npr_rdv_owner *owner=job->op->rdv_owner;
 int rc=-1;
 if(npr_rdv_source_data_begin(owner))rc=npr_rdv_write_data_now(job->ce,job->qp,job->op);
 npr_rdv_source_data_submit_done(owner,rc);free(job);
}
#endif
static int npr_rdv_write_data(struct npr_ctx_entry *ce,struct ibv_qp *qp,struct npr_op *op)
{
#ifdef NPR_PROGRESS_INTEGRATED
 struct npr_rdv_write_job *job=malloc(sizeof(*job));if(!job)return -1;
 *job=(struct npr_rdv_write_job){ce,qp,op};
 if(npr_progress_submit_for(qp->send_cq,npr_rdv_write_job,job)){free(job);return -1;}
 return 1;
#else
 int rc=-1;
 if(npr_rdv_source_data_begin(op->rdv_owner))rc=npr_rdv_write_data_now(ce,qp,op);
 npr_rdv_source_data_submit_done(op->rdv_owner,rc);return rc;
#endif
}
static int npr_rdv_app_error(struct npr_ctx_entry *ce,struct ibv_qp *qp)
{
 if(!ce||!ce->ctx||ce->closing)return EBUSY;
 struct ibv_qp_attr attr={.qp_state=IBV_QPS_ERR};
 return ibv_modify_qp(qp,&attr,IBV_QP_STATE);
}
#include "npr_rdv_native.inc"
const struct npr_rdv_cq_ops npr_rdv_gate_ops={
 .reserve=npr_rdv_cell_reserve,.complete=npr_rdv_cell_complete,.discard=npr_rdv_cell_discard,
 .discard_epoch=npr_rdv_cells_discard_epoch,.source_get=npr_order_get,.source_done=npr_rdv_source_order_done,.source_data=npr_rdv_write_data,.qp_error=npr_rdv_app_error,
 .notify_recv=npr_rdv_native_recv,.notify_send=npr_rdv_native_send
};
