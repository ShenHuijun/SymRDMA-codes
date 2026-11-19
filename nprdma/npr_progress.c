/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include "npr_progress.h"
#include "nprdma_internal.h"
#include <dlfcn.h>
#include <fcntl.h>
#include <poll.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/epoll.h>
#include <time.h>
#include <limits.h>
#include <assert.h>
#include <sched.h>

#define JOB_LIMIT 1024
#define JOB_WORKERS 4
struct progress_job {
	struct progress_job *next, *active_next;
	void (*cb)(void *);
	void *arg;
	struct ibv_cq *cq;
	uint64_t ticket;
};
struct event_channel;
struct event_epoch {
	struct event_epoch *next;
	uint64_t frontier, generation;
	unsigned remaining;
	int frozen, delivered;
};
struct event_cq {
	struct event_cq *next;
	struct ibv_cq *cq;
	struct npr_ctx_entry *ce;
	struct event_channel *channel;
	void *context;
	unsigned queued, unacked;
	int public_events, native_armed, native_public;
 unsigned autonomous;
	int armed, solicited, raw_pending, frontier_set, pending_visible,
	    closing, orphan;
	uint64_t frontier, generation;
	int software_notified;
	struct event_epoch *epochs, **epochs_tail;
};
struct event_node {
	struct event_node *next;
	struct event_cq *cq;
};
struct event_channel {
	struct event_channel *next;
	struct ibv_comp_channel public;
	struct ibv_comp_channel *provider;
	struct event_node *head, **tail;
	unsigned getters, cqs;
	int orphan, hidden;
 int software_fd;
};
static pthread_once_t once = PTHREAD_ONCE_INIT;
static pthread_mutex_t api_mu, queue_mu = PTHREAD_MUTEX_INITIALIZER,
			       event_mu = PTHREAD_MUTEX_INITIALIZER;
/* Different predicates have different waiters: jobs, pump metadata, drain. */
static pthread_cond_t queue_cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t jobs_cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t pump_cv = PTHREAD_COND_INITIALIZER;
static pthread_cond_t event_cv = PTHREAD_COND_INITIALIZER;
static __thread unsigned api_depth, internal_depth;
/* FIFO admission prevents both a hot autonomous pump and a stream of
 * posting threads from starving the other side of the same API gate. */
static pthread_mutex_t admission_mu = PTHREAD_MUTEX_INITIALIZER;
struct admission_waiter {
 struct admission_waiter *next;
 pthread_cond_t cv;
 uint64_t ticket;
};
static struct admission_waiter *admission_head,**admission_tail=&admission_head;
static uint64_t admission_next, admission_serving;
static struct progress_job *jobs, **jobs_tail = &jobs, *active;
static unsigned job_count, waits, quiescers;
static int wake_latched; /* queue_mu: at most one outstanding pump FD token */
static uint64_t next_ticket, wake_sequence;
static struct {
	struct ibv_cq *cq;
	uint64_t ticket;
} owners[4096];
static unsigned owner_overflow, owner_count;
static int started, start_error, event_mode, mode_error;
static int wake_fd = -1;
static void (*pump_fn)(void);
static uint64_t pump_deadline;
void npr_progress_deadline(uint64_t ns)
{if(ns&&(!pump_deadline||ns<pump_deadline))pump_deadline=ns;}
static uint64_t progress_now(void)
{struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000ull+ts.tv_nsec;}
static struct event_channel *channels;
static struct event_cq *cqs;
static struct ibv_comp_channel *(*real_channel_create)(struct ibv_context *);
static int (*real_channel_destroy)(struct ibv_comp_channel *);
static int (*real_event_get)(struct ibv_comp_channel *, struct ibv_cq **,
			     void **);
static void (*real_event_ack)(struct ibv_cq *, unsigned);

static void signal_poll(void)
{
	uint64_t one = 1;
	int saved = errno;
	if (event_mode && wake_fd >= 0 && !wake_latched) {
		ssize_t n;
		do {
			n = write(wake_fd, &one, sizeof(one));
		} while (n < 0 && errno == EINTR);
        if(n==(ssize_t)sizeof(one)||(n<0&&errno==EAGAIN))wake_latched=1;
	}
	errno = saved;
}
/* queue_mu excludes signal_poll while the token is drained and re-enabled.
 * A producer after this snapshot always writes a fresh token; none can be
 * lost between the drain and clearing the latch. */
static uint64_t pump_wake_snapshot(void)
{
 uint64_t value,seen;
 pthread_mutex_lock(&queue_mu);seen=wake_sequence;
 if(event_mode){
  ssize_t n;do{n=read(wake_fd,&value,sizeof(value));}while(n==(ssize_t)sizeof(value)||(n<0&&errno==EINTR));
  wake_latched=0;
 }
 pthread_mutex_unlock(&queue_mu);return seen;
}
static void initialize(void)
{
	pthread_mutexattr_t a;
	const char *mode = getenv("SYMRDMA_CQ_PROGRESS");
	if (mode && strcmp(mode, "poll") && strcmp(mode, "event"))
		mode_error = EINVAL;
	event_mode = mode && !strcmp(mode, "event");
	wake_fd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (wake_fd < 0)
		mode_error = errno;
	pthread_mutexattr_init(&a);
	pthread_mutexattr_settype(&a, PTHREAD_MUTEX_RECURSIVE);
	pthread_mutex_init(&api_mu, &a);
	pthread_mutexattr_destroy(&a);
	real_channel_create = dlsym(RTLD_NEXT, "ibv_create_comp_channel");
	real_channel_destroy = dlsym(RTLD_NEXT, "ibv_destroy_comp_channel");
	real_event_get = dlvsym(RTLD_NEXT, "ibv_get_cq_event", "IBVERBS_1.1");
	real_event_ack = dlvsym(RTLD_NEXT, "ibv_ack_cq_events", "IBVERBS_1.1");
}
void npr_progress_lock(void)
{
	pthread_once(&once, initialize);
	if (!api_depth) {
		pthread_mutex_lock(&admission_mu);
		uint64_t ticket = admission_next++;
        if(ticket!=admission_serving){
            struct admission_waiter waiter={.cv=PTHREAD_COND_INITIALIZER,.ticket=ticket};
            *admission_tail=&waiter;admission_tail=&waiter.next;
            while(ticket!=admission_serving)pthread_cond_wait(&waiter.cv,&admission_mu);
            assert(admission_head==&waiter);admission_head=waiter.next;
            if(!admission_head)admission_tail=&admission_head;
            pthread_cond_destroy(&waiter.cv);
        }
		pthread_mutex_unlock(&admission_mu);
	}
	pthread_mutex_lock(&api_mu);
	api_depth++;
}
/* Speculative monitoring must not enqueue behind an application currently
 * driving the same native CQ. Reserve a ticket only when admission is empty;
 * existing FIFO waiters always win. Bounded misses fall back to fair admission
 * in the worker, so autonomous repair cannot starve under continuous API use. */
static int progress_try_lock(void)
{
 pthread_once(&once,initialize);
 if(api_depth){npr_progress_lock();return 1;}
 pthread_mutex_lock(&admission_mu);
 if(admission_next!=admission_serving){pthread_mutex_unlock(&admission_mu);return 0;}
 admission_next++;
 pthread_mutex_unlock(&admission_mu);
 pthread_mutex_lock(&api_mu);api_depth=1;return 1;
}
void npr_progress_unlock(void)
{
	if (api_depth) {
		api_depth--;
		pthread_mutex_unlock(&api_mu);
		if (!api_depth) {
			pthread_mutex_lock(&admission_mu);
			admission_serving++;
			if(admission_head){assert(admission_head->ticket==admission_serving);pthread_cond_signal(&admission_head->cv);}
			pthread_mutex_unlock(&admission_mu);
		}
	}
}
static unsigned suspend_gate(void)
{
	unsigned n = api_depth;
	while (api_depth)
		npr_progress_unlock();
	return n;
}
static void resume_gate(unsigned n)
{
	while (n--)
		npr_progress_lock();
}
unsigned npr_progress_wait_begin(void)
{
	pthread_mutex_lock(&queue_mu);
	waits++;
	pthread_mutex_unlock(&queue_mu);
	return suspend_gate();
}
void npr_progress_wait_end(unsigned n)
{
	resume_gate(n);
	pthread_mutex_lock(&queue_mu);
	if (waits)
		waits--;
    if(quiescers&&!job_count&&!waits)pthread_cond_broadcast(&queue_cv);
	wake_sequence++;
	pthread_cond_signal(&pump_cv);
	signal_poll();
	pthread_mutex_unlock(&queue_mu);
}
void npr_progress_internal_begin(void) { internal_depth++; }
void npr_progress_internal_end(void)
{
	if (internal_depth)
		internal_depth--;
}
int npr_progress_internal(void) { return internal_depth != 0; }
void npr_progress_wake(void)
{
	pthread_mutex_lock(&queue_mu);
	wake_sequence++;
	pthread_cond_signal(&pump_cv);
	signal_poll();
	pthread_mutex_unlock(&queue_mu);
}
void npr_progress_quiesce(void)
{
	unsigned depth = suspend_gate();
	pthread_mutex_lock(&queue_mu);
    while(job_count||waits){quiescers++;pthread_cond_wait(&queue_cv,&queue_mu);quiescers--;}
	pthread_mutex_unlock(&queue_mu);
	resume_gate(depth);
}
int npr_progress_submit_for(struct ibv_cq *cq, void (*cb)(void *), void *arg)
{
	struct progress_job *j;
	if (!cb)
		return -EINVAL;
	j = calloc(1, sizeof(*j));
	if (!j)
		return -ENOMEM;
	pthread_mutex_lock(&queue_mu);
	if (start_error || job_count == JOB_LIMIT) {
		pthread_mutex_unlock(&queue_mu);
		free(j);
		return start_error ? -start_error : -ENOMEM;
	}
	j->cb = cb;
	j->arg = arg;
	j->cq = cq;
	j->ticket = ++next_ticket;
	j->active_next = active;
	active = j;
	*jobs_tail = j;
	jobs_tail = &j->next;
	job_count++;
    pthread_cond_signal(&jobs_cv);
	wake_sequence++;
	pthread_cond_signal(&pump_cv);
	signal_poll();
	pthread_mutex_unlock(&queue_mu);
	return 0;
}
int npr_progress_submit(void (*cb)(void *), void *arg)
{
	return npr_progress_submit_for(NULL, cb, arg);
}
static void discard_epochs(struct event_cq *c)
{
	struct event_epoch *e;
	while ((e = c->epochs)) {
		c->epochs = e->next;
		free(e);
	}
	c->epochs_tail = &c->epochs;
}
static struct event_cq *find_cq(struct ibv_cq *cq)
{
	struct event_cq *c;
	for (c = cqs; c; c = c->next)
		if (c->cq == cq)
			return c;
	return NULL;
}
static __attribute__((noinline)) struct event_channel *
find_channel(struct ibv_comp_channel *p)
{
	struct event_channel *c;
	for (c = channels; c; c = c->next)
		if (&c->public == p)
			return c;
	return NULL;
}
uint64_t npr_progress_owner_begin(struct ibv_cq *cq)
{
	unsigned i;
	uint64_t t;
	pthread_mutex_lock(&queue_mu);
	for (i = 0; i < 4096; i++)
		if (!owners[i].ticket)
			break;
	if (i == 4096) {
		owner_overflow++;
		t = UINT64_MAX;
	} else {
		t = ++next_ticket;
		owners[i].cq = cq;
		owners[i].ticket = t;
	}
	owner_count++;
	pthread_mutex_unlock(&queue_mu);
	return t;
}
static void owner_end(uint64_t t,int inline_clean)
{
	unsigned i;
	struct ibv_cq *cq = NULL;
	if (!t)
		return;
	pthread_mutex_lock(&queue_mu);
	if (t == UINT64_MAX) {
		if (owner_overflow) {owner_overflow--;owner_count--;}
	} else
		for (i = 0; i < 4096; i++)
			if (owners[i].ticket == t) {
				cq = owners[i].cq;
                owner_count--;
				owners[i].ticket = 0;
				owners[i].cq = NULL;
				break;
			}
 pthread_mutex_unlock(&queue_mu);
 if(cq)npr_progress_ready(cq);
 /* CLEAN release has no PIN/window/identity cleanup left. Keep the wake for
  * overflow (which gates every CQ), queued work, async tasks and retries. */
 if(!inline_clean||t==UINT64_MAX||!cq||!npr_progress_cq_caller_driven(cq))npr_progress_wake();
}
void npr_progress_owner_end(uint64_t t){owner_end(t,0);}
void npr_progress_owner_end_inline_clean(uint64_t t){owner_end(t,1);}

static int frontier_done(struct event_cq *c, uint64_t frontier)
{
	struct progress_job *j;
	unsigned i;
	int done = 1;
	pthread_mutex_lock(&queue_mu);
	if (owner_overflow)
		done = 0;
	for (j = active; j; j = j->active_next)
		if (j->cq == c->cq && j->ticket <= frontier) {
			done = 0;
			break;
		}
	for (i = 0; i < 4096; i++)
		if (owners[i].cq == c->cq && owners[i].ticket &&
		    owners[i].ticket <= frontier) {
			done = 0;
			break;
		}
	pthread_mutex_unlock(&queue_mu);
	return done;
}
static int publish_event(struct event_cq *c, struct event_epoch *epoch)
{
	struct event_node *n, **slot;
	struct event_epoch *e;
	uint64_t one = 1;
	ssize_t rc;
	if (!c->channel || !c->public_events || (!epoch && !c->armed))
		return 0;
	n = calloc(1, sizeof(*n));
	if (!n)
		return 0;
	n->cq = c;
	slot = c->channel->tail;
	*slot = n;
	c->channel->tail = &n->next;
	c->queued++;
	do {
		rc = write(c->channel->software_fd, &one, sizeof(one));
	} while (rc < 0 && errno == EINTR);
	if (rc != (ssize_t)sizeof(one)) {
		*slot = NULL;
		c->channel->tail = slot;
		c->queued--;
		free(n);
		return 0;
	}
	if (!epoch || epoch->generation == c->generation) {
		c->armed = 0;
		c->pending_visible = 0;
		c->software_notified = 1;
		for (e = c->epochs; e; e = e->next)
			if (e->generation == c->generation)
				e->delivered = 1;
	}
	return 1;
}

void npr_progress_cq_observed(struct ibv_cq *cq)
{
	struct event_cq *c;
	struct event_epoch *e;
	uint64_t frontier;
	pthread_mutex_lock(&event_mu);
	c = find_cq(cq);
	if (c) {
		pthread_mutex_lock(&queue_mu);
		frontier = next_ticket;
		pthread_mutex_unlock(&queue_mu);
		for (e = c->epochs; e; e = e->next)
			if (!e->frozen && e->remaining && !--e->remaining) {
				e->frontier = frontier;
				e->frozen = 1;
			}
	}
	pthread_mutex_unlock(&event_mu);
}

void npr_progress_cq_drained(struct ibv_cq *cq)
{
	struct event_cq *c;
	struct event_epoch *e;
	uint64_t frontier;
	pthread_mutex_lock(&event_mu);
	c = find_cq(cq);
	if (c) {
		pthread_mutex_lock(&queue_mu);
		frontier = next_ticket;
		pthread_mutex_unlock(&queue_mu);
		for (e = c->epochs; e; e = e->next)
			if (!e->frozen) {
				e->frontier = frontier;
				e->frozen = 1;
			}
	}
	pthread_mutex_unlock(&event_mu);
}

void npr_progress_ready(struct ibv_cq *cq)
{
	struct event_cq *c;
	struct npr_cq_entry *q;
	struct ibv_wc wc;
 unsigned solicited;
	pthread_mutex_lock(&event_mu);
	c = find_cq(cq);
	/* Poll-only and internal event-channel CQs have no public event sink.
	 * Provider arming, event draining and acknowledgements are handled by
	 * the pump; walking software notification candidates cannot publish. */
	if (!c || !c->public_events) {
		pthread_mutex_unlock(&event_mu);
		return;
	}
	q = c->ce ? npr_cq_get(c->ce, cq) : NULL;
	while (q && npr_gate_next_notification(q, &wc, &solicited))
		if (c->armed && (!c->solicited || solicited || wc.status != IBV_WC_SUCCESS))
			c->pending_visible = 1;
	if (c->armed && c->pending_visible)
		publish_event(c, NULL);
	while (c->epochs && c->epochs->frozen &&
	       frontier_done(c, c->epochs->frontier)) {
		struct event_epoch *e = c->epochs;
		if (!e->delivered && !publish_event(c, e))
			break;
		c->epochs = e->next;
		if (!c->epochs)
			c->epochs_tail = &c->epochs;
		free(e);
	}
	pthread_mutex_unlock(&event_mu);
}
static int collect_native_events_for(struct event_channel *only)
{
 int error=0;
	struct event_channel *ch;
	pthread_mutex_lock(&event_mu);
	for (ch = channels; ch; ch = ch->next)
        if(only?ch==only:ch->hidden)
		for (; !ch->orphan;) {
			struct pollfd p = {.fd = ch->provider->fd,
					   .events = POLLIN};
			struct ibv_cq *cq;
			void *ctx;
			struct event_cq *c;
			struct event_epoch *e;
			if (poll(&p, 1, 0) <= 0 || !(p.revents & POLLIN))
				break;
			e = calloc(1, sizeof(*e));
			if (!e){error=ENOMEM;break;}
			if (real_event_get(ch->provider, &cq, &ctx)) {
                if(errno!=EAGAIN&&errno!=EWOULDBLOCK)error=errno?errno:EIO;
				free(e);
				break;
			}
			if (!cq) {
				npr_log_emit("[nprdma] provider returned a CQ "
					     "event without a modern CQ handle "
					     "(ABI failure)\n");
				free(e);
				break;
			}
			real_event_ack(cq, 1);
			c = find_cq(cq);
			if (c)
				c->native_armed = 0;
			if (c && !c->orphan && c->public_events && c->native_public) {
				e->remaining =
				    cq->cqe > 0 ? (unsigned)cq->cqe : 1;
				e->generation = c->generation;
				e->delivered = c->software_notified;
				*c->epochs_tail = e;
				c->epochs_tail = &e->next;
			} else
				free(e);
		}
	pthread_mutex_unlock(&event_mu);
 return error;
}
static void collect_native_events(void){(void)collect_native_events_for(NULL);}
static int deferred_work(void)
{
 int active;pthread_mutex_lock(&queue_mu);active=job_count||waits;pthread_mutex_unlock(&queue_mu);return active;
}
int npr_progress_cq_autonomous_begin(struct ibv_cq *cq)
{
 int held=0,wake=0;pthread_mutex_lock(&event_mu);struct event_cq *c=find_cq(cq);
 if(c){wake=!c->autonomous;c->autonomous++;held=1;}pthread_mutex_unlock(&event_mu);
 if(wake)npr_progress_wake();
 return held;
}
void npr_progress_cq_autonomous_end(struct ibv_cq *cq)
{
 pthread_mutex_lock(&event_mu);struct event_cq *c=find_cq(cq);
 if(c&&c->autonomous)c->autonomous--;
 pthread_mutex_unlock(&event_mu);
}
static int cq_background_needed(struct event_cq *c,int active)
{
 /* Ordinary queued READ/WRITE is driven by the caller, including ordering
  * barriers. Control/other operations retain autonomous dispatch. */
 struct npr_cq_entry *q=c->ce?npr_cq_get(c->ce,c->cq):NULL;
 int deferred=c->ce&&(!q||q->order_background_deferred);
 return deferred||c->autonomous||active||
  (c->armed&&c->pending_visible)||
  (c->epochs&&c->epochs->frozen&&frontier_done(c,c->epochs->frontier));
}
int npr_progress_cq_caller_driven(struct ibv_cq *cq)
{
 int caller=0,active=deferred_work();pthread_mutex_lock(&event_mu);struct event_cq *c=find_cq(cq);
 if(c)caller=!cq_background_needed(c,active);
 pthread_mutex_unlock(&event_mu);return caller;
}
/* API gate held. Drain only this public channel so consuming one provider
 * event cannot remove another channel's sole readiness indication. */
static int progress_channel(struct event_channel *ch,int rearm)
{
 int error=collect_native_events_for(ch);struct event_cq *c;
 for(c=cqs;c;c=c->next)if(c->channel==ch&&c->ce&&!c->orphan){
  struct npr_cq_entry *q=npr_cq_get(c->ce,c->cq);if(!q){error=ENOMEM;continue;}
  if(npr_drain_cq(c->ce,q)<0){error=errno?errno:EIO;continue;}
  npr_progress_ready(c->cq);
  if(rearm&&c->armed&&!c->native_armed&&c->ce->real_req_notify_cq){
   int rc=c->ce->real_req_notify_cq(c->cq,0);
   if(!rc){
    c->native_armed=1;c->native_public=0;
    /* Arm/recheck closes the empty-CQ -> sleep arrival race. The
     * progress-only event must not create a solicited public epoch. */
    if(npr_drain_cq(c->ce,q)<0)error=errno?errno:EIO;
    npr_progress_ready(c->cq);
   }else error=rc>0?rc:(errno?errno:EIO);
  }
 }
 return error;
}
static void *job_worker(void *unused)
{
	(void)unused;
	for (;;) {
		struct progress_job *j, **p;
		pthread_mutex_lock(&queue_mu);
        while(!jobs)pthread_cond_wait(&jobs_cv,&queue_mu);
		j = jobs;
		jobs = j->next;
		if (!jobs)
			jobs_tail = &jobs;
		pthread_mutex_unlock(&queue_mu);
		npr_progress_lock();
		j->cb(j->arg);
		pthread_mutex_lock(&queue_mu);
		for (p = &active; *p; p = &(*p)->active_next)
			if (*p == j) {
				*p = j->active_next;
				break;
			}
		job_count--;
        if(quiescers&&!job_count&&!waits)pthread_cond_broadcast(&queue_cv);
		wake_sequence++;
		pthread_cond_signal(&pump_cv);
		signal_poll();
		pthread_mutex_unlock(&queue_mu);
		if (j->cq) {
			npr_progress_ready(j->cq);
		}
		free(j);
		npr_progress_unlock();
	}
	return NULL;
}
/* Public provider readiness is shared with the application, never consumed
 * here. Watch it only while an eligible CQ has a non-solicited native arm.
 * After native owners retire, an unread provider token must not spin the pump. */
static int channel_waitable(struct event_channel *ch,int active)
{
 if(ch->orphan||!ch->cqs)return 0;
 if(ch->hidden)return 1;
 for(struct event_cq *c=cqs;c;c=c->next)
  if(c->channel==ch&&c->ce&&!c->orphan&&cq_background_needed(c,active)&&
     c->armed&&!c->solicited&&c->native_armed)return 1;
 return 0;
}
static struct pollfd *interrupt_wait_set(nfds_t *count, int *busy)
{
	struct event_cq *c;
	struct event_channel *ch;
	struct pollfd *fds;
	nfds_t n = 1, i = 1;
	*busy = 0;
	*count = 0;
 int active=deferred_work();
	pthread_mutex_lock(&event_mu);
	for (c = cqs; c; c = c->next) {
        if(!cq_background_needed(c,active))continue;
		if (c->ce && !c->orphan) {
			/* Allocation failure retains eligibility. Memory
			 * recovery is not an FD wake source, so a publishable
			 * event must be retried before sleeping. */
			if ((c->armed && c->pending_visible) ||
			    (c->epochs && c->epochs->frozen &&
			     frontier_done(c, c->epochs->frontier)))
				*busy = 1;
			if (!c->channel) {
				*busy = 1;
				continue;
			}
			if (c->channel->hidden) {
				if (!c->native_armed) {
					int rc =
					    c->ce->real_req_notify_cq
						? c->ce->real_req_notify_cq(
						      c->cq, 0)
						: ENOSYS;
					if (rc)
						*busy = 1;
					else
						c->native_armed = 1;
				}
			} else if (!(c->armed && !c->solicited &&
				     c->native_armed))
				*busy = 1;
		}
    }
	for (ch = channels; ch; ch = ch->next)
		if (channel_waitable(ch,active))
			n++;
	fds = calloc(n, sizeof(*fds));
	if (fds) {
		fds[0].fd = wake_fd;
		fds[0].events = POLLIN;
		for (ch = channels; ch; ch = ch->next)
			if (channel_waitable(ch,active)) {
				fds[i].fd = ch->provider->fd;
				fds[i].events = POLLIN;
				i++;
			}
		*count = i;
	} else
		*busy = 1;
	pthread_mutex_unlock(&event_mu);
	return fds;
}
static void *progress_worker(void *unused)
{
	(void)unused;
 unsigned admission_misses=0;
	for (;;) {
		int has_cq = 0, busy = 0;
		struct event_cq *c;
		uint64_t seen;
		struct pollfd *fds = NULL;
		nfds_t nfds = 0;
		seen = pump_wake_snapshot();
        if(!progress_try_lock()){
            if(++admission_misses<32){sched_yield();continue;}
            npr_progress_lock();
        }
        admission_misses=0;
		pump_deadline=0;
		collect_native_events();
		if (pump_fn)
			pump_fn();
        int active=deferred_work();
		pthread_mutex_lock(&event_mu);
		for (c = cqs; c; c = c->next)
			if (c->ce&&cq_background_needed(c,active)) {
				has_cq = 1;
				break;
			}
		pthread_mutex_unlock(&event_mu);
		if (event_mode) {
			fds = interrupt_wait_set(&nfds, &busy);
			/* Arm then recheck. Do not consume the native event
			 * after this recheck: either the CQ is still empty or
			 * its event remains ready for poll(). */
			if (pump_fn)
				pump_fn();
		}
		uint64_t deadline=pump_deadline;
		npr_progress_unlock();
		if (event_mode && !busy && fds) {
			int rc;
			do {
				uint64_t now=progress_now();
				int timeout=!deadline?-1:deadline<=now?0:(int)(((deadline-now+999999)/1000000)>INT_MAX?INT_MAX:(deadline-now+999999)/1000000);
				rc = poll(fds, nfds, timeout);
			} while (rc < 0 && errno == EINTR);
		} else if (!has_cq) {
			pthread_mutex_lock(&queue_mu);
			while (wake_sequence == seen) {
                if(!deadline)pthread_cond_wait(&pump_cv,&queue_mu);
                else {
                    uint64_t now=progress_now();if(now>=deadline)break;
                    struct timespec until;clock_gettime(CLOCK_REALTIME,&until);
                    uint64_t nsec=(uint64_t)until.tv_nsec+deadline-now;
                    until.tv_sec+=nsec/1000000000ull;until.tv_nsec=nsec%1000000000ull;
                    if(pthread_cond_timedwait(&pump_cv,&queue_mu,&until)==ETIMEDOUT)break;
                }
            }
			pthread_mutex_unlock(&queue_mu);
		}
		free(fds);
	}
	return NULL;
}

int npr_progress_start(void (*pump)(void))
{
	pthread_t t;
	unsigned i;
	int rc = 0;
	pthread_once(&once, initialize);
	if (mode_error)
		return mode_error;
	pthread_mutex_lock(&queue_mu);
	if (started) {
		rc = start_error;
		pthread_mutex_unlock(&queue_mu);
		return rc;
	}
	pump_fn = pump;
	started = 1;
	for (i = 0; i < JOB_WORKERS; i++) {
		rc = pthread_create(&t, NULL, job_worker, NULL);
		if (rc)
			break;
		pthread_detach(t);
	}
	if (!rc) {
		rc = pthread_create(&t, NULL, progress_worker, NULL);
		if (!rc)
			pthread_detach(t);
	}
	start_error = rc;
	pthread_mutex_unlock(&queue_mu);
	return rc;
}
int npr_progress_channel_is_proxy(struct ibv_comp_channel *p)
{
	int yes;
	pthread_mutex_lock(&event_mu);
	yes = find_channel(p) != NULL;
	pthread_mutex_unlock(&event_mu);
	return yes;
}
struct ibv_comp_channel *
npr_progress_provider_channel(struct ibv_comp_channel *p)
{
	struct event_channel *c;
	struct ibv_comp_channel *r = p;
	pthread_mutex_lock(&event_mu);
	c = find_channel(p);
	if (c)
		r = c->provider;
	pthread_mutex_unlock(&event_mu);
	return r;
}
static void hidden_channel_release(struct event_channel *ch)
{
	struct event_channel **p;
	if (!ch || !ch->hidden || ch->cqs)
		return;
 pthread_mutex_lock(&queue_mu);signal_poll();pthread_mutex_unlock(&queue_mu);
	if (real_channel_destroy(ch->provider))
		return;
	for (p = &channels; *p; p = &(*p)->next)
		if (*p == ch) {
			*p = ch->next;
			break;
		}
	free(ch);
}
struct ibv_comp_channel *
npr_progress_cq_provider_channel(struct ibv_context *ctx,
				 struct ibv_comp_channel *public)
{
	struct event_channel *ch;
	struct ibv_comp_channel *provider;
	int saved;
	pthread_once(&once, initialize);
	errno = 0;
	if (mode_error) {
		errno = mode_error;
		return NULL;
	}
	if (public)
		return npr_progress_provider_channel(public);
	if (!event_mode)
		return NULL;
	pthread_mutex_lock(&event_mu);
	for (ch = channels; ch; ch = ch->next)
		if (ch->hidden && !ch->orphan && ch->public.context == ctx)
			break;
	pthread_mutex_unlock(&event_mu);
	if (ch)
		return ch->provider;
	if (!real_channel_create || !real_channel_destroy || !real_event_get ||
	    !real_event_ack) {
		errno = ENOSYS;
		return NULL;
	}
	provider = real_channel_create(ctx);
	if (!provider)
		return NULL;
	ch = calloc(1, sizeof(*ch));
	if (!ch) {
		saved = errno;
		real_channel_destroy(provider);
		errno = saved;
		return NULL;
	}
	ch->provider = provider;
	ch->public.context = ctx;
	ch->public.fd = -1;
	ch->hidden = 1;
	ch->tail = &ch->head;
	fcntl(provider->fd, F_SETFL, fcntl(provider->fd, F_GETFL) | O_NONBLOCK);
	pthread_mutex_lock(&event_mu);
	ch->next = channels;
	channels = ch;
	pthread_mutex_unlock(&event_mu);
	return provider;
}
struct ibv_comp_channel *npr_progress_cq_native_channel(struct ibv_cq *cq)
{
	struct event_cq *c;
	struct ibv_comp_channel *result;
	pthread_mutex_lock(&event_mu);
	c = find_cq(cq);
	result = c && c->channel ? c->channel->provider : cq->channel;
	pthread_mutex_unlock(&event_mu);
	return result;
}
void npr_progress_cq_prepare_cancel(struct ibv_context *ctx,
				    struct ibv_comp_channel *public,
				    struct ibv_comp_channel *provider)
{
	struct event_channel *ch;
	(void)ctx;
	if (public || !provider)
		return;
	pthread_mutex_lock(&event_mu);
	for (ch = channels; ch; ch = ch->next)
		if (ch->provider == provider)
			break;
	hidden_channel_release(ch);
	pthread_mutex_unlock(&event_mu);
}
int npr_progress_cq_attach(struct ibv_cq *cq, struct ibv_comp_channel *channel,
			   void *context)
{
	struct event_cq *c = calloc(1, sizeof(*c));
	if (!c)
		return ENOMEM;
	c->cq = cq;
	c->ce = context;
	c->context = cq->cq_context;
	c->epochs_tail = &c->epochs;
	pthread_mutex_lock(&event_mu);
	c->channel = find_channel(channel);
	if (!channel) {
		struct event_channel *ch;
		for (ch = channels; ch; ch = ch->next)
			if (ch->hidden && ch->provider == cq->channel) {
				c->channel = ch;
				break;
			}
	}
	c->public_events = channel && c->channel && !c->channel->hidden;
	if (c->channel) {
		c->channel->cqs++;
		c->channel->public.refcnt++;
		cq->channel = channel;
	}
	c->next = cqs;
	cqs = c;
	pthread_mutex_unlock(&event_mu);
	npr_progress_wake();
	return 0;
}
int npr_progress_cq_can_destroy(struct ibv_cq *cq)
{
	struct event_cq *c;
	unsigned depth;
	/* The caller holds the engine gate and has quiesced this CQ's
	 * work. Drain native event reports before destroying a provider
	 * CQ, whose destroy waits for the corresponding provider
	 * acknowledgements. */
    pthread_mutex_lock(&event_mu);c=find_cq(cq);struct event_channel *ch=c?c->channel:NULL;pthread_mutex_unlock(&event_mu);
    if(ch)progress_channel(ch,0);
	if (pump_fn)
		pump_fn();
	pthread_mutex_lock(&event_mu);
	c = find_cq(cq);
	if (!c) {
		pthread_mutex_unlock(&event_mu);
		return 0;
	}
	if (c->closing) {
		pthread_mutex_unlock(&event_mu);
		return EBUSY;
	}
	c->closing = 1;
	/* Match uverbs: only events already read by the application need ack.
  * Unread nodes remain intact if native destruction fails, and are purged
  * on successful detach, like the kernel's CQ completion-event list. */
 while (c->unacked) {
		depth = suspend_gate();
		pthread_cond_wait(&event_cv, &event_mu);
		pthread_mutex_unlock(&event_mu);
		resume_gate(depth);
		pthread_mutex_lock(&event_mu);
	}
	pthread_mutex_unlock(&event_mu);
	return 0;
}

void npr_progress_cq_destroy_abort(struct ibv_cq *cq)
{
	struct event_cq *c;
	pthread_mutex_lock(&event_mu);
	c = find_cq(cq);
	if (c)
		c->closing = 0;
	pthread_mutex_unlock(&event_mu);
}

/* event_mu held. Software eventfd tokens are interchangeable semaphore
 * units; remove one per discarded node, preserving every other CQ's unit. */
static void discard_queued_events(struct event_cq *c)
{
 struct event_channel *ch=c->channel;
 if(!ch)return;
 struct event_node **p=&ch->head,*n;
 while((n=*p)){
  if(n->cq!=c){p=&n->next;continue;}
  uint64_t value;ssize_t rc;
  do{rc=read(ch->software_fd,&value,sizeof(value));}while(rc<0&&errno==EINTR);
  if(rc!=(ssize_t)sizeof(value))npr_log_emit("[nprdma] CQ event token drift on detach\n");
  *p=n->next;c->queued--;free(n);
 }
 ch->tail=p;
}
void npr_progress_cq_detach(struct ibv_cq *cq)
{
	struct event_cq **p, *c;
	pthread_mutex_lock(&event_mu);
	for (p = &cqs; (c = *p); p = &c->next)
		if (c->cq == cq) {
			*p = c->next;
   discard_queued_events(c);
			if (c->channel) {
				c->channel->cqs--;
				c->channel->public.refcnt--;
				hidden_channel_release(c->channel);
			}
			discard_epochs(c);
			free(c);
			break;
		}
	pthread_mutex_unlock(&event_mu);
}
void npr_progress_context_closed(void *opaque)
{
	struct event_cq **p, *c;
	struct event_channel *ch;
	struct npr_ctx_entry *ce = opaque;
	pthread_mutex_lock(&event_mu);
	for (ch = channels; ch; ch = ch->next)
		if (ch->public.context == ce->ctx)
			ch->orphan = 1;
	for (p = &cqs; (c = *p);) {
		if (c->ce != ce) {
			p = &c->next;
			continue;
		}
		discard_epochs(c);
		c->ce = NULL;
		c->closing = c->orphan = 1;
		c->armed = c->raw_pending = c->frontier_set = 0;
		if (c->queued || c->unacked) {
			p = &c->next;
			continue;
		}
		*p = c->next;
		if (c->channel) {
			c->channel->cqs--;
			c->channel->public.refcnt--;
			hidden_channel_release(c->channel);
		}
		free(c);
	}
	pthread_cond_broadcast(&event_cv);
	pthread_mutex_unlock(&event_mu);
	npr_progress_wake();
}

int npr_progress_notify(struct ibv_cq *cq, int solicited)
{
	struct event_cq *c;
	int rc = 0;
	npr_progress_lock();
 /* Capture a previous public notification under its original generation.
  * Hidden-only background collection deliberately cannot consume this fd. */
 pthread_mutex_lock(&event_mu);c=find_cq(cq);
 struct event_channel *ch=c?c->channel:NULL;
 pthread_mutex_unlock(&event_mu);
 int error=ch?collect_native_events_for(ch):0;
 if(error){npr_progress_unlock();return error;}
	npr_progress_ready(cq);
	pthread_mutex_lock(&event_mu);
	c = find_cq(cq);
	if (!c || c->closing) {
		pthread_mutex_unlock(&event_mu);
		npr_progress_unlock();
		return c ? EBUSY : EINVAL;
	}
	if (c->ce && c->ce->real_req_notify_cq)
		rc = c->ce->real_req_notify_cq(
		    cq, c->channel && c->channel->hidden ? 0 : solicited);

	if (!rc) {
		c->native_armed = 1;c->native_public=1;
		c->generation++;
		c->software_notified = 0;
		c->armed = 1;
		c->solicited = !!solicited;
		c->pending_visible = 0;
	}
	pthread_mutex_unlock(&event_mu);

 /* The public provider fd wakes the application's event waiter directly.
  * Only autonomous/repair work needs to wake the background pump as well. */
 int caller=npr_progress_cq_caller_driven(cq);
 npr_progress_unlock();
 if(!caller)npr_progress_wake();
 return rc;
}
struct ibv_comp_channel *ibv_create_comp_channel(struct ibv_context *ctx)
{
	struct event_channel *c;
	struct ibv_comp_channel *p;
	pthread_once(&once, initialize);
	if (!real_channel_create || !real_channel_destroy || !real_event_get ||
	    !real_event_ack) {
		errno = ENOSYS;
		return NULL;
	}
	p = real_channel_create(ctx);
	if (!p || internal_depth)
		return p;
	c = calloc(1, sizeof(*c));
	if (!c) {
		real_channel_destroy(p);
		return NULL;
	}
	c->public.context = ctx;
 c->public.fd=epoll_create1(EPOLL_CLOEXEC);
 c->software_fd=eventfd(0,EFD_CLOEXEC|EFD_SEMAPHORE|EFD_NONBLOCK);
 struct epoll_event ev={.events=EPOLLIN,.data.u32=1};int failed=c->public.fd<0||c->software_fd<0;
 if(!failed)failed=epoll_ctl(c->public.fd,EPOLL_CTL_ADD,p->fd,&ev)<0;
 ev.data.u32=2;
 if(!failed)failed=epoll_ctl(c->public.fd,EPOLL_CTL_ADD,c->software_fd,&ev)<0;
 if(failed){int saved=errno;if(c->public.fd>=0)close(c->public.fd);if(c->software_fd>=0)close(c->software_fd);free(c);real_channel_destroy(p);errno=saved;return NULL;}
	c->provider = p;
	c->tail = &c->head;
	fcntl(p->fd, F_SETFL, fcntl(p->fd, F_GETFL) | O_NONBLOCK);
	pthread_mutex_lock(&event_mu);
	c->next = channels;
	channels = c;
	pthread_mutex_unlock(&event_mu);
	return &c->public;
}
int ibv_destroy_comp_channel(struct ibv_comp_channel *p)
{
	struct event_channel *c, **q;
	int rc;
	pthread_once(&once, initialize);
	pthread_mutex_lock(&event_mu);
	c = find_channel(p);
	if (!c) {
		pthread_mutex_unlock(&event_mu);
		if (real_channel_destroy)
			return real_channel_destroy(p);
		errno = ENOSYS;
		return -1;
	}
	if (c->cqs || c->head || c->getters) {
		pthread_mutex_unlock(&event_mu);
		return EBUSY;
	}
	rc = real_channel_destroy(c->provider);
	if (rc) {
		pthread_mutex_unlock(&event_mu);
		return rc;
	}
	for (q = &channels; *q; q = &(*q)->next) {
		if (*q == c) {
			*q = c->next;
			break;
		}
	}
	close(c->public.fd);close(c->software_fd);
	free(c);
	pthread_mutex_unlock(&event_mu);
	return 0;
}
static void getter_cancelled(void *opaque)
{
	struct event_channel *c = opaque;
	pthread_mutex_lock(&event_mu);
	if (c->getters)
		c->getters--;
	pthread_cond_broadcast(&event_cv);
	pthread_mutex_unlock(&event_mu);
}
int ibv_get_cq_event(struct ibv_comp_channel *p, struct ibv_cq **cq,void **context)
{
 struct event_channel *c;struct event_node *node=NULL;volatile int result=-1,saved=0;
 pthread_once(&once,initialize);pthread_mutex_lock(&event_mu);c=find_channel(p);
 if(!c){pthread_mutex_unlock(&event_mu);return real_event_get?real_event_get(p,cq,context):-1;}
 c->getters++;pthread_mutex_unlock(&event_mu);
 pthread_cleanup_push(getter_cancelled,c);
 for(;;){
  struct epoll_event ev[2];int nonblock=fcntl(p->fd,F_GETFL)&O_NONBLOCK;
  int n=epoll_wait(p->fd,ev,2,nonblock?0:-1);
  if(n<0){saved=errno;break;}if(!n){saved=EAGAIN;break;}
  int fd_error=0;for(int i=0;i<n;i++)if(ev[i].events&(EPOLLERR|EPOLLHUP))fd_error=EIO;
  int oldstate;pthread_setcancelstate(PTHREAD_CANCEL_DISABLE,&oldstate);
  npr_progress_lock();int progress_error=progress_channel(c,1);
  pthread_mutex_lock(&event_mu);
  if(c->head){
   uint64_t value;
   if(read(c->software_fd,&value,sizeof(value))==(ssize_t)sizeof(value)){
    node=c->head;c->head=node->next;if(!c->head)c->tail=&c->head;
    node->cq->queued--;node->cq->unacked++;*cq=node->cq->cq;*context=node->cq->context;
    pthread_cond_broadcast(&event_cv);free(node);result=0;
   }
  }
  pthread_mutex_unlock(&event_mu);npr_progress_unlock();
  pthread_setcancelstate(oldstate,NULL);
  if(!result)break;
  if(progress_error||fd_error){saved=progress_error?progress_error:fd_error;break;}
 }
 pthread_cleanup_pop(0);
 pthread_mutex_lock(&event_mu);c->getters--;pthread_cond_broadcast(&event_cv);pthread_mutex_unlock(&event_mu);
 if(result)errno=saved;
 return result;
}
void ibv_ack_cq_events(struct ibv_cq *cq, unsigned n)
{
	struct event_cq *c;
	pthread_once(&once, initialize);
	pthread_mutex_lock(&event_mu);
	c = find_cq(cq);
	if (c) {
		if (n <= c->unacked)
			c->unacked -= n;
		pthread_cond_broadcast(&event_cv);
		if (c->orphan && !c->queued && !c->unacked) {
			struct event_cq **p;
			for (p = &cqs; *p; p = &(*p)->next)
				if (*p == c) {
					*p = c->next;
					break;
				}
			if (c->channel) {
				c->channel->cqs--;
				c->channel->public.refcnt--;
				hidden_channel_release(c->channel);
			}
			discard_epochs(c);
			free(c);
		}
		pthread_mutex_unlock(&event_mu);
		return;
	}
	pthread_mutex_unlock(&event_mu);
	if (real_event_ack)
		real_event_ack(cq, n);
}
