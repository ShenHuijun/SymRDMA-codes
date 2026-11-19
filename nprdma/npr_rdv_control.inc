/* SPDX-License-Identifier: GPL-2.0 */
/* Included by the core: actors see copied control records, never these owners. */
#ifdef NPRDMA_TEST_INJECT
static struct npr_test_rdv_control rdv_control_proof;
#endif
static pthread_mutex_t rdv_control_mu=PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t rdv_control_cv;
static pthread_once_t rdv_control_once=PTHREAD_ONCE_INIT;
static void rdv_control_initialize(void)
{
 pthread_condattr_t a;pthread_condattr_init(&a);
 pthread_condattr_setclock(&a,CLOCK_MONOTONIC);
 pthread_cond_init(&rdv_control_cv,&a);pthread_condattr_destroy(&a);
}
static void rdv_control_signal(void)
{
 pthread_once(&rdv_control_once,rdv_control_initialize);
 pthread_mutex_lock(&rdv_control_mu);pthread_cond_broadcast(&rdv_control_cv);pthread_mutex_unlock(&rdv_control_mu);
}
static uint64_t rdv_control_head(struct npr_rdv_epoch *e,uint64_t frontier)
{
 uint64_t head=0;
 for(struct npr_rdv_owner *o=e->owners;o;o=o->next)
  if(o->source_accepted&&o->sequence<=frontier&&(!head||o->sequence<head))head=o->sequence;
 return head;
}
static void rdv_control_events(struct npr_rdv_epoch *e)
{
 if(!e->mailbox)return;
 uint64_t frontier=sir_rdv_event_frontier(e->mailbox);struct sir_rdv_drain_record r;
 while(!sir_rdv_drain_take(e->mailbox,1,frontier,&r)){
  struct rdv_control_state *c=&e->control[r.side];
  if(r.kind==SIR_RDV_DRAIN_BEGIN&&r.side==SIR_RDV_DRAIN_PEER){
   if(!c->active){
    *c=(struct rdv_control_state){.request=r,.active=1,.begun=1};
    c->request.frontier=e->next_sequence?e->next_sequence-1:UINT64_MAX;
    c->request.status=rdv_current(e,&r.id)?0:ESTALE;
   }
  }else if(r.kind==SIR_RDV_DRAIN_DONE&&c->active&&r.nonce==c->request.nonce&&rdv_identity_equal(&r.id,&c->request.id)){
   c->done=1;c->request.status=r.status;
   if(r.side==SIR_RDV_DRAIN_PEER)c->active=0;
   rdv_control_signal();
  }
  (void)sir_rdv_drain_ack(e->mailbox,1,r.side,r.serial);
 }
}
static void rdv_control_progress(struct npr_rdv_epoch *e)
{
 if(!e->mailbox)return;
 for(unsigned side=0;side<2;side++){
  struct rdv_control_state *c=&e->control[side];
  if(c->cancelling){
   struct sir_rdv_drain_record r=c->request;r.kind=SIR_RDV_DRAIN_CANCEL;
   int rc=sir_rdv_drain_publish(e->mailbox,0,&r);
   if(!rc||rc==EALREADY||rc==ESHUTDOWN)c->cancelling=0;
  }
  if(!c->active||c->done)continue;
  struct sir_rdv_drain_record r=c->request;
  r.head=rdv_control_head(e,r.frontier);
  if(e->closing||e->qp->closed||e->qp->active!=e)r.status=ESHUTDOWN;
  else if(!rdv_current(e,&r.id))r.status=ESTALE;
  r.kind=!c->begun&&side==SIR_RDV_DRAIN_LOCAL?SIR_RDV_DRAIN_BEGIN:SIR_RDV_DRAIN_HEAD;
  if(c->begun&&c->published&&c->last_head==r.head&&c->request.status==r.status)continue;
  int rc=sir_rdv_drain_publish(e->mailbox,0,&r);
  if(!rc||rc==EALREADY){c->begun=c->published=1;c->last_head=r.head;c->request.status=r.status;}
 }
}
#ifdef NPR_PROGRESS_INTEGRATED
extern unsigned npr_progress_wait_begin(void) __attribute__((visibility("hidden")));
extern void npr_progress_wait_end(unsigned) __attribute__((visibility("hidden")));
static uint64_t rdv_next_control_nonce=1;
static void rdv_control_wait(uint64_t deadline)
{
 pthread_once(&rdv_control_once,rdv_control_initialize);
 pthread_mutex_lock(&rdv_control_mu);
 unsigned depth=npr_progress_wait_begin();
 struct timespec until={.tv_sec=(time_t)(deadline/1000000000ull),.tv_nsec=(long)(deadline%1000000000ull)};
 (void)pthread_cond_timedwait(&rdv_control_cv,&rdv_control_mu,&until);
 pthread_mutex_unlock(&rdv_control_mu);npr_progress_wait_end(depth);
}
static int rdv_control_one(struct npr_rdv_qp *q,uint64_t deadline)
{
 struct npr_rdv_epoch *e=q->active;
 if(q->closed||!q->data_enabled||q->policy!=SIR_APP_QP_RENDEZVOUS_REQUIRED||!e||e->closing||!e->registration||q->native_state!=IBV_QPS_RTS||e->binding.state!=SIR_APP_QP_BOUND)return 0;
 struct crdv_stats stats;
 if(e->actor_ops.stats(e->registration,&stats)||!stats.data_ready||!rdv_stats_authorized(e,&stats))return 0;
 e->control_borrows++;
 struct rdv_control_state *c=&e->control[SIR_RDV_DRAIN_LOCAL];
 while(c->active&&!e->closing&&!q->closed&&q->active==e&&rdv_now()<deadline)rdv_control_wait(deadline);
 int rc=0;
 if(e->closing||q->closed||q->active!=e){rc=ESTALE;goto out;}
 if(c->active||rdv_now()>=deadline){rc=ETIMEDOUT;goto out;}
 if(!rdv_next_control_nonce){rc=EOVERFLOW;goto out;}
 const struct sir_app_qp_snapshot *b=&e->binding;
 *c=(struct rdv_control_state){.active=1,.request={.nonce=rdv_next_control_nonce++,
   .frontier=e->next_sequence?e->next_sequence-1:UINT64_MAX,.side=SIR_RDV_DRAIN_LOCAL,.kind=SIR_RDV_DRAIN_BEGIN,
   .id={.session_id=b->session_id,.transport_generation=b->transport_generation,.command_revision=b->command_revision,.local=b->local,.peer=b->peer}}};
#ifdef NPRDMA_TEST_INJECT
 rdv_control_proof.started++;rdv_control_proof.nonce=c->request.nonce;
 rdv_control_proof.cookie=q->key.cookie;rdv_control_proof.generation=q->key.generation;
 rdv_control_proof.connection_epoch=e->number;rdv_control_proof.frontier=c->request.frontier;
#endif
 rdv_control_progress(e);rdv_app_wake();
 while(!c->done&&!e->closing&&!q->closed&&q->active==e&&rdv_now()<deadline)rdv_control_wait(deadline);
 rc=c->done?(c->request.status==EAGAIN?0:(int)c->request.status):e->closing||q->closed||q->active!=e?ESTALE:ETIMEDOUT;
#ifdef NPRDMA_TEST_INJECT
 rdv_control_proof.result=rc;
 if(!rc){rdv_control_proof.completed++;if(c->request.status==EAGAIN)rdv_control_proof.unmatched++;}
 else if(rc==ETIMEDOUT)rdv_control_proof.timeouts++;else rdv_control_proof.aborted++;
#endif
 if(!c->done){c->request.status=(unsigned)rc;c->cancelling=1;}
 c->active=0;rdv_control_progress(e);rdv_control_signal();
out:
 assert(e->control_borrows);e->control_borrows--;rdv_app_wake();return rc;
}
int npr_rdv_control_drain_qp(struct ibv_qp *qp)
{
 for(struct npr_rdv_qp *q=rdv_qps;q;q=q->next)if(!q->closed&&q->native_qp==qp)
  return rdv_control_one(q,rdv_now()+5000000000ull);
 return 0;
}
int npr_rdv_control_drain_pd(void *context,void *pd)
{
 uint64_t deadline=rdv_now()+5000000000ull,frontier=rdv_next_qp_ordinal?rdv_next_qp_ordinal-1:UINT64_MAX,after=0;
 int result=0;
 for(;;){
  struct npr_rdv_qp *found=NULL;
  for(struct npr_rdv_qp *q=rdv_qps;q;q=q->next)
   if(!q->closed&&q->context==context&&q->pd==pd&&q->ordinal>after&&q->ordinal<=frontier&&(!found||q->ordinal<found->ordinal))found=q;
  if(!found)break;
  after=found->ordinal;
  int rc=rdv_control_one(found,deadline);if(rc&&!result)result=rc;
  if(rdv_now()>=deadline){if(!result)result=ETIMEDOUT;break;}
 }
 return result;
}
#else
int npr_rdv_control_drain_qp(struct ibv_qp *qp){(void)qp;return 0;}
int npr_rdv_control_drain_pd(void *context,void *pd){(void)context;(void)pd;return 0;}
#endif

#ifdef NPRDMA_TEST_INJECT
#include "npr_progress.h"
__attribute__((visibility("default"))) int npr_test_rdv_control_snapshot(struct npr_test_rdv_control *out)
{
 if(!out)return EINVAL;
 npr_progress_lock();*out=rdv_control_proof;out->abi=NPR_TEST_CONTROL_ABI;out->size=sizeof(*out);npr_progress_unlock();return 0;
}
#endif
