/* SPDX-License-Identifier: GPL-2.0 */
#include "npr_rendezvous.h"
#include "npr_op.h"
#include "npr_native_notify.h"
#include <time.h>
#ifdef NPR_PROGRESS_INTEGRATED
extern void npr_progress_wake(void) __attribute__((visibility("hidden")));
extern void npr_progress_deadline(uint64_t) __attribute__((visibility("hidden")));
static void rdv_deadline(uint64_t ns){npr_progress_deadline(ns);}
static void rdv_app_wake(void){npr_progress_wake();}
#else
static void rdv_app_wake(void){}
static void rdv_deadline(uint64_t ns){(void)ns;}
#endif
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
struct rdv_fd {int original,duplicate;};
struct rdv_attempt {
 struct sir_rdv_record event;
 struct crdv_offer_snapshot snapshot;
 unsigned active,no_rq,reply_sent,backpressure_sent;
 int preparation_error;
};
struct rdv_native_credit {
 struct rdv_native_credit *next,*ready_next;
 struct npr_rdv_epoch *epoch;
 uint64_t rq_token;
 unsigned done,processed,rq_done,decoded,queued;
 struct ibv_wc wc;
 struct npr_notify_message message;
 unsigned char bytes[NPR_NOTIFY_BYTES];
};
struct npr_rdv_owner {
 struct npr_rdv_owner *next;
 struct npr_rdv_epoch *epoch;
 struct sir_rdv_identity identity;
 struct sir_rdv_value value,event_value[SIR_RDV_EVENT_N];
 unsigned event_evidence[SIR_RDV_EVENT_N];
 struct npr_mra_capture *captures;
 struct sir_rdv_span *spans;
 struct rdv_fd *fds;
 size_t nspan,ncap,nfd,capacity;
 struct npr_op *source_op;
 struct npr_order_entry *source_order;
 uint64_t sequence,bind_deadline,source_visit;
 unsigned source_prepared,source_accepted,source_dispatch,source_bound,source_cancel,source_discard;
 unsigned data_started,data_pending,data_done,data_owned,processing,data_submit_failed,wwi_result_submitted;
 unsigned native_notify,notify_pending,notify_done;
 enum ibv_wc_status notify_status;
 enum ibv_wc_status data_status;
 enum ibv_wc_status source_status;
 uint64_t app_token,mailbox_token;
 unsigned role,events,released,published,adopted,callback_held;
 uint64_t rq_token;
 void *cell;
 enum ibv_wc_status rx_status,tx_status;
 unsigned planned_spans,release_evidence;
 int source_memory_error;
 int release_status;
};
struct rdv_control_state {
 struct sir_rdv_drain_record request;
 uint64_t last_head;
 unsigned active,done,begun,published,cancelling;
};
struct npr_rdv_epoch {
 struct npr_rdv_epoch *next;
 struct npr_rdv_qp *qp;
 struct npr_rq *rq;
 struct sir_rdv_mailbox *mailbox;
 struct npr_rdv_owner *owners;
 struct crdv_registration *registration;
 struct npr_rdv_actor_ops actor_ops;
 struct rdv_attempt *attempts;
 size_t attempt_capacity,attempt_extent;
 struct sir_app_qp_key stream_peer;
 uint64_t stream_peer_epoch;
 unsigned stream_active;
 uint64_t number,next_sequence,pending_sources,source_visit,pump_visit;
 struct sir_app_qp_snapshot binding;
 unsigned committed,closing,control_borrows,ever_bound;
 unsigned native_refs;
 struct rdv_native_credit *credits,*credit_last,*ready_credits,*ready_last;
 struct rdv_control_state control[2];
};
struct npr_rdv_qp {
 struct npr_rdv_qp *next;
 struct npr_ctx_entry *ce;
 void *context,*pd;
 struct ibv_cq *send_cq,*recv_cq;
 struct ibv_qp *native_qp;
 struct sir_app_qp_key key;
 struct ibv_qp_cap visible,provider;
 struct npr_rdv_epoch *active,*retired;
 uint32_t number;
 uint64_t ordinal;
 unsigned policy,committed,closed,service_set,data_enabled,native_paused;
 uint64_t source_admitted,virtual_rq_posted,error_epoch;
 uint64_t native_send_posted,native_wwi_posted,native_recv_posted,native_recv_done;
#ifdef NPRDMA_TEST_INJECT
 uint64_t native_rq_posted;
#endif
 uint8_t rnr_retry,min_rnr_timer;
 enum ibv_qp_state native_state;
 struct npr_rdv_actor_ops actor_ops;
 const struct npr_rdv_cq_ops *cq_ops;
 npr_rdv_backend_fn backend;
 struct crdv_stats history;
};
static struct npr_rdv_qp *rdv_qps;
static uint64_t rdv_next_qp_ordinal=1;
static void rdv_control_events(struct npr_rdv_epoch *);
static void rdv_control_progress(struct npr_rdv_epoch *);
static void rdv_control_signal(void);
static int rdv_source_spans(struct npr_rdv_owner *);
static int rdv_credit_post(void *,uint64_t);
static void rdv_credit_retired(struct npr_rdv_epoch *,uint64_t);
static unsigned rdv_pumping;
static uint64_t rdv_pump_visit;
static struct npr_rdv_actor_ops rdv_default_ops;
static unsigned rdv_default_active;
void npr_rdv_service_config(const struct npr_rdv_actor_ops *ops,unsigned active)
{assert(ops);rdv_default_ops=*ops;rdv_default_active=!!active;}
static int rdv_storage(struct npr_rdv_epoch *);
static uint64_t rdv_next_owner=1; /* Opaque app-owner namespace, never a wr_id. */
static int rdv_endpoint_equal(const struct sir_app_qp_endpoint *a,const struct sir_app_qp_endpoint *b)
{
 return a->key.cookie==b->key.cookie&&a->key.generation==b->key.generation&&
 a->bind_nonce==b->bind_nonce&&a->policy==b->policy&&
 a->route.connection_epoch==b->route.connection_epoch&&
 a->route.local_qpn==b->route.local_qpn&&a->route.peer_qpn==b->route.peer_qpn&&
 a->route.port_num==b->route.port_num&&a->route.kind==b->route.kind&&
 a->route.local_lid==b->route.local_lid&&a->route.peer_lid==b->route.peer_lid&&
 !memcmp(a->route.local_gid,b->route.local_gid,16)&&!memcmp(a->route.peer_gid,b->route.peer_gid,16);
}
static int rdv_identity_equal(const struct sir_rdv_identity *a,const struct sir_rdv_identity *b)
{
 return a->session_id==b->session_id&&a->transport_generation==b->transport_generation&&
 a->command_revision==b->command_revision&&a->message_id==b->message_id&&a->rq_message_seq==b->rq_message_seq&&
 rdv_endpoint_equal(&a->local,&b->local)&&rdv_endpoint_equal(&a->peer,&b->peer);
}
static int rdv_current(const struct npr_rdv_epoch *e,const struct sir_rdv_identity *id)
{
 const struct sir_app_qp_snapshot *s=&e->binding;
 return !e->closing&&!e->qp->closed&&e->qp->active==e&&s->state==SIR_APP_QP_BOUND&&!s->status&&
 !(s->flags&(SIR_APP_QP_SESSION_CLOSING|SIR_APP_QP_DMA_STOPPED))&&s->session_id==id->session_id&&
 s->transport_generation==id->transport_generation&&s->command_revision==id->command_revision&&
 rdv_endpoint_equal(&s->local,&id->local)&&rdv_endpoint_equal(&s->peer,&id->peer);
}
static struct npr_rdv_epoch *rdv_epoch_prepare(struct npr_rdv_qp *q,uint64_t number)
{
 struct npr_rdv_epoch *e=calloc(1,sizeof(*e));if(!e)return NULL;
 e->qp=q;e->number=number;e->next_sequence=1;
 struct npr_rq_config c={.key={q->key.cookie,q->key.generation,number},.context=q->context,.pd=q->pd};
 e->rq=npr_rq_prepare(&c);if(!e->rq){free(e);return NULL;}return e;
}
struct npr_rdv_qp *npr_rdv_prepare(struct npr_ctx_entry *ce,void *context,void *pd,
 const struct sir_app_qp_key *key,enum sir_app_qp_policy policy)
{
 if(!ce||!context||!key||!key->cookie||!key->generation||(policy!=SIR_APP_QP_NATIVE_ONLY&&policy!=SIR_APP_QP_RENDEZVOUS_REQUIRED)){errno=EINVAL;return NULL;}
 if(!rdv_next_qp_ordinal){errno=EOVERFLOW;return NULL;}
 struct npr_rdv_qp *q=calloc(1,sizeof(*q));if(!q)return NULL;
 q->ordinal=rdv_next_qp_ordinal++;
 q->ce=ce;q->context=context;q->pd=pd;q->key=*key;q->policy=policy;
 q->data_enabled=rdv_default_active;
 if(rdv_default_ops.register_qp){q->actor_ops=rdv_default_ops;q->service_set=1;}
 q->active=rdv_epoch_prepare(q,1);if(!q->active){free(q);return NULL;}return q;
}
void npr_rdv_reset_abort(struct npr_rdv_epoch *e)
{if(e){assert(!e->committed);npr_rq_abort(e->rq);free(e);}}
void npr_rdv_abort(struct npr_rdv_qp *q)
{if(q){assert(!q->committed);npr_rdv_reset_abort(q->active);free(q);}}
void npr_rdv_cq_ops(struct npr_rdv_qp *q,const struct npr_rdv_cq_ops *ops)
{assert(q);q->cq_ops=ops;}
void npr_rdv_backend(struct npr_rdv_qp *q,npr_rdv_backend_fn fn){assert(q);q->backend=fn;}
void npr_rdv_data_enable(struct npr_rdv_qp *q,unsigned enabled){assert(q);q->data_enabled=!!enabled;}
int npr_rdv_actor_config(struct npr_rdv_qp *q,const struct npr_rdv_actor_ops *ops,struct crdv_registration_config *out)
{
 if(!q||!ops||!out||q->closed||!q->committed||q->policy!=SIR_APP_QP_RENDEZVOUS_REQUIRED)return EINVAL;
 if(!ops->offer_snapshot||!ops->offer_reply||!ops->close||!ops->free||!ops->stats||!ops->final_stats||!ops->update_attrs)return EINVAL;
 if(q->active->registration)return EALREADY;
 if(q->active->mailbox&&!q->service_set)return EBUSY;
 q->actor_ops=*ops;q->service_set=1;
 int rc=rdv_storage(q->active);if(rc)return rc;
 *out=(struct crdv_registration_config){.key=q->key,.connection_epoch=q->active->number,.mailbox=q->active->mailbox,
  .native_wwi=q->cq_ops&&q->cq_ops->notify_recv&&q->cq_ops->notify_send,
  .caps={q->visible.max_send_wr,q->visible.max_recv_wr,q->visible.max_send_sge,q->visible.max_recv_sge,q->rnr_retry,q->min_rnr_timer}};
 return 0;
}
void npr_rdv_actor_attach(struct npr_rdv_qp *q,struct crdv_registration *registration)
{
 assert(q&&!q->closed&&q->service_set&&registration&&!q->active->registration&&q->active->mailbox);
 q->active->registration=registration;q->active->actor_ops=q->actor_ops;
}
void npr_rdv_native_state(struct npr_rdv_qp *q,enum ibv_qp_state state)
{if(q&&!q->closed){q->native_state=state;rdv_app_wake();}}
void npr_rdv_native_pause(struct npr_rdv_qp *q,unsigned paused)
{if(q){q->native_paused=!!paused;rdv_app_wake();}}
void npr_rdv_update_attrs(struct npr_rdv_qp *q,uint8_t retry,uint8_t timer)
{
 if(!q||q->closed||retry>7||timer>31)return;
 q->rnr_retry=retry;q->min_rnr_timer=timer;
 if(q->active->registration)(void)q->active->actor_ops.update_attrs(q->active->registration,retry,timer);
}
static void rdv_epoch_commit(struct npr_rdv_epoch *e)
{
 struct npr_rdv_qp *q=e->qp;
 struct npr_rq_config c={.key={q->key.cookie,q->key.generation,e->number},.context=q->context,.pd=q->pd,
 .qp_num=q->number,.max_recv_wr=q->visible.max_recv_wr,.max_recv_sge=q->visible.max_recv_sge};
 npr_rq_commit(e->rq,&c);e->committed=1;
}
void npr_rdv_commit(struct npr_rdv_qp *q,struct ibv_qp *qp,const struct ibv_qp_cap *visible,const struct ibv_qp_cap *provider)
{
 assert(q&&!q->committed&&qp&&qp->context==q->context&&qp->pd&&(!q->pd||q->pd==qp->pd)&&visible&&provider);
 q->native_qp=qp;q->pd=qp->pd;q->number=qp->qp_num;q->send_cq=qp->send_cq;q->recv_cq=qp->recv_cq;
 q->visible=*visible;q->provider=*provider;rdv_epoch_commit(q->active);q->committed=1;
 q->next=rdv_qps;rdv_qps=q;rdv_app_wake();
}
struct npr_rdv_epoch *npr_rdv_reset_prepare(struct npr_rdv_qp *q,uint64_t number)
{
 if(!q||!q->committed||q->closed||!number||number<=q->active->number){errno=EINVAL;return NULL;}
 return rdv_epoch_prepare(q,number);
}
static void rdv_epoch_close(struct npr_rdv_epoch *e,enum npr_rq_close_mode mode)
{
 e->closing=1;rdv_control_signal();
 for(struct npr_rdv_owner *o=e->owners;o;o=o->next)if(o->source_accepted){o->source_cancel=1;o->source_status=IBV_WC_WR_FLUSH_ERR;if(mode==NPR_RQ_CLOSE_DISCARD)o->source_discard=1;}
 npr_rq_close(e->rq,mode);
 if(mode==NPR_RQ_CLOSE_DISCARD&&e->qp->cq_ops&&e->qp->cq_ops->discard_epoch){
  e->qp->cq_ops->discard_epoch(e->qp->ce,e->qp->recv_cq,e->qp->number,e->qp->key.generation,e->number);
  if(e->qp->send_cq!=e->qp->recv_cq)e->qp->cq_ops->discard_epoch(e->qp->ce,e->qp->send_cq,e->qp->number,e->qp->key.generation,e->number);
 }
 if(e->registration)(void)e->actor_ops.close(e->registration);
 if(e->mailbox)(void)sir_rdv_mailbox_close(e->mailbox);
}
void npr_rdv_reset_commit(struct npr_rdv_qp *q,struct npr_rdv_epoch *fresh)
{
 assert(q&&fresh&&fresh->qp==q&&!fresh->committed&&!q->closed&&fresh->number>q->active->number);
 struct npr_rdv_epoch *old=q->active;rdv_epoch_commit(fresh);q->active=fresh;
 rdv_epoch_close(old,NPR_RQ_CLOSE_DISCARD);old->next=q->retired;q->retired=old;
}
void npr_rdv_binding(struct npr_rdv_qp *q,const struct sir_app_qp_snapshot *s)
{
 if(!q||q->closed||!s)return;
 if(s->local.key.cookie!=q->key.cookie||s->local.key.generation!=q->key.generation||
 s->local.route.connection_epoch!=q->active->number)return;
 if(s->command_revision<q->active->binding.command_revision||s->serial<q->active->binding.serial)return;
 q->active->binding=*s;if(s->state==SIR_APP_QP_BOUND)q->active->ever_bound=1;
}
void npr_rdv_error(struct npr_rdv_qp *q)
{if(q&&!q->closed)rdv_epoch_close(q->active,NPR_RQ_CLOSE_FLUSH);}
void npr_rdv_close(struct npr_rdv_qp *q)
{
 if(!q||q->closed)return;
 q->closed=1;rdv_epoch_close(q->active,NPR_RQ_CLOSE_DISCARD);
 q->active->next=q->retired;q->retired=q->active;q->active=NULL;
}
struct npr_rdv_epoch *npr_rdv_active(struct npr_rdv_qp *q){return q&&!q->closed?q->active:NULL;}
struct npr_rq *npr_rdv_rq(struct npr_rdv_epoch *e){return e?e->rq:NULL;}
static void rdv_wake(void *unused){(void)unused;rdv_app_wake();}
static int rdv_storage(struct npr_rdv_epoch *e)
{
 if(e->mailbox)return 0;
 const struct ibv_qp_cap *c=&e->qp->visible;
 size_t slots=(size_t)c->max_send_wr;
 if(SIZE_MAX-slots<c->max_recv_wr)return EOVERFLOW;
 slots+=c->max_recv_wr;
 if(slots==SIZE_MAX)return EOVERFLOW;
 slots++; /* One prematch metadata credit, never an extra posted RQ. */
 size_t spans=c->max_send_sge>c->max_recv_sge?c->max_send_sge:c->max_recv_sge;if(!spans)spans=1;
 if(slots>SIZE_MAX/spans||slots*spans>SIZE_MAX/sizeof(struct sir_rdv_span)||slots>SIZE_MAX/sizeof(struct rdv_attempt))return EOVERFLOW;
 struct sir_rdv_mailbox_config config={.slot_count=slots,.max_spans=spans,.wake_app=rdv_wake,
  .wake_actor=e->qp->actor_ops.wake_actor,.wake_opaque=e->qp->actor_ops.wake_opaque};
 int rc=sir_rdv_mailbox_new(&config,&e->mailbox);if(rc)return rc;
 e->attempts=calloc(slots,sizeof(*e->attempts));
 if(!e->attempts){(void)sir_rdv_mailbox_close(e->mailbox);(void)sir_rdv_mailbox_free(e->mailbox);e->mailbox=NULL;return ENOMEM;}
 e->attempt_capacity=slots;return 0;
}
static struct npr_rdv_owner *rdv_owner_allocate(struct npr_rdv_epoch *e,enum sir_rdv_role role)
{
 struct npr_rdv_owner *o=calloc(1,sizeof(*o));if(!o)return NULL;
 o->capacity=role==SIR_RDV_SOURCE?e->qp->visible.max_send_sge:e->qp->visible.max_recv_sge;
 if(!o->capacity)o->capacity=1;
 o->captures=calloc(o->capacity,sizeof(*o->captures));o->spans=calloc(o->capacity,sizeof(*o->spans));o->fds=calloc(o->capacity,sizeof(*o->fds));
 if(!o->captures||!o->spans||!o->fds){free(o->captures);free(o->spans);free(o->fds);free(o);return NULL;}
 o->epoch=e;o->role=role;return o;
}
static int rdv_value_equal(const struct sir_rdv_value *a,const struct sir_rdv_value *b)
{return rdv_identity_equal(&a->id,&b->id)&&a->length==b->length&&a->kind==b->kind&&a->imm_be==b->imm_be&&a->solicited==b->solicited&&a->status==b->status;}
int npr_rdv_owner_adopt_sink(struct npr_rdv_qp *q,struct crdv_registration *registration,
 const struct sir_rdv_record *event,struct npr_rdv_owner **out)
{
 if(out)*out=NULL;
 if(!q||!out||!event||event->kind!=SIR_RDV_OFFER_READY||!event->token||!event->app_token||q->closed||!q->active)return EINVAL;
 struct npr_rdv_epoch *e=q->active;
 if(q->policy!=SIR_APP_QP_RENDEZVOUS_REQUIRED||e->registration!=registration||!e->actor_ops.offer_snapshot)return ESTALE;
 if(!rdv_current(e,&event->value.id))return ESTALE;
 for(struct npr_rdv_owner *p=e->owners;p;p=p->next)if(p->mailbox_token==event->token)return EALREADY;
 size_t matched=0;for(struct npr_rdv_owner *p=e->owners;p;p=p->next)if(p->role==SIR_RDV_SINK)matched++;
 if(matched>=q->visible.max_recv_wr)return ENOMEM;
 struct crdv_offer_snapshot snapshot;int rc=e->actor_ops.offer_snapshot(registration,event->token,event->app_token,&snapshot);
 if(rc)return rc;
 if(!snapshot.attempt||!rdv_value_equal(&snapshot.value,&event->value))return ESTALE;
 struct npr_rdv_owner *o=rdv_owner_allocate(e,SIR_RDV_SINK);if(!o)return ENOMEM;
 rc=sir_rdv_message_hold(e->mailbox,event->token,SIR_RDV_CALLBACK);
 if(rc){free(o->captures);free(o->spans);free(o->fds);free(o);return rc;}
 o->identity=event->value.id;o->app_token=event->app_token;o->mailbox_token=event->token;o->adopted=1;o->callback_held=1;o->native_notify=snapshot.native_wwi;
 o->next=e->owners;e->owners=o;*out=o;return 0;
}
int npr_rdv_owner_reserve(struct npr_rdv_qp *q,enum sir_rdv_role role,const struct sir_rdv_identity *id,struct npr_rdv_owner **out)
{
 if(out)*out=NULL;
 if(!q||!out||!id||!id->message_id||!id->rq_message_seq||(role!=SIR_RDV_SOURCE&&role!=SIR_RDV_SINK))return EINVAL;
 if(q->policy!=SIR_APP_QP_RENDEZVOUS_REQUIRED)return EOPNOTSUPP;
 if(q->closed||!q->active||!rdv_current(q->active,id))return ESTALE;
 size_t used=0;for(struct npr_rdv_owner *p=q->active->owners;p;p=p->next)if(p->role==(unsigned)role)used++;
 if(used>=(role==SIR_RDV_SOURCE?q->visible.max_send_wr:q->visible.max_recv_wr))return ENOMEM;
 if(!rdv_next_owner)return EOVERFLOW;
 int rc=rdv_storage(q->active);if(rc)return rc;
 struct npr_rdv_owner *o=rdv_owner_allocate(q->active,role);if(!o)return ENOMEM;
 o->identity=*id;o->app_token=rdv_next_owner++;
 rc=sir_rdv_message_reserve(o->epoch->mailbox,role,o->app_token,&o->mailbox_token);
 if(rc){free(o->captures);free(o->spans);free(o->fds);free(o);return rc;}
 o->next=o->epoch->owners;o->epoch->owners=o;*out=o;return 0;
}
int npr_rdv_owner_capture(struct npr_rdv_owner *o,struct npr_mra_capture *capture,
 uint64_t offset,uint64_t length,uint64_t message_offset,enum npr_mra_direction dir,npr_rdv_backend_fn snapshot)
{
 if(!o||!capture||!length||o->released)return EINVAL;
 if(o->nspan>=o->capacity)return EMSGSIZE;
 if(o->published)return EBUSY;
 if(o->nspan>=(o->role==SIR_RDV_SOURCE?o->epoch->qp->visible.max_send_sge:o->epoch->qp->visible.max_recv_sge))return EMSGSIZE;
 if(dir!=(o->role==SIR_RDV_SOURCE?NPR_MRA_SOURCE:NPR_MRA_SINK))return EINVAL;
 if(!rdv_current(o->epoch,&o->identity))return ESTALE;
 struct npr_mra_view view;int rc=npr_mra_claim_used(capture,offset,length,dir,&view);if(rc)return rc;
 struct sir_rdv_span span={.cpu_address=view.cpu_address,.length=view.length,.message_offset=message_offset};
 if(view.kind==NPR_MRA_CPU_ADOPTED){
  struct npr_rdv_backend_source source;
  if(!snapshot)return ENOSYS;
  rc=snapshot(&view,&source);if(rc)return rc;
  if(source.fd<0||source.mr_id<0||source.registration_gen!=view.generation)return ESTALE;
  size_t i;for(i=0;i<o->nfd;i++)if(o->fds[i].original==source.fd)break;
  if(i==o->nfd){int fd=fcntl(source.fd,F_DUPFD_CLOEXEC,0);if(fd<0)return errno;o->fds[o->nfd++]=(struct rdv_fd){source.fd,fd};}
  span.backend=(struct sir_rdv_backend){.kind=SIR_RDV_SYM_PIN,.dupfd=o->fds[i].duplicate,.mr_id=source.mr_id,.registration_gen=view.generation};
 }
 o->captures[o->ncap++]=*capture;memset(capture,0,sizeof(*capture));o->spans[o->nspan++]=span;return 0;
}
static void rdv_resources_release(struct npr_rdv_owner *o)
{
 while(o->nfd){int fd=o->fds[--o->nfd].duplicate;(void)close(fd);}
 while(o->ncap)npr_mra_release(&o->captures[--o->ncap]);
 o->nspan=0;
}
static void rdv_owner_free(struct npr_rdv_owner *o)
{
 struct npr_rdv_owner **p=&o->epoch->owners;while(*p&&*p!=o)p=&(*p)->next;assert(*p==o);*p=o->next;
 free(o->captures);free(o->spans);free(o->fds);free(o);
}
static struct npr_rdv_qp *rdv_find(struct npr_ctx_entry *ce,struct ibv_qp *qp)
{for(struct npr_rdv_qp *q=rdv_qps;q;q=q->next)if(!q->closed&&q->ce==ce&&q->native_qp==qp)return q;return NULL;}
int npr_rdv_post_recv(struct npr_ctx_entry *ce,struct ibv_qp *qp,struct ibv_recv_wr *wr,struct ibv_recv_wr **bad,int *result)
{
 struct npr_rdv_qp *q=rdv_find(ce,qp);
 if(!q||!q->data_enabled||q->policy!=SIR_APP_QP_RENDEZVOUS_REQUIRED)return 0;
 struct npr_rq_counts before,after;npr_rq_get_counts(q->active->rq,&before);
 *result=npr_rq_post_native(q->active->rq,wr,bad,
  q->cq_ops&&q->cq_ops->notify_recv&&q->cq_ops->notify_send?rdv_credit_post:NULL,q->active);npr_rq_get_counts(q->active->rq,&after);
 q->virtual_rq_posted+=after.outstanding-before.outstanding;rdv_app_wake();return 1;
}
int npr_rdv_source_prepare(struct npr_ctx_entry *ce,struct ibv_qp *qp,
 struct npr_op *op,struct npr_order_entry *order,struct npr_rdv_owner **out)
{
 if(out)*out=NULL;
 if(!ce||!qp||!op||!order||!out)return -EINVAL;
 struct npr_rdv_qp *q=rdv_find(ce,qp);
 if(!q||!q->data_enabled||q->policy!=SIR_APP_QP_RENDEZVOUS_REQUIRED||
  (!npr_op_is_send(op)&&op->kind!=NPR_OP_WRITE_IMM))return 0;
 struct npr_rdv_epoch *e=q->active;
 if(e->closing)return -EBUSY;
 size_t used=0;for(struct npr_rdv_owner *p=e->owners;p;p=p->next)if(p->role==SIR_RDV_SOURCE)used++;
 if(used>=q->visible.max_send_wr)return -ENOMEM;
 if(!e->next_sequence||e->pending_sources>UINT64_MAX-e->next_sequence||!rdv_next_owner)return -EOVERFLOW;
 if(op->num_sge>q->visible.max_send_sge)return -EINVAL;
 int rc=rdv_storage(e);if(rc)return -rc;
 struct npr_rdv_owner *o=rdv_owner_allocate(e,SIR_RDV_SOURCE);if(!o)return -ENOMEM;
 o->source_op=op;o->source_order=order;o->source_prepared=1;o->app_token=rdv_next_owner++;
 rc=sir_rdv_message_reserve(e->mailbox,SIR_RDV_SOURCE,o->app_token,&o->mailbox_token);
 if(rc)goto fail;
 if(!op->inline_)for(unsigned i=0;i<op->num_sge;i++)if(op->sge[i].length){
  rc=npr_mra_capture(q->context,q->pd,op->sge[i].lkey,op->sge[i].addr,op->sge[i].length,&o->captures[o->ncap]);
  if(rc)goto abort;
  o->ncap++;
 }
 memset(op->local_mr,0,sizeof(op->local_mr));
 o->source_memory_error=rdv_source_spans(o);op->local_bound=1;
 e->pending_sources++;o->next=e->owners;e->owners=o;*out=o;return 1;
abort:
 (void)sir_rdv_message_abort(e->mailbox,o->mailbox_token);
fail:
 rdv_resources_release(o);free(o->captures);free(o->spans);free(o->fds);free(o);return -rc;
}
int npr_rdv_source_preaccept_validate(const struct npr_rdv_owner *o)
{
 if(!o||!o->source_prepared||o->source_accepted)return EINVAL;
 return o->epoch->qp->closed||o->epoch->closing||o->epoch->qp->active!=o->epoch?ESTALE:0;
}
uint64_t npr_rdv_source_epoch(const struct npr_rdv_owner *o){return o?o->epoch->number:0;}
void npr_rdv_source_accept(struct npr_rdv_owner *o)
{
 assert(o&&o->source_prepared&&!o->source_accepted&&o->epoch->pending_sources&&o->epoch->next_sequence);
 o->source_accepted=1;o->sequence=o->epoch->next_sequence++;o->epoch->pending_sources--;
 o->epoch->qp->source_admitted++;
 assert(o->epoch->qp->cq_ops&&o->epoch->qp->cq_ops->source_get&&o->epoch->qp->cq_ops->source_done);
 o->epoch->qp->cq_ops->source_get(o->source_order);
}
void npr_rdv_source_abort(struct npr_rdv_owner *o)
{
 if(!o)return;
 assert(o->source_prepared&&!o->source_accepted&&o->epoch->pending_sources);
 o->epoch->pending_sources--;
 if(o->source_op&&o->source_op->rdv_owner==o)o->source_op->rdv_owner=NULL;
 int rc=npr_rdv_owner_abort(o);assert(!rc);
}
int npr_rdv_source_data_begin(struct npr_rdv_owner *o)
{
 assert(o&&o->data_started&&o->data_pending&&!o->data_owned);
 if(o->source_cancel||!rdv_current(o->epoch,&o->identity)||o->epoch->qp->native_state!=IBV_QPS_RTS){
  o->data_pending=0;o->data_done=1;o->data_status=o->source_cancel?IBV_WC_WR_FLUSH_ERR:IBV_WC_GENERAL_ERR;return 0;
 }
 o->processing=1;return 1;
}
void npr_rdv_source_data_submit_done(struct npr_rdv_owner *o,int rc)
{
 assert(o&&o->data_started);
 o->processing=0;
 if(rc<0){
  o->data_submit_failed=1;
  if(!o->data_owned&&!o->data_done){o->data_pending=0;o->data_done=1;o->data_status=IBV_WC_GENERAL_ERR;}
  if(o->data_done&&o->data_status==IBV_WC_SUCCESS)o->data_status=IBV_WC_GENERAL_ERR;
 }
 rdv_app_wake();
}
void npr_rdv_source_data_hold(struct npr_rdv_owner *o)
{assert(o&&o->data_started&&o->data_pending&&!o->data_owned);o->data_owned=1;}
void npr_rdv_source_data_done(struct npr_rdv_owner *o,const struct ibv_wc *wc)
{assert(o&&o->data_started&&o->data_pending&&o->data_owned&&wc);o->data_pending=0;o->data_done=1;o->data_status=o->data_submit_failed&&wc->status==IBV_WC_SUCCESS?IBV_WC_GENERAL_ERR:wc->status;rdv_app_wake();}
static int rdv_source_publish(struct npr_rdv_owner *o);
int npr_rdv_source_dispatch(struct npr_rdv_owner *o)
{
 if(!o||!o->source_accepted)return EINVAL;
 o->source_dispatch=1;rdv_app_wake();
 /* Only publish this ready source's prepared metadata. Do not enter the
  * global pump or WWI data callbacks from the posting call. Failed/busy
  * publication remains accepted and is handled by ordinary source progress. */
 if(!o->source_memory_error&&!o->source_cancel&&
    !o->published&&!o->epoch->closing&&o->epoch->qp->native_state==IBV_QPS_RTS)
  (void)rdv_source_publish(o);
 return 0;
}
void npr_rdv_source_cancel(struct npr_rdv_owner *o,enum ibv_wc_status status,int discard)
{
 if(!o)return;
 assert(o->source_accepted);
 o->source_cancel=1;o->source_status=status;o->source_discard|=!!discard;rdv_app_wake();
}
int npr_rdv_owner_submit(struct npr_rdv_owner *o,const struct sir_rdv_value *value)
{
 if(!o||!value)return EINVAL;
 if(o->published)return EALREADY;
 if(!rdv_identity_equal(&value->id,&o->identity)||!rdv_current(o->epoch,&o->identity))return ESTALE;
 int rc=sir_rdv_command_submit(o->epoch->mailbox,o->mailbox_token,
  o->role==SIR_RDV_SOURCE?SIR_RDV_SOURCE_PREPARE:SIR_RDV_MATCH_PREPARE,value,o->spans,o->nspan);
 if(!rc){o->published=1;o->value=*value;}
 return rc;
}
int npr_rdv_owner_abort(struct npr_rdv_owner *o)
{
 if(!o)return EINVAL;
 if(o->source_accepted||o->notify_pending)return EBUSY;
 if(o->adopted){
  if(o->published)return EBUSY;
  if(o->cell){o->epoch->qp->cq_ops->complete(o->cell,NULL,0,1);o->cell=NULL;}
  if(o->callback_held){(void)sir_rdv_message_drop(o->epoch->mailbox,o->mailbox_token,SIR_RDV_CALLBACK);o->callback_held=0;}
 }else {int rc=sir_rdv_message_abort(o->epoch->mailbox,o->mailbox_token);if(rc)return rc;}
 rdv_resources_release(o);rdv_owner_free(o);return 0;
}
uint64_t npr_rdv_owner_app_token(const struct npr_rdv_owner *o){return o?o->app_token:0;}
uint64_t npr_rdv_owner_mailbox_token(const struct npr_rdv_owner *o){return o?o->mailbox_token:0;}
struct sir_rdv_mailbox *npr_rdv_owner_mailbox(struct npr_rdv_owner *o){return o?o->epoch->mailbox:NULL;}
int npr_rdv_owner_spans(const struct npr_rdv_owner *o,const struct sir_rdv_span **spans,size_t *count)
{if(!o||!spans||!count)return EINVAL;*spans=o->spans;*count=o->nspan;return 0;}
int npr_rdv_owner_event(struct npr_rdv_owner *o,const struct sir_rdv_record *r)
{
 if(!o||!r||r->kind>=SIR_RDV_EVENT_N)return EINVAL;
 if(r->token!=o->mailbox_token||r->app_token!=o->app_token||!rdv_identity_equal(&r->value.id,&o->identity))return ESTALE;
 if(o->published&&(r->value.length!=o->value.length||r->value.kind!=o->value.kind||r->value.imm_be!=o->value.imm_be||r->value.solicited!=o->value.solicited))return EPROTO;
 int released=r->kind==SIR_RDV_SOURCE_RELEASED||r->kind==SIR_RDV_SINK_RELEASED;
 if(released){
  if(r->kind!=(o->role==SIR_RDV_SOURCE?SIR_RDV_SOURCE_RELEASED:SIR_RDV_SINK_RELEASED))return EPROTO;
  if(r->evidence<SIR_RDV_NO_DATA||r->evidence>SIR_RDV_STOPPED_CLEANED)return EPROTO;
  /* A matched data plan retains its leases/fds until the resource owner
   * certifies physical cleanup. Error status cannot strengthen NO_DATA. */
  if(o->role==SIR_RDV_SINK&&o->planned_spans&&r->evidence==SIR_RDV_NO_DATA)return EPROTO;
 }else if((r->kind==SIR_RDV_OFFER_READY||r->kind==SIR_RDV_WWI_READY||r->kind==SIR_RDV_SOURCE_PREPARED)&&!rdv_current(o->epoch,&o->identity))return ESTALE;
 if(r->kind==SIR_RDV_SOURCE_PREPARED&&(o->role!=SIR_RDV_SOURCE||!o->source_op||r->value.status||r->evidence))return EPROTO;
 if(r->kind==SIR_RDV_WWI_READY&&(o->role!=SIR_RDV_SOURCE||!o->source_op||o->source_op->kind!=NPR_OP_WRITE_IMM||r->value.status||r->evidence))return EPROTO;
 if(o->events&(1u<<r->kind))return o->event_value[r->kind].status==r->value.status&&
  o->event_evidence[r->kind]==r->evidence?EALREADY:EPROTO;
 o->events|=1u<<r->kind;o->event_value[r->kind]=r->value;o->event_evidence[r->kind]=r->evidence;
 if(released){if(o->role!=SIR_RDV_SOURCE||(!o->data_pending&&!o->processing))rdv_resources_release(o);o->released=1;o->release_evidence=r->evidence;o->release_status=(int)r->value.status;}
 return 0;
}
int npr_rdv_owner_retire(struct npr_rdv_owner *o)
{if(!o)return EINVAL;if(!o->released||o->cell||o->rq_token||o->notify_pending)return EBUSY;rdv_owner_free(o);return 0;}
static struct rdv_attempt *rdv_attempt_find(struct npr_rdv_epoch *e,uint64_t token,uint64_t app_token)
{for(size_t i=0;i<e->attempt_extent;i++)if(e->attempts[i].active&&e->attempts[i].event.token==token&&e->attempts[i].event.app_token==app_token)return &e->attempts[i];return NULL;}
static void rdv_attempt_clear(struct npr_rdv_epoch *e,struct rdv_attempt *a)
{
 memset(a,0,sizeof(*a));
 while(e->attempt_extent&&!e->attempts[e->attempt_extent-1].active)e->attempt_extent--;
}
static void rdv_attempt_ack(struct npr_rdv_epoch *e,struct rdv_attempt *a)
{if(a->event.serial){(void)sir_rdv_event_ack(e->mailbox,a->event.token,a->event.serial);a->event.serial=0;}}
static int rdv_stream_authorize(struct npr_rdv_epoch *e,const struct crdv_offer_snapshot *s)
{
 const struct sir_app_qp_endpoint *peer=&s->value.id.peer;
 int same=e->stream_active&&e->stream_peer.cookie==peer->key.cookie&&e->stream_peer.generation==peer->key.generation&&e->stream_peer_epoch==peer->route.connection_epoch;
 if(same)return 0;
 if(!s->stream_first||!s->stream_base||s->stream_base!=s->value.id.rq_message_seq)return ESTALE;
 int rc=npr_rq_stream_begin(e->rq,s->stream_base);if(rc)return rc;
 e->stream_peer=peer->key;e->stream_peer_epoch=peer->route.connection_epoch;e->stream_active=1;return 0;
}
static int rdv_offer_record(struct npr_rdv_epoch *e,const struct sir_rdv_record *event)
{
 if(!e->registration||event->kind!=SIR_RDV_OFFER_READY)return ESTALE;
 struct rdv_attempt *old=rdv_attempt_find(e,event->token,event->app_token);if(old)return EALREADY;
 struct crdv_offer_snapshot snapshot;int rc=e->actor_ops.offer_snapshot(e->registration,event->token,event->app_token,&snapshot);
 if(rc)return rc;
 if(!snapshot.attempt||!rdv_value_equal(&snapshot.value,&event->value))return ESTALE;
 struct rdv_attempt *a=NULL;for(size_t i=0;i<e->attempt_capacity;i++)if(!e->attempts[i].active){a=&e->attempts[i];break;}
 if(!a)return ENOMEM;
 memset(a,0,sizeof(*a));a->event=*event;a->snapshot=snapshot;a->active=1;
 size_t end=(size_t)(a-e->attempts)+1;if(end>e->attempt_extent)e->attempt_extent=end;
 return 0;
}

#include "npr_rdv_credits.inc"
static void rdv_native_tx_done(void *opaque,const struct ibv_wc *wc,const void *bytes)
{
 struct npr_rdv_owner *o=opaque;(void)bytes;
 assert(o->notify_pending&&o->epoch->native_refs);
 o->notify_pending=0;o->notify_done=1;o->notify_status=wc->status;o->epoch->native_refs--;
 if(wc->status!=IBV_WC_SUCCESS){o->source_cancel=1;o->source_status=wc->status;}
 rdv_app_wake();
}
static int rdv_native_tx(struct npr_rdv_owner *o)
{
 if(o->epoch->qp->native_paused)return EBUSY;
 const struct sir_app_qp_endpoint *src=&o->identity.local,*dst=&o->identity.peer;
 struct npr_notify_message m={
  .source={src->key.cookie,src->key.generation,src->route.connection_epoch},
  .target={dst->key.cookie,dst->key.generation,dst->route.connection_epoch},
  .message_id=o->identity.message_id,.sequence=o->identity.rq_message_seq,
  .length=o->value.length,.kind=o->value.kind,.imm_be=o->value.imm_be,.solicited=o->value.solicited,
  .session_id=o->identity.session_id,.source_nonce=src->bind_nonce,.target_nonce=dst->bind_nonce};
 unsigned char bytes[NPR_NOTIFY_BYTES];int rc=npr_notify_encode(bytes,sizeof(bytes),&m);
 if(rc)return rc;
 struct npr_rdv_qp *q=o->epoch->qp;
 rc=q->cq_ops->notify_send(q->ce,q->native_qp,bytes,m.solicited,o,rdv_native_tx_done);
 if(!rc){
  o->notify_pending=1;o->epoch->native_refs++;q->native_send_posted++;if(o->value.kind==NPR_RQ_WWI)q->native_wwi_posted++;
  if(o->value.kind!=NPR_RQ_WWI){
   int exposed=sir_rdv_command_submit(o->epoch->mailbox,o->mailbox_token,SIR_RDV_NATIVE_EXPOSED,&o->value,NULL,0);
   if(exposed&&exposed!=EALREADY){o->source_cancel=1;o->source_status=IBV_WC_GENERAL_ERR;o->epoch->qp->error_epoch=o->epoch->number;}
  }
 }
 return rc;
}
struct rdv_claim_context {struct npr_rdv_epoch *epoch;struct rdv_attempt *attempt;struct npr_rdv_owner *owner;};
static int rdv_claim_reserve(void *opaque,const struct npr_rq_plan *plan,uint64_t *reservation)
{
 struct rdv_claim_context *c=opaque;struct npr_rdv_epoch *e=c->epoch;struct npr_rdv_qp *q=e->qp;
 if(!q->cq_ops||!q->cq_ops->reserve||!q->cq_ops->complete)return EOPNOTSUPP;
 struct npr_rdv_owner *o=NULL;int rc=npr_rdv_owner_adopt_sink(q,e->registration,&c->attempt->event,&o);if(rc)return rc;
 o->rq_token=plan->token;o->rx_status=plan->rx_status;o->tx_status=plan->tx_status;o->planned_spans=plan->span_count;
 rc=q->cq_ops->reserve(q->ce,q->recv_cq,q->number,q->key.generation,e->number,plan->user_wr_id,&o->cell);
 if(rc)goto rollback;
 if(o->native_notify&&plan->message.kind==NPR_RQ_WWI){
  struct rdv_native_credit *credit=rdv_credit_find(e,plan->token);
  if(c->attempt->snapshot.value.status==EREMOTEIO){o->rx_status=IBV_WC_LOC_ACCESS_ERR;o->tx_status=IBV_WC_REM_ACCESS_ERR;}
  else if(!credit||!credit->done||!credit->decoded||credit->message.kind!=NPR_NOTIFY_WWI||
     credit->message.message_id!=plan->message.message_id||credit->message.sequence!=plan->message.sequence){rc=EPROTO;goto rollback;}
  else o->notify_done=1;
 }
 for(unsigned i=0;i<plan->span_count;i++){
  const struct npr_mra_view *v=&plan->spans[i].view;struct npr_mra_capture capture={0};
  rc=npr_mra_capture(v->context,v->pd,v->lkey,v->iova_address,v->length,&capture);if(rc)goto rollback;
  if(capture.generation!=v->generation||capture.classification!=NPR_MRA_KNOWN){npr_mra_release(&capture);rc=ESTALE;goto rollback;}
  rc=npr_rdv_owner_capture(o,&capture,0,v->length,plan->spans[i].message_offset,NPR_MRA_SINK,q->backend);
  if(rc){npr_mra_release(&capture);goto rollback;}
 }
 *reservation=o->mailbox_token;c->owner=o;return 0;
rollback:
 (void)npr_rdv_owner_abort(o);return rc;
}
static void rdv_match_failed_unpublished(struct npr_rdv_owner *o)
{
 /* MATCH was rejected: no target spans transferred, so local metadata can be
  * cleaned immediately. This is an error with no posted DMA, never success. */
 struct npr_rdv_epoch *e=o->epoch;
 rdv_resources_release(o);
 if(o->callback_held){(void)sir_rdv_message_drop(e->mailbox,o->mailbox_token,SIR_RDV_CALLBACK);o->callback_held=0;}
 o->rx_status=IBV_WC_GENERAL_ERR;o->tx_status=IBV_WC_REM_OP_ERR;
 (void)npr_rq_finish(e->rq,o->rq_token,o->rx_status,o->tx_status,NPR_RQ_DATA_CLEANED);
 o->released=1;o->release_status=EIO;o->release_evidence=SIR_RDV_DATA_CLEANED;
 /* The actor still owns the original attempt; closing authorization requests
  * its cancellation, without claiming that any other matched DMA has stopped. */
 if(e->registration)(void)e->actor_ops.close(e->registration);
}
static void rdv_attempt_progress(struct npr_rdv_epoch *e,struct rdv_attempt *a)
{
 if(!a->active)return;
 if(e->closing||!rdv_current(e,&a->snapshot.value.id)){rdv_attempt_ack(e,a);return;}
 if(a->no_rq){
  if(!a->reply_sent){int rc=e->actor_ops.offer_reply(e->registration,a->event.token,a->event.app_token,a->snapshot.attempt,CRDV_NO_RQ);if(!rc||rc==EALREADY){a->reply_sent=1;rdv_attempt_ack(e,a);}}
  return; /* A later post_recv never revives this already decided attempt. */
 }
 if(rdv_stream_authorize(e,&a->snapshot)){rdv_attempt_ack(e,a);return;}
 struct npr_rq_counts counts;npr_rq_get_counts(e->rq,&counts);
 if(!counts.queued){a->no_rq=1;rdv_attempt_progress(e,a);return;}
 struct rdv_claim_context c={e,a,NULL};uint64_t token=0;
 struct npr_rq_message message={.local={e->qp->key.cookie,e->qp->key.generation,e->number},
  .sequence=a->snapshot.value.id.rq_message_seq,.message_id=a->snapshot.value.id.message_id,.length=a->snapshot.value.length,
  .kind=a->snapshot.value.kind,.imm_be=a->snapshot.value.imm_be,.solicited=a->snapshot.value.solicited};
 int rc=npr_rq_claim(e->rq,&message,rdv_claim_reserve,&c,&token);
 if(rc){
  if(rc==EALREADY||rc==ESTALE){rdv_attempt_ack(e,a);return;}
  if(!a->backpressure_sent){int reply=e->actor_ops.offer_reply(e->registration,a->event.token,a->event.app_token,a->snapshot.attempt,CRDV_RESOURCE_BACKPRESSURE);if(!reply||reply==EALREADY)a->backpressure_sent=1;}
  return;
 }
 struct npr_rdv_owner *o=c.owner;assert(o&&o->rq_token==token);
 struct sir_rdv_value value=a->snapshot.value;
 value.status=o->rx_status==IBV_WC_LOC_ACCESS_ERR?EREMOTEIO:o->rx_status==IBV_WC_LOC_PROT_ERR?EACCES:o->rx_status==IBV_WC_LOC_LEN_ERR?EMSGSIZE:0;
 rc=npr_rdv_owner_submit(o,&value);
 if(o->callback_held){(void)sir_rdv_message_drop(e->mailbox,o->mailbox_token,SIR_RDV_CALLBACK);o->callback_held=0;}
 rdv_attempt_ack(e,a);
 if(rc)rdv_match_failed_unpublished(o);
 rdv_attempt_clear(e,a);
}
static void rdv_finish_matches(struct npr_rdv_epoch *e)
{
 for(struct npr_rdv_owner *o=e->owners,*next;o;o=next){
  next=o->next;
  if(!o->rq_token||!o->released)continue;
  if(o->native_notify&&!o->notify_done&&!o->release_status&&o->rx_status==IBV_WC_SUCCESS)continue;
  if(o->value.kind==NPR_RQ_WWI&&o->release_status==ENODATA){
   if(npr_rq_wwi_unclaim(e->rq,o->rq_token))continue;
   if(!e->closing){
    if(o->cell)e->qp->cq_ops->complete(o->cell,NULL,0,1);
    o->cell=NULL;o->rq_token=0;(void)npr_rdv_owner_retire(o);
   }
   continue;
  }
  enum ibv_wc_status rx=o->rx_status,tx=o->tx_status;
  if(o->value.kind==NPR_RQ_WWI&&o->release_status==EREMOTEIO){rx=IBV_WC_LOC_ACCESS_ERR;tx=IBV_WC_REM_ACCESS_ERR;}
  if(rx==IBV_WC_SUCCESS&&o->release_status){
   rx=o->release_status==EACCES?IBV_WC_LOC_PROT_ERR:o->release_status==EMSGSIZE?IBV_WC_LOC_LEN_ERR:o->release_status==ECANCELED?IBV_WC_WR_FLUSH_ERR:IBV_WC_GENERAL_ERR;
   tx=rx==IBV_WC_LOC_LEN_ERR?IBV_WC_REM_INV_REQ_ERR:IBV_WC_REM_OP_ERR;
  }
  enum npr_rq_cleanup_evidence proof=o->release_evidence==SIR_RDV_STOPPED_CLEANED?NPR_RQ_DMA_STOPPED_CLEANED:
   o->release_evidence==SIR_RDV_DATA_CLEANED?NPR_RQ_DATA_CLEANED:NPR_RQ_NO_DATA;
  if(!npr_rq_finish(e->rq,o->rq_token,rx,tx,proof)&&rx!=IBV_WC_SUCCESS&&rx!=IBV_WC_WR_FLUSH_ERR&&e->qp->active==e&&!e->closing)e->qp->error_epoch=e->number;
 }
 for(;;){
  struct npr_rq_completion result;if(npr_rq_peek_terminal(e->rq,&result))break;
  struct npr_rdv_owner *o;for(o=e->owners;o;o=o->next)if(o->rq_token==result.token)break;
  void *cell=o?o->cell:NULL;
  if(!result.discard&&!cell){
   if(!e->qp->cq_ops||!e->qp->cq_ops->reserve||e->qp->cq_ops->reserve(e->qp->ce,e->qp->recv_cq,e->qp->number,e->qp->key.generation,e->number,result.user_wr_id,&cell))break;
  }
  if(cell)e->qp->cq_ops->complete(cell,&result.wc,result.solicited,result.discard);
  (void)npr_rq_retire(e->rq,result.token);rdv_credit_retired(e,result.token);
  if(o){o->cell=NULL;o->rq_token=0;(void)npr_rdv_owner_retire(o);}
 }
}
static void rdv_events(struct npr_rdv_epoch *e)
{
 rdv_credits_progress(e);
 rdv_control_events(e);
 if(e->mailbox){
  uint64_t frontier=sir_rdv_event_frontier(e->mailbox);struct sir_rdv_record event;
  while(!sir_rdv_event_take(e->mailbox,frontier,&event)){
   struct npr_rdv_owner *o;for(o=e->owners;o;o=o->next)if(o->app_token==event.app_token&&o->mailbox_token==event.token)break;
   if(o){(void)npr_rdv_owner_event(o,&event);(void)sir_rdv_event_ack(e->mailbox,event.token,event.serial);continue;}
   if(event.kind==SIR_RDV_OFFER_READY&&!rdv_offer_record(e,&event))continue; /* Retain delivery until reply or MATCH. */
   struct rdv_attempt *a=rdv_attempt_find(e,event.token,event.app_token);
   if(a&&event.kind==SIR_RDV_SINK_RELEASED&&rdv_identity_equal(&a->event.value.id,&event.value.id)){
    rdv_attempt_ack(e,a);rdv_attempt_clear(e,a);
   }
   (void)sir_rdv_event_ack(e->mailbox,event.token,event.serial);
  }
  /* Restore cancelled WWI reservations before any later offer selects an
   * RQ from this same finite event frontier. Otherwise it can skip the head. */
  rdv_finish_matches(e);
  for(size_t i=0;i<e->attempt_extent;i++)rdv_attempt_progress(e,&e->attempts[i]);
 }
 rdv_finish_matches(e);
}
static void rdv_source_terminal(struct npr_rdv_owner *o,enum ibv_wc_status status)
{
 struct npr_rdv_qp *q=o->epoch->qp;
 struct ibv_wc wc={.wr_id=o->source_op->wr_id,.qp_num=q->number,.status=status,
  .opcode=o->source_op->kind==NPR_OP_WRITE_IMM?IBV_WC_RDMA_WRITE:IBV_WC_SEND};
 if(status!=IBV_WC_SUCCESS&&status!=IBV_WC_WR_FLUSH_ERR&&q->active==o->epoch&&!o->epoch->closing)q->error_epoch=o->epoch->number;
 int discard=o->source_discard;
 struct npr_order_entry *order=o->source_order;
 if(o->source_op->rdv_owner==o)o->source_op->rdv_owner=NULL;
 o->source_op=NULL;o->source_order=NULL;
 rdv_resources_release(o);rdv_owner_free(o);
 q->cq_ops->source_done(order,&wc,discard);
}
static uint64_t rdv_now(void)
{struct timespec ts;clock_gettime(CLOCK_MONOTONIC,&ts);return (uint64_t)ts.tv_sec*1000000000u+(uint64_t)ts.tv_nsec;}
static int rdv_source_spans(struct npr_rdv_owner *o)
{
 struct npr_op *op=o->source_op;size_t cap=0;uint64_t offset=0;
 for(unsigned i=0;i<op->num_sge;i++){
  uint64_t length=op->sge[i].length;if(!length)continue;
  struct sir_rdv_span span={.length=length,.message_offset=offset};
  if(op->inline_)span.cpu_address=op->sge[i].addr;
  else {
   struct npr_mra_view view;
   if(cap>=o->ncap||npr_mra_claim_used(&o->captures[cap++],0,length,NPR_MRA_SOURCE,&view))return EACCES;
   span.cpu_address=view.cpu_address;op->local_mr[i]=view.adopted;
   if(view.kind==NPR_MRA_CPU_ADOPTED){
    struct npr_rdv_backend_source source;
    if(!o->epoch->qp->backend||o->epoch->qp->backend(&view,&source)||source.fd<0||source.mr_id<0||source.registration_gen!=view.generation)return EACCES;
    size_t n;for(n=0;n<o->nfd;n++)if(o->fds[n].original==source.fd)break;
    if(n==o->nfd){int fd=fcntl(source.fd,F_DUPFD_CLOEXEC,0);if(fd<0)return errno;o->fds[o->nfd++]=(struct rdv_fd){source.fd,fd};}
    span.backend=(struct sir_rdv_backend){.kind=SIR_RDV_SYM_PIN,.dupfd=o->fds[n].duplicate,.mr_id=source.mr_id,.registration_gen=view.generation};
   }
  }
  o->spans[o->nspan++]=span;offset+=length;
 }
 return 0;
}
static int rdv_stats_authorized(struct npr_rdv_epoch *e,const struct crdv_stats *stats)
{
 const struct sir_app_qp_snapshot *a=&stats->authorization;
 struct sir_rdv_identity id={.session_id=a->session_id,.transport_generation=a->transport_generation,
  .command_revision=a->command_revision,.local=a->local,.peer=a->peer};
 return stats->key.cookie==e->qp->key.cookie&&stats->key.generation==e->qp->key.generation&&stats->connection_epoch==e->number&&
  stats->session_id==a->session_id&&stats->transport_generation==a->transport_generation&&a->state==SIR_APP_QP_BOUND&&rdv_current(e,&id);
}
static int rdv_source_publish(struct npr_rdv_owner *o)
{
 struct npr_rdv_epoch *e=o->epoch;
 if(e->qp->actor_ops.capability&&e->qp->actor_ops.capability()==EOPNOTSUPP)return EOPNOTSUPP;
 if(!e->registration)return EAGAIN;
 struct crdv_stats stats;
 if(e->actor_ops.stats(e->registration,&stats)||!stats.data_ready||!rdv_stats_authorized(e,&stats))return EAGAIN;
 o->native_notify=stats.native_wwi;
 if(!o->source_bound){
  const struct sir_app_qp_snapshot *s=&e->binding;
  struct sir_rdv_identity id={.session_id=s->session_id,.transport_generation=s->transport_generation,.command_revision=s->command_revision,
   .local=s->local,.peer=s->peer,.message_id=o->app_token,.rq_message_seq=o->sequence};
  if(!rdv_current(e,&id))return EAGAIN;
  o->identity=id;o->source_bound=1;
  if(o->source_memory_error)return o->source_memory_error;
 }
 /* WWI publishes receive admission before starting its WRITE owner. */
 if(o->source_op->kind==NPR_OP_WRITE_IMM)o->nspan=0;

 struct sir_rdv_value value={.id=o->identity,.length=o->source_op->len,
  .kind=o->source_op->kind==NPR_OP_WRITE_IMM?NPR_RQ_WWI:o->source_op->kind==NPR_OP_SEND_IMM?NPR_RQ_SEND_IMM:NPR_RQ_SEND,
  .imm_be=o->source_op->kind==NPR_OP_SEND?0:o->source_op->imm,.solicited=!!(o->source_op->flags&IBV_SEND_SOLICITED)};
 int rc=npr_rdv_owner_submit(o,&value);
 if(!rc)o->planned_spans=o->nspan;
 return rc;
}
static void rdv_wwi_data_progress(struct npr_rdv_owner *o)
{
 if(o->source_op->kind!=NPR_OP_WRITE_IMM || !o->published ||
    !(o->events&(1u<<(o->native_notify?SIR_RDV_SOURCE_PREPARED:SIR_RDV_WWI_READY))) || o->source_cancel ||
    o->released || o->wwi_result_submitted || o->epoch->qp->native_paused)return;
 struct npr_rdv_epoch *e=o->epoch;
 if(!o->data_started){
  if(!e->qp->cq_ops->source_data)return;
  o->data_started=o->data_pending=1;o->processing=1;
  int rc=e->qp->cq_ops->source_data(e->qp->ce,e->qp->native_qp,o->source_op);
  npr_rdv_source_data_submit_done(o,rc);
 }
 if(o->data_pending||!o->data_done)return;
 if(o->data_status!=IBV_WC_SUCCESS&&o->data_status!=IBV_WC_REM_ACCESS_ERR){
  o->source_cancel=1;o->source_status=o->data_status;rdv_app_wake();return;
 }
 if(o->native_notify&&o->data_status==IBV_WC_SUCCESS){
  if(!o->notify_pending&&!o->notify_done){
   int rc=rdv_native_tx(o);
   if(rc){o->notify_done=1;o->notify_status=IBV_WC_GENERAL_ERR;o->source_cancel=1;o->source_status=IBV_WC_GENERAL_ERR;rdv_app_wake();return;}
  }
  o->wwi_result_submitted=1;return; /* native SEND, no success RESULT frame */
 }
 struct sir_rdv_value result=o->value;
 result.status=o->data_status==IBV_WC_REM_ACCESS_ERR?EREMOTEIO:0;
 int rc=sir_rdv_command_submit(e->mailbox,o->mailbox_token,SIR_RDV_WWI_RESULT,&result,NULL,0);
 if(!rc||rc==EALREADY)o->wwi_result_submitted=1;
 else if(rc!=EAGAIN){o->source_cancel=1;o->source_status=IBV_WC_WR_FLUSH_ERR;rdv_app_wake();}
}
static void rdv_sources(struct npr_rdv_epoch *e,uint64_t frontier)
{
 uint64_t visit=++e->source_visit;
 if(!visit){for(struct npr_rdv_owner *p=e->owners;p;p=p->next)p->source_visit=0;visit=++e->source_visit;}
 for(;;){
  /* Posting transactions may abort/free another prepared owner while a data
   * callback yields. Re-find by visitation mark; never retain next across it. */
  struct npr_rdv_owner *o;
  for(o=e->owners;o;o=o->next)if(o->source_accepted&&o->app_token<=frontier&&o->source_visit!=visit)break;
  if(!o)break;
  o->source_visit=visit;
  /* A prepared descriptor belongs to its posting transaction even when ERR
   * happens during the authority-query gate yield. Only its caller aborts it. */
  if(!o->source_accepted||o->processing)continue;
  if(e->closing){o->source_cancel=1;o->source_status=IBV_WC_WR_FLUSH_ERR;}
  if(o->released){
   if(o->notify_pending){if(o->release_status)e->qp->error_epoch=e->number;continue;}
   if(o->data_pending)continue;
   if(!o->release_status&&!(o->events&(1u<<SIR_RDV_PEER_ACK)))continue;
   enum ibv_wc_status status=o->source_discard?IBV_WC_WR_FLUSH_ERR:
    o->release_status==ETIMEDOUT?IBV_WC_RNR_RETRY_EXC_ERR:
    o->release_status==EACCES?((o->events&(1u<<SIR_RDV_PEER_ACK))?IBV_WC_REM_OP_ERR:IBV_WC_LOC_PROT_ERR):
    o->release_status==EMSGSIZE?((o->events&(1u<<SIR_RDV_PEER_ACK))?IBV_WC_REM_INV_REQ_ERR:IBV_WC_GENERAL_ERR):
    o->release_status==ECANCELED?IBV_WC_WR_FLUSH_ERR:
    o->release_status?IBV_WC_GENERAL_ERR:o->source_cancel?o->source_status:IBV_WC_SUCCESS;
   if(o->source_op->kind==NPR_OP_WRITE_IMM&&o->data_done&&o->data_status!=IBV_WC_SUCCESS)status=o->data_status;
   else if(o->notify_done&&o->notify_status!=IBV_WC_SUCCESS&&
     (o->notify_status!=IBV_WC_WR_FLUSH_ERR||!o->release_status||o->release_status==ECANCELED))status=o->notify_status;
   rdv_source_terminal(o,status);continue;
  }
  if(!o->source_cancel&&o->native_notify&&npr_op_is_send(o->source_op)&&
     (o->events&(1u<<SIR_RDV_SOURCE_PREPARED))&&!o->notify_pending&&!o->notify_done&&!e->qp->native_paused){
   int rc=rdv_native_tx(o);
   if(rc){o->notify_done=1;o->notify_status=IBV_WC_GENERAL_ERR;o->source_cancel=1;o->source_status=IBV_WC_GENERAL_ERR;}
  }
  if(!o->source_cancel)rdv_wwi_data_progress(o);
  if(o->data_pending||o->notify_pending)continue;
  if(o->source_cancel&&!o->published){
   enum ibv_wc_status status=!o->source_discard&&o->data_done&&o->data_status!=IBV_WC_SUCCESS&&o->data_status!=IBV_WC_WR_FLUSH_ERR?o->data_status:o->source_status;
   if(!sir_rdv_message_abort(e->mailbox,o->mailbox_token))rdv_source_terminal(o,status);
   continue;
  }
  if(o->source_cancel&&o->published){
   struct sir_rdv_value cancel=o->value;cancel.status=ECANCELED;
   (void)sir_rdv_command_submit(e->mailbox,o->mailbox_token,SIR_RDV_CANCEL,&cancel,NULL,0);
  }
  if(o->source_dispatch&&!o->source_cancel&&!o->published){
   if(e->qp->native_state!=IBV_QPS_RTS){o->bind_deadline=0;continue;}
   if(!o->bind_deadline)o->bind_deadline=rdv_now()+5000000000ull;
   int rc=rdv_source_publish(o);
   if(rc==EAGAIN&&rdv_now()<o->bind_deadline){rdv_deadline(o->bind_deadline);continue;}
   if(rc){
    enum ibv_wc_status status=o->data_done&&o->data_status!=IBV_WC_SUCCESS?o->data_status:rc==EACCES?IBV_WC_LOC_PROT_ERR:IBV_WC_GENERAL_ERR;
    if(!sir_rdv_message_abort(e->mailbox,o->mailbox_token))rdv_source_terminal(o,status);
   }
  }
 }
}
static void rdv_stats_accumulate(struct crdv_stats *to,const struct crdv_stats *from)
{
#define ADD(field) to->field+=from->field
 ADD(wwi_offers_posted);ADD(wwi_ready_posted);ADD(native_arrivals);
 ADD(source_messages_offered);ADD(source_offers_posted);ADD(sink_offers_received);ADD(sink_matches);
 ADD(reverse_read_posted);ADD(reverse_read_wc);ADD(wire_ack_validated);ADD(source_released);ADD(sink_released);
#undef ADD
}
static int rdv_epoch_reap(struct npr_rdv_epoch *e)
{
 struct npr_rq_completion c;
 while(!npr_rq_peek_terminal(e->rq,&c)&&c.discard)(void)npr_rq_retire(e->rq,c.token);
 struct npr_rq_counts counts;npr_rq_get_counts(e->rq,&counts);
 if(e->native_refs||e->credits||e->control_borrows||e->owners||counts.queued||counts.claimed||counts.terminal)return 0;
 if(e->registration){
  struct crdv_stats final;
  if(e->actor_ops.final_stats(e->registration,&final))return 0;
  if(final.key.cookie!=e->qp->key.cookie||final.key.generation!=e->qp->key.generation||final.connection_epoch!=e->number)return 0;
  if(e->actor_ops.free(e->registration))return 0;
  rdv_stats_accumulate(&e->qp->history,&final);e->registration=NULL;
 }
 if(e->mailbox&&sir_rdv_mailbox_free(e->mailbox))return 0;
 return 1;
}
static void rdv_register_active(struct npr_rdv_qp *q)
{
 if(!q->data_enabled||q->closed||!q->active||q->active->closing||q->active->registration||!q->service_set||!q->actor_ops.register_qp||q->policy!=SIR_APP_QP_RENDEZVOUS_REQUIRED)return;
 struct crdv_registration_config config;int rc=npr_rdv_actor_config(q,&q->actor_ops,&config);
 if(rc)return;
 struct crdv_registration *registration=NULL;
 if(!q->actor_ops.register_qp(&config,&registration))npr_rdv_actor_attach(q,registration);
}
void npr_rdv_progress(void)
{
 /* Callback/native/PIN boundaries may yield the API gate. A second pump may
  * update lifecycle metadata, but cannot reclaim objects borrowed here. */
 if(rdv_pumping)return;
 rdv_pumping=1;
 uint64_t owner_frontier=rdv_next_owner?rdv_next_owner-1:UINT64_MAX;
 uint64_t visit=++rdv_pump_visit;
 if(!visit){
  for(struct npr_rdv_qp *q=rdv_qps;q;q=q->next){if(q->active)q->active->pump_visit=0;for(struct npr_rdv_epoch *e=q->retired;e;e=e->next)e->pump_visit=0;}
  visit=++rdv_pump_visit;
 }
 /* Only this pump frees committed QPs. A saved next QP is stable; newly
  * prepended QPs wait for the next finite round. Never retain a link address
  * across a callback, because RESET/create may prepend to either registry. */
 struct npr_rdv_qp *q=rdv_qps,*next_q;
 for(;q;q=next_q){
  next_q=q->next;
  uint64_t epoch_frontier=q->active?q->active->number:UINT64_MAX;
  rdv_register_active(q);
  if(q->data_enabled&&q->active&&!q->active->closing&&q->actor_ops.capability&&q->actor_ops.capability()==EOPNOTSUPP){
   struct npr_rq_counts count;npr_rq_get_counts(q->active->rq,&count);
   if(count.queued||count.claimed)npr_rdv_error(q);
  }
  if(q->active){struct npr_rdv_epoch *e=q->active;e->pump_visit=visit;rdv_events(e);rdv_sources(e,owner_frontier);rdv_control_progress(e);}
  for(;;){
   struct npr_rdv_epoch *e;
   for(e=q->retired;e;e=e->next)if(e->pump_visit!=visit&&e->number<=epoch_frontier)break;
   if(!e)break;
   e->pump_visit=visit;rdv_events(e);rdv_sources(e,owner_frontier);rdv_control_progress(e);
   struct npr_rdv_epoch *after=e->next;
   if(rdv_epoch_reap(e)){
    struct npr_rdv_epoch **link=&q->retired;while(*link&&*link!=e)link=&(*link)->next;
    assert(*link==e);*link=after;
    npr_rq_put(e->rq);free(e->attempts);free(e);
   }
  }
  if(q->error_epoch){
   uint64_t epoch=q->error_epoch;q->error_epoch=0;
   if(!q->closed&&q->active&&q->active->number==epoch&&!q->active->closing){
    if(q->cq_ops&&q->cq_ops->qp_error)(void)q->cq_ops->qp_error(q->ce,q->native_qp);
    /* ERR cannot certify SIR DMA stop. Owners retain original receipts. */
    if(!q->closed&&q->active&&q->active->number==epoch&&!q->active->closing)npr_rdv_error(q);
   }
  }
  if(q->closed&&!q->retired){
   struct npr_rdv_qp **link=&rdv_qps;while(*link&&*link!=q)link=&(*link)->next;
   assert(*link==q);*link=q->next;free(q);
  }
 }
 rdv_pumping=0;
}
int npr_rdv_snapshot(const struct npr_rdv_qp *q,struct npr_rdv_snapshot *out)
{
 if(!q||!out)return EINVAL;
 memset(out,0,sizeof(*out));out->key=q->key;out->policy=q->policy;out->closed=q->closed;out->visible_cap=q->visible;out->provider_cap=q->provider;
 if(q->active){out->connection_epoch=q->active->number;npr_rq_get_counts(q->active->rq,&out->rq);for(struct npr_rdv_owner *o=q->active->owners;o;o=o->next)out->owners++;}
 for(struct npr_rdv_epoch *e=q->retired;e;e=e->next){out->retired_epochs++;for(struct npr_rdv_owner *o=e->owners;o;o=o->next)out->owners++;}
 return 0;
}

#ifdef NPRDMA_TEST_INJECT
#include "npr_inject.h"
static void rdv_test_epoch(struct npr_rdv_epoch *e,struct npr_test_rdv_qp *out,int retired)
{
 struct npr_rq_counts count;npr_rq_get_counts(e->rq,&count);
 out->queued_rq+=count.queued;out->matched_rq+=count.claimed;out->terminal_rq+=count.terminal;out->core_captures+=count.captures;
 for(struct npr_rdv_owner *o=e->owners;o;o=o->next){out->core_owners++;out->core_captures+=o->ncap;out->core_dup_fds+=o->nfd;if(retired)out->retired_core_owners++;}
 if(!e->registration)return;
 struct crdv_stats s;
 if(e->actor_ops.stats(e->registration,&s)||s.key.cookie!=e->qp->key.cookie||s.key.generation!=e->qp->key.generation||s.connection_epoch!=e->number)return;
#define RDV_TEST_ADD(f) out->f+=s.f
 RDV_TEST_ADD(source_messages_offered);RDV_TEST_ADD(source_offers_posted);RDV_TEST_ADD(sink_offers_received);RDV_TEST_ADD(sink_matches);
 RDV_TEST_ADD(reverse_read_posted);RDV_TEST_ADD(reverse_read_wc);RDV_TEST_ADD(wire_ack_validated);RDV_TEST_ADD(source_released);RDV_TEST_ADD(sink_released);
 RDV_TEST_ADD(actor_sources);RDV_TEST_ADD(actor_sinks);RDV_TEST_ADD(actor_pin_spans);RDV_TEST_ADD(actor_bridge_mrs);RDV_TEST_ADD(actor_native_outstanding);RDV_TEST_ADD(actor_cleanup_pending);
#undef RDV_TEST_ADD
 if(retired)out->retired_actor_resources+=s.actor_sources+s.actor_sinks+s.actor_pin_spans+s.actor_bridge_mrs+s.actor_native_outstanding+s.actor_cleanup_pending;
 else if(rdv_stats_authorized(e,&s)){
  out->actor_stats_valid=1;out->session_id=s.session_id;out->transport_generation=s.transport_generation;
  out->data_enabled=e->qp->data_enabled&&s.data_ready&&e->binding.state==SIR_APP_QP_BOUND&&!e->closing;
 }
}
int npr_rdv_test_protocol(struct npr_rdv_qp *q,struct npr_test_wwi_protocol *out)
{
 if(!q||!out)return EINVAL;
 *out=(struct npr_test_wwi_protocol){.abi=NPR_TEST_WWI_PROTOCOL_ABI,.size=sizeof(*out),
  .native_send_posted=q->native_send_posted,.native_wwi_posted=q->native_wwi_posted,
  .native_recv_posted=q->native_recv_posted,.native_recv_done=q->native_recv_done,
  .wwi_offers_posted=q->history.wwi_offers_posted,.wwi_ready_posted=q->history.wwi_ready_posted,.native_arrivals=q->history.native_arrivals};
 for(struct npr_rdv_epoch *e=q->active?q->active:q->retired;e;e=e==q->active?q->retired:e->next){
  out->native_outstanding+=e->native_refs;
  for(struct rdv_native_credit *c=e->credits;c;c=c->next)out->receive_slots++;
  struct crdv_stats stats;
  if(e->registration&&!e->actor_ops.stats(e->registration,&stats)){
   out->wwi_offers_posted+=stats.wwi_offers_posted;out->wwi_ready_posted+=stats.wwi_ready_posted;out->native_arrivals+=stats.native_arrivals;
  }
 }
 return 0;
}
void npr_rdv_native_recv_posted(struct npr_ctx_entry *ce,struct ibv_qp *qp)
{struct npr_rdv_qp *q=rdv_find(ce,qp);if(q)q->native_rq_posted++;}
int npr_rdv_test_snapshot(struct npr_rdv_qp *q,struct npr_test_rdv_qp *out)
{
 if(!q||!out)return EINVAL;
 memset(out,0,sizeof(*out));out->abi=NPR_TEST_RDV_ABI;out->size=sizeof(*out);out->policy=q->policy;out->native_state=q->native_state;
 out->cookie=q->key.cookie;out->generation=q->key.generation;out->virtual_rq_posted=q->virtual_rq_posted;out->source_admitted=q->source_admitted;out->native_rq_posted=q->native_rq_posted;
 out->capability_status=q->actor_ops.capability?(unsigned)q->actor_ops.capability():EAGAIN;
#define RDV_TEST_HISTORY(f) out->f=q->history.f
 RDV_TEST_HISTORY(source_messages_offered);RDV_TEST_HISTORY(source_offers_posted);RDV_TEST_HISTORY(sink_offers_received);RDV_TEST_HISTORY(sink_matches);
 RDV_TEST_HISTORY(reverse_read_posted);RDV_TEST_HISTORY(reverse_read_wc);RDV_TEST_HISTORY(wire_ack_validated);RDV_TEST_HISTORY(source_released);RDV_TEST_HISTORY(sink_released);
#undef RDV_TEST_HISTORY
 if(q->active){out->connection_epoch=q->active->number;rdv_test_epoch(q->active,out,0);}
 for(struct npr_rdv_epoch *e=q->retired;e;e=e->next){out->retired_epochs++;rdv_test_epoch(e,out,1);}
 return 0;
}
#endif

#include "npr_rdv_control.inc"
