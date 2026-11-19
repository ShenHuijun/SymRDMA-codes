/* SPDX-License-Identifier: GPL-2.0 */
#include "app_rdv_mailbox.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

struct rdv_delivery { struct sir_rdv_record r; unsigned state; };
struct rdv_slot {
 uint64_t token,app_token;
 enum sir_rdv_role role;
 unsigned published,terminal_acked;
 size_t refs[SIR_RDV_HOLD_N];
 struct sir_rdv_value value;
 struct sir_rdv_span *spans;
 size_t nspan;
 struct rdv_delivery cmd[3],event[SIR_RDV_EVENT_N];
};
struct rdv_drain_delivery {struct sir_rdv_drain_record r;unsigned state;};
struct sir_rdv_mailbox {
 pthread_mutex_t mu;
 struct sir_rdv_mailbox_config cfg;
 struct rdv_slot *slots;
 struct rdv_drain_delivery drain_cmd[2],drain_event[2];
 struct sir_rdv_span *spans;
 size_t used,external_refs,wake_refs;
 size_t occupied_extent; /* Highest occupied slot + 1; protected by mu. */
 unsigned closed;
 uint64_t next_serial;
};
static pthread_mutex_t token_mu=PTHREAD_MUTEX_INITIALIZER;
static uint64_t next_token=1;

static struct rdv_slot *find_slot(struct sir_rdv_mailbox *b,uint64_t token)
{
 if(!token)return NULL;
 for(size_t i=0;i<b->occupied_extent;i++)if(b->slots[i].token==token)return &b->slots[i];
 return NULL;
}
static int serial_new(struct sir_rdv_mailbox *b,uint64_t *out)
{
 if(!b->next_serial)return EOVERFLOW;
 *out=b->next_serial++;
 return 0;
}
static int endpoint_equal(const struct sir_app_qp_endpoint *a,const struct sir_app_qp_endpoint *b)
{
 return a->key.cookie==b->key.cookie&&a->key.generation==b->key.generation&&
 a->route.connection_epoch==b->route.connection_epoch&&a->route.local_qpn==b->route.local_qpn&&
 a->route.peer_qpn==b->route.peer_qpn&&a->route.local_lid==b->route.local_lid&&
 a->route.peer_lid==b->route.peer_lid&&a->route.port_num==b->route.port_num&&
 a->route.kind==b->route.kind&&a->bind_nonce==b->bind_nonce&&a->policy==b->policy&&
 !memcmp(a->route.local_gid,b->route.local_gid,16)&&!memcmp(a->route.peer_gid,b->route.peer_gid,16);
}
static int identity_equal(const struct sir_rdv_identity *a,const struct sir_rdv_identity *b)
{
 return a->session_id==b->session_id&&a->transport_generation==b->transport_generation&&
 a->command_revision==b->command_revision&&a->message_id==b->message_id&&
 a->rq_message_seq==b->rq_message_seq&&endpoint_equal(&a->local,&b->local)&&endpoint_equal(&a->peer,&b->peer);
}
static int value_equal(const struct sir_rdv_value *a,const struct sir_rdv_value *b)
{
 return a->id.session_id==b->id.session_id&&a->id.transport_generation==b->id.transport_generation&&
 a->id.command_revision==b->id.command_revision&&a->id.message_id==b->id.message_id&&
 a->id.rq_message_seq==b->id.rq_message_seq&&endpoint_equal(&a->id.local,&b->id.local)&&
 endpoint_equal(&a->id.peer,&b->id.peer)&&a->length==b->length&&a->kind==b->kind&&
 a->imm_be==b->imm_be&&a->solicited==b->solicited&&a->status==b->status;
}
/* The caller owns mu. Temporary references cover unlock -> wake -> return.
 * Explicit free cannot succeed before all of these references are returned. */
static void unlock_wake(struct sir_rdv_mailbox *b,unsigned actor,unsigned app)
{
 unsigned run[2]={actor,app};
 void (*fn[2])(void *)={b->cfg.wake_actor,b->cfg.wake_app};
 void *opaque=b->cfg.wake_opaque;
 for(unsigned i=0;i<2;i++){
  run[i]=run[i]&&fn[i];
  if(run[i])b->wake_refs++;
 }
 pthread_mutex_unlock(&b->mu);
 for(unsigned i=0;i<2;i++)if(run[i])fn[i](opaque);
 if(run[0]||run[1]){
  pthread_mutex_lock(&b->mu);
  for(unsigned i=0;i<2;i++)if(run[i])b->wake_refs--;
  pthread_mutex_unlock(&b->mu);
 }
}
static void clear_slot(struct sir_rdv_mailbox *b,struct rdv_slot *s)
{
 struct sir_rdv_span *spans=s->spans;
 memset(s,0,sizeof(*s));s->spans=spans;b->used--;
 while(b->occupied_extent&&!b->slots[b->occupied_extent-1].token)b->occupied_extent--;
}
static unsigned try_recycle(struct sir_rdv_mailbox *b,struct rdv_slot *s)
{
 if(!s->terminal_acked)return 0;
 for(unsigned i=0;i<SIR_RDV_HOLD_N;i++)if(s->refs[i])return 0;
 for(unsigned i=0;i<3;i++)if(s->cmd[i].state==1||s->cmd[i].state==2)return 0;
 for(unsigned i=0;i<SIR_RDV_EVENT_N;i++)if(s->event[i].state==1||s->event[i].state==2)return 0;
 clear_slot(b,s);return 1;
}
int sir_rdv_mailbox_new(const struct sir_rdv_mailbox_config *cfg,struct sir_rdv_mailbox **out)
{
 if(!cfg||!out)return EINVAL;
 *out=NULL;
 if(!cfg->slot_count||cfg->slot_count>SIZE_MAX/sizeof(struct rdv_slot)||
 (cfg->max_spans&&cfg->slot_count>SIZE_MAX/cfg->max_spans)||
 (cfg->max_spans&&cfg->slot_count*cfg->max_spans>SIZE_MAX/sizeof(struct sir_rdv_span)))return EINVAL;
 struct sir_rdv_mailbox *b=calloc(1,sizeof(*b));
 if(!b)return ENOMEM;
 b->slots=calloc(cfg->slot_count,sizeof(*b->slots));
 if(!b->slots){free(b);return ENOMEM;}
 if(cfg->max_spans){
  b->spans=calloc(cfg->slot_count*cfg->max_spans,sizeof(*b->spans));
  if(!b->spans){free(b->slots);free(b);return ENOMEM;}
 }
 int rc=pthread_mutex_init(&b->mu,NULL);
 if(rc){free(b->spans);free(b->slots);free(b);return rc;}
 b->cfg=*cfg;b->next_serial=1;
 for(size_t i=0;i<cfg->slot_count;i++)if(b->spans)b->slots[i].spans=b->spans+i*cfg->max_spans;
 *out=b;return 0;
}
int sir_rdv_mailbox_get(struct sir_rdv_mailbox *b)
{
 if(!b)return EINVAL;
 pthread_mutex_lock(&b->mu);
 int rc=b->external_refs==SIZE_MAX?EOVERFLOW:0;
 if(!rc)b->external_refs++;
 pthread_mutex_unlock(&b->mu);return rc;
}
int sir_rdv_mailbox_put(struct sir_rdv_mailbox *b)
{
 if(!b)return EINVAL;
 pthread_mutex_lock(&b->mu);
 int rc=!b->external_refs?EINVAL:0;
 if(!rc)b->external_refs--;
 pthread_mutex_unlock(&b->mu);return rc;
}
static int drain_busy(struct sir_rdv_mailbox *b)
{
 for(unsigned i=0;i<2;i++)
  if(b->drain_cmd[i].state==1||b->drain_cmd[i].state==2||
     b->drain_event[i].state==1||b->drain_event[i].state==2)return 1;
 return 0;
}
int sir_rdv_mailbox_free(struct sir_rdv_mailbox *b)
{
 if(!b)return EINVAL;
 pthread_mutex_lock(&b->mu);
 if(!b->closed||b->used||b->external_refs||b->wake_refs||drain_busy(b)){pthread_mutex_unlock(&b->mu);return EBUSY;}
 pthread_mutex_unlock(&b->mu);
 pthread_mutex_destroy(&b->mu);free(b->spans);free(b->slots);free(b);return 0;
}
void sir_rdv_mailbox_counts(struct sir_rdv_mailbox *b,struct sir_rdv_mailbox_counts *out)
{
 if(!b||!out)return;
 pthread_mutex_lock(&b->mu);
 *out=(struct sir_rdv_mailbox_counts){.reserved=b->used,.external_refs=b->external_refs,.wake_refs=b->wake_refs,.closed=b->closed,.control_pending=(size_t)drain_busy(b)};
 pthread_mutex_unlock(&b->mu);
}
int sir_rdv_message_reserve(struct sir_rdv_mailbox *b,enum sir_rdv_role role,uint64_t app_token,uint64_t *token)
{
 if(!b||!token||(role!=SIR_RDV_SOURCE&&role!=SIR_RDV_SINK))return EINVAL;
 *token=0;pthread_mutex_lock(&b->mu);
 if(b->closed){pthread_mutex_unlock(&b->mu);return ESHUTDOWN;}
 struct rdv_slot *s=NULL;
 for(size_t i=0;i<b->cfg.slot_count;i++)if(!b->slots[i].token){s=&b->slots[i];break;}
 if(!s){pthread_mutex_unlock(&b->mu);return EAGAIN;}
 pthread_mutex_lock(&token_mu);
 if(!next_token){pthread_mutex_unlock(&token_mu);pthread_mutex_unlock(&b->mu);return EOVERFLOW;}
 s->token=next_token++;
 pthread_mutex_unlock(&token_mu);
 s->app_token=app_token;s->role=role;b->used++;*token=s->token;
 size_t end=(size_t)(s-b->slots)+1;if(end>b->occupied_extent)b->occupied_extent=end;
 pthread_mutex_unlock(&b->mu);return 0;
}
int sir_rdv_message_abort(struct sir_rdv_mailbox *b,uint64_t token)
{
 if(!b)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_slot *s=find_slot(b,token);
 int rc=!s?ESTALE:s->published?EBUSY:0;
 if(!rc)for(unsigned i=0;i<SIR_RDV_HOLD_N;i++)if(s->refs[i]){rc=EBUSY;break;}
 if(!rc)clear_slot(b,s);
 pthread_mutex_unlock(&b->mu);return rc;
}
int sir_rdv_message_hold(struct sir_rdv_mailbox *b,uint64_t token,enum sir_rdv_hold kind)
{
 if(!b||(unsigned)kind>=SIR_RDV_HOLD_N)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_slot *s=find_slot(b,token);
 int rc=!s?ESTALE:(s->event[SIR_RDV_SOURCE_RELEASED].state||s->event[SIR_RDV_SINK_RELEASED].state)?ESHUTDOWN:s->refs[kind]==SIZE_MAX?EOVERFLOW:0;
 if(!rc)s->refs[kind]++;
 pthread_mutex_unlock(&b->mu);return rc;
}
int sir_rdv_message_drop(struct sir_rdv_mailbox *b,uint64_t token,enum sir_rdv_hold kind)
{
 if(!b||(unsigned)kind>=SIR_RDV_HOLD_N)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_slot *s=find_slot(b,token);
 int rc=!s?ESTALE:!s->refs[kind]?EINVAL:0;
 unsigned recycled=0;
 if(!rc){s->refs[kind]--;recycled=try_recycle(b,s);}
 unlock_wake(b,0,recycled);return rc;
}
static int delivery_set(struct sir_rdv_mailbox *b,struct rdv_slot *s,struct rdv_delivery *d,
 unsigned kind,unsigned evidence,const struct sir_rdv_value *value,unsigned spans)
{
 if(d->state)return value_equal(&d->r.value,value)&&d->r.evidence==evidence?EALREADY:EPROTO;
 uint64_t serial;int rc=serial_new(b,&serial);if(rc)return rc;
 d->r=(struct sir_rdv_record){.token=s->token,.serial=serial,.app_token=s->app_token,
  .kind=kind,.span_count=spans,.evidence=evidence,.value=*value};
 d->state=1;
 if(!s->published)s->value=*value;
 s->published=1;return 0;
}
int sir_rdv_command_submit(struct sir_rdv_mailbox *b,uint64_t token,enum sir_rdv_command_kind kind,
 const struct sir_rdv_value *value,const struct sir_rdv_span *spans,size_t nspan)
{
 if(!b||!value||kind<SIR_RDV_SOURCE_PREPARE||kind>SIR_RDV_NATIVE_EXPOSED||nspan>UINT_MAX||(!spans&&nspan))return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_slot *s=find_slot(b,token);int rc=0;
 if(!s)rc=ESTALE;
 else if((b->closed&&kind!=SIR_RDV_CANCEL)||s->terminal_acked)rc=ESHUTDOWN;
 else if(nspan>b->cfg.max_spans)rc=EMSGSIZE;
 else if(s->published&&!identity_equal(&s->value.id,&value->id))rc=ESTALE;
 else if(kind==SIR_RDV_CANCEL&&!s->published)rc=EINVAL;
 else if((kind==SIR_RDV_SOURCE_PREPARE||kind==SIR_RDV_WWI_RESULT)&&s->role!=SIR_RDV_SOURCE)rc=EINVAL;
 else if(kind==SIR_RDV_MATCH_PREPARE&&s->role!=SIR_RDV_SINK)rc=EINVAL;
 else if(kind==SIR_RDV_WWI_RESULT&&(!s->published||value->kind!=3||nspan||
   (!s->event[SIR_RDV_WWI_READY].state&&!s->event[SIR_RDV_SOURCE_PREPARED].state)||s->value.kind!=3||
   value->length!=s->value.length||value->imm_be!=s->value.imm_be||value->solicited!=s->value.solicited||
   (value->status&&value->status!=EREMOTEIO)))rc=EINVAL;
 else if(kind==SIR_RDV_NATIVE_RECEIVED&&(s->role!=SIR_RDV_SINK||!s->published||(value->kind<1||value->kind>3)||nspan||value->status||
   value->length!=s->value.length||value->imm_be!=s->value.imm_be||value->solicited!=s->value.solicited))rc=EINVAL;
 else if(kind==SIR_RDV_NATIVE_EXPOSED&&(s->role!=SIR_RDV_SOURCE||!s->published||nspan||value->status||
   !s->event[SIR_RDV_SOURCE_PREPARED].state||!value_equal(&s->value,value)))rc=EINVAL;
 else if(kind==SIR_RDV_CANCEL&&nspan)rc=EINVAL;
 else if(s->event[SIR_RDV_SOURCE_RELEASED].state||s->event[SIR_RDV_SINK_RELEASED].state)rc=ESHUTDOWN;
 else {
  for(size_t i=0;i<nspan;i++)if(!sir_rdv_backend_valid(&spans[i].backend)){rc=EINVAL;break;}
  if(rc){pthread_mutex_unlock(&b->mu);return rc;}
  struct rdv_delivery *d=&s->cmd[kind==SIR_RDV_CANCEL?1:(kind==SIR_RDV_WWI_RESULT||kind==SIR_RDV_NATIVE_RECEIVED||kind==SIR_RDV_NATIVE_EXPOSED)?2:0];
  if(d->state&&kind!=SIR_RDV_CANCEL){
   rc=EALREADY;
   if(d->r.kind!=(unsigned)kind||!value_equal(&d->r.value,value)||s->nspan!=nspan)rc=EPROTO;
   else for(size_t i=0;i<nspan;i++)if(s->spans[i].cpu_address!=spans[i].cpu_address||
    s->spans[i].length!=spans[i].length||s->spans[i].message_offset!=spans[i].message_offset||
    !sir_rdv_backend_equal(&s->spans[i].backend,&spans[i].backend)){rc=EPROTO;break;}
  }else rc=delivery_set(b,s,d,kind,0,value,(unsigned)nspan);
  if(!rc&&(kind==SIR_RDV_SOURCE_PREPARE||kind==SIR_RDV_MATCH_PREPARE)){
   s->value=*value;s->nspan=nspan;
   if(nspan)memcpy(s->spans,spans,nspan*sizeof(*spans));
  }
 }
 unlock_wake(b,!rc,0);return rc;
}
int sir_rdv_mailbox_close(struct sir_rdv_mailbox *b)
{
 if(!b)return EINVAL;
 pthread_mutex_lock(&b->mu);int rc=0;unsigned wake=0;b->closed=1;
 for(unsigned i=0;i<2;i++){
  if(b->drain_cmd[i].state==1)b->drain_cmd[i].state=3;
  if(b->drain_event[i].state==1)b->drain_event[i].state=3;
 }
 for(size_t i=0;i<b->occupied_extent;i++){
  struct rdv_slot *s=&b->slots[i];
  if(!s->token||!s->published)continue;
  if(s->event[SIR_RDV_OFFER_READY].state==1)s->event[SIR_RDV_OFFER_READY].state=3;
  if(s->event[SIR_RDV_SOURCE_RELEASED].state||s->event[SIR_RDV_SINK_RELEASED].state)continue;
  /* Accepted MATCH metadata must drain so its original span leases receive
   * a cleaned receipt. The actor observes close and starts no PIN or DMA. */
  if(s->cmd[0].state==1&&s->role==SIR_RDV_SOURCE)s->cmd[0].state=3;
  if(!s->cmd[1].state){
   struct sir_rdv_value value=s->value;value.status=ESHUTDOWN;
   int err=delivery_set(b,s,&s->cmd[1],SIR_RDV_CANCEL,0,&value,0);
   if(err)rc=err;else wake=1;
  }
 }
 unlock_wake(b,wake,0);return rc;
}
static uint64_t frontier(struct sir_rdv_mailbox *b)
{
 if(!b)return 0;
 pthread_mutex_lock(&b->mu);uint64_t n=b->next_serial?b->next_serial-1:UINT64_MAX;
 pthread_mutex_unlock(&b->mu);return n;
}
uint64_t sir_rdv_command_frontier(struct sir_rdv_mailbox *b){return frontier(b);}
uint64_t sir_rdv_event_frontier(struct sir_rdv_mailbox *b){return frontier(b);}
static int delivery_take(struct sir_rdv_mailbox *b,uint64_t limit,struct sir_rdv_record *out,unsigned events)
{
 if(!b||!out)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_delivery *best=NULL;
 for(size_t i=0;i<b->occupied_extent;i++){
  struct rdv_slot *s=&b->slots[i];if(!s->token)continue;
  unsigned n=events?SIR_RDV_EVENT_N:3;struct rdv_delivery *d=events?s->event:s->cmd;
  for(unsigned j=0;j<n;j++)if(d[j].state==1&&d[j].r.serial<=limit&&
    (!best||d[j].r.serial<best->r.serial))best=&d[j];
 }
 if(best){best->state=2;*out=best->r;}
 pthread_mutex_unlock(&b->mu);return best?0:EAGAIN;
}
int sir_rdv_command_take(struct sir_rdv_mailbox *b,uint64_t limit,struct sir_rdv_record *out){return delivery_take(b,limit,out,0);}
int sir_rdv_event_take(struct sir_rdv_mailbox *b,uint64_t limit,struct sir_rdv_record *out){return delivery_take(b,limit,out,1);}
static int delivery_ack(struct sir_rdv_mailbox *b,uint64_t token,uint64_t serial,unsigned events)
{
 if(!b||!serial)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_slot *s=find_slot(b,token);int rc=ESTALE;unsigned recycled=0;
 if(s){
  unsigned n=events?SIR_RDV_EVENT_N:3;struct rdv_delivery *d=events?s->event:s->cmd;
  for(unsigned j=0;j<n;j++)if(d[j].state&&d[j].r.serial==serial){
   rc=d[j].state==2?0:EINVAL;
   if(!rc){d[j].state=3;if(events&&(j==SIR_RDV_SOURCE_RELEASED||j==SIR_RDV_SINK_RELEASED))s->terminal_acked=1;}
   break;
  }
  if(!rc)recycled=try_recycle(b,s);
 }
 unlock_wake(b,0,recycled);return rc;
}
int sir_rdv_command_ack(struct sir_rdv_mailbox *b,uint64_t token,uint64_t serial){return delivery_ack(b,token,serial,0);}
int sir_rdv_event_ack(struct sir_rdv_mailbox *b,uint64_t token,uint64_t serial){return delivery_ack(b,token,serial,1);}
int sir_rdv_spans_copy(struct sir_rdv_mailbox *b,uint64_t token,struct sir_rdv_span *out,size_t cap,size_t *count)
{
 if(!b||!count)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_slot *s=find_slot(b,token);int rc=0;
 if(!s)rc=ESTALE;
 else {
  *count=s->nspan;
  if(cap<s->nspan||(!out&&s->nspan))rc=EMSGSIZE;
  else if(s->nspan)memcpy(out,s->spans,s->nspan*sizeof(*out));
 }
 pthread_mutex_unlock(&b->mu);return rc;
}
int sir_rdv_event_publish(struct sir_rdv_mailbox *b,uint64_t token,enum sir_rdv_event_kind kind,const struct sir_rdv_value *value)
{
 if(!b||!value||((unsigned)kind>SIR_RDV_DMA_STOPPED&&kind!=SIR_RDV_WWI_READY&&kind!=SIR_RDV_SOURCE_PREPARED))return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_slot *s=find_slot(b,token);int rc=0;
 if(!s)rc=ESTALE;
 else if(!s->published&&kind!=SIR_RDV_OFFER_READY)rc=EINVAL;
 else if(s->published&&!identity_equal(&s->value.id,&value->id))rc=ESTALE;
 else if(s->terminal_acked||s->event[SIR_RDV_SOURCE_RELEASED].state||s->event[SIR_RDV_SINK_RELEASED].state)rc=ESHUTDOWN;
 else if(kind==SIR_RDV_SOURCE_PREPARED&&(s->role!=SIR_RDV_SOURCE||value->status||!value_equal(&s->value,value)))rc=EINVAL;
 else if(kind==SIR_RDV_WWI_READY&&(s->role!=SIR_RDV_SOURCE||value->kind!=3||value->status||!value_equal(&s->value,value)))rc=EINVAL;
 else if(kind==SIR_RDV_OFFER_READY&&(b->closed||s->role!=SIR_RDV_SINK))rc=ESHUTDOWN;
 else {rc=delivery_set(b,s,&s->event[kind],kind,0,value,0);if(!rc&&kind==SIR_RDV_OFFER_READY)s->value=*value;}
 unlock_wake(b,0,!rc);return rc;
}
int sir_rdv_message_released(struct sir_rdv_mailbox *b,uint64_t token,enum sir_rdv_release_evidence evidence,const struct sir_rdv_value *value)
{
 if(!b||!value||evidence<SIR_RDV_NO_DATA||evidence>SIR_RDV_STOPPED_CLEANED)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_slot *s=find_slot(b,token);int rc=0;
 if(!s)rc=ESTALE;
 else if(s->published&&!identity_equal(&s->value.id,&value->id))rc=ESTALE;
 else if(s->refs[SIR_RDV_NATIVE]||s->refs[SIR_RDV_CLEANUP]||s->cmd[0].state==2||s->cmd[1].state==2||s->cmd[2].state==2)rc=EBUSY;
 /* A copied MATCH may already own application leases before the actor
  * consumes it. Do not retire that queued prepare with an empty receipt:
  * the actor must consume it and prove cleanup of the original spans. */
 else if(s->role==SIR_RDV_SINK&&s->nspan&&evidence==SIR_RDV_NO_DATA)rc=EBUSY;
 else if(evidence==SIR_RDV_STOPPED_CLEANED&&!s->event[SIR_RDV_DMA_STOPPED].state)rc=EPROTO;
 else if(s->role==SIR_RDV_SOURCE&&evidence==SIR_RDV_DATA_CLEANED&&!s->event[SIR_RDV_PEER_ACK].state)rc=EPROTO;
 else {
  unsigned kind=s->role==SIR_RDV_SOURCE?SIR_RDV_SOURCE_RELEASED:SIR_RDV_SINK_RELEASED;
  rc=delivery_set(b,s,&s->event[kind],kind,evidence,value,0);
  if(!rc){
   for(unsigned i=0;i<3;i++)if(s->cmd[i].state==1)s->cmd[i].state=3;
   if(s->event[SIR_RDV_OFFER_READY].state==1)s->event[SIR_RDV_OFFER_READY].state=3;
  }
 }
 unlock_wake(b,0,!rc);return rc;
}

void sir_rdv_mailbox_notify_app(struct sir_rdv_mailbox *b)
{if(!b)return;pthread_mutex_lock(&b->mu);unlock_wake(b,0,1);}

static int drain_record_equal(const struct sir_rdv_drain_record *a,const struct sir_rdv_drain_record *b)
{
 return a->nonce==b->nonce&&a->frontier==b->frontier&&a->head==b->head&&
 a->side==b->side&&a->kind==b->kind&&a->status==b->status&&identity_equal(&a->id,&b->id);
}
int sir_rdv_drain_publish(struct sir_rdv_mailbox *b,unsigned events,const struct sir_rdv_drain_record *r)
{
 if(!b||!r||events>1||r->side>1||!r->nonce||r->kind<SIR_RDV_DRAIN_BEGIN||r->kind>SIR_RDV_DRAIN_DONE)return EINVAL;
 if(events?(r->kind!=SIR_RDV_DRAIN_DONE&&(r->kind!=SIR_RDV_DRAIN_BEGIN||r->side!=SIR_RDV_DRAIN_PEER)):
   (r->kind==SIR_RDV_DRAIN_DONE||(r->kind==SIR_RDV_DRAIN_BEGIN&&r->side!=SIR_RDV_DRAIN_LOCAL)))return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_drain_delivery *d=events?&b->drain_event[r->side]:&b->drain_cmd[r->side];int rc=0;
 if(b->closed&&r->kind!=SIR_RDV_DRAIN_DONE&&r->kind!=SIR_RDV_DRAIN_CANCEL)rc=ESHUTDOWN;
 else if(d->state&&drain_record_equal(&d->r,r))rc=EALREADY;
 else if(d->state&&r->nonce==d->r.nonce&&!identity_equal(&r->id,&d->r.id))rc=EPROTO;
 else if(d->state&&r->nonce==d->r.nonce&&r->kind==d->r.kind&&
   ((r->kind==SIR_RDV_DRAIN_BEGIN||r->kind==SIR_RDV_DRAIN_DONE)||
    (r->kind==SIR_RDV_DRAIN_HEAD&&(r->frontier!=d->r.frontier||!identity_equal(&r->id,&d->r.id)))))rc=EPROTO;
 else if(d->state==2)rc=EAGAIN;
 else if(d->state==1&&!(r->nonce==d->r.nonce&&
   ((r->kind==SIR_RDV_DRAIN_HEAD&&d->r.kind==SIR_RDV_DRAIN_HEAD)||r->kind==SIR_RDV_DRAIN_CANCEL)))rc=EAGAIN;
 else {
  uint64_t serial;rc=serial_new(b,&serial);
  if(!rc){d->r=*r;d->r.serial=serial;d->state=1;}
 }
 unlock_wake(b,!events&&!rc,events&&!rc);return rc;
}
int sir_rdv_drain_take(struct sir_rdv_mailbox *b,unsigned events,uint64_t limit,struct sir_rdv_drain_record *out)
{
 if(!b||events>1||!out)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_drain_delivery *ds=events?b->drain_event:b->drain_cmd,*best=NULL;
 for(unsigned i=0;i<2;i++)if(ds[i].state==1&&ds[i].r.serial<=limit&&(!best||ds[i].r.serial<best->r.serial))best=&ds[i];
 if(best){best->state=2;*out=best->r;}
 pthread_mutex_unlock(&b->mu);return best?0:EAGAIN;
}
int sir_rdv_drain_ack(struct sir_rdv_mailbox *b,unsigned events,unsigned side,uint64_t serial)
{
 if(!b||events>1||side>1||!serial)return EINVAL;
 pthread_mutex_lock(&b->mu);struct rdv_drain_delivery *d=events?&b->drain_event[side]:&b->drain_cmd[side];
 int rc=d->r.serial!=serial?ESTALE:d->state!=2?EINVAL:0;
 if(!rc)d->state=3;
 unlock_wake(b,events&&!rc,!events&&!rc);return rc;
}
