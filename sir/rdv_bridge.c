/* SPDX-License-Identifier: GPL-2.0 */
#include "rdv_bridge.h"
#include "control_executor.h"
#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
struct bridge_read {uint64_t local,remote,token;uint32_t lkey,rkey,length;unsigned state;};
struct bridge_span {struct sir_rdv_span value;struct ibv_mr *mr;unsigned pinned;};
struct rdv_bridge_epoch {
 struct rdv_bridge_epoch *next;struct cexec *exec;struct ctrans_epoch *epoch;
 struct ctrans_cleanup cleanup;unsigned cleanup_done;
};
struct rdv_bridge_owner {
 struct rdv_bridge_owner *next;struct rdv_bridge_epoch *group;struct cexec *exec;
 struct ctrans_epoch *epoch;struct bridge_span *spans;unsigned nspan;
 struct rdv_bridge_config config;
 struct ctrans_rev_pool *reverse;struct bridge_read *reads;
 uint64_t read_posted,read_wc;
 uint64_t resource_token;unsigned nread,read_next,native_refs,read_prepared,read_cancel,read_finished;
 enum ibv_wc_status read_status;
 uint64_t job_id;unsigned job_span,job_op,job_imported;
 unsigned started,ready,release,exposed,proof,released,committed;
 int error;
 struct sir_rdv_record receipt;
};
static uint64_t next_resource_token=1;
static uint64_t resource_token_new(void)
{uint64_t n=__atomic_load_n(&next_resource_token,__ATOMIC_RELAXED);for(;;){if(n==UINT64_MAX)return 0;if(__atomic_compare_exchange_n(&next_resource_token,&n,n+1,0,__ATOMIC_RELAXED,__ATOMIC_RELAXED))return n;}}
static int identity_equal(const struct sir_rdv_identity *a,const struct sir_rdv_identity *b)
{
 /* Same local producer values, including local port indices, never comparing
  * one host's transport generation/port against the other host's counter. */
 const struct sir_app_qp_endpoint *x[2]={&a->local,&a->peer},*y[2]={&b->local,&b->peer};
 if(a->session_id!=b->session_id||a->transport_generation!=b->transport_generation||a->command_revision!=b->command_revision||a->message_id!=b->message_id||a->rq_message_seq!=b->rq_message_seq)return 0;
 for(unsigned i=0;i<2;i++)if(x[i]->key.cookie!=y[i]->key.cookie||x[i]->key.generation!=y[i]->key.generation||x[i]->route.connection_epoch!=y[i]->route.connection_epoch||x[i]->route.local_qpn!=y[i]->route.local_qpn||x[i]->route.peer_qpn!=y[i]->route.peer_qpn||x[i]->route.local_lid!=y[i]->route.local_lid||x[i]->route.peer_lid!=y[i]->route.peer_lid||x[i]->route.port_num!=y[i]->route.port_num||x[i]->route.kind!=y[i]->route.kind||x[i]->bind_nonce!=y[i]->bind_nonce||x[i]->policy!=y[i]->policy||memcmp(x[i]->route.local_gid,y[i]->route.local_gid,16)||memcmp(x[i]->route.peer_gid,y[i]->route.peer_gid,16))return 0;
 return 1;
}
static int stopped(struct rdv_bridge_owner *o)
{struct ctrans_epoch_info info={0};return !ctrans_epoch_snapshot(o->epoch,&info)&&info.qp_stopped;}
static unsigned resources(struct rdv_bridge_owner *o)
{unsigned n=(unsigned)!!o->job_id+o->native_refs;for(unsigned i=0;i<o->nspan;i++)n+=!!o->spans[i].mr+o->spans[i].pinned;return n;}
static int aggregate_cleanup(void *opaque)
{
 struct rdv_bridge_epoch *g=opaque;unsigned pending=0;
 for(struct rdv_bridge_owner *o=g->exec->rdv_owners;o;o=o->next)if(o->group==g&&o->release&&!o->released){(void)rdv_bridge_progress(o);pending+=!o->released;}
 if(!pending)g->cleanup_done=1;
 unsigned owners=0;for(struct rdv_bridge_owner *o=g->exec->rdv_owners;o;o=o->next)owners+=o->group==g;
 if(!owners){struct rdv_bridge_epoch **p=&g->exec->rdv_epochs;while(*p&&*p!=g)p=&(*p)->next;assert(*p==g);*p=g->next;ctrans_epoch_release(g->epoch);free(g);return 0;}
 return pending?-EBUSY:0;
}
static void defer_cleanup(struct rdv_bridge_owner *o)
{
 struct rdv_bridge_epoch *g=o->group;
 if(g->cleanup_done){memset(&g->cleanup,0,sizeof(g->cleanup));g->cleanup_done=0;}
 if(!g->cleanup.queued&&!g->cleanup.active)(void)ctrans_epoch_defer_cleanup(g->epoch,&g->cleanup,aggregate_cleanup,g);
}
int rdv_bridge_prepare(struct ctrans_provider *pv,struct cexec *ex,const struct rdv_bridge_config *c,struct rdv_bridge_owner **out)
{
 if(!out)return EINVAL;
 *out=NULL;
 if(!pv||!ex||!c||(c->role!=RDV_BRIDGE_SOURCE&&c->role!=RDV_BRIDGE_SINK)||(!c->spans&&c->span_count)||!c->message.id.message_id)return EINVAL;
 uint64_t covered=0;
 for(unsigned i=0;i<c->span_count;i++){if(c->spans[i].message_offset!=covered||c->spans[i].length>UINT64_MAX-covered)return EINVAL;covered+=c->spans[i].length;}
 if(c->span_count&&covered!=c->message.length)return EINVAL;
 for(unsigned i=0;i<c->span_count;i++)if(!sir_rdv_backend_valid(&c->spans[i].backend)||!c->spans[i].length||c->spans[i].length>SIZE_MAX||c->spans[i].length>UINT64_MAX-c->spans[i].cpu_address)return EINVAL;
 struct rdv_bridge_owner *o=calloc(1,sizeof(*o));if(!o)return ENOMEM;
 o->resource_token=resource_token_new();if(!o->resource_token){free(o);return EOVERFLOW;}
 if(c->span_count){o->spans=calloc(c->span_count,sizeof(*o->spans));if(!o->spans){free(o);return ENOMEM;}}
 int rc=ctrans_epoch_acquire(pv,&o->epoch);if(rc)goto fail;
 struct ctrans_epoch_info info={0};ctrans_epoch_snapshot(o->epoch,&info);
 if(info.session_id!=c->message.id.session_id||info.generation!=c->message.id.transport_generation){rc=-ESTALE;goto fail;}
 struct rdv_bridge_epoch *g;for(g=ex->rdv_epochs;g&&g->epoch!=o->epoch;g=g->next){}
 if(!g){
  g=calloc(1,sizeof(*g));if(!g){rc=-ENOMEM;goto fail;}
  rc=ctrans_epoch_acquire(pv,&g->epoch);if(rc){free(g);goto fail;}
  g->exec=ex;g->next=ex->rdv_epochs;ex->rdv_epochs=g;
 }
 o->exec=ex;o->group=g;o->config=*c;o->config.spans=NULL;o->nspan=c->span_count;
 for(unsigned i=0;i<o->nspan;i++)o->spans[i].value=c->spans[i];
 o->next=ex->rdv_owners;ex->rdv_owners=o;*out=o;return 0;
fail:if(o->epoch)ctrans_epoch_release(o->epoch);free(o->spans);free(o);return rc<0?-rc:rc;
}
static int schedule_memory(struct rdv_bridge_owner *o,unsigned i,unsigned operation)
{
 if(!o->exec->nthreads||!__atomic_load_n(&o->exec->run,__ATOMIC_ACQUIRE))return EBUSY;
 int rc=operation==CEXEC_MEMORY_PIN?ctrans_epoch_job_begin(o->epoch):ctrans_epoch_cleanup_begin(o->epoch);
 if(rc)return -rc;
 uint64_t id=0;struct sir_rdv_span *s=&o->spans[i].value;
 rc=cexec_job_admit(o->exec,CEXEC_JOB_RDV_MEMORY,0,0,s->cpu_address,s->length,&id);
 if(rc){ctrans_epoch_job_end(o->epoch);return -rc;}
 struct cexec_cmd cmd={.kind=CEXEC_JOB_RDV_MEMORY,.memory=*s,.memory_operation=operation,.session_id=o->config.message.id.session_id,.request_id=o->config.slot_token};
 rc=cexec_job_set_cmd(o->exec,id,&cmd);
 if(rc){cexec_job_claim(o->exec,id);cexec_job_finish(o->exec,id,ECANCELED,0);cexec_job_release(o->exec,id);ctrans_epoch_job_end(o->epoch);return -rc;}
 o->job_id=id;o->job_span=i;o->job_op=operation;o->job_imported=0;
 rc=cexec_schedule(o->exec);return rc?-rc:0;
}
static void import_result(struct rdv_bridge_owner *o,const struct cexec_result *r)
{
 if(o->job_imported)return;
 if(r->memory_succeeded){
  if(o->job_op==CEXEC_MEMORY_PIN)o->spans[o->job_span].pinned=1;
  else o->spans[o->job_span].pinned=0; /* raw ioctl success is final */
 }
 if(r->status&&o->job_op==CEXEC_MEMORY_PIN&&!o->error)o->error=r->status;
 if(r->status&&o->job_op==CEXEC_MEMORY_PIN)o->release=1;
 o->job_imported=1;ctrans_epoch_job_end(o->epoch);
}
int rdv_bridge_on_exec(struct cexec *ex,uint64_t id)
{
 struct rdv_bridge_owner *o;for(o=ex->rdv_owners;o&&o->job_id!=id;o=o->next){}
 if(!o)return -EPROTO;
 struct cexec_result r;int rc=cexec_result(ex,id,&r);if(rc)return rc;
 import_result(o,&r);rc=cexec_job_release(ex,id);if(rc)return rc;
 o->job_id=0;o->job_imported=0;
 (void)rdv_bridge_progress(o);return 0;
}
int rdv_bridge_start(struct rdv_bridge_owner *o)
{if(!o)return EINVAL;if(o->started)return EALREADY;o->started=1;return rdv_bridge_progress(o);}
int rdv_bridge_mark_exposed(struct rdv_bridge_owner *o)
{if(!o||o->config.role!=RDV_BRIDGE_SOURCE||!o->ready||o->release)return EINVAL;o->exposed=1;return 0;}
int rdv_bridge_release_allowed(struct rdv_bridge_owner *o,enum rdv_bridge_release_proof proof,const struct sir_rdv_identity *id)
{
 if(!o||proof<RDV_BRIDGE_NOT_EXPOSED||proof>RDV_BRIDGE_OLD_TRANSPORT_STOPPED)return EINVAL;
 if(proof==RDV_BRIDGE_NOT_EXPOSED&&o->exposed)return EBUSY;
 if(proof==RDV_BRIDGE_PEER_FINAL_ACK&&(!id||!identity_equal(&o->config.message.id,id)))return ESTALE;
 if(proof==RDV_BRIDGE_OLD_TRANSPORT_STOPPED&&!stopped(o))return EBUSY;
 if(o->read_prepared&&!o->read_finished&&!o->read_cancel)return EBUSY;
 o->proof=proof;o->started=1;o->release=1;return rdv_bridge_progress(o);
}
void rdv_bridge_cancel(struct rdv_bridge_owner *o)
{if(o){if(o->read_prepared&&!o->read_finished){o->read_cancel=1;if(o->read_status==IBV_WC_SUCCESS)o->read_status=IBV_WC_WR_FLUSH_ERR;}o->started=1;o->release=1;if(!o->exposed)o->proof=RDV_BRIDGE_NOT_EXPOSED;(void)rdv_bridge_progress(o);}}
int rdv_bridge_progress(struct rdv_bridge_owner *o)
{
 if(!o||!o->started)return EINVAL;
 if(o->released)return 0;
 if(o->job_id)return EAGAIN;
 if(!o->release&&ctrans_epoch_job_valid(o->epoch)){
  /* No active job can also mean READY. Snapshot distinguishes that state. */
  struct ctrans_epoch_info info={0};ctrans_epoch_snapshot(o->epoch,&info);
  if(info.closing||!info.ready){o->release=1;if(o->read_prepared&&!o->read_finished){o->read_cancel=1;if(o->read_status==IBV_WC_SUCCESS)o->read_status=IBV_WC_WR_FLUSH_ERR;}if(!o->error)o->error=ECANCELED;}
 }
 if(o->release){
  if(o->native_refs){defer_cleanup(o);return EBUSY;}
  /* Preparation can fail without a caller-issued cancel/proof. An unexposed
   * owner never granted peer DMA, so its fully cleaned receipt is NO_DATA. */
  if(!o->exposed&&!o->proof)o->proof=RDV_BRIDGE_NOT_EXPOSED;
  if(o->exposed&&!o->proof){if(stopped(o))o->proof=RDV_BRIDGE_OLD_TRANSPORT_STOPPED;else{defer_cleanup(o);return EBUSY;}}
  for(unsigned i=0;i<o->nspan;i++){
   struct bridge_span *s=&o->spans[i];
   if(s->mr){int rc=ctrans_epoch_cleanup_begin(o->epoch);if(rc){defer_cleanup(o);return -rc;}rc=ctrans_epoch_dereg_bridge(o->epoch,s->mr);ctrans_epoch_job_end(o->epoch);if(rc){defer_cleanup(o);return -rc;}s->mr=NULL;}
   if(s->pinned){
    if(!o->exec->nthreads&&!__atomic_load_n(&o->exec->run,__ATOMIC_ACQUIRE)){
     int rc=cexec_memory_ioctl(&s->value,CEXEC_MEMORY_UNPIN);if(rc){defer_cleanup(o);return rc;}s->pinned=0;
    }else{int rc=schedule_memory(o,i,CEXEC_MEMORY_UNPIN);defer_cleanup(o);return rc?rc:EAGAIN;}
   }
  }
  o->released=1;o->ready=0;
  o->receipt=(struct sir_rdv_record){.token=o->config.slot_token,.app_token=o->config.app_token,.kind=o->config.role==RDV_BRIDGE_SOURCE?SIR_RDV_SOURCE_RELEASED:SIR_RDV_SINK_RELEASED,.evidence=o->proof==RDV_BRIDGE_OLD_TRANSPORT_STOPPED?SIR_RDV_STOPPED_CLEANED:(o->config.role==RDV_BRIDGE_SOURCE&&o->proof==RDV_BRIDGE_NOT_EXPOSED)?SIR_RDV_NO_DATA:o->nspan?SIR_RDV_DATA_CLEANED:SIR_RDV_NO_DATA,.value=o->config.message};
  if(o->error)o->receipt.value.status=(unsigned)o->error;
  return 0;
 }
 for(unsigned i=0;i<o->nspan;i++){
  struct bridge_span *s=&o->spans[i];
  if(s->value.backend.kind==SIR_RDV_SYM_PIN&&!s->pinned){int rc=schedule_memory(o,i,CEXEC_MEMORY_PIN);return rc?rc:EAGAIN;}
  if(!s->mr){
   int rc=ctrans_epoch_job_begin(o->epoch);if(rc){o->release=1;o->error=-rc;defer_cleanup(o);return -rc;}
   rc=ctrans_epoch_reg_bridge(o->epoch,(void*)(uintptr_t)s->value.cpu_address,(size_t)s->value.length,o->config.role==RDV_BRIDGE_SOURCE?IBV_ACCESS_REMOTE_READ:IBV_ACCESS_LOCAL_WRITE,&s->mr);
   int valid=ctrans_epoch_job_valid(o->epoch);ctrans_epoch_job_end(o->epoch);
   if(rc||valid){o->release=1;o->error=rc?-rc:ECANCELED;defer_cleanup(o);return o->error;}
  }
 }
 o->ready=1;return 0;
}
int rdv_bridge_views(struct rdv_bridge_owner *o,struct rdv_bridge_view *out,unsigned cap,unsigned *count)
{
 if(!o||!count)return EINVAL;
 *count=o->nspan;if(!o->ready||o->release)return EBUSY;
 if(cap<o->nspan||(!out&&o->nspan))return ENOSPC;
 for(unsigned i=0;i<o->nspan;i++)out[i]=(struct rdv_bridge_view){.address=(uint64_t)(uintptr_t)o->spans[i].mr->addr,.length=o->spans[i].value.length,.message_offset=o->spans[i].value.message_offset,.lkey=o->spans[i].mr->lkey,.rkey=o->spans[i].mr->rkey};
 return 0;
}
int rdv_bridge_take_released(struct rdv_bridge_owner *o,struct sir_rdv_record *out)
{if(!o||!out)return EINVAL;if(!o->released)return EAGAIN;*out=o->receipt;return 0;}
int rdv_bridge_released_committed(struct rdv_bridge_owner *o)
{if(!o||!o->released)return EBUSY;if(o->committed)return EALREADY;o->committed=1;return 0;}
int rdv_bridge_free(struct rdv_bridge_owner *o)
{
 if(!o)return EINVAL;
 if(!o->committed||resources(o))return EBUSY;
 struct cexec *ex=o->exec;struct rdv_bridge_owner **p=&ex->rdv_owners;while(*p&&*p!=o)p=&(*p)->next;assert(*p==o);*p=o->next;
 struct rdv_bridge_epoch *g=o->group;ctrans_epoch_release(o->epoch);free(o->reads);free(o->spans);free(o);
 unsigned used=0;for(o=ex->rdv_owners;o;o=o->next)used+=o->group==g;
 if(!used&&(!g->cleanup.queued&&(!g->cleanup.active||g->cleanup_done))){struct rdv_bridge_epoch **q=&ex->rdv_epochs;while(*q&&*q!=g)q=&(*q)->next;assert(*q==g);*q=g->next;ctrans_epoch_release(g->epoch);free(g);}
 return 0;
}
void rdv_bridge_get_counts(struct rdv_bridge_owner *o,struct rdv_bridge_counts *c)
{memset(c,0,sizeof(*c));if(!o)return;c->pending_jobs=!!o->job_id;c->ready=o->ready;c->released=o->released;c->exposed=o->exposed;c->native_refs=o->native_refs;c->error=o->error;c->read_posted=o->read_posted;c->read_wc=o->read_wc;for(unsigned i=0;i<o->nspan;i++){c->pins+=o->spans[i].pinned;c->mrs+=!!o->spans[i].mr;}}
int rdv_bridge_executor_stopped(struct cexec *ex)
{
 if(ex->nthreads||__atomic_load_n(&ex->run,__ATOMIC_ACQUIRE))return -EBUSY;
 for(struct rdv_bridge_owner *o=ex->rdv_owners;o;o=o->next){
  if(o->read_prepared&&!o->read_finished){o->read_cancel=1;if(o->read_status==IBV_WC_SUCCESS)o->read_status=IBV_WC_WR_FLUSH_ERR;}
  o->started=1;o->release=1;if(!o->exposed)o->proof=RDV_BRIDGE_NOT_EXPOSED;
  if(o->job_id&&!o->job_imported){int rc=cexec_stopped_cancel(ex,o->job_id);if(rc)return rc;struct cexec_result r;rc=cexec_result(ex,o->job_id,&r);if(rc)return rc;import_result(o,&r);}
 }
 return 0;
}
int rdv_bridge_stopped_finish(struct cexec *ex)
{
 for(struct rdv_bridge_owner *o=ex->rdv_owners;o;o=o->next){
  if(o->job_id){if(!o->job_imported)return -EBUSY;int rc=cexec_job_release(ex,o->job_id);if(rc)return rc;o->job_id=0;}
  (void)rdv_bridge_progress(o);
 }
 return 0;
}
void rdv_bridge_progress_all(struct cexec *ex)
{for(struct rdv_bridge_owner *o=ex->rdv_owners;o;o=o->next)(void)rdv_bridge_progress(o);}
int rdv_bridge_busy(const struct cexec *ex)
{return ex&&(ex->rdv_owners||ex->rdv_epochs);}

static int read_prepare_failed(struct rdv_bridge_owner *o,int error)
{o->error=error;o->read_status=IBV_WC_GENERAL_ERR;o->read_cancel=1;o->read_finished=1;o->release=1;(void)rdv_bridge_progress(o);return error;}
int rdv_bridge_read_prepare(struct rdv_bridge_owner *o,struct ctrans_rev_pool *pool,const struct rdv_bridge_remote *remote,unsigned count)
{
 if(!o||!pool||o->config.role!=RDV_BRIDGE_SINK||!o->ready||o->release)return EINVAL;
 if(o->read_prepared)return EALREADY;
 if((count&&!remote)||o->config.message.length>UINT32_MAX)return read_prepare_failed(o,EINVAL);
 uint64_t total=0;
 for(unsigned i=0;i<count;i++){if(!remote[i].length||remote[i].message_offset!=total||remote[i].length>UINT64_MAX-total||remote[i].length>UINT64_MAX-remote[i].address)return read_prepare_failed(o,EINVAL);total+=remote[i].length;}
 if(total!=o->config.message.length||(!o->nspan&&total))return read_prepare_failed(o,EINVAL);
 size_t cap=(size_t)o->nspan+count;
 if(cap>SIZE_MAX/sizeof(struct bridge_read))return read_prepare_failed(o,EOVERFLOW);
 struct bridge_read *parts=cap?calloc(cap,sizeof(*parts)):NULL;
 if(cap&&!parts)return read_prepare_failed(o,ENOMEM);
 unsigned li=0,ri=0,n=0;uint64_t lo=0,ro=0,done=0;
 while(done<total){
  if(li>=o->nspan||ri>=count){free(parts);return read_prepare_failed(o,EINVAL);}
  uint64_t l=o->spans[li].value.length-lo,r=remote[ri].length-ro,bytes=l<r?l:r;
  if(!bytes||bytes>UINT32_MAX){free(parts);return read_prepare_failed(o,EINVAL);}
  parts[n++]=(struct bridge_read){.local=(uint64_t)(uintptr_t)o->spans[li].mr->addr+lo,.remote=remote[ri].address+ro,.length=(uint32_t)bytes,.lkey=o->spans[li].mr->lkey,.rkey=remote[ri].rkey};
  done+=bytes;lo+=bytes;ro+=bytes;if(lo==o->spans[li].value.length){li++;lo=0;}if(ro==remote[ri].length){ri++;ro=0;}
 }
 o->reverse=pool;o->reads=parts;o->nread=n;o->read_prepared=1;o->read_status=IBV_WC_SUCCESS;o->read_finished=!n;return 0;
}
int rdv_bridge_read_progress(struct rdv_bridge_owner *o,unsigned *accepted)
{
 if(!o||!accepted||!o->read_prepared)return EINVAL;
 *accepted=0;if(o->read_cancel||o->release)return ECANCELED;
 struct ctrans_epoch_info info;int rc=ctrans_epoch_snapshot(o->epoch,&info);if(rc)return -rc;
 while(o->read_next<o->nread){
  struct bridge_read *part=&o->reads[o->read_next];rc=ctrans_epoch_job_begin(o->epoch);
  if(rc)break;
  uint64_t token;rc=ctrans_rev_arm(o->reverse,info.generation,CTRANS_REV_RDV,o->resource_token,CONTROL_DIR_READ,&token);
  if(rc){ctrans_epoch_job_end(o->epoch);if(rc==-EBUSY)return EAGAIN;break;}
  part->token=token;
  rc=ctrans_epoch_post_read(o->epoch,o->reverse,token,part->local,part->lkey,part->remote,part->rkey,part->length);
  if(rc){(void)ctrans_rev_abort(o->reverse,token);part->token=0;ctrans_epoch_job_end(o->epoch);break;}
  part->state=1;o->read_posted++;o->native_refs++;o->read_next++;(*accepted)++;ctrans_epoch_job_end(o->epoch);
 }
 if(rc){o->read_status=IBV_WC_GENERAL_ERR;o->read_cancel=1;o->release=1;if(!o->error)o->error=-rc;(void)rdv_bridge_progress(o);return -rc;}
 return 0;
}
static int read_terminal(struct cexec *ex,const struct ctrans_rev_ticket *ticket,enum ibv_wc_status status,int actual_wc)
{
 if(!ex||!ticket||ticket->domain!=CTRANS_REV_RDV)return -EINVAL;
 struct rdv_bridge_owner *o;for(o=ex->rdv_owners;o&&o->resource_token!=ticket->owner_token;o=o->next){}
 if(!o)return -EPROTO;
 struct ctrans_epoch_info info;if(ctrans_epoch_snapshot(o->epoch,&info)||info.generation!=ticket->epoch_generation)return -ESTALE;
 for(unsigned i=0;i<o->nread;i++)if(o->reads[i].token==ticket->token&&o->reads[i].state==1){
  o->reads[i].state=2;if(actual_wc)o->read_wc++;assert(o->native_refs);o->native_refs--;
  if(status!=IBV_WC_SUCCESS){if(o->read_status==IBV_WC_SUCCESS)o->read_status=status;o->read_cancel=1;o->release=1;if(!o->error)o->error=EIO;}
  if(!o->native_refs&&(o->read_cancel||o->read_next==o->nread))o->read_finished=1;
  (void)rdv_bridge_progress(o);return 0;
 }
 return -ESTALE;
}
int rdv_bridge_on_read_wc(struct cexec *ex,const struct ctrans_rev_ticket *ticket,enum ibv_wc_status status)
{return read_terminal(ex,ticket,status,1);}
int rdv_bridge_on_read_stopped(struct cexec *ex,const struct ctrans_rev_ticket *ticket)
{return read_terminal(ex,ticket,IBV_WC_WR_FLUSH_ERR,0);}
int rdv_bridge_reads_done(struct rdv_bridge_owner *o,enum ibv_wc_status *status)
{
 if(!o||!status||!o->read_prepared)return EINVAL;
 if(o->native_refs||(!o->read_cancel&&o->read_next!=o->nread))return EAGAIN;
 o->read_finished=1;*status=o->read_status;return 0;
}
