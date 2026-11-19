/* SPDX-License-Identifier: GPL-2.0 */
#include "npr_qp_connection.h"
#include "npr_identity.h"
#include "npr_rendezvous.h"
#include "nprdma_internal.h"
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <assert.h>
struct npr_qp_connection {
 struct npr_qp_connection *next;
 struct npr_ctx_entry *ce;
 struct ibv_pd *pd;
 struct ibv_context *context;
 struct ibv_qp *qp;
 struct npr_qp_identity_reservation *identity;
 struct npr_qp_state *state;
 struct npr_sq_depth *depth;
 struct npr_ex_rec *ex;
 struct sir_app_qp_mailbox *mailbox;
 struct npr_rdv_qp *rendezvous;
 struct npr_rdv_epoch *reset_epoch;
 struct ibv_qp_cap visible_cap,provider_cap;
 struct sir_app_qp_key key;
 struct sir_app_qp_route route;
 enum sir_app_qp_policy policy;
 enum ibv_qp_state native_state;
 uint8_t retry_cnt,rnr_retry,timeout,min_rnr_timer;
 unsigned retry_mask;
 struct ibv_ah_attr av;
 uint64_t revision;
 unsigned have_av:1, have_dest:1, have_port:1, published:1, destroying:1;
 int bind_error;
};
static struct npr_qp_connection *connections;
struct npr_qp_connection *npr_qp_connection_prepare(struct npr_ctx_entry *ce,struct ibv_pd *pd,unsigned depth,int sig_all)
{
 struct npr_qp_connection *c=calloc(1,sizeof(*c));
 if(!c)return NULL;
 c->ce=ce;c->pd=pd;c->context=ce->ctx;
 c->identity=npr_identity_qp_reserve();if(!c->identity)goto fail;
 c->key.cookie=c->key.generation=npr_identity_qp_reserved_generation(c->identity);
 c->policy=sir_app_qp_peer_configured()?SIR_APP_QP_RENDEZVOUS_REQUIRED:SIR_APP_QP_NATIVE_ONLY;
 c->rendezvous=npr_rdv_prepare(ce,ce->ctx,pd,&c->key,c->policy);if(!c->rendezvous)goto fail;
 c->mailbox=sir_app_qp_mailbox_new(&c->key,c->policy);if(!c->mailbox)goto fail;
 c->state=npr_qp_state_reserve(depth,sig_all);if(!c->state)goto fail;
 c->depth=calloc(1,sizeof(*c->depth));if(!c->depth)goto fail;
 c->depth->app_depth=depth;c->depth->sq_sig_all=!!sig_all;
 c->ex=npr_ex_reserve();if(!c->ex)goto fail;
 c->route.connection_epoch=1;c->native_state=IBV_QPS_RESET;
 return c;
fail:;
 int saved=errno?errno:ENOMEM;npr_qp_connection_abort(c);errno=saved;return NULL;
}
void npr_qp_connection_abort(struct npr_qp_connection *c)
{
 if(!c)return;
 assert(!c->qp);
 if(c->mailbox){sir_app_qp_mailbox_close(c->mailbox);sir_app_qp_mailbox_put(c->mailbox);}
 npr_rdv_abort(c->rendezvous);
 npr_identity_qp_abort(c->identity);npr_qp_state_abort(c->state);free(c->depth);npr_ex_abort(c->ex);free(c);
}
void npr_qp_connection_caps(struct npr_qp_connection *c,const struct ibv_qp_cap *visible,const struct ibv_qp_cap *provider)
{assert(c&&!c->qp&&visible&&provider);c->visible_cap=*visible;c->provider_cap=*provider;}
struct npr_rdv_qp *npr_qp_connection_rendezvous(struct npr_qp_connection *c)
{return c?c->rendezvous:NULL;}
int npr_qp_connection_modify_prepare(struct npr_qp_connection *c,const struct ibv_qp_attr *a,int mask)
{
 if(!c||!a)return 0;
 int reset=(mask&IBV_QP_STATE)&&a->qp_state==IBV_QPS_RESET;
 int error=(mask&IBV_QP_STATE)&&a->qp_state==IBV_QPS_ERR;
 int path=!error&&(mask&(IBV_QP_AV|IBV_QP_DEST_QPN|IBV_QP_PORT))&&c->have_av&&c->have_dest&&c->have_port;
 if(!reset&&!path)return 0;
 if(c->reset_epoch)return EBUSY;
 c->reset_epoch=npr_rdv_reset_prepare(c->rendezvous,c->route.connection_epoch+1);
 return c->reset_epoch?0:(errno?errno:ENOMEM);
}
void npr_qp_connection_modify_abort(struct npr_qp_connection *c)
{if(c){npr_rdv_reset_abort(c->reset_epoch);c->reset_epoch=NULL;}}
void npr_qp_connection_commit(struct npr_qp_connection *c,struct ibv_qp *qp)
{
 c->qp=qp;c->route.local_qpn=qp->qp_num;
 npr_rdv_commit(c->rendezvous,qp,&c->visible_cap,&c->provider_cap);
 npr_rdv_cq_ops(c->rendezvous,&npr_rdv_gate_ops);
 npr_rdv_backend(c->rendezvous,npr_rdv_backend_snapshot);
 npr_identity_qp_commit(c->identity,qp);c->identity=NULL;
 npr_qp_state_commit(c->ce,c->state,qp);c->state=NULL;
 c->depth->qp=qp;c->depth->next=c->ce->depths;c->ce->depths=c->depth;
 npr_ex_install_reserved(c->ce,qp,c->ex);c->ex=NULL;
 c->next=connections;connections=c;
}
struct npr_qp_connection *npr_qp_connection_find(struct ibv_qp *qp)
{struct npr_qp_connection *c;for(c=connections;c;c=c->next)if(c->qp==qp)return c;return NULL;}
int npr_qp_connection_modify_check(struct npr_qp_connection *c)
{ return c&&(c->revision>UINT64_MAX-3||c->route.connection_epoch==UINT64_MAX)?EOVERFLOW:0; }
static void withdraw(struct npr_qp_connection *c,enum sir_app_qp_withdraw_reason reason)
{
 c->published=0;
 c->bind_error=sir_app_qp_withdraw(c->mailbox,++c->revision,reason);
}
static void publish(struct npr_qp_connection *c)
{
 struct ibv_port_attr port;
 union ibv_gid gid;
 if(c->policy==SIR_APP_QP_NATIVE_ONLY)return;
 if(c->native_state!=IBV_QPS_RTR&&c->native_state!=IBV_QPS_RTS)return;
 if(!c->have_av||!c->have_dest||!c->have_port){c->bind_error=EINVAL;return;}
 if(c->av.is_global){
  if(ibv_query_gid(c->context,c->route.port_num,c->av.grh.sgid_index,&gid)){c->bind_error=errno?errno:EIO;return;}
  c->route.kind=SIR_APP_QP_ROUTE_GID;
  memcpy(c->route.local_gid,gid.raw,16);memcpy(c->route.peer_gid,c->av.grh.dgid.raw,16);
 }else{
  if(ibv_query_port(c->context,c->route.port_num,&port)){c->bind_error=errno?errno:EIO;return;}
  c->route.kind=SIR_APP_QP_ROUTE_LID;c->route.local_lid=port.lid;c->route.peer_lid=c->av.dlid;
 }
 c->bind_error=sir_app_qp_publish(c->mailbox,++c->revision,&c->route);
 c->published=!c->bind_error;
}
void npr_qp_connection_modified(struct npr_qp_connection *c,const struct ibv_qp_attr *a,int mask)
{
 if(!c||!a)return;
 int had_route=c->have_av&&c->have_dest&&c->have_port;
 int route_change=(mask&(IBV_QP_AV|IBV_QP_DEST_QPN))!=0;
 if(mask&IBV_QP_RETRY_CNT)c->retry_cnt=a->retry_cnt;
 if(mask&IBV_QP_RNR_RETRY)c->rnr_retry=a->rnr_retry;
 if(mask&IBV_QP_TIMEOUT)c->timeout=a->timeout;
 if(mask&IBV_QP_MIN_RNR_TIMER)c->min_rnr_timer=a->min_rnr_timer;
 c->retry_mask|=mask&(IBV_QP_RETRY_CNT|IBV_QP_RNR_RETRY|IBV_QP_TIMEOUT|IBV_QP_MIN_RNR_TIMER);
 if(mask&(IBV_QP_RNR_RETRY|IBV_QP_MIN_RNR_TIMER))npr_rdv_update_attrs(c->rendezvous,c->rnr_retry,c->min_rnr_timer);
 if((mask&IBV_QP_STATE)&&a->qp_state==IBV_QPS_RESET){
  assert(c->reset_epoch);
  npr_rdv_reset_commit(c->rendezvous,c->reset_epoch);c->reset_epoch=NULL;
  npr_rdv_progress();
  withdraw(c,SIR_APP_QP_LOCAL_RESET);c->route.connection_epoch++;
  c->have_av=c->have_dest=c->have_port=0;c->native_state=IBV_QPS_RESET;npr_rdv_native_state(c->rendezvous,c->native_state);
  c->retry_cnt=c->rnr_retry=c->timeout=c->min_rnr_timer=0;c->retry_mask=0;
  npr_rdv_update_attrs(c->rendezvous,0,0);
  return;
 }
 if(mask&IBV_QP_PORT){c->route.port_num=a->port_num;c->have_port=1;route_change=1;}
 if(mask&IBV_QP_AV){c->av=a->ah_attr;if(!c->have_port){c->route.port_num=a->ah_attr.port_num;c->have_port=1;}c->have_av=1;}
 if(mask&IBV_QP_DEST_QPN){c->route.peer_qpn=a->dest_qp_num;c->have_dest=1;}
 if(mask&IBV_QP_STATE){c->native_state=a->qp_state;npr_rdv_native_state(c->rendezvous,c->native_state);}
 if(c->native_state==IBV_QPS_ERR){npr_rdv_error(c->rendezvous);withdraw(c,SIR_APP_QP_LOCAL_ERROR);return;}
 if(route_change&&had_route){
  assert(c->reset_epoch);npr_rdv_reset_commit(c->rendezvous,c->reset_epoch);c->reset_epoch=NULL;
  npr_rdv_progress();
  withdraw(c,SIR_APP_QP_PATH_CHANGED);c->route.connection_epoch++;
 }
 if(!c->published)publish(c);
}
void npr_qp_connection_destroying(struct npr_qp_connection *c)
{if(c){c->destroying=1;npr_rdv_native_pause(c->rendezvous,1);}}
void npr_qp_connection_destroy_failed(struct npr_qp_connection *c)
{if(c){c->destroying=0;npr_rdv_native_pause(c->rendezvous,0);}}
void npr_qp_connection_stopped(struct npr_qp_connection *c)
{
 if(!c)return;
 /* Provider success is the close boundary. Failed destroy keeps the exact
  * previously published authorization and its accepted owners intact. */
 withdraw(c,SIR_APP_QP_DESTROY_PREPARE);
 struct npr_qp_connection **p=&connections;while(*p&&*p!=c)p=&(*p)->next;
 assert(*p==c);*p=c->next;
 struct npr_sq_depth **d=&c->ce->depths;while(*d&&*d!=c->depth)d=&(*d)->next;
 if(*d){*d=c->depth->next;free(c->depth);}
 npr_qp_connection_modify_abort(c);npr_rdv_close(c->rendezvous);
 npr_rdv_progress();
 sir_app_qp_mailbox_close(c->mailbox);sir_app_qp_mailbox_put(c->mailbox);free(c);
}
void npr_qp_connection_context_stopped(struct ibv_context *ctx)
{struct npr_qp_connection *c=connections,*next;for(;c;c=next){next=c->next;if(c->context==ctx)npr_qp_connection_stopped(c);}}
void npr_qp_connection_progress(void)
{
 for(struct npr_qp_connection *c=connections;c;c=c->next){
  struct sir_app_qp_snapshot s;
  if(!npr_qp_connection_snapshot(c,&s))npr_rdv_binding(c->rendezvous,&s);
 }
 npr_rdv_progress();
}
int npr_qp_connection_snapshot(struct npr_qp_connection *c,struct sir_app_qp_snapshot *out)
{
 if(!c||!out)return EINVAL;
 int rc=sir_app_qp_snapshot(c->mailbox,out);if(rc)return rc;
 if(out->local.key.cookie!=c->key.cookie||out->local.key.generation!=c->key.generation)return ESTALE;
 if(out->state==SIR_APP_QP_BOUND&&(c->destroying||!c->published||out->command_revision!=c->revision||out->local.route.connection_epoch!=c->route.connection_epoch))return ESTALE;
 return 0;
}

#ifdef NPRDMA_TEST_INJECT
#include "npr_inject.h"
#include "npr_progress.h"
int npr_test_wwi_protocol_snapshot(struct ibv_qp *qp,struct npr_test_wwi_protocol *out)
{
 if(!qp||!out)return EINVAL;
 npr_progress_lock();struct npr_qp_connection *c=npr_qp_connection_find(qp);
 int rc=c?npr_rdv_test_protocol(c->rendezvous,out):ENOENT;npr_progress_unlock();return rc;
}
int npr_test_rdv_qp_snapshot(struct ibv_qp *qp,struct npr_test_rdv_qp *out)
{
 if(!qp||!out)return EINVAL;
 npr_progress_lock();
 struct npr_qp_connection *c=npr_qp_connection_find(qp);
 if(!c){npr_progress_unlock();return ENOENT;}
 struct sir_app_qp_snapshot binding;
 if(!npr_qp_connection_snapshot(c,&binding))npr_rdv_binding(c->rendezvous,&binding);
 int rc=npr_rdv_test_snapshot(c->rendezvous,out);
 npr_progress_unlock();return rc;
}
int npr_test_qp_binding_snapshot(struct ibv_qp *qp,struct npr_test_qp_binding *out)
{
 if(!qp||!out)return EINVAL;
 npr_progress_lock();
 struct npr_qp_connection *c=npr_qp_connection_find(qp);
 if(!c){npr_progress_unlock();return ENOENT;}
 memset(out,0,sizeof(*out));
 out->cookie=c->key.cookie;out->generation=c->key.generation;
 out->connection_epoch=c->route.connection_epoch;out->command_revision=c->revision;
 out->policy=c->policy;out->native_state=c->native_state;out->local_error=c->bind_error;
 int rc=npr_qp_connection_snapshot(c,&out->binding);
 npr_progress_unlock();return rc;
}
#endif

int npr_qp_connection_pd_live(const struct ibv_pd *pd)
{for(struct npr_qp_connection *c=connections;c;c=c->next)if(c->qp&&c->qp->pd==pd)return 1;return 0;}

int npr_qp_connection_cq_live(const struct ibv_cq *cq)
{
 for(struct npr_qp_connection *c=connections;c;c=c->next)
  if(c->qp&&(c->qp->send_cq==cq||c->qp->recv_cq==cq))return 1;
 return 0;
}
