/* SPDX-License-Identifier: GPL-2.0 */
/* Actor-owned metadata only. Each active direction has one registry hold. */
#define CRDV_DRAIN_TIMEOUT_US 5000000ull
static void drain_hold(struct crdv_registration *r,struct crdv_drain_state *d)
{
 if(d->held)return;
 pthread_mutex_lock(&r->registry->mu);r->actor_refs++;pthread_mutex_unlock(&r->registry->mu);d->held=1;
}
static void drain_drop(struct crdv_registration *r,struct crdv_drain_state *d)
{
 if(!d->held)return;
 d->held=0;registration_put(r);
}
static uint64_t drain_deadline(struct crdv_actor *a)
{return a->now>UINT64_MAX-CRDV_DRAIN_TIMEOUT_US?UINT64_MAX:a->now+CRDV_DRAIN_TIMEOUT_US;}
static unsigned drain_wire_status(unsigned status)
{return !status?RDVP_DRAIN_COMPLETE:status==EAGAIN?RDVP_DRAIN_WAIT:status==ETIMEDOUT?RDVP_DRAIN_TIMEOUT:RDVP_DRAIN_CLOSED;}
static unsigned drain_local_status(enum rdvp_drain_status status)
{return status==RDVP_DRAIN_COMPLETE?0:status==RDVP_DRAIN_WAIT?EAGAIN:status==RDVP_DRAIN_TIMEOUT?ETIMEDOUT:ESHUTDOWN;}
static int drain_receive(struct crdv_actor *a,const struct cproto_header *h,const uint8_t *payload,uint32_t op)
{
 struct rdvp_drain wire;uint32_t actual;int rc=rdvp_drain_decode(payload,h->payload_len,&actual,&wire);
 if(rc)return -rc;
 if(!h->request_id)return EPROTO;
 struct crdv_registration *r=registration_for(a,op==CPROTO_OP_RDV_DRAIN_REQUEST?&wire.receiver:&wire.sender);
 if(!r)return ESTALE;
 struct crdv_drain_state *d=&r->drain[op==CPROTO_OP_RDV_DRAIN_REQUEST?SIR_RDV_DRAIN_PEER:SIR_RDV_DRAIN_LOCAL];
 if(op==CPROTO_OP_RDV_DRAIN_ACK){
  if(!d->active||h->request_id!=d->request.nonce||h->session_id!=d->request.id.session_id||
     !endpoint_equal(&wire.sender,&d->request.id.local)||!endpoint_equal(&wire.receiver,&d->request.id.peer))rc=ESTALE;
  else if(d->remote_done&&d->request.status!=drain_local_status(wire.status))rc=EPROTO;
  else {d->remote_done=1;d->request_pending=0;d->next_due=0;d->request.status=drain_local_status(wire.status);rc=0;}
  registration_put(r);return rc;
 }
 struct sir_app_qp_snapshot b={0};rc=current(a,r,&b);
 if(!rc&&(b.session_id!=h->session_id||!endpoint_equal(&wire.receiver,&b.local)||!endpoint_equal(&wire.sender,&b.peer)))rc=ESTALE;
 if(rc){registration_put(r);return rc;}
 if(d->request.nonce&&h->request_id<=d->request.nonce){
  rc=h->request_id==d->request.nonce?0:ESTALE;
  if(!rc&&!d->active){drain_hold(r,d);d->ack_pending=1;}
  registration_put(r);return rc;
 }
 if(d->active){registration_put(r);return EAGAIN;}
 struct sir_rdv_drain_record request={.nonce=h->request_id,.kind=SIR_RDV_DRAIN_BEGIN,.side=SIR_RDV_DRAIN_PEER,
  .id={.session_id=b.session_id,.transport_generation=b.transport_generation,.command_revision=b.command_revision,.local=b.local,.peer=b.peer}};
 rc=sir_rdv_drain_publish(r->config.mailbox,1,&request);
 if(!rc||rc==EALREADY){
  drain_hold(r,d);unsigned held=d->held;
  *d=(struct crdv_drain_state){.request=request,.active=1,.held=held,.deadline=drain_deadline(a)};rc=0;
 }
 registration_put(r);return rc;
}
static void drain_commands(struct crdv_actor *a,struct crdv_registration *r)
{
 uint64_t frontier=sir_rdv_command_frontier(r->config.mailbox);struct sir_rdv_drain_record command;
 while(!sir_rdv_drain_take(r->config.mailbox,0,frontier,&command)){
  struct crdv_drain_state *d=&r->drain[command.side];
  if(command.kind==SIR_RDV_DRAIN_BEGIN&&command.side==SIR_RDV_DRAIN_LOCAL){
   if(!d->active||d->request.nonce!=command.nonce){
    drain_hold(r,d);unsigned held=d->held;
    *d=(struct crdv_drain_state){.request=command,.active=1,.held=held,.have_frontier=1,
      .deadline=drain_deadline(a),.request_pending=!command.status,.status=command.status};
    if(command.status){d->head_done=d->remote_done=1;}
   }
  }else if(command.nonce==d->request.nonce&&d->active&&
           command.id.session_id==d->request.id.session_id&&
           command.id.transport_generation==d->request.id.transport_generation&&
           command.id.command_revision==d->request.id.command_revision&&
           command.id.message_id==d->request.id.message_id&&command.id.rq_message_seq==d->request.id.rq_message_seq&&
           endpoint_equal(&command.id.local,&d->request.id.local)&&endpoint_equal(&command.id.peer,&d->request.id.peer)){
   if(command.kind==SIR_RDV_DRAIN_CANCEL){d->status=command.status?command.status:ECANCELED;d->head_done=d->remote_done=1;d->request_pending=0;if(command.side==SIR_RDV_DRAIN_PEER)d->ack_pending=1;}
   else if(command.kind==SIR_RDV_DRAIN_HEAD){
    if(d->have_frontier&&d->request.frontier!=command.frontier){d->status=EPROTO;d->head_done=d->remote_done=1;}
    else {
     d->have_frontier=1;d->request.frontier=command.frontier;
     if(!d->head_seen||d->request.head!=command.head){d->request.head=command.head;d->head_seen=0;d->head_done=0;}
     if(command.status){d->status=command.status;d->head_done=d->remote_done=1;}
    }
   }
  }
  (void)sir_rdv_drain_ack(r->config.mailbox,0,command.side,command.serial);
 }
}
static int drain_publish_done(struct crdv_registration *r,struct crdv_drain_state *d)
{
 struct sir_rdv_drain_record done=d->request;done.kind=SIR_RDV_DRAIN_DONE;done.status=d->status;
 int rc=sir_rdv_drain_publish(r->config.mailbox,1,&done);
 if(!rc||rc==EALREADY){d->active=d->request_pending=d->ack_pending=d->end_pending=0;drain_drop(r,d);return 0;}
 return rc;
}
static void drain_registration_progress(struct crdv_actor *a,struct crdv_registration *r)
{
 for(unsigned side=0;side<2;side++){
  struct crdv_drain_state *d=&r->drain[side];
  if(!d->active){if(!d->request_pending&&!d->ack_pending&&!d->end_pending)drain_drop(r,d);continue;}
  if(a->down||__atomic_load_n(&r->closed,__ATOMIC_ACQUIRE)){
   d->status=ESHUTDOWN;d->head_done=d->remote_done=1;d->request_pending=d->ack_pending=0;d->next_due=0;d->end_pending=1;
   (void)drain_publish_done(r,d);continue;
  }
  if(a->now>=d->deadline){d->status=ETIMEDOUT;d->head_done=d->remote_done=1;d->request_pending=0;d->next_due=0;}
  /* Native SEND acceptance does not prove receiver metadata admission.
   * RETRY drops/reposts that RX frame; replay only the same control nonce,
   * on the existing retransmit deadline, until ACK or the overall bound. */
  if(side==SIR_RDV_DRAIN_LOCAL&&!d->remote_done&&!d->request_pending&&d->next_due&&a->now>=d->next_due){
   d->next_due=0;d->request_pending=1;
  }
  if(d->have_frontier&&!d->head_done){
   if(!d->request.head)d->head_done=1;
   else {
    struct crdv_message *m;
    for(m=a->messages;m;m=m->next)if(m->registration==r&&m->role==SIR_RDV_SOURCE&&m->wire.sequence==d->request.head)break;
    if(m){
     if(!d->head_seen){d->baseline=m->challenge;d->head_seen=1;}
     if(m->challenge>d->baseline){d->head_done=1;if(!d->status)d->status=EAGAIN;}
    }
   }
  }
  if(side==SIR_RDV_DRAIN_LOCAL&&d->head_done&&d->remote_done){
   if(d->request.status&&(!d->status||d->status==EAGAIN))d->status=d->request.status;
   (void)drain_publish_done(r,d);
  }else if(side==SIR_RDV_DRAIN_PEER&&d->head_done){
   if(d->end_pending)(void)drain_publish_done(r,d);else d->ack_pending=1;
  }
 }
}
static int drain_frame(struct crdv_actor *a,struct crdv_frame *out,uint8_t *payload)
{
 for(struct crdv_registration *r=registration_first(a->registry);r;r=registration_next(r)){
  if(__atomic_load_n(&r->closed,__ATOMIC_ACQUIRE))continue;
  for(unsigned side=0;side<2;side++){
   struct crdv_drain_state *d=&r->drain[side];
   unsigned op=side==SIR_RDV_DRAIN_LOCAL&&d->request_pending?CPROTO_OP_RDV_DRAIN_REQUEST:
               side==SIR_RDV_DRAIN_PEER&&d->ack_pending?CPROTO_OP_RDV_DRAIN_ACK:0;
   if(!op)continue;
   struct rdvp_drain wire={.sender=side==SIR_RDV_DRAIN_LOCAL?d->request.id.local:d->request.id.peer,
     .receiver=side==SIR_RDV_DRAIN_LOCAL?d->request.id.peer:d->request.id.local,
     .status=op==CPROTO_OP_RDV_DRAIN_REQUEST?RDVP_DRAIN_COMPLETE:(enum rdvp_drain_status)drain_wire_status(d->status)};
   int n=rdvp_drain_encode(payload,CONTROL_PAYLOAD_MAX,op,&wire);
   int rc=frame_finish(a,out,n,d->request.id.session_id,d->request.nonce,op,NULL,r);
   registration_put(r);return rc;
  }
 }
 return EAGAIN;
}
static int drain_tx_result(struct crdv_actor *a,struct crdv_registration *r,unsigned op,int result)
{
 if(!r)return EPROTO;
 if(result){
  if(error_value(result)!=EAGAIN)crdv_session_down(a,0);
  registration_put(r);return error_value(result);
 }
 struct cproto_header h;int rc=cproto_header_decode(a->inflight.bytes,(uint32_t)a->inflight.length,&h);
 if(rc){registration_put(r);return error_value(rc);}
 struct crdv_drain_state *d=&r->drain[op==CPROTO_OP_RDV_DRAIN_REQUEST?SIR_RDV_DRAIN_LOCAL:SIR_RDV_DRAIN_PEER];
 if(d->request.nonce==h.request_id){
  if(op==CPROTO_OP_RDV_DRAIN_REQUEST){
   d->request_pending=0;
   d->next_due=d->active&&!d->remote_done?
    (a->now>UINT64_MAX-CRDV_RETRANSMIT_US?UINT64_MAX:a->now+CRDV_RETRANSMIT_US):0;
  }
  else {d->ack_pending=0;if(d->active)d->end_pending=1;}
 }
 drain_registration_progress(a,r);registration_put(r);return 0;
}
