/* SPDX-License-Identifier: GPL-2.0 */
/* Native notification receives follow the original RQ, including ordinary
 * SEND. Metadata owns no application DMA authority beyond that RQ capture. */
static struct rdv_native_credit *rdv_credit_find(struct npr_rdv_epoch *e,uint64_t token)
{for(struct rdv_native_credit *c=e->credits;c;c=c->next)if(c->rq_token==token)return c;return NULL;}
static void rdv_credit_ready(struct npr_rdv_epoch *e,struct rdv_native_credit *c)
{
 c->ready_next=NULL;c->queued=1;
 if(e->ready_last)e->ready_last->ready_next=c;else e->ready_credits=c;
 e->ready_last=c;
}
static void rdv_credit_gc(struct npr_rdv_epoch *e)
{
 /* Original RQ retirement is FIFO. Only the completed retired prefix can
  * disappear; never scan the many native receives still waiting on hardware. */
 while(e->credits&&e->credits->done&&e->credits->rq_done&&!e->credits->queued){
  struct rdv_native_credit *c=e->credits;e->credits=c->next;
  if(e->credit_last==c)e->credit_last=NULL;
  free(c);
 }
}
static void rdv_credit_retired(struct npr_rdv_epoch *e,uint64_t token)
{struct rdv_native_credit *c=rdv_credit_find(e,token);if(c)c->rq_done=1;rdv_credit_gc(e);}
static void rdv_credit_native_done(void *opaque,const struct ibv_wc *wc,const void *bytes)
{
 struct rdv_native_credit *c=opaque;struct npr_rdv_epoch *e=c->epoch;
 assert(!c->done&&e->native_refs);c->done=1;c->wc=*wc;e->native_refs--;e->qp->native_recv_done++;
 if(wc->status==IBV_WC_SUCCESS)memcpy(c->bytes,bytes,NPR_NOTIFY_BYTES);
 rdv_credit_ready(e,c);
 rdv_app_wake();
}
static int rdv_credit_post(void *opaque,uint64_t token)
{
 struct npr_rdv_epoch *e=opaque;struct npr_rdv_qp *q=e->qp;
 if(e->closing||q->native_paused||!q->cq_ops||!q->cq_ops->notify_recv)return EBUSY;
 struct rdv_native_credit *c=calloc(1,sizeof(*c));if(!c)return ENOMEM;
 c->epoch=e;c->rq_token=token;
 int rc=q->cq_ops->notify_recv(q->ce,q->native_qp,c,rdv_credit_native_done);
 if(rc){free(c);return rc;}
 if(e->credit_last)e->credit_last->next=c;else e->credits=c;
 e->credit_last=c;e->native_refs++;q->native_recv_posted++;return 0;
}
static int rdv_credit_authorized(const struct npr_notify_message *m,
 const struct sir_rdv_identity *id)
{
 const struct sir_app_qp_endpoint *src=&id->peer,*dst=&id->local;
 struct npr_notify_endpoint source={src->key.cookie,src->key.generation,src->route.connection_epoch};
 struct npr_notify_endpoint target={dst->key.cookie,dst->key.generation,dst->route.connection_epoch};
 if(npr_notify_authorize(m,&source,&target))return ESTALE;
 return m->session_id==id->session_id&&m->source_nonce==src->bind_nonce&&m->target_nonce==dst->bind_nonce?0:ESTALE;
}
static void rdv_credit_progress_one(struct npr_rdv_epoch *e,struct rdv_native_credit *c)
{
  if(!c->done||c->processed||c->rq_done)return;
  if(e->closing){c->processed=1;return;}
  struct npr_rdv_owner *o;
  for(o=e->owners;o;o=o->next)if(o->role==SIR_RDV_SINK&&o->rq_token==c->rq_token)break;
  if(c->wc.status!=IBV_WC_SUCCESS){
   /* WRITE failure may flush the native RQ before its typed error arrives.
    * Do not turn that anonymous flush into an unrelated application error. */
   if(c->wc.status==IBV_WC_WR_FLUSH_ERR){
    if(e->ever_bound&&e->binding.state!=SIR_APP_QP_BOUND){e->qp->error_epoch=e->number;c->processed=1;return;}
    if(o&&o->value.kind!=NPR_RQ_WWI){o->rx_status=IBV_WC_WR_FLUSH_ERR;o->notify_done=1;c->processed=1;e->qp->error_epoch=e->number;}
    return;
   }
   e->qp->error_epoch=e->number;c->processed=1;return;
  }
  int rc=npr_notify_decode(c->bytes,c->wc.byte_len,&c->message);
  if(rc||c->wc.opcode!=IBV_WC_RECV||(c->wc.wc_flags&IBV_WC_WITH_IMM)){
   e->qp->error_epoch=e->number;c->processed=1;return;
  }
  c->decoded=1;struct npr_notify_message *m=&c->message;
  if(m->kind!=NPR_NOTIFY_WWI){
   /* A native notification may beat its SIR data OFFER. Keep the exact RQ
    * token until that data owner exists; do not consume a different RQ. */
   if(!o){
    const struct sir_app_qp_snapshot *b=&e->binding;
    struct sir_rdv_identity id={.session_id=b->session_id,.local=b->local,.peer=b->peer};
    if(b->state!=SIR_APP_QP_BOUND){if(e->ever_bound)e->qp->error_epoch=e->number;}
    else if(rdv_credit_authorized(m,&id))e->qp->error_epoch=e->number;
    return;
   }
   if(!o->published)return;
   if(!o->native_notify||rdv_credit_authorized(m,&o->identity)||m->message_id!=o->identity.message_id||
      m->sequence!=o->identity.rq_message_seq||m->kind!=o->value.kind||m->length!=o->value.length||
      m->imm_be!=o->value.imm_be||m->solicited!=o->value.solicited){e->qp->error_epoch=e->number;c->processed=1;return;}
   if(o->value.status){o->notify_done=1;c->processed=1;return;}
   rc=sir_rdv_command_submit(e->mailbox,o->mailbox_token,SIR_RDV_NATIVE_RECEIVED,&o->value,NULL,0);
   if(!rc||rc==EALREADY){o->notify_done=1;c->processed=1;}
   else if(rc!=EAGAIN){e->qp->error_epoch=e->number;c->processed=1;}
   return;
  }
  const struct sir_app_qp_snapshot *b=&e->binding;
  struct sir_rdv_identity id={.session_id=b->session_id,.transport_generation=b->transport_generation,
   .command_revision=b->command_revision,.local=b->local,.peer=b->peer,
   .message_id=m->message_id,.rq_message_seq=m->sequence};
  if(b->state!=SIR_APP_QP_BOUND&&!e->ever_bound)return;
  if(b->state!=SIR_APP_QP_BOUND||rdv_credit_authorized(m,&id)||!rdv_current(e,&id)){
   e->qp->error_epoch=e->number;c->processed=1;return;
  }
  if(!e->registration||!e->actor_ops.native_arrival)return;
  struct sir_rdv_value value={.id=id,.kind=NPR_RQ_WWI,.length=m->length,.imm_be=m->imm_be,.solicited=m->solicited};
  rc=e->actor_ops.native_arrival(e->registration,&value);
  if(!rc)c->processed=1;
  else if(rc!=EAGAIN){e->qp->error_epoch=e->number;c->processed=1;}
}
static void rdv_credits_progress(struct npr_rdv_epoch *e)
{
 if(!e->closing&&e->registration&&e->actor_ops.stats){
  struct crdv_stats stats;
  if(!e->actor_ops.stats(e->registration,&stats)&&stats.native_error)e->qp->error_epoch=e->number;
 }

 struct rdv_native_credit *c=e->ready_credits;e->ready_credits=e->ready_last=NULL;
 while(c){
  struct rdv_native_credit *next=c->ready_next;rdv_credit_progress_one(e,c);
  if(!c->processed&&!c->rq_done)rdv_credit_ready(e,c);else c->queued=0;
  c=next;
 }
 rdv_credit_gc(e);
}
