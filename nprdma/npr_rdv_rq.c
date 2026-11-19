/* SPDX-License-Identifier: GPL-2.0 */
#include "npr_rdv_rq.h"
#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
enum rq_state { RQ_QUEUED,RQ_CLAIMED,RQ_TERMINAL };
struct rq_desc {
 struct rq_desc *next;
 enum rq_state state;
 struct npr_mra_capture *captures;
 struct npr_rq_span *spans;
 unsigned num_sge,cancel_requested;
 struct npr_rq_plan plan;
 struct npr_rq_completion completion;
};
struct npr_rq {
 struct npr_rq_config config;
 struct rq_desc *first,*last;
 size_t refs,outstanding,queued,claimed,terminal,captures;
 uint64_t receive_sequence,message_sequence;
 unsigned committed,closing,close_mode;
};
static uint64_t next_token=1; /* Existing global API gate serializes all users. */
static int same_key(const struct npr_rq_key *a,const struct npr_rq_key *b)
{return a->cookie==b->cookie&&a->generation==b->generation&&a->connection_epoch==b->connection_epoch;}
static int valid_config(const struct npr_rq_config *c)
{return c&&c->context&&c->key.cookie&&c->key.generation&&c->key.connection_epoch;}
struct npr_rq *npr_rq_prepare(const struct npr_rq_config *c)
{
 if(!valid_config(c)){errno=EINVAL;return NULL;}
 struct npr_rq *q=calloc(1,sizeof(*q));if(!q)return NULL;
 q->config=*c;q->refs=1;q->receive_sequence=q->message_sequence=1;return q;
}
void npr_rq_commit(struct npr_rq *q,const struct npr_rq_config *c)
{
 assert(q&&!q->committed&&valid_config(c)&&c->pd&&same_key(&q->config.key,&c->key)&&q->config.context==c->context&&(!q->config.pd||q->config.pd==c->pd));
 q->config=*c;q->committed=1;
}
void npr_rq_get(struct npr_rq *q){assert(q&&q->refs&&q->refs<SIZE_MAX);q->refs++;}
void npr_rq_put(struct npr_rq *q){if(!q)return;assert(q->refs);if(!--q->refs){assert(!q->first);free(q);}}
void npr_rq_abort(struct npr_rq *q){if(q){assert(!q->committed&&!q->first);npr_rq_put(q);}}
static size_t release_captures(struct rq_desc *d)
{size_t n=0;for(unsigned i=0;i<d->num_sge;i++){n+=d->captures[i].registration!=NULL;npr_mra_release(&d->captures[i]);}return n;}
static void free_desc(struct rq_desc *d){free(d->captures);free(d->spans);free(d);}
int npr_rq_post_native(struct npr_rq *q,struct ibv_recv_wr *wr,struct ibv_recv_wr **bad,npr_rq_post_native_fn native,void *opaque)
{
 int rc=0;if(bad)*bad=NULL;
 if(!q||!q->committed||q->closing){if(bad)*bad=wr;return EBUSY;}
 for(struct ibv_recv_wr *w=wr;w;w=w->next){
  struct rq_desc *d=NULL;
  if(w->num_sge<0||(w->num_sge&&!w->sg_list)){rc=EINVAL;goto failed;}
  if((unsigned)w->num_sge>q->config.max_recv_sge){rc=EINVAL;goto failed;}
  if(q->outstanding>=q->config.max_recv_wr){rc=ENOMEM;goto failed;}
  if(!next_token||!q->receive_sequence){rc=EOVERFLOW;goto failed;}
  d=calloc(1,sizeof(*d));if(!d){rc=ENOMEM;goto failed;}
  d->num_sge=(unsigned)w->num_sge;
  if(d->num_sge){
   d->captures=calloc(d->num_sge,sizeof(*d->captures));d->spans=calloc(d->num_sge,sizeof(*d->spans));
   if(!d->captures||!d->spans){rc=ENOMEM;goto failed;}
  }
  for(unsigned i=0;i<d->num_sge;i++){
   const struct ibv_sge *s=&w->sg_list[i];
   if(!s->length)continue;
   rc=npr_mra_capture(q->config.context,q->config.pd,s->lkey,s->addr,s->length,&d->captures[i]);
   if(rc)goto failed;
  }
  d->state=RQ_QUEUED;d->plan.token=next_token;d->plan.user_wr_id=w->wr_id;d->plan.receive_sequence=q->receive_sequence;
  if(native){rc=native(opaque,d->plan.token);if(rc)goto failed;}
  next_token++;q->receive_sequence++;
  d->plan.spans=d->spans;
  if(q->last)q->last->next=d;else q->first=d;q->last=d;
  q->outstanding++;q->queued++;
  for(unsigned i=0;i<d->num_sge;i++)q->captures+=d->captures[i].registration!=NULL;
  npr_rq_get(q);continue;
failed:
  if(d){if(d->captures)release_captures(d);free_desc(d);}if(bad)*bad=w;return rc;
 }
 return 0;
}
int npr_rq_post(struct npr_rq *q,struct ibv_recv_wr *wr,struct ibv_recv_wr **bad)
{return npr_rq_post_native(q,wr,bad,NULL,NULL);}
static struct rq_desc *lookup(const struct npr_rq *q,uint64_t token)
{for(struct rq_desc *d=q->first;d;d=d->next)if(d->plan.token==token)return d;return NULL;}
static void make_plan(struct rq_desc *d,const struct npr_rq_message *m)
{
 uint64_t remaining=m->length,offset=0;
 d->plan.message=*m;d->plan.span_count=0;d->plan.rx_status=d->plan.tx_status=IBV_WC_SUCCESS;
 if(m->kind==NPR_RQ_WWI)return;
 for(unsigned i=0;i<d->num_sge&&remaining;i++){
  uint64_t declared=d->captures[i].declared_length,used=declared<remaining?declared:remaining;
  if(!used)continue;
  struct npr_rq_span *s=&d->spans[d->plan.span_count];
  if(npr_mra_validate_used(&d->captures[i],0,used,NPR_MRA_SINK,&s->view)){
   d->plan.rx_status=IBV_WC_LOC_PROT_ERR;d->plan.tx_status=IBV_WC_REM_OP_ERR;d->plan.span_count=0;return;
  }
  s->message_offset=offset;d->plan.span_count++;remaining-=used;offset+=used;
 }
 if(remaining){d->plan.rx_status=IBV_WC_LOC_LEN_ERR;d->plan.tx_status=IBV_WC_REM_INV_REQ_ERR;d->plan.span_count=0;}
}
int npr_rq_stream_begin(struct npr_rq *q,uint64_t base)
{
 if(!q||!base)return EINVAL;
 if(!q->committed||q->closing)return EBUSY;
 q->message_sequence=base;return 0;
}
int npr_rq_claim(struct npr_rq *q,const struct npr_rq_message *m,npr_rq_reserve_fn reserve,void *opaque,uint64_t *token)
{
 if(token)*token=0;
 if(!q||!m||!reserve||!token||!m->message_id||m->kind<NPR_RQ_SEND||m->kind>NPR_RQ_WWI||m->length>UINT32_MAX)return EINVAL;
 if(!q->committed||q->closing)return EBUSY;
 if(!same_key(&q->config.key,&m->local))return ESTALE;
 if(!q->message_sequence)return EOVERFLOW;
 if(m->sequence<q->message_sequence)return EALREADY;
 if(m->sequence>q->message_sequence)return EAGAIN;
 struct rq_desc *d;for(d=q->first;d&&d->state!=RQ_QUEUED;d=d->next){}
 if(!d)return EAGAIN;
 make_plan(d,m);uint64_t reservation=0;int rc=reserve(opaque,&d->plan,&reservation);
 if(rc)return rc;
 d->completion.reservation=reservation;d->state=RQ_CLAIMED;assert(q->queued);q->queued--;q->claimed++;q->message_sequence++;*token=d->plan.token;return 0;
}
static void terminal(struct npr_rq *q,struct rq_desc *d,enum ibv_wc_status rx,enum ibv_wc_status tx)
{
 size_t released=release_captures(d);assert(q->captures>=released);q->captures-=released;
 if(d->state==RQ_QUEUED){assert(q->queued);q->queued--;}else {assert(d->state==RQ_CLAIMED&&q->claimed);q->claimed--;}
 assert(q->outstanding);q->outstanding--;q->terminal++;d->state=RQ_TERMINAL;
 struct npr_rq_completion *c=&d->completion;
 c->token=d->plan.token;c->user_wr_id=d->plan.user_wr_id;c->receive_sequence=d->plan.receive_sequence;c->key=q->config.key;c->tx_status=tx;
 c->discard=q->closing&&q->close_mode==NPR_RQ_CLOSE_DISCARD;
 c->wc=(struct ibv_wc){.wr_id=c->user_wr_id,.qp_num=q->config.qp_num,.status=rx};
 if(rx==IBV_WC_SUCCESS){
  c->wc.opcode=d->plan.message.kind==NPR_RQ_WWI?IBV_WC_RECV_RDMA_WITH_IMM:IBV_WC_RECV;
  c->wc.byte_len=(uint32_t)d->plan.message.length;
  if(d->plan.message.kind!=NPR_RQ_SEND){c->wc.wc_flags=IBV_WC_WITH_IMM;c->wc.imm_data=d->plan.message.imm_be;}
  c->solicited=d->plan.message.solicited;
 }
}
int npr_rq_wwi_unclaim(struct npr_rq *q,uint64_t token)
{
 if(!q)return EINVAL;
 struct rq_desc *d=lookup(q,token);if(!d)return ENOENT;
 if(d->state!=RQ_CLAIMED||d->plan.message.kind!=NPR_RQ_WWI||d->plan.span_count)return EINVAL;
 if(q->closing){terminal(q,d,IBV_WC_WR_FLUSH_ERR,IBV_WC_WR_FLUSH_ERR);return 0;}
 assert(q->claimed);q->claimed--;q->queued++;
 d->state=RQ_QUEUED;d->plan.message=(struct npr_rq_message){0};
 d->plan.rx_status=d->plan.tx_status=IBV_WC_SUCCESS;
 d->completion=(struct npr_rq_completion){0};return 0;
}
int npr_rq_finish(struct npr_rq *q,uint64_t token,enum ibv_wc_status rx,enum ibv_wc_status tx,enum npr_rq_cleanup_evidence evidence)
{
 if(!q)return EINVAL;
 struct rq_desc *d=lookup(q,token);if(!d)return ENOENT;
 if(d->state==RQ_TERMINAL)return EALREADY;
 if(d->state!=RQ_CLAIMED)return EINVAL;
 if(evidence<NPR_RQ_NO_DATA||evidence>NPR_RQ_DMA_STOPPED_CLEANED)return EINVAL;
 if(evidence==NPR_RQ_NO_DATA&&d->plan.span_count)return EBUSY;
 if(d->plan.rx_status!=IBV_WC_SUCCESS&&(rx!=d->plan.rx_status||tx!=d->plan.tx_status))return EINVAL;
 terminal(q,d,rx,tx);return 0;
}
void npr_rq_close(struct npr_rq *q,enum npr_rq_close_mode mode)
{
 assert(q&&(mode==NPR_RQ_CLOSE_FLUSH||mode==NPR_RQ_CLOSE_DISCARD));
 if(q->closing){
  if(mode==NPR_RQ_CLOSE_DISCARD){q->close_mode=mode;for(struct rq_desc *d=q->first;d;d=d->next)if(d->state==RQ_TERMINAL)d->completion.discard=1;}
  return;
 }
 q->closing=1;q->close_mode=mode;
 for(struct rq_desc *d=q->first;d;d=d->next){
  if(d->state==RQ_QUEUED)terminal(q,d,IBV_WC_WR_FLUSH_ERR,IBV_WC_WR_FLUSH_ERR);
  else if(d->state==RQ_CLAIMED)d->cancel_requested=1;
  else if(mode==NPR_RQ_CLOSE_DISCARD)d->completion.discard=1;
 }
}
int npr_rq_cancel_requested(const struct npr_rq *q,uint64_t token)
{if(!q)return 0;struct rq_desc *d=lookup(q,token);return d&&d->cancel_requested;}
int npr_rq_peek_terminal(struct npr_rq *q,struct npr_rq_completion *out)
{
 if(!q||!out)return EINVAL;
 for(struct rq_desc *d=q->first;d;d=d->next){if(d->state!=RQ_TERMINAL)return EAGAIN;*out=d->completion;return 0;}
 return ENOENT;
}
int npr_rq_retire(struct npr_rq *q,uint64_t token)
{
 if(!q)return EINVAL;
 struct rq_desc **p=&q->first;while(*p&&(*p)->plan.token!=token)p=&(*p)->next;
 if(!*p)return ENOENT;
 struct rq_desc *d=*p;if(d->state!=RQ_TERMINAL)return EBUSY;
 if(d!=q->first)return EAGAIN;
 *p=d->next;if(q->last==d)q->last=NULL;assert(q->terminal);q->terminal--;free_desc(d);npr_rq_put(q);return 0;
}
void npr_rq_get_counts(const struct npr_rq *q,struct npr_rq_counts *out)
{
 *out=q?(struct npr_rq_counts){.queued=q->queued,.claimed=q->claimed,
  .terminal=q->terminal,.outstanding=q->outstanding,.captures=q->captures}:(struct npr_rq_counts){0};
}
