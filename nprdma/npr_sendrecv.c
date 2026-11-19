/* SPDX-License-Identifier: GPL-2.0 */
#include "npr_sendrecv.h"
#include "npr_progress.h"
#include "endpoint_registry.h"
#include "nprdma_internal.h"
#include <errno.h>
#include <stdlib.h>

/* All mutations run under the process progress gate. Identity owns successful
 * preparations; only preparations abandoned before native posting enter retry. */
struct sr_hold {
 const struct mr_entry *mr;
 uint64_t addr,len,lease;
 unsigned pinned;
 struct sr_hold *next;
};
struct npr_sr_owner {
 struct npr_sr_owner *next;
 struct ibv_pd *pd;
 struct sr_hold *holds;
 unsigned abandoned,processing;
 uint64_t last_retry;
};
static struct npr_sr_owner *owners;
int npr_sr_owner_create(struct ibv_qp *qp,struct npr_sr_owner **out)
{
 struct npr_sr_owner *o;
 if(!qp || !out) return EINVAL;
 *out=NULL;o=calloc(1,sizeof(*o));if(!o)return ENOMEM;
 o->pd=qp->pd;o->next=owners;owners=o;*out=o;return 0;
}
int npr_sr_release(void *opaque)
{
 struct npr_sr_owner *o=opaque,**p;
 struct sr_hold **h,*old;
 int failed=0;
 if(!o)return 0;
 if(o->processing)return EBUSY;
 o->processing=1;
 for(h=&o->holds;(old=*h);) {
  if(old->pinned && npr_sr_unpin(old->mr,old->addr,old->len)) {failed=1;h=&old->next;continue;}
  old->pinned=0;
  if(old->lease)creg_lease_put(old->lease);
  if(old->mr)npr_sr_mr_put(old->mr);
  *h=old->next;free(old);
 }
 if(failed){o->processing=0;return EBUSY;}
 for(p=&owners;*p && *p!=o;p=&(*p)->next){}
 if(*p)*p=o->next;
 free(o);return 0;
}
void npr_sr_discard(struct npr_sr_owner *o)
{if(o){o->abandoned=1;(void)npr_sr_release(o);}}
void npr_sr_progress(void)
{
 struct npr_sr_owner *o,*candidate=NULL;
 static uint64_t retry_sequence;
 /* Retry one abandoned preparation per pump. Select the least recently
  * attempted one so a persistently failing UNPIN cannot starve later cleanup. */
 for(o=owners;o;o=o->next)
  if(o->abandoned&&!o->processing&&(!candidate||o->last_retry<candidate->last_retry))candidate=o;
 if(candidate){candidate->last_retry=++retry_sequence;if(npr_sr_release(candidate))npr_progress_wake();}
}
int npr_sr_pd_release(struct ibv_pd *pd)
{
 struct npr_sr_owner *o;
 npr_sr_progress();
 for(o=owners;o;o=o->next)if(o->pd==pd)return EBUSY;
 return 0;
}
int npr_sr_hold_pin(void *opaque,const struct mr_entry *m,uint64_t addr,uint64_t len)
{
 struct npr_sr_owner *o=opaque;
 struct sr_hold *h;
 if(!o||!m||!len)return EINVAL;
 h=calloc(1,sizeof(*h));if(!h)return ENOMEM;
 if(npr_sr_mr_get(m)){free(h);return EBUSY;}
 h->mr=m;h->addr=addr;h->len=len;h->next=o->holds;o->holds=h;
 o->processing=1;
 int rc=npr_local_pin(m,addr,len),saved=errno;
 if(!rc)h->pinned=1;
 o->processing=0;errno=saved;
 if(rc)return EIO;
 return 0;
}
static int sr_prepare(struct ibv_qp *qp,struct ibv_sge *sg,unsigned n,int recv,struct npr_sr_owner **out,int retain_failure,const struct npr_op *original)
{
 struct npr_sr_owner *o;
 unsigned i;
 int rc;
 if(!out||n>1024||(n&&!sg))return EINVAL;
 *out=NULL;
 if((rc=npr_sr_owner_create(qp,&o)))return rc;
 for(i=0;i<n;i++){
  if(original&&original->local_mr[i]&&sg[i].length){
   rc=npr_sr_hold_pin(o,original->local_mr[i],sg[i].addr,sg[i].length);if(rc)goto fail;
   if(npr_data_lkey_owned(original,i,recv,&sg[i].lkey)){rc=EACCES;goto fail;}
   continue;
  }
  if(original&&original->local_bound)continue; /* original native/unknown, never upgrade by a reused key */
  struct sr_hold *h=calloc(1,sizeof(*h));uint32_t key=sg[i].lkey;
  if(!h){rc=ENOMEM;goto fail;}
  h->next=o->holds;o->holds=h;
  rc=npr_sr_pin_sge(qp->pd,&sg[i],recv,&h->mr,&h->lease);
  if(rc<0){rc=errno?errno:EACCES;goto fail;}
  if(rc){
   h->addr=sg[i].addr;h->len=sg[i].length;h->pinned=1;
   if(npr_data_lkey(key,recv,&sg[i].lkey)){rc=EACCES;goto fail;}
  }
 }
 *out=o;return 0;
fail:
 if(retain_failure)*out=o;else npr_sr_discard(o);
 return rc;
}
int npr_sr_prepare(struct ibv_qp *qp,struct ibv_sge *sg,unsigned n,int recv,struct npr_sr_owner **out)
{return sr_prepare(qp,sg,n,recv,out,0,NULL);}
int npr_sr_prepare_op(struct ibv_qp *qp,const struct npr_op *op,struct ibv_sge *sg,unsigned n,int recv,struct npr_sr_owner **out,int retain_failure)
{return sr_prepare(qp,sg,n,recv,out,retain_failure,op);}

#include "npr_identity.h"
#include "npr_order.h"
#include "npr_op.h"
#include "npr_rendezvous.h"
#include <string.h>
int npr_sr_send_submit(struct npr_ctx_entry *ce,struct ibv_qp *qp,const struct npr_op *op)
{
 struct ibv_sge sge[NPR_OP_MAX_SGE];struct ibv_send_wr wr={0},*bad=NULL;
 struct npr_sr_owner *hold=NULL;struct npr_identity *id;unsigned i;int rc;
 struct npr_identity_spec spec;
 if(!ce||!qp||!ce->real_post_send||!op||!npr_op_is_send(op)||op->num_sge>NPR_OP_MAX_SGE)return EINVAL;
 spec=(struct npr_identity_spec){.kind=NPR_ID_SEND,.lane=NPR_LANE_SQ,
  .user_wr_id=op->wr_id,.opcode=IBV_WC_SEND,.visible=op->signaled||npr_qp_sig_all(ce,qp),.order=op->order};
 if(op->rdv_owner)return npr_rdv_source_dispatch(op->rdv_owner);
 if(qp->qp_type!=IBV_QPT_RC)return EOPNOTSUPP;
 id=npr_identity_prepare(ce,qp,qp->send_cq,&spec);if(!id)return errno?errno:ENOMEM;
 for(i=0;i<op->num_sge;i++)sge[i]=(struct ibv_sge){.addr=op->sge[i].addr,.length=op->sge[i].length,.lkey=op->sge[i].lkey};
 rc=npr_sr_prepare_op(qp,op,sge,op->inline_?0:op->num_sge,0,&hold,0);
 if(rc){npr_identity_abort(id);return rc;}
 id->spec.resource=hold;id->spec.release=npr_sr_release;
 wr.opcode=op->kind==NPR_OP_SEND?IBV_WR_SEND:IBV_WR_SEND_WITH_IMM;wr.imm_data=op->imm;
 wr.num_sge=op->num_sge;wr.sg_list=op->num_sge?sge:NULL;wr.wr_id=id->token;
 wr.send_flags=(op->flags&~NPR_ORDER_HINT_MASK)|IBV_SEND_SIGNALED;
 if(op->inline_)wr.send_flags|=IBV_SEND_INLINE;
 if(op->order)npr_order_get(op->order);
 rc=ce->real_post_send(qp,&wr,&bad);
 if(rc){npr_identity_abort(id);if(op->order)npr_order_put(op->order);return rc;}
 npr_identity_accept(id);return 0;
}
