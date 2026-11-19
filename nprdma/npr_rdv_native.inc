/* SPDX-License-Identifier: GPL-2.0 */
/* Internal, transient native buffers: never application SGEs or adopted MRs.
 * Included by the engine so native identities use its existing stop/cleanup. */
#include "npr_native_notify.h"
#include "npr_native_notify.h"
#include "npr_native_notify.h"
struct npr_rdv_native_buffer {
 struct ibv_mr *mr;
 void *page,*opaque;
 npr_rdv_notify_fn done;
 unsigned accepted;
};
static int npr_rdv_native_release(void *opaque)
{
 struct npr_rdv_native_buffer *b=opaque;
 if(b->mr){
  int (*dereg)(struct ibv_mr *)=dlvsym(RTLD_NEXT,"ibv_dereg_mr","IBVERBS_1.1");
  if(!dereg||dereg(b->mr))return EBUSY;
  b->mr=NULL;
 }
 /* Keep bytes and callback storage until identity retirement. */
 return 0;
}
static void npr_rdv_native_context_stopped(void *opaque)
{struct npr_rdv_native_buffer *b=opaque;b->mr=NULL;}
static void npr_rdv_native_done(void *opaque,const struct ibv_wc *wc)
{
 struct npr_rdv_native_buffer *b=opaque;
 if(b->accepted&&b->done)b->done(b->opaque,wc,b->page);
 munmap(b->page,4096);free(b);
}
static int npr_rdv_native_post(struct npr_ctx_entry *ce,struct ibv_qp *qp,
 const void *bytes,unsigned solicited,void *opaque,npr_rdv_notify_fn done)
{
 int send=bytes!=NULL,rc;
 if(!ce||!qp||!done||ce->closing||
    (send?!ce->real_post_send:!ce->real_post_recv))return EINVAL;
 struct ibv_mr *(*reg)(struct ibv_pd *,void *,size_t,uint64_t,unsigned)=g_real_reg_mr_iova2;
 if(!reg)reg=dlvsym(RTLD_NEXT,"ibv_reg_mr_iova2","IBVERBS_1.8");
 if(!reg)return EOPNOTSUPP;
 struct npr_rdv_native_buffer *b=calloc(1,sizeof(*b));if(!b)return ENOMEM;
 b->page=mmap(NULL,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
 if(b->page==MAP_FAILED){free(b);return ENOMEM;}
 if(bytes)memcpy(b->page,bytes,NPR_NOTIFY_BYTES);
 struct npr_identity_spec spec={.kind=NPR_ID_INTERNAL,.lane=send?NPR_LANE_SQ:NPR_LANE_RQ,
  .opcode=send?IBV_WC_SEND:IBV_WC_RECV,.owner=b,
  .resource=b,.release=npr_rdv_native_release,.internal_done=npr_rdv_native_done,
  .internal_context_stopped=npr_rdv_native_context_stopped};
 struct npr_identity *id=npr_identity_prepare(ce,qp,send?qp->send_cq:qp->recv_cq,&spec);
 if(!id){munmap(b->page,4096);free(b);return errno?errno:ENOMEM;}
 b->mr=reg(qp->pd,b->page,4096,(uint64_t)(uintptr_t)b->page,IBV_ACCESS_LOCAL_WRITE);
 if(!b->mr){rc=errno?errno:ENOMEM;npr_identity_abort(id);return rc;}
 struct ibv_sge sg={.addr=(uint64_t)(uintptr_t)b->page,.length=NPR_NOTIFY_BYTES,.lkey=b->mr->lkey};
 if(send){
  struct ibv_send_wr wr={.wr_id=id->token,.opcode=IBV_WR_SEND,.num_sge=1,.sg_list=&sg,
   .send_flags=IBV_SEND_SIGNALED|(solicited?IBV_SEND_SOLICITED:0)},*bad=NULL;
  rc=ce->real_post_send(qp,&wr,&bad);
 }else{
  struct ibv_recv_wr wr={.wr_id=id->token,.num_sge=1,.sg_list=&sg},*bad=NULL;
  rc=ce->real_post_recv(qp,&wr,&bad);
 }
 if(rc){npr_identity_abort(id);return rc;}
 b->opaque=opaque;b->done=done;b->accepted=1;npr_identity_accept(id);
 if(debug_on())fprintf(stderr,"[nprdma] native WWI %s qp=%u token=%llu\n",
  send?"SEND":"RECV",qp->qp_num,(unsigned long long)id->token);
 return 0;
}
static int npr_rdv_native_recv(struct npr_ctx_entry *ce,struct ibv_qp *qp,
 void *opaque,npr_rdv_notify_fn done)
{return npr_rdv_native_post(ce,qp,NULL,0,opaque,done);}
static int npr_rdv_native_send(struct npr_ctx_entry *ce,struct ibv_qp *qp,
 const void *bytes,unsigned solicited,void *opaque,npr_rdv_notify_fn done)
{return npr_rdv_native_post(ce,qp,bytes,solicited,opaque,done);}
