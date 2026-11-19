/* SPDX-License-Identifier: GPL-2.0 */
#include "npr_native_notify.h"
#include <errno.h>
#include <string.h>

static void put64(unsigned char *p,uint64_t v)
{for(unsigned i=0;i<8;i++)p[i]=(unsigned char)(v>>(56-8*i));}
static uint64_t get64(const unsigned char *p)
{uint64_t v=0;for(unsigned i=0;i<8;i++)v=(v<<8)|p[i];return v;}
static void put32(unsigned char *p,uint32_t v)
{for(unsigned i=0;i<4;i++)p[i]=(unsigned char)(v>>(24-8*i));}
static uint32_t get32(const unsigned char *p)
{return (uint32_t)p[0]<<24|(uint32_t)p[1]<<16|(uint32_t)p[2]<<8|p[3];}
static int endpoint_valid(const struct npr_notify_endpoint *e)
{return e&&e->cookie&&e->generation&&e->epoch;}
static int endpoint_equal(const struct npr_notify_endpoint *a,const struct npr_notify_endpoint *b)
{return a->cookie==b->cookie&&a->generation==b->generation&&a->epoch==b->epoch;}
static int valid(const struct npr_notify_message *m)
{
 return m&&endpoint_valid(&m->source)&&endpoint_valid(&m->target)&&m->message_id&&m->sequence&&
  m->length<=UINT32_MAX&&m->kind>=NPR_NOTIFY_SEND&&m->kind<=NPR_NOTIFY_WWI&&m->solicited<=1&&
  (m->kind!=NPR_NOTIFY_SEND||!m->imm_be)&&
  (m->kind==NPR_NOTIFY_WWI||(!m->remote_address&&!m->remote_rkey));
}
int npr_notify_encode(void *buffer,size_t capacity,const struct npr_notify_message *m)
{
 if(!buffer||capacity<NPR_NOTIFY_BYTES||!valid(m))return EINVAL;
 unsigned char p[NPR_NOTIFY_BYTES]={0};
 memcpy(p,"NPNF",4);p[4]=2;p[5]=(unsigned char)m->kind;p[6]=(unsigned char)m->solicited;
 put64(p+8,m->source.cookie);put64(p+16,m->source.generation);put64(p+24,m->source.epoch);
 put64(p+32,m->target.cookie);put64(p+40,m->target.generation);put64(p+48,m->target.epoch);
 put64(p+56,m->message_id);put64(p+64,m->sequence);put64(p+72,m->length);
 put64(p+80,m->remote_address);put32(p+88,m->remote_rkey);
 /* Verbs immediate is already in network byte order. */
 memcpy(p+92,&m->imm_be,4);
 put64(p+96,m->session_id);put64(p+104,m->source_nonce);put64(p+112,m->target_nonce);
 memcpy(buffer,p,sizeof(p));return 0;
}
int npr_notify_decode(const void *buffer,size_t length,struct npr_notify_message *out)
{
 if(!buffer||!out)return EINVAL;
 if(length!=NPR_NOTIFY_BYTES)return EPROTO;
 const unsigned char *p=buffer;
 if(memcmp(p,"NPNF",4)||p[4]!=2||p[7])return EPROTO;
 struct npr_notify_message m={
  .source={get64(p+8),get64(p+16),get64(p+24)},
  .target={get64(p+32),get64(p+40),get64(p+48)},
  .message_id=get64(p+56),.sequence=get64(p+64),.length=get64(p+72),
  .remote_address=get64(p+80),.remote_rkey=get32(p+88),.kind=p[5],.solicited=p[6],
  .session_id=get64(p+96),.source_nonce=get64(p+104),.target_nonce=get64(p+112)};
 memcpy(&m.imm_be,p+92,4);
 if(!valid(&m))return EPROTO;
 *out=m;return 0;
}
int npr_notify_authorize(const struct npr_notify_message *m,
 const struct npr_notify_endpoint *source,const struct npr_notify_endpoint *target)
{
 if(!valid(m)||!endpoint_valid(source)||!endpoint_valid(target))return EINVAL;
 return endpoint_equal(&m->source,source)&&endpoint_equal(&m->target,target)?0:ESTALE;
}
int npr_notify_wwi_completion(const struct ibv_wc *native,uint64_t wr_id,
 const struct npr_notify_message *m,struct ibv_wc *out)
{
 if(!native||!out)return EINVAL;
 /* On an error only wr_id/status/qp_num/vendor_err are provider-defined. */
 struct ibv_wc wc={.wr_id=wr_id,.status=native->status,.qp_num=native->qp_num,
  .vendor_err=native->vendor_err,.opcode=IBV_WC_RECV_RDMA_WITH_IMM};
 if(native->status==IBV_WC_SUCCESS){
  if(!valid(m)||m->kind!=NPR_NOTIFY_WWI||native->opcode!=IBV_WC_RECV||
     native->byte_len!=NPR_NOTIFY_BYTES||(native->wc_flags&IBV_WC_WITH_IMM))return EPROTO;
  wc.byte_len=(uint32_t)m->length;wc.imm_data=m->imm_be;wc.wc_flags=IBV_WC_WITH_IMM;
 }
 *out=wc;return 0;
}
int npr_notify_send_wr(struct ibv_send_wr *wr,struct ibv_sge *sge,uint64_t token,
 uint64_t address,uint32_t lkey,unsigned solicited)
{
 if(!wr||!sge||!token||!address||solicited>1)return EINVAL;
 *sge=(struct ibv_sge){.addr=address,.length=NPR_NOTIFY_BYTES,.lkey=lkey};
 *wr=(struct ibv_send_wr){.wr_id=token,.sg_list=sge,.num_sge=1,.opcode=IBV_WR_SEND,
  .send_flags=IBV_SEND_SIGNALED|(solicited?IBV_SEND_SOLICITED:0)};
 return 0;
}
void npr_notify_tx_init(struct npr_notify_tx *t,uint64_t generation)
{if(t)*t=(struct npr_notify_tx){.generation=generation};}
static int current(struct npr_notify_tx *t,uint64_t generation)
{return !t||!generation?EINVAL:t->generation!=generation?ESTALE:t->retired?EALREADY:0;}
int npr_notify_tx_data(struct npr_notify_tx *t,uint64_t generation,enum ibv_wc_status status)
{
 int rc=current(t,generation);if(rc)return rc;
 if(t->data_done)return EALREADY;
 t->data_done=1;t->data_status=status;return 0;
}
int npr_notify_tx_posted(struct npr_notify_tx *t,uint64_t generation)
{
 int rc=current(t,generation);if(rc)return rc;
 if(t->send_posted||t->send_rejected)return EALREADY;
 if(!t->data_done)return EAGAIN;
 if(t->stopped||t->data_status!=IBV_WC_SUCCESS)return ECANCELED;
 t->send_posted=1;return 0;
}
int npr_notify_tx_rejected(struct npr_notify_tx *t,uint64_t generation,enum ibv_wc_status status)
{
 int rc=current(t,generation);if(rc)return rc;
 if(t->send_posted||t->send_rejected)return EALREADY;
 if(!t->data_done)return EAGAIN;
 if(status==IBV_WC_SUCCESS||t->data_status!=IBV_WC_SUCCESS||t->stopped)return EINVAL;
 t->send_rejected=1;t->send_status=status;return 0;
}
int npr_notify_tx_send(struct npr_notify_tx *t,uint64_t generation,enum ibv_wc_status status)
{
 int rc=current(t,generation);if(rc)return rc;
 if(!t->send_posted)return EINVAL;
 if(t->send_done)return EALREADY;
 t->send_done=1;t->send_status=status;return 0;
}
int npr_notify_tx_receipt(struct npr_notify_tx *t,uint64_t generation,enum ibv_wc_status status)
{
 int rc=current(t,generation);if(rc)return rc;
 if(!t->send_posted)return EINVAL;
 if(t->receipt_done)return EALREADY;
 t->receipt_done=1;t->receipt_status=status;return 0;
}
int npr_notify_tx_stopped(struct npr_notify_tx *t,uint64_t generation)
{
 int rc=current(t,generation);if(rc)return rc;
 if(t->stopped)return EALREADY;
 t->stopped=1;return 0;
}
int npr_notify_tx_retire(struct npr_notify_tx *t,enum ibv_wc_status *status)
{
 if(!t||!status||!t->generation)return EINVAL;
 if(t->retired)return EALREADY;
 /* stopped is a caller-supplied proof of all native DMA and peer repair stop,
  * not merely QP ERR or a cancellation request. */
 if(t->stopped)*status=IBV_WC_WR_FLUSH_ERR;
 else if(!t->data_done)return EAGAIN;
 else if(t->data_status!=IBV_WC_SUCCESS)*status=t->data_status;
 else if(t->send_rejected)*status=t->send_status;
 else if(!t->send_posted||!t->send_done||!t->receipt_done)return EAGAIN;
 else *status=t->send_status!=IBV_WC_SUCCESS?t->send_status:t->receipt_status;
 t->retired=1;return 0;
}
