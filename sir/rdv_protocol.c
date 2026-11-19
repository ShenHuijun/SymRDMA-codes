/* SPDX-License-Identifier: GPL-2.0 */
#include "rdv_protocol.h"
#include <errno.h>
#include <limits.h>
#include <string.h>

static void p16(uint8_t *p,uint16_t v){p[0]=(uint8_t)(v>>8);p[1]=(uint8_t)v;}
static void p32(uint8_t *p,uint32_t v){for(unsigned i=0;i<4;i++)p[i]=(uint8_t)(v>>(24-8*i));}
static void p64(uint8_t *p,uint64_t v){for(unsigned i=0;i<8;i++)p[i]=(uint8_t)(v>>(56-8*i));}
static uint16_t g16(const uint8_t *p){return (uint16_t)((uint16_t)p[0]<<8|p[1]);}
static uint32_t g32(const uint8_t *p){uint32_t v=0;for(unsigned i=0;i<4;i++)v=(v<<8)|p[i];return v;}
static uint64_t g64(const uint8_t *p){uint64_t v=0;for(unsigned i=0;i<8;i++)v=(v<<8)|p[i];return v;}
static int zero(const uint8_t *p,unsigned n){unsigned v=0;for(unsigned i=0;i<n;i++)v|=p[i];return !v;}
static int message_valid(const struct rdvp_message *m)
{
 return m&&cproto_qp_endpoint_valid(&m->sender)&&cproto_qp_endpoint_valid(&m->receiver)&&
 m->message_id&&m->sequence&&m->total_length<=UINT32_MAX&&m->kind>=RDVP_SEND&&m->kind<=RDVP_WWI&&
 !(m->flags&~RDVP_F_SOLICITED);
}
static void common_put(uint8_t *p,uint32_t op,const struct rdvp_message *m)
{
 p32(p,op);p[4]=m->kind;p[5]=m->flags;p16(p+6,0);
 cproto_qp_endpoint_put(p+8,&m->sender);cproto_qp_endpoint_put(p+88,&m->receiver);
 p64(p+168,m->message_id);p64(p+176,m->sequence);p64(p+184,m->total_length);
}
static int common_get(const uint8_t *p,uint32_t len,uint32_t op,struct rdvp_message *m)
{
 if(!p||len<RDVP_COMMON_SIZE||len>CONTROL_PAYLOAD_MAX||g32(p)!=op||!zero(p+6,2))return -EPROTO;
 memset(m,0,sizeof(*m));m->kind=p[4];m->flags=p[5];
 if(cproto_qp_endpoint_get(p+8,&m->sender)||cproto_qp_endpoint_get(p+88,&m->receiver))return -EPROTO;
 m->message_id=g64(p+168);m->sequence=g64(p+176);m->total_length=g64(p+184);
 return message_valid(m)?0:-EPROTO;
}
static int offer_header_valid(const struct rdvp_offer *o)
{
 if(!o||!message_valid(&o->message))return 0;
 if(o->message.kind==RDVP_SEND&&o->imm_be)return 0;
 int empty=o->message.kind==RDVP_WWI||!o->message.total_length;
 if(empty)return !o->total_segments&&o->fragment_count==1&&!o->fragment_index&&
 !o->segment_offset&&!o->entry_count&&!o->message_offset;
 if(!o->total_segments||o->total_segments>o->message.total_length)return 0;
 /* All arithmetic is wide, including ceil and hostile index products. */
 uint64_t count=((uint64_t)o->total_segments+RDVP_SEGMENTS_PER_FRAME-1)/RDVP_SEGMENTS_PER_FRAME;
 uint64_t offset=(uint64_t)o->fragment_index*RDVP_SEGMENTS_PER_FRAME;
 if(o->fragment_count!=count||o->fragment_index>=count||o->segment_offset!=offset)return 0;
 uint64_t remaining=(uint64_t)o->total_segments-offset;
 uint64_t entries=remaining<RDVP_SEGMENTS_PER_FRAME?remaining:RDVP_SEGMENTS_PER_FRAME;
 return o->entry_count==entries&&o->message_offset<=o->message.total_length&&
 (o->fragment_index||!o->message_offset);
}
static int segments_valid(const struct rdvp_offer *o,const struct rdvp_segment *s)
{
 if(o->entry_count&&!s)return 0;
 uint64_t sum=0;
 for(uint32_t i=0;i<o->entry_count;i++){
  if(!s[i].length||s[i].address>UINT64_MAX-s[i].length||sum>UINT64_MAX-s[i].length)return 0;
  sum+=s[i].length;
 }
 if(o->message_offset>o->message.total_length||sum>o->message.total_length-o->message_offset)return 0;
 /* WWI carries write byte_len but intentionally no source DMA segments. */
 if(o->entry_count&&(uint64_t)o->fragment_index+1==o->fragment_count&&
    sum!=o->message.total_length-o->message_offset)return 0;
 return 1;
}
int rdvp_offer_encode(uint8_t *p,uint32_t cap,const struct rdvp_offer *o,const struct rdvp_segment *s)
{
 if(!p||!offer_header_valid(o)||!segments_valid(o,s))return -EINVAL;
 uint32_t n=RDVP_OFFER_SIZE+o->entry_count*RDVP_SEGMENT_SIZE;
 if(cap<n)return -ENOSPC;
 memset(p,0,n);common_put(p,CPROTO_OP_RDV_OFFER,&o->message);
 memcpy(p+192,&o->imm_be,4);p32(p+196,o->total_segments);p32(p+200,o->fragment_count);
 p32(p+204,o->fragment_index);p32(p+208,o->segment_offset);p32(p+212,o->entry_count);p64(p+216,o->message_offset);
 for(uint32_t i=0;i<o->entry_count;i++){
  uint8_t *e=p+RDVP_OFFER_SIZE+i*RDVP_SEGMENT_SIZE;
  p64(e,s[i].address);p64(e+8,s[i].length);p32(e+16,s[i].rkey);
 }
 return (int)n;
}
int rdvp_offer_decode(const uint8_t *p,uint32_t len,struct rdvp_offer *out,struct rdvp_segment *s,uint32_t cap)
{
 struct rdvp_offer o;struct rdvp_segment tmp[RDVP_SEGMENTS_PER_FRAME]={{0}};
 if(!out||!p||len<RDVP_OFFER_SIZE||common_get(p,len,CPROTO_OP_RDV_OFFER,&o.message))return -EPROTO;
 memcpy(&o.imm_be,p+192,4);o.total_segments=g32(p+196);o.fragment_count=g32(p+200);
 o.fragment_index=g32(p+204);o.segment_offset=g32(p+208);o.entry_count=g32(p+212);o.message_offset=g64(p+216);
 if(!offer_header_valid(&o)||len!=RDVP_OFFER_SIZE+(uint64_t)o.entry_count*RDVP_SEGMENT_SIZE)return -EPROTO;
 for(uint32_t i=0;i<o.entry_count;i++){
  const uint8_t *e=p+RDVP_OFFER_SIZE+i*RDVP_SEGMENT_SIZE;
  if(!zero(e+20,4))return -EPROTO;
  tmp[i]=(struct rdvp_segment){g64(e),g64(e+8),g32(e+16)};
 }
 if(!segments_valid(&o,tmp))return -EPROTO;
 if(o.entry_count>cap||(!s&&o.entry_count))return -ENOSPC;
 if(o.entry_count)memcpy(s,tmp,o.entry_count*sizeof(*s));
 *out=o;return 0;
}
int rdvp_wait_encode(uint8_t *p,uint32_t cap,const struct rdvp_wait *w)
{
 if(!p||!w||!message_valid(&w->message)||w->min_rnr_timer>31)return -EINVAL;
 if(cap<RDVP_WAIT_SIZE)return -ENOSPC;
 memset(p,0,RDVP_WAIT_SIZE);common_put(p,CPROTO_OP_RDV_WAIT,&w->message);p[192]=w->min_rnr_timer;return RDVP_WAIT_SIZE;
}
int rdvp_wait_decode(const uint8_t *p,uint32_t len,struct rdvp_wait *out)
{
 struct rdvp_wait w;
 if(!out||len!=RDVP_WAIT_SIZE||common_get(p,len,CPROTO_OP_RDV_WAIT,&w.message)||p[192]>31||!zero(p+193,7))return -EPROTO;
 w.min_rnr_timer=p[192];*out=w;return 0;
}
static int ack_valid(uint32_t op,const struct rdvp_ack *a)
{
 return a&&(op==CPROTO_OP_RDV_ACK||op==CPROTO_OP_RDV_CANCEL_ACK||op==CPROTO_OP_RDV_WWI_READY||op==CPROTO_OP_RDV_WWI_RESULT)&&message_valid(&a->message)&&
 (unsigned)a->status<=RDVP_REMOTE_ACCESS&&
 (a->status!=RDVP_REMOTE_ACCESS||a->message.kind==RDVP_WWI)&&
 ((op!=CPROTO_OP_RDV_WWI_READY&&op!=CPROTO_OP_RDV_WWI_RESULT)||a->message.kind==RDVP_WWI)&&
 (op!=CPROTO_OP_RDV_WWI_READY||(a->status==RDVP_OK&&!a->completed_length))&&
 (op!=CPROTO_OP_RDV_WWI_RESULT||a->status==RDVP_OK||(a->status==RDVP_REMOTE_ACCESS&&!a->completed_length))&&a->completed_length<=a->message.total_length&&
 (a->status!=RDVP_OK||op==CPROTO_OP_RDV_WWI_READY||a->completed_length==a->message.total_length);
}
int rdvp_ack_encode(uint8_t *p,uint32_t cap,uint32_t op,const struct rdvp_ack *a)
{
 if(!p||!ack_valid(op,a))return -EINVAL;
 if(cap<RDVP_ACK_SIZE)return -ENOSPC;
 memset(p,0,RDVP_ACK_SIZE);common_put(p,op,&a->message);p16(p+192,(uint16_t)a->status);p64(p+200,a->completed_length);return RDVP_ACK_SIZE;
}
int rdvp_ack_decode(const uint8_t *p,uint32_t len,uint32_t *op,struct rdvp_ack *out)
{
 struct rdvp_ack a;
 if(!out||!op||!p||len!=RDVP_ACK_SIZE)return -EPROTO;
 uint32_t kind=g32(p);
 if((kind!=CPROTO_OP_RDV_ACK&&kind!=CPROTO_OP_RDV_CANCEL_ACK&&kind!=CPROTO_OP_RDV_WWI_READY&&kind!=CPROTO_OP_RDV_WWI_RESULT)||common_get(p,len,kind,&a.message)||!zero(p+194,6))return -EPROTO;
 a.status=(enum rdvp_status)g16(p+192);a.completed_length=g64(p+200);
 if(!ack_valid(kind,&a))return -EPROTO;
 *op=kind;*out=a;return 0;
}
int rdvp_cancel_encode(uint8_t *p,uint32_t cap,const struct rdvp_cancel *c)
{
 if(!p||!c||!message_valid(&c->message)||c->reason<RDVP_LOCAL_QP_STOP||c->reason>RDVP_SESSION_CLOSE)return -EINVAL;
 if(cap<RDVP_CANCEL_SIZE)return -ENOSPC;
 memset(p,0,RDVP_CANCEL_SIZE);common_put(p,CPROTO_OP_RDV_CANCEL,&c->message);p16(p+192,(uint16_t)c->reason);return RDVP_CANCEL_SIZE;
}
int rdvp_cancel_decode(const uint8_t *p,uint32_t len,struct rdvp_cancel *out)
{
 struct rdvp_cancel c;
 if(!out||len!=RDVP_CANCEL_SIZE||common_get(p,len,CPROTO_OP_RDV_CANCEL,&c.message)||!zero(p+194,6))return -EPROTO;
 c.reason=(enum rdvp_cancel_reason)g16(p+192);
 if(c.reason<RDVP_LOCAL_QP_STOP||c.reason>RDVP_SESSION_CLOSE)return -EPROTO;
 *out=c;return 0;
}
int rdvp_retired_encode(uint8_t *p,uint32_t cap,const struct rdvp_message *m)
{
 if(!p||!message_valid(m))return -EINVAL;
 if(cap<RDVP_RETIRED_SIZE)return -ENOSPC;
 common_put(p,CPROTO_OP_RDV_RETIRED,m);return RDVP_RETIRED_SIZE;
}
int rdvp_retired_decode(const uint8_t *p,uint32_t len,struct rdvp_message *out)
{
 struct rdvp_message m;
 if(!out||len!=RDVP_RETIRED_SIZE||common_get(p,len,CPROTO_OP_RDV_RETIRED,&m))return -EPROTO;
 *out=m;return 0;
}

int rdvp_caps_encode(uint8_t *p,uint32_t cap,const struct rdvp_caps *v)
{
 if(!p||!v||!cproto_qp_endpoint_valid(&v->sender)||!cproto_qp_endpoint_valid(&v->receiver))return -EINVAL;
 if(cap<RDVP_CAPS_SIZE)return -ENOSPC;
 memset(p,0,RDVP_CAPS_SIZE);p32(p,CPROTO_OP_RDV_CAPS);
 cproto_qp_endpoint_put(p+4,&v->sender);cproto_qp_endpoint_put(p+84,&v->receiver);
 if(v->flags&~RDVP_CAP_NATIVE_WWI)return -EINVAL;
 p32(p+164,v->source_sge_limit);p32(p+168,v->flags);return RDVP_CAPS_SIZE;
}
int rdvp_caps_decode(const uint8_t *p,uint32_t len,struct rdvp_caps *out)
{
 if(!p||!out||len!=RDVP_CAPS_SIZE||g32(p)!=CPROTO_OP_RDV_CAPS||(g32(p+168)&~RDVP_CAP_NATIVE_WWI))return -EPROTO;
 struct rdvp_caps v={0};
 if(cproto_qp_endpoint_get(p+4,&v.sender)||cproto_qp_endpoint_get(p+84,&v.receiver))return -EPROTO;
 v.source_sge_limit=g32(p+164);v.flags=g32(p+168);*out=v;return 0;
}

int rdvp_caps_ack_encode(uint8_t *p,uint32_t cap,const struct rdvp_caps *v)
{int rc=rdvp_caps_encode(p,cap,v);if(rc>0)p32(p,CPROTO_OP_RDV_CAPS_ACK);return rc;}
int rdvp_caps_ack_decode(const uint8_t *p,uint32_t len,struct rdvp_caps *out)
{
 if(!p||!out||len!=RDVP_CAPS_SIZE||g32(p)!=CPROTO_OP_RDV_CAPS_ACK||(g32(p+168)&~RDVP_CAP_NATIVE_WWI))return -EPROTO;
 struct rdvp_caps v={0};if(cproto_qp_endpoint_get(p+4,&v.sender)||cproto_qp_endpoint_get(p+84,&v.receiver))return -EPROTO;
 v.source_sge_limit=g32(p+164);v.flags=g32(p+168);*out=v;return 0;
}

static int drain_valid(uint32_t op,const struct rdvp_drain *d)
{
 return d&&(op==CPROTO_OP_RDV_DRAIN_REQUEST||op==CPROTO_OP_RDV_DRAIN_ACK)&&
 cproto_qp_endpoint_valid(&d->sender)&&cproto_qp_endpoint_valid(&d->receiver)&&
 (unsigned)d->status<=RDVP_DRAIN_CLOSED&&
 (op!=CPROTO_OP_RDV_DRAIN_REQUEST||d->status==RDVP_DRAIN_COMPLETE);
}
int rdvp_drain_encode(uint8_t *p,uint32_t cap,uint32_t op,const struct rdvp_drain *d)
{
 if(!p||!drain_valid(op,d))return -EINVAL;
 if(cap<RDVP_DRAIN_SIZE)return -ENOSPC;
 memset(p,0,RDVP_DRAIN_SIZE);p32(p,op);
 cproto_qp_endpoint_put(p+4,&d->sender);cproto_qp_endpoint_put(p+84,&d->receiver);
 p32(p+164,(uint32_t)d->status);return RDVP_DRAIN_SIZE;
}
int rdvp_drain_decode(const uint8_t *p,uint32_t n,uint32_t *op,struct rdvp_drain *out)
{
 if(!p||!op||!out||n!=RDVP_DRAIN_SIZE||!zero(p+168,4))return -EPROTO;
 uint32_t kind=g32(p);struct rdvp_drain d={0};
 if(cproto_qp_endpoint_get(p+4,&d.sender)||cproto_qp_endpoint_get(p+84,&d.receiver))return -EPROTO;
 d.status=(enum rdvp_drain_status)g32(p+164);
 if(!drain_valid(kind,&d))return -EPROTO;
 *op=kind;*out=d;return 0;
}
