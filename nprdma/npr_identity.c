/* SPDX-License-Identifier: GPL-2.0 */
#include "npr_identity.h"
#include "npr_progress.h"
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#define ID_BUCKETS 1024
struct npr_qp_identity_reservation {
 struct npr_qp_identity_reservation *next;
 struct ibv_qp *qp;
 struct ibv_context *context;
 uint32_t number;
 uint64_t generation;
};
static struct npr_qp_identity_reservation *qps;
static struct npr_identity *ids, *buckets[ID_BUCKETS];
static struct npr_identity *cleanup_first,*cleanup_last;
static uint64_t next_token=1, next_generation=1;
static unsigned live_count;
struct npr_qp_identity_reservation *npr_identity_qp_reserve(void)
{
 struct npr_qp_identity_reservation *q;
 if(!next_generation) {errno=EOVERFLOW;return NULL;}
 q=calloc(1,sizeof(*q));if(!q)return NULL;
 q->generation=next_generation++;
 return q;
}
uint64_t npr_identity_qp_reserved_generation(const struct npr_qp_identity_reservation *q)
{ return q->generation; }
void npr_identity_qp_commit(struct npr_qp_identity_reservation *q,struct ibv_qp *qp)
{
 assert(q&&qp&&!q->qp);
 q->qp=qp;q->context=qp->context;q->number=qp->qp_num;
 q->next=qps;qps=q;
}
void npr_identity_qp_abort(struct npr_qp_identity_reservation *q)
{ assert(!q||!q->qp);free(q); }
static struct npr_qp_identity_reservation *qp_identity(struct ibv_qp *qp)
{
 struct npr_qp_identity_reservation *q;
 for(q=qps;q;q=q->next) if(q->qp==qp) {
  if(q->context!=qp->context||q->number!=qp->qp_num) {errno=ESTALE;return NULL;}
  return q;
 }
 q=npr_identity_qp_reserve();if(!q)return NULL;
 npr_identity_qp_commit(q,qp);return q;
}
struct npr_identity *npr_identity_prepare(struct npr_ctx_entry *ce,struct ibv_qp *qp,
 struct ibv_cq *cq,const struct npr_identity_spec *spec)
{
 struct npr_identity *id;
 struct npr_qp_identity_reservation *q;
 if(!ce||!qp||!cq||!spec||spec->lane>NPR_LANE_RQ||(spec->resource&&!spec->release)) {errno=EINVAL;return NULL;}
 if(!next_token) {errno=EOVERFLOW;return NULL;}
 q=qp_identity(qp);if(!q) return NULL;
 id=calloc(1,sizeof(*id));if(!id) return NULL;
 id->token=next_token++;id->generation=q->generation;
 id->ce=ce;id->qp=qp;id->cq=cq;id->context=q->context;id->qp_num=q->number;
 id->spec=*spec;id->state=NPR_ID_PREPARED;
 id->hash_next=buckets[id->token%ID_BUCKETS];buckets[id->token%ID_BUCKETS]=id;
 id->next=ids;if(ids)ids->prev=id;ids=id;live_count++;return id;
}
void npr_identity_accept(struct npr_identity *id)
{ assert(id&&id->state==NPR_ID_PREPARED);id->state=NPR_ID_ACCEPTED;
 if(!id->spec.caller_driven)id->autonomous_held=npr_progress_cq_autonomous_begin(id->cq); }
static void cleanup_remove(struct npr_identity *id)
{
 if(!id->cleanup_queued)return;
 if(id->cleanup_prev)id->cleanup_prev->cleanup_next=id->cleanup_next;else cleanup_first=id->cleanup_next;
 if(id->cleanup_next)id->cleanup_next->cleanup_prev=id->cleanup_prev;else cleanup_last=id->cleanup_prev;
 id->cleanup_next=id->cleanup_prev=NULL;id->cleanup_queued=0;
}
void npr_identity_cleanup_claim(struct npr_identity *id)
{
 assert(id&&(id->state==NPR_ID_CLEANUP||id->state==NPR_ID_CANCELED));
 cleanup_remove(id);id->processing=1;
}
void npr_identity_cleanup_retry(struct npr_identity *id)
{
 assert(id&&(id->state==NPR_ID_CLEANUP||id->state==NPR_ID_CANCELED));
 id->processing=0;
 if(id->cleanup_queued)return;
 id->cleanup_prev=cleanup_last;id->cleanup_next=NULL;id->cleanup_queued=1;
 if(cleanup_last)cleanup_last->cleanup_next=id;else cleanup_first=id;
 cleanup_last=id;
}
void npr_identity_retire(struct npr_identity *id)
{
 struct npr_identity **p;
 assert(id&&!id->spec.resource);
 if(id->autonomous_held){npr_progress_cq_autonomous_end(id->cq);id->autonomous_held=0;}
 for(p=&buckets[id->token%ID_BUCKETS];*p&&*p!=id;p=&(*p)->hash_next) {}
 assert(*p==id);*p=id->hash_next;
 cleanup_remove(id);
 if(id->prev)id->prev->next=id->next;else {assert(ids==id);ids=id->next;}
 if(id->next)id->next->prev=id->prev;
 live_count--;
 struct npr_rdv_owner *data=id->spec.rdv_owner;
 void (*done)(struct npr_rdv_owner *,const struct ibv_wc *)=id->spec.rdv_done;
 struct ibv_wc wc=id->wc;
 if(id->state==NPR_ID_CANCELED&&wc.status==IBV_WC_SUCCESS)wc.status=IBV_WC_WR_FLUSH_ERR;
 void (*internal_done)(void *,const struct ibv_wc *)=id->spec.internal_done;
 void *internal_owner=id->spec.owner;
 free(id);
 if(internal_done)internal_done(internal_owner,&wc);
 /* Physical resource cleanup has finished on every path, including a
  * rejected post retained for UNPIN retry. Notify its source exactly once. */
 if(data){assert(done);done(data,&wc);}
}
void npr_identity_abort(struct npr_identity *id)
{
 assert(id&&id->state==NPR_ID_PREPARED);
 id->state=NPR_ID_CANCELED;id->spec.order=NULL;npr_identity_cleanup_claim(id);
 if(id->spec.rdv_owner)id->wc.status=IBV_WC_GENERAL_ERR;
 if(id->spec.resource && id->spec.release && id->spec.release(id->spec.resource)>0) {npr_identity_cleanup_retry(id);return;}
 id->spec.resource=NULL;npr_identity_retire(id);
}
struct npr_identity *npr_identity_resolve(struct npr_ctx_entry *ce,struct ibv_cq *cq,
 const struct ibv_wc *wc)
{
 struct npr_identity *id;
 struct npr_qp_identity_reservation *q;
 for(id=buckets[wc->wr_id%ID_BUCKETS];id;id=id->hash_next) if(id->token==wc->wr_id) break;
 if(!id||id->state!=NPR_ID_ACCEPTED||id->ce!=ce||id->cq!=cq||id->qp_num!=wc->qp_num) return NULL;
 for(q=qps;q;q=q->next) if(q->qp==id->qp) break;
 if(!q||q->generation!=id->generation||q->context!=id->context||q->number!=id->qp_num) return NULL;
 id->state=NPR_ID_CLAIMED;return id;
}
struct npr_identity *npr_identity_pending(struct npr_ctx_entry *ce)
{
 /* Scan only ready owners, never posted receives or accepted DMA. Matching
  * contexts keep FIFO service; retries append after other ready owners. */
 for(struct npr_identity *id=cleanup_first;id;id=id->cleanup_next)if(id->ce==ce){
  assert(!id->processing);return id;
 }
 return NULL;
}

struct npr_identity *npr_identity_for_context(struct npr_ctx_entry *ce)
{
 struct npr_identity *id;
 for(id=ids;id;id=id->next) if(id->ce==ce&&!id->processing) return id;
 return NULL;
}
struct npr_identity *npr_identity_for_qp(struct ibv_qp *qp)
{
 struct npr_identity *id;
 for(id=ids;id;id=id->next) if(id->qp==qp&&!id->processing) return id;
 return NULL;
}
void npr_identity_forget_qp(struct ibv_qp *qp)
{
 struct npr_qp_identity_reservation **p,*q;
 for(p=&qps;(q=*p);p=&q->next) if(q->qp==qp) {*p=q->next;free(q);return;}
}
unsigned npr_identity_count(void) {return live_count;}

void npr_identity_forget_context(struct ibv_context *context)
{
 struct npr_qp_identity_reservation **p=&qps,*q;
 while((q=*p)) {
  if(q->context==context) {*p=q->next;free(q);}else p=&q->next;
 }
}
int npr_identity_has_cq(struct ibv_cq *cq)
{
 struct npr_identity *id;
 for(id=ids;id;id=id->next) if(id->cq==cq) return 1;
 return 0;
}

unsigned npr_identity_qp_count(struct ibv_qp *qp)
{
 unsigned n=0;struct npr_identity *id;struct npr_qp_identity_reservation *q;
 for(q=qps;q;q=q->next) if(q->qp==qp) break;
 if(!q) return 0;
 for(id=ids;id;id=id->next) if(id->qp==qp&&id->generation==q->generation) n++;
 return n;
}

void npr_identity_detach_qp(struct ibv_qp *qp)
{
 struct npr_identity *id;
 for(id=ids;id;id=id->next) if(id->qp==qp) id->qp=NULL;
 npr_identity_forget_qp(qp);
}

uint64_t npr_identity_qp_generation(struct ibv_qp *qp)
{
 struct npr_qp_identity_reservation *q;
 if(!qp) {errno=EINVAL;return 0;}
 q=qp_identity(qp);return q?q->generation:0;
}

uint64_t npr_identity_qp_known_generation(struct ibv_qp *qp)
{
 struct npr_qp_identity_reservation *q;
 for(q=qps;q;q=q->next) if(q->qp==qp) return q->generation;
 return 0;
}
struct npr_identity *npr_identity_for_qp_generation(struct ibv_qp *qp,uint64_t generation)
{
 struct npr_identity *id;
 for(id=ids;id;id=id->next) if(id->qp==qp&&id->generation==generation&&!id->processing) return id;
 return NULL;
}
void npr_identity_detach_qp_generation(struct ibv_qp *qp,uint64_t generation)
{
 struct npr_identity *id;struct npr_qp_identity_reservation **p,*q;
 for(id=ids;id;id=id->next) if(id->qp==qp&&id->generation==generation) id->qp=NULL;
 for(p=&qps;(q=*p);p=&q->next) if(q->qp==qp&&q->generation==generation) {*p=q->next;free(q);break;}
}

#if defined(NPRDMA_TEST_INJECT) && defined(NPR_PROGRESS_INTEGRATED)
#include "npr_inject.h"
#include "npr_progress.h"
int npr_test_native_qp_snapshot(struct ibv_qp *qp,struct npr_test_native_qp *out)
{
 if(!qp||!out)return EINVAL;
 npr_progress_lock();uint64_t generation=npr_identity_qp_known_generation(qp);
 if(!generation){npr_progress_unlock();return ENOENT;}
 *out=(struct npr_test_native_qp){.abi=NPR_TEST_NATIVE_ABI,.size=sizeof(*out),.generation=generation};
 for(struct npr_identity *id=ids;id;id=id->next)if(id->qp==qp&&id->generation==generation){
  switch(id->state){
  case NPR_ID_PREPARED:out->prepared++;break;
  case NPR_ID_ACCEPTED:out->accepted++;break;
  case NPR_ID_CLAIMED:out->claimed++;break;
  case NPR_ID_CLEANUP:out->cleanup++;if(id->wc.status==IBV_WC_SUCCESS)out->success_cleanup++;break;
  case NPR_ID_CANCELED:out->canceled++;break;
  }
  out->resources+=!!id->spec.resource;out->processing+=!!id->processing;
 }
 npr_progress_unlock();return 0;
}
#endif
