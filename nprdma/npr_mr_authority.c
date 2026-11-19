/* SPDX-License-Identifier: GPL-2.0 */
#include "npr_mr_authority.h"
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <limits.h>
#include <infiniband/verbs.h>
enum mra_state { MRA_PREPARED,MRA_LIVE,MRA_DEREG,MRA_REREG,MRA_INVALID,MRA_DEAD };
struct npr_mra_registration {
 struct npr_mra_registration *next;
 struct npr_mra_spec spec;
 void *handle;
 uint64_t generation;
 uint32_t lkey,rkey;
 size_t leases,uses;
 enum mra_state state;
 unsigned published,mutation,retained_use;
};
static pthread_mutex_t mra_mu=PTHREAD_MUTEX_INITIALIZER;
static struct npr_mra_registration *registrations;
static uint64_t next_generation=1;
static struct npr_mra_stop_guard *stop_guards;
static int blocked(const struct npr_mra_spec *s)
{
 for(struct npr_mra_stop_guard *g=stop_guards;g;g=g->next)
  if(g->context==s->context&&(!g->pd||g->pd==s->pd))return 1;
 return 0;
}
static void reap(struct npr_mra_registration *r)
{
 assert(r->uses<=r->leases);
 if(r->state!=MRA_DEAD||r->leases||r->mutation)return;
 struct npr_mra_registration **p=&registrations;
 while(*p&&*p!=r)p=&(*p)->next;
 assert(*p==r);*p=r->next;free(r);
}
struct npr_mra_registration *npr_mra_reserve(const struct npr_mra_spec *s)
{
 if(!s||!s->context||!s->pd||(s->kind!=NPR_MRA_CPU_NATIVE&&s->kind!=NPR_MRA_CPU_ADOPTED)){errno=EINVAL;return NULL;}
 struct npr_mra_registration *r=calloc(1,sizeof(*r));if(!r)return NULL;
 pthread_mutex_lock(&mra_mu);
 if(blocked(s)){pthread_mutex_unlock(&mra_mu);free(r);errno=EBUSY;return NULL;}
 if(!next_generation){pthread_mutex_unlock(&mra_mu);free(r);errno=EOVERFLOW;return NULL;}
 r->generation=next_generation++;r->spec=*s;r->state=MRA_PREPARED;r->mutation=1;
 r->next=registrations;registrations=r;pthread_mutex_unlock(&mra_mu);return r;
}
void npr_mra_abort(struct npr_mra_registration *r)
{
 if(!r)return;
 pthread_mutex_lock(&mra_mu);assert(!r->published);r->state=MRA_DEAD;r->mutation=0;reap(r);pthread_mutex_unlock(&mra_mu);
}
void npr_mra_reservation_adopted(struct npr_mra_registration *r,void *adopted)
{
 pthread_mutex_lock(&mra_mu);assert(r&&!r->published);
 r->spec.kind=NPR_MRA_CPU_ADOPTED;r->spec.adopted=adopted;
 pthread_mutex_unlock(&mra_mu);
}
void npr_mra_commit(struct npr_mra_registration *r,void *handle,uint32_t lkey,uint32_t rkey)
{
 assert(r&&handle&&!r->published);
 pthread_mutex_lock(&mra_mu);
 r->handle=handle;r->lkey=lkey;r->rkey=rkey;r->published=1;
 if(r->state!=MRA_DEAD)r->state=MRA_LIVE;
 /* A native provider must not return a still-live application handle twice.
  * If it does, no ambiguous record may authorize a bridge DMA. */
 for(struct npr_mra_registration *p=registrations;p;p=p->next)
  if(p!=r&&p->published&&p->handle==handle&&p->state!=MRA_DEAD&&r->state!=MRA_DEAD){p->state=MRA_INVALID;r->state=MRA_INVALID;}
 r->mutation=0;reap(r);pthread_mutex_unlock(&mra_mu);
}
int npr_mra_capture(void *context,void *pd,uint32_t lkey,uint64_t address,uint64_t declared_length,struct npr_mra_capture *out)
{
 if(!out)return EINVAL;
 memset(out,0,sizeof(*out));out->address=address;out->declared_length=declared_length;out->classification=NPR_MRA_UNKNOWN;
 if(!declared_length)return 0;
 pthread_mutex_lock(&mra_mu);
 struct npr_mra_registration *match=NULL;
 for(struct npr_mra_registration *r=registrations;r;r=r->next){
  if(!r->published||r->state==MRA_DEAD||r->spec.context!=context||r->lkey!=lkey)continue;
  if(r->spec.pd!=pd){if(out->classification==NPR_MRA_UNKNOWN)out->classification=NPR_MRA_WRONG_PD;continue;}
  if(match){out->classification=NPR_MRA_UNAVAILABLE;match=NULL;break;}
  match=r;
 }
 int rc=0;
 if(match){
  if(match->state!=MRA_LIVE||blocked(&match->spec)||match->spec.iova_unverified||(match->spec.access&(IBV_ACCESS_ON_DEMAND|IBV_ACCESS_ZERO_BASED)))out->classification=NPR_MRA_UNAVAILABLE;
  else if(match->leases==SIZE_MAX)rc=EOVERFLOW;
  else{match->leases++;out->registration=match;out->generation=match->generation;out->classification=NPR_MRA_KNOWN;}
 }
 pthread_mutex_unlock(&mra_mu);return rc;
}
static int validate_locked(const struct npr_mra_capture *c,uint64_t offset,uint64_t length,enum npr_mra_direction direction,struct npr_mra_view *out)
{
 if(!c||!out||(direction!=NPR_MRA_SOURCE&&direction!=NPR_MRA_SINK))return EINVAL;
 memset(out,0,sizeof(*out));if(!length)return 0;
 if(offset>c->declared_length||length>c->declared_length-offset||offset>UINT64_MAX-c->address)return EACCES;
 struct npr_mra_registration *r=c->registration;int rc=EACCES;
 if(c->classification!=NPR_MRA_KNOWN||!r||r->generation!=c->generation)goto done;
 if(c->claimed){
  if(direction!=(enum npr_mra_direction)c->direction||offset<c->used_offset||offset-c->used_offset>c->used_length||length>c->used_length-(offset-c->used_offset))goto done;
  if(r->state!=MRA_LIVE&&r->state!=MRA_DEREG&&!(r->state==MRA_DEAD&&r->retained_use))goto done;
 }else if(r->state!=MRA_LIVE)goto done;
 uint64_t iova=c->address+offset;
 if(iova<r->spec.iova_base||length>UINT64_MAX-iova)goto done;
 uint64_t displacement=iova-r->spec.iova_base;
 if(displacement>r->spec.length||length>r->spec.length-displacement)goto done;
 if(displacement>UINT64_MAX-r->spec.cpu_base)goto done;
 uint64_t cpu=r->spec.cpu_base+displacement;
 if(length>UINT64_MAX-cpu)goto done;
 if(direction==NPR_MRA_SINK&&!(r->spec.access&IBV_ACCESS_LOCAL_WRITE))goto done;
 *out=(struct npr_mra_view){.context=r->spec.context,.pd=r->spec.pd,.handle=r->handle,.adopted=r->spec.adopted,.generation=r->generation,.cpu_address=cpu,.iova_address=iova,.length=length,.lkey=r->lkey,.rkey=r->rkey,.access=r->spec.access,.kind=r->spec.kind};rc=0;
done:return rc;
}
int npr_mra_validate_used(const struct npr_mra_capture *c,uint64_t offset,uint64_t length,enum npr_mra_direction direction,struct npr_mra_view *out)
{
 pthread_mutex_lock(&mra_mu);int rc=validate_locked(c,offset,length,direction,out);pthread_mutex_unlock(&mra_mu);return rc;
}
int npr_mra_claim_used(struct npr_mra_capture *c,uint64_t offset,uint64_t length,enum npr_mra_direction direction,struct npr_mra_view *out)
{
 pthread_mutex_lock(&mra_mu);int rc=validate_locked(c,offset,length,direction,out);
 if(!rc&&length&&!c->claimed){
  if(c->registration->uses==SIZE_MAX)rc=EOVERFLOW;
  else{c->registration->uses++;c->used_offset=offset;c->used_length=length;c->direction=direction;c->claimed=1;}
 }
 pthread_mutex_unlock(&mra_mu);return rc;
}
int npr_mra_adopted_busy(void *adopted)
{
 int found=0;pthread_mutex_lock(&mra_mu);
 for(struct npr_mra_registration *r=registrations;r;r=r->next)if(r->spec.adopted==adopted&&r->uses){found=1;break;}
 pthread_mutex_unlock(&mra_mu);return found;
}
void npr_mra_release(struct npr_mra_capture *c)
{
 if(!c)return;
 pthread_mutex_lock(&mra_mu);
 struct npr_mra_registration *r=c->registration;
 if(r){assert(r->generation==c->generation&&r->leases);r->leases--;if(c->claimed){assert(r->uses);r->uses--;}reap(r);}
 pthread_mutex_unlock(&mra_mu);memset(c,0,sizeof(*c));
}
static struct npr_mra_registration *find_handle(void *handle)
{
 for(struct npr_mra_registration *r=registrations;r;r=r->next)if(r->published&&r->handle==handle&&r->state!=MRA_DEAD)return r;
 return NULL;
}
int npr_mra_describe(void *handle,struct npr_mra_spec *out)
{
 if(!out)return EINVAL;
 pthread_mutex_lock(&mra_mu);struct npr_mra_registration *r=find_handle(handle);
 int rc=!r?ENOENT:r->state!=MRA_LIVE?EINVAL:0;
 if(!rc)*out=r->spec;
 pthread_mutex_unlock(&mra_mu);return rc;
}
static int begin(void *handle,struct npr_mra_mutation *t,struct npr_mra_registration *replacement)
{
 struct npr_mra_registration *r=find_handle(handle);
 if(!r)return ENOENT;
 if(r->mutation||(replacement&&r->leases)||blocked(&r->spec))return EBUSY;
 if(replacement&&r->state!=MRA_LIVE)return EINVAL;
 t->previous_state=r->state;r->mutation=1;r->state=replacement?MRA_REREG:MRA_DEREG;
 t->original=r;t->replacement=replacement;t->operation=replacement?2:1;return 0;
}
int npr_mra_borrow_handle(void *handle,struct npr_mra_capture *out,struct npr_mra_spec *spec)
{
 if(!out||!spec)return EINVAL;
 memset(out,0,sizeof(*out));pthread_mutex_lock(&mra_mu);
 struct npr_mra_registration *r=find_handle(handle);
 int rc=!r?ENOENT:r->state!=MRA_LIVE||r->mutation||blocked(&r->spec)?EBUSY:r->leases==SIZE_MAX?EOVERFLOW:0;
 if(!rc){r->leases++;*out=(struct npr_mra_capture){.registration=r,.generation=r->generation,.classification=NPR_MRA_KNOWN};*spec=r->spec;}
 pthread_mutex_unlock(&mra_mu);return rc;
}
int npr_mra_dereg_begin_borrowed(void *handle,const struct npr_mra_capture *capture,struct npr_mra_mutation *t)
{
 if(!capture||!t)return EINVAL;
 memset(t,0,sizeof(*t));pthread_mutex_lock(&mra_mu);
 struct npr_mra_registration *r=find_handle(handle);
 int rc=!r||r!=capture->registration||r->generation!=capture->generation||capture->classification!=NPR_MRA_KNOWN||r->state!=MRA_LIVE?ESTALE:begin(handle,t,NULL);
 pthread_mutex_unlock(&mra_mu);return rc;
}
int npr_mra_dereg_begin(void *handle,struct npr_mra_mutation *t)
{
 if(!t)return EINVAL;
 memset(t,0,sizeof(*t));
 pthread_mutex_lock(&mra_mu);int rc=begin(handle,t,NULL);pthread_mutex_unlock(&mra_mu);return rc;
}
void npr_mra_dereg_finish_closing(struct npr_mra_mutation *t,int result,int irreversible)
{
 assert(t&&t->operation==1&&t->original);
 pthread_mutex_lock(&mra_mu);struct npr_mra_registration *r=t->original;
 if(r->state!=MRA_DEAD){r->state=result?(irreversible?MRA_DEREG:(enum mra_state)t->previous_state):MRA_DEAD;if(!result)r->retained_use=1;}
 r->mutation=0;reap(r);pthread_mutex_unlock(&mra_mu);memset(t,0,sizeof(*t));
}
void npr_mra_dereg_finish(struct npr_mra_mutation *t,int result)
{npr_mra_dereg_finish_closing(t,result,0);}
int npr_mra_rereg_begin(void *handle,const struct npr_mra_spec *proposed,struct npr_mra_mutation *t)
{
 if(!t){errno=EINVAL;return IBV_REREG_MR_ERR_INPUT;}
 memset(t,0,sizeof(*t));struct npr_mra_registration *replacement=npr_mra_reserve(proposed);
 if(!replacement)return IBV_REREG_MR_ERR_INPUT;
 pthread_mutex_lock(&mra_mu);int rc=begin(handle,t,replacement);pthread_mutex_unlock(&mra_mu);
 if(rc){npr_mra_abort(replacement);errno=rc;return IBV_REREG_MR_ERR_INPUT;}return 0;
}
void npr_mra_rereg_finish(struct npr_mra_mutation *t,int result,uint32_t lkey,uint32_t rkey)
{
 assert(t&&t->operation==2&&t->original&&t->replacement);
 pthread_mutex_lock(&mra_mu);struct npr_mra_registration *old=t->original,*fresh=t->replacement;
 if(result==0||result==IBV_REREG_MR_ERR_DO_FORK_OLD){
  fresh->handle=old->handle;fresh->lkey=lkey;fresh->rkey=rkey;fresh->published=1;
  if(old->state==MRA_DEAD||fresh->state==MRA_DEAD)fresh->state=MRA_DEAD;
  else fresh->state=MRA_LIVE;
  old->state=MRA_DEAD;
 }else{
  if(old->state!=MRA_DEAD)old->state=(result==IBV_REREG_MR_ERR_INPUT||result==IBV_REREG_MR_ERR_DONT_FORK_NEW)?(enum mra_state)t->previous_state:MRA_INVALID;
  fresh->state=MRA_DEAD;
 }
 fresh->mutation=0;reap(fresh);
 old->mutation=0;reap(old);pthread_mutex_unlock(&mra_mu);memset(t,0,sizeof(*t));
}
static void stopped(void *identity,int pd)
{
 pthread_mutex_lock(&mra_mu);
 for(struct npr_mra_registration *r=registrations,*next;r;r=next){next=r->next;if((pd?r->spec.pd:r->spec.context)==identity){r->retained_use=0;r->state=MRA_DEAD;reap(r);}}
 pthread_mutex_unlock(&mra_mu);
}
int npr_mra_stop_begin(void *context,void *pd,struct npr_mra_stop_guard *g)
{
 if(!context||!g)return EINVAL;
 memset(g,0,sizeof(*g));pthread_mutex_lock(&mra_mu);
 int rc=0;
 for(struct npr_mra_stop_guard *p=stop_guards;p;p=p->next)
  if(p->context==context&&(!p->pd||!pd||p->pd==pd)){rc=EBUSY;break;}
 for(struct npr_mra_registration *r=registrations;!rc&&r;r=r->next)
  if(r->spec.context==context&&(!pd||r->spec.pd==pd)&&(r->leases||r->mutation))rc=EBUSY;
 if(!rc){g->context=context;g->pd=pd;g->active=1;g->next=stop_guards;stop_guards=g;}
 pthread_mutex_unlock(&mra_mu);return rc;
}
void npr_mra_stop_end(struct npr_mra_stop_guard *g,int success)
{
 assert(g&&g->active);pthread_mutex_lock(&mra_mu);
 if(success)for(struct npr_mra_registration *r=registrations,*next;r;r=next){
  next=r->next;if(r->spec.context==g->context&&(!g->pd||r->spec.pd==g->pd)){r->retained_use=0;r->state=MRA_DEAD;reap(r);}
 }
 struct npr_mra_stop_guard **p=&stop_guards;while(*p&&*p!=g)p=&(*p)->next;
 assert(*p==g);*p=g->next;memset(g,0,sizeof(*g));pthread_mutex_unlock(&mra_mu);
}
void npr_mra_context_stopped(void *context){stopped(context,0);}
void npr_mra_pd_stopped(void *pd){stopped(pd,1);}
static int busy(void *identity,int pd)
{
 int value=0;pthread_mutex_lock(&mra_mu);
 for(struct npr_mra_registration *r=registrations;r;r=r->next)if((pd?r->spec.pd:r->spec.context)==identity&&(r->leases||r->mutation)){value=1;break;}
 pthread_mutex_unlock(&mra_mu);return value;
}
int npr_mra_context_busy(void *context){return busy(context,0);}
int npr_mra_pd_busy(void *pd){return busy(pd,1);}
void npr_mra_get_counts(struct npr_mra_counts *out)
{
 memset(out,0,sizeof(*out));pthread_mutex_lock(&mra_mu);
 for(struct npr_mra_registration *r=registrations;r;r=r->next){out->records++;out->live+=r->state==MRA_LIVE;out->leases+=r->leases;out->mutations+=r->mutation;}
 pthread_mutex_unlock(&mra_mu);
}

int npr_mra_pd_registered(void *pd)
{
 int found=0;pthread_mutex_lock(&mra_mu);
 for(struct npr_mra_registration *r=registrations;r;r=r->next)
  if(r->published&&r->state!=MRA_DEAD&&r->spec.pd==pd){found=1;break;}
 pthread_mutex_unlock(&mra_mu);return found;
}
