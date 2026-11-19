/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "control_err.h"
#include "endpoint_registry.h"

CRT_INTERNAL void creg_init(struct creg_registry *reg)
{
	memset(reg, 0, sizeof(*reg));
}

static int creg_acquire(struct creg_registry *reg, enum creg_lease_view view,
			uint32_t key, uint64_t va, uint64_t len,
			uint64_t entry_id, uint64_t *lease_id)
{
	uint32_t i;

	if (reg->fail_closed)
		return -EPROTO;
	for (i = 0; i < CONTROL_LEASE_CAP; i++) {
		struct creg_lease *l = &reg->lease[i];

		if (l->taken)
			continue;
		memset(l, 0, sizeof(*l));
		reg->next_id++;
		l->id = reg->next_id;
		l->state = CREG_LEASE_ACTIVE;
		l->taken = 1;
		l->view = (uint8_t)view;
		l->entry_id = entry_id;
		l->key = key;
		l->va = va;
		l->len = len;
		reg->active++;
		*lease_id = l->id;
		return 0;
	}
	return -EBUSY;
}

CRT_INTERNAL int creg_owner_export_acquire(struct creg_registry *reg,
					    uint32_t rkey, uint64_t entry_id,
					    uint64_t *lease_id)
{
	if (!reg || !lease_id)
		return -EINVAL;
	if (rkey == 0)
		return -EINVAL;
	return creg_acquire(reg, CREG_LEASE_OWNER_EXPORT, rkey, 0, 0,
			    entry_id, lease_id);
}

CRT_INTERNAL int creg_initiator_endpoint_acquire(struct creg_registry *reg,
						  uint64_t va, uint64_t len,
						  uint64_t entry_id,
						  uint64_t *lease_id)
{
	if (!reg || !lease_id)
		return -EINVAL;
	if (len < 1)
		return -EINVAL;
	return creg_acquire(reg, CREG_LEASE_INITIATOR_ENDPOINT, 0, va, len,
			    entry_id, lease_id);
}

CRT_INTERNAL int creg_lease_release_entry(struct creg_registry *reg,
					   uint64_t lease_id,
					   uint64_t *entry_id_out)
{
	uint32_t i;

	if (!reg)
		return -EINVAL;
	if (reg->fail_closed)
		return -EPROTO;
	if (lease_id == 0)
		return -EINVAL;
	for (i = 0; i < CONTROL_LEASE_CAP; i++) {
		struct creg_lease *l = &reg->lease[i];

		if (!l->taken || l->id != lease_id)
			continue;
		if (l->state != CREG_LEASE_ACTIVE)
			return crt_violation(&reg->fail_closed,
					      &reg->violations);
		if (entry_id_out)
			*entry_id_out = l->entry_id;
		l->state = CREG_LEASE_FREE;
		l->taken = 0;
		l->id = 0;
		l->entry_id = 0;
		reg->active--;
		return 0;
	}
	return crt_violation(&reg->fail_closed, &reg->violations);
}

CRT_INTERNAL int creg_lease_release(struct creg_registry *reg,
				     uint64_t lease_id)
{
	return creg_lease_release_entry(reg, lease_id, NULL);
}

CRT_INTERNAL uint32_t creg_active_count(const struct creg_registry *reg,
					 enum creg_lease_view view)
{
	uint32_t i, n = 0;

	if (!reg)
		return 0;
	for (i = 0; i < CONTROL_LEASE_CAP; i++)
		if (reg->lease[i].taken && reg->lease[i].view == (uint8_t)view)
			n++;
	return n;
}

enum creg_kind {
	CREG_K_LOCAL_MR = 0,
	CREG_K_OWNER_EXPORT,
};

struct creg_entry {
	uint8_t  taken;
	uint8_t  kind;
	uint8_t  state;
	uint64_t id;
	uint64_t va, len;
	uint32_t rkey;
	uint32_t wkey;
	uint32_t app_rkey;
	uint32_t app_access;
	uint32_t v_rkey;
	uint64_t v_addr;
	int32_t  mr_id;
	uint32_t lkey;
	uint32_t leases;
};

struct creg_singleton {
	pthread_mutex_t mu;
	pthread_cond_t  cv;
	int             cv_ready;
	struct creg_registry tok;
	struct creg_entry ent[CONTROL_REG_ENTRY_CAP];
	uint64_t next_entry_id;
	uint32_t ent_used;
	int      fail_closed;
	long     violations;
};

static struct creg_singleton creg_g = {
	.mu = PTHREAD_MUTEX_INITIALIZER,
};

static void creg_cond_setup(void)
{
	pthread_condattr_t ca;

	if (pthread_condattr_init(&ca) != 0)
		goto fail;
	if (pthread_condattr_setclock(&ca, CLOCK_MONOTONIC) != 0) {
		pthread_condattr_destroy(&ca);
		goto fail;
	}
	if (pthread_cond_init(&creg_g.cv, &ca) != 0) {
		pthread_condattr_destroy(&ca);
		goto fail;
	}
	pthread_condattr_destroy(&ca);
	creg_g.cv_ready = 1;
	return;
fail:
	creg_g.cv_ready = 0;
}

static int creg_lock(void)
{
	static pthread_once_t once = PTHREAD_ONCE_INIT;

	pthread_once(&once, creg_cond_setup);
	if (pthread_mutex_lock(&creg_g.mu) != 0)
		return -1;
	return 0;
}

static int creg_evio(void)
{
	creg_g.fail_closed = 1;
	creg_g.violations++;
	return -EPROTO;
}

static struct creg_entry *creg_ent_alloc_locked(void)
{
	uint32_t i;

	if (creg_g.fail_closed)
		return NULL;
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (e->taken)
			continue;
		memset(e, 0, sizeof(*e));
		e->taken = 1;
		e->state = CREG_ES_ACTIVE;
		creg_g.next_entry_id++;
		e->id = creg_g.next_entry_id;
		creg_g.ent_used++;
		return e;
	}
	return NULL;
}

static void creg_ent_free_locked(struct creg_entry *e)
{
	e->taken = 0;
	creg_g.ent_used--;
}

static struct creg_entry *creg_ent_by_id_locked(uint64_t id)
{
	uint32_t i;

	if (!id)
		return NULL;
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (e->taken && e->id == id)
			return e;
	}
	return NULL;
}

static void creg_view_fill_locked(const struct creg_entry *e,
				  struct creg_owner_view *v)
{
	v->app_rkey = e->app_rkey;
	v->app_access = e->app_access;
	v->data_rkey = e->rkey;
	v->write_rkey = e->wkey;
	v->v_rkey = e->v_rkey;
	v->addr = e->va;
	v->len = e->len;
	v->v_addr = e->v_addr;
	v->mr_id = e->mr_id;
	v->lkey = e->lkey;
	v->entry_id = e->id;
}

CRT_INTERNAL int creg_local_mr_publish(uint64_t va, uint64_t len,
					uint32_t rkey)
{
	struct creg_entry *e;

	if (!va || !len || !rkey)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (creg_g.fail_closed) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}
	e = creg_ent_alloc_locked();
	if (!e) {
		pthread_mutex_unlock(&creg_g.mu);
		return -ENOSPC;
	}
	e->kind = CREG_K_LOCAL_MR;
	e->va = va;
	e->len = len;
	e->rkey = rkey;
	pthread_mutex_unlock(&creg_g.mu);
	return 0;
}

CRT_INTERNAL int creg_owner_export_publish(const struct creg_owner_export *m,
					    int *merge_kind)
{
	struct creg_entry *e;
	int mk = 0;

	if (!m || (!m->data_rkey && !m->write_rkey))
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (creg_g.fail_closed) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}
	if (!m->data_rkey && m->write_rkey) {
		uint32_t i;

		for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
			struct creg_entry *x = &creg_g.ent[i];

			if (!x->taken || x->kind != CREG_K_OWNER_EXPORT ||
			    x->state != CREG_ES_ACTIVE)
				continue;
			if (x->rkey && !x->wkey &&
			    x->va == m->addr && x->len == m->len &&
			    x->app_rkey == m->app_rkey && x->app_access == m->app_access) {
				x->wkey = m->write_rkey;
				mk = 1;
				e = x;
				goto out;
			}
		}
	}
	if (m->data_rkey && !m->write_rkey) {
		uint32_t i;

		for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
			struct creg_entry *x = &creg_g.ent[i];

			if (!x->taken || x->kind != CREG_K_OWNER_EXPORT ||
			    x->state != CREG_ES_ACTIVE)
				continue;
			if (!x->rkey && x->wkey &&
			    x->va == m->addr && x->len == m->len &&
			    x->app_rkey == m->app_rkey && x->app_access == m->app_access) {
				x->rkey   = m->data_rkey;
				x->v_rkey = m->v_rkey;
				x->v_addr = m->v_addr;
				x->mr_id  = m->mr_id;
				x->lkey   = m->lkey;
				mk = 2;
				e = x;
				goto out;
			}
		}
	}
	{
		uint32_t i;

		for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
			struct creg_entry *x = &creg_g.ent[i];

			if (!x->taken || x->kind != CREG_K_OWNER_EXPORT ||
			    x->state != CREG_ES_ACTIVE)
				continue;
			if ((m->data_rkey && x->rkey == m->data_rkey) ||
			    (m->write_rkey && x->wkey == m->write_rkey)) {
				/* An alias/access refresh must not leave the old application's
				 * permissions attached to a reused private key. */
				if (x->rkey == m->data_rkey && x->wkey == m->write_rkey &&
				    x->va == m->addr && x->len == m->len && !x->leases &&
				    (x->app_rkey != m->app_rkey || x->app_access != m->app_access)) {
					x->app_rkey = m->app_rkey;
					x->app_access = m->app_access;
					e = x;
					goto out;
				}
				int rc = creg_evio();

				pthread_mutex_unlock(&creg_g.mu);
				return rc;
			}
		}
	}
	e = creg_ent_alloc_locked();
	if (!e) {
		pthread_mutex_unlock(&creg_g.mu);
		return -ENOSPC;
	}
	e->kind = CREG_K_OWNER_EXPORT;
	e->va = m->addr;
	e->len = m->len;
	e->app_rkey = m->app_rkey;
	e->app_access = m->app_access;
	e->rkey = m->data_rkey;
	e->wkey = m->write_rkey;
	e->v_rkey = m->v_rkey;
	e->v_addr = m->v_addr;
	e->mr_id = m->mr_id;
	e->lkey = m->lkey;
out:
	if (merge_kind)
		*merge_kind = mk;
	pthread_mutex_unlock(&creg_g.mu);
	return 0;
}

CRT_INTERNAL int creg_owner_acquire(uint32_t rkey,
				     struct creg_owner_view *v,
				     uint64_t *lease)
{
	struct creg_entry *hit = NULL;
	uint32_t i;
	int rc;

	if (!rkey || !v || !lease)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (creg_g.fail_closed) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (!e->taken || e->kind != CREG_K_OWNER_EXPORT ||
		    e->state != CREG_ES_ACTIVE)
			continue;
		if (e->app_rkey == rkey || e->rkey == rkey || e->wkey == rkey) {
			hit = e;
			break;
		}
	}
	if (!hit) {
		int rc = -ENOENT;

		for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
			struct creg_entry *e = &creg_g.ent[i];

			if (!e->taken || e->kind != CREG_K_OWNER_EXPORT ||
			    e->state == CREG_ES_ACTIVE)
				continue;
			if (e->app_rkey == rkey || e->rkey == rkey || e->wkey == rkey) {
				rc = -ESHUTDOWN;
				break;
			}
		}
		pthread_mutex_unlock(&creg_g.mu);
		return rc;
	}
	rc = creg_owner_export_acquire(&creg_g.tok, rkey, hit->id, lease);
	if (rc == 0) {
		hit->leases++;
		creg_view_fill_locked(hit, v);
	}
	pthread_mutex_unlock(&creg_g.mu);
	return rc;
}

CRT_INTERNAL int creg_owner_peek(uint32_t rkey, struct creg_owner_view *v)
{
	struct creg_entry *hit = NULL;
	uint32_t i;

	if (!rkey || !v)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (creg_g.fail_closed) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (!e->taken || e->kind != CREG_K_OWNER_EXPORT ||
		    e->state != CREG_ES_ACTIVE)
			continue;
		if (e->app_rkey == rkey || e->rkey == rkey || e->wkey == rkey) {
			hit = e;
			break;
		}
	}
	if (!hit) {
		pthread_mutex_unlock(&creg_g.mu);
		return -ENOENT;
	}
	creg_view_fill_locked(hit, v);
	pthread_mutex_unlock(&creg_g.mu);
	return 0;
}

CRT_INTERNAL int creg_initiator_acquire(uint64_t va, uint64_t len,
					 struct creg_initiator_view *v,
					 uint64_t *lease)
{
	struct creg_entry *hit = NULL;
	uint32_t i;
	int rc;

	if (!va || !len || !v || !lease)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (creg_g.fail_closed) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}

	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (!e->taken || e->kind != CREG_K_LOCAL_MR ||
		    e->state != CREG_ES_ACTIVE)
			continue;
		if (va >= e->va && va + len <= e->va + e->len) {
			hit = e;
			break;
		}
	}
	if (!hit) {
		int rc = -ENOENT;

		for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
			struct creg_entry *e = &creg_g.ent[i];

			if (!e->taken || e->kind != CREG_K_LOCAL_MR ||
			    e->state == CREG_ES_ACTIVE)
				continue;
			if (va >= e->va && va + len <= e->va + e->len) {
				rc = -ESHUTDOWN;
				break;
			}
		}
		pthread_mutex_unlock(&creg_g.mu);
		return rc;
	}
	rc = creg_initiator_endpoint_acquire(&creg_g.tok, va, len, hit->id,
					     lease);
	if (rc == 0) {
		hit->leases++;
		v->rkey = hit->rkey;
		v->va = hit->va;
		v->len = hit->len;
		v->entry_id = hit->id;
	}
	pthread_mutex_unlock(&creg_g.mu);
	return rc;
}

CRT_INTERNAL int creg_lease_put(uint64_t lease)
{
	uint64_t entry_id = 0;
	int rc;

	if (creg_lock())
		return -EPROTO;
	rc = creg_lease_release_entry(&creg_g.tok, lease, &entry_id);
	if (rc == 0 && entry_id) {
		struct creg_entry *e = creg_ent_by_id_locked(entry_id);

		if (!e) {
			rc = creg_evio();
		} else if (e->leases == 0) {
			rc = creg_evio();
		} else {
			e->leases--;
			pthread_cond_broadcast(&creg_g.cv);
		}
	}
	pthread_mutex_unlock(&creg_g.mu);
	return rc;
}

CRT_INTERNAL int creg_mr_close(uint32_t key,uint64_t va,uint64_t len,struct creg_mr_retirement *out)
{
 if(!key||!va||!len||!out)return -EINVAL;
 if(creg_lock())return -EPROTO;
 if(creg_g.fail_closed){pthread_mutex_unlock(&creg_g.mu);return -EPROTO;}
 memset(out,0,sizeof(*out));
 for(unsigned i=0;i<CONTROL_REG_ENTRY_CAP;i++){
  struct creg_entry *e=&creg_g.ent[i];
  if(!e->taken||e->state!=CREG_ES_ACTIVE||e->va!=va||e->len!=len)continue;
  uint64_t *id=NULL;
  if(e->kind==CREG_K_LOCAL_MR&&e->rkey==key)id=&out->local_id;
  if(e->kind==CREG_K_OWNER_EXPORT&&e->app_rkey==key)id=&out->export_id;
  if(id){if(*id){pthread_mutex_unlock(&creg_g.mu);return -EPROTO;}*id=e->id;}
 }
 struct creg_entry *e=creg_ent_by_id_locked(out->local_id);if(e)e->state=CREG_ES_CLOSING;
 e=creg_ent_by_id_locked(out->export_id);if(e)e->state=CREG_ES_CLOSING;
 pthread_mutex_unlock(&creg_g.mu);return 0;
}
CRT_INTERNAL int creg_mr_drain(const struct creg_mr_retirement *r,uint32_t timeout_ms)
{
 if(!r)return -EINVAL;
 if(creg_lock())return -EPROTO;
 struct timespec until;int rc=0;
 if(clock_gettime(CLOCK_MONOTONIC,&until)){pthread_mutex_unlock(&creg_g.mu);return -EPROTO;}
 until.tv_sec+=timeout_ms/1000u;until.tv_nsec+=(long)(timeout_ms%1000u)*1000000L;
 if(until.tv_nsec>=1000000000L){until.tv_sec++;until.tv_nsec-=1000000000L;}
 for(;;){
  struct creg_entry *local=creg_ent_by_id_locked(r->local_id),*exp=creg_ent_by_id_locked(r->export_id);
  if((local&&local->state!=CREG_ES_CLOSING)||(exp&&exp->state!=CREG_ES_CLOSING)){rc=-EPROTO;break;}
  if((!local||!local->leases)&&(!exp||!exp->leases))break;
  if(!timeout_ms||!creg_g.cv_ready){rc=-EBUSY;break;}
  int wait=pthread_cond_timedwait(&creg_g.cv,&creg_g.mu,&until);
  if(wait){rc=wait==ETIMEDOUT?-EBUSY:-EPROTO;break;}
 }
 pthread_mutex_unlock(&creg_g.mu);return rc;
}
CRT_INTERNAL int creg_mr_reopen(const struct creg_mr_retirement *r)
{
 if(!r)return -EINVAL;
 if(creg_lock())return -EPROTO;
 uint64_t ids[]={r->local_id,r->export_id};int rc=0;
 for(unsigned i=0;i<2;i++){struct creg_entry *e=creg_ent_by_id_locked(ids[i]);if(ids[i]&&(!e||e->state!=CREG_ES_CLOSING)){rc=-ESTALE;break;}}
 if(!rc)for(unsigned i=0;i<2;i++){struct creg_entry *e=creg_ent_by_id_locked(ids[i]);if(e)e->state=CREG_ES_ACTIVE;}
 pthread_mutex_unlock(&creg_g.mu);return rc;
}
CRT_INTERNAL int creg_mr_reclaim(struct creg_mr_retirement *r)
{
 if(!r)return -EINVAL;
 if(creg_lock())return -EPROTO;
 uint64_t ids[]={r->local_id,r->export_id};int rc=0;
 for(unsigned i=0;i<2;i++){
  struct creg_entry *e=creg_ent_by_id_locked(ids[i]);
  if(e&&(e->state!=CREG_ES_CLOSING||e->leases)){rc=-EBUSY;break;}
 }
 if(!rc){for(unsigned i=0;i<2;i++){struct creg_entry *e=creg_ent_by_id_locked(ids[i]);if(e)creg_ent_free_locked(e);}memset(r,0,sizeof(*r));}
 pthread_mutex_unlock(&creg_g.mu);return rc;
}

CRT_INTERNAL int creg_region_close(uint64_t va, uint64_t len)
{
	uint32_t i;
	int seen = 0;

	if (!va || !len)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (creg_g.fail_closed) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (!e->taken || e->va != va || e->len != len)
			continue;
		seen = 1;
		if (e->state == CREG_ES_ACTIVE)
			e->state = CREG_ES_CLOSING;
	}
	pthread_mutex_unlock(&creg_g.mu);
	return seen ? 0 : -ENOENT;
}

CRT_INTERNAL int creg_region_drain(uint64_t va, uint64_t len,
				    uint32_t timeout_ms)
{
	struct timespec dl;
	int rc = 0;

	if (!va || !len)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (clock_gettime(CLOCK_MONOTONIC, &dl)) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}
	dl.tv_sec  += timeout_ms / 1000u;
	dl.tv_nsec += (long)(timeout_ms % 1000u) * 1000000L;
	if (dl.tv_nsec >= 1000000000L) {
		dl.tv_sec++;
		dl.tv_nsec -= 1000000000L;
	}
	for (;;) {
		uint32_t i, outstanding = 0;
		int closing = 0, active = 0;

		for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
			struct creg_entry *e = &creg_g.ent[i];

			if (!e->taken || e->va != va || e->len != len)
				continue;
			if (e->state == CREG_ES_ACTIVE)
				active++;
			else {
				closing++;
				outstanding += e->leases;
			}
		}
		if (!closing && !active) {
			rc = 0;
			break;
		}
		if (active && !closing) {
			rc = -ENOENT;
			break;
		}
		if (outstanding == 0) {
			rc = 0;
			break;
		}

		if (!creg_g.cv_ready) {
			rc = -EPROTO;
			break;
		}
		if (pthread_cond_timedwait(&creg_g.cv, &creg_g.mu, &dl) ==
		    ETIMEDOUT) {
			rc = -ETIMEDOUT;
			break;
		}
	}
	pthread_mutex_unlock(&creg_g.mu);
	return rc;
}

CRT_INTERNAL int creg_region_reclaim(uint64_t va, uint64_t len)
{
	uint32_t i;
	int rc = 0;

	if (!va || !len)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (!e->taken || e->va != va || e->len != len)
			continue;
		if (e->state == CREG_ES_ACTIVE) {
			rc = creg_evio();
			break;
		}
		if (e->leases) {
			rc = creg_evio();
			break;
		}
		creg_ent_free_locked(e);
	}
	pthread_mutex_unlock(&creg_g.mu);
	return rc;
}

static int creg_export_finish(uint64_t entry_id, uint32_t timeout_ms)
{
	uint64_t va = 0, len = 0;
	uint32_t i;
	int rc;

	if (creg_lock())
		return -EPROTO;
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (e->taken && e->id == entry_id) {
			va = e->va;
			len = e->len;
			break;
		}
	}
	pthread_mutex_unlock(&creg_g.mu);
	if (!va)
		return 0;
	rc = creg_region_drain(va, len, timeout_ms);
	if (rc)
		return rc;
	if (creg_lock())
		return -EPROTO;
	{
		struct creg_entry *e = creg_ent_by_id_locked(entry_id);

		if (e) {
			if (e->state == CREG_ES_ACTIVE || e->leases) {
				rc = creg_evio();
			} else {
				creg_ent_free_locked(e);
				rc = 0;
			}
		} else {
			rc = 0;
		}
	}
	pthread_mutex_unlock(&creg_g.mu);
	return rc;
}

CRT_INTERNAL int creg_owner_export_close(uint32_t key, uint32_t timeout_ms)
{
	uint64_t entry_id = 0;
	uint32_t i;

	if (!key)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (creg_g.fail_closed) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (!e->taken || e->kind != CREG_K_OWNER_EXPORT ||
		    e->state != CREG_ES_ACTIVE)
			continue;
		if (e->app_rkey == key || e->rkey == key || e->wkey == key) {
			e->state = CREG_ES_CLOSING;
			entry_id = e->id;
			break;
		}
	}
	pthread_mutex_unlock(&creg_g.mu);
	if (!entry_id)
		return -ENOENT;
	return creg_export_finish(entry_id, timeout_ms);
}

CRT_INTERNAL int creg_owner_export_unpublish_wkey(uint32_t wkey,
						   uint32_t timeout_ms)
{
	uint64_t entry_id = 0;
	int standalone = 0;
	uint32_t i;
	int rc;

	if (!wkey)
		return -EINVAL;
	if (creg_lock())
		return -EPROTO;
	if (creg_g.fail_closed) {
		pthread_mutex_unlock(&creg_g.mu);
		return -EPROTO;
	}
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (!e->taken || e->kind != CREG_K_OWNER_EXPORT ||
		    e->state != CREG_ES_ACTIVE || e->wkey != wkey)
			continue;
		if (e->rkey) {
			e->wkey = 0;
		} else {
			e->state = CREG_ES_CLOSING;
			standalone = 1;
		}
		entry_id = e->id;
		break;
	}
	pthread_mutex_unlock(&creg_g.mu);
	if (!entry_id)
		return -ENOENT;
	if (!standalone)
		return 0;
	rc = creg_export_finish(entry_id, timeout_ms);
	return rc ? rc : 1;
}

CRT_INTERNAL uint32_t creg_owner_snapshot(struct creg_owner_view *out,
					   uint32_t cap, int *truncated)
{
	uint32_t i, n = 0;

	if (truncated)
		*truncated = 0;
	if (!out || !cap)
		return 0;
	if (creg_lock())
		return 0;
	for (i = 0; i < CONTROL_REG_ENTRY_CAP; i++) {
		struct creg_entry *e = &creg_g.ent[i];

		if (!e->taken || e->kind != CREG_K_OWNER_EXPORT ||
		    e->state != CREG_ES_ACTIVE)
			continue;
		if (n == cap) {
			if (truncated)
				*truncated = 1;
			break;
		}
		creg_view_fill_locked(e, &out[n]);
		n++;
	}
	pthread_mutex_unlock(&creg_g.mu);
	return n;
}

CRT_INTERNAL uint32_t creg_entry_count(void)
{
	return creg_g.ent_used;
}

CRT_INTERNAL int creg_fail_closed(void)
{
	return creg_g.fail_closed || creg_g.tok.fail_closed;
}

CRT_INTERNAL long creg_violations(void)
{
	return creg_g.violations + creg_g.tok.violations;
}
