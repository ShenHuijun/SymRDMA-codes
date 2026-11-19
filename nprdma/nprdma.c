/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include "npr_progress.h"
#include "npr_sendrecv.h"
#include "npr_identity.h"
#include "npr_rendezvous.h"
#include "npr_mr_authority.h"
#include "npr_qp_connection.h"
#include <limits.h>
#include <time.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <stdarg.h>
#include <pthread.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdint.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <infiniband/verbs.h>
#include "sir.h"
#include "endpoint_registry.h"
#include "npr_inject.h"
#include "nprdma_internal.h"
#include "vtpages.h"

#undef ibv_reg_mr
#undef ibv_reg_mr_iova
#ifndef IBV_ACCESS_ON_DEMAND
#define IBV_ACCESS_ON_DEMAND (1 << 6)
#endif

static unsigned int symrdma_eff_access(unsigned int access)
{
	unsigned int eff = access | NPRDMA_MR_SYMRDMA;

	if ((access & IBV_ACCESS_REMOTE_WRITE) &&
	    !(access & IBV_ACCESS_REMOTE_READ))
		eff |= SYMRDMA_ACCESS_WREG;
	return eff;
}

int sym_fd = -1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static int n_registered = 0;
static void npr_application_pump(void);
static struct ibv_mr *npr_provider_reg_mr_iova2(struct ibv_pd *,void *,size_t,uint64_t,unsigned int);
static __thread unsigned in_mr_provider;
struct ibv_mr *(*g_real_reg_mr_iova2)(struct ibv_pd *, void *, size_t,
                                             uint64_t, unsigned int)=npr_provider_reg_mr_iova2;

struct mr_entry {
 struct ibv_context *context_identity;
 struct ibv_pd *pd_identity;
 void *facade_identity;
 uint32_t app_lkey,app_rkey;
 unsigned retired,closing,export_revoked,retire_registry_failed;
 struct creg_mr_retirement retirement;
	struct ibv_mr *ibv_mr;
	int mr_id;
	uintptr_t va_start;
	size_t len;
	void *version_buf;
	size_t version_buf_len;
	int version_buf_mr_id;
	struct ibv_mr *version_ibv_mr;

	int ioctl_shared;

	/* Private data views preserve the application MR permissions. */
	uint32_t write_key;
	struct ibv_mr *write_ibv_mr;
	struct ibv_mr *read_ibv_mr;
 /* Lazy per-direction owner capabilities, never published as exports. */
 struct ibv_mr *owner_read_ibv_mr,*owner_write_ibv_mr;
 struct ibv_mr *carrier_read_ibv_mr,*carrier_write_ibv_mr;
	unsigned int app_access;
	int orphaned;
	unsigned order_refs;
 unsigned sr_refs;
 unsigned control_exported;

	struct mr_entry *next;
};
static struct mr_entry *mr_list = NULL;

static struct mr_entry *g_memo_lkey;

static struct mr_entry *mr_find_by_lkey(uint32_t lkey)
{
	struct mr_entry *e;

	if (g_memo_lkey && !g_memo_lkey->retired && !g_memo_lkey->closing && g_memo_lkey->ibv_mr &&
	    g_memo_lkey->ibv_mr->lkey == lkey)
		return g_memo_lkey;
	for (e = mr_list; e; e = e->next)
		if (!e->retired && !e->closing && e->ibv_mr && e->ibv_mr->lkey == lkey)
			break;
	g_memo_lkey = e;
	return e;
}

static int npr_mr_owner_prepare(struct mr_entry *m,int sink)
{
 struct ibv_mr **view=sink?&m->owner_write_ibv_mr:&m->owner_read_ibv_mr;
 if(*view)return 0;
 unsigned access=IBV_ACCESS_LOCAL_WRITE|NPRDMA_MR_SYMRDMA|
  (sink?(IBV_ACCESS_REMOTE_WRITE|SYMRDMA_ACCESS_WREG):IBV_ACCESS_REMOTE_READ);
 *view=g_real_reg_mr_iova2(m->pd_identity,(void*)m->va_start,m->len,m->va_start,access);
 return *view?0:(errno?errno:ENOMEM);
}

/* Reverse transfers arrive on the shared SIR QP. Its PD may differ from
 * the application's PD (RDMA-CM applications commonly allocate both). Native
 * local views stay in the application PD; reverse rkeys need service-PD views. */
static int npr_mr_carrier_prepare(struct mr_entry *m,int sink)
{
 struct ibv_mr **view=sink?&m->carrier_write_ibv_mr:&m->carrier_read_ibv_mr;
 if(*view)return 0;
 struct ibv_pd *pd=NULL;
 int rc=sir_carrier_pd(m->context_identity,&pd);
 if(rc){errno=rc;return -1;}
 unsigned access=IBV_ACCESS_LOCAL_WRITE|NPRDMA_MR_SYMRDMA|
  (sink?(IBV_ACCESS_REMOTE_WRITE|SYMRDMA_ACCESS_WREG):IBV_ACCESS_REMOTE_READ);
 *view=g_real_reg_mr_iova2(pd,(void*)m->va_start,m->len,m->va_start,access);
 return *view?0:(errno?errno:ENOMEM);
}

/* The original authority capture protects this registration during the
 * gate-local snapshot and immediate CLOEXEC duplication in the core owner. */
NPRDMA_INTERNAL int npr_rdv_backend_snapshot(const struct npr_mra_view *v,struct npr_rdv_backend_source *out)
{
 if(!v||!out||v->kind!=NPR_MRA_CPU_ADOPTED||!v->generation||!v->length)return EINVAL;
 int rc=ESTALE;pthread_mutex_lock(&lock);
 for(struct mr_entry *m=mr_list;m;m=m->next)if(m==v->adopted){
  if(!m->orphaned&&m->facade_identity==v->handle&&m->context_identity==v->context&&m->pd_identity==v->pd&&
   m->app_lkey==v->lkey&&m->mr_id>=0&&sym_fd>=0&&v->cpu_address>=m->va_start&&
   v->cpu_address-m->va_start<=m->len&&v->length<=m->len-(v->cpu_address-m->va_start)){
   *out=(struct npr_rdv_backend_source){sym_fd,m->mr_id,v->generation};rc=0;
  }
  break;
 }
 pthread_mutex_unlock(&lock);return rc;
}

/* Queued requests hold MR identity without preventing OS paging. */
struct npr_order_lease { struct npr_mra_capture atomic_sink; unsigned n; struct mr_entry *mr[NPR_OP_MAX_SGE + 1]; };
/* A partial teardown still has a real facade, but cannot authorize a new
 * operation. Call under the API gate or MR mutex; retained owners use their
 * already-bound entry instead of this admission lookup. */
static int npr_mr_admission_closing(const struct ibv_pd *pd,uint32_t lkey)
{
 for(struct mr_entry *e=mr_list;e;e=e->next)
  if(!e->retired&&e->closing&&e->ibv_mr&&
     e->ibv_mr->pd==pd&&e->ibv_mr->lkey==lkey)return 1;
 return 0;
}

NPRDMA_INTERNAL int npr_order_lease_acquire(struct ibv_pd *pd,
                                          struct npr_op *op, void **cookie)
{
 struct npr_order_lease *l;
 unsigned i;int error=EACCES;
 if (!cookie || !op || op->num_sge > NPR_OP_MAX_SGE) return EINVAL;
 *cookie = NULL;memset(op->local_mr,0,sizeof(op->local_mr));op->local_bound=0;op->atomic_sink_cpu=0;
 l = calloc(1, sizeof(*l));
 if (!l) return ENOMEM;
 if(op->kind==NPR_OP_ATOMIC&&op->num_sge==1){
  struct npr_mra_view v;
  int rc=npr_mra_capture(pd->context,pd,op->sge[0].lkey,op->sge[0].addr,op->sge[0].length,&l->atomic_sink);
  if(!rc&&!npr_mra_claim_used(&l->atomic_sink,0,8,NPR_MRA_SINK,&v))op->atomic_sink_cpu=v.cpu_address;
 }
 pthread_mutex_lock(&lock);
 for (i = 0; i < op->num_sge; i++) {
  struct mr_entry *m;
  uint64_t off;
  if (op->inline_ || !op->sge[i].length) continue;
  m = mr_find_by_lkey(op->sge[i].lkey);
  if (!m) {
   if(npr_mr_admission_closing(pd,op->sge[i].lkey))goto invalid;
   continue; /* Native MR lifetime follows the verbs caller contract. */
  }
  if(npr_op_has_remote(op)&&!m->control_exported){error=EOPNOTSUPP;goto invalid;}
  if (!m->ibv_mr || m->ibv_mr->pd != pd || op->sge[i].addr < m->va_start) goto invalid;
  off = op->sge[i].addr - m->va_start;
  if (off > m->len || op->sge[i].length > m->len - off) goto invalid;
  if ((npr_op_is_read(op) || op->kind == NPR_OP_ATOMIC) && !(m->app_access & IBV_ACCESS_LOCAL_WRITE)) goto invalid;
  if (m->order_refs == UINT32_MAX) goto invalid;
  int owner_error=npr_mr_owner_prepare(m,npr_op_local_sink(op));
  if(owner_error){error=owner_error;goto invalid;}
  m->order_refs++; l->mr[l->n++] = m;op->local_mr[i]=m;
 }
 pthread_mutex_unlock(&lock);
 *cookie = l;op->local_bound=1;
 return 0;
invalid:
 memset(op->local_mr,0,sizeof(op->local_mr));
 while (l->n) l->mr[--l->n]->order_refs--;
 pthread_mutex_unlock(&lock);
 npr_mra_release(&l->atomic_sink);op->atomic_sink_cpu=0;
 free(l);
 return error;
}
NPRDMA_INTERNAL void npr_order_lease_release(void *cookie)
{
 struct npr_order_lease *l = cookie;
 if (!l) return;
 pthread_mutex_lock(&lock);
 while (l->n) { struct mr_entry *m = l->mr[--l->n]; if (m->order_refs) m->order_refs--; }
 pthread_mutex_unlock(&lock);
 npr_mra_release(&l->atomic_sink);
 free(l);
}

NPRDMA_INTERNAL const struct mr_entry *npr_mr_by_lkey(uint32_t lkey)
{
	return mr_find_by_lkey(lkey);
}

/*
 * Census over the MR that backs a range (mode 0: decide only).
 *
 * The kernel keeps no cursor, so this walks the range in chunks and folds the
 * rows: the newest transition it saw, and how many pages do not serve real
 * bytes. Both are evidence a gate can compare across a window without reading
 * any repair verb's report - the verb says what a caller tried, the census says
 * what the page was.
 */

/* The MR that backs [start, start+len), under the library lock. NULL when the
 * range is not inside a kernel MR this process owns, or the device is not
 * open - the honest answer, not a silent zero. */
static struct mr_entry *census_mr_of(uintptr_t start, size_t len)
{
	struct mr_entry *e;

	if (sym_fd < 0)
		return NULL;
	for (e = mr_list; e; e = e->next) {
		if (e->retired || e->closing || e->mr_id < 0)   /* new callers cannot borrow retired storage */
			continue;
		if (start >= e->va_start && start + len <= e->va_start + e->len)
			return e;
	}
	return NULL;
}

/* One chunk of the census walk: the decide-only ioctl plus the read of its
 * rows. This is the single ioctl path both census faces share - the fold
 * (nprdma_census_scan) and the per-page hand-over (nprdma_census_pages) - so
 * they cannot grow different ideas of what the kernel said. Caller holds the
 * library lock. */
static int census_chunk(const struct mr_entry *e, unsigned long page_idx,
			unsigned long n, struct symrdma_census_page *rows,
			uint64_t *cookie)
{
	struct symrdma_ioc_census req;
	ssize_t got;

	memset(&req, 0, sizeof(req));
	req.abi = SYMRDMA_ABI_VERSION;
	req.mr_id = e->mr_id;
	req.page_idx = page_idx;
	req.npages = n;
	req.mode = 0;
	if (ioctl(sym_fd, SYMRDMA_IOC_CENSUS, &req))
		return -1;
	got = read(sym_fd, rows, n * sizeof(rows[0]));
	if (got != (ssize_t)(n * sizeof(rows[0]))) {
		errno = EPROTO;
		return -1;
	}
	if (cookie)
		*cookie = req.cookie;
	return 0;
}

int nprdma_census_scan(const void *addr, size_t len, struct nprdma_census *out)
{
	struct symrdma_census_page rows[SYMRDMA_CENSUS_MAX];
	uintptr_t start = (uintptr_t)addr;
	struct mr_entry *e;
	uint64_t cookie = 0, max_seq = 0;
	uint32_t pages = 0, not_ok = 0;
	unsigned long first, total, off;

	if (!out || !len) {
		errno = EINVAL;
		return -1;
	}
	pthread_mutex_lock(&lock);
	e = census_mr_of(start, len);
	if (!e) {
		pthread_mutex_unlock(&lock);
		errno = ENOENT;
		return -1;
	}

	first = (start - e->va_start) / SYMRDMA_PAGE_SIZE;
	total = (len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	for (off = 0; off < total; off += SYMRDMA_CENSUS_MAX) {
		unsigned long n = total - off;
		unsigned long i;

		if (n > SYMRDMA_CENSUS_MAX)
			n = SYMRDMA_CENSUS_MAX;
		if (census_chunk(e, first + off, n, rows, &cookie)) {
			pthread_mutex_unlock(&lock);
			return -1;
		}
		for (i = 0; i < n; i++) {
			if (rows[i].cause_seq > max_seq)
				max_seq = rows[i].cause_seq;
			if (rows[i].verdict != SYMRDMA_CV_OK)
				not_ok++;
		}
		pages += (uint32_t)n;
	}
	pthread_mutex_unlock(&lock);

	out->cookie = cookie;
	out->max_cause_seq = max_seq;
	out->pages = pages;
	out->not_ok = not_ok;
	return 0;
}

/*
 * The per-page face of the same census walk. nprdma_census_scan folds the
 * rows into one `not_ok` count, and that fold is the wrong shape for a gate
 * that must tell apart "the page is absent (a fault this system repairs)"
 * from "the page cannot be mapped at all" (UNMAPPABLE / SPECIAL / ERROR):
 * the fold counts both the same way, so a range full of unusable pages reads
 * exactly like a range waiting for its repair - fail-open for the very
 * judgement the census exists to settle. This face hands the verdicts over
 * unmerged, one row per page in the caller's buffer. A gate that reads a
 * verdict it does not recognise as "absent" makes that mistake on its own
 * account; the rows say what the page was, never less.
 *
 * `rows` must hold one slot per page of the range (`max` bounds it); a range
 * larger than the buffer fails with ENOSPC rather than coming back silently
 * truncated. Returns the number of rows filled, or -1 with errno (EINVAL for
 * bad arguments, ENOENT when the range is not inside an owned kernel MR, and
 * the ioctl/read failures as they are).
 */
long nprdma_census_pages(const void *addr, size_t len,
			 struct symrdma_census_page *rows, unsigned long max)
{
	uintptr_t start = (uintptr_t)addr;
	struct mr_entry *e;
	unsigned long first, total, off, filled = 0;

	if (!rows || !max || !len) {
		errno = EINVAL;
		return -1;
	}
	pthread_mutex_lock(&lock);
	e = census_mr_of(start, len);
	if (!e) {
		pthread_mutex_unlock(&lock);
		errno = ENOENT;
		return -1;
	}
	first = (start - e->va_start) / SYMRDMA_PAGE_SIZE;
	total = (len + SYMRDMA_PAGE_SIZE - 1) / SYMRDMA_PAGE_SIZE;
	if (total > max) {
		pthread_mutex_unlock(&lock);
		errno = ENOSPC;
		return -1;
	}
	for (off = 0; off < total; off += SYMRDMA_CENSUS_MAX) {
		unsigned long n = total - off;

		if (n > SYMRDMA_CENSUS_MAX)
			n = SYMRDMA_CENSUS_MAX;
		if (census_chunk(e, first + off, n, rows + filled, NULL)) {
			pthread_mutex_unlock(&lock);
			return -1;
		}
		filled += n;
	}
	pthread_mutex_unlock(&lock);
	return (long)filled;
}

/* Local native two-sided buffers retain MR identity until unpin succeeds. */
int npr_sr_pin_sge(struct ibv_pd *pd,const struct ibv_sge *sg,int recv,const struct mr_entry **out,uint64_t *lease)
{
 struct mr_entry *m;
 if(!sg||!out||!lease){errno=EINVAL;return -1;}*out=NULL;*lease=0;
 if(!sg->length)return 0;
 pthread_mutex_lock(&lock);m=mr_find_by_lkey(sg->lkey);
 if(!m){int closing=npr_mr_admission_closing(pd,sg->lkey);pthread_mutex_unlock(&lock);
  if(closing){errno=EACCES;return -1;}return 0;}
 if(!m->ibv_mr||m->pd_identity!=pd||(recv&&!(m->app_access&IBV_ACCESS_LOCAL_WRITE))||
    sg->addr<m->va_start||sg->addr-m->va_start>m->len||sg->length>m->len-(sg->addr-m->va_start)||m->sr_refs==UINT32_MAX){
  pthread_mutex_unlock(&lock);errno=EACCES;return -1;
 }
 if(npr_mr_owner_prepare(m,recv)){pthread_mutex_unlock(&lock);return -1;}
 /* PIN may yield the API gate; retain identity before dropping the MR lock. */
 m->sr_refs++;pthread_mutex_unlock(&lock);
 /* Local PIN is retained by the MR ref, never by a remote export lease. */
 if(npr_local_pin(m,sg->addr,sg->length))goto fail;
 *out=m;return 1;
fail:{int saved=errno;npr_sr_mr_put(m);errno=saved;return -1;}
}
int npr_sr_mr_get(const struct mr_entry *entry)
{
 struct mr_entry *m=(struct mr_entry *)entry;int rc=EBUSY;
 pthread_mutex_lock(&lock);if(m&&m->sr_refs!=UINT32_MAX){m->sr_refs++;rc=0;}pthread_mutex_unlock(&lock);return rc;
}
void npr_sr_mr_put(const struct mr_entry *entry)
{struct mr_entry *m=(struct mr_entry *)entry;pthread_mutex_lock(&lock);if(m&&m->sr_refs)m->sr_refs--;pthread_mutex_unlock(&lock);}
int npr_sr_unpin(const struct mr_entry *m,uint64_t addr,uint64_t len)
{
 if(npr_fault_unpin_fail()){errno=EAGAIN;return -1;}
 struct symrdma_ioc_pin p={0};int rc,saved;unsigned depth;
 if(!m||!len||sym_fd<0)return -1;
 p.mr_id=m->mr_id;p.va=addr;p.len=len;
 depth=npr_progress_wait_begin();rc=ioctl(sym_fd,SYMRDMA_IOC_UNPIN_PAGES,&p);saved=errno;
 npr_progress_wait_end(depth);errno=saved;return rc?-1:0;
}

NPRDMA_INTERNAL int npr_data_lkey(uint32_t app_lkey, int write, uint32_t *out)
{
 struct mr_entry *e;
 struct ibv_mr *view;
 int rc = -1;
 pthread_mutex_lock(&lock);
 e = mr_find_by_lkey(app_lkey);
 if (e && (!write || (e->app_access & IBV_ACCESS_LOCAL_WRITE))) {
  if(npr_mr_owner_prepare(e,write)){pthread_mutex_unlock(&lock);return -1;}
  view = write ? e->owner_write_ibv_mr : e->owner_read_ibv_mr;
  if (view) { *out = view->lkey; rc = 0; }
 }
 pthread_mutex_unlock(&lock);
 return rc;
}

NPRDMA_INTERNAL int npr_data_rkey(uint32_t app_lkey, int write, uint32_t *out)
{
 struct mr_entry *e;
 struct ibv_mr *view;
 int rc = -1;
 pthread_mutex_lock(&lock);
 e = mr_find_by_lkey(app_lkey);
 if (e && (!write || (e->app_access & IBV_ACCESS_LOCAL_WRITE))) {
  if(npr_mr_carrier_prepare(e,write)){pthread_mutex_unlock(&lock);return -1;}
  view = write ? e->carrier_write_ibv_mr : e->carrier_read_ibv_mr;
  if (view) { *out = view->rkey; rc = 0; }
 }
 pthread_mutex_unlock(&lock);
 return rc;
}

static int npr_data_key_owned(const struct npr_op *op,unsigned i,int write,int remote,uint32_t *out)
{
 if(!op||i>=op->num_sge)return -1;
 const struct mr_entry *m=op->local_mr[i];
 if(!m&&op->local_bound)return -1;
 if(!m)return remote?npr_data_rkey(op->sge[i].lkey,write,out):npr_data_lkey(op->sge[i].lkey,write,out);
 if(remote?npr_mr_carrier_prepare((struct mr_entry*)m,write):npr_mr_owner_prepare((struct mr_entry*)m,write))return -1;
 struct ibv_mr *v=remote?(write?m->carrier_write_ibv_mr:m->carrier_read_ibv_mr):(write?m->owner_write_ibv_mr:m->owner_read_ibv_mr);
 if(!v||(write&&!(m->app_access&IBV_ACCESS_LOCAL_WRITE)))return -1;
 *out=remote?v->rkey:v->lkey;return 0;
}
NPRDMA_INTERNAL int npr_data_lkey_owned(const struct npr_op *op,unsigned i,int write,uint32_t *out)
{return npr_data_key_owned(op,i,write,0,out);}
NPRDMA_INTERNAL int npr_data_rkey_owned(const struct npr_op *op,unsigned i,int write,uint32_t *out)
{return npr_data_key_owned(op,i,write,1,out);}

/* Called only with a stable descriptor and local MR borrows, outside the
 * ordering mutex. A missing asynchronous snapshot is not proof of FOREIGN. */
NPRDMA_INTERNAL int npr_resolve_remote(struct npr_op *op)
{
 struct sir_export exp;
 unsigned depth;
 int rc,saved;
 if(!op) return EINVAL;
 if(!npr_op_has_remote(op)||op->remote_state!=NPR_REMOTE_UNRESOLVED) return 0;
 if(!sir_remote_lookup_cached(op->rkey,&exp)) {
  op->exp=exp;op->remote_state=NPR_REMOTE_FOUND;return 0;
 }
 depth=npr_progress_wait_begin();
 rc=sir_remote_lookup_authoritative(op->rkey,&exp);saved=errno;
 npr_progress_wait_end(depth);errno=saved;
 if(!rc) {op->exp=exp;op->remote_state=NPR_REMOTE_FOUND;return 0;}
 if(saved==ENOENT||saved==ENODEV) {
  memset(&op->exp,0,sizeof(op->exp));op->remote_state=NPR_REMOTE_FOREIGN;return 0;
 }
 return saved?saved:EIO;
}
NPRDMA_INTERNAL int npr_write_key(const struct npr_op *op,uint32_t *out)
{
 struct sir_export exp;
 if(!op||!out) return NPR_WRITE_KEY_NONE;
 if(op->remote_state==NPR_REMOTE_FOREIGN) return NPR_WRITE_KEY_FOREIGN;
 if(op->remote_state==NPR_REMOTE_FOUND) exp=op->exp;
 else if(sir_remote_lookup_cached(op->rkey,&exp)) return NPR_WRITE_KEY_NONE;
 if(!exp.write_rkey||(exp.app_rkey&&!(exp.app_access&IBV_ACCESS_REMOTE_WRITE)))
  return NPR_WRITE_KEY_NONE;
 *out=exp.write_rkey;return NPR_WRITE_KEY_RESOLVED;
}

NPRDMA_INTERNAL int npr_version_read_mr(const struct mr_entry *e, uint64_t va,
					uint32_t *out, unsigned long np)
{
	unsigned long i, page, npages;

	if (!e || !e->version_buf || !e->len)
		return -1;
	if (va < e->va_start)
		return -1;
	/* the window is judged in whole pages *inside* the MR: caller passes the
	 * page span the op touches, so "page + np <= npages" is the exact
	 * condition. Comparing va - va_start + np*PAGE against len over-counts
	 * by (va % PAGE) and rejected every unaligned tail range. */
	npages = (unsigned long)(e->len / SYMRDMA_PAGE_SIZE);
	page = (unsigned long)((va - e->va_start) / SYMRDMA_PAGE_SIZE);
	if (!npages || page >= npages || np > npages - page)
		return -1;
	for (i = 0; i < np; i++)
		out[i] = ((const uint32_t *)e->version_buf)[page + i];
	return 0;
}

/* The kernel's STATS face, for the one observation a user-space verb cannot
 * report itself (a counter is the evidence, not a guess). The transparent
 * library reads the kernel ABI directly. */
static int npr_kernel_stat(unsigned idx, unsigned long long *out)
{
	struct symrdma_ioc_stats st;

	if (sym_fd < 0 || !out || idx >= SYMRDMA_STATS_MAX)
		return -1;
	memset(&st, 0, sizeof(st));
	if (ioctl(sym_fd, SYMRDMA_IOC_STATS, &st))
		return -1;
	if (st.magic != SYMRDMA_STATS_MAGIC || st.count <= idx ||
	    st.count > SYMRDMA_STATS_MAX) {
		errno = EPROTO;
		return -1;
	}
	*out = st.v[idx];
	return 0;
}

/* Repair-window PIN. Same ioctl the flush-before-unmap barrier uses:
 * no new ABI. PIN promotes the range and holds it, which is the only thing that
 * makes "the carrier's write completed" mean "the bytes landed" - the sentinel
 * page is a real mapping, so a write into it completes and is discarded. */
NPRDMA_INTERNAL int npr_local_pin(const struct mr_entry *e, uint64_t va,
				  uint64_t len)
{
	struct symrdma_ioc_pin p;

	if (!e || !len || sym_fd < 0)
		return -1;
	if (va < e->va_start || va - e->va_start + len > e->len)
		return -1;
	memset(&p, 0, sizeof(p));
	p.mr_id = e->mr_id;
	p.va = va;
	p.len = len;
	unsigned depth=npr_progress_wait_begin();
 int rc=ioctl(sym_fd,SYMRDMA_IOC_PIN_PAGES,&p), saved=errno;
 npr_progress_wait_end(depth);errno=saved;return rc?-1:0;
}

/* UNPIN releases the hold. It does not evict, page out, or move the mapping the
 * repair just established - a release that demoted would make every
 * repair end by re-sentinelizing what it just fixed. What is worth reading here
 * is the verb's transition counter: a page that changed under the pin (COW,
 * remap) means the landing spot is no longer the page the app reads, so the
 * bytes this window carried are not verified. */
NPRDMA_INTERNAL int npr_local_unpin_observed(const struct mr_entry *e, uint64_t va,
				    uint64_t len, unsigned long *transitions,int *released)
{
	struct symrdma_ioc_pin p;
	unsigned long long before = 0, after = 0;
	int observed, observation_errno;
 if(released)*released=0;

	if (transitions)
		*transitions = 0;
	if (!e || !len || sym_fd < 0)
		return -1;
	if (va < e->va_start || va - e->va_start + len > e->len)
		return -1;
	observed = npr_kernel_stat(SYMSTAT_PIN_TRANSITIONS, &before) == 0;
	observation_errno = errno;
	memset(&p, 0, sizeof(p));
	p.mr_id = e->mr_id;
	p.va = va;
	p.len = len;
	unsigned depth=npr_progress_wait_begin();
 int rc=ioctl(sym_fd,SYMRDMA_IOC_UNPIN_PAGES,&p), saved=errno;
 npr_progress_wait_end(depth);errno=saved;
 if(rc) { return -1; }
 if(released)*released=1;
	if (!observed) {
		errno = observation_errno;
		return -1;
	}
	if (npr_kernel_stat(SYMSTAT_PIN_TRANSITIONS, &after))
		return -1;
	if (after < before) {
		errno = EIO;
		return -1;
	}
	if (transitions)
		*transitions = (unsigned long)(after - before);
	return 0;
}

NPRDMA_INTERNAL int npr_local_unpin(const struct mr_entry *e,uint64_t va,uint64_t len,unsigned long *tr)
{return npr_local_unpin_observed(e,va,len,tr,NULL);}

int debug_on(void)
{
	/* Read once: the flag is set by the harness before exec, and the engine asks
	 * per op (delivery check, emit path). A getenv in there is a linear environ
	 * scan on the data path; a cached int is a predictable branch. */
	static int cached = -1;

	if (cached < 0)
		cached = getenv("NPRDMA_DEBUG") != NULL;
	return cached;
}

#define NPRDMA_INTERCEPT_ALL  0
#define NPRDMA_INTERCEPT_FLAG 1
static int g_intercept = NPRDMA_INTERCEPT_FLAG;
static int g_intercept_inited;
static int g_intercept_invalid;

static int intercept_policy(void)
{
	const char *m;

	if (g_intercept_inited)
		return g_intercept;
	g_intercept_inited = 1;
	m = getenv("NPRDMA_INTERCEPT");
	if (!m || !*m) {
		g_intercept = NPRDMA_INTERCEPT_FLAG;
	} else if (strcmp(m, "all") == 0) {
		g_intercept = NPRDMA_INTERCEPT_ALL;
		if (debug_on())
			fprintf(stderr,
				"[nprdma] adopt domain=all (whole-process MRs adopted by SymRDMA)\n");
	} else if (strcmp(m, "flag") == 0) {
		g_intercept = NPRDMA_INTERCEPT_FLAG;
	} else {
		g_intercept = NPRDMA_INTERCEPT_FLAG;
		g_intercept_invalid = 1;
	}
	return g_intercept;
}

static int intercept_invalid(void)
{
	intercept_policy();
	return g_intercept_invalid;
}

static void intercept_reject_value(void)
{
	static int warned;
	const char *m;
	const unsigned char *mu;
	size_t n = 0;

	if (warned)
		return;
	warned = 1;
	m = getenv("NPRDMA_INTERCEPT");
	mu = (const unsigned char *)m;
	if (m && *m)
		n = strlen(m);
	fprintf(stderr,
		"[nprdma] invalid NPRDMA_INTERCEPT value (len=%zu hex=%02x %02x %02x %02x %02x %02x %02x %02x)"
		" — only flag|all accepted (unset/empty = flag): registration fails explicitly (EOPNOTSUPP),"
		" no fallback to default adopt domain\n",
		n,
		n > 0 ? mu[0] : 0, n > 1 ? mu[1] : 0,
		n > 2 ? mu[2] : 0, n > 3 ? mu[3] : 0,
		n > 4 ? mu[4] : 0, n > 5 ? mu[5] : 0,
		n > 6 ? mu[6] : 0, n > 7 ? mu[7] : 0);
}

int symrdma_open_locked(void)
{
	if (sym_fd >= 0)
		return 0;
	sym_fd = open("/dev/symrdma", O_RDWR);
	return sym_fd >= 0 ? 0 : -1;
}

static int g_sym_unavailable_warned;

static unsigned int vanilla_access(unsigned int access)
{
	return access & ~(NPRDMA_MR_SYMRDMA | SYMRDMA_ACCESS_WREG);
}

static int symrdma_probe_reg(void)
{
	static int cached = -1;
	void *pg;
	struct symrdma_ioc_reg_mr req;
	int id;

	if (cached >= 0)
		return cached;
	if (symrdma_open_locked() != 0)
		goto fail;
	pg = mmap(NULL, SYMRDMA_PAGE_SIZE, PROT_READ | PROT_WRITE,
		  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
	if (pg == MAP_FAILED)
		goto fail;
	memset(&req, 0, sizeof(req));
	req.va_start = (unsigned long long)(uintptr_t)pg;
	req.len = SYMRDMA_PAGE_SIZE;
	id = ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &req);
	if (id >= 0) {

		ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, req.mr_id);
		munmap(pg, SYMRDMA_PAGE_SIZE);
		cached = 1;
		return cached;
	}
	munmap(pg, SYMRDMA_PAGE_SIZE);
fail:
	cached = 0;
	if (intercept_policy() == NPRDMA_INTERCEPT_FLAG) {
		if (!g_sym_unavailable_warned) {
			g_sym_unavailable_warned = 1;
			fprintf(stderr,
				"[nprdma] SymRDMA module unavailable or REG_MR failed — MRs pure pass-through in this process (vanilla RDMA)\n");
		} else if (debug_on()) {
			fprintf(stderr, "[nprdma] module probe failed → pass-through\n");
		}
	}
	return cached;
}

static int symrdma_available(void)
{
	return symrdma_probe_reg();
}

static int npr_read_sysfs_u64(const char *path, unsigned long long *out)
{
	char buf[64];
	ssize_t n;
	int fd = open(path, O_RDONLY);

	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = 0;
	{
		char *end;
		unsigned long long v = strtoull(buf, &end, 10);

		if (end == buf)
			return -1;
		*out = v;
	}
	return 0;
}

enum npr_pf_fail {
	NPR_PF_NONE = 0,
	NPR_PF_DEVICE,
	NPR_PF_MODE,
	NPR_PF_MTT_MISSING,
	NPR_PF_MTT_UNREADABLE,
	NPR_PF_WRITE_OFFSET,
};

static int npr_all_preflight(void)
{
	static int done, result = -1;
	enum npr_pf_fail fail = NPR_PF_NONE;
	unsigned long long v;

	if (done)
		return result;
	done = 1;

	if (!symrdma_probe_reg()) {
		fail = NPR_PF_DEVICE;
		goto out;
	}
	if (npr_read_sysfs_u64("/sys/module/symrdma/parameters/mode", &v) ||
	    v != 1) {
		fail = NPR_PF_MODE;
		goto out;
	}
	{
		char b[8];
		ssize_t n;
		int fd = open("/sys/module/mlx5_ib/parameters/identity_mtt",
			      O_RDONLY);

		if (fd < 0) {
			fail = NPR_PF_MTT_MISSING;
			goto out;
		}
		n = read(fd, b, sizeof(b) - 1);
		close(fd);
		if (n <= 0) {
			fail = NPR_PF_MTT_UNREADABLE;
			goto out;
		}
		b[n] = 0;
		if (b[0] == 'Y' || b[0] == '1') {
			static int warned;

			if (!warned) {
				warned = 1;
				fprintf(stderr,
					"[nprdma] adopt domain=all: identity_mtt=1 (global force) — processes on this host without preload will DMA fault\n");
			}
		}
	}
	if (npr_read_sysfs_u64(
		    "/sys/module/mlx5_ib/parameters/identity_mtt_write_offset",
		    &v) || v != 34359738368ULL) {
		fail = NPR_PF_WRITE_OFFSET;
		goto out;
	}
	if (npr_read_sysfs_u64(
		    "/sys/module/mlx5_ib/parameters/identity_mtt_log_pgsize",
		    &v) == 0 && v != 31) {
		static int warned;

		if (!warned) {
			warned = 1;
			fprintf(stderr,
				"[nprdma] adopt domain=all: identity_mtt_log_pgsize=%llu (not 31=2GB; works but more MTT entries)\n",
				v);
		}
	}
	result = 0;
	return 0;
out:
	switch (fail) {
	case NPR_PF_DEVICE:
		fprintf(stderr,
			"[nprdma] adopt domain=all preflight failed: /dev/symrdma unavailable or REG_MR probe failed — registration fails explicitly (EOPNOTSUPP), no silent vanilla fallback\n");
		break;
	case NPR_PF_MODE:
		fprintf(stderr,
			"[nprdma] adopt domain=all preflight failed: symrdma mode != 1 (VERIFY mode does not bind NIC) — registration fails explicitly (EOPNOTSUPP), no silent vanilla fallback\n");
		break;
	case NPR_PF_MTT_MISSING:
		fprintf(stderr,
			"[nprdma] adopt domain=all preflight failed: mlx5_ib has no identity_mtt parameter (OFED patch missing) — registration fails explicitly (EOPNOTSUPP), no silent vanilla fallback\n");
		break;
	case NPR_PF_MTT_UNREADABLE:
		fprintf(stderr,
			"[nprdma] adopt domain=all preflight failed: identity_mtt parameter unreadable — registration fails explicitly (EOPNOTSUPP), no silent vanilla fallback\n");
		break;
	case NPR_PF_WRITE_OFFSET:
		fprintf(stderr,
			"[nprdma] adopt domain=all preflight failed: identity_mtt_write_offset != 32GB (write-region IOVA mismatch) — registration fails explicitly (EOPNOTSUPP), no silent vanilla fallback\n");
		break;
	case NPR_PF_NONE:
		break;
	}
	result = -1;
	return -1;
}

static void symrdma_dereg_mr(struct mr_entry *e);

static int symrdma_reg_mr(struct mr_entry *e, struct ibv_pd *pd)
{
	struct symrdma_ioc_reg_mr req = {
		.va_start = (unsigned long long)e->va_start,
		.len = (unsigned long long)e->len,
	};
	int ret = -1;

	void *vb = NULL;
	size_t vsize = 0;

	req.len = (req.len + 4095) & ~4095ULL;

	pthread_mutex_lock(&lock);
	if (symrdma_open_locked() == 0) {
		struct mr_entry *x;
		int shared = 0;

		for (x = mr_list; x; x = x->next) {
			if (x->va_start == e->va_start && x->len == e->len &&
			    x->mr_id >= 0 && x->pd_identity == pd) {
    /* A failed retirement may already have removed the group's version MR.
     * Do not publish a borrower of half-destroyed storage. */
    if(!x->version_buf||!x->version_ibv_mr||!x->version_buf_len){pthread_mutex_unlock(&lock);errno=EBUSY;return -1;}
				e->mr_id = x->mr_id;
				e->ioctl_shared = 1;
				/* a second handle on the same kernel MR shares its
				 * version table and its auxiliary MRs: the parity judge
				 * reads the table through whichever handle the op carries,
				 * so a shared entry without the pointers would silently
				 * lose the judge */
				e->version_buf = x->version_buf;
				e->version_buf_len = x->version_buf_len;
				e->version_ibv_mr = x->version_ibv_mr;
				e->write_key = x->write_key;
				shared = 1;
				break;
			}
		}
		if (shared ||
		    ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &req) == 0) {
			if (!shared)
				e->mr_id = req.mr_id;
			n_registered++;
			ret = 0;

			/* a shared MR already carries a version table: bind once */
			if (!shared) {
				struct symrdma_ioc_reg_mr vreq;
				struct symrdma_ioc_set_version_page sv;
				unsigned long npages = req.len / SYMRDMA_PAGE_SIZE;
				unsigned long vt_pages = symrdma_vt_pages(npages);

				vsize = vt_pages * SYMRDMA_PAGE_SIZE;
				vb = mmap(NULL, vsize, PROT_READ | PROT_WRITE,
					  MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
				if (vb != MAP_FAILED) {
					memset(vb, 0, vsize);

					if (mlock(vb, vsize) != 0) {
						munmap(vb, vsize);
						vb = MAP_FAILED;
					} else {
						memset(&vreq, 0, sizeof(vreq));
						vreq.va_start = (unsigned long long)(uintptr_t)vb;
						vreq.len = vsize;
						memset(&sv, 0, sizeof(sv));
						sv.mr_id = e->mr_id;
						sv.version_va = (unsigned long long)(uintptr_t)vb;
						sv.version_len = vt_pages;
						vreq.mr_id = -1;
						if (ioctl(sym_fd, SYMRDMA_IOC_REG_MR, &vreq) == 0 &&
						    ioctl(sym_fd, SYMRDMA_IOC_SET_VERSION_PAGE, &sv) == 0) {
							e->version_buf = vb;
							e->version_buf_mr_id = vreq.mr_id;
							e->version_buf_len = vsize;
						} else {
							if (vreq.mr_id >= 0) ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, vreq.mr_id);
							munmap(vb, vsize);
							vb = MAP_FAILED;
						}
					}
				}
				if (vb == MAP_FAILED)
					vsize = 0;
			}
		}
	}
	pthread_mutex_unlock(&lock);

	/*
	 * An adopted page whose generation token has no DMA-visible carrier is
	 * an adopted page nobody can validate: refuse the registration instead
	 * of running with a version channel that silently reads zero.
	 */
	if (ret == 0 && !e->ioctl_shared) {
		int bind_ok = vb && vsize && pd && g_real_reg_mr_iova2;

		if (bind_ok) {
			e->version_ibv_mr = g_real_reg_mr_iova2(pd, vb, vsize,
						       (uint64_t)(uintptr_t)vb,
						       IBV_ACCESS_REMOTE_READ |
						       NPRDMA_MR_SYMRDMA);
			bind_ok = e->version_ibv_mr != NULL;
		}
		if (!bind_ok) {
			fprintf(stderr,
				"[nprdma] MR registration refused: the version table has no DMA-visible carrier (mmap/mlock/REG_MR/SET_VERSION_PAGE/reg_mr_iova2 failed) — an adopted page without a generation token cannot be validated\n");
			if (sym_fd >= 0 && e->version_buf_mr_id >= 0)
				ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR,
				      e->version_buf_mr_id);
			if (e->version_buf)
				munmap(e->version_buf, e->version_buf_len);
			e->version_buf = NULL;
			e->version_buf_mr_id = -1;
			e->version_buf_len = 0;
			symrdma_dereg_mr(e);
			return -1;
		}
	}
	return ret;
}

static void symrdma_dereg_mr(struct mr_entry *e)
{
	struct ibv_mr *vmr = NULL;
	struct ibv_mr *wmr = NULL;
	struct ibv_mr *rmr = NULL;
	void *vbuf = NULL;
	size_t vlen = 0;

	pthread_mutex_lock(&lock);

	if (sym_fd >= 0) {
		if (e->version_buf_mr_id >= 0)
			ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, e->version_buf_mr_id);
		if (!e->ioctl_shared && e->mr_id >= 0)
			ioctl(sym_fd, SYMRDMA_IOC_DEREG_MR, e->mr_id);
	}

	if (g_memo_lkey == e)
		g_memo_lkey = NULL;

	vmr = e->version_ibv_mr;
	wmr = e->write_ibv_mr;
	rmr = e->read_ibv_mr;
	vbuf = e->version_buf;
	vlen = e->version_buf_len;
	if (e->ioctl_shared) {
		/* a shared entry only borrowed the first entry's version table and
		 * auxiliary MRs: the owner of the kernel MR frees them */
		vmr = NULL;
		vbuf = NULL;
	}
	e->version_ibv_mr = NULL;
	e->write_ibv_mr = NULL;
	e->read_ibv_mr = NULL;
	e->version_buf = NULL;
	n_registered--;
	pthread_mutex_unlock(&lock);

	if (vmr) {
		static int (*real_dereg)(struct ibv_mr *);
		if (!real_dereg)
			real_dereg = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
		if (real_dereg)
			real_dereg(vmr);
	}
	if (rmr) {
		int (*fn)(struct ibv_mr *) = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
		if (fn) fn(rmr);
	}
	if (wmr) {
		static int (*real_dereg2)(struct ibv_mr *);
		if (!real_dereg2)
			real_dereg2 = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
		if (real_dereg2)
			real_dereg2(wmr);
	}
	if (vbuf)
		munmap(vbuf, vlen ? vlen : SYMRDMA_PAGE_SIZE);
}

static int npr_auto_export(struct mr_entry *e, struct ibv_pd *pd,
                            struct ibv_context *ctx, int access)
{
 struct sir_export exp = {0};
 e->read_ibv_mr = g_real_reg_mr_iova2(pd, (void *)e->va_start, e->len,
     e->va_start, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ | NPRDMA_MR_SYMRDMA);
 if (!e->read_ibv_mr) return -1;
 e->write_ibv_mr = g_real_reg_mr_iova2(pd, (void *)e->va_start, e->len,
     e->va_start, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE |
     NPRDMA_MR_SYMRDMA | SYMRDMA_ACCESS_WREG);
 if (!e->write_ibv_mr) return -1;
 e->write_key = (access & IBV_ACCESS_REMOTE_WRITE) ? e->write_ibv_mr->rkey : 0;
 sir_init(ctx, pd, NULL, sym_fd);
 exp.app_rkey = e->ibv_mr->rkey;
 exp.app_access = access & (IBV_ACCESS_REMOTE_READ | IBV_ACCESS_REMOTE_WRITE | IBV_ACCESS_REMOTE_ATOMIC);
 exp.data_rkey = e->read_ibv_mr->rkey;
 exp.write_rkey = e->write_key;
 exp.addr = e->va_start; exp.len = e->len; exp.mr_id = e->mr_id;

 exp.v_rkey = e->version_ibv_mr->rkey;
 exp.v_addr = (uint64_t)(uintptr_t)e->version_buf;
 /* Native two-sided DMA needs local views, not a remote-key exchange.
  * A configured peer still requires successful publication. */
 if((!getenv("SYMRDMA_PEER")||!*getenv("SYMRDMA_PEER"))&&
    (!getenv("SYMRDMA_SIR_TCP")||!*getenv("SYMRDMA_SIR_TCP")))return 0;
 /* The owner executes reverse DMA on the service QP, whose PD need not
  * equal this application's PD. Local DMA needs the matching service lkey. */
 if(npr_mr_carrier_prepare(e,0))return -1;
 exp.lkey = e->carrier_read_ibv_mr->lkey;
 if(sir_export_add(&exp))return -1;
 e->control_exported=1;return 0;
}

static __thread int in_reg_mr;

enum npr_reject_kind {
	NPR_REJECT_ODP,
	NPR_REJECT_DMABUF,
	NPR_REJECT_REREG,
};
static int g_reject_dmabuf;
static int g_reject_rereg;
static int g_reject_odp;

static void npr_intercept_reject(int *warned, enum npr_reject_kind kind)
{
	if (*warned)
		return;
	*warned = 1;
	switch (kind) {
	case NPR_REJECT_ODP:
		fprintf(stderr,
			"[nprdma] adopt domain all does not support ODP MR (IBV_ACCESS_ON_DEMAND) — rejected (EOPNOTSUPP)\n");
		break;
	case NPR_REJECT_DMABUF:
		fprintf(stderr,
			"[nprdma] adopt domain all does not support dmabuf MR (ibv_reg_dmabuf_mr) — rejected (EOPNOTSUPP)\n");
		break;
	case NPR_REJECT_REREG:
		fprintf(stderr,
			"[nprdma] adopt domain all does not support MR rereg (ibv_rereg_mr) — rejected (EOPNOTSUPP)\n");
		break;
	}
}

/* Every raw provider registration, including private views and window pools,
 * preserves provider flags but excludes recursive external-MR adoption. */
static struct ibv_mr *npr_provider_reg_mr_iova2(struct ibv_pd *pd,void *addr,size_t length,uint64_t iova,unsigned access)
{
 static struct ibv_mr *(*raw)(struct ibv_pd *,void *,size_t,uint64_t,unsigned);
 if(!raw)raw=dlvsym(RTLD_NEXT,"ibv_reg_mr_iova2","IBVERBS_1.8");
 if(!raw){errno=ENOSYS;return NULL;}
 in_mr_provider++;struct ibv_mr *mr=raw(pd,addr,length,iova,access);int saved=errno;in_mr_provider--;errno=saved;return mr;
}
static struct ibv_mr *npr_reg_mr_common_impl(struct ibv_pd *,void *,size_t,uint64_t,unsigned,int);
static struct ibv_mr *npr_reg_mr_common(struct ibv_pd *pd,void *addr,size_t length,uint64_t iova,unsigned access,int via_iova)
{
 if(in_mr_provider||in_reg_mr)return npr_provider_reg_mr_iova2(pd,addr,length,iova,access);
 if(npr_progress_internal())return npr_provider_reg_mr_iova2(pd,addr,length,iova,access&~(NPRDMA_MR_SYMRDMA|SYMRDMA_ACCESS_WREG));
 npr_progress_lock();
 struct npr_mra_spec spec={.context=pd?pd->context:NULL,.pd=pd,.cpu_base=(uintptr_t)addr,.iova_base=iova,.length=length,.access=vanilla_access(access),.kind=NPR_MRA_CPU_NATIVE,.iova_unverified=!!(access&IBV_ACCESS_ZERO_BASED)};
 struct npr_mra_registration *authority=npr_mra_reserve(&spec);
 if(!authority){npr_progress_unlock();return NULL;}
 struct ibv_mr *mr=npr_reg_mr_common_impl(pd,addr,length,iova,access,via_iova);
 int saved=errno;
 if(mr&&(access&IBV_ACCESS_ON_DEMAND)){
  /* ODP remains the existing native-only non-target surface. It cannot
   * supply CPU authority for a later internal bridge. */
  npr_mra_abort(authority);
 }else if(mr){
  struct mr_entry *adopted=NULL;
  pthread_mutex_lock(&lock);
  for(struct mr_entry *e=mr_list;e;e=e->next)if(e->ibv_mr==mr){adopted=e;break;}
  pthread_mutex_unlock(&lock);
  if(adopted)npr_mra_reservation_adopted(authority,adopted);
  npr_mra_commit(authority,mr,mr->lkey,mr->rkey);
 }else npr_mra_abort(authority);
 npr_progress_unlock();errno=saved;return mr;
}
static struct ibv_mr *npr_reg_mr_common_impl(struct ibv_pd *pd, void *addr,
					size_t length, uint64_t iova,
					unsigned int access, int via_iova)
{
	static struct ibv_mr *(*real_fn)(struct ibv_pd *, void *, size_t,
					 uint64_t, unsigned int);
	struct ibv_mr *mr;
	struct mr_entry *e;

	if (!real_fn) {
		real_fn = dlvsym(RTLD_NEXT, "ibv_reg_mr_iova2", "IBVERBS_1.8");
		g_real_reg_mr_iova2 = npr_provider_reg_mr_iova2;
	}
	if (!real_fn)
		return NULL;

	if (in_reg_mr)
		return npr_provider_reg_mr_iova2(pd,addr,length,iova,access);

	if (intercept_invalid()) {
		intercept_reject_value();
		errno = EOPNOTSUPP;
		return NULL;
	}

	if (intercept_policy() == NPRDMA_INTERCEPT_FLAG &&
	    !(access & NPRDMA_MR_SYMRDMA)) {
		if (debug_on())
			fprintf(stderr,
				"[nprdma] adopt domain flag pass-through MR %p:%zu (no NPRDMA_MR_SYMRDMA bit)\n",
				addr, length);
		return npr_provider_reg_mr_iova2(pd,addr,length,iova,access);
	}

	if (intercept_policy() == NPRDMA_INTERCEPT_ALL) {
		if (access & IBV_ACCESS_ON_DEMAND) {
			npr_intercept_reject(&g_reject_odp, NPR_REJECT_ODP);
			errno = EOPNOTSUPP;
			return NULL;
		}
		if (npr_all_preflight()) {
			errno = EOPNOTSUPP;
			return NULL;
		}
	} else if (!symrdma_available()) {
		return npr_provider_reg_mr_iova2(pd,addr,length,iova,vanilla_access(access));
	}

    e=calloc(1,sizeof(*e));if(!e){errno=ENOMEM;return NULL;}
	in_reg_mr = 1;
	{
		unsigned int eff = symrdma_eff_access(access);


		mr = npr_provider_reg_mr_iova2(pd,addr,length,iova,eff);
	}
	in_reg_mr = 0;
	if (!mr){int saved=errno;free(e);errno=saved;return NULL;}

{
		e->ibv_mr = mr; e->context_identity=mr->context;
  e->pd_identity=mr->pd;e->facade_identity=mr;e->app_lkey=mr->lkey;e->app_rkey=mr->rkey;
		e->app_access = access;
		e->va_start = (uintptr_t)addr;
		e->len = length;
		e->version_buf_mr_id = -1;
		e->mr_id = -1;
		if (symrdma_reg_mr(e, pd) == 0) {
			pthread_mutex_lock(&lock);
			e->next = mr_list;
			mr_list = e;
			pthread_mutex_unlock(&lock);
			if (debug_on())
				fprintf(stderr,
					"[nprdma] reg_mr(%p, %zu, via_iova=%d) → "
					"SymRDMA mr_id=%d (now %d)\n",
					addr, length, via_iova, e->mr_id,
					n_registered);

			/* a fault asked for before the first operation has to be
			 * placed now: this is the only moment the engine knows both
			 * the MR id and that the ops are still ahead of it */
			if (npr_fault_arm_requested() &&
			    npr_fault_arm(e->mr_id, (uintptr_t)addr, length))
				fprintf(stderr, "[nprdma] fault-arm requested but "
					"not applied (mr=%d)\n", e->mr_id);

			if (creg_local_mr_publish((uint64_t)(uintptr_t)addr,
						  length, e->ibv_mr->rkey))
				fprintf(stderr, "[nprdma] local MR registry "
					"publish failed (va=%p len=%zu)\n", addr,
					length);
			if (npr_auto_export(e, pd, pd->context, (int)access)) {
                int saved = errno ? errno : ENOMEM;
                /* A failed rollback has no application handle for retry.
                 * Keep it discoverable by PD teardown until it can drain. */
                e->orphaned = 1;
                ibv_dereg_mr(mr);
                errno = saved;
                return NULL;
            }
		} else {
			if (debug_on())
				fprintf(stderr,
					"[nprdma] reg_mr(%p, %zu, via_iova=%d): "
					"SymRDMA registration failed — transparent fallback\n",
					addr, length, via_iova);
            free(e);
            { int (*dereg)(struct ibv_mr *) = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
              if (dereg) dereg(mr); }
            errno = ENOMEM;
            return NULL;
        }
    }
    return mr;
}

struct ibv_mr *ibv_reg_mr_iova2(struct ibv_pd *pd, void *addr, size_t length,
				uint64_t iova, unsigned int access)
{
	return npr_reg_mr_common(pd, addr, length, iova, access, 1);
}

struct ibv_mr *ibv_reg_mr_iova(struct ibv_pd *pd,void *addr,size_t length,uint64_t iova,int access)
{return npr_reg_mr_common(pd,addr,length,iova,(unsigned)access,1);}

struct ibv_mr *ibv_reg_mr(struct ibv_pd *pd, void *addr, size_t length,
			  int access)
{
	return npr_reg_mr_common(pd, addr, length, (uint64_t)(uintptr_t)addr,
				 (unsigned int)access, 0);
}

struct ibv_mr *ibv_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
				 size_t length, uint64_t iova, int fd,
				 int access);

struct ibv_mr *ibv_reg_dmabuf_mr(struct ibv_pd *pd, uint64_t offset,
				 size_t length, uint64_t iova, int fd,
				 int access)
{
	static struct ibv_mr *(*real_fn)(struct ibv_pd *, uint64_t, size_t,
					 uint64_t, int, int);

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_reg_dmabuf_mr",
				 "IBVERBS_1.12");
	if (!real_fn) {
		errno = ENOSYS;
		return NULL;
	}
	if (intercept_invalid()) {
		intercept_reject_value();
		errno = EOPNOTSUPP;
		return NULL;
	}
	if (intercept_policy() == NPRDMA_INTERCEPT_ALL) {
		npr_intercept_reject(&g_reject_dmabuf, NPR_REJECT_DMABUF);
		errno = EOPNOTSUPP;
		return NULL;
	}
	return real_fn(pd, offset, length, iova, fd, access);
}

int ibv_rereg_mr(struct ibv_mr *mr, int flags, struct ibv_pd *pd,
		 void *addr, size_t length, int access);

static int ibv_rereg_mr_impl(struct ibv_mr *,int,struct ibv_pd *,void *,size_t,int);
int ibv_rereg_mr(struct ibv_mr *mr,int flags,struct ibv_pd *pd,void *addr,size_t length,int access)
{
 if(npr_progress_internal()||in_mr_provider)return ibv_rereg_mr_impl(mr,flags,pd,addr,length,access);
 npr_progress_lock();int rc=ibv_rereg_mr_impl(mr,flags,pd,addr,length,access);int saved=errno;npr_progress_unlock();errno=saved;return rc;
}
static int ibv_rereg_mr_impl(struct ibv_mr *mr,int flags,struct ibv_pd *pd,void *addr,size_t length,int access)
{
 static int (*raw)(struct ibv_mr *,int,struct ibv_pd *,void *,size_t,int);
 if(!raw)raw=dlvsym(RTLD_NEXT,"ibv_rereg_mr","IBVERBS_1.1");
 if(!raw){errno=ENOSYS;return IBV_REREG_MR_ERR_INPUT;}
 int internal=npr_progress_internal()||in_mr_provider;
 if(internal){in_mr_provider++;int rc=raw(mr,flags,pd,addr,length,access),saved=errno;in_mr_provider--;errno=saved;return rc;}
 if(intercept_invalid()){intercept_reject_value();errno=EOPNOTSUPP;return IBV_REREG_MR_ERR_INPUT;}
 struct npr_mra_spec proposed;
 int known=npr_mra_describe(mr,&proposed);
 if(intercept_policy()==NPRDMA_INTERCEPT_ALL||(!known&&proposed.kind==NPR_MRA_CPU_ADOPTED)){
  npr_intercept_reject(&g_reject_rereg,NPR_REJECT_REREG);errno=EOPNOTSUPP;return IBV_REREG_MR_ERR_INPUT;
 }
 if(known&&known!=ENOENT){errno=known;return IBV_REREG_MR_ERR_INPUT;}
 struct npr_mra_mutation t;
 if(!known){
  if(flags&IBV_REREG_MR_CHANGE_PD){if(!pd){errno=EINVAL;return IBV_REREG_MR_ERR_INPUT;}proposed.pd=pd;proposed.context=pd->context;}
  if(flags&IBV_REREG_MR_CHANGE_ACCESS)proposed.access=(unsigned)access;
  if(flags&IBV_REREG_MR_CHANGE_TRANSLATION){
   /* mlx5 rereg passes the new CPU address as hca_va. Do not infer an old
    * explicit IOVA from mr->addr or guess ZERO_BASED hardware semantics. */
   proposed.cpu_base=(uintptr_t)addr;proposed.length=length;proposed.iova_base=(uintptr_t)addr;
   proposed.iova_unverified=!!(proposed.access&IBV_ACCESS_ZERO_BASED);
  }else if(proposed.access&IBV_ACCESS_ZERO_BASED)proposed.iova_unverified=1;
  if(npr_mra_rereg_begin(mr,&proposed,&t))return IBV_REREG_MR_ERR_INPUT;
 }
 in_mr_provider++;int rc=raw(mr,flags,pd,addr,length,access),saved=errno;in_mr_provider--;
 if(!known)npr_mra_rereg_finish(&t,rc,(rc==0||rc==IBV_REREG_MR_ERR_DO_FORK_OLD)?mr->lkey:0,(rc==0||rc==IBV_REREG_MR_ERR_DO_FORK_OLD)?mr->rkey:0);
 errno=saved;return rc;
}

static int npr_release_owned_views(struct mr_entry *e)
{
 int (*dereg)(struct ibv_mr *) = dlvsym(RTLD_NEXT, "ibv_dereg_mr", "IBVERBS_1.1");
 struct ibv_mr **views[] = { &e->carrier_read_ibv_mr, &e->carrier_write_ibv_mr, &e->owner_read_ibv_mr, &e->owner_write_ibv_mr, &e->read_ibv_mr, &e->write_ibv_mr };
 unsigned i;
 pthread_mutex_lock(&lock);
 if (!e->ioctl_shared) {
  struct mr_entry *x;
  for (x = mr_list; x; x = x->next) {
   if (x != e && x->ioctl_shared && x->mr_id == e->mr_id &&
       x->version_buf == e->version_buf) {
    x->ioctl_shared = 0;
    x->version_buf_mr_id = e->version_buf_mr_id;
    e->version_buf_mr_id = -1;
    e->ioctl_shared = 1;
    break;
   }
  }
 }
 pthread_mutex_unlock(&lock);
 if (!dereg) return ENOSYS;
 if (!e->ioctl_shared && e->version_ibv_mr) {
  int rc = dereg(e->version_ibv_mr);
  if (rc) return rc;
  e->version_ibv_mr = NULL;
 }
 for (i = 0; i < sizeof(views) / sizeof(views[0]); i++) {
  if (*views[i]) {
   int rc = dereg(*views[i]);
   if (rc) return rc;
   *views[i] = NULL;
  }
 }
 return 0;
}

static int npr_provider_dereg_mr(struct ibv_mr *);
static int npr_mr_is_closing(const struct ibv_mr *mr)
{
 for(struct mr_entry *e=mr_list;e;e=e->next)if(!e->retired&&e->ibv_mr==mr)return e->closing;
 return 0;
}
static int npr_mr_revoke_exports(struct mr_entry *e)
{
 if(!e->control_exported)return 0;
 if(!e->closing){
  int rc=creg_mr_close(e->app_rkey,e->va_start,e->len,&e->retirement);
  if(rc)return -rc;
  pthread_mutex_lock(&lock);e->closing=1;if(g_memo_lkey==e)g_memo_lkey=NULL;
  pthread_mutex_unlock(&lock);
 }
 unsigned depth=npr_progress_wait_begin();
 int rc=-creg_mr_drain(&e->retirement,CONTROL_DRAIN_TIMEOUT_MS);
 npr_progress_wait_end(depth);
 if(!rc){
  struct ibv_mr **views[]={&e->read_ibv_mr,&e->write_ibv_mr};
  for(unsigned i=0;i<2;i++)if(*views[i]){
   rc=npr_provider_dereg_mr(*views[i]);
   if(rc)break;
   *views[i]=NULL;e->export_revoked=1;
  }
 }
 if(rc&&!e->export_revoked){
  if(!creg_mr_reopen(&e->retirement)){pthread_mutex_lock(&lock);e->closing=0;pthread_mutex_unlock(&lock);memset(&e->retirement,0,sizeof(e->retirement));}
 }
 return rc;
}

static int ibv_dereg_mr_impl(struct ibv_mr *mr);
static int npr_provider_dereg_mr(struct ibv_mr *mr)
{
 static int (*raw)(struct ibv_mr *);
 if(!raw)raw=dlvsym(RTLD_NEXT,"ibv_dereg_mr","IBVERBS_1.1");
 if(!raw){errno=ENOSYS;return -1;}
 in_mr_provider++;int rc=raw(mr),saved=errno;in_mr_provider--;errno=saved;return rc;
}
int ibv_dereg_mr(struct ibv_mr *mr)
{
 if(npr_progress_internal()||in_mr_provider)return npr_provider_dereg_mr(mr);
 npr_progress_lock();
 struct npr_mra_capture guard={0};struct npr_mra_spec spec={0};
 int borrowed=npr_mra_borrow_handle(mr,&guard,&spec);
 if(borrowed&&borrowed!=ENOENT&&borrowed!=EBUSY){npr_progress_unlock();errno=borrowed;return borrowed;}
 if(!borrowed)(void)npr_rdv_control_drain_pd(spec.context,spec.pd);
 struct npr_mra_mutation t;
 int tracked=!borrowed?npr_mra_dereg_begin_borrowed(mr,&guard,&t):npr_mra_dereg_begin(mr,&t);
 if(tracked&&tracked!=ENOENT){npr_mra_release(&guard);npr_progress_unlock();errno=tracked;return tracked;}
 int rc=ibv_dereg_mr_impl(mr),saved=errno;
 if(!tracked)npr_mra_dereg_finish_closing(&t,rc,rc&&npr_mr_is_closing(mr));
 npr_mra_release(&guard);
 npr_progress_unlock();npr_progress_wake();errno=saved;return rc;
}
/* Retired entries stay in the stable storage list, but never in live lookup.
 * Reclamation is nonblocking: each physical failure leaves the exact owner for
 * the next pump. The public facade is already gone and must never be retried. */
static void npr_mr_retire_progress(void)
{
 struct mr_entry **pp=&mr_list,*e;
 while((e=*pp)){
  if(!e->retired||e->retire_registry_failed||e->order_refs||e->sr_refs||npr_mra_adopted_busy(e)){pp=&e->next;continue;}
  if(creg_mr_reclaim(&e->retirement)){pp=&e->next;continue;}
  if(npr_release_owned_views(e)){pp=&e->next;continue;}
  if(!e->ioctl_shared&&e->version_buf_mr_id>=0){
   if(sym_fd<0||ioctl(sym_fd,SYMRDMA_IOC_DEREG_MR,e->version_buf_mr_id)){pp=&e->next;continue;}
   e->version_buf_mr_id=-1;
  }
  if(!e->ioctl_shared&&e->mr_id>=0){
   if(sym_fd<0||ioctl(sym_fd,SYMRDMA_IOC_DEREG_MR,e->mr_id)){pp=&e->next;continue;}
   e->mr_id=-1;
  }
  if(!e->ioctl_shared&&e->version_buf){
   if(munmap(e->version_buf,e->version_buf_len?e->version_buf_len:SYMRDMA_PAGE_SIZE)){pp=&e->next;continue;}
   e->version_buf=NULL;
  }
  pthread_mutex_lock(&lock);
  *pp=e->next;if(g_memo_lkey==e)g_memo_lkey=NULL;n_registered--;free(e);
  pthread_mutex_unlock(&lock);
 }
 /* Retry physical failures even with no CQ, app poll or other work left. */
 for(e=mr_list;e;e=e->next)if(e->retired){
  struct timespec now;clock_gettime(CLOCK_MONOTONIC,&now);
  npr_progress_deadline((uint64_t)now.tv_sec*1000000000ull+now.tv_nsec+10000000ull);break;
 }
}
static int npr_mr_retired_busy(void *identity,int pd)
{
 for(struct mr_entry *e=mr_list;e;e=e->next)
  if((e->retired||e->closing)&&(pd?(void*)e->pd_identity:(void*)e->context_identity)==identity)return 1;
 return 0;
}
static int ibv_dereg_mr_impl(struct ibv_mr *mr)
{
 struct mr_entry *e=NULL;
 pthread_mutex_lock(&lock);
 for(e=mr_list;e;e=e->next)if(!e->retired&&e->ibv_mr==mr)break;
 pthread_mutex_unlock(&lock);
 int rc=e?npr_progress_start(npr_application_pump):0;
 if(rc){errno=rc;return rc;}
 rc=e?npr_mr_revoke_exports(e):0;
 if(rc){if(rc>0)errno=rc;return rc;}
 /* Once an export key was revoked, a later provider failure remains CLOSING.
  * The still-valid facade is retried last; no freed handle is ever retried. */
 rc=npr_provider_dereg_mr(mr);int saved=errno;
 if(!rc&&e){
  pthread_mutex_lock(&lock);e->ibv_mr=NULL;e->retired=1;
  if(g_memo_lkey==e)g_memo_lkey=NULL;
  pthread_mutex_unlock(&lock);
  if(!e->closing)e->retire_registry_failed=!!creg_mr_close(e->app_rkey,e->va_start,e->len,&e->retirement);
  npr_mr_retire_progress();
 }
 errno=saved;return rc;
}

struct ibv_pd *ibv_alloc_pd(struct ibv_context *context);

static int ibv_dealloc_pd_impl(struct ibv_pd *pd);
int ibv_dealloc_pd(struct ibv_pd *pd)
{
 int rc;if(npr_progress_internal()) {int (*raw)(struct ibv_pd *)=dlvsym(RTLD_NEXT,"ibv_dealloc_pd","IBVERBS_1.1");return raw?raw(pd):ENOSYS;}
 npr_progress_lock();struct npr_mra_stop_guard guard;
 rc=npr_mra_stop_begin(pd?pd->context:NULL,pd,&guard);
 if(rc){npr_progress_unlock();errno=rc;return rc;}
 npr_progress_quiesce();rc=ibv_dealloc_pd_impl(pd);int saved=errno;
 npr_mra_stop_end(&guard,!rc);npr_progress_unlock();errno=saved;return rc;
}
static int ibv_dealloc_pd_impl(struct ibv_pd *pd)
{
	static int (*real_fn)(struct ibv_pd *);

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_dealloc_pd", "IBVERBS_1.1");
	if (!real_fn)
		return ENOSYS;
 npr_mr_retire_progress();
 if(npr_mra_pd_busy(pd)||npr_mr_retired_busy(pd,1)){errno=EBUSY;return EBUSY;}
 {int busy=npr_sr_pd_release(pd);if(busy){errno=busy;return busy;}}
    for (;;) {
        struct mr_entry *e;
        struct ibv_mr *orphan = NULL;
        pthread_mutex_lock(&lock);
        for (e = mr_list; e; e = e->next) {
            if (!e->retired && e->orphaned && e->pd_identity == pd) {
                orphan = e->ibv_mr;
                break;
            }
        }
        pthread_mutex_unlock(&lock);
        if (!orphan) break;
        if (ibv_dereg_mr(orphan)) {
            errno = EBUSY;
            return EBUSY;
        }
    }

 /* A failed application teardown must not shut down the shared service. */
 if(npr_mra_pd_registered(pd)||npr_qp_connection_pd_live(pd))return real_fn(pd);
 { int rc=npr_pd_release_windows(pd);if(rc){errno=rc;return rc;} }
 int taken=sir_take_pd(pd);
 if(taken<0){errno=-taken;return -taken;}
 if(taken)return 0;
 if(sir_transport_pd_busy(pd)){errno=EBUSY;return EBUSY;}
 int rc=real_fn(pd),saved=errno;
 if(!rc)sir_pd_closed(pd);
 errno=saved;return rc;
}

/* Posting borrows cover preparations whose PIN syscall yields the API gate.
 * The borrow ends only after acceptance/rollback has reconciled the identity. */
int npr_posting_enter(struct npr_ctx_entry *ce)
{
 if(!ce||!ce->ctx||ce->closing||ce->posting_blocked)return EBUSY;
 if(ce->posting_refs==UINT_MAX)return EOVERFLOW;
 ce->posting_refs++;return 0;
}
void npr_posting_leave(struct npr_ctx_entry *ce)
{
 if(ce&&ce->posting_refs)ce->posting_refs--;
 /* Every public posting wrapper wakes after releasing the API gate. A wake
  * here only queues the pump while the posting caller still owns that gate. */
}
int npr_posting_wait(struct npr_ctx_entry *ce)
{
 struct timespec begin,now;
 if(!ce)return 0;
 if(clock_gettime(CLOCK_MONOTONIC,&begin))return EBUSY;
 while(ce->posting_refs){
  unsigned depth=npr_progress_wait_begin();
  usleep(1000);npr_progress_wait_end(depth);
  if(clock_gettime(CLOCK_MONOTONIC,&now)||
     now.tv_sec-begin.tv_sec>=10)return EBUSY;
 }
 return 0;
}

static void symrdma_forget_context(struct ibv_context *);
int ibv_close_device(struct ibv_context *context)
{
 static int (*real_fn)(struct ibv_context *);
 struct npr_ctx_entry *ce;
 int rc,saved;
 if(!real_fn) real_fn=dlvsym(RTLD_NEXT,"ibv_close_device","IBVERBS_1.1");
 if(!real_fn) return ENOSYS;
 if(npr_progress_internal()) return real_fn(context);
 npr_progress_lock();
 npr_mr_retire_progress();
 if(npr_mr_retired_busy(context,0)){npr_progress_unlock();errno=EBUSY;return EBUSY;}
 for(ce=npr_ctx_list;ce;ce=ce->next) if(ce->ctx==context) break;
 if(ce&&(ce->posting_blocked||ce->closing)){npr_progress_unlock();errno=EBUSY;return EBUSY;}
 if(ce) ce->closing=1;
 if(npr_posting_wait(ce)){if(ce)ce->closing=0;npr_progress_unlock();return EBUSY;}
 struct npr_mra_stop_guard guard;
 rc=npr_mra_stop_begin(context,NULL,&guard);
 if(rc){if(ce)ce->closing=0;npr_progress_unlock();errno=rc;return rc;}
 npr_progress_quiesce();sir_fini_context(context);
 if(sir_transport_ctx_busy(context)) {
  if(ce) ce->closing=0;
  npr_mra_stop_end(&guard,0);npr_progress_unlock();errno=EBUSY;return EBUSY;
 }
 rc=real_fn(context);saved=errno;
 if(!rc)sir_context_closed(context);
 npr_mra_stop_end(&guard,!rc);
 if(ce && !rc) {
  npr_qp_connection_context_stopped(context);
  npr_progress_context_closed(ce);
  npr_order_context_stopped(ce);
  npr_identity_context_stopped(ce);
  while(ce->cqs) npr_cq_destroy(ce,ce->cqs->cq);
  symrdma_forget_context(context);
  ce->ctx=NULL;
 } else if(ce) ce->closing=0;
 npr_progress_unlock();errno=saved;return rc;
}

struct ibv_pd *ibv_alloc_pd(struct ibv_context *context)
{
	static struct ibv_pd *(*real_fn)(struct ibv_context *);
	struct ibv_pd *pd;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_alloc_pd", "IBVERBS_1.1");
	if (!real_fn)
		return NULL;
	pd = real_fn(context);
	if (pd) {

		sir_init(context, pd, NULL, -1);

		sir_ensure_start();
		if (debug_on())
			fprintf(stderr, "[nprdma] ibv_alloc_pd → SIR ready (peer=%c)\n",
				getenv("SYMRDMA_PEER") && *getenv("SYMRDMA_PEER") ?
				'1' : '0');
	}
	return pd;
}

NPRDMA_INTERNAL void npr_pin_once(int mr_id, uint64_t va, size_t len)
{
	struct symrdma_ioc_pin p = {
		.mr_id = mr_id,
		.va = va,
		.len = len,
	};

	if (sym_fd < 0 || mr_id < 0)
		return;
	ioctl(sym_fd, SYMRDMA_IOC_PIN_PAGES, &p);
}

static int npr_op_from_wr(struct ibv_qp *qp, const struct ibv_send_wr *w,
			  struct npr_op *op)
{
	uint64_t total = 0;
	int i;

	(void)qp;

	memset(op, 0, sizeof(*op));
	switch (w->opcode) {
 case IBV_WR_SEND:
 case IBV_WR_SEND_WITH_IMM:
  if(qp->qp_type!=IBV_QPT_RC)return -1; /* Native-only non-RC stays on its original posting path. */
  op->kind=w->opcode==IBV_WR_SEND?NPR_OP_SEND:NPR_OP_SEND_IMM;op->imm=w->imm_data;break;
	case IBV_WR_RDMA_READ:
		op->kind = NPR_OP_READ;
		op->remote_addr = w->wr.rdma.remote_addr;
		op->rkey = w->wr.rdma.rkey;
		break;
	case IBV_WR_RDMA_WRITE:
	case IBV_WR_RDMA_WRITE_WITH_IMM:
		op->kind = (w->opcode == IBV_WR_RDMA_WRITE) ?
			   NPR_OP_WRITE : NPR_OP_WRITE_IMM;
		op->remote_addr = w->wr.rdma.remote_addr;
		op->rkey = w->wr.rdma.rkey;
		op->imm = w->imm_data;
		break;
	case IBV_WR_ATOMIC_CMP_AND_SWP:
	case IBV_WR_ATOMIC_FETCH_AND_ADD:
		op->kind = NPR_OP_ATOMIC;
		op->remote_addr = w->wr.atomic.remote_addr;
		op->rkey = w->wr.atomic.rkey;
		op->atom_cas = (w->opcode == IBV_WR_ATOMIC_CMP_AND_SWP);
		op->atom_compare_add = w->wr.atomic.compare_add;
		op->atom_swap = w->wr.atomic.swap;
		break;
	default:
		return -1;
	}

	if(w->num_sge<0 || (w->num_sge&&!w->sg_list))return -1;
 op->num_sge = w->sg_list ? w->num_sge : 0;
	for (i = 0; w->sg_list && i < w->num_sge; i++)
		total += w->sg_list[i].length;
	op->len = total;
	op->signaled = !!(w->send_flags & IBV_SEND_SIGNALED);
	op->inline_  = !!(w->send_flags & IBV_SEND_INLINE);
	op->flags    = w->send_flags &
		       ~(uint32_t)(IBV_SEND_SIGNALED | IBV_SEND_INLINE);
	op->wr_id    = w->wr_id;
	for (i = 0; w->sg_list && i < w->num_sge && i < NPR_OP_MAX_SGE; i++) {
		op->sge[i].addr = w->sg_list[i].addr;
		op->sge[i].length = w->sg_list[i].length;
		op->sge[i].lkey = w->sg_list[i].lkey;
	}

	return 0;
}

/* The pre-check's local SGE judge. The peer owns remote-target judgement;
 * numeric keys and virtual addresses cannot identify its memory here. The
 * version-table parity of every page of the face's window (read judge, not
 * residency, not a hint). A face found absent is pinned (promote + hold) and the
 * hold goes to the op's holder; *absent is set so the caller routes the op away
 * from the optimistic emit. The window's size is not a silent cap: the table is
 * scanned in bounded chunks across the whole window, and a face whose table
 * exists but cannot be read is -1 (never "judged clean").
 *
 * A face that belongs to no adopted MR (no mr_entry, or an entry without a
 * version table) is not judged at all: the sentinel mechanism does not apply to
 * it, so there is nothing to claim - that is the only skip, and it is stated as
 * "not ours". */
static void npr_precheck_fail_trace(const char *stage,const char *face,
 const struct mr_entry *m,uint64_t va,uint64_t len,unsigned long page)
{
 static unsigned logs;
 int saved=errno;
 if(debug_on()&&logs++<32) fprintf(stderr,
  "[nprdma] precheck failure stage=%s face=%s va=0x%llx len=%llu page=%lu mr_start=0x%llx mr_len=%llu errno=%d (bounded32)\n",
  stage,face,(unsigned long long)va,(unsigned long long)len,page,
  (unsigned long long)(m?m->va_start:0),(unsigned long long)(m?m->len:0),saved);
 errno=saved;
}
static int npr_precheck_face(const struct mr_entry *m, uint64_t va, uint64_t len,
			     const char *face, const struct npr_preholder *h,
			     int *absent)
{
	uint32_t v[NPR_PRECHECK_CHUNK_PAGES];
	unsigned long np_all, i;

	if (!m || !m->version_buf)
		return 0;
	np_all = (va % SYMRDMA_PAGE_SIZE + len + SYMRDMA_PAGE_SIZE - 1) /
		 SYMRDMA_PAGE_SIZE;
	if (!np_all)
		return 0;
	for (i = 0; i < np_all; i += NPR_PRECHECK_CHUNK_PAGES) {
		unsigned long np = np_all - i;
		unsigned long k;

		if (np > NPR_PRECHECK_CHUNK_PAGES)
			np = NPR_PRECHECK_CHUNK_PAGES;
		if (npr_version_read_mr(m, va + i * SYMRDMA_PAGE_SIZE, v, np)) {
   npr_precheck_fail_trace("version-read",face,m,va,len,i);return -1;
  }
		for (k = 0; k < np; k++) {
			if (v[k] & 1u)
				continue;
			if (debug_on())
				fprintf(stderr,
					"[nprdma] precheck %s m=%p va=0x%llx len=%llu page=%lu absent - pin\n",
					face, (void *)m, (unsigned long long)va,
					(unsigned long long)len, i + k);
            if (h->pin(h->ctx,m,va,len)) {
                npr_precheck_fail_trace("holder-pin",face,m,va,len,i+k);
                npr_engine_stat_inc(NPRDMA_ES_PRE_PIN_FAIL);
                return -1;
            }
            npr_engine_stat_inc(NPRDMA_ES_PRE_PIN_TAKEN);
			*absent = 1;
			return 0;
		}
	}
	return 0;
}

NPRDMA_INTERNAL int npr_precheck(const struct npr_op *op,
				 const struct npr_preholder *h, int *absent)
{
	const struct mr_entry *m;
	uint64_t va;

	if (!absent || !h || !op || !op->len)
		return -1;
	*absent = 0;
	/* The local buffer the NIC touches through an lkey - a read's
	 * sink, a write's source. Both are where an evicted page is still
	 * sentinel-mapped while the CPU has already faulted it back in, so a
	 * write's payload can quietly be the sentinel magic and a read's sink
	 * can silently drop the incoming DMA unless this face is judged. */
 if(npr_op_is_read(op)||(npr_op_is_write(op)&&!op->inline_)) {
  if(!npr_sg_valid(op))return -1;
  for(unsigned i=0;i<op->num_sge;i++) {
   if(!op->sge[i].length)continue;
   m=npr_mr_for_op(op,i);va=op->sge[i].addr;
   if(npr_precheck_face(m,va,op->sge[i].length,
       npr_op_is_read(op)?"sink":"src",h,absent))return -1;
  }
 }
 /* Remote keys belong to the peer's namespace. Only the owner/SIR path
  * may judge that target; numeric equality never identifies our own MR. */
	return 0;
}

/* Passthrough has no repair carrier: absent faces fail before native emit.
 * Failed preparation owns cleanup by object identity, never application wr_id. */
static int npr_passthrough_precheck(struct ibv_qp *qp,const struct npr_op *op)
{
 struct npr_sr_owner *owner=NULL;int absent=0,rc;
 struct npr_preholder holder={.pin=npr_sr_hold_pin};
 if(npr_sr_owner_create(qp,&owner))return -1;
 holder.ctx=owner;
 rc=npr_precheck(op,&holder,&absent);
 npr_sr_discard(owner);
 return rc||absent?-1:0;
}

struct symrdma_ctx_entry {
 int (*real_post_recv)(struct ibv_qp *,struct ibv_recv_wr *,struct ibv_recv_wr **);
	struct ibv_context *ctx;
	int (*real_post_send)(struct ibv_qp *qp, struct ibv_send_wr *wr,
			      struct ibv_send_wr **bad_wr);
	struct symrdma_ctx_entry *next;
};
static struct symrdma_ctx_entry *ctx_list;
static void symrdma_forget_context(struct ibv_context *ctx)
{
 struct symrdma_ctx_entry **p,*old;
 for(p=&ctx_list;(old=*p);p=&old->next) if(old->ctx==ctx) {*p=old->next;free(old);break;}
 /* Invalid close-with-live-MRs must not make old key identities visible to a
  * reused provider context. Metadata is quarantined, not provider-deregistered
  * through the already closed device. Normal valid close finds no entries. */
 pthread_mutex_lock(&lock);
 { struct mr_entry **m=&mr_list,*e;
  while((e=*m)) {
   if(e->context_identity==ctx) {*m=e->next;e->next=NULL;}
   else m=&e->next;
  }
 }
 g_memo_lkey=NULL;
 pthread_mutex_unlock(&lock);
}


static int symrdma_poll_cq_impl(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc);
static int symrdma_poll_cq(struct ibv_cq *cq, int num_entries, struct ibv_wc *wc)
{ int rc; if(npr_progress_internal() || sir_is_internal_cq(cq)) return symrdma_poll_cq_impl(cq,num_entries,wc); npr_progress_lock(); rc=symrdma_poll_cq_impl(cq,num_entries,wc); int wake=rc>0&&!npr_progress_cq_caller_driven(cq); npr_progress_unlock(); if(wake)npr_progress_wake(); return rc; }
static int symrdma_poll_cq_impl(struct ibv_cq *cq, int num_entries,
			   struct ibv_wc *wc)
{
	struct npr_ctx_entry *ce;
	struct npr_cq_entry *cqe;

	for (ce = npr_ctx_list; ce; ce = ce->next)
		if (ce->ctx == cq->context)
			break;
	if (!ce || !ce->real_poll_cq)
		return 0;

	if (sir_is_internal_cq(cq))
		return ce->real_poll_cq(cq, num_entries, wc);
	cqe = npr_cq_get(ce, cq);
	return npr_poll_verified_cq(ce,cqe,num_entries,wc);
}

int npr_order_raw_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp, struct npr_op *op)
{
 struct npr_op native;struct ibv_sge sg[NPR_OP_MAX_SGE];
 struct npr_sr_owner *hold=NULL;struct npr_identity *id;
 struct npr_identity_spec spec;unsigned i;int rc;
 if(!ce||!qp||!op||op->num_sge>NPR_OP_MAX_SGE)return EINVAL;
 if(npr_op_is_write(op)) {
  uint32_t wk;rc=npr_write_key(op,&wk);
  if(rc==NPR_WRITE_KEY_NONE)return EACCES;
  op->wkey=rc==NPR_WRITE_KEY_FOREIGN?op->rkey:wk;
 }
 native=*op;
 spec=(struct npr_identity_spec){.kind=op->order?NPR_ID_ORDER:NPR_ID_PASS,.lane=NPR_LANE_SQ,
  .user_wr_id=op->wr_id,.visible=op->signaled||npr_qp_sig_all(ce,qp),.order=op->order,
  .opcode=npr_op_is_read(op)?IBV_WC_RDMA_READ:op->kind==NPR_OP_ATOMIC?
   (op->atom_cas?IBV_WC_COMP_SWAP:IBV_WC_FETCH_ADD):IBV_WC_RDMA_WRITE};
 id=npr_identity_prepare(ce,qp,qp->send_cq,&spec);if(!id)return errno?errno:ENOMEM;
 if(op->order)npr_order_get(op->order);
 for(i=0;i<op->num_sge;i++)sg[i]=(struct ibv_sge){.addr=op->sge[i].addr,.length=op->sge[i].length,.lkey=op->sge[i].lkey};
 /* A foreign/native target has no SIR repair channel. Keep every adopted
  * local DMA span real for the entire provider operation, including spans
  * that happened to be resident at admission. Ordinary native MRs pass through. */
 rc=npr_sr_prepare_op(qp,op,sg,op->inline_?0:op->num_sge,npr_op_local_sink(op),&hold,!!op->rdv_owner);
 id->spec.resource=hold;id->spec.release=npr_sr_release;
 if(op->rdv_owner&&hold){npr_rdv_source_data_hold(op->rdv_owner);id->spec.rdv_owner=op->rdv_owner;id->spec.rdv_done=npr_rdv_source_data_done;}
 if(rc){npr_identity_abort(id);if(op->order)npr_order_put(op->order);return rc;}
 for(i=0;i<op->num_sge;i++)native.sge[i].lkey=sg[i].lkey;
 rc=npr_emit_prepared(ce,qp,&native,id);
 if(rc&&op->order)npr_order_put(op->order);
 return rc;
}

/* Native fallback is only for requests outside the supported IR. An adopted
 * local buffer or a known SymRDMA remote target needs a judgement shape and
 * cannot be silently emitted with public keys. Other opcode unions are opaque. */
static int npr_native_fallback_guard(struct ibv_qp *qp,const struct ibv_send_wr *wr)
{
 struct npr_op probe={0};int i,rc;
 for(i=0;wr->sg_list&&i<wr->num_sge;i++){
  if(!(wr->send_flags&IBV_SEND_INLINE)&&wr->sg_list[i].length&&
     npr_mr_admission_closing(qp->pd,wr->sg_list[i].lkey))return EACCES;
  if(npr_mr_by_lkey(wr->sg_list[i].lkey))return EOPNOTSUPP;
 }
 switch(wr->opcode){
 case IBV_WR_RDMA_READ:probe.kind=NPR_OP_READ;probe.rkey=wr->wr.rdma.rkey;break;
 case IBV_WR_RDMA_WRITE:case IBV_WR_RDMA_WRITE_WITH_IMM:
  probe.kind=NPR_OP_WRITE;probe.rkey=wr->wr.rdma.rkey;break;
 case IBV_WR_ATOMIC_CMP_AND_SWP:case IBV_WR_ATOMIC_FETCH_AND_ADD:
  probe.kind=NPR_OP_ATOMIC;probe.rkey=wr->wr.atomic.rkey;break;
 default:return 0;
 }
 rc=npr_resolve_remote(&probe);if(rc)return rc;
 return probe.remote_state==NPR_REMOTE_FOREIGN?0:EOPNOTSUPP;
}

static int symrdma_post_send_impl(struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr);
static int symrdma_post_send(struct ibv_qp *qp, struct ibv_send_wr *wr, struct ibv_send_wr **bad_wr)
{
 struct npr_ctx_entry *ce;int rc;
 if(npr_progress_internal()||sir_is_internal_qp(qp))return symrdma_post_send_impl(qp,wr,bad_wr);
 npr_progress_lock();ce=npr_ctx_get(qp->context);rc=npr_posting_enter(ce);
 if(rc){if(bad_wr)*bad_wr=wr;}else{rc=symrdma_post_send_impl(qp,wr,bad_wr);npr_posting_leave(ce);}
 /* Clean public event CQs are driven by the native fd/getter. Deferred
  * descriptors and autonomous identities keep the original background path. */
 int wake=rc||!ce||ce->closing||ce->posting_blocked||!npr_progress_cq_caller_driven(qp->send_cq);
 npr_progress_unlock();if(wake)npr_progress_wake();return rc;
}
static int symrdma_post_send_impl(struct ibv_qp *qp, struct ibv_send_wr *wr,
			     struct ibv_send_wr **bad_wr)
{
	int (*real)(struct ibv_qp *, struct ibv_send_wr *,
		    struct ibv_send_wr **) = NULL;
	struct symrdma_ctx_entry *dce;
	struct npr_ctx_entry *nce = NULL;
	struct ibv_send_wr *w;

	if (sir_is_internal_qp(qp)) {
		for (dce = ctx_list; dce; dce = dce->next)
			if (dce->ctx == qp->context)
				real = dce->real_post_send;
		if (real)
			return real(qp, wr, bad_wr);
	}

	for (dce = ctx_list; dce; dce = dce->next)
		if (dce->ctx == qp->context) {
			real = dce->real_post_send;
			break;
		}
	if (!real)
		return ENOSYS;
	for (nce = npr_ctx_list; nce; nce = nce->next)
		if (nce->ctx == qp->context)
			break;
	if (!nce)
		nce = npr_ctx_get(qp->context);
 if(!nce){if(bad_wr)*bad_wr=wr;return ENOMEM;}

	for (w = wr; w; w = w->next) {
		struct ibv_send_wr one = *w, *bad = NULL;
		struct npr_op op;
		int ret;

		one.next = NULL;
	one.send_flags &= ~NPR_ORDER_HINT_MASK;
		if (npr_op_from_wr(qp, w, &op) == 0) {
   if(op.num_sge>NPR_OP_MAX_SGE)goto native_fallback;
			ret=npr_order_submit(nce,qp,&op);
			if(ret>0) continue;
			if(ret<0) {*bad_wr=w;return -ret;}
   if(npr_op_is_send(&op)){*bad_wr=w;return EINVAL;}
			if (op.kind == NPR_OP_ATOMIC) {

				int rc;

				if (npr_batch_write_barrier(nce, qp, op.remote_addr,
							    op.len)) {
					*bad_wr = w;
					return EBUSY;
				}
				rc = npr_atomic_submit(nce, qp, &op);
				if (rc == 1)
					continue;
				if (rc < 0) {
					*bad_wr = w;
					return EINVAL;
				}
			} else {
				int took = (op.kind == NPR_OP_WRITE_IMM) ?
					   npr_wwi_submit(nce, qp, &op) :
					   npr_engine_submit(nce, qp, &op);

				if (took > 0)
					continue;
				if (took < 0) {
					/* the engine decided this op's lane but
					 * could not establish its judgement:
					 * fail-closed, never post it unverified */
					*bad_wr = w;
					return EINVAL;
				}

				if (npr_op_is_write(&op) &&
				    npr_batch_write_barrier(nce, qp, op.remote_addr,
							    op.len)) {
					*bad_wr = w;
					return EBUSY;
				}
				if (npr_op_is_write(&op)) {
					uint32_t wk;
					int wkr = npr_write_key(&op, &wk);

					if (wkr == NPR_WRITE_KEY_NONE) {
						/* the target is ours and has no write
						 * view: the read key is never a write
						 * key, so this write is rejected */
						npr_engine_stat_inc(NPRDMA_ES_WRITE_NO_WKEY);
						*bad_wr = w;
						return EINVAL;
					}
					if (wkr == NPR_WRITE_KEY_FOREIGN) {
						/* a bare app's own key: nothing here
						 * to re-key against */
						npr_engine_stat_inc(NPRDMA_ES_WRITE_KEY_FOREIGN);
					} else {
						one.wr.rdma.rkey = wk;
					}
				}
				if (npr_passthrough_precheck(qp,&op)) {
					/* fail-closed: the face could not be made real, so
					 * the op is never posted as if it had been checked */
					*bad_wr = w;
					return EINVAL;
				}
			}
		}

native_fallback:
  {
   ret=npr_native_fallback_guard(qp,w);if(ret){*bad_wr=w;return ret;}
   struct npr_identity_spec spec={.kind=NPR_ID_PASS,.lane=NPR_LANE_SQ,
    .user_wr_id=w->wr_id,.visible=!!(w->send_flags&IBV_SEND_SIGNALED)||npr_qp_sig_all(nce,qp)};
   switch(w->opcode){
    case IBV_WR_RDMA_READ:spec.opcode=IBV_WC_RDMA_READ;break;
    case IBV_WR_RDMA_WRITE:case IBV_WR_RDMA_WRITE_WITH_IMM:spec.opcode=IBV_WC_RDMA_WRITE;break;
    case IBV_WR_ATOMIC_CMP_AND_SWP:spec.opcode=IBV_WC_COMP_SWAP;break;
    case IBV_WR_ATOMIC_FETCH_AND_ADD:spec.opcode=IBV_WC_FETCH_ADD;break;
    default:spec.opcode=IBV_WC_SEND;break;
   }
   struct npr_identity *id=npr_identity_prepare(nce,qp,qp->send_cq,&spec);
   if(!id){*bad_wr=w;return errno?errno:ENOMEM;}
   one.wr_id=id->token;one.send_flags|=IBV_SEND_SIGNALED;
   ret=real(qp,&one,&bad);
   if(ret)npr_identity_abort(id);else npr_identity_accept(id);
  }
		if (ret) {
			*bad_wr = w;
			return ret;
		}
	}
	return 0;
}

static int symrdma_post_recv(struct ibv_qp *qp,struct ibv_recv_wr *wr,struct ibv_recv_wr **bad_wr)
{
 struct symrdma_ctx_entry *saved;struct npr_ctx_entry *ce=NULL;
 struct ibv_recv_wr *w;int rc=ENOSYS,borrowed=0;
 int (*real)(struct ibv_qp *,struct ibv_recv_wr *,struct ibv_recv_wr **)=NULL;
 if(npr_progress_internal()||sir_is_internal_qp(qp)){
  for(saved=ctx_list;saved;saved=saved->next)if(saved->ctx==qp->context){real=saved->real_post_recv;break;}
  return real?real(qp,wr,bad_wr):ENOSYS;
 }
 npr_progress_lock();
 ce=npr_ctx_get(qp->context);if(!ce){if(bad_wr)*bad_wr=wr;rc=ENOMEM;goto out;}
 rc=npr_posting_enter(ce);if(rc){if(bad_wr)*bad_wr=wr;goto out;}borrowed=1;
 if(npr_rdv_post_recv(ce,qp,wr,bad_wr,&rc))goto out;
 for(saved=ctx_list;saved;saved=saved->next)if(saved->ctx==qp->context){real=saved->real_post_recv;break;}
 if(!real){if(bad_wr)*bad_wr=wr;rc=ENOSYS;goto out;}
 for(w=wr;w;w=w->next){
  struct ibv_recv_wr one=*w,*bad=NULL;struct ibv_sge *sg=NULL;
  struct npr_sr_owner *hold=NULL;struct npr_identity *id;
  struct npr_identity_spec spec={.kind=NPR_ID_RECV,.lane=NPR_LANE_RQ,.visible=1,.user_wr_id=w->wr_id,.opcode=IBV_WC_RECV};
  if(w->num_sge<0||w->num_sge>1024||(w->num_sge&&!w->sg_list)){rc=EINVAL;goto fail;}
  if(w->num_sge){sg=malloc(sizeof(*sg)*(unsigned)w->num_sge);if(!sg){rc=ENOMEM;goto fail;}memcpy(sg,w->sg_list,sizeof(*sg)*(unsigned)w->num_sge);}
  id=npr_identity_prepare(ce,qp,qp->recv_cq,&spec);
  if(!id){rc=errno?errno:ENOMEM;free(sg);goto fail;}
  rc=0;
  if(qp->qp_type!=IBV_QPT_RC||qp->srq){
   int i;for(i=0;i<w->num_sge;i++)if(npr_mr_by_lkey(sg[i].lkey)||(sg[i].length&&npr_mr_admission_closing(qp->pd,sg[i].lkey))){rc=EOPNOTSUPP;break;}
  }else rc=npr_sr_prepare(qp,sg,(unsigned)w->num_sge,1,&hold);
  if(rc){npr_identity_abort(id);free(sg);goto fail;}
  id->spec.resource=hold;id->spec.release=npr_sr_release;
  one.next=NULL;one.sg_list=sg;one.wr_id=id->token;
  rc=real(qp,&one,&bad);free(sg);
  if(rc){npr_identity_abort(id);goto fail;}
  npr_identity_accept(id);
#ifdef NPRDMA_TEST_INJECT
  npr_rdv_native_recv_posted(ce,qp);
#endif
  continue;
fail:if(bad_wr)*bad_wr=w;goto out;
 }
 rc=0;
out:if(borrowed)npr_posting_leave(ce);npr_progress_unlock();npr_progress_wake();return rc;
}

static __thread int in_create_qp;
static __thread int in_create_cq;

static const struct npr_rdv_actor_ops npr_rdv_real_actor_ops={
 .register_qp=sir_app_rdv_register,.capability=sir_app_rdv_capability,.native_arrival=crdv_native_arrival,
 .offer_snapshot=crdv_offer_snapshot,.offer_reply=crdv_offer_reply,
 .close=crdv_registration_close,.free=sir_app_rdv_registration_free,
 .update_attrs=crdv_registration_update_attrs,.stats=crdv_stats_snapshot,
 .final_stats=crdv_registration_final_stats,.wake_actor=sir_app_rdv_wake
};
static void __attribute__((constructor)) npr_rdv_runtime_init(void)
{npr_rdv_service_config(&npr_rdv_real_actor_ops,CONTROL_RDV_DATA_ACTIVE);}

static void npr_application_pump(void)
{
 npr_qp_connection_progress();
 npr_sr_progress();
 npr_mr_retire_progress();
 npr_identity_progress(NULL);
 struct npr_ctx_entry *ce;
 for(ce=npr_ctx_list;ce;ce=ce->next) {
  struct npr_cq_entry *cq;
  /* Detached cleanup owns no provider pointer and remains retryable after
   * close. Native CQ polling/dispatch below requires a live open context. */
  npr_identity_progress(ce);
  if(!ce->ctx || ce->closing) continue;
  /* Application signaled WRs and explicit ordering/lifecycle drains close
   * batches. A pump pass is not a batch boundary. */
  npr_order_progress();
  for(cq=ce->cqs;cq;cq=cq->next) if(!sir_is_internal_cq(cq->cq)) {
   if(!npr_progress_cq_caller_driven(cq->cq))(void)npr_drain_cq(ce,cq);
   /* A synchronous PIN/carrier result can exist without a native CQ event.
    * Caller-driven native polling must never skip software publication. */
   npr_progress_ready(cq->cq);
  }
 }
}
static int symrdma_req_notify_cq(struct ibv_cq *cq,int solicited)
{
 int rc;
 if(npr_progress_internal() || sir_is_internal_cq(cq)) {
  struct npr_ctx_entry *ce;
  for(ce=npr_ctx_list;ce;ce=ce->next) if(ce->ctx==cq->context) break;
  return ce && ce->real_req_notify_cq ? ce->real_req_notify_cq(cq,solicited):ENOSYS;
 }
 npr_progress_lock();rc=npr_progress_notify(cq,solicited);npr_progress_unlock();return rc;
}

static int symrdma_ensure_ctx_hooks(struct ibv_context *ctx)
{
	struct symrdma_ctx_entry *e = NULL;
	struct npr_ctx_entry *ne = NULL;
	int found = 0;

	for (ne = npr_ctx_list; ne; ne = ne->next)
		if (ne->ctx == ctx)
			break;
	for (e = ctx_list; e; e = e->next)
		if (e->ctx == ctx) {
			found = 1;
			break;
		}
	if (!found && ctx->ops.post_send != symrdma_post_send) {
		e = calloc(1, sizeof(*e));
		if (!e) return ENOMEM;
		if (e) {
			e->ctx = ctx;
			e->real_post_send = ctx->ops.post_send;
			e->next = ctx_list;
			ctx_list = e;
			if (ne && !ne->real_post_send)
				ne->real_post_send = e->real_post_send;
			ctx->ops.post_send = symrdma_post_send;
			if (debug_on())
				fprintf(stderr,
					"[nprdma] replacing context->ops.post_send (paper §4.1 inline function interception)\n");
		}
	} else if (found && e && ne && !ne->real_post_send) {
		ne->real_post_send = e->real_post_send;
	}
 if(e && !e->real_post_recv && ctx->ops.post_recv!=symrdma_post_recv){
  e->real_post_recv=ctx->ops.post_recv;ctx->ops.post_recv=symrdma_post_recv;
 }
 if(ne && e && !ne->real_post_recv)ne->real_post_recv=e->real_post_recv;

	if(ne && !ne->real_req_notify_cq && ctx->ops.req_notify_cq != symrdma_req_notify_cq) {
 ne->real_req_notify_cq=ctx->ops.req_notify_cq;ctx->ops.req_notify_cq=symrdma_req_notify_cq;
 }
	if (ne && !ne->real_poll_cq && ctx->ops.poll_cq != symrdma_poll_cq) {
		ne->real_poll_cq = ctx->ops.poll_cq;
		ctx->ops.poll_cq = symrdma_poll_cq;
		if (debug_on())
			fprintf(stderr,
				"[nprdma] replacing context->ops.poll_cq (M2 CQ interception)\n");
	}
 return (!ne || !e) ? ENOMEM : 0;
}

static struct ibv_qp *ibv_create_qp_impl(struct ibv_pd *pd,struct ibv_qp_init_attr *init_attr);
struct ibv_qp *ibv_create_qp(struct ibv_pd *pd,struct ibv_qp_init_attr *init_attr)
{ struct ibv_qp *result; if(npr_progress_internal()||in_create_qp) return ibv_create_qp_impl(pd,init_attr); npr_progress_lock();result=ibv_create_qp_impl(pd,init_attr);npr_progress_unlock();return result; }
static struct ibv_qp *ibv_create_qp_impl(struct ibv_pd *pd,
                                     struct ibv_qp_init_attr *init_attr)
{
 static struct ibv_qp *(*real_fn)(struct ibv_pd *,struct ibv_qp_init_attr *);
 struct npr_qp_connection *connection;
 struct npr_ctx_entry *ce;
 struct ibv_qp_init_attr a;
 struct ibv_qp *qp;
 if(!real_fn)real_fn=dlvsym(RTLD_NEXT,"ibv_create_qp","IBVERBS_1.1");
 if(!real_fn){errno=ENOSYS;return NULL;}
 if(npr_progress_internal()||in_create_qp||!init_attr||init_attr->qp_type!=IBV_QPT_RC)
  return real_fn(pd,init_attr);
 if(init_attr->cap.max_send_wr>UINT32_MAX/3||init_attr->cap.max_recv_wr>UINT32_MAX/3){errno=EINVAL;return NULL;}
 ce=npr_ctx_get(pd->context);if(!ce){errno=ENOMEM;return NULL;}
 if(ce->closing){errno=EBUSY;return NULL;}
 pthread_mutex_lock(&lock);int rc=symrdma_ensure_ctx_hooks(pd->context);pthread_mutex_unlock(&lock);
 if(rc){errno=rc;return NULL;}
 connection=npr_qp_connection_prepare(ce,pd,init_attr->cap.max_send_wr,init_attr->sq_sig_all);
 if(!connection)return NULL;
 a=*init_attr;a.cap.max_send_wr*=3;a.cap.max_recv_wr*=3;
 /* Hidden notification WQEs need one physical SGE even when the original
  * legal application operation has zero SGEs. Keep the visible limits. */
 if(a.cap.max_send_wr&&!a.cap.max_send_sge)a.cap.max_send_sge=1;
 if(a.cap.max_recv_wr&&!a.cap.max_recv_sge)a.cap.max_recv_sge=1;
 in_create_qp=1;qp=real_fn(pd,&a);in_create_qp=0;
 struct ibv_qp_cap actual=a.cap;
 if(!qp&&(a.cap.max_send_wr!=init_attr->cap.max_send_wr||a.cap.max_recv_wr!=init_attr->cap.max_recv_wr)){
  unsigned send_sge=init_attr->cap.max_send_sge,recv_sge=init_attr->cap.max_recv_sge;
  a=*init_attr;if(a.cap.max_send_wr&&!a.cap.max_send_sge)a.cap.max_send_sge=1;if(a.cap.max_recv_wr&&!a.cap.max_recv_sge)a.cap.max_recv_sge=1;
  in_create_qp=1;qp=real_fn(pd,&a);in_create_qp=0;actual=a.cap;
  if(qp){init_attr->cap=a.cap;if(!send_sge)init_attr->cap.max_send_sge=0;if(!recv_sge)init_attr->cap.max_recv_sge=0;}
 }
 if(!qp){int saved=errno;npr_qp_connection_abort(connection);errno=saved;return NULL;}
 npr_qp_connection_caps(connection,&init_attr->cap,&actual);
 npr_qp_connection_commit(connection,qp);
 return qp;
}

static int ibv_destroy_qp_impl(struct ibv_qp *qp);
int ibv_destroy_qp(struct ibv_qp *qp)
{
 struct npr_ctx_entry *ce;int rc;
 if(npr_progress_internal()||sir_is_internal_qp(qp))return ibv_destroy_qp_impl(qp);
 npr_progress_lock();
 for(ce=npr_ctx_list;ce;ce=ce->next)if(ce->ctx==qp->context)break;
 if(ce&&(ce->posting_blocked||ce->closing)){npr_progress_unlock();return EBUSY;}
 if(ce)ce->posting_blocked++;
 rc=npr_posting_wait(ce);
 /* A concurrent context close may have won the gate while preparation was
  * finishing. Otherwise retain a lifecycle borrow across teardown yields. */
 if(!rc&&ce&&ce->closing)rc=EBUSY;
 if(!rc){
  if(ce)ce->posting_refs++;
  /* First settle the accepted prefix of any existing posting transaction.
   * The posting guard rejects new API calls; accepted engine/actor work
   * continues independently while the finite source frontier drains. */
  (void)npr_rdv_control_drain_qp(qp);
  npr_progress_quiesce();rc=ibv_destroy_qp_impl(qp);
  if(ce)npr_posting_leave(ce);
 }
 if(ce)ce->posting_blocked--;
 npr_progress_unlock();npr_progress_wake();return rc;
}
static int ibv_destroy_qp_impl(struct ibv_qp *qp)
{
	static int (*real_fn)(struct ibv_qp *);
	struct npr_ctx_entry *ne = NULL;
	uint32_t qp_num;
	int ret;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_destroy_qp", "IBVERBS_1.1");
	if (!real_fn)
		return -1;
 if(npr_progress_internal() || sir_is_internal_qp(qp)) return real_fn(qp);
	qp_num = qp->qp_num;
    struct npr_qp_connection *connection=npr_qp_connection_find(qp);
    int check=npr_qp_connection_modify_check(connection);if(check)return check;
    npr_qp_connection_destroying(connection);
	for (ne = npr_ctx_list; ne; ne = ne->next)
		if (ne->ctx == qp->context)
			break;
    struct npr_qp_state *old_state=ne?npr_qp_state_find(ne,qp):NULL;
    uint64_t old_generation=npr_identity_qp_known_generation(qp);
    struct npr_ex_rec *old_ex=ne?npr_ex_detach(ne,qp):NULL;
/* No logical cancellation before native success: a rejected destroy must
     * leave the live QP and its software owners intact. */
	ret = real_fn(qp);
    int saved_errno=errno;
    if(!ret){npr_qp_connection_stopped(connection);npr_ex_abort(old_ex);}
    else {npr_qp_connection_destroy_failed(connection);npr_ex_reattach(old_ex);}
    errno=saved_errno;
	if (ne) {
  if (!ret) {
   npr_qp_native_discard(ne,qp,qp_num,old_generation,old_state,1);
  }
 }
	if (debug_on())
		fprintf(stderr, "[nprdma] ibv_destroy_qp → %d\n", ret);
	return ret;
}

static int ibv_modify_qp_impl(struct ibv_qp *qp,struct ibv_qp_attr *attr,int attr_mask);
int ibv_modify_qp(struct ibv_qp *qp,struct ibv_qp_attr *attr,int attr_mask)
{
 struct npr_ctx_entry *ce=NULL;int result=0,reset=attr&&(attr_mask&IBV_QP_STATE)&&attr->qp_state==IBV_QPS_RESET;
 if(npr_progress_internal()||sir_is_internal_qp(qp))return ibv_modify_qp_impl(qp,attr,attr_mask);
 npr_progress_lock();
 if(reset){
  for(ce=npr_ctx_list;ce;ce=ce->next)if(ce->ctx==qp->context)break;
  if(ce&&(ce->posting_blocked||ce->closing)){npr_progress_unlock();return EBUSY;}
  if(ce)ce->posting_blocked++;
  result=npr_posting_wait(ce);
  if(!result&&ce&&ce->closing)result=EBUSY;
  if(!result){if(ce)ce->posting_refs++;npr_progress_quiesce();result=ibv_modify_qp_impl(qp,attr,attr_mask);if(ce)npr_posting_leave(ce);}
  if(ce)ce->posting_blocked--;
 }else result=ibv_modify_qp_impl(qp,attr,attr_mask);
 npr_progress_unlock();npr_progress_wake();return result;
}
static int ibv_modify_qp_impl(struct ibv_qp *qp, struct ibv_qp_attr *attr, int attr_mask)
{
	static int (*real_fn)(struct ibv_qp *, struct ibv_qp_attr *, int);
	struct npr_ctx_entry *ne;
	int rc;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_modify_qp", "IBVERBS_1.1");
	if (!real_fn) {
		errno = ENOSYS;
		return -1;
	}
    if(npr_progress_internal()||sir_is_internal_qp(qp))return real_fn(qp,attr,attr_mask);
    struct npr_qp_connection *connection=npr_qp_connection_find(qp);
    rc=npr_qp_connection_modify_check(connection);if(rc)return rc;
    struct ibv_qp_attr provider_attr;
    const struct ibv_qp_attr *app_attr=attr;
    if (attr && qp->qp_type == IBV_QPT_RC) {
        for (ne = npr_ctx_list; ne; ne = ne->next) {
            if (ne->ctx == qp->context) {
                /* Verification reads use a private MR key. The application
                 * key retains its own access bits and cannot use this right. */
                provider_attr = *attr;
                if (attr_mask & IBV_QP_ACCESS_FLAGS)
                    provider_attr.qp_access_flags |= IBV_ACCESS_REMOTE_READ;
                if ((attr_mask & IBV_QP_MAX_QP_RD_ATOMIC) && !provider_attr.max_rd_atomic)
                    provider_attr.max_rd_atomic = 1;
                if ((attr_mask & IBV_QP_MAX_DEST_RD_ATOMIC) && !provider_attr.max_dest_rd_atomic)
                    provider_attr.max_dest_rd_atomic = 1;
                attr = &provider_attr;
                break;
            }
        }
    }
    struct npr_ctx_entry *owner=NULL;
    struct npr_qp_state *old_state=NULL,*fresh=NULL;
    uint64_t generation=0;
    uint32_t number=qp->qp_num;
    int reset=app_attr&&(attr_mask&IBV_QP_STATE)&&app_attr->qp_state==IBV_QPS_RESET;
    if(reset){
     for(owner=npr_ctx_list;owner;owner=owner->next)if(owner->ctx==qp->context)break;
     if(owner&&qp->qp_type==IBV_QPT_RC){
      old_state=npr_qp_state_find(owner,qp);generation=npr_identity_qp_known_generation(qp);
      fresh=npr_qp_state_reserve(old_state?old_state->if_cap:0,old_state?old_state->sq_sig_all:0);
      if(!fresh)return ENOMEM;
     }
    }
    rc=npr_qp_connection_modify_prepare(connection,app_attr,attr_mask);if(rc){npr_qp_state_abort(fresh);return rc;}
	rc = real_fn(qp, attr, attr_mask);
	if (rc){npr_qp_connection_modify_abort(connection);npr_qp_state_abort(fresh);return rc;}
    int saved=errno;
    npr_qp_connection_modified(connection,app_attr,attr_mask);
    if(fresh){
     /* Install the new epoch before any physical release can yield. Cleanup
      * below retains the exact old state, never searches by recycled QPN. */
     npr_qp_state_commit(owner,fresh,qp);
     npr_qp_native_discard(owner,qp,number,generation,old_state,0);
    }
    errno=saved;
	for (ne = npr_ctx_list; ne; ne = ne->next)
		if (ne->ctx == qp->context) {
			npr_ex_refresh(ne, qp);
			break;
		}
	return 0;
}

static struct ibv_cq *ibv_create_cq_impl(struct ibv_context *context,int cqe,void *cq_context,struct ibv_comp_channel *channel,int comp_vector);
struct ibv_cq *ibv_create_cq(struct ibv_context *context,int cqe,void *cq_context,struct ibv_comp_channel *channel,int comp_vector)
{ struct ibv_cq *result; if(npr_progress_internal()) return ibv_create_cq_impl(context,cqe,cq_context,channel,comp_vector); npr_progress_lock();result=ibv_create_cq_impl(context,cqe,cq_context,channel,comp_vector);npr_progress_unlock();return result; }
static struct ibv_cq *ibv_create_cq_impl(struct ibv_context *context, int cqe,
			     void *cq_context, struct ibv_comp_channel *channel,
			     int comp_vector)
{
	static struct ibv_cq *(*real_fn)(struct ibv_context *, int, void *,
					 struct ibv_comp_channel *, int);
	struct ibv_cq *cq;
	struct ibv_comp_channel *provider_channel;
	int cqe_x3;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_create_cq", "IBVERBS_1.1");
	if (!real_fn)
		return NULL;

	if (in_create_cq || npr_progress_internal())
		return real_fn(context, cqe, cq_context, channel, comp_vector);

	if(cqe < 0 || cqe > INT_MAX/3) {errno=EINVAL;return NULL;}
	errno=0;
	provider_channel=npr_progress_cq_provider_channel(context,channel);
	if(!provider_channel && errno) return NULL;
	cqe_x3 = cqe * 3;
	in_create_cq = 1;
	cq = real_fn(context, cqe_x3, cq_context, provider_channel, comp_vector);
	in_create_cq = 0;
	if(!cq) {int saved=errno;npr_progress_cq_prepare_cancel(context,channel,provider_channel);errno=saved;return NULL;}
	if (cq) {
		struct npr_ctx_entry *ne = npr_ctx_get(context);

		if(!ne) {
   int (*destroy)(struct ibv_cq *)=dlvsym(RTLD_NEXT,"ibv_destroy_cq","IBVERBS_1.1");
   if(destroy) {destroy(cq);} npr_progress_cq_prepare_cancel(context,channel,provider_channel);errno=ENOMEM;return NULL;
  }
  if(!npr_cq_get(ne,cq)) {
   int (*destroy)(struct ibv_cq *)=dlvsym(RTLD_NEXT,"ibv_destroy_cq","IBVERBS_1.1");
   if(destroy) {destroy(cq);}
   npr_progress_cq_prepare_cancel(context,channel,provider_channel);errno=ENOMEM;return NULL;
  }
  npr_cq_note_depth(ne, cq, cqe);
  { struct npr_cq_entry *gate=npr_cq_get(ne,cq);
   if(!gate || gate->cap < (unsigned)cqe*3+NPR_GATE_SLACK ||
      !gate->ready_overflow || gate->ready_cap < (unsigned)(cq->cqe>0?cq->cqe:1)) {
    int (*destroy)(struct ibv_cq *)=dlvsym(RTLD_NEXT,"ibv_destroy_cq","IBVERBS_1.1");
    if(destroy) {destroy(cq);}
    npr_cq_destroy(ne,cq);npr_progress_cq_prepare_cancel(context,channel,provider_channel);errno=ENOMEM;return NULL;
   }
  }
  symrdma_ensure_ctx_hooks(context);
  if(npr_progress_cq_attach(cq,channel,ne) || npr_progress_start(npr_application_pump)) {
   int (*destroy)(struct ibv_cq *)=dlvsym(RTLD_NEXT,"ibv_destroy_cq","IBVERBS_1.1");
   cq->channel=provider_channel;
   if(destroy) {destroy(cq);}
   npr_progress_cq_detach(cq);if(ne)npr_cq_destroy(ne,cq);npr_progress_cq_prepare_cancel(context,channel,provider_channel);errno=ENOMEM;return NULL;
  }
		if (debug_on())
			fprintf(stderr,
				"[nprdma] ibv_create_cq → cqe %d→%d (3×, paper §4.1)\n",
				cqe, cqe_x3);
	}
	return cq;
}

static int ibv_destroy_cq_impl(struct ibv_cq *cq);
int ibv_destroy_cq(struct ibv_cq *cq)
{ int rc; if(npr_progress_internal() || sir_is_internal_cq(cq)) return ibv_destroy_cq_impl(cq); npr_progress_lock(); npr_progress_quiesce(); rc=ibv_destroy_cq_impl(cq); npr_progress_unlock(); return rc; }
static int ibv_destroy_cq_impl(struct ibv_cq *cq)
{
	static int (*real_fn)(struct ibv_cq *);
	struct npr_ctx_entry *ne = NULL;
	int ret;

	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_destroy_cq", "IBVERBS_1.1");
	if (!real_fn)
		return -1;
 if(npr_progress_internal() || sir_is_internal_cq(cq)) return real_fn(cq);
	for (ne = npr_ctx_list; ne; ne = ne->next)
		if (ne->ctx == cq->context)
			break;
 /* A provider rejects a CQ still attached to a QP before waiting for event
  * acknowledgements. Preserve that order for the public event proxy too. */
 if(npr_qp_connection_cq_live(cq))return EBUSY;
	if(ne&&npr_identity_cq_busy(ne,cq))return EBUSY;
	if(npr_progress_cq_can_destroy(cq)) return EBUSY;
 struct ibv_comp_channel *public_channel=cq->channel;
 cq->channel=npr_progress_cq_native_channel(cq);
 ret = real_fn(cq);
 if(ret) {cq->channel=public_channel;npr_progress_cq_destroy_abort(cq);}
 else npr_progress_cq_detach(cq);
	if (ne && !ret)
		npr_cq_destroy(ne, cq);
	if (debug_on())
		fprintf(stderr, "[nprdma] ibv_destroy_cq → %d\n", ret);
	return ret;
}

static struct ibv_cq_ex *(*g_real_create_cq_ex)(
	struct ibv_context *context, struct ibv_cq_init_attr_ex *cq_attr);

static struct ibv_cq_ex *symrdma_create_cq_ex(struct ibv_context *context,
					      struct ibv_cq_init_attr_ex *cq_attr)
{
	struct ibv_cq_init_attr_ex a;

	if (!g_real_create_cq_ex)
		return NULL;
	if(!npr_progress_internal()) {errno=EOPNOTSUPP;return NULL;}
	memcpy(&a, cq_attr, sizeof(a));
	a.cqe *= 3;
	if (debug_on())
		fprintf(stderr, "[nprdma] ibv_create_cq_ex → cqe %u→%u (3×)\n",
			cq_attr->cqe, a.cqe);
	return g_real_create_cq_ex(context, &a);
}

static struct ibv_qp *(*g_real_create_qp_ex)(
	struct ibv_context *context, struct ibv_qp_init_attr_ex *qp_init_attr_ex);

static struct ibv_qp *symrdma_create_qp_ex_impl(struct ibv_context *,struct ibv_qp_init_attr_ex *);
static struct ibv_qp *symrdma_create_qp_ex_all(struct ibv_context *context,struct ibv_qp_init_attr_ex *attr)
{
 if(npr_progress_internal()||in_create_qp)return symrdma_create_qp_ex_impl(context,attr);
 npr_progress_lock();struct ibv_qp *qp=symrdma_create_qp_ex_impl(context,attr);npr_progress_unlock();return qp;
}
static struct ibv_qp *symrdma_create_qp_ex_impl(
 struct ibv_context *context,struct ibv_qp_init_attr_ex *attr)
{
 struct npr_ctx_entry *ce;
 struct npr_qp_connection *connection;
 struct ibv_qp *qp;
 if(!g_real_create_qp_ex){errno=ENOSYS;return NULL;}
 if(npr_progress_internal()||in_create_qp||!attr||attr->qp_type!=IBV_QPT_RC)
  return g_real_create_qp_ex(context,attr);
 if(attr->cap.max_send_wr>UINT32_MAX/3||attr->cap.max_recv_wr>UINT32_MAX/3){errno=EINVAL;return NULL;}
 ce=npr_ctx_get(context);if(!ce){errno=ENOMEM;return NULL;}
 if(ce->closing){errno=EBUSY;return NULL;}
 pthread_mutex_lock(&lock);int rc=symrdma_ensure_ctx_hooks(context);pthread_mutex_unlock(&lock);
 if(rc){errno=rc;return NULL;}
 connection=npr_qp_connection_prepare(ce,(attr->comp_mask&IBV_QP_INIT_ATTR_PD)?attr->pd:NULL,attr->cap.max_send_wr,attr->sq_sig_all);
 if(!connection)return NULL;
 struct ibv_qp_init_attr_ex provider_attr=*attr;
 provider_attr.cap.max_send_wr*=3;provider_attr.cap.max_recv_wr*=3;
 if(provider_attr.cap.max_send_wr&&!provider_attr.cap.max_send_sge)provider_attr.cap.max_send_sge=1;
 if(provider_attr.cap.max_recv_wr&&!provider_attr.cap.max_recv_sge)provider_attr.cap.max_recv_sge=1;
 in_create_qp=1;qp=g_real_create_qp_ex(context,&provider_attr);in_create_qp=0;
 if(!qp){int saved=errno;npr_qp_connection_abort(connection);errno=saved;return NULL;}
 npr_qp_connection_caps(connection,&attr->cap,&provider_attr.cap);
 npr_qp_connection_commit(connection,qp);return qp;
}

struct ibv_context *ibv_open_device(struct ibv_device *device)
{
	static struct ibv_context *(*real_fn)(struct ibv_device *);
	struct verbs_context *vctx;
	struct ibv_context *ctx;
	if (!real_fn)
		real_fn = dlvsym(RTLD_NEXT, "ibv_open_device", "IBVERBS_1.1");
	if (!real_fn)
		return NULL;

	ctx = real_fn(device);
	if (!ctx)
		return NULL;

	vctx = (struct verbs_context *)
		((char *)ctx - offsetof(struct verbs_context, context));
	if (vctx->create_cq_ex) {
		g_real_create_cq_ex = vctx->create_cq_ex;
		vctx->create_cq_ex = symrdma_create_cq_ex;
		if (debug_on())
			fprintf(stderr,
				"[nprdma] replacing verbs_context->create_cq_ex (audit D3)\n");
	}

	if (vctx->create_qp_ex) {
		g_real_create_qp_ex = vctx->create_qp_ex;
		vctx->create_qp_ex = symrdma_create_qp_ex_all;
		if (debug_on())
			fprintf(stderr,
				"[nprdma] replacing verbs_context->create_qp_ex (ex surface takeover)\n");
	}
	return ctx;
}
