/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include "npr_progress.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>
#include <infiniband/verbs.h>

#include "nprdma_internal.h"
#include "npr_op.h"

#define NPR_EX_TABLE(X) \
	X(wr_atomic_cmp_swp) X(wr_atomic_fetch_add) X(wr_bind_mw) \
	X(wr_local_inv) X(wr_rdma_read) X(wr_rdma_write) \
	X(wr_rdma_write_imm) X(wr_send) X(wr_send_imm) X(wr_send_inv) \
	X(wr_send_tso) X(wr_set_ud_addr) X(wr_set_xrc_srqn) \
	X(wr_set_inline_data) X(wr_set_inline_data_list) X(wr_set_sge) \
	X(wr_set_sge_list) X(wr_start) X(wr_complete) X(wr_abort)

#define NPR_EX_MAX_OPS      8
#define NPR_EX_TSO_HDR_MAX  128

enum npr_ex_kind {
	NPR_EXK_RDMA_READ = 0,
	NPR_EXK_RDMA_WRITE,
	NPR_EXK_RDMA_WRITE_IMM,
	NPR_EXK_ATOMIC_CMP_SWP,
	NPR_EXK_ATOMIC_FETCH_ADD,
	NPR_EXK_SEND,
	NPR_EXK_SEND_IMM,
	NPR_EXK_SEND_INV,
	NPR_EXK_SEND_TSO,
	NPR_EXK_BIND_MW,
	NPR_EXK_LOCAL_INV,
	NPR_EXK_ATOMIC_WRITE,
	NPR_EXK_NONE,
};

struct npr_ex_op {
	uint8_t kind;
	uint8_t has_sge;
	uint8_t sge_list;
	uint8_t has_inline;
	uint8_t inline_list;
	uint8_t unsupported;
	uint32_t rkey;
	uint32_t num_sge;
	struct npr_sge sge[NPR_OP_MAX_SGE];
	uint64_t remote_addr;
	uint64_t wr_id;
	unsigned wr_flags;
	__be32 imm;
	uint64_t atom_cmp;
	uint64_t atom_swp;
	uint8_t atom_buf[16];
	struct ibv_mw *mw;
	struct ibv_mw_bind_info bind_info;
	uint8_t tso_hdr[NPR_EX_TSO_HDR_MAX];
	uint16_t tso_hdr_sz;
	uint16_t tso_mss;
	struct ibv_ah *ah;
	uint32_t remote_qpn;
	uint32_t remote_qkey;
	uint32_t xrc_srqn;

	void *inline_addr;
	size_t inline_len;
	uint64_t flush_len;
	uint8_t flush_type;
	uint8_t flush_level;
};

struct npr_ex_rec {
	struct npr_ctx_entry *ce;
	struct ibv_qp *qp;
	struct ibv_qp_ex *real;
#define NPR_EX_DECL(n) __typeof__(((struct ibv_qp_ex *)0)->n) n;
	struct {
		NPR_EX_TABLE(NPR_EX_DECL)
	} saved;
	unsigned n;
	unsigned overflow;
	unsigned dead;
	struct npr_ex_op ops[NPR_EX_MAX_OPS];
	struct npr_ex_rec *next;
};

static pthread_mutex_t g_ex_mu = PTHREAD_MUTEX_INITIALIZER;
static struct npr_ex_rec *g_ex_recs;

static struct npr_ex_rec *npr_ex_find(struct ibv_qp_ex *q)
{
	struct npr_ex_rec *r;

	pthread_mutex_lock(&g_ex_mu);
	for (r = g_ex_recs; r; r = r->next)
		if (r->real == q && !r->dead)
			break;
	pthread_mutex_unlock(&g_ex_mu);
	return r;
}

static int npr_ex_push(struct npr_ex_rec *rec, uint8_t kind)
{
	struct npr_ex_op *o;

	if (rec->overflow)
		return -1;
	if (rec->n >= NPR_EX_MAX_OPS) {
		rec->overflow = 1;
		npr_ex_count(NPR_EX_STAT_OVERFLOW);
		return -1;
	}
	o = &rec->ops[rec->n++];
	memset(o, 0, sizeof(*o));
	o->kind = kind;

	o->wr_id = rec->real->wr_id;
	o->wr_flags = rec->real->wr_flags;
	return 0;
}

static struct npr_ex_op *npr_ex_cur(struct npr_ex_rec *rec)
{
	if (!rec || !rec->n)
		return NULL;
	return &rec->ops[rec->n - 1];
}

#define REC_BODY() \
	struct npr_ex_rec *rec = npr_ex_find(q); \
	if (!rec) \
		return

static void npr_ex_wr_start(struct ibv_qp_ex *q)
{
	REC_BODY();
	if (debug_on())
		fprintf(stderr, "[nprdma] ex wr_start (rec=%p)\n", (void *)rec);
	rec->n = 0;
	rec->overflow = 0;
}

static void npr_ex_wr_abort(struct ibv_qp_ex *q)
{
	REC_BODY();
	if (debug_on())
		fprintf(stderr, "[nprdma] ex wr_abort\n");
	rec->n = 0;
	rec->overflow = 0;
}

static void npr_ex_wr_rdma_read(struct ibv_qp_ex *q, uint32_t rkey,
				uint64_t addr)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_RDMA_READ))
		return;
	o = npr_ex_cur(rec);
	o->rkey = rkey;
	o->remote_addr = addr;
}

static void npr_ex_wr_rdma_write(struct ibv_qp_ex *q, uint32_t rkey,
				 uint64_t addr)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_RDMA_WRITE))
		return;
	o = npr_ex_cur(rec);
	o->rkey = rkey;
	o->remote_addr = addr;
}

static void npr_ex_wr_rdma_write_imm(struct ibv_qp_ex *q, uint32_t rkey,
				     uint64_t addr, __be32 imm)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_RDMA_WRITE_IMM))
		return;
	o = npr_ex_cur(rec);
	o->rkey = rkey;
	o->remote_addr = addr;
	o->imm = imm;
}

static void npr_ex_wr_atomic_cmp_swp(struct ibv_qp_ex *q, uint32_t rkey,
				     uint64_t addr, uint64_t compare,
				     uint64_t swap)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_ATOMIC_CMP_SWP))
		return;
	o = npr_ex_cur(rec);
	o->rkey = rkey;
	o->remote_addr = addr;
	o->atom_cmp = compare;
	o->atom_swp = swap;
}

static void npr_ex_wr_atomic_fetch_add(struct ibv_qp_ex *q, uint32_t rkey,
				       uint64_t addr, uint64_t add)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_ATOMIC_FETCH_ADD))
		return;
	o = npr_ex_cur(rec);
	o->rkey = rkey;
	o->remote_addr = addr;
	o->atom_swp = add;
}

static void npr_ex_wr_send(struct ibv_qp_ex *q)
{
	REC_BODY();
	(void)npr_ex_push(rec, NPR_EXK_SEND);
}

static void npr_ex_wr_send_imm(struct ibv_qp_ex *q, __be32 imm)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_SEND_IMM))
		return;
	o = npr_ex_cur(rec);
	o->imm = imm;
}

static void npr_ex_wr_send_inv(struct ibv_qp_ex *q, uint32_t rkey)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_SEND_INV))
		return;
	o = npr_ex_cur(rec);
	o->rkey = rkey;
}

static void npr_ex_wr_send_tso(struct ibv_qp_ex *q, void *hdr, uint16_t hdr_sz,
			       uint16_t mss)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_SEND_TSO))
		return;
	o = npr_ex_cur(rec);
	if (hdr_sz > NPR_EX_TSO_HDR_MAX) {

		o->unsupported = 1;
		npr_ex_count(NPR_EX_STAT_UNSUPPORTED);
		return;
	}
	if (hdr && hdr_sz)
		memcpy(o->tso_hdr, hdr, hdr_sz);
	o->tso_hdr_sz = hdr_sz;
	o->tso_mss = mss;
}

static void npr_ex_wr_bind_mw(struct ibv_qp_ex *q, struct ibv_mw *mw,
			      uint32_t rkey,
			      const struct ibv_mw_bind_info *bind_info)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_BIND_MW))
		return;
	o = npr_ex_cur(rec);
	o->mw = mw;
	o->rkey = rkey;
	if (bind_info)
		o->bind_info = *bind_info;
}

static void npr_ex_wr_local_inv(struct ibv_qp_ex *q, uint32_t rkey)
{
	struct npr_ex_op *o;

	REC_BODY();
	if (npr_ex_push(rec, NPR_EXK_LOCAL_INV))
		return;
	o = npr_ex_cur(rec);
	o->rkey = rkey;
}

static void npr_ex_wr_set_ud_addr(struct ibv_qp_ex *q, struct ibv_ah *ah,
				  uint32_t remote_qpn, uint32_t remote_qkey)
{
	struct npr_ex_op *o;

	REC_BODY();
	o = npr_ex_cur(rec);
	if (!o)
		return;
	o->ah = ah;
	o->remote_qpn = remote_qpn;
	o->remote_qkey = remote_qkey;
}

static void npr_ex_wr_set_xrc_srqn(struct ibv_qp_ex *q, uint32_t srqn)
{
	struct npr_ex_op *o;

	REC_BODY();
	o = npr_ex_cur(rec);
	if (o)
		o->xrc_srqn = srqn;
}

static void npr_ex_wr_set_inline_data(struct ibv_qp_ex *q, void *addr,
				      size_t length)
{
	struct npr_ex_op *o;

	REC_BODY();
	o = npr_ex_cur(rec);
	if (!o)
		return;
	o->has_inline = 1;
	o->inline_list = 0;
	o->inline_addr = addr;
	o->inline_len = length;
}

static void npr_ex_wr_set_inline_data_list(struct ibv_qp_ex *q, size_t num,
					   const struct ibv_data_buf *list)
{
	struct npr_ex_op *o;

	REC_BODY();
	o = npr_ex_cur(rec);
	if (!o)
		return;
	o->has_inline = 1;
	o->inline_list = 1;
	o->inline_addr = (void *)(uintptr_t)list;
	o->inline_len = num;
}

static void npr_ex_wr_set_sge(struct ibv_qp_ex *q, uint32_t lkey, uint64_t addr,
			      uint32_t length)
{
	struct npr_ex_op *o;

	REC_BODY();
	o = npr_ex_cur(rec);
	if (!o)
		return;
	o->has_sge = 1;
	o->sge_list = 0;
	o->num_sge = 1;
	o->sge[0].addr = addr;
	o->sge[0].length = length;
	o->sge[0].lkey = lkey;
}

static void npr_ex_wr_set_sge_list(struct ibv_qp_ex *q, size_t num,
				   const struct ibv_sge *list)
{
	struct npr_ex_op *o;
	size_t i;

	REC_BODY();
	o = npr_ex_cur(rec);
	if (!o)
		return;
	o->has_sge = 1;
	o->sge_list = 1;
	if (num > NPR_OP_MAX_SGE) {

		o->unsupported = 1;
		npr_ex_count(NPR_EX_STAT_UNSUPPORTED);
		return;
	}
	o->num_sge = (uint32_t)num;
	for (i = 0; i < num; i++) {
		o->sge[i].addr = list[i].addr;
		o->sge[i].length = list[i].length;
		o->sge[i].lkey = list[i].lkey;
	}
}

static void npr_ex_to_ir(const struct npr_ex_op *o, struct npr_op *op)
{
	unsigned i;

	memset(op, 0, sizeof(*op));
	op->kind = (o->kind == NPR_EXK_RDMA_READ) ? NPR_OP_READ :
		   (o->kind == NPR_EXK_RDMA_WRITE_IMM) ? NPR_OP_WRITE_IMM :
		   (o->kind == NPR_EXK_RDMA_WRITE) ? NPR_OP_WRITE :
    (o->kind == NPR_EXK_SEND) ? NPR_OP_SEND :
    (o->kind == NPR_EXK_SEND_IMM) ? NPR_OP_SEND_IMM : NPR_OP_ATOMIC;
	op->remote_addr = o->remote_addr;
	op->rkey = o->rkey;
	op->wr_id = o->wr_id;
	op->signaled = (o->wr_flags & IBV_SEND_SIGNALED) != 0;
	op->inline_ = (o->wr_flags & IBV_SEND_INLINE) != 0;
	op->flags = o->wr_flags &
		    ~(unsigned)(IBV_SEND_SIGNALED | IBV_SEND_INLINE);
	op->imm = o->imm;
	if (o->kind == NPR_EXK_ATOMIC_CMP_SWP ||
	    o->kind == NPR_EXK_ATOMIC_FETCH_ADD) {
		op->atom_cas = (o->kind == NPR_EXK_ATOMIC_CMP_SWP);
		op->atom_compare_add = op->atom_cas ? o->atom_cmp : o->atom_swp;
		op->atom_swap = o->atom_swp;
	}
	op->num_sge = o->num_sge;
	for (i = 0; i < o->num_sge && i < NPR_OP_MAX_SGE; i++) {
		op->sge[i].addr = o->sge[i].addr;
		op->sge[i].length = o->sge[i].length;
		op->sge[i].lkey = o->sge[i].lkey;
		op->len += o->sge[i].length;
	}
	if (o->has_inline) {
		op->sge[0].addr = (uint64_t)(uintptr_t)o->inline_addr;
		op->sge[0].length = (uint32_t)o->inline_len;
		op->len = o->inline_len;
		op->num_sge = 1;
		op->inline_ = 1;
	}
}

static int npr_ex_materialize(struct npr_ex_rec *rec, const struct npr_ex_op *o)
{
	struct npr_op op;
	struct npr_ex_op normalized = *o;
	int took;
	int ordered_kind = o->kind == NPR_EXK_RDMA_READ ||
		o->kind == NPR_EXK_RDMA_WRITE || o->kind == NPR_EXK_RDMA_WRITE_IMM ||
		o->kind == NPR_EXK_ATOMIC_CMP_SWP || o->kind == NPR_EXK_ATOMIC_FETCH_ADD ||
  o->kind == NPR_EXK_SEND || o->kind == NPR_EXK_SEND_IMM;

	if (o->unsupported)
		return EOPNOTSUPP;
	/* Normalize descriptor lists before admission. Both the ordering core and
	 * the ordinary engine consume SGEs, never the descriptor bytes as data. */
	if (ordered_kind && o->has_inline && o->inline_list) {
		const struct ibv_data_buf *list = o->inline_addr;
		size_t i, len = 0;

		if (o->inline_len > NPR_OP_MAX_SGE || (o->inline_len && !list))
			return EINVAL;
		for (i = 0; i < o->inline_len; i++) {
			if (list[i].length > UINT32_MAX - len ||
			    (list[i].length && !list[i].addr))
				return EINVAL;
			len += list[i].length;
			normalized.sge[i].addr = (uintptr_t)list[i].addr;
			normalized.sge[i].length = list[i].length;
			normalized.sge[i].lkey = 0;
		}
		normalized.has_inline = 0;
		normalized.num_sge = o->inline_len;
		normalized.wr_flags |= IBV_SEND_INLINE;
	}
	o = &normalized;
	/* Accepted admission owns all descriptors and inline contents before
	 * returning, even when the operation remains queued after wr_complete. */
	if (ordered_kind) {
		npr_ex_to_ir(o, &op);
		took = npr_order_submit(rec->ce, rec->qp, &op);
		if (took < 0)
			return -took;
		if (took == 1) {
			npr_ex_count(NPR_EX_STAT_TAKEOVER);
			return 0;
		}
	}
 /* This managed session cannot be split into native per-operation posting:
  * wr_complete failure must abort the entire session. Non-IR opcodes are
  * rejected before commit; ordinary legacy native posting remains available. */
 return EOPNOTSUPP;
}

static int npr_ex_wr_complete_impl(struct ibv_qp_ex *q);
static int npr_ex_wr_complete(struct ibv_qp_ex *q)
{
 int rc;struct npr_ex_rec *rec;
 npr_progress_lock();rec=npr_ex_find(q);
 if(!rec) rc=EINVAL;
 else if((rc=npr_posting_enter(rec->ce))) rec->n=0;
 else {rc=npr_ex_wr_complete_impl(q);npr_posting_leave(rec->ce);}
 int wake=rc||!rec||rec->ce->closing||rec->ce->posting_blocked||!npr_progress_cq_caller_driven(rec->qp->send_cq);
 npr_progress_unlock();if(wake)npr_progress_wake();return rc;
}
static int npr_ex_wr_complete_impl(struct ibv_qp_ex *q)
{
	struct npr_ex_rec *rec = npr_ex_find(q);
	unsigned i;
	int rc = 0;

	if (!rec)
		return EINVAL;
	if (rec->overflow) {
		rec->n = 0;
		rec->overflow = 0;
		return ENOBUFS;
	}
	if (debug_on())
		fprintf(stderr, "[nprdma] ex wr_complete n=%u\n", rec->n);

	if (rec->n) {
		rec->ops[rec->n - 1].wr_id = rec->real->wr_id;
		rec->ops[rec->n - 1].wr_flags = rec->real->wr_flags;
	}
 if(!rec->n) return 0;
 if(rec->qp->qp_type!=IBV_QPT_RC) {rec->n=0;return EOPNOTSUPP;}
 rc=npr_order_batch_begin();
 if(rc) {rec->n=0;return rc;}
 for(i=0;i<rec->n;i++) {
  rc=npr_ex_materialize(rec,&rec->ops[i]);
  if(rc) break;
 }
 rec->n=0;
 if(rc) {npr_order_batch_abort();return rc;}
 return npr_order_batch_commit();
}

#define NPR_EX_SAVE(n)  rec->saved.n = real->n;
#define NPR_EX_HOOK(n)  real->n = npr_ex_##n;

NPRDMA_INTERNAL struct npr_ex_rec *npr_ex_reserve(void)
{ return calloc(1,sizeof(struct npr_ex_rec)); }
NPRDMA_INTERNAL void npr_ex_abort(struct npr_ex_rec *rec)
{ free(rec); }
NPRDMA_INTERNAL void npr_ex_install_reserved(struct npr_ctx_entry *ce,struct ibv_qp *qp,struct npr_ex_rec *rec)
{
 struct ibv_qp_ex *real=ibv_qp_to_qp_ex(qp);
 if(!real||npr_ex_find(real)){free(rec);return;}
	rec->ce = ce;
	rec->qp = qp;
	rec->real = real;
	NPR_EX_TABLE(NPR_EX_SAVE)
	NPR_EX_TABLE(NPR_EX_HOOK)
	pthread_mutex_lock(&g_ex_mu);
	rec->next = g_ex_recs;
	g_ex_recs = rec;
	pthread_mutex_unlock(&g_ex_mu);
	npr_ex_count(NPR_EX_STAT_INSTALL);
	if (debug_on())
		fprintf(stderr,
			"[nprdma] ex surface wrapped in place (qp_num=%u; provider table %p)\n",
			qp->qp_num, (void *)real);
}
NPRDMA_INTERNAL int npr_ex_install(struct npr_ctx_entry *ce,struct ibv_qp *qp)
{
 if(!ce||!qp)return -1;
 struct ibv_qp_ex *real=ibv_qp_to_qp_ex(qp);
 if(!real)return 1;
 if(npr_ex_find(real))return 0;
 struct npr_ex_rec *rec=npr_ex_reserve();if(!rec)return -1;
 npr_ex_install_reserved(ce,qp,rec);return 0;
}

NPRDMA_INTERNAL void npr_ex_refresh(struct npr_ctx_entry *ce, struct ibv_qp *qp)
{
	struct ibv_qp_ex *real;
	struct npr_ex_rec *rec;

	(void)ce;
	if (!qp)
		return;
	real = ibv_qp_to_qp_ex(qp);
	if (!real)
		return;
	rec = npr_ex_find(real);
	if (!rec)
		return;
#define NPR_EX_RESYNC(n) \
	do { \
		if ((void *)real->n != (void *)npr_ex_##n) \
			rec->saved.n = real->n; \
		real->n = npr_ex_##n; \
	} while (0);
	NPR_EX_TABLE(NPR_EX_RESYNC)
#undef NPR_EX_RESYNC
	if (debug_on())
		fprintf(stderr, "[nprdma] ex table re-aligned after modify_qp (qp_num=%u)\n",
			qp->qp_num);
}

NPRDMA_INTERNAL struct npr_ex_rec *npr_ex_detach(struct npr_ctx_entry *ce, struct ibv_qp *qp)
{
	struct npr_ex_rec **pp, *rec;
	struct ibv_qp_ex *real;

	(void)ce;
	if (!qp)
		return NULL;
	pthread_mutex_lock(&g_ex_mu);
	for (pp = &g_ex_recs; *pp; pp = &(*pp)->next)
		if ((*pp)->qp == qp)
			break;
	rec = *pp;
	if (rec)
		*pp = rec->next;
	pthread_mutex_unlock(&g_ex_mu);
	if (!rec)
		return NULL;
	rec->dead = 1;

	real = rec->real;
	if (real) {
#define NPR_EX_RESTORE(n)  real->n = rec->saved.n;
		NPR_EX_TABLE(NPR_EX_RESTORE)
#undef NPR_EX_RESTORE
	}
 return rec;
}
NPRDMA_INTERNAL void npr_ex_reattach(struct npr_ex_rec *rec)
{
 if(!rec)return;
 struct ibv_qp_ex *real=rec->real;
 rec->dead=0;
 NPR_EX_TABLE(NPR_EX_HOOK)
 pthread_mutex_lock(&g_ex_mu);rec->next=g_ex_recs;g_ex_recs=rec;pthread_mutex_unlock(&g_ex_mu);
}
NPRDMA_INTERNAL void npr_ex_uninstall(struct npr_ctx_entry *ce,struct ibv_qp *qp)
{npr_ex_abort(npr_ex_detach(ce,qp));}
