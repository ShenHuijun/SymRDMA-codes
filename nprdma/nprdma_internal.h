/* SPDX-License-Identifier: GPL-2.0 */

#ifndef NPRDMA_INTERNAL_H
#define NPRDMA_INTERNAL_H

#if defined(__GNUC__)
#define NPRDMA_INTERNAL __attribute__((visibility("hidden")))
#else
#define NPRDMA_INTERNAL
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <infiniband/verbs.h>
#include "symrdma_abi.h"
#include "sentinel.h"
#include "detect.h"
#include "repair_policy.h"
#include "sir.h"
#include "libnprdma.h"
#include "npr_op.h"
#include "npr_order.h"

extern int sir_is_internal_qp(const struct ibv_qp *qp);
extern int sir_is_internal_cq(const struct ibv_cq *cq);

extern NPRDMA_INTERNAL int sym_fd;

extern NPRDMA_INTERNAL struct ibv_mr *(*g_real_reg_mr_iova2)(struct ibv_pd *, void *, size_t,
					     uint64_t, unsigned int);

NPRDMA_INTERNAL int debug_on(void);
static inline void npr_log_emit_buf(const char *buf, size_t n)
{
	size_t off = 0;

	while (off < n) {
		ssize_t r = write(2, buf + off, n - off);

		if (r < 0) {
			if (errno == EINTR)
				continue;
			break;
		}
		off += (size_t)r;
	}
}

static inline void npr_log_emit(const char *fmt, ...)
	__attribute__((format(printf, 1, 2)));

static inline void npr_log_emit(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	if (n < 0)
		return;
	if ((size_t)n >= sizeof(buf)) {
		static const char mark[] = " …TRUNC";
		size_t keep = sizeof(buf) - sizeof(mark);

		memcpy(buf + keep, mark, sizeof(mark) - 1);
		n = (int)(keep + sizeof(mark) - 1);
	}
	npr_log_emit_buf(buf, (size_t)n);
}

static inline size_t npr_bnd_add(char *dst, size_t cap, size_t o,
				 const char *src, size_t max)
{
	size_t n = strnlen(src, max);

	if (o >= cap - 1)
		return o;
	if (n > cap - 1 - o)
		n = cap - 1 - o;
	memcpy(dst + o, src, n);
	return o + n;
}

/* The version table is read through the MR handle, not through a key: a local
 * sink page is identified by its lkey and a remote range by its rkey, and
 * taking the handle first makes the caller say which surface it means
 * (The delivery invariant has a local sink face as well as a remote one.)
 */
struct mr_entry;

NPRDMA_INTERNAL const struct mr_entry *npr_mr_by_lkey(uint32_t lkey);
static inline const struct mr_entry *npr_mr_for_op(const struct npr_op *op,unsigned i)
{return op->inline_||i>=op->num_sge?NULL:op->local_mr[i]?op->local_mr[i]:op->local_bound?NULL:npr_mr_by_lkey(op->sge[i].lkey);}
NPRDMA_INTERNAL int npr_data_lkey_owned(const struct npr_op *,unsigned,int,uint32_t *);
NPRDMA_INTERNAL int npr_data_rkey_owned(const struct npr_op *,unsigned,int,uint32_t *);

NPRDMA_INTERNAL int npr_resolve_remote(struct npr_op *);
/* The write path's key has one source. An application write lands on
 * the write view, so its key is the MR's write-view key, resolved in process:
 * (1) the published export (SIR peer registry) first - the cross-host owner's
 * key; (2) else the MR object's own write_key, set once at registration (the
 * WREG auxiliary MR's rkey for a read+write MR, the application MR's own rkey
 * for a write-only MR) - an own/loopback write needs neither a published
 * export nor a session. No key from either path is fail-closed: the read key
 * is never a write key. Returns 0 with *out = the write key, -1 otherwise
 * (the caller must reject the op). */
/* npr_write_key() outcomes: RESOLVED = *out is the write-view key to post with;
 * NONE = the target is ours and has no write view (fail-closed: the read key is
 * never a write key); FOREIGN = the rkey is not ours to resolve (a bare app
 * posting keys it got out of band), so the application's choice stands. */
#define NPR_WRITE_KEY_RESOLVED 0
#define NPR_WRITE_KEY_NONE     (-1)
#define NPR_WRITE_KEY_FOREIGN  1

NPRDMA_INTERNAL int npr_data_lkey(uint32_t app_lkey, int write, uint32_t *out);
NPRDMA_INTERNAL int npr_data_rkey(uint32_t app_lkey, int write, uint32_t *out);
NPRDMA_INTERNAL int npr_write_key(const struct npr_op *op, uint32_t *out);
struct npr_prehold {
 unsigned pinned,pinning,mr_ref;
	const struct mr_entry *mr;
	uint64_t va;
	uint64_t len;
};

/* A holder reserves capacity and original MR identity before PIN can yield.
 * Callback success means the PIN is recorded in a stable cleanup owner. */
struct npr_preholder {
	int (*pin)(void *ctx, const struct mr_entry *m, uint64_t va, uint64_t len);
	void *ctx;
};

/* The one pre-check primitive, shared by both posting faces, and a
 * routing judge - not only a delivery invariant. Judges every local face of the
 * op by the version-table parity (npr_version_read_mr): the local buffer (a
 * read's sink / a write's source, via sge[0].lkey) and, when the rkey resolves
 * to an in-process owner, the target range. A face found absent is pinned
 * (npr_local_pin: promote + hold) and the hold is registered with the op's
 * holder; *absent is set because that op must then not be emitted optimistically
 * - it goes to the bilateral carrier (repair facet).
 *
 * Outcomes: 0 with *absent == 0 - every face judged and real; 0 with *absent > 0
 * - a face was absent and is now held (carry the op through the carrier, or fail
 * it closed when there is no carrier channel); -1 - a face could not be judged,
 * or its PIN/holder failed (fail-closed: the op is never posted as if checked).
 * "Not judged" is distinguishable from "judged clean": a face that belongs to no
 * adopted MR is not judged at all (no version table exists for it), while a face
 * whose version table exists but cannot be read is -1, never 0. */
NPRDMA_INTERNAL int npr_precheck(const struct npr_op *op,
				 const struct npr_preholder *h, int *absent);
NPRDMA_INTERNAL int npr_version_read_mr(const struct mr_entry *e, uint64_t va,
					uint32_t *out, unsigned long np);
/* The repair window's pin: PIN completes the promote and holds the
 * page for the whole repair (dma_ref blocks the demote verb, the GUP'd
 * page_count blocks reclaim), so a completed carrier write means the bytes
 * landed. UNPIN releases the hold only - it does not evict, page out, or touch
 * the mapping; *transitions reports the verb's own transition counter, which is
 * an observation (a moved page means the landing spot is not the app's page). */
/* One engine counter, from the interposer side (the pre-check lives there). */
NPRDMA_INTERNAL void npr_engine_stat_inc(unsigned idx);

NPRDMA_INTERNAL int npr_local_pin(const struct mr_entry *e, uint64_t va,
				  uint64_t len);
NPRDMA_INTERNAL int npr_local_unpin_observed(const struct mr_entry *,uint64_t,uint64_t,unsigned long *,int *);
NPRDMA_INTERNAL int npr_local_unpin(const struct mr_entry *e, uint64_t va,
				    uint64_t len, unsigned long *transitions);

NPRDMA_INTERNAL int symrdma_open_locked(void);

#define NPRDMA_INFLIGHT_MAX 128

#define NPR_DETECT_INLINE_PAGES 8
#define NPR_DATA_LEN_MAX       (4ULL * 1024 * 1024)
#define NPR_DETECT_PAGES_MAX    1025

struct npr_detect_domain {
	unsigned np;
	uint8_t miss_inline[NPR_DETECT_INLINE_PAGES];
	uint8_t *miss;
	uint8_t *heap;
};

struct npr_gate_item {
 struct npr_cq_entry *cq_owner;
 struct npr_gate_item *next, *prev, *free_next;
 unsigned owner_refs, lane;
 uint64_t generation,connection_epoch;
 unsigned allocated : 1;
 unsigned linked : 1;
 unsigned spill : 1;
	struct ibv_wc wc;
	unsigned ready : 1;
	unsigned visible : 1;
	unsigned consumed : 1;
	unsigned notification_seen : 1;
 /* Eligibility of a software receive, independent of public WC flags. */
 unsigned software_solicited : 1;
};

struct npr_cq_entry {
	struct ibv_cq *cq;
	int drift;

	struct npr_gate_item *ring;
	unsigned cap, head, n;
 unsigned gate_initialized;
 struct npr_gate_item *first, *last, *free_primary, *free_ready;
	/* Ready-only spill cells never alias reserved logical completion cells. */
 struct npr_gate_item *ready_overflow;
 unsigned ready_cap, ready_head, ready_n;
	unsigned order_wait;
 unsigned order_deferred; /* Accepted descriptors not yet dispatched. */
 unsigned order_background_deferred; /* Control/non-RW descriptors requiring autonomous dispatch. */
	unsigned long overflow;
	struct npr_cq_entry *next;
};

#define NPR_GATE_SLACK 64
#define NPR_GATE_DEFAULT 1024

#define NPR_SMALL_DATA_MAX     SYMRDMA_PAGE_SIZE
/* 1025 version entries cover an unaligned 4 MiB operation.
 * Sixty-four slots bound the registered pool to 512 KiB per PD. The
 * per-inflight local snapshots are bounded to about 4 KiB (128 entries/QP).
 * Data snapshots retain the independent 4 KiB small-message limit. */
#define NPR_WINDOW_SLOT_SIZE   (2 * SYMRDMA_PAGE_SIZE)
#define NPRDMA_WINDOW_SLOTS    64
#define NPR_WINDOW_POOL_SIZE   (NPR_WINDOW_SLOT_SIZE * NPRDMA_WINDOW_SLOTS)
#define NPR_WINDOW_NONE        ((unsigned)-1)

struct npr_window_pool {
	struct ibv_pd *pd;
	void *base;
	struct ibv_mr *mr;
	int mr_id;
	uint64_t used;
	unsigned n_used;
	int failed;
	unsigned long exhausted;
};

#define NPRDMA_BATCH_SPAN  (256u * 1024u)
#define NPRDMA_BATCH_BYTES (256u * 1024u)
#define NPRDMA_BATCH_OPS   256u

struct npr_batch_pool {
	void *base;
	struct ibv_mr *mr;
	int mr_id;
	int failed;
	struct detect_window *runs;
	unsigned n_runs;
};

struct npr_batch_member {
	struct npr_order_entry *order;
	uint64_t remote_addr;
	uint32_t len;
	uint32_t rkey;
};

struct npr_batch {
 uint64_t revision;
	struct sir_export exp;
	uint64_t base;
	uint64_t span;
	uint64_t bytes;
	unsigned n_ops;
	uint32_t rkey;
	struct npr_batch_member members[NPRDMA_BATCH_OPS];
};

struct npr_span {
	char *shadow;
	char *readback;
	uint64_t remote_addr;
	uint64_t len;
	uint32_t rkey;
	unsigned long np;
	struct sir_export exp;
};

enum npr_landing {
	NPR_LANDING_NONE = 0,
	NPR_LANDING_WINDOW,
	NPR_LANDING_BATCH,
};

enum npr_if_state {
	NPR_IF_EMITTED = 0,
	NPR_IF_APP_DONE,
	NPR_IF_AUX_DONE,
	NPR_IF_READY,
};

/* The pre-check scans a face's version table in bounded chunks; the bound is a
 * scan chunk, never a silent cap on what is judged. */
#define NPR_PRECHECK_CHUNK_PAGES 16

/* The local sink snapshot covers the whole op window: an op is bounded by
 * NPR_DETECT_PAGES_MAX pages, plus one page for an unaligned first page. */
#define NPR_SINK_SNAP_PAGES (NPR_DETECT_PAGES_MAX + NPR_OP_MAX_SGE)

/* Pre-check holds per posting face. The engine's inflight carries its own
 * bounded array (faces: the local buffer + a locally-resolved owner target);
 * the passthrough's holder is the wr_id table; a batch carries one hold per
 * member in the batch state. */
#define NPR_PREHOLD_MAX (2 * NPR_OP_MAX_SGE)

struct npr_inflight {
	uint64_t progress_ticket;
	struct npr_order_entry *order_batch[NPRDMA_BATCH_OPS];
	unsigned order_batch_n;
	struct npr_qp_state *qs;
	struct npr_ctx_entry *ce;
	struct ibv_qp *qp;
	struct ibv_cq *send_cq;
	struct npr_op op;
	struct ibv_wc wc;
	/* Leading version READ failure precedes the application WQE on the SQ. */
	struct ibv_wc leading_remote_error;
	unsigned seq;
	struct npr_gate_item *item;

	unsigned visible : 1;
	unsigned is_wwi : 1;
	unsigned notify_pending : 1;
	unsigned notify_done : 1;
	unsigned app_done : 1;
	unsigned app_ok : 1;
	unsigned aux_want : 1;
	unsigned aux_done : 1;
	unsigned aux_ok : 1;
	unsigned seqlock : 1;
	unsigned aux2_done : 1;
	unsigned aux2_ok : 1;

	unsigned in_check : 1;
	unsigned async_check : 1;
 unsigned inline_clean : 1;
	unsigned release_pending : 1;
	unsigned cleanup_active : 1;
 unsigned prepare_active : 1; /* Window pressure may suspend the posting caller. */
	unsigned publish_pending : 1;
	unsigned native_refs;
	unsigned delivered : 1;
	uint8_t state;
	uint8_t landing;

	__be32 imm;

	struct npr_window_pool *pool;
	struct npr_span span;
	struct npr_batch_pool *bpool;

	struct npr_inflight *cover;
 unsigned cover_refs; /* predecessor batches hold this signaled owner */
	unsigned cover_bad : 1;
	unsigned sticky_claimed : 1;
	unsigned src_slot;
	unsigned aux_slot;
	unsigned aux2_slot;


	/* Local sink face: a read's receive buffer is a SymRDMA MR too, and
	 * while its read IOVA sits on the sentinel page the incoming DMA is dropped
	 * silently. The submit-side snapshot lives here and covers the whole op
	 * window; delivery re-reads it. l1_bad says the axis could not be taken
	 * (not that it was taken and found clean) - the delivery is then an error
	 * WC, never a claim. */
	uint32_t l1_snap[NPR_SINK_SNAP_PAGES];
 unsigned l1_seg_np[NPR_OP_MAX_SGE];
	unsigned long l1_np;
	unsigned l1_bad : 1;
	/* the op was carried bilaterally instead of being emitted */
	unsigned bilateral : 1;

	/* Pre-check holds: faces the pre-check found absent were pinned
	 * for this op's DMA window. Released only by npr_if_release (the single
	 * funnel: every submit failure exit and every delivery exit). */
	struct npr_prehold pre_pin[NPR_PREHOLD_MAX];
	unsigned pre_pin_n;

	struct npr_inflight *next;
};

struct npr_qp_state {
	struct ibv_qp *qp;
	uint32_t qp_num;
	struct npr_inflight *ifs;
	unsigned if_cap, if_n;
 unsigned lifecycle_refs; /* stable old-state borrow across cleanup yields */
	unsigned long inflight_barrier;
	struct ibv_cq *send_cq;
	struct npr_batch_pool *bat_pool;
	struct npr_batch bat;
	unsigned batch_native_refs;
	unsigned batch_drop_pending : 1;
	unsigned batch_closing : 1;
	unsigned sq_sig_all : 1;
	unsigned bat_busy : 1;
	unsigned closing : 1;
	unsigned dead : 1;
	/* An unsignaled op (batch member / invisible carrier) has no completion of
	 * its own, so its failure is recorded here and the next signaled completion
	 * on this QP reports it as an error WC. One report, then the flag clears. */
	unsigned sticky_err : 1;
	struct npr_qp_state *next;
};

struct npr_ctx_entry {
	struct ibv_context *ctx;
 unsigned posting_refs, posting_blocked;
	unsigned closing : 1;
	int (*real_post_send)(struct ibv_qp *qp, struct ibv_send_wr *wr,
			      struct ibv_send_wr **bad_wr);
	int (*real_post_recv)(struct ibv_qp *, struct ibv_recv_wr *, struct ibv_recv_wr **);
	int (*real_req_notify_cq)(struct ibv_cq *, int);
	int (*real_poll_cq)(struct ibv_cq *cq, int num_entries,
			    struct ibv_wc *wc);
	struct npr_cq_entry *cqs;
	struct npr_qp_state *qps;
	struct npr_window_pool **pools;
	unsigned npools;
	struct npr_sq_depth *depths;
	struct npr_qp_state *dead_qps;
	struct npr_ctx_entry *next;
};

struct npr_sq_depth {
	struct ibv_qp *qp;
	unsigned app_depth;
	unsigned sq_sig_all : 1;
	struct npr_sq_depth *next;
};

extern NPRDMA_INTERNAL struct npr_ctx_entry *npr_ctx_list;

NPRDMA_INTERNAL struct npr_ctx_entry *npr_ctx_get(struct ibv_context *ctx);
NPRDMA_INTERNAL int npr_posting_enter(struct npr_ctx_entry *);
NPRDMA_INTERNAL void npr_posting_leave(struct npr_ctx_entry *);
NPRDMA_INTERNAL int npr_posting_wait(struct npr_ctx_entry *);
NPRDMA_INTERNAL struct npr_cq_entry *npr_cq_get(struct npr_ctx_entry *ce, struct ibv_cq *cq);

NPRDMA_INTERNAL struct npr_gate_item *npr_gate_reserve_raw(struct npr_cq_entry *);
void npr_gate_get(struct npr_gate_item *);
void npr_gate_put(struct npr_gate_item *);
void npr_gate_set_lane(struct npr_gate_item *, unsigned);
int npr_gate_push_wc_lane(struct npr_cq_entry *, const struct ibv_wc *, unsigned);
int npr_gate_next_notification(struct npr_cq_entry *, struct ibv_wc *, unsigned *);
NPRDMA_INTERNAL int npr_gate_pop(struct npr_cq_entry *cqe, struct ibv_wc *wc);

NPRDMA_INTERNAL int npr_poll_verified_cq(struct npr_ctx_entry *, struct npr_cq_entry *, int, struct ibv_wc *);

NPRDMA_INTERNAL int npr_drain_cq(struct npr_ctx_entry *ce,
				 struct npr_cq_entry *cqe);

NPRDMA_INTERNAL int npr_drain_qp_until(struct npr_ctx_entry *ce,
				       struct npr_qp_state *qs,
				       unsigned min_free);

NPRDMA_INTERNAL void npr_cq_note_depth(struct npr_ctx_entry *ce,
				       struct ibv_cq *cq, int app_cqe);

NPRDMA_INTERNAL void npr_qp_native_discard(struct npr_ctx_entry *, struct ibv_qp *, uint32_t, uint64_t, struct npr_qp_state *, int);
NPRDMA_INTERNAL struct npr_qp_state *npr_qp_state_find(struct npr_ctx_entry *,struct ibv_qp *);
NPRDMA_INTERNAL int npr_qp_destroy_end_state(struct npr_ctx_entry *,struct npr_qp_state *);
NPRDMA_INTERNAL void npr_identity_qp_stopped_state(struct npr_ctx_entry *,struct ibv_qp *,uint32_t,uint64_t,struct npr_qp_state *);
NPRDMA_INTERNAL struct npr_qp_state *npr_qp_state_reserve(unsigned, int);
NPRDMA_INTERNAL void npr_qp_state_abort(struct npr_qp_state *);
NPRDMA_INTERNAL void npr_qp_state_commit(struct npr_ctx_entry *, struct npr_qp_state *, struct ibv_qp *);
struct npr_ex_rec;
NPRDMA_INTERNAL struct npr_ex_rec *npr_ex_reserve(void);
NPRDMA_INTERNAL struct npr_ex_rec *npr_ex_detach(struct npr_ctx_entry *,struct ibv_qp *);
NPRDMA_INTERNAL void npr_ex_reattach(struct npr_ex_rec *);
NPRDMA_INTERNAL void npr_ex_abort(struct npr_ex_rec *);
NPRDMA_INTERNAL void npr_ex_install_reserved(struct npr_ctx_entry *, struct ibv_qp *, struct npr_ex_rec *);
NPRDMA_INTERNAL void npr_qp_note_depth(struct npr_ctx_entry *ce,
				       struct ibv_qp *qp,
				       unsigned app_depth);

NPRDMA_INTERNAL void npr_qp_note_sig_all(struct npr_ctx_entry *, struct ibv_qp *, int);
NPRDMA_INTERNAL int npr_qp_sig_all(struct npr_ctx_entry *, struct ibv_qp *);

NPRDMA_INTERNAL void npr_qp_destroy_abort(struct npr_ctx_entry *, struct ibv_qp *);
NPRDMA_INTERNAL void npr_qp_destroy_begin(struct npr_ctx_entry *ce,
					  struct ibv_qp *qp);
NPRDMA_INTERNAL int npr_qp_destroy_end(struct npr_ctx_entry *ce,
				       uint32_t qp_num);

NPRDMA_INTERNAL void npr_cq_destroy(struct npr_ctx_entry *ce,
				    struct ibv_cq *cq);

NPRDMA_INTERNAL int npr_engine_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
		      struct npr_op *op);

NPRDMA_INTERNAL int npr_atomic_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
		      const struct npr_op *op);

NPRDMA_INTERNAL int npr_wwi_submit(struct npr_ctx_entry *ce, struct ibv_qp *qp,
			   struct npr_op *op);

NPRDMA_INTERNAL int npr_ex_install(struct npr_ctx_entry *ce, struct ibv_qp *qp);
NPRDMA_INTERNAL void npr_ex_uninstall(struct npr_ctx_entry *ce, struct ibv_qp *qp);
NPRDMA_INTERNAL void npr_ex_refresh(struct npr_ctx_entry *ce, struct ibv_qp *qp);

enum npr_ex_stat {
	NPR_EX_STAT_INSTALL = 0,
	NPR_EX_STAT_REPLAY,
	NPR_EX_STAT_TAKEOVER,
	NPR_EX_STAT_UNSUPPORTED,
	NPR_EX_STAT_OVERFLOW,
	NPR_EX_STAT_MAX,
};
NPRDMA_INTERNAL void npr_ex_count(enum npr_ex_stat s);

NPRDMA_INTERNAL int npr_emit_op(struct npr_ctx_entry *ce, struct ibv_qp *qp,
				const struct npr_op *op);

NPRDMA_INTERNAL struct npr_batch_pool *npr_batch_pool_get(struct npr_qp_state *qs);

NPRDMA_INTERNAL int npr_batch_write_barrier(struct npr_ctx_entry *ce,
					    struct ibv_qp *qp,
					    uint64_t addr, uint64_t len);

NPRDMA_INTERNAL void npr_pin_once(int mr_id, uint64_t va, size_t len);

int npr_pd_release_windows(struct ibv_pd *pd);

NPRDMA_INTERNAL int npr_order_submit(struct npr_ctx_entry *, struct ibv_qp *, struct npr_op *);

#endif
