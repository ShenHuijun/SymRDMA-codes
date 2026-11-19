/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_ORDER_H
#define NPR_ORDER_H
#include <infiniband/verbs.h>
#ifndef NPRDMA_INTERNAL
#define NPRDMA_INTERNAL __attribute__((visibility("hidden")))
#endif
#define NPR_ORDER_BEFORE (1u << 28)
#define NPR_ORDER_AFTER (1u << 29)
#define NPR_ORDER_HINT_MASK (NPR_ORDER_BEFORE | NPR_ORDER_AFTER)
struct npr_op;
struct npr_order_entry;
struct npr_ctx_entry;
struct npr_cq_entry;
NPRDMA_INTERNAL struct npr_gate_item *npr_order_item(struct npr_order_entry *);
NPRDMA_INTERNAL void npr_order_note_transport_error(struct npr_order_entry *, enum ibv_wc_status);
NPRDMA_INTERNAL void npr_order_complete(struct npr_order_entry *, const struct ibv_wc *);
/* CLEAN producer releases its last engine borrow and runs order_progress
 * synchronously; only queued dependent descriptors require a pump wake. */
NPRDMA_INTERNAL void npr_order_complete_inline_clean(struct npr_order_entry *, const struct ibv_wc *);
NPRDMA_INTERNAL void npr_order_complete_verification(struct npr_order_entry *, const struct ibv_wc *);
NPRDMA_INTERNAL void npr_order_complete_batch_clean(struct npr_order_entry **,unsigned,const struct ibv_wc *);
NPRDMA_INTERNAL void npr_order_progress(void);
NPRDMA_INTERNAL void npr_order_qp_stopped(struct ibv_qp *);
/* Exact old-epoch terminal: hide this cell only, retaining engine leases. */
NPRDMA_INTERNAL void npr_order_entry_discard(struct npr_order_entry *);
NPRDMA_INTERNAL void npr_order_qp_discard(struct ibv_qp *, uint64_t);
NPRDMA_INTERNAL void npr_order_context_stopped(struct npr_ctx_entry *);
NPRDMA_INTERNAL int npr_order_batch_begin(void);
NPRDMA_INTERNAL void npr_order_batch_abort(void);
NPRDMA_INTERNAL int npr_order_batch_commit(void);
NPRDMA_INTERNAL void npr_order_get(struct npr_order_entry *);
NPRDMA_INTERNAL void npr_order_batch_member_set(struct npr_order_entry *,int);
NPRDMA_INTERNAL void npr_order_put(struct npr_order_entry *);
NPRDMA_INTERNAL int npr_order_raw_submit(struct npr_ctx_entry *, struct ibv_qp *, struct npr_op *);
NPRDMA_INTERNAL struct npr_gate_item *npr_gate_reserve(struct npr_cq_entry *);
NPRDMA_INTERNAL int npr_order_lease_acquire(struct ibv_pd *, struct npr_op *, void **);
NPRDMA_INTERNAL void npr_order_lease_release(void *);
NPRDMA_INTERNAL void npr_order_flush_batches(struct npr_ctx_entry *, struct ibv_qp *);
NPRDMA_INTERNAL void npr_order_cancel_qp(struct ibv_qp *, int only_pending);
NPRDMA_INTERNAL void npr_order_cancel_cq(struct npr_cq_entry *);
#endif
