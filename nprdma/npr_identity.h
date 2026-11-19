/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_IDENTITY_H
#define NPR_IDENTITY_H
#include <stdint.h>
#include <infiniband/verbs.h>
struct npr_ctx_entry;
struct npr_order_entry;
struct npr_op;
struct npr_rdv_owner;
struct npr_gate_item;
struct npr_qp_identity_reservation;
enum npr_identity_lane { NPR_LANE_SQ=0, NPR_LANE_RQ=1 };
enum npr_identity_kind {
 NPR_ID_APP, NPR_ID_AUX, NPR_ID_NOTIFY, NPR_ID_BATCH_MEMBER,
 NPR_ID_PASS, NPR_ID_ORDER, NPR_ID_SEND, NPR_ID_RECV, NPR_ID_INTERNAL
};
enum npr_identity_state { NPR_ID_PREPARED, NPR_ID_ACCEPTED, NPR_ID_CLAIMED,
 NPR_ID_CLEANUP, NPR_ID_CANCELED };
struct npr_identity_spec {
 unsigned caller_driven; /* ordinary READ/WRITE and write batches: upper CQ driver */
 enum npr_identity_kind kind;
 unsigned lane;
 uint64_t user_wr_id;
 enum ibv_wc_opcode opcode;
 unsigned visible;
 void *owner;
 struct npr_order_entry *order;
 struct npr_rdv_owner *rdv_owner;
 void (*rdv_done)(struct npr_rdv_owner *,const struct ibv_wc *);
 void *resource;
 int (*release)(void *);
 /* Hidden native protocol completion, after actual resource cleanup. */
 void (*internal_done)(void *,const struct ibv_wc *);
 /* Successful provider context close: forget dead handles without native calls. */
 void (*internal_context_stopped)(void *);
};
/* Every call is serialized by the application progress API gate. Objects stay
 * stable across blocking resource cleanup; only their terminal owner retires. */
struct npr_identity {
 struct npr_identity *hash_next, *next, *prev, *stop_next;
 struct npr_identity *cleanup_next,*cleanup_prev;
 struct npr_ctx_entry *ce;
 struct ibv_qp *qp;
 struct ibv_cq *cq;
 struct ibv_context *context;
 uint64_t token, generation, progress_ticket;
 uint32_t qp_num;
 struct npr_identity_spec spec;
 enum npr_identity_state state;
 struct ibv_wc wc;
 struct npr_gate_item *item;
 unsigned processing,cleanup_queued,autonomous_held;
};
#pragma GCC visibility push(hidden)
/* Precreate reservation: commit is allocation-free after native success. */
struct npr_qp_identity_reservation *npr_identity_qp_reserve(void);
uint64_t npr_identity_qp_reserved_generation(const struct npr_qp_identity_reservation *);
void npr_identity_qp_commit(struct npr_qp_identity_reservation *, struct ibv_qp *);
void npr_identity_qp_abort(struct npr_qp_identity_reservation *);
struct npr_identity *npr_identity_prepare(struct npr_ctx_entry *, struct ibv_qp *,
 struct ibv_cq *, const struct npr_identity_spec *);
void npr_identity_accept(struct npr_identity *);
void npr_identity_abort(struct npr_identity *);
struct npr_identity *npr_identity_resolve(struct npr_ctx_entry *, struct ibv_cq *,
 const struct ibv_wc *);
void npr_identity_retire(struct npr_identity *);
/* Only terminal, idle cleanup owners belong to the ready queue. Claim removes
 * them before any cleanup can yield the API gate; failed work retries at tail. */
void npr_identity_cleanup_retry(struct npr_identity *);
void npr_identity_cleanup_claim(struct npr_identity *);
struct npr_identity *npr_identity_pending(struct npr_ctx_entry *);
struct npr_identity *npr_identity_for_qp(struct ibv_qp *);
struct npr_identity *npr_identity_for_context(struct npr_ctx_entry *);
void npr_identity_context_stopped(struct npr_ctx_entry *);
void npr_identity_forget_qp(struct ibv_qp *);
void npr_identity_detach_qp(struct ibv_qp *);
void npr_identity_forget_context(struct ibv_context *);
int npr_identity_has_cq(struct ibv_cq *);
int npr_identity_cq_busy(struct npr_ctx_entry *,struct ibv_cq *);
unsigned npr_identity_count(void);
unsigned npr_identity_qp_count(struct ibv_qp *);
uint64_t npr_identity_qp_generation(struct ibv_qp *);
uint64_t npr_identity_qp_known_generation(struct ibv_qp *);
struct npr_identity *npr_identity_for_qp_generation(struct ibv_qp *,uint64_t);
void npr_identity_detach_qp_generation(struct ibv_qp *,uint64_t);
int npr_emit_prepared(struct npr_ctx_entry *,struct ibv_qp *,const struct npr_op *,struct npr_identity *);
void npr_identity_progress(struct npr_ctx_entry *);
void npr_identity_qp_stopped(struct npr_ctx_entry *,struct ibv_qp *,uint32_t);
int npr_emit_owned(struct npr_ctx_entry *, struct ibv_qp *, const struct npr_op *,
 enum npr_identity_kind, void *);
#pragma GCC visibility pop
#endif
