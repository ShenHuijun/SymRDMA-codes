/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_RENDEZVOUS_H
#define NPR_RENDEZVOUS_H
#include <infiniband/verbs.h>
#include "app_rdv_mailbox.h"
#include "control_app_rdv.h"
#include "npr_rdv_rq.h"
struct npr_ctx_entry;
struct npr_rdv_qp;
struct npr_rdv_epoch;
struct npr_rdv_owner;
struct npr_op;
struct npr_order_entry;
typedef void (*npr_rdv_notify_fn)(void *,const struct ibv_wc *,const void *);
struct npr_rdv_cq_ops {
 int (*reserve)(struct npr_ctx_entry *,struct ibv_cq *,uint32_t,uint64_t,uint64_t,uint64_t,void **);
 void (*complete)(void *,const struct ibv_wc *,unsigned,int);
 void (*discard)(void *);
 void (*discard_epoch)(struct npr_ctx_entry *,struct ibv_cq *,uint32_t,uint64_t,uint64_t);
 void (*source_get)(struct npr_order_entry *);
 void (*source_done)(struct npr_order_entry *,const struct ibv_wc *,int discard);
 int (*source_data)(struct npr_ctx_entry *,struct ibv_qp *,struct npr_op *);
 int (*qp_error)(struct npr_ctx_entry *,struct ibv_qp *);
 int (*notify_recv)(struct npr_ctx_entry *,struct ibv_qp *,void *,npr_rdv_notify_fn);
 int (*notify_send)(struct npr_ctx_entry *,struct ibv_qp *,const void *,unsigned,void *,npr_rdv_notify_fn);
};
struct npr_rdv_actor_ops {
 int (*register_qp)(const struct crdv_registration_config *,struct crdv_registration **);
 int (*capability)(void);
 int (*native_arrival)(struct crdv_registration *,const struct sir_rdv_value *);
 int (*offer_snapshot)(struct crdv_registration *,uint64_t,uint64_t,struct crdv_offer_snapshot *);
 int (*offer_reply)(struct crdv_registration *,uint64_t,uint64_t,uint64_t,enum crdv_offer_result);
 int (*close)(struct crdv_registration *);
 int (*free)(struct crdv_registration *); /* SIR service wrapper, not raw free. */
 int (*update_attrs)(struct crdv_registration *,uint8_t,uint8_t);
 int (*stats)(struct crdv_registration *,struct crdv_stats *);
 int (*final_stats)(struct crdv_registration *,struct crdv_stats *);
 void (*wake_actor)(void *);
 void *wake_opaque;
};
extern const struct npr_rdv_cq_ops npr_rdv_gate_ops __attribute__((visibility("hidden")));

struct npr_rdv_snapshot {
 struct sir_app_qp_key key;
 uint64_t connection_epoch;
 struct ibv_qp_cap visible_cap,provider_cap;
 struct npr_rq_counts rq;
 size_t retired_epochs,owners;
 unsigned policy,closed,data_enabled;
};
/* A gate-local borrowed snapshot, never sent to the actor. The callback must
 * verify the adopted entry while the original capture is still held. */
struct npr_rdv_backend_source {int fd,mr_id;uint64_t registration_gen;};
int npr_rdv_backend_snapshot(const struct npr_mra_view *,struct npr_rdv_backend_source *) __attribute__((visibility("hidden")));
typedef int (*npr_rdv_backend_fn)(const struct npr_mra_view *,struct npr_rdv_backend_source *);
#pragma GCC visibility push(hidden)
/* Gate-owned admission, virtual RQ matching and terminal progress. All calls
 * require the NPR API gate. The actor owns bridge DMA/PIN; callbacks integrate
 * the existing order/CQ and WRITE data owners. */
struct npr_rdv_qp *npr_rdv_prepare(struct npr_ctx_entry *,void *context,void *pd,
 const struct sir_app_qp_key *,enum sir_app_qp_policy);
void npr_rdv_abort(struct npr_rdv_qp *);
void npr_rdv_cq_ops(struct npr_rdv_qp *,const struct npr_rdv_cq_ops *);
void npr_rdv_backend(struct npr_rdv_qp *,npr_rdv_backend_fn);
/* Internal compile-time activation only; no live native-RQ mode switch. */
void npr_rdv_data_enable(struct npr_rdv_qp *,unsigned);
void npr_rdv_service_config(const struct npr_rdv_actor_ops *,unsigned);
/* 0 native path, 1 handled (status in *result), no target bytes/PIN. */
int npr_rdv_post_recv(struct npr_ctx_entry *,struct ibv_qp *,struct ibv_recv_wr *,struct ibv_recv_wr **,int *);
/* Pure metadata preparation before future WR acceptance; registration itself
 * is through the SIR process service, never a second independent registry. */
int npr_rdv_actor_config(struct npr_rdv_qp *,const struct npr_rdv_actor_ops *,struct crdv_registration_config *);
void npr_rdv_actor_attach(struct npr_rdv_qp *,struct crdv_registration *);
void npr_rdv_native_state(struct npr_rdv_qp *,enum ibv_qp_state);
/* Close native post admission before provider destroy/cleanup can yield. */
void npr_rdv_native_pause(struct npr_rdv_qp *,unsigned);
void npr_rdv_update_attrs(struct npr_rdv_qp *,uint8_t rnr_retry,uint8_t min_rnr_timer);
/* Existing actor slot only, role/current full pair validated by offer_snapshot.
 * No second mailbox reservation; abort only rolls back new core metadata. */
int npr_rdv_owner_adopt_sink(struct npr_rdv_qp *,struct crdv_registration *,
 const struct sir_rdv_record *,struct npr_rdv_owner **);

void npr_rdv_commit(struct npr_rdv_qp *,struct ibv_qp *,
 const struct ibv_qp_cap *visible,const struct ibv_qp_cap *provider);
struct npr_rdv_epoch *npr_rdv_reset_prepare(struct npr_rdv_qp *,uint64_t next_epoch);
void npr_rdv_reset_abort(struct npr_rdv_epoch *);
void npr_rdv_reset_commit(struct npr_rdv_qp *,struct npr_rdv_epoch *);
void npr_rdv_binding(struct npr_rdv_qp *,const struct sir_app_qp_snapshot *);
void npr_rdv_error(struct npr_rdv_qp *);
/* Application QP stop only: close queued RQ, cancel matched owners. It is
 * never a transport-DMA-stopped or bridge-cleaned receipt. */
void npr_rdv_close(struct npr_rdv_qp *);
void npr_rdv_progress(void);
/* Gate-owned bounded frontier drain before logical MR close / QP withdrawal.
 * No app poll or unmatched-RQ wait is required. Returns a diagnostic errno;
 * native teardown still owns its actual success/failure and cleanup. */
int npr_rdv_control_drain_qp(struct ibv_qp *);
int npr_rdv_control_drain_pd(void *context,void *pd);
int npr_rdv_snapshot(const struct npr_rdv_qp *,struct npr_rdv_snapshot *);
#ifdef NPRDMA_TEST_INJECT
struct npr_test_rdv_qp;
int npr_rdv_test_snapshot(struct npr_rdv_qp *,struct npr_test_rdv_qp *);
struct npr_test_wwi_protocol;
int npr_rdv_test_protocol(struct npr_rdv_qp *,struct npr_test_wwi_protocol *);
/* Called only after a real application native RQ WR is accepted. */
void npr_rdv_native_recv_posted(struct npr_ctx_entry *,struct ibv_qp *);
#endif
/* Gate-owned epoch borrow for future adapters/tests. Not actor handles. */
struct npr_rdv_epoch *npr_rdv_active(struct npr_rdv_qp *);
struct npr_rq *npr_rdv_rq(struct npr_rdv_epoch *);
/* All fallible storage and owner reservation precede WR acceptance. */
/* SOURCE admission transaction. prepare returns 1 reserved, 0 native path,
 * or negative errno before admission. Invalid source descriptors are retained
 * as markers for asynchronous protection errors; no PIN or BIND is needed.
 * accept is allocation-free at final legacy link / atomic ex-batch commit;
 * abort is only for an unaccepted reservation and consumes no sequence.
 * dispatch/cancel only request deferred progress, never publish/reap inline.
 * Accepted owner holds exactly one order borrow until ACK + real cleanup. */
int npr_rdv_source_prepare(struct npr_ctx_entry *,struct ibv_qp *,
 struct npr_op *,struct npr_order_entry *,struct npr_rdv_owner **);
int npr_rdv_source_preaccept_validate(const struct npr_rdv_owner *);
uint64_t npr_rdv_source_epoch(const struct npr_rdv_owner *);
void npr_rdv_source_accept(struct npr_rdv_owner *);
void npr_rdv_source_abort(struct npr_rdv_owner *);
int npr_rdv_source_dispatch(struct npr_rdv_owner *);
int npr_rdv_source_data_begin(struct npr_rdv_owner *);
void npr_rdv_source_data_submit_done(struct npr_rdv_owner *,int);
void npr_rdv_source_data_hold(struct npr_rdv_owner *);
void npr_rdv_source_data_done(struct npr_rdv_owner *,const struct ibv_wc *);
void npr_rdv_source_cancel(struct npr_rdv_owner *,enum ibv_wc_status,int discard);

int npr_rdv_owner_reserve(struct npr_rdv_qp *,enum sir_rdv_role,
 const struct sir_rdv_identity *,struct npr_rdv_owner **);
/* Move a validated capture only on success; no PIN. Duplicated SYM fd is
 * CLOEXEC and core-owned until an exact original-owner RELEASED receipt. */
int npr_rdv_owner_capture(struct npr_rdv_owner *,struct npr_mra_capture *,
 uint64_t offset,uint64_t length,uint64_t message_offset,
 enum npr_mra_direction,npr_rdv_backend_fn);
/* Publish copied metadata to the actor; cleanup ownership remains explicit. */
int npr_rdv_owner_submit(struct npr_rdv_owner *,const struct sir_rdv_value *);
int npr_rdv_owner_abort(struct npr_rdv_owner *);
uint64_t npr_rdv_owner_app_token(const struct npr_rdv_owner *);
uint64_t npr_rdv_owner_mailbox_token(const struct npr_rdv_owner *);
/* Borrow only while protected by the gate/owner; actor registry integration
 * must acquire mailbox_get before handing a pointer across threads. */
struct sir_rdv_mailbox *npr_rdv_owner_mailbox(struct npr_rdv_owner *);
int npr_rdv_owner_spans(const struct npr_rdv_owner *,const struct sir_rdv_span **,size_t *);
/* No event is DMA proof by itself. Typed RELEASED is the resource owner's
 * receipt; OFFER/new work requires current pair; ACK/STOPPED and RELEASED use the
 * exact saved owner pair. ACK/STOPPED alone never release or complete. */
int npr_rdv_owner_event(struct npr_rdv_owner *,const struct sir_rdv_record *);
int npr_rdv_owner_retire(struct npr_rdv_owner *);
#pragma GCC visibility pop
#endif
