/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RDV_BRIDGE_H
#define RDV_BRIDGE_H
#include "app_rdv_mailbox.h"
#include "control_transport.h"
struct cexec;
struct rdv_bridge_owner;
struct rdv_bridge_epoch;
enum rdv_bridge_role { RDV_BRIDGE_SOURCE=1,RDV_BRIDGE_SINK };
enum rdv_bridge_release_proof { RDV_BRIDGE_NOT_EXPOSED=1,RDV_BRIDGE_PEER_FINAL_ACK,RDV_BRIDGE_OLD_TRANSPORT_STOPPED };
struct rdv_bridge_config {
 enum rdv_bridge_role role;
 uint64_t slot_token,app_token;
 struct sir_rdv_value message;
 const struct sir_rdv_span *spans;
 unsigned span_count;
};
struct rdv_bridge_view {uint64_t address,length,message_offset;uint32_t lkey,rkey;};
struct rdv_bridge_counts {unsigned pins,mrs,pending_jobs,ready,released,exposed,native_refs;uint64_t read_posted,read_wc;int error;};
struct rdv_bridge_remote {uint64_t address,length,message_offset;uint32_t rkey;};
#pragma GCC visibility push(hidden)
/* All mutation is by the reactor, or its explicit joined-owner replacement.
 * No function takes the application API gate. FD/captures remain core-owned. */
int rdv_bridge_prepare(struct ctrans_provider *,struct cexec *,const struct rdv_bridge_config *,struct rdv_bridge_owner **);
int rdv_bridge_start(struct rdv_bridge_owner *);
int rdv_bridge_progress(struct rdv_bridge_owner *);
void rdv_bridge_cancel(struct rdv_bridge_owner *);
int rdv_bridge_mark_exposed(struct rdv_bridge_owner *);
/* ACK proof must be the complete original message tuple, never a boolean.
 * STOPPED proof is independently checked in the original transport epoch. */
int rdv_bridge_release_allowed(struct rdv_bridge_owner *,enum rdv_bridge_release_proof,const struct sir_rdv_identity *);
int rdv_bridge_views(struct rdv_bridge_owner *,struct rdv_bridge_view *,unsigned,unsigned *);
/* Caller has already authorized the complete OFFER's original tuple/source
 * view. Syntax/range checks here do not establish that remote permission. */
int rdv_bridge_read_prepare(struct rdv_bridge_owner *,struct ctrans_rev_pool *,const struct rdv_bridge_remote *,unsigned);
/* accepted counts only this call's real native successes. EAGAIN is credit
 * backpressure; rejected WRs have no native ref, earlier successes retain it. */
int rdv_bridge_read_progress(struct rdv_bridge_owner *,unsigned *accepted);
int rdv_bridge_on_read_stopped(struct cexec *,const struct ctrans_rev_ticket *);
int rdv_bridge_on_read_wc(struct cexec *,const struct ctrans_rev_ticket *,enum ibv_wc_status);
int rdv_bridge_reads_done(struct rdv_bridge_owner *,enum ibv_wc_status *);
int rdv_bridge_take_released(struct rdv_bridge_owner *,struct sir_rdv_record *);
int rdv_bridge_released_committed(struct rdv_bridge_owner *);
int rdv_bridge_free(struct rdv_bridge_owner *);
void rdv_bridge_get_counts(struct rdv_bridge_owner *,struct rdv_bridge_counts *);
/* Executor dispatcher consumes only RDV_MEMORY jobs, never legacy cown jobs. */
int rdv_bridge_on_exec(struct cexec *,uint64_t);
/* First import all real results after join, ending PREPARING jobs before
 * force_stop. Preserve completion entries until the dispatcher drains them. */
int rdv_bridge_executor_stopped(struct cexec *);
/* Called after shared completion ring has drained and old QP really stopped. */
int rdv_bridge_stopped_finish(struct cexec *);
void rdv_bridge_progress_all(struct cexec *);
int rdv_bridge_busy(const struct cexec *);
#pragma GCC visibility pop
#endif
