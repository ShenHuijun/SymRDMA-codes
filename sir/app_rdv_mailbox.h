/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APP_RDV_MAILBOX_H
#define APP_RDV_MAILBOX_H
#include <stddef.h>
#include <stdint.h>
#include "app_qp_binding.h"
#include "rdv_memory.h"

/* Metadata storage only. No protocol authorization, PIN, DMA, verbs, CQ or
 * application-object pointers. Tokens and serials never repeat or wrap. */
struct sir_rdv_mailbox;
enum sir_rdv_role { SIR_RDV_SOURCE=1, SIR_RDV_SINK };
enum sir_rdv_hold { SIR_RDV_CALLBACK=0, SIR_RDV_NATIVE, SIR_RDV_CLEANUP, SIR_RDV_HOLD_N };
enum sir_rdv_command_kind { SIR_RDV_SOURCE_PREPARE=1, SIR_RDV_MATCH_PREPARE, SIR_RDV_CANCEL, SIR_RDV_WWI_RESULT, SIR_RDV_NATIVE_RECEIVED, SIR_RDV_NATIVE_EXPOSED };
enum sir_rdv_event_kind {
 SIR_RDV_OFFER_READY=0, SIR_RDV_PEER_ACK, SIR_RDV_DMA_STOPPED,
 SIR_RDV_SOURCE_RELEASED, SIR_RDV_SINK_RELEASED, SIR_RDV_WWI_READY, SIR_RDV_SOURCE_PREPARED, SIR_RDV_EVENT_N
};
enum sir_rdv_release_evidence {
 SIR_RDV_NO_DATA=1, SIR_RDV_DATA_CLEANED, SIR_RDV_STOPPED_CLEANED
};
struct sir_rdv_identity {
 uint64_t session_id,transport_generation,command_revision;
 struct sir_app_qp_endpoint local,peer;
 uint64_t message_id,rq_message_seq;
};
struct sir_rdv_value {
 struct sir_rdv_identity id;
 uint64_t length;
 uint32_t kind,imm_be,solicited,status;
};
struct sir_rdv_record {
 uint64_t token,serial,app_token;
 unsigned kind,span_count,evidence;
 struct sir_rdv_value value;
};
/* Separate preallocated per-QP control lane: never consumes a WR/RQ slot.
 * HEAD may advance within one fixed BEGIN frontier, without starting DMA. */
enum sir_rdv_drain_side {SIR_RDV_DRAIN_LOCAL=0,SIR_RDV_DRAIN_PEER};
enum sir_rdv_drain_kind {SIR_RDV_DRAIN_BEGIN=1,SIR_RDV_DRAIN_HEAD,SIR_RDV_DRAIN_CANCEL,SIR_RDV_DRAIN_DONE};
struct sir_rdv_drain_record {
 uint64_t serial,nonce,frontier,head;
 unsigned side,kind,status;
 struct sir_rdv_identity id;
};
struct sir_rdv_mailbox_config {
 size_t slot_count,max_spans;
 /* Wake-only, nonblocking callbacks, never verbs/PIN/gate/RPC/wait. Called
  * outside the lock. opaque must live until mailbox_free actually succeeds;
  * a failed free does NOT permit its destruction. Each publication wakes; callbacks must not recursively publish new work. */
 void (*wake_actor)(void *),(*wake_app)(void *);
 void *wake_opaque;
};
struct sir_rdv_mailbox_counts {
 size_t reserved,external_refs,wake_refs;
 unsigned closed;
 size_t control_pending;
};
#pragma GCC visibility push(hidden)
/* No global QP or preaccepted-message cap. All fallible storage is prepared
 * here, before WR acceptance; the caller must use actual provider capacity
 * (allocation may follow native create), not silently lower it to requested
 * limits. Actor credit admission is a separate layer. */
int sir_rdv_drain_publish(struct sir_rdv_mailbox *,unsigned actor_to_app,const struct sir_rdv_drain_record *);
int sir_rdv_drain_take(struct sir_rdv_mailbox *,unsigned actor_to_app,uint64_t frontier,struct sir_rdv_drain_record *);
int sir_rdv_drain_ack(struct sir_rdv_mailbox *,unsigned actor_to_app,unsigned side,uint64_t serial);
int sir_rdv_mailbox_new(const struct sir_rdv_mailbox_config *,struct sir_rdv_mailbox **);
/* Registry owners acquire an external reference while still under the
 * registry lock BEFORE exposing a pointer. Close first unlinks the mailbox
 * from enumeration, then waits for borrows/callers to leave before free.
 * get() cannot rescue an unprotected raw pointer racing a successful free. */
int sir_rdv_mailbox_get(struct sir_rdv_mailbox *);
int sir_rdv_mailbox_put(struct sir_rdv_mailbox *);
/* Explicit destruction only: closed + zero slots/borrows/callbacks required.
 * Returns EBUSY without changing anything. No callback frees the mailbox. */
int sir_rdv_mailbox_free(struct sir_rdv_mailbox *);
/* Close retires unsent source prepares/OFFER events and queues cancellation.
 * Accepted MATCH metadata remains queued for cleanup without starting DMA. An
 * already taken event/command still belongs to its consumer, which must check
 * current generation/closed state before starting new work. */
int sir_rdv_mailbox_close(struct sir_rdv_mailbox *);
void sir_rdv_mailbox_notify_app(struct sir_rdv_mailbox *);
void sir_rdv_mailbox_counts(struct sir_rdv_mailbox *,struct sir_rdv_mailbox_counts *);
/* Reserve before SQ acceptance or inside the RQ claim reservation callback.
 * app_token is an opaque owner id, never a pointer and never dereferenced.
 * Abort only an unpublished reservation (e.g. ex abort). */
int sir_rdv_message_reserve(struct sir_rdv_mailbox *,enum sir_rdv_role,uint64_t app_token,uint64_t *token);
int sir_rdv_message_abort(struct sir_rdv_mailbox *,uint64_t token);
int sir_rdv_message_hold(struct sir_rdv_mailbox *,uint64_t token,enum sir_rdv_hold);
int sir_rdv_message_drop(struct sir_rdv_mailbox *,uint64_t token,enum sir_rdv_hold);
/* One immutable prepare plus independently reserved cancel and WWI-result cells.
 * All values/spans are copied; an error transfers no ownership. Span values
 * borrow original app-authority leases retained by the caller until RELEASED.
 * Process-local backend values are validated/copied, never interpreted as PIN
 * success. Duplicated fds remain core-owned; this module never closes them. */
int sir_rdv_command_submit(struct sir_rdv_mailbox *,uint64_t token,enum sir_rdv_command_kind,
 const struct sir_rdv_value *,const struct sir_rdv_span *,size_t nspan);
/* Snapshot one finite frontier per progress round. New publications are not
 * consumed by take(frontier); take copies, ack releases that delivery. */
uint64_t sir_rdv_command_frontier(struct sir_rdv_mailbox *);
int sir_rdv_command_take(struct sir_rdv_mailbox *,uint64_t frontier,struct sir_rdv_record *);
/* Establish CALLBACK/NATIVE/CLEANUP holds before ack when work outlives the
 * command. Inflight commands block RELEASED; queued commands retire on release. */
int sir_rdv_command_ack(struct sir_rdv_mailbox *,uint64_t token,uint64_t serial);
int sir_rdv_spans_copy(struct sir_rdv_mailbox *,uint64_t token,struct sir_rdv_span *,size_t capacity,size_t *count);
/* Each event kind (including WWI READY) has a reserved cell independent of queue pressure. Identical
 * duplicates return EALREADY without requeueing; conflicting duplicates EPROTO.
 * PEER_ACK/STOPPED are evidence events, NOT cleanup receipts or CQ completions. */
int sir_rdv_event_publish(struct sir_rdv_mailbox *,uint64_t token,enum sir_rdv_event_kind,const struct sir_rdv_value *);
/* Actor calls only after real resources are clean. DATA source requires prior
 * peer ACK (no-more-READ) or DMA_STOPPED; sink requires DATA/STOPPED_CLEANED.
 * NO_DATA is not proof of a successful logical SEND/RECV. This module cannot
 * verify provider/ioctl receipts; the resource owner remains responsible. */
int sir_rdv_message_released(struct sir_rdv_mailbox *,uint64_t token,
 enum sir_rdv_release_evidence,const struct sir_rdv_value *);
uint64_t sir_rdv_event_frontier(struct sir_rdv_mailbox *);
int sir_rdv_event_take(struct sir_rdv_mailbox *,uint64_t frontier,struct sir_rdv_record *);
int sir_rdv_event_ack(struct sir_rdv_mailbox *,uint64_t token,uint64_t serial);
#pragma GCC visibility pop
#endif
