/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_RDV_RQ_H
#define NPR_RDV_RQ_H
#include <stdint.h>
#include <stddef.h>
#include <infiniband/verbs.h>
#include "npr_mr_authority.h"
struct npr_rq;
struct npr_rq_key { uint64_t cookie,generation,connection_epoch; };
struct npr_rq_config {
 struct npr_rq_key key;
 void *context,*pd;
 uint32_t qp_num;
 unsigned max_recv_wr,max_recv_sge;
};
enum npr_rq_message_kind { NPR_RQ_SEND=1,NPR_RQ_SEND_IMM,NPR_RQ_WWI };
struct npr_rq_message {
 struct npr_rq_key local;
 uint64_t sequence,message_id,length;
 uint32_t kind,imm_be;
 unsigned solicited;
};
struct npr_rq_span { struct npr_mra_view view;uint64_t message_offset; };
/* Borrowed only during the reserve callback. Copy values to the bounded bridge
 * slot; retain this RQ/token until finish. Views borrow original captures.
 * Core must strip app/provider pointers: actor receives only CPU span values
 * and opaque tokens, never view.handle/pd/adopted/context or captures. */
struct npr_rq_plan {
 uint64_t token,user_wr_id,receive_sequence;
 struct npr_rq_message message;
 enum ibv_wc_status rx_status,tx_status;
 const struct npr_rq_span *spans;
 unsigned span_count;
};
/* Callback is nonblocking, metadata-only, under the caller's API gate.
 * Return 0 only after ALL external slots are reserved; failure leaves no slots
 * owned and does not consume the RQ. The module never releases its opaque value. */
typedef int (*npr_rq_reserve_fn)(void *,const struct npr_rq_plan *,uint64_t *reservation);
enum npr_rq_cleanup_evidence { NPR_RQ_NO_DATA=1,NPR_RQ_DATA_CLEANED,NPR_RQ_DMA_STOPPED_CLEANED };
struct npr_rq_completion {
 uint64_t token,reservation,user_wr_id,receive_sequence;
 struct npr_rq_key key;
 struct ibv_wc wc;
 enum ibv_wc_status tx_status;
 unsigned solicited,discard;
};
enum npr_rq_close_mode { NPR_RQ_CLOSE_FLUSH=1,NPR_RQ_CLOSE_DISCARD };
struct npr_rq_counts {size_t queued,claimed,terminal,outstanding,captures;};
#pragma GCC visibility push(hidden)
/* All APIs require the existing NPR API gate; no private lock, verbs, PIN,
 * RPC, application-memory access or background thread exists in this module. */
/* Precreate may leave pd unknown; context/key remain mandatory. No post or
 * capture is allowed before commit supplies the actual nonnull native PD. */
struct npr_rq *npr_rq_prepare(const struct npr_rq_config *);
/* Commit only copies validated actual provider values; bad input is an
 * internal invariant violation, never a failure after native create success. */
void npr_rq_commit(struct npr_rq *,const struct npr_rq_config *actual);
void npr_rq_abort(struct npr_rq *);
void npr_rq_get(struct npr_rq *);
void npr_rq_put(struct npr_rq *);
int npr_rq_post(struct npr_rq *,struct ibv_recv_wr *,struct ibv_recv_wr **bad_wr);
/* Native callback runs only after descriptor allocation and authority captures.
 * Success means its WQE was accepted; no subsequent fallible step precedes
 * software commit. Failure preserves the already accepted list prefix. */
typedef int (*npr_rq_post_native_fn)(void *,uint64_t token);
int npr_rq_post_native(struct npr_rq *,struct ibv_recv_wr *,struct ibv_recv_wr **,
 npr_rq_post_native_fn,void *);
/* Core validates current full BIND/session/peer tuple before passing a message.
 * Module rechecks its local key/epoch and exact shared SEND/IMM/WWI sequence.
 * No CQ cell is held by merely posted RQ. No reservation callback => EINVAL. */
/* Trusted core only: a newly authorized logical pair may start at sequence k.
 * Caller excludes nonce-only refresh and guarantees first OFFER source FIFO.
 * Existing queued captures and claimed descriptors are never relabelled. */
int npr_rq_stream_begin(struct npr_rq *,uint64_t base_sequence);
int npr_rq_claim(struct npr_rq *,const struct npr_rq_message *,npr_rq_reserve_fn,void *,uint64_t *token);
/* NO_DATA is valid only for zero/WWI/authorization-error plans that cannot have
 * posted DMA. Data plans require bridge-owned cleaned evidence, including
 * successful provider dereg and actual UNPIN; timeout alone is never evidence. */
/* Return a cancelled, unconsumed WWI reservation to its original queue
 * position. A closing original epoch instead terminalizes its own RQ. */
int npr_rq_wwi_unclaim(struct npr_rq *,uint64_t token);
int npr_rq_finish(struct npr_rq *,uint64_t token,enum ibv_wc_status rx_status,
 enum ibv_wc_status tx_status,enum npr_rq_cleanup_evidence);
void npr_rq_close(struct npr_rq *,enum npr_rq_close_mode);
int npr_rq_cancel_requested(const struct npr_rq *,uint64_t token);
/* Stable terminal descriptors retain no MR leases. Core can wait for CQ space,
 * or discard only after successful CQ/context lifecycle detach. */
int npr_rq_peek_terminal(struct npr_rq *,struct npr_rq_completion *);
int npr_rq_retire(struct npr_rq *,uint64_t token);
void npr_rq_get_counts(const struct npr_rq *,struct npr_rq_counts *);
#pragma GCC visibility pop
#endif
