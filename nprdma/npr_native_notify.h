/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_NATIVE_NOTIFY_H
#define NPR_NATIVE_NOTIFY_H
#include <infiniband/verbs.h>
#include <stddef.h>
#include <stdint.h>

/* Internal SEND envelope. Never place it in the application's receive SGEs.
 * Explicit byte encoding, independent of host ABI, padding and endianness. */
#define NPR_NOTIFY_BYTES 120u
enum npr_notify_kind { NPR_NOTIFY_SEND=1, NPR_NOTIFY_SEND_IMM, NPR_NOTIFY_WWI };
struct npr_notify_endpoint { uint64_t cookie,generation,epoch; };
struct npr_notify_message {
 struct npr_notify_endpoint source,target;
 uint64_t message_id,sequence,length,remote_address;
 uint64_t session_id,source_nonce,target_nonce;
 uint32_t remote_rkey,imm_be;
 unsigned kind,solicited;
};

#pragma GCC visibility push(hidden)
int npr_notify_encode(void *,size_t,const struct npr_notify_message *);
int npr_notify_decode(const void *,size_t,struct npr_notify_message *);
/* Caller validates the peer binding before exposing any completion. Matching
 * only a wr_id or QPN is insufficient after RESET/reconnect. */
int npr_notify_authorize(const struct npr_notify_message *,
 const struct npr_notify_endpoint *source,const struct npr_notify_endpoint *target);
/* The provider WC is for an internal RECV buffer; the original WWI RQ SGEs
 * are deliberately absent from this interface. Errors never expose metadata. */
int npr_notify_wwi_completion(const struct ibv_wc *,uint64_t original_wr_id,
 const struct npr_notify_message *,struct ibv_wc *);
/* One internal SEND after the verified WRITE. The caller owns registration,
 * native identity, SQ admission and memory until the provider WC. */
int npr_notify_send_wr(struct ibv_send_wr *,struct ibv_sge *,uint64_t token,
 uint64_t address,uint32_t lkey,unsigned solicited);

/* Data completion and receiver receipt are separate evidence. A native SEND
 * WC alone cannot release a source still needed by target-side repair. All
 * calls are serialized by the NPR API gate. No pre-data READY state exists. */
struct npr_notify_tx {
 uint64_t generation;
 enum ibv_wc_status data_status,send_status,receipt_status;
 unsigned data_done,send_posted,send_done,send_rejected,receipt_done,stopped,retired;
};
void npr_notify_tx_init(struct npr_notify_tx *,uint64_t generation);
int npr_notify_tx_data(struct npr_notify_tx *,uint64_t,enum ibv_wc_status);
int npr_notify_tx_posted(struct npr_notify_tx *,uint64_t);
/* Only for a proven unaccepted notification WR, after data cleanup. A partial
 * linked-list post must inspect bad_wr before using this no-exposure path. */
int npr_notify_tx_rejected(struct npr_notify_tx *,uint64_t,enum ibv_wc_status);
int npr_notify_tx_send(struct npr_notify_tx *,uint64_t,enum ibv_wc_status);
int npr_notify_tx_receipt(struct npr_notify_tx *,uint64_t,enum ibv_wc_status);
int npr_notify_tx_stopped(struct npr_notify_tx *,uint64_t);
/* Returns EAGAIN until cleanup is safe, then succeeds once. Notification
 * submission failure uses rejected proof, never a fake provider WC. */
int npr_notify_tx_retire(struct npr_notify_tx *,enum ibv_wc_status *);
#pragma GCC visibility pop
#endif
