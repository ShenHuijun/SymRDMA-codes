/* SPDX-License-Identifier: GPL-2.0 */
#ifndef RDV_PROTOCOL_H
#define RDV_PROTOCOL_H
#include "control_protocol.h"

/* Pure payload codecs only: no DATA capability, RX dispatch, credit admission,
 * allocation, reassembly, owner state or application authorization. Session id
 * is carried by the existing outer header, never local transport_generation.
 * Replies preserve original sender/receiver orientation. */
#define RDVP_CAPS_SIZE 172u
#define RDVP_COMMON_SIZE 192u
#define RDVP_OFFER_SIZE 224u
#define RDVP_SEGMENT_SIZE 24u
#define RDVP_SEGMENTS_PER_FRAME ((CONTROL_PAYLOAD_MAX-RDVP_OFFER_SIZE)/RDVP_SEGMENT_SIZE)
#define RDVP_DRAIN_SIZE 172u
/* Nonce is the nonzero outer request_id; replies retain request orientation. */
enum rdvp_drain_status {RDVP_DRAIN_COMPLETE=0,RDVP_DRAIN_WAIT,RDVP_DRAIN_TIMEOUT,RDVP_DRAIN_CLOSED};
struct rdvp_drain {struct sir_app_qp_endpoint sender,receiver;enum rdvp_drain_status status;};
#define RDVP_WAIT_SIZE 200u
#define RDVP_ACK_SIZE 208u
#define RDVP_CANCEL_SIZE 200u
#define RDVP_RETIRED_SIZE RDVP_COMMON_SIZE
#define RDVP_F_SOLICITED 1u

enum rdvp_message_kind { RDVP_SEND=1,RDVP_SEND_IMM,RDVP_WWI };
enum rdvp_status {
 RDVP_OK=0,RDVP_SINK_PROTECTION,RDVP_SINK_LENGTH,
 RDVP_CANCELLED_UNMATCHED,RDVP_CANCELLED_MATCHED,RDVP_TRANSPORT_FAILURE,RDVP_REMOTE_ACCESS
};
enum rdvp_cancel_reason {
 RDVP_LOCAL_QP_STOP=1,RDVP_RNR_EXHAUSTED,RDVP_SENDER_FAILURE,RDVP_SESSION_CLOSE
};
struct rdvp_message {
 struct sir_app_qp_endpoint sender,receiver;
 uint64_t message_id,sequence,total_length;
 uint8_t kind,flags;
};
/* address and rkey preserve their full bit patterns, including zero; the
 * codec does not infer DMA authorization or provider key allocation policy. */
struct rdvp_segment { uint64_t address,length;uint32_t rkey; };
/* Wire prefix: op@0:u32, kind@4:u8, flags@5:u8, reserved@6:u16,
 * sender@8:80B, receiver@88:80B, msgid@168:u64, seq@176:u64, len@184:u64.
 * OFFER suffix: imm@192:4raw, total_segments@196:u32, fragment_count@200:u32,
 * index@204:u32, segment_offset@208:u32, entry_count@212:u32, msg_offset@216:u64.
 * Segment = address:u64,length:u64,rkey:u32,reserved:u32 (24B). Canonical
 * pages of SEGMENTS_PER_FRAME; no global SGE cap. Reassembly owns cross-page
 * continuity/conflict checks; codec verifies first offset zero and final sum. */
struct rdvp_offer {
 struct rdvp_message message;
 /* Four opaque already-network-order verbs immediate bytes; no double hton. */
 uint32_t imm_be,total_segments,fragment_count,fragment_index,segment_offset,entry_count;
 uint64_t message_offset;
};
/* op@0, sender@4, receiver@84, source_sge_limit@164, feature flags@168.
 * Limit is actual sender-visible source capability, including a legal inline
 * representation when applicable; it is never inferred from receiver limits. */
struct rdvp_caps {struct sir_app_qp_endpoint sender,receiver;uint32_t source_sge_limit,flags;};
#define RDVP_CAP_NATIVE_WWI 2u
struct rdvp_wait {struct rdvp_message message;uint8_t min_rnr_timer;};
struct rdvp_ack {struct rdvp_message message;enum rdvp_status status;uint64_t completed_length;};
struct rdvp_cancel {struct rdvp_message message;enum rdvp_cancel_reason reason;};
#pragma GCC visibility push(hidden)
/* Encode: positive encoded length, -EINVAL invalid value, -ENOSPC small buffer.
 * Decode: zero, -EPROTO malformed wire, -ENOSPC output segment capacity too small.
 * Failed decode leaves output unchanged. Callers provide finite frame storage.
 * Codec validates individual endpoints, not current BOUND peer authorization. */
int rdvp_drain_encode(uint8_t *,uint32_t,uint32_t op,const struct rdvp_drain *);
int rdvp_drain_decode(const uint8_t *,uint32_t,uint32_t *op,struct rdvp_drain *);
int rdvp_caps_encode(uint8_t *,uint32_t,const struct rdvp_caps *);
int rdvp_caps_ack_encode(uint8_t *,uint32_t,const struct rdvp_caps *);
int rdvp_caps_ack_decode(const uint8_t *,uint32_t,struct rdvp_caps *);
int rdvp_caps_decode(const uint8_t *,uint32_t,struct rdvp_caps *);
int rdvp_offer_encode(uint8_t *,uint32_t,const struct rdvp_offer *,const struct rdvp_segment *);
int rdvp_offer_decode(const uint8_t *,uint32_t,struct rdvp_offer *,struct rdvp_segment *,uint32_t capacity);
int rdvp_wait_encode(uint8_t *,uint32_t,const struct rdvp_wait *);
int rdvp_wait_decode(const uint8_t *,uint32_t,struct rdvp_wait *);
int rdvp_ack_encode(uint8_t *,uint32_t,uint32_t op,const struct rdvp_ack *);
int rdvp_ack_decode(const uint8_t *,uint32_t,uint32_t *op,struct rdvp_ack *);
int rdvp_cancel_encode(uint8_t *,uint32_t,const struct rdvp_cancel *);
int rdvp_cancel_decode(const uint8_t *,uint32_t,struct rdvp_cancel *);
/* Exact per-message retirement, only after peer final ACK + actual local source
 * cleanup. ACK TX completion is insufficient. Later owner tracks contiguous
 * retired floor without crossing holes; this stateless codec never drops replay. */
int rdvp_retired_encode(uint8_t *,uint32_t,const struct rdvp_message *);
int rdvp_retired_decode(const uint8_t *,uint32_t,struct rdvp_message *);
#pragma GCC visibility pop
#endif
