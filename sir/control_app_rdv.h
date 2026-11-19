/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CONTROL_APP_RDV_H
#define CONTROL_APP_RDV_H
#include "app_rdv_mailbox.h"
#include "control_log.h"
#include "rdv_bridge.h"
struct ctrl_reactor;
struct crdv_registry;
struct crdv_registration;
struct crdv_actor;
/* Actual visible application limits captured after native create. The storage
 * may be SQ+RQ+1, but SOURCE and matched SINK quotas never borrow each other.
 * The single prematch metadata credit permits NO_RQ even with rq_depth==0. */
struct crdv_qp_caps {
  uint32_t sq_depth, rq_depth, source_sge_limit, sink_sge_limit;
  uint8_t rnr_retry, min_rnr_timer;
};
struct crdv_registry_config {
  /* Wake-only callback outside locks; opaque survives successful registry_free.
   */
  void (*wake_actor)(void *);
  void *wake_opaque;
};
struct crdv_registration_config {
  struct sir_app_qp_key key;
  uint64_t connection_epoch;
  struct sir_rdv_mailbox *mailbox;
  struct crdv_qp_caps caps;
  unsigned native_wwi;
};
struct crdv_offer_snapshot {
  uint64_t attempt, stream_base;
  unsigned stream_first,native_wwi;
  struct sir_rdv_value value;
};
/* value.status is always zero/positive errno, never rdvp_status or WC opcode.
 * MATCH EACCES/EMSGSIZE prescribes sink protection/length failure; actor skips
 * READ, performs real cleanup, then maps once to typed wire ACK status. */
enum crdv_offer_result { CRDV_NO_RQ = 1, CRDV_RESOURCE_BACKPRESSURE };
enum crdv_rx_outcome { CRDV_RX_ACCEPTED = 1, CRDV_RX_IGNORED, CRDV_RX_RETRY };
struct crdv_stats {
  unsigned data_ready,native_wwi,native_error;
  /* Full actor-confirmed CAPS/BIND authority, copied atomically with ready.
   * Zero when not ready; local snapshot serial is not a peer wire identity. */
  struct sir_app_qp_snapshot authorization;
  struct sir_app_qp_key key;
  uint64_t connection_epoch, session_id, transport_generation;
  uint64_t source_messages_offered, source_offers_posted, sink_offers_received;
  uint64_t sink_matches, reverse_read_posted, reverse_read_wc,
      wire_ack_validated;
  uint64_t source_released, sink_released, actor_sources, actor_sinks;
  uint64_t wwi_offers_posted,wwi_ready_posted,native_arrivals;
  uint64_t actor_pin_spans, actor_bridge_mrs, actor_native_outstanding,
      actor_cleanup_pending;
};
/* Only runtime-owned transport resources cross this boundary, never an app
 * object. Production binds both callbacks to the same reactor pv/exec/rev.
 * All other lifecycle/proof/cleanup operations use actual rdv_bridge APIs. */
struct crdv_resource_ops {
  int (*prepare)(void *, const struct rdv_bridge_config *,
                 struct rdv_bridge_owner **);
  int (*read_prepare)(void *, struct rdv_bridge_owner *,
                      const struct rdv_bridge_remote *, unsigned);
};
struct crdv_frame {
  uint64_t ticket;
  size_t length;
  unsigned char bytes[4096];
};
#pragma GCC visibility push(hidden)
/* No native calls, PIN, API gate or callbacks under registry locks.
 * Registration acquires its mailbox external ref before publishing it. A caller
 * must retain the registry/registration ownership while using these handles; a
 * get from an unprotected pointer racing final free is never valid. There is no
 * QP cap. */
int crdv_registry_new(const struct crdv_registry_config *,
                      struct crdv_registry **);
/* Callback suitable for mailbox_config.wake_actor. Temporary wake refs protect
 * opaque across the unlocked callback and prevent registry_free success. */
void crdv_registry_wake(void *);
void crdv_registry_notify_apps(struct crdv_registry *);
void crdv_registry_close_producers(struct crdv_registry *);
int crdv_registry_free(struct crdv_registry *);
int crdv_register(struct crdv_registry *,
                  const struct crdv_registration_config *,
                  struct crdv_registration **);
/* Stops new authorization immediately; old owners and their original tuple
 * remain available for ACK/STOPPED/cleanup. EBUSY retains the handle and box.
 */
int crdv_registration_update_attrs(struct crdv_registration *,
                                   uint8_t rnr_retry, uint8_t min_rnr_timer);
int crdv_registration_close(struct crdv_registration *);
int crdv_registration_free(struct crdv_registration *);
/* OFFER_READY names an actor-reserved SINK slot, not a core owner. Core adopts
 * exactly {registration,slot,app_token}, keeps the delivery until processed,
 * and copies this immutable attempt snapshot before RQ claim. The first
 * authorized OFFER establishes stream_base; subsequent offers never do.
 * Directional stream identity is both cookie/generation/connection_epoch,
 * excluding bind nonce. Nonce refresh does not reset the logical stream.
 * Actor offers in SOURCE_PREPARE acceptance FIFO, even if later PIN is ready.
 */
/* Gate-to-actor native arrival; copies metadata only, no application pointers. */
int crdv_native_arrival(struct crdv_registration *,const struct sir_rdv_value *);
int crdv_offer_snapshot(struct crdv_registration *, uint64_t slot,
                        uint64_t app_token, struct crdv_offer_snapshot *);
/* Separate bounded receipt, never overwrites immutable MATCH_PREPARE. Success
 * claim submits MATCH_PREPARE on the existing slot. Failure does not pop RQ.
 * NO_RQ retires this unclaimed slot with SINK_RELEASED/NO_DATA and sends WAIT;
 * only a legal sender retry creates a fresh slot/attempt. post_recv must not
 * revive it. RESOURCE_BACKPRESSURE keeps the same matchable attempt, no RNR.
 * attempt is a nonzero local token, not mailbox serial or wire request_id. */
int crdv_offer_reply(struct crdv_registration *, uint64_t slot,
                     uint64_t app_token, uint64_t attempt,
                     enum crdv_offer_result);
/* Actor owner is the existing SIR reactor, or its explicit joined replacement.
 * Current full BOUND is revalidated by cbind_current for new work; app-copied
 * metadata is not authority. Old terminal proof uses the original full tuple.
 * actor lifetime retains the registry; no app/provider object pointer enters.
 */
int crdv_actor_new(struct crdv_registry *, struct ctrl_reactor *,
                   const struct crdv_resource_ops *, void *resource_opaque,
                   struct crdv_actor **);
int crdv_actor_free(struct crdv_actor *);
void crdv_progress(struct crdv_actor *, uint64_t now_us);
/* Earliest monotonic absolute usec timer, or UINT64_MAX. Reactor must include
 * this in its real wait; no unrelated event/busy polling is required for RNR.
 */
uint64_t crdv_next_deadline(struct crdv_actor *);
/* Only copies actor-published counters under a short metadata lock. No waits
 * for actor/native completion and no API-gate acquisition. */
int crdv_registration_final_stats(struct crdv_registration *,
                                  struct crdv_stats *);
int crdv_stats_snapshot(struct crdv_registration *, struct crdv_stats *);
int crdv_receive(struct crdv_actor *, const void *frame, size_t length,
                 uint64_t now_us, enum crdv_rx_outcome *);
/* Complete wire frames, with independent finite DATA credit. Terminal control
 * frames win over OFFER. No native acceptance until tx_result(ticket,0).
 * EAGAIN rejects this take without losing its frame; other error closes the
 * transport authorization, retaining all exposed-resource obligations. */
int crdv_frame_take(struct crdv_actor *, struct crdv_frame *);
int crdv_tx_result(struct crdv_actor *, uint64_t ticket, int result);
int crdv_session_up(struct crdv_actor *, uint64_t session_id);
void crdv_session_down(struct crdv_actor *, int dma_stopped);
#pragma GCC visibility pop
#endif
