/* SPDX-License-Identifier: GPL-2.0 */
#ifndef APP_QP_BINDING_H
#define APP_QP_BINDING_H

#include "control_log.h"
#include <stdint.h>

/* Internal metadata interface. No native QP/PD/context pointers cross it. */
struct sir_app_qp_mailbox;

enum sir_app_qp_policy {
	SIR_APP_QP_NATIVE_ONLY = 0,
	SIR_APP_QP_RENDEZVOUS_REQUIRED = 1,
};
enum sir_app_qp_route_kind {
	SIR_APP_QP_ROUTE_GID = 1,
	SIR_APP_QP_ROUTE_LID = 2,
};
struct sir_app_qp_key {
	uint64_t cookie;
	uint64_t generation;
};
struct sir_app_qp_route {
	uint64_t connection_epoch;
	uint32_t local_qpn, peer_qpn;
	uint8_t local_gid[16], peer_gid[16];
	uint16_t local_lid, peer_lid;
	uint8_t port_num;
	uint8_t kind;
};
/* Value descriptor; wire code encodes fields explicitly, never sizeof/memcpy.
 * GID routes validate/cross-match GIDs; LID routes validate/cross-match LIDs.
 * port_num belongs to this endpoint and is never compared across hosts.
 * No APM/alternate-path interpretation is implied. */
struct sir_app_qp_endpoint {
	struct sir_app_qp_key key;
	struct sir_app_qp_route route;
	uint64_t bind_nonce;
	uint8_t policy;
};
enum sir_app_qp_binding_state {
	SIR_APP_QP_UNPUBLISHED = 0,
	SIR_APP_QP_WAIT_SESSION,
	SIR_APP_QP_WAIT_PEER,
	SIR_APP_QP_BOUND,
	SIR_APP_QP_WITHDRAWN,
	SIR_APP_QP_UNAVAILABLE,
	SIR_APP_QP_CLOSED,
	SIR_APP_QP_NATIVE,
};
enum sir_app_qp_withdraw_reason {
	SIR_APP_QP_LOCAL_RESET = 1,
	SIR_APP_QP_LOCAL_ERROR,
	SIR_APP_QP_PATH_CHANGED,
	SIR_APP_QP_DESTROY_PREPARE,
};
#define SIR_APP_QP_SESSION_CLOSING (1u << 0)
#define SIR_APP_QP_DMA_STOPPED (1u << 1)
struct sir_app_qp_snapshot {
	uint64_t serial;
	uint64_t command_revision;
	uint64_t transport_generation;
	uint64_t session_id;
	uint32_t state;
	uint32_t
	    status; /* zero or positive errno, distinct from binding state */
	uint32_t
	    flags; /* CLOSING and real DMA_STOPPED are different evidence */
	struct sir_app_qp_endpoint local, peer;
};

/* Capture once at application QP creation, before its first MR/WR. Existing
 * SYMRDMA_PEER/SYMRDMA_SIR_TCP or explicitly captured peer config count as
 * configured even if malformed/down; this does not start/wait for a session. */
CRT_INTERNAL int sir_app_qp_peer_configured(void);

/* Dynamic, one-to-one allocation before provider QP create: no artificial
 * application-QP count limit. NULL+errno on allocation/identity error, and no
 * native calls, PIN, transport start or binding publication on failure.
 * Core owns the producer reference; control borrows the stable mailbox. */
CRT_INTERNAL struct sir_app_qp_mailbox *
sir_app_qp_mailbox_new(const struct sir_app_qp_key *, enum sir_app_qp_policy);

/* Nonblocking metadata copies. Return zero or positive errno. Revisions are
 * nonzero, strictly increasing across BOTH publish and withdraw. A publish can
 * reuse a connection_epoch after a failed tentative native destroy; the new
 * command revision/nonce still invalidates every old reply. Core publishes
 * only actual successful native path state. No provider call occurs here.
 * Publish/withdraw can repeat for this QP; neither permanently closes it. */
CRT_INTERNAL int sir_app_qp_publish(struct sir_app_qp_mailbox *,
				    uint64_t command_revision,
				    const struct sir_app_qp_route *);
CRT_INTERNAL int sir_app_qp_withdraw(struct sir_app_qp_mailbox *,
				     uint64_t command_revision,
				     enum sir_app_qp_withdraw_reason);

/* Terminal and idempotent. Only after successful native QP destruction (or
 * precreate rollback), never before a destroy attempt which might fail.
 * Future publish/withdraw fail ESHUTDOWN. No waiting for actor/app ACK. */
CRT_INTERNAL void sir_app_qp_mailbox_close(struct sir_app_qp_mailbox *);
CRT_INTERNAL void sir_app_qp_mailbox_put(struct sir_app_qp_mailbox *);

/* Copies the latest typed inbox under its short metadata lock; never waits on
 * actor/network and never takes the NPR API gate. Core checks key/epoch and
 * command_revision against its current connection before trusting BOUND.
 * BOUND is binding-only: it does not advertise RDV_DATA, enable data DMA,
 * consume RQ, generate WC or authorize peer-unmatched-RQ flush.
 * A snapshot's epoch identifiers are values, not transport resource borrows.
 * Transport invalidation does not wait for this snapshot to be consumed. */
CRT_INTERNAL int sir_app_qp_snapshot(struct sir_app_qp_mailbox *,
				     struct sir_app_qp_snapshot *);

#endif
