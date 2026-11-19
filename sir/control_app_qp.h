/* SPDX-License-Identifier: GPL-2.0 */
#ifndef CONTROL_APP_QP_H
#define CONTROL_APP_QP_H
#include "app_qp_binding.h"
#include "control_protocol.h"
struct ctrl_reactor;
CRT_INTERNAL int cbind_actor_attach(struct ctrl_reactor *);
CRT_INTERNAL void cbind_actor_detach(struct ctrl_reactor *);
CRT_INTERNAL void cbind_session_ready(struct ctrl_reactor *,
				      uint64_t session_id,
				      uint64_t transport_generation,
				      uint32_t peer_caps);
CRT_INTERNAL void cbind_session_down(struct ctrl_reactor *, int dma_stopped);
/* Actor-side authority, not an app-provided snapshot. A pending producer
 * revision, retirement, withdrawn/closed QP, or noncurrent session is rejected
 * even if the previously published inbox still says BOUND. Values only. */
CRT_INTERNAL int cbind_current(struct ctrl_reactor *,const struct sir_app_qp_key *,struct sir_app_qp_snapshot *);
CRT_INTERNAL int cbind_progress(struct ctrl_reactor *);
CRT_INTERNAL int64_t cbind_next_deadline(struct ctrl_reactor *);
CRT_INTERNAL int cbind_rx(struct ctrl_reactor *, const struct cproto_header *,
			  const uint8_t *, uint32_t);
#endif
