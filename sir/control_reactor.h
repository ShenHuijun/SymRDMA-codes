/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_REACTOR_H
#define CONTROL_REACTOR_H

#include <pthread.h>
#include <stdint.h>
#include <infiniband/verbs.h>

#include "control_log.h"
#include "control_runtime.h"
#include "control_protocol.h"
#include "control_rpc.h"
#include "control_transport.h"
#include "control_executor.h"
#include "control_owner.h"
#include "endpoint_registry.h"
#include "control_rendezvous.h"
#include "peer_registry.h"
#include "control_session.h"
#include "control_app_rdv.h"

#define CTRL_SUB_RING            32u
#define CTRL_RPC_DEADLINE_US     (5ull * 1000 * 1000)
#define CTRL_CQ_BATCH            32
#define CTRL_HOT_MAX_ITERS       4096u
#define CTRL_HOT_MAX_US          500

#define CTRL_OP_HOT_HORIZON_US   200

struct ctrl_submit_ent {
	uint8_t  used;
	struct crpc_desc d;
	struct crpc_caller *caller;

	int64_t  t_push_ns;
	int64_t  t_efd_ns;
};

struct ctrl_reactor {
	struct ctrans_runtime_guard *lifetime_guard;
	int fatal_cleanup;
	struct crt_cfg cfg;

	struct ctrans_provider pv;
	struct ctrans_tx_pool tx;
	struct ctrans_rx_pool rx;
	struct ctrans_rev_pool rev;

	struct crpc_requester rreq;
	struct cexec exec;
	struct cown *own;

	pthread_mutex_t sub_mu;
	struct ctrl_submit_ent sub[CTRL_SUB_RING];
	uint32_t sub_head, sub_tail;
	int      sub_efd;

	int      hot;
	long     hot_spins;

	int64_t  op_hot_until_ns;
	uint8_t  rx_hold_idx[CTRANS_RX_SLOTS];
	uint32_t rx_hold_n;
	int64_t  rx_hold_due_us;

	int64_t  loop_entry_ns;

	pthread_t thread;
	int running;
	int quit;
	int fatal;
	int quit_efd;
	int timer_fd;
	int64_t timer_armed_us;

	struct csess *sess;

	struct crdv rdv;
	struct crdv_actor *app_rdv;
	struct ctrans_data_credit data_credit;
	uint64_t data_credit_sid;
	uint64_t data_rx_sid[CTRANS_RX_SLOTS];

	struct cpeer *peer;

	pthread_mutex_t sig_mu;
	pthread_cond_t  sig_cv;

	struct crpc_caller *ping_caller;
	uint64_t ping_nonce;
	uint64_t ping_seq;
	int64_t  ping_deadline_us;

};

CRT_INTERNAL int ctrl_tx_control(struct ctrl_reactor *r, uint16_t kind,
				  const uint8_t *payload, uint32_t plen,
				  uint64_t generation,
				  uint64_t trace_request_id);
CRT_INTERNAL void ctrl_mark_fatal(struct ctrl_reactor *r);
CRT_INTERNAL int  ctrl_is_fatal(const struct ctrl_reactor *r);
CRT_INTERNAL void ctrl_mark_qp_broken(struct ctrl_reactor *r);

CRT_INTERNAL void ctrl_signal_session(struct ctrl_reactor *r);
CRT_INTERNAL void ctrl_session_ready_hook(struct ctrl_reactor *r);
CRT_INTERNAL void ctrl_session_note_failed(struct ctrl_reactor *r);
CRT_INTERNAL void ctrl_snapshot_note_applied(struct ctrl_reactor *r);
CRT_INTERNAL void ctrl_requester_reset(struct ctrl_reactor *r,
					uint64_t session_id, uint32_t window);

CRT_INTERNAL int ctrl_tx_response(struct ctrl_reactor *r, uint32_t slot_idx,
				   uint64_t request_id,
				   const struct cown_resp *resp);

CRT_INTERNAL void ctrl_fail_pending_submits(struct ctrl_reactor *r);
CRT_INTERNAL void ctrl_fail_requests(struct ctrl_reactor *r);

CRT_INTERNAL int ctrl_submit(struct ctrl_reactor *r,
			      const struct crpc_desc *desc,
			      struct crpc_caller *caller);

CRT_INTERNAL struct cpeer *ctrl_peer_registry(struct ctrl_reactor *r);

CRT_INTERNAL int ctrl_reactor_has_work(struct ctrl_reactor *r);

CRT_INTERNAL void ctrl_reactor_op_hint(struct ctrl_reactor *r, int64_t until_ns);

CRT_INTERNAL int ctrl_session_wait(struct ctrl_reactor *r, uint32_t timeout_ms);

CRT_INTERNAL int ctrl_session_ready(const struct ctrl_reactor *r);

CRT_INTERNAL void ctrl_session_retry(struct ctrl_reactor *r);

CRT_INTERNAL void *ctrl_reactor_loop(void *arg);

CRT_INTERNAL int ctrl_app_rdv_attach(struct ctrl_reactor *);
CRT_INTERNAL int ctrl_app_rdv_detach(struct ctrl_reactor *);
CRT_INTERNAL void ctrl_app_rdv_progress(struct ctrl_reactor *);
CRT_INTERNAL void ctrl_app_rdv_down(struct ctrl_reactor *,int dma_stopped);

CRT_INTERNAL int ctrl_reverse_stopped(struct ctrl_reactor *);
CRT_INTERNAL int ctrl_reverse_wc(struct ctrl_reactor *,const struct ibv_wc *);
#endif
