/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_TRANSPORT_H
#define CONTROL_TRANSPORT_H

#include <infiniband/verbs.h>

#include <stdint.h>
#include "control_log.h"
#include "control_protocol.h"

#ifndef IBV_QP_MTU
#define IBV_QP_MTU IBV_QP_PATH_MTU
#endif

#define CTRANS_DATA_SLOTS CONTROL_DATA_FRAME_CREDIT
#define CTRANS_TX_CTRL_SLOTS   4u
#define CTRANS_TX_SLOTS        (2u * CONTROL_WINDOW_MAX + CTRANS_TX_CTRL_SLOTS + CTRANS_DATA_SLOTS)
#define CTRANS_RX_SLOTS        (2u * CONTROL_WINDOW_MAX + CTRANS_TX_CTRL_SLOTS + CTRANS_DATA_SLOTS)
#define CTRANS_REV_SLOTS       CONTROL_REVERSE_WINDOW_MAX
#define CONTROL_CQ_MARGIN      16u

#define CTRANS_WRID_TX_BASE    0x4354580000000000ull
#define CTRANS_WRID_RX_BASE    0x4352580000000000ull
#define CTRANS_WRID_REV_BASE   0x4352560000000000ull

static inline uint64_t ctrans_wrid_make(uint64_t base, uint32_t idx)
{
	return base | (uint64_t)idx;
}

static inline uint64_t ctrans_wrid_kind(uint64_t wrid, uint32_t *idx)
{
 if((wrid&0xffffff0000000000ull)==CTRANS_WRID_REV_BASE){*idx=UINT32_MAX;return CTRANS_WRID_REV_BASE;}
	*idx = (uint32_t)(wrid & 0xffffffffu);
	switch (wrid >> 32) {
	case (uint32_t)(CTRANS_WRID_TX_BASE >> 32):
		return CTRANS_WRID_TX_BASE;
	case (uint32_t)(CTRANS_WRID_RX_BASE >> 32):
		return CTRANS_WRID_RX_BASE;
	case (uint32_t)(CTRANS_WRID_REV_BASE >> 32):
		return CTRANS_WRID_REV_BASE;
	}
	return 0;
}

CRT_INTERNAL uint32_t ctrans_window_reverse(uint32_t rmax,
					     uint32_t init_rd_atom,
					     uint32_t dest_rd_atom,
					     uint32_t prov_init_rd_atom,
					     uint32_t prov_resp_rd_atom,
					     uint32_t rev_slots);

CRT_INTERNAL uint32_t ctrans_cq_depth_min(uint32_t rx_slots, uint32_t tx_slots,
					   uint32_t reverse_slots);

enum ctrans_tx_class {
	CTRANS_TX_REQUEST = 0,
	CTRANS_TX_RESPONSE,
	CTRANS_TX_CONTROL,
	CTRANS_TX_DATA,

	CTRANS_TX_CLASS_N,
};

/* Session-owned, physical DATA frames; never RPC request retirement. */
struct ctrans_data_credit {uint64_t tx_total,peer_retired,rx_seen,rx_retired,credit_sent;uint32_t peer_initial,local_initial;};
CRT_INTERNAL int ctrans_data_init(struct ctrans_data_credit *,uint32_t,uint32_t);
CRT_INTERNAL int ctrans_data_can_send(const struct ctrans_data_credit *);
CRT_INTERNAL int ctrans_data_sent(struct ctrans_data_credit *);
CRT_INTERNAL int ctrans_data_credit_recv(struct ctrans_data_credit *,uint64_t);
CRT_INTERNAL int ctrans_data_received(struct ctrans_data_credit *);
CRT_INTERNAL int ctrans_data_reposted(struct ctrans_data_credit *);

enum ctrans_tx_state {
	CTRANS_TX_FREE = 0,
	CTRANS_TX_RESERVED,
	CTRANS_TX_POSTED,
};

struct ctrans_tx_tag {
	uint64_t session_id;
	uint64_t request_id;
	uint64_t job_id;
	int64_t  post_ns;
	uint16_t phase;
	uint16_t status;
};

struct ctrans_tx_pool {
	uint8_t  buf[CTRANS_TX_SLOTS][CONTROL_SLOT_CAPACITY];
	uint8_t  state[CTRANS_TX_SLOTS];
	uint8_t  slot_class[CTRANS_TX_SLOTS];

	uint16_t in_flight[CTRANS_TX_CLASS_N];
	uint32_t caps[CTRANS_TX_CLASS_N];

	uint32_t post_gen[CTRANS_TX_SLOTS];
	uint32_t used;
	struct ctrans_tx_tag tag[CTRANS_TX_SLOTS];
	int      fail_closed;
	long     violations;
};

CRT_INTERNAL void ctrans_tx_init(struct ctrans_tx_pool *p, uint32_t request_cap,
				  uint32_t response_cap);
CRT_INTERNAL int ctrans_tx_reserve(struct ctrans_tx_pool *p,
				    enum ctrans_tx_class cls, uint32_t *idx);
CRT_INTERNAL uint8_t *ctrans_tx_payload(struct ctrans_tx_pool *p, uint32_t idx);

CRT_INTERNAL int ctrans_tx_abort(struct ctrans_tx_pool *,uint32_t);
CRT_INTERNAL int ctrans_tx_post(struct ctrans_tx_pool *p, uint32_t idx);
CRT_INTERNAL void ctrans_tx_tag_set(struct ctrans_tx_pool *p, uint32_t idx,
				    uint16_t phase, uint64_t session_id,
				    uint64_t request_id, uint64_t job_id,
				    int64_t post_ns);
CRT_INTERNAL int  ctrans_tx_tag_get(const struct ctrans_tx_pool *p,
				    uint32_t idx, struct ctrans_tx_tag *out);
CRT_INTERNAL int ctrans_tx_release(struct ctrans_tx_pool *p, uint32_t idx);

CRT_INTERNAL int ctrans_tx_set_window(struct ctrans_tx_pool *p,
				       uint32_t request_cap,
				       uint32_t response_cap);

enum ctrans_rx_state {
	CTRANS_RX_FREE = 0,
	CTRANS_RX_POSTED,
	CTRANS_RX_RESERVED,
};

struct ctrans_rx_pool {
	uint8_t  buf[CTRANS_RX_SLOTS][CONTROL_SLOT_CAPACITY];
	uint32_t byte_len[CTRANS_RX_SLOTS];
	uint8_t  state[CTRANS_RX_SLOTS];
	uint8_t  in_rq[CTRANS_RX_SLOTS];
	uint32_t outstanding;
	int      fail_closed;
	long     violations;
};

CRT_INTERNAL void ctrans_rx_init(struct ctrans_rx_pool *p);

CRT_INTERNAL int ctrans_rx_give(struct ctrans_rx_pool *p, uint32_t idx);

CRT_INTERNAL uint8_t *ctrans_rx_take(struct ctrans_rx_pool *p, uint32_t idx,
				      uint32_t wc_byte_len);

CRT_INTERNAL int ctrans_rx_release(struct ctrans_rx_pool *p, uint32_t idx);

CRT_INTERNAL int ctrans_rx_invariant_ok(const struct ctrans_rx_pool *p);

enum ctrans_rev_state {
	CTRANS_REV_FREE = 0,
	CTRANS_REV_ARMED,
	CTRANS_REV_POSTED,
};

enum ctrans_rev_domain { CTRANS_REV_COWN=1, CTRANS_REV_RDV };
struct ctrans_epoch;
struct ctrans_rev_ticket {
 uint64_t token,epoch_generation,owner_token;
 uint32_t domain,dir;
 unsigned posted,accounted;
};
struct ctrans_rev_slot {
 uint8_t state;
 struct ctrans_rev_ticket ticket;
};

struct ctrans_rev_pool {
	struct ctrans_rev_slot slot[CTRANS_REV_SLOTS];
	uint32_t in_flight;
	uint32_t cap;
	int      fail_closed;
	long     violations;
};

CRT_INTERNAL void ctrans_rev_init(struct ctrans_rev_pool *p);

CRT_INTERNAL int ctrans_rev_set_window(struct ctrans_rev_pool *p, uint32_t rw);
/* Full process-unique token, never a slot index or application wr_id. */
CRT_INTERNAL int ctrans_rev_arm(struct ctrans_rev_pool *,uint64_t epoch_generation,
 enum ctrans_rev_domain,uint64_t owner_token,uint32_t dir,uint64_t *token);
CRT_INTERNAL int ctrans_rev_post(struct ctrans_rev_pool *,uint64_t token);
CRT_INTERNAL int ctrans_rev_lookup(const struct ctrans_rev_pool *,uint64_t token,struct ctrans_rev_ticket *);
CRT_INTERNAL int ctrans_rev_release(struct ctrans_rev_pool *,uint64_t token,struct ctrans_rev_ticket *);
/* Abort only an ARMED, never accepted WR. POSTED ownership is retired only
 * by exact WC or certified original-QP stop; native rejection rollback is private. */
CRT_INTERNAL int ctrans_rev_abort(struct ctrans_rev_pool *,uint64_t token);
/* One exact old-epoch ticket at a time, only after real QP stopped. */
CRT_INTERNAL int ctrans_epoch_reverse_stopped(struct ctrans_epoch *,struct ctrans_rev_pool *,struct ctrans_rev_ticket *);

CRT_INTERNAL void ctrans_tx_reset(struct ctrans_tx_pool *p);
CRT_INTERNAL void ctrans_rx_reset(struct ctrans_rx_pool *p);
CRT_INTERNAL int ctrans_rev_reset(struct ctrans_rev_pool *p);

struct ctrans_ops {
	struct ibv_mr *(*reg_mr)(struct ibv_pd *, void *, size_t, int);
	int (*dereg_mr)(struct ibv_mr *);
	struct ibv_qp *(*create_qp)(struct ibv_pd *,
					    struct ibv_qp_init_attr *);
	int (*destroy_qp)(struct ibv_qp *);
	struct ibv_cq *(*create_cq)(struct ibv_context *, int, void *,
					    struct ibv_comp_channel *, int);
	int (*destroy_cq)(struct ibv_cq *);
	struct ibv_comp_channel *(*create_comp_channel)(struct ibv_context *);
	int (*destroy_comp_channel)(struct ibv_comp_channel *);
	int (*modify_qp)(struct ibv_qp *, struct ibv_qp_attr *, int);
	int (*req_notify_cq)(struct ibv_cq *, int);
	int (*get_cq_event)(struct ibv_comp_channel *, struct ibv_cq **,
			    void **);
	void (*ack_cq_events)(struct ibv_cq *, unsigned int);
	int (*query_gid)(struct ibv_context *, uint8_t, int, union ibv_gid *);
	int (*query_port)(struct ibv_context *, uint8_t,
			  struct ibv_port_attr *);
	int (*query_device)(struct ibv_context *, struct ibv_device_attr *);
};

CRT_INTERNAL void ctrans_ops_load_real(struct ctrans_ops *ops);

/* The owner holds the provider until every borrowed epoch is returned.
 * Borrowed users must enter a job before touching its PD/provider resources;
 * closing rejects new jobs, and stop waits asynchronously for existing jobs. */
struct ctrans_epoch;
struct ctrans_runtime_guard;
CRT_INTERNAL int ctrans_runtime_guard_acquire(struct ibv_context *,
					      struct ibv_pd *,
					      struct ctrans_runtime_guard **);
CRT_INTERNAL void ctrans_runtime_guard_release(struct ctrans_runtime_guard *);
/* Caller-owned stable record, kept alive with its epoch borrow on failure.
 * Success callback may release/free its owner. The record is terminal one-shot;
 * a retained record must be explicitly reinitialized before any later reuse. No
 * callback waits for reactor/API gate work. Only the transport owner (or
 * joined-owner reaper) invokes it. */
struct ctrans_cleanup {
	struct ctrans_cleanup *next;
	struct ctrans_epoch *epoch;
	int (*run)(void *);
	void *owner;
	int queued, active;
};
CRT_INTERNAL int ctrans_epoch_defer_cleanup(struct ctrans_epoch *,
					    struct ctrans_cleanup *,
					    int (*)(void *), void *);
CRT_INTERNAL int ctrans_epoch_cleanup_begin(struct ctrans_epoch *);
struct ctrans_epoch_info {
	uint64_t generation, session_id;
	unsigned borrows, jobs;
	int ready, closing, qp_stopped;
};
struct ctrans_provider;
CRT_INTERNAL void ctrans_epoch_set_wake(struct ctrans_provider *,
					void (*)(void *), void *);
CRT_INTERNAL int ctrans_provider_cleanup(struct ctrans_provider *);
CRT_INTERNAL int ctrans_epoch_cleanup_pending(const struct ctrans_provider *);
CRT_INTERNAL int64_t
ctrans_epoch_cleanup_deadline_us(const struct ctrans_provider *);
CRT_INTERNAL int ctrans_epoch_ready(struct ctrans_provider *,
				    uint64_t session_id);
CRT_INTERNAL int ctrans_epoch_acquire(struct ctrans_provider *,
				      struct ctrans_epoch **out);
CRT_INTERNAL void ctrans_epoch_release(struct ctrans_epoch *);
CRT_INTERNAL int ctrans_epoch_job_begin(struct ctrans_epoch *);
CRT_INTERNAL void ctrans_epoch_job_end(struct ctrans_epoch *);
CRT_INTERNAL int ctrans_epoch_job_valid(struct ctrans_epoch *);
CRT_INTERNAL int ctrans_epoch_close(struct ctrans_provider *);
CRT_INTERNAL int ctrans_epoch_jobs_busy(const struct ctrans_provider *);
CRT_INTERNAL int ctrans_epoch_snapshot(struct ctrans_epoch *,
				       struct ctrans_epoch_info *);
/* PD accessor requires a live borrow plus an active job, not just a raw
 * pointer. */
CRT_INTERNAL struct ibv_pd *ctrans_epoch_pd(struct ctrans_epoch *);
/* Actor/joined-owner only, caller already owns an epoch borrow + active job.
 * Reg refuses closing before entry; successful native handle is always returned
 * even if close races the call. Dereg is valid under a cleanup job. */
CRT_INTERNAL int ctrans_epoch_reg_bridge(struct ctrans_epoch *,void *,size_t,unsigned,struct ibv_mr **);
CRT_INTERNAL int ctrans_epoch_dereg_bridge(struct ctrans_epoch *,struct ibv_mr *);
CRT_INTERNAL int ctrans_epoch_post_read(struct ctrans_epoch *,struct ctrans_rev_pool *,uint64_t token,
 uint64_t local_addr,uint32_t lkey,uint64_t remote_addr,uint32_t rkey,uint32_t length);
CRT_INTERNAL int ctrans_provider_busy(const struct ctrans_provider *);
CRT_INTERNAL int ctrans_is_internal_qp(const struct ibv_qp *);
CRT_INTERNAL int ctrans_is_internal_cq(const struct ibv_cq *);
int sir_transport_pd_busy(const struct ibv_pd *);
int sir_transport_ctx_busy(const struct ibv_context *);
struct ctrans_provider {
 struct ctrans_rev_pool *reverse_pool;
	struct ctrans_epoch *epoch;
	struct ctrans_ops ops;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	struct ibv_comp_channel *ch;
	struct ibv_cq *cq;
	struct ibv_qp *qp;
	struct ibv_mr *tx_mr, *rx_mr;
	int ch_fd;
	uint32_t cq_depth;
	uint32_t max_send_wr, max_recv_wr;
	uint32_t rq_outstanding;
	uint32_t sq_outstanding;
	uint32_t dev_max_rd_atom;
	uint32_t dev_max_init_rd_atom;
	uint8_t  active_mtu;
	uint8_t  port_num;
	uint32_t tx_lkey, rx_lkey;
	int armed;
	int broken;
	int err_done;

};

CRT_INTERNAL int ctrans_provider_create(struct ctrans_provider *pv,
					 struct ibv_context *ctx,
					 struct ibv_pd *pd,
					 void *tx_buf, size_t tx_len,
					 void *rx_buf, size_t rx_len,
					 uint32_t tx_slots, uint32_t rx_slots,
					 uint32_t reverse_slots);
CRT_INTERNAL int ctrans_provider_destroy(struct ctrans_provider *pv);
/* Emergency DMA-stop evidence, not logical-owner retirement. Outstanding
 * counters stay intact for the session owner to reconcile after success. */
CRT_INTERNAL int ctrans_provider_force_stop(struct ctrans_provider *pv);

CRT_INTERNAL int ctrans_qp_init(struct ctrans_provider *pv);
CRT_INTERNAL int ctrans_qp_rtr(struct ctrans_provider *pv,
				uint32_t dest_qp, const union ibv_gid *dgid,
				int sgid_index, uint32_t rd_atom_dest);
CRT_INTERNAL int ctrans_qp_rts(struct ctrans_provider *pv, uint32_t psn,
				uint32_t rd_atom_init);

CRT_INTERNAL int ctrans_qp_err(struct ctrans_provider *pv);

CRT_INTERNAL int ctrans_post_recv(struct ctrans_provider *pv, void *buf,
				   uint32_t len, uint64_t wrid);
CRT_INTERNAL int ctrans_post_send(struct ctrans_provider *pv, void *buf,
				   uint32_t len, uint64_t wrid);
CRT_INTERNAL int ctrans_post_reverse(struct ctrans_provider *pv,struct ctrans_rev_pool *pool,
				      uint64_t wrid, int is_read,
				      uint64_t local_addr, uint32_t lkey,
				      uint64_t remote_addr, uint32_t rkey,
				      uint32_t len);

CRT_INTERNAL int ctrans_cq_notify(struct ctrans_provider *pv);
CRT_INTERNAL int ctrans_cq_get_event(struct ctrans_provider *pv,
				      void **cq_ctx);
CRT_INTERNAL void ctrans_cq_ack(struct ctrans_provider *pv,
				 unsigned int count);
CRT_INTERNAL int ctrans_poll(struct ctrans_provider *pv, struct ibv_wc *wc,
			      int cap);

CRT_INTERNAL int ctrans_drain(struct ctrans_provider *pv, struct ibv_wc *wc,
			       int cap, uint32_t timeout_ms, long *drained);

#endif
