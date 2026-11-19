#include "rdv_bridge.h"
/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "control_reactor.h"
#include "control_efd.h"
#include "control_app_qp.h"
#include "control_session.h"
#include "endpoint_registry.h"
#include "peer_registry.h"

struct csess_entry {
	uint32_t app_rkey;
	uint32_t app_access;
	uint32_t data_rkey;
	uint32_t write_rkey;
	uint32_t v_rkey;
	uint64_t addr;
	uint64_t len;
	uint64_t v_addr;
};

struct csess_snap_rx {
	uint64_t generation;
	uint32_t chunk_count;
	uint32_t chunks_got;
	uint8_t  seen[CONTROL_SNAPSHOT_CHUNKS_MAX];
	uint32_t n_entries;
	struct csess_entry entries[CPROTO_SNAP_ENTRIES_MAX];
	int      active;
};

struct csess {
	struct ctrl_reactor *r;

	uint8_t  state;
	uint64_t session_id;
	uint32_t peer_app_caps;
	uint32_t window;
	uint32_t window_in;
	uint32_t rev_window;
	uint64_t gen_local;
	int      snap_pub_pending;
	int      rts_done;
	int64_t  rts_retry_ms;
	int64_t  hs_deadline_us;
	int64_t  teardown_deadline_us;
	int64_t teardown_retry_us;
	int      hs_sent;
	int      hs_peer;
	int      snap_sent;
	int      snap_dirty;
	struct csess_snap_rx snap;

	struct creg_owner_view tx_view[CPROTO_SNAP_ENTRIES_MAX];
};

CRT_INTERNAL struct csess *csess_new(struct ctrl_reactor *r)
{
	struct csess *s = calloc(1, sizeof(*s));

	if (!s)
		return NULL;
	s->r = r;
	s->state = CSESS_DOWN;
	s->window_in = CONTROL_WINDOW_MAX;
	return s;
}

CRT_INTERNAL void csess_free(struct csess *s)
{
	free(s);
}

CRT_INTERNAL uint8_t csess_state(const struct csess *s)
{
	return s ? s->state : CSESS_DOWN;
}

CRT_INTERNAL int csess_ready(const struct csess *s)
{
	return s && s->state == CSESS_READY;
}

CRT_INTERNAL int csess_teardown_active(const struct csess *s)
{
	return s && s->state == CSESS_TEARDOWN;
}

CRT_INTERNAL uint64_t csess_session_id(const struct csess *s)
{
	return s ? s->session_id : 0;
}

CRT_INTERNAL uint32_t csess_window(const struct csess *s)
{
	return s ? s->window : 0;
}

CRT_INTERNAL uint32_t csess_window_in(const struct csess *s)
{
	return s ? s->window_in : CONTROL_WINDOW_MAX;
}

CRT_INTERNAL uint32_t csess_cap_rev_window(uint32_t rw, uint8_t cap)
{
	if (cap && rw > (uint32_t)cap)
		return (uint32_t)cap;
	return rw;
}

CRT_INTERNAL uint32_t csess_rev_window(const struct csess *s)
{
	return s ? s->rev_window : 0;
}

static int csess_local_gid(struct ctrl_reactor *r, union ibv_gid *g)
{
	if (!r->cfg.ctx || !r->pv.ops.query_gid)
		return -ENODEV;
	if (r->pv.ops.query_gid(r->cfg.ctx, r->pv.port_num, r->cfg.sgid_index,
				g))
		return -EIO;
	return 0;
}

static void csess_epoch_wake(void *arg)
{
 struct ctrl_reactor *r=arg;
 if(r->sub_efd>=0)crt_efd_write(r->sub_efd,1);
}

static int csess_provider_start(struct ctrl_reactor *r)
{
	int rc;

	if (r->pv.qp)
		return 0;
	if(ctrans_provider_busy(&r->pv))return -EBUSY;
	if (!r->cfg.ctx || !r->cfg.pd)
		return 0;
	rc = ctrans_provider_create(&r->pv, r->cfg.ctx, r->cfg.pd,
				    r->tx.buf, sizeof(r->tx.buf),
				    r->rx.buf, sizeof(r->rx.buf),
				    CTRANS_TX_SLOTS, CTRANS_RX_SLOTS,
				    CTRANS_REV_SLOTS);
	if (rc) {
		crt_log("provider create failed rc=%d", rc);
		return rc;
	}

	ctrans_epoch_set_wake(&r->pv,csess_epoch_wake,r);
	if (ctrans_qp_init(&r->pv)) {
		crt_log("QP INIT failed errno=%d", errno);
		return -EIO;
	}
	{
		uint32_t i;

		for (i = 0; i < CTRANS_RX_SLOTS; i++) {
			if (ctrans_rx_give(&r->rx, i)) {
				crt_log("RX initial give violation idx=%u", i);
				return -EPROTO;
			}
			if (ctrans_post_recv(&r->pv, r->rx.buf[i],
					     CONTROL_SLOT_CAPACITY,
					     ctrans_wrid_make(
						     CTRANS_WRID_RX_BASE, i))) {
				crt_log("RX initial post failed idx=%u errno=%d",
					 i, errno);
				return -EIO;
			}
		}
	}
	if (ctrans_cq_notify(&r->pv)) {
		crt_log("initial rearm failed");
		return -EIO;
	}
	crt_log("provider ready qp=0x%x cq=%u ch_fd=%d (dev rd_atom=%u/%u)",
		 r->pv.qp->qp_num, r->pv.cq_depth, r->pv.ch_fd,
		 r->pv.dev_max_init_rd_atom, r->pv.dev_max_rd_atom);
	return 0;
}

static int csess_rts_step(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	union ibv_gid dgid, local;
	uint32_t rd_atom;

	if (s->rts_done)
		return 0;
	if (csess_local_gid(r, &local))
		return -EIO;
	if (r->rdv.peer_gid_valid)
		dgid = *(union ibv_gid *)r->rdv.peer_gid;
	else
		dgid = local;
	rd_atom = s->rev_window ? s->rev_window : 1;
	rd_atom = rd_atom > r->pv.dev_max_rd_atom ? r->pv.dev_max_rd_atom :
						    rd_atom;
	if (ctrans_qp_rtr(&r->pv, r->rdv.peer_qp, &dgid, r->cfg.sgid_index,
			  rd_atom)) {
		crt_log("RTR failed errno=%d (dest=0x%x gid_valid=%c)",
			 errno, r->rdv.peer_qp,
			 r->rdv.peer_gid_valid ? 'Y' : 'N');
		return -EIO;
	}
	{
		uint32_t ri = s->rev_window ? s->rev_window : 1;

		ri = ri > r->pv.dev_max_init_rd_atom ?
			     r->pv.dev_max_init_rd_atom : ri;
		if (!ri)
			return -EIO;
		if (ctrans_qp_rts(&r->pv, 0, ri)) {
			crt_log("RTS failed errno=%d", errno);
			return -EIO;
		}
	}
	s->rts_done = 1;
	crt_log("RTS done (dest=0x%x rw=%u)", r->rdv.peer_qp, rd_atom);
	return 0;
}

static void csess_enter_snapshot(struct csess *s)
{
	if (s->state != CSESS_HANDSHAKE)
		return;
	s->state = CSESS_SNAPSHOT;
	s->hs_deadline_us = crt_now_us() + CSESS_CONNECT_TIMEOUT_MS * 1000;
}

static int csess_enter_handshake(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;

	ctrl_requester_reset(r, s->session_id,
			     s->window ? s->window : CONTROL_WINDOW_MAX);
	cown_ledger_reset(r);
	if (r->cfg.rdv_kind == CRDV_FILE)
		crdv_file_sync_own(&r->rdv);
	s->hs_deadline_us = crt_now_us() + CSESS_CONNECT_TIMEOUT_MS * 1000;
	s->hs_sent = 0;
	s->hs_peer = 0;
	s->snap_sent = 0;
	s->state = CSESS_HANDSHAKE;
	return 0;
}

static int csess_hello_send(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	struct cproto_caps caps;
	uint8_t pl[32];
	int rc;

	memset(&caps, 0, sizeof(caps));
	caps.protocol_version = CONTROL_PROTO_VERSION;
	caps.frame_capacity = CONTROL_SLOT_CAPACITY;
	caps.request_credit = s->window_in;
	caps.worker_capacity = CONTROL_EXEC_PENDING_MAX;
	caps.reverse_read_credit =
		r->pv.dev_max_rd_atom < CONTROL_REVERSE_WINDOW_MAX ?
			(r->pv.dev_max_rd_atom ? r->pv.dev_max_rd_atom : 1) :
			CONTROL_REVERSE_WINDOW_MAX;
	caps.reverse_write_credit = caps.reverse_read_credit;
	caps.session_flags=CPROTO_CAP_QP_BIND;
 if(CONTROL_RDV_DATA_ACTIVE&&r->app_rdv){caps.session_flags|=CPROTO_CAP_RDV_DATA;caps.data_frame_credit=CTRANS_DATA_SLOTS;}

	if (r->cfg.test_rd_atom_cap &&
	    caps.reverse_read_credit > r->cfg.test_rd_atom_cap) {
		caps.reverse_read_credit = r->cfg.test_rd_atom_cap;
		caps.reverse_write_credit = r->cfg.test_rd_atom_cap;
	}
	if (!s->session_id || cproto_hello_encode(pl, sizeof(pl), &caps) != 32)
		return -EPROTO;
	rc = ctrl_tx_control(r, CPROTO_CONTROL_EVENT, pl, 32, 0, 0);
	if (rc)
		return rc;
	s->hs_sent = 1;
	return 0;
}

static int csess_apply_peer_caps(struct ctrl_reactor *r,
				 const struct cproto_caps *c)
{
	struct csess *s = r->sess;
	uint32_t w, rw;

	w = crpc_window_request(CONTROL_WINDOW_MAX,
				(uint32_t)CONTROL_RPC_TABLE_CAP,
				c->request_credit,
				CTRANS_TX_SLOTS - CTRANS_TX_CTRL_SLOTS - CTRANS_DATA_SLOTS,
				CTRANS_RX_SLOTS, CONTROL_EXEC_PENDING_MAX,
				CTRANS_TX_SLOTS - CTRANS_TX_CTRL_SLOTS - CTRANS_DATA_SLOTS);
	rw = ctrans_window_reverse(CONTROL_REVERSE_WINDOW_MAX,
				   c->reverse_read_credit,
				   c->reverse_write_credit,
				   r->pv.dev_max_init_rd_atom ?
					   r->pv.dev_max_init_rd_atom : 1,
				   r->pv.dev_max_rd_atom ?
					   r->pv.dev_max_rd_atom : 1,
				   CTRANS_REV_SLOTS);

	rw = csess_cap_rev_window(rw, r->cfg.test_rd_atom_cap);
	if (!w || !rw) {
		crt_log("negotiated window zero (w=%u rw=%u) — session must not go READY",
			 w, rw);
		return -EPROTO;
	}
	if (r->cfg.test_rd_atom_cap)
		crt_log("test injection: rd_atomic clamp active rw=%u (cap=%u)",
			 rw, r->cfg.test_rd_atom_cap);
	s->window = w;
	s->rev_window = rw;
	if (ctrans_tx_set_window(&r->tx, w, w))
		return -EPROTO;

	if (ctrans_rev_set_window(&r->rev, rw)) {
		crt_log("reverse window publish failed rw=%u — session must not go READY", rw);
		return -EPROTO;
	}
	if(ctrans_data_init(&r->data_credit,
  CONTROL_RDV_DATA_ACTIVE&&r->app_rdv&&(c->session_flags&CPROTO_CAP_RDV_DATA)?CTRANS_DATA_SLOTS:0,
  CONTROL_RDV_DATA_ACTIVE&&r->app_rdv&&(c->session_flags&CPROTO_CAP_RDV_DATA)?c->data_frame_credit:0))return -EPROTO;
 r->data_credit_sid=s->session_id;memset(r->data_rx_sid,0,sizeof(r->data_rx_sid));
 if(r->cfg.app_rdv_capability_publish)r->cfg.app_rdv_capability_publish(
  r->cfg.app_rdv_service_opaque,c->session_flags&CPROTO_CAP_RDV_DATA?0:EOPNOTSUPP);
	ctrl_requester_reset(r, s->session_id, w);
	cown_ledger_reset(r);
	crt_log("HELLO agreed: w=%u rw=%u peer_credit=%u", w, rw,
		 c->request_credit);
	return 0;
}

CRT_INTERNAL void csess_rx_gate(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;

	if (s && s->state == CSESS_HANDSHAKE && s->hs_sent && s->hs_peer)
		csess_enter_snapshot(s);
}

CRT_INTERNAL int csess_rx_hello_gate(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;

	if (!s || s->state != CSESS_QP_CONNECT)
		return -1;
	r->rdv.peer_up = 1;
	if (csess_kick(r))
		return -1;
	if (s->state != CSESS_HANDSHAKE) {
		crt_log("HELLO early but local side still sess=%u (own_up=%d) — cannot advance",
			 s->state, r->rdv.own_up);
		return -1;
	}
	crt_log("HELLO early: peer-up evidence advances QP_CONNECT→HANDSHAKE "
		 "(TCP INFO event not yet processed)");
	return 0;
}

CRT_INTERNAL int csess_rx_hello(struct ctrl_reactor *r,
				 const struct cproto_header *h,
				 const uint8_t *payload, uint32_t plen)
{
	struct csess *s = r->sess;
	struct cproto_caps caps;

	if (cproto_hello_decode(payload, plen, &caps)) {
		crt_log("HELLO capability rejected (version/limit mismatch) — explicit failure");
		return -EPROTO;
	}
	if (r->rdv.role == 'b') {

		if (!s->hs_peer)
			s->session_id = h->session_id;
		else if (h->session_id != s->session_id)
			return -EPROTO;
	} else if (r->rdv.role == 'a') {

		if (h->session_id != s->session_id)
			return -EPROTO;
	} else {
		return -EPROTO;
	}
	s->peer_app_caps=caps.session_flags;
	if (csess_apply_peer_caps(r, &caps))
		return -EPROTO;
	s->hs_peer = 1;
	if (!s->hs_sent)
		return csess_hello_send(r);
	return 0;
}

CRT_INTERNAL void csess_mark_export_dirty(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;

	if (!s)
		return;
	s->snap_dirty = 1;
}

CRT_INTERNAL int csess_send_snapshot(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	struct cproto_export_entry ents[CPROTO_SNAP_ENTRIES_CHUNK];
	uint32_t n, i, chunk_count, ci;
	uint64_t gen;
	int truncated = 0;

	if (!s || (s->state != CSESS_SNAPSHOT && s->state != CSESS_READY))
		return 0;
	gen = ++s->gen_local;
	n = creg_owner_snapshot(s->tx_view, CPROTO_SNAP_ENTRIES_MAX,
				&truncated);
	if (truncated) {

		s->gen_local--;
		crt_log("local export table over protocol capacity %u — generation not published",
			 (unsigned)CPROTO_SNAP_ENTRIES_MAX);
		return -ENOSPC;
	}
	chunk_count = (n + CPROTO_SNAP_ENTRIES_CHUNK - 1) /
		      CPROTO_SNAP_ENTRIES_CHUNK;
	if (!chunk_count)
		chunk_count = 1;
	for (ci = 0; ci < chunk_count; ci++) {
		struct cproto_snap_chunk ch;
		uint8_t pl[CONTROL_PAYLOAD_MAX];
		uint32_t first = ci * CPROTO_SNAP_ENTRIES_CHUNK;
		uint32_t cnt = n - first;

		if (cnt > CPROTO_SNAP_ENTRIES_CHUNK)
			cnt = CPROTO_SNAP_ENTRIES_CHUNK;
		for (i = 0; i < cnt; i++) {
			const struct creg_owner_view *v = &s->tx_view[first + i];

			memset(&ents[i], 0, sizeof(ents[i]));
			ents[i].app_rkey = v->app_rkey;
			ents[i].app_access = v->app_access;
			ents[i].data_rkey = v->data_rkey;
			ents[i].write_rkey = v->write_rkey;
			ents[i].v_rkey = v->v_rkey;
			ents[i].addr = v->addr;
			ents[i].len = v->len;
			ents[i].v_addr = v->v_addr;
		}
		memset(&ch, 0, sizeof(ch));
		ch.generation = gen;
		ch.chunk_index = ci;
		ch.chunk_count = chunk_count;
		ch.entry_count = cnt;
		{
			int plen = cproto_snapshot_encode(pl, sizeof(pl), &ch,
							  cnt ? ents : NULL);
			int rc;

			if (plen < 0)
				return -EIO;
			rc = ctrl_tx_control(r, CPROTO_CONTROL_EVENT,
					     (uint8_t *)pl, (uint32_t)plen, gen,
					     0);
			if (rc == -EBUSY)
				return -EAGAIN;
			if (rc)
				return -EIO;
		}
	}
	crt_log("generation=%llu published (entries=%u chunks=%u)",
		 (unsigned long long)gen, n, chunk_count);
	return 0;
}

static void csess_maybe_ready(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;

	if (s->state != CSESS_SNAPSHOT || !s->snap_sent ||
	    !cpeer_ready(r->peer))
		return;
	if(ctrans_epoch_ready(&r->pv,s->session_id)) {
		csess_fail(r,CSESS_FAIL_ADMISSION);
		return;
	}
	s->state = CSESS_READY;
	s->hs_deadline_us = 0;
	struct ctrans_epoch *epoch=NULL;struct ctrans_epoch_info info={0};
	if(!ctrans_epoch_acquire(&r->pv,&epoch)){ctrans_epoch_snapshot(epoch,&info);ctrans_epoch_release(epoch);}
	cbind_session_ready(r,s->session_id,info.generation,s->peer_app_caps);
	crt_log("session READY (session=%llu generation=%llu)",
		 (unsigned long long)s->session_id,
		 (unsigned long long)cpeer_gen(r->peer));
	ctrl_session_ready_hook(r);
}

static int csess_publish_snapshot(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	struct csess_snap_rx *snap = &s->snap;
	struct cpeer_ent ents[CPROTO_SNAP_ENTRIES_MAX];
	uint32_t n_entries = snap->n_entries, i;
	int rc;

	for (i = 0; i < n_entries; i++) {
		ents[i].app_rkey = snap->entries[i].app_rkey;
		ents[i].app_access = snap->entries[i].app_access;
		ents[i].data_rkey = snap->entries[i].data_rkey;
		ents[i].write_rkey = snap->entries[i].write_rkey;
		ents[i].v_rkey = snap->entries[i].v_rkey;
		ents[i].addr = snap->entries[i].addr;
		ents[i].len = snap->entries[i].len;
		ents[i].v_addr = snap->entries[i].v_addr;
	}
	rc = cpeer_publish(r->peer, snap->generation, ents, n_entries);
	if (rc == -EBUSY) {
		s->snap_pub_pending = 1;
		return -EAGAIN;
	}
	if (rc == -EPROTO) {
		crt_log("peer generation=%llu non-monotonic (published=%llu) — protocol violation",
			 (unsigned long long)snap->generation,
			 (unsigned long long)cpeer_gen(r->peer));
		return -EPROTO;
	}
	if (rc)
		return rc;
	s->snap_pub_pending = 0;
	ctrl_snapshot_note_applied(r);

	memset(snap, 0, sizeof(*snap));
	crt_log("peer generation=%llu published (entries=%u)",
		 (unsigned long long)cpeer_gen(r->peer), n_entries);
	csess_maybe_ready(r);
	return 0;
}

CRT_INTERNAL int csess_rx_snapshot(struct ctrl_reactor *r,
				    const struct cproto_header *h,
				    const uint8_t *payload, uint32_t plen)
{
	struct csess *s = r->sess;
	struct csess_snap_rx *snap = &s->snap;
	struct cproto_snap_chunk ch;
	struct csess_entry ents[CPROTO_SNAP_ENTRIES_CHUNK];
	uint32_t n = 0, i;
	int rc;

	if (!h->generation) {
		crt_log("snapshot frame generation=0 — protocol violation");
		return -EPROTO;
	}
	{
		struct cproto_export_entry wire[CPROTO_SNAP_ENTRIES_CHUNK];

		rc = cproto_snapshot_decode(payload, plen, &ch, wire,
					    CPROTO_SNAP_ENTRIES_CHUNK, &n);
		if (rc)
			return rc;
		for (i = 0; i < n; i++) {
			ents[i].app_rkey = wire[i].app_rkey;
			ents[i].app_access = wire[i].app_access;
			ents[i].data_rkey = wire[i].data_rkey;
			ents[i].write_rkey = wire[i].write_rkey;
			ents[i].v_rkey = wire[i].v_rkey;
			ents[i].addr = wire[i].addr;
			ents[i].len = wire[i].len;
			ents[i].v_addr = wire[i].v_addr;
		}
	}

	if (ch.generation != h->generation || !ch.chunk_count ||
	    ch.chunk_count > CONTROL_SNAPSHOT_CHUNKS_MAX ||
	    ch.chunk_index >= ch.chunk_count)
		return -EPROTO;
	if (snap->active && (snap->generation != ch.generation ||
			     snap->chunk_count != ch.chunk_count))
		memset(snap, 0, sizeof(*snap));
	if (!snap->active) {
		memset(snap, 0, sizeof(*snap));
		snap->active = 1;
		snap->generation = ch.generation;
		snap->chunk_count = ch.chunk_count;
	}
	if (snap->seen[ch.chunk_index])
		return 0;
	if (snap->n_entries + n > CPROTO_SNAP_ENTRIES_MAX)
		return -EPROTO;
	snap->seen[ch.chunk_index] = 1;
	for (i = 0; i < n; i++)
		snap->entries[snap->n_entries++] = ents[i];
	if (snap->chunks_got < snap->chunk_count)
		snap->chunks_got++;
	if (snap->chunks_got < snap->chunk_count)
		return 0;
	rc = csess_publish_snapshot(r);
	if (rc == -EAGAIN)
		return 0;
	return rc;
}

CRT_INTERNAL int csess_progress(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;

	if (!s || ctrl_is_fatal(r) || cown_reset_pending(r))
		return 0;

	if (s->snap_pub_pending) {
		int rc = csess_publish_snapshot(r);

		if (rc == -EAGAIN)
			return 0;
		if (rc)
			return -EIO;
	}
	switch (s->state) {
	case CSESS_DOWN:
		if (r->cfg.rdv_kind == CRDV_TCP_CONNECT &&
		    r->rdv.next_retry_ms &&
		    crt_now_ms() < r->rdv.next_retry_ms)
			return 0;
		if (csess_provider_start(r))
			return -EIO;
		if (!r->cfg.ctx)
			return 0;
		if (r->pv.qp) {
			union ibv_gid lg;

			if (!csess_local_gid(r, &lg))
				crdv_set_own(&r->rdv, r->pv.qp->qp_num,
					     lg.raw, 1, 0);
		}
		s->hs_deadline_us = 0;
		s->state = CSESS_BOOTSTRAP;
		if (r->cfg.rdv_kind == CRDV_FILE) {
			crdv_elect_role_file(&r->rdv);
			crdv_file_sync_own(&r->rdv);
		}
		if (r->cfg.rdv_kind == CRDV_TCP_LISTEN)
			(void)crdv_tcp_listen(&r->rdv);
		break;
	case CSESS_BOOTSTRAP:
		if (r->cfg.rdv_kind == CRDV_TCP_CONNECT) {
			(void)crdv_tcp_reconnect(&r->rdv, crt_now_ms());
		}
		if (r->cfg.rdv_kind == CRDV_FILE) {
			unsigned pqp = 0;
			uint8_t gid[CRDV_GID_LEN];
			int gvalid = 0, pup = 0;
			union ibv_gid lg;

			if (!crdv_file_read_peer(&r->rdv, &pqp, gid, &gvalid,
						 &pup) && pqp) {
				r->rdv.peer_qp = pqp;
				r->rdv.peer_up = pup;
				r->rdv.peer_gid_valid = gvalid;
				if (gvalid)
					memcpy(r->rdv.peer_gid, gid,
					       CRDV_GID_LEN);
			}
			if (!r->rdv.own_qp && r->pv.qp) {
				if (!csess_local_gid(r, &lg))
					crdv_file_write_own(&r->rdv,
							    r->pv.qp->qp_num,
							    lg.raw, 0);
			}
		}
		if (r->rdv.peer_qp && r->rdv.peer_got) {
			s->state = CSESS_QP_CONNECT;
			s->rts_retry_ms = 0;
		}
		if (!s->hs_deadline_us &&
		    ((r->cfg.rdv_kind == CRDV_TCP_LISTEN &&
		      r->rdv.conn_fd >= 0) ||
		     (r->cfg.rdv_kind == CRDV_TCP_CONNECT &&
		      (r->rdv.conn_fd >= 0 ||
		       r->rdv.tcp_st == CRDV_TCP_CONNECTING)) ||
		     (r->cfg.rdv_kind == CRDV_FILE &&
		      r->rdv.peer_qp && r->rdv.peer_got))) {
			s->hs_deadline_us = crt_now_us() +
					    CSESS_CONNECT_TIMEOUT_MS * 1000;
		}
		break;
	case CSESS_QP_CONNECT:
		if (r->cfg.rdv_kind == CRDV_FILE) {
			unsigned pqp = 0;
			uint8_t gid[CRDV_GID_LEN];
			int gvalid = 0, pup = 0;

			if (!crdv_file_read_peer(&r->rdv, &pqp, gid, &gvalid,
						 &pup))
				r->rdv.peer_up = pup;
		}
		if (!r->rdv.own_up && !csess_rts_step(r)) {
			union ibv_gid lg;

			r->rdv.own_up = 1;
			if (r->pv.qp && !csess_local_gid(r, &lg))
				crdv_set_own(&r->rdv, r->pv.qp->qp_num, lg.raw,
					     1, 1);
			if (r->cfg.rdv_kind == CRDV_FILE)
				crdv_file_sync_own(&r->rdv);
			else
				(void)crdv_tcp_send_up(&r->rdv);
			crt_log("own RTS done — up published (role=%c)",
				 r->rdv.role);
		}
		if (r->rdv.own_up && r->rdv.peer_up) {
			if (r->rdv.role == 'a') {
				unsigned long long sid = 0;

				if (syscall(SYS_getrandom, &sid, sizeof(sid), 0)
				    != (ssize_t)sizeof(sid) || !sid)
					return -EIO;
				s->session_id = sid;
			} else if (r->rdv.role != 'b') {
				return -EPROTO;
			}
			if (csess_enter_handshake(r))
				return -EIO;
		}
		break;
	case CSESS_HANDSHAKE:

		if (!s->hs_sent && r->rdv.role == 'a' && csess_hello_send(r))
			return -EIO;
		if (s->hs_sent && s->hs_peer)
			csess_enter_snapshot(s);
		break;
	case CSESS_SNAPSHOT:
		if (!s->snap_sent) {
			int rc = csess_send_snapshot(r);

			if (rc == -EAGAIN)
				return 0;
			if (rc)
				return -EIO;
			s->snap_sent = 1;
			csess_maybe_ready(r);
		}
		break;
	case CSESS_READY:
		if (s->snap_dirty) {
			int rc = csess_send_snapshot(r);

			if (rc == -EAGAIN)
				return 0;
			if (rc)
				return -EIO;
			s->snap_dirty = 0;
		}
		break;
	default:
		break;
	}
	return 0;
}

CRT_INTERNAL int csess_kick(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	uint32_t i;

	if (!s)
		return 0;
	for (i = 0; i < 8; i++) {
		uint8_t before = s->state;

		if (csess_progress(r))
			return -1;
		if (s->state == before)
			break;
	}
	return 0;
}

CRT_INTERNAL int64_t csess_next_deadline_us(const struct csess *s)
{
	const struct ctrl_reactor *r;
	int64_t best = 0, cand;

	if (!s)
		return 0;
	r = s->r;
	best=ctrans_epoch_cleanup_deadline_us(&r->pv);
	if (s->state != CSESS_READY && s->state != CSESS_DOWN &&
	    s->state != CSESS_TEARDOWN && s->hs_deadline_us)
		best = s->hs_deadline_us;
	if (s->snap_pub_pending || s->snap_dirty ||
	    (s->state == CSESS_SNAPSHOT && !s->snap_sent)) {

		cand = crt_now_us() + 1000;
		if (!best || cand < best)
			best = cand;
	}
	if (s->state == CSESS_TEARDOWN && s->teardown_deadline_us) {
		cand=s->teardown_retry_us?s->teardown_retry_us:crt_now_us()+5*1000;
		if(!best||cand<best)best=cand;
	}
	if (s->state == CSESS_BOOTSTRAP && r->cfg.rdv_kind == CRDV_FILE) {
		cand = crt_now_us() + 10 * 1000;
		if (!best || cand < best)
			best = cand;
	}
	if (r->cfg.rdv_kind == CRDV_TCP_CONNECT && r->rdv.next_retry_ms) {
		cand = r->rdv.next_retry_ms * 1000;
		if (!best || cand < best)
			best = cand;
	}
	return best;
}

CRT_INTERNAL void csess_on_timer(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	uint64_t now = (uint64_t)crt_now_us();

	if (!s)
		return;
	if (s->state != CSESS_READY && s->state != CSESS_DOWN &&
	    s->hs_deadline_us && now >= (uint64_t)s->hs_deadline_us) {
		crt_log("bootstrap/handshake deadline hit (%u ms) — session fails for retry",
			 CSESS_CONNECT_TIMEOUT_MS);
		csess_fail(r, CSESS_FAIL_BOOTSTRAP_DEADLINE);
		return;
	}
	if (s->state == CSESS_BOOTSTRAP &&
	    r->cfg.rdv_kind == CRDV_TCP_CONNECT) {
		int rc = crdv_tcp_reconnect(&r->rdv, (int64_t)(now / 1000));

		if (rc < 0)
			r->rdv.next_retry_ms = (int64_t)(now / 1000) +
					       r->rdv.backoff_ms;
	}
}

CRT_INTERNAL void csess_retry(struct ctrl_reactor *r)
{
	if (!r || !r->sess)
		return;
	if (r->sess->state == CSESS_DOWN)
		r->rdv.next_retry_ms = 0;
}

CRT_INTERNAL void csess_fail(struct ctrl_reactor *r,
			      enum csess_fail_reason reason)
{
	struct csess *s = r->sess;

	if (!s || s->state == CSESS_TEARDOWN)
		return;
	ctrl_session_note_failed(r);
	crt_log("session failed: reason=%u (role=%c sess=%u)",
		 (unsigned)reason, r->rdv.role, s->state);
	crt_log("failure state: cexec fc=%d v=%ld | tx v=%ld | rx v=%ld | "
		 "rev v=%ld | rreq v=%ld",
		 r->exec.fail_closed, r->exec.violations, r->tx.violations,
		 r->rx.violations, r->rev.violations, r->rreq.violations);
	s->state = CSESS_TEARDOWN;
	s->teardown_deadline_us = crt_now_us() + 1000 * 1000;
	s->teardown_retry_us=0;
	s->snap.active = 0;
	s->snap_sent = 0;
	s->hs_deadline_us = 0;

	ctrans_epoch_close(&r->pv);
	if(r->cfg.app_rdv_capability_publish)r->cfg.app_rdv_capability_publish(r->cfg.app_rdv_service_opaque,EAGAIN);
	cbind_session_down(r,0);
	ctrl_app_rdv_down(r,0);
	if (r->pv.qp && !ctrans_epoch_jobs_busy(&r->pv) && ctrans_qp_err(&r->pv)) {
		crt_log("QP→ERR failed — no DMA termination evidence");
		ctrl_mark_qp_broken(r);
		/* Keep the owner alive to retry an actual native stop. */
	}

	if (r->cfg.rdv_kind != CRDV_FILE)
		crdv_tcp_conn_close(&r->rdv);
}

static int csess_teardown_finalize(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	int bad = 0;

 if(ctrl_is_fatal(r)){int rc=rdv_bridge_executor_stopped(&r->exec);if(rc)return rc;}
 int stop_rc=ctrans_provider_force_stop(&r->pv);if(stop_rc)return stop_rc;
 stop_rc=ctrl_reverse_stopped(r);if(stop_rc)return stop_rc;
 ctrl_app_rdv_down(r,1);
 if(ctrl_is_fatal(r)){stop_rc=cown_stopped_reap(r);if(stop_rc)return stop_rc;}
 else {stop_rc=cown_session_abort(r);if(stop_rc)return stop_rc;if(cown_busy(r))return -EBUSY;}
 int release_rc=ctrans_provider_destroy(&r->pv);
	if(release_rc) {
		/* A failed provider release retains its exact handles and epoch.
		 * Return to the reactor; jobs/callbacks must never be waited here. */
		return release_rc;
	}
	cbind_session_down(r,1);

	ctrans_tx_reset(&r->tx);
	ctrans_rx_reset(&r->rx);
	if(ctrans_rev_reset(&r->rev))return -EBUSY;

	if (cown_session_abort(r)) {
		crt_log("old-session owner recycle violation — terminal");
		bad = 1;
	}

	s->snap.active = 0;
	s->session_id = 0;
	s->rts_done = 0;
	s->hs_sent = 0;
	s->hs_peer = 0;
	s->snap_sent = 0;
	s->snap_dirty = 0;
	s->hs_deadline_us = 0;
	s->teardown_deadline_us = 0;
	s->teardown_retry_us=0;
	s->gen_local = 0;
	s->snap_pub_pending = 0;
	s->window = 0;
	s->window_in = CONTROL_WINDOW_MAX;
	s->rev_window = 0;
	r->rdv.own_up = 0;
	r->rdv.peer_qp = 0;
	r->rdv.peer_up = 0;
	r->rdv.peer_got = 0;
	r->rdv.peer_gid_valid = 0;
	r->rdv.greet_ok = 0;
	r->rdv.tcp_st = CRDV_TCP_IDLE;
	if (r->cfg.rdv_kind != CRDV_FILE) {
		crdv_tcp_conn_close(&r->rdv);
		if (r->cfg.rdv_kind == CRDV_TCP_CONNECT)
			r->rdv.next_retry_ms = crt_now_ms() +
					       r->rdv.backoff_ms;
	}
	cpeer_reset(r->peer);
	ctrl_fail_pending_submits(r);
	ctrl_fail_requests(r);

	s->state = CSESS_DOWN;
	if (bad)
		ctrl_mark_fatal(r);
	ctrl_signal_session(r);
	return bad ? -EPROTO : 0;
}

CRT_INTERNAL int csess_teardown_step(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	struct ibv_wc wc[CTRL_CQ_BATCH];
	long drained = 0;
	int rc;

	if (!s)
		return -1;
	if (s->state != CSESS_TEARDOWN)
		return 0;
	if (s->teardown_retry_us && crt_now_us() < s->teardown_retry_us)
		return 0;
	if(ctrl_is_fatal(r)&&!r->exec.nthreads&&!__atomic_load_n(&r->exec.run,__ATOMIC_ACQUIRE)){
  rc=rdv_bridge_executor_stopped(&r->exec);if(rc)return rc;
 }
	if (ctrans_epoch_jobs_busy(&r->pv)) {
		s->teardown_deadline_us = crt_now_us() + 1000 * 1000;
		s->teardown_retry_us = crt_now_us() + 5000;
		return 0;
	}
	if (r->pv.qp && !r->pv.err_done && ctrans_qp_err(&r->pv)) {
		if (ctrans_provider_force_stop(&r->pv)) {
			s->teardown_retry_us = crt_now_us() + 5000;
			return 0;
		}
	}
	if (r->pv.qp) {
		rc = ctrans_drain(&r->pv, wc, CTRL_CQ_BATCH, 0, &drained);
		if (rc) {
			if (rc == -ETIMEDOUT &&
			    crt_now_us() < s->teardown_deadline_us) {
				s->teardown_retry_us = crt_now_us() + 5000;
				return 0;
			}
			/* A broken CQ cannot deliver all flush WCs. Native QP
			 * destroy is alternative evidence; never erase counters
			 * to fake a drain. */
			if (ctrans_provider_force_stop(&r->pv)) {
				s->teardown_retry_us =
				    crt_now_us() + 5 * 1000;
				return 0;
			}
		}
		crt_log("teardown stop: drained=%ld rq=%u sq=%u rc=0", drained,
			r->pv.rq_outstanding, r->pv.sq_outstanding);
	}
	int release_rc = csess_teardown_finalize(r);
	if (release_rc) {
		/* Retained cleanup is retried by the owner on a bounded timer;
		 * a nonzero step result would terminate that owner loop. */
		s->teardown_retry_us = crt_now_us() + 5 * 1000;
		return 0;
	}
	return 0;
}

CRT_INTERNAL int csess_release(struct ctrl_reactor *r)
{
	if (!r)
		return 0;
	if(r->cfg.app_rdv_capability_publish)r->cfg.app_rdv_capability_publish(r->cfg.app_rdv_service_opaque,EAGAIN);
	ctrl_app_rdv_down(r,0);
	ctrans_epoch_close(&r->pv);
 int rdv_rc=rdv_bridge_executor_stopped(&r->exec);if(rdv_rc)return rdv_rc;
	if (ctrans_epoch_jobs_busy(&r->pv))
		return -EBUSY;
	if (r->pv.qp && (r->pv.rq_outstanding || r->pv.sq_outstanding)) {
		struct ibv_wc wc[CTRL_CQ_BATCH];
		long drained = 0;
		int rc = ctrans_qp_err(&r->pv);
		if (rc) {
			rc = ctrans_provider_force_stop(&r->pv);
			if (rc)
				return rc;
		}
		rc = r->pv.qp
			 ? ctrans_drain(&r->pv, wc, CTRL_CQ_BATCH, 0, &drained)
			 : 0;
		if (rc) {
			rc = ctrans_provider_force_stop(&r->pv);
			if (rc)
				return rc;
		}
	}
	/* Keep the epoch registered until old owner resources really reconcile.
	 */
	int rc = rdv_bridge_executor_stopped(&r->exec);
	if (rc) return rc;
	rc = ctrans_provider_force_stop(&r->pv);
	if (rc)
		return rc;
	rc = ctrl_reverse_stopped(r);
	if(rc)return rc;
	ctrl_app_rdv_down(r,1);
	rc = cown_stopped_reap(r);
	if (rc)
		return rc;
	rc = ctrans_provider_destroy(&r->pv);
	if (rc)
		return rc;
	return 0;
}
CRT_INTERNAL void csess_shutdown(struct ctrl_reactor *r)
{
	struct csess *s = r->sess;
	struct ibv_wc wc[CTRL_CQ_BATCH];
	long drained = 0;

	csess_fail(r, CSESS_FAIL_SHUTDOWN);
	ctrans_epoch_close(&r->pv);
	if (ctrans_epoch_jobs_busy(&r->pv))
		return;
	if ((s->state == CSESS_TEARDOWN || ctrl_is_fatal(r)) && r->pv.qp) {
		int rc =
		    ctrans_drain(&r->pv, wc, CTRL_CQ_BATCH, 1000, &drained);

		if (rc) {
			crt_log(
			    "shutdown drain not drained rq=%u sq=%u rc=%d — "
			    "terminal fatal",
			    r->pv.rq_outstanding, r->pv.sq_outstanding, rc);
			if (ctrans_provider_force_stop(&r->pv))
				return;
		}
	}
	if (s->state == CSESS_TEARDOWN || ctrl_is_fatal(r))
		(void)csess_teardown_finalize(r);
}
