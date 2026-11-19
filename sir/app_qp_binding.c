/* SPDX-License-Identifier: GPL-2.0 */
#include "control_app_qp.h"
#include "control_efd.h"
#include "control_reactor.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define CBIND_PENDING 256u
#define CBIND_RETRY_US 10000ll
#define CBIND_UNMATCHED_TTL_US 3500000ll
struct sir_app_qp_mailbox {
	struct sir_app_qp_mailbox *next;
	unsigned refs;
	uint64_t id;
	struct sir_app_qp_key key;
	uint8_t policy, closed, published;
	uint32_t reason;
	uint64_t revision;
	struct sir_app_qp_route desired;
	struct sir_app_qp_snapshot snapshot;
	/* The reactor alone changes these fields. */
	uint64_t applied_revision, applied_generation;
	uint8_t applied_closed, peer_seen, peer_acked, retiring;
	uint32_t retire_reason;
	uint8_t refresh;
	struct sir_app_qp_endpoint retired_local, retired_peer;
	struct sir_app_qp_endpoint local, seen, ack;
	/* Same-session peer high-water survives local RESET/challenge refresh. */
	struct sir_app_qp_endpoint peer_floor;
	uint8_t have_peer_floor;
	int64_t next_tx;
};
struct cbind_pending {
	int used;
	int64_t expires;
	struct sir_app_qp_endpoint peer;
};
struct cbind_tx {
	uint32_t op, status;
	struct sir_app_qp_endpoint a, b;
};
struct cbind_actor {
	struct ctrl_reactor *r;
	int ready, waiting_control;
	uint64_t session, generation, cursor, retire_cursor;
	unsigned tx_turn;
	uint32_t caps, down_flags;
	struct cbind_pending pending[CBIND_PENDING];
	struct cbind_tx tx[CBIND_PENDING];
	unsigned head, n;
	int64_t retry_at;
};
static pthread_mutex_t bind_mu = PTHREAD_MUTEX_INITIALIZER;
static struct sir_app_qp_mailbox *boxes;
static struct cbind_actor *actor;
static uint64_t next_id = 1, next_nonce = 1, notification_serial;
extern void npr_progress_wake(void) __attribute__((weak));
static void app_wake(void)
{
	void (*wake)(void) = npr_progress_wake;
	if (wake)
		wake();
}
/* Bounded nonblocking eventfd write while lifetime/removal is excluded. This
 * never invokes a callback, waits for the actor, or takes the application gate.
 */
static void actor_wake_locked(void)
{
	if (actor && actor->r->sub_efd >= 0)
		crt_efd_write(actor->r->sub_efd, 1);
}
static int key_eq(const struct sir_app_qp_key *a,
		  const struct sir_app_qp_key *b)
{
	return a->cookie == b->cookie && a->generation == b->generation;
}
static int endpoint_eq(const struct sir_app_qp_endpoint *a,
		       const struct sir_app_qp_endpoint *b)
{
	return key_eq(&a->key, &b->key) && a->bind_nonce == b->bind_nonce &&
	       a->policy == b->policy &&
	       a->route.connection_epoch == b->route.connection_epoch &&
	       a->route.local_qpn == b->route.local_qpn &&
	       a->route.peer_qpn == b->route.peer_qpn &&
	       a->route.kind == b->route.kind &&
	       a->route.port_num == b->route.port_num &&
	       a->route.local_lid == b->route.local_lid &&
	       a->route.peer_lid == b->route.peer_lid &&
	       !memcmp(a->route.local_gid, b->route.local_gid, 16) &&
	       !memcmp(a->route.peer_gid, b->route.peer_gid, 16);
}
/* Peer challenge nonces correlate its handshake attempts; cookie/generation,
 * connection epoch and route identify the QP candidate. Our own echoed nonce
 * is always compared exactly. */
static int peer_identity_eq(const struct sir_app_qp_endpoint *a,
			    const struct sir_app_qp_endpoint *b)
{
	struct sir_app_qp_endpoint x = *a, y = *b;
	x.bind_nonce = y.bind_nonce = 0;
	return endpoint_eq(&x, &y);
}
/* These counters belong to ONE remote process in this control session:
 * object generation is monotonic; within one object its connection epoch is
 * monotonic. Never compare our epoch with the remote epoch. Nonce is only a
 * challenge within an otherwise identical peer identity. 2 means unordered. */
static int peer_version(const struct sir_app_qp_endpoint *a,
                        const struct sir_app_qp_endpoint *b)
{
 if(key_eq(&a->key,&b->key)) {
  if(a->route.connection_epoch!=b->route.connection_epoch)
   return a->route.connection_epoch>b->route.connection_epoch?1:-1;
  return peer_identity_eq(a,b)?0:2;
 }
 if(a->key.generation!=b->key.generation)
  return a->key.generation>b->key.generation?1:-1;
 return 2;
}
static int peer_is_old(const struct sir_app_qp_mailbox *b,
                       const struct sir_app_qp_endpoint *peer)
{
 if(!b->have_peer_floor)return 0;
 int v=peer_version(peer,&b->peer_floor);
 return v<0||(v==0&&peer->bind_nonce<b->peer_floor.bind_nonce);
}
static void peer_observe(struct sir_app_qp_mailbox *b,
                         const struct sir_app_qp_endpoint *peer)
{
 b->peer_floor=*peer;b->have_peer_floor=1;
}
static int reciprocal(const struct sir_app_qp_endpoint *a,
		      const struct sir_app_qp_endpoint *b)
{
	if (a->policy != SIR_APP_QP_RENDEZVOUS_REQUIRED ||
	    b->policy != a->policy || a->route.kind != b->route.kind ||
	    a->route.local_qpn != b->route.peer_qpn ||
	    a->route.peer_qpn != b->route.local_qpn)
		return 0;
	if (a->route.kind == SIR_APP_QP_ROUTE_GID)
		return !memcmp(a->route.local_gid, b->route.peer_gid, 16) &&
		       !memcmp(a->route.peer_gid, b->route.local_gid, 16);
	return a->route.local_lid == b->route.peer_lid &&
	       a->route.peer_lid == b->route.local_lid;
}
static void snapshot_set(struct sir_app_qp_mailbox *b, uint32_t state,
			 uint32_t status, uint32_t flags)
{
	struct sir_app_qp_snapshot *s = &b->snapshot;
	uint64_t sid = actor ? actor->session : 0,
		 gen = actor ? actor->generation : 0;
	if (s->command_revision == b->revision && s->state == state &&
	    s->status == status && s->flags == flags && s->session_id == sid &&
	    s->transport_generation == gen &&
	    endpoint_eq(&s->local, &b->local) && endpoint_eq(&s->peer, &b->ack))
		return;
	s->serial++;
	notification_serial++;
	s->command_revision = b->revision;
	s->state = state;
	s->status = status;
	s->flags = flags;
	s->local = b->local;
	s->peer = b->ack;
	s->session_id = actor ? actor->session : 0;
	s->transport_generation = actor ? actor->generation : 0;
}
static void unlink_box(struct sir_app_qp_mailbox *b)
{
	struct sir_app_qp_mailbox **p = &boxes;
	while (*p && *p != b)
		p = &(*p)->next;
	if (*p) {
		*p = b->next;
		if (!--b->refs)
			free(b);
	}
}
CRT_INTERNAL struct sir_app_qp_mailbox *
sir_app_qp_mailbox_new(const struct sir_app_qp_key *key,
		       enum sir_app_qp_policy policy)
{
	if (!key || !key->cookie || !key->generation ||
	    (policy != SIR_APP_QP_NATIVE_ONLY &&
	     policy != SIR_APP_QP_RENDEZVOUS_REQUIRED)) {
		errno = EINVAL;
		return NULL;
	}
	struct sir_app_qp_mailbox *b = calloc(1, sizeof(*b));
	if (!b)
		return NULL;
	pthread_mutex_lock(&bind_mu);
	if (!next_id) {
		pthread_mutex_unlock(&bind_mu);
		free(b);
		errno = EOVERFLOW;
		return NULL;
	}
	for (struct sir_app_qp_mailbox *p = boxes; p; p = p->next)
		if (key_eq(&p->key, key)) {
			pthread_mutex_unlock(&bind_mu);
			free(b);
			errno = EEXIST;
			return NULL;
		}
	b->id = next_id++;
	b->refs = 2;
	b->key = *key;
	b->policy = policy;
	b->snapshot.state = policy == SIR_APP_QP_NATIVE_ONLY
				? SIR_APP_QP_NATIVE
				: SIR_APP_QP_UNPUBLISHED;
	b->local.key = *key;
	b->local.policy = policy;
	b->snapshot.local = b->local;
	b->next = boxes;
	boxes = b;
	pthread_mutex_unlock(&bind_mu);
	return b;
}
CRT_INTERNAL int sir_app_qp_publish(struct sir_app_qp_mailbox *b, uint64_t rev,
				    const struct sir_app_qp_route *route)
{
	if (!b || !route || !rev)
		return EINVAL;
	struct sir_app_qp_endpoint e = {.key = b->key,
					.route = *route,
					.bind_nonce = 1,
					.policy =
					    SIR_APP_QP_RENDEZVOUS_REQUIRED};
	if (!cproto_qp_endpoint_valid(&e))
		return EINVAL;
	pthread_mutex_lock(&bind_mu);
	int rc = 0;
	if (b->closed)
		rc = ESHUTDOWN;
	else if (rev <= b->revision)
		rc = ESTALE;
	else {
		b->revision = rev;
		b->desired = *route;
		b->published = 1;
		actor_wake_locked();
	}
	pthread_mutex_unlock(&bind_mu);
	return rc;
}
CRT_INTERNAL int sir_app_qp_withdraw(struct sir_app_qp_mailbox *b, uint64_t rev,
				     enum sir_app_qp_withdraw_reason reason)
{
	if (!b || !rev || reason < SIR_APP_QP_LOCAL_RESET ||
	    reason > SIR_APP_QP_DESTROY_PREPARE)
		return EINVAL;
	pthread_mutex_lock(&bind_mu);
	int rc = 0;
	if (b->closed)
		rc = ESHUTDOWN;
	else if (rev <= b->revision)
		rc = ESTALE;
	else {
		b->revision = rev;
		b->published = 0;
		b->reason = reason;
		actor_wake_locked();
	}
	pthread_mutex_unlock(&bind_mu);
	return rc;
}
CRT_INTERNAL void sir_app_qp_mailbox_close(struct sir_app_qp_mailbox *b)
{
	if (!b)
		return;
	pthread_mutex_lock(&bind_mu);
	b->closed = 1;
	actor_wake_locked();
	pthread_mutex_unlock(&bind_mu);
}
CRT_INTERNAL void sir_app_qp_mailbox_put(struct sir_app_qp_mailbox *b)
{
	if (!b)
		return;
	pthread_mutex_lock(&bind_mu);
	if (!b->closed)
		b->closed = 1;
	actor_wake_locked();
	if (!actor || (!b->retiring && !b->peer_seen && !b->peer_acked))
		unlink_box(b);
	if (!--b->refs)
		free(b);
	pthread_mutex_unlock(&bind_mu);
}
CRT_INTERNAL int sir_app_qp_snapshot(struct sir_app_qp_mailbox *b,
				     struct sir_app_qp_snapshot *out)
{
	if (!b || !out)
		return EINVAL;
	pthread_mutex_lock(&bind_mu);
	*out = b->snapshot;
	if (b->closed) {
		out->state = SIR_APP_QP_CLOSED;
		out->status = ESHUTDOWN;
	} else if (b->revision != out->command_revision) {
		out->command_revision = b->revision;
		out->local.key = b->key;
		out->local.route = b->desired;
		out->local.bind_nonce = 0;
		out->local.policy = b->policy;
		out->state = b->policy == SIR_APP_QP_NATIVE_ONLY
				 ? SIR_APP_QP_NATIVE
				 : (!b->published ? SIR_APP_QP_WITHDRAWN
						  : SIR_APP_QP_WAIT_SESSION);
		out->status = 0;
		memset(&out->peer, 0, sizeof(out->peer));
	}
	pthread_mutex_unlock(&bind_mu);
	return 0;
}
CRT_INTERNAL int cbind_current(struct ctrl_reactor *r,
 const struct sir_app_qp_key *key,struct sir_app_qp_snapshot *out)
{
 if(!r||!key||!out)return -EINVAL;
 memset(out,0,sizeof(*out));
 pthread_mutex_lock(&bind_mu);int rc=-ENOENT;
 if(!actor||actor->r!=r||!actor->ready)rc=-ENOTCONN;
 else for(struct sir_app_qp_mailbox *b=boxes;b;b=b->next)if(key_eq(key,&b->key)) {
  rc=-ESTALE;
  if(!b->closed&&b->published&&!b->retiring&&b->policy==SIR_APP_QP_RENDEZVOUS_REQUIRED&&
   b->applied_revision==b->revision&&b->applied_generation==actor->generation&&
   b->snapshot.state==SIR_APP_QP_BOUND&&!b->snapshot.status&&!b->snapshot.flags&&
   b->snapshot.command_revision==b->revision&&b->snapshot.session_id==actor->session&&
   b->snapshot.transport_generation==actor->generation&&b->peer_seen&&b->peer_acked&&
   endpoint_eq(&b->seen,&b->ack)&&endpoint_eq(&b->snapshot.local,&b->local)&&
   endpoint_eq(&b->snapshot.peer,&b->ack)&&reciprocal(&b->local,&b->ack)) {
   *out=b->snapshot;rc=0;
  }
  break;
 }
 pthread_mutex_unlock(&bind_mu);return rc;
}
static int queue_tx(uint32_t op, uint32_t status,
		    const struct sir_app_qp_endpoint *a,
		    const struct sir_app_qp_endpoint *b)
{
	for (unsigned i = 0; i < actor->n; i++) {
		struct cbind_tx *t =
		    &actor->tx[(actor->head + i) % CBIND_PENDING];
		if (t->op == op && t->status == status &&
		    endpoint_eq(&t->a, a) && endpoint_eq(&t->b, b))
			return 0;
	}
	if (actor->n == CBIND_PENDING)
		return -EAGAIN;
	struct cbind_tx *t =
	    &actor->tx[(actor->head + actor->n++) % CBIND_PENDING];
	t->op = op;
	t->status = status;
	t->a = *a;
	t->b = *b;
	return 0;
}
/* Retire one local nonce before coalesced desired metadata can replace it.
 * Queued ACKs are retractable; a confirmation that may already be on the wire
 * needs an ordered UNBIND. One nonce confirms at most one peer candidate. */
static void purge_local_tx(const struct sir_app_qp_endpoint *local)
{
	unsigned kept = 0;
	for (unsigned i = 0; i < actor->n; i++) {
		struct cbind_tx t =
		    actor->tx[(actor->head + i) % CBIND_PENDING];
		if ((t.op == CPROTO_OP_QP_BIND_ACK &&
		     endpoint_eq(&t.b, local)) ||
		    (t.op == CPROTO_OP_QP_BIND_INIT &&
		     endpoint_eq(&t.a, local)))
			continue;
		actor->tx[(actor->head + kept++) % CBIND_PENDING] = t;
	}
	actor->n = kept;
}
static void retire_nonce(struct sir_app_qp_mailbox *b, uint32_t reason)
{
	if (b->retiring)
		return;
	purge_local_tx(&b->local);
	if (b->local.bind_nonce && (b->peer_seen || b->peer_acked)) {
		b->retiring = 1;
		b->retired_local = b->local;
		/* The latest ACK target is sufficient: same-control-QP INITs
		 * are ordered, and a newer peer challenge already invalidates
		 * the older one. All queued ACKs for this local nonce are
		 * purged, not just the latest. */
		b->retired_peer = b->peer_seen ? b->seen : b->ack;
		b->retire_reason = reason ? reason : SIR_APP_QP_LOCAL_ERROR;
		for (unsigned i = 0; i < CBIND_PENDING; i++)
			if (actor->pending[i].used &&
			    endpoint_eq(&actor->pending[i].peer,
					&b->retired_peer))
				actor->pending[i].used = 0;
	}
	b->next_tx = 0;
	b->peer_seen = b->peer_acked = 0;
	memset(&b->seen, 0, sizeof(b->seen));
	memset(&b->ack, 0, sizeof(b->ack));
	b->local.bind_nonce = 0;
}
static void retire_clear(struct sir_app_qp_mailbox *b)
{
	b->retiring = 0;
	memset(&b->retired_local, 0, sizeof(b->retired_local));
	memset(&b->retired_peer, 0, sizeof(b->retired_peer));
}

CRT_INTERNAL int cbind_actor_attach(struct ctrl_reactor *r)
{
	struct cbind_actor *a = calloc(1, sizeof(*a));
	if (!a)
		return -ENOMEM;
	a->r = r;
	pthread_mutex_lock(&bind_mu);
	if (actor) {
		pthread_mutex_unlock(&bind_mu);
		free(a);
		return -EBUSY;
	}
	actor = a;
	pthread_mutex_unlock(&bind_mu);
	return 0;
}
CRT_INTERNAL void cbind_session_down(struct ctrl_reactor *r, int stopped)
{
	pthread_mutex_lock(&bind_mu);
	if (actor && actor->r == r) {
		actor->ready = 0;
		actor->down_flags = SIR_APP_QP_SESSION_CLOSING |
				    (stopped ? SIR_APP_QP_DMA_STOPPED : 0);
		actor->n = actor->head = 0;
		actor->retry_at = 0;
		memset(actor->pending, 0, sizeof(actor->pending));
		for (struct sir_app_qp_mailbox *b = boxes; b; b = b->next) {
			if (stopped)
				retire_clear(b);
			else
				retire_nonce(b, SIR_APP_QP_LOCAL_ERROR);
			b->refresh = 0;
			b->applied_generation = actor->generation;
			b->peer_seen = b->peer_acked = 0;
			b->next_tx = 0;
			memset(&b->ack, 0, sizeof(b->ack));
			if (b->policy == SIR_APP_QP_NATIVE_ONLY) {
				snapshot_set(b,
					     b->closed ? SIR_APP_QP_CLOSED
						       : SIR_APP_QP_NATIVE,
					     0, 0);
				continue;
			}
			snapshot_set(
			    b,
			    b->closed
				? SIR_APP_QP_CLOSED
				: (!b->published ? SIR_APP_QP_WITHDRAWN
						 : SIR_APP_QP_WAIT_SESSION),
			    ENOTCONN,
			    SIR_APP_QP_SESSION_CLOSING |
				(stopped ? SIR_APP_QP_DMA_STOPPED : 0));
		}
		if (stopped)
			for (struct sir_app_qp_mailbox *q = boxes, *next; q;
			     q = next) {
				next = q->next;
				if (q->closed)
					unlink_box(q);
			}
	}
	pthread_mutex_unlock(&bind_mu);
	app_wake();
}
CRT_INTERNAL void cbind_actor_detach(struct ctrl_reactor *r)
{
	cbind_session_down(r, 1);
	pthread_mutex_lock(&bind_mu);
	if (actor && actor->r == r) {
		free(actor);
		actor = NULL;
		for (struct sir_app_qp_mailbox *b = boxes, *next; b; b = next) {
			next = b->next;
			if (b->closed)
				unlink_box(b);
		}
	}
	pthread_mutex_unlock(&bind_mu);
}
CRT_INTERNAL void cbind_session_ready(struct ctrl_reactor *r, uint64_t sid,
				      uint64_t gen, uint32_t caps)
{
	pthread_mutex_lock(&bind_mu);
	if (actor && actor->r == r) {
		if(actor->session!=sid||actor->generation!=gen)
   for(struct sir_app_qp_mailbox *b=boxes;b;b=b->next)b->have_peer_floor=0;
		actor->ready = 1;
		actor->down_flags = 0;
		actor->session = sid;
		actor->generation = gen;
		actor->caps = caps;
		actor->retry_at = 0;
		actor_wake_locked();
	}
	pthread_mutex_unlock(&bind_mu);
}
static void try_bound(struct sir_app_qp_mailbox *b)
{
	if (b->peer_seen && b->peer_acked && endpoint_eq(&b->seen, &b->ack)) {
		b->next_tx = 0;
		if (b->snapshot.state != SIR_APP_QP_BOUND)
			snapshot_set(b, SIR_APP_QP_BOUND, 0, 0);
	} else if (b->peer_seen && b->peer_acked &&
		   peer_identity_eq(&b->seen, &b->ack)) {
		/* A peer challenge is not its QP identity. Fetch a matching
		 * current ACK without rotating our own challenge and chasing
		 * the peer's nonce. */
		if (!b->next_tx)
			b->next_tx = crt_now_us();
		if (b->snapshot.state == SIR_APP_QP_BOUND)
			snapshot_set(b, SIR_APP_QP_WAIT_PEER, 0, 0);
	}
}
static int match_init(const struct sir_app_qp_endpoint *peer)
{
	struct sir_app_qp_mailbox *match = NULL;
	for (struct sir_app_qp_mailbox *b = boxes; b; b = b->next)
		if (!b->closed && b->published &&
		    b->policy == SIR_APP_QP_RENDEZVOUS_REQUIRED &&
		    b->applied_revision == b->revision &&
		    b->applied_generation == actor->generation &&
		    b->local.bind_nonce && !b->retiring &&
		    (b->snapshot.state == SIR_APP_QP_WAIT_PEER ||
		     b->snapshot.state == SIR_APP_QP_BOUND) &&
		    reciprocal(&b->local, peer)) {
			if (match)
				return 0;
			match = b;
		}
	if (!match)
		return 0;
 if(peer_is_old(match,peer))return 1;
 if(match->have_peer_floor&&peer_version(peer,&match->peer_floor)==1&&
    ((match->peer_seen&&!peer_identity_eq(&match->seen,peer))||
     (match->peer_acked&&!peer_identity_eq(&match->ack,peer)))) {
  /* Two freshly reset endpoints may both first observe delayed old INITs.
   * Silently swallowing each other's newer INIT would make both wait forever
   * for ACKs that neither side can emit. Retain the original revoke obligation,
   * then refresh; the peer floor also rejects stale pending cache entries. */
  static unsigned logs;
  if(logs++<128)crt_log("bind newer peer local=%llu peer=%llu gen=%llu epoch=%llu nonce=%llu",
   (unsigned long long)match->key.cookie,(unsigned long long)peer->key.cookie,
   (unsigned long long)peer->key.generation,(unsigned long long)peer->route.connection_epoch,
   (unsigned long long)peer->bind_nonce);
  peer_observe(match,peer);
  retire_nonce(match,SIR_APP_QP_LOCAL_ERROR);match->refresh=1;
  if(!match->retiring)match->applied_revision=0;
  snapshot_set(match,SIR_APP_QP_WAIT_PEER,EINPROGRESS,0);
  return 0; /* bounded pending cache keeps the new candidate, never the old */
 }
	if ((match->peer_seen && !peer_identity_eq(&match->seen, peer)) ||
	    (match->peer_acked && !peer_identity_eq(&match->ack, peer)))
		return 1;
	/* Within one session/candidate identity a challenge only advances. A
	 * cached/delayed older INIT cannot lower seen or revive an old ACK. */
	if ((match->peer_seen && peer->bind_nonce < match->seen.bind_nonce) ||
	    (match->peer_acked && peer->bind_nonce < match->ack.bind_nonce))
		return 1;
	if (queue_tx(CPROTO_OP_QP_BIND_ACK, 0, peer, &match->local))
		return 0;
	peer_observe(match,peer);
	match->seen = *peer;
	match->peer_seen = 1;
	try_bound(match);
	return 1;
}
CRT_INTERNAL int cbind_rx(struct ctrl_reactor *r, const struct cproto_header *h,
			  const uint8_t *p, uint32_t n)
{
	uint32_t op, status;
	struct sir_app_qp_endpoint a, b;
	if (cproto_qp_bind_decode(p, n, &op, &status, &a, &b))
		return -EPROTO;
	pthread_mutex_lock(&bind_mu);
	uint64_t notify_before = notification_serial;
	if (!actor || actor->r != r || !actor->ready ||
	    h->session_id != actor->session) {
		pthread_mutex_unlock(&bind_mu);
		return 0;
	}
	if (op == CPROTO_OP_QP_BIND_INIT) {
		if (!match_init(&a)) {
			unsigned slot = CBIND_PENDING;
			int64_t now = crt_now_us();
			for (unsigned i = 0; i < CBIND_PENDING; i++) {
				if (actor->pending[i].used &&
				    endpoint_eq(&actor->pending[i].peer, &a)) {
					slot = i;
					break;
				}
				if (!actor->pending[i].used ||
				    actor->pending[i].expires <= now)
					slot = i;
			}
			if (slot < CBIND_PENDING)
				actor->pending[slot] = (struct cbind_pending){
				    1, now + CBIND_UNMATCHED_TTL_US, a};
		}
	} else
		for (struct sir_app_qp_mailbox *box = boxes; box;
		     box = box->next) {
			if (box->closed || box->retiring || !box->published ||
			    box->applied_revision != box->revision ||
			    box->applied_generation != actor->generation ||
			    (box->snapshot.state != SIR_APP_QP_WAIT_PEER &&
			     box->snapshot.state != SIR_APP_QP_BOUND))
				continue;
			if (op == CPROTO_OP_QP_BIND_ACK &&
			    endpoint_eq(&box->local, &a)) {
				if (status) {
					retire_nonce(box,
						     SIR_APP_QP_LOCAL_ERROR);
					snapshot_set(box,
						     SIR_APP_QP_UNAVAILABLE,
						     status, 0);
				} else if (reciprocal(&box->local, &b)) {
     if(peer_is_old(box,&b))continue;
     peer_observe(box,&b);
					if ((box->peer_seen &&
					     !peer_identity_eq(&box->seen,
							       &b)) ||
					    (box->peer_acked &&
					     !peer_identity_eq(&box->ack,
							       &b))) {
						retire_nonce(
						    box,
						    SIR_APP_QP_LOCAL_ERROR);
						box->refresh = 1;
						if (!box->retiring)
							box->applied_revision =
							    0;
						snapshot_set(
						    box, SIR_APP_QP_WAIT_PEER,
						    EINPROGRESS, 0);
					} else if (!(box->peer_seen &&
						     b.bind_nonce <
							 box->seen
							     .bind_nonce) &&
						   !(box->peer_acked &&
						     b.bind_nonce <
							 box->ack.bind_nonce)) {
						box->ack = b;
						box->peer_acked = 1;
						try_bound(box);
					}
				}

			} else if (op == CPROTO_OP_QP_UNBIND &&
				   endpoint_eq(&box->local, &b) &&
     !peer_is_old(box,&a) &&
				   !(box->peer_seen &&
				     peer_identity_eq(&box->seen, &a) &&
				     a.bind_nonce < box->seen.bind_nonce) &&
				   !(box->peer_acked &&
				     peer_identity_eq(&box->ack, &a) &&
				     a.bind_nonce < box->ack.bind_nonce) &&
				   ((box->peer_acked &&
				     endpoint_eq(&box->ack, &a)) ||
				    (box->peer_seen &&
				     endpoint_eq(&box->seen, &a)))) {
				/* Peer withdrawal proves this pair is abandoned
				 * there. Refresh our challenge without a revoke
				 * ping-pong. */
				purge_local_tx(&box->local);
				box->next_tx = 0;
				box->peer_seen = box->peer_acked =
				    box->refresh = 0;
				memset(&box->ack, 0, sizeof(box->ack));
				box->local.bind_nonce = 0;
				box->applied_revision = 0;
				snapshot_set(box, SIR_APP_QP_WAIT_PEER,
					     ENOTCONN, 0);
			}
		}
	int notify = notification_serial != notify_before;
	pthread_mutex_unlock(&bind_mu);
	if (notify)
		app_wake();
	return 0;
}
CRT_INTERNAL int64_t cbind_next_deadline(struct ctrl_reactor *r)
{
	int64_t d = 0;
	pthread_mutex_lock(&bind_mu);
	if (actor && actor->r == r && actor->ready) {
		d = actor->n
			? (actor->retry_at ? actor->retry_at : crt_now_us() + 1)
			: 0;
		for (struct sir_app_qp_mailbox *b = boxes; b; b = b->next) {
			if (b->retiring || b->closed ||
			    b->applied_revision != b->revision ||
			    b->applied_generation != actor->generation) {
				int64_t due = actor->retry_at
						  ? actor->retry_at
						  : crt_now_us() + 1;
				if (!d || due < d)
					d = due;
			}
			if (b->next_tx) {
				int64_t due = b->next_tx;
				if (actor->retry_at > due)
					due = actor->retry_at;
				if (!d || due < d)
					d = due;
			}
		}
	}
	pthread_mutex_unlock(&bind_mu);
	return d;
}
CRT_INTERNAL int cbind_progress(struct ctrl_reactor *r)
{
	struct cbind_tx send = {0};
	int have = 0;
	uint8_t payload[CPROTO_QP_PAIR_SIZE];
	pthread_mutex_lock(&bind_mu);
	if (!actor || actor->r != r) {
		pthread_mutex_unlock(&bind_mu);
		return 0;
	}
	int64_t now = crt_now_us();
	uint64_t notify_before = notification_serial;
	for (struct sir_app_qp_mailbox *b = boxes, *next; b; b = next) {
		next = b->next;
		if (b->closed || b->applied_revision != b->revision ||
		    b->applied_generation != actor->generation) {
			retire_nonce(b, b->reason ? b->reason
						  : SIR_APP_QP_DESTROY_PREPARE);
			if (b->retiring) {
				snapshot_set(b,
					     b->closed
						 ? SIR_APP_QP_CLOSED
						 : (!b->published
							? SIR_APP_QP_WITHDRAWN
							: SIR_APP_QP_WAIT_PEER),
					     EINPROGRESS, 0);
				continue;
			}
			b->refresh = 0;
			b->peer_seen = b->peer_acked = 0;
			b->next_tx = 0;
			memset(&b->ack, 0, sizeof(b->ack));
			b->applied_revision = b->revision;
			b->applied_generation = actor->generation;
			b->local =
			    (struct sir_app_qp_endpoint){.key = b->key,
							 .route = b->desired,
							 .policy = b->policy};
			/* A different expected peer QPN/path is a different authority
			 * scope: its already-live object may have a lower generation. */
			if(b->have_peer_floor&&!reciprocal(&b->local,&b->peer_floor))
			 b->have_peer_floor=0;
			if (b->closed) {
				snapshot_set(b, SIR_APP_QP_CLOSED, ESHUTDOWN,
					     0);
				unlink_box(b);
				continue;
			}
			if (b->policy == SIR_APP_QP_NATIVE_ONLY) {
				snapshot_set(b, SIR_APP_QP_NATIVE, 0, 0);
				continue;
			}
			if (!b->published) {
				snapshot_set(b, SIR_APP_QP_WITHDRAWN, 0, 0);
				continue;
			}
			if (!actor->ready) {
				snapshot_set(b, SIR_APP_QP_WAIT_SESSION,
					     ENOTCONN, actor->down_flags);
				continue;
			}
			if (!(actor->caps & CPROTO_CAP_QP_BIND)) {
				snapshot_set(b, SIR_APP_QP_UNAVAILABLE,
					     EOPNOTSUPP, 0);
				continue;
			}
			if (!next_nonce) {
				snapshot_set(b, SIR_APP_QP_UNAVAILABLE,
					     EOVERFLOW, 0);
				continue;
			}
			b->local.bind_nonce = next_nonce++;
			b->next_tx = now;
			snapshot_set(b, SIR_APP_QP_WAIT_PEER, 0, 0);
		}
	}
	if (actor->ready) {
		for (unsigned i = 0; i < CBIND_PENDING; i++)
			if (actor->pending[i].used) {
				if (actor->pending[i].expires <= now ||
				    match_init(&actor->pending[i].peer))
					actor->pending[i].used = 0;
			}
		/* Leave three control slots for credit/handshake/snapshot
		 * traffic. */
		if (r->tx.in_flight[CTRANS_TX_CONTROL]) {
			actor->waiting_control = 1;
			if (now >= actor->retry_at)
				actor->retry_at = now + 5000;
		} else if (actor->waiting_control) {
			actor->waiting_control = 0;
			actor->retry_at = 0;
		}
		if (r->tx.in_flight[CTRANS_TX_CONTROL] == 0 &&
		    now >= actor->retry_at) {
			for (unsigned phase = 0; phase < 3 && !have; phase++) {
				unsigned cls = (actor->tx_turn + phase) % 3;
				if (cls == 0 && actor->n) {
					send = actor->tx[actor->head];
					actor->head =
					    (actor->head + 1) % CBIND_PENDING;
					actor->n--;
					have = 1;
				} else if (cls == 1) {
					struct sir_app_qp_mailbox *pick = NULL,
								  *wrap = NULL;
					for (struct sir_app_qp_mailbox *q =
						 boxes;
					     q; q = q->next)
						if (q->retiring) {
							if (!wrap ||
							    q->id < wrap->id)
								wrap = q;
							if (q->id >
								actor
								    ->retire_cursor &&
							    (!pick ||
							     q->id < pick->id))
								pick = q;
						}
					if (!pick)
						pick = wrap;
					if (pick) {
						send.op = CPROTO_OP_QP_UNBIND;
						send.status =
						    pick->retire_reason;
						send.a = pick->retired_local;
						send.b = pick->retired_peer;
						actor->retire_cursor = pick->id;
						have = 3;
					}
				} else if (cls == 2) {
					struct sir_app_qp_mailbox *pick = NULL,
								  *wrap = NULL;
					for (struct sir_app_qp_mailbox *q =
						 boxes;
					     q; q = q->next)
						if (!q->retiring &&
						    q->next_tx &&
						    q->next_tx <= now) {
							if (!wrap ||
							    q->id < wrap->id)
								wrap = q;
							if (q->id >
								actor->cursor &&
							    (!pick ||
							     q->id < pick->id))
								pick = q;
						}
					if (!pick)
						pick = wrap;
					if (pick) {
						send.op =
						    CPROTO_OP_QP_BIND_INIT;
						send.a = pick->local;
						pick->next_tx =
						    now + CBIND_RETRY_US;
						actor->cursor = pick->id;
						have = 2;
					}
				}
				if (have)
					actor->tx_turn = (cls + 1) % 3;
			}
		}
	}
	int notify = notification_serial != notify_before;
	pthread_mutex_unlock(&bind_mu);
	if (notify)
		app_wake();
	if (!have)
		return 0;
	int n = cproto_qp_bind_encode(
	    payload, sizeof(payload), send.op, send.status, &send.a,
	    send.op == CPROTO_OP_QP_BIND_INIT ? NULL : &send.b);
	if (n < 0)
		return n;
	int rc = ctrl_tx_control(r, CPROTO_CONTROL_EVENT, payload, n, 0, 0);
	pthread_mutex_lock(&bind_mu);
	if (actor && actor->r == r) {
		if (!rc && have == 3)
			for (struct sir_app_qp_mailbox *q = boxes; q;
			     q = q->next)
				if (q->retiring &&
				    endpoint_eq(&q->retired_local, &send.a) &&
				    endpoint_eq(&q->retired_peer, &send.b)) {
					retire_clear(q);
					if (q->refresh)
						q->applied_revision = 0;
					break;
				}
		actor->retry_at = rc ? crt_now_us() + 5000 : 0;
	}
	pthread_mutex_unlock(&bind_mu);
	return rc;
}
