/* SPDX-License-Identifier: GPL-2.0 */
#include "control_app_rdv.h"
#include "control_app_qp.h"
#include "rdv_protocol.h"
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define CRDV_ACTIVE_MAX 256u /* Actor credit, never preaccepted SQ storage. */
#define CRDV_RETRANSMIT_US 100000u
struct crdv_message;
struct crdv_drain_state {
 struct sir_rdv_drain_record request;
 uint64_t deadline,baseline,next_due;
 unsigned active,held,have_frontier,head_seen,head_done,remote_done;
 unsigned request_pending,ack_pending,end_pending,status;
};
struct crdv_registration {
  struct crdv_registration *next;
  struct crdv_registry *registry;
  struct crdv_registration_config config;
  unsigned closed, owners, actor_refs, finalized;
  unsigned rnr_attrs;
  struct crdv_stats stats, pending_stats;
  struct sir_app_qp_snapshot binding;
  uint32_t peer_sge_limit;
  unsigned caps_sent, peer_caps, caps_acked, caps_ack_pending,peer_flags;
  struct sir_rdv_value native_value;
  unsigned native_pending;
  uint64_t native_due;
  uint64_t caps_due, source_failed_sequence;
  struct crdv_drain_state drain[2];
};
struct crdv_registry {
  pthread_mutex_t mu;
  struct crdv_registry_config config;
  struct crdv_registration *registrations;
  struct crdv_actor *actor;
  size_t wake_refs;
};
struct crdv_stream {
  struct crdv_stream *next;
  struct crdv_registration *registration;
  struct sir_app_qp_endpoint sender, receiver;
  uint64_t base, next_sequence, failed_sequence;
};
struct crdv_message {
  struct crdv_message *next;
  struct crdv_registration *registration;
  struct crdv_stream *stream;
  struct sir_rdv_value value;
  struct rdvp_message wire;
  struct rdv_bridge_owner *resource;
  uint64_t slot, app_token, attempt, challenge, offer_request, next_due;
  unsigned role, hold, closed, offered, offer_complete, offer_fragment;
  struct crdv_offer_snapshot published_offer;
  unsigned offer_visible;
  unsigned pending_prepare, span_count, release_counted;
  uint64_t read_posted_seen, read_wc_seen;
  unsigned offer_pending, wait_pending, ack_pending, cancel_pending,
      retired_pending;
  unsigned matched, matchable, reply_pending, reply_result, stream_first, source_prepared, native_received;
  unsigned final_ack, terminal, released, release_committed, read_prepared,
      retired_seen;
  unsigned retries, read_error, read_finished_seen;
  unsigned wwi_ready, wwi_ready_pending, wwi_result, wwi_result_pending;
  enum rdvp_status wwi_result_status;
  enum rdvp_status final_status;
  unsigned ack_opcode;
  uint64_t acknowledged_length;
  uint32_t segment_count, fragments_received, fragment_count;
  uint64_t received_length;
  struct rdvp_segment *segments;
};
static void message_free(struct crdv_actor *, struct crdv_message *);
static void refresh_caps(struct crdv_actor *, struct crdv_registration *);
static void stats_progress(struct crdv_actor *, struct crdv_registration *);
static void registration_put(struct crdv_registration *);
static void drain_commands(struct crdv_actor *,struct crdv_registration *);
static void drain_registration_progress(struct crdv_actor *,struct crdv_registration *);
static int drain_receive(struct crdv_actor *,const struct cproto_header *,const uint8_t *,uint32_t);
static int drain_frame(struct crdv_actor *,struct crdv_frame *,uint8_t *);
static int drain_tx_result(struct crdv_actor *,struct crdv_registration *,unsigned,int);
static int publish_release(struct crdv_message *, unsigned);
struct crdv_actor {
  struct crdv_registry *registry;
  struct ctrl_reactor *reactor;
  struct crdv_resource_ops ops;
  void *resource_opaque;
  struct crdv_message *messages;
  struct crdv_stream *streams;
  uint64_t now, next_ticket, next_attempt, next_challenge, current_sid;
  unsigned active, down, dma_stopped, external_refs, retiring;
  struct crdv_frame inflight;
  struct crdv_message *tx_message;
  struct crdv_registration *tx_registration;
  unsigned unmatched_reply;
  uint64_t unmatched_sid;
  struct rdvp_message unmatched_wire;
  unsigned tx_op, tx_fragment;
};
static int key_equal(const struct sir_app_qp_key *a,
                     const struct sir_app_qp_key *b) {
  return a->cookie == b->cookie && a->generation == b->generation;
}
static int endpoint_equal(const struct sir_app_qp_endpoint *a,
                          const struct sir_app_qp_endpoint *b) {
  uint8_t x[80], y[80];
  cproto_qp_endpoint_put(x, a);
  cproto_qp_endpoint_put(y, b);
  return !memcmp(x, y, sizeof(x));
}
static int logical_equal(const struct sir_app_qp_endpoint *a,
                         const struct sir_app_qp_endpoint *b) {
  return key_equal(&a->key, &b->key) &&
         a->route.connection_epoch == b->route.connection_epoch;
}
static int message_equal(const struct rdvp_message *a,
                         const struct rdvp_message *b) {
  return endpoint_equal(&a->sender, &b->sender) &&
         endpoint_equal(&a->receiver, &b->receiver) &&
         a->message_id == b->message_id && a->sequence == b->sequence &&
         a->total_length == b->total_length && a->kind == b->kind &&
         a->flags == b->flags;
}
static int error_value(int rc) { return rc < 0 ? -rc : rc; }
static enum rdvp_status status_wire(unsigned e) {
  if (!e)
    return RDVP_OK;
  if (e == EREMOTEIO)
    return RDVP_REMOTE_ACCESS;
  if (e == EACCES)
    return RDVP_SINK_PROTECTION;
  if (e == EMSGSIZE)
    return RDVP_SINK_LENGTH;
  if (e == ECANCELED || e == ENODATA)
    return RDVP_CANCELLED_MATCHED;
  return RDVP_TRANSPORT_FAILURE;
}
static unsigned status_local(enum rdvp_status s) {
  switch (s) {
  case RDVP_REMOTE_ACCESS:
    return EREMOTEIO;
  case RDVP_OK:
    return 0;
  case RDVP_SINK_PROTECTION:
    return EACCES;
  case RDVP_SINK_LENGTH:
    return EMSGSIZE;
  case RDVP_CANCELLED_UNMATCHED:
  case RDVP_CANCELLED_MATCHED:
    return ECANCELED;
  default:
    return EIO;
  }
}
static struct rdvp_message value_wire(const struct sir_rdv_value *v,
                                      unsigned role) {
  return (struct rdvp_message){
      .sender = role == SIR_RDV_SOURCE ? v->id.local : v->id.peer,
      .receiver = role == SIR_RDV_SOURCE ? v->id.peer : v->id.local,
      .message_id = v->id.message_id,
      .sequence = v->id.rq_message_seq,
      .total_length = v->length,
      .kind = (uint8_t)v->kind,
      .flags = v->solicited ? RDVP_F_SOLICITED : 0};
}
static uint64_t serial_next(uint64_t *p) {
  if (!*p || *p == UINT64_MAX)
    return 0;
  return (*p)++;
}
static void publish_stats(struct crdv_registration *r,
                          const struct crdv_stats *s) {
  pthread_mutex_lock(&r->registry->mu);
  if (!r->finalized)
    r->stats = *s;
  pthread_mutex_unlock(&r->registry->mu);
}
void crdv_registry_wake(void *opaque) {
  struct crdv_registry *g = opaque;
  if (!g)
    return;
  pthread_mutex_lock(&g->mu);
  g->wake_refs++;
  void (*wake)(void *) = g->config.wake_actor;
  void *arg = g->config.wake_opaque;
  pthread_mutex_unlock(&g->mu);
  if (wake)
    wake(arg);
  pthread_mutex_lock(&g->mu);
  g->wake_refs--;
  pthread_mutex_unlock(&g->mu);
}
int crdv_registry_new(const struct crdv_registry_config *c,
                      struct crdv_registry **out) {
  if (!out)
    return EINVAL;
  *out = NULL;
  struct crdv_registry *g = calloc(1, sizeof(*g));
  if (!g)
    return ENOMEM;
  int rc = pthread_mutex_init(&g->mu, NULL);
  if (rc) {
    free(g);
    return rc;
  }
  if (c)
    g->config = *c;
  *out = g;
  return 0;
}
int crdv_registry_free(struct crdv_registry *g) {
  if (!g)
    return EINVAL;
  pthread_mutex_lock(&g->mu);
  int busy = g->actor || g->registrations || g->wake_refs;
  pthread_mutex_unlock(&g->mu);
  if (busy)
    return EBUSY;
  pthread_mutex_destroy(&g->mu);
  free(g);
  return 0;
}
int crdv_register(struct crdv_registry *g,
                  const struct crdv_registration_config *c,
                  struct crdv_registration **out) {
  if (!g || !c || !out || !c->mailbox || !c->key.cookie || !c->key.generation ||
      !c->connection_epoch || c->caps.rnr_retry > 7 ||
      c->caps.min_rnr_timer > 31)
    return EINVAL;
  *out = NULL;
  struct crdv_registration *r = calloc(1, sizeof(*r));
  if (!r)
    return ENOMEM;
  r->registry = g;
  r->config = *c;
  r->rnr_attrs =
      (unsigned)c->caps.rnr_retry | ((unsigned)c->caps.min_rnr_timer << 8);
  r->pending_stats.key = c->key;
  r->pending_stats.connection_epoch = c->connection_epoch;
  r->stats = r->pending_stats;
  pthread_mutex_lock(&g->mu);
  for (struct crdv_registration *p = g->registrations; p; p = p->next)
    if (!__atomic_load_n(&p->closed, __ATOMIC_ACQUIRE) &&
        key_equal(&p->config.key, &c->key) &&
        p->config.connection_epoch == c->connection_epoch) {
      pthread_mutex_unlock(&g->mu);
      free(r);
      return EEXIST;
    }
  int rc = sir_rdv_mailbox_get(c->mailbox);
  if (rc) {
    pthread_mutex_unlock(&g->mu);
    free(r);
    return rc;
  }
  r->next = g->registrations;
  g->registrations = r;
  pthread_mutex_unlock(&g->mu);
  *out = r;
  crdv_registry_wake(g);
  return 0;
}
int crdv_registration_update_attrs(struct crdv_registration *r, uint8_t retry,
                                   uint8_t timer) {
  if (!r || retry > 7 || timer > 31)
    return EINVAL;
  pthread_mutex_lock(&r->registry->mu);
  int rc = __atomic_load_n(&r->closed, __ATOMIC_ACQUIRE) ? ESHUTDOWN : 0;
  if (!rc)
    r->actor_refs++;
  if (!rc)
    __atomic_store_n(&r->rnr_attrs, (unsigned)retry | ((unsigned)timer << 8),
                     __ATOMIC_RELEASE);
  pthread_mutex_unlock(&r->registry->mu);
  if (!rc) {
    crdv_registry_wake(r->registry);
    registration_put(r);
  }
  return rc;
}
static struct crdv_registration *registration_first(struct crdv_registry *g) {
  pthread_mutex_lock(&g->mu);
  struct crdv_registration *r = g->registrations;
  if (r)
    r->actor_refs++;
  pthread_mutex_unlock(&g->mu);
  return r;
}
static struct crdv_registration *
registration_next(struct crdv_registration *r) {
  struct crdv_registry *g = r->registry;
  pthread_mutex_lock(&g->mu);
  struct crdv_registration *next = r->next;
  if (next)
    next->actor_refs++;
  r->actor_refs--;
  pthread_mutex_unlock(&g->mu);
  return next;
}
static void registration_put(struct crdv_registration *r) {
  if (!r)
    return;
  pthread_mutex_lock(&r->registry->mu);
  r->actor_refs--;
  pthread_mutex_unlock(&r->registry->mu);
}
int crdv_registration_close(struct crdv_registration *r) {
  if (!r)
    return EINVAL;
  pthread_mutex_lock(&r->registry->mu);
  __atomic_store_n(&r->closed, 1, __ATOMIC_RELEASE);
  r->native_pending=0;
  r->actor_refs++;
  pthread_mutex_unlock(&r->registry->mu);
  sir_rdv_mailbox_close(r->config.mailbox);
  crdv_registry_wake(r->registry);
  registration_put(r);
  return 0;
}
void crdv_registry_notify_apps(struct crdv_registry *g) {
  if (!g)
    return;
  for (struct crdv_registration *r = registration_first(g); r;
       r = registration_next(r))
    sir_rdv_mailbox_notify_app(r->config.mailbox);
}
void crdv_registry_close_producers(struct crdv_registry *g) {
  if (!g)
    return;
  for (struct crdv_registration *r = registration_first(g); r;
       r = registration_next(r))
    crdv_registration_close(r);
}
int crdv_registration_final_stats(struct crdv_registration *r,
                                  struct crdv_stats *out) {
  if (!r || !out)
    return EINVAL;
  pthread_mutex_lock(&r->registry->mu);
  struct sir_rdv_mailbox_counts c = {0};
  sir_rdv_mailbox_counts(r->config.mailbox, &c);
  int rc = !__atomic_load_n(&r->closed, __ATOMIC_ACQUIRE) || r->owners ||
                   r->actor_refs || c.reserved || c.control_pending
               ? EBUSY
               : 0;
  if (!rc) {
    r->finalized = 1;
    *out = r->stats;
  }
  pthread_mutex_unlock(&r->registry->mu);
  return rc;
}
int crdv_registration_free(struct crdv_registration *r) {
  if (!r)
    return EINVAL;
  struct crdv_registry *g = r->registry;
  pthread_mutex_lock(&g->mu);
  struct sir_rdv_mailbox_counts pending={0};sir_rdv_mailbox_counts(r->config.mailbox,&pending);
  if (!__atomic_load_n(&r->closed, __ATOMIC_ACQUIRE) || r->owners ||
      r->actor_refs || pending.control_pending) {
    pthread_mutex_unlock(&g->mu);
    return EBUSY;
  }
  struct crdv_registration **p = &g->registrations;
  while (*p && *p != r)
    p = &(*p)->next;
  if (!*p) {
    pthread_mutex_unlock(&g->mu);
    return ESTALE;
  }
  *p = r->next;
  pthread_mutex_unlock(&g->mu);
  sir_rdv_mailbox_put(r->config.mailbox);
  free(r);
  return 0;
}
int crdv_stats_snapshot(struct crdv_registration *r, struct crdv_stats *out) {
  if (!r || !out)
    return EINVAL;
  pthread_mutex_lock(&r->registry->mu);
  *out = r->stats;
  pthread_mutex_unlock(&r->registry->mu);
  return 0;
}
static struct crdv_message *find_slot(struct crdv_registration *r,
                                      uint64_t slot, uint64_t app) {
  struct crdv_actor *a = r->registry->actor;
  if (!a || a->retiring)
    return NULL;
  for (struct crdv_message *m = a->messages; m; m = m->next)
    if (m->registration == r && m->role == SIR_RDV_SINK && m->slot == slot &&
        m->app_token == app && m->offer_visible)
      return m;
  return NULL;
}
int crdv_native_arrival(struct crdv_registration *r,const struct sir_rdv_value *v)
{
 if(!r||!v||v->kind!=RDVP_WWI||v->status||!r->config.native_wwi)return EINVAL;
 pthread_mutex_lock(&r->registry->mu);
 int rc=__atomic_load_n(&r->closed,__ATOMIC_ACQUIRE)?ESHUTDOWN:r->native_pending?EAGAIN:0;
 if(!rc){r->native_value=*v;r->native_pending=1;}
 pthread_mutex_unlock(&r->registry->mu);
 if(!rc)crdv_registry_wake(r->registry);
 return rc;
}
int crdv_offer_snapshot(struct crdv_registration *r, uint64_t slot,
                        uint64_t app, struct crdv_offer_snapshot *out) {
  if (!r || !out)
    return EINVAL;
  pthread_mutex_lock(&r->registry->mu);
  struct crdv_message *m = find_slot(r, slot, app);
  int rc = !m ? ESTALE : 0;
  struct crdv_offer_snapshot value = {0};
  struct ctrl_reactor *reactor = NULL;
  if (!rc) {
    value = m->published_offer;
    reactor = r->registry->actor->reactor;
    r->actor_refs++;
    r->registry->actor->external_refs++;
  }
  pthread_mutex_unlock(&r->registry->mu);
  if (!rc) {
    struct sir_app_qp_snapshot b = {0};
    rc = cbind_current(reactor, &r->config.key, &b);
    if (rc)
      rc = error_value(rc);
    else if (b.session_id != value.value.id.session_id ||
             b.transport_generation != value.value.id.transport_generation ||
             b.command_revision != value.value.id.command_revision ||
             !endpoint_equal(&b.local, &value.value.id.local) ||
             !endpoint_equal(&b.peer, &value.value.id.peer))
      rc = ESTALE;
    if (!rc)
      *out = value;
    pthread_mutex_lock(&r->registry->mu);
    r->registry->actor->external_refs--;
    pthread_mutex_unlock(&r->registry->mu);
    registration_put(r);
  }
  return rc;
}
int crdv_offer_reply(struct crdv_registration *r, uint64_t slot, uint64_t app,
                     uint64_t attempt, enum crdv_offer_result result) {
  if (!r || !attempt ||
      (result != CRDV_NO_RQ && result != CRDV_RESOURCE_BACKPRESSURE))
    return EINVAL;
  pthread_mutex_lock(&r->registry->mu);
  struct crdv_message *m = find_slot(r, slot, app);
  int rc = 0;
  if (!m || m->published_offer.attempt != attempt)
    rc = ESTALE;
  else if (m->reply_pending)
    rc = m->reply_result == (unsigned)result ? EALREADY : EPROTO;
  else {
    m->reply_pending = 1;
    m->reply_result = result;
    r->actor_refs++;
  }
  pthread_mutex_unlock(&r->registry->mu);
  if (!rc) {
    crdv_registry_wake(r->registry);
    registration_put(r);
  }
  return rc;
}
int crdv_actor_new(struct crdv_registry *g, struct ctrl_reactor *r,
                   const struct crdv_resource_ops *ops, void *opaque,
                   struct crdv_actor **out) {
  if (!g || !r || !ops || !ops->prepare || !ops->read_prepare || !out)
    return EINVAL;
  *out = NULL;
  struct crdv_actor *a = calloc(1, sizeof(*a));
  if (!a)
    return ENOMEM;
  a->registry = g;
  a->reactor = r;
  a->ops = *ops;
  a->resource_opaque = opaque;
  a->next_ticket = a->next_attempt = a->next_challenge = 1;
  pthread_mutex_lock(&g->mu);
  if (g->actor) {
    pthread_mutex_unlock(&g->mu);
    free(a);
    return EBUSY;
  }
  g->actor = a;
  pthread_mutex_unlock(&g->mu);
  *out = a;
  return 0;
}
int crdv_actor_free(struct crdv_actor *a) {
  if (!a)
    return EINVAL;
  for (struct crdv_message *m = a->messages; m; m = m->next)
    if (m->resource)
      return EBUSY;
  pthread_mutex_lock(&a->registry->mu);
  if (a->external_refs) {
    pthread_mutex_unlock(&a->registry->mu);
    return EBUSY;
  }
  a->retiring = 1;
  pthread_mutex_unlock(&a->registry->mu);
  if (a->inflight.ticket) {
    registration_put(a->tx_registration);
    a->inflight.ticket = 0;
    a->tx_registration = NULL;
    a->tx_message = NULL;
  }
  while (a->messages) {
    struct crdv_message *m = a->messages;
    if (!m->released && m->slot) {
      m->value.status = ECANCELED;
      m->ack_opcode = CPROTO_OP_RDV_CANCEL_ACK;
      int rc = publish_release(m, SIR_RDV_NO_DATA);
      if (rc && rc != EALREADY)
        return rc;
    }
    message_free(a, m);
  }
  pthread_mutex_lock(&a->registry->mu);
  a->registry->actor = NULL;
  pthread_mutex_unlock(&a->registry->mu);
  while (a->streams) {
    struct crdv_stream *s = a->streams;
    a->streams = s->next;
    registration_put(s->registration);
    free(s);
  }
  free(a);
  return 0;
}
static int current(struct crdv_actor *a, struct crdv_registration *r,
                   struct sir_app_qp_snapshot *s) {
  if (a->down || __atomic_load_n(&r->closed, __ATOMIC_ACQUIRE))
    return ENOTCONN;
  int rc = cbind_current(a->reactor, &r->config.key, s);
  if (rc)
    return error_value(rc);
  return s->local.route.connection_epoch == r->config.connection_epoch ? 0
                                                                       : ESTALE;
}
static int authorized(struct crdv_actor *a, struct crdv_registration *r,
                      const struct rdvp_message *m, unsigned source,
                      uint64_t sid) {
  struct sir_app_qp_snapshot s;
  if (current(a, r, &s) || s.session_id != sid)
    return 0;
  return endpoint_equal(&s.local, source ? &m->sender : &m->receiver) &&
         endpoint_equal(&s.peer, source ? &m->receiver : &m->sender);
}
static struct crdv_registration *
registration_for(struct crdv_actor *a,
                 const struct sir_app_qp_endpoint *local) {
  struct crdv_registration *found = NULL;
  pthread_mutex_lock(&a->registry->mu);
  for (struct crdv_registration *r = a->registry->registrations; r; r = r->next)
    if (!__atomic_load_n(&r->closed, __ATOMIC_ACQUIRE) &&
        key_equal(&r->config.key, &local->key) &&
        r->config.connection_epoch == local->route.connection_epoch) {
      r->actor_refs++;
      found = r;
      break;
    }
  pthread_mutex_unlock(&a->registry->mu);
  return found;
}
static struct crdv_stream *stream_for(struct crdv_actor *a,
                                      struct crdv_registration *r,
                                      const struct rdvp_message *m,
                                      int create) {
  for (struct crdv_stream *s = a->streams; s; s = s->next)
    if (s->registration == r && logical_equal(&s->sender, &m->sender) &&
        logical_equal(&s->receiver, &m->receiver))
      return s;
  if (!create)
    return NULL;
  struct crdv_stream *s = calloc(1, sizeof(*s));
  if (!s)
    return NULL;
  s->registration = r;
  s->sender = m->sender;
  s->receiver = m->receiver;
  s->base = s->next_sequence = m->sequence;
  s->next = a->streams;
  a->streams = s;
  pthread_mutex_lock(&a->registry->mu);
  r->actor_refs++;
  pthread_mutex_unlock(&a->registry->mu);
  return s;
}
static struct crdv_message *message_find(struct crdv_actor *a,
                                         const struct rdvp_message *wire,
                                         uint64_t sid, unsigned role) {
  for (struct crdv_message *m = a->messages; m; m = m->next)
    if (m->role == role && m->value.id.session_id == sid &&
        message_equal(&m->wire, wire))
      return m;
  return NULL;
}
static struct crdv_message *
message_new(struct crdv_actor *a, struct crdv_registration *r, unsigned role) {
  struct crdv_message *m = calloc(1, sizeof(*m));
  if (!m)
    return NULL;
  m->registration = r;
  m->role = role;
  pthread_mutex_lock(&a->registry->mu);
  m->next = a->messages;
  a->messages = m;
  r->owners++;
  pthread_mutex_unlock(&a->registry->mu);
  a->active++;
  return m;
}
static void message_free(struct crdv_actor *a, struct crdv_message *m) {
  if (a->tx_message == m || m->resource)
    return;
  pthread_mutex_lock(&a->registry->mu);
  struct crdv_message **p = &a->messages;
  while (*p && *p != m)
    p = &(*p)->next;
  if (*p)
    *p = m->next;
  struct crdv_registration *registration = m->registration;
  registration->actor_refs++;
  registration->owners--;
  pthread_mutex_unlock(&a->registry->mu);
  free(m->segments);
  free(m);
  a->active--;
  stats_progress(a, registration);
  registration_put(registration);
}
static unsigned reg_count(struct crdv_actor *a, struct crdv_registration *r,
                          unsigned role) {
  unsigned n = 0;
  for (struct crdv_message *m = a->messages; m; m = m->next)
    n += m->registration == r && m->role == role && !m->released && m->slot &&
         !m->matched;
  return n;
}
static void hold_drop(struct crdv_message *m) {
  if (m->hold) {
    sir_rdv_message_drop(m->registration->config.mailbox, m->slot,
                         SIR_RDV_CALLBACK);
    m->hold = 0;
  }
}
static int publish_release(struct crdv_message *m, unsigned evidence) {
  pthread_mutex_lock(&m->registration->registry->mu);
  m->offer_visible = 0;
  pthread_mutex_unlock(&m->registration->registry->mu);
  if (!m->release_counted && (m->role == SIR_RDV_SOURCE || m->matched)) {
    m->release_counted = 1;
    if (m->role == SIR_RDV_SOURCE)
      m->registration->pending_stats.source_released++;
    else
      m->registration->pending_stats.sink_released++;
    stats_progress(m->registration->registry->actor, m->registration);
  }
  hold_drop(m);
  int rc = sir_rdv_message_released(m->registration->config.mailbox, m->slot,
                                    (enum sir_rdv_release_evidence)evidence,
                                    &m->value);
  if (!rc || rc == EALREADY)
    m->released = 1;
  return rc;
}
static void source_prepare(struct crdv_actor *a, struct crdv_registration *r,
                           const struct sir_rdv_record *record) {
  struct crdv_message *m = message_new(a, r, SIR_RDV_SOURCE);
  if (!m) {
    struct sir_rdv_value value = record->value;
    value.status = ENOMEM;
    if (!r->source_failed_sequence ||
        value.id.rq_message_seq < r->source_failed_sequence)
      r->source_failed_sequence = value.id.rq_message_seq;
    sir_rdv_command_ack(r->config.mailbox, record->token, record->serial);
    r->pending_stats.source_released++;
    stats_progress(a, r);
    sir_rdv_message_released(r->config.mailbox, record->token, SIR_RDV_NO_DATA,
                             &value);
    return;
  }
  m->slot = record->token;
  m->app_token = record->app_token;
  m->value = record->value;
  m->wire = value_wire(&m->value, SIR_RDV_SOURCE);
  m->offer_pending = !(m->wire.kind==RDVP_WWI&&r->config.native_wwi&&(r->peer_flags&RDVP_CAP_NATIVE_WWI));
  m->span_count = record->span_count;
  m->pending_prepare = 1;
  int rc = sir_rdv_message_hold(r->config.mailbox, m->slot, SIR_RDV_CALLBACK);
  if (!rc)
    m->hold = 1;
  sir_rdv_command_ack(r->config.mailbox, record->token, record->serial);
  if (rc) {
    m->value.status = rc;
    m->closed = 1;
    m->offer_pending = 0;
    m->pending_prepare = 0;
    publish_release(m, SIR_RDV_NO_DATA);
  }
}
static void source_fail(struct crdv_registration *r, uint64_t sequence) {
  if (!r->source_failed_sequence || sequence < r->source_failed_sequence)
    r->source_failed_sequence = sequence;
}
static unsigned prepared_count(struct crdv_actor *a, unsigned role) {
  unsigned n = 0;
  for (struct crdv_message *p = a->messages; p; p = p->next)
    if (p->role == role && p->resource) {
      struct rdv_bridge_counts c = {0};
      rdv_bridge_get_counts(p->resource, &c);
      n += c.pending_jobs || c.native_refs || (!c.ready && !c.released);
    }
  return n;
}
static void prepare_progress(struct crdv_actor *a, struct crdv_message *m) {
  if (!m->pending_prepare || m->resource)
    return;
  unsigned closing =
      m->closed ||
      __atomic_load_n(&m->registration->closed, __ATOMIC_ACQUIRE) || a->down;
  if (!closing && prepared_count(a, m->role) >= CRDV_ACTIVE_MAX)
    return;
  struct crdv_registration *r = m->registration;
  int rc = m->role == SIR_RDV_SOURCE ? (int)m->value.status : 0;
  if (m->closed || __atomic_load_n(&r->closed, __ATOMIC_ACQUIRE) || a->down ||
      (m->role == SIR_RDV_SOURCE && r->source_failed_sequence &&
       m->wire.sequence >= r->source_failed_sequence))
    rc = ECANCELED;
  struct sir_app_qp_snapshot bound = {0};
  if (!rc)
    rc = current(a, r, &bound);
  if (!rc && (m->value.id.session_id != bound.session_id ||
              m->value.id.transport_generation != bound.transport_generation ||
              m->value.id.command_revision != bound.command_revision ||
              !endpoint_equal(&m->value.id.local, &bound.local) ||
              !endpoint_equal(&m->value.id.peer, &bound.peer)))
    rc = ESTALE;
  struct sir_rdv_span *spans = NULL;
  size_t n = 0;
  if (!rc && m->span_count) {
    spans = calloc(m->span_count, sizeof(*spans));
    if (!spans)
      rc = ENOMEM;
  }
  if (!rc)
    rc = sir_rdv_spans_copy(r->config.mailbox, m->slot, spans, m->span_count,
                            &n);
  if (!rc) {
    struct rdv_bridge_config config = {
        .role = m->role == SIR_RDV_SOURCE ? RDV_BRIDGE_SOURCE : RDV_BRIDGE_SINK,
        .slot_token = m->slot,
        .app_token = m->app_token,
        .message = m->value,
        .spans = spans,
        .span_count = (unsigned)n};
    rc = a->ops.prepare(a->resource_opaque, &config, &m->resource);
    if (!rc)
      rc = rdv_bridge_start(m->resource);
  }
  free(spans);
  m->pending_prepare = 0;
  if (rc && !m->resource) {
    m->value.status = error_value(rc);
    if (m->role == SIR_RDV_SOURCE)
      source_fail(r, m->wire.sequence);
    m->closed = 1;
    m->offer_pending = 0;
    publish_release(m, m->role == SIR_RDV_SINK && m->matched && m->span_count
                           ? SIR_RDV_DATA_CLEANED
                           : SIR_RDV_NO_DATA);
    if (m->role == SIR_RDV_SINK) {
      m->terminal = m->ack_pending = 1;
      m->final_status = status_wire(m->value.status);
      if (m->value.status && !m->stream->failed_sequence)
        m->stream->failed_sequence = m->wire.sequence;
      if (m->stream->next_sequence == m->wire.sequence)
        m->stream->next_sequence++;
    }
  }
}
/* code25 is the IB_RNR_TIMER_061_44 encoding (61440us). Linux v5.11 RXE
 * spells its table entry 61410; use the specified 61.44ms, not that typo. */
static uint64_t rnr_usec(unsigned code) {
  static const uint32_t table[32] = {
      655360, 10,    20,    30,     40,     60,     80,     120,
      160,    240,   320,   480,    640,    960,    1280,   1920,
      2560,   3840,  5120,  7680,   10240,  15360,  20480,  30720,
      40960,  61440, 81920, 122880, 163840, 245760, 327680, 491520};
  return table[code & 31];
}
static void sink_release_empty(struct crdv_message *m, unsigned status) {
  m->value.status = status;
  publish_release(m, SIR_RDV_NO_DATA);
}
static int offer_publish(struct crdv_actor *a, struct crdv_message *m) {
  struct crdv_registration *r = m->registration;
  uint64_t token = 0;
  if (reg_count(a, r, SIR_RDV_SINK) >= 1)
    return EAGAIN;
  uint64_t app = serial_next(&a->next_attempt);
  if (!app)
    return EOVERFLOW;
  int rc =
      sir_rdv_message_reserve(r->config.mailbox, SIR_RDV_SINK, app, &token);
  if (rc)
    return rc;
  m->slot = token;
  m->app_token = m->attempt = app;
  m->released = 0;
  rc = sir_rdv_message_hold(r->config.mailbox, token, SIR_RDV_CALLBACK);
  if (!rc)
    m->hold = 1;
  if (!rc) {
    m->matchable = 1;
    pthread_mutex_lock(&a->registry->mu);
    m->offer_visible = 1;
    m->published_offer =
        (struct crdv_offer_snapshot){.attempt = m->attempt,
                                     .stream_base = m->stream->base,
                                     .stream_first = m->stream_first,
                                     .native_wwi = r->config.native_wwi&&(r->peer_flags&RDVP_CAP_NATIVE_WWI),
                                     .value = m->value};
    pthread_mutex_unlock(&a->registry->mu);
    rc = sir_rdv_event_publish(r->config.mailbox, token, SIR_RDV_OFFER_READY,
                               &m->value);
  }
  if (rc) {
    pthread_mutex_lock(&a->registry->mu);
    m->offer_visible = 0;
    pthread_mutex_unlock(&a->registry->mu);
    m->matchable = 0;
    hold_drop(m);
    sir_rdv_message_abort(r->config.mailbox, token);
    m->slot = 0;
    return rc;
  }
  return 0;
}
static int receive_offer(struct crdv_actor *a,
                         const struct cproto_header *header,
                         const uint8_t *payload,unsigned native,unsigned native_status) {
  struct rdvp_offer offer;
  struct rdvp_segment segment[RDVP_SEGMENTS_PER_FRAME];
  int rc = rdvp_offer_decode(payload, header->payload_len, &offer, segment,
                             RDVP_SEGMENTS_PER_FRAME);
  if (rc)
    return -rc;
  struct crdv_message *m =
      message_find(a, &offer.message, header->session_id, SIR_RDV_SINK);
  if (m) {
    if (m->terminal) {
      m->ack_pending = 1;
      return 0;
    }
    if (m->wait_pending || (!m->matchable && m->challenge)) {
      if (header->request_id != m->challenge) {
        m->wait_pending = 1;
        return 0;
      }
      if (m->offer_request == m->challenge)
        return 0; /* same attempt already handled */
      m->offer_request = m->challenge;
      m->challenge = 0;
      m->value.status = 0;
      m->wait_pending = 0;
      m->fragments_received = 0;
      m->received_length = 0;
    } else if (header->request_id != m->offer_request)
      return ESTALE;
    if (m->matched) {
      if(m->wire.kind==RDVP_WWI&&m->wwi_ready&&!m->wwi_result&&!m->closed)
        m->wwi_ready_pending=1;
      return 0;
    }
  } else {
    struct crdv_registration *r = registration_for(a, &offer.message.receiver);
    if (!r)
      return ESTALE;
    if (!authorized(a, r, &offer.message, 0, header->session_id)) {
      registration_put(r);return ESTALE;
    }
    if(!r->peer_caps||!r->caps_acked){registration_put(r);return native?EAGAIN:ESTALE;}
    if(offer.message.kind==RDVP_WWI&&r->config.native_wwi&&(r->peer_flags&RDVP_CAP_NATIVE_WWI)&&!native){registration_put(r);return EPROTO;}
    if (offer.total_segments > r->peer_sge_limit) {
      registration_put(r);
      return EPROTO;
    }
    if (header->request_id || offer.fragment_index) {
      registration_put(r);
      return EAGAIN;
    }
    struct crdv_stream *stream = stream_for(a, r, &offer.message, 1);
    if (!stream) {
      registration_put(r);
      return ENOMEM;
    }
    if ((stream->failed_sequence &&
         offer.message.sequence >= stream->failed_sequence) ||
        offer.message.sequence != stream->next_sequence) {
      registration_put(r);
      return ESTALE;
    }
    unsigned metadata = 0;
    for (struct crdv_message *p = a->messages; p; p = p->next)
      metadata += p->role == SIR_RDV_SINK && p->registration == r;
    if (metadata >= (uint64_t)r->config.caps.rq_depth + 1) {
      registration_put(r);
      return EAGAIN;
    }
    m = message_new(a, r, SIR_RDV_SINK);
    registration_put(r);
    if (!m)
      return EAGAIN;
    m->stream = stream;
    m->stream_first = offer.message.sequence == stream->base;
    m->wire = offer.message;
    struct sir_app_qp_snapshot b = {0};
    if (current(a, r, &b)) {
      message_free(a, m);
      return ESTALE;
    }
    m->value = (struct sir_rdv_value){
        .id = {.session_id = header->session_id,
               .transport_generation = b.transport_generation,
               .command_revision = b.command_revision,
               .local = b.local,
               .peer = b.peer,
               .message_id = offer.message.message_id,
               .rq_message_seq = offer.message.sequence},
        .length = offer.message.total_length,
        .kind = offer.message.kind,
        .imm_be = offer.imm_be,
        .solicited = !!(offer.message.flags & RDVP_F_SOLICITED),.status=native_status};
    if(native){m->native_received=1;m->wwi_result=1;m->wwi_result_status=native_status?RDVP_REMOTE_ACCESS:RDVP_OK;}
    m->segment_count = offer.total_segments;
    m->fragment_count = offer.fragment_count;
    if (m->segment_count) {
      if ((uint64_t)m->segment_count * sizeof(*m->segments) > SIZE_MAX) {
        message_free(a, m);
        return EOVERFLOW;
      }
      m->segments = calloc(m->segment_count, sizeof(*m->segments));
      if (!m->segments) {
        message_free(a, m);
        return ENOMEM;
      }
    }
  }
  if (offer.total_segments != m->segment_count ||
      offer.imm_be != m->value.imm_be)
    return EPROTO;
  if (offer.fragment_index < m->fragments_received) {
    for (unsigned i = 0; i < offer.entry_count; i++) {
      struct rdvp_segment *old = &m->segments[offer.segment_offset + i];
      if (old->address != segment[i].address ||
          old->length != segment[i].length || old->rkey != segment[i].rkey)
        return EPROTO;
    }
    return 0;
  }
  if (offer.fragment_index != m->fragments_received ||
      offer.message_offset != m->received_length)
    return EAGAIN;
  for (unsigned i = 0; i < offer.entry_count; i++) {
    m->segments[offer.segment_offset + i] = segment[i];
    m->received_length += segment[i].length;
  }
  m->fragments_received++;
  if (m->fragments_received == offer.fragment_count) {
    if(!native)m->registration->pending_stats.sink_offers_received++;
    if (m->slot && !m->released)
      return 0;
    return offer_publish(a, m);
  }
  return 0;
}
static int receive_caps(struct crdv_actor *a,
                        const struct cproto_header *header,
                        const uint8_t *payload) {
  struct rdvp_caps caps;
  int rc = rdvp_caps_decode(payload, header->payload_len, &caps);
  if (rc)
    return -rc;
  struct crdv_registration *r = registration_for(a, &caps.receiver);
  if (!r)
    return ESTALE;
  struct rdvp_message m = {.sender = caps.sender, .receiver = caps.receiver};
  int result = 0;
  refresh_caps(a, r);
  if (!authorized(a, r, &m, 0, header->session_id))
    result = ESTALE;
  else if(caps.flags!=(r->config.native_wwi?RDVP_CAP_NATIVE_WWI:0)){
    r->pending_stats.native_error=EOPNOTSUPP;result=EOPNOTSUPP;
  }
  else if (r->peer_caps && (r->peer_sge_limit != caps.source_sge_limit||r->peer_flags!=caps.flags))
    result = EPROTO;
  else {
    r->peer_sge_limit = caps.source_sge_limit;r->peer_flags=caps.flags;
    r->peer_caps = 1;
    r->caps_ack_pending = 1;
  }
  registration_put(r);
  return result;
}
static int receive_inner(struct crdv_actor *a, const void *frame, size_t length,
                         uint64_t now) {
  if (!a || !frame || length > CONTROL_SLOT_CAPACITY)
    return EINVAL;
  a->now = now;
  struct cproto_header header;
  int rc = cproto_header_decode(frame, (uint32_t)length, &header);
  if (rc)
    return -rc;
  if (header.kind != CPROTO_CONTROL_EVENT || header.flags ||
      header.payload_len + CONTROL_HEADER_LEN != length)
    return EPROTO;
  const uint8_t *payload = (const uint8_t *)frame + CONTROL_HEADER_LEN;
  uint32_t op;
  if (cproto_op_get(payload, header.payload_len, &op))
    return EPROTO;
  if(op==CPROTO_OP_RDV_DRAIN_REQUEST||op==CPROTO_OP_RDV_DRAIN_ACK)
    return drain_receive(a,&header,payload,op);
  if (op == CPROTO_OP_RDV_CAPS_ACK) {
    struct rdvp_caps caps;
    int result = rdvp_caps_ack_decode(payload, header.payload_len, &caps);
    if (result)
      return -result;
    if (header.request_id)
      return EPROTO;
    struct crdv_registration *r = registration_for(a, &caps.sender);
    if (!r)
      return ESTALE;
    struct sir_app_qp_snapshot b = {0};
    refresh_caps(a, r);
    result = current(a, r, &b);
    if (!result && (!r->caps_sent || b.session_id != header.session_id ||
                    !endpoint_equal(&b.local, &caps.sender) ||
                    !endpoint_equal(&b.peer, &caps.receiver) ||
                    caps.source_sge_limit != r->config.caps.source_sge_limit||
                    caps.flags!=(r->config.native_wwi?RDVP_CAP_NATIVE_WWI:0)))
      result = ESTALE;
    if (!result) {
      r->caps_acked = 1;
      r->caps_due = 0;
    }
    registration_put(r);
    return result;
  }
  if (op == CPROTO_OP_RDV_CAPS) {
    if (header.request_id)
      return EPROTO;
    return receive_caps(a, &header, payload);
  }
  if (op == CPROTO_OP_RDV_OFFER)
    return receive_offer(a, &header, payload,0,0);
  if (op == CPROTO_OP_RDV_WWI_READY || op == CPROTO_OP_RDV_WWI_RESULT) {
    struct rdvp_ack ack; uint32_t actual;
    rc = rdvp_ack_decode(payload, header.payload_len, &actual, &ack);
    if (rc) return -rc;
    if (header.request_id || ack.message.kind != RDVP_WWI) return EPROTO;
    struct crdv_message *m = message_find(a, &ack.message, header.session_id,
        op == CPROTO_OP_RDV_WWI_READY ? SIR_RDV_SOURCE : SIR_RDV_SINK);
    if(!m&&op==CPROTO_OP_RDV_WWI_RESULT&&ack.status==RDVP_REMOTE_ACCESS){
      struct crdv_registration *r=registration_for(a,&ack.message.receiver);
      unsigned enabled=r&&r->config.native_wwi&&(r->peer_flags&RDVP_CAP_NATIVE_WWI);
      if(r)registration_put(r);
      if(enabled){
        struct rdvp_offer offer={.message=ack.message,.fragment_count=1};
        unsigned char data[RDVP_OFFER_SIZE];
        int n=rdvp_offer_encode(data,sizeof(data),&offer,NULL);if(n<0)return -n;
        struct cproto_header h=header;h.payload_len=(unsigned)n;
        return receive_offer(a,&h,data,1,EREMOTEIO);
      }
    }
    if (!m) return ESTALE;
    if (op == CPROTO_OP_RDV_WWI_READY) {
      if (m->wwi_ready) return 0;
      if (!m->offered || m->closed || m->final_ack ||
          !authorized(a,m->registration,&m->wire,1,header.session_id)) return ESTALE;
      m->wwi_ready=1; m->offer_pending=0; m->next_due=0;
      rc=sir_rdv_event_publish(m->registration->config.mailbox,m->slot,
                              SIR_RDV_WWI_READY,&m->value);
      return rc==EALREADY?0:rc;
    }
    if (ack.status!=RDVP_OK && ack.status!=RDVP_REMOTE_ACCESS) return EPROTO;
    if(ack.status==RDVP_OK&&m->registration->config.native_wwi&&
       (m->registration->peer_flags&RDVP_CAP_NATIVE_WWI))return EPROTO;
    if (m->wwi_result) {
      if (m->wwi_result_status!=ack.status) return EPROTO;
      if (m->terminal) m->ack_pending=1;
      return 0;
    }
    if (!m->matched || !m->wwi_ready || m->closed || m->terminal) return ESTALE;
    m->wwi_result=1; m->wwi_result_status=ack.status;
    m->value.status=status_local(ack.status);
    return 0;
  }
  if (op == CPROTO_OP_RDV_ACK || op == CPROTO_OP_RDV_CANCEL_ACK) {
    struct rdvp_ack ack;
    uint32_t actual;
    rc = rdvp_ack_decode(payload, header.payload_len, &actual, &ack);
    if (rc)
      return -rc;
    struct crdv_message *m =
        message_find(a, &ack.message, header.session_id, SIR_RDV_SOURCE);
    if (!m || !m->offered)
      return ESTALE;
    if (m->final_ack) {
      return m->final_status == ack.status &&
                     m->acknowledged_length == ack.completed_length
                 ? 0
                 : EPROTO;
    }
    if (ack.status == RDVP_OK && ack.completed_length != m->value.length)
      return EPROTO;
    m->final_ack = 1;
    m->final_status = ack.status;
    m->acknowledged_length = ack.completed_length;
    if (!m->value.status)
      m->value.status = status_local(ack.status);
    if (m->value.status)
      source_fail(m->registration, m->wire.sequence);
    m->next_due = 0;
    m->offer_pending = m->cancel_pending = 0;
    m->registration->pending_stats.wire_ack_validated++;
    rc = sir_rdv_event_publish(m->registration->config.mailbox, m->slot,
                               SIR_RDV_PEER_ACK, &m->value);
    if (rc && rc != EALREADY)
      return rc;
    if (!m->resource)
      return EPROTO;
    (void)rdv_bridge_release_allowed(m->resource, RDV_BRIDGE_PEER_FINAL_ACK,
                                     &m->value.id);
    return 0;
  }
  if (op == CPROTO_OP_RDV_WAIT) {
    struct rdvp_wait wait;
    rc = rdvp_wait_decode(payload, header.payload_len, &wait);
    if (rc)
      return -rc;
    struct crdv_message *m =
        message_find(a, &wait.message, header.session_id, SIR_RDV_SOURCE);
    if (!m || !m->offered || m->final_ack || !header.request_id)
      return ESTALE;
    if (header.request_id == m->challenge)
      return 0;
    if (header.request_id < m->challenge)
      return ESTALE;
    m->challenge = header.request_id;
    m->offer_pending = 0;
    unsigned retry =
        (__atomic_load_n(&m->registration->rnr_attrs, __ATOMIC_ACQUIRE) & 255u);
    if (retry != 7 && m->retries >= retry) {
      m->value.status = ETIMEDOUT;
      source_fail(m->registration, m->wire.sequence);
      m->cancel_pending = 1;
      m->closed = 1;
      return 0;
    }
    m->retries++;
    uint64_t delay = rnr_usec(wait.min_rnr_timer);
    m->next_due = now > UINT64_MAX - delay ? UINT64_MAX : now + delay;
    return 0;
  }
  if (op == CPROTO_OP_RDV_RETIRED) {
    struct rdvp_message wire;
    rc = rdvp_retired_decode(payload, header.payload_len, &wire);
    if (rc)
      return -rc;
    struct crdv_message *m =
        message_find(a, &wire, header.session_id, SIR_RDV_SINK);
    if (!m)
      return ESTALE;
    if (!m->terminal || !m->released)
      return EBUSY;
    m->ack_pending = m->wait_pending = 0;
    m->retired_seen = 1;
    if (m->wire.sequence < m->stream->next_sequence)
      message_free(a, m);
    return 0;
  }
  if (op == CPROTO_OP_RDV_CANCEL) {
    struct rdvp_cancel cancel;
    rc = rdvp_cancel_decode(payload, header.payload_len, &cancel);
    if (rc)
      return -rc;
    struct crdv_message *m =
        message_find(a, &cancel.message, header.session_id, SIR_RDV_SINK);
    if (!m) {
      struct crdv_registration *r =
          registration_for(a, &cancel.message.receiver);
      if (r) {
        struct crdv_stream *stream = stream_for(a, r, &cancel.message, 1);
        unsigned metadata = 0;
        for (struct crdv_message *p = a->messages; p; p = p->next)
          metadata += p->role == SIR_RDV_SINK && p->registration == r;
        if (!stream || metadata >= (uint64_t)r->config.caps.rq_depth + 1) {
          registration_put(r);
          return EAGAIN;
        }
        if (cancel.message.sequence < stream->next_sequence) {
          registration_put(r);
          r = NULL;
        } else {
          m = message_new(a, r, SIR_RDV_SINK);
          registration_put(r);
          if (!m)
            return ENOMEM;
          struct sir_app_qp_snapshot b = {0};
          (void)cbind_current(a->reactor, &r->config.key, &b);
          m->wire = cancel.message;
          m->stream = stream;
          m->released = 1;
          m->value = (struct sir_rdv_value){
              .id = {.session_id = header.session_id,
                     .transport_generation = b.transport_generation,
                     .command_revision = b.command_revision,
                     .local = cancel.message.receiver,
                     .peer = cancel.message.sender,
                     .message_id = cancel.message.message_id,
                     .rq_message_seq = cancel.message.sequence},
              .length = cancel.message.total_length,
              .kind = cancel.message.kind};
        }
      }
      if (!m) {
        if (a->unmatched_reply &&
            !message_equal(&a->unmatched_wire, &cancel.message))
          return EAGAIN;
        a->unmatched_reply = 1;
        a->unmatched_sid = header.session_id;
        a->unmatched_wire = cancel.message;
        return 0;
      }
    }
    if (m->terminal) {
      m->ack_pending = 1;
      return 0;
    }
    pthread_mutex_lock(&a->registry->mu);
    m->closed = 1;
    m->matchable = 0;
    pthread_mutex_unlock(&a->registry->mu);
    m->wait_pending = 0;
    m->final_status =
        m->matched ? RDVP_CANCELLED_MATCHED : RDVP_CANCELLED_UNMATCHED;
    m->value.status = m->wire.kind==RDVP_WWI && !m->wwi_result ? ENODATA : ECANCELED;
    m->wwi_ready_pending=0;
    m->ack_opcode = CPROTO_OP_RDV_CANCEL_ACK;
    if (m->resource)
      rdv_bridge_cancel(m->resource);
    else {
      if (m->slot && !m->released)
        sink_release_empty(m, m->value.status);
      m->terminal = 1;
      m->ack_pending = 1;
      if (m->stream->next_sequence == m->wire.sequence)
        m->stream->next_sequence++;
    }
    return 0;
  }
  return EOPNOTSUPP;
}
static void match_prepare(struct crdv_actor *a, struct crdv_registration *r,
                          const struct sir_rdv_record *record) {
  struct crdv_message *m = NULL;
  for (m = a->messages; m; m = m->next)
    if (m->registration == r && m->role == SIR_RDV_SINK &&
        m->slot == record->token && m->app_token == record->app_token)
      break;
  int rc = !m || !m->matchable || m->closed || m->matched ? ESTALE : 0;
  if (!rc &&
      (!authorized(a, r, &m->wire, 0, m->value.id.session_id) ||
       record->value.id.transport_generation !=
           m->value.id.transport_generation ||
       record->value.id.command_revision != m->value.id.command_revision))
    rc = ESTALE;
  if (!rc) {
    struct rdvp_message wire = value_wire(&record->value, SIR_RDV_SINK);
    if (!message_equal(&wire, &m->wire))
      rc = ESTALE;
  }
  if (m && !m->matched) {
    m->matched = 1;
    m->matchable = 0;
    m->span_count = record->span_count;
    pthread_mutex_lock(&a->registry->mu);
    m->offer_visible = 0;
    pthread_mutex_unlock(&a->registry->mu);
    m->value.status = rc ? (unsigned)error_value(rc) : record->value.status;
    m->pending_prepare = 1;
    r->pending_stats.sink_matches++;
    if (rc)
      m->closed = 1;
  }
  sir_rdv_command_ack(r->config.mailbox, record->token, record->serial);
}
static void consume_commands(struct crdv_actor *a,
                             struct crdv_registration *r) {
  uint64_t frontier = sir_rdv_command_frontier(r->config.mailbox);
  struct sir_rdv_record record;
  while (sir_rdv_command_take(r->config.mailbox, frontier, &record) == 0) {
    if (record.kind == SIR_RDV_SOURCE_PREPARE)
      source_prepare(a, r, &record);
    else if (record.kind == SIR_RDV_MATCH_PREPARE)
      match_prepare(a, r, &record);
    else if(record.kind==SIR_RDV_NATIVE_EXPOSED){
      struct crdv_message *m;
      for(m=a->messages;m;m=m->next)if(m->registration==r&&m->role==SIR_RDV_SOURCE&&m->slot==record.token&&m->app_token==record.app_token)break;
      if(m&&m->resource&&!m->closed&&!m->offered){
        int rc=rdv_bridge_mark_exposed(m->resource);
        if(!rc)m->offered=1;else {m->closed=1;m->value.status=error_value(rc);}
      }
      sir_rdv_command_ack(r->config.mailbox,record.token,record.serial);
    }
    else if (record.kind == SIR_RDV_NATIVE_RECEIVED) {
      struct crdv_message *m;
      for(m=a->messages;m;m=m->next)
        if(m->registration==r&&m->role==SIR_RDV_SINK&&m->slot==record.token&&m->app_token==record.app_token)break;
      if(m&&r->config.native_wwi&&(r->peer_flags&RDVP_CAP_NATIVE_WWI)&&
         m->matched&&!m->closed&&!m->terminal){
        m->native_received=1;
        if(m->wire.kind==RDVP_WWI){m->wwi_result=1;m->wwi_result_status=RDVP_OK;m->value.status=0;}
      }
      sir_rdv_command_ack(r->config.mailbox,record.token,record.serial);
    }
    else if (record.kind == SIR_RDV_WWI_RESULT) {
      struct crdv_message *m;
      for(m=a->messages;m;m=m->next)
        if(m->registration==r && m->role==SIR_RDV_SOURCE &&
           m->slot==record.token && m->app_token==record.app_token) break;
      if(m && m->wire.kind==RDVP_WWI && m->wwi_ready && !m->closed && !m->final_ack){
        m->wwi_result=1;
        m->wwi_result_status=record.value.status==EREMOTEIO?RDVP_REMOTE_ACCESS:RDVP_OK;
        m->wwi_result_pending=1;
      }
      sir_rdv_command_ack(r->config.mailbox,record.token,record.serial);
    } else {
      for (struct crdv_message *m = a->messages; m; m = m->next)
        if (m->registration == r && m->slot == record.token) {
          m->closed = 1;
          m->matchable = 0;
          m->value.status = ECANCELED;
          if (m->role == SIR_RDV_SOURCE)
            source_fail(r, m->wire.sequence);
          m->ack_opcode = CPROTO_OP_RDV_CANCEL_ACK;
          if (m->role == SIR_RDV_SOURCE && m->offered)
            m->cancel_pending = 1;
          else if (m->resource)
            rdv_bridge_cancel(m->resource);
        }
      sir_rdv_command_ack(r->config.mailbox, record.token, record.serial);
    }
  }
}
static void refresh_caps(struct crdv_actor *a, struct crdv_registration *r) {
  struct sir_app_qp_snapshot b = {0};
  if (current(a, r, &b)) {
    r->caps_sent = r->peer_caps = r->caps_acked = r->caps_ack_pending = 0;
    r->caps_due = 0;
    return;
  }
  if (r->binding.session_id != b.session_id ||
      r->binding.command_revision != b.command_revision ||
      !endpoint_equal(&r->binding.local, &b.local) ||
      !endpoint_equal(&r->binding.peer, &b.peer)) {
    r->binding = b;
    r->caps_sent = r->peer_caps = r->caps_acked = r->caps_ack_pending = 0;
    r->caps_due = 0;
    r->pending_stats.session_id = b.session_id;
    r->pending_stats.transport_generation = b.transport_generation;
  }
  if (!a->current_sid)
    a->current_sid = b.session_id;
}
static int source_segments(struct crdv_message *m) {
  unsigned n = 0;
  int rc = rdv_bridge_views(m->resource, NULL, 0, &n);
  if (rc && rc != ENOSPC)
    return rc;
  if (n > m->registration->config.caps.source_sge_limit)
    return EOVERFLOW;
  struct rdv_bridge_view *views = n ? calloc(n, sizeof(*views)) : NULL;
  if (n && !views)
    return ENOMEM;
  struct rdvp_segment *segments = n ? calloc(n, sizeof(*segments)) : NULL;
  if (n && !segments) {
    free(views);
    return ENOMEM;
  }
  rc = rdv_bridge_views(m->resource, views, n, &n);
  if (!rc)
    for (unsigned i = 0; i < n; i++)
      segments[i] = (struct rdvp_segment){.address = views[i].address,
                                          .length = views[i].length,
                                          .rkey = views[i].rkey};
  free(views);
  if (rc) {
    free(segments);
    return rc;
  }
  m->segments = segments;
  m->segment_count = n;
  return 0;
}
static void receipt_progress(struct crdv_actor *a, struct crdv_message *m) {
  struct sir_rdv_record receipt;
  if (rdv_bridge_take_released(m->resource, &receipt))
    return;
  if (!m->value.status)
    m->value.status = receipt.value.status;
  if (m->role == SIR_RDV_SINK) {
    m->terminal = 1;
    m->final_status = status_wire(m->value.status);
    if (m->value.status && !m->stream->failed_sequence)
      m->stream->failed_sequence = m->wire.sequence;
    if (m->stream->next_sequence == m->wire.sequence)
      m->stream->next_sequence++;
  }
  /* The resource receipt is actual dereg/UNPIN evidence. Publish the logical
   * status separately; a peer ACK never substitutes for this cleanup step. */
  if (!m->release_counted) {
    m->release_counted = 1;
    if (m->role == SIR_RDV_SOURCE)
      m->registration->pending_stats.source_released++;
    else
      m->registration->pending_stats.sink_released++;
  }
  stats_progress(a, m->registration);
  int rc = publish_release(m, receipt.evidence);
  if (rc && rc != EALREADY)
    return;
  rdv_bridge_released_committed(m->resource);
  if (rdv_bridge_free(m->resource))
    return;
  m->resource = NULL;
  if (m->role == SIR_RDV_SOURCE) {
    if (m->final_ack)
      m->retired_pending = 1;
  } else {
    m->ack_pending = 1;
  }
  (void)a;
}
static void resource_progress(struct crdv_actor *a, struct crdv_message *m) {
  if (m->pending_prepare)
    prepare_progress(a, m);
  if (!m->resource)
    return;
  if (__atomic_load_n(&m->registration->closed, __ATOMIC_ACQUIRE) || a->down ||
      (m->role == SIR_RDV_SOURCE && m->registration->source_failed_sequence &&
       m->wire.sequence >= m->registration->source_failed_sequence))
    m->closed = 1;
  if (m->closed) {
    m->offer_pending = 0;
    if (m->role == SIR_RDV_SOURCE && m->offered && !m->final_ack &&
        !a->dma_stopped)
      m->cancel_pending = 1;
    else
      rdv_bridge_cancel(m->resource);
    if (a->dma_stopped) {
      int rc = rdv_bridge_release_allowed(
          m->resource, RDV_BRIDGE_OLD_TRANSPORT_STOPPED, &m->value.id);
      if (!rc || rc == EAGAIN) {
        m->value.status = m->value.status ? m->value.status : EIO;
        sir_rdv_event_publish(m->registration->config.mailbox, m->slot,
                              SIR_RDV_DMA_STOPPED, &m->value);
      }
    }
  }
  (void)rdv_bridge_progress(m->resource);
  struct rdv_bridge_counts counts = {0};
  rdv_bridge_get_counts(m->resource, &counts);
  m->registration->pending_stats.reverse_read_posted +=
      counts.read_posted - m->read_posted_seen;
  m->read_posted_seen = counts.read_posted;
  m->registration->pending_stats.reverse_read_wc +=
      counts.read_wc - m->read_wc_seen;
  m->read_wc_seen = counts.read_wc;
  if (counts.error && !m->value.status)
    m->value.status = (unsigned)counts.error;
  if (m->role == SIR_RDV_SOURCE && m->value.status)
    source_fail(m->registration, m->wire.sequence);
  if (m->role == SIR_RDV_SOURCE && counts.ready && !m->closed && !m->segments &&
      m->value.length && m->value.kind != RDVP_WWI) {
    int rc = source_segments(m);
    if (rc) {
      m->value.status = error_value(rc);
      m->closed = 1;
      rdv_bridge_cancel(m->resource);
    }
  }
  if(m->role==SIR_RDV_SOURCE&&counts.ready&&!m->closed&&!m->source_prepared&&
     m->registration->config.native_wwi&&(m->registration->peer_flags&RDVP_CAP_NATIVE_WWI)){
    int rc=0;
    if(m->wire.kind==RDVP_WWI&&!m->offered){rc=rdv_bridge_mark_exposed(m->resource);if(!rc){m->offered=1;m->offer_complete=1;m->wwi_ready=1;}}
    if(!rc)rc=sir_rdv_event_publish(m->registration->config.mailbox,m->slot,SIR_RDV_SOURCE_PREPARED,&m->value);
    if(!rc||rc==EALREADY)m->source_prepared=1;
    else {m->closed=1;m->value.status=error_value(rc);}
  }
  if (m->role == SIR_RDV_SINK && counts.ready && !m->closed) {
    if (m->value.kind == RDVP_WWI && !m->wwi_result) {
      if (!m->wwi_ready) {m->wwi_ready=1; m->wwi_ready_pending=1;}
    } else if (m->value.status || !m->value.length || m->value.kind == RDVP_WWI) {
      if(!m->value.status&&m->registration->config.native_wwi&&
         (m->registration->peer_flags&RDVP_CAP_NATIVE_WWI)&&!m->native_received)return;
      (void)rdv_bridge_release_allowed(m->resource, RDV_BRIDGE_NOT_EXPOSED,
                                       NULL);
    } else {
      if (!m->read_prepared) {
        struct rdv_bridge_remote *remote =
            m->segment_count ? calloc(m->segment_count, sizeof(*remote)) : NULL;
        int rc = m->segment_count && !remote ? ENOMEM : 0;
        uint64_t offset = 0;
        if (!rc)
          for (unsigned i = 0; i < m->segment_count; i++) {
            remote[i] =
                (struct rdv_bridge_remote){.address = m->segments[i].address,
                                           .length = m->segments[i].length,
                                           .message_offset = offset,
                                           .rkey = m->segments[i].rkey};
            offset += remote[i].length;
          }
        if (!rc)
          rc = a->ops.read_prepare(a->resource_opaque, m->resource, remote,
                                   m->segment_count);
        free(remote);
        if (rc) {
          m->value.status = error_value(rc);
          m->read_error = 1;
          rdv_bridge_cancel(m->resource);
        } else
          m->read_prepared = 1;
      }
      if (m->read_prepared && !m->read_error && !m->read_finished_seen) {
        unsigned accepted = 0;
        int rc = rdv_bridge_read_progress(m->resource, &accepted);
        (void)accepted;
        if (rc && rc != EAGAIN) {
          m->read_error = 1;
          m->value.status = error_value(rc);
          rdv_bridge_cancel(m->resource);
        }
      }
      if (m->read_prepared && !m->read_finished_seen) {
        enum ibv_wc_status status;
        int rc = rdv_bridge_reads_done(m->resource, &status);
        if (!rc) {
          if (!m->read_finished_seen) {
            m->read_finished_seen = 1; /* Exact native WC count is read from
                                    typed adapter, not guessed here. */
          }
          if (status != IBV_WC_SUCCESS)
            if (!m->value.status)
              m->value.status = EIO;
        }
      }
      if(m->read_finished_seen&&(m->value.status||!m->registration->config.native_wwi||
         !(m->registration->peer_flags&RDVP_CAP_NATIVE_WWI)||m->native_received))
        (void)rdv_bridge_release_allowed(m->resource,RDV_BRIDGE_NOT_EXPOSED,NULL);
    }
  }
  receipt_progress(a, m);
}
static void replies_progress(struct crdv_actor *a, struct crdv_message *m) {
  pthread_mutex_lock(&a->registry->mu);
  unsigned reply = m->reply_pending ? m->reply_result : 0;
  m->reply_pending = 0;
  if (reply == CRDV_NO_RQ)
    m->offer_visible = 0;
  pthread_mutex_unlock(&a->registry->mu);
  if (reply == CRDV_NO_RQ && !m->matched && !m->terminal) {
    m->matchable = 0;
    uint64_t challenge = serial_next(&a->next_challenge);
    if (!challenge) {
      m->closed = 1;
      return;
    }
    m->challenge = challenge;
    m->wait_pending = 1;
    sink_release_empty(m, EAGAIN);
  }
}
static void stats_progress(struct crdv_actor *a, struct crdv_registration *r) {
  struct crdv_stats s = r->pending_stats;
  struct sir_app_qp_snapshot b = {0};
  s.data_ready = !current(a, r, &b) && r->caps_acked && r->peer_caps &&
                 b.session_id == r->binding.session_id &&
                 b.transport_generation == r->binding.transport_generation &&
                 b.command_revision == r->binding.command_revision &&
                 endpoint_equal(&b.local, &r->binding.local) &&
                 endpoint_equal(&b.peer, &r->binding.peer);
  s.native_wwi=s.data_ready&&r->config.native_wwi&&(r->peer_flags&RDVP_CAP_NATIVE_WWI);
  memset(&s.authorization, 0, sizeof(s.authorization));
  if (s.data_ready)
    s.authorization = b;
  s.actor_sources = s.actor_sinks = s.actor_pin_spans = s.actor_bridge_mrs =
      s.actor_native_outstanding = s.actor_cleanup_pending = 0;
  for (struct crdv_message *m = a->messages; m; m = m->next)
    if (m->registration == r) {
      if (!m->released && !m->release_counted) {
        if (m->role == SIR_RDV_SOURCE)
          s.actor_sources++;
        else
          s.actor_sinks++;
      }
      if (m->resource) {
        struct rdv_bridge_counts c = {0};
        rdv_bridge_get_counts(m->resource, &c);
        s.actor_pin_spans += c.pins;
        s.actor_bridge_mrs += c.mrs;
        s.actor_native_outstanding += c.native_refs;
        s.actor_cleanup_pending +=
            c.pending_jobs + (unsigned)(m->closed && !c.released);
      }
    }
  unsigned changed = s.data_ready != r->pending_stats.data_ready;
  r->pending_stats.data_ready = s.data_ready;
  publish_stats(r, &s);
  if (changed)
    sir_rdv_mailbox_notify_app(r->config.mailbox);
}
static void native_arrival_progress(struct crdv_actor *a,struct crdv_registration *r)
{
 struct sir_rdv_value v;unsigned pending;
 pthread_mutex_lock(&r->registry->mu);pending=r->native_pending;v=r->native_value;pthread_mutex_unlock(&r->registry->mu);
 if(!pending){r->native_due=0;return;}
 if(a->now<r->native_due)return;
 struct rdvp_offer offer={.message=value_wire(&v,SIR_RDV_SINK),.imm_be=v.imm_be,.fragment_count=1};
 unsigned char data[RDVP_OFFER_SIZE];int n=rdvp_offer_encode(data,sizeof(data),&offer,NULL);
 struct cproto_header h={.session_id=v.id.session_id,.payload_len=RDVP_OFFER_SIZE};
 struct sir_app_qp_snapshot bound={0};int rc=current(a,r,&bound);
 if(!rc&&(v.id.transport_generation!=bound.transport_generation||v.id.command_revision!=bound.command_revision||
    !endpoint_equal(&v.id.local,&bound.local)||!endpoint_equal(&v.id.peer,&bound.peer)))rc=ESTALE;
 if(!rc)rc=n<0?-n:receive_offer(a,&h,data,1,0);
 pthread_mutex_lock(&r->registry->mu);
 if(rc==EAGAIN){r->native_due=a->now+1000;}
 else {r->native_pending=0;r->native_due=0;if(rc)r->pending_stats.native_error=error_value(rc);else r->pending_stats.native_arrivals++;}
 pthread_mutex_unlock(&r->registry->mu);
 if(rc&&rc!=EAGAIN)sir_rdv_mailbox_notify_app(r->config.mailbox);
}
void crdv_progress(struct crdv_actor *a, uint64_t now) {
  if (!a)
    return;
  a->now = now;
  for (struct crdv_registration *r = registration_first(a->registry); r;
       r = registration_next(r)) {
    refresh_caps(a, r);
    consume_commands(a, r);native_arrival_progress(a,r);drain_commands(a,r);
  }
  for (struct crdv_message *m = a->messages, *next; m; m = next) {
    next = m->next;
    replies_progress(a, m);
    if (m->role == SIR_RDV_SINK && !m->slot && !m->terminal &&
        m->fragments_received == m->fragment_count) {
      (void)offer_publish(a, m);
    }
    if (m->role == SIR_RDV_SOURCE && m->next_due && now >= m->next_due &&
        !m->closed && !m->final_ack) {
      m->next_due = 0;
      m->offer_request = m->challenge;
      m->offer_fragment = 0;
      if(m->wire.kind==RDVP_WWI && m->wwi_result){m->offer_pending=0;m->wwi_result_pending=1;}
      else m->offer_pending = 1;
    }
    if (m->role == SIR_RDV_SOURCE && m->closed && m->offered && !m->final_ack &&
        m->next_due && now >= m->next_due) {
      m->next_due = 0;
      m->cancel_pending = 1;
    }
    resource_progress(a, m);
    if (m->role == SIR_RDV_SINK && m->terminal && m->released &&
        m->stream->next_sequence == m->wire.sequence)
      m->stream->next_sequence++;
    if (a->down && m->role == SIR_RDV_SINK && !m->resource && !m->terminal) {
      m->closed = 1;
      m->matchable = 0;
      if (m->slot && !m->released)
        sink_release_empty(m, EIO);
      else
        m->released = 1;
      m->terminal = 1;
    }
    if (a->down && a->dma_stopped && !m->resource && m->released) {
      m->ack_pending = m->wait_pending = m->retired_pending = 0;
      message_free(a, m);
    } else if (m->role == SIR_RDV_SOURCE && m->closed && m->released &&
               !m->final_ack && !m->offered)
      message_free(a, m);
  }
  unsigned advanced;
  do {
    advanced = 0;
    for (struct crdv_message *m = a->messages; m; m = m->next)
      if (m->role == SIR_RDV_SINK && m->terminal && m->released &&
          m->stream->next_sequence == m->wire.sequence) {
        m->stream->next_sequence++;
        advanced = 1;
      }
  } while (advanced);
  for (struct crdv_message *m = a->messages, *next; m; m = next) {
    next = m->next;
    if (m->role == SIR_RDV_SINK && m->retired_seen && m->released &&
        !m->resource && m->wire.sequence < m->stream->next_sequence)
      message_free(a, m);
  }
  for (struct crdv_registration *r = registration_first(a->registry); r;
       r = registration_next(r))
    {drain_registration_progress(a,r);stats_progress(a, r);}
  struct crdv_stream **at = &a->streams;
  while (*at) {
    struct crdv_stream *stream = *at;
    struct crdv_registration *r = stream->registration;
    if (__atomic_load_n(&r->closed, __ATOMIC_ACQUIRE) && !r->owners) {
      *at = stream->next;
      registration_put(r);
      free(stream);
    } else
      at = &stream->next;
  }
}
uint64_t crdv_next_deadline(struct crdv_actor *a) {
  uint64_t due = UINT64_MAX;
  if (a)
    for (struct crdv_message *m = a->messages; m; m = m->next)
      if (m->next_due && m->next_due < due)
        due = m->next_due;
  if (a && !a->down)
    for (struct crdv_registration *r = registration_first(a->registry); r;
         r = registration_next(r))
      if (!r->caps_acked && r->caps_due && r->caps_due < due)
        due = r->caps_due;
  if(a&&!a->down)for(struct crdv_registration *r=registration_first(a->registry);r;r=registration_next(r))
    if(r->native_due&&r->native_due<due)due=r->native_due;
  if(a&&!a->down)for(struct crdv_registration *r=registration_first(a->registry);r;r=registration_next(r))
    for(unsigned side=0;side<2;side++){
     struct crdv_drain_state *d=&r->drain[side];
     if(!d->active)continue;
     if(d->deadline<due)due=d->deadline;
     if(side==SIR_RDV_DRAIN_LOCAL&&!d->remote_done&&d->next_due&&d->next_due<due)due=d->next_due;
    }
  return due;
}
int crdv_session_up(struct crdv_actor *a, uint64_t sid) {
  if (!a || !sid)
    return EINVAL;
  if (!a->down && a->current_sid == sid)
    return 0;
  if (a->current_sid && (a->messages || a->inflight.ticket || !a->dma_stopped))
    return EBUSY;
  a->current_sid = sid;
  a->down = a->dma_stopped = 0;
  return 0;
}
void crdv_session_down(struct crdv_actor *a, int stopped) {
  if (a) {
    a->down = 1;
    a->dma_stopped |= !!stopped;
    for (struct crdv_message *m = a->messages; m; m = m->next) {
      m->closed = 1;
      if (!m->value.status)
        m->value.status = EIO;
    }
  }
}
static int frame_finish(struct crdv_actor *a, struct crdv_frame *out,
                        int length, uint64_t sid, uint64_t request, unsigned op,
                        struct crdv_message *m, struct crdv_registration *r) {
  if (length < 0)
    return -length;
  uint64_t ticket = serial_next(&a->next_ticket);
  if (!ticket)
    return EOVERFLOW;
  struct cproto_header h = {.magic = CONTROL_PROTO_MAGIC,
                            .version = CONTROL_PROTO_VERSION,
                            .header_len = CONTROL_HEADER_LEN,
                            .kind = CPROTO_CONTROL_EVENT,
                            .payload_len = (uint32_t)length,
                            .session_id = sid,
                            .request_id = request};
  int rc =
      cproto_header_encode(a->inflight.bytes, sizeof(a->inflight.bytes), &h);
  if (rc < 0)
    return -rc;
  a->inflight.ticket = ticket;
  a->inflight.length = CONTROL_HEADER_LEN + (size_t)length;
  a->tx_op = op;
  a->tx_message = m;
  a->tx_registration = r;
  if (r) {
    pthread_mutex_lock(&a->registry->mu);
    r->actor_refs++;
    pthread_mutex_unlock(&a->registry->mu);
  }
  *out = a->inflight;
  return 0;
}
static int source_lane_ready(struct crdv_actor *a, struct crdv_message *m) {
  for (struct crdv_message *p = a->messages; p; p = p->next)
    if (p != m && p->role == SIR_RDV_SOURCE &&
        p->registration == m->registration && !p->offer_complete &&
        !p->released && p->wire.sequence < m->wire.sequence)
      return 0;
  return 1;
}
int crdv_frame_take(struct crdv_actor *a, struct crdv_frame *out) {
  if (!a || !out)
    return EINVAL;
  if (a->inflight.ticket)
    return EBUSY;
  uint8_t *payload = a->inflight.bytes + CONTROL_HEADER_LEN;
  if (a->unmatched_reply) {
    struct rdvp_ack ack = {.message = a->unmatched_wire,
                           .status = RDVP_CANCELLED_UNMATCHED};
    int n = rdvp_ack_encode(payload, CONTROL_PAYLOAD_MAX,
                            CPROTO_OP_RDV_CANCEL_ACK, &ack);
    return frame_finish(a, out, n, a->unmatched_sid, 0,
                        CPROTO_OP_RDV_CANCEL_ACK, NULL, NULL);
  }
  for (unsigned priority = 0; priority < 3; priority++)
    for (struct crdv_message *m = a->messages; m; m = m->next) {
      unsigned op = priority == 0 && m->ack_pending
                        ? (m->ack_opcode ? m->ack_opcode : CPROTO_OP_RDV_ACK)
                    : priority == 1 && m->cancel_pending ? CPROTO_OP_RDV_CANCEL
                    : priority == 2 && m->retired_pending
                        ? CPROTO_OP_RDV_RETIRED
                        : 0;
      if (!op)
        continue;
      int length;
      if (op == CPROTO_OP_RDV_ACK || op == CPROTO_OP_RDV_CANCEL_ACK) {
        struct rdvp_ack ack = {.message = m->wire,
                               .status = m->final_status,
                               .completed_length = m->final_status == RDVP_OK
                                                       ? m->value.length
                                                       : 0};
        length = rdvp_ack_encode(payload, CONTROL_PAYLOAD_MAX, op, &ack);
      } else if (op == CPROTO_OP_RDV_CANCEL) {
        struct rdvp_cancel c = {.message = m->wire,
                                .reason = m->value.status == ETIMEDOUT
                                              ? RDVP_RNR_EXHAUSTED
                                              : RDVP_LOCAL_QP_STOP};
        length = rdvp_cancel_encode(payload, CONTROL_PAYLOAD_MAX, &c);
      } else
        length = rdvp_retired_encode(payload, CONTROL_PAYLOAD_MAX, &m->wire);
      return frame_finish(a, out, length, m->value.id.session_id, 0, op, m,
                          m->registration);
    }
  if (a->down)
    return EAGAIN;
  int drained=drain_frame(a,out,payload);if(drained!=EAGAIN)return drained;
  for(struct crdv_message *m=a->messages;m;m=m->next)
    if(!m->closed && (m->wwi_ready_pending || m->wwi_result_pending)){
      if(m->wire.kind==RDVP_WWI&&m->registration->config.native_wwi&&
         (m->registration->peer_flags&RDVP_CAP_NATIVE_WWI))m->wwi_ready_pending=0;
      if(!m->wwi_ready_pending&&!m->wwi_result_pending)continue;
      unsigned op=m->wwi_ready_pending?CPROTO_OP_RDV_WWI_READY:CPROTO_OP_RDV_WWI_RESULT;
      struct rdvp_ack ack={.message=m->wire,
        .status=op==CPROTO_OP_RDV_WWI_READY?RDVP_OK:m->wwi_result_status,
        .completed_length=op==CPROTO_OP_RDV_WWI_RESULT && m->wwi_result_status==RDVP_OK?m->value.length:0};
      int n=rdvp_ack_encode(payload,CONTROL_PAYLOAD_MAX,op,&ack);
      return frame_finish(a,out,n,m->value.id.session_id,0,op,m,m->registration);
    }
  for (struct crdv_registration *r = registration_first(a->registry); r;
       r = registration_next(r))
    if (r->caps_ack_pending) {
      struct rdvp_caps caps = {.sender = r->binding.peer,
                               .receiver = r->binding.local,
                               .source_sge_limit = r->peer_sge_limit,.flags=r->peer_flags};
      int length = rdvp_caps_ack_encode(payload, CONTROL_PAYLOAD_MAX, &caps);
      int result = frame_finish(a, out, length, r->binding.session_id, 0,
                                CPROTO_OP_RDV_CAPS_ACK, NULL, r);
      registration_put(r);
      return result;
    }
  for (struct crdv_registration *r = registration_first(a->registry); r;
       r = registration_next(r))
    if (!__atomic_load_n(&r->closed, __ATOMIC_ACQUIRE) && !r->caps_acked &&
        (!r->caps_sent || a->now >= r->caps_due) &&
        r->binding.state == SIR_APP_QP_BOUND) {
      struct rdvp_caps caps = {.sender = r->binding.local,
                               .receiver = r->binding.peer,
                               .source_sge_limit =
                                   r->config.caps.source_sge_limit,.flags=r->config.native_wwi?RDVP_CAP_NATIVE_WWI:0};
      int length = rdvp_caps_encode(payload, CONTROL_PAYLOAD_MAX, &caps);
      int result = frame_finish(a, out, length, r->binding.session_id, 0,
                                CPROTO_OP_RDV_CAPS, NULL, r);
      registration_put(r);
      return result;
    }
  for (struct crdv_message *m = a->messages; m; m = m->next)
    if (m->wait_pending) {
      struct rdvp_wait w = {
          .message = m->wire,
          .min_rnr_timer =
              (__atomic_load_n(&m->registration->rnr_attrs, __ATOMIC_ACQUIRE) >>
               8)};
      int length = rdvp_wait_encode(payload, CONTROL_PAYLOAD_MAX, &w);
      return frame_finish(a, out, length, m->value.id.session_id, m->challenge,
                          CPROTO_OP_RDV_WAIT, m, m->registration);
    }
  for (struct crdv_message *m = a->messages; m; m = m->next)
    if (m->role == SIR_RDV_SOURCE && m->offer_pending && !m->closed &&
        m->resource &&
        (!m->registration->source_failed_sequence ||
         m->wire.sequence < m->registration->source_failed_sequence) &&
        source_lane_ready(a, m)) {
      struct crdv_registration *r = m->registration;
      if(m->wire.kind==RDVP_WWI&&r->config.native_wwi&&(r->peer_flags&RDVP_CAP_NATIVE_WWI))continue;
      struct rdv_bridge_counts c = {0};
      rdv_bridge_get_counts(m->resource, &c);
      if (!c.ready || !r->caps_acked || !r->peer_caps ||
          !authorized(a, r, &m->wire, 1, m->value.id.session_id))
        continue;
      uint64_t offset = (uint64_t)m->offer_fragment * RDVP_SEGMENTS_PER_FRAME;
      unsigned entries = m->segment_count > (uint32_t)offset
                             ? m->segment_count - (uint32_t)offset
                             : 0;
      if (entries > RDVP_SEGMENTS_PER_FRAME)
        entries = RDVP_SEGMENTS_PER_FRAME;
      uint64_t message_offset = 0;
      for (uint64_t i = 0; i < offset; i++)
        message_offset += m->segments[i].length;
      struct rdvp_offer offer = {
          .message = m->wire,
          .imm_be = m->value.imm_be,
          .total_segments = m->segment_count,
          .fragment_count = m->segment_count
                                ? (uint32_t)(((uint64_t)m->segment_count +
                                              RDVP_SEGMENTS_PER_FRAME - 1) /
                                             RDVP_SEGMENTS_PER_FRAME)
                                : 1,
          .fragment_index = m->offer_fragment,
          .segment_offset = (uint32_t)offset,
          .entry_count = entries,
          .message_offset = message_offset};
      int length = rdvp_offer_encode(payload, CONTROL_PAYLOAD_MAX, &offer,
                                     entries ? m->segments + offset : NULL);
      a->tx_fragment = m->offer_fragment;
      return frame_finish(a, out, length, m->value.id.session_id,
                          m->offer_request, CPROTO_OP_RDV_OFFER, m, r);
    }
  return EAGAIN;
}
int crdv_tx_result(struct crdv_actor *a, uint64_t ticket, int result) {
  if (!a || !ticket || ticket != a->inflight.ticket)
    return ESTALE;
  struct crdv_message *m = a->tx_message;
  struct crdv_registration *tx_registration = a->tx_registration;
  unsigned op = a->tx_op;
  a->inflight.ticket = 0;
  a->tx_message = NULL;
  a->tx_registration = NULL;
  if(op==CPROTO_OP_RDV_DRAIN_REQUEST||op==CPROTO_OP_RDV_DRAIN_ACK)
    return drain_tx_result(a,tx_registration,op,result);
  if (op != CPROTO_OP_RDV_CAPS && op != CPROTO_OP_RDV_CAPS_ACK)
    registration_put(tx_registration);
  if (result) {
    if (op == CPROTO_OP_RDV_CAPS || op == CPROTO_OP_RDV_CAPS_ACK)
      registration_put(tx_registration);
    if (error_value(result) != EAGAIN) {
      crdv_session_down(a, 0);
      return error_value(result);
    }
    return EAGAIN;
  }
  if (op == CPROTO_OP_RDV_CAPS_ACK) {
    tx_registration->caps_ack_pending = 0;
    registration_put(tx_registration);
    return 0;
  }
  if (op == CPROTO_OP_RDV_CAPS) { /* Never mark a newer revision sent by an old
                                     frame. */
    struct rdvp_caps caps;
    if (!rdvp_caps_decode(a->inflight.bytes + CONTROL_HEADER_LEN,
                          (uint32_t)a->inflight.length - CONTROL_HEADER_LEN,
                          &caps)) {
      struct crdv_registration *r = tx_registration;
      struct sir_app_qp_snapshot bound = {0};
      if (!current(a, r, &bound) &&
          endpoint_equal(&bound.local, &caps.sender) &&
          endpoint_equal(&bound.peer, &caps.receiver)) {
        r->caps_sent = 1;
        r->caps_due = a->now + CRDV_RETRANSMIT_US;
      }
    }
    registration_put(tx_registration);
    return 0;
  }
  if (!m && op == CPROTO_OP_RDV_CANCEL_ACK) {
    a->unmatched_reply = 0;
    return 0;
  }
  if (!m)
    return EPROTO;
  if (op == CPROTO_OP_RDV_OFFER) {
    if (!m->offered) {
      int rc = rdv_bridge_mark_exposed(m->resource);
      if (rc)
        return rc;
      m->offered = 1;
      m->registration->pending_stats.source_messages_offered++;
    }else if(m->source_prepared&&!m->offer_complete&&!m->offer_fragment){
      m->registration->pending_stats.source_messages_offered++;
    }
    m->registration->pending_stats.source_offers_posted++;
    if(m->wire.kind==RDVP_WWI)m->registration->pending_stats.wwi_offers_posted++;
    m->offer_fragment++;
    uint64_t fragments =
        m->segment_count
            ? ((uint64_t)m->segment_count + RDVP_SEGMENTS_PER_FRAME - 1) /
                  RDVP_SEGMENTS_PER_FRAME
            : 1;
    if (m->offer_fragment >= fragments) {
      m->offer_pending = 0;
      m->offer_complete = 1;
      m->offer_fragment = 0; /* Query lost replies with the same attempt, never
                                consume new RNR credit. */
      m->next_due = a->now + CRDV_RETRANSMIT_US;
    }
  } else if (op == CPROTO_OP_RDV_WWI_READY){
    m->registration->pending_stats.wwi_ready_posted++;
    m->wwi_ready_pending=0;
  }
  else if (op == CPROTO_OP_RDV_WWI_RESULT){
    m->wwi_result_pending=0;m->next_due=a->now+CRDV_RETRANSMIT_US;
  } else if (op == CPROTO_OP_RDV_ACK || op == CPROTO_OP_RDV_CANCEL_ACK)
    m->ack_pending = 0;
  else if (op == CPROTO_OP_RDV_WAIT)
    m->wait_pending = 0;
  else if (op == CPROTO_OP_RDV_CANCEL) {
    m->cancel_pending = 0;
    m->next_due = a->now + CRDV_RETRANSMIT_US;
  } else if (op == CPROTO_OP_RDV_RETIRED) {
    m->retired_pending = 0;
    message_free(a, m);
  }
  return 0;
}

int crdv_receive(struct crdv_actor *a, const void *frame, size_t length,
                 uint64_t now, enum crdv_rx_outcome *out) {
  if (!a || !out || !frame || length < CONTROL_HEADER_LEN ||
      length > CONTROL_SLOT_CAPACITY)
    return EINVAL;
  *out = 0;
  struct cproto_header h;
  int rc = cproto_header_decode(frame, (uint32_t)length, &h);
  if (rc)
    return error_value(rc);
  if (!a->current_sid || h.session_id != a->current_sid)
    return ESTALE;
  rc = receive_inner(a, frame, length, now);
  if (rc == ESTALE || rc == ENOENT) {
    *out = CRDV_RX_IGNORED;
    return 0;
  }
  if (rc == EAGAIN || rc == ENOMEM) {
    uint32_t op = 0;
    const uint8_t *payload = (const uint8_t *)frame + CONTROL_HEADER_LEN;
    if (cproto_op_get(payload, h.payload_len, &op) ||
        (op != CPROTO_OP_RDV_OFFER && op != CPROTO_OP_RDV_CANCEL && op != CPROTO_OP_RDV_DRAIN_REQUEST))
      return rc;
    *out = CRDV_RX_RETRY;
    return 0;
  }
  if (rc)
    return rc;
  *out = CRDV_RX_ACCEPTED;
  return 0;
}

#include "control_app_rdv_drain.inc"
