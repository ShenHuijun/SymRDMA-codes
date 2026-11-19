/* SPDX-License-Identifier: GPL-2.0 */

#define _GNU_SOURCE
#include <errno.h>
#include <dlfcn.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/eventfd.h>
#include "control_app_rdv.h"
#include <infiniband/verbs.h>

#include "sir.h"
#include "control_log.h"
#include "control_futex.h"
#include "control_reactor.h"
#include "control_runtime.h"
#include "control_app_qp.h"
#include "control_trace.h"

#define SIR_TEST_DEADLINE_MIN_US   10000
#define SIR_TEST_DEADLINE_MAX_US 5000000
#define SIR_TEST_RNR_HOLD_MAX_US 1000000

static pthread_mutex_t g_sir_mu = PTHREAD_MUTEX_INITIALIZER;
static struct ctrl_reactor *g_r;
static struct crt_cfg g_cfg;
static int g_cfg_valid;
static int g_enabled;

static int g_cfg_knob_bad;

/* RDV_METADATA_SERVICE_BEGIN: pure metadata, independent of g_sir_mu and NPR. */
struct sir_rdv_wake_link {
 int fd;
 int capability;
 struct crdv_registry *registry;
 unsigned refs;
 int detached;
};
static pthread_mutex_t g_rdv_meta_mu=PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t g_rdv_wake_mu=PTHREAD_MUTEX_INITIALIZER;
static struct crdv_registry *g_rdv_registry;
static unsigned g_rdv_users;
static struct sir_rdv_wake_link *g_rdv_active;
static struct sir_rdv_wake_link *g_rdv_runtime_link;
/* A captured link owns its FD until both runtime and callbacks have left.
 * In particular detach cannot close/reuse it underneath an unlocked write. */
static void sir_rdv_link_put(struct sir_rdv_wake_link *l)
{
 int dispose;
 pthread_mutex_lock(&g_rdv_wake_mu);
 dispose=!--l->refs;
 pthread_mutex_unlock(&g_rdv_wake_mu);
 if(dispose){close(l->fd);free(l);}
}
static void sir_rdv_wake(void *unused)
{
 struct sir_rdv_wake_link *l;uint64_t one=1;ssize_t n;
 (void)unused;
 pthread_mutex_lock(&g_rdv_wake_mu);
 l=g_rdv_active;if(l)++l->refs;
 pthread_mutex_unlock(&g_rdv_wake_mu);
 if(!l)return;
 do{n=write(l->fd,&one,sizeof(one));}while(n<0&&errno==EINTR);
 /* EAGAIN means an unread wake is already pending. Never block a producer. */
 sir_rdv_link_put(l);
}
void sir_app_rdv_wake(void *unused)
{sir_rdv_wake(unused);}
int sir_app_rdv_capability(void)
{
 pthread_mutex_lock(&g_rdv_wake_mu);
 int status=g_rdv_active?g_rdv_active->capability:EAGAIN;
 pthread_mutex_unlock(&g_rdv_wake_mu);return status;
}
static void sir_rdv_capability_publish(void *opaque,int status)
{
 struct sir_rdv_wake_link *l=opaque;struct crdv_registry *notify=NULL;
 if(status&&status!=EAGAIN&&status!=EOPNOTSUPP)return;
 pthread_mutex_lock(&g_rdv_wake_mu);
 if(l&&l==g_rdv_active&&l->capability!=status){l->capability=status;notify=l->registry;}
 pthread_mutex_unlock(&g_rdv_wake_mu);
 /* The calling runtime retains its link+registry until joined. No registry
  * lock, wake lock or NPR gate crosses consumer callbacks. */
 if(notify)crdv_registry_notify_apps(notify);
}
static int sir_rdv_registry_get(struct crdv_registry **out)
{
 int rc=0;
 pthread_mutex_lock(&g_rdv_meta_mu);
 if(!g_rdv_registry){
  struct crdv_registry_config cfg={.wake_actor=sir_rdv_wake};
  rc=crdv_registry_new(&cfg,&g_rdv_registry);
 }
 if(!rc){++g_rdv_users;*out=g_rdv_registry;}
 pthread_mutex_unlock(&g_rdv_meta_mu);
 return rc;
}
static void sir_rdv_registry_put(void)
{
 pthread_mutex_lock(&g_rdv_meta_mu);
 if(g_rdv_users)--g_rdv_users;
 if(!g_rdv_users&&g_rdv_registry&&!crdv_registry_free(g_rdv_registry))
  g_rdv_registry=NULL;
 pthread_mutex_unlock(&g_rdv_meta_mu);
}
int sir_app_rdv_register(const struct crdv_registration_config *cfg,
                         struct crdv_registration **out)
{
 struct crdv_registry *reg;int rc;
 if(!cfg||!out)return EINVAL;
 rc=sir_rdv_registry_get(&reg);if(rc)return rc;
 /* No service lock crosses registry calls/callbacks. */
 rc=crdv_register(reg,cfg,out);
 sir_rdv_registry_put();return rc;
}
int sir_app_rdv_registration_free(struct crdv_registration *registration)
{
 struct crdv_registry *reg;int rc;
 if(!registration)return 0;
 /* The live registration itself prevents registry_free; take an additional
  * service ref before retiring that last producer. */
 rc=sir_rdv_registry_get(&reg);if(rc)return rc;
 (void)reg;rc=crdv_registration_free(registration);
 sir_rdv_registry_put();return rc;
}
static int sir_rdv_runtime_acquire(struct crt_cfg *cfg)
{
 struct sir_rdv_wake_link *l;struct crdv_registry *reg;int rc;
 l=calloc(1,sizeof(*l));if(!l)return ENOMEM;
 l->fd=eventfd(0,EFD_CLOEXEC|EFD_NONBLOCK);
 if(l->fd<0){rc=errno;free(l);return rc;}
 l->refs=1;l->capability=EAGAIN;
 rc=sir_rdv_registry_get(&reg);
 if(rc){close(l->fd);free(l);return rc;}
 pthread_mutex_lock(&g_rdv_wake_mu);
 l->registry=reg;g_rdv_active=l;g_rdv_runtime_link=l;
 pthread_mutex_unlock(&g_rdv_wake_mu);
 cfg->app_rdv_registry=reg;cfg->app_rdv_wake_fd=l->fd;
 cfg->app_rdv_capability_publish=sir_rdv_capability_publish;cfg->app_rdv_service_opaque=l;
 return 0;
}
static void sir_rdv_runtime_detach(void)
{
 pthread_mutex_lock(&g_rdv_wake_mu);
 if(g_rdv_active==g_rdv_runtime_link)g_rdv_active=NULL;
 if(g_rdv_runtime_link)g_rdv_runtime_link->detached=1;
 pthread_mutex_unlock(&g_rdv_wake_mu);
}
static void sir_rdv_runtime_release(struct crt_cfg *cfg)
{
 struct sir_rdv_wake_link *l=g_rdv_runtime_link;
 if(!l)return;
 sir_rdv_runtime_detach();g_rdv_runtime_link=NULL;
 cfg->app_rdv_registry=NULL;cfg->app_rdv_wake_fd=-1;
 cfg->app_rdv_capability_publish=NULL;cfg->app_rdv_service_opaque=NULL;
 sir_rdv_link_put(l);sir_rdv_registry_put();
}
static void sir_rdv_producers_close(void)
{
 struct crdv_registry *reg;
 pthread_mutex_lock(&g_rdv_meta_mu);
 reg=g_rdv_registry;if(reg)++g_rdv_users;
 pthread_mutex_unlock(&g_rdv_meta_mu);
 if(reg){crdv_registry_close_producers(reg);sir_rdv_registry_put();}
}
/* RDV_METADATA_SERVICE_END */

int64_t sir_op_trace_mark(void)
{
	return ctrace_on() ? crt_now_ns() : 0;
}

void sir_op_trace_begin(void)
{
	int64_t hint = crt_now_ns() +
			(int64_t)CTRL_OP_HOT_HORIZON_US * 1000;

	(void)ctrace_op_begin();

	ctrl_reactor_op_hint(g_r, hint);
}

void sir_op_trace_retry(int64_t t_mark)
{
	ctrace_op_retry(t_mark);
}

static int sir_env_int(const char *name, int dflt)
{
	const char *e = getenv(name);

	return e && e[0] ? atoi(e) : dflt;
}

static void sir_cfg_capture(struct ibv_context *ctx, struct ibv_pd *pd,
			    const char *key, int sym_fd)
{
	const char *envdir, *tcp, *k;

	memset(&g_cfg, 0, sizeof(g_cfg));
	g_cfg.ctx = ctx;
	g_cfg.pd = pd;
	g_cfg.sym_fd = sym_fd;
	k = (key && key[0]) ? key : getenv("SYMRDMA_PEER");
	if (k && k[0]) {
		snprintf(g_cfg.key, sizeof(g_cfg.key), "%s", k);
		g_enabled = 1;
	}
	envdir = getenv("SYMRDMA_SIR_DIR");
	snprintf(g_cfg.dir, sizeof(g_cfg.dir), "%s",
		 envdir && envdir[0] ? envdir : SIR_DIR_DEFAULT);
	tcp = getenv("SYMRDMA_SIR_TCP");
	if (tcp && tcp[0]) {
		const char *colon = strrchr(tcp, ':');

		if (colon && colon != tcp) {
			g_cfg.tcp_port = atoi(colon + 1);
			if (!strncmp(tcp, "listen:", 7)) {
				g_cfg.rdv_kind = CRDV_TCP_LISTEN;
				g_enabled = 1;
				crt_log("rendezvous mode: TCP listen:%d (role a)",
					 g_cfg.tcp_port);
			} else if (g_cfg.tcp_port > 0) {
				size_t hl = (size_t)(colon - tcp);

				if (hl >= sizeof(g_cfg.tcp_host))
					hl = sizeof(g_cfg.tcp_host) - 1;
				memcpy(g_cfg.tcp_host, tcp, hl);
				g_cfg.tcp_host[hl] = 0;
				g_cfg.rdv_kind = CRDV_TCP_CONNECT;
				g_enabled = 1;
				{
					const unsigned char *hu =
						(const unsigned char *)
						g_cfg.tcp_host;

					crt_log("rendezvous mode: TCP port=%d "
						 "host_hex=%02x%02x%02x%02x"
						 "%02x%02x%02x%02x (role b)",
						 g_cfg.tcp_port,
						 hu[0], hu[1], hu[2], hu[3],
						 hu[4], hu[5], hu[6], hu[7]);
				}
			}
		}
	}
	g_cfg.sgid_index = sir_env_int("SYMRDMA_SIR_GID", 0);
	{
		int v = sir_env_int("SYMRDMA_SIR_INLINE_MAX", SIR_INLINE_MAX);

		if (v < 0)
			v = 0;
		if (v > (int)SIR_INLINE_LIMIT)
			v = (int)SIR_INLINE_LIMIT;
		g_cfg.inline_max = v;
	}
	{
		const char *p = getenv("SYMRDMA_CTRL_RESOURCE_DEBUG");

		g_cfg.poison_debug = p && p[0] && p[0] != '0';
	}
	g_cfg.workers = CONTROL_EXEC_WORKERS_MAX;

	{
		const char *p = getenv("SYMRDMA_CTRL_TEST_DEADLINE_US");
		int v = (p && p[0]) ? atoi(p) : 0;

		if (v) {
			int c = v;

			if (c < SIR_TEST_DEADLINE_MIN_US)
				c = SIR_TEST_DEADLINE_MIN_US;
			if (c > SIR_TEST_DEADLINE_MAX_US)
				c = SIR_TEST_DEADLINE_MAX_US;
			g_cfg.test_deadline_us = (uint32_t)c;
			crt_log("test injection: deadline_us=%u clamp=%d "
				 "(test/diagnostic only, production default 5s)",
				 g_cfg.test_deadline_us, c != v);
		}
	}

	{
		const char *p = getenv("SYMRDMA_CTRL_TEST_RD_ATOM_CAP");
		int v = (p && p[0]) ? atoi(p) : 0;

		if (v) {
			if (v < 1 || v > (int)CONTROL_REVERSE_WINDOW_MAX) {
				crt_log("invalid test injection: rd_atom_cap=%d out of range "
					 "[1,%u] — fail-closed (refusing to start)",
					 v, CONTROL_REVERSE_WINDOW_MAX);
				g_cfg_knob_bad = 1;
			} else {
				g_cfg.test_rd_atom_cap = (uint8_t)v;
				crt_log("test injection: rd_atom_cap=%d "
					 "(test/diagnostic only, production default 0)",
					 g_cfg.test_rd_atom_cap);
			}
		}
	}

	{
		const char *p = getenv("SYMRDMA_CTRL_TEST_RNR_HOLD_US");
		int v = (p && p[0]) ? atoi(p) : 0;

		if (v) {
			int c = v;

			if (c < 0)
				c = 0;
			if (c > SIR_TEST_RNR_HOLD_MAX_US)
				c = SIR_TEST_RNR_HOLD_MAX_US;
			g_cfg.test_rnr_hold_us = (uint32_t)c;
			crt_log("test injection: rnr_hold_us=%u clamp=%d "
				 "(test/diagnostic only, production default 0)",
				 g_cfg.test_rnr_hold_us, c != v);
		}
	}
	g_cfg_valid = 1;
}

/* The application may release a PD after its own children are gone while
 * the shared control service still needs the native PD. Transfer that native
 * handle to one internal owner; the context guard survives failed cleanup. */
static struct ibv_pd *g_service_owned_pd;
static struct ibv_context *g_service_owned_ctx;
static struct ctrans_runtime_guard *g_service_pd_guard;
int sir_take_pd(struct ibv_pd *pd)
{
 int rc=0;
 pthread_mutex_lock(&g_sir_mu);
 if(g_r&&g_r->cfg.pd==pd){
  if(g_service_owned_pd){rc=g_service_owned_pd==pd?1:-EBUSY;}
  else {
   rc=ctrans_runtime_guard_acquire(g_r->cfg.ctx,pd,&g_service_pd_guard);
   if(!rc){g_service_owned_pd=pd;g_service_owned_ctx=g_r->cfg.ctx;rc=1;}
  }
 }
 pthread_mutex_unlock(&g_sir_mu);return rc;
}
static int sir_owned_pd_release_locked(void)
{
 if(!g_service_owned_pd)return 0;
 if(g_r)return EBUSY;
 int (*release)(struct ibv_pd *)=dlvsym(RTLD_NEXT,"ibv_dealloc_pd","IBVERBS_1.1");
 if(!release)return ENOSYS;
 struct ibv_pd *pd=g_service_owned_pd;
 int rc=release(pd);if(rc)return rc>0?rc:(errno?errno:EIO);
 if(g_cfg.pd==pd)g_cfg.pd=NULL;
 g_service_owned_pd=NULL;g_service_owned_ctx=NULL;
 ctrans_runtime_guard_release(g_service_pd_guard);g_service_pd_guard=NULL;
 return 0;
}
void sir_pd_closed(const struct ibv_pd *pd)
{
 pthread_mutex_lock(&g_sir_mu);
 if(g_cfg.pd==pd){
  g_cfg.pd=g_r?g_r->cfg.pd:NULL;
  if(g_r)g_cfg.ctx=g_r->cfg.ctx;
 }
 pthread_mutex_unlock(&g_sir_mu);
}
void sir_context_closed(const struct ibv_context *ctx)
{
 pthread_mutex_lock(&g_sir_mu);
 if(g_cfg.ctx==ctx){g_cfg.ctx=g_r?g_r->cfg.ctx:NULL;g_cfg.pd=g_r?g_r->cfg.pd:NULL;}
 pthread_mutex_unlock(&g_sir_mu);
}

static int sir_start_locked(void)
{
	int rc;

	if (g_r)
		return 0;
	int pd_rc=sir_owned_pd_release_locked();
	if(pd_rc){errno=pd_rc;return -pd_rc;}
	if (!g_cfg_valid || !g_enabled || !g_cfg.ctx || !g_cfg.pd)
		return -1;
	if (g_cfg_knob_bad) {
		crt_log("invalid test injection (see above) — fail-closed: refusing to start");
		return -EINVAL;
	}
	rc=sir_rdv_runtime_acquire(&g_cfg);
	if(rc){errno=rc;return -1;}
	g_r = crt_reactor_new(&g_cfg);
	if (!g_r){sir_rdv_runtime_release(&g_cfg);return -1;}
	rc=cbind_actor_attach(g_r);
	if(rc){if(crt_reactor_stop(g_r)==0&&crt_reactor_free(g_r)==0){g_r=NULL;sir_rdv_runtime_release(&g_cfg);}return rc;}
	rc = crt_reactor_start(g_r);
	if (rc) {
		crt_log("reactor start failed rc=%d", rc);
		if (crt_reactor_stop(g_r) == 0) {
			if(crt_reactor_free(g_r)==0){g_r=NULL;sir_rdv_runtime_release(&g_cfg);}
		}
		return rc;
	}
	return 0;
}

static int sir_ensure_ready(int wait_ms)
{
	int rc;

	pthread_mutex_lock(&g_sir_mu);
	rc = sir_start_locked();
	pthread_mutex_unlock(&g_sir_mu);
	if (rc)
		return rc;
	if (ctrl_session_ready(g_r))
		return 0;
	rc = ctrl_session_wait(g_r, (uint32_t)wait_ms);
	if (rc) {
		errno = rc == -ETIMEDOUT ? ETIMEDOUT : ENOTCONN;
		return -1;
	}
	return 0;
}

int sir_init(struct ibv_context *ctx, struct ibv_pd *pd,
	     const char *key, int sym_fd)
{
	pthread_mutex_lock(&g_sir_mu);
	if (!g_cfg_valid)
		sir_cfg_capture(ctx, pd, key, sym_fd);
	else {
		if (ctx)
			g_cfg.ctx = ctx;
		if (pd)
			g_cfg.pd = pd;
		if (sym_fd >= 0) {
			g_cfg.sym_fd = sym_fd;

			if (g_r)
				crt_reactor_bind_sym_fd(g_r, sym_fd);
		}
	}
	pthread_mutex_unlock(&g_sir_mu);
	return 0;
}

int sir_export_add(const struct sir_export *e)
{
	struct creg_owner_export m;
	struct crpc_desc d;
	int mk = 0, rc;

	if (!e || (e->data_rkey == 0 && e->write_rkey == 0)) {
		errno = EINVAL;
		return -1;
	}
	pthread_mutex_lock(&g_sir_mu);
	rc = sir_start_locked();
	pthread_mutex_unlock(&g_sir_mu);
	if (rc) {
		errno = ENOTCONN;
		return -1;
	}
	memset(&m, 0, sizeof(m));
	m.app_rkey = e->app_rkey;
	m.app_access = e->app_access;
	m.data_rkey   = e->data_rkey;
	m.write_rkey  = e->write_rkey;
	m.v_rkey      = e->v_rkey;
	m.addr        = e->addr;
	m.len         = e->len;
	m.v_addr      = e->v_addr;
	m.mr_id       = e->mr_id;
	m.lkey        = e->lkey;
	rc = creg_owner_export_publish(&m, &mk);
	if (rc) {
		errno = -rc;
		crt_log("export failed rkey=0x%x wkey=0x%x → %d (fail-closed)",
			 e->data_rkey, e->write_rkey, rc);
		return -1;
	}
	memset(&d, 0, sizeof(d));
	d.op = CRPC_OP_PUBLISH_SNAPSHOT;
	(void)ctrl_submit(g_r, &d, NULL);
	switch (mk) {
	case 1:
		crt_log("export merged wkey=0x%x (folded into same-range data export)",
			 e->write_rkey);
		break;
	case 2:
		crt_log("export reverse-merged rkey=0x%x (folded into same-range write export)",
			 e->data_rkey);
		break;
	default:
		crt_log("export rkey=0x%x wkey=0x%x addr=%p len=%llu mr_id=%d",
			 e->data_rkey, e->write_rkey,
			 (void *)(uintptr_t)e->addr,
			 (unsigned long long)e->len, e->mr_id);
	}
	return 0;
}

void sir_export_del(uint32_t data_rkey)
{
	struct crpc_desc d;
	int rc;

	rc = creg_owner_export_close(data_rkey, CONTROL_DRAIN_TIMEOUT_MS);
	memset(&d, 0, sizeof(d));
	d.op = CRPC_OP_PUBLISH_SNAPSHOT;
	if (g_r)
		(void)ctrl_submit(g_r, &d, NULL);

	if (rc)
		crt_log("export revoked rkey=0x%x → %d", data_rkey, rc);
}

void sir_export_del_wkey(uint32_t write_rkey)
{
	struct crpc_desc d;
	int rc;

	if (!write_rkey)
		return;
	rc = creg_owner_export_unpublish_wkey(write_rkey,
					      CONTROL_DRAIN_TIMEOUT_MS);
	memset(&d, 0, sizeof(d));
	d.op = CRPC_OP_PUBLISH_SNAPSHOT;
	if (g_r)
		(void)ctrl_submit(g_r, &d, NULL);

	if (rc < 0)
		crt_log("export wkey revoked 0x%x → %d", write_rkey, rc);
}

int sir_remote_lookup_cached(uint32_t data_rkey, struct sir_export *out)
{
	struct cpeer_ent pe;

	if (out)
		memset(out, 0, sizeof(*out));
 /* Runtime lifetime is protected by the caller's application API gate.
  * This cache-only helper must not initiate or wait for a control session. */
 if(!g_r||!ctrl_session_ready(g_r)){errno=ENOTCONN;return -1;}

	if (cpeer_lookup(ctrl_peer_registry(g_r), data_rkey, &pe)) {
		errno = ENXIO;
		return -1;
	}
	if (out) {
		out->app_rkey = pe.app_rkey;
		out->app_access = pe.app_access;
		out->data_rkey  = pe.data_rkey;
		out->write_rkey = pe.write_rkey;
		out->addr       = pe.addr;
		out->len        = pe.len;
		out->v_rkey     = pe.v_rkey;
		out->v_addr     = pe.v_addr;
		out->mr_id      = -1;
		out->lkey       = 0;
	}
	return 0;
}

int sir_remote_lookup(uint32_t key,struct sir_export *out)
{
 if(out)memset(out,0,sizeof(*out));
 if(sir_ensure_ready(CSESS_CONNECT_TIMEOUT_MS))return -1;
 return sir_remote_lookup_cached(key,out);
}

int sir_ensure_start(void)
{
	pthread_mutex_lock(&g_sir_mu);
	{
		int rc = sir_start_locked();

		pthread_mutex_unlock(&g_sir_mu);
		return rc ? -1 : 0;
	}
}

#define SIR_CALLER_SPIN_MAX    200000
#define SIR_CALLER_SPIN_NS     30000LL

static inline void sir_cpu_relax(void)
{
#if defined(__x86_64__) || defined(__i386__)
	__builtin_ia32_pause();
#else
	__asm__ __volatile__("" ::: "memory");
#endif
}

static int sir_call(const struct crpc_desc *d, struct crpc_reply *out)
{
	struct crpc_desc dd;
	struct crpc_caller *c;
	int64_t deadline;
	int64_t pv_t_run = 0, pv_t_ver = 0;
	int has_reverse, ret = -1, rc;

	if (sir_ensure_ready(CSESS_CONNECT_TIMEOUT_MS))
		return -1;

	deadline = d->deadline_us ? (int64_t)d->deadline_us :
		   crt_now_us() + (int64_t)(g_cfg.test_deadline_us ?
					     g_cfg.test_deadline_us :
					     CTRL_RPC_DEADLINE_US);
	dd = *d;
	dd.deadline_us = (uint64_t)deadline;
	c = crpc_caller_new();
	if (!c) {
		errno = ENOMEM;
		return -1;
	}

	c->refs = 2;

	if (d->op == CRPC_OP_REPAIR_INLINE || d->op == CRPC_OP_REPAIR_REVERSE ||
	    d->op == CRPC_OP_REPAIR_BATCH)
		c->trace_op_ns = ctrace_op_take();
	else
		c->trace_op_ns = 0;
	rc = ctrl_submit(g_r, &dd, c);
	if (rc) {
		c->refs = 1;
		crpc_caller_put(c);
		errno = rc < 0 ? -rc : EBUSY;
		return -1;
	}
	has_reverse = (d->op == CRPC_OP_REPAIR_REVERSE ||
		       d->op == CRPC_OP_REPAIR_BATCH);

	crpc_caller_wait_enter(c);
	{

		int64_t spin_until = crt_futex_now_ns() + SIR_CALLER_SPIN_NS;
		long spins = 0;

		while (!crpc_caller_done_p(c) &&
		       spins < (long)SIR_CALLER_SPIN_MAX &&
		       crt_futex_now_ns() < spin_until) {
			spins++;
			sir_cpu_relax();
		}
		if (ctrace_on())
			ctrace_stat_inc(CTRACE_STAT_CALLER_SPIN, (uint64_t)spins);
	}
	for (;;) {
		int wrc;

		if (crpc_caller_done_p(c))
			break;
		if (has_reverse && deadline <= crt_now_us()) {
			wrc = crpc_caller_wait(c, 0);
		} else {
			int64_t dl_ns = (int64_t)deadline * 1000LL;

			wrc = crpc_caller_wait(c, dl_ns);
		}
		if (wrc == -ETIMEDOUT) {
			if (has_reverse)
				continue;
			__atomic_store_n(&c->abandoned, 1, __ATOMIC_RELEASE);
			errno = ETIMEDOUT;
			goto out_release;
		}
		if (wrc && wrc != -EINTR) {
			if (has_reverse)
				continue;
			__atomic_store_n(&c->abandoned, 1, __ATOMIC_RELEASE);
			errno = -wrc;
			goto out_release;
		}
	}
out_release:
	crpc_caller_wait_exit(c);
	if (ctrace_sub_on()) {
		int64_t t_run = ctrace_ts();

		if (t_run && c->trace_wake_ns && t_run > c->trace_wake_ns)
			ctrace_at(CTRACE_PHASE_PV_WAKE_RUN,
				  c->trace_session_id, c->trace_request_id, 0,
				  (uint16_t)(c->err ? (uint16_t)(-c->err) :
					     (uint16_t)(c->reply.status &
							0xffffu)),
				  c->trace_wake_ns,
				  (uint64_t)(t_run - c->trace_wake_ns));
		pv_t_run = t_run;
	}
	if (c->err) {
		errno = -c->err;
	} else if (c->reply.status) {
		errno = (int)c->reply.status;
	} else {
		ret = 0;
		if (out)
			*out = c->reply;
	}
	pv_t_ver = ctrace_sub_on() ? ctrace_ts() : 0;

	if (c->trace_wake_ns) {
		uint16_t st = c->err ? (uint16_t)(-c->err) :
			      (uint16_t)(c->reply.status & 0xffffu);
		int64_t t_end = ctrace_ts();

		if (pv_t_run && pv_t_ver && pv_t_ver > pv_t_run)
			ctrace_at(CTRACE_PHASE_PV_VERIFY,
				  c->trace_session_id, c->trace_request_id, 0,
				  st, pv_t_run,
				  (uint64_t)(pv_t_ver - pv_t_run));
		if (pv_t_ver && t_end && t_end > pv_t_ver)
			ctrace_at(CTRACE_PHASE_PV_RETURN,
				  c->trace_session_id, c->trace_request_id, 0,
				  st, pv_t_ver, (uint64_t)(t_end - pv_t_ver));
		ctrace_at(CTRACE_PHASE_POST_VERIFY, c->trace_session_id,
			  c->trace_request_id, 0, st, c->trace_wake_ns,
			  t_end ? (uint64_t)(t_end - c->trace_wake_ns) : 0);

		if (ctrace_on() &&
		    (d->op == CRPC_OP_REPAIR_INLINE ||
		     d->op == CRPC_OP_REPAIR_REVERSE ||
		     d->op == CRPC_OP_REPAIR_BATCH))
			ctrace_op_host(c->trace_session_id, c->trace_request_id,
					crt_now_ns());
	}
	crpc_caller_put(c);
	return ret;
}

int sir_remote_lookup_authoritative(uint32_t key,struct sir_export *out)
{
 struct crpc_desc d={0};struct crpc_reply reply;struct cproto_export_entry entry;
 const char *peer,*tcp;int disabled;
 if(out)memset(out,0,sizeof(*out));
 if(!key){errno=EINVAL;return -1;}
 pthread_mutex_lock(&g_sir_mu);
 peer=getenv("SYMRDMA_PEER");tcp=getenv("SYMRDMA_SIR_TCP");
 disabled=!g_enabled&&!g_cfg_knob_bad&&(!peer||!*peer)&&(!tcp||!*tcp);
 pthread_mutex_unlock(&g_sir_mu);
 if(disabled){errno=ENODEV;return -1;}
 d.op=CRPC_OP_KEY_LOOKUP;d.rkey=key;
 if(sir_call(&d,&reply)){if(errno==ENODEV)errno=ENOTCONN;return -1;}
 if(reply.old_val!=key||reply.mlen!=sizeof(entry)){errno=EPROTO;return -1;}
 memcpy(&entry,reply.data,sizeof(entry));
 if(out){
  out->app_rkey=entry.app_rkey;out->app_access=entry.app_access;
  out->data_rkey=entry.data_rkey;out->write_rkey=entry.write_rkey;out->v_rkey=entry.v_rkey;
  out->addr=entry.addr;out->len=entry.len;out->v_addr=entry.v_addr;out->mr_id=-1;
 }
 return 0;
}

int sir_remote_repair(uint32_t data_rkey, unsigned long page_idx, int dir,
		      uint32_t off, uint32_t len, void *data)
{
	struct crpc_desc d;
	struct crpc_reply rep;
	int rc;

	if ((dir != SIR_F_READ && dir != SIR_F_WRITE) ||
	    len == 0 || len > SIR_INLINE_MAX || off + len > SIR_PAGE_SIZE ||
	    (dir == SIR_F_WRITE && len && !data)) {
		errno = EINVAL;
		return -1;
	}
	memset(&d, 0, sizeof(d));
	d.op = CRPC_OP_REPAIR_INLINE;
	d.rkey = data_rkey;
	d.dir = dir == SIR_F_WRITE ? CONTROL_DIR_WRITE : CONTROL_DIR_READ;
	d.page_idx = page_idx;
	d.off = off;
	d.len = len;
	if (len && data)
		memcpy(d.inline_data, data, len);
	rc = sir_call(&d, &rep);
	if (rc == 0 && dir == SIR_F_READ && len && data) {
		uint32_t n = rep.mlen < len ? rep.mlen : len;

		if (n)
			memcpy(data, rep.data, n);
	}
	return rc;
}

int sir_remote_repair_x(uint32_t data_rkey, unsigned long page_idx,
			unsigned long npages, int dir,
			uint64_t xaddr, uint32_t xrkey,
			uint32_t xoff, uint32_t xlen)
{
	struct crpc_desc d;
	int rc;

	if (!xaddr || !xrkey || npages == 0 || npages > SIR_RANGE_MAX ||
	    !xlen || xoff >= SIR_PAGE_SIZE ||
	    (uint64_t)xoff + xlen > npages * SIR_PAGE_SIZE ||
	    (dir != SIR_F_READ && dir != SIR_F_WRITE)) {
		errno = EINVAL;
		return -1;
	}
	memset(&d, 0, sizeof(d));
	d.op = CRPC_OP_REPAIR_REVERSE;
	d.rkey = data_rkey;
	d.dir = dir == SIR_F_WRITE ? CONTROL_DIR_WRITE : CONTROL_DIR_READ;
	d.page_idx = page_idx;
	d.npages = npages;
	d.off = xoff;
	d.len = xlen;
	d.xaddr = xaddr;
	d.xrkey = xrkey;
	rc = sir_call(&d, NULL);
	return rc;
}

int sir_remote_repair_batch(uint32_t data_rkey,
			    const struct sir_repair_span *spans,
			    uint32_t nspan, uint8_t *span_status)
{
	struct crpc_desc d;
	struct crpc_reply rep;
	int rc;
	uint32_t i;

	if (!spans || nspan == 0 || nspan > SIR_REPAIR_BATCH_MAX) {
		errno = EINVAL;
		return -1;
	}
	for (i = 0; i < nspan; i++) {
		if (spans[i].rsv ||
		    (spans[i].dir != SIR_F_READ && spans[i].dir != SIR_F_WRITE) ||
		    spans[i].npages == 0 ||
		    spans[i].npages > SIR_RANGE_MAX ||
		    spans[i].xoff >= SIR_PAGE_SIZE ||
		    spans[i].xlen == 0 ||
		    (uint64_t)spans[i].xoff + spans[i].xlen >
			    (uint64_t)spans[i].npages * SIR_PAGE_SIZE) {
			errno = EINVAL;
			return -1;
		}
	}
	memset(&d, 0, sizeof(d));
	d.op = CRPC_OP_REPAIR_BATCH;
	d.rkey = data_rkey;
	d.nspan = nspan;
	for (i = 0; i < nspan; i++) {
		d.span[i].page_idx = spans[i].page_idx;
		d.span[i].npages = spans[i].npages;
		d.span[i].dir = spans[i].dir == SIR_F_WRITE ?
					CONTROL_DIR_WRITE : CONTROL_DIR_READ;
		d.span[i].xaddr = spans[i].xaddr;
		d.span[i].xrkey = spans[i].xrkey;
		d.span[i].xoff = spans[i].xoff;
		d.span[i].xlen = spans[i].xlen;
		d.span[i].rsv = 0;
	}
	rc = sir_call(&d, &rep);
	if (rc == 0 && span_status && rep.nspan_status) {
		uint32_t n = rep.nspan_status < nspan ? rep.nspan_status :
							 nspan;

		memcpy(span_status, rep.data, n);
		if (n < nspan)
			memset(span_status + n, 0, nspan - n);
	}
	return rc;
}

int sir_remote_atomic(uint32_t data_rkey, uint64_t va, int op,
		      uint64_t compare, uint64_t swap_or_add, uint64_t *old_out)
{
	struct crpc_desc d;
	struct crpc_reply rep;
	int rc;

	if (op != SIR_F_ATOMIC_CAS && op != SIR_F_ATOMIC_FAA) {
		errno = EINVAL;
		return -1;
	}
	memset(&d, 0, sizeof(d));
	d.op = CRPC_OP_ATOMIC;
	d.rkey = data_rkey;
	d.dir = op == SIR_F_ATOMIC_CAS ? CONTROL_ATOMIC_CAS :
					 CONTROL_ATOMIC_FAA;
	d.va = va;

	if (op == SIR_F_ATOMIC_CAS) {
		d.operand_a = compare;
		d.operand_b = swap_or_add;
	} else {
		d.operand_a = swap_or_add;
		d.operand_b = 0;
	}
	rc = sir_call(&d, &rep);
	if (rc == 0 && old_out)
		*old_out = rep.old_val;
	return rc;
}

int sir_ping(uint32_t timeout_ms)
{
	struct crpc_desc d;
	int64_t dl;

	memset(&d, 0, sizeof(d));
	d.op = CRPC_OP_PING;
	if (!timeout_ms)
		timeout_ms = 1000;
	dl = crt_now_us() + (int64_t)timeout_ms * 1000;
	d.deadline_us = (uint64_t)dl;
	return sir_call(&d, NULL);
}

int sir_inline_max(void)
{
	return g_cfg_valid && g_cfg.inline_max >= 0 ? g_cfg.inline_max :
						      SIR_INLINE_MAX;
}

static void sir_fini_locked(void)
{
	sir_rdv_runtime_detach();
	sir_rdv_producers_close();
	if (g_r && crt_reactor_stop(g_r) == 0) {

		crt_trace_dump_at_exit();
		if(crt_reactor_free(g_r)==0){g_r=NULL;sir_rdv_runtime_release(&g_cfg);}
	}
 (void)sir_owned_pd_release_locked();
}
void sir_fini(void)
{pthread_mutex_lock(&g_sir_mu);sir_fini_locked();pthread_mutex_unlock(&g_sir_mu);}
void sir_fini_context(const struct ibv_context *ctx)
{
 pthread_mutex_lock(&g_sir_mu);
 if((g_r&&g_r->cfg.ctx==ctx)||(g_service_owned_ctx==ctx&&ctx))sir_fini_locked();
 pthread_mutex_unlock(&g_sir_mu);
}

int sir_carrier_pd(struct ibv_context *ctx, struct ibv_pd **out)
{
 int rc=ENOTCONN;
 if(!ctx||!out)return EINVAL;
 *out=NULL;
 pthread_mutex_lock(&g_sir_mu);
 if(g_r&&g_r->cfg.ctx==ctx&&g_r->cfg.pd){*out=g_r->cfg.pd;rc=0;}
 pthread_mutex_unlock(&g_sir_mu);
 return rc;
}

int sir_is_connected(void)
{
	return ctrl_session_ready(g_r);
}

uint32_t sir_peak_inflight(void)
{

	return ctrace_peak_inflight();
}

long sir_service_count(void)
{
	return (long)ctrace_stat_get(CTRACE_STAT_SERVED);
}

int sir_is_internal_qp(const struct ibv_qp *qp)
{
	return ctrans_is_internal_qp(qp);
}

int sir_is_internal_cq(const struct ibv_cq *cq)
{
	return ctrans_is_internal_cq(cq);
}

int sir_app_qp_peer_configured(void)
{
	const char *peer = getenv("SYMRDMA_PEER"),
		   *tcp = getenv("SYMRDMA_SIR_TCP");
	int from_env = (peer && peer[0]) || (tcp && tcp[0]);
	pthread_mutex_lock(&g_sir_mu);
	int captured = g_cfg_valid && (g_enabled || g_cfg_knob_bad);
	pthread_mutex_unlock(&g_sir_mu);
	return from_env || captured;
}
