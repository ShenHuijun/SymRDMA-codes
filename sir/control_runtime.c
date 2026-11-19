/* SPDX-License-Identifier: GPL-2.0 */
#define _GNU_SOURCE
#include "rdv_bridge.h"

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "control_efd.h"
#include "control_reactor.h"
#include "control_app_qp.h"
#include "control_runtime.h"
#include "control_trace.h"

static char g_trace_dump_path[512];
static int  g_trace_dumped;

static void crt_trace_dump_path_capture(void)
{
	const char *p = getenv("SYMRDMA_CTRL_TRACE_DUMP");

	if (p && p[0])
		snprintf(g_trace_dump_path, sizeof(g_trace_dump_path), "%s", p);
}

CRT_INTERNAL void crt_trace_dump_at_exit(void)
{
	int fd, rc;

	if (g_trace_dumped || !ctrace_on() || !g_trace_dump_path[0])
		return;
	g_trace_dumped = 1;
	fd = open(g_trace_dump_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
		  0644);
	if (fd < 0) {
		crt_log("trace dump open failed errno=%d (ignored, teardown semantics unchanged)",
			errno);
		return;
	}
	rc = ctrace_dump(fd);
	close(fd);
	if (rc)
		crt_log("trace dump write failed rc=%d path_len=%u (ignored, teardown semantics unchanged)",
			rc, (unsigned)strlen(g_trace_dump_path));
	else
		crt_log("trace dump written path_len=%u (records/dropped in dump header)",
			(unsigned)strlen(g_trace_dump_path));
}

CRT_INTERNAL void *crt_reactor_main(void *arg)
{
	return ctrl_reactor_loop(arg);
}

struct ctrl_reactor *crt_reactor_new(const struct crt_cfg *cfg)
{
	struct ctrl_reactor *r;
	pthread_mutexattr_t ma;
	pthread_condattr_t ca;

	if (!cfg || !cfg->key[0])
		return NULL;

	ctrace_startup();
	crt_trace_dump_path_capture();
	r = calloc(1, sizeof(*r));
	if (!r)
		return NULL;
	if(ctrans_runtime_guard_acquire(cfg->ctx,cfg->pd,&r->lifetime_guard)) {free(r);return NULL;}
	r->cfg = *cfg;
	r->timer_armed_us = 0;
	pthread_mutexattr_init(&ma);
	pthread_mutexattr_settype(&ma, PTHREAD_MUTEX_ERRORCHECK);
	pthread_mutex_init(&r->sub_mu, &ma);
	pthread_mutexattr_destroy(&ma);

	pthread_mutex_init(&r->sig_mu, NULL);
	pthread_condattr_init(&ca);
	pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
	pthread_cond_init(&r->sig_cv, &ca);
	pthread_condattr_destroy(&ca);
	ctrans_tx_init(&r->tx, CONTROL_WINDOW_MAX, CONTROL_WINDOW_MAX);
	ctrans_rx_init(&r->rx);
	ctrans_rev_init(&r->rev);
	cexec_init(&r->exec);
	crpc_requester_init(&r->rreq, 0, CONTROL_WINDOW_MAX);
	r->own = cown_new(r);
	r->peer = cpeer_new();
	if (!r->own || !r->peer) {
		cown_free(r->own);
		cpeer_free(r->peer);
		pthread_mutex_destroy(&r->sub_mu);
		pthread_mutex_destroy(&r->sig_mu);
		pthread_cond_destroy(&r->sig_cv);
		ctrans_runtime_guard_release(r->lifetime_guard);
		free(r);
		return NULL;
	}
	r->sess = csess_new(r);
	if (!r->sess) {
		cown_free(r->own);
		cpeer_free(r->peer);
		pthread_mutex_destroy(&r->sub_mu);
		pthread_mutex_destroy(&r->sig_mu);
		pthread_cond_destroy(&r->sig_cv);
		ctrans_runtime_guard_release(r->lifetime_guard);
		free(r);
		return NULL;
	}
	r->pv.ch_fd = -1;
	r->sub_efd = r->quit_efd = r->timer_fd = -1;
	crdv_init(&r->rdv, cfg->rdv_kind, cfg->dir, cfg->key, cfg->tcp_host,
		  cfg->tcp_port, cfg->sgid_index);
	if(ctrl_app_rdv_attach(r)){(void)crt_reactor_free(r);return NULL;}
	return r;
}

void crt_reactor_bind_sym_fd(struct ctrl_reactor *r, int fd)
{
	if (!r || fd < 0)
		return;
	__atomic_store_n(&r->cfg.sym_fd, fd, __ATOMIC_RELEASE);
}

int crt_reactor_start(struct ctrl_reactor *r)
{
	int rc;

	if (!r || r->running)
		return -EINVAL;
	r->sub_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	r->quit_efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	r->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC |
				     TFD_NONBLOCK);
	if (r->sub_efd < 0 || r->quit_efd < 0 || r->timer_fd < 0) {
		rc = -errno;
		(void)crt_reactor_stop(r);
		return rc;
	}
	rc = cexec_start(&r->exec, r->cfg.workers);
	if (rc) {
		(void)crt_reactor_stop(r);
		return rc;
	}
	rc = pthread_create(&r->thread, NULL, crt_reactor_main, r);
	if (rc) {
		cexec_stop(&r->exec);
		(void)crt_reactor_stop(r);
		return -rc;
	}
	r->running = 1;
	return 0;
}

int crt_reactor_stop(struct ctrl_reactor *r)
{
	if (!r)
		return -EINVAL;
	if (r->running) {
		if (pthread_equal(pthread_self(), r->thread))
			return -EDEADLK;
		crt_efd_write(r->quit_efd, 1);
		struct timespec join_deadline;
		if (clock_gettime(CLOCK_REALTIME, &join_deadline))
			return -errno;
		join_deadline.tv_sec += 2;
		int join_rc =
		    pthread_timedjoin_np(r->thread, NULL, &join_deadline);
		if (join_rc == ETIMEDOUT)
			return -EBUSY;
		if (join_rc)
			return -join_rc;
		r->running = 0;
	}
	/* No worker may still own an unpublished result when the joined owner
	 * reconciles the old session. The completion ring itself is preserved.
	 */
	cexec_stop(&r->exec);
	int release_rc = csess_release(r);
	if (release_rc)
		return release_rc;
	/* The reactor may have returned before owner abort when native stop
	 * failed. Worker results and every old owner must be reaped before
	 * free. */
	/* After join this thread owns final reconciliation. Native DMA is
	 * stopped; a prior fatal exit may deliberately have retained callers.
	 */
	ctrl_fail_pending_submits(r);
	ctrl_fail_requests(r);
	int app_rc=ctrl_app_rdv_detach(r);if(app_rc)return -app_rc;
	cbind_actor_detach(r);
	if (r->sub_efd >= 0)
		close(r->sub_efd);
	if (r->quit_efd >= 0)
		close(r->quit_efd);
	if (r->timer_fd >= 0)
		close(r->timer_fd);
	r->sub_efd = r->quit_efd = r->timer_fd = -1;
	return ctrans_provider_busy(&r->pv) ? -EBUSY : 0;
}

int crt_reactor_free(struct ctrl_reactor *r)
{
	if (!r)
		return 0;
	if (r->running || r->exec.nthreads ||
	    __atomic_load_n(&r->exec.run, __ATOMIC_ACQUIRE) ||
	    ctrans_provider_busy(&r->pv) || cown_busy(r) ||
	    cexec_pending(&r->exec) || rdv_bridge_busy(&r->exec))
		return -EBUSY;
	int app_rc=ctrl_app_rdv_detach(r);if(app_rc)return -app_rc;
	cown_free(r->own);
	cpeer_free(r->peer);
	csess_free(r->sess);
	cexec_fini(&r->exec);
	pthread_mutex_destroy(&r->sub_mu);
	pthread_mutex_destroy(&r->sig_mu);
	pthread_cond_destroy(&r->sig_cv);
	ctrans_runtime_guard_release(r->lifetime_guard);
	free(r);
	return 0;
}
