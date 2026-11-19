#include <infiniband/verbs.h>
/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/eventfd.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "control_err.h"
#include "control_executor.h"
#include "control_trace.h"
#include "symrdma_abi.h"

#define CEXEC_CAP CONTROL_EXEC_PENDING_MAX

#define CEXEC_TEST_DELAY_MAX_US 2000000u
#define CEXEC_TEST_JITTER_MAX_US 200000u
#define CEXEC_TEST_DELAY_JOBS_MAX 64u

CRT_INTERNAL void cexec_init(struct cexec *ex)
{
	pthread_condattr_t ca;

	if (ex->inited) {
		pthread_mutex_lock(&ex->mu);
		memset(ex->job, 0, sizeof(ex->job));
		memset(ex->cmd, 0, sizeof(ex->cmd));
		memset(ex->res, 0, sizeof(ex->res));
		ex->next_job_id = 0;
		ex->used = 0;
		ex->fail_closed = 0;
		ex->violations = 0;
		crt_ring_init(&ex->ready, ex->ready_slots,
			      CONTROL_EXEC_PENDING_MAX,
			      sizeof(struct cexec_ready_ent));
		crt_ring_init(&ex->cpl, ex->cpl_slots,
			      CONTROL_EXEC_PENDING_MAX,
			      sizeof(struct cexec_cpl_ent));
		ex->jobs_done = 0;
		ex->jobs_cancelled = 0;
		pthread_mutex_unlock(&ex->mu);
		return;
	}
	memset(ex, 0, sizeof(*ex));
	ex->efd = -1;

	pthread_mutex_init(&ex->mu, NULL);

	pthread_mutex_init(&ex->park_mu, NULL);
	pthread_condattr_init(&ca);
	pthread_condattr_setclock(&ca, CLOCK_MONOTONIC);
	pthread_cond_init(&ex->park_cv, &ca);
	pthread_condattr_destroy(&ca);

	crt_ring_init(&ex->ready, ex->ready_slots, CONTROL_EXEC_PENDING_MAX,
		      sizeof(struct cexec_ready_ent));
	crt_ring_init(&ex->cpl, ex->cpl_slots, CONTROL_EXEC_PENDING_MAX,
		      sizeof(struct cexec_cpl_ent));
	ex->inited = 1;
}

static struct cexec_job *cexec_find_locked(struct cexec *ex, uint64_t job_id)
{
	uint32_t i;

	for (i = 0; i < CEXEC_CAP; i++)
		if (ex->job[i].taken && ex->job[i].job_id == job_id)
			return &ex->job[i];
	return NULL;
}

CRT_INTERNAL int cexec_job_admit(struct cexec *ex,
				  enum cexec_job_kind kind, uint32_t dir,
				  uint32_t rkey, uint64_t range_start,
				  uint64_t range_len, uint64_t *job_id)
{
	uint32_t i;
	int rc = -EBUSY;

	if (!ex || !job_id)
		return -EINVAL;
	if (kind > CEXEC_JOB_RDV_MEMORY || (kind!=CEXEC_JOB_RDV_MEMORY && rkey == 0) || range_len < 1)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	if (ex->fail_closed) {
		rc = -EPROTO;
		goto out;
	}
	for (i = 0; i < CEXEC_CAP; i++) {
		struct cexec_job *j = &ex->job[i];

		if (j->taken)
			continue;
		memset(j, 0, sizeof(*j));
		memset(&ex->cmd[i], 0, sizeof(ex->cmd[i]));
		memset(&ex->res[i], 0, sizeof(ex->res[i]));
		ex->next_job_id++;
		j->job_id = ex->next_job_id;
		j->state = CEXEC_ADMITTED;
		j->taken = 1;
		j->kind = (uint8_t)kind;
		j->dir = (uint8_t)dir;
		j->rkey = rkey;
		j->range_start = range_start;
		j->range_len = range_len;
		j->trace_admit_ns = ctrace_ts();
		ex->used++;
		*job_id = j->job_id;
		rc = 0;
		break;
	}
out:
	pthread_mutex_unlock(&ex->mu);
	return rc;
}

CRT_INTERNAL int cexec_job_set_cmd(struct cexec *ex, uint64_t job_id,
				    const struct cexec_cmd *cmd)
{
	struct cexec_job *j;
	uint32_t idx;
	int rc = 0;

	if (!ex || !cmd)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	j = cexec_find_locked(ex, job_id);
	if (!j || j->state != CEXEC_ADMITTED) {
		crt_log("cexec violation site=set_cmd job=%llu state=%u",
			 (unsigned long long)job_id, j ? j->state : 0xffu);
		rc = crt_violation(&ex->fail_closed, &ex->violations);
		goto out;
	}
	idx = (uint32_t)(j - ex->job);
	ex->cmd[idx] = *cmd;
out:
	pthread_mutex_unlock(&ex->mu);
	return rc;
}

CRT_INTERNAL int cexec_job_cancel(struct cexec *ex, uint64_t job_id)
{
	struct cexec_job *j;
	int rc = 0;

	if (!ex)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	j = cexec_find_locked(ex, job_id);
	if (!j) {
		crt_log("cexec violation site=cancel job=%llu (no such job)",
			 (unsigned long long)job_id);
		rc = crt_violation(&ex->fail_closed, &ex->violations);
		goto out;
	}
	j->cancelled = 1;
out:
	pthread_mutex_unlock(&ex->mu);
	return rc;
}

CRT_INTERNAL int cexec_stopped_cancel(struct cexec *ex, uint64_t job_id)
{
	if (!ex)
		return -EINVAL;
	int rc = 0;
	pthread_mutex_lock(&ex->mu);
	struct cexec_job *j = cexec_find_locked(ex, job_id);
	if (ex->nthreads || __atomic_load_n(&ex->run, __ATOMIC_ACQUIRE))
		rc = -EBUSY;
	else if (!j)
		rc = -ENOENT;
	else if (j->state == CEXEC_ADMITTED) {
		unsigned i = (unsigned)(j - ex->job);
		memset(&ex->res[i], 0, sizeof(ex->res[i]));
		ex->res[i].status = ECANCELED;
		j->cancelled = 1;
		j->queued = 0;
		j->state = CEXEC_DONE;
		j->status = ECANCELED;
		__atomic_fetch_add(&ex->jobs_cancelled, 1, __ATOMIC_RELAXED);
	} else if (j->state != CEXEC_DONE)
		rc = -EBUSY;
	pthread_mutex_unlock(&ex->mu);
	return rc;
}
CRT_INTERNAL int cexec_job_claim(struct cexec *ex, uint64_t job_id)
{
	struct cexec_job *j;
	int rc = 0;

	if (!ex)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	j = cexec_find_locked(ex, job_id);
	if (!j || j->state != CEXEC_ADMITTED) {
		crt_log("cexec violation site=claim job=%llu state=%u",
			 (unsigned long long)job_id, j ? j->state : 0xffu);
		rc = crt_violation(&ex->fail_closed, &ex->violations);
		goto out;
	}
	j->state = CEXEC_EXECUTING;
	j->queued = 0;
out:
	pthread_mutex_unlock(&ex->mu);
	return rc;
}

CRT_INTERNAL int cexec_job_finish(struct cexec *ex, uint64_t job_id,
				   int32_t status, uint32_t mlen)
{
	struct cexec_job *j;
	int rc = 0;

	if (!ex)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	j = cexec_find_locked(ex, job_id);
	if (!j || j->state != CEXEC_EXECUTING) {
		crt_log("cexec violation site=finish job=%llu state=%u",
			 (unsigned long long)job_id, j ? j->state : 0xffu);
		rc = crt_violation(&ex->fail_closed, &ex->violations);
		goto out;
	}
	j->state = CEXEC_DONE;
	j->status = status;
	j->mlen = mlen;
	__atomic_fetch_add(&ex->jobs_done, 1, __ATOMIC_RELAXED);
out:
	pthread_mutex_unlock(&ex->mu);
	return rc;
}

CRT_INTERNAL int cexec_job_release(struct cexec *ex, uint64_t job_id)
{
	struct cexec_job *j;
	int rc = 0;

	if (!ex)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	j = cexec_find_locked(ex, job_id);
	if (!j || j->state != CEXEC_DONE) {
		crt_log("cexec violation site=release job=%llu state=%u",
			 (unsigned long long)job_id, j ? j->state : 0xffu);
		rc = crt_violation(&ex->fail_closed, &ex->violations);
		goto out;
	}
	memset(j, 0, sizeof(*j));
	ex->used--;
out:
	pthread_mutex_unlock(&ex->mu);
	return rc;
}

CRT_INTERNAL int cexec_job_bind_reverse(struct cexec *ex, uint64_t job_id,
					 uint64_t token)
{
	struct cexec_job *j;
	int rc = 0;

	if (!ex)
		return -EINVAL;
	if (token == 0)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	j = cexec_find_locked(ex, job_id);
	if (!j) {
		rc = -EINVAL;
		goto out;
	}
	j->reverse_binds++;
	j->last_reverse_token = token;
out:
	pthread_mutex_unlock(&ex->mu);
	return rc;
}

CRT_INTERNAL int cexec_job_overlap(const struct cexec_job *a,
				    const struct cexec_job *b)
{
	uint64_t a_end, b_end;

	if (!a || !b)
		return 0;
	if (a->kind==CEXEC_JOB_RDV_MEMORY||b->kind==CEXEC_JOB_RDV_MEMORY||a->rkey != b->rkey)
		return 0;
	if (a->range_len == 0 || b->range_len == 0)
		return 0;
	a_end = a->range_start + a->range_len;
	b_end = b->range_start + b->range_len;
	return a->range_start < b_end && b->range_start < a_end;
}

static int cexec_scope_hit(const struct cexec_job *j, enum cexec_dep_scope scope)
{
	if (!j->taken || j->cancelled)
		return 0;
	if (scope == CEXEC_DEP_HELD)
		return 1;
	return j->state == CEXEC_ADMITTED || j->state == CEXEC_EXECUTING;
}

static int cexec_conflicts_locked(const struct cexec *ex, uint32_t rkey,
				  uint64_t range_start, uint64_t range_len,
				  enum cexec_dep_scope scope, int skip,
				  uint64_t before_id)
{
	uint32_t i, n = 0;
	struct cexec_job cand;

	memset(&cand, 0, sizeof(cand));
	cand.rkey = rkey;
	cand.range_start = range_start;
	cand.range_len = range_len;
	for (i = 0; i < CEXEC_CAP; i++) {
		const struct cexec_job *j = &ex->job[i];

		if ((int)i == skip)
			continue;

		if (before_id && j->job_id >= before_id)
			continue;
		if (!cexec_scope_hit(j, scope))
			continue;
		if (cexec_job_overlap(&cand, j))
			n++;
	}
	return (int)n;
}

CRT_INTERNAL int cexec_dependency_conflicts(struct cexec *ex, uint32_t rkey,
					     uint64_t range_start,
					     uint64_t range_len,
					     enum cexec_dep_scope scope)
{
	int n;

	if (!ex)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	n = cexec_conflicts_locked(ex, rkey, range_start, range_len, scope,
				   -1, 0);
	pthread_mutex_unlock(&ex->mu);
	return n;
}

CRT_INTERNAL int cexec_fail_closed(const struct cexec *ex)
{
	return ex ? (ex->fail_closed ? 1 : 0) : 0;
}

CRT_INTERNAL uint32_t cexec_pending(struct cexec *ex)
{
	uint32_t n;

	if (!ex)
		return 0;
	pthread_mutex_lock(&ex->mu);
	n = ex->used;
	pthread_mutex_unlock(&ex->mu);
	return n;
}

static void cexec_wake_workers(struct cexec *ex, uint32_t n)
{
	pthread_mutex_lock(&ex->park_mu);
	while (n && __atomic_load_n(&ex->parked, __ATOMIC_RELAXED)) {
		pthread_cond_signal(&ex->park_cv);
		n--;
		if (!n)
			break;
	}
	pthread_mutex_unlock(&ex->park_mu);
}

static void cexec_schedule_locked(struct cexec *ex)
{
	uint32_t pick[CEXEC_CAP];
	uint32_t npick = 0, i, k;
	struct cexec_ready_ent ent;
	int pushed = 0;

	for (i = 0; i < CEXEC_CAP; i++) {
		struct cexec_job *j = &ex->job[i];

		if (!j->taken || j->state != CEXEC_ADMITTED || j->queued)
			continue;
		for (k = npick; k > 0 &&
		     ex->job[pick[k - 1]].job_id > j->job_id; k--)
			pick[k] = pick[k - 1];
		pick[k] = i;
		npick++;
	}
	for (i = 0; i < npick; i++) {
		uint32_t idx = pick[i];
		struct cexec_job *j = &ex->job[idx];

		if (j->kind!=CEXEC_JOB_RDV_MEMORY && cexec_conflicts_locked(ex, j->rkey, j->range_start,
					   j->range_len, CEXEC_DEP_HELD,
					   (int)idx, j->job_id))
			continue;
		j->queued = 1;
		if (j->trace_admit_ns) {
			int64_t now = crt_now_ns();

			ctrace_at(CTRACE_PHASE_DEP_WAIT,
				  ex->cmd[idx].session_id,
				  ex->cmd[idx].request_id, j->job_id,
				  0, j->trace_admit_ns,
				  (uint64_t)(now - j->trace_admit_ns));
			j->trace_admit_ns = 0;
			j->trace_queued_ns = now;
		}
		ent.idx = idx;
		ent.job_id = j->job_id;

		if (crt_ring_push(&ex->ready, &ent)) {
			crt_violation(&ex->fail_closed, &ex->violations);
			return;
		}
		pushed++;
	}
	if (pushed)
		cexec_wake_workers(ex, (uint32_t)pushed);
}

CRT_INTERNAL int cexec_schedule(struct cexec *ex)
{
	if (!ex)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	cexec_schedule_locked(ex);
	pthread_mutex_unlock(&ex->mu);
	return ex->fail_closed ? -EPROTO : 0;
}

CRT_INTERNAL int cexec_poll(struct cexec *ex, uint64_t *job_id)
{
	struct cexec_cpl_ent ent;
	int rc;

	if (!ex || !job_id)
		return -EINVAL;

	rc = crt_ring_peek(&ex->cpl, &ent);
	if (rc)
		return -ENOENT;
	crt_ring_pop(&ex->cpl);
	if (ent.gone)
		return crt_violation(&ex->fail_closed, &ex->violations);
	*job_id = ent.job_id;
	return 0;
}

CRT_INTERNAL int cexec_result(struct cexec *ex, uint64_t job_id,
			       struct cexec_result *out)
{
	struct cexec_job *j;
	int rc = 0;

	if (!ex || !out)
		return -EINVAL;
	pthread_mutex_lock(&ex->mu);
	j = cexec_find_locked(ex, job_id);
	if (!j) {
		rc = -ENOENT;
		goto out;
	}
	if (j->state != CEXEC_DONE) {
		rc = -EAGAIN;
		goto out;
	}
	*out = ex->res[(uint32_t)(j - ex->job)];
out:
	pthread_mutex_unlock(&ex->mu);
	return rc;
}

static int cexec_export_pages_ok(const struct creg_owner_view *v,
				 uint64_t page_idx, uint64_t npages)
{
	uint64_t pages = (v->len + CONTROL_PAGE_SIZE - 1) / CONTROL_PAGE_SIZE;

	if (!npages || page_idx >= pages || npages > pages - page_idx)
		return -EINVAL;
	return 0;
}

static int cexec_export_span_ok(const struct creg_owner_view *v,
				uint64_t page_idx, uint64_t npages,
				uint64_t xoff, uint64_t xlen)
{
	uint64_t start, end;

	if (cexec_export_pages_ok(v, page_idx, npages))
		return -EINVAL;
	if (page_idx > (UINT64_MAX - xoff) / CONTROL_PAGE_SIZE)
		return -EINVAL;
	start = page_idx * CONTROL_PAGE_SIZE + xoff;
	if (xlen > UINT64_MAX - start)
		return -EINVAL;
	end = start + xlen;
	if (end > v->len)
		return -EINVAL;
	return 0;
}

/* The owner's side of the repair window: PIN the export range and hold
 * it across the reverse write. PIN is the promote - the verb completes the
 * mapping and takes the dma_ref barrier in one action, so there is no "promote
 * here, write later" gap in which the page can be demoted again. The hold is
 * released by the owner when the request reaches a terminal state (cown_respond
 * / cown_recycle), never here: the reverse write has not landed yet.
 *
 * The old shape was a REPAIR_RANGE chunk loop that promoted and then wrote with
 * nothing held; a demote landing between the two dropped the write silently
 * No chunking here either: one span, one PIN, or fail-closed. */
static int cexec_kernel_pin(int sym_fd, const struct creg_owner_view *v,
			    uint64_t page_idx, uint64_t npages, uint32_t *status,
			    const struct cexec_cmd *cmd, uint64_t job_id)
{
	struct symrdma_ioc_pin pin;
	int64_t t_io;
	int irc, ierr;

	if (cexec_export_pages_ok(v, page_idx, npages)) {
		*status = EINVAL;
		return -1;
	}
	if (sym_fd < 0 || v->mr_id < 0) {
		if (crt_log_level() > 0)
			crt_log("kernel pin precondition failed sym_fd=%d mr_id=%d",
				 sym_fd, v->mr_id);
		*status = ENOENT;
		return -1;
	}
	memset(&pin, 0, sizeof(pin));
	pin.mr_id = v->mr_id;
	pin.va = v->addr + page_idx * CONTROL_PAGE_SIZE;
	pin.len = npages * CONTROL_PAGE_SIZE;
	t_io = ctrace_ts();
	irc = ioctl(sym_fd, SYMRDMA_IOC_PIN_PAGES, &pin);
	ierr = irc ? errno : 0;
	/* The phase names the kernel verb it wraps: PIN is the kernel-side repair
	 * verb now, so the phase is KERNEL_PIN. */
	ctrace_at(CTRACE_PHASE_KERNEL_PIN, cmd ? cmd->session_id : 0,
		  cmd ? cmd->request_id : 0, job_id, (uint16_t)ierr, t_io,
		  t_io ? (uint64_t)(crt_now_ns() - t_io) : 0);
	ctrace_stat_inc(CTRACE_STAT_IOCTL_PIN, 1);
	if (irc) {
		if (crt_log_level() > 0)
			crt_log("kernel PIN failed mr=%d page=%llu npages=%llu "
				"errno=%d", v->mr_id,
				(unsigned long long)page_idx,
				(unsigned long long)npages, ierr);
		*status = (uint32_t)ierr;
		return -1;
	}
	return 0;
}

/* Release one span's hold. Only the holder calls this: the executor releases a
 * span it pinned and then refused, the owner releases the spans whose reverse
 * write has been completed (or abandoned). UNPIN releases - it does not evict. */
static int cexec_kernel_unpin(int sym_fd, const struct creg_owner_view *v,
			      uint64_t page_idx, uint64_t npages)
{
	struct symrdma_ioc_pin pin;

	if (sym_fd < 0 || v->mr_id < 0)
		return -1;
	memset(&pin, 0, sizeof(pin));
	pin.mr_id = v->mr_id;
	pin.va = v->addr + page_idx * CONTROL_PAGE_SIZE;
	pin.len = npages * CONTROL_PAGE_SIZE;
	return ioctl(sym_fd, SYMRDMA_IOC_UNPIN_PAGES, &pin) ? -1 : 0;
}

static int cexec_version_gate(const struct creg_owner_view *v,
			      uint64_t page_idx, uint64_t xoff, uint64_t xlen,
			      uint32_t *status)
{
	const volatile uint32_t *vt;
	uint64_t n, k;

	if (!v->v_rkey || !v->v_addr)
		return 0;
	vt = (const volatile uint32_t *)(uintptr_t)v->v_addr;
	n = (xoff + xlen + CONTROL_PAGE_SIZE - 1) / CONTROL_PAGE_SIZE;
	for (k = 0; k < n; k++) {
		if (!(vt[page_idx + k] & 1u)) {
			*status = EAGAIN;
			return -1;
		}
	}
	return 0;
}

static void cexec_test_delay(struct cexec *ex, const struct cexec_cmd *cmd)
{
	uint64_t us = ex->test_delay_us;
	struct timespec ts;

	if (ex->test_jitter_us)
		us += (cmd->request_id % 4u) * (uint64_t)ex->test_jitter_us;
	if (!us)
		return;
	if (ex->test_delay_jobs &&
	    (uint32_t)__sync_fetch_and_add(&ex->delay_jobs_applied, 1) >=
		    ex->test_delay_jobs)
		return;
	ts.tv_sec = (time_t)(us / 1000000u);
	ts.tv_nsec = (long)((us % 1000000u) * 1000u);
	while (clock_nanosleep(CLOCK_MONOTONIC, 0, &ts, &ts) == EINTR)
		;
}

static void cexec_exec(struct cexec *ex, uint64_t job_id,
		       const struct cexec_cmd *cmd, struct cexec_result *res)
{
	struct creg_owner_view v;
	uint64_t lease = 0;
	uint32_t status = 0;
	int rc;

	res->status = 0;
	res->mlen = 0;
	res->old_val = 0;
	res->rev_needed = 0;
	memset(res->span_pinned, 0, sizeof(res->span_pinned));
	res->resp_len = 0;

 memset(res,0,sizeof(*res));
 if(cmd->kind==CEXEC_JOB_RDV_MEMORY){
  int memory_rc=cexec_memory_ioctl(&cmd->memory,cmd->memory_operation);
  res->status=memory_rc;res->memory_succeeded=!memory_rc;return;
 }
	cexec_test_delay(ex, cmd);
	rc = creg_owner_acquire(cmd->rkey, &v, &lease);
	if (rc) {
		if (crt_log_level() > 0)
			crt_log("owner acquire failed rkey=0x%x op=%u rc=%d",
				 cmd->rkey, cmd->op, rc);
		res->status = (rc == -ESHUTDOWN) ? (int32_t)ESHUTDOWN :
			      (rc == -EBUSY) ? (int32_t)EBUSY :
					       (int32_t)ENOENT;
		return;
	}

	if (cmd->op == CPROTO_OP_ATOMIC) {
		volatile uint64_t *p;

		if (v.app_rkey && !(v.app_access & IBV_ACCESS_REMOTE_ATOMIC)) {
			res->status = EACCES;
			goto out_lease;
		}
		if (v.data_rkey != cmd->rkey && v.app_rkey != cmd->rkey) {
			res->status = ENOENT;
			goto out_lease;
		}
		if (cmd->va < v.addr || cmd->va + 8 > v.addr + v.len ||
		    (cmd->va & 7)) {
			res->status = EFAULT;
			goto out_lease;
		}
		p = (volatile uint64_t *)(uintptr_t)cmd->va;
		if (cmd->dir == CONTROL_ATOMIC_CAS)
			res->old_val = __sync_val_compare_and_swap(
				p, cmd->operand_a, cmd->operand_b);
		else
			res->old_val = __sync_fetch_and_add(p,
							    cmd->operand_a);
		if (cmd->sym_fd >= 0 && v.mr_id >= 0) {
			struct symrdma_ioc_repair rp;
			int64_t t_io = ctrace_ts();
			int irc;

			memset(&rp, 0, sizeof(rp));
			rp.mr_id = v.mr_id;
			rp.page_idx = (unsigned long)((cmd->va - v.addr) /
						      CONTROL_PAGE_SIZE);
			irc = ioctl(cmd->sym_fd, SYMRDMA_IOC_REPAIR, &rp);
			{
				int ierr = irc ? errno : 0;

				ctrace_at(CTRACE_PHASE_KERNEL_PIN,
					  cmd->session_id, cmd->request_id,
					  job_id, (uint16_t)ierr, t_io,
					  t_io ? (uint64_t)(crt_now_ns() - t_io)
					       : 0);
			}
			ctrace_stat_inc(CTRACE_STAT_IOCTL_PIN, 1);
		}
		res->status = 0;
		goto out_lease;
	}

	if (cmd->op == CPROTO_OP_REPAIR_INLINE) {
		void *page;

		if (cexec_export_span_ok(&v, cmd->page_idx, 1, cmd->off,
					 cmd->len)) {
			res->status = EINVAL;
			goto out_lease;
		}
		if (cexec_kernel_pin(cmd->sym_fd, &v, cmd->page_idx, 1,
				     &status, cmd, job_id)) {
			res->status = (int32_t)status;
			goto out_lease;
		}
		page = (void *)(uintptr_t)(v.addr + cmd->page_idx *
					   CONTROL_PAGE_SIZE);
		if (cmd->dir == CONTROL_DIR_WRITE) {
			memcpy((char *)page + cmd->off, cmd->inline_data,
			       cmd->len);
		} else {
			memcpy(res->resp_data, (char *)page + cmd->off,
			       cmd->len);
			res->resp_len = cmd->len;
		}
		/* The inline carrier has no reverse write, so the hold ends here. */
		if (cexec_kernel_unpin(cmd->sym_fd, &v, cmd->page_idx, 1)) {
			res->status = EIO;
			goto out_lease;
		}
		res->mlen = 1;
		res->status = 0;
		goto out_lease;
	}

	{
		uint32_t i, nrev = 0;

		res->nspan = cmd->nspan;
		for (i = 0; i < cmd->nspan; i++) {
			const struct cproto_repair_span *sp = &cmd->span[i];
			uint32_t sst = 0;

			if (cexec_export_span_ok(&v, sp->page_idx,
						 sp->npages, sp->xoff,
						 sp->xlen)) {
				res->span_status[i] = EINVAL;
				continue;
			}
			if (cexec_kernel_pin(cmd->sym_fd, &v, sp->page_idx,
					     sp->npages, &sst, cmd, job_id)) {
				res->span_status[i] = (int32_t)sst;
				continue;
			}
			if (!v.lkey) {
				(void)cexec_kernel_unpin(cmd->sym_fd, &v,
							 sp->page_idx,
							 sp->npages);
				res->span_status[i] = EINVAL;
				continue;
			}
			if (cexec_version_gate(&v, sp->page_idx, sp->xoff,
					       sp->xlen, &sst)) {
				(void)cexec_kernel_unpin(cmd->sym_fd, &v,
							 sp->page_idx,
							 sp->npages);
				res->span_status[i] = (int32_t)sst;
				continue;
			}
			res->span_status[i] = 0;
			res->span_pinned[i] = 1;
			nrev++;
		}
		res->mlen = cmd->nspan;
		res->status = 0;
		if (nrev) {
			res->view = v;
			res->lease = lease;
			res->rev_needed = nrev;
			return;
		}
		/* Not one span needs a reverse write although the initiator asked for
		 * them: responding "ok" here is how a request that did report missing
		 * pages got a silent success. Fail closed and let the
		 * initiator re-probe. */
		res->status = EAGAIN;
		goto out_lease;
	}

out_lease:
	if (lease)
		creg_lease_put(lease);
	res->lease = 0;
}

static void *cexec_worker(void *arg)
{
	struct cexec *ex = arg;

	for (;;) {
		struct cexec_job *j;
		struct cexec_cmd cmd;
		struct cexec_result res;
		struct cexec_ready_ent ent;
		struct cexec_cpl_ent cp;
		uint32_t idx;
		uint64_t job_id;
		int64_t run_ns, queued_ns;
		int busy;

		if (crt_ring_claim(&ex->ready, &ent)) {
			pthread_mutex_lock(&ex->park_mu);
			if (!__atomic_load_n(&ex->run, __ATOMIC_ACQUIRE)) {
				pthread_mutex_unlock(&ex->park_mu);
				return NULL;
			}
			if (crt_ring_empty(&ex->ready)) {
				__atomic_fetch_add(&ex->parked, 1,
						   __ATOMIC_RELAXED);
				pthread_cond_wait(&ex->park_cv, &ex->park_mu);
				__atomic_fetch_sub(&ex->parked, 1,
						   __ATOMIC_RELAXED);
			}
			pthread_mutex_unlock(&ex->park_mu);
			continue;
		}
		if (!__atomic_load_n(&ex->run, __ATOMIC_ACQUIRE)) {
			return NULL;
		}
		idx = ent.idx;
		j = &ex->job[idx];
		job_id = j->job_id;
		busy = __atomic_load_n(&j->cancelled, __ATOMIC_ACQUIRE);
		cmd = ex->cmd[idx];
		queued_ns = j->trace_queued_ns;
		j->trace_queued_ns = 0;

		run_ns = ctrace_ts();
		if (queued_ns) {
			ctrace_at(CTRACE_PHASE_EXEC_QUEUE, cmd.session_id,
				  cmd.request_id, job_id, 0, queued_ns,
				  (uint64_t)(run_ns - queued_ns));
			ctrace_stat_inc(CTRACE_STAT_WAKE_WORKER, 1);
		}
		(void)cexec_job_claim(ex, job_id);
		if (busy) {
			memset(&res, 0, sizeof(res));
			res.status = ECANCELED;
			__atomic_fetch_add(&ex->jobs_cancelled, 1,
					   __ATOMIC_RELAXED);
		} else {
			cexec_exec(ex, job_id, &cmd, &res);
		}
		ctrace_done(CTRACE_PHASE_EXEC_RUN, cmd.session_id,
			    cmd.request_id, job_id,
			    (uint16_t)(res.status > 0 ? res.status : 0), run_ns);

		ex->res[idx] = res;
		(void)cexec_job_finish(ex, job_id, res.status, res.mlen);

		memset(&cp, 0, sizeof(cp));
		cp.idx = idx;
		cp.mlen = res.mlen;
		cp.status = res.status;
		cp.job_id = job_id;
		if (crt_ring_push(&ex->cpl, &cp))
			crt_violation(&ex->fail_closed, &ex->violations);
		if (ex->efd >= 0) {
			uint64_t one = 1;

			(void)!write(ex->efd, &one, sizeof(one));
			ctrace_stat_inc(CTRACE_STAT_EFD_WRITE, 1);
		}
	}
}

static uint32_t cexec_env_us(const char *name, uint32_t cap)
{
	const char *e = getenv(name);
	long v;

	if (!e || !*e)
		return 0;
	v = atol(e);
	if (v <= 0)
		return 0;
	return (uint32_t)(v > (long)cap ? (long)cap : v);
}

CRT_INTERNAL int cexec_start(struct cexec *ex, uint32_t workers)
{
	uint32_t i;

	if (!ex)
		return -EINVAL;
	if (ex->nthreads)
		return -EBUSY;
	if (!workers)
		workers = 1;
	if (workers > CONTROL_EXEC_WORKERS_MAX)
		workers = CONTROL_EXEC_WORKERS_MAX;
	ex->efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	if (ex->efd < 0)
		return -errno;
	ex->test_delay_us = cexec_env_us("SYMRDMA_CTRL_TEST_DELAY_US",
					 CEXEC_TEST_DELAY_MAX_US);
	ex->test_jitter_us = cexec_env_us("SYMRDMA_CTRL_TEST_DELAY_JITTER_US",
					  CEXEC_TEST_JITTER_MAX_US);
	ex->test_delay_jobs = cexec_env_us("SYMRDMA_CTRL_TEST_DELAY_JOBS",
					   CEXEC_TEST_DELAY_JOBS_MAX);
	__atomic_store_n(&ex->run, 1, __ATOMIC_RELEASE);
	for (i = 0; i < workers; i++) {
		int rc = pthread_create(&ex->th[i], NULL, cexec_worker, ex);

		if (rc) {
			cexec_stop(ex);
			return -rc;
		}
		ex->nthreads++;
	}
	crt_log("executor start: workers=%u pending=%u (zero verbs, )",
		 ex->nthreads, (uint32_t)CONTROL_EXEC_PENDING_MAX);
	if (ex->test_delay_us || ex->test_jitter_us)
		crt_log("test injection: delay_us=%u jitter_us=%u jobs=%u "
			 "(test-only, always 0 in production)", ex->test_delay_us,
			 ex->test_jitter_us, ex->test_delay_jobs);
	return 0;
}

CRT_INTERNAL void cexec_stop(struct cexec *ex)
{
	uint32_t i;

	if (!ex)
		return;
	__atomic_store_n(&ex->run, 0, __ATOMIC_RELEASE);
	pthread_mutex_lock(&ex->park_mu);
	pthread_cond_broadcast(&ex->park_cv);
	pthread_mutex_unlock(&ex->park_mu);
	for (i = 0; i < ex->nthreads; i++)
		pthread_join(ex->th[i], NULL);
	ex->nthreads = 0;
	if (ex->efd >= 0) {
		close(ex->efd);
		ex->efd = -1;
	}
	pthread_mutex_lock(&ex->mu);
	crt_ring_init(&ex->ready, ex->ready_slots, CONTROL_EXEC_PENDING_MAX,
		      sizeof(struct cexec_ready_ent));
	for (i = 0; i < CEXEC_CAP; i++)
		ex->job[i].queued = 0;
	pthread_mutex_unlock(&ex->mu);

	crt_log("executor shutdown: jobs_done=%ld jobs_cancelled=%ld",
		__atomic_load_n(&ex->jobs_done, __ATOMIC_RELAXED),
		__atomic_load_n(&ex->jobs_cancelled, __ATOMIC_RELAXED));
}

CRT_INTERNAL void cexec_fini(struct cexec *ex)
{
	if (!ex || !ex->inited)
		return;
	pthread_cond_destroy(&ex->park_cv);
	pthread_mutex_destroy(&ex->park_mu);
	pthread_mutex_destroy(&ex->mu);
	ex->inited = 0;
}

CRT_INTERNAL int cexec_event_fd(const struct cexec *ex)
{
	return ex ? ex->efd : -1;
}

CRT_INTERNAL int cexec_job_kind(struct cexec *ex,uint64_t id,enum cexec_job_kind *out)
{
 if(!ex||!out)return -EINVAL;
 pthread_mutex_lock(&ex->mu);struct cexec_job *j=cexec_find_locked(ex,id);
 if(j)*out=(enum cexec_job_kind)j->kind;
 pthread_mutex_unlock(&ex->mu);return j?0:-ENOENT;
}
CRT_INTERNAL int cexec_memory_ioctl(const struct sir_rdv_span *s,unsigned op)
{
 if(!s||!sir_rdv_backend_valid(&s->backend)||s->backend.kind!=SIR_RDV_SYM_PIN||!s->length||
  (op!=CEXEC_MEMORY_PIN&&op!=CEXEC_MEMORY_UNPIN))return EINVAL;
 struct symrdma_ioc_pin p={.mr_id=s->backend.mr_id,.va=s->cpu_address,.len=s->length};
 int rc=ioctl(s->backend.dupfd,op==CEXEC_MEMORY_PIN?SYMRDMA_IOC_PIN_PAGES:SYMRDMA_IOC_UNPIN_PAGES,&p);
 return rc?(errno?errno:EIO):0;
}
