/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_EXECUTOR_H
#define CONTROL_EXECUTOR_H

#include <pthread.h>
#include <stdint.h>

#include "control_log.h"
#include "control_ring.h"
#include "control_protocol.h"
#include "endpoint_registry.h"
#include "rdv_memory.h"
struct rdv_bridge_owner;
struct rdv_bridge_epoch;

#define CONTROL_EXEC_WORKERS_MAX   4u
#define CONTROL_EXEC_PENDING_MAX   16u

enum cexec_job_kind {
	CEXEC_JOB_INLINE = 0,
	CEXEC_JOB_REVERSE,
	CEXEC_JOB_BATCH,
	CEXEC_JOB_ATOMIC,
 CEXEC_JOB_RDV_MEMORY,
};

enum cexec_job_state {
	CEXEC_ADMITTED = 0,
	CEXEC_EXECUTING,
	CEXEC_DONE,
};

enum cexec_dep_scope {
	CEXEC_DEP_ACTIVE = 0,
	CEXEC_DEP_HELD,
};

struct cexec_job {
	uint8_t  state;
	uint8_t  taken;
	uint8_t  kind;
	uint8_t  dir;
	uint8_t  queued;
	uint8_t  cancelled;
	uint64_t job_id;
	uint32_t rkey;
	uint64_t range_start;
	uint64_t range_len;
	uint32_t reverse_binds;

	uint64_t last_reverse_token;
	int32_t  status;

	uint32_t mlen;

	int64_t  trace_admit_ns;
	int64_t  trace_queued_ns;
};

struct cexec_ready_ent {
	uint32_t idx;
	uint32_t pad;
	uint64_t job_id;
};

struct cexec_cpl_ent {
	uint32_t idx;
	uint32_t mlen;
	int32_t  status;
	uint32_t gone;
	uint64_t job_id;
};

enum cexec_memory_operation { CEXEC_MEMORY_PIN=1,CEXEC_MEMORY_UNPIN };
struct cexec_cmd {
 struct sir_rdv_span memory;
 unsigned memory_operation;
	uint8_t  kind;
	uint8_t  op;
	uint32_t dir;
	uint32_t rkey;
	uint64_t page_idx;
	uint64_t npages;
	uint32_t off;
	uint32_t len;
	uint64_t xaddr;
	uint32_t xrkey;
	uint64_t va;
	uint64_t operand_a;
	uint64_t operand_b;
	uint32_t nspan;
	struct cproto_repair_span span[CONTROL_REPAIR_BATCH_MAX];
	uint8_t  inline_data[CONTROL_PAYLOAD_MAX];
	uint64_t request_id;

	uint64_t session_id;
	int      sym_fd;
};

struct cexec_result {
 unsigned memory_succeeded;
	int32_t  status;
	uint32_t mlen;
	uint64_t old_val;
	uint32_t nspan;
	int32_t  span_status[CONTROL_REPAIR_BATCH_MAX];
	/* set when this span's export range is held by a PIN: the owner releases it
	 * when the request reaches a terminal state (the reverse write has landed,
	 * or the request was abandoned) - never earlier, never twice. */
	uint8_t  span_pinned[CONTROL_REPAIR_BATCH_MAX];
	uint32_t rev_needed;
	uint64_t lease;
	struct creg_owner_view view;
	uint32_t resp_len;
	uint8_t  resp_data[CONTROL_PAYLOAD_MAX];
};

struct cexec {
 struct rdv_bridge_owner *rdv_owners;
 struct rdv_bridge_epoch *rdv_epochs;
	int      inited;
	struct cexec_job job[CONTROL_EXEC_PENDING_MAX];
	uint64_t next_job_id;
	uint32_t used;
	int      fail_closed;
	long     violations;

	pthread_mutex_t mu;
	struct cexec_cmd cmd[CONTROL_EXEC_PENDING_MAX];
	struct cexec_result res[CONTROL_EXEC_PENDING_MAX];

	struct crt_ring ready;
	struct crt_ring cpl;
	uint8_t ready_slots[CRT_RING_BYTES(CONTROL_EXEC_PENDING_MAX,
					   sizeof(struct cexec_ready_ent))]
		__attribute__((aligned(8)));
	uint8_t cpl_slots[CRT_RING_BYTES(CONTROL_EXEC_PENDING_MAX,
					 sizeof(struct cexec_cpl_ent))]
		__attribute__((aligned(8)));

	pthread_mutex_t park_mu;
	pthread_cond_t  park_cv;
	uint32_t parked;

	pthread_t th[CONTROL_EXEC_WORKERS_MAX];
	uint32_t nthreads;
	int      run;
	int      efd;
	long     jobs_done;
	long     jobs_cancelled;

	uint32_t test_delay_us;
	uint32_t test_jitter_us;
	uint32_t test_delay_jobs;
	long     delay_jobs_applied;
};

CRT_INTERNAL void cexec_init(struct cexec *ex);
CRT_INTERNAL int cexec_start(struct cexec *ex, uint32_t workers);
CRT_INTERNAL void cexec_stop(struct cexec *ex);

CRT_INTERNAL void cexec_fini(struct cexec *ex);
CRT_INTERNAL int cexec_event_fd(const struct cexec *ex);

CRT_INTERNAL int cexec_job_admit(struct cexec *ex,
				  enum cexec_job_kind kind, uint32_t dir,
				  uint32_t rkey, uint64_t range_start,
				  uint64_t range_len, uint64_t *job_id);

CRT_INTERNAL int cexec_job_set_cmd(struct cexec *ex, uint64_t job_id,
				    const struct cexec_cmd *cmd);
CRT_INTERNAL int cexec_schedule(struct cexec *ex);

CRT_INTERNAL int cexec_job_cancel(struct cexec *ex, uint64_t job_id);
/* Joined-owner only: no worker can execute an unstarted cancelled command. */
CRT_INTERNAL int cexec_stopped_cancel(struct cexec *ex,uint64_t job_id);
CRT_INTERNAL int cexec_job_claim(struct cexec *ex, uint64_t job_id);
CRT_INTERNAL int cexec_job_finish(struct cexec *ex, uint64_t job_id,
				   int32_t status, uint32_t mlen);

CRT_INTERNAL int cexec_job_release(struct cexec *ex, uint64_t job_id);
CRT_INTERNAL int cexec_job_bind_reverse(struct cexec *ex,
					 uint64_t job_id, uint64_t token);
CRT_INTERNAL int cexec_poll(struct cexec *ex, uint64_t *job_id);
CRT_INTERNAL int cexec_result(struct cexec *ex, uint64_t job_id,
			       struct cexec_result *out);
CRT_INTERNAL uint32_t cexec_pending(struct cexec *ex);
CRT_INTERNAL int cexec_fail_closed(const struct cexec *ex);

CRT_INTERNAL int cexec_job_kind(struct cexec *,uint64_t,enum cexec_job_kind *);
/* Raw memory primitive shared with joined-owner UNPIN only. */
CRT_INTERNAL int cexec_memory_ioctl(const struct sir_rdv_span *,unsigned operation);
CRT_INTERNAL int cexec_job_overlap(const struct cexec_job *a,
				    const struct cexec_job *b);

CRT_INTERNAL int cexec_dependency_conflicts(struct cexec *ex, uint32_t rkey,
					     uint64_t range_start,
					     uint64_t range_len,
					     enum cexec_dep_scope scope);

#endif
