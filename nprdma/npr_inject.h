/* SPDX-License-Identifier: GPL-2.0 */

/*
 * The engine's injection entries.
 *
 * These exist in a test build only. A production build of this library has no
 * way to make a repair fail or a window mapping fail: the two functions do not
 * exist, the call sites compile to their "injection off" answer, and the
 * environment variable names are absent from the binary. A deployment that
 * carries them is a test package, which this build system marks and the
 * deployment chain refuses to install as if it were a production one.
 *
 * Programming mistake, not policy: a call site never branches on the build
 * kind - it calls the entry and gets the honest answer.
 */

#ifndef NPR_INJECT_H
#define NPR_INJECT_H

#include <stdint.h>
#include <stddef.h>
enum npr_repair_gate_state {
 NPR_REPAIR_GATE_IDLE, NPR_REPAIR_GATE_ARMED, NPR_REPAIR_GATE_ENTERED,
 NPR_REPAIR_GATE_RELEASED, NPR_REPAIR_GATE_TIMED_OUT
};

#ifdef NPRDMA_TEST_INJECT

#include "app_qp_binding.h"
struct ibv_qp;
struct npr_test_qp_binding {
 uint64_t cookie,generation,connection_epoch,command_revision;
 uint32_t policy,native_state;
 int local_error;
 struct sir_app_qp_snapshot binding;
};
/* Copy from the loaded library's live registry, never from a carrier-owned
 * replica. Returns zero or positive errno; no mutation or provider call. */
int npr_test_qp_binding_snapshot(struct ibv_qp *,struct npr_test_qp_binding *);

/* Test-library ABI only. Object-lifetime counters are monotonic; live resource
 * counts include retired epochs of this same QP object. A getter never waits
 * for actor/verbs/PIN: actor_stats_valid requires a matching typed snapshot. */
#define NPR_TEST_NATIVE_ABI 1u
struct npr_test_native_qp {
 uint32_t abi,size;
 uint64_t generation,prepared,accepted,claimed,cleanup,canceled,resources,processing,success_cleanup;
};
int npr_test_native_qp_snapshot(struct ibv_qp *,struct npr_test_native_qp *);

/* Separate historical control proof: survives destruction of the CPU QP.
 * Does not change the existing native/RDV getter ABI or grant authorization. */
#define NPR_TEST_CONTROL_ABI 1u
struct npr_test_rdv_control {
 uint32_t abi,size;
 uint64_t started,completed,unmatched,timeouts,aborted;
 uint64_t nonce,cookie,generation,connection_epoch,frontier;
 int result;
};
int npr_test_rdv_control_snapshot(struct npr_test_rdv_control *);

#define NPR_TEST_RDV_ABI 1u
struct npr_test_rdv_qp {
 uint32_t abi,size,policy,data_enabled,actor_stats_valid,native_state;
 uint32_t capability_status;
 uint64_t cookie,generation,connection_epoch,session_id,transport_generation;
 uint64_t virtual_rq_posted,native_rq_posted,source_admitted;
 /* Actual successful wire/native boundaries, never PREPARE queue admission.
  * OFFER/ACK may include retransmission; source_messages_offered is unique. */
 uint64_t source_messages_offered,source_offers_posted,sink_offers_received;
 uint64_t sink_matches,reverse_read_posted,reverse_read_wc,wire_ack_validated;
 uint64_t source_released,sink_released;
 uint64_t queued_rq,matched_rq,terminal_rq;
 uint64_t core_owners,core_captures,core_dup_fds;
 uint64_t actor_sources,actor_sinks,actor_pin_spans,actor_bridge_mrs;
 uint64_t actor_native_outstanding,actor_cleanup_pending;
 uint64_t retired_epochs,retired_core_owners,retired_actor_resources;
};
int npr_test_rdv_qp_snapshot(struct ibv_qp *,struct npr_test_rdv_qp *);
#define NPR_TEST_WWI_PROTOCOL_ABI 1u
struct npr_test_wwi_protocol {
 uint32_t abi,size;
 uint64_t native_send_posted,native_wwi_posted,native_recv_posted,native_recv_done;
 uint64_t wwi_offers_posted,wwi_ready_posted,native_arrivals;
 uint64_t receive_slots,native_outstanding;
};
int npr_test_wwi_protocol_snapshot(struct ibv_qp *,struct npr_test_wwi_protocol *);



/* Exact repair rendezvous for causal ordering tests. All matching requests
 * wait for the same release; the carrier must observe ENTERED before explicitly releasing.
 * Wait is called after suspending the engine API gate, before the RPC begins. */
int npr_fault_repair_gate_arm(uint32_t key, unsigned long page, unsigned timeout_ms);
int npr_fault_repair_gate_wait(uint32_t key, unsigned long page);
int npr_fault_repair_gate_state(void);
int npr_fault_repair_gate_release(void);

/* Read the injection variables; they exist only in this build kind. */
int npr_fault_repair_fail(void);
int npr_fault_window_mmap(void);
int npr_fault_unpin_fail(void);
int npr_fault_unpin_hold(int enabled);

/*
 * Put one page of a freshly adopted MR into a faulted state, from inside the
 * process that owns it.
 *
 * This is the only way to fault a page before the first operation: perftest
 * registers its payload when the peer connects and measures immediately, so no
 * control round trip from outside fits in the window between registration and
 * the first op. `minor` forces the page to the sentinel through the test face's
 * kernel verb (the state authority's own force_page_state, which checks that
 * the caller owns the mm); `major` writes the page out with MADV_PAGEOUT and
 * checks the pagemap's swapped bit. Returns 0 when the page really is in that
 * state, -1 otherwise (never "probably").
 */
int npr_fault_arm_requested(void);
int npr_fault_arm(int mr_id, uintptr_t va, size_t len);

#else

static inline int npr_fault_repair_gate_wait(uint32_t key, unsigned long page)
{ (void)key; (void)page; return 0; }

static inline int npr_fault_repair_fail(void)
{
	return 0;
}

static inline int npr_fault_unpin_fail(void)
{return 0;}

static inline int npr_fault_window_mmap(void)
{
	return 0;
}

static inline int npr_fault_arm_requested(void)
{
	return 0;
}

static inline int npr_fault_arm(int mr_id, uintptr_t va, size_t len)
{
	(void)mr_id; (void)va; (void)len;
	return -1;                /* no injection surface in a production build */
}

#endif /* NPRDMA_TEST_INJECT */

#endif /* NPR_INJECT_H */
