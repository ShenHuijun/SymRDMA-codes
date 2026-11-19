/* SPDX-License-Identifier: GPL-2.0 */

#ifndef LIBSIR_H
#define LIBSIR_H

#include <stdint.h>
#include <stddef.h>
#include <infiniband/verbs.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SIR_INLINE_MAX    1024
#define SIR_INLINE_LIMIT  4012u
#define SIR_PAGE_SIZE     4096

#define SIR_RANGE_MAX     65536ULL

#define SIR_DIR_DEFAULT   "/tmp/symrdma_sir_auto"

#define SIR_F_READ        1
#define SIR_F_WRITE       2
#define SIR_F_ATOMIC_CAS  4
#define SIR_F_ATOMIC_FAA  8
#define SIR_F_BATCH       16

#include "repair_span.h"

struct sir_export {
	uint32_t app_rkey;
	uint32_t app_access;
	uint32_t data_rkey;
	uint32_t write_rkey;
	uint64_t addr;
	uint64_t len;
	uint32_t v_rkey;
	uint64_t v_addr;
	int      mr_id;
	uint32_t lkey;

};

/* Hidden, nonblocking metadata registration; no reactor startup or network. */
__attribute__((visibility("hidden"))) void sir_app_rdv_wake(void *);
/* 0: current HELLO supports DATA, EAGAIN: not yet known, EOPNOTSUPP:
 * current HELLO explicitly lacks DATA. Never waits for actor/network. */
__attribute__((visibility("hidden"))) int sir_app_rdv_capability(void);
struct crdv_registration_config;
struct crdv_registration;
__attribute__((visibility("hidden"))) int sir_app_rdv_register(
 const struct crdv_registration_config *,struct crdv_registration **);
__attribute__((visibility("hidden"))) int sir_app_rdv_registration_free(struct crdv_registration *);

int sir_init(struct ibv_context *ctx, struct ibv_pd *pd,
	     const char *key, int sym_fd);

int  sir_export_add(const struct sir_export *e);
void sir_export_del(uint32_t data_rkey);
void sir_export_del_wkey(uint32_t write_rkey);

int  sir_remote_lookup(uint32_t data_rkey, struct sir_export *out);
/* No connect/RPC; caller keeps the application lifecycle gate held. */
__attribute__((visibility("hidden"))) int sir_remote_lookup_cached(uint32_t, struct sir_export *);
/* Internal authority query: ENOENT is peer NOTFOUND; ENODEV means no
 * configured peer. Other errors never authorize native-key passthrough. */
__attribute__((visibility("hidden"))) int sir_remote_lookup_authoritative(uint32_t, struct sir_export *);

int  sir_ensure_start(void);

int sir_remote_repair(uint32_t data_rkey, unsigned long page_idx, int dir,
		      uint32_t off, uint32_t len, void *data);

int sir_remote_repair_x(uint32_t data_rkey, unsigned long page_idx,
			unsigned long npages, int dir,
			uint64_t xaddr, uint32_t xrkey,
			uint32_t xoff, uint32_t xlen);

int sir_remote_repair_batch(uint32_t data_rkey,
			    const struct sir_repair_span *spans, uint32_t nspan,
			    uint8_t *span_status);

int sir_remote_atomic(uint32_t data_rkey, uint64_t va, int op,
		      uint64_t compare, uint64_t swap_or_add, uint64_t *old_out);

int sir_inline_max(void);

void sir_fini(void);
/* Called only after all application children of this PD have retired.
 * Positive means the service now owns the native handle; negative is errno. */
__attribute__((visibility("hidden"))) int sir_take_pd(struct ibv_pd *);
__attribute__((visibility("hidden"))) void sir_pd_closed(const struct ibv_pd *);
__attribute__((visibility("hidden"))) void sir_fini_context(const struct ibv_context *);
__attribute__((visibility("hidden"))) void sir_context_closed(const struct ibv_context *);
/* Survive session teardown until every native object and epoch borrow has
 * retired. A software reference alone must never permit freeing its PD/ctx. */
__attribute__((visibility("hidden"))) int sir_transport_pd_busy(const struct ibv_pd *);
__attribute__((visibility("hidden"))) int sir_transport_ctx_busy(const struct ibv_context *);

/* Borrow under the application API gate. The native MR created on this PD
 * must retire before context teardown; its provider reference also prevents
 * premature native PD deallocation. */
__attribute__((visibility("hidden"))) int sir_carrier_pd(struct ibv_context *, struct ibv_pd **);

int  sir_ping(uint32_t timeout_ms);

int  sir_is_connected(void);
long sir_service_count(void);

uint32_t sir_peak_inflight(void);

void sir_op_trace_begin(void);

int64_t sir_op_trace_mark(void);

void sir_op_trace_retry(int64_t t_mark);

#ifdef __cplusplus
}
#endif

#endif
