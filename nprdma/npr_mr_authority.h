/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_MR_AUTHORITY_H
#define NPR_MR_AUTHORITY_H
#include <stdint.h>
#include <stddef.h>
struct npr_mra_registration;
/* Provider identities are compared only; this module never dereferences them,
 * calls verbs, accesses application memory or owns a physical PIN. */
struct npr_mra_spec {
 void *context,*pd;
 uint64_t cpu_base,iova_base,length;
 unsigned access,kind;
 /* Native-only addressing flag whose effective NIC IOVA has not been proven.
  * Keep unavailable across ACCESS-only edits; a verified full translation can
  * supply a new explicit IOVA without inheriting this uncertainty. */
 unsigned iova_unverified;
 void *adopted;
};
enum npr_mra_kind { NPR_MRA_CPU_NATIVE=1,NPR_MRA_CPU_ADOPTED=2 };
enum npr_mra_capture_kind {
 NPR_MRA_KNOWN=1,NPR_MRA_UNKNOWN,NPR_MRA_WRONG_PD,NPR_MRA_UNAVAILABLE
};
enum npr_mra_direction { NPR_MRA_SOURCE=0,NPR_MRA_SINK=1 };
/* Caller-owned, move-only lease: do not copy or share it while releasing. The
 * declared range is intentionally not classified invalid at capture time. */
struct npr_mra_capture {
 struct npr_mra_registration *registration;
 uint64_t generation,address,declared_length;
 enum npr_mra_capture_kind classification;
 /* A concrete use claim is confined to one original range and direction. */
 uint64_t used_offset,used_length;
 unsigned claimed,direction;
};
/* Borrowed view: retain the capture until all use/cleanup has ended. The
 * caller still needs its own provider/PIN/transport lifecycle evidence. */
struct npr_mra_view {
 void *context,*pd,*handle,*adopted;
 uint64_t generation,cpu_address,iova_address,length;
 uint32_t lkey,rkey;
 unsigned access,kind;
};
/* Caller-owned mutation token, also move-only; finish exactly once after the
 * native call. Rereg preallocates a replacement generation before native work. */
struct npr_mra_mutation {
 struct npr_mra_registration *original,*replacement;
 unsigned operation,previous_state;
};
/* Move-only stack guard. begin closes registration admission before any
 * yielding teardown. end(success) invalidates first, then reopens admission;
 * it does not certify DMA stop or free provider resources. pd=NULL covers ctx. */
struct npr_mra_stop_guard {struct npr_mra_stop_guard *next;void *context,*pd;unsigned active;};
struct npr_mra_counts {size_t records,live,leases,mutations;};
#pragma GCC visibility push(hidden)
/* Reserve is itself visible to context/PD busy/stop. Commit/abort consume
 * the reservation; commit never allocates and never resurrects a stopped one.
 * Stop invalidates authorization, but is not proof that provider DMA stopped. */
struct npr_mra_registration *npr_mra_reserve(const struct npr_mra_spec *);
void npr_mra_commit(struct npr_mra_registration *,void *handle,uint32_t lkey,uint32_t rkey);
void npr_mra_abort(struct npr_mra_registration *);
void npr_mra_reservation_adopted(struct npr_mra_registration *,void *adopted);
/* Snapshot only; no lease. The wrapper serializes describe/begin with its API
 * lifecycle gate; begin still arbitrates independently against captures. */
int npr_mra_describe(void *handle,struct npr_mra_spec *);
/* Read-only handle borrow while a control drain yields the API gate. It keeps
 * the original record alive without closing admission or claiming DMA use. */
int npr_mra_borrow_handle(void *handle,struct npr_mra_capture *,struct npr_mra_spec *);
int npr_mra_dereg_begin_borrowed(void *handle,const struct npr_mra_capture *,struct npr_mra_mutation *);
/* out must not already own an unreleased capture. */
int npr_mra_capture(void *context,void *pd,uint32_t lkey,uint64_t address,uint64_t declared_length,struct npr_mra_capture *);
/* Zero used bytes always require no authorization. Nonzero use checks only the
 * requested subrange, original generation, actual access and IOVA translation.
 * This reports authorization; the caller determines native-like WC timing. */
int npr_mra_validate_used(const struct npr_mra_capture *,uint64_t offset,uint64_t used_length,enum npr_mra_direction,struct npr_mra_view *);
int npr_mra_claim_used(struct npr_mra_capture *,uint64_t offset,uint64_t used_length,enum npr_mra_direction,struct npr_mra_view *);
int npr_mra_adopted_busy(void *adopted);
void npr_mra_release(struct npr_mra_capture *);
/* Dereg does not wait for descriptor leases or concrete uses. Provider success
 * kills new authorization; an already claimed use retains only its exact range.
 * Native failure restores the original record without retiring private storage. */
int npr_mra_dereg_begin(void *handle,struct npr_mra_mutation *);
void npr_mra_dereg_finish(struct npr_mra_mutation *,int native_result);
void npr_mra_dereg_finish_closing(struct npr_mra_mutation *,int native_result,int irreversible);
/* Rereg begin: zero or IBV_REREG_MR_ERR_INPUT (-1), with errno. Proposed
 * translation/access/PD already reflects the caller's CHANGE_* flags. Finish
 * takes native ABI 0/-1..-5 plus actual resulting provider keys. No allocation
 * occurs after native work. Unexpected results fail closed as invalid. */
int npr_mra_rereg_begin(void *handle,const struct npr_mra_spec *,struct npr_mra_mutation *);
void npr_mra_rereg_finish(struct npr_mra_mutation *,int native_result,uint32_t lkey,uint32_t rkey);
int npr_mra_stop_begin(void *context,void *pd,struct npr_mra_stop_guard *);
void npr_mra_stop_end(struct npr_mra_stop_guard *,int native_success);
void npr_mra_context_stopped(void *context);
void npr_mra_pd_stopped(void *pd);
int npr_mra_context_busy(void *context);
int npr_mra_pd_busy(void *pd);
int npr_mra_pd_registered(void *pd) __attribute__((visibility("hidden")));
void npr_mra_get_counts(struct npr_mra_counts *);
#pragma GCC visibility pop
#endif
