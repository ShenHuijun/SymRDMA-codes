/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_PROGRESS_H
#define NPR_PROGRESS_H
#include <infiniband/verbs.h>
#ifdef NPR_PROGRESS_INTEGRATED
#pragma GCC visibility push(hidden)
void npr_progress_lock(void);
void npr_progress_unlock(void);
unsigned npr_progress_wait_begin(void);
void npr_progress_wait_end(unsigned);
void npr_progress_quiesce(void);
int npr_progress_submit(void (*)(void *), void *);
int npr_progress_submit_for(struct ibv_cq *, void (*)(void *), void *);
void npr_progress_cq_drained(struct ibv_cq *);
void npr_progress_cq_observed(struct ibv_cq *);
uint64_t npr_progress_owner_begin(struct ibv_cq *);
void npr_progress_owner_end(uint64_t);
void npr_progress_owner_end_inline_clean(uint64_t);
int npr_progress_start(void (*)(void));
void npr_progress_wake(void);
int npr_progress_cq_autonomous_begin(struct ibv_cq *);
void npr_progress_cq_autonomous_end(struct ibv_cq *);
int npr_progress_cq_caller_driven(struct ibv_cq *);
/* API-gate held; earliest absolute CLOCK_MONOTONIC deadline for this pump. */
void npr_progress_deadline(uint64_t);
void npr_progress_internal_begin(void);
void npr_progress_internal_end(void);
int npr_progress_internal(void);
int npr_progress_channel_is_proxy(struct ibv_comp_channel *);
struct ibv_comp_channel *
npr_progress_cq_provider_channel(struct ibv_context *,
				 struct ibv_comp_channel *);
struct ibv_comp_channel *npr_progress_cq_native_channel(struct ibv_cq *);
void npr_progress_cq_prepare_cancel(struct ibv_context *,
				    struct ibv_comp_channel *,
				    struct ibv_comp_channel *);
struct ibv_comp_channel *
npr_progress_provider_channel(struct ibv_comp_channel *);
int npr_progress_cq_attach(struct ibv_cq *, struct ibv_comp_channel *, void *);
int npr_progress_cq_can_destroy(struct ibv_cq *);
void npr_progress_cq_detach(struct ibv_cq *);
void npr_progress_cq_destroy_abort(struct ibv_cq *);
void npr_progress_context_closed(void *);
int npr_progress_notify(struct ibv_cq *, int);
void npr_progress_ready(struct ibv_cq *);
#pragma GCC visibility pop
#else
#include <errno.h>
static inline void npr_progress_lock(void) {}
static inline void npr_progress_unlock(void) {}
static inline void npr_progress_wake(void) {}
static inline int npr_progress_cq_autonomous_begin(struct ibv_cq *c) {(void)c;return 0;}
static inline void npr_progress_cq_autonomous_end(struct ibv_cq *c) {(void)c;}
static inline int npr_progress_cq_caller_driven(struct ibv_cq *c) {(void)c;return 0;}
static inline void npr_progress_deadline(uint64_t ns) { (void)ns; }
static inline void npr_progress_ready(struct ibv_cq *cq) { (void)cq; }
static inline void npr_progress_cq_observed(struct ibv_cq *cq) { (void)cq; }
static inline int npr_progress_internal(void) { return 0; }
static inline uint64_t npr_progress_owner_begin(struct ibv_cq *cq)
{
	(void)cq;
	return 0;
}
static inline void npr_progress_owner_end(uint64_t t) { (void)t; }
static inline void npr_progress_owner_end_inline_clean(uint64_t t) { (void)t; }
static inline unsigned npr_progress_wait_begin(void) { return 0; }
static inline void npr_progress_wait_end(unsigned d) { (void)d; }
static inline int npr_progress_submit(void (*cb)(void *), void *arg)
{
	(void)cb;
	(void)arg;
	return -ENOSYS;
}
#endif
#endif
