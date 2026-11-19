/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_SENDRECV_H
#define NPR_SENDRECV_H
#include <stdint.h>
#include <infiniband/verbs.h>
struct mr_entry;
struct npr_sr_owner;
struct npr_ctx_entry;
struct npr_op;
__attribute__((visibility("hidden"))) int npr_sr_send_submit(struct npr_ctx_entry *, struct ibv_qp *, const struct npr_op *);
__attribute__((visibility("hidden"))) int npr_sr_prepare(struct ibv_qp *, struct ibv_sge *, unsigned, int, struct npr_sr_owner **);
/* Once allocated, *out remains caller-owned even on failure. Attach it to
 * the completion owner before retryable cleanup; NULL means no resources. */
__attribute__((visibility("hidden"))) int npr_sr_prepare_op(struct ibv_qp *, const struct npr_op *, struct ibv_sge *, unsigned, int, struct npr_sr_owner **, int retain_failure);
__attribute__((visibility("hidden"))) int npr_sr_release(void *);
__attribute__((visibility("hidden"))) void npr_sr_progress(void);
__attribute__((visibility("hidden"))) int npr_sr_pd_release(struct ibv_pd *);
/* Reserve a stable MR hold before PIN; even failed preparation owns cleanup. */
__attribute__((visibility("hidden"))) int npr_sr_hold_pin(void *, const struct mr_entry *, uint64_t, uint64_t);
__attribute__((visibility("hidden"))) int npr_sr_owner_create(struct ibv_qp *, struct npr_sr_owner **);
__attribute__((visibility("hidden"))) void npr_sr_discard(struct npr_sr_owner *);
/* MR helpers live beside the private registration metadata. */
__attribute__((visibility("hidden"))) int npr_sr_pin_sge(struct ibv_pd *, const struct ibv_sge *, int, const struct mr_entry **, uint64_t *);
__attribute__((visibility("hidden"))) void npr_sr_mr_put(const struct mr_entry *);
__attribute__((visibility("hidden"))) int npr_sr_mr_get(const struct mr_entry *);
__attribute__((visibility("hidden"))) int npr_sr_unpin(const struct mr_entry *, uint64_t, uint64_t);
#endif
