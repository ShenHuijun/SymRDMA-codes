/* SPDX-License-Identifier: GPL-2.0 */
#ifndef NPR_QP_CONNECTION_H
#define NPR_QP_CONNECTION_H
#include <infiniband/verbs.h>
#include "app_qp_binding.h"
struct npr_ctx_entry;
struct npr_qp_connection;
struct npr_rdv_qp;
#pragma GCC visibility push(hidden)
/* All calls run under the NPR progress gate. Prepare owns all fallible create
 * storage; commit consumes it after native success without allocation. */
struct npr_qp_connection *npr_qp_connection_prepare(struct npr_ctx_entry *,struct ibv_pd *,unsigned,int);
void npr_qp_connection_abort(struct npr_qp_connection *);
void npr_qp_connection_caps(struct npr_qp_connection *,const struct ibv_qp_cap *,const struct ibv_qp_cap *);
struct npr_rdv_qp *npr_qp_connection_rendezvous(struct npr_qp_connection *);
int npr_qp_connection_modify_prepare(struct npr_qp_connection *,const struct ibv_qp_attr *,int);
void npr_qp_connection_modify_abort(struct npr_qp_connection *);
void npr_qp_connection_progress(void);
void npr_qp_connection_commit(struct npr_qp_connection *,struct ibv_qp *);
struct npr_qp_connection *npr_qp_connection_find(struct ibv_qp *);
int npr_qp_connection_cq_live(const struct ibv_cq *);
int npr_qp_connection_pd_live(const struct ibv_pd *) __attribute__((visibility("hidden")));
int npr_qp_connection_modify_check(struct npr_qp_connection *);
void npr_qp_connection_modified(struct npr_qp_connection *,const struct ibv_qp_attr *,int);
void npr_qp_connection_destroying(struct npr_qp_connection *);
void npr_qp_connection_destroy_failed(struct npr_qp_connection *);
void npr_qp_connection_stopped(struct npr_qp_connection *);
void npr_qp_connection_context_stopped(struct ibv_context *);
int npr_qp_connection_snapshot(struct npr_qp_connection *,struct sir_app_qp_snapshot *);
#pragma GCC visibility pop
#endif
