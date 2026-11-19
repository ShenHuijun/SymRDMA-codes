/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_RUNTIME_H
#define CONTROL_RUNTIME_H

#include <infiniband/verbs.h>

#include <stdint.h>

#include "control_log.h"

struct ctrl_reactor;
struct crdv_registry;

struct crt_cfg {
	/* Borrowed while the SIR service runtime ref is held. NULL means no actor. */
	struct crdv_registry *app_rdv_registry;
	int app_rdv_wake_fd;
	void (*app_rdv_capability_publish)(void *,int);
	void *app_rdv_service_opaque;
	struct ibv_context *ctx;
	struct ibv_pd *pd;
	int      sym_fd;

	char     key[128];
	char     dir[512];
	uint8_t  rdv_kind;
	char     tcp_host[128];
	int      tcp_port;
	int      sgid_index;
	int      inline_max;
	uint32_t workers;
	int      poison_debug;
	uint32_t test_deadline_us;

	uint8_t  test_rd_atom_cap;

	uint32_t test_rnr_hold_us;

};

CRT_INTERNAL struct ctrl_reactor *crt_reactor_new(const struct crt_cfg *cfg);

CRT_INTERNAL int crt_reactor_start(struct ctrl_reactor *r);

CRT_INTERNAL int crt_reactor_stop(struct ctrl_reactor *r);
CRT_INTERNAL void *crt_reactor_main(void *arg);

CRT_INTERNAL int crt_reactor_free(struct ctrl_reactor *r);

CRT_INTERNAL void crt_reactor_bind_sym_fd(struct ctrl_reactor *r, int fd);

CRT_INTERNAL void crt_trace_dump_at_exit(void);

#endif
