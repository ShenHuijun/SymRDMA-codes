/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_SESSION_H
#define CONTROL_SESSION_H

#include <stdint.h>

#include "control_log.h"
#include "control_protocol.h"
#include "control_transport.h"

struct ctrl_reactor;

#define CSESS_CONNECT_TIMEOUT_MS 3500u

enum csess_state {
	CSESS_DOWN = 0,
	CSESS_BOOTSTRAP,
	CSESS_QP_CONNECT,
	CSESS_HANDSHAKE,
	CSESS_SNAPSHOT,
	CSESS_READY,
	CSESS_TEARDOWN,
};

enum csess_fail_reason {
	CSESS_FAIL_CQ_ERROR = 1,
	CSESS_FAIL_BOOTSTRAP_DEADLINE,
	CSESS_FAIL_BOOTSTRAP,
	CSESS_FAIL_TCP_EOF,
	CSESS_FAIL_CRPC_SUBMIT,
	CSESS_FAIL_SNAPSHOT_POST,
	CSESS_FAIL_REQUEST_POST,
	CSESS_FAIL_REVERSE_TIMEOUT,
	CSESS_FAIL_OWNER_COMPLETION,
	CSESS_FAIL_REVERSE_POST,
	CSESS_FAIL_CQ_REARM,
	CSESS_FAIL_ADMISSION,
	CSESS_FAIL_SHUTDOWN,
};

struct csess;

CRT_INTERNAL struct csess *csess_new(struct ctrl_reactor *r);
CRT_INTERNAL void csess_free(struct csess *s);

CRT_INTERNAL uint8_t csess_state(const struct csess *s);
CRT_INTERNAL int csess_ready(const struct csess *s);
CRT_INTERNAL int csess_teardown_active(const struct csess *s);
CRT_INTERNAL uint64_t csess_session_id(const struct csess *s);
CRT_INTERNAL uint32_t csess_window(const struct csess *s);
CRT_INTERNAL uint32_t csess_window_in(const struct csess *s);
CRT_INTERNAL uint32_t csess_rev_window(const struct csess *s);

CRT_INTERNAL uint32_t csess_cap_rev_window(uint32_t rw, uint8_t cap);

CRT_INTERNAL int csess_progress(struct ctrl_reactor *r);

CRT_INTERNAL int csess_kick(struct ctrl_reactor *r);
CRT_INTERNAL void csess_on_timer(struct ctrl_reactor *r);
CRT_INTERNAL int64_t csess_next_deadline_us(const struct csess *s);

CRT_INTERNAL void csess_retry(struct ctrl_reactor *r);

CRT_INTERNAL int csess_rx_hello(struct ctrl_reactor *r,
				 const struct cproto_header *h,
				 const uint8_t *payload, uint32_t plen);
CRT_INTERNAL int csess_rx_snapshot(struct ctrl_reactor *r,
				    const struct cproto_header *h,
				    const uint8_t *payload, uint32_t plen);
CRT_INTERNAL void csess_rx_gate(struct ctrl_reactor *r);

CRT_INTERNAL int csess_rx_hello_gate(struct ctrl_reactor *r);
CRT_INTERNAL int csess_send_snapshot(struct ctrl_reactor *r);
CRT_INTERNAL void csess_mark_export_dirty(struct ctrl_reactor *r);

CRT_INTERNAL void csess_fail(struct ctrl_reactor *r,
			      enum csess_fail_reason reason);

CRT_INTERNAL int csess_teardown_step(struct ctrl_reactor *r);
CRT_INTERNAL void csess_shutdown(struct ctrl_reactor *r);

CRT_INTERNAL int csess_release(struct ctrl_reactor *r);

#endif
