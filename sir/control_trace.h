/* SPDX-License-Identifier: GPL-2.0 */

#ifndef CONTROL_TRACE_H
#define CONTROL_TRACE_H

#include <stdint.h>

#include "control_log.h"

#ifndef CTRACE_RING_MAX
#define CTRACE_RING_MAX  65536u
#endif
#define CTRACE_DUMP_MAGIC    0x43545231u
#define CTRACE_DUMP_VERSION  1u
#define CTRACE_NAME_MAX      24u

enum ctrace_phase {
	CTRACE_PHASE_SUBMIT = 0,
	CTRACE_PHASE_CREDIT_WAIT,
	CTRACE_PHASE_TX_POST,
	CTRACE_PHASE_TX_WC,
	CTRACE_PHASE_RX_FRAME,
	CTRACE_PHASE_ADMIT,
	CTRACE_PHASE_DEP_WAIT,
	CTRACE_PHASE_EXEC_QUEUE,
	CTRACE_PHASE_EXEC_RUN,
	CTRACE_PHASE_KERNEL_PIN,
	CTRACE_PHASE_REVERSE_POST,
	CTRACE_PHASE_REVERSE_WC,
	CTRACE_PHASE_RESP_POST,
	CTRACE_PHASE_RESP_WC,
	CTRACE_PHASE_CALLER_WAKE,
	CTRACE_PHASE_POST_VERIFY,
	CTRACE_PHASE_DETECT,
	CTRACE_PHASE_RETRY_DATA,
	CTRACE_PHASE_SUB_RING,

	CTRACE_PHASE_SUB_EFD,
	CTRACE_PHASE_SUB_WAKE,

	CTRACE_PHASE_SUB_REG,
	CTRACE_PHASE_WAKE_MATCH,

	CTRACE_PHASE_WAKE_SIGNAL,

	CTRACE_PHASE_PV_WAKE_RUN,

	CTRACE_PHASE_PV_VERIFY,

	CTRACE_PHASE_PV_RETURN,

	CTRACE_PHASE_N
};

struct ctrace_ev {
	uint64_t ts_ns;
	uint64_t session_id;
	uint64_t request_id;
	uint64_t job_id;
	uint16_t phase;
	uint16_t status;
	uint32_t rsv;
	uint64_t value;
};

enum ctrace_stat {
	CTRACE_STAT_SERVED = 0,
	CTRACE_STAT_REQUESTED,
	CTRACE_STAT_WAKE_SUB,
	CTRACE_STAT_WAKE_CQ,
	CTRACE_STAT_WAKE_CPL,
	CTRACE_STAT_WAKE_TIMER,
	CTRACE_STAT_WAKE_RDV,
	CTRACE_STAT_WAKE_QUIT,
	CTRACE_STAT_RESP_LATE,
	CTRACE_STAT_SESSIONS_FAILED,
	CTRACE_STAT_SNAPSHOT_APPLIED,
	CTRACE_STAT_PEAK_INFLIGHT,
	CTRACE_STAT_DROPPED,
	CTRACE_STAT_IOCTL_PIN,
	CTRACE_STAT_WAKE_WORKER,
	CTRACE_STAT_WAKE_CALLER,
	CTRACE_STAT_EFD_WRITE,
	CTRACE_STAT_EFD_HOT_SKIP,
	CTRACE_STAT_CALLER_SPIN,
	CTRACE_STAT_WIRE_TX,
	CTRACE_STAT_WIRE_RX,

	CTRACE_STAT_CQ_EVENTS,
	CTRACE_STAT_WC_TOTAL,
	CTRACE_STAT_WC_ERR,
	CTRACE_STAT_REARM_FAIL,
	CTRACE_STAT_N
};

enum ctrace_stat_kind {
	CTRACE_STAT_INC = 0,
	CTRACE_STAT_MAX,
	CTRACE_STAT_SET,
};

struct ctrace_stat_ent {
	char     name[CTRACE_NAME_MAX];
	uint32_t kind;
	uint32_t rsv;
	uint64_t value;
};

struct ctrace_dump_hdr {
	uint32_t magic;
	uint16_t version;
	uint16_t record_size;
	uint32_t phase_n;
	uint32_t n_records;
	uint32_t stat_n;
	uint32_t hdr_size;
	uint32_t ring_max;
	uint32_t rsv;
	uint64_t dropped;
	uint64_t first_ticket;
	uint64_t last_ticket;
	uint64_t first_ts_ns;
	uint64_t last_ts_ns;
};

CRT_INTERNAL void ctrace_startup(void);
CRT_INTERNAL int ctrace_on(void);
CRT_INTERNAL void ctrace_configure(int on);

CRT_INTERNAL int  ctrace_sub_on(void);
CRT_INTERNAL void ctrace_configure_sub(int on);
CRT_INTERNAL void ctrace_reset(void);

CRT_INTERNAL int64_t ctrace_op_begin(void);
CRT_INTERNAL int64_t ctrace_op_take(void);
CRT_INTERNAL void ctrace_op_detect(int64_t t_op, int64_t t_sub,
				   uint16_t status);
CRT_INTERNAL void ctrace_op_host(uint64_t session_id, uint64_t request_id,
				 int64_t t_end);
CRT_INTERNAL void ctrace_op_retry(int64_t t_mark);

static inline int64_t ctrace_ts(void)
{
	return ctrace_on() ? crt_now_ns() : 0;
}

CRT_INTERNAL void ctrace_at(uint16_t phase, uint64_t session_id,
			    uint64_t request_id, uint64_t job_id,
			    uint16_t status, int64_t t0, uint64_t dur_ns);

CRT_INTERNAL void ctrace_done(uint16_t phase, uint64_t session_id,
			      uint64_t request_id, uint64_t job_id,
			      uint16_t status, int64_t t0);

CRT_INTERNAL void ctrace_stat_inc(uint32_t id, uint64_t n);
CRT_INTERNAL void ctrace_stat_max(uint32_t id, uint64_t v);
CRT_INTERNAL void ctrace_stat_set(uint32_t id, uint64_t v);
CRT_INTERNAL uint64_t ctrace_stat_get(uint32_t id);

CRT_INTERNAL uint32_t ctrace_peak_inflight(void);

CRT_INTERNAL int ctrace_dump(int fd);
CRT_INTERNAL int ctrace_dump_hdr_check(const void *buf, size_t len,
				      struct ctrace_dump_hdr *out);

CRT_INTERNAL const char *ctrace_phase_name(uint32_t phase);
CRT_INTERNAL const char *ctrace_stat_name(uint32_t stat);

#endif
