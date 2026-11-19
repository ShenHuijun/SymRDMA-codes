/* SPDX-License-Identifier: GPL-2.0 */

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "control_trace.h"

/*
 * Dump layout is read by userspace (the probe, and the dev driver through its
 * own parser). Pin the sizes the readers rely on: a layout change must break
 * this build, not silently shift a column in a reader.
 */
_Static_assert(sizeof(struct ctrace_dump_hdr) == 72, "dump header size");
_Static_assert(sizeof(struct ctrace_ev) == 48, "dump record size");
_Static_assert(sizeof(struct ctrace_stat_ent) == 40, "dump stat size");
_Static_assert(offsetof(struct ctrace_dump_hdr, dropped) == 32,
	       "dropped offset");
_Static_assert(offsetof(struct ctrace_dump_hdr, last_ticket) == 48,
	       "last_ticket offset");

struct ctrace_slot {
	uint64_t seq;
	struct ctrace_ev ev;
};

static struct {
	struct ctrace_slot slot[CTRACE_RING_MAX];
	uint64_t ticket;
	uint64_t dumped;
	int      on;
	int      sub;
	int      env_parsed;
	uint64_t stat[CTRACE_STAT_N];
} g_tr;

static __thread struct {
	uint8_t  declared;
	uint8_t  taken;
	int64_t  t_op;
	uint64_t host_sess;
	uint64_t host_req;
	int64_t  host_end;
} t_op;

static const char *const g_phase_name[CTRACE_PHASE_N] = {
	"submit", "credit_wait", "tx_post", "tx_wc", "rx_frame", "admit",
	"dep_wait", "exec_queue", "exec_run", "kernel_pin",
	"reverse_post", "reverse_wc", "resp_post", "resp_wc",
	"caller_wake", "post_verify",
	"detect", "retry_data",
	"sub_ring", "sub_efd", "sub_wake", "sub_reg",
	"wake_match", "wake_signal",
	"pv_wake_run", "pv_verify", "pv_return",
};

struct ctrace_stat_def {
	const char *name;
	uint32_t kind;
};

static const struct ctrace_stat_def g_stat_def[CTRACE_STAT_N] = {
	{ "served",           CTRACE_STAT_INC },
	{ "requested",        CTRACE_STAT_INC },
	{ "wake_sub",         CTRACE_STAT_INC },
	{ "wake_cq",          CTRACE_STAT_INC },
	{ "wake_cpl",         CTRACE_STAT_INC },
	{ "wake_timer",       CTRACE_STAT_INC },
	{ "wake_rdv",         CTRACE_STAT_INC },
	{ "wake_quit",        CTRACE_STAT_INC },
	{ "resp_late",        CTRACE_STAT_INC },
	{ "sessions_failed",  CTRACE_STAT_INC },
	{ "snapshot_applied", CTRACE_STAT_INC },
	{ "peak_inflight",    CTRACE_STAT_MAX },
	{ "dropped",          CTRACE_STAT_INC },
	{ "ioctl_pin",         CTRACE_STAT_INC },
	{ "wake_worker",      CTRACE_STAT_INC },
	{ "wake_caller",      CTRACE_STAT_INC },
	{ "efd_write",        CTRACE_STAT_INC },
	{ "efd_hot_skip",     CTRACE_STAT_INC },
	{ "caller_spin",      CTRACE_STAT_INC },
	{ "wire_tx",          CTRACE_STAT_INC },
	{ "wire_rx",          CTRACE_STAT_INC },
	{ "cq_events",        CTRACE_STAT_INC },
	{ "wc_total",         CTRACE_STAT_INC },
	{ "wc_err",           CTRACE_STAT_INC },
	{ "rearm_fail",       CTRACE_STAT_INC },
};

typedef char ctrace_phase_name_len_check[
	(sizeof(g_phase_name) / sizeof(g_phase_name[0]) == CTRACE_PHASE_N) ?
	1 : -1];
typedef char ctrace_stat_name_len_check[
	(sizeof(g_stat_def) / sizeof(g_stat_def[0]) == CTRACE_STAT_N) ? 1 : -1];

CRT_INTERNAL const char *ctrace_phase_name(uint32_t phase)
{
	return phase < CTRACE_PHASE_N ? g_phase_name[phase] : "?";
}

CRT_INTERNAL const char *ctrace_stat_name(uint32_t stat)
{
	return stat < CTRACE_STAT_N ? g_stat_def[stat].name : "?";
}

CRT_INTERNAL void ctrace_startup(void)
{
	if (g_tr.env_parsed)
		return;
	g_tr.env_parsed = 1;
	{
		const char *e = getenv("SYMRDMA_CTRL_TRACE");
		int lvl = e && e[0] ? atoi(e) : 0;

		g_tr.on = (e && e[0] && e[0] != '0') ? 1 : 0;

		g_tr.sub = (lvl >= 2) ? 1 : 0;
	}
}

CRT_INTERNAL int ctrace_on(void)
{
	return g_tr.on;
}

CRT_INTERNAL int ctrace_sub_on(void)
{
	return g_tr.on && g_tr.sub;
}

CRT_INTERNAL void ctrace_configure_sub(int on)
{
	g_tr.sub = on ? 1 : 0;
}

CRT_INTERNAL void ctrace_configure(int on)
{
	g_tr.env_parsed = 1;
	g_tr.on = on ? 1 : 0;
}

CRT_INTERNAL void ctrace_reset(void)
{
	uint32_t i;

	for (i = 0; i < CTRACE_RING_MAX; i++) {
		__atomic_store_n(&g_tr.slot[i].seq, 0, __ATOMIC_RELEASE);
		memset(&g_tr.slot[i].ev, 0, sizeof(g_tr.slot[i].ev));
	}
	__atomic_store_n(&g_tr.ticket, 0, __ATOMIC_RELEASE);
	__atomic_store_n(&g_tr.dumped, 0, __ATOMIC_RELEASE);

	t_op.declared = 0;
	t_op.taken = 0;
	t_op.t_op = 0;
	t_op.host_sess = 0;
	t_op.host_req = 0;
	t_op.host_end = 0;
	for (i = 0; i < CTRACE_STAT_N; i++)
		__atomic_store_n(&g_tr.stat[i], 0, __ATOMIC_RELEASE);
}

CRT_INTERNAL void ctrace_stat_inc(uint32_t id, uint64_t n)
{
	if (id >= CTRACE_STAT_N)
		return;
	__atomic_fetch_add(&g_tr.stat[id], n ? n : 1, __ATOMIC_RELAXED);
}

CRT_INTERNAL void ctrace_stat_max(uint32_t id, uint64_t v)
{
	uint64_t cur;

	if (id >= CTRACE_STAT_N)
		return;
	cur = __atomic_load_n(&g_tr.stat[id], __ATOMIC_RELAXED);
	while (v > cur) {
		if (__atomic_compare_exchange_n(&g_tr.stat[id], &cur, v, 0,
						__ATOMIC_RELAXED,
						__ATOMIC_RELAXED))
			break;
	}
}

CRT_INTERNAL void ctrace_stat_set(uint32_t id, uint64_t v)
{
	if (id >= CTRACE_STAT_N)
		return;
	__atomic_store_n(&g_tr.stat[id], v, __ATOMIC_RELEASE);
}

CRT_INTERNAL uint64_t ctrace_stat_get(uint32_t id)
{
	if (id >= CTRACE_STAT_N)
		return 0;
	return __atomic_load_n(&g_tr.stat[id], __ATOMIC_ACQUIRE);
}

CRT_INTERNAL uint32_t ctrace_peak_inflight(void)
{
	return (uint32_t)ctrace_stat_get(CTRACE_STAT_PEAK_INFLIGHT);
}

static void ctrace_put(uint16_t phase, uint64_t session_id, uint64_t request_id,
		       uint64_t job_id, uint16_t status, int64_t ts_ns,
		       uint64_t value_ns)
{
	uint64_t t = __atomic_fetch_add(&g_tr.ticket, 1, __ATOMIC_RELAXED);
	struct ctrace_slot *s = &g_tr.slot[t % (uint64_t)CTRACE_RING_MAX];
	uint64_t prev = __atomic_load_n(&s->seq, __ATOMIC_ACQUIRE);

	if (prev && prev > __atomic_load_n(&g_tr.dumped, __ATOMIC_RELAXED))
		ctrace_stat_inc(CTRACE_STAT_DROPPED, 1);
	__atomic_store_n(&s->seq, 0, __ATOMIC_RELEASE);
	s->ev.ts_ns = (uint64_t)ts_ns;
	s->ev.session_id = session_id;
	s->ev.request_id = request_id;
	s->ev.job_id = job_id;
	s->ev.phase = phase;
	s->ev.status = status;
	s->ev.rsv = 0;
	s->ev.value = value_ns;
	__atomic_store_n(&s->seq, t + 1, __ATOMIC_RELEASE);
}

CRT_INTERNAL void ctrace_at(uint16_t phase, uint64_t session_id,
			    uint64_t request_id, uint64_t job_id,
			    uint16_t status, int64_t t0, uint64_t dur_ns)
{
	if (!t0 || !g_tr.on || phase >= CTRACE_PHASE_N)
		return;
	ctrace_put(phase, session_id, request_id, job_id, status, t0, dur_ns);
}

CRT_INTERNAL void ctrace_done(uint16_t phase, uint64_t session_id,
			      uint64_t request_id, uint64_t job_id,
			      uint16_t status, int64_t t0)
{
	int64_t now;

	if (!t0 || !g_tr.on || phase >= CTRACE_PHASE_N)
		return;
	now = crt_now_ns();
	ctrace_put(phase, session_id, request_id, job_id, status, t0,
		   (uint64_t)(now - t0));
}

CRT_INTERNAL int64_t ctrace_op_begin(void)
{
	if (!g_tr.on)
		return 0;
	t_op.declared = 1;
	t_op.taken = 0;
	t_op.t_op = crt_now_ns();
	t_op.host_sess = 0;
	t_op.host_req = 0;
	t_op.host_end = 0;
	return t_op.t_op;
}

CRT_INTERNAL int64_t ctrace_op_take(void)
{
	if (!g_tr.on || !t_op.declared || t_op.taken || !t_op.t_op)
		return 0;
	t_op.taken = 1;
	return t_op.t_op;
}

CRT_INTERNAL void ctrace_op_detect(int64_t t_op_ns, int64_t t_sub,
				   uint16_t status)
{
	if (!g_tr.on || !t_op_ns || !t_sub || t_sub <= t_op_ns)
		return;
	ctrace_at(CTRACE_PHASE_DETECT, 0, 0, 0, status, t_op_ns,
		  (uint64_t)(t_sub - t_op_ns));
}

CRT_INTERNAL void ctrace_op_host(uint64_t session_id, uint64_t request_id,
				 int64_t t_end)
{
	if (!g_tr.on || !request_id || !t_end)
		return;
	t_op.host_sess = session_id;
	t_op.host_req = request_id;
	t_op.host_end = t_end;
}

CRT_INTERNAL void ctrace_op_retry(int64_t t_mark)
{
	int64_t now;

	if (!g_tr.on || !t_mark || !t_op.declared)
		return;
	now = crt_now_ns();
	if (now <= t_mark)
		return;

	if (t_op.host_req && t_op.host_end && now > t_op.host_end)
		ctrace_at(CTRACE_PHASE_POST_VERIFY, t_op.host_sess, t_op.host_req,
			  0, 0, t_op.host_end,
			  (uint64_t)(now - t_op.host_end));
	t_op.host_req = 0;
	t_op.host_sess = 0;
	t_op.host_end = 0;
	ctrace_at(CTRACE_PHASE_RETRY_DATA, 0, 0, 0, 0, t_mark,
		  (uint64_t)(now - t_mark));
}

struct ctrace_rd_ent {
	uint64_t ticket;
	struct ctrace_ev ev;
};

static int ctrace_cmp_ticket(const void *a, const void *b)
{
	const struct ctrace_rd_ent *x = a, *y = b;

	return (x->ticket > y->ticket) - (x->ticket < y->ticket);
}

static int ctrace_write_all(int fd, const void *buf, size_t n)
{
	const char *p = buf;
	size_t off = 0;

	while (off < n) {
		ssize_t w = write(fd, p + off, n - off);

		if (w < 0) {
			if (errno == EINTR)
				continue;
			return -errno;
		}
		off += (size_t)w;
	}
	return 0;
}

int ctrace_dump_hdr_check(const void *buf, size_t len, struct ctrace_dump_hdr *out)
{
	struct ctrace_dump_hdr h;

	if (!buf || len < sizeof(h))
		return -EINVAL;
	memcpy(&h, buf, sizeof(h));
	if (h.magic != CTRACE_DUMP_MAGIC)
		return -EINVAL;
	if (h.version != CTRACE_DUMP_VERSION)
		return -EPROTO;
	if (h.record_size != sizeof(struct ctrace_ev))
		return -EPROTO;
	if (h.hdr_size < sizeof(h))
		return -EPROTO;
	if (out)
		*out = h;
	return 0;
}

CRT_INTERNAL int ctrace_dump(int fd)
{
	struct ctrace_dump_hdr h;
	struct ctrace_rd_ent *ents;
	uint32_t i, n = 0;
	int rc = 0;

	if (fd < 0)
		return -EBADF;
	ents = calloc(CTRACE_RING_MAX, sizeof(*ents));
	if (!ents)
		return -ENOMEM;
	for (i = 0; i < CTRACE_RING_MAX; i++) {
		struct ctrace_slot *s = &g_tr.slot[i];
		uint64_t a = __atomic_load_n(&s->seq, __ATOMIC_ACQUIRE);
		struct ctrace_ev ev;
		uint64_t b;

		if (!a)
			continue;
		memcpy(&ev, &s->ev, sizeof(ev));

		b = __atomic_load_n(&s->seq, __ATOMIC_ACQUIRE);
		if (a != b)
			continue;
		if (ev.rsv != 0 || ev.phase >= CTRACE_PHASE_N)
			continue;
		ents[n].ticket = a - 1;
		ents[n].ev = ev;
		n++;
	}
	if (n > 1)
		qsort(ents, n, sizeof(*ents), ctrace_cmp_ticket);

	memset(&h, 0, sizeof(h));
	h.magic = CTRACE_DUMP_MAGIC;
	h.version = CTRACE_DUMP_VERSION;
	h.record_size = (uint16_t)sizeof(struct ctrace_ev);
	h.phase_n = CTRACE_PHASE_N;
	h.n_records = n;
	h.stat_n = CTRACE_STAT_N;
	h.hdr_size = (uint32_t)sizeof(h);
	h.ring_max = CTRACE_RING_MAX;
	h.dropped = ctrace_stat_get(CTRACE_STAT_DROPPED);
	h.first_ticket = n ? ents[0].ticket : 0;
	h.last_ticket = n ? ents[n - 1].ticket : 0;
	h.first_ts_ns = n ? ents[0].ev.ts_ns : 0;
	h.last_ts_ns = n ? ents[n - 1].ev.ts_ns : 0;

	rc = ctrace_write_all(fd, &h, sizeof(h));
	for (i = 0; rc == 0 && i < CTRACE_PHASE_N; i++) {
		char name[CTRACE_NAME_MAX];

		memset(name, 0, sizeof(name));
		strncpy(name, g_phase_name[i], sizeof(name) - 1);
		rc = ctrace_write_all(fd, name, sizeof(name));
	}
	if (rc == 0 && n) {
		for (i = 0; i < n && rc == 0; i++)
			rc = ctrace_write_all(fd, &ents[i].ev, sizeof(ents[i].ev));
	}
	for (i = 0; rc == 0 && i < CTRACE_STAT_N; i++) {
		struct ctrace_stat_ent se;

		memset(&se, 0, sizeof(se));
		strncpy(se.name, g_stat_def[i].name, sizeof(se.name) - 1);
		se.kind = g_stat_def[i].kind;
		se.value = ctrace_stat_get(i);
		rc = ctrace_write_all(fd, &se, sizeof(se));
	}

	if (n)
		__atomic_store_n(&g_tr.dumped, ents[n - 1].ticket + 1,
				 __ATOMIC_RELEASE);
	free(ents);
	return rc;
}
