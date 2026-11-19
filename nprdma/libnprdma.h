
#ifndef _LIBNPRDMA_H
#define _LIBNPRDMA_H

#include "symrdma_abi.h"

/* Software ordering hints for supported RC READ/WRITE/WRITE_WITH_IMM/CAS/FAA
 * through legacy send_flags or qp_ex wr_flags. BEFORE waits for earlier
 * supported operations on the same QP; AFTER holds later ones through repair.
 * The library consumes these bits before posting to the provider. */
#define SYMRDMA_ORDER_BEFORE (1u << 28)
#define SYMRDMA_ORDER_AFTER  (1u << 29)

#define NPRDMA_ENGINE_STAT_LIST(X) \
	X(TAKEN_READ, "taken_read", "<4KB read taken via sentinel/aux axis") \
	X(TAKEN_WRITE, "taken_write", "<4KB write taken via aux read-back axis") \
	X(TAKEN_WWI, "taken_wwi", "with-immediate taken via translation") \
	X(TAKEN_ATOMIC, "taken_atomic", "remote atomic taken via SIR RPC") \
	X(PASS_NO_ENGINE, "pass_no_engine", "pass: no engine on this context") \
	X(PASS_MULTI_SGE, "pass_multi_sge", "pass: multi-SGE over IR limit") \
	X(PASS_NO_EXPORT, "pass_no_export", "pass: MR not exported (no peer / not adopted)") \
	X(PASS_OUT_OF_RANGE, "pass_out_of_range", "pass: outside exported range") \
	X(PASS_UNSIGNED_WWI, "pass_unsigned_wwi", "pass: unsignaled WITH_IMM (imm timing anchor)") \
	X(PASS_UNSIGNED_BIG_WRITE, "pass_unsigned_big_write", "pass: ≥4KB unsignaled write (repair-carrier data source not settled)") \
	X(PASS_WRITE_TOO_LARGE, "pass_write_too_large", "pass: write over decision-domain bound") \
	X(PASS_READ_TOO_LARGE, "pass_read_too_large", "pass: read over decision-domain bound") \
	X(PASS_ATOMIC_FORM, "pass_atomic_form", "pass: unsupported atomic form") \
	X(TAKEN_SEQLOCK_READ, "taken_seqlock_read", "≥4KB read via remote seqlock") \
	X(TAKEN_SEQLOCK_WRITE, "taken_seqlock_write", "≥4KB write via remote seqlock") \
	X(PASS_NO_VERSION, "pass_no_version", "pass: ≥4KB but export has no version table") \
	X(AUX_UNAVAILABLE, "aux_unavailable", "a delivery axis could not be taken (aux readback / version read) — the op is delivered as an error WC, never claimed clean") \
	X(PASS_BATCH_UNAVAILABLE, "pass_batch_unavailable", "batch surface unavailable → explicit pass") \
	X(QP_DESTROY, "qp_destroy", "QP destroy convergence complete") \
	X(QP_REBORN, "qp_reborn", "same pointer reused → clean state reallocated") \
	X(QP_FLUSH_TIMEOUT, "qp_flush_timeout", "destroy convergence timeout → residual entries dropped fail-closed") \
	X(CQ_DESTROY_INFLIGHT, "cq_destroy_inflight", "entries still in flight at CQ destroy (usage violation)") \
	X(BATCH_OPEN, "batch_open", "new batch opened") \
	X(BATCH_CLOSE, "batch_close", "closed (incl. split / barrier / destroy close-out)") \
	X(BATCH_SPLIT, "batch_split", "hit bound / crossed export → close in place, split batch") \
	X(BATCH_BARRIER, "batch_barrier", "mirror busy → bounded barrier at commit point") \
	X(BATCH_OPS, "batch_ops", "members packed into batch (cumulative)") \
	X(BATCH_BYTES, "batch_bytes", "member bytes packed into batch (cumulative)") \
	X(BATCH_COVER_APP, "batch_cover_app", "cover = next signaled app op") \
	X(BATCH_COVER_AUX, "batch_cover_aux", "cover = engine-initiated batch aux READ") \
	X(BATCH_DROPPED, "batch_dropped", "dropped (incl. destroy) — not counted as verified") \
	X(BATCH_MISS_PAGES, "batch_miss_pages", "pages judged missing (cumulative)") \
	X(BATCH_REPAIR_OK, "batch_repair_ok", "repair carrier successes") \
	X(BATCH_REPAIR_FAIL, "batch_repair_fail", "repair failed / budget exhausted (escalate)") \
	X(BATCH_INVARIANT, "batch_invariant", "batch pool / batch accounting invariant violation (fail-closed)") \
	X(BATCH_GAP_BYTES, "batch_gap_bytes", "span bytes not covered by members (observability)") \
	X(BATCH_WRITE_BARRIER, "batch_write_barrier", "non-member write intersects batch range → close out first + wait") \
	X(BATCH_COVER_BAD, "batch_cover_bad", "app WC landing on cover after batch verify failure") \
	X(EX_INSTALL, "ex_install", "QPs with recorder installed") \
	X(EX_TAKEOVER, "ex_takeover", "ops taken over by engine on ex surface") \
	X(EX_REPLAY, "ex_replay", "ops not taken on ex surface replayed via original setter") \
	X(EX_UNSUPPORTED, "ex_unsupported", "recorded but not replayable (fail-closed)") \
	X(EX_OVERFLOW, "ex_overflow", "session over limit (fail-closed, ENOBUFS)") \
	X(LOCAL_SINK_ABSENT, "local_sink_absent", "read sink page sat on the sentinel mapping at delivery (DMA dropped)") \
	X(LOCAL_SINK_CHANGED, "local_sink_changed", "read sink page transitioned inside the op window (DMA may be dropped)") \
	X(LOCAL_SINK_PIN_FAIL, "local_sink_pin_fail", "repair window could not be pinned (fail-closed: no pin, no repair)") \
	X(LOCAL_SINK_TRANSITION, "local_sink_transition", "a pinned sink page moved inside the window (landing spot is not the app page - re-verify)") \
	X(PRE_PIN_TAKEN, "pre_pin_taken", "pre-check found a local page on the sentinel mapping and held it across the transfer") \
	X(PRE_PIN_FAIL, "pre_pin_fail", "pre-check could not take the hold (counted: the op is still posted, never claimed verified)") \
	X(PRE_SNAP_ORDER, "pre_snap_order", "a v1 snapshot predates the pre-check PIN (pinned page read even) - snapshot dropped, delivery degraded") \
	X(HOLD_EVICT, "hold_evict", "no completion arrived for a held wr_id - the oldest hold was released (bounded table)") \
	X(PASS_NO_WRITE_KEY, "pass_no_write_key", "pass: write op on an export without a write key (read-only MR) - the posting face rejects it") \
	X(CARRIER_AMBIGUOUS_WRITE, "carrier_ambiguous_write", "write whose expected bytes collide with the sentinel sample → carried, never posted optimistically") \
	X(CARRIER_AMBIGUOUS_BATCH, "carrier_ambiguous_batch", "unsignaled batch member carried instead of packed (its readback could not tell a drop from a match)") \
	X(CARRIER_SOURCE_PIN_FAIL, "carrier_source_pin_fail", "carrier could not hold the write source (fail-closed: no hold, no landing claim)") \
	X(CARRIER_STICKY_ERR, "carrier_sticky_err", "an unsignaled carrier failed and had no WC of its own — the next signaled completion on the QP reports it") \
	X(AMBIGUOUS_WWI, "ambiguous_wwi", "with-immediate whose expected bytes collide and has no imm carrier → fail-closed") \
	X(WRITE_NO_WKEY, "write_no_wkey", "write op targeted a managed MR that has no write view - rejected (EINVAL) fail-closed; the read key is never a write key") \
	X(WRITE_KEY_FOREIGN, "write_key_foreign", "write op carried a key nobody here can resolve (a bare app's out-of-band key) - posted as the app chose") \
	X(EXPORT_WREG_FAIL, "export_wreg_fail", "WREG auxiliary MR registration failed - the MR gets no write export (fail-closed)")

enum nprdma_engine_stat {
#define NPRDMA_ES_ENUM(k, n, d) NPRDMA_ES_##k,
	NPRDMA_ENGINE_STAT_LIST(NPRDMA_ES_ENUM)
#undef NPRDMA_ES_ENUM
	NPRDMA_ES_MAX,
};

struct nprdma_engine_stats {
	unsigned long v[NPRDMA_ES_MAX];
};

const char *nprdma_engine_stat_name(enum nprdma_engine_stat s);
const char *nprdma_engine_stat_desc(enum nprdma_engine_stat s);

int nprdma_engine_stats_get(struct nprdma_engine_stats *out);

int nprdma_engine_stats_dump(int fd);

/*
 * Census over the kernel MR that backs this address range (the page-state
 * judgement, mode 0: decide only, no side effects).
 *
 * `cookie` is the interval bound taken at the end of the scan and
 * `max_cause_seq` the newest transition among the addressed pages, so a caller
 * can close a window: every transition inside it has cause_seq <= the cookie it
 * took when the window opened. `not_ok` counts pages whose verdict is not "the
 * page serves real bytes" - the number a fault-free window must see at zero.
 *
 * Returns 0, or -1 with errno when the range is not inside a kernel MR this
 * process owns (which is the honest answer, not a silent zero).
 */
struct nprdma_census {
	uint64_t cookie;
	uint64_t max_cause_seq;
	uint32_t pages;
	uint32_t not_ok;
};

int nprdma_census_scan(const void *addr, size_t len, struct nprdma_census *out);

/*
 * The per-page face of the same census walk: one row per page, unmerged.
 *
 * nprdma_census_scan folds the walk into one `not_ok` number, and that fold
 * is the wrong shape for a gate that has to tell "the page is absent (a fault
 * this system repairs)" from "the page cannot be mapped at all"
 * (UNMAPPABLE / SPECIAL / ERROR): the fold counts both the same way, so a
 * range full of unusable pages reads exactly like a range waiting for its
 * repair. This face hands the verdicts over unmerged; telling them apart is
 * the caller's gate, and a verdict the caller does not recognise is never
 * allowed to pass for an absent page.
 *
 * `rows` must hold one slot per page of the range; `max` bounds it. A range
 * larger than the buffer fails with ENOSPC rather than coming back silently
 * truncated. Returns the number of rows filled, or -1 with errno (EINVAL for
 * bad arguments, ENOENT when the range is not inside a kernel MR this process
 * owns, ioctl/read failures as they are).
 */
long nprdma_census_pages(const void *addr, size_t len,
			 struct symrdma_census_page *rows, unsigned long max);

#endif
