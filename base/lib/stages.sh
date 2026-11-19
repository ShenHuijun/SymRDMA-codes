# Shared stage implementations for the sym build / sym install commands.
# Sourced by base/build.sh and base/install.sh (which define SYM_DRY_RUN,
# SKIP_OFED, FORCE, ... and the flow); base/lib/log.sh is already loaded.
#
# Stage split:
#   sym build   ofed/files -> ofed/build -> build      (no privileges)
#   sym install deploy -> load                         (privileged)
# The install record ($SYM_HOME/install.state) and the fingerprint chain are
# shared: build feeds deploy, deploy feeds load.

SYM_STATE="$SYM_HOME/install.state"

FP_OFED_FILES=     # fingerprints computed by the stages
FP_OFED_BUILD=
FP_BUILD=
FP_DEPLOY=
FP_LOAD=
SYM_PLAN_FAIL=0        # dry-run bookkeeping: 1 = the plan predicts a failure
SYM_PLAN_BUILD_RUNS=0  # dry-run: will the ofed/build stage actually run?
MLX5_PARAMS_CHANGED=0  # set by ensure_mlx5_params when the file content changes
OFED_COPIED=0          # set by stage_ofed_files when files were copied
OFED_PREVIOUS=""       # pre-copy digests of the last copy (audit)
KO_PATH="$SYM_ROOT/kernel/symrdma.ko"
KO_SHA256=""
KO_SRCVERSION=""
LOAD_RAN=0

plan_fail() { # plan_fail <stage> — mark a dry-run plan as predicted-to-fail
	SYM_PLAN_FAIL=1
}

stage_forced() { # stage_forced <stage> — did the user force this stage?
	[ "${FORCE:-}" = all ] || [ "${FORCE:-}" = "$1" ]
}

# --- record helpers ---------------------------------------------------------

state_read() { # state_read <KEY> — value from the previous install record
	[ -r "$SYM_STATE" ] || return 0
	grep -m1 "^$1=" "$SYM_STATE" 2>/dev/null | cut -d= -f2-
}

hash16() { # hash16 <text...> — short fingerprint of the given text
	printf '%s' "$*" | sha256sum | cut -c1-16
}

src_commit() { # commit of the source tree this tool builds, "none" outside git
	git -C "$SYM_ROOT" rev-parse HEAD 2>/dev/null || printf 'none'
}

require_source_tree() { # require_source_tree <stage> — the repository must be
	# the full product tree; a partial tree (shipping copies only) must fail
	# closed instead of hashing an empty set into the install identity
	local d
	for d in kernel nprdma; do
		[ -d "$SYM_ROOT/$d" ] || log_fail "$1" "source tree incomplete: $SYM_ROOT/$d missing" \
			"run from the repository root (the tree that holds kernel/ nprdma/)"
	done
}

src_hash() { # sha256 over the product sources (kernel nprdma); callers
	# must run require_source_tree first — an empty set hashes to nothing
	(cd "$SYM_ROOT" && find kernel nprdma -type f \
		\( -name '*.c' -o -name '*.h' -o -name 'Makefile' -o -name 'Kbuild' \) 2>/dev/null \
		| LC_ALL=C sort | xargs -r sha256sum 2>/dev/null) | sha256sum | cut -d' ' -f1
}

ofed_version() { # installed OFED version string, best effort
	ofed_info -s 2>/dev/null | head -1 | tr -d ':' || true
}

# --- ofed/BASELINE ----------------------------------------------------------

baseline_value() { # baseline_value <key> — one value from ofed/BASELINE
	grep -m1 "^$1=" "$SYM_ROOT/ofed/BASELINE" 2>/dev/null | cut -d= -f2-
}

baseline_digest() { # baseline_digest <prefix> — digest of all "path=sha" lines
	local prefix=$1
	sed -n "s/^${prefix}\.//p" "$SYM_ROOT/ofed/BASELINE" 2>/dev/null | sha256sum | cut -c1-16
}

shipped_digest() { baseline_digest file; }
anchor_digest() { baseline_digest anchor; }

# shipped_path <real-path> — where the shipped copy of a file lives in this
# repository (ofed/ib_core/modified or ofed/mlx5_ib/modified)
shipped_path() {
	case $1 in
		drivers/infiniband/core/*|include/*) printf '%s/ofed/ib_core/modified/%s' "$SYM_ROOT" "${1##*/}" ;;
		drivers/infiniband/hw/mlx5/*)        printf '%s/ofed/mlx5_ib/modified/%s' "$SYM_ROOT" "${1##*/}" ;;
		*) return 1 ;;
	esac
}

# --- identity-MTT module parameters -----------------------------------------

MLX5_PARAMS_CONF=/etc/modprobe.d/mlx5_ib.conf
# identity_mtt=0 keeps the identity path per-MR (NPRDMA_MR_SYMRDMA bit);
# write_offset 32GiB is the reserved window above the application's address
# space; log_pgsize 31 = 2GiB identity-MTT entries. These values are part of
# the identity-MTT contract, not machine-specific.
MLX5_PARAMS_LINE="options mlx5_ib identity_mtt=0 identity_mtt_write_offset=34359738368 identity_mtt_log_pgsize=31"

mlx5_params_ok() { # are the identity-MTT module parameters in place?
	grep -qsF "$MLX5_PARAMS_LINE" "$MLX5_PARAMS_CONF"
}

ensure_mlx5_params() { # ensure_mlx5_params <stage> — idempotent write of the
	                     # identity-MTT modprobe.d options; sets
	                     # MLX5_PARAMS_CHANGED=1 when the content changes
	MLX5_PARAMS_CHANGED=0
	if mlx5_params_ok; then
		return 0
	fi
	if [ "${SYM_DRY_RUN:-0}" = 1 ]; then
		log_msg "$1" "would write $MLX5_PARAMS_CONF (identity_mtt parameters)"
		MLX5_PARAMS_CHANGED=1
		return 0
	fi
	local tmp
	tmp=$(mktemp)
	printf '%s\n' "$MLX5_PARAMS_LINE" >"$tmp"
	$SUDO install -m 644 "$tmp" "$MLX5_PARAMS_CONF" || {
		rm -f "$tmp"
		log_fail "$1" "could not write $MLX5_PARAMS_CONF" "check permissions"
	}
	rm -f "$tmp"
	MLX5_PARAMS_CHANGED=1
	log_msg "$1" "wrote $MLX5_PARAMS_CONF (identity_mtt=0 identity_mtt_write_offset=34359738368 identity_mtt_log_pgsize=31)"
}

reload_mlx5_for_params() { # reload_mlx5_for_params <stage> — apply changed
	                          # module parameters by reloading mlx5_ib
	local s=$1
	log_msg "$s" "mlx5_ib parameters changed; reloading mlx5_ib before loading symrdma"
	if is_loaded mlx5_ib; then
		$SUDO rmmod mlx5_ib 2>/dev/null || {
			module_holders mlx5_ib "$s"
			log_fail "$s" "mlx5_ib is in use" "stop the holders above, then rerun the command"
		}
	fi
	$SUDO modprobe mlx5_ib || log_fail "$s" "mlx5_ib failed to reload" "check dmesg"
	log_msg "$s" "$(head -1 "$MLX5_PARAMS_CONF" 2>/dev/null)"
}

check_skip_ofed_gate() { # machine check for --skip-ofed: the running stack
	                     # must already carry this project's OFED changes
	[ "${SKIP_OFED:-0}" = 1 ] || return 0
	if ! grep -q ib_umem_get_nopin /proc/kallsyms || [ ! -e /sys/module/mlx5_ib/parameters/identity_mtt ]; then
		if [ "${SYM_DRY_RUN:-0}" = 1 ]; then
			log_msg "${2:-install}" "WOULD FAIL: --skip-ofed needs a running stack that carries this project's OFED changes (ib_umem_get_nopin in kallsyms, identity_mtt in mlx5_ib)"
			plan_fail "${2:-install}"
		else
			log_fail "${2:-install}" "--skip-ofed needs a running stack that carries this project's OFED changes" \
				"the running kernel must expose ib_umem_get_nopin and mlx5_ib must expose identity_mtt; run without --skip-ofed instead"
		fi
	fi
}

# --- fingerprints ------------------------------------------------------------

fp_ofed_files() { hash16 "ofed/files|$(shipped_digest)"; }
fp_ofed_build() { hash16 "ofed/build|$FP_OFED_FILES|make -j$(nproc)|$(uname -r)"; }
fp_build()      { hash16 "build|$SYM_SRC_HASH|$KDIR|kernel nprdma|kind=${SYM_BUILD_KIND:-prod}"; }
fp_deploy()     { hash16 "deploy|$FP_OFED_BUILD|$FP_BUILD|make install + depmod + params|$(uname -r)"; }
fp_load()       { hash16 "load|$KO_SRCVERSION|$MODE|$PCI_BDF|$LOADED_NOW|kind=${SYM_BUILD_KIND:-prod}|${SYM_MODULE_PARAMS:-}|${SYM_TEST_PARAMS:-}"; }

ofed_configured() { # did the user run ./configure for the running kernel?
	grep -q "$(uname -r)" "$OFED_TREE/configure.mk.kernel" 2>/dev/null
}

# --- stage: ofed/files (sym build) -------------------------------------------

stage_ofed_files() {
	local s=ofed/files fp key path want have repo prev prev_list changed
	if [ "$SKIP_OFED" = 1 ]; then
		OFED_TREE=external
		FP_OFED_FILES=external
		log_skip "$s" external
		log_msg "$s" "the running stack is verified to carry the shipped sources (--skip-ofed)"
		return 0
	fi
	if [ -z "$OFED_TREE" ]; then
		log_fail "$s" "no OFED source tree given" \
			"pass ofed=<validated OFED deployment tree>, or --skip-ofed if the running stack already carries the changes"
	fi
	if [ -f "$OFED_TREE" ]; then
		log_fail "$s" "$OFED_TREE is not a directory (archives are not accepted)" \
			"pass the OFED source tree directory (ofed=<dir>)"
	fi
	[ -d "$OFED_TREE" ] || log_fail "$s" "path not found: $OFED_TREE" \
		"pass the validated OFED deployment tree directory"
	OFED_TREE="$(cd "$OFED_TREE" && pwd)"
	if [ ! -f "$OFED_TREE/Makefile" ] || [ ! -d "$OFED_TREE/drivers/infiniband/core" ] \
		|| [ ! -d "$OFED_TREE/drivers/infiniband/hw/mlx5" ]; then
		log_fail "$s" "not an MLNX_OFED kernel source tree: $OFED_TREE" \
			"the tree needs Makefile and drivers/infiniband/{core,hw/mlx5}"
	fi
	# lineage gate: the tree must be the validated deployment tree
	while IFS= read -r entry; do
		key=${entry%%=*}
		path=${key#anchor.}
		want=$(baseline_value "$key")
		have=$(sha256sum "$OFED_TREE/$path" 2>/dev/null | cut -d' ' -f1)
		if [ -z "$have" ]; then
			log_fail "$s" "lineage anchor missing: $OFED_TREE/$path" \
				"supported release: $(baseline_value release) — the tree must be the validated deployment tree (see ofed/README.md)"
		fi
		if [ "$have" != "$want" ]; then
			log_fail "$s" "not the validated deployment tree (release $(baseline_value release)): $OFED_TREE/$path does not match the lineage anchor" \
				"expected $want, found ${have:-nothing}; see ofed/README.md for what tree sym build supports"
		fi
	done < <(sed -n '/^anchor\./p' "$SYM_ROOT/ofed/BASELINE")
	log_msg "$s" "lineage gate passed: $OFED_TREE is the validated deployment tree ($(baseline_value release))"
	fp=$(fp_ofed_files)
	# already in place? (the six files carry the shipped digests)
	changed=0
	while IFS= read -r entry; do
		key=${entry%%=*}
		path=${key#file.}
		want=$(baseline_value "$key")
		have=$(sha256sum "$OFED_TREE/$path" 2>/dev/null | cut -d' ' -f1)
		[ "$have" = "$want" ] || changed=1
	done < <(sed -n '/^file\./p' "$SYM_ROOT/ofed/BASELINE")
	if [ "$changed" -eq 0 ]; then
		# nothing to copy: report skip, never "would copy"
		if [ "$SYM_DRY_RUN" = 1 ]; then
			while IFS= read -r entry; do
				key=${entry%%=*}
				path=${key#file.}
				log_msg "$s" "$path: already carries the shipped source"
			done < <(sed -n '/^file\./p' "$SYM_ROOT/ofed/BASELINE")
		fi
		FP_OFED_FILES=$fp
		if ! stage_forced "$s" && [ "$fp" = "$(state_read SYM_FP_OFED_FILES)" ]; then
			log_skip "$s" "$fp"
		else
			log_msg "$s" "nothing to copy (key=$fp)"
		fi
		return 0
	fi
	if [ "$SYM_DRY_RUN" = 1 ]; then
		while IFS= read -r entry; do
			key=${entry%%=*}
			path=${key#file.}
			want=$(baseline_value "$key")
			have=$(sha256sum "$OFED_TREE/$path" 2>/dev/null | cut -d' ' -f1)
			if [ "$have" = "$want" ]; then
				log_msg "$s" "$path: already carries the shipped source"
			else
				log_msg "$s" "$path: would copy the shipped source over ${have:-<missing>}"
			fi
		done < <(sed -n '/^file\./p' "$SYM_ROOT/ofed/BASELINE")
		log_msg "$s" "would copy and record (key=$fp)"
		FP_OFED_FILES=$fp
		return 0
	fi
	prev_list=""
	while IFS= read -r entry; do
		key=${entry%%=*}
		path=${key#file.}
		want=$(baseline_value "$key")
		repo=$(shipped_path "$path")
		[ -f "$repo" ] || log_fail "$s" "shipped source missing in this repository: $repo" \
			"the repository copy of ofed/ is incomplete"
		have=$(sha256sum "$OFED_TREE/$path" 2>/dev/null | cut -d' ' -f1)
		if [ "$have" != "$want" ]; then
			prev="${have:-none}"
			prev_list="${prev_list}${path}=${prev},"
			cp -f "$repo" "$OFED_TREE/$path" || \
				log_fail "$s" "could not copy the shipped source over $OFED_TREE/$path" \
				"the OFED tree must be writable (copy it somewhere you own)"
			have=$(sha256sum "$OFED_TREE/$path" | cut -d' ' -f1)
			[ "$have" = "$want" ] || log_fail "$s" "copied file does not match the shipped digest: $OFED_TREE/$path" \
				"expected $want, found $have"
			log_msg "$s" "$path: copied over $prev"
			OFED_COPIED=1
		fi
	done < <(sed -n '/^file\./p' "$SYM_ROOT/ofed/BASELINE")
	OFED_PREVIOUS="${prev_list%,}"
	FP_OFED_FILES=$fp
	return 0
}

# --- stage: ofed/build (sym build; make -j only, no privileges) ---------------

stage_ofed_build() {
	local s=ofed/build fp mklog rc f v bad
	if [ "$SKIP_OFED" = 1 ]; then
		FP_OFED_BUILD=external
		log_skip "$s" external
		return 0
	fi
	fp=$(fp_ofed_build)
	if ! stage_forced "$s" && [ -n "$fp" ] && [ "$fp" = "$(state_read SYM_FP_OFED_BUILD)" ]; then
		FP_OFED_BUILD=$fp
		log_skip "$s" "$fp"
		return 0
	fi
	if [ "$SYM_DRY_RUN" = 1 ]; then
		if ! ofed_configured; then
			log_msg "$s" "WOULD FAIL: tree not configured for $(uname -r) (sym never runs ./configure)"
			plan_fail "$s"
		elif ! find "$OFED_TREE" -name '*.ko' -print -quit 2>/dev/null | grep -q .; then
			log_msg "$s" "WOULD FAIL: first build of the OFED tree takes minutes and needs force=ofed/build or an interactive confirmation"
			plan_fail "$s"
		fi
		dry_print "$s" "make -C $OFED_TREE -j$(nproc)"
		log_msg "$s" "would run (key=$fp)"
		FP_OFED_BUILD=$fp
		return 0
	fi
	if ! ofed_configured; then
		log_fail "$s" "OFED tree is not configured for kernel $(uname -r)" \
			"run ./configure in $OFED_TREE first (sym never runs configure)"
	fi
	if ! find "$OFED_TREE" -name '*.ko' -print -quit 2>/dev/null | grep -q .; then
		if ! stage_forced "$s"; then
			if [ -t 0 ]; then
				printf 'sym: %s: first build of the OFED tree takes several minutes. continue? [y/N] ' "$s" >&2
				read -r ans
				case $ans in y|Y|yes|YES) ;; *) log_fail "$s" "first OFED build declined" \
					"rerun with force=ofed/build to allow the multi-minute build" ;; esac
			else
				log_fail "$s" "first build of the OFED tree takes minutes (no build artifacts present)" \
					"allow it with force=ofed/build, or run sym build from a terminal and confirm"
			fi
		fi
		log_msg "$s" "first build: full compile of the OFED tree (several minutes)"
	else
		log_msg "$s" "incremental rebuild of the replaced modules"
	fi
	mklog=$(mktemp)
	log_msg "$s" "building (output tail follows on failure)"
	rc=0
	make -C "$OFED_TREE" -j"$(nproc)" >"$mklog" 2>&1 || rc=$?
	if [ "$rc" -ne 0 ]; then
		tail -25 "$mklog" >&2
		rm -f "$mklog"
		log_fail "$s" "OFED build failed" "see the compiler errors above (missing headers or packages)"
	fi
	rm -f "$mklog"
	bad=0
	while IFS= read -r -d '' f; do
		v=$(modinfo -F vermagic "$f" 2>/dev/null) || continue
		case $v in
			"$(uname -r)"*) ;;
			*) log_msg "$s" "wrong vermagic: ${f#"$OFED_TREE"/} [$v]"; bad=1 ;;
		esac
	done < <(find "$OFED_TREE" -name '*.ko' -print0 2>/dev/null)
	[ "$bad" -eq 0 ] || log_fail "$s" "the OFED tree holds modules built for another kernel" \
		"rebuild the tree for $(uname -r) by hand (make clean && ./configure && make), then rerun"
	FP_OFED_BUILD=$fp
	return 0
}

# --- stage: build (sym build; the SymRDMA module and libraries) ---------------

stage_build() {
	local s=build fp mklog rc d
	fp=$(fp_build)
	if ! stage_forced "$s" && [ -n "$fp" ] && [ "$fp" = "$(state_read SYM_FP_BUILD)" ]; then
		FP_BUILD=$fp
		log_skip "$s" "$fp"
		return 0
	fi
	if [ ! -d "$KDIR" ]; then
		if [ "$SYM_DRY_RUN" = 1 ]; then
			log_msg "$s" "WOULD FAIL: missing kernel build directory $KDIR (install the kernel headers or pass KDIR=<dir>)"
			plan_fail "$s"
		else
			log_fail "$s" "missing kernel build directory: $KDIR" \
				"install the kernel headers for $(uname -r), or pass KDIR=<kernel build dir>"
		fi
	fi
	dry_print "$s" "make -C $KDIR M=$SYM_ROOT/kernel modules BUILD_KIND=$SYM_BUILD_KIND"
	dry_print "$s" "make -C $SYM_ROOT/nprdma BUILD_KIND=$SYM_BUILD_KIND"
	if [ "$SYM_DRY_RUN" = 1 ]; then
		FP_BUILD=$fp
		SYM_PLAN_BUILD_RUNS=1
		log_msg "$s" "would run (key=$fp)"
		return 0
	fi
	for d in kernel nprdma; do
		mklog=$(mktemp)
		rc=0
		if [ "$d" = kernel ]; then
			make -C "$KDIR" M="$SYM_ROOT/kernel" modules \
				BUILD_KIND="$SYM_BUILD_KIND" >"$mklog" 2>&1 || rc=$?
		elif [ "$d" = nprdma ]; then
			make -C "$SYM_ROOT/$d" BUILD_KIND="$SYM_BUILD_KIND" \
				>"$mklog" 2>&1 || rc=$?
		else
			make -C "$SYM_ROOT/$d" >"$mklog" 2>&1 || rc=$?
		fi
		if [ "$rc" -ne 0 ]; then
			tail -25 "$mklog" >&2
			rm -f "$mklog"
			log_fail "$s" "make failed in $d/" "see the errors above (check kernel/OFED headers and libibverbs development files)"
		fi
		rm -f "$mklog"
		log_msg "$s" "$d/: built"
	done
	[ -f "$SYM_ROOT/kernel/symrdma.ko" ] || log_fail "$s" "kernel/symrdma.ko missing after build" \
		"rerun with force=build"
	# the kind decides which modules exist: a production package has no test
	# face to load, and a test package without one is an incomplete build
	if [ "$SYM_BUILD_KIND" = test ]; then
		[ -f "$SYM_ROOT/kernel/symrdma_test.ko" ] || log_fail "$s" \
			"kind=test but kernel/symrdma_test.ko was not built" "rerun with force=build"
	else
		[ -f "$SYM_ROOT/kernel/symrdma_test.ko" ] && log_fail "$s" \
			"kind=prod but kernel/symrdma_test.ko is present (stale test artifact)" \
			"rm kernel/symrdma_test.ko, or build with kind=test on purpose"
	fi
	if [ -f "$KO_PATH" ]; then
		KO_SHA256=$(sha256sum "$KO_PATH" | cut -d' ' -f1)
		KO_SRCVERSION=$(modinfo -F srcversion "$KO_PATH" 2>/dev/null || printf 'unknown')
	fi
	FP_BUILD=$fp
	return 0
}

# --- stage: deploy (sym install; privileged) ----------------------------------

stage_deploy() {
	local s=deploy fp f v
	# the deploy inputs are the recorded build results, not this run's
	FP_OFED_BUILD=${FP_OFED_BUILD:-$(state_read SYM_FP_OFED_BUILD)}
	FP_BUILD=${FP_BUILD:-$(state_read SYM_FP_BUILD)}
	if [ "$SKIP_OFED" = 1 ]; then
		FP_DEPLOY=external
		log_skip "$s" external
		return 0
	fi
	fp=$(fp_deploy)
	if ! stage_forced "$s" && [ -n "$fp" ] && [ "$fp" = "$(state_read SYM_FP_DEPLOY)" ]; then
		FP_DEPLOY=$fp
		log_skip "$s" "$fp"
		return 0
	fi
	if [ "$SYM_DRY_RUN" = 1 ]; then
		local missing=""
		for k in SYM_FP_OFED_BUILD SYM_FP_BUILD SYM_KO_PATH SYM_KO_SRCVERSION; do
			[ -n "$(state_read "$k")" ] || missing="$missing $k"
		done
		if [ -n "$missing" ]; then
			log_msg "$s" "WOULD FAIL: no build record:$missing — run ./base/sym build ofed=<tree> first"
			plan_fail "$s"
			return 0
		fi
		dry_print "$s" "$SUDO make -C ${OFED_TREE:-<tree from the build record>} install"
		dry_print "$s" "$SUDO depmod -a $(uname -r)"
		dry_print "$s" "write $MLX5_PARAMS_CONF (if the identity-MTT parameters changed)"
		dry_print "$s" "reload the IB stack (full-stack: the shipped files include the IB core)"
		log_msg "$s" "would run (key=$fp)"
		FP_DEPLOY=$fp
		return 0
	fi
	require_privilege "$s"
	[ -f "$SYM_ROOT/kernel/symrdma.ko" ] || log_fail "$s" "kernel/symrdma.ko missing" \
		"run: ./base/sym build"
	# the record must prove a complete build: both build-stage fingerprints and
	# the deployed ko identity — a partial record (some stages saved, the build
	# not finished) is not a build record
	local missing=""
	for k in SYM_FP_OFED_BUILD SYM_FP_BUILD SYM_KO_PATH SYM_KO_SRCVERSION; do
		[ -n "$(state_read "$k")" ] || missing="$missing $k"
	done
	[ -z "$missing" ] || log_fail "$s" "no build record:$missing" \
		"run: ./base/sym build ofed=<tree> (it verifies the OFED lineage and compiles the tree)"
	if [ -n "$OFED_TREE" ] && [ "$OFED_TREE" != external ]; then
		[ -f "$OFED_TREE/Makefile" ] || log_fail "$s" "the OFED tree from the build run is not reachable: ${OFED_TREE:-<none>}" \
			"rebuild with: ./base/sym build ofed=<tree> ; or reinstall from the same tree"
	fi
	log_msg "$s" "installing OFED modules into /lib/modules/$(uname -r)/updates"
	$SUDO make -C "$OFED_TREE" install >/dev/null 2>&1 || \
		log_fail "$s" "make install failed" "check the OFED tree and module install paths"
	while IFS= read -r -d '' f; do
		v=$(modinfo -F vermagic "$f" 2>/dev/null) || continue
		case $v in
			"$(uname -r)"*) ;;
			*) log_msg "$s" "removing stale system module: $f [$v]"; $SUDO rm -f "$f" ;;
		esac
	done < <(find "/lib/modules/$(uname -r)/updates" -name '*.ko' -print0 2>/dev/null)
	$SUDO depmod -a "$(uname -r)"
	ensure_mlx5_params "$s"
	log_msg "$s" "full-stack reload (the shipped files include the IB core; existing RDMA processes are interrupted)"
	reload_full_stack "$s"
	FP_DEPLOY=$fp
	return 0
}

reload_full_stack() { # deploy-side: reload the IB stack so the running kernel
	local s=$1 m ok i    # picks up the deployed modules
	log_msg "$s" "stopping RDMA services"
	$SUDO systemctl stop openibd 2>/dev/null || true
	$SUDO fuser -k /dev/infiniband/uverbs* 2>/dev/null || true
	sleep 1
	$SUDO rmmod symrdma 2>/dev/null || true
	for m in rdma_ucm rdma_cm ib_ipoib iw_cm ib_cm ib_umad; do
		$SUDO rmmod $m 2>/dev/null || true
	done
	ok=0
	for i in 1 2 3 4 5; do
		if $SUDO rmmod mlx5_ib 2>/dev/null; then ok=1; break; fi
		sleep 1
	done
	if [ "$ok" != 1 ] && is_loaded mlx5_ib; then
		module_holders mlx5_ib "$s"
		log_fail "$s" "mlx5_ib unload failed (still referenced)" \
			"resolve the holders above (or reboot), then rerun sym install"
	fi
	for m in ib_uverbs ib_umad ib_core mlx5_core mlxdevm mlxfw mlx_compat; do
		$SUDO rmmod $m 2>/dev/null || true
	done
	if is_loaded ib_core || is_loaded mlx5_core || is_loaded ib_uverbs; then
		log_fail "$s" "the IB stack did not unload completely" \
			"check holders: sudo fuser -v /dev/infiniband/* ; or reboot and rerun sym install"
	fi
	for m in mlx5_core ib_core mlx5_ib; do
		modinfo -n "$m" >/dev/null 2>&1 || log_fail "$s" "$m unresolvable after deploy" \
			"depmod did not register the new modules; rerun sym install"
	done
	$SUDO modprobe mlx5_core
	$SUDO modprobe ib_core
	$SUDO modprobe ib_uverbs ib_umad ib_cm iw_cm ib_ipoib rdma_cm rdma_ucm
	$SUDO modprobe mlx5_ib
	grep -q ib_umem_get_nopin /proc/kallsyms || log_fail "$s" \
		"the shipped ib_core is not in effect (no ib_umem_get_nopin in kallsyms)" \
		"the running kernel still uses the stock ib_core; reboot and rerun sym install"
	$SUDO systemctl enable --now openibd 2>/dev/null || true
	log_msg "$s" "IB stack reloaded; symrdma is loaded by the next stage"
}

# --- stage: load (sym install; privileged) ------------------------------------

stage_load() {
	local s=load fp ibdev d state
	if [ -f "$KO_PATH" ]; then
		KO_SHA256=$(sha256sum "$KO_PATH" | cut -d' ' -f1)
		KO_SRCVERSION=$(modinfo -F srcversion "$KO_PATH" 2>/dev/null || printf 'unknown')
	elif [ "$SYM_DRY_RUN" = 1 ]; then
		log_msg "$s" "WOULD FAIL: kernel/symrdma.ko missing"
		plan_fail "$s"
	else
		log_fail "$s" "module not found: $KO_PATH" "run: ./base/sym build"
	fi
	LOADED_NOW=0
	is_loaded && LOADED_NOW=1
	fp=$(fp_load)
	if ! stage_forced "$s" && [ -n "$fp" ] && [ "$fp" = "$(state_read SYM_FP_LOAD)" ]; then
		FP_LOAD=$fp
		log_skip "$s" "$fp"
		return 0
	fi
	if [ "$MODE" = 1 ] && [ -z "$PCI_BDF" ]; then
		if [ "$SYM_DRY_RUN" = 1 ]; then
			log_msg "$s" "WOULD FAIL: mode=1 needs pci_bdf=<domain:bus:dev.fn> (candidates: lspci -D | grep -i mellanox; try sym env --print)"
			plan_fail "$s"
		else
			log_fail "$s" "mode=1 needs the PCI address of the port to attach" \
				"pass pci_bdf=<domain:bus:dev.fn> (candidates: lspci -D | grep -i mellanox; try sym env --print)"
		fi
	fi
	dry_print "$s" "write $MLX5_PARAMS_CONF (if the identity-MTT parameters changed)"
	dry_print "$s" "reload mlx5_ib (only if the parameters changed)"
	dry_print "$s" "$SUDO rmmod symrdma"
	dry_print "$s" "$SUDO insmod $KO_PATH mode=$MODE pci_bdf=$PCI_BDF ${SYM_MODULE_PARAMS:-}"
	if [ "$SYM_BUILD_KIND" = test ]; then
		dry_print "$s" "$SUDO rmmod symrdma_test"
		dry_print "$s" "$SUDO insmod $SYM_ROOT/kernel/symrdma_test.ko ${SYM_TEST_PARAMS:-}"
	fi
	if [ "$SYM_DRY_RUN" = 1 ]; then
		FP_LOAD=$fp
		log_msg "$s" "would run (key=$fp)"
		return 0
	fi
	require_privilege "$s"
	ensure_mlx5_params "$s"
	if [ "$MLX5_PARAMS_CHANGED" = 1 ]; then
		reload_mlx5_for_params "$s"
	fi
	if [ -n "$PCI_BDF" ]; then
		ibdev=""
		for d in /sys/class/infiniband/*; do
			[ -e "$d/device" ] || continue
			[ "$(basename "$(readlink -f "$d/device")")" = "$PCI_BDF" ] && ibdev=$(basename "$d")
		done
		[ -n "$ibdev" ] || log_fail "$s" "no RDMA device matches pci_bdf=$PCI_BDF" \
			"list candidates: ls /sys/class/infiniband/ ; or run: sym env --print"
		state=$(cat "/sys/class/infiniband/$ibdev/ports/1/state" 2>/dev/null || printf '?')
		case $state in
			*ACTIVE*) log_msg "$s" "load gate: $ibdev port1 $state (pci_bdf=$PCI_BDF)" ;;
			*) log_fail "$s" "$ibdev port1 is $state (not ACTIVE)" \
				"bring the link up, or pass the pci_bdf of the ACTIVE port" ;;
		esac
	fi
	# a test face must go before the module it collaborates with
	is_loaded symrdma_test && {
		$SUDO rmmod symrdma_test 2>/dev/null ||
			log_fail "$s" "symrdma_test is in use" "stop its holders, then rerun sym install"
	}
	if is_loaded; then
		$SUDO rmmod symrdma 2>/dev/null || {
			module_holders symrdma "$s"
			log_fail "$s" "symrdma is in use" "stop the holders above, then rerun sym install"
		}
	fi
	$SUDO insmod "$KO_PATH" mode="$MODE" ${PCI_BDF:+pci_bdf="$PCI_BDF"} \
		${SYM_MODULE_PARAMS:-} || \
		log_fail "$s" "insmod failed" "check dmesg (IOMMU enabled? the OFED sources applied?)"
	is_loaded || log_fail "$s" "symrdma missing from /proc/modules after insmod" "check dmesg"
	if [ "$SYM_BUILD_KIND" = test ]; then
		$SUDO insmod "$SYM_ROOT/kernel/symrdma_test.ko" ${SYM_TEST_PARAMS:-} || \
			log_fail "$s" "the test face did not load" \
				"check dmesg: it needs the module under test loaded first"
		is_loaded symrdma_test ||
			log_fail "$s" "symrdma_test missing from /proc/modules after insmod"
		log_msg "$s" "test face loaded (/dev/symrdma_test, ${SYM_TEST_PARAMS:-no injection})"
	fi
	LOAD_RAN=1
	log_msg "$s" "symrdma loaded (mode=$MODE pci_bdf=${PCI_BDF:-none})"
	log_msg "$s" "$(head -4 /proc/symrdma 2>/dev/null | tr '\n' '|')"
	FP_LOAD=$fp
	return 0
}

# --- install record ----------------------------------------------------------
# One writer shape for both commands: every key falls back to the previous
# record when this run does not own it, so build and install each update only
# their own side of the record.

require_state_readable() { # require_state_readable [stage] — a record that
	# exists but cannot be read by the current user must fail closed: identity
	# fields missing from sym.env are untrusted, and a write here would
	# silently replace the record instead of merging into it
	local stage=${1:-${SYM_FLOW:-install}}
	[ -e "$SYM_STATE" ] || return 0
	[ -r "$SYM_STATE" ] || log_fail "$stage" "install record not readable: $SYM_STATE" \
		"run: sudo chown ${SUDO_USER:-$(id -un)} $SYM_STATE, or re-run the privileged command"
}

_ov() { # _ov <KEY> <value> — overlay one key when this run owns a value
	[ -n "${2:-}" ] || return 0
	printf '%s=%s\n' "$1" "$2" >> "${_OV_FILE:?}"
}

save_state() { # save_state — merge this stage's keys into the install record.
	# Read-modify-write: existing lines (including the comment header) pass
	# through untouched; only the keys this run owns are overlaid; new keys are
	# appended. Atomic: temp file + rename in the same directory. Ownership:
	# under sudo the record is handed back to the invoking user (SUDO_UID/
	# SUDO_GID) with mode 0644, which also migrates legacy root-owned records;
	# unprivileged runs keep the existing owner and permissions.
	[ "${SYM_DRY_RUN:-0}" = 1 ] && return 0
	require_state_readable
	local overlay tmp src
	overlay=$(mktemp)
	_OV_FILE=$overlay

	ov() { _ov "$@"; }
	ov SYM_MLX5_PARAMS "$(mlx5_params_ok && echo ok || echo missing)"
	ov SYM_KERNEL_RELEASE "$(uname -r)"
	ov SYM_SRC_COMMIT "$(src_commit)"
	ov SYM_SRC_HASH "$SYM_SRC_HASH"
	ov SYM_OFED_VERSION "$(ofed_version)"
	local files anchors
	case ${SKIP_OFED:-0} in
		1) files=external; anchors=external ;;
		*) files=$(shipped_digest); anchors=$(anchor_digest) ;;
	esac
	ov SYM_OFED_FILES "$files"
	ov SYM_OFED_ANCHORS "$anchors"
	if [ "$SYM_FLOW" = build ]; then
		ov SYM_OFED_TREE "${OFED_TREE:-}"
		ov SYM_OFED_PREVIOUS "${OFED_PREVIOUS:-}"
		ov SYM_KO_PATH "${KO_PATH:-}"
		ov SYM_KO_SHA256 "${KO_SHA256:-}"
		ov SYM_KO_SRCVERSION "${KO_SRCVERSION:-}"
		ov SYM_FP_OFED_FILES "${FP_OFED_FILES:-}"
		ov SYM_FP_OFED_BUILD "${FP_OFED_BUILD:-}"
		ov SYM_FP_BUILD "${FP_BUILD:-}"
		ov SYM_BUILD_KIND "${SYM_BUILD_KIND:-prod}"
	fi
	if [ "$SYM_FLOW" = install ]; then
		ov SYM_SRCVERSION "$(loaded_srcversion)"
		[ "${LOAD_RAN:-0}" = 1 ] && ov SYM_LOADED_AT "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
		ov SYM_MODE "${MODE:-}"
		ov SYM_PCI_BDF "${PCI_BDF:-}"
		ov SYM_FP_DEPLOY "${FP_DEPLOY:-}"
		ov SYM_FP_LOAD "${FP_LOAD:-}"
	fi

	if [ -s "$SYM_STATE" ]; then
		src=$SYM_STATE
	else
		src=/dev/null
	fi
	tmp=$(mktemp "$SYM_HOME/.install.state.XXXXXX")
	if [ "$src" = /dev/null ]; then
		{
			printf '# install.state — SymRDMA install record for this machine\n'
			printf '# Written by ./base/sym build and ./base/sym install; sym.env is generated from it by ./base/sym env.\n'
			cat "$overlay"
		} >"$tmp"
	else
		awk -F= '
			NR==FNR { upd[$1]=$0; next }
			/^#/    { print; next }
			/=/{ k=$1; if (k in upd) { print upd[k]; delete upd[k] } else print; next }
			{ print }
			END { for (k in upd) print upd[k] }
		' "$overlay" "$src" >"$tmp"
	fi
	rm -f "$overlay"
	if [ -n "${SUDO_UID:-}" ]; then
		# privileged write: hand the record back to the invoking user, 0644
		# (this is also the migration path for legacy root-owned records)
		chown "${SUDO_UID}:${SUDO_GID:-$SUDO_UID}" "$tmp" 2>/dev/null || true
		chmod 644 "$tmp"
	elif [ -f "$SYM_STATE" ]; then
		# unprivileged write: keep the existing owner and permissions
		chown "$(stat -c %u "$SYM_STATE" 2>/dev/null):$(stat -c %g "$SYM_STATE" 2>/dev/null)" "$tmp" 2>/dev/null || true
		chmod --reference="$SYM_STATE" "$tmp" 2>/dev/null || chmod 644 "$tmp"
	else
		chmod 644 "$tmp"
	fi
	mv -f "$tmp" "$SYM_STATE"
}

# computed last: needs the helper functions defined above
SYM_SRC_HASH=$(src_hash)
