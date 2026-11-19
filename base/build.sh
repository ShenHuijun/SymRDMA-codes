# sym build — verify the OFED lineage, ship the six source files, compile.
# Unprivileged: no sudo anywhere in this flow. Sourced by base/sym with the
# user's arguments still in "$@". The privileged counterpart is sym install.
#
# Stages: ofed/files -> ofed/build -> build

FORCE=             # force=<stage|all>: redo a stage even if its inputs match
OFED_TREE=         # the validated OFED deployment tree (ofed=<dir>)
SKIP_OFED=0        # --skip-ofed: the running stack already carries the changes
KDIR="${KDIR:-/lib/modules/$(uname -r)/build}"
KIND=prod         # kind=prod|test: what this package is for

for a in "$@"; do
	case $a in
		--dry-run)   SYM_DRY_RUN=1 ;;
		--skip-ofed) SKIP_OFED=1 ;;
		ofed=*)      OFED_TREE=${a#ofed=} ;;
		force=*)     FORCE=${a#force=} ;;
		KDIR=*)      KDIR=${a#KDIR=} ;;
		kind=*)      KIND=${a#kind=} ;;
		*) log_fail "build" "unknown argument: $a" "run: sym --help" ;;
	esac
done
case $FORCE in
	""|all|ofed/files|ofed/build|build) ;;
	*) log_fail "build" "unknown force stage: $FORCE" \
		"force is one of: ofed/files, ofed/build, build, all" ;;
esac
case $KIND in
	prod) ;;
	test)
		# the test face is a second module with its own device and injection
		# entries; a tree that ships the production package does not carry it
		[ -f "$SYM_ROOT/kernel/symrdma_test.c" ] ||
			log_fail "build" "kind=test needs the test face (kernel/symrdma_test.c), which this tree does not ship" \
				"build kind=prod (the default)" ;;
	*) log_fail "build" "unknown kind: $KIND" \
		"kind is one of: prod (no test face), test (builds the test face too)" ;;
esac
SYM_BUILD_KIND=$KIND
SYM_FLOW=build
require_source_tree "build"
require_state_readable
check_skip_ofed_gate "build"

log_msg "build" "stages: ofed/files ofed/build build (record: $SYM_STATE)"
stage_ofed_files
save_state
stage_ofed_build
save_state
stage_build
save_state
if [ "${SYM_DRY_RUN:-0}" = 1 ]; then
	if [ "$SYM_PLAN_FAIL" = 1 ]; then
		log_msg "build" "dry run complete: the plan would fail (nothing executed, nothing written)"
		exit 1
	fi
	log_msg "build" "dry run complete: the plan would succeed (nothing executed, nothing written)"
	exit 0
fi
log_msg "build" "done — apply it with: sudo ./base/sym install (record: $SYM_STATE)"
