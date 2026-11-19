# sym install — apply the built tree to this machine and load the module.
# Privileged: everything here needs root (sudo). Sourced by base/sym with the
# user's arguments still in "$@". The unprivileged counterpart is sym build;
# run that first — this flow fails closed when the build record is missing.
#
# Stages: deploy -> load

MODE=              # SYM_MODE: 1 = NIC mode (default), 0 = standalone verify
PCI_BDF=           # SYM_PCI_BDF: <domain:bus:dev.fn> of the port to attach
SKIP_OFED=0        # --skip-ofed: the running stack already carries the changes
FORCE=             # force=<stage|all>: redo a stage even if its inputs match
OFED_FULL=0        # ofed_full=1: force the full-stack module reload
OFED_TREE=         # the tree the build run used (read from the record)
KIND=              # kind=test: acknowledge installing a test package
TEST_PARAMS=       # test_params="demote_fail_grp=2": parameters for the test face
MODULE_PARAMS=     # params="iommu_huge=0": parameters for the module under test

for a in "$@"; do
	case $a in
		--dry-run)   SYM_DRY_RUN=1 ;;
		--skip-ofed) SKIP_OFED=1 ;;
		mode=*)      MODE=${a#mode=} ;;
		pci_bdf=*)   PCI_BDF=${a#pci_bdf=} ;;
		force=*)     FORCE=${a#force=} ;;
		ofed_full=*) OFED_FULL=${a#ofed_full=} ;;
		kind=*)      KIND=${a#kind=} ;;
		test_params=*) TEST_PARAMS=${a#test_params=} ;;
		params=*)    MODULE_PARAMS=${a#params=} ;;
		*) log_fail "install" "unknown argument: $a" "run: sym --help" ;;
	esac
done
case $MODE in
	""|0|1) ;;
	*) log_fail "install" "bad mode: $MODE" "mode is 1 (NIC) or 0 (standalone verify)" ;;
esac
if [ -n "$PCI_BDF" ]; then
	printf '%s' "$PCI_BDF" | grep -Eq '^[0-9a-fA-F]{4}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-9a-fA-F]$' || \
		log_fail "install" "bad pci_bdf: $PCI_BDF" \
		"expected domain:bus:dev.fn (list candidates: lspci -D | grep -i mellanox)"
fi
case $FORCE in
	""|all|deploy|load) ;;
	*) log_fail "install" "unknown force stage: $FORCE" \
		"force is one of: deploy, load, all" ;;
esac
[ "$OFED_FULL" = "1" ] || [ "$OFED_FULL" = "0" ] || \
	log_fail "install" "bad ofed_full: $OFED_FULL" "ofed_full is 0 or 1"
# A package's kind is decided at build time and cannot be overridden here: a
# test package carries a fault-injection face that must not reach a production
# machine, and a production package has no such face to install. So the request
# has to agree with the record, and nothing about the request can add a face.
REC_KIND=$(state_read SYM_BUILD_KIND)
REC_KIND=${REC_KIND:-prod}
case $KIND in
	"")        KIND=$REC_KIND ;;
	prod|test) ;;
	*) log_fail "install" "unknown kind: $KIND" "kind is one of: prod, test" ;;
esac
if [ "$REC_KIND" != "$KIND" ]; then
	log_fail "install" "this build is a $REC_KIND package, not a $KIND one" \
		"build with kind=$KIND first (kind is a property of the package, not an install option)"
fi
SYM_BUILD_KIND=$KIND
SYM_TEST_PARAMS=$TEST_PARAMS
SYM_MODULE_PARAMS=$MODULE_PARAMS
if [ -n "$TEST_PARAMS" ] && [ "$KIND" != test ]; then
	log_fail "install" "test_params given for a prod package" \
		"the test face's parameters exist only in a test package (build with kind=test)"
fi
SYM_FLOW=install
require_source_tree "install"
require_state_readable
check_skip_ofed_gate "install"

MODE=${MODE:-$(state_read SYM_MODE)}
[ -n "$MODE" ] || { MODE=1; log_msg "install" "mode not given: using mode=1 (NIC mode)"; }
PCI_BDF=${PCI_BDF:-$(state_read SYM_PCI_BDF)}
OFED_TREE=$(state_read SYM_OFED_TREE)

log_msg "install" "stages: deploy load (record: $SYM_STATE)"
stage_deploy
save_state
stage_load
save_state
if [ "${SYM_DRY_RUN:-0}" = 1 ]; then
	if [ "$SYM_PLAN_FAIL" = 1 ]; then
		log_msg "install" "dry run complete: the plan would fail (nothing executed, nothing written)"
		exit 1
	fi
	log_msg "install" "dry run complete: the plan would succeed (nothing executed, nothing written)"
	exit 0
fi
log_msg "install" "done (record: $SYM_STATE)"
