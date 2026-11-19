# sym uninstall — unload the symrdma module; --purge also clears the install
# products under $SYM_HOME. Sourced by base/sym with "$@" still set.

PURGE=0
while [ "$#" -gt 0 ]; do
	case $1 in
		--purge)   PURGE=1 ;;
		--dry-run) SYM_DRY_RUN=1 ;;
		*) log_fail "uninstall" "unknown argument: $1" "usage: sym uninstall [--purge] [--dry-run]" ;;
	esac
	shift
done

# a test face must go before the module it collaborates with
if is_loaded symrdma_test; then
	if [ "$SYM_DRY_RUN" = 1 ]; then
		dry_print "uninstall" "$SUDO rmmod symrdma_test"
		log_msg "uninstall" "would unload symrdma_test"
	else
		require_privilege "uninstall"
		if ! $SUDO rmmod symrdma_test 2>/dev/null; then
			module_holders symrdma_test "uninstall"
			log_fail "uninstall" "symrdma_test is in use" \
				"close /dev/symrdma_test holders, then rerun sym uninstall"
		fi
		log_msg "uninstall" "symrdma_test unloaded"
	fi
fi

if is_loaded; then
	if [ "$SYM_DRY_RUN" = 1 ]; then
		dry_print "uninstall" "$SUDO rmmod symrdma"
		log_msg "uninstall" "would unload symrdma"
	else
		require_privilege "uninstall"
		if ! $SUDO rmmod symrdma 2>/dev/null; then
			module_holders symrdma "uninstall"
			log_fail "uninstall" "symrdma is in use" \
				"stop the holders above (or close the MRs), then rerun sym uninstall"
		fi
		is_loaded && log_fail "uninstall" "symrdma still loaded after rmmod" "check dmesg"
		log_msg "uninstall" "symrdma unloaded"
	fi
else
	log_msg "uninstall" "symrdma is not loaded (nothing to unload)"
fi

# the identity-MTT module parameters are written by sym install; remove them
CONF=/etc/modprobe.d/mlx5_ib.conf
if [ -e "$CONF" ]; then
	if [ "$SYM_DRY_RUN" = 1 ]; then
		dry_print "uninstall" "$SUDO rm -f $CONF"
	else
		require_privilege "uninstall"
		$SUDO rm -f "$CONF" && log_msg "uninstall" "removed $CONF"
	fi
else
	log_msg "uninstall" "$CONF not present (nothing to remove)"
fi

if [ "$PURGE" = 1 ]; then
	for f in "$SYM_HOME/install.state" "$SYM_HOME/sym.env"; do
		[ -e "$f" ] || continue
		if [ "$SYM_DRY_RUN" = 1 ]; then
			dry_print "uninstall" "rm $f"
		else
			rm -f "$f"
			log_msg "uninstall" "removed $f"
		fi
	done
	if [ "$SYM_DRY_RUN" != 1 ] && [ -d "$SYM_HOME" ] && [ -z "$(ls -A "$SYM_HOME" 2>/dev/null)" ]; then
		rmdir "$SYM_HOME" 2>/dev/null && log_msg "uninstall" "removed empty $SYM_HOME"
	fi
fi
log_msg "uninstall" "done"
