# Shared helpers for the sym entry points: one-line logging, privilege
# checks and module-state queries.
#
# Every diagnostic is a single greppable English line:
#   sym: <stage>: <message>          progress
#   sym: <stage>: skip (key=<key>)   stage skipped, its inputs are unchanged
#   sym: <stage>: <reason> [hint]    failure, exits non-zero

SYM_LOG_PREFIX=sym
SYM_DRY_RUN="${SYM_DRY_RUN:-0}"

log_msg() { # log_msg <stage> <message>
	printf '%s: %s: %s\n' "$SYM_LOG_PREFIX" "$1" "$2"
}

log_skip() { # log_skip <stage> <key>
	printf '%s: %s: skip (key=%s)\n' "$SYM_LOG_PREFIX" "$1" "$2"
}

dry_print() { # dry_print <stage> <command text> — show what a dry run would do
	[ "$SYM_DRY_RUN" = 1 ] || return 0
	printf '%s: %s: + %s\n' "$SYM_LOG_PREFIX" "$1" "$2"
}

log_fail() { # log_fail <stage> <reason> [hint] — one line to stderr, exit 1
	if [ -n "${3:-}" ]; then
		printf '%s: %s: %s [%s]\n' "$SYM_LOG_PREFIX" "$1" "$2" "$3" >&2
	else
		printf '%s: %s: %s\n' "$SYM_LOG_PREFIX" "$1" "$2" >&2
	fi
	exit 1
}

# --- privilege ------------------------------------------------------------

SUDO=sudo
[ "$(id -u)" -eq 0 ] && SUDO=""

require_privilege() { # require_privilege <stage> — must run before the first
	                   # privileged command; fails with a runnable hint
	[ "$(id -u)" -eq 0 ] && return 0
	if [ -t 0 ]; then
		command -v sudo >/dev/null 2>&1 || \
			log_fail "$1" "sudo not found" "run as root instead"
		return 0    # an interactive terminal may prompt for the password
	fi
	if ! sudo -n true 2>/dev/null; then
		log_fail "$1" "sudo unavailable (no terminal and no passwordless sudo)" \
			"run interactively on this host: sudo ./base/sym install mode=1 pci_bdf=<domain:bus:dev.fn>"
	fi
}

# --- module state ---------------------------------------------------------

is_loaded() { # is_loaded [module] — is the module in /proc/modules?
	grep -q "^${1:-symrdma} " /proc/modules 2>/dev/null
}

loaded_srcversion() { # srcversion of the loaded symrdma, empty if not loaded
	cat /sys/module/symrdma/srcversion 2>/dev/null || printf ''
}

module_holders() { # module_holders <module> — print who keeps the module busy
	local mod=$1
	log_msg "${2:-uninstall}" "holders of $mod:"
	if command -v fuser >/dev/null 2>&1; then
		fuser -v /dev/symrdma 2>&1 | sed 's/^/  /'
		fuser -v /dev/infiniband/uverbs* 2>&1 | sed 's/^/  /'
	else
		log_msg "${2:-uninstall}" "fuser not available"
	fi
	grep -i 'active MRs\|pid' /proc/symrdma 2>/dev/null | head -20 | sed 's/^/  /'
}
