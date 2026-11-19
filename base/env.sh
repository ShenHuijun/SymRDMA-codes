# sym env — probe this machine's RDMA port and write the runtime env file.
# Sourced by base/sym with the user's arguments still in "$@".
#
# Probes: show_gids (GID index <-> IPv4 <-> device), ibv_devinfo (port state,
# active MTU), ip -4 (netdev address), sysfs (PCI address of the device),
# uname, the installed OFED version — merged with $SYM_HOME/install.state.
#
# Red line: the GID's IPv4 must equal the netdev address on this machine; the
# two disagreeing means a stale RoCE configuration and sym exits non-zero.

SYM_ENV_PRINT=0
SYM_ENV_OUT=

while [ "$#" -gt 0 ]; do
	case $1 in
		--print) SYM_ENV_PRINT=1 ;;
		--out)   [ "$#" -ge 2 ] || log_fail "env" "--out needs a path" "usage: sym env [--print] [--out <path>]"
		         SYM_ENV_OUT=$2; shift ;;
		--out=*) SYM_ENV_OUT=${1#--out=} ;;
		*) log_fail "env" "unknown argument: $1" "usage: sym env [--print] [--out <path>]" ;;
	esac
	shift
done

# --- probe -------------------------------------------------------------------

SYM_FLOW=env
require_source_tree "env"
require_state_readable
command -v show_gids >/dev/null 2>&1 || log_fail "env" "show_gids not found" \
	"install the MLNX_OFED user-space tools"
command -v ibv_devinfo >/dev/null 2>&1 || log_fail "env" "ibv_devinfo not found" \
	"install the MLNX_OFED user-space tools"
ls /sys/class/infiniband/* >/dev/null 2>&1 || log_fail "env" \
	"no RDMA device present (/sys/class/infiniband is empty)" "check that mlx5_ib is loaded"

STATE_BDF=""
if [ -r "$SYM_HOME/install.state" ]; then
	STATE_BDF=$(grep -m1 '^SYM_PCI_BDF=' "$SYM_HOME/install.state" | cut -d= -f2-)
fi

# Manual link selection ($SYM_HOME/sym.conf, written by the operator): on a
# host with several RDMA-capable links sym never picks one by itself.
# Optional keys, combinable: SYM_IP=<ipv4> and SYM_NETDEV=<name>.
CONF_IP=""
CONF_NETDEV=""
if [ -r "$SYM_HOME/sym.conf" ]; then
	while IFS= read -r line || [ -n "$line" ]; do
		case $line in
			''|'#'*) continue ;;
			SYM_IP=*)     CONF_IP=${line#SYM_IP=} ;;
			SYM_NETDEV=*) CONF_NETDEV=${line#SYM_NETDEV=} ;;
			*) log_fail "env" "unknown key in $SYM_HOME/sym.conf: ${line%%=*}" \
				"sym.conf accepts SYM_IP=<ipv4> and SYM_NETDEV=<name> only" ;;
		esac
	done < "$SYM_HOME/sym.conf"
	if [ -n "$CONF_IP" ]; then
		printf '%s' "$CONF_IP" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' || \
			log_fail "env" "bad SYM_IP in $SYM_HOME/sym.conf: $CONF_IP" "expected an IPv4 address"
	fi
	if [ -n "$CONF_NETDEV" ]; then
		ip link show dev "$CONF_NETDEV" >/dev/null 2>&1 || \
			log_fail "env" "SYM_NETDEV=$CONF_NETDEV (from $SYM_HOME/sym.conf) does not exist on this host" \
			"list interfaces: ip -o link show"
	fi
fi

# RoCE v2 GID entries: DEV PORT INDEX GID IPv4 VER
CANDIDATES=$(show_gids 2>/dev/null | awk \
	'NF >= 6 && $5 ~ /^[0-9]+\./ && $6 ~ /^v2$/ { print $1, $2, $3, $4, $5 }')

[ -n "$CANDIDATES" ] || log_fail "env" "no ACTIVE RDMA port with a RoCE IPv4 GID" \
	"check the mlx5 driver and port state (show_gids, ibv_devinfo)"

ibdev_bdf() { basename "$(readlink -f "/sys/class/infiniband/$1/device" 2>/dev/null)" 2>/dev/null; }
netdev_bdf() { basename "$(readlink -f "/sys/class/net/$1/device" 2>/dev/null)" 2>/dev/null; }

# netdev -> IPv4 pairs on this machine
ADDRS=$(ip -4 -o addr show 2>/dev/null | awk '$2 != "lo" { split($4, a, "/"); print $2, a[1] }')

MATCHES=
while read -r dev port index gid ip; do
	[ -n "$dev" ] || continue
	if [ -n "$STATE_BDF" ] && [ "$(ibdev_bdf "$dev")" != "$STATE_BDF" ]; then
		continue
	fi
	if [ -n "$CONF_IP" ] && [ "$ip" != "$CONF_IP" ]; then
		continue
	fi
	while read -r ndev nip; do
		[ -n "$ndev" ] || continue
		if [ -n "$CONF_NETDEV" ] && [ "$ndev" != "$CONF_NETDEV" ]; then
			continue
		fi
		if [ "$nip" = "$ip" ] && [ "$(netdev_bdf "$ndev")" = "$(ibdev_bdf "$dev")" ]; then
			MATCHES="$MATCHES$dev $port $index $gid $ip $ndev"$'\n'
		fi
	done <<EOF2
$ADDRS
EOF2
done <<EOF1
$CANDIDATES
EOF1

MATCHES=$(printf '%s' "$MATCHES" | sed '/^$/d')
if [ -n "$CONF_IP" ] && ! printf '%s' "$MATCHES" | grep -q .; then
	log_fail "env" "SYM_IP=$CONF_IP from $SYM_HOME/sym.conf matches no RoCE v2 GID on this host" \
		"probe with show_gids; candidates: $(printf '%s' "$CANDIDATES" | awk '{print $1, $5}' | sort -u | tr '\n' ';')"
fi
CONF_NOTE=""
[ -n "$CONF_IP$CONF_NETDEV" ] && CONF_NOTE=" (filtered by $SYM_HOME/sym.conf)"
[ -n "$MATCHES" ] || log_fail "env" "no ACTIVE RDMA port" \
	"no RoCE GID matches a netdev address${STATE_BDF:+ (installed pci_bdf=$STATE_BDF)}$CONF_NOTE; check the mlx5 driver and port state"

COUNT=$(printf '%s\n' "$MATCHES" | grep -c .)
if [ "$COUNT" -gt 1 ]; then
	log_fail "env" "several RDMA links match ($COUNT candidates); sym does not pick a link by itself" \
		"write SYM_IP=<address> and/or SYM_NETDEV=<name> into $SYM_HOME/sym.conf, then rerun sym env; candidates: $(printf '%s' "$MATCHES" | awk '{print $1, $5, $6}' | sort -u | tr '\n' ';')"
fi
read -r IBDEV PORT GID_INDEX GID_VALUE GID_IP NETDEV <<EOF
$MATCHES
EOF

# --- port facts ---------------------------------------------------------------

INFO=$(ibv_devinfo -d "$IBDEV" -i "$PORT" 2>/dev/null)
PORT_STATE=$(printf '%s\n' "$INFO" | sed -n 's/^[[:space:]]*state:[[:space:]]*\([^[:space:]]*\).*/\1/p' | head -1)
if [ -z "$PORT_STATE" ]; then # older verb stacks: fall back to sysfs
	PORT_STATE=$(sed -n 's/^[0-9]*:[[:space:]]*//p' "/sys/class/infiniband/$IBDEV/ports/$PORT/state" 2>/dev/null | head -1)
fi
[ "$PORT_STATE" = "ACTIVE" ] || [ "$PORT_STATE" = "PORT_ACTIVE" ] || log_fail "env" \
	"$IBDEV port$PORT is ${PORT_STATE:-unknown} (not ACTIVE)" "check the link and the mlx5 driver"
MTU=$(printf '%s\n' "$INFO" | sed -n 's/.*(\([0-9]*\) bytes).*/\1/p' | head -1)
[ -n "$MTU" ] || MTU=$(printf '%s\n' "$INFO" | sed -n 's/.*active_mtu:[[:space:]]*\([0-9]*\).*/\1/p' | head -1)
case $MTU in
	''|*[!0-9]*) log_fail "env" "could not read the active MTU of $IBDEV/$PORT" "run: ibv_devinfo -d $IBDEV" ;;
esac

# --- red line: the GID's IPv4 must be the address carried by its netdev -------

if ! ip -4 addr show dev "$NETDEV" 2>/dev/null | grep -qw "$GID_IP"; then
	log_fail "env" "consistency check failed: GID $GID_INDEX carries $GID_IP but $NETDEV does not" \
		"the RoCE GID and the interface address disagree; fix the address or the GID, then rerun sym env"
fi

# --- merge with the install record --------------------------------------------

state_val() { # state_val <KEY> <fallback>
	local v=""
	if [ -r "$SYM_HOME/install.state" ]; then
		v=$(grep -m1 "^$1=" "$SYM_HOME/install.state" 2>/dev/null | cut -d= -f2-)
	fi
	printf '%s' "${v:-$2}"
}

SYM_MODE_V=$(state_val SYM_MODE "")
SYM_PCI_BDF_V=$(state_val SYM_PCI_BDF "")
SYM_SRC_COMMIT_V=$(state_val SYM_SRC_COMMIT "none")
SYM_SRC_HASH_V=$(src_hash)
SYM_KO_PATH_V=$(state_val SYM_KO_PATH "")
SYM_KO_SHA256_V=$(state_val SYM_KO_SHA256 "")
SYM_KO_SRCVERSION_V=$(state_val SYM_KO_SRCVERSION "")
SYM_SRCVERSION_V=$(state_val SYM_SRCVERSION "$(loaded_srcversion)")
SYM_LOADED_AT_V=$(state_val SYM_LOADED_AT "")
SYM_OFED_PATCHES_V=""
SYM_OFED_FILES_V=$(state_val SYM_OFED_FILES "")
[ -n "$SYM_OFED_FILES_V" ] || SYM_OFED_FILES_V=$(sed -n 's/^file\.//p' "$SYM_ROOT/ofed/BASELINE" | sha256sum | cut -c1-16)
SYM_OFED_ANCHORS_V=$(state_val SYM_OFED_ANCHORS "")
[ -n "$SYM_OFED_ANCHORS_V" ] || SYM_OFED_ANCHORS_V=$(sed -n 's/^anchor\.//p' "$SYM_ROOT/ofed/BASELINE" | sha256sum | cut -c1-16)
if mlx5_params_ok; then
	SYM_MLX5_PARAMS_V=ok
else
	SYM_MLX5_PARAMS_V=missing
fi
if command -v ofed_info >/dev/null 2>&1; then
	OFED_VER=$(ofed_info -s 2>/dev/null | head -1 | tr -d ':')
else
	OFED_VER=""
fi
SYM_OFED_VERSION_V=$(state_val SYM_OFED_VERSION "${OFED_VER:-unknown}")

CONTENT=$(cat <<EOF
# sym.env — SymRDMA runtime configuration for this machine.
# Generated by: ./base/sym env        Source it with:  . <this file>
# Install identity keys are copied from $SYM_HOME/install.state (written by ./base/sym install).

# module load configuration
SYM_MODE=$SYM_MODE_V
SYM_PCI_BDF=$SYM_PCI_BDF_V

# local port coordinates (the peer's coordinates live on the peer)
NP_RDMA_DEV=$IBDEV
SYM_RDMA_NETDEV=$NETDEV
SYM_RDMA_IP=$GID_IP
SYM_RDMA_GID=$GID_INDEX
SYM_RDMA_MTU=$MTU

# install identity
SYM_SRC_COMMIT=$SYM_SRC_COMMIT_V
SYM_SRC_HASH=$SYM_SRC_HASH_V
SYM_KO_PATH=$SYM_KO_PATH_V
SYM_KO_SHA256=$SYM_KO_SHA256_V
SYM_KO_SRCVERSION=$SYM_KO_SRCVERSION_V
SYM_SRCVERSION=$SYM_SRCVERSION_V
SYM_LOADED_AT=$SYM_LOADED_AT_V
SYM_KERNEL_RELEASE=$(uname -r)
SYM_OFED_VERSION=$SYM_OFED_VERSION_V
SYM_OFED_FILES=$SYM_OFED_FILES_V
SYM_OFED_ANCHORS=$SYM_OFED_ANCHORS_V
SYM_MLX5_PARAMS=$SYM_MLX5_PARAMS_V
EOF
)

if [ "$SYM_ENV_PRINT" = 1 ]; then
	printf '%s\n' "$CONTENT"
	exit 0
fi
[ -n "$SYM_ENV_OUT" ] || SYM_ENV_OUT="$SYM_HOME/sym.env"
mkdir -p "$(dirname "$SYM_ENV_OUT")"
tmp=$(mktemp "$(dirname "$SYM_ENV_OUT")/.sym.env.XXXXXX")
printf '%s\n' "$CONTENT" >"$tmp"
mv "$tmp" "$SYM_ENV_OUT"
log_msg "env" "wrote $SYM_ENV_OUT (NP_RDMA_DEV=$IBDEV SYM_RDMA_GID=$GID_INDEX SYM_RDMA_IP=$GID_IP mtu=$MTU)"
