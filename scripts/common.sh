#!/bin/bash
# SymRDMA 开发脚本 — 公共库
# 来源: source "$(dirname "$0")/common.sh" (tests/ 下为 source .../../../scripts/common.sh)
#
# 内容: 目标机器 / SSH 参数与连接工具 (ssh_run/ssh_host/ssh_bash/ssh_put) /
#       远端脚本推送与模板渲染 (push_remote_script/render_template, 模板在
#       scripts/remote/) / 通用小工具 (die/symrdma_mr_count/pct_delta) /
#       双机测试床拓扑默认值 / 本地与远端路径。
# 各机器实况/操作手册见 env/ (独立 git 仓库, 不入库)。

# 目标机器 (可通过环境变量覆盖: REMOTE=host-b scripts/build.sh)
# v0.26.0: 默认双机测试床 host-a; 基准机 基准机支持已移除
# v0.40.3: 测试环境固定 host-a↔8 (03, env/ 入库)
# (5.4 内核兼容分支同步移除; 机器实况/恢复手册见 env/ 独立仓库)
REMOTE="${REMOTE:-host-a}"

# ---- SSH 统一参数 (所有脚本经 ssh_run()/ssh_host() 连接远端) ----
# 覆盖示例: SSH_TIMEOUT=20 tests/scripts/test.sh all
SSH_TIMEOUT="${SSH_TIMEOUT:-10}"
SSH_OPTS="-o ConnectTimeout=$SSH_TIMEOUT"

# ssh_host <host> [args...] — 显式主机 ssh (双机脚本逐主机连接)
ssh_host() {
	ssh $SSH_OPTS "$@"
}

# ssh_run "远端命令" — 单机 $REMOTE 场景 (统一超时 + 远端路径引用)
ssh_run() {
	if [ $# -eq 0 ]; then
		echo "ssh_run: 缺少远端命令" >&2
		return 2
	fi
	ssh_host "$REMOTE" "$@"
}

# ssh_bash <host> [-- arg1 ...] — fish 登录 shell 规避: ssh <host> bash -s
# (注意): stdin 喂脚本, bash 位置参数经 -- 后传入。
# 用法: ssh_bash <host> [-- a b ...] <<'EOF' ... EOF
# ⚠ 严禁给该形态加 -n: stdin=/dev/null → 远端 bash -s 读到空脚本直接退出 0
#   (假通过, 脚本根本不执行 — 实测教训)。
ssh_bash() {
	ssh $SSH_OPTS "$1" bash -s "${@:2}"
}

# ssh_put <host> <local-file> <remote-path> — 单文件推送 (stdin 经远端 cat 落地)
ssh_put() {
	ssh_host "$1" "cat > $3" < "$2"
}

# push_remote_script <host> <remote-path> — 推送远端脚本 (stdin/管道提供内容)
# + chmod +x + 远端 bash -n 语法检查; 静态脚本直接 < file, 模板经
# render_template 管道接入 (scripts/remote/*.sh)
push_remote_script() {
	local host=$1 remote_path=$2
	ssh_host "$host" "cat > $remote_path && chmod +x $remote_path && bash -n $remote_path"
}

# render_template <local-file> [NAME=value ...] — __NAME__ 占位符替换 → stdout
# 用于远端 sudo 脚本模板 (scripts/remote/); 替换值不含 / 与 & 时安全
# (现有占位符: BDF/开关/数字, 均安全)
render_template() {
	local f=$1 kv
	shift
	local sed_args=()
	for kv in "$@"; do
		sed_args+=(-e "s/__${kv%%=*}__/${kv#*=}/g")
	done
	if [ ${#sed_args[@]} -eq 0 ]; then
		cat -- "$f"   # GNU sed 无脚本参数时报 usage (sed "" 空脚本才行), 零占位符直接透传
	else
		sed "${sed_args[@]}" < "$f"
	fi
}

# die <msg...> — 错误退出 (✗ 前缀, stderr, rc=1)
die() { echo "✗ $*" >&2; exit 1; }

# symrdma_mr_count <host> — /proc/symrdma "活跃 MR" 计数 (经 ssh_bash)
# 模块未加载/不可读时输出空 — 调用方自行判定 (空值 ≠ 基线即异常)
symrdma_mr_count() {
	ssh_bash "$1" <<'EOF'
grep '活跃 MR' /proc/symrdma 2>/dev/null | tr -dc 0-9
echo
EOF
}

# pct_delta <new> <base> — (new-base)/base×100, 一位小数;
# base≤0 / 空 / 非数值 (new 或 base) 时输出 "—" (调用方无需预判)
pct_delta() {
	awk -v x="$1" -v b="$2" 'BEGIN{
		if (b>0 && x~/^-?[0-9]+(\.[0-9]+)?$/ && b~/^-?[0-9]+(\.[0-9]+)?$/)
			printf "%.1f",(x-b)/b*100
		else
			print "—"
	}'
}

# ---- 双机测试床拓扑 (run_nopf_bw / run_odp_compare / nopf_pipeline 共用) ----
# 拓扑参数须由使用者经 testbed.env 配置 (模板 testbed.env.example)。
CLIENT_HOST="${CLIENT_HOST:-host-a}"
DEV="${DEV:-mlx5_1}"   # RDMA 设备名
GID="${GID:-3}"

# ---- 远程路径 ----
# v0.24.2 本地重组: 测试源码在本地 tests/{programs,bench,diag}, 远端部署目录
# 仍是扁平的 ~/pro/symrdma/test (build.sh rsync 本地 tests/programs/ → 远端 TEST_DIR)
KERNEL_DIR="~/pro/symrdma/kernel"
TEST_DIR="~/pro/symrdma/test"
LIB_DIR="~/pro/symrdma/lib"
SIR_DIR="~/pro/symrdma/sir"      # v0.24.3: SIR 通道独立目录 (lib/nprdma 共享编译单元)
NPRDMA_DIR="~/pro/symrdma/nprdma"
REMOTE_OFED="~/pro/symrdma/mlnx-ofed-kernel-5.8-work"   # OFED 远端工作树 (ofed_push.sh 用)

# ---- 每机器 NIC 配置 (ofed_push.sh 生成远端重载脚本用, 环境变量可覆盖) ----
# PCI_BDF: 活动口 mlx5_1 所在 PCI 地址 (2026-10-13 起 .0 口 DOWN, 迁 .1);
# NIC_LOOPBACK: 1=设置 PHY loopback (仅单机自环)
# 多机直连/交换机拓扑必须为 0, 否则 loopback 会断开对端链路!
# v0.26.0: 未知机器不再默认继承自环配置 — 显式传入 PCI_BDF (loopback 默认
# 0, 安全; 单机自环场景需显式 NIC_LOOPBACK=1)
case "$REMOTE" in
	host-a) PCI_BDF="${PCI_BDF:-0000:5e:00.1}"; NIC_LOOPBACK="${NIC_LOOPBACK:-0}" ;;
	host-b) PCI_BDF="${PCI_BDF:-0000:d8:00.1}"; NIC_LOOPBACK="${NIC_LOOPBACK:-0}" ;;
	*)
		[ -n "${PCI_BDF:-}" ] || die "未知 REMOTE=$REMOTE: 请显式指定 PCI_BDF=<domain:bus:dev.fn> (NIC_LOOPBACK 默认 0, 单机自环需显式 NIC_LOOPBACK=1)"
		NIC_LOOPBACK="${NIC_LOOPBACK:-0}"
		;;
esac

# ---- 本地路径 ----
# v0.24.2: 从 common.sh 自身位置解析 (BASH_SOURCE), 不随调用者所在目录变
# (tests/scripts/ 下的脚本也 source 本文件, 用 $0 会把 LOCAL 算成 tests/)
LOCAL="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TESTS_RESULTS="$LOCAL/tests/results"   # 测量产物默认目录 (gitignore: CSV/PNG/log)
