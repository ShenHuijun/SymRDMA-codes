#!/bin/bash
# apply_env_fix.sh — SymRDMA 主机环境修复: identity_mtt_write_offset=32GB + 模块重载
# (机器无关; 各机器的 BDF/规程实况见 env/<机器>/ 文档; 远端脚本模板在
#  scripts/remote/env_fix_write_offset.sh, 经 common.sh 渲染推送)
#
# 背景 (2026-09-15 哨兵污染教训, host-a/host-b):
#   mlx5_ib 以默认参数加载 (identity_mtt_write_offset=0, 无 modprobe.d 配置) 时,
#   写区域 MR (无 REMOTE_READ) 的 MTT=VA 而非 VA+32GB → RDMA Write 落到读 IOVA
#   → 换出页读 IOVA 的哨兵映射被 DMA 写入 → 全局哨兵页粘性污染 (所有 MR 哨兵
#   检测失效)。正确配置为 32GB (与内核模块 SYMRDMA_MR_WRITE_OFFSET 一致);
#   v0.21.2 起哨兵映射只读 (kernel 侧结构性防污染), 本脚本负责配置 + 重载。
#
# 用法 (开发侧, 无需 sudo):
#   bash scripts/apply_env_fix.sh push [user@]host ...     # 推送远端脚本
#   bash scripts/apply_env_fix.sh try  [user@]host:bdf ... # (可选) ssh -tt 远程执行
#
# 推送后由管理员在远端执行 (sudo 交互):
#   bash ~/pro/symrdma/scripts/env_fix_write_offset.sh [bdf]    # bdf 省略时自动探测
set -u
source "$(dirname "$0")/common.sh"

WRITE_OFFSET="34359738368"
REMOTE_NAME="env_fix_write_offset.sh"
REMOTE_PATH="~/pro/symrdma/scripts/$REMOTE_NAME"

usage() { sed -n '2,18p' "$0"; exit 1; }
[ $# -ge 2 ] || usage
MODE=$1; shift

case "$MODE" in
try)
	# 可选: 开发侧直接远程执行 (ssh -tt 强制分配 pty, sudo 从 /dev/tty 读密码
	# — heredoc/sudo 陷阱见脚本头注
	for TARGET in "$@"; do
		case "$TARGET" in
		*:*) HOST="${TARGET%%:*}"; BDF="${TARGET#*:}" ;;
		*)   HOST="$TARGET"; BDF="" ;;
		esac
		echo "=== $HOST: 远程执行 (sudo 密码经 -tt 交互) ==="
		ssh -tt $SSH_OPTS "$HOST" "bash ~/pro/symrdma/scripts/$REMOTE_NAME $BDF" \
			|| { echo "  (见上方失败项)"; RC=1; }
		RC=${RC:-0}
		echo ""
	done
	exit ${RC:-0}
	;;
push)
	for HOST in "$@"; do
		echo "=== 推送 $REMOTE_NAME → $HOST:~/pro/symrdma/scripts/ ==="
		render_template "$LOCAL/scripts/remote/$REMOTE_NAME" WRITE_OFFSET="$WRITE_OFFSET" \
			| push_remote_script "$HOST" "$REMOTE_PATH" \
			|| { echo "  ✗ 推送失败"; continue; }
		echo "  ✓ 推送完成 + 语法 OK"
		echo ""
	done
	echo "=== 下一步: 管理员在每台远端执行 (sudo 交互) ==="
	for HOST in "$@"; do
		echo "  ssh $HOST        # 然后运行:"
		echo "    bash ~/pro/symrdma/scripts/$REMOTE_NAME"
	done
	;;
*)
	usage
	;;
esac
