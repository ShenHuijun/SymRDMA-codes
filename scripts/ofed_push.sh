#!/bin/bash
# SymRDMA — 本地辅助脚本 (无需 sudo):
#   1. 推送本地 OFED 源码修改 → $REMOTE 工作树
#   2. 推送远程 sudo 脚本 update_mlx5.sh / reload_mlx5.sh
#      (模板 scripts/remote/*.sh 渲染 __PCI_BDF__/__NIC_LOOPBACK__ 后推送)
#   3. 远程增量编译
#
# 用法: bash scripts/ofed_push.sh
# 之后在目标机上执行 (含 sudo): bash ~/pro/symrdma/scripts/update_mlx5.sh
set -e
cd "$(dirname "$0")/.."
source scripts/common.sh

echo "=== 1/4 推送 OFED 源码修改 → $REMOTE ==="
bash scripts/sync_ofed.sh push

echo ""
echo "=== 2/4 推送远程 sudo 脚本 (update_mlx5.sh, 目标: $REMOTE BDF=$PCI_BDF loopback=$NIC_LOOPBACK) ==="
ssh_run "mkdir -p ~/pro/symrdma/scripts"
# 全栈重载版 — ib_core/mlx5_ib 变更都靠它 (轻量版在改动仅限 mlx5_ib 时曾导致
# 旧 ib_core 残留, ); __PCI_BDF__/__NIC_LOOPBACK__ 按 REMOTE 渲染 (查表见 common.sh)
render_template "$LOCAL/scripts/remote/update_mlx5.sh" \
	PCI_BDF="$PCI_BDF" NIC_LOOPBACK="$NIC_LOOPBACK" \
	| push_remote_script "$REMOTE" "~/pro/symrdma/scripts/update_mlx5.sh"
echo "  已推送 ~/pro/symrdma/scripts/update_mlx5.sh"

echo ""
echo "=== 3/4 推送轻量重载脚本 (reload_mlx5.sh, 目标: $REMOTE) ==="
# 仅 mlx5_ib 改动时的最快迭代 (无需全栈重载); ib_core 改动请用 update_mlx5.sh
render_template "$LOCAL/scripts/remote/reload_mlx5.sh" \
	PCI_BDF="$PCI_BDF" NIC_LOOPBACK="$NIC_LOOPBACK" \
	| push_remote_script "$REMOTE" "~/pro/symrdma/scripts/reload_mlx5.sh"
echo "  已推送 ~/pro/symrdma/scripts/reload_mlx5.sh"

echo ""
echo "=== 4/4 远程增量编译 (make -j\$(nproc), stdin 喂 bash 规避 fish) ==="
# 远端登录 shell 可能是 fish (不支持 \$(...) 命令替换) — 统一经 stdin 喂 bash,
# 且 pipefail 让 make 失败传播
REBUILD_STATUS=0
cat <<'REBUILD_EOF' | ssh_bash "$REMOTE" || REBUILD_STATUS=$?
set -o pipefail
cd ~/pro/symrdma/mlnx-ofed-kernel-5.8-work
KVER=$(uname -r)
if ! grep -q "$KVER" configure.mk.kernel 2>/dev/null; then
	echo "  内核配置不匹配 → 重新 configure ($KVER)"
	./configure > /tmp/ofed_configure.log 2>&1 || { echo "✗ configure 失败:"; tail -15 /tmp/ofed_configure.log; exit 1; }
	echo "  ✓ configure 完成"
fi
# 工作树产物可能是从其它机拷来的旧内核构建 (tar 保 mtime, make 不重编)
# → 装进系统树后 modprobe 报 Exec format error; 检测到即全量重编
if ! modinfo compat/mlx_compat.ko 2>/dev/null | grep -q "$KVER"; then
	echo "  工作树产物 vermagic ≠ $KVER → make clean 全量重编 (首次约 10-20 分钟)"
	make clean > /dev/null 2>&1
fi
make -j $(nproc) 2>&1 | tail -6
REBUILD_EOF
if [ "$REBUILD_STATUS" != "0" ]; then
	echo "!! 远端 OFED 编译失败 — 查看上方输出"
	exit 1
fi

echo ""
echo "=== 完成。下一步 (远程, 含 sudo): ==="
echo "  bash ~/pro/symrdma/scripts/update_mlx5.sh   # ib_core 改动 (全栈重载)"
echo "  bash ~/pro/symrdma/scripts/reload_mlx5.sh    # 仅 mlx5_ib 改动 (轻量重载)"
