#!/bin/bash
# SymRDMA — 仅重载 mlx5_ib (含 sudo, 远端手动执行)
# 模板: scripts/remote/reload_mlx5.sh (ofed_push.sh 渲染 __PCI_BDF__/__NIC_LOOPBACK__ 后推送)
# 适用: 改动仅在 mlx5_ib (mem.c/mr.c/main_ext.c) 时 — 最快迭代
# 若改动涉及 ib_core (umem.c) 需用 update_mlx5.sh 全栈重载
# 用法 (远端): bash ~/pro/symrdma/scripts/reload_mlx5.sh
set -e
WORK=~/pro/symrdma/mlnx-ofed-kernel-5.8-work
PCI_BDF="__PCI_BDF__"            # mlx5_0 所在 PCI 地址
NIC_LOOPBACK="__NIC_LOOPBACK__"  # 1=单机自环; 0=多机拓扑(禁设 loopback)
cd "$WORK"

echo "=== 1/3 工作树预检 + 安装模块 (make install) ==="
KREL=$(uname -r)
for f in $(find "$WORK" -name "mlx5_ib.ko" 2>/dev/null); do
    v=$(modinfo -F vermagic "$f" 2>/dev/null)
    case "$v" in "$KREL"*) ;; *) echo "!! 异 vermagic: $f [$v] — 拒绝安装"; exit 1;; esac
done
sudo make install 2>&1 | tail -2 || true
sudo depmod -a "$KREL"

echo "=== 2/3 重载 mlx5_ib (identity_mtt 从 modprobe.d 自动注入) ==="
sudo rmmod mlx5_ib 2>/dev/null || true
sudo modprobe mlx5_ib

echo "=== 3/3 (可选) PHY loopback + 状态 ==="
if [ "$NIC_LOOPBACK" = "1" ]; then
    sudo mlxlink -d $PCI_BDF -l PH >/dev/null 2>&1 && echo 'PHY loopback 已设置' || echo '(loopback 设置失败)'
else
    echo "(多机直连/交换机拓扑: 跳过 PHY loopback)"
fi
echo "identity_mtt: $(cat /sys/module/mlx5_ib/parameters/identity_mtt 2>/dev/null)"
echo "identity_mtt_write_offset: $(cat /sys/module/mlx5_ib/parameters/identity_mtt_write_offset 2>/dev/null)"
ibstat 2>/dev/null | grep -E 'State|Physical' | head -4
