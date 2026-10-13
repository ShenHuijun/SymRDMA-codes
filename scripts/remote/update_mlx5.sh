#!/bin/bash
# SymRDMA — 全栈重载 (ib_core + mlx5_ib + symrdma, 含 sudo)
# 模板: scripts/remote/update_mlx5.sh (ofed_push.sh 渲染 __PCI_BDF__/__NIC_LOOPBACK__ 后推送)
# 用法 (远端): bash ~/pro/symrdma/scripts/update_mlx5.sh
set -e
WORK=~/pro/symrdma/mlnx-ofed-kernel-5.8-work
PCI_BDF="__PCI_BDF__"            # mlx5_0 所在 PCI 地址
NIC_LOOPBACK="__NIC_LOOPBACK__"  # 1=单机自环基准机; 0=多机拓扑(禁设 loopback)
cd "$WORK"

echo "=== 1/6 工作树预检 + 安装模块 + 系统树清扫 (make install) ==="
# 预检: 工作树所有 .ko 的 vermagic 必须匹配当前内核 (脏树/跨内核拷贝防护 —
# 2026-09-15 host-a/host-b 教训: 5.4 时代 stale .ko 装入系统树 → modprobe 全挂)
KREL=$(uname -r)
BAD=0
for f in $(find "$WORK" -name "*.ko" 2>/dev/null); do
    v=$(modinfo -F vermagic "$f" 2>/dev/null)
    case "$v" in
        "$KREL"*) ;;
        *) echo "  ✗ 异 vermagic: $f [$v]"; BAD=1 ;;
    esac
done
[ "$BAD" = "0" ] || { echo "!! 工作树含异内核模块 — 拒绝安装 (先重建工作树)"; exit 1; }
echo "  ✓ 工作树 $(find "$WORK" -name '*.ko' 2>/dev/null | wc -l) 个 .ko vermagic 全部 = $KREL"
sudo make install 2>&1 | tail -3 || true
# 清扫: 新构建不再产出的模块 (如 auxiliary.ko — 5.15 内建 auxiliary bus,
# compat 不再 backport) 永远不会被 make install 覆盖; 历史残留的异内核版本
# 会永久滞留并挂死 modprobe 依赖链 (module_layout CRC 冲突) → 逐个扫除
for f in $(find /lib/modules/$KREL/updates -name "*.ko" 2>/dev/null); do
    v=$(modinfo -F vermagic "$f" 2>/dev/null)
    case "$v" in
        "$KREL"*) ;;
        *) echo "  移除系统树残留: $f [$v]"; sudo rm -f "$f" ;;
    esac
done
sudo depmod -a "$KREL"

echo "=== 2/6 停止 RDMA 服务 (阻止自动 modprobe) ==="
sudo systemctl stop openibd 2>/dev/null || true
sudo fuser -k /dev/infiniband/uverbs0 2>/dev/null || true
sleep 1

echo "=== 3/6 卸载 symrdma + IB 栈 (依赖序 + 重试 + 失败即停) ==="
# 2026-10-13 教训修复: 原顺序 ib_uverbs 先于 mlx5_ib (被引者先卸必失败),
# 且失败后仅打印继续 → 半卸载态 + mlx5_ib dying (-1) 无恢复路径只能重启。
# 现改为: mlx5_ib 先于 uverbs/core; 带重试; 任一核心模块卸不掉即报错
# 退出 (此时 make install 已完成, 重跑本脚本即可续, 无需重启)。
sudo rmmod symrdma 2>/dev/null || true
for m in rdma_ucm rdma_cm ib_ipoib iw_cm ib_cm ib_umad; do
    sudo rmmod $m 2>/dev/null || true
done
# mlx5_ib 先卸 (引用 ib_uverbs/ib_core); dying 态 (引用 -1) 重试等待回收
_MLX5_OK=0
for i in 1 2 3 4 5; do
    if sudo rmmod mlx5_ib 2>/dev/null; then _MLX5_OK=1; break; fi
    sleep 1
done
if [ "$_MLX5_OK" != "1" ] && lsmod | grep -q '^mlx5_ib'; then
    echo "!! mlx5_ib 卸载失败 (dying/引用残留, 见 dmesg) — 排查占用后重跑本脚本"
    exit 1
fi
for m in ib_uverbs ib_umad ib_core mlx5_core mlxdevm mlxfw mlx_compat; do
    sudo rmmod $m 2>/dev/null && echo "  rmmod $m OK" || true
done
if lsmod | grep -qE '^ib_core|^mlx5_core|^ib_uverbs'; then
    echo "!! 栈未清空:"; lsmod | grep -E '^ib_core|^mlx|^ib_uverbs|^rdma'
    echo "!! 请检查占用进程: sudo fuser -v /dev/infiniband/*; 或重启后重跑"
    exit 1
fi
echo "(IB 栈已清空)"

echo "=== 4/6 装载 IB 栈 (identity_mtt 从 modprobe.d 自动注入) ==="
# 装载前解析验证: modinfo -n 走 depmod 索引, 确认依赖链全部指向本内核模块
for m in mlx5_core ib_core mlx5_ib; do
    p=$(modinfo -n $m 2>/dev/null) || { echo "  ✗ $m 无法解析 (depmod 未跑?)"; exit 1; }
    echo "  $m → $p [$(modinfo -F vermagic "$p" 2>/dev/null | awk '{print $1}')]"
done
sudo modprobe mlx5_core
sudo modprobe ib_core
sudo modprobe ib_uverbs ib_umad ib_cm iw_cm ib_ipoib rdma_cm rdma_ucm
sudo modprobe mlx5_ib

echo "=== 5/6 验证新 ib_core 生效 (no-pin 符号) ==="
grep -q ib_umem_get_nopin /proc/kallsyms && echo "  ✓ ib_umem_get_nopin 在运行内核中" || { echo "  ✗ 新 ib_core 未生效"; exit 1; }

echo "=== 6/6 symrdma + (可选) PHY loopback ==="
if [ -f ~/pro/symrdma/kernel/symrdma.ko ]; then
    sudo insmod ~/pro/symrdma/kernel/symrdma.ko mode=1 pci_bdf=$PCI_BDF
    head -4 /proc/symrdma
else
    echo "  (symrdma.ko 未编译, 跳过 — 先跑 scripts/build.sh 再 symrdma_reload.sh)"
fi
if [ "$NIC_LOOPBACK" = "1" ]; then
    sudo mlxlink -d $PCI_BDF -l PH >/dev/null 2>&1 && echo 'PHY loopback 已设置' || echo '(loopback 设置失败)'
else
    echo "(多机直连/交换机拓扑: 跳过 PHY loopback)"
fi

# 之前故障排查时 openibd 可能被 disable, 恢复自启 + 启动
sudo systemctl enable --now openibd 2>/dev/null || true

echo ""
echo "=== 状态 ==="
echo "identity_mtt: $(cat /sys/module/mlx5_ib/parameters/identity_mtt 2>/dev/null)"
modinfo ib_core | grep '^filename'
ibstat 2>/dev/null | grep -E 'State|Physical' | head -4
