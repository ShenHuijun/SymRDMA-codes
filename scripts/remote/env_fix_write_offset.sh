#!/bin/bash
# env_fix_write_offset.sh — 写 modprobe.d (write_offset=32GB) + 重载 mlx5_ib/symrdma
# 模板: scripts/remote/env_fix_write_offset.sh (apply_env_fix.sh 渲染 __WRITE_OFFSET__ 后推送)
# 用法 (远端, sudo 交互): bash ~/pro/symrdma/scripts/env_fix_write_offset.sh [bdf]
#   bdf 省略时自动探测 (lspci 第一块 Mellanox)
set -u
WRITE_OFFSET="__WRITE_OFFSET__"
CONF="options mlx5_ib identity_mtt=0 identity_mtt_write_offset=$WRITE_OFFSET identity_mtt_log_pgsize=31"
BDF="${1:-}"
FAIL=0

# 0. BDF 自动探测 (未显式给出时)
if [ -z "$BDF" ]; then
	BDF=$(lspci -D 2>/dev/null | grep -i -m1 "Mellanox" | awk '{print $1}')
	[ -n "$BDF" ] || { echo "✗ 未能探测 Mellanox BDF — 请显式给出"; exit 1; }
	echo "自动探测 BDF: $BDF"
fi

# 1. modprobe.d (幂等: 已含目标行则跳过写文件)
if grep -qs "identity_mtt_write_offset=$WRITE_OFFSET" /etc/modprobe.d/mlx5_ib.conf 2>/dev/null; then
	echo "modprobe.d 已是正确配置"
else
	echo "$CONF" > /tmp/mlx5_ib.conf.new \
		&& sudo install -m 644 /tmp/mlx5_ib.conf.new /etc/modprobe.d/mlx5_ib.conf \
		&& echo "modprobe.d 已写入"
fi
echo "内容: $(cat /etc/modprobe.d/mlx5_ib.conf 2>/dev/null)"

# 2. 重载顺序: symrdma → mlx5_ib (symrdma 持 NIC domain 引用, 必须先卸)
sudo rmmod symrdma 2>/dev/null && echo "symrdma 已卸载" || echo "symrdma 未加载 (跳过)"
if sudo rmmod mlx5_ib 2>/dev/null; then echo "mlx5_ib 已卸载"; else
	echo "✗ mlx5_ib 卸载失败 (被占用? sudo fuser -v /dev/infiniband/*)"; FAIL=1
fi
sudo modprobe mlx5_ib && echo "mlx5_ib 已重载 (新参数)"
sleep 2

# 3. 重挂 symrdma (NIC 模式, 新 .ko 由 build.sh 编译就绪)
if sudo insmod ~/pro/symrdma/kernel/symrdma.ko mode=1 pci_bdf="$BDF"; then
	echo "symrdma 已重挂 (NIC 模式)"
else
	echo "✗ symrdma 挂载失败 (若提示已存在属并发重跑, 可忽略)"; grep -qs "^symrdma" /proc/modules || FAIL=1
fi
sleep 2

# 4. 校验
echo "--- 校验 ---"
for p in identity_mtt identity_mtt_write_offset identity_mtt_log_pgsize; do
	echo "  $p = $(cat /sys/module/mlx5_ib/parameters/$p 2>/dev/null)"
done
[ "$(cat /sys/module/mlx5_ib/parameters/identity_mtt_write_offset 2>/dev/null)" = "$WRITE_OFFSET" ] \
	|| { echo "  ✗ write_offset 未生效"; FAIL=1; }
grep -qs "^symrdma" /proc/modules || { echo "  ✗ symrdma 未加载"; FAIL=1; }
NIC=$(ls /sys/class/infiniband 2>/dev/null | head -1)
STATE=$(ibstat "$NIC" 2>/dev/null | grep "State:" | awk '{print $2}' | head -1)
if [ "$STATE" = "Active" ]; then echo "  端口状态: $NIC Active"; else echo "  ✗ 端口状态: ${STATE:-未知} ($NIC, 等几秒后 ibstat 重查)"; FAIL=1; fi
if head -8 /proc/symrdma 2>/dev/null | grep -qs "$BDF"; then
	echo "  symrdma domain: 已附加 $BDF"
else
	echo "  ✗ /proc/symrdma 无 $BDF"; FAIL=1
fi
if [ "$FAIL" = "0" ]; then echo "✅ 修复完成"; else echo "❌ 有失败项 (见上)"; fi
exit $FAIL
