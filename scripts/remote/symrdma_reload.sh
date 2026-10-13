#!/bin/bash
# SymRDMA — 加载/重载内核模块 (含 sudo, 远端手动执行)
# 模板: scripts/remote/symrdma_reload.sh (build.sh 经 push_remote_script 推送, 无占位符)
# 用法: bash ~/pro/symrdma/scripts/symrdma_reload.sh                 # VERIFY 模式
#       bash ~/pro/symrdma/scripts/symrdma_reload.sh mode=1 pci_bdf=0000:42:00.0   # NIC 模式
set -e
ARGS="$@"
sudo rmmod symrdma 2>/dev/null || true
sudo insmod ~/pro/symrdma/kernel/symrdma.ko $ARGS
cat /proc/symrdma | head -6
