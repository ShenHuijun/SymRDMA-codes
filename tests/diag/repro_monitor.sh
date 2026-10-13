#!/bin/bash
# wedge 幸存监控: dmesg 增量 + meminfo 每秒落盘 (本地磁盘)
OUT=$HOME/pro/symrdma/tests/results
TS=$(date +%Y%m%d_%H%M%S)
D=$OUT/repro_dmesg_$TS.log
M=$OUT/repro_mem_$TS.log
d0=$(dmesg | wc -l)
echo "monitor start $(date) baseline=$d0" > "$D"
echo "monitor start $(date)" > "$M"
while :; do
  d1=$(dmesg 2>/dev/null | wc -l)
  if [ "$d1" -gt "$d0" ] 2>/dev/null; then
    dmesg 2>/dev/null | tail -n +$((d0+1)) >> "$D"
    d0=$d1
  fi
  echo "$(date +%T) $(grep -E '^(MemFree|MemAvailable):' /proc/meminfo | tr '\n' ' ' | sed 's/  */ /g')" >> "$M"
  sleep 1
done
