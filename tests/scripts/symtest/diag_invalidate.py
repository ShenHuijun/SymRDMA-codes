"""外部页失效源调查 — investigate_invalidation.sh 的 Python 引擎 (诊断工具)。

背景: 双机测试床存在外部页失效源 (EDR 代理嫌疑 — mlocked 匿名页仍被周期性
invalidate), 曾与引擎预修复的 unmap→map 窗口相撞导致 4MB 写 LOC_PROT。
本工具系统化调查:
  A. 系统级嫌疑快照 (NUMA 均衡 / THP khugepaged / KSM / DAMON / 压缩
     proactive / EDR 类代理进程 / 定时任务)
  B. 静默窗口测量: notif_holder (常驻 MR + mlockall, 零自触发) 持有期间
     vmstat + /proc/symrdma 统计差值 → mlocked 页是否仍被失效、频率多少
  C. 取证环形缓冲: notifier 取证段直接给出事件来源 (comm/pid/调用栈)
只读诊断 (除 pkill notif_holder 收尾), 无门禁 — 退出码恒 0。
"""

from __future__ import annotations

import re
import time

from .ssh import Ctx

VMSTAT_KEYS = ("pgmigrate_success", "pgmigrate_fail", "thp_fault_alloc",
               "thp_collapse_alloc", "thp_split_page", "compact_stall",
               "compact_daemon_wake", "compact_wake", "numa_hint_faults",
               "numa_pages_migrated", "numa_pte_updates", "pswpin",
               "pswpout", "pageoutrun", "allocstall")

_SNAPSHOT_SCRIPT = r"""sys_read() { [ -r "$1" ] && cat "$1" 2>/dev/null || echo "(不可读)"; }

echo "[NUMA 均衡] kernel.numa_balancing = $(sys_read /proc/sys/kernel/numa_balancing)  (1=开启: PROTNONE 提示页+迁移会触发 notifier)"
echo "[THP]       enabled = $(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null | grep -o '\[.*\]' || echo '?')"
echo "            defrag  = $(cat /sys/kernel/mm/transparent_hugepage/defrag 2>/dev/null | grep -o '\[.*\]' || echo '?')"
echo "            khugepaged: $(grep -H . /sys/kernel/mm/transparent_hugepage/khugepaged/scan_sleep_ms /sys/kernel/mm/transparent_hugepage/khugepaged/pages_to_scan 2>/dev/null | tr '\n' ' ')"
echo "[KSM]       run = $(sys_read /sys/kernel/mm/ksm/run)  pages_shared = $(sys_read /sys/kernel/mm/ksm/pages_shared)"
echo "[DAMON]     $(ls /sys/kernel/mm/damon 2>/dev/null && echo '存在' || echo '不存在')"
echo "[compaction] proactiveness = $(sys_read /proc/sys/vm/compaction_proactiveness)  (非 0: kcompactd 周期迁移页)"
echo "[swappiness] = $(sys_read /proc/sys/vm/swappiness)"
echo
echo "[嫌疑代理进程 (EDR/安全/运维 agent 常见名)]:"
ps -eo pid,ppid,comm,args --no-headers 2>/dev/null | \
	grep -iE 'edr|360|qax|titanagent|sangfor|titan|falcon|crowdstrike|deepsec|trend|yunjing|elkeid|ssense|c60|esets|avg|symantec|mcafee|sophos|kaspersky|qihoo|huorong|whitesnow|secneo|venus|dbapp|topsec|hillstone|nwatch|ast|ai guards|guard|monitor|agent' | \
	grep -v grep | head -15 || echo "  (无匹配)"
echo
echo "[systemd 定时任务]:"
systemctl list-timers --no-pager --no-legend 2>/dev/null | head -10 || echo "  (不可用)"
echo
echo "[高 CPU 进程 Top5] (EDR 扫描常驻特征):"
ps -eo pid,comm,pcpu,pmem --sort=-pcpu --no-headers 2>/dev/null | head -5
"""

_STATS_KEYS = ("notifier 回调", "失效事件记录", "驻留失效恢复",
               "确认真缺失", "pending 溢出")

_GUIDE = """栈符号 → 失效源分类 (对照测试床取证):
  change_prot_numa / change_prot_and_migrate_test  → NUMA 均衡 (可关: numa_balancing=0)
  collapse_huge_page / khugepaged*                 → THP 整理 (可关: THP madvise)
  migrate_pages / compact_* / move_pages           → 内存压缩/迁移
  try_to_unmap* / shrink_* / vmscan*               → 内核回收 (mlocked 页不应出现!)
  access_remote_vm / process_vm_* / pin_user*      → /proc/<pid>/mem 读取者
                                                     (EDR/监控代理嫌疑 — 用
                                                      lsof/auditd 实锤)
  madvise*                                         → 显式 madvise (本项目测试)
  若 comm 为安全类 agent (对照 A 段进程列表) 且栈为 access_remote_vm →
  EDR 实锤; 无 root 时可用 cgroup 隔离 + 记录 agent 的 CPU 时间增量作旁证。
"""


def _vmstat_snap(host) -> dict[str, int]:
    alt = "|".join(VMSTAT_KEYS)
    res = host.run_script(
        f"grep -E '^({alt})' /proc/vmstat | tr '\\n' ';'\n", timeout=20)
    out: dict[str, int] = {}
    for item in res.text.split(";"):
        parts = item.split()
        if len(parts) == 2 and parts[1].isdigit():
            out[parts[0]] = int(parts[1])
    return out


def _symrdma_stats(host) -> dict[str, int]:
    alt = "|".join(_STATS_KEYS)
    res = host.run_script(
        f"grep -E '{alt}' /proc/symrdma 2>/dev/null | tr -d ' ' | tr '\\n' ';'\n",
        timeout=20)
    out: dict[str, int] = {}
    for item in res.text.split(";"):
        m = re.match(r"(.+?):(\d+)", item)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def run_investigate(ctx: Ctx, *, remote: str, window: int) -> int:
    host = ctx.host(remote)
    print(f"=== 外部页失效源调查 (host={remote}, 窗口={window}s) ===")

    # ---- 前置检查 ----
    if not ctx.dry_run:
        probe = host.run_script("test -e /proc/symrdma\n", timeout=15)
        if probe.rc != 0:
            print("!! /proc/symrdma 不存在 — 模块未加载 (先跑 symrdma_reload.sh)")
            return 1

    # ---- A. 系统级嫌疑快照 ----
    print("\n--- A. 系统级嫌疑快照 ---")
    res = host.run_script(_SNAPSHOT_SCRIPT, timeout=60)
    print(res.text.rstrip())

    # ---- B. 静默窗口测量 ----
    print(f"\n--- B. 静默窗口测量 ({window}s, notif_holder 常驻零自触发) ---")
    if ctx.dry_run:
        host.run_script("cat /tmp/notif_holder_inv.log 2>/dev/null; echo; "
                        "tail -45 /proc/symrdma\n", timeout=30)
        return 0
    t0_vm = _vmstat_snap(host)
    t0_sr = _symrdma_stats(host)
    host.run_script("bash -c 'cat /tmp/notif_holder_inv.log 2>/dev/null; echo; "
                    "tail -45 /proc/symrdma'\n", timeout=30)
    time.sleep(window)
    t1_vm = _vmstat_snap(host)
    t1_sr = _symrdma_stats(host)
    host.pkill("notif_holder")

    print("[vmstat 差值 (窗口内)]:")
    any_delta = False
    for k, v in t0_vm.items():
        d = t1_vm.get(k, 0) - v
        if d:
            print(f"  {k:<24} +{d}")
            any_delta = True
    if not any_delta:
        print("  (全部为零 — 窗口内无内核级迁移/THP/压缩/swap 活动)")

    print("\n[/proc/symrdma 统计差值] (notifier 回调数 > 0 ⇒ 外部源确实在"
          "失效 mlocked 页):")
    for k, v in t0_sr.items():
        d = t1_sr.get(k, 0) - v
        print(f"  {k} {v} → {t1_sr.get(k, 0)}  (Δ{d:+d})")

    # ---- C. 取证环形缓冲 ----
    print("\n--- C. notifier 取证 (comm/pid/调用栈 — 栈顶符号即失效源) ---")
    res = host.run_script(
        "bash -c 'cat /tmp/notif_holder_inv.log 2>/dev/null; echo; "
        "tail -45 /proc/symrdma'\n", timeout=30)
    print(res.text.rstrip())

    print("\n--- D. 结论指引 ---")
    print(_GUIDE)
    return 0
