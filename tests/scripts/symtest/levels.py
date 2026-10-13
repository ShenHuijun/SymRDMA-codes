"""单机 Level 套件 — test.sh 的 Python 引擎（v0.39.0 自 bash 移植）。

行为契约与 bash test.sh (v0.38.2) 完全一致：

  * 用法：`[levelN|level6r|all]`，默认 all；L15 不入 all（全矩阵 >10min，
    超出超时契约 — 单跑：TEST_TIMEOUT=900 ... level15）；
  * 每级执行 = 远端 `timeout -k 10 $T stdbuf -oL <cmd>`（远端自杀优先，
    防孤儿持模块引用）+ 本地外层超时 T+60（防 ssh 永久阻塞）+ 前后
    `pkill -9 -f '[t]est_'` 孤儿清扫（§5 教训教训 #12/#13）；
  * all 模式（多目标同）：哨兵页粘性污染金丝雀预检 —— rc=2 中止套件并给
    出恢复指引（v0.21.2；污染会级联误报 L1/L3/L4/L5）；单级失败不中止，
    汇总后统一退出码（bash 子 shell 隔离的 errexit 问题在此不存在）；
  * QUIET 行过滤只影响控制台；全量输出逐级落盘 results/levels_<ts>/L*.log
    （bash 版只打控制台，不落盘）；
  * 退出码：0 全绿 / 1 有失败 / 2 哨兵污染中止；单目标模式 = 该级退出码
    （bash set -e 语义）。

新增（纯增量）：每级计时、JSON manifest、--dry-run/--list/多目标。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from . import config
from .report import CaseRecord, Check, Con, write_manifest
from .ssh import Ctx, RunResult, qh

# 注释移植自 bash lv_cmd/lv_name（v0.33.0 起双进程 Level L7/L10/L12/L13
# 迁往 run_sir_cross.sh 跨机形态；L19 需 v0.38 模块 + THP，fail-closed
# 子测仅专用装载（demote_fail_grp=2）激活，默认装载 SKIP；L20 纯 CPU）。
ALL_LEVELS = ("1", "2", "3", "4", "5", "6", "6r", "8", "9", "11", "14",
              "16", "19", "20")

# 注: L6 的 LD_PRELOAD 由 ld.so 解析（不展开 ~）—— "$HOME" 在远端 bash
# 双引号内展开，等效于 bash 版的 \$HOME 形态。
# NPRDMA_INTERCEPT=all: test_nprdma 无显式位，验证全拦截形态
# (v0.23.3 默认翻转 flag 后需显式开启)。6r 反转：不挂 → 原版路径 (P4)。
# L11 错误处理工具 (论文 §4.1)：进程退出清理 + 并发控制面/数据面组合。
# L14 并发缺页竞态压测 (v0.24.0, 论文 §3.1 Host-Remote Race)。


@dataclass(frozen=True)
class Level:
    id: str
    display: str
    prog: str
    args: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()
    in_all: bool = True
    note: str = ""


LEVELS: tuple[Level, ...] = (
    Level("1", "IOMMU 验证", "test_iommu_verify"),
    Level("2", "RDMA 验证", "test_rdma_verify"),
    Level("3", "真实 swap-out", "test_swapout"),
    Level("4", "自动检测修复 + Seqlock", "test_auto_repair"),
    Level("5", "写路径黑洞吸收", "test_rdma_write"),
    Level("6", "LD_PRELOAD 透明拦截", "test_nprdma",
          env=(("NPRDMA_INTERCEPT", "all"),
               ("LD_PRELOAD", "$HOME/pro/symrdma/nprdma/libnprdma.so"))),
    Level("6r", "反转验证 (普通应用不受影响, P4)", "test_nprdma"),
    Level("8", "no-pin 注册", "test_nopin"),
    Level("9", "故障比例扫描 (论文 §5.2.1)", "test_fault_sweep"),
    Level("11", "错误处理工具 (论文 §4.1, 进程退出清理+并发组合)",
          "test_error_combos"),
    Level("14", "并发缺页竞态压测 (论文 §3.1 Host-Remote Race)",
          "test_race_stress"),
    Level("15", "ODP 同机对照 Phase A (论文 §5.2.1/A.7)",
          "test_odp_compare", args=("local",), in_all=False,
          note="全矩阵 >10min 不入 all; 单跑 TEST_TIMEOUT=900"),
    Level("16", "哨兵相位单测 (R2, 共享原语等价性)", "test_sentinel_phase"),
    Level("19", "组粒度映射验证 (Phase 2: 提升/降级/修复/fail-closed)",
          "test_group_mapping"),
    Level("20", "引擎 scratch 锁纪律白盒单测 (P1-2 回归)", "test_engine_scratch"),
)

LEVEL_LOOKUP = {lv.id: lv for lv in LEVELS}
ALL_IDS = [lv.id for lv in LEVELS if lv.in_all]

# 哨兵污染级联误报的 Level 列表（金丝雀提示用，v0.21.2 契约）
SENTINEL_SENSITIVE = "L1/L3/L4/L5"

# 孤儿清扫（[t] 防自匹配括号保留原约定；bash -s 下命令行不含模式文本）
ORPHAN_SWEEP = "pkill -9 -f '[t]est_' 2>/dev/null\ntrue\n"

QUIET_RE = re.compile("|".join(re.escape(s) for s in config.QUIET_SUBSTRINGS))


class UsageError(ValueError):
    pass


def resolve_targets(targets: list[str]) -> list[Level]:
    """['all'] / ['level3'] / ['3', 'level6r'] → Level 列表（保序去重）。"""
    if not targets or targets == ["all"]:
        return [LEVEL_LOOKUP[i] for i in ALL_IDS]
    if "all" in targets:
        if len(targets) != 1:
            raise UsageError("'all' 不能与其他目标混用")
        return [LEVEL_LOOKUP[i] for i in ALL_IDS]
    ids: list[str] = []
    for t in targets:
        norm = t.removeprefix("level")
        if norm not in LEVEL_LOOKUP:
            raise UsageError(
                f"未知 Level: {t} (可用: {' '.join(LEVEL_LOOKUP)} / all)")
        if norm not in ids:
            ids.append(norm)
    return [LEVEL_LOOKUP[i] for i in ids]


def level_script(lv: Level, timeout: int) -> str:
    """单级远端执行脚本（timeout -k + stdbuf + env 注入，bash 版同构）。"""
    parts: list[str] = []
    if lv.env:
        envs = " ".join(f"{k}={qh(v)}" for k, v in lv.env)
        parts.append(f"env {envs}")
    parts.extend(qh(a) for a in (f"$HOME/pro/symrdma/test/{lv.prog}", *lv.args))
    cmd = " ".join(parts)
    return f"timeout -k 10 {int(timeout)} stdbuf -oL {cmd} 2>&1\n"


def _rc_detail(res: RunResult, timeout: int) -> str:
    if res.timed_out:
        return f"rc={res.rc} (本地外层超时 {timeout + 60}s — ssh 卡死?)"
    if res.rc == 124:
        return f"rc=124 (远端 timeout, TEST_TIMEOUT={timeout}s)"
    if res.rc in (137,):
        return "rc=137 (远端 timeout -k SIGKILL)"
    return f"rc={res.rc}"


def run_level(host, lv: Level, *, timeout: int, log_path: Path) -> CaseRecord:
    """运行单个 Level：孤儿清扫 → 流式执行（全量落盘 + 控制台过滤）→ 清扫。"""
    if host.dry_run:
        host.run_script(ORPHAN_SWEEP)
        host.run_script(level_script(lv, timeout))
        host.run_script(ORPHAN_SWEEP)
        return CaseRecord(name=f"L{lv.id}", display=lv.display, rc=0,
                          checks=[Check("dry-run", True, "仅打印远端脚本")])
    t0 = time.monotonic()
    log_path.parent.mkdir(parents=True, exist_ok=True)
    f = open(log_path, "w", encoding="utf-8", errors="replace")
    try:
        def on_line(line: str) -> None:
            f.write(line if line.endswith("\n") else line + "\n")
            if not QUIET_RE.search(line):
                print(line, end="")

        host.run_script(ORPHAN_SWEEP, timeout=15)
        res = host.run_script(level_script(lv, timeout),
                              timeout=timeout + 60, on_line=on_line)
        host.run_script(ORPHAN_SWEEP, timeout=15)
    finally:
        f.close()
    dur = time.monotonic() - t0
    rc = res.rc
    if res.timed_out and rc != 124:
        rc = 124
    checks = [Check("exit-code", rc == 0 and not res.timed_out,
                    _rc_detail(res, timeout))]
    return CaseRecord(name=f"L{lv.id}", display=lv.display, rc=rc,
                      duration=dur, timed_out=res.timed_out,
                      checks=checks, log=str(log_path))


def sentinel_canary(host) -> tuple[int, str]:
    """哨兵页完整性金丝雀（test_iommu_verify --sentinel-check）。"""
    script = ('timeout -k 10 50 "$HOME"/pro/symrdma/test/test_iommu_verify '
              '--sentinel-check 2>&1\n')
    res = host.run_script(script, timeout=60)
    return res.rc, res.text


def _print_summary(records: list[CaseRecord], total: float, manifest: Path | None):
    from . import ui
    print("========================================")
    nfail = sum(1 for r in records if not r.ok)
    if nfail == 0:
        n = len(records)
        print(Con.ok(f"全套通过: {n} 项 Level 全部成功")
              + Con.dim(f" · 总耗时 {total:.1f}s"
                        + (f" · manifest: {manifest}" if manifest else "")))
    else:
        failed = " ".join(r.name for r in records if not r.ok)
        print(Con.err(f"全套汇总: {nfail} 个 Level 失败:{failed}")
              + Con.dim(f" · 总耗时 {total:.1f}s"
                        + (f" · manifest: {manifest}" if manifest else "")))
    # 逐级明细表（rich 可用时带框着色，否则纯文本列对齐 — 信息不变）
    ui.table(
        ["Level", "名称", "结果", "耗时"],
        [[r.name, r.display,
          Con.ok("✓ PASS") if r.ok else Con.err("✗ FAIL"),
          f"{r.duration:.1f}s"] for r in records],
    )
    for r in records:
        if not r.ok:
            details = "; ".join(f"{c.name}[{c.detail}]" for c in r.failed_checks)
            print(Con.err(f"  {r.name} {r.display}: {details}"))
            if r.log:
                print(Con.dim(f"    全量日志: {r.log}"))
    print("========================================")


def run_levels(ctx: Ctx, *, remote: str, targets: list[str], timeout: int,
               out_dir: Path, json_path: str | None = "auto") -> int:
    """执行 Level 套件；返回退出码（0/1/2，见模块头注契约）。"""
    host = ctx.host(remote)
    levels = resolve_targets(targets)
    multi = len(levels) > 1
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    outdir = out_dir / f"levels_{ts}"
    manifest: Path | None = None
    if json_path == "auto":
        if not ctx.dry_run:
            manifest = outdir / "manifest.json"
    elif json_path not in ("none", None):
        manifest = Path(json_path)

    records: list[CaseRecord] = []

    if multi and not ctx.dry_run:
        print(f"=== 预检: 哨兵页完整性 ({remote}) ===")
        rc, text = sentinel_canary(host)
        print(text, end="" if text.endswith("\n") else "\n")
        if rc == 2:
            print("========================================")
            print(Con.err("中止: 哨兵页已污染 — 哨兵相关 Level "
                          f"({SENTINEL_SENSITIVE}) 会级联误报"))
            print("恢复: 重载 symrdma 模块 (特权): "
                  "bash ~/pro/symrdma/scripts/symrdma_reload.sh mode=1 "
                  "pci_bdf=<本机BDF>")
            print("========================================")
            if manifest:
                write_manifest(manifest, suite="levels",
                               meta={"remote": remote, "timeout": timeout,
                                     "aborted": "sentinel-polluted"},
                               cases=[], verdict="ABORT", failed=[],
                               started=started, duration=time.monotonic() - t0)
            return 2
        if rc != 0:
            print(f">>> 预检失败 (rc={rc}, /dev/symrdma 不可用或超时) — 继续执行套件")
        print()

    for lv in levels:
        print(f"=== Level {lv.id}: {lv.display} ({remote}) ===")
        rec = run_level(host, lv, timeout=timeout,
                        log_path=outdir / f"L{lv.id}.log")
        records.append(rec)
        if not rec.ok:
            if multi:
                detail = "; ".join(f"{c.name}[{c.detail}]"
                                   for c in rec.failed_checks)
                print(f">>> Level {lv.id} 失败 ({detail}), 继续后续 Level...")
            elif not ctx.dry_run:
                print(Con.err(f"✗ L{lv.id} 失败")
                      + Con.dim(f" (耗时 {rec.duration:.1f}s"
                                + (f", 日志 {rec.log}" if rec.log else ")")))
        elif not ctx.dry_run:
            print(Con.ok(f"✓ L{lv.id} ({rec.duration:.1f}s)"))
        print()

    total = time.monotonic() - t0
    if manifest:
        failed = [r.name for r in records if not r.ok]
        write_manifest(manifest, suite="levels",
                       meta={"remote": remote, "timeout": timeout,
                             "dry_run": ctx.dry_run, "targets":
                                 [lv.id for lv in levels]},
                       cases=records,
                       verdict="PASS" if not failed else "FAIL",
                       failed=failed, started=started, duration=total)

    if not multi:
        # 单目标：退出码 = 该级退出码（bash set -e 语义）
        return records[0].rc if records[0].ok or records[0].rc > 0 else 1

    _print_summary(records, total, manifest)
    return 0 if all(r.ok for r in records) else 1


def list_levels() -> None:
    print("单机 Level 套件 (levels):")
    for lv in LEVELS:
        mark = "all" if lv.in_all else "单独"
        note = f"  — {lv.note}" if lv.note else ""
        print(f"  L{lv.id:<3} {lv.display} [{mark}]{note}")
    print("  跨机双进程 (sir): L7/L10/L12/L13 → symtest sir")
