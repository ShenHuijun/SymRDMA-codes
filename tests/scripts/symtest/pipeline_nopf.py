"""no-PF 全流水线 — nopf_pipeline.sh 的 Python 引擎。

流程: [0]双机预检 → [1]同步+编译 (build.sh × 2 机) → [2]基准 × N 轮
(bench_nopf.run_nopf, 自带生效门禁) → [3]多轮平均+回归对比 (nopf_avg.py)
→ [4]出图 (plot_nopf_bw.py) → [5]汇总。
退出码: 任一轮失败 / 线速区回归 > THRESH → 非零。
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

from . import config
from .report import Tee
from .ssh import Ctx


def run_pipeline(ctx: Ctx, *, server_host_name: str, client_host_name: str,
                 server_ip: str, dev: str, gid: str, runs: int,
                 thresh: float, skip_build: bool, out_dir: Path,
                 json_path: str | None = "auto") -> int:
    from . import bench_nopf  # 局部导入避免循环

    ts = config.timestamp()
    out_dir.mkdir(parents=True, exist_ok=True)
    pipe_log = out_dir / f"nopf_pipeline_{ts}.log"
    csvs: list[Path] = []

    def log(msg: str) -> None:
        print(msg)
        with pipe_log.open("a", encoding="utf-8", errors="replace") as f:
            f.write(msg + "\n")

    log(f"=== SymRDMA no-PF 流水线: {runs} 轮 × ({server_host_name} server / "
        f"{client_host_name} client) ===")
    log(f"=== 开始 {ts} (日志: {pipe_log}) ===")

    # ---- [0/5] 预检: 可达 + 模块 + 无残留 ----
    log("")
    log("--- [0/5] 预检 ---")
    if not ctx.dry_run:
        for h in (client_host_name, server_host_name):
            host = ctx.host(h)
            res = host.run_script(
                "test -c /dev/symrdma || exit 1\n"
                "pgrep -f npfbw_bench >/dev/null && exit 1\n"
                "pgrep -f test_odp >/dev/null && exit 1\n"
                "lsmod | grep -q '^symrdma ' || exit 1\n", timeout=30)
            mr = host.mr_count()
            if res.rc != 0:
                log(f"✗ {h}: 预检失败 (/dev/symrdma 缺失 / 模块未加载 / "
                    "残留进程)")
                return 1
            if mr != 0:
                log(f"✗ {h}: 活跃 MR={mr} ≠ 0 (残留注册, 先清理)")
                return 1
            log(f"  {h}: /dev/symrdma OK, 模块 OK, MR 基线 0, 无残留进程")

    # ---- [1/5] 同步 + 编译 (两台各一遍; build.sh 增量) ----
    log("")
    log("--- [1/5] 同步 + 编译 ---")
    if ctx.dry_run:
        for h in (client_host_name, server_host_name):
            log(f"  [dry-run] REMOTE={h} bash scripts/build.sh")
    elif skip_build:
        log("  跳过 (--skip-build)")
    else:
        for h in (client_host_name, server_host_name):
            env = {**__import__("os").environ, "REMOTE": h}
            proc_b = subprocess.run(
                ["bash", str(config.REPO / "scripts" / "build.sh")],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            with pipe_log.open("ab") as f:
                f.write(proc_b.stdout or b"")
            if proc_b.returncode != 0:
                log(f"✗ {h}: build.sh 失败 (详见 {pipe_log})")
                return 1
            log(f"  {h}: build OK")

    # ---- [2/5] 基准 × N 轮 (生效门禁内建, 失败即中止) ----
    log("")
    log(f"--- [2/5] 基准 × {runs} 轮 ---")
    if ctx.dry_run:
        bench_nopf.run_nopf(
            ctx, server_host_name=server_host_name,
            client_host_name=client_host_name, server_ip=server_ip,
            dev=dev, gid=gid, sizes=list(bench_nopf.DEFAULT_SIZES),
            out_dir=out_dir, json_path="none")
        log("  dry-run: 跳过平均/出图 (轮脚本已打印)")
        log(f"  流水线日志: {pipe_log}")
        return 0
    for i in range(1, runs + 1):
        rc, csv = bench_nopf.run_nopf(
            ctx, server_host_name=server_host_name,
            client_host_name=client_host_name, server_ip=server_ip,
            dev=dev, gid=gid, sizes=list(bench_nopf.DEFAULT_SIZES),
            out_dir=out_dir, json_path="none",
            tee=Tee(None if ctx.dry_run else pipe_log))
        if rc != 0 or csv is None:
            log(f"✗ 第 {i} 轮基准失败 (生效门禁或测量错误)")
            return 1
        csvs.append(csv)
        log(f"  轮 {i}/{runs}: {csv} ✓")
        time.sleep(2)   # 轮间冷却 (swap/页面状态归零)

    # ---- [3/5] 平均 + 回归对比 ----
    log("")
    log("--- [3/5] 平均 + 回归对比 ---")
    prev_csvs = sorted(out_dir.glob("nopf_bw_avg_*.csv"))
    prev = prev_csvs[-1] if prev_csvs else None
    avg_csv = out_dir / f"nopf_bw_avg_{ts}.csv"
    cmd = [sys.executable, str(config.PKG_DIR.parent / "nopf_avg.py"),
           *[str(c) for c in csvs], "--out", str(avg_csv)]
    if prev and prev != avg_csv:
        cmd += ["--compare", str(prev), "--thresh", str(thresh)]
        log(f"  基线: {prev}")
    else:
        log("  无历史 avg 基线 — 首次运行, 跳过回归判定")
    proc = subprocess.run(cmd, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True)
    print(proc.stdout.rstrip())
    with pipe_log.open("a", encoding="utf-8", errors="replace") as log_f:
        log_f.write(proc.stdout)
    if proc.returncode != 0:
        log(f"  ✗ 线速区回归超阈值 (THRESH={thresh}%)")
    rc_avg = proc.returncode

    # ---- [4/5] 出图 ----
    log("")
    log("--- [4/5] 出图 ---")
    proc2 = subprocess.run(
        [sys.executable, str(config.PKG_DIR.parent / "plot_nopf_bw.py"),
         str(avg_csv)],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    print(proc2.stdout.rstrip()[-400:])
    log(f"  图: {str(avg_csv).removesuffix('.csv')}.png / .pdf")

    # ---- [5/5] 汇总 ----
    log("")
    log("--- [5/5] 完成 ---")
    log(f"  原始 CSV × {len(csvs)}: {' '.join(str(c) for c in csvs)}")
    log(f"  平均 CSV: {avg_csv}")
    log(f"  流水线日志: {pipe_log}")
    return rc_avg
