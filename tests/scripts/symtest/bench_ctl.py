"""控制面开销基准 — run_ctl_bench.sh 的 Python 引擎 (论文 Tables 1/2)。

每台主机独立跑两相位 (全部测量主机本地, 无跨机配对):
  vanilla: 无 preload — 原生路径 (注册 = GUP pin + dma_map)
  sym:     NPRDMA_INTERCEPT=all + LD_PRELOAD=libnprdma.so — 拦截层生效
           门禁: 输出必含 "SymRDMA mr_id" 拦截行 + swap_notifier_delta > 0
           (notifier 真实触发); vanilla 反向门禁: 输出不得含 "[nprdma]"

测量行: lib_init / mr_first / mr_base / mr_reg_<MB> + mr_slope(ms/GB) /
cq_create / qp_create / qp_rts / swap_out (+swap_notifier_delta 仅 sym)。
论文参考值 (Table 2): Library init 43→49ms; Create MR 50µs+400ms/GB →
135µs+20ms/GB; Create QP 45→67µs; Create CQ 29→56µs; QP init 12→19µs;
Swap out 75→78µs/page。

斜率口径注记: 本实现内核 REG_MR 逐 4KB 页双 IOVA iommu_map (2 次/页),
与论文的 IOMMU 大页映射实现不同 — sym 斜率预计高于论文 20ms/GB, 为如实
记录的实现差异 (TESTING §7.3)。

无 mlockall (swap 测量需要可换出页, 与 npfbw 的 no-PF 前提相反)。
含空格串 (PRE/MBS) 一律经 Python 拼进脚本文本并 shlex.quote —
bash 版的 "ssh argv 拆词" 陷阱 (v0.24.5/v0.29.1) 在此结构性消失。
"""

from __future__ import annotations

import time
from pathlib import Path

from . import config
from .deploy import DeployUnit, ensure_deployed
from .report import CaseRecord, Check, Con, Tee, count_lines, write_manifest
from .ssh import Ctx, q

# 斜率点 (MB; 上限 512 — 内核页数组 kcalloc 16B/页, >512MB 有超
# KMALLOC_MAX(4MB) 风险)
CTLB_MBS_DEFAULT = "64 128 256 512"


def _deploy_unit() -> DeployUnit:
    src = config.BENCH_SRC / "ctlbench.c"
    return DeployUnit(
        name="ctlbench",
        sources=[(str(src), "/tmp/ctlbench.c")],
        binaries=["/tmp/ctlbench"],
        compile_script=("gcc -O2 -Wall -o /tmp/ctlbench /tmp/ctlbench.c "
                        "-libverbs && { echo COMPILE_OK; exit 0; }\n"
                        "echo COMPILE_FAIL\n"),
    )


def _precheck() -> str:
    return (
        "ok=1\n"
        '[ -r /proc/symrdma ] && echo "  symrdma 模块: ok" '
        '|| { echo "  symrdma 模块: 缺失"; ok=0; }\n'
        'command -v gcc >/dev/null 2>&1 && echo "  gcc: ok" '
        '|| { echo "  gcc: 缺失"; ok=0; }\n'
        '[ -f "$HOME/pro/symrdma/nprdma/libnprdma.so" ] && echo "  libnprdma: ok" '
        '|| { echo "  libnprdma: 缺失"; ok=0; }\n'
        'command -v ibv_devinfo >/dev/null 2>&1 && echo "  verbs: ok" '
        '|| { echo "  verbs: 缺失"; ok=0; }\n'
        '[ "$ok" = 1 ] && exit 0 || exit 1\n'
    )


def run_phase(ctx: Ctx, host, *, mode: str, dev: str, gid: str, mbs: str,
              out_dir: Path, ts: str, tee: Tee) -> tuple[CaseRecord, list[str]]:
    """单机单相位 (vanilla|sym): 运行 + 门禁 + CSV 行提取。"""
    t0 = time.monotonic()
    phase_log = out_dir / f"ctlbench_{ts}_{host.host}_{mode}.log"
    extra = "--mr" if mode == "sym" else ""
    # sym 相位: swap 缓冲注册为 SymRDMA MR (notifier 附加); vanilla 注册会
    # pin 住页无法换出, 基线用裸匿名页
    if mode == "sym":
        pre = ("env NPRDMA_INTERCEPT=all "
               f"LD_PRELOAD={config.LIBNPRDMA} NPRDMA_DEBUG=1")
    else:
        pre = "env"

    script = (
        f"timeout 180 {pre} /tmp/ctlbench -d {q(dev)} -g {q(gid)} "
        f"--swap {extra} -m {q(mbs)} 2>&1\n"
    )
    collected: list[str] = []

    def _on_line(line: str) -> None:
        collected.append(line)
        tee.emit(line)

    host.run_script(script, timeout=240, on_line=_on_line)
    out = "".join(collected)
    if ctx.dry_run:
        rec = CaseRecord(
            name=f"{host.host}/{mode}",
            display=f"{mode} 相位",
            rc=0,
            duration=time.monotonic() - t0,
            checks=[Check("dry-run", True, "命令已生成，跳过真实结果门禁")],
            log=None,
        )
        tee.emit(f"[{host.host}/{mode}] dry-run")
        return rec, []

    phase_log.write_text(out, encoding="utf-8")

    # ---- 门禁 (grep -c 语义 → count_lines, 无 SIGPIPE 假阴性) ----
    checks = [Check("FAIL", count_lines(out, r"^FAIL ") == 0,
                    f"FAIL 行 ×{count_lines(out, r'^FAIL ')}"),
              Check("DONE", "DONE fail=0" in out, "DONE 行缺失或 fail≠0")]
    nreg = count_lines(out, "SymRDMA mr_id")
    nnpr = count_lines(out, r"\[nprdma\]")
    ndelta = ""
    for line in out.splitlines():
        if line.startswith("RESULT ") and "swap_notifier_delta" in line:
            ndelta = line.split()[2]
            break
    if mode == "sym":
        checks.append(Check("intercept", nreg >= 1,
                            "无 [nprdma] reg 拦截行 (拦截未生效?)"
                            if nreg < 1 else f"拦截行 ×{nreg}"))
        try:
            delta_ok = ndelta != "" and float(ndelta) > 0
        except ValueError:
            delta_ok = False
        checks.append(Check("notifier-delta", delta_ok,
                            f"swap_notifier_delta={ndelta or '空'} "
                            "(notifier 未触发)"))
    else:
        checks.append(Check("no-preload-leak", nnpr == 0,
                            "vanilla 相位输出含 [nprdma] 行 (preload 泄漏?)"))

    # RESULT 行 → CSV (host,mode,row,value,unit)
    csv_rows = []
    for line in out.splitlines():
        if line.startswith("RESULT "):
            parts = line.split()
            if len(parts) >= 4:
                csv_rows.append(f"{host.host},{mode},"
                                f"{parts[1]},{parts[2]},{parts[3]}")

    rec = CaseRecord(name=f"{host.host}/{mode}", display=f"{mode} 相位",
                     rc=0 if all(c.ok or c.warn for c in checks) else 1,
                     duration=time.monotonic() - t0, checks=checks,
                     log=str(phase_log) if not ctx.dry_run else None)
    mark = Con.ok("✓") if rec.ok else Con.err("✗")
    tee.emit(f"[{host.host}/{mode}] {mark}")
    return rec, csv_rows


# 论文 Table 2 参考值 (vanilla → sym)
PAPER_ROWS = (
    ("lib_init", "43 → 49", "ms"),
    ("mr_first", "—(含于 init)", "us"),
    ("mr_base", "50 → 135", "us"),
    ("mr_slope", "400 → 20", "ms/gb"),
    ("cq_create", "29 → 56", "us"),
    ("qp_create", "45 → 67", "us"),
    ("qp_rts", "12 → 19", "us"),
    ("swap_out", "75 → 78", "us/page"),
)


def _print_summary(hosts: list[str], vals: dict[tuple[str, str, str], str],
                   tee: Tee) -> None:
    tee.emit()
    tee.emit("=== 汇总 (论文 Table 2 参考: vanilla → sym) ===")
    tee.emit(f"{'row':<14} {'paper (van→sym)':<22} "
             + " ".join(f"{h} (van→sym)" for h in hosts))
    for row, paper, _unit in PAPER_ROWS:
        cols = []
        for h in hosts:
            v0 = vals.get((h, "vanilla", row), "—")
            v1 = vals.get((h, "sym", row), "—")
            cols.append(f"{v0} → {v1}")
        tee.emit(f"{row:<14} {paper:<22} " + "  ".join(f"{c:<24}" for c in cols))
    tee.emit()


def run_ctl(ctx: Ctx, *, hosts: list[str], dev: str, gid: str, mbs: str,
            out_dir: Path, json_path: str | None = "auto") -> int:
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    csv_path = out_dir / f"ctlbench_{ts}.csv"
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else out_dir / f"ctlbench_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None
    if not ctx.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    host_objs = [ctx.host(h) for h in hosts]
    records: list[CaseRecord] = []
    csv_lines: list[str] = ["host,mode,row,value,unit"]
    try:
        with Tee(None if ctx.dry_run else
                 out_dir / f"ctlbench_{ts}.log") as tee:
            tee.emit(f"=== 预检 (hosts={hosts} dev={dev} gid={gid}) ===")
            for h in host_objs:
                res = h.run_script(_precheck(), timeout=30)
                tee.emit(res.text.rstrip())
                if res.rc != 0 and not ctx.dry_run:
                    tee.emit(Con.err(f"[{h.host}] 预检失败"))
                    return 1

            tee.emit("=== 部署 (ctlbench, md5 比对) ===")
            unit = _deploy_unit()
            for h in host_objs:
                ensure_deployed(h, unit, log=tee.emit)

            tee.emit("=== 运行 (每机 vanilla + sym) ===")
            failed = 0
            for h in host_objs:
                for mode in ("vanilla", "sym"):
                    rec, rows = run_phase(ctx, h, mode=mode, dev=dev,
                                          gid=gid, mbs=mbs, out_dir=out_dir,
                                          ts=ts, tee=tee)
                    records.append(rec)
                    csv_lines.extend(rows)
                    if not rec.ok:
                        failed += 1

            vals: dict[tuple[str, str, str], str] = {}
            for line in csv_lines[1:]:
                parts = line.split(",")
                if len(parts) >= 4:
                    vals[(parts[0], parts[1], parts[2])] = parts[3]
            _print_summary(hosts, vals, tee)
            if not ctx.dry_run:
                csv_path.write_text("\n".join(csv_lines) + "\n",
                                    encoding="utf-8")
                tee.emit(f"CSV: {csv_path}")
    finally:
        if not ctx.dry_run:
            for h in host_objs:
                h.pkill("ctlbench")

    total = time.monotonic() - t0
    ok = all(r.ok for r in records)
    if manifest and records:
        write_manifest(manifest, suite="ctl",
                       meta={"hosts": hosts, "dev": dev, "gid": gid,
                             "mbs": mbs},
                       cases=records, verdict="PASS" if ok else "FAIL",
                       failed=[] if ok else [r.name for r in records
                                             if not r.ok],
                       started=started, duration=total)
    return 0 if ok else 1
