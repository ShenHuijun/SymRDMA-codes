"""原子操作基准 — run_atomic_bench.sh 的 Python 引擎（v0.39.0 自 bash 移植）。

三配置对照 (server@SERVER_HOST 的三个 MR 区; client@CLIENT_HOST 发起):
  pinned — Pinned Native: 硬件 RDMA 原子 (FAA/CAS) 打普通 pin MR
  odp    — ODP Native:    同硬件原子打 ON_DEMAND MR; 延迟轮前 server 换出
           全部计数页 (smaps Swap 就位确认) — 复现论文 "低密度延迟尖峰"
  sym    — SymRDMA 双端 (§3.4): 控制 QP RPC → server CPU lock cmpxchg/xadd

两族测量: lat (密度 {4,16,64,256} × N_LAT=512 → avg/p50/p99/max, Fig 14a/b)
+ thr (深度 {2..128} × 批在飞 N_THR=4096 → M ops/s, Fig 14c/d)。

门禁契约（bash 版一致）: RESULT 行计数 (lat/lat99 各 24, thr 42; ODP 跳过
时 16/16/28) + 零 FAIL + DONE 行; client rc=2 (ODP 不可用) 计 warning 通过。
输出: results/atomicbench_<ts>.log + .csv (+ manifest.json)。

改进（纯增量）: 双机预检/部署并行、JSON manifest、全量日志留档。
"""

from __future__ import annotations

import time
from pathlib import Path

from . import config
from .deploy import DeployUnit, ensure_deployed
from .remote import bg_start_script, run_parallel
from .report import CaseRecord, Check, Con, Tee, count_lines, write_manifest
from .ssh import Ctx, q


def _deploy_unit() -> DeployUnit:
    src = config.BENCH_SRC / "atomicbench.c"
    return DeployUnit(
        name="atomicbench",
        sources=[(str(src), "/tmp/atomicbench.c")],
        binaries=["/tmp/atomicbench"],
        compile_script=(
            "gcc -O2 -Wall -o /tmp/atomicbench /tmp/atomicbench.c -libverbs "
            "&& { echo COMPILE_OK; exit 0; }\n"
            "echo COMPILE_FAIL\n"
        ),
    )


def _precheck_script() -> str:
    return (
        "ok=1\n"
        '[ -r /proc/symrdma ] && echo "  symrdma 模块: ok" '
        '|| { echo "  symrdma 模块: 缺失"; ok=0; }\n'
        'command -v gcc >/dev/null 2>&1 && echo "  gcc: ok" '
        '|| { echo "  gcc: 缺失"; ok=0; }\n'
        'command -v ibv_devinfo >/dev/null 2>&1 && echo "  verbs: ok" '
        '|| { echo "  verbs: 缺失"; ok=0; }\n'
        '[ "$ok" = 1 ] && exit 0 || exit 1\n'
    )


def _gate(client_text: str, rc: int) -> list[Check]:
    """门禁（bash 版判据逐条移植；grep -c 计数 → count_lines）。"""
    nfail = count_lines(client_text, r"^FAIL ")
    ndone = count_lines(client_text, r"^DONE fail=")
    nlat = count_lines(client_text, r"^RESULT lat_")
    nlat99 = count_lines(client_text, r"^RESULT lat99_")
    nthr = count_lines(client_text, r"^RESULT thr_")
    odp_skip = count_lines(client_text, "ODP MR 不可用") > 0
    # 期望行数: lat avg 与 lat99 各 = 3cfg×2op×4dens = 24; thr = 3×2×7 = 42
    # (odp 跳过时 lat/lat99 各 16 + thr 28)
    exp_lat = 16 if odp_skip else 24
    exp_thr = 28 if odp_skip else 42
    checks = [
        Check("FAIL", nfail == 0, f"FAIL 行 ×{nfail}"),
        Check("DONE", ndone >= 1, "DONE 行缺失 (client 异常退出)"
              if ndone < 1 else f"DONE ×{ndone}"),
        Check("lat-rows", nlat == exp_lat, f"{nlat} ≠ 期望 {exp_lat}"),
        Check("lat99-rows", nlat99 == exp_lat, f"{nlat99} ≠ 期望 {exp_lat}"),
        Check("thr-rows", nthr == exp_thr, f"{nthr} ≠ 期望 {exp_thr}"),
    ]
    if rc == 2:
        checks.append(Check("exit-code", True,
                            "client rc=2 (ODP 不可用跳过)", warn=True))
    else:
        checks.append(Check("exit-code", rc == 0, f"client rc={rc}"))
    return checks


def _csv_rows(client_text: str) -> list[str]:
    """RESULT 行 → CSV 行（bash: awk '{print $2","$3","$4}'）。"""
    rows = []
    for line in client_text.splitlines():
        if line.startswith("RESULT "):
            parts = line.split()
            if len(parts) >= 4:
                rows.append(",".join(parts[1:4]))
    return rows


def _fmt(v: str | None) -> str:
    return v if v else "—"


def _print_summary(csv_rows: list[str], tee: Tee) -> None:
    vals: dict[str, str] = {}
    for row in csv_rows:
        key = row.split(",")[0]
        vals.setdefault(key, row.split(",")[1] if "," in row else "")

    tee.emit()
    tee.emit("=== 汇总 (论文 Fig 14 口径) ===")
    tee.emit("--- Fig 14a/14b: 延迟 avg (µs) vs 计数密度 ---")
    tee.emit(f"{'密度(计数/页)':<14} {'pinned':>10} {'odp':>10} {'sym':>10} "
             f"{'sym−pinned':>12}")
    for d in (4, 16, 64, 256):
        for op in ("faa", "cas"):
            p = vals.get(f"lat_pinned_{op}_d{d}")
            o = vals.get(f"lat_odp_{op}_d{d}")
            s = vals.get(f"lat_sym_{op}_d{d}")
            delta = ""
            if p and s:
                try:
                    delta = f"{float(s) - float(p):.2f}"
                except ValueError:
                    delta = ""
            tee.emit(f"{op + '/d' + str(d):<14} {_fmt(p):>10} "
                     f"{o if o else '(skip)':>10} {_fmt(s):>10} {delta:>12}")
    tee.emit("--- Fig 14c/14d: 吞吐 (Mops/s) vs 流水深度 ---")
    tee.emit(f"{'深度':<14} {'pinned':>10} {'odp':>10} {'sym':>10}")
    for depth in (2, 4, 8, 16, 32, 64, 128):
        for op in ("faa", "cas"):
            pv = vals.get(f"thr_pinned_{op}_p{depth}")
            ov = vals.get(f"thr_odp_{op}_p{depth}")
            sv = vals.get(f"thr_sym_{op}_p{depth}")
            tee.emit(f"{op + '/2^' + str(depth):<14} {_fmt(pv):>10} "
                     f"{ov if ov else '(skip)':>10} {_fmt(sv):>10}")


def run_atomic(ctx: Ctx, *, server_host_name: str, client_host_name: str,
               server_ip: str, port: int, gid: str, dev: str,
               out_dir: Path, json_path: str | None = "auto") -> int:
    server_host = ctx.host(server_host_name)
    client_host = ctx.host(client_host_name)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    out_log = out_dir / f"atomicbench_{ts}.log"
    csv_path = out_dir / f"atomicbench_{ts}.csv"
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else \
            out_dir / f"atomicbench_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None
    if not ctx.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    srv_log = "/tmp/atomicbench_server.log"

    records: list[CaseRecord] = []
    try:
        with Tee(None if ctx.dry_run else out_log) as tee:
            tee.emit(f"=== 预检 (server={server_host_name} "
                     f"client={client_host_name} dev={dev} gid={gid}) ===")

            def _pre(host) -> bool:
                res = host.run_script(_precheck_script(), timeout=30)
                if res.rc != 0 and not ctx.dry_run:
                    raise RuntimeError(f"[{host.host}] 预检失败:\n{res.text.strip()}")
                print(f"[{host.host}] ok")
                return True
            run_parallel({server_host_name: lambda: _pre(server_host),
                          client_host_name: lambda: _pre(client_host)})

            tee.emit("=== 部署 (atomicbench, md5 比对) ===")
            unit = _deploy_unit()
            if ctx.dry_run:
                ensure_deployed(server_host, unit, log=tee.emit)
                ensure_deployed(client_host, unit, log=tee.emit)
            else:
                run_parallel({
                    server_host_name: lambda: ensure_deployed(server_host, unit, log=print),
                    client_host_name: lambda: ensure_deployed(client_host, unit, log=print),
                })

            if ctx.dry_run:
                server_host.run_script(bg_start_script(
                    ["/tmp/atomicbench", "server", "-p", str(port),
                     "-d", dev, "-g", gid],
                    log=srv_log, prekill="atomicbench",
                    sleep_before_start=1))
                client_host.run_script(
                    f"stdbuf -oL timeout 600 /tmp/atomicbench client "
                    f"-c {q(server_ip)} -d {q(dev)} -g {q(gid)} -p {q(str(port))}\n")
                client_host.run_script(f"tail -5 {q(srv_log)}\n")
                return 0

            tee.emit(f"=== [1/2] 启动 server@{server_host_name} (port={port}) ===")
            server_host.run_script(bg_start_script(
                ["/tmp/atomicbench", "server", "-p", str(port),
                 "-d", dev, "-g", gid],
                log=srv_log, prekill="atomicbench", sleep_before_start=1),
                timeout=30)
            time.sleep(2)
            nready = sum(1 for line in server_host.read_file(srv_log).splitlines()
                         if "ready" in line)
            if nready < 1:
                tee.emit(Con.err(f"server 未就绪 "
                                 f"(见 {server_host_name}:{srv_log})"))
                raise RuntimeError("server 未就绪")

            tee.emit(f"=== [2/2] 运行 client@{client_host_name} ===")
            collected: list[str] = []

            def on_line(line: str) -> None:
                collected.append(line)
                tee.emit(line)

            res = client_host.run_script(
                f"stdbuf -oL timeout 600 /tmp/atomicbench client "
                f"-c {q(server_ip)} -d {q(dev)} -g {q(gid)} -p {q(str(port))}\n",
                timeout=660, on_line=on_line)
            client_text = "".join(collected)

            # server 收尾 + 日志取回
            time.sleep(1)
            tail = server_host.run_script(f"tail -5 {q(srv_log)}\n", timeout=15)
            tee.emit(tail.text.rstrip("\n"))

            tee.emit()
            tee.emit("=== 门禁 ===")
            checks = _gate(client_text, res.rc)
            for c in checks:
                if c.ok:
                    tee.emit(Con.ok(f"  ✓ {c.name}: {c.detail}"))
                elif c.warn:
                    tee.emit(Con.warn(f"  ⚠ {c.name}: {c.detail}"))
                else:
                    tee.emit(Con.err(f"  ✗ {c.name}: {c.detail}"))
            rec = CaseRecord(name="atomicbench", display="原子基准双机",
                             rc=res.rc, duration=time.monotonic() - t0,
                             checks=checks, log=str(out_log))
            records.append(rec)
            n_ok = sum(1 for c in checks if c.ok)
            if rec.ok:
                tee.emit(Con.ok(f"✓ 门禁全绿 ({n_ok}/{len(checks)} 项判定通过)"))
            else:
                tee.emit(Con.err("✗ 门禁存在失败项"))

            # ---- CSV 提取 + 汇总表 ----
            csv_path.write_text(
                "row,value,unit\n" + "\n".join(_csv_rows(client_text)) + "\n",
                encoding="utf-8")
            _print_summary(_csv_rows(client_text), tee)

            tee.emit()
            tee.emit(f"日志: {out_log}")
            tee.emit(f"CSV : {csv_path}")
    finally:
        if not ctx.dry_run:
            server_host.pkill("atomicbench")

    if manifest:
        failed = [] if all(r.ok for r in records) else [r.name for r in records]
        write_manifest(manifest, suite="atomic",
                       meta={"server": server_host_name, "client":
                             client_host_name, "server_ip": server_ip,
                             "port": port, "gid": gid, "dev": dev},
                       cases=records,
                       verdict="PASS" if not failed else "FAIL",
                       failed=failed, started=started,
                       duration=time.monotonic() - t0)
    return 0 if all(r.ok for r in records) else 1
