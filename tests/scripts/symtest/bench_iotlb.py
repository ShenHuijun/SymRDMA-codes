"""L18 IOTLB/ATC 工作集容量曲线 — run_iotlb_ws.sh 的 Python 引擎 (论文 Fig 19)。

server 分配/触碰/注册 -W 工作集 (thp 可控), client 固定 4KB RDMA Read 按
seq/rand 访问整个 WS → 工作集超出 ATC 容量时带宽骤降 (per-page 4KB IOMMU
映射形态)。对照: raw (无引擎) / sym (透明引擎拦截, Phase 2 后 2MB 超页)。

部署 (npfbw_bench + mlockall_shim) 与 run_nopf 同款: md5 比对按需编译,
新二进制先 EDR 放行预热 (TESTING §5.2: 行为扫描窗口会 SIGTERM 洪水)。
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from . import config
from .deploy import DeployUnit, ensure_deployed
from .remote import bg_start_script, run_parallel, wait_ready_script
from .report import CaseRecord, Check, Con, Tee, write_manifest
from .ssh import Ctx, q


def _deploy_unit() -> DeployUnit:
    bench = config.BENCH_SRC / "npfbw_bench.c"
    shim = config.BENCH_SRC / "mlockall_shim.c"
    return DeployUnit(
        name="npfbw_ws",
        sources=[(str(bench), "/tmp/npfbw_bench.c"),
                 (str(shim), "/tmp/npfbw_mlock.c")],
        binaries=["/tmp/npfbw_bench", "/tmp/npfbw_mlock.so"],
        compile_script=(
            "gcc -O2 -shared -fPIC -o /tmp/npfbw_mlock.so /tmp/npfbw_mlock.c "
            "|| { echo COMPILE_FAIL; exit 0; }\n"
            "gcc -O2 -Wall -o /tmp/npfbw_bench /tmp/npfbw_bench.c -libverbs "
            "|| { echo COMPILE_FAIL; exit 0; }\n"
            "echo COMPILE_OK\n"
        ),
    )


def _pre(variant: str) -> str:
    """LD_PRELOAD 前缀（sym = shim + 透明引擎; raw = 仅 shim）。"""
    if variant == "sym":
        return ("env NPRDMA_INTERCEPT=all "
                "LD_PRELOAD=/tmp/npfbw_mlock.so:$HOME/pro/symrdma/nprdma/libnprdma.so "
                "NPRDMA_DEBUG=1")
    return "env LD_PRELOAD=/tmp/npfbw_mlock.so"


def preheat(server_host, client_host, *, server_ip: str, dev: str, gid: str,
           attempts: int = 4, tee: Tee) -> bool:
    """EDR 放行预热：小洪水至存活 (≥4 PREHEAT 行) — 新二进制扫描窗口。"""
    for att in range(1, attempts + 1):
        server_host.run_script(
            "pkill -f npfbw_bench 2>/dev/null; true\nsleep 0.3\n"
            'nohup env LD_PRELOAD=/tmp/npfbw_mlock.so /tmp/npfbw_bench -s '
            '-d mlx5_0 -g 5 >/tmp/npfbw_preheat_srv.log 2>&1 </dev/null &\n'
            "sleep 1\n", timeout=30)
        r = client_host.run_script(
            f"timeout 120 env LD_PRELOAD=/tmp/npfbw_mlock.so /tmp/npfbw_bench "
            f"-P -c {q(server_ip)} -d {q(dev)} -g {q(gid)}\n", timeout=150)
        n = sum(1 for line in r.text.splitlines()
                if line.startswith("PREHEAT "))
        if n >= 4:
            tee.emit(f"  预热尝试 {att}: 存活 (PREHEAT ×{n}) — EDR 放行")
            server_host.pkill("npfbw_bench")
            return True
        tee.emit(f"  预热尝试 {att}: 被终止 (PREHEAT ×{n}) — 等 20s 重试")
        server_host.pkill("npfbw_bench")
        time.sleep(20)
    return False


def run_point(ctx: Ctx, *, server_host, client_host, server_ip: str,
              dev: str, gid: str, port: int, variant: str, ws: str,
              pattern: str, thp: str, iters: int, msg: int,
              csv_f, tee: Tee) -> bool:
    """单点: server 单进程 (-W ws) → client 扫描 → WSRESULT/WSTHP → CSV 行。"""
    thp_args = ("-T", "on") if thp == "on" else ()
    iters_args = ("-n", str(int(iters))) if iters else ()
    srv_log = "/tmp/npfbw_ws_srv.log"
    server_host.run_script(
        bg_start_script(
            ["/tmp/npfbw_bench", "-s", "-d", dev, "-g", gid,
             "-p", str(port), "-W", ws, *thp_args],
            log=srv_log, prekill="npfbw_bench", sleep_before_start=0.3,
            prefix=_pre(variant)), timeout=30)
    # 触碰+注册大 WS 需时间: 等 server 就绪 (最多 120s)
    res = server_host.run_script(
        wait_ready_script(srv_log, "SERVER waiting", "npfbw_bench",
                          tries=60, interval=2.0), timeout=140)
    if res.rc != 0:
        tee.emit(Con.err(f"  ✗ {variant} {ws} {pattern}: server 未就绪"))
        csv_f.write(f"WS,{variant},{pattern},{thp},{ws},{msg},,,NA\n")
        return False

    script = (
        f"timeout 400 {_pre(variant)} /tmp/npfbw_bench -c {q(server_ip)} "
        f"-d {q(dev)} -g {q(gid)} -p {q(str(port))} -W {q(ws)} "
        + " ".join(q(a) for a in thp_args)
        + f" --pattern {q(pattern)} -m {int(msg)} "
        + " ".join(q(a) for a in iters_args) + "\n"
    )
    res = client_host.run_script(script, timeout=460)
    wsresult = ""
    for line in res.text.splitlines():
        if line.startswith("WSRESULT,"):
            wsresult = line
    # server 侧 THP 驻留验证行 (AnonHugePages 佐证)
    sthp = server_host.read_file(srv_log)
    if ctx.dry_run:
        tee.emit(f"  {variant} {ws} {pattern}: dry-run")
        server_host.pkill("npfbw_bench")
        return True
    anon = ""
    m = re.search(r"WSTHP .*anon_huge_mb=(\d+)", sthp)
    if m:
        anon = m.group(1)

    ok = bool(wsresult)
    if ok:
        # WSRESULT,thp=,pattern=,ws_mb=,msg=,iters=,bw_MB_s= → CSV 行
        vals = [f.split("=", 1)[1] if "=" in f else f
                for f in wsresult.split(",")[1:]]
        csv_f.write(f"WS,{variant},"
                    + ",".join(vals) + f",{anon or 'NA'}\n")
        bw = vals[5] if len(vals) > 5 else "?"
        tee.emit(f"  {variant} {ws} {pattern} thp={thp}: bw={bw} MB/s "
                 f"anon_huge_mb={anon or 'NA'}")
    else:
        csv_f.write(f"WS,{variant},{pattern},{thp},{ws},{msg},,,{anon or 'NA'}\n")
        tee.emit(Con.err(f"  ✗ {variant} {ws} {pattern}: 无 WSRESULT "
                         f"(rc={res.rc})"))
    csv_f.flush()
    server_host.pkill("npfbw_bench")
    time.sleep(0.5)
    return ok


def run_iotlb(ctx: Ctx, *, server_host_name: str, client_host_name: str,
              server_ip: str, dev: str, gid: str, port: int, tag: str,
              thp: str, iters: int, msg: int, ws_raw: list[str],
              ws_sym: list[str], patterns: list[str], out_dir: Path,
              json_path: str | None = "auto") -> int:
    server_host = ctx.host(server_host_name)
    client_host = ctx.host(client_host_name)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    csv_path = out_dir / f"iotlb_ws_{tag}_{ts}.csv"
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else \
            out_dir / f"iotlb_ws_{tag}_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None
    if not ctx.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)

    records: list[CaseRecord] = []
    checks: list[Check] = []
    nfail = 0
    try:
        with Tee(None if ctx.dry_run else
                 out_dir / f"iotlb_ws_{tag}_{ts}.log") as tee:
            tee.emit(f"=== L18 IOTLB 工作集扫描 (client={client_host_name} "
                     f"server={server_host_name} thp={thp} tag={tag}) ===")
            unit = _deploy_unit()
            if ctx.dry_run:
                ensure_deployed(server_host, unit, log=tee.emit)
                ensure_deployed(client_host, unit, log=tee.emit)
            else:
                changed = run_parallel({
                    server_host_name: lambda: ensure_deployed(server_host, unit, log=print),
                    client_host_name: lambda: ensure_deployed(client_host, unit, log=print),
                })
                if any(changed.values()):
                    tee.emit("=== EDR 放行预热 (新二进制, 最多 4 轮) ===")
                    if not preheat(server_host, client_host,
                                   server_ip=server_ip, dev=dev, gid=gid,
                                   tee=tee):
                        tee.emit(Con.err("预热未放行 — 稍后重跑 (跳过重编译)"))
                        return 1

            if ctx.dry_run:
                base_mr = None
            else:
                base_mr = server_host.mr_count()
                tee.emit(f"server 活跃 MR 基线: {base_mr}")

            csv_f = None
            try:
                csv_f = csv_path.open("w", encoding="utf-8") \
                    if not ctx.dry_run else None
                points: list[tuple[str, str]] = (
                    [(v, w) for v, wlist in (("raw", ws_raw),
                                             ("sym", ws_sym))
                     for w in wlist])
                for pattern in patterns:
                    for variant, ws in points:
                        if ctx.dry_run:
                            run_point(ctx, server_host=server_host,
                                      client_host=client_host,
                                      server_ip=server_ip, dev=dev, gid=gid,
                                      port=port, variant=variant, ws=ws,
                                      pattern=pattern, thp=thp, iters=iters,
                                      msg=msg, csv_f=_NullSink(), tee=tee)
                            continue
                        assert csv_f is not None
                        if not run_point(ctx, server_host=server_host,
                                         client_host=client_host,
                                         server_ip=server_ip, dev=dev,
                                         gid=gid, port=port, variant=variant,
                                         ws=ws, pattern=pattern, thp=thp,
                                         iters=iters, msg=msg, csv_f=csv_f,
                                         tee=tee):
                            nfail += 1
            finally:
                if csv_f:
                    csv_f.close()

            if ctx.dry_run:
                checks.append(Check("dry-run", True, "命令矩阵已生成"))
            else:
                end_mr = server_host.mr_count()
                tee.emit(f"server 结束活跃 MR: {end_mr} (基线 {base_mr})")
                checks.append(Check("mr-leak", end_mr == base_mr,
                                    f"{base_mr} → {end_mr}"))
                checks.append(Check("points", nfail == 0,
                                    f"失败点 ×{nfail}"))
            if not ctx.dry_run:
                tee.emit(f"=== 完成: {csv_path} ===")
                tee.emit("--- 摘要 (bw_MB_s; 失败为空) ---")
                tee.emit(csv_path.read_text(encoding="utf-8"))
    finally:
        if not ctx.dry_run:
            for h in (server_host, client_host):
                h.pkill("npfbw_bench")

    total = time.monotonic() - t0
    ok = all(c.ok for c in checks)
    records.append(CaseRecord(name=f"iotlb_{tag}", display="L18 IOTLB WS",
                              rc=0 if ok else 1, duration=total,
                              checks=checks, log=str(csv_path)))
    if manifest and records:
        write_manifest(manifest, suite="iotlb",
                       meta={"server": server_host_name,
                             "client": client_host_name, "thp": thp,
                             "tag": tag, "iters": iters, "msg": msg,
                             "ws_raw": ws_raw, "ws_sym": ws_sym,
                             "patterns": patterns},
                       cases=records, verdict="PASS" if ok else "FAIL",
                       failed=[] if ok else [records[0].name],
                       started=started, duration=total)
    return 0 if ok else 1


class _NullSink:
    """dry-run 用 CSV 汇 (不落盘)。"""

    def write(self, _s: str) -> None:
        pass

    def flush(self) -> None:
        pass
