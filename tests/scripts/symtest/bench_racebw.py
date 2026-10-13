"""Race 吞吐基准双机编排 — run_racebw.sh 的 Python 引擎 (论文 §5.2.1 Fig 12)。

四曲线对照 (server@SERVER_HOST 两区; client@CLIENT_HOST 发起):
  sym minor/major — SymRDMA 远端乐观路径 (libsymrdma 哨兵/seqlock + SIR
                    区间修复) 打 SymRDMA MR (unpinned, IOMMU 哨兵/黑洞)
  odp minor/major — 硬件 ODP (ON_DEMAND MR, 裸 verbs)
故障态: minor = span DONTNEED 重置; major = memset+PAGEOUT+smaps ≥90% 确认
尺寸: 2/16/128/1K/8K/64K/512K/4M × read/write → 64 RESULT 行

关键形态 (v0.36.0 实测教训):
  * client setsid 脱离 + exit 文件轮询 — 长持 SSH 会话会被环境杀
    (kubelet 崩溃循环期/EDR, rc=255 且 client 自身无害);
  * numactl 绑定 — DMA-only 数据区对 CPU 是"冷"页, NUMA balancing 反复
    PROT_NONE 标记 + 回收 → 哨兵化风暴; 绑定后标记仍会发生但页不迁移;
  * 新鲜度键 = bench 源码 + **libsymrdma.a** (静态链接库变更须重链;
    只比源码会用修复前的旧库 — 首跑实测教训)。
输出: results/racebw_<ts>.log + .csv + manifest。
退出码: 0=全绿 1=有 FAIL 2=ODP 不可用跳过 (带 warning 通过)。
"""

from __future__ import annotations

import time
from pathlib import Path

from . import config
from .deploy import DeployUnit, ensure_deployed
from .remote import detached_run_script, run_parallel
from .report import CaseRecord, Check, Con, Tee, count_lines, write_manifest
from .ssh import Ctx, q

SIZES = ("2", "16", "128", "1K", "8K", "64K", "512K", "4M")


def _deploy_unit() -> DeployUnit:
    return DeployUnit(
        name="racebw",
        sources=[(str(config.BENCH_SRC / "racebw_bench.c"),
                  "/tmp/racebw_bench.c")],
        # lib 只参与 hash、不推送 — 远端 .a 是 build.sh 远端编译产物
        hash_only=[(str(config.REPO / "lib" / "libsymrdma.a"),
                    "$HOME/pro/symrdma/lib/libsymrdma.a")],
        binaries=["/tmp/racebw"],
        compile_script=(
            'gcc -O2 -Wall -o /tmp/racebw /tmp/racebw_bench.c '
            '-I "$HOME"/pro/symrdma/lib -I "$HOME"/pro/symrdma/sir '
            '"$HOME"/pro/symrdma/lib/libsymrdma.a -libverbs -lpthread -ldl '
            '|| { echo COMPILE_FAIL; exit 0; }\n'
            "echo COMPILE_OK\n"
        ),
    )


def _gate(client_text: str, rc: str) -> list[Check]:
    """门禁 (bash 版判据移植): FAIL=0 + DONE + thr 行数 + sanity 块数。"""
    nfail = count_lines(client_text, r"^FAIL ")
    ndone = count_lines(client_text, r"^DONE fail=")
    nthr = count_lines(client_text, r"^RESULT thr_")
    nsanity = count_lines(client_text, r"^  (sym|odp) (minor|major):")
    odp_skip = count_lines(client_text, "ODP MR 不可用") > 0
    # 期望行数: 2cfg × 2fault × 2op × 8size = 64 (odp 跳过时 32); sanity 块 4/2
    exp_thr = 32 if odp_skip else 64
    exp_sanity = 2 if odp_skip else 4
    checks = [
        Check("FAIL", nfail == 0, f"FAIL 行 ×{nfail}"),
        Check("DONE", ndone >= 1, "DONE 行缺失 (client 异常退出)"
              if ndone < 1 else f"DONE ×{ndone}"),
        Check("thr-rows", nthr == exp_thr, f"{nthr} ≠ 期望 {exp_thr}"),
        Check("sanity", nsanity >= exp_sanity,
              f"sanity 通过块 {nsanity} < 期望 {exp_sanity}"),
    ]
    if rc == "2":
        checks.append(Check("exit-code", True,
                            "client rc=2 (ODP 不可用跳过)", warn=True))
    else:
        checks.append(Check("exit-code", rc == "0", f"client rc={rc}"))
    return checks


def _numactl_prefix(host) -> str:
    """numactl 绑定前缀 (存在才用; 绑定理由见模块头注)。"""
    res = host.run_script("command -v numactl >/dev/null && echo yes\n",
                          timeout=15)
    return "numactl --membind=0 --cpunodebind=0" if "yes" in res.text else ""


def _print_summary(vals: dict[str, str], tee: Tee, odp_skip: bool) -> None:
    """论文 Fig 12 口径汇总表 (sym/odp 比值随尺寸)。"""
    def ratio(a: str, b: str) -> str:
        try:
            return f"{float(a) / float(b):.2f}" if a and b and float(b) > 0 \
                else "—"
        except ValueError:
            return "—"
    for op, fig in (("read", "12a"), ("write", "12b")):
        tee.emit(f"--- Fig {fig}: {op} 吞吐 (MB/s) vs 消息尺寸 ---")
        header = (f"{'尺寸':<8} {'sym-minor':>10} {'sym-major':>10} "
                  f"{'odp-minor':>10} {'odp-major':>10} "
                  f"{'sym/odp(minor)':>15} {'sym/odp(major)':>15}")
        tee.emit(header)
        for s in SIZES:
            sm = vals.get(f"thr_sym_minor_{op}_s{s}", "")
            smj = vals.get(f"thr_sym_major_{op}_s{s}", "")
            if odp_skip:
                om = omj = "(skip)"
            else:
                om = vals.get(f"thr_odp_minor_{op}_s{s}", "") or "(skip)"
                omj = vals.get(f"thr_odp_major_{op}_s{s}", "") or "(skip)"
            r1 = "—" if om == "(skip)" else ratio(sm, om)
            r2 = "—" if omj == "(skip)" else ratio(smj, omj)
            tee.emit(f"{s:<8} {sm or '—':>10} {smj or '—':>10} {om:>10} "
                     f"{omj:>10} {r1:>15} {r2:>15}")


def run_racebw(ctx: Ctx, *, server_host_name: str, client_host_name: str,
               server_ip: str, dev: str, gid: str, port: int, threads: int,
               out_dir: Path, json_path: str | None = "auto",
               poll_tries: int = 360, poll_interval: float = 10.0) -> int:
    server_host = ctx.host(server_host_name)
    client_host = ctx.host(client_host_name)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    out_log = out_dir / f"racebw_{ts}.log"
    csv_path = out_dir / f"racebw_{ts}.csv"
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else \
            out_dir / f"racebw_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None
    if not ctx.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    srv_log = "/tmp/racebw_server.log"
    cli_log = "/tmp/racebw_client.log"
    exit_file = "/tmp/racebw_exit"

    verdict = "FAIL"
    checks: list[Check] = [Check("dry-run", True, "仅打印远端脚本")]
    client_text = ""
    rc = ""
    try:
        with Tee(None if ctx.dry_run else out_log) as tee:
            tee.emit(f"=== 预检 (server={server_host_name} "
                     f"client={client_host_name} dev={dev} gid={gid}) ===")
            for h in (server_host, client_host):
                res = h.run_script(
                    "[ -r /proc/symrdma ] && echo '  symrdma 模块: ok' || "
                    "{ echo '  symrdma 模块: 缺失'; exit 1; }\n"
                    "command -v gcc >/dev/null && echo '  gcc: ok' || exit 1\n"
                    "command -v ibv_devinfo >/dev/null && echo '  verbs: ok' "
                    "|| exit 1\n"
                    '[ -r "$HOME/pro/symrdma/lib/libsymrdma.a" ] && '
                    'echo "  libsymrdma.a: ok" || '
                    '{ echo "  libsymrdma.a: 缺失 (先跑 build.sh)"; exit 1; }\n',
                    timeout=30)
                tee.emit(res.text.rstrip())
                if res.rc != 0 and not ctx.dry_run:
                    tee.emit(Con.err(f"[{h.host}] 预检失败"))
                    return 1

            tee.emit("=== 部署 (racebw, md5 比对 — 源码+静态库) ===")
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
                server_host.run_script(
                    "pkill -f racebw 2>/dev/null; true\nsleep 1\n"
                    f"rm -f {q(srv_log)}\n"
                    "export SYMRDMA_SIR_DEBUG=1\n"
                    f"nohup /tmp/racebw server -p {q(str(port))} -d {q(dev)} "
                    f"-g {q(gid)} > {q(srv_log)} 2>&1 </dev/null &\n", timeout=30)
                client_host.run_script(detached_run_script(
                    ["/tmp/racebw", "client", "-c", server_ip, "-d", dev,
                     "-g", gid, "-t", str(threads), "-p", str(port)],
                    log=cli_log, exit_file=exit_file, timeout_cmd=3300,
                    prefix="numactl --membind=0 --cpunodebind=0",
                    pre_rm=[cli_log, exit_file]), timeout=30)
                return 0

            # ---- server (numactl 绑定 + SIR 取证日志) ----
            tee.emit(f"=== [1/2] 启动 server@{server_host_name} "
                     f"(port={port} threads={threads}) ===")
            server_host.run_script(
                "pkill -f racebw 2>/dev/null; true\nsleep 1\n"
                f"rm -f {q(srv_log)}\n"
                "export SYMRDMA_SIR_DEBUG=1\n"
                + _numactl_prefix(server_host)
                + f" /tmp/racebw server -p {q(str(port))} -d {q(dev)} "
                f"-g {q(gid)} > {q(srv_log)} 2>&1 </dev/null &\n", timeout=30)
            time.sleep(2)
            if "ready" not in server_host.read_file(srv_log):
                tee.emit(Con.err(f"server 未就绪 "
                                 f"(见 {server_host_name}:{srv_log})"))
                return 1

            # ---- client: setsid 脱离 + exit 文件轮询 (环境杀 SSH 会话规避)
            tee.emit(f"=== [2/2] 运行 client@{client_host_name} (setsid 脱离) "
                     "— 最长 55 分钟, 进度单行汇报 ===")
            client_host.run_script(detached_run_script(
                ["/tmp/racebw", "client", "-c", server_ip, "-d", dev,
                 "-g", gid, "-t", str(threads), "-p", str(port)],
                log=cli_log, exit_file=exit_file, timeout_cmd=3300,
                prefix="numactl --membind=0 --cpunodebind=0",
                pre_rm=[cli_log, exit_file]), timeout=30)

            from . import ui
            with ui.PollProgress("等待 client 完成", total=poll_tries,
                                 interval=poll_interval) as pb:
                rc = ""
                for _ in range(poll_tries):
                    time.sleep(poll_interval)
                    pb.step()
                    val = client_host.read_file(exit_file, timeout=20).strip()
                    if val:
                        rc = val
                        break
                pb.done(f"rc={rc or '超时'}")
            if not rc:
                tee.emit(Con.err(f"client 60 分钟未完成 "
                                 f"(见 {client_host_name}:{cli_log})"))
                return 1
            tee.emit(f"client rc={rc}")
            client_text = client_host.read_file(cli_log)
            if not ctx.dry_run:
                out_log.write_text(client_text, encoding="utf-8")
            for line in client_text.splitlines()[-5:]:
                tee.emit(line)
            server_host.run_script(f"tail -5 {q(srv_log)}\n", timeout=15)

            # ---- 门禁 ----
            tee.emit("\n=== 门禁 ===")
            checks = _gate(client_text, rc)
            for c in checks:
                if c.ok:
                    tee.emit(Con.ok(f"  ✓ {c.name}: {c.detail}"))
                elif c.warn:
                    tee.emit(Con.warn(f"  ⚠ {c.name}: {c.detail}"))
                else:
                    tee.emit(Con.err(f"  ✗ {c.name}: {c.detail}"))
            n_ok = sum(1 for c in checks if c.ok)
            tee.emit(Con.ok(f"✓ 门禁全绿 ({n_ok}/{len(checks)})")
                     if all(c.ok or c.warn for c in checks)
                     else Con.err("✗ 门禁存在失败项"))

            # ---- CSV + 汇总 ----
            vals: dict[str, str] = {}
            csv_rows: list[str] = ["row,value,unit"]
            for line in client_text.splitlines():
                if line.startswith("RESULT "):
                    parts = line.split()
                    if len(parts) >= 4:
                        csv_rows.append(",".join(parts[1:4]))
                        vals.setdefault(parts[1], parts[2])
            if not ctx.dry_run:
                csv_path.write_text("\n".join(csv_rows) + "\n",
                                    encoding="utf-8")
            odp_skip = "ODP MR 不可用" in client_text
            _print_summary(vals, tee, odp_skip)
            tee.emit(f"\n日志: {out_log}\nCSV : {csv_path}")
            verdict = "PASS" if all(c.ok or c.warn for c in checks) else "FAIL"
    finally:
        if not ctx.dry_run:
            server_host.pkill("racebw")
            client_host.pkill("racebw")

    if manifest:
        write_manifest(manifest, suite="racebw",
                       meta={"server": server_host_name,
                             "client": client_host_name, "dev": dev,
                             "gid": gid, "port": port, "threads": threads},
                       cases=[CaseRecord(name="racebw", rc=int(rc or "1"),
                                         checks=checks,
                                         log=str(out_log))],
                       verdict=verdict,
                       failed=[] if verdict == "PASS" else ["racebw"],
                       started=started, duration=time.monotonic() - t0)
    return 0 if verdict == "PASS" else 1
