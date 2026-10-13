"""双机 no-PF 分类带宽矩阵 — run_nopf_bw.sh 的 Python 引擎 (论文 Fig 13(b))。

四分类 × 9 尺寸 (64B..1MB):
  rdma_read / rdma_write : 裸 RDMA (仅 mlockall shim, 无 LD_PRELOAD 引擎)
  sym_read  / sym_write  : SymRDMA 透明 (双侧 NPRDMA_INTERCEPT=all + shim)

生效验证 (按相位, 失败自动重试一次):
  bare 相: 运行中两机 /proc/symrdma 活跃 MR 零增量 + 日志零 nprdma 行
  sym 相 : 运行中两机 MR 增量 + 双端日志含 reg 拦截行 + 退出后回落基线
  (server MR 在 client 连接前注册 — bench 先 reg 后 TCP 会合)
mlockall shim = 论文 no-PF 前提 ("working set naturally resident")。

为何不用系统 perftest: 默认 ibv_wr* 直发绕过 post_send 拦截 + write-only
MR 被 identity_womr 启发式误判 → LOC_PROT (TESTING §5.2, 3 跑 2 挂)。
部署含 EDR 放行预热 (新二进制行为扫描窗口 SIGTERM 洪水, 6 轮至存活)。
"""

from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import config
from .deploy import DeployUnit, ensure_deployed
from .remote import bg_start_script, run_parallel
from .report import CaseRecord, Check, Con, Tee, write_manifest
from .ssh import Ctx

DEFAULT_SIZES = ("64", "256", "1024", "2048", "4096", "16384", "65536",
                 "262144", "1048576")


def _iters_for(size: int) -> int:
    """小消息多迭代降噪, 大消息控时长 (bash iter_for 同款)。"""
    if size <= 4096:
        return 50000
    if size <= 65536:
        return 20000
    return 5000


def _deploy_unit() -> DeployUnit:
    bench = config.BENCH_SRC / "npfbw_bench.c"
    shim = config.BENCH_SRC / "mlockall_shim.c"
    return DeployUnit(
        name="npfbw",
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
    """以赋值语句形态注入远端脚本体 (bash v0.24.5 教训的框架化解法:
    值经 Python 拼进 stdin 脚本文本, 不经 ssh argv — 拆词不可能发生)。"""
    if variant == "sym":
        return ("env NPRDMA_INTERCEPT=all "
                "LD_PRELOAD=/tmp/npfbw_mlock.so:"
                "$HOME/pro/symrdma/nprdma/libnprdma.so NPRDMA_DEBUG=1")
    return "env LD_PRELOAD=/tmp/npfbw_mlock.so"


def preheat(server_host, client_host, *, server_ip: str, dev: str, gid: str,
            attempts: int = 6, log=print) -> bool:
    """EDR 放行预热: 小洪水至存活 (≥4 PREHEAT 行)。"""
    for att in range(1, attempts + 1):
        server_host.run_script(
            "pkill -f npfbw_bench 2>/dev/null; true\nsleep 0.3\n"
            "nohup env LD_PRELOAD=/tmp/npfbw_mlock.so /tmp/npfbw_bench -s "
            "-d mlx5_0 -g 5 >/tmp/npfbw_preheat_srv.log 2>&1 </dev/null &\n"
            "sleep 1\n", timeout=30)
        r = client_host.run_script(
            "timeout 120 env LD_PRELOAD=/tmp/npfbw_mlock.so /tmp/npfbw_bench "
            f"-P -c {server_ip} -d {dev} -g {gid}\n", timeout=150)
        n = sum(1 for line in r.text.splitlines()
                if line.startswith("PREHEAT "))
        if n >= 4:
            log(f"  预热尝试 {att}: 存活 (PREHEAT ×{n}) — EDR 放行")
            server_host.pkill("npfbw_bench")
            return True
        log(f"  预热尝试 {att}: 被终止 (PREHEAT ×{n}) — 等 20s 重试")
        server_host.pkill("npfbw_bench")
        time.sleep(20)
    return False


def _run_phase(ctx: Ctx, *, variant: str, server_host, client_host,
               server_ip: str, dev: str, gid: str, sizes: list[str],
               base_cli: int | None, base_srv: int | None,
               srv_log: str, tee: Tee) -> tuple[CaseRecord, dict[int, dict[str, str]]]:
    """单相位: server bg → client 后台线程 → 运行中 MR 采样 → 汇合校验。"""
    t0 = time.monotonic()
    script = (
        f"timeout 900 {_pre(variant)} /tmp/npfbw_bench "
        f"-c {server_ip} -d {dev} -g {gid}\n"
    )
    collected: list[str] = []

    def _client() -> None:
        client_host.run_script(script, timeout=960,
                               on_line=collected.append)

    with ThreadPoolExecutor(max_workers=1) as ex:
        fut = ex.submit(_client)
        time.sleep(3)
        dur_cli = client_host.mr_count()
        dur_srv = server_host.mr_count()
        fut.result()
    text = "".join(collected)
    aft_cli = client_host.mr_count()
    aft_srv = server_host.mr_count()

    # server 侧拦截行 (日志)
    srv_reg = 0
    if not ctx.dry_run:
        srv_reg = sum(1 for line in server_host.read_file(srv_log).splitlines()
                      if "ibv_reg_mr" in line and "mr_id" in line)
    nreg = sum(1 for line in text.splitlines()
               if "ibv_reg_mr" in line and "mr_id" in line)
    nres = sum(1 for line in text.splitlines() if line.startswith("RESULT "))
    nexp = 2 * len(sizes)

    checks: list[Check] = []
    if variant == "bare":
        checks.append(Check("bare-mr-cli", dur_cli == base_cli,
                            f"运行中 {base_cli}→{dur_cli} — 混入 SymRDMA"))
        checks.append(Check("bare-mr-srv", dur_srv == base_srv,
                            f"运行中 {base_srv}→{dur_srv}"))
        checks.append(Check("bare-no-nprdma",
                            "nprdma" not in text, "日志出现 nprdma 行"))
    else:
        checks.append(Check("sym-mr-cli",
                            dur_cli is not None and base_cli is not None
                            and dur_cli > base_cli, "运行中无 MR 增量"))
        checks.append(Check("sym-mr-srv",
                            dur_srv is not None and base_srv is not None
                            and dur_srv > base_srv, "运行中无 MR 增量"))
        checks.append(Check("sym-reg-cli", nreg >= 1, "无 reg 拦截行"))
        checks.append(Check("sym-reg-srv", srv_reg >= 1, "server 无拦截行"))
    checks.append(Check("mr-restore-cli", aft_cli == base_cli,
                        f"未回落 {base_cli}→{aft_cli}"))
    checks.append(Check("mr-restore-srv", aft_srv == base_srv,
                        f"未回落 {base_srv}→{aft_srv}"))
    checks.append(Check("result-rows", nres == nexp,
                        f"{nres}/{nexp} — 扫描中断"))

    # RESULT 行 → {(size, dir): bw}
    results: dict[int, dict[str, str]] = {}
    for line in text.splitlines():
        if line.startswith("RESULT "):
            parts = line.split()
            if len(parts) >= 5:
                results.setdefault(int(parts[2]), {})[parts[1]] = parts[4]

    ok = all(c.ok for c in checks)
    rec = CaseRecord(name=f"phase-{variant}", display=f"{variant} 相位",
                     rc=0 if ok else 1, duration=time.monotonic() - t0,
                     checks=checks)
    mark = Con.ok("  ✓ 相位通过") if ok else Con.err("  ✗ 相位失败")
    tee.emit(mark)
    if not ok:
        for c in checks:
            if not c.ok:
                tee.emit(Con.err(f"      {c.name}: {c.detail}"))
        tail = [line for line in text.splitlines() if line.strip()][-8:]
        if tail:
            tee.emit(Con.dim("      client 输出尾部:"))
            for line in tail:
                tee.emit(Con.dim(f"        {line}"))
    tee.emit(f"  运行中 MR: client={dur_cli} server={dur_srv} "
             f"(基线 {base_cli}/{base_srv}); RESULT {nres}/{nexp}")
    return rec, results


def run_nopf(ctx: Ctx, *, server_host_name: str, client_host_name: str,
             server_ip: str, dev: str, gid: str, sizes: list[str],
             out_dir: Path, json_path: str | None = "auto",
             tee: Tee | None = None) -> tuple[int, Path | None]:
    """执行双相位基准。返回 (退出码, CSV 路径) — pipeline 复用入口。

    退出码: 0=全绿 1=失败 (两相位各自自动重试一次 — 外部 SIGTERM 嫌疑)。
    """
    if tee is None:
        tee = Tee(None)  # 无外部 tee (pipeline 复用) 时仅控制台
    server_host = ctx.host(server_host_name)
    client_host = ctx.host(client_host_name)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    csv_path = out_dir / f"nopf_bw_{ts}.csv"
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else \
            out_dir / f"nopf_bw_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None
    if not ctx.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    srv_log = "/tmp/npfbw_srv.log"

    sizes_int = [int(s) for s in sizes]
    results_all: dict[str, dict[int, dict[str, str]]] = {}
    records: list[CaseRecord] = []
    try:
        tee.emit(f"=== 预检 (client={client_host_name} "
                 f"server={server_host_name} dev={dev} gid={gid}) ===")
        precheck = (
            "ok=1\n"
            '[ -r /proc/symrdma ] && echo "  symrdma 模块: ok" '
            '|| { echo "  symrdma 模块: 缺失"; ok=0; }\n'
            'command -v gcc >/dev/null 2>&1 && echo "  gcc: ok" '
            '|| { echo "  gcc: 缺失"; ok=0; }\n'
            '[ -f "$HOME/pro/symrdma/nprdma/libnprdma.so" ] && echo "  libnprdma: ok" '
            '|| { echo "  libnprdma: 缺失"; ok=0; }\n'
            '[ "$ok" = 1 ] && exit 0 || exit 1\n'
        )
        for h in (client_host, server_host):
            res = h.run_script(precheck, timeout=30)
            if not ctx.dry_run:
                tee.emit(res.text.rstrip())
                if res.rc != 0:
                    tee.emit(Con.err(f"[{h.host}] 预检失败"))
                    return 1, None

        tee.emit("=== 部署 (mlockall shim + npfbw_bench, md5 比对) ===")
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
                tee.emit("=== EDR 放行预热 (新二进制, 最多 6 轮) ===")
                if not preheat(server_host, client_host, server_ip=server_ip,
                               dev=dev, gid=gid, log=tee.emit):
                    tee.emit(Con.err("预热未放行 — 稍等 2-3 分钟后重跑"))
                    return 1, None

        if ctx.dry_run:
            for variant in ("bare", "sym"):
                server_host.run_script(bg_start_script(
                    ["/tmp/npfbw_bench", "-s", "-d", dev, "-g", gid],
                    log=srv_log, prekill="npfbw_bench",
                    prefix=_pre(variant)), timeout=30)
                client_host.run_script(
                    f"timeout 900 {_pre(variant)} /tmp/npfbw_bench "
                    f"-c {server_ip} -d {dev} -g {gid}\n", timeout=960)
            return 0, None

        base_cli = client_host.mr_count()
        base_srv = server_host.mr_count()
        tee.emit(f"活跃 MR 基线: client={base_cli} server={base_srv}")

        for variant in ("bare", "sym"):
            tee.emit(f"=== 相位: {variant} ===")
            for attempt in (1, 2):
                server_host.run_script(bg_start_script(
                    ["/tmp/npfbw_bench", "-s", "-d", dev, "-g", gid],
                    log=srv_log, prekill="npfbw_bench",
                    sleep_before_start=0.3, prefix=_pre(variant)), timeout=30)
                rec, results = _run_phase(
                    ctx, variant=variant, server_host=server_host,
                    client_host=client_host, server_ip=server_ip, dev=dev,
                    gid=gid, sizes=sizes, base_cli=base_cli,
                    base_srv=base_srv, srv_log=srv_log, tee=tee)
                results_all[variant] = results
                records.append(rec)
                if rec.ok:
                    break
                if attempt == 1:
                    tee.emit(f">>> 相位 {variant} 失败, 自动重试一次 "
                             "(外部 SIGTERM 嫌疑)")
                    time.sleep(2)
                else:
                    tee.emit(f">>> 相位 {variant} 两次尝试均失败")
            tee.emit()

        # ---- CSV + 汇总 ----
        with csv_path.open("w", encoding="utf-8") as f:
            f.write("# SymRDMA 双机 no-page-fault 带宽矩阵 (symtest 引擎; "
                    "论文 §5.2.2 Fig 13(b) 双机版)\n")
            f.write(f"# date={time.strftime('%F %T')} server={server_host_name}"
                    f"({server_ip}) client={client_host_name} dev={dev} "
                    f"gid={gid} tool=npfbw_bench\n")
            f.write("size_bytes,rdma_read,rdma_write,sym_read,sym_write\n")
            for s in sizes_int:
                bare = results_all.get("bare", {}).get(s, {})
                sym = results_all.get("sym", {}).get(s, {})
                f.write(f"{s},{bare.get('read', '')},{bare.get('write', '')},"
                        f"{sym.get('read', '')},{sym.get('write', '')}\n")

        tee.emit("=== 汇总 ===")
        tee.emit("| size(B) | rdma_read | rdma_write | sym_read | sym_write |"
                 " read Δ% | write Δ% |")
        tee.emit("|---------|-----------|------------|----------|"
                 "----------|---------|----------|")
        for s in sizes_int:
            bare = results_all.get("bare", {}).get(s, {})
            sym = results_all.get("sym", {}).get(s, {})
            dr = _pct(sym.get("read"), bare.get("read"))
            dw = _pct(sym.get("write"), bare.get("write"))
            tee.emit(f"| {s} | {bare.get('read') or '-'} | "
                     f"{bare.get('write') or '-'} | {sym.get('read') or '-'} | "
                     f"{sym.get('write') or '-'} | {dr} | {dw} |")
        verdict = "PASS" if all(r.ok for r in records) else "FAIL"
        tee.emit(f"\nΔ% = (SymRDMA−裸)/裸×100; 结果 CSV: {csv_path}")
        total = time.monotonic() - t0
        if manifest:
            write_manifest(manifest, suite="nopf",
                           meta={"server": server_host_name,
                                 "client": client_host_name,
                                 "server_ip": server_ip, "dev": dev,
                                 "gid": gid, "sizes": sizes},
                           cases=records, verdict=verdict,
                           failed=[] if verdict == "PASS" else
                           [r.name for r in records if not r.ok],
                           started=started, duration=total)
        return (0 if verdict == "PASS" else 1), csv_path
    finally:
        if not ctx.dry_run:
            for h in (server_host, client_host):
                h.pkill("npfbw_bench")


def _pct(new: str | None, base: str | None) -> str:
    """(new-base)/base×100 一位小数 (bash pct_delta 等价; 缺值 → —)。"""
    try:
        if new and base and float(base) != 0:
            return f"{(float(new) - float(base)) / float(base) * 100:+.1f}"
    except ValueError:
        pass
    return "—"
