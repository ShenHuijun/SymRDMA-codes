"""跨机双进程套件 — run_sir_cross.sh 的 Python 引擎（v0.39.0 自 bash 移植）。

编排 server@$SERVER_HOST (role a, listen) ← client@$CLIENT_HOST (role b)：

  L7  test_sir             — SIR 手写协议 (控制 QP/反向 RDMA/内联/KEYMAP, §3.2/4.1)
  L10 test_atomic          — 双端 RPC 原子 (远端 CPU 执行, §3.4)
  L12 test_auto_sir        — 库内建 SIR 自动双向修复 (透明 API)
  L13 test_transparent_read — libnprdma 透明引擎 (纯 verbs, 两端 LD_PRELOAD)

端口分配: PORT = SIR 会合 (库层, 仅 L12/L13), PORT+1 = 测试参数/事件协调
(netcoord.h, SYMRDMA_TEST_TCP, 全部 Level)。L7/L10 为手写控制协议, 不用
库层 SIR。跨机 QP 要点 (v0.32.0/v0.33.0): dgid 取对端 GID, path_mtu =
min(active_mtu, 4096), sgid_index = GID (按测试床拓扑固定, 见 testbed.env)。

行为契约与 bash 版一致：server FAIL 行 + client 退出码双判定；server 启动
失败即中止套件；退出码 0=全绿 / 1=有失败。
输出: results/sir_cross_<ts>.log (+ manifest.json)。

对 bash 版的一处修正：头注承诺的 SIR_DEBUG=1 (库层调试日志, 仅 L12/L13)
此前实际未接线 —— 本版接通为 SYMRDMA_SIR_DEBUG=1 (双端)。
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from pathlib import Path

from . import config
from .remote import (
    bg_start_script,
    env_prefix,
    run_parallel,
    wait_pattern_script,
    wait_ready_script,
)
from .report import CaseRecord, Check, Con, Tee, write_manifest
from .ssh import Ctx, q, qh


@dataclass(frozen=True)
class SirCase:
    lv: str
    prog: str
    done_re: str          # server 收尾标志（等待 + 判定）
    gate: str             # "generic" | "summary"


SIR_CASES: dict[str, SirCase] = {
    "7":  SirCase("7", "test_sir", "清理退出", "generic"),
    "10": SirCase("10", "test_atomic", "QUIT", "generic"),
    # server 完成判据: 12/13 有汇总行; 7/10 静默协议循环看收尾标志
    "12": SirCase("12", "test_auto_sir", r"server: [0-9]+ 通过", "summary"),
    "13": SirCase("13", "test_transparent_read", r"server: [0-9]+ 通过", "summary"),
}

SIR_LEVELS = ("7", "10", "12", "13")


class UsageError(ValueError):
    pass


class SuiteAbort(RuntimeError):
    """环境级失败（原 bash die）— 中止整个套件。"""


def case_envs(lv: str, *, port: int, gid: str, server_ip: str,
              sir_debug: bool) -> tuple[dict[str, str], dict[str, str]]:
    """构造 (server_env, client_env)。

    LD_PRELOAD 形态（同原单机接线）: L7 client flag 模式 / L10 client 全
    拦截 / L13 两端全拦截; server 侧一律不挂 — ioctl 自含 (L13 例外)。
    """
    nc = port + 1
    server: dict[str, str] = {
        "SYMRDMA_TEST_TCP": f"listen:{nc}",
        "SYMRDMA_TEST_GID": str(gid),
    }
    client: dict[str, str] = {
        "SYMRDMA_TEST_TCP": f"{server_ip}:{nc}",
        "SYMRDMA_TEST_GID": str(gid),
    }
    if lv in ("12", "13"):
        # L12/L13: 库层 SIR 会合 (SYMRDMA_SIR_TCP) — L7/L10 手写控制协议不用
        peer = f"l{lv}x"
        server.update({
            "SYMRDMA_PEER": peer,
            "SYMRDMA_SIR_TCP": f"listen:{port}",
            "SYMRDMA_SIR_GID": str(gid),
        })
        client.update({
            "SYMRDMA_PEER": peer,
            "SYMRDMA_SIR_TCP": f"{server_ip}:{port}",
            "SYMRDMA_SIR_GID": str(gid),
        })
        if sir_debug:
            server["SYMRDMA_SIR_DEBUG"] = "1"
            client["SYMRDMA_SIR_DEBUG"] = "1"
    if lv == "7":
        client["LD_PRELOAD"] = config.LIBNPRDMA
    elif lv == "10":
        client["NPRDMA_INTERCEPT"] = "all"
        client["LD_PRELOAD"] = config.LIBNPRDMA
    elif lv == "13":
        pre = {"NPRDMA_INTERCEPT": "all", "LD_PRELOAD": config.LIBNPRDMA}
        server.update(pre)
        client.update(pre)
    return server, client


def _server_script(case: SirCase, env: dict[str, str], lv: str) -> str:
    """server 启动 + 就绪等待（一次 ssh 往返，语义同 bash 版 heredoc）。"""
    log = f"/tmp/sir_cross_{lv}.log"
    start = bg_start_script(
        [f"$HOME/pro/symrdma/test/{case.prog}", "server"],
        env=env, log=log, prekill=case.prog, cwd=config.TEST_DIR)
    # 就绪: 首条输出 (Level|===) 出现, 或进程仍活 (最多 30s)
    return start + wait_ready_script(log, "Level|===", case.prog, tries=30)


def _client_script(case: SirCase, env: dict[str, str], client_timeout: int) -> str:
    return (f"cd {qh(config.TEST_DIR)}\n"
            f"timeout {int(client_timeout)} stdbuf -oL {env_prefix(env)} "
            f"{qh(f'$HOME/pro/symrdma/test/{case.prog}')} client\n")


def _gate_server_log(case: SirCase, text: str) -> list[Check]:
    """server 侧日志判定（远端日志回捞判定: 零 FAIL 行 + 完成标志）。"""
    checks: list[Check] = []
    if case.gate == "summary":
        n_fail = sum(1 for line in text.splitlines()
                     if line.startswith("  FAIL:"))
        has_zero = any(" 0 失败" in line for line in text.splitlines())
        checks.append(Check("server-FAIL", n_fail == 0, f"FAIL 行 ×{n_fail}"))
        checks.append(Check("server-summary", has_zero,
                            "server 汇总行含 '0 失败'" if has_zero
                            else "server 汇总行缺失/非零失败"))
    else:
        n = sum(1 for line in text.splitlines()
                if re.search(r"FAIL|失败|超时", line))
        checks.append(Check("server-log", n == 0, f"可疑行 ×{n}"))
    return checks


def run_case(ctx: Ctx, *, case: SirCase, server_host, client_host,
             server_ip: str, port: int, gid: str, sir_debug: bool,
             client_timeout: int, tee: Tee) -> CaseRecord:
    lv, prog = case.lv, case.prog
    sir_port, nc_port = port, port + 1
    server_env, client_env = case_envs(lv, port=port, gid=gid,
                                       server_ip=server_ip, sir_debug=sir_debug)
    log_path = f"/tmp/sir_cross_{lv}.log"
    name = f"L{lv}"
    t0 = time.monotonic()

    tee.emit(f"=== L{lv} 跨机: client@{client_host.host} → "
             f"server@{server_host.host} (SIR:{sir_port} coord:{nc_port} "
             f"GID:{gid}) ===")

    # 预检（双机并行；dry-run 下 run_parallel 退化为串行打印）
    def _pre(host):
        ok = host.test_x(f"$HOME/pro/symrdma/test/{prog}")
        if not ok and not ctx.dry_run:
            raise SuiteAbort(f"{host.host}: $HOME/pro/symrdma/test/{prog} 不存在 — "
                             "先跑 bash scripts/build.sh")
        return ok
    run_parallel({server_host.host: lambda: _pre(server_host),
                  client_host.host: lambda: _pre(client_host)})

    if ctx.dry_run:
        server_host.run_script(_server_script(case, server_env, lv))
        client_host.run_script(_client_script(case, client_env, client_timeout))
        server_host.run_script(wait_pattern_script(log_path, case.done_re))
        server_host.run_script(f"cat {q(log_path)} 2>/dev/null\ntrue\n")
        server_host.pkill(prog)
        return CaseRecord(name=name, display=f"跨机 {prog}",
                          checks=[Check("dry-run", True, "仅打印远端脚本")])

    # server 后台启动 + 就绪等待（stdbuf -oL: 日志文件全缓冲问题, §5 教训）
    res = server_host.run_script(_server_script(case, server_env, lv),
                                 timeout=45)
    if res.rc != 0 or res.timed_out:
        tee.emit(Con.err(f"✗ L{lv} server 未启动 "
                         f"(见 {server_host.host}:{log_path})"))
        raise SuiteAbort(f"server 未启动 (rc={res.rc})")

    # client 前台（流式 → 控制台 + OUT；本地外层超时 = client_timeout + 60）
    collected: list[str] = []

    def _on_client_line(line: str) -> None:
        collected.append(line)
        tee.emit(line)

    res = client_host.run_script(
        _client_script(case, client_env, client_timeout),
        timeout=client_timeout + 60, on_line=_on_client_line)

    # 等 server 收尾 (DONE 事件处理 + 汇总打印, 最多 15s) + 回捞日志
    server_host.run_script(wait_pattern_script(log_path, case.done_re),
                           timeout=30)
    slog = server_host.read_file(log_path)
    for line in slog.splitlines():
        tee.emit(f"  [server] {line}")
    server_host.pkill(prog)

    checks = [Check("client-exit", res.rc == 0, f"client rc={res.rc}")]
    checks.extend(_gate_server_log(case, slog))
    rec = CaseRecord(name=name, display=f"跨机 {prog}", rc=res.rc,
                     duration=time.monotonic() - t0, checks=checks)
    if rec.ok:
        tee.emit(Con.ok(f"✓ L{lv} 跨机通过"))
    else:
        detail = "; ".join(f"{c.name}[{c.detail}]" for c in rec.failed_checks)
        tee.emit(Con.err(f"✗ L{lv} 跨机失败 ({detail})"))
    return rec


def run_sir(ctx: Ctx, *, targets: list[str], server_host_name: str,
            client_host_name: str, server_ip: str, port: int, gid: str,
            sir_debug: bool, client_timeout: int, out_dir: Path,
            json_path: str | None = "auto") -> int:
    if not targets or targets == ["all"]:
        lvs = list(SIR_LEVELS)
    elif "all" in targets:
        if len(targets) != 1:
            raise UsageError("'all' 不能与其他目标混用")
        lvs = list(SIR_LEVELS)
    else:
        lvs = []
        for t in targets:
            if t not in SIR_CASES:
                raise UsageError("用法: symtest sir [7|10|12|13|all]")
            if t not in lvs:
                lvs.append(t)

    server_host = ctx.host(server_host_name)
    client_host = ctx.host(client_host_name)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    out_log = out_dir / f"sir_cross_{ts}.log"
    if not ctx.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else \
            out_dir / f"sir_cross_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None

    records: list[CaseRecord] = []
    try:
        with Tee(None if ctx.dry_run else out_log) as tee:
            for lv in lvs:
                case = SIR_CASES[lv]
                rec = run_case(ctx, case=case, server_host=server_host,
                               client_host=client_host, server_ip=server_ip,
                               port=port, gid=gid, sir_debug=sir_debug,
                               client_timeout=client_timeout, tee=tee)
                records.append(rec)
                tee.emit()
            total = time.monotonic() - t0
            nfail = sum(1 for r in records if not r.ok)
            if nfail == 0:
                tee.emit(Con.ok("✓ 跨机会合验证全部通过")
                         + Con.dim(f" · 总耗时 {total:.1f}s · 日志: {out_log}"))
            else:
                failed_str = " ".join(r.name for r in records if not r.ok)
                tee.emit(Con.err(f"✗ 跨机会合验证存在失败: {failed_str}")
                         + Con.dim(f" · 日志: {out_log}"))
    finally:
        # 孤儿清扫（bash cleanup trap 等价）: 双机清所有双进程测试程序
        if not ctx.dry_run:
            for h in (server_host, client_host):
                for prog in ("test_auto_sir", "test_transparent_read",
                             "test_sir", "test_atomic"):
                    h.pkill(prog)

    if manifest:
        failed = [r.name for r in records if not r.ok]
        write_manifest(manifest, suite="sir",
                       meta={"server": server_host_name, "client":
                             client_host_name, "server_ip": server_ip,
                             "port": port, "gid": gid, "sir_debug": sir_debug},
                       cases=records,
                       verdict="PASS" if not failed else "FAIL",
                       failed=failed, started=started,
                       duration=time.monotonic() - t0)
    return 0 if all(r.ok for r in records) else 1
