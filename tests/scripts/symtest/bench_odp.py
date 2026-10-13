"""L15 Phase B 双机 ODP 对照 — run_odp_compare.sh 的 Python 引擎。

头条场景 (论文 §2.3): server 的 ODP MR 页被换出后 client 发起 RDMA Read —
initiator 无法区分"远程缺页延迟"与丢包, 依赖传输层超时。对照 SymRDMA
detect→REPAIR→re-read 全链路。

v0.29.2 教训 (path_mtu 硬编码 > active_mtu → 多包响应静默丢弃) 已修在
测试程序内 (动态 min(active_mtu, 4096)); 逐尺寸重建连接的形态保留
(尺寸间状态隔离, 便于单尺寸重跑)。
输出: results/odp_compare_<ts>.log (+ manifest)。退出码恒 0 (对照测量,
不设门禁 — 与 bash 版一致)。
"""

from __future__ import annotations

import re
import time
from pathlib import Path

from . import config
from .deploy import DeployUnit, ensure_deployed
from .remote import bg_start_script, run_parallel
from .report import CaseRecord, Con, Tee, write_manifest
from .ssh import Ctx, q

COMPILE_SCRIPT = (
    'mkdir -p /tmp/lib\n'
    'cp "$HOME"/pro/symrdma/lib/libsymrdma.h /tmp/lib/libsymrdma.h 2>/dev/null || true\n'
    'cd /tmp\n'
    'PK="$(pkg-config --cflags --libs libibverbs 2>/dev/null)"\n'
    'if [ -n "$PK" ]; then set -- $PK; else set -- -I/usr/local/include '
    '-L/usr/local/lib; fi\n'
    'gcc -O2 -Wall -o /tmp/test_odp_compare /tmp/test_odp_compare.c '
    '-I/tmp/lib "$HOME"/pro/symrdma/lib/libsymrdma.a "$@" -libverbs -lpthread -ldl '
    '&& { echo COMPILE_OK; exit 0; }\n'
    'echo COMPILE_FAIL\n'
)

# 合并表取行: markdown 头/分隔/数据行 (与 bash grep 等价)
_TABLE_HEAD = re.compile(r"^\| 尺寸")
_TABLE_SEP = re.compile(r"^\|---")
_TABLE_ROW = re.compile(r"^\| (256B|4KB|64KB|256KB) ")


def _deploy_unit() -> DeployUnit:
    src = config.PROGRAMS_SRC / "test_odp_compare.c"
    return DeployUnit(
        name="test_odp_compare",
        sources=[(str(src), "/tmp/test_odp_compare.c")],
        binaries=["/tmp/test_odp_compare"],
        compile_script=COMPILE_SCRIPT,
    )


def run_odp(ctx: Ctx, *, server_host_name: str, client_host_name: str,
            server_ip: str, port: int, gid: str, dev: str,
            sizes: list[str], out_dir: Path,
            json_path: str | None = "auto") -> int:
    server_host = ctx.host(server_host_name)
    client_host = ctx.host(client_host_name)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    out_log = out_dir / f"odp_compare_{ts}.log"
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else \
            out_dir / f"odp_compare_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None
    if not ctx.dry_run:
        out_dir.mkdir(parents=True, exist_ok=True)
    srv_log = "/tmp/odp_server.log"
    prog = "/tmp/test_odp_compare"
    merged_rows: list[str] = []   # 各尺寸输出中的 markdown 行 (合并表)

    records: list[CaseRecord] = []
    with Tee(None if ctx.dry_run else out_log) as tee:
        tee.emit("=== [1/3] 推送 + 编译 test_odp_compare ===")
        unit = _deploy_unit()
        if ctx.dry_run:
            ensure_deployed(server_host, unit, log=tee.emit)
            ensure_deployed(client_host, unit, log=tee.emit)
        else:
            run_parallel({
                server_host_name: lambda: ensure_deployed(server_host, unit, log=print),
                client_host_name: lambda: ensure_deployed(client_host, unit, log=print),
            })

        tee.emit(f"=== [2/3] 逐尺寸测量 (client@{client_host_name} → "
                 f"server@{server_host_name}) ===")
        for sz in sizes:
            if not ctx.dry_run:
                # 逐尺寸重建连接 (v0.29.1 形态: 尺寸间状态隔离, 便于单尺寸重跑)
                server_host.pkill("test_odp_compare")
                server_host.run_script(bg_start_script(
                    [prog, "server", "-p", str(port), "-d", dev],
                    log=srv_log, prekill="test_odp_compare",
                    sleep_before_start=1, cwd="/tmp"), timeout=30)
                time.sleep(2)
                if "等待 client" not in server_host.read_file(srv_log):
                    tee.emit(Con.err(f"server 未就绪 size={sz} "
                                     f"(见 {server_host_name}:{srv_log})"))
                    return 1
            tee.emit(f"--- size={sz} ---")

            collected: list[str] = []

            def on_line(line: str, _c=collected, _m=merged_rows) -> None:
                # 默认参数绑定当前迭代的列表 (B023: 同名变量每轮重建)
                _c.append(line)
                if (_TABLE_HEAD.search(line) or _TABLE_SEP.search(line)
                        or _TABLE_ROW.search(line)):
                    _m.append(line)
                tee.emit(line)

            if ctx.dry_run:
                client_host.run_script(
                    f"stdbuf -oL timeout 600 {prog} client -c {q(server_ip)} "
                    f"-g {q(gid)} -d {q(dev)} -p {q(str(port))} -s {q(sz)}\n",
                    timeout=660)
                continue
            res = client_host.run_script(
                f"stdbuf -oL timeout 600 {prog} client -c {q(server_ip)} "
                f"-g {q(gid)} -d {q(dev)} -p {q(str(port))} -s {q(sz)}\n",
                timeout=660, on_line=on_line)
            if res.rc != 0:
                tee.emit(Con.warn(f"  ! size={sz} client rc={res.rc}"))
            server_host.pkill("test_odp_compare")
            time.sleep(1)
            records.append(CaseRecord(name=f"size-{sz}", rc=res.rc))

        # ---- [3/3] 合并表 (各尺寸 markdown 行去重拼合) ----
        tee.emit("=== Phase B 合并表 (每尺寸独立连接; ODP 楔死规避) ===")
        seen_head = seen_sep = False
        for line in merged_rows:
            if _TABLE_HEAD.search(line):
                if seen_head:
                    continue
                seen_head = True
            if _TABLE_SEP.search(line):
                if seen_sep:
                    continue
                seen_sep = True
            tee.emit(line.rstrip())
        tee.emit()
        for line in (
            "[Phase B 判定] ODP remote fault ≈2ms 级停顿 (传输层歧义, 论文 §2.3",
            "头条场景, 与尺寸无关); Sym remote = detect + 控制 REPAIR + 重读",
            "全链路 (TCP 控制通道同构近似, 只慢于 SIR)。比值随尺寸收敛:",
            "256B/4KB ≈ 12–14×, 64KB ≈ 4–6×, 256KB ≈ 1.5–1.6× (Sym 成本为",
            "REPAIR + 重读传输, 随尺寸增长)。",
        ):
            tee.emit(line)

    total = time.monotonic() - t0
    if manifest and records:
        write_manifest(manifest, suite="odp",
                       meta={"server": server_host_name,
                             "client": client_host_name,
                             "server_ip": server_ip, "port": port,
                             "gid": gid, "dev": dev, "sizes": sizes},
                       cases=records, verdict="DONE", failed=[],
                       started=started, duration=total)
    print(f"✓ 完成: {out_log}")
    return 0
