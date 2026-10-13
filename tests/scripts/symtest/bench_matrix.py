"""原版 vs SymRDMA 性能矩阵 — run_matrix.sh 的 Python 引擎 (论文 §5.2.2)。

A = 原版路径 (无 preload, 普通 MR = GUP pin + dma_map)
C = SymRDMA   (NPRDMA_INTERCEPT=all + LD_PRELOAD → 带 IDENTITY 位 MR)

已知口径 (TESTING §5.2): 系统 perftest 6.06 默认走 ibv_wr* 直发 API 绕过
引擎 post_send 拦截 — 本矩阵测的是 **MR 注册路径** (identity MTT + IOMMU
翻译 vs pin) 的稳态开销, 注册拦截不受影响; 含页故障的数据面验证矩阵见
run_nopf_bw.sh。另: 6.06 的 GID 走 -x (4.5 的 -g 在 6.06 触发 multicast
语义, write/read 直接报错)。

perftest lat 类禁用 -D 时长模式 (恒定伪读数 ~1496µs)。
"""

from __future__ import annotations

import time
from pathlib import Path

from . import config
from .report import CaseRecord, Check, Con, Tee, write_manifest
from .ssh import Ctx, q

TOOLS = ("ib_write_bw", "ib_read_bw", "ib_write_lat", "ib_read_lat")
ITER = 1000
PFTEST = "ib_write_bw"   # 预检用 (PATH 上的系统 perftest)


def _pre(cfg: str) -> str:
    """相位前缀: A = 裸; C = env NPRDMA_INTERCEPT=all LD_PRELOAD=libnprdma."""
    if cfg == "C":
        return (f"env NPRDMA_INTERCEPT=all "
                f"LD_PRELOAD={config.LIBNPRDMA}")
    return ""


def run_pair(ctx: Ctx, *, server_host, client_host, server_ip: str,
             dev: str, gid: str, tool: str, size: str, cfg: str,
             tee: Tee) -> str:
    """单对运行: server 后台 → client 前台 → 提取末个数据行。"""
    pre = _pre(cfg)
    srv_log = f"/tmp/matrix_srv_{tool}.log"
    server_host.run_script(
        f'pkill -f "[i]b_(read|write)_(bw|lat)" 2>/dev/null; true\n'
        f"sleep 0.3\n"
        f"rm -f {q(srv_log)}\n"
        f'nohup {pre} {tool} -d {q(dev)} -x {q(gid)} -s {q(size)} '
        f'-n {ITER} > {q(srv_log)} 2>&1 </dev/null &\n', timeout=30)
    # client 数据行提取: bw 行 = 'size iters peak avg mrate' → $4;
    # lat 行 = 'size iters min med... t_typical' → $5 (bash awk 同列)
    script = (
        f"timeout 60 {pre} {tool} -d {q(dev)} -x {q(gid)} -s {q(size)} "
        f"-n {ITER} {q(server_ip)} 2>/dev/null\n"
    )
    res = client_host.run_script(script, timeout=90)
    server_host.pkill("[i]b_(read|write)_(bw|lat)")
    data_lines = [line for line in (res.text or "").splitlines()
                  if line.lstrip()[:1].isdigit()]
    if not data_lines:
        return ""
    fields = data_lines[-1].split()
    return fields[4] if "lat" in tool else fields[3]


def run_matrix(ctx: Ctx, *, server_host_name: str, client_host_name: str,
               server_ip: str, dev: str, gid: str, sizes: list[str],
               out_dir: Path, json_path: str | None = "auto") -> int:
    server_host = ctx.host(server_host_name)
    client_host = ctx.host(client_host_name)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else \
            out_dir / f"matrix_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None

    records: list[CaseRecord] = []
    checks: list[Check] = []
    rows: list[list[str]] = []
    with Tee(None if ctx.dry_run else out_dir / f"matrix_{ts}.log") as tee:
        tee.emit(f"=== SymRDMA 性能矩阵 (原版 A vs SymRDMA C) — "
                 f"client={client_host_name} → server={server_host_name}"
                 f"({server_ip}) dev={dev} gid={gid} ===")

        # ---- 预检: perftest 存在 + 模块 + identity_mtt 选择性模式 ----
        if not ctx.dry_run:
            r = client_host.run_script(
                f"command -v {PFTEST}\n"
                f"[ -r /proc/symrdma ] && echo mod-ok\n"
                f"cat /sys/module/mlx5_ib/parameters/identity_mtt 2>/dev/null\n",
                timeout=30)
            lines = r.text.splitlines()
            if not lines or PFTEST not in lines[0]:
                tee.emit(Con.err(f"✗ {client_host_name} 无 perftest ({PFTEST})"))
                return 1
            if "mod-ok" not in r.text:
                tee.emit(Con.warn("! 注意: /proc/symrdma 不可读 (模块未加载?)"))
            idmtt = lines[-1].strip() if lines else "?"
            if idmtt != "N":
                tee.emit(Con.warn(f"! 注意: identity_mtt={idmtt} (非选择性模式)"))
            if not server_host.test_x("/usr/bin/env"):
                pass  # 占位: server 可达性由后续 run_pair 暴露
        else:
            client_host.run_script(f"command -v {PFTEST}\n", timeout=30)
            server_host.run_script(f"command -v {PFTEST}\n", timeout=30)

        tee.emit()
        tee.emit("| 工具 | 大小(B) | 原版 A | SymRDMA C | Δ% |")
        tee.emit("|------|--------|--------|-----------|----|")
        for tool in TOOLS:
            for size in sizes:
                if ctx.dry_run:
                    server_host.run_script(
                        f"nohup {tool} -d {q(dev)} -x {q(gid)} -s {q(size)} "
                        f"-n {ITER} >/dev/null 2>&1 </dev/null &\n", timeout=30)
                    client_host.run_script(
                        f"timeout 60 {tool} -d {q(dev)} -x {q(gid)} "
                        f"-s {q(size)} -n {ITER} {q(server_ip)}\n", timeout=90)
                    continue
                a = run_pair(ctx, server_host=server_host,
                             client_host=client_host, server_ip=server_ip,
                             dev=dev, gid=gid, tool=tool, size=size,
                             cfg="A", tee=tee)
                c = run_pair(ctx, server_host=server_host,
                             client_host=client_host, server_ip=server_ip,
                             dev=dev, gid=gid, tool=tool, size=size,
                             cfg="C", tee=tee)
                try:
                    delta = f"{(float(c) - float(a)) / float(a) * 100:.1f}" \
                        if a and c and float(a) != 0 else "—"
                except (ValueError, ZeroDivisionError):
                    delta = "—"
                tee.emit(f"| {tool} | {size} | {a or '—'} | {c or '—'} | "
                         f"{delta}% |")
                rows.append([tool, size, a, c, delta])
                checks.append(Check(
                    f"{tool}@{size}", bool(a) and bool(c),
                    "缺数据行" if not (a and c) else f"A={a} C={c}"))
        tee.emit()
        tee.emit("完成。Δ% = (C−A)/A×100: 吞吐为正表 SymRDMA 更快, "
                 "延迟为正表更慢。")

    total = time.monotonic() - t0
    ok = all(c.ok for c in checks)
    records.append(CaseRecord(name="matrix", display="原版 vs SymRDMA 矩阵",
                              rc=0 if ok else 1, duration=total,
                              checks=checks))
    if manifest and records:
        write_manifest(manifest, suite="matrix",
                       meta={"server": server_host_name,
                             "client": client_host_name, "dev": dev,
                             "gid": gid, "sizes": sizes, "tools": TOOLS},
                       cases=records, verdict="PASS" if ok else "FAIL",
                       failed=[] if ok else ["matrix"],
                       started=started, duration=total)
    return 0 if ok else 1
