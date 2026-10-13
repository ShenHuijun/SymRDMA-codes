"""Phase 2 (组粒度 IOMMU 映射) 门禁编排 — run_group_gates.sh 的 Python 引擎。

docs/PLAN_IOMMU_HUGEPAGE.md 定义的 5 次模块加载形态门禁 (重载需 sudo,
经 ssh -tt 交互执行 scripts/remote/symrdma_reload.sh — 首次输密码, 之后
sudo 15min 凭据缓存免密; 两次重载间的测试全部非特权):

  Load 1  默认参数            → test.sh all + npmapbench + sir all + racebw
  Load 2  demote_fail_grp=2  → test.sh level19 (fail-closed 注入形态)
  Load 3  iommu_huge=0       → test.sh all (组机制 kill-switch 对照)
  Load 4  repair_sg=0        → test.sh all (sg 批关闭 → 逐页交错对照)
  Load 5  (收尾) 默认参数重载 — 机器留在标准形态

每次加载后抓 dmesg 增量, 汇总报新 WARN/OOPS/BUG 行。
双机 .ko srcversion 一致性预检 (v0.38.1): 防 server 侧旧模块装载
(v0.38.0 L1d 停机复发根因)。

⚠ 运行前提: 当前终端可交互输 sudo 密码 (ssh -tt); CI/无 TTY 场景不可用。
"""

from __future__ import annotations

import re
import subprocess
import sys
import time
from pathlib import Path

from . import config
from .report import CaseRecord, Check, Con, Tee, write_manifest
from .ssh import Ctx, q


def _load_ver(text: str) -> str | None:
    """从 grep 输出提取 v0.x.x 版本号。"""
    m = re.search(r"v0\.\d+\.\d+", text)
    return m.group(0) if m else None

VERSION_GATE_DEFAULT = "v0.38.0"   # /proc 统计段组粒度版本门禁 (env 可覆盖)


def _ko_srcversion(host) -> str:
    res = host.run_script(
        "modinfo -F srcversion \"$HOME\"/pro/symrdma/kernel/symrdma.ko 2>/dev/null\n",
        timeout=20)
    return res.text.strip()


def _reload(ctx: Ctx, host, bdf: str, extra: str, tee: Tee) -> bool:
    """交互式模块重载 (ssh -tt + 本地 stdin 继承 — sudo 密码从终端输入)。"""
    tee.emit(f"--- 重载模块 @{host.host} (mode=1 pci_bdf={bdf} {extra}) ---")
    if ctx.dry_run:
        host.run_tty(f"bash ~/pro/symrdma/scripts/symrdma_reload.sh mode=1 "
                     f"pci_bdf={bdf} {extra}".strip())
        return True
    argv = ["ssh", "-tt", "-o", f"ConnectTimeout={ctx.ssh_timeout}",
            host.host,
            f"bash ~/pro/symrdma/scripts/symrdma_reload.sh mode=1 pci_bdf={bdf}"
            + (f" {extra}" if extra else "")]
    proc = subprocess.run(argv, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, text=True,
                          encoding="utf-8", errors="replace")
    for line in proc.stdout.splitlines():
        if not any(x in line for x in ("post-quantum", "store now", "upgraded")):
            tee.emit(line)
    if proc.returncode != 0:
        tee.emit(Con.err(f"    重载失败 (rc={proc.returncode})"))
        return False
    return True


def _dmesg_count(host) -> int | None:
    res = host.run_script("dmesg 2>/dev/null | wc -l\n", timeout=20)
    s = res.text.strip()
    return int(s) if s.isdigit() else None


def _dmesg_check_dry(stage: str, record) -> None:
    record(True, f"dmesg 清洁 ({stage}) (dry-run 跳过)")


def _dmesg_check(ctx: Ctx, host, base: int | None, stage: str, ts: str,
                 out_dir: Path, tee: Tee, record) -> None:
    if base is None:
        record(False, f"dmesg 基线读取失败 ({stage})")
        return
    res = host.run_script(
        f"dmesg 2>/dev/null | tail -n +{base + 1} | "
        "grep -cE 'WARNING|BUG|Oops|general protection|UBSAN|call trace'\n",
        timeout=30)
    s = res.text.strip()
    n = int(s) if s.isdigit() else None
    if n is None:
        record(False, f"dmesg 读取失败 ({stage})")
    elif n == 0:
        record(True, f"dmesg 清洁 ({stage})")
    else:
        record(False, f"dmesg 新告警 ×{n} ({stage}) — 见 "
                      f"results/dmesg_{ts}_{stage}.txt")
        if not ctx.dry_run:
            out_dir.mkdir(parents=True, exist_ok=True)
            host.run_script(
                f"dmesg 2>/dev/null | tail -n +{base + 1} > "
                f"{q(str(out_dir / f'dmesg_{ts}_{stage}.txt'))}\n", timeout=60)


def _run_local(ctx: Ctx, desc: str, cmd: list[str], tee: Tee,
               log_path: Path, record) -> None:
    """本地子脚本运行 (日志全量落盘, 屏显摘要) — bash run_local_script 等价。"""
    tee.emit(f"--- {desc} ---")
    if ctx.dry_run:
        record(True, f"{desc} (dry-run 跳过)")
        return
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with log_path.open("a", encoding="utf-8", errors="replace") as f:
        rc = subprocess.run(cmd, stdout=f, stderr=subprocess.STDOUT).returncode
    if rc == 0:
        record(True, desc)
    else:
        record(False, f"{desc} (rc={rc})")


def run_group_gates(ctx: Ctx, *, client_host_name: str, server_host_name: str,
                    client_bdf: str, server_bdf: str, out_dir: Path,
                    version_gate: str = VERSION_GATE_DEFAULT,
                    json_path: str | None = "auto") -> int:
    client = ctx.host(client_host_name)
    server = ctx.host(server_host_name)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    out_dir.mkdir(parents=True, exist_ok=True)
    out_log = out_dir / f"group_gates_{ts}.log"
    manifest: Path | None
    if json_path in ("auto", None):
        manifest = None if ctx.dry_run else \
            out_dir / f"group_gates_{ts}_manifest.json"
    else:
        manifest = Path(json_path) if json_path != "none" else None

    fail = 0
    fail_items: list[str] = []
    records: list[CaseRecord] = []
    tee = Tee(None if ctx.dry_run else out_log)

    def record(ok: bool, desc: str) -> None:
        nonlocal fail
        tee.emit(f"[{'ok' if ok else 'FAIL'}] {desc}")
        if ok:
            records.append(CaseRecord(name=desc[:40], rc=0,
                                      checks=[Check("ok", True)]))
        else:
            fail += 1
            fail_items.append(desc)
            records.append(CaseRecord(name=desc[:40], rc=1,
                                      checks=[Check("ok", False, desc)]))

    try:
        with tee:
            tee.emit(f"=== Phase 2 门禁 (v0.38.0): {ts} — 日志 {out_log} ===")

            # ---- STEP -1: 双机 .ko srcversion 一致性 (L1d 停机教训) ----
            cli_ko = _ko_srcversion(client)
            srv_ko = _ko_srcversion(server)
            if cli_ko and srv_ko and cli_ko != srv_ko:
                tee.emit(Con.err("✗ 双机 .ko srcversion 不一致:"))
                tee.emit(f"  {client_host_name}: {cli_ko}")
                tee.emit(f"  {server_host_name}: {srv_ko} (旧!)")
                tee.emit(f"  先: REMOTE={server_host_name} bash scripts/build.sh")
                record(False, f"预检: {server_host_name} .ko 过期")
                return 1
            record(True, "预检: 双机 .ko srcversion 一致"
                         + (f" ({cli_ko})" if cli_ko else ""))

            # ---- STEP 0: server 一次性默认重载 ----
            tee.emit(f"STEP 0: {server_host_name} 一次性重载 (默认参数)")
            _reload(ctx, server, server_bdf, "", tee)

            def load(tag: str, extra: str, then) -> None:
                dm = _dmesg_count(client)
                if _reload(ctx, client, client_bdf, extra, tee):
                    then()
                    if ctx.dry_run:
                        _dmesg_check_dry(tag, record)
                    else:
                        _dmesg_check(ctx, client, dm, tag, ts, out_dir, tee,
                                     record)
                else:
                    record(False, f"{tag} 重载失败 ({extra or '默认参数'})")

            # ---- Load 1: 默认参数 (全量门禁) ----
            def load1() -> None:
                if ctx.dry_run:
                    record(True, "模块版本 (dry-run 跳过)")
                else:
                    # /proc 统计段头报组粒度版本 (旧模块无统计段 → 门禁失败)
                    ver_res = client.run_script(
                        "grep -E '统计 \\(v0\\.[0-9]+\\.[0-9]+\\) 组粒度映射'"
                        " /proc/symrdma | grep -oE 'v0\\.[0-9]+\\.[0-9]+'\n",
                        timeout=20)
                    ver = _load_ver(ver_res.text) or "?"
                    if ver == version_gate:
                        record(True, f"模块版本 {ver}")
                    else:
                        record(False, f"模块版本 {ver} != {version_gate} "
                                      "(重载旧 .ko?)")
                _run_local(ctx, "L1a: test.sh all (默认参数, 含 L19)",
                           [sys.executable,
                            str(config.PKG_DIR / "__main__.py"),
                            "levels", "all"], tee,
                           out_dir / f"group_gates_{ts}_L1a.log", record)
                _run_local(ctx, "L1c: run_sir_cross.sh all (跨机数据面)",
                           [sys.executable,
                            str(config.PKG_DIR / "__main__.py"),
                            "sir", "all"], tee,
                           out_dir / f"group_gates_{ts}_L1c.log", record)
                _run_local(ctx, "L1d: racebw (双机吞吐回归)",
                           [sys.executable,
                            str(config.PKG_DIR / "__main__.py"),
                            "racebw"], tee,
                           out_dir / f"group_gates_{ts}_L1d.log", record)

            load("load1", "", load1)

            # ---- Load 2-4: 专项形态对照 ----
            def run_l19() -> None:
                _run_local(ctx, "L2: test.sh level19 (demote_fail_grp=2 注入)",
                           [sys.executable,
                            str(config.PKG_DIR / "__main__.py"),
                            "levels", "level19"], tee,
                           out_dir / f"group_gates_{ts}_L2.log", record)

            def run_all(tag: str) -> None:
                _run_local(ctx, f"{tag}: test.sh all (对照回归)",
                           [sys.executable,
                            str(config.PKG_DIR / "__main__.py"),
                            "levels", "all"], tee,
                           out_dir / f"group_gates_{ts}_{tag}.log", record)

            load("load2", "demote_fail_grp=2", run_l19)
            load("load3", "iommu_huge=0", lambda: run_all("L3"))
            load("load4", "repair_sg=0", lambda: run_all("L4"))

            # ---- Load 5: 收尾默认重载 ----
            if _reload(ctx, client, client_bdf, "", tee):
                record(True, "L5: 收尾默认参数重载")
            else:
                record(False, "收尾默认重载失败")

            # ---- 汇总 ----
            tee.emit()
            tee.emit("========================================")
            total = time.monotonic() - t0
            if fail == 0:
                n = sum(1 for r in records if r.rc == 0)
                tee.emit(Con.ok(f"Phase 2 门禁全绿: {n} 项通过")
                         + Con.dim(f" · 总耗时 {total / 60:.0f}m"))
            else:
                tee.emit(Con.err(f"Phase 2 门禁失败: {fail} 项"))
                for it in fail_items:
                    tee.emit(f"  ✗ {it}")
                tee.emit(f"日志: {out_log}")
            tee.emit("========================================")
    finally:
        pass  # tee 关闭由 with 承担; 后续重载残留进程无 (门禁自身无后台进程)

    ok = fail == 0
    if manifest and records:
        write_manifest(manifest, suite="group-gates",
                       meta={"client": client_host_name,
                             "server": server_host_name,
                             "client_bdf": client_bdf,
                             "server_bdf": server_bdf,
                             "version_gate": version_gate},
                       cases=records, verdict="PASS" if ok else "FAIL",
                       failed=[] if ok else fail_items, started=started,
                       duration=time.monotonic() - t0)
    return 0 if ok else 1
