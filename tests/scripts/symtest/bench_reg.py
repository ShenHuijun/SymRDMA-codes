"""L17 注册可扩展性基准 — run_reg_bench.sh 的 Python 引擎（A 轴, Phase 0）。

单机 (REMOTE, 默认 host-a — 模块加载机), 纯控制面: 推送并编译
tests/bench/npreg_bench.c, 按 (touch × size × thp) 矩阵跑 REG_MR/DEREG_MR
ioctl 计时, 汇总 CSV。

基线 (v0.37.0 逐页形态) 预期: ~682MB 之上 REG 失败 (-ENOMEM, pages[]
kcalloc 单块超 kmalloc 上限 — A 轴问题陈述, 失败点 = 实测数据); 成功点
耗时 ∝ 页数。Phase 2 (组模型) 后同矩阵复测: 64GB/128GB none/sparse 应
成功且 ≤1s 量级; iommu_huge=0 回退形态与本基线一致 (回归门禁)。

输出: $OUT_DIR/reg_${TAG}_${ts}.csv
"""

from __future__ import annotations

import time
from pathlib import Path

from . import config
from .deploy import DeployUnit, ensure_deployed
from .report import CaseRecord, Check, Con, Tee, write_manifest
from .ssh import Ctx, q


DEFAULT_SIZES = ("256M", "512M", "682M", "1G", "4G", "16G", "64G", "128G")
ALL_SIZES = ("256M", "512M")
SPARSE_SIZES = ("256M", "512M", "682M")
THP_SIZES = ("256M",)


def _deploy_unit() -> DeployUnit:
    src = config.BENCH_SRC / "npreg_bench.c"
    return DeployUnit(
        name="npreg_bench",
        sources=[(str(src), "/tmp/npreg_bench.c")],
        binaries=["/tmp/npreg_bench"],
        compile_script=("gcc -O2 -Wall -o /tmp/npreg_bench /tmp/npreg_bench.c "
                        "&& { echo COMPILE_OK; exit 0; }\necho COMPILE_FAIL\n"),
    )


def run_point(host, *, touch: str, size: str, thp: str, iters: int,
              csv_f, tee: Tee) -> None:
    """单点: REG/DEREG ioctl 计时（成功点中位 + 失败点 rc 均为数据）。"""
    res = host.run_script(
        f"timeout 600 /tmp/npreg_bench -S {q(size)} -t {q(touch)} "
        f"-i {int(iters)} -T {q(thp)} 2>&1\n", timeout=660)
    out = res.text
    reg_rows = [line for line in out.splitlines() if line.startswith("REG,")]
    for line in reg_rows:
        csv_f.write(line + "\n")
    csv_f.flush()
    for line in out.splitlines():
        if "中位" in line or "全部失败" in line:
            tee.emit(line.replace("[npreg_bench]", " ", 1))
    if not reg_rows:
        tee.emit(Con.err(f"  ✗ {touch} {size} thp={thp}: 无 REG 行 (rc={res.rc})"))


def _summary(csv_path: Path, tee: Tee) -> None:
    """成功点中位 reg_ms / 失败点 rc 汇总（bash awk 版等价）。"""
    tee.emit("=== 摘要 (成功点中位 reg_ms / 失败点 rc) ===")
    times: dict[str, list[str]] = {}
    rc: dict[str, str] = {}
    for line in csv_path.read_text().splitlines():
        if not line.startswith("REG,"):
            continue
        fields = dict(f.split("=", 1) for f in line.split(",")[1:] if "=" in f)
        key = (f"{fields.get('size_mb', '?')}MB {fields.get('touch', '?')} "
               f"thp={fields.get('thp', '?')}")
        if fields.get("rc") == "0":
            times.setdefault(key, []).append(fields.get("reg_ms", "?"))
        else:
            rc[key] = fields.get("rc", "?")
    for key, ms in times.items():
        tee.emit(f"{key:<24} reg_ms: {' '.join(ms)}")
    for key, r in rc.items():
        tee.emit(f"{key:<24} rc={r} (失败)")


def run_reg(ctx: Ctx, *, remote: str, sizes: list[str], tag: str,
            iters: int, out_dir: Path, json_path: str | None = "auto") -> int:
    host = ctx.host(remote)
    started = time.time()
    t0 = time.monotonic()
    ts = config.timestamp()
    out_dir.mkdir(parents=True, exist_ok=True)
    csv_path = out_dir / f"reg_{tag}_{ts}.csv"
    manifest = (out_dir / f"reg_{tag}_{ts}_manifest.json") \
        if json_path in ("auto", None) and not ctx.dry_run \
        else (Path(json_path) if json_path not in ("auto", "none", None) else None)

    matrix: list[tuple[str, tuple[str, ...], str]] = [
        ("none", tuple(sizes), "off"), ("all", ALL_SIZES, "off"),
        ("sparse", SPARSE_SIZES, "off"), ("all", THP_SIZES, "on"),
        ("sparse", ("256M",), "on")]

    with Tee(None if ctx.dry_run else out_dir / f"reg_{tag}_{ts}.log") as tee:
        tee.emit(f"=== L17 注册基准 (目标: {remote}, tag={tag}) ===")
        ensure_deployed(host, _deploy_unit(), log=tee.emit)
        if ctx.dry_run:
            for touch, sz_list, thp in matrix:
                for s in sz_list:
                    host.run_script(
                        f"timeout 600 /tmp/npreg_bench -S {q(s)} -t {q(touch)} "
                        f"-i {int(iters)} -T {q(thp)} 2>&1\n", timeout=660)
            return 0

        base_mr = host.mr_count()
        if base_mr is None:
            tee.emit(Con.err("/proc/symrdma 不可读 (模块未加载?)"))
            return 1
        tee.emit(f"基线活跃 MR: {base_mr}")

        checks: list[Check] = []
        with csv_path.open("w", encoding="utf-8") as csv_f:
            for touch, sz_list, thp in matrix:
                for s in sz_list:
                    run_point(host, touch=touch, size=s, thp=thp,
                              iters=iters, csv_f=csv_f, tee=tee)

        end_mr = host.mr_count()
        tee.emit(f"结束活跃 MR: {end_mr} (基线 {base_mr})")
        if end_mr != base_mr:
            tee.emit(Con.warn("  ⚠ MR 计数未回落 — 检查泄漏"))
        checks.append(Check("mr-leak", end_mr == base_mr,
                            f"{base_mr} → {end_mr}"))

        _summary(csv_path, tee)
        total = time.monotonic() - t0
        rec = CaseRecord(name=f"reg_{tag}", display="L17 注册基准",
                         rc=0 if all(c.ok for c in checks) else 1,
                         duration=total, checks=checks, log=str(csv_path))
        tee.emit(f"完成: {csv_path}")
        if manifest:
            write_manifest(manifest, suite="reg",
                           meta={"remote": remote, "tag": tag,
                                 "iters": iters, "sizes": sizes},
                           cases=[rec],
                           verdict="PASS" if rec.ok else "FAIL",
                           failed=[] if rec.ok else [rec.name],
                           started=started, duration=total)
        return 0 if rec.ok else 1
