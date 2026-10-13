#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plot_paper_figs.py — 从 tests/results/ 的基准 CSV/日志复现论文图 (自动取最新产物)

产出 (tests/results/paper_figs_<ts>/, PNG + PDF):
  fig12_race_throughput   论文 Fig 12  — race 吞吐 (racebw CSV, sym/odp × minor/major, read/write)
  fig14_atomic            论文 Fig 14  — 原子操作延迟/吞吐 (atomicbench CSV, pinned/odp/sym)
  fig11_read_latency      论文 Fig 11(a) 对应 — race 下 Read 延迟 (odp_compare 日志合并表)
  tables1_2_ctl           论文 Tables 1/2 对应 — 控制面开销 (ctlbench CSV, vanilla vs sym)
  fig13b_nopf_bw          论文 Fig 13(b) — no-PF 分类带宽 (调用既有 plot_nopf_bw.py)

用法:
    python3 tests/scripts/plot_paper_figs.py                  # 全部图
    python3 tests/scripts/plot_paper_figs.py fig12 fig14      # 指定图
图内标签用英文 (避免 matplotlib 中文字体缺失); 控制台打印关键比值对照。
"""
import argparse
import glob
import os
import re
import subprocess
import sys
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.normpath(os.path.join(HERE, "..", "results"))

C_SYM = "#2166ac"    # 蓝 — SymRDMA
C_SYM_W = "#b2182b"  # 红 — SymRDMA write
C_ODP = "#7f7f7f"    # 灰 — ODP
C_PIN = "#1b7837"    # 绿 — pinned native


def latest(pattern):
    hits = sorted(glob.glob(os.path.join(RESULTS, pattern)))
    if not hits:
        sys.exit(f"✗ 找不到产物: {pattern}")
    return hits[-1]


def load_kv_csv(path):
    """racebw/atomic 形态: row,value,unit (可带 # 注释)"""
    kv = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("row,"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) >= 2:
                kv[parts[0]] = float(parts[1])
    return kv


def size_bytes(tag):
    tag = tag[1:] if tag.startswith("s") else tag  # 行名形如 s2 / s1K / s4M
    mult = {"K": 1024, "M": 1024 * 1024}
    if tag.isdigit():
        return int(tag)
    return int(float(tag[:-1]) * mult[tag[-1]])


# ---------------------------------------------------------------- Fig 12
def fig12(outdir):
    csv = latest("racebw_2*.csv")
    kv = load_kv_csv(csv)
    sizes = ["s2", "s16", "s128", "s1K", "s8K", "s64K", "s512K", "s4M"]
    xs = [size_bytes(s) for s in sizes]

    def series(op, kind, cls):
        vals = [kv.get(f"thr_{cls}_{kind}_{op}_{s}", float("nan")) for s in sizes]
        return [v * 8 / 1000 if False else v for v in vals]  # mbps 原样

    fig, axes = plt.subplots(1, 2, figsize=(10.5, 4.2), sharey=True)
    styles = [
        ("sym",  "minor", f"SymRDMA (minor)", dict(color=C_ODP, ls="-", marker="o", lw=2.0, ms=5)),
        ("sym",  "major", f"SymRDMA (major)", dict(color=C_SYM, ls="-", marker="o", lw=2.0, ms=5)),
        ("odp",  "minor", f"ODP (minor)",     dict(color=C_ODP, ls="--", marker="s", mfc="white", lw=1.6, ms=5)),
        ("odp",  "major", f"ODP (major)",     dict(color=C_SYM, ls="--", marker="s", mfc="white", lw=1.6, ms=5)),
    ]
    for ax, op, title in zip(axes, ["read", "write"], ["(a) Read", "(b) Write"]):
        for cls, kind, label, st in styles:
            c = C_SYM if cls == "sym" else C_ODP
            if op == "write":
                c = C_SYM_W if cls == "sym" else "#8b1a1a"
            st = dict(st, color=c)
            ys = series(op, kind, cls)
            ax.plot(xs, ys, label=label, **st)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_title(title)
        ax.set_xlabel("Message Size (Bytes)")
        ax.grid(True, which="both", alpha=0.25)
        ax.set_xticks(xs)
        ax.set_xticklabels([f"{s}" for s in ["2", "16", "128", "1K", "8K", "64K", "512K", "4M"]], rotation=0, fontsize=8)
    axes[0].set_ylabel("Throughput (MB/s)")
    axes[0].legend(fontsize=9, frameon=False)
    fig.suptitle("Throughput under Host-Remote Races (paper Fig 12)", fontsize=12)
    fig.tight_layout()
    out = os.path.join(outdir, "fig12_race_throughput")
    fig.savefig(out + ".png", dpi=150)
    fig.savefig(out + ".pdf")
    plt.close(fig)

    # 控制台比值对照 (论文 §5.2.1: 2B minor 600×; 1MB read 19× / write 7×)
    print(f"[fig12] 源: {os.path.basename(csv)}")
    for s, paper in [("s2", "600×"), ("s1M", "19×")]:
        pass
    for s in sizes:
        r = kv.get(f"thr_sym_minor_read_{s}", 0) / max(kv.get(f"thr_odp_minor_read_{s}", 1e-9), 1e-12)
        w = kv.get(f"thr_sym_minor_write_{s}", 0) / max(kv.get(f"thr_odp_minor_write_{s}", 1e-9), 1e-12)
        print(f"  {s:>5}: sym/odp minor read {r:7.1f}× | write {w:7.1f}×")
    return out


# ---------------------------------------------------------------- Fig 14
def fig14(outdir):
    csv = latest("atomicbench_2*.csv")
    kv = load_kv_csv(csv)
    dens = [4, 16, 64, 256]
    depth = [2, 4, 8, 16, 32, 64, 128]
    fig, axes = plt.subplots(1, 4, figsize=(15.5, 3.8))
    series3 = [("pinned", "Pinned Native", dict(color=C_PIN, ls="-", marker="o", lw=1.9, ms=5)),
               ("odp",    "ODP Native",    dict(color=C_ODP, ls="--", marker="s", mfc="white", lw=1.6, ms=5)),
               ("sym",    "SymRDMA",       dict(color=C_SYM, ls="-", marker="^", lw=1.9, ms=5))]

    def plot_lat(ax, op):
        for cls, label, st in series3:
            ys = [kv.get(f"lat_{cls}_{op}_d{d}", float("nan")) for d in dens]
            ax.plot(dens, ys, label=label, **st)
        ax.set_xscale("log", base=2)
        ax.set_yscale("log")
        ax.set_xlabel("Counters per page")
        ax.grid(True, which="both", alpha=0.25)

    def plot_thr(ax, op):
        for cls, label, st in series3:
            ys = [kv.get(f"thr_{cls}_{op}_p{d}", float("nan")) for d in depth]
            ax.plot(depth, ys, label=label, **st)
        ax.set_xscale("log", base=2)
        ax.set_xlabel("Pipeline Depth")
        ax.grid(True, which="both", alpha=0.25)

    plot_lat(axes[0], "faa"); axes[0].set_title("(a) FAA Latency"); axes[0].set_ylabel("Avg Latency (µs)")
    plot_thr(axes[1], "faa"); axes[1].set_title("(b) FAA Throughput"); axes[1].set_ylabel("Throughput (M ops/s)")
    plot_lat(axes[2], "cas"); axes[2].set_title("(c) CAS Latency")
    plot_thr(axes[3], "cas"); axes[3].set_title("(d) CAS Throughput")
    axes[0].legend(fontsize=9, frameon=False)
    fig.suptitle("Atomic Operations (paper Fig 14) — two-sided CPU path vs NIC atomics", fontsize=12)
    fig.tight_layout()
    out = os.path.join(outdir, "fig14_atomic")
    fig.savefig(out + ".png", dpi=150)
    fig.savefig(out + ".pdf")
    plt.close(fig)

    print(f"[fig14] 源: {os.path.basename(csv)}")
    for op in ("faa", "cas"):
        d_sym = kv[f"lat_sym_{op}_d4"] - kv[f"lat_pinned_{op}_d4"]
        print(f"  {op.upper()} sym−pinned @d4 {d_sym:+.2f}µs (论文 +1–2µs) | ODP 尖峰 {kv[f'lat_odp_{op}_d4']:.0f}µs (论文 hundreds of µs)")
    for op in ("faa", "cas"):
        sp = kv[f"thr_sym_{op}_p128"] / max(kv[f"thr_pinned_{op}_p128"], 1e-9)
        print(f"  {op.upper()} 深流水 p128 sym/pinned {sp:.2f}× ({(sp-1)*100:+.0f}%, 论文 +10–60%)")
    return out


# ---------------------------------------------------------------- Fig 11(a) 对应
FIG11_RE = re.compile(
    r"^\|\s*(\S+)\s*\|\s*(\d+)\s*/\s*(\d+)\s*\|\s*(\d+)\s*/\s*(\d+)\s*\|"
    r"\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*\|\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*\|"
    r"\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*\|\s*(\d+)\s*/\s*(\d+)\s*/\s*(\d+)\s*\|")


def fig11(outdir):
    log = latest("odp_compare_2*.log")
    rows = []
    in_merged = False
    with open(log, encoding="utf-8") as f:
        for line in f:
            if "Phase B 合并表" in line:
                in_merged = True
                continue
            if in_merged:
                m = FIG11_RE.match(line.strip())
                if m:
                    rows.append(m.groups())
                elif rows and line.strip() and not line.strip().startswith("|"):
                    break
    if not rows:
        sys.exit(f"✗ 日志中未找到 Phase B 合并表: {log}")

    sizes = [r[0] for r in rows]
    groups = [
        ("ODP remote minor", [float(r[5]) for r in rows], C_ODP, "//"),
        ("Sym remote minor", [float(r[8]) for r in rows], C_SYM, ""),
        ("ODP remote major", [float(r[11]) for r in rows], C_ODP, "\\\\"),
        ("Sym remote major", [float(r[14]) for r in rows], C_SYM_W, "xx"),
    ]
    import numpy as np
    x = np.arange(len(sizes))
    w = 0.2
    fig, ax = plt.subplots(figsize=(8.2, 4.4))
    for i, (label, vals, color, hatch) in enumerate(groups):
        ax.bar(x + (i - 1.5) * w, vals, w, label=label, color=color, hatch=hatch, edgecolor="white", linewidth=0.5)
    ax.set_yscale("log")
    ax.set_xticks(x)
    ax.set_xticklabels(sizes)
    ax.set_xlabel("Message Size")
    ax.set_ylabel("Read Latency (µs, avg)")
    ax.set_title("Read latency under remote page faults (paper Fig 11(a) counterpart)")
    ax.legend(fontsize=9, frameon=False, ncol=2)
    ax.grid(True, axis="y", which="both", alpha=0.25)
    fig.tight_layout()
    out = os.path.join(outdir, "fig11_read_latency")
    fig.savefig(out + ".png", dpi=150)
    fig.savefig(out + ".pdf")
    plt.close(fig)

    print(f"[fig11] 源: {os.path.basename(log)}")
    for r in rows:
        sym_m, odp_m = float(r[8]), float(r[5])
        sym_M, odp_M = float(r[14]), float(r[11])
        print(f"  {r[0]:>6}: minor sym/odp {odp_m/sym_m:5.1f}× | major sym/odp {odp_M/sym_M:5.1f}× | ODP 恒 ≈{odp_m:.0f}µs (论文 ≈2ms 量级)")
    return out


# ---------------------------------------------------------------- Tables 1/2 对应
def tables12(outdir):
    csv = latest("ctlbench_2*.csv")
    rows = {}  # (mode,row) -> [values per host]
    with open(csv, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("host,"):
                continue
            parts = [p.strip() for p in line.split(",")]
            if len(parts) < 4:
                continue
            host, mode, row, val = parts[0], parts[1], parts[2], float(parts[3])
            rows.setdefault((mode, row), []).append(val)
    avg = {k: sum(v) / len(v) for k, v in rows.items()}

    items = [  # (row, 显示名, 单位, 论文参考 original→sym)
        ("lib_init",  "Library init", "ms", "(43→49 ms)"),
        ("mr_first",  "First MR reg", "us", "(50→135 µs)"),
        ("cq_create", "Create CQ", "us", "(29→56 µs)"),
        ("qp_create", "Create QP", "us", "(45→67 µs)"),
        ("qp_rts",    "QP init (RTS)", "us", "(12→19 µs)"),
        ("swap_out",  "Swap out /page", "us", "(75→78 µs)"),
    ]
    fig, axes = plt.subplots(1, 2, figsize=(12.5, 4.3), gridspec_kw={"width_ratios": [3, 1.15]})
    ax = axes[0]
    x = range(len(items))
    vanilla = [avg.get(("vanilla", r), float("nan")) for r, *_ in items]
    sym = [avg.get(("sym", r), float("nan")) for r, *_ in items]
    w = 0.36
    ax.bar([i - w / 2 for i in x], vanilla, w, label="Original", color=C_ODP)
    ax.bar([i + w / 2 for i in x], sym, w, label="SymRDMA", color=C_SYM)
    ax.set_yscale("log")
    ax.set_xticks(list(x))
    ax.set_xticklabels([f"{name}\n{ref}" for _, name, _, ref in items], fontsize=8)
    ax.set_ylabel("Time (per-unit, log)")
    ax.set_title("Control-plane time cost (paper Table 2)")
    ax.legend(fontsize=9, frameon=False)
    ax.grid(True, axis="y", which="both", alpha=0.25)

    ax2 = axes[1]
    regs = [64, 128, 256, 512]
    vr = [avg.get(("vanilla", f"mr_reg_{m}MB"), float("nan")) for m in regs]
    sr = [avg.get(("sym", f"mr_reg_{m}MB"), float("nan")) for m in regs]
    ax2.plot(regs, vr, "o--", color=C_ODP, label="Original")
    ax2.plot(regs, sr, "o-", color=C_SYM, label="SymRDMA")
    ax2.set_xscale("log", base=2)
    ax2.set_yscale("log")
    ax2.set_xticks(regs, [f"{m}MB" for m in regs])
    ax2.set_xlabel("MR size")
    ax2.set_ylabel("Registration time (µs)")
    ax2.set_title("MR registration scaling")
    ax2.legend(fontsize=8, frameon=False)
    ax2.grid(True, which="both", alpha=0.25)
    fig.tight_layout()
    out = os.path.join(outdir, "tables1_2_ctl")
    fig.savefig(out + ".png", dpi=150)
    fig.savefig(out + ".pdf")
    plt.close(fig)

    print(f"[tables12] 源: {os.path.basename(csv)} (双机均值)")
    for r, name, unit, ref in items:
        print(f"  {name:<16} vanilla {avg.get(('vanilla', r), float('nan')):9.2f} {unit} | sym {avg.get(('sym', r), float('nan')):9.2f} {unit}  论文 {ref}")
    for m in ("vanilla", "sym"):
        if ("slope_note") :
            pass
    print(f"  MR slope: vanilla {avg.get(('vanilla','mr_slope'), float('nan')):.1f} ms/GB | sym {avg.get(('sym','mr_slope'), float('nan')):.1f} ms/GB (论文 400→20 ms/GB; 本实现逐 4KB 双 IOVA, 方向差如实记录)")
    return out


# ---------------------------------------------------------------- Fig 13(b)
def fig13b(outdir):
    csv = latest("nopf_bw_avg_2*.csv")
    out = os.path.join(outdir, "fig13b_nopf_bw")
    ret = subprocess.run(
        [sys.executable, os.path.join(HERE, "plot_nopf_bw.py"), csv, "--ref", "2764"],
        capture_output=True, text=True)
    print(ret.stdout)
    if ret.returncode != 0:
        print(ret.stderr)
        sys.exit("✗ plot_nopf_bw.py 失败")
    stem = os.path.splitext(os.path.basename(csv))[0]
    for ext in (".png", ".pdf"):
        src = os.path.join(RESULTS, stem + ext)
        if os.path.exists(src):
            dst = os.path.join(outdir, "fig13b_nopf_bw" + ext)
            os.replace(src, dst)
            print(f"  → {dst}")
    return out


MAIN = {"fig12": fig12, "fig14": fig14, "fig11": fig11, "tables12": tables12, "fig13b": fig13b}


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("figs", nargs="*", choices=[*MAIN.keys(), ""], help="要出的图 (默认全部)")
    args = ap.parse_args()
    which = [f for f in args.figs if f] or list(MAIN.keys())
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = os.path.join(RESULTS, f"paper_figs_{ts}")
    os.makedirs(outdir, exist_ok=True)
    print(f"输出目录: {outdir}\n")
    for f in which:
        out = MAIN[f](outdir)
        print(f"  → {out}.png / .pdf\n")
    print("完成。")


if __name__ == "__main__":
    main()
