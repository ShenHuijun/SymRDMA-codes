#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
plot_nopf_bw.py — 双机 no-page-fault 分类带宽矩阵画图 (论文 §5.2.2 Fig 13(b) 对照)

输入: scripts/run_nopf_bw.sh 产出的 CSV (size_bytes,rdma_read,rdma_write,sym_read,sym_write)
用法:
    python3 tests/scripts/plot_nopf_bw.py                  # 自动取 tests/results/ 最新 CSV
    python3 tests/scripts/plot_nopf_bw.py tests/results/nopf_bw_*.csv
    python3 tests/scripts/plot_nopf_bw.py <csv> --linear      # 线性 y 轴 (默认 log)
    python3 tests/scripts/plot_nopf_bw.py <csv> --ref 2764    # 水平参考线 (如实测线速 MB/s)

输出: 与 CSV 同目录同名 .png / .pdf; stdout 打印 sym/bare 比值表。
图内标签用英文 (避免 matplotlib 中文字体缺失问题)。
"""
import argparse
import glob
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

# (列名, 图例, 样式) — bare 虚线空心 marker / sym 实线实心; read 蓝 / write 红
CATS = [
    ("rdma_read",  "RDMA Read (bare)",  dict(color="#2166ac", ls="--", marker="o", mfc="white", lw=1.6, ms=6)),
    ("rdma_write", "RDMA Write (bare)", dict(color="#b2182b", ls="--", marker="s", mfc="white", lw=1.6, ms=6)),
    ("sym_read",   "SymRDMA Read",      dict(color="#2166ac", ls="-",  marker="o", lw=2.0, ms=6)),
    ("sym_write",  "SymRDMA Write",     dict(color="#b2182b", ls="-",  marker="s", lw=2.0, ms=6)),
]


def fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    if n < 1024 * 1024:
        return f"{n // 1024} KB"
    return f"{n // (1024 * 1024)} MB"


def load_csv(path: str):
    header, rows, meta = None, [], []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            if line.startswith("#"):
                meta.append(line[1:].strip())
                continue
            parts = [p.strip() for p in line.split(",")]
            if header is None:
                header = parts
            else:
                rows.append(parts)
    if header is None or "size_bytes" not in header:
        sys.exit(f"✗ CSV 格式不对 (缺 size_bytes 表头): {path}")
    return header, rows, meta


def main():
    repo = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ap = argparse.ArgumentParser(description="no-pf 双机带宽矩阵画图")
    ap.add_argument("csv", nargs="?", default=None, help="CSV 路径 (默认 tests/results/ 最新)")
    ap.add_argument("--linear", action="store_true", help="y 轴线性 (默认 log)")
    ap.add_argument("--ref", type=float, default=None, help="水平参考线 MB/s (如实测线速)")
    ap.add_argument("--out", default=None, help="输出目录 (默认与 CSV 同目录)")
    args = ap.parse_args()

    path = args.csv
    if path is None:
        cands = sorted(glob.glob(os.path.join(repo, "tests", "results", "nopf_bw_*.csv")))
        if not cands:
            sys.exit("✗ tests/results/ 下没有 nopf_bw_*.csv — 先跑 tests/scripts/nopf_pipeline.sh")
        path = cands[-1]
    header, rows, meta = load_csv(path)
    col = {name: i for i, name in enumerate(header)}

    def num(v):
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    sizes, data = [], {c[0]: {} for c in CATS}
    for row in rows:
        if len(row) < len(header):
            continue
        s = int(row[col["size_bytes"]])
        sizes.append(s)
        for name, _, _ in CATS:
            data[name][s] = num(row[col[name]]) if name in col else None
    sizes = sorted(set(sizes))

    outdir = args.out or os.path.dirname(path) or "."
    stem = os.path.splitext(os.path.basename(path))[0]
    png = os.path.join(outdir, stem + ".png")
    pdf = os.path.join(outdir, stem + ".pdf")

    fig, ax = plt.subplots(figsize=(8, 5))
    for name, label, style in CATS:
        xs = [s for s in sizes if data[name].get(s) is not None]
        ys = [data[name][s] for s in xs]
        if xs:
            ax.plot(xs, ys, label=label, **style)
    if not ax.lines:
        sys.exit("✗ CSV 内无可绘数据")

    ax.set_xscale("log", base=2)
    if not args.linear:
        ax.set_yscale("log")
    ax.set_xticks(sizes)
    ax.set_xticklabels([fmt_size(s) for s in sizes], fontsize=9)
    ax.xaxis.set_minor_formatter(matplotlib.ticker.NullFormatter())
    ax.minorticks_off()
    ax.set_xlabel("Message Size (Bytes)")
    ax.set_ylabel("Bandwidth (MB/s)")
    ax.set_title("Dual-host no-page-fault bandwidth\nSymRDMA (transparent, LD_PRELOAD) vs bare RDMA",
                 fontsize=12)
    ax.grid(True, which="both", alpha=0.3)
    ax.legend(loc="upper left", fontsize=9, framealpha=0.9)
    if args.ref:
        ax.axhline(args.ref, color="gray", ls=":", lw=1)
        ax.text(0.99, args.ref, f"  line rate ≈ {args.ref:.0f} MB/s",
                color="gray", fontsize=8, ha="right", va="bottom",
                transform=ax.get_yaxis_transform())
    if meta:
        fig.text(0.01, 0.005, "\n".join(meta)[:300], fontsize=6, color="gray", va="bottom")
    fig.tight_layout(rect=(0, 0.03, 1, 1))
    fig.savefig(png, dpi=150)
    fig.savefig(pdf)
    print(f"图: {png}\n   {pdf}")

    # 比值表
    print("\nSymRDMA / 裸 RDMA 带宽比 (1.00 = 零开销):")
    print(f"{'size':>10} {'read':>8} {'write':>8}")
    for s in sizes:
        cells = []
        for bare, sym in (("rdma_read", "sym_read"), ("rdma_write", "sym_write")):
            b, y = data[bare].get(s), data[sym].get(s)
            cells.append(f"{y / b:8.3f}" if b and y else "     —")
        print(f"{s:>10} {cells[0]} {cells[1]}")


if __name__ == "__main__":
    main()
