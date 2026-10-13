#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
nopf_avg.py — no-PF 带宽矩阵多轮 CSV 平均 + 回归对比 (nopf_pipeline.sh 第 3/5 步)

输入: run_nopf_bw.sh 产出的一个或多个 CSV (size_bytes,rdma_read,rdma_write,sym_read,sym_write;
      '#' 注释行自动跳过)
用法:
    python3 tests/scripts/nopf_avg.py tests/results/nopf_bw_A.csv results/nopf_bw_B.csv \
            [--out tests/results/nopf_bw_avg_TS.csv] [--compare tests/results/nopf_bw_avg_prev.csv] \
            [--thresh 3.0]

输出:
    - 平均 CSV (元数据行记录来源文件数)
    - stdout: 平均表 + sym/bare 比值表
    - --compare 时: 逐尺寸 Δ% 对比; **线速区 (≥1024B)** |Δ| > thresh 记为回归
      (退出码 1), 小消息区仅提示 (单轮噪声大, 见 TESTING §5.2)
"""
import argparse
import csv
import glob
import os
import sys
import time

CATS = ("rdma_read", "rdma_write", "sym_read", "sym_write")
LINE_SPEED_MIN = 1024   # ≥ 此尺寸视为线速区 (回归判定), 小消息区噪声大仅提示


def load_csv(path):
    rows = {}
    with open(path, encoding="utf-8") as f:
        lines = [ln for ln in f if not ln.startswith("#") and ln.strip()]
    for r in csv.DictReader(lines):
        k = int(r["size_bytes"])
        rows[k] = {c: float(r[c]) for c in CATS}
    return rows


def avg_rows(list_of_rows):
    acc = {}
    for rows in list_of_rows:
        for k, v in rows.items():
            a = acc.setdefault(k, {c: 0.0 for c in CATS})
            for c in CATS:
                a[c] += v[c]
    n = len(list_of_rows)
    return {k: {c: a[c] / n for c in CATS} for k, a in acc.items()}


def md_table(rows, title):
    out = [f"\n{title}", "",
           "| size(B) | rdma_read | rdma_write | sym_read | sym_write | read Δ% | write Δ% |",
           "|---------|-----------|------------|----------|-----------|---------|----------|"]
    for k in sorted(rows):
        r, w = rows[k]["rdma_read"], rows[k]["rdma_write"]
        sr, sw = rows[k]["sym_read"], rows[k]["sym_write"]
        dr = (sr - r) / r * 100 if r else 0.0
        dw = (sw - w) / w * 100 if w else 0.0
        out.append(f"| {k} | {r:.2f} | {w:.2f} | {sr:.2f} | {sw:.2f} | {dr:+.1f} | {dw:+.1f} |")
    return "\n".join(out)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csvs", nargs="+", help="待平均的 CSV (≥1)")
    ap.add_argument("--out", default=None, help="平均 CSV 输出路径 (默认 tests/results/nopf_bw_avg_<ts>.csv)")
    ap.add_argument("--compare", default=None, help="与之前的平均 CSV 对比 (回归检查)")
    ap.add_argument("--thresh", type=float, default=3.0,
                    help="线速区回归阈值 %% (默认 3.0)")
    args = ap.parse_args()

    srcs = []
    for pat in args.csvs:
        srcs.extend(sorted(glob.glob(pat)) if any(ch in pat for ch in "*?[") else [pat])
    if not srcs:
        print("✗ 无输入 CSV", file=sys.stderr)
        return 2
    for p in srcs:
        if not os.path.exists(p):
            print(f"✗ 文件不存在: {p}", file=sys.stderr)
            return 2

    all_rows = [load_csv(p) for p in srcs]
    sizes = set()
    for rows in all_rows:
        sizes.update(rows)
    missing = {k for k in sizes if any(k not in rows for rows in all_rows)}
    if missing:
        print(f"✗ 各 CSV 尺寸点不一致, 缺失: {sorted(missing)}", file=sys.stderr)
        return 2

    rows = avg_rows(all_rows)

    out = args.out or f"tests/results/nopf_bw_avg_{time.strftime('%Y%m%d_%H%M%S')}.csv"
    os.makedirs(os.path.dirname(out) or ".", exist_ok=True)
    with open(out, "w", newline="") as f:
        f.write(f"# SymRDMA no-PF 带宽矩阵 {len(all_rows)} 轮平均 (scripts/nopf_avg.py)\n")
        f.write(f"# date={time.strftime('%F %T')} runs={len(all_rows)}\n")
        f.write("# sources: " + " ".join(os.path.basename(p) for p in srcs) + "\n")
        f.write("size_bytes,rdma_read,rdma_write,sym_read,sym_write\n")
        for k in sorted(rows):
            f.write(f"{k}," + ",".join(f"{rows[k][c]:.2f}" for c in CATS) + "\n")

    print(md_table(rows, f"## 平均结果 ({len(all_rows)} 轮, {out})"))
    print("\nSymRDMA / 裸 RDMA 带宽比 (1.00 = 零开销):")
    print("      size     read    write")
    for k in sorted(rows):
        rr = rows[k]["sym_read"] / rows[k]["rdma_read"] if rows[k]["rdma_read"] else 0
        rw = rows[k]["sym_write"] / rows[k]["rdma_write"] if rows[k]["rdma_write"] else 0
        print(f"  {k:>8}   {rr:.3f}   {rw:.3f}")

    rc = 0
    if args.compare:
        if not os.path.exists(args.compare):
            print(f"\n[对比] 基线不存在 ({args.compare}) — 首次运行, 跳过回归检查")
        else:
            prev = load_csv(args.compare)
            common = sorted(set(rows) & set(prev))
            only_new = sorted(set(rows) - set(prev))
            if only_new:
                print(f"\n[对比] 基线缺少尺寸点 {only_new} — 这些点不做回归判定")
            print(f"\n## 回归对比 vs {args.compare} (阈值 {args.thresh}%, 仅线速区 ≥{LINE_SPEED_MIN}B 判定)")
            print("| size(B) | read Δ% | write Δ% | 判定 |")
            print("|---------|---------|----------|------|")
            for k in common:
                # 判定用 sym/bare 比值的变化 ( overhead 变化, 剥离 bare 侧机器噪声):
                # bare 自身波动 (如 EDR 扫描/频率) 不该被记成 SymRDMA 回归
                dr = (rows[k]["rdma_read"] / prev[k]["rdma_read"] - 1) * 100
                dw = (rows[k]["rdma_write"] / prev[k]["rdma_write"] - 1) * 100
                dsr = (rows[k]["sym_read"] / prev[k]["sym_read"] - 1) * 100
                dsw = (rows[k]["sym_write"] / prev[k]["sym_write"] - 1) * 100

                def ratio_shift(sym_c, bare_c):
                    p = prev[k]
                    n = rows[k]
                    if p[sym_c] <= 0 or p[bare_c] <= 0 or n[sym_c] <= 0 or n[bare_c] <= 0:
                        return 0.0
                    r_prev = p[sym_c] / p[bare_c]
                    r_now = n[sym_c] / n[bare_c]
                    return (r_now - r_prev) * 100   # 百分点 (1.00 → 1.03 = +3)

                rr = ratio_shift("sym_read", "rdma_read")
                rw = ratio_shift("sym_write", "rdma_write")
                if k >= LINE_SPEED_MIN:
                    bad = abs(rr) > args.thresh or abs(rw) > args.thresh
                    tag = "✗ 回归" if bad else "✓"
                    if bad:
                        rc = 1
                    print(f"| {k} | sym/bare 比 {rr:+.1f}pp (值 {dsr:+.1f}, bare {dr:+.1f}) | "
                          f"比 {rw:+.1f}pp (值 {dsw:+.1f}, bare {dw:+.1f}) | {tag} |")
                else:
                    print(f"| {k} | {dsr:+.1f} | {dsw:+.1f} | (小消息区, 仅提示) |")

    # 稳定引用名 (文档/对比用)
    latest = os.path.join(os.path.dirname(out) or ".", "nopf_bw_avg_latest.csv")
    if out != latest:
        with open(out) as fi, open(latest, "w") as fo:
            fo.write(fi.read())
    print(f"\n✓ 平均 CSV: {out} (latest 引用: {latest})")
    return rc


if __name__ == "__main__":
    sys.exit(main())
