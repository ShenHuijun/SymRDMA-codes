#!/bin/bash
# regen_patch.sh — 从 ofed/{mlx5_ib,ib_core}/{original,modified} 生成 ofed/patches/*.patch
#
# 纯本地操作, 无远端依赖 (np_code 已退出工作流)。
# 修改 OFED 源码后运行本脚本更新补丁。
set -e
cd "$(dirname "$0")/.."

FILES="main_ext.c mem.c mr.c mlx5_ib.h"
SRC="ofed/mlx5_ib/original"
DST="ofed/mlx5_ib/modified"
OUT="ofed/patches/identity_mtt.patch"

> "$OUT"
for f in $FILES; do
	# diff 有差异时返回 1, 属正常
	diff -u --label "a/drivers/infiniband/hw/mlx5/$f" \
	     --label "b/drivers/infiniband/hw/mlx5/$f" \
	     "$SRC/$f" "$DST/$f" >> "$OUT" || true
done

echo "=== 补丁已生成: $OUT ($(wc -l < "$OUT") 行) ==="
grep '^---' "$OUT"

# ---- ib_umem_nopin.patch (v0.9.0, 同样统一为 a/ b/ 树路径 → patch -p1 可直接应用) ----
SRC2="ofed/ib_core/original"
DST2="ofed/ib_core/modified"
OUT2="ofed/patches/ib_umem_nopin.patch"

> "$OUT2"
# 树内路径映射: umem.c → drivers/infiniband/core/, ib_umem.h → include/rdma/
diff -u --label "a/drivers/infiniband/core/umem.c" \
     --label "b/drivers/infiniband/core/umem.c" \
     "$SRC2/umem.c" "$DST2/umem.c" >> "$OUT2" || true
diff -u --label "a/include/rdma/ib_umem.h" \
     --label "b/include/rdma/ib_umem.h" \
     "$SRC2/ib_umem.h" "$DST2/ib_umem.h" >> "$OUT2" || true

echo "=== 补丁已生成: $OUT2 ($(wc -l < "$OUT2") 行) ==="
grep '^---' "$OUT2"
