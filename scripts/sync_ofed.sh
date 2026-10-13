#!/bin/bash
# sync_ofed.sh — OFED 修改文件同步 (ofed/{mlx5_ib,ib_core}/modified → $REMOTE 工作树)
#
# 修改文件由 git 跟踪 (ofed/{mlx5_ib,ib_core}/{original,modified}),
# 本脚本只负责把修改后的文件推送到 $REMOTE 工作树供编译
# (由 ofed_push.sh 调用; 拓扑默认 REMOTE 见 common.sh)。
source "$(dirname "$0")/common.sh"

MLX5_IB="$REMOTE_OFED/drivers/infiniband/hw/mlx5"
LOCAL_FILES="$LOCAL/ofed/mlx5_ib/modified"

# v0.15.0: 同时同步 ib_core 的 no-pin umem 修改 (ib_umem_nopin.patch)
IB_CORE="$REMOTE_OFED/drivers/infiniband/core"
IB_CORE_INC="$REMOTE_OFED/include/rdma"
LOCAL_IB_CORE="$LOCAL/ofed/ib_core/modified"

echo "=== OFED 修改文件同步 (push: ofed/mlx5_ib/modified → $REMOTE) ==="
rsync -az "$LOCAL_FILES/" "$REMOTE:$MLX5_IB/"
echo "=== ib_core 同步 (umem.c + ib_umem.h) ==="
rsync -az "$LOCAL_IB_CORE/umem.c" "$REMOTE:$IB_CORE/"
rsync -az "$LOCAL_IB_CORE/ib_umem.h" "$REMOTE:$IB_CORE_INC/"
echo "=== 完成 ==="
