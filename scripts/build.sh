#!/bin/bash
# build.sh — 同步 + 编译内核模块 + 编译测试程序 + 推送远程 sudo 脚本 (我执行)
# 增量编译: make 按依赖追踪, 只重编变更文件 (v0.13.1 去掉无条件 make clean)
source "$(dirname "$0")/common.sh"
set -e

echo "=== 编译 SymRDMA (目标: $REMOTE) ==="

# 同步
# 同步 (v0.13.1: 排除编译产物 — 本地编译器 glibc 新, 推到远端 glibc 旧
# 会二进制不兼容 (GLIBC_2.34 not found); 测试二进制一律由远端 make 生成)
# F1: 测试二进制名单从 tests/programs/Makefile TARGETS 动态生成, 新增测试
# 自动纳入排除, 不再手工枚举 (历史两次 glibc 二进制污染教训)
# v0.24.2: 本地重组 tests/ — 远端部署目录 $TEST_DIR (~/pro/symrdma/test) 不变
TEST_BINS=$(grep -hE '^TARGETS' "$LOCAL/tests/programs/Makefile" \
	| sed 's/^TARGETS[[:space:]]*[:+]*=[[:space:]]*//' | tr ' ' '\n' \
	| grep -v '^$' || true)
EXCLUDE_BIN=(--exclude=libsymrdma.a --exclude=libsymrdma.o \
	--exclude='*.so' --exclude='*.o' --exclude='.tmp_versions')
for b in $TEST_BINS; do EXCLUDE_BIN+=(--exclude="$b"); done

echo "[1/4] 同步源码..."
ssh_run "mkdir -p $KERNEL_DIR $TEST_DIR $LIB_DIR $SIR_DIR $NPRDMA_DIR ~/pro/symrdma/scripts"
rsync -az "$LOCAL/kernel/" "$REMOTE:$KERNEL_DIR/"
# v0.24.2: tests/{programs,diag,bench} 平铺合并同步 (远端 TEST_DIR 扁平布局)
rsync -az "${EXCLUDE_BIN[@]}" "$LOCAL/tests/programs/" "$LOCAL/tests/diag/" \
	"$LOCAL/tests/bench/" "$REMOTE:$TEST_DIR/"
rsync -az --exclude='*.a' --exclude='*.o' "$LOCAL/lib/" "$REMOTE:$LIB_DIR/"
# v0.36.0: 清理 v0.24.3 拆分时代的 lib/sir.{c,h} 惰性残留 — 引号 include
# "sir.h" 同目录优先, 残留旧头会遮蔽 sir/sir.h (新增声明不可见 → 隐式声明;
# 实测 host-a/host-b 均有残留, 第一次编译报警后增量编译掩盖)
ssh "$REMOTE" "rm -f $LIB_DIR/sir.c $LIB_DIR/sir.h" 2>/dev/null || true
# v0.24.3: SIR 通道源码独立目录 (lib/nprdma 远端编译时均引 ../sir/sir.c)
rsync -az "$LOCAL/sir/" "$REMOTE:$SIR_DIR/"
# nprdma 同样排除编译产物 (本地 glibc 新, 坏 .o 推远端 → 链接崩, v0.14.1 实测)
rsync -az --exclude='*.o' --exclude='*.so' "$LOCAL/nprdma/" "$REMOTE:$NPRDMA_DIR/"

# 推送远程 sudo 脚本 (用户执行: 加载/重载内核模块; 模板在 scripts/remote/)
echo "[2/4] 推送远程 sudo 脚本 (symrdma_reload.sh)..."
push_remote_script "$REMOTE" "~/pro/symrdma/scripts/symrdma_reload.sh" \
	< "$LOCAL/scripts/remote/symrdma_reload.sh"
echo "  已推送 ~/pro/symrdma/scripts/symrdma_reload.sh"

# 编译 (合并为单次 ssh: 内核模块 + 测试 + nprdma 拦截库)
echo "[3/4] 远端增量编译 (内核模块 + 测试 + libnprdma)..."
# 审查实战教训 (2026-10-12 host-a/host-b): rsync -a 保留本地 mtime, 本地改
# 过的源在远端 mtime 可能早于上一轮编译的 .o → make 判定无需重编, 旧
# .o 照常链入 .ko (实测: 属主检查修复被静默吞掉)。源文件一律 touch 到
# 当前时间, 强制本轮全量重编 (模块/库文件数少, 代价可忽略)。
ssh_run "bash -c 'find $KERNEL_DIR $LIB_DIR $NPRDMA_DIR $SIR_DIR \
	$TEST_DIR -maxdepth 1 \\( -name \"*.c\" -o -name \"*.h\" \\) -exec touch {} +'" || true
ssh_run "bash -c '
set -e
cd $KERNEL_DIR && make -C /lib/modules/\$(uname -r)/build M=\$PWD modules
echo \"  → symrdma.ko OK\"
cd $LIB_DIR && make
echo \"  → libsymrdma.a OK\"
cd $TEST_DIR && make
echo \"  → 测试程序编译完成\"
cd $NPRDMA_DIR && make
echo \"  → libnprdma.so OK\"
'"

echo "[4/4] 完成"
echo "  特权命令 (可选): bash ~/pro/symrdma/scripts/symrdma_reload.sh [mode=1 pci_bdf=...]"
echo "  测试: REMOTE=$REMOTE bash tests/scripts/test.sh all"
