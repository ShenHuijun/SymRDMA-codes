# Makefile for SymRDMA test programs
#
# Build: make

CC       = gcc
CFLAGS  := -O2 -Wall -Wextra
LDFLAGS :=

# lib 路径自适应 (v0.24.2): 本地 tests/programs/ 两层深 (../../lib);
# 远端部署 ~/pro/symrdma/test/ 一层深 (../lib)。以 libsymrdma.h 存在位置判定
# (该头文件 git 跟踪/同步, 与构建状态无关, 双布局均确定)
ifneq ($(wildcard ../../lib/libsymrdma.h),)
  LIBDIR := ../../lib
else
  LIBDIR := ../lib
endif

# SIR 通道头文件 (v0.24.3: sir/ 独立目录) — 同样双布局自适应:
# 本地 tests/programs/ 两层深 (../../sir); 远端部署 ~/pro/symrdma/test/ 一层深 (../sir)
ifneq ($(wildcard ../../sir/sir.h),)
  SIRDIR := ../../sir
else
  SIRDIR := ../sir
endif

# nprdma 引擎源码 (v0.38.2 L20 白盒直含) — 双布局同上。白盒 include
# 的编译单元必须列为依赖: 引擎改动时重编, 否则陈旧二进制假绿
# (历史教训: 只比源码会用修复前的旧库)
ifneq ($(wildcard ../../nprdma/nprdma_engine.c),)
  NPRDIR := ../../nprdma
else
  NPRDIR := ../nprdma
endif

# IOMMU level verification (always built)
TARGETS := test_iommu_verify

# RDMA verification (requires libibverbs)
# 使用 OFED 5.8 (/usr/local, 与论文一致) — pkg-config 已正确指向
HAVE_IBVERBS := $(shell pkg-config --exists libibverbs 2>/dev/null && echo 1 || echo 0)
ifeq ($(HAVE_IBVERBS),1)
    IBV_CFLAGS  = $(shell pkg-config --cflags libibverbs)
    IBV_LDFLAGS = $(shell pkg-config --libs libibverbs)
else
    IBV_CFLAGS  = -I/usr/local/include
    IBV_LDFLAGS = -L/usr/local/lib -libverbs -ldl -lpthread
endif
TARGETS += test_rdma_verify test_swapout test_auto_repair test_rdma_write test_nprdma test_sir test_nopin test_fault_sweep test_atomic test_error_combos test_auto_sir test_transparent_read test_race_stress test_odp_compare
# v0.24.2: diag_notifier/notif_holder 源码在本地 tests/diag/, build.sh 将
# tests/{programs,diag,bench} 平铺同步到远端 TEST_DIR — 本 Makefile 为
# 远端扁平布局的一级形态 (本地 make 仅 programs 内目标可直接用)
# 环境诊断也纳入 all (注意: 规则必须在 all: 目标之后 — 否则 make 默认目标
# 变成它, 裸 make 只检查该目标而静默跳过整个套件编译, 2026-09-15 实测)
TARGETS += diag_notifier notif_holder

# R2 (v0.29.0): 哨兵扫描原语相位单测 (纯 CPU, 无 RDMA/ibverbs;
# REFACTOR 第 2 批门禁 "相位专项单测" — 等价性 oracle 见程序内注释)
TARGETS += test_sentinel_phase

# v0.38.0 (L19 B 轴): IOMMU 组粒度映射微基准驱动 (cmd 12) — 无 ibverbs 依赖
TARGETS += npmapbench

# v0.38.0 (L19): 组粒度映射验证 (Phase 2 门禁) — REPAIR_RANGE (cmd 11)
# 与 demote_fail_grp 注入形态; 纯 ioctl 无库依赖
TARGETS += test_group_mapping

# v0.38.2 (L20): 引擎 scratch 锁纪律白盒单测 (P1-2 回归) — 白盒直含
# nprdma_engine.c (static 触达), 纯 CPU 无 RDMA; 链接 -ldl/-lpthread
# (verbs 头经 IBV_CFLAGS, 不链接 libibverbs — 引擎经函数指针/桩)
TARGETS += test_engine_scratch

# libsymrdma 静态库现含 sir.o (sir/sir.c): dlsym + pthread;
# test_auto_sir 另直接 include sir/sir.h (SIRDIR 自适应见上)
LDLIBS_SYM = $(IBV_LDFLAGS) -lpthread -ldl

.PHONY: all clean

all: $(TARGETS)

$(LIBDIR)/libsymrdma.a: $(LIBDIR)/libsymrdma.c $(LIBDIR)/libsymrdma.h \
		$(LIBDIR)/libsymrdma_internal.h $(SIRDIR)/sir.c $(SIRDIR)/sir_channel.c \
		$(SIRDIR)/sir_service.c $(SIRDIR)/sir.h $(SIRDIR)/sir_internal.h
	$(MAKE) -C $(LIBDIR)

test_iommu_verify: test_iommu_verify.c
	$(CC) $(CFLAGS) -o $@ $<

test_rdma_verify: test_rdma_verify.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -o $@ $< $(IBV_LDFLAGS)

test_swapout: test_swapout.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -o $@ $< $(IBV_LDFLAGS)

test_auto_repair: test_auto_repair.c $(LIBDIR)/libsymrdma.a
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I$(LIBDIR) -o $@ $< $(LIBDIR)/libsymrdma.a $(LDLIBS_SYM)

test_rdma_write: test_rdma_write.c $(LIBDIR)/libsymrdma.a
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I$(LIBDIR) -o $@ $< $(LIBDIR)/libsymrdma.a $(LDLIBS_SYM)

# Level 6: 普通应用 (不链接 libsymrdma — 验证 LD_PRELOAD 透明拦截)
test_nprdma: test_nprdma.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -o $@ $< $(IBV_LDFLAGS)

# Level 7: 双进程 Server-Initiated Repair (自包含 ioctl, 不链 libsymrdma)
test_sir: test_sir.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -o $@ $< $(IBV_LDFLAGS)

# Level 8: no-pin 注册验证 (VmLocked 不增长 + 换出 RSS 下降)
test_nopin: test_nopin.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -o $@ $< $(IBV_LDFLAGS)

# Level 9: 故障比例扫描实验 (论文 §5.2.1 故障成本曲线, 审稿人 Q4)
test_fault_sweep: test_fault_sweep.c $(LIBDIR)/libsymrdma.a
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I$(LIBDIR) -o $@ $< $(LIBDIR)/libsymrdma.a $(LDLIBS_SYM)

# Level 10: 非 pin 原子 (论文 §3.4, 双进程, 自包含 ioctl)
test_atomic: test_atomic.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -o $@ $< $(IBV_LDFLAGS)

# Level 11: 错误处理工具 (论文 §4.1, 并发控制面/数据面组合 + 进程退出清理)
test_error_combos: test_error_combos.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -o $@ $< $(IBV_LDFLAGS) -lpthread

# Level 12-A: 库内建自动双向修复 (v0.18.0, 双进程; 透明 API, 零 SIR 代码)
test_auto_sir: test_auto_sir.c $(LIBDIR)/libsymrdma.a
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I$(LIBDIR) -I$(SIRDIR) -o $@ $< $(LIBDIR)/libsymrdma.a $(LDLIBS_SYM)

# Level 12-B: libnprdma 透明引擎 (纯 verbs, 零 SymRDMA 代码; LD_PRELOAD 运行)
test_transparent_read: test_transparent_read.c
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -o $@ $< $(IBV_LDFLAGS)

# Level 14: 并发缺页竞态压测 (多线程 reader/writer + swapper 对抗, 论文 §3.1)
test_race_stress: test_race_stress.c $(LIBDIR)/libsymrdma.a
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I$(LIBDIR) -o $@ $< $(LIBDIR)/libsymrdma.a $(LDLIBS_SYM)

# Level 15: ODP 同机对照 (论文 §5.2.1/A.7; local 单机 / server+client 跨机)
test_odp_compare: test_odp_compare.c $(LIBDIR)/libsymrdma.a
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I$(LIBDIR) -o $@ $< $(LIBDIR)/libsymrdma.a $(LDLIBS_SYM)

# R2 (v0.29.0): 哨兵相位单测 — 仅头文件原语, 不链 libsymrdma.a/ibverbs
test_sentinel_phase: test_sentinel_phase.c $(SIRDIR)/sentinel.h $(SIRDIR)/vtpages.h
	$(CC) $(CFLAGS) -I$(SIRDIR) -o $@ $<

# v0.38.2 (L20): 引擎 scratch 锁纪律白盒单测 (P1-2) — 引擎编译单元直含
# (include 路径双布局在源内 __has_include 判定; 引擎符号函数指针/桩,
# 不链 libibverbs; sir.h 需 SIRDIR include)
test_engine_scratch: test_engine_scratch.c $(SIRDIR)/sir.h \
		$(NPRDIR)/nprdma_engine.c $(NPRDIR)/nprdma_internal.h
	$(CC) $(CFLAGS) $(IBV_CFLAGS) -I$(SIRDIR) -o $@ $< -ldl -lpthread

clean:
	rm -f $(TARGETS)

# v0.38.0 (L19 B 轴): 组粒度映射微基准 — 纯 ioctl, 无库依赖
npmapbench: npmapbench.c
	$(CC) $(CFLAGS) -o $@ $<

# v0.38.0 (L19): 组粒度映射验证 (Phase 2 门禁) — 纯 ioctl, 无库依赖
test_group_mapping: test_group_mapping.c
	$(CC) $(CFLAGS) -o $@ $<

# 环境诊断: MMU notifier 触发矩阵 (PAGEOUT/DONTNEED/COLD) + 哨兵页污染检测
diag_notifier: diag_notifier.c
	$(CC) $(CFLAGS) -o $@ $<

# 外部页失效源调查诱饵: 常驻 MR 持有者 (v0.23.1)
notif_holder: notif_holder.c
	$(CC) $(CFLAGS) -o $@ $<
