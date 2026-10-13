# SymRDMA 测试套件

> 测试相关内容的单一入口 (v0.24.2 重组)。主项目文档见
> [../README.md](../README.md)。

## 目录布局

```
tests/
├── README.md        # 本文件 — 测试入口
├── programs/        # L1–L20 功能/正确性测试程序 (Makefile + 20 个 .c + netcoord.h)
├── bench/           # 性能基准工具源码 (npfbw/npreg/atomicbench/ctlbench/racebw_bench
│                    #   + mlockall_shim.c)
├── diag/            # 环境诊断/取证工具 (diag_notifier / diag_sweep / notif_holder
│                    #   / npmapbench / racebw_repro + repro_probe/monitor)
├── scripts/         # 测试编排与基准脚本 (test.sh / nopf_pipeline.sh / run_matrix.sh ...)
│   └── symtest/     #   Python 编排引擎 v0.39.0 (test.sh 等三个脚本的内核 + 自测)
└── results/         # 测量产物 (gitignore: CSV/PNG/PDF/log; 新: manifest.json)
```

划分依据: **programs** 每轮回归跑 (功能正确性) / **bench** 出论文数字 (性能) /
**diag** 排障时才用 / **scripts** 人与 CI 调 / **results** 机器写。

## 快速开始

```bash
# 功能回归 — 单机 Level 全集 (L1-L6/6r/L8/L9/L11/L14/L16/L19/L20; 双机各跑一遍)
# L15 Phase A ODP 对照 >10min 单独跑
REMOTE=host-a bash tests/scripts/test.sh all
TEST_TIMEOUT=900 bash tests/scripts/test.sh level15
# 多目标 / 空跑 / 列表 (v0.39.0 Python 引擎新增, 入口契约不变):
REMOTE=host-a bash tests/scripts/test.sh 3 6 16      # 多目标
bash tests/scripts/test.sh --dry-run all                # 只打印远端脚本
bash tests/scripts/test.sh --list                       # Level 一览

# 双进程 Level 跨机套件 (L7 SIR / L10 原子 / L12 自动修复 / L13 透明引擎)
# server@$SERVER_HOST ← client@$CLIENT_HOST; 双向各跑一遍覆盖两机角色
bash tests/scripts/run_sir_cross.sh all
SERVER_HOST=host-a SERVER_IP=192.168.1.2 CLIENT_HOST=host-b \
	bash tests/scripts/run_sir_cross.sh all

# 原子基准 (论文 §5.2.4 Fig 14; v0.39.0 Python 引擎)
bash tests/scripts/run_atomic_bench.sh

# L15 Phase B 跨机 ODP 对照 (v0.29.2 全 4 尺寸闭环, 也可 SIZES= 单尺寸)
bash tests/scripts/run_odp_compare.sh

# 控制面开销基准 (论文 Tables 1/2, v0.34.0; 每机 vanilla+sym 两相位)
bash tests/scripts/run_ctl_bench.sh

# no-PF 性能全流水线: 预检 → 构建 × 2 机 → 3 轮基准 → 平均 → 出图 → 回归对比
bash tests/scripts/nopf_pipeline.sh

# 单独能力
bash tests/scripts/run_matrix.sh                # 原版 vs SymRDMA 性能矩阵
python3 tests/scripts/plot_nopf_bw.py           # 重画最新 CSV
```

## 脚本协作关系

**v0.40.0 起 tests/scripts/ 全部 12 个测试套件由 Python 引擎
`scripts/symtest/` 驱动**，每个 .sh 都是瘦包装（入口/环境变量/退出码/产物名
全兼容）。引擎文档: [scripts/symtest/README.md](scripts/symtest/README.md)；
单元自测: `python3 tests/scripts/symtest/selftest.py`（64 用例, pytest 兼容）。
可选增强（rich 表格/进度、argcomplete 补全、matplotlib 出图）见
symtest/README.md「依赖与可选增强」。远端 sudo 脚本模板仍在
`scripts/remote/`（构建侧 build.sh 等保持 bash）。

```
nopf_pipeline.sh ──┬─ build.sh (../../scripts, 同步+编译 × 2 机)
                   ├─ run_nopf_bw.sh ── npfbw_bench (bench/, 推远端 /tmp 编译)
                   ├─ nopf_avg.py (多轮平均 + 线速区回归判定)
                   └─ plot_nopf_bw.py (size 横轴 / 带宽纵轴, 裸 vs SymRDMA)
run_ctl_bench.sh ── ctlbench (bench/, 推远端 /tmp 编译; 每机 vanilla+sym,
                    论文 Tables 1/2; v0.34.0)
test.sh ─(symtest levels)─ 单机 Level 逐级/全量 (远端 make 产物直接跑;
                    逐级日志+manifest 落盘 results/levels_<ts>/)
run_sir_cross.sh ─(symtest sir)─ 双进程 Level 跨机套件 (L7/L10/L12/L13,
                    netcoord.h 参数/事件 TCP 协调 + 库层 SYMRDMA_SIR_TCP)
run_atomic_bench.sh ─(symtest atomic)─ 原子基准双机 (bench/ 推 /tmp 编译,
                    论文 Fig 14; v0.39.0)
# 其余 9 套件同为 symtest 瘦包装 (v0.40.0, 引擎单元在 symtest/):
#   bench_racebw / bench_nopf / pipeline_nopf / bench_ctl / bench_iotlb /
#   bench_matrix / bench_odp / bench_reg / gates_group / diag_invalidate
```

> 双进程 Level 仅保留跨机形态 (v0.33.0): 真实网络 QP (对端 GID/动态 MTU)
> 是同机 loopback 形态的严格超集, 同机双进程形态已从套件删除。单机机制
> 验证 (IOMMU/notifier/swap/MTT/拦截/竞态) 仍由 test.sh 在每台机器上覆盖。

## 本地 vs 远端布局 (重要)

本地 (git 仓库, 分类目录) 与远端部署机 (扁平) 的映射:

| 本地 | 远端 (host-a/host-b) | 说明 |
|------|-------------------|------|
| `tests/programs/*.c` + `Makefile` | `~/pro/symrdma/test/` | build.sh 平铺 rsync; 远端 `make` 产物就在此 |
| `tests/diag/*.c` | `~/pro/symrdma/test/` (平铺) | 同上 |
| `tests/bench/*.c` | `/tmp/` (按需编译) | run_nopf_bw.sh / run_ctl_bench.sh 推送 |
| `tests/scripts/*` | 不同步 (本地发起) | ssh 远端执行 |
| `lib/`, `sir/`, `kernel/`, `nprdma/` | `~/pro/symrdma/{lib,sir,kernel,nprdma}` | 一一对应 |

`tests/programs/Makefile` 的 `LIBDIR` 自适应两种布局 (按 `libsymrdma.h`
存在位置判定): 本地两层深 (`../../lib`), 远端一层深 (`../lib`)。

## 文档

- 测试方法与断言、生效门禁、性能基线与论文数字复现对照由各测试程序
  自带注释与脚本头注承载（本仓库不单独维护测试详录文档）
- 立项期复现/验证计划已清理 (见 git 历史; 复现对照由各基准脚本维护)
