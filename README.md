# SymRDMA

实验项目：RDMA one-sided 读写保护机制（SymRDMA）的实现与测试。

**核心机制**: 通过 IOMMU 将非驻留页面的 DMA 访问重定向到哨兵/黑洞页，配合 MTT identity mapping，实现 unpinned 应用内存上的乐观 one-sided RDMA，替代传统 MR 注册的内存 pinning。

## 环境要求

两台配置好的机器即可复现，下文以 **host-a / host-b** 称呼：

- 基线内核 **5.11**（其它版本未验证）
- IOMMU 翻译模式：`intel_iommu=on`（**非** `iommu=pt`）+ `iommu.strict=1`
- OFED 5.8 全套内核模块 + 本仓库补丁（见 [ofed/patches/README.md](ofed/patches/README.md)）：
  `identity_mtt=0`(按 MR 选择性) + `identity_mtt_write_offset=32GB` +
  `identity_mtt_log_pgsize=31`(2GB MTT 大页, 论文 §4.2)
- swap 空间（Level 3+ 需要）; memlock rlimit unlimited（基准类需要）
- 两机各一块 Mellanox RDMA 网卡（mlx5 驱动），直连或经交换机互通；开发
  账号免密 ssh，特权操作由机器管理员经 `scripts/remote/` 模板执行

## 双机拓扑配置（testbed.env）

仓库约定两台机器的 SSH 别名（在 `~/.ssh/config` 中配置）为
`host-a`（client / 单机套件默认目标）与 `host-b`（server）：

```bash
cp testbed.env.example testbed.env   # 已 gitignore; 填 SERVER_IP / PCI_BDF 等
```

`scripts/` 下所有脚本会自动 source `testbed.env`（命令行/环境变量优先级更高）。

## 构建与部署

工作流分工：无 sudo 脚本由开发侧执行，特权脚本由机器管理员在远端执行。
**一律使用辅助脚本完成同步/编译/测试**，**不要手工 rsync**。
远端部署布局约定：仓库同步到远端 `~/pro/symrdma/`。

```bash
# 1. 同步 + 编译模块/测试/libnprdma（本地）—— 每次改代码后先跑这个
bash scripts/build.sh

# 2. 加载/重载内核模块（远端含 sudo; 首次部署见下方「OFED 部署」）
#    PCI_BDF 从 testbed.env 读取 (PCI_BDF_HOST_A/PCI_BDF_HOST_B)
ssh host-a 'bash ~/pro/symrdma/scripts/symrdma_reload.sh mode=1 pci_bdf=$PCI_BDF_HOST_A'
ssh host-b 'bash ~/pro/symrdma/scripts/symrdma_reload.sh mode=1 pci_bdf=$PCI_BDF_HOST_B'

# 3. 运行验证（见下节「测试套件」）
```

OFED 补丁部署 / 变更后：

```bash
bash scripts/ofed_push.sh                 # 推送补丁源码 + 远端编译（本地）
bash ~/pro/symrdma/scripts/update_mlx5.sh      # 安装 + 重载全栈（远端, sudo）
```

## 测试套件

全部 12 个测试套件由 `tests/scripts/symtest/` Python 引擎驱动
（[引擎文档](tests/scripts/symtest/README.md)），每个 .sh 是瘦包装。
测试程序目录：`tests/programs/`（功能回归）/ `tests/bench/`（性能基准）/
`tests/diag/`（诊断）。

```bash
# ---- 功能回归: 单机 Level 全集 (L1–L6/6r/L8/L9/L11/L14/L16/L19/L20, 双机各跑) ----
REMOTE=host-a bash tests/scripts/test.sh all
REMOTE=host-b bash tests/scripts/test.sh all
bash tests/scripts/test.sh --list                 # Level 一览
bash tests/scripts/test.sh --dry-run all          # 空跑

# ---- 双进程 Level 跨机套件 (L7 SIR / L10 原子 / L12 自动修复 / L13 透明引擎) ----
bash tests/scripts/run_sir_cross.sh all           # 正向
SERVER_HOST=host-a SERVER_IP=<host-b 的 RDMA IP> CLIENT_HOST=host-b \
	bash tests/scripts/run_sir_cross.sh all        # 反向 (覆盖两机角色)

# ---- 论文性能复现基准 ----
bash tests/scripts/nopf_pipeline.sh               # Fig 13(b): 预检→构建→3 轮→平均→出图→回归对比
bash tests/scripts/run_racebw.sh                  # Fig 12: race 吞吐 (sym/odp × minor/major × 2B..4M)
bash tests/scripts/run_atomic_bench.sh            # Fig 14: 原子操作
bash tests/scripts/run_ctl_bench.sh               # Tables 1/2: 控制面开销
bash tests/scripts/run_odp_compare.sh             # Fig 11: ODP 对照 (L15)
bash tests/scripts/run_matrix.sh                  # 原版 vs SymRDMA 性能矩阵
bash tests/scripts/run_reg_bench.sh               # MR 注册规模
bash tests/scripts/run_group_gates.sh             # 组粒度映射门禁 (需交互 sudo)

# ---- 诊断 ----
bash tests/scripts/investigate_invalidation.sh    # 外部页失效源调查
```

基准 CSV/PNG 产物落在 `tests/results/`（gitignore）。

## 应用形态（远端，任意未修改的 RDMA 程序透明获得保护）

```bash
# 默认 flag 模式: 仅显式带 NPRDMA_MR_SYMRDMA (1<<21) 位的 MR 转 SymRDMA, 其余纯透传 (preload 可常驻)
env LD_PRELOAD=~/pro/symrdma/nprdma/libnprdma.so ./app
# 全拦截模式 (未修改应用透明获得 SymRDMA, perftest 等):
env NPRDMA_INTERCEPT=all LD_PRELOAD=~/pro/symrdma/nprdma/libnprdma.so ./your_app
```
