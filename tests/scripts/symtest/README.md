# symtest — 测试编排引擎（v0.39.0）

Bash 测试脚本的 Python 引擎。**入口契约（文件名 / 参数 / 环境变量 / 退出码）
与原 bash 版完全兼容** —— `test.sh` / `run_sir_cross.sh` /
`run_atomic_bench.sh` 是本引擎的瘦包装（`exec python3 …/symtest/__main__.py`），
所有既有文档、muscle memory、CI 调用不变。

```
python3 tests/scripts/symtest/__main__.py <cmd> [args]

  levels [levelN|N|6r|all] [--timeout T] [--list]   # test.sh 引擎
  sir [7|10|12|13|all] [--port P] [--sir-debug]      # run_sir_cross.sh 引擎
  atomic [--port P]                                  # run_atomic_bench.sh 引擎
  list                                               # 全部套件/单元一览

公共参数 (可在子命令前或后):
  --dry-run        只打印将执行的远端脚本 (不连接/不判定)
  --remote H       单机套件目标机 ($REMOTE)
  --out-dir DIR    产物目录 ($OUT_DIR, 默认 tests/results)
  --json [PATH]    manifest 输出 ("none" 关闭; $NO_JSON=1)
  -v               ssh 调用摘要
```

单元自测（无网络）：`python3 tests/scripts/symtest/selftest.py`

## 依赖与可选增强

**核心零第三方依赖** — Python ≥3.10（stdlib 即可运行全部套件）；远端只需
bash（引擎自己不部署到远端）。另有既有的画图依赖：`plot_nopf_bw.py`
需要 matplotlib（非 symtest 核心依赖）。

### 可选运行时增强（`requirements.txt`）

```bash
pip install -r tests/scripts/symtest/requirements.txt   # = rich + argcomplete
```

| 包 | 解锁什么 | 未装时 |
|---|---|---|
| **rich** | Level 汇总表带边框着色；长轮询单行进度（racebw 60min 等待不再静默 — bash 版已知体验缺口）；非 TTY（管道/文件）自动降级纯文本 | 纯文本列对齐表格（信息不变）+ 每 30s 一行轮询汇报 |
| **argcomplete** | CLI 补全：`symtest <TAB>` 补全子命令/参数 | 无补全 |

强制纯文本（CI/截图一致性/诊断）：`SYMTEST_PLAIN=1`。

argcomplete 需一次性 shell 注册（二选一）：

```bash
# bash（永久）:
echo 'eval "$(register-python-argcomplete python3)"' >> ~/.bashrc
# 或临时激活（当前 shell）:
eval "$(register-python-argcomplete python3)"
```

> 本机为 externally-managed Python（Arch 系）：用 venv 而非 pip --user ——
> `python3 -m venv ~/.venvs/symtest && ~/.venvs/symtest/bin/pip install -r
> tests/scripts/symtest/requirements.txt`，之后用 venv 的 python 调引擎，
> 或把 venv 的 site-packages 加入 PYTHONPATH。

### 开发质量工具（`requirements-dev.txt`，不影响运行）

```bash
pip install -r tests/scripts/symtest/requirements-dev.txt   # = pytest + ruff + mypy
pytest tests/scripts/symtest/selftest.py     # 单元自测（unittest 形态兼容, 直接收集）
ruff  check  tests/scripts/symtest/          # lint（含未用导入/不可达代码）
mypy tests/scripts/symtest/                  # 类型检查
```

### 刻意不引入（避免依赖膨胀/形态冲突）

- **paramiko / fabric / asyncssh**（SSH 库）：ssh 子进程形态是刻意设计 —
  交互式 sudo `-tt`（group_gates 密码提示）、`~/.ssh/config`（代理/跳板/
  认证流）全部透明兼容；SSH 库需自行复刻这些行为, 收益仅是“纯 Python”
  而 io 模型并未变快。
- **pandas**：CSV 摘要标准库足够（nopf_avg.py 形态）；引入 ~100MB 依赖
  换几行 groupby 不划算。
- **toml/yaml 配置层**：环境变量 + CLI 参数已是 bash 版契约，配置文件
  只会引入第二套真相源。

## 为什么迁移到 Python

Bash 版 15 个脚本 (~2500 行) 里沉淀了全部 shell 实测教训，
但每条都是**补丁式**规避 —— 语法陷阱本身还在，下一个脚本还会再踩。
Python 引擎把这些规则变成**结构性不可能**：

| bash 陷阱（历史教训） | symtest 的结构性保证 |
|---|---|
| ssh argv 拼接被远端 fish 重新解析/拆词（v0.24.5/v0.28.0/v0.29.1 三次实测） | 脚本**只走 stdin**（`ssh host bash -s`），值在本地 shlex.quote 注入脚本文本，远端零解析 |
| heredoc 转义地狱（`\$HOME` vs `$HOME`、unquoted heredoc 意外展开） | 脚本是 Python 字符串，`"$HOME"` 前缀显式双引号展开（`qh()`），无转义歧义 |
| pipefail × grep -q SIGPIPE 假阴性（v0.34.0） | 门禁是 Python 行计数，无管道无 SIGPIPE |
| PIPESTATUS[0] 退出码传播（grep/tee 吞码） | `subprocess.returncode` 直取 |
| `set -e` 穿透 `set +e`、`local rc` 掩盖 `$?`、子 shell 隔离 errexit（bash 5.3 实测） | 异常/返回值是语言结构，无 shell 语义坑 |
| stdbuf/timeout/pkill/孤儿清扫组合每个脚本重抄 | `SshHost`/`bg_start_script`/`run_level` 统一封装，一处修复全体生效 |
| 结果散在控制台 + grep 提取 CSV | 逐单元日志落盘 + JSON manifest（机器可读，CI/回归对比） |
| 双机预检/部署串行 | `run_parallel` 并行（deploy 编译是真实节省） |

同时保留**全部行为语义**：远端 `timeout -k 10` 自杀 + 本地外层超时 T+60、
`stdbuf -oL`、前后 `pkill -9 -f '[t]est_'` 孤儿清扫、哨兵金丝雀预检
（rc=2 中止）、QUIET 行过滤（只影响控制台，全量日志落盘）、退出码契约、
产物命名（`sir_cross_<ts>.log` / `atomicbench_<ts>.csv` …）。

## 模块结构

```
symtest/
├── __main__.py       # 直接执行入口 (sys.path 自举)
├── cli.py            # argparse 分发; 公共参数子命令前后均可; argcomplete 可选钩子
├── config.py         # 环境变量 + 双机拓扑 + 路径 (镜像 common.sh 契约)
├── ssh.py            # SSH 传输层: run_script(stdin→bash -s)/put/pkill/流式回调
│                     #   + Ctx (主机连接缓存) + q/qh (bash 引用)
├── remote.py         # 后台进程脚本构造器 (nohup+stdbuf+就绪等待) + 双机并行
├── deploy.py         # md5 新鲜度部署 + 按需编译 (CHECK_OK/COMPILE_OK 协议)
├── report.py         # Check/CaseRecord 门禁模型 + manifest + Tee + 彩色
├── ui.py             # 可选增强层 (rich 表格/进度, 优雅降级) — 依赖策略见 README
├── levels.py         # 单机 Level 套件 (test.sh 移植, L1-L20 注册表)
├── sir.py            # 跨机双进程套件 (run_sir_cross.sh 移植)
├── bench_atomic.py   # 原子基准 (run_atomic_bench.sh 移植)
├── selftest.py       # 单元自测 (FakeExec 注入, 51 用例; pytest 兼容)
├── requirements.txt        # 可选运行时增强 (rich/argcomplete)
└── requirements-dev.txt   # 开发质量工具 (pytest/ruff/mypy)
```

## 产物

- `results/levels_<ts>/`：`L<n>.log`（全量未过滤输出，**bash 版不落盘**）+
  `manifest.json`（环境 + 逐级 rc/耗时/门禁 + 总判定）
- `results/sir_cross_<ts>.log`（与 bash 同名兼容）+ `_manifest.json`
- `results/atomicbench_<ts>.log/.csv`（同名兼容）+ `_manifest.json`

manifest 示例：
```json
{"suite": "levels", "verdict": "PASS", "failed": [],
 "cases": [{"name": "L6", "rc": 0, "duration_s": 4.2,
            "checks": [{"name": "exit-code", "verdict": "PASS"}],
            "log": ".../L6.log"}]}
```

## 迁移状态 (v0.40.0 — 全部完成)

tests/scripts/ 下 **12 个测试套件全部由本引擎驱动**：每个 bash 脚本都是
瘦包装（`exec python3 …/symtest/__main__.py <cmd>`），参数/环境变量/退出码/
产物名兼容。真机验证（host-a/host-b）：levels all 双机 14/14、sir 双向 ×2、
atomic/racebw/nopf/nopf-pipeline/ctl/matrix/odp/reg/iotlb 门禁全绿且数值
与 v0.38 基线一致、investigate 取证正常；group-gates 因需交互 sudo 仅
dry-run 验证（真跑需管理员在终端执行）。

`scripts/` 侧（build.sh / ofed_push.sh 等构建部署脚本）保持 bash —— 它们
不是测试套件，且 common.sh 契约稳定。

迁移中沉淀的经验（新增脚本时仍适用）：

1. **远端命令一律 `host.run_script()`** —— 绝不把含空格/变量串放 ssh argv
   （fish 拆词）；绝不假设远端登录 shell 是 bash。
2. **后台进程必须 `</dev/null >log 2>&1`** —— 否则 ssh 因后台进程持有 std
   流而挂住；就绪判定前用 `stdbuf -oL` 启动（管道全缓冲假象）。
3. **长跑 client**：setsid 脱离 + exit 文件轮询（环境会杀长 SSH 会话 —
   kubelet 崩溃期/EDR）；本地外层超时只杀 ssh, 远端 timeout 自杀, pkill 兜底。
4. **新鲜度键**要包含**静态库**（racebw 教训：只比源码会用修复前旧库）；
   远端 build.sh 产物（.a/.so）用 `DeployUnit.hash_only` — 参与 hash 但
   绝不从本地推送（本地编译产物会污染远端）。
5. **门禁计数**用 `report.count_lines()`（无 SIGPIPE 假阴性），期望值随
   SKIP 模式分支（如 ODP 跳过 24→16）。
6. **`$HOME` 路径**经 `qh()` 注入 —— 远端 bash 展开；dry-run 显示与真实
   执行同一份脚本文本。
7. **每个 bench 的 CLI 形态先查 .c 头注**（npfbw 用 `-s` 旗标, racebw/atomic
   用位置参数 server/client — 首跑即挂的门禁几乎都是这类形态错配）。
