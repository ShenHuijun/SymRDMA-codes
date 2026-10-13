#!/bin/bash
# run_atomic_bench.sh — 原子操作基准双机编排 (论文 §5.2.4 Fig 14, TESTING §7.2)
#
# v0.39.0: 引擎迁移至 Python (tests/scripts/symtest/, 见 symtest/README.md)。
# 入口契约不变: 环境变量 (SERVER_HOST/SERVER_IP/CLIENT_HOST/PORT/GID/DEV/
# OUT_DIR) / 退出码 (0 全绿, 1 有 FAIL, 2=ODP 跳过带 warning 通过) /
# 输出 (results/atomicbench_<ts>.log + .csv)。
# 新能力: 双机预检/部署并行 + JSON manifest。
# 直接用引擎: python3 tests/scripts/symtest/__main__.py atomic
exec python3 "$(dirname "$0")/symtest/__main__.py" atomic "$@"
