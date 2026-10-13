#!/bin/bash
# test.sh — 远程运行验证测试 (无需 sudo, 我执行)
# 用法: bash tests/scripts/test.sh [level1|...|level20|level6r|all]  默认 all
# (单机 Level 全集; 双进程 Level L7/L10/L12/L13 见 run_sir_cross.sh)
#
# v0.39.0: 引擎迁移至 Python (tests/scripts/symtest/, 见 symtest/README.md)。
# 入口契约不变: 参数 (levelN|all) / 环境变量 (REMOTE/TEST_TIMEOUT/SSH_TIMEOUT)
# / 退出码 (0 全绿, 1 有失败, 2 哨兵污染中止; 单目标 = 该级退出码)。
# 新能力: 多目标 ("3 6 16") / --dry-run / --list / per-Level 日志与 JSON
# manifest 落盘 results/levels_<ts>/。
# 直接用引擎: python3 tests/scripts/symtest/__main__.py levels all
exec python3 "$(dirname "$0")/symtest/__main__.py" levels "$@"
