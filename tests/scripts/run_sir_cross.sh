#!/bin/bash
# run_sir_cross.sh — 双进程测试跨机会合验证 (L7/L10/L12/L13)
#
# v0.39.0: 引擎迁移至 Python (tests/scripts/symtest/, 见 symtest/README.md)。
# 入口契约不变: 参数 (7|10|12|13|all) / 环境变量 (SERVER_HOST/SERVER_IP/
# CLIENT_HOST/PORT/GID/SIR_DEBUG/OUT_DIR) / 退出码 (0 全绿, 1 有失败) /
# 输出 (results/sir_cross_<ts>.log)。
# v0.39.0 修正: SIR_DEBUG=1 现在真正接线为 SYMRDMA_SIR_DEBUG=1 (双端,
# 仅 L12/L13) — bash 版头注承诺但从未接线。
# 直接用引擎: python3 tests/scripts/symtest/__main__.py sir all
exec python3 "$(dirname "$0")/symtest/__main__.py" sir "$@"
