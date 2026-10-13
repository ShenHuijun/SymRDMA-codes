"""SymRDMA 测试编排框架 (v0.39.0)。

Bash 测试脚本的 Python 引擎。入口契约（文件名 / 参数 / 环境变量 / 退出码）
与原 bash 脚本完全兼容 —— test.sh / run_sir_cross.sh / run_atomic_bench.sh
均为本引擎的瘦包装，也可直接调用：

    python3 tests/scripts/symtest/__main__.py levels all
    python3 tests/scripts/symtest/__main__.py sir 7
    python3 tests/scripts/symtest/__main__.py atomic
    python3 tests/scripts/symtest/__main__.py list

设计文档与移植指南：tests/scripts/symtest/README.md
单元自测（无需网络）：python3 tests/scripts/symtest/selftest.py
"""

__version__ = "0.39.0"
