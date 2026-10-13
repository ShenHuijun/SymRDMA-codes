#!/bin/bash
# run_group_gates.sh — v0.40.0 起为 symtest Python 引擎瘦包装 (入口/环境变量/退出码兼容)
# 引擎文档: tests/scripts/symtest/README.md
exec python3 "$(dirname "$0")/symtest/__main__.py" group-gates "$@"
