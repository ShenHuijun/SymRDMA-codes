"""配置 — 环境变量 + 双机拓扑 + 路径（镜像 scripts/common.sh 的契约）。

所有默认值与 common.sh 一致；环境变量可覆盖；CLI 参数优先于环境变量。
远端路径一律以 "$HOME" 前缀书写，在远端 bash -s 脚本内展开（脚本经
stdin 传输，不经远端 fish 解析，见 ssh.py 头注）。
"""

from __future__ import annotations

import os
from pathlib import Path


def env(name: str, default: str | None = None) -> str:
    """读环境变量；空串视为未设置（与 bash ${VAR:-def} 语义一致）。"""
    v = os.environ.get(name)
    return v if v not in (None, "") else (default if default is not None else "")


def port_for(suite_default: int) -> int:
    """PORT 环境变量覆盖（各套件默认端口不同但共用同一变量名，与 bash 一致）。"""
    try:
        return int(env("PORT", str(suite_default)))
    except ValueError:
        return suite_default


# ---- 单机套件 (levels) 目标机 ----
REMOTE_DEFAULT = env("REMOTE", "host-a")
SSH_TIMEOUT_DEFAULT = int(env("SSH_TIMEOUT", "10"))
TEST_TIMEOUT_DEFAULT = int(env("TEST_TIMEOUT", "180"))

# ---- 双机拓扑 (sir / atomic / bench 类脚本共用) ----
# 拓扑参数 (SERVER_IP/DEV/GID) 须由使用者经 testbed.env 配置;
# GID 应按 ibv_devinfo 固定 RoCE v2 GID index。
SERVER_HOST_DEFAULT = env("SERVER_HOST", "host-b")
SERVER_IP_DEFAULT = env("SERVER_IP", "")   # 必填 (testbed.env)
CLIENT_HOST_DEFAULT = env("CLIENT_HOST", "host-a")
DEV_DEFAULT = env("DEV", "")
GID_DEFAULT = env("GID", "")

# ---- 端口默认值 ----
SIR_PORT_DEFAULT = 18721        # sir: PORT = 库层 SIR 会合, PORT+1 = netcoord 协调
ATOMIC_PORT_DEFAULT = 18716
SIR_CLIENT_TIMEOUT_DEFAULT = int(env("SIR_CLIENT_TIMEOUT", "150"))

# ---- 调试开关 ----
SIR_DEBUG_DEFAULT = env("SIR_DEBUG", "0") == "1"

# ---- 本地路径 (symtest/ → tests/scripts/ → tests/ → 仓库根) ----
PKG_DIR = Path(__file__).resolve().parent
REPO = PKG_DIR.parent.parent.parent
PROGRAMS_SRC = REPO / "tests" / "programs"
BENCH_SRC = REPO / "tests" / "bench"
RESULTS_DIR = REPO / "tests" / "results"

# ---- 远端路径（"$HOME" 在远端 bash 内展开）----
TEST_DIR = "$HOME/pro/symrdma/test"                    # build.sh 部署的测试二进制目录
LIBNPRDMA = "$HOME/pro/symrdma/nprdma/libnprdma.so"    # LD_PRELOAD 透明拦截库

# ---- 输出过滤（test.sh QUIET 契约：SSH 噪声 + 库内部哨兵调试行）----
# 子串匹配（与 grep -E 的字面量分支等价），只影响控制台显示，全量日志仍落盘。
QUIET_SUBSTRINGS = (
    "libibverbs: Warning",
    "WARNING",
    "store now",
    "pq.html",
    "node:",
    "[libsymrdma] sentinel:",
)


def timestamp() -> str:
    import time

    return time.strftime("%Y%m%d_%H%M%S")
