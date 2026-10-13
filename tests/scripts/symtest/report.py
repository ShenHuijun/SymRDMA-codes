"""结果报告 — 门禁模型 / 运行记录 / 彩色控制台 / JSON manifest / tee 日志。

bash 版散落在各脚本里的判定（grep -c 计数、PIPESTATUS 退出码、tee -a
落盘、汇总 printf 表）统一到这里：
  * Check   —— 一条门禁判定（ok / warn / detail）；
  * CaseRecord —— 一个测试单元的结果（rc、耗时、门禁列表、日志路径）；
  * manifest.json —— 机器可读的运行清单（环境 + 逐单元结果 + 总判定），
    供 CI / 回归对比 / 事后取证；
  * Tee     —— bash `2>&1 | tee -a log` 的等价物（行粒度双写）。
"""

from __future__ import annotations

import json
import os
import re
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path


# ---- 控制台 ----
class Con:
    """TTY 彩色输出（NO_COLOR / 非 TTY 自动降级）。"""

    _on = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

    @classmethod
    def _c(cls, code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if cls._on else s

    @classmethod
    def ok(cls, s: str) -> str:
        return cls._c("32", s)

    @classmethod
    def err(cls, s: str) -> str:
        return cls._c("31", s)

    @classmethod
    def warn(cls, s: str) -> str:
        return cls._c("33", s)

    @classmethod
    def info(cls, s: str) -> str:
        return cls._c("36", s)

    @classmethod
    def dim(cls, s: str) -> str:
        return cls._c("2", s)

    @classmethod
    def bold(cls, s: str) -> str:
        return cls._c("1", s)


# ---- 门禁 ----
@dataclass
class Check:
    """一条门禁判定。warn=True 的检查失败只降级为 warning，不计失败。"""

    name: str
    ok: bool
    detail: str = ""
    warn: bool = False

    @property
    def verdict(self) -> str:
        if self.ok:
            return "PASS"
        return "WARN" if self.warn else "FAIL"


@dataclass
class CaseRecord:
    name: str
    display: str = ""
    rc: int = 0
    duration: float = 0.0
    timed_out: bool = False
    checks: list[Check] = field(default_factory=list)
    log: str | None = None

    @property
    def ok(self) -> bool:
        return all(c.ok or c.warn for c in self.checks)

    @property
    def failed_checks(self) -> list[Check]:
        return [c for c in self.checks if not (c.ok or c.warn)]


def count_lines(text: str, pattern: str) -> int:
    """按行首正则/子串计数（grep -c 的 Python 等价，无 SIGPIPE 假阴性）。"""
    rx = re.compile(pattern)
    return sum(1 for line in text.splitlines() if rx.search(line))


def has_line(text: str, pattern: str) -> bool:
    rx = re.compile(pattern)
    return any(rx.search(line) for line in text.splitlines())


# ---- manifest ----
def write_manifest(path: str | Path, *, suite: str, meta: dict,
                   cases: list[CaseRecord], verdict: str,
                   failed: list[str], started: float, duration: float) -> Path:
    data = {
        "suite": suite,
        "verdict": verdict,
        "failed": failed,
        "started": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(started)),
        "duration_s": round(duration, 1),
        "meta": meta,
        "cases": [
            {
                "name": c.name,
                "display": c.display,
                "rc": c.rc,
                "timed_out": c.timed_out,
                "duration_s": round(c.duration, 1),
                "log": c.log,
                "checks": [
                    {"name": k.name, "verdict": k.verdict, "detail": k.detail}
                    for k in c.checks
                ],
            }
            for c in cases
        ],
    }
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n",
                 encoding="utf-8")
    return p


# ---- tee 日志（bash `2>&1 | tee -a` 等价）----
class Tee:
    """控制台 + 文件双写。emit() 接受流式行（可能带换行）或普通消息。"""

    def __init__(self, path: str | Path | None):
        self._f = open(path, "a", encoding="utf-8", errors="replace") if path else None

    def emit(self, line: str = "") -> None:
        s = line.rstrip("\n")
        print(s)
        if self._f:
            self._f.write(s + "\n")

    def close(self) -> None:
        if self._f:
            self._f.close()
            self._f = None

    def __enter__(self) -> Tee:
        return self

    def __exit__(self, *exc) -> None:
        self.close()
