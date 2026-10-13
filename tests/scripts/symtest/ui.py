"""可选增强层 — rich 彩色表格/进度显示，未安装时优雅降级为纯文本。

依赖策略（见 symtest/README.md「依赖与可选增强」）：
  * symtest 核心**零第三方依赖**（stdlib 即可运行全部套件）；
  * rich 安装后自动启用：Level 汇总表、长轮询进度行（终端单行刷新）；
    非 TTY（管道/文件）时 rich 自动降级为纯文本 — 日志文件不受污染；
  * SYMTEST_PLAIN=1 强制纯文本（诊断/截图一致性/CI）；
  * 明确**不引入**：paramiko/fabric（ssh 子进程形态是刻意设计 — 交互
    sudo -tt、ssh_config、密钥/代理全兼容），pandas（csv 标准库足够）。

安装（可选）：
    pip install rich argcomplete      # 输出增强 + CLI 补全
    pip install pytest ruff mypy      # 开发质量工具
"""

from __future__ import annotations

import os
import sys
import time
from typing import Any


def _plain_mode() -> bool:
    return os.environ.get("SYMTEST_PLAIN") == "1"


_console: Any  # rich Console（可选依赖 — 未安装时为 None, 见 README 依赖策略）
try:
    if _plain_mode():
        raise ImportError  # 强制降级开关
    import rich.progress as _rp
    from rich.console import Console
    from rich.table import Table as _RichTable
    HAVE_RICH = True
    _console = Console()
except ImportError:
    HAVE_RICH = False
    _console = None



# ---- 表格 ----

def table(headers: list[str], rows: list[list[str]], *,
          title: str | None = None) -> None:
    """打印对齐表格：rich 可用时带边框/颜色，否则纯文本列对齐（与
    bash 版 printf %-Ns 输出同形态 — 降级不改变信息内容）。"""
    if HAVE_RICH and sys.stdout.isatty():
        t = _RichTable(title=title, header_style="bold cyan")
        for h in headers:
            t.add_column(h)
        for r in rows:
            t.add_row(*r)
        _console.print(t)
        return
    # 纯文本回退：按显示宽度对齐（CJK 记 2 列宽 — 与 bash printf 对 CJK 的
    # 近似一致, 不追求完美栅格, 保证不串行即可）
    def pad(s: str, w: int) -> str:
        return s + " " * max(0, w - _disp_len(s))

    widths = [_disp_len(h) for h in headers]
    for r in rows:
        for i, cell in enumerate(r):
            widths[i] = max(widths[i], _disp_len(str(cell)))
    if title:
        print(title)
    print("  ".join(pad(h, widths[i]) for i, h in enumerate(headers)))
    print("  ".join("-" * w for w in widths))
    for r in rows:
        print("  ".join(pad(str(c), widths[i]) for i, c in enumerate(r)))


def _disp_len(s: str) -> int:
    """显示宽度近似（CJK 记 2）— 纯文本对齐用。"""
    return sum(2 if ord(ch) > 0x2E80 else 1 for ch in s)


# ---- 长轮询进度 ----

class PollProgress:
    """长轮询进度显示（racebw 60min 等待 / iotlb 矩阵点）。

    rich: 终端单行刷新（spinner + 计数 + 已耗时）；
    回退: 每 report_every 秒打印一行（默认 30s — 覆盖"静默等待无法区分
    挂死"的问题，bash 版完全静默是已知体验缺口）。
    用法:
        with PollProgress("等待 client 完成", total=360, interval=10) as pb:
            for i in range(360):
                ...poll...
                pb.step(status="...")
    """

    def __init__(self, label: str, *, total: int, interval: float = 10.0,
                 report_every: float = 30.0):
        self.label = label
        self.total = total
        self.interval = interval
        self.report_every = report_every
        self.count = 0
        self._t0 = time.monotonic()
        self._last_report = 0.0
        self._ctx: Any = None
        self._task: Any = None

    def __enter__(self) -> PollProgress:
        if HAVE_RICH and sys.stdout.isatty():
            self._ctx = _rp.Progress(
                _rp.SpinnerColumn(),
                _rp.TextColumn("[bold]{task.fields[label]}"),
                _rp.MofNCompleteColumn(),
                _rp.TimeElapsedColumn(),
                _rp.TextColumn("{task.fields[status]}"),
                console=_console, transient=True)
            self._ctx.__enter__()
            self._task = self._ctx.add_task(
                "poll", total=self.total, label=self.label, status="")
        else:
            print(f"[..] {self.label} (最长 {self._nice_total()}，"
                  f"每 {self.report_every:.0f}s 汇报一次)")
        return self

    def step(self, status: str = "") -> None:
        self.count += 1
        elapsed = time.monotonic() - self._t0
        if self._ctx is not None:
            self._ctx.update(self._task, advance=1, status=status)
            self._ctx.refresh()
        elif elapsed - self._last_report >= self.report_every:
            self._last_report = elapsed
            print(f"[..] {self.label}: {self.count}/{self.total} "
                  f"({elapsed:.0f}s){(' — ' + status) if status else ''}")

    def done(self, status: str = "") -> None:
        if self._ctx is not None:
            self._ctx.update(self._task, completed=self.total, status=status)
            self._ctx.refresh()
        else:
            print(f"[ok] {self.label}: 完成 ({time.monotonic() - self._t0:.0f}s)"
                  f"{(' — ' + status) if status else ''}")

    def __exit__(self, *exc) -> None:
        if self._ctx is not None:
            self._ctx.__exit__(*exc)

    def _nice_total(self) -> str:
        secs = self.total * self.interval
        if secs >= 3600:
            return f"{secs // 3600:.0f}h{(secs % 3600) // 60:.0f}m"
        if secs >= 60:
            return f"{secs // 60:.0f}m{secs % 60:.0f}s"
        return f"{secs:.0f}s"
