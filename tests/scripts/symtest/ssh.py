"""SSH 传输层 — 一切远端命令经 `ssh <host> bash -s` 脚本走 stdin。

本模块把 ssh.py 头注 里用血泪换来的 shell 规则固化为结构性保证：

  * 远端登录 shell 是 fish —— 脚本**永不经 ssh argv 传输**（argv 会被
    ssh 以空格拼接后交 fish 重新解析、引号丢失、含空格串被拆词，
    v0.24.5/v0.28.0/v0.29.1 三次实测教训），而是整段脚本经 stdin 喂给
    `bash -s`。bash -s 的命令行只有 "bash -s"，不含脚本内容 → fish
    永远看不到脚本文本。
  * 需要注入的值（端口/IP/路径/含空格串）在本地拼进脚本文本并经
    shlex.quote 引用 —— 引号语义由本地 Python 唯一决定，远端零解析。
  * "$HOME" 前缀路径在远端 bash 双引号内展开（原 bash 版 heredoc 里
    \\$HOME 转义的等价物，但不再有转义地狱）。
  * 流式输出走行回调（QUIET 过滤 + 控制台 + 落盘），bash 管道
    PIPESTATUS/SIGPIPE 假阴性（v0.34.0 ctlbench 教训）结构性消失。
  * 超时分层：远端内层 `timeout -k` 让进程自杀（本地 timeout 只杀 ssh，
    远端进程会变孤儿继续持有模块引用），本地外层超时仅作
    兜底；两层职责与 test.sh v0.21.x 加固一致。

退出码语义：run_script 返回的 rc = 远端脚本退出码（经 ssh 原样传播，
等价于 bash 的 PIPESTATUS[0]）。本地外层超时被杀时 rc 规整为 124 并置
timed_out=True。
"""

from __future__ import annotations

import contextlib
import shlex
import subprocess
import threading
from dataclasses import dataclass


@dataclass
class RunResult:
    rc: int = 0
    text: str = ""
    timed_out: bool = False


def q(v: str) -> str:
    """bash 字面量引用（值在远端不展开）。"""
    return shlex.quote(v)


def qh(v: str) -> str:
    """bash 引用，但保留 "$HOME" 前缀在远端展开（双引号拼接）。

    qh('$HOME/pro/symrdma/x')  →  '"$HOME"/pro/symrdma/x'
    qh('普通值')          →  shlex.quote
    """
    if v.startswith("$HOME"):
        return '"$HOME"' + shlex.quote(v[len("$HOME"):])
    return shlex.quote(v)


def _real_exec(argv: list[str], script: str | None, timeout: float | None,
               on_line=None) -> RunResult:
    """真实执行：Popen + 可选行回调 + 定时器看门狗。

    script 经 stdin 传给远端 bash -s；stdout/stderr 合流（对应远端 2>&1）。
    on_line 不为 None 时流式逐行回调（text 为空）；否则全量捕获到 text。
    """
    try:
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE if script is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except FileNotFoundError as e:
        return RunResult(rc=255, text=f"本地无法启动 ssh: {e}")
    except OSError as e:
        return RunResult(rc=255, text=f"本地 ssh 启动失败: {e}")

    timed_out = False
    timer: threading.Timer | None = None
    if timeout is not None and timeout > 0:
        def _kill() -> None:
            nonlocal timed_out
            timed_out = True
            # 只杀本地 ssh；远端由内层 timeout 自杀
            with contextlib.suppress(OSError):
                proc.kill()
        timer = threading.Timer(timeout, _kill)
        timer.daemon = True
        timer.start()

    parts: list[str] = []
    try:
        if script is not None and proc.stdin is not None:
            try:
                proc.stdin.write(script)
                proc.stdin.flush()
                proc.stdin.close()
            except (BrokenPipeError, OSError):
                pass  # 远端提前退出（如主机不可达）— 继续收取输出
        if on_line is not None and proc.stdout is not None:
            for line in proc.stdout:
                on_line(line)
        elif proc.stdout is not None:
            parts.append(proc.stdout.read())
        try:
            rc = proc.wait(timeout=30)
        except subprocess.TimeoutExpired:
            # stdout 已 EOF 但 ssh 未退出（异常形态）— 强杀
            timed_out = True
            proc.kill()
            rc = proc.wait()
    finally:
        if timer is not None:
            timer.cancel()

    if timed_out and rc < 0:
        rc = 124  # 与本地 `timeout` 命令的退出码对齐
    return RunResult(rc=rc, text="".join(parts), timed_out=timed_out)


def _real_put(argv: list[str], local_path: str) -> RunResult:
    """真实推送：ssh host 'cat > remote' 以本地文件为 stdin。"""
    try:
        with open(local_path, "rb") as f:
            proc = subprocess.run(argv, stdin=f, capture_output=True, timeout=120)
    except FileNotFoundError as e:
        return RunResult(rc=255, text=f"本地无法启动 ssh: {e}")
    except subprocess.TimeoutExpired:
        return RunResult(rc=124, text="put 超时 (120s)", timed_out=True)
    return RunResult(rc=proc.returncode,
                     text=proc.stderr.decode("utf-8", "replace"))


def _print_dry(host: str, remote_cmd: str, script: str | None) -> None:
    print(f"---- [dry-run] ssh {host} {remote_cmd} ----")
    if script:
        for line in script.rstrip("\n").split("\n"):
            print(f"  | {line}")
    print("---- [dry-run] ----")


class SshHost:
    """单台远端主机的 SSH 访问面（exec_fn/put_fn 可注入用于单元自测）。"""

    def __init__(self, host: str, *, ssh_timeout: int = 10,
                 dry_run: bool = False, verbose: bool = False,
                 exec_fn=None, put_fn=None):
        self.host = host
        self.ssh_timeout = ssh_timeout
        self.dry_run = dry_run
        self.verbose = verbose
        self._exec_fn = exec_fn or _real_exec
        self._put_fn = put_fn or _real_put

    # ---- 基础 ----
    def _argv(self, remote_cmd: str) -> list[str]:
        return ["ssh", "-o", f"ConnectTimeout={self.ssh_timeout}",
                self.host, remote_cmd]

    def _log_argv(self, remote_cmd: str, timeout) -> None:
        print(f"[ssh {self.host}] {remote_cmd}"
              + (f" (timeout={timeout})" if timeout else ""))

    # ---- 执行 ----
    def run_script(self, script: str, *, timeout: float | None = None,
                   on_line=None) -> RunResult:
        """远端执行一段 bash 脚本（stdin 喂给 bash -s）。

        timeout: 本地外层超时（远端内层 timeout 由脚本文本自带）。
        on_line: 行回调（keepends，含换行符）时流式返回，text 为空。
        """
        remote_cmd = "bash -s"
        if self.dry_run:
            _print_dry(self.host, remote_cmd, script)
            return RunResult(rc=0)
        if self.verbose:
            self._log_argv(remote_cmd, timeout)
        return self._exec_fn(self._argv(remote_cmd), script, timeout, on_line)

    # ---- 文件 ----
    def put(self, local_path: str, remote_path: str) -> RunResult:
        """单文件推送（ssh cat > remote < local）。"""
        if self.dry_run:
            print(f"---- [dry-run] ssh {self.host} put {local_path} → {remote_path} ----")
            return RunResult(rc=0)
        if self.verbose:
            print(f"[ssh {self.host}] put {local_path} → {remote_path}")
        return self._put_fn(self._argv(f"cat > {q(remote_path)}"), local_path)

    def read_file(self, remote_path: str, *, timeout: float | None = 30) -> str:
        """读远端文本文件（缺失/不可读 → 空串）。"""
        res = self.run_script(f"cat {q(remote_path)} 2>/dev/null\ntrue\n",
                              timeout=timeout)
        return res.text

    # ---- 进程 ----
    def pkill(self, pattern: str, *, sig: str = "-9",
              timeout: float | None = 15) -> RunResult:
        """按完整命令行模式清理远端进程（不匹配时 rc 也为 0）。"""
        script = f"pkill {sig} -f {q(pattern)} 2>/dev/null\ntrue\n"
        return self.run_script(script, timeout=timeout)

    def mr_count(self, *, timeout: float | None = 15) -> int | None:
        """"/proc/symrdma 活跃 MR 计数（模块未加载/不可读 → None）。"""
        script = "grep '活跃 MR' /proc/symrdma 2>/dev/null | tr -dc 0-9\necho\n"
        res = self.run_script(script, timeout=timeout)
        s = res.text.strip()
        return int(s) if s.isdigit() else None

    def run_tty(self, cmd: str, *, extra_args: list[str] | None = None) -> RunResult:
        """交互式远端命令（ssh -tt，stdin 继承本地终端）— sudo 密码场景。

        远程交互式 sudo 最稳路径；本地 stdout 捕获仍可
        （-tt 强制分配远端 pty，本地管道不受影响）。
        """
        argv = ["ssh", "-tt", "-o", f"ConnectTimeout={self.ssh_timeout}"] \
            + (extra_args or []) + [self.host, cmd]
        if self.dry_run:
            print(f"---- [dry-run] ssh -tt {self.host} {cmd} ----")
            return RunResult(rc=0)
        if self.verbose:
            print(f"[ssh {self.host}] -tt {cmd}")
        import subprocess
        try:
            proc = subprocess.run(argv, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True,
                                  encoding="utf-8", errors="replace")
        except FileNotFoundError as e:
            return RunResult(rc=255, text=f"本地无法启动 ssh: {e}")
        return RunResult(rc=proc.returncode, text=proc.stdout)

    def test_x(self, remote_path: str, *, timeout: float | None = 15) -> bool:
        """远端可执行文件存在性检查。"""
        script = f"test -x {qh(remote_path)}\n"
        res = self.run_script(script, timeout=timeout)
        return res.rc == 0


class Ctx:
    """一次 CLI 调用的运行上下文：dry-run / verbose / 主机连接缓存。"""

    def __init__(self, *, dry_run: bool = False, verbose: bool = False,
                 ssh_timeout: int = 10):
        self.dry_run = dry_run
        self.verbose = verbose
        self.ssh_timeout = ssh_timeout
        self._hosts: dict[str, SshHost] = {}

    def host(self, name: str) -> SshHost:
        if name not in self._hosts:
            self._hosts[name] = SshHost(
                name, ssh_timeout=self.ssh_timeout,
                dry_run=self.dry_run, verbose=self.verbose)
        return self._hosts[name]
