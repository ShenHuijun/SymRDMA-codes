"""远端后台进程管理 + 脚本构造器 + 双主机并行工具。

后台启动脚本遵循既定形态：
    nohup stdbuf -oL env K=V <argv> </dev/null > <log> 2>&1 &
  * stdbuf -oL —— ssh 管道下 libc 全缓冲会让"挂死"伪装成"秒退无输出"
    （§5 教训教训 #12/#13）；
  * </dev/null + 重定向到日志文件 —— ssh 不会因后台进程持有 std 流而挂住；
  * 就绪等待循环与原 bash 版语义一致：日志出现 ready 模式 → 成功；
    进程消失 → 失败；轮询耗尽后 ready 命中或进程仍活均算成功。
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from collections.abc import Callable

from .ssh import q, qh


def env_prefix(env: dict[str, str] | None) -> str:
    """{'K': 'V'} → 'env K="V" ...'（值经 qh，$HOME 前缀可展开；空 → ''）。"""
    if not env:
        return ""
    parts = " ".join(f"{k}={qh(v)}" for k, v in env.items())
    return f"env {parts}"


def bg_start_script(argv: list[str], *, log: str, env: dict[str, str] | None = None,
                    prekill: str | None = None, sleep_before_start: float = 0,
                    cwd: str | None = None, rm_log: bool = True,
                    prefix: str = "") -> str:
    """构造后台启动脚本（调用方负责就绪等待）。

    argv 元素支持 "$HOME" 前缀路径（经 qh 展开）。prefix 为命令前缀
    （如 numactl 绑定，环境可用性由调用方在脚本文本中自行判定）。
    prekill: 启动前清理的进程模式（SIGTERM，与原脚本一致）。
    """
    lines: list[str] = []
    if prekill:
        lines.append(f"pkill -f {q(prekill)} 2>/dev/null; true")
    if sleep_before_start > 0:
        s = sleep_before_start
        s = int(s) if s.is_integer() else s
        lines.append(f"sleep {s}")
    if cwd:
        lines.append(f"cd {qh(cwd)}")
    if rm_log:
        lines.append(f"rm -f {q(log)}")
    cmd = " ".join(x for x in ["nohup stdbuf -oL", prefix, env_prefix(env),
                                *[qh(a) for a in argv]] if x)
    lines.append(f"{cmd} </dev/null >{q(log)} 2>&1 &")
    return "\n".join(lines) + "\n"


def wait_ready_script(log: str, ready_re: str, alive_pattern: str,
                      *, tries: int = 30, interval: float = 1.0) -> str:
    """就绪等待脚本（一次 ssh 往返，语义移植自 run_sir_cross.sh）。

    循环内 ready 命中 → exit 0；进程消失 → exit 1。
    轮询耗尽后：ready 命中或进程仍活 → exit 0（与原版兜底一致）。
    """
    iv = int(interval) if interval.is_integer() else interval
    return (
        f"for i in $(seq 1 {int(tries)}); do\n"
        f"  grep -qE {q(ready_re)} {q(log)} 2>/dev/null && exit 0\n"
        f"  pgrep -f {q(alive_pattern)} >/dev/null || exit 1\n"
        f"  sleep {iv}\n"
        f"done\n"
        f"grep -qE {q(ready_re)} {q(log)} 2>/dev/null || "
        f"pgrep -f {q(alive_pattern)} >/dev/null\n"
    )


def wait_pattern_script(log: str, pattern_re: str, *, tries: int = 15,
                        interval: float = 1.0) -> str:
    """纯等待脚本：等日志出现模式（用于 server 收尾），rc 恒 0。"""
    iv = int(interval) if interval.is_integer() else interval
    return (
        f"for i in $(seq 1 {int(tries)}); do\n"
        f"  grep -qE {q(pattern_re)} {q(log)} 2>/dev/null && exit 0\n"
        f"  sleep {iv}\n"
        f"done\n"
        f"true\n"
    )


def detached_run_script(argv: list[str], *, log: str, exit_file: str,
                        env: dict[str, str] | None = None,
                        timeout_cmd: int = 3300, prefix: str = "",
                        pre_rm: list[str] | None = None) -> str:
    """setsid 脱离执行（racebw 形态，v0.36.0）:

    长持 SSH 会话会被环境杀（kubelet 崩溃循环期/EDR, 实测 rc=255 且无害）—
    改为 setsid 脱离启动 + 轮询 exit 文件。脚本退出码写入 exit_file。
    引号嵌套：内层 bash -c 串用单引号包裹，$? 在单引号内不被外层展开
    （bash 版 heredoc 里的 \\$? 转义仅因 heredoc 展开 — 此处直写 $?）。
    """
    pre = " ".join(x for x in [prefix, env_prefix(env)] if x)
    cmd = " ".join(qh(a) for a in argv)
    rms = "".join(f"rm -f {q(p)}\n" for p in (pre_rm or []))
    return (
        f"{rms}"
        f"setsid bash -c 'stdbuf -oL timeout {int(timeout_cmd)} {pre} {cmd} "
        f">{q(log)} 2>&1; echo $? > {q(exit_file)}' "
        "</dev/null >/dev/null 2>&1 &\n"
        "echo launched\n"
    )


def wait_exit_file(host, exit_file: str, *, tries: int = 360,
                   interval: float = 10.0,
                   poll_timeout: float | None = 20) -> str | None:
    """轮询远端 exit 文件 → 退出码字符串（超时 → None）。"""
    import time
    for _ in range(tries):
        time.sleep(interval)
        val = host.read_file(exit_file, timeout=poll_timeout).strip()
        if val:
            return val
    return None


def run_parallel(tasks: dict[str, Callable[[], object]]) -> dict[str, object]:
    """双主机并行执行（预检/部署等互不依赖的操作）。

    返回 {name: result}；任一任务抛异常则在全部结束后重抛第一个。
    dry-run 场景调用方应自行串行（避免输出交错），见 suites。
    """
    if not tasks:
        return {}
    if len(tasks) == 1:
        name, fn = next(iter(tasks.items()))
        return {name: fn()}
    results: dict[str, object] = {}
    first_exc: BaseException | None = None
    with ThreadPoolExecutor(max_workers=len(tasks)) as ex:
        futs = {ex.submit(fn): name for name, fn in tasks.items()}
        for fut, name in futs.items():
            try:
                results[name] = fut.result()
            except BaseException as e:  # 汇聚后重抛第一个
                if first_exc is None:
                    first_exc = e
    if first_exc is not None:
        raise first_exc
    return results
