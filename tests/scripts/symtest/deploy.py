"""远端部署 — 源码 md5 新鲜度检查 + 按需推送编译。

协议与 bash 版一致（run_atomic_bench / run_nopf_bw 同款）：
  1. 远端逐文件 md5 比对 + 产物 -x 检查 → CHECK_OK（跳过）/ CHECK_STALE；
  2. STALE → 推送源码 → 远端编译（输出 COMPILE_OK / COMPILE_FAIL 标记）。

EDR 教训（TESTING §5.2）：新 mtime 二进制有行为扫描放行窗口，持续网络
洪水在 ~4.5s 处被 SIGTERM —— 所以"源码未变则跳过重编译"不只是省时间，
还是稳定性措施。调用方拿到 recompiled=True 时可自行做放行预热
（racebw/nopf 形态；atomic 无需）。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

from .ssh import q


class DeployError(RuntimeError):
    pass


@dataclass
class DeployUnit:
    """一个远端部署单元（源文件 + 产物 + 编译脚本）。"""

    name: str
    sources: list[tuple[str, str]]          # (local_path, remote_path) — 会推送
    binaries: list[str]                     # 远端须 -x 的产物
    compile_script: str                     # 成功须输出 COMPILE_OK 行
    log_tag: str = ""                       # 显示用前缀（默认 name）
    # 只参与新鲜度 hash、绝不推送的对 (如远端 build.sh 编译的静态库 —
    # 本地推 .a 会用本地编译产物污染远端, racebw 首跑教训的对称面)
    hash_only: list[tuple[str, str]] = field(default_factory=list)


def _file_md5(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def check_script(unit: DeployUnit) -> str:
    lines = ["ok=1"]
    for local, remote in [*unit.sources, *unit.hash_only]:
        lines.append(
            "[ \"$(md5sum " + q(remote) + " 2>/dev/null | awk '{print $1}')\""
            f" = \"{_file_md5(local)}\" ] || ok=0"
        )
    for b in unit.binaries:
        lines.append(f"[ -x {q(b)} ] || ok=0")
    lines.append('[ "$ok" = 1 ] && { echo CHECK_OK; exit 0; }')
    lines.append("echo CHECK_STALE")
    return "\n".join(lines) + "\n"


def ensure_deployed(host, unit: DeployUnit, *, log=print) -> bool:
    """确保单元在 host 上就绪。返回 True = 本次重编译了（False = 未变）。

    dry-run：打印检查/推送/编译脚本后返回 False（不执行、不判标记）。
    """
    tag = f"[{host.host}/{unit.log_tag or unit.name}] "
    res = host.run_script(check_script(unit), timeout=60)
    if host.dry_run:
        return False
    if res.timed_out:
        raise DeployError(f"{tag}部署检查超时")
    if "CHECK_OK" in res.text:
        log(f"{tag}二进制未变, 跳过重编译")
        return False
    if "CHECK_STALE" not in res.text:
        raise DeployError(f"{tag}部署检查失败:\n{res.text.strip()}")
    for local, remote in unit.sources:
        r = host.put(local, remote)
        if r.rc != 0:
            raise DeployError(f"{tag}源码推送失败: {remote} ({r.text.strip()})")
    res = host.run_script(unit.compile_script, timeout=600)
    if res.timed_out:
        raise DeployError(f"{tag}编译超时 (600s)")
    if "COMPILE_OK" not in res.text:
        raise DeployError(f"{tag}编译失败:\n{res.text.strip()}")
    log(f"{tag}已重编译")
    return True
