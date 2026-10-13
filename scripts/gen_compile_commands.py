#!/usr/bin/env python3
"""gen_compile_commands.py — 生成 VSCode/clangd 用的 compile_commands.json

原理: 对每个组件跑 `make -n -B` 干跑 (不实际编译), 解析打印出的编译命令行,
合并写入仓库根目录 compile_commands.json。因此本地内核头 (7.2.4) 与项目
目标内核 (5.11) 的 API 不匹配不影响本脚本 — 干跑只打印命令, 不检查编译结果。

覆盖组件:
  kernel/           内核模块 (out-of-tree kbuild; gcc 命令嵌在复合 shell 行内)
  lib/              libsymrdma.a (普通 Makefile, CC=cc)
  nprdma/           libnprdma.so
  tests/programs/   测试程序 (链接行直接含 .c, 一并收录)

注意: 项目的权威构建在远端测试床 (5.11 + OFED 5.8, 见 scripts/build.sh)。
本文件仅供本地编辑器索引; 若要精确匹配远端环境, 可在远端跑本脚本后把
compile_commands.json rsync 回来。

用法:  python3 scripts/gen_compile_commands.py
"""

import json
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
OUT = REPO / "compile_commands.json"

# 匹配编译器调用: 编译器名 + 参数, 以 "-c -o <obj> <src>.c" 结尾 (compile 行)
# 兼容: (1) 独立命令行 "cc -O2 ... -c -o x.o x.c"
#       (2) kbuild 复合行 "...; trap ...; gcc -Wp,... -c -o x.o x.c; printf ..."
RE_COMPILE = re.compile(
    r"(?<![\w.$/-])((?:[\w.-]+/)?(?:cc|gcc|clang)[\w.-]*)\s"  # 编译器名
    r"([^;]*?)"                                                # flags (不含 ;)
    r"-c\s+-o\s+(\S+)\s+(\S+?\.c)\s*(?=;|$)"                   # -c -o obj src.c
)

# 链接行: "gcc -O2 ... -o prog prog.c lib.a" (无 -c, 直接 .c -> 二进制,
# tests/programs/Makefile 依赖 make 内建规则, 干跑只打印链接行)
RE_LINK = re.compile(
    r"^(?:[\w.-]+/)?(?:cc|gcc|clang)[\w.-]*\s(.*)$"
)


def kernel_kbuild_cmd() -> str:
    kbuild = Path("/lib/modules") / os.uname().release / "build"
    if not kbuild.is_dir():
        sys.exit(f"错误: 找不到内核构建树 {kbuild} (linux-headers 未安装?)")
    return (
        f"make -n -B -C {kbuild} M={REPO / 'kernel'} modules"
    )


COMPONENTS = [
    # (名称, 干跑命令, 编译命令的 cwd (解析相对路径基准)); -k 跳过无法满足的目标
    ("kernel", kernel_kbuild_cmd() + " -k", REPO / "kernel"),
    ("lib", "make -k -n -B -C lib", REPO / "lib"),
    ("nprdma", "make -k -n -B -C nprdma", REPO / "nprdma"),
    ("tests", "make -k -n -B -C tests/programs", REPO / "tests" / "programs"),
]


def dry_run(cmd: str) -> str:
    r = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=REPO)
    if r.returncode != 0:
        # -k 下仍可能非零 (如远端扁平布局的缺失源), 但已有输出可用
        print(f"  警告: {cmd} 退出码 {r.returncode}, 使用已有输出", file=sys.stderr)
    # Makefile 续行符 \\+换行 → 空格 (nprdma/Makefile 的 -shared 多行命令)
    return r.stdout.replace("\\\n", " ")


def parse_output(text: str, directory: Path, name: str) -> list[dict]:
    """从干跑输出提取 compile_commands.json 条目"""
    entries = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        # --- compile 行 (含 -c) ---
        m = RE_COMPILE.search(line)
        if m:
            compiler, flags, _obj, src = m.groups()
            command = f"{compiler} {flags}-c -o {_obj} {src}".strip()
            entries.append(("compile", command, src, directory))
            continue
        # --- 链接行 (无 -c, 但含 .c 输入) ---
        if line.startswith(("cc ", "gcc ", "clang ", "clang++ ", "c++ ", "g++ ")) \
                and " -c " not in f" {line} " and ".c" in line:
            m2 = RE_LINK.match(line)
            if not m2:
                continue
            try:
                toks = shlex.split(m2.group(1))
            except ValueError:
                continue
            srcs = [t for t in toks if t.endswith(".c") and not t.startswith("-")]
            for src in srcs:
                entries.append(("link", line, src, directory))
    # 解析绝对路径, 过滤不存在的源文件 (内核 host 工具 / 远端扁平布局残留)
    out = []
    for kind, command, src, directory in entries:
        path = (directory / src).resolve()
        if not path.is_file():
            continue
        out.append({
            "directory": str(directory),
            "file": str(path),
            "command": command,
        })
    print(f"  [{name}] {len(out)} 条")
    return out


def dedupe(entries: list[dict]) -> list[dict]:
    """同一源文件可能被多个组件收录 (如 nprdma_engine.c 被测试白盒直含);
    优先保留 directory == 文件所在目录 的"原生"条目"""
    by_file: dict[str, list[dict]] = {}
    for e in entries:
        by_file.setdefault(e["file"], []).append(e)
    final = []
    for f, group in by_file.items():
        native = [e for e in group if os.path.dirname(f) == e["directory"]]
        final.append((native or group)[0])
    return sorted(final, key=lambda e: e["file"])


def main() -> None:
    all_entries: list[dict] = []
    print("生成 compile_commands.json (make -n -B 干跑解析):")
    for name, cmd, directory in COMPONENTS:
        all_entries += parse_output(dry_run(cmd), directory, name)
    final = dedupe(all_entries)
    OUT.write_text(json.dumps(final, indent=1))
    print(f"→ {OUT} ({len(final)} 个编译单元)")


if __name__ == "__main__":
    main()
