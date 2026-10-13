"""CLI 入口 — 子命令: levels / sir / atomic / list。

公共参数（--dry-run/-v/--out-dir/--json/--ssh-timeout/--remote）既可放在
子命令之前（symtest --dry-run levels all）也可放在子命令之后
（symtest levels all --dry-run，wrapper 透传形态）— 经 parents=[common]
双注册实现，SUPPRESS 默认值保证不互相覆盖。
环境变量契约与 bash 版一致（REMOTE / TEST_TIMEOUT / SSH_TIMEOUT /
SERVER_HOST / SERVER_IP / CLIENT_HOST / PORT / GID / SIR_DEBUG / OUT_DIR），
CLI 参数优先于环境变量。
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__, config
from .ssh import Ctx


def _common() -> argparse.ArgumentParser:
    """公共参数（SUPPRESS 默认 — 未指定时不覆盖主解析器值）。"""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--dry-run", action="store_true", default=argparse.SUPPRESS,
                   help="只打印将执行的远端脚本, 不连接不判定")
    p.add_argument("-v", "--verbose", action="store_true",
                   default=argparse.SUPPRESS, help="显示 ssh 调用摘要")
    p.add_argument("--out-dir", default=argparse.SUPPRESS,
                   help="产物目录 (默认 tests/results, 同 OUT_DIR 环境变量)")
    p.add_argument("--json", dest="json_path", default=argparse.SUPPRESS,
                   nargs="?", const="auto", metavar="PATH",
                   help="manifest 输出 (默认自动命名; --json none 关闭)")
    p.add_argument("--ssh-timeout", type=int, default=argparse.SUPPRESS,
                   help="SSH 连接超时秒数 (默认 $SSH_TIMEOUT / 10)")
    p.add_argument("--remote", default=argparse.SUPPRESS,
                   help="单机套件目标机 (默认 $REMOTE / host-a)")
    return p


def _common_real() -> argparse.ArgumentParser:
    """主解析器版公共参数（真实默认值 — 子命令 SUPPRESS 形态不覆盖它们）。"""
    p = argparse.ArgumentParser(add_help=False)
    p.add_argument("--dry-run", action="store_true", default=False,
                   help="只打印将执行的远端脚本, 不连接不判定")
    p.add_argument("-v", "--verbose", action="store_true", default=False,
                   help="显示 ssh 调用摘要")
    p.add_argument("--out-dir", default=None,
                   help="产物目录 (默认 tests/results, 同 OUT_DIR 环境变量)")
    p.add_argument("--json", dest="json_path", default="auto",
                   nargs="?", const="auto", metavar="PATH",
                   help="manifest 输出 (默认自动命名; --json none 关闭)")
    p.add_argument("--ssh-timeout", type=int, default=None,
                   help="SSH 连接超时秒数 (默认 $SSH_TIMEOUT / 10)")
    p.add_argument("--remote", default=None,
                   help="单机套件目标机 (默认 $REMOTE / host-a)")
    return p


def build_parser() -> argparse.ArgumentParser:
    common = _common()  # 子命令用 (SUPPRESS)
    p = argparse.ArgumentParser(
        prog="symtest",
        parents=[_common_real()],
        description="SymRDMA 测试编排引擎 (v%s) — test.sh / run_sir_cross.sh / "
                    "run_atomic_bench.sh 的 Python 引擎, 入口契约兼容"
                    % __version__,
    )
    sub = p.add_subparsers(dest="cmd", required=True)

    lp = sub.add_parser("levels", parents=[common],
                        help="单机 Level 套件 (test.sh 引擎)")
    lp.add_argument("targets", nargs="*", default=[],
                    help="levelN | N | 6r | all (默认 all; 可多目标)")
    lp.add_argument("--timeout", type=int, default=None,
                    help="远端单级超时 (默认 $TEST_TIMEOUT / 180)")
    lp.add_argument("--list", action="store_true", help="列出全部 Level")

    sp = sub.add_parser("sir", parents=[common],
                        help="跨机双进程套件 (run_sir_cross.sh 引擎)")
    sp.add_argument("levels", nargs="*", default=[],
                    help="7 | 10 | 12 | 13 | all (默认 all)")
    sp.add_argument("--server-host", default=None)
    sp.add_argument("--client-host", default=None)
    sp.add_argument("--server-ip", default=None)
    sp.add_argument("--port", type=int, default=None,
                    help="SIR 会合端口 (默认 $PORT / 18721; +1 为协调端口)")
    sp.add_argument("--gid", default=None, help="GID index (默认 5, 测试床强制)")
    sp.add_argument("--sir-debug", action="store_true",
                    help="SYMRDMA_SIR_DEBUG=1 (库层调试日志, 仅 L12/L13)")
    sp.add_argument("--client-timeout", type=int, default=None,
                    help="client 远端超时 (默认 150)")

    ap = sub.add_parser("atomic", parents=[common],
                        help="原子基准双机 (run_atomic_bench.sh 引擎)")
    ap.add_argument("--server-host", default=None)
    ap.add_argument("--client-host", default=None)
    ap.add_argument("--server-ip", default=None)
    ap.add_argument("--port", type=int, default=None, help="默认 $PORT / 18716")
    ap.add_argument("--gid", default=None)
    ap.add_argument("--dev", default=None, help="RDMA 设备名 (默认 mlx5_0)")

    # ---- v0.40.0: 剩余 bash 脚本迁移 ----

    def _bench_pair(sp):
        sp.add_argument("--server-host", default=None)
        sp.add_argument("--client-host", default=None)
        sp.add_argument("--server-ip", default=None)
        sp.add_argument("--port", type=int, default=None)
        sp.add_argument("--gid", default=None)
        return sp

    rp = _bench_pair(sub.add_parser(
        "racebw", parents=[common],
        help="race 吞吐基准双机 (run_racebw.sh 引擎, 论文 Fig 12)"))
    rp.add_argument("--dev", default=None)
    rp.add_argument("--threads", type=int, default=None,
                    help="client 线程数 (默认 $THREADS / 1)")

    np_ = _bench_pair(sub.add_parser(
        "nopf", parents=[common],
        help="no-PF 带宽矩阵双机 (run_nopf_bw.sh 引擎, 论文 Fig 13(b))"))
    np_.add_argument("--dev", default=None)
    np_.add_argument("sizes", nargs="*", default=None,
                    help="尺寸列表 (默认 64B..1MB 共 9 点)")

    pp = sub.add_parser("nopf-pipeline", parents=[common],
                        help="no-PF 全流水线 (nopf_pipeline.sh 引擎: "
                             "预检→构建→N 轮→平均→出图→回归)")
    pp.add_argument("--server-host", default=None)
    pp.add_argument("--client-host", default=None)
    pp.add_argument("--server-ip", default=None)
    pp.add_argument("--dev", default=None)
    pp.add_argument("--runs", type=int, default=None, help="基准轮数 (默认 3)")
    pp.add_argument("--thresh", type=float, default=None,
                    help="线速区回归阈值 %% (默认 3.0)")
    pp.add_argument("--skip-build", action="store_true",
                    help="跳过构建 (纯测量迭代)")

    gb = sub.add_parser(
        "group-gates", parents=[common],
        help="Phase 2 组粒度门禁 (run_group_gates.sh 引擎; ⚠ 需交互 sudo)")
    gb.add_argument("--client-host", default=None)
    gb.add_argument("--server-host", default=None)
    gb.add_argument("--client-bdf", default=None)
    gb.add_argument("--server-bdf", default=None)
    gb.add_argument("--version-gate", default=None,
                    help="模块版本门禁 (默认 v0.38.0)")

    rg = _bench_pair(sub.add_parser(
        "iotlb", parents=[common],
        help="L18 IOTLB 工作集扫描 (run_iotlb_ws.sh 引擎, 论文 Fig 19)"))
    rg.add_argument("--dev", default=None)
    rg.add_argument("--tag", default=None, help="产物标签 (默认 base)")
    rg.add_argument("--thp", default=None, choices=("off", "on"),
                    help="THP 开关 (默认 off)")
    rg.add_argument("--iters", type=int, default=0,
                    help="0 = bench 自适应")
    rg.add_argument("--msg", type=int, default=None, help="消息尺寸 (默认 4096)")
    rg.add_argument("--ws-raw", default=None, help="raw 工作集列表")
    rg.add_argument("--ws-sym", default=None, help="sym 工作集列表")
    rg.add_argument("--patterns", default=None, help="seq rand")

    mb = _bench_pair(sub.add_parser(
        "matrix", parents=[common],
        help="原版 vs SymRDMA 矩阵 (run_matrix.sh 引擎, 论文 §5.2.2)"))
    mb.add_argument("--dev", default=None)
    mb.add_argument("sizes", nargs="*", default=None,
                    help="尺寸列表 (默认 64 1024 4096 65536)")

    op = _bench_pair(sub.add_parser(
        "odp", parents=[common],
        help="L15 Phase B ODP 对照 (run_odp_compare.sh 引擎)"))
    op.add_argument("--dev", default=None)
    op.add_argument("sizes", nargs="*", default=None,
                    help="尺寸列表 (默认 256 4096 65536 262144)")

    cb = sub.add_parser("ctl", parents=[common],
                        help="控制面开销基准 (run_ctl_bench.sh 引擎, "
                             "论文 Tables 1/2)")
    cb.add_argument("hosts", nargs="*", default=None,
                    help="主机列表 (默认 CLIENT_HOST + SERVER_HOST)")
    cb.add_argument("--mbs", default=None,
                    help="斜率点 MB (默认 $CTLB_MBS / '64 128 256 512')")

    sb = sub.add_parser("reg", parents=[common],
                        help="L17 注册基准 (run_reg_bench.sh 引擎)")
    sb.add_argument("sizes", nargs="*", default=None,
                    help="none 轴尺寸 (默认 256M..128G)")
    sb.add_argument("--tag", default=None, help="产物标签 (默认 base)")
    sb.add_argument("--iters", type=int, default=None, help="默认 3")

    iv = sub.add_parser("investigate", parents=[common],
                        help="外部页失效源调查 (investigate_invalidation.sh)")
    iv.add_argument("--window", type=int, default=None,
                    help="静默窗口秒数 (默认 $WINDOW / 30)")

    sub.add_parser("list", parents=[common], help="列出全部套件与测试单元")
    return p


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    # 可选 CLI 补全（rich 同为可选依赖 — 未安装时静默跳过；见 ui.py 头注）
    try:
        import argcomplete
        argcomplete.autocomplete(parser)
    except ImportError:
        pass
    args = parser.parse_args(argv)

    out_dir = Path(getattr(args, "out_dir", None)
                   or config.env("OUT_DIR", str(config.RESULTS_DIR)))
    ssh_timeout = getattr(args, "ssh_timeout", None) \
        or config.SSH_TIMEOUT_DEFAULT
    ctx = Ctx(dry_run=getattr(args, "dry_run", False),
              verbose=getattr(args, "verbose", False),
              ssh_timeout=ssh_timeout)
    json_path = getattr(args, "json_path", "auto")
    if config.env("NO_JSON") == "1":
        json_path = "none"

    from . import bench_atomic
    from . import levels as levels_mod
    from . import sir as sir_mod

    try:
        if args.cmd == "list":
            levels_mod.list_levels()
            print("跨机双进程套件 (sir):")
            print("  L7 test_sir · L10 test_atomic · L12 test_auto_sir · "
                  "L13 test_transparent_read")
            print("基准 (atomic): 原子操作基准 (论文 §5.2.4 Fig 14)")
            return 0

        if args.cmd == "levels":
            if args.list:
                levels_mod.list_levels()
                return 0
            remote = getattr(args, "remote", None) or config.REMOTE_DEFAULT
            timeout = args.timeout or config.TEST_TIMEOUT_DEFAULT
            return levels_mod.run_levels(
                ctx, remote=remote, targets=args.targets, timeout=timeout,
                out_dir=out_dir, json_path=json_path)

        if args.cmd == "sir":
            server_host = args.server_host or config.SERVER_HOST_DEFAULT
            client_host = args.client_host or config.CLIENT_HOST_DEFAULT
            server_ip = args.server_ip or config.SERVER_IP_DEFAULT
            port = args.port or config.port_for(config.SIR_PORT_DEFAULT)
            gid = args.gid or config.GID_DEFAULT
            sir_debug = args.sir_debug or config.SIR_DEBUG_DEFAULT
            client_timeout = args.client_timeout \
                or config.SIR_CLIENT_TIMEOUT_DEFAULT
            return sir_mod.run_sir(
                ctx, targets=args.levels, server_host_name=server_host,
                client_host_name=client_host, server_ip=server_ip,
                port=port, gid=gid, sir_debug=sir_debug,
                client_timeout=client_timeout, out_dir=out_dir,
                json_path=json_path)

        if args.cmd == "atomic":
            server_host = args.server_host or config.SERVER_HOST_DEFAULT
            client_host = args.client_host or config.CLIENT_HOST_DEFAULT
            server_ip = args.server_ip or config.SERVER_IP_DEFAULT
            port = args.port or config.port_for(config.ATOMIC_PORT_DEFAULT)
            gid = args.gid or config.GID_DEFAULT
            dev = args.dev or config.DEV_DEFAULT
            return bench_atomic.run_atomic(
                ctx, server_host_name=server_host,
                client_host_name=client_host, server_ip=server_ip,
                port=port, gid=gid, dev=dev, out_dir=out_dir,
                json_path=json_path)

        # ---- v0.40.0: 剩余 bash 脚本迁移 ----
        from . import (bench_iotlb, bench_matrix, bench_nopf, bench_odp,
                       bench_racebw, bench_reg, diag_invalidate, gates_group,
                       pipeline_nopf)

        def srv() -> tuple[str, str, str]:
            return (args.server_host or config.SERVER_HOST_DEFAULT,
                    args.client_host or config.CLIENT_HOST_DEFAULT,
                    args.server_ip or config.SERVER_IP_DEFAULT)

        if args.cmd == "racebw":
            return bench_racebw.run_racebw(
                ctx, server_host_name=srv()[0], client_host_name=srv()[1],
                server_ip=srv()[2], dev=args.dev or config.DEV_DEFAULT,
                gid=args.gid or config.GID_DEFAULT,
                port=args.port or config.port_for(18777),
                threads=args.threads if args.threads is not None
                else int(config.env("THREADS", "1")),
                out_dir=out_dir, json_path=json_path)

        if args.cmd == "nopf":
            rc, _csv = bench_nopf.run_nopf(
                ctx, server_host_name=srv()[0], client_host_name=srv()[1],
                server_ip=srv()[2], dev=args.dev or config.DEV_DEFAULT,
                gid=args.gid or config.GID_DEFAULT,
                sizes=args.sizes or list(bench_nopf.DEFAULT_SIZES),
                out_dir=out_dir, json_path=json_path)
            return rc

        if args.cmd == "nopf-pipeline":
            return pipeline_nopf.run_pipeline(
                ctx, server_host_name=srv()[0], client_host_name=srv()[1],
                server_ip=srv()[2], dev=config.DEV_DEFAULT,
                gid=config.GID_DEFAULT,
                runs=args.runs or int(config.env("RUNS", "3")),
                thresh=args.thresh if args.thresh is not None
                else float(config.env("THRESH", "3.0")),
                skip_build=args.skip_build
                or config.env("SKIP_BUILD") == "1",
                out_dir=out_dir, json_path=json_path)

        if args.cmd == "group-gates":
            return gates_group.run_group_gates(
                ctx, client_host_name=args.client_host
                or config.CLIENT_HOST_DEFAULT,
                server_host_name=args.server_host
                or config.SERVER_HOST_DEFAULT,
                client_bdf=args.client_bdf
                or config.env("CLIENT_BDF", "0000:5e:00.0"),
                server_bdf=args.server_bdf
                or config.env("SERVER_BDF", "0000:d8:00.0"),
                out_dir=out_dir, json_path=json_path,
                version_gate=args.version_gate
                or config.env("GROUP_VERSION_GATE",
                              gates_group.VERSION_GATE_DEFAULT))

        if args.cmd == "iotlb":
            return bench_iotlb.run_iotlb(
                ctx, server_host_name=srv()[0], client_host_name=srv()[1],
                server_ip=srv()[2], dev=args.dev or config.DEV_DEFAULT,
                gid=args.gid or config.GID_DEFAULT,
                port=args.port or config.port_for(18526),
                tag=args.tag or config.env("TAG", "base"),
                thp=args.thp or config.env("THP", "off"),
                iters=args.iters, msg=args.msg or 4096,
                ws_raw=(args.ws_raw or config.env(
                    "WS_RAW", "16M 64M 256M 512M 1G 4G 16G")).split(),
                ws_sym=(args.ws_sym
                        or config.env("WS_SYM", "16M 64M 256M 512M")).split(),
                patterns=(args.patterns
                          or config.env("PATTERNS", "seq rand")).split(),
                out_dir=out_dir, json_path=json_path)

        if args.cmd == "matrix":
            return bench_matrix.run_matrix(
                ctx, server_host_name=srv()[0], client_host_name=srv()[1],
                server_ip=srv()[2], dev=args.dev or config.DEV_DEFAULT,
                gid=args.gid or config.GID_DEFAULT,
                sizes=args.sizes or ["64", "1024", "4096", "65536"],
                out_dir=out_dir, json_path=json_path)

        if args.cmd == "odp":
            return bench_odp.run_odp(
                ctx, server_host_name=srv()[0], client_host_name=srv()[1],
                server_ip=srv()[2], dev=args.dev or config.DEV_DEFAULT,
                gid=args.gid or config.GID_DEFAULT,
                port=args.port or config.port_for(18715),
                sizes=args.sizes or ["256", "4096", "65536", "262144"],
                out_dir=out_dir, json_path=json_path)

        if args.cmd == "ctl":
            from . import bench_ctl
            return bench_ctl.run_ctl(
                ctx, hosts=args.hosts or [config.CLIENT_HOST_DEFAULT,
                                          config.SERVER_HOST_DEFAULT],
                dev=config.DEV_DEFAULT, gid=config.GID_DEFAULT,
                mbs=args.mbs or config.env("CTLB_MBS",
                                           bench_ctl.CTLB_MBS_DEFAULT),
                out_dir=out_dir, json_path=json_path)

        if args.cmd == "reg":
            return bench_reg.run_reg(
                ctx, remote=args.remote or config.REMOTE_DEFAULT,
                sizes=args.sizes or list(bench_reg.DEFAULT_SIZES),
                tag=args.tag or config.env("TAG", "base"),
                iters=args.iters if args.iters is not None
                else int(config.env("ITERS", "3")),
                out_dir=out_dir, json_path=json_path)

        if args.cmd == "investigate":
            return diag_invalidate.run_investigate(
                ctx, remote=args.remote or config.REMOTE_DEFAULT,
                window=args.window if args.window is not None
                else int(config.env("WINDOW", "30")))
        return 1
    except (levels_mod.UsageError, sir_mod.UsageError) as e:
        print(f"✗ {e}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\n[中断] 清理远端进程后退出 (Ctrl-C)", file=sys.stderr)
        return 130
    except RuntimeError as e:  # SuiteAbort / DeployError / 环境失败
        print(f"✗ {e}", file=sys.stderr)
        return 1
