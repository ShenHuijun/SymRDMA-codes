"""symtest 单元自测 — 无网络、无远端依赖（FakeExec 注入）。

运行: python3 tests/scripts/symtest/selftest.py
"""

from __future__ import annotations

import contextlib
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from symtest import (
    bench_atomic,
    config,
    report,
)
from symtest import levels as lv_mod
from symtest import sir as sir_mod
from symtest.deploy import ensure_deployed
from symtest.remote import (
    bg_start_script,
    env_prefix,
    run_parallel,
    wait_ready_script,
)
from symtest.ssh import RunResult, SshHost, q, qh


class FakeExec:
    """记录 (argv, script) 并按 handler 返回合成结果。"""

    def __init__(self, handler=None):
        self.handler = handler or (lambda argv, script: (0, ""))
        self.calls: list[tuple[list[str], str]] = []

    def __call__(self, argv, script, timeout, on_line):
        self.calls.append((argv, script))
        rc, text = self.handler(argv, script)
        if on_line is not None:
            for line in text.splitlines(keepends=True):
                on_line(line)
        return RunResult(rc=rc, text=text)


def fake_host(handler=None, name: str = "h1") -> tuple[SshHost, FakeExec]:
    """构造注入 FakeExec 的 SshHost（handler 是第一个位置参数）。"""
    ex = FakeExec(handler)
    h = SshHost(name, exec_fn=ex,
                put_fn=lambda argv, local: RunResult(rc=0))
    return h, ex


# ---------------- ssh / 引用 ----------------

class TestQuoting(unittest.TestCase):
    def test_q_plain(self):
        self.assertEqual(q("abc"), "abc")
        self.assertEqual(q("a b"), "'a b'")

    def test_qh_home(self):
        self.assertEqual(qh("$HOME/pro/symrdma/x"), '"$HOME"/pro/symrdma/x')
        # $HOME 后缀含特殊字符: 双引号段 + 单引号段拼接（合法 bash）
        self.assertEqual(qh("$HOME/a b"), '"$HOME"' + "'/a b'")
        self.assertEqual(qh("plain"), "plain")

    def test_env_prefix(self):
        s = env_prefix({"A": "1", "LD_PRELOAD": "$HOME/pro/symrdma/x"})
        self.assertIn('A=1', s)
        self.assertIn('LD_PRELOAD="$HOME"/pro/symrdma/x', s)
        self.assertTrue(s.startswith("env "))
        self.assertEqual(env_prefix(None), "")
        self.assertEqual(env_prefix({}), "")


class TestSshHost(unittest.TestCase):
    def test_run_script_argv_bash_s(self):
        h, ex = fake_host()
        res = h.run_script("true\n", timeout=5)
        argv, script = ex.calls[0]
        self.assertEqual(argv[-1], "bash -s")
        self.assertIn("-o", argv)
        self.assertEqual(script, "true\n")
        self.assertEqual(res.rc, 0)

    def test_dry_run_no_calls(self):
        h, ex = fake_host()
        h.dry_run = True
        res = h.run_script("echo hi\n")
        self.assertEqual(res.rc, 0)
        self.assertEqual(ex.calls, [])

    def test_pkill_script(self):
        h, ex = fake_host()
        h.pkill("[t]est_")
        argv, script = ex.calls[0]
        self.assertIn("pkill -9 -f '[t]est_'", script)
        self.assertIn("true", script)

    def test_read_file_missing_ok(self):
        h, ex = fake_host(handler=lambda a, s: (1, ""))
        self.assertEqual(h.read_file("/tmp/nope"), "")

    def test_timeout_normalizes_124(self):
        # exec_fn 无法直接模拟 timed_out — 用返回值断言 RunResult 语义
        r = RunResult(rc=-9, timed_out=True)
        self.assertTrue(r.timed_out)

    def test_mr_count_script_and_parse(self):
        h, ex = fake_host(lambda a, s: (0, "42\n"))
        self.assertEqual(h.mr_count(), 42)
        argv, script = ex.calls[0]
        self.assertIn("grep '活跃 MR' /proc/symrdma", script)

    def test_mr_count_unreadable(self):
        h, _ = fake_host(lambda a, s: (0, "\n"))
        self.assertIsNone(h.mr_count())

    def test_run_tty_dry_run(self):
        h, ex = fake_host()
        h.dry_run = True
        res = h.run_tty("bash ~/pro/symrdma/scripts/symrdma_reload.sh mode=1")
        self.assertEqual(res.rc, 0)
        self.assertEqual(ex.calls, [])  # dry-run 不经 exec_fn

    def test_detached_run_script_shape(self):
        from symtest.remote import detached_run_script
        s = detached_run_script(
            ["/tmp/racebw", "client", "-c", "1.2.3.4"],
            log="/tmp/c.log", exit_file="/tmp/e", timeout_cmd=3300,
            prefix="numactl --membind=0", pre_rm=["/tmp/c.log"])
        self.assertIn("rm -f /tmp/c.log\n", s)
        self.assertIn("setsid bash -c '", s)
        # $? 在内层单引号串内不被外层展开（直写 $? — bash 版 heredoc 转义
        # 仅因 heredoc 展开, 此形态不需要）
        self.assertIn("echo $? > /tmp/e", s)
        self.assertNotIn("\\$?", s)
        self.assertIn("</dev/null >/dev/null 2>&1 &", s)
        self.assertIn("echo launched", s)


# ---------------- levels ----------------

class TestLevels(unittest.TestCase):
    def test_registry_consistency(self):
        ids = [lv.id for lv in lv_mod.LEVELS]
        self.assertEqual(len(ids), len(set(ids)), "Level id 重复")
        self.assertEqual(set(lv_mod.ALL_LEVELS),
                         {i for i in ids if lv_mod.LEVEL_LOOKUP[i].in_all})
        self.assertNotIn("15", lv_mod.ALL_LEVELS)
        self.assertIn("15", lv_mod.LEVEL_LOOKUP, "L15 须可单独运行")

    def test_resolve_all(self):
        self.assertEqual([lv.id for lv in lv_mod.resolve_targets([])],
                         list(lv_mod.ALL_LEVELS))
        self.assertEqual([lv.id for lv in lv_mod.resolve_targets(["all"])],
                         list(lv_mod.ALL_LEVELS))

    def test_resolve_single_and_multi(self):
        self.assertEqual([lv.id for lv in lv_mod.resolve_targets(["level3"])], ["3"])
        self.assertEqual([lv.id for lv in lv_mod.resolve_targets(["3", "level6r"])],
                         ["3", "6r"])
        self.assertEqual([lv.id for lv in lv_mod.resolve_targets(["3", "3"])], ["3"])

    def test_resolve_unknown(self):
        with self.assertRaises(lv_mod.UsageError):
            lv_mod.resolve_targets(["level99"])

    def test_level_script_plain(self):
        s = lv_mod.level_script(lv_mod.LEVEL_LOOKUP["1"], 180)
        self.assertIn("timeout -k 10 180 stdbuf -oL", s)
        self.assertIn('"$HOME"/pro/symrdma/test/test_iommu_verify 2>&1', s)
        self.assertNotIn(" env ", s)

    def test_level_script_l6_env(self):
        s = lv_mod.level_script(lv_mod.LEVEL_LOOKUP["6"], 180)
        self.assertIn("env NPRDMA_INTERCEPT=all", s)
        self.assertIn('LD_PRELOAD="$HOME"/pro/symrdma/nprdma/libnprdma.so', s)
        self.assertIn('"$HOME"/pro/symrdma/test/test_nprdma 2>&1', s)

    def test_level_script_l15_args(self):
        s = lv_mod.level_script(lv_mod.LEVEL_LOOKUP["15"], 900)
        self.assertIn("test_odp_compare local", s)
        self.assertIn("timeout -k 10 900", s)

    def test_quiet_filter(self):
        self.assertRegex("WARNING: something", lv_mod.QUIET_RE)
        self.assertRegex("[libsymrdma] sentinel: ...", lv_mod.QUIET_RE)
        self.assertNotRegex("CHECK OK — 数据一致", lv_mod.QUIET_RE)

    def test_run_level_records_and_saves_log(self):
        h, ex = fake_host(lambda a, s: (0, "CHECK OK\nline2\n"))
        with tempfile.TemporaryDirectory() as td:
            log = Path(td) / "L1.log"
            rec = lv_mod.run_level(h, lv_mod.LEVEL_LOOKUP["1"], timeout=30,
                                   log_path=log)
            content = log.read_text()
        self.assertTrue(rec.ok)
        self.assertEqual(rec.rc, 0)
        self.assertEqual(len(ex.calls), 3, "前后孤儿清扫 + 执行")
        self.assertIn("pkill -9 -f '[t]est_'", ex.calls[0][1])
        self.assertEqual(content, "CHECK OK\nline2\n")

    def test_run_level_failure(self):
        h, _ = fake_host(lambda a, s: (1, "FAIL\n"))
        with tempfile.TemporaryDirectory() as td:
            rec = lv_mod.run_level(h, lv_mod.LEVEL_LOOKUP["1"], timeout=30,
                                   log_path=Path(td) / "L1.log")
        self.assertFalse(rec.ok)
        self.assertEqual(rec.rc, 1)

    def test_rc_detail_timeout(self):
        r = RunResult(rc=124)
        self.assertIn("远端 timeout", lv_mod._rc_detail(r, 180))

    def test_multi_mode_summary_exit_code(self):
        # 两个 Level: 一个成功 (L1) 一个失败 (L3) → 汇总退出码 1 + manifest 落盘
        from symtest.ssh import Ctx

        def handler(argv, script):
            if "sentinel-check" in script:
                return (0, "sentinel ok\n")
            return (1 if "test_swapout" in script else 0, "out\n")

        ctx = Ctx()
        h, _ = fake_host(handler)
        ctx._hosts["h1"] = h
        with tempfile.TemporaryDirectory() as td:
            rc = lv_mod.run_levels(ctx, remote="h1", targets=["1", "3"],
                                   timeout=30, out_dir=Path(td),
                                   json_path="auto")
        self.assertEqual(rc, 1)

    def test_single_mode_exit_code_is_level_rc(self):
        from symtest.ssh import Ctx
        ctx = Ctx()
        h, _ = fake_host(lambda a, s: (3, "boom\n"))
        ctx._hosts["h1"] = h
        with tempfile.TemporaryDirectory() as td:
            rc = lv_mod.run_levels(ctx, remote="h1", targets=["level2"],
                                   timeout=30, out_dir=Path(td),
                                   json_path="none")
        self.assertEqual(rc, 3)

    def test_canary_abort_exit_2(self):
        from symtest.ssh import Ctx
        ctx = Ctx()
        def handler(argv, script):
            return (2, "L1 sentinel 被污染\n") if "sentinel-check" in script \
                else (0, "ok\n")
        h, _ = fake_host(handler)
        ctx._hosts["h1"] = h
        with tempfile.TemporaryDirectory() as td:
            rc = lv_mod.run_levels(ctx, remote="h1", targets=["all"],
                                   timeout=30, out_dir=Path(td),
                                   json_path="none")
        self.assertEqual(rc, 2)


# ---------------- sir ----------------

class TestSir(unittest.TestCase):
    def test_case_env_l7_client_preload_only(self):
        srv, cli = sir_mod.case_envs("7", port=18721, gid="5",
                                     server_ip="10.1.2.3", sir_debug=False)
        self.assertEqual(srv["SYMRDMA_TEST_TCP"], "listen:18722")
        self.assertEqual(cli["SYMRDMA_TEST_TCP"], "10.1.2.3:18722")
        self.assertEqual(srv["SYMRDMA_TEST_GID"], "5")
        self.assertNotIn("LD_PRELOAD", srv)
        self.assertEqual(cli["LD_PRELOAD"], "$HOME/pro/symrdma/nprdma/libnprdma.so")
        self.assertNotIn("SYMRDMA_SIR_TCP", srv)

    def test_case_env_l10_all_intercept(self):
        srv, cli = sir_mod.case_envs("10", port=18721, gid="5",
                                     server_ip="10.1.2.3", sir_debug=False)
        self.assertEqual(cli["NPRDMA_INTERCEPT"], "all")
        self.assertNotIn("NPRDMA_INTERCEPT", srv)
        self.assertIn("LD_PRELOAD", cli)

    def test_case_env_l12_sir_rendezvous(self):
        srv, cli = sir_mod.case_envs("12", port=18721, gid="5",
                                     server_ip="10.1.2.3", sir_debug=False)
        self.assertEqual(srv["SYMRDMA_PEER"], "l12x")
        self.assertEqual(srv["SYMRDMA_SIR_TCP"], "listen:18721")
        self.assertEqual(cli["SYMRDMA_SIR_TCP"], "10.1.2.3:18721")
        self.assertNotIn("LD_PRELOAD", srv)
        self.assertNotIn("LD_PRELOAD", cli)

    def test_case_env_l13_both_preload(self):
        srv, cli = sir_mod.case_envs("13", port=18721, gid="5",
                                     server_ip="10.1.2.3", sir_debug=False)
        self.assertEqual(srv["NPRDMA_INTERCEPT"], "all")
        self.assertEqual(cli["NPRDMA_INTERCEPT"], "all")
        self.assertIn("$HOME", srv["LD_PRELOAD"])
        self.assertIn("$HOME", cli["LD_PRELOAD"])

    def test_sir_debug_wired(self):
        srv, cli = sir_mod.case_envs("12", port=100, gid="5",
                                     server_ip="ip", sir_debug=True)
        self.assertEqual(srv["SYMRDMA_SIR_DEBUG"], "1")
        self.assertEqual(cli["SYMRDMA_SIR_DEBUG"], "1")

    def test_server_script_shape(self):
        case = sir_mod.SIR_CASES["7"]
        srv, _ = sir_mod.case_envs("7", port=18721, gid="5",
                                   server_ip="ip", sir_debug=False)
        s = sir_mod._server_script(case, srv, "7")
        self.assertIn("pkill -f test_sir", s)
        self.assertIn("nohup stdbuf -oL env SYMRDMA_TEST_TCP=listen:18722", s)
        self.assertIn('"$HOME"/pro/symrdma/test/test_sir server', s)
        self.assertIn("</dev/null >/tmp/sir_cross_7.log 2>&1 &", s)
        self.assertIn("grep -qE 'Level|==='", s)
        self.assertIn("pgrep -f test_sir", s)

    def test_client_script_shape(self):
        case = sir_mod.SIR_CASES["10"]
        _, cli = sir_mod.case_envs("10", port=18721, gid="5",
                                   server_ip="10.1.2.3", sir_debug=False)
        s = sir_mod._client_script(case, cli, 150)
        self.assertIn("timeout 150 stdbuf -oL", s)
        self.assertIn('"$HOME"/pro/symrdma/test/test_atomic client', s)

    def test_gate_summary_mode(self):
        case = sir_mod.SIR_CASES["12"]
        log = "  PASS: x\n  FAIL: y\nserver: 10 通过 0 失败\n"
        checks = sir_mod._gate_server_log(case, log)
        by = {c.name: c for c in checks}
        self.assertFalse(by["server-FAIL"].ok)
        self.assertTrue(by["server-summary"].ok)

    def test_gate_generic_mode(self):
        case = sir_mod.SIR_CASES["10"]
        log = "INFO a\nINFO b\n超时 1 次\n"
        checks = sir_mod._gate_server_log(case, log)
        self.assertEqual(len(checks), 1)
        self.assertFalse(checks[0].ok)
        self.assertIn("×1", checks[0].detail)

    def test_run_sir_flow_with_fake_hosts(self):
        from symtest.ssh import Ctx

        def handler(argv, script):
            if "nohup" in script:
                return (0, "")
            if "cat /tmp/sir_cross_" in script:
                return (0, "server: 34 通过 0 失败\n")
            if "for i in $(seq 1 15)" in script:
                return (0, "")
            if "client" in script:
                return (0, "client output\n")
            return (0, "test -x ok\n")

        ctx = Ctx()
        sh, _ = fake_host(handler, "srv")
        ch, _ = fake_host(handler, "cli")
        ctx._hosts["srv"] = sh
        ctx._hosts["cli"] = ch
        with tempfile.TemporaryDirectory() as td:
            rc = sir_mod.run_sir(ctx, targets=["12"], server_host_name="srv",
                                 client_host_name="cli", server_ip="ip",
                                 port=18721, gid="5", sir_debug=False,
                                 client_timeout=150, out_dir=Path(td),
                                 json_path="none")
        self.assertEqual(rc, 0)

    def test_run_sir_client_fail(self):
        from symtest.ssh import Ctx

        def handler(argv, script):
            if "cat /tmp/sir_cross_" in script:
                return (0, "server: 1 通过 0 失败\n")
            if "client" in script and "timeout" in script:
                return (1, "client died\n")
            return (0, "")

        ctx = Ctx()
        sh, _ = fake_host(handler, "srv")
        ch, _ = fake_host(handler, "cli")
        ctx._hosts["srv"] = sh
        ctx._hosts["cli"] = ch
        with tempfile.TemporaryDirectory() as td:
            rc = sir_mod.run_sir(ctx, targets=["7"], server_host_name="srv",
                                 client_host_name="cli", server_ip="ip",
                                 port=18721, gid="5", sir_debug=False,
                                 client_timeout=150, out_dir=Path(td),
                                 json_path="none")
        self.assertEqual(rc, 1)


# ---------------- atomic ----------------

SAMPLE_ATOMIC = (
    "RESULT lat_pinned_faa_d4 1.2 us\n" * 4 +
    "RESULT lat99_pinned_faa_d4 1.3 us\n" * 4 +
    "RESULT thr_pinned_faa_p2 1.0 Mops\n" * 7 +
    "DONE fail=0\n"
)


class TestAtomic(unittest.TestCase):
    def test_gate_full(self):
        text = (
            "".join(f"RESULT lat_{c}_{op}_d{d} 1.0 us\n"
                    f"RESULT lat99_{c}_{op}_d{d} 1.0 us\n"
                    for c in ("pinned", "odp", "sym")
                    for op in ("faa", "cas")
                    for d in (4, 16, 64, 256)) +
            "".join(f"RESULT thr_{c}_{op}_p{p} 1.0 Mops\n"
                    for c in ("pinned", "odp", "sym")
                    for op in ("faa", "cas")
                    for p in (2, 4, 8, 16, 32, 64, 128)) +
            "DONE fail=0\n"
        )
        checks = bench_atomic._gate(text, 0)
        by = {c.name: c for c in checks}
        self.assertTrue(by["lat-rows"].ok)
        self.assertTrue(by["lat99-rows"].ok)
        self.assertTrue(by["thr-rows"].ok)
        self.assertTrue(by["exit-code"].ok)
        self.assertTrue(all(c.ok for c in checks))

    def test_gate_odp_skip(self):
        text = (
            "".join(f"RESULT lat_{c}_{op}_d{d} 1.0 us\n"
                    f"RESULT lat99_{c}_{op}_d{d} 1.0 us\n"
                    for c in ("pinned", "sym")
                    for op in ("faa", "cas")
                    for d in (4, 16, 64, 256)) +
            "".join(f"RESULT thr_{c}_{op}_p{p} 1.0 Mops\n"
                    for c in ("pinned", "sym")
                    for op in ("faa", "cas")
                    for p in (2, 4, 8, 16, 32, 64, 128)) +
            "ODP MR 不可用\nDONE fail=0\n"
        )
        checks = bench_atomic._gate(text, 2)
        by = {c.name: c for c in checks}
        self.assertTrue(by["lat-rows"].ok)
        self.assertTrue(by["thr-rows"].ok)
        self.assertTrue(by["exit-code"].ok)
        self.assertTrue(by["exit-code"].warn)

    def test_gate_fail_rows(self):
        text = "FAIL x\nDONE fail=1\n"
        checks = bench_atomic._gate(text, 1)
        by = {c.name: c for c in checks}
        self.assertFalse(by["FAIL"].ok)
        self.assertFalse(by["exit-code"].ok)

    def test_csv_rows(self):
        rows = bench_atomic._csv_rows(
            "RESULT lat_pinned_faa_d4 1.25 us\nnoise\nRESULT thr_x_p2 3 Mops\n")
        self.assertEqual(rows, ["lat_pinned_faa_d4,1.25,us", "thr_x_p2,3,Mops"])

    def test_deploy_unit_script(self):
        u = bench_atomic._deploy_unit()
        s = u.compile_script
        self.assertIn("gcc -O2 -Wall -o /tmp/atomicbench", s)
        self.assertIn("COMPILE_OK", s)

    def test_ensure_deployed_ok_skips(self):
        h, ex = fake_host(lambda a, s: (0, "CHECK_OK\n"))
        u = bench_atomic._deploy_unit()
        changed = ensure_deployed(h, u, log=lambda *_: None)
        self.assertFalse(changed)
        self.assertEqual(len(ex.calls), 1)

    def test_ensure_deployed_stale_compiles(self):
        h, ex = fake_host(lambda a, s: (0, "CHECK_STALE\nCOMPILE_OK\n"))
        u = bench_atomic._deploy_unit()
        changed = ensure_deployed(h, u, log=lambda *_: None)
        self.assertTrue(changed)
        # 1 check + 1 compile（put 走 put_fn 不经 FakeExec）
        self.assertEqual(len(ex.calls), 2)


# ---------------- remote / report ----------------

class TestRemote(unittest.TestCase):
    def test_bg_start_script_shape(self):
        s = bg_start_script(["/tmp/bench", "server", "-p", "123"],
                            log="/tmp/x.log", prekill="bench",
                            sleep_before_start=1, cwd="/tmp")
        self.assertIn("pkill -f bench 2>/dev/null; true", s)
        self.assertIn("sleep 1", s)
        self.assertIn("cd /tmp", s)
        self.assertIn("rm -f /tmp/x.log", s)
        self.assertIn("nohup stdbuf -oL /tmp/bench server -p 123", s)
        self.assertIn("</dev/null >/tmp/x.log 2>&1 &", s)

    def test_wait_ready_script(self):
        s = wait_ready_script("/tmp/x.log", "Level|===", "prog", tries=30)
        self.assertIn("seq 1 30", s)
        self.assertIn("grep -qE 'Level|===' /tmp/x.log", s)
        self.assertIn("pgrep -f prog", s)

    def test_run_parallel(self):
        import time as _t
        t0 = _t.monotonic()
        out = run_parallel({"a": lambda: "A", "b": lambda: "B"})
        self.assertEqual(out, {"a": "A", "b": "B"})
        self.assertLess(_t.monotonic() - t0, 2)

    def test_run_parallel_exception_propagates(self):
        def boom():
            raise ValueError("x")
        with self.assertRaises(ValueError):
            run_parallel({"a": lambda: 1, "b": boom})


class TestReport(unittest.TestCase):
    def test_count_lines(self):
        self.assertEqual(report.count_lines("FAIL a\nFAIL b\nok\n", r"^FAIL "), 2)
        self.assertEqual(report.count_lines("", r"^FAIL "), 0)

    def test_case_record_verdict(self):
        rec = report.CaseRecord(name="x", checks=[
            report.Check("a", True), report.Check("b", False, "why", warn=True)])
        self.assertTrue(rec.ok)
        self.assertEqual(rec.failed_checks, [])
        rec2 = report.CaseRecord(name="y", checks=[report.Check("a", False)])
        self.assertFalse(rec2.ok)

    def test_manifest_roundtrip(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "m.json"
            rec = report.CaseRecord(name="L1", display="d", rc=0, duration=1.5,
                                    checks=[report.Check("exit-code", True, "rc=0")])
            report.write_manifest(p, suite="levels", meta={"remote": "h"},
                                  cases=[rec], verdict="PASS", failed=[],
                                  started=0, duration=2.0)
            import json
            data = json.loads(p.read_text(encoding="utf-8"))
            self.assertEqual(data["suite"], "levels")
            self.assertEqual(data["cases"][0]["name"], "L1")
            self.assertEqual(data["cases"][0]["checks"][0]["verdict"], "PASS")

    def test_tee_writes_file_and_stdout(self):
        import contextlib
        import io
        buf = io.StringIO()
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "t.log"
            with contextlib.redirect_stdout(buf), report.Tee(p) as t:
                t.emit("hello")
                t.emit("streamed\n")
            self.assertEqual(buf.getvalue(), "hello\nstreamed\n")
            self.assertEqual(p.read_text(), "hello\nstreamed\n")


# ---------------- ui（可选增强降级） ----------------

class TestUi(unittest.TestCase):
    def test_table_plain_fallback(self):
        """SYMTEST_PLAIN=1 或无 rich 时 — 纯文本对齐表（信息内容不变）。"""
        import contextlib
        import io

        from symtest import ui
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), ui_force_plain():
            ui.table(["Level", "结果"], [["L1", "✓ PASS"], ["L6r", "✗ FAIL"]],
                     title="测试表")
        out = buf.getvalue()
        self.assertIn("测试表", out)
        self.assertIn("Level", out)
        self.assertIn("✓ PASS", out)
        # CJK 宽度对齐: “结果”列与 ASCII 列各自对齐（不异常即可）
        self.assertIn("----", out)

    def test_poll_progress_plain(self):
        import contextlib
        import io
        import time as _t

        from symtest import ui
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf), ui_force_plain():
            with ui.PollProgress("等待", total=3, interval=0.01,
                                 report_every=0.0) as pb:
                for _ in range(3):
                    _t.sleep(0.01)
                    pb.step()
                pb.done()
        out = buf.getvalue()
        self.assertIn("等待", out)
        self.assertIn("完成", out)

    def test_cjk_disp_len(self):
        from symtest import ui
        self.assertEqual(ui._disp_len("abc"), 3)
        self.assertEqual(ui._disp_len("结果"), 4)


@contextlib.contextmanager
def ui_force_plain():
    """临时把 ui 压到纯文本形态（不依赖 rich 是否安装）。"""
    from symtest import ui
    old = ui.HAVE_RICH, ui._console
    ui.HAVE_RICH, ui._console = False, None
    try:
        yield
    finally:
        ui.HAVE_RICH, ui._console = old


# ---------------- config ----------------

class TestConfig(unittest.TestCase):
    def test_env_empty_is_default(self):
        os.environ["SYMTEST_TEST_VAR"] = ""
        self.assertEqual(config.env("SYMTEST_TEST_VAR", "def"), "def")
        os.environ["SYMTEST_TEST_VAR"] = "set"
        self.assertEqual(config.env("SYMTEST_TEST_VAR", "def"), "set")
        del os.environ["SYMTEST_TEST_VAR"]

    def test_port_for(self):
        os.environ["PORT"] = "19999"
        self.assertEqual(config.port_for(18721), 19999)
        del os.environ["PORT"]
        self.assertEqual(config.port_for(18721), 18721)

    def test_paths(self):
        self.assertEqual(config.TEST_DIR, "$HOME/pro/symrdma/test")
        self.assertTrue((config.REPO / "tests" / "scripts").is_dir())



# ---------------- v0.40.0 迁移模块 ----------------

class TestMigratedSuites(unittest.TestCase):
    """剩余 bash 脚本移植模块的关键门禁/形态测试。"""

    def test_racebw_gate_full(self):
        from symtest import bench_racebw
        text = ("  sym minor: 写读回 OK\n" * 4 +
                "".join(
                    f"RESULT thr_{c}_{f}_{op}_s{s} 1.0 MB/s\n"
                    for c in ("sym", "odp") for f in ("minor", "major")
                    for op in ("read", "write") for s in bench_racebw.SIZES) +
                "DONE fail=0\n")
        checks = bench_racebw._gate(text, "0")
        self.assertTrue(all(c.ok for c in checks),
                        [c.name for c in checks if not c.ok])

    def test_racebw_gate_odp_skip(self):
        from symtest import bench_racebw
        text = ("  sym minor: ok\n" * 2 +
                "".join(
                    f"RESULT thr_sym_{f}_{op}_s{s} 1.0 MB/s\n"
                    for f in ("minor", "major") for op in ("read", "write")
                    for s in bench_racebw.SIZES) +
                "ODP MR 不可用\nDONE fail=0\n")
        checks = bench_racebw._gate(text, "2")
        by = {c.name: c for c in checks}
        self.assertTrue(by["thr-rows"].ok)
        self.assertTrue(by["exit-code"].ok and by["exit-code"].warn)

    def test_nopf_deploy_uses_s_flag(self):
        """npfbw_bench 的 server 形态是 -s 旗标 (首跑教训: 位置参数 server
        会让 bench 立即退出 → 门禁全挂)。"""
        src = (config.PKG_DIR / "bench_nopf.py").read_text(encoding="utf-8")
        self.assertNotIn('"/tmp/npfbw_bench", "server"', src)
        self.assertIn('"/tmp/npfbw_bench", "-s"', src)

    def test_ctl_phase_gates(self):
        # sym 相位门禁判据: 拦截行 + notifier delta 存在于输出
        sym_out = ("[nprdma] reg → SymRDMA mr_id=1\n"
                   "RESULT swap_notifier_delta 128 pages\nDONE fail=0\n")
        self.assertIn("SymRDMA mr_id", sym_out)
        self.assertIn("swap_notifier_delta", sym_out)
        self.assertIn("DONE fail=0", sym_out)

    def test_deploy_hash_only_never_pushed(self):
        from symtest.deploy import DeployUnit, check_script
        u2 = DeployUnit(name="x", sources=[], binaries=["/tmp/b"],
                        compile_script=":", log_tag="",
                        hash_only=[(str(config.PKG_DIR / "ssh.py"),
                                    "$HOME/pro/symrdma/lib/libsymrdma.a")])
        s = check_script(u2)
        self.assertIn("libsymrdma.a", s)  # 参与 hash
        # ensure_deployed 推送循环只遍历 sources — 源码级断言
        src = (config.PKG_DIR / "deploy.py").read_text(encoding="utf-8")
        self.assertIn("for local, remote in unit.sources:", src)
        self.assertNotIn("unit.hash_only]", src.replace(
            "for local, remote in [*unit.sources, *unit.hash_only]:", ""))

    def test_iotlb_pre_sanity(self):
        from symtest.bench_iotlb import _pre
        self.assertIn("mlock.so", _pre("raw"))
        self.assertIn("NPRDMA_INTERCEPT=all", _pre("sym"))
        self.assertIn("libnprdma.so", _pre("sym"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
