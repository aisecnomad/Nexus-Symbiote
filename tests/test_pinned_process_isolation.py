"""Default launches require kernel containment; explicit opt-out is best effort only."""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.live import pinned_process, stdio, verify
from nexus_symbiote.live.pinned_process import isolation_off
from nexus_symbiote.live.session import PinnedStdioSession
from nexus_symbiote.live.stdio import (
    LaunchPolicyError,
    SessionDeadlineError,
    StdioProtocolError,
    observe_pinned,
)
from nexus_symbiote.runtime import AuthorizationError
from tests.test_pinned_stdio import command, inventory, launcher

_SERVE = """
for line in sys.stdin:
    request = json.loads(line)
    method = request.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fixture", "version": "1"},
        }
    elif method == "tools/list":
        result = {"tools": [{"name": "weather", "description": "x", "inputSchema": {"type": "object"}}]}
    else:
        raise SystemExit(1)
    print(json.dumps({"jsonrpc": "2.0", "id": request["id"], "result": result}), flush=True)
"""


def _pinned(path: Path, prelude: str, serve: str = _SERVE) -> tuple[Path, str]:
    """A Python MCP server that runs ``prelude`` first, and its pin."""
    path.write_text(f"#!{sys.executable}\nimport json, os, sys, threading, time\n{prelude}{serve}")
    path.chmod(0o700)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _launcher(tmp_path: Path, marker: Path, *, detached: bool = False) -> tuple[Path, str]:
    return _pinned(
        tmp_path / "launcher",
        f"""marker = {str(marker)!r}
def record():
    # Written whole before it appears, so a reader never sees an empty marker. In a PID
    # namespace only /proc/self holds the host pid; elsewhere there is no namespace.
    host = os.readlink("/proc/self") if sys.platform == "linux" else str(os.getpid())
    open(marker + ".tmp", "w").write(host)
    os.rename(marker + ".tmp", marker)
if os.fork() == 0:
    os.setsid()
    if {detached!r}:
        if os.fork() == 0:
            record()
            time.sleep(60)
        os._exit(0)
    record()
    time.sleep(60)
    raise SystemExit
deadline = time.monotonic() + 10
while not os.path.exists(marker) and time.monotonic() < deadline:
    time.sleep(0.01)
""",
    )


def _watchdog_launcher(tmp_path: Path, helpers: Path) -> tuple[Path, str]:
    """A launcher whose watchdog thread restarts a ``setsid`` helper whenever it exits."""
    return _pinned(
        tmp_path / "watchdog",
        f"""import subprocess
helpers = {str(helpers)!r}
def watchdog():
    while True:
        helper = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(60)"], start_new_session=True
        )
        open(os.path.join(helpers, str(helper.pid)), "w").close()
        helper.wait()
threading.Thread(target=watchdog, daemon=True).start()
while not os.listdir(helpers):
    time.sleep(0.01)
""",
    )


# The host's, read before any test simulates another platform.
_LINUX = sys.platform.startswith("linux")
_LINUX_ONLY = pytest.mark.skipif(not _LINUX, reason="the subreaper wrapper is Linux-only")
_SWEEP_ONLY = pytest.mark.skipif(not _LINUX, reason="the /proc descendant sweep is Linux-only")
_NAMESPACE_ONLY = pytest.mark.skipif(not _LINUX, reason="the PID namespace teardown is Linux-only")


def _host_pid(marker: Path) -> int:
    return int(marker.read_text())


def _stat(pid: int) -> list[str]:
    """The state, parent and later fields of ``/proc/<pid>/stat``; ``["X"]`` once reaped.

    Without /proc only the state is known, from ``ps``, so that a process that is still
    running is never read as reaped.
    """
    if not _LINUX:
        state = subprocess.run(  # noqa: S603
            ["/bin/ps", "-o", "stat=", "-p", str(pid)],
            capture_output=True,
            text=True,
            check=False,
            timeout=10,
        ).stdout.strip()
        return [state[:1] or "X"]
    try:
        with open(f"/proc/{pid}/stat", "rb") as stat:
            return stat.read().rpartition(b")")[2].decode().split()
    except (FileNotFoundError, ProcessLookupError):
        return ["X"]


def _assert_dead(pid: int) -> None:
    """Wait for ``pid`` to exit; a running, sleeping or stopped process still fails.

    The namespace teardown follows the supervisor's death by a short interval. A
    killed orphan stays a zombie until its new parent waits, and a pid 1 that does
    not reap never does, so state Z (or X) counts as dead. ``kill(pid, 0)`` succeeds
    for a zombie and cannot tell the two apart.
    """
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _stat(pid)[0] in {"Z", "X"}:
            return
        time.sleep(0.05)
    raise AssertionError(f"process {pid} was still running")


def test_observe_pinned_requires_containment_or_kills_its_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    if not pinned_process.namespace_available():
        with pytest.raises(LaunchPolicyError) as denied:
            observe_pinned(str(command), digest)
        assert denied.value.reason == "isolation-unavailable"
        assert not marker.exists()
        return
    observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))


def test_a_pinned_session_requires_containment_or_kills_its_descendants(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    session = PinnedStdioSession(command=str(command), sha256=digest, server_id="server:mail")
    if not pinned_process.namespace_available():
        with pytest.raises(AuthorizationError, match="kernel PID containment"), session:
            pass
        assert not marker.exists()
        return
    with session:
        pass
    _assert_dead(_host_pid(marker))


@pytest.mark.parametrize("namespace_available", [False, True])
def test_a_missing_namespace_or_launcher_never_starts_the_pinned_program(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, namespace_available: bool
) -> None:
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: namespace_available)
    if namespace_available:
        monkeypatch.setattr(pinned_process, "_unshare_path", lambda: None)
    starts = []

    def refuse_start(*args, **kwargs):
        starts.append(args)
        raise AssertionError("the pinned program must not be started")

    monkeypatch.setattr(pinned_process.subprocess, "Popen", refuse_start)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with pytest.raises(LaunchPolicyError) as denied:
        observe_pinned(str(command), digest)
    assert denied.value.reason == "isolation-unavailable"
    assert starts == []
    assert not marker.exists()


def test_off_linux_a_default_launch_is_refused_before_anything_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An executable named unshare on a macOS path is not util-linux's, and the teardown
    # that would confirm a namespace ended reads /proc: no probe and no launch may pass.
    def no_probe() -> bool:
        raise AssertionError("no namespace probe runs off Linux")

    monkeypatch.setattr(pinned_process, "_probe_namespace", no_probe)
    monkeypatch.setattr(pinned_process.sys, "platform", "darwin")
    assert pinned_process.namespace_available() is False
    fake = tmp_path / "unshare"
    fake.write_text(_SAME_NAMESPACE_UNSHARE)
    fake.chmod(0o700)
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: True)
    monkeypatch.setattr(pinned_process, "_unshare_path", lambda: str(fake))
    starts: list[object] = []

    def refuse_start(*args: object, **kwargs: object) -> None:
        starts.append(args)
        raise AssertionError("the pinned program must not be started")

    monkeypatch.setattr(pinned_process.subprocess, "Popen", refuse_start)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with pytest.raises(LaunchPolicyError) as denied:
        observe_pinned(str(command), digest)
    assert denied.value.reason == "isolation-unavailable"
    session = PinnedStdioSession(command=str(command), sha256=digest, server_id="server:mail")
    with pytest.raises(AuthorizationError, match="kernel PID containment"), session:
        pass
    assert starts == []
    assert not marker.exists()


def test_off_linux_the_cli_refuses_pinned_execution_without_an_explicit_opt_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process.sys, "platform", "darwin")
    monkeypatch.setattr("nexus_symbiote.supply_chain_cli._running_as_root", lambda: False)
    arguments, _ = command(tmp_path, inventory(), launcher(tmp_path))
    blocked = CliRunner().invoke(main, [*arguments, "--json-output"])
    assert blocked.exit_code == 1, blocked.output
    assert json.loads(blocked.stdout)["results"][0]["reason"] == "isolation-unavailable"


def _recorded_launches(monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    """Every process the pinned launch helpers start, still started for real."""
    launches: list[list[str]] = []
    popen = subprocess.Popen

    def record(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        launches.append(list(argv))
        return popen(argv, **kwargs)

    monkeypatch.setattr(pinned_process.subprocess, "Popen", record)
    return launches


def test_off_linux_verify_live_refuses_the_isolation_opt_out(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Off Linux only killpg would remain, and a setsid child would outlive a session
    # reported as a success, so the opt-out is refused before any launcher runs.
    monkeypatch.setattr(pinned_process.sys, "platform", "darwin")
    monkeypatch.setattr("nexus_symbiote.supply_chain_cli._running_as_root", lambda: True)
    launches = _recorded_launches(monkeypatch)
    arguments, _ = command(tmp_path, inventory(), launcher(tmp_path))
    refused = CliRunner().invoke(main, [*arguments, "--json-output", "--no-isolation"])
    assert refused.exit_code == 1, refused.output
    report = json.loads(refused.stdout)
    assert not report["complete"]
    assert [result["reason"] for result in report["results"]] == ["isolation-unavailable"]
    # The shown remedy must not offer the opt-out that was just refused.
    assert "--no-isolation" not in report["results"][0]["error"]
    stderr = " ".join(refused.stderr.split())
    assert "--no-isolation is refused off Linux" in stderr
    assert "kernel PID containment is disabled" not in stderr
    assert "--no-isolation as root" not in stderr
    assert launches == []


@pytest.mark.parametrize(("platform", "offered"), [("darwin", False), ("linux", True)])
def test_the_isolation_unavailable_remedy_offers_the_opt_out_only_on_linux(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, platform: str, offered: bool
) -> None:
    monkeypatch.setattr(pinned_process.sys, "platform", platform)
    shown = verify.reason_message("isolation-unavailable")
    assert ("--no-isolation" in shown) is offered
    assert "the pinned launcher was not executed" in shown
    # The default launch is refused off Linux as well, and shows the same remedy.
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: False)
    report = verify.verify_mcp_servers(inventory(), trusted_launchers=launcher(tmp_path))
    assert [(r.reason, r.error) for r in report.results] == [("isolation-unavailable", shown)]


def test_off_linux_isolation_off_refuses_every_launch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process.sys, "platform", "darwin")
    launches = _recorded_launches(monkeypatch)
    marker = tmp_path / "pid"
    command_path, digest = _launcher(tmp_path, marker, detached=True)
    with isolation_off():
        assert pinned_process.opt_out_supported() is False
        with pytest.raises(LaunchPolicyError) as denied:
            observe_pinned(str(command_path), digest)
        assert denied.value.reason == "isolation-unavailable"
        session = PinnedStdioSession(
            command=str(command_path), sha256=digest, server_id="server:mail"
        )
        with pytest.raises(AuthorizationError, match="opt-out is refused off Linux"), session:
            pass
        with pytest.raises(pinned_process.PinnedProcessError) as argv_denied:
            pinned_process.isolated_argv(tmp_path / "server")
        assert argv_denied.value.reason == "isolation-unavailable"
    assert launches == []
    time.sleep(0.2)
    assert not marker.exists()


def test_on_linux_the_isolation_opt_out_still_launches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    staged = tmp_path / "server"
    with monkeypatch.context() as linux:
        linux.setattr(pinned_process.sys, "platform", "linux")
        assert pinned_process.opt_out_supported() is True
        with isolation_off():
            argv = pinned_process.isolated_argv(staged)
        assert argv[-1] == str(staged)
    if not _LINUX:
        return
    # On a Linux host the opted-out launch runs, and its double-forked child is killed.
    marker = tmp_path / "pid"
    command_path, digest = _launcher(tmp_path, marker, detached=True)
    with isolation_off():
        observe_pinned(str(command_path), digest)
    _assert_dead(_host_pid(marker))


@pytest.mark.parametrize(
    ("platform", "exited", "raised"),
    [("darwin", True, False), ("darwin", False, True), ("linux", True, True)],
)
def test_only_macos_refusing_to_signal_an_exited_launcher_group_counts_as_ended(
    monkeypatch: pytest.MonkeyPatch, platform: str, exited: bool, raised: bool
) -> None:
    # macOS answers killpg with EPERM when the group holds only the unreaped launcher.
    script = "" if exited else "import time; time.sleep(30)"
    proc = subprocess.Popen([sys.executable, "-c", script], start_new_session=True)  # noqa: S603
    try:
        if exited:
            deadline = time.monotonic() + 10
            while _stat(proc.pid)[0] not in {"Z", "X"} and time.monotonic() < deadline:
                time.sleep(0.01)

        def refuse(pgid: int, sig: int) -> None:
            raise PermissionError(errno.EPERM, "Operation not permitted")

        monkeypatch.setattr(pinned_process.sys, "platform", platform)
        monkeypatch.setattr(pinned_process.os, "killpg", refuse)
        monkeypatch.setattr(pinned_process, "_kill_descendants", lambda root: None)
        monkeypatch.setattr(pinned_process, "_kill_session", lambda sid: None)
        # The stop needs os.waitid, which macOS has only from Python 3.13.
        monkeypatch.setattr(pinned_process, "_stop_launcher", lambda pid: None)
        if raised:
            with pytest.raises(PermissionError):
                pinned_process.terminate_process_group(proc)
        else:
            pinned_process.terminate_process_group(proc)
            assert proc.returncode == 0
    finally:
        monkeypatch.undo()
        with contextlib.suppress(ProcessLookupError):
            os.kill(proc.pid, signal.SIGKILL)
        proc.wait(timeout=5)


def test_a_finished_pid_is_not_remembered_as_namespaced() -> None:
    proc = subprocess.Popen([sys.executable, "-c", ""], start_new_session=True)  # noqa: S603
    proc.wait(timeout=5)
    pinned_process._NAMESPACED.add(proc.pid)
    pinned_process.terminate_process_group(proc)
    assert proc.pid not in pinned_process._NAMESPACED


def test_teardown_leaves_the_exit_status_of_another_child() -> None:
    # Code elsewhere in the process, such as the validation worker, trusts its child's
    # exit status; reaping every zombie child would turn this 3 into 0.
    other = subprocess.Popen([sys.executable, "-c", "raise SystemExit(3)"])  # noqa: S603
    if hasattr(os, "waitid"):
        os.waitid(os.P_PID, other.pid, os.WEXITED | os.WNOWAIT)
    else:  # pragma: no cover - macOS before Python 3.13
        time.sleep(1)
    proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)  # noqa: S603
    try:
        pinned_process.terminate_process_group(proc)
    finally:
        proc.wait(timeout=5)
    assert other.wait(timeout=5) == 3


def test_a_forgotten_pid_is_swept_again_when_reused(monkeypatch: pytest.MonkeyPatch) -> None:
    swept: list[int] = []
    monkeypatch.setattr(pinned_process, "_kill_descendants", swept.append)
    proc = subprocess.Popen([sys.executable, "-c", ""], start_new_session=True)  # noqa: S603
    proc.wait(timeout=5)
    pinned_process._NAMESPACED.add(proc.pid)
    pinned_process.terminate_process_group(proc)
    assert swept == []
    pinned_process.terminate_process_group(proc)
    assert swept == [proc.pid, proc.pid]


@_LINUX_ONLY
def test_opt_out_kills_a_double_fork(tmp_path: Path) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker, detached=True)
    with isolation_off():
        observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))


def test_a_refused_namespace_never_starts_a_double_fork(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: False)
    off = tmp_path / "off"
    off.mkdir()
    blocked = off / "pid"
    blocked_command, blocked_digest = _launcher(off, blocked, detached=True)
    with pytest.raises(LaunchPolicyError) as denied:
        observe_pinned(str(blocked_command), blocked_digest)
    assert denied.value.reason == "isolation-unavailable"
    assert not blocked.exists()


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="clone(CLONE_PARENT) is Linux-only"
)
def test_opt_out_kills_a_clone_parent_child_that_leaves_the_session(tmp_path: Path) -> None:
    """``clone(CLONE_PARENT)`` plus ``setsid`` reparents to the supervisor and leaves the group.

    The descendant sweep does not see it, and ``killpg`` does not signal the new session.
    """
    marker = tmp_path / "pid"
    command, digest = _pinned(
        tmp_path / "launcher",
        f"""
import ctypes
marker = {str(marker)!r}
CLONE_PARENT = 0x00008000
stack = ctypes.create_string_buffer(1024 * 1024)
libc = ctypes.CDLL(None, use_errno=True)
def child(_):
    try:
        os.setsid()
    except OSError:
        pass
    # Written whole, then renamed, so the supervisor never reads a partial pid.
    with open(marker + ".tmp", "w") as out:
        out.write(str(os.getpid()))
    os.replace(marker + ".tmp", marker)
    time.sleep(60)
    return 0
callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(child)
sys._keep = (callback, stack)
cloned = libc.clone(
    callback, ctypes.c_void_p(ctypes.addressof(stack) + len(stack)), CLONE_PARENT, None
)
if cloned < 0:
    raise SystemExit(1)
# The child must have recorded its pid before the session can end, or a loaded runner
# kills it first and the test learns nothing.
for _ in range(1000):
    if os.path.exists(marker):
        break
    time.sleep(0.01)
""",
    )
    with isolation_off():
        observe_pinned(str(command), digest)
    assert marker.exists(), "the clone(CLONE_PARENT) child did not start within 10 seconds"
    try:
        _assert_dead(_host_pid(marker))
    finally:
        # A failed run must not leave the escaped child alive for the rest of the suite.
        with contextlib.suppress(ProcessLookupError, ValueError, OSError):
            os.kill(_host_pid(marker), signal.SIGKILL)


@_SWEEP_ONLY
def test_opt_out_stops_the_launcher_before_its_tree_is_swept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The watchdog restarts its helper whenever the sweep kills it. A launcher that still
    # runs after the sweep starts another one in a new session, which pid 1 adopts once
    # killpg kills the launcher, out of reach of the second sweep. Cleanup must stop the
    # launcher first. Real timing opens that window only in some runs, so killpg here
    # waits until a running launcher has started such a helper, and returns once the
    # helper has been reparented, as a preempted cleanup thread would.
    helpers = tmp_path / "helpers"
    helpers.mkdir()
    command, digest = _watchdog_launcher(tmp_path, helpers)
    killpg = os.killpg
    late: set[int] = set()

    def preempted_killpg(pgid: int, sig: int) -> None:
        deadline = time.monotonic() + 5
        while not late and _stat(pgid)[0] not in {"T", "Z", "X"}:
            for pid in pinned_process._descendant_pids(pgid):
                fields = _stat(pid)
                # Alive, and leading its own session, so killpg does not reach it.
                if fields[0] not in {"Z", "X"} and fields[3] == str(pid):
                    late.add(pid)
            if time.monotonic() > deadline:
                break
            time.sleep(0.005)
        killpg(pgid, sig)
        while any(_stat(pid)[1:2] == [str(pgid)] for pid in late):
            if time.monotonic() > deadline:
                break
            time.sleep(0.005)

    monkeypatch.setattr(pinned_process.os, "killpg", preempted_killpg)
    try:
        with isolation_off():
            observe_pinned(str(command), digest)
        started = {int(entry.name) for entry in helpers.iterdir()}
        assert started
        for pid in sorted(started | late):
            _assert_dead(pid)
    finally:
        for pid in {int(entry.name) for entry in helpers.iterdir()} | late:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


@_LINUX_ONLY
def test_a_launcher_that_does_not_stop_is_still_killed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A tracer can swallow SIGSTOP. The wait for the stop is bounded, and the running
    # launcher still adopts its double-forked grandchild until the sweep kills it.
    kill = os.kill

    def swallow_stop(pid: int, sig: int) -> None:
        if sig != signal.SIGSTOP:
            kill(pid, sig)

    monkeypatch.setattr(pinned_process.os, "kill", swallow_stop)
    monkeypatch.setattr(pinned_process, "_STOP_SECONDS", 0.2)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker, detached=True)
    started = time.monotonic()
    with isolation_off():
        observe_pinned(str(command), digest)
    assert time.monotonic() - started < 10
    _assert_dead(_host_pid(marker))


def test_cleanup_elsewhere_than_linux_does_not_stop_the_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Python before 3.13 has no os.waitid on macOS, and the sweep that the stop serves
    # reads Linux's /proc. Without them a setsid child outlived the cleanup, so the opt-out
    # is refused there before anything runs, and nothing is left to stop or signal.
    monkeypatch.setattr(pinned_process.sys, "platform", "darwin")
    monkeypatch.delattr(pinned_process.os, "waitid", raising=False)
    kill = os.kill
    sent: list[int] = []

    def record(pid: int, sig: int) -> None:
        sent.append(sig)
        kill(pid, sig)

    monkeypatch.setattr(pinned_process.os, "kill", record)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with isolation_off(), pytest.raises(LaunchPolicyError) as denied:
        observe_pinned(str(command), digest)
    assert denied.value.reason == "isolation-unavailable"
    assert sent == []
    time.sleep(0.2)
    assert not marker.exists()


class _NoPrctl:
    """A C library without prctl, as on macOS."""

    def __init__(self, *args: object, **kwargs: object) -> None:
        pass

    def __getattr__(self, name: str) -> object:
        raise AttributeError(name)


@pytest.mark.parametrize(
    ("attribute", "value"),
    [
        ("CDLL", _NoPrctl),
        ("platform", "darwin"),
        ("frozen", True),
        ("executable", ""),
        ("executable", "python3"),
    ],
)
def test_subreaper_wrapper_needs_linux_prctl_and_an_interpreter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, attribute: str, value: object
) -> None:
    staged = tmp_path / "server"
    if not _LINUX:
        # This host is the case the parameters simulate: no wrapper, and the opt-out is
        # refused rather than run as a direct exec.
        assert pinned_process._subreaper_argv(staged) is None
        with isolation_off(), pytest.raises(pinned_process.PinnedProcessError) as denied:
            pinned_process.isolated_argv(staged)
        assert denied.value.reason == "isolation-unavailable"
        return
    assert pinned_process._subreaper_argv(staged) == [
        sys.executable,
        "-I",
        "-S",
        "-B",
        "-c",
        pinned_process._SUBREAPER_EXEC,
        str(staged),
    ]
    owner = pinned_process.ctypes if attribute == "CDLL" else pinned_process.sys
    monkeypatch.setattr(owner, attribute, value, raising=False)
    assert pinned_process._subreaper_argv(staged) is None
    with isolation_off():
        if attribute == "platform":
            # Off Linux the opt-out is refused rather than run as a direct exec.
            with pytest.raises(pinned_process.PinnedProcessError) as denied:
                pinned_process.isolated_argv(staged)
            assert denied.value.reason == "isolation-unavailable"
        else:
            assert pinned_process.isolated_argv(staged) == [str(staged)]


@_SWEEP_ONLY
def test_opt_out_without_prctl_still_launches_and_cleans_up(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Without prctl the launch skips the subreaper wrapper and keeps best-effort cleanup.
    monkeypatch.setattr(pinned_process.ctypes, "CDLL", _NoPrctl)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    with isolation_off():
        observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))


def test_cli_requires_an_explicit_opt_out_when_the_namespace_is_unavailable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: False)
    monkeypatch.setattr("nexus_symbiote.supply_chain_cli._running_as_root", lambda: False)
    arguments, _ = command(tmp_path, inventory(), launcher(tmp_path))
    blocked = CliRunner().invoke(main, [*arguments, "--json-output"])
    assert blocked.exit_code == 1, blocked.output
    assert json.loads(blocked.stdout)["results"][0]["reason"] == "isolation-unavailable"
    allowed = CliRunner().invoke(main, [*arguments, "--json-output", "--no-isolation"])
    usage = " ".join(CliRunner().invoke(main, ["verify-live", "--help"]).output.split())
    assert "Refused off Linux, where no launcher runs" in usage
    texts = [usage]
    if _LINUX:
        assert allowed.exit_code == 0, allowed.output
        assert "kernel PID containment is disabled" in allowed.stderr
        texts.append(" ".join(allowed.stderr.split()))
    else:
        # The opt-out is refused here before any launcher runs.
        assert allowed.exit_code == 1, allowed.output
        assert json.loads(allowed.stdout)["results"][0]["reason"] == "isolation-unavailable"
        assert "--no-isolation is refused off Linux" in " ".join(allowed.stderr.split())
    for text in texts:
        assert "its own process group" in text
        assert "stays its parent as a child subreaper" in text
        assert "ignores the signals it can" in text
        assert "clone(CLONE_PARENT)" in text
        assert "kills its wrapper with SIGKILL can escape" in text
        assert "isolation-teardown-failed" in text
        assert "unless the launcher runs as root" in text
        assert "Never opt out as root" in text
        assert "cgroup v2" in text
        assert "not a namespace or sandbox" in text
    assert "--no-isolation as root" not in allowed.stderr


@_LINUX_ONLY
def test_a_descendant_that_cannot_be_signalled_does_not_abort_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    kill, killpg = os.kill, os.killpg
    groups: list[int] = []

    def refuse(pid: int, sig: int) -> None:
        if marker.exists() and pid == _host_pid(marker):
            raise PermissionError(1, "Operation not permitted")
        kill(pid, sig)

    def record(pgid: int, sig: int) -> None:
        groups.append(pgid)
        killpg(pgid, sig)

    monkeypatch.setattr(pinned_process.os, "kill", refuse)
    monkeypatch.setattr(pinned_process.os, "killpg", record)
    # No cgroup.kill, which would end the child without os.kill; a short drain deadline.
    monkeypatch.setattr(pinned_process, "_prepare_cgroup", lambda work: None)
    monkeypatch.setattr(pinned_process, "_TEARDOWN_SECONDS", 0.5)
    try:
        with isolation_off(), pytest.raises(LaunchPolicyError) as failed:
            observe_pinned(str(command), digest)
    finally:
        monkeypatch.undo()
        with contextlib.suppress(ProcessLookupError, FileNotFoundError, ValueError):
            kill(_host_pid(marker), signal.SIGKILL)
    # Cleanup still ran to the end, and the child it could not signal may still be
    # running, so the session fails closed instead of reporting success.
    assert failed.value.reason == "isolation-teardown-failed"
    assert len(groups) == 1
    _assert_dead(groups[0])


@_SWEEP_ONLY
def test_a_process_name_that_is_not_utf8_does_not_end_the_descendant_scan() -> None:
    """/proc/<pid>/status holds the name as raw bytes, and any process may set its own."""
    rename = "import ctypes, time; ctypes.CDLL(None).prctl(15, b'caf\\xe9', 0, 0, 0); "
    child = subprocess.Popen(  # noqa: S603
        [sys.executable, "-c", rename + "print('named', flush=True); time.sleep(30)"],
        stdout=subprocess.PIPE,
    )
    try:
        assert child.stdout is not None and child.stdout.readline() == b"named\n"
        assert Path(f"/proc/{child.pid}/comm").read_bytes() == b"caf\xe9\n"
        assert child.pid in pinned_process._descendant_pids(os.getpid())
    finally:
        child.kill()
        child.wait(timeout=5)


def test_the_launcher_group_is_killed_when_the_sweep_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    killpg = os.killpg
    groups: list[int] = []

    def record(pgid: int, sig: int) -> None:
        groups.append(pgid)
        killpg(pgid, sig)

    def fail(root: int) -> None:
        raise RuntimeError("sweep failed")

    monkeypatch.setattr(pinned_process, "_kill_descendants", fail)
    monkeypatch.setattr(pinned_process.os, "killpg", record)
    proc = subprocess.Popen(["/bin/sleep", "30"], start_new_session=True)  # noqa: S603
    try:
        with pytest.raises(RuntimeError, match="sweep failed"):
            pinned_process.terminate_process_group(proc)
    finally:
        monkeypatch.undo()
        # macOS refuses killpg for a group that holds only the killed, unreaped leader.
        with contextlib.suppress(ProcessLookupError, PermissionError):
            killpg(proc.pid, signal.SIGKILL)
    assert groups == [proc.pid]
    assert proc.wait(timeout=5) == -signal.SIGKILL


@_LINUX_ONLY
def test_no_launch_runs_python_between_fork_and_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # preexec_fn is unsafe in a threaded caller, and Popen waits for it before any
    # protocol deadline exists. The opt-out instead executes a fixed wrapper.
    launches: list[tuple[list[str], dict[str, Any]]] = []
    popen = subprocess.Popen

    def record(argv: list[str], **kwargs: Any) -> subprocess.Popen[bytes]:
        launches.append((argv, kwargs))
        return popen(argv, **kwargs)

    monkeypatch.setattr(pinned_process.subprocess, "Popen", record)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker, detached=True)
    with isolation_off():
        observe_pinned(str(command), digest)
    _assert_dead(_host_pid(marker))
    argv, kwargs = launches[-1]
    if pinned_process.namespace_available():
        observe_pinned(str(command), digest)
    assert all(options.get("preexec_fn") is None for _, options in launches)
    wrapper = [sys.executable, "-I", "-S", "-B", "-c", pinned_process._SUBREAPER_EXEC]
    # The wrapper writes its last byte to the descriptor after the launcher, and must
    # have this process as its parent.
    server = str(Path(kwargs["cwd"]) / "server")
    assert argv == [*wrapper, server, str(kwargs["pass_fds"][0]), str(os.getpid())]
    assert kwargs["env"] == {"PATH": os.defpath}
    assert kwargs["start_new_session"] is True


# The signal lines are read with builtins before the shell first forks. dash blocks
# every signal around a fork and clears its mask afterwards, so a later read shows
# either of those masks, never the one the launcher inherited. The shell applies a
# redirection to itself while the redirected command runs, so the descriptors are
# read in a command substitution outside any redirected command. In a PID namespace
# $$ is 1 while /proc shows host pids, so the host pid comes from /proc/self.
STATE = r"""#!/bin/sh
read -r pid rest < /proc/self/stat
signals=
while read -r key value; do
  case $key in SigBlk:|SigIgn:) signals="$signals$key $value
" ;; esac
done < /proc/$pid/status
fds=$(readlink /proc/$pid/cwd /proc/$pid/fd/0 /proc/$pid/fd/1 /proc/$pid/fd/2)
tr '\0' '\n' < /proc/$pid/environ >> OUT
printf '%s' "$signals" >> OUT
tr '\0' '\n' < /proc/$pid/cmdline >> OUT
printf '%s\n' "$fds" >> OUT
cat /proc/$pid/stat >> OUT
"""
# Each wrapper program and the function that selects it; the gate runs only in a namespace.
_WRAPPERS = {
    "subreaper": ("_SUBREAPER_EXEC", "_subreaper_argv"),
    "gate": ("_GATE_EXEC", "_gate_argv"),
}


def _launch_state(
    tmp_path: Path, name: str, *, namespaced: bool = False, wrapped: bool = True
) -> list[str]:
    out = tmp_path / f"{name}.state"
    script = tmp_path / name
    script.write_text(STATE.replace("OUT", shlex.quote(str(out))))
    script.chmod(0o700)
    pin = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    launch = contextlib.nullcontext() if namespaced else isolation_off()
    with launch, pytest.raises(StdioProtocolError):
        observe_pinned(str(script), pin)
    *lines, stat = out.read_text().splitlines()
    pid = stat.split()[0]
    parent, *group = stat.rpartition(")")[2].split()[1:4]
    if namespaced:
        # In a namespace, unshare leads the session.
        assert group != [pid, pid]
    elif wrapped:
        # Opted out, the subreaper wrapper stays the launcher's parent and leads its
        # session, and the launcher leads its own group, which the wrapper is not in.
        assert group == [pid, parent]
    else:
        assert group == [pid, pid]
    work = re.compile(r"\S*/nexus-live-\w+")
    return [re.sub(r"pipe:\[\d+\]", "pipe", work.sub("WORK", line)) for line in lines]


def _wrapped_and_direct(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wrapper: str = "subreaper"
) -> tuple[list[str], list[str], set[int]]:
    """The launch state through the wrapper and by direct exec, and the blocked signals.

    The launcher inherits the calling thread's blocked signals, so one is blocked here
    to show that the mask reaches the launcher, and a mask the wrapper adds would not.
    """
    namespaced = wrapper == "gate"
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR2})
    try:
        wrapped = _launch_state(tmp_path, "wrapped", namespaced=namespaced)
        with monkeypatch.context() as direct_exec:
            direct_exec.setattr(pinned_process, _WRAPPERS[wrapper][1], lambda staged: None)
            direct = _launch_state(tmp_path, "direct", namespaced=namespaced, wrapped=False)
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)
    return wrapped, direct, {*previous, signal.SIGUSR2}


def _refuses_without_a_namespace(tmp_path: Path) -> bool:
    """Where the kernel refuses the namespace, check that and report it."""
    if pinned_process.namespace_available():
        return False
    command, digest = _pinned(tmp_path / "refused", "")
    with pytest.raises(LaunchPolicyError) as denied:
        observe_pinned(str(command), digest)
    assert denied.value.reason == "isolation-unavailable"
    return True


@pytest.mark.parametrize("wrapper", sorted(_WRAPPERS))
def test_each_wrapper_hands_over_the_state_of_a_direct_exec(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wrapper: str
) -> None:
    if wrapper == "gate" and _refuses_without_a_namespace(tmp_path):
        return
    if not _LINUX:
        pytest.skip("the subreaper wrapper is Linux-only")
    wrapped, direct, blocked = _wrapped_and_direct(tmp_path, monkeypatch, wrapper)
    assert wrapped == direct
    assert wrapped[0] == f"PATH={os.defpath}"
    mask = sum(1 << (number - 1) for number in blocked)
    assert wrapped[1].split() == ["SigBlk:", f"{mask:016x}"]
    assert wrapped[2].split(":")[0] == "SigIgn"
    assert wrapped[3:] == ["/bin/sh", "WORK/server", "WORK", "pipe", "pipe", "/dev/null"]


@pytest.mark.parametrize(
    ("restored", "leak"),
    [
        ("os.execve(", "signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGUSR1})\nos.execve("),
        ("signal.signal(signal.SIGPIPE, signal.SIG_DFL)\n", ""),
        ("signal.signal(signal.SIGXFSZ, signal.SIG_DFL)\n", ""),
        ('{"PATH": os.defpath}', "os.environ"),
    ],
    ids=["blocked-signal", "ignored-sigpipe", "ignored-sigxfsz", "environment"],
)
@pytest.mark.parametrize("wrapper", sorted(_WRAPPERS))
def test_the_launch_state_comparison_detects_a_wrapper_that_leaks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, restored: str, leak: str, wrapper: str
) -> None:
    if wrapper == "gate" and _refuses_without_a_namespace(tmp_path):
        return
    if not _LINUX:
        pytest.skip("the subreaper wrapper is Linux-only")
    program = _WRAPPERS[wrapper][0]
    leaky = getattr(pinned_process, program).replace(restored, leak)
    assert leaky != getattr(pinned_process, program)
    monkeypatch.setattr(pinned_process, program, leaky)
    wrapped, direct, _ = _wrapped_and_direct(tmp_path, monkeypatch, wrapper)
    assert wrapped != direct


@_LINUX_ONLY
def test_a_stalled_subreaper_wrapper_is_bounded_by_the_protocol_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process, "_SUBREAPER_EXEC", "import time; time.sleep(60)")
    monkeypatch.setattr(stdio, "DEADLINE_SECONDS", 1.0)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    started = time.monotonic()
    with isolation_off(), pytest.raises(SessionDeadlineError):
        observe_pinned(str(command), digest)
    assert time.monotonic() - started < 10
    assert not marker.exists()


# A launcher, or a library it loads, can clear the parent-death signal that
# ``--kill-child`` sets and leave the process group that killpg reaches, or kill
# ``unshare`` through that group. Each variant records the host pid of every process it
# wants to outlive the session.
_ESCAPE = """import ctypes
libc = ctypes.CDLL(None, use_errno=True)
libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
pids = {pids!r}
def record():
    open(os.path.join(pids, os.readlink("/proc/self")), "w").close()
if libc.prctl(1, 0, 0, 0, 0) != 0:
    raise SystemExit(3)
{leave}
record()
{spawn}
deadline = time.monotonic() + 5
while len(os.listdir(pids)) < {count} and time.monotonic() < deadline:
    time.sleep(0.01)
"""
_FORKED = """if os.fork() == 0:
    os.setsid()
    record()
    time.sleep(60)
    os._exit(0)
"""
_DAEMON = """if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        record()
        time.sleep(60)
    os._exit(0)
"""
# The launcher is root in its user namespace, so it can start a nested PID namespace.
_NESTED = """if libc.unshare(0x20000000) != 0:
    raise SystemExit(4)
if os.fork() == 0:
    record()
    time.sleep(60)
    os._exit(0)
"""
# A child left in unshare's process group kills that group, unshare included, once the
# init has left it. The init then waits until it has been reparented, comparing with
# the parent it had before the child could run.
_GROUP_KILL = """def parent():
    with open("/proc/self/stat", "rb") as stat:
        return stat.read().rpartition(b")")[2].split()[1]
first = parent()
if os.fork() == 0:
    for _ in range(500):
        if os.getpgid(1) == 1:
            break
        time.sleep(0.01)
    os.kill(0, 9)
os.setsid()
"""
_ORPHANED = """deadline = time.monotonic() + 5
while parent() == first and time.monotonic() < deadline:
    time.sleep(0.01)
if parent() != first:
    open(os.path.join(os.path.dirname(pids), "orphaned"), "w").close()
"""
# A command name that is not UTF-8, which the forked child inherits.
_RENAMED = """os.setsid()
with open("/proc/self/comm", "wb") as comm:
    comm.write(b"\\xff\\xfe\\x80name")
"""
_ESCAPES = {
    "setsid": ("os.setsid()", "", 1),
    "setpgid": ("os.setpgid(0, 0)", "", 1),
    "setsid-child": ("os.setsid()", _FORKED, 2),
    "setsid-double-fork": ("os.setsid()", _DAEMON, 2),
    "nested-pid-namespace": ("os.setsid()", _NESTED, 2),
    "process-group-kill": (_GROUP_KILL, _ORPHANED, 1),
    "undecodable-name": (_RENAMED, _FORKED, 2),
}
# Without a pidfd for the init, an unshare killed before cleanup is reported instead.
_ENDED_ESCAPES = [
    (variant, held)
    for variant in sorted(_ESCAPES)
    for held in (True, False)
    if held or variant != "process-group-kill"
]


def _escaping_launcher(tmp_path: Path, variant: str) -> tuple[Path, str, Path, int]:
    pids = tmp_path / "pids"
    pids.mkdir()
    leave, spawn, count = _ESCAPES[variant]
    prelude = _ESCAPE.format(pids=str(pids), leave=leave, spawn=spawn, count=count)
    # Outlive the end of stdin as well, in case cleanup closes it first.
    command, digest = _pinned(tmp_path / "launcher", prelude, _SERVE + "time.sleep(60)\n")
    return command, digest, pids, count


def _recorded(pids: Path) -> list[int]:
    return sorted(int(entry.name) for entry in pids.iterdir())


def _kill_leftovers(pids: Path) -> None:
    for pid in _recorded(pids):
        if _stat(pid)[0] not in {"Z", "X"}:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


def _without_init_pidfd(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start the init at once, as without a runnable interpreter, so no pidfd is held."""
    monkeypatch.setattr(pinned_process, "_gate_argv", lambda staged: None)


@pytest.mark.parametrize("entry", ["observe_pinned", "PinnedStdioSession"])
@pytest.mark.parametrize(
    ("variant", "held"),
    _ENDED_ESCAPES,
    ids=[f"{variant}-{'held' if held else 'unheld'}" for variant, held in _ENDED_ESCAPES],
)
def test_a_launcher_that_drops_its_death_signal_and_group_ends_with_the_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, variant: str, held: bool, entry: str
) -> None:
    command, digest, pids, count = _escaping_launcher(tmp_path, variant)
    if not pinned_process.namespace_available():
        with pytest.raises(LaunchPolicyError) as denied:
            observe_pinned(str(command), digest)
        assert denied.value.reason == "isolation-unavailable"
        assert _recorded(pids) == []
        return
    if not held:
        _without_init_pidfd(monkeypatch)
    try:
        if entry == "observe_pinned":
            assert [tool["name"] for tool in observe_pinned(str(command), digest).tools] == [
                "weather"
            ]
        else:
            session = PinnedStdioSession(
                command=str(command), sha256=digest, server_id="server:mail"
            )
            with session:
                assert session._process is not None
                assert (session._process.pid in pinned_process._INITS) is held
        recorded = _recorded(pids)
        assert len(recorded) == count
        # Cleanup returns only once the kernel has ended the namespace, so there is no
        # grace period here.
        states = {pid: _stat(pid)[0] for pid in recorded}
        assert set(states.values()) <= {"Z", "X"}, states
        assert (tmp_path / "orphaned").exists() is (variant == "process-group-kill")
        assert not pinned_process._INITS
    finally:
        _kill_leftovers(pids)


@pytest.mark.parametrize("entry", ["observe_pinned", "PinnedStdioSession"])
def test_without_an_init_pidfd_a_killed_unshare_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, entry: str
) -> None:
    command, digest, pids, _ = _escaping_launcher(tmp_path, "process-group-kill")
    if not pinned_process.namespace_available():
        with pytest.raises(LaunchPolicyError) as denied:
            observe_pinned(str(command), digest)
        assert denied.value.reason == "isolation-unavailable"
        return
    _without_init_pidfd(monkeypatch)
    try:
        if entry == "observe_pinned":
            with pytest.raises(LaunchPolicyError) as failed:
                observe_pinned(str(command), digest)
            assert failed.value.reason == "isolation-teardown-failed"
        else:
            session = PinnedStdioSession(
                command=str(command), sha256=digest, server_id="server:mail"
            )
            with pytest.raises(AuthorizationError, match="could not be confirmed ended"), session:
                pass
        assert (tmp_path / "orphaned").exists()
    finally:
        _kill_leftovers(pids)


def test_without_pidfd_open_the_init_is_ended_through_a_stopped_unshare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unsupported(pid: int, flags: int = 0) -> int:
        raise OSError(errno.ENOSYS, "Function not implemented")

    command, digest, pids, count = _escaping_launcher(tmp_path, "setsid-double-fork")
    if _refuses_without_a_namespace(tmp_path):
        return
    monkeypatch.setattr(pinned_process.os, "pidfd_open", unsupported)
    try:
        observe_pinned(str(command), digest)
        recorded = _recorded(pids)
        assert len(recorded) == count
        assert {_stat(pid)[0] for pid in recorded} <= {"Z", "X"}
    finally:
        _kill_leftovers(pids)


# Not UTF-8, with a newline, and mimicking the fields that follow the name in /proc/<pid>/stat.
_UNDECODABLE_NAME = b"\xff\n) Z 1 (\xfe"


@pytest.fixture
def undecodable_bystander() -> Iterator[int]:
    """A process outside every session whose command name is not UTF-8."""
    if not _LINUX:
        pytest.skip("the /proc descendant sweep is Linux-only")
    proc = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-I",
            "-S",
            "-c",
            "import sys, time\n"
            "open('/proc/self/comm', 'wb').write(bytes.fromhex(sys.argv[1]))\n"
            "time.sleep(60)\n",
            _UNDECODABLE_NAME.hex(),
        ]
    )
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            with open(f"/proc/{proc.pid}/comm", "rb") as comm:
                if comm.read() == _UNDECODABLE_NAME + b"\n":
                    break
            time.sleep(0.01)
        yield proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=5)


def test_the_process_scan_reads_names_that_are_not_utf8(undecodable_bystander: int) -> None:
    assert undecodable_bystander in pinned_process._children_by_parent()[os.getpid()]
    assert pinned_process._parent(undecodable_bystander) == os.getpid()
    status = pinned_process._status(undecodable_bystander)
    assert status is not None
    assert status["PPid"] == str(os.getpid())
    assert pinned_process._ended(undecodable_bystander) is False


@pytest.mark.parametrize("mode", ["held", "unheld", "opted-out"])
def test_a_process_name_that_is_not_utf8_does_not_stop_cleanup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, undecodable_bystander: int, mode: str
) -> None:
    if mode == "opted-out":
        marker = tmp_path / "pid"
        command, digest = _launcher(tmp_path, marker, detached=True)
        with isolation_off():
            observe_pinned(str(command), digest)
        _assert_dead(_host_pid(marker))
        return
    command, digest, pids, count = _escaping_launcher(tmp_path, "setsid-double-fork")
    if _refuses_without_a_namespace(tmp_path):
        return
    if mode == "unheld":
        _without_init_pidfd(monkeypatch)
    try:
        observe_pinned(str(command), digest)
        recorded = _recorded(pids)
        assert len(recorded) == count
        assert {_stat(pid)[0] for pid in recorded} <= {"Z", "X"}
    finally:
        _kill_leftovers(pids)


def test_a_launcher_that_exits_after_its_reply_is_not_a_teardown_failure(tmp_path: Path) -> None:
    serve = _SERVE.replace(
        "flush=True)\n", 'flush=True)\n    if method == "tools/list":\n        os._exit(0)\n'
    )
    command, digest = _pinned(tmp_path / "launcher", "", serve)
    if not pinned_process.namespace_available():
        with pytest.raises(LaunchPolicyError, match="kernel PID containment"):
            observe_pinned(str(command), digest)
        return
    for _ in range(5):
        assert [tool["name"] for tool in observe_pinned(str(command), digest).tools] == ["weather"]


# A stand-in for ``unshare --fork`` that needs no namespace: it waits for a child that
# has left its session, as a namespace init that called setsid has.
_SUPERVISOR = """import os, sys, time
if sys.argv[2] == "idle":
    time.sleep(60)
child = os.fork()
if child == 0:
    os.setsid()
    open(sys.argv[1], "w").write(str(os.getpid()))
    if sys.argv[2] == "exit":
        os._exit(0)
    time.sleep(60)
    os._exit(0)
os.waitpid(child, 0)
"""


def _supervised(tmp_path: Path, mode: str = "wait") -> tuple[subprocess.Popen[bytes], int | None]:
    """A process marked as ``unshare``, and the pid of its child once it has one."""
    marker = tmp_path / "init"
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-I", "-S", "-c", _SUPERVISOR, str(marker), mode],
        start_new_session=True,
    )
    pinned_process._NAMESPACED.add(proc.pid)
    if mode == "idle":
        return proc, None
    deadline = time.monotonic() + 10
    while not (marker.exists() and marker.read_text()) and time.monotonic() < deadline:
        time.sleep(0.01)
    if mode == "exit":
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT)
    return proc, int(marker.read_text())


def _end_supervised(proc: subprocess.Popen[bytes], init: int | None) -> None:
    pinned_process._NAMESPACED.discard(proc.pid)
    for pid in (proc.pid, init):
        if pid is not None and _stat(pid)[0] not in {"Z", "X"}:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
    proc.wait(timeout=5)


@_NAMESPACE_ONLY
def test_namespaced_cleanup_kills_an_init_that_left_the_process_group(tmp_path: Path) -> None:
    proc, init = _supervised(tmp_path)
    assert init is not None
    try:
        pinned_process.terminate_process_group(proc)
        assert proc.wait(timeout=5) == -signal.SIGKILL
        assert _stat(init)[0] in {"Z", "X"}
        assert proc.pid not in pinned_process._NAMESPACED
    finally:
        _end_supervised(proc, init)


@_NAMESPACE_ONLY
@pytest.mark.parametrize("held", [True, False])
def test_an_init_that_outlived_a_killed_unshare_is_ended_or_reported(
    tmp_path: Path, held: bool
) -> None:
    # A process left in unshare's process group can kill unshare with kill(0, SIGKILL)
    # after the init has cleared its parent-death signal and called setsid. unshare
    # then reports CLD_KILLED, as it does when it re-raises the signal that ended the
    # init, so only a pidfd taken at launch can still reach the init.
    proc, init = _supervised(tmp_path)
    assert init is not None
    try:
        if held:
            pinned_process._INITS[proc.pid] = os.pidfd_open(init)
        os.kill(proc.pid, signal.SIGKILL)
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT)
        assert _stat(init)[0] not in {"Z", "X"}
        if held:
            pinned_process.terminate_process_group(proc)
            assert _stat(init)[0] in {"Z", "X"}
        else:
            with pytest.raises(pinned_process.PinnedProcessError) as failed:
                pinned_process.terminate_process_group(proc)
            assert failed.value.reason == "isolation-teardown-failed"
        assert proc.wait(timeout=5) == -signal.SIGKILL
        assert proc.pid not in pinned_process._INITS
        assert proc.pid not in pinned_process._NAMESPACED
    finally:
        _end_supervised(proc, init)


@_NAMESPACE_ONLY
def test_a_held_init_that_does_not_end_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc, init = _supervised(tmp_path)
    assert init is not None
    try:
        pinned_process._INITS[proc.pid] = os.pidfd_open(init)
        monkeypatch.setattr(pinned_process.signal, "pidfd_send_signal", lambda pidfd, sig: None)
        monkeypatch.setattr(pinned_process, "_TEARDOWN_SECONDS", 0.2)
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
        assert proc.wait(timeout=5) == -signal.SIGKILL
        assert proc.pid not in pinned_process._INITS
    finally:
        monkeypatch.undo()
        _end_supervised(proc, init)


def test_an_unexpected_error_while_ending_the_namespace_is_a_teardown_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    proc, init = _supervised(tmp_path)

    def undecodable() -> dict[int, list[int]]:
        raise UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")

    try:
        monkeypatch.setattr(pinned_process, "_children_by_parent", undecodable)
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
        assert proc.wait(timeout=5) == -signal.SIGKILL
    finally:
        monkeypatch.undo()
        _end_supervised(proc, init)


@_NAMESPACE_ONLY
@pytest.mark.parametrize("mode", ["idle", "exit"])
def test_namespaced_cleanup_without_a_running_init_succeeds(tmp_path: Path, mode: str) -> None:
    # unshare stopped before it forked, or after its init exited: nothing is left to end.
    proc, init = _supervised(tmp_path, mode)
    try:
        pinned_process.terminate_process_group(proc)
        assert proc.wait(timeout=5) == (-signal.SIGKILL if mode == "idle" else 0)
    finally:
        _end_supervised(proc, init)


def test_namespaced_cleanup_fails_closed_when_the_init_does_not_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # An init that never finishes exiting, as one blocked in the kernel would, must not
    # be reported as ended.
    proc, init = _supervised(tmp_path)
    kill = os.kill

    def spare_init(pid: int, sig: int) -> None:
        if pid != init:
            kill(pid, sig)

    try:
        monkeypatch.setattr(pinned_process.os, "kill", spare_init)
        monkeypatch.setattr(pinned_process, "_TEARDOWN_SECONDS", 0.2)
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
        assert proc.wait(timeout=5) == -signal.SIGKILL
        assert proc.pid not in pinned_process._NAMESPACED
    finally:
        monkeypatch.undo()
        _end_supervised(proc, init)


@_NAMESPACE_ONLY
def test_namespaced_cleanup_signals_no_child_of_a_running_unshare(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Only a stopped unshare keeps its child's pid from being reaped and reused, so a
    # stop that never arrives is reported, and no pid is signalled on a stale scan.
    proc, init = _supervised(tmp_path)
    kill = os.kill
    sent: list[int] = []

    def swallow_stop(pid: int, sig: int) -> None:
        sent.append(pid)
        if sig != signal.SIGSTOP:
            kill(pid, sig)

    try:
        monkeypatch.setattr(pinned_process.os, "kill", swallow_stop)
        monkeypatch.setattr(pinned_process, "_STOP_SECONDS", 0.2)
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
        assert set(sent) == {proc.pid}
        assert proc.wait(timeout=5) == -signal.SIGKILL
    finally:
        monkeypatch.undo()
        _end_supervised(proc, init)


@pytest.mark.parametrize(
    ("status", "ended"),
    [
        (None, True),
        ({"State": "Z (zombie)", "Threads": "1"}, True),
        ({"State": "X (dead)", "Threads": "1"}, True),
        # A thread-group leader that exited while another thread still runs.
        ({"State": "Z (zombie)", "Threads": "2"}, False),
        ({"State": "S (sleeping)", "Threads": "1"}, False),
        ({"State": "D (disk sleep)", "Threads": "1"}, False),
        ({"State": "T (stopped)", "Threads": "1"}, False),
        ({"State": "Z (zombie)"}, False),
        ({}, False),
    ],
)
def test_an_init_has_ended_only_once_every_thread_has_exited(
    monkeypatch: pytest.MonkeyPatch, status: dict[str, str] | None, ended: bool
) -> None:
    monkeypatch.setattr(pinned_process, "_status", lambda pid: status)
    assert pinned_process._ended(4242) is ended


def test_an_unreadable_init_status_is_not_an_ended_init(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(pid: int) -> dict[str, str] | None:
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(pinned_process, "_status", refuse)
    assert pinned_process._ended(4242) is False


@_NAMESPACE_ONLY
def test_the_status_reader_returns_the_fields_of_a_live_and_a_reaped_process() -> None:
    fields = pinned_process._status(os.getpid())
    assert fields is not None
    assert fields["State"][0] in {"R", "S"}
    assert fields["PPid"] == str(os.getppid())
    proc = subprocess.Popen(["/bin/true"])  # noqa: S603
    proc.wait(timeout=5)
    assert pinned_process._status(proc.pid) is None


@pytest.mark.parametrize(
    ("stdin", "code"),
    [(b"", 127), (b'{"jsonrpc": "2.0"}\n', 127), (b'\n{"jsonrpc": "2.0"}\n', 0)],
    ids=["end-of-input", "other-byte", "released"],
)
def test_the_gate_executes_the_launcher_only_once_released(
    tmp_path: Path, stdin: bytes, code: int
) -> None:
    out = tmp_path / "out"
    script = tmp_path / "server"
    script.write_text(f"#!/bin/sh\ncat > {shlex.quote(str(out))}\n")
    script.chmod(0o700)
    gate = [sys.executable, "-I", "-S", "-B", "-c", pinned_process._GATE_EXEC, str(script)]
    result = subprocess.run(gate, input=stdin, timeout=30, check=False)  # noqa: S603
    assert result.returncode == code
    # The launcher reads exactly what follows the release byte.
    assert (out.read_bytes() if out.exists() else None) == (stdin[1:] if code == 0 else None)


_SAME_NAMESPACE_UNSHARE = """#!/bin/sh
while [ "$1" != -- ]; do shift; done
shift
"$@" &
wait
"""


@pytest.mark.parametrize("supervisor", ["exits", "same-namespace"])
def test_no_launcher_runs_unless_its_namespace_init_is_held(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, supervisor: str
) -> None:
    # A stand-in unshare that exits before forking, or forks the gate in the caller's own
    # PID namespace, never yields an init one namespace deeper, so the gate is never
    # released and the pinned program never runs.
    fake = tmp_path / "unshare"
    fake.write_text("#!/bin/sh\nexit 0\n" if supervisor == "exits" else _SAME_NAMESPACE_UNSHARE)
    fake.chmod(0o700)
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: True)
    monkeypatch.setattr(pinned_process, "_unshare_path", lambda: str(fake))
    monkeypatch.setattr(pinned_process, "_START_SECONDS", 0.5)
    marker = tmp_path / "pid"
    command, digest = _launcher(tmp_path, marker)
    started = time.monotonic()
    with pytest.raises(LaunchPolicyError) as denied:
        observe_pinned(str(command), digest)
    assert denied.value.reason == "isolation-unavailable"
    assert time.monotonic() - started < 10
    assert not pinned_process._NAMESPACED
    assert not pinned_process._INITS
    time.sleep(0.2)
    assert not marker.exists()


def test_verify_live_fails_a_server_whose_namespace_did_not_end(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terminate = stdio.terminate_process_group

    def teardown_fails(proc: subprocess.Popen[bytes]) -> None:
        terminate(proc)
        raise pinned_process.PinnedProcessError("isolation-teardown-failed", "did not end")

    monkeypatch.setattr(stdio, "terminate_process_group", teardown_fails)
    arguments, _ = command(tmp_path, inventory(), launcher(tmp_path))
    result = CliRunner().invoke(main, [*arguments, "--json-output", "--no-isolation"])
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    assert not report["complete"]
    # Off Linux the opt-out is refused before a launcher runs, so no teardown happens.
    reason = "isolation-teardown-failed" if _LINUX else "isolation-unavailable"
    assert report["results"][0]["reason"] == reason
    assert report["results"][0]["error"] == verify.reason_message(reason)


def test_gate_is_disabled_and_init_fd_closes_without_pidfd_send_signal(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delattr(pinned_process.signal, "pidfd_send_signal", raising=False)
    assert pinned_process._gate_argv(tmp_path / "server") is None
    assert pinned_process._hold_init(os.getpid()) is None
    proc, init = _supervised(tmp_path)
    read_fd, write_fd = os.pipe()
    os.close(write_fd)
    try:
        pinned_process._INITS[proc.pid] = read_fd
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
        with pytest.raises(OSError):
            os.fstat(read_fd)
        assert proc.wait(timeout=5) == -signal.SIGKILL
    finally:
        with contextlib.suppress(OSError):
            os.close(read_fd)
        monkeypatch.undo()
        _end_supervised(proc, init)


def _spawn_opted_out(
    tmp_path: Path, body: str, interpreter: str = "/bin/sh"
) -> subprocess.Popen[bytes]:
    """Stage a launcher script and start it opted out, as ``observe_pinned`` would."""
    script = tmp_path / "launcher.sh"
    script.write_text(f"#!{interpreter}\n" + body)
    script.chmod(0o700)
    digest = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    work = tmp_path / "work"
    work.mkdir()
    staged = pinned_process.stage_pinned_executable(str(script), digest, work)
    with isolation_off():
        return pinned_process.spawn_pinned(staged, work)


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="the subreaper wrapper is Linux-only"
)
@pytest.mark.parametrize(("body", "expected"), [("exit 3\n", 3), ("kill -9 $$\n", -9)])
def test_the_opt_out_wrapper_reports_the_launchers_exit_status(
    tmp_path: Path, body: str, expected: int
) -> None:
    # The wrapper is the process the caller waits for; its status is the launcher's.
    proc = _spawn_opted_out(tmp_path, body)
    try:
        assert proc.wait(timeout=10) == expected
    finally:
        pinned_process.terminate_process_group(proc)
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


@pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="the subreaper wrapper is Linux-only"
)
def test_opt_out_kills_what_a_launcher_that_already_exited_left_behind(tmp_path: Path) -> None:
    # The launcher starts a daemon in its own session and exits at once. The daemon's
    # parent becomes the wrapper, not pid 1, so cleanup still finds and kills it.
    marker = tmp_path / "pid"
    launcher = tmp_path / "launcher-pid"
    quoted, recorded = shlex.quote(str(marker)), shlex.quote(str(launcher))
    body = (
        f"setsid sh -c 'echo $$ > {quoted}.tmp && mv {quoted}.tmp {quoted} && exec sleep 60' "
        "</dev/null >/dev/null 2>&1 &\n"
        f"while [ ! -e {quoted} ]; do sleep 0.01; done\n"
        f"echo $$ > {recorded}.tmp && mv {recorded}.tmp {recorded}\n"
        "exit 0\n"
    )
    proc = _spawn_opted_out(tmp_path, body)
    try:
        deadline = time.monotonic() + 10
        while not launcher.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert launcher.exists(), "the launcher did not start its daemon within 10 seconds"
        # Cleanup must run only after the launcher has exited and the daemon was orphaned.
        _assert_dead(_host_pid(launcher))
        pinned_process.terminate_process_group(proc)
        proc.wait(timeout=10)
        _assert_dead(_host_pid(marker))
    finally:
        with contextlib.suppress(ProcessLookupError, ValueError, OSError):
            os.kill(_host_pid(marker), signal.SIGKILL)
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


def _worker_prelude(marker: Path) -> str:
    """Start a ``setsid`` worker that records its host pid, and wait until it has.

    The worker holds no copy of the launcher's streams, so the launcher's exit is their
    end of file.
    """
    return f"""import signal
marker = {str(marker)!r}
if os.fork() == 0:
    os.setsid()
    null = os.open(os.devnull, os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(null, 1)
    open(marker + ".tmp", "w").write(os.readlink("/proc/self"))
    os.rename(marker + ".tmp", marker)
    time.sleep(60)
    raise SystemExit
while not os.path.exists(marker):
    time.sleep(0.01)
"""


def _kill_marked(marker: Path) -> None:
    with contextlib.suppress(ProcessLookupError, ValueError, OSError):
        os.kill(_host_pid(marker), signal.SIGKILL)


@_LINUX_ONLY
@pytest.mark.parametrize("target", ["group", "parent"])
@pytest.mark.parametrize(
    "number",
    [signal.SIGTERM, signal.SIGHUP, signal.SIGINT, signal.SIGUSR1],
    ids=["SIGTERM", "SIGHUP", "SIGINT", "SIGUSR1"],
)
def test_a_launcher_cannot_end_its_wrapper_with_a_signal(
    tmp_path: Path, number: int, target: str
) -> None:
    # Had the signal ended the wrapper, the setsid worker would have been reparented to
    # pid 1, out of the tree cleanup sweeps, while the session reported success.
    marker = tmp_path / "pid"
    send = "os.killpg(0, number)" if target == "group" else "os.kill(os.getppid(), number)"
    command, digest = _pinned(
        tmp_path / "launcher",
        _worker_prelude(marker)
        + f"number = {int(number)}\nsignal.signal(number, signal.SIG_IGN)\n{send}\ntime.sleep(0.2)\n",
    )
    try:
        with isolation_off():
            observe_pinned(str(command), digest)
        _assert_dead(_host_pid(marker))
    finally:
        _kill_marked(marker)


@_LINUX_ONLY
def test_a_launcher_that_kills_its_own_group_leaves_the_wrapper_to_clean_up(
    tmp_path: Path,
) -> None:
    # The launcher leads its own group, so kill(0, SIGKILL) ends it but not the wrapper,
    # which still adopts and kills the worker.
    marker = tmp_path / "pid"
    command, digest = _pinned(
        tmp_path / "launcher", _worker_prelude(marker) + "os.killpg(0, signal.SIGKILL)\n"
    )
    try:
        with isolation_off(), pytest.raises(StdioProtocolError):
            observe_pinned(str(command), digest)
        _assert_dead(_host_pid(marker))
    finally:
        _kill_marked(marker)


@_LINUX_ONLY
@pytest.mark.parametrize("path", ["observation", "session"])
def test_a_launcher_that_kills_its_wrapper_fails_closed(tmp_path: Path, path: str) -> None:
    # SIGKILL still ends the wrapper, and its worker escapes to pid 1; the session must
    # then report that it could not contain the launcher instead of succeeding.
    marker = tmp_path / "pid"
    command, digest = _pinned(
        tmp_path / "launcher",
        _worker_prelude(marker) + "os.kill(os.getppid(), signal.SIGKILL)\ntime.sleep(0.2)\n",
    )
    try:
        if path == "observation":
            with isolation_off(), pytest.raises(LaunchPolicyError) as failed:
                observe_pinned(str(command), digest)
            assert failed.value.reason == "isolation-teardown-failed"
        else:
            session = PinnedStdioSession(
                command=str(command), sha256=digest, server_id="server:mail"
            )
            with (
                isolation_off(),
                pytest.raises(AuthorizationError, match="did not outlive everything"),
                session,
            ):
                pass
    finally:
        _kill_marked(marker)


_CHAIN = """import os, sys, time
beat = sys.argv[1]
deadline = time.monotonic() + 10
os.setsid()
while time.monotonic() < deadline:
    with open(beat + ".tmp", "w") as out:
        out.write(str(os.getpid()))
    os.replace(beat + ".tmp", beat)
    if os.fork():
        os._exit(0)
    os.setsid()
    time.sleep(0.002)
"""


# A process whose main thread exits while another runs on reads as a zombie in its stat.
_THREADED = """import ctypes, os, sys, threading, time
beat = sys.argv[1]
os.setsid()
threading.Thread(target=time.sleep, args=(60,)).start()
with open(beat + ".tmp", "w") as out:
    out.write(str(os.getpid()))
os.replace(beat + ".tmp", beat)
ctypes.CDLL(None).pthread_exit(None)
"""


def _assert_ended(pid: int) -> None:
    """Wait until every thread of ``pid`` has exited; a running thread still fails."""
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if pinned_process._ended(pid):
            return
        time.sleep(0.05)
    raise AssertionError(f"process {pid} still had a running thread")


def _stop_chain(beat: Path) -> None:
    """Kill a fork chain that escaped, one generation at a time, within a few seconds."""
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        with contextlib.suppress(ProcessLookupError, ValueError, OSError):
            os.kill(int(beat.read_text()), signal.SIGKILL)
        time.sleep(0.01)


@_LINUX_ONLY
@pytest.mark.parametrize("descendant", ["daemon", "fork-chain", "exited-main-thread"])
def test_what_the_tree_sweep_misses_is_killed_under_the_stopped_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, descendant: str
) -> None:
    # Without the tree sweep, only the drain of the stopped wrapper's children reaches a
    # process that left the launcher's session; a chain that forks and calls setsid in
    # a loop is caught one generation at a time as each is reparented to the wrapper.
    beat = tmp_path / "beat"
    quoted = shlex.quote(str(beat))
    if descendant == "daemon":
        start = (
            f"setsid sh -c 'echo $$ > {quoted}.tmp && mv {quoted}.tmp {quoted} && exec sleep 60' "
            "</dev/null >/dev/null 2>&1 &\n"
        )
    else:
        program = _CHAIN if descendant == "fork-chain" else _THREADED
        start = (
            f"{shlex.quote(sys.executable)} -I -S -c {shlex.quote(program)} {quoted} "
            "</dev/null >/dev/null 2>&1 &\n"
        )
    proc = _spawn_opted_out(
        tmp_path, start + f"while [ ! -e {quoted} ]; do sleep 0.01; done\nexec sleep 60\n"
    )
    try:
        deadline = time.monotonic() + 10
        while not beat.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert beat.exists(), "the launcher did not start its descendant within 10 seconds"
        monkeypatch.setattr(pinned_process, "_kill_descendants", lambda root: None)
        pinned_process.terminate_process_group(proc)
        proc.wait(timeout=10)
        last = beat.read_text()
        _assert_ended(int(last))
        time.sleep(0.2)
        assert beat.read_text() == last
    finally:
        _stop_chain(beat)
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


def _run_wrapper(
    tmp_path: Path, prelude: str, body: str
) -> tuple[subprocess.CompletedProcess[bytes], bytes]:
    """Run the subreaper wrapper on a shell launcher; return the result and its last byte."""
    launcher = tmp_path / "launcher.sh"
    launcher.write_text("#!/bin/sh\n" + body)
    launcher.chmod(0o700)
    done, finished = pinned_process._wrapper_channel()
    try:
        result = subprocess.run(  # noqa: S603
            [
                sys.executable,
                "-I",
                "-S",
                "-B",
                "-c",
                prelude + pinned_process._SUBREAPER_EXEC,
                str(launcher),
                str(finished),
                str(os.getpid()),
            ],
            cwd=tmp_path,
            env={"PATH": os.defpath},
            pass_fds=(finished,),
            capture_output=True,
            timeout=30,
            check=False,
        )
    finally:
        os.close(finished)
    try:
        return result, os.read(done, 16)
    finally:
        os.close(done)


@_LINUX_ONLY
def test_a_wrapper_that_cannot_fork_exits_127_and_reports_no_child(tmp_path: Path) -> None:
    # Fork fails with EAGAIN once RLIMIT_NPROC is reached; that must read as a launcher
    # that could not start, not as a crash, and the wrapper has nothing to wait for.
    refuse = (
        "import os\n"
        "def _refuse():\n"
        "    raise BlockingIOError(11, 'Resource temporarily unavailable')\n"
        "os.fork = _refuse\n"
    )
    result, last = _run_wrapper(tmp_path, refuse, "exit 0\n")
    assert result.returncode == 127
    assert result.stderr == b""
    assert last == b"\n"


@_LINUX_ONLY
def test_the_wrapper_repeats_the_launchers_signal_without_dumping_core(tmp_path: Path) -> None:
    # A wrapper that is still dumpable when it re-raises SIGABRT writes its own core,
    # over the launcher's or as a second crash report blamed on the interpreter.
    record = tmp_path / "dumpable"
    observe = f"""import ctypes, os
_kill = os.kill
def _observed(pid, number):
    if pid == os.getpid():
        with open({str(record)!r}, "w") as out:
            out.write(str(ctypes.CDLL(None).prctl(3, 0, 0, 0, 0)))
    _kill(pid, number)
os.kill = _observed
"""
    result, last = _run_wrapper(tmp_path, observe, "kill -ABRT $$\n")
    assert result.returncode == -signal.SIGABRT
    assert record.read_text() == "0"
    assert last == b"\n"


def _launcher_view(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, name: str, *, direct: bool
) -> dict[str, Any]:
    """The descriptors and dumpable flag a launcher starts with, opted out."""
    view = tmp_path / f"{name}.view"
    command, digest = _pinned(
        tmp_path / name,
        f"""import ctypes
prctl = ctypes.CDLL(None).prctl
death, reaper = ctypes.c_int(-1), ctypes.c_int(-1)
prctl(2, ctypes.byref(death), 0, 0, 0)
prctl(37, ctypes.byref(reaper), 0, 0, 0)
state = {{
    "fds": sorted(os.listdir("/proc/self/fd")),
    "dumpable": prctl(3, 0, 0, 0, 0),
    "pdeathsig": death.value,
    "subreaper": reaper.value,
    "leads_group": os.getpgrp() == os.getpid(),
}}
for name, call in (("setsid", os.setsid), ("killpg", lambda: os.killpg(os.getpid(), 0))):
    try:
        call()
        state[name] = "ok"
    except OSError as exc:
        state[name] = exc.errno
open({str(view)!r}, "w").write(json.dumps(state))
raise SystemExit
""",
    )
    with monkeypatch.context() as launch:
        if direct:
            launch.setattr(pinned_process, "_subreaper_argv", lambda staged: None)
        with isolation_off(), pytest.raises(StdioProtocolError):
            observe_pinned(str(command), digest)
    return dict(json.loads(view.read_text()))


@_LINUX_ONLY
@pytest.mark.parametrize(
    "leak",
    ["", "os.set_inheritable(done, False)\n", "os.setpgid(0, 0)\n"],
    ids=["wrapper", "leaked-descriptor", "shared-group"],
)
def test_the_launcher_starts_as_it_would_without_the_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, leak: str
) -> None:
    # The last-byte descriptor must close on exec: a launcher that held it could write
    # the byte itself and then kill the wrapper unnoticed. A launcher that does not lead
    # its own group could leave the session with setsid, and kill(0) would reach the
    # wrapper. Its parent-death signal, subreaper flag and dumpable flag are its own.
    if leak:
        program = pinned_process._SUBREAPER_EXEC.replace(leak, "")
        assert program != pinned_process._SUBREAPER_EXEC
        monkeypatch.setattr(pinned_process, "_SUBREAPER_EXEC", program)
    wrapped = _launcher_view(tmp_path, monkeypatch, "wrapped", direct=False)
    direct = _launcher_view(tmp_path, monkeypatch, "direct", direct=True)
    assert (wrapped != direct) is bool(leak)
    assert direct == {
        "fds": direct["fds"],
        "dumpable": 1,
        "pdeathsig": 0,
        "subreaper": 0,
        "leads_group": True,
        "setsid": errno.EPERM,
        "killpg": "ok",
    }


@_LINUX_ONLY
def test_a_launcher_cannot_forge_its_wrappers_last_byte_through_proc(tmp_path: Path) -> None:
    # The launcher runs as the caller's user, so it can open the caller's descriptors
    # through /proc/<pid>/fd. Reopening the caller's end of a pipe for writing would let
    # it forge the byte and then kill the wrapper unnoticed; a socket cannot be reopened.
    target, outcome, marker = tmp_path / "target", tmp_path / "outcome", tmp_path / "pid"
    source = f"""import errno, os, signal, time
target, outcome, marker = {str(target)!r}, {str(outcome)!r}, {str(marker)!r}
while not os.path.exists(target):
    time.sleep(0.01)
caller, number = open(target).read().split()
try:
    forged = os.open(f"/proc/{{caller}}/fd/{{number}}", os.O_WRONLY | os.O_NONBLOCK)
except OSError as exc:
    result = errno.errorcode.get(exc.errno, str(exc.errno))
else:
    os.write(forged, b"\\n")
    result = "forged"
open(outcome, "w").write(result)
if os.fork() == 0:
    os.setsid()
    open(marker + ".tmp", "w").write(os.readlink("/proc/self"))
    os.rename(marker + ".tmp", marker)
    time.sleep(60)
    raise SystemExit
while not os.path.exists(marker):
    time.sleep(0.01)
os.kill(os.getppid(), signal.SIGKILL)
time.sleep(60)
"""
    proc = _spawn_opted_out(tmp_path, source, interpreter=sys.executable)
    try:
        done = pinned_process._OPT_OUT[proc.pid][2]
        assert done is not None
        target.write_text(f"{os.getpid()} {done}")
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists(), "the launcher did not start its worker within 10 seconds"
        _assert_dead(proc.pid)
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
        assert outcome.read_text() == "ENXIO"
    finally:
        _kill_marked(marker)
        with contextlib.suppress(ProcessLookupError):
            os.kill(proc.pid, signal.SIGKILL)
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()
        proc.wait(timeout=10)


_HOST = """import sys, time
from pathlib import Path
from nexus_symbiote.live import pinned_process
work, script, digest = Path(sys.argv[1]), sys.argv[2], sys.argv[3]
staged = pinned_process.stage_pinned_executable(script, digest, work)
with pinned_process.isolation_off():
    proc = pinned_process.spawn_pinned(staged, work)
(work / "wrapper.tmp").write_text(str(proc.pid))
(work / "wrapper.tmp").rename(work / "wrapper")
time.sleep(60)
"""


@_LINUX_ONLY
def test_the_wrapper_and_a_launcher_that_watches_its_parent_end_with_a_crashed_client(
    tmp_path: Path,
) -> None:
    # A launcher started directly sees its parent go when the client dies; through the
    # wrapper it would keep a living parent, so the wrapper must die with the client.
    marker = tmp_path / "pid"
    script = tmp_path / "launcher"
    script.write_text(
        f"#!{sys.executable}\n"
        "import ctypes, os, signal, time\n"
        "ctypes.CDLL(None).prctl(1, signal.SIGKILL, 0, 0, 0)\n"
        f"open({str(marker)!r} + '.tmp', 'w').write(str(os.getpid()))\n"
        f"os.rename({str(marker)!r} + '.tmp', {str(marker)!r})\n"
        "time.sleep(60)\n"
    )
    script.chmod(0o700)
    digest = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    work = tmp_path / "work"
    work.mkdir()
    source = str(Path(pinned_process.__file__).parents[2])
    host = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-I",
            "-c",
            f"import sys; sys.path.insert(0, {source!r})\n" + _HOST,
            str(work),
            str(script),
            digest,
        ],
        stdin=subprocess.DEVNULL,
    )
    wrapper = work / "wrapper"
    try:
        deadline = time.monotonic() + 15
        while not (marker.exists() and wrapper.exists()) and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists() and wrapper.exists(), "the client did not start the launcher"
        host.kill()
        host.wait(timeout=10)
        _assert_dead(int(wrapper.read_text()))
        _assert_dead(_host_pid(marker))
    finally:
        with contextlib.suppress(ProcessLookupError):
            host.kill()
        host.wait(timeout=10)
        _kill_marked(marker)
        with contextlib.suppress(ProcessLookupError, ValueError, OSError):
            os.kill(int(wrapper.read_text()), signal.SIGKILL)


@_LINUX_ONLY
def test_cleanup_before_the_wrapper_forks_never_starts_the_launcher(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A session can end before the wrapper has forked, as when the first write fails.
    # Resumed so that it could reap, the wrapper would start the launcher only then,
    # after cleanup began, so it must be killed while it is still stopped.
    marker = tmp_path / "pid"
    held = "import time\ntime.sleep(0.3)\n" + pinned_process._SUBREAPER_EXEC
    monkeypatch.setattr(pinned_process, "_SUBREAPER_EXEC", held)
    quoted = shlex.quote(str(marker))
    proc = _spawn_opted_out(tmp_path, f"echo $$ > {quoted}\nexec sleep 60\n")
    try:
        pinned_process.terminate_process_group(proc)
        assert proc.wait(timeout=5) == -signal.SIGKILL
        time.sleep(1)
        assert not marker.exists()
    finally:
        _kill_marked(marker)
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


@_LINUX_ONLY
def test_the_session_is_swept_only_while_the_launch_is_unreaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The session id is the wrapper's pid. Once the caller has reaped it, the number can
    # name a session that an unrelated process started, which the sweep would kill.
    swept: list[int] = []
    proc = _spawn_opted_out(tmp_path, "exit 0\n")
    try:
        assert proc.wait(timeout=10) == 0
        monkeypatch.setattr(pinned_process, "_kill_session", swept.append)
        pinned_process.terminate_process_group(proc)
        assert swept == []
    finally:
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()


@_LINUX_ONLY
def test_opt_out_stops_the_whole_tree_before_it_is_swept(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Stopping only the wrapper leaves a watchdog in the launcher free to restart a helper
    # while the tree is swept, and a running parent free to reap a child the sweep found,
    # whose pid could then name another process when it is signalled. Ported from #228.
    helpers = tmp_path / "helpers"
    helpers.mkdir()
    command, digest = _watchdog_launcher(tmp_path, helpers)
    seen: list[dict[int, str]] = []
    sweep = pinned_process._kill_descendants

    def observed(root: int) -> None:
        if not seen:
            tree = {root} | pinned_process._descendant_pids(root)
            seen.append({pid: _stat(pid)[0] for pid in tree})
        sweep(root)

    monkeypatch.setattr(pinned_process, "_kill_descendants", observed)
    try:
        with isolation_off():
            observe_pinned(str(command), digest)
        # The wrapper, the launcher and at least one helper, none of them running.
        assert len(seen[0]) >= 3, seen
        assert set(seen[0].values()) <= {"T", "Z"}, seen
    finally:
        for entry in helpers.iterdir():
            with contextlib.suppress(ProcessLookupError):
                os.kill(int(entry.name), signal.SIGKILL)


@_LINUX_ONLY
def test_a_byte_from_a_copy_of_the_wrappers_end_does_not_count(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A process of the same user can copy the wrapper's end with pidfd_getfd while the
    # wrapper's interpreter starts, before it makes itself undumpable. Here the test
    # holds that copy, writes the byte, and the launcher then kills its wrapper: the
    # kernel credits the byte to this process, not the wrapper, so cleanup fails closed.
    marker = tmp_path / "pid"
    copies: list[int] = []
    channel = pinned_process._wrapper_channel

    def copied() -> tuple[int, int]:
        done, finished = channel()
        copies.append(os.dup(finished))
        return done, finished

    monkeypatch.setattr(pinned_process, "_wrapper_channel", copied)
    proc = _spawn_opted_out(
        tmp_path,
        "import os, time\n"
        + _worker_prelude(marker)
        + "time.sleep(0.3)\nos.kill(os.getppid(), signal.SIGKILL)\ntime.sleep(60)\n",
        interpreter=sys.executable,
    )
    try:
        os.write(copies[0], b"\n")
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert marker.exists(), "the launcher did not start its worker within 10 seconds"
        _assert_dead(proc.pid)
        with pytest.raises(pinned_process.PinnedProcessError) as failed:
            pinned_process.terminate_process_group(proc)
        assert failed.value.reason == "isolation-teardown-failed"
    finally:
        os.close(copies[0])
        _kill_marked(marker)
        with contextlib.suppress(ProcessLookupError):
            os.kill(proc.pid, signal.SIGKILL)
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()
        proc.wait(timeout=10)


def _python_launcher(tmp_path: Path, marker: Path) -> subprocess.Popen[bytes]:
    """An opted-out launcher that ignores SIGHUP and starts three sleeps in its group."""
    source = f"""import os, signal, subprocess, time
signal.signal(signal.SIGHUP, signal.SIG_IGN)
pids = [subprocess.Popen(["/bin/sleep", "300"]).pid for _ in range(3)]
open({str(marker)!r} + ".tmp", "w").write(" ".join(map(str, [os.getpid(), *pids])))
os.rename({str(marker)!r} + ".tmp", {str(marker)!r})
time.sleep(300)
"""
    return _spawn_opted_out(tmp_path, source, interpreter=sys.executable)


@_LINUX_ONLY
@pytest.mark.parametrize(
    ("step", "after"),
    [("_stop_tree", False), ("_stop_tree", True), ("_drain_children", True)],
    ids=["before-tree-stop", "after-tree-stop", "in-drain"],
)
def test_an_interrupted_cleanup_still_kills_the_launchers_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, step: str, after: bool
) -> None:
    # The launcher leads its own group, which killpg of the wrapper's group misses, so
    # a KeyboardInterrupt during cleanup must not leave its tree running.
    marker = tmp_path / "pids"
    proc = _python_launcher(tmp_path, marker)
    try:
        deadline = time.monotonic() + 10
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        pids = [int(pid) for pid in marker.read_text().split()]
        real = getattr(pinned_process, step)

        def interrupted(*args: object) -> object:
            if after:
                real(*args)
            raise KeyboardInterrupt

        monkeypatch.setattr(pinned_process, step, interrupted)
        with pytest.raises(KeyboardInterrupt):
            pinned_process.terminate_process_group(proc)
        for pid in pids:
            _assert_dead(pid)
    finally:
        with contextlib.suppress(FileNotFoundError, ValueError):
            for pid in marker.read_text().split():
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(pid), signal.SIGKILL)
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()
        proc.wait(timeout=10)


@_LINUX_ONLY
def test_a_session_spawned_on_a_thread_that_exits_is_still_cleaned_up(tmp_path: Path) -> None:
    # A thread pool's worker can start a session and exit before the session ends; only
    # the death of the process that started it may end the wrapper.
    spawned: list[subprocess.Popen[bytes]] = []

    def spawn() -> None:
        spawned.append(_spawn_opted_out(tmp_path, "exec sleep 60\n"))
        # Long enough for the wrapper to have started: a parent-death signal tied to this
        # thread would then fire when it exits.
        time.sleep(0.5)

    worker = threading.Thread(target=spawn)
    worker.start()
    worker.join()
    proc = spawned[0]
    try:
        time.sleep(1)
        assert proc.poll() is None
        pinned_process.terminate_process_group(proc)
    finally:
        for stream in (proc.stdin, proc.stdout):
            if stream is not None:
                stream.close()
        proc.wait(timeout=10)


@_LINUX_ONLY
def test_the_session_sweep_does_not_count_an_ended_leader(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The unreaped wrapper leads the session; signalling its zombie in each pass made
    # every teardown scan /proc eight times.
    leader = subprocess.Popen(["/bin/true"], start_new_session=True)  # noqa: S603
    try:
        os.waitid(os.P_PID, leader.pid, os.WEXITED | os.WNOWAIT)
        signalled: list[int] = []
        monkeypatch.setattr(pinned_process.os, "kill", lambda pid, sig: signalled.append(pid))
        pinned_process._kill_session(leader.pid)
        assert signalled == []
    finally:
        monkeypatch.undo()
        leader.wait(timeout=5)


@_LINUX_ONLY
def test_the_drain_reads_the_proc_scan_fallback_only_a_few_times(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Without the kernel's children list every read is a scan of all of /proc.
    stopped = subprocess.Popen(["/bin/sleep", "30"])  # noqa: S603
    try:
        os.kill(stopped.pid, signal.SIGSTOP)
        reads: list[int] = []
        real = pinned_process._children_of
        exists = os.path.exists

        def counted(pid: int) -> list[int]:
            reads.append(pid)
            return real(pid)

        monkeypatch.setattr(pinned_process, "_children_of", counted)
        monkeypatch.setattr(
            pinned_process.os.path,
            "exists",
            lambda path: "/children" not in str(path) and exists(path),
        )
        assert pinned_process._drain_children(stopped.pid)
        assert len(reads) <= 3
    finally:
        monkeypatch.undo()
        stopped.kill()
        stopped.wait(timeout=5)


@_LINUX_ONLY
def test_an_interrupted_spawn_leaks_no_descriptor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def interrupted(*args: object, **kwargs: object) -> None:
        raise KeyboardInterrupt

    script = tmp_path / "launcher.sh"
    script.write_text("#!/bin/sh\nexit 0\n")
    script.chmod(0o700)
    digest = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    work = tmp_path / "work"
    work.mkdir()
    staged = pinned_process.stage_pinned_executable(str(script), digest, work)
    before = set(os.listdir("/proc/self/fd"))
    monkeypatch.setattr(pinned_process.subprocess, "Popen", interrupted)
    with isolation_off(), pytest.raises(KeyboardInterrupt):
        pinned_process.spawn_pinned(staged, work)
    assert set(os.listdir("/proc/self/fd")) <= before


def test_opting_out_as_root_prints_a_second_warning(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process, "namespace_available", lambda: False)
    monkeypatch.setattr("nexus_symbiote.supply_chain_cli._running_as_root", lambda: True)
    arguments, _ = command(tmp_path, inventory(), launcher(tmp_path))
    allowed = CliRunner().invoke(main, [*arguments, "--json-output", "--no-isolation"])
    if not _LINUX:
        # The opt-out is refused here, so no launcher runs as root to warn about.
        assert allowed.exit_code == 1, allowed.output
        assert "--no-isolation is refused off Linux" in " ".join(allowed.stderr.split())
        assert "warning: --no-isolation as root" not in allowed.stderr
        return
    assert allowed.exit_code == 0, allowed.output
    assert "warning: --no-isolation as root" in allowed.stderr


def _wrapper_status(pid: int) -> dict[str, str]:
    with open(f"/proc/{pid}/status") as status:
        return dict(line.rstrip("\n").split(":\t", 1) for line in status if ":\t" in line)


@_LINUX_ONLY
def test_the_wrapper_waits_for_children_with_sigchld_blocked(tmp_path: Path) -> None:
    # Without the block SIGCHLD is discarded, and every exit is seen only when the
    # half-second poll ends, which slows each teardown and status by that much. The
    # kernel unblocks the awaited signal during the wait, so the mask is read as the
    # wait begins.
    record = tmp_path / "blocked"
    observe = f"""import signal
_wait = signal.sigtimedwait
def _observed(signals, timeout):
    with open({str(record)!r}, "a") as out:
        out.write("1" if signal.SIGCHLD in signal.pthread_sigmask(signal.SIG_BLOCK, []) else "0")
    return _wait(signals, timeout)
signal.sigtimedwait = _observed
"""
    result, _ = _run_wrapper(tmp_path, observe, "sleep 0.3\nexit 3\n")
    assert result.returncode == 3
    assert record.read_text() and set(record.read_text()) == {"1"}


@_LINUX_ONLY
@pytest.mark.parametrize("abandon", ["close", "kill-while-stopped"])
def test_a_wrapper_whose_caller_gives_up_ends_the_launchers_tree(
    tmp_path: Path, abandon: str
) -> None:
    # A caller interrupted after the fork closes its end of the socket; one that dies
    # while cleanup has the wrapper stopped leaves it to resume and end the tree.
    marker = tmp_path / "pids"
    source = """import os, subprocess, sys, time
from pathlib import Path
from nexus_symbiote.live import pinned_process
work, script, digest, marker, abandon = Path(sys.argv[1]), sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5]
staged = pinned_process.stage_pinned_executable(script, digest, work)
with pinned_process.isolation_off():
    proc = pinned_process.spawn_pinned(staged, work)
while not (os.path.exists(marker) and os.path.exists(marker + ".go")):
    time.sleep(0.01)
if abandon == "close":
    os.close(pinned_process._OPT_OUT[proc.pid][2])
    time.sleep(60)
pinned_process._stop_launcher(proc.pid)
pinned_process._stop_tree(proc.pid)
os.kill(os.getpid(), 9)
"""
    script = tmp_path / "launcher"
    script.write_text(
        "#!/bin/sh\n"
        "setsid sleep 300 </dev/null >/dev/null 2>&1 &\n"
        "sleep 300 </dev/null >/dev/null 2>&1 &\n"
        f"echo $$ > {shlex.quote(str(marker))}.tmp && mv {shlex.quote(str(marker))}.tmp {shlex.quote(str(marker))}\n"
        "exec sleep 300\n"
    )
    script.chmod(0o700)
    digest = "sha256:" + hashlib.sha256(script.read_bytes()).hexdigest()
    work = tmp_path / "work"
    work.mkdir()
    src = str(Path(pinned_process.__file__).parents[2])
    host = subprocess.Popen(  # noqa: S603
        [
            sys.executable,
            "-I",
            "-c",
            f"import sys; sys.path.insert(0, {src!r})\n" + source,
            str(work),
            str(script),
            digest,
            str(marker),
            abandon,
        ],
        stdin=subprocess.DEVNULL,
    )
    tree: set[int] = set()
    try:
        deadline = time.monotonic() + 15
        while not marker.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        launcher = int(marker.read_text())
        wrapper = pinned_process._parent(launcher)
        assert wrapper is not None
        tree = {wrapper, *pinned_process._descendant_pids(wrapper)}
        # The host stops the tree only once the test holds every pid: without this
        # hand-off a slow runner reads the launcher's parent after the host has
        # already ended it.
        marker.with_suffix(".go").touch()
        if abandon == "kill-while-stopped":
            host.wait(timeout=15)
        for pid in tree:
            _assert_ended(pid)
    finally:
        with contextlib.suppress(ProcessLookupError):
            host.kill()
        host.wait(timeout=10)
        for pid in tree:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)


# Records the caller's pid whole, then renames it, so a reader never sees a partial pid.
_RECORD = """
def record(path):
    with open(path + ".tmp", "w") as out:
        out.write(str(os.getpid()))
    os.replace(path + ".tmp", path)
def detach():
    null = os.open(os.devnull, os.O_RDWR)
    os.dup2(null, 0)
    os.dup2(null, 1)
def await_record(path):
    deadline = time.monotonic() + 10
    while not os.path.exists(path) and time.monotonic() < deadline:
        time.sleep(0.01)
"""
_PYTHON = "import os, signal, sys, time\n" + _RECORD

# A setsid grandchild that holds neither pipe records its pid and sleeps; the launcher
# waits for the record and then runs END.
_ORPHANING = """marker = {marker!r}
if os.fork() == 0:
    os.setsid()
    if os.fork() == 0:
        detach()
        record(marker)
        time.sleep(60)
    os._exit(0)
await_record(marker)
{end}
"""


def _spawn_python(tmp_path: Path, source: str) -> subprocess.Popen[bytes]:
    return _spawn_opted_out(tmp_path, _PYTHON + source, interpreter=sys.executable)


def _eventually(check: Callable[[], bool]) -> bool:
    deadline = time.monotonic() + 10
    while not check():
        if time.monotonic() > deadline:
            return False
        time.sleep(0.01)
    return True


def _release_spawned(proc: subprocess.Popen[bytes]) -> None:
    """Reap a launch that a test may have left half cleaned up, wrapper and channel too."""
    # A stale entry would steer the cleanup of a later process that reuses the pid.
    _, cgroup, done = pinned_process._OPT_OUT.pop(proc.pid, (None, None, None))
    if done is not None:
        with contextlib.suppress(OSError):
            os.close(done)
    for pipe in (proc.stdin, proc.stdout):
        if pipe is not None:
            pipe.close()
    with contextlib.suppress(ProcessLookupError):
        os.kill(proc.pid, signal.SIGKILL)
    proc.wait(timeout=5)
    if cgroup is not None:
        pinned_process._remove_cgroup(cgroup)


def _clone_parent_launcher(tmp_path: Path, marker: Path) -> tuple[Path, str]:
    """A server whose ``clone(CLONE_PARENT)`` child calls ``setsid`` and records its pid."""
    return _pinned(
        tmp_path / "launcher",
        f"""import ctypes
{_RECORD}
marker = {str(marker)!r}
CLONE_PARENT = 0x00008000
stack = ctypes.create_string_buffer(1024 * 1024)
libc = ctypes.CDLL(None, use_errno=True)
def child(_):
    os.setsid()
    record(marker)
    time.sleep(60)
    return 0
callback = ctypes.CFUNCTYPE(ctypes.c_int, ctypes.c_void_p)(child)
sys._keep = (callback, stack)
cloned = libc.clone(
    callback, ctypes.c_void_p(ctypes.addressof(stack) + len(stack)), CLONE_PARENT, None
)
if cloned < 0:
    raise SystemExit(1)
await_record(marker)
""",
    )


@_LINUX_ONLY
def test_opt_out_teardown_leaves_the_exit_status_of_another_child(tmp_path: Path) -> None:
    # Code elsewhere in the process, such as the validation worker, trusts its child's
    # exit status. A sweep that reaped zombie children of this process, looking for a
    # clone(CLONE_PARENT) child, would turn this 3 into 0. Ported from #228.
    other = subprocess.Popen([sys.executable, "-c", "raise SystemExit(3)"])  # noqa: S603
    os.waitid(os.P_PID, other.pid, os.WEXITED | os.WNOWAIT)
    marker = tmp_path / "pid"
    command, digest = _clone_parent_launcher(tmp_path, marker)
    try:
        with isolation_off():
            observe_pinned(str(command), digest)
        assert marker.exists()
        _assert_dead(_host_pid(marker))
        assert other.wait(timeout=5) == 3
    finally:
        _kill_marked(marker)


@_LINUX_ONLY
def test_opt_out_kills_the_tree_before_its_wrapper(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Killing the wrapper first, as cgroup.kill ahead of the sweep once did to the
    # launcher, hands its tree to pid 1 before the sweep can walk it. Ported from #228.
    marker = tmp_path / "pid"
    proc = _spawn_python(tmp_path, _ORPHANING.format(marker=str(marker), end="time.sleep(60)"))
    kill, killpg = os.kill, os.killpg
    killed: list[int] = []

    def record_kill(pid: int, sig: int) -> None:
        if sig == signal.SIGKILL:
            killed.append(pid)
        kill(pid, sig)

    def record_killpg(pgid: int, sig: int) -> None:
        if sig == signal.SIGKILL:
            killed.append(pgid)
        killpg(pgid, sig)

    try:
        assert _eventually(marker.exists)
        orphan = _host_pid(marker)
        monkeypatch.setattr(pinned_process.os, "kill", record_kill)
        monkeypatch.setattr(pinned_process.os, "killpg", record_killpg)
        pinned_process.terminate_process_group(proc)
        monkeypatch.undo()
        assert orphan in killed[: killed.index(proc.pid)]
        _assert_dead(orphan)
    finally:
        monkeypatch.undo()
        _kill_marked(marker)
        _release_spawned(proc)


@_LINUX_ONLY
def test_opt_out_kills_a_descendant_that_outlives_the_launcher(tmp_path: Path) -> None:
    # Executed directly, the launcher was the subreaper, so once it had exited its
    # orphans were adopted outside its tree and escaped. The wrapper stays their parent,
    # which the cgroup, where one exists, does not show. Ported from #228.
    marker = tmp_path / "pid"
    proc = _spawn_python(tmp_path, _ORPHANING.format(marker=str(marker), end=""))
    try:
        assert proc.stdout is not None
        # End of output: the launcher has exited, and its orphan holds neither pipe.
        assert proc.stdout.read() == b""
        orphan = _host_pid(marker)
        assert _eventually(lambda: _stat(orphan)[1] == str(proc.pid))
        pinned_process.terminate_process_group(proc)
        _assert_dead(orphan)
    finally:
        _kill_marked(marker)
        _release_spawned(proc)


@_LINUX_ONLY
@pytest.mark.parametrize("wrapped", [True, False], ids=["wrapped", "direct"])
def test_opt_out_kills_an_orphan_that_left_the_process_group(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, wrapped: bool
) -> None:
    # killpg misses a process that called setpgid. Under the wrapper it stays in the
    # wrapper's tree. Executed directly, once the launcher has exited, it was adopted
    # outside the tree, and only the sweep of the launch's own session still finds it.
    # Ported from #228.
    if not wrapped:
        monkeypatch.setattr(pinned_process, "_subreaper_argv", lambda staged: None)
    marker = tmp_path / "pid"
    proc = _spawn_python(
        tmp_path,
        f"""marker = {str(marker)!r}
if os.fork() == 0:
    os.setpgid(0, 0)
    detach()
    record(marker)
    time.sleep(60)
    os._exit(0)
await_record(marker)
""",
    )
    try:
        assert proc.stdout is not None
        assert proc.stdout.read() == b""
        orphan = _host_pid(marker)
        assert _stat(orphan)[2:4] == [str(orphan), str(proc.pid)]
        pinned_process.terminate_process_group(proc)
        _assert_dead(orphan)
    finally:
        _kill_marked(marker)
        _release_spawned(proc)


@_LINUX_ONLY
@pytest.mark.parametrize("ending", ["wrapper-killed", "launcher-killed"])
def test_opt_out_reports_a_wrapper_that_a_signal_ended(tmp_path: Path, ending: str) -> None:
    # A wrapper that a signal ended wrote no last byte, and its tree was adopted out of
    # the sweep's reach, so cleanup fails closed. A launcher that a signal ended is
    # reaped by its wrapper, which writes the byte once its tree is empty and only then
    # repeats the launcher's signal, so that cleanup succeeds. Adapted from #228, where
    # both endings read the same.
    marker = tmp_path / "pid"
    if ending == "wrapper-killed":
        end = f"if os.getppid() != {os.getpid()}:\n    os.kill(os.getppid(), signal.SIGKILL)"
        source = _ORPHANING.format(marker=str(marker), end=end)
    else:
        source = "os.kill(os.getpid(), signal.SIGKILL)\n"
    proc = _spawn_python(tmp_path, source)
    try:
        os.waitid(os.P_PID, proc.pid, os.WEXITED | os.WNOWAIT)
        if ending == "wrapper-killed":
            with pytest.raises(pinned_process.PinnedProcessError) as failed:
                pinned_process.terminate_process_group(proc)
            assert failed.value.reason == "isolation-teardown-failed"
            assert "did not outlive everything it started" in str(failed.value)
        else:
            pinned_process.terminate_process_group(proc)
            assert proc.wait(timeout=5) == -signal.SIGKILL
        assert proc.pid not in pinned_process._OPT_OUT
    finally:
        _kill_marked(marker)
        _release_spawned(proc)


@_LINUX_ONLY
@pytest.mark.parametrize(
    "fault", ["passes-exhausted", "proc-scan-unreadable", "proc-unreadable", "wrapper-died"]
)
def test_opt_out_reports_a_tree_it_could_not_confirm_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fault: str
) -> None:
    # A tree that forks faster than it is scanned can outlast the bounded passes, and a
    # /proc scan that cannot be read shows no tree at all; the drain of the stopped
    # wrapper's own children list still kills and confirms what they missed. With that
    # list unreadable too, nothing confirms the tree empty, and a wrapper that died while
    # its tree was swept adopted none of the orphans the sweep made. Adapted from #228,
    # whose sweep alone had to confirm the tree empty.
    marker = tmp_path / "pid"
    quoted = shlex.quote(str(marker))
    # No cgroup.kill, which would end the tree whatever the faults hide.
    monkeypatch.setattr(pinned_process, "_current_cgroup", lambda: None)
    proc = _spawn_opted_out(
        tmp_path, f"echo $$ > {quoted}.tmp && mv {quoted}.tmp {quoted}\necho ready\nexec sleep 60\n"
    )
    sweep = pinned_process._kill_descendants
    real_open = open

    def unreadable() -> dict[int, list[int]]:
        raise PermissionError(13, "Permission denied")

    def no_children_list(path: Any, *args: Any, **kwargs: Any) -> Any:
        if str(path).endswith("/children"):
            raise PermissionError(13, "Permission denied")
        return real_open(path, *args, **kwargs)

    def wrapper_dies_first(root: int) -> None:
        with contextlib.suppress(ProcessLookupError):
            os.kill(root, signal.SIGKILL)
        os.waitid(os.P_PID, root, os.WEXITED | os.WNOWAIT)
        sweep(root)

    try:
        assert proc.stdout is not None and proc.stdout.readline() == b"ready\n"
        launcher = _host_pid(marker)
        if fault == "passes-exhausted":
            monkeypatch.setattr(pinned_process, "_SWEEP_PASSES", 0)
        elif fault == "proc-scan-unreadable":
            monkeypatch.setattr(pinned_process, "_children_by_parent", unreadable)
        elif fault == "proc-unreadable":
            monkeypatch.setattr(pinned_process, "_children_by_parent", unreadable)
            monkeypatch.setattr(pinned_process, "open", no_children_list, raising=False)
        else:
            monkeypatch.setattr(pinned_process, "_kill_descendants", wrapper_dies_first)
        if fault in {"proc-unreadable", "wrapper-died"}:
            with pytest.raises(pinned_process.PinnedProcessError) as failed:
                pinned_process.terminate_process_group(proc)
            assert failed.value.reason == "isolation-teardown-failed"
        else:
            pinned_process.terminate_process_group(proc)
        monkeypatch.undo()
        # Reported or not, nothing the launch started is left running once cleanup ends.
        _assert_dead(launcher)
    finally:
        monkeypatch.undo()
        _kill_marked(marker)
        _release_spawned(proc)


@_LINUX_ONLY
@pytest.mark.parametrize(
    ("ending", "status"),
    [("exit 3", 3), ("kill -TERM $$", -signal.SIGTERM), ("kill -KILL $$", -signal.SIGKILL)],
)
def test_the_wrapper_reports_the_launcher_exit_status_as_a_direct_exec_does(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, ending: str, status: int
) -> None:
    # Callers report a launcher that crashed from the status of the process they started.
    # Ported from #228.
    results = []
    for wrapped in (True, False):
        with monkeypatch.context() as direct:
            if not wrapped:
                direct.setattr(pinned_process, "_subreaper_argv", lambda staged: None)
            base = tmp_path / str(wrapped)
            base.mkdir()
            proc = _spawn_opted_out(base, f"read -r line\necho got:$line\n{ending}\n")
        try:
            output, _ = proc.communicate(b"x\n", timeout=10)
            results.append((output, proc.returncode))
            pinned_process.terminate_process_group(proc)
        finally:
            _release_spawned(proc)
    assert results == [(b"got:x\n", status)] * 2


@_LINUX_ONLY
@pytest.mark.parametrize(
    ("ending", "contained"),
    [("exit 0", True), ("kill -KILL $$", True), ("kill -KILL $PPID", False)],
)
def test_cleanup_after_the_wrapper_was_reaped_reports_how_it_ended(
    tmp_path: Path, ending: str, contained: bool
) -> None:
    # A reaped wrapper's pid may already name another process, so nothing is stopped or
    # swept; only its last byte shows that it had emptied its tree, which a wrapper that
    # the launcher killed never wrote. Adapted from #228, where any wrapper that a signal
    # ended failed, including one that only repeated its launcher's signal.
    proc = _spawn_opted_out(tmp_path, f"{ending}\n")
    proc.wait(timeout=10)
    try:
        if contained:
            pinned_process.terminate_process_group(proc)
        else:
            with pytest.raises(pinned_process.PinnedProcessError, match="did not outlive"):
                pinned_process.terminate_process_group(proc)
    finally:
        _release_spawned(proc)


@_LINUX_ONLY
def test_the_session_sweep_targets_only_a_session_the_launch_leads(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The session sweep kills every member of the session, so it may only ever target one
    # that start_new_session created for the launch, never the caller's own. Adapted from
    # #228, which checked the session before recording it.
    proc = _spawn_opted_out(tmp_path, "exec sleep 60\n")
    try:
        assert pinned_process._OPT_OUT[proc.pid][0] == proc.pid != os.getsid(0)
    finally:
        _release_spawned(proc)
    inherited = subprocess.Popen(["/bin/sleep", "30"])  # noqa: S603
    try:
        assert os.getsid(inherited.pid) == os.getsid(0)
        signalled: list[int] = []
        monkeypatch.setattr(pinned_process.os, "kill", lambda pid, sig: signalled.append(pid))
        pinned_process._kill_session(os.getsid(0))
        monkeypatch.undo()
        assert signalled == []
    finally:
        monkeypatch.undo()
        inherited.kill()
        inherited.wait(timeout=5)


# The main thread exits while a second thread sleeps, so the process reads as a zombie
# in /proc/<pid>/stat although it is still running.
_EXITED_MAIN_THREAD = (
    "import ctypes, os, sys, threading, time\n"
    "threading.Thread(target=time.sleep, args=(60,)).start()\n"
    "open(sys.argv[1] + '.tmp', 'w').write(str(os.getpid()))\n"
    "os.replace(sys.argv[1] + '.tmp', sys.argv[1])\n"
    "ctypes.CDLL(None).pthread_exit(None)\n"
)


@_LINUX_ONLY
def test_a_survivor_whose_main_thread_exited_is_not_taken_for_ended(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A descendant that cleanup may not signal, whose main thread has exited, must keep
    # the teardown from being confirmed. Ported from #228.
    marker = tmp_path / "pid"
    command, digest = _pinned(
        tmp_path / "launcher",
        "import subprocess\n"
        f"subprocess.Popen([{sys.executable!r}, '-I', '-S', '-c', {_EXITED_MAIN_THREAD!r},"
        f" {str(marker)!r}], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,"
        " stderr=subprocess.DEVNULL)\n"
        f"for _ in range(300):\n    if os.path.exists({str(marker)!r}):\n        break\n"
        "    time.sleep(0.01)\n"
        "time.sleep(0.2)\n",
    )
    kill = os.kill

    def refuse(pid: int, sig: int) -> None:
        # Stands in for a process of the tree that this user may not signal.
        if marker.exists() and pid == _host_pid(marker):
            raise PermissionError(1, "Operation not permitted")
        kill(pid, sig)

    monkeypatch.setattr(pinned_process.os, "kill", refuse)
    monkeypatch.setattr(pinned_process, "_TEARDOWN_SECONDS", 0.5)
    try:
        with isolation_off(), pytest.raises(LaunchPolicyError) as failed:
            observe_pinned(str(command), digest)
        assert failed.value.reason == "isolation-teardown-failed"
    finally:
        monkeypatch.undo()
        _kill_marked(marker)


@pytest.mark.parametrize(
    ("platform", "opted_out", "verifiable"),
    [("darwin", True, False), ("darwin", False, True), ("linux", True, True)],
)
def test_teardown_is_verifiable_unless_opted_out_where_descendants_cannot_be_listed(
    platform: str, opted_out: bool, verifiable: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(pinned_process.sys, "platform", platform)
    with isolation_off() if opted_out else contextlib.nullcontext():
        assert pinned_process.teardown_verifiable() is verifiable
