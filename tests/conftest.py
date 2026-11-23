"""Suite-wide isolation, a per-test time limit, skip accounting and Hypothesis profiles.

Every test starts without the ambient variables that the tool, the Action runner and the gate
scripts read, with HOME, the XDG directories and TMPDIR in a private temporary directory and
the default collection limits, and must leave no operating mode enforced and no other limits.
Python-level connects, datagrams and name resolution to anywhere but loopback fail the test
(subprocesses and native code are not covered). A
test that runs longer than ``test_timeout`` seconds fails with its traceback. Every skip is listed with its reason; with ``--strict-skips`` (CI) a skip
for any reason other than the host's file system, a Linux interface on another host, or, outside
CI, a missing pip, fails the run.
"""

from __future__ import annotations

import ipaddress
import os
import re
import signal
import socket
import sys
import tempfile
import threading
from collections.abc import Callable, Iterator
from types import FrameType, ModuleType
from typing import Any

import pytest
from click.testing import CliRunner
from hypothesis import HealthCheck, settings

from nexus_symbiote import limits, modes
from nexus_symbiote.supply_chain_cli import _HOST_CREDENTIAL_ENV

ISOLATED_PREFIXES = ("NEXUS_SYMBIOTE_", "SYMBIOTE_", "SHADOWSCAN_", "GITHUB_", "RUNNER_")
ISOLATED_NAMES = frozenset(
    {
        *_HOST_CREDENTIAL_ENV,
        "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
        "ACTIONS_ID_TOKEN_REQUEST_URL",
        "ACTIONS_RUNTIME_TOKEN",
        "COLUMNS",
        "LINES",
        "FORCE_COLOR",
        "NO_COLOR",
        "CLICOLOR",
        "CLICOLOR_FORCE",
        "TTY_COMPATIBLE",
        "TTY_INTERACTIVE",
        "SOURCE_DATE_EPOCH",
        "SOAK_OVERRIDE",
        "ALLOWED_RELEASE_TAG_SIGNERS",
        "SSLKEYLOGFILE",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "http_proxy",
        "https_proxy",
        "all_proxy",
        "no_proxy",
        "REQUEST_METHOD",
        # The unsigned-discovery gate fails closed when these say the run is automated;
        # a test that needs that sets one itself.
        "CI",
        "GITLAB_CI",
        "CIRCLECI",
        "TF_BUILD",
        "JENKINS_URL",
        "BUILDKITE",
        "DRONE",
        "TRAVIS",
    }
)
PRIVATE_DIRECTORIES = ("XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME")
# Skips that depend only on the host: a case-insensitive alias exists only on a
# case-insensitive file system, and some file systems refuse unusual names.
# Only these exact reason texts pass a strict run: a reason that merely starts with or
# contains the words could disable any test.
EXPECTED_SKIP_REASONS = (
    re.compile(r"\Athe file system is case-sensitive, so the alias does not exist\Z"),
)
# Expected only outside CI: an environment that uv created has no pip, while CI always
# installs with pip, so there the differential against pip's own reader has to run.
LOCAL_SKIP_REASONS = (
    re.compile(r"\Apip is not importable here; CI, which installs with pip, runs this test\Z"),
)
# Expected only off Linux: these tests drive /proc, prctl, pidfds or clone(CLONE_PARENT),
# which macOS lacks. A Linux run that skips one fails. Pinned execution elsewhere refuses
# the namespace launch these mechanisms serve, which runs on every platform.
NON_LINUX_SKIP_REASONS = (
    re.compile(
        r"\A(?:the subreaper wrapper|clone\(CLONE_PARENT\)|the /proc descendant sweep"
        r"|the PID namespace teardown) is Linux-only\Z"
    ),
    re.compile(r"\Ano (?:/proc/self/cwd|/dev/fd link into /proc)\Z"),
    # The suite's tmp_path lies on a case-sensitive Linux file system that holds any byte
    # string but "/" and NUL as a name (not vfat, ntfs3, a casefold ext4 directory or a
    # utf8only ZFS dataset): a Linux run that skips for one of these is testing nothing.
    re.compile(
        r"\Afile system rejects (?:the name|distinct case spellings|names that are not UTF-8)\Z"
    ),
    re.compile(r"\Aneeds a case-sensitive file system to hold (?:both|distinct) spellings\Z"),
)
DEFAULT_TIMEOUT_SECONDS = 300


@pytest.fixture
def nonisolated_pinned_fixtures(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Protocol fixtures opt out explicitly; containment has separate default-denial tests.

    Off Linux the product refuses the opt-out. These tests check the MCP exchange, not
    containment, so they lift that refusal to keep running there; the refusal itself is
    tested without this fixture, in tests/test_pinned_process_isolation.py.
    """
    from nexus_symbiote.live import pinned_process

    monkeypatch.setattr(pinned_process, "opt_out_supported", lambda: True)
    with pinned_process.isolation_off():
        yield


settings.register_profile(
    "repository",
    derandomize=True,
    database=None,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
settings.register_profile(
    "fuzz",
    derandomize=False,
    max_examples=2000,
    deadline=None,
    print_blob=True,
    suppress_health_check=[HealthCheck.too_slow],
)
# Hypothesis's own --hypothesis-profile option is applied later and still wins.
settings.load_profile("repository")


def pytest_addoption(parser: pytest.Parser) -> None:
    parser.addini(
        "test_timeout",
        "seconds after which a test fails as hung; 0 disables the limit",
        default=str(DEFAULT_TIMEOUT_SECONDS),
    )
    parser.addoption(
        "--strict-skips",
        action="store_true",
        help=(
            "fail the run when a test is skipped for a reason other than the host file system, "
            "a Linux interface on another host, or, outside CI, a missing pip"
        ),
    )


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "timeout(seconds): this test's own time limit instead of test_timeout"
    )
    config.addinivalue_line(
        "markers",
        "locked_only: compares what a pinned dependency generates, such as a pydantic JSON"
        " schema, with a committed file; the dependency-floor job deselects it",
    )
    config.pluginmanager.register(SkipAccounting(config), "nexus-symbiote-skip-accounting")
    # pytest-cov starts its controller's collector in every pytest-xdist worker before it knows
    # the process is a worker, and the worker's own collector on top. Pausing the latter for a
    # no_cover test resumes the former, whose data is never saved, so the test would run traced.
    controller = getattr(config.pluginmanager.get_plugin("_cov"), "cov_controller", None)
    if controller is not None and hasattr(config, "workerinput"):
        controller.cov.stop()


class SkipAccounting:
    """Collect every skip, so that a test which silently stops running is visible."""

    def __init__(self, config: pytest.Config) -> None:
        self.config = config
        self.skips: list[tuple[str, str]] = []

    def _record(self, report: pytest.TestReport | pytest.CollectReport) -> None:
        if not report.skipped:
            return
        if hasattr(report, "wasxfail"):
            # An expected failure did not run to its assertions, as a skip does not:
            # pytest.xfail(), xfail(run=False) or a conditional marker. No reason is expected.
            self.skips.append((report.nodeid, f"xfail: {report.wasxfail}"))
            return
        longrepr = report.longrepr
        if isinstance(longrepr, tuple) and len(longrepr) == 3:
            reason = str(longrepr[2])
        else:
            reason = str(longrepr)
        self.skips.append((report.nodeid, reason.removeprefix("Skipped: ")))

    def pytest_runtest_logreport(self, report: pytest.TestReport) -> None:
        self._record(report)

    def pytest_collectreport(self, report: pytest.CollectReport) -> None:
        self._record(report)

    def unexpected(self) -> list[tuple[str, str]]:
        expected = EXPECTED_SKIP_REASONS + (() if os.environ.get("CI") else LOCAL_SKIP_REASONS)
        if not sys.platform.startswith("linux"):
            expected += NON_LINUX_SKIP_REASONS
        return [
            (nodeid, reason)
            for nodeid, reason in self.skips
            if not any(pattern.search(reason) for pattern in expected)
        ]

    @pytest.hookimpl(tryfirst=True)
    def pytest_sessionfinish(self, session: pytest.Session, exitstatus: int) -> None:
        if self.config.getoption("--strict-skips") and self.unexpected() and exitstatus == 0:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED

    def pytest_terminal_summary(self, terminalreporter: Any) -> None:
        if not self.skips:
            return
        unexpected = set(self.unexpected())
        terminalreporter.section("skip accounting")
        for nodeid, reason in self.skips:
            state = "UNEXPECTED" if (nodeid, reason) in unexpected else "expected"
            terminalreporter.write_line(f"{state}: {nodeid}: {reason}")
        if unexpected and self.config.getoption("--strict-skips"):
            terminalreporter.write_line("--strict-skips: unexpected skips fail this run")


@pytest.fixture(autouse=True)
def _isolated_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Iterator[None]:
    for name in list(os.environ):
        if name.startswith(ISOLATED_PREFIXES) or name in ISOLATED_NAMES:
            monkeypatch.delenv(name)
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    for name in PRIVATE_DIRECTORIES:
        monkeypatch.setenv(name, str(home / name.lower()))
    private_tmp = home / "tmp"
    private_tmp.mkdir()
    monkeypatch.setenv("TMPDIR", str(private_tmp))
    # tempfile caches the directory on first use; the cache must follow TMPDIR.
    tempfile.tempdir = None

    # The suite's own tripwire against a test that reaches the network: connecting,
    # sending a datagram or resolving a name anywhere but the loopback interface or
    # exact localhost fails the test. Reserved suffixes still may reach a resolver and
    # are not a network boundary. The product's offline
    # guard (modes.enforce) replaces the same entry points while it is installed, so the
    # tripwire stands down only then and never masks an OfflineViolation a test expects.
    # _socket.socket, the C type, is immutable: the product's audit hook is its only guard.
    def _is_loopback_name(host: Any) -> bool:
        if isinstance(host, (bytes, bytearray)):
            host = bytes(host).decode("ascii", "replace")
        if not isinstance(host, str):
            return False
        name = host.lower()
        if name == "localhost":
            return True
        try:
            # Do not strip suffixes that the real resolver will still receive.
            # Scoped IPv6 and dotted DNS spellings need an explicit test stub.
            return "%" not in name and ipaddress.ip_address(name).is_loopback
        except ValueError:
            return False

    def _is_loopback_target(address: Any) -> bool:
        if not isinstance(address, tuple):
            return True  # Unix-domain addresses have no Internet host to resolve.
        return bool(address) and _is_loopback_name(address[0])

    def _refuse(what: str) -> OSError:
        return OSError(f"test suite blocked outbound non-loopback {what}")

    def _guarded() -> bool:
        return not modes._patches

    orig_connect = socket.socket.connect
    orig_connect_ex = socket.socket.connect_ex
    orig_sendto = socket.socket.sendto
    orig_sendmsg = socket.socket.sendmsg
    orig_getaddrinfo = socket.getaddrinfo
    orig_gethostbyname = socket.gethostbyname
    orig_gethostbyname_ex = socket.gethostbyname_ex
    orig_gethostbyaddr = socket.gethostbyaddr
    orig_getnameinfo = socket.getnameinfo
    orig_create_connection = socket.create_connection

    def _guarded_connect(sock: socket.socket, address: Any) -> Any:
        if _guarded() and not _is_loopback_target(address):
            raise _refuse("socket connection")
        return orig_connect(sock, address)

    def _guarded_connect_ex(sock: socket.socket, address: Any) -> int:
        if _guarded() and not _is_loopback_target(address):
            raise _refuse("socket connection")
        return orig_connect_ex(sock, address)

    def _guarded_sendto(sock: socket.socket, data: Any, *rest: Any) -> int:
        # sendto(data, address) or sendto(data, flags, address).
        if _guarded() and rest and not _is_loopback_target(rest[-1]):
            raise _refuse("datagram (sendto)")
        return orig_sendto(sock, data, *rest)

    def _guarded_sendmsg(sock: socket.socket, buffers: Any, *rest: Any) -> int:
        # sendmsg(buffers[, ancdata[, flags[, address]]]).
        if _guarded() and len(rest) >= 3 and not _is_loopback_target(rest[2]):
            raise _refuse("datagram (sendmsg)")
        return orig_sendmsg(sock, buffers, *rest)

    def _guarded_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
        # None requests a local passive/unspecified address without DNS.
        if _guarded() and host is not None and not _is_loopback_name(host):
            raise _refuse("name resolution (getaddrinfo)")
        return orig_getaddrinfo(host, *args, **kwargs)

    def _guarded_gethostbyname(host: Any) -> Any:
        if _guarded() and not _is_loopback_name(host):
            raise _refuse("name resolution (gethostbyname)")
        return orig_gethostbyname(host)

    def _guarded_gethostbyname_ex(host: Any) -> Any:
        if _guarded() and not _is_loopback_name(host):
            raise _refuse("name resolution (gethostbyname_ex)")
        return orig_gethostbyname_ex(host)

    def _guarded_gethostbyaddr(host: Any) -> Any:
        if _guarded() and not _is_loopback_name(host):
            raise _refuse("name resolution (gethostbyaddr)")
        return orig_gethostbyaddr(host)

    def _guarded_getnameinfo(address: Any, flags: Any) -> Any:
        if _guarded() and (not isinstance(address, tuple) or not _is_loopback_target(address)):
            raise _refuse("name resolution (getnameinfo)")
        return orig_getnameinfo(address, flags)

    def _guarded_create_connection(address: Any, *args: Any, **kwargs: Any) -> Any:
        if _guarded() and not _is_loopback_target(address):
            raise _refuse("socket connection (create_connection)")
        return orig_create_connection(address, *args, **kwargs)

    monkeypatch.setattr(socket.socket, "connect", _guarded_connect)
    monkeypatch.setattr(socket.socket, "connect_ex", _guarded_connect_ex)
    monkeypatch.setattr(socket.socket, "sendto", _guarded_sendto)
    monkeypatch.setattr(socket.socket, "sendmsg", _guarded_sendmsg)
    monkeypatch.setattr(socket, "getaddrinfo", _guarded_getaddrinfo)
    monkeypatch.setattr(socket, "gethostbyname", _guarded_gethostbyname)
    monkeypatch.setattr(socket, "gethostbyname_ex", _guarded_gethostbyname_ex)
    monkeypatch.setattr(socket, "gethostbyaddr", _guarded_gethostbyaddr)
    monkeypatch.setattr(socket, "getnameinfo", _guarded_getnameinfo)
    monkeypatch.setattr(socket, "create_connection", _guarded_create_connection)
    # Collection limits and umask are process state: normalize umask to 0022 so permission
    # checks behave identically inside containers with umask 0000, and restore both after.
    previous_umask = os.umask(0o022)
    try:
        with limits.applied(limits.DEFAULTS):
            yield
            limits_left = limits.current() != limits.DEFAULTS
    finally:
        tempfile.tempdir = None
        os.umask(previous_umask)
    leaked = modes.current()
    if leaked is not None:
        pytest.fail(f"the test left the {leaked.value} mode enforced", pytrace=False)
    if limits_left:
        pytest.fail("the test left collection limits other than the defaults", pytrace=False)


@pytest.fixture(autouse=True)
def _restored_scanner_registry() -> Iterator[None]:
    from nexus_symbiote import cli

    saved = dict(cli.SCANNER_REGISTRY)
    yield
    cli.SCANNER_REGISTRY.clear()
    cli.SCANNER_REGISTRY.update(saved)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def load_script() -> Callable[[str], ModuleType]:
    from tests.support import load_script

    return load_script


def _time_limit(item: pytest.Item) -> float:
    marker = item.get_closest_marker("timeout")
    if marker is not None and marker.args:
        return float(marker.args[0])
    return float(item.config.getini("test_timeout") or 0)


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_call(item: pytest.Item) -> Iterator[None]:
    seconds = _time_limit(item)
    if (
        seconds <= 0
        or not hasattr(signal, "setitimer")
        or threading.current_thread() is not threading.main_thread()
        or item.config.pluginmanager.hasplugin("timeout")
    ):
        yield
        return

    def expire(_signum: int, _frame: FrameType | None) -> None:
        pytest.fail(f"test exceeded its {seconds:g}-second time limit")

    previous = signal.signal(signal.SIGALRM, expire)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
