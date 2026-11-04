"""Offline-by-default operation and explicit live mode."""

from __future__ import annotations

import _socket
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import modes
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.live_mcp import DiscoveryResult

UNSET = {modes.ENV_VAR: None}


def _attempts() -> dict[str, object]:
    return {
        "socket.getaddrinfo": lambda: socket.getaddrinfo("example.com", 443),
        "socket.gethostbyname": lambda: socket.gethostbyname("example.com"),
        "_socket.getaddrinfo": lambda: _socket.getaddrinfo("example.com", 443),
        "socket.create_connection": lambda: socket.create_connection(("192.0.2.1", 443), 0.01),
        "socket.connect": lambda: socket.socket().connect(("192.0.2.1", 443)),
        "subprocess": lambda: subprocess.run([sys.executable, "-c", "pass"], check=False),  # noqa: S603
        "os.system": lambda: os.system("true"),  # noqa: S605, S607
    }


@pytest.mark.parametrize(
    ("offline", "live", "environ", "expected", "source"),
    [
        (False, False, {}, modes.Mode.OFFLINE, "default"),
        (False, False, {modes.ENV_VAR: ""}, modes.Mode.OFFLINE, "default"),
        (False, False, {modes.ENV_VAR: "live"}, modes.Mode.LIVE, "environment"),
        (False, False, {modes.ENV_VAR: "offline"}, modes.Mode.OFFLINE, "environment"),
        (True, False, {modes.ENV_VAR: "live"}, modes.Mode.OFFLINE, "flag"),
        (False, True, {modes.ENV_VAR: "offline"}, modes.Mode.LIVE, "flag"),
    ],
)
def test_resolve_prefers_flag_then_environment_then_offline(
    offline, live, environ, expected, source
):
    resolved = modes.resolve(offline=offline, live=live, environ=environ)
    assert (resolved.mode, resolved.source) == (expected, source)


@pytest.mark.parametrize("value", ["LIVE", "on", "1", "true", " live"])
def test_unrecognized_environment_value_is_an_error_not_a_fallback(value):
    with pytest.raises(ValueError, match=modes.ENV_VAR):
        modes.resolve(offline=False, live=False, environ={modes.ENV_VAR: value})


def test_both_flags_are_refused():
    with pytest.raises(ValueError, match="not both"):
        modes.resolve(offline=True, live=True, environ={})


def test_only_live_commands_can_run_live():
    for command in modes.LIVE_COMMANDS:
        assert modes.command_mode(modes.Mode.LIVE, command) is modes.Mode.LIVE
        assert modes.command_mode(modes.Mode.OFFLINE, command) is modes.Mode.OFFLINE
    for command in ("scan", "validate", "runtime", None):
        assert modes.command_mode(modes.Mode.LIVE, command) is modes.Mode.OFFLINE


@pytest.mark.parametrize("operation", sorted(_attempts()))
def test_offline_guard_refuses_network_and_process_creation(operation):
    attempt = _attempts()[operation]
    with modes.enforce(modes.Mode.OFFLINE), pytest.raises(modes.OfflineViolation):
        attempt()


def test_offline_violation_escapes_broad_exception_handlers():
    caught_as_exception = False
    with modes.enforce(modes.Mode.OFFLINE), pytest.raises(modes.OfflineViolation):
        try:
            socket.getaddrinfo("example.com", 443)
        except Exception:
            caught_as_exception = True
    assert not caught_as_exception


def test_guard_is_removed_after_the_block_even_when_it_raises():
    originals = (
        socket.getaddrinfo,
        _socket.getaddrinfo,
        socket.create_connection,
        subprocess.Popen._execute_child,  # type: ignore[attr-defined]
        os.system,
    )
    assert "connect" not in vars(socket.socket)

    def failing_body() -> None:
        with modes.enforce(modes.Mode.OFFLINE):
            assert modes.current() is modes.Mode.OFFLINE
            raise RuntimeError("body failed")

    with pytest.raises(RuntimeError):
        failing_body()
    assert modes.current() is None
    assert "connect" not in vars(socket.socket)
    assert (
        socket.getaddrinfo,
        _socket.getaddrinfo,
        socket.create_connection,
        subprocess.Popen._execute_child,  # type: ignore[attr-defined]
        os.system,
    ) == originals


def test_live_mode_installs_no_guard():
    original = socket.getaddrinfo
    with modes.enforce(modes.Mode.LIVE):
        assert socket.getaddrinfo is original
        assert modes.current() is modes.Mode.LIVE
    assert modes.current() is None


def test_nested_enforcement_must_agree():
    with modes.enforce(modes.Mode.OFFLINE):
        with modes.enforce(modes.Mode.OFFLINE):
            assert modes.current() is modes.Mode.OFFLINE
        assert modes.current() is modes.Mode.OFFLINE
        with pytest.raises(RuntimeError), modes.enforce(modes.Mode.LIVE):
            pass
    assert modes.current() is None


def test_require_live_outside_the_cli_defaults_to_offline(monkeypatch):
    monkeypatch.delenv(modes.ENV_VAR, raising=False)
    with pytest.raises(modes.LiveModeRequiredError, match="--live"):
        modes.require_live("advisories")
    monkeypatch.setenv(modes.ENV_VAR, "live")
    modes.require_live("advisories")
    with modes.enforce(modes.Mode.OFFLINE), pytest.raises(modes.LiveModeRequiredError):
        modes.require_live("advisories")


def _live_invocations(tmp_path: Path) -> dict[str, list[str]]:
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM().to_json())
    project = tmp_path / "project"
    project.mkdir()
    policy = tmp_path / "operator" / "launch-policy.json"
    policy.parent.mkdir()
    policy.write_text("{}")
    return {
        "discover-mcp": [
            "discover-mcp",
            "https://mcp.example.com/mcp",
            "--allowed-origin",
            "https://mcp.example.com",
        ],
        "advisories": ["advisories", str(bom)],
        "verify-live": [
            "verify-live",
            str(bom),
            "--project",
            str(project),
            "--launch-policy",
            str(policy),
        ],
    }


def _forbid_live_work(monkeypatch) -> None:
    def forbidden(*_args, **_kwargs):
        raise AssertionError("a live step ran without live mode")

    monkeypatch.setattr("nexus_symbiote.live_cli.discover_tools", forbidden)
    monkeypatch.setattr("nexus_symbiote.advisories.fetch_advisories", forbidden)
    monkeypatch.setattr("nexus_symbiote.live.verify.verify_mcp_servers", forbidden)


@pytest.mark.parametrize("command", sorted(modes.LIVE_COMMANDS))
@pytest.mark.parametrize(
    ("prefix", "env"),
    [
        ([], UNSET),
        (["--offline"], UNSET),
        ([], {modes.ENV_VAR: "offline"}),
        (["--offline"], {modes.ENV_VAR: "live"}),
    ],
)
def test_live_commands_refuse_to_run_offline(tmp_path, monkeypatch, command, prefix, env):
    _forbid_live_work(monkeypatch)
    args = prefix + _live_invocations(tmp_path)[command]
    result = CliRunner().invoke(main, args, env=env)
    assert result.exit_code == 2, result.output
    assert f"{command} is a live command" in result.output
    assert f"nexus-symbiote --live {command}" in result.output
    assert result.exception is None or isinstance(result.exception, SystemExit)


@pytest.mark.parametrize(("prefix", "env"), [(["--live"], UNSET), ([], {modes.ENV_VAR: "live"})])
def test_live_mode_runs_live_commands_without_the_guard(monkeypatch, prefix, env):
    observed: list[object] = []

    def fake_discover(endpoint, **_kwargs):
        observed.append((modes.current(), socket.getaddrinfo))
        return DiscoveryResult(endpoint=endpoint, complete=True)

    monkeypatch.setattr("nexus_symbiote.live_cli.discover_tools", fake_discover)
    result = CliRunner().invoke(
        main,
        prefix
        + [
            "discover-mcp",
            "https://mcp.example.com/mcp",
            "--allowed-origin",
            "https://mcp.example.com",
        ],
        env=env,
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["complete"] is True
    [(mode, resolver)] = observed
    assert mode is modes.Mode.LIVE
    assert resolver is socket.getaddrinfo


class _NetworkScanner(Scanner):
    name = "network"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        try:
            socket.getaddrinfo("example.com", 443)
        except Exception:  # a collector's broad handler must not absorb the violation
            result.scan_failures.append("lookup failed")
        return result


class _ProcessScanner(Scanner):
    name = "process"

    def scan(self, project_root: Path) -> ScanResult:
        subprocess.run(["true"], check=False)  # noqa: S603, S607
        return ScanResult(scanner_name=self.name)


@pytest.mark.parametrize("scanner", [_NetworkScanner, _ProcessScanner])
@pytest.mark.parametrize("prefix", [[], ["--live"]])
def test_static_commands_stay_offline_even_in_live_mode(tmp_path, monkeypatch, scanner, prefix):
    monkeypatch.setattr("nexus_symbiote.cli._get_scanners", lambda: {scanner.name: scanner})
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        prefix
        + ["scan", str(tmp_path), "--scanner", scanner.name, "--report-only", "-o", str(output)],
        env=UNSET,
    )
    assert result.exit_code == 1, result.output
    assert "offline mode blocked" in result.output
    assert "report this as a defect" in result.output
    assert not output.exists()
    assert modes.current() is None


def test_mode_flags_after_the_command_get_a_placement_hint(tmp_path):
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM().to_json())
    result = CliRunner().invoke(main, ["advisories", "--live", str(bom)], env=UNSET)
    assert result.exit_code == 2
    assert "Mode flags go before the command: nexus-symbiote --live <command>" in result.output


def test_invalid_environment_mode_fails_closed_but_version_still_works(tmp_path):
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM().to_json())
    env = {modes.ENV_VAR: "yes"}
    refused = CliRunner().invoke(main, ["summary", str(bom)], env=env)
    assert refused.exit_code == 2
    assert f"{modes.ENV_VAR} must be 'offline' or 'live'" in refused.output
    version = CliRunner().invoke(main, ["--version"], env=env)
    assert version.exit_code == 0
    assert "nexus-symbiote, version" in version.output


REPOSITORY = Path(__file__).resolve().parents[1]
SHADOWSCAN_REPORT = REPOSITORY / "tests" / "fixtures" / "shadowscan" / "code-report-0.1.4.json"


def test_every_static_command_runs_under_the_offline_guard(tmp_path):
    from datetime import UTC, datetime, timedelta
    from hashlib import sha256

    from nexus_symbiote.runtime import TrustStatus

    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp@1.2.3"]}}})
    )
    (project / "system_prompt.md").write_text("Answer from the documentation only.\n")
    digest = "sha256:" + sha256((project / "system_prompt.md").read_bytes()).hexdigest()
    (tmp_path / "policy").mkdir()
    native, imported = tmp_path / "bom.json", tmp_path / "imported.json"
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    now = datetime.now(UTC)
    contract = tmp_path / "trust.json"
    contract.write_text(
        TrustStatus(
            tenant="acme",
            serial=1,
            not_before=now - timedelta(seconds=1),
            not_after=now + timedelta(minutes=5),
        ).model_dump_json()
    )
    runner = CliRunner()

    def run(*args: str, expect: tuple[int, ...] = (0,)) -> str:
        result = runner.invoke(main, list(args), env=UNSET)
        assert "offline mode blocked" not in result.output, (args, result.output)
        assert not isinstance(result.exception, modes.OfflineViolation), args
        assert result.exit_code in expect, (args, result.exit_code, result.output)
        return result.stdout

    run("init", "--path", str(tmp_path / "policy"))
    run("scan", str(project), "-o", str(native), expect=(0, 1))
    for fmt in ("cyclonedx", "spdx", "sarif"):
        run("scan", str(project), "--report-only", "-f", fmt, "-o", str(tmp_path / fmt))
        assert (tmp_path / fmt).stat().st_size > 0
    run("validate", str(native), "--project", str(project), "--no-project-policy", expect=(0, 1))
    run("risk", str(native), "--no-project-policy", expect=(0, 1))
    run("summary", str(native))
    run("diff", str(native), str(native), "--fail-on-alert")
    agent = next(
        c["bom_ref"]
        for c in json.loads(native.read_text())["components"]
        if c["component_type"] == "agent"
    )
    run("blast-radius", str(native), agent, "--json-output")
    run("vex", str(native), "-o", str(tmp_path / "vex.json"))
    run("baseline", str(project), "-o", str(tmp_path / "baseline.json"), expect=(0, 1))
    run("verify-artifact", "system_prompt.md", "--project", str(project), "--sha256", digest)
    run("import-shadowscan", str(SHADOWSCAN_REPORT), "--report-only", "-o", str(imported))
    run("verify-discovery", str(imported), str(SHADOWSCAN_REPORT), "--projection")
    run("runtime", "keygen", "--private-key", str(private), "--public-key", str(public))
    signed = tmp_path / "signed.json"
    run(
        "runtime",
        "sign",
        str(contract),
        "--kind",
        "trust",
        "--key",
        str(private),
        "--out",
        str(signed),
    )
    verified = run("runtime", "verify", str(signed), "--kind", "trust", "--public-key", str(public))
    assert json.loads(verified)["contract_verified"] is True


# A random operator key in the format the walkthrough generates with token_hex(32).
DEMO_BINDING_KEY = "de61cc580f37acf0bae7d6f264f846bf257b698be498660944892cb2f7fe1fc3"


def test_documented_offline_demo_collects_every_surface(tmp_path, monkeypatch):
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", DEMO_BINDING_KEY)
    demo = REPOSITORY / "examples" / "demo-agent"
    if not demo.is_dir():
        pytest.skip("the demo project ships in the repository, not in the wheel")
    output = tmp_path / "demo.aibom.json"
    result = CliRunner().invoke(main, ["scan", str(demo), "-o", str(output)], env=UNSET)
    assert result.exit_code == 0, result.output
    bom = json.loads(output.read_text())
    completeness = bom["metadata"]["completeness"]
    assert completeness["scan_failures"] == []
    assert set(completeness["scanner_status"].values()) == {"complete"}
    types = {c["component_type"] for c in bom["components"]}
    assert {
        "agent",
        "mcp-client",
        "mcp-server",
        "model",
        "prompt-template",
        "rag-source",
        "registry-entry",
        "a2a-server",
        "ide-agent",
    } <= types


def test_demo_results_match_the_published_walkthrough(tmp_path, monkeypatch):
    # README.md ("See it on the demo agent") and examples/README.md quote these
    # results; update both documents together with this test. The A2A card needs
    # the operator binding key, or the scan's default gate fails.
    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", DEMO_BINDING_KEY)
    demo = REPOSITORY / "examples" / "demo-agent"
    if not demo.is_dir():
        pytest.skip("the demo project ships in the repository, not in the wheel")
    output = tmp_path / "demo.aibom.json"
    runner = CliRunner()
    scanned = runner.invoke(main, ["scan", str(demo), "-o", str(output)], env=UNSET)
    assert scanned.exit_code == 0, scanned.output
    components = json.loads(output.read_text())["components"]
    assert len(components) == 11
    assert len({component["component_type"] for component in components}) == 9
    risk = runner.invoke(
        main, ["risk", str(output), "--no-project-policy", "--json-output"], env=UNSET
    )
    assert risk.exit_code == 0, risk.output
    report = json.loads(risk.stdout)
    assert report["overall_score"] == 33
    assert {k: v for k, v in report["severity_counts"].items() if v} == {"high": 3, "medium": 3}


def test_sigstore_offline_verifier_needs_no_network_or_process(tmp_path, monkeypatch):
    pytest.importorskip("sigstore")
    from sigstore.verify import Verifier

    for variable in ("XDG_DATA_HOME", "XDG_CACHE_HOME"):
        monkeypatch.setenv(variable, str(tmp_path / variable.lower()))
    with modes.enforce(modes.Mode.OFFLINE):
        Verifier.production(offline=True)
