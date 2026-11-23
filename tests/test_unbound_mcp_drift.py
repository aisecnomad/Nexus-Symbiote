"""Drift must not pass when MCP launch values were collected without a binding key."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import UNBOUND_VALUES_DETAIL, MCPServerComponent, RiskAssessment
from nexus_symbiote.diff import differ
from nexus_symbiote.diff.differ import _values_unbound
from nexus_symbiote.scanners import mcp
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from tests.support import load_script

runner = load_script("run_action")
KEY = "k" * 32


def _project(root: Path, served: str) -> None:
    root.mkdir()
    (root / "CLAUDE.md").write_text("Use the configured filesystem server.\n")
    (root / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "fs": {
                        "command": "npx",
                        "args": [
                            "-y",
                            "@modelcontextprotocol/server-filesystem@2025.1.14",
                            served,
                        ],
                    }
                }
            }
        )
    )


def _scan(project: Path, output: Path) -> None:
    result = CliRunner().invoke(
        main,
        ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)],
    )
    assert result.exit_code == 0, result.output


def test_unkeyed_filesystem_widening_cannot_pass_the_drift_gate(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    _project(base_root, "/srv/data")
    _project(head_root, "/")
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    _scan(base_root, before)
    _scan(head_root, after)
    result = CliRunner().invoke(main, ["diff", str(before), str(after), "--fail-on-alert"])
    assert result.exit_code == 1, result.output
    assert "unbound" in result.output
    same = CliRunner().invoke(main, ["diff", str(before), str(before), "--fail-on-alert"])
    assert same.exit_code == 1 and "unbound" in same.output


def test_the_same_widening_is_a_critical_alert_when_both_scans_are_keyed(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    _project(base_root, "/srv/data")
    _project(head_root, "/")
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    _scan(base_root, before)
    _scan(head_root, after)
    widened = CliRunner().invoke(
        main, ["diff", str(before), str(after), "--fail-on-alert", "--json-output"]
    )
    assert widened.exit_code == 1, widened.output
    alerts = json.loads(widened.stdout)["security_alerts"]
    assert any(alert["severity"] == "critical" for alert in alerts)
    assert all("unbound" not in alert["alert"] for alert in alerts)
    unchanged = CliRunner().invoke(main, ["diff", str(before), str(before), "--fail-on-alert"])
    assert unchanged.exit_code == 0, unchanged.output
    assert "No changes detected" in unchanged.output


def test_the_collector_and_the_differ_share_the_unbound_values_phrase(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    root = tmp_path / "project"
    _project(root, "/srv/data")

    def collected() -> MCPServerComponent:
        components = mcp.MCPScanner().scan(root).components
        [server] = [c for c in components if isinstance(c, MCPServerComponent)]
        return server

    def completeness(server: MCPServerComponent) -> list[str]:
        return [risk.detail for risk in server.risks if risk.category == "completeness"]

    def finding(detail: str) -> MCPServerComponent:
        risk = RiskAssessment(severity=RiskSeverity.LOW, category="completeness", detail=detail)
        return MCPServerComponent(bom_ref="mcp-server:fs", name="fs", risks=[risk])

    server = collected()
    assert any(UNBOUND_VALUES_DETAIL in detail for detail in completeness(server))
    assert _values_unbound(server)
    phrased = f"MCP server 'fs' {UNBOUND_VALUES_DETAIL}: launch arguments."
    assert _values_unbound(finding(phrased))
    assert not _values_unbound(finding("MCP server 'fs' launch arguments were redacted."))

    renamed = "values recorded without a binding key"
    monkeypatch.setattr(mcp, "UNBOUND_VALUES_DETAIL", renamed)
    monkeypatch.setattr(differ, "UNBOUND_VALUES_DETAIL", renamed)
    assert any(renamed in detail for detail in completeness(collected()))
    assert _values_unbound(collected())
    assert not _values_unbound(finding(phrased))


def test_reviewed_baseline_requires_a_binding_key(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    baseline = tmp_path / "reviewed.json"
    baseline.write_text('{"components": []}')
    with pytest.raises(ValueError, match="source binding key"):
        runner.Config.from_env(
            {
                "GITHUB_WORKSPACE": str(workspace),
                "SYMBIOTE_REVIEWED_BASELINE": str(baseline),
            }
        )
    short = "too-short"
    with pytest.raises(ValueError, match="source-binding-key"):
        runner.Config.from_env(
            {
                "GITHUB_WORKSPACE": str(workspace),
                "SYMBIOTE_SOURCE_BINDING_KEY": short,
            }
        )
    config = runner.Config.from_env(
        {
            "GITHUB_WORKSPACE": str(workspace),
            "SYMBIOTE_REVIEWED_BASELINE": str(baseline),
            "SYMBIOTE_SOURCE_BINDING_KEY": KEY,
        }
    )
    assert config.binding_key == KEY and config.baseline is not None


def test_binding_key_input_reaches_the_cli_and_is_not_printed(tmp_path, monkeypatch, capsys):
    seen: list[str | None] = []

    def invoke(args, **kwargs):
        seen.append(kwargs["env"].get(SOURCE_BINDING_KEY_ENV))
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(runner.subprocess, "run", invoke)
    runner._run(["scan"], private=tmp_path, binding_key=KEY)
    assert seen == [KEY]
    log = capsys.readouterr().err + capsys.readouterr().out
    assert KEY not in log


def _server(root: Path, config: dict) -> MCPServerComponent:
    root.mkdir()
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"s": config}}))
    (server,) = [
        c for c in mcp.MCPScanner().scan(root).components if isinstance(c, MCPServerComponent)
    ]
    return server


def _unbound_kinds(server: MCPServerComponent) -> list[str]:
    detail = next(r.detail for r in server.risks if UNBOUND_VALUES_DETAIL in r.detail)
    return detail.rsplit(": ", 1)[1].rstrip(".").split("; ")


@pytest.mark.parametrize(
    "first,second,unbound",
    [
        # Redacted for its shape: both export "[redacted-command]".
        ({"command": "srv@good"}, {"command": "srv@evil"}, "command"),
        ({"command": "g" * 70}, {"command": "e" * 70}, "command"),
        # Exported case-folded: two files on POSIX share one record.
        ({"command": "mcpserver"}, {"command": "MCPServer"}, "command"),
        ({"url": "https://${HOST_A}/"}, {"url": "https://${HOST_B}/"}, "endpoint"),
    ],
)
def test_a_command_or_endpoint_the_export_redacts_or_folds_is_unbound_without_a_key(
    tmp_path, first, second, unbound
):
    one, two = _server(tmp_path / "one", first), _server(tmp_path / "two", second)
    assert one.properties["static_config_hash"] == two.properties["static_config_hash"]
    assert unbound in _unbound_kinds(two)
    assert _values_unbound(two)


def test_a_command_the_export_shows_verbatim_stays_bound(tmp_path, monkeypatch):
    assert not _values_unbound(_server(tmp_path / "bare", {"command": "mcpserver"}))
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    keyed = _server(tmp_path / "keyed", {"command": "MCPServer"})
    assert keyed.properties["source_values_bound"] is True
    assert not _values_unbound(keyed)
