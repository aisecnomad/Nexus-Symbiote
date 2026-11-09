"""Declared IDE permissions follow provider syntax without claiming effective access."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import IDEAgentComponent
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.validators.risk import RiskScorer


def write_settings(root: Path, permissions: dict, *, local: bool = False) -> None:
    directory = root / ".claude"
    directory.mkdir(exist_ok=True)
    filename = "settings.local.json" if local else "settings.json"
    (directory / filename).write_text(json.dumps({"permissions": permissions}))


def claude_agent(result) -> IDEAgentComponent:
    return next(
        c
        for c in result.components
        if isinstance(c, IDEAgentComponent) and c.ide_type == "claude-code"
    )


@pytest.mark.parametrize(
    "mode", ["default", "manual", "acceptEdits", "plan", "auto", "dontAsk", "bypassPermissions"]
)
def test_actual_default_mode_key_is_recorded_as_a_declaration(tmp_path: Path, mode: str) -> None:
    write_settings(tmp_path, {"defaultMode": mode})
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    agent = claude_agent(result)
    assert agent.permission_mode == mode
    assert agent.properties["permission_evidence"] == "declaration-only"
    assert agent.properties["effective_authorization_verified"] is False
    assert any("may be ignored" in p for p in agent.properties["permission_policy_limitations"])


def test_nonexistent_mode_key_is_not_interpreted_as_provider_permission(tmp_path: Path) -> None:
    write_settings(tmp_path, {"mode": "bypassPermissions"})
    assert claude_agent(IDEAgentScanner().scan(tmp_path)).permission_mode is None


@pytest.mark.parametrize("rule", ["Bash", "Edit", "Write", "Bash(*)", "Edit(*)", "Write(*)"])
def test_unscoped_tool_grants_are_reported(tmp_path: Path, rule: str) -> None:
    write_settings(tmp_path, {"allow": [rule]})
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    assert any(r.category == "permission_scope" for r in claude_agent(result).risks)


def test_scoped_command_is_not_reported_as_unrestricted_shell_access(tmp_path: Path) -> None:
    write_settings(tmp_path, {"allow": ["Bash(git diff *)"]})
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not any(r.category == "permission_scope" for r in claude_agent(result).risks)


def test_local_mode_declaration_does_not_hide_project_tool_allowance(tmp_path: Path) -> None:
    write_settings(tmp_path, {"allow": ["Bash"], "defaultMode": "plan"})
    write_settings(tmp_path, {"defaultMode": "acceptEdits"}, local=True)
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    agent = claude_agent(result)
    assert agent.permission_mode == "acceptEdits"
    assert any(r.category == "permission_scope" for r in agent.risks)


def test_deny_and_ask_declarations_are_not_claimed_to_be_effective_authorization(
    tmp_path: Path,
) -> None:
    write_settings(tmp_path, {"allow": ["Bash"], "deny": ["Bash"], "ask": ["Write"]})
    result = IDEAgentScanner().scan(tmp_path)
    agent = claude_agent(result)
    assert agent.properties["effective_authorization_verified"] is False
    assert any("Deny and ask" in p for p in agent.properties["permission_policy_limitations"])
    assert "declares unscoped" in agent.risks[0].detail


@pytest.mark.parametrize("field", ["allow", "ask", "deny", "defaultMode"])
def test_malformed_permission_fields_fail_collection_without_input_values(
    tmp_path: Path, field: str
) -> None:
    write_settings(tmp_path, {field: {"secret": "CANARY_PERMISSION_SECRET"}})
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures
    assert "CANARY_PERMISSION_SECRET" not in repr(result)


def test_cli_does_not_report_unrestricted_shell_declaration_as_clean(tmp_path: Path) -> None:
    write_settings(tmp_path, {"allow": ["Bash"], "defaultMode": "acceptEdits"})
    output = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(output)]
    )
    assert result.exit_code == 1
    bom = AIBOM.load(output)
    assert bom.metadata.completeness is not None
    assert any("partially inventoried" in s for s in bom.metadata.completeness.surfaces_excluded)
    report = RiskScorer().score(bom)
    assert report.risk_level != "clean"
    assert any(f.category == "permission_scope" for f in report.findings)
    assert claude_agent(bom).permission_mode == "acceptEdits"
