"""Codex sandbox authority from permission profiles, workspace settings and nested layers."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.core.models import IDEAgentComponent, MCPClientComponent, MCPServerComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner

FULL_ACCESS = "Codex declares unrestricted filesystem access."
OUTSIDE = "Codex declares writable paths outside the workspace."
NETWORK = "Codex declares sandbox network access."
UNPROMPTED = "Codex declares workspace writes with no interactive escalation prompts."


def write_layer(root: Path, value: str, directory: str = ".") -> None:
    folder = root / directory / ".codex"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "config.toml").write_text(value)


def codex(result: ScanResult) -> IDEAgentComponent:
    return next(
        c for c in result.components if isinstance(c, IDEAgentComponent) and c.name == "codex"
    )


def findings(agent: IDEAgentComponent) -> set[tuple[RiskSeverity, str]]:
    assert all(risk.category == "permission_scope" for risk in agent.risks)
    return {(risk.severity, risk.detail) for risk in agent.risks}


def test_default_permissions_take_precedence_over_legacy_sandbox_mode(tmp_path: Path) -> None:
    write_layer(
        tmp_path,
        'sandbox_mode = "read-only"\napproval_policy = "never"\n'
        'default_permissions = ":danger-full-access"\n',
    )
    result = IDEAgentScanner().scan(tmp_path)
    agent = codex(result)
    assert agent.permission_mode == "danger-full-access"
    assert agent.properties["default_permissions"] == ":danger-full-access"
    assert agent.properties["sandbox_mode"] == "read-only"
    assert findings(agent) == {(RiskSeverity.HIGH, FULL_ACCESS)}
    assert not result.scan_failures and not result.surfaces_excluded


@pytest.mark.parametrize(
    ("profile", "mode"), [(":read-only", "read-only"), (":workspace", "workspace-write")]
)
def test_built_in_profiles_map_to_sandbox_modes(tmp_path: Path, profile: str, mode: str) -> None:
    write_layer(
        tmp_path, f'sandbox_mode = "danger-full-access"\ndefault_permissions = "{profile}"\n'
    )
    agent = codex(IDEAgentScanner().scan(tmp_path))
    assert agent.permission_mode == mode
    # Codex versions without permission profiles still apply the legacy key.
    assert findings(agent) == {(RiskSeverity.HIGH, FULL_ACCESS)}


def test_each_directory_scope_selects_its_own_syntax(tmp_path: Path) -> None:
    write_layer(tmp_path, 'default_permissions = ":workspace"\n')
    write_layer(tmp_path, 'sandbox_mode = "read-only"\napproval_policy = "never"\n', "service")
    agent = codex(IDEAgentScanner().scan(tmp_path))
    assert agent.permission_mode == "workspace-write"
    assert agent.properties["nested_config_layers"] == {
        "service/.codex/config.toml": {"sandbox_mode": "read-only", "approval_policy": "never"}
    }
    # In service/ the later layer selects read-only, so disabling prompts there is no risk.
    assert not agent.risks
    write_layer(tmp_path, 'approval_policy = "never"\n', "service")
    agent = codex(IDEAgentScanner().scan(tmp_path))
    assert findings(agent) == {(RiskSeverity.MEDIUM, UNPROMPTED)}


@pytest.mark.parametrize(
    "body",
    [
        'default_permissions = "ci"\n[permissions.ci]\nextends = ":danger-full-access"\n',
        'default_permissions = "ci"\n[permissions.ci]\nextends = "base"\n'
        '[permissions.base]\nextends = ":danger-full-access"\n',
        # A declared profile is selectable at run time even when this layer selects another.
        'default_permissions = ":read-only"\n[permissions.ci]\nextends = ":danger-full-access"\n',
    ],
)
def test_profiles_extending_full_access_are_high_risk(tmp_path: Path, body: str) -> None:
    write_layer(tmp_path, body)
    result = IDEAgentScanner().scan(tmp_path)
    assert (RiskSeverity.HIGH, FULL_ACCESS) in findings(codex(result))
    assert not result.scan_failures


def test_custom_profile_records_interpreted_grants(tmp_path: Path) -> None:
    write_layer(
        tmp_path,
        """default_permissions = "ci"
[permissions.ci]
description = "CANARY_DESCRIPTION"
extends = ":workspace"
[permissions.ci.filesystem]
":root" = "read"
"/var/cache/build" = "write"
"~/.ssh" = "none"
":workspace_roots" = { "src" = "write", "." = "read" }
[permissions.ci.network]
enabled = true
""",
    )
    result = IDEAgentScanner().scan(tmp_path)
    agent = codex(result)
    assert agent.permission_mode == "profile:ci"
    assert agent.properties["permission_profiles"] == {
        "ci": {
            "extends": ":workspace",
            "filesystem": {
                "/var/cache/build": "write",
                ":root": "read",
                ":workspace_roots": {".": "read", "src": "write"},
                "~/.ssh": "deny",
            },
            "network_enabled": True,
        }
    }
    assert findings(agent) == {(RiskSeverity.HIGH, OUTSIDE), (RiskSeverity.MEDIUM, NETWORK)}
    assert "CANARY_DESCRIPTION" not in repr(result)
    assert not result.scan_failures and not result.surfaces_excluded


def test_workspace_scoped_profile_writes_are_not_outside_the_workspace(tmp_path: Path) -> None:
    write_layer(
        tmp_path,
        'default_permissions = "dev"\n[permissions.dev.filesystem]\n'
        '":workspace_roots" = "write"\n":tmpdir" = "write"\n":minimal" = "read"\n',
    )
    agent = codex(IDEAgentScanner().scan(tmp_path))
    assert agent.permission_mode == "profile:dev"
    assert not agent.risks


@pytest.mark.parametrize("root", ["/", "~", "~/.config", "../..", "/srv/../tmp", "C:\\\\"])
def test_writable_roots_outside_the_workspace_are_high_risk(tmp_path: Path, root: str) -> None:
    write_layer(
        tmp_path,
        f'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\nwritable_roots = ["{root}"]\n',
    )
    agent = codex(IDEAgentScanner().scan(tmp_path))
    assert findings(agent) == {(RiskSeverity.HIGH, OUTSIDE)}


def test_workspace_write_settings_are_recorded(tmp_path: Path) -> None:
    write_layer(
        tmp_path,
        'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\n'
        'writable_roots = ["../build"]\nnetwork_access = true\nexclude_slash_tmp = true\n',
    )
    agent = codex(IDEAgentScanner().scan(tmp_path))
    assert agent.permission_mode == "workspace-write"
    assert agent.properties["sandbox_workspace_write"] == {
        "writable_roots": ["../build"],
        "network_access": True,
        "exclude_slash_tmp": True,
    }
    # A relative root resolves against the .codex folder: ../build stays in the project.
    assert findings(agent) == {(RiskSeverity.MEDIUM, NETWORK)}


def test_workspace_write_without_prompts_is_medium_risk(tmp_path: Path) -> None:
    write_layer(tmp_path, 'sandbox_mode = "workspace-write"\napproval_policy = "never"\n')
    assert findings(codex(IDEAgentScanner().scan(tmp_path))) == {(RiskSeverity.MEDIUM, UNPROMPTED)}


def test_granular_policy_rejecting_every_prompt_is_unprompted(tmp_path: Path) -> None:
    body = (
        'sandbox_mode = "workspace-write"\n[approval_policy.granular]\n'
        "sandbox_approval = false\nrules = false\nmcp_elicitations = false\n"
    )
    write_layer(tmp_path, body)
    assert findings(codex(IDEAgentScanner().scan(tmp_path))) == {(RiskSeverity.MEDIUM, UNPROMPTED)}
    write_layer(tmp_path, body.replace("rules = false", "rules = true"))
    assert not codex(IDEAgentScanner().scan(tmp_path)).risks


def test_approvals_reviewer_is_recorded(tmp_path: Path) -> None:
    write_layer(tmp_path, 'approvals_reviewer = "guardian_subagent"\n')
    result = IDEAgentScanner().scan(tmp_path)
    assert codex(result).properties["approvals_reviewer"] == "auto_review"
    assert not result.scan_failures


@pytest.mark.parametrize(
    "body",
    [
        'default_permissions = ":CANARY_SECRET"',
        'default_permissions = "CANARY_SECRET"',
        "default_permissions = 1",
        'default_permissions = "ci"\n[permissions.ci]\nextends = "CANARY_SECRET"',
        'default_permissions = "a"\n[permissions.a]\nextends = "b"\n[permissions.b]\nextends = "a"',
        "[permissions.ci]\nCANARY_SECRET = true",
        '[permissions.ci.filesystem]\n"/x" = "CANARY_SECRET"',
        '[permissions."CANARY SECRET"]\nextends = ":read-only"',
        "[sandbox_workspace_write]\nCANARY_SECRET = true",
        "[sandbox_workspace_write]\nwritable_roots = [1]",
        '[sandbox_workspace_write]\nnetwork_access = "CANARY_SECRET"',
        'approvals_reviewer = "CANARY_SECRET"',
    ],
)
def test_invalid_permission_declarations_fail_closed(tmp_path: Path, body: str) -> None:
    write_layer(tmp_path, body)
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures
    assert "CANARY_SECRET" not in repr(result)
    assert "CANARY SECRET" not in repr(result)


@pytest.mark.parametrize(
    "body",
    [
        '[permissions.ci.network]\nenabled = false\nproxy_url = "http://CANARY_SECRET@proxy"',
        '[permissions.ci.filesystem]\n":CANARY_SECRET" = "write"',
        '[[hooks.PermissionRequest]]\nmatcher = "CANARY_SECRET"',
        '[auto_review]\npolicy = "CANARY_SECRET"',
    ],
)
def test_uninterpreted_permission_settings_leave_coverage_unknown(
    tmp_path: Path, body: str
) -> None:
    write_layer(tmp_path, body)
    result = IDEAgentScanner().scan(tmp_path)
    assert result.surfaces_excluded
    assert "CANARY_SECRET" not in repr(result)


def test_nested_layers_are_collected(tmp_path: Path) -> None:
    write_layer(tmp_path, 'sandbox_mode = "read-only"\n')
    write_layer(
        tmp_path,
        """sandbox_mode = "danger-full-access"
approval_policy = "never"
[mcp_servers.helper]
command = "npx"
args = ["helper@latest"]
""",
        "packages/app",
    )
    result = IDEAgentScanner().scan(tmp_path)
    agent = codex(result)
    assert agent.permission_mode == "read-only"
    assert "packages/app/.codex/config.toml" in agent.config_files
    assert agent.properties["nested_config_layers"] == {
        "packages/app/.codex/config.toml": {
            "sandbox_mode": "danger-full-access",
            "approval_policy": "never",
        }
    }
    assert agent.properties["mcp_config_paths"] == ["packages/app/.codex/config.toml"]
    assert findings(agent) == {(RiskSeverity.HIGH, FULL_ACCESS)}
    mcp = MCPScanner().scan(tmp_path)
    server = next(c for c in mcp.components if isinstance(c, MCPServerComponent))
    assert server.name == "helper" and server.version_pinned is False
    client = next(c for c in mcp.components if isinstance(c, MCPClientComponent))
    assert client.host_application == "codex" and client.server_refs == [server.bom_ref]


def test_nested_layer_alone_identifies_codex(tmp_path: Path) -> None:
    write_layer(tmp_path, 'default_permissions = ":danger-full-access"\n', "tools")
    agent = codex(IDEAgentScanner().scan(tmp_path))
    assert agent.permission_mode is None
    assert findings(agent) == {(RiskSeverity.HIGH, FULL_ACCESS)}


def test_nested_layer_can_select_a_profile_declared_by_the_root(tmp_path: Path) -> None:
    write_layer(
        tmp_path, '[permissions.wide]\nextends = ":workspace"\nnetwork = { enabled = true }\n'
    )
    write_layer(tmp_path, 'default_permissions = "wide"\n', "app")
    result = IDEAgentScanner().scan(tmp_path)
    assert not result.scan_failures
    assert findings(codex(result)) == {(RiskSeverity.MEDIUM, NETWORK)}


def test_excess_nested_layers_are_a_collection_failure(tmp_path: Path) -> None:
    for index in range(17):
        write_layer(tmp_path, 'sandbox_mode = "read-only"\n', f"p{index:02d}")
    for scanner in (IDEAgentScanner(), MCPScanner()):
        assert any("layer" in failure for failure in scanner.scan(tmp_path).scan_failures)


@pytest.mark.parametrize(
    ("before", "after"),
    [
        (
            'sandbox_mode = "read-only"\n',
            'sandbox_mode = "read-only"\ndefault_permissions = ":danger-full-access"\n',
        ),
        (
            'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\n'
            'writable_roots = ["/tmp/x"]\nnetwork_access = false\n',
            'sandbox_mode = "workspace-write"\n[sandbox_workspace_write]\n'
            'writable_roots = ["/"]\nnetwork_access = true\n',
        ),
        (
            '[permissions.ci.filesystem]\n"/opt/a" = "write"\n',
            '[permissions.ci.filesystem]\n"/opt/b" = "write"\n',
        ),
    ],
)
def test_permission_changes_fail_the_drift_gate_without_the_binding_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, before: str, after: str
) -> None:
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    root = tmp_path / "project"
    (root / ".codex").mkdir(parents=True)
    (root / "AGENTS.md").write_text("Be careful.")
    outputs = []
    for index, body in enumerate((before, after)):
        (root / ".codex/config.toml").write_text(body)
        output = tmp_path / f"bom{index}.json"
        CliRunner().invoke(
            main, ["scan", str(root), "--no-project-policy", "--report-only", "-o", str(output)]
        )
        outputs.append(str(output))
    run = CliRunner().invoke(main, ["diff", *outputs, "--json-output", "--fail-on-alert"])
    assert run.exit_code == 1, run.output
    assert json.loads(run.stdout)["total_changes"] > 0


def test_cli_reports_profile_full_access_as_unsafe(tmp_path: Path) -> None:
    root = tmp_path / "project"
    write_layer(
        root,
        'sandbox_mode = "read-only"\napproval_policy = "never"\n'
        'default_permissions = ":danger-full-access"\n',
    )
    (root / "AGENTS.md").write_text("Be careful.")
    output = tmp_path / "bom.json"
    scan = CliRunner().invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(output)])
    assert scan.exit_code == 0, scan.output
    agent = next(c for c in AIBOM.load(output).components if isinstance(c, IDEAgentComponent))
    assert agent.permission_mode == "danger-full-access"
    risk = CliRunner().invoke(
        main,
        ["risk", str(output), "--project", str(root), "--no-project-policy", "--json-output"],
    )
    report = json.loads(risk.stdout)
    assert report["assessment_basis"] == "project-reconciled"
    assert report["risk_level"] != "clean"
    assert any(f["category"] == "permission_scope" for f in report["findings"])
