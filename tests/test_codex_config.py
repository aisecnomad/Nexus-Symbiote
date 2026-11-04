"""Collect project-local Codex declarations without reading user settings or launching servers."""

from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import IDEAgentComponent, MCPClientComponent, MCPServerComponent
from nexus_symbiote.scanners.ide_agents import IDEAgentScanner
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.validators.risk import RiskScorer


def write_config(root: Path, value: str) -> Path:
    folder = root / ".codex"
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "config.toml"
    path.write_text(value)
    return path


def test_full_access_project_and_mcp_launchers_are_visible_in_cli_bom(tmp_path: Path) -> None:
    root = tmp_path / "project"
    write_config(
        root,
        """sandbox_mode = "danger-full-access"
approval_policy = "never"
[mcp_servers.local]
command = "npx"
args = ["--yes", "example@latest"]
env = { API_TOKEN = "CANARY_TOKEN" }
[mcp_servers.remote]
url = "http://example.test/HIDDEN_PATH?key=HIDDEN_QUERY"
http_headers = { Authorization = "CANARY_HEADER" }
[mcp_servers.remote.tools.example]
approval_mode = "approve"
""",
    )
    path = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(path)])
    assert run.exit_code == 0, run.output
    bom = AIBOM.load(path)
    agent = next(c for c in bom.components if isinstance(c, IDEAgentComponent))
    assert agent.permission_mode == "danger-full-access"
    assert agent.properties["approval_policy"] == "never"
    assert agent.properties["effective_authorization_verified"] is False
    assert agent.properties["mcp_config_paths"] == [".codex/config.toml"]
    servers = {c.name: c for c in bom.components if isinstance(c, MCPServerComponent)}
    assert servers["local"].version_pinned is False
    assert servers["remote"].endpoint_url == "http://example.test"
    assert servers["remote"].tool_count == 0
    client = next(c for c in bom.components if isinstance(c, MCPClientComponent))
    assert client.host_application == "codex"
    assert set(client.server_refs) == {s.bom_ref for s in servers.values()}
    categories = {f.category for f in RiskScorer().score(bom).findings}
    assert {"permission_scope", "version_pinning", "transport_security"} <= categories
    assert not any(
        s in path.read_text()
        for s in ("CANARY_TOKEN", "CANARY_HEADER", "HIDDEN_PATH", "HIDDEN_QUERY")
    )


def test_read_only_project_cannot_escalate_merely_by_disabling_prompts(tmp_path: Path) -> None:
    write_config(tmp_path, 'sandbox_mode = "read-only"\napproval_policy = "never"\n')
    result = IDEAgentScanner().scan(tmp_path)
    agent = next(c for c in result.components if isinstance(c, IDEAgentComponent))
    assert not agent.risks
    assert not result.scan_failures
    assert not MCPScanner().scan(tmp_path).components


def test_granular_approval_is_a_declaration(tmp_path: Path) -> None:
    write_config(
        tmp_path,
        """[approval_policy.granular]
sandbox_approval = false
rules = true
mcp_elicitations = false
""",
    )
    result = IDEAgentScanner().scan(tmp_path)
    agent = next(c for c in result.components if isinstance(c, IDEAgentComponent))
    assert agent.properties["approval_policy"]["granular"]["rules"] is True
    assert not result.scan_failures


@pytest.mark.parametrize(
    "body",
    [
        'sandbox_mode = "CANARY_SECRET"',
        "approval_policy = { granular = { CANARY_SECRET = true } }",
    ],
)
def test_unknown_permission_values_are_incomplete_and_redacted(tmp_path: Path, body: str) -> None:
    write_config(tmp_path, body)
    result = IDEAgentScanner().scan(tmp_path)
    assert result.scan_failures
    assert "CANARY_SECRET" not in repr(result)


@pytest.mark.parametrize("scanner", [MCPScanner, IDEAgentScanner])
def test_malformed_or_linked_toml_does_not_yield_a_clean_collection(
    tmp_path: Path, scanner: type[MCPScanner] | type[IDEAgentScanner]
) -> None:
    root = tmp_path / "project"
    path = write_config(root, 'CANARY_SECRET = "unterminated')
    malformed = scanner().scan(root)
    assert malformed.scan_failures
    assert "CANARY_SECRET" not in repr(malformed)
    path.unlink()
    outside = write_config(tmp_path / "user", '[mcp_servers.CANARY_SECRET]\ncommand = "sh"')
    path.symlink_to(outside)
    linked = scanner().scan(root)
    assert linked.scan_failures or linked.surfaces_excluded
    assert not linked.components
    assert "CANARY_SECRET" not in repr(linked)


@pytest.mark.parametrize(
    "body",
    [
        'mcp_servers = ["CANARY_SECRET"]',
        '[mcp_servers.CANARY_SECRET]\ncommand = "npx"\nurl = "http://example.test"',
        '[mcp_servers.CANARY_SECRET]\ncommand = "npx"\nenabled = "no"',
    ],
)
def test_malformed_server_declarations_are_incomplete(tmp_path: Path, body: str) -> None:
    write_config(tmp_path, body)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures
    assert "CANARY_SECRET" not in repr(result)


def test_legacy_json_cannot_supply_toml_only_settings(tmp_path: Path) -> None:
    path = write_config(tmp_path, 'model = "example"')
    path.with_suffix(".json").write_text(
        '{"agent": {"permissionMode": "manual"}, "sandbox_mode": "danger-full-access"}'
    )
    result = IDEAgentScanner().scan(tmp_path)
    agent = next(c for c in result.components if isinstance(c, IDEAgentComponent))
    assert agent.permission_mode == "manual"
    assert "sandbox_mode" not in agent.properties
    assert not agent.risks
