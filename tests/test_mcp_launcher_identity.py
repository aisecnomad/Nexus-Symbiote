"""The static inventory binds each server to its declared launcher package."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners.mcp import MCPScanner


def write_project(project: Path, command: str, args: list[str]) -> None:
    server = {
        "command": command,
        "args": args,
        "env": {"TOKEN": "secret-canary"},
        "tools": [{"name": "read", "description": "Read docs", "inputSchema": {"type": "object"}}],
    }
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))


@pytest.mark.parametrize(
    "command,args,expected",
    [
        ("npx", ["-y", "@scope/docs@1.2.3", "secret-canary"], "npm:@scope/docs"),
        ("bunx", ["pkg@^1.2.3"], "npm:pkg"),
        ("uvx", ["--from", "My_Docs[cli]==1.2.3", "docs"], "pypi:my-docs"),
        ("pipx", ["run", "--spec", "My.Docs==1.2.3", "docs"], "pypi:my-docs"),
        (
            "docker",
            ["run", "--rm", "registry.test:5000/team/docs:1.2.3"],
            "oci:registry.test:5000/team/docs",
        ),
        ("docker", ["run", "docs@sha256:" + "ab" * 32], "oci:docs"),
        ("npx", ["docs@npm:other@1.2.3"], None),
        ("npx", ["docs@https://example.test/secret-canary"], None),
        ("uvx", ["docs @ https://example.test/secret-canary"], None),
        ("npx", ["--password", "secret-canary"], None),
        ("npx", ["secret-canary@1.2.3"], None),
    ],
)
def test_safe_launcher_package_projection(tmp_path, command, args, expected):
    write_project(tmp_path, command, args)
    result = MCPScanner().scan(tmp_path)
    assert not result.scan_failures
    server = next(c for c in result.components if isinstance(c, MCPServerComponent))
    assert server.launcher_package == expected
    assert "secret-canary" not in server.model_dump_json()
    assert server.args == ["***"] * len(args)


def test_cli_rejects_substituted_missing_and_legacy_package_identity(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    runner = CliRunner()

    def scan(filename, target):
        path = tmp_path / filename
        write_project(project, "npx", [target])
        result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(path)])
        assert result.exit_code == 0, result.output
        return path

    def validate(bom, expected):
        result = runner.invoke(
            main, ["validate", str(bom), "--project", str(project), "--no-project-policy"]
        )
        assert result.exit_code == expected, result.output

    def diff(old, new):
        result = runner.invoke(
            main, ["diff", str(old), str(new), "--json-output", "--fail-on-alert"]
        )
        assert result.exit_code == 1, result.output
        alerts = json.loads(result.output)["security_alerts"]
        assert any(a["severity"] == "critical" and "launcher package" in a["alert"] for a in alerts)

    original = scan("reviewed.json", "reviewed-docs@1.2.3")
    validate(original, 0)

    legacy = tmp_path / "legacy.json"
    document = json.loads(original.read_text())
    server = next(c for c in document["components"] if "launcher_package" in c)
    del server["launcher_package"]
    legacy.write_text(json.dumps(document))
    validate(legacy, 1)
    diff(legacy, original)

    candidate = scan("candidate.json", "replacement-docs@1.2.3")
    validate(candidate, 0)
    validate(original, 1)
    diff(original, candidate)

    opaque = scan("opaque.json", "reviewed-docs@npm:replacement-docs@1.2.3")
    validate(original, 1)
    diff(original, opaque)


def scan_server(project: Path, server: dict) -> MCPServerComponent:
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))
    result = MCPScanner().scan(project)
    assert not result.scan_failures
    return next(c for c in result.components if isinstance(c, MCPServerComponent))


def test_short_environment_flags_do_not_discard_launcher_identity(tmp_path):
    server = scan_server(
        tmp_path,
        {"command": "npx", "args": ["-y", "mcp-1@1.2.3"], "env": {"MODE": "m", "DEBUG": "1"}},
    )
    assert server.launcher_package == "npm:mcp-1"


def test_credential_inside_package_name_withholds_launcher_identity(tmp_path):
    server = scan_server(
        tmp_path,
        {"command": "npx", "args": ["-y", "docs-k8x2v9q4zt"], "env": {"TOKEN": "k8x2v9q4zt"}},
    )
    assert server.launcher_package is None
    assert "k8x2v9q4zt" not in server.model_dump_json()


@pytest.mark.parametrize(
    "command,args",
    [
        ("npx", ["-y", "docs@."]),
        ("npx", ["-y", "docs@.."]),
        ("npx", ["-y", "docs.tgz"]),
        ("npx", ["-y", "docs@release.TAR.GZ"]),
        ("uvx", ["--from", "docs==1.2.3", "--index-url", "https://mirror.test/simple", "docs"]),
        ("uvx", ["--from", "docs==1.2.3", "--find-links=/opt/wheels", "docs"]),
        ("pipx", ["run", "--spec", "docs==1.2.3", "--index-url", "https://mirror.test", "docs"]),
    ],
)
def test_local_or_alternate_index_launchers_have_no_registry_identity(tmp_path, command, args):
    assert scan_server(tmp_path, {"command": command, "args": args}).launcher_package is None


@pytest.mark.parametrize(
    "before,after",
    [
        (
            {"command": "npx", "args": ["-y", "docs@1.2.3"], "env": {"BASE": "https://a.test"}},
            {"command": "npx", "args": ["-y", "docs@1.2.3"], "env": {"BASE": "https://b.test"}},
        ),
        ({"url": "https://mcp.test/safe/sse"}, {"url": "https://mcp.test/other/sse"}),
    ],
)
def test_drift_gate_reports_redacted_source_changes_as_critical(
    tmp_path, monkeypatch, before, after
):
    monkeypatch.setenv(
        "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY",
        "79209c4244e765a38d59849bdfffa982a7eaeaacd42af7151072fc7f6c2eaf0a",
    )
    project = tmp_path / "project"
    project.mkdir()
    runner = CliRunner()
    snapshots = []
    for index, server in enumerate([before, after]):
        (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"docs": server}}))
        path = tmp_path / f"snapshot-{index}.json"
        run = runner.invoke(
            main, ["scan", str(project), "--report-only", "-f", "json", "-o", str(path)]
        )
        assert run.exit_code == 0, run.output
        snapshots.append(str(path))
    run = runner.invoke(main, ["diff", *snapshots, "--json-output", "--fail-on-alert"])
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert any(
        alert["severity"] == "critical" and "static source binding changed" in alert["alert"]
        for alert in alerts
    ), alerts
