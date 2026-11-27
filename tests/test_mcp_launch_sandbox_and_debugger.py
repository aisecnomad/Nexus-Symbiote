"""Tests for Deno sandbox, TLS-bypass, and Node/Deno debugger MCP launch auditing."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.mcp_launch import analyze


@pytest.mark.parametrize(
    ("args", "expected_flag"),
    [
        (["run", "-A", "npm:@acme/mcp@1.2.3"], "deno_all_permissions"),
        (["run", "--allow-all", "npm:@acme/mcp@1.2.3"], "deno_all_permissions"),
        (["run", "--allow-run", "npm:@acme/mcp@1.2.3"], "deno_dangerous_permissions"),
        (["run", "--allow-ffi", "npm:@acme/mcp@1.2.3"], "deno_dangerous_permissions"),
        (["run", "--allow-sys", "npm:@acme/mcp@1.2.3"], "deno_dangerous_permissions"),
        (["run", "-S", "npm:@acme/mcp@1.2.3"], "deno_dangerous_permissions"),
        (["run", "--allow-net", "npm:@acme/mcp@1.2.3"], "deno_broad_permissions"),
        (["run", "-W", "npm:@acme/mcp@1.2.3"], "deno_broad_permissions"),
        (
            ["run", "--unsafely-ignore-certificate-errors", "npm:@acme/mcp@1.2.3"],
            "tls_verification_disabled",
        ),
        (
            ["run", "--unsafely-ignore-certificate-errors=api.local", "npm:@acme/mcp@1.2.3"],
            "tls_verification_disabled",
        ),
        (["run", "--inspect=0.0.0.0:9229", "npm:@acme/mcp@1.2.3"], "debugger_enabled"),
        (["run", "--inspect-brk", "npm:@acme/mcp@1.2.3"], "debugger_enabled"),
    ],
)
def test_deno_launch_context_flags(args: list[str], expected_flag: str) -> None:
    launch = analyze("deno", args)
    assert launch.unknown is None
    assert launch.context.get(expected_flag, 0) >= 1


def test_scoped_deno_permissions_are_not_flagged_as_broad() -> None:
    launch = analyze(
        "deno",
        [
            "run",
            "--allow-net=api.example.com",
            "--allow-read=./data",
            "--allow-env=PORT",
            "npm:@acme/mcp@1.2.3",
        ],
    )
    assert launch.unknown is None
    assert "deno_all_permissions" not in launch.context
    assert "deno_dangerous_permissions" not in launch.context
    assert "deno_broad_permissions" not in launch.context
    assert "tls_verification_disabled" not in launch.context
    assert "debugger_enabled" not in launch.context


@pytest.mark.parametrize(
    ("cmd", "args"),
    [
        ("node", ["--inspect", "./server.js"]),
        ("node", ["--inspect-brk=0.0.0.0:9229", "./server.js"]),
        ("node", ["--inspect-wait", "./server.js"]),
        ("node", ["--inspect-port", "9229", "./server.js"]),
        ("node", ["--inspect_brk=0.0.0.0:9229", "./server.js"]),
        ("node", ["--inspect_port", "9229", "./server.js"]),
        ("node", ["--debug_port=5858", "./server.js"]),
        ("node", ["--debug-port=5858", "./server.js"]),
        ("ts-node", ["--inspect", "./server.ts"]),
    ],
)
def test_node_debugger_launch_context_flagged(cmd: str, args: list[str]) -> None:
    launch = analyze(cmd, args)
    assert launch.context.get("debugger_enabled", 0) >= 1


def test_mcp_scanner_emits_high_and_medium_launch_context_findings(tmp_path: Path) -> None:
    config = {
        "mcpServers": {
            "deno-unsafe": {
                "command": "deno",
                "args": [
                    "run",
                    "-A",
                    "--unsafely-ignore-certificate-errors",
                    "npm:@acme/mcp@1.2.3",
                ],
            },
            "deno-scoped": {
                "command": "deno",
                "args": ["run", "--allow-net=api.example.com", "npm:@acme/mcp@1.2.3"],
            },
            "node-debug": {
                "command": "node",
                "args": ["--inspect=0.0.0.0:9229", "./server.js"],
            },
        }
    }
    (tmp_path / "server.js").write_text("// benign server\n", encoding="utf-8")
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")

    result = MCPScanner().scan(tmp_path)
    by_name = {c.name: c for c in result.components}

    unsafe_risks = [r for r in by_name["deno-unsafe"].risks if r.category == "launch_context"]
    assert any(r.severity is RiskSeverity.HIGH for r in unsafe_risks)
    assert any("unrestricted Deno permissions" in r.detail for r in unsafe_risks)
    assert any("disabled TLS certificate verification" in r.detail for r in unsafe_risks)

    scoped_risks = [r for r in by_name["deno-scoped"].risks if r.category == "launch_context"]
    assert not scoped_risks

    debug_risks = [r for r in by_name["node-debug"].risks if r.category == "launch_context"]
    assert any(
        r.severity is RiskSeverity.MEDIUM and "enabled runtime debugger" in r.detail
        for r in debug_risks
    )
