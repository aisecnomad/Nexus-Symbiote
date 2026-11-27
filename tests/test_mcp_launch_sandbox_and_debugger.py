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
    ("short_name", "long_name", "scope", "expected_context"),
    [
        ("-R", "--allow-read", "./data", {}),
        ("-W", "--allow-write", "./reports", {}),
        ("-N", "--allow-net", "api.example.test", {}),
        ("-E", "--allow-env", "PORT", {}),
        ("-S", "--allow-sys", "hostname", {"deno_scoped_host_permissions": 1}),
    ],
)
def test_scoped_deno_permission_aliases_agree(
    short_name: str, long_name: str, scope: str, expected_context: dict[str, int]
) -> None:
    for name in (short_name, long_name):
        launch = analyze("deno", ["run", f"{name}={scope}", "./catalog.ts"])
        assert launch.unknown is None
        assert launch.context == expected_context


@pytest.mark.parametrize("option", ["-A=example", "-q=example", "-Z=example", "-Rdata", "-NS=host"])
def test_other_deno_short_forms_still_require_a_known_option(option: str) -> None:
    launch = analyze("deno", ["run", option, "./catalog.ts"])
    assert launch.unknown == "unrecognised deno run option"


@pytest.mark.parametrize(
    ("args", "enabled"),
    [
        (["--inspect", "./server.js"], True),
        (["--inspect-brk=127.0.0.1:9229", "./server.js"], True),
        (["--inspect-wait", "./server.js"], True),
        (["--inspect-port", "9229", "./server.js"], False),
        (["--inspect_brk=127.0.0.1:9229", "./server.js"], True),
        (["--inspect_port", "9229", "./server.js"], False),
        (["--debug_port=5858", "./server.js"], False),
        (["--debug-port=5858", "./server.js"], False),
        (["--inspect-port", "9230", "--inspect", "./server.js"], True),
        (["./server.js", "--inspect"], False),
    ],
)
def test_node_debugger_activation(args: list[str], enabled: bool) -> None:
    launch = analyze("node", args)
    assert launch.unknown is None
    assert bool(launch.context.get("debugger_enabled")) == enabled


@pytest.mark.parametrize("option", ["--inspect", "--inspect-port=9230"])
def test_direct_ts_node_refuses_node_inspector_args(option: str) -> None:
    launch = analyze("ts-node", [option, "./server.ts"])
    assert launch.unknown == "direct ts-node arguments do not accept Node inspector flags"
    assert "debugger_enabled" not in launch.context


@pytest.mark.parametrize("system_permission", ["--allow-sys=hostname", "-S=hostname"])
def test_mcp_scanner_emits_high_and_medium_launch_context_findings(
    tmp_path: Path, system_permission: str
) -> None:
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
            "deno-host-unscoped": {
                "command": "deno",
                "args": ["run", "--allow-sys", "./server.js"],
            },
            "deno-host-scoped": {
                "command": "deno",
                "args": ["run", system_permission, "./server.js"],
            },
            "node-port": {
                "command": "node",
                "args": ["--inspect-port=9229", "./server.js"],
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

    assert any(
        r.category == "launch_context" and "unscoped Deno host permissions" in r.detail
        for r in by_name["deno-host-unscoped"].risks
    )
    scoped_host_risks = [
        r for r in by_name["deno-host-scoped"].risks if r.category == "launch_context"
    ]
    assert any("for specified targets" in r.detail for r in scoped_host_risks)
    assert not any("unscoped" in r.detail for r in scoped_host_risks)
    assert not any(r.category == "launch_context" for r in by_name["node-port"].risks)
    debug_risks = [r for r in by_name["node-debug"].risks if r.category == "launch_context"]
    assert any(
        r.severity is RiskSeverity.MEDIUM and "enabled runtime debugger" in r.detail
        for r in debug_risks
    )


@pytest.mark.parametrize(
    ("command", "args", "expected"),
    [
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=0", "node", "./server.js"], True),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=0", "tsx", "./server.ts"], True),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=0", "npx", "-y", "@acme/mcp@1.2.3"], True),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=0", "bunx", "@acme/mcp@1.2.3"], True),
        ("env", ["-i", "NODE_TLS_REJECT_UNAUTHORIZED=0", "node", "./server.js"], True),
        ("sh", ["-c", "NODE_TLS_REJECT_UNAUTHORIZED=0 node ./server.js"], True),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=1", "node", "./server.js"], False),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED= 0", "node", "./server.js"], False),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=false", "node", "./server.js"], False),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=00", "node", "./server.js"], False),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=0", "python", "./server.py"], False),
        ("env", ["NODE_TLS_REJECT_UNAUTHORIZED=0", "deno", "run", "./server.ts"], False),
    ],
)
def test_node_tls_reject_unauthorized_wrapper_detection(
    command: str, args: list[str], expected: bool
) -> None:
    launch = analyze(command, args)
    assert bool(launch.context.get("tls_verification_disabled")) == expected


def test_mcp_scanner_reports_effective_node_tls_bypass_and_honors_overrides(
    tmp_path: Path,
) -> None:
    config = {
        "mcpServers": {
            "node-tls-env": {
                "command": "node",
                "args": ["./server.js"],
                "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
            },
            "npx-tls-env": {
                "command": "npx",
                "args": ["-y", "@acme/mcp@1.2.3"],
                "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
            },
            "node-tls-wrapper": {
                "command": "env",
                "args": ["NODE_TLS_REJECT_UNAUTHORIZED=0", "node", "./server.js"],
            },
            "node-tls-re-enabled": {
                "command": "env",
                "args": ["NODE_TLS_REJECT_UNAUTHORIZED=1", "node", "./server.js"],
                "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
            },
            "node-tls-unset": {
                "command": "env",
                "args": ["-u", "NODE_TLS_REJECT_UNAUTHORIZED", "node", "./server.js"],
                "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
            },
            "node-tls-cleared": {
                "command": "env",
                "args": ["-i", "node", "./server.js"],
                "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
            },
            "node-tls-non-zero-string": {
                "command": "node",
                "args": ["./server.js"],
                "env": {"NODE_TLS_REJECT_UNAUTHORIZED": " 0"},
            },
            "python-ignores-node-tls": {
                "command": "python3",
                "args": ["./server.py"],
                "env": {"NODE_TLS_REJECT_UNAUTHORIZED": "0"},
            },
        }
    }
    (tmp_path / "server.js").write_text("// benign\n", encoding="utf-8")
    (tmp_path / "server.py").write_text("# benign\n", encoding="utf-8")
    (tmp_path / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")

    result = MCPScanner().scan(tmp_path)
    by_name = {c.name: c for c in result.components}

    for name in ("node-tls-env", "npx-tls-env", "node-tls-wrapper"):
        assert any(
            r.category == "launch_context"
            and r.severity is RiskSeverity.HIGH
            and "disabled TLS certificate verification" in r.detail
            for r in by_name[name].risks
        ), name

    for name in (
        "node-tls-re-enabled",
        "node-tls-unset",
        "node-tls-cleared",
        "node-tls-non-zero-string",
        "python-ignores-node-tls",
    ):
        assert not any(
            r.category == "launch_context" and "disabled TLS certificate verification" in r.detail
            for r in by_name[name].risks
        ), name
