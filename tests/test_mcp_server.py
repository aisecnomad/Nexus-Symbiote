"""Tests for the offline read-only ``mcp-server`` JSON-RPC 2.0 server and CLI."""

from __future__ import annotations

import io
import json
import math
import subprocess
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.advisories import AdvisoryReport
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    AutonomyLevel,
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
)
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    AgentComponent,
    CapabilityDeclaration,
    MCPServerComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.mcp_server import (
    DEFAULT_MAX_ITEMS,
    MAX_ALLOWED_REQUESTS,
    MAX_FRAME_BYTES,
    MAX_FRAME_DEPTH,
    MAX_HEADER_BYTES,
    OfflineMCPServer,
    _collect_advisories,
    _normalize_advisory_row,
    run_mcp_server_streams,
)
from nexus_symbiote.modes import Mode, enforce
from nexus_symbiote.vex_decisions import load_advisory_report

_SYNTHETIC_FIXTURE = "sk-ant-" + "api03-fixture1234567890abcdef"
_RAW_ANSI = "\x1b[31mbad\x1b[0m"
_RAW_BIDI = "\u202ehidden"


def _build_rich_bom() -> AIBOM:
    agent = AgentComponent(
        bom_ref="agent:assistant",
        name=f"helper-{_RAW_ANSI}",
        autonomy_level=AutonomyLevel.L2_AGENT,
        assurance_level=AssuranceLevel.OBSERVED,
        tool_refs=["tool:cred-reader", "tool:net-runner"],
        risks=[
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="oversight_gap",
                detail=f"Agent uses key {_SYNTHETIC_FIXTURE}",
                recommendation=f"Rotate {_SYNTHETIC_FIXTURE} now",
            )
        ],
    )
    server = MCPServerComponent(
        bom_ref="mcp:gateway",
        name=f"gateway-{_RAW_BIDI}",
        assurance_level=AssuranceLevel.OBSERVED,
        command="uvx",
        tool_refs=["tool:cred-reader", "tool:net-runner"],
        risks=[
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="tool_description_poisoning",
                detail="Untrusted MCP tool metadata overrides instructions.",
            )
        ],
    )
    cred_tool = ToolComponent(
        bom_ref="tool:cred-reader",
        name="read_secrets",
        mcp_server_ref="mcp:gateway",
        assurance_level=AssuranceLevel.DECLARED,
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.CREDENTIALS, CapabilityClass.READ],
            side_effect_profile=SideEffectProfile.READ_ONLY,
        ),
        risks=[
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="credential_exposure",
                detail=f"Leaked {_SYNTHETIC_FIXTURE} in config {_RAW_ANSI}",
            )
        ],
    )
    net_tool = ToolComponent(
        bom_ref="tool:net-runner",
        name="run_and_send",
        mcp_server_ref="mcp:gateway",
        assurance_level=AssuranceLevel.OBSERVED,
        capabilities=CapabilityDeclaration(
            capabilities=[CapabilityClass.EXECUTE, CapabilityClass.NETWORK],
            side_effect_profile=SideEffectProfile.STATE_MODIFYING,
        ),
        risks=[
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="code_execution",
                detail="Arbitrary shell command reachable from untrusted MCP context.",
            )
        ],
    )
    pkg = RegistryEntryComponent(
        bom_ref="pkg:pypi/requests@2.31.0",
        name="requests",
        version="2.31.0",
        registry_type="pypi",
        package_url="pkg:pypi/requests@2.31.0",
        assurance_level=AssuranceLevel.VERIFIED,
        properties={
            "advisories": [
                {
                    "id": "GHSA-9wx4-h78v-qvmr",
                    "severity": "medium",
                    "package": "requests",
                    "version": "2.31.0",
                    "ecosystem": "pypi",
                    "aliases": ["CVE-2024-35195", "CVE-2024-35195"],
                    "fixed_versions": ["2.32.0"],
                    "summary": f"Verify=True bypass note with {_SYNTHETIC_FIXTURE}",
                    "epss_score": 0.12,
                    "in_kev": False,
                },
                {
                    "id": "CVE-2024-0002",
                    "severity": "low",
                    "package": "requests",
                    "version": "2.31.0",
                    "ecosystem": "pypi",
                    "fixed": ["2.32.2"],
                    "epss_score": 0.01,
                },
                "malformed-entry",
                {"severity": "high"},
            ]
        },
    )
    return AIBOM(
        components=[agent, server, cred_tool, net_tool, pkg],
        dependencies=[
            DependencyEdge(
                source_ref="agent:assistant",
                target_ref="mcp:gateway",
                relationship="invokes",
            ),
            DependencyEdge(
                source_ref="mcp:gateway",
                target_ref="tool:cred-reader",
                relationship="provides-tool",
            ),
            DependencyEdge(
                source_ref="mcp:gateway",
                target_ref="tool:net-runner",
                relationship="provides-tool",
            ),
            DependencyEdge(
                source_ref="agent:assistant",
                target_ref="pkg:pypi/requests@2.31.0",
                relationship="depends-on",
            ),
        ],
    )


def _write_bound_advisories(tmp_path: Path, inv_sha256: str, *, complete: bool = True) -> Path:
    report = AdvisoryReport(
        components_checked=1,
        errors=[] if complete else ["partial timeout"],
        inventory_sha256=inv_sha256,
        advisories=[
            {
                "id": "CVE-2024-KEV1",
                "bom_ref": "pkg:pypi/requests@2.31.0",
                "severity": "critical",
                "package": "requests",
                "version": "2.31.0",
                "ecosystem": "pypi",
                "aliases": ["GHSA-kev1-0001"],
                "fixed_versions": ["2.32.3"],
                "summary": f"Actively exploited advisory {_RAW_ANSI}",
                "in_kev": True,
                "epss_score": 0.97,
            },
            # Overrides embedded GHSA-9wx4-h78v-qvmr with report severity/source.
            {
                "id": "GHSA-9wx4-h78v-qvmr",
                "component_ref": "pkg:pypi/requests@2.31.0",
                "severity": "high",
                "package": "requests",
                "version": "2.31.0",
                "ecosystem": "pypi",
                "epss_score": 0.55,
                "in_kev": False,
            },
            # Malformed rows ignored safely.
            {"id": "", "bom_ref": "pkg:pypi/requests@2.31.0"},
            {"id": "CVE-2024-NOREF", "bom_ref": "   "},
        ],
    ).to_dict()
    adv_dir = tmp_path / "external"
    adv_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    adv_path = adv_dir / "advisories.json"
    adv_path.write_text(json.dumps(report), encoding="utf-8")
    adv_path.chmod(0o600)
    return adv_path


def _call_tool(server: OfflineMCPServer, name: str, arguments: dict[str, Any] | None = None) -> Any:
    reply = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments if arguments is not None else {}},
        }
    )
    assert reply is not None
    assert "result" in reply, reply
    return reply["result"]


def _decode_content_length_stream(data: bytes) -> list[dict[str, Any]]:
    messages: list[dict[str, Any]] = []
    pos = 0
    while pos < len(data):
        sep = data.index(b"\r\n\r\n", pos)
        header = data[pos:sep].decode("ascii")
        assert header.startswith("Content-Length: ")
        length = int(header.split(":", 1)[1].strip())
        start = sep + 4
        messages.append(json.loads(data[start : start + length].decode("utf-8")))
        pos = start + length
    return messages


def test_initialize_ping_notifications_and_tool_list():
    bom = _build_rich_bom()
    server = OfflineMCPServer(bom, inventory_sha256="a" * 64, content_digest="sha256:" + "b" * 64)

    init_ok = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": "init-1",
            "method": "initialize",
            "params": {"protocolVersion": "2024-11-05"},
        }
    )
    assert init_ok is not None
    assert init_ok["result"]["protocolVersion"] == "2024-11-05"
    assert init_ok["result"]["capabilities"] == {"tools": {"listChanged": False}}

    init_fallback = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "initialize",
            "params": {"protocolVersion": "1999-01-01"},
        }
    )
    assert init_fallback is not None
    assert init_fallback["result"]["protocolVersion"] == "2025-03-26"

    assert server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert server.handle_message({"jsonrpc": "2.0", "id": 3, "method": "ping"}) == {
        "jsonrpc": "2.0",
        "id": 3,
        "result": {},
    }

    tools_reply = server.handle_message({"jsonrpc": "2.0", "id": None, "method": "tools/list"})
    assert tools_reply is not None
    assert tools_reply["id"] is None
    tools = tools_reply["result"]["tools"]
    names = {t["name"] for t in tools}
    assert names == {
        "inventory_summary",
        "list_components",
        "get_findings",
        "get_advisories",
        "blast_radius",
        "trifecta_flows",
        "evidence_profile",
        "minimum_elements",
    }
    for tool in tools:
        assert tool["annotations"] == {
            "readOnlyHint": True,
            "destructiveHint": False,
            "idempotentHint": True,
            "openWorldHint": False,
        }


def test_all_eight_tools_filters_sorting_and_sanitization(tmp_path):
    bom = _build_rich_bom()
    inv_bytes = bom.to_native_json().encode("utf-8")
    inv_sha = hash_bytes(inv_bytes)
    adv_path = _write_bound_advisories(tmp_path, inv_sha)
    loaded = load_advisory_report(adv_path, expected_inventory_sha256=inv_sha)
    server = OfflineMCPServer(
        bom,
        advisory_report=loaded,
        inventory_sha256=inv_sha,
        content_digest="sha256:" + "c" * 64,
    )

    summary = _call_tool(server, "inventory_summary")["structuredContent"]
    assert summary["total_components"] == 5
    assert summary["total_dependencies"] == 4
    assert summary["advisories"]["total"] == 3
    assert summary["advisories"]["kev"] == 1
    assert summary["advisories"]["report"]["coverage"] == "complete"
    assert summary["findings_by_severity"]["critical"] == 1
    assert summary["trifecta"]["finding_count"] >= 1

    # list_components filters & pagination
    all_comps = _call_tool(server, "list_components", {"limit": 2, "offset": 1})[
        "structuredContent"
    ]
    assert all_comps["total"] == 5
    assert all_comps["count"] == 2
    assert all_comps["truncated"] is True

    filtered = _call_tool(
        server,
        "list_components",
        {
            "component_type": "tool",
            "min_severity": "critical",
            "assurance_level": "observed",
            "name_contains": "send",
        },
    )["structuredContent"]
    assert filtered["total"] == 1
    assert filtered["components"][0]["bom_ref"] == "tool:net-runner"

    assert (
        _call_tool(server, "list_components", {"component_type": "model"})["structuredContent"][
            "total"
        ]
        == 0
    )
    assert (
        _call_tool(server, "list_components", {"name_contains": "no-such-component"})[
            "structuredContent"
        ]["total"]
        == 0
    )
    assert (
        _call_tool(
            server,
            "list_components",
            {"min_severity": "critical", "component_type": "mcp-server"},
        )["structuredContent"]["total"]
        == 0
    )

    # get_findings filters & crosswalks
    findings = _call_tool(
        server,
        "get_findings",
        {
            "severity": "high",
            "category": "credential_exposure",
            "component_ref": "tool:cred-reader",
        },
    )["structuredContent"]
    assert findings["total"] == 1
    assert findings["findings"][0]["frameworks"]
    assert _SYNTHETIC_FIXTURE not in json.dumps(findings)

    assert (
        _call_tool(server, "get_findings", {"category": "nonexistent"})["structuredContent"][
            "total"
        ]
        == 0
    )
    assert (
        _call_tool(
            server,
            "get_findings",
            {"severity": "info", "component_ref": "tool:cred-reader"},
        )["structuredContent"]["total"]
        == 0
    )

    # get_advisories ordering (KEV first, then EPSS desc) & overrides
    advs = _call_tool(server, "get_advisories")["structuredContent"]
    assert [a["id"] for a in advs["advisories"]] == [
        "CVE-2024-KEV1",
        "GHSA-9wx4-h78v-qvmr",
        "CVE-2024-0002",
    ]
    assert advs["advisories"][1]["source"] == "advisory-report"
    assert advs["advisories"][1]["severity"] == "high"
    kev_only = _call_tool(
        server,
        "get_advisories",
        {"kev_only": True, "min_severity": "critical", "component_ref": "pkg:pypi/requests@2.31.0"},
    )["structuredContent"]
    assert [a["id"] for a in kev_only["advisories"]] == ["CVE-2024-KEV1"]

    # blast_radius positive & unknown ref tool-error
    blast = _call_tool(server, "blast_radius", {"component_ref": "mcp:gateway"})[
        "structuredContent"
    ]
    assert blast["reachable_advisories_total"] == 3
    bad_blast = _call_tool(server, "blast_radius", {"component_ref": "missing:ref"})
    assert bad_blast["isError"] is True
    assert "error" in bad_blast["structuredContent"]

    # trifecta_flows
    flows = _call_tool(
        server, "trifecta_flows", {"min_severity": "high", "include_shadowing": False}
    )["structuredContent"]
    assert all(f["kind"] != "tool_shadowing" for f in flows["findings"])
    high_trifecta = _call_tool(
        server, "trifecta_flows", {"min_severity": "critical", "include_shadowing": False}
    )["structuredContent"]
    assert high_trifecta["total"] <= flows["total"]

    # evidence_profile with cleaned bom_ref lookup + global
    ev = _call_tool(server, "evidence_profile", {"component_ref": "pkg:pypi/requests@2.31.0"})[
        "structuredContent"
    ]
    assert ev["total"] == 1
    assert _call_tool(server, "evidence_profile")["structuredContent"]["total"] == 5

    # minimum_elements
    me = _call_tool(server, "minimum_elements", {"offset": 0, "limit": 5})["structuredContent"]
    assert me["non_present_total"] >= 1
    assert me["count"] <= 5

    # Depth-truncated _clean_value & missing optional fields on _AdvisoryEntry.to_dict
    deep: Any = "leaf"
    for _ in range(MAX_FRAME_DEPTH + 4):
        deep = [deep]
    from nexus_symbiote.mcp_server import _clean_value

    cleaned_deep = _clean_value(deep)
    assert "<depth-truncated>" in json.dumps(cleaned_deep)
    minimal_adv = _normalize_advisory_row(
        {"id": "CVE-2025-MINIMAL"}, component_ref="c:1", source="embedded-component"
    )
    assert minimal_adv is not None
    assert "summary" not in minimal_adv.to_dict()
    assert "epss_score" not in minimal_adv.to_dict()

    # Zero raw secrets or unneutralized terminal sequences anywhere across all 8 tools
    dumped = json.dumps([summary, all_comps, findings, advs, blast, flows, ev, me])
    assert _SYNTHETIC_FIXTURE not in dumped
    assert "\x1b" not in dumped
    assert "\u202e" not in dumped


def test_advisory_row_edge_cases_and_json_rpc_validation():
    bom = _build_rich_bom()
    server = OfflineMCPServer(bom)

    assert _normalize_advisory_row(
        {"id": "CVE-2025-0001", "epss_score": math.nan, "severity": "bogus"},
        component_ref="c:1",
        source="embedded-component",
    ) == _normalize_advisory_row(
        {"id": "CVE-2025-0001", "epss_score": True, "severity": "medium"},
        component_ref="c:1",
        source="embedded-component",
    )
    entries = _collect_advisories(
        AIBOM(
            components=[
                RegistryEntryComponent(
                    bom_ref="pkg:a",
                    name="a",
                    properties={"advisories": "not-a-list"},
                )
            ]
        ),
        None,
    )
    assert entries == []

    # Invalid JSON-RPC envelopes & args
    assert (
        server.handle_message({"jsonrpc": "1.0", "id": 1, "method": "ping"})["error"]["code"]
        == -32600
    )  # type: ignore[index]
    assert (
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": ""})["error"]["code"] == -32600
    )  # type: ignore[index]
    assert (
        server.handle_message({"jsonrpc": "2.0", "id": True, "method": "ping"})["error"]["code"]
        == -32600
    )  # type: ignore[index]
    assert (
        server.handle_message({"jsonrpc": "2.0", "id": "x" * 257, "method": "ping"})["error"][
            "code"
        ]
        == -32600
    )  # type: ignore[index]
    assert (
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": []})[
            "error"
        ]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": []})[
            "error"
        ]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": []})[
            "error"
        ]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "ping", "arguments": []},
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": ""}}
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "nope"})["error"]["code"]
        == -32601
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "unknown_tool"}}
        )["error"]["code"]
        == -32601
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "inventory_summary", "arguments": {"extra": 1}},
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "blast_radius", "arguments": {}},
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "blast_radius", "arguments": {"component_ref": 123}},
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "blast_radius", "arguments": {"component_ref": ""}},
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list_components", "arguments": {"assurance_level": "reported"}},
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "list_components", "arguments": {"offset": True}},
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {
                    "name": "list_components",
                    "arguments": {"limit": DEFAULT_MAX_ITEMS + 1},
                },
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]
    assert (
        server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": "get_advisories", "arguments": {"kev_only": "yes"}},
            }
        )["error"]["code"]
        == -32602
    )  # type: ignore[index]


def test_stream_framers_bounds_and_offline_isolation(monkeypatch):
    bom = _build_rich_bom()
    server = OfflineMCPServer(bom)

    def _no_subprocess(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("Offline MCP server must never spawn subprocesses")

    monkeypatch.setattr(subprocess, "Popen", _no_subprocess)
    monkeypatch.setattr(subprocess, "run", _no_subprocess)

    # 1. NDJSON stream + notifications + blank lines + error frames under Mode.OFFLINE
    ndjson_in = (
        b"\n"
        + json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}).encode()
        + b"\n"
        + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"}).encode()
        + b"\n"
        + b"[1, 2, 3]\n"
        + b'{"jsonrpc":"2.0","id":1,"id":2,"method":"ping"}\n'
        + (b"[" * (MAX_FRAME_DEPTH + 2) + b"0" + b"]" * (MAX_FRAME_DEPTH + 2))
        + b"\n"
    )
    out = io.BytesIO()
    with enforce(Mode.OFFLINE):
        run_mcp_server_streams(server, client_in=io.BytesIO(ndjson_in), client_out=out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    assert [r.get("result", r.get("error", {}).get("code")) for r in replies] == [
        {},
        -32600,
        -32700,
        -32600,
    ]

    # 2. Content-Length framing + max_requests cap
    req_a = json.dumps({"jsonrpc": "2.0", "id": "a", "method": "ping"}).encode()
    req_b = json.dumps({"jsonrpc": "2.0", "id": "b", "method": "ping"}).encode()
    framed_in = (
        f"Content-Length: {len(req_a)}\r\nContent-Type: application/json\r\n\r\n".encode("ascii")
        + req_a
        + f"Content-Length: {len(req_b)}\r\n\r\n".encode("ascii")
        + req_b
    )
    out_cl = io.BytesIO()
    run_mcp_server_streams(
        server, client_in=io.BytesIO(framed_in), client_out=out_cl, max_requests=1
    )
    decoded = _decode_content_length_stream(out_cl.getvalue())
    assert [m["id"] for m in decoded] == ["a"]

    # 3. Malformed/oversized Content-Length and NDJSON frames
    # Non-fatal oversized NDJSON line (exact MAX_FRAME_BYTES + "\n") recovers for next frame.
    exact_over = (
        (b"a" * MAX_FRAME_BYTES)
        + b"\n"
        + json.dumps({"jsonrpc": "2.0", "id": "recovered", "method": "ping"}).encode()
        + b"\n"
    )
    recover_out = io.BytesIO()
    run_mcp_server_streams(server, client_in=io.BytesIO(exact_over), client_out=recover_out)
    recover_lines = [json.loads(line) for line in recover_out.getvalue().splitlines()]
    assert [r.get("result", r.get("error", {}).get("code")) for r in recover_lines] == [-32600, {}]

    bad_frames = [
        b"x" * (MAX_FRAME_BYTES + 2),  # unclosed oversized line
        (b"a" * (MAX_FRAME_BYTES + 2)) + b"\n",  # newline-terminated oversized line
        b"Content-Length: " + b"0" * (MAX_HEADER_BYTES + 2) + b"\n",
        b"Content-Length: 5\r\n\xff\r\nhello",  # non-ascii header
        b"Content-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        b"Content-Length: 0\r\n\r\n",
        f"Content-Length: {MAX_FRAME_BYTES + 1}\r\n\r\n".encode("ascii"),
        b"Content-Length: 5\r\n" + (b"X-H: 1\r\n" * 17) + b"\r\nhello",
        b"Content-Length: 5\r\nX-Pad: " + (b"z" * (MAX_HEADER_BYTES + 5)) + b"\r\n\r\n",
        b"Content-Length: 10\r\n\r\nshort",  # truncated body
        b"Content-Length: 5\r\nX-Empty-No-CL: 1\r\n",  # EOF inside headers
        b"Content-Length: nope\r\n\r\nhello",  # invalid Content-Length value
    ]
    for bad in bad_frames:
        err_out = io.BytesIO()
        run_mcp_server_streams(server, client_in=io.BytesIO(bad), client_out=err_out)
        raw_out = err_out.getvalue()
        assert b'"error"' in raw_out

    # Depth truncation in _clean_value & invalid max_requests
    with pytest.raises(ValueError, match="max_requests"):
        run_mcp_server_streams(
            server, client_in=io.BytesIO(b""), client_out=io.BytesIO(), max_requests=0
        )
    with pytest.raises(ValueError, match="max_requests"):
        run_mcp_server_streams(
            server,
            client_in=io.BytesIO(b""),
            client_out=io.BytesIO(),
            max_requests=MAX_ALLOWED_REQUESTS + 1,
        )


def test_mcp_server_cli_round_trip_and_refusals(tmp_path, runner):
    bom = _build_rich_bom()
    inv_path = tmp_path / "bom.json"
    inv_bytes = bom.to_native_json().encode("utf-8")
    inv_path.write_bytes(inv_bytes)
    inv_sha = hash_bytes(inv_bytes)
    adv_path = _write_bound_advisories(tmp_path, inv_sha)

    checkout = tmp_path / "repo"
    checkout.mkdir(mode=0o700)

    req_init = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}).encode()
    req_summary = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {"name": "get_advisories", "arguments": {"kev_only": True}},
        }
    ).encode()
    stdin_payload = req_init + b"\n" + req_summary + b"\n"

    res = runner.invoke(
        main,
        [
            "mcp-server",
            str(inv_path),
            "--advisories",
            str(adv_path),
            "--project-root",
            str(checkout),
            "--max-requests",
            "5",
        ],
        input=stdin_payload,
    )
    assert res.exit_code == 0, res.output
    lines = [json.loads(line) for line in res.stdout.splitlines()]
    assert lines[0]["result"]["serverInfo"]["name"] == "nexus-symbiote-offline-mcp"
    assert lines[1]["result"]["structuredContent"]["total"] == 1

    # Flag usage errors
    bad_partial = runner.invoke(main, ["mcp-server", str(inv_path), "--allow-partial-advisories"])
    assert bad_partial.exit_code == 2
    bad_proj = runner.invoke(main, ["mcp-server", str(inv_path), "--project-root", str(checkout)])
    assert bad_proj.exit_code == 2

    # Invalid native file & symlink refusal
    bad_aibom = tmp_path / "bad.json"
    bad_aibom.write_text('{"metadata":{"spec_version":"99.0.0"},"components":[]}', encoding="utf-8")
    assert runner.invoke(main, ["mcp-server", str(bad_aibom)]).exit_code == 1

    not_json = tmp_path / "garbage.json"
    not_json.write_bytes(b"{not json")
    assert runner.invoke(main, ["mcp-server", str(not_json)]).exit_code == 1

    sym = tmp_path / "link.json"
    sym.symlink_to(inv_path)
    assert runner.invoke(main, ["mcp-server", str(sym)]).exit_code == 1

    # Refusal when advisory file lives inside --project-root
    inside_adv = checkout / "advisories.json"
    inside_adv.write_bytes(adv_path.read_bytes())
    inside_adv.chmod(0o600)
    refused_inside = runner.invoke(
        main,
        [
            "mcp-server",
            str(inv_path),
            "--advisories",
            str(inside_adv),
            "--project-root",
            str(checkout),
        ],
    )
    assert refused_inside.exit_code == 1
    assert "outside the scanned project" in refused_inside.output

    # Refusal on mismatched inventory SHA-256
    wrong_adv = _write_bound_advisories(tmp_path / "other", "f" * 64)
    wrong_sha = runner.invoke(main, ["mcp-server", str(inv_path), "--advisories", str(wrong_adv)])
    assert wrong_sha.exit_code == 1

    # Partial advisories refused without --allow-partial-advisories, allowed with it
    partial_adv = _write_bound_advisories(tmp_path / "partial", inv_sha, complete=False)
    assert (
        runner.invoke(
            main, ["mcp-server", str(inv_path), "--advisories", str(partial_adv)]
        ).exit_code
        == 1
    )
    allowed_partial = runner.invoke(
        main,
        [
            "mcp-server",
            str(inv_path),
            "--advisories",
            str(partial_adv),
            "--allow-partial-advisories",
        ],
        input=req_summary + b"\n",
    )
    assert allowed_partial.exit_code == 0, allowed_partial.output

    # Offline run without --advisories
    plain_res = runner.invoke(main, ["mcp-server", str(inv_path)], input=req_init + b"\n")
    assert plain_res.exit_code == 0, plain_res.output


def test_mcp_server_cli_unexpected_io_and_digest_fallbacks(tmp_path, runner, monkeypatch):
    from nexus_symbiote import mcp_server_cli

    bom = _build_rich_bom()
    inv_path = tmp_path / "bom.json"
    inv_bytes = bom.to_native_json().encode("utf-8")
    inv_path.write_bytes(inv_bytes)
    inv_sha = hash_bytes(inv_bytes)
    adv_path = _write_bound_advisories(tmp_path / "ext", inv_sha)

    monkeypatch.setattr(
        mcp_server_cli,
        "inventory_content_digest",
        lambda _doc: (_ for _ in ()).throw(ValueError("bad")),
    )
    req_summary = json.dumps(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": "inventory_summary", "arguments": {}},
        }
    ).encode()
    res_digest_fallback = runner.invoke(
        main, ["mcp-server", str(inv_path)], input=req_summary + b"\n"
    )
    assert res_digest_fallback.exit_code == 0
    assert (
        json.loads(res_digest_fallback.stdout)["result"]["structuredContent"]["content_digest"]
        is None
    )

    monkeypatch.setattr(
        mcp_server_cli,
        "load_advisory_report",
        lambda *_a, **_kw: (_ for _ in ()).throw(OSError("unreadable")),
    )
    res_adv_io = runner.invoke(main, ["mcp-server", str(inv_path), "--advisories", str(adv_path)])
    assert res_adv_io.exit_code == 1
    assert "Cannot safely load advisory report." in res_adv_io.output

    monkeypatch.setattr(
        AIBOM,
        "load_with_bytes",
        classmethod(lambda cls, _p: (_ for _ in ()).throw(OSError("io fail"))),
    )
    res_bom_io = runner.invoke(main, ["mcp-server", str(inv_path)])
    assert res_bom_io.exit_code == 1
    assert "is not a valid native AIBOM file." in res_bom_io.output
