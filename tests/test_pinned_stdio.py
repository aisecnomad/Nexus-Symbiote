"""Independently pinned stdio observations never inherit checkout authority."""

from __future__ import annotations

import hashlib
import json
import sys
import time
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import TOOL_DEFINITION_HASH_VERSION, hash_tool_definition
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.live import stdio
from nexus_symbiote.live.verify import verify_mcp_servers

TOOL = {"name": "weather", "description": "Read weather", "inputSchema": {"type": "object"}}
SERVER = """import json, os, sys
assert "PINNED_STDIO_TEST_SECRET" not in os.environ
assert not os.path.exists(".mcp.json")
tools = TOOLS
for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {"protocolVersion":"2025-06-18", "capabilities":{"tools":{}}, "serverInfo":{"name":"fixture","version":"1"}}
    elif method == "tools/list":
        result = {"tools": tools}
    else:
        raise AssertionError("unexpected method")
    print(json.dumps({"jsonrpc":"2.0", "id": request["id"], "result":result}), flush=True)
"""


def launcher(tmp_path: Path, source: str | None = None, tools=None):
    path = tmp_path / "operator-launcher"
    source = source or SERVER.replace("TOOLS", repr([TOOL] if tools is None else tools))
    path.write_text("#!" + sys.executable + "\n" + source)
    return {
        "mcp:weather": {
            "command": str(path),
            "sha256": "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(),
        }
    }


def inventory(*, approved: bool = True, name: str = "weather") -> AIBOM:
    bom = AIBOM(
        components=[MCPServerComponent(bom_ref="mcp:weather", name="weather", transport="stdio")]
    )
    if approved:
        bom.add_component(
            ToolComponent(
                bom_ref="tool:weather",
                name=name,
                mcp_server_ref="mcp:weather",
                description_text=TOOL["description"],
                input_schema=TOOL["inputSchema"],
                definition_hash=hash_tool_definition(
                    name, TOOL["description"], TOOL["inputSchema"]
                ),
                definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
            )
        )
    return bom


def command(tmp_path: Path, bom: AIBOM, policy):
    project = tmp_path / "checkout"
    project.mkdir(exist_ok=True)
    target = project / "bom.json"
    bom.save(target)
    policy_path = tmp_path / "operator-policy.json"
    policy_path.write_text(json.dumps(policy))
    return [
        "--live",
        "verify-live",
        str(target),
        "--project",
        str(project),
        "--launch-policy",
        str(policy_path),
    ], target


def test_matching_pinned_inventory_ignores_checkout_config_and_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("PINNED_STDIO_TEST_SECRET", "private-canary")
    args, target = command(tmp_path, inventory(), launcher(tmp_path))
    marker = tmp_path / "unauthorized"
    (target.parent / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "weather": {
                        "command": sys.executable,
                        "args": ["-c", f"open({str(marker)!r},'w').close()"],
                    }
                }
            }
        )
    )
    result = CliRunner().invoke(main, args + ["--json-output"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["complete"]
    assert not marker.exists()


def test_no_project_policy_or_display_name_can_authorize_execution(tmp_path):
    policy = launcher(tmp_path)
    args, target = command(tmp_path, inventory(), {})
    runner = CliRunner()
    assert runner.invoke(main, args + ["--json-output"]).exit_code != 0
    project_policy = target.parent / "forged.json"
    project_policy.write_text(json.dumps(policy))
    assert runner.invoke(main, [*args[:-1], str(project_policy)]).exit_code != 0
    assert not verify_mcp_servers(
        inventory(), trusted_launchers={"weather": next(iter(policy.values()))}
    ).complete
    assert not verify_mcp_servers(inventory(), {"weather": next(iter(policy.values()))}).complete


def test_hash_substitution_symlink_and_extra_launch_arguments_are_refused(tmp_path):
    policy = launcher(tmp_path)
    original = (tmp_path / "operator-launcher").read_text()
    (tmp_path / "operator-launcher").write_text(original + "\n# substituted\n")
    assert not verify_mcp_servers(inventory(), trusted_launchers=policy).complete
    policy = launcher(tmp_path)
    link = tmp_path / "link"
    link.symlink_to(tmp_path / "operator-launcher")
    policy["mcp:weather"]["command"] = str(link)
    assert not verify_mcp_servers(inventory(), trusted_launchers=policy).complete
    policy = launcher(tmp_path)
    policy["mcp:weather"]["args"] = ["--untrusted"]
    assert not verify_mcp_servers(inventory(), trusted_launchers=policy).complete


def test_candidate_is_separate_and_can_be_verified_twice(tmp_path):
    policy = launcher(tmp_path)
    args, target = command(tmp_path, inventory(approved=False), policy)
    original = target.read_bytes()
    runner = CliRunner()
    assert runner.invoke(main, args).exit_code != 0
    recorded = runner.invoke(main, args + ["--record"])
    assert recorded.exit_code == 0, recorded.output
    candidate = AIBOM.model_validate_json(recorded.stdout)
    for _ in range(2):
        report = verify_mcp_servers(candidate, trusted_launchers=policy)
        assert report.complete and not report.has_drift
    assert target.read_bytes() == original


def test_missing_tools_and_legacy_profiles_fail_without_candidate(tmp_path):
    policy = launcher(tmp_path)
    args, _ = command(tmp_path, inventory(name="removed"), policy)
    runner = CliRunner()
    missing = runner.invoke(main, args + ["--json-output"])
    assert missing.exit_code != 0
    assert any(
        f["status"] == "missing" for r in json.loads(missing.stdout)["results"] for f in r["tools"]
    )
    assert runner.invoke(main, args + ["--record"]).exit_code != 0
    legacy = inventory()
    legacy.components[1].definition_hash_version = "rfc8785-jcs-v1"
    report = verify_mcp_servers(legacy, trusted_launchers=policy)
    assert not report.complete and report.has_drift


@pytest.mark.parametrize(
    "tools",
    [
        [TOOL, TOOL],
        [{**TOOL, "inputSchema": []}],
        [{**TOOL, "inputSchema": {"type": "invalid"}}],
        [{**TOOL, "outputSchema": {"type": "object"}}],
        [{**TOOL, "annotations": {"readOnlyHint": "true"}}],
    ],
)
def test_incomplete_or_unsupported_descriptors_fail_closed(tmp_path, tools):
    report = verify_mcp_servers(inventory(), trusted_launchers=launcher(tmp_path, tools=tools))
    assert not report.complete
    assert report.results[0].tool_findings == []


def test_silent_peer_and_repeated_pagination_are_bounded(tmp_path, monkeypatch):
    monkeypatch.setattr(stdio, "DEADLINE_SECONDS", 0.2)
    start = time.monotonic()
    assert not verify_mcp_servers(
        inventory(), trusted_launchers=launcher(tmp_path, "import time; time.sleep(30)")
    ).complete
    assert time.monotonic() - start < 3
    # No tools on the repeated page: a repeated tool would be refused as a duplicate
    # before the cursor check runs, so the case would pass without exercising it.
    repeated = SERVER.replace("TOOLS", repr([])).replace(
        'result = {"tools": tools}', 'result = {"tools": tools, "nextCursor":"same"}'
    )
    assert not verify_mcp_servers(
        inventory(), trusted_launchers=launcher(tmp_path, repeated)
    ).complete


LISTING = 'result = {"tools": tools}'


@pytest.mark.parametrize(
    ("old", "new", "tools", "reason"),
    [
        ("2025-06-18", "2024-11-05", [TOOL], "unsupported MCP protocol version"),
        ('"capabilities":{"tools":{}}', '"capabilities":{}', [TOOL], "not negotiated"),
        ('"version":"1"}}', '"version":1}}', [TOOL], "not negotiated"),
        ('"id": request["id"]', '"id": request["id"] + 1', [TOOL], "unexpected MCP response"),
        (LISTING, 'result = {"tools": tools, "nextCursor":"same"}', [], "pagination cursor"),
        (LISTING, 'result = {"tools": tools, "nextCursor":""}', [], "pagination cursor"),
        (LISTING, 'result = {"tools": tools, "nextCursor":"c" * 257}', [], "pagination cursor"),
        (LISTING, 'result = {"tools": {"weather": tools}}', [TOOL], "invalid or oversized"),
        (LISTING, LISTING, [{**TOOL, "name": "weather\nforged"}], "invalid or duplicate"),
        (LISTING, LISTING, [{**TOOL, "name": "x" * 257}], "invalid or duplicate"),
    ],
    ids=[
        "protocol-version",
        "tools-capability",
        "server-info",
        "response-id",
        "repeated-cursor",
        "empty-cursor",
        "oversized-cursor",
        "tool-list-type",
        "unprintable-tool-name",
        "oversized-tool-name",
    ],
)
def test_handshake_and_listing_violations_fail_for_the_stated_reason(
    tmp_path, old, new, tools, reason
):
    # verify_mcp_servers reports only that verification is incomplete, so check the
    # launcher's own refusal to show which guard fired.
    base = SERVER.replace("TOOLS", repr(tools))
    source = base.replace(old, new)
    assert old in base and (source != base or old == new)
    policy = launcher(tmp_path, source)["mcp:weather"]
    with pytest.raises(ValueError, match=reason):
        stdio.list_pinned_tools(policy["command"], policy["sha256"])


def test_peer_that_never_reads_requests_cannot_block_writes(tmp_path, monkeypatch):
    monkeypatch.setattr(stdio, "DEADLINE_SECONDS", 0.2)
    source = """import json, sys, time
hello = {"protocolVersion":"2025-06-18", "capabilities":{"tools":{}}, "serverInfo":{"name":"fixture","version":"1"}}
print(json.dumps({"jsonrpc":"2.0", "id":1, "result":hello}), flush=True)
for page in range(64):
    cursor = str(page) + "x" * 250
    print(json.dumps({"jsonrpc":"2.0", "id":page+2, "result":{"tools":[], "nextCursor":cursor}}), flush=True)
time.sleep(30)
"""
    started = time.monotonic()
    report = verify_mcp_servers(inventory(), trusted_launchers=launcher(tmp_path, source))
    assert not report.complete
    assert time.monotonic() - started < 3
