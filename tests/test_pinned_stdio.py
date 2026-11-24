"""Independently pinned stdio observations never inherit checkout authority."""

from __future__ import annotations

import hashlib
import json
import os
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
from tests.support import STDIO_HELLO, launcher_log, misbehaving_launcher

pytestmark = pytest.mark.usefixtures("nonisolated_pinned_fixtures")


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
    with pytest.raises(ValueError, match="config_lookup"):
        verify_mcp_servers(inventory(), {"weather": next(iter(policy.values()))})
    with pytest.raises(ValueError, match="config_lookup"):
        verify_mcp_servers(inventory(), config_lookup={"weather": next(iter(policy.values()))})


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
    # Recording tools that no inventory approved is drift: the candidate is printed
    # for review, but the command fails unless the operator accepts the drift.
    recorded = runner.invoke(main, args + ["--record"])
    assert recorded.exit_code == 1, recorded.output
    assert "Drift in server mcp:weather: new tool weather" in recorded.stderr
    AIBOM.model_validate_json(recorded.stdout)
    accepted = runner.invoke(main, args + ["--record", "--accept-drift"])
    assert accepted.exit_code == 0, accepted.output
    candidate = AIBOM.model_validate_json(accepted.stdout)
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
        [{**TOOL, "outputSchema": {"type": "array"}}],
        [{**TOOL, "title": 7}],
        [{**TOOL, "_meta": []}],
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
    assert time.monotonic() - start < 3  # deadline check: DEADLINE_SECONDS timeout
    repeated = SERVER.replace("TOOLS", repr([TOOL])).replace(
        'result = {"tools": tools}', 'result = {"tools": tools, "nextCursor":"same"}'
    )
    assert not verify_mcp_servers(
        inventory(), trusted_launchers=launcher(tmp_path, repeated)
    ).complete


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


# The bounds of the pinned stdio exchange. A launcher that misbehaves in one way is refused
# at a fixed diagnostic, its process group is killed and reaped before the refusal is
# reported, and nothing is imported. The snippets run inside the launcher; see
# tests.support.misbehaving_launcher.
NOTIFICATION = '{"jsonrpc":"2.0","method":"notifications/message","params":{}}'
STREAM_ENDED = "MCP stream ended or exceeded its byte limit"
BAD_ENTRY = "invalid or duplicate MCP list entry"
BAD_CURSOR = "invalid MCP pagination cursor"


def pinned(tmp_path: Path, **behaviour: str | dict) -> tuple[str, str, Path]:
    log = tmp_path / "launcher.log"
    path = tmp_path / "misbehaving-launcher"
    pin = misbehaving_launcher(path, log, **behaviour)
    return str(path), pin, log


def assert_reaped(log: Path) -> list[object]:
    entries = launcher_log(log)
    assert entries and entries[0][0] == "started"
    for entry in entries:
        with pytest.raises(ProcessLookupError):
            os.kill(int(entry[1]), 0)
    return [entry[0] for entry in entries]


def refused_observation(
    tmp_path: Path, failure: str, *, reason: str = "protocol", **behaviour: str | dict
) -> list[object]:
    command, pin, log = pinned(tmp_path, **behaviour)
    with pytest.raises(stdio.StdioProtocolError) as refusal:
        stdio.observe_pinned(command, pin)
    assert str(refusal.value) == failure
    assert refusal.value.reason == reason
    return assert_reaped(log)


def test_a_frame_over_the_line_limit_is_refused(tmp_path):
    on_list = f"reply({{'tools': [], 'pad': 'x' * {stdio.MAX_LINE}}})"
    methods = refused_observation(tmp_path, "MCP frame exceeds size limit", on_list=on_list)
    assert methods == ["started", "initialize", "notifications/initialized", "tools/list"]


def test_more_frames_than_the_budget_are_refused_before_the_reply_is_read(tmp_path):
    on_list = f"for _ in range(1030):\n    emit({NOTIFICATION!r})\nreply({{'tools': []}})"
    refused_observation(tmp_path, "MCP frame budget exceeded", on_list=on_list)


def test_a_stream_over_the_byte_budget_is_refused_before_the_reply_is_read(tmp_path):
    padded = (
        "{'jsonrpc': '2.0', 'method': 'notifications/message', 'params': {'pad': 'x' * 500000}}"
    )
    on_list = f"for _ in range(20):\n    emit(json.dumps({padded}))\nreply({{'tools': []}})"
    refused_observation(tmp_path, STREAM_ENDED, on_list=on_list)


def test_a_launcher_that_exits_before_replying_is_refused(tmp_path):
    methods = refused_observation(tmp_path, STREAM_ENDED, on_list="raise SystemExit(0)")
    assert methods[-1] == "tools/list"


@pytest.mark.parametrize(
    ("on_list", "failure"),
    [
        ("emit('not json')", "invalid JSON-RPC frame"),
        (
            'emit(\'{"jsonrpc":"2.0","jsonrpc":"2.0","id":2,"result":{}}\')',
            "invalid JSON-RPC frame",
        ),
        ("emit('[]')", "invalid JSON-RPC envelope"),
        ("emit('null')", "invalid JSON-RPC envelope"),
        ('emit(\'{"jsonrpc":"1.0","id":2,"result":{"tools":[]}}\')', "invalid JSON-RPC envelope"),
        ("reply({'tools': []}, request_id=99)", "unexpected MCP response"),
        (
            "emit(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], 'result': {}, 'extra': 1}))",
            "unexpected MCP response",
        ),
        (
            "emit(json.dumps({'jsonrpc': '2.0', 'id': msg['id'], "
            "'error': {'code': -32603, 'message': 'x'}}))",
            "unexpected MCP response",
        ),
        ("reply([])", "invalid MCP result"),
    ],
    ids=[
        "not-json",
        "duplicate-key",
        "array",
        "null",
        "wrong-version",
        "wrong-id",
        "extra-member",
        "error-reply",
        "non-object-result",
    ],
)
def test_malformed_frames_and_replies_are_refused(tmp_path, on_list, failure):
    refused_observation(tmp_path, failure, on_list=on_list)


LIST_CHANGED = "MCP server changed a list during observation"


@pytest.mark.parametrize("kind", ["tools", "prompts", "resources"])
def test_a_list_changed_notification_before_the_reply_is_refused(tmp_path, kind):
    # The server says the list it is about to serve is already stale.
    changed = json.dumps({"jsonrpc": "2.0", "method": f"notifications/{kind}/list_changed"})
    on_list = f"emit({changed!r})\nreply({{'tools': []}})"
    refused_observation(tmp_path, LIST_CHANGED, on_list=on_list)


def test_a_list_changed_notification_between_pages_is_refused(tmp_path):
    # A list_changed-aware client would refetch here and could see other tools.
    changed = json.dumps({"jsonrpc": "2.0", "method": "notifications/tools/list_changed"})
    on_list = (
        "if page == 1:\n"
        "    reply({'tools': [{'name': 'a'}], 'nextCursor': 'c'})\n"
        f"    emit({changed!r})\n"
        "else:\n"
        "    reply({'tools': [{'name': 'b'}]})"
    )
    refused_observation(tmp_path, LIST_CHANGED, on_list=on_list)


def test_other_notifications_are_still_skipped(tmp_path):
    command, pin, log = pinned(tmp_path, on_list=f"emit({NOTIFICATION!r})\nreply({{'tools': []}})")
    assert stdio.observe_pinned(command, pin).tools == []
    assert_reaped(log)


@pytest.mark.parametrize(
    "on_list",
    [
        "reply({'tools': [{'name': 't%d' % i} for i in range(4097)]})",
        "reply({'tools': 'weather'})",
        "reply({})",
    ],
    ids=["too-many", "not-a-list", "absent"],
)
def test_an_oversized_or_invalid_tool_list_is_refused(tmp_path, on_list):
    refused_observation(tmp_path, "invalid or oversized MCP list", on_list=on_list)


@pytest.mark.parametrize(
    "on_list",
    [
        "reply({'tools': [{'name': 'a'}, {'name': 'a'}]})",
        "reply({'tools': ['a']})",
        "reply({'tools': [{'name': ''}]})",
        "reply({'tools': [{'name': 7}]})",
        "reply({'tools': [{'name': 'x' * 2049}]})",
        "reply({'tools': [{'name': 'a\\x00b'}]})",
    ],
    ids=["duplicate", "not-an-object", "empty-name", "non-string-name", "long-name", "control"],
)
def test_an_invalid_or_duplicate_list_entry_is_refused(tmp_path, on_list):
    refused_observation(tmp_path, BAD_ENTRY, on_list=on_list)


def test_a_duplicate_across_pages_is_refused_like_one_within_a_page(tmp_path):
    on_list = (
        "if page == 1:\n    reply({'tools': [{'name': 'a'}], 'nextCursor': 'two'})\n"
        "else:\n    reply({'tools': [{'name': 'a'}]})"
    )
    methods = refused_observation(tmp_path, BAD_ENTRY, on_list=on_list)
    assert methods.count("tools/list") == 2


@pytest.mark.parametrize(
    "on_list",
    [
        "reply({'tools': [], 'nextCursor': ''})",
        "reply({'tools': [], 'nextCursor': 7})",
        "reply({'tools': [], 'nextCursor': 'x' * 257})",
        "reply({'tools': [], 'nextCursor': 'same'})",
    ],
    ids=["empty", "not-a-string", "too-long", "repeated"],
)
def test_an_invalid_or_repeated_cursor_is_refused(tmp_path, on_list):
    refused_observation(tmp_path, BAD_CURSOR, on_list=on_list)


def test_the_page_budget_ends_a_list_that_never_finishes(tmp_path):
    on_list = "reply({'tools': [], 'nextCursor': 'page-%d' % page})"
    methods = refused_observation(tmp_path, "MCP page budget exceeded", on_list=on_list)
    assert methods.count("tools/list") == 64


@pytest.mark.parametrize(
    "capabilities", [{}, {"tools": "yes"}, {"prompts": {}}], ids=["none", "not-an-object", "other"]
)
def test_a_server_that_does_not_negotiate_tool_listing_is_refused(tmp_path, capabilities):
    hello = {**STDIO_HELLO, "capabilities": capabilities}
    methods = refused_observation(
        tmp_path, "MCP tool listing was not negotiated", hello=hello, on_list="reply({'tools': []})"
    )
    assert methods == ["started", "initialize"]


def test_an_unsupported_protocol_version_is_refused_with_its_own_reason(tmp_path):
    hello = {**STDIO_HELLO, "protocolVersion": "2099-01-01"}
    refused_observation(
        tmp_path,
        "unsupported MCP protocol version",
        reason="unsupported-protocol-version",
        hello=hello,
    )


def test_a_launcher_that_closes_its_input_is_refused_when_the_next_message_is_sent(tmp_path):
    # The input is closed before the reply, so the client's next message, sent only once
    # the reply has arrived, always meets a pipe without a reader.
    on_initialize = "os.close(0)\nreply(hello)\ntime.sleep(30)"
    methods = refused_observation(tmp_path, "MCP input stream closed", on_initialize=on_initialize)
    assert methods == ["started", "initialize"]


class _ZeroWrites:
    """``os`` as seen by the module under test, with every write accepting nothing."""

    def __getattr__(self, name: str):
        return getattr(os, name)

    def write(self, fd: int, data) -> int:
        return 0


def test_a_write_that_makes_no_progress_is_a_closed_input_stream(tmp_path, monkeypatch):
    command, pin, _ = pinned(tmp_path)
    monkeypatch.setattr(stdio, "os", _ZeroWrites())
    with pytest.raises(stdio.StdioProtocolError, match="MCP input stream closed"):
        stdio.observe_pinned(command, pin)


def test_an_exhausted_frame_source_is_a_missing_response(tmp_path, monkeypatch):
    command, pin, _ = pinned(tmp_path)
    monkeypatch.setattr(stdio, "_frames", lambda fd, deadline: iter(()))
    with pytest.raises(stdio.StdioProtocolError, match="missing MCP response"):
        stdio.observe_pinned(command, pin)


def test_a_launcher_over_the_byte_budget_is_refused_before_it_is_read_or_run(tmp_path):
    # A sparse file: the size check reads st_size before any byte, so no 128 MiB is written.
    path = tmp_path / "huge-launcher"
    with path.open("wb") as stream:
        stream.truncate(128 * 1024 * 1024 + 1)
    pin = "sha256:" + hashlib.sha256(b"").hexdigest()
    with pytest.raises(stdio.LaunchPolicyError) as refusal:
        stdio.observe_pinned(str(path), pin)
    assert str(refusal.value) == "launcher exceeds byte budget"
    assert refusal.value.reason == "launcher-unavailable"
    policy = {"mcp:weather": {"command": str(path), "sha256": pin}}
    report = verify_mcp_servers(inventory(), trusted_launchers=policy)
    assert not report.complete
    assert report.results[0].reason == "launcher-unavailable"
