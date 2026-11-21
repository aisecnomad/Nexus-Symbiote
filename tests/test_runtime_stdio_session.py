from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

from nexus_symbiote.live import session as live_session
from nexus_symbiote.live.pinned_process import isolation_off
from nexus_symbiote.live.session import (
    MAX_REQUEST_BYTES,
    ExecutionOutcomeUnknown,
    PinnedStdioSession,
    invoke_pinned_stdio,
)
from nexus_symbiote.runtime import AuthorizationError, digest, sign_contract
from nexus_symbiote.runtime_validation import MAX_ARGUMENT_BYTES, ValidationBudgetError
from tests.support import STDIO_HELLO, launcher_log, misbehaving_launcher
from tests.test_runtime_authorization import DEFINITION, fixture

pytestmark = pytest.mark.usefixtures("nonisolated_pinned_fixtures")


def launcher(
    tmp_path: Path,
    *,
    altered: bool = False,
    missing: bool = False,
    mode: str = "normal",
    output_schema: dict | None = None,
    tool_result: dict | None = None,
) -> tuple[Path, str, Path]:
    log = tmp_path / "calls.jsonl"
    path = tmp_path / "launcher"
    definition = dict(DEFINITION)
    if altered:
        definition["description"] = "changed after approval"
    if output_schema is not None:
        definition["outputSchema"] = output_schema
    script = f"""#!{sys.executable}
import json, os, sys, time
tool_result = {tool_result!r}
definition = {definition!r}
log = {str(log)!r}
mode = {mode!r}
for line in sys.stdin:
    msg = json.loads(line)
    method = msg.get("method")
    if method == "notifications/initialized":
        continue
    if method == "initialize":
        result = {{"protocolVersion": "2025-06-18", "capabilities": {{"tools": {{}}}}, "serverInfo": {{"name": "test", "version": "1"}}}}
        if mode == "no-tools":
            result["capabilities"] = {{}}
        if mode == "stall-initialize":
            time.sleep(30)
    elif method == "tools/list":
        with open(log, "a") as f:
            f.write(json.dumps([method, int(os.readlink("/proc/self"))]) + "\\n")
        if mode == "exit":
            raise SystemExit(1)
        if mode == "stall":
            time.sleep(30)
        result = {{"tools": [] if {missing!r} else [definition]}}
        if mode == "null-cursor":
            result["nextCursor"] = None
    elif method == "tools/call":
        with open(log, "a") as f:
            f.write(json.dumps([method, int(os.readlink("/proc/self")), msg["params"]]) + "\\n")
        result = {{"content": [{{"type": "text", "text": "ok"}}]}}
        if tool_result is not None:
            result = tool_result
    else:
        raise SystemExit(1)
    reply_id = msg["id"] + 1 if method == "tools/list" and mode == "wrong-id" else msg["id"]
    print(json.dumps({{"jsonrpc": "2.0", "id": reply_id, "result": result}}), flush=True)
"""
    path.write_text(script)
    path.chmod(0o700)
    return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest(), log


def signed_inputs(values, pin):
    gateway, call, bom, snapshot, status, approval, release, human, trust, executed = values
    grant = snapshot.tools[0].model_copy(update={"endpoint_identity": "stdio+launcher:" + pin})
    snapshot = snapshot.model_copy(update={"tools": (grant,)})
    approval = approval.model_copy(
        update={"snapshot_digest": digest(snapshot.model_dump(mode="json"))}
    )
    return {
        "snapshot": sign_contract(snapshot, "snapshot", (release,)),
        "trust": sign_contract(status, "trust", (trust,)),
        "bom": bom,
        "approval": sign_contract(approval, "approval", (human,)),
    }


def test_authorized_call_uses_same_pinned_process_and_consumes_nonce(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path)
    kwargs = signed_inputs(values, pin)
    result = invoke_pinned_stdio(values[0], values[1], command=str(path), sha256=pin, **kwargs)
    assert result["content"][0]["text"] == "ok"
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r[0] for r in records] == ["tools/list", "tools/call"]
    assert records[0][1] == records[1][1]
    assert records[1][2] == {"name": "send", "arguments": {"to": "team@example.test"}}
    assert values[-1] == []  # The gateway's separate executor was never called.
    with pytest.raises(AuthorizationError, match="already been used"):
        invoke_pinned_stdio(values[0], values[1], command=str(path), sha256=pin, **kwargs)
    assert len(log.read_text().splitlines()) == 3  # Second process listed but did not call.


def test_largest_admitted_arguments_reach_the_server_in_one_request(tmp_path):
    values = list(fixture(tmp_path))
    body = "a" * (MAX_ARGUMENT_BYTES - 96)
    call = values[1].model_copy(update={"arguments": {"to": "team@example.test", "body": body}})
    values[1] = call
    values[5] = values[5].model_copy(
        update={"request_digest": digest(call.model_dump(mode="json"))}
    )
    path, pin, log = launcher(tmp_path)
    result = invoke_pinned_stdio(
        values[0], call, command=str(path), sha256=pin, **signed_inputs(values, pin)
    )
    assert result["content"][0]["text"] == "ok"
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r[0] for r in records] == ["tools/list", "tools/call"]
    assert records[1][2]["arguments"]["body"] == body


def test_null_pagination_cursor_ends_the_tool_list(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, mode="null-cursor")
    result = invoke_pinned_stdio(
        values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
    )
    assert result["content"][0]["text"] == "ok"
    assert [json.loads(line)[0] for line in log.read_text().splitlines()] == [
        "tools/list",
        "tools/call",
    ]


def test_changed_descriptor_denied_before_call(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, altered=True)
    with pytest.raises(AuthorizationError, match="descriptor changed"):
        invoke_pinned_stdio(
            values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    assert [json.loads(line)[0] for line in log.read_text().splitlines()] == ["tools/list"]


def test_wrong_launcher_pin_never_starts_process(tmp_path):
    values = fixture(tmp_path)
    path, _, log = launcher(tmp_path)
    pin = "sha256:" + "0" * 64
    with pytest.raises(AuthorizationError, match="differs"):
        invoke_pinned_stdio(
            values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    assert not log.exists()


@pytest.mark.parametrize(
    ("mode", "pinned", "reason"),
    [
        ("normal", False, "denied"),
        ("no-tools", True, "denied"),
        ("stall-initialize", True, "adapter-error"),
    ],
)
def test_launcher_refusals_are_recorded_once(tmp_path, monkeypatch, mode, pinned, reason):
    values = fixture(tmp_path)
    decisions = []
    values[0].on_decision = decisions.append
    monkeypatch.setattr("nexus_symbiote.live.session.DEADLINE_SECONDS", 1.0)
    path, pin, log = launcher(tmp_path, mode=mode)
    if not pinned:
        pin = "sha256:" + "0" * 64
    with pytest.raises((AuthorizationError, OSError, ValueError)):
        invoke_pinned_stdio(
            values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    [decision] = decisions
    assert (decision.admitted, decision.reason) == (False, reason)
    assert (decision.server_id, decision.tool_name) == ("server:mail", "send")
    assert decision.store_id == values[0].state.store_id
    assert not log.exists()


def test_session_is_single_use_and_rejects_wrong_server(tmp_path):
    path, pin, _ = launcher(tmp_path)
    session = PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail")
    with session, pytest.raises(AuthorizationError, match="server mismatch"):
        session.describe("server:other", "send")
    with pytest.raises(AuthorizationError, match="reused"), session:
        pass


def test_concurrent_replay_allows_only_one_call(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path)
    kwargs = signed_inputs(values, pin)

    def request():
        try:
            with isolation_off():
                invoke_pinned_stdio(values[0], values[1], command=str(path), sha256=pin, **kwargs)
            return "executed"
        except AuthorizationError as exc:
            assert "already been used" in str(exc)
            return "denied"

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: request(), range(2)))
    assert sorted(results) == ["denied", "executed"]
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert sum(row[0] == "tools/call" for row in records) == 1


def test_session_rejects_call_for_different_tool_and_repeat(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        session.describe("server:mail", "send")
        with pytest.raises(AuthorizationError, match="described session"):
            session.execute(values[1].model_copy(update={"tool_name": "other"}))
        session.execute(values[1])
        with pytest.raises(AuthorizationError, match="described session"):
            session.execute(values[1])
    assert [json.loads(line)[0] for line in log.read_text().splitlines()] == [
        "tools/list",
        "tools/call",
    ]


def test_failed_descriptor_lookup_cannot_enable_execution(tmp_path):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, missing=True)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        with pytest.raises(AuthorizationError, match="missing"):
            session.describe("server:mail", "send")
        with pytest.raises(AuthorizationError, match="described session"):
            session.execute(values[1])
        with pytest.raises(AuthorizationError, match="repeated"):
            session.describe("server:mail", "send")
    assert [json.loads(line)[0] for line in log.read_text().splitlines()] == ["tools/list"]


def test_symlink_launcher_is_rejected(tmp_path):
    path, pin, log = launcher(tmp_path)
    alias = tmp_path / "alias"
    alias.symlink_to(path)
    with (
        pytest.raises((OSError, ValueError)),
        PinnedStdioSession(command=str(alias), sha256=pin, server_id="server:mail"),
    ):
        pass
    assert not log.exists()


@pytest.mark.parametrize("mode", ["wrong-id", "exit", "stall"])
def test_protocol_failure_kills_and_reaps_process(tmp_path, monkeypatch, mode):
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, mode=mode)
    monkeypatch.setattr("nexus_symbiote.live.session.DEADLINE_SECONDS", 1.5)
    with pytest.raises((AuthorizationError, OSError, ValueError)):
        invoke_pinned_stdio(
            values[0], values[1], command=str(path), sha256=pin, **signed_inputs(values, pin)
        )
    records = [json.loads(line) for line in log.read_text().splitlines()]
    assert [r[0] for r in records] == ["tools/list"]
    # The PID namespace is torn down after the supervisor dies, not in the same instant.
    deadline = time.monotonic() + 10
    pid = records[0][1]
    while time.monotonic() < deadline:
        try:
            os.kill(pid, 0)
        except ProcessLookupError:
            break
        time.sleep(0.05)
    else:
        raise AssertionError(f"launcher process {pid} was still running")


@pytest.mark.parametrize(
    ("failure", "reason"),
    [
        ("workload", "trust-tenant-mismatch"),
        ("changed-workload", "identity-changed"),
        ("scope", "scope-mismatch"),
        ("endpoint", "endpoint-mismatch"),
        ("revocation", "tool-revoked"),
        ("approval", "approval-request-mismatch"),
    ],
)
def test_gateway_gates_prevent_real_process_tool_calls(tmp_path, failure, reason):
    values = list(fixture(tmp_path))
    gateway, call, _, snapshot, status, approval, _, human, trust_key, _ = values
    path, pin, log = launcher(tmp_path)
    kwargs = signed_inputs(values, pin)
    if failure == "workload":
        context = gateway.authenticate()
        gateway.authenticate = lambda: context.model_copy(update={"tenant": "other"})
    elif failure == "changed-workload":
        context = gateway.authenticate()
        calls = iter([context, context.model_copy(update={"tenant": "other"})])
        gateway.authenticate = lambda: next(calls)
    elif failure == "scope":
        gateway.resolve_scope = lambda _: ("send", "mailbox:admin")
    elif failure == "endpoint":
        kwargs = signed_inputs(values, "sha256:" + "f" * 64)
    elif failure == "revocation":
        status = status.model_copy(update={"revoked_tools": (snapshot.tools[0].definition_digest,)})
        kwargs["trust"] = sign_contract(status, "trust", (trust_key,))
    elif failure == "approval":
        grant = snapshot.tools[0].model_copy(update={"endpoint_identity": "stdio+launcher:" + pin})
        pinned = snapshot.model_copy(update={"tools": (grant,)})
        approval = approval.model_copy(
            update={
                "snapshot_digest": digest(pinned.model_dump(mode="json")),
                "request_digest": "sha256:" + "0" * 64,
            }
        )
        kwargs["approval"] = sign_contract(approval, "approval", (human,))
    with pytest.raises(AuthorizationError) as denied:
        invoke_pinned_stdio(gateway, call, command=str(path), sha256=pin, **kwargs)
    assert denied.value.reason == reason
    records = [json.loads(line)[0] for line in log.read_text().splitlines()] if log.exists() else []
    assert "tools/call" not in records


# The bounds of the session's handshake and descriptor lookup. A launcher that misbehaves
# in one way is denied at a fixed diagnostic before any tools/call is written, and its
# process group is killed and reaped. The snippets run inside the launcher; see
# tests.support.misbehaving_launcher.
SERVED = f"reply({{'tools': [{DEFINITION!r}]}})"
BAD_NAME = "invalid or duplicate MCP tool name"
BAD_CURSOR = "invalid MCP pagination cursor"


def scripted(tmp_path: Path, **behaviour: str | dict) -> tuple[Path, str, Path]:
    log = tmp_path / "scripted.log"
    path = tmp_path / "scripted-launcher"
    pin = misbehaving_launcher(path, log, **behaviour)
    return path, pin, log


def assert_reaped_without_a_call(log: Path) -> list[object]:
    entries = launcher_log(log)
    assert entries and entries[0][0] == "started"
    methods = [entry[0] for entry in entries]
    assert "tools/call" not in methods
    for entry in entries:
        with pytest.raises(ProcessLookupError):
            os.kill(int(entry[1]), 0)
    return methods


def denied_describe(tmp_path: Path, failure: str, **behaviour: str | dict) -> list[object]:
    call = fixture(tmp_path)[1]
    path, pin, log = scripted(tmp_path, **behaviour)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        with pytest.raises(AuthorizationError) as denied:
            session.describe("server:mail", "send")
        assert str(denied.value) == failure
        with pytest.raises(AuthorizationError, match="described session"):
            session.execute(call)
    return assert_reaped_without_a_call(log)


@pytest.mark.parametrize(
    "on_list",
    [
        "reply({'tools': [{'name': 't%d' % i} for i in range(4097)]})",
        "reply({'tools': 'send'})",
        "reply({})",
    ],
    ids=["too-many", "not-a-list", "absent"],
)
def test_an_oversized_or_invalid_tool_list_is_denied(tmp_path, on_list):
    denied_describe(tmp_path, "invalid or oversized MCP tool list", on_list=on_list)


@pytest.mark.parametrize("on_list", ["reply({'tools': ['send']})", "reply({'tools': [None]})"])
def test_a_tool_that_is_not_an_object_is_denied(tmp_path, on_list):
    denied_describe(tmp_path, "invalid MCP tool", on_list=on_list)


@pytest.mark.parametrize(
    "on_list",
    [
        f"reply({{'tools': [{DEFINITION!r}, {DEFINITION!r}]}})",
        "reply({'tools': [{'name': ''}]})",
        "reply({'tools': [{'description': 'unnamed'}]})",
        "reply({'tools': [{'name': 7}]})",
        "reply({'tools': [{'name': 'x' * 257}]})",
        "reply({'tools': [{'name': 'send\\x1b[0m'}]})",
    ],
    ids=["duplicate", "empty-name", "no-name", "non-string-name", "long-name", "control"],
)
def test_an_invalid_or_duplicate_tool_name_is_denied(tmp_path, on_list):
    denied_describe(tmp_path, BAD_NAME, on_list=on_list)


def test_a_duplicate_across_pages_is_denied_like_one_within_a_page(tmp_path):
    on_list = (
        f"if page == 1:\n    reply({{'tools': [{DEFINITION!r}], 'nextCursor': 'two'}})\n"
        f"else:\n    reply({{'tools': [{DEFINITION!r}]}})"
    )
    methods = denied_describe(tmp_path, BAD_NAME, on_list=on_list)
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
def test_an_invalid_or_repeated_cursor_is_denied(tmp_path, on_list):
    denied_describe(tmp_path, BAD_CURSOR, on_list=on_list)


def test_the_page_budget_ends_a_tool_list_that_never_finishes(tmp_path):
    on_list = "reply({'tools': [], 'nextCursor': 'page-%d' % page})"
    methods = denied_describe(tmp_path, "MCP page budget exceeded", on_list=on_list)
    assert methods.count("tools/list") == 64


@pytest.mark.parametrize(
    "hello",
    [
        {**STDIO_HELLO, "capabilities": {}},
        {**STDIO_HELLO, "capabilities": {"tools": "yes"}},
        {**STDIO_HELLO, "protocolVersion": "2099-01-01"},
        {**STDIO_HELLO, "serverInfo": {"name": "fixture"}},
        {**STDIO_HELLO, "serverInfo": {"name": "", "version": "1"}},
    ],
    ids=["no-tools", "tools-not-an-object", "protocol", "no-version", "empty-name"],
)
def test_a_handshake_without_the_tool_capability_denies_before_listing(tmp_path, hello):
    path, pin, log = scripted(tmp_path, hello=hello)
    with (
        pytest.raises(AuthorizationError, match="MCP tool capability not negotiated"),
        PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail"),
    ):
        pass
    assert assert_reaped_without_a_call(log) == ["started", "initialize"]


def test_a_tools_call_request_over_the_byte_limit_is_never_written(tmp_path):
    call = fixture(tmp_path)[1]
    oversized = call.model_copy(
        update={"arguments": {"to": "team@example.test", "body": "a" * MAX_REQUEST_BYTES}}
    )
    path, pin, log = scripted(tmp_path, on_list=SERVED)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        session.describe("server:mail", "send")
        with pytest.raises(ExecutionOutcomeUnknown) as outcome:
            session.execute(oversized)
    cause = outcome.value.__cause__
    assert isinstance(cause, AuthorizationError)
    assert str(cause) == "MCP request exceeds byte limit"
    assert assert_reaped_without_a_call(log) == [
        "started",
        "initialize",
        "notifications/initialized",
        "tools/list",
    ]


class _ZeroWrites:
    """``os`` as seen by the module under test, with every write accepting nothing."""

    def __getattr__(self, name: str):
        return getattr(os, name)

    def write(self, fd: int, data) -> int:
        return 0


def test_a_write_that_makes_no_progress_closes_the_session_and_reaps_the_process(
    tmp_path, monkeypatch
):
    path, pin, _ = scripted(tmp_path)
    started: list[subprocess.Popen[bytes]] = []
    popen = subprocess.Popen

    def record(*args, **kwargs):
        process = popen(*args, **kwargs)
        started.append(process)
        return process

    monkeypatch.setattr(live_session.subprocess, "Popen", record)
    monkeypatch.setattr(live_session, "os", _ZeroWrites())
    with (
        pytest.raises(AuthorizationError, match="MCP request stream closed"),
        PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail"),
    ):
        pass
    assert len(started) == 1 and started[0].returncode is not None
    with pytest.raises(ProcessLookupError):
        os.kill(started[0].pid, 0)


def test_an_exhausted_frame_source_is_a_missing_response(tmp_path):
    path, pin, log = scripted(tmp_path)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        session._inbound = iter(())
        with pytest.raises(AuthorizationError, match="missing MCP response"):
            session.describe("server:mail", "send")
    # The launcher is killed as soon as the lookup fails, so it may not have logged the
    # request it was reading.
    assert assert_reaped_without_a_call(log)[:2] == ["started", "initialize"]


def test_a_launcher_over_the_byte_budget_is_denied_before_it_is_read_or_run(tmp_path):
    # A sparse file: the size check reads st_size before any byte, so no 128 MiB is written.
    path = tmp_path / "huge-launcher"
    with path.open("wb") as stream:
        stream.truncate(128 * 1024 * 1024 + 1)
    pin = "sha256:" + hashlib.sha256(b"").hexdigest()
    with (
        pytest.raises(AuthorizationError, match="launcher exceeds byte budget"),
        PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail"),
    ):
        pass


@pytest.mark.parametrize(
    ("result", "accepted", "validation_reason"),
    [
        ({"structuredContent": {"count": 1}}, True, None),
        ({"structuredContent": {"count": "one"}}, False, "arguments-invalid"),
        ({"content": []}, False, None),
        ({"isError": True, "content": []}, True, None),
        ({"isError": "true", "content": []}, False, None),
        (
            {"structuredContent": {"count": 1, "text": "a" * MAX_ARGUMENT_BYTES}},
            False,
            None,
        ),
    ],
)
def test_stdio_checks_successful_structured_results(tmp_path, result, accepted, validation_reason):
    call = fixture(tmp_path)[1]
    schema = {
        "type": "object",
        "properties": {"count": {"type": "integer"}},
        "required": ["count"],
    }
    path, pin, log = launcher(tmp_path, output_schema=schema, tool_result=result)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        session.describe("server:mail", "send")
        if accepted:
            assert session.execute(call) == result
        else:
            with pytest.raises(ExecutionOutcomeUnknown) as failure:
                session.execute(call)
            if validation_reason is not None:
                cause = failure.value.__cause__
                assert isinstance(cause, ValidationBudgetError)
                assert cause.reason == validation_reason
                assert "output schema" in str(cause)
    assert sum(record[0] == "tools/call" for record in launcher_log(log)) == 1
