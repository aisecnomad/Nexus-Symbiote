"""Capture descriptors from an independently pinned, single-file POSIX launcher."""

from __future__ import annotations

import contextlib
import json
import os
import selectors
import subprocess
import tempfile
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.live.pinned_process import (
    PinnedProcessError,
    spawn_pinned,
    stage_pinned_executable,
    terminate_process_group,
)
from nexus_symbiote.scanners.live_mcp import (
    PROTOCOL_VERSION,
    SUPPORTED_PROTOCOL_VERSIONS,
    is_method_not_found,
)

PROTOCOL = PROTOCOL_VERSION
MAX_LINE = 1024 * 1024
MAX_BYTES = 8 * MAX_LINE
MAX_TOOLS = 4096
DEADLINE_SECONDS = 20.0


class LaunchPolicyError(OSError):
    """The operator launch policy or the pinned launcher cannot be used."""

    def __init__(self, reason: str, message: str) -> None:
        super().__init__(message)
        self.reason = reason


class SessionDeadlineError(OSError):
    """The bounded MCP exchange did not finish before its deadline."""

    reason = "deadline"


class StdioProtocolError(ValueError):
    """The pinned server's MCP messages were invalid or exceeded protocol limits."""

    def __init__(self, message: str, *, reason: str = "protocol") -> None:
        super().__init__(message)
        self.reason = reason


@dataclass
class PinnedObservation:
    """Raw initialize result and list responses of one pinned stdio session."""

    hello: dict[str, Any]
    tools: list[dict[str, Any]]
    prompts: list[dict[str, Any]] | None = None
    resource_templates: list[dict[str, Any]] | None = None
    launcher_sha256: str | None = field(default=None)
    teardown_confirmed: bool = False


def _ready(fd: int, event: int, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SessionDeadlineError("MCP session deadline exceeded")
    with selectors.DefaultSelector() as selector:
        selector.register(fd, event)
        if not selector.select(remaining):
            raise SessionDeadlineError("MCP session deadline exceeded")


def _frames(fd: int, deadline: Callable[[], float]) -> Iterator[dict[str, Any]]:
    """Yield JSON-RPC frames; ``deadline`` is read on every wait so a caller can renew it."""
    buf = bytearray()
    total = 0
    for _ in range(1024):
        if time.monotonic() >= deadline():
            raise SessionDeadlineError("MCP session deadline exceeded")
        while b"\n" not in buf:
            if len(buf) > MAX_LINE:
                raise StdioProtocolError("MCP frame exceeds size limit")
            _ready(fd, selectors.EVENT_READ, deadline())
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            total += len(chunk)
            if not chunk or total > MAX_BYTES:
                raise StdioProtocolError("MCP stream ended or exceeded its byte limit")
            buf.extend(chunk)
        raw, _, buf = buf.partition(b"\n")
        if len(raw) > MAX_LINE:
            raise StdioProtocolError("MCP frame exceeds size limit")
        try:
            message = parse_json_strict(bytes(raw), max_bytes=MAX_LINE)
        except (ValueError, RecursionError) as exc:
            raise StdioProtocolError("invalid JSON-RPC frame") from exc
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise StdioProtocolError("invalid JSON-RPC envelope")
        yield message
    raise StdioProtocolError("MCP frame budget exceeded")


def _capture(binary: Path, work: Path) -> PinnedObservation:
    # Executable is the private copy checked against the operator digest in observe_pinned.
    try:
        proc = spawn_pinned(binary, work)
    except PinnedProcessError as exc:
        raise LaunchPolicyError(exc.reason, str(exc)) from exc
    assert proc.stdin is not None and proc.stdout is not None
    try:
        inbox = proc.stdin.fileno()
        deadline = time.monotonic() + DEADLINE_SECONDS
        frames = _frames(proc.stdout.fileno(), lambda: deadline)
        next_id = 0

        def send(message: dict[str, Any]) -> None:
            data = memoryview(json.dumps({"jsonrpc": "2.0", **message}).encode() + b"\n")
            while data:
                _ready(inbox, selectors.EVENT_WRITE, deadline)
                try:
                    written = os.write(inbox, data)
                except BlockingIOError:
                    continue
                except BrokenPipeError as exc:
                    raise StdioProtocolError("MCP input stream closed") from exc
                if written <= 0:
                    raise StdioProtocolError("MCP input stream closed")
                data = data[written:]

        def call(
            method: str, params: dict[str, Any], *, optional: bool = False
        ) -> dict[str, Any] | None:
            """One request; with ``optional``, a -32601 reply returns None (not offered)."""
            nonlocal next_id
            next_id += 1
            send({"id": next_id, "method": method, "params": params})
            for msg in frames:
                if "id" not in msg and isinstance(msg.get("method"), str):
                    continue
                if optional and msg.get("id") == next_id and is_method_not_found(msg):
                    return None
                if (
                    set(msg) != {"jsonrpc", "id", "result"}
                    or type(msg.get("id")) is not int
                    or msg["id"] != next_id
                ):
                    raise StdioProtocolError("unexpected MCP response")
                result = msg.get("result")
                if not isinstance(result, dict):
                    raise StdioProtocolError("invalid MCP result")
                return result
            raise StdioProtocolError("missing MCP response")

        def listing(method: str, key: str, identity: str) -> list[dict[str, Any]] | None:
            """A paginated list, or None when the server does not implement ``method``."""
            items: list[dict[str, Any]] = []
            seen: set[str] = set()
            cursors: set[str] = set()
            params: dict[str, Any] = {}
            for _ in range(64):
                result = call(method, params, optional=method != "tools/list" and not params)
                if result is None:
                    return None
                values = result.get(key)
                if not isinstance(values, list) or len(items) + len(values) > MAX_TOOLS:
                    raise StdioProtocolError("invalid or oversized MCP list")
                for value in values:
                    name = value.get(identity) if isinstance(value, dict) else None
                    if (
                        not isinstance(name, str)
                        or not name
                        or len(name) > 2048
                        or not name.isprintable()
                        or name in seen
                    ):
                        raise StdioProtocolError("invalid or duplicate MCP list entry")
                    seen.add(name)
                    items.append(value)
                cursor = result.get("nextCursor")
                if cursor is None:
                    return items
                if (
                    not isinstance(cursor, str)
                    or not cursor
                    or len(cursor.encode()) > 256
                    or cursor in cursors
                ):
                    raise StdioProtocolError("invalid MCP pagination cursor")
                cursors.add(cursor)
                params = {"cursor": cursor}
            raise StdioProtocolError("MCP page budget exceeded")

        os.set_blocking(inbox, False)
        os.set_blocking(proc.stdout.fileno(), False)
        hello = call(
            "initialize",
            {
                "protocolVersion": PROTOCOL,
                "capabilities": {},
                "clientInfo": {"name": "nexus-symbiote", "version": "1"},
            },
        )
        if hello is None or hello.get("protocolVersion") not in SUPPORTED_PROTOCOL_VERSIONS:
            raise StdioProtocolError(
                "unsupported MCP protocol version", reason="unsupported-protocol-version"
            )
        capabilities = hello.get("capabilities")
        if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
            raise StdioProtocolError("MCP tool listing was not negotiated")
        send({"method": "notifications/initialized"})
        tools = listing("tools/list", "tools", "name")
        if tools is None:
            raise StdioProtocolError("MCP tool listing was not negotiated")
        observation = PinnedObservation(hello, tools)
        if isinstance(capabilities.get("prompts"), dict):
            observation.prompts = listing("prompts/list", "prompts", "name")
        if isinstance(capabilities.get("resources"), dict):
            observation.resource_templates = listing(
                "resources/templates/list", "resourceTemplates", "uriTemplate"
            )
    finally:
        try:
            try:
                teardown_confirmed = terminate_process_group(proc)
            except PinnedProcessError as exc:
                raise LaunchPolicyError(exc.reason, str(exc)) from exc
        finally:
            with contextlib.suppress(OSError):
                proc.stdin.close()
            with contextlib.suppress(OSError):
                proc.stdout.close()
            with contextlib.suppress(subprocess.TimeoutExpired):
                proc.wait(timeout=5.0)
    observation.teardown_confirmed = teardown_confirmed
    return observation


def observe_pinned(command: str, digest: str) -> PinnedObservation:
    """Execute only a private copy of the exact bytes selected by operator policy."""
    with tempfile.TemporaryDirectory(prefix="nexus-live-") as directory:
        work = Path(directory)
        try:
            staged = stage_pinned_executable(command, digest, work)
        except PinnedProcessError as exc:
            raise LaunchPolicyError(exc.reason, str(exc)) from exc
        observation = _capture(staged, work)
        observation.launcher_sha256 = digest
        return observation


def list_pinned_tools(command: str, digest: str) -> list[dict[str, Any]]:
    """Execute only a private copy of the exact bytes selected by operator policy."""
    return observe_pinned(command, digest).tools
