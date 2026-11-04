"""One pinned stdio process for descriptor observation and authorized tool calls.

The launcher must be independently approved by the operator. This module does
not sandbox the process, authenticate the workload, or prove backend behavior.
"""

from __future__ import annotations

import hashlib
import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Any, TypeVar

from nexus_symbiote.core.hashing import open_regular_file
from nexus_symbiote.live.stdio import (
    DEADLINE_SECONDS,
    MAX_TOOLS,
    PROTOCOL,
    _frames,
    _ready,
    spawn_staged,
)
from nexus_symbiote.runtime import (
    AuthorizationError,
    Envelope,
    ReferenceGateway,
    ServedTool,
    ToolCall,
    canonical_bytes,
)

T = TypeVar("T")


class PinnedStdioSession:
    """Single-use MCP session. One live process handles list and call.

    The pin covers launcher bytes only. Interpreter, shared libraries, mutable
    files, network and server behavior remain in the operator's trust boundary.
    """

    def __init__(self, *, command: str, sha256: str, server_id: str) -> None:
        if (
            os.name != "posix"
            or not Path(command).is_absolute()
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", sha256)
            or not server_id
        ):
            raise AuthorizationError("absolute POSIX launcher, SHA-256 pin and server ID required")
        self.command = command
        self.sha256 = sha256
        self.server_id = server_id
        self.endpoint_identity = "stdio+launcher:" + sha256
        self._directory: tempfile.TemporaryDirectory[str] | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._deadline = 0.0
        self._next_id = 1
        self._lookup_attempted = False
        self._described: str | None = None
        self._called = False
        self._used = False

    def __enter__(self) -> PinnedStdioSession:
        if self._directory is not None or self._used:
            raise AuthorizationError("session cannot be reused")
        self._used = True
        self._directory = tempfile.TemporaryDirectory(prefix="nexus-runtime-")
        work = Path(self._directory.name)
        staged = work / "server"
        try:
            hasher = hashlib.sha256()
            budget = 128 * 1024 * 1024
            with open_regular_file(Path(self.command)) as source, staged.open("xb") as out:
                if os.fstat(source.fileno()).st_size > budget:
                    raise AuthorizationError("launcher exceeds byte budget")
                while chunk := source.read(1024 * 1024):
                    budget -= len(chunk)
                    if budget < 0:
                        raise AuthorizationError("launcher exceeds byte budget")
                    hasher.update(chunk)
                    out.write(chunk)
            if self.sha256 != "sha256:" + hasher.hexdigest():
                raise AuthorizationError("launcher differs from approved digest")
            staged.chmod(0o500)
            self._process = spawn_staged(staged, work)
            assert self._process.stdin is not None and self._process.stdout is not None
            os.set_blocking(self._process.stdin.fileno(), False)
            os.set_blocking(self._process.stdout.fileno(), False)
            self._deadline = time.monotonic() + DEADLINE_SECONDS
            self._inbound = _frames(self._process.stdout.fileno(), self._deadline)
            hello = self._request(
                "initialize",
                {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {"name": "nexus-symbiote-runtime", "version": "1"},
                },
            )
            if (
                hello.get("protocolVersion") != PROTOCOL
                or not isinstance(hello.get("capabilities"), dict)
                or not isinstance(hello["capabilities"].get("tools"), dict)
                or not isinstance(hello.get("serverInfo"), dict)
                or not all(
                    isinstance(hello["serverInfo"].get(key), str) and bool(hello["serverInfo"][key])
                    for key in ("name", "version")
                )
            ):
                raise AuthorizationError("MCP tool capability not negotiated")
            self._send({"method": "notifications/initialized"})
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def _send(self, message: dict[str, Any]) -> None:
        proc = self._process
        # Do not poll/reap before cleanup: keeping the child waitable prevents
        # PID reuse before killpg, including when the server exits early.
        if proc is None or proc.stdin is None:
            raise AuthorizationError("pinned session is closed")
        payload = memoryview(canonical_bytes({"jsonrpc": "2.0", **message}) + b"\n")
        if len(payload) > 1024 * 1024:
            raise AuthorizationError("MCP request exceeds byte limit")
        while payload:
            _ready(proc.stdin.fileno(), selectors.EVENT_WRITE, self._deadline)
            try:
                written = os.write(proc.stdin.fileno(), payload)
            except BlockingIOError:
                continue
            if written <= 0:
                raise AuthorizationError("MCP request stream closed")
            payload = payload[written:]

    def _request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        request_id = self._next_id
        self._next_id += 1
        self._send({"id": request_id, "method": method, "params": params})
        msg = next(self._inbound)
        if (
            set(msg) != {"jsonrpc", "id", "result"}
            or type(msg.get("id")) is not int
            or msg["id"] != request_id
            or not isinstance(msg.get("result"), dict)
        ):
            raise AuthorizationError("unexpected MCP response or notification")
        return msg["result"]  # type: ignore[no-any-return]

    def describe(self, server_id: str, tool_name: str) -> ServedTool:
        if server_id != self.server_id or self._lookup_attempted:
            raise AuthorizationError("session server mismatch or repeated descriptor lookup")
        self._lookup_attempted = True
        tools: dict[str, dict[str, Any]] = {}
        cursors: set[str] = set()
        params: dict[str, Any] = {}
        for _ in range(64):
            result = self._request("tools/list", params)
            items = result.get("tools")
            if not isinstance(items, list) or len(tools) + len(items) > MAX_TOOLS:
                raise AuthorizationError("invalid or oversized MCP tool list")
            for item in items:
                if not isinstance(item, dict):
                    raise AuthorizationError("invalid MCP tool")
                name = item.get("name")
                if (
                    not isinstance(name, str)
                    or not name
                    or len(name) > 256
                    or not name.isprintable()
                    or name in tools
                ):
                    raise AuthorizationError("invalid or duplicate MCP tool name")
                tools[name] = item
            if "nextCursor" not in result:
                if tool_name not in tools:
                    raise AuthorizationError("approved tool missing from session")
                self._described = tool_name
                return ServedTool(
                    endpoint_identity=self.endpoint_identity, definition=tools[tool_name]
                )
            cursor = result["nextCursor"]
            if (
                not isinstance(cursor, str)
                or not cursor
                or len(cursor.encode()) > 256
                or cursor in cursors
            ):
                raise AuthorizationError("invalid MCP pagination cursor")
            cursors.add(cursor)
            params = {"cursor": cursor}
        raise AuthorizationError("MCP page budget exceeded")

    def execute(self, call: ToolCall) -> dict[str, Any]:
        if (
            self._described is None
            or call.server_id != self.server_id
            or call.tool_name != self._described
            or self._called
        ):
            raise AuthorizationError("call does not match the described session")
        self._called = True
        return self._request("tools/call", {"name": call.tool_name, "arguments": call.arguments})

    def __exit__(self, *_: object) -> None:
        proc = self._process
        self._process = None
        try:
            if proc is not None:
                try:
                    try:
                        os.killpg(proc.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        # The process group already exited; wait() still reaps it.
                        pass
                    proc.wait(timeout=5)
                finally:
                    if proc.stdin is not None:
                        proc.stdin.close()
                    if proc.stdout is not None:
                        proc.stdout.close()
        finally:
            if self._directory is not None:
                self._directory.cleanup()
                self._directory = None


def invoke_pinned_stdio(
    gateway: ReferenceGateway[T],
    call: ToolCall,
    *,
    command: str,
    sha256: str,
    snapshot: Envelope,
    trust: Envelope,
    bom: Mapping[str, Any],
    approval: Envelope | None = None,
) -> dict[str, Any]:
    """Authorize and execute via the same pinned launcher process, never reconnecting."""
    with PinnedStdioSession(command=command, sha256=sha256, server_id=call.server_id) as session:
        bound: ReferenceGateway[dict[str, Any]] = ReferenceGateway(
            snapshot_keys=gateway.snapshot_keys,
            approval_keys=gateway.approval_keys,
            trust_keys=gateway.trust_keys,
            state=gateway.state,
            authenticate=gateway.authenticate,
            describe=session.describe,
            resolve_scope=gateway.resolve_scope,
            execute=session.execute,
            approval_actors=gateway.approval_actors,
            clock=gateway.clock,
            snapshot_threshold=gateway.snapshot_threshold,
            approval_threshold=gateway.approval_threshold,
            trust_threshold=gateway.trust_threshold,
        )
        return bound.invoke(call, snapshot=snapshot, trust=trust, bom=bom, approval=approval)
