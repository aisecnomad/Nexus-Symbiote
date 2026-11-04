"""Capture descriptors from an independently pinned, single-file POSIX launcher."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import tempfile
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict

PROTOCOL = "2025-06-18"
MAX_LINE = 1024 * 1024
MAX_BYTES = 8 * MAX_LINE
MAX_TOOLS = 4096
DEADLINE_SECONDS = 20.0
# Bounded backoff (about 0.4 s in total) for a staged copy the kernel reports busy.
EXEC_BUSY_RETRY_DELAYS = (0.001, 0.002, 0.005, 0.01, 0.02, 0.05, 0.1, 0.2)


def spawn_staged(binary: Path, work: Path) -> subprocess.Popen[bytes]:
    """Start the private launcher copy without a shell, environment or terminal.

    A process forked by any other thread while the copy's write descriptor was
    open holds a duplicate of it until that child execs or closes it, and Linux
    refuses to execute a file that is open for writing (ETXTBSY). The refused
    exec ran nothing, so only that refusal is retried, briefly, on the same
    private copy; every other error propagates unchanged.
    """
    delays = iter(EXEC_BUSY_RETRY_DELAYS)
    while True:
        try:
            # The executable is the private copy checked against the operator digest.
            return subprocess.Popen(  # noqa: S603
                [str(binary)],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                cwd=work,
                env={"PATH": os.defpath},
                start_new_session=True,
                bufsize=0,
            )
        except OSError as exc:
            delay = next(delays, None)
            if exc.errno != errno.ETXTBSY or delay is None:
                raise
        time.sleep(delay)


def strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _ready(fd: int, event: int, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OSError("MCP session deadline exceeded")
    with selectors.DefaultSelector() as selector:
        selector.register(fd, event)
        if not selector.select(remaining):
            raise OSError("MCP session deadline exceeded")


def _frames(fd: int, deadline: float) -> Iterator[dict[str, Any]]:
    buf = bytearray()
    total = 0
    for _ in range(1024):
        if time.monotonic() >= deadline:
            raise OSError("MCP session deadline exceeded")
        while b"\n" not in buf:
            if len(buf) > MAX_LINE:
                raise ValueError("MCP frame exceeds size limit")
            _ready(fd, selectors.EVENT_READ, deadline)
            try:
                chunk = os.read(fd, 65536)
            except BlockingIOError:
                continue
            total += len(chunk)
            if not chunk or total > MAX_BYTES:
                raise ValueError("MCP stream ended or exceeded its byte limit")
            buf.extend(chunk)
        raw, _, buf = buf.partition(b"\n")
        if len(raw) > MAX_LINE:
            raise ValueError("MCP frame exceeds size limit")
        message = parse_json_strict(bytes(raw), max_bytes=MAX_LINE)
        if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
            raise ValueError("invalid JSON-RPC envelope")
        yield message
    raise ValueError("MCP frame budget exceeded")


def _capture(binary: Path, work: Path) -> list[dict[str, Any]]:
    # Executable is the private copy checked against the operator digest in list_pinned_tools.
    with spawn_staged(binary, work) as proc:
        assert proc.stdin is not None and proc.stdout is not None
        inbox = proc.stdin.fileno()
        deadline = time.monotonic() + DEADLINE_SECONDS
        frames = _frames(proc.stdout.fileno(), deadline)

        def send(message: dict[str, Any]) -> None:
            data = memoryview(json.dumps({"jsonrpc": "2.0", **message}).encode() + b"\n")
            while data:
                _ready(inbox, selectors.EVENT_WRITE, deadline)
                try:
                    written = os.write(inbox, data)
                except BlockingIOError:
                    continue
                if written <= 0:
                    raise OSError("MCP input stream closed")
                data = data[written:]

        def call(request_id: int, method: str, params: dict[str, Any]) -> dict[str, Any]:
            send({"id": request_id, "method": method, "params": params})
            for msg in frames:
                if "id" not in msg and isinstance(msg.get("method"), str):
                    continue
                if (
                    set(msg) != {"jsonrpc", "id", "result"}
                    or type(msg.get("id")) is not int
                    or msg["id"] != request_id
                ):
                    raise ValueError("unexpected MCP response")
                result = msg.get("result")
                if not isinstance(result, dict):
                    raise ValueError("invalid MCP result")
                return result
            raise ValueError("missing MCP response")

        try:
            os.set_blocking(inbox, False)
            os.set_blocking(proc.stdout.fileno(), False)
            hello = call(
                1,
                "initialize",
                {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {"name": "nexus-symbiote", "version": "1"},
                },
            )
            if hello.get("protocolVersion") != PROTOCOL:
                raise ValueError("unsupported MCP protocol version")
            capabilities, info = hello.get("capabilities"), hello.get("serverInfo")
            if (
                not isinstance(capabilities, dict)
                or not isinstance(capabilities.get("tools"), dict)
                or not isinstance(info, dict)
                or not all(isinstance(info.get(k), str) for k in ("name", "version"))
            ):
                raise ValueError("MCP tool listing was not negotiated")
            send({"method": "notifications/initialized"})
            tools: list[dict[str, Any]] = []
            names: set[str] = set()
            cursors: set[str] = set()
            params: dict[str, Any] = {}
            for page in range(64):
                result = call(page + 2, "tools/list", params)
                items = result.get("tools")
                if not isinstance(items, list) or len(tools) + len(items) > MAX_TOOLS:
                    raise ValueError("invalid or oversized MCP tool list")
                for tool in items:
                    if not isinstance(tool, dict):
                        raise ValueError("invalid MCP tool")
                    name = tool.get("name")
                    if (
                        not isinstance(name, str)
                        or not name
                        or len(name) > 256
                        or not name.isprintable()
                        or name in names
                        or not isinstance(tool.get("inputSchema"), dict)
                    ):
                        raise ValueError("invalid or duplicate MCP tool")
                    names.add(name)
                    tools.append(tool)
                if "nextCursor" not in result:
                    return tools
                cursor = result["nextCursor"]
                if (
                    not isinstance(cursor, str)
                    or not cursor
                    or len(cursor.encode()) > 256
                    or cursor in cursors
                ):
                    raise ValueError("invalid MCP pagination cursor")
                cursors.add(cursor)
                params = {"cursor": cursor}
            raise ValueError("MCP page budget exceeded")
        finally:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


def list_pinned_tools(command: str, digest: str) -> list[dict[str, Any]]:
    """Execute only a private copy of the exact bytes selected by operator policy."""
    if (
        os.name != "posix"
        or not Path(command).is_absolute()
        or not re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
    ):
        raise OSError("expected an absolute POSIX executable and its SHA-256 pin")
    with tempfile.TemporaryDirectory(prefix="nexus-live-") as directory:
        work = Path(directory)
        staged = work / "server"
        hasher = hashlib.sha256()
        budget = 128 * 1024 * 1024
        with open_regular_file(Path(command)) as source, staged.open("xb") as out:
            if os.fstat(source.fileno()).st_size > budget:
                raise OSError("launcher exceeds byte budget")
            while chunk := source.read(1024 * 1024):
                budget -= len(chunk)
                if budget < 0:
                    raise OSError("launcher exceeds byte budget")
                hasher.update(chunk)
                out.write(chunk)
        if digest != "sha256:" + hasher.hexdigest():
            raise OSError("launcher differs from approved digest")
        staged.chmod(0o500)
        return _capture(staged, work)
