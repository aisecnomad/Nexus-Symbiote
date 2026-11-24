"""One pinned stdio process for descriptor observation and authorized tool calls.

The launcher must be independently approved by the operator. By default a kernel
PID namespace is required before execution. An explicit operator isolation_off()
context accepts best-effort cleanup in an independently isolated worker instead, on
Linux only; elsewhere it is refused before execution.
Neither mode is a filesystem or network sandbox, and it does not authenticate the
workload or prove backend behavior.

Once ``tools/call`` has been written, a failure is never reported as an
authorization denial: a JSON-RPC error reply raises ``ToolCallError`` and any
other failure raises ``ExecutionOutcomeUnknown``, because the tool may have run
and the one-use approval has been spent.
"""

from __future__ import annotations

import os
import re
import selectors
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Mapping
from contextlib import ExitStack, suppress
from copy import deepcopy
from pathlib import Path
from typing import Any, TypeVar

from nexus_symbiote.live.pinned_process import (
    PinnedProcessError,
    spawn_pinned,
    stage_pinned_executable,
    terminate_process_group,
)
from nexus_symbiote.live.stdio import DEADLINE_SECONDS, MAX_TOOLS, PROTOCOL, _frames, _ready
from nexus_symbiote.runtime import (
    REASONS,
    AuthorizationError,
    Decision,
    Envelope,
    ReferenceGateway,
    ServedTool,
    ToolCall,
    canonical_bytes,
)
from nexus_symbiote.runtime_validation import (
    MAX_ARGUMENT_BYTES,
    MAX_SCHEMA_BYTES,
    ValidationBudgetError,
    check_json_budget,
    prepare_output_validation,
)
from nexus_symbiote.scanners.live_mcp import SUPPORTED_PROTOCOL_VERSIONS

T = TypeVar("T")
# Room for the JSON-RPC envelope and tool name, so every argument set the gateway
# admits fits in one tools/call request.
MAX_REQUEST_BYTES = MAX_ARGUMENT_BYTES + 64 * 1024


class ExecutionOutcomeUnknown(Exception):  # noqa: N818 - the name states the outcome, not a fault
    """``tools/call`` was sent but no valid reply arrived; the tool may have run."""


class ToolCallError(Exception):
    """The server answered ``tools/call`` with a JSON-RPC error object."""

    def __init__(self, code: int | None) -> None:
        super().__init__("MCP server answered tools/call with a JSON-RPC error")
        self.code = code


class PinnedStdioSession:
    """Single-use MCP session. One live process handles list and call.

    The pin covers launcher bytes only. Interpreter, shared libraries, mutable
    files, network and server behavior remain in the operator's trust boundary.
    The handshake and listing share one deadline; ``tools/call`` gets its own
    ``call_deadline_seconds``, counted from when the call is sent.
    """

    def __init__(
        self,
        *,
        command: str,
        sha256: str,
        server_id: str,
        call_deadline_seconds: float = DEADLINE_SECONDS,
    ) -> None:
        if (
            os.name != "posix"
            or not Path(command).is_absolute()
            or not re.fullmatch(r"sha256:[0-9a-f]{64}", sha256)
            or not server_id
            or not 0 < call_deadline_seconds <= 3600
        ):
            raise AuthorizationError("absolute POSIX launcher, SHA-256 pin and server ID required")
        self.command = command
        self.sha256 = sha256
        self.server_id = server_id
        self.endpoint_identity = "stdio+launcher:" + sha256
        self._directory: tempfile.TemporaryDirectory[str] | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._deadline = 0.0
        self._call_deadline_seconds = call_deadline_seconds
        self._next_id = 1
        self._lookup_attempted = False
        self._described: str | None = None
        self._output_schema: Any = None
        self._validate_output: Callable[[dict[str, Any]], None] | None = None
        self._called = False
        self._used = False

    def __enter__(self) -> PinnedStdioSession:
        if self._directory is not None or self._used:
            raise AuthorizationError("session cannot be reused")
        self._used = True
        self._directory = tempfile.TemporaryDirectory(prefix="nexus-runtime-")
        work = Path(self._directory.name)
        try:
            staged = stage_pinned_executable(self.command, self.sha256, work)
            self._process = spawn_pinned(staged, work)
            assert self._process.stdin is not None and self._process.stdout is not None
            os.set_blocking(self._process.stdin.fileno(), False)
            os.set_blocking(self._process.stdout.fileno(), False)
            self._deadline = time.monotonic() + DEADLINE_SECONDS
            self._inbound = _frames(self._process.stdout.fileno(), lambda: self._deadline)
            hello = self._request(
                "initialize",
                {
                    "protocolVersion": PROTOCOL,
                    "capabilities": {},
                    "clientInfo": {"name": "nexus-symbiote-runtime", "version": "1"},
                },
            )
            if (
                hello.get("protocolVersion") not in SUPPORTED_PROTOCOL_VERSIONS
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
        except PinnedProcessError as exc:
            self.__exit__(None, None, None)
            reason = exc.reason if exc.reason in REASONS else "denied"
            raise AuthorizationError(str(exc), reason=reason) from exc
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
        if len(payload) > MAX_REQUEST_BYTES:
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
        # Log and progress notifications may precede the reply; _frames bounds
        # how many frames and bytes they can take.
        for msg in self._inbound:
            if "id" not in msg and isinstance(msg.get("method"), str):
                continue
            if (
                method == "tools/call"
                and set(msg) == {"jsonrpc", "id", "error"}
                and type(msg.get("id")) is int
                and msg["id"] == request_id
            ):
                error = msg["error"]
                code = error.get("code") if isinstance(error, dict) else None
                raise ToolCallError(code if type(code) is int else None)
            if (
                set(msg) != {"jsonrpc", "id", "result"}
                or type(msg.get("id")) is not int
                or msg["id"] != request_id
                or not isinstance(msg.get("result"), dict)
            ):
                raise AuthorizationError("unexpected MCP response")
            return msg["result"]  # type: ignore[no-any-return]
        raise AuthorizationError("missing MCP response")

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
            cursor = result.get("nextCursor")
            if cursor is None:
                if tool_name not in tools:
                    raise AuthorizationError("approved tool missing from session")
                definition = tools[tool_name]
                schema = definition.get("outputSchema")
                if schema is not None:
                    try:
                        check_json_budget(schema, maximum=MAX_SCHEMA_BYTES)
                    except ValidationBudgetError as exc:
                        reason = (
                            "descriptor-too-large"
                            if exc.reason == "json-budget-exceeded"
                            else "descriptor-not-json"
                        )
                        raise AuthorizationError(
                            "MCP output schema is outside the supported JSON budget", reason=reason
                        ) from None
                    self._output_schema = deepcopy(schema)
                self._described = tool_name
                return ServedTool(endpoint_identity=self.endpoint_identity, definition=definition)
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

    def _prepare_output(self, schema: Any, stack: ExitStack) -> None:
        if schema is not None and self._validate_output is None:
            try:
                self._validate_output = stack.enter_context(prepare_output_validation(schema))
            except ValidationBudgetError as exc:
                raise AuthorizationError(
                    "MCP output schema validation could not be prepared", reason=exc.reason
                ) from None

    def execute(self, call: ToolCall) -> dict[str, Any]:
        if (
            self._described is None
            or call.server_id != self.server_id
            or call.tool_name != self._described
            or self._called
        ):
            raise AuthorizationError("call does not match the described session")
        with ExitStack() as stack:
            self._prepare_output(self._output_schema, stack)
            return self._dispatch(call)

    def _dispatch(self, call: ToolCall) -> dict[str, Any]:
        self._called = True
        self._deadline = time.monotonic() + self._call_deadline_seconds
        try:
            result = self._request(
                "tools/call", {"name": call.tool_name, "arguments": call.arguments}
            )
            validate_output = self._validate_output
            if validate_output is None:
                return result
            is_error = result.get("isError", False)
            if not isinstance(is_error, bool):
                raise ValueError("MCP tool result has an invalid error flag")
            if not is_error:
                structured = result.get("structuredContent")
                if not isinstance(structured, dict):
                    raise ValueError("MCP tool result lacks structured content")
                try:
                    validate_output(structured)
                except ValidationBudgetError as exc:
                    raise ValidationBudgetError(
                        "MCP structured result failed offline output schema validation",
                        reason=exc.reason,
                    ) from None
            return result
        except ToolCallError:
            raise
        except Exception as exc:
            raise ExecutionOutcomeUnknown(
                "tools/call was sent but no valid result arrived; the tool may have run"
            ) from exc

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        *_: object,
    ) -> None:
        proc = self._process
        self._process = None
        teardown: Exception | None = None
        try:
            if proc is not None:
                try:
                    try:
                        confirmed = terminate_process_group(proc)
                        if sys.platform.startswith("linux") and self._called and confirmed is False:
                            teardown = PinnedProcessError(
                                "isolation-teardown-failed",
                                "pinned MCP launcher process group teardown could not be verified",
                            )
                    except Exception as err:
                        teardown = err
                finally:
                    try:
                        proc.wait(timeout=5)
                    except subprocess.TimeoutExpired as err:
                        with suppress(ProcessLookupError, PermissionError):
                            proc.kill()
                        with suppress(subprocess.TimeoutExpired):
                            proc.wait(timeout=1)
                        if teardown is None:
                            teardown = err
                    finally:
                        if proc.stdin is not None:
                            proc.stdin.close()
                        if proc.stdout is not None:
                            proc.stdout.close()
        finally:
            if self._directory is not None:
                try:
                    self._directory.cleanup()
                except OSError as err:
                    if teardown is None:
                        teardown = err
                finally:
                    self._directory = None
        if teardown is None:
            return
        if self._called:
            if isinstance(exc, ExecutionOutcomeUnknown) and not isinstance(
                teardown, PinnedProcessError
            ):
                return
            raise ExecutionOutcomeUnknown(
                "the launcher's processes could not be confirmed ended; "
                "the tool may still be running"
                if isinstance(teardown, PinnedProcessError)
                else "launcher cleanup did not complete; the tool may still be running"
            ) from teardown
        if isinstance(teardown, PinnedProcessError):
            if exc is not None and not isinstance(exc, Exception):
                # An interrupt or an exit is not replaced by an error a caller's loop
                # catches; the teardown failure rides along as a note.
                exc.add_note(f"launcher teardown failed: {teardown}")
                return
            raise AuthorizationError(str(teardown), reason=teardown.reason) from teardown
        if exc is not None:
            exc.add_note(f"launcher cleanup failed: {teardown}")
            return
        raise teardown


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
    call_deadline_seconds: float = DEADLINE_SECONDS,
) -> dict[str, Any]:
    """Authorize and execute via the same pinned launcher process, never reconnecting.

    Raises ``AuthorizationError`` only before ``tools/call`` is sent. After that,
    ``ToolCallError`` reports a JSON-RPC error reply and ``ExecutionOutcomeUnknown``
    any other failure. Neither is a denial: the approval has been spent, and an
    unknown outcome means the tool may have run. The launcher is staged and started,
    and the ``initialize`` handshake completed, only when the gateway asks for the
    served descriptor, after the trust status, snapshot, workload context, companion
    BOM, scope and grant have been checked. A launcher that cannot be staged or
    started, or a failed handshake, is then reported by the gateway as a failing
    ``describe`` adapter: ``AuthorizationError`` with its reason, anything else as
    ``adapter-error``. Invalid launcher settings are refused before the gateway runs.
    """
    try:
        session = PinnedStdioSession(
            command=command,
            sha256=sha256,
            server_id=call.server_id,
            call_deadline_seconds=call_deadline_seconds,
        )
    except Exception as exc:
        reason = exc.reason if isinstance(exc, AuthorizationError) else "adapter-error"
        if gateway.on_decision is not None:
            gateway.on_decision(
                Decision(
                    admitted=False,
                    reason=reason,
                    time=gateway.clock(),
                    server_id=call.server_id,
                    tool_name=call.tool_name,
                    action=call.action,
                    resource=call.resource,
                    store_id=getattr(gateway.state, "store_id", None),
                )
            )
        raise
    with ExitStack() as stack:
        # Starting the launcher lazily keeps a caller whose trust status or snapshot
        # fails verification from running it at all (audit 2026-11-14 L25). The
        # approval is checked after the descriptor (verification order step 9), so a
        # caller holding a valid snapshot and trust status still starts it.
        def describe(server_id: str, tool_name: str) -> ServedTool:
            return stack.enter_context(session).describe(server_id, tool_name)

        def prepare(definition: Mapping[str, Any]) -> None:
            # The gateway has verified this exact definition and has yet to record consent.
            session._prepare_output(definition.get("outputSchema"), stack)

        bound = gateway.bind_adapters(describe=describe, prepare=prepare, execute=session.execute)
        return bound.invoke(call, snapshot=snapshot, trust=trust, bom=bom, approval=approval)
