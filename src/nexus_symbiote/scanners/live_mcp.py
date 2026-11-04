"""Opt-in, bounded HTTP MCP descriptor discovery; never invokes tools.

Implements the 2025-06-18 initialize/initialized/tools-list lifecycle for JSON
and bounded SSE responses. This is a point-in-time observation, not authorization
or a claim about server safety. Discovery itself sends authenticated requests to
an explicitly allowed service. stdio, redirects, proxying, roots, sampling,
elicitation, tool calls, resource retrieval and automatic retries are unsupported.

Protocol sources:
https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
https://modelcontextprotocol.io/specification/2025-06-18/server/tools
"""

from __future__ import annotations

import hashlib
import http.client
import io
import ipaddress
import json
import queue
import socket
import ssl
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

from jsonschema import Draft202012Validator, FormatChecker
from jsonschema.exceptions import SchemaError

from nexus_symbiote.core.hashing import hash_canonical
from nexus_symbiote.utils.secrets import redact_descriptor, redact_text

PROTOCOL_VERSION = "2025-06-18"
_RESOLVER_SLOTS = threading.BoundedSemaphore(2)
# Meta-validate tool schemas with the "regex" check of every install, never whatever
# format checkers happen to be installed: with rfc3986-validator, "$ref" values that
# jsonschema resolves fail "uri-reference", and None would skip invalid patterns.
SCHEMA_FORMAT_CHECKER = FormatChecker(formats=("regex",))


class DiscoveryError(ValueError):
    """A bounded, nonsecret discovery failure."""


@dataclass(frozen=True)
class DiscoveryLimits:
    max_response_bytes: int = 1024 * 1024
    max_total_bytes: int = 4 * 1024 * 1024
    max_pages: int = 20
    max_tools: int = 1000
    timeout_seconds: float = 5
    total_timeout_seconds: float = 30
    max_session_id_bytes: int = 256
    max_cursor_bytes: int = 4096
    max_sse_events: int = 100

    def __post_init__(self) -> None:
        if not (
            0 < self.max_response_bytes <= 4 * 1024 * 1024
            and 0 < self.max_total_bytes <= 32 * 1024 * 1024
            and 0 < self.max_pages <= 100
            and 0 < self.max_tools <= 10_000
            and 0 < self.timeout_seconds <= 30
            and 0 < self.total_timeout_seconds <= 300
            and 0 < self.max_session_id_bytes <= 1024
            and 0 < self.max_cursor_bytes <= 16_384
            and 0 < self.max_sse_events <= 1000
        ):
            raise DiscoveryError("unsupported discovery limits")


@dataclass(frozen=True)
class HTTPReply:
    status: int
    headers: dict[str, str]
    body: bytes


class DiscoveryTransport(Protocol):
    """Trusted application injection point; never load one from scanned input."""

    def request(
        self, endpoint: str, body: bytes, headers: dict[str, str], *, timeout: float, max_bytes: int
    ) -> HTTPReply:
        """Send one bounded request and return the complete reply."""


@dataclass
class ObservedTool:
    name: str
    descriptor: dict[str, Any]
    definition_hash: str
    lints: list[str] = field(default_factory=list)
    digest_profile: str = "nexus_symbiote.observed-mcp-tool/2025-06-18/full-v1"


@dataclass
class DiscoveryResult:
    endpoint: str = "[invalid-endpoint]"
    protocol_version: str = PROTOCOL_VERSION
    collector_id: str = "nexus-symbiote-live-mcp"
    collection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    observed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str | None = None
    session_established: bool = False
    session_digest: str | None = None
    tools: list[ObservedTool] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    complete: bool = False
    pages_observed: int = 0
    bytes_observed: int = 0
    coverage: dict[str, Any] = field(
        default_factory=lambda: {
            "scope": "tools/list responses in one bounded discovery session",
            "assurance": "observed-server-declarations",
            "tool_implementation_observed": False,
            "tool_execution_performed": False,
            "authorization_verified": False,
            "continuous_monitoring": False,
        }
    )

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def _endpoint(value: str, *, origin_only: bool = False) -> tuple[str, str, int, str]:
    if (
        not isinstance(value, str)
        or len(value) > 4096
        or any(ord(c) <= 32 or ord(c) >= 127 for c in value)
    ):
        raise DiscoveryError("endpoint must be an ASCII HTTPS URL without controls")
    try:
        parsed = urlsplit(value)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or "?" in value
            or "#" in value
            or "%" in parsed.netloc
            or "\\" in value
            or (origin_only and parsed.path not in ("", "/"))
        ):
            raise DiscoveryError(
                "endpoint credentials, queries, fragments or non-HTTPS scheme refused"
            )
        host = parsed.hostname.lower()
        port = 443 if parsed.port is None else parsed.port
    except ValueError as exc:
        raise DiscoveryError("invalid endpoint") from exc
    if host.endswith(".") or not 1 <= port <= 65535:
        raise DiscoveryError("invalid endpoint authority")
    authority = f"[{host}]" if ":" in host else host
    origin = f"https://{authority}" + (f":{port}" if port != 443 else "")
    return origin, host, port, parsed.path or "/"


def _public_ip(value: str) -> bool:
    address = ipaddress.ip_address(value)
    mapped = getattr(address, "ipv4_mapped", None)
    if mapped is not None:
        address = mapped
    # Embedded-IPv4 forms can reach the IPv4 address they carry, and none of
    # them names a legitimate public service: refuse them outright. ::/96 is the
    # deprecated IPv4-compatible range and ::ffff:0:0:0/96 is SIIT translation.
    if isinstance(address, ipaddress.IPv6Address) and (
        address.sixtofour is not None
        or address.teredo is not None
        or address in ipaddress.ip_network("64:ff9b::/96")
        or address in ipaddress.ip_network("64:ff9b:1::/48")
        or address in ipaddress.ip_network("::/96")
        or address in ipaddress.ip_network("::ffff:0:0:0/96")
    ):
        return False
    return bool(address.is_global and not address.is_multicast and not address.is_unspecified)


def _resolve_public(host: str, port: int, timeout: float) -> tuple[int, str]:
    """Bound resolver waiting and outstanding lookups, then pin a public result.

    System DNS cannot be forcibly cancelled. At most two daemon resolver calls
    may remain outstanding; exhaustion fails closed instead of spawning threads.
    """
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None:
        if not _public_ip(host):
            raise DiscoveryError("nonpublic destination refused")
        return (socket.AF_INET6 if address.version == 6 else socket.AF_INET), str(address)
    if not _RESOLVER_SLOTS.acquire(blocking=False):
        raise DiscoveryError("resolver capacity unavailable")
    answers: queue.Queue[Any] = queue.Queue(maxsize=1)

    def resolve() -> None:
        try:
            answers.put(
                socket.getaddrinfo(host, port, type=socket.SOCK_STREAM, proto=socket.IPPROTO_TCP)
            )
        except OSError:
            answers.put(None)
        finally:
            _RESOLVER_SLOTS.release()

    threading.Thread(target=resolve, daemon=True, name="nexus-symbiote-mcp-dns").start()
    try:
        records = answers.get(timeout=timeout)
    except queue.Empty as exc:
        raise DiscoveryError("DNS resolution timed out") from exc
    if not records or len(records) > 64:
        raise DiscoveryError("DNS resolution failed or exceeded limits")
    candidates: set[tuple[int, str]] = set()
    for family, _, _, _, address_info in records:
        if family not in (socket.AF_INET, socket.AF_INET6) or not _public_ip(address_info[0]):
            raise DiscoveryError("nonpublic or unsupported DNS answer refused")
        candidates.add((family, address_info[0]))
    return sorted(candidates)[0]


class _DeadlineReader(io.RawIOBase):
    def __init__(self, owner: _DeadlineSocket) -> None:
        self.owner = owner

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        remaining = self.owner.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("discovery request deadline exceeded")
        self.owner.stream.settimeout(remaining)
        return self.owner.stream.recv_into(buffer)

    def close(self) -> None:
        if not self.closed:
            self.owner.release_reader()
        super().close()


class _DeadlineSocket:
    def __init__(self, stream: ssl.SSLSocket, deadline: float) -> None:
        self.stream = stream
        self.deadline = deadline
        self._readers = 0
        self._closing = False

    def makefile(self, mode: str, buffering: int | None = None) -> io.BufferedReader:
        if mode != "rb":
            raise DiscoveryError("unsupported HTTP stream mode")
        self._readers += 1
        return io.BufferedReader(_DeadlineReader(self))

    def sendall(self, data: bytes) -> None:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("discovery request deadline exceeded")
        self.stream.settimeout(remaining)
        self.stream.sendall(data)

    def close(self) -> None:
        self._closing = True
        if not self._readers:
            self.stream.close()

    def release_reader(self) -> None:
        self._readers -= 1
        if self._closing and not self._readers:
            self.stream.close()


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, family: int, address: str, timeout: float) -> None:
        context = ssl.create_default_context()
        # Explicit: a system OpenSSL policy must not lower the floor below TLS 1.2.
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._tls_context = context
        super().__init__(host, port, timeout=timeout, context=self._tls_context)
        self._family = family
        self._address = address
        self._deadline = time.monotonic() + timeout

    def connect(self) -> None:
        # Connect to a numeric address directly. There is no second DNS lookup,
        # proxy tunnel, redirect, or TLS hostname substitution.
        raw = socket.socket(self._family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        try:
            raw.settimeout(max(0.001, self._deadline - time.monotonic()))
            destination: Any = (self._address, self.port)
            if self._family == socket.AF_INET6:
                destination = (self._address, self.port, 0, 0)
            raw.connect(destination)
            raw.settimeout(max(0.001, self._deadline - time.monotonic()))
            secured = self._tls_context.wrap_socket(raw, server_hostname=self.host)
            self.sock = cast(Any, _DeadlineSocket(secured, self._deadline))
        except BaseException:
            raw.close()
            raise


class PinnedHTTPTransport:
    """Direct public-IP-pinned HTTPS transport with platform TLS verification.

    A new instance is used per discovery, retaining the resolved public peer for
    that session. Environment HTTP proxies are not used: a proxy that resolves
    the hostname itself would invalidate this transport's destination check.
    Deployment egress policy must independently restrict permitted services.
    """

    def __init__(self, *, max_sse_events: int = 100) -> None:
        self._peers: dict[tuple[str, int], tuple[int, str]] = {}
        self._max_sse_events = max_sse_events

    def request(
        self, endpoint: str, body: bytes, headers: dict[str, str], *, timeout: float, max_bytes: int
    ) -> HTTPReply:
        _, host, port, path = _endpoint(endpoint)
        started = time.monotonic()
        key = (host, port)
        if key not in self._peers:
            if len(self._peers) >= 8:
                raise DiscoveryError("transport origin limit exceeded")
            self._peers[key] = _resolve_public(host, port, timeout)
        family, address = self._peers[key]
        remaining = timeout - (time.monotonic() - started)
        if remaining <= 0:
            raise DiscoveryError("request deadline exceeded")
        connection = _PinnedHTTPSConnection(host, port, family, address, remaining)
        response: http.client.HTTPResponse | None = None
        try:
            connection.request("POST", path, body=body, headers=headers)
            response = connection.getresponse()
            raw_headers = response.getheaders()
            if len(raw_headers) > 64 or sum(len(k) + len(v) for k, v in raw_headers) > 16_384:
                raise DiscoveryError("HTTP header limit exceeded")
            normalized: dict[str, str] = {}
            for name, value in raw_headers:
                name = name.lower()
                if name in normalized:
                    raise DiscoveryError("duplicate HTTP header refused")
                normalized[name] = value
            if 300 <= response.status < 400:
                raise DiscoveryError("HTTP redirect refused")
            if normalized.get("content-encoding", "identity").lower() != "identity":
                raise DiscoveryError("compressed HTTP response refused")
            if "content-length" in normalized:
                length = int(normalized["content-length"])
                if length < 0 or length > max_bytes or "transfer-encoding" in normalized:
                    raise DiscoveryError("HTTP body length refused")
            if normalized.get("content-type", "").split(";", 1)[0].lower() == "text/event-stream":
                payload = self._read_sse(response, body, max_bytes)
            else:
                payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise DiscoveryError("HTTP response byte limit exceeded")
            return HTTPReply(response.status, normalized, payload)
        finally:
            if response is not None:
                response.close()
            connection.close()

    def _read_sse(self, response: http.client.HTTPResponse, body: bytes, maximum: int) -> bytes:
        request_id = _json(body).get("id")
        payload = bytearray()
        event = bytearray()
        events = 0
        while len(payload) <= maximum:
            if response.fp is None:
                break
            line = response.fp.readline(min(65_537, maximum + 1 - len(payload)))
            if not line:
                break
            payload.extend(line)
            if len(line) > 65_536 or len(payload) > maximum:
                raise DiscoveryError("SSE response byte or line limit exceeded")
            event.extend(line)
            if line in (b"\n", b"\r\n"):
                events += 1
                if events > self._max_sse_events:
                    raise DiscoveryError("SSE event limit exceeded")
                for message in _sse(bytes(event), self._max_sse_events):
                    if message.get("id") == request_id and (
                        "result" in message or "error" in message
                    ):
                        return bytes(payload)
                event.clear()
        raise DiscoveryError("SSE ended without matching response")


def _json(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise DiscoveryError("duplicate JSON key")
            value[key] = item
        return value

    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(DiscoveryError("nonfinite JSON")),
        )
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise DiscoveryError("invalid JSON response") from exc
    if not isinstance(value, dict):
        raise DiscoveryError("JSON response must be an object")
    return cast(dict[str, Any], value)


def _sse(raw: bytes, maximum: int) -> list[dict[str, Any]]:
    try:
        lines = raw.decode("utf-8").splitlines()
    except UnicodeError as exc:
        raise DiscoveryError("invalid SSE UTF-8") from exc
    messages = []
    data: list[str] = []
    events = 0
    for line in [*lines, ""]:
        if not line:
            if data:
                events += 1
                if events > maximum:
                    raise DiscoveryError("SSE event limit exceeded")
                messages.append(_json("\n".join(data).encode("utf-8")))
                data.clear()
        elif line.startswith("data:"):
            data.append(line[5:].removeprefix(" "))
        elif line.startswith((":", "event:", "id:", "retry:")):
            continue
        else:
            raise DiscoveryError("unsupported SSE field")
    return messages


def _response(reply: HTTPReply, identifier: int, limits: DiscoveryLimits) -> dict[str, Any]:
    if reply.status != 200:
        raise DiscoveryError("MCP request returned an unsuccessful HTTP status")
    content_type = reply.headers.get("content-type", "").split(";", 1)[0].lower()
    if content_type == "application/json":
        messages = [_json(reply.body)]
    elif content_type == "text/event-stream":
        messages = _sse(reply.body, limits.max_sse_events)
    else:
        raise DiscoveryError("unsupported MCP response media type")
    matching = []
    for message in messages:
        if message.get("jsonrpc") != "2.0":
            raise DiscoveryError("invalid JSON-RPC version")
        if "method" in message:
            # Never service sampling, roots, elicitation or other server requests.
            if "id" in message:
                raise DiscoveryError("server-initiated request unsupported")
            continue
        if type(message.get("id")) is not int or message["id"] != identifier:
            raise DiscoveryError("JSON-RPC response ID mismatch")
        if "error" in message or not isinstance(message.get("result"), dict):
            raise DiscoveryError("MCP server reported an error or invalid result")
        matching.append(message["result"])
    if len(matching) != 1:
        raise DiscoveryError("missing or duplicate JSON-RPC response")
    return cast(dict[str, Any], matching[0])


def _tool(raw: Any, secrets: list[str]) -> ObservedTool:
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str) or not raw["name"]:
        raise DiscoveryError("invalid MCP tool identity")
    if len(raw["name"]) > 256 or any(ord(c) < 32 for c in raw["name"]):
        raise DiscoveryError("invalid MCP tool name")
    for key in ("title", "description"):
        if key in raw and not isinstance(raw[key], str):
            raise DiscoveryError("invalid MCP tool text field")
    for key in ("inputSchema", "outputSchema"):
        schema = raw.get(key)
        if key == "inputSchema" or key in raw:
            if not isinstance(schema, dict) or schema.get("type") != "object":
                raise DiscoveryError("tool schemas must declare object type")
            try:
                Draft202012Validator.check_schema(schema, format_checker=SCHEMA_FORMAT_CHECKER)
            except (SchemaError, RecursionError) as exc:
                raise DiscoveryError("invalid MCP tool JSON Schema") from exc
    annotations = raw.get("annotations", {})
    if not isinstance(annotations, dict):
        raise DiscoveryError("invalid MCP tool annotations")
    if "title" in annotations and not isinstance(annotations["title"], str):
        raise DiscoveryError("invalid MCP annotation title")
    if "_meta" in raw and not isinstance(raw["_meta"], dict):
        raise DiscoveryError("invalid MCP tool metadata")
    for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
        if hint in annotations and type(annotations[hint]) is not bool:
            raise DiscoveryError("invalid MCP annotation hint")
    lints = [
        "Server metadata and annotations are unverified declarations; no capability was authorized."
    ]
    unsupported = set(raw) - {
        "name",
        "title",
        "description",
        "inputSchema",
        "outputSchema",
        "annotations",
        "_meta",
    }
    if unsupported:
        lints.append(
            "Unsupported descriptor extension fields retained in full digest; not admission-compatible."
        )
    if "title" in raw or "outputSchema" in raw or "_meta" in raw:
        lints.append(
            "Full observed-descriptor digest includes fields outside the static four-field profile."
        )
    # Full raw descriptor is the digest subject. Shown metadata is redacted and
    # cannot be used to recompute this digest without obtaining original evidence.
    digest = hash_canonical(raw)
    safe = redact_descriptor(raw, secrets)
    return ObservedTool(safe["name"], safe, digest, lints)


def discover_tools(
    endpoint_url: str,
    *,
    allowed_origins: Iterable[str],
    bearer_token: str | None = None,
    transport: DiscoveryTransport | None = None,
    limits: DiscoveryLimits | None = None,
    collector_id: str = "nexus-symbiote-live-mcp",
) -> DiscoveryResult:
    """Observe one explicitly authorized HTTP MCP endpoint without calling tools.

    Caller-supplied transport is trusted code and can bypass network destination
    checks; it exists for local fixtures or an independently controlled transport.
    It must never be selected from a repository/configuration being scanned.
    """
    result = DiscoveryResult()
    session: str | None = None
    protected = [bearer_token] if isinstance(bearer_token, str) else []
    try:
        limits = limits or DiscoveryLimits()
        origin, _, _, path = _endpoint(endpoint_url)
        approved = {_endpoint(value, origin_only=True)[0] for value in allowed_origins}
        if origin not in approved:
            raise DiscoveryError("endpoint origin is not explicitly allowed")
        # Even trusted injected transports receive only an explicit HTTPS URL.
        if bearer_token and isinstance(bearer_token, str) and bearer_token in origin + path:
            raise DiscoveryError("bearer credential in endpoint refused")
        result.endpoint = origin + path
        if (
            not isinstance(collector_id, str)
            or len(collector_id) > 128
            or not collector_id.isascii()
        ):
            raise DiscoveryError("invalid collector identifier")
        result.collector_id = redact_text(collector_id, protected)
        if bearer_token is not None and (
            not isinstance(bearer_token, str)
            or not 1 <= len(bearer_token) <= 8192
            or any(ord(c) <= 32 or ord(c) >= 127 for c in bearer_token)
        ):
            raise DiscoveryError("invalid bearer credential encoding")
        transport = transport or PinnedHTTPTransport(max_sse_events=limits.max_sse_events)
        deadline = time.monotonic() + limits.total_timeout_seconds
        identifier = 0

        def request(
            method: str, params: dict[str, Any] | None = None, *, notification: bool = False
        ) -> tuple[dict[str, Any], HTTPReply]:
            nonlocal identifier
            message: dict[str, Any] = {"jsonrpc": "2.0", "method": method}
            if not notification:
                identifier += 1
                message["id"] = identifier
            if params is not None:
                message["params"] = params
            headers = {
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
                "Accept-Encoding": "identity",
            }
            if method != "initialize":
                headers["MCP-Protocol-Version"] = PROTOCOL_VERSION
            if bearer_token:
                headers["Authorization"] = "Bearer " + bearer_token
            if session:
                headers["Mcp-Session-Id"] = session
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DiscoveryError("discovery session deadline exceeded")
            reply = transport.request(
                result.endpoint,
                json.dumps(message, separators=(",", ":")).encode(),
                headers,
                timeout=min(limits.timeout_seconds, remaining),
                max_bytes=limits.max_response_bytes,
            )
            if time.monotonic() > deadline:
                raise DiscoveryError("discovery session deadline exceeded")
            reply = HTTPReply(
                reply.status, {k.lower(): v for k, v in reply.headers.items()}, reply.body
            )
            result.bytes_observed += len(reply.body)
            if (
                len(reply.body) > limits.max_response_bytes
                or result.bytes_observed > limits.max_total_bytes
            ):
                raise DiscoveryError("discovery response byte limit exceeded")
            if 300 <= reply.status < 400:
                raise DiscoveryError("HTTP redirect refused")
            changed_session = reply.headers.get("mcp-session-id")
            if (
                method != "initialize"
                and changed_session is not None
                and changed_session != session
            ):
                raise DiscoveryError("MCP session changed during discovery")
            if notification:
                if reply.status != 202 or reply.body:
                    raise DiscoveryError("initialized notification was not acknowledged")
                return {}, reply
            return _response(reply, identifier, limits), reply

        initialized, reply = request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "nexus-symbiote-discovery", "version": "0.1.0"},
            },
        )
        if initialized.get("protocolVersion") != PROTOCOL_VERSION:
            raise DiscoveryError("unsupported negotiated MCP protocol version")
        capabilities, server_info = initialized.get("capabilities"), initialized.get("serverInfo")
        if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
            raise DiscoveryError("MCP server did not negotiate tool listing")
        if not isinstance(server_info, dict) or not all(
            isinstance(server_info.get(k), str) for k in ("name", "version")
        ):
            raise DiscoveryError("invalid MCP server implementation identity")
        session = reply.headers.get("mcp-session-id")
        if session is not None:
            if not 1 <= len(session) <= limits.max_session_id_bytes or any(
                not 0x21 <= ord(c) <= 0x7E for c in session
            ):
                raise DiscoveryError("invalid MCP session identifier")
            result.session_established = True
            result.session_digest = "sha256:" + hashlib.sha256(session.encode()).hexdigest()
        request("notifications/initialized", notification=True)
        cursor: str | None = None
        cursors: set[str] = set()
        names: set[str] = set()
        secrets = [value for value in (bearer_token, session) if value]
        for _ in range(limits.max_pages):
            page, _ = request("tools/list", {"cursor": cursor} if cursor is not None else {})
            tools = page.get("tools")
            if not isinstance(tools, list) or len(tools) + len(result.tools) > limits.max_tools:
                raise DiscoveryError("invalid tool list or tool-count limit exceeded")
            observed = []
            for raw_tool in tools:
                if time.monotonic() > deadline:
                    raise DiscoveryError("discovery session deadline exceeded")
                observed.append(_tool(raw_tool, secrets))
            if time.monotonic() > deadline:
                raise DiscoveryError("discovery session deadline exceeded")
            for tool in observed:
                if tool.name in names:
                    raise DiscoveryError("duplicate tool identity across discovery pages")
                names.add(tool.name)
            result.tools.extend(observed)
            result.pages_observed += 1
            cursor = page.get("nextCursor")
            if cursor is None:
                result.complete = True
                break
            if (
                not isinstance(cursor, str)
                or not 1 <= len(cursor.encode()) <= limits.max_cursor_bytes
                or cursor in cursors
            ):
                raise DiscoveryError("invalid or repeated tool-list cursor")
            cursors.add(cursor)
        if not result.complete:
            raise DiscoveryError("tool-list page limit exceeded")
    except DiscoveryError as exc:
        # DiscoveryError messages are fixed local diagnostics without payloads.
        result.failures.append(redact_text(str(exc), [*protected, *([session] if session else [])]))
        result.complete = False
    except (
        OSError,
        TypeError,
        ValueError,
        RecursionError,
        http.client.HTTPException,
    ):
        # Do not serialize exception strings, remote error messages, authorization
        # headers, cursors or session IDs. Caller-controlled transports may throw
        # credential-bearing diagnostics; report the failed operation generically.
        result.failures.append(
            "Live MCP discovery refused or incomplete; check endpoint policy, protocol and configured limits."
        )
        result.complete = False
    finally:
        result.completed_at = datetime.now(UTC).isoformat()
    return result
