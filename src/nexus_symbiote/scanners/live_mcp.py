"""Opt-in, bounded HTTP MCP descriptor discovery; never invokes tools.

Implements the initialize/initialized/tools-list lifecycle over the Streamable
HTTP transport for JSON and bounded SSE responses, negotiating one of
``SUPPORTED_PROTOCOL_VERSIONS``. When the server declares them, prompts/list and
resources/templates/list are observed as well. This is a point-in-time
observation, not authorization or a claim about server safety. Discovery itself
sends authenticated requests to an explicitly allowed service. stdio, redirects,
proxying, roots, sampling, elicitation, tool calls, prompts/get, resources/list,
resource retrieval, stream resumption and automatic retries are unsupported.

Protocol sources:
https://modelcontextprotocol.io/specification/2025-06-18/basic/lifecycle
https://modelcontextprotocol.io/specification/2025-06-18/basic/transports
https://modelcontextprotocol.io/specification/2025-06-18/server/tools
https://html.spec.whatwg.org/multipage/server-sent-events.html#event-stream-interpretation
"""

from __future__ import annotations

import hashlib
import http.client
import io
import ipaddress
import json
import queue
import re
import socket
import ssl
import threading
import time
import uuid
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any, NamedTuple, Protocol, cast
from urllib.parse import unquote, urlsplit

from jsonschema import (
    Draft4Validator,
    Draft6Validator,
    Draft7Validator,
    Draft201909Validator,
    Draft202012Validator,
)

from nexus_symbiote import __version__
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_canonical,
    hash_tool_definition,
    tool_definition_extensions,
)
from nexus_symbiote.modes import OfflineViolation
from nexus_symbiote.runtime_validation import (
    DIALECTS,
    MAX_SCHEMA_BYTES,
    check_json_budget,
    ecma_pattern,
)
from nexus_symbiote.utils.secrets import redact_descriptor, redact_metadata, redact_text

# Revisions whose initialize, tools/list, prompts/list and resources/templates/list
# exchanges this client implements. The first is requested; a server may answer
# with any other entry. A server that negotiates anything else is refused.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05")
PROTOCOL_VERSION = SUPPORTED_PROTOCOL_VERSIONS[0]
DEFAULT_CLIENT_NAME = "nexus-symbiote-discovery"
DEFAULT_CLIENT_VERSION = __version__
# Descriptor members that hash_tool_definition binds; any other member is bound
# only through the server declaration digest.
FINGERPRINT_FIELDS = frozenset(
    {"name", "title", "description", "inputSchema", "outputSchema", "annotations", "_meta"}
)
DECLARATION_PROFILE = "nexus-symbiote/mcp-server-declaration/v1"
IDENTITY_PROFILE = "nexus-symbiote/mcp-server-identity/v1"
METHOD_NOT_FOUND = -32601
OBSERVED_DIGEST_PROFILE = "nexus_symbiote.observed-mcp-tool/2025-06-18/full-v1"
_RESOLVER_SLOTS = threading.BoundedSemaphore(2)
# Only headers the client reads must be unambiguous; repeated Set-Cookie or Via
# lines from an intermediary carry nothing this client uses.
_CONSUMED_HEADERS = frozenset(
    {
        "content-length",
        "transfer-encoding",
        "content-type",
        "content-encoding",
        "mcp-session-id",
        "location",
    }
)
# jsonschema's uniqueItems compares unsortable array items pairwise. The 2020-12
# metaschema requires unique "type", "required", "dependentRequired" and
# "dependencies" arrays, and its anyOf for "type" and "dependencies" evaluates a
# whole branch, required lists included, before it reports the first error.
# Longer unsortable arrays under those keywords are refused before checking.
_UNIQUE_ITEMS_PAIRWISE_LIMIT = 64
# Keywords whose values the 2020-12 metaschema checks as subschemas. It checks
# "dependencies" values through anyOf instead; see _checked_dependency_schemas.
_SUBSCHEMA_KEYWORDS = frozenset(
    {
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
_SUBSCHEMA_LISTS = frozenset({"allOf", "anyOf", "oneOf", "prefixItems"})
_SUBSCHEMA_MAPS = frozenset(
    {"$defs", "definitions", "dependentSchemas", "patternProperties", "properties"}
)
_NONPUBLIC_NETWORKS = tuple(
    ipaddress.ip_network(network)
    for network in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
        "::/96",
        "::ffff:0:0:0/96",
        "64:ff9b::/96",
        "64:ff9b:1::/48",
        "100::/64",
        "2001::/23",
        "2001:db8::/32",
        "2002::/16",
        "3fff::/20",
        "5f00::/16",
        "fc00::/7",
        "fe80::/10",
        "fec0::/10",
        "ff00::/8",
    )
)


class DiscoveryError(ValueError):
    """A bounded, nonsecret discovery failure."""


class _MethodNotFoundError(DiscoveryError):
    """The server answered an optional list request with JSON-RPC -32601."""


def is_method_not_found(message: dict[str, Any]) -> bool:
    """A JSON-RPC error reply whose code is -32601 (Method not found)."""
    error = message.get("error")
    return (
        set(message) == {"jsonrpc", "id", "error"}
        and isinstance(error, dict)
        and type(error.get("code")) is int
        and error["code"] == METHOD_NOT_FOUND
    )


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


@dataclass(frozen=True)
class CheckedDescriptor:
    """A served tool descriptor that passed bounded intake checks."""

    name: str
    fingerprint: str
    observed_hash: str
    display: dict[str, Any]
    unprofiled_fields: tuple[str, ...]
    unprofiled_hash: str | None
    display_differs: bool


@dataclass
class ObservedTool:
    name: str
    descriptor: dict[str, Any]
    definition_hash: str
    lints: list[str] = field(default_factory=list)
    digest_profile: str = OBSERVED_DIGEST_PROFILE
    fingerprint: str | None = None
    fingerprint_profile: str = TOOL_DEFINITION_HASH_VERSION
    display_differs: bool = False
    unprofiled_fields: list[str] = field(default_factory=list)


@dataclass
class ObservedItem:
    """One prompts/list or resources/templates/list entry: redacted view and full digest."""

    identity: str
    descriptor: dict[str, Any]
    digest: str


@dataclass
class DiscoveryResult:
    endpoint: str = "[invalid-endpoint]"
    protocol_version: str | None = None
    requested_protocol_version: str = PROTOCOL_VERSION
    collector_id: str = "nexus-symbiote-live-mcp"
    collection_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    observed_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    completed_at: str | None = None
    client_info: dict[str, str] = field(
        default_factory=lambda: {"name": DEFAULT_CLIENT_NAME, "version": DEFAULT_CLIENT_VERSION}
    )
    user_agent: str | None = None
    session_established: bool = False
    session_digest: str | None = None
    server_info: dict[str, Any] | None = None
    server_capabilities: dict[str, Any] | None = None
    instructions: str | None = None
    instructions_hash: str | None = None
    declaration_hash: str | None = None
    declaration_profile: str = DECLARATION_PROFILE
    identity_hash: str | None = None
    identity_profile: str = IDENTITY_PROFILE
    tools: list[ObservedTool] = field(default_factory=list)
    prompts: list[ObservedItem] | None = None
    resource_templates: list[ObservedItem] | None = None
    failures: list[str] = field(default_factory=list)
    complete: bool = False
    pages_observed: int = 0
    bytes_observed: int = 0
    coverage: dict[str, Any] = field(
        default_factory=lambda: {
            "scope": (
                "initialize result and tools/list responses, plus prompts/list and "
                "resources/templates/list when the server declares them, in one bounded "
                "discovery session"
            ),
            "assurance": "observed-server-declarations",
            "tool_implementation_observed": False,
            "tool_execution_performed": False,
            "authorization_verified": False,
            "continuous_monitoring": False,
            "unobserved": [
                "tool implementation and backend behavior",
                "resources/list entries and resource contents",
                "prompt messages (prompts/get)",
                "authorization metadata",
                "notifications and list changes after this session",
                "responses the server gives to clients that identify differently",
            ],
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
    except DiscoveryError:
        # The refusal above; DiscoveryError is a ValueError, which the next clause would
        # otherwise replace with the generic text.
        raise
    except ValueError as exc:
        raise DiscoveryError("invalid endpoint") from exc
    if any(unquote(part) in (".", "..") for part in parsed.path.split("/")):
        raise DiscoveryError("endpoint dot segments refused")
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
    # them names a legitimate public service: refuse them outright. The explicit
    # special-purpose list keeps the answer independent of the interpreter's
    # ipaddress tables, which have changed between patch releases.
    if isinstance(address, ipaddress.IPv6Address) and (
        address.sixtofour is not None or address.teredo is not None or address.is_site_local
    ):
        return False
    if any(address in network for network in _NONPUBLIC_NETWORKS):
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
        except (OSError, ValueError):
            answers.put(None)
        except OfflineViolation as exc:
            # The guard's violation is a BaseException by design; handed to the caller,
            # it is raised there at once instead of dying with this thread at the timeout.
            answers.put(exc)
        finally:
            _RESOLVER_SLOTS.release()

    worker = threading.Thread(target=resolve, daemon=True, name="nexus-symbiote-mcp-dns")
    try:
        worker.start()
    except BaseException:
        _RESOLVER_SLOTS.release()
        raise
    try:
        records = answers.get(timeout=timeout)
    except queue.Empty as exc:
        raise DiscoveryError("DNS resolution timed out") from exc
    if isinstance(records, OfflineViolation):
        raise records
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


def _client_context() -> ssl.SSLContext:
    context = ssl.create_default_context()
    # create_default_context() honours SSLKEYLOGFILE; this client never writes
    # session secrets that would let a packet capture recover the bearer token.
    context.keylog_filename = None  # type: ignore[assignment]
    # Explicit: a system OpenSSL policy must not lower the floor below TLS 1.2.
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    def __init__(self, host: str, port: int, family: int, address: str, timeout: float) -> None:
        self._tls_context = _client_context()
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
    SSLKEYLOGFILE is ignored. Deployment egress policy must independently
    restrict permitted services.
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
                    if name in _CONSUMED_HEADERS:
                        raise DiscoveryError("duplicate HTTP header refused")
                    continue
                normalized[name] = value
            if 300 <= response.status < 400:
                raise DiscoveryError("HTTP redirect refused")
            if normalized.get("content-encoding", "identity").lower() != "identity":
                raise DiscoveryError("compressed HTTP response refused")
            if "content-length" in normalized:
                raw_length = normalized["content-length"].strip()
                if not raw_length.isascii() or not raw_length.isdigit():
                    raise DiscoveryError("HTTP body length refused")
                length = int(raw_length)
                if length > max_bytes or "transfer-encoding" in normalized:
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
        """Read event lines until the requested response arrives.

        HTTPResponse.read1 / readline decodes chunked transfer coding. Lines may
        terminate in CRLF, LF or bare CR (WHATWG SSE), and a single line may use
        the whole response byte limit when SDK servers emit one large data line.
        """
        request_id = _json(body).get("id")
        decoder = _SSEDecoder(self._max_sse_events)
        payload = bytearray()
        buffer = bytearray()
        saw_bare_cr = False
        use_read1 = hasattr(response, "read1")
        while True:
            remaining = maximum + 1 - len(payload) - len(buffer)
            if remaining <= 0:
                raise DiscoveryError("SSE response byte limit exceeded")
            chunk = (
                response.read1(min(4096, remaining)) if use_read1 else response.readline(remaining)
            )
            eof = not chunk
            buffer.extend(chunk)
            while buffer:
                cr = buffer.find(b"\r")
                lf = buffer.find(b"\n")
                if cr < 0 and lf < 0:
                    if len(payload) + len(buffer) > maximum:
                        raise DiscoveryError("SSE response byte limit exceeded")
                    if not eof:
                        break
                    end = len(buffer)
                elif lf >= 0 and (cr < 0 or lf < cr):
                    end = lf + 1
                elif cr + 1 < len(buffer):
                    if buffer[cr + 1] == 0x0A:
                        end = cr + 2
                    else:
                        saw_bare_cr = True
                        end = cr + 1
                elif eof or saw_bare_cr:
                    end = cr + 1
                else:
                    if len(payload) + len(buffer) > maximum:
                        raise DiscoveryError("SSE response byte limit exceeded")
                    break
                line = bytes(buffer[:end])
                del buffer[:end]
                payload.extend(line)
                if len(payload) > maximum:
                    raise DiscoveryError("SSE response byte limit exceeded")
                for message in decoder.feed(line):
                    if message.get("id") == request_id and (
                        "result" in message or "error" in message
                    ):
                        return bytes(payload)
            if eof:
                break
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
    except DiscoveryError:
        # The hooks' own diagnostics; DiscoveryError is a ValueError, which the next
        # clause would otherwise replace with the generic text.
        raise
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise DiscoveryError("invalid JSON response") from exc
    if not isinstance(value, dict):
        raise DiscoveryError("JSON response must be an object")
    return cast(dict[str, Any], value)


class _SSEDecoder:
    """Decode an event stream into JSON-RPC messages, following the WHATWG rules.

    Lines end in CRLF, LF or CR only, so U+2028, U+2029 and U+0085 stay inside
    JSON strings. Comments, ``id``, ``retry`` and unknown fields carry no message.
    An event without data, such as a resumption priming event, and an event of
    a type other than ``message`` are skipped. An unterminated final event is
    discarded at the end of the stream.
    """

    def __init__(self, maximum_events: int) -> None:
        self._maximum = maximum_events
        self._events = 0
        self._partial = bytearray()
        self._pending_cr = False
        self._started = False
        self._data: list[str] = []
        self._event_type = ""

    def feed(self, chunk: bytes) -> list[dict[str, Any]]:
        if self._pending_cr and chunk.startswith(b"\n"):
            chunk = chunk[1:]
        self._pending_cr = chunk.endswith(b"\r")
        self._partial.extend(chunk)
        *lines, rest = re.split(rb"\r\n|\r|\n", bytes(self._partial))
        self._partial = bytearray(rest)
        messages = []
        for line in lines:
            message = self._line(line)
            if message is not None:
                messages.append(message)
        return messages

    def _line(self, raw: bytes) -> dict[str, Any] | None:
        try:
            line = raw.decode("utf-8")
        except UnicodeError as exc:
            raise DiscoveryError("invalid SSE UTF-8") from exc
        if not self._started:
            self._started = True
            line = line.removeprefix("\ufeff")
        if not line:
            return self._dispatch()
        if line.startswith(":"):
            return None
        name, colon, value = line.partition(":")
        if colon:
            value = value.removeprefix(" ")
        if name == "data":
            self._data.append(value)
        elif name == "event":
            self._event_type = value
        return None

    def _dispatch(self) -> dict[str, Any] | None:
        data, event_type = "\n".join(self._data), self._event_type
        self._data, self._event_type = [], ""
        if not data or event_type not in ("", "message"):
            return None
        self._events += 1
        if self._events > self._maximum:
            raise DiscoveryError("SSE event limit exceeded")
        return _json(data.encode("utf-8"))


def _sse(raw: bytes, maximum: int) -> list[dict[str, Any]]:
    return _SSEDecoder(maximum).feed(raw)


def _response(
    reply: HTTPReply, identifier: int, limits: DiscoveryLimits, *, optional: bool = False
) -> dict[str, Any]:
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
        if optional and is_method_not_found(message):
            raise _MethodNotFoundError("MCP server does not implement a declared list method")
        if "error" in message or not isinstance(message.get("result"), dict):
            raise DiscoveryError("MCP server reported an error or invalid result")
        matching.append(message["result"])
    if len(matching) != 1:
        raise DiscoveryError("missing or duplicate JSON-RPC response")
    return cast(dict[str, Any], matching[0])


def _bounded_unique_items(schema: dict[str, Any]) -> None:
    pending: list[Any] = [schema]
    while pending:
        item = pending.pop()
        if isinstance(item, dict):
            arrays = [item.get("type"), item.get("required")]
            for key in ("dependentRequired", "dependencies"):
                mapping = item.get(key)
                if isinstance(mapping, dict):
                    arrays.extend(mapping.values())
            for array in arrays:
                if (
                    isinstance(array, list)
                    and len(array) > _UNIQUE_ITEMS_PAIRWISE_LIMIT
                    and not all(isinstance(element, str) for element in array)
                ):
                    raise DiscoveryError("MCP tool schema exceeds the validation budget")
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def _checked_dependency_schemas(node: Any, validator_cls: Any = Draft202012Validator) -> Any:
    """Check each object in a "dependencies" map on its own, then stand in ``true``.

    The metaschema reaches those objects through anyOf, which evaluates a whole
    object before it reports the first error; checked alone, the check stops at
    the first error. Validity is unchanged: such an object must be a valid schema,
    and ``true`` is one. Each node is checked once, within its nearest such object.
    """
    if not isinstance(node, dict):
        return node
    copy = dict(node)
    for key, value in node.items():
        if key in _SUBSCHEMA_KEYWORDS:
            copy[key] = _checked_dependency_schemas(value, validator_cls)
        elif key in _SUBSCHEMA_LISTS and isinstance(value, list):
            copy[key] = [_checked_dependency_schemas(item, validator_cls) for item in value]
        elif key in _SUBSCHEMA_MAPS and isinstance(value, dict):
            copy[key] = {
                name: _checked_dependency_schemas(item, validator_cls)
                for name, item in value.items()
            }
        elif key == "dependencies" and isinstance(value, dict):
            copy[key] = {
                name: _standalone_schema(item, validator_cls) if isinstance(item, dict) else item
                for name, item in value.items()
            }
    return copy


def _standalone_schema(schema: dict[str, Any], validator_cls: Any = Draft202012Validator) -> bool:
    validator_cls.check_schema(_checked_dependency_schemas(schema, validator_cls))
    return True


_DIALECT_VALIDATORS: dict[str, Any] = {
    DIALECTS[0]: Draft4Validator,
    DIALECTS[1]: Draft6Validator,
    DIALECTS[2]: Draft7Validator,
    DIALECTS[3]: Draft201909Validator,
    DIALECTS[4]: Draft202012Validator,
}
_ALLOWED_VOCABULARIES_2020_12 = frozenset(
    {
        "https://json-schema.org/draft/2020-12/vocab/core",
        "https://json-schema.org/draft/2020-12/vocab/applicator",
        "https://json-schema.org/draft/2020-12/vocab/validation",
        "https://json-schema.org/draft/2020-12/vocab/meta-data",
        "https://json-schema.org/draft/2020-12/vocab/unevaluated",
        "https://json-schema.org/draft/2020-12/vocab/format-annotation",
    }
)
_ALLOWED_VOCABULARIES_2019_09 = frozenset(
    {
        "https://json-schema.org/draft/2019-09/vocab/core",
        "https://json-schema.org/draft/2019-09/vocab/applicator",
        "https://json-schema.org/draft/2019-09/vocab/validation",
        "https://json-schema.org/draft/2019-09/vocab/meta-data",
    }
)


def _local_pointer_exists(root: dict[str, Any], pointer: str) -> bool:
    if pointer == "#":
        return True
    if not pointer.startswith("#/"):
        return False
    current: Any = root
    for raw_token in pointer[2:].split("/"):
        token = raw_token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, dict) and token in current:
            current = current[token]
        elif isinstance(current, list):
            if (
                not token.isascii()
                or not token.isdigit()
                or (len(token) > 1 and token.startswith("0"))
            ):
                return False
            idx = int(token)
            if idx >= len(current):
                return False
            current = current[idx]
        else:
            return False
    return isinstance(current, (dict, bool))


def _check_tool_schema_dialect(schema: dict[str, Any]) -> str:
    declared = schema.get("$schema", DIALECTS[-1])
    if not isinstance(declared, str):
        raise DiscoveryError("invalid JSON Schema $schema declaration")
    dialect = declared.removesuffix("#")
    if dialect not in _DIALECT_VALIDATORS:
        raise DiscoveryError("unsupported JSON Schema $schema dialect")

    subschema_id = "id" if dialect == DIALECTS[0] else "$id"
    pending: list[tuple[dict[str, Any], int]] = [(schema, 0)]
    while pending:
        node, depth = pending.pop()
        for ref_key in ("$ref", "$dynamicRef", "$recursiveRef"):
            if ref_key in node:
                target = node[ref_key]
                if not isinstance(target, str) or (target != "#" and not target.startswith("#/")):
                    raise DiscoveryError("non-pointer or external JSON Schema reference refused")
                if ref_key == "$ref" and not _local_pointer_exists(schema, target):
                    raise DiscoveryError("dangling JSON Schema local reference")
        pattern = node.get("pattern")
        if isinstance(pattern, str):
            try:
                re.compile(ecma_pattern(pattern))
            except (re.error, OverflowError, RecursionError) as exc:
                raise DiscoveryError("invalid MCP tool JSON Schema") from exc
        pat_props = node.get("patternProperties")
        if isinstance(pat_props, dict):
            for pat_key in pat_props:
                if isinstance(pat_key, str):
                    try:
                        re.compile(ecma_pattern(pat_key))
                    except (re.error, OverflowError, RecursionError) as exc:
                        raise DiscoveryError("invalid MCP tool JSON Schema") from exc
        if depth > 0:
            for meta_key in ("$schema", subschema_id, "$vocabulary"):
                if meta_key in node:
                    if (
                        meta_key == subschema_id
                        and dialect in DIALECTS[:3]
                        and isinstance(node[meta_key], str)
                        and node[meta_key].startswith("#")
                    ):
                        continue
                    raise DiscoveryError("subschema dialect or base URI override refused")
        elif "$vocabulary" in node:
            if dialect not in (DIALECTS[3], DIALECTS[4]):
                raise DiscoveryError("$vocabulary is unsupported in declared dialect")
            vocab = node["$vocabulary"]
            if not isinstance(vocab, dict) or not all(
                isinstance(k, str) and isinstance(v, bool) for k, v in vocab.items()
            ):
                raise DiscoveryError("invalid JSON Schema $vocabulary")
            allowed = (
                _ALLOWED_VOCABULARIES_2020_12
                if dialect == DIALECTS[4]
                else _ALLOWED_VOCABULARIES_2019_09
            )
            validation_vocab = (
                "https://json-schema.org/draft/2020-12/vocab/validation"
                if dialect == DIALECTS[4]
                else "https://json-schema.org/draft/2019-09/vocab/validation"
            )
            for uri, enabled in vocab.items():
                if uri not in allowed:
                    raise DiscoveryError("unsupported JSON Schema vocabulary")
                if not enabled and uri.endswith(
                    ("/core", "/applicator", "/validation", "/unevaluated")
                ):
                    raise DiscoveryError("required JSON Schema vocabulary disabled")
            if vocab.get(validation_vocab) is not True:
                raise DiscoveryError("JSON Schema validation vocabulary must be enabled")
        for key, value in node.items():
            if key in (_SUBSCHEMA_KEYWORDS | {"additionalItems"}) and isinstance(value, dict):
                pending.append((value, depth + 1))
            elif key in (_SUBSCHEMA_LISTS | {"items"}) and isinstance(value, list):
                pending.extend((item, depth + 1) for item in value if isinstance(item, dict))
            elif key in (_SUBSCHEMA_MAPS | {"dependencies"}) and isinstance(value, dict):
                pending.extend(
                    (item, depth + 1) for item in value.values() if isinstance(item, dict)
                )
    return dialect


def _check_schema(schema: Any) -> None:
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise DiscoveryError("tool schemas must declare object type")
    dialect = _check_tool_schema_dialect(schema)
    _bounded_unique_items(schema)
    validator_cls = _DIALECT_VALIDATORS[dialect]
    try:
        validator_cls.check_schema(_checked_dependency_schemas(schema, validator_cls))
    except Exception as exc:
        # The regex format check runs re.compile, which raises OverflowError and
        # RecursionError besides re.error; any failure means an invalid schema.
        raise DiscoveryError("invalid MCP tool JSON Schema") from exc


def check_served_tool(raw: Any, secrets: Iterable[str] = ()) -> CheckedDescriptor:
    """Validate one served tool descriptor within a fixed budget and fingerprint it.

    The descriptor must fit the runtime gateway's JSON budget (256 KiB, 32 levels,
    20,000 nodes) before any JSON Schema work starts. ``fingerprint`` follows
    ``hash_tool_definition``; members outside ``FINGERPRINT_FIELDS`` are reported
    and digested separately for the server declaration.
    """
    secrets = tuple(secrets)
    if not isinstance(raw, dict) or not isinstance(raw.get("name"), str) or not raw["name"]:
        raise DiscoveryError("invalid MCP tool identity")
    name = raw["name"]
    if len(name) > 256 or not name.isprintable():
        raise DiscoveryError("invalid MCP tool name")
    try:
        check_json_budget(raw, maximum=MAX_SCHEMA_BYTES)
    except ValueError as exc:
        raise DiscoveryError("MCP tool descriptor exceeds the validation budget") from exc
    for key in ("title", "description"):
        if key in raw and not isinstance(raw[key], str):
            raise DiscoveryError("invalid MCP tool text field")
    for key in ("inputSchema", "outputSchema"):
        if key == "inputSchema" or key in raw:
            _check_schema(raw.get(key))
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
    unprofiled = tuple(sorted(set(raw) - FINGERPRINT_FIELDS))
    try:
        fingerprint = hash_tool_definition(
            name,
            raw.get("description", ""),
            raw["inputSchema"],
            annotations,
            **tool_definition_extensions(raw),
        )
        observed = hash_canonical(raw)
        unprofiled_hash = (
            hash_canonical({key: raw[key] for key in unprofiled}) if unprofiled else None
        )
        display = redact_descriptor(raw, secrets)
    except (ValueError, TypeError, RecursionError) as exc:
        raise DiscoveryError("MCP tool descriptor cannot be canonicalized") from exc
    return CheckedDescriptor(
        name=name,
        fingerprint=fingerprint,
        observed_hash=observed,
        display=display,
        # Field names are controlled by the server too. Keep the original names
        # only in the digest above; reporting them verbatim can disclose a bearer
        # token or session ID echoed as an extension key.
        unprofiled_fields=tuple(redact_text(key, secrets) for key in unprofiled),
        unprofiled_hash=unprofiled_hash,
        display_differs=display != raw,
    )


def check_listed_item(raw: Any, identity: str, secrets: Iterable[str] = ()) -> ObservedItem:
    """Validate one prompts/list or resources/templates/list entry and digest it whole."""
    value = raw.get(identity) if isinstance(raw, dict) else None
    if not isinstance(value, str) or not value or len(value) > 2048 or not value.isprintable():
        raise DiscoveryError("invalid MCP list entry identity")
    try:
        check_json_budget(raw, maximum=MAX_SCHEMA_BYTES)
        digest = hash_canonical(raw)
        display = redact_metadata(raw, secrets)
    except (ValueError, TypeError, RecursionError) as exc:
        raise DiscoveryError("MCP list entry exceeds the validation budget") from exc
    return ObservedItem(identity=value, descriptor=display, digest=digest)


def declaration_hash(
    *,
    instructions: str | None,
    tool_extensions: dict[str, str],
    prompts: dict[str, str] | None,
    resource_templates: dict[str, str] | None,
) -> str:
    """Digest the model-visible server declarations other than tool fingerprints.

    ``tool_extensions`` maps tool names to digests of descriptor members outside
    the tool fingerprint profile. ``None`` lists were not offered by the server.
    """
    return hash_canonical(
        {
            "profile": DECLARATION_PROFILE,
            "instructions": instructions,
            "toolExtensions": tool_extensions,
            "prompts": prompts,
            "resourceTemplates": resource_templates,
        }
    )


class ServerHello(NamedTuple):
    """A validated initialize result.

    ``server_info`` and ``capabilities`` are redacted display values;
    ``instructions`` is raw, for digesting. ``identity_hash`` binds every
    ``serverInfo`` member and the capabilities exactly as served.
    """

    version: str
    server_info: dict[str, Any]
    capabilities: dict[str, Any]
    instructions: str | None
    identity_hash: str


def check_server_hello(hello: dict[str, Any], secrets: Iterable[str] = ()) -> ServerHello:
    """Validate an initialize result within the descriptor budget."""
    negotiated = hello.get("protocolVersion")
    if negotiated not in SUPPORTED_PROTOCOL_VERSIONS:
        raise DiscoveryError("unsupported negotiated MCP protocol version")
    capabilities, server_info = hello.get("capabilities"), hello.get("serverInfo")
    if not isinstance(capabilities, dict) or not isinstance(capabilities.get("tools"), dict):
        raise DiscoveryError("MCP server did not negotiate tool listing")
    if any(
        key in capabilities and not isinstance(capabilities[key], dict)
        for key in ("prompts", "resources")
    ):
        raise DiscoveryError("invalid MCP server capabilities")
    if not isinstance(server_info, dict) or not all(
        isinstance(server_info.get(k), str) for k in ("name", "version")
    ):
        raise DiscoveryError("invalid MCP server implementation identity")
    instructions = hello.get("instructions")
    if instructions is not None and not isinstance(instructions, str):
        raise DiscoveryError("invalid MCP server instructions")
    try:
        check_json_budget(capabilities, maximum=MAX_SCHEMA_BYTES)
        check_json_budget(server_info, maximum=MAX_SCHEMA_BYTES)
        identity = hash_canonical(
            {"profile": IDENTITY_PROFILE, "serverInfo": server_info, "capabilities": capabilities}
        )
        shown_info = redact_metadata(
            {key: server_info[key] for key in ("name", "title", "version") if key in server_info},
            secrets,
        )
        shown_capabilities = redact_metadata(capabilities, secrets)
    except (ValueError, TypeError, RecursionError) as exc:
        raise DiscoveryError(
            "MCP server identity or capabilities exceed the validation budget"
        ) from exc
    if not all(isinstance(value, str) for value in shown_info.values()):
        raise DiscoveryError("invalid MCP server implementation identity")
    return ServerHello(negotiated, shown_info, shown_capabilities, instructions, identity)


def _tool(raw: Any, secrets: list[str]) -> ObservedTool:
    return _observed_tool(check_served_tool(raw, secrets))


def _observed_tool(checked: CheckedDescriptor) -> ObservedTool:
    lints = [
        "Server metadata and annotations are unverified declarations; no capability was authorized."
    ]
    if checked.unprofiled_fields:
        lints.append(
            "Descriptor members outside the tool fingerprint profile are bound by the full "
            "digest and the server declaration digest."
        )
    if checked.display_differs:
        lints.append(
            "The displayed descriptor omits or reduces content that the digests cover; "
            "review the original descriptor before approving it."
        )
    return ObservedTool(
        checked.display["name"],
        checked.display,
        checked.observed_hash,
        lints,
        fingerprint=checked.fingerprint,
        display_differs=checked.display_differs,
        unprofiled_fields=list(checked.unprofiled_fields),
    )


# A session identifier shorter than this is not a credential worth guarding, and it
# would occur by chance in ordinary declarations.
MIN_GUARDED_SESSION_ID = 8


def _repeats(value: Any, text: str) -> bool:
    """Whether ``text`` occurs in any string or key of a JSON value."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if text in item:
                return True
        elif isinstance(item, dict):
            pending.extend(item)
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return False


def _mask_exact(value: Any, secrets: list[str]) -> Any:
    """Mask only the exact credential values; the raw review copy keeps everything else."""
    if isinstance(value, str):
        for secret in secrets:
            value = value.replace(secret, "***")
        return value
    if isinstance(value, dict):
        return {_mask_exact(k, secrets): _mask_exact(v, secrets) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask_exact(item, secrets) for item in value]
    return value


def _client_field(value: str | None, *, optional: bool = False) -> str | None:
    if value is None and optional:
        return None
    if (
        not isinstance(value, str)
        or not 1 <= len(value) <= 256
        or any(not 0x20 <= ord(c) <= 0x7E for c in value)
    ):
        raise DiscoveryError("invalid client identity")
    return value


def discover_tools(
    endpoint_url: str,
    *,
    allowed_origins: Iterable[str],
    bearer_token: str | None = None,
    transport: DiscoveryTransport | None = None,
    limits: DiscoveryLimits | None = None,
    collector_id: str = "nexus-symbiote-live-mcp",
    client_name: str = DEFAULT_CLIENT_NAME,
    client_version: str = DEFAULT_CLIENT_VERSION,
    user_agent: str | None = None,
    raw_sink: dict[str, Any] | None = None,
) -> DiscoveryResult:
    """Observe one explicitly authorized HTTP MCP endpoint without calling tools.

    Caller-supplied transport is trusted code and can bypass network destination
    checks; it exists for local fixtures or an independently controlled transport.
    It must never be selected from a repository/configuration being scanned.
    ``client_name``, ``client_version`` and ``user_agent`` let an operator present
    the identity of the production host, since a server can serve a different
    tool list to a client it recognizes as an observer. A ``raw_sink`` receives the
    unredacted server info, capabilities, instructions, tool descriptors, prompts
    and resource templates that passed intake, with only the bearer token masked,
    for review. The server's session identifier is never masked: a declaration that
    repeats an identifier of ``MIN_GUARDED_SESSION_ID`` or more characters ends the
    observation, and a shorter one is not checked.
    """
    result = DiscoveryResult()
    raw: dict[str, Any] = raw_sink if raw_sink is not None else {}
    raw.update(
        {
            "serverInfo": None,
            "capabilities": None,
            "instructions": None,
            "tools": [],
            "prompts": None,
            "resourceTemplates": None,
        }
    )
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
        client = {
            "name": _client_field(client_name) or DEFAULT_CLIENT_NAME,
            "version": _client_field(client_version) or DEFAULT_CLIENT_VERSION,
        }
        agent = _client_field(user_agent, optional=True)
        if any(bearer_token and bearer_token in value for value in (*client.values(), agent or "")):
            raise DiscoveryError("bearer credential in client identity refused")
        result.client_info, result.user_agent = client, agent
        transport = transport or PinnedHTTPTransport(max_sse_events=limits.max_sse_events)
        deadline = time.monotonic() + limits.total_timeout_seconds
        identifier = 0
        negotiated: str | None = None

        def request(
            method: str,
            params: dict[str, Any] | None = None,
            *,
            notification: bool = False,
            optional: bool = False,
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
            if negotiated is not None:
                headers["MCP-Protocol-Version"] = negotiated
            if agent is not None:
                headers["User-Agent"] = agent
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
            return _response(reply, identifier, limits, optional=optional), reply

        def listing(method: str, key: str) -> list[dict[str, Any]]:
            """Follow bounded pagination; a null or absent cursor ends the list."""
            cursor: str | None = None
            cursors: set[str] = set()
            items: list[dict[str, Any]] = []
            for _ in range(limits.max_pages):
                page, _ = request(
                    method,
                    {"cursor": cursor} if cursor is not None else {},
                    optional=method != "tools/list" and cursor is None,
                )
                values = page.get(key)
                if not isinstance(values, list) or len(values) + len(items) > limits.max_tools:
                    raise DiscoveryError("invalid list or item-count limit exceeded")
                items.extend(values)
                result.pages_observed += 1
                cursor = page.get("nextCursor")
                if cursor is None:
                    return items
                if (
                    not isinstance(cursor, str)
                    or not 1 <= len(cursor.encode()) <= limits.max_cursor_bytes
                    or cursor in cursors
                ):
                    raise DiscoveryError("invalid or repeated list cursor")
                cursors.add(cursor)
            raise DiscoveryError("list page limit exceeded")

        def check_deadline() -> None:
            if time.monotonic() > deadline:
                raise DiscoveryError("discovery session deadline exceeded")

        hello, reply = request(
            "initialize",
            {"protocolVersion": PROTOCOL_VERSION, "capabilities": {}, "clientInfo": client},
        )
        session = reply.headers.get("mcp-session-id")
        if session is not None:
            if not 1 <= len(session) <= limits.max_session_id_bytes or any(
                not 0x21 <= ord(c) <= 0x7E for c in session
            ):
                raise DiscoveryError("invalid MCP session identifier")
        # The server chooses its session identifier, so it is never a redaction pattern:
        # as one, it would let the server blank any text of its own out of the inventory
        # and the review copy while the fingerprints still bind that text. A declaration
        # that repeats the identifier ends the observation instead.
        guarded = (
            session if session is not None and len(session) >= MIN_GUARDED_SESSION_ID else None
        )

        def refuse_session(declaration: Any) -> None:
            if guarded is not None and _repeats(declaration, guarded):
                raise DiscoveryError("server declaration repeats the session identifier")

        secrets = [bearer_token] if bearer_token else []
        refuse_session(hello)
        negotiated, server_info, capabilities, instructions, identity = check_server_hello(
            hello, secrets
        )
        result.protocol_version, result.identity_hash = negotiated, identity
        result.server_info, result.server_capabilities = server_info, capabilities
        raw["serverInfo"] = _mask_exact(hello["serverInfo"], secrets)
        raw["capabilities"] = _mask_exact(hello["capabilities"], secrets)
        if instructions is not None:
            result.instructions = redact_text(instructions, secrets)
            result.instructions_hash = hash_canonical({"instructions": instructions})
            raw["instructions"] = _mask_exact(instructions, secrets)
        if session is not None:
            result.session_established = True
            result.session_digest = "sha256:" + hashlib.sha256(session.encode()).hexdigest()
        request("notifications/initialized", notification=True)
        names: set[str] = set()
        extensions: dict[str, str] = {}
        for raw_tool in listing("tools/list", "tools"):
            check_deadline()
            refuse_session(raw_tool)
            checked = check_served_tool(raw_tool, secrets)
            if checked.name in names:
                raise DiscoveryError("duplicate tool identity across discovery pages")
            names.add(checked.name)
            if checked.unprofiled_hash is not None:
                extensions[checked.name] = checked.unprofiled_hash
            result.tools.append(_observed_tool(checked))
            raw["tools"].append(_mask_exact(raw_tool, secrets))
        check_deadline()

        def surface(
            method: str, key: str, identity: str
        ) -> tuple[list[ObservedItem] | None, dict[str, str] | None]:
            observed: list[ObservedItem] = []
            digests: dict[str, str] = {}
            raw[key] = []
            try:
                raw_items = listing(method, key)
            except _MethodNotFoundError:
                # Low-level SDK servers advertise resources without implementing
                # templates; the surface is recorded as not offered, not as empty.
                result.coverage["unobserved"].append(f"{method} (declared, not implemented)")
                raw[key] = None
                return None, None
            for raw_item in raw_items:
                check_deadline()
                refuse_session(raw_item)
                item = check_listed_item(raw_item, identity, secrets)
                if item.identity in digests:
                    raise DiscoveryError("duplicate list entry identity")
                digests[item.identity] = item.digest
                item.identity = redact_text(item.identity, secrets)
                observed.append(item)
                raw[key].append(_mask_exact(raw_item, secrets))
            return observed, digests

        prompts = templates = None
        if "prompts" in hello["capabilities"]:
            result.prompts, prompts = surface("prompts/list", "prompts", "name")
        if "resources" in hello["capabilities"]:
            result.resource_templates, templates = surface(
                "resources/templates/list", "resourceTemplates", "uriTemplate"
            )
        result.declaration_hash = declaration_hash(
            instructions=instructions,
            tool_extensions=extensions,
            prompts=prompts,
            resource_templates=templates,
        )
        result.complete = True
    except DiscoveryError as exc:
        # DiscoveryError messages are fixed local diagnostics without payloads, so the
        # server's session identifier is not a redaction pattern here either.
        result.failures.append(redact_text(str(exc), protected))
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
    except Exception:
        result.failures.append(
            "Live MCP discovery stopped on an unexpected internal error; the observation is incomplete."
        )
        result.complete = False
    finally:
        result.completed_at = datetime.now(UTC).isoformat()
    return result
