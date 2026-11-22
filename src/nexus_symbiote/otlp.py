"""Bounded, allowlisted reading of OpenTelemetry trace exports in OTLP/JSON.

A trace file is a report by an agent's own instrumentation, read as hostile input: a
regular file reached without a symbolic link, at most ``MAX_TRACE_FILE_BYTES``, holding
strict I-JSON, either one ``ExportTraceServiceRequest`` object or JSON Lines with one such
object per line, as the OpenTelemetry Collector's file exporter writes. Every level that
is read is type-checked; a malformed structure is an error that names the file's position
and the structural problem, never a value.

Only the identifier attributes in ``IDENTIFIERS`` are read, from span and resource
attributes, and ``service.name`` from resource attributes. A span carries GenAI or MCP
semantics only through a ``gen_ai.*`` or ``mcp.*`` attribute of its own: resource
attributes apply beneath such spans and never make a span count, so a resource that
names an agent cannot pass off spans from which the GenAI instrumentation is missing.
Content attributes, which can hold prompts, messages, tool arguments and results, are
recognized by key and their values are never read. An identifier is used only when it
is a string of at most ``MAX_IDENTIFIER_CHARS`` characters that the redactor leaves
unchanged; any other value is kept only as the reason it was not used. Span names,
events, links and status are not read.

Reading establishes what the instrumentation reported, not that an operation happened,
and nothing about operations it did not report.
"""

from __future__ import annotations

import errno
import functools
import re
from collections import Counter
from collections.abc import Iterator, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize

MAX_TRACE_FILES = 16
MAX_TRACE_FILE_BYTES = 64 * 1024 * 1024
MAX_LINE_BYTES = 16 * 1024 * 1024
MAX_SPANS = 1_000_000
MAX_IDENTIFIER_CHARS = 512
MAX_ATTRIBUTES = 128
SPAN_KIND_CLIENT = 3

IDENTIFIERS = frozenset(
    {
        "gen_ai.operation.name",
        "gen_ai.provider.name",
        "gen_ai.system",
        "gen_ai.request.model",
        "gen_ai.response.model",
        "gen_ai.agent.id",
        "gen_ai.agent.name",
        "gen_ai.agent.version",
        "gen_ai.tool.name",
        "gen_ai.tool.type",
        "gen_ai.data_source.id",
        "gen_ai.memory.store.id",
        "gen_ai.skill.name",
        "gen_ai.prompt.name",
        "mcp.method.name",
        "mcp.protocol.version",
        "network.transport",
        "server.address",
        "server.port",
        "spiffe.id",
        "peer.identity",
        "gen_ai.tool.definition_hash",
    }
)
SERVICE_NAME = "service.name"

# Content attributes of the GenAI semantic conventions, with the legacy indexed
# gen_ai.prompt.N.* and gen_ai.completion.N.* forms. gen_ai.prompt.name and
# gen_ai.prompt.version are identifiers, and gen_ai.retrieval.top_k is a number.
CONTENT_ATTRIBUTES = frozenset(
    {
        "gen_ai.input.messages",
        "gen_ai.output.messages",
        "gen_ai.system_instructions",
        "gen_ai.tool.definitions",
        "gen_ai.tool.call.arguments",
        "gen_ai.tool.call.result",
        "gen_ai.tool.description",
        "gen_ai.agent.description",
        "gen_ai.main_agent.description",
        "gen_ai.skill.description",
        "gen_ai.memory.records",
        "gen_ai.memory.query.text",
        "gen_ai.evaluation.explanation",
        "gen_ai.prompt",
        "gen_ai.completion",
    }
)
_CONTENT_PREFIXES = ("gen_ai.prompt.", "gen_ai.completion.", "gen_ai.retrieval.")
_NOT_CONTENT = frozenset({"gen_ai.prompt.name", "gen_ai.prompt.version", "gen_ai.retrieval.top_k"})

GENAI_OPERATIONS = frozenset(
    {
        "chat",
        "generate_content",
        "realtime_inference",
        "user_speech",
        "text_completion",
        "embeddings",
        "retrieval",
        "fetch_response",
        "create_agent",
        "invoke_agent",
        "execute_tool",
        "invoke_workflow",
        "invoke_runner",
        "plan",
        "search_memory",
        "create_memory",
        "update_memory",
        "upsert_memory",
        "delete_memory",
        "create_memory_store",
        "delete_memory_store",
    }
)
MCP_METHODS = frozenset(
    {
        "notifications/cancelled",
        "initialize",
        "notifications/initialized",
        "notifications/progress",
        "ping",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "notifications/resources/list_changed",
        "resources/subscribe",
        "resources/unsubscribe",
        "notifications/resources/updated",
        "prompts/list",
        "prompts/get",
        "notifications/prompts/list_changed",
        "tools/list",
        "tools/call",
        "notifications/tools/list_changed",
        "logging/setLevel",
        "notifications/message",
        "sampling/createMessage",
        "completion/complete",
        "roots/list",
        "notifications/roots/list_changed",
        "elicitation/create",
    }
)

_VALUE_TYPES = (
    "stringValue",
    "boolValue",
    "intValue",
    "doubleValue",
    "arrayValue",
    "kvlistValue",
    "bytesValue",
)
_NOT_WHITESPACE = re.compile(rb"[^ \t\r\n]")
_SURROGATE = re.compile("[\ud800-\udfff]")
_DECIMAL = re.compile(r"[0-9]{1,20}")
_PORT = re.compile(r"[0-9]{1,5}")
_TRIM = " \t\r\n"
_MAX_UINT64 = 2**64 - 1
_MIB = 1024 * 1024
_NOT_JSON = object()
_STRICT_JSON = (
    "is not strict JSON: one OTLP/JSON object, or JSON Lines with one object per line; "
    "duplicate keys, non-finite numbers and integers beyond 2^53 are refused (OTLP/JSON writes "
    "64-bit values as strings)"
)


class TraceInputError(ValueError):
    """A trace file was refused; the message names its position and the problem only."""

    def __init__(self, index: int, problem: str) -> None:
        super().__init__(f"trace file {index} {problem}")


class _MalformedError(Exception):
    """A structural problem, named by its JSON path and never by a value."""


@dataclass(frozen=True)
class Unreadable:
    """An identifier that was present but not used: ``invalid``, ``oversized`` or ``withheld``."""

    reason: str


Identifier = str | Unreadable


@dataclass(frozen=True)
class Span:
    """The identifiers one span reports, its own above those of its resource.

    A span without a GenAI or MCP attribute of its own reports none.
    """

    file: int
    kind: int
    start: int | None
    attributes: Mapping[str, Identifier]
    service: Identifier | None


@dataclass
class TraceFile:
    """One trace file as read: its position among the arguments, base name and digest."""

    index: int
    name: str
    size: int
    sha256: str
    form: str = ""
    records: int = 0
    spans: int = 0


def file_name(path: Path) -> str:
    """A file's base name as neutralized text; a byte that is not UTF-8 becomes U+FFFD.

    The file system decodes such a byte to a lone surrogate, which I-JSON refuses.
    """
    return neutralize(_SURROGATE.sub("\ufffd", path.name))


def is_content(key: str) -> bool:
    """Whether an attribute key names content (messages, prompts, tool arguments, results)."""
    if key in CONTENT_ATTRIBUTES or (key.startswith("gen_ai.") and key.endswith("_ref")):
        return True
    return key.startswith(_CONTENT_PREFIXES) and key not in _NOT_CONTENT


def _open_problem(exc: OSError) -> str:
    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        return (
            "is reached through a symbolic link or a path component that is not a "
            "directory; trace files are read without following links"
        )
    if exc.errno is None:
        return "is not a regular file; FIFOs, devices, directories and standard input are refused"
    if exc.errno == errno.ENOENT:
        return "does not exist"
    if exc.errno in {errno.EACCES, errno.EPERM}:
        return "cannot be read: permission denied"
    return "cannot be opened for reading"


def _parse(raw: bytes, maximum: int) -> Any:
    return parse_json_strict(raw.decode("utf-8"), max_bytes=maximum)


def _parse_problem(exc: BaseException) -> str:
    if isinstance(exc, RecursionError):
        return "is nested too deeply to read"
    if isinstance(exc, UnicodeError):
        return "is not UTF-8 text"
    return _STRICT_JSON


@functools.lru_cache(maxsize=4096)
def _credential_shaped(text: str) -> bool:
    # The redactor's rules decide: a credential format, a credential assignment, an
    # authorization scheme, or a URL with user information, path, query or fragment.
    # The cache is bounded, so distinct hostile values cost time, not memory.
    return redact_text(text) != text


def _attempt(line: bytes) -> Any:
    try:
        return _parse(line, MAX_LINE_BYTES)
    except (UnicodeError, ValueError, RecursionError):
        return _NOT_JSON


def _whole(raw: bytes, index: int, *, long_first_line: bool = False) -> Any:
    try:
        return _parse(raw, MAX_TRACE_FILE_BYTES)
    except (UnicodeError, ValueError, RecursionError) as exc:
        problem = _parse_problem(exc)
        if long_first_line and problem == _STRICT_JSON:
            problem = (
                "is not one JSON document, and its first line exceeds the "
                f"{MAX_LINE_BYTES // _MIB} MiB JSON Lines bound"
            )
        raise TraceInputError(index, problem) from None


def _object(value: object, where: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise _MalformedError(f"{where} must be an object")
    return value


def _optional_object(value: object, where: str) -> dict[str, Any]:
    return {} if value is None else _object(value, where)


# Span containers under a name this reader does not read: the pre-1.0 OTLP name and the
# proto field names, which proto3 JSON parsers also accept. Skipping them would hide their
# spans while a sibling entry's spans still let the gate pass.
_UNREAD_CONTAINERS = frozenset(
    {
        "resource_spans",
        "scope_spans",
        "instrumentationLibrarySpans",
        "instrumentation_library_spans",
    }
)


def _refuse_unread_containers(value: dict[str, Any], where: str) -> None:
    unread = sorted(_UNREAD_CONTAINERS.intersection(value))
    if unread:
        raise _MalformedError(f"{where} holds {unread[0]}, which is not read; use scopeSpans")


def _optional_list(value: object, where: str) -> list[Any]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise _MalformedError(f"{where} must be an array")
    return value


def _kind(value: object, where: str) -> int:
    if value is None:
        return 0
    if isinstance(value, bool) or not isinstance(value, int):
        raise _MalformedError(f"{where}.kind must be an integer")
    return value


def _start(value: object, where: str) -> int | None:
    if value is None:
        return None
    number: int | None = None
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and _DECIMAL.fullmatch(value):
        number = int(value)
    if number is None or not 0 <= number <= _MAX_UINT64:
        raise _MalformedError(f"{where}.startTimeUnixNano must be a decimal number of nanoseconds")
    return number or None


def _port(value: Mapping[str, Any]) -> Identifier:
    number = value.get("intValue", value.get("stringValue"))
    if isinstance(number, str) and _PORT.fullmatch(number):
        number = int(number)
    if isinstance(number, bool) or not isinstance(number, int) or not 1 <= number <= 65535:
        return Unreadable("invalid")
    return str(number)


def _documents(raw: bytes, record: TraceFile) -> Iterator[tuple[int | None, Any]]:
    """Each parsed object with its line number, or with None for a one-document file.

    The form is detected from the bytes: a file whose first non-blank line is JSON by
    itself and which has further non-blank lines is JSON Lines; any other file must be
    one JSON document.
    """
    first = _NOT_WHITESPACE.search(raw)
    if first is None:
        raise TraceInputError(record.index, "holds no JSON")
    start = raw.rfind(b"\n", 0, first.start()) + 1
    end = raw.find(b"\n", first.start())
    end = len(raw) if end < 0 else end
    parsed = _NOT_JSON
    if _NOT_WHITESPACE.search(raw, end) is not None:
        if end - start > MAX_LINE_BYTES:
            record.form = "json"
            yield None, _whole(raw, record.index, long_first_line=True)
            return
        parsed = _attempt(raw[start:end])
    if parsed is _NOT_JSON:
        record.form = "json"
        yield None, _whole(raw, record.index)
        return
    record.form = "json-lines"
    number = raw.count(b"\n", 0, start) + 1
    yield number, parsed
    position = end + 1
    while position < len(raw):
        number += 1
        end = raw.find(b"\n", position)
        end = len(raw) if end < 0 else end
        line = raw[position:end]
        position = end + 1
        if _NOT_WHITESPACE.search(line) is None:
            continue
        if len(line) > MAX_LINE_BYTES:
            raise TraceInputError(
                record.index,
                f"line {number} exceeds the {MAX_LINE_BYTES // _MIB} MiB JSON Lines bound",
            )
        try:
            yield number, _parse(line, MAX_LINE_BYTES)
        except (UnicodeError, ValueError, RecursionError) as exc:
            raise TraceInputError(record.index, f"line {number} {_parse_problem(exc)}") from None


class TraceReader:
    """Read trace files one after another under shared bounds, recording what was read.

    ``read`` yields the identifiers of each span and appends the file's record to
    ``files``; the counters cover every span read so far. A refusal raises
    ``TraceInputError``, and a reader that raised must not be used further.
    """

    def __init__(self) -> None:
        self.files: list[TraceFile] = []
        self.resource_spans = 0
        self.spans = 0
        self.semantic_spans = 0
        self.content_spans = 0
        self.lists_over_bound = 0
        self.unreadable: Counter[str] = Counter()

    def read(self, path: Path) -> Iterator[Span]:
        index = len(self.files) + 1
        if index > MAX_TRACE_FILES:
            raise TraceInputError(index, f"exceeds the bound of {MAX_TRACE_FILES} trace files")
        try:
            with open_regular_file(path) as stream:
                raw = stream.read(MAX_TRACE_FILE_BYTES + 1)
        except OSError as exc:
            raise TraceInputError(index, _open_problem(exc)) from None
        if len(raw) > MAX_TRACE_FILE_BYTES:
            raise TraceInputError(
                index, f"exceeds the {MAX_TRACE_FILE_BYTES // _MIB} MiB trace file bound"
            )
        record = TraceFile(index, file_name(path), len(raw), hash_bytes(raw))
        self.files.append(record)
        for line, document in _documents(raw, record):
            try:
                yield from self._spans(document, record)
            except _MalformedError as exc:
                at = "" if line is None else f" at line {line}"
                raise TraceInputError(index, f"is malformed{at}: {exc}") from None

    def _spans(self, document: Any, record: TraceFile) -> Iterator[Span]:
        if not isinstance(document, dict) or not isinstance(document.get("resourceSpans"), list):
            raise _MalformedError(
                "the object has no resourceSpans array; it is not an OTLP/JSON export"
            )
        _refuse_unread_containers(document, "the document")
        record.records += 1
        for i, resource_spans in enumerate(document["resourceSpans"]):
            path = f"resourceSpans[{i}]"
            entry = _object(resource_spans, path)
            _refuse_unread_containers(entry, path)
            resource = _optional_object(entry.get("resource"), f"{path}.resource")
            values, content, _ = self._attributes(
                resource.get("attributes"), f"{path}.resource.attributes", resource=True
            )
            service = values.pop(SERVICE_NAME, None)
            self.resource_spans += 1
            scopes = _optional_list(entry.get("scopeSpans"), f"{path}.scopeSpans")
            for j, scope_spans in enumerate(scopes):
                scope_path = f"{path}.scopeSpans[{j}]"
                scope = _object(scope_spans, scope_path)
                for k, raw_span in enumerate(
                    _optional_list(scope.get("spans"), f"{scope_path}.spans")
                ):
                    span_path = f"{scope_path}.spans[{k}]"
                    span = _object(raw_span, span_path)
                    if self.spans >= MAX_SPANS:
                        raise TraceInputError(
                            record.index,
                            f"exceeds the bound of {MAX_SPANS:,} spans across all trace files",
                        )
                    self.spans += 1
                    record.spans += 1
                    kind = _kind(span.get("kind"), span_path)
                    start = _start(span.get("startTimeUnixNano"), span_path)
                    own, own_content, semantic = self._attributes(
                        span.get("attributes"), f"{span_path}.attributes", resource=False
                    )
                    if content or own_content:
                        self.content_spans += 1
                    if semantic:
                        self.semantic_spans += 1
                    reported = {**values, **own} if semantic else {}
                    yield Span(record.index, kind, start, reported, service)

    def _attributes(
        self, entries: object, where: str, *, resource: bool
    ) -> tuple[dict[str, Identifier], bool, bool]:
        """Read at most MAX_ATTRIBUTES entries; values are read only for identifiers."""
        listed = _optional_list(entries, where)
        if len(listed) > MAX_ATTRIBUTES:
            self.lists_over_bound += 1
        values: dict[str, Identifier] = {}
        keys: set[str] = set()
        content = semantic = False
        for position, item in enumerate(listed[:MAX_ATTRIBUTES]):
            entry = _object(item, f"{where}[{position}]")
            key = entry.get("key")
            if not isinstance(key, str):
                raise _MalformedError(f"{where}[{position}].key must be a string")
            if key in keys:
                raise _MalformedError(f"{where} repeats an attribute key")
            keys.add(key)
            value = _optional_object(entry.get("value"), f"{where}[{position}].value")
            semantic = semantic or key.startswith(("gen_ai.", "mcp."))
            if is_content(key):
                content = True
            elif key in IDENTIFIERS or (resource and key == SERVICE_NAME):
                if sum(name in value for name in _VALUE_TYPES) > 1:
                    raise _MalformedError(f"{where}[{position}].value sets more than one type")
                values[key] = self._identifier(key, value)
        return values, content, semantic

    def _identifier(self, key: str, value: Mapping[str, Any]) -> Identifier:
        result = (
            _port(value)
            if key == "server.port"
            else self._text(
                value.get("stringValue"),
                allow_spiffe=key in ("spiffe.id", "peer.identity"),
            )
        )
        if isinstance(result, Unreadable):
            self.unreadable[result.reason] += 1
        return result

    def _text(self, value: object, *, allow_spiffe: bool = False) -> Identifier:
        if not isinstance(value, str):
            return Unreadable("invalid")
        if len(value) > MAX_IDENTIFIER_CHARS:
            return Unreadable("oversized")
        text = value.strip(_TRIM)
        if not text:
            return Unreadable("invalid")
        if (
            allow_spiffe
            and re.fullmatch(r"spiffe://[a-z0-9._-]+(?:/[A-Za-z0-9._-]+)+", text)
            and not _credential_shaped(text.removeprefix("spiffe://"))
        ):
            return text
        return Unreadable("withheld") if _credential_shaped(text) else text
