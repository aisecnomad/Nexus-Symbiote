"""MCP and agent SDK references in Python, TypeScript and JavaScript, found without running it.

Only files that contain an SDK marker are parsed: the MCP SDK, or for Python one of
the agent frameworks whose tools are collected. Finding them is a streaming search
under the collector's source budget, so unrelated source files appear nowhere in the
inventory, and plain ASCII ones that fit the budget never fail the collector. Python
source is searched as CPython reads it: decoded as its encoding declaration says, also
as ``python -x`` reads it, with identifiers compared in NFKC form. A declaration whose
decoding static reading cannot follow is a failure. TypeScript and JavaScript, in
every suffix tsc reads, are searched as tsc reads them: UTF-16 after a UTF-16 byte
order mark, otherwise UTF-8. A Python module of the MCP SDK that a dynamic import
names in literals, and an MCP server that application code starts or connects to,
are gaps: the server is not inventoried. A file is listed as a scanned surface only
when it produced a component, a gap or a failure. Every limit that stops collection
is a scan failure naming the limit.
"""

from __future__ import annotations

import ast
import codecs
import functools
import io
import re
import sys
import tokenize
import unicodedata
import warnings
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path

from nexus_symbiote import limits
from nexus_symbiote.core.enums import TrustTier
from nexus_symbiote.core.models import MCPClientComponent
from nexus_symbiote.scanners.base import KnownValues, ScanResult, SourceBudget, parse_python
from nexus_symbiote.scanners.mcp import without_js_comments
from nexus_symbiote.scanners.python_tools import (
    _AGENT_FACTORIES,
    _DECORATOR_IMPORTS,
    _FACTORIES,
    PYTHON_TOOL_HINTS,
    SDK_IMPORT_ROOTS,
    _annotation_names,
    _PassiveModule,
    _ProjectImports,
    collect_python_tools,
)
from nexus_symbiote.scanners.ts_tools import (
    LAUNCHED,
    NOT_SOURCE_NAMES,
    REACHED,
    SCRIPT_SUFFIXES,
    SOURCE_MARKERS,
    UTF16_BYTE_ORDER_MARKS,
    collect_typescript_source,
    is_analysis_candidate,
    is_server_source,
    source_text,
)
from nexus_symbiote.utils.confined import (
    CollectionError,
    ConfinedCollection,
    fold_name,
    recorded_count,
)

_SDK_IMPORT = re.compile(
    r"(?:\bfrom\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"']|"
    r"\brequire\s*\(\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"'])"
)

# Test, build output, documentation and example trees are not searched, so code
# that only illustrates an SDK never fails the collector.
SOURCE_SEARCH_SKIPPED = frozenset(
    {"tests", "test", "dist", "build", "docs", "benchmarks", "examples"}
)
# The launcher names below, like the server class names among the tool hints, are
# markers too, so a file that reaches one through a module of its own project, without
# naming the SDK, is read.
_PYTHON_MARKERS = (
    *PYTHON_TOOL_HINTS,
    "MCPClient",
    "StdioServerParameters",
    "sse_client",
    "stdio_client",
    "streamablehttp_client",
    "streamable_http_client",
    "websocket_client",
)
# Imports the tool collector reads from the syntax tree once a marker is present.
_FRAMEWORK_IMPORTS = frozenset({*_DECORATOR_IMPORTS, *_AGENT_FACTORIES})
_FRAMEWORK_MODULES = frozenset(module for module, _ in _FRAMEWORK_IMPORTS)
_PYTHON_NEEDLES = frozenset(marker.encode() for marker in _PYTHON_MARKERS)
_CLIENT_MARKER = b"@modelcontextprotocol/sdk"
_NEEDLES = (*_PYTHON_NEEDLES, *SOURCE_MARKERS, _CLIENT_MARKER)
_OVERLAP = max(len(needle) for needle in _NEEDLES) - 1
# Earlier releases read only these, and hold a root-level one to valid UTF-8.
_CHECKED_SUFFIXES = frozenset({".ts", ".js"})
# Client references are listed by suffix, .ts and .js first as before.
_CLIENT_SUFFIXES = (".ts", ".js", *sorted(SCRIPT_SUFFIXES - {".ts", ".js"}))
_SCRIPT_MARKERS = {needle.decode(): needle for needle in (*SOURCE_MARKERS, _CLIENT_MARKER)}
_TEXT_OVERLAP = max(len(marker) for marker in _SCRIPT_MARKERS) - 1
_CHUNK_BYTES = 1024 * 1024
_LINE = re.compile(rb"([^\r\n]*)(\r\n|\r|\n)?")
_MAY_DECLARE = re.compile(rb"[ \t\f]*(?:#|\Z)")
_LINE_END = re.compile(rb"[\r\n]")
# tokenize's declaration expression; bytes patterns match ASCII names only, as CPython does.
_COOKIE = re.compile(rb"[ \t\f]*#.*?coding[:=][ \t]*([-\w.]+)")
_LATIN_1 = ("latin-1", "iso-8859-1", "iso-latin-1")
# Longer than any codec name or alias. A lookup costs time per character, and the
# codec registry keeps every name it failed to find for the life of the process.
_MAX_CODEC_NAME = 64
_FOLD_SLICE = 4096
_FOLD_TAIL = max(len(marker) for marker in _PYTHON_MARKERS) - 1
# A codec that decodes each probe to its ASCII reading has no shift state (UTF-7,
# ISO-2022, HZ), escape syntax (unicode_escape), label syntax (IDNA, punycode) or
# non-ASCII byte order (UTF-16, EBCDIC). The stdlib codecs that pass are single-byte
# code pages and stateless multibyte codecs, all linear, line-independent C decoders.
_ASCII_PROBES = (
    b"+AG0-",
    b"\\x6d\\u006d\\155",
    b"\x1b$B#M\x1b(B",
    b"\x1b$)C\x0e#M\x0f",
    b"~{#M~}",
    b"xn--ls8h",
    bytes(range(128)),
)
_INVALID_UTF8 = "invalid UTF-8"
_INVALID_DECLARED = "invalid text for its declared source encoding"
_UNSUPPORTED_ENCODING = "unsupported source encoding declaration"
_LAUNCHED_OR_REACHED = "MCP servers launched or reached from application code; not inventoried"
_SERVER_LOADED = "MCP server module loaded dynamically; tools not inventoried"
_CLIENT_LOADED = "MCP client module loaded dynamically; launched servers not inventoried"
_LAUNCHER_PASSED_ON = (
    "MCP launcher imported without a use here; servers started or reached through it "
    "elsewhere not inventoried"
)
_LAUNCHER_ELSEWHERE = (
    "MCP launcher imported from a module other than its package; servers started or "
    "reached through it not inventoried"
)
_SERVER_CLASS_ELSEWHERE = (
    "MCP server class imported from a module the collector does not recognize as its "
    "own; servers built from it not inventoried"
)
_SERVER_CLASS_ATTRIBUTE = (
    "MCP server class reached as an attribute; servers built from it not inventoried"
)
# Python classes and functions that start an MCP server process or connect to one,
# with the packages that export them: the MCP SDK, the OpenAI Agents SDK, PydanticAI
# and LangChain's MCP adapters.
_PYTHON_LAUNCHERS = {
    "StdioServerParameters": (frozenset({"mcp"}), LAUNCHED),
    "sse_client": (frozenset({"mcp"}), REACHED),
    "stdio_client": (frozenset({"mcp"}), LAUNCHED),
    "streamablehttp_client": (frozenset({"mcp"}), REACHED),
    "streamable_http_client": (frozenset({"mcp"}), REACHED),
    "websocket_client": (frozenset({"mcp"}), REACHED),
    "MCPServerStdio": (frozenset({"agents", "pydantic_ai"}), LAUNCHED),
    "MCPServerSse": (frozenset({"agents"}), REACHED),
    "MCPServerStreamableHttp": (frozenset({"agents"}), REACHED),
    "MCPServerSSE": (frozenset({"pydantic_ai"}), REACHED),
    "MCPServerHTTP": (frozenset({"pydantic_ai"}), REACHED),
    "MCPServerStreamableHTTP": (frozenset({"pydantic_ai"}), REACHED),
    "MultiServerMCPClient": (frozenset({"langchain_mcp_adapters"}), _LAUNCHED_OR_REACHED),
}
# A launcher class name is distinctive enough to be a gap as an attribute of any
# value; a launcher function, such as ``sse_client``, only of an imported name.
_LAUNCHER_CLASSES = frozenset(name for name in _PYTHON_LAUNCHERS if not name.islower())
# Python MCP server classes, with the exact modules a file may import them from: those
# the tool collector reads servers from, and the Agents SDK and PydanticAI client
# packages, whose MCPServer is a base class. Any other module, a submodule of the
# same package included, is a gap.
_SERVER_CLASSES = {
    "FastMCP": frozenset(module for module, name in _FACTORIES if name == "FastMCP"),
    "MCPServer": frozenset(
        {
            *(module for module, name in _FACTORIES if name == "MCPServer"),
            "agents.mcp",
            "pydantic_ai.mcp",
        }
    ),
}
_CLIENT_MODULES = ("mcp.client", "agents.mcp", "pydantic_ai.mcp", "langchain_mcp_adapters")
_LOADERS = frozenset({"import_module", "__import__", "resolve_name"})
_LOADER_MODULES = frozenset({"importlib", "builtins", "pkgutil"})
# Builtins and attributes that rebind a name or a module attribute without naming it.
_REBINDING_BUILTINS = frozenset(
    {"globals", "locals", "vars", "exec", "eval", "setattr", "delattr", "__builtins__", "modules"}
)
_REBINDING_ATTRIBUTES = frozenset(
    {"modules", "__dict__", "__setattr__", "__builtins__", "__globals__"}
)


class _UnreadableError(ValueError):
    """A source cannot be read the way Python would read it; the message names why."""


class _BudgetSpentError(Exception):
    """The source budget ran out during a read; the budget recorded the one failure."""


@functools.cache
def _keeps_ascii(codec: str) -> bool:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        try:
            return all(probe.decode(codec) == probe.decode("ascii") for probe in _ASCII_PROBES)
        except (LookupError, ValueError):
            return False


def _declaration_lines(head: bytes, *, complete: bool) -> list[bytes]:
    """The lines CPython searches for an encoding declaration, split by universal newlines.

    CPython reads a second line only after a blank or comment first line. When
    ``head`` is only the start of a file and a declaration could still follow
    beyond it, the codec is unknown and the file is refused.
    """
    lines: list[bytes] = []
    position = 0
    while len(lines) < 2:
        match = _LINE.match(head, position)
        if match is None:
            break
        text = match.group(1)
        may_declare = bool(_MAY_DECLARE.match(text.removeprefix(codecs.BOM_UTF8)))
        if match.group(2) is None and not complete and may_declare:
            raise _UnreadableError(limits.bound("file-bytes").exceeded())
        if match.end() == position:
            break
        lines.append(text + b"\n")
        position = match.end()
        if not may_declare:
            break
    return lines


@dataclass(frozen=True)
class _Skipped:
    """The line ``python -x`` searches for a declaration, and whether all of it was read.

    The option skips through the first line feed, whatever the file's line endings,
    and reads what follows as a second line, so that line can declare a codec even
    after a first line of code.
    """

    line: bytes
    whole: bool


def _skipped_line(content: bytes) -> _Skipped | None:
    """The ``python -x`` declaration line of a complete file; None when -x skips all of it."""
    start = content.find(b"\n") + 1
    if not start:
        return None
    match = _LINE.match(content, start)
    return _Skipped(b"" if match is None else match.group(1), True)


def _declared_codec(line: bytes) -> str | None:
    """The codec name one line declares, normalized as CPython normalizes it, or None."""
    match = _COOKIE.match(line)
    if match is None:
        return None
    name = match.group(1).decode("ascii")
    folded = name[:12].lower().replace("_", "-")
    if folded == "utf-8" or folded.startswith("utf-8-"):
        return "utf-8"
    if folded in _LATIN_1 or folded.startswith(tuple(f"{prefix}-" for prefix in _LATIN_1)):
        return "iso-8859-1"
    if len(name) > _MAX_CODEC_NAME:
        raise _UnreadableError(_UNSUPPORTED_ENCODING)
    return name


def _followed(encoding: str) -> str:
    """The codec's canonical name when static reading follows it; any other is refused."""
    try:
        name = codecs.lookup(encoding).name
    except LookupError:
        raise _UnreadableError(_UNSUPPORTED_ENCODING) from None
    if not _keeps_ascii(name):
        raise _UnreadableError(_UNSUPPORTED_ENCODING)
    return "utf-8" if name == "utf-8-sig" else name


def _source_encoding(
    head: bytes, *, complete: bool, skipped: _Skipped | None
) -> tuple[str, str | None]:
    """The codecs CPython decodes a Python source with, when static reading can follow them.

    The first decodes the file when it is imported or run; the second, a canonical
    name, decodes what ``python -x`` runs, and is None when that option leaves
    nothing. Only codecs that read ASCII as ASCII are followed. A script run
    directly and a module imported then decode the file alike, so the text searched
    and parsed here is the text CPython runs; any other declaration is refused.
    """
    lines = _declaration_lines(head, complete=complete)
    if skipped is not None and not skipped.whole and _MAY_DECLARE.match(skipped.line):
        raise _UnreadableError(limits.bound("file-bytes").exceeded())
    # Refuse a name too long to be a codec before anything looks it up.
    for index, line in enumerate(lines):
        _declared_codec(line.removeprefix(codecs.BOM_UTF8) if index == 0 else line)
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(b"".join(lines)).readline)
    except SyntaxError:
        try:
            b"".join(lines).decode("utf-8")
        except UnicodeDecodeError:
            raise _UnreadableError(_INVALID_UTF8) from None
        raise _UnreadableError(_UNSUPPORTED_ENCODING) from None
    _followed(encoding)
    if skipped is None:
        return encoding, None
    return encoding, _followed(_declared_codec(skipped.line) or "utf-8")


def _python_text(content: bytes) -> str:
    """The text CPython compiles from one complete Python source file."""
    encoding, skipped = _source_encoding(content, complete=True, skipped=_skipped_line(content))
    try:
        text = content.decode(encoding)
    except UnicodeDecodeError:
        utf8 = encoding in {"utf-8", "utf-8-sig"}
        raise _UnreadableError(_INVALID_UTF8 if utf8 else _INVALID_DECLARED) from None
    if skipped is None or skipped == _followed(encoding):
        return text
    rest = content[content.index(b"\n") :]
    if rest.isascii():
        return text
    # python -x decodes the rest in another codec. A second reading that names the
    # SDK could declare servers and tools this text does not show.
    try:
        other = rest.decode(skipped)
    except UnicodeDecodeError:
        return text
    if _names_sdk(other):
        raise _UnreadableError(_UNSUPPORTED_ENCODING)
    return text


def _names_sdk(text: str) -> bool:
    """Whether Python could read an SDK marker in this text, folding identifiers to NFKC.

    Every run of ASCII letters that NFKC gives an identifier is already adjacent in
    the NFKD form, which neither moves nor merges letters. Decomposing a slice at a
    time keeps a hostile character's expansion (up to 18 characters each) to one
    slice instead of the whole text.
    """
    if any(marker in text for marker in _PYTHON_MARKERS):
        return True
    if text.isascii() or unicodedata.is_normalized("NFKC", text):
        return False
    tail = ""
    for start in range(0, len(text), _FOLD_SLICE):
        window = tail + unicodedata.normalize("NFKD", text[start : start + _FOLD_SLICE])
        if any(marker in window for marker in _PYTHON_MARKERS):
            return True
        tail = window[-_FOLD_TAIL:]
    return False


def _client_reference(text: str) -> bool:
    # A bounded syntax hint, never a claim that an SDK is installed or deployed.
    return bool(_SDK_IMPORT.search(without_js_comments(text)))


def _python_client(tree: ast.Module) -> bool:
    return any(
        isinstance(node, ast.ImportFrom)
        and node.module is not None
        and node.module.split(".")[0] == "mcp"
        and any("Client" in alias.name for alias in node.names)
        for node in ast.walk(tree)
    ) or any(
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "MCPClient"
        for node in ast.walk(tree)
    )


def _server_module(name: str) -> bool:
    parts = name.split(".")
    return parts[0] == "fastmcp" or parts[:2] == ["mcp", "server"]


@dataclass(frozen=True)
class _Source:
    """What one streaming search found: the file's first bytes, its size and its markers.

    ``error`` says why a root-level script that is not a candidate still fails.
    """

    head: bytes
    size: int
    found: frozenset[bytes]
    ascii: bool
    skipped: _Skipped | None = None
    error: str | None = None

    @property
    def complete(self) -> bool:
        return len(self.head) == self.size


class _Markers:
    """The SDK markers in one source stream, searched in the text its tools read.

    Python is searched by bytes, and the line ``python -x`` would search for a
    declaration is kept, up to ``keep`` bytes. A script that starts with a UTF-16
    byte order mark is searched in its decoded text, as tsc reads it: a lone
    surrogate stays and a trailing odd byte is ignored. Any other root-level script
    is checked to be valid UTF-8, as earlier releases required.
    """

    def __init__(self, path: Path, keep: int) -> None:
        script = path.suffix in SCRIPT_SUFFIXES
        self.found: set[bytes] = set()
        self.ascii = True
        self.utf8 = True
        self._keep = keep
        self._python = path.suffix == ".py"
        self._start: bytes | None = b"" if script else None
        self._tail = b""
        self._text: codecs.IncrementalDecoder | None = None
        self._text_tail = ""
        root_script = path.suffix in _CHECKED_SUFFIXES and len(path.parts) == 1
        self._utf8 = codecs.getincrementaldecoder("utf-8")() if root_script else None
        self._after_line_feed = False
        self._skipped = bytearray()
        self._skipped_end = False
        self._skipped_whole = True

    def feed(self, chunk: bytes) -> None:
        self.ascii = self.ascii and chunk.isascii()
        if self._python:
            self._skip(chunk)
        if self._start is not None:
            # The first two bytes decide how the whole script is read.
            self._start += chunk
            if len(self._start) < 2:
                return
            chunk, self._start = self._start, None
            encoding = UTF16_BYTE_ORDER_MARKS.get(chunk[:2])
            if encoding is not None:
                self._text = codecs.getincrementaldecoder(encoding)("surrogatepass")
                self._utf8 = None
                chunk = chunk[2:]
        if self._text is not None:
            text = self._text_tail + self._text.decode(chunk)
            self.found.update(
                needle for marker, needle in _SCRIPT_MARKERS.items() if marker in text
            )
            self._text_tail = text[-_TEXT_OVERLAP:]
            return
        window = self._tail + chunk
        self.found.update(needle for needle in _NEEDLES if needle in window)
        self._tail = window[-_OVERLAP:]
        if self._utf8 is not None:
            try:
                self._utf8.decode(chunk)
            except UnicodeDecodeError:
                self.utf8 = False
                self._utf8 = None

    def close(self) -> None:
        if self._start:
            # Too short to hold a byte order mark.
            start, self._start = self._start, None
            self.feed(start)
        if self._utf8 is not None:
            try:
                self._utf8.decode(b"", final=True)
            except UnicodeDecodeError:
                self.utf8 = False

    def skipped(self) -> _Skipped | None:
        if not self._after_line_feed:
            return None
        return _Skipped(bytes(self._skipped), self._skipped_whole)

    def _skip(self, chunk: bytes) -> None:
        if self._skipped_end:
            return
        if not self._after_line_feed:
            index = chunk.find(b"\n")
            if index < 0:
                return
            self._after_line_feed = True
            chunk = chunk[index + 1 :]
        end = _LINE_END.search(chunk)
        piece = chunk if end is None else chunk[: end.start()]
        room = self._keep - len(self._skipped)
        self._skipped += piece[:room]
        if end is not None or len(piece) > room:
            self._skipped_end = True
            self._skipped_whole = len(piece) <= room


def _search(files: ConfinedCollection, path: Path, keep: int, budget: SourceBudget) -> _Source:
    """Read a file in chunks, keeping its first ``keep`` bytes and noting each marker.

    A relative symlink to a regular file in the project is read through its target.
    Every chunk is charged to the source budget. A file larger than the whole budget
    is refused alone before it is read, so it does not spend the budget.
    """
    head = bytearray()
    size = 0
    markers = _Markers(path, keep)
    # A path with no such target is opened itself, so the refusal is recorded.
    target = files.in_root_target(path) or path
    with files.open_regular(target, max_bytes=budget.bound) as stream:
        while chunk := stream.read(_CHUNK_BYTES):
            if not budget.admit(len(chunk), path):
                raise _BudgetSpentError
            size += len(chunk)
            if len(head) < keep:
                head += chunk[: keep - len(head)]
            markers.feed(chunk)
    markers.close()
    return _Source(
        bytes(head),
        size,
        frozenset(markers.found),
        markers.ascii,
        markers.skipped(),
        None if markers.utf8 else _INVALID_UTF8,
    )


def _names_sdk_when_skipped(content: bytes) -> bool:
    """Whether what ``python -x`` reads after the first line feed names an SDK marker."""
    skipped = _skipped_line(content)
    if skipped is None:
        return False
    codec = _followed(_declared_codec(skipped.line) or "utf-8")
    try:
        other = content[content.index(b"\n") :].decode(codec)
    except UnicodeDecodeError:
        return False
    return _names_sdk(other)


def _python_candidate(path: Path, source: _Source) -> bool:
    if source.found & _PYTHON_NEEDLES:
        return True
    if source.ascii:
        # ASCII reads as itself in every codec followed, so the byte search was exact.
        _source_encoding(source.head, complete=source.complete, skipped=source.skipped)
        return False
    if not source.complete:
        raise _UnreadableError(limits.bound("file-bytes").exceeded())
    try:
        return _names_sdk(_python_text(source.head))
    except _UnreadableError as exc:
        if len(path.parts) == 1 or str(exc) != _INVALID_UTF8:
            raise
    # Python cannot import or run this nested file, which declares no codec and is not
    # UTF-8, so it is an unrelated module and no failure; unless python -x, which
    # skips the first line, would read a reference in the rest.
    if _names_sdk_when_skipped(source.head):
        raise _UnreadableError(_INVALID_UTF8)
    return False


def _server_candidate(path: Path, source: _Source) -> bool:
    return is_analysis_candidate(source.found)


def _client_candidate(path: Path, source: _Source) -> bool:
    return _CLIENT_MARKER in source.found


@dataclass
class _Kind:
    """One kind of source reference: which files qualify and which are candidates."""

    eligible: Callable[[Path], bool]
    candidate: Callable[[Path, _Source], bool]
    selected: list[tuple[Path, bytes]] = field(default_factory=list)


def _python_source(path: Path) -> bool:
    return path.suffix == ".py" and not SOURCE_SEARCH_SKIPPED.intersection(path.parts)


def _script_source(suffix: str) -> Callable[[Path], bool]:
    def eligible(path: Path) -> bool:
        return (
            path.suffix == suffix
            and not SOURCE_SEARCH_SKIPPED.intersection(path.parts)
            and not path.name.endswith(NOT_SOURCE_NAMES)
        )

    return eligible


def _server_import(tree: ast.Module) -> bool:
    return any(
        (
            isinstance(node, ast.ImportFrom)
            and node.module is not None
            and _server_module(node.module)
        )
        or (isinstance(node, ast.Import) and any(_server_module(a.name) for a in node.names))
        for node in ast.walk(tree)
    )


def _framework_import(tree: ast.Module) -> bool:
    """An import of a framework's tool decorator or agent class, or of its module.

    The tool collector reads the first and records a qualified or star import of the
    module as a gap, so each is a framework import here.
    """
    return any(
        (
            isinstance(node, ast.ImportFrom)
            and not node.level
            and any(
                (node.module, alias.name) in _FRAMEWORK_IMPORTS
                or (alias.name == "*" and node.module in _FRAMEWORK_MODULES)
                for alias in node.names
            )
        )
        or (
            isinstance(node, ast.Import)
            and any(alias.name in _FRAMEWORK_MODULES for alias in node.names)
        )
        for node in ast.walk(tree)
    )


def _hidden_import(text: str, tree: ast.Module) -> str | None:
    """The gap for an import the tool collector cannot see, or None.

    The tool collector reads a file only when one of its names appears literally,
    while Python folds identifiers to NFKC, so an import spelled only with
    compatibility characters would otherwise drop its servers and tools silently.
    """
    if any(hint in text for hint in PYTHON_TOOL_HINTS):
        return None
    if _server_import(tree):
        return (
            "Python MCP server import spelled with compatibility characters; "
            "its servers and tools are not collected"
        )
    if _framework_import(tree):
        return (
            "Python agent framework tool import spelled with compatibility characters; "
            "its tools are not collected"
        )
    return None


def _loaded_module(name: str) -> str | None:
    """The gap a dynamic import of ``name`` leaves when it loads an MCP server or client."""
    if name == "mcp" or _server_module(name):
        return _SERVER_LOADED
    if any(name == module or name.startswith(f"{module}.") for module in _CLIENT_MODULES):
        return _CLIENT_LOADED
    return None


def _loader(function: ast.expr, loaders: set[str]) -> bool:
    return (isinstance(function, ast.Name) and function.id in loaders) or (
        isinstance(function, ast.Attribute) and function.attr in _LOADERS
    )


def _literal(node: ast.expr | None) -> str | None:
    """A string Python builds without running code: a constant, or an f-string of constants."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    if isinstance(node, ast.JoinedStr):
        parts = [_literal(part) for part in node.values]
        return None if None in parts else "".join(part or "" for part in parts)
    return None


def _absolute(name: str, package: str | None, level: int = 0) -> str | None:
    """A module name as ``importlib`` resolves it ``level`` packages up from ``package``.

    Leading dots add to ``level``. None when the name cannot resolve: no package, or
    more levels than the package has, which also bounds the work by its length.
    """
    rest = name.lstrip(".")
    level += len(name) - len(rest)
    if not level:
        return name
    if not package or level > package.count(".") + 1:
        return None
    base = package.rsplit(".", level - 1)[0]
    return f"{base}.{rest}" if rest else base


def _globals_package(node: ast.expr | None) -> str | None:
    """The package ``__import__`` resolves a relative name against, from a literal globals dict."""
    if not isinstance(node, ast.Dict):
        return None
    entries = {_literal(key): value for key, value in zip(node.keys, node.values, strict=True)}
    package = _literal(entries.get("__package__"))
    if package is not None:
        return package
    name = _literal(entries.get("__name__"))
    if name is None or "__path__" in entries:
        return name
    return name.rpartition(".")[0]


def _spread(call: ast.Call) -> tuple[list[ast.expr], dict[str, ast.expr]]:
    """A call's arguments by position and by keyword, with ``*`` and ``**`` displays spread.

    A ``*`` argument that is not a list or tuple display ends the known positions.
    """
    positional: list[ast.expr] = []
    for value in call.args:
        if not isinstance(value, ast.Starred):
            positional.append(value)
        elif isinstance(value.value, ast.List | ast.Tuple) and not any(
            isinstance(item, ast.Starred) for item in value.value.elts
        ):
            positional.extend(value.value.elts)
        else:
            break
    keywords: dict[str, ast.expr] = {}
    for keyword in call.keywords:
        if keyword.arg:
            keywords[keyword.arg] = keyword.value
        elif isinstance(keyword.value, ast.Dict):
            for key, item in zip(keyword.value.keys, keyword.value.values, strict=True):
                if (name := _literal(key)) is not None:
                    keywords[name] = item
    return positional, keywords


def _arguments(call: ast.Call) -> list[ast.expr]:
    """A call's arguments and keyword values, with ``*`` and ``**`` displays spread."""
    values: list[ast.expr] = []
    for value in call.args:
        if isinstance(value, ast.Starred) and isinstance(
            value.value, ast.List | ast.Tuple | ast.Set
        ):
            values.extend(value.value.elts)
        else:
            values.append(value)
    for keyword in call.keywords:
        if keyword.arg is None and isinstance(keyword.value, ast.Dict):
            values.extend(keyword.value.values)
        else:
            values.append(keyword.value)
    return values


def _argument_literals(call: ast.Call, *, containers: bool) -> set[str]:
    """Every literal a call is given as an argument, each up to its first colon.

    ``*`` and ``**`` displays are spread into arguments first. With ``containers``, an
    element of a list, tuple, set or dict argument counts too.
    """
    found: set[str] = set()
    for value in _arguments(call):
        if isinstance(value, ast.Starred):
            value = value.value
        items: list[ast.expr] = [value]
        if containers and isinstance(value, ast.List | ast.Tuple | ast.Set):
            items = value.elts
        elif containers and isinstance(value, ast.Dict):
            items = value.values
        for item in items:
            text = _literal(item.value if isinstance(item, ast.Starred) else item)
            if text:
                found.add(text.partition(":")[0])
    return found


def _loaded_names(call: ast.Call) -> set[str]:
    """Every module name a dynamic import call can load, as its literal arguments say.

    The callee may be ``import_module(name, package)``, ``__import__(name, globals,
    locals, fromlist, level)`` or ``pkgutil.resolve_name("module:attribute")``, so each
    reading applies; a relative name counts once resolved against a literal package.
    """
    positional, keywords = _spread(call)

    def argument(position: int, keyword: str) -> ast.expr | None:
        return positional[position] if position < len(positional) else keywords.get(keyword)

    found = _argument_literals(call, containers=False)
    name = _literal(argument(0, "name"))
    if name is not None:
        texts = [_absolute(name, _literal(argument(1, "package")))]
        level = argument(4, "level")
        if isinstance(level, ast.Constant) and type(level.value) is int and level.value > 0:
            texts.append(_absolute(name, _globals_package(argument(1, "globals")), level.value))
        found.update(text.partition(":")[0] for text in texts if text)
    return found


def _binding_names(node: ast.expr) -> list[ast.expr]:
    """The expressions a binding spreads ``node`` into: itself, or its unpacked elements."""
    found: list[ast.expr] = []
    pending = [node]
    while pending:
        item = pending.pop()
        if isinstance(item, (ast.Tuple, ast.List, ast.Set)):
            pending.extend(item.elts)
        elif isinstance(item, ast.Starred):
            pending.append(item.value)
        else:
            found.append(item)
    return found


def _bindings(nodes: list[ast.AST]) -> list[tuple[list[ast.expr], list[ast.expr]]]:
    """Every binding that can give a plain name a value, as (targets, values) pairs.

    Assignments, unpacking, ``for`` and comprehension targets, ``with ... as``
    targets, whose value may be an argument of the context manager, and parameter
    defaults.
    """
    found: list[tuple[list[ast.expr], list[ast.expr]]] = []
    for node in nodes:
        if isinstance(node, ast.Assign):
            found.append((node.targets, [node.value]))
        elif isinstance(node, (ast.AnnAssign, ast.NamedExpr)) and node.value is not None:
            found.append(([node.target], [node.value]))
        elif isinstance(node, (ast.For, ast.AsyncFor, ast.comprehension)):
            found.append(([node.target], [node.iter]))
        elif isinstance(node, ast.withitem) and node.optional_vars is not None:
            value = node.context_expr
            values = [value]
            if isinstance(value, ast.Call):
                values += [*value.args, *(keyword.value for keyword in value.keywords)]
            found.append(([node.optional_vars], values))
        elif isinstance(node, ast.arguments):
            positional = [*node.posonlyargs, *node.args]
            pairs = [
                *zip(
                    positional[len(positional) - len(node.defaults) :], node.defaults, strict=True
                ),
                *zip(node.kwonlyargs, node.kw_defaults, strict=True),
            ]
            found.extend(
                ([ast.Name(argument.arg)], [default])
                for argument, default in pairs
                if default is not None
            )
    return found


def _bound_names(nodes: list[ast.AST]) -> set[str]:
    """Every plain name bound, imported or declared as a parameter in ``nodes``."""
    bound: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bound.add(node.id)
        elif isinstance(node, ast.alias):
            bound.add(node.asname or node.name.split(".")[0])
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bound.add(node.name)
        elif isinstance(node, ast.arg):
            bound.add(node.arg)
        elif isinstance(node, (ast.ExceptHandler, ast.MatchAs, ast.MatchStar)) and node.name:
            bound.add(node.name)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bound.add(node.rest)
    return bound


def _unshadowed_getattr(
    node: ast.AST, bound_names: set[str]
) -> tuple[ast.expr, str, tuple[ast.expr, ...]] | None:
    """``(target, attr, non_attr_args)`` for an unshadowed ``getattr(target, "attr"[, default])``."""
    if not (
        "getattr" not in bound_names
        and isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "getattr"
        and not node.keywords
        and len(node.args) in (2, 3)
        and not any(isinstance(a, ast.Starred) for a in node.args)
    ):
        return None
    attribute = node.args[1]
    if isinstance(attribute, ast.Constant) and isinstance(attribute.value, str):
        return node.args[0], attribute.value, (node.args[0], *node.args[2:])
    return None


def _loader_aliases(nodes: list[ast.AST], loaders: set[str], bound_names: set[str]) -> set[str]:
    """``loaders`` and every name a binding gives one, however many steps away.

    Any binding counts, wherever it is, so a name once bound to a loader is one. An
    unpacking binds each of its names to each of its values, which can only add
    loaders: one node per binding joins them, so the work stays linear.
    """
    reached = set(loaders)
    bound: dict[str, set[str]] = {}
    for index, (targets, values) in enumerate(_bindings(nodes)):
        joint = f"#{index}"
        for value in (item for node in values for item in _binding_names(node)):
            if isinstance(value, ast.Name):
                bound.setdefault(value.id, set()).add(joint)
            elif (isinstance(value, ast.Attribute) and value.attr in _LOADERS) or (
                (pair := _unshadowed_getattr(value, bound_names)) is not None
                and pair[1] in _LOADERS
            ):
                reached.add(joint)
        for target in (item for node in targets for item in _binding_names(node)):
            if isinstance(target, ast.Name):
                bound.setdefault(joint, set()).add(target.id)
    pending = list(reached)
    while pending:
        for name in bound.pop(pending.pop(), ()):
            if name not in reached:
                reached.add(name)
                pending.append(name)
    return {name for name in reached if not name.startswith("#")}


def _elsewhere(name: str) -> str:
    return _LAUNCHER_ELSEWHERE if name in _PYTHON_LAUNCHERS else _SERVER_CLASS_ELSEWHERE


def _owned(name: str, module: str | None) -> bool:
    """Whether an absolute import from ``module`` gives the SDK's own launcher or server class."""
    if module is None:
        return False
    if name in _PYTHON_LAUNCHERS:
        return module.split(".")[0] in _PYTHON_LAUNCHERS[name][0]
    return module in _SERVER_CLASSES[name]


def _literals_in_expressions(values: Sequence[ast.expr]) -> set[str]:
    found: set[str] = set()
    for value in values:
        if isinstance(value, ast.Starred):
            value = value.value
        items: list[ast.expr] = [value]
        if isinstance(value, ast.List | ast.Tuple | ast.Set):
            items = value.elts
        elif isinstance(value, ast.Dict):
            items = value.values
        for item in items:
            text = _literal(item.value if isinstance(item, ast.Starred) else item)
            if text:
                found.add(text.partition(":")[0])
    return found


def _named_module(call: ast.Call) -> set[str]:
    """Every module a call's arguments name as a literal, in any position.

    Any callee counts, and so does a literal inside a list, tuple, set or dict argument,
    also behind ``*`` or ``**``, so a loader that reaches the call under a name no
    binding shows (an argument, a match capture, a return value, ``functools.partial``,
    ``map`` or a thread target's ``args`` or ``kwargs``) still leaves a gap.
    """
    return _argument_literals(call, containers=True)


def _honest_loggers(
    nodes: list[ast.AST], loggers: set[str], *, stdlib_clear: bool = True
) -> tuple[bool, set[str]]:
    """Whether ``logging.getLogger`` can only be the standard library's, and which of the
    names ``from logging import getLogger`` binds can only be that function.

    Assigning ``getLogger`` a loader, by rebinding a name, ``logging`` itself or one of
    its attributes (including through an alias such as ``import logging as L``), turns a
    logger name into a module to load. A local ``logging.py`` or uncertain stdlib search
    root also withdraws the exemption.
    """
    if not stdlib_clear:
        return False, set()
    logging_aliases: set[str] = {"logging"}
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "logging" or alias.name.startswith("logging."):
                    logging_aliases.add(alias.asname or alias.name.split(".")[0])
    watched = logging_aliases | loggers
    rebound: set[str] = set()
    imported = False
    reads: dict[str, int] = dict.fromkeys(logging_aliases, 0)
    attributes: dict[str, int] = dict.fromkeys(logging_aliases, 0)
    for node in nodes:
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                honest = (
                    bound in logging_aliases
                    and (not alias.asname or alias.name == "logging")
                    and (alias.name == "logging" or alias.name.startswith("logging."))
                )
                if bound == "logging" and honest:
                    imported = True
                if bound in watched and not honest:
                    rebound.add(bound)
        elif isinstance(node, ast.ImportFrom):
            from_logging = not node.level and node.module == "logging"
            for alias in node.names:
                if alias.name == "*" and not from_logging:
                    return False, set()
                if not node.level and node.module == "sys" and alias.name == "modules":
                    return False, set()
                bound = alias.asname or alias.name
                if bound in watched and not (
                    bound in loggers and from_logging and alias.name == "getLogger"
                ):
                    rebound.add(bound)
        elif isinstance(node, ast.Name):
            if node.id in _REBINDING_BUILTINS:
                return False, set()
            if node.id in watched and not isinstance(node.ctx, ast.Load):
                rebound.add(node.id)
            if node.id in logging_aliases and isinstance(node.ctx, ast.Load):
                reads[node.id] += 1
        elif isinstance(node, ast.Attribute):
            if node.attr in _REBINDING_ATTRIBUTES or node.attr in _REBINDING_BUILTINS:
                return False, set()
            if isinstance(node.value, ast.Name) and node.value.id in logging_aliases:
                if isinstance(node.ctx, ast.Load) and not node.attr.startswith("__"):
                    attributes[node.value.id] += 1
                else:
                    rebound.add(node.value.id)
        elif isinstance(node, ast.Call):
            pair = _unshadowed_getattr(node, set())
            if pair is not None and (
                pair[1] in _REBINDING_ATTRIBUTES or pair[1] in _REBINDING_BUILTINS
            ):
                return False, set()
        elif not isinstance(node, ast.alias):
            rebound.update(_bound_names([node]) & watched)
    # Any mutation or escaping read of any `logging` alias can mutate `logging.getLogger`.
    module_tampered = any(
        alias in rebound or reads[alias] != attributes[alias] for alias in logging_aliases
    )
    honest_module = imported and not module_tampered
    return honest_module, (set() if module_tampered else loggers - rebound)


def _exempt_call(func: ast.expr, owned: set[str], loggers: set[str], logging_module: bool) -> bool:
    """A call whose literal arguments name a server or a logger, not a module to load."""
    if isinstance(func, ast.Name):
        return func.id in owned or func.id in loggers
    return (
        logging_module
        and isinstance(func, ast.Attribute)
        and func.attr == "getLogger"
        and isinstance(func.value, ast.Name)
        and func.value.id == "logging"
    )


def _root_name(node: ast.expr, bound_names: set[str]) -> str | None:
    while True:
        if isinstance(node, ast.Attribute):
            node = node.value
        elif (pair := _unshadowed_getattr(node, bound_names)) is not None:
            node = pair[0]
        else:
            break
    return node.id if isinstance(node, ast.Name) else None


def _record_attribute_gap(
    target: ast.expr,
    attr: str,
    packages: set[str],
    imported: set[str],
    bound_names: set[str],
    gaps: set[str],
) -> None:
    if attr in _PYTHON_LAUNCHERS:
        owners, reason = _PYTHON_LAUNCHERS[attr]
        if (
            attr in _LAUNCHER_CLASSES
            or owners & packages
            or _root_name(target, bound_names) in imported
        ):
            gaps.add(reason)
    elif attr in _SERVER_CLASSES:
        gaps.add(_SERVER_CLASS_ATTRIBUTE)


def _python_launches(tree: ast.Module, project_imports: _ProjectImports) -> list[str]:
    """Gaps for MCP servers a file starts or reaches, or loads through a dynamic import.

    A launcher class or function counts wherever it is used other than as a type in an
    annotation (see ``_annotation_names``), by its imported name, by a star import or
    as an attribute of its package; a launcher class also as an attribute of any value,
    and a launcher function as an attribute of any name the file imports. ``ast`` has
    already folded identifiers to NFKC, as Python does. A launcher imported by name
    from its package and not used other than as such a type is a gap too, because
    another module can import it from this one. A
    launcher or server class imported from any other module, or used by its name after
    a star import of one, is a gap, and so is a server class reached as an attribute:
    the tool collector inventories only servers built from the SDK's own import. A
    dynamic import counts when a literal argument names an MCP server or client
    module, through a loader or a name bound to one, and so does any call given such a
    literal in any argument position or keyword, or as an element of a list, tuple, set
    or dict argument, also behind ``*`` or ``**``, whatever the callee; a computed
    name is not followed.
    """
    nodes = list(ast.walk(tree))
    bound_names = _bound_names(nodes)
    packages: set[str] = set()
    imported: set[str] = set()
    names: dict[str, str] = {}
    unused: set[str] = set()
    loaders = set(_LOADERS)
    gaps: set[str] = set()
    owned: set[str] = set()
    loggers: set[str] = set()
    for node in nodes:
        if isinstance(node, ast.Import):
            packages.update(alias.name.split(".")[0] for alias in node.names)
            imported.update(alias.asname or alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            package = None if node.level or not node.module else node.module.split(".")[0]
            if package is not None:
                packages.add(package)
            for alias in node.names:
                imported.add(alias.asname or alias.name)
                if node.module in _LOADER_MODULES and alias.name in _LOADERS and package:
                    loaders.add(alias.asname or alias.name)
                if node.module == "logging" and alias.name == "getLogger":
                    loggers.add(alias.asname or alias.name)
                star = alias.name == "*"
                for name in (*_PYTHON_LAUNCHERS, *_SERVER_CLASSES) if star else (alias.name,):
                    if name not in _PYTHON_LAUNCHERS and name not in _SERVER_CLASSES:
                        continue
                    if not _owned(name, None if node.level else node.module):
                        if star:
                            names.setdefault(name, _elsewhere(name))
                        else:
                            gaps.add(_elsewhere(name))
                    elif name in _SERVER_CLASSES and not star:
                        owned.add(alias.asname or name)
                    elif name in _PYTHON_LAUNCHERS:
                        names[alias.asname or name] = _PYTHON_LAUNCHERS[name][1]
                        if not star:
                            unused.add(alias.asname or name)
    loaders = _loader_aliases(nodes, loaders, bound_names)
    # A local logging module in any first search root shadows the standard one:
    # has_module() asks for one in every root, which is what a local exemption needs.
    stdlib_clear = project_imports is None or (
        project_imports.stdlib_search_clear and not project_imports.shadows("logging")
    )
    logging_module, loggers = _honest_loggers(nodes, loggers, stdlib_clear=stdlib_clear)
    annotations = _annotation_names(nodes, project_imports=project_imports)
    for node in nodes:
        if isinstance(node, ast.Call):
            func_getattr = _unshadowed_getattr(node.func, bound_names)
            call_getattr = _unshadowed_getattr(node, bound_names)
            if _loader(node.func, loaders) or (
                func_getattr is not None and func_getattr[1] in _LOADERS
            ):
                modules = _loaded_names(node)
            elif call_getattr is not None:
                target, attr, non_attr_args = call_getattr
                modules = _literals_in_expressions(non_attr_args)
                if node not in annotations:
                    _record_attribute_gap(target, attr, packages, imported, bound_names, gaps)
            elif _exempt_call(node.func, owned - loaders, loggers - loaders, logging_module):
                modules = set()
            else:
                modules = _named_module(node)
            loaded = (_loaded_module(name) for name in modules)
            gaps.update(gap for gap in loaded if gap is not None)
        elif node in annotations or not isinstance(getattr(node, "ctx", None), ast.Load):
            continue
        elif isinstance(node, ast.Name) and node.id in names:
            gaps.add(names[node.id])
            unused.discard(node.id)
        elif isinstance(node, ast.Attribute):
            _record_attribute_gap(node.value, node.attr, packages, imported, bound_names, gaps)
    if unused:
        gaps.add(_LAUNCHER_PASSED_ON)
    return sorted(gaps)


# These imports are common before a tool declaration. Without a local stdlib
# candidate, importing them only binds their names in a passive helper.
_PASSIVE_HEADER_MODULES = frozenset(
    {"collections.abc", "dataclasses", "functools", "logging", "os", "pathlib", "typing"}
)


def _plain_module_names(path: Path, source: _Source, node_limit: int) -> _PassiveModule | None:
    """Names a passive SDK-named package helper can supply at import time."""
    try:
        tree = parse_python(_python_text(source.head))
    except (_UnreadableError, SyntaxError, ValueError, RecursionError):
        return None
    if next(islice(ast.walk(tree), node_limit, None), None) is not None:
        return None
    names: set[str] = set()
    imports_stdlib = False
    for stmt in tree.body:
        if isinstance(stmt, ast.Pass) or (
            isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant)
        ):
            continue
        if isinstance(stmt, ast.Assign) and isinstance(stmt.value, ast.Constant):
            for target in stmt.targets:
                if not isinstance(target, ast.Name) or target.id.startswith("__"):
                    return None
                names.add(target.id)
            continue
        if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)) and not stmt.name.startswith(
            "__"
        ):
            args = stmt.args
            if (
                stmt.decorator_list
                or stmt.returns
                or getattr(stmt, "type_params", None)
                or args.defaults
                or any(v is not None for v in args.kw_defaults)
                or any(
                    arg.annotation
                    for arg in (
                        *args.posonlyargs,
                        *args.args,
                        *args.kwonlyargs,
                        args.vararg,
                        args.kwarg,
                    )
                    if arg
                )
            ):
                return None
            names.add(stmt.name)
            continue
        if isinstance(stmt, (ast.Import, ast.ImportFrom)) and any(
            alias.name.startswith("__") or (alias.asname or "").startswith("__")
            for alias in stmt.names
        ):
            return None
        if isinstance(stmt, ast.Import) and all(
            alias.name in _PASSIVE_HEADER_MODULES for alias in stmt.names
        ):
            names.update(alias.asname or alias.name.split(".")[0] for alias in stmt.names)
            imports_stdlib = True
            continue
        if isinstance(stmt, ast.ImportFrom) and not stmt.level and stmt.module:
            if stmt.module in _PASSIVE_HEADER_MODULES and all(
                alias.name != "*" for alias in stmt.names
            ):
                names.update(alias.asname or alias.name for alias in stmt.names)
                imports_stdlib = True
                continue
            if stmt.module == "__future__" and all(
                alias.name == "annotations" and not alias.asname for alias in stmt.names
            ):
                names.add("annotations")
                imports_stdlib = True
                continue
            # When this flat helper is imported as the top-level name, an
            # absent self-import stops execution before subsequent statements.
            if path.name != "__init__.py" and (
                stmt.module.startswith(path.stem + ".")
                or (
                    stmt.module == path.stem
                    and any(alias.name != "*" and alias.name not in names for alias in stmt.names)
                )
            ):
                return _PassiveModule(frozenset(names), imports_stdlib)
        return None
    return _PassiveModule(frozenset(names), imports_stdlib)


def _outcome(result: ScanResult) -> tuple[int, int, int]:
    return (
        len(result.components),
        recorded_count(result.surfaces_excluded),
        recorded_count(result.scan_failures),
    )


def collect_source_references(
    files: ConfinedCollection,
    result: ScanResult,
    sources: Sequence[Path],
    budget: SourceBudget,
    known: KnownValues | None = None,
    *,
    unvisited: Sequence[Path] = (),
    walk_complete: bool = True,
) -> None:
    """Inventory MCP servers, MCP clients and agent tools declared in source.

    ``sources`` is the collector's walk of the root. Every eligible file is searched
    as a stream, root files first, and ``budget`` bounds the text read: running out
    of it is the budget's one named failure, and nothing after it is read. A server
    name declared in source that holds one of the ``known`` values, which the scan
    read from configuration files, is not recorded.
    """
    settings = limits.current()
    python_nodes = limits.bound("python-nodes")
    servers = _Kind(is_server_source, _server_candidate)
    python = _Kind(_python_source, _python_candidate)
    clients = [_Kind(_script_source(suffix), _client_candidate) for suffix in _CLIENT_SUFFIXES]
    kinds = (servers, python, *clients)
    python_paths = frozenset(path for path in sources if path.suffix == ".py")
    plain_modules: dict[Path, _PassiveModule] = {}
    # Include non-Python files and nested directories as possible import
    # entries. An extension module or namespace directory keeps its ambiguity.
    entries = frozenset(
        entry
        for source_path in sources
        if not SDK_IMPORT_ROOTS.isdisjoint(source_path.parts[:-1])
        for entry in (
            source_path.with_name(source_path.name.split(".", 1)[0] or source_path.name),
            *source_path.parents,
        )
        if entry.parent.name in SDK_IMPORT_ROOTS
    )
    # A package link, alternate loader, or excluded local bytecode cache makes
    # the selected source uncertain. Never open a binary or enter a skipped cache.
    uncertain: set[Path] = set()
    cache_parents = {p.parent for p in unvisited if fold_name(p.name) == "__pycache__"}
    for path in unvisited:
        uncertain.update(p for p in (path, *path.parents) if p.name in SDK_IMPORT_ROOTS)
    for path in sources:
        stem, dot, suffix = path.name.partition(".")
        if not stem or not dot or suffix == "py":
            continue
        owner = path.parent if stem == "__init__" else path.with_name(stem)
        if owner.name in SDK_IMPORT_ROOTS and (
            path.suffix.casefold() in {".so", ".pyd", ".pyc"}
            or owner.with_suffix(".py") in python_paths
            or owner / "__init__.py" in python_paths
        ):
            uncertain.add(owner)
    uncertain_modules = frozenset(uncertain)
    # A standard module (or one of its own imports) can also resolve to the
    # checkout. Index candidate roots once and check them for each entry file.
    stdlib_roots: set[Path] = set()
    for path in (*sources, *unvisited):
        if path.name.partition(".")[0] in sys.stdlib_module_names:
            stdlib_roots.add(path.parent)
        if not sys.stdlib_module_names.isdisjoint(path.parts[:-1]):
            stdlib_roots.update(p.parent for p in path.parents if p.name in sys.stdlib_module_names)
    # The walk skips an excluded entry in any spelling a case-insensitive file system
    # folds to its name, which is then the name a standard import resolves to.
    for path in unvisited:
        if fold_name(path.name).partition(".")[0] in sys.stdlib_module_names:
            stdlib_roots.add(path.parent)
    eligible = [path for path in sources if any(kind.eligible(path) for kind in kinds)]
    # Root files first, as before, so what a lowered budget reads stays predictable.
    eligible.sort(key=lambda path: len(path.parts) > 1)
    failed: set[Path] = set()

    def fail(path: Path, reason: str) -> None:
        if path not in failed:
            failed.add(path)
            files._fail(path.as_posix(), reason)

    # Every eligible file can fail, so past the listing bound the failures of the
    # search are summarized by reason instead of growing the inventory without end.
    with files.bounded_failures():
        for path in eligible:
            try:
                source = _search(files, path, settings.file_bytes, budget)
            except _BudgetSpentError:
                break
            except (OSError, CollectionError):
                # The confined reader recorded why. Once the collection's own byte
                # budget is spent, no later file can be read either.
                if files.bytes_exhausted:
                    break
                continue
            owner = path.parent if path.name == "__init__.py" else path.with_suffix("")
            if (
                path.suffix == ".py"
                and owner.name in SDK_IMPORT_ROOTS
                and owner.parent / "__init__.py" in python_paths
                and walk_complete
                and owner not in uncertain_modules
                and path.parent not in cache_parents
                and files.link_target(path) is None
                and source.complete
                and source.size <= settings.syntax_bytes
            ):
                names = _plain_module_names(path, source, python_nodes.value)
                if names is not None:
                    plain_modules[path] = names
            candidate = False
            for kind in kinds:
                if not kind.eligible(path):
                    continue
                try:
                    if not kind.candidate(path, source):
                        continue
                except _UnreadableError as exc:
                    fail(path, str(exc))
                    continue
                candidate = True
                if source.size > settings.syntax_bytes:
                    fail(path, limits.bound("syntax-bytes").exceeded())
                elif not source.complete:
                    fail(path, limits.bound("file-bytes").exceeded())
                else:
                    kind.selected.append((path, source.head))
            if not candidate and source.error is not None:
                # tsc would read the file, replacing what is not UTF-8, but another
                # runtime could decode it differently; earlier releases failed it too.
                fail(path, source.error)

    surfaces: list[str] = []
    detected: list[str] = []
    for path, content in servers.selected:
        before = _outcome(result)
        collect_typescript_source(path, content, result, known)
        if _outcome(result) != before:
            surfaces.append(path.as_posix())
    for path, content in python.selected:
        location = path.as_posix()
        before = _outcome(result)
        client = False
        try:
            text = _python_text(content)
        except _UnreadableError as exc:
            fail(path, str(exc))
            continue
        try:
            tree = parse_python(text)
        except (SyntaxError, ValueError, RecursionError):
            fail(path, "invalid Python syntax")
        else:
            # Every analysis below walks the whole tree, so none runs past the bound.
            nodes = list(islice(ast.walk(tree), python_nodes.value + 1))
            if len(nodes) > python_nodes.value:
                fail(path, python_nodes.exceeded())
                continue
            project_imports = _ProjectImports(
                python_paths,
                path.parent,
                plain_modules,
                entries,
                uncertain_modules,
                stdlib_roots.isdisjoint((Path(), Path("src"), path.parent)),
            )
            collect_python_tools(
                tree, nodes, text, path, result, known, project_imports=project_imports
            )
            client = _python_client(tree)
            if client:
                detected.append(location)
            gap = _hidden_import(text, tree)
            if gap is not None:
                result.surfaces_excluded.append(f"{location}: {gap}")
            result.surfaces_excluded.extend(
                f"{location}: {gap}" for gap in _python_launches(tree, project_imports)
            )
        if _outcome(result) != before or client:
            surfaces.append(location)
    for path, content in (selected for kind in clients for selected in kind.selected):
        try:
            text = source_text(content)
        except ValueError as exc:
            fail(path, str(exc))
            continue
        if _client_reference(text):
            detected.append(path.as_posix())
            surfaces.append(path.as_posix())
    result.surfaces_scanned.extend(dict.fromkeys(surfaces))
    if detected:
        result.components.append(
            MCPClientComponent(
                bom_ref="mcp-client:sdk",
                name="MCP SDK client (code-detected)",
                host_application="sdk",
                source_path=detected[0],
                trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                properties={
                    "collection_mode": "static-source-reference",
                    "source_paths": detected,
                },
            )
        )
