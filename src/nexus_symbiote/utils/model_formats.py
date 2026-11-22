"""Bounded, non-executing readers for the parts of model files that name other content.

ONNX graphs can keep tensor bytes in files they name (external data); GGUF files
embed Jinja chat templates. These readers stream the artifact once, never import
a model library and never evaluate a template. Error messages are fixed text.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field

Read = Callable[[int], bytes]

_CHUNK = 65536
# Structure units (protobuf fields, GGUF keys and array items) that one scan may
# spend across all files, so many hostile files cannot add up to a long scan.
MAX_INSPECTION_UNITS = 16_000_000


class FormatError(ValueError):
    """A bounded reader could not establish the structure it needs."""


class InspectionBudget:
    """Structure units shared by every bounded format reader in one collection."""

    def __init__(self, units: int | None = None) -> None:
        self.remaining = MAX_INSPECTION_UNITS if units is None else units

    def charge(self, units: int, error: str) -> None:
        self.remaining -= units
        if self.remaining < 0:
            raise FormatError(error)


class _Reader:
    """Forward-only buffered reader with exact reads and skips."""

    def __init__(self, read: Read, error: str) -> None:
        self._read = read
        self._buffer = b""
        self._pos = 0
        self.offset = 0
        self.error = error

    def _chunk(self) -> bytes:
        return self._read(_CHUNK)

    def _fill(self) -> bool:
        chunk = self._chunk()
        if not chunk:
            return False
        self._buffer = self._buffer[self._pos :] + chunk
        self._pos = 0
        return True

    def exhausted(self) -> bool:
        return self._pos >= len(self._buffer) and not self._fill()

    def drain(self) -> None:
        self._buffer, self._pos = b"", 0
        while self._chunk():
            pass

    def byte(self) -> int:
        if self._pos >= len(self._buffer) and not self._fill():
            raise FormatError(self.error)
        value = self._buffer[self._pos]
        self._pos += 1
        self.offset += 1
        return value

    def take(self, count: int) -> bytes:
        if len(self._buffer) - self._pos >= count:
            data = self._buffer[self._pos : self._pos + count]
            self._pos += count
            self.offset += count
            return data
        parts = [self._buffer[self._pos :]]
        have = len(parts[0])
        while have < count:
            chunk = self._chunk()
            if not chunk:
                raise FormatError(self.error)
            parts.append(chunk)
            have += len(chunk)
        joined = b"".join(parts)
        self._buffer, self._pos = joined[count:], 0
        self.offset += count
        return joined[:count]

    def skip(self, count: int) -> None:
        while count > 0:
            if self._pos >= len(self._buffer) and not self._fill():
                raise FormatError(self.error)
            step = min(count, len(self._buffer) - self._pos)
            self._pos += step
            self.offset += step
            count -= step

    def uint(self, width: int) -> int:
        return int.from_bytes(self.take(width), "little")


# ONNX ------------------------------------------------------------------------

ONNX_UNREADABLE = "ONNX graph could not be parsed; external weight files are unknown"
ONNX_LIMIT = "ONNX graph exceeds the inspection limits; external weight files are unknown"
ONNX_UNEXPLAINED = (
    "ONNX file holds an external-data key outside the parsed graph; "
    "external weight files are unknown"
)
MAX_ONNX_DEPTH = 64
MAX_ONNX_FIELDS = 4_000_000
MAX_ONNX_LOCATION_BYTES = 4096

(
    _MODEL,
    _GRAPH,
    _NODE,
    _ATTRIBUTE,
    _TENSOR,
    _SPARSE,
    _FUNCTION,
    _TRAINING,
    _ENTRY,
    _VALUE_INFO,
    _ANNOTATION,
    _OPSET,
) = range(12)
# onnx.proto: the length-delimited fields that can hold a tensor, a subgraph or a
# StringStringEntryProto, and the messages whose field 1 is a name. Other fields
# are skipped by wire type, as protobuf does.
_SCHEMA: dict[int, dict[int, int]] = {
    _MODEL: {7: _GRAPH, 8: _OPSET, 14: _ENTRY, 20: _TRAINING, 25: _FUNCTION},
    _GRAPH: {
        1: _NODE,
        5: _TENSOR,
        11: _VALUE_INFO,
        12: _VALUE_INFO,
        13: _VALUE_INFO,
        14: _ANNOTATION,
        15: _SPARSE,
        16: _ENTRY,
    },
    _NODE: {5: _ATTRIBUTE, 9: _ENTRY},
    _ATTRIBUTE: {5: _TENSOR, 6: _GRAPH, 10: _TENSOR, 11: _GRAPH, 22: _SPARSE, 23: _SPARSE},
    _TENSOR: {13: _ENTRY, 16: _ENTRY},
    _SPARSE: {1: _TENSOR, 2: _TENSOR},
    _FUNCTION: {7: _NODE, 9: _OPSET, 11: _ATTRIBUTE, 12: _VALUE_INFO, 14: _ENTRY},
    _TRAINING: {1: _GRAPH, 2: _GRAPH, 3: _ENTRY, 4: _ENTRY},
    _ENTRY: {},
    _VALUE_INFO: {4: _ENTRY},
    _ANNOTATION: {2: _ENTRY},
    _OPSET: {},
}
# Singular fields that hold a tensor. protobuf merges repeated occurrences of one into
# a single tensor, so a tensor split across them could be EXTERNAL with a location
# that no one occurrence pairs with EXTERNAL; such a file is not read.
_SINGULAR: dict[int, frozenset[int]] = {
    _ATTRIBUTE: frozenset({5, 22}),
    _SPARSE: frozenset({1, 2}),
}
_KEY = b"location"
# Field 1 length-delimited, then a length of 8, then the key, with each varint in any
# encoding of up to ten bytes: protobuf's C++ parsers, which ONNX Runtime uses, keep
# only the low 32 bits of a tag. A tenth length byte is not checked further. The
# pattern matches the reversed bytes, so the engine starts a match only at the
# literal key and hostile filler cannot make it try one at every byte.
_REVERSED_KEY_MARKER = re.compile(
    rb"noitacol(?:\x08|\x00\x80{0,7}\x88|[\x00-\x7f]\x80{8}\x88)"
    rb"(?:\x0a|\x00\x80{0,2}\x8a|[\x00\x10\x20\x30\x40\x50\x60\x70]\x80{3}\x8a"
    rb"|[\x00-\x7f][\x80-\xff]{0,4}[\x80\x90\xa0\xb0\xc0\xd0\xe0\xf0]\x80{3}\x8a)"
)
_MAX_MARKER_BYTES = 10 + 10 + len(_KEY)
# An enum is read as int32, and a value a closed (proto2) enum does not define is
# kept as an unknown field: it never replaces an earlier valid value.
_DATA_LOCATIONS = (0, 1)
_EXTERNAL = 1


class _OnnxReader(_Reader):
    """Counts the ``location`` bytes in the raw stream, parsed or not.

    ``occurrences`` counts every occurrence and ``markers`` those encoded as a
    field-1 string of exactly that value, as an external-data key is. Both are
    counted in C by searches anchored on the literal key, so hostile bytes cost
    no more than a linear scan.
    """

    def __init__(self, read: Read) -> None:
        super().__init__(read, ONNX_UNREADABLE)
        self.markers = 0
        self.occurrences = 0
        self._tail = b""

    def _chunk(self) -> bytes:
        chunk = self._read(_CHUNK)
        window = self._tail + chunk
        self.occurrences += window.count(_KEY, max(len(self._tail) - len(_KEY) + 1, 0))
        if _KEY in window:
            # Markers are disjoint, so those ending in this chunk are the window's
            # minus the tail's, which the previous window counted.
            self.markers += len(_REVERSED_KEY_MARKER.findall(window[::-1])) - len(
                _REVERSED_KEY_MARKER.findall(self._tail[::-1])
            )
        self._tail = window[-(_MAX_MARKER_BYTES - 1) :]
        return chunk

    def varint(self) -> int:
        buffer, start = self._buffer, self._pos
        if start < len(buffer) and buffer[start] < 0x80:
            self._pos += 1
            self.offset += 1
            return buffer[start]
        result = 0
        for shift in range(0, 70, 7):
            byte = self.byte()
            result |= (byte & 0x7F) << shift
            if byte < 0x80:
                return result & 0xFFFFFFFFFFFFFFFF
        raise FormatError(ONNX_UNREADABLE)


@dataclass
class _OnnxState:
    budget: InspectionBudget
    fields: int = 0
    explained: int = 0
    locations: list[str] = field(default_factory=list)

    def count(self) -> None:
        self.fields += 1
        self.budget.charge(1, ONNX_LIMIT)
        if self.fields > MAX_ONNX_FIELDS:
            raise FormatError(ONNX_LIMIT)


def _skip_value(reader: _OnnxReader, wire: int, field_number: int, state: _OnnxState) -> None:
    if wire == 0:
        reader.varint()
    elif wire == 1:
        reader.skip(8)
    elif wire == 2:
        reader.skip(reader.varint())
    elif wire == 5:
        reader.skip(4)
    elif wire == 3:
        _skip_group(reader, field_number, state)
    else:
        raise FormatError(ONNX_UNREADABLE)


def _skip_group(reader: _OnnxReader, group: int, state: _OnnxState) -> None:
    depth = 1
    stack = [group]
    while stack:
        state.count()
        if depth > MAX_ONNX_DEPTH:
            raise FormatError(ONNX_LIMIT)
        tag = reader.varint()
        number, wire = tag >> 3, tag & 7
        if number == 0 or tag >= 2**32:
            raise FormatError(ONNX_UNREADABLE)
        if wire == 4:
            if stack.pop() != number:
                raise FormatError(ONNX_UNREADABLE)
            depth -= 1
        elif wire == 3:
            stack.append(number)
            depth += 1
        else:
            _skip_value(reader, wire, number, state)


def _message(
    reader: _OnnxReader, end: int | None, kind: int, depth: int, state: _OnnxState
) -> tuple[bytes | None, bytes | None]:
    """Parse one message; an entry returns its final key and value."""
    if depth > MAX_ONNX_DEPTH:
        raise FormatError(ONNX_LIMIT)
    location = 0
    externals: list[bytes | None] = []
    singular = _SINGULAR.get(kind, frozenset())
    seen: set[int] = set()
    key: bytes | None = None
    value: bytes | None = None
    while (reader.offset < end) if end is not None else not reader.exhausted():
        state.count()
        tag = reader.varint()
        number, wire = tag >> 3, tag & 7
        if number == 0 or tag >= 2**32:
            raise FormatError(ONNX_UNREADABLE)
        if wire == 0 and kind == _TENSOR and number == 14:
            stored = reader.varint() & 0xFFFFFFFF
            if stored in _DATA_LOCATIONS:
                location = stored
            continue
        if wire != 2:
            _skip_value(reader, wire, number, state)
            continue
        length = reader.varint()
        stop = reader.offset + length
        if end is not None and stop > end:
            raise FormatError(ONNX_UNREADABLE)
        if kind == _ENTRY and number in (1, 2):
            if length > MAX_ONNX_LOCATION_BYTES:
                reader.skip(length)
                text = None
            else:
                text = reader.take(length)
            if number == 1:
                key = text
                state.explained += text == _KEY
            else:
                value = text
            continue
        child = _SCHEMA[kind].get(number)
        if child is None and number == 1 and length == len(_KEY):
            # A name or other scalar data in a parsed message, never an entry key.
            state.explained += reader.take(length) == _KEY
            continue
        if child is None:
            reader.skip(length)
            continue
        if number in singular:
            if number in seen:
                raise FormatError(ONNX_UNREADABLE)
            seen.add(number)
        entry_key, entry_value = _message(reader, stop, child, depth + 1, state)
        if kind == _TENSOR and number == 13 and entry_key == _KEY:
            externals.append(entry_value)
    if end is not None and reader.offset != end:
        raise FormatError(ONNX_UNREADABLE)
    # A runtime reads external data only for tensors stored as EXTERNAL.
    if kind == _TENSOR and location == _EXTERNAL:
        for raw in externals:
            if raw is None:
                raise FormatError(ONNX_UNREADABLE)
            try:
                state.locations.append(raw.decode("utf-8"))
            except UnicodeDecodeError:
                raise FormatError(ONNX_UNREADABLE) from None
    return key, value


def onnx_external_data(read: Read, budget: InspectionBudget | None = None) -> tuple[str, ...]:
    """Return the external-data locations an ONNX runtime would open, as written.

    Tensors in graphs, subgraphs, node attributes, functions and training graphs
    are followed. A runtime opens external data only through an entry whose key is
    the literal ``location``, and those eight bytes appear in the file whatever
    field holds them and however its tag and length are encoded. So in a parsed
    file every field-1 string ``location`` must be an entry key or a name the
    parser read, and a file the parser cannot read fails whenever those bytes
    occur at all: without them it cannot name external data.
    """
    reader = _OnnxReader(read)
    state = _OnnxState(budget or InspectionBudget())
    try:
        _message(reader, None, _MODEL, 0, state)
    except (FormatError, RecursionError) as exc:
        reader.drain()
        if reader.occurrences:
            raise FormatError(str(exc) if isinstance(exc, FormatError) else ONNX_LIMIT) from None
        return ()
    if reader.markers > state.explained:
        raise FormatError(ONNX_UNEXPLAINED)
    return tuple(sorted(set(state.locations)))


# GGUF ------------------------------------------------------------------------

GGUF_MAGIC = b"GGUF"
GGUF_UNREADABLE = "GGUF metadata could not be read"
GGUF_LIMIT = "GGUF metadata exceeds the inspection limits"
MAX_GGUF_KEYS = 65536
MAX_GGUF_STRING_BYTES = 16 * 1024 * 1024
MAX_GGUF_ARRAY_ITEMS = 1 << 21
MAX_GGUF_METADATA_BYTES = 128 * 1024 * 1024
_GGUF_SCALARS = {0: 1, 1: 1, 2: 2, 3: 2, 4: 4, 5: 4, 6: 4, 7: 1, 10: 8, 11: 8, 12: 8}
_GGUF_STRING = 8
_GGUF_ARRAY = 9
_ARCHITECTURE = re.compile(rb"[a-z0-9][a-z0-9_.-]{0,63}")
_TEMPLATE = b"tokenizer.chat_template"
_TEMPLATE_KEY = re.compile(rb"tokenizer\.chat_template(?:\.[A-Za-z0-9_-]{1,64})?")


@dataclass(frozen=True)
class GGUFMetadata:
    architecture: str | None
    chat_templates: tuple[tuple[str, bytes], ...]


def _gguf_string(reader: _Reader) -> bytes:
    length = reader.uint(8)
    if length > MAX_GGUF_STRING_BYTES:
        raise FormatError(GGUF_LIMIT)
    return reader.take(length)


def _skip_gguf_value(reader: _Reader, kind: int, depth: int, budget: InspectionBudget) -> None:
    budget.charge(1, GGUF_LIMIT)
    if kind in _GGUF_SCALARS:
        reader.skip(_GGUF_SCALARS[kind])
    elif kind == _GGUF_STRING:
        length = reader.uint(8)
        if length > MAX_GGUF_STRING_BYTES:
            raise FormatError(GGUF_LIMIT)
        reader.skip(length)
    elif kind == _GGUF_ARRAY:
        if depth >= 2:
            # The format allows deeper nesting; a template after it is unread, not absent.
            raise FormatError(GGUF_LIMIT)
        item = reader.uint(4)
        count = reader.uint(8)
        if count > MAX_GGUF_ARRAY_ITEMS:
            raise FormatError(GGUF_LIMIT)
        if item in _GGUF_SCALARS:
            reader.skip(count * _GGUF_SCALARS[item])
            return
        for _ in range(count):
            _skip_gguf_value(reader, item, depth + 1, budget)
            if reader.offset > MAX_GGUF_METADATA_BYTES:
                raise FormatError(GGUF_LIMIT)
    else:
        raise FormatError(GGUF_UNREADABLE)


def gguf_metadata(read: Read, budget: InspectionBudget | None = None) -> GGUFMetadata:
    """Read the architecture and chat templates from a GGUF v2 or v3 header."""
    budget = budget or InspectionBudget()
    reader = _Reader(read, GGUF_UNREADABLE)
    if reader.take(4) != GGUF_MAGIC or reader.uint(4) not in (2, 3):
        raise FormatError(GGUF_UNREADABLE)
    reader.uint(8)
    count = reader.uint(8)
    if count > MAX_GGUF_KEYS:
        raise FormatError(GGUF_LIMIT)
    architecture: str | None = None
    templates: list[tuple[str, bytes]] = []
    for _ in range(count):
        budget.charge(1, GGUF_LIMIT)
        key = _gguf_string(reader)
        kind = reader.uint(4)
        # llama.cpp looks keys up as C strings, so a key ends at its first NUL there.
        base = key.split(b"\0", 1)[0]
        template = base == _TEMPLATE or base.startswith(_TEMPLATE + b".")
        if kind == _GGUF_STRING and (template or key == b"general.architecture"):
            value = _gguf_string(reader)
            if template:
                # Key names reach the inventory; an unusual one is named by position.
                name = (
                    key.decode("ascii")
                    if _TEMPLATE_KEY.fullmatch(key)
                    else f"tokenizer.chat_template.#{len(templates)}"
                )
                templates.append((name, value))
            elif _ARCHITECTURE.fullmatch(value):
                architecture = value.decode("ascii")
        else:
            _skip_gguf_value(reader, kind, 0, budget)
        if reader.offset > MAX_GGUF_METADATA_BYTES:
            raise FormatError(GGUF_LIMIT)
    return GGUFMetadata(architecture, tuple(templates))


# Chat templates ----------------------------------------------------------------

# These patterns can indicate an attempt to access Python internals. A match is
# not evidence that a template escapes the renderer's sandbox.
_TEMPLATE_ESCAPE = re.compile(
    r"\.\s*__[A-Za-z0-9_]+__|['\"]__[A-Za-z0-9_]+__['\"]|(?<![A-Za-z0-9_])attr\s*\("
    r"|\|\s*attr\b|\.\s*_(?:globals|builtins)\b"
    r"|['\"]__[A-Za-z0-9_]*['\"][\s)]*[~+]|[~+][\s(]*['\"][A-Za-z0-9_]*__['\"]"
    # A private name Python mangled, as in self._TemplateReference__context, which
    # reaches the render context without a dunder.
    r"|(?:\.\s*|['\"])_[A-Za-z0-9][A-Za-z0-9_]*__[A-Za-z0-9]"
    # Underscores repeated by string multiplication spell a dunder without writing one.
    r"|['\"]_+['\"][\s)]*\*|\*[\s(]*['\"]_+['\"]"
)
# The escapes Jinja decodes in a string literal, with an escaped backslash first so
# that it is consumed whole; every other backslash is kept as written. Jinja turns
# every line break into a line feed first, and a backslash before one is removed.
_STRING_ESCAPE = re.compile(
    r"\\(?:\\|\r\n?|\n|x[0-9A-Fa-f]{2}|u[0-9A-Fa-f]{4}|U[0-9A-Fa-f]{8}|[0-7]{1,3}"
    r"|N\{[A-Za-z0-9 -]{1,100}\})"
)


def _unescaped(match: re.Match[str]) -> str:
    if match.group()[1] in "\r\n":
        return ""
    try:
        return match.group().encode("ascii").decode("unicode-escape")
    except UnicodeDecodeError:
        return match.group()


_RAW_OPEN = re.compile(r"\{%[+-]?\s*raw\s*[+-]?%\}")
_RAW_CLOSE = re.compile(r"\{%[+-]?\s*endraw\s*[+-]?%\}")


def _joined_literal_marker(text: str) -> bool:
    """Find dunder names made by joining constant Jinja string literals.

    This is deliberately a bounded lexical heuristic, not a Jinja evaluator.
    Only adjacent quoted strings joined by ``~`` or ``+`` (or juxtaposed as
    Jinja permits) are folded. Other expressions and variables are not resolved.
    Work is linear in the input, including a long or unterminated literal, and
    the matcher keeps constant auxiliary state even for a long literal chain.
    """
    position = 0
    size = len(text)
    inside = False
    while position < size:
        if not inside:
            if text.startswith("{%", position):
                raw_open = _RAW_OPEN.match(text, position)
                if raw_open is not None:
                    raw_close = _RAW_CLOSE.search(text, raw_open.end())
                    position = size if raw_close is None else raw_close.end()
                    continue
                inside = True
                position += 2
            elif text.startswith("{{", position):
                inside = True
                position += 2
            elif text.startswith("{#", position):
                end = text.find("#}", position + 2)
                position = size if end < 0 else end + 2
            else:
                position += 1
            continue
        if text.startswith(("}}", "%}"), position):
            inside = False
            position += 2
            continue
        if text[position] not in "\"'":
            position += 1
            continue

        pieces = 0
        # State for the substring pattern __[A-Za-z0-9_]+__: zero, one
        # underscore, two underscores, body, one possible closing underscore,
        # or a match. This avoids collecting every decoded string in the chain.
        state = 0
        while position < size and text[position] in "\"'":
            quote = text[position]
            pieces += 1
            position += 1
            while position < size and text[position] != quote:
                if text[position] == "\\":
                    escape = _STRING_ESCAPE.match(text, position)
                    if escape is not None:
                        decoded = _unescaped(escape)
                        position = escape.end()
                    else:
                        decoded = text[position : position + 2]
                        position += 2
                else:
                    decoded = text[position]
                    position += 1
                for char in decoded:
                    if state == 5:
                        continue
                    if state == 0:
                        state = 1 if char == "_" else 0
                    elif state == 1:
                        state = 2 if char == "_" else 0
                    elif state == 2:
                        state = 3 if char.isascii() and (char.isalnum() or char == "_") else 0
                    elif state == 3:
                        state = 4 if char == "_" else 3 if char.isascii() and char.isalnum() else 0
                    else:
                        state = 5 if char == "_" else 3 if char.isascii() and char.isalnum() else 0
            if position >= size:
                return False
            position += 1
            after_string = position
            while position < size and (text[position].isspace() or text[position] in "()"):
                position += 1
            if position < size and text[position] in "~+":
                position += 1
                while position < size and (text[position].isspace() or text[position] in "()"):
                    position += 1
            if position >= size or text[position] not in "\"'":
                # Let the outer loop process the operator or expression boundary.
                position = after_string
                break
        if pieces > 1 and state == 5:
            return True
    return False


def template_escape_markers(template: bytes) -> bool:
    """Whether a template contains a potential Python-internals access pattern.

    The template is matched as Jinja reads it: as text, with string-literal escapes
    decoded, so ``\\x5f`` spells an underscore. Escapes outside a literal are decoded
    too, and the text is also matched as written, so decoding can only add a match.
    """
    text = template.decode("utf-8", "replace")
    if _TEMPLATE_ESCAPE.search(text) or _TEMPLATE_ESCAPE.search(
        _STRING_ESCAPE.sub(_unescaped, text)
    ):
        return True
    return _joined_literal_marker(text)
