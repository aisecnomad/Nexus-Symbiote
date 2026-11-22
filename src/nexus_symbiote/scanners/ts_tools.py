"""Bounded static MCP names from lexically bound TypeScript and JavaScript SDK registrations.

This records source declarations, never evaluated tool descriptors or runtime
registration. Servers are collected only when ``McpServer`` is imported from a
known module of the official SDK, by name or through a namespace import, and
constructed in a supported form. A module specifier names the SDK wherever its
scope appears in it: after ``npm:``, in a URL or in a path into ``node_modules``.
The uses of the SDK this analysis meets and does not follow are explicit collection
gaps: another import form or module path, a module load by ``require`` or dynamic
import, also of a module name it cannot read, a re-export, the low-level ``Server``
class, a client transport that starts or reaches a server, a direct ``eval``,
dynamic names, unsupported bindings and registration ordering. It does not see the
SDK behind an alias resolved outside the file, such as a ``#`` subpath import, or
what code does with a collected server other than registering tools on it. No
source module or package code is executed.

TypeScript is parsed with the TypeScript grammar, and ``.tsx`` and JavaScript with
its TSX variant, as tsc reads them. The grammar is TypeScript's, so a JavaScript file
it cannot parse, or that it reads as type syntax where JavaScript reads a comparison,
is a gap rather than a failure.

The tree-sitter runtime and grammar are native code and parse the file in this
process, bounded by the source size and a node limit. A limit on the processor time
of one parse remains as a backstop for input the grammar cannot parse, whose parse
no size bounds; how busy the machine is does not count toward it. They are not
isolated in a separate process.
"""

from __future__ import annotations

import codecs
import re
import sys
import time
import warnings
from collections.abc import Callable, Collection, Iterator
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote, unquote

if TYPE_CHECKING:
    from tree_sitter import Node, Parser, Tree

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.limits import Bound
from nexus_symbiote.scanners.base import KnownValues, ScanResult, declared_server_name

_SDK = "@modelcontextprotocol/"
_MODULES = {"@modelcontextprotocol/server", "@modelcontextprotocol/sdk/server/mcp.js"}
_IGNORED = {"dist", "build", "__tests__", "tests", "test", "docs", "benchmarks", "examples"}
# Whether tsc reads a suffix with JSX: TypeScript without, .tsx and JavaScript with.
_JSX = {
    ".ts": False,
    ".mts": False,
    ".cts": False,
    ".tsx": True,
    ".js": True,
    ".jsx": True,
    ".mjs": True,
    ".cjs": True,
}
SCRIPT_SUFFIXES = frozenset(_JSX)
_JAVASCRIPT = frozenset({".js", ".jsx", ".mjs", ".cjs"})
NOT_SOURCE_NAMES = (
    ".d.ts",
    ".d.mts",
    ".d.cts",
    *(f".{kind}{suffix}" for kind in ("spec", "test") for suffix in _JSX),
)
SDK_MARKER = b"@modelcontextprotocol/"
# A file is parsed when it names the SDK and a server or client transport class, or
# names a server or client module, also by a build path or with a version, so a
# server or launch built by any import form is seen.
_CLASS_MARKERS = (b"McpServer", b"ClientTransport")
_MODULE_MARKERS = (
    *(b"@modelcontextprotocol/sdk" + end for end in (b"/server", b"/client", b"/dist", b"@")),
    *(
        b"@modelcontextprotocol/" + package + end
        for package in (b"server", b"client")
        for end in (b'"', b"'", b"`", b"/", b"@", b"?", b"#")
    ),
)
SOURCE_MARKERS = (SDK_MARKER, *_CLASS_MARKERS, *_MODULE_MARKERS)
# tsc and web browsers decode a source file that starts with a UTF-16 byte order
# mark as UTF-16 (bun only the little-endian form), and any other file as UTF-8.
UTF16_BYTE_ORDER_MARKS = {codecs.BOM_UTF16_LE: "utf-16-le", codecs.BOM_UTF16_BE: "utf-16-be"}
MAX_REGISTRATIONS = 1_000
# The processor time one parse may use, the bound releases up to 0.2.0 set as wall-clock time
# and scaled the same way: a file whose parse needs more is refused. It bounds only
# the parse, because the analysis after it is linear in the nodes ts-nodes bounds. A
# busy machine does not use it up, and the one-time load of the native parser before
# the first parse does not count toward it.
MAX_PARSE_SECONDS = 0.25
# The parser can be stopped only after an interval of wall-clock time. The interval
# equals the processor budget, which is the wall-clock deadline used before, so a parse
# the grammar cannot end reaches, in one attempt, exactly the point it was stopped at,
# and uses no more time or memory. The interval does not grow between attempts.
_PARSE_INTERVAL = 1.0
# Attempts before a file is refused for want of its processor time. A parse the clock
# stops while the machine held it up is retried from the beginning a few times, which
# absorbs a brief scheduling stall, so that a small server is still collected. Each
# attempt costs at most one budget.
_PARSE_ATTEMPTS = 3
# A stopped parse that had at least this share of its budget as processor time was not
# held up: another attempt would spend the same again, so it is refused at once. An idle
# machine measures just under the whole budget, never all of it, because the processor
# clock leaves out the moments the thread did not run.
_HELD_UP_SHARE = 0.5

LAUNCHED = "MCP server launched from application code; launcher not inventoried"
REACHED = "MCP server reached from application code; endpoint not inventoried"
_TRANSPORTS = {
    "StdioClientTransport": LAUNCHED,
    "SSEClientTransport": REACHED,
    "StreamableHTTPClientTransport": REACHED,
    "WebSocketClientTransport": REACHED,
}
_LOW_LEVEL = "low-level MCP server tool list uncollected"
_UNSUPPORTED_IMPORT = "unsupported MCP SDK import"
_UNSUPPORTED_BINDING = "unsupported MCP server SDK binding"
_NAMESPACE_USE = "unsupported use of an MCP SDK namespace"
_UNREAD_MODULE = "module specifier the analysis cannot read"
_EVALUATED = "direct eval can use the MCP SDK imports of the file; what it builds not inventoried"
_REEXPORTED = (
    "MCP SDK class re-exported; servers it builds, starts or reaches elsewhere not inventoried"
)
_LOADED = {
    "server": "MCP server SDK loaded by require or dynamic import; servers and tools not "
    "inventoried",
    "client": "MCP client SDK loaded by require or dynamic import; servers it starts or "
    "reaches not inventoried",
}
_COMPUTED_LOAD = (
    "require or dynamic import of a module name the analysis cannot read; what it loads not "
    "inventoried"
)
_NAMED = "MCP SDK module named as a call argument; what the call loads not inventoried"
# Expressions that evaluate to one operand: `(0, require)`, `require as Loader`, `require!`,
# `eval<any>` (type arguments are erased).
_WRAPPERS = frozenset(
    {
        "parenthesized_expression",
        "sequence_expression",
        "type_assertion",
        "as_expression",
        "satisfies_expression",
        "non_null_expression",
        "instantiation_expression",
    }
)
_OPERAND_FIRST = frozenset(
    {"as_expression", "satisfies_expression", "non_null_expression", "instantiation_expression"}
)
# `(eval)(code)` and `eval!(code)` still call eval directly; `(0, eval)(code)` does not.
_REFERENCE_WRAPPERS = _WRAPPERS - {"sequence_expression"}
_UNPARSED_JAVASCRIPT = (
    "JavaScript the TypeScript grammar cannot parse; servers and tools in the file not inventoried"
)
_TYPE_READING = (
    "JavaScript comparison the TypeScript grammar reads as type arguments; servers and "
    "tools in the file not inventoried"
)
# Type syntax, which TypeScript erases: a name inside it is no runtime reference.
_TYPE_SYNTAX = frozenset(
    {
        "type_annotation",
        "type_arguments",
        "type_parameters",
        "type_query",
        "type_alias_declaration",
        "interface_declaration",
        "implements_clause",
        "extends_type_clause",
        "ambient_declaration",
        "function_signature",
        "method_signature",
        "abstract_method_signature",
        "index_signature",
        "property_signature",
        "call_signature",
        "construct_signature",
        "nested_type_identifier",
        "generic_type",
        "object_type",
        "function_type",
        "constructor_type",
        "union_type",
        "intersection_type",
        "array_type",
        "tuple_type",
        "parenthesized_type",
        "lookup_type",
        "index_type_query",
        "conditional_type",
        "infer_type",
        "literal_type",
        "readonly_type",
        "template_literal_type",
        "predefined_type",
        "type_predicate",
        "type_predicate_annotation",
        "asserts",
        "asserts_annotation",
        "opting_type_annotation",
        "omitting_type_annotation",
        "adding_type_annotation",
    }
)
# Statements and specifiers that ``type`` makes type-only: `export type { X }`.
_TYPE_ONLY_CAPABLE = frozenset(
    {"import_statement", "import_specifier", "export_statement", "export_specifier"}
)
_IDENTIFIER_ESCAPE = re.compile(r"\\u(?:\{([0-9A-Fa-f]{1,6})\}|([0-9A-Fa-f]{4}))")
_HEX_ESCAPE = re.compile(r"x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|u\{([0-9A-Fa-f]{1,6})\}")
_SINGLE_ESCAPES = {"b": "\b", "f": "\f", "n": "\n", "r": "\r", "t": "\t", "v": "\v", "0": "\0"}
_LINE_CONTINUATIONS = frozenset({"\n", "\r", "\r\n", "\u2028", "\u2029"})


class _RefusedError(ValueError):
    """The file was not collected; the message names why and quotes no source."""


@dataclass(frozen=True)
class _Namespace:
    """A namespace import of an SDK module: server, client or other, and the collected one."""

    kind: str
    exact: bool


@dataclass(frozen=True)
class _Launcher:
    """A client transport class of the SDK, which starts or reaches a server."""

    reason: str


def is_server_source(path: Path) -> bool:
    """A TypeScript or JavaScript file this collector supports, before its content is known."""
    return (
        path.suffix in SCRIPT_SUFFIXES
        and not _IGNORED.intersection(path.parts)
        and not path.name.endswith(NOT_SOURCE_NAMES)
    )


def is_analysis_candidate(found: Collection[bytes]) -> bool:
    """Whether the markers a search found make a script one the analysis parses."""
    return (SDK_MARKER in found and any(marker in found for marker in _CLASS_MARKERS)) or any(
        marker in found for marker in _MODULE_MARKERS
    )


def source_text(content: bytes) -> str:
    """The text tsc reads from one complete source file; a ValueError says why there is none."""
    encoding = UTF16_BYTE_ORDER_MARKS.get(content[:2])
    try:
        return content.decode("utf-8") if encoding is None else content[2:].decode(encoding)
    except UnicodeDecodeError:
        raise _RefusedError("invalid UTF-8" if encoding is None else "invalid UTF-16") from None


def _value(node: Node | None) -> str:
    return ((node.text or b"") if node is not None else b"").decode("utf-8")


def _code_point(match: re.Match[str]) -> str:
    value = int(match.group(1) or match.group(2), 16)
    return chr(value) if value <= 0x10FFFF else match.group(0)


def _name(node: Node | None) -> str:
    """An identifier as JavaScript reads it: ``\\u0073erver`` is ``server``."""
    text = _value(node)
    return text if "\\" not in text else _IDENTIFIER_ESCAPE.sub(_code_point, text)


def _escape(sequence: str) -> str | None:
    """The text one string escape sequence stands for; None for legacy octal forms."""
    body = sequence[1:]
    hexadecimal = _HEX_ESCAPE.fullmatch(body)
    if hexadecimal is not None:
        value = int(next(group for group in hexadecimal.groups() if group), 16)
        return chr(value) if value <= 0x10FFFF else None
    if body in _SINGLE_ESCAPES:
        return _SINGLE_ESCAPES[body]
    if body in _LINE_CONTINUATIONS:
        return ""
    return body if len(body) == 1 and not body.isdigit() and body not in {"x", "u"} else None


def _string_value(node: Node | None) -> str | None:
    """A string or substitution-free template literal as JavaScript reads it, else None."""
    if node is None or node.type not in {"string", "template_string"}:
        return None
    parts: list[str] = []
    for child in node.named_children:
        if child.type == "string_fragment":
            parts.append(_value(child))
            continue
        decoded = _escape(_value(child)) if child.type == "escape_sequence" else None
        if decoded is None:
            return None
        parts.append(decoded)
    return "".join(parts)


def _module_kind(module: str) -> str | None:
    """Whether a module specifier names a server, client or other module of the SDK.

    The scope counts wherever it appears, since a runtime or bundler can resolve it
    there: after ``npm:`` or ``jsr:``, in a URL, in a path into ``node_modules``, with a
    version after the package name, with a query or fragment, percent-encoded, with
    backslashes or in another letter case. Only the exact names in ``_MODULES`` are
    followed.
    """
    text = unquote(module).replace("\\", "/").lower()
    start = text.find(_SDK)
    if start < 0:
        return None
    path = re.split(r"[?#]", text[start + len(_SDK) :], maxsplit=1)[0]
    package, *rest = path.split("/")
    segments = [package.split("@", 1)[0], *rest]
    for kind in ("server", "client"):
        if kind in segments:
            return kind
    return "other"


def _type_only(node: Node) -> bool:
    return any(child.type == "type" for child in node.children)


def _same(node: Node | None, other: Node) -> bool:
    return node is not None and node.id == other.id


def _nodes(root: Node, limit: Bound) -> Iterator[Node]:
    pending = [root]
    count = 0
    while pending:
        node = pending.pop()
        count += 1
        if count > limit.value:
            raise _RefusedError(limit.exceeded())
        yield node
        pending.extend(reversed(node.named_children))


_FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
}
# Where `var` and function parameters live; `let`, `const` and `class` stay in the
# nearest of _SCOPES, which adds the blocks and the loop and switch heads.
_VAR_SCOPES = {"program", "class_static_block", "internal_module", "module", *_FUNCTIONS}
_SCOPES = {
    "statement_block",
    "catch_clause",
    "for_statement",
    "for_in_statement",
    "switch_body",
    *_VAR_SCOPES,
}


@dataclass
class _Index:
    """Every named node once, with its parent, its enclosing scope and whether it is erased.

    tree-sitter finds a node's parent by descending from the root, so climbing
    ``Node.parent`` costs the depth at every step. Recording these relations in one
    traversal keeps the analysis linear in the number of nodes. ``erased`` holds the
    nodes inside type syntax, which has no runtime effect. ``hoists`` maps each scope
    to the function, module or static block that a ``var`` declared in it belongs to.
    """

    nodes: list[Node]
    parents: dict[int, Node]
    scopes: dict[int, Node]
    hoists: dict[int, Node]
    erased: set[int]

    def parent(self, node: Node | None) -> Node | None:
        return None if node is None else self.parents.get(node.id)

    def scope(self, node: Node | None) -> Node | None:
        """The nearest scope that is ``node`` itself or encloses it."""
        return None if node is None else self.scopes.get(node.id)

    def var_scope(self, node: Node | None) -> Node | None:
        """The scope a ``var`` declared at ``node`` is hoisted to."""
        scope = self.scope(node)
        return None if scope is None else self.hoists.get(scope.id)


def _index(root: Node, limit: Bound) -> _Index:
    index = _Index([], {}, {}, {}, set())
    pending: list[tuple[Node, Node | None]] = [(root, None)]
    while pending:
        node, parent = pending.pop()
        if len(index.nodes) >= limit.value:
            raise _RefusedError(limit.exceeded())
        index.nodes.append(node)
        if parent is not None:
            index.parents[node.id] = parent
        if parent is None or node.type in _SCOPES:
            index.scopes[node.id] = node
            index.hoists[node.id] = (
                node
                if parent is None or node.type in _VAR_SCOPES
                else index.hoists[index.scopes[parent.id].id]
            )
        else:
            index.scopes[node.id] = index.scopes[parent.id]
        if (
            (parent is not None and parent.id in index.erased)
            or node.type in _TYPE_SYNTAX
            or (node.type in _TYPE_ONLY_CAPABLE and _type_only(node))
        ):
            index.erased.add(node.id)
        pending.extend((child, node) for child in reversed(node.named_children))
    return index


def _pattern_names(node: Node | None) -> list[str]:
    """Names a declaration pattern binds; default values and types declare nothing."""
    names: list[str] = []
    pending = [] if node is None else [node]
    while pending:
        current = pending.pop()
        kind = current.type
        if kind in {"identifier", "shorthand_property_identifier_pattern"}:
            names.append(_name(current))
            continue
        children: list[Node | None]
        if kind in {"object_pattern", "array_pattern", "rest_pattern", "formal_parameters"}:
            children = list(reversed(current.named_children))
        elif kind == "pair_pattern":
            children = [current.child_by_field_name("value")]
        elif kind in {"assignment_pattern", "object_assignment_pattern"}:
            children = [current.child_by_field_name("left")]
        elif kind in {"required_parameter", "optional_parameter"}:
            children = [current.child_by_field_name("pattern")]
        else:
            continue
        pending.extend(child for child in children if child is not None)
    return names


@dataclass
class _Declarations:
    """The names a file binds, the SDK import forms that are gaps, and the import identifiers.

    ``declared`` holds the identifiers inside import and re-export statements, which
    bind a name or name another module's export and never use a binding of this file.
    ``loaders`` holds ``require`` and every name the file binds to what
    ``createRequire`` returns, and ``creators`` ``createRequire`` and every name the
    file binds to it.
    """

    bindings: dict[tuple[int, str], object]
    gaps: list[tuple[Node, str]]
    declared: set[int]
    loaders: set[str]
    creators: set[str]


def _imported_name(node: Node | None) -> str | None:
    """An imported or exported name, which may be a string: ``import { "a b" as c }``."""
    if node is not None and node.type == "string":
        return _string_value(node)
    return _name(node)


def _namespace_body(index: _Index, node: Node | None) -> bool:
    """Whether ``node`` is the body of a ``namespace`` or ``module`` declaration."""
    owner = index.parent(node)
    return (
        node is not None
        and node.type == "statement_block"
        and owner is not None
        and owner.type in {"internal_module", "module"}
    )


def _bind_import(
    statement: Node,
    root: Node | None,
    bind: Callable[[Node | None, str, object, Node], None],
    found: _Declarations,
) -> None:
    """Bind the names one import declares, sorting the SDK forms the analysis follows."""
    clause = next((c for c in statement.named_children if c.type == "import_require_clause"), None)
    module = _string_value((clause or statement).child_by_field_name("source"))
    if module is None:
        found.gaps.append((statement, _UNREAD_MODULE))
    kind = None if module is None or _type_only(statement) else _module_kind(module)
    for spec in _nodes(statement, limits.bound("ts-nodes")):
        if spec.type == "identifier":
            found.declared.add(spec.id)
        elif spec.type == "import_specifier":
            imported = _imported_name(spec.child_by_field_name("name"))
            alias = spec.child_by_field_name("alias")
            value: object = "other"
            if kind is not None and not _type_only(spec):
                if (
                    imported is None
                    or (imported == "McpServer" and module not in _MODULES)
                    or (imported == "default" and kind in {"server", "client"})
                ):
                    found.gaps.append((spec, _UNSUPPORTED_IMPORT))
                elif imported == "McpServer":
                    value = "sdk"
                elif imported == "Server" and kind == "server":
                    found.gaps.append((spec, _LOW_LEVEL))
                elif imported in _TRANSPORTS:
                    value = _Launcher(_TRANSPORTS[imported])
            bind(root, _name(alias) if alias is not None else imported or "", value, spec)
        elif spec.type == "namespace_import":
            for child in spec.named_children:
                if child.type == "identifier":
                    namespace = None if kind is None else _Namespace(kind, module in _MODULES)
                    bind(root, _name(child), namespace or "other", child)
        elif spec.type in {"import_clause", "import_require_clause"}:
            for child in spec.named_children:
                if child.type != "identifier":
                    continue
                # A default import of a server or client module may be the whole module.
                if kind in {"server", "client"}:
                    reason = _LOADED[kind] if spec.type == "import_require_clause" else None
                    found.gaps.append((child, reason or _UNSUPPORTED_IMPORT))
                bind(root, _name(child), "other", child)


def _reexport(statement: Node, found: _Declarations) -> None:
    """Record a re-export of an SDK class or module: what is built from it is elsewhere."""
    specifiers: list[Node] = []
    for node in _nodes(statement, limits.bound("ts-nodes")):
        if node.type == "identifier":
            found.declared.add(node.id)
        elif node.type == "export_specifier" and not _type_only(node):
            specifiers.append(node)
    module = _string_value(statement.child_by_field_name("source"))
    if module is None:
        found.gaps.append((statement, _UNREAD_MODULE))
        return
    kind = _module_kind(module)
    if kind is None or _type_only(statement):
        return
    module_wide = kind in {"server", "client"}
    whole = any(child.type in {"*", "namespace_export"} for child in statement.children)
    if whole and module_wide:
        found.gaps.append((statement, _REEXPORTED))
    for spec in specifiers:
        name = _imported_name(spec.child_by_field_name("name"))
        if (
            name in {None, "McpServer", *_TRANSPORTS}
            or (name == "Server" and kind == "server")
            or (name == "default" and module_wide)
        ):
            found.gaps.append((spec, _REEXPORTED))


def _creators(index: _Index) -> set[str]:
    """``createRequire`` and the names an import, a destructuring or an alias gives it.

    A name bound to any of them may be one, wherever it is bound, so the set only grows.
    """
    creators = {"createRequire"}
    for _ in range(8):
        before = len(creators)
        for node in index.nodes:
            if node.id in index.erased:
                continue
            if node.type == "import_specifier":
                if _imported_name(node.child_by_field_name("name")) == "createRequire":
                    alias = node.child_by_field_name("alias")
                    if alias is not None:
                        creators.add(_name(alias))
            elif node.type == "pair_pattern":
                if _literal_key(node.child_by_field_name("key")) == "createRequire":
                    target = node.child_by_field_name("value")
                    if target is not None and target.type == "assignment_pattern":
                        target = target.child_by_field_name("left")
                    if (alias_name := _identifier(target)) is not None:
                        creators.add(alias_name)
            elif node.type in {"variable_declarator", "assignment_expression"}:
                value = _operand(
                    node.child_by_field_name(
                        "value" if node.type == "variable_declarator" else "right"
                    )
                )
                if value is not None and (
                    (value.type == "identifier" and _name(value) in creators)
                    or _property(value) == "createRequire"
                ):
                    target = node.child_by_field_name(
                        "name" if node.type == "variable_declarator" else "left"
                    )
                    if (alias_name := _identifier(target)) is not None:
                        creators.add(alias_name)
        if len(creators) == before:
            break
    return creators


def _bindings(index: _Index, root: Node) -> _Declarations:
    found = _Declarations({}, [], set(), {"require"}, _creators(index))
    bindings = found.bindings
    followed: set[tuple[int, str]] = set()

    def bind(scope: Node | None, name: str, value: object, at: Node) -> None:
        if scope is None or not name:
            return
        key = (scope.id, name)
        if value == "sdk" or isinstance(value, (_Namespace, _Launcher)):
            followed.add(key)
        if key not in bindings:
            bindings[key] = value
            return
        bindings[key] = "ambiguous"
        if key in followed:
            # Which declaration a use names is unknown, so nothing built from it is followed.
            found.gaps.append((at, _UNSUPPORTED_BINDING))

    for node in index.nodes:
        if node.id in index.erased:
            continue
        parent = index.parent(node)
        at_root = parent is not None and parent.id == root.id
        if node.type == "import_statement" and at_root:
            _bind_import(node, root, bind, found)
        elif node.type == "import_statement" and _namespace_body(index, parent):
            # ``import x = require(...)`` loads a module inside a namespace body as well.
            _bind_import(node, index.scope(parent), bind, found)
        elif node.type == "export_statement" and at_root and node.child_by_field_name("source"):
            _reexport(node, found)
        elif node.type == "variable_declarator":
            target = node.child_by_field_name("name")
            hoisted = parent is not None and parent.type == "variable_declaration"
            scope = index.var_scope(parent) if hoisted else index.scope(parent)
            for declared_name in _pattern_names(target):
                bind(scope, declared_name, node.id, node)
            if _creates_require(node.child_by_field_name("value"), found.creators):
                found.loaders.update(_pattern_names(target))
        elif node.type == "assignment_expression":
            if _creates_require(node.child_by_field_name("right"), found.creators):
                found.loaders.update(_pattern_names(node.child_by_field_name("left")))
        elif node.type in _FUNCTIONS:
            name = node.child_by_field_name("name")
            # A method's name is a property key: `McpServer() {}` binds no McpServer.
            if name is not None and node.type != "method_definition":
                bind(
                    index.scope(parent) if "declaration" in node.type else node,
                    _name(name),
                    "other",
                    node,
                )
            parameters = node.child_by_field_name("parameters") or node.child_by_field_name(
                "parameter"
            )
            for parameter in _pattern_names(parameters):
                bind(node, parameter, "parameter", node)
        elif node.type in {"class_declaration", "enum_declaration"}:
            bind(index.scope(parent), _name(node.child_by_field_name("name")), "other", node)
        elif node.type == "catch_clause":
            for caught_name in _pattern_names(node.child_by_field_name("parameter")):
                bind(node, caught_name, "other", node)
        elif node.type == "for_in_statement":
            kind = node.child_by_field_name("kind")
            if kind is not None:
                scope = index.var_scope(parent) if kind.type == "var" else node
                for loop_name in _pattern_names(node.child_by_field_name("left")):
                    bind(scope, loop_name, "other", node)
    for _ in range(8):
        before = len(found.loaders)
        for node in index.nodes:
            if node.id in index.erased:
                continue
            if node.type in {"variable_declarator", "assignment_expression"}:
                rhs = _operand(
                    node.child_by_field_name(
                        "value" if node.type == "variable_declarator" else "right"
                    )
                )
                if rhs is not None and rhs.type == "identifier" and _name(rhs) in found.loaders:
                    lhs = node.child_by_field_name(
                        "name" if node.type == "variable_declarator" else "left"
                    )
                    found.loaders.update(_pattern_names(lhs))
        if len(found.loaders) == before:
            break
    return found


class _Resolver:
    """The binding each name in the file refers to, found in one walk of the tree.

    The walk keeps, for every name, the stack of bindings in effect, so resolving all
    references costs one step each however deep the scopes or many the names. A
    binding's value can change later, when a server is bound to its receiver; which
    binding a reference names cannot.
    """

    def __init__(self, root: Node, bindings: dict[tuple[int, str], object]) -> None:
        self.bindings = bindings
        self._targets: dict[int, tuple[int, str]] = {}
        declared: dict[int, list[str]] = {}
        for scope_id, name in bindings:
            declared.setdefault(scope_id, []).append(name)
        active: dict[str, list[tuple[int, str]]] = {}
        pending: list[tuple[Node, bool]] = [(root, False)]
        while pending:
            node, leaving = pending.pop()
            names = declared.get(node.id, ())
            if leaving:
                for name in names:
                    active[name].pop()
                continue
            if node.type in {"identifier", "shorthand_property_identifier"}:
                stack = active.get(_name(node))
                if stack:
                    self._targets[node.id] = stack[-1]
            if names:
                for name in names:
                    active.setdefault(name, []).append((node.id, name))
                pending.append((node, True))
            pending.extend((child, False) for child in reversed(node.named_children))

    def bind(self, scope: Node, name: str, value: object) -> None:
        self.bindings[(scope.id, name)] = value

    def lookup(self, node: Node | None) -> object:
        """The value of the binding an identifier refers to, or None when it is unbound."""
        target = None if node is None else self._targets.get(node.id)
        return None if target is None else self.bindings.get(target)


def _identifier(node: Node | None) -> str | None:
    """A plain name, without copying the text of a larger expression."""
    return _name(node) if node is not None and node.type == "identifier" else None


_COMPUTED_BUILTINS = frozenset({"Math", "console"})


def _ordinary_builtin_value(value: Node | None, receiver: str) -> bool:
    value = _operand(value)
    if value is None:
        return False
    if value.type == "arrow_function":
        parameters = value.child_by_field_name("parameters")
        if parameters is None or parameters.named_child_count:
            return False
        value = _operand(value.child_by_field_name("body"))
        return value is not None and value.type in {"number", "string", "true", "false", "null"}
    if value.type in {"number", "string", "true", "false", "null"}:
        return True
    return (
        value.type in {"member_expression", "subscript_expression"}
        and _identifier(_operand(value.child_by_field_name("object"))) == receiver
        and _called_method(value) is not None
    )


_GLOBAL_OBJECTS = frozenset({"globalThis", "global", "self", "window"})


def _collect_arg_builtin_refs(arg: Node, assigned: set[str]) -> None:
    """Record computed builtins passed by reference directly or through value containers."""
    pending: list[Node] = [arg]
    while pending:
        operand = _operand(pending.pop())
        if operand is None:
            continue
        name = _identifier(operand)
        if name is not None:
            if name in _COMPUTED_BUILTINS:
                assigned.add(name)
            elif name in _GLOBAL_OBJECTS:
                assigned.update(_COMPUTED_BUILTINS)
            continue
        if operand.type in {"member_expression", "subscript_expression"}:
            if _identifier(_operand(operand.child_by_field_name("object"))) in _GLOBAL_OBJECTS:
                prop = _called_method(operand)
                if prop is None:
                    assigned.update(_COMPUTED_BUILTINS)
                elif prop in _COMPUTED_BUILTINS:
                    assigned.add(prop)
            continue
        if operand.type in {"array", "object", "spread_element", "sequence_expression"}:
            pending.extend(operand.named_children)
        elif operand.type == "pair":
            val = operand.child_by_field_name("value")
            if val is not None:
                pending.append(val)
        elif operand.type == "shorthand_property_identifier":
            shorthand = _name(operand)
            if shorthand in _COMPUTED_BUILTINS:
                assigned.add(shorthand)
            elif shorthand in _GLOBAL_OBJECTS:
                assigned.update(_COMPUTED_BUILTINS)
        elif operand.type == "ternary_expression":
            for field in ("consequence", "alternative"):
                branch = operand.child_by_field_name(field)
                if branch is not None:
                    pending.append(branch)
        elif operand.type == "binary_expression":
            for field in ("left", "right"):
                side = operand.child_by_field_name(field)
                if side is not None:
                    pending.append(side)
        elif operand.type == "assignment_expression":
            rhs = operand.child_by_field_name("right")
            if rhs is not None:
                pending.append(rhs)


def _assigned_computed_builtins(index: _Index) -> set[str]:
    assigned: set[str] = set()
    for node in index.nodes:
        if node.id in index.erased:
            continue
        if node.type == "call_expression":
            arguments = node.child_by_field_name("arguments")
            if arguments is not None and arguments.type == "arguments":
                for arg in _parts(arguments):
                    _collect_arg_builtin_refs(arg, assigned)
            continue
        if node.type not in {"assignment_expression", "augmented_assignment_expression"}:
            continue
        target = _operand(node.child_by_field_name("left"))
        assigned.update(_COMPUTED_BUILTINS.intersection(_pattern_names(target)))
        if target is None or target.type not in {"member_expression", "subscript_expression"}:
            continue
        receiver = _identifier(_operand(target.child_by_field_name("object")))
        if receiver is not None and receiver in _COMPUTED_BUILTINS:
            if node.type != "assignment_expression" or not _ordinary_builtin_value(
                node.child_by_field_name("right"), receiver
            ):
                assigned.add(receiver)
        elif receiver in _GLOBAL_OBJECTS:
            property_name = _called_method(target)
            if property_name is None:
                assigned.update(_COMPUTED_BUILTINS)
            elif property_name in _COMPUTED_BUILTINS:
                assigned.add(property_name)
    return assigned


def _called_method(member: Node) -> str | None:
    """Return the static method name, or None when its spelling needs evaluation."""
    if member.type == "member_expression":
        name = _value(member.child_by_field_name("property"))
        return None if "\\" in name else name
    index = member.child_by_field_name("index")
    if index is None or index.type not in {"string", "template_string"}:
        return None
    if any(child.type != "string_fragment" for child in index.named_children):
        return None
    return _value(index)[1:-1]


def _parts(node: Node) -> list[Node]:
    """The named children of ``node`` other than comments.

    The grammar gives a comment as a child of the node it sits in, so ``(require /* */)``
    would otherwise read as a comment in place of the callee.
    """
    return [child for child in node.named_children if not child.is_extra]


def _operand(node: Node | None, wrappers: Collection[str] = _WRAPPERS) -> Node | None:
    """The expression a wrapper such as ``(0, require)`` or ``require as Loader`` evaluates to."""
    while node is not None and node.type in wrappers and (children := _parts(node)):
        node = children[0] if node.type in _OPERAND_FIRST else children[-1]
    return node


def _property(member: Node) -> str | None:
    """A member's name as JavaScript reads it, or None when it is computed."""
    if member.type == "member_expression":
        return _name(member.child_by_field_name("property"))
    if member.type == "subscript_expression":
        return _string_value(member.child_by_field_name("index"))
    return None


def _creates_require(node: Node | None, creators: Collection[str]) -> bool:
    """Whether an expression calls ``createRequire``, which returns a module loader."""
    call = _operand(node)
    if call is None or call.type != "call_expression":
        return False
    function = _operand(call.child_by_field_name("function"))
    if function is not None and function.type == "identifier":
        return _name(function) in creators
    return function is not None and _property(function) == "createRequire"


def _loader(function: Node | None, loaders: Collection[str], creators: Collection[str]) -> bool:
    """Whether a callee loads a module: ``import``, ``require``, ``module.require`` or a loader
    ``createRequire`` made."""
    callee = _operand(function)
    if callee is not None and callee.type in {"import", "identifier"}:
        return callee.type == "import" or _name(callee) in loaders
    return callee is not None and (
        _property(callee) == "require" or _creates_require(callee, creators)
    )


def _load(
    call: Node, loaders: Collection[str], creators: Collection[str]
) -> tuple[bool, Node | None]:
    """Whether a call loads a module, and the argument that names it, if any.

    The name is the first argument of a direct call, the second of ``call`` and of
    ``bind``, whose bound loader is a load wherever it is called, and the first
    element of the array literal ``apply`` passes; for any other call, the first
    argument is returned for the caller to check.
    """
    function = _operand(call.child_by_field_name("function"))
    arguments = call.child_by_field_name("arguments")
    # A tagged template passes no specifier a loader accepts.
    listed = arguments is not None and arguments.type == "arguments"
    values = _parts(arguments) if arguments is not None and listed else []
    if _loader(function, loaders, creators):
        return True, values[0] if values else None
    method = None if function is None else _property(function)
    if function is not None and method in {"call", "apply", "bind"}:
        if _loader(function.child_by_field_name("object"), loaders, creators):
            passed = values[1] if len(values) > 1 else None
            if method == "apply":
                array = passed is not None and passed.type == "array"
                elements = _parts(passed) if passed is not None and array else []
                passed = elements[0] if elements else None
            return True, passed
    return False, values[0] if values else None


def _names_module_elsewhere(call: Node) -> bool:
    """Whether a call passes a server or client module's name in any argument or container literal."""
    arguments = call.child_by_field_name("arguments")
    if arguments is None or arguments.type != "arguments":
        return False
    pending = list(reversed(_parts(arguments)))
    while pending:
        value = _operand(pending.pop())
        if value is None:
            continue
        module = _string_value(value)
        if module is not None and _module_kind(module) in _LOADED:
            return True
        if value.type in {"array", "object", "spread_element"}:
            pending.extend(reversed(_parts(value)))
        elif value.type == "pair":
            if (rhs := value.child_by_field_name("value")) is not None:
                pending.append(rhs)
    return False


def _is_constructor(node: Node, index: _Index) -> bool:
    """Whether ``node`` is what a ``new`` expression constructs."""
    outer = index.parent(node)
    return (
        outer is not None
        and outer.type == "new_expression"
        and _same(outer.child_by_field_name("constructor"), node)
    )


def _use(node: Node, binding: object, index: _Index) -> str | None:
    """The gap one use of an SDK import leaves, or None when the analysis follows it."""
    parent = index.parent(node)
    if parent is not None and parent.type == "export_specifier":
        if _same(parent.child_by_field_name("alias"), node):
            return None
    if binding == "sdk":
        return None if _is_constructor(node, index) else _UNSUPPORTED_BINDING
    if isinstance(binding, _Launcher):
        return binding.reason
    if not isinstance(binding, _Namespace):
        return None
    member = (
        parent
        if parent is not None
        and parent.type in {"member_expression", "subscript_expression"}
        and _same(parent.child_by_field_name("object"), node)
        else None
    )
    name = None if member is None else _property(member)
    # With CommonJS interop, ``default`` can be the whole module again.
    if name is None or name == "default":
        return _NAMESPACE_USE if binding.kind in {"server", "client"} else None
    if name == "McpServer" and member is not None:
        if not binding.exact:
            return _UNSUPPORTED_IMPORT
        return None if _is_constructor(member, index) else _UNSUPPORTED_BINDING
    if name == "Server" and binding.kind == "server":
        return _LOW_LEVEL
    return _TRANSPORTS.get(name)


def _sdk_uses(index: _Index, root: Node, found: _Declarations, resolver: _Resolver) -> None:
    """Record each use of the SDK the analysis does not follow as a gap.

    A use is an identifier outside type syntax that resolves to an SDK import; a
    module load, such as ``require`` or ``import()``, of a server or client module or
    of a name the analysis cannot read; any other call whose first argument names a
    server or client module; and a direct ``eval``, which can reach the imports of
    the module it runs in.
    """
    tracked = {
        name
        for (scope, name), value in found.bindings.items()
        if scope == root.id and (value == "sdk" or isinstance(value, (_Namespace, _Launcher)))
    }
    for node in index.nodes:
        if node.id in index.erased:
            continue
        if node.type == "call_expression":
            function = node.child_by_field_name("function")
            if tracked and _identifier(_operand(function, _REFERENCE_WRAPPERS)) == "eval":
                found.gaps.append((node, _EVALUATED))
            loads, specifier = _load(node, found.loaders, found.creators)
            module = _string_value(specifier)
            kind = None if module is None else _module_kind(module)
            if loads and module is None:
                found.gaps.append((node, _COMPUTED_LOAD))
            elif kind in _LOADED:
                found.gaps.append((node, _LOADED[kind] if loads else _NAMED))
            elif not loads and _names_module_elsewhere(node):
                found.gaps.append((node, _NAMED))
            continue
        if (
            node.type not in {"identifier", "shorthand_property_identifier"}
            or node.id in found.declared
        ):
            continue
        if _name(node) in tracked:
            reason = _use(node, resolver.lookup(node), index)
            if reason is not None:
                found.gaps.append((node, reason))


# Keys a serializer reads in place of the entries: JSON.stringify calls toJSON, which
# a prototype set by __proto__ can also provide.
_SERIALIZED_KEYS = frozenset({"toJSON", "__proto__"})


def _literal_key(node: Node | None) -> str | None:
    """A property key as JavaScript reads it, or None when it is computed."""
    if node is None:
        return None
    if node.type in {"property_identifier", "shorthand_property_identifier"}:
        return _name(node)
    if node.type == "computed_property_name":
        inner = _parts(node)
        return _string_value(_operand(inner[0], _REFERENCE_WRAPPERS)) if inner else None
    return _string_value(node) if node.type in {"string", "template_string"} else _value(node)


def _declared_name(constructor: Node, known: KnownValues | None) -> str | None:
    """The literal ``name`` of a constructor's first argument, an object literal, else None.

    A later ``name`` entry replaces an earlier one, and a spread after it can, so
    only a literal that nothing after it can replace counts. A client that
    serializes the object calls its ``toJSON``, which a computed key that is not a
    string literal or ``__proto__`` can supply and which a method, getter or setter
    can stand for, so any such entry, wherever it is, leaves the name computed. A
    computed key that is a string literal, ``['name']``, is that key.
    """
    arguments = constructor.child_by_field_name("arguments")
    listed = arguments is not None and arguments.type == "arguments"
    values = _parts(arguments) if arguments is not None and listed else []
    options = _operand(values[0], _REFERENCE_WRAPPERS) if values else None
    if options is None or options.type != "object":
        return None
    literal: Node | None = None
    for entry in _parts(options):
        if entry.type == "pair":
            key = _literal_key(entry.child_by_field_name("key"))
            if key is None or key in _SERIALIZED_KEYS:
                return None
            if key == "name":
                literal = entry.child_by_field_name("value")
        elif entry.type == "shorthand_property_identifier":
            key = _literal_key(entry)
            if key in _SERIALIZED_KEYS:
                return None
            if key == "name":
                literal = None
        elif entry.type == "spread_element":
            literal = None
        else:
            return None
    # Only the entry that wins is read, so repeated entries cost no more than one.
    return declared_server_name(_string_value(_operand(literal, _REFERENCE_WRAPPERS)), known)


def _sdk_constructor(callee: Node | None, resolver: _Resolver) -> bool:
    """Whether a ``new`` expression's callee is the collected ``McpServer`` class."""
    if callee is not None and callee.type in {"member_expression", "subscript_expression"}:
        binding = resolver.lookup(callee.child_by_field_name("object"))
        return (
            isinstance(binding, _Namespace) and binding.exact and _property(callee) == "McpServer"
        )
    return resolver.lookup(callee) == "sdk"


def collect_typescript_source(
    path: Path, content: bytes, result: ScanResult, known: KnownValues | None = None
) -> None:
    """Collect one candidate server file; every refusal is a scan failure naming why.

    A declared server name holding one of the ``known`` values is not recorded.
    """
    location = path.as_posix()
    try:
        _collect_source(content, path, result, known)
    except ImportError:
        result.scan_failures.append(
            f"{location}: TypeScript MCP parser dependency unavailable or incompatible"
        )
    except _RefusedError as exc:
        result.scan_failures.append(f"{location}: {exc}")
    except UnicodeError:
        result.scan_failures.append(f"{location}: invalid UTF-8")
    except ValueError:
        result.scan_failures.append(f"{location}: TypeScript source analysis refused")


def _parser(seconds: float, jsx: bool) -> Parser:
    from tree_sitter import Language, Parser
    from tree_sitter_typescript import language_tsx, language_typescript

    # The pinned 0.25 binding's callback parse path crashes for this grammar.
    # Its supported native timeout stops a parse without invoking callbacks.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            return Parser(
                Language(language_tsx() if jsx else language_typescript()),
                timeout_micros=max(1, int(seconds * 1_000_000)),
            )
    except (TypeError, ValueError, AttributeError) as exc:
        # A binding without timeout_micros, or a grammar ABI it rejects.
        raise ImportError("incompatible TypeScript parser binding") from exc


def _processor_time() -> float:
    """The parsing thread's processor time, or a refusal where the clock is unavailable.

    The bound on a parse is processor time so that a busy machine does not use it up.
    Without that clock the parse cannot be bounded safely, so the file is refused
    rather than parsed under the wall clock, which refused small files on a loaded machine.
    """
    if not hasattr(time, "thread_time"):  # pragma: no cover - present on Linux and macOS
        raise _RefusedError("TypeScript parsing cannot be bounded on this platform")
    return time.thread_time()


def _parse(source: bytes, jsx: bool, seconds: float) -> Tree:
    """Parse within ``seconds`` of the parsing thread's processor time.

    The binding stops a parse only after an interval of wall-clock time, which passes
    whether or not the parser runs, so the interval only returns control for the
    processor time to be read. The interval equals the budget, the wall-clock deadline
    used before, so one attempt reaches the point a runaway parse was stopped at. A
    parse the interval stops when the parser has had less than ``_HELD_UP_SHARE`` of its
    budget starts again from the beginning, up to ``_PARSE_ATTEMPTS`` times, because a
    resumed parse can build a different tree. A stopped parse that had that share, and
    one that reaches its processor time, finished or not, is refused. Load alone does
    not use the budget up, though a parse that never gets its processor time within the
    attempts is refused, and a slower machine reaches the budget on a smaller file. The
    one-time load of the native parser does not count, because the clock is read after it.
    """
    interval = _PARSE_INTERVAL * seconds
    for _ in range(_PARSE_ATTEMPTS):
        parser = _parser(interval, jsx)
        started = _processor_time()
        try:
            tree: Tree | None = parser.parse(source)
        except ValueError:
            # How the binding reports that the interval ended first.
            tree = None
        spent = _processor_time() - started
        # Free the parser's native arena before the next attempt builds another, so a
        # retried parse holds no more memory at once than a single parse does.
        del parser
        if tree is not None and spent < seconds:
            return tree
        if spent >= seconds * _HELD_UP_SHARE:
            break
    raise _RefusedError("TypeScript parsing exceeded its time limit")


def _collect_source(
    content: bytes, path: Path, result: ScanResult, known: KnownValues | None
) -> None:
    text = source_text(content)
    # The parser reads UTF-8; the file digest stays that of the bytes as stored.
    source = content if content[:2] not in UTF16_BYTE_ORDER_MARKS else text.encode("utf-8")
    scale = max(1.0, limits.current().syntax_bytes / limits.DEFAULTS.syntax_bytes)
    tree = _parse(source, _JSX.get(path.suffix, False), MAX_PARSE_SECONDS * scale)
    root = tree.root_node
    location = path.as_posix()
    javascript = path.suffix in _JAVASCRIPT
    if root.has_error:
        if javascript:
            result.surfaces_excluded.append(f"{location}: {_UNPARSED_JAVASCRIPT}")
            return
        raise _RefusedError("invalid TypeScript syntax")
    index = _index(root, limits.bound("ts-nodes"))
    if javascript:
        # JavaScript reads `a < b > (c)` as two comparisons, TypeScript as a call.
        reading = next((node for node in index.nodes if node.type == "type_arguments"), None)
        if reading is not None:
            result.surfaces_excluded.append(
                f"{location}:{reading.start_point.row + 1} ({_TYPE_READING})"
            )
            return
    found = _bindings(index, root)
    bindings = found.bindings
    resolver = _Resolver(root, bindings)
    _sdk_uses(index, root, found, resolver)
    found.gaps.sort(key=lambda gap: (gap[0].start_byte, gap[1]))
    result.surfaces_excluded.extend(
        dict.fromkeys(f"{location}:{node.start_point.row + 1} ({why})" for node, why in found.gaps)
    )
    if not any(
        value == "sdk" or (isinstance(value, _Namespace) and value.exact)
        for value in bindings.values()
    ):
        return
    file_digest = hash_bytes(content)
    servers: dict[int, tuple[MCPServerComponent, int]] = {}
    # An ambient declaration, such as `declare namespace`, is erased and never runs.
    for node in index.nodes:
        if node.type != "new_expression" or node.id in index.erased:
            continue
        if not _sdk_constructor(node.child_by_field_name("constructor"), resolver):
            continue
        variable = index.parent(node)
        declaration = index.parent(variable)
        identifier = variable.child_by_field_name("name") if variable is not None else None
        receiver = _name(identifier) if identifier is not None else ""
        direct_scope = index.parent(declaration)
        scope = index.scope(direct_scope)
        if direct_scope is not None and direct_scope.type == "export_statement":
            direct_scope = index.parent(direct_scope)
        if (
            variable is None
            or variable.type != "variable_declarator"
            or declaration is None
            or declaration.type != "lexical_declaration"
            or not declaration.children
            or declaration.children[0].type != "const"
            or direct_scope is None
            or direct_scope.type not in {"program", "statement_block"}
            or scope is None
            or identifier is None
            or identifier.type != "identifier"
            or not re.fullmatch(r"[A-Za-z_$][A-Za-z0-9_$]{0,127}", receiver)
            or bindings.get((scope.id, receiver)) != variable.id
        ):
            result.surfaces_excluded.append(
                f"{location}:{node.start_point.row + 1} (unsupported MCP constructor binding or scope)"
            )
            continue
        line = declaration.start_point.row + 1
        literal = _declared_name(node, known)
        identity = receiver if literal is None else quote(literal, safe="")
        ref = f"mcp-source:{quote(location, safe='')}:{identity}:{line}:{node.start_byte}"
        server = MCPServerComponent(
            bom_ref=ref,
            name=receiver if literal is None else literal,
            source_path=location,
            properties={
                "binding": receiver,
                "declaration_line": line,
                "method": "typescript-ast",
                "collection_mode": "static-source-declaration",
                "runtime_registration": "unknown",
            },
        )
        resolver.bind(scope, receiver, (server, node.end_byte))
        servers[node.id] = (server, node.end_byte)
    components: list[MCPServerComponent | ToolComponent] = [s for s, _ in servers.values()]
    scalar_literals = frozenset(
        {"number", "string", "template_string", "true", "false", "null", "undefined", "regex"}
    )
    reassigned_declarators: set[int] = set()
    for node in index.nodes:
        if node.id in index.erased:
            continue
        lhs: Node | None = None
        if node.type in {"assignment_expression", "augmented_assignment_expression"} or (
            node.type == "for_in_statement" and node.child_by_field_name("kind") is None
        ):
            lhs = node.child_by_field_name("left")
        if lhs is None:
            continue
        pending_lhs: list[Node] = [lhs]
        while pending_lhs:
            part = _operand(pending_lhs.pop())
            if part is None:
                continue
            if part.type in {"identifier", "shorthand_property_identifier"}:
                resolved = resolver.lookup(part)
                if isinstance(resolved, int):
                    reassigned_declarators.add(resolved)
            elif part.type in {
                "array_pattern",
                "object_pattern",
                "rest_pattern",
                "object_assignment_pattern",
                "assignment_pattern",
                "pair_pattern",
            }:
                if part.type in {"assignment_pattern", "object_assignment_pattern"}:
                    target_part = part.child_by_field_name("left")
                    if target_part is not None:
                        pending_lhs.append(target_part)
                elif part.type == "pair_pattern":
                    val_part = part.child_by_field_name("value")
                    if val_part is not None:
                        pending_lhs.append(val_part)
                else:
                    pending_lhs.extend(part.named_children)
    aliases = {
        node.id
        for node in index.nodes
        if node.type == "variable_declarator"
        and (
            node.id in reassigned_declarators
            or (rhs := _operand(node.child_by_field_name("value"))) is None
            or rhs.type not in scalar_literals
        )
    }
    assigned_builtins = _assigned_computed_builtins(index) if servers else set()
    registrations = 0
    for node in index.nodes:
        if node.type != "call_expression" or node.id in index.erased:
            continue
        member = node.child_by_field_name("function")
        if member is None or member.type not in {"member_expression", "subscript_expression"}:
            continue
        method = _called_method(member)
        if method is not None and method not in {"registerTool", "tool"}:
            continue
        receiver_node = member.child_by_field_name("object")
        if method is None:
            # A computed method may register a tool. A parameter or alias in a server
            # file can carry a server whose exact binding remains unproved.
            operand = _operand(receiver_node)
            computed = resolver.lookup(operand)
            computed_receiver = _identifier(operand)
            builtin = computed_receiver in _COMPUTED_BUILTINS
            unassigned_global = (
                builtin and computed is None and computed_receiver not in assigned_builtins
            )
            if isinstance(computed, tuple):
                result.surfaces_excluded.append(
                    f"{location}:{node.start_point.row + 1} (unresolved MCP method name)"
                )
            elif (
                servers
                and not unassigned_global
                and (
                    builtin
                    or computed in (None, "parameter", "ambiguous")
                    or (isinstance(computed, int) and computed in aliases)
                )
            ):
                result.surfaces_excluded.append(
                    f"{location}:{node.start_point.row + 1} (unresolved MCP registration receiver)"
                )
            continue
        binding = resolver.lookup(receiver_node)
        if not isinstance(binding, tuple):
            result.surfaces_excluded.append(
                f"{location}:{node.start_point.row + 1} (unresolved MCP registration receiver)"
            )
            continue
        registrations += 1
        if registrations > MAX_REGISTRATIONS:
            raise _RefusedError(f"more than {MAX_REGISTRATIONS} MCP tool registrations")
        server, declared_at = binding
        statement = index.parent(node)
        statement_scope = index.parent(statement)
        if (
            statement is None
            or statement.type != "expression_statement"
            or statement_scope is None
            or statement_scope.type not in {"program", "statement_block"}
            or node.start_byte < declared_at
        ):
            result.surfaces_excluded.append(
                f"{location}:{node.start_point.row + 1} (unsupported MCP registration scope or ordering)"
            )
            continue
        arguments = node.child_by_field_name("arguments")
        values = _parts(arguments) if arguments is not None else []
        arg = values[0] if values else None
        name = _value(arg)[1:-1] if arg is not None and arg.type == "string" else ""
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", name):
            result.surfaces_excluded.append(
                f"{location}:{node.start_point.row + 1} (unresolved MCP tool name)"
            )
            continue
        ref = f"tool:{server.bom_ref}/{name}"
        if ref in server.tool_refs:
            result.scan_failures.append(
                f"{location}:{node.start_point.row + 1} (duplicate MCP tool registration)"
            )
            continue
        from nexus_symbiote.scanners.prompt import detect_invisible_characters

        raw_source = (node.text or b"").decode("utf-8", "replace")
        decoded_source = _decode_js_unicode_escapes(raw_source) if "\\" in raw_source else None
        tool_risks = detect_invisible_characters(
            raw_source,
            f"{location}:{node.start_point.row + 1} ({name})",
            decoded=decoded_source,
        )
        tool = ToolComponent(
            bom_ref=ref,
            name=name,
            mcp_server_ref=server.bom_ref,
            source_path=location,
            risks=tool_risks,
            properties={
                "declaration_line": node.start_point.row + 1,
                "method": "typescript-ast",
                "collection_mode": "static-source-declaration",
                "registration_source_sha256": hash_bytes(node.text or b""),
                "source_sha256": file_digest,
            },
            claims={
                "tool_definition": ClaimEvidence(
                    method="not-collected",
                    scope="source-declaration",
                    unknown_reason="Only the literal registration name was collected; the effective descriptor is unobserved",
                )
            },
        )
        server.tool_refs.append(ref)
        server.tool_count += 1
        components.append(tool)
    result.components.extend(components)


_JS_UNICODE_ESCAPE_RE = re.compile(
    r"\\(?:u\{([0-9a-fA-F]{1,6})\}|u([0-9a-fA-F]{4})|x([0-9a-fA-F]{2}))"
)


def _decode_js_unicode_escapes(source: str) -> str:
    """Decode JS/TS hex and Unicode escapes (joining surrogate pairs) for hidden-char checks."""

    def _replace(match: re.Match[str]) -> str:
        digits = match.group(1) or match.group(2) or match.group(3)
        code = int(digits, 16)
        return chr(code) if code <= sys.maxunicode else match.group(0)

    decoded = _JS_UNICODE_ESCAPE_RE.sub(_replace, source)
    if any("\ud800" <= ch <= "\udfff" for ch in decoded):
        decoded = decoded.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")
    return decoded
