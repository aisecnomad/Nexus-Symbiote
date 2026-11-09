"""Bounded static MCP names from lexically bound TypeScript SDK registrations.

This records source declarations, never evaluated tool descriptors or runtime
registration. Dynamic names and unsupported bindings remain
explicit collection gaps. No source module or package code is executed.
"""

from __future__ import annotations

import re
import time
import warnings
from collections.abc import Iterator, Sequence
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import quote

if TYPE_CHECKING:
    from tree_sitter import Node

from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.utils.confined import ConfinedCollection

_MODULES = {"@modelcontextprotocol/server", "@modelcontextprotocol/sdk/server/mcp.js"}
_IGNORED = {"dist", "build", "__tests__", "tests", "test"}
MAX_SOURCE_FILES = 50
MAX_SOURCE_BYTES = 262_144
MAX_AST_NODES = 20_000
MAX_AST_DEPTH = 128
MAX_REGISTRATIONS = 1_000
MAX_PARSE_SECONDS = 0.25
MAX_ANALYSIS_SECONDS = 2.0


def _value(node: Node | None) -> str:
    return ((node.text or b"") if node is not None else b"").decode("utf-8")


def _nodes(root: Node) -> Iterator[Node]:
    pending = [(root, 0)]
    count = 0
    while pending:
        node, depth = pending.pop()
        count += 1
        if count > MAX_AST_NODES:
            raise ValueError("TypeScript AST node limit exceeded")
        if depth > MAX_AST_DEPTH:
            raise ValueError("TypeScript AST depth limit exceeded")
        yield node
        pending.extend((child, depth + 1) for child in reversed(node.named_children))


_FUNCTIONS = {
    "function_declaration",
    "function_expression",
    "arrow_function",
    "method_definition",
    "generator_function_declaration",
    "generator_function",
}
_SCOPES = {"program", "statement_block", "catch_clause", *_FUNCTIONS}


def _scope(node: Node | None) -> Node | None:
    while node is not None and node.type not in _SCOPES:
        node = node.parent
    return node


def _pattern_names(node: Node | None) -> list[str]:
    if node is None:
        return []
    return [
        _value(n)
        for n in _nodes(node)
        if n.type in {"identifier", "shorthand_property_identifier_pattern"}
    ]


def _bindings(nodes: Sequence[Node], root: Node, deadline: float) -> dict[tuple[int, str], object]:
    bindings: dict[tuple[int, str], object] = {}

    def bind(scope: Node | None, name: str, value: object) -> None:
        if scope is not None and name:
            key = (scope.id, name)
            bindings[key] = "ambiguous" if key in bindings else value

    for node in nodes:
        if time.monotonic() >= deadline:
            raise ValueError("TypeScript AST analysis deadline exceeded")
        if node.type == "import_statement" and node.parent == root:
            sdk = _value(node.child_by_field_name("source"))[1:-1] in _MODULES and not any(
                child.type == "type" for child in node.children
            )
            for spec in _nodes(node):
                if spec.type == "import_specifier":
                    name = spec.child_by_field_name("name")
                    bind(
                        root,
                        _value(spec.child_by_field_name("alias") or name),
                        "sdk"
                        if sdk
                        and _value(name) == "McpServer"
                        and not any(child.type == "type" for child in spec.children)
                        else "other",
                    )
                elif spec.type in {"namespace_import", "import_clause"}:
                    for child in spec.named_children:
                        if child.type == "identifier":
                            bind(root, _value(child), "other")
        elif node.type == "variable_declarator":
            for declared_name in _pattern_names(node.child_by_field_name("name")):
                bind(_scope(node.parent), declared_name, node.id)
        elif node.type in _FUNCTIONS:
            name = node.child_by_field_name("name")
            if name is not None:
                bind(
                    _scope(node.parent) if "declaration" in node.type else node,
                    _value(name),
                    "other",
                )
            parameters = node.child_by_field_name("parameters") or node.child_by_field_name(
                "parameter"
            )
            for parameter in _pattern_names(parameters):
                bind(node, parameter, "other")
        elif node.type in {"class_declaration", "enum_declaration"}:
            bind(_scope(node.parent), _value(node.child_by_field_name("name")), "other")
        elif node.type == "catch_clause":
            for caught_name in _pattern_names(node.child_by_field_name("parameter")):
                bind(node, caught_name, "other")
    return bindings


def _lookup(bindings: dict[tuple[int, str], object], name: str, node: Node) -> object:
    scope = _scope(node.parent)
    while scope is not None:
        key = (scope.id, name)
        if key in bindings:
            return bindings[key]
        scope = _scope(scope.parent)
    return None


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


def collect_typescript(
    files: ConfinedCollection, result: ScanResult, sources: Sequence[Path]
) -> None:
    """Use the scanner's existing pinned root, exclusions and shared I/O budgets."""
    for path in sources:
        unsupported = path.suffix in {".js", ".mjs", ".cjs", ".mts", ".cts"} or (
            path.suffix == ".ts"
            and (
                bool(_IGNORED.intersection(path.parts))
                or path.name.endswith((".d.ts", ".spec.ts", ".test.ts"))
            )
        )
        if not unsupported:
            continue
        content = files.read_bytes(path)
        if content is not None and b"@modelcontextprotocol/" in content and b"McpServer" in content:
            result.surfaces_excluded.append(
                f"{path}: unsupported MCP server source form or location"
            )
    paths = [
        path
        for path in sources
        if path.suffix == ".ts"
        and not _IGNORED.intersection(path.parts)
        and not path.name.endswith((".d.ts", ".spec.ts", ".test.ts"))
    ]
    if len(paths) > MAX_SOURCE_FILES:
        result.scan_failures.append("TypeScript MCP source file collection limit exceeded")
    for path in paths[:MAX_SOURCE_FILES]:
        content = files.read_bytes(path)
        if content is None:
            continue
        if len(content) > MAX_SOURCE_BYTES:
            result.scan_failures.append(f"{path}: TypeScript syntax collection size limit exceeded")
            continue
        if b"@modelcontextprotocol/" not in content or b"McpServer" not in content:
            continue
        result.surfaces_scanned.append(path.as_posix())
        try:
            _collect_source(content, path, result)
        except ImportError:
            result.scan_failures.append(f"{path}: TypeScript MCP parser dependency unavailable")
        except (ValueError, UnicodeError):
            result.scan_failures.append(f"{path}: TypeScript source parsing or AST limit refused")


def _collect_source(content: bytes, path: Path, result: ScanResult) -> None:
    from tree_sitter import Language, Parser
    from tree_sitter_typescript import language_typescript

    content.decode("utf-8")
    deadline = time.monotonic() + MAX_PARSE_SECONDS
    # The pinned 0.25 binding's callback parse path crashes for this grammar.
    # Its supported native timeout bounds parsing without invoking callbacks.
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        parser = Parser(
            Language(language_typescript()),
            timeout_micros=max(1, int(MAX_PARSE_SECONDS * 1_000_000)),
        )
    tree = parser.parse(content)
    if tree is None or time.monotonic() >= deadline:
        raise ValueError("TypeScript parsing deadline exceeded")
    root = tree.root_node
    if root.has_error:
        raise ValueError("invalid TypeScript syntax")
    deadline = time.monotonic() + MAX_ANALYSIS_SECONDS
    nodes = list(_nodes(root))
    bindings = _bindings(nodes, root, deadline)
    if "sdk" not in bindings.values():
        # A server-like source that names the SDK but uses a namespace or
        # otherwise unsupported binding must not silently appear covered.
        if b"McpServer" in content:
            result.surfaces_excluded.append(f"{path}: unsupported TypeScript MCP server binding")
        return
    servers: dict[int, tuple[MCPServerComponent, int]] = {}
    for node in nodes:
        if time.monotonic() >= deadline:
            raise ValueError("TypeScript AST analysis deadline exceeded")
        if node.type != "new_expression":
            continue
        constructor_node = node.child_by_field_name("constructor")
        # Only a lexical SDK identifier can resolve to the supported import.
        # Serializing a nested constructor for every new-expression is quadratic.
        if constructor_node is None or constructor_node.type != "identifier":
            continue
        constructor = _value(constructor_node)
        if _lookup(bindings, constructor, node) != "sdk":
            continue
        variable = node.parent
        declaration = variable.parent if variable is not None else None
        identifier = variable.child_by_field_name("name") if variable is not None else None
        receiver = _value(identifier)
        scope = _scope(declaration.parent) if declaration is not None else None
        direct_scope = declaration.parent if declaration is not None else None
        if direct_scope is not None and direct_scope.type == "export_statement":
            direct_scope = direct_scope.parent
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
                f"{path}:{node.start_point.row + 1} (unsupported MCP constructor binding or scope)"
            )
            continue
        line = declaration.start_point.row + 1
        ref = f"mcp-source:{quote(path.as_posix(), safe='')}:{receiver}:{line}:{node.start_byte}"
        server = MCPServerComponent(
            bom_ref=ref,
            name=receiver,
            source_path=path.as_posix(),
            properties={
                "declaration_line": line,
                "method": "typescript-ast",
                "collection_mode": "static-source-declaration",
                "runtime_registration": "unknown",
            },
        )
        bindings[(scope.id, receiver)] = (server, node.end_byte)
        servers[node.id] = (server, node.end_byte)
    components: list[MCPServerComponent | ToolComponent] = [s for s, _ in servers.values()]
    registrations = 0
    for node in nodes:
        if time.monotonic() >= deadline:
            raise ValueError("TypeScript AST analysis deadline exceeded")
        if node.type != "call_expression":
            continue
        member = node.child_by_field_name("function")
        if member is None or member.type not in {"member_expression", "subscript_expression"}:
            continue
        method = _called_method(member)
        if method is not None and method not in {"registerTool", "tool"}:
            continue
        receiver = _value(member.child_by_field_name("object"))
        binding = _lookup(bindings, receiver, node)
        if method is None:
            if isinstance(binding, tuple):
                result.surfaces_excluded.append(
                    f"{path}:{node.start_point.row + 1} (unresolved MCP method name)"
                )
            continue
        if not isinstance(binding, tuple):
            result.surfaces_excluded.append(
                f"{path}:{node.start_point.row + 1} (unresolved MCP registration receiver)"
            )
            continue
        registrations += 1
        if registrations > MAX_REGISTRATIONS:
            raise ValueError("TypeScript registration limit exceeded")
        server, declared_at = binding
        statement = node.parent
        if (
            statement is None
            or statement.type != "expression_statement"
            or statement.parent is None
            or statement.parent.type not in {"program", "statement_block"}
            or node.start_byte < declared_at
        ):
            result.surfaces_excluded.append(
                f"{path}:{node.start_point.row + 1} (unsupported MCP registration scope or ordering)"
            )
            continue
        arguments = node.child_by_field_name("arguments")
        arg = arguments.named_children[0] if arguments and arguments.named_children else None
        name = _value(arg)[1:-1] if arg is not None and arg.type == "string" else ""
        if not re.fullmatch(r"[a-zA-Z0-9_.-]{1,128}", name):
            result.surfaces_excluded.append(
                f"{path}:{node.start_point.row + 1} (unresolved MCP tool name)"
            )
            continue
        ref = f"tool:{server.bom_ref}/{name}"
        if ref in server.tool_refs:
            result.scan_failures.append(
                f"{path}:{node.start_point.row + 1} (duplicate MCP tool registration)"
            )
            continue
        tool = ToolComponent(
            bom_ref=ref,
            name=name,
            mcp_server_ref=server.bom_ref,
            source_path=path.as_posix(),
            properties={
                "declaration_line": node.start_point.row + 1,
                "method": "typescript-ast",
                "collection_mode": "static-source-declaration",
                "registration_source_sha256": hash_bytes(node.text or b""),
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
