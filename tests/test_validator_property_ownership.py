"""Every literal component property used by a validator needs an explicit trust decision."""

from __future__ import annotations

import ast
from pathlib import Path
from types import ModuleType

import pytest

from nexus_symbiote.validators import completeness, integrity, risk


def _string_values(
    node: ast.AST, module: ModuleType, loop_bindings: dict[str, set[str]]
) -> set[str]:
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return {node.value}
    if isinstance(node, ast.Name):
        if node.id in loop_bindings:
            return set(loop_bindings[node.id])
        value = getattr(module, node.id, None)
        if isinstance(value, str):
            return {value}
        if isinstance(value, (tuple, list, set, frozenset)) and all(
            isinstance(item, str) for item in value
        ):
            return set(value)
    return set()


def _iterable_strings(
    node: ast.AST, module: ModuleType, loop_bindings: dict[str, set[str]]
) -> list[tuple[str, ...]]:
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        rows: list[tuple[str, ...]] = []
        for elt in node.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                rows.append((elt.value,))
            elif isinstance(elt, (ast.Tuple, ast.List)) and all(
                isinstance(part, ast.Constant) and isinstance(part.value, str) for part in elt.elts
            ):
                rows.append(
                    tuple(part.value for part in elt.elts if isinstance(part, ast.Constant))
                )
        return rows
    if isinstance(node, ast.Name):
        values = _string_values(node, module, loop_bindings)
        return [(val,) for val in values]
    return []


@pytest.mark.parametrize("module", [completeness, integrity, risk], ids=lambda mod: mod.__name__)
def test_validator_property_reads_have_an_explicit_source(module: ModuleType) -> None:
    assert module.__file__ is not None
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    keys: set[str] = set()

    def walk(node: ast.AST, loop_bindings: dict[str, set[str]]) -> None:
        if isinstance(node, ast.For):
            rows = _iterable_strings(node.iter, module, loop_bindings)
            next_bindings = dict(loop_bindings)
            if rows:
                if isinstance(node.target, ast.Name) and all(len(r) == 1 for r in rows):
                    next_bindings[node.target.id] = {r[0] for r in rows}
                elif isinstance(node.target, (ast.Tuple, ast.List)) and all(
                    isinstance(t, ast.Name) for t in node.target.elts
                ):
                    width = len(node.target.elts)
                    if all(len(r) == width for r in rows):
                        for idx, target in enumerate(node.target.elts):
                            assert isinstance(target, ast.Name)
                            next_bindings[target.id] = {r[idx] for r in rows}
            for child in ast.iter_child_nodes(node):
                walk(child, next_bindings)
            return
        if isinstance(node, ast.comprehension):
            rows = _iterable_strings(node.iter, module, loop_bindings)
            if rows and isinstance(node.target, ast.Name) and all(len(r) == 1 for r in rows):
                loop_bindings[node.target.id] = {r[0] for r in rows}
            return
        if isinstance(node, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)):
            next_bindings = dict(loop_bindings)
            for gen in node.generators:
                walk(gen, next_bindings)
            for child in ast.iter_child_nodes(node):
                if not isinstance(child, ast.comprehension):
                    walk(child, next_bindings)
            return
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr == "get" and node.args:
                mapping, key = node.func.value, node.args[0]
                if isinstance(mapping, ast.Attribute) and mapping.attr == "properties":
                    keys.update(_string_values(key, module, loop_bindings))
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            mapping, key = node.value, node.slice
            if isinstance(mapping, ast.Attribute) and mapping.attr == "properties":
                keys.update(_string_values(key, module, loop_bindings))
        for child in ast.iter_child_nodes(node):
            walk(child, loop_bindings)

    walk(tree, {})

    # Only integrity reads these supplier extensions, as inputs to the MCP descriptor digest.
    descriptor_fields = {
        "title",
        "mcp_title",
        "output_schema",
        "mcp_output_schema",
        "meta",
        "mcp_meta",
    }
    permitted = descriptor_fields if module is integrity else set()
    assert not {key for key in keys - permitted if not completeness._collector_owned(key)}
