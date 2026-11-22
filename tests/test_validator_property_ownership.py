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


def _bind_loop_target(
    target: ast.AST, rows: list[tuple[str, ...]], bindings: dict[str, set[str]]
) -> None:
    if not rows:
        return
    if isinstance(target, ast.Name) and all(len(r) == 1 for r in rows):
        bindings[target.id] = {r[0] for r in rows}
    elif isinstance(target, (ast.Tuple, ast.List)) and all(
        isinstance(t, ast.Name) for t in target.elts
    ):
        width = len(target.elts)
        if all(len(r) == width for r in rows):
            for idx, item in enumerate(target.elts):
                assert isinstance(item, ast.Name)
                bindings[item.id] = {r[idx] for r in rows}


def _collect_property_keys(tree: ast.AST, module: ModuleType) -> set[str]:
    keys: set[str] = set()

    def walk(node: ast.AST, loop_bindings: dict[str, set[str]]) -> None:
        if isinstance(node, ast.For):
            walk(node.iter, loop_bindings)
            rows = _iterable_strings(node.iter, module, loop_bindings)
            next_bindings = dict(loop_bindings)
            _bind_loop_target(node.target, rows, next_bindings)
            for stmt in node.body:
                walk(stmt, next_bindings)
            for stmt in node.orelse:
                walk(stmt, next_bindings)
            return
        if isinstance(node, ast.comprehension):
            walk(node.iter, loop_bindings)
            rows = _iterable_strings(node.iter, module, loop_bindings)
            _bind_loop_target(node.target, rows, loop_bindings)
            for cond in node.ifs:
                walk(cond, loop_bindings)
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
    return keys


@pytest.mark.parametrize("module", [completeness, integrity, risk], ids=lambda mod: mod.__name__)
def test_validator_property_reads_have_an_explicit_source(module: ModuleType) -> None:
    assert module.__file__ is not None
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    keys = _collect_property_keys(tree, module)

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


def test_property_walker_captures_comprehension_ifs_iters_and_tuple_targets() -> None:
    sample = ast.parse(
        """
a = [c for c in items if c.properties.get("forged_if_key")]
b = [x for c in items for x in c.properties.get("forged_iter_key", [])]
c = [c.properties.get("seen_elt_key") for c in items]
d = [c.properties.get(k) for k, _ in (("pair_key", "v"),) for c in items]
e = any(True for c in items if c.properties.get("forged_gen_if_key"))
"""
    )
    assert _collect_property_keys(sample, risk) == {
        "forged_if_key",
        "forged_iter_key",
        "seen_elt_key",
        "pair_key",
        "forged_gen_if_key",
    }
