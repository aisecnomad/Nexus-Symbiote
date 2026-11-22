"""Every literal component property used by a validator needs an explicit trust decision."""

from __future__ import annotations

import ast
from pathlib import Path
from types import ModuleType

import pytest

from nexus_symbiote.validators import completeness, integrity, risk


@pytest.mark.parametrize("module", [completeness, integrity, risk], ids=lambda mod: mod.__name__)
def test_validator_property_reads_have_an_explicit_source(module: ModuleType) -> None:
    assert module.__file__ is not None
    tree = ast.parse(Path(module.__file__).read_text(encoding="utf-8"))
    keys: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr != "get" or not node.args:
                continue
            mapping, key = node.func.value, node.args[0]
        elif isinstance(node, ast.Subscript) and isinstance(node.ctx, ast.Load):
            mapping, key = node.value, node.slice
        else:
            continue
        if (
            isinstance(mapping, ast.Attribute)
            and mapping.attr == "properties"
            and isinstance(key, ast.Constant)
            and isinstance(key.value, str)
        ):
            keys.add(key.value)

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
