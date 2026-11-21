"""A native inventory nests at most ``MAX_NATIVE_NESTING`` levels, whatever the stack.

The strict parser used to bound nesting only by the interpreter's recursion limit, so a
document that loaded still made pydantic's ``model_dump`` fail in ``diff`` and
``validate --project`` with an internal error, while ``risk`` and ``summary`` read it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, MAX_NATIVE_NESTING, NativeFormatError
from nexus_symbiote.core.models import ModelComponent
from nexus_symbiote.runtime import MAX_BOM_DEPTH

REFUSED = f"inventory nests deeper than {MAX_NATIVE_NESTING} levels"
NOT_VALID = "is not a valid native AIBOM file."


def nested_document(levels: int) -> dict[str, Any]:
    """A valid inventory whose deepest value sits ``levels`` containers below the root."""
    nested: Any = "leaf"
    for _ in range(levels - 3):
        nested = {"n": nested}
    return {
        "metadata": {"spec_version": "1.1.0", "tool_name": "nexus-symbiote"},
        "components": [
            {
                "bom_ref": "tool:search",
                "component_type": "tool",
                "name": "search",
                "properties": nested,
            }
        ],
        "dependencies": [],
    }


def depth(value: Any) -> int:
    pending: list[tuple[Any, int]] = [(value, 1)]
    deepest = 0
    while pending:
        item, level = pending.pop()
        if isinstance(item, dict | list):
            deepest = max(deepest, level)
            children = item.values() if isinstance(item, dict) else item
            pending.extend((child, level + 1) for child in children)
    return deepest


def written(tmp_path: Path, levels: int) -> Path:
    document = nested_document(levels)
    assert depth(document) == levels
    path = tmp_path / f"nested-{levels}.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def at_stack_depth(frames: int, call):
    return call() if frames == 0 else at_stack_depth(frames - 1, call)


def test_the_bound_is_a_constant_above_the_snapshot_budget_and_below_the_stack():
    assert isinstance(MAX_NATIVE_NESTING, int)
    assert MAX_BOM_DEPTH <= MAX_NATIVE_NESTING < sys.getrecursionlimit()


def test_a_document_at_the_bound_loads_and_one_deeper_is_refused(tmp_path):
    bom = AIBOM.load(written(tmp_path, MAX_NATIVE_NESTING))
    assert bom.components[0].name == "search"
    with pytest.raises(NativeFormatError) as refused:
        AIBOM.load(written(tmp_path, MAX_NATIVE_NESTING + 1))
    assert str(refused.value) == REFUSED


def test_the_accepted_depth_does_not_depend_on_the_stack_or_the_recursion_limit(tmp_path):
    accepted = written(tmp_path, MAX_NATIVE_NESTING)
    refused = written(tmp_path, MAX_NATIVE_NESTING + 1)
    assert at_stack_depth(400, lambda: AIBOM.load(accepted)).components
    with pytest.raises(NativeFormatError, match=REFUSED):
        at_stack_depth(400, lambda: AIBOM.load(refused))
    previous = sys.getrecursionlimit()
    sys.setrecursionlimit(previous * 4)
    try:
        with pytest.raises(NativeFormatError, match=REFUSED):
            AIBOM.load(refused)
    finally:
        sys.setrecursionlimit(previous)


COMMANDS = {
    "diff": lambda path: ["diff", path, path],
    "validate": lambda path: ["validate", path],
    "risk": lambda path: ["risk", path],
    "graph": lambda path: ["graph", path, "--format", "json"],
    "summary": lambda path: ["summary", path],
}


@pytest.mark.parametrize("command", sorted(COMMANDS))
@pytest.mark.parametrize("levels", [MAX_NATIVE_NESTING + 1, 300])
def test_every_reader_refuses_a_too_deep_inventory_with_the_fixed_text(tmp_path, command, levels):
    path = str(written(tmp_path, levels))
    result = CliRunner().invoke(main, COMMANDS[command](path))
    assert result.exit_code == 1, result.output
    assert "internal error" not in result.output
    assert f"{path} {NOT_VALID} {REFUSED}" in result.output


@pytest.mark.parametrize("command", sorted(COMMANDS))
def test_every_reader_reads_an_inventory_at_the_bound(tmp_path, command):
    path = str(written(tmp_path, MAX_NATIVE_NESTING))
    result = CliRunner().invoke(main, COMMANDS[command](path))
    assert "internal error" not in result.output
    assert NOT_VALID not in result.output


def _deep_inventory(levels: int) -> AIBOM:
    nested: object = "leaf"
    for _ in range(levels):
        nested = {"k": nested}
    return AIBOM(
        components=[ModelComponent(bom_ref="model:m", name="m", properties={"deep": nested})]
    )


def test_the_writer_refuses_what_the_reader_refuses(tmp_path):
    # The component's properties sit four levels below the root, so a property
    # nested MAX_NATIVE_NESTING - 4 deep is the deepest document either side accepts.
    accepted = tmp_path / "accepted.json"
    _deep_inventory(MAX_NATIVE_NESTING - 4).save(accepted)
    assert AIBOM.load(accepted).components[0].properties["deep"]

    refused = tmp_path / "refused.json"
    with pytest.raises(NativeFormatError, match=f"nests deeper than {MAX_NATIVE_NESTING} levels"):
        _deep_inventory(MAX_NATIVE_NESTING - 3).save(refused)
    assert not refused.exists()


def test_an_export_embedding_a_too_deep_inventory_is_refused_as_a_native_file_is():
    from nexus_symbiote.core.canonical import content_digest
    from nexus_symbiote.generators._common import recover_native
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
    from nexus_symbiote.generators.recovery import recover_export

    def embedded(levels: int) -> list[dict[str, str]]:
        document = nested_document(levels)
        return [
            {"name": "nexus-symbiote:document", "value": json.dumps(document)},
            {"name": "nexus-symbiote:documentDigest", "value": content_digest(document)},
            {"name": "nexus-symbiote:lossReport", "value": "[]"},
        ]

    assert recover_native(embedded(MAX_NATIVE_NESTING))[0].components[0].name == "search"
    with pytest.raises(ValueError, match="embedded native document is nested too deeply"):
        recover_native(embedded(MAX_NATIVE_NESTING + 1))
    deep = AIBOM.from_document(nested_document(MAX_NATIVE_NESTING + 1))
    text = CycloneDXGenerator(projection_version=3).generate_json(deep)
    with pytest.raises(ValueError, match="embedded native document is nested too deeply"):
        recover_export(text)
