"""Check the explicit ownership and drift assertions in the standalone benchmark."""

from pathlib import Path
from runpy import run_path

import pytest

REPLAY = run_path(
    str(Path(__file__).resolve().parents[1] / "benchmarks/agent-model-swap/replay.py")
)


def inventory():
    return {
        "components": [
            {
                "component_type": "agent",
                "bom_ref": "a",
                "name": "CopperReader",
                "model_refs": ["x"],
            },
            {"component_type": "agent", "bom_ref": "b", "name": "VioletCurator"},
            {
                "component_type": "agent",
                "bom_ref": "root",
                "name": "repository",
                "model_refs": ["x", "y"],
            },
            {"component_type": "model", "bom_ref": "x", "name": "openai:gpt-4o-mini"},
            {"component_type": "model", "bom_ref": "y", "name": "gpt-4.1-mini"},
        ],
        "dependencies": [
            {"source_ref": "a", "relationship": "uses-model", "target_ref": "x"},
            {"source_ref": "b", "relationship": "uses-model", "target_ref": "y"},
        ],
    }


def test_native_fields_and_typed_edges_agree_and_repository_models_earn_no_credit():
    document = inventory()
    bindings = REPLAY["bindings"]
    expected = {("CopperReader", "gpt-4o-mini"), ("VioletCurator", "gpt-4.1-mini")}
    assert bindings(document) == expected
    document["components"][0]["model_refs"] = []
    document["dependencies"] = []
    assert bindings(document) == set()


def test_a_persistent_extra_binding_fails_even_with_four_correct_changes():
    get_score = REPLAY["score"]
    before = REPLAY["bindings"](inventory())
    after = {("CopperReader", "gpt-4.1-mini"), ("VioletCurator", "gpt-4o-mini")}
    clean = get_score({"before": before, "after": after})
    assert clean["passed"] and clean["correct_changes"] == 4
    extra = {("CopperReader", "unrelated-model")}
    bad = get_score({"before": before | extra, "after": after | extra})
    assert not bad["passed"] and bad["correct_changes"] == 4
    assert bad["snapshots"]["before"]["extra"] == sorted(extra)


@pytest.mark.parametrize("invalid_target", ["missing", "b"])
def test_a_dangling_or_wrong_type_reference_cannot_earn_model_credit(invalid_target):
    document = inventory()
    document["components"][0]["model_refs"] = [invalid_target]
    with pytest.raises(ValueError, match="typed model target"):
        REPLAY["bindings"](document)
