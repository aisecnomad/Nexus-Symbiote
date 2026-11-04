from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import AgentComponent, CapabilityDeclaration


def test_native_schema_matches_runtime_and_preserves_unknowns():
    schema = json.loads(
        (Path(__file__).parents[1] / "schemas/nexus-symbiote-aibom-1.0.schema.json").read_text()
    )
    assert schema == AIBOM.model_json_schema()
    bom = AIBOM(components=[AgentComponent(bom_ref="agent:one", name="one", autonomy_level=None)])
    document = bom.to_dict()
    assert not list(Draft202012Validator(schema).iter_errors(document))
    assert AIBOM.model_validate(document).components[0].autonomy_level is None
    document["components"][0]["unrecognized_authority"] = {"admin": True}
    assert list(Draft202012Validator(schema).iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)


def test_published_examples_match_schema_and_runtime():
    schemas = Path(__file__).parents[1] / "schemas"
    validator = Draft202012Validator(
        json.loads((schemas / "nexus-symbiote-aibom-1.0.schema.json").read_text())
    )
    examples = sorted((schemas / "examples").glob("*.json"))
    assert examples
    for example in examples:
        document = json.loads(example.read_text())
        assert not list(validator.iter_errors(document)), example.name
        AIBOM.model_validate(document)


def test_nested_capability_unknown_semantics_rejected():
    with pytest.raises(ValidationError):
        CapabilityDeclaration.model_validate({"unrecognized_approval_bypass": True})


def test_dependency_edge_unknown_semantics_rejected_by_schema_model_and_cli(tmp_path):
    document = AIBOM(components=[AgentComponent(bom_ref="agent:one", name="one")]).to_dict()
    document["dependencies"] = [
        {
            "source_ref": "agent:one",
            "target_ref": "agent:one",
            "relationship": "invokes",
            "required_approval": "human",
        }
    ]
    schema = AIBOM.model_json_schema()
    assert list(Draft202012Validator(schema).iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.model_validate(document)
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    result = CliRunner().invoke(main, ["validate", str(path), "--no-project-policy"])
    assert result.exit_code == 1
    assert "not a valid native AIBOM" in result.output


def test_loader_rejects_duplicate_keys_and_limits(tmp_path):
    path = tmp_path / "bom.json"
    path.write_text('{"components":[],"components":[]}')
    with pytest.raises(ValueError):
        AIBOM.load(path)


def test_signature_policy_cli_requires_explicit_project(tmp_path):
    policy = tmp_path / "policy.json"
    policy.write_text('{"version":1,"artifacts":[]}')
    path = tmp_path / "bom.json"
    AIBOM().save(path)
    result = CliRunner().invoke(main, ["validate", str(path), "--signature-policy", str(policy)])
    assert result.exit_code != 0 and "requires --project" in result.output
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--signature-policy", str(policy)])
    assert result.exit_code != 0
