"""Regression tests for canonical fingerprints and CycloneDX projections."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.hashing import canonical_json
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from tests.test_generators import _sample_aibom


def test_jcs_numbers_and_unicode_order():
    assert canonical_json(1e-7) == "1e-7"
    assert canonical_json(1e20) == "100000000000000000000"
    assert canonical_json({"\ue000": 1, "\U00010000": 2}) == '{"\U00010000":2,"\ue000":1}'
    with pytest.raises(ValueError):
        canonical_json(float("nan"))


def test_cyclonedx_preserves_edge_semantics_without_invalid_fields():
    bom = _sample_aibom()
    exported = CycloneDXGenerator().generate(bom)
    assert all(set(edge) == {"ref", "dependsOn"} for edge in exported["dependencies"])
    relationship = json.loads(exported["metadata"]["properties"][0]["value"])
    assert relationship["type"] == "invokes"
    agent = next(c for c in exported["components"] if c["bom-ref"] == "agent:main")
    assert agent["type"] == "application"


def test_cyclonedx_strict_validator():
    # Optional dependency; CI should install a CycloneDX 1.7-capable version.
    pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    if not hasattr(SchemaVersion, "V1_7"):
        pytest.skip("installed cyclonedx library does not support 1.7")
    data = CycloneDXGenerator().generate_json(_sample_aibom())
    assert JsonStrictValidator(SchemaVersion.V1_7).validate_str(data) is None


def test_legacy_tool_fingerprint_requires_migration():
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.core.models import ToolComponent
    from nexus_symbiote.validators.integrity import IntegrityValidator

    bom = AIBOM()
    bom.add_component(
        ToolComponent(bom_ref="tool:legacy", name="legacy", definition_hash="sha256:old")
    )
    report = IntegrityValidator().validate(bom)
    assert not report.is_valid
    assert report.hashes_verified == 0
    assert any(i.category == "fingerprint_version_unknown" for i in report.issues)


def test_diff_does_not_compare_legacy_and_new_fingerprints():
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.core.models import ToolComponent
    from nexus_symbiote.diff.differ import AIBOMDiffer

    old = AIBOM()
    new = AIBOM()
    old.add_component(ToolComponent(bom_ref="tool:t", name="t", definition_hash="sha256:old"))
    new.add_component(
        ToolComponent(
            bom_ref="tool:t",
            name="t",
            definition_hash="sha256:new",
            definition_hash_version="rfc8785-jcs-v1",
        )
    )
    result = AIBOMDiffer().diff(old, new)
    assert result.has_changes
    assert any(
        "unknown or incompatible" in item for c in result.components_modified for item in c.details
    )


@pytest.mark.parametrize(
    "fmt,generator", [("cyclonedx", CycloneDXGenerator), ("spdx", SPDXGenerator)]
)
def test_verify_export_rejects_extension_loss_and_projection_tampering(tmp_path, fmt, generator):
    path = tmp_path / "export.json"
    original = generator().generate(_sample_aibom())
    runner = CliRunner()
    args = ["verify-export", "--format", fmt, str(path)]

    path.write_text(json.dumps(original))
    result = runner.invoke(main, args)
    assert result.exit_code == 0, result.output
    assert "not authenticated" in result.output

    altered = json.loads(json.dumps(original))
    if fmt == "cyclonedx":
        altered["metadata"]["properties"] = [
            p for p in altered["metadata"]["properties"] if p["name"] != "nexus-symbiote:document"
        ]
    else:
        document = next(n for n in altered["@graph"] if n["type"] == "SpdxDocument")
        properties = document["extension"][0]["extension_cdxProperty"]
        properties[:] = [
            p for p in properties if p["extension_cdxPropName"] != "nexus-symbiote:document"
        ]
    path.write_text(json.dumps(altered))
    assert runner.invoke(main, args).exit_code != 0

    altered = json.loads(json.dumps(original))
    if fmt == "cyclonedx":
        altered["components"][0]["name"] = "altered"
    else:
        node = next(n for n in altered["@graph"] if n["type"] == "software_Package")
        node["name"] = "altered"
    path.write_text(json.dumps(altered))
    assert runner.invoke(main, args).exit_code != 0


def test_verify_export_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "duplicate.json"
    path.write_text('{"bomFormat":"CycloneDX","bomFormat":"CycloneDX"}')
    assert (
        CliRunner().invoke(main, ["verify-export", "--format", "cyclonedx", str(path)]).exit_code
        != 0
    )
