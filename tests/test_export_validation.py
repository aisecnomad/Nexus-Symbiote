"""Export validation is deterministic and preserves schema checks and fast graph walks."""

from __future__ import annotations

import sys
from copy import deepcopy
from typing import Any

import jsonschema._keywords
import jsonschema._utils
import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment, ToolComponent
from nexus_symbiote.generators import validation
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.validation import (
    FORMAT_CHECKS,
    format_checker,
    spdx_errors,
    validate_cyclonedx,
)
from nexus_symbiote.generators.vex import VEXGenerator
from tests.support import scaling_ratio
from tests.test_export_conformance import fixture_bom

JSON = st.recursive(
    st.none()
    | st.booleans()
    | st.integers(-3, 3)
    | st.sampled_from([0.0, 1.0, -1.0, 2.5])
    | st.sampled_from(["", "a", "1", "true"]),
    lambda children: (
        st.lists(children, max_size=3)
        | st.dictionaries(st.sampled_from(["a", "b", "1"]), children, max_size=3)
    ),
    max_leaves=8,
)


@settings(max_examples=400, deadline=None)
@given(JSON, JSON)
def test_linear_uniqueness_agrees_with_jsonschema_equality(left, right):
    assert (validation._identity(left) == validation._identity(right)) == jsonschema._utils.equal(
        left, right
    )


def _refuse_pairwise(monkeypatch: pytest.MonkeyPatch) -> None:
    def refuse(container: Any) -> bool:
        raise AssertionError("pairwise uniqueItems comparison")

    monkeypatch.setattr(jsonschema._utils, "uniq", refuse)
    monkeypatch.setattr(jsonschema._keywords, "uniq", refuse)


def test_large_exports_never_compare_array_items_pairwise(monkeypatch):
    _refuse_pairwise(monkeypatch)
    risk = RiskAssessment(severity=RiskSeverity.HIGH, category="capability_scope", detail="d")
    boms = {
        scale: AIBOM(
            components=[
                ToolComponent(bom_ref=f"tool:{index}", name=f"t{index}", risks=[risk])
                for index in range(500 * scale)
            ]
        )
        for scale in (1, 4)
    }

    def export(scale: int) -> tuple[dict[str, Any], dict[str, Any]]:
        return CycloneDXGenerator().generate(boms[scale]), VEXGenerator().generate(boms[scale])

    assert scaling_ratio(export) < 10
    document, vex = export(4)
    assert len(document["components"]) == len(vex["vulnerabilities"]) == 2000
    duplicate = deepcopy(document)
    duplicate["components"].append(deepcopy(duplicate["components"][0]))
    assert any("non-unique" in error for error in validate_cyclonedx(duplicate))
    compositions = deepcopy(document)
    compositions["compositions"].append(deepcopy(compositions["compositions"][0]))
    assert any("non-unique" in error for error in validate_cyclonedx(compositions))


def _licensed_packages(count: int) -> list[dict[str, Any]]:
    graph: list[dict[str, Any]] = [
        {"type": "SpdxDocument", "spdxId": "urn:d", "element": [], "rootElement": []}
    ]
    for index in range(count):
        package = f"urn:p{index}"
        graph.append({"type": "dataset_DatasetPackage", "spdxId": package})
        for kind in ("hasDeclaredLicense", "hasConcludedLicense"):
            graph.append(
                {
                    "type": "Relationship",
                    "spdxId": f"{package}/{kind}",
                    "relationshipType": kind,
                    "from": package,
                    "to": ["expandedlicensing_NoAssertionLicense"],
                }
            )
    return graph


def test_spdx_graph_checks_index_relationships_once(monkeypatch):
    monkeypatch.setattr(validation, "_schema_errors", lambda document, fmt: [])
    graphs = {scale: _licensed_packages(2_500 * scale) for scale in (1, 4)}
    assert scaling_ratio(lambda scale: spdx_errors({"@graph": graphs[scale]})) < 10
    graph = graphs[4]
    assert spdx_errors({"@graph": graph}) == []
    graph.append({**graph[2], "spdxId": "urn:duplicate"})
    assert any("requires exactly one" in error for error in spdx_errors({"@graph": graph}))


def test_format_assertions_do_not_depend_on_optional_packages(monkeypatch):
    for name in ("rfc3339_validator", "rfc3986_validator", "rfc3987", "rfc3987_syntax"):
        monkeypatch.setitem(sys.modules, name, None)
    checker = format_checker()
    assert set(checker.checkers) == set(FORMAT_CHECKS)
    assert checker.conforms("2026-11-10T12:00:00Z", "date-time")
    assert checker.conforms("2016-12-31T23:59:60+00:00", "date-time")
    for value in ("not-a-date", "2026-13-01T00:00:00Z", "2026-11-10 12:00:00Z", "2026-11-10"):
        assert not checker.conforms(value, "date-time"), value
    # RFC 3339 digits are ASCII; fullwidth and Arabic-Indic digits are not.
    for value in (
        "２０２６-１１-１０T１２:００:００Z",
        "2026-11-10T12:00:00.١٢Z",
        "2026-11-10T12:00:00+٠١:00",
    ):
        assert not checker.conforms(value, "date-time"), value
    assert checker.conforms("2026-11-10", "date")
    assert not checker.conforms("٢٠٢٦-11-10", "date")
    assert checker.conforms("https://example.com/a?b#c", "iri-reference")
    assert checker.conforms("urn:cdx:x/1#ref", "iri-reference")
    for value in ("https://exa mple", "a\nb", "%zz", "a#b#c", "<x>"):
        assert not checker.conforms(value, "iri-reference"), value
    assert not checker.conforms("relative/path", "uri")
    document = CycloneDXGenerator().generate(fixture_bom())
    document["metadata"]["timestamp"] = "not-a-date"
    assert any("date-time" in error for error in validate_cyclonedx(document))


def _walk(value: Any, key: str) -> list[Any]:
    found = []
    if isinstance(value, dict):
        if key in value:
            found.append(value[key])
        for item in value.values():
            found.extend(_walk(item, key))
    elif isinstance(value, list):
        for item in value:
            found.extend(_walk(item, key))
    return found


VENDORED = [
    "cyclonedx/bom-1.7.schema.json",
    "cyclonedx/cryptography-defs.schema.json",
    "cyclonedx/jsf-0.82.schema.json",
    "cyclonedx/spdx.schema.json",
    "spdx/spdx-json-schema-3.0.1.json",
    "sarif/sarif-schema-2.1.0.json",
]


def test_every_format_and_external_reference_in_the_vendored_schemas_is_handled():
    formats = {
        value
        for name in VENDORED
        for value in _walk(validation._schema(name), "format")
        if isinstance(value, str)
    }
    assert formats <= set(FORMAT_CHECKS)
    external = {
        ref.split("#", 1)[0]
        for name in VENDORED
        for ref in _walk(validation._schema(name), "$ref")
        if isinstance(ref, str) and not ref.startswith("#")
    }
    assert external <= set(validation._CYCLONEDX_SUBSCHEMAS)


def test_cryptographic_assets_validate_instead_of_raising():
    document: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "version": 1,
        "components": [
            {
                "type": "cryptographic-asset",
                "bom-ref": "key",
                "name": "key",
                "cryptoProperties": {
                    "assetType": "algorithm",
                    "algorithmProperties": {"algorithmFamily": "AES"},
                },
            }
        ],
    }
    assert validate_cyclonedx(document) == []
    document["components"][0]["cryptoProperties"]["algorithmProperties"]["algorithmFamily"] = "?"
    assert validate_cyclonedx(document)


def test_vendored_schemas_must_match_their_recorded_digest(monkeypatch):
    monkeypatch.setattr(validation, "_provenance", lambda: {VENDORED[0]: "0" * 64})
    with pytest.raises(ValueError, match="provenance"):
        validation._schema(VENDORED[0])


def test_root_component_service_and_nested_references_resolve():
    document = CycloneDXGenerator().generate(fixture_bom())
    document["metadata"]["component"] = {
        "type": "application",
        "bom-ref": "environment",
        "name": "environment",
        "components": [{"type": "library", "bom-ref": "nested", "name": "nested"}],
    }
    document["services"] = [{"bom-ref": "service:api", "name": "api"}]
    document["dependencies"].append(
        {"ref": "environment", "dependsOn": ["nested", "service:api", "tool:send"]}
    )
    assert validate_cyclonedx(document) == []
    document["dependencies"][-1]["dependsOn"].append("missing")
    assert validate_cyclonedx(document) == ["unresolved CycloneDX reference: missing"]
    document["dependencies"][-1]["dependsOn"].pop()
    document["services"].append({"bom-ref": "nested", "name": "again"})
    assert validate_cyclonedx(document) == ["duplicate CycloneDX bom-ref"]


def test_vex_affected_references_must_resolve_or_be_bom_links():
    bom = fixture_bom()
    tool = bom.get_component("tool:send")
    assert isinstance(tool, ToolComponent)
    tool.risks = [RiskAssessment(severity=RiskSeverity.LOW, category="c", detail="d")]
    vex = VEXGenerator().generate(bom)
    assert validate_cyclonedx(vex) == []
    link = "urn:cdx:00000000-0000-0000-0000-000000000000/1#tool:send"
    vex["vulnerabilities"][0]["affects"] = [{"ref": link}]
    assert validate_cyclonedx(vex) == []
    for malformed in ("urn:cdx:", "urn:cdx:garbage"):
        vex["vulnerabilities"][0]["affects"] = [{"ref": malformed}]
        assert validate_cyclonedx(vex) == [f"unresolved CycloneDX reference: {malformed}"]
    vex["vulnerabilities"][0]["affects"] = [{"ref": "elsewhere"}]
    assert validate_cyclonedx(vex) == ["unresolved CycloneDX reference: elsewhere"]


def test_sarif_validates_against_the_vendored_oasis_schema(tmp_path):
    from nexus_symbiote.generators.sarif import SARIFGenerator
    from nexus_symbiote.generators.validation import validate_sarif

    bom = fixture_bom()
    document = SARIFGenerator(tmp_path).generate(bom)
    assert validate_sarif(document) == []
    unexpected = deepcopy(document)
    unexpected["runs"][0]["unexpectedTopLevelRunField"] = True
    assert any("unexpectedTopLevelRunField" in error for error in validate_sarif(unexpected))
