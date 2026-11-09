"""What a consumer that ignores the SymBiote extension reads from the standard exports.

Such a consumer must never see a conditional native edge as an unconditional typed
relationship, and must see that a scoped, failed or imported inventory is incomplete.
"""

from __future__ import annotations

import io
import json
import shutil
import uuid
from copy import deepcopy
from pathlib import Path
from typing import Any, get_args

import pytest
from click.testing import CliRunner

from nexus_symbiote import modes
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.models import CompletenessClaim, ToolComponent
from nexus_symbiote.generators._common import BUILTIN_EXCLUSIONS, NAMESPACE, coverage_aggregate
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import validate_cyclonedx, validate_spdx
from nexus_symbiote.policy import DEFAULT_POLICY_YAML
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from tests.test_export_conformance import fixture_bom

DEMO = Path(__file__).resolve().parents[1] / "examples" / "demo-agent"
EXTENSION_PREFIXES = ("nexus-symbiote:", "agentbom:")
LICENSE_RELATIONSHIPS = {"hasDeclaredLicense", "hasConcludedLicense"}
TYPED = {"usesTool", "dependsOn", "trainedOn", "descendantOf"}
TYPED_MAPPING = {
    "invokes": "usesTool",
    "depends-on": "dependsOn",
    "trained-on": "trainedOn",
    "fine-tuned-from": "descendantOf",
    "quantized-from": "descendantOf",
    "merged-from": "descendantOf",
}
NATIVE_RELATIONSHIPS = get_args(DependencyEdge.model_fields["relationship"].annotation)
RELATIONSHIP_PROPERTY = "nexus-symbiote:dependency:relationship"
# One non-default value per imported-report field of the completeness claim.
IMPORTED_MARKERS: dict[str, Any] = {
    "source_report_digest": "sha256:" + "0" * 64,
    "source_report_content_digest": "sha256:" + "1" * 64,
    "source_report_content_profile": "nexus-symbiote/shadowscan-content/v1",
    "source_report_format": "shadowscan-json",
    "source_report_status": "complete",
    "source_projection_limitations": ["unmapped entries are not represented"],
    "source_unmapped_count": 1,
    "source_unmapped_indexes": [0],
}
SCAN_CONDITION = "runtime use and authority unobserved"
APPROVAL = "only after a human approves the call"
EDGE_CASES = [
    (relationship, conditions)
    for relationship in NATIVE_RELATIONSHIPS
    for conditions in (None, "", APPROVAL)
]
DEFAULT_EXCLUDE_LINE = '  exclude_paths: ["node_modules", ".git", "__pycache__", ".venv"]'


def standard_only(document: dict[str, Any], fmt: str) -> dict[str, Any]:
    """Drop every SymBiote extension carrier and keep only standard fields."""
    if fmt == "spdx":
        return _without_extension(document)
    view = deepcopy(document)
    for holder in (view.get("metadata", {}), *view.get("components", [])):
        kept = [
            prop
            for prop in holder.get("properties", [])
            if not prop["name"].startswith(EXTENSION_PREFIXES)
        ]
        if kept:
            holder["properties"] = kept
        else:
            holder.pop("properties", None)
    return view


def _without_extension(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _without_extension(item) for key, item in value.items() if key != "extension"}
    if isinstance(value, list):
        return [_without_extension(item) for item in value]
    return value


def _spdx_id(view: dict[str, Any], bom_ref: str) -> str:
    suffix = f"#component-{uuid.uuid5(NAMESPACE, bom_ref)}"
    return next(n["spdxId"] for n in view["@graph"] if n.get("spdxId", "").endswith(suffix))


def _spdx_document(view: dict[str, Any]) -> dict[str, Any]:
    return next(n for n in view["@graph"] if n["type"] == "SpdxDocument")


def _edges(view: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        n
        for n in view["@graph"]
        if n["type"] == "Relationship" and n["relationshipType"] not in LICENSE_RELATIONSHIPS
    ]


def _between(view: dict[str, Any], source: str, target: str) -> list[dict[str, Any]]:
    source_id, target_id = _spdx_id(view, source), _spdx_id(view, target)
    return [e for e in _edges(view) if e["from"] == source_id and e["to"] == [target_id]]


def _one_edge(relationship: str, conditions: str | None = APPROVAL) -> AIBOM:
    bom = fixture_bom()
    # Two components keep the SPDX schema validation in generate and recover cheap.
    bom.components = [c for c in bom.components if c.bom_ref in {"agent:main", "tool:send"}]
    bom.dependencies = [
        DependencyEdge(
            source_ref="agent:main",
            target_ref="tool:send",
            relationship=relationship,
            conditions=conditions,
        )
    ]
    return bom


def _relationship_properties(document: dict[str, Any]) -> list[dict[str, Any]]:
    return [
        json.loads(prop["value"])
        for prop in document["metadata"]["properties"]
        if prop["name"] == RELATIONSHIP_PROPERTY
    ]


def _spdx_round_trip(document: dict[str, Any]) -> dict[str, Any]:
    from spdx_python_model.bindings import v3_0_1 as spdx

    objects = spdx.SHACLObjectSet()
    spdx.JSONLDDeserializer().read(io.BytesIO(json.dumps(document).encode()), objects)
    output = io.BytesIO()
    spdx.JSONLDSerializer().write(objects, output)
    consumed: dict[str, Any] = json.loads(output.getvalue())
    assert validate_spdx(consumed) == []
    return consumed


def _cyclonedx_strict(document: dict[str, Any]) -> None:
    assert validate_cyclonedx(document) == []
    pytest.importorskip("cyclonedx.validation.json")
    from cyclonedx.schema import SchemaVersion
    from cyclonedx.validation.json import JsonStrictValidator

    if not hasattr(SchemaVersion, "V1_7"):
        pytest.skip("installed cyclonedx library does not support 1.7")
    assert JsonStrictValidator(SchemaVersion.V1_7).validate_str(json.dumps(document)) is None


@pytest.mark.parametrize(("relationship", "typed"), sorted(TYPED_MAPPING.items()))
def test_spdx_conditional_edge_is_never_a_public_typed_relationship(relationship, typed):
    view = standard_only(SPDXGenerator().generate(_one_edge(relationship)), "spdx")
    assert not any(e["relationshipType"] in TYPED for e in _edges(view))
    (edge,) = _between(view, "agent:main", "tool:send")
    assert edge["relationshipType"] == "other"
    assert APPROVAL in edge.get("comment", "")
    assert f"'{relationship}'" in edge.get("comment", "")
    assert f"Not an unconditional {typed} assertion" in edge.get("comment", "")
    consumed = _spdx_round_trip(view)
    (kept,) = [n for n in consumed["@graph"] if n.get("comment", "").find(APPROVAL) >= 0]
    assert kept["relationshipType"] == "other"


def test_spdx_unconditional_edges_keep_their_typed_mapping():
    view = standard_only(SPDXGenerator().generate(fixture_bom()), "spdx")
    (uses,) = _between(view, "agent:main", "tool:send")
    (depends,) = _between(view, "agent:main", "model:one")
    assert (uses["relationshipType"], depends["relationshipType"]) == ("usesTool", "dependsOn")
    assert "comment" not in uses and "comment" not in depends


def test_spdx_conditional_comment_is_bounded():
    bom = _one_edge("invokes")
    bom.dependencies[0].conditions = "x" * 5000
    view = standard_only(SPDXGenerator().generate(bom), "spdx")
    (edge,) = _between(view, "agent:main", "tool:send")
    assert len(edge["comment"]) < 1200 and "[truncated]" in edge.get("comment", "")
    assert SPDXGenerator.recover(SPDXGenerator().generate(bom)).dependencies[0].conditions == (
        "x" * 5000
    )


def test_imported_conditional_dependency_matches_the_cyclonedx_public_graph():
    from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
    from tests.test_shadowscan_relationships import FIXTURE

    bom = ShadowScanImporter().read_report(FIXTURE).to_native_bom()
    assert any(e.relationship == "depends-on" and e.conditions for e in bom.dependencies)
    spdx_view = standard_only(SPDXGenerator().generate(bom), "spdx")
    cdx_view = standard_only(CycloneDXGenerator().generate(bom), "cyclonedx")
    assert not any(e["relationshipType"] == "dependsOn" for e in _edges(spdx_view))
    assert cdx_view.get("dependencies", []) == []
    # Imported discovery is never complete, in either format.
    assert cdx_view["compositions"] == [{"aggregate": "incomplete"}]
    assert {e.get("completeness") for e in _edges(spdx_view)} == {"incomplete"}
    _cyclonedx_strict(cdx_view)
    _spdx_round_trip(spdx_view)


@pytest.mark.parametrize("change", ["remove", "alter", "retype", "complete"])
def test_spdx_recovery_rejects_a_changed_public_condition(change):
    document = SPDXGenerator().generate(_one_edge("invokes"))
    edge = next(n for n in document["@graph"] if APPROVAL in n.get("comment", ""))
    if change == "remove":
        del edge["comment"]
    elif change == "alter":
        edge["comment"] = "Unconditional."
    elif change == "retype":
        edge["relationshipType"] = "usesTool"
    else:
        edge["completeness"] = "complete"
    with pytest.raises(ValueError, match="projection conflicts"):
        SPDXGenerator.recover(document)


def test_spdx_native_relationship_comment_survives_a_standard_reader():
    bom = _one_edge("delegates-to", None)
    document = SPDXGenerator().generate(bom)
    view = standard_only(document, "spdx")
    (kept,) = [n for n in _spdx_round_trip(view)["@graph"] if n.get("relationshipType") == "other"]
    assert kept.get("comment") == "Native relationship 'delegates-to'."
    assert SPDXGenerator.recover(_spdx_round_trip(document)).dependencies == bom.dependencies


@pytest.mark.parametrize("change", ["remove", "alter", "pad", "retype"])
def test_spdx_recovery_rejects_a_changed_native_relationship_comment(change):
    document = SPDXGenerator().generate(_one_edge("delegates-to", None))
    edge = next(
        n for n in document["@graph"] if n.get("comment") == "Native relationship 'delegates-to'."
    )
    if change == "remove":
        del edge["comment"]
    elif change == "alter":
        edge["comment"] = "Native relationship 'configured-with'."
    elif change == "pad":
        edge["comment"] += " "
    else:
        edge["relationshipType"] = "usesTool"
    with pytest.raises(ValueError, match="projection conflicts"):
        SPDXGenerator.recover(document)


@pytest.fixture(scope="module")
def every_edge() -> tuple[AIBOM, dict[str, Any], dict[str, Any]]:
    """One export per format, with a separate target for each relationship and condition."""
    bom = fixture_bom()
    bom.components += [
        ToolComponent(bom_ref=f"tool:case-{index}", name=f"case-{index}")
        for index in range(len(EDGE_CASES))
    ]
    bom.dependencies = [
        DependencyEdge(
            source_ref="agent:main",
            target_ref=f"tool:case-{index}",
            relationship=relationship,
            conditions=conditions,
        )
        for index, (relationship, conditions) in enumerate(EDGE_CASES)
    ]
    return bom, SPDXGenerator().generate(bom), CycloneDXGenerator().generate(bom)


@pytest.mark.parametrize(("relationship", "conditions"), EDGE_CASES)
def test_every_public_spdx_relationship_agrees_with_the_cyclonedx_graph(
    every_edge, relationship, conditions
):
    _bom, spdx_document, cdx = every_edge
    target = f"tool:case-{EDGE_CASES.index((relationship, conditions))}"
    (edge,) = _between(standard_only(spdx_document, "spdx"), "agent:main", target)
    typed = None if conditions else TYPED_MAPPING.get(relationship)
    # An empty condition stays typed, as `not edge.conditions` keeps it in the CycloneDX graph.
    assert edge["relationshipType"] == (typed or "other")
    if conditions:
        assert edge["comment"] == (
            f"Conditional native relationship '{relationship}' (conditions: {conditions}). "
            f"Not an unconditional {TYPED_MAPPING.get(relationship, 'relationship')} assertion."
        )
    elif typed is None:
        assert edge["comment"] == f"Native relationship '{relationship}'."
    else:
        assert "comment" not in edge
    graph = standard_only(cdx, "cyclonedx").get("dependencies", [])
    in_graph = any(
        target in row.get("dependsOn", []) for row in graph if row["ref"] == "agent:main"
    )
    assert in_graph == (typed == "dependsOn")
    flag = {"conditional": True} if conditions else {}
    assert [p for p in _relationship_properties(cdx) if p["to"] == target] == [
        {"from": "agent:main", "to": target, "type": relationship, **flag}
    ]


def test_every_relationship_and_condition_recovers_exactly(every_edge):
    bom, spdx_document, cdx = every_edge
    for recovered in (
        SPDXGenerator.recover(deepcopy(spdx_document)),
        CycloneDXGenerator.recover(deepcopy(cdx)),
    ):
        assert sorted(recovered.dependencies, key=str) == sorted(bom.dependencies, key=str)


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("conditions", [None, APPROVAL])
def test_cyclonedx_recovery_rejects_a_changed_conditional_flag(conditions, legacy):
    document = CycloneDXGenerator().generate(_one_edge("invokes", conditions))
    assert CycloneDXGenerator.recover(deepcopy(document)).dependencies[0].conditions == conditions
    prop = next(p for p in document["metadata"]["properties"] if p["name"] == RELATIONSHIP_PROPERTY)
    value = json.loads(prop["value"])
    if conditions:
        del value["conditional"]
    else:
        value["conditional"] = True
    prop["value"] = json.dumps(value, sort_keys=True, separators=(",", ":"))
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(document, allow_legacy_relationships=legacy)


def _claim(**changes: Any) -> CompletenessClaim:
    names = sorted(BUILTIN_SCANNER_NAMES)
    fields: dict[str, Any] = {
        "scope": "repository",
        "collectors_requested": names,
        "collectors_completed": names,
        "scanner_status": dict.fromkeys(names, "complete"),
        "exclusions": ["**/.git", "**/node_modules", ".venv", "__pycache__"],
        "unobserved_surfaces": ["runtime", "network"],
    }
    return CompletenessClaim(**{**fields, **changes})


@pytest.mark.parametrize(
    ("changes", "aggregate"),
    [
        (None, "unknown"),
        ({}, "unknown"),
        ({"unobserved_surfaces": []}, "unknown"),
        ({"collectors_requested": ["mcp"], "collectors_completed": ["mcp"]}, "incomplete"),
        ({"collectors_requested": [], "collectors_completed": []}, "incomplete"),
        ({"collectors_completed": ["mcp"]}, "incomplete"),
        ({"scanner_status": {"mcp": "partial"}}, "incomplete"),
        ({"scan_failures": [".mcp.json: invalid JSON or duplicate keys"]}, "incomplete"),
        ({"surfaces_excluded": ["tools.py: unresolved Python MCP tool name"]}, "incomplete"),
        ({"exclusions": ["**/.git", "src"]}, "incomplete"),
        *(({name: value}, "incomplete") for name, value in IMPORTED_MARKERS.items()),
        ({"source_projection_limitations": []}, "incomplete"),
        ({"scope": "repository+shadowscan"}, "incomplete"),
        ({"scope": "shadowscan-imported"}, "incomplete"),
        ({"scope": "Repository+ShadowScan"}, "incomplete"),
    ],
)
def test_public_coverage_is_derived_from_the_native_claim(changes, aggregate):
    bom = _one_edge("invokes", None)
    bom.metadata.completeness = None if changes is None else _claim(**changes)
    cdx = standard_only(CycloneDXGenerator().generate(bom), "cyclonedx")
    assert cdx.get("compositions") == [{"aggregate": aggregate}]
    spdx_view = standard_only(SPDXGenerator().generate(bom), "spdx")
    expected = "incomplete" if aggregate == "incomplete" else "noAssertion"
    assert {e.get("completeness") for e in _edges(spdx_view)} == {expected}
    assert (
        _spdx_document(spdx_view)
        .get("comment", "")
        .startswith(f"Collection coverage is {aggregate}")
    )
    assert coverage_aggregate(bom.metadata.completeness) == aggregate


def test_every_imported_report_field_has_a_public_coverage_case():
    fields = {name for name in CompletenessClaim.model_fields if name.startswith("source_")}
    assert set(IMPORTED_MARKERS) == fields
    for name, value in IMPORTED_MARKERS.items():
        default = CompletenessClaim.model_fields[name].get_default(call_default_factory=True)
        assert value != default and getattr(_claim(**{name: value}), name) == value


@pytest.mark.parametrize(
    "marker",
    [
        *({name: value} for name, value in IMPORTED_MARKERS.items()),
        {"scope": "repository+shadowscan"},
    ],
    ids=lambda marker: ",".join(marker),
)
def test_recovery_rejects_unknown_coverage_for_a_marker_only_import(marker):
    bom = _one_edge("invokes", None)
    bom.metadata.completeness = _claim(**marker)
    cdx = CycloneDXGenerator().generate(bom)
    spdx_document = SPDXGenerator().generate(bom)
    for recovered in (
        CycloneDXGenerator.recover(deepcopy(cdx)),
        SPDXGenerator.recover(deepcopy(spdx_document)),
    ):
        assert recovered.metadata.completeness == bom.metadata.completeness
    for weakened in (None, [{"aggregate": "unknown"}]):
        document = {k: v for k, v in cdx.items() if k != "compositions"}
        if weakened is not None:
            document["compositions"] = weakened
        with pytest.raises(ValueError, match="projection conflicts"):
            CycloneDXGenerator.recover(document)
    for edge in _edges(spdx_document):
        edge["completeness"] = "noAssertion"
    with pytest.raises(ValueError, match="projection conflicts"):
        SPDXGenerator.recover(spdx_document)


@pytest.fixture(scope="module")
def scans(tmp_path_factory) -> dict[str, dict[str, dict[str, Any]]]:
    if not DEMO.is_dir():
        pytest.skip("the demo project ships in the repository, not in the wheel")
    base = tmp_path_factory.mktemp("consumer")
    full = base / "demo-agent"
    shutil.copytree(DEMO, full)
    gap = base / "gap-agent"
    shutil.copytree(DEMO, gap)
    (gap / ".mcp.json").write_text('{"mcpServers": {"x": ', encoding="utf-8")
    initialized = base / "init-agent"
    shutil.copytree(DEMO, initialized)
    result = CliRunner().invoke(main, ["init", "--path", str(initialized)])
    assert result.exit_code == 0, result.output
    policy = (initialized / ".nexus-symbiote.yaml").read_text(encoding="utf-8")
    assert policy == DEFAULT_POLICY_YAML
    narrowed = base / "models-excluded-agent"
    shutil.copytree(DEMO, narrowed)
    (narrowed / ".nexus-symbiote.yaml").write_text(
        DEFAULT_POLICY_YAML.replace(DEFAULT_EXCLUDE_LINE, '  exclude_paths: ["models"]'),
        encoding="utf-8",
    )
    every_scanner = [arg for name in sorted(BUILTIN_SCANNER_NAMES) for arg in ("--scanner", name)]
    runs = {
        "full": (full, []),
        "subset": (full, ["--scanner", "mcp"]),
        "failed": (gap, []),
        "init-policy": (initialized, []),
        "models-excluded": (narrowed, []),
        "every-scanner": (full, every_scanner),
    }
    documents: dict[str, dict[str, dict[str, Any]]] = {}
    for name, (root, extra) in runs.items():
        documents[name] = {}
        for fmt in ("cyclonedx", "spdx"):
            output = base / f"{name}.{fmt}.json"
            result = CliRunner().invoke(
                main,
                ["scan", str(root), "-f", fmt, "-o", str(output), "--report-only", *extra],
                env={modes.ENV_VAR: None},
            )
            assert result.exit_code == 0, result.output
            documents[name][fmt] = json.loads(output.read_text(encoding="utf-8"))
    return documents


def test_scan_edges_carry_their_public_condition_in_spdx(scans):
    view = standard_only(scans["full"]["spdx"], "spdx")
    edges = _edges(view)
    assert edges
    for edge in edges:
        assert edge["relationshipType"] == "other"
        assert SCAN_CONDITION in edge.get("comment", "")
        assert "Not an unconditional" in edge.get("comment", "")
    properties = _relationship_properties(scans["full"]["cyclonedx"])
    assert properties and all(prop.get("conditional") is True for prop in properties)


def test_cli_runs_record_the_scope_each_case_needs(scans):
    def claim(scan: str) -> CompletenessClaim:
        recovered = CycloneDXGenerator.recover(scans[scan]["cyclonedx"]).metadata.completeness
        assert recovered is not None
        return recovered

    assert DEFAULT_EXCLUDE_LINE in DEFAULT_POLICY_YAML
    for scan in ("full", "init-policy", "every-scanner"):
        assert set(claim(scan).collectors_requested) == BUILTIN_SCANNER_NAMES
    # The init policy lists only built-in names, so it narrows nothing.
    assert set(claim("init-policy").exclusions) <= BUILTIN_EXCLUSIONS
    assert "models" in claim("models-excluded").exclusions
    assert set(claim("models-excluded").collectors_requested) == BUILTIN_SCANNER_NAMES
    assert not claim("models-excluded").scan_failures


@pytest.mark.parametrize("scan", ["full", "init-policy", "every-scanner"])
def test_full_static_demo_reports_incomplete_for_partial_ide_settings(scans, scan):
    cdx = standard_only(scans[scan]["cyclonedx"], "cyclonedx")
    spdx_view = standard_only(scans[scan]["spdx"], "spdx")
    assert cdx.get("compositions") == [{"aggregate": "incomplete"}]
    assert {e.get("completeness") for e in _edges(spdx_view)} == {"incomplete"}
    assert (
        _spdx_document(spdx_view).get("comment", "").startswith("Collection coverage is incomplete")
    )
    _cyclonedx_strict(cdx)
    _spdx_round_trip(spdx_view)
    document = scans[scan]["cyclonedx"]
    claim = CycloneDXGenerator.recover(document).metadata.completeness
    assert claim is not None
    assert claim.scanner_status["ide_agents"] == "partial"
    assert any(
        ".claude/settings.json: IDE settings only partially inventoried" in item
        for item in claim.surfaces_excluded
    )
    # Dropping an incomplete warning is a downgrade and recovery rejects it.
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover({k: v for k, v in document.items() if k != "compositions"})
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover({**document, "compositions": [{"aggregate": "complete"}]})


@pytest.mark.parametrize("scan", ["subset", "failed", "models-excluded"])
def test_scoped_or_failed_scan_is_publicly_incomplete(scans, scan):
    cdx = standard_only(scans[scan]["cyclonedx"], "cyclonedx")
    spdx_view = standard_only(scans[scan]["spdx"], "spdx")
    assert cdx.get("compositions") == [{"aggregate": "incomplete"}]
    assert cdx.get("dependencies", []) == []
    edges = _edges(spdx_view)
    assert edges and {e.get("completeness") for e in edges} == {"incomplete"}
    assert not any(e["relationshipType"] in TYPED for e in edges)
    assert (
        _spdx_document(spdx_view).get("comment", "").startswith("Collection coverage is incomplete")
    )
    _cyclonedx_strict(cdx)
    consumed = _spdx_round_trip(spdx_view)
    assert {
        n.get("completeness") for n in consumed["@graph"] if n.get("relationshipType") == "other"
    } == {"incomplete"}


@pytest.mark.parametrize("scan", ["subset", "failed", "models-excluded"])
@pytest.mark.parametrize("composition", [None, "unknown", "complete"])
def test_cyclonedx_recovery_rejects_a_weakened_partial_composition(scans, scan, composition):
    document = deepcopy(scans[scan]["cyclonedx"])
    assert CycloneDXGenerator.recover(document).metadata.completeness is not None
    if composition is None:
        del document["compositions"]
    else:
        document["compositions"] = [{"aggregate": composition}]
    with pytest.raises(ValueError, match="projection conflicts"):
        CycloneDXGenerator.recover(document)


def test_no_export_claims_complete_coverage(scans):
    for documents in scans.values():
        cdx, spdx_document = documents["cyclonedx"], documents["spdx"]
        assert all(c["aggregate"] != "complete" for c in cdx["compositions"])
        assert all(e.get("completeness") != "complete" for e in _edges(spdx_document))
