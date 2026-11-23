"""The G7 AI SBOM minimum-element catalog, and the evaluation of an inventory's export."""

from __future__ import annotations

import copy
import re
from datetime import UTC, datetime
from fractions import Fraction
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote import minimum_elements as me
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AnyComponent,
    ClaimEvidence,
    DataSourceComponent,
    GuardrailComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    RAGSourceComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from tests.support import scaling_ratio

ROOT = Path(__file__).resolve().parents[1]
SERIAL = "urn:uuid:3c7a1d8e-2b5f-4c1a-9e0d-7f6b5a4c3d21"
SUBJECT = "agent:repository:" + "1" * 24
DIGEST = "ab" * 32

# The element names and order of the G7 document, as four independent enumerations give them.
G7_ELEMENTS = {
    "Metadata": [
        "SBOM author",
        "SBOM version",
        "SBOM data format name",
        "SBOM data format version",
        "SBOM author signature",
        "SBOM tool name",
        "SBOM tool version",
        "SBOM generation context",
        "SBOM timestamp",
        "SBOM dependency relationship",
    ],
    "System Level Properties": [
        "System name",
        "System components",
        "System producer",
        "System version",
        "System timestamp",
        "System data flow",
        "System data usage",
        "System input/output properties",
        "Intended application area",
    ],
    "Models": [
        "Model name",
        "Model identifier",
        "Model version",
        "Model timestamp",
        "Model producer",
        "Model description",
        "Model hash value",
        "Model hash algorithm",
        "Model properties",
        "Model input-output properties",
        "Model training properties",
        "Model license",
        "Model external references",
    ],
    "Datasets Properties": [
        "Dataset name",
        "Dataset description",
        "Dataset content",
        "Dataset identifier",
        "Dataset hash",
        "Dataset provenance",
        "Dataset statistical properties",
        "Dataset sensitivity",
        "Dataset dependency relationship",
        "Dataset license",
    ],
    "Infrastructure": ["Infrastructure software", "Infrastructure hardware"],
    "Security Properties": [
        "Security controls",
        "Security compliance",
        "Cybersecurity policy information",
        "Vulnerability referencing",
    ],
    "Key Performance Indicators": ["Security metrics", "Operational performance KPIs"],
}
# No static source exists for these: producer documentation, runtime data or a signing step.
NEEDS_PRODUCER_INPUT = {
    "SBOM author signature",
    "System data usage",
    "System input/output properties",
    "Model training properties",
    "Dataset statistical properties",
    "Dataset sensitivity",
    "Dataset dependency relationship",
    "Infrastructure hardware",
    "Security compliance",
    "Security metrics",
    "Operational performance KPIs",
}


def inventory(*components: AnyComponent, dependencies: list[DependencyEdge] | None = None) -> AIBOM:
    bom = AIBOM(components=list(components), dependencies=dependencies or [])
    bom.metadata.serial_number = SERIAL
    bom.metadata.timestamp = datetime(2026, 11, 10, 12, 0, tzinfo=UTC)
    bom.metadata.tool_version = "0.1.0"
    return bom


def subject(**fields: Any) -> AgentComponent:
    declared = {
        key: ClaimEvidence(method="agent-manifest", scope="repository")
        for key in fields.pop("claims", ())
    }
    return AgentComponent(bom_ref=SUBJECT, claims=declared, **{"name": "triager", **fields})


def result(report: me.Report, slug: str) -> me.ElementResult:
    return next(r for r in report.elements if r.element.id.endswith("/" + slug))


def export_of(bom: AIBOM) -> dict[str, Any]:
    return CycloneDXGenerator().generate(bom.model_copy(deep=True))


def statuses(report: me.Report, cluster: me.Cluster) -> dict[str, str]:
    return {r.element.name: r.status for r in report.results(cluster)}


def result_ids(names: list[str]) -> list[str]:
    by_name = {element.name: element.id for element in me.ELEMENTS}
    return [by_name[name] for name in names]


def scanned_demo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> AIBOM:
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    output = tmp_path / "demo.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(ROOT / "examples" / "demo-agent"), "-o", str(output)]
    )
    assert scanned.exit_code == 0, scanned.output
    return AIBOM.load(output)


def test_catalog_lists_the_fifty_elements_verbatim_in_document_order():
    assert me.EDITION == "g7-ai-sbom-2026-05-12"
    assert [cluster.heading for cluster in me.CLUSTERS] == list(G7_ELEMENTS)
    assert [element.name for element in me.ELEMENTS] == [
        name for names in G7_ELEMENTS.values() for name in names
    ]
    split = [len([e for e in me.ELEMENTS if e.cluster is cluster]) for cluster in me.CLUSTERS]
    assert split == [10, 9, 13, 10, 2, 4, 2]
    assert len(me.ELEMENTS) == 50


def test_identifiers_are_unique_stable_and_scoped_to_their_cluster():
    ids = [element.id for element in me.ELEMENTS]
    assert len(set(ids)) == 50
    for element in me.ELEMENTS:
        assert re.fullmatch(r"g7ai-2026/[a-z]+/[a-z0-9]+(?:-[a-z0-9]+)*", element.id), element.id
        assert element.id.startswith(element.cluster.id + "/")
    assert [cluster.slug for cluster in me.CLUSTERS] == [
        "metadata",
        "slp",
        "models",
        "dp",
        "infrastructure",
        "sp",
        "kpi",
    ]
    assert [cluster.subject for cluster in me.CLUSTERS] == [
        "document",
        "system",
        "model",
        "dataset",
        "infrastructure",
        "security",
        "kpi",
    ]
    # Identifiers are minted here, so a later spelling fix of a name must not move one.
    assert result_ids(["Model input-output properties", "System input/output properties"]) == [
        "g7ai-2026/models/model-input-output-properties",
        "g7ai-2026/slp/system-input-output-properties",
    ]


def test_assessability_follows_what_a_static_scan_can_evidence():
    assert {
        element.name for element in me.ELEMENTS if element.assessable == me.NEEDS_PRODUCER_INPUT
    } == NEEDS_PRODUCER_INPUT
    assert {element.assessable for element in me.ELEMENTS} == {
        me.FROM_BOM,
        me.NEEDS_PRODUCER_INPUT,
    }
    assessable = {e.id for e in me.ELEMENTS if e.assessable == me.FROM_BOM}
    checks, rules = set(me._DOCUMENT_CHECKS), set(me._SUBJECT_RULES)
    assert not checks & rules
    assert checks | rules == assessable


def test_hints_are_fixed_single_lines_that_say_when_this_build_cannot_carry_an_element():
    for element in me.ELEMENTS:
        texts = (element.hint, element.rule, element.cyclonedx, element.spdx, element.name)
        for text in texts:
            assert text and "\n" not in text and "|" not in text and "`" not in text
        unavailable = element.hint.startswith("Not available in this build:")
        never = element.rule.startswith("Never:")
        if element.assessable == me.FROM_BOM:
            assert unavailable == (element.carried != me.WRITTEN), element.name
            assert never == (element.carried == me.NO_FIELD), element.name
        else:
            assert not unavailable and element.rule.startswith("Not evaluated:"), element.name
        assert element.carried in {me.WRITTEN, me.NOT_WRITTEN, me.NO_FIELD}
        assert (element.cyclonedx == "none") == (element.carried == me.NO_FIELD), element.name
    for text in [*me.REASONS.values(), *me.NOTES.values()]:
        assert "\n" not in text and "|" not in text and "`" not in text


def test_demo_agent_coverage_is_pinned(tmp_path, monkeypatch):
    report = me.assess(scanned_demo(tmp_path, monkeypatch))
    assert report.counts() == {
        me.PRESENT: 11,
        me.MISSING: 28,
        me.EXPLICIT_UNKNOWN: 0,
        me.NEEDS_PRODUCER_INPUT: 11,
        me.NOT_APPLICABLE: 0,
    }
    assert report.coverage() == me.Coverage(11, 39)
    assert report.coverage().percent() == "28.2"
    assert [(report.coverage(c).present, report.coverage(c).assessable) for c in me.CLUSTERS] == [
        (6, 9),
        (1, 7),
        (3, 12),
        (0, 7),
        (1, 1),
        (0, 3),
        (0, 0),
    ]
    assert report.subjects == {"system": True, "models": 1, "datasets": 0, "retrieval_sources": 1}
    assert report.projection == "cyclonedx-1.7/2"
    name = result(report, "system-name")
    assert (name.status, name.reasons) == (me.MISSING, ("inferred-placeholder",))
    hashes = result(report, "model-hash-value")
    assert (hashes.status, hashes.basis) == (me.PRESENT, me.OBSERVED)
    # A scan records no timestamp unless SOURCE_DATE_EPOCH pins one.
    stamp = result(report, "sbom-timestamp")
    assert (stamp.status, stamp.reasons) == (me.MISSING, ())
    assert "SOURCE_DATE_EPOCH" in stamp.element.hint
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1767225600")
    pinned = me.assess(scanned_demo(tmp_path, monkeypatch))
    assert pinned.coverage() == me.Coverage(12, 39)
    assert result(pinned, "sbom-timestamp").status == me.PRESENT
    assert hashes.cyclonedx.items == ("/components/6/hashes/0/content",)
    flow = result(report, "system-data-flow")
    assert flow.extension_only and len(flow.native.items) == 3
    datasets = result(report, "dataset-identifier")
    assert datasets.reasons == ("not-identified",)
    assert datasets.subjects == me.Subjects("dataset", 1, 0, me.Listing(("rag:product-notes",), 0))
    assert report.notes(me.DATASETS) == ("retrieval-sources",)


def test_an_inventory_without_a_model_makes_the_models_cluster_not_applicable():
    report = me.assess(inventory(subject(), MCPServerComponent(bom_ref="mcp:docs", name="docs")))
    models = report.results(me.MODELS)
    assert {r.status for r in models} == {me.NOT_APPLICABLE}
    assert {r.reasons for r in models} == {("no-model-component",)}
    assert {r.status for r in report.results(me.DATASETS)} == {me.NOT_APPLICABLE}
    # Never because nothing can be seen: the other clusters stay applicable.
    assert me.NOT_APPLICABLE not in {r.status for r in report.results(me.SYSTEM)}
    assert report.coverage().assessable == 39 - 12 - 7


def test_a_licence_carried_only_in_a_property_is_extension_only_and_missing():
    model = ModelComponent(
        bom_ref="model:weights", name="weights", properties={"license": "Apache-2.0"}
    )
    bom = inventory(subject(), model)
    export = export_of(bom)
    exported = next(c for c in export["components"] if c["bom-ref"] == "model:weights")
    assert "licenses" not in exported
    assert any("Apache-2.0" in p["value"] for p in exported["properties"])
    licence = result(me.evaluate(bom, export), "model-license")
    assert licence.status == me.MISSING and licence.extension_only
    assert licence.native.items == ("/components/1/properties/license",)
    exported["licenses"] = [{"license": {"id": "Apache-2.0"}}]
    licence = result(me.evaluate(bom, export), "model-license")
    assert (licence.status, licence.basis) == (me.PRESENT, me.DECLARED)
    assert licence.cyclonedx.items == (f"{pointer(export, 'model:weights')}/licenses/0/license/id",)
    assert not licence.extension_only


def pointer(export: dict[str, Any], ref: str) -> str:
    index = next(i for i, c in enumerate(export["components"]) if c["bom-ref"] == ref)
    return f"/components/{index}"


@pytest.mark.parametrize(
    ("licence", "expected"),
    [
        ({"license": {"id": "NOASSERTION"}}, me.MISSING),
        ({"license": {"name": "NoAssertionLicense"}}, me.MISSING),
        ({"expression": " \u200b\t"}, me.MISSING),
        ({"license": {"name": "unknown"}}, me.EXPLICIT_UNKNOWN),
        ({"expression": "MIT OR Apache-2.0"}, me.PRESENT),
    ],
)
def test_placeholder_licences_are_not_present(licence, expected):
    bom = inventory(ModelComponent(bom_ref="model:weights", name="weights"))
    export = export_of(bom)
    export["components"][0]["licenses"] = [licence]
    assert result(me.evaluate(bom, export), "model-license").status == expected


def test_placeholder_and_invisible_values_are_missing_and_unknown_is_counted_apart():
    model = ModelComponent(
        bom_ref="model:weights",
        name="\u200b\u202e ",
        version="Unknown",
        supplier="NOASSERTION",
        description="\t ",
    )
    report = me.assess(inventory(subject(version="unknown", supplier=" "), model))
    assert result(report, "model-name").status == me.MISSING
    assert result(report, "model-version").status == me.EXPLICIT_UNKNOWN
    assert result(report, "model-producer").status == me.MISSING
    assert result(report, "model-description").status == me.MISSING
    assert result(report, "system-version").status == me.EXPLICIT_UNKNOWN
    assert result(report, "system-producer").status == me.MISSING
    # A stated unknown is assessable and not present: it cannot raise the ratio.
    counts = report.counts()
    assert counts[me.EXPLICIT_UNKNOWN] == 2
    coverage = report.coverage()
    assert coverage.assessable == counts[me.PRESENT] + counts[me.MISSING] + 2


@pytest.mark.parametrize(
    "blank",
    ["\u3164", "\u115f\u1160", "\uffa0", "\u2800", "\u034f\ufe0f", "\u0301", " \u3000\t"],
)
def test_text_with_no_visible_character_is_missing(blank):
    model = ModelComponent(
        bom_ref="model:w", name="w", version=blank, supplier=blank, description=blank
    )
    report = me.assess(inventory(subject(version=blank, supplier=blank), model))
    for slug in ("system-version", "system-producer", "model-producer", "model-description"):
        assert result(report, slug).status == me.MISSING, slug
    version = result(report, "model-version")
    assert version.status == me.MISSING and not version.native.items
    # A base letter with a combining mark, or a filler beside a letter, is visible text.
    shown = ModelComponent(bom_ref="model:w", name="w", version="e\u0301", supplier="\u2800x")
    report = me.assess(inventory(shown))
    assert result(report, "model-version").status == me.PRESENT
    assert result(report, "model-producer").status == me.PRESENT


def test_unknown_never_reads_better_than_missing():
    stated = me.assess(inventory(subject(version="unknown")))
    absent = me.assess(inventory(subject()))
    assert stated.coverage() == absent.coverage()


def test_values_an_export_would_substitute_are_not_counted():
    bom = AIBOM(components=[subject()])
    report = me.assess(bom)
    for slug in ("sbom-tool-version", "sbom-version"):
        assert result(report, slug).status == me.MISSING, slug
        assert result(report, slug).reasons == ("export-default",)
    # The export writes no timestamp the inventory lacks, so there is none to discount.
    assert export_of(bom)["metadata"].get("timestamp") is None
    assert result(report, "sbom-timestamp").status == me.MISSING
    # The inventory is not changed, so the report cannot depend on the wall clock.
    assert bom.metadata.timestamp is None and bom.metadata.serial_number is None
    assert me.assess(bom).to_dict() == report.to_dict()
    assert result(me.assess(inventory(subject())), "sbom-timestamp").status == me.PRESENT


def test_per_model_offenders_are_sorted_and_bounded_with_an_omitted_count():
    models = [ModelComponent(bom_ref=f"model:{i:02d}", name=f"m{i}") for i in range(25)]
    models[3].version = "1.0"
    report = me.assess(inventory(*reversed(models)))
    version = result(report, "model-version")
    assert version.status == me.MISSING
    assert version.subjects is not None
    assert (version.subjects.total, version.subjects.present) == (25, 1)
    expected = [f"model:{i:02d}" for i in range(25) if i != 3]
    assert list(version.subjects.offenders.items) == expected[: me.MAX_LISTED]
    assert version.subjects.offenders.omitted == len(expected) - me.MAX_LISTED == 4
    name = result(report, "model-name")
    assert len(name.cyclonedx.items) == me.MAX_LISTED and name.cyclonedx.omitted == 5


def test_a_per_subject_element_is_present_only_when_every_subject_has_it():
    local = ModelComponent(
        bom_ref="model:local",
        name="local",
        hashes={"sha256": "sha256:" + DIGEST},
        assurance_level=AssuranceLevel.OBSERVED,
    )
    hosted = ModelComponent(bom_ref="model:hosted", name="gpt-4o", provider="openai")
    mixed = result(me.assess(inventory(local, hosted)), "model-hash-value")
    assert mixed.status == me.MISSING
    assert mixed.subjects == me.Subjects("model", 2, 1, me.Listing(("model:hosted",), 0))
    alone = result(me.assess(inventory(local)), "model-hash-algorithm")
    assert (alone.status, alone.basis) == (me.PRESENT, me.OBSERVED)
    # A hosting provider is not the producer.
    assert result(me.assess(inventory(hosted)), "model-producer").status == me.MISSING


def test_the_weakest_basis_wins_in_the_order_imported_declared_observed():
    assert me._weakest([me.OBSERVED, me.DECLARED]) == me.DECLARED
    assert me._weakest([me.DECLARED, me.IMPORTED]) == me.IMPORTED
    assert me._weakest([me.OBSERVED, me.IMPORTED, me.DECLARED]) == me.IMPORTED
    assert me._weakest([None, me.OBSERVED]) == me.OBSERVED
    assert me._weakest([]) is None


def test_a_mixed_set_of_models_reports_its_weakest_basis():
    # Sorted by reference, the observed model comes first: the basis is not the first's.
    local = ModelComponent(
        bom_ref="model:a-local",
        name="classifier",
        version="1.0",
        hashes={"sha256": "sha256:" + DIGEST},
        assurance_level=AssuranceLevel.OBSERVED,
    )
    # A digest the inventory states, without a collector measuring it, stays declared.
    stated = ModelComponent(
        bom_ref="model:b-stated", name="ranker", version="2.0", hashes={"sha256": "cd" * 32}
    )
    measured = ("model-name", "model-hash-value", "model-hash-algorithm")
    alone = me.assess(inventory(local))
    assert {slug: result(alone, slug).basis for slug in measured} == dict.fromkeys(
        measured, me.OBSERVED
    )
    mixed = me.assess(inventory(local, stated))
    for slug in measured:
        assert (result(mixed, slug).status, result(mixed, slug).basis) == (
            me.PRESENT,
            me.DECLARED,
        ), slug
    imported = ModelComponent(
        bom_ref="shadowscan:0123456789abcdef",
        name="ShadowScan local-model 0123456789ab",
        version="3.0",
        properties={"collection_mode": "imported-unverified-report"},
    )
    version = result(me.assess(inventory(local, stated, imported)), "model-version")
    assert (version.status, version.basis) == (me.PRESENT, me.IMPORTED)


def test_system_components_take_the_weakest_presence_claim():
    def configured(ref: str, assurance: AssuranceLevel | None) -> MCPServerComponent:
        claims = (
            {}
            if assurance is None
            else {
                "repository_presence": ClaimEvidence(
                    assurance=assurance, method="mcp-config", scope="repository"
                )
            }
        )
        return MCPServerComponent(bom_ref=ref, name="docs", claims=claims)

    seen = configured("mcp:a-seen", AssuranceLevel.OBSERVED)
    for other, basis in [
        (configured("mcp:b-also-seen", AssuranceLevel.OBSERVED), me.OBSERVED),
        (configured("mcp:b-stated", AssuranceLevel.DECLARED), me.DECLARED),
        (configured("mcp:b-unclaimed", None), me.DECLARED),
    ]:
        components = result(me.assess(inventory(subject(), seen, other)), "system-components")
        assert (components.status, components.basis) == (me.PRESENT, basis), other.bom_ref


@pytest.mark.parametrize(
    ("assurance", "basis"),
    [
        (None, me.DECLARED),
        ("declared", me.DECLARED),
        ("observed", me.OBSERVED),
        ("verified", me.OBSERVED),
    ],
)
def test_the_dependency_relationship_basis_follows_the_exported_edges(assurance, basis):
    server = MCPServerComponent(bom_ref="mcp:docs", name="docs")
    tools = [ToolComponent(bom_ref=f"tool:{name}", name=name) for name in ("fetch", "search")]

    def provides(tool: str, level: str | None) -> DependencyEdge:
        return DependencyEdge(
            source_ref="mcp:docs",
            target_ref=tool,
            relationship="provides-tool",
            assurance_level=level,
        )

    alone = inventory(subject(), server, *tools, dependencies=[provides("tool:search", assurance)])
    edges = result(me.assess(alone), "sbom-dependency-relationship")
    assert (edges.status, edges.basis) == (me.PRESENT, basis)
    observed = provides("tool:fetch", "observed")
    mixed = inventory(
        subject(), server, *tools, dependencies=[observed, provides("tool:search", assurance)]
    )
    edges = result(me.assess(mixed), "sbom-dependency-relationship")
    assert (edges.status, edges.basis) == (me.PRESENT, basis)


def test_an_imported_registry_entry_makes_infrastructure_software_imported():
    image = RegistryEntryComponent(
        bom_ref="registry:docker/ollama", name="ollama/ollama", registry_type="docker-hub"
    )
    imported = RegistryEntryComponent(
        bom_ref="shadowscan:fedcba9876543210",
        name="ShadowScan registry fedcba987654",
        registry_type="pypi",
        properties={"collection_mode": "imported-unverified-report"},
    )
    software = result(me.assess(inventory(image)), "infrastructure-software")
    assert (software.status, software.basis) == (me.PRESENT, me.DECLARED)
    software = result(me.assess(inventory(image, imported)), "infrastructure-software")
    assert (software.status, software.basis) == (me.PRESENT, me.IMPORTED)


def test_md5_and_sha1_alone_do_not_count_as_a_model_hash():
    model = ModelComponent(
        bom_ref="model:weights", name="w", hashes={"md5": "0" * 32, "sha1": "1" * 40}
    )
    report = me.assess(inventory(model))
    assert result(report, "model-hash-value").status == me.MISSING
    assert result(report, "model-hash-algorithm").status == me.MISSING


def test_an_imported_shadowscan_label_is_not_a_model_name():
    imported = ModelComponent(
        bom_ref="shadowscan:0123456789abcdef",
        name="ShadowScan local-model 0123456789ab",
        version="2.0",
        properties={"collection_mode": "imported-unverified-report"},
    )
    report = me.assess(inventory(imported))
    name = result(report, "model-name")
    assert (name.status, name.reasons) == (me.MISSING, ("synthetic-name",))
    version = result(report, "model-version")
    assert (version.status, version.basis) == (me.PRESENT, me.IMPORTED)


def test_a_component_the_standard_fields_do_not_identify_is_not_a_subject_with_values():
    bom = inventory(ModelComponent(bom_ref="model:weights", name="weights", version="1.0"))
    export = export_of(bom)
    export["components"][0]["type"] = "library"
    version = result(me.evaluate(bom, export), "model-version")
    assert (version.status, version.reasons) == (me.MISSING, ("not-identified",))
    assert version.native.items == ("/components/0/version",)
    del export["components"][0]
    assert result(me.evaluate(bom, export), "model-name").reasons == ("not-identified",)


def test_datasets_count_only_when_a_standard_field_marks_them():
    data = DataSourceComponent(
        bom_ref="data:tickets",
        name="tickets",
        description="Fine-tuning set",
        license="CC-BY-4.0",
        source_uri="https://data.example/tickets",
        content_hash="sha256:" + DIGEST,
    )
    bom = inventory(subject(), data)
    export = export_of(bom)
    report = me.evaluate(bom, export)
    unmarked = {r.element.name: r for r in report.results(me.DATASETS)}
    assert {r.status for r in unmarked.values()} == {me.MISSING, me.NEEDS_PRODUCER_INPUT}
    assert unmarked["Dataset license"].native.items == ("/components/1/license",)
    assert unmarked["Dataset identifier"].native.items == ("/components/1/source_uri",)
    assert unmarked["Dataset hash"].native.items == ("/components/1/content_hash",)
    assert report.subjects["datasets"] == 1 and not report.notes(me.DATASETS)
    component = export["components"][0]
    component["data"] = [
        {
            "type": "dataset",
            "name": "tickets",
            "contents": {"url": "https://data.example/tickets"},
            "governance": {"owners": [{"organization": {"name": "Acme"}}]},
        }
    ]
    component["licenses"] = [{"license": {"id": "CC-BY-4.0"}}]
    marked = {r.element.name: r for r in me.evaluate(bom, export).results(me.DATASETS)}
    assert {name: r.status for name, r in marked.items() if r.status == me.PRESENT} == {
        "Dataset name": me.PRESENT,
        "Dataset description": me.PRESENT,
        "Dataset content": me.PRESENT,
        "Dataset identifier": me.PRESENT,
        "Dataset hash": me.PRESENT,
        "Dataset provenance": me.PRESENT,
        "Dataset license": me.PRESENT,
    }
    del component["data"]
    component["tags"] = ["dataset"]
    assert result(me.evaluate(bom, export), "dataset-name").status == me.PRESENT


def test_model_card_and_identifier_fields_are_read_from_standard_fields_only():
    bom = inventory(ModelComponent(bom_ref="model:weights", name="weights"))
    export = export_of(bom)
    component = export["components"][0]
    report = me.evaluate(bom, export)
    absent = ("model-identifier", "model-properties", "model-input-output-properties")
    assert {result(report, slug).status for slug in absent} == {me.MISSING}
    component["modelCard"] = {
        "bom-ref": "card",
        "modelParameters": {"architectureFamily": "llama", "inputs": [{"format": "text"}]},
    }
    component["omniborId"] = ["gitoid:blob:sha1:" + "1" * 40]
    component["externalReferences"] = [{"type": "model-card", "url": "https://hub.example/m"}]
    report = me.evaluate(bom, export)
    assert result(report, "model-identifier").cyclonedx.items == ("/components/0/omniborId/0",)
    assert result(report, "model-properties").status == me.PRESENT
    assert result(report, "model-description").status == me.PRESENT
    assert result(report, "model-external-references").status == me.PRESENT
    # Inputs without outputs do not describe the model's input-output properties.
    assert result(report, "model-input-output-properties").status == me.MISSING
    component["modelCard"]["modelParameters"]["outputs"] = [{"format": "label"}]
    assert result(me.evaluate(bom, export), "model-input-output-properties").status == me.PRESENT
    component["modelCard"] = {"bom-ref": "card-only"}
    component.pop("externalReferences")
    assert result(me.evaluate(bom, export), "model-description").status == me.MISSING


def test_extension_properties_inside_a_standard_structure_do_not_count():
    bom = inventory(ModelComponent(bom_ref="model:weights", name="weights"))
    export = export_of(bom)
    card = {"bom-ref": "card", "properties": [{"name": "nexus-symbiote:card", "value": "x"}]}
    export["components"][0]["modelCard"] = card
    assert result(me.evaluate(bom, export), "model-description").status == me.MISSING
    card["properties"].append({"name": "cdx:card", "value": "a model card"})
    description = result(me.evaluate(bom, export), "model-description")
    assert description.cyclonedx.items == ("/components/0/modelCard",)


def test_system_elements_need_one_declared_subject():
    report = me.assess(inventory(ModelComponent(bom_ref="model:weights", name="weights")))
    system = report.results(me.SYSTEM)
    assessable = [r for r in system if r.element.assessable == me.FROM_BOM]
    assert {r.status for r in assessable} == {me.MISSING}
    assert {r.reasons for r in assessable} == {("no-system-subject",)}
    declared = me.assess(
        inventory(
            subject(
                name="repository", version="1.4", supplier="platform-security", claims=["name"]
            ),
            ModelComponent(bom_ref="model:weights", name="weights"),
        )
    )
    assert statuses(declared, me.SYSTEM) == {
        "System name": me.PRESENT,
        "System components": me.PRESENT,
        "System producer": me.PRESENT,
        "System version": me.PRESENT,
        "System timestamp": me.MISSING,
        "System data flow": me.MISSING,
        "System data usage": me.NEEDS_PRODUCER_INPUT,
        "System input/output properties": me.NEEDS_PRODUCER_INPUT,
        "Intended application area": me.MISSING,
    }
    assert result(declared, "system-name").basis == me.DECLARED
    placeholder = me.assess(inventory(subject(name="repository")))
    assert result(placeholder, "system-name").reasons == ("inferred-placeholder",)


def test_only_unconditional_dependencies_count_and_the_rest_is_listed():
    server = MCPServerComponent(bom_ref="mcp:docs", name="docs")
    tool = ToolComponent(bom_ref="tool:search", name="search")
    associated = DependencyEdge(
        source_ref=SUBJECT,
        target_ref="mcp:docs",
        relationship="configured-with",
        conditions="repository association",
    )
    provides = DependencyEdge(
        source_ref="mcp:docs",
        target_ref="tool:search",
        relationship="provides-tool",
        assurance_level="observed",
    )
    only_conditional = me.assess(inventory(subject(), server, tool, dependencies=[associated]))
    edges = result(only_conditional, "sbom-dependency-relationship")
    assert edges.status == me.MISSING and edges.native.items == ("/dependencies/0",)
    assert (edges.reasons, edges.relationships) == ((), me.Relationships(1, 0))
    bom = inventory(subject(), server, tool, dependencies=[associated, provides])
    export = export_of(bom)
    edges = result(me.evaluate(bom, export), "sbom-dependency-relationship")
    assert (edges.status, edges.basis) == (me.PRESENT, me.OBSERVED)
    assert edges.native.items == ("/dependencies/0",)
    # Present, but the export carries one of the two relationships: that is stated.
    assert edges.reasons == ("partial", "unexported-relationships")
    assert edges.relationships == me.Relationships(recorded=2, exported=1)
    assert edges.to_dict()["relationships"] == {"recorded": 2, "exported": 1}
    exported = {
        (row["ref"], target) for row in export["dependencies"] for target in row["dependsOn"]
    }
    carried = [edge for edge in bom.dependencies if me._exported_edge(edge)]
    assert exported == {(edge.target_ref, edge.source_ref) for edge in carried}
    every = result(
        me.assess(inventory(subject(), server, tool, dependencies=[provides])),
        "sbom-dependency-relationship",
    )
    # A static scan never claims its relationships are complete, even when all are exported.
    assert (every.status, every.reasons) == (me.PRESENT, ("partial",))
    assert every.relationships == me.Relationships(1, 1) and not every.native.items
    none = result(me.assess(inventory(subject(), server, tool)), "sbom-dependency-relationship")
    assert (none.status, none.relationships, none.to_dict()["relationships"]) == (
        me.MISSING,
        None,
        None,
    )


def test_infrastructure_software_is_a_package_or_image_not_a_tool_definition():
    tool = ToolComponent(bom_ref="tool:search", name="search")
    assert result(me.assess(inventory(tool)), "infrastructure-software").status == me.MISSING
    framework = me.assess(inventory(subject(framework="langgraph"), tool))
    software = result(framework, "infrastructure-software")
    assert software.extension_only and software.native.items == ("/components/0/framework",)
    image = RegistryEntryComponent(
        bom_ref="registry:docker/ollama", name="ollama/ollama", registry_type="docker-hub"
    )
    present = result(me.assess(inventory(tool, image)), "infrastructure-software")
    assert (present.status, present.basis, present.reasons) == (
        me.PRESENT,
        me.DECLARED,
        ("partial",),
    )


@pytest.mark.parametrize(
    ("registry", "expected"),
    [
        ("pypi", me.PRESENT),
        ("npm", me.PRESENT),
        ("oci", me.PRESENT),
        ("Docker-Hub", me.PRESENT),
        ("huggingface", me.MISSING),
        ("mcp-registry", me.MISSING),
        ("skill-marketplace", me.MISSING),
        (None, me.MISSING),
    ],
)
def test_infrastructure_software_counts_only_package_and_image_registries(registry, expected):
    entry = RegistryEntryComponent(
        bom_ref="registry:entry", name="example", registry_type=registry, version="1.0"
    )
    software = result(me.assess(inventory(subject(), entry)), "infrastructure-software")
    assert software.status == expected


def test_security_properties_count_standard_references_and_not_inventory_findings():
    bom = inventory(
        subject(),
        A2AServerComponent(bom_ref="a2a:support", name="support", authentication_required=True),
        GuardrailComponent(bom_ref="guard:filter", name="filter"),
        MemoryStoreComponent(bom_ref="memory:notes", name="notes", encryption_at_rest=True),
    )
    export = export_of(bom)
    report = me.evaluate(bom, export)
    controls = result(report, "security-controls")
    assert controls.status == me.MISSING and controls.reasons == ("no-standard-field",)
    assert set(controls.native.items) == {
        "/components/1/authentication_required",
        "/components/2",
        "/components/3/encryption_at_rest",
    }
    export["vulnerabilities"] = [{"bom-ref": "v1", "id": "NEXUS-0123"}]
    assert result(me.evaluate(bom, export), "vulnerability-referencing").status == me.MISSING
    export["vulnerabilities"].append({"bom-ref": "v2", "id": "CVE-2024-34359"})
    found = result(me.evaluate(bom, export), "vulnerability-referencing")
    assert found.cyclonedx.items == ("/vulnerabilities/1/id",)
    export["metadata"]["component"]["externalReferences"] = [
        {"type": "rfc-9116", "url": "https://example.com/.well-known/security.txt"}
    ]
    policy = result(me.evaluate(bom, export), "cybersecurity-policy-information")
    assert policy.cyclonedx.items == ("/metadata/component/externalReferences/0/url",)


def test_services_carry_system_data_flow_for_standard_readers():
    remote = MCPServerComponent(bom_ref="mcp:remote", name="r", endpoint_url="https://mcp.example")
    client = A2AClientComponent(
        bom_ref="a2a:client", name="c", agent_card_url="https://agents.example/card"
    )
    bom = inventory(subject(), remote, client)
    export = export_of(bom)
    flow = result(me.evaluate(bom, export), "system-data-flow")
    assert flow.extension_only
    assert flow.native.items == ("/components/1/endpoint_url", "/components/2/agent_card_url")
    export["services"] = [{"name": "r", "data": [{"flow": "unknown", "classification": "x"}]}]
    assert result(me.evaluate(bom, export), "system-data-flow").status == me.EXPLICIT_UNKNOWN
    export["services"][0]["endpoints"] = ["https://mcp.example"]
    flow = result(me.evaluate(bom, export), "system-data-flow")
    assert (flow.status, flow.reasons) == (me.PRESENT, ("partial",))


def test_coverage_rounds_down_and_compares_thresholds_exactly():
    two_thirds = me.Coverage(2, 3)
    assert two_thirds.percent() == "66.6"
    assert not two_thirds.below(Fraction(200, 3)) and two_thirds.below(Fraction("66.67"))
    assert me.Coverage(1999, 2000).percent() == "99.9"
    nothing = me.Coverage(0, 0)
    assert nothing.percent() is None and nothing.below(Fraction(0))
    assert nothing.to_dict() == {"present": 0, "assessable": 0, "percent": None}


def test_the_report_is_deterministic_and_names_its_format(tmp_path, monkeypatch):
    bom = scanned_demo(tmp_path, monkeypatch)
    first, second = me.assess(bom).to_dict(), me.assess(copy.deepcopy(bom)).to_dict()
    assert first == second
    assert first["format"] == "nexus-symbiote/minimum-elements/v1"
    assert first["guidance"]["binding"] is False
    assert first["guidance"]["verification"] == "secondary"
    assert [e["id"] for e in first["elements"]] == [e.id for e in me.ELEMENTS]
    assert first["coverage"] == {"present": 11, "assessable": 39, "percent": 28.2}
    assert first["gate"] is None
    gated = me.assess(bom).to_dict(fail_under="30.8")
    assert gated["gate"] == {"fail_under": "30.8", "passed": False}


def test_evaluation_time_grows_linearly_with_the_number_of_subjects():
    prepared: dict[int, tuple[AIBOM, dict[str, Any]]] = {}
    for scale in (1, 4):
        models = [
            ModelComponent(bom_ref=f"model:{i:05d}", name=f"m{i}", version="1")
            for i in range(150 * scale)
        ]
        rag = [RAGSourceComponent(bom_ref=f"rag:{i:05d}", name=f"r{i}") for i in range(40 * scale)]
        bom = inventory(subject(), *models, *rag)
        prepared[scale] = (bom, export_of(bom))
    # Only the evaluation is timed here; the next test times the export with it.
    assert scaling_ratio(lambda scale: me.evaluate(*prepared[scale])) < 8


def test_assessment_time_grows_linearly_with_the_inventory():
    # The command exports a supplied inventory of up to 16 MiB, not only a bounded scan.
    boms: dict[int, AIBOM] = {}
    for scale in (1, 4):
        server = MCPServerComponent(bom_ref="mcp:docs", name="docs")
        tools = [ToolComponent(bom_ref=f"tool:{i:05d}", name=f"t{i}") for i in range(50 * scale)]
        edges = [
            DependencyEdge(
                source_ref="mcp:docs", target_ref=tool.bom_ref, relationship="provides-tool"
            )
            for tool in tools
        ]
        models = [
            ModelComponent(bom_ref=f"model:{i:05d}", name=f"m{i}") for i in range(100 * scale)
        ]
        boms[scale] = inventory(subject(), server, *tools, *models, dependencies=edges)
    assert scaling_ratio(lambda scale: me.assess(boms[scale])) < 8


def test_document_identity_and_tools_are_read_as_the_export_writes_them():
    bom = inventory(subject())
    export = export_of(bom)
    export["metadata"]["tools"] = [{"name": "other-tool", "version": "2.0"}]
    report = me.evaluate(bom, export)
    assert result(report, "sbom-tool-name").cyclonedx.items == ("/metadata/tools/0/name",)
    assert result(report, "sbom-tool-version").status == me.PRESENT
    for malformed in ({"version": True}, {"version": 0}, {"serialNumber": " "}):
        broken = {**export, **malformed}
        assert result(me.evaluate(bom, broken), "sbom-version").status == me.MISSING, malformed
    del export["metadata"]["component"]
    names = result(me.evaluate(bom, export), "system-name")
    assert (names.status, names.reasons) == (me.MISSING, ("no-system-subject",))


def test_imported_components_make_the_system_component_list_imported():
    imported = MCPServerComponent(
        bom_ref="shadowscan:0123456789abcdef",
        name="ShadowScan mcp-server 0123456789ab",
        properties={"collection_mode": "imported-unverified-report"},
    )
    components = result(me.assess(inventory(subject(), imported)), "system-components")
    assert (components.status, components.basis) == (me.PRESENT, me.IMPORTED)


def test_a_deeply_nested_native_value_cannot_exhaust_the_stack():
    nested: object = "Apache-2.0"
    for _ in range(20_000):
        nested = {"terms": [nested]}
    model = ModelComponent(bom_ref="model:weights", name="weights")
    bom = inventory(model)
    export = export_of(bom)
    model.properties["license"] = nested
    licence = result(me.evaluate(bom, export), "model-license")
    assert licence.extension_only
    assert licence.native.items == ("/components/0/properties/license",)


@pytest.mark.parametrize("value", ["unknown\u2800", "\u2800Unknown", "unknown\u3164"])
def test_a_blank_filler_does_not_turn_unknown_into_a_value(value):
    model = ModelComponent(bom_ref="model:w", name="w", version=value)
    report = me.assess(inventory(subject(version=value), model))
    assert result(report, "system-version").status == me.EXPLICIT_UNKNOWN
    assert result(report, "model-version").status == me.EXPLICIT_UNKNOWN
    licence = ModelComponent(bom_ref="model:w", name="w")
    bom = inventory(licence)
    export = export_of(bom)
    export["components"][0]["licenses"] = [{"license": {"id": "NOASSERTION\u2800"}}]
    assert result(me.evaluate(bom, export), "model-license").status == me.MISSING


def test_a_legacy_agent_named_after_its_checkout_has_no_system_name():
    # Release 0.1.0 named an agent without agent.yaml after the checkout directory.
    legacy = subject(name="checkout", properties={"identity_source": "repository-path"})
    name = result(me.assess(inventory(legacy)), "system-name")
    assert (name.status, name.reasons) == (me.MISSING, ("inferred-placeholder",))
    declared = subject(
        name="checkout", properties={"identity_source": "agent.yaml"}, claims=["name"]
    )
    assert result(me.assess(inventory(declared)), "system-name").status == me.PRESENT
