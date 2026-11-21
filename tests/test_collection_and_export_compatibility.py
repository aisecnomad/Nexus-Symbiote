"""Compatibility checks for typed declarations, source collection, and export recovery."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM, MAX_NATIVE_NESTING
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import DataSourceComponent, GuardrailComponent, ModelComponent
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.spdx_profiles import apply_agent_yaml_declarations
from tests.test_a2a_collection import CARD


def test_unobserved_dataset_and_model_can_share_a_name(tmp_path: Path):
    (tmp_path / "agent.yaml").write_text(
        "datasets:\n  - name: evaluation\n"
        "models:\n  - name: evaluation\n    training:\n      datasets: [evaluation]\n"
    )
    bom = AIBOM()
    assert apply_agent_yaml_declarations(bom, tmp_path) == []
    dataset = next(c for c in bom.components if isinstance(c, DataSourceComponent))
    model = next(c for c in bom.components if isinstance(c, ModelComponent))
    assert model.name == dataset.name == "evaluation"
    assert any(
        edge.source_ref == model.bom_ref
        and edge.target_ref == dataset.bom_ref
        and edge.relationship == "trained-on"
        for edge in bom.dependencies
    )


@pytest.mark.parametrize(
    ("component_type", "section"),
    [(ModelComponent, "datasets"), (DataSourceComponent, "models")],
)
def test_cross_type_declaration_respects_existing_collected_record(
    tmp_path: Path, component_type, section: str
):
    (tmp_path / "agent.yaml").write_text(f"{section}:\n  - name: evaluation\n")
    collected = component_type(
        bom_ref="collected:evaluation",
        name="evaluation",
        assurance_level=AssuranceLevel.DECLARED,
    )
    bom = AIBOM(components=[collected])

    notices = apply_agent_yaml_declarations(bom, tmp_path)

    assert bom.components == [collected]
    assert len(notices) == 1 and "name conflict" in notices[0]
    assert [risk.category for risk in collected.risks] == ["declaration_conflict"]


def test_conflicting_duplicate_declaration_keeps_first_values(tmp_path: Path):
    (tmp_path / "agent.yaml").write_text(
        "datasets:\n  - name: evaluation\n    release_time: '2025-01-01'\n"
        "  - name: evaluation\n    release_time: '2025-02-01'\n"
    )
    bom = AIBOM()
    notices = apply_agent_yaml_declarations(bom, tmp_path)
    dataset = next(c for c in bom.components if isinstance(c, DataSourceComponent))
    assert len([c for c in bom.components if isinstance(c, DataSourceComponent)]) == 1
    assert dataset.properties["declared_release_time"] == "2025-01-01T00:00:00Z"
    assert [r.category for r in dataset.risks] == ["declaration_conflict"]
    assert len(notices) == 1 and "conflicting declaration" in notices[0]


def test_refused_declared_uri_preserves_observed_source_and_conflict(tmp_path: Path):
    (tmp_path / "agent.yaml").write_text(
        "datasets:\n  - name: evaluation\n    source_uri: 'https://data.example.test/café.csv'\n"
    )
    dataset = DataSourceComponent(
        bom_ref="dataset:evaluation",
        name="evaluation",
        source_uri="https://data.example.test/current.csv",
        assurance_level=AssuranceLevel.OBSERVED,
    )
    bom = AIBOM(components=[dataset])
    notices = apply_agent_yaml_declarations(bom, tmp_path)
    assert dataset.source_uri == "https://data.example.test/current.csv"
    assert "declared_download_location" not in dataset.properties
    assert any("source_uri conflict" in notice for notice in notices)


@pytest.mark.parametrize("withhold_rail", [False, True])
def test_nemo_keeps_configuration_when_its_colang_is_named_or_withheld(
    tmp_path: Path, withhold_rail: bool
):
    config = b"models: []\n"
    (tmp_path / "config.yml").write_bytes(config)
    rail = tmp_path / "check_secrets.co"
    if withhold_rail:
        private = tmp_path / "credentials.json"
        private.write_text("{}")
        rail.symlink_to(private.name)
    else:
        rail.write_text("define flow check vocabulary\n")
    result = RAGScanner().scan(tmp_path)
    guardrail = next(c for c in result.components if isinstance(c, GuardrailComponent))
    assert guardrail.source_path == "config.yml" and not result.scan_failures
    if withhold_rail:
        assert guardrail.config_hash == hash_bytes(config)
        assert "rail_files" not in guardrail.properties
        assert result.surfaces_excluded
    else:
        assert set(guardrail.properties["rail_files"]) == {rail.name}
        assert not result.surfaces_excluded


def test_known_card_below_credentials_directory_keeps_interface_origin(tmp_path: Path):
    path = tmp_path / "services/credentials/.well-known/agent-card.json"
    path.parent.mkdir(parents=True)
    card = dict(
        CARD,
        additionalInterfaces=[{"url": "https:\t//service.example.test/a2a"}, {"url": "HTTP: 503"}],
    )
    path.write_text(json.dumps(card))
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    [server] = [c for c in result.components if "additional_interface_origins" in c.properties]
    assert "https://service.example.test" in server.properties["additional_interface_origins"]
    assert not any(r.category == "transport_security" for r in server.risks)


@pytest.mark.parametrize(
    "exporter",
    [
        CycloneDXGenerator(projection_version=3),
        CycloneDXGenerator(projection_version=3, spec_version="1.6"),
        SPDXGenerator(projection_version=4),
    ],
)
def test_exact_prior_typed_download_location_can_be_recovered(exporter):
    location = "https://data.example.test/evaluation.csv?format=table"
    dataset = DataSourceComponent(
        bom_ref="dataset:evaluation",
        name="evaluation",
        properties={"declared_download_location": location},
    )
    bom = AIBOM(components=[dataset])
    document = exporter.generate(bom)
    if isinstance(exporter, CycloneDXGenerator):
        [reference] = document["components"][0]["externalReferences"]
        field = "url"
    else:
        reference = next(e for e in document["@graph"] if "software_downloadLocation" in e)
        field = "software_downloadLocation"
    assert reference[field] == "https://data.example.test/evaluation.csv"
    reference[field] = location
    recovered = exporter.recover(document)
    assert recovered.components[0].properties["declared_download_location"] == location
    reference[field] = "https://data.example.test/unrelated.csv"
    with pytest.raises(ValueError, match="projection conflicts"):
        exporter.recover(document)


@pytest.mark.parametrize("exporter", [CycloneDXGenerator(), SPDXGenerator()])
def test_generators_refuse_embedded_inventory_above_recovery_depth(exporter):
    properties = {"description": "leaf"}
    for _ in range(MAX_NATIVE_NESTING):
        properties = {"entry": properties}
    dataset = DataSourceComponent(
        bom_ref="dataset:evaluation", name="evaluation", properties=properties
    )
    with pytest.raises(ValueError, match="embedded native document is nested too deeply"):
        exporter.generate(AIBOM(components=[dataset]))
