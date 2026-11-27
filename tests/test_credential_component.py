"""The credential component: named, never valued, through the native format and every export."""

from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator
from pydantic import ValidationError

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge, native_document
from nexus_symbiote.core.enums import ComponentType, RiskSeverity
from nexus_symbiote.core.models import (
    AgentComponent,
    AIBOMMetadata,
    CredentialComponent,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import spdx_errors, validate_cyclonedx
from nexus_symbiote.validators.risk import RiskScorer

ROOT = Path(__file__).resolve().parents[1]
# Assembled at run time so no token-shaped literal sits in this file.
TOKEN = "ghp_" + "Zq7" * 12


def _inventory(*, exposed: bool = False) -> AIBOM:
    credential = CredentialComponent(
        bom_ref="credential:OPENAI_API_KEY",
        name="OPENAI_API_KEY",
        credential_kind="environment-variable",
        value_in_checkout=exposed,
        source_path="app/agent.py",
        risks=[
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="credential_exposure",
                detail="A value for OPENAI_API_KEY is committed in app/agent.py",
                recommendation="Remove the value, rotate it and load it from a secret store",
            )
        ]
        if exposed
        else [],
    )
    # A collection time keeps reference libraries from stamping their own, which recovery
    # would rightly read as an edit.
    return AIBOM(
        metadata=AIBOMMetadata(timestamp=datetime(2026, 1, 1, tzinfo=UTC)),
        components=[
            AgentComponent(bom_ref="agent:support", name="support", framework="langgraph"),
            ModelComponent(bom_ref="model:gpt-4o", name="gpt-4o", model_type="hosted"),
            credential,
        ],
        dependencies=[
            DependencyEdge(
                source_ref="agent:support", target_ref="model:gpt-4o", relationship="uses-model"
            ),
            DependencyEdge(
                source_ref="model:gpt-4o",
                target_ref="credential:OPENAI_API_KEY",
                relationship="acts-as-identity",
            ),
        ],
    )


def _credential(document: dict[str, Any]) -> dict[str, Any]:
    (record,) = (c for c in document["components"] if c["component_type"] == "credential")
    return record


def _schema() -> Draft202012Validator:
    schema = json.loads((ROOT / "schemas/nexus-symbiote-aibom-1.0.schema.json").read_text())
    return Draft202012Validator(schema)


def test_a_credential_round_trips_through_the_native_format_and_its_schema(tmp_path: Path) -> None:
    bom = _inventory(exposed=True)
    document = bom.to_dict()
    assert document["metadata"]["spec_version"] == "1.2.0"
    assert list(_schema().iter_errors(document)) == []
    path = tmp_path / "bom.json"
    bom.save(path)
    loaded = AIBOM.load(path)
    (credential,) = (c for c in loaded.components if isinstance(c, CredentialComponent))
    assert credential.component_type is ComponentType.CREDENTIAL
    assert (credential.credential_kind, credential.value_in_checkout) == (
        "environment-variable",
        True,
    )
    assert native_document(loaded) == native_document(bom)


@pytest.mark.parametrize("field", ["name", "bom_ref"])
def test_a_name_or_reference_shaped_like_a_value_is_refused(tmp_path: Path, field: str) -> None:
    values = {"bom_ref": "credential:token", "name": "GITHUB_TOKEN"}
    values[field] = TOKEN if field == "name" else f"credential:{TOKEN}"
    with pytest.raises(ValidationError):
        CredentialComponent(**values)

    # A stored inventory carrying one is refused as a whole, without echoing the value.
    document = _inventory().to_dict()
    _credential(document)[field] = values[field]
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    result = CliRunner().invoke(main, ["summary", str(path)])
    assert result.exit_code != 0
    assert TOKEN not in result.output


@pytest.mark.parametrize(
    "values",
    [
        {"description": f"rotated {TOKEN}"},
        {"version": TOKEN},
        {"source_path": f"app/{TOKEN}.py"},
        {"properties": {"note": [TOKEN]}},
        {"properties": {TOKEN: "x"}},
    ],
    ids=["description", "version", "source_path", "property-value", "property-key"],
)
def test_no_other_text_of_a_credential_may_hold_a_value(values: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as caught:
        CredentialComponent(bom_ref="credential:A", name="A", **values)
    assert TOKEN not in str(caught.value)


def test_a_credential_records_no_digest_of_its_value() -> None:
    with pytest.raises(ValidationError, match="no digest"):
        CredentialComponent(bom_ref="credential:A", name="A", hashes={"SHA-256": "0" * 64})


def test_credential_kinds_are_a_closed_vocabulary() -> None:
    for kind in ("environment-variable", "workflow-credential", "source-literal"):
        assert CredentialComponent(bom_ref="credential:A", name="A", credential_kind=kind)
    with pytest.raises(ValidationError):
        CredentialComponent(bom_ref="credential:A", name="A", credential_kind="vault-secret")
    document = _inventory().to_dict()
    _credential(document)["credential_kind"] = "vault-secret"
    assert list(_schema().iter_errors(document))


def _properties(document: dict[str, Any]) -> dict[str, str]:
    return {p["name"]: p["value"] for p in document["metadata"]["properties"]}


@pytest.mark.parametrize("spec_version", ["1.7", "1.6"])
def test_cyclonedx_records_a_credential_as_crypto_material_with_no_value(spec_version: str) -> None:
    from cyclonedx.model.bom import Bom
    from cyclonedx.output.json import JsonV1Dot6, JsonV1Dot7

    bom = _inventory(exposed=True)
    projection = {"projection_version": 3} if spec_version == "1.6" else {}
    document = CycloneDXGenerator(spec_version=spec_version, **projection).generate(bom)
    assert validate_cyclonedx(document) == []
    (credential,) = (c for c in document["components"] if c["bom-ref"].startswith("credential:"))
    assert credential["type"] == "cryptographic-asset"
    assert credential["cryptoProperties"] == {
        "assetType": "related-crypto-material",
        "relatedCryptoMaterialProperties": {"type": "credential"},
    }
    assert "value" not in json.dumps(credential["cryptoProperties"])
    # The reference library reads and writes the record unchanged, and the export recovers.
    writer = JsonV1Dot7 if spec_version == "1.7" else JsonV1Dot6
    output = json.loads(writer(Bom.from_json(document)).output_as_string())
    (rewritten,) = (c for c in output["components"] if c["bom-ref"].startswith("credential:"))
    assert rewritten["cryptoProperties"] == credential["cryptoProperties"]
    assert native_document(CycloneDXGenerator.recover(output)) == native_document(bom)


@pytest.mark.parametrize("projection", [3, 4])
def test_spdx_leaves_credentials_to_the_embedded_document_and_reports_the_loss(
    projection: int,
) -> None:
    from spdx_python_model.bindings import v3_0_1 as spdx

    bom = _inventory(exposed=True)
    document = SPDXGenerator(projection_version=projection).generate(bom)
    assert spdx_errors(document) == []
    graph = document["@graph"]
    assert not [n for n in graph if n.get("name") == "OPENAI_API_KEY"]
    relationships = [n for n in graph if n.get("type") == "Relationship"]
    # The model-to-credential edge is the native document's alone; the agent-to-model one stays.
    assert "acts-as-identity" not in json.dumps(relationships)
    assert "uses-model" in json.dumps(relationships)
    doc = next(n for n in graph if n["type"] == "SpdxDocument")
    report = json.loads(
        next(
            p["extension_cdxPropValue"]
            for p in doc["extension"][0]["extension_cdxProperty"]
            if p["extension_cdxPropName"] == "nexus-symbiote:lossReport"
        )
    )
    index = next(
        i
        for i, c in enumerate(native_document(bom)["components"])
        if c["bom_ref"].startswith("credential:")
    )
    assert any(
        item["path"] == f"/components/{index}" and "no class for a credential" in item["reason"]
        for item in report["items"]
    )
    # The reference library reads the document, and the credential recovers from the embedding.
    objects = spdx.SHACLObjectSet()
    spdx.JSONLDDeserializer().read(io.BytesIO(json.dumps(document).encode()), objects)
    buffer = io.BytesIO()
    spdx.JSONLDSerializer().write(objects, buffer)
    recovered = SPDXGenerator.recover(json.loads(buffer.getvalue()))
    assert native_document(recovered) == native_document(bom)


def test_cyclonedx_loss_report_has_no_spdx_entry() -> None:
    report = json.loads(
        _properties(CycloneDXGenerator().generate(_inventory()))["nexus-symbiote:lossReport"]
    )
    assert not [item for item in report["items"] if "no class for a credential" in item["reason"]]


def test_a_credential_finding_gates_and_reaches_sarif(tmp_path: Path) -> None:
    bom = _inventory(exposed=True)
    passed, report = RiskScorer().passes_gate(bom)
    assert not passed
    assert any(f.category == "credential_exposure" for f in report.findings)
    sarif = json.loads(SARIFGenerator(scan_root=tmp_path).generate_json(bom))
    assert any(
        r["ruleId"] == "nexus_symbiote/credential_exposure/high"
        for r in sarif["runs"][0]["results"]
    )


def test_a_new_identity_an_agent_acts_as_is_a_drift_alert() -> None:
    before = _inventory()
    before.components = [c for c in before.components if c.bom_ref != "credential:OPENAI_API_KEY"]
    before.dependencies = [d for d in before.dependencies if d.relationship != "acts-as-identity"]
    result = AIBOMDiffer().diff(before, _inventory())
    assert any("credential:OPENAI_API_KEY" in str(alert) for alert in result.security_alerts)


def test_a_value_newly_committed_for_a_credential_is_a_high_drift_alert() -> None:
    report = AIBOMDiffer().diff(_inventory(), _inventory(exposed=True))
    (change,) = report.components_modified
    assert change.bom_ref == "credential:OPENAI_API_KEY"
    assert change.severity == "high"
    assert any("now committed in the checkout" in d for d in change.details)
    # The reverse, a value removed, is an improvement and is not rated high for it.
    reverse = AIBOMDiffer().diff(_inventory(exposed=True), _inventory())
    assert not any("now committed" in d for c in reverse.components_modified for d in c.details)


def test_reconciliation_vouches_for_no_credential_that_no_collector_records(tmp_path: Path) -> None:
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.\n")
    target = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(target)]
    )
    assert scanned.exit_code == 0, scanned.output
    document = json.loads(target.read_text())
    document["components"].append(
        CredentialComponent(bom_ref="credential:STRIPE_KEY", name="STRIPE_KEY").model_dump(
            mode="json", exclude_none=True
        )
    )
    target.write_text(json.dumps(document))
    validated = CliRunner().invoke(
        main, ["validate", str(target), "--project", str(project), "--no-project-policy"]
    )
    assert validated.exit_code != 0
    assert "credential:STRIPE_KEY" in validated.output
