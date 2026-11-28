"""The credential component: named, never valued, through the native format and every export."""

from __future__ import annotations

import io
import json
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from jsonschema import Draft202012Validator
from pydantic import ValidationError

import nexus_symbiote.scanners as scanners_module
from nexus_symbiote import cli
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import (
    AIBOM,
    DependencyEdge,
    ExportCheckError,
    NativeFormatError,
    native_document,
)
from nexus_symbiote.core.canonical import content_digest, json_text
from nexus_symbiote.core.enums import ComponentType, RiskSeverity
from nexus_symbiote.core.identifiers import RAW_DIGESTS, neutralize_identifiers
from nexus_symbiote.core.models import (
    AgentComponent,
    AIBOMMetadata,
    ClaimEvidence,
    CredentialComponent,
    CredentialProperties,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.generators.validation import spdx_errors, validate_cyclonedx
from nexus_symbiote.graph_view import build_view
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.validators.risk import RiskScorer

ROOT = Path(__file__).resolve().parents[1]
# Assembled at run time so no token-shaped literal sits in this file.
TOKEN = "ghp_" + "Zq7" * 12
# A value with no recognisable shape: only the closed property set keeps it out.
PLAIN = "hunter2-plain-value"


def _inventory(*, exposed: bool = False, supplied_risk: bool = True) -> AIBOM:
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
        if exposed and supplied_risk
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


@pytest.mark.parametrize(
    "text",
    [
        "-----BEGIN RSA " + "PRIVATE KEY-----\nsynthetic",
        "database postgresql://reader:synthetic@store.example/db",
    ],
    ids=["private-key", "connection-userinfo"],
)
def test_structured_secrets_are_refused_at_construction_and_export(text: str) -> None:
    with pytest.raises(ValidationError) as error:
        CredentialComponent(bom_ref="credential:A", name="A", description=text)
    assert text not in str(error.value)

    bom = _inventory()
    (credential,) = (c for c in bom.components if isinstance(c, CredentialComponent))
    credential.claims["ref"] = ClaimEvidence(method="lookup", scope="repository", locator=text)
    with pytest.raises(NativeFormatError) as export:
        bom.to_native_json()
    assert text not in str(export.value)


def test_a_credential_records_no_digest_of_its_value() -> None:
    with pytest.raises(ValidationError):
        CredentialComponent(bom_ref="credential:A", name="A", hashes={"SHA-256": "0" * 64})
    # The schema refuses what the model refuses.
    document = _inventory().to_dict()
    _credential(document)["hashes"] = {"SHA-256": "0" * 64}
    assert list(_schema().iter_errors(document))


def test_a_credential_records_only_how_and_where_it_was_collected() -> None:
    allowed = {
        "collection_mode": "static-source-declaration",
        "declaration_line": 12,
        RAW_DIGESTS: {"name": "sha256:" + "a" * 64},
    }
    credential = CredentialComponent(bom_ref="credential:A", name="A", properties=allowed)
    assert credential.properties == allowed
    document = _inventory().to_dict()
    _credential(document)["properties"] = allowed
    assert list(_schema().iter_errors(document)) == []


@pytest.mark.parametrize(
    "properties",
    [
        {"value": PLAIN},
        {"password": PLAIN},
        {"collection_mode": PLAIN},
        {"declaration_line": 0},
        {"declaration_line": True},
        {RAW_DIGESTS: {"name": PLAIN}},
        {RAW_DIGESTS: {"value": "sha256:" + "a" * 64}},
    ],
    ids=["value", "password", "mode", "line-zero", "line-bool", "digest-shape", "digest-field"],
)
def test_no_property_of_a_credential_holds_a_value(properties: dict[str, Any]) -> None:
    with pytest.raises(ValidationError) as built:
        CredentialComponent(bom_ref="credential:A", name="A", properties=properties)
    document = _inventory().to_dict()
    _credential(document)["properties"] = properties
    assert list(_schema().iter_errors(document))
    with pytest.raises(ValidationError) as read:
        AIBOM.from_document(document)
    # Neither error quotes the record it refused.
    assert PLAIN not in str(built.value) + str(read.value)


def test_neutralized_text_keeps_its_digests_on_a_credential() -> None:
    assert RAW_DIGESTS in CredentialProperties.model_fields
    bom = _inventory()
    credential = next(c for c in bom.components if isinstance(c, CredentialComponent))
    credential.description = "Read by the agent\x1b[2J"
    neutralize_identifiers(credential)
    assert set(credential.properties[RAW_DIGESTS]) == {"description"}
    assert "\\u001b" not in bom.to_native_json()


@pytest.mark.parametrize("version", ["1.0.0", "1.1.0"])
def test_only_a_format_that_defines_credentials_carries_one(tmp_path: Path, version: str) -> None:
    document = _inventory().to_dict()
    document["metadata"]["spec_version"] = version
    assert list(_schema().iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.from_document(document)
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    with pytest.raises(NativeFormatError):
        AIBOM.load(path)
    with pytest.raises(ValidationError):
        AIBOM(metadata=AIBOMMetadata(spec_version=version), components=_inventory().components)
    # An older document without credentials is read as before.
    document["components"] = [
        c for c in document["components"] if c["component_type"] != "credential"
    ]
    document["dependencies"] = [
        d for d in document["dependencies"] if d["relationship"] != "acts-as-identity"
    ]
    assert list(_schema().iter_errors(document)) == []
    path.write_text(json.dumps(document))
    assert AIBOM.load(path).metadata.spec_version == version


def test_a_document_that_declares_no_version_carries_no_credential() -> None:
    (credential,) = (
        c for c in _inventory().to_dict()["components"] if c["component_type"] == "credential"
    )
    document = {"components": [credential]}
    assert list(_schema().iter_errors(document))
    with pytest.raises(ValidationError):
        AIBOM.from_document(document)


def _hash_added(bom: AIBOM) -> None:
    next(c for c in bom.components if isinstance(c, CredentialComponent)).hashes["SHA-256"] = (
        "ab" * 32
    )


def _token_assigned(bom: AIBOM) -> None:
    next(c for c in bom.components if isinstance(c, CredentialComponent)).description = TOKEN


def _token_in_a_property(bom: AIBOM) -> None:
    credential = next(c for c in bom.components if isinstance(c, CredentialComponent))
    credential.properties.setdefault("notes", []).append(TOKEN)


def _value_property_added(bom: AIBOM) -> None:
    credential = next(c for c in bom.components if isinstance(c, CredentialComponent))
    credential.properties["value"] = PLAIN


def _built_unvalidated(bom: AIBOM) -> None:
    bom.components.append(CredentialComponent.model_construct(bom_ref="credential:x", name=TOKEN))


def _older_format(bom: AIBOM) -> None:
    bom.metadata.spec_version = "1.1.0"


@pytest.mark.parametrize(
    "change",
    [
        _hash_added,
        _token_assigned,
        _token_in_a_property,
        _value_property_added,
        _built_unvalidated,
        _older_format,
    ],
)
def test_every_export_refuses_a_credential_changed_after_it_was_built(
    tmp_path: Path, change: Any
) -> None:
    bom = _inventory(exposed=True)
    change(bom)
    with pytest.raises(NativeFormatError) as refused:
        bom.to_native_json()
    assert TOKEN not in str(refused.value) and PLAIN not in str(refused.value)
    target = tmp_path / "bom.json"
    with pytest.raises(NativeFormatError):
        bom.save(target)
    assert not target.exists()
    for exporter in (
        CycloneDXGenerator(),
        CycloneDXGenerator(spec_version="1.6", projection_version=3),
        SPDXGenerator(),
        SPDXGenerator(projection_version=4),
        SARIFGenerator(scan_root=tmp_path),
    ):
        with pytest.raises(ExportCheckError) as refused_export:
            exporter.generate(bom)
        shown = str(refused_export.value)
        assert TOKEN not in shown and PLAIN not in shown


def test_recovery_refuses_an_embedded_credential_that_carries_a_digest() -> None:
    document = CycloneDXGenerator().generate(_inventory(exposed=True))
    properties = {p["name"]: p for p in document["metadata"]["properties"]}
    embedded = json.loads(properties["nexus-symbiote:document"]["value"])
    _credential(embedded)["hashes"] = {"SHA-256": "ab" * 32}
    properties["nexus-symbiote:document"]["value"] = json_text(embedded)
    properties["nexus-symbiote:documentDigest"]["value"] = content_digest(embedded)
    with pytest.raises(ValueError):
        CycloneDXGenerator.recover(document)


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


def _exposure_findings(bom: AIBOM) -> list[Any]:
    _, report = RiskScorer().passes_gate(bom)
    return [f for f in report.findings if f.category == "credential_exposure"]


def test_a_value_in_the_checkout_is_a_high_finding_from_the_recorded_fact(tmp_path: Path) -> None:
    bom = _inventory(exposed=True, supplied_risk=False)
    (finding,) = _exposure_findings(bom)
    assert finding.severity is RiskSeverity.HIGH
    assert finding.component_ref == "credential:OPENAI_API_KEY"
    sarif = json.loads(SARIFGenerator(scan_root=tmp_path).generate_json(bom))
    assert [r["ruleId"] for r in sarif["runs"][0]["results"]] == [
        "nexus_symbiote/credential_exposure/high"
    ]
    view = build_view(bom, max_nodes=10)
    (node,) = (node for node in view.nodes if node.type is ComponentType.CREDENTIAL)
    assert node.findings.highest is RiskSeverity.HIGH
    assert any(path.nodes[-1] == node.index for path in view.paths)
    # A collector's own finding stands in for it; no value in the checkout, no finding.
    assert len(_exposure_findings(_inventory(exposed=True))) == 1
    assert _exposure_findings(_inventory()) == []


def _without_the_credential() -> AIBOM:
    bom = _inventory()
    bom.components = [c for c in bom.components if c.bom_ref != "credential:OPENAI_API_KEY"]
    bom.dependencies = [d for d in bom.dependencies if d.relationship != "acts-as-identity"]
    return bom


@pytest.mark.parametrize("supplied_risk", [True, False])
def test_an_added_credential_with_a_value_in_the_checkout_is_a_high_drift_alert(
    supplied_risk: bool,
) -> None:
    report = AIBOMDiffer().diff(
        _without_the_credential(), _inventory(exposed=True, supplied_risk=supplied_risk)
    )
    (added,) = (c for c in report.components_added if c.bom_ref == "credential:OPENAI_API_KEY")
    assert added.severity == "high"
    quiet = AIBOMDiffer().diff(_without_the_credential(), _inventory())
    (plain,) = (c for c in quiet.components_added if c.bom_ref == "credential:OPENAI_API_KEY")
    assert plain.severity == "medium"


def test_a_new_identity_an_agent_acts_as_is_a_drift_alert() -> None:
    before = _inventory()
    before.components = [c for c in before.components if c.bom_ref != "credential:OPENAI_API_KEY"]
    before.dependencies = [d for d in before.dependencies if d.relationship != "acts-as-identity"]
    result = AIBOMDiffer().diff(before, _inventory())
    assert any("credential:OPENAI_API_KEY" in str(alert) for alert in result.security_alerts)


@pytest.mark.parametrize("supplied_risk", [True, False])
def test_a_value_newly_committed_for_a_credential_is_a_high_drift_alert(
    supplied_risk: bool,
) -> None:
    exposed = _inventory(exposed=True, supplied_risk=supplied_risk)
    report = AIBOMDiffer().diff(_inventory(), exposed)
    (change,) = report.components_modified
    assert change.bom_ref == "credential:OPENAI_API_KEY"
    assert change.severity == "high"
    assert any("now committed in the checkout" in d for d in change.details)
    # The reverse, a value removed, is an improvement and is not rated high for it.
    reverse = AIBOMDiffer().diff(_inventory(exposed=True), _inventory())
    assert not any("now committed" in d for c in reverse.components_modified for d in c.details)


def _validated_with(tmp_path: Path, credential: CredentialComponent) -> Any:
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.\n")
    target = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(target)]
    )
    assert scanned.exit_code == 0, scanned.output
    document = json.loads(target.read_text())
    document["components"].append(credential.model_dump(mode="json", exclude_none=True))
    target.write_text(json.dumps(document))
    return CliRunner().invoke(
        main, ["validate", str(target), "--project", str(project), "--no-project-policy"]
    )


def test_reconciliation_vouches_for_no_credential_that_no_collector_records(tmp_path: Path) -> None:
    validated = _validated_with(
        tmp_path, CredentialComponent(bom_ref="credential:STRIPE_KEY", name="STRIPE_KEY")
    )
    assert validated.exit_code != 0
    assert "credential:STRIPE_KEY" in validated.output


_RUNTIME = {"presence": ClaimEvidence(method="observed", scope="runtime")}


@pytest.mark.parametrize("in_checkout", [True, False])
def test_a_checkout_fact_needs_local_evidence_whatever_else_is_claimed(
    tmp_path: Path, in_checkout: bool
) -> None:
    credential = CredentialComponent(
        bom_ref="credential:STRIPE_KEY",
        name="STRIPE_KEY",
        value_in_checkout=in_checkout,
        claims=_RUNTIME,
    )
    validated = _validated_with(tmp_path, credential)
    assert validated.exit_code != 0
    assert "no matching local evidence: credential:STRIPE_KEY" in validated.output


def test_a_runtime_observed_credential_with_no_checkout_fact_is_a_supplier_claim(
    tmp_path: Path,
) -> None:
    credential = CredentialComponent(
        bom_ref="credential:STRIPE_KEY", name="STRIPE_KEY", claims=_RUNTIME
    )
    validated = _validated_with(tmp_path, credential)
    assert validated.exit_code == 0, validated.output
    assert "supplementary observation" in validated.output


class _CredentialCollector(Scanner):
    """Stands in for ``rag``: the credential that ``app.py`` reads, as a collector records it."""

    name = "rag"
    value_in_checkout: bool | None = None

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        if (project_root / "app.py").is_file():
            known = type(self).value_in_checkout
            # A collector that cannot tell leaves the field unset rather than null.
            fact = {} if known is None else {"value_in_checkout": known}
            result.components.append(
                CredentialComponent(
                    bom_ref="credential:STRIPE_KEY",
                    name="STRIPE_KEY",
                    credential_kind="environment-variable",
                    source_path="app.py",
                    **fact,
                )
            )
            result.surfaces_scanned.append("app.py")
        return result


@pytest.fixture
def credential_collector(monkeypatch: pytest.MonkeyPatch) -> Iterator[type[_CredentialCollector]]:
    registry = cli.SCANNER_REGISTRY
    registry.clear()
    cli._get_scanners()
    saved = dict(registry)
    registry["rag"] = _CredentialCollector
    monkeypatch.setattr(
        scanners_module,
        "ALL_SCANNERS",
        [_CredentialCollector if s is RAGScanner else s for s in scanners_module.ALL_SCANNERS],
    )
    yield _CredentialCollector
    registry.clear()
    registry.update(saved)


@pytest.mark.parametrize(
    ("collected", "supplied", "reconciles"),
    [
        (None, None, True),
        (None, True, False),
        (None, False, False),
        (False, False, True),
        (False, True, False),
        (True, True, True),
        (True, False, False),
    ],
)
def test_a_matched_credential_s_checkout_fact_is_the_collector_s(
    tmp_path: Path,
    credential_collector: type[_CredentialCollector],
    monkeypatch: pytest.MonkeyPatch,
    collected: bool | None,
    supplied: bool | None,
    reconciles: bool,
) -> None:
    monkeypatch.setattr(credential_collector, "value_in_checkout", collected)
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("import os\nos.environ['STRIPE_KEY']\n")
    target = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(target)]
    )
    assert scanned.exit_code == 0, scanned.output
    document = json.loads(target.read_text())
    credential = _credential(document)
    if supplied is None:
        credential.pop("value_in_checkout", None)
    else:
        credential["value_in_checkout"] = supplied
    target.write_text(json.dumps(document))
    validated = CliRunner().invoke(
        main, ["validate", str(target), "--project", str(project), "--no-project-policy"]
    )
    mismatch = "mismatched local component from credential: credential:STRIPE_KEY"
    assert (mismatch not in validated.output) is reconciles, validated.output
    # Reconciliation decides; the integrity check is unknown here, with no digest to verify.
    basis = "project-reconciled" if reconciles else "project-reconciliation-failed"
    assert f"Basis: {basis}\n" in validated.output, validated.output
    assert "SUPPLIER-CLAIM [credential:STRIPE_KEY]" not in validated.output
