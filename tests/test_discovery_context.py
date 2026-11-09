"""Signed discovery context is checked against independent operator expectations."""

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.utils.crypto import VerificationResult
from tests.test_discovery_signature_gate import GATED, IDENTITY, ISSUER, _project

REVISION = "a" * 40


def _setup(tmp_path, monkeypatch):
    project, bom = _project(tmp_path, GATED)
    report = project / ".shadowscan/report.json"
    statement_path = project / ".shadowscan/statement.json"
    (project / ".shadowscan/statement.sigstore.json").write_text("{}")
    statement = {
        "version": 1,
        "report_sha256": "sha256:" + hashlib.sha256(report.read_bytes()).hexdigest(),
        "repository": "example/agent",
        "revision": REVISION,
        "scope": "code:repository",
        "producer_version": "0.1.4",
        "produced_at": (datetime.now(UTC) - timedelta(seconds=1))
        .isoformat()
        .replace("+00:00", "Z"),
    }
    statement_path.write_text(json.dumps(statement))
    policy = {
        "version": 1,
        "artifacts": [
            {
                "artifact_path": ".shadowscan/report.json",
                "bundle_path": ".shadowscan/report.sigstore.json",
                "expected_identity": IDENTITY,
                "expected_issuer": ISSUER,
                "discovery_context": {
                    "statement_path": ".shadowscan/statement.json",
                    "bundle_path": ".shadowscan/statement.sigstore.json",
                    "repository": "example/agent",
                    "revision": REVISION,
                    "scope": "code:repository",
                    "producer_version": "0.1.4",
                    "max_age_seconds": 3600,
                },
            }
        ],
    }
    policy_path = tmp_path / "policy.json"
    policy_path.write_text(json.dumps(policy))

    def verify(artifact, bundle, identity, issuer):
        digest = "sha256:" + hashlib.sha256(Path(artifact).read_bytes()).hexdigest()
        return VerificationResult(True, identity, issuer, details={"artifact_digest": digest})

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_bundle", verify)
    return project, bom, statement_path, statement, policy_path, policy


def _validate(project, bom, policy_path):
    return CliRunner().invoke(
        main,
        ["validate", str(bom), "--project", str(project), "--signature-policy", str(policy_path)],
    )


def test_current_statement_passes_validate_and_risk(tmp_path, monkeypatch):
    project, bom, _, _, path, _ = _setup(tmp_path, monkeypatch)
    result = _validate(project, bom, path)
    assert result.exit_code == 0, result.output
    risk = CliRunner().invoke(
        main,
        [
            "risk",
            str(bom),
            "--project",
            str(project),
            "--signature-policy",
            str(path),
            "--json-output",
        ],
    )
    assert risk.exit_code == 0, risk.output


@pytest.mark.parametrize(
    "field,value",
    [
        ("repository", "other/agent"),
        ("revision", "b" * 40),
        ("scope", "identity"),
        ("producer_version", "0.2.0"),
        ("report_sha256", "sha256:" + "0" * 64),
        ("produced_at", "2000-01-01T00:00:00Z"),
        ("produced_at", "2999-01-01T00:00:00Z"),
        ("produced_at", "invalid"),
        ("version", 2),
    ],
)
def test_signed_old_or_wrong_statement_fails(tmp_path, monkeypatch, field, value):
    project, bom, statement_path, statement, path, _ = _setup(tmp_path, monkeypatch)
    statement[field] = value
    statement_path.write_text(json.dumps(statement))
    result = _validate(project, bom, path)
    assert result.exit_code != 0, result.output


def test_statement_signature_cannot_be_downgraded(tmp_path, monkeypatch):
    project, bom, _, _, path, _ = _setup(tmp_path, monkeypatch)
    original = __import__(
        "nexus_symbiote.utils.crypto", fromlist=["verify_sigstore_bundle"]
    ).verify_sigstore_bundle

    def verify(artifact, *args):
        if Path(artifact).name == "statement.json":
            return VerificationResult(False, error="invalid signature")
        return original(artifact, *args)

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_bundle", verify)
    result = _validate(project, bom, path)
    assert result.exit_code == 1
    assert "Discovery statement signature or signer policy verification failed" in result.output


@pytest.mark.parametrize("edit", ["missing", "extra", "weak_revision", "bad_age"])
def test_operator_context_is_strict_and_cannot_be_partially_configured(tmp_path, monkeypatch, edit):
    project, bom, _, _, path, policy = _setup(tmp_path, monkeypatch)
    context = policy["artifacts"][0]["discovery_context"]
    if edit == "missing":
        del context["scope"]
    elif edit == "extra":
        context["unexpected"] = True
    elif edit == "weak_revision":
        context["revision"] = "main"
    else:
        context["max_age_seconds"] = True
    path.write_text(json.dumps(policy))
    assert _validate(project, bom, path).exit_code != 0


def test_context_requires_discovery_evidence_in_the_bom(tmp_path, monkeypatch):
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.signature_policy import load_signature_policies
    from nexus_symbiote.validators.completeness import discovery_producer_problems

    project, _, _, _, path, _ = _setup(tmp_path, monkeypatch)
    policies = load_signature_policies(path, project)
    assert discovery_producer_problems(AIBOM(), project, policies) == [
        "Required ShadowScan discovery evidence is absent from the BOM."
    ]


def test_context_cannot_be_attached_to_an_unrelated_file(tmp_path, monkeypatch):
    project, bom, _, _, path, policy = _setup(tmp_path, monkeypatch)
    policy["artifacts"][0]["artifact_path"] = ".mcp.json"
    path.write_text(json.dumps(policy))
    result = _validate(project, bom, path)
    assert result.exit_code != 0
    assert "Discovery context must name the report" in result.output


def test_statement_duplicate_json_keys_fail_closed(tmp_path, monkeypatch):
    project, bom, statement_path, _, path, _ = _setup(tmp_path, monkeypatch)
    statement_path.write_text('{"version":1,"version":1}')
    assert _validate(project, bom, path).exit_code != 0


def test_statement_signature_must_cover_the_inspected_bytes(tmp_path, monkeypatch):
    project, bom, _, _, path, _ = _setup(tmp_path, monkeypatch)
    original = __import__(
        "nexus_symbiote.utils.crypto", fromlist=["verify_sigstore_bundle"]
    ).verify_sigstore_bundle

    def verify(artifact, *args):
        if Path(artifact).name == "statement.json":
            return VerificationResult(
                True, IDENTITY, ISSUER, details={"artifact_digest": "sha256:" + "0" * 64}
            )
        return original(artifact, *args)

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_bundle", verify)
    result = _validate(project, bom, path)
    assert result.exit_code == 1
    assert "Discovery statement signature or signer policy verification failed" in result.output


def test_cli_validate_and_risk_reject_removed_discovery_when_completeness_off(
    tmp_path, monkeypatch
):
    project, bom, _, _, path, _ = _setup(tmp_path, monkeypatch)
    (project / ".nexus-symbiote.yaml").write_text(
        "validate: {require_completeness: false, require_integrity: false}\n"
    )
    doc = json.loads(bom.read_text())
    doc["components"] = [c for c in doc["components"] if not c["bom_ref"].startswith("shadowscan:")]
    doc["dependencies"] = [
        edge
        for edge in doc["dependencies"]
        if not edge["source_ref"].startswith("shadowscan:")
        and not edge["target_ref"].startswith("shadowscan:")
    ]
    doc["metadata"]["completeness"].update(
        scope="repository",
        source_report_format=None,
        source_report_status=None,
        source_report_digest=None,
        source_report_content_digest=None,
        source_report_content_profile=None,
    )
    bom.write_text(json.dumps(doc))
    result = _validate(project, bom, path)
    assert result.exit_code == 1, result.output
    assert "Required ShadowScan discovery evidence is absent" in result.output
    risk = CliRunner().invoke(
        main,
        [
            "risk",
            str(bom),
            "--project",
            str(project),
            "--signature-policy",
            str(path),
            "--json-output",
        ],
    )
    assert risk.exit_code == 1, risk.output
    assert any(
        "Required ShadowScan discovery evidence is absent" in reason
        for reason in json.loads(risk.stdout)["gate_reasons"]
    )
