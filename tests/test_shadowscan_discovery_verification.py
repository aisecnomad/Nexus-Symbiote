"""SEC-F1: imported ShadowScan evidence records its verification outcome.

An unsigned import records ``unverified`` in the BOM with the report digest
and the repo/commit/time binding the report itself carries; a signed import
(with --bundle) records ``verified`` with the signer identity and issuer.
Unsigned evidence warns loudly everywhere and fails in CI (or with
--fail-on-unsigned-discovery) unless explicitly accepted with
--allow-unsigned-discovery.
"""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import DiscoveryVerification
from nexus_symbiote.scanners.shadowscan import (
    ShadowScanImporter,
    verify_discovery_report,
)
from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, VerificationResult

FIXTURES = Path(__file__).parent / "fixtures"
REPORT = FIXTURES / "shadowscan/code-report-0.1.4.json"
CYCLONEDX = FIXTURES / "shadowscan-producer/cyclonedx-agent-model.json"
IDENTITY = "https://github.com/acme/discovery/.github/workflows/scan.yml@refs/heads/main"
ISSUER = "https://token.actions.githubusercontent.com"
# A project policy under which validate otherwise passes, so the unsigned gate
# is the only thing that can fail it.
LENIENT = "validate: {require_integrity: false}\n"

MINIMAL = {
    "version": "0.1.4",
    "started_at": "2026-01-01T00:00:00Z",
    "finished_at": "2026-01-01T00:00:01Z",
    "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
    "stats": [
        {
            "connector": "code.filesystem",
            "started_at": "2026-01-01T00:00:00Z",
            "finished_at": "2026-01-01T00:00:01Z",
            "errors": [],
            "skipped": False,
            "incomplete": False,
        }
    ],
    "findings": [
        {
            "id": "ss-1",
            "kind": "agent",
            "surface": "code",
            "confidence": 0.5,
            "first_seen": None,
            "last_seen": "2026-01-01T00:00:01Z",
        }
    ],
}


def _project(tmp_path: Path, *, with_report: bool = True) -> tuple[Path, Path]:
    """A scanned project whose validate otherwise passes (cf. signature-gate tests)."""
    project, bom = tmp_path / "proj", tmp_path / "bom.json"
    (project / ".shadowscan").mkdir(parents=True)
    if with_report:
        shutil.copy(REPORT, project / ".shadowscan/report.json")
    server = {"command": "npx", "args": ["-y", "@acme/payments-mcp@1.2.3"]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"payments": server}}))
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(bom)])
    assert result.exit_code == 0, result.output
    (project / ".nexus-symbiote.yaml").write_text(LENIENT)
    return project, bom


def _claim(bom_path: Path) -> dict:
    return json.loads(bom_path.read_text())["metadata"]["completeness"]


def _verification(bom_path: Path) -> dict:
    return _claim(bom_path)["discovery_verification"]


def _verifier(monkeypatch, **overrides):
    # Accepts the trust-root kwargs SEC-C1 added to verify_sigstore_digest;
    # this fake stands in for the verifier itself, not the trust-root
    # plumbing (covered by tests/test_crypto_trust_root.py).
    def verify(digest_hex, bundle_json, identity, issuer, **kwargs):
        return VerificationResult(
            True,
            identity=identity,
            issuer=issuer,
            details={"artifact_digest": digest_hex},
            **overrides,
        )

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_digest", verify)


def _clear_ci(monkeypatch) -> None:
    for name in (
        "CI",
        "GITHUB_ACTIONS",
        "GITLAB_CI",
        "CIRCLECI",
        "TF_BUILD",
        "JENKINS_URL",
        "BUILDKITE",
        "DRONE",
        "TRAVIS",
    ):
        monkeypatch.delenv(name, raising=False)


def test_unsigned_import_records_unverified_with_digest_and_binding(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["import-shadowscan", str(REPORT), "-o", str(out), "--report-only"]
    )
    assert result.exit_code == 0, result.output
    record = _verification(out)
    assert record["status"] == "unverified"
    assert record["method"] == "none"
    assert record["report_digest"] == (
        "sha256:09ee8e976318815bf9beaac994af0457d8c75574a0122610223bbe0cbc16ad48"
    )
    assert record["report_content_digest"] == (
        "sha256:eec0919b1ee517aaf6a267b578145f775a79735796bda48e65615900d44e9532"
    )
    assert record.get("signer_identity") is None
    assert record.get("issuer") is None
    # The current report format carries no repository or commit: both stay
    # unknown rather than fabricated. Its own run time binds the report.
    assert record["repository"] == "unknown"
    assert record["commit"] == "unknown"
    assert record["report_time"] == "2026-11-02T00:09:37+00:00"
    assert _claim(out)["source_report_path"] == REPORT.name


def test_report_binding_uses_fields_the_report_carries():
    data = json.loads(json.dumps(MINIMAL))
    data["repository"] = "https://example.test/acme/repo"
    data["commit"] = "0123456789abcdef0123456789abcdef01234567"
    imported = ShadowScanImporter().parse_report(json.dumps(data))
    record = imported.discovery_verification
    assert record is not None
    assert record.repository == "https://example.test/acme/repo"
    assert record.commit == "0123456789abcdef0123456789abcdef01234567"
    assert record.report_time == "2026-01-01T00:00:01Z"


def test_cyclonedx_binding_uses_metadata_timestamp():
    imported = ShadowScanImporter().parse_report(CYCLONEDX.read_bytes())
    record = imported.discovery_verification
    assert record is not None
    assert record.status == "unverified"
    assert record.report_time == "2026-01-01T00:00:00Z"
    assert record.repository == "unknown"
    assert record.commit == "unknown"


def test_scan_records_verification_and_not_applicable_without_a_report(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    project, bom = _project(tmp_path)
    record = _verification(bom)
    assert record["status"] == "unverified"
    assert record["report_digest"] == _claim(bom)["source_report_digest"]
    assert _claim(bom)["source_report_path"] == ".shadowscan/report.json"

    plain_project, plain_bom = _project(tmp_path / "plain", with_report=False)
    assert _verification(plain_bom)["status"] == "not-applicable"
    assert _verification(plain_bom).get("report_digest") is None


def test_unsigned_import_warns_but_passes_interactively(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main, ["import-shadowscan", str(REPORT), "-o", str(out), "--report-only"]
    )
    assert result.exit_code == 0, result.output
    assert "UNVERIFIED" in result.output
    assert "sha256:09ee8e976318815bf9beaac994af0457d8c75574a0122610223bbe0cbc16ad48" in (
        result.output
    )


def test_fail_on_unsigned_discovery_flag_fails_interactively(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        [
            "import-shadowscan",
            str(REPORT),
            "-o",
            str(out),
            "--report-only",
            "--fail-on-unsigned-discovery",
        ],
    )
    assert result.exit_code == 1
    assert "UNVERIFIED" in result.output


def test_unsigned_import_fails_in_ci_unless_explicitly_allowed(tmp_path, monkeypatch):
    out = tmp_path / "bom.json"
    monkeypatch.setenv("CI", "true")
    result = CliRunner().invoke(
        main, ["import-shadowscan", str(REPORT), "-o", str(out), "--report-only"]
    )
    assert result.exit_code == 1
    assert "UNVERIFIED" in result.output
    assert "--allow-unsigned-discovery" in result.output
    allowed = CliRunner().invoke(
        main,
        [
            "import-shadowscan",
            str(REPORT),
            "-o",
            str(tmp_path / "allowed.json"),
            "--report-only",
            "--allow-unsigned-discovery",
        ],
    )
    assert allowed.exit_code == 0, allowed.output
    assert "UNVERIFIED" in allowed.output


def test_validate_warns_interactively_and_fails_in_ci(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    project, bom = _project(tmp_path)
    interactive = CliRunner().invoke(
        main,
        ["validate", str(bom), "--project", str(project), "--accept-project-policy"],
    )
    assert interactive.exit_code == 0, interactive.output
    assert "UNVERIFIED" in interactive.output

    monkeypatch.setenv("CI", "true")
    # Without --accept-project-policy the lenient file is not applied, so the
    # built-in integrity gate fails and the warning names the flag.
    refused = CliRunner().invoke(main, ["validate", str(bom), "--project", str(project)])
    assert refused.exit_code == 1
    assert "--accept-project-policy" in refused.output
    assert "looks like CI" not in refused.output
    accept = ["--project", str(project), "--accept-project-policy"]
    ci = CliRunner().invoke(main, ["validate", str(bom), *accept])
    assert ci.exit_code == 1
    assert "UNVERIFIED" in ci.output

    flagged = CliRunner().invoke(
        main, ["validate", str(bom), *accept, "--fail-on-unsigned-discovery"]
    )
    assert flagged.exit_code == 1

    _clear_ci(monkeypatch)
    allowed = CliRunner().invoke(
        main,
        [
            "validate",
            str(bom),
            "--project",
            str(project),
            "--accept-project-policy",
            "--allow-unsigned-discovery",
        ],
    )
    assert allowed.exit_code == 0, allowed.output
    assert "UNVERIFIED" in allowed.output


def test_risk_reports_unsigned_evidence_as_unknown_in_ci(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    _, bom = _project(tmp_path)
    interactive = CliRunner().invoke(
        main, ["risk", str(bom), "--threshold", "100", "--json-output"]
    )
    assert interactive.exit_code == 0, interactive.output
    assert "UNVERIFIED" in interactive.output

    monkeypatch.setenv("CI", "true")
    ci = CliRunner().invoke(main, ["risk", str(bom), "--threshold", "100", "--json-output"])
    assert ci.exit_code == 1
    body = json.loads(ci.stdout)
    assert body["assessment_basis"] == "unsigned-discovery-evidence"
    assert body["overall_score"] is None
    assert body["gate_reasons"] == [
        "Unsigned ShadowScan discovery evidence in CI; pass "
        "--allow-unsigned-discovery to accept it explicitly."
    ]


def test_signed_import_records_verified_identity_and_issuer(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    _verifier(monkeypatch)
    bundle = tmp_path / "report.sigstore"
    bundle.write_text("{}")
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        [
            "import-shadowscan",
            str(REPORT),
            "-o",
            str(out),
            "--report-only",
            "--bundle",
            str(bundle),
            "--signer-identity",
            IDENTITY,
            "--issuer",
            ISSUER,
        ],
    )
    assert result.exit_code == 0, result.output
    assert "UNVERIFIED" not in result.output
    record = _verification(out)
    assert record["status"] == "verified"
    assert record["method"] == "sigstore"
    assert record["signer_identity"] == IDENTITY
    assert record["issuer"] == ISSUER
    assert record["report_digest"] == (
        "sha256:09ee8e976318815bf9beaac994af0457d8c75574a0122610223bbe0cbc16ad48"
    )

    # The recorded outcome is unsigned text in the BOM, so a later run does not
    # trust it: without a producer check in that run, CI still fails closed.
    monkeypatch.setenv("CI", "true")
    scored = CliRunner().invoke(main, ["risk", str(out), "--threshold", "100", "--json-output"])
    assert scored.exit_code == 1, scored.output
    assert json.loads(scored.stdout)["assessment_basis"] == "unsigned-discovery-evidence"
    accepted = CliRunner().invoke(
        main,
        ["risk", str(out), "--threshold", "100", "--json-output", "--allow-unsigned-discovery"],
    )
    assert json.loads(accepted.stdout)["assessment_basis"] == "supplied-bom"


@pytest.mark.parametrize("status", ["verified", "not-applicable"])
@pytest.mark.parametrize("command", ["risk", "validate"])
def test_a_recorded_outcome_the_bom_declares_about_itself_does_not_pass(
    tmp_path, monkeypatch, status, command
):
    _clear_ci(monkeypatch)
    out = tmp_path / "bom.json"
    imported = CliRunner().invoke(
        main, ["import-shadowscan", str(REPORT), "-o", str(out), "--report-only"]
    )
    assert imported.exit_code == 0, imported.output
    document = json.loads(out.read_text())
    record = document["metadata"]["completeness"]["discovery_verification"]
    record.update(status=status, method="sigstore", signer_identity="attacker", issuer="attacker")
    out.write_text(json.dumps(document))
    monkeypatch.setenv("CI", "true")
    result = CliRunner().invoke(main, [command, str(out), "--json-output"])
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    assert report["passed"] is False
    reason = report["unsigned_discovery"] if command == "validate" else report["gate_reasons"][0]
    assert "Unsigned ShadowScan discovery evidence" in reason


def test_unsigned_risk_failure_has_the_scored_report_keys(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    out = tmp_path / "bom.json"
    CliRunner().invoke(main, ["import-shadowscan", str(REPORT), "-o", str(out), "--report-only"])
    accepted = CliRunner().invoke(
        main, ["risk", str(out), "--json-output", "--allow-unsigned-discovery"]
    )
    monkeypatch.setenv("CI", "true")
    refused = CliRunner().invoke(main, ["risk", str(out), "--json-output"])
    assert refused.exit_code == 1
    assert set(json.loads(refused.stdout)) == set(json.loads(accepted.stdout))


def test_contradictory_unsigned_discovery_flags_are_a_usage_error(tmp_path):
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        [
            "import-shadowscan",
            str(REPORT),
            "-o",
            str(out),
            "--fail-on-unsigned-discovery",
            "--allow-unsigned-discovery",
        ],
    )
    assert result.exit_code == 2 and not out.exists()


def test_signed_import_projection_still_verifies(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    _verifier(monkeypatch)
    bundle = tmp_path / "report.sigstore"
    bundle.write_text("{}")
    out = tmp_path / "bom.json"
    CliRunner().invoke(
        main,
        [
            "import-shadowscan",
            str(REPORT),
            "-o",
            str(out),
            "--report-only",
            "--bundle",
            str(bundle),
            "--signer-identity",
            IDENTITY,
            "--issuer",
            ISSUER,
        ],
    )
    checked = CliRunner().invoke(
        main,
        [
            "verify-discovery",
            str(out),
            str(REPORT),
            "--bundle",
            str(bundle),
            "--signer-identity",
            IDENTITY,
            "--issuer",
            ISSUER,
        ],
    )
    assert checked.exit_code == 0, checked.output
    assert "Report signer and direct native projection verified." in checked.output


def test_signed_import_with_a_failing_bundle_is_refused(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)

    def failing(digest_hex, bundle_json, identity, issuer):
        return VerificationResult(False, error="Sigstore artifact verification failed")

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_digest", failing)
    bundle = tmp_path / "report.sigstore"
    bundle.write_text("{}")
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        [
            "import-shadowscan",
            str(REPORT),
            "-o",
            str(out),
            "--report-only",
            "--bundle",
            str(bundle),
            "--signer-identity",
            IDENTITY,
            "--issuer",
            ISSUER,
        ],
    )
    assert result.exit_code == 1
    assert "signature or signer policy verification failed" in result.output
    assert not out.is_file()


def test_missing_sigstore_extra_fails_with_its_install_hint(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)

    def missing(digest_hex, bundle_json, identity, issuer):
        return VerificationResult(False, error=SIGSTORE_MISSING)

    monkeypatch.setattr("nexus_symbiote.utils.crypto.verify_sigstore_digest", missing)
    bundle = tmp_path / "report.sigstore"
    bundle.write_text("{}")
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        [
            "import-shadowscan",
            str(REPORT),
            "-o",
            str(out),
            "--report-only",
            "--bundle",
            str(bundle),
            "--signer-identity",
            IDENTITY,
            "--issuer",
            ISSUER,
        ],
    )
    assert result.exit_code == 1
    assert SIGSTORE_MISSING in result.output


def test_bundle_options_must_be_supplied_together(tmp_path):
    bundle = tmp_path / "report.sigstore"
    bundle.write_text("{}")
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        ["import-shadowscan", str(REPORT), "-o", str(out), "--bundle", str(bundle)],
    )
    assert result.exit_code == 2
    assert "--bundle, --signer-identity and --issuer must be supplied together" in result.output


def test_a_bom_claiming_verified_fails_projection_without_a_bundle(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    out = tmp_path / "bom.json"
    CliRunner().invoke(main, ["import-shadowscan", str(REPORT), "-o", str(out), "--report-only"])
    doc = json.loads(out.read_text())
    doc["metadata"]["completeness"]["discovery_verification"]["status"] = "verified"
    doc["metadata"]["completeness"]["discovery_verification"]["method"] = "sigstore"
    doc["metadata"]["completeness"]["discovery_verification"]["signer_identity"] = IDENTITY
    doc["metadata"]["completeness"]["discovery_verification"]["issuer"] = ISSUER
    out.write_text(json.dumps(doc))
    result = CliRunner().invoke(main, ["verify-discovery", str(out), str(REPORT), "--projection"])
    assert result.exit_code != 0
    assert "BOM does not match the direct native ShadowScan projection" in result.output


def test_verification_for_another_digest_is_rejected():
    imported = ShadowScanImporter().parse_report(json.dumps(MINIMAL))
    with pytest.raises(ValueError, match="different report digest"):
        imported.with_verification(
            DiscoveryVerification(
                status="verified",
                method="sigstore",
                report_digest="sha256:" + "c" * 64,
                signer_identity=IDENTITY,
                issuer=ISSUER,
            )
        )
    with pytest.raises(ValueError, match="no report digest"):
        verify_discovery_report(DiscoveryVerification(), b"{}", IDENTITY, ISSUER)


@pytest.mark.parametrize(
    "hostile",
    ["https://example.test/a\x9bb", "repo\u2028name", "acme\u202erepo.example"],
)
def test_bindings_with_disguising_characters_stay_unknown(hostile):
    data = json.loads(json.dumps(MINIMAL))
    data["repository"] = hostile
    record = ShadowScanImporter().parse_report(json.dumps(data)).discovery_verification
    assert record is not None
    assert record.repository == "unknown"


def _scan_check(project: Path, *args: str, env: dict[str, str] | None = None):
    return CliRunner().invoke(main, ["scan", str(project), "--check", *args], env=env or {})


def test_scan_report_only_does_not_relax_the_unsigned_discovery_gate(tmp_path, monkeypatch):
    # Audit 2026-11-16 S10-01: report-only relaxes collection and findings, never
    # the separate discovery-verification gate.
    _clear_ci(monkeypatch)
    project, _ = _project(tmp_path)
    in_ci = _scan_check(project, "--no-project-policy", "--report-only", env={"CI": "true"})
    assert in_ci.exit_code == 1, in_ci.output
    assert "report only: exit status 0" not in in_ci.output
    assert "UNVERIFIED" in in_ci.output
    allowed = _scan_check(
        project,
        "--no-project-policy",
        "--report-only",
        "--allow-unsigned-discovery",
        env={"CI": "true"},
    )
    assert allowed.exit_code == 0, allowed.output
    explicit = _scan_check(
        project, "--no-project-policy", "--report-only", "--fail-on-unsigned-discovery"
    )
    assert explicit.exit_code == 1, explicit.output
    interactive = _scan_check(project, "--no-project-policy", "--report-only")
    assert interactive.exit_code == 0, interactive.output


def test_project_report_only_policy_cannot_cancel_fail_on_unsigned_discovery(tmp_path, monkeypatch):
    # Audit 2026-11-16 S10-V02: the scanned checkout chooses report-only and the
    # operator asks for verified discovery outside detected CI.
    _clear_ci(monkeypatch)
    project, _ = _project(tmp_path)
    (project / ".nexus-symbiote.yaml").write_text(LENIENT + "scan: {failure_mode: report-only}\n")
    result = _scan_check(project, "--accept-project-policy", "--fail-on-unsigned-discovery")
    assert result.exit_code == 1, result.output
    assert "report only: exit status 0" not in result.output


def test_scan_report_only_does_not_relax_a_failed_producer_check(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    project, _ = _project(tmp_path)
    (project / ".nexus-symbiote.yaml").write_text(
        "validate: {require_integrity: false, require_discovery_signature: true}\n"
    )
    result = _scan_check(project, "--accept-project-policy", "--report-only")
    assert result.exit_code == 1, result.output
    assert "report only: exit status 0" not in result.output


def test_scan_gate_output_says_report_only_does_not_cover_discovery(tmp_path, monkeypatch):
    _clear_ci(monkeypatch)
    project, _ = _project(tmp_path)
    blocked = _scan_check(project, "--no-project-policy", "--report-only", env={"CI": "true"})
    assert blocked.exit_code == 1, blocked.output
    assert (
        "Scan gate failed (report-only does not cover unverified discovery evidence)"
        in blocked.output
    )
    reasons = [line for line in blocked.output.splitlines() if "Unsigned ShadowScan" in line]
    assert reasons
    assert all(line.startswith("  - discovery verification: ") for line in reasons)
    plain = _scan_check(project, "--no-project-policy", env={"CI": "true"})
    assert plain.exit_code == 1, plain.output
    assert "report-only does not cover" not in plain.output
    assert any(
        line.startswith("  - discovery verification: Unsigned ShadowScan")
        for line in plain.output.splitlines()
    )
    relaxed = _scan_check(project, "--no-project-policy", "--report-only")
    assert relaxed.exit_code == 0, relaxed.output
    assert "discovery verification:" not in relaxed.output
    assert "report-only does not cover" not in relaxed.output
