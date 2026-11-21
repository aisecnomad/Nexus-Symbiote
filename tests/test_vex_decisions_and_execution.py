"""Tests for execution-bound VEX, operator VEX decisions with expiry, and advisory linkage (Item 23 & N5)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.attestation import build_statement, sign_statement
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import RegistryEntryComponent, RiskAssessment, ToolComponent
from nexus_symbiote.generators.vex import VEXGenerator, finding_id
from nexus_symbiote.vex_decisions import (
    LoadedVEXDecisions,
    VEXDecisionEntry,
    VEXDecisionError,
    load_advisory_report,
    load_execution_evidence,
    load_vex_decisions,
)


def _three_component_bom() -> AIBOM:
    risk = RiskAssessment(
        severity=RiskSeverity.HIGH,
        category="unpinned_tool",
        detail="Tool definition is unpinned",
        recommendation="Pin the tool definition digest.",
    )
    return AIBOM(
        components=[
            ToolComponent(bom_ref="tool:never-loaded", name="never_loaded", risks=[risk]),
            ToolComponent(bom_ref="tool:invoked", name="invoked_tool", risks=[risk]),
            ToolComponent(bom_ref="tool:shadowed", name="shadowed_tool", risks=[risk]),
        ]
    )


def _sign_trace_file(trace_path: Path, att_path: Path, pub_path: Path) -> None:
    private = Ed25519PrivateKey.generate()
    pub_bytes = private.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    pub_path.write_bytes(pub_bytes)
    statement = build_statement(
        trace_path.read_bytes(),
        name=trace_path.name,
        purpose="generated",
        signed_at=datetime.now(UTC).replace(microsecond=0),
    )
    envelope = sign_statement(statement, [private])
    att_path.write_text(
        json.dumps(envelope.model_dump(mode="json", by_alias=True), indent=2) + "\n",
        encoding="utf-8",
    )


def test_execution_bound_vex_yields_distinct_outcomes_and_keeps_unobserved_in_triage(tmp_path):
    """Trace observations retain triage for every outcome."""
    bom = _three_component_bom()
    bom.components.append(
        ToolComponent(
            bom_ref="tool:unobserved",
            name="unobserved_tool",
            risks=[
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="unpinned_tool",
                    detail="Tool definition is unpinned",
                )
            ],
        )
    )
    trace_file = tmp_path / "trace-evidence.json"
    trace_file.write_text(
        json.dumps(
            {
                "reconciliation": {
                    "matched": [{"kind": "tool", "inventory_ref": "tool:invoked"}],
                    "unobserved": [{"kind": "tool", "inventory_ref": "tool:unobserved"}],
                },
                "declared_never_loaded": ["tool:never-loaded"],
                "shadowed": ["tool:shadowed"],
            }
        ),
        encoding="utf-8",
    )
    evidence = load_execution_evidence(trace_file, allow_unsigned=True)
    doc = VEXGenerator(execution_evidence=evidence).generate(bom)

    assert any(
        p["value"] == "unsigned" and p["name"] == "nexus-symbiote:traceAuthentication"
        for p in doc["metadata"]["properties"]
    )
    by_comp = {v["affects"][0]["ref"]: v for v in doc["vulnerabilities"]}
    assert set(by_comp.keys()) == {
        "tool:never-loaded",
        "tool:unobserved",
        "tool:invoked",
        "tool:shadowed",
    }

    # 1. A component absent from these observations stays in triage.
    never = by_comp["tool:never-loaded"]["analysis"]
    assert never["state"] == "in_triage"
    assert "justification" not in never

    # 2. Real trace-diff unobserved -> MUST remain in_triage (absence of spans proves nothing).
    unobs = by_comp["tool:unobserved"]["analysis"]
    assert unobs["state"] == "in_triage"
    assert "justification" not in unobs

    # 3. Real trace-diff matched (inventory_ref) -> in_triage: an invocation of a component
    #    with a heuristic finding is recorded as a property and asserts no exploitability.
    invoked = by_comp["tool:invoked"]["analysis"]
    assert invoked["state"] == "in_triage"
    assert "response" not in invoked
    assert "invoked" in invoked["detail"]
    outcomes = {
        ref: {p["name"]: p["value"] for p in vuln["properties"]}.get(
            "nexus-symbiote:executionOutcome"
        )
        for ref, vuln in by_comp.items()
    }
    assert outcomes == {
        "tool:never-loaded": "declared-never-loaded",
        "tool:unobserved": "unobserved",
        "tool:invoked": "invoked",
        "tool:shadowed": "shadowed",
    }

    # 4. Shadowed -> in_triage + explicit shadowing reason.
    shadowed = by_comp["tool:shadowed"]["analysis"]
    assert shadowed["state"] == "in_triage"
    assert "shadowed" in shadowed["detail"]


def test_trace_evidence_cannot_suppress_hook_commands_critical_or_kev(tmp_path):
    """Critical, hook_commands, and KEV advisories stay in_triage even under declared_never_loaded or unobserved."""
    comp_hook = ToolComponent(
        bom_ref="tool:hooked",
        name="hooked_tool",
        risks=[
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="hook_commands",
                detail="Shell hook executes untrusted command",
            )
        ],
    )
    comp_pkg = RegistryEntryComponent(
        bom_ref="pkg:pypi:transformers@4.35.0",
        name="transformers",
        version="4.35.0",
        registry_type="pypi",
        package_url="pkg:pypi/transformers@4.35.0",
    )
    bom = AIBOM(components=[comp_hook, comp_pkg])
    trace_file = tmp_path / "trace.json"
    trace_file.write_text(
        json.dumps(
            {
                "declared_never_loaded": ["tool:hooked", "pkg:pypi:transformers@4.35.0"],
                "unobserved": ["tool:hooked"],
            }
        ),
        encoding="utf-8",
    )
    evidence = load_execution_evidence(trace_file, allow_unsigned=True)
    advisories = [
        {
            "component_ref": "pkg:pypi:transformers@4.35.0",
            "advisory_id": "CVE-2024-99999",
            "severity": "high",
            "in_kev": True,
            "kev_sources": ["cisa-kev"],
            "offline": True,
        }
    ]
    doc = VEXGenerator(execution_evidence=evidence, advisories=advisories).generate(bom)
    assert len(doc["vulnerabilities"]) == 2
    for vuln in doc["vulnerabilities"]:
        assert vuln["analysis"]["state"] == "in_triage"
        props = {p["name"]: p["value"] for p in vuln["properties"]}
        assert props["nexus-symbiote:suppressionBlocked"] == "true"


def test_operator_vex_decisions_wall_clock_expiry_ignores_stale_bom_and_source_date_epoch(
    tmp_path, monkeypatch
):
    """A stale 2020 inventory timestamp and SOURCE_DATE_EPOCH=2020 must NOT keep a 2021 decision alive."""
    bom = _three_component_bom()
    bom.metadata.timestamp = datetime(2020, 1, 1, 0, 0, tzinfo=UTC)
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "1577836800")  # 2020-01-01T00:00:00Z

    fid = finding_id("tool:invoked", "unpinned_tool", "Tool definition is unpinned")
    decisions_file = tmp_path / "decisions.yaml"
    decisions_file.write_text(
        f"""version: 1
decisions:
  - id: "{fid}"
    component_ref: "tool:invoked"
    state: "not_affected"
    justification: "protected_at_runtime"
    detail: "Expired in 2021"
    owner: "secops@example.com"
    expires_at: "2021-01-01T00:00:00Z"
""",
        encoding="utf-8",
    )
    loaded = load_vex_decisions(decisions_file)
    doc = VEXGenerator(decisions=loaded).generate(bom)
    by_comp = {v["affects"][0]["ref"]: v for v in doc["vulnerabilities"]}
    assert by_comp["tool:invoked"]["analysis"]["state"] == "in_triage"
    assert "Expired operator VEX decision" in by_comp["tool:invoked"]["analysis"]["detail"]


def test_operator_vex_decisions_active_and_duplicate_refused(tmp_path):
    bom = _three_component_bom()
    fid_active = finding_id("tool:never-loaded", "unpinned_tool", "Tool definition is unpinned")
    fid_expired = finding_id("tool:invoked", "unpinned_tool", "Tool definition is unpinned")

    decisions_file = tmp_path / "vex-decisions.yaml"
    decisions_file.write_text(
        f"""version: 1
decisions:
  - id: "{fid_active}"
    component_ref: "tool:never-loaded"
    state: "not_affected"
    justification: "protected_at_runtime"
    detail: "Blocked by gateway policy"
    inventory_sha256: "{hash_bytes(bom.to_native_json().encode())}"
    deployment_id: "prod"
    owner: "secops@example.com"
    expires_at: "2027-01-01T00:00:00Z"
  - id: "{fid_expired}"
    component_ref: "tool:invoked"
    state: "resolved"
    detail: "Previously patched in staging"
    owner: "secops@example.com"
    expires_at: "2026-01-01T00:00:00Z"
""",
        encoding="utf-8",
    )
    loaded = load_vex_decisions(decisions_file)
    ref_time = datetime(2026, 11, 19, 0, 0, tzinfo=UTC)
    generator = VEXGenerator(decisions=loaded, reference_time=ref_time, deployment_id="prod")
    doc = generator.generate(bom)

    by_comp = {v["affects"][0]["ref"]: v for v in doc["vulnerabilities"]}
    assert by_comp["tool:never-loaded"]["analysis"]["state"] == "not_affected"
    assert by_comp["tool:invoked"]["analysis"]["state"] == "in_triage"
    meta_props = {p["name"]: p["value"] for p in doc["metadata"].get("properties", [])}
    assert meta_props["nexus-symbiote:expiredVexDecisions"] == "1"

    ref_changed = VEXGenerator(decisions=loaded, reference_time=ref_time, deployment_id="staging")
    wrong_deployment = ref_changed.generate(bom)
    bom.components[0].hashes["sha256"] = "sha256:" + "a" * 64
    changed_inventory = generator.generate(bom)
    for result in (wrong_deployment, changed_inventory):
        entry = next(v for v in result["vulnerabilities"] if v["id"] == fid_active)
        assert entry["analysis"]["state"] == "in_triage"

    # Conflicting / duplicate (id, component_ref) decisions must be refused.
    dup_file = tmp_path / "dup-decisions.yaml"
    dup_file.write_text(
        f"""version: 1
decisions:
  - id: "{fid_active}"
    component_ref: "tool:never-loaded"
    state: "not_affected"
    detail: "First"
    owner: "a@example.com"
    expires_at: "2027-01-01T00:00:00Z"
  - id: "{fid_active}"
    component_ref: "tool:never-loaded"
    state: "exploitable"
    detail: "Second"
    owner: "b@example.com"
    expires_at: "2027-01-01T00:00:00Z"
""",
        encoding="utf-8",
    )
    with pytest.raises(VEXDecisionError, match="duplicate VEX decision"):
        load_vex_decisions(dup_file)


@pytest.mark.parametrize(
    ("deployment", "state", "status"),
    [
        ("production", "not_affected", "active"),
        ("staging", "in_triage", "scope-mismatch"),
        (None, "in_triage", "scope-mismatch"),
    ],
)
def test_vex_cli_scopes_suppression_to_deployment_and_exact_file_bytes(
    tmp_path, deployment, state, status
):
    project = tmp_path / "project"
    project.mkdir()
    inventory = project / "inventory.json"
    # A valid noncanonical serialization distinguishes the file digest from a reserialization.
    raw = _three_component_bom().to_native_json().encode() + b"\n\n"
    inventory.write_bytes(raw)
    ref = "tool:never-loaded"
    fid = finding_id(ref, "unpinned_tool", "Tool definition is unpinned")
    decision = {
        "id": fid,
        "component_ref": ref,
        "inventory_sha256": hash_bytes(raw),
        "deployment_id": "production",
        "state": "not_affected",
        "justification": "protected_at_runtime",
        "detail": "Production policy blocks this tool",
        "owner": "security",
        "expires_at": "2099-01-01T00:00:00Z",
    }
    decisions = tmp_path / "decisions.yaml"
    decisions.write_text(json.dumps({"version": 1, "decisions": [decision]}), encoding="utf-8")
    args = ["vex", str(inventory), "--decisions", str(decisions), "--project-root", str(project)]
    if deployment is not None:
        args.extend(["--deployment-id", deployment])
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    entry = next(v for v in json.loads(result.output)["vulnerabilities"] if v["id"] == fid)
    assert entry["analysis"]["state"] == state
    assert {"name": "nexus-symbiote:vexDecisionStatus", "value": status} in entry["properties"]


def test_vex_confinement_refuses_in_repo_without_project_root_symlinks_and_hardlinks(
    tmp_path, monkeypatch
):
    repo_dir = tmp_path / "repo"
    (repo_dir / ".git").mkdir(parents=True)
    bom_in_repo = repo_dir / "aibom.json"
    _three_component_bom().save(bom_in_repo)

    dec_in_repo = repo_dir / "decisions.yaml"
    dec_in_repo.write_text("version: 1\ndecisions: []\n", encoding="utf-8")

    # Even WITHOUT --project-root, a decisions file inside the inventory's git repo is refused.
    with pytest.raises(VEXDecisionError, match="outside the scanned project"):
        load_vex_decisions(dec_in_repo, inventory_path=bom_in_repo)

    # Even when inventory is elsewhere, running with cwd inside the repo refuses repo decisions.
    monkeypatch.chdir(repo_dir)
    with pytest.raises(VEXDecisionError, match="outside the scanned project"):
        load_vex_decisions(dec_in_repo)
    monkeypatch.chdir(tmp_path)

    # Trace evidence inside repo is refused too.
    trace_in_repo = repo_dir / "trace.json"
    trace_in_repo.write_text(json.dumps({"invoked": []}), encoding="utf-8")
    with pytest.raises(VEXDecisionError, match="outside the scanned project"):
        load_execution_evidence(trace_in_repo, inventory_path=bom_in_repo, allow_unsigned=True)

    # Symlink and hard-linked decisions files are refused.
    outside_dir = tmp_path / "operator"
    outside_dir.mkdir()
    outside_file = outside_dir / "outside.yaml"
    outside_file.write_text("version: 1\ndecisions: []\n", encoding="utf-8")
    symlink = outside_dir / "link.yaml"
    symlink.symlink_to(outside_file)
    with pytest.raises(VEXDecisionError):
        load_vex_decisions(symlink)

    hardlink = outside_dir / "hardlink.yaml"
    os.link(outside_file, hardlink)
    with pytest.raises(VEXDecisionError, match="hard links"):
        load_vex_decisions(hardlink)


def test_vex_cli_requires_dsse_attestation_links_live_advisories_and_verifies_sha256(tmp_path):
    pkg = RegistryEntryComponent(
        bom_ref="pkg:pypi:transformers@4.35.0",
        name="transformers",
        version="4.35.0",
        registry_type="pypi",
        package_url="pkg:pypi/transformers@4.35.0",
    )
    art_dir = tmp_path / "artifacts"
    op_dir = tmp_path / "operator"
    art_dir.mkdir()
    op_dir.mkdir()

    bom_path = art_dir / "aibom.json"
    AIBOM(components=[pkg]).save(bom_path)
    inv_sha = hash_bytes(bom_path.read_bytes())

    # Live advisories format uses component_ref + advisory_id + inventory_sha256.
    live_adv = art_dir / "live-advisories.json"
    live_adv.write_text(
        json.dumps(
            {
                "inventory_sha256": inv_sha,
                "coverage": "complete",
                "complete": True,
                "errors": [],
                "components_checked": 1,
                "components_skipped": 0,
                "components_excluded": 0,
                "dry_run": False,
                "advisories": [
                    {
                        "component_ref": "pkg:pypi:transformers@4.35.0",
                        "advisory_id": "GHSA-live-1234-5678",
                        "ecosystem": "PyPI",
                        "version": "4.35.0",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    # Mismatched inventory_sha256 on advisories must fail closed.
    wrong_adv = art_dir / "wrong-advisories.json"
    wrong_adv.write_text(
        json.dumps({"inventory_sha256": "sha256:" + "0" * 64, "advisories": []}),
        encoding="utf-8",
    )
    with pytest.raises(VEXDecisionError, match="inventory_sha256"):
        load_advisory_report(wrong_adv, expected_inventory_sha256=inv_sha)

    # Real trace-diff format with inputs.inventory.sha256 + reconciliation.matched.
    trace_file = art_dir / "trace-diff.json"
    trace_file.write_text(
        json.dumps(
            {
                "inputs": {"inventory": {"sha256": inv_sha}},
                "reconciliation": {
                    "matched": [
                        {"kind": "package", "inventory_ref": "pkg:pypi:transformers@4.35.0"}
                    ],
                    "unobserved": [],
                },
            }
        ),
        encoding="utf-8",
    )

    runner = CliRunner()
    # Unsigned trace evidence is refused by default!
    res_unsigned = runner.invoke(
        main,
        ["vex", str(bom_path), "--advisories", str(live_adv), "--trace-evidence", str(trace_file)],
    )
    assert res_unsigned.exit_code != 0
    assert "--trace-attestation" in res_unsigned.output

    # Signed trace evidence via DSSE Ed25519 attestation succeeds!
    att_file = art_dir / "trace-diff.att.json"
    pub_file = op_dir / "trace-signer.pub"
    _sign_trace_file(trace_file, att_file, pub_file)

    res_signed = runner.invoke(
        main,
        [
            "vex",
            str(bom_path),
            "--advisories",
            str(live_adv),
            "--trace-evidence",
            str(trace_file),
            "--trace-attestation",
            str(att_file),
            "--trusted-key",
            str(pub_file),
        ],
    )
    assert res_signed.exit_code == 0, res_signed.output
    doc = json.loads(res_signed.output)
    metadata = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert metadata["nexus-symbiote:traceAuthentication"] == "attested"
    assert metadata["nexus-symbiote:traceAttestationSha256"] == hash_bytes(att_file.read_bytes())
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["specVersion"] == "1.7"
    assert len(doc["vulnerabilities"]) == 1
    vuln = doc["vulnerabilities"][0]
    assert vuln["id"] == "GHSA-live-1234-5678"
    assert vuln["analysis"]["state"] == "in_triage"
    assert "response" not in vuln["analysis"]
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props["nexus-symbiote:executionOutcome"] == "invoked"
    assert props["nexus-symbiote:assurance"] == "osv-advisory-match"

    # Tampering with trace evidence after signing fails verification.
    trace_file.write_text(trace_file.read_text(encoding="utf-8") + " ", encoding="utf-8")
    res_tampered = runner.invoke(
        main,
        [
            "vex",
            str(bom_path),
            "--trace-evidence",
            str(trace_file),
            "--trace-attestation",
            str(att_file),
            "--trusted-key",
            str(pub_file),
        ],
    )
    assert res_tampered.exit_code != 0
    assert "attestation verification failed" in res_tampered.output.lower()


def test_only_an_operator_decision_can_state_exploitable(tmp_path):
    """Trace evidence is reported, not verified: no outcome of it may assert exploitability."""
    bom = _three_component_bom()
    refs = [comp.bom_ref for comp in bom.components]
    trace_file = tmp_path / "trace-evidence.json"
    advisories = [
        {"advisory_id": "GHSA-live-1234-5678", "component_ref": ref, "severity": "critical"}
        for ref in refs
    ]
    for key in ("invoked", "shadowed", "declared_never_loaded", "unobserved"):
        trace_file.write_text(json.dumps({key: refs}), encoding="utf-8")
        evidence = load_execution_evidence(trace_file, allow_unsigned=True)
        doc = VEXGenerator(execution_evidence=evidence, advisories=advisories).generate(bom)
        assert len(doc["vulnerabilities"]) == 2 * len(refs)
        for vuln in doc["vulnerabilities"]:
            assert vuln["analysis"]["state"] != "exploitable", key
            assert "response" not in vuln["analysis"], key


def test_a_flagged_offline_match_says_its_range_was_undecidable():
    pkg = RegistryEntryComponent(
        bom_ref="pkg:pypi:torch@2.5.1",
        name="torch",
        version="2.5.1",
        registry_type="pypi",
        package_url="pkg:pypi/torch@2.5.1",
    )
    match = {"component_ref": pkg.bom_ref, "severity": "high", "offline": True}
    advisories = [
        {**match, "advisory_id": "PYSEC-2025-193", "range_undecidable": True},
        {**match, "advisory_id": "PYSEC-2025-194"},
    ]
    doc = VEXGenerator(advisories=advisories).generate(AIBOM(components=[pkg]))
    flags = {
        vuln["id"]: {p["name"]: p["value"] for p in vuln["properties"]}.get(
            "nexus-symbiote:rangeUndecidable"
        )
        for vuln in doc["vulnerabilities"]
    }
    assert flags == {"PYSEC-2025-193": "true", "PYSEC-2025-194": None}


def test_partial_advisory_report_requires_opt_in_and_carries_coverage(tmp_path):
    from nexus_symbiote.advisories import AdvisoryReport

    report = AdvisoryReport(components_checked=1, errors=["lookup unavailable"])
    path = tmp_path / "report.json"
    path.write_text(json.dumps(report.to_dict()))
    with pytest.raises(VEXDecisionError, match="coverage"):
        load_advisory_report(path)
    loaded = load_advisory_report(path, allow_partial=True)
    inventory = AIBOM()
    doc = VEXGenerator(advisory_report=loaded).generate(inventory)
    props = {p["name"]: p["value"] for p in doc["metadata"]["properties"]}
    assert props["nexus-symbiote:advisoryCoverage"] == "partial"
    assert props["nexus-symbiote:advisoryErrors"] == "1"
    assert props["nexus-symbiote:advisoryReportSha256"] == hash_bytes(path.read_bytes())
    assert doc["serialNumber"] != VEXGenerator().generate(inventory)["serialNumber"]
    assert (
        doc["serialNumber"]
        == VEXGenerator(advisory_report=loaded).generate(inventory)["serialNumber"]
    )


def test_vex_operator_material_rejects_writable_files_and_duplicate_yaml(tmp_path):
    path = tmp_path / "decisions.yaml"
    path.write_text("version: 1\ndecisions: []\ndecisions: []\n")
    with pytest.raises(VEXDecisionError):
        load_vex_decisions(path)
    path.write_text("version: 1\ndecisions: []\n")
    path.chmod(0o666)
    with pytest.raises(VEXDecisionError, match="writable"):
        load_vex_decisions(path)


@pytest.mark.parametrize(
    "category",
    [
        "custom_code",
        "code_execution",
        "credential_helper",
        "hidden_markup",
        "invisible_characters",
        "bidi_override",
        "tag_characters",
        "instruction_injection",
        "tool_description_poisoning",
        "identifier_characters",
    ],
)
def test_trace_evidence_cannot_suppress_a_high_static_or_hidden_text_finding(tmp_path, category):
    risk = RiskAssessment(severity=RiskSeverity.HIGH, category=category, detail="finding")
    bom = AIBOM(components=[ToolComponent(bom_ref="tool:t", name="t", risks=[risk])])
    trace_file = tmp_path / "trace.json"
    trace_file.write_text(json.dumps({"declared_never_loaded": ["tool:t"]}), encoding="utf-8")
    evidence = load_execution_evidence(trace_file, allow_unsigned=True)
    (vuln,) = VEXGenerator(execution_evidence=evidence).generate(bom)["vulnerabilities"]
    assert vuln["analysis"]["state"] == "in_triage"
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert props["nexus-symbiote:suppressionBlocked"] == "true"


_ACCEPTED_DECISION = (
    "version: 1\ndecisions:\n  - id: NEXUS-abc\n    state: in_triage\n    detail: d\n    owner: o\n"
)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        # A repeated key silently replaced the first, here the decision's state.
        (
            "version: 1\ndecisions:\n  - id: NEXUS-abc\n    state: in_triage\n"
            "    state: not_affected\n    justification: code_not_reachable\n"
            "    expires_at: 2027-01-01T00:00:00Z\n    detail: d\n    owner: o\n",
            "unique",
        ),
        (_ACCEPTED_DECISION + "decisions: []\n", "unique"),
        # Alias expansion multiplies validation work about tenfold per level.
        (
            "version: 1\nx:\n  a0: &a0 [x]\n  a1: &a1 [*a0, *a0]\ndecisions: *a1\n",
            "anchors",
        ),
        (_ACCEPTED_DECISION.replace("detail: d", "detail: &d d"), "anchors"),
    ],
    ids=["repeated-state", "repeated-decisions", "alias-list", "anchored-scalar"],
)
def test_vex_decisions_refuse_yaml_aliases_and_repeated_keys(tmp_path, text, message):
    path = tmp_path / "decisions.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(VEXDecisionError, match="syntax or complexity") as refused:
        load_vex_decisions(path)
    assert message in str(refused.value.__cause__)
    path.write_text(_ACCEPTED_DECISION, encoding="utf-8")
    assert load_vex_decisions(path).entries[0].owner == "o"


def test_vex_decisions_bound_yaml_nodes(tmp_path, monkeypatch):
    from nexus_symbiote import vex_decisions

    budgets = []
    parse = vex_decisions.parse_yaml_mapping

    def recording(text, **kwargs):
        budgets.append(kwargs.get("max_nodes"))
        return parse(text, **kwargs)

    monkeypatch.setattr(vex_decisions, "parse_yaml_mapping", recording)
    path = tmp_path / "decisions.yaml"
    path.write_text(_ACCEPTED_DECISION, encoding="utf-8")
    load_vex_decisions(path)
    assert budgets == [100_000]


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("decisions.yaml", b"version: 1\ndecisions: [\n  token-5f3a9c: : [\n"),
        ("decisions.json", b'{"version": 1, "decisions": [token-5f3a9c]}'),
        ("decisions.yaml", b"version: 1\ndecisions: []\n# token-5f3a9c \xff\n"),
    ],
    ids=["yaml-syntax", "json-syntax", "invalid-utf8"],
)
def test_vex_decisions_syntax_errors_never_quote_the_file(tmp_path, name, content):
    path = tmp_path / name
    path.write_bytes(content)
    with pytest.raises(VEXDecisionError) as refused:
        load_vex_decisions(path)
    assert str(refused.value) == "Invalid VEX decisions syntax or complexity"


def test_vex_decision_with_a_null_deployment_id_loads_unscoped(tmp_path):
    path = tmp_path / "decisions.yaml"
    path.write_text(_ACCEPTED_DECISION + "    deployment_id: null\n", encoding="utf-8")
    (entry,) = load_vex_decisions(path).entries
    assert entry.deployment_id is None


def test_vex_decisions_report_invalid_utf8_as_a_decision_error(tmp_path):
    path = tmp_path / "decisions.yaml"
    path.write_bytes(b"version: 1\ndecisions: []\n# \xff\xfe\n")
    with pytest.raises(VEXDecisionError, match="Invalid VEX decisions syntax"):
        load_vex_decisions(path)


@pytest.mark.parametrize(
    "mutation",
    [
        {"complete": True},
        {"components_checked": False},
        {"dry_run": "false"},
        {"coverage": "complete"},
    ],
)
def test_inconsistent_advisory_coverage_refused_even_with_partial_opt_in(tmp_path, mutation):
    from nexus_symbiote.advisories import AdvisoryReport

    payload = AdvisoryReport(components_checked=1, errors=["lookup incomplete"]).to_dict()
    payload.update(mutation)
    path = tmp_path / "advisories.json"
    path.write_text(json.dumps(payload))
    with pytest.raises(VEXDecisionError, match="coverage"):
        load_advisory_report(path, allow_partial=True)


def test_trusted_public_key_requires_protected_parent(tmp_path):
    from nexus_symbiote.vex_decisions import _load_trusted_keys

    directory = tmp_path / "keys"
    directory.mkdir(mode=0o700)
    public = directory / "verify.pem"
    public.write_bytes(b"invalid key fixture")
    directory.chmod(0o777)
    with pytest.raises(VEXDecisionError, match="writable or untrusted ancestor"):
        _load_trusted_keys((public,))


def test_vex_checks_owner_of_writable_filesystem_anchor(tmp_path, monkeypatch):
    import os
    import stat
    from types import SimpleNamespace

    from nexus_symbiote.vex_decisions import _check_operator_directory

    anchor = tmp_path.parents[-1].stat()
    real_fstat = os.fstat

    def stat_descriptor(fd):
        result = real_fstat(fd)
        if (result.st_dev, result.st_ino) == (anchor.st_dev, anchor.st_ino):
            fields = list(result)
            fields[stat.ST_UID] = 987654
            return os.stat_result(fields)
        return result

    monkeypatch.setattr(os, "fstat", stat_descriptor)
    monkeypatch.setattr(os, "fstatvfs", lambda fd: SimpleNamespace(f_flag=0))
    with pytest.raises(VEXDecisionError, match="untrusted ancestor"):
        _check_operator_directory(tmp_path / "decisions.json", {0, os.geteuid()})


def test_vex_rejects_an_expiry_outside_the_supported_utc_range(tmp_path):
    path = tmp_path / "decisions.json"
    expires_at = datetime.max.replace(tzinfo=timezone(-timedelta(hours=1)))
    decision = {"id": "sample", "state": "in_triage", "expires_at": expires_at.isoformat()}
    path.write_text(json.dumps({"decisions": [decision]}), encoding="utf-8")
    with pytest.raises(VEXDecisionError, match="Invalid VEX decisions schema"):
        load_vex_decisions(path)


def test_vex_loads_decisions_below_a_trusted_traverse_only_ancestor(tmp_path, monkeypatch):
    from nexus_symbiote import vex_decisions

    outer = tmp_path / "operator"
    inner = outer / "decisions"
    inner.mkdir(parents=True)
    path = inner / "sample.json"
    path.write_text('{"decisions": []}', encoding="utf-8")
    outer.chmod(0o711)
    open_directory = vex_decisions.open_directory_nofollow

    def deny_directory_read(directory):
        if directory == outer:
            raise PermissionError("The fixture grants directory traversal only")
        return open_directory(directory)

    monkeypatch.setattr(vex_decisions, "open_directory_nofollow", deny_directory_read)
    assert load_vex_decisions(path).entries == ()


@pytest.mark.parametrize(
    "text",
    [
        "Mallory\u202e",
        "Mal\x9b[2J",
        "a\u200bb",
        "tab\there",
        "esc\x1b[2J",
        "two\nlines",
        "iso\u2066late\u2069",
        "line\u2028separator",
        "tag\U000e0041\U000e007f",
        "joiner\u2060",
        "bom\ufeff",
        "mark\u200e",
        "mark\u200f",
        "arabic\u061cmark",
        "grapheme\u034fjoiner",
        "mongolian\u180bselector",
    ],
    ids=[
        "bidi-override",
        "c1-csi",
        "zero-width-space",
        "tab",
        "c0-escape",
        "newline",
        "bidi-isolate",
        "line-separator",
        "tag-characters",
        "word-joiner",
        "byte-order-mark",
        "left-to-right-mark",
        "right-to-left-mark",
        "arabic-letter-mark",
        "combining-grapheme-joiner",
        "mongolian-free-variation-selector",
    ],
)
def test_vex_decision_text_refuses_c1_bidi_and_invisible_characters(text):
    for field in ("id", "detail", "owner", "deployment_id"):
        values = {"id": "NEXUS-abc", "detail": "d", "owner": "o", field: text}
        with pytest.raises(ValueError, match="control, bidirectional or invisible"):
            VEXDecisionEntry(state="in_triage", **values)


@pytest.mark.parametrize(
    "text",
    [
        "\u2714\ufe0f reviewed",
        "\U0001f469\u200d\U0001f4bb on call",
        "\u0645\u06cc\u200c\u062e\u0648\u0627\u0647\u0645",
        "\u0915\u094d\u200d\u0937",
        "co\u00adoperate",
        "glyph\U000e0100variant",
    ],
    ids=["emoji-vs16", "zwj-emoji", "persian-zwnj", "devanagari-zwj", "soft-hyphen", "vs17"],
)
def test_vex_decision_text_accepts_format_characters_ordinary_text_uses(text):
    for field in ("detail", "owner", "deployment_id"):
        values = {"id": "NEXUS-abc", "detail": "d", "owner": "o", field: text}
        assert getattr(VEXDecisionEntry(state="in_triage", **values), field) == text
    assert (
        VEXDecisionEntry(id="NEXUS-abc", state="in_triage", detail="d", owner="o").deployment_id
        is None
    )


def test_vex_decision_owner_is_neutralized_on_output():
    bom = _three_component_bom()
    fid = finding_id("tool:invoked", "unpinned_tool", "Tool definition is unpinned")
    entry = VEXDecisionEntry.model_construct(
        id=fid,
        component_ref="tool:invoked",
        state="in_triage",
        justification=None,
        detail="d",
        owner="Mallory\u202e\x9b[2J\u200d\ufe0f",
        expires_at=None,
    )
    decisions = LoadedVEXDecisions(entries=(entry,), sha256="sha256:" + "0" * 64)
    doc = VEXGenerator(decisions=decisions).generate(bom)
    vuln = next(v for v in doc["vulnerabilities"] if v["id"] == fid)
    owner = {p["name"]: p["value"] for p in vuln["properties"]}["nexus-symbiote:vexDecisionOwner"]
    for text in (owner, vuln["analysis"]["detail"]):
        for character in ("\u202e", "\x9b", "\u200d", "\ufe0f"):
            assert character not in text


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("in_kev", "false"),
        ("in_kev", 0),
        ("epss_score", True),
        ("epss_score", "0.5"),
        ("epss_score", float("nan")),
        ("aliases", ["CVE-2024-1,CVE-2024-2", "CVE-2024-3"]),
        ("kev_sources", ["cisa-kev,enisa"]),
    ],
)
def test_vex_refuses_mistyped_or_ambiguous_advisory_fields(field, value):
    pkg = RegistryEntryComponent(
        bom_ref="pkg:pypi:torch@2.5.1",
        name="torch",
        version="2.5.1",
        registry_type="pypi",
        package_url="pkg:pypi/torch@2.5.1",
    )
    advisory = {"advisory_id": "GHSA-a", "component_ref": pkg.bom_ref, "in_kev": True}
    advisory[field] = value
    with pytest.raises(ValueError, match=field):
        VEXGenerator(advisories=[advisory]).generate(AIBOM(components=[pkg]))
    accepted = {"advisory_id": "GHSA-a", "component_ref": pkg.bom_ref, "in_kev": False}
    accepted.update(epss_score=0.25, aliases=["CVE-2024-3"])
    (vuln,) = VEXGenerator(advisories=[accepted]).generate(AIBOM(components=[pkg]))[
        "vulnerabilities"
    ]
    props = {p["name"]: p["value"] for p in vuln["properties"]}
    assert "nexus-symbiote:inKev" not in props
    assert props["nexus-symbiote:epssScore"] == "0.250000"
    assert props["nexus-symbiote:aliases"] == "CVE-2024-3"
