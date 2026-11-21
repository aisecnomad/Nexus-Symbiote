"""Tests for execution-bound VEX, operator VEX decisions with expiry, and advisory linkage (Item 23 & N5)."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
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
from nexus_symbiote.generators._rules import RULES
from nexus_symbiote.generators.vex import _NON_SUPPRESSIBLE_CATEGORIES, VEXGenerator, finding_id
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
    """declared_never_loaded clears non-critical dynamic risk, while unobserved stays in_triage."""
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

    by_comp = {v["affects"][0]["ref"]: v for v in doc["vulnerabilities"]}
    assert set(by_comp.keys()) == {
        "tool:never-loaded",
        "tool:unobserved",
        "tool:invoked",
        "tool:shadowed",
    }

    # 1. Explicit declared_never_loaded on non-critical dynamic finding -> not_affected.
    never = by_comp["tool:never-loaded"]["analysis"]
    assert never["state"] == "not_affected"
    assert never["justification"] == "code_not_reachable"

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
    doc = VEXGenerator(decisions=loaded, reference_time=ref_time).generate(bom)

    by_comp = {v["affects"][0]["ref"]: v for v in doc["vulnerabilities"]}
    assert by_comp["tool:never-loaded"]["analysis"]["state"] == "not_affected"
    assert by_comp["tool:invoked"]["analysis"]["state"] == "in_triage"
    meta_props = {p["name"]: p["value"] for p in doc["metadata"].get("properties", [])}
    assert meta_props["nexus-symbiote:expiredVexDecisions"] == "1"

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


def test_non_suppressible_categories_are_real_rule_categories():
    assert RULES.keys() >= _NON_SUPPRESSIBLE_CATEGORIES


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
    with pytest.raises(VEXDecisionError, match=message):
        load_vex_decisions(path)
    path.write_text(_ACCEPTED_DECISION, encoding="utf-8")
    assert load_vex_decisions(path).entries[0].owner == "o"


def test_vex_decisions_report_invalid_utf8_as_a_decision_error(tmp_path):
    path = tmp_path / "decisions.yaml"
    path.write_bytes(b"version: 1\ndecisions: []\n# \xff\xfe\n")
    with pytest.raises(VEXDecisionError, match="Invalid VEX decisions syntax"):
        load_vex_decisions(path)


@pytest.mark.parametrize(
    "text",
    ["Mallory\u202e", "Mal\x9b[2J", "a\u200bb", "tab\there"],
    ids=["bidi-override", "c1-csi", "zero-width-space", "tab"],
)
def test_vex_decision_text_refuses_c1_bidi_and_invisible_characters(text):
    for field in ("id", "detail", "owner"):
        values = {"id": "NEXUS-abc", "detail": "d", "owner": "o", field: text}
        with pytest.raises(ValueError, match="control, bidirectional or invisible"):
            VEXDecisionEntry(state="in_triage", **values)


def test_vex_decision_owner_is_neutralized_on_output():
    bom = _three_component_bom()
    fid = finding_id("tool:invoked", "unpinned_tool", "Tool definition is unpinned")
    entry = VEXDecisionEntry.model_construct(
        id=fid,
        component_ref="tool:invoked",
        state="in_triage",
        justification=None,
        detail="d",
        owner="Mallory\u202e\x9b[2J",
        expires_at=None,
    )
    decisions = LoadedVEXDecisions(entries=(entry,), sha256="sha256:" + "0" * 64)
    doc = VEXGenerator(decisions=decisions).generate(bom)
    vuln = next(v for v in doc["vulnerabilities"] if v["id"] == fid)
    owner = {p["name"]: p["value"] for p in vuln["properties"]}["nexus-symbiote:vexDecisionOwner"]
    for text in (owner, vuln["analysis"]["detail"]):
        assert "\u202e" not in text
        assert "\x9b" not in text


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
