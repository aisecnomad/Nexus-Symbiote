"""Hardening, operator-policy, export-bound, exit-code, and gate verification (`R0.3.0-1/3`, `R1.0.0-rc.1-1`, `R1.0.0-1/2`, `R1.1-6`)."""

from __future__ import annotations

import json
import tomllib
import xml.etree.ElementTree as ET
from datetime import date, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.diff.upgrade_attribution import attribute_expected_upgrade
from nexus_symbiote.generators._rules import RULES
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.operator_policy import (
    EXIT_COLLECTION_FAILED,
    EXIT_GATE_FAILED,
    EXIT_PASSED,
    EXIT_USAGE_ERROR,
    OperatorPolicyError,
    inert_markdown_cell,
    load_operator_policy,
    narrow_policy,
    render_gate_junit,
    render_gate_markdown,
)
from nexus_symbiote.policy import Policy, RiskPolicy, ScanPolicy, Suppression, ValidatePolicy
from nexus_symbiote.runtime import key_id
from nexus_symbiote.validators.risk import RiskScorer
from tests.support import REPLACEABLE_ANCHOR_LAYOUTS, trust_anchor_in_layout

REPO_ROOT = Path(__file__).resolve().parents[1]

# Invariant 3: zero model SDKs or LLM clients may enter dependencies, optional extras, or lockfiles.
FORBIDDEN_MODEL_SDKS = frozenset(
    {
        "openai",
        "anthropic",
        "litellm",
        "google-genai",
        "google-generativeai",
        "cohere",
        "mistralai",
        "ollama",
        "langchain",
        "langchain-core",
        "llama-index",
        "dspy-ai",
        "transformers",
        "torch",
        "vllm",
        "boto3",
    }
)


def _write_keypair(directory: Path, stem: str = "operator") -> tuple[Path, Path, str]:
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_path = directory / f"{stem}.key"
    pub_path = directory / f"{stem}.pub"
    priv_path.write_bytes(
        priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    priv_path.chmod(0o600)
    pub_path.write_bytes(
        pub.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    pub_path.chmod(0o600)
    return priv_path, pub_path, key_id(pub)


# --- R1.0.0-rc.1-1: Invariant 3 allowlist test across pyproject.toml & lockfile ---


def test_invariant_3_zero_llm_sdks_in_dependencies_extras_or_action_lock():
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    project = pyproject["project"]
    declared_specs: list[str] = list(project.get("dependencies", []))
    for extra_specs in project.get("optional-dependencies", {}).values():
        declared_specs.extend(extra_specs)
    declared_names = {canonicalize_name(Requirement(spec).name) for spec in declared_specs}
    assert not (declared_names & FORBIDDEN_MODEL_SDKS), declared_names & FORBIDDEN_MODEL_SDKS

    lock_lines = (REPO_ROOT / "requirements-action.lock").read_text(encoding="utf-8").splitlines()
    locked_names: set[str] = set()
    for raw in lock_lines:
        stripped = raw.strip()
        if not stripped or stripped.startswith(("#", "--")):
            continue
        head = stripped.split("\\")[0].split("--hash")[0].strip()
        if head:
            locked_names.add(canonicalize_name(Requirement(head).name))
    assert not (locked_names & FORBIDDEN_MODEL_SDKS), locked_names & FORBIDDEN_MODEL_SDKS


# --- R1.1-6: Signed out-of-checkout operator policy + monotonic narrowing ---


def test_operator_policy_refuses_placement_inside_scanned_project_or_git_repo(tmp_path):
    project = tmp_path / "checkout"
    project.mkdir()
    (project / ".git").mkdir()
    inside_policy = project / "operator.yaml"
    inside_policy.write_text("version: '1.0'\nrisk:\n  fail_threshold: 20.0\n", encoding="utf-8")

    with pytest.raises(OperatorPolicyError, match="outside the scanned project"):
        load_operator_policy(inside_policy, project)

    # World-writable policy file is refused even outside the checkout.
    outside = tmp_path / "operator"
    outside.mkdir()
    writable_policy = outside / "world.yaml"
    writable_policy.write_text("version: '1.0'\n", encoding="utf-8")
    writable_policy.chmod(0o666)
    try:
        with pytest.raises(OperatorPolicyError, match="world-writable"):
            load_operator_policy(writable_policy, project)
    finally:
        writable_policy.chmod(0o600)


def test_operator_policy_key_and_attestation_pairing_fails_closed(tmp_path):
    project = tmp_path / "checkout"
    project.mkdir()
    op_dir = tmp_path / "operator"
    op_dir.mkdir()
    pol_path = op_dir / "policy.yaml"
    pol_path.write_text("version: '1.0'\n", encoding="utf-8")
    _, pub_path, _ = _write_keypair(op_dir)

    with pytest.raises(OperatorPolicyError, match="requires --operator-policy-attestation"):
        load_operator_policy(pol_path, project, trusted_keys=(pub_path,))

    fake_env = op_dir / "env.dsse.json"
    fake_env.write_text("{}", encoding="utf-8")
    with pytest.raises(OperatorPolicyError, match="requires at least one --operator-policy-key"):
        load_operator_policy(pol_path, project, envelope_path=fake_env)


@pytest.mark.parametrize("layout", REPLACEABLE_ANCHOR_LAYOUTS)
def test_operator_policy_refuses_a_file_another_user_could_replace(tmp_path, monkeypatch, layout):
    project = tmp_path / "checkout"
    project.mkdir()
    policy = trust_anchor_in_layout(tmp_path, layout, "op.yaml", b"version: '1.0'\n", monkeypatch)
    with pytest.raises(OperatorPolicyError, match="group- or world-writable"):
        load_operator_policy(policy, project, allow_unsigned=True)


def test_operator_policy_accepts_a_sticky_directory_like_tmp(tmp_path, monkeypatch):
    project = tmp_path / "checkout"
    project.mkdir()
    policy = trust_anchor_in_layout(
        tmp_path, "sticky grandparent", "op.yaml", b"version: '1.0'\n", monkeypatch
    )
    assert load_operator_policy(policy, project, allow_unsigned=True).digest.startswith("sha256:")


@pytest.mark.parametrize(("git", "cwd_is_project"), [(False, False), (False, True), (True, False)])
def test_operator_policy_key_inside_the_scanned_project_is_refused(
    tmp_path, monkeypatch, git, cwd_is_project
):
    project = tmp_path / "checkout"
    (project / "keys").mkdir(parents=True)
    if git:
        (project / ".git").mkdir()
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(project if cwd_is_project else elsewhere)
    op_dir = tmp_path / "operator"
    op_dir.mkdir()
    policy = op_dir / "policy.yaml"
    policy.write_text("version: '1.0'\n", encoding="utf-8")
    envelope = op_dir / "policy.dsse.json"
    envelope.write_text("{}", encoding="utf-8")
    _, pub_path, _ = _write_keypair(op_dir)
    planted = project / "keys" / "op.pub"
    planted.write_bytes(pub_path.read_bytes())
    planted.chmod(0o600)
    with pytest.raises(OperatorPolicyError, match="that holds PROJECT"):
        load_operator_policy(policy, project, envelope_path=envelope, trusted_keys=(planted,))


def test_a_project_policy_may_narrow_operator_exclusions_to_none():
    operator = Policy.model_validate({"scan": {"exclude_paths": ["vendor/**"]}})
    narrowed, clamped = narrow_policy(
        operator, Policy.model_validate({"scan": {"exclude_paths": []}})
    )
    assert narrowed.scan.exclude_paths == [] and clamped == []
    narrowed, clamped = narrow_policy(
        operator, Policy.model_validate({"scan": {"exclude_paths": ["other/**"]}})
    )
    assert narrowed.scan.exclude_paths == []
    assert clamped == ["scan.exclude_paths (refused extra project exclusions)"]
    # A project policy that does not set the list keeps the operator's exclusions.
    narrowed, _ = narrow_policy(operator, Policy.model_validate({"risk": {"fail_threshold": 10}}))
    assert narrowed.scan.exclude_paths == ["vendor/**"]


def test_signed_operator_policy_clamps_checkout_weakening_and_records_provenance_in_sarif_and_json(
    tmp_path,
):
    runner = CliRunner()
    project = tmp_path / "checkout"
    project.mkdir()
    # Risky project: unsafe pickle model + checkout policy attempting to raise fail_threshold to 999
    # and relax fail_on_severity to none.
    (project / "weights.pkl").write_bytes(b"\x80\x04\x95\x02\x00\x00\x00\x00\x00\x00\x00N.")
    (project / ".nexus-symbiote.yaml").write_text(
        "version: '1.0'\n"
        "scan:\n"
        "  scanners: [mcp]\n"
        "  exclude_paths: [node_modules, secret_dir]\n"
        "  failure_mode: report-only\n"
        "validate:\n"
        "  require_completeness: false\n"
        "  require_integrity: false\n"
        "  minimum_assurance_level: declared\n"
        "risk:\n"
        "  fail_threshold: 999.0\n"
        "  warn_threshold: 500.0\n"
        "  fail_on_severity: none\n"
        "  ignore_categories: [serialization_format]\n",
        encoding="utf-8",
    )

    op_dir = tmp_path / "operator"
    op_dir.mkdir()
    op_policy = op_dir / "operator-policy.yaml"
    op_policy.write_text(
        "version: '1.0'\n"
        "validate:\n"
        "  require_completeness: true\n"
        "  require_integrity: true\n"
        "  minimum_assurance_level: verified\n"
        "risk:\n"
        "  fail_threshold: 10.0\n"
        "  warn_threshold: 5.0\n"
        "  fail_on_severity: high\n",
        encoding="utf-8",
    )
    priv_path, pub_path, signer_kid = _write_keypair(op_dir)
    evidence_dir = tmp_path / "evidence"
    evidence_dir.mkdir()
    evidence_dir.chmod(0o775)
    att_path = evidence_dir / "operator-policy.dsse.json"

    # Sign operator policy via CLI `attest --purpose policy` and verify via `verify-attestation`.
    att_res = runner.invoke(
        main,
        [
            "attest",
            str(op_policy),
            "--purpose",
            "policy",
            "--key",
            str(priv_path),
            "--out",
            str(att_path),
        ],
    )
    assert att_res.exit_code == 0, att_res.output
    ver_res = runner.invoke(
        main,
        [
            "verify-attestation",
            str(op_policy),
            str(att_path),
            "--purpose",
            "policy",
            "--trusted-key",
            str(pub_path),
        ],
    )
    assert ver_res.exit_code == 0, ver_res.output

    # Tampered policy bytes fail closed under signed operator policy verification.
    tampered = op_dir / "tampered.yaml"
    tampered.write_text("version: '1.0'\nrisk:\n  fail_threshold: 999.0\n", encoding="utf-8")
    with pytest.raises(OperatorPolicyError, match="attestation verification failed"):
        load_operator_policy(tampered, project, envelope_path=att_path, trusted_keys=(pub_path,))

    # 1. `scan --check --detailed-exit-codes` with signed operator policy clamps checkout
    # weakening, collects `weights.pkl`, and fails closed with exit code 3.
    check_res = runner.invoke(
        main,
        [
            "scan",
            str(project),
            "--check",
            "--detailed-exit-codes",
            "--operator-policy",
            str(op_policy),
            "--operator-policy-attestation",
            str(att_path),
            "--operator-policy-key",
            str(pub_path),
        ],
    )
    assert check_res.exit_code == EXIT_GATE_FAILED, check_res.output

    # 2. `scan --report-only -f sarif` records operator_policy_digest + signer key IDs in SARIF.
    sarif_out = tmp_path / "out.sarif"
    sarif_res = runner.invoke(
        main,
        [
            "scan",
            str(project),
            "--report-only",
            "--operator-policy",
            str(op_policy),
            "--operator-policy-attestation",
            str(att_path),
            "--operator-policy-key",
            str(pub_path),
            "-f",
            "sarif",
            "-o",
            str(sarif_out),
        ],
    )
    assert sarif_res.exit_code == EXIT_PASSED, sarif_res.output
    sarif_doc = json.loads(sarif_out.read_text(encoding="utf-8"))
    run_props = sarif_doc["runs"][0]["properties"]
    assert run_props["operatorPolicyDigest"].startswith("sha256:")
    assert run_props["operatorPolicySigners"] == [signer_kid]

    # Native JSON scan + `risk --report-format json --detailed-exit-codes` records clamped settings
    # and operator:sha256:... provenance.
    bom_out = tmp_path / "inventory.json"
    ok_scan = runner.invoke(
        main,
        [
            "scan",
            str(project),
            "--report-only",
            "--operator-policy",
            str(op_policy),
            "--operator-policy-attestation",
            str(att_path),
            "--operator-policy-key",
            str(pub_path),
            "-o",
            str(bom_out),
        ],
    )
    assert ok_scan.exit_code == 0, ok_scan.output

    risk_res = runner.invoke(
        main,
        [
            "risk",
            str(bom_out),
            "--project",
            str(project),
            "--operator-policy",
            str(op_policy),
            "--operator-policy-attestation",
            str(att_path),
            "--operator-policy-key",
            str(pub_path),
            "--report-format",
            "json",
            "--detailed-exit-codes",
        ],
    )
    assert risk_res.exit_code == EXIT_GATE_FAILED, risk_res.output
    verdict = json.loads(risk_res.output)
    assert verdict["passed"] is False
    assert verdict["policy_source"].startswith("operator:sha256:")
    assert verdict["operator_policy_signers"] == [signer_kid]
    assert any("risk.fail_threshold=10.0" in item for item in verdict["clamped_project_settings"])


def test_narrow_policy_allows_project_to_tighten_and_blocks_unapproved_suppressions():
    op = Policy(
        version="1.0",
        scan=ScanPolicy(scanners=["mcp", "model"]),
        risk=RiskPolicy(fail_threshold=50.0, warn_threshold=25.0, fail_on_severity="critical"),
        validate=ValidatePolicy(
            require_completeness=False,
            require_integrity=True,
            minimum_assurance_level="declared",
            require_discovery_signature=True,
        ),
    )
    unapproved = Suppression(
        component_ref="model:weights.pkl",
        category="serialization_format",
        fingerprint="sha256:" + "a" * 64,
        reason="checkout tried to self-suppress",
        owner="attacker",
        expires=date.today() + timedelta(days=30),
    )
    proj = Policy(
        version="1.0",
        scan=ScanPolicy(scanners=["mcp", "model", "rag"]),
        risk=RiskPolicy(
            fail_threshold=20.0,
            warn_threshold=10.0,
            fail_on_severity="high",
            suppressions=[unapproved],
        ),
        validate=ValidatePolicy(
            require_completeness=True,
            require_integrity=True,
            minimum_assurance_level="verified",
            require_discovery_signature=False,
        ),
    )
    narrowed, clamped = narrow_policy(op, proj)
    assert narrowed.risk.fail_threshold == 20.0
    assert narrowed.risk.fail_on_severity == "high"
    assert narrowed.validation.require_completeness is True
    assert narrowed.validation.minimum_assurance_level == "verified"
    assert narrowed.validation.require_discovery_signature is True
    assert narrowed.risk.suppressions == []
    assert any("suppressions" in c for c in clamped)
    assert any("require_discovery_signature" in c for c in clamped)


# --- R0.3.0-3: diff --expect-upgrade ---


def test_diff_expect_upgrade_attributes_profile_transitions_and_blocks_piggybacked_drift(
    tmp_path,
):
    runner = CliRunner()
    old_srv = MCPServerComponent(
        bom_ref="mcp:demo",
        name="demo",
        command="node",
        args=["server.js", "--config-url", "https://config.acme.example/prod.json"],
        properties={
            "static_config_hash_profile": "v2",
            "static_config_hash": "sha256:" + "1" * 64,
        },
    )
    upgraded_srv = MCPServerComponent(
        bom_ref="mcp:demo",
        name="demo",
        command="node",
        args=["server.js", "--config-url", "https://config.acme.example/prod.json"],
        properties={
            "static_config_hash_profile": "v3",
            "static_config_hash": "sha256:" + "1" * 64,
        },
    )
    old_bom = AIBOM(components=[old_srv])
    old_bom.metadata.tool_version = "0.2.0"
    upgraded_bom = AIBOM(components=[upgraded_srv])
    old_path = tmp_path / "old.json"
    upg_path = tmp_path / "upgraded.json"
    old_bom.save(old_path)
    upgraded_bom.save(upg_path)

    # Without --expect-upgrade, static_config_hash_profile change raises a security alert (exit 3).
    raw_diff = runner.invoke(
        main,
        ["diff", str(old_path), str(upg_path), "--fail-on-alert", "--detailed-exit-codes"],
    )
    assert raw_diff.exit_code == EXIT_GATE_FAILED

    # With --expect-upgrade 0.2.0, pure profile bump moves to tool_upgrade_changes (exit 0).
    upg_diff = runner.invoke(
        main,
        [
            "diff",
            str(old_path),
            str(upg_path),
            "--expect-upgrade",
            "0.2.0",
            "--fail-on-alert",
            "--detailed-exit-codes",
            "--report-format",
            "json",
        ],
    )
    assert upg_diff.exit_code == EXIT_PASSED, upg_diff.output
    doc = json.loads(upg_diff.output)
    assert doc["security_alerts"] == []
    assert len(doc["tool_upgrade_changes"]) >= 1

    # Adversarial check 1: static_config_hash changed WITH profile bump (e.g. --config-url prod -> pwn) -> NOT attributed!
    hash_changed_srv = MCPServerComponent(
        bom_ref="mcp:demo",
        name="demo",
        command="node",
        args=["server.js", "--config-url", "https://evil.example/pwn.json"],
        properties={
            "static_config_hash_profile": "v3",
            "static_config_hash": "sha256:" + "9" * 64,
        },
    )
    hash_changed_path = tmp_path / "hash_changed.json"
    AIBOM(components=[hash_changed_srv]).save(hash_changed_path)
    hash_changed_res = runner.invoke(
        main,
        [
            "diff",
            str(old_path),
            str(hash_changed_path),
            "--expect-upgrade",
            "0.2.0",
            "--fail-on-alert",
            "--detailed-exit-codes",
        ],
    )
    assert hash_changed_res.exit_code == EXIT_GATE_FAILED

    # Adversarial check 2: mismatched baseline tool_version -> usage error (exit 2).
    mismatch_res = runner.invoke(
        main,
        [
            "diff",
            str(old_path),
            str(upg_path),
            "--expect-upgrade",
            "0.1.0",
            "--detailed-exit-codes",
        ],
    )
    assert mismatch_res.exit_code == EXIT_USAGE_ERROR

    with pytest.raises(ValueError, match="Unsupported --expect-upgrade"):
        attribute_expected_upgrade({"security_alerts": []}, "9.9.9")


@pytest.mark.parametrize("from_version", ["0.1.0", "0.2.0"])
def test_expect_upgrade_keeps_a_tool_fingerprint_version_change_as_an_alert(tmp_path, from_version):
    # Every supported release wrote rfc8785-jcs-v2, so a relabelled profile next to a new
    # digest is a descriptor change the upgrade does not explain.
    def tool_bom(digest: str, version: str) -> AIBOM:
        tool = ToolComponent(
            bom_ref="tool:add",
            name="add",
            definition_hash="sha256:" + digest * 64,
            definition_hash_version=version,
        )
        return AIBOM(components=[tool])

    old_bom = tool_bom("a", "rfc8785-jcs-v1")
    old_bom.metadata.tool_version = from_version
    old_path, new_path = tmp_path / "old.json", tmp_path / "new.json"
    old_bom.save(old_path)
    tool_bom("b", "rfc8785-jcs-v2").save(new_path)
    result = CliRunner().invoke(
        main,
        [
            "diff",
            str(old_path),
            str(new_path),
            "--expect-upgrade",
            from_version,
            "--detailed-exit-codes",
            "--report-format",
            "json",
        ],
    )
    assert result.exit_code == EXIT_GATE_FAILED, result.output
    doc = json.loads(result.output)
    assert doc["tool_upgrade_changes"] == []
    assert [alert["component"] for alert in doc["security_alerts"]] == ["tool:add"]


def test_expect_upgrade_keeps_an_unsupported_spec_version_alert():
    alerts = [
        {
            "severity": "high",
            "component": "metadata",
            "alert": f"The {label} snapshot uses a spec_version this release does not support; "
            "the comparison can miss fields.",
        }
        for label in ("baseline", "candidate")
    ]
    for from_version in ("0.1.0", "0.2.0"):
        attributed = attribute_expected_upgrade({"security_alerts": alerts}, from_version)
        assert attributed["security_alerts"] == alerts
        assert attributed["tool_upgrade_changes"] == []


# --- R1.0.0-rc.1-1: Exit-code contract & Markdown / JUnit injection-safe rendering ---


def test_detailed_vs_legacy_exit_codes_separate_usage_gate_and_collection_failures(tmp_path):
    runner = CliRunner()
    # 2 = CLI usage error
    bad_flag = runner.invoke(main, ["scan", "--definitely-unknown-flag"])
    assert bad_flag.exit_code == EXIT_USAGE_ERROR

    # 4 = collection / input failure under --detailed-exit-codes (legacy = 1)
    corrupt = tmp_path / "corrupt.json"
    corrupt.write_text("{not valid json", encoding="utf-8")
    det_val = runner.invoke(main, ["validate", str(corrupt), "--detailed-exit-codes"])
    leg_val = runner.invoke(main, ["validate", str(corrupt), "--legacy-exit-codes"])
    assert det_val.exit_code == EXIT_COLLECTION_FAILED
    assert leg_val.exit_code == 1

    # 0 = clean scan + reconciled validate
    clean_proj = tmp_path / "clean"
    clean_proj.mkdir()
    (clean_proj / "agent.yaml").write_text(
        "name: clean-bot\nversion: '1.0'\nowner: platform-sec\npurpose: demo\n",
        encoding="utf-8",
    )
    (clean_proj / "CLAUDE.md").write_text("# Reviewed instructions\n", encoding="utf-8")
    bom_path = tmp_path / "clean.json"
    assert (
        runner.invoke(
            main, ["scan", str(clean_proj), "-o", str(bom_path), "--detailed-exit-codes"]
        ).exit_code
        == EXIT_PASSED
    )
    assert (
        runner.invoke(main, ["validate", str(bom_path), "--detailed-exit-codes"]).exit_code
        == EXIT_GATE_FAILED
    )
    assert (
        runner.invoke(
            main,
            ["validate", str(bom_path), "--project", str(clean_proj), "--detailed-exit-codes"],
        ).exit_code
        == EXIT_PASSED
    )


def test_markdown_step_summary_and_junit_reports_neutralize_injection_payloads(tmp_path):
    hostile_reason = (
        "[click me](https://evil.example) <script>alert(1)</script>\n"
        "::error file=app.py::spoofed\n##[set-output name=pwn]1"
    )
    doc = {
        "passed": False,
        "policy_source": "operator:sha256:" + "a" * 64,
        "operator_policy_digest": "sha256:" + "a" * 64,
        "operator_policy_signers": ["ed25519:key1"],
        "overall_score": 88.5,
        "gate_reasons": [hostile_reason],
        "security_alerts": [{"severity": "high", "alert": hostile_reason}],
    }
    md = render_gate_markdown("risk", doc)
    # No unescaped Markdown link, HTML tag, or raw GitHub workflow command survives.
    assert "[click me](" not in md
    assert "<script>" not in md
    assert "::error" not in md
    assert "##[set-output" not in md
    assert "\\:\\:error" in md or inert_markdown_cell("::error") in md
    assert "passed" in render_gate_markdown("diff", {"security_alerts": []})

    junit_xml = render_gate_junit("risk", doc)
    root = ET.fromstring(junit_xml)  # noqa: S314 - parsing our own generated XML in test
    assert root.attrib["failures"] == "1"
    failure_el = root.find("./testcase/failure")
    assert failure_el is not None
    assert "<script>" not in junit_xml
    assert ET.fromstring(render_gate_junit("diff", {"passed": True})).attrib["failures"] == "0"  # noqa: S314
    assert ET.fromstring(render_gate_junit("diff", {"passed": False})).attrib["failures"] == "1"  # noqa: S314

    # Extra branch checks for narrow_policy(op, None), invalid operator YAML, and metadata upgrade attribution.
    base_op = Policy(version="1.0")
    assert narrow_policy(base_op, None) == (base_op, [])
    bad_op_dir = tmp_path / "bad_op"
    bad_op_dir.mkdir()
    bad_yaml = bad_op_dir / "invalid.yaml"
    bad_yaml.write_text("version: [unterminated\n", encoding="utf-8")
    with pytest.raises(OperatorPolicyError, match="invalid YAML"):
        load_operator_policy(bad_yaml, None, allow_unsigned=True)
    meta_upg = attribute_expected_upgrade(
        {
            "security_alerts": [
                {"severity": "medium", "component": "metadata", "alert": "Tool version changed."}
            ],
            "components_modified": [{"bom_ref": "mcp:empty", "details": []}],
        },
        "0.1.0",
    )
    assert meta_upg["security_alerts"] == []
    assert len(meta_upg["tool_upgrade_changes"]) == 1
    assert (
        attribute_expected_upgrade({"security_alerts": None}, "0.1.0")["tool_upgrade_changes"] == []
    )

    # End-to-end CLI --step-summary + --report-format junit on `validate`
    runner = CliRunner()
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "weights.pkl").write_bytes(b"\x80\x04N.")
    bom_path = tmp_path / "bom.json"
    runner.invoke(main, ["scan", str(proj), "--report-only", "-o", str(bom_path)])
    summary_file = tmp_path / "step_summary.md"
    res = runner.invoke(
        main,
        [
            "validate",
            str(bom_path),
            "--report-format",
            "junit",
            "--step-summary",
            str(summary_file),
            "--detailed-exit-codes",
        ],
    )
    assert res.exit_code == EXIT_GATE_FAILED
    assert ET.fromstring(res.output).attrib["failures"] == "1"  # noqa: S314
    assert "### Nexus SymBiote validate: failed" in summary_file.read_text(encoding="utf-8")


# --- R0.3.0-1 & R1.0.0-1/2: Every rule category positive/negative + scripts + CODEOWNERS ---


def test_every_rule_catalog_category_scores_positive_finding_and_zero_when_absent():
    scorer = RiskScorer()
    assert len(RULES) >= 20
    for category in sorted(RULES):
        pos_bom = AIBOM(
            components=[
                ToolComponent(
                    bom_ref=f"tool:test/{category}",
                    name="probe",
                    risks=[
                        RiskAssessment(
                            category=category,
                            severity=RiskSeverity.HIGH,
                            detail=f"synthetic positive probe for {category}",
                        )
                    ],
                )
            ]
        )
        neg_bom = AIBOM(
            components=[ToolComponent(bom_ref=f"tool:test/{category}", name="probe", risks=[])]
        )
        pos_eval = scorer.score(pos_bom)
        neg_eval = scorer.score(neg_bom)
        assert pos_eval.overall_score > neg_eval.overall_score == 0.0, category
        sarif = SARIFGenerator().generate(pos_bom)
        assert sarif["runs"][0]["results"][0]["ruleId"] == f"nexus_symbiote/{category}/high"


def test_default_signed_operator_policy_empty_tool_version_step_summary_and_exit_3(tmp_path):
    runner = CliRunner()
    op_dir = tmp_path / "ops"
    op_dir.mkdir()
    op_policy = op_dir / "policy.yaml"
    op_policy.write_text("version: '1.0'\nrisk:\n  fail_threshold: 9999.0\n", encoding="utf-8")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "CLAUDE.md").write_text("# ok\n", encoding="utf-8")
    bom_path = tmp_path / "bom.json"
    assert runner.invoke(main, ["scan", str(proj), "-o", str(bom_path)]).exit_code == 0

    # D7: --operator-policy without attestation/key fails closed by default (exit 3 under detailed).
    req_res = runner.invoke(
        main,
        [
            "risk",
            str(bom_path),
            "--operator-policy",
            str(op_policy),
            "--detailed-exit-codes",
        ],
    )
    assert req_res.exit_code == EXIT_GATE_FAILED, req_res.output

    # Explicit --allow-unsigned-operator-policy opts in; combining with attestation is a usage error (2).
    allow_res = runner.invoke(
        main,
        [
            "risk",
            str(bom_path),
            "--operator-policy",
            str(op_policy),
            "--allow-unsigned-operator-policy",
            "--detailed-exit-codes",
        ],
    )
    assert allow_res.exit_code == EXIT_PASSED, allow_res.output

    # D8: baseline with empty tool_version ("") is rejected by diff --expect-upgrade with exit 2.
    empty_ver_bom = json.loads(bom_path.read_text(encoding="utf-8"))
    empty_ver_bom["metadata"]["tool_version"] = ""
    empty_ver_path = tmp_path / "empty_ver.json"
    empty_ver_path.write_text(json.dumps(empty_ver_bom), encoding="utf-8")
    empty_upg = runner.invoke(
        main,
        [
            "diff",
            str(empty_ver_path),
            str(bom_path),
            "--expect-upgrade",
            "0.1.0",
            "--detailed-exit-codes",
        ],
    )
    assert empty_upg.exit_code == EXIT_USAGE_ERROR, empty_upg.output

    # --step-summary appends in place: preserves existing mode (0644) and existing content > 1 MiB.
    summary_file = tmp_path / "summary.md"
    large_prefix = "## Existing\n" + ("x" * (1024 * 1024 + 4096)) + "\n"
    summary_file.write_text(large_prefix, encoding="utf-8")
    summary_file.chmod(0o644)
    runner.invoke(
        main,
        ["validate", str(bom_path), "--step-summary", str(summary_file), "--detailed-exit-codes"],
    )
    assert (summary_file.stat().st_mode & 0o777) == 0o644
    summary_text = summary_file.read_text(encoding="utf-8")
    assert summary_text.startswith(large_prefix)
    assert "### Nexus SymBiote validate: failed" in summary_text
    assert inert_markdown_cell("integrity:") in summary_text

    # Wrong key on --operator-policy-key AND verify-attestation exits 3 (gate failed), whereas corrupt key exits 4.
    priv_a, pub_a = op_dir / "a.key", op_dir / "a.pub"
    priv_b, pub_b = op_dir / "b.key", op_dir / "b.pub"
    assert (
        runner.invoke(
            main, ["runtime", "keygen", "--private-key", str(priv_a), "--public-key", str(pub_a)]
        ).exit_code
        == 0
    )
    assert (
        runner.invoke(
            main, ["runtime", "keygen", "--private-key", str(priv_b), "--public-key", str(pub_b)]
        ).exit_code
        == 0
    )
    pol_att = op_dir / "policy.att.json"
    assert (
        runner.invoke(
            main,
            [
                "attest",
                str(op_policy),
                "--purpose",
                "policy",
                "--key",
                str(priv_a),
                "--out",
                str(pol_att),
            ],
        ).exit_code
        == 0
    )
    wrong_pol_key = runner.invoke(
        main,
        [
            "risk",
            str(bom_path),
            "--operator-policy",
            str(op_policy),
            "--operator-policy-attestation",
            str(pol_att),
            "--operator-policy-key",
            str(pub_b),
            "--detailed-exit-codes",
        ],
    )
    assert wrong_pol_key.exit_code == EXIT_GATE_FAILED, wrong_pol_key.output

    corrupt_key = op_dir / "corrupt.pub"
    corrupt_key.write_text("not-a-pem-key\n", encoding="utf-8")
    corrupt_key.chmod(0o600)
    bad_key_res = runner.invoke(
        main,
        [
            "risk",
            str(bom_path),
            "--operator-policy",
            str(op_policy),
            "--operator-policy-attestation",
            str(pol_att),
            "--operator-policy-key",
            str(corrupt_key),
            "--detailed-exit-codes",
        ],
    )
    assert bad_key_res.exit_code == EXIT_COLLECTION_FAILED, bad_key_res.output

    env_path = op_dir / "bom.att.json"
    assert (
        runner.invoke(
            main,
            [
                "attest",
                str(bom_path),
                "--purpose",
                "reviewed",
                "--key",
                str(priv_a),
                "--out",
                str(env_path),
            ],
        ).exit_code
        == 0
    )
    bad_att = runner.invoke(
        main,
        [
            "--detailed-exit-codes",
            "verify-attestation",
            str(bom_path),
            str(env_path),
            "--trusted-key",
            str(pub_b),
            "--purpose",
            "reviewed",
        ],
    )
    assert bad_att.exit_code == EXIT_GATE_FAILED, bad_att.output


@pytest.mark.parametrize("git_root", [False, True])
def test_policy_key_cannot_come_from_explicit_target(tmp_path, monkeypatch, git_root):
    from nexus_symbiote.operator_policy import OperatorPolicyError, _verify_policy_attestation

    project = tmp_path / "project"
    project.mkdir()
    if git_root:
        (project / ".git").mkdir()
    target = project / "subproject" if git_root else project
    target.mkdir(exist_ok=True)
    independent = tmp_path / "operator"
    independent.mkdir()
    monkeypatch.chdir(independent)
    envelope = independent / "policy.dsse"
    envelope.write_bytes(b"{}")
    key = project / "trust.pem"
    key.write_bytes(b"fixture")
    with pytest.raises(OperatorPolicyError, match="outside the target checkout"):
        _verify_policy_attestation(b"{}", independent / "policy.yaml", target, envelope, (key,))


def test_step_summary_preserves_hard_linked_file(tmp_path):
    import os

    import click

    from nexus_symbiote.operator_policy import append_step_summary

    original = tmp_path / "original"
    original.write_bytes(b"existing")
    summary = tmp_path / "summary"
    os.link(original, summary)
    with pytest.raises(click.ClickException):
        append_step_summary(summary, "report")
    assert original.read_bytes() == b"existing"
