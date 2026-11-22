"""Project validation must corroborate a supplied inventory with local observations."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import hash_tool_definition
from nexus_symbiote.graph import INFERRED_AGENT_REF, validate_graph
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.validators.completeness import CompletenessValidator


def _claimed_complete(project: Path, target: Path) -> AIBOM:
    run = CliRunner().invoke(
        main, ["scan", "--report-only", "--no-project-policy", str(project), "-o", str(target)]
    )
    assert run.exit_code == 0, run.output
    bom = AIBOM.load(target)
    claim = bom.metadata.completeness
    assert claim is not None
    claim.scanner_status = dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete")
    claim.collectors_completed = claim.collectors_requested = sorted(BUILTIN_SCANNER_NAMES)
    claim.scan_failures = []
    claim.surfaces_excluded = []
    return bom


def test_cli_rejects_omitted_instruction_with_forged_complete_coverage(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Safe instructions.")
    (project / "AGENTS.md").write_text("hidden\u202edirective")
    target = tmp_path / "bom.json"
    bom = _claimed_complete(project, target)
    hidden = "prompt:AGENTS.md"
    bom.components = [component for component in bom.components if component.bom_ref != hidden]
    for component in bom.components:
        if hidden in getattr(component, "prompt_refs", ()):
            component.prompt_refs.remove(hidden)
    bom.dependencies = [edge for edge in bom.dependencies if edge.target_ref != hidden]
    bom.metadata.completeness.exclusions = ["AGENTS.md"]
    assert not validate_graph(bom)
    bom.save(target)

    run = CliRunner().invoke(
        main, ["validate", "--no-project-policy", str(target), "--project", str(project)]
    )
    assert run.exit_code == 1, run.output
    assert "Missing or mismatched local component" in run.output
    assert hidden in run.output


def test_source_substitution_cannot_satisfy_a_collector_reference(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    for name in ("CLAUDE.md", "AGENTS.md"):
        (project / name).write_text("Identical bytes.")
    bom = _claimed_complete(project, tmp_path / "bom.json")
    component = bom.get_component("prompt:AGENTS.md")
    assert component is not None
    component.source_path = "AGENTS.md"  # Relative form of the actual in-root subject.
    validator = CompletenessValidator()
    assert not any(
        i.surface == component.bom_ref
        for i in validator.validate_against_project(bom, project).issues
    )
    component.source_path = "CLAUDE.md"
    report = validator.validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface == component.bom_ref for i in report.issues)


def test_new_server_in_existing_mcp_config_is_detected(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    config = project / ".mcp.json"
    servers = {"first": {"command": "local-first"}}
    config.write_text(json.dumps({"mcpServers": servers}))
    bom = _claimed_complete(project, tmp_path / "bom.json")
    servers["second"] = {"command": "local-second"}
    config.write_text(json.dumps({"mcpServers": servers}))

    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface.startswith("mcp-server:") for i in report.issues)


def test_local_read_failure_overrides_claimed_complete_status(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("original")
    bom = _claimed_complete(project, tmp_path / "bom.json")
    (project / ".mcp.json").write_text("{ malformed")
    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface == "mcp" and ".mcp.json" in i.description for i in report.issues)


def test_same_server_reference_cannot_substitute_a_different_configured_origin(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"mail": {"url": "https://mail.example.test/mcp"}}})
    )
    bom = _claimed_complete(project, tmp_path / "bom.json")
    server = next(c for c in bom.components if c.component_type.value == "mcp-server")
    server.endpoint_url = "https://elsewhere.example.test"

    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface == server.bom_ref for i in report.issues)


def test_recorded_empty_discovery_report_cannot_disappear(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    report_file = project / "shadowscan-report.json"
    report_file.write_text(
        json.dumps(
            {
                "version": "1.0",
                "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
                "stats": [{"errors": [], "skipped": False, "incomplete": False}],
                "findings": [],
            }
        )
    )
    bom = _claimed_complete(project, tmp_path / "bom.json")
    report_file.unlink()

    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any(i.surface == "shadowscan" and "digest" in i.description for i in report.issues)


@pytest.mark.parametrize(
    "edit", ["trust", "risk", "extra-ref", "claim", "scope", "unmapped", "limitations"]
)
def test_cli_rejects_forged_discovery_projection_in_combined_bom(tmp_path, edit):
    root = tmp_path / "project"
    root.mkdir()
    (root / "CLAUDE.md").write_text("Check all requests.")
    (root / "shadowscan.json").write_text(
        json.dumps(
            {
                "version": "1",
                "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
                "stats": [{"errors": [], "skipped": False, "incomplete": False}],
                "findings": [
                    {
                        "id": "reported",
                        "surface": "code",
                        "kind": "agent",
                        "risk": {"level": "high"},
                    }
                ],
            }
        )
    )
    target = tmp_path / "bom.json"
    runner = CliRunner()
    result = runner.invoke(main, ["scan", "--report-only", str(root), "-o", str(target)])
    assert result.exit_code == 0, result.output
    args = [
        "validate",
        "--project",
        str(root),
        "--no-project-policy",
        "--allow-unsigned-discovery",
        str(target),
    ]
    original = runner.invoke(main, args)
    assert original.exit_code == 0, original.output
    doc = json.loads(target.read_bytes())
    imported = next(c for c in doc["components"] if c["bom_ref"].startswith("shadowscan:"))
    scope = doc["metadata"]["completeness"]
    if edit == "trust":
        imported.update(assurance_level="verified", trust_tier="third-party-signed")
    elif edit == "risk":
        assert imported["risks"]
        imported["risks"] = []
    elif edit == "extra-ref":
        doc["components"].append({**imported, "bom_ref": "shadowscan:invented"})
    elif edit == "claim":
        imported["claims"]["discovery_report_entry"]["assurance"] = "observed"
    elif edit == "scope":
        scope["scope"] = "runtime"
    elif edit == "unmapped":
        scope["source_unmapped_count"] = 1
        scope["source_unmapped_indexes"] = [9]
    else:
        scope["source_projection_limitations"] = []
    target.write_text(json.dumps(doc))
    altered = runner.invoke(main, args)
    assert altered.exit_code == 1, altered.output
    assert "discovery report" in altered.output


def test_known_package_url_cannot_be_replaced_with_another_package(tmp_path):
    root = tmp_path / "project"
    root.mkdir()
    (root / "requirements.txt").write_text("langchain==1.2.3\n")
    bom = _claimed_complete(root, tmp_path / "bom.json")
    package = bom.get_component("registry:pypi/langchain")
    assert package.package_url == "pkg:pypi/langchain@1.2.3"
    package.package_url = "pkg:pypi/other@1.2.3"

    checked = CompletenessValidator().validate_against_project(bom, root)
    assert not checked.is_complete
    assert any(i.surface == package.bom_ref for i in checked.issues)


def _scanned(
    tmp_path: Path, files: dict[str, str | bytes] | None = None
) -> tuple[Path, Path, dict]:
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Use the configured tools.")
    tool = {"name": "lookup", "description": "Look up a record", "inputSchema": {"type": "object"}}
    server = {"command": "npx", "args": ["-y", "lookup-mcp@1.2.3"], "tools": [tool]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"lookup": server}}))
    for name, content in (files or {}).items():
        path = project / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            path.write_bytes(content)
        else:
            path.write_text(content)
    target = tmp_path / "bom.json"
    run = CliRunner().invoke(main, ["scan", "--no-project-policy", str(project), "-o", str(target)])
    assert run.exit_code == 0, run.output
    return project, target, json.loads(target.read_text())


def _agent(doc: dict) -> dict:
    return next(c for c in doc["components"] if c["component_type"] == "agent")


def _server_ref(doc: dict) -> str:
    return next(c["bom_ref"] for c in doc["components"] if c["component_type"] == "mcp-server")


def _tool(doc: dict) -> dict:
    return next(c for c in doc["components"] if c["component_type"] == "tool")


VERIFIED_RUNTIME_CLAIM = {"method": "sigstore", "scope": "runtime", "assurance": "verified"}


def _validate(project: Path, target: Path, doc: dict):
    target.write_text(json.dumps(doc))
    args = ["validate", "--no-project-policy", str(target), "--project", str(project)]
    return CliRunner().invoke(main, args)


@pytest.mark.parametrize(
    "edit",
    [
        "edge-removed",
        "edge-added-verified",
        "edge-altered",
        "agent-profile-forged",
        "agent-refs-emptied",
        "extra-verified-component",
        "extra-internal-trust-component",
        "local-tool-verified-claim",
        "agent-gap-filled-with-verified-claim",
    ],
)
def test_reconciliation_compares_relationships_agent_and_extras(tmp_path, edit):
    project, target, doc = _scanned(tmp_path)
    assert _validate(project, target, doc).exit_code == 0
    agent = _agent(doc)
    if edit == "edge-removed":
        doc["dependencies"] = []
        agent["tool_refs"] = []
        agent["prompt_refs"] = []
    elif edit == "edge-added-verified":
        doc["dependencies"].append(
            {
                "source_ref": agent["bom_ref"],
                "target_ref": _server_ref(doc),
                "relationship": "approved-under",
                "assurance_level": "verified",
            }
        )
    elif edit == "edge-altered":
        doc["dependencies"][0]["conditions"] = None
    elif edit == "agent-profile-forged":
        agent["autonomy_level"] = "L0-chatbot"
    elif edit == "agent-refs-emptied":
        agent["tool_refs"] = []
    elif edit == "local-tool-verified-claim":
        _tool(doc)["claims"]["attestation"] = VERIFIED_RUNTIME_CLAIM
    elif edit == "agent-gap-filled-with-verified-claim":
        # The collector records deployment as not collected. A supplier may fill that
        # gap with its own claim, which is listed, but never with verified assurance.
        agent["claims"]["deployment"] = VERIFIED_RUNTIME_CLAIM
    else:
        verified = edit == "extra-verified-component"
        doc["components"].append(
            {
                "bom_ref": "guardrail:prod",
                "component_type": "guardrail-policy",
                "name": "prod",
                "assurance_level": "verified" if verified else "declared",
                "trust_tier": "internal-verified",
                "claims": {
                    "deployment": {
                        "method": "attested",
                        "scope": "runtime",
                        "assurance": "verified" if verified else "declared",
                    }
                },
            }
        )
    result = _validate(project, target, doc)
    assert result.exit_code == 1, result.output
    assert "Basis: project-reconciliation-failed" in result.output
    risk = CliRunner().invoke(
        main,
        ["risk", str(target), "--project", str(project), "--no-project-policy", "--json-output"],
    )
    assert risk.exit_code == 1
    assert json.loads(risk.stdout)["assessment_basis"] == "project-reconciliation-failed"


def test_supplier_enrichment_is_reported_as_supplier_claims_not_reconciled(tmp_path):
    project, target, doc = _scanned(tmp_path)
    risk_args = ["risk", str(target), "--project", str(project), "--no-project-policy"]
    original = CliRunner().invoke(main, [*risk_args, "--json-output"])
    assert json.loads(original.stdout)["assessment_basis"] == "project-reconciled"
    assert json.loads(original.stdout)["supplier_claims"] == []
    agent = _agent(doc)
    agent["capabilities"] = {"human_in_the_loop": "required"}
    agent["authorizations"] = [{"principal": "ciso", "action": "deploy"}]
    agent["claims"]["deployment"] = {"method": "change-ticket", "scope": "runtime"}
    _tool(doc)["claims"]["attestation"] = {
        "method": "sigstore",
        "scope": "runtime",
        "assurance": "observed",
    }
    result = _validate(project, target, doc)
    assert result.exit_code == 0, result.output
    assert "Basis: project-reconciled-with-supplier-claims" in result.output
    assert "SUPPLIER-CLAIM" in result.output
    doc["components"].append(
        {
            "bom_ref": "tool:observed",
            "component_type": "tool",
            "name": "observed",
            "claims": {"tool_definition": {"scope": "served-descriptor", "method": "live"}},
        }
    )
    result = _validate(project, target, doc)
    # Completeness accepts the observation as a supplier claim; integrity has no evidence.
    assert result.exit_code == 1, result.output
    assert "UNKNOWN [tool:observed]" in result.output
    payload = json.loads(CliRunner().invoke(main, [*risk_args, "--json-output"]).stdout)
    assert payload["assessment_basis"] == "project-reconciled-with-supplier-claims"
    claimed = {(c["subject"], c["kind"], c["detail"]) for c in payload["supplier_claims"]}
    assert {
        (agent["bom_ref"], "field", "capabilities"),
        (agent["bom_ref"], "field", "authorizations"),
        (agent["bom_ref"], "claim", "deployment"),
        (_tool(doc)["bom_ref"], "claim", "attestation"),
        ("tool:observed", "component", "supplementary observation"),
    } <= claimed
    assert payload["supplier_claims_omitted"] == 0


def test_risk_json_counts_supplier_claims_beyond_the_listed_ones(tmp_path):
    from nexus_symbiote.validators.completeness import MAX_REPORTED_SUPPLIER_CLAIMS

    project, target, doc = _scanned(tmp_path)
    _agent(doc)["properties"].update(
        {f"supplier-note-{index}": index for index in range(MAX_REPORTED_SUPPLIER_CLAIMS + 5)}
    )
    result = _validate(project, target, doc)
    assert result.exit_code == 0, result.output
    assert "5 further supplier claims omitted" in result.output
    args = ["risk", str(target), "--project", str(project), "--no-project-policy"]
    payload = json.loads(CliRunner().invoke(main, [*args, "--json-output"]).stdout)
    assert len(payload["supplier_claims"]) == MAX_REPORTED_SUPPLIER_CLAIMS
    assert payload["supplier_claims_omitted"] == 5


def test_repository_agent_from_another_checkout_location_is_matched_by_identity(tmp_path):
    project, target, doc = _scanned(tmp_path)
    agent = _agent(doc)
    # The inferred agent's reference and name do not depend on the checkout path, so an
    # inventory of one checkout reconciles with the same tree checked out elsewhere.
    assert (agent["bom_ref"], agent["name"]) == (INFERRED_AGENT_REF, "repository")
    elsewhere = tmp_path / "elsewhere" / "checkout"
    shutil.copytree(project, elsewhere)
    result = _validate(elsewhere, target, doc)
    assert result.exit_code == 0, result.output
    second = {**agent, "bom_ref": "agent:repository:" + "1" * 24}
    result = _validate(elsewhere, target, {**doc, "components": [*doc["components"], second]})
    assert result.exit_code == 1, result.output
    # A reference derived from a checkout path, as 0.1.0 wrote it, names no local agent.
    original = agent["bom_ref"]
    moved = "agent:repository:" + "0" * 24
    agent["bom_ref"] = moved
    agent["name"] = "checkout-elsewhere"
    for edge in doc["dependencies"]:
        edge["source_ref"] = moved if edge["source_ref"] == original else edge["source_ref"]
    result = _validate(elsewhere, target, doc)
    assert result.exit_code == 1, result.output
    assert f"Missing or mismatched local component from agent: {original}" in result.output


def test_validate_project_requires_a_local_subject(tmp_path):
    empty = tmp_path / "empty"
    empty.mkdir()
    claim = {
        "scope": "supplier",
        "surfaces_scanned": ["supplier-pipeline"],
        "scanner_status": dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete"),
    }
    supplied = {
        "metadata": {"completeness": claim},
        "components": [
            {
                "bom_ref": "tool:x",
                "component_type": "tool",
                "name": "x",
                "description_text": "d",
                "definition_hash": hash_tool_definition("x", "d"),
                "definition_hash_version": "rfc8785-jcs-v2",
                "claims": {"tool_definition": {"method": "supplier", "scope": "runtime"}},
            }
        ],
    }
    target = tmp_path / "supplied.json"
    result = _validate(empty, target, supplied)
    assert result.exit_code == 1, result.output
    assert "No local project subject was available to reconcile." in result.output
    report = CompletenessValidator().validate_against_project(AIBOM.load(target), empty)
    assert report.local_subjects == 0 and not report.is_complete


RUNTIME_SURFACES = [
    "runtime",
    "effective-identity",
    "effective-authorization",
    "live-tools",
    "network",
]
COVERAGE_CLAIM = "metadata.completeness"
FAILED = "project-reconciliation-failed"
LISTED = "project-reconciled-with-supplier-claims"
DISCOVERY_REPORT = {
    "version": "1",
    "summary": {"complete": True, "declared_omissions": 0, "tolerated_gaps": 0},
    "stats": [{"errors": [], "skipped": False, "incomplete": False}],
    "findings": [{"id": "reported", "surface": "code", "kind": "agent", "risk": {"level": "high"}}],
}


def _safetensors() -> bytes:
    header = json.dumps({"w": {"dtype": "F32", "shape": [2], "data_offsets": [0, 8]}}).encode()
    return len(header).to_bytes(8, "little") + header + bytes(8)


def _gates(
    project: Path, target: Path, doc: dict, *, skip_integrity: bool = False
) -> tuple[dict, dict]:
    """The `validate --project` and `risk --project` JSON reports for ``doc``."""
    target.write_text(json.dumps(doc))
    common = ["--no-project-policy", "--json-output", str(target), "--project", str(project)]
    runner = CliRunner()
    validate = (
        ["validate", "--skip-integrity", *common] if skip_integrity else ["validate", *common]
    )
    validated, risked = runner.invoke(main, validate), runner.invoke(main, ["risk", *common])
    reports = json.loads(validated.stdout), json.loads(risked.stdout)
    for result, report in zip((validated, risked), reports, strict=True):
        assert result.exit_code == (0 if report["passed"] else 1), result.output
    return reports


def _claims(payload: dict) -> list[tuple[str, str, str]]:
    return [(c["subject"], c["kind"], c["detail"]) for c in payload["supplier_claims"]]


def _assert_refused(validated: dict, risked: dict, reason: str) -> None:
    for payload in (validated, risked):
        assert payload["passed"] is False
        assert payload["assessment_basis"] == FAILED
    assert any(reason in issue["description"] for issue in validated["completeness"]["issues"])
    assert any(reason in gate_reason for gate_reason in risked["gate_reasons"])


def _assert_listed(validated: dict, risked: dict, expected: list[tuple[str, str, str]]) -> None:
    for payload, claimed in ((validated, validated["completeness"]), (risked, risked)):
        assert payload["passed"] is True
        assert payload["assessment_basis"] == LISTED
        assert _claims(claimed) == expected


@pytest.mark.parametrize(
    ("edit", "listed"),
    [
        ("assurance-verified", None),
        ("scope-full-agent", None),
        ("unobserved-surfaces-emptied", None),
        ("one-runtime-surface-observed", None),
        ("repository-scope-verified-and-observed", None),
        ("scope-names-a-discovery-report", None),
        ("full-agent-without-collection-records", None),
        ("runtime-surfaces-scanned", ["surfaces_scanned"]),
        ("exclusions-dropped", ["exclusions"]),
        ("default-exclusion-dropped", ["exclusions"]),
        ("collector-added", ["collectors_requested", "collectors_completed", "scanner_status"]),
    ],
)
def test_coverage_claim_is_reconciled_with_the_local_collection(tmp_path, edit, listed):
    project, target, doc = _scanned(tmp_path)
    claim = doc["metadata"]["completeness"]
    assert (claim["scope"], claim["assurance_level"]) == ("repository", "observed")
    if edit == "assurance-verified":
        claim["assurance_level"] = "verified"
    elif edit == "scope-full-agent":
        claim["scope"] = "full-agent"
    elif edit == "unobserved-surfaces-emptied":
        claim["unobserved_surfaces"] = []
    elif edit == "one-runtime-surface-observed":
        claim["unobserved_surfaces"].remove("network")
    elif edit == "repository-scope-verified-and-observed":
        # `diff --fail-on-alert` reports this edit as two INFO notes only.
        claim.update(assurance_level="verified", unobserved_surfaces=[])
    elif edit == "scope-names-a-discovery-report":
        claim["scope"] = "repository+shadowscan"
    elif edit == "full-agent-without-collection-records":
        # Outside a repository scope the coverage evaluation needs no collection records.
        claim.update(scope="full-agent", collectors_requested=[], collectors_completed=[])
    elif edit == "runtime-surfaces-scanned":
        claim["surfaces_scanned"] = sorted([*claim["surfaces_scanned"], *RUNTIME_SURFACES])
    elif edit == "exclusions-dropped":
        claim["exclusions"] = []
    elif edit == "default-exclusion-dropped":
        claim["exclusions"].remove("**/node_modules")
    else:
        claim["collectors_requested"].append("runtime-probe")
        claim["collectors_completed"].append("runtime-probe")
        claim["scanner_status"]["runtime-probe"] = "complete"
    validated, risked = _gates(project, target, doc)
    completeness = validated["completeness"]
    # Under a project basis the coverage the report states is the local collection's.
    assert completeness["assurance_level"] == "observed"
    assert not set(RUNTIME_SURFACES) & set(completeness["surfaces_covered"])
    if listed is None:
        _assert_refused(validated, risked, "Coverage claim")
    else:
        _assert_listed(validated, risked, [(COVERAGE_CLAIM, "field", name) for name in listed])


@pytest.mark.parametrize("variant", ["plain", "discovery-report", "agent-manifest", "moved"])
def test_honest_scans_reconcile_without_supplier_claims(tmp_path, variant):
    files: dict[str, str | bytes] = {}
    if variant == "discovery-report":
        files["shadowscan.json"] = json.dumps(DISCOVERY_REPORT)
    elif variant == "agent-manifest":
        # The manifest and the instruction file only it declares are collection surfaces.
        files["agent.yaml"] = "name: triage\ninstructions: [docs/rules.md]\n"
        files["docs/rules.md"] = "Answer from the configured tools only.\n"
    project, target, doc = _scanned(tmp_path, files)
    claim = doc["metadata"]["completeness"]
    if variant == "discovery-report":
        assert claim["scope"] == "repository+shadowscan"
    if variant == "agent-manifest":
        assert {"agent.yaml", "docs/rules.md"} <= set(claim["surfaces_scanned"])
    if variant == "moved":
        project = shutil.copytree(project, tmp_path / "elsewhere" / "checkout")
    validated, risked = _gates(project, target, doc)
    for payload, claimed in ((validated, validated["completeness"]), (risked, risked)):
        assert payload["passed"] is True
        assert payload["assessment_basis"] == "project-reconciled"
        assert claimed["supplier_claims"] == []
    assert validated["completeness"]["surfaces_covered"] == claim["surfaces_scanned"]
    assert validated["completeness"]["assurance_level"] == "observed"


def test_inventory_written_under_wider_exclusions_still_reconciles(tmp_path):
    # Exclusions the producer chose beyond the local run's claim less coverage, not more.
    project, target, doc = _scanned(tmp_path)
    doc["metadata"]["completeness"]["exclusions"].append("vendor")
    validated, risked = _gates(project, target, doc)
    assert validated["assessment_basis"] == risked["assessment_basis"] == "project-reconciled"


def test_policy_naming_fewer_default_exclusions_still_reconciles(tmp_path):
    # Dependency caches, virtual environments and Git internals are excluded at every
    # level whatever a policy lists, so a policy that names only some of them excludes
    # what the built-in policy does.
    project, target, _ = _scanned(tmp_path)
    (project / ".nexus-symbiote.yaml").write_text("scan: {exclude_paths: [node_modules, .git]}\n")
    run = CliRunner().invoke(
        main, ["scan", str(project), "--accept-project-policy", "-o", str(target)]
    )
    assert run.exit_code == 0, run.output
    doc = json.loads(target.read_text())
    assert ".venv" not in doc["metadata"]["completeness"]["exclusions"]
    validated, risked = _gates(project, target, doc)
    assert validated["assessment_basis"] == risked["assessment_basis"] == "project-reconciled"


def _deployment_profile(state: str, evidence_status: str) -> dict:
    evidence = {
        "source": "attestation",
        "collector": "operator",
        "collected_at": "2026-01-01T00:00:00Z",
        "subject_digest": "sha256:" + "a" * 64,
        "verification_status": evidence_status,
        "verifier": "verifier",
        "verification_policy": "policy",
        "verified_at": "2026-01-01T00:00:00Z",
    }
    authority = {
        "kind": "effective",
        "state": state,
        "principal": "svc",
        "action": "read",
        "resource": "records",
        "evidence": [evidence],
    }
    return {"deployment_id": "prod", "environment": "prod", "authority": [authority]}


@pytest.mark.parametrize(
    ("state", "evidence_status", "refused"),
    [
        ("verified", "verified", True),
        ("declared", "verified", True),
        ("declared", "unverified", False),
    ],
)
@pytest.mark.parametrize("subject", ["repository-agent", "supplementary-agent"])
def test_deployment_profile_cannot_assert_verified_authority(
    tmp_path, subject, state, evidence_status, refused
):
    project, target, doc = _scanned(tmp_path)
    profile = _deployment_profile(state, evidence_status)
    if subject == "repository-agent":
        # The collector records the agent's deployment as not collected; a profile fills
        # that gap as a claims entry would, and verified evidence may not fill it.
        agent = _agent(doc)
        agent["deployment_profile"] = profile
        expected = [(agent["bom_ref"], "field", "deployment_profile")]
    else:
        doc["components"].append(
            {
                "bom_ref": "agent:prod",
                "component_type": "agent",
                "name": "prod",
                "claims": {"deployment": {"method": "change-ticket", "scope": "runtime"}},
                "deployment_profile": profile,
            }
        )
        expected = [("agent:prod", "component", "supplementary observation")]
    validated, risked = _gates(project, target, doc)
    if refused:
        _assert_refused(validated, risked, "asserts verified assurance")
    else:
        _assert_listed(validated, risked, expected)


SUPPLEMENTARY_EXTENSION = {
    "bom_ref": "verified-extension:supplier/agent-tools",
    "component_type": "verified-extension",
    "name": "agent-tools",
    "source_path": "https://marketplace.example.test/agent-tools",
    "claims": {"publisher": {"method": "marketplace-listing", "scope": "runtime"}},
}


@pytest.mark.parametrize(
    ("fields", "refused"),
    [
        ({"publisher_verified": True}, True),
        ({"attestation_status": "verified"}, True),
        ({"attestation_status": " Verified "}, True),
        ({"component_type": "model", "signing_status": "sigstore-signed"}, True),
        ({"component_type": "model", "signing_status": "digest-pinned"}, True),
        ({"publisher_verified": False, "attestation_status": "unverified"}, False),
    ],
)
def test_supplementary_component_cannot_assert_verification(tmp_path, fields, refused):
    project, target, doc = _scanned(tmp_path)
    extra = {**SUPPLEMENTARY_EXTENSION, **fields}
    if extra["component_type"] == "model":
        extra = {key: extra[key] for key in ("component_type", "name", "claims", "signing_status")}
        extra["bom_ref"] = "model:hosted/agent-tools"
    doc["components"].append(extra)
    validated, risked = _gates(project, target, doc, skip_integrity=True)
    if refused:
        _assert_refused(validated, risked, "asserts verified assurance")
    else:
        _assert_listed(
            validated, risked, [(extra["bom_ref"], "component", "supplementary observation")]
        )


@pytest.mark.parametrize(
    ("fields", "refused"),
    [
        ({"publisher_verified": True}, True),
        ({"attestation_status": "verified"}, True),
        ({"attestation_status": "unverified"}, False),
    ],
)
def test_supplier_fields_on_a_local_package_cannot_assert_verification(tmp_path, fields, refused):
    project, target, doc = _scanned(tmp_path, {"requirements.txt": "langchain==1.2.3\n"})
    package = next(c for c in doc["components"] if c["bom_ref"] == "registry:pypi/langchain")
    assert package.get("publisher_verified") is None and package.get("attestation_status") is None
    package.update(fields)
    validated, risked = _gates(project, target, doc)
    if refused:
        _assert_refused(validated, risked, "asserts verified assurance")
    else:
        _assert_listed(validated, risked, [(package["bom_ref"], "field", name) for name in fields])


def test_trust_the_collector_establishes_on_a_local_model_still_reconciles(tmp_path):
    # An operator digest pin makes the collector record internal-verified trust; only
    # what the supplier adds is examined for verification it cannot establish.
    weights = _safetensors()
    project, target, _ = _scanned(tmp_path, {"models/m.safetensors": weights})
    pins = tmp_path / "pins.json"
    pin = {
        "kind": "digest-pin",
        "artifact_path": "models/m.safetensors",
        "expected_sha256": "sha256:" + hashlib.sha256(weights).hexdigest(),
    }
    pins.write_text(json.dumps({"version": 2, "artifacts": [pin]}))
    common = ["--no-project-policy", "--signature-policy", str(pins)]
    run = CliRunner().invoke(main, ["scan", *common, str(project), "-o", str(target)])
    assert run.exit_code == 0, run.output
    components = json.loads(target.read_text())["components"]
    model = next(c for c in components if c["component_type"] == "model")
    assert model["trust_tier"] == "internal-verified"
    for command in ("validate", "risk"):
        args = [command, *common, "--json-output", str(target), "--project", str(project)]
        result = CliRunner().invoke(main, args)
        assert result.exit_code == 0, result.output
        payload = json.loads(result.stdout)
        assert payload["assessment_basis"] == "project-reconciled"


def _supplementary_guardrail(source_path: str | None) -> dict:
    guardrail = {
        "bom_ref": "guardrail:extra",
        "component_type": "guardrail-policy",
        "name": "extra",
        "claims": {"deployment": {"method": "attested", "scope": "runtime"}},
    }
    if source_path is not None:
        guardrail["source_path"] = source_path
    return guardrail


@pytest.mark.parametrize(
    "source_path",
    [
        "file:///etc/passwd",
        "file://localhost/etc/passwd",
        "FILE:///etc/passwd",
        "policies/a://b.yaml",
        "CLAUDE.md#://",
        "a://b.yaml",
        "https:///etc/passwd",
        "https:CLAUDE.md",
        " https://policies.example.test/prod.yaml",
        "/etc/passwd",
    ],
)
def test_supplementary_component_with_local_provenance_needs_local_evidence(tmp_path, source_path):
    project, target, doc = _scanned(tmp_path)
    doc["components"].append(_supplementary_guardrail(source_path))
    validated, risked = _gates(project, target, doc)
    _assert_refused(
        validated, risked, "Supplied component has no matching local evidence: guardrail:extra"
    )


@pytest.mark.parametrize(
    "source_path",
    [
        "https://policies.example.test/prod.yaml",
        "HTTPS://policies.example.test/prod.yaml",
        "wss://mcp.example.test/socket",
        "git://git.example.test/policies.git",
        None,
    ],
)
def test_remote_supplementary_observation_is_listed(tmp_path, source_path):
    project, target, doc = _scanned(tmp_path)
    doc["components"].append(_supplementary_guardrail(source_path))
    validated, risked = _gates(project, target, doc)
    _assert_listed(
        validated, risked, [("guardrail:extra", "component", "supplementary observation")]
    )


@pytest.mark.parametrize(
    "edit",
    [
        "recommendation-rewritten",
        "references-rewritten",
        "recommendation-removed",
        "finding-added",
        "finding-repeated",
    ],
)
def test_supplier_findings_on_local_components_are_listed(tmp_path, edit):
    project, target, doc = _scanned(tmp_path, {"models/m.safetensors": _safetensors()})
    honest_validated, honest_risk = _gates(project, target, doc, skip_integrity=True)
    assert honest_validated["assessment_basis"] == honest_risk["assessment_basis"]
    assert honest_risk["assessment_basis"] == "project-reconciled"
    model = next(c for c in doc["components"] if c["component_type"] == "model")
    (finding,) = [r for r in model["risks"] if r["category"] == "signing_status"]
    assert finding["severity"] == "high" and finding["recommendation"] and finding["references"]
    revised = (
        model["bom_ref"],
        "risk",
        "high signing_status: remediation differs from the local finding",
    )
    if edit == "recommendation-rewritten":
        finding["recommendation"] = "No action needed; accepted."
        expected = [revised]
    elif edit == "references-rewritten":
        finding["references"] = ["https://attacker.example/accepted-risk"]
        expected = [revised]
    elif edit == "recommendation-removed":
        finding["recommendation"] = None
        finding["references"] = []
        expected = [revised]
    elif edit == "finding-added":
        server = next(c for c in doc["components"] if c["component_type"] == "mcp-server")
        server["risks"].append(
            {
                "severity": "info",
                "category": "supplier_review",
                "detail": "Reviewed and accepted by supplier security team.",
            }
        )
        expected = [
            (server["bom_ref"], "risk", "info supplier_review: not in the local collection")
        ]
    else:
        model["risks"].append(dict(finding))
        expected = [(model["bom_ref"], "risk", "high signing_status: not in the local collection")]
    validated, risked = _gates(project, target, doc, skip_integrity=True)
    _assert_listed(validated, risked, expected)
    # The verdict still rests on the local severity, category and detail of each finding.
    if edit != "finding-repeated":
        assert risked["overall_score"] == honest_risk["overall_score"]
    if edit.endswith(("rewritten", "removed")):
        assert risked["severity_counts"] == honest_risk["severity_counts"]


def test_a_local_finding_cannot_be_reworded_or_removed(tmp_path):
    project, target, doc = _scanned(tmp_path, {"models/m.safetensors": _safetensors()})
    model = next(c for c in doc["components"] if c["component_type"] == "model")
    model["risks"] = [r for r in model["risks"] if r["category"] != "signing_status"]
    validated, risked = _gates(project, target, doc, skip_integrity=True)
    _assert_refused(validated, risked, "Missing or mismatched local component from model files")


@pytest.mark.parametrize(
    ("subject", "key"),
    [
        ("prompt", "content_hash_withheld"),
        ("prompt", "static_value_binding"),
        ("prompt", "static_value_binding_profile"),
        ("prompt", "static_config_hash"),
        ("prompt", "static_card_hash"),
        ("prompt", "weight_files"),
        ("agent", "collection_mode"),
    ],
)
def test_a_supplier_cannot_add_collector_owned_binding_properties(tmp_path, subject, key):
    # Risk fingerprints, integrity and the static binding checks read these keys, so a
    # value only the supplier recorded is refused rather than listed as a claim.
    project, target, doc = _scanned(tmp_path)
    component = (
        _agent(doc)
        if subject == "agent"
        else next(c for c in doc["components"] if c["bom_ref"] == "prompt:CLAUDE.md")
    )
    assert key not in component["properties"]
    component["properties"][key] = "hmac-sha256:" + "0" * 64
    validated, risked = _gates(project, target, doc, skip_integrity=True)
    _assert_refused(
        validated,
        risked,
        "collector-owned properties the local collection did not record: "
        f"{component['bom_ref']} ({key})",
    )


def test_a_supplier_added_hash_cannot_turn_integrity_unknown_into_pass(tmp_path):
    project, target, doc = _scanned(tmp_path)
    server = next(c for c in doc["components"] if c["component_type"] == "mcp-server")
    assert not server["hashes"]
    # The true digest of the server's file: integrity would verify it as recorded evidence.
    server["hashes"] = {"sha256": hashlib.sha256((project / ".mcp.json").read_bytes()).hexdigest()}
    validated, risked = _gates(project, target, doc)
    _assert_refused(
        validated,
        risked,
        f"Missing or mismatched local component from MCP inventory: {server['bom_ref']}",
    )


def _minimum_observed(project: Path, target: Path, doc: dict) -> dict:
    (project / ".nexus-symbiote.yaml").write_text("validate: {minimum_assurance_level: observed}\n")
    target.write_text(json.dumps(doc))
    args = [
        "validate",
        "--skip-integrity",
        "--json-output",
        str(target),
        "--project",
        str(project),
        "--accept-project-policy",
    ]
    return json.loads(CliRunner().invoke(main, args).stdout)


def test_a_supplier_added_observation_cannot_meet_the_minimum_assurance(tmp_path):
    manifest = "name: triage\nmodels: {chat: {provider: example, requested_ref: latest}}\n"
    project, target, doc = _scanned(tmp_path, {"agent.yaml": manifest})
    hosted = next(c for c in doc["components"] if c["bom_ref"].endswith("/hosted/chat"))
    declared = ["minimum observed assurance not attained (1 declared component)"]
    honest = _minimum_observed(project, target, doc)
    assert honest["passed"] is False and honest["assurance_errors"] == declared
    hosted["claims"]["runtime_observation"] = {
        "assurance": "observed",
        "method": "supplier-observer",
        "scope": "runtime",
        "collector": "supplier",
    }
    forged = _minimum_observed(project, target, doc)
    assert forged["completeness"]["status"] == "pass"
    assert (hosted["bom_ref"], "claim", "runtime_observation") in _claims(forged["completeness"])
    assert forged["passed"] is False and forged["assurance_errors"] == declared


def test_an_observation_added_to_a_locally_observed_component_keeps_the_minimum(tmp_path):
    project, target, doc = _scanned(tmp_path)
    assert _minimum_observed(project, target, doc)["passed"] is True
    tool = _tool(doc)
    tool["claims"]["tool_definition"] = {
        "assurance": "observed",
        "method": "operator-pinned-stdio-tools-list",
        "scope": "served-descriptor",
        "collector": "nexus-symbiote-live-stdio",
    }
    recorded = _minimum_observed(project, target, doc)
    assert (tool["bom_ref"], "claim", "tool_definition") in _claims(recorded["completeness"])
    assert recorded["passed"] is True and recorded["assurance_errors"] == []
