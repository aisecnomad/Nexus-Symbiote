"""Project validation must corroborate a supplied inventory with local observations."""

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.graph import validate_graph
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.validators.completeness import CompletenessValidator


@pytest.fixture(autouse=True)
def unrelated_ancestor_policy(tmp_path):
    # Policy lookup walks every ancestor of a project, and each project here sits
    # below tmp_path. No test in this module is about project policy.
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        "scan:\n"
        "  scanners: [prompt, mcp]\n"
        "  exclude_paths: [AGENTS.md]\n"
        "  failure_mode: report-only\n"
    )


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
    result = runner.invoke(
        main, ["scan", "--report-only", "--no-project-policy", str(root), "-o", str(target)]
    )
    assert result.exit_code == 0, result.output
    args = ["validate", "--project", str(root), "--no-project-policy", str(target)]
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


@pytest.mark.parametrize("edit", ["remove", "repoint", "qualifiers", "duplicate", "root-refs"])
def test_project_gates_bind_repository_relationships(tmp_path, edit):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Review requests.")
    (project / "CLAUDE.md").write_text("Check scope.")
    runner = CliRunner()
    output = tmp_path / "bom.json"
    scan = ["scan", str(project), "--no-project-policy", "-o", str(output)]
    assert runner.invoke(main, scan).exit_code == 0
    validate = ["validate", str(output), "--project", str(project), "--no-project-policy"]
    risk = ["risk", str(output), "--project", str(project), "--no-project-policy", "--json-output"]
    assert runner.invoke(main, validate).exit_code == 0
    assert runner.invoke(main, risk).exit_code == 0

    bom = AIBOM.load(output)
    edge = next(e for e in bom.dependencies if e.target_ref == "prompt:AGENTS.md")
    if edit == "remove":
        bom.dependencies.remove(edge)
    elif edit == "repoint":
        edge.target_ref = "prompt:CLAUDE.md"
    elif edit == "qualifiers":
        edge.assurance_level, edge.conditions = "verified", "always allowed"
    elif edit == "duplicate":
        bom.add_dependency(edge.model_copy())
    else:
        root = bom.get_component(edge.source_ref)
        root.prompt_refs.clear()
    assert not validate_graph(bom)  # References still resolve and have the expected types.
    bom.save(output)
    assert runner.invoke(main, validate).exit_code == 1
    result = runner.invoke(main, risk)
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    assert report["assessment_basis"] == "project-reconciliation-failed"
    assert report["overall_score"] is None


def test_project_reconciliation_preserves_supplementary_live_edges(tmp_path):
    from nexus_symbiote.core.aibom import DependencyEdge
    from nexus_symbiote.core.models import ClaimEvidence, ToolComponent

    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text('{"mcpServers":{"local":{"command":"node"}}}')
    output = tmp_path / "bom.json"
    runner = CliRunner()
    scan = ["scan", str(project), "--no-project-policy", "-o", str(output)]
    assert runner.invoke(main, scan).exit_code == 0
    bom = AIBOM.load(output)
    server = next(c for c in bom.components if c.component_type.value == "mcp-server")
    runtime_tool = ToolComponent(
        bom_ref="tool:observed",
        name="observed",
        mcp_server_ref=server.bom_ref,
        claims={
            "tool_definition": ClaimEvidence(
                assurance="observed",
                scope="served-descriptor",
                method="operator-pinned-stdio-tools-list",
            )
        },
    )
    bom.add_component(runtime_tool)
    agent = next(c for c in bom.components if c.component_type.value == "agent")
    agent.tool_refs.append(runtime_tool.bom_ref)
    bom.add_dependency(
        DependencyEdge(
            source_ref=server.bom_ref,
            target_ref=runtime_tool.bom_ref,
            relationship="provides-tool",
            assurance_level="observed",
        )
    )
    bom.save(output)
    args = ["risk", str(output), "--project", str(project), "--no-project-policy", "--json-output"]
    checked = runner.invoke(main, args)
    assert (
        checked.exit_code == 0
        and json.loads(checked.stdout)["assessment_basis"] == "project-reconciled"
    )


TWO_SERVERS = '{"mcpServers":{"local":{"command":"node"},"other":{"command":"deno"}}}'


def _scanned(tmp_path: Path, files: dict[str, str]) -> tuple[Path, Path, AIBOM]:
    project = tmp_path / "project"
    project.mkdir()
    for name, text in files.items():
        (project / name).write_text(text)
    output = tmp_path / "bom.json"
    scan = ["scan", str(project), "--no-project-policy", "-o", str(output)]
    assert CliRunner().invoke(main, scan).exit_code == 0
    return project, output, AIBOM.load(output)


def _assert_reconciled(project: Path, output: Path) -> None:
    args = ["risk", str(output), "--project", str(project), "--no-project-policy", "--json-output"]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["assessment_basis"] == "project-reconciled"


def _assert_unreconciled(project: Path, output: Path, culprit: str) -> None:
    runner = CliRunner()
    against = [str(output), "--project", str(project), "--no-project-policy"]
    result = runner.invoke(main, ["validate", *against])
    assert result.exit_code == 1, result.output
    assert culprit in result.output
    result = runner.invoke(main, ["risk", *against, "--json-output"])
    assert result.exit_code == 1, result.output
    report = json.loads(result.stdout)
    assert report["assessment_basis"] == "project-reconciliation-failed"
    assert any(culprit in reason for reason in report["gate_reasons"])


@pytest.mark.parametrize(
    ("claimed", "level", "trust", "edge", "referenced"),
    [
        # A record stronger than the supplementary observation.
        ("observed", "declared", "unknown", ("out", "uses-guardrail", "verified"), True),
        ("verified", "declared", "unknown", ("out", "uses-guardrail", "verified"), True),
        ("declared", "declared", "unknown", ("out", "uses-guardrail", "observed"), True),
        ("observed", "declared", "unknown", ("in", "invokes", "verified"), True),
        # A weaker record, or a reference alone, attaches the same control.
        ("verified", "verified", "internal-verified", ("out", "uses-guardrail", "observed"), True),
        ("verified", "verified", "internal-verified", ("out", "uses-guardrail", None), True),
        ("verified", "verified", "internal-verified", None, True),
        ("observed", "observed", "unknown", ("out", "uses-guardrail", "observed"), True),
        ("observed", "observed", "unknown", None, True),
        ("observed", "observed", "unknown", ("in", "invokes", "observed"), False),
        # Nothing offline establishes verified assurance or trust, attached or not.
        ("declared", "verified", "unknown", None, False),
        ("verified", "declared", "unknown", None, False),
        ("observed", "observed", "internal-verified", None, False),
        ("observed", "observed", "third-party-signed", None, False),
    ],
    ids=[
        "verified-record",
        "verified-claim-and-record",
        "record-exceeds-claim",
        "inbound-verified-record",
        "verified-claim-observed-record",
        "verified-claim-unqualified-record",
        "verified-claim-reference-only",
        "observed-record",
        "observed-reference-only",
        "inbound-observed-record",
        "unattached-verified-component",
        "unattached-verified-claim",
        "unattached-verified-trust",
        "unattached-signed-trust",
    ],
)
def test_supplementary_controls_cannot_attach_to_local_subjects(
    tmp_path, claimed, level, trust, edge, referenced
):
    from nexus_symbiote.core.aibom import DependencyEdge
    from nexus_symbiote.core.models import ClaimEvidence, GuardrailComponent

    project, output, bom = _scanned(tmp_path, {"AGENTS.md": "Review requests."})
    agent = next(c for c in bom.components if c.component_type.value == "agent")
    guardrail = GuardrailComponent(
        bom_ref="guardrail:approval-gate",
        name="human approval gate",
        assurance_level=level,
        trust_tier=trust,
        claims={
            "enforcement": ClaimEvidence(assurance=claimed, method="runtime-trace", scope="runtime")
        },
    )
    bom.add_component(guardrail)
    if referenced:
        agent.guardrail_refs.append(guardrail.bom_ref)
    if edge:
        direction, relationship, asserted = edge
        source, target = agent.bom_ref, guardrail.bom_ref
        if direction == "in":
            source, target = target, source
        bom.add_dependency(
            DependencyEdge(
                source_ref=source,
                target_ref=target,
                relationship=relationship,
                assurance_level=asserted,
                conditions="all tool calls mediated",
            )
        )
    assert not validate_graph(bom)
    bom.save(output)
    _assert_unreconciled(project, output, guardrail.bom_ref)


def test_unattached_supplementary_observation_is_kept_unverified(tmp_path):
    from nexus_symbiote.core.models import ClaimEvidence, GuardrailComponent

    project, output, bom = _scanned(tmp_path, {"AGENTS.md": "Review requests."})
    bom.add_component(
        GuardrailComponent(
            bom_ref="guardrail:approval-gate",
            name="human approval gate",
            claims={
                "enforcement": ClaimEvidence(
                    assurance="observed", method="runtime-trace", scope="runtime"
                )
            },
        )
    )
    bom.save(output)
    _assert_reconciled(project, output)


def test_supplied_verified_claim_on_a_local_subject_is_unreconciled(tmp_path):
    from nexus_symbiote.core.models import ClaimEvidence

    project, output, bom = _scanned(tmp_path, {"AGENTS.md": "Review requests."})
    agent = next(c for c in bom.components if c.component_type.value == "agent")
    agent.claims["human_approval"] = ClaimEvidence(
        assurance="verified", method="runtime-trace", scope="runtime"
    )
    bom.save(output)
    _assert_unreconciled(project, output, agent.bom_ref)


def test_supplied_verified_completeness_claim_is_unreconciled(tmp_path):
    from nexus_symbiote.core.enums import AssuranceLevel

    project, output, bom = _scanned(tmp_path, {"AGENTS.md": "Review requests."})
    assert bom.metadata.completeness is not None
    bom.metadata.completeness.assurance_level = AssuranceLevel.VERIFIED
    bom.save(output)
    _assert_unreconciled(project, output, "Completeness claim is verified")


@pytest.mark.parametrize("attachment", ["delegating-agent", "unserved-server"])
def test_other_supplementary_components_cannot_attach_to_local_subjects(tmp_path, attachment):
    from nexus_symbiote.core.models import AgentComponent, ClaimEvidence, MCPServerComponent

    project, output, bom = _scanned(tmp_path, {"AGENTS.md": "Review requests."})
    agent = next(c for c in bom.components if c.component_type.value == "agent")
    runtime = {
        "observation": ClaimEvidence(assurance="observed", method="runtime-trace", scope="runtime")
    }
    extra: AgentComponent | MCPServerComponent
    if attachment == "delegating-agent":
        extra = AgentComponent(bom_ref="agent:orchestrator", name="orchestrator", claims=runtime)
    else:
        extra = MCPServerComponent(bom_ref="mcp:remote", name="remote", claims=runtime)
    bom.add_component(extra)
    bom.save(output)
    _assert_reconciled(project, output)
    if isinstance(extra, AgentComponent):
        extra.sub_agent_refs.append(agent.bom_ref)
    else:
        agent.tool_refs.append(extra.bom_ref)
    assert not validate_graph(bom)
    bom.save(output)
    _assert_unreconciled(project, output, extra.bom_ref)


@pytest.mark.parametrize(
    "variant",
    [
        "foreign-provider",
        "foreign-listing",
        "verified-provider",
        "unsupported-provider",
        "invoked",
        "unserved",
    ],
)
def test_recorded_tools_attach_only_through_their_serving_server(tmp_path, variant):
    from nexus_symbiote.core.aibom import DependencyEdge
    from nexus_symbiote.core.enums import AssuranceLevel
    from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent

    project, output, bom = _scanned(tmp_path, {".mcp.json": TWO_SERVERS})
    local, other = sorted(
        (c for c in bom.components if isinstance(c, MCPServerComponent)), key=lambda c: c.name
    )
    agent = next(c for c in bom.components if c.component_type.value == "agent")
    served = ClaimEvidence(
        assurance="observed", scope="served-descriptor", method="operator-pinned-stdio-tools-list"
    )
    tool = ToolComponent(
        bom_ref="tool:observed",
        name="observed",
        mcp_server_ref=local.bom_ref,
        assurance_level="observed",
        claims={"tool_definition": served},
    )
    bom.add_component(tool)
    provided = DependencyEdge(
        source_ref=local.bom_ref,
        target_ref=tool.bom_ref,
        relationship="provides-tool",
        assurance_level="observed",
    )
    bom.add_dependency(provided)
    local.tool_refs.append(tool.bom_ref)
    agent.tool_refs.append(tool.bom_ref)
    bom.save(output)
    _assert_reconciled(project, output)

    if variant == "foreign-provider":
        bom.add_dependency(provided.model_copy(update={"source_ref": other.bom_ref}))
    elif variant == "foreign-listing":
        other.tool_refs.append(tool.bom_ref)
    elif variant == "verified-provider":
        provided.assurance_level = "verified"
    elif variant == "unsupported-provider":
        served.assurance = AssuranceLevel.DECLARED
    elif variant == "invoked":
        invoked = {"source_ref": agent.bom_ref, "relationship": "invokes"}
        bom.add_dependency(provided.model_copy(update=invoked))
    else:
        tool.mcp_server_ref = None
    assert not validate_graph(bom)
    bom.save(output)
    _assert_unreconciled(project, output, tool.bom_ref)


def test_recorded_tool_with_an_additional_weaker_claim_still_reconciles(tmp_path):
    from nexus_symbiote.core.aibom import DependencyEdge
    from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent

    project, output, bom = _scanned(tmp_path, {".mcp.json": TWO_SERVERS})
    local = min(
        (c for c in bom.components if isinstance(c, MCPServerComponent)), key=lambda c: c.name
    )
    # The provides-tool record may claim as much as the tool's strongest claim.
    tool = ToolComponent(
        bom_ref="tool:observed",
        name="observed",
        mcp_server_ref=local.bom_ref,
        assurance_level="observed",
        claims={
            "tool_definition": ClaimEvidence(
                assurance="observed",
                scope="served-descriptor",
                method="operator-pinned-stdio-tools-list",
            ),
            "publisher_listing": ClaimEvidence(
                assurance="declared", scope="vendor-listing", method="supplier-statement"
            ),
        },
    )
    bom.add_component(tool)
    local.tool_refs.append(tool.bom_ref)
    bom.add_dependency(
        DependencyEdge(
            source_ref=local.bom_ref,
            target_ref=tool.bom_ref,
            relationship="provides-tool",
            assurance_level="observed",
        )
    )
    bom.save(output)
    _assert_reconciled(project, output)


def test_recorded_live_observation_still_reconciles(tmp_path, monkeypatch):
    from nexus_symbiote.live.verify import record_candidate, verify_mcp_servers

    project, output, bom = _scanned(tmp_path, {".mcp.json": TWO_SERVERS})
    served = {
        "name": "observed",
        "description": "Served at run time only",
        "inputSchema": {"type": "object", "properties": {}},
    }
    monkeypatch.setattr(
        "nexus_symbiote.live.verify.fetch_tools_from_config",
        lambda *args, **kwargs: ("stdio", [served]),
    )
    report = verify_mcp_servers(bom)
    assert [f.status for r in report.results for f in r.tool_findings] == ["new", "new"]
    record_candidate(bom, report)
    bom.save(output)
    checked = CompletenessValidator().validate_against_project(bom, project)
    assert checked.is_complete, [issue.description for issue in checked.issues]
    _assert_reconciled(project, output)


@pytest.mark.parametrize("basename", ["agent", "agent-ci-clone"])
def test_relative_subjects_still_reconcile_after_moving_or_renaming_a_checkout(tmp_path, basename):
    root = tmp_path / "original" / "agent"
    root.mkdir(parents=True)
    (root / "AGENTS.md").write_text("Check scope.")
    output = tmp_path / "bom.json"
    runner = CliRunner()
    scan = ["scan", str(root), "--no-project-policy", "-o", str(output)]
    assert runner.invoke(main, scan).exit_code == 0
    bom = AIBOM.load(output)
    prompt = bom.get_component("prompt:AGENTS.md")
    prompt.source_path = "AGENTS.md"
    bom.save(output)
    moved = tmp_path / "relocated" / basename
    moved.parent.mkdir()
    root.rename(moved)
    # The inferred root's reference and name both derive from the original path.
    inferred = next(c for c in bom.components if c.component_type.value == "agent")
    assert inferred.name == "agent"
    against = [str(output), "--project", str(moved), "--no-project-policy"]
    validated = runner.invoke(main, ["validate", *against])
    assert validated.exit_code == 0, validated.output
    checked = runner.invoke(main, ["risk", *against, "--json-output"])
    assert (
        checked.exit_code == 0
        and json.loads(checked.stdout)["assessment_basis"] == "project-reconciled"
    )


def test_absolute_source_paths_do_not_follow_a_moved_checkout(tmp_path):
    root = tmp_path / "original" / "agent"
    root.mkdir(parents=True)
    (root / "AGENTS.md").write_text("Check scope.")
    output = tmp_path / "bom.json"
    runner = CliRunner()
    assert (
        runner.invoke(main, ["scan", str(root), "--no-project-policy", "-o", str(output)]).exit_code
        == 0
    )
    prompt = AIBOM.load(output).get_component("prompt:AGENTS.md")
    assert prompt is not None and Path(prompt.source_path).is_absolute()
    moved = tmp_path / "relocated" / "agent"
    moved.parent.mkdir()
    root.rename(moved)
    against = [str(output), "--project", str(moved), "--no-project-policy"]
    validated = runner.invoke(main, ["validate", *against])
    assert validated.exit_code == 1, validated.output
    assert "Artifact path escapes the supplied project root" in validated.output


def test_the_inferred_root_agent_name_is_not_evidence(tmp_path):
    project, output, bom = _scanned(tmp_path, {"AGENTS.md": "Review requests."})
    agent = next(c for c in bom.components if c.component_type.value == "agent")
    assert agent.properties["identity_source"] == "repository-path"
    agent.name = "payments-approval-agent"
    bom.save(output)
    against = [str(output), "--project", str(project), "--no-project-policy"]
    assert CliRunner().invoke(main, ["validate", *against]).exit_code == 0
    _assert_reconciled(project, output)


def test_deployment_profiles_keep_their_producer_reported_state(tmp_path):
    from datetime import UTC, datetime

    from nexus_symbiote.core.evidence import AuthorityClaim, DeploymentProfile, EvidenceRecord

    project, output, bom = _scanned(tmp_path, {"AGENTS.md": "Review requests."})
    agent = next(c for c in bom.components if c.component_type.value == "agent")
    now = datetime.now(UTC)
    evidence = EvidenceRecord(
        source="iam",
        collector="exporter",
        collected_at=now,
        subject_digest="sha256:" + "0" * 64,
        verification_status="verified",
        verifier="verifier",
        verification_policy="policy",
        verified_at=now,
    )
    claim = AuthorityClaim(
        kind="effective",
        state="verified",
        principal="agent",
        action="deploy",
        resource="prod",
        evidence=[evidence],
    )
    agent.deployment_profile = DeploymentProfile(
        deployment_id="prod", environment="production", authority=[claim]
    )
    bom.save(output)
    against = [str(output), "--project", str(project), "--no-project-policy"]
    assert CliRunner().invoke(main, ["validate", *against]).exit_code == 0
    _assert_reconciled(project, output)


def test_provides_tool_conditions_are_kept_as_supplied(tmp_path):
    from nexus_symbiote.core.aibom import DependencyEdge
    from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent

    project, output, bom = _scanned(tmp_path, {".mcp.json": TWO_SERVERS})
    local = min(
        (c for c in bom.components if isinstance(c, MCPServerComponent)), key=lambda c: c.name
    )
    served = ClaimEvidence(
        assurance="observed", scope="served-descriptor", method="operator-pinned-stdio-tools-list"
    )
    tool = ToolComponent(
        bom_ref="tool:observed",
        name="observed",
        mcp_server_ref=local.bom_ref,
        assurance_level="observed",
        claims={"tool_definition": served},
    )
    bom.add_component(tool)
    local.tool_refs.append(tool.bom_ref)
    bom.add_dependency(
        DependencyEdge(
            source_ref=local.bom_ref,
            target_ref=tool.bom_ref,
            relationship="provides-tool",
            assurance_level="observed",
            conditions="human approval enforced for every call",
        )
    )
    bom.save(output)
    _assert_reconciled(project, output)
