"""Security assertions for scoped graph evidence and policy gates."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner
from pydantic import ValidationError

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import (
    AgentComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.graph import assemble_repository_agent, blast_radius, validate_graph
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.validators.risk import RiskScorer


def test_repository_agent_has_no_runtime_identity_or_autonomy(tmp_path):
    bom = AIBOM()
    bom.add_component(MCPServerComponent(bom_ref="server:s", name="s"))
    bom.add_component(ToolComponent(bom_ref="tool:t", name="t", mcp_server_ref="server:s"))
    bom.add_component(ModelComponent(bom_ref="model:m", name="m"))
    bom.add_component(PromptComponent(bom_ref="prompt:p", name="p"))
    agent = assemble_repository_agent(bom, tmp_path)
    assert agent.deployment_status == "unknown"
    assert agent.deployment_id is agent.workload_identity is agent.autonomy_level is None
    assert agent.claims["repository_presence"].scope == "repository"
    assert agent.claims["deployment"].unknown_reason
    assert not validate_graph(bom)
    reach = blast_radius(bom, "server:s")
    assert reach["affected_agents"] == [agent.bom_ref]
    assert "tool:t" in reach["reachable_components"]
    assert reach["effective_authority"] == "unknown"
    assert all(e.relationship != "invokes" for e in bom.dependencies)
    restored = AIBOM.model_validate(json.loads(bom.to_json()))
    restored_agent = restored.get_component(agent.bom_ref)
    assert restored_agent.autonomy_level is None


def test_declared_agent_id_survives_checkout_move(tmp_path):
    ids = []
    for name in ["first", "moved"]:
        root = tmp_path / name
        root.mkdir()
        (root / "agent.yaml").write_text("id: acme:triager\nname: triager\nowner: security\n")
        ids.append(assemble_repository_agent(AIBOM(), root).bom_ref)
    assert ids[0] == ids[1]


def test_typed_references_and_discriminators():
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a", name="a", model_refs=["p"]),
            PromptComponent(bom_ref="p", name="p"),
        ]
    )
    assert "wrong target type" in validate_graph(bom)[0]
    with pytest.raises(ValidationError):
        DependencyEdge(source_ref="a", target_ref="p", relationship="unknown")
    with pytest.raises(ValidationError):
        ToolComponent(bom_ref="t", name="t", component_type="model")


def test_blast_radius_rejects_invalid_graph():
    bom = AIBOM(components=[AgentComponent(bom_ref="a", name="a", tool_refs=["missing"])])
    with pytest.raises(ValueError, match="invalid graph"):
        blast_radius(bom, "a")


def test_serialization_does_not_change_snapshot_timestamp():
    bom = AIBOM()
    before = bom.to_json()
    bom.finalize()
    assert bom.to_json() == before


def test_critical_gate_independent_of_score_and_explicit_ignore():
    bom = AIBOM(
        components=[
            ModelComponent(
                bom_ref="m",
                name="m",
                risks=[
                    RiskAssessment(
                        severity=RiskSeverity.CRITICAL, category="unsafe", detail="unsafe loader"
                    )
                ],
            )
        ]
    )
    passed, report = RiskScorer(fail_threshold=10000).passes_gate(bom)
    assert not passed and report.overall_score == 10
    assert "finding at or above critical" in report.gate_reasons
    from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim

    bom.metadata = AIBOMMetadata(
        completeness=CompletenessClaim(
            scope="fixture",
            surfaces_scanned=["fixture"],
            scanner_status=dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete"),
        )
    )
    passed, report = RiskScorer(ignore_categories=["unsafe"]).passes_gate(bom)
    assert passed and report.ignored_findings == 1


class FailingScanner:
    def configure(self, *, exclude_paths, accept_default_excludes=False):
        self.exclusions = exclude_paths

    def scan(self, root):
        return ScanResult(scanner_name="mcp", scan_failures=["permission-denied: fixture"])


def test_scanner_failure_nonzero_and_explicit_report_only(tmp_path, monkeypatch):
    monkeypatch.setattr("nexus_symbiote.cli._get_scanners", lambda: {"mcp": FailingScanner})
    runner = CliRunner()
    out = tmp_path / "bom.json"
    args = ["scan", str(tmp_path), "--scanner", "mcp", "-o", str(out)]
    result = runner.invoke(main, args)
    assert result.exit_code == 1
    data = json.loads(out.read_text())
    coverage = data["metadata"]["completeness"]
    assert coverage["scope"] == "repository"
    assert coverage["collectors_completed"] == []
    assert "runtime" in coverage["unobserved_surfaces"]
    assert coverage["scan_failures"]
    assert coverage["assurance_level"] == "declared"
    assert runner.invoke(main, [*args, "--report-only"]).exit_code == 0


def test_policy_exclusions_reach_scanner(tmp_path, monkeypatch):
    seen = []

    class RecordingScanner(FailingScanner):
        def configure(self, *, exclude_paths, accept_default_excludes=False):
            seen.extend(exclude_paths)

        def scan(self, root):
            return ScanResult(scanner_name="mcp")

    monkeypatch.setattr("nexus_symbiote.cli._get_scanners", lambda: {"mcp": RecordingScanner})
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        "scan: {scanners: [mcp], exclude_paths: [vendor]}"
    )
    result = CliRunner().invoke(
        main,
        [
            "scan",
            "--report-only",
            "--accept-project-policy",
            str(tmp_path),
            "-o",
            str(tmp_path / "bom.json"),
        ],
    )
    assert result.exit_code == 0, result.output
    assert seen == ["vendor"]


def test_malformed_policy_is_error_even_report_only(tmp_path):
    (tmp_path / ".nexus-symbiote.yaml").write_text("output: {default_format: invalid}")
    out = tmp_path / "bom.json"
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--report-only", "--accept-project-policy", "-o", str(out)],
    )
    assert result.exit_code != 0 and not out.exists()
    assert "invalid policy" in result.output


def test_blast_radius_cli(tmp_path):
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a", name="a"),
            MCPServerComponent(bom_ref="s", name="s"),
        ],
        dependencies=[
            DependencyEdge(source_ref="a", target_ref="s", relationship="configured-with")
        ],
    )
    path = tmp_path / "bom.json"
    bom.save(path)
    result = CliRunner().invoke(main, ["blast-radius", str(path), "s", "--json-output"])
    assert result.exit_code == 0
    assert json.loads(result.output)["affected_agents"] == ["a"]


def _scanned_project(tmp_path, model_name, *, policy=None, inventory=None):
    project = tmp_path / "project"
    (project / "models").mkdir(parents=True)
    (project / "AGENTS.md").write_text("Use read-only tools.\n")
    # A pickle-family name is rated by its content; any other name holds no pickle.
    pickled = model_name.endswith(".pkl")
    (project / "models" / model_name).write_bytes(b"\x80\x04N." if pickled else b"model bytes")
    if policy is not None:
        (project / ".nexus-symbiote.yaml").write_text(policy)
    inventory = inventory or tmp_path / "bom.json"
    inventory.parent.mkdir(parents=True, exist_ok=True)
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(inventory)]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    return project, inventory


def test_risk_policy_ignored_categories_and_warning_are_honored(tmp_path):
    project, inventory = _scanned_project(
        tmp_path,
        "classifier.pkl",
        policy="risk: {ignore_categories: [serialization_format], warn_threshold: 1}",
    )
    args = [
        "risk",
        str(inventory),
        "--project",
        str(project),
        "--accept-project-policy",
        "--json-output",
    ]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data["assessment_basis"] == "project-reconciled"
    assert data["ignored_findings"] == 1
    assert data["warning_threshold_exceeded"] is True
    assert data["severity_counts"] == {"high": 1}


def test_validation_settings_are_not_ignored(tmp_path):
    bom = AIBOM(components=[ModelComponent(bom_ref="m", name="m")])
    path = tmp_path / "bom.json"
    bom.save(path)
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        "validate: {require_completeness: false, require_integrity: false}"
    )
    result = CliRunner().invoke(
        main, ["validate", str(path), "--project", str(tmp_path), "--accept-project-policy"]
    )
    assert result.exit_code == 0
    assert result.output.count("SKIPPED by explicit policy") == 2
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        "validate: {require_completeness: false, require_integrity: false, "
        "minimum_assurance_level: observed}"
    )
    result = CliRunner().invoke(
        main, ["validate", str(path), "--project", str(tmp_path), "--accept-project-policy"]
    )
    assert result.exit_code != 0
    assert "minimum observed assurance not attained" in result.output


def test_repository_claim_without_collection_evidence_is_incomplete():
    from nexus_symbiote.core.models import AIBOMMetadata, CompletenessClaim
    from nexus_symbiote.validators.completeness import CompletenessValidator

    bom = AIBOM(metadata=AIBOMMetadata(completeness=CompletenessClaim(scope="repository")))
    assert not CompletenessValidator().validate(bom).is_complete


def test_agent_manifest_records_instructions_models_and_declared_autonomy(tmp_path):
    import hashlib

    (tmp_path / "instructions.md").write_bytes(b"Read-only triage instructions.\n")
    (tmp_path / "models").mkdir()
    (tmp_path / "models/weights.safetensors").write_bytes(b"collected model fixture")
    (tmp_path / "agent.yaml").write_text("""
id: acme:triager
name: triager
version: '1.0'
purpose: Security triage
owner: security
framework: custom
autonomy_level: L3-autonomous
instructions: [instructions.md]
models:
  local:
    path: models
  hosted:
    provider: openai
    requested_ref: example-model-alias
""")
    bom = AIBOM(
        components=[
            ModelComponent(
                bom_ref="model:local", name="local", source_path="models/weights.safetensors"
            )
        ]
    )
    agent = assemble_repository_agent(bom, tmp_path)
    assert agent.autonomy_level is None
    assert agent.properties["declared_autonomy_level"] == "L3-autonomous"
    assert agent.claims["autonomy_level"].assurance.value == "declared"
    assert agent.deployment_status == "unknown"
    assert len(agent.prompt_refs) == 1
    prompt = bom.get_component(agent.prompt_refs[0])
    assert (
        prompt.content_hash
        == "sha256:" + hashlib.sha256(b"Read-only triage instructions.\n").hexdigest()
    )
    assert prompt.claims["content_hash"].assurance.value == "observed"
    assert "model:local" in agent.model_refs
    hosted = next(
        comp
        for comp in bom.components
        if isinstance(comp, ModelComponent) and comp.model_type == "hosted"
    )
    assert hosted.bom_ref in agent.model_refs
    assert hosted.requested_alias == "example-model-alias"
    assert hosted.provider == "openai"
    assert hosted.resolved_revision is None
    assert hosted.signing_status is None
    assert hosted.trust_tier.value == "unknown"
    assert hosted.assurance_level.value == "declared"
    assert not validate_graph(bom)


@pytest.mark.parametrize(
    "instruction",
    ["../outside.md", "/outside.md", "missing.md", "linked.md", "symlink-dir/instructions.md"],
)
def test_agent_manifest_instruction_refs_fail_closed_without_partial_bom(tmp_path, instruction):
    from nexus_symbiote.policy import PolicyError

    outside = tmp_path.parent / "outside.md"
    outside.write_text("outside")
    (tmp_path / "linked.md").symlink_to(outside)
    elsewhere = tmp_path.parent / f"{tmp_path.name}-elsewhere"
    elsewhere.mkdir()
    (elsewhere / "instructions.md").write_text("outside")
    (tmp_path / "symlink-dir").symlink_to(elsewhere, target_is_directory=True)
    (tmp_path / "valid.md").write_text("valid instruction")
    (tmp_path / "agent.yaml").write_text(f"name: test\ninstructions: [valid.md, {instruction}]\n")
    bom = AIBOM()
    before = bom.to_json()
    with pytest.raises(PolicyError):
        assemble_repository_agent(bom, tmp_path)
    assert bom.to_json() == before


@pytest.mark.parametrize(
    "declaration",
    [
        "path: ../outside",
        "path: /outside",
        "path: missing",
        "provider: example",
        "requested_ref: alias",
        "path: local\n    provider: example\n    requested_ref: alias",
    ],
)
def test_agent_manifest_model_declarations_fail_closed(tmp_path, declaration):
    from nexus_symbiote.policy import PolicyError

    (tmp_path / "agent.yaml").write_text(
        "name: test\nmodels:\n  invalid:\n    " + declaration + "\n"
    )
    bom = AIBOM()
    with pytest.raises(PolicyError):
        assemble_repository_agent(bom, tmp_path)
    assert not bom.components and not bom.dependencies


def test_agent_manifest_rejects_symlinked_local_model(tmp_path):
    from nexus_symbiote.policy import PolicyError

    outside = tmp_path.parent / "weight-file"
    outside.write_bytes(b"outside model")
    (tmp_path / "local.bin").symlink_to(outside)
    (tmp_path / "agent.yaml").write_text("name: test\nmodels: {local: {path: local.bin}}\n")
    bom = AIBOM(components=[ModelComponent(bom_ref="m", name="m", source_path="local.bin")])
    with pytest.raises(PolicyError):
        assemble_repository_agent(bom, tmp_path)
    assert len(bom.components) == 1
    assert not bom.dependencies


def test_agent_manifest_reuses_instruction_digest_and_rejects_changed_bytes(tmp_path):
    import hashlib

    from nexus_symbiote.policy import PolicyError

    (tmp_path / "instruction.txt").write_bytes(b"approved bytes")
    (tmp_path / "agent.yaml").write_text("name: test\ninstructions: [instruction.txt]\n")
    prompt = PromptComponent(
        bom_ref="p",
        name="p",
        source_path="instruction.txt",
        content_hash="sha256:" + hashlib.sha256(b"approved bytes").hexdigest(),
    )
    bom = AIBOM(components=[prompt])
    agent = assemble_repository_agent(bom, tmp_path)
    assert agent.prompt_refs == ["p"]
    assert len(bom.components) == 2
    (tmp_path / "instruction.txt").write_bytes(b"changed bytes")
    with pytest.raises(PolicyError, match="changed"):
        assemble_repository_agent(AIBOM(components=[prompt]), tmp_path)


def test_policy_source_and_relaxations_are_visible(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    out = tmp_path / "bom.json"
    runner = CliRunner()
    assert (
        runner.invoke(main, ["scan", str(project), "-o", str(out), "--no-project-policy"]).exit_code
        == 0
    )
    builtin = runner.invoke(main, ["risk", str(out), "--no-project-policy", "--json-output"])
    assert json.loads(builtin.output)["policy_source"] == "built-in"
    (project / ".nexus-symbiote.yaml").write_text("risk: {fail_on_severity: none}\n")
    relaxed = runner.invoke(
        main,
        [
            "risk",
            str(out),
            "--project",
            str(project),
            "--accept-project-policy",
            "--json-output",
        ],
    )
    payload = json.loads(relaxed.stdout)
    assert payload["policy_source"].startswith("project:")
    assert payload["policy_weakened"] == ["risk.fail_on_severity=none"]
    human = runner.invoke(
        main, ["risk", str(out), "--project", str(project), "--accept-project-policy"]
    )
    assert "weakens the built-in gates: risk.fail_on_severity=none" in human.output
    shown = runner.invoke(
        main, ["validate", str(out), "--project", str(project), "--accept-project-policy"]
    )
    assert "Policy: project:" in shown.output


def test_policy_relaxation_report_is_exact_and_cannot_rewrite_the_warning(tmp_path):
    project = tmp_path / "team[ci]"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    out = tmp_path / "bom.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", str(project), "-o", str(out), "--no-project-policy"])
    assert scan.exit_code == 0, scan.output
    hostile = "x\\r\\e[2K\\e[32mPolicy: built-in\\e[0m\\n::notice::forged"
    policy_file = project / ".nexus-symbiote.yaml"
    policy_file.write_text(
        f'risk: {{fail_threshold: 50.000001, ignore_categories: ["{hostile}"]}}\n'
    )
    args = ["risk", str(out), "--project", str(project), "--accept-project-policy"]
    report = json.loads(runner.invoke(main, [*args, "--json-output"]).stdout)
    assert report["policy_source"] == f"project:{policy_file}"
    assert report["policy_weakened"] == [
        "risk.fail_threshold=50.000001",
        "risk.ignore_categories=x\r\x1b[2K\x1b[32mPolicy: built-in\x1b[0m\n::notice::forged",
    ]
    stderr = runner.invoke(main, args).stderr
    assert "\x1b" not in stderr and "\r" not in stderr
    assert not any(line.startswith("::") for line in stderr.splitlines())
    (warning,) = [line for line in stderr.splitlines() if "weakens the built-in gates" in line]
    assert warning.startswith(f"WARNING: policy {policy_file} weakens")
    assert warning.endswith("::notice::forged")
    shown = runner.invoke(
        main,
        ["validate", str(out), "--project", str(project), "--accept-project-policy"],
    )
    assert f"Policy: project:{policy_file}" in shown.output


def test_validation_policy_above_project_root_is_ignored(tmp_path):
    project = tmp_path / "anc" / "sub" / "project"
    project.mkdir(parents=True)
    (project / "AGENTS.md").write_text("Keep receipts.")
    out = tmp_path / "bom.json"
    runner = CliRunner()
    scan = runner.invoke(main, ["scan", str(project), "-o", str(out), "--no-project-policy"])
    assert scan.exit_code == 0, scan.output
    (project / "AGENTS.md").write_text("Different instructions.")
    (tmp_path / "anc" / ".nexus-symbiote.yaml").write_text(
        "validate: {require_completeness: false, require_integrity: false}"
    )
    result = runner.invoke(main, ["validate", str(out), "--project", str(project)])
    assert result.exit_code == 1
    assert "SKIPPED by explicit policy" not in result.output


def test_policy_beside_an_inventory_is_not_applied_without_project(tmp_path):
    _, inventory = _scanned_project(tmp_path, "classifier.pkl")
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        "risk: {fail_on_severity: none, fail_threshold: 100}\n"
        "validate: {require_completeness: false, require_integrity: false}\n"
    )
    runner = CliRunner()
    risk = runner.invoke(main, ["risk", str(inventory), "--json-output"])
    assert risk.exit_code == 1
    assert json.loads(risk.stdout)["gate_reasons"]
    assert "was not applied" in risk.stderr
    validate = runner.invoke(main, ["validate", str(inventory)])
    assert "SKIPPED by explicit policy" not in validate.output
    assert "was not applied" in validate.stderr
    quiet = runner.invoke(main, ["risk", str(inventory), "--no-project-policy", "--json-output"])
    assert "was not applied" not in quiet.stderr


def test_policy_notice_names_the_file_literally(tmp_path):
    _, inventory = _scanned_project(
        tmp_path, "classifier.pkl", inventory=tmp_path / "inv[old]" / "bom.json"
    )
    (inventory.parent / ".nexus-symbiote.yaml").write_text("risk: {fail_threshold: 100}\n")
    result = CliRunner().invoke(main, ["risk", str(inventory), "--json-output"])
    assert str(inventory.parent / ".nexus-symbiote.yaml") in result.stderr
    assert "\\[old]" not in result.stderr


def test_shipped_hooks_gate_with_the_built_in_policy_and_write_nothing(tmp_path):
    import shlex

    import yaml

    hooks = yaml.safe_load((Path(__file__).parents[1] / ".pre-commit-hooks.yaml").read_text())
    assert {hook["id"] for hook in hooks} == {"nexus-symbiote-scan", "nexus-symbiote-risk"}
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    # A checkout must not pick the gate it is checked under.
    (project / ".nexus-symbiote.yaml").write_text("scan: {failure_mode: report-only}\n")
    (project / "classifier.pkl").write_bytes(b"\x80\x04N.")
    for hook in hooks:
        program, *args = shlex.split(hook["entry"])
        assert program == "nexus-symbiote"
        assert "--no-project-policy" in args and "-o" not in args and "--output" not in args
        result = CliRunner().invoke(main, [str(project) if a == "." else a for a in args])
        assert result.exit_code == 1, result.output
        assert "Scan gate failed" in result.output and "classifier.pkl" in result.output
        assert sorted(p.name for p in project.iterdir()) == [
            ".nexus-symbiote.yaml",
            "AGENTS.md",
            "classifier.pkl",
        ]


def test_project_policy_applies_through_project_and_is_named_otherwise(tmp_path):
    project, inventory = _scanned_project(
        tmp_path,
        "model.onnx",
        policy='risk: {fail_on_severity: "high"}',
        inventory=tmp_path / "project" / "build" / "bom.json",
    )
    runner = CliRunner()
    unnamed = runner.invoke(main, ["risk", str(inventory), "--json-output"])
    assert unnamed.exit_code == 0, unnamed.output
    assert str(project / ".nexus-symbiote.yaml") in unnamed.stderr
    named = runner.invoke(
        main,
        [
            "risk",
            str(inventory),
            "--project",
            str(project),
            "--accept-project-policy",
            "--json-output",
        ],
    )
    assert named.exit_code == 1
    assert json.loads(named.stdout)["gate_reasons"] == ["finding at or above high"]
