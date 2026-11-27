"""Every gate says why it failed, results go to standard output, and validate states its basis."""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote import cli
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.models import (
    AIBOMMetadata,
    CompletenessClaim,
    MCPServerComponent,
    PromptComponent,
)
from nexus_symbiote.operator_policy import render_gate_markdown
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES


def _lines(output: str) -> list[str]:
    return output.splitlines()


def _agent(root: Path, *, pickle: bool = False) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "agent.yaml").write_text("name: Demo\ninstructions: [CLAUDE.md]\n")
    (root / "CLAUDE.md").write_text("Use the configured tools.\n")
    if pickle:
        (root / "classifier.pkl").write_bytes(b"\x80\x04N.")
    return root


def test_an_empty_project_fails_the_scan_gate_with_its_reason(tmp_path):
    result = CliRunner().invoke(main, ["scan", str(tmp_path), "--no-project-policy", "--check"])
    assert result.exit_code == 1
    lines = _lines(result.stderr)
    assert "Scan gate failed" in lines
    assert "  - no agent manifest or supported local inventory evidence was found" in lines


def test_a_scoped_scan_names_the_collectors_it_left_out(tmp_path):
    result = CliRunner().invoke(
        main, ["scan", str(_agent(tmp_path / "p")), "--no-project-policy", "--scanner", "prompt"]
    )
    assert result.exit_code == 1
    lines = _lines(result.stderr)
    assert "  - collection coverage is unknown or incomplete" in lines
    assert any(line.startswith("  - not collected: a2a, code, ide_agents, mcp") for line in lines)
    # Standard output carries only the inventory.
    assert json.loads(result.stdout)["components"]


def test_a_symlink_names_its_collectors_and_failure_once(tmp_path):
    # Every walking collector meets the symlink and records the same failure; the gate
    # lists it once, naming all seven, in alphabetical rather than run order.
    project = _agent(tmp_path / "p")
    (project / "AGENTS.md").symlink_to(project / "CLAUDE.md")
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert result.exit_code == 1
    failures = [line for line in _lines(result.stderr) if line.startswith("  - collection: ")]
    assert failures == [
        "  - collection: AGENTS.md: symlink target is absolute "
        "(from a2a, code, ide_agents, mcp, model, prompt, rag)"
    ]


def test_a_critical_finding_fails_the_scan_gate_and_is_listed(tmp_path):
    project = _agent(tmp_path / "p", pickle=True)
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert result.exit_code == 1
    lines = _lines(result.stderr)
    assert "  - finding at or above critical" in lines
    assert any(
        line.startswith("  - finding: critical ")
        and "classifier.pkl [serialization_format] " in line
        for line in lines
    )
    assert "  - score: 17.0 (fail threshold 50)" in lines


def test_report_only_prints_the_same_reasons_and_passes(tmp_path):
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--no-project-policy", "--report-only", "--check"]
    )
    assert result.exit_code == 0
    lines = _lines(result.stderr)
    assert "Scan gate failed (report only: exit status 0)" in lines
    assert "  - no agent manifest or supported local inventory evidence was found" in lines


def test_check_writes_nothing_and_refuses_an_output(tmp_path):
    project = _agent(tmp_path / "p")
    before = sorted(project.iterdir())
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    assert result.exit_code == 0, result.output
    assert result.stdout == "" and "Scan gate passed" in result.stderr
    assert sorted(project.iterdir()) == before
    refused = CliRunner().invoke(
        main, ["scan", str(project), "--check", "-o", str(tmp_path / "bom.json")]
    )
    assert refused.exit_code == 2 and not (tmp_path / "bom.json").exists()


def test_a_repeated_collector_is_refused(tmp_path):
    result = CliRunner().invoke(
        main, ["scan", str(tmp_path), "--scanner", "mcp", "--scanner", "mcp", "--check"]
    )
    assert result.exit_code == 2
    assert "each collector may be selected only once" in result.output


@pytest.mark.parametrize("command", ["scan", "baseline"])
def test_a_project_path_that_is_a_file_is_a_usage_error(tmp_path, command):
    target = tmp_path / "file.txt"
    target.write_text("x")
    output = tmp_path / "out.json"
    result = CliRunner().invoke(main, [command, str(target), "-o", str(output)])
    assert result.exit_code == 2 and not output.exists()


def _linked(root: Path, count: int) -> Path:
    (root / "target").mkdir(parents=True)
    for index in range(count):
        (root / f"link{index}").symlink_to(root / "target", target_is_directory=True)
    return root


def _more(output: str) -> str:
    (line,) = [line for line in _lines(output) if re.match(r"  - collection: \d+ more", line)]
    return line


def test_a_gate_that_lists_some_gaps_says_where_the_rest_are(tmp_path):
    # Six collectors record each link; the gate lists distinct failures, so more than
    # MAX_SHOWN_FAILURES links are needed before it counts the rest.
    project = _linked(tmp_path / "p", 21)
    runner = CliRunner()
    output = tmp_path / "bom.json"
    written = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert written.exit_code == 1
    assert _more(written.stderr).endswith(
        " more distinct failures in metadata.completeness.scan_failures"
    )
    failures = AIBOM.load(output).metadata.completeness.scan_failures
    assert all(any(f"link{index}:" in failure for failure in failures) for index in range(21))
    # --check (the pre-commit hooks) and baseline keep no inventory to look in.
    checked = runner.invoke(main, ["scan", str(project), "--no-project-policy", "--check"])
    target = tmp_path / "baseline.json"
    staged = runner.invoke(main, ["baseline", str(project), "-o", str(target)])
    for result in (checked, staged):
        assert result.exit_code == 1
        assert "this run keeps no inventory: scan with -o FILE records them all" in _more(
            result.stderr
        )
        assert " more in metadata.completeness" not in result.stderr
    assert not any(line.startswith("Saved ") for line in _lines(staged.stderr))
    assert sorted(path.name for path in tmp_path.iterdir()) == ["bom.json", "p"]


def _risky_bom(tmp_path: Path, *, complete: bool = True) -> Path:
    status = dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete")
    if not complete:
        status["a2a"] = "unknown"
    bom = AIBOM(
        metadata=AIBOMMetadata(
            completeness=CompletenessClaim(
                scope="full-agent",
                surfaces_scanned=["prompts"],
                assurance_level=AssuranceLevel.OBSERVED,
                scanner_status=status,
            )
        ),
        components=[PromptComponent(bom_ref="prompt:1", name="CLAUDE.md", content_hash="x")],
    )
    path = tmp_path / "risk.json"
    bom.save(path)
    return path


def test_risk_names_the_reason_a_low_score_still_fails(tmp_path):
    result = CliRunner().invoke(main, ["risk", str(_risky_bom(tmp_path, complete=False))])
    assert result.exit_code == 1
    lines = _lines(result.stdout)
    assert "Gate: FAILED" in lines
    assert "  - collection coverage is unknown or incomplete" in lines
    assert "  - score: 0.0 (fail threshold 50)" in lines
    assert "Gate (threshold" not in result.output


def test_risk_json_carries_the_verdict_threshold_and_cutoff(tmp_path):
    result = CliRunner().invoke(main, ["risk", str(_risky_bom(tmp_path)), "--json-output"])
    document = json.loads(result.stdout)
    assert result.exit_code == 0 and document["passed"] is True
    assert document["score_threshold"] == 50.0 and document["fail_on_severity"] == "critical"
    assert result.stderr == ""


def test_no_score_threshold_keeps_the_severity_and_coverage_gates(tmp_path):
    runner = CliRunner()
    path = _risky_bom(tmp_path, complete=False)
    result = runner.invoke(main, ["risk", str(path), "--no-score-threshold", "--json-output"])
    document = json.loads(result.stdout)
    assert result.exit_code == 1 and document["score_threshold"] is None
    assert document["gate_reasons"] == ["collection coverage is unknown or incomplete"]
    both = runner.invoke(main, ["risk", str(path), "--no-score-threshold", "--threshold", "5"])
    assert both.exit_code == 2


def test_failed_reconciliation_json_has_the_scored_shape(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "AGENTS.md").write_text("Keep receipts.")
    bom = tmp_path / "bom.json"
    bom.write_text(AIBOM().to_json())
    result = CliRunner().invoke(
        main, ["risk", str(bom), "--project", str(project), "--json-output", "--no-project-policy"]
    )
    assert result.exit_code == 1
    document = json.loads(result.stdout)
    assert document["assessment_basis"] == "project-reconciliation-failed"
    assert document["overall_score"] is None and document["passed"] is False
    assert {"findings", "severity_counts", "total_components"} <= document.keys()


def test_validate_without_project_says_it_checked_only_the_inventorys_claims(tmp_path):
    path = _risky_bom(tmp_path)
    runner = CliRunner()
    result = runner.invoke(main, ["validate", str(path), "--no-project-policy"])
    lines = _lines(result.stdout)
    assert any(
        line.startswith("Assessment basis: supplied-bom: only the inventory's own claims")
        for line in lines
    )
    document = json.loads(
        runner.invoke(main, ["validate", str(path), "--no-project-policy", "--json-output"]).stdout
    )
    assert document["assessment_basis"] == "supplied-bom"
    assert document["passed"] is (result.exit_code == 0)


def test_validate_with_project_says_what_was_reconciled(tmp_path):
    project = _agent(tmp_path / "project")
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    assert runner.invoke(main, ["scan", str(project), "-o", str(bom)]).exit_code == 0
    result = runner.invoke(main, ["validate", str(bom), "--project", str(project)])
    assert result.exit_code == 0, result.output
    assert (
        "Assessment basis: project-reconciled: the inventory was compared with a fresh local "
        f"collection of {project}"
    ) in _lines(result.stdout)
    assert _lines(result.stdout)[-1] == "Validation: PASSED"
    document = json.loads(
        runner.invoke(
            main, ["validate", str(bom), "--project", str(project), "--json-output"]
        ).stdout
    )
    assert document["passed"] is True and document["assessment_basis"] == "project-reconciled"
    assert document["completeness"]["status"] == "pass"
    assert document["integrity"]["status"] == "pass"


SKIP_COMPLETENESS = 'version: "1.0"\nvalidate:\n  require_completeness: false\n'
SKIP_BOTH = SKIP_COMPLETENESS + "  require_integrity: false\n"


def _mcp_project(root: Path, policy: str | None = None) -> Path:
    root.mkdir(parents=True)
    server = {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0"]}
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": {"filesystem": server}}))
    (root / "CLAUDE.md").write_text("Be helpful.\n")
    if policy is not None:
        (root / ".nexus-symbiote.yaml").write_text(policy)
    return root


def _scanned(project: Path, output: Path) -> Path:
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    return output


def _without_mcp(inventory: Path, output: Path) -> Path:
    """The inventory with its MCP server and client deleted, consistently enough to pass."""
    document = json.loads(inventory.read_text())
    dropped = {
        component["bom_ref"]
        for component in document["components"]
        if component["component_type"] in {"mcp-server", "mcp-client"}
    }
    assert dropped
    document["components"] = [c for c in document["components"] if c["bom_ref"] not in dropped]
    for component in document["components"]:
        for key, value in component.items():
            if key.endswith("_refs") and isinstance(value, list):
                component[key] = [ref for ref in value if ref not in dropped]
    document["dependencies"] = [
        edge
        for edge in document["dependencies"]
        if not {edge["source_ref"], edge["target_ref"]} & dropped
    ]
    output.write_text(json.dumps(document))
    return output


@pytest.mark.parametrize(
    ("policy", "inventory", "extra"),
    [
        (SKIP_COMPLETENESS, "forged", []),
        (SKIP_BOTH, "forged", []),
        (SKIP_COMPLETENESS, "forged", ["--skip-integrity"]),
        (SKIP_BOTH, "other-directory", []),
        (SKIP_COMPLETENESS, "other-directory", ["--skip-integrity"]),
    ],
    ids=[
        "completeness-off",
        "completeness-and-integrity-off",
        "completeness-off-skip-integrity",
        "other-directory-both-off",
        "other-directory-skip-integrity",
    ],
)
def test_validate_never_claims_a_comparison_the_policy_skipped(tmp_path, policy, inventory, extra):
    project = _mcp_project(tmp_path / "project", policy)
    if inventory == "forged":
        path = _without_mcp(_scanned(project, tmp_path / "honest.json"), tmp_path / "forged.json")
    else:
        other = tmp_path / "other"
        other.mkdir()
        (other / "CLAUDE.md").write_text("A different agent.\n")
        path = _scanned(other, tmp_path / "other.json")
    args = [
        "validate",
        str(path),
        "--project",
        str(project),
        "--accept-project-policy",
        *extra,
    ]
    runner = CliRunner()
    result = runner.invoke(main, args)
    # The policy still decides the verdict; only the stated basis must be true.
    assert result.exit_code == 0, result.output
    lines = _lines(result.stdout)
    assert (
        "Assessment basis: project-not-reconciled: the completeness check, and with it the "
        f"comparison with {project}, was skipped by policy"
    ) in lines
    assert not any(line.startswith("Assessment basis: project-reconciled") for line in lines)
    assert "compared with a fresh local collection" not in result.stdout
    assert "Pass --project" not in result.stdout
    document = json.loads(runner.invoke(main, [*args, "--json-output"]).stdout)
    assert document["passed"] is True
    assert document["assessment_basis"] == "project-not-reconciled"
    assert document["completeness"] == {"status": "skipped", "skipped_by": "policy"}
    assert "validate.require_completeness=false" in document["policy_weakened"]


def test_validate_reconciles_when_the_project_policy_is_not_read(tmp_path):
    project = _mcp_project(tmp_path / "project", SKIP_BOTH)
    honest = _scanned(project, tmp_path / "honest.json")
    forged = _without_mcp(honest, tmp_path / "forged.json")
    runner = CliRunner()
    built_in = ["--project", str(project), "--no-project-policy", "--json-output"]
    refused = runner.invoke(main, ["validate", str(forged), *built_in])
    assert refused.exit_code == 1, refused.output
    assert json.loads(refused.stdout)["assessment_basis"] == "project-reconciliation-failed"
    reconciled = runner.invoke(main, ["validate", str(honest), *built_in])
    assert reconciled.exit_code == 0, reconciled.output
    assert json.loads(reconciled.stdout)["assessment_basis"] == "project-reconciled"
    without_project = runner.invoke(main, ["validate", str(forged), "--json-output"])
    assert json.loads(without_project.stdout)["assessment_basis"] == "supplied-bom"


def test_the_validation_report_states_only_the_basis_it_was_given():
    from nexus_symbiote.reporting import validation_report_lines

    def basis_line(document: dict) -> tuple[str, str | None]:
        (line,) = [
            entry
            for entry in validation_report_lines(document, project=Path("/work/agent"))
            if entry[0].startswith("Assessment basis: ")
        ]
        return line

    assert basis_line({"assessment_basis": "project-not-reconciled"}) == (
        "Assessment basis: project-not-reconciled: the completeness check, and with it the "
        "comparison with /work/agent, was skipped by policy",
        "yellow",
    )
    assert basis_line({"assessment_basis": "supplied-bom"})[0].endswith(
        "nothing was compared with a project. Pass --project to reconcile it."
    )
    for unknown in ({}, {"assessment_basis": "\x1b[2Jproject-verified"}):
        text, style = basis_line(unknown)
        assert style == "yellow" and "\x1b" not in text
        assert "compared with a fresh" not in text and "Pass --project" not in text
        assert "not a basis this release reports" in text


def test_unknown_integrity_is_named_and_explained(tmp_path):
    bom = AIBOM(
        metadata=AIBOMMetadata(
            completeness=CompletenessClaim(
                scope="full-agent",
                surfaces_scanned=["prompts"],
                scanner_status=dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete"),
            )
        )
    )
    path = tmp_path / "empty.json"
    bom.save(path)
    result = CliRunner().invoke(main, ["validate", str(path), "--no-project-policy"])
    assert result.exit_code == 1
    lines = _lines(result.stdout)
    assert "  Status: UNKNOWN" in lines
    # The integrity validator names the gap itself; the report adds a line only when no
    # issue explains an unknown verdict.
    assert (
        "  UNKNOWN [inventory] No artifact hash or signature could be verified against local "
        "evidence"
    ) in lines
    assert "  UNKNOWN: no hash or signature could be verified" not in lines
    from nexus_symbiote.reporting import validation_report_lines

    unexplained = validation_report_lines(
        {"passed": False, "integrity": {"status": "unknown", "issues": []}}
    )
    assert ("  UNKNOWN: no hash or signature could be verified", None) in unexplained


def test_a_status_cannot_form_a_log_command_by_case_mapping():
    from nexus_symbiote.reporting import validation_report_lines

    # U+017F (long s) upper-cases to "S", so "##vſo[" would become "##VSO[" after the
    # neutralizer had already passed it.
    status = "##vſo[task.setvariable variable=x]1"
    lines = validation_report_lines(
        {"passed": False, "completeness": {"status": status}, "integrity": {"status": status}}
    )
    statuses = [text for text, _ in lines if text.startswith("  Status: ")]
    assert len(statuses) == 2
    assert not any(re.search(r"##[A-Za-z]*\[", text) for text in statuses)


def test_skip_integrity_checks_completeness_only_and_says_so(tmp_path):
    project = _agent(tmp_path / "project", pickle=True)
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    runner.invoke(main, ["scan", str(project), "--report-only", "-o", str(bom)])
    args = ["validate", str(bom), "--project", str(project), "--no-project-policy"]
    assert runner.invoke(main, args).exit_code == 1
    skipped = runner.invoke(main, [*args, "--skip-integrity"])
    assert skipped.exit_code == 0, skipped.output
    assert "  SKIPPED by --skip-integrity: no hash or signature was checked" in _lines(
        skipped.stdout
    )
    document = json.loads(runner.invoke(main, [*args, "--skip-integrity", "--json-output"]).stdout)
    assert document["integrity"] == {"status": "skipped", "skipped_by": "--skip-integrity"}


def test_results_go_to_standard_output_and_diagnostics_to_standard_error(tmp_path):
    project = _agent(tmp_path / "project")
    bom = tmp_path / "bom.json"
    runner = CliRunner()
    scanned = runner.invoke(main, ["scan", str(project), "-o", str(bom)])
    assert scanned.stdout == "" and "Scanning" in scanned.stderr
    for args in (
        ["summary", str(bom)],
        ["validate", str(bom), "--no-project-policy"],
        ["risk", str(bom), "--no-project-policy"],
        ["diff", str(bom), str(bom)],
    ):
        result = runner.invoke(main, args)
        assert result.stdout.strip() and result.stderr == "", args
    summary = json.loads(runner.invoke(main, ["summary", str(bom), "--json-output"]).stdout)
    assert summary["total_components"] == len(AIBOM.load(bom).components)
    assert summary["completeness"]["scope"] == "repository"


def test_diff_lists_a_relationship_only_change(tmp_path):
    components = [
        MCPServerComponent(bom_ref="mcp:a", name="a"),
        MCPServerComponent(bom_ref="mcp:b", name="b"),
    ]
    old, new = tmp_path / "old.json", tmp_path / "new.json"
    AIBOM(components=components).save(old)
    edged = AIBOM(components=components)
    edged.add_dependency(
        DependencyEdge(source_ref="mcp:a", target_ref="mcp:b", relationship="delegates-to")
    )
    edged.save(new)
    result = CliRunner().invoke(main, ["diff", str(old), str(new)])
    assert "1 changes detected" in result.stdout
    assert "+1 relationships added" in _lines(result.stdout)
    assert "  + [HIGH] mcp:a delegates-to mcp:b" in _lines(result.stdout)


def test_unreadable_inventories_name_the_class_of_problem(tmp_path):
    cases = {
        "schema": '{"metadata": "x"}',
        "json": '{"metadata": ',
        "strict": '{"a": 1, "a": 2}',
    }
    # The reader's NativeFormatError names the class of problem, never the content.
    expected = {
        "schema": "It does not match the native AgentBOM schema.",
        "json": "It is not strict UTF-8 JSON",
        "strict": "duplicate keys",
    }
    for name, content in cases.items():
        path = tmp_path / f"{name}.json"
        path.write_text(content)
        result = CliRunner().invoke(main, ["summary", str(path)])
        assert result.exit_code == 1
        assert f"{path} is not a valid native AIBOM file. It " in result.output
        assert expected[name] in result.output


def test_an_unexpected_error_is_a_clean_failure_with_an_opt_in_traceback(tmp_path, monkeypatch):
    path = tmp_path / "bom.json"
    path.write_text(AIBOM().to_json())

    def broken(self: AIBOM) -> dict[str, object]:
        raise KeyError("canary ##[set-output name=x]y")

    monkeypatch.setattr(AIBOM, "summary", broken)
    result = CliRunner().invoke(main, ["summary", str(path)])
    assert result.exit_code == 1 and result.exception.__class__ is SystemExit
    assert "Error: internal error (KeyError)" in result.output
    assert "canary" not in result.output and "Traceback" not in result.output
    debug = CliRunner().invoke(main, ["--debug", "summary", str(path)])
    assert debug.exit_code == 1
    assert all(line.startswith(("Debug: ", "Error: ")) for line in _lines(debug.stderr))
    assert "Debug: KeyError raised at:" in _lines(debug.stderr)
    assert any(line.endswith(" in broken") for line in _lines(debug.stderr))
    # Where it was raised, never the message, which can quote input.
    assert "canary" not in debug.stderr and "##[" not in debug.stderr


def test_an_export_failure_names_the_format_not_the_values(tmp_path, monkeypatch):
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator

    def invalid(self: object, bom: AIBOM) -> str:
        raise ValueError("invalid cyclonedx export: version: '##[set-output name=a]canary'")

    monkeypatch.setattr(CycloneDXGenerator, "generate_json", invalid)
    project = _agent(tmp_path / "project")
    result = CliRunner().invoke(main, ["scan", str(project), "-f", "cyclonedx"])
    assert result.exit_code == 1
    assert "cannot be exported as cyclonedx" in result.output
    assert "canary" not in result.output


def test_shell_completion_cannot_short_circuit_a_gate(tmp_path):
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--check"],
        env={"_NEXUS_SYMBIOTE_COMPLETE": "bash_source"},
        prog_name="nexus-symbiote",
    )
    assert result.exit_code == 1 and "Scan gate failed" in result.output


def test_a_short_binding_key_is_a_usage_error_before_collection(tmp_path, monkeypatch):
    collected = []
    monkeypatch.setattr(cli, "_get_scanners", lambda: collected.append(1) or {})
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--check"],
        env={"NEXUS_SYMBIOTE_SOURCE_BINDING_KEY": "too-short"},
    )
    assert result.exit_code == 2 and not collected
    assert "must contain at least 32 characters" in result.output
    assert "too-short" not in result.output


def test_a_relative_project_that_a_link_leads_elsewhere_is_refused(tmp_path, monkeypatch):
    checkout = tmp_path / "checkout"
    checkout.mkdir()
    elsewhere = _agent(tmp_path / "elsewhere")
    (checkout / "my-agent").symlink_to(elsewhere, target_is_directory=True)
    monkeypatch.chdir(checkout)
    runner = CliRunner()
    refused = runner.invoke(main, ["scan", "my-agent", "--check"])
    assert refused.exit_code == 2
    assert "leads outside the current directory through a symbolic link" in refused.output
    named = runner.invoke(main, ["scan", str(checkout / "my-agent"), "--check"])
    assert named.exit_code == 0, named.output
    assert (
        f"Note: PROJECT_PATH {checkout / 'my-agent'} resolves through a symbolic link to {elsewhere}"
        in _lines(named.stderr)
    )


def test_import_with_markup_in_the_output_path_reports_success(tmp_path):
    report = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
    # Rich read "[/]" in this path as a closing tag and failed after the file was written.
    (tmp_path / "out[").mkdir()
    output = tmp_path / "out[" / "]bom.json"
    assert "[/]" in str(output)
    result = CliRunner().invoke(
        main, ["import-shadowscan", str(report), "-o", str(output), "--report-only"]
    )
    assert result.exit_code == 0, result.output
    assert str(output) in result.output


@pytest.mark.parametrize(
    "args",
    [
        ["--sha256", "sha256:XYZ"],
        ["--sha256", "sha256:" + "0" * 64, "--signer-identity", "x"],
    ],
)
def test_verify_artifact_misuse_is_a_usage_error(tmp_path, args):
    (tmp_path / "a.bin").write_bytes(b"x")
    result = CliRunner().invoke(
        main, ["verify-artifact", "a.bin", "--project", str(tmp_path), *args]
    )
    assert result.exit_code == 2


def test_verify_discovery_names_the_input_that_failed(tmp_path):
    bom, report = tmp_path / "bom.json", tmp_path / "report.json"
    bom.write_text("{")
    report.write_text("{}")
    result = CliRunner().invoke(main, ["verify-discovery", str(bom), str(report)])
    assert result.exit_code == 1
    assert "Cannot safely read the BOM: it is not valid JSON" in result.output


def test_no_color_and_a_pipe_print_no_escape_sequences(tmp_path):
    bom = _risky_bom(tmp_path)
    result = CliRunner().invoke(main, ["risk", str(bom)], env={"NO_COLOR": "1"}, color=True)
    assert "\x1b" not in result.output
    colored = CliRunner().invoke(main, ["risk", str(bom)], color=True)
    assert "\x1b[" in colored.output


def test_baseline_names_why_the_built_in_gate_refused_it(tmp_path):
    project = _agent(tmp_path / "project", pickle=True)
    # The checkout's policy turns the scan gate into a report; the baseline gate holds.
    (project / ".nexus-symbiote.yaml").write_text("scan: {failure_mode: report-only}\n")
    target = tmp_path / "baseline.json"
    result = CliRunner().invoke(
        main, ["baseline", str(project), "--accept-project-policy", "-o", str(target)]
    )
    assert result.exit_code == 1 and not target.exists()
    lines = _lines(result.stderr)
    assert "Built-in scan gate failed; a project policy cannot relax it here:" in lines
    assert "  - finding at or above critical" in lines
    assert "Error: Baseline was not written: static scan gate failed" in lines


def test_sarif_locations_are_relative_to_the_scanned_project(tmp_path, monkeypatch):
    project = tmp_path / "repo" / "services" / "bot"
    (project / "models").mkdir(parents=True)
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp"]}}})
    )
    (project / "models" / "classifier.pkl").write_bytes(b"\x80\x04N.")
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)
    output = tmp_path / "out.sarif"
    result = CliRunner().invoke(
        main, ["scan", str(project), "--report-only", "-f", "sarif", "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    uris = [
        location["physicalLocation"]["artifactLocation"]["uri"]
        for run in json.loads(output.read_text())["runs"]
        for finding in run["results"]
        for location in finding.get("locations", [])
    ]
    assert uris and all((project / uri).exists() for uri in uris), uris


def test_reports_show_coverage_gaps_suppressions_and_omitted_issues():
    from nexus_symbiote.reporting import risk_report_lines, validation_report_lines

    risk = [
        text
        for text, _ in risk_report_lines(
            {
                "passed": False,
                "overall_score": 4.0,
                "gate_reasons": ["collection coverage is unknown or incomplete"],
                "coverage_gaps": ["::error::collector a2a was not run"],
                "suppressed_findings": [{"component_ref": "x", "category": "y"}],
            }
        )
    ]
    assert "  - coverage gap: ::error::collector a2a was not run" in risk
    assert (
        "  - suppressed by project policy: 1 findings (reasons, owners and expiry in --json-output)"
        in risk
    )
    validation = [
        text
        for text, _ in validation_report_lines(
            {
                "passed": False,
                "completeness": {"status": "fail", "issues": [], "issues_omitted": 3},
                "integrity": {"status": "skipped", "skipped_by": "policy"},
            }
        )
    ]
    assert "  ... and 3 more issues, counted in --json-output" in validation


def test_a_missing_choice_option_lists_its_choices_on_their_own_lines(tmp_path):
    envelope, key = tmp_path / "envelope.json", tmp_path / "key.pem"
    envelope.write_text("{}")
    key.write_text("")
    result = CliRunner().invoke(
        main, ["runtime", "verify", str(envelope), "--public-key", str(key)]
    )
    assert result.exit_code == 2
    assert "\ufffd" not in result.output
    lines = _lines(result.output)
    assert "Error: Missing option '--kind'. Choose from:" in lines
    assert {"\tsnapshot,", "\tapproval,", "\ttrust,", "\tmodel"} <= set(lines)


def test_a_command_group_without_arguments_still_prints_its_help():
    result = CliRunner().invoke(main, ["runtime"], prog_name="nexus-symbiote")
    assert result.output.startswith("Usage: nexus-symbiote runtime")
    assert "Commands:" in result.output and "\ufffd" not in result.output


def test_risk_report_lists_severities_from_critical_down():
    from nexus_symbiote.reporting import risk_report_lines

    document = {
        "overall_score": 5.0,
        "risk_level": "high",
        "severity_counts": {"info": 1, "low": 1, "medium": 1, "critical": 1, "high": 1},
    }
    shown = [text.strip(" -").split(":")[0] for text, _ in risk_report_lines(document)]
    start = shown.index("Severity breakdown:".rstrip(":")) + 1
    assert shown[start : start + 5] == ["critical", "high", "medium", "low", "info"]


def test_unscored_risk_report_does_not_claim_components_or_coverage():
    from nexus_symbiote.reporting import risk_report_lines

    document = {
        "passed": False,
        "overall_score": None,
        "assessment_basis": "unsigned-discovery-evidence",
        "discovery_producer": "not-verified",
        "gate_reasons": ["Unsigned evidence."],
    }
    text = "\n".join(line for line, _ in risk_report_lines(document))
    assert "Risk unknown (unsigned-discovery-evidence): not scored." in text
    assert "Discovery producer: not verified (unsigned)" in text
    assert "with risks" not in text and "Coverage" not in text


def test_accepted_unsigned_evidence_is_said_so_when_the_gate_fails_otherwise():
    from nexus_symbiote.reporting import risk_report_lines

    document = {
        "passed": False,
        "overall_score": 80.0,
        "assessment_basis": "supplied-bom",
        "discovery_producer": "not-verified",
    }
    text = "\n".join(line for line, _ in risk_report_lines(document))
    assert "not verified (unsigned evidence accepted)" in text


@pytest.mark.parametrize("command", ["verify-artifact", "verify-discovery"])
@pytest.mark.parametrize("option", ["--trust-root-sha256", "--trust-root"])
def test_a_trust_root_pin_without_a_bundle_is_a_usage_error(tmp_path, command, option):
    (tmp_path / "a.bin").write_bytes(b"x")
    digest = "sha256:" + "0" * 64
    if command == "verify-artifact":
        args = ["a.bin", "--project", str(tmp_path), "--sha256", digest]
    else:
        (tmp_path / "bom.json").write_text(AIBOM().to_json())
        args = [str(tmp_path / "bom.json"), str(tmp_path / "a.bin")]
    value = str(tmp_path / "a.bin") if option == "--trust-root" else "not-a-digest"
    result = CliRunner().invoke(main, [command, *args, option, value])
    assert result.exit_code == 2
    assert "require --bundle" in result.output


@pytest.mark.parametrize("command", ["vex", "advisories"])
def test_inventory_loaders_name_an_unsupported_native_version(tmp_path, command):
    document = AIBOM().to_dict()
    document["metadata"]["spec_version"] = "99.0.0"
    path = tmp_path / "bom.json"
    path.write_text(json.dumps(document))
    extra = ["--dry-run"] if command == "advisories" else []
    result = CliRunner().invoke(main, [command, str(path), *extra])
    assert result.exit_code == 1
    assert "supported: 1.0.x, 1.1.x, 1.2.x" in result.output


def test_gate_reasons_list_the_first_tripped_findings_and_count_the_rest():
    from nexus_symbiote.reporting import LISTED, gate_reason_lines

    findings = [
        {"severity": "critical", "component_name": f"c{index}", "category": "k", "detail": "d"}
        for index in range(LISTED + 3)
    ]
    findings.append({"severity": "low", "component_name": "quiet", "category": "k", "detail": "d"})
    document = {
        "gate_reasons": ["finding at or above high severity"],
        "fail_on_severity": "high",
        "findings": findings,
    }
    lines = [text for text, _ in gate_reason_lines(document)]
    assert lines[0] == "  - finding at or above high severity"
    assert lines[1 : LISTED + 1] == [
        f"  - finding: critical c{index} [k] d" for index in range(LISTED)
    ]
    assert lines[LISTED + 1] == "  - finding: 3 more at or above high"
    assert len(lines) == LISTED + 2
    document["findings"] = findings[:LISTED]
    assert all("more at or above" not in text for text, _ in gate_reason_lines(document))


def test_risk_report_lists_the_first_coverage_gaps_and_points_to_the_json():
    from nexus_symbiote.reporting import LISTED, risk_report_lines

    document = {
        "passed": False,
        "overall_score": 4.0,
        "gate_reasons": ["collection coverage is unknown or incomplete"],
        "coverage_gaps": [f"gap {index:02d}" for index in range(LISTED + 2)],
    }
    lines = [text for text, _ in risk_report_lines(document)]
    listed = [text for text in lines if text.startswith("  - coverage gap: gap ")]
    assert listed == [f"  - coverage gap: gap {index:02d}" for index in range(LISTED)]
    assert "  - coverage gap: 2 more in --json-output" in lines
    document["coverage_gaps"] = document["coverage_gaps"][:LISTED]
    assert all("more in --json-output" not in text for text, _ in risk_report_lines(document))


def test_step_summary_names_completeness_and_discovery_reasons_not_raw_records():
    document = {
        "passed": False,
        "completeness": {
            "status": "fail",
            "issues": [
                {"surface": "tool:x", "description": "Tool x has no hash.", "severity": "error"}
            ],
        },
        "integrity": {"status": "pass", "issues": []},
        "discovery_producer": {"status": "failed", "problems": ["Producer is unverified."]},
    }
    rendered = render_gate_markdown("validate", document)
    assert "- completeness\\: Tool x has no hash\\." in rendered
    assert "- discovery\\_producer\\: Producer is unverified\\." in rendered
    assert "surface" not in rendered


@pytest.mark.parametrize("alias", ["same", "hard link"])
def test_step_summary_onto_an_input_inventory_is_refused(tmp_path, alias):
    inventory = tmp_path / "bom.json"
    bom = AIBOM()
    bom.add_component(MCPServerComponent(bom_ref="mcp:demo", name="demo", transport="stdio"))
    bom.save(inventory)
    before = inventory.read_bytes()
    summary = inventory
    if alias == "hard link":
        summary = tmp_path / "summary.md"
        summary.hardlink_to(inventory)
    for command in (["validate", str(inventory)], ["diff", str(inventory), str(inventory)]):
        result = CliRunner().invoke(main, [*command, "--step-summary", str(summary)])
        assert result.exit_code == 2, result.output
        assert "--step-summary must not name a file this command reads" in result.output
    assert inventory.read_bytes() == before
