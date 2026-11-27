"""One cause met by seven collectors is reported once, while the inventory keeps seven records.

Every walking collector records the same out-of-root symlink or depth failure, and each
is recorded as not complete. The inventory's records are a contract and stay as they
are; the scan, risk and validate reports, and the Action log that relays them, state
each distinct failure once and the collectors in each state once.
"""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.coverage import (
    MAX_LISTED_GAPS,
    GapKind,
    assess_coverage,
    group_failures,
)
from nexus_symbiote.core.models import CompletenessClaim
from nexus_symbiote.reporting import (
    MAX_SHOWN_FAILURES,
    gate_reason_lines,
    listed_failures,
    risk_report_lines,
    scan_gate_lines,
)
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.utils.confined import ConfinedCollection

ROOT = Path(__file__).resolve().parents[1]
WALKERS = ("a2a", "code", "ide_agents", "mcp", "model", "prompt", "rag")
ESCAPE = "escape: symlink target is absolute"
GROUPED_SCAN = f"  - collection: {ESCAPE} (from {', '.join(WALKERS)})"
RECORDED = f"{ESCAPE} (recorded {len(WALKERS)} times)"
GROUPED_RISK = f"  - collection: {RECORDED}"
COVERAGE = f"Scanner coverage is failed for {', '.join(WALKERS)}."


def _agent(root: Path, *, escaping: bool) -> Path:
    root.mkdir(parents=True)
    (root / "agent.yaml").write_text("name: Demo\ninstructions: [CLAUDE.md]\n")
    (root / "CLAUDE.md").write_text("Use the configured tools.\n")
    if escaping:
        (root / "escape").symlink_to(root.parent / "outside.txt")
    return root


def _lines(text: str) -> list[str]:
    return text.splitlines()


def _scan(project: Path, output: Path) -> None:
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(output)]
    )
    assert result.exit_code == 1, result.output
    assert _lines(result.stderr).count(GROUPED_SCAN) == 1
    assert sum(line.startswith("  - collection: ") for line in _lines(result.stderr)) == 1


def test_one_escaping_symlink_is_one_line_in_each_report_and_seven_records(tmp_path):
    project = _agent(tmp_path / "p", escaping=True)
    output = tmp_path / "bom.json"
    _scan(project, output)
    claim = AIBOM.load(output).metadata.completeness
    assert claim is not None
    assert claim.scan_failures == [ESCAPE] * len(WALKERS)
    assert {name for name, state in claim.scanner_status.items() if state == "failed"} == set(
        WALKERS
    )
    runner = CliRunner()
    risk = runner.invoke(main, ["risk", str(output)])
    assert risk.exit_code == 1
    lines = _lines(risk.stdout)
    assert lines.count(GROUPED_RISK) == 1
    assert lines.count(f"  - coverage gap: {COVERAGE}") == 1
    assert sum(ESCAPE in line for line in lines) == 1
    assert sum("Scanner coverage is" in line for line in lines) == 1
    risk_json = runner.invoke(main, ["risk", str(output), "--json-output"])
    gaps = json.loads(risk_json.stdout)["coverage_gaps"]
    assert gaps.count(RECORDED) == 1
    assert [gap for gap in gaps if gap.startswith("Scanner coverage is")] == [COVERAGE]
    validated = runner.invoke(main, ["validate", str(output)])
    assert validated.exit_code == 1
    assert _lines(validated.stdout).count(f"  ERROR [collection] {RECORDED}") == 1
    assert _lines(validated.stdout).count(f"  ERROR [coverage] {COVERAGE}") == 1
    validated_json = runner.invoke(main, ["validate", str(output), "--json-output"])
    issues = json.loads(validated_json.stdout)["completeness"]["issues"]
    coverage = [issue for issue in issues if issue["description"].startswith("Scanner coverage")]
    assert coverage == [{"surface": "coverage", "description": COVERAGE, "severity": "error"}]
    assert [issue for issue in issues if ESCAPE in issue["description"]] == [
        {
            "surface": "collection",
            "description": RECORDED,
            "severity": "error",
        }
    ]


def test_the_benign_twin_reports_no_failure_and_no_coverage_gap(tmp_path):
    project = _agent(tmp_path / "p", escaping=False)
    output = tmp_path / "bom.json"
    runner = CliRunner()
    scanned = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert scanned.exit_code == 0, scanned.output
    assert not any(line.startswith("  - collection: ") for line in _lines(scanned.stderr))
    claim = AIBOM.load(output).metadata.completeness
    assert claim is not None and claim.scan_failures == []
    assert set(claim.scanner_status.values()) == {"complete"}
    risk = runner.invoke(main, ["risk", str(output), "--json-output"])
    assert risk.exit_code == 0 and json.loads(risk.stdout)["coverage_gaps"] == []
    validated = runner.invoke(main, ["validate", str(output)])
    assert "Scanner coverage is" not in validated.stdout and "recorded" not in validated.stdout


def test_two_runs_of_the_grouped_reports_are_byte_identical(tmp_path):
    project = _agent(tmp_path / "p", escaping=True)
    inventories: list[bytes] = []
    reports: list[str] = []
    for name in ("one", "two"):
        output = tmp_path / f"{name}.json"
        _scan(project, output)
        inventories.append(output.read_bytes())
        risk = CliRunner().invoke(main, ["risk", str(output)])
        reports.append(risk.stdout)
    assert inventories[0] == inventories[1]
    assert reports[0] == reports[1] and GROUPED_RISK in reports[0]


def _action_log(tmp_path: Path, workspace: Path, capsys) -> str:
    spec = importlib.util.spec_from_file_location(
        "grouping_action", ROOT / "scripts" / "run_action.py"
    )
    assert spec is not None and spec.loader is not None
    runner = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = runner
    spec.loader.exec_module(runner)

    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        result = CliRunner().invoke(main, args)
        return subprocess.CompletedProcess(args, result.exit_code, result.stdout, result.stderr)

    config = runner.Config.from_env({"GITHUB_WORKSPACE": str(workspace)})
    assert runner.run(config, command=command, outputs=tmp_path / "out") == 1
    return str(capsys.readouterr().err)


def test_the_action_log_relays_the_grouped_scan_line(tmp_path, capsys):
    workspace = tmp_path / "workspace"
    _agent(workspace, escaping=True)
    log = _action_log(tmp_path, workspace, capsys)
    relayed = [line for line in _lines(log) if "collection: " in line and ESCAPE in line]
    assert len(relayed) == 1 and relayed[0].endswith(GROUPED_SCAN)
    assert (
        f"Collection failed: 1 distinct collection failure ({len(WALKERS)} records) was recorded"
        in log
    )


def test_the_action_summary_omits_the_record_count_when_each_failure_is_recorded_once(
    tmp_path, capsys
):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / ".mcp.json").write_text('{"mcpServers": ')
    log = _action_log(tmp_path, workspace, capsys)
    assert "Collection failed: 1 distinct collection failure was recorded (listed above" in log
    assert "records)" not in log


def test_identical_failures_group_in_first_record_order_and_distinct_ones_stay():
    failures = ["b: x", "a: y", "b: x", "c: z", "b: x", "a: y"]
    assert group_failures(failures) == [("b: x", 3), ("a: y", 2), ("c: z", 1)]
    assert listed_failures(failures) == [
        "b: x (recorded 3 times)",
        "a: y (recorded 2 times)",
        "c: z",
    ]
    assert listed_failures([]) == []
    assert listed_failures(["same", "same "]) == ["same", "same "]


def test_the_gate_counts_distinct_failures_past_the_shown_bound():
    repeated = [f"f{index}" for index in range(MAX_SHOWN_FAILURES + 1)] * 6
    lines = [text for text, _ in gate_reason_lines({}, repeated)]
    assert (
        len([line for line in lines if line.startswith("  - collection: f")]) == MAX_SHOWN_FAILURES
    )
    assert (
        lines[-1]
        == "  - collection: 1 more distinct failures in metadata.completeness.scan_failures"
    )
    exact = [f"f{index}" for index in range(MAX_SHOWN_FAILURES)] * 6
    assert not any("more" in text for text, _ in gate_reason_lines({}, exact))


def test_scan_gate_names_the_collectors_of_each_distinct_failure_sorted():
    # A message that names its only collector itself is not attributed again; one
    # that another collector also recorded names both.
    failures = {
        "prompt": ["a.md: unreadable", "shadowscan: report refused"],
        "mcp": ["a.md: unreadable", "b.json: invalid JSON"],
        "a2a": ["a.md: unreadable"],
        "shadowscan": ["shadowscan: report refused", "shadowscan: report unsigned"],
    }
    lines = [text for text, _ in scan_gate_lines({}, failures, {}, [], recorded=True)]
    assert lines == [
        "  - collection: a.md: unreadable (from a2a, mcp, prompt)",
        "  - collection: shadowscan: report refused (from prompt, shadowscan)",
        "  - collection: b.json: invalid JSON (from mcp)",
        "  - collection: shadowscan: report unsigned",
    ]


def test_risk_report_drops_the_coverage_gap_that_restates_a_grouped_failure():
    document = {
        "passed": False,
        "overall_score": 0.0,
        "gate_reasons": ["collection coverage is unknown or incomplete"],
        "coverage_gaps": [RECORDED, COVERAGE],
    }
    lines = [text for text, _ in risk_report_lines(document, failures=[ESCAPE] * len(WALKERS))]
    assert lines.count(GROUPED_RISK) == 1
    assert lines.count(f"  - coverage gap: {COVERAGE}") == 1
    assert sum(ESCAPE in line for line in lines) == 1


def test_collector_states_collapse_to_one_gap_per_state_with_sorted_names():
    status = dict.fromkeys(BUILTIN_SCANNER_NAMES, "complete")
    status.update({"rag": "failed", "a2a": "failed", "prompt": "partial", "mcp": "failed"})
    claim = CompletenessClaim(scope="repository", surfaces_scanned=["x"], scanner_status=status)
    gaps = [
        gap for gap in assess_coverage(claim).gaps if gap.kind is GapKind.COLLECTOR_NOT_COMPLETE
    ]
    assert [(gap.subject, gap.reason) for gap in gaps] == [
        ("coverage", "Scanner coverage is failed for a2a, mcp, rag."),
        ("coverage", "Scanner coverage is partial for prompt."),
    ]
    assert not assess_coverage(claim).complete


def test_a_claim_with_many_incomplete_collectors_lists_a_bounded_number():
    status = {f"c{index:05d}": f"state{index}" for index in range(MAX_LISTED_GAPS + 50)}
    claim = CompletenessClaim(scope="repository", surfaces_scanned=["x"], scanner_status=status)
    reasons = [
        gap.reason
        for gap in assess_coverage(claim).gaps
        if gap.kind is GapKind.COLLECTOR_NOT_COMPLETE
    ]
    assert len(reasons) == MAX_LISTED_GAPS + 1
    assert reasons[-1] == "50 further collectors are not complete"
    assert sum(reason.count("c0") for reason in reasons[:-1]) == MAX_LISTED_GAPS
    hostile = CompletenessClaim(
        scope="repository",
        surfaces_scanned=["x"],
        scanner_status={"\n::error::x": "failed\x1b[2J", "mcp": "complete"},
    )
    document = {
        "passed": False,
        "overall_score": 0.0,
        "coverage_gaps": assess_coverage(hostile).reasons(),
    }
    rendered = [text for text, _ in risk_report_lines(document)]
    (hostile_line,) = [text for text in rendered if "::error::x" in text]
    assert hostile_line.startswith("  - coverage gap: Scanner coverage is failed")
    for text in rendered:
        assert "\n" not in text and "\x1b" not in text


def test_the_depth_default_is_64_walked_and_65_refused_with_the_same_message(tmp_path):
    assert limits.DEFAULTS.depth == 64
    deep = tmp_path / Path(*[f"d{index}" for index in range(1, 65)])
    deep.mkdir(parents=True)
    (deep / "f64.md").write_text("x")
    (deep / "d65").mkdir()
    (deep / "d65" / "f65.md").write_text("x")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        walked = [path.as_posix() for path in files.iter_files()]
    relative = deep.relative_to(tmp_path).as_posix()
    assert f"{relative}/f64.md" in walked and f"{relative}/d65/f65.md" not in walked
    assert failures == [
        f"{relative}/d65: depth limit of 64 exceeded; raise it with --limit depth=N"
    ]
    raised: list[str] = []
    with ConfinedCollection(tmp_path, raised, max_depth=65) as files:
        assert f"{relative}/d65/f65.md" in [path.as_posix() for path in files.iter_files()]
    assert raised == []
