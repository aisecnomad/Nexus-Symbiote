"""Project reconciliation imports the edges a collector records between its own components."""

from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path

import pytest
from click.testing import CliRunner

import nexus_symbiote.scanners as scanners_module
from nexus_symbiote import cli
from nexus_symbiote.core.aibom import DependencyEdge
from nexus_symbiote.core.models import AgentComponent, ToolComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.rag import RAGScanner

_TOOL = "tool:code:agent%2Fapp.py/lookup"
_AGENT = "agent:code:agent%2Fapp.py/assistant"


class _EdgeCollector(Scanner):
    """Stands in for ``rag``: one agent, one tool and the edge between them, from source."""

    name = "rag"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        if not (project_root / "agent" / "app.py").is_file():
            return result
        result.components.append(
            ToolComponent(bom_ref=_TOOL, name="lookup", source_path="agent/app.py")
        )
        result.components.append(
            AgentComponent(
                bom_ref=_AGENT, name="assistant", source_path="agent/app.py", tool_refs=[_TOOL]
            )
        )
        result.dependencies.append(
            DependencyEdge(
                source_ref=_AGENT,
                target_ref=_TOOL,
                relationship="invokes",
                assurance_level="declared",
            )
        )
        result.surfaces_scanned.append("agent/app.py")
        return result


@pytest.fixture
def edge_collector(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    registry = cli.SCANNER_REGISTRY
    registry.clear()
    cli._get_scanners()
    saved = dict(registry)
    registry["rag"] = _EdgeCollector
    monkeypatch.setattr(
        scanners_module,
        "ALL_SCANNERS",
        [_EdgeCollector if s is RAGScanner else s for s in scanners_module.ALL_SCANNERS],
    )
    yield
    registry.clear()
    registry.update(saved)


def test_the_edges_a_collector_records_reconcile_against_the_checkout(
    tmp_path: Path, edge_collector: None
) -> None:
    project = tmp_path / "project"
    (project / "agent").mkdir(parents=True)
    (project / "agent" / "app.py").write_text("print('agent')\n")
    (project / "CLAUDE.md").write_text("Instructions.\n")
    out = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        cli.main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    assert scanned.exit_code == 0, scanned.output
    document = json.loads(out.read_text())
    assert any(
        e["source_ref"] == _AGENT and e["target_ref"] == _TOOL and e["relationship"] == "invokes"
        for e in document["dependencies"]
    )
    validated = CliRunner().invoke(
        cli.main, ["validate", str(out), "--project", str(project), "--no-project-policy"]
    )
    assert "no local evidence" not in validated.output, validated.output
    assert "project-reconciliation-failed" not in validated.output, validated.output
    assert "Basis: project-reconciled" in validated.output, validated.output


def test_an_edge_the_collector_did_not_record_is_still_unevidenced(
    tmp_path: Path, edge_collector: None
) -> None:
    project = tmp_path / "project"
    (project / "agent").mkdir(parents=True)
    (project / "agent" / "app.py").write_text("print('agent')\n")
    out = tmp_path / "bom.json"
    scanned = CliRunner().invoke(
        cli.main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(out)]
    )
    assert scanned.exit_code == 0, scanned.output
    document = json.loads(out.read_text())
    document["dependencies"].append(
        {"source_ref": _TOOL, "target_ref": _AGENT, "relationship": "invokes"}
    )
    out.write_text(json.dumps(document))
    validated = CliRunner().invoke(
        cli.main, ["validate", str(out), "--project", str(project), "--no-project-policy"]
    )
    assert "no local evidence" in validated.output, validated.output


@pytest.mark.parametrize("target", ["prompt:absent", "prompt:CLAUDE.md"])
def test_refused_endpoint_is_a_collection_failure_in_scan_and_both_project_gates(
    tmp_path: Path, edge_collector: None, monkeypatch: pytest.MonkeyPatch, target: str
) -> None:
    project = tmp_path / "project"
    (project / "agent").mkdir(parents=True)
    (project / "agent" / "app.py").write_text("print('agent')\n")
    (project / "CLAUDE.md").write_text("Instructions.\n")
    baseline, current = tmp_path / "baseline.json", tmp_path / "current.json"
    runner = CliRunner()
    scan = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    result = runner.invoke(cli.main, [*scan, str(baseline)])
    assert result.exit_code == 0, result.output
    prior_refs = {c["bom_ref"] for c in json.loads(baseline.read_text())["components"]}
    assert "prompt:CLAUDE.md" in prior_refs and "prompt:absent" not in prior_refs

    original_scan = _EdgeCollector.scan

    def collect(self: _EdgeCollector, root: Path) -> ScanResult:
        result = original_scan(self, root)
        result.dependencies.append(
            DependencyEdge(source_ref=_AGENT, target_ref=target, relationship="invokes")
        )
        return result

    monkeypatch.setattr(_EdgeCollector, "scan", collect)
    result = runner.invoke(cli.main, [*scan, str(current)])
    assert result.exit_code == 0, result.output
    claim = json.loads(current.read_text())["metadata"]["completeness"]
    assert "rag: dependency endpoint was not imported" in claim["scan_failures"]
    assert claim["scanner_status"]["rag"] == "failed"

    for command in ("validate", "risk"):
        result = runner.invoke(
            cli.main,
            [
                command,
                str(baseline),
                "--project",
                str(project),
                "--no-project-policy",
                "--json-output",
            ],
        )
        assert result.exit_code == 1, result.output
        report = json.loads(result.stdout)
        assert report["assessment_basis"] == "project-reconciliation-failed"
        if command == "validate":
            claims = report["completeness"]["supplier_claims"]
            coverage = {c["detail"] for c in claims if c["kind"] == "field"}
            assert {"collectors_completed", "scanner_status"} <= coverage
        assert "dependency endpoint was not imported" in result.stdout
