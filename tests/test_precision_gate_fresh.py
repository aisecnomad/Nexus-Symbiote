"""The precision gate over a benchmark scan made now, not over committed numbers.

A gate that reads the committed AIBOM-Bench score file passes whatever the collectors do,
because nothing recomputes that file. ``--fresh`` builds the benchmark corpus, scans it with
this checkout and applies the class recall floors to that run.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import scripts.check_precision_gate as precision_gate
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES

COMMITTED = precision_gate.BENCH_DIR / "results" / "scores.json"


def test_the_fresh_gate_scores_a_scan_made_by_this_checkout(tmp_path: Path) -> None:
    out = tmp_path / "precision-gate.json"
    assert precision_gate.main(["--fresh", "--out", str(out)]) == 0
    summary = json.loads(out.read_text(encoding="utf-8"))
    assert summary["passed"] is True
    assert (summary["aibom_bench_status"], summary["aibom_bench_source"]) == ("passed", "fresh-run")
    measured = summary["aibom_bench_fresh_class_recall"]
    assert set(measured) == set(precision_gate.DEFAULT_CLASS_FLOORS)
    for name, floor in precision_gate.DEFAULT_CLASS_FLOORS.items():
        assert measured[name] >= floor, name


def test_a_collector_that_stops_finding_a_class_fails_the_fresh_gate(tmp_path: Path) -> None:
    """The regression the committed numbers cannot show: a scan without the MCP collector."""
    without_mcp = tuple(
        argument
        for name in sorted(BUILTIN_SCANNER_NAMES - {"mcp"})
        for argument in ("--scanner", name)
    )
    work = tmp_path / "work"
    work.mkdir()
    scores = precision_gate.fresh_scores(work, scan_options=without_mcp)
    failures = precision_gate.evaluate_class_floors(scores)
    assert any(failure.startswith("mcp-server: recall ") for failure in failures), failures
    committed = json.loads(COMMITTED.read_text(encoding="utf-8"))
    assert precision_gate.evaluate_class_floors(committed) == []


def test_a_fresh_run_that_cannot_be_scored_fails_the_gate(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    work = tmp_path / "work"
    work.mkdir()
    # --check writes no inventory, so there is nothing to score.
    with pytest.raises(ValueError, match="wrote no inventory"):
        precision_gate.fresh_scores(work, scan_options=("--check",))

    def unscorable(_work: Path) -> dict[str, object]:
        raise ValueError("the benchmark run could not be scored")

    monkeypatch.setattr(precision_gate, "fresh_scores", unscorable)
    out = tmp_path / "precision-gate.json"
    assert precision_gate.main(["--fresh", "--out", str(out)]) == 1
    summary = json.loads(out.read_text(encoding="utf-8"))
    assert summary["aibom_bench_status"] == "failed"
    assert summary["failures"] == ["scores: ValueError: the benchmark run could not be scored"]


def test_fresh_and_a_score_file_cannot_be_combined(tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as refused:
        precision_gate.main(["--fresh", "--scores", str(COMMITTED), "--out", str(tmp_path / "o")])
    assert refused.value.code == 2
