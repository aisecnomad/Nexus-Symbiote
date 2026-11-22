"""Precision and drift-regression gate (`make precision`).

Enforces:
1. Committed per-case security regression contracts (`benchmarks/manifest.json`).
2. `model_drift` and `a2a_scope_drift` drift-detection invariants over `AIBOMDiffer`.
3. Per-class recall floors over AIBOM-Bench scores: of a run made now with this checkout
   (`--fresh`), of a supplied score file (`--scores`), or of the committed one.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from benchmark_security import DEFAULT_MANIFEST, load_manifest, run_benchmark  # noqa: E402
from check_security_regressions import regression_failures  # noqa: E402

from nexus_symbiote.core.aibom import AIBOM  # noqa: E402
from nexus_symbiote.core.enums import SerializationSafety  # noqa: E402
from nexus_symbiote.core.models import A2AServerComponent, ModelComponent  # noqa: E402
from nexus_symbiote.diff.differ import AIBOMDiffer  # noqa: E402

# Recorded Corpus A / Corpus B per-class recall floors on main before ShadowScan pair merge.
DEFAULT_CLASS_FLOORS: dict[str, float] = {
    "model-file": 0.80,
    "mcp-server": 0.65,
    "tool": 0.65,
    "skill": 1.00,
    "a2a": 1.00,
    "package": 0.60,
    "vector-store": 0.50,
}


def verify_drift_kinds() -> list[str]:
    """Verify `model_drift` and `a2a_scope_drift` fail `AIBOMDiffer` with security alerts."""
    failures: list[str] = []
    differ = AIBOMDiffer()
    old_m = ModelComponent(
        bom_ref="model:weights/model.safetensors",
        name="weights/model.safetensors",
        source_path="weights/model.safetensors",
        hashes={"sha256": "0" * 64},
        serialization_safety=SerializationSafety.SAFE,
    )
    new_m = old_m.model_copy(
        update={
            "hashes": {"sha256": "f" * 64},
            "serialization_safety": SerializationSafety.UNSAFE_CODE_EXECUTION,
        }
    )
    if not differ.diff(AIBOM(components=[old_m]), AIBOM(components=[new_m])).security_alerts:
        failures.append("model_drift: altered model digest and safety raised no security alert")

    old_a = A2AServerComponent(
        bom_ref="a2a-server:partner",
        name="partner",
        endpoint_url="https://agent.example.com",
        authentication_required=True,
        skills_declared=["read-tickets"],
    )
    new_a = old_a.model_copy(
        update={"authentication_required": False, "skills_declared": ["read-tickets", "admin"]}
    )
    if not differ.diff(AIBOM(components=[old_a]), AIBOM(components=[new_a])).security_alerts:
        failures.append("a2a_scope_drift: widened A2A skills/auth raised no security alert")
    return failures


BENCH_DIR = Path(__file__).resolve().parent.parent / "benchmarks" / "aibom-bench"
FRESH_RUN_SECONDS = 600


def fresh_scores(work: Path, scan_options: tuple[str, ...] = ()) -> dict[str, Any]:
    """Scan a newly built AIBOM-Bench corpus with this checkout and score that run.

    The committed score file records one graded run, so a gate over it only catches a
    commit that lowers the recorded numbers, never a collector that stopped finding a
    class. This run is scored with strict matching and no reviewer overrides: a name in a
    coverage or log line, and a correction made for the graded run, are not detections.
    """
    work = work.resolve(strict=True)
    deadline = time.monotonic() + FRESH_RUN_SECONDS
    corpus, home = work / "corpus", work / "home"
    out = work / "results" / "nexus-symbiote" / "airgap"
    out.mkdir(parents=True)
    home.mkdir()
    overrides = work / "no-overrides.json"
    overrides.write_text('{"overrides": []}\n', encoding="utf-8")
    scores = work / "scores.json"
    # The benchmark runner's environment: an empty HOME and a fixed build date.
    env = {
        **{
            name: value
            for name, value in os.environ.items()
            if not name.startswith("NEXUS_SYMBIOTE_")
        },
        "PYTHONPATH": str(BENCH_DIR.parents[1] / "src"),
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / ".cache"),
        "XDG_CONFIG_HOME": str(home / ".config"),
        "SOURCE_DATE_EPOCH": "1700000000",
    }

    def run(*argv: str) -> int:
        done = subprocess.run(  # noqa: S603 - this interpreter, on files of this checkout
            [sys.executable, *argv],
            cwd=work,
            env=env,
            capture_output=True,
            timeout=max(0.0, deadline - time.monotonic()),
            check=False,
        )
        return done.returncode

    manifest = str(work / "manifest.json")
    status = run(str(BENCH_DIR / "build_corpus.py"), "--out", str(corpus), "--manifest", manifest)
    if status:
        raise ValueError(f"the benchmark corpus could not be built (status {status})")
    inventory = out / "bom.json"
    status = run(
        "-m", "nexus_symbiote", "scan", str(corpus), "-f", "json", "-o", str(inventory),
        *scan_options,
    )  # fmt: skip
    # The corpus plants findings, so the scan gate fails with status 1 and still writes.
    if status not in (0, 1) or not inventory.is_file():
        raise ValueError(f"the scan of the benchmark corpus wrote no inventory (status {status})")
    status = run(
        str(BENCH_DIR / "score.py"),
        "--results", str(work / "results"),
        "--schemas", str(BENCH_DIR / "schemas"),
        "--overrides", str(overrides),
        "--strict",
        "--out", str(scores),
    )  # fmt: skip
    if status:
        raise ValueError(f"the benchmark run could not be scored (status {status})")
    document = json.loads(scores.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("scores root must be an object")
    return document


def evaluate_class_floors(
    scores_doc: dict[str, Any], floors: dict[str, float] = DEFAULT_CLASS_FLOORS
) -> list[str]:
    """Check per-class recall in an AIBOM-Bench score document against recorded floors."""
    import math

    failures: list[str] = []
    per_class = scores_doc.get("per_class_recall")
    if per_class is None:
        per_class = scores_doc.get("classes")
    if per_class is None:
        # The committed AIBOM-Bench layout: {tool: {dataset: {"class_recall": {...}}}}.
        # Only dataset d1 scores component classes; any missing level fails closed below.
        bench = scores_doc.get("nexus-symbiote")
        corpus = bench.get("d1") if isinstance(bench, dict) else None
        per_class = corpus.get("class_recall") if isinstance(corpus, dict) else None
    if not isinstance(per_class, dict):
        return ["scores document missing per_class_recall / classes mapping"]
    for cls_name, floor in sorted(floors.items()):
        if cls_name not in per_class:
            failures.append(f"{cls_name}: missing from scores document")
            continue
        entry = per_class[cls_name]
        recall = entry.get("recall") if isinstance(entry, dict) else entry
        if (
            isinstance(recall, bool)
            or not isinstance(recall, (int, float))
            or not math.isfinite(float(recall))
        ):
            failures.append(f"{cls_name}: invalid recall value")
            continue
        if float(recall) + 1e-9 < floor:
            failures.append(f"{cls_name}: recall {float(recall):.3f} fell below floor {floor:.3f}")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group()
    source.add_argument(
        "--scores", type=Path, default=None, help="Optional AIBOM-Bench scores JSON"
    )
    source.add_argument(
        "--fresh",
        action="store_true",
        help="Build the AIBOM-Bench corpus, scan it with this checkout and gate on that run",
    )
    parser.add_argument(
        "--out", type=Path, default=Path("precision-gate.json"), help="Summary output path"
    )
    args = parser.parse_args(argv)

    manifest, _ = load_manifest(DEFAULT_MANIFEST)
    reg_report = run_benchmark(DEFAULT_MANIFEST)
    failures = regression_failures(reg_report, manifest)
    failures.extend(verify_drift_kinds())

    default_bench = Path("benchmarks/aibom-bench/results/scores.json")
    score_path = args.scores or (default_bench if default_bench.is_file() else None)
    bench_status = "not-present"
    bench_source = "fresh-run" if args.fresh else "score-file"
    scores_doc: object = None
    fresh_recall: dict[str, object] | None = None
    try:
        if args.fresh:
            with tempfile.TemporaryDirectory(prefix="precision-gate-") as work:
                scores_doc = fresh_scores(Path(work))
            measured = scores_doc["nexus-symbiote"]["d1"]["class_recall"]
            fresh_recall = {name: measured.get(name) for name in sorted(DEFAULT_CLASS_FLOORS)}
        elif score_path is not None:
            scores_doc = json.loads(score_path.read_text(encoding="utf-8"))
        if args.fresh or score_path is not None:
            if not isinstance(scores_doc, dict):
                raise ValueError("scores root must be an object")
            floor_failures = evaluate_class_floors(scores_doc)
            failures.extend(floor_failures)
            bench_status = "failed" if floor_failures else "passed"
    except (OSError, ValueError, KeyError, AttributeError, subprocess.TimeoutExpired) as exc:
        # Only this script's own fixed messages are shown; a score file's text is not.
        shown = f": {exc}" if args.fresh and type(exc) is ValueError else ""
        failures.append(f"scores: {type(exc).__name__}{shown}")
        bench_status = "failed"

    summary = {
        "passed": not failures,
        "security_cases": len(reg_report.get("results", [])),
        "drift_kinds_checked": ["model_drift", "a2a_scope_drift"],
        "aibom_bench_status": bench_status,
        "aibom_bench_source": bench_source if bench_status != "not-present" else None,
        "aibom_bench_fresh_class_recall": fresh_recall,
        "failures": failures,
    }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(summary, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    for item in failures:
        print(item)
    print(f"Precision gate: {'PASSED' if not failures else 'FAILED'} ({len(failures)} failures)")
    return int(bool(failures))


if __name__ == "__main__":
    raise SystemExit(main())
