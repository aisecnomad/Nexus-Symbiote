"""Run the versioned, labeled inventory cases locally against the installed collectors.

The public CLI runs only the coverage-gate and policy controls.
"""

import hashlib
import json
import sys
import tempfile
from collections import Counter
from pathlib import Path

from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.core.models import (
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.base import read_regular_text
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import ModelScanner
from nexus_symbiote.validators.risk import RiskScorer

DIRECTORY = Path(__file__).resolve().parent


def score_tools(
    predicted: set[str],
    expected: list[str],
    decoys: list[str],
    *,
    collection_incomplete: bool = False,
) -> dict:
    """Score only labeled tools and explicitly labeled non-tools.

    An unexpected, unlabeled name fails the case but does not become a false
    positive in a closed-world confusion matrix without an adjudicated label.
    Missing labels are unknown when collection is incomplete, not false or true negatives.
    """
    if (
        len(set(expected)) != len(expected)
        or len(set(decoys)) != len(decoys)
        or set(expected) & set(decoys)
    ):
        raise ValueError("Tool and decoy labels must be unique and disjoint")
    positives, negatives = set(expected), set(decoys)
    return {
        "tp": len(predicted & positives),
        "fn": 0 if collection_incomplete else len(positives - predicted),
        "fp": len(predicted & negatives),
        "tn": 0 if collection_incomplete else len(negatives - predicted),
        "unknown_positive_labels": len(positives - predicted) if collection_incomplete else 0,
        "unknown_negative_labels": len(negatives - predicted) if collection_incomplete else 0,
        "unexpected_unlabeled": sorted(predicted - positives - negatives),
    }


def label_bounds(scores: dict) -> dict:
    """Bound recall and specificity over explicit labels when collection is incomplete.

    These are deterministic best/worst cases for the unobserved labels, not
    statistical confidence intervals or estimates for unlabeled predictions.
    """

    def interval(success: int, failure: int, unknown: int) -> dict:
        total = success + failure + unknown
        return {
            "label_count": total,
            "observed_count": success + failure,
            "unknown_count": unknown,
            "lower": success / total if total else None,
            "upper": (success + unknown) / total if total else None,
        }

    return {
        "recall": interval(scores["tp"], scores["fn"], scores["unknown_positive_labels"]),
        "specificity": interval(scores["tn"], scores["fp"], scores["unknown_negative_labels"]),
    }


def critical_gate(report) -> bool:
    """The gate fails because of a critical finding, not merely because it fails."""
    return report.severity_counts.get("critical", 0) > 0 and any(
        "critical" in reason for reason in report.gate_reasons
    )


def unknown_coverage_gate(project: Path, scratch: Path) -> bool:
    """The real scan, with every collector, refuses a project that yields no evidence."""
    runner = CliRunner()
    output = scratch / "gate.json"
    output.unlink(missing_ok=True)
    scanned = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    if scanned.exit_code == 0 or not output.exists():
        return False
    risk = runner.invoke(main, ["risk", str(output), "--json-output", "--no-project-policy"])
    try:
        reasons = json.loads(risk.stdout).get("gate_reasons")
    except ValueError:
        return False
    return risk.exit_code != 0 and isinstance(reasons, list) and bool(reasons)


def policy_rejected(project: Path, scratch: Path) -> bool:
    """An accepted checkout policy that is invalid is refused before anything is written.

    A project policy is not applied unless ``--accept-project-policy`` is passed.
    When it is, a malformed policy stops the scan before an inventory is written.
    A scan that merely fails its gate still writes the inventory, so a fixture that
    also fails the gate cannot pass this check.
    """
    output = scratch / "policy.json"
    output.unlink(missing_ok=True)
    result = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--accept-project-policy",
            "--report-only",
            "-o",
            str(output),
        ],
    )
    return result.exit_code != 0 and not output.exists() and "policy" in result.output.lower()


def operator_policy_isolated(project: Path, scratch: Path) -> bool:
    """With the operator's --no-project-policy the hostile policy cannot hide the model."""
    output = scratch / "isolated.json"
    output.unlink(missing_ok=True)
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )
    if result.exit_code != 0 or not output.exists():
        return False
    components = json.loads(output.read_text()).get("components", [])
    return any(c.get("component_type") == "model" for c in components)


def run() -> dict:
    manifest = parse_json_strict(read_regular_text(DIRECTORY / "manifest.json"))
    rows = []
    totals = Counter()
    for case in manifest["cases"]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            project = root / "input"
            project.mkdir()
            files = {k: v.encode() for k, v in case.get("files", {}).items()}
            files.update({k: bytes.fromhex(v) for k, v in case.get("hex_files", {}).items()})
            if "fixture" in case:
                relative = Path(case["fixture"])
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("Fixture path must stay in the committed corpus")
                source = read_regular_text(DIRECTORY / "fixtures" / relative).encode("utf-8")
                if hashlib.sha256(source).hexdigest() != case["sha256"]:
                    raise ValueError("Reference source does not match its pinned digest")
                files[case["file"]] = source
            for name, data in files.items():
                relative = Path(name)
                if relative.is_absolute() or ".." in relative.parts:
                    raise ValueError("Case input paths must be relative and confined")
                path = project / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            bom = AIBOM()
            failures, exclusions = [], []
            mcp_exclusions = []
            statuses = {}
            for scanner in (MCPScanner(), ModelScanner()):
                collected = scanner.scan(project)
                for component in collected.components:
                    try:
                        bom.add_component(component)
                    except ValueError:
                        failures.append("conflicting scanner component identity")
                failures.extend(collected.scan_failures)
                exclusions.extend(collected.surfaces_excluded)
                if scanner.name == "mcp":
                    mcp_exclusions.extend(collected.surfaces_excluded)
                statuses[scanner.name] = (
                    "failed"
                    if collected.scan_failures
                    else "partial"
                    if collected.surfaces_excluded
                    else "complete"
                )
            bom.metadata.completeness = CompletenessClaim(
                scope="inventory-regression",
                scanner_status=statuses,
                scan_failures=failures,
                surfaces_excluded=exclusions,
            )
            output = root / "result.json"
            output.write_text(bom.to_json())
            tools = [c for c in bom.components if isinstance(c, ToolComponent)]
            servers = [c for c in bom.components if isinstance(c, MCPServerComponent)]
            models = [c for c in bom.components if isinstance(c, ModelComponent)]
            predicted = {t.name for t in tools}
            expected = set(case["tools"])
            checks = {}
            for name in case.get("checks", []):
                if name == "distinct_scoped_edges":
                    by_ref = {s.bom_ref: s for s in servers}
                    ok = len(by_ref) == 2 and all(
                        t.mcp_server_ref in by_ref
                        and t.bom_ref in by_ref[t.mcp_server_ref].tool_refs
                        for t in tools
                    )
                elif name == "origin_only":
                    ok = {s.endpoint_url for s in servers} == {
                        "http://localhost.attacker.invalid",
                        "https://trusted.invalid",
                    }
                elif name == "no_secret_in_bom":
                    ok = "SECRET_BENCH_MARKER" not in output.read_text()
                elif name == "deceptive_localhost_flagged":
                    ok = any(
                        r.category == "transport_security"
                        for s in servers
                        if s.endpoint_url == "http://localhost.attacker.invalid"
                        for r in s.risks
                    )
                elif name in {"unsafe_format", "safe_format", "unknown_format"}:
                    expected_format = {
                        "unsafe_format": "unsafe-code-execution",
                        "safe_format": "safe",
                        "unknown_format": "unknown",
                    }[name]
                    ok = (
                        len(models) == 1 and models[0].serialization_safety.value == expected_format
                    )
                elif name in {"unsigned", "signer_unverified"}:
                    expected_status = {
                        "unsigned": "signature-not-found",
                        "signer_unverified": "signature-present-unverified",
                    }[name]
                    ok = (
                        len(models) == 1
                        and not models[0].signing_identity
                        and models[0].signing_status == expected_status
                    )
                elif name == "critical_gate":
                    ok = critical_gate(RiskScorer().score(bom))
                elif name == "unknown_coverage_gate":
                    ok = unknown_coverage_gate(project, root)
                elif name == "policy_rejected":
                    ok = policy_rejected(project, root)
                elif name == "operator_policy_isolated":
                    ok = operator_policy_isolated(project, root)
                else:
                    raise ValueError(f"Unknown benchmark assertion {name}")
                checks[name] = ok
            misses, extras = sorted(expected - predicted), sorted(predicted - expected)
            relevant_exclusions = sorted(mcp_exclusions)
            has_tool_labels = bool(case["tools"] or case["decoys"])
            incomplete = bool(failures or (has_tool_labels and relevant_exclusions))
            scores = score_tools(
                predicted, case["tools"], case["decoys"], collection_incomplete=incomplete
            )
            expected_exclusions = sorted(case.get("expected_mcp_exclusions", []))
            exclusions_match = not has_tool_labels or relevant_exclusions == expected_exclusions
            totals.update(
                {
                    k: scores[k]
                    for k in (
                        "tp",
                        "fp",
                        "fn",
                        "tn",
                        "unknown_positive_labels",
                        "unknown_negative_labels",
                    )
                }
            )
            rows.append(
                {
                    "case": case["id"],
                    "tools": sorted(predicted),
                    "missing": misses,
                    "unexpected": extras,
                    "unexpected_unlabeled": scores["unexpected_unlabeled"],
                    "tool_counts": {k: scores[k] for k in ("tp", "fp", "fn", "tn")},
                    "label_bounds": label_bounds(scores),
                    "unknown_positive_labels": scores["unknown_positive_labels"],
                    "unknown_negative_labels": scores["unknown_negative_labels"],
                    "checks": checks,
                    "collection_failures": failures,
                    "collector_status": statuses,
                    "relevant_mcp_exclusions": relevant_exclusions,
                    "coverage_incomplete": incomplete,
                    "coverage_rationale": case.get("coverage_rationale"),
                    "expected_mcp_exclusions": expected_exclusions,
                    "passed": not misses
                    and not extras
                    and not failures
                    and exclusions_match
                    and all(checks.values()),
                }
            )
    return {
        "corpus_version": manifest["version"],
        "counts": {key: totals[key] for key in ("tp", "fp", "fn", "tn")},
        "denominators": {
            "expected_tools": totals["tp"] + totals["fn"],
            "explicit_decoys": totals["tn"] + totals["fp"],
        },
        "unlabeled_predictions": sum(len(row["unexpected_unlabeled"]) for row in rows),
        "unknown_positive_labels": sum(row["unknown_positive_labels"] for row in rows),
        "unknown_negative_labels": sum(row["unknown_negative_labels"] for row in rows),
        "label_bounds": label_bounds(totals),
        "scope": "finite labeled MCP inventory regressions; model and policy checks are separate controls",
        "cases": rows,
        "passed": all(r["passed"] for r in rows),
    }


if __name__ == "__main__":
    report = run()
    print(json.dumps(report, indent=2))
    sys.exit(0 if report["passed"] else 1)
