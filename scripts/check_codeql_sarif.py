"""Require exact-checkout CodeQL evidence and reject high/critical security findings."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

MAX_SARIF_BYTES = 32 * 1024 * 1024
MINIMUM_SECURITY_SCORE = 7.0


def evaluate(document: Any, sha: str) -> dict[str, Any]:
    if re.fullmatch(r"[0-9a-f]{40}", sha) is None:
        raise ValueError("an exact analyzed commit SHA is required")
    if not isinstance(document, dict) or document.get("version") != "2.1.0":
        raise ValueError("expected SARIF 2.1.0")
    runs = document.get("runs")
    if not isinstance(runs, list) or not runs:
        raise ValueError("CodeQL analysis runs are missing")
    findings = []
    total = 0
    for run in runs:
        if not isinstance(run, dict):
            raise ValueError("invalid analysis run")
        driver = run.get("tool", {}).get("driver", {})
        if driver.get("name") not in {"CodeQL", "CodeQL command-line toolchain"}:
            raise ValueError("analysis was not produced by CodeQL")
        provenance = run.get("versionControlProvenance", [])
        if not isinstance(provenance, list) or (
            "versionControlProvenance" in run and not provenance
        ):
            raise ValueError("SARIF source provenance is malformed")
        for source in provenance:
            if not isinstance(source, dict) or source.get("revisionId") != sha:
                raise ValueError("SARIF source revision differs from the checked-out commit")
        # The CodeQL CLI records each run's invocation but not, by default, its source
        # revision, so provenance is checked when present and an invocation is required.
        invocations = run.get("invocations")
        if (
            not isinstance(invocations, list)
            or not invocations
            or any(
                not isinstance(invocation, dict)
                or invocation.get("executionSuccessful") is not True
                for invocation in invocations
            )
        ):
            raise ValueError("CodeQL invocation was unsuccessful")
        catalog = {}
        extensions = run.get("tool", {}).get("extensions", [])
        if not isinstance(extensions, list):
            raise ValueError("CodeQL rule extensions are malformed")
        for component in [driver, *extensions]:
            rules = component.get("rules", []) if isinstance(component, dict) else None
            if not isinstance(rules, list):
                raise ValueError("CodeQL rule catalog is missing")
            for rule in rules:
                identity = rule.get("id") if isinstance(rule, dict) else None
                if not isinstance(identity, str) or not identity or identity in catalog:
                    raise ValueError("CodeQL rule identity is missing or ambiguous")
                catalog[identity] = rule
        if not catalog:
            raise ValueError("CodeQL analyzed rule catalog is empty")
        results = run.get("results")
        if not isinstance(results, list):
            raise ValueError("CodeQL result list is missing")
        for result in results:
            identity = result.get("ruleId") if isinstance(result, dict) else None
            if identity not in catalog:
                raise ValueError("CodeQL result has no known rule identity")
            total += 1
            properties = catalog[identity].get("properties", {})
            if not isinstance(properties, dict):
                raise ValueError("CodeQL rule properties are malformed")
            score = properties.get("security-severity")
            tags = properties.get("tags", [])
            if not isinstance(tags, list) or any(not isinstance(tag, str) for tag in tags):
                raise ValueError("CodeQL rule tags are malformed")
            if "security-severity" not in properties and "security" not in tags:
                continue
            if isinstance(score, bool) or not isinstance(score, (str, int, float)):
                raise ValueError("security result has no numeric severity")
            numeric = float(score)
            if not math.isfinite(numeric) or not 0 <= numeric <= 10:
                raise ValueError("security result has invalid severity")
            # Existing, baseline and suppressed findings still require review.
            if numeric >= MINIMUM_SECURITY_SCORE:
                findings.append({"rule_id": identity, "security_severity": numeric})
    return {
        "schema_version": 1,
        "source_sha": sha,
        "source_binding": "workflow-checkout",
        "scope": "policy result from a pinned successful CodeQL step on the exact workflow checkout; not standalone provenance",
        "minimum_blocking_security_score": MINIMUM_SECURITY_SCORE,
        "results_checked": total,
        "blocking_findings": findings,
        "complete": True,
        "passed": not findings,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("sarif", type=Path)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        sha = os.environ.get("GITHUB_SHA", "")
        git = shutil.which("git")
        if git is None:
            raise ValueError("git executable is unavailable")
        checkout = subprocess.check_output(  # noqa: S603 - resolved git, fixed arguments
            [git, "rev-parse", "HEAD"], text=True, timeout=60
        ).strip()
        if checkout != sha:
            raise ValueError("checkout differs from workflow's exact source SHA")
        subprocess.run(  # noqa: S603 - resolved git executable and fixed arguments
            [git, "diff", "--exit-code", "HEAD", "--"], check=True, capture_output=True, timeout=120
        )
        with args.sarif.open("rb") as stream:
            raw = stream.read(MAX_SARIF_BYTES + 1)
        if len(raw) > MAX_SARIF_BYTES:
            raise ValueError("SARIF size limit exceeded")
        report = evaluate(json.loads(raw), sha)
        report["sarif_sha256"] = hashlib.sha256(raw).hexdigest()
    except (
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        RecursionError,
        subprocess.SubprocessError,
    ):
        report = {
            "complete": False,
            "passed": False,
            "errors": ["exact-source CodeQL evidence unavailable or malformed"],
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("CodeQL high/critical policy: " + ("passed" if report["passed"] else "failed"))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
