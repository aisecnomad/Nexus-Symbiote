"""Replay the offline advisory gate with two synthetic package advisories."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from tempfile import TemporaryDirectory

PYPI = "nexus-bench-atlas-mcp"
NPM = "@nexus-bench/atlas-mcp"
PYPI_ID = "CVE-2099-900001"
NPM_ID = "CVE-2099-900002"


def write_json(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def advisory(identifier: str, ecosystem: str, package: str, range_type: str, fixed: str) -> dict:
    return {
        "id": identifier,
        "modified": datetime.now(UTC).date().isoformat() + "T00:00:00Z",
        "summary": "Synthetic benchmark advisory for a fixture package",
        "affected": [
            {
                "package": {"ecosystem": ecosystem, "name": package},
                "ranges": [
                    {"type": range_type, "events": [{"introduced": "1.0.0"}, {"fixed": fixed}]},
                ],
            },
        ],
    }


def materialize(repository: Path, python_requirement: str, npm_version: str) -> None:
    repository.mkdir()
    (repository / "requirements.txt").write_text(f"{PYPI}{python_requirement}\n", encoding="utf-8")
    package = {
        "name": "atlas-advisory-fixture",
        "version": "1.0.0",
        "dependencies": {NPM: npm_version},
    }
    write_json(repository / "package.json", package)
    write_json(
        repository / "package-lock.json",
        {
            "name": package["name"],
            "version": package["version"],
            "lockfileVersion": 3,
            "packages": {"": package, f"node_modules/{NPM}": {"version": npm_version}},
        },
    )


def command(arguments: list[str], environment: dict[str, str], prefix: Path, cwd: Path) -> int:
    result = subprocess.run(  # noqa: S603 - operator-selected CLI and generated fixture paths
        arguments, cwd=cwd, env=environment, capture_output=True, text=True, timeout=75, check=False
    )
    prefix.with_suffix(".stdout").write_text(result.stdout, encoding="utf-8")
    prefix.with_suffix(".stderr").write_text(result.stderr, encoding="utf-8")
    return result.returncode


def replay(nexus: str, output: Path, operator_dir: Path | None) -> bool:
    output.mkdir(parents=True, exist_ok=False)
    with TemporaryDirectory(prefix="aibom-advisories-", dir=operator_dir) as temporary:
        operator = Path(temporary)
        home = operator / "home"
        home.mkdir()
        env = {"PATH": os.environ["PATH"], "HOME": str(home), "NO_COLOR": "1", "TZ": "UTC"}
        feed = operator / "synthetic-osv.json"
        write_json(
            feed,
            {
                "advisories": [
                    advisory(PYPI_ID, "PyPI", PYPI, "ECOSYSTEM", "2.0.0"),
                    advisory(NPM_ID, "npm", NPM, "SEMVER", "3.0.0"),
                ]
            },
        )
        shutil.copyfile(feed, output / feed.name)
        feed_digest = sha256(feed)
        summary = {}
        for name, python_requirement, npm_version, exit_status, complete, expected in (
            (
                "affected",
                "==1.2.0",
                "2.1.0",
                1,
                True,
                [(PYPI_ID, "PyPI", PYPI, "1.2.0"), (NPM_ID, "npm", NPM, "2.1.0")],
            ),
            ("fixed", "==2.0.0", "3.0.0", 0, True, []),
            ("floating", ">=1.2.0", "3.0.0", 1, False, []),
        ):
            case = output / name
            case.mkdir()
            project = case / "input"
            materialize(project, python_requirement, npm_version)
            bom, report = case / "inventory.json", case / "advisories.json"
            scan_exit = command(
                [nexus, "--offline", "scan", str(project), "-o", str(bom)],
                env,
                case / "scan",
                output,
            )
            if scan_exit or not bom.is_file():
                raise RuntimeError(f"{name}: scan exited {scan_exit}; see {case / 'scan.stderr'}")
            advisory_exit = command(
                [
                    nexus,
                    "--offline",
                    "advisories",
                    str(bom),
                    "--offline-db",
                    str(feed),
                    "-o",
                    str(report),
                ],
                env,
                case / "advisories",
                output,
            )
            if not report.is_file():
                raise RuntimeError(
                    f"{name}: advisory command exited {advisory_exit}; see {case / 'advisories.stderr'}"
                )
            result = json.loads(report.read_text(encoding="utf-8"))
            matches = sorted(
                (r["id"], r["ecosystem"], r["package"], r["version"]) for r in result["advisories"]
            )
            provenance = result["provenance"]
            checks = {
                "exact_matches": matches == sorted(expected),
                "expected_exit_and_coverage": advisory_exit == exit_status
                and result["complete"] is complete,
                "offline_feed_binding": provenance["offline"] is True
                and provenance["db_sha256"] == feed_digest,
                "inventory_binding": result["inventory_sha256"] == sha256(bom),
                "expected_errors": not result["errors"]
                if complete
                else any(
                    "exact package identity unavailable" in error for error in result["errors"]
                ),
            }
            summary[name] = {
                "exit_status": advisory_exit,
                "complete": result["complete"],
                "matches": matches,
                "checks": checks,
            }
        write_json(
            output / "summary.json",
            {"synthetic": True, "feed_sha256": feed_digest, "cases": summary},
        )
        return all(all(case["checks"].values()) for case in summary.values())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nexus", default="nexus-symbiote", help="Path to the installed CLI")
    parser.add_argument(
        "--out", required=True, type=Path, help="New directory for inputs and reports"
    )
    parser.add_argument(
        "--operator-dir", type=Path, help="Existing scratch directory for the operator's feed"
    )
    args = parser.parse_args()
    nexus = shutil.which(args.nexus)
    if nexus is None:
        parser.error(f"CLI not found: {args.nexus}")
    output = args.out.resolve()
    try:
        passed = replay(str(Path(nexus).resolve()), output, args.operator_dir)
    except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
        parser.exit(1, f"{error}\n")
    print(f"{'PASS' if passed else 'FAIL'} {output / 'summary.json'}")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
