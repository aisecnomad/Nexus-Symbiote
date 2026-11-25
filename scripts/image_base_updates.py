"""Record the Debian security fixes that the release image's base packages are behind.

Reads the inventory ``scripts/check_image.py --packages-out`` wrote and asks OSV, for each
source package at its installed version, which advisories of that Debian release affect it.
An advisory that names a fixed version in that release is a pending update: the pinned base
predates the fix. The others have no fix there yet. A published image is not rebuilt, so
this is a record for the release notes and not a gate: pending updates do not fail it. An
incomplete lookup does, because the record would then claim more than was checked.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.scanners.live_mcp import DiscoveryTransport, PinnedHTTPTransport

OSV_QUERY_URL = "https://api.osv.dev/v1/query"
MAX_PACKAGES = 2000
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 10
TOTAL_TIMEOUT_SECONDS = 300
HEADERS = {"Content-Type": "application/json", "Accept": "application/json"}
# Every value below can reach the CI log, where a line break would start a workflow command.
PACKAGE = re.compile(r"[a-z0-9][a-z0-9+.-]{0,127}")
VERSION = re.compile(r"[0-9][0-9A-Za-z.+~:-]{0,127}")
ADVISORY = re.compile(r"[A-Za-z0-9_.:-]{1,200}")
BASE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/:@-]{0,299}")
SYSTEMS = {"debian": "Debian"}


def load_inventory(path: Path) -> tuple[str, str, list[dict[str, Any]]]:
    """The base reference, the OSV ecosystem and the source packages of a checked image."""
    document = parse_json_strict(path.read_bytes(), max_bytes=MAX_RESPONSE_BYTES)
    system = document.get("os") if isinstance(document, dict) else None
    packages = document.get("packages") if isinstance(document, dict) else None
    if not isinstance(system, dict) or not isinstance(packages, list):
        raise ValueError("the image inventory has no operating system or package list")
    release = system.get("version_id")
    if system.get("id") not in SYSTEMS or not re.fullmatch(r"[0-9]{1,3}", str(release)):
        raise ValueError("the image's operating system is not one whose advisories OSV names")
    base = document.get("base")
    if not isinstance(base, str) or not BASE.fullmatch(base):
        raise ValueError("the image inventory names no base image")
    seen = set()
    for package in packages:
        source = package.get("source") if isinstance(package, dict) else None
        version = package.get("version") if isinstance(package, dict) else None
        if (
            not isinstance(source, str)
            or not isinstance(version, str)
            or not PACKAGE.fullmatch(source)
            or not VERSION.fullmatch(version)
            or (source, version) in seen
        ):
            raise ValueError("invalid or duplicate source package in the image inventory")
        seen.add((source, version))
    if not packages or len(packages) > MAX_PACKAGES:
        raise ValueError("the image inventory is empty or exceeds the limit")
    return base, f"{SYSTEMS[system['id']]}:{release}", packages


def _fixes(vuln: dict[str, Any], ecosystem: str, source: str) -> list[str]:
    """The versions of this release in which the advisory records the package as fixed."""
    fixed = set()
    for affected in vuln.get("affected") or []:
        package = affected.get("package") if isinstance(affected, dict) else None
        if not isinstance(package, dict) or (package.get("ecosystem"), package.get("name")) != (
            ecosystem,
            source,
        ):
            continue
        for span in affected.get("ranges") or []:
            for event in (span.get("events") if isinstance(span, dict) else None) or []:
                version = event.get("fixed") if isinstance(event, dict) else None
                if version is not None:
                    if not isinstance(version, str) or not VERSION.fullmatch(version):
                        raise ValueError("OSV advisory names an invalid fixed version")
                    fixed.add(version)
    return sorted(fixed)


def _post(client: DiscoveryTransport, query: dict[str, Any], deadline: float) -> bytes:
    """One query's reply. A request that fails is sent once more: there is one request per
    package, and a single dropped connection should not cost a release run."""
    for attempt in (1, 2):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            reply = client.request(
                OSV_QUERY_URL,
                json.dumps(query).encode(),
                HEADERS,
                timeout=min(20, remaining),
                max_bytes=MAX_RESPONSE_BYTES,
            )
        except (OSError, ValueError, http.client.HTTPException):
            if attempt == 2:
                raise
            continue
        if reply.status == 200:
            return reply.body
    raise ValueError("OSV query did not succeed before the deadline")


def _advisories(
    client: DiscoveryTransport, ecosystem: str, source: str, version: str, deadline: float
) -> dict[str, list[str]]:
    """Every advisory OSV holds for one package version, with its fixed versions."""
    query: dict[str, Any] = {
        "package": {"ecosystem": ecosystem, "name": source},
        "version": version,
    }
    found: dict[str, list[str]] = {}
    tokens: set[str] = set()
    for _ in range(MAX_PAGES):
        body = parse_json_strict(_post(client, query, deadline), max_bytes=MAX_RESPONSE_BYTES)
        if not isinstance(body, dict) or body.keys() - {"vulns", "next_page_token"}:
            raise ValueError("OSV reply is malformed or reports an error")
        vulns = body.get("vulns", [])
        if not isinstance(vulns, list):
            raise ValueError("OSV vulnerability list is malformed")
        for vuln in vulns:
            advisory = vuln.get("id") if isinstance(vuln, dict) else None
            if not isinstance(advisory, str) or not ADVISORY.fullmatch(advisory):
                raise ValueError("OSV vulnerability record has no valid identifier")
            found[advisory] = _fixes(vuln, ecosystem, source)
        token = body.get("next_page_token", "")
        if not isinstance(token, str) or len(token) > 2048 or token in tokens:
            raise ValueError("OSV pagination is malformed or repeats a page")
        if not token:
            return found
        tokens.add(token)
        query["page_token"] = token
    raise ValueError("OSV pagination limit exceeded")


def lookup(
    base: str,
    ecosystem: str,
    packages: list[dict[str, Any]],
    *,
    transport: DiscoveryTransport | None = None,
) -> dict[str, Any]:
    """Split each package's advisories into pending fixes and those without a fix."""
    report: dict[str, Any] = {
        "schema_version": 1,
        "source_sha": os.environ.get("GITHUB_SHA"),
        "checked_at": datetime.now(UTC).isoformat(),
        "scope": (
            "source packages installed in the image at their exact versions; an advisory is"
            " pending when OSV records a fixed version in this release; OSV knowledge is"
            " incomplete"
        ),
        "base": base,
        "ecosystem": ecosystem,
        "inventory_sha256": hashlib.sha256(
            json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "packages": len(packages),
        "complete": False,
        "pending": [],
        "without_fix": [],
        "errors": [],
    }
    client = transport or PinnedHTTPTransport()
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    try:
        for package in packages:
            source, version = package["source"], package["version"]
            found = _advisories(client, ecosystem, source, version, deadline)
            entry = {"source": source, "version": version}
            fixed = sorted({v for versions in found.values() for v in versions})
            if fixed:
                pending = sorted(advisory for advisory, versions in found.items() if versions)
                report["pending"].append({**entry, "fixed": fixed, "advisories": pending})
            unfixed = sorted(advisory for advisory, versions in found.items() if not versions)
            if unfixed:
                report["without_fix"].append({**entry, "advisories": unfixed})
        report["complete"] = True
    except (OSError, ValueError, TypeError, RecursionError, http.client.HTTPException):
        report["errors"].append("OSV lookup of the image's base packages is incomplete")
    return report


def summary(report: dict[str, Any]) -> list[str]:
    """What the release notes can say about the base, as Markdown lines."""
    lines = [
        f"Base image `{report['base']}` ({report['ecosystem']}): {len(report['pending'])} of"
        f" {report['packages']} source packages are behind a fix in that release."
    ]
    for entry in report["pending"]:
        lines.append(
            f"- `{entry['source']}` {entry['version']} is fixed in {', '.join(entry['fixed'])}"
            f" ({', '.join(entry['advisories'])})"
        )
    without = sum(len(entry["advisories"]) for entry in report["without_fix"])
    lines.append(f"{without} more advisories have no fixed version in {report['ecosystem']}.")
    return lines


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path, help="written by check_image.py --packages-out")
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = lookup(*load_inventory(args.inventory))
    except (OSError, ValueError, TypeError, RecursionError):
        report = {"complete": False, "errors": ["the image inventory is unavailable or invalid"]}
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    lines = summary(report) if report["complete"] else report["errors"]
    print("\n".join(lines))
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary and report["complete"]:
        with open(step_summary, "a", encoding="utf-8") as stream:
            stream.write("## Image base updates\n\n" + "\n".join(lines) + "\n")
    return 0 if report["complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
