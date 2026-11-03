"""Fail CI on known OSV advisories or incomplete checks of installed PyPI versions.

Batch ordering and per-query pagination: https://google.github.io/osv.dev/post-v1-querybatch/
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import importlib.metadata
import json
import os
import re
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.scanners.live_mcp import DiscoveryTransport, PinnedHTTPTransport

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
MAX_PACKAGES = 500
BATCH_SIZE = 100
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_PAGES = 10
TOTAL_TIMEOUT_SECONDS = 120


def installed_packages() -> list[dict[str, str]]:
    """Include the actual environment, excluding only this source-built project."""
    packages: dict[str, str] = {}
    for distribution in importlib.metadata.distributions():
        name = (distribution.metadata.get_all("Name") or [""])[0]
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name) is None:
            raise ValueError("installed distribution has no valid PyPI identity")
        name = re.sub(r"[-_.]+", "-", name).lower()
        if name == "nexus-symbiote":
            continue
        version = distribution.version
        if not version or len(version) > 200 or any(c.isspace() for c in version):
            raise ValueError("installed distribution has no exact version")
        if name in packages and packages[name] != version:
            raise ValueError("conflicting installed versions for one package")
        packages[name] = version
    if not packages or len(packages) > MAX_PACKAGES:
        raise ValueError("installed dependency inventory is empty or exceeds the limit")
    return [{"name": name, "version": version} for name, version in sorted(packages.items())]


def audit(
    packages: list[dict[str, str]], *, transport: DiscoveryTransport | None = None
) -> dict[str, Any]:
    """Follow bounded batch pages; errors and unknown responses never mean clean."""
    if not packages or len(packages) > MAX_PACKAGES:
        raise ValueError("dependency inventory is empty or exceeds the limit")
    queries = []
    identities: set[tuple[str, str]] = set()
    for package in packages:
        name, version = package.get("name", ""), package.get("version", "")
        if (
            re.fullmatch(r"[a-z0-9][a-z0-9-]{0,199}", name) is None
            or not version
            or len(version) > 200
            or any(c.isspace() for c in version)
            or (name, version) in identities
        ):
            raise ValueError("invalid or duplicate exact dependency identity")
        identities.add((name, version))
        queries.append({"package": {"ecosystem": "PyPI", "name": name}, "version": version})
    report: dict[str, Any] = {
        "schema_version": 1,
        "source_sha": os.environ.get("GITHUB_SHA"),
        "checked_at": datetime.now(UTC).isoformat(),
        "scope": "installed exact PyPI versions; source project excluded; OSV knowledge is incomplete",
        "packages": packages,
        "inventory_sha256": hashlib.sha256(
            json.dumps(packages, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest(),
        "complete": False,
        "advisories": [],
        "errors": [],
    }
    client = transport or PinnedHTTPTransport()
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    try:
        for start in range(0, len(queries), BATCH_SIZE):
            pending: list[tuple[int, dict[str, Any], set[str]]] = [
                (i, queries[i], set()) for i in range(start, min(start + BATCH_SIZE, len(queries)))
            ]
            for _ in range(MAX_PAGES):
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ValueError("OSV audit deadline exceeded")
                reply = client.request(
                    OSV_BATCH_URL,
                    json.dumps({"queries": [query for _, query, _ in pending]}).encode(),
                    {"Content-Type": "application/json", "Accept": "application/json"},
                    timeout=min(20, remaining),
                    max_bytes=MAX_RESPONSE_BYTES,
                )
                if reply.status != 200 or len(reply.body) > MAX_RESPONSE_BYTES:
                    raise ValueError("OSV batch did not return bounded success")
                body = parse_json_strict(reply.body, max_bytes=MAX_RESPONSE_BYTES)
                if not isinstance(body, dict) or set(body) != {"results"}:
                    raise ValueError("OSV batch is malformed or reports an error")
                results = body["results"]
                if not isinstance(results, list) or len(results) != len(pending):
                    raise ValueError("OSV batch result count differs from dependency queries")
                following = []
                for (index, query, seen), result in zip(pending, results, strict=True):
                    if not isinstance(result, dict) or result.keys() - {"vulns", "next_page_token"}:
                        raise ValueError("OSV batch result is malformed or reports an error")
                    vulns = result.get("vulns", [])
                    if not isinstance(vulns, list) or len(vulns) > 10_000:
                        raise ValueError("OSV vulnerability list is malformed or excessive")
                    for vuln in vulns:
                        advisory = vuln.get("id") if isinstance(vuln, dict) else None
                        if (
                            not isinstance(advisory, str)
                            or re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", advisory) is None
                        ):
                            raise ValueError("OSV vulnerability record has no valid identifier")
                        record = {**packages[index], "advisory_id": advisory}
                        if record not in report["advisories"]:
                            report["advisories"].append(record)
                    token = result.get("next_page_token", "")
                    if not isinstance(token, str) or len(token) > 2048 or token in seen:
                        raise ValueError("OSV pagination is malformed or repeats a page")
                    if token:
                        following.append((index, {**query, "page_token": token}, seen | {token}))
                pending = following
                if not pending:
                    break
            if pending:
                raise ValueError("OSV pagination limit exceeded")
        if time.monotonic() > deadline:
            raise ValueError("OSV audit deadline exceeded")
        report["complete"] = True
    except (OSError, ValueError, TypeError, RecursionError, http.client.HTTPException):
        report["errors"].append("OSV dependency lookup is incomplete; approval denied")
    report["passed"] = report["complete"] and not report["advisories"]
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    try:
        report = audit(installed_packages())
    except (OSError, ValueError, TypeError):
        report = {
            "complete": False,
            "passed": False,
            "errors": ["dependency identities unavailable"],
        }
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("Dependency advisory acceptance: " + ("passed" if report["passed"] else "failed"))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
