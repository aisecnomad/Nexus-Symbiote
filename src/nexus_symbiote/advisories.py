"""Explicit, bounded OSV queries for exact declared PyPI/npm package identities.

What leaves the machine: for each component in scope, the ecosystem (``PyPI`` or
``npm``), the normalized package name and the exact version, posted to
``https://api.osv.dev/v1/querybatch``. Packages resolved from a private registry
are included unless the operator excludes them. Nothing else from the inventory
is sent. Batch ordering and per-query pagination:
https://google.github.io/osv.dev/post-v1-querybatch/

Only a lockfile resolution records where a package came from. The registry
collector labels a Python package that no uv.lock or poetry.lock resolves with
the public PyPI origin, which is assumed; under ``exclude_private_origins`` such
a label is not evidence, and a package without a lockfile-backed public origin
is not sent. A package that a project setting redirects to another registry or
index has no package URL, so it is never sent.
"""

from __future__ import annotations

import http.client
import json
import re
import time
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import unquote

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import extract_version_pin, parse_json_strict
from nexus_symbiote.core.models import MCPServerComponent, RegistryEntryComponent
from nexus_symbiote.scanners.live_mcp import DiscoveryTransport, PinnedHTTPTransport

OSV_QUERY_URL = "https://api.osv.dev/v1/querybatch"
MAX_RESPONSE_BYTES = 4 * 1024 * 1024
MAX_COMPONENTS = 500
BATCH_SIZE = 100
MAX_PAGES = 10
# One reply may list 10,000 advisories per package; across pages and packages the
# report keeps at most these many, so a hostile reply cannot grow it without bound.
MAX_ADVISORIES_PER_PACKAGE = 10_000
MAX_ADVISORIES = 20_000
TOTAL_TIMEOUT_SECONDS = 120.0
PUBLIC_REGISTRY_ORIGINS = {
    "pypi": frozenset({"https://pypi.org", "https://files.pythonhosted.org"}),
    "npm": frozenset({"https://registry.npmjs.org", "https://registry.yarnpkg.com"}),
}
SCOPE = (
    "exact pkg:pypi and pkg:npm package URLs on registry entries and MCP servers; the "
    "registry collector reads supported root declarations, filtered by the AI catalog "
    "unless --all-packages was selected. Lockfile-only dependencies are outside registry "
    "collection. Other ecosystems are skipped; operator exclusions are "
    "not queried; installed artifacts are unverified and OSV knowledge is incomplete"
)


class _BatchLookupError(Exception):
    """A fixed, nonsecret reason why lookups of one batch stopped."""


@dataclass
class AdvisoryReport:
    components_checked: int = 0
    components_skipped: int = 0
    components_excluded: int = 0
    errors: list[str] = field(default_factory=list)
    advisories: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    excluded: list[dict[str, str]] = field(default_factory=list)
    queries: list[dict[str, str]] = field(default_factory=list)
    checked_at: str | None = None
    tool_version: str = __version__
    inventory_sha256: str | None = None
    dry_run: bool = False

    @property
    def coverage(self) -> str:
        """``complete`` only when every component in scope was looked up without error."""
        if self.dry_run or not self.components_checked:
            return "none"
        return "partial" if self.errors else "complete"

    @property
    def complete(self) -> bool:
        return self.coverage == "complete"

    def to_dict(self) -> dict[str, Any]:
        return {
            **asdict(self),
            "coverage": self.coverage,
            "complete": self.complete,
            "scope": SCOPE,
            "sent_to_osv": (
                "nothing (dry run)"
                if self.dry_run
                else "nothing (package component limit exceeded)"
                if len(self.queries) > MAX_COMPONENTS
                else "ecosystem, normalized package name and exact version of each query"
            ),
        }


def _purl_identity(purl: Any, registry_uri: str | None = None) -> tuple[str, str, str]:
    if not isinstance(purl, str) or len(purl) > 2048 or "#" in purl:
        raise ValueError("exact package_url is required, without qualifiers or subpath")
    purl, qualified, qualifiers = purl.partition("?")
    # The registry collector names the registry a lockfile resolved a package from
    # when it is not the default one. That qualifier, naming the component's own
    # registry, is the only one accepted; the origin decides whether it is sent.
    if qualified:
        if (
            registry_uri is None
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in qualifiers)
            or re.search(r"%(?![0-9A-Fa-f]{2})", qualifiers)
        ):
            raise ValueError("exact package_url is required, without qualifiers or subpath")
        parts = qualifiers.split("&")
        if len(parts) != 1 or "=" not in parts[0]:
            raise ValueError("exact package_url is required, without qualifiers or subpath")
        q_key, _, q_val = parts[0].partition("=")
        decoded_val = unquote(q_val, errors="strict")
        if (
            q_key.lower() != "repository_url"
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in decoded_val)
            or decoded_val != registry_uri
        ):
            raise ValueError("exact package_url is required, without qualifiers or subpath")
    match = re.fullmatch(r"pkg:(pypi|npm)/(.+)@([^@/]+)", purl)
    if match is None:
        raise ValueError("only exact PyPI/npm package URLs are supported")
    kind, encoded_name, encoded_version = match.groups()
    name, version = (
        unquote(encoded_name, errors="strict"),
        unquote(encoded_version, errors="strict"),
    )
    valid_name = (
        re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,199}", name)
        if kind == "pypi"
        else re.fullmatch(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*", name)
    )
    version_pin = extract_version_pin(
        "package==" + version if kind == "pypi" else name + "@" + version,
        ecosystem="python" if kind == "pypi" else "npm",
    )
    if valid_name is None or len(version) > 200 or version_pin != version:
        raise ValueError("package URL name or exact version is invalid")
    return kind, name, version


def _normalize(kind: str, name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower() if kind == "pypi" else name


def package_identity(component: RegistryEntryComponent) -> tuple[str, str, str]:
    """Accept a narrow purl subset and reconcile it with the inventory declaration."""
    kind, name, version = _purl_identity(component.package_url, component.registry_uri)
    declared_version = component.version or ""
    if kind == "pypi":
        declared_version = (
            extract_version_pin(
                "package" + declared_version
                if declared_version.startswith("==")
                else "package==" + declared_version,
                ecosystem="python",
            )
            or ""
        )
    if (
        component.registry_type != kind
        or _normalize(kind, component.name) != _normalize(kind, name)
        or declared_version != version
    ):
        raise ValueError("package URL disagrees with registry, name or version")
    return ("PyPI" if kind == "pypi" else "npm"), _normalize(kind, name), version


def mcp_package_identity(server: MCPServerComponent) -> tuple[str, str, str]:
    """Reconcile an MCP server's package URL with its launcher package and pinned version."""
    kind, name, version = _purl_identity(getattr(server, "package_url", None))
    launcher_kind, _, launcher_name = (server.launcher_package or "").partition(":")
    if (
        launcher_kind != kind
        or _normalize(kind, launcher_name) != _normalize(kind, name)
        or server.version != version
    ):
        raise ValueError("package URL disagrees with the launcher package or version")
    return ("PyPI" if kind == "pypi" else "npm"), _normalize(kind, name), version


def _excluded(kind: str, name: str, patterns: Iterable[str]) -> bool:
    # A queried npm name is lower case, so a pattern in another case still withholds it.
    name = _normalize(kind, name).lower()
    for pattern in patterns:
        if pattern.endswith("*"):
            if name.startswith(_normalize(kind, pattern[:-1]).lower()):
                return True
        elif name == _normalize(kind, pattern).lower():
            return True
    return False


def _origin_exclusion(component: Any, kind: str) -> str | None:
    """Why ``exclude_private_origins`` withholds a package, or None to send it."""
    origin = getattr(component, "registry_uri", None)
    if "package_resolution" not in component.claims or not isinstance(origin, str):
        return "registry origin is not recorded by a lockfile resolution"
    if origin.rstrip("/") not in PUBLIC_REGISTRY_ORIGINS[kind]:
        return "resolved from a non-public registry origin"
    return None


def _in_scope(component: Any) -> str | None:
    """``pypi`` or ``npm`` for a queried package, "" for a package in another ecosystem.

    None means the component is not a package: a registry entry always is, and an
    MCP server is one when it carries a package URL.
    """
    if isinstance(component, RegistryEntryComponent):
        return component.registry_type if component.registry_type in {"pypi", "npm"} else ""
    if isinstance(component, MCPServerComponent):
        purl = getattr(component, "package_url", None)
        if purl is None:
            return None
        match = re.match(r"pkg:(pypi|npm)/", purl) if isinstance(purl, str) else None
        return match.group(1) if match else ""
    return None


def fetch_advisories(
    bom: AIBOM,
    timeout: float = 15.0,
    *,
    transport: DiscoveryTransport | None = None,
    exclude: Iterable[str] = (),
    exclude_private_origins: bool = False,
    dry_run: bool = False,
    inventory_sha256: str | None = None,
) -> AdvisoryReport:
    """Query only OSV over pinned HTTPS; report missing identity and lookup failures.

    One malformed or failed reply stops only its batch: earlier results are kept
    and every unfinished component in that batch gets an error. A package with
    more than ``MAX_ADVISORIES_PER_PACKAGE`` advisories, or a report reaching
    ``MAX_ADVISORIES``, ends those lookups with an error instead of growing further.
    """
    if not 0 < timeout <= 30:
        raise ValueError("timeout must be in (0, 30] seconds")
    patterns = list(exclude)
    if any(not isinstance(p, str) or not p or len(p) > 256 for p in patterns):
        raise ValueError("exclusion patterns must be 1 to 256 characters")
    if any("*" in p[:-1] for p in patterns):
        raise ValueError("an exclusion pattern may hold '*' only as its last character")
    report = AdvisoryReport(
        checked_at=datetime.now(UTC).isoformat(),
        inventory_sha256=inventory_sha256,
        dry_run=dry_run,
    )
    scoped = [(c, kind) for c in bom.components if (kind := _in_scope(c)) is not None]
    queries: list[dict[str, Any]] = []
    for component, kind in scoped:
        if not kind:
            report.components_skipped += 1
            report.skipped.append(
                {"component_ref": component.bom_ref, "reason": "ecosystem is not queried"}
            )
            continue
        try:
            if isinstance(component, RegistryEntryComponent):
                ecosystem, name, version = package_identity(component)
            elif isinstance(component, MCPServerComponent):
                ecosystem, name, version = mcp_package_identity(component)
            else:
                continue
        except (ValueError, TypeError, UnicodeError):
            report.errors.append(f"{component.bom_ref}: exact package identity unavailable")
            continue
        reason = None
        if _excluded(kind, name, patterns):
            reason = "excluded by the operator"
        elif exclude_private_origins:
            reason = _origin_exclusion(component, kind)
        if reason is not None:
            report.components_excluded += 1
            report.excluded.append({"component_ref": component.bom_ref, "reason": reason})
            continue
        queries.append(
            {
                "component": component,
                "query": {"package": {"name": name, "ecosystem": ecosystem}, "version": version},
                "token": None,
                "seen": set(),
                "done": False,
                "found": 0,
                "error": None,
            }
        )
        report.queries.append(
            {
                "component_ref": component.bom_ref,
                "ecosystem": ecosystem,
                "name": name,
                "version": version,
            }
        )
    if len(queries) > MAX_COMPONENTS:
        report.errors.append("package component limit exceeded; no lookups performed")
        return report
    if dry_run or not queries:
        return report
    client = transport or PinnedHTTPTransport()
    deadline = time.monotonic() + TOTAL_TIMEOUT_SECONDS
    recorded: set[tuple[Any, ...]] = set()
    for start in range(0, len(queries), BATCH_SIZE):
        batch = queries[start : start + BATCH_SIZE]
        try:
            _query_batch(
                client, batch, report, recorded=recorded, timeout=timeout, deadline=deadline
            )
            failure = None
        except _BatchLookupError as exc:
            failure = str(exc)
        except Exception:
            failure = "OSV lookup stopped on an unexpected internal error"
        for state in batch:
            if state["done"]:
                report.components_checked += 1
            else:
                reason = state["error"] or failure or "OSV lookup incomplete"
                report.errors.append(f"{state['component'].bom_ref}: {reason}")
    return report


def _within(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise _BatchLookupError("OSV lookup deadline exceeded")


def _collect(
    state: dict[str, Any],
    vulns: list[Any],
    report: AdvisoryReport,
    recorded: set[tuple[Any, ...]],
    deadline: float,
) -> bool:
    """Record one result's advisories; False when the package exceeds its limit.

    Each entry costs constant time, so a large untrusted reply stays linear, and
    the deadline is checked per entry, not only between pages.
    """
    query = state["query"]
    ref = state["component"].bom_ref
    package_url = getattr(state["component"], "package_url", None)
    ecosystem, version = query["package"]["ecosystem"], query["version"]
    for vuln in vulns:
        _within(deadline)
        advisory = vuln.get("id") if isinstance(vuln, dict) else None
        if (
            not isinstance(advisory, str)
            or re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", advisory) is None
        ):
            raise _BatchLookupError("OSV reply was malformed or reported an error")
        key = (ref, package_url, advisory, ecosystem, version)
        if key in recorded:
            continue
        if state["found"] >= MAX_ADVISORIES_PER_PACKAGE:
            state["error"] = "OSV advisories for this package exceed the per-package limit"
            return False
        if len(report.advisories) >= MAX_ADVISORIES:
            raise _BatchLookupError("OSV advisories exceed the report limit")
        recorded.add(key)
        state["found"] += 1
        # No uncontrolled nested API data is propagated as verified local evidence.
        report.advisories.append(
            {
                "component_ref": ref,
                "package_url": package_url,
                "advisory_id": advisory,
                "ecosystem": ecosystem,
                "version": version,
                "url": "https://osv.dev/vulnerability/" + advisory,
            }
        )
    return True


def _query_batch(
    client: DiscoveryTransport,
    batch: list[dict[str, Any]],
    report: AdvisoryReport,
    *,
    recorded: set[tuple[Any, ...]],
    timeout: float,
    deadline: float,
) -> None:
    pending = list(batch)
    for _ in range(MAX_PAGES):
        if len(report.advisories) >= MAX_ADVISORIES:
            raise _BatchLookupError("OSV advisories exceed the report limit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise _BatchLookupError("OSV lookup deadline exceeded")
        body = json.dumps(
            {
                "queries": [
                    {**state["query"], **({"page_token": state["token"]} if state["token"] else {})}
                    for state in pending
                ]
            }
        ).encode()
        try:
            reply = client.request(
                OSV_QUERY_URL,
                body,
                {"Content-Type": "application/json", "Accept": "application/json"},
                timeout=min(timeout, remaining),
                max_bytes=MAX_RESPONSE_BYTES,
            )
        except (OSError, ValueError, http.client.HTTPException) as exc:
            # Transport text can contain server data; keep it out of reports.
            raise _BatchLookupError("OSV request failed or exceeded its limits") from exc
        if reply.status != 200 or len(reply.body) > MAX_RESPONSE_BYTES:
            raise _BatchLookupError("OSV returned a non-success or oversized response")
        try:
            parsed = parse_json_strict(reply.body, max_bytes=MAX_RESPONSE_BYTES)
        except (ValueError, RecursionError, UnicodeError) as exc:
            raise _BatchLookupError("OSV reply was malformed") from exc
        if not isinstance(parsed, dict) or set(parsed) != {"results"}:
            raise _BatchLookupError("OSV reply was malformed or reported an error")
        results = parsed["results"]
        if not isinstance(results, list) or len(results) != len(pending):
            raise _BatchLookupError("OSV reply was malformed or reported an error")
        following = []
        for state, result in zip(pending, results, strict=True):
            _within(deadline)
            if not isinstance(result, dict) or result.keys() - {"vulns", "next_page_token"}:
                raise _BatchLookupError("OSV reply was malformed or reported an error")
            vulns = result.get("vulns", [])
            if not isinstance(vulns, list) or len(vulns) > MAX_ADVISORIES_PER_PACKAGE:
                raise _BatchLookupError("OSV reply was malformed or reported an error")
            if not _collect(state, vulns, report, recorded, deadline):
                continue
            token = result.get("next_page_token", "")
            if not isinstance(token, str) or len(token) > 2048 or token in state["seen"]:
                raise _BatchLookupError("OSV pagination is malformed or repeats a page")
            if token:
                state["token"] = token
                state["seen"].add(token)
                following.append(state)
            else:
                state["done"] = True
        pending = following
        if not pending:
            return
    raise _BatchLookupError("OSV result pages exceed the per-package limit")
