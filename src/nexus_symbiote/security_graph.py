"""Assurance-tiered multi-hop security and advisory exposure graph with traceable edge evidence.

Correlates supply-chain advisories and poisoned or shadowed control-plane surfaces offline across:
- Vulnerability advisories (operator-supplied ``advisories`` OSV/KEV/EPSS reports or scan-time
  ``properties.advisories`` records)
- Registry packages and container images (``RegistryEntryComponent``)
- MCP servers, gateways, and high-risk launch contexts (``MCPServerComponent``)
- MCP and framework tools, including poisoned or shadowed descriptors (``ToolComponent``)
- Repository and IDE agents (``AgentComponent``, ``IDEAgentComponent``)
- Reachable declared credential names, retrieval/data/memory stores, and side-effect tools

Every directed edge records traceable provenance (relationship, assurance, method, source and
target locators, version agreement, and explicit conditions). Associations derived from static
inventories or advisory feeds describe declared/reported exposure paths rather than observed
runtime execution or proven exploitability, and credential surfaces record names only—never
secret values.
"""

from __future__ import annotations

import base64
import hashlib
import html
import math
import re
from collections import deque
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.coverage import assess_coverage
from nexus_symbiote.core.enums import ComponentType, RiskSeverity
from nexus_symbiote.core.hashing import extract_version_pin
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AnyComponent,
    MCPServerComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.graph import _is_credential_env_var_name, _references, validate_graph
from nexus_symbiote.risk_classes import RiskClass, classify
from nexus_symbiote.trifecta import analyze_trifecta
from nexus_symbiote.utils.secrets import (
    _AUTHORIZATION_KEY,
    _COOKIE_KEY,
    _CREDENTIAL_KEY,
    TOKEN_SHAPE,
    redact_text,
)
from nexus_symbiote.utils.terminal import UNSAFE_TEXT, neutralize
from nexus_symbiote.vex_decisions import (
    VEXDecisionError,
    _ensure_outside_project,
    load_advisory_report,
)

FORMAT = "nexus-symbiote/security-graph/v1"
DEFAULT_MAX_NODES = 2_000
MAX_NODES = 20_000
MAX_ADVISORY_NODES = 10_000
MAX_CORRELATED_CHAINS = 500
MAX_CHAIN_HOPS = 6
MAX_LABEL_CHARS = 120
MAX_LOCATOR_CHARS = 240
MAX_CREDENTIAL_SURFACES_PER_NODE = 32

_AGENT_TYPES = frozenset({ComponentType.AGENT, ComponentType.IDE_AGENT})
_DATA_TYPES = frozenset(
    {
        ComponentType.RAG_SOURCE,
        ComponentType.DATA_SOURCE,
        ComponentType.MEMORY_STORE,
    }
)
_HIGH_RISK_CLASSES = frozenset(
    {
        RiskClass.CODE_EXEC,
        RiskClass.EXFIL_CAPABLE,
        RiskClass.WRITE_CAPABLE,
        RiskClass.SECRET_ACCESS,
    }
)
_POISONING_CATEGORIES = frozenset(
    {
        "tool_description_poisoning",
        "instruction_injection",
        "hidden_markup",
        "invisible_characters",
        "bidi_override",
        "tag_characters",
    }
)
_SEVERITY_RANK: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
}
_HEADER_NAME_RE = re.compile(r"[A-Za-z0-9-]{2,128}")
_SPIFFE_ID_RE = re.compile(r"spiffe://[A-Za-z0-9.-]{1,128}(?:/[A-Za-z0-9._-]{1,128}){0,16}")
_CREDENTIAL_PROP_KEYS = (
    "env_vars_referenced",
    "credential_env_vars",
    "credential_environment_names",
    "credential_references",
)


class SecurityGraphError(ValueError):
    """Raised when an inventory or advisory input violates security-graph invariants."""


@dataclass(frozen=True)
class CredentialSurface:
    """A redacted, secret-free credential or authority surface declared on a component."""

    kind: str
    identifier: str
    assurance: str
    locator: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "kind": self.kind,
            "identifier": self.identifier,
            "assurance": self.assurance,
            "locator": self.locator,
        }


@dataclass(frozen=True)
class TraceableEdge:
    """A directed graph edge with explicit assurance, method, locators, and conditions."""

    source_ref: str
    target_ref: str
    relationship: str
    assurance: str
    evidence_method: str
    source_locator: str | None
    target_locator: str | None
    version_agreement: str | None
    conditions: str | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "relationship": self.relationship,
            "assurance": self.assurance,
            "evidence_method": self.evidence_method,
            "source_locator": self.source_locator,
            "target_locator": self.target_locator,
            "version_agreement": self.version_agreement,
            "conditions": self.conditions,
        }


def _clean_label(value: str, limit: int = MAX_LABEL_CHARS) -> str:
    if _SPIFFE_ID_RE.fullmatch(value):
        scrubbed = neutralize(value)
    else:
        scrubbed = neutralize(redact_text(value))
    return scrubbed if len(scrubbed) <= limit else scrubbed[: limit - 1] + "…"


def _component_locator(comp: AnyComponent) -> str | None:
    for claim in comp.claims.values():
        if claim.locator:
            return _clean_label(claim.locator, MAX_LOCATOR_CHARS)
    if comp.source_path:
        decl_line = comp.properties.get("declaration_line") or comp.properties.get("source_line")
        loc = f"{comp.source_path}:{decl_line}" if type(decl_line) is int else comp.source_path
        return _clean_label(loc, MAX_LOCATOR_CHARS)
    return None


def _primary_method(comp: AnyComponent, fallback: str) -> str:
    for claim in comp.claims.values():
        if claim.method:
            return _clean_label(claim.method, 80)
    return fallback


def extract_credential_surfaces(comp: AnyComponent) -> tuple[CredentialSurface, ...]:
    """Extract declared credential and authority identifiers by name only (never values)."""
    locator = _component_locator(comp)
    assurance = comp.assurance_level.value
    found: dict[tuple[str, str], CredentialSurface] = {}

    if isinstance(comp, AgentComponent) and comp.workload_identity:
        wl_id = _clean_label(comp.workload_identity.strip(), MAX_LABEL_CHARS)
        found[("workload-identity", wl_id)] = CredentialSurface(
            kind="workload-identity",
            identifier=f"workload-identity:{wl_id}",
            assurance=assurance,
            locator=locator,
        )

    env_candidates: list[str] = []
    if isinstance(comp, MCPServerComponent):
        env_candidates.extend(k for k in comp.env if isinstance(k, str))
        header_candidates: list[str] = []
        raw_hdr_names = comp.properties.get("header_names")
        if isinstance(raw_hdr_names, list):
            header_candidates.extend(h for h in raw_hdr_names if isinstance(h, str))
        raw_hdr_map = comp.properties.get("headers")
        if isinstance(raw_hdr_map, Mapping):
            header_candidates.extend(k for k in raw_hdr_map if isinstance(k, str))
        for hdr_name in header_candidates:
            is_auth_hdr = (
                _CREDENTIAL_KEY.search(hdr_name) is not None
                or _AUTHORIZATION_KEY.fullmatch(hdr_name) is not None
                or _COOKIE_KEY.fullmatch(hdr_name) is not None
            )
            if (
                _HEADER_NAME_RE.fullmatch(hdr_name)
                and "redacted" not in hdr_name.lower()
                and not TOKEN_SHAPE.search(hdr_name)
                and is_auth_hdr
            ):
                clean_hdr = _clean_label(hdr_name)
                if "***" not in clean_hdr:
                    found[("mcp-header", clean_hdr)] = CredentialSurface(
                        kind="mcp-header",
                        identifier=f"mcp-header:{clean_hdr}",
                        assurance=assurance,
                        locator=locator,
                    )

    for prop_key in _CREDENTIAL_PROP_KEYS:
        raw_list = comp.properties.get(prop_key)
        if isinstance(raw_list, list):
            env_candidates.extend(item for item in raw_list if isinstance(item, str))

    for env_name in env_candidates:
        if _is_credential_env_var_name(env_name) and not TOKEN_SHAPE.search(env_name):
            clean_env = _clean_label(env_name)
            if "***" not in clean_env:
                found[("env", clean_env)] = CredentialSurface(
                    kind="env",
                    identifier=f"env:{clean_env}",
                    assurance=assurance,
                    locator=locator,
                )

    if isinstance(comp, A2AServerComponent):
        raw_schemes = comp.properties.get("authentication_schemes")
        if isinstance(raw_schemes, list):
            for scheme in raw_schemes:
                if isinstance(scheme, str) and scheme.strip():
                    clean_scheme = _clean_label(scheme.strip(), 64)
                    found[("auth-scheme", clean_scheme)] = CredentialSurface(
                        kind="auth-scheme",
                        identifier=f"auth-scheme:{clean_scheme}",
                        assurance=assurance,
                        locator=locator,
                    )
    elif isinstance(comp, A2AClientComponent):
        for method in comp.authentication_methods:
            if isinstance(method, str) and method.strip():
                clean_method = _clean_label(method.strip(), 64)
                found[("auth-scheme", clean_method)] = CredentialSurface(
                    kind="auth-scheme",
                    identifier=f"auth-scheme:{clean_method}",
                    assurance=assurance,
                    locator=locator,
                )

    for auth in getattr(comp, "authorizations", ()):
        principal = getattr(auth, "principal", None)
        if isinstance(principal, str) and principal.strip():
            clean_principal = _clean_label(principal.strip(), MAX_LABEL_CHARS)
            found[("principal", clean_principal)] = CredentialSurface(
                kind="principal",
                identifier=f"principal:{clean_principal}",
                assurance=assurance,
                locator=locator,
            )

    ordered = sorted(found.values(), key=lambda s: (s.kind, s.identifier))
    return tuple(ordered[:MAX_CREDENTIAL_SURFACES_PER_NODE])


def _validate_advisory_fields(
    entry: Mapping[str, Any],
) -> tuple[str, list[str], str, bool, list[str], float | None, str | None]:
    raw_id = entry.get("advisory_id") or entry.get("id")
    if not isinstance(raw_id, str) or not raw_id.strip() or UNSAFE_TEXT.search(raw_id):
        raise SecurityGraphError("Advisory record carries an invalid or unsafe identifier")
    adv_id = raw_id.strip()[:128]

    raw_aliases = entry.get("aliases") or []
    if not isinstance(raw_aliases, list) or not all(
        isinstance(a, str) and a.strip() and "," not in a and not UNSAFE_TEXT.search(a)
        for a in raw_aliases
    ):
        raise SecurityGraphError(f"Advisory {neutralize(adv_id)} carries malformed aliases")
    aliases = sorted({a.strip()[:128] for a in raw_aliases if a.strip() != adv_id})

    raw_sev = entry.get("severity")
    sev = str(raw_sev).lower() if isinstance(raw_sev, str) else "unknown"
    if sev not in _SEVERITY_RANK:
        sev = "unknown"

    in_kev_raw = entry.get("in_kev", False)
    if type(in_kev_raw) is not bool:
        raise SecurityGraphError(f"Advisory {neutralize(adv_id)} in_kev must be a boolean")
    kev_sources_raw = entry.get("kev_sources") or []
    if not isinstance(kev_sources_raw, list) or not all(
        isinstance(s, str) and s.strip() and "," not in s and not UNSAFE_TEXT.search(s)
        for s in kev_sources_raw
    ):
        raise SecurityGraphError(f"Advisory {neutralize(adv_id)} carries malformed kev_sources")
    kev_sources = sorted({s.strip()[:64] for s in kev_sources_raw})
    in_kev = in_kev_raw or bool(kev_sources)

    epss_raw = entry.get("epss_score")
    epss_score: float | None = None
    if epss_raw is not None:
        if type(epss_raw) not in (int, float) or not math.isfinite(float(epss_raw)):
            raise SecurityGraphError(f"Advisory {neutralize(adv_id)} epss_score must be finite")
        val = float(epss_raw)
        if not 0.0 <= val <= 1.0:
            raise SecurityGraphError(
                f"Advisory {neutralize(adv_id)} epss_score out of [0, 1] range"
            )
        epss_score = round(val, 6)

    purl_raw = entry.get("package_url") or entry.get("purl")
    purl = _clean_label(purl_raw, 200) if isinstance(purl_raw, str) and purl_raw.strip() else None
    return adv_id, aliases, sev, in_kev, kev_sources, epss_score, purl


def _normalize_pin(raw: str | None, *, is_pypi: bool) -> str | None:
    if not raw:
        return None
    val = raw.strip()
    if is_pypi:
        candidate = (
            val
            if "==" in val
            else (f"pkg=={val}" if not any(c in val for c in "<>!=~*,; ") else val)
        )
        return extract_version_pin(candidate, ecosystem="python")
    return extract_version_pin(val)


def _version_agreement(mcp: MCPServerComponent, pkg: RegistryEntryComponent) -> str:
    if mcp.version_pinned is False:
        return "unpinned"
    mcp_ver = mcp.version
    if not mcp_ver and mcp.package_url and "@" in mcp.package_url:
        mcp_ver = mcp.package_url.rpartition("@")[2].partition("?")[0]
    is_pypi = pkg.registry_type == "pypi"
    mcp_pin = _normalize_pin(mcp_ver, is_pypi=is_pypi)
    pkg_pin = _normalize_pin(pkg.version, is_pypi=is_pypi)
    if mcp_pin is None or pkg_pin is None:
        return "unpinned"
    return "exact-match" if mcp_pin == pkg_pin else "version-mismatch"


def _shortest_paths_to_targets(
    adj: Mapping[str, Sequence[tuple[str, int]]],
    start: str,
    targets: frozenset[str],
    *,
    max_hops: int = MAX_CHAIN_HOPS,
) -> dict[str, tuple[tuple[str, ...], tuple[int, ...]]]:
    if not targets:
        return {}
    found: dict[str, tuple[tuple[str, ...], tuple[int, ...]]] = {}
    queue: deque[tuple[str, tuple[str, ...], tuple[int, ...]]] = deque([(start, (start,), ())])
    visited = {start}
    while queue and len(found) < len(targets):
        current, nodes_path, edges_path = queue.popleft()
        if len(edges_path) >= max_hops:
            continue
        for nxt, edge_idx in adj.get(current, ()):
            if nxt in visited:
                continue
            visited.add(nxt)
            next_nodes = (*nodes_path, nxt)
            next_edges = (*edges_path, edge_idx)
            if nxt in targets:
                found[nxt] = (next_nodes, next_edges)
            queue.append((nxt, next_nodes, next_edges))
    return found


def correlate_security_graph(
    bom: AIBOM,
    *,
    inventory_sha256: str | None = None,
    advisories_path: Path | None = None,
    allow_partial_advisories: bool = False,
    project_root: Path | None = None,
    inventory_path: Path | None = None,
    max_nodes: int = DEFAULT_MAX_NODES,
) -> dict[str, Any]:
    """Build a deterministic ``nexus-symbiote/security-graph/v1`` correlation document."""
    if not 1 <= max_nodes <= MAX_NODES:
        raise SecurityGraphError(f"max_nodes must be between 1 and {MAX_NODES}")
    if len(bom.components) > max_nodes:
        raise SecurityGraphError(
            f"Inventory contains {len(bom.components)} components, exceeding --max-nodes {max_nodes}"
        )

    issues = validate_graph(bom)
    if issues:
        raise SecurityGraphError("Invalid inventory graph: " + "; ".join(issues))

    loaded_adv = None
    if advisories_path is not None:
        try:
            if project_root is not None:
                _ensure_outside_project(
                    advisories_path,
                    project_root,
                    inventory_path=inventory_path,
                    forbid_inventory_dir=False,
                    label="Advisory report",
                )
            loaded_adv = load_advisory_report(
                advisories_path,
                expected_inventory_sha256=inventory_sha256,
                allow_partial=allow_partial_advisories,
            )
        except VEXDecisionError as exc:
            msg = str(exc)
            if msg.startswith("Cannot safely read advisory report:"):
                raise SecurityGraphError("Advisory report could not be read safely") from exc
            raise SecurityGraphError(neutralize(msg)) from exc
        except (UnicodeError, ValueError, TypeError, RecursionError, OSError) as exc:
            raise SecurityGraphError("Advisory report is not valid strict UTF-8 JSON") from exc

    trifecta_report = analyze_trifecta(bom)
    shadowed_set = frozenset(trifecta_report.shadowed_refs)
    coverage = assess_coverage(bom.metadata.completeness)

    components_by_ref: dict[str, AnyComponent] = {c.bom_ref: c for c in bom.components}
    locators: dict[str, str | None] = {c.bom_ref: _component_locator(c) for c in bom.components}
    cred_by_ref: dict[str, tuple[CredentialSurface, ...]] = {
        c.bom_ref: extract_credential_surfaces(c) for c in bom.components
    }
    class_by_ref = {c.bom_ref: classify(c) for c in bom.components}
    poisoned_refs: set[str] = set()
    risky_launch_refs: set[str] = set()

    nodes_out: list[dict[str, Any]] = []
    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        poison_cats = sorted(
            {r.category for r in comp.risks if r.category in _POISONING_CATEGORIES}
        )
        is_poisoned = bool(poison_cats)
        is_shadowed = comp.bom_ref in shadowed_set
        if is_poisoned:
            poisoned_refs.add(comp.bom_ref)
        has_high_launch = isinstance(comp, MCPServerComponent) and any(
            r.category in {"launch_context", "local_process"}
            and r.severity in {RiskSeverity.CRITICAL, RiskSeverity.HIGH}
            for r in comp.risks
        )
        if has_high_launch:
            risky_launch_refs.add(comp.bom_ref)
        cls = class_by_ref[comp.bom_ref]
        nodes_out.append(
            {
                "id": comp.bom_ref,
                "kind": "component",
                "type": comp.component_type.value,
                "name": _clean_label(comp.name),
                "version": _clean_label(comp.version) if comp.version else None,
                "assurance": comp.assurance_level.value,
                "locator": locators[comp.bom_ref],
                "risk_classes": [rc.value for rc in cls.classes],
                "credential_surfaces": [cs.to_dict() for cs in cred_by_ref[comp.bom_ref]],
                "poisoned": is_poisoned,
                "poisoning_categories": poison_cats,
                "shadowed": is_shadowed,
            }
        )

    advisory_nodes: dict[str, dict[str, Any]] = {}
    advisory_links: set[tuple[str, str, str | None, str]] = set()

    def _ingest_advisory(
        entry: Mapping[str, Any], comp_ref: str, *, method: str, locator: str | None
    ) -> None:
        if comp_ref not in components_by_ref:
            return
        adv_id, aliases, sev, in_kev, kev_sources, epss, purl = _validate_advisory_fields(entry)
        safe_adv_id = neutralize(adv_id)
        node_id = f"advisory:{safe_adv_id}"
        existing = advisory_nodes.get(node_id)
        if existing is None:
            if len(advisory_nodes) >= MAX_ADVISORY_NODES:
                raise SecurityGraphError(
                    f"Advisory count exceeds maximum limit ({MAX_ADVISORY_NODES})"
                )
            advisory_nodes[node_id] = {
                "id": node_id,
                "kind": "advisory",
                "type": "vulnerability-advisory",
                "name": safe_adv_id,
                "aliases": [neutralize(a) for a in aliases],
                "severity": sev,
                "in_kev": in_kev,
                "kev_sources": [neutralize(s) for s in kev_sources],
                "epss_score": epss,
                "assurance": "reported",
                "locator": locator,
            }
        else:
            merged_aliases = sorted({*existing["aliases"], *(neutralize(a) for a in aliases)})
            existing["aliases"] = merged_aliases
            if _SEVERITY_RANK[sev] < _SEVERITY_RANK[existing["severity"]]:
                existing["severity"] = sev
            existing["in_kev"] = existing["in_kev"] or in_kev
            existing["kev_sources"] = sorted(
                {*existing["kev_sources"], *(neutralize(s) for s in kev_sources)}
            )
            if epss is not None and (
                existing["epss_score"] is None or epss > existing["epss_score"]
            ):
                existing["epss_score"] = epss
        advisory_links.add((node_id, comp_ref, purl, method))

    if loaded_adv is not None:
        report_loc = f"advisory-report:{loaded_adv.sha256[:19]}"
        for raw_adv in loaded_adv.advisories:
            target_ref = str(raw_adv.get("component_ref") or raw_adv.get("bom_ref"))
            _ingest_advisory(raw_adv, target_ref, method="osv-advisory-report", locator=report_loc)

    for comp in bom.components:
        prop_advisories = comp.properties.get("advisories")
        if prop_advisories is not None:
            if not isinstance(prop_advisories, list) or not all(
                isinstance(item, Mapping) for item in prop_advisories
            ):
                raise SecurityGraphError(
                    "Component properties.advisories must be a list of objects"
                )
            for item in prop_advisories:
                _ingest_advisory(
                    item,
                    comp.bom_ref,
                    method="inventory-advisory-property",
                    locator=locators[comp.bom_ref],
                )

    for adv_node_id in sorted(advisory_nodes):
        nodes_out.append(advisory_nodes[adv_node_id])

    edges_set: dict[tuple[str, str, str], TraceableEdge] = {}

    def _record_edge(edge: TraceableEdge) -> None:
        key = (edge.source_ref, edge.target_ref, edge.relationship)
        if key not in edges_set:
            edges_set[key] = edge

    for adv_node_id, comp_ref, purl, method in sorted(advisory_links):
        cond = (
            f"Advisory matched declared package ({purl}); installed artifact and vulnerable "
            "code-path reachability unverified"
            if purl
            else "Advisory matched declared component; runtime reachability unverified"
        )
        _record_edge(
            TraceableEdge(
                source_ref=adv_node_id,
                target_ref=comp_ref,
                relationship="affects-package",
                assurance="reported",
                evidence_method=method,
                source_locator=advisory_nodes[adv_node_id]["locator"],
                target_locator=locators[comp_ref],
                version_agreement=None,
                conditions=cond,
            )
        )

    for dep in bom.dependencies:
        src_comp = components_by_ref[dep.source_ref]
        dst_comp = components_by_ref[dep.target_ref]
        ver_agree: str | None = None
        if isinstance(src_comp, MCPServerComponent) and isinstance(
            dst_comp, RegistryEntryComponent
        ):
            ver_agree = _version_agreement(src_comp, dst_comp)
        _record_edge(
            TraceableEdge(
                source_ref=dep.source_ref,
                target_ref=dep.target_ref,
                relationship=dep.relationship,
                assurance=dep.assurance_level or "declared",
                evidence_method=_primary_method(src_comp, "bom-dependency-edge"),
                source_locator=locators[dep.source_ref],
                target_locator=locators[dep.target_ref],
                version_agreement=ver_agree,
                conditions=neutralize(dep.conditions) if dep.conditions else None,
            )
        )

    for comp in bom.components:
        for field_name, ref in _references(comp):
            dst_comp = components_by_ref[ref]
            ver_agree = (
                _version_agreement(comp, dst_comp)
                if isinstance(comp, MCPServerComponent)
                and isinstance(dst_comp, RegistryEntryComponent)
                else None
            )
            _record_edge(
                TraceableEdge(
                    source_ref=comp.bom_ref,
                    target_ref=ref,
                    relationship=f"ref:{field_name}",
                    assurance=comp.assurance_level.value,
                    evidence_method=_primary_method(comp, f"component-field:{field_name}"),
                    source_locator=locators[comp.bom_ref],
                    target_locator=locators[ref],
                    version_agreement=ver_agree,
                    conditions="static component reference; runtime invocation unobserved",
                )
            )
        upstreams = comp.properties.get("upstream_server_refs")
        if isinstance(upstreams, list):
            for srv_ref in upstreams:
                if isinstance(srv_ref, str) and srv_ref in components_by_ref:
                    _record_edge(
                        TraceableEdge(
                            source_ref=comp.bom_ref,
                            target_ref=srv_ref,
                            relationship="bridges-mcp-server",
                            assurance=comp.assurance_level.value,
                            evidence_method="mcp-gateway-property",
                            source_locator=locators[comp.bom_ref],
                            target_locator=locators[srv_ref],
                            version_agreement=None,
                            conditions="declared MCP bridge upstream; runtime routing unobserved",
                        )
                    )

    ordered_edges = sorted(
        edges_set.values(), key=lambda e: (e.source_ref, e.target_ref, e.relationship)
    )

    # Build exposure propagation adjacency (compromise flows from dependency/tool/advisory to
    # dependent MCP server / agent) AND forward agent reach adjacency (agent -> resources).
    propagation_adj: dict[str, list[tuple[str, int]]] = {}
    forward_adj: dict[str, list[tuple[str, int]]] = {}
    for idx, edge in enumerate(ordered_edges):
        if edge.relationship == "affects-package":
            propagation_adj.setdefault(edge.source_ref, []).append((edge.target_ref, idx))
        else:
            forward_adj.setdefault(edge.source_ref, []).append((edge.target_ref, idx))
            # If A depends-on / configured-with / provides-tool / registered-as B,
            # then compromise or poisoning at B propagates up to A.
            propagation_adj.setdefault(edge.target_ref, []).append((edge.source_ref, idx))
            if isinstance(components_by_ref.get(edge.source_ref), ToolComponent) and (
                edge.relationship == "ref:mcp_server_ref"
            ):
                # ToolComponent.mcp_server_ref points tool -> server; propagate tool -> server
                # and allow server -> tool forward reach discovery.
                propagation_adj.setdefault(edge.source_ref, []).append((edge.target_ref, idx))
                forward_adj.setdefault(edge.target_ref, []).append((edge.source_ref, idx))

    agent_refs = sorted(
        ref for ref, c in components_by_ref.items() if c.component_type in _AGENT_TYPES
    )
    agent_target_set = frozenset(agent_refs)

    def _agent_reach(agent_ref: str) -> tuple[list[str], list[str], list[str], set[str]]:
        visited = {agent_ref}
        queue: deque[str] = deque([agent_ref])
        while queue:
            cur = queue.popleft()
            for nxt, _ in forward_adj.get(cur, ()):
                if nxt not in visited:
                    visited.add(nxt)
                    queue.append(nxt)
        creds = sorted({cs.identifier for r in visited for cs in cred_by_ref.get(r, ())})
        data_refs = sorted(
            r
            for r in visited
            if r in components_by_ref and components_by_ref[r].component_type in _DATA_TYPES
        )
        risky_tools = sorted(
            r
            for r in visited
            if r in components_by_ref
            and components_by_ref[r].component_type is ComponentType.TOOL
            and bool(set(class_by_ref[r].classes) & _HIGH_RISK_CLASSES)
        )
        return creds, data_refs, risky_tools, visited

    agent_exposure_cache = {ag: _agent_reach(ag) for ag in agent_refs}

    raw_chains: list[dict[str, Any]] = []

    # 1. Multi-hop CVE / KEV / EPSS -> Package -> MCP Server -> Agent -> Credentials / Data / Tools
    for adv_node_id in sorted(advisory_nodes):
        adv_meta = advisory_nodes[adv_node_id]
        paths_by_agent = _shortest_paths_to_targets(propagation_adj, adv_node_id, agent_target_set)
        for ag_ref in agent_refs:
            found = paths_by_agent.get(ag_ref)
            if found is None:
                continue
            node_path, edge_indices = found
            creds, data_stores, risky_tools, _ = agent_exposure_cache[ag_ref]
            mcp_hops = [
                r
                for r in node_path
                if r in components_by_ref
                and components_by_ref[r].component_type is ComponentType.MCP_SERVER
            ]
            pkg_hops = [
                r
                for r in node_path
                if r in components_by_ref
                and components_by_ref[r].component_type is ComponentType.REGISTRY_ENTRY
            ]
            raw_chains.append(
                {
                    "kind": "advisory_exposure",
                    "severity": adv_meta["severity"],
                    "in_kev": adv_meta["in_kev"],
                    "epss_score": adv_meta["epss_score"],
                    "entry_ref": adv_node_id,
                    "package_refs": pkg_hops,
                    "mcp_server_refs": mcp_hops,
                    "agent_ref": ag_ref,
                    "path_nodes": list(node_path),
                    "edge_indices": list(edge_indices),
                    "reachable_credentials": creds,
                    "reachable_data_stores": data_stores,
                    "reachable_high_risk_tools": risky_tools,
                }
            )

    # 2. Poisoned / Shadowed Tool or High-Risk MCP Launch -> Agent -> Credentials / Data / Tools
    hazard_starts = sorted(
        (poisoned_refs | set(shadowed_set) | risky_launch_refs) - set(agent_refs)
    )
    for hz_ref in hazard_starts:
        hz_comp = components_by_ref[hz_ref]
        hz_sev = min(
            (_SEVERITY_RANK.get(r.severity.value, 3) for r in hz_comp.risks),
            default=1 if hz_ref in shadowed_set else 2,
        )
        sev_label = next(k for k, v in _SEVERITY_RANK.items() if v == hz_sev)
        paths_by_agent = _shortest_paths_to_targets(propagation_adj, hz_ref, agent_target_set)
        for ag_ref in agent_refs:
            found = paths_by_agent.get(ag_ref)
            if found is None:
                continue
            node_path, edge_indices = found
            creds, data_stores, risky_tools, _ = agent_exposure_cache[ag_ref]
            if not (creds or data_stores or risky_tools):
                continue
            mcp_hops = [
                r
                for r in node_path
                if r in components_by_ref
                and components_by_ref[r].component_type is ComponentType.MCP_SERVER
            ]
            raw_chains.append(
                {
                    "kind": "control_plane_exposure",
                    "severity": sev_label,
                    "in_kev": False,
                    "epss_score": None,
                    "entry_ref": hz_ref,
                    "package_refs": [],
                    "mcp_server_refs": mcp_hops,
                    "agent_ref": ag_ref,
                    "path_nodes": list(node_path),
                    "edge_indices": list(edge_indices),
                    "reachable_credentials": creds,
                    "reachable_data_stores": data_stores,
                    "reachable_high_risk_tools": risky_tools,
                }
            )

    raw_chains.sort(
        key=lambda c: (
            not c["in_kev"],
            _SEVERITY_RANK.get(c["severity"], 5),
            -(c["epss_score"] or 0.0),
            c["kind"],
            c["entry_ref"],
            c["agent_ref"],
        )
    )
    total_kev_chains = sum(1 for c in raw_chains if c["in_kev"])
    chains_omitted = max(0, len(raw_chains) - MAX_CORRELATED_CHAINS)
    kept_chains = raw_chains[:MAX_CORRELATED_CHAINS]
    for idx, ch in enumerate(kept_chains):
        ch["chain_id"] = f"chain:{idx + 1:04d}"

    return {
        "format": FORMAT,
        "tool_version": __version__,
        "inventory_sha256": inventory_sha256,
        "coverage": {
            "inventory_status": coverage.status,
            "advisory_status": loaded_adv.coverage if loaded_adv is not None else "not-supplied",
            "advisory_report_sha256": loaded_adv.sha256 if loaded_adv is not None else None,
        },
        "summary": {
            "component_count": len(bom.components),
            "advisory_count": len(advisory_nodes),
            "kev_advisory_count": sum(1 for a in advisory_nodes.values() if a["in_kev"]),
            "edge_count": len(ordered_edges),
            "exposure_chain_count": len(kept_chains),
            "kev_chain_count": total_kev_chains,
            "chains_omitted": chains_omitted,
            "poisoned_component_count": len(poisoned_refs),
            "shadowed_tool_count": len(shadowed_set),
            "trifecta_finding_count": len(trifecta_report.findings),
        },
        "nodes": nodes_out,
        "edges": [e.to_dict() for e in ordered_edges],
        "exposure_chains": kept_chains,
        "limitations": [
            "Edges restate declared or reported associations; runtime execution and exploitability are unobserved.",
            "Credential surfaces record variable, header, scheme, or principal names only; secret values are never read or stored.",
            "Absence of matched advisories or chains means unrecorded exposure, not verified safety.",
        ],
    }


_STYLE = """\
:root { color-scheme: light dark; font-family: system-ui, -apple-system, sans-serif; }
body { margin: 1.5rem; line-height: 1.45; max-width: 76rem; }
h1, h2 { margin-bottom: 0.4rem; }
.meta, .limits { font-size: 0.875rem; opacity: 0.85; margin-bottom: 1rem; }
.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(10rem, 1fr)); gap: 0.6rem; margin: 1rem 0; }
.card { border: 1px solid #8884; border-radius: 6px; padding: 0.6rem 0.8rem; }
.card strong { display: block; font-size: 1.25rem; font-variant-numeric: tabular-nums; }
input[type="search"] { width: 100%; max-width: 24rem; padding: 0.4rem 0.6rem; margin: 0.5rem 0 1rem; border: 1px solid #8886; border-radius: 4px; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin-bottom: 1.5rem; }
th, td { text-align: left; padding: 0.45rem 0.55rem; border-bottom: 1px solid #8883; vertical-align: top; }
code { font-family: ui-monospace, SFMono-Regular, Menlo, monospace; font-size: 0.82rem; }
.badge { display: inline-block; padding: 0.1rem 0.4rem; border-radius: 4px; border: 1px solid #8885; font-size: 0.75rem; font-weight: 600; }
.hidden { display: none; }
"""

_SCRIPT = """\
(function () {
  var box = document.getElementById("chain-filter");
  if (!box) return;
  var rows = Array.prototype.slice.call(document.querySelectorAll("tr[data-filter]"));
  box.addEventListener("input", function () {
    var q = (box.value || "").toLowerCase().slice(0, 200);
    for (var i = 0; i < rows.length; i++) {
      var hay = rows[i].getAttribute("data-filter") || "";
      rows[i].className = (!q || hay.indexOf(q) !== -1) ? "" : "hidden";
    }
  });
})();
"""


def _csp_hash(content: str) -> str:
    digest = hashlib.sha256(content.encode("utf-8")).digest()
    return "'sha256-" + base64.b64encode(digest).decode("ascii") + "'"


def _esc(value: object) -> str:
    return html.escape(neutralize(str(value)), quote=True)


def render_security_graph_html(document: Mapping[str, Any]) -> str:
    """Render a ``nexus-symbiote/security-graph/v1`` document as an inert CSP-pinned HTML page."""
    csp = (
        "default-src 'none'; "
        f"style-src {_csp_hash(_STYLE)}; "
        f"script-src {_csp_hash(_SCRIPT)}; "
        "base-uri 'none'; form-action 'none'"
    )
    summary = document.get("summary", {})
    coverage = document.get("coverage", {})
    chains = document.get("exposure_chains", [])
    edges = document.get("edges", [])

    chain_rows: list[str] = []
    for ch in chains if isinstance(chains, Sequence) else ():
        if not isinstance(ch, Mapping):
            continue
        hops = " -> ".join(_esc(n) for n in ch.get("path_nodes", ()))
        creds = (
            ", ".join(f"<code>{_esc(c)}</code>" for c in ch.get("reachable_credentials", ()))
            or "none"
        )
        stores = (
            ", ".join(f"<code>{_esc(d)}</code>" for d in ch.get("reachable_data_stores", ()))
            or "none"
        )
        tools = (
            ", ".join(f"<code>{_esc(t)}</code>" for t in ch.get("reachable_high_risk_tools", ()))
            or "none"
        )
        kev_tag = " [KEV]" if ch.get("in_kev") else ""
        filter_key = _esc(
            f"{ch.get('chain_id', '')} {ch.get('entry_ref', '')} {ch.get('agent_ref', '')} "
            f"{' '.join(ch.get('reachable_credentials', ()))}"
        ).lower()
        chain_rows.append(
            f'<tr data-filter="{filter_key}">'
            f"<td><code>{_esc(ch.get('chain_id', ''))}</code></td>"
            f'<td><span class="badge">{_esc(ch.get("severity", ""))}{_esc(kev_tag)}</span></td>'
            f"<td>{_esc(ch.get('kind', ''))}</td>"
            f"<td><code>{hops}</code></td>"
            f"<td>{creds}</td>"
            f"<td>{stores}</td>"
            f"<td>{tools}</td>"
            "</tr>"
        )

    edge_rows: list[str] = []
    for idx, ed in enumerate(edges[:300] if isinstance(edges, Sequence) else ()):
        if not isinstance(ed, Mapping):
            continue
        loc = _esc(ed.get("source_locator") or ed.get("target_locator") or "—")
        ver = _esc(ed.get("version_agreement") or "—")
        cond = _esc(ed.get("conditions") or "—")
        edge_rows.append(
            "<tr>"
            f"<td><code>{idx}</code></td>"
            f"<td><code>{_esc(ed.get('source_ref', ''))}</code></td>"
            f"<td><code>{_esc(ed.get('relationship', ''))}</code></td>"
            f"<td><code>{_esc(ed.get('target_ref', ''))}</code></td>"
            f"<td>{_esc(ed.get('assurance', ''))} ({_esc(ed.get('evidence_method', ''))})</td>"
            f"<td>{ver}</td>"
            f"<td><code>{loc}</code></td>"
            f"<td>{cond}</td>"
            "</tr>"
        )

    limits_html = "".join(f"<li>{_esc(item)}</li>" for item in document.get("limitations", ()))
    chains_body = (
        "".join(chain_rows)
        or '<tr><td colspan="7">No correlated exposure chains recorded.</td></tr>'
    )
    edges_body = "".join(edge_rows) or '<tr><td colspan="8">No graph edges recorded.</td></tr>'

    return (
        "<!DOCTYPE html>\n"
        '<html lang="en">\n<head>\n<meta charset="utf-8">\n'
        f'<meta http-equiv="Content-Security-Policy" content="{csp}">\n'
        "<title>Nexus SymBiote Security Exposure Graph</title>\n"
        f"<style>{_STYLE}</style>\n"
        "</head>\n<body>\n"
        "<h1>Nexus SymBiote — Unified Security Exposure Graph</h1>\n"
        f'<p class="meta">Format: <code>{_esc(document.get("format", FORMAT))}</code> · '
        f"Inventory coverage: <code>{_esc(coverage.get('inventory_status', 'unknown'))}</code> · "
        f"Advisory coverage: <code>{_esc(coverage.get('advisory_status', 'not-supplied'))}</code></p>\n"
        '<div class="cards">'
        f'<div class="card"><span>Components</span><strong>{_esc(summary.get("component_count", 0))}</strong></div>'
        f'<div class="card"><span>Advisories (KEV)</span><strong>{_esc(summary.get("advisory_count", 0))} ({_esc(summary.get("kev_advisory_count", 0))})</strong></div>'
        f'<div class="card"><span>Exposure Chains</span><strong>{_esc(summary.get("exposure_chain_count", 0))}</strong></div>'
        f'<div class="card"><span>Poisoned / Shadowed</span><strong>{_esc(summary.get("poisoned_component_count", 0))} / {_esc(summary.get("shadowed_tool_count", 0))}</strong></div>'
        "</div>\n"
        "<h2>Correlated Multi-Hop Exposure Chains</h2>\n"
        '<input id="chain-filter" type="search" maxlength="200" placeholder="Filter by CVE, component, agent, or credential name...">\n'
        "<table><thead><tr>"
        "<th>ID</th><th>Severity</th><th>Kind</th><th>Propagation Path</th>"
        "<th>Reachable Credentials</th><th>Reachable Data Stores</th><th>High-Risk Tools</th>"
        f"</tr></thead><tbody>{chains_body}</tbody></table>\n"
        "<h2>Traceable Edge Evidence</h2>\n"
        "<table><thead><tr>"
        "<th>#</th><th>Source</th><th>Relationship</th><th>Target</th>"
        "<th>Assurance &amp; Method</th><th>Version Pin</th><th>Locator</th><th>Conditions</th>"
        f"</tr></thead><tbody>{edges_body}</tbody></table>\n"
        f'<ul class="limits">{limits_html}</ul>\n'
        f"<script>{_SCRIPT}</script>\n"
        "</body>\n</html>\n"
    )
