"""Unified assurance-tiered security graph correlator.

Correlates advisories (OSV, CISA/ENISA KEV, EPSS — from either ``advisories --offline-db``
reports or native ``properties.advisories``), high-risk/poisoned components, MCP servers,
tools, agents, IDE agents, credential names (never values), data/RAG/memory stores,
declared egress domains, and declared SPIFFE workload identities into multi-hop exposure
chains with per-hop edge provenance.

Every hop preserves its assurance tier (``observed``, ``declared``, ``reported``, or
``unknown``). Static repository associations never claim proven exploitability or
observed runtime authority, and optional trace evidence is annotated strictly as
``reported`` execution status.
"""

from __future__ import annotations

import hashlib
import html
import json
from collections import deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, RiskSeverity
from nexus_symbiote.core.models import AnyComponent
from nexus_symbiote.graph import _is_credential_env_var_name, _references, validate_graph
from nexus_symbiote.risk_classes import RiskClass, classify
from nexus_symbiote.trifecta import analyze_trifecta
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.vex_decisions import ExecutionEvidence, LoadedAdvisoryReport

SECURITY_GRAPH_SCHEMA = "nexus-symbiote/security-graph/v1"
MAX_CORRELATION_CHAINS = 500
MAX_CHAIN_HOPS = 8

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}
_TRIGGER_RISK_CATEGORIES = frozenset(
    {
        "tool_description_poisoning",
        "instruction_injection",
        "serialization_format",
        "launch_context",
        "credential_exposure",
        "known_vulnerability",
        "capability_scope",
        "oversight_gap",
        "tool_shadowing",
    }
)
_CREDENTIAL_PROP_KEYS = (
    "env_vars_referenced",
    "credential_env_vars",
    "credential_environment_names",
    "credential_references",
)
_SINK_TYPES = frozenset(
    {
        ComponentType.DATA_SOURCE,
        ComponentType.RAG_SOURCE,
        ComponentType.MEMORY_STORE,
    }
)
_AGENT_TYPES = frozenset({ComponentType.AGENT, ComponentType.IDE_AGENT})
_SENSITIVE_RISK_CLASSES = frozenset(
    {
        RiskClass.CODE_EXEC,
        RiskClass.EXFIL_CAPABLE,
        RiskClass.WRITE_CAPABLE,
        RiskClass.SECRET_ACCESS,
    }
)


@dataclass(frozen=True)
class ChainHop:
    """One directed, evidence-backed edge in a correlated security exposure chain."""

    source_ref: str
    target_ref: str
    relationship: str
    assurance: str
    evidence_method: str
    source_locator: str | None = None
    target_locator: str | None = None
    conditions: str | None = None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "source_ref": self.source_ref,
            "target_ref": self.target_ref,
            "relationship": self.relationship,
            "assurance": self.assurance,
            "evidence_method": self.evidence_method,
        }
        if self.source_locator:
            payload["source_locator"] = self.source_locator
        if self.target_locator:
            payload["target_locator"] = self.target_locator
        if self.conditions:
            payload["conditions"] = self.conditions
        return payload


@dataclass(frozen=True)
class AttackChain:
    """One multi-hop exposure chain from an advisory or high-risk trigger to sinks."""

    chain_id: str
    severity: str
    kind: str
    trigger_id: str
    trigger_kind: str
    subject_ref: str
    kev: bool
    epss: float | None
    hops: tuple[ChainHop, ...]
    affected_agents: tuple[str, ...]
    credential_names: tuple[str, ...]
    data_sinks: tuple[str, ...]
    egress_domains: tuple[str, ...]
    workload_identities: tuple[str, ...]
    runtime_status: str
    summary: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id": self.chain_id,
            "severity": self.severity,
            "kind": self.kind,
            "trigger_id": self.trigger_id,
            "trigger_kind": self.trigger_kind,
            "subject_ref": self.subject_ref,
            "kev": self.kev,
            "epss": self.epss,
            "hops": [hop.to_dict() for hop in self.hops],
            "affected_agents": list(self.affected_agents),
            "credential_names": list(self.credential_names),
            "data_sinks": list(self.data_sinks),
            "egress_domains": list(self.egress_domains),
            "workload_identities": list(self.workload_identities),
            "runtime_status": self.runtime_status,
            "summary": self.summary,
        }


@dataclass(frozen=True)
class SecurityGraphReport:
    """Deterministic unified security graph correlation report."""

    schema_version: str
    inventory_sha256: str | None
    advisory_report_sha256: str | None
    trace_evidence_sha256: str | None
    node_count: int
    edge_count: int
    chain_count: int
    kev_chain_count: int
    chains_omitted: int
    severity_counts: dict[str, int]
    chains: tuple[AttackChain, ...]
    trifecta_finding_count: int
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "inventory_sha256": self.inventory_sha256,
            "advisory_report_sha256": self.advisory_report_sha256,
            "trace_evidence_sha256": self.trace_evidence_sha256,
            "node_count": self.node_count,
            "edge_count": self.edge_count,
            "chain_count": self.chain_count,
            "kev_chain_count": self.kev_chain_count,
            "chains_omitted": self.chains_omitted,
            "severity_counts": dict(self.severity_counts),
            "trifecta_finding_count": self.trifecta_finding_count,
            "chains": [chain.to_dict() for chain in self.chains],
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class _AdvisoryEntry:
    advisory_id: str
    component_ref: str
    severity: str
    kev: bool
    epss: float | None
    source: str
    aliases: tuple[str, ...] = ()


def _component_locator(component: AnyComponent) -> str | None:
    if component.source_path:
        return component.source_path
    for claim in component.claims.values():
        if claim.locator:
            return claim.locator
    return None


def _normalize_severity(raw: object) -> str:
    if isinstance(raw, RiskSeverity):
        return raw.value
    if isinstance(raw, str):
        low = raw.strip().lower()
        if low in _SEVERITY_ORDER:
            return low
        if low == "moderate":
            return "medium"
    return "medium"


def _parse_epss(raw: object) -> float | None:
    if isinstance(raw, bool):
        return None
    if isinstance(raw, (int, float)):
        value = float(raw)
        return round(value, 6) if 0.0 <= value <= 1.0 else None
    if isinstance(raw, dict):
        leaf = raw["score"] if "score" in raw else raw.get("epss")
        if isinstance(leaf, bool) or not isinstance(leaf, (int, float)):
            return None
        value = float(leaf)
        return round(value, 6) if 0.0 <= value <= 1.0 else None
    return None


def _parse_kev(entry: Mapping[str, Any]) -> bool:
    for key in ("kev", "in_kev", "cisa_kev", "enisa_kev"):
        val = entry.get(key)
        if val is True:
            return True
        if isinstance(val, dict) and val:
            return True
    return False


def _collect_advisories(
    bom: AIBOM, advisory_report: LoadedAdvisoryReport | None
) -> list[_AdvisoryEntry]:
    """Merge advisories from an offline/live report and native ``properties.advisories``."""
    merged: dict[tuple[str, str], _AdvisoryEntry] = {}
    alias_index: dict[tuple[str, str], tuple[str, str]] = {}

    def add(entry: _AdvisoryEntry) -> None:
        all_ids = (entry.advisory_id, *entry.aliases)
        key = next(
            (
                alias_index[(ident, entry.component_ref)]
                for ident in all_ids
                if (ident, entry.component_ref) in alias_index
            ),
            (entry.advisory_id, entry.component_ref),
        )
        existing = merged.get(key)
        if existing is None:
            merged[key] = entry
        else:
            best_sev = (
                entry.severity
                if _SEVERITY_ORDER[entry.severity] < _SEVERITY_ORDER[existing.severity]
                else existing.severity
            )
            best_epss = (
                entry.epss
                if existing.epss is None or (entry.epss is not None and entry.epss > existing.epss)
                else existing.epss
            )
            merged[key] = _AdvisoryEntry(
                advisory_id=existing.advisory_id,
                component_ref=existing.component_ref,
                severity=best_sev,
                kev=existing.kev or entry.kev,
                epss=best_epss,
                source=existing.source,
                aliases=tuple(
                    sorted((set(existing.aliases) | set(all_ids)) - {existing.advisory_id})
                ),
            )
        for ident in all_ids:
            alias_index[(ident, entry.component_ref)] = key

    if advisory_report is not None:
        for raw in advisory_report.advisories:
            adv_id = str(raw.get("advisory_id") or raw.get("id") or "").strip()
            comp_ref = str(raw.get("component_ref") or raw.get("bom_ref") or "").strip()
            if not adv_id or not comp_ref:
                continue
            raw_aliases = raw.get("aliases")
            aliases = (
                tuple(sorted({str(a) for a in raw_aliases if isinstance(a, str) and a.strip()}))
                if isinstance(raw_aliases, list)
                else ()
            )
            add(
                _AdvisoryEntry(
                    advisory_id=adv_id,
                    component_ref=comp_ref,
                    severity=_normalize_severity(raw.get("severity")),
                    kev=_parse_kev(raw),
                    epss=_parse_epss(raw.get("epss") if "epss" in raw else raw.get("epss_score")),
                    source="advisory-report",
                    aliases=aliases,
                )
            )

    for comp in bom.components:
        prop_advisories = comp.properties.get("advisories")
        if not isinstance(prop_advisories, list):
            continue
        for raw in prop_advisories:
            if not isinstance(raw, Mapping):
                continue
            adv_id = str(raw.get("id") or raw.get("advisory_id") or "").strip()
            if not adv_id:
                continue
            raw_aliases = raw.get("aliases")
            aliases = (
                tuple(sorted({str(a) for a in raw_aliases if isinstance(a, str) and a.strip()}))
                if isinstance(raw_aliases, list)
                else ()
            )
            add(
                _AdvisoryEntry(
                    advisory_id=adv_id,
                    component_ref=comp.bom_ref,
                    severity=_normalize_severity(raw.get("severity")),
                    kev=_parse_kev(raw),
                    epss=_parse_epss(raw.get("epss") if "epss" in raw else raw.get("epss_score")),
                    source="inventory-property",
                    aliases=aliases,
                )
            )

    return sorted(merged.values(), key=lambda item: (item.component_ref, item.advisory_id))


def _credential_names_for_component(component: AnyComponent) -> set[str]:
    """Extract credential environment variable names (never values) from a component."""
    names: set[str] = set()
    env_map = getattr(component, "env", None)
    if isinstance(env_map, Mapping):
        for key in env_map:
            if isinstance(key, str) and _is_credential_env_var_name(key):
                names.add(key)
    for prop_key in _CREDENTIAL_PROP_KEYS:
        raw = component.properties.get(prop_key)
        if isinstance(raw, list):
            for entry in raw:
                if isinstance(entry, str) and _is_credential_env_var_name(entry):
                    names.add(entry)
    return names


def _build_evidence_graph(
    bom: AIBOM, nodes: Mapping[str, AnyComponent]
) -> tuple[dict[str, list[ChainHop]], dict[str, list[ChainHop]], int]:
    """Construct forward and reverse adjacency tables with per-edge provenance."""
    forward: dict[str, list[ChainHop]] = {}
    reverse: dict[str, list[ChainHop]] = {}
    seen: set[tuple[str, str, str]] = set()

    def register(hop: ChainHop) -> None:
        key = (hop.source_ref, hop.target_ref, hop.relationship)
        if key in seen or hop.source_ref not in nodes or hop.target_ref not in nodes:
            return
        seen.add(key)
        forward.setdefault(hop.source_ref, []).append(hop)
        reverse.setdefault(hop.target_ref, []).append(hop)

    for edge in bom.dependencies:
        src = nodes.get(edge.source_ref)
        dst = nodes.get(edge.target_ref)
        if src is None or dst is None:
            continue
        register(
            ChainHop(
                source_ref=edge.source_ref,
                target_ref=edge.target_ref,
                relationship=edge.relationship,
                assurance=edge.assurance_level or AssuranceLevel.DECLARED.value,
                evidence_method="bom-dependency-edge",
                source_locator=_component_locator(src),
                target_locator=_component_locator(dst),
                conditions=edge.conditions,
            )
        )

    for comp in bom.components:
        src_loc = _component_locator(comp)
        for field_name, target_ref in _references(comp):
            dst = nodes.get(target_ref)
            if dst is None:
                continue
            register(
                ChainHop(
                    source_ref=comp.bom_ref,
                    target_ref=target_ref,
                    relationship=field_name,
                    assurance=comp.assurance_level.value,
                    evidence_method="component-reference",
                    source_locator=src_loc,
                    target_locator=_component_locator(dst),
                )
            )
        upstreams = comp.properties.get("upstream_server_refs")
        if isinstance(upstreams, list):
            for target_ref in upstreams:
                if isinstance(target_ref, str) and target_ref in nodes:
                    register(
                        ChainHop(
                            source_ref=comp.bom_ref,
                            target_ref=target_ref,
                            relationship="proxies-to",
                            assurance=comp.assurance_level.value,
                            evidence_method="mcp-gateway-upstream",
                            source_locator=src_loc,
                            target_locator=_component_locator(nodes[target_ref]),
                        )
                    )

    for adj in (forward, reverse):
        for key in adj:
            adj[key].sort(key=lambda h: (h.source_ref, h.target_ref, h.relationship))
    return forward, reverse, len(seen)


def _shortest_reverse_path(
    reverse: Mapping[str, list[ChainHop]],
    start_ref: str,
    target_refs: set[str],
    max_hops: int,
) -> tuple[str | None, list[ChainHop]]:
    """Find shortest path from ``start_ref`` upstream to any ref in ``target_refs``."""
    if start_ref in target_refs:
        return start_ref, []
    queue: deque[tuple[str, list[ChainHop]]] = deque([(start_ref, [])])
    visited = {start_ref}
    while queue:
        current, path = queue.popleft()
        if len(path) >= max_hops:
            continue
        for hop in reverse.get(current, ()):
            upstream_ref = hop.source_ref
            if upstream_ref in visited:
                continue
            next_path = [*path, hop]
            if upstream_ref in target_refs:
                return upstream_ref, next_path
            visited.add(upstream_ref)
            queue.append((upstream_ref, next_path))
    return None, []


def _shortest_forward_paths(
    forward: Mapping[str, list[ChainHop]],
    start_ref: str,
    max_hops: int,
) -> dict[str, list[ChainHop]]:
    """Shortest forward paths anchored strictly at ``start_ref`` so hops stay contiguous."""
    paths: dict[str, list[ChainHop]] = {start_ref: []}
    queue: deque[tuple[str, list[ChainHop]]] = deque([(start_ref, [])])
    while queue:
        cur, path = queue.popleft()
        if len(path) >= max_hops:
            continue
        for hop in forward.get(cur, ()):
            nxt = hop.target_ref
            if nxt in paths:
                continue
            next_path = [*path, hop]
            paths[nxt] = next_path
            queue.append((nxt, next_path))
    return paths


def _collect_reachable(
    forward: Mapping[str, list[ChainHop]],
    reverse: Mapping[str, list[ChainHop]],
    starts: Iterable[str],
    max_hops: int,
) -> tuple[set[str], set[str]]:
    """Return upstream refs and all forward-reachable refs from starts and upstream."""
    upstream: set[str] = set()
    up_queue: deque[tuple[str, int]] = deque((ref, 0) for ref in starts)
    while up_queue:
        cur, depth = up_queue.popleft()
        if cur in upstream:
            continue
        upstream.add(cur)
        if depth < max_hops:
            for hop in reverse.get(cur, ()):
                if hop.source_ref not in upstream:
                    up_queue.append((hop.source_ref, depth + 1))

    reachable: set[str] = set()
    fwd_queue: deque[tuple[str, int]] = deque((ref, 0) for ref in sorted(set(starts) | upstream))
    while fwd_queue:
        cur, depth = fwd_queue.popleft()
        if cur in reachable:
            continue
        reachable.add(cur)
        if depth < max_hops:
            for hop in forward.get(cur, ()):
                if hop.target_ref not in reachable:
                    fwd_queue.append((hop.target_ref, depth + 1))
    return upstream, reachable


def _chain_severity(
    base_severity: str,
    *,
    kev: bool,
    epss: float | None,
    has_agent: bool,
    has_sensitive_sink: bool,
) -> str:
    if kev and (has_agent or has_sensitive_sink):
        return "critical"
    if base_severity == "critical":
        return "critical"
    if base_severity == "high" and has_agent and has_sensitive_sink:
        return "critical" if (epss is not None and epss >= 0.5) else "high"
    return base_severity


def _runtime_status_for_refs(
    refs: Iterable[str], execution_evidence: ExecutionEvidence | None
) -> str:
    if execution_evidence is None:
        return "unobserved"
    outcomes = {
        outcome for ref in refs if (outcome := execution_evidence.outcome_for(ref)) is not None
    }
    if "shadowed" in outcomes:
        return "reported:shadowed"
    if "invoked" in outcomes:
        return "reported:invoked"
    if "declared-never-loaded" in outcomes:
        return "reported:declared-never-loaded"
    return "reported:unobserved"


def _make_chain_id(trigger_kind: str, trigger_id: str, subject_ref: str) -> str:
    raw = f"{trigger_kind}\0{trigger_id}\0{subject_ref}".encode()
    return "chain:" + hashlib.sha256(raw).hexdigest()[:16]


def build_security_graph(
    bom: AIBOM,
    *,
    advisory_report: LoadedAdvisoryReport | None = None,
    execution_evidence: ExecutionEvidence | None = None,
    inventory_sha256: str | None = None,
    max_chains: int = MAX_CORRELATION_CHAINS,
) -> SecurityGraphReport:
    """Correlate advisories, risks, components, and agents into traceable exposure chains."""
    issues = validate_graph(bom)
    if issues:
        raise ValueError("invalid graph: " + "; ".join(issues))

    nodes = {comp.bom_ref: comp for comp in bom.components}
    forward, reverse, edge_count = _build_evidence_graph(bom, nodes)
    agent_refs = {ref for ref, comp in nodes.items() if comp.component_type in _AGENT_TYPES}
    trifecta_report = analyze_trifecta(bom)

    component_creds: dict[str, set[str]] = {
        ref: _credential_names_for_component(comp) for ref, comp in nodes.items()
    }
    component_classes: dict[str, set[RiskClass]] = {
        ref: set(classify(comp).classes) for ref, comp in nodes.items()
    }

    chains: list[AttackChain] = []

    def build_chain(
        *,
        trigger_kind: str,
        trigger_id: str,
        subject_ref: str,
        base_severity: str,
        kev: bool,
        epss: float | None,
        chain_kind: str,
        evidence_method: str,
    ) -> None:
        if subject_ref not in nodes:
            return
        subject = nodes[subject_ref]
        upstream, reachable = _collect_reachable(forward, reverse, [subject_ref], MAX_CHAIN_HOPS)
        affected_agents = sorted(ref for ref in upstream if ref in agent_refs)

        hops: list[ChainHop] = [
            ChainHop(
                source_ref=f"{trigger_kind}:{trigger_id}",
                target_ref=subject_ref,
                relationship="affects",
                assurance="reported"
                if trigger_kind == "advisory"
                else subject.assurance_level.value,
                evidence_method=evidence_method,
                target_locator=_component_locator(subject),
            )
        ]

        reached_agent: str | None = None
        if affected_agents:
            reached_agent, rev_hops = _shortest_reverse_path(
                reverse, subject_ref, set(affected_agents), MAX_CHAIN_HOPS
            )
            if reached_agent is not None:
                for hop in rev_hops:
                    hops.append(
                        ChainHop(
                            source_ref=hop.target_ref,
                            target_ref=hop.source_ref,
                            relationship=f"reaches-via:{hop.relationship}",
                            assurance=hop.assurance,
                            evidence_method=hop.evidence_method,
                            source_locator=hop.target_locator,
                            target_locator=hop.source_locator,
                            conditions=hop.conditions,
                        )
                    )

        cred_names: set[str] = set()
        data_sinks: set[str] = set()
        egress_domains: set[str] = set()
        workload_ids: set[str] = set()
        sensitive_tool_sinks: list[str] = []

        for ref in sorted(reachable):
            comp = nodes[ref]
            cred_names.update(component_creds[ref])
            if comp.component_type in _SINK_TYPES:
                data_sinks.add(ref)
            if component_classes[ref] & _SENSITIVE_RISK_CLASSES and ref != subject_ref:
                sensitive_tool_sinks.append(ref)
            spiffe = comp.properties.get("declared_spiffe_id")
            if isinstance(spiffe, str) and spiffe:
                workload_ids.add(spiffe)
            domains = comp.properties.get("declared_egress_domains")
            if isinstance(domains, list):
                egress_domains.update(d for d in domains if isinstance(d, str) and d)

        # Anchor forward sink path strictly at the tail of the current hop chain so every
        # consecutive edge shares an endpoint (never concatenating disconnected branches).
        anchor_ref = reached_agent if reached_agent is not None else subject_ref
        fwd_paths = _shortest_forward_paths(forward, anchor_ref, MAX_CHAIN_HOPS)
        sink_target = next(
            (ref for ref in sorted(data_sinks) if fwd_paths.get(ref)),
            next((ref for ref in sensitive_tool_sinks if fwd_paths.get(ref)), None),
        )
        if sink_target is not None:
            for hop in fwd_paths[sink_target]:
                if len(hops) < MAX_CHAIN_HOPS + 2:
                    hops.append(hop)

        has_sensitive = bool(cred_names or data_sinks or egress_domains or sensitive_tool_sinks)
        severity = _chain_severity(
            base_severity,
            kev=kev,
            epss=epss,
            has_agent=bool(affected_agents),
            has_sensitive_sink=has_sensitive,
        )
        runtime_status = _runtime_status_for_refs(
            {subject_ref, *affected_agents, *data_sinks}, execution_evidence
        )
        parts = [f"{trigger_id} on {subject.name}"]
        if affected_agents:
            parts.append(f"reaches {len(affected_agents)} agent(s)")
        if cred_names:
            parts.append(f"{len(cred_names)} credential name(s)")
        if data_sinks:
            parts.append(f"{len(data_sinks)} data/memory sink(s)")
        if kev:
            parts.append("KEV-listed")

        chains.append(
            AttackChain(
                chain_id=_make_chain_id(trigger_kind, trigger_id, subject_ref),
                severity=severity,
                kind=chain_kind,
                trigger_id=trigger_id,
                trigger_kind=trigger_kind,
                subject_ref=subject_ref,
                kev=kev,
                epss=epss,
                hops=tuple(hops),
                affected_agents=tuple(affected_agents),
                credential_names=tuple(sorted(cred_names)),
                data_sinks=tuple(sorted(data_sinks)),
                egress_domains=tuple(sorted(egress_domains)),
                workload_identities=tuple(sorted(workload_ids)),
                runtime_status=runtime_status,
                summary="; ".join(parts),
            )
        )

    for adv in _collect_advisories(bom, advisory_report):
        build_chain(
            trigger_kind="advisory",
            trigger_id=adv.advisory_id,
            subject_ref=adv.component_ref,
            base_severity=adv.severity,
            kev=adv.kev,
            epss=adv.epss,
            chain_kind="advisory-exposure",
            evidence_method=adv.source,
        )

    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        best_by_cat: dict[str, str] = {}
        for risk in comp.risks:
            if (
                risk.severity in (RiskSeverity.CRITICAL, RiskSeverity.HIGH)
                and risk.category in _TRIGGER_RISK_CATEGORIES
            ):
                sev = risk.severity.value
                prev = best_by_cat.get(risk.category)
                if prev is None or _SEVERITY_ORDER[sev] < _SEVERITY_ORDER[prev]:
                    best_by_cat[risk.category] = sev
        for category, sev in sorted(best_by_cat.items()):
            build_chain(
                trigger_kind="finding",
                trigger_id=category,
                subject_ref=comp.bom_ref,
                base_severity=sev,
                kev=False,
                epss=None,
                chain_kind="risk-exposure",
                evidence_method="component-risk",
            )

    best_trifecta: dict[tuple[str, str], str] = {}
    for finding in trifecta_report.findings:
        if finding.component_refs:
            tkey = (finding.kind, finding.component_refs[0])
            sev = finding.severity.value
            prev = best_trifecta.get(tkey)
            if prev is None or _SEVERITY_ORDER[sev] < _SEVERITY_ORDER[prev]:
                best_trifecta[tkey] = sev
    for (kind, subject_ref), sev in sorted(best_trifecta.items()):
        build_chain(
            trigger_kind="trifecta",
            trigger_id=kind,
            subject_ref=subject_ref,
            base_severity=sev,
            kev=False,
            epss=None,
            chain_kind=kind,
            evidence_method="trifecta-analysis",
        )

    # Sort KEV-listed chains first so max_chains truncation can never hide a KEV chain,
    # and compute total kev_chain_count across all correlated chains before slicing.
    chains.sort(
        key=lambda c: (
            not c.kev,
            _SEVERITY_ORDER.get(c.severity, 99),
            -(c.epss if c.epss is not None else -1.0),
            c.chain_id,
        )
    )
    total_kev_chains = sum(1 for c in chains if c.kev)
    omitted = max(0, len(chains) - max_chains)
    kept = tuple(chains[:max_chains])
    sev_counts: dict[str, int] = {}
    for chain in kept:
        sev_counts[chain.severity] = sev_counts.get(chain.severity, 0) + 1

    limitations = [
        "Correlated chains express static repository and reported advisory associations, "
        "not proven exploitability or observed runtime authority.",
    ]
    if advisory_report is None:
        limitations.append(
            "No external advisory report was supplied; only advisories embedded in inventory "
            "properties were correlated."
        )
    if execution_evidence is None:
        limitations.append("No runtime trace evidence was supplied; runtime_status is unobserved.")
    if omitted:
        limitations.append(
            f"{omitted} lower-priority chain(s) omitted beyond max_chains={max_chains}."
        )

    return SecurityGraphReport(
        schema_version=SECURITY_GRAPH_SCHEMA,
        inventory_sha256=inventory_sha256,
        advisory_report_sha256=None if advisory_report is None else advisory_report.sha256,
        trace_evidence_sha256=None if execution_evidence is None else execution_evidence.sha256,
        node_count=len(nodes),
        edge_count=edge_count,
        chain_count=len(kept),
        kev_chain_count=total_kev_chains,
        chains_omitted=omitted,
        severity_counts=dict(sorted(sev_counts.items())),
        chains=kept,
        trifecta_finding_count=len(trifecta_report.findings),
        limitations=tuple(limitations),
    )


def render_security_graph_json(report: SecurityGraphReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


def _mermaid_node_id(raw: str) -> str:
    return "n_" + hashlib.sha256(raw.encode("utf-8")).hexdigest()[:12]


def _mermaid_label(raw: str) -> str:
    escaped = html.escape(neutralize(raw), quote=True)
    for char, repl in (
        ("|", "/"),
        ("[", "("),
        ("]", ")"),
        ("`", "'"),
        ("#", ""),
        (";", ","),
    ):
        escaped = escaped.replace(char, repl)
    return escaped


def _md_cell(raw: str) -> str:
    return neutralize(raw).replace("|", "\\|").replace("<", "&lt;").replace(">", "&gt;")


def render_security_graph_mermaid(report: SecurityGraphReport) -> str:
    lines = ["flowchart LR"]
    declared: set[str] = set()
    edges: set[tuple[str, str, str]] = set()
    for chain in report.chains:
        for hop in chain.hops:
            src_id = _mermaid_node_id(hop.source_ref)
            dst_id = _mermaid_node_id(hop.target_ref)
            if src_id not in declared:
                lines.append(f'  {src_id}["{_mermaid_label(hop.source_ref)}"]')
                declared.add(src_id)
            if dst_id not in declared:
                lines.append(f'  {dst_id}["{_mermaid_label(hop.target_ref)}"]')
                declared.add(dst_id)
            edge_key = (src_id, dst_id, hop.relationship)
            if edge_key not in edges:
                label = _mermaid_label(f"{hop.relationship} ({hop.assurance})")
                lines.append(f'  {src_id} -->|"{label}"| {dst_id}')
                edges.add(edge_key)
    if len(lines) == 1:
        lines.append('  empty["No correlated exposure chains"]')
    return "\n".join(neutralize(line) for line in lines) + "\n"


def render_security_graph_markdown(report: SecurityGraphReport) -> str:
    lines = [
        "# Security Graph Correlation Report",
        "",
        f"- **Nodes:** {report.node_count} | **Edges:** {report.edge_count} | "
        f"**Chains:** {report.chain_count} | **KEV Chains:** {report.kev_chain_count}",
        "",
    ]
    if not report.chains:
        lines.append("No correlated exposure chains found.")
    else:
        lines.extend(
            [
                "| Severity | Trigger | Subject | Agents | Credentials | KEV | Runtime |",
                "| --- | --- | --- | --- | --- | --- | --- |",
            ]
        )
        for chain in report.chains:
            agents = ", ".join(_md_cell(a) for a in chain.affected_agents) or "-"
            creds = ", ".join(_md_cell(c) for c in chain.credential_names) or "-"
            lines.append(
                f"| {_md_cell(chain.severity)} | {_md_cell(chain.trigger_id)} | "
                f"{_md_cell(chain.subject_ref)} | {agents} | {creds} | "
                f"{'yes' if chain.kev else 'no'} | {_md_cell(chain.runtime_status)} |"
            )
    lines.extend(["", "## Limitations", ""])
    lines.extend(f"- {neutralize(item)}" for item in report.limitations)
    return "\n".join(neutralize(line) for line in lines) + "\n"


def render_security_graph_html(report: SecurityGraphReport) -> str:
    """Render a self-contained, CSP-pinned static HTML view (zero scripts)."""
    rows: list[str] = []
    for chain in report.chains:
        hops_html = " &rarr; ".join(
            f"<code>{html.escape(neutralize(h.source_ref))}</code> "
            f"<em>[{html.escape(neutralize(h.relationship))}/{html.escape(neutralize(h.assurance))}]</em> "
            f"&rarr; <code>{html.escape(neutralize(h.target_ref))}</code>"
            for h in chain.hops
        )
        rows.append(
            "<tr>"
            f"<td>{html.escape(neutralize(chain.severity))}</td>"
            f"<td><code>{html.escape(neutralize(chain.trigger_id))}</code></td>"
            f"<td>{'YES' if chain.kev else 'no'}</td>"
            f"<td>{html.escape(neutralize(chain.runtime_status))}</td>"
            f"<td>{hops_html}</td>"
            "</tr>"
        )
    table_body = "".join(rows) or '<tr><td colspan="5">No correlated exposure chains.</td></tr>'
    limits_html = "".join(
        f"<li>{html.escape(neutralize(item))}</li>" for item in report.limitations
    )
    return (
        "<!DOCTYPE html>\n"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" '
        "content=\"default-src 'none'; style-src 'unsafe-inline'\">"
        "<title>Nexus SymBiote Security Graph</title>"
        "<style>body{font-family:system-ui,sans-serif;margin:2rem;color:#111}"
        "table{border-collapse:collapse;width:100%}th,td{border:1px solid #ccc;padding:.5rem;text-align:left}"
        "th{background:#f4f4f4}</style></head><body>"
        "<h1>Nexus SymBiote Security Graph Correlation</h1>"
        f"<p>Nodes: {report.node_count} | Edges: {report.edge_count} | "
        f"Chains: {report.chain_count} | KEV Chains: {report.kev_chain_count}</p>"
        "<table><thead><tr><th>Severity</th><th>Trigger</th><th>KEV</th>"
        "<th>Runtime</th><th>Evidence Path</th></tr></thead>"
        f"<tbody>{table_body}</tbody></table>"
        f"<h2>Limitations</h2><ul>{limits_html}</ul></body></html>\n"
    )
