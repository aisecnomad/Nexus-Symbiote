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
from bisect import bisect_left
from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, RiskSeverity
from nexus_symbiote.core.models import AnyComponent
from nexus_symbiote.graph import (
    _declared_workload_values,
    _is_credential_env_var_name,
    _references,
    validate_graph,
)
from nexus_symbiote.risk_classes import RiskClass, classify
from nexus_symbiote.trifecta import analyze_trifecta
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.vex_decisions import ExecutionEvidence, LoadedAdvisoryReport

SECURITY_GRAPH_SCHEMA = "nexus-symbiote/security-graph/v1"
MAX_CORRELATION_CHAINS = 500
MAX_CHAIN_HOPS = 8
MAX_SUBJECT_EDGE_VISITS = 4096
MAX_REPORT_EDGE_VISITS = 100_000

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
    "unknown": 5,
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
    traversal_complete: bool = True

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
            "traversal_complete": self.traversal_complete,
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


def _merge_advisory_aliases(entries: list[_AdvisoryEntry]) -> list[_AdvisoryEntry]:
    """Resolve every alias link for one component before ranking its advisories."""
    parents: dict[str, str] = {}

    def root(ident: str) -> str:
        while ident in parents:
            parent = parents[ident]
            if parent in parents:
                parents[ident] = parents[parent]
            ident = parents[ident]
        return ident

    for entry in entries:
        primary = root(entry.advisory_id)
        for alias in entry.aliases:
            other = root(alias)
            if other != primary:
                parents[other] = primary

    groups: dict[str, list[_AdvisoryEntry]] = defaultdict(list)
    for entry in entries:
        groups[root(entry.advisory_id)].append(entry)

    merged = []
    for group in groups.values():
        # Preserve a sole reported ID. Among multiple primary IDs prefer CVE, then lexical order.
        primary = min(
            (e.advisory_id for e in group), key=lambda i: (not i.upper().startswith("CVE-"), i)
        )
        identifiers = {i for e in group for i in (e.advisory_id, *e.aliases)}
        merged.append(
            _AdvisoryEntry(
                advisory_id=primary,
                component_ref=group[0].component_ref,
                severity=min((e.severity for e in group), key=_SEVERITY_ORDER.__getitem__),
                kev=any(e.kev for e in group),
                epss=max((e.epss for e in group if e.epss is not None), default=None),
                source="advisory-report"
                if any(e.source == "advisory-report" for e in group)
                else "inventory-property",
                aliases=tuple(sorted(identifiers - {primary})),
            )
        )
    return sorted(merged, key=lambda e: e.advisory_id)


def _collect_advisories(
    bom: AIBOM, advisory_report: LoadedAdvisoryReport | None, subject_refs: set[str]
) -> dict[str, list[_AdvisoryEntry]]:
    """Merge advisories from an offline/live report and native ``properties.advisories``."""
    by_subject: dict[str, list[_AdvisoryEntry]] = defaultdict(list)

    def add(raw: Mapping[str, Any], ident: object, ref: str, source: str) -> None:
        adv_id = str(ident or "").strip()
        if not adv_id:
            return
        raw_aliases = raw.get("aliases")
        aliases = (
            tuple(sorted({a.strip() for a in raw_aliases if isinstance(a, str) and a.strip()}))
            if isinstance(raw_aliases, list)
            else ()
        )
        by_subject[ref].append(
            _AdvisoryEntry(
                advisory_id=adv_id,
                component_ref=ref,
                severity=_normalize_severity(raw.get("severity")),
                kev=_parse_kev(raw),
                epss=_parse_epss(raw.get("epss", raw.get("epss_score"))),
                source=source,
                aliases=aliases,
            )
        )

    if advisory_report is not None:
        for raw in advisory_report.advisories:
            ref = str(raw.get("component_ref") or raw.get("bom_ref") or "").strip()
            if ref in subject_refs:
                add(raw, raw.get("advisory_id") or raw.get("id"), ref, "advisory-report")

    for comp in bom.components:
        if comp.bom_ref not in subject_refs:
            continue
        prop_advisories = comp.properties.get("advisories")
        if isinstance(prop_advisories, list):
            for raw in prop_advisories:
                if isinstance(raw, Mapping):
                    add(
                        raw,
                        raw.get("id") or raw.get("advisory_id"),
                        comp.bom_ref,
                        "inventory-property",
                    )
    return {ref: _merge_advisory_aliases(entries) for ref, entries in by_subject.items()}


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


def _reference_evidence(
    component: AnyComponent, field_name: str, fallback_locator: str | None
) -> tuple[str, str | None]:
    """Derive per-hop assurance from relationship evidence, never component identity."""
    claim = component.claims.get(field_name)
    if claim is not None:
        return claim.assurance.value, claim.locator or fallback_locator
    return AssuranceLevel.DECLARED.value, fallback_locator


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
            ref_assurance, ref_locator = _reference_evidence(comp, field_name, src_loc)
            register(
                ChainHop(
                    source_ref=comp.bom_ref,
                    target_ref=target_ref,
                    relationship=field_name,
                    assurance=ref_assurance,
                    evidence_method="component-reference",
                    source_locator=ref_locator,
                    target_locator=_component_locator(dst),
                )
            )
        upstreams = comp.properties.get("upstream_server_refs")
        if isinstance(upstreams, list):
            ref_assurance, ref_locator = _reference_evidence(comp, "upstream_server_refs", src_loc)
            for target_ref in upstreams:
                if isinstance(target_ref, str) and target_ref in nodes:
                    register(
                        ChainHop(
                            source_ref=comp.bom_ref,
                            target_ref=target_ref,
                            relationship="proxies-to",
                            assurance=ref_assurance,
                            evidence_method="mcp-gateway-upstream",
                            source_locator=ref_locator,
                            target_locator=_component_locator(nodes[target_ref]),
                        )
                    )

    for adj in (forward, reverse):
        for key in adj:
            adj[key].sort(key=lambda h: (h.source_ref, h.target_ref, h.relationship))
    return forward, reverse, len(seen)


@dataclass
class _WalkBudget:
    remaining: int
    subject_remaining: int = 0
    complete: bool = True

    def paths(
        self,
        adjacency: Mapping[str, list[ChainHop]],
        starts: Iterable[str],
        *,
        reverse: bool = False,
    ) -> dict[str, ChainHop | None]:
        """Record one shortest-path parent per discovered component, charging each examined edge."""
        parents: dict[str, ChainHop | None] = dict.fromkeys(starts)
        queue = deque((ref, 0) for ref in parents)
        while queue:
            current, depth = queue.popleft()
            for hop in adjacency.get(current, ()):
                if not self.remaining or not self.subject_remaining:
                    self.complete = False
                    return parents
                self.remaining -= 1
                self.subject_remaining -= 1
                ref = hop.source_ref if reverse else hop.target_ref
                if ref in parents:
                    continue
                if depth == MAX_CHAIN_HOPS:
                    self.complete = False
                    continue
                parents[ref] = hop
                queue.append((ref, depth + 1))
        return parents


def _path(
    parents: Mapping[str, ChainHop | None], end: str, *, reverse: bool = False
) -> list[ChainHop]:
    path: list[ChainHop] = []
    while (hop := parents[end]) is not None:
        if reverse:
            end = hop.target_ref
            hop = ChainHop(
                hop.target_ref,
                hop.source_ref,
                f"reaches-via:{hop.relationship}",
                hop.assurance,
                hop.evidence_method,
                hop.target_locator,
                hop.source_locator,
                hop.conditions,
            )
        else:
            end = hop.source_ref
        path.append(hop)
    return list(reversed(path))


@dataclass(frozen=True)
class _Exposure:
    hops: tuple[ChainHop, ...]
    agents: tuple[str, ...]
    credentials: tuple[str, ...]
    sinks: tuple[str, ...]
    egress: tuple[str, ...]
    workloads: tuple[str, ...]
    sensitive: bool
    runtime_status: str


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
    subject_refs: set[str] | None = None,
) -> SecurityGraphReport:
    """Correlate advisories, risks, components, and agents into traceable exposure chains."""
    issues = validate_graph(bom)
    if issues:
        raise ValueError("invalid graph: " + "; ".join(issues))

    if not 1 <= max_chains <= MAX_CORRELATION_CHAINS:
        raise ValueError(f"max_chains must be between 1 and {MAX_CORRELATION_CHAINS}")
    nodes = {comp.bom_ref: comp for comp in bom.components}
    scope = set(nodes) if subject_refs is None else nodes.keys() & subject_refs
    forward, reverse, edge_count = _build_evidence_graph(bom, nodes)
    agent_refs = {ref for ref, comp in nodes.items() if comp.component_type in _AGENT_TYPES}
    trifecta_report = analyze_trifecta(bom)

    component_creds: dict[str, set[str]] = {
        ref: _credential_names_for_component(comp) for ref, comp in nodes.items()
    }
    component_classes: dict[str, set[RiskClass]] = {
        ref: set(classify(comp).classes) for ref, comp in nodes.items()
    }

    budget = _WalkBudget(MAX_REPORT_EDGE_VISITS)

    def exposure(subject_ref: str) -> _Exposure:
        budget.subject_remaining = MAX_SUBJECT_EDGE_VISITS
        upstream = budget.paths(reverse, [subject_ref], reverse=True)
        agents = tuple(sorted(agent_refs.intersection(upstream)))
        anchor = next((ref for ref in upstream if ref in agent_refs), subject_ref)
        reverse_hops = _path(upstream, anchor, reverse=True)
        paths = budget.paths(forward, [anchor])
        reachable = paths if len(upstream) == 1 else budget.paths(forward, upstream)
        # Each traversal may reach a different boundary when its budget runs out.
        refs = set(reachable) | paths.keys()
        creds = tuple(sorted({name for ref in refs for name in component_creds[ref]}))
        sinks = tuple(sorted(ref for ref in refs if nodes[ref].component_type in _SINK_TYPES))
        tools = sorted(
            ref
            for ref in refs
            if ref != subject_ref and component_classes[ref] & _SENSITIVE_RISK_CLASSES
        )

        def declared(field: str) -> tuple[str, ...]:
            return tuple(
                sorted({v for ref in refs for v in _declared_workload_values(nodes[ref], field)})
            )

        egress = declared("egress_domains")
        target = next((ref for ref in (*sinks, *tools) if paths.get(ref)), None)
        hops = reverse_hops + (_path(paths, target) if target is not None else [])
        if len(hops) > MAX_CHAIN_HOPS + 1:
            budget.complete = False
            hops = hops[: MAX_CHAIN_HOPS + 1]
        runtime = _runtime_status_for_refs(
            {subject_ref, *agents, *sinks, *(hop.target_ref for hop in hops)}, execution_evidence
        )
        return _Exposure(
            tuple(hops),
            agents,
            creds,
            sinks,
            egress,
            declared("spiffe_id"),
            bool(creds or sinks or egress or tools),
            runtime,
        )

    advisories = _collect_advisories(bom, advisory_report, scope)
    trifectas: dict[str, dict[str, str]] = defaultdict(dict)
    for finding in trifecta_report.findings:
        if finding.component_refs and finding.component_refs[0] in scope:
            kinds = trifectas[finding.component_refs[0]]
            sev = finding.severity.value
            if (
                finding.kind not in kinds
                or _SEVERITY_ORDER[sev] < _SEVERITY_ORDER[kinds[finding.kind]]
            ):
                kinds[finding.kind] = sev

    def triggers(
        subject: AnyComponent,
    ) -> Iterable[tuple[str, str, str, bool, float | None, str, str]]:
        for adv in advisories.get(subject.bom_ref, ()):
            yield (
                "advisory",
                adv.advisory_id,
                adv.severity,
                adv.kev,
                adv.epss,
                "advisory-exposure",
                adv.source,
            )
        best_by_cat: dict[str, str] = {}
        for risk in subject.risks:
            if (
                risk.severity in (RiskSeverity.CRITICAL, RiskSeverity.HIGH)
                and risk.category in _TRIGGER_RISK_CATEGORIES
            ):
                sev = risk.severity.value
                if (
                    risk.category not in best_by_cat
                    or _SEVERITY_ORDER[sev] < _SEVERITY_ORDER[best_by_cat[risk.category]]
                ):
                    best_by_cat[risk.category] = sev
        for category, sev in best_by_cat.items():
            yield "finding", category, sev, False, None, "risk-exposure", "component-risk"
        for kind, sev in trifectas.get(subject.bom_ref, {}).items():
            yield "trifecta", kind, sev, False, None, kind, "trifecta-analysis"

    priorities: list[tuple[bool, int, float, str]] = []
    chains: list[AttackChain] = []
    total = total_kev_chains = 0
    for ref in sorted(scope):
        subject = nodes[ref]
        context = None
        for trigger_kind, trigger_id, base, kev, epss, kind, method in triggers(subject):
            if context is None:
                context = exposure(ref)
            total += 1
            total_kev_chains += int(kev)
            severity = _chain_severity(
                base,
                kev=kev,
                epss=epss,
                has_agent=bool(context.agents),
                has_sensitive_sink=context.sensitive,
            )
            chain_id = _make_chain_id(trigger_kind, trigger_id, ref)
            rank = (
                not kev,
                _SEVERITY_ORDER[severity],
                -(epss if epss is not None else -1.0),
                chain_id,
            )
            index = bisect_left(priorities, rank)
            if index >= max_chains:
                continue
            if len(chains) == max_chains:
                priorities.pop()
                chains.pop()
            priorities.insert(index, rank)
            parts = [f"{trigger_id} on {subject.name}"]
            if context.agents:
                parts.append(f"reaches {len(context.agents)} agent(s)")
            if context.credentials:
                parts.append(f"{len(context.credentials)} credential name(s)")
            if context.sinks:
                parts.append(f"{len(context.sinks)} data/memory sink(s)")
            if kev:
                parts.append("KEV-listed")
            first = ChainHop(
                source_ref=f"{trigger_kind}:{trigger_id}",
                target_ref=ref,
                relationship="affects",
                assurance="reported"
                if trigger_kind == "advisory"
                else AssuranceLevel.DECLARED.value,
                evidence_method=method,
                target_locator=_component_locator(subject),
            )
            chains.insert(
                index,
                AttackChain(
                    chain_id=chain_id,
                    severity=severity,
                    kind=kind,
                    trigger_id=trigger_id,
                    trigger_kind=trigger_kind,
                    subject_ref=ref,
                    kev=kev,
                    epss=epss,
                    hops=(first, *context.hops),
                    affected_agents=context.agents,
                    credential_names=context.credentials,
                    data_sinks=context.sinks,
                    egress_domains=context.egress,
                    workload_identities=context.workloads,
                    runtime_status=context.runtime_status,
                    summary="; ".join(parts),
                ),
            )

    kept = tuple(chains)
    omitted = total - len(kept)
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
    if not budget.complete:
        limitations.append(
            f"Traversal incomplete: paths, affected components, and severity may be incomplete "
            f"at {MAX_CHAIN_HOPS} hops, {MAX_SUBJECT_EDGE_VISITS} edge visits per subject, "
            f"or {MAX_REPORT_EDGE_VISITS} edge visits per report."
        )
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
        traversal_complete=budget.complete,
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
    if not report.traversal_complete or report.chains_omitted:
        lines.append('  partial["Partial view: traversal or output limit reached"]')
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
