"""A navigable view of one inventory: its components, their recorded associations, risk
classes, findings, and the shortest recorded path from each agent to each risky component.

The view restates the native inventory, as a JSON document or as one self-contained HTML
file. Edges are recorded dependency edges and typed reference fields, so a path is a
repository association, not observed runtime reachability or effective authority. Risk
classes restate recorded evidence (``risk_classes``), and unclassified means unknown, not
safe. Every listing the view bounds says how much it left out.

The HTML file is inert: every inventory string is clipped, neutralized and escaped by one
function and appears only as text or as an escaped attribute value; ids, classes and the
data attributes other than ``data-name`` come from node indexes and fixed vocabularies.
The one style block and the one script are fixed text whose hashes the file's
Content-Security-Policy pins, and the script reads indexes and fixed-vocabulary
attributes from the page, and ``data-name`` only to compare it with the name filter.
"""

from __future__ import annotations

import base64
import heapq
import html
import re
from collections import Counter, deque
from collections.abc import Sequence
from dataclasses import dataclass
from operator import attrgetter
from typing import Any, Literal

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.coverage import assess_coverage
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    AnyComponent,
    CompletenessClaim,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.generators._common import coverage_aggregate
from nexus_symbiote.graph import _references, blast_radius, validate_graph
from nexus_symbiote.risk_classes import RiskClass, RiskClassification, classify
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.validators.risk import _intrinsic_model_risks

FORMAT = "nexus-symbiote/graph-view/v1"
MAX_SOURCES = 200
MAX_PATHS = 200
MAX_FINDINGS = 20
MAX_GAPS = 20
LABEL_CHARS = 28
DETAIL_CHARS = 2_000
NAME_FILTER_CHARS = 200

LIMITATIONS = (
    (
        "Edges are repository associations recorded by a static scan; runtime use and "
        "effective authority are unobserved."
    ),
    (
        "Risk classes restate recorded, mostly declared or name-inferred evidence; they do "
        "not establish what a component can do at run time."
    ),
    (
        "Unclassified means no capability evidence that the risk-class rules read was "
        "recorded: unknown, not safe."
    ),
    (
        "Exposure paths show potential reach through recorded edges, not proven "
        "exploitability or runtime access."
    ),
)

_SOURCE_TYPES = frozenset({ComponentType.AGENT, ComponentType.IDE_AGENT})
_SEVERITIES = tuple(RiskSeverity)
_SEVERITY_RANK = {severity: rank for rank, severity in enumerate(_SEVERITIES)}
# A sink's weight orders exposure paths: each flag outranks every flag after it.
_SINK_CLASSES = (
    RiskClass.CODE_EXEC,
    RiskClass.EXFIL_CAPABLE,
    RiskClass.WRITE_CAPABLE,
    RiskClass.SECRET_ACCESS,
)
_UNPINNED_CATEGORIES = frozenset({"version_pinning", "mutable_image_tag"})
_FACTS = (
    "version_pinned",
    "transport",
    "serialization_safety",
    "signing_status",
    "permission_mode",
    "autonomy_level",
    "authentication_required",
)
_COLUMNS: tuple[tuple[str, tuple[ComponentType, ...]], ...] = (
    ("Agents", (ComponentType.AGENT, ComponentType.IDE_AGENT)),
    (
        "Instructions and clients",
        (
            ComponentType.PROMPT_TEMPLATE,
            ComponentType.SKILL_PACKAGE,
            ComponentType.MCP_CLIENT,
            ComponentType.A2A_CLIENT,
        ),
    ),
    ("Servers", (ComponentType.MCP_SERVER, ComponentType.A2A_SERVER)),
    ("Tools", (ComponentType.TOOL,)),
    (
        "Models and data",
        (
            ComponentType.MODEL,
            ComponentType.RAG_SOURCE,
            ComponentType.DATA_SOURCE,
            ComponentType.MEMORY_STORE,
            ComponentType.GUARDRAIL_POLICY,
        ),
    ),
    ("Credentials", (ComponentType.CREDENTIAL,)),
    ("Packages and extensions", (ComponentType.REGISTRY_ENTRY, ComponentType.VERIFIED_EXTENSION)),
)
_PLACE = {
    component_type: (column, row)
    for column, (_, types) in enumerate(_COLUMNS)
    for row, component_type in enumerate(types)
}


class GraphViewError(ValueError):
    """The inventory cannot be viewed; the message quotes at most clipped references."""


class TooManyComponentsError(GraphViewError):
    """The selected graph holds more components than the caller allows."""

    def __init__(self, count: int, limit: int) -> None:
        super().__init__(f"the graph holds {count} components, more than the limit of {limit}")
        self.count = count
        self.limit = limit


@dataclass(frozen=True)
class ShownFinding:
    severity: RiskSeverity
    category: str
    detail: str


@dataclass(frozen=True)
class FindingSummary:
    total: int
    counts: tuple[tuple[RiskSeverity, int], ...]
    shown: tuple[ShownFinding, ...]

    @property
    def highest(self) -> RiskSeverity | None:
        return next((severity for severity, count in self.counts if count), None)

    @property
    def omitted(self) -> int:
        return self.total - len(self.shown)


@dataclass(frozen=True)
class Node:
    index: int
    ref: str
    type: ComponentType
    name: str
    version: str | None
    assurance: AssuranceLevel
    trust_tier: TrustTier
    classification: RiskClassification
    findings: FindingSummary
    facts: tuple[tuple[str, str | bool], ...]
    unpinned: bool
    source_path: str | None

    @property
    def weight(self) -> int:
        """Nonzero for a sink; a critical finding outweighs everything after it, and so on."""
        counts = dict(self.findings.counts)
        flags = (
            counts[RiskSeverity.CRITICAL] > 0,
            counts[RiskSeverity.HIGH] > 0,
            *(risk in self.classification.classes for risk in _SINK_CLASSES),
        )
        return sum(1 << (len(flags) - 1 - place) for place, flag in enumerate(flags) if flag)


@dataclass(frozen=True)
class Edge:
    index: int
    source: int
    target: int
    kind: Literal["dependency", "reference"]
    label: str
    assurance: str | None
    conditional: bool


@dataclass(frozen=True)
class ExposurePath:
    nodes: tuple[int, ...]
    edges: tuple[int, ...]
    labels: tuple[str, ...]
    sink_classes: tuple[RiskClass, ...]
    sink_severity: RiskSeverity | None


@dataclass(frozen=True)
class Coverage:
    status: Literal["incomplete", "unknown"]
    collection: str
    scan_failures: int
    surfaces_excluded: int
    gaps: tuple[str, ...]
    gaps_omitted: int


@dataclass(frozen=True)
class GraphView:
    spec_version: str
    timestamp: str | None
    inventory_components: int
    inventory_dependencies: int
    focus: str | None
    coverage: Coverage
    nodes: tuple[Node, ...]
    edges: tuple[Edge, ...]
    sources: int
    sources_omitted: int
    sinks: int
    paths: tuple[ExposurePath, ...]
    paths_omitted: int


def _clip(text: str, limit: int) -> str:
    return text if len(text) <= limit else text[: limit - 1] + "…"


_RECORDED = re.compile(r" \(recorded \d+ times\)$")


def _clip_gap(gap: str) -> str:
    """Clip a gap to DETAIL_CHARS, keeping the record count a grouped failure ends with."""
    suffix = _RECORDED.search(gap)
    if suffix is None or len(gap) <= DETAIL_CHARS:
        return _clip(gap, DETAIL_CHARS)
    return _clip(gap[: suffix.start()], DETAIL_CHARS - len(suffix[0])) + suffix[0]


def build_view(bom: AIBOM, *, max_nodes: int, focus: str | None = None) -> GraphView:
    """The view of ``bom``, or of the potential blast radius of ``focus`` in it.

    Refuses an invalid graph, an unknown focus and more than ``max_nodes`` components.
    The work is linear in the inventory, plus the kept sources times nodes and edges.
    """
    issues = validate_graph(bom)
    if issues:
        raise GraphViewError("invalid graph: " + "; ".join(issues))
    components: list[AnyComponent] = list(bom.components)
    if focus is not None:
        try:
            radius = blast_radius(bom, focus)
        except ValueError as exc:
            raise GraphViewError(str(exc)) from exc
        kept = {radius["subject"], *radius["dependent_components"], *radius["reachable_components"]}
        components = [component for component in components if component.bom_ref in kept]
    if len(components) > max_nodes:
        raise TooManyComponentsError(len(components), max_nodes)
    components.sort(key=lambda c: (_PLACE[c.component_type], c.name, c.bom_ref))
    nodes = tuple(_node(index, component) for index, component in enumerate(components))
    edges = _edges(bom, components)
    sources, sources_omitted, paths, paths_omitted = _exposure(nodes, edges)
    return GraphView(
        spec_version=bom.metadata.spec_version,
        timestamp=bom.metadata.model_dump(mode="json", include={"timestamp"}).get("timestamp"),
        inventory_components=len(bom.components),
        inventory_dependencies=len(bom.dependencies),
        focus=focus,
        coverage=_coverage(bom.metadata.completeness),
        nodes=nodes,
        edges=edges,
        sources=sources,
        sources_omitted=sources_omitted,
        sinks=sum(1 for node in nodes if node.weight),
        paths=paths,
        paths_omitted=paths_omitted,
    )


def _risks(component: AnyComponent) -> list[RiskAssessment]:
    # A model's recorded fields stand even when its findings were edited away, as in `risk`.
    if isinstance(component, ModelComponent):
        return _intrinsic_model_risks(component)
    return list(getattr(component, "risks", []))


def _findings(risks: Sequence[RiskAssessment]) -> FindingSummary:
    ordered = sorted(risks, key=lambda r: (_SEVERITY_RANK[r.severity], r.category, r.detail))
    counts = Counter(risk.severity for risk in ordered)
    return FindingSummary(
        total=len(ordered),
        counts=tuple((severity, counts[severity]) for severity in _SEVERITIES),
        shown=tuple(
            ShownFinding(
                severity=risk.severity,
                category=_clip(risk.category, DETAIL_CHARS),
                detail=_clip(risk.detail, DETAIL_CHARS),
            )
            for risk in ordered[:MAX_FINDINGS]
        ),
    )


def _facts(component: AnyComponent) -> tuple[tuple[str, str | bool], ...]:
    facts: list[tuple[str, str | bool]] = []
    for name in _FACTS:
        value = getattr(component, name, None)
        if isinstance(value, bool):
            facts.append((name, value))
        elif value is not None:
            facts.append((name, _clip(str(getattr(value, "value", value)), DETAIL_CHARS)))
    evidence = component.properties.get("capability_evidence")
    if isinstance(evidence, str):
        facts.append(("capability_evidence", _clip(evidence, DETAIL_CHARS)))
    return tuple(facts)


def _node(index: int, component: AnyComponent) -> Node:
    risks = _risks(component)
    return Node(
        index=index,
        ref=component.bom_ref,
        type=component.component_type,
        name=component.name,
        version=component.version,
        assurance=component.assurance_level,
        trust_tier=component.trust_tier,
        classification=classify(component),
        findings=_findings(risks),
        facts=_facts(component),
        unpinned=getattr(component, "version_pinned", None) is False
        or any(risk.category in _UNPINNED_CATEGORIES for risk in risks),
        source_path=component.source_path,
    )


def _edges(bom: AIBOM, components: Sequence[AnyComponent]) -> tuple[Edge, ...]:
    """Dependency edges, then the reference fields no dependency edge already records."""
    index = {component.bom_ref: position for position, component in enumerate(components)}
    recorded = {(edge.source_ref, edge.target_ref) for edge in bom.dependencies}
    found: set[tuple[int, int, int, str, str, bool]] = set()
    for edge in bom.dependencies:
        source, target = index.get(edge.source_ref), index.get(edge.target_ref)
        if source is not None and target is not None:
            found.add(
                (
                    source,
                    target,
                    0,
                    edge.relationship,
                    edge.assurance_level or "",
                    bool(edge.conditions),
                )
            )
    for component in components:
        for field_name, ref in _references(component):
            target = index.get(ref)
            if target is not None and (component.bom_ref, ref) not in recorded:
                found.add((index[component.bom_ref], target, 1, field_name, "", False))
        upstreams = component.properties.get("upstream_server_refs")
        if isinstance(upstreams, list):
            for srv_ref in upstreams:
                if (
                    isinstance(srv_ref, str)
                    and (target := index.get(srv_ref)) is not None
                    and (component.bom_ref, srv_ref) not in recorded
                ):
                    found.add(
                        (index[component.bom_ref], target, 1, "upstream_server_refs", "", False)
                    )
    return tuple(
        Edge(
            index=position,
            source=source,
            target=target,
            kind="reference" if kind else "dependency",
            label=label,
            assurance=assurance or None,
            conditional=conditional,
        )
        for position, (source, target, kind, label, assurance, conditional) in enumerate(
            sorted(found)
        )
    )


def _breadth_first(
    start: int, adjacency: Sequence[Sequence[int]]
) -> tuple[list[int], list[int], list[int]]:
    """Visit order, parents and depths from ``start``; a parent of -1 marks an unvisited node."""
    parent = [-1] * len(adjacency)
    depth = [0] * len(adjacency)
    parent[start] = start
    order = [start]
    position = 0
    while position < len(order):
        current = order[position]
        position += 1
        for target in adjacency[current]:
            if parent[target] < 0:
                parent[target] = current
                depth[target] = depth[current] + 1
                order.append(target)
    return order, parent, depth


def _exposure(
    nodes: Sequence[Node], edges: Sequence[Edge]
) -> tuple[int, int, tuple[ExposurePath, ...], int]:
    """The best-ranked shortest paths from agents and IDE agents to sinks.

    A first pass over each kept source ranks every (source, sink) pair it reaches by sink
    weight, then distance, without building its route, and keeps the best MAX_PATHS; a
    second pass rebuilds only those paths.
    Choosing which sources to keep is one search back from the sinks, linear in nodes and
    edges; the rest is linear in kept sources times nodes and edges, plus MAX_PATHS paths.
    """
    successors: list[set[int]] = [set() for _ in nodes]
    first_edge: dict[tuple[int, int], Edge] = {}
    for edge in edges:
        successors[edge.source].add(edge.target)
        first_edge.setdefault((edge.source, edge.target), edge)
    adjacency = [sorted(targets) for targets in successors]
    rank = {node.index: rank for rank, node in enumerate(sorted(nodes, key=attrgetter("ref")))}
    weight = [node.weight for node in nodes]
    sources = [node.index for node in nodes if node.type in _SOURCE_TYPES]
    # Search the sources whose best path ranks highest, and the kept paths are the best of
    # every source's. A path ranks by its sink's weight, then its length, then the source,
    # so a source's best path ends at the heaviest sink it reaches, at the shortest
    # distance. If a source is cut, 200 sources each have a path that ranks above any of
    # its own. A breadth-first search back from the sinks, heaviest first, finds the
    # weight and distance of every node and visits each node once: whatever reaches a
    # heavier sink was visited before, and no shortest path to a sink of this weight
    # passes through it. A source that reaches no sink has no path and is cut first.
    predecessors: list[list[int]] = [[] for _ in nodes]
    for origin, successors_of in enumerate(adjacency):
        for successor in successors_of:
            predecessors[successor].append(origin)
    sinks_by_weight: dict[int, list[int]] = {}
    for index, value in enumerate(weight):
        if value:
            sinks_by_weight.setdefault(value, []).append(index)
    heaviest = [0] * len(nodes)
    distance = [len(nodes)] * len(nodes)
    for level in sorted(sinks_by_weight, reverse=True):
        queue = deque(index for index in sinks_by_weight[level] if not heaviest[index])
        for index in queue:
            heaviest[index], distance[index] = level, 0
        while queue:
            current = queue.popleft()
            for previous in predecessors[current]:
                if not heaviest[previous]:
                    heaviest[previous], distance[previous] = level, distance[current] + 1
                    queue.append(previous)
    sources.sort(key=lambda source: (-heaviest[source], distance[source], rank[source]))
    kept = sources[:MAX_SOURCES]
    best: list[tuple[int, int, int, int, int, int]] = []
    total = 0
    for source in kept:
        order, _, depth = _breadth_first(source, adjacency)
        reached = [
            (-weight[node], depth[node], rank[source], rank[node], source, node)
            for node in order
            if weight[node]
        ]
        total += len(reached)
        best = heapq.nsmallest(MAX_PATHS, [*best, *heapq.nsmallest(MAX_PATHS, reached)])
    paths: list[ExposurePath] = []
    parents: dict[int, list[int]] = {}
    for *_, source, sink in best:
        if source not in parents:
            parents[source] = _breadth_first(source, adjacency)[1]
        route = [sink]
        while route[-1] != source:
            route.append(parents[source][route[-1]])
        route.reverse()
        hops = [first_edge[pair] for pair in zip(route, route[1:], strict=False)]
        target = nodes[sink]
        paths.append(
            ExposurePath(
                nodes=tuple(route),
                edges=tuple(edge.index for edge in hops),
                labels=tuple(edge.label for edge in hops),
                sink_classes=target.classification.classes,
                sink_severity=target.findings.highest,
            )
        )
    return len(sources), len(sources) - len(kept), tuple(paths), total - len(paths)


def _coverage(claim: CompletenessClaim | None) -> Coverage:
    assessment = assess_coverage(claim)
    gaps = assessment.reasons()
    return Coverage(
        status=coverage_aggregate(claim),
        collection=assessment.status.value,
        scan_failures=len(claim.scan_failures) if claim is not None else 0,
        surfaces_excluded=len(claim.surfaces_excluded) if claim is not None else 0,
        gaps=tuple(_clip_gap(gap) for gap in gaps[:MAX_GAPS]),
        gaps_omitted=max(0, len(gaps) - MAX_GAPS),
    )


def view_document(view: GraphView) -> dict[str, Any]:
    """The view as the documented ``nexus-symbiote/graph-view/v1`` JSON document."""
    return {
        "format": FORMAT,
        "inventory": {
            "spec_version": view.spec_version,
            "timestamp": view.timestamp,
            "components": view.inventory_components,
            "dependencies": view.inventory_dependencies,
        },
        "focus": view.focus,
        "coverage": {
            "status": view.coverage.status,
            "collection": view.coverage.collection,
            "scan_failures": view.coverage.scan_failures,
            "surfaces_excluded": view.coverage.surfaces_excluded,
            "gaps": list(view.coverage.gaps),
            "gaps_omitted": view.coverage.gaps_omitted,
        },
        "limitations": list(LIMITATIONS),
        "nodes": [_node_document(node) for node in view.nodes],
        "edges": [
            {
                "index": edge.index,
                "source": edge.source,
                "target": edge.target,
                "kind": edge.kind,
                "label": edge.label,
                "assurance": edge.assurance,
                "conditional": edge.conditional,
            }
            for edge in view.edges
        ],
        "exposure": {
            "sources": view.sources,
            "sources_omitted": view.sources_omitted,
            "sinks": view.sinks,
            "paths": [
                {
                    "source": path.nodes[0],
                    "sink": path.nodes[-1],
                    "length": len(path.edges),
                    "nodes": list(path.nodes),
                    "edges": list(path.edges),
                    "labels": list(path.labels),
                    "sink_classes": [risk.value for risk in path.sink_classes],
                    "sink_severity": path.sink_severity.value if path.sink_severity else None,
                }
                for path in view.paths
            ],
            "paths_omitted": view.paths_omitted,
        },
    }


def _node_document(node: Node) -> dict[str, Any]:
    findings = node.findings
    return {
        "index": node.index,
        "ref": node.ref,
        "type": node.type.value,
        "name": node.name,
        "version": node.version,
        "assurance": node.assurance.value,
        "trust_tier": node.trust_tier.value,
        "risk_classes": [risk.value for risk in node.classification.classes],
        "basis": list(node.classification.basis),
        "assessed": node.classification.assessed,
        "findings": {
            "total": findings.total,
            "highest": findings.highest.value if findings.highest else None,
            "counts": {severity.value: count for severity, count in findings.counts},
            "shown": [
                {
                    "severity": finding.severity.value,
                    "category": finding.category,
                    "detail": finding.detail,
                }
                for finding in findings.shown
            ],
            "omitted": findings.omitted,
        },
        "facts": dict(node.facts),
        "unpinned": node.unpinned,
        "source_path": node.source_path,
    }


# Every inventory string reaches the page only through _text.

STYLE = """
:root {
  color-scheme: light dark;
  --bg: #ffffff; --fg: #1f2328; --muted: #59636e; --line: #d1d9e0; --soft: #f6f8fa;
  --node: #ffffff; --node-line: #818b98; --edge: #8c959f; --on: #0969da; --focus: #0969da;
  --chip: #eef1f4; --chip-on: #0969da; --warn-bg: #fff8c5; --warn-line: #bf8700;
  --bad-bg: #ffebe9; --bad-line: #cf222e;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0d1117; --fg: #e6edf3; --muted: #9198a1; --line: #3d444d; --soft: #151b23;
    --node: #151b23; --node-line: #7d8590; --edge: #656c76; --on: #4493f8; --focus: #4493f8;
    --chip: #212830; --chip-on: #1f6feb; --warn-bg: #2e2a1a; --warn-line: #bb8009;
    --bad-bg: #2d1416; --bad-line: #f85149;
  }
}
* { box-sizing: border-box; }
html, body { background: var(--bg); color: var(--fg); }
body {
  margin: 0;
  font: 14px/1.5 system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial,
    sans-serif;
}
header, main, footer { padding: 0 24px; }
h1 { font-size: 1.5rem; margin: 2px 0 12px; }
h2 { font-size: 1.1rem; margin: 18px 0 8px; }
h3 { font-size: 1rem; margin: 0 0 4px; overflow-wrap: anywhere; }
h4 { font-size: .9rem; margin: 12px 0 4px; }
code {
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
  font-size: .85em; overflow-wrap: anywhere;
}
.kicker {
  margin: 20px 0 0; color: var(--muted); font-size: .8rem; letter-spacing: .06em;
  text-transform: uppercase;
}
.banner {
  border: 1px solid var(--warn-line); background: var(--warn-bg); border-radius: 6px;
  padding: 10px 14px; margin: 0 0 14px;
}
.banner.cov-incomplete { border-color: var(--bad-line); background: var(--bad-bg); }
.facts { display: flex; flex-wrap: wrap; gap: 8px 28px; margin: 0 0 12px; }
.facts dt { color: var(--muted); font-size: .8rem; }
.facts dd { margin: 0; font-weight: 600; overflow-wrap: anywhere; }
.limits, .gaps { margin: 0 0 12px; padding-left: 20px; color: var(--muted); }
.gaps li { overflow-wrap: anywhere; }
.controls {
  display: none; flex-wrap: wrap; align-items: center; gap: 8px; padding: 10px 0;
  border-top: 1px solid var(--line); border-bottom: 1px solid var(--line);
}
.js .controls { display: flex; }
.controls .keys, .status { margin: 0; color: var(--muted); font-size: .85rem; }
.chip, .all {
  font: inherit; font-size: .85rem; color: var(--fg); background: var(--chip);
  border: 1px solid var(--line); border-radius: 999px; padding: 2px 12px; cursor: pointer;
}
.chip[aria-pressed="true"], .all[aria-pressed="true"] {
  background: var(--chip-on); border-color: var(--chip-on); color: #ffffff;
}
input[type="search"] {
  font: inherit; color: var(--fg); background: var(--bg); border: 1px solid var(--line);
  border-radius: 6px; padding: 2px 8px;
}
:focus-visible { outline: 3px solid var(--focus); outline-offset: 2px; }
.layout { display: grid; grid-template-columns: minmax(0, 5fr) minmax(19rem, 2fr); gap: 24px; }
.side { align-self: start; position: sticky; top: 8px; max-height: calc(100vh - 16px); overflow: auto; }
@media (max-width: 1000px) {
  .layout { grid-template-columns: minmax(0, 1fr); }
  .side { position: static; max-height: none; }
}
.scroll {
  overflow: auto; max-height: 78vh; border: 1px solid var(--line); border-radius: 6px;
  background: var(--soft);
}
svg.map { display: block; }
svg.map text { fill: var(--fg); font-size: 12px; }
svg.map .colh { fill: var(--muted); font-weight: 600; }
.node { cursor: pointer; }
.node:focus { outline: none; }
.node .box { fill: var(--node); stroke: var(--node-line); stroke-width: 1.2; }
.node.unc .box { stroke-dasharray: 6 4; }
.node:focus-visible .box { stroke: var(--focus); stroke-width: 3; }
svg.map .nm { font-size: 12px; font-weight: 600; }
svg.map .gt, svg.map .st { fill: #ffffff; font-size: 8.5px; font-weight: 700; text-anchor: middle; }
svg.map .bt { font-size: 8.5px; font-weight: 700; text-anchor: middle; }
.b { fill: var(--chip); stroke: var(--node-line); stroke-width: .6; }
.edge .ln { fill: none; stroke: var(--edge); stroke-width: 1.3; }
.edge .hd { fill: var(--edge); }
.edge.cond .ln { stroke-dasharray: 6 4; }
.edge.ref .ln { stroke-dasharray: 2 3; }
.edge.on .ln { stroke: var(--on); stroke-width: 2.6; }
.edge.on .hd { fill: var(--on); }
.node.sel .box { stroke: var(--on); stroke-width: 3.2; }
.node.on .box, .node.up .box, .node.down .box { stroke: var(--on); stroke-width: 2; }
.node.dim, .edge.dim, .node.fo, .edge.fo { opacity: .2; }
.g1 { fill: #6e40c9; background: #6e40c9; }
.g2 { fill: #1a7f37; background: #1a7f37; }
.g3 { fill: #0a6e8a; background: #0a6e8a; }
.g4 { fill: #a8510b; background: #a8510b; }
.g5 { fill: #9a3a6a; background: #9a3a6a; }
.g6 { fill: #4b5563; background: #4b5563; }
.s-critical { fill: #7d1a1a; background: #7d1a1a; }
.s-high { fill: #b42318; background: #b42318; }
.s-medium { fill: #9a6700; background: #9a6700; }
.s-low { fill: #0b5cad; background: #0b5cad; }
.s-info { fill: #57606a; background: #57606a; }
.glyph, .sev {
  display: inline-block; color: #ffffff; border-radius: 4px; padding: 0 6px;
  font-size: .72rem; font-weight: 700; text-transform: uppercase; vertical-align: 1px;
  print-color-adjust: exact; -webkit-print-color-adjust: exact;
}
.badge {
  display: inline-block; border: 1px solid var(--line); background: var(--chip);
  border-radius: 4px; padding: 0 5px; font-size: .72rem; font-weight: 700;
}
.legend ul { list-style: none; padding: 0; margin: 4px 0 10px; display: flex; flex-wrap: wrap; gap: 6px 18px; }
.eg { display: inline-block; width: 30px; border-top: 2px solid var(--edge); vertical-align: middle; }
.eg.cond { border-top-style: dashed; }
.eg.ref { border-top-style: dotted; }
.ub {
  display: inline-block; width: 24px; height: 12px; border: 2px dashed var(--node-line);
  border-radius: 3px; vertical-align: middle;
}
.note, .more, .hint { color: var(--muted); font-size: .85rem; }
.pathlist { padding-left: 24px; margin: 0; }
.pathlist li { margin: 0 0 6px; }
.path {
  font: inherit; font-size: .85rem; color: var(--fg); background: var(--bg); width: 100%;
  text-align: left; border: 1px solid var(--line); border-radius: 6px; padding: 6px 10px;
  cursor: pointer; overflow-wrap: anywhere;
}
.path.on { border-color: var(--on); box-shadow: inset 4px 0 0 var(--on); }
.hint, .all { display: none; }
.js .hint { display: block; }
.js .all { display: inline-block; margin: 0 0 10px; }
.js .details.has-open .hint { display: none; }
.panel {
  border: 1px solid var(--line); border-radius: 6px; padding: 12px 14px; margin: 0 0 12px;
  background: var(--bg);
}
.js .panel { display: none; }
.js .panel.open, .js .details.all .panel { display: block; }
.ptype { margin: 0 0 6px; color: var(--muted); }
.kv { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 2px 12px; margin: 6px 0; }
.kv dt { color: var(--muted); }
.kv dd { margin: 0; overflow-wrap: anywhere; }
.findings { padding-left: 18px; margin: 4px 0; }
.findings li { margin: 0 0 4px; overflow-wrap: anywhere; }
footer { color: var(--muted); font-size: .85rem; padding-top: 12px; padding-bottom: 32px; }
@media print {
  .js .controls, .js .hint, .js .all { display: none; }
  .js .panel { display: block; }
  svg.map { width: 100%; height: auto; }
  .layout { display: block; }
  .side { position: static; max-height: none; overflow: visible; }
  .scroll { overflow: visible; max-height: none; border: none; }
  .panel { break-inside: avoid; }
  .node.dim, .edge.dim, .node.fo, .edge.fo { opacity: 1; }
}
"""

SCRIPT = """
(function () {
  "use strict";
  var body = document.body;
  body.classList.add("js");
  function all(selector) {
    return Array.prototype.slice.call(document.querySelectorAll(selector));
  }
  var nodeEls = all("svg.map g.node");
  var edgeEls = all("svg.map g.edge");
  var pathEls = all("button.path");
  var chipEls = all("button.chip");
  var panelEls = all("article.panel");
  var details = document.querySelector("section.details");
  var showAll = document.querySelector("button.all");
  var search = document.getElementById("q");
  var status = document.getElementById("status");
  var nodes = new Map();
  var panels = new Map();
  var out = new Map();
  var inc = new Map();
  var active = new Set();
  nodeEls.forEach(function (el) {
    nodes.set(el.dataset.i, el);
    out.set(el.dataset.i, []);
    inc.set(el.dataset.i, []);
  });
  panelEls.forEach(function (el) {
    panels.set(el.dataset.i, el);
  });
  edgeEls.forEach(function (el) {
    var s = el.dataset.s;
    var t = el.dataset.t;
    if (out.has(s) && inc.has(t)) {
      out.get(s).push(t);
      inc.get(t).push(s);
    }
  });
  function reach(start, graph) {
    var seen = new Set([start]);
    var stack = [start];
    while (stack.length) {
      (graph.get(stack.pop()) || []).forEach(function (next) {
        if (!seen.has(next)) {
          seen.add(next);
          stack.push(next);
        }
      });
    }
    return seen;
  }
  function say(text) {
    if (status) {
      status.textContent = text;
    }
  }
  function clearMarks() {
    nodeEls.forEach(function (el) {
      el.classList.remove("sel", "up", "down", "on", "dim");
    });
    edgeEls.forEach(function (el) {
      el.classList.remove("on", "dim");
    });
    pathEls.forEach(function (el) {
      el.classList.remove("on");
      el.setAttribute("aria-pressed", "false");
    });
    panelEls.forEach(function (el) {
      el.classList.remove("open");
    });
    if (details) {
      details.classList.remove("has-open");
    }
  }
  function openPanel(i) {
    var panel = panels.get(i);
    if (panel) {
      panel.classList.add("open");
      if (details) {
        details.classList.add("has-open");
      }
      panel.scrollIntoView({ block: "nearest" });
    }
  }
  function selectNode(i) {
    clearMarks();
    var down = reach(i, out);
    var up = reach(i, inc);
    nodeEls.forEach(function (el) {
      var k = el.dataset.i;
      el.classList.add(k === i ? "sel" : down.has(k) ? "down" : up.has(k) ? "up" : "dim");
    });
    edgeEls.forEach(function (el) {
      var s = el.dataset.s;
      var t = el.dataset.t;
      var on = (down.has(s) && down.has(t)) || (up.has(s) && up.has(t));
      el.classList.add(on ? "on" : "dim");
    });
    openPanel(i);
    say("Selected: " + (down.size - 1) + " reachable, " + (up.size - 1) + " dependent.");
  }
  function selectPath(button) {
    clearMarks();
    var onNodes = new Set((button.dataset.nodes || "").split(" "));
    var onEdges = new Set((button.dataset.edges || "").split(" "));
    nodeEls.forEach(function (el) {
      el.classList.add(onNodes.has(el.dataset.i) ? "on" : "dim");
    });
    edgeEls.forEach(function (el) {
      el.classList.add(onEdges.has(el.dataset.i) ? "on" : "dim");
    });
    button.classList.add("on");
    button.setAttribute("aria-pressed", "true");
    openPanel(button.dataset.sink);
    say("Exposure path selected.");
  }
  function matches(el, filter) {
    if (filter === "severe") {
      return el.dataset.sev === "critical" || el.dataset.sev === "high";
    }
    if (filter === "unpinned") {
      return el.dataset.unpinned === "1";
    }
    if (filter === "unclassified") {
      return el.dataset.unclassified === "1";
    }
    return (" " + (el.dataset.classes || "") + " ").indexOf(" " + filter + " ") !== -1;
  }
  function applyFilters() {
    var query = search ? search.value.trim().toLowerCase() : "";
    var shown = 0;
    nodeEls.forEach(function (el) {
      var keep = true;
      active.forEach(function (filter) {
        keep = keep && matches(el, filter);
      });
      if (keep && query) {
        keep = (el.dataset.name || "").toLowerCase().indexOf(query) !== -1;
      }
      el.classList.toggle("fo", !keep);
      if (keep) {
        shown += 1;
      }
    });
    edgeEls.forEach(function (el) {
      var s = nodes.get(el.dataset.s);
      var t = nodes.get(el.dataset.t);
      el.classList.toggle(
        "fo", !s || !t || s.classList.contains("fo") || t.classList.contains("fo")
      );
    });
    say(active.size || query ? shown + " of " + nodeEls.length + " components match." : "");
  }
  nodeEls.forEach(function (el) {
    el.addEventListener("click", function () {
      selectNode(el.dataset.i);
    });
    el.addEventListener("keydown", function (event) {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        selectNode(el.dataset.i);
      }
    });
  });
  pathEls.forEach(function (button) {
    button.addEventListener("click", function () {
      selectPath(button);
    });
  });
  chipEls.forEach(function (chip) {
    chip.addEventListener("click", function () {
      var filter = chip.dataset.f;
      if (active.has(filter)) {
        active.delete(filter);
      } else {
        active.add(filter);
      }
      chip.setAttribute("aria-pressed", active.has(filter) ? "true" : "false");
      applyFilters();
    });
  });
  if (search) {
    search.addEventListener("input", applyFilters);
  }
  if (showAll && details) {
    showAll.addEventListener("click", function () {
      var on = !details.classList.contains("all");
      details.classList.toggle("all", on);
      showAll.setAttribute("aria-pressed", on ? "true" : "false");
    });
  }
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
      clearMarks();
      active.clear();
      chipEls.forEach(function (chip) {
        chip.setAttribute("aria-pressed", "false");
      });
      if (search) {
        search.value = "";
      }
      applyFilters();
      say("Selection and filters cleared.");
    }
  });
}());
"""


def _source_hash(text: str) -> str:
    digest = hash_bytes(text.encode("utf-8")).split(":", 1)[1]
    return "'sha256-" + base64.b64encode(bytes.fromhex(digest)).decode("ascii") + "'"


CONTENT_SECURITY_POLICY = (
    f"default-src 'none'; style-src {_source_hash(STYLE)}; script-src {_source_hash(SCRIPT)}; "
    "img-src data:; base-uri 'none'; form-action 'none'"
)

_GLYPHS = {
    ComponentType.AGENT: "AG",
    ComponentType.IDE_AGENT: "IDE",
    ComponentType.PROMPT_TEMPLATE: "PR",
    ComponentType.SKILL_PACKAGE: "SK",
    ComponentType.MCP_CLIENT: "MC",
    ComponentType.A2A_CLIENT: "A2C",
    ComponentType.MCP_SERVER: "MCP",
    ComponentType.A2A_SERVER: "A2A",
    ComponentType.TOOL: "T",
    ComponentType.MODEL: "M",
    ComponentType.RAG_SOURCE: "RAG",
    ComponentType.DATA_SOURCE: "DS",
    ComponentType.MEMORY_STORE: "MEM",
    ComponentType.GUARDRAIL_POLICY: "GR",
    ComponentType.CREDENTIAL: "KEY",
    ComponentType.REGISTRY_ENTRY: "PKG",
    ComponentType.VERIFIED_EXTENSION: "EXT",
}
_BADGES = {
    RiskClass.CODE_EXEC: "EXEC",
    RiskClass.WRITE_CAPABLE: "WRITE",
    RiskClass.EXFIL_CAPABLE: "EXFIL",
    RiskClass.NETWORK_EGRESS: "NET",
    RiskClass.SECRET_ACCESS: "SECRET",
}
_SHORT_SEVERITY = {
    RiskSeverity.CRITICAL: "CRIT",
    RiskSeverity.HIGH: "HIGH",
    RiskSeverity.MEDIUM: "MED",
    RiskSeverity.LOW: "LOW",
    RiskSeverity.INFO: "INFO",
}
_COVERAGE_NOTE = {
    "unknown": (
        "Static collection never observes runtime, network or live tools, so the best "
        "coverage an inventory can state is unknown."
    ),
    "incomplete": (
        "A collector failed, was skipped or left a gap, a surface was excluded, or the "
        "inventory holds imported claims; anything outside the collected surfaces is missing."
    ),
}
_FILTERS = (
    *((risk.value, risk.value) for risk in RiskClass),
    ("severe", "high or critical findings"),
    ("unpinned", "unpinned"),
    ("unclassified", "unclassified"),
)
_BOX_WIDTH, _BOX_HEIGHT, _COLUMN_GAP, _ROW_HEIGHT = 260, 52, 100, 66
_MARGIN, _TOP = 24, 48
_ROUTE_SHOWN = 8


def _text(value: object, limit: int = DETAIL_CHARS) -> str:
    """Inventory text as inert HTML element text or a quoted attribute value, never markup.

    The text is clipped first, so the work is bounded by ``limit`` however long the text
    is; clipping only drops a tail and adds an ellipsis, which cannot form a character or
    CI log command that neutralizing removes. Neutralizing can lengthen the text, so it is
    clipped again, and escaped last, so the escape never splits an entity.
    """
    return html.escape(_clip(neutralize(_clip(str(value), limit)), limit), quote=True)


def render_html(view: GraphView) -> str:
    """One self-contained, deterministic HTML page for ``view``."""
    parts: list[str] = [
        '<!DOCTYPE html>\n<html lang="en">\n<head>\n',
        f'<meta http-equiv="Content-Security-Policy" content="{CONTENT_SECURITY_POLICY}">\n',
        '<meta charset="utf-8">\n',
        '<meta name="viewport" content="width=device-width, initial-scale=1">\n',
        '<meta name="color-scheme" content="light dark">\n',
        "<title>Agent association graph</title>\n",
        f"<style>{STYLE}</style>\n</head>\n<body>\n",
    ]
    parts.extend(_header(view))
    parts.append("<main>\n")
    parts.extend(_controls())
    parts.append('<div class="layout">\n<section class="graph" aria-labelledby="h-graph">\n')
    parts.append('<h2 id="h-graph">Graph</h2>\n<div class="scroll">\n')
    parts.extend(_svg(view))
    parts.append("</div>\n")
    parts.extend(_legend())
    parts.append('</section>\n<aside class="side">\n')
    parts.extend(_path_list(view))
    parts.extend(_panels(view))
    parts.append("</aside>\n</div>\n</main>\n")
    parts.append(
        f"<footer><p>Written by nexus-symbiote {_text(__version__)} from a native inventory. "
        "The view restates recorded evidence; it does not establish runtime behavior, "
        "reachability or authority.</p></footer>\n"
    )
    parts.append(f"<script>{SCRIPT}</script>\n</body>\n</html>\n")
    return "".join(parts)


def _header(view: GraphView) -> list[str]:
    coverage = view.coverage
    shown = len(view.nodes)
    facts = [
        ("Components", f"{shown} of {view.inventory_components}"),
        ("Edges", str(len(view.edges))),
        ("Exposure paths", f"{len(view.paths)} of {len(view.paths) + view.paths_omitted}"),
        ("Agent sources", f"{view.sources - view.sources_omitted} of {view.sources}"),
        ("Risky components", str(view.sinks)),
        ("Collection", coverage.collection),
        ("Scan failures", str(coverage.scan_failures)),
        ("Excluded surfaces", str(coverage.surfaces_excluded)),
        ("Native format", view.spec_version),
        ("Inventory time", view.timestamp or "not recorded"),
    ]
    parts = [
        '<header>\n<p class="kicker">Nexus SymBiote graph view</p>\n',
        "<h1>Agent association graph</h1>\n",
        (
            f'<div class="banner cov-{_text(coverage.status)}" role="note"><strong>Coverage '
            f"{_text(coverage.status)}.</strong> {_COVERAGE_NOTE[coverage.status]}</div>\n"
        ),
        '<dl class="facts">\n',
        *(f"<div><dt>{name}</dt><dd>{_text(value)}</dd></div>\n" for name, value in facts),
        "</dl>\n",
    ]
    if view.focus is not None:
        parts.append(
            "<p>Focus: the potential blast radius of <code>"
            f"{_text(view.focus)}</code>: it, what depends on it, and what it and the "
            "components of type agent among those reach. What IDE agents and clients among "
            "them reach is not shown.</p>\n"
        )
    if coverage.gaps:
        parts.append('<h2>Coverage gaps</h2>\n<ul class="gaps">\n')
        parts.extend(f"<li>{_text(gap)}</li>\n" for gap in coverage.gaps)
        parts.append("</ul>\n")
        if coverage.gaps_omitted:
            parts.append(f'<p class="more">{coverage.gaps_omitted} more gaps not shown.</p>\n')
    parts.append('<ul class="limits">\n')
    parts.extend(f"<li>{sentence}</li>\n" for sentence in LIMITATIONS)
    parts.append("</ul>\n</header>\n")
    return parts


def _controls() -> list[str]:
    chips = "".join(
        f'<button type="button" class="chip" data-f="{key}" aria-pressed="false">{label}</button>\n'
        for key, label in _FILTERS
    )
    return [
        '<section class="controls" aria-label="Filters">\n',
        '<span class="keys">Show only components that are:</span>\n',
        chips,
        '<label for="q">Name contains</label>\n',
        '<input id="q" type="search" autocomplete="off" spellcheck="false">\n',
        (
            '<p class="keys">Select a component (click, or Enter) to trace what it reaches and '
            "what depends on it; Escape clears.</p>\n"
        ),
        '<p id="status" class="status" role="status" aria-live="polite"></p>\n',
        "</section>\n",
    ]


def _columns(view: GraphView) -> tuple[list[int], dict[int, tuple[int, int]]]:
    """Visible columns, and each node's column position and row."""
    used = sorted({_PLACE[node.type][0] for node in view.nodes})
    position = {column: place for place, column in enumerate(used)}
    rows: dict[int, int] = {}
    places: dict[int, tuple[int, int]] = {}
    for node in view.nodes:
        column = position[_PLACE[node.type][0]]
        places[node.index] = (column, rows.get(column, 0))
        rows[column] = rows.get(column, 0) + 1
    return used, places


def _svg(view: GraphView) -> list[str]:
    used, places = _columns(view)
    rows = max((row for _, row in places.values()), default=-1) + 1
    width = _MARGIN * 2 + len(used) * _BOX_WIDTH + max(0, len(used) - 1) * _COLUMN_GAP
    height = _TOP + rows * _ROW_HEIGHT + _MARGIN
    corner = {
        index: (_MARGIN + column * (_BOX_WIDTH + _COLUMN_GAP), _TOP + row * _ROW_HEIGHT)
        for index, (column, row) in places.items()
    }
    parts = [
        (
            f'<svg class="map" role="group" aria-label="Component association graph" '
            f'width="{width}" height="{height}" viewBox="0 0 {width} {height}">\n'
        )
    ]
    parts.extend(
        f'<text class="colh" x="{_MARGIN + place * (_BOX_WIDTH + _COLUMN_GAP)}" y="28">'
        f"{_COLUMNS[column][0]}</text>\n"
        for place, column in enumerate(used)
    )
    for edge in view.edges:
        parts.append(_edge_svg(edge, corner, places))
    for node in view.nodes:
        parts.append(_node_svg(node, *corner[node.index]))
    parts.append("</svg>\n")
    return parts


def _edge_svg(
    edge: Edge, corner: dict[int, tuple[int, int]], places: dict[int, tuple[int, int]]
) -> str:
    (sx, sy), (tx, ty) = corner[edge.source], corner[edge.target]
    middle = _BOX_HEIGHT // 2
    if edge.source == edge.target:
        x, y = sx + _BOX_WIDTH, sy
        line = f"M{x} {y + 18} C{x + 44} {y + 2} {x + 44} {y + 50} {x} {y + 34}"
        head = f"M{x} {y + 34} l9 -2 l-5 7 z"
    elif places[edge.source][0] < places[edge.target][0]:
        x1, y1, x2, y2 = sx + _BOX_WIDTH, sy + middle, tx, ty + middle
        bend = (x2 - x1) // 2
        line = f"M{x1} {y1} C{x1 + bend} {y1} {x2 - bend} {y2} {x2} {y2}"
        head = f"M{x2} {y2} l-9 -4 v8 z"
    elif places[edge.source][0] > places[edge.target][0]:
        x1, y1, x2, y2 = sx, sy + middle, tx + _BOX_WIDTH, ty + middle
        bend = (x1 - x2) // 2
        line = f"M{x1} {y1} C{x1 - bend} {y1} {x2 + bend} {y2} {x2} {y2}"
        head = f"M{x2} {y2} l9 -4 v8 z"
    else:
        x1, y1, x2, y2 = sx + _BOX_WIDTH, sy + middle, tx + _BOX_WIDTH, ty + middle
        bend = 40 + min(60, abs(y2 - y1) // 10)
        line = f"M{x1} {y1} C{x1 + bend} {y1} {x2 + bend} {y2} {x2} {y2}"
        head = f"M{x2} {y2} l9 -4 v8 z"
    kind = "ref" if edge.kind == "reference" else "dep"
    style = f"edge {kind}" + (" cond" if edge.conditional else "")
    title = " · ".join(
        [
            edge.label,
            "reference field"
            if edge.kind == "reference"
            else edge.assurance or "assurance unstated",
            *(["conditional association"] if edge.conditional else []),
        ]
    )
    return (
        f'<g class="{style}" data-i="{edge.index}" data-s="{edge.source}" '
        f'data-t="{edge.target}"><title>{_text(title)}</title>'
        f'<path class="ln" d="{line}"/><path class="hd" d="{head}"/></g>\n'
    )


def _badge_width(text: str) -> int:
    return 11 * len(text) // 2 + 6


def _node_svg(node: Node, x: int, y: int) -> str:
    classification = node.classification
    severity = node.findings.highest
    group = _PLACE[node.type][0] + 1
    style = f"node k-{node.type.value} g{group}" + ("" if classification.assessed else " unc")
    label = f"{node.type.value}: {node.name}"
    parts = [
        (
            f'<g class="{style}" data-i="{node.index}" '
            f'data-classes="{" ".join(risk.value for risk in classification.classes)}" '
            f'data-sev="{severity.value if severity else "none"}" '
            f'data-unpinned="{int(node.unpinned)}" '
            f'data-unclassified="{int(not classification.assessed)}" '
            f'data-name="{_text(node.name, NAME_FILTER_CHARS)}" tabindex="0" role="button" '
            f'aria-label="{_text(label, NAME_FILTER_CHARS)}" transform="translate({x},{y})">'
        ),
        f"<title>{_text(label)}</title>",
        f'<rect class="box" width="{_BOX_WIDTH}" height="{_BOX_HEIGHT}" rx="8"/>',
        f'<circle class="g{group}" cx="22" cy="26" r="15"/>',
        f'<text class="gt" x="22" y="29">{_GLYPHS[node.type]}</text>',
        f'<text class="nm" x="44" y="21">{_text(node.name, LABEL_CHARS)}</text>',
    ]
    left = 44
    for risk in classification.classes:
        badge = _BADGES[risk]
        width = _badge_width(badge)
        parts.append(
            f'<rect class="b" x="{left}" y="30" width="{width}" height="14" rx="3"/>'
            f'<text class="bt" x="{left + width // 2}" y="40">{badge}</text>'
        )
        left += width + 4
    if severity is not None:
        short = _SHORT_SEVERITY[severity]
        width = _badge_width(short)
        start = _BOX_WIDTH - 8 - width
        parts.append(
            f'<rect class="s-{severity.value}" x="{start}" y="30" width="{width}" height="14" '
            f'rx="3"/><text class="st" x="{start + width // 2}" y="40">{short}</text>'
        )
    parts.append("</g>\n")
    return "".join(parts)


def _legend() -> list[str]:
    groups = "".join(
        f'<li><span class="glyph g{column + 1}">{"/".join(_GLYPHS[t] for t in types)}</span> '
        f"{name}: {', '.join(t.value for t in types)}</li>\n"
        for column, (name, types) in enumerate(_COLUMNS)
    )
    classes = "".join(
        f'<li><span class="badge">{_BADGES[risk]}</span> {risk.value}</li>\n' for risk in RiskClass
    )
    severities = "".join(
        f'<li><span class="sev s-{severity.value}">{_SHORT_SEVERITY[severity]}</span> '
        f"highest finding: {severity.value}</li>\n"
        for severity in RiskSeverity
    )
    return [
        '<section class="legend" aria-labelledby="h-legend">\n<h3 id="h-legend">Legend</h3>\n',
        f"<ul>\n{groups}</ul>\n<ul>\n{classes}</ul>\n<ul>\n{severities}</ul>\n",
        "<ul>\n",
        (
            '<li><span class="ub"></span> dashed outline: unclassified (no evidence the '
            "risk-class rules read; unknown, not safe)</li>\n"
        ),
        '<li><span class="eg"></span> recorded dependency edge</li>\n',
        (
            '<li><span class="eg cond"></span> conditional association (a static scan\'s '
            "repository association)</li>\n"
        ),
        '<li><span class="eg ref"></span> typed reference field no dependency edge records</li>\n',
        "</ul>\n</section>\n",
    ]


def _route(view: GraphView, path: ExposurePath) -> str:
    """The names along a path; a long path shows its first and last three, and only the
    names shown are escaped."""

    def name(index: int) -> str:
        return _text(view.nodes[index].name, LABEL_CHARS)

    if len(path.nodes) <= _ROUTE_SHOWN:
        return " → ".join(map(name, path.nodes))
    hidden = f"… {len(path.nodes) - 6} more …"
    return " → ".join([*map(name, path.nodes[:3]), hidden, *map(name, path.nodes[-3:])])


def _path_list(view: GraphView) -> list[str]:
    parts = [
        '<section class="paths" aria-labelledby="h-paths">\n<h2 id="h-paths">Exposure paths</h2>\n',
        (
            '<p class="note">The shortest recorded path from each agent or IDE agent to each '
            "component with a code-exec, exfil-capable, write-capable or secret-access class or a "
            "high or critical finding, ranked by that component's weight (critical finding, high "
            "finding, then the classes in that order), then by length.</p>\n"
        ),
    ]
    if view.sources_omitted:
        parts.append(
            f'<p class="more">{view.sources_omitted} more agent sources were not searched.</p>\n'
        )
    if not view.paths:
        parts.append(
            "<p>No exposure path was found in the recorded edges. That is not evidence of "
            "safety: the edges and classes restate only what the inventory records.</p>\n"
            "</section>\n"
        )
        return parts
    parts.append('<ol class="pathlist">\n')
    for number, path in enumerate(view.paths):
        badges = "".join(
            f'<span class="badge">{_BADGES[risk]}</span> ' for risk in path.sink_classes
        )
        severity = (
            f'<span class="sev s-{path.sink_severity.value}">{path.sink_severity.value}</span> '
            if path.sink_severity
            else ""
        )
        hops = len(path.edges)
        length = "the source itself" if not hops else f"{hops} edge{'' if hops == 1 else 's'}"
        parts.append(
            f'<li><button type="button" class="path" data-p="{number}" '
            f'data-nodes="{" ".join(map(str, path.nodes))}" '
            f'data-edges="{" ".join(map(str, path.edges))}" data-sink="{path.nodes[-1]}" '
            f'aria-pressed="false">{severity}{badges}{_route(view, path)} '
            f"({length})</button></li>\n"
        )
    parts.append("</ol>\n")
    if view.paths_omitted:
        parts.append(f'<p class="more">{view.paths_omitted} more paths not shown.</p>\n')
    parts.append("</section>\n")
    return parts


def _panels(view: GraphView) -> list[str]:
    parts = [
        '<section class="details" aria-labelledby="h-details">\n',
        '<h2 id="h-details">Components</h2>\n',
        '<p class="hint">Select a component or an exposure path to show its details.</p>\n',
        '<button type="button" class="all" aria-pressed="false">Show all components</button>\n',
    ]
    parts.extend(_panel(node) for node in view.nodes)
    parts.append("</section>\n")
    return parts


def _classes_html(classification: RiskClassification) -> str:
    if not classification.assessed:
        return (
            "Unclassified: the record holds no capability evidence that the risk-class rules "
            "read. Unknown, not safe."
        )
    if not classification.classes:
        return "None derived from the recorded evidence; this is not a statement of safety."
    badges = ", ".join(
        f'<span class="badge">{_BADGES[risk]}</span> {risk.value}'
        for risk in classification.classes
    )
    basis = ", ".join(f"<code>{_text(item)}</code>" for item in classification.basis)
    return f"{badges}. Basis: {basis}."


def _findings_html(findings: FindingSummary) -> list[str]:
    if not findings.total:
        return ["<h4>Findings</h4>\n<p>No recorded findings.</p>\n"]
    counts = ", ".join(f"{severity.value} {count}" for severity, count in findings.counts if count)
    parts = [
        (
            f"<h4>Findings</h4>\n<p>{findings.total} finding{'' if findings.total == 1 else 's'}: "
            f"{counts}.</p>\n"
        ),
        '<ul class="findings">\n',
    ]
    parts.extend(
        f'<li><span class="sev s-{finding.severity.value}">{finding.severity.value}</span> '
        f"<code>{_text(finding.category)}</code> {_text(finding.detail)}</li>\n"
        for finding in findings.shown
    )
    parts.append("</ul>\n")
    if findings.omitted:
        parts.append(f'<p class="more">{findings.omitted} more findings not shown.</p>\n')
    return parts


def _panel(node: Node) -> str:
    group = _PLACE[node.type][0] + 1
    rows: list[tuple[str, str]] = [("Reference", f"<code>{_text(node.ref)}</code>")]
    if node.version is not None:
        rows.append(("Version", _text(node.version)))
    if node.source_path is not None:
        rows.append(("Source", f"<code>{_text(node.source_path)}</code>"))
    rows.append(("Risk classes", _classes_html(node.classification)))
    rows.extend(
        (name, ("true" if value else "false") if isinstance(value, bool) else _text(value))
        for name, value in node.facts
    )
    parts = [
        (
            f'<article class="panel" id="c{node.index}" data-i="{node.index}" '
            f'aria-labelledby="c{node.index}h">\n'
        ),
        (
            f'<h3 id="c{node.index}h"><span class="glyph g{group}" aria-hidden="true">'
            f"{_GLYPHS[node.type]}</span> {_text(node.name)}</h3>\n"
        ),
        (
            f'<p class="ptype">{_text(node.type.value)} · {_text(node.assurance.value)} · '
            f"{_text(node.trust_tier.value)}</p>\n"
        ),
        '<dl class="kv">\n',
        *(f"<dt>{_text(name)}</dt><dd>{value}</dd>\n" for name, value in rows),
        "</dl>\n",
        *_findings_html(node.findings),
        "</article>\n",
    ]
    return "".join(parts)
