"""The graph view model is exact and bounded, and its HTML is inert for any inventory text."""

from __future__ import annotations

import base64
import hashlib
import random
import re
from html import unescape
from html.parser import HTMLParser
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote import graph_view
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import (
    CapabilityClass,
    ComponentType,
    RiskSeverity,
    SerializationSafety,
)
from nexus_symbiote.core.models import (
    AgentComponent,
    CapabilityDeclaration,
    CompletenessClaim,
    IDEAgentComponent,
    MCPClientComponent,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.graph_view import (
    _COLUMNS,
    CONTENT_SECURITY_POLICY,
    DETAIL_CHARS,
    FORMAT,
    LABEL_CHARS,
    LIMITATIONS,
    MAX_FINDINGS,
    MAX_GAPS,
    MAX_PATHS,
    MAX_SOURCES,
    SCRIPT,
    STYLE,
    GraphViewError,
    TooManyComponentsError,
    build_view,
    render_html,
    view_document,
)
from nexus_symbiote.utils.terminal import UNSAFE_TEXT
from tests.support import scaling_ratio

ROOT = Path(__file__).resolve().parents[1]
LIMIT = 2_000


def view_of(bom: AIBOM, **options: Any):
    return build_view(bom, max_nodes=options.pop("max_nodes", LIMIT), **options)


def finding(severity: RiskSeverity, category: str = "c", detail: str = "d") -> RiskAssessment:
    return RiskAssessment(severity=severity, category=category, detail=detail)


def demo_view(tmp_path: Path):
    output = tmp_path / "demo.json"
    result = CliRunner().invoke(
        main, ["scan", str(ROOT / "examples" / "demo-agent"), "-o", str(output)]
    )
    assert result.exit_code == 0, result.output
    return view_of(AIBOM.load(output))


def test_demo_scan_gives_the_documented_graph(tmp_path):
    view = demo_view(tmp_path)
    names = {node.index: node.name for node in view.nodes}
    assert len(view.nodes) == 11
    assert [edge.kind for edge in view.edges].count("dependency") == 10
    references = [edge for edge in view.edges if edge.kind == "reference"]
    assert {edge.label for edge in references} == {"server_refs"}
    assert len(references) == 3
    assert view.sinks == 3
    assert view.sources == 2 and view.sources_omitted == 0
    assert [(names[path.nodes[0]], names[path.nodes[-1]]) for path in view.paths] == [
        ("repository", "memory"),
        ("repository", "models/intent-classifier.safetensors"),
        ("repository", "ollama/ollama:latest"),
    ]
    assert all(path.sink_severity is RiskSeverity.HIGH for path in view.paths)
    assert view.paths_omitted == 0
    tickets = next(node for node in view.nodes if node.name == "tickets")
    assert [risk.value for risk in tickets.classification.classes] == ["network-egress"]
    memory = next(node for node in view.nodes if node.name == "memory")
    assert memory.unpinned and dict(memory.facts)["version_pinned"] is False
    assert view.coverage.status == "unknown" and view.coverage.collection == "complete"


def test_every_component_type_has_one_column():
    placed = [component_type for _, types in _COLUMNS for component_type in types]
    assert sorted(placed) == sorted(ComponentType)


def test_reference_fields_are_edges_unless_a_dependency_records_the_pair():
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a", name="a", tool_refs=["s"], model_refs=["m"]),
            MCPServerComponent(bom_ref="s", name="s"),
            ModelComponent(bom_ref="m", name="m"),
        ],
        dependencies=[
            DependencyEdge(source_ref="a", target_ref="s", relationship="configured-with"),
            DependencyEdge(source_ref="a", target_ref="s", relationship="configured-with"),
            DependencyEdge(
                source_ref="a", target_ref="s", relationship="configured-with", conditions="x"
            ),
        ],
    )
    view = view_of(bom)
    refs = {node.index: node.ref for node in view.nodes}
    shown = [
        (refs[edge.source], refs[edge.target], edge.kind, edge.label, edge.conditional)
        for edge in view.edges
    ]
    assert shown == [
        ("a", "s", "dependency", "configured-with", False),
        ("a", "s", "dependency", "configured-with", True),
        ("a", "m", "reference", "model_refs", False),
    ]
    assert [edge.index for edge in view.edges] == [0, 1, 2]


def test_input_order_does_not_change_the_view(tmp_path):
    view = demo_view(tmp_path)
    bom = AIBOM.load(tmp_path / "demo.json")
    shuffled = bom.model_copy(deep=True)
    shuffled.components = [*shuffled.components[5:], *reversed(shuffled.components[:5])]
    shuffled.dependencies.reverse()
    assert render_html(view_of(shuffled)) == render_html(view)
    assert view_document(view_of(shuffled)) == view_document(view)


def two_islands() -> AIBOM:
    return AIBOM(
        components=[
            AgentComponent(bom_ref="a1", name="alpha-marker", tool_refs=["t1"]),
            ToolComponent(bom_ref="t1", name="t1"),
            AgentComponent(bom_ref="a2", name="beta-marker", tool_refs=["t2"]),
            ToolComponent(bom_ref="t2", name="t2"),
            ToolComponent(bom_ref="alone", name="alone"),
        ]
    )


def test_focus_keeps_only_the_blast_radius():
    view = view_of(two_islands(), focus="t1")
    assert sorted(node.ref for node in view.nodes) == ["a1", "t1"]
    assert view.focus == "t1"
    assert [view.nodes[edge.source].ref for edge in view.edges] == ["a1"]
    alone = view_of(two_islands(), focus="alone")
    assert [node.ref for node in alone.nodes] == ["alone"] and not alone.edges


def test_focus_keeps_what_agents_reach_but_not_what_ide_agents_or_clients_reach():
    bom = AIBOM(
        components=[
            IDEAgentComponent(bom_ref="ide", name="ide", mcp_server_refs=["s1", "s2"]),
            MCPClientComponent(bom_ref="client", name="client", server_refs=["s1", "s3"]),
            AgentComponent(bom_ref="agent", name="agent", tool_refs=["s1", "s4"]),
            *(MCPServerComponent(bom_ref=ref, name=ref) for ref in ("s1", "s2", "s3", "s4")),
        ]
    )
    view = view_of(bom, focus="s1")
    assert sorted(node.ref for node in view.nodes) == ["agent", "client", "ide", "s1", "s4"]
    assert (
        "Focus: the potential blast radius of <code>s1</code>: it, what depends on it, and "
        "what it and the components of type agent among those reach. What IDE agents and "
        "clients among them reach is not shown."
    ) in render_html(view)


def test_an_unknown_focus_names_only_the_clipped_reference():
    bom = two_islands()
    with pytest.raises(GraphViewError) as raised:
        view_of(bom, focus="missing-" + "x" * 5_000)
    message = str(raised.value)
    assert message.startswith("unknown component: missing-xxx")
    assert len(message) < 300
    assert "marker" not in message and "a2" not in message and "t2" not in message


def test_more_components_than_the_limit_fail_without_truncation():
    with pytest.raises(TooManyComponentsError) as raised:
        view_of(two_islands(), max_nodes=4)
    assert (raised.value.count, raised.value.limit) == (5, 4)
    assert len(view_of(two_islands(), max_nodes=5).nodes) == 5
    assert len(view_of(two_islands(), max_nodes=2, focus="t2").nodes) == 2


def test_an_invalid_graph_is_refused():
    bom = AIBOM(
        components=[AgentComponent(bom_ref="a", name="a", tool_refs=["missing"])],
        dependencies=[DependencyEdge(source_ref="a", target_ref="gone", relationship="invokes")],
    )
    with pytest.raises(GraphViewError, match=r"^invalid graph: .*missing target missing"):
        view_of(bom)


def sink_tools(count: int, *, prefix: str = "t") -> list[ToolComponent]:
    return [
        ToolComponent(
            bom_ref=f"{prefix}{index:04d}",
            name=f"{prefix}{index:04d}",
            risks=[finding(RiskSeverity.CRITICAL)],
        )
        for index in range(count)
    ]


def test_sources_and_paths_are_capped_with_omitted_counts():
    agents = [
        AgentComponent(bom_ref=f"a{index:04d}", name=f"a{index:04d}", tool_refs=["t0000"])
        for index in range(MAX_SOURCES + 50)
    ]
    view = view_of(AIBOM(components=[*agents, *sink_tools(1)]))
    assert (view.sources, view.sources_omitted) == (MAX_SOURCES + 50, 50)
    assert (len(view.paths), view.paths_omitted) == (MAX_SOURCES, 0)
    assert {view.nodes[path.nodes[0]].ref for path in view.paths} == {
        f"a{index:04d}" for index in range(MAX_SOURCES)
    }
    tools = sink_tools(MAX_PATHS + 30)
    agent = AgentComponent(bom_ref="a", name="a", tool_refs=[tool.bom_ref for tool in tools])
    many = view_of(AIBOM(components=[agent, *tools]))
    assert (len(many.paths), many.paths_omitted) == (MAX_PATHS, 30)
    assert view_document(many)["exposure"]["paths_omitted"] == 30


def test_paths_rank_by_sink_weight_then_length_then_reference():
    def tool(ref: str, *capabilities: CapabilityClass, risks=()) -> ToolComponent:
        return ToolComponent(
            bom_ref=ref,
            name=ref,
            capabilities=CapabilityDeclaration(capabilities=list(capabilities)),
            risks=list(risks),
        )

    components = [
        AgentComponent(
            bom_ref="agent",
            name="agent",
            tool_refs=["secret", "write", "exfil", "exec", "high", "crit", "exec-b", "medium-only"],
            sub_agent_refs=["hop"],
        ),
        tool("secret", CapabilityClass.CREDENTIALS),
        tool("write", CapabilityClass.WRITE),
        tool("exfil", CapabilityClass.NETWORK, CapabilityClass.READ),
        tool("exec", CapabilityClass.EXECUTE),
        tool("exec-b", CapabilityClass.EXECUTE),
        tool("high", risks=[finding(RiskSeverity.HIGH)]),
        tool("crit", risks=[finding(RiskSeverity.CRITICAL)]),
        tool("medium-only", CapabilityClass.NETWORK, risks=[finding(RiskSeverity.MEDIUM)]),
        AgentComponent(bom_ref="hop", name="hop", tool_refs=["deep"]),
        tool("deep", CapabilityClass.EXECUTE),
    ]
    view = view_of(AIBOM(components=components))
    ranked = [(view.nodes[p.nodes[0]].ref, view.nodes[p.nodes[-1]].ref) for p in view.paths]
    assert ranked[:8] == [
        ("agent", "crit"),
        ("agent", "high"),
        ("agent", "exec"),
        ("agent", "exec-b"),
        ("hop", "deep"),
        ("agent", "deep"),
        ("agent", "exfil"),
        ("agent", "write"),
    ]
    assert ranked[8:] == [("agent", "secret")]
    deep = view.paths[5]
    assert [view.nodes[index].ref for index in deep.nodes] == ["agent", "hop", "deep"]
    assert deep.labels == ("sub_agent_refs", "tool_refs")
    assert "medium-only" not in {view.nodes[p.nodes[-1]].ref for p in view.paths}


def test_each_path_is_a_shortest_one_whichever_route_is_found_first():
    # Each sink has a two-edge and a three-edge route. The longer route to x leaves the
    # agent through c, the later of its tools in index order, and the longer route to y
    # through b, the earlier, so a depth-first search in either order lengthens one path.
    hops = [("b", "x"), ("b", "e"), ("e", "y"), ("c", "d"), ("d", "x"), ("c", "y")]
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a", name="a", tool_refs=["b", "c"]),
            *(ToolComponent(bom_ref=ref, name=ref) for ref in ("b", "c", "d", "e")),
            *(
                ToolComponent(bom_ref=ref, name=ref, risks=[finding(RiskSeverity.CRITICAL)])
                for ref in ("x", "y")
            ),
        ],
        dependencies=[
            DependencyEdge(source_ref=source, target_ref=target, relationship="depends-on")
            for source, target in hops
        ],
    )
    view = view_of(bom)
    refs = [node.ref for node in view.nodes]
    assert [([refs[index] for index in path.nodes], path.labels) for path in view.paths] == [
        (["a", "b", "x"], ("tool_refs", "depends-on")),
        (["a", "c", "y"], ("tool_refs", "depends-on")),
    ]
    document = view_document(view)["exposure"]["paths"]
    assert [
        (path["length"], [refs[i] for i in path["nodes"]], path["labels"]) for path in document
    ] == [
        (2, ["a", "b", "x"], ["tool_refs", "depends-on"]),
        (2, ["a", "c", "y"], ["tool_refs", "depends-on"]),
    ]


def _routes(view) -> list[list[str]]:
    return sorted([view.nodes[index].ref for index in path.nodes] for path in view.paths)


def test_a_source_that_reaches_no_sink_is_the_first_left_unsearched():
    # An imported discovery report can add hundreds of agents. A rating below high gives
    # each a finding and makes none a sink.
    alone = [
        AgentComponent(
            bom_ref=f"a{index:04d}", name=f"a{index:04d}", risks=[finding(RiskSeverity.MEDIUM)]
        )
        for index in range(MAX_SOURCES + 50)
    ]
    wired = AgentComponent(bom_ref="y", name="y", tool_refs=["t0000"])
    rated = AgentComponent(bom_ref="z", name="z", risks=[finding(RiskSeverity.HIGH)])
    capped = view_of(AIBOM(components=[*alone, wired, rated, *sink_tools(1)]))
    assert (capped.sources, capped.sources_omitted) == (MAX_SOURCES + 52, 52)
    assert _routes(capped) == [["y", "t0000"], ["z"]]


def test_an_edge_that_leads_to_no_sink_does_not_keep_a_source_ahead_of_one_with_a_path():
    # A report whose entries depend on one another, on an unrated entry or on themselves.
    quiet = ToolComponent(bom_ref="quiet", name="quiet")
    ring = [
        AgentComponent(bom_ref=f"a{index:04d}", name=f"a{index:04d}", tool_refs=["quiet"])
        for index in range(MAX_SOURCES + 50)
    ]
    edges = [
        DependencyEdge(
            source_ref=f"a{index:04d}",
            target_ref=f"a{(index + 1) % len(ring):04d}",
            relationship="depends-on",
        )
        for index in range(len(ring))
    ]
    wired = AgentComponent(bom_ref="y", name="y", tool_refs=["t0000"])
    view = view_of(AIBOM(components=[*ring, wired, quiet, *sink_tools(1)], dependencies=edges))
    assert (view.sources, view.sources_omitted) == (MAX_SOURCES + 51, 51)
    assert _routes(view) == [["y", "t0000"]]


def test_an_ide_agent_that_is_a_sink_by_its_class_is_searched_before_idle_ones():
    idle = [
        IDEAgentComponent(bom_ref=f"i{index:04d}", name=f"i{index:04d}", ide_type="claude-code")
        for index in range(MAX_SOURCES + 50)
    ]
    bypass = IDEAgentComponent(
        bom_ref="z", name="z", ide_type="claude-code", permission_mode="bypassPermissions"
    )
    view = view_of(AIBOM(components=[*idle, bypass]))
    assert (view.sources, view.sources_omitted) == (MAX_SOURCES + 51, 51)
    assert _routes(view) == [["z"]]


def _crowded(seed: int) -> AIBOM:
    # More than 200 agents, each a sink itself or wired to a tool that may be one.
    rng = random.Random(seed)  # noqa: S311 - fixed test data, not a secret
    levels = (RiskSeverity.HIGH, RiskSeverity.CRITICAL)
    tools = [
        ToolComponent(
            bom_ref=f"t{index:03d}",
            name=f"t{index:03d}",
            risks=[finding(rng.choice(levels))] if rng.random() < 0.5 else [],
        )
        for index in range(30)
    ]
    # Names sort against references, so node order and reference order differ.
    agents = [
        AgentComponent(bom_ref=f"a{index:04d}", name=f"n{9999 - index:04d}", risks=[finding(level)])
        if (level := rng.choice(levels)) and rng.random() < 0.4
        else AgentComponent(
            bom_ref=f"a{index:04d}",
            name=f"n{9999 - index:04d}",
            tool_refs=[rng.choice(tools).bom_ref],
        )
        for index in range(rng.randint(MAX_SOURCES + 10, 2 * MAX_SOURCES))
    ]
    edges = [
        DependencyEdge(source_ref=a.bom_ref, target_ref=b.bom_ref, relationship="depends-on")
        for a, b in (rng.sample(tools, 2) for _ in range(20))
    ]
    return AIBOM(components=[*agents, *tools], dependencies=edges)


@pytest.mark.parametrize("seed", range(12))
def test_the_capped_view_holds_the_best_paths_of_every_source(monkeypatch, seed):
    bom = _crowded(seed)
    capped = view_of(bom)
    assert capped.sources_omitted > 0
    monkeypatch.setattr(graph_view, "MAX_SOURCES", 10**9)
    whole = view_of(bom)
    assert whole.sources_omitted == 0
    assert _routes(capped) == _routes(whole)
    assert [path.nodes for path in capped.paths] == [path.nodes for path in whole.paths]


def test_the_distance_that_decides_the_cut_is_the_shortest():
    # `z` reaches the critical tool in two hops through `x`, and in three through `p`.
    # Two hundred others reach it in two hops and sort after `z`, so `z` must be kept.
    hop = ToolComponent(bom_ref="q", name="q")
    others = [
        AgentComponent(bom_ref=f"b{index:04d}", name=f"b{index:04d}", tool_refs=["q"])
        for index in range(MAX_SOURCES)
    ]
    chain = [ToolComponent(bom_ref=ref, name=ref) for ref in ("p", "x", "y")]
    agent = AgentComponent(bom_ref="a", name="a", tool_refs=["p", "x"])
    links = [("q", "t0000"), ("x", "t0000"), ("y", "t0000"), ("p", "y")]
    edges = [
        DependencyEdge(source_ref=s, target_ref=t, relationship="depends-on") for s, t in links
    ]
    view = view_of(
        AIBOM(components=[*others, agent, hop, *chain, *sink_tools(1)], dependencies=edges)
    )
    assert view.sources_omitted == 1
    assert [view.nodes[index].ref for index in view.paths[0].nodes] == ["a", "x", "t0000"]


def test_a_source_that_reaches_a_heavier_sink_is_searched_first():
    # Imported agents rated high are sinks themselves and sort before the repository
    # agent, which reaches a critical tool through an edge.
    imported = [
        AgentComponent(
            bom_ref=f"a{index:04d}", name=f"a{index:04d}", risks=[finding(RiskSeverity.HIGH)]
        )
        for index in range(MAX_SOURCES + 50)
    ]
    repository = AgentComponent(bom_ref="repo-agent", name="repo-agent", tool_refs=["t0000"])
    view = view_of(AIBOM(components=[*imported, repository, *sink_tools(1)]))
    assert (view.sources, view.sources_omitted) == (MAX_SOURCES + 51, 51)
    assert _routes(view)[-1] == ["repo-agent", "t0000"]
    first = view.paths[0]
    assert [view.nodes[index].ref for index in first.nodes] == ["repo-agent", "t0000"]


def test_a_source_reaching_a_heavy_sink_far_away_outranks_one_beside_a_light_sink():
    # The heaviest sink a source reaches decides, not the nearest one.
    light = ToolComponent(bom_ref="light", name="light", risks=[finding(RiskSeverity.HIGH)])
    near = [
        AgentComponent(bom_ref=f"a{index:04d}", name=f"a{index:04d}", tool_refs=["light"])
        for index in range(MAX_SOURCES)
    ]
    far = AgentComponent(bom_ref="far", name="far", tool_refs=["hop"])
    hop = ToolComponent(bom_ref="hop", name="hop")
    edge = DependencyEdge(source_ref="hop", target_ref="t0000", relationship="depends-on")
    view = view_of(AIBOM(components=[*near, far, hop, light, *sink_tools(1)], dependencies=[edge]))
    assert view.sources_omitted == 1
    assert [view.nodes[index].ref for index in view.paths[0].nodes] == ["far", "hop", "t0000"]


def test_a_source_that_is_itself_a_sink_has_a_path_of_length_zero():
    agent = IDEAgentComponent(
        bom_ref="ide",
        name="claude-code",
        ide_type="claude-code",
        permission_mode="bypassPermissions",
    )
    view = view_of(AIBOM(components=[agent]))
    assert len(view.paths) == 1
    assert view.paths[0].nodes == (0,) and view.paths[0].edges == ()
    assert [risk.value for risk in view.paths[0].sink_classes] == ["code-exec", "write-capable"]
    assert view_document(view)["exposure"]["paths"][0]["length"] == 0


def chain(agents: int, length: int) -> AIBOM:
    """Agents that all reach a chain of sinks, so every source reaches every sink."""
    tools = [
        ToolComponent(
            bom_ref=f"t{index:06d}",
            name="t",
            mcp_server_ref=None,
            risks=[finding(RiskSeverity.CRITICAL)],
        )
        for index in range(length)
    ]
    components = [
        *(
            AgentComponent(bom_ref=f"a{i:04d}", name="a", tool_refs=["t000000"])
            for i in range(agents)
        ),
        *tools,
    ]
    edges = [
        DependencyEdge(
            source_ref=f"t{index:06d}", target_ref=f"t{index + 1:06d}", relationship="depends-on"
        )
        for index in range(length - 1)
    ]
    return AIBOM(components=components, dependencies=edges)


@pytest.mark.timeout(120)
def test_exposure_work_grows_linearly_with_the_graph():
    boms = {scale: chain(20, 600 * scale) for scale in (1, 4)}
    view = view_of(boms[1])
    assert len(view.paths) == MAX_PATHS
    assert view.paths_omitted == 20 * 600 - MAX_PATHS
    # Four times the nodes and edges: about four times the work if linear, sixteen if
    # every (source, sink) path were rebuilt.
    assert scaling_ratio(lambda scale: view_of(boms[scale], max_nodes=20_000)) < 10


@pytest.mark.timeout(120)
def test_exposure_work_grows_linearly_with_the_sources():
    boms = {scale: chain(10 * scale, 1_500) for scale in (1, 4)}
    assert scaling_ratio(lambda scale: view_of(boms[scale], max_nodes=20_000)) < 10


def long_paths(tools: int, sinks: int, name: str = "c") -> AIBOM:
    """An agent, a chain of tools named ``name``, and critical sinks at the chain's end:
    every exposure path passes through every tool of the chain."""
    links = [f"c{index:05d}" for index in range(tools)]
    tails = sink_tools(sinks, prefix="s")
    edges = [
        DependencyEdge(source_ref=source, target_ref=target, relationship="depends-on")
        for source, target in zip(links, links[1:], strict=False)
    ]
    edges.extend(
        DependencyEdge(source_ref=links[-1], target_ref=tail.bom_ref, relationship="depends-on")
        for tail in tails
    )
    return AIBOM(
        components=[
            AgentComponent(bom_ref="a", name="a", tool_refs=links[:1]),
            *(ToolComponent(bom_ref=ref, name=name) for ref in links),
            *tails,
        ],
        dependencies=edges,
    )


@pytest.mark.timeout(120)
def test_page_rendering_does_not_grow_with_the_length_of_a_name():
    # Every kept path passes through one tool. Neutralizing its whole name before clipping
    # it, once per path, cost about sixteen times as much at sixteen times the length.
    views = {scale: view_of(long_paths(1, MAX_PATHS, "n" * 20_000 * scale)) for scale in (1, 16)}
    assert len(views[16].paths) == MAX_PATHS
    assert scaling_ratio(lambda scale: render_html(views[scale]), factor=16) < 4


@pytest.mark.timeout(120)
def test_long_kept_paths_add_only_their_index_lists_to_the_page():
    # MAX_PATHS paths through the same thousand tools instead of one. Each lists its node
    # and edge indexes; escaping every name on every path as well made the page about
    # ten times as costly to render.
    views = {scale: view_of(long_paths(1_000, scale)) for scale in (1, MAX_PATHS)}
    assert [len(views[scale].paths[-1].nodes) for scale in (1, MAX_PATHS)] == [1_002, 1_002]
    assert len(views[MAX_PATHS].paths) == MAX_PATHS

    def ratio() -> float:
        return scaling_ratio(lambda scale: render_html(views[scale]), factor=MAX_PATHS)

    # scaling_ratio measures again only above 1.5 times its factor, which is 300 here and
    # far over this bound, so load during the larger render alone is not forgiven there:
    # 5.98 was measured once on a hosted runner for a ratio that is otherwise about 2.2.
    assert ratio() < 5 or ratio() < 5


def test_findings_are_ordered_bounded_and_clipped():
    risks = [finding(RiskSeverity.LOW, "low", "x" * 5_000)] * 5 + [
        finding(RiskSeverity.CRITICAL, f"c{index}") for index in range(MAX_FINDINGS + 3)
    ]
    view = view_of(AIBOM(components=[ToolComponent(bom_ref="t", name="t", risks=risks)]))
    summary = view.nodes[0].findings
    assert summary.total == MAX_FINDINGS + 8
    assert len(summary.shown) == MAX_FINDINGS and summary.omitted == 8
    assert summary.highest is RiskSeverity.CRITICAL
    assert dict(summary.counts)[RiskSeverity.LOW] == 5
    assert [item.category for item in summary.shown[:2]] == ["c0", "c1"]
    low = view_of(AIBOM(components=[ToolComponent(bom_ref="t", name="t", risks=risks[:1])]))
    detail = low.nodes[0].findings.shown[0].detail
    assert len(detail) == DETAIL_CHARS and detail.endswith("…")


def test_a_model_keeps_the_findings_its_recorded_fields_imply():
    model = ModelComponent(
        bom_ref="m", name="m", serialization_safety=SerializationSafety.UNSAFE_CODE_EXECUTION
    )
    agent = AgentComponent(bom_ref="a", name="a", model_refs=["m"])
    view = view_of(AIBOM(components=[agent, model]))
    node = next(node for node in view.nodes if node.ref == "m")
    assert node.findings.highest is RiskSeverity.CRITICAL
    assert [item.category for item in node.findings.shown] == ["serialization_format"]
    assert view.paths[0].sink_severity is RiskSeverity.CRITICAL


@pytest.mark.parametrize(
    ("component", "unpinned"),
    [
        (MCPServerComponent(bom_ref="s", name="s", version_pinned=False), True),
        (MCPServerComponent(bom_ref="s", name="s", version_pinned=True), False),
        (MCPServerComponent(bom_ref="s", name="s"), False),
        (
            RegistryEntryComponent(
                bom_ref="r", name="r", risks=[finding(RiskSeverity.HIGH, "version_pinning")]
            ),
            True,
        ),
        (
            RegistryEntryComponent(
                bom_ref="r", name="r", risks=[finding(RiskSeverity.MEDIUM, "mutable_image_tag")]
            ),
            True,
        ),
    ],
)
def test_unpinned_follows_the_pin_field_and_pinning_findings(component, unpinned):
    assert view_of(AIBOM(components=[component])).nodes[0].unpinned is unpinned


def test_coverage_without_a_claim_is_unknown():
    coverage = view_of(AIBOM()).coverage
    assert (coverage.status, coverage.collection) == ("unknown", "unknown")
    assert coverage.gaps == ("AIBOM has no completeness claim — cannot assess coverage.",)


def test_a_clipped_gap_keeps_the_record_count_of_a_grouped_failure():
    failure = "x" * (DETAIL_CHARS + 500)
    bom = AIBOM(components=[])
    bom.metadata.completeness = CompletenessClaim(
        scope="repository", scan_failures=[failure] * 6, surfaces_scanned=["."]
    )
    gaps = view_of(bom).coverage.gaps
    (gap,) = [gap for gap in gaps if gap.endswith(" (recorded 6 times)")]
    assert len(gap) == DETAIL_CHARS and "…" in gap and gap.startswith("x" * 100)
    single = AIBOM(components=[])
    single.metadata.completeness = CompletenessClaim(
        scope="repository", scan_failures=[failure], surfaces_scanned=["."]
    )
    (short,) = [gap for gap in view_of(single).coverage.gaps if gap.startswith("x")]
    assert len(short) == DETAIL_CHARS and short.endswith("…")


def test_scan_failures_make_coverage_incomplete_and_gaps_are_bounded():
    claim = CompletenessClaim(
        scope="repository",
        scan_failures=[f"failure {index}" for index in range(MAX_GAPS + 15)],
        surfaces_excluded=["x"],
        surfaces_scanned=["a"],
    )
    bom = AIBOM()
    bom.metadata.completeness = claim
    coverage = view_of(bom).coverage
    assert coverage.status == "incomplete" and coverage.collection == "partial"
    assert (coverage.scan_failures, coverage.surfaces_excluded) == (MAX_GAPS + 15, 1)
    assert len(coverage.gaps) == MAX_GAPS and coverage.gaps_omitted > 0
    html = render_html(view_of(bom))
    assert "Coverage incomplete." in html and f"{coverage.gaps_omitted} more gaps not shown" in html


def check_document(document: dict[str, Any]) -> None:
    """The documented shape of the JSON view, key by key."""
    assert list(document) == [
        "format",
        "inventory",
        "focus",
        "coverage",
        "limitations",
        "nodes",
        "edges",
        "exposure",
    ]
    assert document["format"] == FORMAT
    assert set(document["inventory"]) == {"spec_version", "timestamp", "components", "dependencies"}
    assert set(document["coverage"]) == {
        "status",
        "collection",
        "scan_failures",
        "surfaces_excluded",
        "gaps",
        "gaps_omitted",
    }
    assert document["coverage"]["status"] in {"incomplete", "unknown"}
    assert document["limitations"] == list(LIMITATIONS)
    nodes = document["nodes"]
    for position, node in enumerate(nodes):
        assert set(node) == {
            "index",
            "ref",
            "type",
            "name",
            "version",
            "assurance",
            "trust_tier",
            "risk_classes",
            "basis",
            "assessed",
            "findings",
            "facts",
            "unpinned",
            "source_path",
        }
        assert node["index"] == position
        assert set(node["findings"]) == {"total", "highest", "counts", "shown", "omitted"}
        assert list(node["findings"]["counts"]) == [severity.value for severity in RiskSeverity]
        assert all(
            set(item) == {"severity", "category", "detail"} for item in node["findings"]["shown"]
        )
        assert isinstance(node["assessed"], bool) and isinstance(node["unpinned"], bool)
    for position, edge in enumerate(document["edges"]):
        assert set(edge) == {
            "index",
            "source",
            "target",
            "kind",
            "label",
            "assurance",
            "conditional",
        }
        assert edge["index"] == position and edge["kind"] in {"dependency", "reference"}
        assert 0 <= edge["source"] < len(nodes) and 0 <= edge["target"] < len(nodes)
    exposure = document["exposure"]
    assert set(exposure) == {"sources", "sources_omitted", "sinks", "paths", "paths_omitted"}
    for path in exposure["paths"]:
        assert set(path) == {
            "source",
            "sink",
            "length",
            "nodes",
            "edges",
            "labels",
            "sink_classes",
            "sink_severity",
        }
        assert path["nodes"][0] == path["source"] and path["nodes"][-1] == path["sink"]
        assert path["length"] == len(path["edges"]) == len(path["labels"]) == len(path["nodes"]) - 1
        for hop, edge_index in enumerate(path["edges"]):
            edge = document["edges"][edge_index]
            assert (edge["source"], edge["target"]) == (path["nodes"][hop], path["nodes"][hop + 1])
            assert edge["label"] == path["labels"][hop]


def test_the_json_document_has_the_documented_shape(tmp_path):
    check_document(view_document(demo_view(tmp_path)))
    check_document(view_document(view_of(hostile_inventory())))


# Hostile text in every inventory field the view can show.
HOSTILE = (
    "</script><script>alert(1)</script>",
    '"><img src=x onerror=alert(1)>',
    "javascript:alert(1)",
    "' onmouseover='alert(1)'",
    "<!--",
    "]]>",
    "</style><style>*{color:red}</style>",
    "&lt;b&gt;",
    "nul\x00byte",
    "bidi\u202eoverride",
    "zero\u200bwidth\u2060joiner\ufeff",
    "::error::forged",
    "##[error]forged",
    '<a href="https://evil.example/x">link</a> //evil.example',
    "line\nbreak\r::warning::forged",
    "[md](https://evil.example) **bold** `code`",
)
WORD = re.compile(r"[a-z]{4,}")


def hostile_inventory() -> AIBOM:
    components: list[Any] = []
    dependencies: list[DependencyEdge] = []
    for index, text in enumerate(HOSTILE):
        risks = [finding(RiskSeverity.CRITICAL, text, text), finding(RiskSeverity.HIGH, "c", text)]
        agent_ref = f"agent:{index}:{text}"
        tool_ref = f"tool:{index}:{text}"
        server_ref = f"server:{index}:{text}"
        components.extend(
            [
                AgentComponent(
                    bom_ref=agent_ref,
                    name=text,
                    version=text,
                    description=text,
                    source_path=text,
                    tool_refs=[tool_ref],
                    capabilities=CapabilityDeclaration(capabilities=[CapabilityClass.EXECUTE]),
                    risks=risks,
                    properties={"capability_evidence": text},
                ),
                ToolComponent(
                    bom_ref=tool_ref,
                    name=text,
                    mcp_server_ref=server_ref,
                    description_text=text,
                    risks=risks,
                    capabilities=CapabilityDeclaration(capabilities=[CapabilityClass.WRITE]),
                ),
                MCPServerComponent(
                    bom_ref=server_ref,
                    name=text,
                    transport=text,
                    endpoint_url=text,
                    env={text: "***"},
                    version_pinned=False,
                    risks=risks,
                ),
                IDEAgentComponent(
                    bom_ref=f"ide:{index}:{text}",
                    name=text,
                    ide_type=text,
                    permission_mode=text,
                    mcp_server_refs=[server_ref],
                ),
                ModelComponent(
                    bom_ref=f"model:{index}:{text}", name=text, signing_status=text, version=text
                ),
            ]
        )
        dependencies.append(
            DependencyEdge(
                source_ref=server_ref,
                target_ref=tool_ref,
                relationship="provides-tool",
                conditions=text,
            )
        )
    components.append(MCPClientComponent(bom_ref="client", name="client", server_refs=[]))
    bom = AIBOM(components=components, dependencies=dependencies)
    bom.metadata.completeness = CompletenessClaim(
        scope="repository", scan_failures=list(HOSTILE), surfaces_scanned=list(HOSTILE)
    )
    return bom


class Page(HTMLParser):
    """Every element, attribute, text run, raw block and comment of a page."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.elements: list[tuple[str, list[tuple[str, str | None]]]] = []
        self.raw: dict[str, list[str]] = {"script": [], "style": []}
        self.text: list[str] = []
        self.other: list[str] = []
        self._inside: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, attrs))
        if tag in self.raw:
            self._inside = tag
            self.raw[tag].append("")

    def handle_startendtag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.elements.append((tag, attrs))

    def handle_endtag(self, tag: str) -> None:
        if tag == self._inside:
            self._inside = None

    def handle_data(self, data: str) -> None:
        if self._inside is not None:
            self.raw[self._inside][-1] += data
        else:
            self.text.append(data)

    def handle_comment(self, data: str) -> None:
        self.other.append("comment")

    def handle_pi(self, data: str) -> None:
        self.other.append("pi")

    def unknown_decl(self, data: str) -> None:
        self.other.append("declaration")


ELEMENTS = frozenset(
    (
        *("html", "head", "meta", "title", "style", "script", "body", "header", "main"),
        *("footer", "section", "aside", "article", "div", "p", "h1", "h2", "h3", "h4"),
        *("strong", "span", "code", "dl", "dt", "dd", "ul", "ol", "li", "button", "label"),
        *("input", "svg", "g", "text", "rect", "circle", "path"),
    )
)
ATTRIBUTES = frozenset(
    (
        *("lang", "http-equiv", "content", "charset", "name", "class", "id", "role"),
        *("tabindex", "transform", "width", "height", "viewbox", "x", "y", "rx", "cx", "cy"),
        *("r", "d", "type", "for", "autocomplete", "spellcheck", "aria-label"),
        *("aria-labelledby", "aria-pressed", "aria-hidden", "aria-live", "data-i", "data-s"),
        *("data-t", "data-classes", "data-sev", "data-unpinned", "data-unclassified"),
        *("data-name", "data-f", "data-p", "data-nodes", "data-edges", "data-sink"),
    )
)
# Attributes that may carry inventory text; every other value is generated.
TEXT_ATTRIBUTES = frozenset({"aria-label", "data-name"})
FIXED_VALUE = re.compile(r"[A-Za-z0-9 ._,()-]*")


def source_hash(text: str) -> str:
    return "'sha256-" + base64.b64encode(hashlib.sha256(text.encode()).digest()).decode() + "'"


def parsed(document: str) -> Page:
    page = Page()
    page.feed(document)
    page.close()
    return page


def check_inert(document: str) -> Page:
    page = parsed(document)
    assert document.startswith('<!DOCTYPE html>\n<html lang="en">\n<head>\n<meta http-equiv=')
    assert [tag for tag, _ in page.elements[:3]] == ["html", "head", "meta"]
    assert page.elements[2][1] == [
        ("http-equiv", "Content-Security-Policy"),
        ("content", CONTENT_SECURITY_POLICY),
    ]
    assert page.raw == {"script": [SCRIPT], "style": [STYLE]}
    assert '<meta charset="utf-8">' in document.encode()[:1024].decode(errors="replace")
    expected = (
        f"default-src 'none'; style-src {source_hash(STYLE)}; script-src {source_hash(SCRIPT)}; "
        "img-src data:; base-uri 'none'; form-action 'none'"
    )
    assert expected == CONTENT_SECURITY_POLICY
    assert page.other == []
    for tag, attrs in page.elements:
        assert tag in ELEMENTS, tag
        for name, value in attrs:
            assert name in ATTRIBUTES, (tag, name)
            assert not name.startswith("on")
            if name not in TEXT_ATTRIBUTES and value is not None:
                assert FIXED_VALUE.fullmatch(value) or name == "content", (tag, name, value)
                assert "//" not in value, (tag, name)
    for raw in (SCRIPT, STYLE):
        assert "//" not in raw and "</" not in raw and "<!--" not in raw
        assert not re.search(r"innerHTML|outerHTML|insertAdjacent|eval|Function\(|write\(", raw)
        assert "url(" not in raw and "@import" not in raw
    assert not UNSAFE_TEXT.search(document.replace("\n", ""))
    assert "##[" not in document
    assert not any(line.lstrip().startswith("::") for line in document.splitlines())
    return page


def test_hostile_inventory_text_is_inert_in_the_page():
    document = render_html(view_of(hostile_inventory()))
    page = check_inert(document)
    for raw in ("<img", "<script>alert", "<a href", "onmouseover='", "</style><style>"):
        assert raw not in document
    text = "".join(page.text)
    attributes = [value or "" for _, attrs in page.elements for _, value in attrs]
    for hostile in HOSTILE:
        shown = UNSAFE_TEXT.sub("\ufffd", hostile).replace("##[", "##\ufffd[")
        assert shown in text, hostile
        if len(shown) <= LABEL_CHARS:
            assert any(shown in value for value in attributes), hostile


def test_hostile_text_never_reaches_a_class_id_or_data_attribute():
    page = parsed(render_html(view_of(hostile_inventory())))
    generated = [
        value
        for _, attrs in page.elements
        for name, value in attrs
        if name in {"class", "id"} or (name.startswith("data-") and name != "data-name")
    ]
    assert generated
    for value in generated:
        assert value is None or re.fullmatch(r"[a-z0-9 -]*", value), value


def test_text_stays_within_its_limit_when_neutralizing_lengthens_it():
    # 28 characters; breaking the log command adds one, so the label is clipped again.
    name = "##vso[" + "&" * 22
    page = render_html(view_of(AIBOM(components=[ToolComponent(bom_ref="t", name=name)])))
    label = re.search(r'<text class="nm" x="44" y="21">([^<]*)</text>', page)
    assert label is not None
    assert label.group(1) == "##�vso[" + "&amp;" * 20 + "…"
    assert len(unescape(label.group(1))) == LABEL_CHARS
    assert f'data-name="##�vso[{"&amp;" * 22}"' in page
    # The name filter reads data-name: a name whole up to 200 characters, else its first 199.
    names = [ToolComponent(bom_ref=f"t{size}", name="n" * size) for size in (200, 201)]
    page = render_html(view_of(AIBOM(components=names)))
    assert re.findall(r'data-name="(n+…?)"', page) == ["n" * 200, "n" * 199 + "…"]


def test_every_node_is_focusable_labelled_and_has_a_panel(tmp_path):
    view = demo_view(tmp_path)
    page = parsed(render_html(view))
    nodes = [
        dict(attrs)
        for tag, attrs in page.elements
        if tag == "g" and "node" in (dict(attrs).get("class") or "")
    ]
    panels = [dict(attrs) for tag, attrs in page.elements if tag == "article"]
    assert [node["data-i"] for node in nodes] == [str(index) for index in range(len(view.nodes))]
    assert all(node["tabindex"] == "0" and node["role"] == "button" for node in nodes)
    assert nodes[0]["aria-label"] == "agent: repository"
    assert [panel["id"] for panel in panels] == [f"c{index}" for index in range(len(view.nodes))]
    paths = [
        dict(attrs)
        for tag, attrs in page.elements
        if tag == "button" and "path" in (dict(attrs).get("class") or "").split()
    ]
    assert [path["data-nodes"] for path in paths] == [
        " ".join(map(str, p.nodes)) for p in view.paths
    ]


def test_unclassified_nodes_are_marked_and_never_called_safe():
    view = view_of(
        AIBOM(
            components=[
                ToolComponent(bom_ref="u", name="unknown-tool"),
                ToolComponent(
                    bom_ref="r",
                    name="reader",
                    capabilities=CapabilityDeclaration(capabilities=[CapabilityClass.READ]),
                ),
            ]
        )
    )
    document = render_html(view)
    assert re.search(r'<g class="node k-tool g4 unc" data-i="1"', document)
    assert re.search(r'<g class="node k-tool g4" data-i="0"', document)
    assert "Unclassified: the record holds no capability evidence" in document
    assert "None derived from the recorded evidence; this is not a statement of safety." in document
    assert "no risk" not in document.lower() and " safe." not in document.replace("not safe.", "")


def test_the_page_and_the_document_are_deterministic(tmp_path):
    view = demo_view(tmp_path)
    again = view_of(AIBOM.load(tmp_path / "demo.json"))
    assert render_html(view) == render_html(again)
    assert view_document(view) == view_document(again)
    hostile = hostile_inventory()
    assert render_html(view_of(hostile)) == render_html(view_of(hostile))


def test_an_empty_inventory_renders_an_empty_graph():
    document = render_html(view_of(AIBOM()))
    check_inert(document)
    assert (
        "No exposure path was found in the recorded edges. That is not evidence of safety"
        in document
    )
    assert 'viewBox="0 0 48 72"' in document


def test_the_page_states_every_count_it_leaves_out():
    agents = [
        AgentComponent(bom_ref=f"a{index:04d}", name="a", tool_refs=["t0000"])
        for index in range(MAX_SOURCES + 5)
    ]
    sources = render_html(view_of(AIBOM(components=[*agents, *sink_tools(1)])))
    assert "5 more agent sources were not searched." in sources
    tools = sink_tools(MAX_PATHS + 7)
    risks = [finding(RiskSeverity.HIGH, f"c{index}") for index in range(MAX_FINDINGS + 4)]
    agent = AgentComponent(
        bom_ref="a", name="a", tool_refs=[tool.bom_ref for tool in tools], risks=risks
    )
    view = view_of(AIBOM(components=[agent, *tools]))
    # The agent's own high findings make it a sink as well, with a path of length 0.
    assert view.paths_omitted == 8
    page = render_html(view)
    assert "8 more paths not shown." in page
    assert "4 more findings not shown." in page
    check_inert(page)


def test_a_long_path_is_shortened_in_the_list_but_kept_whole_in_the_data():
    view = view_of(chain(1, 12))
    longest = max(view.paths, key=lambda path: len(path.nodes))
    assert len(longest.nodes) == 13
    page = render_html(view)
    assert "… 7 more …" in page
    assert f'data-nodes="{" ".join(map(str, longest.nodes))}"' in page


def test_edges_in_every_direction_and_a_self_loop_render():
    bom = AIBOM(
        components=[
            AgentComponent(bom_ref="a", name="a", tool_refs=["t"], sub_agent_refs=["b"]),
            AgentComponent(bom_ref="b", name="b"),
            ToolComponent(bom_ref="t", name="t", mcp_server_ref="s"),
            MCPServerComponent(bom_ref="s", name="s", tool_refs=["t"]),
        ],
        dependencies=[
            DependencyEdge(source_ref="t", target_ref="t", relationship="depends-on"),
            DependencyEdge(source_ref="s", target_ref="t", relationship="provides-tool"),
        ],
    )
    view = view_of(bom)
    page = render_html(view)
    check_inert(page)
    paths = re.findall(
        r'<g class="edge[^"]*" data-i="(\d+)"[^>]*><title>[^<]*</title><path class="ln" d="([^"]+)"',
        page,
    )
    assert len(paths) == len(view.edges) == 5
    loop = next(edge for edge in view.edges if edge.source == edge.target)
    assert re.fullmatch(r"M\d+ \d+ C\d+ \d+ \d+ \d+ \d+ \d+", dict(paths)[str(loop.index)])


def test_focus_is_stated_and_edges_outside_it_are_dropped():
    bom = two_islands()
    bom.dependencies.append(
        DependencyEdge(source_ref="a2", target_ref="t2", relationship="configured-with")
    )
    view = view_of(bom, focus="t1")
    assert [edge.label for edge in view.edges] == ["tool_refs"]
    page = render_html(view)
    assert "Focus: the potential blast radius of <code>t1</code>" in page
