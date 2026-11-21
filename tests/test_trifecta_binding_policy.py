"""Policy and modeling controls for the same inventory of inert components."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import HumanInTheLoop
from nexus_symbiote.core.models import (
    A2AClientComponent,
    AgentComponent,
    AuthorizationRecord,
    CapabilityDeclaration,
    MCPClientComponent,
    MCPServerComponent,
)
from nexus_symbiote.trifecta import EVIDENCE_LIMIT, analyze_trifecta
from tests.test_trifecta_and_toxic_flows import _name_only_tools


def _agent(ref, setting="required", **fields):
    return AgentComponent(
        bom_ref=ref,
        name=ref,
        capabilities=CapabilityDeclaration(human_in_the_loop=setting),
        **fields,
    )


def _severities(inventory, *, assume=False):
    return {
        f.scope_ref: f.severity.value
        for f in analyze_trifecta(inventory, assume_declared_approvals=assume).findings
        if f.kind == "lethal_trifecta"
    }


@pytest.mark.parametrize("setting", [None, "none", "conditional", "required"])
@pytest.mark.parametrize("depth", [0, 1, 3])
def test_every_agent_on_the_egress_path_must_declare_approval(setting, depth):
    reader, private, outbound = _name_only_tools()
    root = _agent("agent:root", tool_refs=[reader.bom_ref, private.bom_ref])
    chain = [root]
    for i in range(depth):
        worker = _agent(f"agent:worker-{i}")
        chain[-1].sub_agent_refs.append(worker.bom_ref)
        chain.append(worker)
    chain[depth // 2].capabilities.human_in_the_loop = HumanInTheLoop(setting) if setting else None
    chain[-1].tool_refs.append(outbound.bom_ref)
    bom = AIBOM(components=[*chain, reader, private, outbound])
    assert _severities(bom)[root.bom_ref] == ("high" if setting == "required" else "critical")
    # The explicit design-model API historically applies the scope owner's declaration.
    modeled = None if depth >= 2 or setting == "required" else "critical"
    assert _severities(bom, assume=True).get(root.bom_ref) == modeled


@pytest.mark.parametrize("kind", ["none", "conditional", None])
def test_direct_binding_reports_which_declaration_covers_egress(kind):
    reader, private, outbound = _name_only_tools()
    outbound.capabilities.human_in_the_loop = HumanInTheLoop(kind) if kind else None
    root = _agent("agent:root", tool_refs=[reader.bom_ref, private.bom_ref, outbound.bom_ref])
    report = analyze_trifecta(AIBOM(components=[root, reader, private, outbound]))
    finding = next(f for f in report.findings if f.kind == "lethal_trifecta")
    assert finding.severity.value == ("critical" if kind == "none" else "high")
    (leg,) = [item for item in finding.evidence if item["leg"] == "egress"]
    assert leg["egress_approval_declared"] is (kind != "none")
    assert leg["approval_enforcement_verified"] is False


@pytest.mark.parametrize(
    ("action", "severity"),
    [
        ("read", "high"),
        ("Read", "high"),
        ("READ ", "high"),
        ("query", "high"),
        ("list", "high"),
        ("search", "high"),
        ("get", "high"),
        ("write", "critical"),
        ("egress", "critical"),
        ("*", "critical"),
        ("mutation", "critical"),
    ],
)
def test_read_scope_is_independent_of_egress_and_modeling_keeps_its_precedence(action, severity):
    reader, private, outbound = _name_only_tools()
    root = _agent("agent:root", tool_refs=[reader.bom_ref, private.bom_ref, outbound.bom_ref])
    root.authorizations = [
        AuthorizationRecord(
            principal="reviewer", action=action, resource_scope="kb/*", approval_required=False
        )
    ]
    bom = AIBOM(components=[root, reader, private, outbound])
    assert _severities(bom)[root.bom_ref] == severity
    assert _severities(bom, assume=True) == {}


@pytest.mark.parametrize(
    "scope",
    [
        None,
        "",
        "*",
        "**",
        "https://*",
        "https://example.invalid/items",
        "//example.invalid/*",
        "*/items",
        "kb/../*",
        "kb/./*",
        "example.invalid/items",
    ],
)
def test_read_scope_that_could_authorize_egress_keeps_the_critical_finding(scope):
    reader, private, outbound = _name_only_tools()
    root = _agent(
        "agent:root", setting=None, tool_refs=[reader.bom_ref, private.bom_ref, outbound.bom_ref]
    )
    root.authorizations = [
        AuthorizationRecord(principal="reviewer", action="*", approval_required=True),
        AuthorizationRecord(principal="reviewer", action="read", resource_scope=scope),
    ]
    bom = AIBOM(components=[root, reader, private, outbound])
    assert _severities(bom)[root.bom_ref] == "critical"


@pytest.mark.parametrize("through", ["data", "skill", "memory", "depends-on", "invokes", "a2a"])
@pytest.mark.parametrize("listed_as_tool", [False, True])
def test_only_direct_tool_bindings_inherit_approval(through, listed_as_tool):
    reader, private, outbound = _name_only_tools()
    root = _agent("agent:root", tool_refs=[reader.bom_ref, private.bom_ref])
    if listed_as_tool:
        root.tool_refs.append(outbound.bom_ref)
    deps = []
    extra = []
    if through in {"data", "skill", "memory"}:
        getattr(root, through + "_refs").append(outbound.bom_ref)
    elif through == "a2a":
        peer = A2AClientComponent(
            bom_ref="a2a:peer", name="peer", agent_card_url="https://example.invalid"
        )
        extra.append(peer)
        deps.append(
            DependencyEdge(source_ref=root.bom_ref, target_ref=peer.bom_ref, relationship="invokes")
        )
        deps.append(
            DependencyEdge(
                source_ref=peer.bom_ref, target_ref=outbound.bom_ref, relationship="invokes"
            )
        )
    else:
        deps.append(
            DependencyEdge(
                source_ref=root.bom_ref, target_ref=outbound.bom_ref, relationship=through
            )
        )
    bom = AIBOM(components=[root, reader, private, outbound, *extra], dependencies=deps)
    assert _severities(bom)[root.bom_ref] == ("high" if through == "invokes" else "critical")


@pytest.mark.parametrize("bind_tool", [False, True])
@pytest.mark.parametrize("other_route", [False, True])
@pytest.mark.parametrize("declared_edge", [False, True])
def test_host_record_and_server_containment_preserve_each_agents_bindings(
    bind_tool, other_route, declared_edge
):
    reader, private, outbound = _name_only_tools()
    server = MCPServerComponent(bom_ref="mcp:catalog", name="catalog")
    host = MCPClientComponent(bom_ref="mcp:client", name="client", server_refs=[server.bom_ref])
    root = _agent("agent:root", tool_refs=[reader.bom_ref, private.bom_ref, server.bom_ref])
    if bind_tool:
        root.tool_refs.append(outbound.bom_ref)
    other = _agent("agent:other", tool_refs=[reader.bom_ref, private.bom_ref, server.bom_ref])
    deps = [
        DependencyEdge(
            source_ref=root.bom_ref, target_ref=host.bom_ref, relationship="configured-with"
        )
    ]
    if declared_edge:
        deps.append(
            DependencyEdge(
                source_ref=server.bom_ref, target_ref=outbound.bom_ref, relationship="provides-tool"
            )
        )
    else:
        outbound.mcp_server_ref = server.bom_ref
    if other_route:
        deps.append(
            DependencyEdge(
                source_ref=server.bom_ref, target_ref=outbound.bom_ref, relationship="depends-on"
            )
        )
    bom = AIBOM(
        components=[root, other, reader, private, outbound, server, host], dependencies=deps
    )
    assert _severities(bom) == {
        root.bom_ref: "high" if bind_tool and not other_route else "critical",
        other.bom_ref: "critical",
    }


def test_shared_catalog_reports_the_first_uncovered_members_for_each_owner():
    reader, private, outbound = _name_only_tools()
    size = EVIDENCE_LIMIT * 2 + 1
    servers = [MCPServerComponent(bom_ref=f"mcp:{i:03d}", name=f"server-{i}") for i in range(size)]
    tools = [
        outbound.model_copy(
            update={
                "bom_ref": f"tool:send:{i:03d}",
                "name": f"send_webhook_{i}",
                "mcp_server_ref": s.bom_ref,
            }
        )
        for i, s in enumerate(servers)
    ]
    host = MCPClientComponent(
        bom_ref="mcp:client", name="catalog", server_refs=[s.bom_ref for s in servers]
    )
    owners = []
    expected = {}
    for i in range(3):
        covered = {t.bom_ref for t in tools[i : i + EVIDENCE_LIMIT]}
        owner = _agent(f"agent:{i}", tool_refs=[reader.bom_ref, private.bom_ref, *sorted(covered)])
        owners.append(owner)
        expected[owner.bom_ref] = [t.bom_ref for t in tools if t.bom_ref not in covered][
            :EVIDENCE_LIMIT
        ]
    edges = [
        DependencyEdge(
            source_ref=a.bom_ref, target_ref=host.bom_ref, relationship="configured-with"
        )
        for a in owners
    ]
    bom = AIBOM(components=[*owners, reader, private, *servers, host, *tools], dependencies=edges)
    actual = {
        f.scope_ref: [item["component_ref"] for item in f.evidence if item["leg"] == "egress"]
        for f in analyze_trifecta(bom).findings
        if f.kind == "lethal_trifecta" and f.severity.value == "critical"
    }
    assert actual == expected


def test_undeclared_owner_cannot_use_approval_on_an_unbound_tool():
    reader, private, outbound = _name_only_tools()
    outbound.capabilities.human_in_the_loop = HumanInTheLoop.REQUIRED
    root = _agent("agent:root", setting=None, tool_refs=[reader.bom_ref, private.bom_ref])
    bom = AIBOM(components=[root, reader, private, outbound])
    assert _severities(bom)[root.bom_ref] == "critical"


def test_collected_mcp_host_record_is_not_an_independent_invocation(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    name: {"command": "npx", "args": [f"@modelcontextprotocol/server-{name}"]}
                    for name in ("github", "postgres", "fetch", "slack")
                }
            }
        )
    )
    output = tmp_path / "inventory.json"
    scan = CliRunner().invoke(main, ["scan", str(project), "--output", str(output)])
    assert output.exists(), scan.output
    bom = AIBOM.load(output)
    owner = next(c for c in bom.components if isinstance(c, AgentComponent))
    assert any(isinstance(c, MCPClientComponent) for c in bom.components)
    owner.capabilities = CapabilityDeclaration(human_in_the_loop=HumanInTheLoop.REQUIRED)
    assert _severities(bom)[owner.bom_ref] == "high"


def test_a_configured_peer_is_an_independent_principal():
    reader, private, _ = _name_only_tools()
    peer = A2AClientComponent(bom_ref="a2a:peer", name="peer", properties={"external_egress": True})
    root = _agent("agent:root", tool_refs=[reader.bom_ref, private.bom_ref])
    link = DependencyEdge(
        source_ref=root.bom_ref, target_ref=peer.bom_ref, relationship="configured-with"
    )
    assert _severities(AIBOM(components=[root, reader, private, peer], dependencies=[link])) == {
        root.bom_ref: "critical"
    }


def test_conditional_record_retains_the_historical_explicit_modeling_verdict():
    tools = _name_only_tools()
    root = _agent("agent:root", None, tool_refs=[t.bom_ref for t in tools])
    root.authorizations = [
        AuthorizationRecord(
            principal="owner", action="egress", approval_required=True, conditions=["office hours"]
        )
    ]
    inventory = AIBOM(components=[root, *tools])
    assert _severities(inventory, assume=True) == {}
    assert _severities(inventory) == {root.bom_ref: "critical"}
