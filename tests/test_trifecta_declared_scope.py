"""Approval coverage follows the agent which can exercise each recorded egress."""

import json
from datetime import UTC, datetime

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import HumanInTheLoop
from nexus_symbiote.core.models import AgentComponent, AuthorizationRecord, CapabilityDeclaration
from tests.test_trifecta_and_toxic_flows import _name_only_tools


def _gated_owner(refs):
    return AgentComponent(
        bom_ref="agent:parent",
        name="parent",
        tool_refs=refs,
        capabilities=CapabilityDeclaration(human_in_the_loop=HumanInTheLoop.REQUIRED),
    )


def _verdict(tmp_path, *components):
    path = tmp_path / "inventory.json"
    AIBOM(components=list(components)).save(path)
    result = CliRunner().invoke(main, ["trifecta", str(path)])
    findings = json.loads(result.output)["findings"]
    parent = next(
        f for f in findings if f["kind"] == "lethal_trifecta" and f["scope_ref"] == "agent:parent"
    )
    return result.exit_code, parent


@pytest.mark.parametrize("topology", ["unbound", "child", "child-cycle", "shared"])
def test_a_parent_gate_does_not_approve_independent_egress(tmp_path, topology):
    reader, private, outbound = _name_only_tools()
    parent = _gated_owner([reader.bom_ref, private.bom_ref])
    extra = []
    if topology != "unbound":
        child = AgentComponent(bom_ref="agent:worker", name="child", tool_refs=[outbound.bom_ref])
        parent.sub_agent_refs.append(child.bom_ref)
        if topology == "child-cycle":
            child.sub_agent_refs.append(parent.bom_ref)
        if topology == "shared":
            parent.tool_refs.append(outbound.bom_ref)
        extra.append(child)
    code, finding = _verdict(tmp_path, parent, *extra, reader, private, outbound)
    assert code == 1 and finding["severity"] == "critical"
    assert outbound.bom_ref in finding["component_refs"]


@pytest.mark.parametrize(
    "record",
    [
        {"approval_required": False},
        {"approval_required": True, "expires_at": datetime(2000, 1, 1, tzinfo=UTC)},
    ],
)
def test_contradictory_authorization_is_an_open_gate_even_with_required(tmp_path, record):
    reader, private, outbound = _name_only_tools()
    parent = _gated_owner([reader.bom_ref, private.bom_ref, outbound.bom_ref])
    parent.authorizations = [AuthorizationRecord(principal="reviewer", action="egress", **record)]
    code, finding = _verdict(tmp_path, parent, reader, private, outbound)
    assert code == 1 and finding["severity"] == "critical"


@pytest.mark.parametrize("unbound", [False, True])
def test_individually_gated_egress_keeps_its_own_coverage(tmp_path, unbound):
    reader, private, outbound = _name_only_tools()
    outbound.capabilities.human_in_the_loop = HumanInTheLoop.REQUIRED
    parent = _gated_owner([reader.bom_ref, private.bom_ref])
    idle = AgentComponent(bom_ref="agent:worker", name="worker")
    if not unbound:
        idle.capabilities = CapabilityDeclaration(human_in_the_loop=HumanInTheLoop.REQUIRED)
    parent.sub_agent_refs.append(idle.bom_ref)
    if not unbound:
        idle.tool_refs.append(outbound.bom_ref)
    code, finding = _verdict(tmp_path, parent, idle, reader, private, outbound)
    assert code == 0 and finding["severity"] == "high"
    assert "enforcement is unverified" in finding["summary"]


def test_a_record_with_conditions_does_not_cover_every_egress(tmp_path):
    reader, private, outbound = _name_only_tools()
    parent = AgentComponent(
        bom_ref="agent:parent",
        name="parent",
        tool_refs=[reader.bom_ref, private.bom_ref, outbound.bom_ref],
        authorizations=[
            AuthorizationRecord(
                principal="reviewer",
                action="*",
                approval_required=True,
                conditions=["review window is open"],
            )
        ],
    )
    code, finding = _verdict(tmp_path, parent, reader, private, outbound)
    assert code == 1 and finding["severity"] == "critical"
