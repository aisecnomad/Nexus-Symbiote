"""Bounded database resources and unbounded or network-like authorization names."""

import pytest

from nexus_symbiote.core.models import AgentComponent, AuthorizationRecord
from tests.test_trifecta_and_toxic_flows import _name_only_tools
from tests.test_trifecta_declared_scope import _gated_owner, _verdict


@pytest.mark.parametrize("basis", ["required", "authorization"])
@pytest.mark.parametrize(
    ("scope", "bounded"),
    [
        ("all", False),
        ("any/*", False),
        ("everything", False),
        ("everywhere/*", False),
        ("egress", False),
        ("metadata", False),
        ("metadata/records", False),
        ("0x7f000001", False),
        ("0X7F000001/*", False),
        ("ip6-localhost", False),
        ("localhost6/*", False),
        ("loopback", False),
        ("imds/*", False),
        ("proxy/*", False),
        ("internal/*", False),
        ("gateway", False),
        ("www1/*", False),
        ("web_", False),
        ("fe80/*", False),
        ("w\u0435b/*", False),
        ("\u0430ll", False),
        ("table:*", False),
        ("table:crm.*", False),
        ("table:crm/../customers", False),
        ("table:crm.customers", True),
        ("table:public.users", True),
        ("table:orders", True),
        ("bücher", False),
        ("données/*", False),
        ("orders", False),
    ],
)
def test_typed_and_network_scope_names_at_the_cli(tmp_path, basis, scope, bounded):
    tools = _name_only_tools()
    refs = [tool.bom_ref for tool in tools]
    if basis == "required":
        owner = _gated_owner(refs)
    else:
        owner = AgentComponent(
            bom_ref="agent:parent",
            name="parent",
            tool_refs=refs,
            authorizations=[
                AuthorizationRecord(principal="reviewer", action="*", approval_required=True)
            ],
        )
    owner.authorizations.append(
        AuthorizationRecord(
            principal="reader", action="read", resource_scope=scope, approval_required=False
        )
    )
    status, finding = _verdict(tmp_path, owner, *tools)
    assert (status, finding["severity"]) == ((0, "high") if bounded else (1, "critical"))
    if bounded:
        assert "enforcement is unverified" in finding["summary"]
