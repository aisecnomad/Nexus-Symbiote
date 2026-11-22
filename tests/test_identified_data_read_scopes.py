"""Approval coverage requires a read grant whose resource declaration identifies data."""

import pytest

from nexus_symbiote.core.models import AgentComponent, AuthorizationRecord
from tests.test_trifecta_and_toxic_flows import _name_only_tools
from tests.test_trifecta_declared_scope import _gated_owner, _verdict


@pytest.mark.parametrize("gate", ["agent", "grant"])
@pytest.mark.parametrize(
    ("scope", "data"),
    [
        ("crm.customers", False),
        ("customers", False),
        ("customers/*", False),
        ("public_docs/*", False),
        ("db2/*", False),
        ("service/records", False),
        ("ｋｂ/notes", False),
        ("notes.example.invalid/docs", False),
        ("sites/*", False),
        ("table:customers", True),
        ("TABLE:crm.customers", True),
        ("Table:public.users", True),
        ("table:public_docs", True),
        ("table:db2", True),
        ("table:bücher", True),
        ("kb:données/*", True),
        ("table:all", False),
        ("table:localhost.example.com", True),
        ("table:sample.com", True),
        ("table:crm.*", False),
        ("tаble:customers", False),  # Cyrillic letter in the resource type.
        ("kb:project-notes", True),
        ("KB:project-notes/chapters/*", True),
        ("kb:*", False),
        ("kb:all", False),
        ("kb:notes/../other", False),
        ("arn:aws:s3:::project-notes/*", True),
        ("arn:aws:s3:::*/*", False),
        ("arn:aws:dynamodb:us-east-1:123456789012:table/ProjectNotes", True),
        ("arn:aws-us-gov:dynamodb:us-gov-west-1:123456789012:table/Notes/index/Topics", True),
        ("arn:aws:dynamodb:us-east-1:123456789012:table/*", False),
        ("arn:aws:dynamodb:us-east-1:*:table/ProjectNotes", False),
        ("arn:aws:execute-api:us-east-1:123456789012:table/ProjectNotes", False),
    ],
)
def test_read_scope_needs_an_identified_resource(tmp_path, gate, scope, data):
    tools = _name_only_tools()
    refs = [tool.bom_ref for tool in tools]
    if gate == "agent":
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
    code, finding = _verdict(tmp_path, owner, *tools)
    assert (code, finding["severity"]) == ((0, "high") if data else (1, "critical"))
    if data:
        assert "enforcement is unverified" in finding["summary"]
