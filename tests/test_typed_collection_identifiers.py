"""Compare explicit data namespaces with untyped and unbounded read scopes."""

import pytest

from nexus_symbiote.core.models import AuthorizationRecord
from tests.test_trifecta_and_toxic_flows import _name_only_tools
from tests.test_trifecta_declared_scope import _gated_owner, _verdict


@pytest.mark.parametrize(
    ("scope", "bounded"),
    [
        ("table:sales.net", True),
        ("table:sales.local", True),
        ("TABLE:analytics.public", True),
        ("table:sales.cOM", True),
        ("table:warehouse.int", True),
        ("table:hr.internal", True),
        ("table:2024_sales", True),
        ("table:bücher.orders", True),
        ("table:aLL", False),
        ("table:reports.a-ll", False),
        ("table:reports.everyone", False),
        ("table:_", False),
        ("table:*.rows", False),
        ("table:reports/rows", False),
        ("sales.net", False),
        ("customers/*", False),
        ("KB:données/reports/*", True),
        ("kb:資料/調査/*", True),
        ("kb:project-2/notes", True),
        ("kb:eGRESS", False),
        ("kb:project/a-ll", False),
        ("kb:project/metadata", False),
        ("kb:project/hosts", False),
        ("kb:project/urls", False),
        ("kb:project/ԝеb", False),
        ("kb:project/ᴡᴇʙ", False),
        ("kb:project/mẹtadata", False),
        ("kb:aLl1", False),
        ("kb:project/localhost6", False),
        ("kb:project/notes.example", False),
        ("kb:project/*/topic", False),
        ("kb:_", False),
    ],
)
def test_typed_collection_controls_the_cli_verdict(tmp_path, scope, bounded):
    tools = _name_only_tools()
    owner = _gated_owner([t.bom_ref for t in tools])
    owner.authorizations.append(
        AuthorizationRecord(
            principal="reader", action="read", resource_scope=scope, approval_required=False
        )
    )
    code, finding = _verdict(tmp_path, owner, *tools)
    assert (code, finding["severity"]) == ((0, "high") if bounded else (1, "critical"))
    if bounded:
        assert "enforcement is unverified" in finding["summary"]
