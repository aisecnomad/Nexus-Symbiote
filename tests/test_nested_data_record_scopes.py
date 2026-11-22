"""Check bounded data records and the default CLI gate on ambiguous read grants."""

import pytest

from nexus_symbiote.core.models import AuthorizationRecord
from tests.test_trifecta_and_toxic_flows import _name_only_tools
from tests.test_trifecta_declared_scope import _gated_owner, _verdict


@pytest.mark.parametrize(
    ("scope", "severity"),
    [
        ("table:sales.2024", "high"),
        ("table:sales.2024.07", "high"),
        ("table:warehouse.quarter.03", "high"),
        ("kb:docs/2024", "high"),
        ("kb:docs/2024/07", "high"),
        ("kb:docs/2024/*", "high"),
        ("kb:docs/readme.md", "high"),
        ("KB:guides/getting-started.MARKDOWN", "high"),
        ("kb:docs/2024/report.csv", "high"),
        ("kb:研究/結果.txt", "high"),
        ("kb:guides/account-notes.pdf", "high"),
        ("table:all", "critical"),
        ("table:everybody", "critical"),
        ("table:any-thing", "critical"),
        ("table:allResources", "critical"),
        ("table:𝙖𝙡𝙡", "critical"),
        ("table:everyth1ng", "critical"),
        ("table:aII", "critical"),
        ("table:gIobal", "critical"),
        ("table:Ꭺll", "critical"),
        ("kb:docs/w3b", "critical"),
        ("kb:docs/egre55", "critical"),
        ("kb:docs/pub1ic", "critical"),
        ("kb:docs/ꮃeb", "critical"),
        ("kb:docs/ргоху", "critical"),
        ("kb:docs/readme.md/", "critical"),
        ("table:server", "critical"),
        ("table:customers", "high"),
        ("table:allOrderGroups", "critical"),
        ("table:any-workspace", "critical"),
        ("table:allhosts", "critical"),
        ("kb:docs/api-gateway", "critical"),
        ("kb:docs/remoteProxy", "critical"),
        ("table:alloy", "high"),
        ("kb:docs/network-guide.md", "high"),
        ("table:global", "critical"),
        ("table:world", "critical"),
        ("table:unrestricted", "critical"),
        ("kb:public", "critical"),
        ("kb:guides/public", "critical"),
        ("kb:guides/server", "critical"),
        ("kb:guides/proxies", "critical"),
        ("kb:guides/domain", "critical"),
        ("kb:guides/socket", "critical"),
        ("kb:guides/tcp", "critical"),
        ("kb:guides/ssh", "critical"),
        ("kb:guides/webhook", "critical"),
        ("kb:guides/instance-data", "critical"),
        ("kb:guides/metadata.json", "critical"),
        ("kb:guides/all.md", "critical"),
        ("kb:guides/docs.example", "critical"),
        ("kb:guides/file.md/*", "critical"),
        ("kb:guides/.md", "critical"),
        ("kb:docs/../report.md", "critical"),
        ("kb:docs/over\u200bview.md", "critical"),
        ("kb:docs/*/readme.md", "critical"),
        ("kb:docs/report?.md", "critical"),
        ("kb:docs/version[12].txt", "critical"),
        ("kb:docs/**", "critical"),
        ("kb:docs/report.md/topics", "critical"),
        ("kb:2024", "critical"),
        ("table:42", "critical"),
        ("table:public.users", "high"),
        ("table:warehouse.internal", "high"),
        ("docs/readme.md", "critical"),
        ("sales.2024", "critical"),
        ("docs/2024", "critical"),
        ("kb:*/2024", "critical"),
        ("table:*.2024", "critical"),
        ("kb:docs/../2024", "critical"),
    ],
)
def test_resource_scope_in_default_cli(tmp_path, scope, severity):
    tools = _name_only_tools()
    owner = _gated_owner([tool.bom_ref for tool in tools])
    owner.authorizations.append(
        AuthorizationRecord(
            principal="reader", action="read", resource_scope=scope, approval_required=False
        )
    )
    code, finding = _verdict(tmp_path, owner, *tools)
    assert finding["severity"] == severity
    assert code == int(severity == "critical")
    if severity == "high":
        assert "enforcement is unverified" in finding["summary"]
