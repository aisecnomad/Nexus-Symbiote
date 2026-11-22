"""Adversarial regression tests for PR #325 read-scope classification bypasses."""

from __future__ import annotations

import pytest

from nexus_symbiote.core.models import AuthorizationRecord
from nexus_symbiote.trifecta import _independent_read


@pytest.mark.parametrize(
    "scope",
    [
        "kb:\u03f2loud",
        "table:áll_buckets",
        "kb:wéb_api",
        "table:ᴀll",
        "table:ɢlobal",
        "kb:ʜttp",
        "kb:ɪnternet",
        "table:al\u04c0",
        "table:read_all",
        "table:select_any",
        "table:query_everything",
        "kb:access_global",
        "kb:data_unrestricted",
        "table:tenant_wildcard",
    ],
)
def test_adversarial_read_scopes_keep_critical_trifecta_retention(scope: str) -> None:
    record = AuthorizationRecord(
        principal="reader",
        action="read",
        resource_scope=scope,
        approval_required=False,
    )
    assert _independent_read(record) is False


@pytest.mark.parametrize(
    "scope",
    [
        "table:public.users",
        "table:hr.internal",
        "table:sales.net",
        "table:bücher.orders",
        "kb:資料/調査/*",
    ],
)
def test_legitimate_qualified_and_international_scopes_remain_accepted(scope: str) -> None:
    record = AuthorizationRecord(
        principal="reader",
        action="read",
        resource_scope=scope,
        approval_required=False,
    )
    assert _independent_read(record) is True
