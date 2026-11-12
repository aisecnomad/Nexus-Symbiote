"""Untrusted A2A cards must preserve anonymous authentication alternatives."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.a2a import A2AScanner


def _scan(root: Path, declaration: dict):
    (root / "agent-card.json").write_text(
        json.dumps(
            {
                "name": "test-agent",
                "url": "https://agent.example.com",
                "skills": ["search"],
                **declaration,
            }
        )
    )
    return A2AScanner().scan(root)


@pytest.mark.parametrize(
    ("declaration", "required"),
    [
        ({}, False),
        ({"security": []}, False),
        ({"security": [{}]}, False),
        ({"security": [{"bearer": []}, {}]}, False),
        ({"security": [{}, {"bearer": []}]}, False),
        ({"security": [{"bearer": []}]}, True),
        ({"security": [{"oauth": ["read"]}, {"api-key": [], "mtls": []}]}, True),
        ({"authentication": {"schemes": []}}, False),
        ({"authentication": {"schemes": ["bearer"]}}, True),
        ({"security": [{}], "authentication": {"schemes": ["bearer"]}}, False),
        ({"security": [], "authentication": {"schemes": ["bearer"]}}, False),
    ],
)
def test_declared_authentication_semantics(tmp_path, declaration, required):
    result = _scan(tmp_path, declaration)
    assert not result.scan_failures
    server = result.components[0]
    assert server.authentication_required is required
    assert any(risk.category == "authentication" for risk in server.risks) is not required
    assert server.properties["authentication_evidence"] == "declaration-only"


@pytest.mark.parametrize(
    "declaration",
    [
        {"security": None},
        {"security": True},
        {"security": {"bearer": []}},
        {"security": ["bearer"]},
        {"security": [None]},
        {"security": [{"": []}]},
        {"security": [{"bearer": "read"}]},
        {"security": [{"bearer": [False]}]},
        {"security": [{"bearer": [""]}]},
        {"security": [{}, {"bearer": "read"}]},
        {"security": [{}] * 1001},
        {"security": [{"bearer": ["scope"] * 1001}]},
        {"authentication": {"schemes": "bearer"}},
        {"authentication": {"schemes": [False]}},
        {"authentication": {"schemes": [""]}},
        {"authentication": {"unknown": True}},
    ],
)
def test_malformed_authentication_is_a_collection_gap(tmp_path, declaration):
    result = _scan(tmp_path, declaration)
    assert result.scan_failures
    assert not result.components


def test_anonymous_alternative_changes_inventory_and_triggers_drift(tmp_path):
    before = AIBOM(components=_scan(tmp_path, {"security": [{"bearer": []}]}).components)
    after = AIBOM(components=_scan(tmp_path, {"security": [{"bearer": []}, {}]}).components)

    report = AIBOMDiffer().diff(before, after)

    assert report.security_alerts
    assert any("authentication_required" in alert["alert"] for alert in report.security_alerts)
