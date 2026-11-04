"""A redacted A2A inventory must not silently accept changed source declarations."""

from __future__ import annotations

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.validators.completeness import CompletenessValidator

KEY = "a2a-test-operator-key-which-is-at-least-32-characters"


def _card():
    return {
        "name": "reviewed-agent",
        "version": "1.0.0",
        "url": "https://agent.example/read-only",
        "security": [{"bearer": []}],
        "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
        "skills": [{"name": "read"}],
    }


def _scan(runner, project, output):
    result = runner.invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(output)])
    assert result.exit_code == 0, result.output
    return AIBOM.load(output)


def _a2a_issues(bom, project):
    refs = {component.bom_ref for component in bom.components}
    report = CompletenessValidator().validate_against_project(bom, project)
    return [issue for issue in report.issues if issue.surface == "a2a" or issue.surface in refs]


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("url", "https://agent.example/admin"),
        ("url", "https://agent.example/read-only?tenant=other"),
        ("security", [{"apiKey": []}]),
        ("security", [{"bearer": ["admin"]}]),
        ("securitySchemes", {"bearer": {"type": "http", "scheme": "basic"}}),
    ],
)
def test_changed_card_denies_cli_drift_and_project_risk(tmp_path, monkeypatch, field, value):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    project.mkdir()
    path = project / "agent.json"
    card = _card()
    path.write_text(json.dumps(card))
    runner = CliRunner()
    before = tmp_path / "before.json"
    after = tmp_path / "after.json"
    _scan(runner, project, before)
    args = ["risk", str(before), "--project", str(project), "--no-project-policy"]
    assert runner.invoke(main, args).exit_code == 0

    path.write_text(json.dumps({**card, field: value}))
    _scan(runner, project, after)
    drift = runner.invoke(main, ["diff", str(before), str(after), "--fail-on-alert"])
    assert drift.exit_code == 1, drift.output
    assert "A2A source binding changed" in drift.output
    risk = runner.invoke(main, args)
    assert risk.exit_code == 1, risk.output
    assert "Missing or mismatched local component" in risk.output


def test_client_hidden_path_and_credential_changes_are_bound_without_export(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    path = tmp_path / "a2a.json"

    def collect(url):
        path.write_text(json.dumps({"clients": [{"name": "remote", "url": url}]}))
        result = A2AScanner().scan(tmp_path)
        assert not result.scan_failures and not result.surfaces_excluded
        assert "CANARY" not in repr(result) and KEY not in repr(result)
        assert result.components[0].agent_card_url == "https://agent.example"
        return AIBOM(components=result.components)

    old = collect("https://user:CANARY-A@agent.example/private/CANARY?token=CANARY")
    for url in (
        "https://user:CANARY-A@agent.example/admin/CANARY?token=CANARY",
        "https://user:CANARY-B@agent.example/private/CANARY?token=CANARY",
    ):
        new = collect(url)
        assert AIBOMDiffer().diff(old, new).security_alerts
        assert _a2a_issues(old, tmp_path)


def test_unkeyed_collection_and_same_snapshot_diff_fail_closed(tmp_path, monkeypatch):
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)
    (tmp_path / "agent.json").write_text(json.dumps(_card()))
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded
    component = result.components[0]
    assert "a2a_source_binding" not in component.properties
    bom = AIBOM(components=[component])
    assert AIBOMDiffer().diff(bom, bom).security_alerts
    assert _a2a_issues(bom, tmp_path)
    run = CliRunner().invoke(main, ["scan", str(tmp_path), "--no-project-policy"])
    assert run.exit_code == 1, run.output


@pytest.mark.parametrize("mutation", ["missing", "profile", "mac", "key-id"])
def test_legacy_and_incompatible_binding_require_recollection(tmp_path, monkeypatch, mutation):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    (tmp_path / "agent.json").write_text(json.dumps(_card()))
    result = A2AScanner().scan(tmp_path)
    bom = AIBOM(components=result.components)
    previous = bom.model_copy(deep=True)
    properties = previous.components[0].properties
    if mutation == "missing":
        properties.clear()
        properties["collection_mode"] = "static-agent-card"
    elif mutation == "profile":
        properties["a2a_source_binding_profile"] = "unknown"
    elif mutation == "mac":
        properties["a2a_source_binding"] = "not-a-mac"
    else:
        properties["a2a_source_binding_key_id"] = None
    assert AIBOMDiffer().diff(previous, bom).security_alerts
    assert _a2a_issues(previous, tmp_path)


def test_key_loss_rotation_and_canonical_object_order(tmp_path, monkeypatch):
    path = tmp_path / "agent.json"
    card = _card()
    path.write_text(json.dumps(card))
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    original = A2AScanner().scan(tmp_path)
    path.write_text(json.dumps(dict(reversed(list(card.items()))), indent=4))
    reordered = A2AScanner().scan(tmp_path)
    old = AIBOM(components=original.components)
    assert not AIBOMDiffer().diff(old, AIBOM(components=reordered.components)).has_changes
    assert not _a2a_issues(old, tmp_path)
    for key in ("another-operator-key-that-is-at-least-32-characters", ""):
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
        new = AIBOM(components=A2AScanner().scan(tmp_path).components)
        assert AIBOMDiffer().diff(old, new).security_alerts
        assert _a2a_issues(old, tmp_path)


def test_short_binding_key_is_a_safe_collection_failure(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "CANARY-short")
    (tmp_path / "agent.json").write_text(json.dumps(_card()))
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures and not result.components
    assert "CANARY" not in repr(result)


@pytest.mark.parametrize("security", [[], [{}], [{"bearer": []}, {}]])
def test_anonymous_security_alternative_does_not_claim_authentication(tmp_path, security):
    (tmp_path / "agent.json").write_text(json.dumps({**_card(), "security": security}))
    component = A2AScanner().scan(tmp_path).components[0]
    assert component.authentication_required is False
    assert any(r.category == "authentication" for r in component.risks)


@pytest.mark.parametrize("security", [{"bearer": []}, ["bearer"], [{"bearer": "admin"}]])
def test_malformed_security_requirements_are_collection_failures(tmp_path, security):
    (tmp_path / "agent.json").write_text(json.dumps({**_card(), "security": security}))
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures and not result.components
