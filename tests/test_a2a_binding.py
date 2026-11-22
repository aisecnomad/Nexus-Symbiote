"""A2A records must bind endpoint paths and required scopes without exporting the paths."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import A2AClientComponent, A2AServerComponent
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners import mcp
from nexus_symbiote.scanners.a2a import (
    CARD_STRUCTURE_PROFILE,
    CARD_VALUE_BINDING_PROFILE,
    CLIENT_STRUCTURE_PROFILE,
    CLIENT_VALUE_BINDING_PROFILE,
    A2AScanner,
)
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.validators.completeness import CompletenessValidator

KEY = "k" * 40

CARD: dict[str, Any] = {
    "name": "billing-agent",
    "version": "1.0.0",
    "url": "https://agents.example.com/trusted",
    "protocols": ["a2a/0.3"],
    "securitySchemes": {
        "oauth": {
            "type": "oauth2",
            "flows": {
                "clientCredentials": {
                    "tokenUrl": "https://auth.example.com/token",
                    "scopes": {"read:only": "Read-only access"},
                }
            },
        }
    },
    "security": [{"oauth": ["read:only"]}],
    "skills": [{"id": "lookup", "name": "lookup-invoice"}],
}


def _write_card(root: Path, card: dict[str, Any]) -> None:
    (root / ".well-known").mkdir(parents=True, exist_ok=True)
    (root / ".well-known" / "agent.json").write_text(json.dumps(card))


def _server(root: Path, card: dict[str, Any]) -> A2AServerComponent:
    _write_card(root, card)
    result = A2AScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    (server,) = [c for c in result.components if isinstance(c, A2AServerComponent)]
    return server


def _client(root: Path, client: dict[str, Any]) -> A2AClientComponent:
    root.mkdir(parents=True, exist_ok=True)
    (root / "a2a.json").write_text(json.dumps({"clients": [client]}))
    result = A2AScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    (component,) = [c for c in result.components if isinstance(c, A2AClientComponent)]
    return component


def _failures(root: Path, card: dict[str, Any]) -> list[str]:
    _write_card(root, card)
    result = A2AScanner().scan(root)
    assert not any(isinstance(c, A2AServerComponent) for c in result.components)
    return result.scan_failures


def _scan(project: Path, output: Path) -> str:
    run = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
    )
    assert run.exit_code == 0, run.output
    return output.read_text()


def _drift(tmp_path: Path, before: dict[str, Any], after: dict[str, Any]):
    project = tmp_path / "project"
    _write_card(project, before)
    first = _scan(project, tmp_path / "before.json")
    _write_card(project, after)
    second = _scan(project, tmp_path / "after.json")
    run = CliRunner().invoke(
        main,
        [
            "diff",
            str(tmp_path / "before.json"),
            str(tmp_path / "after.json"),
            "--json-output",
            "--fail-on-alert",
        ],
    )
    return run, first + second


UNBOUND_ALERT = (
    "Values are unbound in one snapshot without the binding key; a change to them is "
    "undetectable and no value is recorded. Set NEXUS_SYMBIOTE_SOURCE_BINDING_KEY during both "
    "collections."
)


def _assert_unchanged(run: Any) -> None:
    """The only alert on an unchanged card is that values are unbound without the key."""
    alerts = json.loads(run.stdout)["security_alerts"]
    assert all(
        alert["severity"] == "medium" and UNBOUND_ALERT in alert["alert"] for alert in alerts
    ), alerts
    assert run.exit_code == (1 if alerts else 0), run.output


def _moved(card: dict[str, Any]) -> dict[str, Any]:
    return {**card, "url": "https://agents.example.com/attacker"}


def _scoped(card: dict[str, Any], scope: str) -> dict[str, Any]:
    scoped = copy.deepcopy(card)
    scoped["securitySchemes"]["oauth"]["flows"]["clientCredentials"]["scopes"] = {scope: "Access"}
    scoped["security"] = [{"oauth": [scope]}]
    return scoped


def _token_url(card: dict[str, Any], url: str) -> dict[str, Any]:
    changed = copy.deepcopy(card)
    changed["securitySchemes"]["oauth"]["flows"]["clientCredentials"]["tokenUrl"] = url
    return changed


AZURE_APP = "api://11111111-2222-3333-4444-555555555555"


@pytest.mark.parametrize(
    ("before", "after"),
    [
        ("read:only", "admin"),
        # Scope URIs name the permission in their path (RFC 6749 section 3.3 tokens).
        (
            "https://www.googleapis.com/auth/drive.readonly",
            "https://www.googleapis.com/auth/cloud-platform",
        ),
        (f"{AZURE_APP}/access_as_user", f"{AZURE_APP}/admin"),
        ("https://graph.microsoft.com/User.Read", "https://graph.microsoft.com/Mail.ReadWrite"),
    ],
)
def test_required_scope_change_fails_the_drift_gate_without_a_key(tmp_path, before, after):
    run, boms = _drift(tmp_path, _scoped(CARD, before), _scoped(CARD, after))
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert any(
        alert["severity"] == "high" and "capabilities changed" in alert["alert"] for alert in alerts
    ), alerts
    baseline = json.loads((tmp_path / "before.json").read_text())
    (server,) = [c for c in baseline["components"] if c["component_type"] == "a2a-server"]
    assert server["capabilities"]["oauth_scopes"] == [before]
    assert server["properties"]["security_scheme_types"] == ["oauth2"]
    assert not any("OAuth scopes" in risk["detail"] for risk in server["risks"])


def test_same_origin_path_change_fails_the_drift_gate_with_a_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    run, boms = _drift(tmp_path, CARD, _moved(CARD))
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert any("billing-agent" in alert["alert"] for alert in alerts), alerts
    assert "trusted" not in boms and "attacker" not in boms
    assert "auth.example.com/token" not in boms and KEY not in boms


def test_without_a_key_the_path_is_neither_exported_nor_digested_but_marked_unbound(tmp_path):
    first = _server(tmp_path / "a", CARD)
    moved = _server(tmp_path / "b", _moved(CARD))
    assert first.endpoint_url == "https://agents.example.com"
    assert first.properties["source_values_bound"] is False
    assert "static_value_binding" not in first.properties
    # An unkeyed digest that changed with the path would let anyone confirm guesses.
    assert first.properties["static_card_hash"] == moved.properties["static_card_hash"]
    (gap,) = [r for r in first.risks if r.category == "completeness"]
    assert gap.severity == "low" and "endpoint URL beyond its exported origin" in gap.detail
    assert SOURCE_BINDING_KEY_ENV in gap.recommendation
    assert "trusted" not in first.model_dump_json()
    origin_only = _server(tmp_path / "c", {**CARD, "url": "https://agents.example.com/"})
    assert origin_only.properties["source_values_bound"] is False
    assert not any("endpoint URL" in r.detail for r in origin_only.risks)


def test_keyed_binding_ignores_key_order_and_whitespace(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    first = _server(tmp_path / "a", CARD)
    reordered = tmp_path / "b" / ".well-known"
    reordered.mkdir(parents=True)
    (reordered / "agent.json").write_text(json.dumps(CARD, indent=4, sort_keys=True))
    result = A2AScanner().scan(tmp_path / "b")
    (second,) = result.components
    for key in ("static_value_binding", "static_value_binding_key_id", "static_card_hash"):
        assert first.properties[key] == second.properties[key]
    assert first.properties["static_value_binding_profile"] == CARD_VALUE_BINDING_PROFILE
    assert first.properties["source_values_bound"] is True
    assert not any(r.category == "completeness" for r in first.risks)


def test_card_client_and_mcp_bindings_are_domain_separated(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    shared = {"name": "same", "url": "https://agents.example.com/same"}
    card = _server(tmp_path / "card", shared)
    client = _client(tmp_path / "client", shared)
    mcp_binding = mcp._value_binding(shared)
    assert mcp_binding is not None
    macs = {
        card.properties["static_value_binding"],
        client.properties["static_value_binding"],
        mcp_binding[0],
    }
    assert len(macs) == 3
    # One operator key has one identifier across collectors.
    assert card.properties["static_value_binding_key_id"] == mcp_binding[1]
    assert client.properties["static_value_binding_key_id"] == mcp_binding[1]


def test_short_binding_key_is_a_scan_failure(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "too-short")
    failures = _failures(tmp_path, CARD)
    assert failures == [
        f".well-known/agent.json: {SOURCE_BINDING_KEY_ENV} must contain at least 32 characters"
    ]
    (tmp_path / "a2a.json").write_text(json.dumps({"clients": [{"name": "c"}]}))
    assert any("a2a.json" in failure for failure in A2AScanner().scan(tmp_path).scan_failures)


def test_validation_with_the_key_rejects_a_baseline_after_a_path_change(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    _write_card(project, CARD)
    # Integrity validation needs at least one verifiable descriptor in the inventory.
    tool = {"name": "read_file", "description": "Read a file", "inputSchema": {"type": "object"}}
    server = {"command": "npx", "args": ["trusted-tool@1.2.3"], "tools": [tool]}
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"local": server}}))
    baseline = tmp_path / "baseline.json"
    _scan(project, baseline)
    validate = ["validate", "--no-project-policy", str(baseline), "--project", str(project)]
    unchanged = CliRunner().invoke(main, validate)
    assert unchanged.exit_code == 0, unchanged.output
    _write_card(project, _moved(CARD))
    run = CliRunner().invoke(main, validate)
    assert run.exit_code == 1, run.output
    assert "a2a-server:billing-agent" in run.output


def test_keyed_baseline_fails_reconciliation_without_its_key(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    _write_card(project, {**CARD, "url": "https://agents.example.com"})
    baseline = tmp_path / "baseline.json"
    _scan(project, baseline)
    bom = AIBOM.load(baseline)
    assert CompletenessValidator().validate_against_project(bom, project).is_complete
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV)
    report = CompletenessValidator().validate_against_project(bom, project)
    assert not report.is_complete
    assert any("a2a-server:billing-agent" in issue.description for issue in report.issues)
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "j" * 40)
    assert not CompletenessValidator().validate_against_project(bom, project).is_complete


@pytest.mark.parametrize("profile", ["v1", "v2", "v3"])
def test_snapshot_with_the_superseded_card_profile_fails_reconciliation(tmp_path, profile):
    project = tmp_path / "project"
    _write_card(project, {**CARD, "url": "https://agents.example.com"})
    baseline = tmp_path / "baseline.json"
    _scan(project, baseline)
    bom = AIBOM.load(baseline)
    assert CompletenessValidator().validate_against_project(bom, project).is_complete
    (server,) = [c for c in bom.components if isinstance(c, A2AServerComponent)]
    server.properties["static_card_hash_profile"] = f"nexus-symbiote/a2a-card-structure/{profile}"
    report = CompletenessValidator().validate_against_project(bom, project)
    assert any("a2a-server:billing-agent" in issue.description for issue in report.issues)


def test_client_card_url_path_change_is_bound_by_the_key(tmp_path, monkeypatch):
    before = {"name": "planner", "agentCardUrl": "https://agents.example.com/trusted/card.json"}
    after = {**before, "agentCardUrl": "https://agents.example.com/attacker/card.json"}
    unkeyed = _client(tmp_path / "a", before)
    assert unkeyed.agent_card_url == "https://agents.example.com"
    assert unkeyed.properties["source_values_bound"] is False
    assert any(r.severity == "low" and r.category == "completeness" for r in unkeyed.risks)
    assert "trusted" not in unkeyed.model_dump_json()
    assert (
        unkeyed.properties["static_config_hash"]
        == _client(tmp_path / "b", after).properties["static_config_hash"]
    )
    well_known = _client(
        tmp_path / "c",
        {**before, "agentCardUrl": "https://agents.example.com/.well-known/agent.json"},
    )
    assert not any(r.category == "completeness" for r in well_known.risks)
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    old, new = _client(tmp_path / "d", before), _client(tmp_path / "e", after)
    assert old.properties["static_value_binding_profile"] == CLIENT_VALUE_BINDING_PROFILE
    report = AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new]))
    assert [alert["component"] for alert in report.security_alerts] == ["a2a-client:planner"]
    assert "trusted" not in old.model_dump_json() and "attacker" not in new.model_dump_json()


@pytest.mark.parametrize(
    ("security", "required"),
    [
        ([{}], False),
        ([{"oauth": ["read:only"]}, {}], False),
        ([], False),
        ([{"undeclared": []}], False),
        ([{"oauth": ["read:only"], "undeclared": []}], False),
        ([{"oauth": ["read:only"]}], True),
        ([{"oauth": []}, {"oauth": ["read:only"]}], True),
    ],
)
def test_authentication_is_required_only_when_every_alternative_names_declared_schemes(
    tmp_path, security, required
):
    server = _server(tmp_path, {**CARD, "security": security})
    assert server.authentication_required is required
    medium = [r for r in server.risks if r.category == "authentication"]
    assert [r.severity for r in medium] == ([] if required else ["medium"])


@pytest.mark.parametrize(
    ("authentication", "security", "required"),
    [
        ({"schemes": ["bearer"]}, None, True),
        ({"schemes": []}, None, False),
        ({}, None, False),
        ({"schemes": ["none"]}, None, False),
        ({"schemes": ["Anonymous", " public "]}, None, False),
        ({"schemes": ["bearer"]}, [{}], False),
        # A card that uses the 0.3 declarations is decided by them alone.
        ({"schemes": []}, [{"oauth": []}], True),
    ],
)
def test_legacy_authentication_needs_nonempty_schemes(tmp_path, authentication, security, required):
    card = {**CARD, "authentication": authentication}
    card.pop("security")
    card.pop("securitySchemes")
    if security is not None:
        card["securitySchemes"] = CARD["securitySchemes"]
        card["security"] = security
    assert _server(tmp_path, card).authentication_required is required


@pytest.mark.parametrize(
    ("change", "drop_schemes"),
    [
        # Clients of a card with securitySchemes do not read the earlier object.
        ({}, False),
        ({"supportedInterfaces": [{"url": "https://a.example"}]}, True),
    ],
)
def test_legacy_authentication_does_not_decide_for_current_cards(tmp_path, change, drop_schemes):
    card = {**CARD, "authentication": {"schemes": ["bearer"]}, **change}
    card.pop("security")
    if drop_schemes:
        card.pop("securitySchemes")
    server = _server(tmp_path, card)
    assert server.authentication_required is False
    assert [r.severity for r in server.risks if r.category == "authentication"] == ["medium"]


@pytest.mark.parametrize("kind", ["none", "x-custom", "Anonymous"])
def test_scheme_of_unknown_type_does_not_count_as_authentication(tmp_path, kind):
    card = copy.deepcopy(CARD)
    card["securitySchemes"] = {"anon": {"type": kind}}
    card["security"] = [{"anon": []}]
    server = _server(tmp_path, card)
    assert server.authentication_required is False
    assert server.properties["security_scheme_types"] == ["other"]


@pytest.mark.parametrize(
    ("methods", "flagged"),
    [
        (["none"], True),
        ({"enabled": False}, True),
        ({"bearer": True, "apiKey": False}, False),
        (["api-key"], False),
    ],
)
def test_client_authentication_methods_are_read_by_value(tmp_path, methods, flagged):
    client = _client(
        tmp_path, {"name": "c", "agentCardUrl": "https://a.example", "authMethods": methods}
    )
    assert any(r.category == "authentication" for r in client.risks) is flagged


@pytest.mark.parametrize(
    "change",
    [
        {"security": {"oauth": ["read:only"]}},
        {"security": [["oauth"]]},
        {"security": [{"oauth": "read:only"}]},
        {"security": [{"oauth": [1]}]},
        {"security": [{"oauth": [f"s{i}" for i in range(1001)]}]},
        {"security": [{f"s{i}": [] for i in range(1001)}]},
        {"securitySchemes": []},
        {"securitySchemes": {"oauth": "oauth2"}},
        {"securitySchemes": {"oauth": {"type": 2}}},
        {"securitySchemes": {f"s{i}": {} for i in range(1001)}},
        {"authentication": ["bearer"]},
        {"authentication": {"schemes": "bearer"}},
        {"authentication": {"schemes": [None]}},
    ],
)
def test_malformed_security_declarations_are_scan_failures(tmp_path, change):
    assert _failures(tmp_path, {**CARD, **change}) == [
        ".well-known/agent.json: invalid A2A card field types"
    ]


def test_scheme_types_map_onto_a_fixed_set_and_scopes_are_redacted(tmp_path):
    secret = "ghp_" + "a" * 36
    card = copy.deepcopy(CARD)
    card["securitySchemes"].update(
        {"key": {"type": "apiKey"}, "custom": {"type": f"x-{secret}"}, "bare": {}}
    )
    card["security"] = [{"oauth": [f"token={secret}", "read:only"], "key": []}]
    server = _server(tmp_path, card)
    assert server.properties["security_scheme_types"] == ["apiKey", "oauth2", "other"]
    assert server.capabilities is not None
    assert "read:only" in server.capabilities.oauth_scopes
    assert secret not in server.model_dump_json()


@pytest.mark.parametrize(
    "change",
    [
        # SDK serializers that keep None fields emit these shapes.
        {"securitySchemes": None, "security": None},
        {"securitySchemes": None},
        {"authentication": {"schemes": None}, "security": None},
        {"authentication": {"schemes": [""]}, "security": None},
        {"authentication": {"schemes": [" "]}, "security": None},
        # A referenced scheme must declare a type to count as authentication.
        {"securitySchemes": {"oauth": {}}, "security": [{"oauth": []}]},
        {"securitySchemes": {"oauth": {"type": None}}, "security": [{"oauth": []}]},
        {"securitySchemes": {"oauth": {"type": ""}}, "security": [{"oauth": []}]},
    ],
)
def test_null_empty_and_typeless_declarations_are_not_authentication(tmp_path, change):
    server = _server(tmp_path, {**CARD, **change})
    assert server.authentication_required is False
    assert [r.severity for r in server.risks if r.category == "authentication"] == ["medium"]


def test_only_oauth_scopes_are_exported_and_secret_shaped_values_are_withheld(
    tmp_path, monkeypatch
):
    pat = "ghp_" + "b" * 36
    jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.c2lnbmF0dXJlc2lnbmF0dXJl"
    card = copy.deepcopy(CARD)
    card["securitySchemes"]["key"] = {"type": "apiKey", "in": "header", "name": "X-Key"}
    card["security"] = [
        {"oauth": ["read:only", jwt, "https://x.example/s?api_key=v"], "key": [pat]}
    ]
    server = _server(tmp_path / "a", card)
    assert server.capabilities is not None
    assert server.capabilities.oauth_scopes == ["***", "https://x.example", "read:only"]
    exported = server.model_dump_json()
    assert pat not in exported and jwt not in exported and "api_key=v" not in exported
    (gap,) = [r for r in server.risks if r.category == "completeness"]
    assert gap.detail.endswith("; redacted OAuth scopes.") and "role names" not in gap.detail
    role_changed = copy.deepcopy(card)
    role_changed["security"][0]["key"] = ["ghp_" + "c" * 36]
    unkeyed = _server(tmp_path / "b", role_changed)
    # Without a key the structure digest still detects the changed requirement value.
    assert unkeyed.properties["static_card_hash"] != server.properties["static_card_hash"]
    assert "ghp_" not in unkeyed.model_dump_json()
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    keyed, rekeyed = _server(tmp_path / "c", card), _server(tmp_path / "d", role_changed)
    assert keyed.properties["static_value_binding"] != rekeyed.properties["static_value_binding"]
    assert not any(r.category == "completeness" for r in keyed.risks)


def test_credential_endpoint_host_change_fails_the_drift_gate_without_a_key(tmp_path):
    run, boms = _drift(tmp_path, CARD, _token_url(CARD, "https://evil.example.net/steal"))
    assert run.exit_code == 1, run.output
    assert any("billing-agent" in a["alert"] for a in json.loads(run.stdout)["security_alerts"])
    assert "auth.example.com/token" not in boms and "evil.example.net/steal" not in boms
    baseline = json.loads((tmp_path / "before.json").read_text())
    (server,) = [c for c in baseline["components"] if c["component_type"] == "a2a-server"]
    assert server["properties"]["security_scheme_origins"] == ["https://auth.example.com"]
    (gap,) = [r for r in server["risks"] if r["category"] == "completeness"]
    assert "security scheme URLs beyond their exported origins" in gap["detail"]


def test_additional_interface_urls_export_origins_and_mark_paths_unbound(tmp_path):
    interface = {"url": "https://grpc.example.com/secret-path", "transport": "GRPC"}
    card = {**_token_url(CARD, "https://auth.example.com"), "url": "https://agents.example.com"}
    server = _server(tmp_path / "a", {**card, "additionalInterfaces": [interface]})
    assert server.properties["additional_interface_origins"] == ["https://grpc.example.com"]
    assert server.properties["security_scheme_origins"] == ["https://auth.example.com"]
    (gap,) = [r for r in server.risks if r.category == "completeness"]
    assert gap.detail.endswith(
        "values not bound in this inventory: additional interface URLs beyond their exported "
        "origins."
    )
    assert "secret-path" not in server.model_dump_json()
    moved = _server(
        tmp_path / "b",
        {**card, "additionalInterfaces": [{**interface, "url": "https://evil.example.net"}]},
    )
    assert moved.properties["additional_interface_origins"] == ["https://evil.example.net"]
    relative = _server(tmp_path / "c", {**card, "additionalInterfaces": [{"url": "/trusted"}]})
    assert any("additional interface" in r.detail for r in relative.risks)
    assert "trusted" not in relative.model_dump_json()
    plain = _server(tmp_path / "d", card)
    assert plain.properties["additional_interface_origins"] == []
    assert not any(r.category == "completeness" for r in plain.risks)


def test_backslash_authority_is_not_exported_as_an_origin(tmp_path):
    hidden = "SecretPathToken123"
    server = _server(tmp_path / "a", {**CARD, "url": f"https://agents.example.com\\{hidden}"})
    client = _client(tmp_path / "b", {"name": "c", "agentCardUrl": f"https://h.example\\{hidden}"})
    assert server.endpoint_url == "[redacted]" and client.agent_card_url == "[redacted]"
    for record in (server, client):
        assert hidden.lower() not in record.model_dump_json().lower()
        assert any(r.category == "completeness" for r in record.risks)


def test_client_well_known_card_path_swap_changes_the_structure_digest(tmp_path):
    hashes = set()
    for index, path in enumerate(("agent.json", "agent-card.json")):
        url = f"https://agents.example.com/.well-known/{path}"
        client = _client(tmp_path / str(index), {"name": "c", "agentCardUrl": url})
        assert not any(r.category == "completeness" for r in client.risks)
        hashes.add(client.properties["static_config_hash"])
    assert len(hashes) == 2


def test_keyed_binding_names_values_that_are_not_json(tmp_path, monkeypatch):
    client, card = tmp_path / "client", tmp_path / "card"
    client.mkdir()
    (client / "a2a.yaml").write_text("clients:\n  - name: c\n    added: 2024-01-01\n")
    _write_card(card, {**CARD, "skills": [{"name": "s", "description": "\ud800"}]})
    assert not A2AScanner().scan(client).scan_failures
    assert not A2AScanner().scan(card).scan_failures
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    for root, relative in ((client, "a2a.yaml"), (card, ".well-known/agent.json")):
        (failure,) = A2AScanner().scan(root).scan_failures
        assert failure.startswith(f"{relative}: {SOURCE_BINDING_KEY_ENV} binding needs RFC 8785")
        assert "quote YAML dates; avoid lone surrogates" in failure


def _requirement(card: dict[str, Any], kind: str | None, values: list[str]) -> dict[str, Any]:
    """Type the oauth scheme as `kind`, or drop every declaration when it is None."""
    changed = copy.deepcopy(card)
    if kind is None:
        del changed["securitySchemes"]
    else:
        changed["securitySchemes"]["oauth"]["type"] = kind
    changed["security"] = [{"oauth": values}]
    return changed


@pytest.mark.parametrize("kind", ["OAuth2", "OPENIDCONNECT", None, "apiKey", "x-custom"])
def test_requirement_value_change_fails_the_drift_gate_without_a_key(tmp_path, kind):
    before = _requirement(CARD, kind, ["read:only"])
    run, boms = _drift(tmp_path / "changed", before, _requirement(CARD, kind, ["admin"]))
    assert run.exit_code == 1, run.output
    alerts = [alert["alert"] for alert in json.loads(run.stdout)["security_alerts"]]
    scoped = kind in {"OAuth2", "OPENIDCONNECT"}
    expected = "capabilities changed" if scoped else "properties.static_card_hash changed"
    assert any(expected in alert and alert.startswith("High ") for alert in alerts), alerts
    # Only scopes are exported; other requirement values enter the unkeyed digest only.
    assert ('"read:only"' in boms) is scoped and ('"admin"' in boms) is scoped
    unchanged, _ = _drift(tmp_path / "unchanged", before, copy.deepcopy(before))
    _assert_unchanged(unchanged)


def test_scheme_types_match_the_known_types_case_insensitively(tmp_path):
    card = _requirement(CARD, "OAuth2", ["read:only"])
    card["securitySchemes"].update(
        {
            "oidc": {"type": "OpenIdConnect", "openIdConnectUrl": "https://id.example.com"},
            "mtls": {"type": "MutualTLS"},
        }
    )
    card["security"] = [{"oauth": ["read:only"], "oidc": ["openid"]}, {"mtls": []}]
    server = _server(tmp_path, card)
    assert server.properties["security_scheme_types"] == ["mutualTLS", "oauth2", "openIdConnect"]
    assert server.capabilities is not None
    assert server.capabilities.oauth_scopes == ["openid", "read:only"]
    assert server.authentication_required is True


def _with_url(kind: str, url: str) -> dict[str, Any]:
    card = copy.deepcopy(CARD)
    oauth = card["securitySchemes"]["oauth"]
    if kind == "url":
        card["url"] = url
    elif kind == "supportedInterfaces":
        del card["url"]
        card[kind] = [{"url": url, "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}]
    elif kind == "additionalInterfaces":
        card[kind] = [{"url": url, "transport": "GRPC"}]
    elif kind == "openIdConnectUrl":
        card["securitySchemes"]["oidc"] = {"type": "openIdConnect", kind: url}
    elif kind == "oauth2MetadataUrl":
        oauth[kind] = url
    elif kind == "authorizationUrl":
        oauth["flows"]["authorizationCode"] = {
            kind: url,
            "tokenUrl": "https://auth.example.com/token",
            "scopes": {},
        }
    else:
        oauth["flows"]["clientCredentials"][kind] = url
    return card


@pytest.mark.parametrize(
    "kind",
    [
        "url",
        "supportedInterfaces",
        "additionalInterfaces",
        "tokenUrl",
        "authorizationUrl",
        "refreshUrl",
        "openIdConnectUrl",
        "oauth2MetadataUrl",
    ],
)
def test_network_path_url_host_change_fails_the_drift_gate_without_a_key(tmp_path, kind):
    before = _with_url(kind, "//auth.example.com")
    run, boms = _drift(tmp_path / "moved", before, _with_url(kind, "//evil.example.net"))
    assert run.exit_code == 1, run.output
    assert '"//auth.example.com"' in boms and '"//evil.example.net"' in boms
    assert "[redacted]" not in boms
    unchanged, _ = _drift(tmp_path / "unchanged", before, copy.deepcopy(before))
    _assert_unchanged(unchanged)


@pytest.mark.parametrize(
    ("url", "origin", "unbound"),
    [
        ("//Auth.Example.com", "//auth.example.com", False),
        ("//auth.example.com:8443/", "//auth.example.com:8443", False),
        ("auth.example.com:443", "//auth.example.com:443", False),
        ("[::1]:50051", "//[::1]:50051", False),
        ("//auth.example.com/secret-path", "//auth.example.com", True),
        ("//user:secret-word@auth.example.com", "//auth.example.com", True),
        # Without an exported origin, nothing of the URL is bound without a key.
        ("//", "[redacted]", True),
        ("https://auth.example.com:99999", "[redacted]", True),
        ("//auth.example.com\\secret-path", "[redacted]", True),
    ],
)
def test_scheme_less_urls_export_their_host_and_unexported_origins_are_unbound(
    tmp_path, url, origin, unbound
):
    server = _server(tmp_path, {**_with_url("tokenUrl", url), "url": "https://agents.example.com"})
    assert server.properties["security_scheme_origins"] == [origin]
    gaps = [r.detail for r in server.risks if r.category == "completeness"]
    assert gaps == (
        [
            "A2A agent 'billing-agent' values not bound in this inventory: security scheme URLs "
            "beyond their exported origins."
        ]
        if unbound
        else []
    )
    assert "secret" not in server.model_dump_json()


@pytest.mark.parametrize("url", ["//agents.example.com", "agents.example.com:443"])
def test_scheme_less_endpoints_still_fail_the_transport_check(tmp_path, url):
    server = _server(tmp_path / "card", {**CARD, "url": url})
    assert server.endpoint_url == "//" + url.removeprefix("//")
    assert [r.severity for r in server.risks if r.category == "transport_security"] == ["high"]
    card_url = "//agents.example.com/.well-known/agent-card.json"
    client = _client(tmp_path / "client", {"name": "c", "agentCardUrl": card_url})
    assert client.agent_card_url == "//agents.example.com"
    assert not any(r.category == "completeness" for r in client.risks)
    assert [r.severity for r in client.risks if r.category == "transport_security"] == ["high"]


CARD_1_0: dict[str, Any] = {
    "name": "billing-agent",
    "description": "Looks up invoices.",
    "version": "1.0.0",
    "supportedInterfaces": [
        {
            "url": "https://agents.example.com/a2a/v1",
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        },
        {"url": "grpc.example.com:443", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
    ],
    "capabilities": {"streaming": True},
    "securitySchemes": {
        "oauth": {
            "oauth2SecurityScheme": {
                "flows": {
                    "clientCredentials": {
                        "tokenUrl": "https://auth.example.com",
                        "scopes": {"read:only": "Read-only access", "admin": "Full access"},
                    }
                }
            }
        }
    },
    "securityRequirements": [{"schemes": {"oauth": {"list": ["read:only"]}}}],
    "defaultInputModes": ["text/plain"],
    "defaultOutputModes": ["text/plain"],
    "skills": [{"id": "lookup", "name": "lookup-invoice", "description": "Finds", "tags": []}],
}


def _interface(card: dict[str, Any], index: int, **fields: Any) -> dict[str, Any]:
    changed = copy.deepcopy(card)
    changed["supportedInterfaces"][index].update(fields)
    return changed


def test_a2a_1_0_card_is_read_from_its_interfaces_and_security_requirements(tmp_path):
    server = _server(tmp_path, CARD_1_0)
    assert server.endpoint_url == "https://agents.example.com"
    assert server.properties["supported_interface_origins"] == [
        "https://agents.example.com",
        "//grpc.example.com:443",
    ]
    assert server.authentication_required is True
    assert server.capabilities is not None and server.capabilities.oauth_scopes == ["read:only"]
    assert server.properties["security_scheme_types"] == ["oauth2"]
    assert server.properties["security_scheme_origins"] == ["https://auth.example.com"]
    assert not any(r.category in {"authentication", "transport_security"} for r in server.risks)
    (gap,) = [r.detail for r in server.risks if r.category == "completeness"]
    assert gap.endswith(
        "not bound in this inventory: endpoint URL beyond its exported origin; "
        "supported interface URLs beyond their exported origins."
    )
    assert "/v1" not in server.model_dump_json()


@pytest.mark.parametrize(
    "changed",
    [
        _interface(CARD_1_0, 0, url="https://evil.example.net/a2a/v1"),
        _interface(CARD_1_0, 1, url="grpc.evil.example.net:443"),
        {**CARD_1_0, "supportedInterfaces": CARD_1_0["supportedInterfaces"][::-1]},
        {**CARD_1_0, "url": "https://agents.example.com"},
    ],
    ids=["preferred-host", "second-host", "preference-order", "legacy-url-added"],
)
def test_a2a_1_0_interface_change_fails_the_drift_gate_without_a_key(tmp_path, changed):
    run, _ = _drift(tmp_path, CARD_1_0, changed)
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert any("billing-agent" in alert["alert"] for alert in alerts), alerts


def test_a2a_1_0_scope_widening_fails_the_drift_gate_without_a_key(tmp_path):
    widened = copy.deepcopy(CARD_1_0)
    widened["securityRequirements"][0]["schemes"]["oauth"]["list"].append("admin")
    run, _ = _drift(tmp_path / "widened", CARD_1_0, widened)
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert any(
        alert["severity"] == "high" and "capabilities changed" in alert["alert"] for alert in alerts
    ), alerts
    unchanged, _ = _drift(tmp_path / "unchanged", CARD_1_0, copy.deepcopy(CARD_1_0))
    _assert_unchanged(unchanged)


@pytest.mark.parametrize(
    "requirements",
    [
        [{"schemes": {"oauth": {"list": ["read:only"]}}}, {}],
        [{"schemes": {"oauth": {"list": ["read:only"]}}}, {"schemes": {}}],
        [{"schemes": {"oauth": {"list": ["read:only"]}}}, {"schemes": None}],
        [],
        [{"schemes": {"undeclared": {"list": []}}}],
        [{"schemes": {"oauth": {"list": ["read:only"]}, "undeclared": {}}}],
    ],
)
def test_a2a_1_0_anonymous_alternative_keeps_the_authentication_finding(tmp_path, requirements):
    changed = {**CARD_1_0, "securityRequirements": requirements}
    server = _server(tmp_path / "card", changed)
    assert server.authentication_required is False
    assert [r.severity for r in server.risks if r.category == "authentication"] == ["medium"]
    run, _ = _drift(tmp_path, CARD_1_0, changed)
    assert run.exit_code == 1, run.output


def test_a2a_1_0_proto_field_names_are_read_like_json_names(tmp_path):
    renamed = copy.deepcopy(CARD_1_0)
    renamed["supported_interfaces"] = renamed.pop("supportedInterfaces")
    renamed["security_requirements"] = renamed.pop("securityRequirements")
    schemes = renamed["security_schemes"] = renamed.pop("securitySchemes")
    schemes["oauth"] = {"oauth2_security_scheme": schemes["oauth"]["oauth2SecurityScheme"]}
    json_names, proto_names = _server(tmp_path / "a", CARD_1_0), _server(tmp_path / "b", renamed)
    for field in ("endpoint_url", "authentication_required", "capabilities"):
        assert getattr(proto_names, field) == getattr(json_names, field)
    for key in ("supported_interface_origins", "security_scheme_types", "security_scheme_origins"):
        assert proto_names.properties[key] == json_names.properties[key]


@pytest.mark.parametrize(
    ("url", "insecure"),
    [
        ("https://agents.example.com", False),
        ("http://agents.example.com", True),
        ("//agents.example.com", True),
        ("agents.example.com:443", True),
    ],
)
def test_a2a_1_0_preferred_interface_gets_the_transport_check(tmp_path, url, insecure):
    card = _interface(CARD_1_0, 0, url=url)
    server = _server(tmp_path / "a", card)
    assert server.endpoint_url == server.properties["supported_interface_origins"][0]
    assert any(r.category == "transport_security" for r in server.risks) is insecure
    legacy = _server(tmp_path / "b", {**card, "url": "https://legacy.example.com"})
    assert legacy.endpoint_url == "https://legacy.example.com"
    assert any(r.category == "transport_security" for r in legacy.risks) is insecure


def test_a2a_1_0_interface_tenant_is_bound_only_by_the_key(tmp_path, monkeypatch):
    card = _interface(CARD_1_0, 0, url="https://agents.example.com", tenant="acme-tenant")
    card["supportedInterfaces"].pop()
    server = _server(tmp_path / "a", card)
    (gap,) = [r.detail for r in server.risks if r.category == "completeness"]
    assert gap.endswith("values not bound in this inventory: supported interface tenants.")
    assert "acme-tenant" not in server.model_dump_json()
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    keyed = _server(tmp_path / "b", card)
    moved = _server(tmp_path / "c", _interface(card, 0, tenant="evil-tenant"))
    assert keyed.properties["static_value_binding"] != moved.properties["static_value_binding"]
    assert not any(r.category == "completeness" for r in keyed.risks)


@pytest.mark.parametrize(
    "change",
    [
        {"supportedInterfaces": {"url": "https://agents.example.com"}},
        {"supportedInterfaces": ["https://agents.example.com"]},
        {"supportedInterfaces": [{"protocolBinding": "JSONRPC"}]},
        {"supportedInterfaces": [{"url": " "}]},
        {"supportedInterfaces": [{"url": 1}]},
        {"supportedInterfaces": [{"url": "https://a.example", "tenant": 1}]},
        {"supportedInterfaces": [{"url": "https://a.example"}] * 1001},
        # A proto3 JSON parser reads both names, so a card must not give both.
        {"supported_interfaces": []},
        {"security_requirements": []},
        {"security_schemes": {}},
        {"securityRequirements": {"schemes": {}}},
        {"securityRequirements": [{"oauth": {"list": ["read:only"]}}]},
        {"securityRequirements": [{"schemes": []}]},
        {"securityRequirements": [{"schemes": {"oauth": ["read:only"]}}]},
        {"securityRequirements": [{"schemes": {"oauth": {"list": "read:only"}}}]},
        {"securityRequirements": [{"schemes": {"oauth": {"list": [1]}}}]},
        {"securityRequirements": [{"schemes": {"oauth": {"list": ["s"] * 1001}}}]},
        {"securitySchemes": {"oauth": {"oauth2SecurityScheme": {}, "mtlsSecurityScheme": {}}}},
        {"securitySchemes": {"oauth": {"oauth2SecurityScheme": "flows"}}},
        {"securitySchemes": {"oauth": {"type": "apiKey", "oauth2SecurityScheme": {}}}},
    ],
)
def test_malformed_a2a_1_0_declarations_are_scan_failures(tmp_path, change):
    assert _failures(tmp_path, {**CARD_1_0, **change}) == [
        ".well-known/agent.json: invalid A2A card field types"
    ]


def _skill_requirement(card: dict[str, Any], scheme: str, values: list[str]) -> dict[str, Any]:
    """Require `values` of `scheme` for the first skill, in the card's A2A version form."""
    changed = copy.deepcopy(card)
    skill = changed["skills"][0]
    if "supportedInterfaces" in changed:
        changed["securitySchemes"]["key"] = {"apiKeySecurityScheme": {"name": "X-Key"}}
        skill["securityRequirements"] = [{"schemes": {scheme: {"list": values}}}]
    else:
        changed["securitySchemes"]["key"] = {"type": "apiKey", "in": "header", "name": "X-Key"}
        skill["security"] = [{scheme: values}]
    return changed


@pytest.mark.parametrize("card", [CARD, CARD_1_0], ids=["a2a-0.3", "a2a-1.0"])
@pytest.mark.parametrize(
    ("scheme", "before", "after", "alert"),
    [
        ("oauth", "read:only", "admin", "capabilities changed"),
        ("key", "skill-reader", "skill-writer", "properties.static_card_hash changed"),
        ("undeclared", "skill-reader", "skill-writer", "properties.static_card_hash changed"),
    ],
)
def test_skill_requirement_change_fails_the_drift_gate_without_a_key(
    tmp_path, card, scheme, before, after, alert
):
    baseline = _skill_requirement(card, scheme, [before])
    changed = _skill_requirement(card, scheme, [after])
    run, boms = _drift(tmp_path / "changed", baseline, changed)
    assert run.exit_code == 1, run.output
    alerts = [a["alert"] for a in json.loads(run.stdout)["security_alerts"]]
    assert any(alert in a and "billing-agent" in a for a in alerts), alerts
    # Only OAuth and OpenID Connect scopes are exported; other values stay digest-only.
    assert ('"admin"' in boms) is (scheme == "oauth") and "skill-" not in boms
    unchanged, _ = _drift(tmp_path / "unchanged", baseline, copy.deepcopy(baseline))
    _assert_unchanged(unchanged)


def test_scope_moved_between_skills_changes_only_the_structure_digest(tmp_path):
    card = copy.deepcopy(CARD)
    card["skills"] = [
        {"id": "a", "name": "a", "security": [{"oauth": ["read:only"]}]},
        {"id": "b", "name": "b", "security": [{"oauth": ["admin"]}]},
    ]
    moved = copy.deepcopy(card)
    moved["skills"][0]["security"] = [{"oauth": ["admin"]}]
    moved["skills"][1]["security"] = [{"oauth": ["read:only"]}]
    run, _ = _drift(tmp_path, card, moved)
    assert run.exit_code == 1, run.output
    alerts = json.loads(run.stdout)["security_alerts"]
    assert [(a["severity"], a["alert"]) for a in alerts] == [
        (
            "high",
            f"High change in 'billing-agent': {UNBOUND_ALERT}; properties.static_card_hash changed.",
        )
    ], alerts


def test_skill_scopes_are_exported_with_the_card_scopes(tmp_path):
    pat = "ghp_" + "d" * 36
    card = _skill_requirement(CARD_1_0, "oauth", ["https://www.googleapis.com/auth/drive", pat])
    server = _server(tmp_path, card)
    assert server.capabilities is not None
    assert server.capabilities.oauth_scopes == [
        "***",
        "https://www.googleapis.com/auth/drive",
        "read:only",
    ]
    assert server.authentication_required is True
    assert pat not in server.model_dump_json()
    (gap,) = [r.detail for r in server.risks if r.category == "completeness"]
    assert gap.endswith("; redacted OAuth scopes.")


@pytest.mark.parametrize(
    ("card", "skill_security", "required"),
    [
        (CARD, {"security": [{}]}, False),
        (CARD, {"security": [{"oauth": ["read:only"]}, {}]}, False),
        (CARD, {"security": [{"undeclared": []}]}, False),
        (CARD, {"security": []}, True),
        (CARD, {"security": None}, True),
        (CARD, {"security": [{"oauth": []}]}, True),
        (CARD_1_0, {"securityRequirements": [{"schemes": {}}]}, False),
        (CARD_1_0, {"security_requirements": [{}]}, False),
        (CARD_1_0, {"securityRequirements": []}, True),
    ],
)
def test_skill_anonymous_alternative_keeps_the_authentication_finding(
    tmp_path, card, skill_security, required
):
    changed = copy.deepcopy(card)
    changed["skills"][0].update(skill_security)
    server = _server(tmp_path / "card", changed)
    assert server.authentication_required is required
    gap = "has a skill without a nonempty authentication requirement declared"
    findings = [r.detail for r in server.risks if r.category == "authentication"]
    assert findings == ([] if required else [f"A2A agent 'billing-agent' {gap}."])
    if not required:
        run, _ = _drift(tmp_path, card, changed)
        assert run.exit_code == 1, run.output


def test_skill_requirements_do_not_make_a_card_require_authentication(tmp_path):
    card = _skill_requirement(CARD, "oauth", ["read:only"])
    del card["security"]
    server = _server(tmp_path, card)
    assert server.authentication_required is False
    assert server.capabilities is not None and server.capabilities.oauth_scopes == ["read:only"]
    findings = [r.detail for r in server.risks if r.category == "authentication"]
    assert findings == [
        "A2A agent 'billing-agent' has no nonempty authentication requirement declared."
    ]


@pytest.mark.parametrize(
    "skills",
    [
        [{"id": "s", "security": {"oauth": ["read:only"]}}],
        [{"id": "s", "security": [["oauth"]]}],
        [{"id": "s", "security": [{"oauth": "read:only"}]}],
        [{"id": "s", "securityRequirements": [{"oauth": {"list": []}}]}],
        [{"id": "s", "securityRequirements": [], "security_requirements": []}],
        # Each skill is within the per-list limit; together they exceed it.
        [{"id": f"s{i}", "security": [{"oauth": ["x"] * 600}]} for i in range(2)],
    ],
)
def test_malformed_or_oversized_skill_security_is_a_scan_failure(tmp_path, skills):
    assert _failures(tmp_path, {**CARD, "skills": skills}) == [
        ".well-known/agent.json: invalid A2A card field types"
    ]


VECTOR_KEY = "nexus-symbiote-a2a-test-vector-key"
VECTOR_CARD = {
    "name": "v",
    "url": "https://a.example/p",
    "securitySchemes": {
        "o": {
            "type": "oauth2",
            "flows": {"clientCredentials": {"tokenUrl": "https://t.example/token", "scopes": {}}},
        },
        "k": {"type": "apiKey"},
    },
    "security": [{"o": ["s", "https://a.example/scope"]}, {"k": ["role"]}],
    "additionalInterfaces": [{"url": "https://g.example", "transport": "GRPC"}],
    "skills": [{"id": "l", "name": "lookup", "security": [{"o": ["t"]}]}],
}
VECTOR_CLIENT = {"name": "c", "agentCardUrl": "https://a.example/.well-known/agent-card.json"}
VECTORS = [
    (
        "static_card_hash",
        '{"profile":"nexus-symbiote/a2a-card-structure/v4",'
        '"structure":{"additional_interfaces":[{"fragment":false,"path_separators":0,'
        '"plain_path":"","query":false,"userinfo":false}],"authentication_schemes":null,'
        '"capabilities":{},'
        '"endpoint":{"fragment":false,"path_separators":1,"plain_path":null,"query":false,'
        '"userinfo":false},"extensions":[],'
        '"fields":["additionalInterfaces","name","security","securitySchemes",'
        '"skills","url"],"provider_url":null,'
        '"security":[{"k":["role"]},{"o":["https://a.example/scope","s"]}],'
        '"security_requirements":null,"security_scheme_urls":[{"fragment":false,'
        '"path_separators":1,"plain_path":null,"query":false,"userinfo":false}],'
        '"security_schemes":[["k","apiKey"],["o","oauth2"]],"signatures":[],'
        '"skill_security":[["lookup",'
        '{"security":[{"o":["t"]}]}]],"supported_interfaces":[]}}',
        "sha256:ab8b20b92b0cf6645924b4075646d699a9e73cc5a4500aad91c7ee4a314a04c5",
    ),
    (
        "static_value_binding",
        '{"configuration":{"additionalInterfaces":[{"transport":"GRPC","url":"https://g.example"}],'
        '"name":"v","security":[{"o":["s","https://a.example/scope"]},{"k":["role"]}],'
        '"securitySchemes":{"k":{"type":"apiKey"},"o":{"flows":{"clientCredentials":{"scopes":{},'
        '"tokenUrl":"https://t.example/token"}},"type":"oauth2"}},"skills":[{"id":"l",'
        '"name":"lookup","security":[{"o":["t"]}]}],"url":"https://a.example/p"},'
        '"profile":"nexus-symbiote/a2a-card-values/v1"}',
        "hmac-sha256:b2bf14d445fff1ba138b8f81aba51d13e16ff125b26e3f1dabd5718417d802a8",
    ),
    (
        "static_config_hash",
        '{"profile":"nexus-symbiote/a2a-client-structure/v1","structure":{"card_url":{'
        '"fragment":false,"path_separators":2,"plain_path":"/.well-known/agent-card.json",'
        '"query":false,"userinfo":false},"fields":["agentCardUrl","name"]}}',
        "sha256:37abbd341b98747178d6d9393bb2343dc6d7f4a2168a0d4fd3dd9d9a56f14d3a",
    ),
    (
        "static_value_binding",
        '{"configuration":{"agentCardUrl":"https://a.example/.well-known/agent-card.json",'
        '"name":"c"},"profile":"nexus-symbiote/a2a-client-values/v1"}',
        "hmac-sha256:54acc1cb60bb70eaa929aa3bec0e4d5ce0ccc13728191fdc72412c76d0ff0462",
    ),
]


def test_binding_profiles_match_their_published_vectors(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, VECTOR_KEY)
    card = _server(tmp_path / "card", VECTOR_CARD)
    client = _client(tmp_path / "client", VECTOR_CLIENT)
    assert card.properties["static_card_hash_profile"] == CARD_STRUCTURE_PROFILE
    assert client.properties["static_config_hash_profile"] == CLIENT_STRUCTURE_PROFILE
    for record, (field, message, expected) in zip(
        (card, card, client, client), VECTORS, strict=True
    ):
        if expected.startswith("sha256:"):
            computed = "sha256:" + hashlib.sha256(message.encode()).hexdigest()
        else:
            mac = hmac.new(VECTOR_KEY.encode(), message.encode(), "sha256").hexdigest()
            computed = "hmac-sha256:" + mac
        assert computed == expected
        assert record.properties[field] == expected
    assert card.properties["static_value_binding_key_id"] == "46c23d6a04382e01f726b1da3f2253b1"
    assert card.capabilities is not None
    assert card.capabilities.oauth_scopes == ["https://a.example/scope", "s", "t"]
    assert card.properties["security_scheme_origins"] == ["https://t.example"]
    assert card.properties["additional_interface_origins"] == ["https://g.example"]


VECTOR_CARD_1_0 = {
    "name": "w",
    "supportedInterfaces": [
        {"url": "https://a.example/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"},
        {"url": "g.example:443", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
    ],
    "securitySchemes": {
        "o": {
            "oauth2SecurityScheme": {
                "flows": {"clientCredentials": {"tokenUrl": "//t.example/token", "scopes": {}}}
            }
        },
        "k": {"apiKeySecurityScheme": {"location": "header", "name": "X-Key"}},
    },
    "securityRequirements": [
        {"schemes": {"o": {"list": ["s"]}}},
        {"schemes": {"k": {"list": ["role"]}}},
    ],
    "skills": [
        {
            "id": "l",
            "name": "lookup",
            "description": "d",
            "tags": [],
            "securityRequirements": [{"schemes": {"o": {"list": ["t"]}, "k": {"list": ["r2"]}}}],
        }
    ],
}
VECTOR_1_0 = (
    '{"profile":"nexus-symbiote/a2a-card-structure/v4","structure":{"additional_interfaces":[],'
    '"authentication_schemes":null,"capabilities":{},"endpoint":{"fragment":false,'
    '"path_separators":1,"plain_path":null,"query":false,"userinfo":false},"extensions":[],'
    '"fields":["name","securityRequirements",'
    '"securitySchemes","skills","supportedInterfaces"],"provider_url":null,"security":null,'
    '"security_requirements":[{"k":["role"]},{"o":["s"]}],'
    '"security_scheme_urls":[{"fragment":false,"path_separators":1,"plain_path":null,"query":false,'
    '"userinfo":false}],"security_schemes":[["k","apiKey"],["o","oauth2"]],"signatures":[],'
    '"skill_security":[["lookup",{"security_requirements":[{"k":["r2"],"o":["t"]}]}]],'
    '"supported_interfaces":[{"fragment":false,"path_separators":1,"plain_path":null,"query":false,'
    '"userinfo":false},{"fragment":false,"path_separators":0,"plain_path":null,"query":false,'
    '"userinfo":false}]}}'
)


def test_a2a_1_0_card_matches_its_published_structure_vector(tmp_path):
    expected = "sha256:06986934fe23bdc0c17ed47b43d0118dff53ec6876593bf218c66ea269bfd92e"
    assert "sha256:" + hashlib.sha256(VECTOR_1_0.encode()).hexdigest() == expected
    card = _server(tmp_path, VECTOR_CARD_1_0)
    assert card.properties["static_card_hash"] == expected
    assert card.endpoint_url == "https://a.example"
    assert card.properties["supported_interface_origins"] == [
        "https://a.example",
        "//g.example:443",
    ]
    assert card.properties["security_scheme_origins"] == ["//t.example"]
    assert card.properties["security_scheme_types"] == ["apiKey", "oauth2"]
    assert card.capabilities is not None and card.capabilities.oauth_scopes == ["s", "t"]


def test_a_card_nested_beyond_the_depth_bound_names_the_bound(tmp_path):
    nested: Any = {"tokenUrl": "https://t.example/token"}
    for _ in range(10):
        nested = {"flows": nested}
    assert _failures(tmp_path, {**CARD, "additionalInterfaces": [nested]}) == [
        ".well-known/agent.json: A2A card nests too deeply"
    ]


@pytest.mark.parametrize(
    "card",
    [
        {**CARD, "additionalInterfaces": [{"url": "https://a.example"}] * 1001},
        {**CARD, "additionalInterfaces": {f"u{i}": {} for i in range(1001)}},
        {**CARD, **{f"x-{i}": "" for i in range(1001)}},
    ],
    ids=["list", "mapping", "card-fields"],
)
def test_a_card_with_too_many_entries_names_the_bound(tmp_path, card):
    assert _failures(tmp_path, card) == [".well-known/agent.json: A2A card has too many entries"]


def test_plaintext_alternative_interfaces_fail_the_transport_check(tmp_path):
    card = {**CARD, "url": "https://agents.example.com"}
    insecure = {"url": "http://agents.example.net/a2a", "transport": "JSONRPC"}
    server = _server(tmp_path / "a", {**card, "additionalInterfaces": [insecure]})
    assert [r.severity for r in server.risks if r.category == "transport_security"] == ["high"]
    moved = dict(CARD_1_0)
    moved["supportedInterfaces"] = [
        CARD_1_0["supportedInterfaces"][0],
        {"url": "http://agents.example.net/a2a", "protocolBinding": "JSONRPC"},
    ]
    second = _server(tmp_path / "b", moved)
    assert [r.severity for r in second.risks if r.category == "transport_security"] == ["high"]
    # A 1.0 gRPC host:port interface declares no cleartext scheme and is not flagged.
    clean = _server(tmp_path / "c", dict(CARD_1_0))
    assert not any(r.category == "transport_security" for r in clean.risks)


@pytest.mark.parametrize("url", ["http:agents.example.net/a2a", "http:\\\\agents.example.net/a2a"])
def test_an_alternative_interface_without_slashes_is_read_as_whatwg_parsers_read_it(tmp_path, url):
    # WHATWG clients connect to http:host/x as http://host/x, in clear text.
    card = dict(CARD_1_0)
    card["supportedInterfaces"] = [
        CARD_1_0["supportedInterfaces"][0],
        {"url": url, "protocolBinding": "JSONRPC"},
    ]
    server = _server(tmp_path, card)
    assert [r.severity for r in server.risks if r.category == "transport_security"] == ["high"]
    assert server.properties["supported_interface_origins"] == [
        "https://agents.example.com",
        "http://agents.example.net",
    ]
