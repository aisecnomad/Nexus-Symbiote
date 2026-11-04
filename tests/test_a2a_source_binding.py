"""A redacted A2A inventory must not silently accept changed source declarations."""

from __future__ import annotations

import base64
import json
import secrets

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import (
    SOURCE_BINDING_KEY_ENV,
    SourceBindingKeyError,
    bind_source_values,
)
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.a2a import A2AScanner, has_a2a_source_binding
from nexus_symbiote.validators.completeness import CompletenessValidator

KEY = "98cac034c72c5e5a7cf015128779ae4e39b178899dca2a89d79745cb4a7379eb"
OTHER_KEY = "e4ca1a1500516486e8e73f2a79b1ea8233087e06586a614ea949174ff30b175f"


@pytest.fixture(autouse=True)
def _unkeyed(monkeypatch):
    """Start unkeyed; an operator key exported in the developer's shell must not leak in."""
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)


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
    card["securitySchemes"]["apiKey"] = {"type": "apiKey", "in": "header", "name": "X-Key"}
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
        client = {"name": "remote", "url": url, "authMethods": ["bearer"]}
        path.write_text(json.dumps({"clients": [client]}))
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


def _clients(path, **lists):
    path.write_text(json.dumps(lists))


def test_every_client_list_is_collected_and_bound(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    search = {"name": "search", "url": "https://search.example/a2a", "authMethods": ["bearer"]}
    billing = {
        "name": "billing",
        "url": "https://billing.example/read-only",
        "authMethods": ["bearer"],
    }
    _clients(tmp_path / "a2a.json", clients=[search], remoteAgents=[billing])
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded
    assert {component.name for component in result.components} == {"search", "billing"}
    assert all(has_a2a_source_binding(component) for component in result.components)


@pytest.mark.parametrize(
    "change",
    [
        {"url": "http://attacker.example/admin", "authMethods": []},
        {"url": "https://billing.example/admin"},
    ],
)
def test_remote_agents_beside_clients_deny_drift_and_project_risk(tmp_path, monkeypatch, change):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    project.mkdir()
    search = {"name": "search", "url": "https://search.example/a2a", "authMethods": ["bearer"]}
    billing = {
        "name": "billing",
        "url": "https://billing.example/read-only",
        "authMethods": ["bearer"],
    }
    _clients(project / "a2a.json", clients=[search], remoteAgents=[billing])
    runner = CliRunner()
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    _scan(runner, project, before)
    _clients(project / "a2a.json", clients=[search], remoteAgents=[{**billing, **change}])
    report_only = ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(after)]
    assert runner.invoke(main, report_only).exit_code == 0
    drift = runner.invoke(main, ["diff", str(before), str(after), "--fail-on-alert"])
    assert drift.exit_code == 1, drift.output
    assert "billing" in drift.output
    risk = runner.invoke(
        main, ["risk", str(before), "--project", str(project), "--no-project-policy"]
    )
    assert risk.exit_code == 1, risk.output


def test_empty_client_list_does_not_shadow_remote_agents(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    billing = {
        "name": "billing",
        "url": "https://billing.example/read-only",
        "authMethods": ["bearer"],
    }
    _clients(tmp_path / "a2a.json", remoteAgents=[billing])
    before = AIBOM(components=A2AScanner().scan(tmp_path).components)
    _clients(tmp_path / "a2a.json", clients=[], remoteAgents=[billing])
    result = A2AScanner().scan(tmp_path)
    assert [component.name for component in result.components] == ["billing"]
    assert not AIBOMDiffer().diff(before, AIBOM(components=result.components)).has_changes


@pytest.mark.parametrize(
    "configuration",
    [
        {"clients": [], "defaults": {"authMethods": []}},
        {"name": "remote", "url": "http://attacker.example/a2a"},
    ],
)
def test_unrecognized_client_configuration_fields_are_unknown_coverage(
    tmp_path, monkeypatch, configuration
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    project.mkdir()
    (project / "a2a.json").write_text(json.dumps(configuration))
    result = A2AScanner().scan(project)
    assert any("unrecognized A2A client configuration" in item for item in result.surfaces_excluded)
    run = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy"])
    assert run.exit_code == 1, run.output


CLIENT_AUTHENTICATION = [
    ({"authMethods": ["bearer"]}, ["bearer"], False, False),
    (
        {"authMethods": ["Bearer", "API-Key", "mutualTLS"]},
        ["Bearer", "API-Key", "mutualTLS"],
        False,
        False,
    ),
    ({"authentication": "OAuth2"}, ["OAuth2"], False, False),
    (
        {"authentication": {"schemes": ["openIdConnect"], "credentials": "CANARY"}},
        ["openIdConnect"],
        False,
        False,
    ),
    ({"authentication": {"bearer": "CANARY-token"}}, ["bearer"], False, False),
    ({"authentication": {"schemes": []}}, [], False, True),
    ({"authentication": {"schemes": None}}, [], False, True),
    ({"authentication": None}, [], False, True),
    ({"authentication": {"none": True}}, ["none"], False, True),
    ({"authMethods": [""]}, [""], False, True),
    ({"authMethods": ["PUBLIC", "bearer"]}, ["PUBLIC", "bearer"], False, True),
    ({"authMethods": ["eyJhbGciOiJIUzI1NiJ9.CANARY.sig"]}, ["[unrecognized]"], True, True),
    ({"authentication": "kx_live_CANARY51H8xQ2abcdef0123456789"}, ["[unrecognized]"], True, True),
    ({"authentication": {"token": "CANARY"}}, ["[unrecognized]"], True, True),
    (
        {"authentication": {"schemes": None, "credentials": "CANARY"}},
        ["[unrecognized]"],
        True,
        True,
    ),
    ({"authMethods": ["bearer", 42]}, ["bearer", "[unrecognized]"], True, True),
    (
        {"authMethods": ["bearer"], "authentication": "CANARY"},
        ["bearer", "[unrecognized]"],
        True,
        True,
    ),
    ({"authentication": 7}, ["[unrecognized]"], True, True),
]


@pytest.mark.parametrize(("declared", "exported", "unknown", "risk"), CLIENT_AUTHENTICATION)
def test_client_authentication_exports_only_recognized_scheme_identifiers(
    tmp_path, monkeypatch, declared, exported, unknown, risk
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    client = {"name": "remote", "url": "https://agent.example/a2a", **declared}
    _clients(tmp_path / "a2a.json", clients=[client])
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = result.components
    assert component.authentication_methods == exported
    assert "CANARY" not in component.model_dump_json()
    semantics = [item for item in result.surfaces_excluded if "semantics are unknown" in item]
    assert bool(semantics) is unknown
    assert any(item.category == "authentication" for item in component.risks) is risk


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx"])
def test_client_authentication_values_never_reach_exports(tmp_path, monkeypatch, output_format):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    project.mkdir()
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJDQU5BUlkifQ.CANARYsignature"
    clients = [
        {"name": "billing", "url": "https://billing.example/a2a", "authentication": jwt},
        {
            "name": "search",
            "url": "https://search.example/a2a",
            "authMethods": ["kx_live_CANARY51H8xQ2"],
        },
    ]
    _clients(project / "a2a.json", clients=clients)
    output = tmp_path / "bom.out"
    run = CliRunner().invoke(
        main,
        [
            "scan",
            str(project),
            "--no-project-policy",
            "--report-only",
            "-f",
            output_format,
            "-o",
            str(output),
        ],
    )
    assert run.exit_code == 0, run.output
    exported = output.read_text()
    assert "CANARY" not in exported and "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in exported


def test_unkeyed_collection_and_same_snapshot_diff_fail_closed(tmp_path):
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
    for key in (OTHER_KEY, ""):
        monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
        new = AIBOM(components=A2AScanner().scan(tmp_path).components)
        assert AIBOMDiffer().diff(old, new).security_alerts
        assert _a2a_issues(old, tmp_path)


WEAK_KEYS = [
    "CANARY-short",
    "acme-agents-binding-key-2026-prod",
    "nexus-symbiote-binding-key-2026!",
    "drift-fixture-operator-key-at-least-32-characters",
    "k" * 40,
    "a" * 64,
    "0123456789abcdef" * 4,
    "00" * 16 + "ff" * 16,
    "A" * 43,
    "abcdef0123456789abcdef0123456789abcdef0123456789",
    "98cac034c72c5e5a7cf015128779ae4e39b178899dca2a89d79745cb4a7379e",
    "+/" + "Qm9vazEyMzQ1Njc4OTBhYmNkZWZnaGlqa2xtbm9wcXJzdHV2d3h5eg==",
    KEY + "\n",
    "\udcff" * 64,
]


@pytest.mark.parametrize("key", WEAK_KEYS, ids=range(len(WEAK_KEYS)))
def test_binding_key_must_be_random_key_material(monkeypatch, key):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
    with pytest.raises(SourceBindingKeyError) as error:
        bind_source_values({"kind": "client"}, profile="test")
    assert SOURCE_BINDING_KEY_ENV in str(error.value)
    assert key.strip() not in str(error.value)


@pytest.mark.parametrize(
    "generate",
    [
        lambda: KEY,
        lambda: KEY.upper(),
        lambda: secrets.token_hex(32),
        lambda: secrets.token_hex(48),
        lambda: secrets.token_urlsafe(32),
        lambda: base64.urlsafe_b64encode(secrets.token_bytes(32)).decode(),
    ],
    ids=["constant", "uppercase", "token_hex", "long_hex", "token_urlsafe", "padded_base64url"],
)
def test_random_binding_keys_are_accepted(monkeypatch, generate):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, generate())
    mac, key_id = bind_source_values({"kind": "client"}, profile="test")
    assert mac.startswith("hmac-sha256:") and len(key_id) == 32


@pytest.mark.parametrize(
    "key",
    ["CANARY-short", "CANARY" + "a" * 64, "\udcff" * 64],
    ids=["short", "low-diversity", "not-utf-8"],
)
def test_invalid_binding_key_is_one_value_free_failure(tmp_path, monkeypatch, key):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, key)
    (tmp_path / "agent.json").write_text(json.dumps(_card()))
    client = {"name": "remote", "url": "https://agent.example/a2a", "authMethods": ["bearer"]}
    _clients(tmp_path / "a2a.json", clients=[client], remoteAgents=[{**client, "name": "other"}])
    result = A2AScanner().scan(tmp_path)
    (failure,) = result.scan_failures
    assert SOURCE_BINDING_KEY_ENV in failure and "field types" not in failure
    assert len(result.components) == 3
    assert not any(has_a2a_source_binding(component) for component in result.components)
    assert "CANARY" not in repr(result)


def test_invalid_key_is_not_reported_without_declarations(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, "too-short")
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures and not result.surfaces_excluded


@pytest.mark.parametrize(
    ("relative", "content"),
    [
        (
            "agent.json",
            '{"name": "big", "url": "https://agent.example/a2a", "limit": 9007199254740993}',
        ),
        ("agent.json", '{"name": "inf", "url": "https://agent.example/a2a", "limit": 1e400}'),
        (
            "a2a.yaml",
            "clients:\n  - name: dated\n    url: https://agent.example/a2a\n    expires: 2025-01-01\n",
        ),
    ],
    ids=["integer-beyond-2^53", "non-finite-number", "yaml-date"],
)
def test_values_outside_i_json_are_a_distinct_binding_failure(
    tmp_path, monkeypatch, relative, content
):
    (tmp_path / relative).write_text(content)
    assert A2AScanner().scan(tmp_path).components
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures == [
        f"{relative}: A2A declaration cannot be canonicalized for binding"
    ]
    assert not result.components


def test_deeply_nested_card_is_a_per_file_failure(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    nested = "[" * 1500 + "]" * 1500
    (tmp_path / "agent.json").write_text(
        '{"name": "deep", "url": "https://agent.example/a2a", "extra": ' + nested + "}"
    )
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "agent.json").write_text(json.dumps(_card()))
    client = {"name": "remote", "url": "https://agent.example/a2a", "authMethods": ["bearer"]}
    _clients(tmp_path / "a2a.json", clients=[client])
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures == [
        "agent.json: A2A declaration cannot be canonicalized for binding"
    ]
    assert {component.name for component in result.components} == {"reviewed-agent", "remote"}


@pytest.mark.parametrize("security", [[], [{}], [{"bearer": []}, {}]])
def test_anonymous_security_alternative_does_not_claim_authentication(tmp_path, security):
    (tmp_path / "agent.json").write_text(json.dumps({**_card(), "security": security}))
    component = A2AScanner().scan(tmp_path).components[0]
    assert component.authentication_required is False
    assert any(r.category == "authentication" for r in component.risks)


@pytest.mark.parametrize("security", [{"bearer": []}, ["bearer"], [{"bearer": "admin"}], "bearer"])
def test_unrecognized_security_shape_keeps_the_card_with_unknown_coverage(tmp_path, security):
    (tmp_path / "agent.json").write_text(json.dumps({**_card(), "security": security}))
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    (component,) = result.components
    assert component.authentication_required is None
    assert any("semantics are unknown" in item for item in result.surfaces_excluded)


def test_unknown_authentication_semantics_fail_the_default_scan_gate(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    project.mkdir()
    card = {**_card(), "security": [{"undeclared": []}]}
    (project / "agent.json").write_text(json.dumps(card))
    run = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy"])
    assert run.exit_code == 1, run.output
    report_only = ["scan", str(project), "--no-project-policy", "--report-only"]
    assert CliRunner().invoke(main, report_only).exit_code == 0


def _keyed_bom(tmp_path, monkeypatch):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    (tmp_path / "agent.json").write_text(json.dumps(_card()))
    return AIBOM(components=A2AScanner().scan(tmp_path).components)


def test_reconciliation_names_an_unbound_supplied_a2a_record(tmp_path, monkeypatch):
    bom = _keyed_bom(tmp_path, monkeypatch)
    for field in ("a2a_source_binding", "a2a_source_binding_key_id"):
        bom.components[0].properties.pop(field)
    issues = CompletenessValidator().validate_against_project(bom, tmp_path).issues
    assert any(
        issue.surface == "a2a-server:reviewed-agent"
        and issue.severity == "unknown"
        and "Static A2A source binding is unknown" in issue.description
        for issue in issues
    ), issues


def test_reconciled_a2a_subject_requires_the_same_binding(tmp_path, monkeypatch):
    local = _keyed_bom(tmp_path, monkeypatch).components[0]
    same = local.model_copy(deep=True)
    assert CompletenessValidator._same_subject(tmp_path, same, local)
    for field, value in (
        ("a2a_source_binding", "hmac-sha256:" + "0" * 64),
        ("a2a_source_binding_key_id", "1" * 32),
    ):
        changed = local.model_copy(deep=True)
        changed.properties[field] = value
        assert not CompletenessValidator._same_subject(tmp_path, changed, local)
    unbound = local.model_copy(deep=True)
    unbound.properties.pop("a2a_source_binding")
    assert not CompletenessValidator._same_subject(tmp_path, unbound, local)


@pytest.mark.parametrize("mode", [["static-agent-card"], {"mode": "static-agent-card"}])
def test_non_string_collection_mode_is_reviewed_not_a_crash(tmp_path, monkeypatch, mode):
    bom = _keyed_bom(tmp_path, monkeypatch)
    supplied = bom.model_copy(deep=True)
    supplied.components[0].properties["collection_mode"] = mode
    supplied.components[0].properties.pop("a2a_source_binding")
    report = AIBOMDiffer().diff(supplied, supplied)
    assert any(alert["severity"] == "high" for alert in report.security_alerts)
    issues = CompletenessValidator().validate_against_project(supplied, tmp_path).issues
    assert any(issue.surface == "a2a-server:reviewed-agent" for issue in issues)
    path = tmp_path / "supplied.json"
    supplied.save(path)
    run = CliRunner().invoke(
        main, ["diff", str(path), str(path), "--json-output", "--fail-on-alert"]
    )
    assert run.exit_code == 1 and json.loads(run.stdout)["security_alerts"], run.output
