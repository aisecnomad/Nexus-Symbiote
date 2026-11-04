"""The A2A card actually used for routing must be the one reviewed by the drift gate."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.diff.differ import AIBOMDiffer
from nexus_symbiote.scanners.a2a import A2AScanner

KEY = "d4ac09449d3f1d08cc8a12a5b50d38fdbfc21374368055004fae7837133830b9"
BEARER = {"bearer": {"type": "http", "scheme": "bearer"}}


@pytest.fixture(autouse=True)
def _unkeyed(monkeypatch):
    """Start unkeyed; an operator key exported in the developer's shell must not leak in."""
    monkeypatch.delenv(SOURCE_BINDING_KEY_ENV, raising=False)


def _card():
    return {
        "name": "planner",
        "supportedInterfaces": [
            {
                "url": "https://primary.example/agent",
                "protocolBinding": "JSONRPC",
                "protocolVersion": "1.0",
            },
            {
                "url": "https://fallback.example/agent",
                "protocolBinding": "GRPC",
                "protocolVersion": "1.0",
            },
        ],
        "securityRequirements": [{"schemes": {"oauth2": {"list": ["read"]}}}],
        "skills": [{"name": "plan"}],
    }


def _server(tmp_path, card):
    (tmp_path / "agent-card.json").write_text(json.dumps(card))
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures, result.scan_failures
    (server,) = result.components
    unknown = any("semantics are unknown" in item for item in result.surfaces_excluded)
    return server, unknown


def _transport_risks(server):
    return [risk.severity.value for risk in server.risks if risk.category == "transport_security"]


def test_projects_v1_interfaces_and_anonymous_alternative(tmp_path):
    card = _card()
    card["supportedInterfaces"][0].update(
        url="https://user:CANARY@primary.example/CANARY?token=CANARY#CANARY", tenant="CANARY"
    )
    card["securityRequirements"].append({"schemes": {}})
    (tmp_path / "agent-card.json").write_text(json.dumps(card))
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    (server,) = result.components
    assert "CANARY" not in server.model_dump_json()
    assert server.endpoint_url == "https://primary.example"
    assert server.supported_protocols == ["JSONRPC", "GRPC"]
    assert [item["origin"] for item in server.properties["supported_interfaces"]] == [
        "https://primary.example",
        "https://fallback.example",
    ]
    assert {"oauth2": ["read"]} in server.properties["security_requirements"]
    assert "legacy_interfaces" not in server.properties
    assert server.authentication_required is False
    assert [risk.category for risk in server.risks] == ["authentication"]


@pytest.mark.parametrize(
    "legacy",
    [
        {"url": "http://user:CANARY@attacker.example/a2a?token=CANARY"},
        {"url": "https://primary.example/agent", "preferredTransport": "JSONRPC"},
        {
            "url": "https://primary.example/agent",
            "additionalInterfaces": [
                {"url": "https://primary.example/agent", "transport": "JSONRPC"},
                {"url": "http://attacker.example/a2a", "transport": "HTTP+JSON"},
            ],
        },
    ],
)
def test_dual_structure_card_keeps_and_checks_legacy_endpoints(tmp_path, legacy):
    server, _ = _server(tmp_path, {**_card(), **legacy})
    assert server.endpoint_url == "https://primary.example"
    recorded = server.properties["legacy_interfaces"]
    assert recorded[0] == {
        "origin": "http://attacker.example"
        if "attacker" in legacy["url"]
        else "https://primary.example",
        "transport": legacy.get("preferredTransport", "JSONRPC"),
    }
    assert len(recorded) == 1 + len(legacy.get("additionalInterfaces", []))
    plaintext = any(item["origin"].startswith("http://") for item in recorded)
    assert _transport_risks(server) == (["high"] if plaintext else [])
    assert "CANARY" not in server.model_dump_json()


def test_legacy_additional_interfaces_are_checked_without_v1_interfaces(tmp_path):
    card = {
        "name": "legacy",
        "url": "https://agent.example/a2a",
        "additionalInterfaces": [{"url": "http://agent.example:8080/a2a", "transport": "GRPC"}],
        "authentication": {"schemes": ["bearer"]},
        "skills": [{"id": "s", "name": "s"}],
    }
    server, _ = _server(tmp_path, card)
    assert server.endpoint_url == "https://agent.example"
    assert server.properties["legacy_interfaces"] == [
        {"origin": "https://agent.example", "transport": "JSONRPC"},
        {"origin": "http://agent.example:8080", "transport": "GRPC"},
    ]
    assert _transport_risks(server) == ["high"]


def test_legacy_endpoint_repoint_is_a_high_alert_even_with_unchanged_bindings(
    tmp_path, monkeypatch
):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    old, _ = _server(tmp_path, {**_card(), "url": "https://primary.example/agent"})
    new = old.model_copy(deep=True)
    new.properties["legacy_interfaces"][0]["origin"] = "https://attacker.example"
    report = AIBOMDiffer().diff(AIBOM(components=[old]), AIBOM(components=[new]))
    (change,) = report.components_modified
    assert change.details == ["properties changed."]
    assert change.severity == "high"


@pytest.mark.parametrize(
    "url, origin, risks",
    [
        ("grpc.example.com:443", "grpc://grpc.example.com:443", ["medium"]),
        ("GRPC.Example.com:50051", "grpc://grpc.example.com:50051", ["medium"]),
        ("[2001:db8::1]:443", "grpc://[2001:db8::1]:443", ["medium"]),
        ("grpcs://grpc.example.com:443", "grpcs://grpc.example.com:443", []),
        ("https://grpc.example.com/a2a", "https://grpc.example.com", []),
        ("http://grpc.example.com/a2a", "http://grpc.example.com", ["high"]),
    ],
)
def test_grpc_interfaces_accept_the_specified_host_port_form(tmp_path, url, origin, risks):
    card = _card()
    card["supportedInterfaces"][1]["url"] = url
    server, _ = _server(tmp_path, card)
    assert server.properties["supported_interfaces"][1]["origin"] == origin
    assert _transport_risks(server) == risks


@pytest.mark.parametrize(
    "binding, url",
    [
        ("GRPC", "grpc.example.com"),
        ("GRPC", "grpc.example.com:0"),
        ("GRPC", "grpc.example.com:99999"),
        ("GRPC", "grpc.example.com:https"),
        ("GRPC", "user:CANARY@grpc.example.com:443"),
        ("GRPC", "grpc.example.com:443/CANARY"),
        ("GRPC", "grpc.example.com:443?token=CANARY"),
        ("GRPC", "dns:///grpc.example.com:443"),
        ("GRPC", "grpc_example..com:443"),
        ("JSONRPC", "agent.example:443"),
        ("JSONRPC", "https://trusted.exa\nmple.attacker.net/x"),
        ("JSONRPC", "https://trusted.example\t/x"),
        ("JSONRPC", "https://trusted.example /x"),
        ("JSONRPC", "https://trusted.example\x7f/x"),
        ("JSONRPC", "https://trusted.example /x"),
        ("GRPC", "grpc.exa\nmple.com:443"),
    ],
)
def test_other_interface_forms_and_control_characters_are_rejected(tmp_path, binding, url):
    card = _card()
    card["supportedInterfaces"][1].update(url=url, protocolBinding=binding)
    (tmp_path / "agent-card.json").write_text(json.dumps(card))
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures and not result.components
    assert "CANARY" not in repr(result)


@pytest.mark.parametrize(
    "url", ["https://trusted.exa\nmple.attacker.net/x", "http://a.example\t/x"]
)
def test_control_characters_in_a_legacy_url_are_rejected(tmp_path, url):
    card = {"name": "legacy", "url": url, "skills": [{"id": "s", "name": "s"}]}
    (tmp_path / "agent.json").write_text(json.dumps(card))
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures and not result.components


def test_snake_case_protojson_and_skill_requirements(tmp_path):
    card = _card()
    interface = card.pop("supportedInterfaces")[0]
    interface["protocol_version"] = interface.pop("protocolVersion")
    interface["protocol_binding"] = interface.pop("protocolBinding")
    card["supported_interfaces"] = [interface]
    card["security_requirements"] = card.pop("securityRequirements")
    card["skills"] = [{"id": "plan", "security_requirements": [{"schemes": {"mtls": {}}}]}]
    path = tmp_path / "agent-card.json"
    path.write_text(json.dumps(card))
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    (server,) = result.components
    assert server.endpoint_url == "https://primary.example"
    assert server.authentication_required
    assert server.properties["skill_security_requirements"] == {"plan": [{"mtls": []}]}
    card["supportedInterfaces"] = []
    path.write_text(json.dumps(card))
    assert A2AScanner().scan(tmp_path).scan_failures


@pytest.mark.parametrize(
    "field, invalid",
    [
        ("supportedInterfaces", []),
        (
            "supportedInterfaces",
            [{"url": "/CANARY", "protocolVersion": "1.0", "protocolBinding": "GRPC"}],
        ),
        ("securityRequirements", [{"schemes": {"oauth": {"list": "CANARY"}}}]),
    ],
)
def test_invalid_v1_declaration_is_a_collection_failure(tmp_path, field, invalid):
    card = _card()
    card[field] = invalid
    (tmp_path / "agent-card.json").write_text(json.dumps(card))
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures and not result.components
    assert "CANARY" not in repr(result.scan_failures)


@pytest.mark.parametrize(
    "change",
    ["preferred_downgrade", "fallback_repoint", "reorder", "change_scopes", "same_origin_path"],
)
def test_cli_fails_on_v1_card_drift(tmp_path, monkeypatch, change):
    monkeypatch.setenv(SOURCE_BINDING_KEY_ENV, KEY)
    project = tmp_path / "project"
    location = project / ".well-known"
    location.mkdir(parents=True)
    card_path = location / "agent-card.json"
    card = _card()
    card_path.write_text(json.dumps(card))
    runner = CliRunner()
    before, after = tmp_path / "before.json", tmp_path / "after.json"
    scan = ["scan", str(project), "--no-project-policy", "-o"]
    baseline = runner.invoke(main, [*scan, str(before)])
    assert baseline.exit_code == 0, baseline.output
    if change == "preferred_downgrade":
        card["supportedInterfaces"][0]["url"] = "http://primary.example/new"
    elif change == "fallback_repoint":
        card["supportedInterfaces"][1]["url"] = "https://different.example"
    elif change == "reorder":
        card["supportedInterfaces"].reverse()
    elif change == "same_origin_path":
        # The exported origin is unchanged; only the keyed source binding sees this.
        card["supportedInterfaces"][0]["url"] = "https://primary.example/admin"
    else:
        card["securityRequirements"][0]["schemes"]["oauth2"]["list"] = ["write"]
    card_path.write_text(json.dumps(card))
    observed = runner.invoke(main, [*scan, str(after)])
    assert observed.exit_code == 0, observed.output
    server = next(c for c in json.loads(after.read_text())["components"] if c["name"] == "planner")
    assert server["authentication_required"] is True
    assert any(r["category"] == "transport_security" for r in server["risks"]) == (
        change == "preferred_downgrade"
    )
    diff = runner.invoke(
        main, ["diff", str(before), str(after), "--json-output", "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert any(a["severity"] == "high" for a in json.loads(diff.stdout)["security_alerts"])


@pytest.mark.parametrize(
    "extra, expected",
    [
        ({"security": [{"bearer": []}], "securitySchemes": BEARER}, True),
        (
            {
                "security": [{"bearer": []}],
                "securitySchemes": BEARER,
                "securityRequirements": [{"schemes": {}}],
            },
            False,
        ),
        ({"security": [{}]}, False),
        ({"authentication": {"schemes": ["Bearer"]}}, True),
        ({"authentication": {"schemes": []}}, False),
        ({"authentication": {"credentials": "unsupported form"}}, None),
        ({"securityRequirements": []}, False),
    ],
)
def test_declared_requirement_forms_combine_conservatively(tmp_path, extra, expected):
    card = {**_card(), **extra}
    server, unknown = _server(tmp_path, card)
    assert server.authentication_required is expected
    assert unknown == (expected is None)


LEGACY = {
    "name": "legacy",
    "url": "https://agent.example/a2a",
    "skills": [{"id": "s", "name": "s"}],
}


@pytest.mark.parametrize(
    "extra, expected",
    [
        ({"authentication": {"schemes": ["bearer"]}}, True),
        ({"authentication": {"schemes": "Basic"}}, True),
        ({"authentication": {"schemes": ["public"]}}, False),
        ({"authentication": {"schemes": ["NONE"]}}, False),
        ({"authentication": {"schemes": ["bearer", "Anonymous"]}}, False),
        ({"authentication": {"schemes": [""]}}, False),
        ({"authentication": {"schemes": [" "]}}, False),
        ({"authentication": {"schemes": None}}, False),
        ({"authentication": {"schemes": None, "credentials": "token"}}, None),
        ({"authentication": {"schemes": [1]}}, None),
        ({"authentication": ["bearer"]}, None),
        ({"authentication": "bearer"}, None),
        ({"authentication": None}, False),
        ({"security": None}, False),
        ({"security": None, "authentication": {"schemes": ["bearer"]}}, True),
        ({"security": [{"bearer": []}]}, None),
        ({"security": [{"bearer": []}], "securitySchemes": None}, None),
        ({"security": [{"bearer": []}], "securitySchemes": ["bearer"]}, None),
        ({"security": [{"bearer": []}], "securitySchemes": BEARER}, True),
        ({"security": [{"bearer": [], "undeclared": []}], "securitySchemes": BEARER}, None),
        ({"security": [{"bearer": []}, {"undeclared": []}], "securitySchemes": BEARER}, None),
        ({"security": [{"undeclared": []}, {}], "securitySchemes": BEARER}, False),
        ({"security": [{"anon": []}], "securitySchemes": {"anon": {"type": "none"}}}, None),
        ({"security": [{"x": []}], "securitySchemes": {"x": {"type": "custom"}}}, None),
        ({"security": [{"x": []}], "securitySchemes": {"x": {"type": "HTTP"}}}, None),
        ({"security": [{"x": []}], "securitySchemes": {"x": {"scheme": "bearer"}}}, None),
        (
            {"security": [{"x": []}], "securitySchemes": {"x": {"type": "http", "scheme": "None"}}},
            None,
        ),
        ({"security": [{"x": []}], "securitySchemes": {"x": {"type": "http"}}}, None),
        (
            {
                "security": [{"key": ["read"], "tls": []}],
                "securitySchemes": {
                    "key": {"type": "apiKey", "in": "header", "name": "X-Key"},
                    "tls": {"type": "mutualTLS"},
                },
            },
            True,
        ),
        (
            {
                "security": [{"oidc": []}],
                "securitySchemes": {
                    "oidc": {"openIdConnectSecurityScheme": {"openIdConnectUrl": "https://id.test"}}
                },
            },
            True,
        ),
        (
            {
                "security": [{"h": []}],
                "securitySchemes": {"h": {"http_auth_security_scheme": {"scheme": "Bearer"}}},
            },
            True,
        ),
        (
            {
                "security": [{"h": []}],
                "securitySchemes": {"h": {"httpAuthSecurityScheme": {"scheme": "none"}}},
            },
            None,
        ),
        (
            {
                "security": [{"h": []}],
                "securitySchemes": {
                    "h": {"httpAuthSecurityScheme": {"scheme": "Bearer"}, "mtlsSecurityScheme": {}}
                },
            },
            None,
        ),
    ],
)
def test_legacy_and_v0_3_authentication_semantics(tmp_path, extra, expected):
    server, unknown = _server(tmp_path, {**LEGACY, **extra})
    assert server.authentication_required is expected
    assert unknown == (expected is None)
    assert any(r.category == "authentication" for r in server.risks) == (expected is not True)


@pytest.mark.parametrize(
    "skill, expected, recorded",
    [
        ({"security": [{}]}, False, [{}]),
        ({"security": []}, False, []),
        ({"security": [{"bearer": ["admin", "admin"]}]}, True, [{"bearer": ["admin"]}]),
        ({"security": [{"bearer": []}, {}]}, False, [{"bearer": []}, {}]),
        ({"security": [{"undeclared": []}]}, None, [{"undeclared": []}]),
        ({"security": {"bearer": []}}, None, None),
        ({"security": None}, True, None),
        ({"securityRequirements": [{"schemes": {}}]}, False, [{}]),
        ({"securityRequirements": []}, False, []),
        ({"securityRequirements": None}, True, None),
        (
            {
                "security": [{"bearer": []}],
                "securityRequirements": [{"schemes": {"bearer": {}}}],
            },
            True,
            [{"bearer": []}],
        ),
        (
            {"security": [{"bearer": []}], "securityRequirements": [{"schemes": {}}]},
            False,
            [{"bearer": []}, {}],
        ),
    ],
)
def test_skill_requirements_decide_whether_authentication_is_universal(
    tmp_path, skill, expected, recorded
):
    card = {
        **LEGACY,
        "security": [{"bearer": []}],
        "securitySchemes": BEARER,
        "skills": [
            {"id": "refund", "name": "issue-refund", **skill},
            {"id": "read", "name": "read"},
        ],
    }
    server, unknown = _server(tmp_path, card)
    assert server.authentication_required is expected
    assert unknown == (expected is None)
    if recorded is None:
        assert "skill_security_requirements" not in server.properties
    else:
        assert server.properties["skill_security_requirements"] == {"refund": recorded}


def test_skill_requirements_need_a_unique_identifier(tmp_path):
    skill = {"name": "refund", "security": [{}]}
    card = {**LEGACY, "skills": [skill]}
    (tmp_path / "agent.json").write_text(json.dumps(card))
    assert A2AScanner().scan(tmp_path).scan_failures
    card["skills"] = [{**skill, "id": "refund"}, {**skill, "id": "refund"}]
    (tmp_path / "agent.json").write_text(json.dumps(card))
    assert A2AScanner().scan(tmp_path).scan_failures


def test_card_level_anonymous_access_is_not_hidden_by_skill_requirements(tmp_path):
    card = {**LEGACY, "skills": [{"id": "refund", "name": "refund", "security": [{"bearer": []}]}]}
    card["securitySchemes"] = BEARER
    server, unknown = _server(tmp_path, card)
    assert server.authentication_required is False
    assert not unknown
