"""The A2A card actually used for routing must be the one reviewed by the drift gate."""

import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.a2a import A2AScanner


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


def test_projects_v1_interfaces_and_anonymous_alternative(tmp_path):
    card = _card()
    card["supportedInterfaces"][0].update(
        url="https://user:CANARY@primary.example/CANARY?token=CANARY#CANARY", tenant="CANARY"
    )
    card["url"] = "http://obsolete.example/ignored"
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
    assert server.authentication_required is False
    assert [risk.category for risk in server.risks] == ["authentication"]


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
    "change", ["preferred_downgrade", "fallback_repoint", "reorder", "change_scopes"]
)
def test_cli_fails_on_v1_card_drift(tmp_path, change):
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
