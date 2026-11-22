"""A2A discovery, card records and SDK heuristics on ordinary and hostile layouts."""

from __future__ import annotations

import base64
import json
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.models import A2AClientComponent, A2AServerComponent
from nexus_symbiote.scanners.a2a import A2AScanner, _scope
from nexus_symbiote.utils.secrets import REDACTED
from tests.support import scaling_ratio

CARD: dict[str, Any] = {
    "name": "billing-agent",
    "url": "https://agents.example.com",
    "skills": [{"id": "lookup", "name": "lookup-invoice"}],
    "securitySchemes": {"bearer": {"type": "http", "scheme": "bearer"}},
    "security": [{"bearer": []}],
}


def _write(root: Path, relative: str, value: Any) -> None:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value if isinstance(value, str) else json.dumps(value))


def _servers(result) -> list[A2AServerComponent]:
    return [c for c in result.components if isinstance(c, A2AServerComponent)]


def _jws_header(header: dict[str, Any]) -> str:
    return base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")


def test_scope_beyond_the_length_bound_is_redacted_without_a_search():
    samples = {
        scale: ("eyJ" * (100_000 * scale), "a" + "eyJ" * (100_000 * scale)) for scale in (1, 4)
    }

    def run(scale: int) -> None:
        first, second = samples[scale]
        assert _scope(first) == REDACTED
        assert _scope(second) == REDACTED

    assert scaling_ratio(run) < 10


def test_card_with_a_huge_scope_is_collected_quickly(tmp_path):
    roots: dict[int, Path] = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        card = {
            **CARD,
            "securitySchemes": {"o": {"type": "oauth2"}},
            "security": [{"o": ["eyJ" * (25_000 * scale), "read"]}],
        }
        _write(root, ".well-known/agent.json", card)
        roots[scale] = root
    result = A2AScanner().scan(roots[4])
    (server,) = _servers(result)
    assert server.capabilities is not None
    assert server.capabilities.oauth_scopes == [REDACTED, "read"]
    assert scaling_ratio(lambda scale: A2AScanner().scan(roots[scale])) < 10


@pytest.mark.parametrize(
    "relative",
    [
        "public/.well-known/agent-card.json",
        "static/.well-known/agent.json",
        "packages/agent/.well-known/agent-card.json",
    ],
)
def test_cards_are_found_under_any_well_known_directory(tmp_path, relative):
    _write(tmp_path, relative, CARD)
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    (server,) = _servers(result)
    assert server.agent_card_path == relative
    assert server.source_path == relative
    assert relative in result.surfaces_scanned


@pytest.mark.parametrize("relative", [".well-known/Agent.json", ".Well-Known/agent-card.json"])
def test_case_variant_card_path_is_a_failure(tmp_path, relative):
    _write(tmp_path, relative, CARD)
    result = A2AScanner().scan(tmp_path)
    assert not _servers(result)
    assert any(
        failure.startswith(relative) and "case-insensitive" in failure
        for failure in result.scan_failures
    )


def test_generic_root_name_without_an_a2a_field_is_not_a_card(tmp_path):
    _write(tmp_path, "agent.json", {"name": "build-agent", "model": "gpt"})
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures and not _servers(result)
    _write(tmp_path, "Agent-Card.json", {"name": "other", "runs": 3})
    assert not A2AScanner().scan(tmp_path).scan_failures


def test_same_card_at_both_well_known_names_is_one_record(tmp_path):
    _write(tmp_path, ".well-known/agent.json", CARD)
    _write(tmp_path, ".well-known/agent-card.json", CARD)
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    (server,) = _servers(result)
    assert server.agent_card_path == ".well-known/agent-card.json"
    assert server.properties["agent_card_paths"] == [
        ".well-known/agent-card.json",
        ".well-known/agent.json",
    ]


def test_different_cards_for_one_agent_name_fail_closed(tmp_path):
    _write(tmp_path, ".well-known/agent.json", CARD)
    _write(tmp_path, ".well-known/agent-card.json", {**CARD, "url": "http://evil.example"})
    result = A2AScanner().scan(tmp_path)
    assert any("different content" in failure for failure in result.scan_failures)


def test_a_number_where_the_other_card_declares_a_flag_is_different_content(tmp_path):
    _write(tmp_path, ".well-known/agent-card.json", {**CARD, "capabilities": {"streaming": True}})
    _write(tmp_path, ".well-known/agent.json", {**CARD, "capabilities": {"streaming": 1}})
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures == [
        ".well-known/agent.json: declares the same agent as .well-known/agent-card.json "
        "with different content"
    ]
    (server,) = _servers(result)
    assert server.properties["agent_card_paths"] == [".well-known/agent-card.json"]


def test_a_card_that_is_not_a_mapping_is_named_by_its_path(tmp_path):
    _write(tmp_path, ".well-known/agent-card.json", CARD)
    _write(tmp_path, "public/.well-known/agent-card.json", [])
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures == ["public/.well-known/agent-card.json: expected a mapping"]


def test_unnamed_cards_in_two_places_do_not_collide(tmp_path):
    unnamed = {key: value for key, value in CARD.items() if key != "name"}
    _write(tmp_path, "a/.well-known/agent.json", unnamed)
    _write(tmp_path, "b/.well-known/agent.json", {**unnamed, "url": "https://b.example"})
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    assert sorted(server.bom_ref for server in _servers(result)) == [
        "a2a-server:a/.well-known/agent.json",
        "a2a-server:b/.well-known/agent.json",
    ]


def test_signatures_and_capabilities_are_recorded_without_verification(tmp_path):
    signed = {
        **CARD,
        "capabilities": {
            "streaming": True,
            "pushNotifications": False,
            "extensions": [{"uri": "https://ext.example/v1/ext", "required": True}],
        },
        "provider": {"organization": "Example", "url": "https://example.com/about"},
        "signatures": [
            {"protected": _jws_header({"alg": "ES256", "kid": "key-1"}), "signature": "c2ln"},
            {"protected": "%%%", "signature": "x"},
        ],
    }
    _write(tmp_path / "a", ".well-known/agent.json", signed)
    (server,) = _servers(A2AScanner().scan(tmp_path / "a"))
    assert server.properties["card_signature_verified"] == "not-checked"
    assert server.properties["card_signatures"] == [
        {"alg": "ES256", "header": "read", "kid": "key-1"},
        {"alg": None, "header": "unreadable", "kid": None},
    ]
    assert server.properties["capability_flags"] == {
        "pushNotifications": False,
        "streaming": True,
    }
    assert server.properties["extensions"] == [{"origin": "https://ext.example", "required": True}]
    assert server.properties["provider_origin"] == "https://example.com"
    unbound = next(r for r in server.risks if "values not bound" in r.detail)
    assert "extension URIs" in unbound.detail
    stripped = {key: value for key, value in signed.items() if key != "signatures"}
    _write(tmp_path / "b", ".well-known/agent.json", stripped)
    (unsigned,) = _servers(A2AScanner().scan(tmp_path / "b"))
    assert unsigned.properties["card_signatures"] == []
    assert unsigned.properties["static_card_hash"] != server.properties["static_card_hash"]


@pytest.mark.parametrize(
    "value",
    [
        "ghp_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8",
        "AKIAIOSFODNN7EXAMPLE",
        "api_key=s3cr3tvalue123",
        "sk-abcdefghijklmnopqrstuvwx",
    ],
)
def test_a_credential_in_a_signature_header_is_not_exported(tmp_path, value):
    header = {"alg": value, "kid": value}
    card = {**CARD, "signatures": [{"protected": _jws_header(header), "signature": "c2ln"}]}
    _write(tmp_path, ".well-known/agent.json", card)
    (server,) = _servers(A2AScanner().scan(tmp_path))
    assert server.properties["card_signatures"] == [
        {"alg": "[redacted]", "header": "read", "kid": "[redacted]"}
    ]
    assert value not in json.dumps(server.model_dump(mode="json"))


@pytest.mark.parametrize(
    "kid", ["key-1", "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs", "did:web:example.com#key-1"]
)
def test_an_ordinary_key_id_is_exported(tmp_path, kid):
    header = {"alg": "EdDSA", "kid": kid}
    card = {**CARD, "signatures": [{"protected": _jws_header(header), "signature": "c2ln"}]}
    _write(tmp_path, ".well-known/agent.json", card)
    (server,) = _servers(A2AScanner().scan(tmp_path))
    assert server.properties["card_signatures"] == [{"alg": "EdDSA", "header": "read", "kid": kid}]


def _drift(tmp_path: Path, before: dict[str, Any], after: dict[str, Any]):
    project = tmp_path / "project"
    outputs = []
    for index, card in enumerate((before, after)):
        _write(project, ".well-known/agent.json", card)
        output = tmp_path / f"{index}.json"
        run = CliRunner().invoke(
            main, ["scan", str(project), "--no-project-policy", "--report-only", "-o", str(output)]
        )
        assert run.exit_code == 0, run.output
        outputs.append(str(output))
    return CliRunner().invoke(main, ["diff", *outputs, "--json-output", "--fail-on-alert"])


@pytest.mark.parametrize(
    "change",
    [
        {"signatures": []},
        {"capabilities": {"pushNotifications": True}},
        {"capabilities": {"extensions": [{"uri": "https://other.example/x", "required": True}]}},
    ],
)
def test_signature_and_capability_changes_fail_the_drift_gate_without_a_key(tmp_path, change):
    before = {
        **CARD,
        "capabilities": {"pushNotifications": False},
        "signatures": [{"protected": _jws_header({"alg": "ES256", "kid": "k"}), "signature": "s"}],
    }
    run = _drift(tmp_path, before, {**before, **change})
    assert run.exit_code == 1, run.output
    assert "a2a-server:billing-agent" in run.output


def test_python_sdk_heuristics_never_fail_the_collector(tmp_path):
    for index in range(25):
        _write(tmp_path, f"script_{index}.py", "print('hello')\n")
    _write(tmp_path, "legacy.py", 'print "python 2"\n')
    _write(tmp_path, "src/deep.py", "import a2a\nx = " + "-" * 100_000 + "1\n")
    _write(tmp_path, "src/big.py", "import a2a\n" + "x = 1\n" * 50_000)
    (tmp_path / "latin.py").write_bytes(b"# a2a \xff\n")
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    assert not result.surfaces_excluded
    assert sorted(result.surfaces_scanned) == [
        "a2a (no A2A configurations found)",
        "a2a: Python SDK references (heuristic)",
    ]
    assert not result.components


def test_unrelated_python_file_does_not_change_the_inventory(tmp_path):
    _write(tmp_path, ".well-known/agent.json", CARD)
    _write(tmp_path, "client.py", "from a2a.client import A2AClient\n")
    first = A2AScanner().scan(tmp_path)
    _write(tmp_path, "src/util.py", "def helper():\n    return 1\n")
    second = A2AScanner().scan(tmp_path)
    assert first.surfaces_scanned == second.surfaces_scanned
    assert first.components == second.components


def test_agent_card_built_in_code_is_a_gap(tmp_path):
    _write(
        tmp_path,
        "services/agent/server.py",
        "from a2a.types import AgentCard\n"
        "card = AgentCard(name='x', url='http://evil.example', skills=[])\n",
    )
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        "services/agent/server.py: A2A agent card built in Python code is not inventoried"
    ]
    (server,) = _servers(result)
    assert server.bom_ref == "a2a-server:code-detected"
    assert server.source_path == "services/agent/server.py"


def test_card_loaded_from_data_stays_a_gap_beside_a_static_card(tmp_path):
    # Audit 2026-11-16 S6-03: any static card hid every card loaded in code, so a
    # second agent served from other data was not inventoried and left no gap.
    _write(
        tmp_path,
        "server.py",
        "import json\nfrom a2a.types import AgentCard\n"
        "card = AgentCard.model_validate(json.load(open('cards/beta.json')))\n",
    )
    _write(tmp_path, "cards/beta.json", {**CARD, "name": "beta", "url": "http://beta.example"})
    gap = ["server.py: A2A agent card loaded in Python code is not inventoried"]
    assert A2AScanner().scan(tmp_path).surfaces_excluded == gap
    _write(tmp_path, ".well-known/agent-card.json", CARD)
    result = A2AScanner().scan(tmp_path)
    assert [server.name for server in _servers(result)] == ["billing-agent"]
    assert result.surfaces_excluded == gap and not result.scan_failures


@pytest.mark.parametrize(
    ("source", "gap"),
    [
        (
            "from a2a.types import AgentCard\ncard = AgentCard.model_validate(json.load(f))\n",
            "loaded",
        ),
        ("from a2a import types\ncard = types.AgentCard.model_validate_json(raw)\n", "loaded"),
        ("from a2a.types import AgentCard\ncard = AgentCard.parse_obj(data)\n", "loaded"),
        (
            "from a2a.types import AgentCard\n"
            "card = AgentCard.model_construct(name='x', url='http://evil.example')\n",
            "built",
        ),
    ],
    ids=["model_validate", "model_validate_json", "parse_obj", "model_construct"],
)
def test_a_card_made_by_a_class_method_is_a_gap_and_a_server(tmp_path, source, gap):
    _write(tmp_path, "server.py", source)
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        f"server.py: A2A agent card {gap} in Python code is not inventoried"
    ]
    (server,) = _servers(result)
    assert server.bom_ref == "a2a-server:code-detected"


def test_unparsable_source_naming_agent_card_is_a_gap(tmp_path):
    _write(tmp_path, "server.py", "card = AgentCard(name='x'\n")
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded and not result.scan_failures


def test_client_sdk_reference_is_named_as_a_client(tmp_path):
    _write(tmp_path, "main.py", "from a2a.client import A2AClient\nclient = A2AClient()\n")
    result = A2AScanner().scan(tmp_path)
    (client,) = result.components
    assert isinstance(client, A2AClientComponent)
    assert client.bom_ref == "a2a-client:code-detected"
    assert client.source_path == "main.py"


def test_client_aliases_are_both_inventoried(tmp_path):
    _write(
        tmp_path,
        "a2a.json",
        {
            "clients": [{"name": "a", "agentCardUrl": "https://a.example/card"}],
            "remoteAgents": [{"name": "x", "agentCardUrl": "http://evil.example/card"}],
        },
    )
    result = A2AScanner().scan(tmp_path)
    assert sorted(c.name for c in result.components) == ["a", "x"]
    client = next(c for c in result.components if c.name == "x")
    assert any(r.category == "transport_security" for r in client.risks)


def test_every_client_endpoint_field_gets_the_transport_check(tmp_path):
    _write(
        tmp_path,
        "a2a.json",
        {
            "clients": [
                {
                    "name": "x",
                    "agentCardUrl": "https://good.example/.well-known/agent-card.json",
                    "url": "http://evil.example/rpc",
                    "authMethods": ["bearer"],
                }
            ]
        },
    )
    (client,) = A2AScanner().scan(tmp_path).components
    assert client.agent_card_url == "https://good.example"
    assert client.properties["endpoint_origins"] == ["http://evil.example"]
    assert any(r.category == "transport_security" for r in client.risks)


def test_unrecognised_client_configuration_shape_is_a_gap(tmp_path):
    _write(tmp_path, "a2a.json", {"agents": [{"name": "x"}]})
    result = A2AScanner().scan(tmp_path)
    assert result.surfaces_excluded == [
        "a2a.json: unrecognised A2A client configuration shape is not inventoried"
    ]
    _write(tmp_path, "a2a.json", {})
    assert not A2AScanner().scan(tmp_path).surfaces_excluded


def test_overlong_names_are_failures_and_details_are_neutralised(tmp_path):
    _write(tmp_path, ".well-known/agent.json", {**CARD, "name": "n" * 300})
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures and not _servers(result)
    _write(tmp_path, ".well-known/agent.json", {**CARD, "name": "a\u202eb\nc", "url": "http://x"})
    (server,) = _servers(A2AScanner().scan(tmp_path))
    transport = next(r for r in server.risks if r.category == "transport_security")
    assert "\u202e" not in transport.detail and "\n" not in transport.detail


def test_inventory_is_identical_when_scanned_at_two_locations(tmp_path):
    for root in (tmp_path / "one", tmp_path / "two" / "nested"):
        _write(root, "public/.well-known/agent.json", CARD)
        _write(root, "a2a.json", {"clients": [{"name": "c", "agentCardUrl": "https://c.example"}]})
    first = A2AScanner().scan(tmp_path / "one")
    second = A2AScanner().scan(tmp_path / "two" / "nested")
    assert first.components == second.components
    assert first.surfaces_scanned == second.surfaces_scanned
    assert str(tmp_path) not in repr(first)


def test_card_read_through_an_in_root_link_names_its_target(tmp_path):
    _write(tmp_path, "public/card.json", CARD)
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "agent-card.json").symlink_to("../public/card.json")
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures
    (server,) = _servers(result)
    assert server.source_path == ".well-known/agent-card.json"
    assert server.properties["symlink_target"] == "public/card.json"


@pytest.mark.parametrize("value", [[{"agent": "planner"}], '"agent"', 3])
def test_generic_root_file_that_is_not_an_object_is_not_a_card(tmp_path, value):
    _write(tmp_path, "agent.json", value)
    _write(tmp_path, "a2a/agent.json", value)
    result = A2AScanner().scan(tmp_path)
    assert not result.scan_failures and not _servers(result)


def test_both_card_endpoint_fields_are_checked_and_digested(tmp_path):
    card = {**CARD, "endpoint": "http://agents.example.com/rpc"}
    _write(tmp_path / "a", ".well-known/agent.json", card)
    (server,) = _servers(A2AScanner().scan(tmp_path / "a"))
    assert server.endpoint_url == "https://agents.example.com"
    assert server.properties["endpoint_origins"] == ["http://agents.example.com"]
    assert any(r.category == "transport_security" for r in server.risks)
    run = _drift(tmp_path, card, {**card, "endpoint": "http://agents.example.com/a/b"})
    assert run.exit_code == 1, run.output


def test_yaml_number_overflow_in_a_client_configuration_is_a_failure(tmp_path):
    _write(tmp_path, "a2a.yaml", "x: " + ":".join(["1"] * 200) + ".0\n")
    result = A2AScanner().scan(tmp_path)
    assert result.scan_failures == ["a2a.yaml: YAML mapping parse failed or unsupported"]


def test_card_below_a_well_known_directory_link_is_recorded(tmp_path):
    _write(tmp_path, "public/wk/agent-card.json", CARD)
    (tmp_path / "public" / ".well-known").symlink_to("wk", target_is_directory=True)
    _write(tmp_path, "site/cards/Agent.json", {**CARD, "name": "Other"})
    (tmp_path / "site" / ".well-known").symlink_to("cards", target_is_directory=True)
    (tmp_path / "web").mkdir()
    (tmp_path / "web" / ".well-known").symlink_to("..", target_is_directory=True)
    result = A2AScanner().scan(tmp_path)
    (server,) = _servers(result)
    assert server.agent_card_path == "public/.well-known/agent-card.json"
    assert server.properties["symlink_target"] == "public/wk/agent-card.json"
    assert sorted(result.scan_failures) == [
        (
            "site/.well-known/Agent.json: case variant of site/.well-known/agent.json is the active "
            "file on case-insensitive file systems and is not inventoried"
        ),
        "web/.well-known/agent-card.json: symlink target is the collection root",
        "web/.well-known/agent.json: symlink target is the collection root",
    ]


@pytest.mark.parametrize(
    ("link", "target", "value"),
    [
        ("agent.json", "credentials.json", CARD),
        (".well-known/agent-card.json", ".well-known/secret.json", CARD),
        ("a2a.json", "secrets.json", {"clients": [{"name": "c", "url": "https://a.example"}]}),
    ],
)
def test_a_declaration_linked_to_a_credential_file_is_a_gap_and_not_read(
    tmp_path, link, target, value
):
    _write(tmp_path, target, {**value, "description": "SYNTH_MARKER"})
    (tmp_path / link).symlink_to(Path(target).name)
    result = A2AScanner().scan(tmp_path)
    assert result.components == [] and result.scan_failures == []
    assert result.surfaces_excluded == [
        f"{link}: a symlink leads to {target}, whose name says it holds credentials; "
        "not read or inventoried"
    ]
