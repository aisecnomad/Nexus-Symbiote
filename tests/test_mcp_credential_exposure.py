"""A literal credential in an MCP launch raises credential_exposure, which names positions only."""

from __future__ import annotations

import base64
import json
import random
import string
import tracemalloc
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.scanners import mcp
from nexus_symbiote.scanners.mcp import (
    LISTED_CREDENTIAL_POSITIONS,
    MAX_CREDENTIAL_POSITIONS,
    MCPScanner,
    _credential_positions,
    _server_hits,
    _server_launch,
    _server_secrets,
)
from nexus_symbiote.utils.secrets import names_reference
from tests.support import scaling_ratio

CATEGORY = "credential_exposure"
NAMED = "a generic secret-like value"
ENV_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_11"
SCHEME_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_12"
PASSWORD = "synthetic-launch-password-98765"  # noqa: S105 - synthetic sentinel
VENDOR_TOKEN = "ghp_" + "A1" * 18
KEY_TOKEN = "ghp_" + "B2" * 18
QUERY_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_13"
ENVFLAG_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_14"
LEAK_VALUE = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_15"
PEM_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_16"
SCRIPT_SENTINEL = "SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_17"
DEFAULT_SENTINEL = "Zx9synthPassw0rdSentinel77"  # noqa: S105 - synthetic sentinel
# A password that is also written as an env name: the name repeats a secret value.
LEAK_NAME = "synthetic-leaked-password-98765"
SENTINELS = (
    ENV_SENTINEL,
    DEFAULT_SENTINEL,
    SCHEME_SENTINEL,
    PASSWORD,
    VENDOR_TOKEN,
    KEY_TOKEN,
    QUERY_SENTINEL,
    ENVFLAG_SENTINEL,
    LEAK_VALUE,
    LEAK_NAME,
    PEM_SENTINEL,
)
PEM_BLOCK = f"-----BEGIN PRIVATE KEY-----\n{PEM_SENTINEL}\n-----END PRIVATE KEY-----"
# The independent review's benign server: each value is a path, a name, a number or
# prose under a name the scrubber treats as a credential's.
REVIEW_BENIGN = {
    "command": "npx",
    "args": [
        "-y",
        "some-mcp@1.0.0",
        "--description",
        "Basic calculator tools",
        "--title",
        "Token usage dashboard",
        "--note",
        "Authentication: handled by the gateway",
    ],
    "env": {
        "PWD": "/workspace/app2",
        "GIT_AUTHOR_NAME": "Jane Developer",
        "SSL_CERT_FILE": "/etc/ssl/certs/ca-certificates.crt",
        "GOOGLE_APPLICATION_CREDENTIALS": "/home/dev/.config/gcloud/sa.json",
        "TOKENIZER": "cl100k_base",
        "KEYBOARD_LAYOUT": "us-international",
        "SESSION_TIMEOUT_MS": "3600000000",
    },
}
REVIEW_SCRIPTS = {
    "script": {
        "command": "sh",
        "args": ["-c", 'API_TOKEN="${API_TOKEN}" exec npx -y some-mcp@1.0.0'],
    },
    "script2": {
        "command": "sh",
        "args": ["-c", "GITHUB_TOKEN=$(gh auth token) exec npx -y x@1.0.0"],
    },
    "export": {
        "command": "sh",
        "args": ["-c", "export API_TOKEN=${API_TOKEN}; exec npx -y x@1.0.0"],
    },
}
QUERY_SERVER = {"type": "sse", "url": f"https://mcp.example.com/sse?api_key={QUERY_SENTINEL}"}
ENVFLAG_SERVER = {
    "command": "docker",
    "args": ["run", f"--env=API_TOKEN={ENVFLAG_SENTINEL}", "img"],
}
LEAK_SERVER = {
    "command": "npx",
    "args": ["x@1.0.0"],
    "env": {LEAK_NAME: LEAK_VALUE, "DB_PASSWORD": LEAK_NAME},
}
PEM_SERVER = {"command": "npx", "args": ["x@1.0.0"], "env": {"TLS_MATERIAL": PEM_BLOCK}}
LITERAL = {
    "command": "npx",
    "args": ["-y", "fixture-mcp@1.2.3", "--token", VENDOR_TOKEN, f"--password={PASSWORD}"],
    "env": {"API_TOKEN": ENV_SENTINEL, "LOG_LEVEL": "info"},
    "url": "https://example.invalid/mcp",
    "headers": {"Authorization": f"Bearer {SCHEME_SENTINEL}", "X-Trace": "abc"},
}
REFERENCED = {
    "command": "npx",
    "args": ["-y", "fixture-mcp@1.2.3", "--token", "${TOKEN}", "--password=$PASSWORD"],
    "env": {"API_TOKEN": "${API_TOKEN}", "LOG_LEVEL": "info"},
    "url": "https://example.invalid/mcp",
    "headers": {"Authorization": "Bearer ${TOKEN}", "X-Trace": "abc"},
}
DEFAULT_SERVER = {
    "command": "npx",
    "args": ["-y", "fixture-mcp@1.2.3", "--token=${TOKEN:-" + DEFAULT_SENTINEL + "}"],
    "env": {"API_TOKEN": "${TOKEN-" + DEFAULT_SENTINEL + "}", "LOG_LEVEL": "${LOG_LEVEL:-info}"},
}
ALL_SERVERS = {
    "api": LITERAL,
    "default": DEFAULT_SERVER,
    "ref": REFERENCED,
    "srv": REVIEW_BENIGN,
    **REVIEW_SCRIPTS,
    "query": QUERY_SERVER,
    "envflag": ENVFLAG_SERVER,
    "leak": LEAK_SERVER,
    "pem": PEM_SERVER,
}


def _project(root: Path, servers: dict) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    return root


def _scan(root: Path, servers: dict):
    _project(root, servers)
    result = MCPScanner().scan(root)
    assert not result.scan_failures, result.scan_failures
    return result


def _servers(result) -> dict[str, MCPServerComponent]:
    return {c.name: c for c in result.components if isinstance(c, MCPServerComponent)}


def _findings(server: MCPServerComponent) -> list:
    return [risk for risk in server.risks if risk.category == CATEGORY]


def _dump(result) -> str:
    return json.dumps([c.model_dump(mode="json") for c in result.components])


def test_literal_credentials_raise_one_finding_naming_each_position(tmp_path):
    result = _scan(tmp_path, {"api": LITERAL})
    server = _servers(result)["api"]
    findings = _findings(server)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.severity == RiskSeverity.HIGH
    assert finding.detail == (
        "MCP server 'api' records a literal credential in its launch: "
        "env API_TOKEN (a generic secret-like value); "
        "argument 4 (a vendor token shape); "
        "argument 5 (a generic secret-like value); "
        "header Authorization (an authorization scheme credential)."
    )
    assert "reference" in finding.recommendation and "rotate" in finding.recommendation
    dump = _dump(result)
    assert not any(sentinel in dump for sentinel in SENTINELS)
    assert "LOG_LEVEL" not in finding.detail and "X-Trace" not in finding.detail


def test_references_and_templates_do_not_fire(tmp_path):
    result = _scan(tmp_path, {"api": REFERENCED})
    assert _findings(_servers(result)["api"]) == []


@pytest.mark.parametrize(
    ("value", "fires"),
    [
        ("${TOKEN:-" + DEFAULT_SENTINEL + "}", True),
        ("${TOKEN:=" + DEFAULT_SENTINEL + "}", True),
        ("${TOKEN-" + DEFAULT_SENTINEL + "}", True),
        ("${TOKEN:+" + DEFAULT_SENTINEL + "}", True),
        ("${TOKEN:-changeme}", False),
        ("${TOKEN:-}", False),
        ("${TOKEN:?set TOKEN}", False),
        ("${TOKEN:-${OTHER}}", False),
        ("${TOKEN:-/run/secrets/token}", False),
        ("${TOKEN:-info}", False),
    ],
    ids=[
        "colon-dash",
        "colon-equals",
        "dash",
        "colon-plus",
        "placeholder",
        "empty",
        "message",
        "nested",
        "path",
        "setting",
    ],
)
def test_a_literal_default_inside_a_shell_expansion_is_reported(tmp_path, value, fires):
    server = {
        "command": "npx",
        "args": ["-y", "fixture-mcp@1.2.3", "--token=" + value],
        "env": {"API_TOKEN": value},
    }
    result = _scan(tmp_path, {"api": server})
    findings = _findings(_servers(result)["api"])
    if fires:
        assert len(findings) == 1
        assert "env API_TOKEN (" in findings[0].detail and "argument 3 (" in findings[0].detail
    else:
        assert findings == []
    assert DEFAULT_SENTINEL not in _dump(result)


def test_the_benign_twin_differs_only_by_the_finding(tmp_path):
    literal = _servers(_scan(tmp_path / "literal", {"api": LITERAL}))["api"]
    referenced = _servers(_scan(tmp_path / "referenced", {"api": REFERENCED}))["api"]
    assert sorted(r.category for r in literal.risks if r.category != CATEGORY) == sorted(
        r.category for r in referenced.risks
    )
    assert literal.env == referenced.env


@pytest.mark.parametrize(
    "value",
    [
        "${TOKEN}",
        "$TOKEN",
        "{{ secrets.token }}",
        "Bearer ${TOKEN}",
        "  Basic $TOKEN ",
        "Token {{ vault.read('x') }}",
    ],
)
def test_names_reference_covers_bare_and_scheme_prefixed_forms(value):
    assert names_reference(value)


@pytest.mark.parametrize(
    "value",
    ["$token", "${}", "{{}}", "Bearer " + SCHEME_SENTINEL, "pa$SWORD12x", "x-${TOKEN}", "Bearer"],
)
def test_names_reference_rejects_literals_and_partial_references(value):
    assert not names_reference(value)


def test_a_token_shaped_env_key_is_withheld_from_the_detail(tmp_path):
    result = _scan(
        tmp_path, {"api": {"command": "npx", "args": ["x@1.0.0"], "env": {KEY_TOKEN: "1"}}}
    )
    server = _servers(result)["api"]
    (finding,) = _findings(server)
    assert finding.detail.endswith("in its launch: an env key (a vendor token shape).")
    assert KEY_TOKEN not in _dump(result) and KEY_TOKEN[:8] not in finding.detail


def test_a_token_shaped_header_name_is_withheld_from_the_detail(tmp_path):
    servers = {"api": {"url": "https://example.invalid/mcp", "headers": {KEY_TOKEN: "1"}}}
    result = _scan(tmp_path, servers)
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith("in its launch: a header (a vendor token shape).")
    assert KEY_TOKEN not in _dump(result)


@pytest.mark.parametrize(
    "server,expected",
    [
        (
            {
                "command": "sh",
                "args": ["-c", f'API_TOKEN="Bearer {SCHEME_SENTINEL}" exec uvx x==1.0'],
            },
            "argument 2 (an authorization scheme credential)",
        ),
        (
            {
                "command": "docker",
                "args": ["run", "-i", "-e", f"API_KEY={ENV_SENTINEL}", "img@sha256:" + "a" * 64],
            },
            "argument 4 (a generic secret-like value)",
        ),
        (
            {
                "command": "npx",
                "args": ["x@1.0.0"],
                "env": {"DATABASE_URL": "postgres://app:Sup3rSecret99@db.invalid/app"},
            },
            "env DATABASE_URL (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0"], "env": {"HF_HOME_TOKEN": "hf_" + "C3" * 15}},
            "env HF_HOME_TOKEN (a vendor token shape)",
        ),
        (
            {"url": "https://example.invalid/mcp", "headers": {"X-Api-Key": PASSWORD}},
            "header X-Api-Key (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0"], "env": {"DB_PASSWORD": f"admin:{PASSWORD}"}},
            "env DB_PASSWORD (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0"], "env": {"TOKEN": f"Xyz9:{ENV_SENTINEL}"}},
            "env TOKEN (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0", "--password", f"user:{PASSWORD}"]},
            "argument 3 (a generic secret-like value)",
        ),
        (
            {"command": "sh", "args": ["-c", f"server --token {ENV_SENTINEL} --port 1"]},
            "argument 2 (a generic secret-like value)",
        ),
    ],
)
def test_each_credential_position_is_named_with_its_pattern_class(tmp_path, server, expected):
    result = _scan(tmp_path, {"api": server})
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith(f"in its launch: {expected}.")
    assert not any(sentinel in _dump(result) for sentinel in (*SENTINELS, "Sup3rSecret99"))


@pytest.mark.parametrize(
    "server",
    [
        {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"TOKEN_URL": "https://example.invalid/oauth/token"},
        },
        {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"DATABASE_URL": "postgres://app:${DB_PASSWORD}@db.invalid/app"},
        },
        {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"DATABASE_URL": "postgres://postgres:postgres@localhost/app"},
        },
        {"command": "npx", "args": ["x@1.0.0"], "env": {"API_TOKEN": "short"}},
        {"command": "uvx", "args": ["mcp-server-tokens==10.20.30"]},
        {"command": "npx", "args": ["x@1.0.0", "--header", "Authorization: Bearer ${TOKEN}"]},
        {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"OTHER": "$OTHER_TOKEN", "TPL": "{{ secrets.token }}"},
        },
        {"url": "https://example.invalid/mcp", "headers": {"X-Api-Key": "{{ vault.key }}"}},
    ],
)
def test_locators_references_and_short_values_stay_clean(tmp_path, server):
    result = _scan(tmp_path, {"api": server})
    assert _findings(_servers(result)["api"]) == []


@pytest.mark.parametrize(
    "env",
    [
        {"API_TOKEN": 12345678},
        {"API_TOKEN": [ENV_SENTINEL]},
        {"API_TOKEN": {"nested": {"deeper": ENV_SENTINEL}}},
        {"API_TOKEN": None},
    ],
)
def test_non_string_env_values_never_crash_or_leak(tmp_path, env):
    _project(tmp_path, {"api": {"command": "npx", "args": ["x@1.0.0"], "env": env}})
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [".mcp.json: invalid server configuration"]
    assert _servers(result) == {}
    text = _dump(result) + json.dumps(result.scan_failures) + json.dumps(result.surfaces_excluded)
    assert ENV_SENTINEL not in text
    assert _positions({"env": env, "headers": env}) == []


@pytest.mark.parametrize(
    "make_value,literal",
    [
        (lambda scale: "ab:" * (750 * scale) + "x", True),
        # A run of one character over half the value reads as a placeholder (xxxxxxxx).
        (lambda scale: "ab:" * (225 * scale) + "y" * (50_000 * scale), False),
        # A value with white space is never one generic literal; it is still scrubbed.
        (lambda scale: "X-A: " * (500 * scale) + PASSWORD, False),
    ],
)
@pytest.mark.parametrize("field", ["env", "args", "headers"])
def test_colon_chains_keep_the_server_inventoried_and_stay_fast(
    tmp_path, field, make_value, literal
):
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        root.mkdir()
        value = make_value(scale)
        server: dict = {"command": "npx", "args": ["x@1.0.0"]}
        if field == "args":
            server["args"] = ["x@1.0.0", "--token", value]
        else:
            server[field] = {"API_TOKEN": value}
        _project(root, {"api": server})
        roots[scale] = root
    result = MCPScanner().scan(roots[4])
    findings = _findings(_servers(result)["api"])
    if literal:
        (finding,) = findings
        assert "(a generic secret-like value)" in finding.detail
    else:
        assert findings == []
    assert PASSWORD not in _dump(result)
    assert scaling_ratio(lambda scale: MCPScanner().scan(roots[scale])) < 10


@pytest.mark.parametrize(
    "field,value,literal",
    [
        ("env", ENV_SENTINEL, True),
        ("env", f"admin:{PASSWORD}", True),
        ("env", f"Authorization: Bearer {SCHEME_SENTINEL}", True),
        ("env", f"Bearer {SCHEME_SENTINEL}", True),
        ("env", f"https://app:{PASSWORD}@db.invalid/app", True),
        ("env", VENDOR_TOKEN, True),
        ("env", "${API_TOKEN}", False),
        ("env", "Authorization: Bearer ${TOKEN}", False),
        ("env", "postgres://app:${DB_PASSWORD}@db.invalid/app", False),
        ("env", "https://example.invalid/oauth/token", False),
        ("env", "short", False),
        ("headers", f"Bearer {SCHEME_SENTINEL}", True),
        ("headers", PASSWORD, True),
        ("headers", "Bearer ${TOKEN}", False),
        ("headers", "{{ vault.key }}", False),
        ("args", f"--token={ENV_SENTINEL}", True),
        ("args", f"run --password {PASSWORD}", True),
        ("args", f"--password=user:{PASSWORD}", True),
        ("args", "--token=${TOKEN}", False),
        ("args", "run --password $PASSWORD", False),
        ("args", "--port=8080", False),
        ("env", "2027-01-01T00:00:00Z", False),
        ("env", "Kq7mZw9x-dev-4Lp8ZtQ2vN", True),
        ("headers", "abc\r\nAuthorization: Bearer " + SCHEME_SENTINEL, True),
        ("headers", "abc\r\nX-Other: Bearer ${TOKEN}", False),
        ("args", "postgres://app:Zx9,Kv4Qm7Tn2@db.invalid/app", True),
        ("args", "https://a.invalid,https://b.invalid", False),
    ],
)
def test_the_finding_fires_exactly_where_the_scrubber_redacts_a_literal(field, value, literal):
    config: dict = {"command": "npx", "args": ["x@1.0.0"], "env": {}, "headers": {}}
    if field == "args":
        config["args"] = ["x@1.0.0", value]
    else:
        config[field] = {"API_TOKEN": value}
    positions = _positions(config)
    secrets = _server_secrets(config, _server_launch(config))
    assert bool(positions) is literal
    if positions:
        assert any(secret and secret in value for secret in secrets)


def test_a_header_shadowed_by_http_headers_is_still_reported(tmp_path):
    servers = {
        "api": {
            "url": "https://example.invalid/mcp",
            "headers": {"X-Api-Key": PASSWORD},
            "http_headers": {"X-Api-Key": "${KEY}"},
        }
    }
    result = _scan(tmp_path, servers)
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith("in its launch: header X-Api-Key (a generic secret-like value).")
    assert PASSWORD not in _dump(result)


def test_an_oversized_value_fires_without_recording_its_length(tmp_path):
    long_value = "Q7" * 5000
    args = ["x@1.0.0", "--verbose", "--token", long_value]
    result = _scan(
        tmp_path, {"api": {"command": "npx", "args": args, "env": {"API_TOKEN": long_value}}}
    )
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith(
        "env API_TOKEN (a generic secret-like value); argument 4 (a generic secret-like value)."
    )
    assert "10000" not in finding.detail and long_value[:16] not in _dump(result)


def test_non_string_arguments_are_a_collection_failure_that_leaks_nothing(tmp_path):
    args = ["x@1.0.0", 42, ["nested", ENV_SENTINEL], None, "--token", VENDOR_TOKEN]
    _project(tmp_path, {"api": {"command": "npx", "args": args}})
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures == [".mcp.json: invalid server configuration"]
    assert _servers(result) == {}
    text = _dump(result) + json.dumps(result.scan_failures) + json.dumps(result.surfaces_excluded)
    assert ENV_SENTINEL not in text and VENDOR_TOKEN not in text


def test_sentinels_never_reach_any_cli_artifact(tmp_path):
    project = _project(tmp_path / "project", ALL_SERVERS)
    out = tmp_path / "out"
    out.mkdir()
    runner = CliRunner()
    outputs: dict[str, str] = {}
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        path = out / f"scan.{fmt}"
        result = runner.invoke(
            main,
            [
                "scan",
                "--no-project-policy",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(path),
                str(project),
            ],
        )
        assert result.exit_code == 0, result.output
        outputs[f"scan-{fmt}-stdout"] = result.output
        outputs[f"scan-{fmt}"] = path.read_text(encoding="utf-8")
    inventory = str(out / "scan.json")
    for name, arguments in {
        "risk-text": ["risk", "--no-project-policy", inventory],
        "risk-json": ["risk", "--no-project-policy", "--json-output", inventory],
        "summary": ["summary", inventory],
        "summary-json": ["summary", "--json-output", inventory],
        "crosswalk-markdown": ["crosswalk", "--format", "markdown", inventory],
        "crosswalk-json": ["crosswalk", inventory],
    }.items():
        result = runner.invoke(main, arguments)
        assert result.exit_code in (0, 1), result.output
        outputs[name] = result.output
    vex = out / "findings.vex.json"
    result = runner.invoke(main, ["vex", "-o", str(vex), inventory])
    assert result.exit_code == 0, result.output
    outputs["vex"] = vex.read_text(encoding="utf-8")
    assert CATEGORY in outputs["scan-json"] and CATEGORY in outputs["risk-json"]
    assert "nexus_symbiote/credential_exposure/high" in outputs["scan-sarif"]
    assert "external/cwe/cwe-798" in outputs["scan-sarif"]
    for name, text in outputs.items():
        for sentinel in SENTINELS:
            assert sentinel not in text, name


def test_two_scans_of_a_literal_credential_are_byte_identical(tmp_path):
    project = _project(tmp_path / "project", ALL_SERVERS)
    runner = CliRunner()
    outputs = []
    for name in ("first", "second"):
        path = tmp_path / f"{name}.json"
        result = runner.invoke(
            main, ["scan", "--no-project-policy", "--report-only", "-o", str(path), str(project)]
        )
        assert result.exit_code == 0, result.output
        outputs.append(path.read_bytes())
    assert outputs[0] == outputs[1]
    assert CATEGORY in outputs[0].decode("utf-8")


def _positions(server: dict) -> list[tuple[str, str]]:
    return _credential_positions(_server_hits(server))


def test_the_review_benign_servers_raise_nothing_in_any_export(tmp_path):
    servers = {"srv": REVIEW_BENIGN, **REVIEW_SCRIPTS}
    result = _scan(tmp_path / "scan", servers)
    found = _servers(result)
    assert set(found) == set(servers)
    assert all(_findings(server) == [] for server in found.values())
    project = _project(tmp_path / "project", servers)
    runner = CliRunner()
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        path = tmp_path / f"scan.{fmt}"
        arguments = ["scan", "--no-project-policy", "--report-only", "-f", fmt, "-o", str(path)]
        outcome = runner.invoke(main, [*arguments, str(project)])
        assert outcome.exit_code == 0, outcome.output
        assert CATEGORY not in path.read_text(encoding="utf-8"), fmt
    vex = tmp_path / "findings.vex.json"
    outcome = runner.invoke(main, ["vex", "-o", str(vex), str(tmp_path / "scan.json")])
    assert outcome.exit_code == 0, outcome.output
    assert CATEGORY not in vex.read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            {"env": {"GOOGLE_APPLICATION_CREDENTIALS": "/home/dev/.config/gcloud/sa.json"}},
            {"env": {"GOOGLE_APPLICATION_CREDENTIALS": ENV_SENTINEL}},
        ),
        ({"env": {"PWD": "/workspace/app2"}}, {"env": {"PWD": PASSWORD}}),
        ({"env": {"API_KEY": "C:\\keys\\api.txt"}}, {"env": {"API_KEY": ENV_SENTINEL}}),
        ({"env": {"API_TOKEN": "./secrets/token"}}, {"env": {"API_TOKEN": "s3cr3t-T0ken"}}),
        ({"env": {"SSL_CERT_FILE": ENV_SENTINEL}}, {"env": {"SSL_CERT_PASSWORD": ENV_SENTINEL}}),
        ({"env": {"TOKENIZER": "cl100k_base"}}, {"env": {"TOKENIZER": VENDOR_TOKEN}}),
        ({"env": {"TOKEN": "cl100k_base"}}, {"env": {"TOKEN": "cl100k_b4se_Q9x2"}}),
        ({"env": {"PUBLIC_KEY": ENV_SENTINEL}}, {"env": {"LICENSE_KEY": ENV_SENTINEL}}),
        ({"env": {"GIT_AUTHOR_NAME": ENV_SENTINEL}}, {"env": {"apiKey": ENV_SENTINEL}}),
        ({"env": {"API_TOKEN": "3600000000"}}, {"env": {"API_TOKEN": "3600abcd0000"}}),
        ({"env": {"API_TOKEN_TTL": "3600abcd0000"}}, {"env": {"API_TOKEN": "3600abcd0000"}}),
        ({"env": {"DB_PASSWORD": "30000ms"}}, {"env": {"DB_PASSWORD": "30000ms-x9"}}),
        ({"env": {"SMTP_PASSWORD": "ops@example.com"}}, {"env": {"SMTP_PASSWORD": PASSWORD}}),
        (
            {"env": {"DB_DSN": "db.internal:5432"}},
            {"env": {"DB_DSN": "postgres://app:Sup3rSecret99@db.internal:5432/app"}},
        ),
        (
            {"env": {"DB_DSN": "db.internal.example.com"}},
            {"env": {"DB_DSN": "db.internal.corp:5432:" + PASSWORD}},
        ),
        (
            {"env": {"API_TOKEN": "https://auth.example.com/token"}},
            {"env": {"API_TOKEN": f"https://auth.example.com/token?token={ENV_SENTINEL}"}},
        ),
        (
            {"args": ["x@1.0.0", "--description", "Basic calculator tools"]},
            {"args": ["x@1.0.0", "--description", f"Bearer {SCHEME_SENTINEL}"]},
        ),
        (
            {"headers": {"X-Title": "Token usage dashboard"}},
            {"headers": {"X-Title": f"Token {SCHEME_SENTINEL}"}},
        ),
        (
            {"headers": {"X-Title": "Basic notebooks"}},
            {"headers": {"Authorization": "Basic notebooks"}},
        ),
        (
            {"args": ["x@1.0.0", "--note", "Authentication: handled by the gateway"]},
            {"args": ["x@1.0.0", "--note", f"Authorization: Bearer {SCHEME_SENTINEL}"]},
        ),
        (
            {"args": ["x@1.0.0", "--note", f"X-Trace: {ENV_SENTINEL}"]},
            {"args": ["x@1.0.0", "--header", f"X-Trace: Bearer {SCHEME_SENTINEL}"]},
        ),
        (
            {"args": ["-c", 'API_TOKEN="${API_TOKEN}" exec npx -y x@1.0.0']},
            {"args": ["-c", f'API_TOKEN="{SCRIPT_SENTINEL}" exec npx -y x@1.0.0']},
        ),
        (
            {"args": ["-c", "GITHUB_TOKEN=$(gh auth token) exec npx -y x@1.0.0"]},
            {"args": ["-c", f"GITHUB_TOKEN={SCRIPT_SENTINEL} exec npx -y x@1.0.0"]},
        ),
        (
            {"args": ["-c", "API_TOKEN=`gh auth token` exec npx -y x@1.0.0"]},
            {"args": ["-c", f"export API_TOKEN={SCRIPT_SENTINEL}; exec npx -y x@1.0.0"]},
        ),
        (
            {"args": ["x@1.0.0", "--token", "two words here"]},
            {"args": ["x@1.0.0", "--token", SCRIPT_SENTINEL]},
        ),
        (
            {"args": ["x@1.0.0", "a=1,token=${TOKEN}"]},
            {"args": ["x@1.0.0", "a=1,token=" + SCRIPT_SENTINEL]},
        ),
    ],
)
def test_each_benign_rule_has_a_credential_twin_that_still_fires(benign, credential):
    base: dict = {"command": "npx", "args": ["x@1.0.0"]}
    assert _positions({**base, **benign}) == []
    assert _positions({**base, **credential})


@pytest.mark.parametrize(
    "args,expected",
    [
        (["run", f"--env=API_TOKEN={ENVFLAG_SENTINEL}", "img"], "argument 2"),
        (["run", "-e", f"API_TOKEN={ENVFLAG_SENTINEL}", "img"], "argument 3"),
        (["build", "--build-arg", f"NPM_TOKEN={ENVFLAG_SENTINEL}", "."], "argument 3"),
        (["build", f"--build-arg=NPM_TOKEN={ENVFLAG_SENTINEL}", "."], "argument 2"),
    ],
)
def test_an_assignment_after_an_env_flag_fires(args, expected):
    assert _positions({"command": "docker", "args": args}) == [(expected, NAMED)]


def test_env_flag_assignment_of_a_reference_or_path_does_not_fire():
    args = ["run", "--env=API_TOKEN=${API_TOKEN}", "--env=CA_CERT_FILE=/etc/ca.pem", "img"]
    assert _positions({"command": "docker", "args": args}) == []


def test_a_credential_in_an_endpoint_url_query_fires_at_its_own_position(tmp_path):
    shaped = {"type": "http", "url": f"https://mcp.example.com/mcp?access_token={VENDOR_TOKEN}"}
    referenced = {"type": "sse", "url": "https://mcp.example.com/sse?api_key=${API_KEY}"}
    plain = {"type": "sse", "url": f"https://mcp.example.com/sse?page={QUERY_SENTINEL}"}
    servers = {"query": QUERY_SERVER, "shaped": shaped, "referenced": referenced, "plain": plain}
    found = _servers(_scan(tmp_path, servers))
    (finding,) = _findings(found["query"])
    assert finding.detail.endswith(
        "in its launch: endpoint URL query (a generic secret-like value)."
    )
    (finding,) = _findings(found["shaped"])
    assert finding.detail.endswith("in its launch: endpoint URL query (a vendor token shape).")
    assert _findings(found["referenced"]) == [] and _findings(found["plain"]) == []
    assert QUERY_SENTINEL not in json.dumps([c.model_dump(mode="json") for c in found.values()])


def test_user_information_in_an_endpoint_stays_with_transport_security(tmp_path):
    servers = {"userinfo": {"type": "sse", "url": f"https://app:{PASSWORD}@mcp.example.com/sse"}}
    result = _scan(tmp_path, servers)
    server = _servers(result)["userinfo"]
    assert _findings(server) == []
    assert any(
        risk.category == "transport_security" and "embeds credentials" in risk.detail
        for risk in server.risks
    )
    assert PASSWORD not in _dump(result)


def test_a_name_that_repeats_a_secret_value_is_withheld(tmp_path):
    result = _scan(tmp_path, {"leak": LEAK_SERVER})
    (finding,) = _findings(_servers(result)["leak"])
    assert finding.detail.endswith(
        "in its launch: env DB_PASSWORD (a generic secret-like value); "
        "an env key (a generic secret-like value)."
    )
    assert LEAK_NAME not in _dump(result) and LEAK_VALUE not in _dump(result)


@pytest.mark.parametrize(
    "server,expected",
    [
        (PEM_SERVER, "env TLS_MATERIAL (a generic secret-like value)"),
        (
            {"command": "npx", "args": ["x@1.0.0", "--material", PEM_BLOCK]},
            "argument 3 (a generic secret-like value)",
        ),
        (
            {"command": "npx", "args": ["x@1.0.0"], "env": {"CA": PEM_BLOCK[:40]}},
            "env CA (a generic secret-like value)",
        ),
    ],
)
def test_a_private_key_block_fires_under_any_name(tmp_path, server, expected):
    result = _scan(tmp_path, {"pem": server})
    (finding,) = _findings(_servers(result)["pem"])
    assert finding.detail.endswith(f"in its launch: {expected}.")
    assert PEM_SENTINEL not in _dump(result)


def _wrapped(text: str, columns: int) -> str:
    return "\n".join(text[start : start + columns] for start in range(0, len(text), columns))


_ENCODED_PEM = base64.b64encode((PEM_BLOCK + "\n").encode()).decode()
_ENCODED_ACCOUNT = base64.b64encode(
    json.dumps({"type": "service_account", "private_key": PEM_BLOCK}).encode()
).decode()


@pytest.mark.parametrize("encoded", [_ENCODED_PEM, _ENCODED_ACCOUNT])
@pytest.mark.parametrize("columns", [64, 76])
def test_a_base64_private_key_wrapped_as_base64_prints_it_fires(tmp_path, encoded, columns):
    # GNU base64 wraps at 76 columns and openssl at 64 by default.
    value = _wrapped(encoded, columns) + "\n"
    result = _scan(tmp_path, {"pem": {"command": "npx", "env": {"SERVICE_CONFIG": value}}})
    (finding,) = _findings(_servers(result)["pem"])
    assert finding.detail.endswith(
        "in its launch: env SERVICE_CONFIG (a generic secret-like value)."
    )
    assert encoded[:40] not in _dump(result)


def test_a_wrapped_base64_value_past_the_encoded_limit_is_not_decoded():
    long = _wrapped(base64.b64encode(b"\0" * 50_000 + PEM_BLOCK.encode()).decode(), 76)
    assert _positions({"command": "npx", "env": {"SERVICE_CONFIG": long}}) == []


def test_a_scheme_credential_split_across_arguments_fires_at_its_name():
    token = "Q7mX2kL9pR4tW8yZ1nB5vC3d"  # noqa: S105 - synthetic, no vendor prefix
    args = ["/c", "set", "API_TOKEN=Bearer", token, "&&", "npx", "-y", "srv@1.0.0"]
    assert _positions({"command": "cmd", "args": args}) == [
        ("argument 3", "an authorization scheme credential")
    ]


def test_a_certificate_block_is_not_a_private_key():
    certificate = "-----BEGIN CERTIFICATE-----\nMIIBszCCAVmgAwIBAgIU\n-----END CERTIFICATE-----"
    assert _positions({"command": "npx", "env": {"CA_BUNDLE": certificate}}) == []


def test_the_detail_lists_twelve_positions_and_counts_the_rest(tmp_path):
    server = {
        "command": "npx",
        "args": ["x@1.0.0", *(f"--token={ENV_SENTINEL}{index:04d}" for index in range(749))],
        "env": {f"API_TOKEN_{index:04d}": f"{SCHEME_SENTINEL}{index:04d}" for index in range(250)},
    }
    assert len(_positions(server)) == MAX_CREDENTIAL_POSITIONS
    result = _scan(tmp_path, {"api": server})
    (finding,) = _findings(_servers(result)["api"])
    listed = MAX_CREDENTIAL_POSITIONS - LISTED_CREDENTIAL_POSITIONS
    assert finding.detail.endswith(
        f"env API_TOKEN_0011 (a generic secret-like value); and at least {listed} more positions."
    )
    assert finding.detail.count("(a generic secret-like value)") == LISTED_CREDENTIAL_POSITIONS

    # A wall-clock bound failed under coverage tracing (1.26 s against 1 s on main 30bb9da6).
    # Past the position cap, scanning more credentials costs about 4x for 4x as many; a
    # quadratic recount of every position would cost about 16x.
    def run(scale: int) -> None:
        count = 200 * scale
        scaled = {
            "command": "npx",
            "args": ["x@1.0.0", *(f"--token={ENV_SENTINEL}{index:04d}" for index in range(count))],
        }
        _scan(tmp_path / f"scaled-{scale}", {"api": scaled})

    assert scaling_ratio(run) < 10
    assert len(finding.detail) < 1000
    assert ENV_SENTINEL not in _dump(result) and SCHEME_SENTINEL not in _dump(result)


def test_thirteen_positions_count_one_more_position(tmp_path):
    env = {f"API_TOKEN_{index:02d}": f"{ENV_SENTINEL}{index:02d}" for index in range(13)}
    result = _scan(tmp_path, {"api": {"command": "npx", "args": ["x@1.0.0"], "env": env}})
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith("(a generic secret-like value); and 1 more position.")


def test_the_review_literal_server_still_raises_its_three_positions(tmp_path):
    real = {
        "command": "npx",
        "args": ["-y", "x@1.0.0"],
        "env": {"API_TOKEN": ENV_SENTINEL, "DB_PASSWORD": PASSWORD},
        "headers": {"Authorization": f"Bearer {SCHEME_SENTINEL}"},
    }
    result = _scan(tmp_path, {"real": real})
    (finding,) = _findings(_servers(result)["real"])
    assert finding.detail == (
        "MCP server 'real' records a literal credential in its launch: "
        "env API_TOKEN (a generic secret-like value); "
        "env DB_PASSWORD (a generic secret-like value); "
        "header Authorization (an authorization scheme credential)."
    )
    assert not any(sentinel in _dump(result) for sentinel in SENTINELS)


@pytest.mark.parametrize(
    "value",
    [
        "%API_TOKEN%",
        "%APITOKEN%",
        "$env:API_TOKEN",
        "${{ secrets.API_TOKEN }}",
        "<your-api-key>",
        "YOUR_API_KEY_HERE",
        "changeme",
    ],
)
def test_placeholders_and_foreign_references_follow_the_value_rules(value):
    assert _positions({"command": "npx", "env": {"API_TOKEN": value}}) == []


# A random value that the scrubber's name rule does not select under SIG: only the
# finding's classifier reads it as a credential.
CLASSIFIER_ONLY = "Zq8vLm2pXr7tKw4n"  # noqa: S105 - synthetic sentinel
RANDOM = "eb0PtJYwJyiQMPj68c7HBAi01TWElQxv"  # noqa: S105 - synthetic sentinel


@pytest.mark.parametrize(
    "name",
    [
        "PGPASSWORD",
        "SMTP_PASS",
        "DB_PASS",
        "DB_PASS_RO",
        "ACCESSTOKEN",
        "AUTHTOKEN",
        "CLIENTSECRET",
        "SECRETKEY",
        "PRIVATEKEY",
        "KEY",
        "API_KEY",
        "SSH_KEY",
        "LICENSE_KEY",
        "ENCRYPTION_KEY",
        "CONNECTION_STRING",
        "REFRESH_TOKEN",
        "X-Api-Key",
        "apiKey",
        "TOKEN2",
        "Secret2",
        "DB_PW",
        "ADMIN_PSWD",
        "SMTP_PSW",
        "ADMINPW",
        "DB_PASSWORD_ROOT",
        "API_KEY_SERVICE",
        "ADMINPSWD",
        "SUPABASE_ANON_KEY",
        "PK_PASSWORD",
        "PK_PASSPHRASE",
        "SIGNING_PK_PASSWORD",
        "ANON_SMTP_PASSWORD",
        "APNS_PK_SECRET",
        "PK_API_KEY",
        "RECAPTCHA_SECRET_KEY",
    ],
)
def test_credential_names_by_their_words_fire(name):
    assert _positions({"command": "npx", "env": {name: RANDOM}}) == [(f"env {name}", NAMED)]
    assert _positions({"command": "npx", "env": {name: "${VALUE}"}}) == []


@pytest.mark.parametrize(
    "name",
    [
        "PASSTHROUGH_MODE",
        "PASSIVE",
        "PASSPORT_ID",
        "TOKENIZER",
        "PASSWORDLESS",
        "SECRETARY",
        "KEYBOARD_LAYOUT",
        "KEY_ID",
        "API_KEY_ID",
        "API_KEY_NAME",
        "SECRET_NAME",
        "COOKIE_NAME",
        "AUTH_STRATEGY",
        "TOKEN_ENDPOINT_AUTH_METHOD",
        "SECRET_BACKEND",
        "SIGNATURE_ALGORITHM",
        "SSH_KEY_FINGERPRINT",
        "PAT_SCOPE",
        "PASSWORD_POLICY",
        "BEARER_TOKEN_ENV_VAR",
        "TOKEN_PATH",
        "SECRET_DIR",
        "CACHE_KEY",
        "SORT_KEY",
        "PARTITION_KEY",
        "IDEMPOTENCY_KEY",
        "STRIPE_PUBLISHABLE_KEY",
        "JWT_VERIFY_KEY",
        "PW_POLICY",
        "PSWD_MIN_LENGTH",
        "SEED_PHRASE_FILE",
        "RECAPTCHA_SITE_KEY",
        "TURNSTILE_SITE_KEY",
        # An owner or a location of the credential: AUTH_USER=McpReader2024 is a setting.
        "JWT_AUDIENCE",
        "TOKEN_AUDIENCE",
        "TOKEN_ISSUER",
        "AUTH_PROVIDER",
        "SECRET_PROVIDER",
        "AUTH_USER",
        "AUTH_USERNAME",
        "API_KEY_USER",
        "PASSWORD_USER",
        "DB_PASSWORD_HOST",
        "AUTH_REALM",
        "AUTH_DOMAIN",
        "SECRET_ROLE",
        "AUTH_REGION",
        "TOKEN_ARN",
        "TOKEN_BUCKET",
        "TOKEN_PORT",
        "AUTH_SERVICE",
        "SECRET_ROOT",
    ],
)
def test_names_that_describe_or_index_do_not_name_a_credential(name):
    assert _positions({"command": "npx", "env": {name: RANDOM}}) == []


@pytest.mark.parametrize(
    "name",
    ["PRIMARY_KEY", "COSMOS_PRIMARY_KEY", "AZURE_STORAGE_PRIMARY_KEY", "PAGERDUTY_ROUTING_KEY"],
)
def test_a_primary_or_routing_key_holds_a_credential_at_32_random_characters(name):
    assert _positions({"command": "npx", "env": {name: CLASSIFIER_ONLY}}) == []
    assert _positions({"command": "npx", "env": {name: RANDOM}}) == [(f"env {name}", NAMED)]


@pytest.mark.parametrize(
    "benign,credential",
    [
        (["--title", RANDOM], ["--key", RANDOM]),
        (["--passthrough", RANDOM], ["--pass", RANDOM]),
        (["-t", RANDOM], ["-k", RANDOM]),
        (["--token-env", "GITHUB_TOKEN_2"], ["--token", RANDOM]),
        (["--api-key-env", RANDOM], ["--api-key", RANDOM]),
        (["--pw-file", RANDOM], ["--pw", RANDOM]),
    ],
)
def test_flag_names_follow_the_name_rules(benign, credential):
    assert _positions({"command": "npx", "args": ["x@1.0.0", *benign]}) == []
    assert _positions({"command": "npx", "args": ["x@1.0.0", *credential]})


@pytest.mark.parametrize(
    "name,value",
    [
        ("API_TOKEN", "hunter2hunter"),
        ("API_TOKEN", "kT9#vQ2!mZ7@wL4&"),
        ("API_TOKEN", "s3cr3tPw9!"),
        ("API_TOKEN", "4a472c89-f239-45be-9f67-cfdeb3c7e0f4"),
        ("API_TOKEN", "synthetic-launch-password-98765"),
        ("API_TOKEN", "S3cret.V4lue#9"),
        ("API_TOKEN", ENV_SENTINEL),
        ("DB_PASSWORD", "correct-horse-battery-staple"),
        ("DB_PASSWORD", "Zürich-Geheimnis-48-äöü"),
        ("ADMIN_PASSWORD", "$ecretPa55w0rd-Kx9"),
        ("AWS_SECRET_ACCESS_KEY", "/O9JSGiOfJUVSJYUEGcOT9nWIaokDJ9thOOJ5SAux"),
        ("AUTH_TOKEN", RANDOM + "\n"),
        ("TOTP_SECRET", "DOXSATMJWAW455UM"),
        # Base64 holds "/": a random segment is not a directory or a port's path.
        ("API_TOKEN", "aGqy4Hp4ozCBKeri7sNkZFqbIH4qNooG0UP6/myix"),
        ("API_TOKEN", "5/mgFBr7lioC8v1ydijSZhEYqIwfdyBHWXEl4g0jx"),
        ("API_TOKEN", "/g5wJ/64ojaMe8Tk6Xe89v9UaDs77mPyv1XXjMvsx"),
        # A short word between a random token's letters and digits is not a placeholder.
        ("API_TOKEN", "Q9x7dev3Kp2mY8vL"),
    ],
)
def test_password_and_token_shapes_stay_literals(name, value):
    assert _positions({"command": "npx", "env": {name: value}}) == [(f"env {name}", NAMED)]


@pytest.mark.parametrize(
    "benign,credential",
    [
        # References, also in other syntaxes, partial ones and code reads.
        ("x-${TOKEN}", "x-" + RANDOM),
        ("$api_token_2", "$ecretPa55w0rd-Kx9"),
        ("$API_TOKEN_2", "$up3rsecret99"),
        ("Bearer " + RANDOM + "$SUFFIX", "Bearer " + RANDOM + "$"),
        ("process.env.API_TOKEN", RANDOM),
        ("os.getenv('API_TOKEN')", RANDOM),
        ("GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN_2024"),
        ("vault:secret/data/app#password", RANDOM),
        ("arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/db-AbCdEf", RANDOM),
        ("op://Private/GitHub/token", RANDOM),
        ("projects/p/secrets/s/versions/1", RANDOM),
        ("fastmcp.server.auth.providers.github.GitHubProvider", RANDOM),
        # Paths and file names.
        ("keys/id_ed25519", "ab12/cd34ef"),
        ("certs/sa.json", RANDOM),
        ("id_ed25519", RANDOM),
        ("/run/secrets/token", "/O9JSGiOfJUVSJYUEGcOT9nWIaokDJ9thOOJ5SAux"),
        # Numbers, versions, images and locators.
        ("3.12.7-slim", RANDOM),
        ("docker://python:3.12.7-slim@sha256:" + "3a7c" * 16, RANDOM),
        ("vault-token-helper:0.9.12-alpine", RANDOM),
        ("auth-service:8443/api/v2", "auth-service:" + RANDOM),
        ("db.internal.corp", "db.internal.corp:5432:" + PASSWORD),
        # Placeholders.
        ("<your-api-key>", RANDOM),
        ("[api-token-1]", RANDOM),
        ("token-1...token-2", RANDOM),
        ("xxxxxxxxxxxxxxxx", RANDOM),
        ("abcdef0123456789", "42c848d5f7be8abcdef7a31c2ec5de1b"),
        ("not-needed", RANDOM),
        ("PasteTokenFromSettings", RANDOM),
        ("TODO-JIRA-4521", RANDOM),
        ("sk-your-openai-api-key-here", "sk-" + RANDOM),
        ("ghp_" + "x" * 36, VENDOR_TOKEN),
        ("AKIAIOSFODNN7EXAMPLE", VENDOR_TOKEN),
        # Word phrases and short settings under a name that is not a password's.
        ("oauth2-client-secret", "oauth2-client-secret-98765"),
        ("hmac-sha256-secret", "hmac-sha256-" + RANDOM),
        ("k8s-webhook-secret", "k8s-webhook-" + RANDOM),
        ("cl100k_base", "cl100k_base_Q9x2"),
        ("Votre-Cle-API-Ici-SVP", RANDOM),
        ("ваш-ключ-api", RANDOM),
        ("请填写1个有效的密钥", RANDOM),
        ("MixedCaseLettersValue", "MixedCaseLettersValue2024x"),
        ("mcp-gateway.internal", "mcp-gateway:" + RANDOM),
        ("mcp-gateway.internal:8443", "mcp-gateway:8443:" + RANDOM),
        ("@Microsoft.KeyVault(VaultName=v;SecretName=s)", RANDOM),
        ("os.environ/OPENAI_API_KEY", RANDOM),
    ],
)
def test_each_value_rule_has_a_credential_twin_under_the_same_name(benign, credential):
    assert _positions({"command": "npx", "env": {"API_TOKEN": benign}}) == []
    assert _positions({"command": "npx", "env": {"API_TOKEN": credential}})


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("Provided by Vault Agent", "purple monkey dishwasher lamp"),
        ("Generate an app password in account settings", "correct horse hunter2hunter"),
    ],
)
def test_a_lower_case_passphrase_counts_only_under_a_passphrase_name(benign, credential):
    assert _positions({"command": "npx", "env": {"SSH_PASSPHRASE": benign}}) == []
    assert _positions({"command": "npx", "env": {"SSH_PASSPHRASE": credential}})
    assert _positions({"command": "npx", "env": {"API_TOKEN": credential}}) == []
    args = ["x@1.0.0", "--passphrase", credential]
    assert _positions({"command": "npx", "args": args}) == [("argument 3", NAMED)]


@pytest.mark.parametrize("name", ["DB_PASSWORD", "DB_PASS", "ADMIN_PSWD", "DB_PW"])
def test_word_phrases_stay_literals_under_password_names(name):
    value = "launch-password-hunter"
    assert _positions({"command": "npx", "env": {name: value}}) == [(f"env {name}", NAMED)]
    assert _positions({"command": "npx", "env": {"API_TOKEN": value}}) == []


@pytest.mark.parametrize(
    "value",
    [
        f"Server=db;User Id=sa;Password={RANDOM};",
        f"jdbc:sqlserver://db.test:1433;user=sa;password={RANDOM}",
        f"DefaultEndpointsProtocol=https;AccountName=acme;AccountKey={RANDOM}+vQ/lWAW==",
        f"Server=tcp:db.test,1433;Initial Catalog=app;User ID=svc;Password={RANDOM};",
    ],
)
def test_a_connection_string_credential_pair_fires_under_any_name(value):
    assert _positions({"command": "npx", "env": {"STORAGE": value}}) == [("env STORAGE", NAMED)]
    benign = value.replace(RANDOM, "${DB_PASSWORD}")
    assert _positions({"command": "npx", "env": {"STORAGE": benign}}) == []


@pytest.mark.parametrize(
    "header,benign,credential",
    [
        ("Cookie", "theme=dark; lang=en-GB", f"sid={RANDOM}; theme=dark"),
        ("Cookie", "sid=${SESSION}", f"a=1; sid={RANDOM}; csrftoken={RANDOM}"),
        ("Authorization", "Bearer Personal Access Token", 'Digest username="u", response="x9Q"'),
        ("Authorization", "postgres", "hunter2hunter"),
        ("Authorization", "Bearer 请在此处填写密钥令牌", "Bearer " + RANDOM),
        ("Authorization", "Bearer test-token-1", "Bearer svc:hunter2hunter"),
        ("Authorization", "Bearer TOKEN_GOES_HERE", f"Bearer v2|{RANDOM}"),
        ("Authorization", "Basic base64(username:password)", "Basic dXNlcjpwYXNzd29yZA=="),
        ("Proxy-Authorization", "Bearer abc123", "Bearer opensesamex"),
        ("X-Custom", "Bearer opensesamex", f"Bearer {RANDOM}$"),
        ("X-Custom", "Bearer realm=api1.example.com", f"Bearer {RANDOM}%"),
    ],
)
def test_header_values_follow_the_cookie_and_authorization_rules(header, benign, credential):
    server = {"url": "https://example.invalid/mcp"}
    assert _positions({**server, "headers": {header: benign}}) == []
    assert _positions({**server, "headers": {header: credential}})


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            ["-c", 'API_TOKEN = "${API_TOKEN}" npx -y x@1.0.0'],
            ["-c", f"API_TOKEN = {RANDOM} npx -y x@1.0.0"],
        ),
        (["--opts", "retries=3,token=${TOKEN}"], ["--opts", f"retries=3,token={RANDOM},x=5"]),
        (["--opt", "/title:" + RANDOM], ["--opt", "/token:" + RANDOM]),
        (
            ["--oauth", '{"clientId": "mcp-reader", "clientSecret": "${SECRET}"}'],
            ["--oauth", f'{{"clientId": "mcp-reader", "clientSecret": "{RANDOM}"}}'],
        ),
        (
            ["--headers", '{"Authorization": "Bearer ${TOKEN}"}'],
            ["--headers", f'{{"Authorization": "Bearer {RANDOM}"}}'],
        ),
        (["--headers", '{"X-Trace": "abc"}'], ["--headers", f'{{"X-Api-Key": "{RANDOM}"}}']),
        (
            ["--config", '{"keys": [{"api_key": "${KEY}"}]}'],
            ["--config", f'{{"keys": [{{"api_key": "{RANDOM}"}}]}}'],
        ),
        (
            ["-c", "curl -u admin:${PASSWORD} https://x.test/"],
            ["-c", f"curl -u admin:{RANDOM} https://x.test/"],
        ),
        (["--secret", "id=npm2,src=.npmrc"], ["--secret", RANDOM]),
        (["--secret=mcp-api-key-v2"], [f"--secret={RANDOM}"]),
        (["--secret", "prod/mcp/api-key-2"], ["--secret", "+" + RANDOM]),
        (["--secret-id", "prod/mcp/api-key-2"], ["--secret-key", RANDOM]),
        (
            ["--note", f"X-Trace: Bearer {SCHEME_SENTINEL}"],
            [f"-HX-Trace: Bearer {SCHEME_SENTINEL}"],
        ),
        (
            [f"--note=X-Trace: Bearer {SCHEME_SENTINEL}"],
            [f"--header=X-Trace: Bearer {SCHEME_SENTINEL}"],
        ),
        (
            ["/c", "set API_TOKEN=Bearer ${TOKEN}&& npx x@1.0.0"],
            ["/c", f"set API_TOKEN=Bearer {SCHEME_SENTINEL}&& npx x@1.0.0"],
        ),
    ],
)
def test_argument_forms_have_credential_twins(benign, credential):
    assert _positions({"command": "npx", "args": ["x@1.0.0", *benign]}) == []
    assert _positions({"command": "npx", "args": ["x@1.0.0", *credential]})


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            "https://x.test/mcp?page_token=abc123def456",
            f"https://x.test/mcp?access_token={RANDOM}",
        ),
        ("https://x.test/mcp?token=<your-token>", f"https://x.test/mcp?token={RANDOM}"),
        ("https://x.test/mcp?state=" + RANDOM, f"https://x.test/mcp?x=1;api_key={RANDOM}"),
        ("https://x.test/mcp?api_key=not-needed", f"https://x.test/mcp?apiKey={RANDOM}"),
    ],
)
def test_endpoint_url_query_values_follow_the_value_rules(benign, credential):
    assert _positions({"type": "http", "url": benign}) == []
    assert _positions({"type": "http", "url": credential}) == [("endpoint URL query", NAMED)]


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            "PuTTY-User-Key-File-3: ssh-ed25519\nPublic-Lines: 2\nAAAA",
            "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\n" + RANDOM,
        ),
        (
            "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----",
            PEM_BLOCK,
        ),
        (
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl",
            "eyJ0eXBlIjogInNlcnZpY2VfYWNjb3VudCIsICJwcml2YXRlX2tleSI6ICJ4In0=",
        ),
        ("pk_live_51HqZq8vLm2pXr7tKw4nBv6y", VENDOR_TOKEN),
    ],
)
def test_private_and_public_key_material_under_any_name(benign, credential):
    assert _positions({"command": "npx", "env": {"MATERIAL": benign}}) == []
    assert _positions({"command": "npx", "env": {"MATERIAL": credential}})


def test_names_that_repeat_a_value_only_the_finding_reads_are_withheld(tmp_path):
    servers = {
        "signed": {
            "url": "https://example.invalid/mcp",
            "env": {"SIG": CLASSIFIER_ONLY},
            "headers": {CLASSIFIER_ONLY: "1", "X-Trace": "abc"},
        },
        "sibling": {"command": "npx", "args": ["x@1.0.0"], "env": {CLASSIFIER_ONLY: "1"}},
    }
    result = _scan(tmp_path, servers)
    found = _servers(result)
    (finding,) = _findings(found["signed"])
    assert finding.detail.endswith("in its launch: env SIG (a generic secret-like value).")
    signed = found["signed"].model_dump(mode="json")
    sibling = found["sibling"].model_dump(mode="json")
    assert signed["properties"]["header_names"] == ["X-Trace", "[redacted]"]
    assert list(sibling["env"]) == ["[redacted-1]"]
    assert CLASSIFIER_ONLY not in _dump(result)


def test_a_header_name_that_repeats_a_value_is_withheld_from_the_finding(tmp_path):
    servers = {
        "api": {
            "url": "https://example.invalid/mcp",
            "headers": {"X-Sig": CLASSIFIER_ONLY, CLASSIFIER_ONLY: f"Bearer {SCHEME_SENTINEL}"},
        }
    }
    result = _scan(tmp_path, servers)
    (finding,) = _findings(_servers(result)["api"])
    assert finding.detail.endswith(
        "in its launch: header X-Sig (a generic secret-like value); "
        "a header (an authorization scheme credential)."
    )
    assert CLASSIFIER_ONLY not in _dump(result)


@pytest.mark.parametrize(
    "name,benign,credential",
    [
        # A path's own signals stand even when one segment mixes cases and digits.
        ("GOOGLE_SA_KEY", "Keys/ServiceAccount2024.json", "Keys/" + RANDOM),
        ("SSH_PRIVATE_KEY", "C:\\Users\\JohnSmith\\Keys\\GoogleSA2024Prod.pem", RANDOM),
        ("TLS_KEY", "./Secrets/MyToken2024File.key", RANDOM),
        ("TLS_KEY", "/etc/ssl/private/Server2024Key.pem", "/" + RANDOM),
        ("SSH_KEY", "~/.ssh/GitHubDeploy2024Key", RANDOM),
        ("API_KEY", "Keys\\Prod2024Service.json", "Keys\\" + RANDOM),
        # Under a password name a path, an e-mail, a package or a host is still none.
        ("DB_PASSWORD", "~/.secrets/dbpassword", RANDOM),
        ("DB_PASSWORD", "C:\\keys\\dbpassword", "C:" + RANDOM),
        ("DB_PASSWORD", "\\\\server\\share\\dbpassword", RANDOM),
        ("DB_PASSWORD", "db_password_2024.txt", "db_password_2024" + RANDOM),
        ("SMTP_PASSWORD", "alerts@acme-corp.io", "alerts@" + RANDOM),
        ("DB_PASSWORD", "some-mcp@1.0.0", "some-mcp@" + RANDOM),
        ("DB_PASSWORD", "requests>=2.31", "requests" + RANDOM),
        ("DB_PASSWORD", "db-prod2.acme-corp.io:5432", "p4ssw0rd.secure"),
        ("DB_PASSWORD", "5432/postgres2", "kx9vq2.zrtpwm"),
        ("TOKEN_SERVER_IMAGE", "acme/token-server:main", "acme/token-server:" + RANDOM),
    ],
)
def test_paths_and_locators_have_twins_under_credential_names(name, benign, credential):
    assert _positions({"command": "npx", "env": {name: benign}}) == []
    assert _positions({"command": "npx", "env": {name: credential}}) == [(f"env {name}", NAMED)]


def test_a_kustomize_directory_after_k_is_a_path():
    args = ["apply", "-k", "overlays/prod-Cluster2024A"]
    assert _positions({"command": "kubectl", "args": args}) == []
    args = ["apply", "-k", "aGqy4Hp4ozCBKeri7sNkZFqbIH4qNooG0UP6/myix"]
    assert _positions({"command": "kubectl", "args": args}) == [("argument 3", NAMED)]


@pytest.mark.parametrize(
    "value", ["Correct Horse Battery Staple 9", "Tr0ub4dor & 3 Horses!", "purple Monkey dishwasher"]
)
def test_a_passphrase_counts_in_any_case_and_punctuation(value):
    assert _positions({"command": "npx", "env": {"DB_PASSWORD": value}}) == [
        ("env DB_PASSWORD", NAMED)
    ]
    args = ["x@1.0.0", "--password", value]
    assert _positions({"command": "npx", "args": args}) == [("argument 3", NAMED)]
    script = ["-c", f"PGPASSWORD='{value}' psql -h db -U app"]
    assert _positions({"command": "sh", "args": script}) == [("argument 2", NAMED)]
    assert _positions({"command": "npx", "env": {"DB_PASSWORD": "Set in the Vault UI"}}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("{api_token}", "a{b}cDe9!xYz"),
        ("{{ secrets.API_TOKEN }}", "Pa$$w0rd{2024}"),
        ("#{api.token}", "hunter2{x}Kq9"),
        ("x-$API_TOKEN", "hunter2hunter$X"),
    ],
)
def test_braces_and_dollars_are_references_only_around_a_name(benign, credential):
    assert _positions({"command": "npx", "env": {"DB_PASSWORD": benign}}) == []
    assert _positions({"command": "npx", "env": {"DB_PASSWORD": credential}})


def test_an_odbc_password_in_braces_is_read_without_them():
    dsn = "Driver={ODBC Driver 18 for SQL Server};Server=db;Uid=sa;Pwd={%s};"
    assert _positions({"command": "npx", "env": {"ODBC_DSN": dsn % "Qx7!vR2#mL9pZ"}}) == [
        ("env ODBC_DSN", NAMED)
    ]
    assert _positions({"command": "npx", "env": {"ODBC_DSN": dsn % "${DB_PASSWORD}"}}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            'export API_KEY="${API_KEY:?set API_KEY}" && exec node s.js',
            f'export API_KEY="{RANDOM}" && exec node s.js',
        ),
        (
            'API_KEY="${API_KEY:-not set yet}" exec node s.js',
            f'API_KEY="{RANDOM}" exec node s.js',
        ),
        (
            'node -e "const apiKey = fs.readFileSync(keyPath).toString(); start(apiKey)"',
            f'node -e "const apiKey = {RANDOM}; start(apiKey)"',
        ),
        (
            'python -c \'import keyring; token = keyring.get_password("mcp", "me"); main(token)\'',
            f"python -c 'import keyring; token = {RANDOM}; main(token)'",
        ),
    ],
)
def test_script_references_and_code_reads_have_literal_twins(benign, credential):
    assert _positions({"command": "sh", "args": ["-c", benign]}) == []
    assert _positions({"command": "sh", "args": ["-c", credential]}) == [("argument 2", NAMED)]


def test_a_chained_code_read_in_an_env_value_is_a_reference():
    value = "require('fs').readFileSync('/run/secrets/api_key','utf8').trim()"
    assert _positions({"command": "npx", "env": {"API_KEY": value}}) == []


@pytest.mark.parametrize(
    "name,benign,credential",
    [
        ("GITHUB_TOKEN", "ghp_YourGitHubTokenGoesHere1234567890ab", VENDOR_TOKEN),
        ("API_TOKEN", "YourApiKeyHere123", "Kx9TestQ2vL7pZr4Tn8Wb"),
        ("DB_PASSWORD", "MyDevPassword9", "Mv9Pass2024Qx7"),
        ("AUTH_SCHEME", "OAuthClientCredentials", "OAuthClient" + RANDOM),
        ("TOKEN_LIFETIME", "P1DT12H30M", "P1DT12H30M" + RANDOM),
        ("JWT_ALGORITHMS", "RS256,ES256", "RS256," + RANDOM),
        ("TOKEN_GRANT", "urn:ietf:params:oauth:grant-type:token-exchange", "urn" + RANDOM),
        ("SECRET_ROTATION", "rotate-every-90d", "rotate-every-" + RANDOM),
        ("AUTH_FLOW", "oauth2:client_credentials", "oauth2:" + RANDOM),
    ],
)
def test_camel_placeholders_and_settings_have_twins(name, benign, credential):
    assert _positions({"command": "npx", "env": {name: benign}}) == []
    assert _positions({"command": "npx", "env": {name: credential}})


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("PASSWORD_HASHER", "DB_PASSWORD"),
        ("PASS_THROUGH_HEADERS", "PASS"),
        ("COMPILER_PASS", "SMTP_PASS"),
        ("FIRST_PASS", "DB_PASS_RO"),
        ("passwordField", "passwordValue"),
    ],
)
def test_a_pass_that_is_a_stage_or_a_field_is_not_a_password(benign, credential):
    value = "dead-code-elimination-" + RANDOM
    assert _positions({"command": "npx", "env": {benign: value}}) == []
    assert _positions({"command": "npx", "env": {credential: value}}) == [
        (f"env {credential}", NAMED)
    ]
    args = ["x@1.0.0", "--first-pass", "analysis2024"]
    assert _positions({"command": "npx", "args": args}) == []
    config = '{"passwordField": "user_password_hash"}'
    assert _positions({"command": "npx", "args": ["x@1.0.0", "--config", config]}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            "host=db port=5432 user=app password=${PGPASSWORD} dbname=app",
            "host=db port=5432 user=app password=Vq8mT3xL2pK dbname=app",
        ),
        ("host=db password=Vq8mT3xL2pK", "user=app password=Vq8mT3xL2pK dbname=app"),
    ],
)
def test_a_libpq_keyword_string_is_read_pair_by_pair(benign, credential):
    assert _positions({"command": "npx", "env": {"LIBPQ": benign}}) == []
    assert _positions({"command": "npx", "env": {"LIBPQ": credential}}) == [("env LIBPQ", NAMED)]


def test_a_user_flag_in_a_cluster_of_short_flags_is_read():
    script = "curl -su admin:Vq8mT3xL2pR7 https://x.test/"
    assert _positions({"command": "sh", "args": ["-c", script]}) == [("argument 2", NAMED)]
    benign = "curl -su admin:${PASSWORD} https://x.test/"
    assert _positions({"command": "sh", "args": ["-c", benign]}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("theme=dark; lang=en-US; tz=Europe/Berlin", "sid=Kx9mQ2vL7pZr; theme=dark"),
        (
            "_ga=GA1.2.987654321.1609459200; _gid=GA1.2.112233445.1609459201",
            f"prefs={RANDOM}; theme=dark",
        ),
    ],
)
def test_preference_and_analytics_cookies_hold_no_credential(benign, credential):
    server = {"url": "https://example.invalid/mcp"}
    assert _positions({**server, "headers": {"Cookie": benign}}) == []
    assert _positions({**server, "headers": {"Cookie": credential}}) == [("header Cookie", NAMED)]


def test_a_putty_key_in_base64_fires_under_any_name():
    key = "PuTTY-User-Key-File-3: ssh-ed25519\nPrivate-Lines: 1\n" + RANDOM + "\n"
    public = "PuTTY-User-Key-File-3: ssh-ed25519\nPublic-Lines: 2\n" + RANDOM + "\n"
    encoded = base64.b64encode(key.encode()).decode()
    assert _positions({"command": "npx", "env": {"MATERIAL": encoded}}) == [("env MATERIAL", NAMED)]
    benign = base64.b64encode(public.encode()).decode()
    assert _positions({"command": "npx", "env": {"MATERIAL": benign}}) == []


@pytest.mark.parametrize(
    "name,value",
    [
        ("STRIPE_KEY", "pk_live_51HqZq8vLm2pXr7tKw4nBv6y"),
        ("POSTHOG_API_KEY", "phc_Kx9mQ2vL7pZr4Tn8Wb3Yc6Hd1aBcDeFgHiJkLmN"),
        ("JWT_KEY", "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + RANDOM),
    ],
)
def test_public_material_by_value_holds_no_credential_under_credential_names(name, value):
    assert _positions({"command": "npx", "env": {name: value}}) == []
    twin = "sk_" + value[3:] if value.startswith("pk_") else RANDOM
    assert _positions({"command": "npx", "env": {name: twin}})


@pytest.mark.parametrize("benign,credential", [("aB3$x9", "aB3$x9Kq"), ("Kx9mQ2v", "Kx9mQ2vL")])
def test_a_literal_needs_eight_characters(benign, credential):
    for name in ("DB_PASSWORD", "API_TOKEN"):
        assert _positions({"command": "npx", "env": {name: benign}}) == []
        assert _positions({"command": "npx", "env": {name: credential}})


@pytest.mark.parametrize(
    "benign,credential",
    [
        (
            '{"a": {"b": [{"apiKey": "${API_KEY}"}]}}',
            f'{{"a": {{"b": [{{"apiKey": "{RANDOM}"}}]}}}}',
        ),
        (
            '{"headers": {"Cookie": "theme=dark; lang=en"}}',
            f'{{"headers": {{"Cookie": "sid={RANDOM}; theme=dark"}}}}',
        ),
        (
            '{"headers": {"Authorization": "postgres"}}',
            '{"headers": {"Authorization": "svc:hunter2hunter"}}',
        ),
    ],
)
def test_a_json_env_value_is_walked_with_header_semantics(benign, credential):
    assert _positions({"command": "npx", "env": {"MCP_CONFIG": benign}}) == []
    assert _positions({"command": "npx", "env": {"MCP_CONFIG": credential}}) == [
        ("env MCP_CONFIG", NAMED)
    ]


@pytest.mark.parametrize(
    "name,benign,credential",
    [
        (
            "CONN",
            "Server=db;User Id=sa;Database=correct-horse-battery-staple;",
            "Server=db;User Id=sa;Password=correct-horse-battery-staple;",
        ),
        ("CONN", f"Password={RANDOM};", f"Server=db;Password={RANDOM};"),
        (
            "NETRC",
            "machine api.acme.io login bot password ${NETRC_PASSWORD}",
            f"machine api.acme.io login bot password {RANDOM}",
        ),
        ("X", "Bearer error=invalid_token2X", "Bearer invalid_token2X"),
        ("API_TOKEN", "@/run/secrets/api", "@" + RANDOM),
        ("API_TOKEN", "process.env.API_TOKEN;", RANDOM + ";"),
    ],
)
def test_connection_netrc_challenge_and_code_read_rules_have_twins(name, benign, credential):
    assert _positions({"command": "npx", "env": {name: benign}}) == []
    assert _positions({"command": "npx", "env": {name: credential}})


def test_a_name_holding_a_variable_name_or_a_word_value_is_kept(tmp_path):
    servers = {
        "a": {"command": "uvx", "args": ["x", "--api-key-env", "OPENAI_API_KEY"]},
        "b": {"command": "uvx", "args": ["x"], "env": {"OPENAI_API_KEY": "${OPENAI_API_KEY}"}},
        "c": {"command": "uvx", "args": ["x"], "env": {"SECRET_KEY": "production"}},
        "d": {"command": "uvx", "args": ["x"], "env": {"production_DB_HOST": "db.invalid"}},
        "e": {
            "url": "https://example.invalid/mcp",
            "headers": {"X-Auth-Header-Name": "X-Api-Key", "X-Api-Key": "${KEY}"},
        },
        "f": {"command": "uvx", "args": ["x"], "env": {"API_TOKEN": "oauth2-client-secret-xyz"}},
        "g": {"command": "uvx", "args": ["x"], "env": {"oauth2-client-secret-xyz": "1"}},
    }
    found = _servers(_scan(tmp_path, servers))
    assert all(_findings(server) == [] for server in found.values())
    assert list(found["b"].env) == ["OPENAI_API_KEY"]
    assert list(found["d"].env) == ["production_DB_HOST"]
    assert list(found["g"].env) == ["[redacted-1]"]
    assert "X-Api-Key" in found["e"].properties["header_names"]


def test_a_server_named_after_its_own_classifier_literal_is_withheld(tmp_path):
    sig, user, cookie, plain = (f"Qz6{index}Kp7Lm9Rt3Vw" for index in range(1, 5))
    servers = {
        sig: {"command": "uvx", "args": [f"--sig={sig}"]},
        user: {"command": "uvx", "args": ["-u", f"bob:{user}"]},
        cookie: {"url": "https://a.example.com/mcp", "headers": {"Cookie": f"sid={cookie}"}},
        "plain": {
            "command": "uvx",
            "args": ["t"],
            "env": {"SIG": plain},
            "tools": [{"name": plain, "description": f"uses {plain} and {sig}"}],
        },
    }
    result = _scan(tmp_path, servers)
    dump = _dump(result)
    for literal in (sig, user, cookie, plain):
        assert literal not in dump
    details = [
        risk.detail
        for component in result.components
        if isinstance(component, MCPServerComponent)
        for risk in _findings(component)
    ]
    assert len(details) == 4
    assert not any(literal in detail for detail in details for literal in (sig, user, cookie))


def test_a_refused_servers_classifier_literal_is_withheld_from_a_sibling_name(tmp_path):
    literal = "Rf41Kp7Lm9Rt3Vw"
    servers = {
        "refused": {"command": "uvx", "args": "notalist", "env": {"SIG": literal}},
        "sib": {"command": "uvx", "args": ["t"], "env": {literal: "2", "N": "x"}},
    }
    _project(tmp_path, servers)
    result = MCPScanner().scan(tmp_path)
    assert result.scan_failures
    assert list(_servers(result)["sib"].env) == ["N", "[redacted-1]"]
    assert literal not in _dump(result)


def test_each_argument_is_split_into_shell_words_once_for_the_finding(tmp_path, monkeypatch):
    split: list[str] = []
    words = mcp._launch_words

    def counting(texts):
        texts = list(texts)
        split.extend(text for text in texts if " " in text)
        return words(texts)

    monkeypatch.setattr(mcp, "_launch_words", counting)
    script = f"API_TOKEN={RANDOM} exec npx -y x@1.0.0"
    result = _scan(tmp_path, {"script": {"command": "sh", "args": ["-c", script]}})
    assert _findings(_servers(result)["script"])
    # Once for the scrubber's launcher values and once for the finding.
    assert split.count(script) == 2
    long_script = script + " " + "x" * mcp._SHELL_SPLIT_LIMIT
    split.clear()
    assert _positions({"command": "sh", "args": ["-c", long_script]}) == [("argument 2", NAMED)]
    assert long_script not in split


@pytest.mark.parametrize("value", ["$up3rsecret99", "$hunter_two_pw"])
def test_a_lower_case_shell_variable_is_a_password_under_a_password_name(value):
    assert _positions({"command": "npx", "env": {"SMTP_PASSWORD": value}}) == [
        ("env SMTP_PASSWORD", NAMED)
    ]


def test_a_negated_flag_names_no_credential():
    args = ["x@1.0.0", "--no-password", "service1.internal"]
    assert _positions({"command": "npx", "args": args}) == []
    args = ["x@1.0.0", "--password", "service1.internal"]
    assert _positions({"command": "npx", "args": args}) == [("argument 3", NAMED)]


SHAPE = "a vendor token shape"
JWT = "eyJ" + "SENTINEL" * 2 + ".eyJ" + "SENTINEL" * 3 + "." + "SENTINEL" * 4
# Each body is a low-entropy sentinel in the vendor's alphabet and length.
UNLISTED_SHAPES = {
    "DIGITALOCEAN": "do" + "p_v1_" + "0a1b" * 16,
    "LINEAR": "lin" + "_api_" + "SENTINEL" * 5,
    "ATLASSIAN": "ATA" + "TT3" + "xFfGF0" + "SENTINEL" * 6 + "=" + "0A1B2C3D",
    "SOPS_AGE": "AGE-SECRET" + "-KEY-1" + ("SYNTHETC" * 8)[:58],
    "DISCORD_BOT": ("N0" + "SENTINEL" * 3)[:24] + "." + "SENTNL" + "." + ("SENTINEL" * 5)[:38],
}


@pytest.mark.parametrize("name", sorted(UNLISTED_SHAPES))
def test_unlisted_vendor_prefixes_are_token_shapes_under_any_name(name):
    token = UNLISTED_SHAPES[name]
    assert _positions({"command": "npx", "env": {name: token}}) == [(f"env {name}", SHAPE)]
    assert _positions({"command": "npx", "env": {name: token[:20]}}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        ({"SUPABASE_ANON_KEY": JWT}, {"SUPABASE_SERVICE_ROLE_KEY": JWT}),
        ({"NEXT_PUBLIC_SUPABASE_KEY": JWT}, {"SUPABASE_KEY": JWT}),
        ({"ANONYMOUS_TOKEN": JWT}, {"JWT_SECRET": JWT}),
        ({"PK": JWT}, {"SUPABASE_ANON_KEY": VENDOR_TOKEN}),
        ({"SUPABASE_ANON_KEY": "Bearer " + JWT}, {"PUB_SUB_TOKEN": JWT}),
        ({"PUBLIC_ANON_KEY": JWT}, {"JWT_VERIFY_KEY": JWT}),
    ],
)
def test_a_jwt_under_a_public_name_is_published_by_design(benign, credential):
    assert _positions({"command": "npx", "env": benign}) == []
    assert [kind for _, kind in _positions({"command": "npx", "env": credential})] == [SHAPE]


MNEMONIC = "alpha bravo delta echo golf hotel india kilo lima mike oscar papa"
MNEMONIC_WORDS = MNEMONIC.split(" ")


@pytest.mark.parametrize(
    "name,benign,credential",
    [
        ("WALLET_MNEMONIC", " ".join(MNEMONIC_WORDS[:11]), " ".join(MNEMONIC_WORDS)),
        ("SEED_PHRASE", " ".join((MNEMONIC_WORDS * 2)[:13]), " ".join(MNEMONIC_WORDS * 2)),
        ("RECOVERY_PHRASE", "/run/secrets/seed", " ".join((MNEMONIC_WORDS * 2)[:15])),
        ("SEEDPHRASE", "${SEED_PHRASE}", " ".join((MNEMONIC_WORDS * 2)[:18])),
        ("MNEMONIC", "english", " ".join((MNEMONIC_WORDS * 2)[:21])),
        ("WALLET_MNEMONIC", " ".join((MNEMONIC_WORDS * 3)[:27]), "  ".join(MNEMONIC_WORDS)),
        ("MNEMONIC", " ".join(MNEMONIC_WORDS[:4]), " ".join(MNEMONIC_WORDS).title()),
        ("MNEMONIC_LANGUAGE", "english", "Kx9Qm7Tn2Lp8Wz4R"),
    ],
)
def test_a_seed_phrase_counts_only_under_a_mnemonic_name(name, benign, credential):
    assert _positions({"command": "npx", "env": {name: benign}}) == []
    assert _positions({"command": "npx", "env": {name: credential}}) == [(f"env {name}", NAMED)]
    phrase = {"API_TOKEN": " ".join(MNEMONIC_WORDS), "SEED": "42", "RANDOM_SEED": "1234"}
    assert _positions({"command": "npx", "env": phrase}) == []


@pytest.mark.parametrize(
    "name,benign,credential",
    [
        ("TOKEN_EXPIRES_AT", "2027-01-01T00:00:00Z", "2027-01-01-Kx9Qm7Tn2Lp8"),
        ("TOKEN", "2027-01-01T00:00:00.123+02:00", "2027-01-01T00:00:00Zx9Kq"),
        ("TOKEN", "2026-11-19", "2026-11-19.Kx9Qm7"),
        ("API_TOKEN", "Mon, 01 Jan 2027 00:00:00 +0000", RANDOM),
        ("DB_PASSWORD", "Mon, 01 Jan 2027 00:00:00 GMT", "Mon-01-Jan-Kx9Qm7"),
        ("API_TOKEN", "1h30m", "1h30m-Kx9Qm7Tn2"),
        ("API_TOKEN", "PT15M", RANDOM),
        ("TOKEN_CREATED", "20270101T000000Z", "20270101T000000Zx9Kq"),
        ("TOKEN_ISSUED_AT", "20270101000000Z", "20270101000000Zx9Kq"),
        ("SECRET_VALID_UNTIL", "01-Jan-2027", "01-Jan-2027-Kx9Qm7"),
        ("SECRET_VALID_UNTIL", "2027-01-01_00-00-00", "2027-01-01_Kx9Qm7Tn"),
        ("API_KEY_CREATED", "2027-001T00:00:00Z", "2027-001T00:00:00Zx9Kq"),
        ("TOKEN_CREATED", "2027-W01-1", "2027-W01-1-Kx9Qm7"),
        ("TOKEN_CREATED", "2027-01-01T00:00:00Z/2027-02-01T00:00:00Z", "2027-01-01/Kx9Qm7Tn2"),
        ("PASSWORD_CHANGED_AT", "2027-01-01T00:00:00.000000000Z", "2027-01-01T00:00:00.Kx9Q"),
        ("API_TOKEN", "12:30:45.250", "12:30:45:Kx9Qm7Tn"),
        # A value under a credential name is judged whole before it is an option list.
        ("DB_PASSWORD", "sslmode=require", "T=/0NbJEjel_"),
        ("DB_PASSWORD", "<db-password>", "aB3[x9]Kq7mZw"),
        ("DB_PASSWORD", "pre-[your password]", "aB3<x9>Kq7mZw"),
        ("API_KEY", "sk-proj-your-key-here", "Kq7mZw9x-dev-4Lp8ZtQ2vN"),
        ("API_KEY", "test-token-dev", "Kq7mZw9x-test-4Lp8ZtQ2vN"),
        ("API_KEY", "changeme-later", "Kq7mZw9x-my-4Lp8ZtQ2vN"),
        ("COSMOS_PRIMARY_KEY", "id", RANDOM),
        ("PRIMARY_KEY", "/tenantId", RANDOM),
        ("ROUTING_KEY", "orders.created", RANDOM),
        ("API_TOKEN", "prefix-<token-1>", "prefix-" + RANDOM),
        ("IGNORE_PAT", "^tmp_[0-9]+$", "Kq7[x9]mZw"),
        ("API_TOKEN", "ENC[AES256_GCM,data:9aBc,iv:x,tag:y,type:str]", "ENC" + RANDOM),
        ("DB_PASSWORD", "sslmode=require&connect_timeout=10", "kq=7mZw9x4Lp8"),
        ("DB_PASSWORD", "SameSite=Lax;Secure", "W3=8gXJ>+z(OJ^oC"),
        ("COOKIE_OPTS", "Secure;HttpOnly;SameSite=Strict;Path=/", "AB=x9!Qm7Tn2"),
        ("TOKEN_FLAGS", "Kind=Bearer,Scope=ReadWrite,Lifetime=3600", "Kq=7mZw9x4Lp8"),
        ("PASSWORD_OPTIONS", "Algorithm=Argon2id,Iterations=3", "alq_=A[WxOC@!,.+fWc"),
        ("SECRET_OPTIONS", "RotationDays=90,AutoRotate=true", "ab=Kq7mZw9x!4Lp8"),
        ("DB_PASSWORD", "[db password]", "h^um<>7^qcp"),
        ("DB_PASSWORD", "<db password>", "!ir]X[]osfX~D7pLJ"),
        ("API_TOKEN", "[Kq7mZw9x4Lp8]", RANDOM),
        ("API_TOKEN", "Kq7mZw9x4Lp8-Zt9Q2vNx7Kp-<My-Key>", RANDOM),
        ("API_TOKEN", "Kq7mZw9x<API_TOKEN>", RANDOM),
        ("API_TOKEN", "Kq7mZw9x4Lp8ZtQ2vN-dev", "Kq7mZw9x4Lp8ZtQ2vN-Wz4"),
        ("API_TOKEN", "8443/api/v2", RANDOM),
        ("REDIS_PASS", "${REDIS_PASS}", "60/<Bjf,@U=W(4(ZtO^"),
        ("DB_PASSWORD", "1h30m15s", "1h30m15sKq"),
        ("DB_PASSWORD", "ops@example.com", "x@hunter.secure"),
        ("DB_PASSWORD", "deploy@db.example.com", "pa@ssw0rd.secure"),
        ("DB_PASSWORD_ROOT", "root", PASSWORD),
        ("API_KEY_SERVICE", "billing-api", RANDOM),
        ("REDIS_PASSWORD", "ops@example.com", "p@ssw0rd.secure"),
        ("REDIS_PASSWORD", "deploy@db.example.com", "p@ss.w0rd.secure"),
        (
            "DATABASE_URL",
            "https://a.example.com,https://b.example.com/x",
            "postgres://app:" + "xJ69,Y2x" + "@db.example.com/app",
        ),
    ],
)
def test_narrowed_value_rules_have_credential_twins(name, benign, credential):
    assert _positions({"command": "npx", "env": {name: benign}}) == []
    assert _positions({"command": "npx", "env": {name: credential}}) == [(f"env {name}", NAMED)]


def test_dates_durations_and_addresses_are_settings_under_any_name():
    env = {
        "SESSION_EXPIRY": "1h30m",
        "KEY_ROTATED_ON": "2026-11-19",
        "TOKEN_TTL": "P1D",
        "SMTP_FROM": "p@ssw0rd.secure",
        "SSH_TARGET": "deploy@host.example.com",
    }
    assert _positions({"command": "npx", "env": env}) == []


@pytest.mark.parametrize(
    "benign,credential",
    [
        ("abc\r\nX-Request-Id: 42", "abc\r\nAuthorization: Bearer " + SCHEME_SENTINEL),
        ("abc\nAuthorization: Bearer ${TOKEN}", "abc\nX-Api-Key: " + RANDOM),
        ("abc\rX-Note: see the docs", "abc\rCookie: sid=" + RANDOM),
    ],
)
def test_a_header_line_injected_after_a_line_break_is_read(benign, credential):
    assert _positions({"url": "https://x.invalid/mcp", "headers": {"X-Trace": benign}}) == []
    found = _positions({"url": "https://x.invalid/mcp", "headers": {"X-Trace": credential}})
    assert [position for position, _ in found] == ["header X-Trace"]


@pytest.mark.parametrize(
    "command,args,fires",
    [
        ("docker", ["run", "-u", "www-data:www-data", "img"], False),
        ("docker", ["run", "--user", "app-user:app-group", "img"], False),
        ("podman", ["run", "-u", "1001:docker-grp", "img"], False),
        ("docker", ["run", "-u", "app:Kq7mZw9x4Lp8", "img"], True),
        ("curl", ["-u", "svc:Zx9Kv4Qm7Tn2Lp8", "https://x.invalid/"], True),
        ("curl", ["-u", "svc:hunter-two-pw", "https://x.invalid/"], True),
        ("http", ["-a", "svc:hunter-two-pw", "https://x.invalid/"], True),
        ("sh", ["-c", "wget --user=svc --password=hunter-two-pw https://x.invalid/"], True),
        ("sh", ["-c", "docker run -u www-data:www-data img"], False),
        ("docker", ["run", "-u", "AppUser42:AppGroup", "img"], False),
        ("npx", ["-y", "x@1.0.0", "-a", "region:EuWest2024x"], False),
        ("npx", ["-y", "x@1.0.0", "-u", "region:EuWest2024x"], True),
        ("http", ["--auth", "svc:hunter-two-pw", "https://x.invalid/"], True),
        ("wget", ["--user", "svc:hunter-two-pw", "https://x.invalid/"], True),
        ("/usr/bin/curl", ["-u", "svc:hunter-two-pw", "https://x.invalid/"], True),
        ("sh", ["-c", "curl -u svc:hunter-two-pw https://x.invalid/"], True),
        ("sh", ["-c", "npx x -u svc:hunter-two-pw"], False),
    ],
)
def test_a_user_flag_is_a_password_pair_for_fetchers_or_a_literal(command, args, fires):
    assert bool(_positions({"command": command, "args": args})) is fires


def test_a_long_argument_of_assignments_scales_linearly():
    def run(scale: int) -> object:
        words = " ".join(f"password=Kx9Qm{index:07d}Lp8" for index in range(9_000 * scale))
        return _positions({"command": "sh", "args": ["-c", words]})

    assert scaling_ratio(run, factor=10) < 25


def test_a_name_that_repeats_a_value_the_scrubber_holds_is_withheld(tmp_path):
    word, phrase = "letmein" * 2, "secret-for-prod-1"
    servers = {
        "a": {"command": "uvx", "args": ["x"], "env": {"DB_SECRET": word, word: "1"}},
        "b": {
            "url": "https://example.invalid/mcp",
            "headers": {"X-Client-Secret": phrase, phrase: "Bearer " + "SYNTHETIC" * 3},
        },
        "c": {"command": "uvx", "args": ["x"], "env": {"DB_PASSWORD": "Sunshinesummer"}},
        "d": {"command": "uvx", "args": ["x"], "env": {"Sunshinesummer": VENDOR_TOKEN}},
    }
    result = _scan(tmp_path, servers)
    found = _servers(result)
    assert list(found["a"].env) == ["DB_SECRET", "[redacted-1]"]
    (finding,) = _findings(found["b"])
    assert finding.detail.endswith("in its launch: a header (an authorization scheme credential).")
    (finding,) = _findings(found["d"])
    assert finding.detail.endswith("in its launch: an env key (a vendor token shape).")
    dump = _dump(result) + json.dumps([risk.detail for risk in _all_findings(result)])
    assert word not in dump and phrase not in dump and "Sunshinesummer" not in dump


def _all_findings(result) -> list:
    return [risk for server in _servers(result).values() for risk in _findings(server)]


@pytest.mark.parametrize(
    "name,value",
    [("DB_PSW", "correct-horse-battery"), ("ADMINPW", "correct-horse-battery")],
)
def test_abbreviated_password_names_read_a_phrase_as_a_password(name, value):
    assert _positions({"command": "npx", "env": {name: value}}) == [(f"env {name}", NAMED)]
    assert _positions({"command": "npx", "env": {"API_TOKEN": value}}) == []


def test_a_libpq_keyword_string_counts_from_three_to_sixty_four_pairs():
    pairs = "host=db port=5432 user=app password=Kq7mZw9x4Lp8 dbname=app sslmode=require"
    assert _positions({"command": "npx", "env": {"PGCONN": pairs}})
    many = " ".join(f"k{index}=v" for index in range(70)) + " password=Kq7mZw9x4Lp8"
    assert _positions({"command": "npx", "env": {"PGCONN": many}}) == []


def test_a_name_that_repeats_a_reported_literal_is_withheld_even_in_upper_case(tmp_path):
    literal = "POSTGRES_PASSWORD_" + "9" * 4
    servers = {
        "a": {"command": "uvx", "args": ["x"], "env": {"DB_PASSWORD": literal}},
        "b": {"command": "uvx", "args": ["x"], "env": {literal: "1", "N": "x"}},
    }
    result = _scan(tmp_path, servers)
    assert list(_servers(result)["b"].env) == ["N", "[redacted-1]"]
    assert literal not in _dump(result)


H1_HEADER = {
    "url": "https://example.invalid/mcp",
    "headers": {"Authorization": "Bearer letmeinplease"},
}


@pytest.mark.parametrize(
    "servers,secret,server,env",
    [
        # A password written as a sibling env name, the whole name being the literal.
        (
            {
                "srv": {
                    "command": "npx",
                    "args": ["-y", "some-mcp@1.0.0"],
                    "env": {"Open-Sesame-Pass": VENDOR_TOKEN, "DB_PASSWORD": "Open-Sesame-Pass"},
                }
            },
            "Open-Sesame-Pass",
            "srv",
            ["DB_PASSWORD", "[redacted-1]"],
        ),
        # A header's bearer value reused inside another server's env name.
        (
            {
                "srv": {**H1_HEADER, "headers": {"Authorization": "Bearer letmeinplease42"}},
                "loc": {
                    "command": "npx",
                    "args": ["x@1.0.0"],
                    "env": {"X_LETMEINPLEASE42": VENDOR_TOKEN},
                },
            },
            "letmeinplease42",
            "loc",
            ["[redacted-1]"],
        ),
        # A header name repeating another header's bearer value.
        (
            {
                "srv": {
                    "url": "https://example.invalid/mcp",
                    "headers": {
                        "Authorization": "Bearer letmeinplease",
                        "X-letmeinplease-Token": f"Bearer {RANDOM}",
                    },
                }
            },
            "letmeinplease",
            "srv",
            None,
        ),
    ],
)
def test_a_name_holding_a_literal_the_file_reads_is_withheld_everywhere(
    tmp_path, servers, secret, server, env
):
    project = _project(tmp_path / "project", servers)
    found = _servers(_scan(project, servers))
    (finding,) = _findings(found[server])
    assert secret not in finding.detail
    assert ("an env key" if env else "a header") in finding.detail
    if env:
        assert list(found[server].env) == env
    else:
        assert "[redacted]" in found[server].properties["header_names"]
    assert not any(secret in text for text in _cli_outputs(tmp_path, project))


def _cli_outputs(tmp_path: Path, project: Path) -> list[str]:
    """Scan JSON and SARIF, the risk text and VEX, each with what its command printed."""
    runner = CliRunner()
    outputs = []
    for fmt in ("json", "sarif"):
        path = tmp_path / f"scan.{fmt}"
        arguments = ["scan", "--no-project-policy", "--report-only", "-f", fmt, "-o", str(path)]
        result = runner.invoke(main, [*arguments, str(project)])
        assert result.exit_code == 0, result.output
        outputs += [result.output, path.read_text(encoding="utf-8")]
    inventory = str(tmp_path / "scan.json")
    risk = runner.invoke(main, ["risk", "--no-project-policy", inventory])
    vex = tmp_path / "findings.vex.json"
    assert runner.invoke(main, ["vex", "-o", str(vex), inventory]).exit_code == 0
    outputs += [risk.output, vex.read_text(encoding="utf-8")]
    assert CATEGORY in outputs[1] and CATEGORY in risk.output
    return outputs


SESAME = "Open-Sesame-Pass"  # noqa: S105 - synthetic sentinel
PARTIAL = "Kq7m-Zw9x-4Lp8-ZtQ2-vN5r"  # noqa: S105 - synthetic sentinel
GH_SERVER = {"command": "npx", "args": ["-y", "some-mcp@1.0.0"]}


def _holder(name: str, *, header: bool = False) -> dict:
    if header:
        return {"url": "https://example.invalid/mcp", "headers": {name: f"Bearer {VENDOR_TOKEN}"}}
    return {**GH_SERVER, "env": {name: VENDOR_TOKEN}}


@pytest.mark.parametrize(
    "files,name",
    [
        # The password of a server the scanner refuses.
        (
            {
                ".mcp.json": {
                    "db": {**GH_SERVER, "disabled": "no", "env": {"DB_PASSWORD": SESAME}},
                    "gh": _holder(SESAME),
                }
            },
            SESAME,
        ),
        # A refused server's argument, whether a field or its command has the wrong type.
        (
            {
                ".mcp.json": {
                    "db": {"command": "npx", "args": ["x@1.0.0", "--password", SESAME], "tools": 1},
                    "gh": _holder(SESAME),
                }
            },
            SESAME,
        ),
        (
            {
                ".mcp.json": {
                    "db": {"command": ["npx"], "args": ["x@1.0.0", "--password", SESAME]},
                    "gh": _holder(SESAME),
                }
            },
            SESAME,
        ),
        # Other separators, or none, in the name or in the literal.
        *(
            (
                {
                    ".mcp.json": {
                        "db": {**GH_SERVER, "env": {"DB_PASSWORD": literal}},
                        "gh": _holder(name),
                    }
                },
                name,
            )
            for literal, name in (
                (SESAME, "Open.Sesame.Pass"),
                (SESAME, "OpenSesamePass"),
                ("OpenSesamePass", "X_Open-Sesame.Pass"),
                (PARTIAL, "X." + PARTIAL.replace("-", "")[:16]),
                (PARTIAL, "kq7m.zw9x.4lp8.ztq2"),
            )
        ),
        # A password of another client file.
        (
            {
                ".mcp.json": {"db": {**GH_SERVER, "env": {"DB_PASSWORD": SESAME}}},
                ".cursor/mcp.json": {"gh": _holder(SESAME)},
            },
            SESAME,
        ),
        # Another case, or "_" for "-".
        (
            {
                ".mcp.json": {
                    "db": {**GH_SERVER, "env": {"DB_PASSWORD": SESAME}},
                    "gh": _holder("OPEN_SESAME_PASS"),
                }
            },
            "OPEN_SESAME_PASS",
        ),
        (
            {
                ".mcp.json": {
                    "db": {**GH_SERVER, "env": {"DB_PASSWORD": SESAME}},
                    "gh": _holder("open-sesame-pass"),
                }
            },
            "open-sesame-pass",
        ),
        (
            {
                ".mcp.json": {
                    "db": {**GH_SERVER, "env": {"DB_PASSWORD": PARTIAL}},
                    "gh": _holder(PARTIAL.replace("-", "_")),
                }
            },
            PARTIAL.replace("-", "_"),
        ),
        # Twenty of a literal's 24 characters in a header name.
        (
            {
                ".mcp.json": {
                    "db": {**GH_SERVER, "env": {"DB_PASSWORD": PARTIAL}},
                    "gh": _holder("X-" + PARTIAL[:20], header=True),
                }
            },
            PARTIAL[:20],
        ),
        # An auth object's secret and the password of an endpoint URL.
        (
            {
                ".mcp.json": {
                    "db": {
                        "url": "https://example.invalid/mcp",
                        "auth": {"client_secret": SESAME},
                    },
                    "gh": _holder(SESAME),
                }
            },
            SESAME,
        ),
        (
            {
                ".mcp.json": {
                    "db": {"url": f"https://bot:{SESAME}@example.invalid/mcp"},
                    "gh": _holder(SESAME),
                }
            },
            SESAME,
        ),
    ],
)
def test_a_name_holding_any_literal_of_the_scan_is_withheld_from_every_output(
    tmp_path, files, name
):
    project = tmp_path / "project"
    for path, servers in files.items():
        (project / path).parent.mkdir(parents=True, exist_ok=True)
        (project / path).write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    gh = _servers(MCPScanner().scan(project))["gh"]
    (finding,) = _findings(gh)
    header = "url" in files[".cursor/mcp.json" if ".cursor/mcp.json" in files else ".mcp.json"].get(
        "gh", {}
    )
    assert ("a header" if header else "an env key") in finding.detail
    if not header:
        assert list(gh.env) == ["[redacted-1]"]
    outputs = _cli_outputs(tmp_path, project)
    assert not any(name in text or SESAME in text for text in outputs)


def test_long_literals_are_indexed_in_bounded_memory(tmp_path):
    letters = string.ascii_letters + string.digits
    choose = random.Random(7).choices  # noqa: S311 - a reproducible test input
    servers = {
        f"s{index}": {**GH_SERVER, "env": {"API_TOKEN": "".join(choose(letters, k=4000))}}
        for index in range(100)
    }
    project = _project(tmp_path, servers)
    size = sum(len(server["env"]["API_TOKEN"]) for server in servers.values())
    tracemalloc.start()
    try:
        result = MCPScanner().scan(project)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert len(_servers(result)) == 100 and not result.scan_failures
    # Every 16-character window as a string cost about 200 bytes for each character.
    assert peak < 60 * size


@pytest.mark.parametrize(
    "name",
    [
        "NEO4J_API_KEY",
        "S3_SECRET_KEY",
        "GH_TOKEN_2",
        "GPT4_API_KEY",
        "X-Api-Key-V2",
        "spring.datasource.password",
    ],
)
def test_a_credential_variable_name_with_digits_or_dots_stays_shown(tmp_path, name):
    servers = {
        "a": {**GH_SERVER, "args": ["-y", "some-mcp@1.0.0", "--api-key-env", name]},
        "b": {**GH_SERVER, "env": {name: "${KEY}"}},
        "c": {"url": "https://example.invalid/mcp", "headers": {name: "${KEY}"}},
    }
    found = _servers(_scan(tmp_path, servers))
    assert list(found["b"].env) == [name]
    assert found["c"].properties["header_names"] == [name]


def test_a_word_authorization_value_leaves_other_servers_names_and_hashes(tmp_path):
    def hash_of_b(value: str) -> tuple[list[str], str]:
        servers = {
            "a": {"url": "https://example.invalid/mcp", "headers": {"Authorization": value}},
            "b": {**GH_SERVER, "env": {"production_db_host": "db.invalid", "X_letmeinplease": "1"}},
        }
        b = _servers(_scan(tmp_path, servers))["b"]
        return list(b.env), b.properties["static_config_hash"]

    reference = hash_of_b("Bearer ${TOKEN}")
    assert reference[0] == ["X_letmeinplease", "production_db_host"]
    assert hash_of_b("Bearer production") == reference
    assert hash_of_b("Bearer letmeinplease") == reference
    holder = {**GH_SERVER, "env": {"X_letmeinplease": VENDOR_TOKEN}}
    servers = {"a": {**holder, "headers": {"Authorization": "Bearer letmeinplease"}}, "b": holder}
    found = _servers(_scan(tmp_path, servers))
    assert list(found["a"].env) == ["[redacted-1]"]
    assert list(found["b"].env) == ["X_letmeinplease"]
    (finding,) = _findings(found["b"])
    assert "letmeinplease" not in finding.detail and "an env key" in finding.detail


def test_a_declared_field_holding_a_literal_is_withheld(tmp_path):
    servers = {"db": {**GH_SERVER, "env": {"DB_PASSWORD": PARTIAL}, PARTIAL: "x"}}
    found = _servers(_scan(tmp_path, servers))
    assert found["db"].properties["declared_fields"] == ["[redacted]", "args", "command", "env"]
    assert PARTIAL not in _dump(_scan(tmp_path, servers))


def test_names_are_checked_in_time_linear_in_the_servers(tmp_path):
    def run(scale: int) -> object:
        servers = {
            f"s{index}": {
                **GH_SERVER,
                "env": {
                    **{f"S{index}_SETTING_{item}_HOST": "db.invalid" for item in range(20)},
                    f"S{index}_DB_PASSWORD": f"Kq7m{index:06d}Zw9xLp8",
                },
                "headers": {"Authorization": f"Bearer Tq{index:06d}Rv4Np7Xw"},
            }
            for index in range(150 * scale)
        }
        return _scan(tmp_path / f"scale{scale}", servers)

    assert scaling_ratio(run, factor=4) < 7


@pytest.mark.parametrize(
    "flag,value,name",
    [
        ("--api-key-env", "OPENAI_API_KEY", "AZURE_OPENAI_API_KEY"),
        ("--api-key-env", "OPENAI_API_KEY", "OPENAI_API_KEY_ORG"),
        ("--token-env", "GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_PERSONAL_ACCESS_TOKEN_SCOPES"),
        ("--auth-header", "x-api-key", "x-api-key"),
        ("--token-env", "github_token", "github_token"),
        ("--token-env", "GitHubToken", "GitHubToken"),
    ],
)
def test_a_credential_variable_name_scrubbed_elsewhere_stays_shown(tmp_path, flag, value, name):
    servers = {
        "a": {"command": "npx", "args": ["-y", "some-mcp@1.0.0", flag, value]},
        "b": {"command": "npx", "args": ["x@1.0.0"], "env": {name: "${" + name.upper() + "}"}},
        "c": {"url": "https://example.invalid/mcp", "headers": {name: "${KEY}"}},
    }
    found = _servers(_scan(tmp_path, servers))
    assert all(_findings(server) == [] for server in found.values())
    assert list(found["b"].env) == [name]
    assert found["c"].properties["header_names"] == [name]


def test_a_credential_variable_name_that_is_also_a_literal_stays_withheld(tmp_path):
    servers = {
        "a": {"command": "npx", "args": ["-y", "some-mcp@1.0.0", "--token-env", "GitHubToken"]},
        "b": {"command": "npx", "args": ["x@1.0.0"], "env": {"GitHubToken": "1"}},
        "c": {
            "command": "npx",
            "args": ["x@1.0.0"],
            "env": {"DB_PASSWORD": "Open-Sesame-Pass", "Open-Sesame-Pass": "1"},
        },
    }
    found = _servers(_scan(tmp_path, servers))
    assert list(found["b"].env) == ["GitHubToken"]
    assert list(found["c"].env) == ["DB_PASSWORD", "[redacted-1]"]
    servers["b"]["env"]["DB_PASSWORD"] = "GitHubToken"  # noqa: S105 - synthetic sentinel
    found = _servers(_scan(tmp_path, servers))
    assert list(found["b"].env) == ["DB_PASSWORD", "[redacted-1]"]
