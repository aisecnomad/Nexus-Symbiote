"""OAuth scopes that hide a glued token or URL user information are withheld."""

from __future__ import annotations

import html
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import A2AServerComponent, CapabilityDeclaration
from nexus_symbiote.scanners.a2a import A2AScanner
from nexus_symbiote.utils.secrets import REDACTED, redact_oauth_scope

PAT = "ghp_" + "a" * 36
KEY_ID = "AKIA" + "B" * 16
PASSWORD = "pw-" + "c" * 12

WITHHELD = [
    "x" + PAT,
    "scope1" + KEY_ID,
    "https://api.example/auth/x" + PAT,
    f"//user:{PASSWORD}@host.example/scope",
    f"//{PASSWORD}@host.example/scope",
    f"user:{PASSWORD}@host.example/scope",
    f"user:{PASSWORD}@localhost/scope",
    f"user:{PASSWORD}@db:5432",
    # What the rules leave of a scope they reduced in part is checked too.
    f"https://host.example/cb?token={PASSWORD} x{PAT}",
    f"https://user:{PASSWORD}@host.example/a x{PAT}",
    f"x user:{PASSWORD}@host.example/scope",
]


@pytest.mark.parametrize("scope", WITHHELD)
def test_a_glued_token_or_schemeless_user_information_is_withheld(scope: str) -> None:
    assert redact_oauth_scope(scope) == REDACTED


@pytest.mark.parametrize(
    "scope",
    [
        "support:admin",
        "user:email",
        "files:read@v2",
        "a?b=1",
        "user@example.com",
        "https://www.googleapis.com/auth/drive.readonly",
        "api://00000003-0000-0000-c000-000000000000/.default",
        "task-scheduler-read-2024-v2",
        "risk-assessment-reports-2024",
    ],
)
def test_ordinary_scopes_stay_in_full(scope: str) -> None:
    assert redact_oauth_scope(scope) == scope


@pytest.mark.parametrize(
    ("scope", "shown"),
    [
        ("repo_" + PAT, "repo_***"),
        ("repo:" + PAT, REDACTED),
        (f"https://user:{PASSWORD}@host.example/scope", "https://host.example"),
        (f"api_key={PASSWORD}", "api_key=***"),
    ],
)
def test_a_scope_the_rules_already_reduced_keeps_its_form(scope: str, shown: str) -> None:
    assert redact_oauth_scope(scope) == shown


def test_the_collector_withholds_glued_tokens_and_user_information(tmp_path: Path) -> None:
    card = {
        "name": "billing-agent",
        "url": "https://agents.example.com",
        "skills": [{"id": "lookup", "name": "lookup-invoice"}],
        "securitySchemes": {"oauth": {"type": "oauth2"}},
        "security": [{"oauth": ["read:only", "x" + PAT, f"user:{PASSWORD}@host.example/s"]}],
    }
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "agent.json").write_text(json.dumps(card))
    (server,) = [
        c for c in A2AScanner().scan(tmp_path).components if isinstance(c, A2AServerComponent)
    ]
    assert server.capabilities is not None
    assert server.capabilities.oauth_scopes == [REDACTED, "read:only"]
    exported = server.model_dump_json()
    assert PAT not in exported and PASSWORD not in exported
    assert any(r.detail.endswith(": redacted OAuth scopes.") for r in server.risks)


def _inventory(scopes: list[str]) -> str:
    bom = AIBOM()
    bom.add_component(
        A2AServerComponent(
            bom_ref="a2a-server:orchestrator",
            name="orchestrator",
            endpoint_url="https://agents.example",
            capabilities=CapabilityDeclaration(oauth_scopes=scopes),
        )
    )
    return bom.to_native_json()


@pytest.mark.parametrize("report_format", ["text", "json", "markdown", "junit"])
def test_drift_output_withholds_imported_glued_tokens_and_user_information(
    tmp_path: Path, report_format: str
) -> None:
    old, new = tmp_path / "before.json", tmp_path / "after.json"
    old.write_text(_inventory(["read:only", "scope1" + KEY_ID]))
    new.write_text(_inventory(["read:only", "x" + PAT, f"//user:{PASSWORD}@host.example/s"]))

    result = CliRunner().invoke(
        main, ["diff", str(old), str(new), "--report-format", report_format]
    )

    assert result.exit_code == 1, result.output
    # Markdown escapes punctuation with backslashes and JUnit with entities.
    shown = html.unescape(result.output.replace("\\", ""))
    assert "OAuth scopes added:" in shown
    assert PAT not in shown and KEY_ID not in shown and PASSWORD not in shown


WEBHOOK_SECRET = "Zq8vR2mN5kL1" + "pX7wT4yH9cJ3"


@pytest.mark.parametrize(
    ("scope", "origin"),
    [
        (
            f"https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/{WEBHOOK_SECRET}",
            "https://hooks.slack.com",
        ),
        (
            "https://discord.com/api/webhooks/123456789012345678/" + "Ab1Cd2Ef3Gh4" * 5,
            "https://discord.com",
        ),
        ("https://example.com/hooks/9f8e7d6c5b4a39281706f5e4d3c2b1a0", "https://example.com"),
        ("https://example.com/hook/" + "AbCdEfGhIjKlMnOpQrStUv", "https://example.com"),
        ("https://example.com/hook/a-" + "1a2b3c4d" * 2 + "_b", "https://example.com"),
    ],
    ids=["slack", "discord", "hex", "mixed-case", "between-separators"],
)
def test_a_scope_uri_whose_path_holds_a_secret_is_reduced_to_its_origin(
    scope: str, origin: str
) -> None:
    assert redact_oauth_scope(scope) == origin


@pytest.mark.parametrize(
    "scope",
    [
        "https://www.googleapis.com/auth/cloudplatformprojects.readonly",
        "https://graph.microsoft.com/Files.ReadWrite.All",
        "https://management.azure.com/user_impersonation",
        "https://api.example.com/task-scheduler-read-2024-v2",
        "https://api.example.com/projects/12345678901234567890/read",
        "api://11111111-2222-3333-4444-555555555555/Files.Read",
    ],
)
def test_scope_uris_that_name_permissions_stay_in_full(scope: str) -> None:
    assert redact_oauth_scope(scope) == scope


def test_drift_output_withholds_a_webhook_secret_in_a_scope_uri(tmp_path: Path) -> None:
    old, new = tmp_path / "before.json", tmp_path / "after.json"
    old.write_text(_inventory(["read:only"]))
    webhook = f"https://hooks.slack.com/services/T0AAAAAAA/B0BBBBBBB/{WEBHOOK_SECRET}"
    new.write_text(_inventory(["read:only", webhook]))

    result = CliRunner().invoke(main, ["diff", str(old), str(new), "--json-output"])

    assert result.exit_code == 1, result.output
    assert '\\"https://hooks.slack.com\\"' in result.output
    assert WEBHOOK_SECRET not in result.output


@pytest.mark.parametrize(
    ("scope", "shown"),
    [
        ("https://hooks.slack.com/services/TEAM/BOT/onlywordshere", "https://hooks.slack.com"),
        ("https://hooks.slack.com/workflows/T/A/123/abc", "https://hooks.slack.com"),
        ("https://HOOKS.SLACK.COM:443/services/T/B/x", "https://hooks.slack.com:443"),
        ("https://discord.com/api/webhooks/1/short", "https://discord.com"),
        ("https://canary.discord.com/api/v10/webhooks/1/abc", "https://canary.discord.com"),
        (
            "https://contoso.webhook.office.com/webhookb2/a@b/IncomingWebhook/c/d",
            "https://contoso.webhook.office.com",
        ),
        ("https://outlook.office.com/webhook/a/IncomingWebhook/b/c", "https://outlook.office.com"),
        ("https://hooks.zapier.com/hooks/catch/123/abc/", "https://hooks.zapier.com"),
        ("https://maker.ifttt.com/trigger/door/with/key/plainkey", "https://maker.ifttt.com"),
        ("https://api.telegram.org/bot123:token/sendMessage", "https://api.telegram.org"),
        ("hooks.slack.com/services/TEAM/BOT/onlywordshere", REDACTED),
        ("discord.com/api/webhooks/1/short", REDACTED),
        ("//hooks.slack.com/services/T/B/publicfixture", REDACTED),
        (r"https://hooks.slack.com\services\T\B\publicfixture", REDACTED),
        ("hooks.slack.com./services/T/B/publicfixture", REDACTED),
        ("discord.com/api/%77ebhooks/1/publicfixture", REDACTED),
        ("read hooks.slack.com/services/T/B/publicfixture", REDACTED),
        ("https://docs.example/read hooks.slack.com/services/T/B/publicfixture", REDACTED),
    ],
    ids=[
        "slack-words",
        "slack-workflow",
        "slack-case-and-port",
        "discord-short",
        "discord-subdomain",
        "teams",
        "outlook",
        "zapier",
        "ifttt",
        "telegram",
        "slack-without-scheme",
        "discord-without-scheme",
        "network-path",
        "backslash",
        "absolute-dns-name",
        "encoded-route",
        "scope-list",
        "mixed-scope-uri-list",
    ],
)
def test_a_recognised_webhook_route_is_withheld_however_it_is_spelled(
    scope: str, shown: str
) -> None:
    assert redact_oauth_scope(scope) == shown


@pytest.mark.parametrize(
    "scope",
    [
        "https://hooks.slack.com",
        "https://discord.com/api/oauth2/authorize",
        "https://outlook.office.com/Mail.Read",
        "https://www.googleapis.com/auth/chat.messages",
        "hooks:read",
        "webhooks.write",
    ],
)
def test_ordinary_scopes_on_webhook_hosts_stay_in_full(scope: str) -> None:
    assert redact_oauth_scope(scope) == scope


def test_the_inventory_and_drift_output_withhold_a_webhook_route(tmp_path: Path) -> None:
    secret = "only" + "words" + "here"
    card = {
        "name": "notifier",
        "url": "https://agents.example.com",
        "skills": [{"id": "notify", "name": "notify"}],
        "securitySchemes": {"oauth": {"type": "oauth2"}},
        "security": [{"oauth": [f"https://hooks.slack.com/services/T/B/{secret}"]}],
    }
    (tmp_path / ".well-known").mkdir()
    (tmp_path / ".well-known" / "agent.json").write_text(json.dumps(card))
    (server,) = [
        c for c in A2AScanner().scan(tmp_path).components if isinstance(c, A2AServerComponent)
    ]
    assert server.capabilities is not None
    assert server.capabilities.oauth_scopes == ["https://hooks.slack.com"]
    assert secret not in server.model_dump_json()
    old, new = tmp_path / "before.json", tmp_path / "after.json"
    old.write_text(_inventory(["read:only"]))
    new.write_text(_inventory(["read:only", f"hooks.slack.com/services/T/B/{secret}"]))
    for report_format in ("text", "json", "markdown", "junit"):
        result = CliRunner().invoke(
            main, ["diff", str(old), str(new), "--report-format", report_format]
        )
        assert result.exit_code == 1, result.output
        assert secret not in html.unescape(result.output.replace("\\", "")), report_format
