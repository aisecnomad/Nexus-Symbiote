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
