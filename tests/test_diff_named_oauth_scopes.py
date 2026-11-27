"""`diff` names the OAuth scopes an A2A card gained or lost."""

from __future__ import annotations

from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import A2AServerComponent, CapabilityDeclaration
from nexus_symbiote.diff.differ import AIBOMDiffer


def test_diff_names_added_oauth_scopes() -> None:
    def card(scopes: list[str]) -> AIBOM:
        bom = AIBOM()
        bom.add_component(
            A2AServerComponent(
                bom_ref="a2a-server:orchestrator",
                name="orchestrator",
                endpoint_url="https://agents.example",
                capabilities=CapabilityDeclaration(oauth_scopes=scopes),
            )
        )
        return bom

    report = AIBOMDiffer().diff(card(["support:read"]), card(["support:read", "support:admin"]))
    (change,) = report.components_modified
    assert any("OAuth scopes added: support:admin" in detail for detail in change.details)
    assert "capabilities changed." not in change.details
    assert change.severity == "high"


def _server(capabilities: CapabilityDeclaration | None) -> AIBOM:
    bom = AIBOM()
    bom.add_component(
        A2AServerComponent(
            bom_ref="a2a-server:orchestrator",
            name="orchestrator",
            endpoint_url="https://agents.example",
            capabilities=capabilities,
        )
    )
    return bom


def test_a_first_grant_and_a_last_removal_are_named() -> None:
    granted = AIBOMDiffer().diff(
        _server(None), _server(CapabilityDeclaration(oauth_scopes=["support:admin"]))
    )
    (change,) = granted.components_modified
    assert change.details == ["capabilities changed: OAuth scopes added: support:admin"]
    assert change.severity == "high"
    revoked = AIBOMDiffer().diff(
        _server(CapabilityDeclaration(oauth_scopes=["support:admin"])), _server(None)
    )
    (change,) = revoked.components_modified
    assert change.details == ["capabilities changed: OAuth scopes removed: support:admin"]
    assert change.severity == "high"


def test_a_simultaneous_non_scope_capability_change_stays_visible() -> None:
    report = AIBOMDiffer().diff(
        _server(CapabilityDeclaration(oauth_scopes=["support:read"])),
        _server(
            CapabilityDeclaration(
                oauth_scopes=["support:read", "support:admin"],
                egress_domains=["crm.example"],
            )
        ),
    )
    (change,) = report.components_modified
    assert "capabilities changed: OAuth scopes added: support:admin" in change.details
    assert "capabilities changed." in change.details


def test_reordered_capability_sets_do_not_add_a_generic_alert() -> None:
    scopes = ["support:read", "support:admin"]
    egress = ["crm.example", "support.example"]
    report = AIBOMDiffer().diff(
        _server(CapabilityDeclaration(oauth_scopes=scopes, egress_domains=egress)),
        _server(CapabilityDeclaration(oauth_scopes=scopes[:1], egress_domains=egress[::-1])),
    )
    (change,) = report.components_modified
    assert change.details == ["capabilities changed: OAuth scopes removed: support:admin"]
    assert change.severity == "high"


@pytest.mark.parametrize("report_format", ["text", "json", "markdown", "junit"])
def test_imported_oauth_scope_values_are_redacted_only_for_display(
    tmp_path: Path, report_format: str
) -> None:
    removed = "ghp_" + "a" * 36
    added = "ghp_" + "b" * 36
    public_uri = "https://www.googleapis.com/auth/drive.readonly"
    old, new = tmp_path / "before.json", tmp_path / "after.json"
    old.write_text(_server(CapabilityDeclaration(oauth_scopes=[removed])).to_native_json())
    new.write_text(
        _server(CapabilityDeclaration(oauth_scopes=[added, public_uri])).to_native_json()
    )

    result = CliRunner().invoke(
        main, ["diff", str(old), str(new), "--report-format", report_format]
    )

    assert result.exit_code == 1, result.output
    # Markdown protects punctuation with backslashes. Check the visible content.
    shown = result.output.replace("\\", "")
    assert added not in shown and removed not in shown
    assert f"OAuth scopes added: ***; {public_uri} and removed: ***" in shown
