"""`diff` names the OAuth scopes an A2A card gained or lost."""

from __future__ import annotations

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
