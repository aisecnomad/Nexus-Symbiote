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
    assert change.severity == "medium"


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
