"""A bounded holder list must still explain the subject's exposure."""

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.models import MCPServerComponent
from nexus_symbiote.graph import MAX_SHARED_CREDENTIAL_HOLDERS, blast_radius


def test_a_late_sorting_reachable_holder_survives_the_display_limit():
    name = "EXAMPLE_API_TOKEN"
    servers = [
        MCPServerComponent(bom_ref=f"server:{n:03d}", name=f"example-{n}", env={name: ""})
        for n in range(MAX_SHARED_CREDENTIAL_HOLDERS + 4)
    ]
    subject = servers[-1].bom_ref
    result = blast_radius(AIBOM(components=servers), subject)
    holders = result["shared_credential_surfaces"][name]
    assert holders[0] == subject
    assert len(holders) == len(set(holders)) == MAX_SHARED_CREDENTIAL_HOLDERS
    assert result["shared_credential_holders_omitted"] == {name: 4}
