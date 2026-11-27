"""How a scan records collector output, shared with project reconciliation.

``scan`` and ``validate --project`` must annotate collector output identically, or a
reconciled inventory could never equal its fresh recollection. Both therefore merge
components through ``merge_collected``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from nexus_symbiote.core.enums import AssuranceLevel
from nexus_symbiote.core.identifiers import neutralize_identifiers
from nexus_symbiote.core.models import (
    AnyComponent,
    ClaimEvidence,
    PromptComponent,
    ToolComponent,
)

IMPORTED_MODE = "imported-unverified-report"
PRESENCE_CLAIM = "repository_presence"
DISCOVERY_CLAIM = "discovery_report_entry"
# On an imported model: where a scan read the identifier that a report cites.
CITED_EVIDENCE_CLAIM = "cited_evidence"
IMPORTING_COLLECTORS = frozenset({"shadowscan"})


def is_imported(component: AnyComponent) -> bool:
    return component.properties.get("collection_mode") == IMPORTED_MODE


def measured_assurance(component: AnyComponent) -> AssuranceLevel:
    """Observed when the collector computed the component's identity from bytes.

    A digest of weights, instruction or skill bytes, or of a tool descriptor read from
    configuration, is a measurement. A package pin, endpoint or hosted-model alias is
    a declaration. Offline collection never establishes ``verified``.
    """
    if is_imported(component):
        return AssuranceLevel.DECLARED
    level = component.assurance_level
    if level is AssuranceLevel.VERIFIED:
        level = AssuranceLevel.DECLARED
    measured = (
        bool(component.hashes)
        or (isinstance(component, PromptComponent) and bool(component.content_hash))
        or (
            isinstance(component, ToolComponent)
            and bool(component.definition_hash)
            and component.properties.get("collection_mode") == "static-config"
        )
    )
    return AssuranceLevel.OBSERVED if measured else level


def collection_claim(
    collector: str, component: AnyComponent, observed_at: datetime | None
) -> tuple[str, ClaimEvidence]:
    """The provenance claim a scan attaches to each component a collector returned."""
    imported = collector in IMPORTING_COLLECTORS
    return (
        DISCOVERY_CLAIM if imported else PRESENCE_CLAIM,
        ClaimEvidence(
            assurance=AssuranceLevel.DECLARED if imported else AssuranceLevel.OBSERVED,
            method="imported-discovery-report" if imported else "filesystem-inventory",
            scope="source-report" if imported else "repository",
            collector=collector,
            locator=component.source_path,
            observed_at=observed_at,
        ),
    )


# Collectors whose references may name what another collector records: the code
# collector links an agent to a decorated tool that the MCP collector reads.
SETTLING_COLLECTORS = frozenset({"code"})
_SETTLED_FIELDS = (
    "tool_refs",
    "model_refs",
    "sub_agent_refs",
    "mcp_server_refs",
    "server_refs",
    "guardrail_refs",
    "data_refs",
    "prompt_refs",
)


def settle_references(components: list[AnyComponent]) -> None:
    """Drop each reference a settling collector made to a component no collector recorded.

    Such a reference stands only when the collector that records its target ran and
    recorded it, so a scan of selected collectors holds no dangling reference. A scan
    and a reconciliation both settle after every collector has been merged.
    """
    present = {component.bom_ref for component in components}
    for component in components:
        if not any(claim.collector in SETTLING_COLLECTORS for claim in component.claims.values()):
            continue
        for field_name in _SETTLED_FIELDS:
            refs = getattr(component, field_name, None)
            if isinstance(refs, list) and any(ref not in present for ref in refs):
                refs[:] = [ref for ref in refs if ref in present]


def merge_collected(
    collected: dict[str, AnyComponent],
    component: AnyComponent,
    collector: str,
    observed_at: datetime | None,
) -> Literal["added", "duplicate", "conflict"]:
    """Annotate ``component`` and add it, or compare it with an earlier collector's copy.

    The comparison happens before the provenance claim is attached: two collectors that
    report the same subject would otherwise always differ in that claim. An identical
    duplicate is kept once and names the second collector in its evidence references.

    The component's name, description, supplier and nested tool names are neutralized
    here, before anything else reads them: this is the one step that every collected
    component passes through on both paths, so a fresh scan and a reconciliation record
    the same text, and a second collector's copy of the same subject compares equal.
    """
    neutralize_identifiers(component)
    component.assurance_level = measured_assurance(component)
    existing = collected.get(component.bom_ref)
    if existing is not None:
        name, _ = collection_claim(collector, component, observed_at)
        claims = {key: value for key, value in existing.claims.items() if key != name}
        if existing.model_copy(update={"claims": claims}) != component:
            return "conflict"
        claim = existing.claims.get(name)
        if claim is not None and f"collector:{collector}" not in claim.evidence_refs:
            claim.evidence_refs.append(f"collector:{collector}")
        return "duplicate"
    name, claim = collection_claim(collector, component, observed_at)
    component.claims[name] = claim
    collected[component.bom_ref] = component
    return "added"
