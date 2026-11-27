"""How a scan records collector output, shared with project reconciliation.

``scan`` and ``validate --project`` must annotate collector output identically, or a
reconciled inventory could never equal its fresh recollection. Both therefore merge
components through ``merge_collected``.
"""

from __future__ import annotations

from datetime import datetime
from typing import Literal

from nexus_symbiote.core.enums import AssuranceLevel, ComponentType
from nexus_symbiote.core.identifiers import neutralize_identifiers
from nexus_symbiote.core.models import (
    AnyComponent,
    ClaimEvidence,
    PromptComponent,
    ToolComponent,
)

IMPORTED_MODE = "imported-unverified-report"
SOURCE_REFERENCE_MODE = "static-source-reference"
PRESENCE_CLAIM = "repository_presence"
DISCOVERY_CLAIM = "discovery_report_entry"
# On an imported model: where a scan read the identifier that a report cites.
CITED_EVIDENCE_CLAIM = "cited_evidence"
IMPORTING_COLLECTORS = frozenset({"shadowscan"})


def is_imported(component: AnyComponent) -> bool:
    return component.properties.get("collection_mode") == IMPORTED_MODE


def is_source_reference(component: AnyComponent) -> bool:
    """Whether a model is an identifier the source collector read, with no artifact.

    Such a model names no weight file: it has no digest and no path, only the line of
    source that names it.
    """
    return (
        component.component_type is ComponentType.MODEL
        and component.properties.get("collection_mode") == SOURCE_REFERENCE_MODE
        and not component.hashes
        and component.source_path is None
    )


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
