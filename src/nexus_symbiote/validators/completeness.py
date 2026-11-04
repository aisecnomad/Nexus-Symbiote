"""Completeness validator — checks that an AIBOM covers all expected surfaces."""

from __future__ import annotations

import re
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, TrustTier
from nexus_symbiote.core.hashing import canonical_json
from nexus_symbiote.core.models import (
    A2AClientComponent,
    A2AServerComponent,
    AgentComponent,
    AnyComponent,
    ClaimEvidence,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.scanners.a2a import (
    A2A_SOURCE_BINDING_FIELDS,
    A2A_STATIC_MODES,
    has_a2a_source_binding,
)

if TYPE_CHECKING:
    from nexus_symbiote.scanners.base import ScanResult
    from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy

REQUIRED_SCANNERS = BUILTIN_SCANNER_NAMES

EXPECTED_SURFACES = {
    "mcp-config": "MCP server configuration (.mcp.json etc.)",
    "model-weights": "Model weight files and signing status",
    "prompts": "System prompts and instruction files",
    "rag-sources": "RAG / vector store configurations",
    "registry-trust": "Package registry trust and pinning",
    "tools": "Tool definitions with capability hashes",
}

MINIMUM_COMPONENT_TYPES = {
    ComponentType.MCP_SERVER,
    ComponentType.TOOL,
    ComponentType.PROMPT_TEMPLATE,
}


@dataclass
class CompletenessIssue:
    surface: str
    description: str
    severity: str = "warning"


@dataclass
class CompletenessReport:
    is_complete: bool = True
    surfaces_covered: list[str] = field(default_factory=list)
    surfaces_missing: list[str] = field(default_factory=list)
    issues: list[CompletenessIssue] = field(default_factory=list)
    assurance_level: AssuranceLevel = AssuranceLevel.DECLARED
    component_type_coverage: dict[str, int] = field(default_factory=dict)
    total_components: int = 0
    local_subjects: int | None = None

    def to_dict(self) -> dict[str, object]:
        return {
            "is_complete": self.is_complete,
            "surfaces_covered": self.surfaces_covered,
            "surfaces_missing": self.surfaces_missing,
            "issues": [
                {"surface": i.surface, "description": i.description, "severity": i.severity}
                for i in self.issues
            ],
            "assurance_level": self.assurance_level.value,
            "component_type_coverage": self.component_type_coverage,
            "total_components": self.total_components,
        }


class CompletenessValidator:
    """Validates that an AIBOM covers all expected attack surfaces."""

    def validate(self, bom: AIBOM) -> CompletenessReport:
        report = CompletenessReport()
        report.total_components = len(bom.components)

        type_counts: dict[str, int] = {}
        for c in bom.components:
            key = c.component_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        report.component_type_coverage = type_counts

        if bom.metadata.completeness:
            report.surfaces_covered = list(bom.metadata.completeness.surfaces_scanned)
            report.surfaces_missing = list(bom.metadata.completeness.surfaces_excluded)
            report.assurance_level = bom.metadata.completeness.assurance_level
        else:
            report.issues.append(
                CompletenessIssue(
                    surface="metadata",
                    description="AIBOM has no completeness claim — cannot assess coverage.",
                    severity="error",
                )
            )
            report.is_complete = False

        claim = bom.metadata.completeness
        if claim and claim.scope == "repository" and not claim.collectors_requested:
            report.is_complete = False
            report.issues.append(
                CompletenessIssue(
                    surface="collection",
                    severity="error",
                    description="Repository completeness requires explicit collection records",
                )
            )
        if claim and claim.scan_failures:
            report.is_complete = False
            report.issues.extend(
                CompletenessIssue(surface="collection", description=f, severity="error")
                for f in claim.scan_failures
            )
        if claim and set(claim.collectors_requested) - set(claim.collectors_completed):
            report.is_complete = False
            report.issues.append(
                CompletenessIssue(
                    surface="collection",
                    severity="error",
                    description="Some requested collectors did not complete",
                )
            )
        if claim:
            missing = REQUIRED_SCANNERS - claim.scanner_status.keys()
            if missing:
                report.is_complete = False
                report.issues.append(
                    CompletenessIssue(
                        "coverage",
                        "Missing scanner coverage: " + ", ".join(sorted(missing)),
                        "error",
                    )
                )
            if claim.surfaces_excluded:
                report.is_complete = False
                report.issues.append(
                    CompletenessIssue(
                        "coverage", "Excluded surfaces leave coverage incomplete.", "error"
                    )
                )
            for scanner, state in claim.scanner_status.items():
                if state != "complete":
                    report.is_complete = False
                    report.issues.append(
                        CompletenessIssue(scanner, f"Scanner coverage is {state}.", "error")
                    )
        # A repository observation is complete only within its stated collection scope.
        # It does not require tools/prompts to exist in every project.

        for c in bom.components:
            if not c.hashes and c.component_type in (
                ComponentType.MODEL,
                ComponentType.TOOL,
                ComponentType.PROMPT_TEMPLATE,
            ):
                if not (hasattr(c, "content_hash") and c.content_hash):
                    if not (hasattr(c, "definition_hash") and c.definition_hash):
                        report.issues.append(
                            CompletenessIssue(
                                surface=c.bom_ref,
                                description=f"Component '{c.name}' has no integrity hash.",
                                severity="warning",
                            )
                        )

        from nexus_symbiote.graph import validate_graph

        for issue in validate_graph(bom):
            report.issues.append(
                CompletenessIssue(surface="graph", description=issue, severity="error")
            )
            report.is_complete = False
        orphan_refs = self._find_orphan_refs(bom)
        for ref, field_name in orphan_refs:
            report.issues.append(
                CompletenessIssue(
                    surface=ref,
                    description=f"Reference '{ref}' in '{field_name}' points to no component.",
                    severity="error",
                )
            )
            report.is_complete = False

        if report.surfaces_missing:
            for surface in report.surfaces_missing:
                for key, _desc in EXPECTED_SURFACES.items():
                    if key in surface.lower():
                        report.issues.append(
                            CompletenessIssue(
                                surface=key,
                                description=f"Surface excluded: {surface}",
                                severity="info",
                            )
                        )

        return report

    def validate_against_project(
        self,
        bom: AIBOM,
        project_root: Path,
        *,
        exclude_paths: Sequence[str] = (),
        signature_policies: Sequence[SigstoreArtifactPolicy] = (),
    ) -> CompletenessReport:
        """Recollect the supported static inventory under caller-selected scope.

        Supplied statuses, exclusions, and paths cannot select or disable a collector.
        Only the local built-in collectors run. None executes project code or uses
        remote discovery. Integrity and signer policy are checked separately.
        """
        from nexus_symbiote.graph import assemble_repository_agent
        from nexus_symbiote.scanners import ALL_SCANNERS, ModelScanner

        report = self.validate(bom)
        root = project_root.absolute()
        observed: dict[str, AnyComponent] = {}
        expected = AIBOM()

        def incomplete(surface: str, description: str, severity: str = "error") -> None:
            report.is_complete = False
            report.issues.append(CompletenessIssue(surface, description, severity))

        for scanner_type in ALL_SCANNERS:
            scanner = (
                ModelScanner(signature_policies=signature_policies)
                if scanner_type is ModelScanner
                else scanner_type()
            )
            scanner.configure(exclude_paths=exclude_paths)
            try:
                local = scanner.scan(root)
            except Exception:
                incomplete(
                    scanner.name, "Local collector failed; inventory could not be reconciled."
                )
                continue
            for reason in (*local.scan_failures, *local.surfaces_excluded):
                incomplete(scanner.name, f"Local collection incomplete: {reason}")
            if scanner.name == "shadowscan":
                for reason in self._discovery_mismatches(bom, local):
                    incomplete(scanner.name, reason)
            expected.dependencies.extend(local.dependencies)
            for component in local.components:
                previous = observed.setdefault(component.bom_ref, component)
                if previous != component:
                    incomplete(scanner.name, f"Conflicting local reference: {component.bom_ref}")

        expected.components.extend(observed.values())
        try:
            agent = assemble_repository_agent(expected, root)
        except (OSError, ValueError, RecursionError):
            incomplete("agent.yaml", "Local agent manifest could not be reconciled.")
        else:
            if agent.properties.get("identity_source") == "repository-path":
                roots = [
                    c
                    for c in bom.components
                    if isinstance(c, AgentComponent)
                    and c.properties.get("identity_source") == "repository-path"
                ]
                if len(roots) > 1:
                    incomplete("graph", "Multiple agents claim to be the inferred checkout root.")
                elif len(roots) == 1 and re.fullmatch(
                    r"agent:repository:[0-9a-f]{24}", roots[0].bom_ref
                ):
                    # This ID and name derive from the checkout path, not from an
                    # artifact. Rebind both so only contents and bindings are compared.
                    for edge in expected.dependencies:
                        if edge.source_ref == agent.bom_ref:
                            edge.source_ref = roots[0].bom_ref
                    agent.bom_ref = roots[0].bom_ref
                    agent.name = roots[0].name
                elif not roots and not any(
                    edge.source_ref == agent.bom_ref for edge in expected.dependencies
                ):
                    # Older inventories can lack an inferred container if it has
                    # no local associations. It never contributes a local subject.
                    expected.components.remove(agent)

        # Compare complete records, including multiplicity, assurance and conditions.
        # A live-only endpoint is outside the static projection and cannot replace
        # a required static edge. ShadowScan edges are also checked against their source.
        projected_refs = {c.bom_ref for c in expected.components}
        supplied_edges = Counter(
            canonical_json(edge.model_dump(mode="json"))
            for edge in bom.dependencies
            if edge.source_ref in projected_refs and edge.target_ref in projected_refs
        )
        expected_edges = Counter(
            canonical_json(edge.model_dump(mode="json")) for edge in expected.dependencies
        )
        if supplied_edges != expected_edges:
            missing = (expected_edges - supplied_edges).total()
            unexpected = (supplied_edges - expected_edges).total()
            incomplete(
                "graph",
                f"Repository dependency records differ from the local projection "
                f"({missing} missing, {unexpected} unexpected).",
            )

        report.local_subjects = sum(
            c.properties.get("collection_mode") != "imported-unverified-report"
            and not (
                isinstance(c, AgentComponent)
                and c.properties.get("identity_source") == "repository-path"
            )
            for c in expected.components
        )
        supplied = {c.bom_ref: c for c in bom.components}
        for actual in expected.components:
            declared = supplied.pop(actual.bom_ref, None)
            if (
                isinstance(actual, (A2AClientComponent, A2AServerComponent))
                and actual.properties.get("collection_mode") in A2A_STATIC_MODES
                and (
                    not isinstance(declared, (A2AClientComponent, A2AServerComponent))
                    or not has_a2a_source_binding(declared)
                    or not has_a2a_source_binding(actual)
                )
            ):
                incomplete(
                    actual.bom_ref,
                    "Static A2A source binding is unknown; re-collect with the operator binding key before reconciliation.",
                    "unknown",
                )
            if (
                isinstance(actual, MCPServerComponent)
                and actual.properties.get("collection_mode") == "static-config"
                and isinstance(declared, MCPServerComponent)
                and (
                    not declared.properties.get("static_config_hash")
                    or declared.properties.get("static_config_hash_profile")
                    != actual.properties["static_config_hash_profile"]
                )
            ):
                incomplete(
                    actual.bom_ref,
                    "Static MCP source binding is unknown in this snapshot; re-collect it before reconciliation.",
                    "unknown",
                )
            if (
                declared is None
                or not self._same_subject(root, declared, actual)
                or not self._retains_local_evidence(declared, actual, projected_refs)
            ):
                source_kind = {
                    ComponentType.PROMPT_TEMPLATE: "instruction files",
                    ComponentType.MODEL: "model files",
                    ComponentType.MCP_CLIENT: "MCP inventory",
                    ComponentType.MCP_SERVER: "MCP inventory",
                }.get(actual.component_type, actual.component_type.value)
                incomplete(
                    actual.bom_ref,
                    f"Missing or mismatched local component from {source_kind}: {actual.bom_ref}",
                )
        supplementary: dict[str, AnyComponent] = {}
        for extra in supplied.values():
            # Supplementary runtime observations have their own provenance. Missing
            # repository subjects cannot be explained by an unrelated observation.
            local_path = extra.source_path is not None and "://" not in extra.source_path
            local_claim = any(
                claim.scope in {"repository", "source-declaration", "dependency-resolution"}
                for claim in extra.claims.values()
            )
            if local_path or local_claim or not extra.claims:
                incomplete(
                    extra.bom_ref,
                    f"Supplied component has no matching local evidence: {extra.bom_ref}",
                )
            else:
                supplementary[extra.bom_ref] = extra
        local_servers = {
            c.bom_ref for c in expected.components if isinstance(c, MCPServerComponent)
        }
        for ref, reason in (
            *self._unestablished_verification(bom, supplementary),
            *self._unreconciled_attachments(bom, projected_refs, local_servers, supplementary),
        ):
            incomplete(ref, reason)
        return report

    @staticmethod
    def _unestablished_verification(
        bom: AIBOM, supplementary: dict[str, AnyComponent]
    ) -> list[tuple[str, str]]:
        """Report verification that no collector, live record or offline check establishes.

        Local subjects must already match the projection's assurance and trust tier, but
        a supplier can add claims to them. Nothing else checks supplementary components.
        """
        unestablished = "which project reconciliation cannot establish."
        verified_tiers = {TrustTier.INTERNAL_VERIFIED, TrustTier.THIRD_PARTY_SIGNED}
        problems: list[tuple[str, str]] = []
        for component in bom.components:
            ref = component.bom_ref
            if ref in supplementary and component.assurance_level is AssuranceLevel.VERIFIED:
                problems.append(
                    (
                        ref,
                        f"Supplementary component {ref} claims verified assurance, {unestablished}",
                    )
                )
            if ref in supplementary and component.trust_tier in verified_tiers:
                tier = component.trust_tier.value
                problems.append(
                    (ref, f"Supplementary component {ref} claims {tier} trust, {unestablished}")
                )
            problems.extend(
                (ref, f"Claim {name} on {ref} is verified, {unestablished}")
                for name, claim in component.claims.items()
                if claim.assurance is AssuranceLevel.VERIFIED
            )
        problems.extend(
            (
                "graph",
                f"Relationship {edge.relationship} {edge.source_ref} -> {edge.target_ref} "
                f"is verified, {unestablished}",
            )
            for edge in bom.dependencies
            if edge.assurance_level == "verified"
        )
        return problems

    @staticmethod
    def _unreconciled_attachments(
        bom: AIBOM,
        projected_refs: set[str],
        local_servers: set[str],
        supplementary: dict[str, AnyComponent],
    ) -> list[tuple[str, str]]:
        """Admit only the attachment that verify-live --record makes to local subjects.

        It records a tool served by a local MCP server, lists it in that server's
        tool_refs and links it by provides-tool from that server; an agent may also
        list the tool. Any other reference or relationship between a local subject
        and a supplementary component would attach an unchecked claim, such as a
        control, to the repository.
        """
        rank: dict[str | None, int] = {None: 0, "declared": 1, "observed": 2, "verified": 3}

        def server_of(ref: str) -> str | None:
            tool = supplementary.get(ref)
            if isinstance(tool, ToolComponent) and tool.mcp_server_ref in local_servers:
                return tool.mcp_server_ref
            return None

        problems: list[tuple[str, str]] = []
        for component in bom.components:
            for name in type(component).model_fields:
                if name == "bom_ref" or not name.endswith(("_ref", "_refs")):
                    continue
                value = getattr(component, name)
                for ref in value if isinstance(value, list) else [value] if value else []:
                    if component.bom_ref in projected_refs and ref in supplementary:
                        extra = ref
                        allowed = (
                            name == "tool_refs"
                            and server_of(ref) is not None
                            and (
                                isinstance(component, AgentComponent)
                                or component.bom_ref == server_of(ref)
                            )
                        )
                    elif component.bom_ref in supplementary and ref in projected_refs:
                        extra = component.bom_ref
                        allowed = name == "mcp_server_ref" and server_of(extra) == ref
                    else:
                        continue
                    if not allowed:
                        problems.append(
                            (
                                extra,
                                f"Reference {component.bom_ref}.{name} attaches supplementary "
                                f"component {extra} to a local subject; only a tool served by a "
                                "local MCP server can be attached.",
                            )
                        )
        for edge in bom.dependencies:
            if edge.source_ref in projected_refs and edge.target_ref in supplementary:
                extra = edge.target_ref
            elif edge.target_ref in projected_refs and edge.source_ref in supplementary:
                extra = edge.source_ref
            else:
                continue
            if (
                edge.relationship != "provides-tool"
                or edge.target_ref != extra
                or edge.source_ref != server_of(extra)
            ):
                problems.append(
                    (
                        extra,
                        f"Relationship {edge.relationship} {edge.source_ref} -> "
                        f"{edge.target_ref} attaches supplementary component {extra} to a local "
                        "subject; only provides-tool from the local MCP server serving that "
                        "tool can.",
                    )
                )
            elif rank[edge.assurance_level] > max(
                rank[claim.assurance.value] for claim in supplementary[extra].claims.values()
            ):
                problems.append(
                    (
                        extra,
                        f"Relationship {edge.relationship} with supplementary component {extra} "
                        "claims more assurance than its unverified claims support.",
                    )
                )
        return problems

    @staticmethod
    def _retains_local_evidence(
        supplied: AnyComponent, local: AnyComponent, projected_refs: set[str]
    ) -> bool:
        """Compare the fields populated by the collector, independently of supplier claims."""
        if local.properties.get("collection_mode") == "imported-unverified-report":
            return True  # _discovery_mismatches checks the entire source projection.
        fields = (local.model_fields_set | {"trust_tier", "assurance_level"}) - {
            "source_path",
            "risks",
            "claims",
            "properties",
        }
        if isinstance(local, AgentComponent) and isinstance(supplied, AgentComponent):
            # The assembler appends associations to default lists in place. Those
            # lists do not appear in model_fields_set and are unordered references.
            for name in AgentComponent.model_fields:
                if name.endswith("_refs"):
                    supplied_refs = (
                        ref for ref in getattr(supplied, name) if ref in projected_refs
                    )
                    if Counter(getattr(local, name)) != Counter(supplied_refs):
                        return False
                    fields.discard(name)
        if (
            isinstance(supplied, ToolComponent)
            and supplied.assurance_level == AssuranceLevel.OBSERVED
        ):
            served = supplied.claims.get("tool_definition")
            if (
                served
                and served.scope == "served-descriptor"
                and served.method == "operator-pinned-stdio-tools-list"
            ):
                # The served descriptor is a separate observation. Static declarations still match below.
                fields.discard("assurance_level")
        if isinstance(local, MCPServerComponent) and isinstance(supplied, MCPServerComponent):
            # A served descriptor can add tools beyond the static declarations.
            fields -= {"tool_refs", "tool_count"}
            if (
                not set(local.tool_refs) <= set(supplied.tool_refs)
                or supplied.tool_count < local.tool_count
            ):
                return False
        if (
            isinstance(local, ModelComponent)
            and isinstance(supplied, ModelComponent)
            and local.signing_status == "sigstore-signed"
            and supplied.signing_status != "sigstore-signed"
            and supplied.trust_tier == TrustTier.UNKNOWN
        ):
            # A newly supplied operator policy may corroborate an initially unsigned inventory.
            fields -= {"signing_status", "signing_identity", "trust_tier"}
        if canonical_json(local.model_dump(mode="json", include=fields)) != canonical_json(
            supplied.model_dump(mode="json", include=fields)
        ):
            return False
        if any(
            key not in supplied.properties
            or canonical_json(supplied.properties[key]) != canonical_json(value)
            for key, value in local.properties.items()
        ):
            return False
        for name, evidence in local.claims.items():
            if evidence.method == "not-collected":
                continue  # A separate observation can fill a gap in the static inventory.
            claim = supplied.claims.get(name)
            if claim is None or evidence.model_dump(exclude={"observed_at"}) != claim.model_dump(
                exclude={"observed_at"}
            ):
                return False
        # Preserve multiplicity. Independent findings and revised remediation text may be added.
        return Counter((r.severity, r.category, r.detail) for r in local.risks) <= Counter(
            (r.severity, r.category, r.detail) for r in supplied.risks
        )

    @staticmethod
    def _discovery_mismatches(bom: AIBOM, local: ScanResult) -> list[str]:
        """Bind every embedded ShadowScan assertion to the freshly projected report."""
        problems: list[str] = []
        claim = bom.metadata.completeness
        if claim is not None:
            if claim.source_report_digest != local.source_report_digest:
                problems.append("Local discovery report differs from the recorded digest.")
            if (
                claim.source_report_format != local.source_report_format
                or claim.source_report_status != local.source_report_status
                or claim.source_unmapped_count != local.source_unmapped_count
                or claim.source_unmapped_indexes != local.source_unmapped_indexes
                or claim.source_projection_limitations != local.source_projection_limitations
                or (claim.scope == "repository+shadowscan") != bool(local.source_report_digest)
            ):
                problems.append(
                    "Local discovery report scope or coverage differs from the projection."
                )
            if local.source_report_digest and (
                claim.assurance_level != AssuranceLevel.OBSERVED
                or "shadowscan:report" not in claim.surfaces_scanned
                or not {
                    "runtime",
                    "effective-identity",
                    "effective-authorization",
                    "live-tools",
                    "network",
                }.issubset(claim.unobserved_surfaces)
            ):
                problems.append("Static discovery coverage or assurance is misrepresented.")

        actual = {c.bom_ref: c for c in local.components}
        imported_refs = set(actual)
        # Imported relationships are supplier claims with source-bound provenance.
        # Compare a sorted list to retain multiplicity and detect injected local links.
        projected_edges = sorted(
            canonical_json(edge.model_dump(mode="json")) for edge in local.dependencies
        )
        supplied_edges = sorted(
            canonical_json(edge.model_dump(mode="json"))
            for edge in bom.dependencies
            if edge.source_ref in imported_refs or edge.target_ref in imported_refs
        )
        if supplied_edges != projected_edges:
            problems.append("Discovery report dependency claims differ from the source projection.")
        for supplied in bom.components:
            component = actual.pop(supplied.bom_ref, None)
            if component is None:
                if (
                    supplied.bom_ref.startswith("shadowscan:")
                    or supplied.properties.get("collection_mode") == "imported-unverified-report"
                    or any(key.startswith("shadowscan:") for key in supplied.properties)
                    or "discovery_report_entry" in supplied.claims
                ):
                    problems.append(f"Unexpected discovery report component: {supplied.bom_ref}")
                continue
            # The combined scan annotates the direct projection at inventory creation.
            # Its timestamp is generated locally; it is not an upstream observation.
            component = component.model_copy(
                update={
                    "claims": {
                        **component.claims,
                        "discovery_report_entry": ClaimEvidence(
                            assurance=AssuranceLevel.DECLARED,
                            method="imported-discovery-report",
                            scope="source-report",
                            collector="shadowscan",
                            locator=component.source_path,
                            observed_at=bom.metadata.timestamp,
                        ),
                    }
                }
            )
            if canonical_json(supplied.model_dump(mode="json")) != canonical_json(
                component.model_dump(mode="json")
            ):
                problems.append(
                    f"Component differs from the discovery report projection: {supplied.bom_ref}"
                )
        problems.extend(f"Missing discovery report component: {ref}" for ref in actual)
        return problems

    @staticmethod
    def _same_subject(root: Path, supplied: AnyComponent, local: AnyComponent) -> bool:
        # Lexical comparison accepts in-root absolute and relative representations
        # without following a manifest-selected symlink or normalizing traversal.
        source = root / supplied.source_path if supplied.source_path is not None else None
        expected = root / local.source_path if local.source_path is not None else None
        if (
            supplied.component_type != local.component_type
            or supplied.name != local.name
            or (local.version is not None and supplied.version != local.version)
            or source != expected
        ):
            return False
        if isinstance(local, RegistryEntryComponent) and local.package_url is not None:
            return isinstance(supplied, RegistryEntryComponent) and (
                supplied.package_url == local.package_url
                and supplied.registry_type == local.registry_type
            )
        if (
            isinstance(local, (A2AClientComponent, A2AServerComponent))
            and local.properties.get("collection_mode") in A2A_STATIC_MODES
        ):
            return (
                isinstance(supplied, type(local))
                and has_a2a_source_binding(supplied)
                and has_a2a_source_binding(local)
                and all(
                    supplied.properties.get(field) == local.properties.get(field)
                    for field in A2A_SOURCE_BINDING_FIELDS
                )
            )
        if (
            isinstance(local, MCPServerComponent)
            and local.properties.get("collection_mode") == "static-config"
        ):
            # A legacy record missing the current launcher package or the versioned
            # source binding cannot bind this subject. Redaction hides executable
            # arguments and endpoint paths, so matching package versions or redacted
            # strings do not identify the same launcher. Live observations may add
            # descriptor evidence but cannot supply missing static source evidence.
            return (
                isinstance(supplied, MCPServerComponent)
                and (
                    supplied.transport,
                    supplied.command,
                    supplied.endpoint_url,
                    supplied.launcher_package,
                    supplied.version,
                    supplied.version_pinned,
                )
                == (
                    local.transport,
                    local.command,
                    local.endpoint_url,
                    local.launcher_package,
                    local.version,
                    local.version_pinned,
                )
                and all(
                    supplied.properties.get(field) == local.properties.get(field)
                    for field in (
                        "static_config_hash",
                        "static_config_hash_profile",
                        "static_value_binding",
                        "static_value_binding_key_id",
                        "static_value_binding_profile",
                    )
                )
            )
        if (
            isinstance(local, ToolComponent)
            and local.properties.get("collection_mode") == "static-config"
        ):
            # IntegrityValidator checks the supplied descriptor's consistency
            # with its own digest. Reconciliation must independently compare
            # that digest to the original descriptor freshly read from config.
            # A served descriptor is a different observation scope and cannot
            # replace this source binding merely by asserting live provenance.
            return isinstance(supplied, ToolComponent) and (
                supplied.mcp_server_ref,
                supplied.definition_hash_version,
                supplied.definition_hash,
            ) == (
                local.mcp_server_ref,
                local.definition_hash_version,
                local.definition_hash,
            )
        return True

    def _find_orphan_refs(self, bom: AIBOM) -> list[tuple[str, str]]:
        all_refs = {c.bom_ref for c in bom.components}
        orphans: list[tuple[str, str]] = []

        for dep in bom.dependencies:
            if dep.source_ref not in all_refs:
                orphans.append((dep.source_ref, "dependency.source_ref"))
            if dep.target_ref not in all_refs:
                orphans.append((dep.target_ref, "dependency.target_ref"))

        for c in bom.components:
            for ref_field in (
                "model_refs",
                "tool_refs",
                "memory_refs",
                "prompt_refs",
                "guardrail_refs",
                "sub_agent_refs",
            ):
                refs = getattr(c, ref_field, None)
                if refs:
                    for ref in refs:
                        if ref not in all_refs:
                            orphans.append((ref, f"{c.bom_ref}.{ref_field}"))

            for ref_field in (
                "mcp_server_ref",
                "model_ref",
                "embedding_model_ref",
                "registry_ref",
                "base_model_ref",
            ):
                ref = getattr(c, ref_field, None)
                if ref and ref not in all_refs:
                    orphans.append((ref, f"{c.bom_ref}.{ref_field}"))

        return orphans
