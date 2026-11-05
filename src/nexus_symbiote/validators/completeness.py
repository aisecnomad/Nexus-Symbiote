"""Completeness validator — checks that an AIBOM covers all expected surfaces."""

from __future__ import annotations

import hmac
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, TrustTier
from nexus_symbiote.core.hashing import canonical_json
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    ClaimEvidence,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    ToolComponent,
)
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES

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


def _binding_equal(supplied: object, local: object) -> bool:
    """Compare binding tags without an early exit at the first differing byte.

    Only string pairs take the constant-time path: ``hmac.compare_digest`` raises on
    ``None``, non-string or non-ASCII values, and a hostile inventory can hold any of them.
    """
    if isinstance(supplied, str) and isinstance(local, str):
        return hmac.compare_digest(supplied.encode("utf-8"), local.encode("utf-8"))
    return supplied == local


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
            for component in local.components:
                previous = observed.setdefault(component.bom_ref, component)
                if previous != component:
                    incomplete(scanner.name, f"Conflicting local reference: {component.bom_ref}")

        expected = AIBOM(components=list(observed.values()))
        try:
            agent = assemble_repository_agent(expected, root)
        except (OSError, ValueError, RecursionError):
            incomplete("agent.yaml", "Local agent manifest could not be reconciled.")
        else:
            if agent.properties.get("identity_source") == "repository-path":
                # An inferred, checkout-specific root is not itself a project artifact.
                expected.components.remove(agent)

        report.local_subjects = sum(
            c.properties.get("collection_mode") != "imported-unverified-report"
            for c in expected.components
        )
        supplied = {c.bom_ref: c for c in bom.components}
        for actual in expected.components:
            declared = supplied.pop(actual.bom_ref, None)
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
                or not self._retains_local_evidence(declared, actual)
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
        for extra in supplied.values():
            if (
                isinstance(extra, AgentComponent)
                and extra.properties.get("identity_source") == "repository-path"
            ):
                continue
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
        return report

    @staticmethod
    def _retains_local_evidence(supplied: AnyComponent, local: AnyComponent) -> bool:
        """Compare the fields populated by the collector, independently of supplier claims."""
        if local.properties.get("collection_mode") == "imported-unverified-report":
            return True  # _discovery_mismatches checks the entire source projection.
        fields = (local.model_fields_set | {"trust_tier", "assurance_level"}) - {
            "source_path",
            "risks",
            "claims",
            "properties",
        }
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
                    _binding_equal(supplied.properties.get(field), local.properties.get(field))
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
