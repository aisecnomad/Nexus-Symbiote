"""Completeness: coverage claims, graph integrity and reconciliation with a project."""

from __future__ import annotations

import hmac
import json
import unicodedata
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Literal
from urllib.parse import urlsplit

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.collection import (
    IMPORTED_MODE,
    is_imported,
    merge_collected,
)
from nexus_symbiote.core.coverage import assess_coverage
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, TrustTier
from nexus_symbiote.core.evidence import ClaimState, VerificationStatus
from nexus_symbiote.core.hashing import canonical_json
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    ClaimEvidence,
    CompletenessClaim,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    RegistryEntryComponent,
    RiskAssessment,
    ToolComponent,
    VerifiedExtensionComponent,
)
from nexus_symbiote.scanner_catalog import BUILTIN_SCANNER_NAMES
from nexus_symbiote.utils.confined import DEFAULT_EXCLUDES, ConfinedCollection
from nexus_symbiote.utils.crypto import (
    SIGNING_EVIDENCE_CLAIM,
    VERIFIED_SIGNING_STATUSES,
    comparable_claim,
)

if TYPE_CHECKING:
    from nexus_symbiote.scanners.base import ScanResult
    from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy

REQUIRED_SCANNERS = BUILTIN_SCANNER_NAMES
MAX_REPORTED_ISSUES = 1000
MAX_REPORTED_SUPPLIER_CLAIMS = 1000
LOCAL_CLAIM_SCOPES = frozenset({"repository", "source-declaration", "dependency-resolution"})
UNOBSERVED_SURFACES = frozenset(
    {"runtime", "effective-identity", "effective-authorization", "live-tools", "network"}
)
"""Surfaces static collection never observes; every coverage claim it makes lists them."""
COVERAGE_CLAIM = "metadata.completeness"
REMOTE_SOURCE_SCHEMES = frozenset({"http", "https", "ws", "wss", "ssh", "git", "hf", "s3", "gs"})
"""Schemes of the remote locations collectors record: web and MCP endpoints, git and ssh
package sources, model hub and object-store retrieval sources. A ``source_path`` is outside
the checkout only as ``scheme://host`` with one of them; anything else names a local file."""
SIGNING_FINDING = "signing_status"
"""The model collector's finding for weights without a verified artifact-bound signature."""
AGENT_REFERENCE_FIELDS = (
    "model_refs",
    "tool_refs",
    "memory_refs",
    "prompt_refs",
    "guardrail_refs",
    "sub_agent_refs",
    "data_refs",
    "skill_refs",
)
_BLOCKING = frozenset({"critical", "error", "unknown"})
_SEVERITY_RANK = {"critical": 0, "error": 0, "unknown": 1, "warning": 2, "info": 3}
NO_LOCAL_SUBJECT = "No local project subject was available to reconcile."

Basis = Literal[
    "supplied-claims",
    "project-reconciled",
    "project-reconciled-with-supplier-claims",
    "project-reconciliation-failed",
]


def _binding_equal(supplied: object, local: object) -> bool:
    """Compare binding tags without an early exit at the first differing byte.

    Only string pairs take the constant-time path: ``hmac.compare_digest`` raises on
    ``None``, non-string or non-ASCII values, and a hostile inventory can hold any of them,
    including lone surrogates, which ``surrogatepass`` still encodes to distinct bytes.
    """
    if isinstance(supplied, str) and isinstance(local, str):
        return hmac.compare_digest(
            supplied.encode("utf-8", "surrogatepass"), local.encode("utf-8", "surrogatepass")
        )
    return supplied == local


@dataclass
class CompletenessIssue:
    surface: str
    description: str
    severity: str = "warning"


@dataclass(frozen=True)
class SupplierClaim:
    """Supplied content that reconciliation accepted without local evidence for it."""

    subject: str
    kind: Literal["component", "field", "claim", "property", "relationship", "risk"]
    detail: str


@dataclass
class CompletenessReport:
    is_complete: bool = True
    surfaces_covered: list[str] = field(default_factory=list)
    surfaces_missing: list[str] = field(default_factory=list)
    issues: list[CompletenessIssue] = field(default_factory=list)
    assurance_level: AssuranceLevel = AssuranceLevel.DECLARED
    component_type_coverage: dict[str, int] = field(default_factory=dict)
    total_components: int = 0
    coverage_status: str = "unknown"
    basis: Basis = "supplied-claims"
    local_subjects: int | None = None
    supplier_claims: list[SupplierClaim] = field(default_factory=list)
    bound_imports: frozenset[str] = frozenset()
    issues_omitted: int = 0
    supplier_claims_omitted: int = 0

    def add_issue(self, surface: str, description: str, severity: str = "error") -> None:
        if severity in _BLOCKING:
            self.is_complete = False
        self.issues.append(CompletenessIssue(surface, description, severity))

    def add_supplier_claim(self, claim: SupplierClaim) -> None:
        if len(self.supplier_claims) < MAX_REPORTED_SUPPLIER_CLAIMS:
            self.supplier_claims.append(claim)
        else:
            self.supplier_claims_omitted += 1

    def bound_issues(self) -> None:
        """Keep at most ``MAX_REPORTED_ISSUES`` issues, blocking ones first.

        The verdict is fixed before truncation, so an omitted issue still counts.
        """
        if len(self.issues) <= MAX_REPORTED_ISSUES:
            return
        ranked = sorted(self.issues, key=lambda issue: _SEVERITY_RANK.get(issue.severity, 0))
        self.issues_omitted += len(ranked) - MAX_REPORTED_ISSUES
        self.issues = ranked[:MAX_REPORTED_ISSUES]

    def to_dict(self) -> dict[str, object]:
        return {
            "is_complete": self.is_complete,
            "assessment_basis": self.basis,
            "coverage_status": self.coverage_status,
            "surfaces_covered": self.surfaces_covered,
            "surfaces_missing": self.surfaces_missing,
            "issues": [
                {"surface": i.surface, "description": i.description, "severity": i.severity}
                for i in self.issues
            ],
            "issues_omitted": self.issues_omitted,
            "assurance_level": self.assurance_level.value,
            "component_type_coverage": self.component_type_coverage,
            "total_components": self.total_components,
            "local_subjects": self.local_subjects,
            "imported_components_bound": len(self.bound_imports),
            "supplier_claims": [
                {"subject": c.subject, "kind": c.kind, "detail": c.detail}
                for c in self.supplier_claims
            ],
            "supplier_claims_omitted": self.supplier_claims_omitted,
        }


def _edge_key(edge: DependencyEdge) -> str:
    return canonical_json(edge.model_dump(mode="json"))


def _edge_label(key: str) -> str:
    data = json.loads(key)
    return f"{data['source_ref']} -[{data['relationship']}]-> {data['target_ref']}"


def _normalized(value: str | None) -> str | None:
    return None if value is None else unicodedata.normalize("NFKC", value).strip().casefold()


def _verified_fields(component: AnyComponent) -> set[str]:
    """Fields whose value asserts a verification that offline collection never performs."""
    fields: set[str] = set()
    if component.assurance_level is AssuranceLevel.VERIFIED:
        fields.add("assurance_level")
    if component.trust_tier is TrustTier.INTERNAL_VERIFIED:
        fields.add("trust_tier")
    if isinstance(component, AgentComponent) and component.deployment_profile is not None:
        if any(
            authority.state == ClaimState.VERIFIED
            or any(e.verification_status == VerificationStatus.VERIFIED for e in authority.evidence)
            for authority in component.deployment_profile.authority
        ):
            fields.add("deployment_profile")
    if isinstance(component, RegistryEntryComponent | VerifiedExtensionComponent):
        if component.publisher_verified is True:
            fields.add("publisher_verified")
        if _normalized(component.attestation_status) == "verified":
            fields.add("attestation_status")
    if (
        isinstance(component, ModelComponent)
        and _normalized(component.signing_status) in VERIFIED_SIGNING_STATUSES
    ):
        fields.add("signing_status")
    return fields


def _asserts_unestablished_trust(component: AnyComponent) -> bool:
    return bool(_verified_fields(component)) or any(
        claim.assurance is AssuranceLevel.VERIFIED for claim in component.claims.values()
    )


def _remote_source(source_path: str) -> bool:
    try:
        parsed = urlsplit(source_path)
    except ValueError:
        return False
    # urlsplit strips leading blanks and drops tabs and newlines; the text itself must
    # start with the scheme and "://".
    return (
        parsed.scheme in REMOTE_SOURCE_SCHEMES
        and bool(parsed.hostname)
        and source_path[: len(parsed.scheme) + 3].lower() == f"{parsed.scheme}://"
    )


def _finding_key(risk: RiskAssessment) -> str:
    return canonical_json(risk.model_dump(mode="json"))


def _unestablished_trust(ref: str) -> str:
    return (
        "Supplied component asserts verified assurance or internal-verified trust "
        f"without local corroboration: {ref}"
    )


class CompletenessValidator:
    """Validates that an AIBOM covers all expected attack surfaces."""

    def validate(self, bom: AIBOM) -> CompletenessReport:
        report = self._validate_claims(bom)
        report.bound_issues()
        return report

    def _validate_claims(self, bom: AIBOM) -> CompletenessReport:
        from nexus_symbiote.graph import validate_graph
        from nexus_symbiote.scanners.prompt import withholds_content_hash

        report = CompletenessReport()
        report.total_components = len(bom.components)

        type_counts: dict[str, int] = {}
        for c in bom.components:
            key = c.component_type.value
            type_counts[key] = type_counts.get(key, 0) + 1
        report.component_type_coverage = type_counts

        claim = bom.metadata.completeness
        if claim:
            report.surfaces_covered = list(claim.surfaces_scanned)
            report.surfaces_missing = list(claim.surfaces_excluded)
            report.assurance_level = claim.assurance_level
        coverage = assess_coverage(claim)
        report.coverage_status = coverage.status.value
        for gap in coverage.gaps:
            report.add_issue(gap.subject, gap.reason, "error")
        # A repository observation is complete only within its stated collection scope.
        # It does not require tools/prompts to exist in every project.

        for c in bom.components:
            if not c.hashes and c.component_type in (
                ComponentType.MODEL,
                ComponentType.TOOL,
                ComponentType.PROMPT_TEMPLATE,
            ):
                if not (hasattr(c, "content_hash") and c.content_hash):
                    # A prompt file that is not an instruction file, such as an import
                    # that is not Markdown, is bound only by the operator key; integrity
                    # verifies that binding or counts it as unbound.
                    if not (hasattr(c, "definition_hash") and c.definition_hash) and not (
                        isinstance(c, PromptComponent) and withholds_content_hash(c)
                    ):
                        report.add_issue(
                            c.bom_ref, f"Component '{c.name}' has no integrity hash.", "warning"
                        )

        for issue in validate_graph(bom):
            report.add_issue("graph", issue, "error")
        for surface in report.surfaces_missing:
            report.add_issue("coverage", f"Surface excluded: {surface}", "info")
        return report

    def validate_against_project(
        self,
        bom: AIBOM,
        project_root: Path,
        *,
        exclude_paths: Sequence[str] = (),
        signature_policies: Sequence[SigstoreArtifactPolicy] = (),
        accept_default_excludes: bool | tuple[str, ...] = False,
    ) -> CompletenessReport:
        """Recollect the supported static inventory under caller-selected scope.

        Supplied statuses, exclusions, and paths cannot select or disable a collector.
        Only the local built-in collectors run. None executes project code or uses
        remote discovery. Components, the repository agent and the relationships among
        local components must equal the recollection, and the coverage claim must state
        the local scope, at most observed assurance and the surfaces static collection
        cannot observe; anything else the supplier added is either refused or listed as
        a supplier claim, never presented as reconciled. The report's coverage is the
        local collection's. Integrity and signer policy are checked separately.
        """
        from nexus_symbiote.graph import assemble_repository_agent
        from nexus_symbiote.scanners import ALL_SCANNERS, ModelScanner
        from nexus_symbiote.text_poisoning import apply_text_poisoning_rules

        report = self._validate_claims(bom)
        report.basis = "project-reconciled"
        root = project_root.absolute()
        collected: dict[str, AnyComponent] = {}
        incomplete = report.add_issue
        surfaces: list[str] = []
        excluded: list[str] = []
        accepted_default_exclusions: set[str] = set()
        accepted_default_names: set[str] = set()
        status: dict[str, str] = {}
        report_digest: str | None = None

        for scanner_type in ALL_SCANNERS:
            scanner = (
                ModelScanner(signature_policies=signature_policies)
                if scanner_type is ModelScanner
                else scanner_type()
            )
            scanner.configure(
                exclude_paths=exclude_paths,
                accept_default_excludes=accept_default_excludes,
            )
            try:
                local = scanner.scan(root)
            except Exception:
                incomplete(
                    scanner.name, "Local collector failed; inventory could not be reconciled."
                )
                status[scanner.name] = "failed"
                continue
            local.make_portable(root)
            for reason in (*local.scan_failures, *local.surfaces_excluded):
                incomplete(scanner.name, f"Local collection incomplete: {reason}")
            if scanner.name == "shadowscan":
                report_digest = local.source_report_digest
                problems = self._discovery_mismatches(bom, local)
                for reason in problems:
                    incomplete(scanner.name, reason)
                if not problems:
                    report.bound_imports = frozenset(c.bom_ref for c in local.components)
            failed = bool(local.scan_failures)
            for component in local.components:
                if merge_collected(collected, component, scanner.name, None) == "conflict":
                    incomplete(scanner.name, f"Conflicting local reference: {component.bom_ref}")
                    failed = True
            surfaces.extend(local.surfaces_scanned)
            excluded.extend(local.surfaces_excluded)
            accepted_default_exclusions.update(local.accepted_default_exclusions)
            accepted_default_names.update(local.accepted_default_names)
            status[scanner.name] = (
                "failed" if failed else "partial" if local.surfaces_excluded else "complete"
            )

        expected = AIBOM(components=list(collected.values()))
        agent: AgentComponent | None = None
        try:
            agent = assemble_repository_agent(
                expected, root, exclude_paths=exclude_paths, surfaces=surfaces
            )
        except (OSError, ValueError, RecursionError):
            incomplete("agent.yaml", "Local agent manifest could not be reconciled.")
        # scan appends these findings after the manifest, so they are re-derived here too;
        # otherwise an inventory with them deleted would match a poisoned checkout.
        text_failures: list[str] = []
        apply_text_poisoning_rules(
            expected, root, exclude_paths=exclude_paths, failures=text_failures, surfaces=surfaces
        )
        for reason in text_failures:
            incomplete("text_poisoning", f"Local collection incomplete: {reason}")
        coverage = self._local_coverage(
            report_digest,
            surfaces,
            excluded,
            status,
            [*exclude_paths, *accepted_default_exclusions],
        )
        coverage.unobserved_surfaces.extend(
            f"accepted default exclusion: {name}" for name in sorted(accepted_default_names)
        )
        report.assurance_level = coverage.assurance_level
        report.surfaces_covered = coverage.surfaces_scanned
        report.surfaces_missing = coverage.surfaces_excluded
        self._reconcile_coverage(bom.metadata.completeness, coverage, root, report)

        # An agent inferred without a manifest is evidence of nothing in the checkout.
        inferred_agent = (
            agent is not None and agent.properties.get("identity_source") == "repository-path"
        )
        report.local_subjects = sum(
            not is_imported(c) and not (inferred_agent and c is agent) for c in expected.components
        )
        if not report.local_subjects:
            incomplete("project", NO_LOCAL_SUBJECT)

        # The repository agent's reference and name do not depend on the checkout
        # location, so every local component, the agent included, is matched by reference.
        supplied = {c.bom_ref: c for c in bom.components}
        local_refs = {c.bom_ref for c in expected.components if not is_imported(c)}
        mismatched = False
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
                mismatched = True
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
            elif not is_imported(actual):
                additions = self._supplier_only(declared, actual)
                if self._asserts_verification(declared, additions):
                    incomplete(actual.bom_ref, _unestablished_trust(actual.bom_ref))
                else:
                    for claim in (*additions, *self._supplier_findings(declared, actual)):
                        report.add_supplier_claim(claim)
        if mismatched and bom.metadata.spec_version.startswith("1.0."):
            incomplete(
                "format",
                "The inventory uses native format 1.0, which records absolute scan-host paths; "
                "re-collect it with this version before reconciling it with a project.",
                "info",
            )

        self._reconcile_relationships(bom, expected, local_refs, supplied, report)
        for extra in supplied.values():
            if is_imported(extra):
                continue  # _discovery_mismatches binds every imported claim to the report.
            # Supplementary runtime observations have their own provenance. Missing
            # repository subjects cannot be explained by an unrelated observation.
            local_path = extra.source_path is not None and not _remote_source(extra.source_path)
            local_claim = any(claim.scope in LOCAL_CLAIM_SCOPES for claim in extra.claims.values())
            if local_path or local_claim or not extra.claims:
                incomplete(
                    extra.bom_ref,
                    f"Supplied component has no matching local evidence: {extra.bom_ref}",
                )
            elif _asserts_unestablished_trust(extra):
                incomplete(extra.bom_ref, _unestablished_trust(extra.bom_ref))
            else:
                report.add_supplier_claim(
                    SupplierClaim(extra.bom_ref, "component", "supplementary observation")
                )
        if report.supplier_claims or report.supplier_claims_omitted:
            report.basis = "project-reconciled-with-supplier-claims"
        if not report.is_complete:
            report.basis = "project-reconciliation-failed"
        report.bound_issues()
        return report

    @staticmethod
    def _local_coverage(
        report_digest: str | None,
        surfaces: list[str],
        excluded: list[str],
        status: dict[str, str],
        exclude_paths: Sequence[str],
    ) -> CompletenessClaim:
        """The coverage claim ``scan`` records for what the local collectors did."""
        completed = [name for name, state in status.items() if state != "failed"]
        return CompletenessClaim(
            scope="repository+shadowscan" if report_digest else "repository",
            surfaces_scanned=sorted(set(surfaces)),
            surfaces_excluded=sorted(set(excluded)),
            assurance_level=AssuranceLevel.OBSERVED if completed else AssuranceLevel.DECLARED,
            scanner_status=status,
            collectors_requested=list(status),
            collectors_completed=completed,
            exclusions=sorted(
                {*map(str, exclude_paths), *(f"**/{name}" for name in DEFAULT_EXCLUDES)}
            ),
            unobserved_surfaces=sorted(UNOBSERVED_SURFACES),
        )

    @staticmethod
    def _reconcile_coverage(
        claim: CompletenessClaim | None,
        local: CompletenessClaim,
        root: Path,
        report: CompletenessReport,
    ) -> None:
        """Refuse coverage the local run contradicts; list coverage it cannot confirm.

        A scope other than the local one, verified assurance, or a runtime surface
        recorded as observed misrepresents static collection. Surfaces, exclusions and
        collector records are supplier claims where they state more than the local run:
        a surface or collector it did not record, or a path it excluded that the claim
        does not. Recording less claims less coverage, which the local run already shows.
        """
        from nexus_symbiote.scanners.base import project_relative

        if claim is None:
            return  # assess_coverage already reports the missing claim.
        if claim.scope != local.scope:
            report.add_issue(
                COVERAGE_CLAIM,
                f"Coverage claim scope differs from the local collection ({local.scope}).",
            )
        if claim.assurance_level is AssuranceLevel.VERIFIED:
            report.add_issue(
                COVERAGE_CLAIM,
                "Coverage claim asserts verified assurance; offline collection cannot "
                "establish it.",
            )
        missing = sorted(set(local.unobserved_surfaces).difference(claim.unobserved_surfaces))
        if missing:
            report.add_issue(
                COVERAGE_CLAIM,
                "Coverage claim leaves out of unobserved_surfaces what static collection "
                "cannot observe: " + ", ".join(missing),
            )
        relative = project_relative(root)
        scanned = {relative(surface) for surface in claim.surfaces_scanned}
        beyond_local = {
            "surfaces_scanned": scanned - set(local.surfaces_scanned),
            # A default name is excluded at every level, whichever list names it.
            "exclusions": set(local.exclusions) - DEFAULT_EXCLUDES - set(claim.exclusions),
            "collectors_requested": set(claim.collectors_requested)
            - set(local.collectors_requested),
            "collectors_completed": set(claim.collectors_completed)
            - set(local.collectors_completed),
            "scanner_status": claim.scanner_status.items() - local.scanner_status.items(),
        }
        for name, stated in beyond_local.items():
            if stated:
                report.add_supplier_claim(SupplierClaim(COVERAGE_CLAIM, "field", name))

    @staticmethod
    def _reconcile_relationships(
        bom: AIBOM,
        expected: AIBOM,
        local_refs: set[str],
        extras: dict[str, AnyComponent],
        report: CompletenessReport,
    ) -> None:
        """Relationships among local components must equal the local assembly exactly.

        Edges that touch imported discovery components are bound by
        ``_discovery_mismatches``. Edges to supplementary components are supplier claims
        and may not assert verified assurance.
        """
        imported_refs = {c.bom_ref for c in bom.components if is_imported(c)}
        local = Counter(
            _edge_key(edge)
            for edge in expected.dependencies
            if edge.source_ref in local_refs and edge.target_ref in local_refs
        )
        supplied: Counter[str] = Counter()
        for edge in bom.dependencies:
            source, target = edge.source_ref, edge.target_ref
            if source in imported_refs or target in imported_refs:
                continue
            if source in local_refs and target in local_refs:
                supplied[_edge_key(edge)] += 1
            elif source in extras or target in extras:
                if edge.assurance_level == "verified":
                    report.add_issue(
                        "relationship",
                        "Supplied relationship asserts verified assurance without local "
                        f"evidence: {edge.source_ref} -[{edge.relationship}]-> {edge.target_ref}",
                    )
                else:
                    report.add_supplier_claim(
                        SupplierClaim(
                            edge.source_ref,
                            "relationship",
                            f"{edge.relationship} {edge.target_ref}",
                        )
                    )
        for key in sorted((local - supplied).elements()):
            report.add_issue(
                "relationship", f"Missing or altered local relationship: {_edge_label(key)}"
            )
        for key in sorted((supplied - local).elements()):
            report.add_issue(
                "relationship",
                f"Supplied relationship between local components has no local evidence: "
                f"{_edge_label(key)}",
            )

    @staticmethod
    def _supplier_only(supplied: AnyComponent, local: AnyComponent) -> list[SupplierClaim]:
        """Fields, properties and claims the supplier added where the collector had none."""
        compared = CompletenessValidator._compared_fields(supplied, local)
        skip = compared | {"bom_ref", "component_type", "source_path", "risks", "claims"}
        skip |= {"properties"}
        if CompletenessValidator._signing_corroborated(supplied, local):
            # The operator policy verified what the supplier recorded as unverified; an
            # identity the supplier asserts is still its own claim.
            skip |= {"signing_status", "trust_tier"}
            if getattr(supplied, "signing_identity", None) is None:
                skip.add("signing_identity")
        local_data = local.model_dump(mode="json")
        supplied_data = supplied.model_dump(mode="json")
        claims = [
            SupplierClaim(supplied.bom_ref, "field", name)
            for name in type(local).model_fields
            if name not in skip
            and canonical_json(local_data.get(name)) != canonical_json(supplied_data.get(name))
        ]
        claims.extend(
            SupplierClaim(supplied.bom_ref, "property", key)
            for key in sorted(supplied.properties.keys() - local.properties.keys())
        )
        claims.extend(
            SupplierClaim(supplied.bom_ref, "claim", name)
            for name in CompletenessValidator._added_claims(supplied, local)
        )
        return claims

    @staticmethod
    def _asserts_verification(supplied: AnyComponent, additions: list[SupplierClaim]) -> bool:
        """A field or claim only the supplier records asserts what collection never verifies."""
        fields = {claim.detail for claim in additions if claim.kind == "field"}
        claims = {claim.detail for claim in additions if claim.kind == "claim"}
        return bool(fields & _verified_fields(supplied)) or any(
            supplied.claims[name].assurance is AssuranceLevel.VERIFIED for name in claims
        )

    @staticmethod
    def _supplier_findings(supplied: AnyComponent, local: AnyComponent) -> list[SupplierClaim]:
        """Supplied findings with no exactly equal local finding, remediation text included.

        ``_retains_local_evidence`` keeps every local severity, category and detail, so a
        finding left over was added or had its recommendation or references rewritten.
        Where an operator policy verified a model the supplier left unsigned, the
        supplier's signing finding is the one that policy resolved.
        """
        resolved = CompletenessValidator._signing_corroborated(supplied, local)
        remaining: Counter[str] = Counter()
        identities: dict[str, tuple[str, str, str]] = {}
        for risk in local.risks:
            key = _finding_key(risk)
            remaining[key] += 1
            identities[key] = (risk.severity.value, risk.category, risk.detail)
        unmatched: list[RiskAssessment] = []
        for risk in supplied.risks:
            key = _finding_key(risk)
            if remaining[key] > 0:
                remaining[key] -= 1
            elif not (resolved and risk.category == SIGNING_FINDING):
                unmatched.append(risk)
        revised: Counter[tuple[str, str, str]] = Counter()
        for key, count in remaining.items():
            revised[identities[key]] += count
        claims: list[SupplierClaim] = []
        for risk in unmatched:
            identity = (risk.severity.value, risk.category, risk.detail)
            if revised[identity] > 0:
                revised[identity] -= 1
                change = "remediation differs from the local finding"
            else:
                change = "not in the local collection"
            claims.append(
                SupplierClaim(
                    supplied.bom_ref, "risk", f"{risk.severity.value} {risk.category}: {change}"
                )
            )
        return claims

    @staticmethod
    def _added_claims(supplied: AnyComponent, local: AnyComponent) -> list[str]:
        """Claims the supplier added, including one that replaces a not-collected gap."""
        added: list[str] = []
        for name, claim in sorted(supplied.claims.items()):
            evidence = local.claims.get(name)
            if evidence is None or (
                evidence.method == "not-collected"
                and comparable_claim(claim) != comparable_claim(evidence)
            ):
                added.append(name)
        return added

    @staticmethod
    def _signing_corroborated(supplied: AnyComponent, local: AnyComponent) -> bool:
        """A newly supplied operator policy verifies a model the supplier left unverified."""
        return (
            isinstance(local, ModelComponent)
            and isinstance(supplied, ModelComponent)
            and local.signing_status in VERIFIED_SIGNING_STATUSES
            and supplied.signing_status not in VERIFIED_SIGNING_STATUSES
            and supplied.trust_tier == TrustTier.UNKNOWN
        )

    @staticmethod
    def _compared_fields(supplied: AnyComponent, local: AnyComponent) -> set[str]:
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
                and local.assurance_level != AssuranceLevel.OBSERVED
            ):
                # The served descriptor is a separate observation. Static declarations still match below.
                fields.discard("assurance_level")
        if isinstance(local, MCPServerComponent):
            # A served descriptor can add tools beyond the static declarations.
            fields -= {"tool_refs", "tool_count"}
        if isinstance(local, AgentComponent):
            fields -= set(AGENT_REFERENCE_FIELDS)
        if CompletenessValidator._signing_corroborated(supplied, local):
            # A newly supplied operator policy may corroborate an initially unsigned inventory.
            fields -= {"signing_status", "signing_identity", "trust_tier"}
        return fields

    @staticmethod
    def _retains_local_evidence(supplied: AnyComponent, local: AnyComponent) -> bool:
        """Compare the fields populated by the collector, independently of supplier claims."""
        if is_imported(local):
            return True  # _discovery_mismatches checks the entire source projection.
        fields = CompletenessValidator._compared_fields(supplied, local)
        corroborated = CompletenessValidator._signing_corroborated(supplied, local)
        if isinstance(local, MCPServerComponent) and isinstance(supplied, MCPServerComponent):
            if (
                not set(local.tool_refs) <= set(supplied.tool_refs)
                or supplied.tool_count < local.tool_count
            ):
                return False
        if isinstance(local, AgentComponent) and isinstance(supplied, AgentComponent):
            # Assembly order follows the collector order, which a scan may choose.
            if any(
                sorted(getattr(local, name)) != sorted(getattr(supplied, name))
                for name in AGENT_REFERENCE_FIELDS
            ):
                return False
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
            if evidence.method == "not-collected" or (
                corroborated and name == SIGNING_EVIDENCE_CLAIM
            ):
                continue  # A separate observation can fill a gap in the static inventory.
            claim = supplied.claims.get(name)
            if claim is None or comparable_claim(evidence) != comparable_claim(claim):
                return False
        # Preserve multiplicity. Added findings and revised remediation text are supplier
        # claims, listed by _supplier_findings.
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
            elif (
                claim.source_report_content_digest != local.source_report_content_digest
                or claim.source_report_content_profile != local.source_report_content_profile
            ):
                problems.append("Recorded discovery content digest differs from the local report.")
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
                or not UNOBSERVED_SURFACES.issubset(claim.unobserved_surfaces)
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


def _carries_discovery(bom: AIBOM) -> bool:
    claim = bom.metadata.completeness
    if claim is not None and (
        claim.source_report_digest is not None
        or claim.source_report_format is not None
        or claim.scope in {"repository+shadowscan", "shadowscan-imported"}
    ):
        return True
    return any(
        component.bom_ref.startswith("shadowscan:")
        or component.properties.get("collection_mode") == "imported-unverified-report"
        or any(key.startswith("shadowscan:") for key in component.properties)
        or "discovery_report_entry" in component.claims
        for component in bom.components
    )


def discovery_signature_required(
    required_by_policy: bool, root: Path, signature_policies: Sequence[SigstoreArtifactPolicy]
) -> bool:
    """An operator signature policy that names a discovery report also requires its signer."""
    from nexus_symbiote.scanners.shadowscan import REPORT_PATHS

    return required_by_policy or _report_policy(root, signature_policies, REPORT_PATHS) is not None


def _report_policy(
    root: Path, signature_policies: Sequence[SigstoreArtifactPolicy], reports: Sequence[str]
) -> SigstoreArtifactPolicy | None:
    """Return the operator entry that names one of ``reports``, by path or else by file.

    Matching by device and inode covers another name for the same file, such as a
    different case on a case-insensitive filesystem; a path comparison alone would
    leave that entry's signer unchecked. Identities are read beneath the pinned
    root without following symlinks.
    """
    paths = {(root / path).resolve() for path in reports}
    named = next((p for p in signature_policies if p.artifact_path.resolve() in paths), None)
    if named is not None or not signature_policies:
        return named
    with ConfinedCollection(root, []) as files:
        identities = {files.path_identity(path) for path in reports} - {None}
        return next(
            (p for p in signature_policies if files.path_identity(p.artifact_path) in identities),
            None,
        )


DiscoveryProducerStatus = Literal["verified", "failed", "not-applicable"]


def discovery_producer_check(
    bom: AIBOM,
    root: Path,
    signature_policies: Sequence[SigstoreArtifactPolicy],
    *,
    exclude_paths: Sequence[str | Path] = (),
) -> tuple[DiscoveryProducerStatus, list[str]]:
    """Require an operator-selected Sigstore signer for the exact report the BOM records.

    The BOM is never trusted for this: the report is re-read beneath ``root`` with
    the importer's confined reader, its digest must equal the recorded one, and the
    operator policy entry for that report path must verify over those bytes. An
    inventory without discovery evidence is checked against the project as well: a
    report beneath the root, or one the operator policy names, must not be omitted.
    """
    from nexus_symbiote.scanners.shadowscan import REPORT_PATHS, ShadowScanImporter
    from nexus_symbiote.utils.crypto import SIGSTORE_MISSING, verify_sigstore_bundle

    importer = ShadowScanImporter()
    importer.configure(exclude_paths=exclude_paths)
    if not _carries_discovery(bom):
        if _report_policy(root, signature_policies, REPORT_PATHS) is not None:
            return "failed", [
                "The inventory omits the ShadowScan report that the operator signature policy names."
            ]
        local = importer.scan(root)
        if local.source_report_digest is not None:
            return "failed", [
                "The inventory omits the ShadowScan report present beneath the project root."
            ]
        if local.scan_failures or local.surfaces_excluded:
            return "failed", [
                "ShadowScan report locations could not be read completely; an omitted report "
                "cannot be ruled out."
            ]
        return "not-applicable", []
    claim = bom.metadata.completeness
    recorded = claim.source_report_digest if claim is not None else None
    if recorded is None:
        return "failed", ["ShadowScan evidence has no recorded report digest to authenticate."]
    local = importer.scan(root)
    if local.source_report_path is None or local.source_report_digest is None:
        return "failed", ["No readable ShadowScan report beneath the project root to authenticate."]
    if not hmac.compare_digest(local.source_report_digest, recorded):
        return "failed", ["Local discovery report differs from the recorded digest."]
    problems = []
    if CompletenessValidator._discovery_mismatches(bom, local):
        problems.append("ShadowScan evidence differs from the projection of the signed report.")
    policy = _report_policy(root, signature_policies, [local.source_report_path])
    if policy is None:
        problems.append(
            "No operator signature policy entry names the ShadowScan report "
            f"{local.source_report_path}; its producer is unverified."
        )
        return "failed", problems
    if policy.allow_oms_dsse:
        problems.append(
            "ShadowScan report requires a sigstore-message-signature entry, not OpenSSF Model Signing DSSE."
        )
        return "failed", problems
    if policy.expected_sha256 is not None and not hmac.compare_digest(
        policy.expected_sha256, recorded
    ):
        problems.append("ShadowScan report differs from the operator's expected_sha256 pin.")
    if policy.rekor_root_hash is not None or policy.minimum_rekor_tree_size is not None:
        verified = verify_sigstore_bundle(
            policy.artifact_path,
            policy.bundle_path,
            policy.expected_identity,
            policy.expected_issuer,
            rekor_root_hash=policy.rekor_root_hash,
            minimum_rekor_tree_size=policy.minimum_rekor_tree_size,
        )
    else:
        verified = verify_sigstore_bundle(
            policy.artifact_path,
            policy.bundle_path,
            policy.expected_identity,
            policy.expected_issuer,
        )
    if verified.error == SIGSTORE_MISSING:
        problems.append(SIGSTORE_MISSING)
    elif not (
        verified.verified
        and verified.identity == policy.expected_identity
        and verified.issuer == policy.expected_issuer
        and verified.details
        and hmac.compare_digest(str(verified.details.get("artifact_digest", "")), recorded)
    ):
        problems.append("ShadowScan report signature or signer policy verification failed.")
    return ("failed" if problems else "verified"), problems


def discovery_producer_problems(
    bom: AIBOM,
    root: Path,
    signature_policies: Sequence[SigstoreArtifactPolicy],
    *,
    exclude_paths: Sequence[str | Path] = (),
) -> list[str]:
    """The reasons ``discovery_producer_check`` fails; empty when verified or not applicable."""
    return discovery_producer_check(bom, root, signature_policies, exclude_paths=exclude_paths)[1]


def carries_discovery_evidence(bom: AIBOM) -> bool:
    return _carries_discovery(bom)


def _observed_composition(component: AnyComponent) -> bool:
    """A named collector measured this component, or observed it in the repository."""
    observed = {AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED}
    return component.assurance_level in observed or any(
        claim.assurance in observed and claim.collector for claim in component.claims.values()
    )


def assurance_problems(
    bom: AIBOM, minimum: str, *, imported_claims: frozenset[str] = frozenset()
) -> list[str]:
    """Apply ``validate.minimum_assurance_level`` to the inventory's components.

    ``observed`` requires observed composition: every component's identity was measured
    from bytes (component ``assurance_level`` observed) or a named collector observed it
    in the repository (an observed claim naming its collector), and every component
    carries claim provenance. Components that rest only on a supplier's or discovery
    report's declaration, such as hosted model aliases, fail. Imported discovery claims
    that reconciliation bound to the local report are judged as imported claims.
    """
    if minimum == "declared":
        return []
    if minimum == "verified":
        return [
            "offline validate cannot establish verified assurance; use subject-bound "
            "cryptographic verification"
        ]
    subjects = [
        c
        for c in bom.components
        if not (
            c.properties.get("collection_mode") == IMPORTED_MODE and c.bom_ref in imported_claims
        )
    ]
    declared = sum(not _observed_composition(c) for c in subjects)
    if not bom.metadata.completeness or not subjects or declared:
        noun = "component" if declared == 1 else "components"
        return [f"minimum observed assurance not attained ({declared} declared {noun})"]
    if any(not c.claims for c in subjects):
        return ["observed assurance requires claim provenance"]
    return []
