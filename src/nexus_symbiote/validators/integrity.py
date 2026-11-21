"""Integrity checks with explicit pass, fail and unavailable-evidence outcomes."""

from __future__ import annotations

import hashlib
import hmac
import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import is_imported
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    canonical_json,
    descriptor_binding,
    hash_tool_definition,
    normalize_digest,
    open_regular_file,
    pathname_identity,
    tool_definition_extensions,
)
from nexus_symbiote.core.identifiers import neutralize_identifiers
from nexus_symbiote.core.models import (
    AnyComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV, MCPScanner
from nexus_symbiote.scanners.model import (
    ModelPackages,
    memoized,
    model_format,
    unused_policy_entries,
    verify_weight_files,
)
from nexus_symbiote.scanners.prompt import IMPORT_CONTENT_BINDING_PROFILE, withholds_content_hash
from nexus_symbiote.scanners.source_binding import BindingError, value_binding
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.crypto import (
    MAX_BUNDLE_BYTES,
    ArtifactPolicy,
    SigstoreArtifactPolicy,
    policy_entries,
    verify_sigstore_bundle,
)

VALIDATION_PASSES = 6
"""How many times a scan's model reads one validation may read from artifacts.

A maximal scan inventory (the model collector reads at most the operator's
``model-total-bytes`` of weights) needs at most four passes over its models; the rest
is headroom. So a supplied BOM cannot multiply the work of the scan behind it.
"""
VALIDATION_BYTE_BUDGET = VALIDATION_PASSES * limits.DEFAULTS.model_total_bytes
"""The validation budget under the default limits; a validator uses the limits in force."""
SIGNATURE_VERIFICATION_COST = MAX_BUNDLE_BYTES
"""Work charged for one offline signature verification beyond the bytes it reads.

Loading the trust root and checking the certificate chain is charged like reading
this many bytes, so verification work draws on the same budget as artifact reads.
"""
MAX_REPORTED_ISSUES = 1000
_IMPORTED_EVIDENCE_GAPS = frozenset(
    {
        "artifact_unavailable",
        "missing_hash",
        "missing_definition",
        "unverified_signature",
        "unsigned_model",
        "descriptor_source_unavailable",
    }
)
"""Unknown-evidence categories that a bound imported claim reports without blocking."""
_BLOCKING = {"critical", "error"}
_SEVERITY_RANK = {"critical": 0, "error": 0, "unknown": 1, "warning": 2, "info": 3}
# These critical findings describe model use independently of a verified byte identity.
_MODEL_BEHAVIOR_RISKS = {
    "unsafe_format": "serialization_format",
    "trust_remote_code": "code_execution",
}


@dataclass
class IntegrityIssue:
    component_ref: str
    category: str
    detail: str
    severity: str = "error"


@dataclass(frozen=True)
class ModelPolicyEvidence:
    weight_files: int
    signatures_verified: int
    digest_pins_verified: int


@dataclass
class IntegrityReport:
    components_checked: int = 0
    hashes_verified: int = 0
    hashes_failed: int = 0
    hashes_unbound: int = 0
    signatures_checked: int = 0
    signatures_verified: int = 0
    issues: list[IntegrityIssue] = field(default_factory=list)
    basis: Literal["supplied-bom", "project"] = "supplied-bom"
    bytes_charged: int = 0
    issues_omitted: int = 0
    omitted_severities: set[str] = field(default_factory=set)
    model_policy_evidence: dict[str, ModelPolicyEvidence] = field(default_factory=dict)
    # Integrity category to inventory risk category, retained before display truncation.
    model_behavior_risks: dict[str, dict[str, str]] = field(default_factory=dict)

    @property
    def status(self) -> Literal["pass", "fail", "unknown"]:
        severities = {i.severity for i in self.issues} | self.omitted_severities
        if severities & _BLOCKING:
            return "fail"
        if "unknown" in severities:
            return "unknown"
        if self.hashes_verified + self.signatures_verified == 0:
            return "unknown"
        return "pass"

    @property
    def is_valid(self) -> bool:
        """Compatibility gate: unknown evidence never produces a passing verdict."""
        return self.status == "pass"

    def bound_issues(self) -> None:
        """Keep at most ``MAX_REPORTED_ISSUES`` issues, blocking ones first; the verdict keeps all."""
        if len(self.issues) <= MAX_REPORTED_ISSUES:
            return
        ranked = sorted(self.issues, key=lambda issue: _SEVERITY_RANK.get(issue.severity, 0))
        omitted = ranked[MAX_REPORTED_ISSUES:]
        self.issues_omitted += len(omitted)
        self.omitted_severities |= {issue.severity for issue in omitted}
        self.issues = ranked[:MAX_REPORTED_ISSUES]

    def to_dict(self) -> dict[str, object]:
        return {
            "is_valid": self.is_valid,
            "status": self.status,
            "assessment_basis": self.basis,
            "components_checked": self.components_checked,
            "hashes_verified": self.hashes_verified,
            "hashes_failed": self.hashes_failed,
            "hashes_unbound": self.hashes_unbound,
            "signatures_checked": self.signatures_checked,
            "signatures_verified": self.signatures_verified,
            "bytes_charged": self.bytes_charged,
            "issues": [
                {
                    "component_ref": i.component_ref,
                    "category": i.category,
                    "detail": i.detail,
                    "severity": i.severity,
                }
                for i in self.issues
            ],
            "issues_omitted": self.issues_omitted,
        }


class _BudgetExhaustedError(Exception):
    pass


class _ArtifactDigests:
    """Hash each artifact at most once per algorithm within one validation.

    Entries are keyed by the open descriptor's identity, so a file changed between two
    reads is hashed again. Bytes read are charged to one validation-wide budget.
    """

    def __init__(self, budget: int) -> None:
        self.remaining = budget
        self._digests: dict[tuple[tuple[int, ...], str], str | None] = {}

    def charge(self, size: int) -> None:
        if size > self.remaining:
            raise _BudgetExhaustedError
        self.remaining -= size

    def digest(self, path: Path, algorithm: str) -> str | None:
        """Return ``algorithm:hex`` of ``path``, or None when it cannot be read safely."""
        try:
            with open_regular_file(path) as stream:
                before = os.fstat(stream.fileno())
                key = (descriptor_binding(before), algorithm)
                if key in self._digests:
                    return self._digests[key]
                if before.st_size > limits.current().model_bytes:
                    self._digests[key] = None
                    return None
                self.charge(before.st_size)
                digest = hashlib.new(algorithm)
                total = 0
                while chunk := stream.read(1024 * 1024):
                    total += len(chunk)
                    if total > before.st_size:
                        return None
                    digest.update(chunk)
                after = os.fstat(stream.fileno())
                if descriptor_binding(before) != descriptor_binding(after) or pathname_identity(
                    path
                ) != (after.st_dev, after.st_ino):
                    return None
        except (OSError, ValueError):
            return None
        value = f"{algorithm}:{digest.hexdigest()}"
        self._digests[key] = value
        return value

    def read(self, path: Path) -> bytes | None:
        """Return the bytes of ``path``, at most the ``file-bytes`` limit that bounded its
        collection, or None when it cannot be read safely."""
        try:
            with open_regular_file(path) as stream:
                before = os.fstat(stream.fileno())
                if before.st_size > limits.current().file_bytes:
                    return None
                self.charge(before.st_size)
                content = stream.read(before.st_size + 1)
                after = os.fstat(stream.fileno())
                if (
                    len(content) != before.st_size
                    or descriptor_binding(before) != descriptor_binding(after)
                    or pathname_identity(path) != (after.st_dev, after.st_ino)
                ):
                    return None
        except (OSError, ValueError):
            return None
        return content


def _locate_artifact(project_root: Path, source_path: str) -> Path | str:
    """Return the in-root artifact a component names, or the fixed reason it is refused.

    Every reader applies these rules: no parent traversal, inside the resolved root,
    not a symbolic link, and a regular file. Collectors read through one in-root
    symlink at any component, such as CLAUDE.md -> AGENTS.md or .claude ->
    config/claude, resolved lexically without following anything, so the artifact is
    that target; the rules then apply to it. Reasons never quote the path.
    """
    root = project_root.resolve()
    candidate = Path(source_path)
    if ".." in candidate.parts:
        return "Parent traversal is not permitted"
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        if candidate.is_relative_to(root):
            with ConfinedCollection(root, []) as files:
                target = files.in_root_target(candidate.relative_to(root))
            candidate = candidate if target is None else root / target
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
            return "Artifact path escapes the supplied project root or is a symlink"
        if not candidate.is_file():
            return "Declared artifact is missing or is not a regular file"
    except (OSError, RuntimeError, ValueError):
        return "Declared artifact could not be examined"
    return candidate


def _regular_file_size(path: Path) -> int:
    """Size of the regular file a no-follow open reaches; zero when there is none."""
    try:
        with open_regular_file(path) as stream:
            return os.fstat(stream.fileno()).st_size
    except (OSError, ValueError):
        return 0


class IntegrityValidator:
    """Check manifest consistency and scoped artifacts, not runtime admission.

    Signature policies must come from the trusted caller. BOM signing_status and
    signing_identity fields, and adjacent signature filenames, are never trusted
    as verification evidence. Model signatures are required by default. A digest
    that agrees only with other fields of the same BOM is self-consistency, not
    verification: it is reported as unknown evidence and never counted as verified.
    """

    def __init__(
        self,
        signature_policies: Sequence[SigstoreArtifactPolicy] = (),
        *,
        require_model_signatures: bool = True,
        byte_budget: int | None = None,
    ) -> None:
        # Digest pins arrive with the Sigstore entries of a loaded policy set.
        self._sigstore_policies: list[SigstoreArtifactPolicy] = [
            p for p in signature_policies if isinstance(p, SigstoreArtifactPolicy)
        ]
        self._signature_policies: dict[Path, ArtifactPolicy] = {
            p.artifact_path.resolve(): p for p in policy_entries(signature_policies)
        }
        self._packages: tuple[IntegrityReport, ModelPackages] | None = None
        self.require_model_signatures = require_model_signatures
        self.byte_budget = (
            VALIDATION_PASSES * limits.current().model_total_bytes
            if byte_budget is None
            else byte_budget
        )
        self._digests = _ArtifactDigests(self.byte_budget)
        self._inspected_models: set[Path] = set()
        self._unchecked_model_directories: set[Path] = set()

    def validate(
        self,
        bom: AIBOM,
        project_root: Path | None = None,
        *,
        exclude_paths: Sequence[str] = (),
        bound_imports: frozenset[str] = frozenset(),
    ) -> IntegrityReport:
        """Check every component; ``bound_imports`` names imported discovery claims.

        Only references that project reconciliation bound to the local discovery report
        may be passed as ``bound_imports``. Those are judged as imported claims: their
        unavailable local evidence is reported without blocking, while intrinsic findings
        such as an unsafe loading format still fail.
        """
        report = IntegrityReport(basis="supplied-bom" if project_root is None else "project")
        self._digests = _ArtifactDigests(self.byte_budget)
        self._inspected_models = set()
        self._unchecked_model_directories = set()
        local_tools: dict[str, ToolComponent | None] = {}
        if project_root is not None and any(isinstance(c, ToolComponent) for c in bom.components):
            # Resolve configuration only inside the operator's root. Never use a BOM-supplied
            # descriptor path or launch a server to corroborate omitted instance values.
            scanner = MCPScanner()
            scanner.configure(exclude_paths)
            for local in scanner.scan(project_root, config_only=True).components:
                if isinstance(local, ToolComponent):
                    # Collected tools are recorded with neutralized names, and the
                    # displayed digest bound to that name; compare like with like.
                    neutralize_identifiers(local)
                    local_tools[local.bom_ref] = None if local.bom_ref in local_tools else local
        for comp in bom.components:
            report.components_checked += 1
            first_issue = len(report.issues)
            if isinstance(comp, ModelComponent) and not self._admit_model(
                comp, project_root, report
            ):
                continue
            if isinstance(comp, ToolComponent):
                self._check_tool_hash(comp, report, local_tools)
            elif isinstance(comp, ModelComponent):
                self._check_model_integrity(comp, project_root, report)
                self._check_tensor_metadata(comp, project_root, report)
            elif isinstance(comp, PromptComponent):
                self._check_prompt_hash(comp, project_root, report)
            elif isinstance(comp, MCPServerComponent) and comp.version_pinned is False:
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "unpinned_version",
                        "MCP package version is not pinned",
                        "warning",
                    )
                )
            if isinstance(comp, MCPServerComponent) and comp.endpoint_url:
                try:
                    if comp.schema_hash is None:
                        raise ValueError("descriptor digest is unavailable")
                    normalize_digest(comp.schema_hash, "sha256")
                except ValueError:
                    report.issues.append(
                        IntegrityIssue(
                            comp.bom_ref,
                            "unpinned_remote_server",
                            "Remote MCP descriptor digest is unavailable or malformed; endpoint identity and behavior remain unverified",
                            "warning",
                        )
                    )
            self._check_file_hash(comp, project_root, report)
            # Matching artifact bytes and safe model behavior are separate facts.
            component_issues = report.issues[first_issue:]
            behavior = {
                issue.category: _MODEL_BEHAVIOR_RISKS[issue.category]
                for issue in component_issues
                if issue.category in _MODEL_BEHAVIOR_RISKS
            }
            if behavior:
                report.model_behavior_risks[comp.bom_ref] = behavior
            if any(issue.category not in _MODEL_BEHAVIOR_RISKS for issue in component_issues):
                report.model_policy_evidence.pop(comp.bom_ref, None)
            if comp.bom_ref in bound_imports and is_imported(comp):
                for issue in report.issues[first_issue:]:
                    if issue.severity == "unknown" and issue.category in _IMPORTED_EVIDENCE_GAPS:
                        issue.severity = "info"
                        issue.detail = "Imported discovery claim without local evidence: " + (
                            issue.detail
                        )
        if project_root is not None:
            from nexus_symbiote.validators.completeness import (
                discovery_producer_check,
                discovery_signature_required,
            )

            if discovery_signature_required(False, project_root, self._sigstore_policies):
                disc_status, disc_problems = discovery_producer_check(
                    bom,
                    project_root,
                    self._sigstore_policies,
                    exclude_paths=exclude_paths,
                )
                if disc_status == "verified":
                    report.signatures_checked += 1
                    report.signatures_verified += 1
                elif disc_status == "failed":
                    report.signatures_checked += 1
                    for problem in disc_problems:
                        report.issues.append(
                            IntegrityIssue(
                                "discovery-report",
                                "discovery_signature_failed",
                                problem,
                                "error",
                            )
                        )
        self._report_unused_policies(project_root, report)
        report.bytes_charged = self.byte_budget - self._digests.remaining
        if report.hashes_verified + report.signatures_verified == 0 and not any(
            i.severity in {"critical", "error", "unknown"} for i in report.issues
        ):
            report.issues.append(
                IntegrityIssue(
                    "inventory",
                    "nothing_verified",
                    "No artifact hash or signature could be verified against local evidence",
                    "unknown",
                )
            )
        report.bound_issues()
        return report

    def _admit_model(
        self, comp: ModelComponent, project_root: Path | None, report: IntegrityReport
    ) -> bool:
        """Charge a model's artifact work to the validation budget before it happens.

        The model check observes the artifact once (inspection, digest and tensor
        metadata come from that one read); a Sigstore entry reads it once more,
        reads its bundle and costs a fixed amount of work, while a digest pin is
        compared with the observed digest. The weight files a model binds are read
        within the model check's own scan-sized budget. A weights file, or a file the
        signer policy covers, is inspected for one component only: a later model
        component naming it fails instead of repeating the work. Other files, such as
        the manifest that declares hosted models, are charged for each component. A
        component the budget cannot cover is unknown, not skipped silently. A path the
        readers refuse costs nothing here; the checks report why.
        """
        if project_root is None or not comp.source_path:
            return True
        located = _locate_artifact(project_root, comp.source_path)
        if isinstance(located, str):
            return True
        try:
            artifact = located.resolve()
        except (OSError, RuntimeError, ValueError):
            return True
        policy = self._signature_policies.get(artifact)
        once = policy is not None or model_format(artifact) is not None
        if once and artifact in self._inspected_models:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "duplicate_artifact",
                    "An earlier model component already names this artifact; an inventory "
                    "describes each model artifact once",
                )
            )
            return False
        size = _regular_file_size(located)
        cost = size
        if isinstance(policy, SigstoreArtifactPolicy):
            bundle = min(_regular_file_size(policy.bundle_path), MAX_BUNDLE_BYTES + 1)
            cost += size + bundle + SIGNATURE_VERIFICATION_COST
        try:
            self._digests.charge(cost)
        except _BudgetExhaustedError:
            report.issues.append(_budget_issue(comp.bom_ref, self.byte_budget))
            # The model is unchecked, not unused: no entry for it or for a weight file
            # it may bind is reported as naming nothing.
            self._unchecked_model_directories.add(artifact.parent)
            return False
        if once:
            self._inspected_models.add(artifact)
        return True

    def _check_tensor_metadata(
        self, comp: ModelComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        declared = {
            "tensor_inventory_sha256": comp.tensor_inventory_hash,
            "safetensors_header_sha256": comp.safetensors_header_hash,
        }
        declared = {key: value for key, value in declared.items() if value is not None}
        if not declared:
            return
        try:
            if project_root is None or comp.source_path is None:
                raise ValueError("project root and artifact path are required")
            expected_weight = comp.hashes.get("sha256")
            if not expected_weight:
                raise ValueError("tensor metadata requires a whole-artifact SHA-256 binding")
            algorithm, hex_digest = normalize_digest(expected_weight, "sha256")
            root = project_root.resolve()
            source = Path(comp.source_path)
            # The integrity check's observation of the same file; the artifact is
            # read once per validation.
            observation = self._model_packages(report, root).observation(
                source.relative_to(root) if source.is_absolute() else source
            )
            if (
                observation is None
                or observation.safety != SerializationSafety.SAFE
                or not observation.fingerprint
            ):
                raise ValueError("SafeTensors metadata could not be corroborated")
            if observation.digest != f"{algorithm}:{hex_digest}":
                raise ValueError("Tensor metadata belongs to different artifact bytes")
            live = observation.fingerprint
            for key, expected in declared.items():
                assert expected is not None
                normalize_digest(expected, "sha256")
                if live[key] != expected:
                    raise ValueError("tensor metadata differs from the declared fingerprint")
                report.hashes_verified += 1
        except (OSError, ValueError, RecursionError):
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "tensor_metadata_unverified",
                    "Declared tensor metadata cannot be corroborated within the supplied root",
                )
            )

    def _check_tool_hash(
        self,
        comp: ToolComponent,
        report: IntegrityReport,
        local_tools: dict[str, ToolComponent | None],
    ) -> None:
        if not comp.definition_hash:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "missing_hash", "Tool definition digest is unavailable", "unknown"
                )
            )
            return
        if comp.definition_hash_version != TOOL_DEFINITION_HASH_VERSION:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "fingerprint_version_unknown",
                    "Tool fingerprint protocol is unknown or legacy; re-collect and re-approve",
                )
            )
            return
        if comp.description_text is None:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "missing_definition",
                    "Model-visible tool description is unavailable",
                    "unknown",
                )
            )
            return
        try:
            algorithm, expected = normalize_digest(comp.definition_hash, "sha256")
            # Both property spellings are supported. Never let a preferred alias
            # hide another displayed value, including a value behind explicit null.
            for primary, alias in (
                ("mcp_title", "title"),
                ("mcp_output_schema", "output_schema"),
                ("mcp_meta", "meta"),
            ):
                if primary in comp.properties and alias in comp.properties:
                    if canonical_json({"value": comp.properties[primary]}) != canonical_json(
                        {"value": comp.properties[alias]}
                    ):
                        raise ValueError("Conflicting tool descriptor extension aliases")
            extensions = tool_definition_extensions(
                {
                    "title": comp.properties.get("mcp_title", comp.properties.get("title")),
                    "outputSchema": comp.properties.get(
                        "mcp_output_schema", comp.properties.get("output_schema")
                    ),
                    "_meta": comp.properties.get("mcp_meta", comp.properties.get("meta")),
                }
            )
            recomputed = hash_tool_definition(
                comp.name,
                comp.description_text,
                comp.input_schema,
                comp.annotations,
                **extensions,
            )
            # Every displayed extension must be bound by the matching digest.
            # Historical observation inventories may have an extension-free
            # redacted hash, but their full descriptor must still match the
            # original hash. Omitting extensions here would let changed metadata
            # pass by matching only the unchanged base fields.
            raw_hash = f"{algorithm}:{expected}"
            accepted = {raw_hash}
            if comp.redacted_definition_hash is not None:
                accepted.add(comp.redacted_definition_hash)
            if recomputed not in accepted:
                raise ValueError("Tool definition differs from its declared digest")
            if comp.bom_ref in local_tools:
                local = local_tools[comp.bom_ref]
                if (
                    local is None
                    or comp.mcp_server_ref != local.mcp_server_ref
                    or raw_hash != local.definition_hash
                    or comp.redacted_definition_hash != local.redacted_definition_hash
                ):
                    raise ValueError("Tool fingerprint differs from its local configuration")
            elif comp.redacted_definition_hash is not None:
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "descriptor_source_unavailable",
                        "Redacted representation matches; original descriptor requires matching source evidence",
                        "unknown",
                    )
                )
                return
            else:
                # The descriptor and its digest both come from the document under review.
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "descriptor_source_unavailable",
                        "Tool descriptor matches only its own recorded digest; no local "
                        "configuration corroborates it",
                        "unknown",
                    )
                )
                return
        except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
            report.hashes_failed += 1
            report.issues.append(IntegrityIssue(comp.bom_ref, "hash_mismatch", str(exc)))
        else:
            report.hashes_verified += 1

    def _artifact_path(
        self, comp: AnyComponent, project_root: Path | None, report: IntegrityReport
    ) -> Path | None:
        if project_root is None or not comp.source_path:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "artifact_unavailable",
                    "A project root and artifact path are required",
                    "unknown",
                )
            )
            return None
        located = _locate_artifact(project_root, comp.source_path)
        if isinstance(located, str):
            report.issues.append(IntegrityIssue(comp.bom_ref, "missing_artifact", located))
            return None
        return located

    def _check_model_integrity(
        self, comp: ModelComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        if comp.serialization_safety in {
            SerializationSafety.UNSAFE_CODE_EXECUTION,
            SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
        }:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "unsafe_format",
                    "Declared model loading format permits unsafe behavior",
                    "critical",
                )
            )
        if comp.trust_remote_code:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "trust_remote_code",
                    "Model loading permits repository code execution",
                    "critical",
                )
            )
        path = self._artifact_path(comp, project_root, report)
        if path is None or project_root is None:
            self._unsigned_model(comp, report)
            return
        root = project_root.resolve()
        packages = self._model_packages(report, root)
        try:
            relative = path.resolve().relative_to(root)
            # The collector's own confined observation: the same verdict, digest and
            # bound weight files for the same bytes, never the BOM's account of them.
            package = packages.observe(relative)
        except (OSError, ValueError):
            package = None
        observation = package.observation if package is not None else None
        if observation is None:
            actual, explanation = (
                SerializationSafety.UNKNOWN,
                "Model structure could not be bound to its SHA-256 subject",
            )
        else:
            actual, explanation = observation.safety, observation.explanation
            recorded = comp.hashes.get("sha256")
            if recorded is None:
                # No subject to bind: missing evidence, not a contradiction. The observed
                # verdict is still reported below.
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "format_unverified",
                        "Model structure could not be bound to its SHA-256 subject",
                        "unknown",
                    )
                )
            else:
                try:
                    _, expected_digest = normalize_digest(recorded, "sha256")
                    if observation.digest != f"sha256:{expected_digest}":
                        raise ValueError("subject mismatch")
                except ValueError:
                    report.issues.append(
                        IntegrityIssue(
                            comp.bom_ref,
                            "format_subject_mismatch",
                            "Inspected model structure does not match the BOM's SHA-256 subject",
                        )
                    )
        if actual in {
            SerializationSafety.UNSAFE_CODE_EXECUTION,
            SerializationSafety.UNSAFE_TEMPLATE_INJECTION,
        }:
            report.issues.append(
                IntegrityIssue(comp.bom_ref, "unsafe_format", explanation, "critical")
            )
        elif actual == SerializationSafety.UNKNOWN:
            report.issues.append(
                IntegrityIssue(comp.bom_ref, "format_unverified", explanation, "unknown")
            )
        if (
            comp.serialization_safety == SerializationSafety.SAFE
            and actual != SerializationSafety.SAFE
        ):
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "format_claim_mismatch",
                    "Declared safe format was not corroborated",
                )
            )
        if package is None:
            self._unsigned_model(comp, report)
            return
        if package.budget_exhausted:
            self._unchecked_model_directories.add((root / package.weight_files[0][0]).parent)
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "validation_budget_exhausted",
                    "Model files of this inventory exceed the bytes or weight-file bindings "
                    "one validation checks (as many as one scan); this model was not checked "
                    "completely",
                    "unknown",
                )
            )
        if not package.complete:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "weight_files_unverified",
                    "The weight files bound to this model could not all be read beneath the root",
                    "unknown",
                )
            )
        local = sorted((weight.as_posix(), digest) for weight, digest in package.weight_files[1:])
        if self._recorded_weight_files(comp) != local:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "weight_files_mismatch",
                    "Weight files bound to this model differ from the BOM's record",
                )
            )
        verification = verify_weight_files(
            package.weight_files,
            root,
            self._signature_policies,
            verify=memoized(verify_sigstore_bundle, packages.verified),
        )
        if verification.status is None:
            self._unsigned_model(comp, report)
            return
        report.signatures_checked += verification.signatures_checked
        report.signatures_verified += verification.signatures_verified
        report.hashes_verified += verification.pins_verified
        weight_count = len(package.weight_files)
        if verification.signatures_verified + verification.pins_verified == weight_count:
            report.model_policy_evidence[comp.bom_ref] = ModelPolicyEvidence(
                weight_count, verification.signatures_verified, verification.pins_verified
            )
        for category, detail, severity in verification.issues:
            if severity == "unknown" and not self.require_model_signatures:
                severity = "warning"
            report.issues.append(IntegrityIssue(comp.bom_ref, category, detail, severity))

    def _model_packages(self, report: IntegrityReport, root: Path) -> ModelPackages:
        """One observer per validation, so models share walks, digests and one byte budget."""
        current = self._packages
        if current is None or current[0] is not report or current[1].root != root:
            current = self._packages = (report, ModelPackages(root))
        return current[1]

    def _report_unused_policies(self, project_root: Path | None, report: IntegrityReport) -> None:
        """An operator entry that no model of this inventory uses must not look enforced.

        The model collector reports the same entries when validation recollects the
        project; this states them even when the completeness check does not run. The
        weight files a model binds never leave its directory, so an entry beneath the
        directory of a model the budget left unchecked is unknown, not unused: that
        model's own issue already keeps the verdict from passing.
        """
        if not self._signature_policies or project_root is None:
            return
        root = project_root.resolve()
        covered = self._model_packages(report, root).covered
        unchecked = self._unchecked_model_directories
        policies = {
            key: policy
            for key, policy in self._signature_policies.items()
            if unchecked.isdisjoint(key.parents)
        }
        with ConfinedCollection(root, []) as files:
            unused = unused_policy_entries(files, policies, covered)
        for label, reason in unused:
            report.issues.append(
                IntegrityIssue("signature-policy", "unused_policy_entry", f"{label}: {reason}")
            )

    @staticmethod
    def _recorded_weight_files(comp: ModelComponent) -> list[tuple[str, str | None]] | None:
        recorded = comp.properties.get("weight_files", [])
        if not isinstance(recorded, list):
            return None
        entries: list[tuple[str, str | None]] = []
        for item in recorded:
            if not isinstance(item, dict) or not isinstance(item.get("path"), str):
                return None
            digest = item.get("sha256")
            entries.append((item["path"], digest if isinstance(digest, str) else None))
        return sorted(entries)

    def _unsigned_model(self, comp: ModelComponent, report: IntegrityReport) -> None:
        category = (
            "unsigned_model"
            if comp.signing_status in {"unsigned", "signature-not-found"}
            else "unverified_signature"
        )
        report.issues.append(
            IntegrityIssue(
                comp.bom_ref,
                category,
                "No trusted artifact-bound signer policy was supplied",
                "unknown" if self.require_model_signatures else "warning",
            )
        )

    def _check_prompt_hash(
        self, comp: PromptComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        if not comp.content_hash:
            if withholds_content_hash(comp):
                self._check_import_binding(comp, project_root, report)
                return
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "missing_hash", "Prompt content digest is unavailable", "unknown"
                )
            )
            return
        path = self._artifact_path(comp, project_root, report)
        if path is None:
            report.hashes_failed += 1
            return
        self._verify_digest(comp, path, comp.content_hash, None, report, "hash_mismatch")

    def _check_import_binding(
        self, comp: PromptComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        """Verify the keyed binding of a prompt file whose unkeyed content hash is withheld.

        The collector withholds the hash of a recorded file whose bytes are not those of
        an instruction file, such as a non-Markdown import, rule file or symlink target,
        so its absence is not missing evidence. With the operator key the HMAC is
        recomputed from the file; without the key, or for an inventory collected
        without it, nothing binds the content and the component is counted as unbound.
        A binding under another profile or key cannot be checked and is unknown.
        """
        recorded = comp.properties.get("static_value_binding")
        if not os.environ.get(SOURCE_BINDING_KEY_ENV) or recorded is None:
            report.hashes_unbound += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "unbound_content",
                    "Prompt file carries no unkeyed content digest by design; collect and "
                    f"validate with {SOURCE_BINDING_KEY_ENV} to verify its keyed binding",
                    "info",
                )
            )
            return
        if comp.properties.get("static_value_binding_profile") != IMPORT_CONTENT_BINDING_PROFILE:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "binding_profile_unknown",
                    "Prompt file content binding has an unknown profile; re-collect it",
                    "unknown",
                )
            )
            return
        path = self._artifact_path(comp, project_root, report)
        if path is None:
            report.hashes_failed += 1
            return
        try:
            content = self._digests.read(path)
        except _BudgetExhaustedError:
            report.issues.append(_budget_issue(comp.bom_ref, self.byte_budget))
            return
        if content is None:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "hash_mismatch", "Failed to read a regular artifact file"
                )
            )
            return
        try:
            binding = value_binding(
                IMPORT_CONTENT_BINDING_PROFILE,
                {"path": comp.source_path, "content": content.decode("utf-8")},
            )
        except BindingError as exc:
            report.issues.append(
                IntegrityIssue(comp.bom_ref, "binding_unavailable", str(exc), "unknown")
            )
            return
        except UnicodeDecodeError:
            # Only UTF-8 text is collected and bound, so this file is no longer what was.
            binding = {}
        if binding and binding["static_value_binding_key_id"] != comp.properties.get(
            "static_value_binding_key_id"
        ):
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "binding_key_unknown",
                    "Prompt file content was bound under another key; validate with the "
                    "key it was collected with",
                    "unknown",
                )
            )
            return
        if (
            binding
            and isinstance(recorded, str)
            and hmac.compare_digest(
                binding["static_value_binding"].encode(),
                recorded.encode("utf-8", "surrogatepass"),
            )
        ):
            report.hashes_verified += 1
            return
        report.hashes_failed += 1
        report.issues.append(
            IntegrityIssue(
                comp.bom_ref,
                "hash_mismatch",
                "Keyed content binding mismatch against the prompt file",
            )
        )

    def _verify_digest(
        self,
        comp: AnyComponent,
        path: Path,
        expected: str,
        algorithm: str | None,
        report: IntegrityReport,
        category: str,
    ) -> None:
        try:
            algorithm, digest = normalize_digest(expected, algorithm)
        except ValueError as exc:
            report.hashes_failed += 1
            report.issues.append(IntegrityIssue(comp.bom_ref, category, str(exc)))
            return
        try:
            actual = self._digests.digest(path, algorithm)
        except _BudgetExhaustedError:
            report.issues.append(_budget_issue(comp.bom_ref, self.byte_budget))
            return
        if actual is None:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(comp.bom_ref, category, "Failed to read a regular artifact file")
            )
        elif actual == f"{algorithm}:{digest}":
            report.hashes_verified += 1
        else:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, category, "Hash mismatch against the expected artifact digest"
                )
            )

    def _check_file_hash(
        self, comp: AnyComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        if not comp.hashes:
            if isinstance(comp, ModelComponent):
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "missing_hash",
                        "Model artifact digest is unavailable",
                        "unknown",
                    )
                )
            return
        # Reject malformed declarations even when the artifact cannot be opened. Keys
        # differing only in case name one algorithm and must not buy another full read.
        valid: dict[str, str] = {}
        for algorithm, expected in comp.hashes.items():
            folded = algorithm.lower()
            try:
                if folded in valid:
                    raise ValueError("Digest algorithm is declared more than once")
                normalize_digest(expected, folded)
                valid[folded] = expected
            except ValueError as exc:
                report.hashes_failed += 1
                report.issues.append(IntegrityIssue(comp.bom_ref, "file_hash_mismatch", str(exc)))
        if not valid:
            return
        path = self._artifact_path(comp, project_root, report)
        if path is None:
            report.hashes_failed += len(valid)
            return
        for algorithm, expected in valid.items():
            self._verify_digest(comp, path, expected, algorithm, report, "file_hash_mismatch")


def _budget_issue(component_ref: str, budget: int) -> IntegrityIssue:
    return IntegrityIssue(
        component_ref,
        "validation_budget_exhausted",
        f"Not checked: the work would exceed this validation's artifact budget of {budget:,} bytes",
        "unknown",
    )
