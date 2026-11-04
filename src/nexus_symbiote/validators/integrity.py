"""Integrity checks with explicit pass, fail and unavailable-evidence outcomes."""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import SerializationSafety
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_tool_definition,
    normalize_digest,
    open_regular_file,
    pathname_identity,
)
from nexus_symbiote.core.models import (
    AnyComponent,
    MCPServerComponent,
    ModelComponent,
    PromptComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.model import inspect_model_artifact
from nexus_symbiote.signature_policy import unmatched_policy_entries
from nexus_symbiote.utils.crypto import (
    SigstoreArtifactPolicy,
    verify_file_hash,
    verify_sigstore_bundle,
)


@dataclass
class IntegrityIssue:
    component_ref: str
    category: str
    detail: str
    severity: str = "error"


@dataclass
class IntegrityReport:
    components_checked: int = 0
    hashes_verified: int = 0
    hashes_failed: int = 0
    signatures_checked: int = 0
    signatures_verified: int = 0
    issues: list[IntegrityIssue] = field(default_factory=list)
    tool_descriptors_self_consistent: int = 0

    @property
    def status(self) -> Literal["pass", "fail", "unknown"]:
        if any(i.severity in {"critical", "error"} for i in self.issues):
            return "fail"
        if any(i.severity == "unknown" for i in self.issues):
            return "unknown"
        if self.hashes_verified + self.signatures_verified == 0:
            return "unknown"
        return "pass"

    @property
    def is_valid(self) -> bool:
        """Compatibility gate: unknown evidence never produces a passing verdict."""
        return self.status == "pass"

    def to_dict(self) -> dict[str, object]:
        return {
            "is_valid": self.is_valid,
            "status": self.status,
            "components_checked": self.components_checked,
            "tool_descriptors_self_consistent": self.tool_descriptors_self_consistent,
            "hashes_verified": self.hashes_verified,
            "hashes_failed": self.hashes_failed,
            "signatures_checked": self.signatures_checked,
            "signatures_verified": self.signatures_verified,
            "issues": [
                {
                    "component_ref": i.component_ref,
                    "category": i.category,
                    "detail": i.detail,
                    "severity": i.severity,
                }
                for i in self.issues
            ],
        }


class IntegrityValidator:
    """Check manifest consistency and scoped artifacts, not runtime admission.

    Signature policies must come from the trusted caller. BOM signing_status and
    signing_identity fields, and adjacent signature filenames, are never trusted
    as verification evidence. Model signatures are required by default.
    """

    def __init__(
        self,
        signature_policies: Sequence[SigstoreArtifactPolicy] = (),
        *,
        require_model_signatures: bool = True,
    ) -> None:
        self._signature_policies = {p.artifact_path.resolve(): p for p in signature_policies}
        if len(self._signature_policies) != len(signature_policies):
            raise ValueError("Duplicate artifact signature policies")
        self.require_model_signatures = require_model_signatures

    def validate(
        self,
        bom: AIBOM,
        project_root: Path | None = None,
        *,
        exclude_paths: Sequence[str] = (),
    ) -> IntegrityReport:
        report = IntegrityReport()
        checked_policies: set[SigstoreArtifactPolicy] = set()
        local_tools: dict[str, ToolComponent | None] = {}
        if project_root is not None and any(isinstance(c, ToolComponent) for c in bom.components):
            # Resolve configuration only inside the operator's root. Never use a BOM-supplied
            # descriptor path or launch a server to corroborate omitted instance values.
            scanner = MCPScanner()
            scanner.configure(exclude_paths)
            for local in scanner.scan(project_root, config_only=True).components:
                if isinstance(local, ToolComponent):
                    local_tools[local.bom_ref] = None if local.bom_ref in local_tools else local
        for comp in bom.components:
            report.components_checked += 1
            if isinstance(comp, ToolComponent):
                self._check_tool_hash(comp, report, local_tools)
            elif isinstance(comp, ModelComponent):
                self._check_model_integrity(comp, project_root, report, checked_policies)
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
        for issue in unmatched_policy_entries(self._signature_policies.values(), checked_policies):
            report.issues.append(
                IntegrityIssue("signature-policy", "unmatched_signature_policy", issue)
            )
        return report

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
        from nexus_symbiote.scanners.model import safetensors_fingerprint

        try:
            if project_root is None or comp.source_path is None:
                raise ValueError("project root and artifact path are required")
            expected_weight = comp.hashes.get("sha256")
            if not expected_weight:
                raise ValueError("tensor metadata requires a whole-artifact SHA-256 binding")
            algorithm, hex_digest = normalize_digest(expected_weight, "sha256")
            live = safetensors_fingerprint(
                Path(comp.source_path),
                root=project_root,
                expected_digest=f"{algorithm}:{hex_digest}",
            )
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
            recomputed = hash_tool_definition(
                comp.name, comp.description_text, comp.input_schema, comp.annotations
            )
            raw_hash = f"{algorithm}:{expected}"
            if recomputed != (comp.redacted_definition_hash or raw_hash):
                raise ValueError("Tool definition differs from its declared digest")
            report.tool_descriptors_self_consistent += 1
            if comp.bom_ref in local_tools:
                local = local_tools[comp.bom_ref]
                if (
                    local is None
                    or comp.mcp_server_ref != local.mcp_server_ref
                    or raw_hash != local.definition_hash
                    or comp.redacted_definition_hash != local.redacted_definition_hash
                ):
                    raise ValueError("Tool fingerprint differs from its local configuration")
            else:
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "descriptor_source_unavailable",
                        "Descriptor is internally consistent but has no matching local configuration evidence",
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
        root = project_root.resolve()
        candidate = Path(comp.source_path)
        if ".." in candidate.parts:
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "missing_artifact", "Parent traversal is not permitted"
                )
            )
            return None
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            if candidate.is_symlink() or not candidate.resolve().is_relative_to(root):
                raise ValueError("Artifact path escapes the supplied project root or is a symlink")
            if not candidate.is_file():
                raise ValueError("Declared artifact is missing or is not a regular file")
        except (OSError, ValueError) as exc:
            report.issues.append(IntegrityIssue(comp.bom_ref, "missing_artifact", str(exc)))
            return None
        return candidate

    def _check_model_integrity(
        self,
        comp: ModelComponent,
        project_root: Path | None,
        report: IntegrityReport,
        checked_policies: set[SigstoreArtifactPolicy],
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
        if path is not None:
            try:
                with open_regular_file(path) as stream:
                    actual, explanation, inspected_digest = inspect_model_artifact(
                        path, stream=stream
                    )
                    after = os.fstat(stream.fileno())
                    if pathname_identity(path) != (after.st_dev, after.st_ino):
                        raise OSError("model artifact pathname changed during inspection")
                _, expected_digest = normalize_digest(comp.hashes.get("sha256", ""), "sha256")
                if inspected_digest != f"sha256:{expected_digest}":
                    report.issues.append(
                        IntegrityIssue(
                            comp.bom_ref,
                            "format_subject_mismatch",
                            "Inspected model structure does not match the BOM's SHA-256 subject",
                        )
                    )
            except (OSError, ValueError):
                actual, explanation = (
                    SerializationSafety.UNKNOWN,
                    "Model structure could not be bound to its SHA-256 subject",
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

        policy = self._signature_policies.get(path.resolve()) if path is not None else None
        if policy is None or path is None:
            category = (
                "unsigned_model" if comp.signing_status == "unsigned" else "unverified_signature"
            )
            severity = "unknown" if self.require_model_signatures else "warning"
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    category,
                    "No trusted artifact-bound signer policy was supplied",
                    severity,
                )
            )
            return
        checked_policies.add(policy)
        report.signatures_checked += 1
        result = verify_sigstore_bundle(
            path, policy.bundle_path, policy.expected_identity, policy.expected_issuer
        )
        if (
            not result.verified
            or result.identity != policy.expected_identity
            or result.issuer != policy.expected_issuer
        ):
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref,
                    "signature_verification_failed",
                    result.error or "Signature verification failed",
                )
            )
            return
        # Bind the verification result to the same bytes represented by the BOM.
        try:
            _, digest = normalize_digest(comp.hashes.get("sha256", ""), "sha256")
            if not result.details or result.details.get("artifact_digest") != f"sha256:{digest}":
                raise ValueError("Signed artifact does not match the BOM's SHA-256 digest")
        except ValueError as exc:
            report.issues.append(
                IntegrityIssue(comp.bom_ref, "signature_subject_mismatch", str(exc))
            )
            return
        report.signatures_verified += 1

    def _check_prompt_hash(
        self, comp: PromptComponent, project_root: Path | None, report: IntegrityReport
    ) -> None:
        if not comp.content_hash:
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
        result = verify_file_hash(path, comp.content_hash)
        if result.verified:
            report.hashes_verified += 1
        else:
            report.hashes_failed += 1
            report.issues.append(
                IntegrityIssue(
                    comp.bom_ref, "hash_mismatch", result.error or "Prompt digest mismatch"
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
        # Reject malformed declarations even when the artifact cannot be opened.
        valid: list[tuple[str, str]] = []
        for algorithm, expected in comp.hashes.items():
            try:
                normalize_digest(expected, algorithm)
                valid.append((algorithm, expected))
            except ValueError as exc:
                report.hashes_failed += 1
                report.issues.append(IntegrityIssue(comp.bom_ref, "file_hash_mismatch", str(exc)))
        if not valid:
            return
        path = self._artifact_path(comp, project_root, report)
        if path is None:
            report.hashes_failed += len(valid)
            return
        for algorithm, expected in valid:
            result = verify_file_hash(path, expected, algorithm)
            if result.verified:
                report.hashes_verified += 1
            else:
                report.hashes_failed += 1
                report.issues.append(
                    IntegrityIssue(
                        comp.bom_ref,
                        "file_hash_mismatch",
                        result.error or "Artifact digest mismatch",
                    )
                )
