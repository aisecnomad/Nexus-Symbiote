"""Per-component evidence profile (R1.1-8 / X9)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from nexus_symbiote.core import models as m
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.validators.risk import effective_component_risks

if TYPE_CHECKING:
    from nexus_symbiote.utils.crypto import SignaturePolicySet
    from nexus_symbiote.validators.integrity import IntegrityReport

EVIDENCE_PROFILE_SCHEMA: Final[str] = "nexus-symbiote/evidence-profile/v2"
_SEVERITY_RANK: Final[dict[RiskSeverity, int]] = {
    s: i for i, s in enumerate(reversed(list(RiskSeverity)), 1)
}
_EXACT_VERSION_RE: Final[re.Pattern[str]] = re.compile(
    r"v?[0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:[-+._][0-9A-Za-z.-]+)?", re.ASCII
)
_COMMIT_HEX_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", re.ASCII)
_RANGE_CHARS: Final[frozenset[str]] = frozenset("^~><*!,| ")
_FLOATING_TAGS: Final[frozenset[str]] = frozenset(
    ("latest", "main", "master", "head", "nightly", "edge")
)


def is_exact_version(version: str | None) -> bool:
    """Return True iff version names a single immutable release rather than a range or branch."""
    if not version:
        return False
    s = version.strip()
    s = s[3:].strip() if s.startswith("===") else (s[2:].strip() if s.startswith("==") else s)
    if not s or s.lower() in _FLOATING_TAGS or any(c in s for c in _RANGE_CHARS):
        return False
    if any(seg.lower() == "x" for seg in re.split(r"[._+-]", s)):
        return False
    return bool(_EXACT_VERSION_RE.fullmatch(s))


def purl_has_exact_version(purl: str | None) -> bool:
    """Return True iff a Package URL carries an exact @version or @sha256:<64hex> qualifier."""
    if not purl or "@" not in purl:
        return False
    without_frag = purl.split("#", 1)[0].split("?", 1)[0]
    if "@" not in without_frag:
        return False
    ver = without_frag.rsplit("@", 1)[1]
    if ver.lower().startswith("sha256:") and len(ver) == 71:
        return bool(re.fullmatch(r"[0-9a-fA-F]{64}", ver[7:]))
    return is_exact_version(ver)


def _is_pinned(comp: m.AnyComponent) -> bool:
    if isinstance(comp, m.MCPServerComponent):
        return bool(comp.version_pinned)
    if isinstance(comp, m.RegistryEntryComponent):
        if comp.version is not None and not is_exact_version(comp.version):
            return False
        if isinstance(comp.properties.get("version_pinned"), bool):
            return bool(comp.properties["version_pinned"])
        return purl_has_exact_version(comp.package_url) or is_exact_version(comp.version)
    if isinstance(comp, m.ModelComponent) and _COMMIT_HEX_RE.fullmatch(
        comp.resolved_revision or ""
    ):
        return True
    return is_exact_version(comp.version)


def _has_recorded_digest(comp: m.AnyComponent) -> bool:
    return bool(
        any(isinstance(v, str) and v for v in comp.hashes.values())
        or isinstance(comp.properties.get("declared_sha256"), str)
        or (isinstance(comp, m.ToolComponent) and comp.definition_hash)
        or (isinstance(comp, m.MCPServerComponent) and comp.schema_hash)
        or (isinstance(comp, m.PromptComponent) and comp.content_hash)
        or (
            isinstance(comp, m.ModelComponent)
            and (comp.safetensors_header_hash or comp.tensor_inventory_hash)
        )
    )


def _verify_model_policy(
    aibom: AIBOM, root: Path | None, pol: SignaturePolicySet | None
) -> IntegrityReport | None:
    if root is None or pol is None or not (len(pol) or len(pol.digest_pins)):
        return None
    from nexus_symbiote.validators.integrity import IntegrityValidator

    res_root = root.resolve()
    covered = {e.artifact_path.resolve() for e in (*pol, *pol.digest_pins)}
    dirs = {p.parent for p in covered}
    candidates: list[m.AnyComponent] = []
    for comp in sorted(aibom.components, key=lambda c: c.bom_ref):
        if not isinstance(comp, m.ModelComponent) or not comp.source_path:
            continue
        # Eligibility uses the recorded path. The validator confines the actual reads.
        target = res_root / comp.source_path
        if target in covered or (comp.properties.get("weight_files") and target.parent in dirs):
            candidates.append(comp)
    return IntegrityValidator(pol).validate(AIBOM(components=candidates), project_root=res_root)


def build_evidence_profile(
    aibom: AIBOM,
    *,
    runtime_matched_refs: set[str] | None = None,
    project_root: Path | None = None,
    signature_policies: SignaturePolicySet | None = None,
) -> dict[str, Any]:
    """Compute a deterministic per-component evidence profile without a scalar TrustScore."""
    matched = runtime_matched_refs or set()
    report = _verify_model_policy(aibom, project_root, signature_policies)
    verified = report.model_policy_evidence if report else {}
    entries: list[dict[str, Any]] = []
    for comp in sorted(aibom.components, key=lambda c: c.bom_ref):
        proof = verified.get(comp.bom_ref)
        ev = {
            "pinned": _is_pinned(comp),
            "digest_recorded": _has_recorded_digest(comp),
            "digest_bound": bool(proof and proof.weight_files > 0),
            "digest_pinned_under_policy": bool(
                proof
                and proof.weight_files > 0
                and proof.digest_pins_verified == proof.weight_files
            ),
            "signed_under_policy": bool(
                proof and proof.weight_files > 0 and proof.signatures_verified == proof.weight_files
            ),
            "runtime_matched": comp.bom_ref in matched,
        }
        claims = {
            "collector_observation": comp.assurance_level
            in {AssuranceLevel.OBSERVED, AssuranceLevel.VERIFIED},
            "runtime_observation": any(
                cl.assurance.value == "reported" or cl.method.startswith("otlp")
                for cl in comp.claims.values()
            ),
        }
        risks = effective_component_risks(comp)
        observed = report.model_behavior_risks.get(comp.bom_ref, {}) if report else {}
        additional = set(observed.values()).difference(r.category for r in risks)
        hi = (
            max(risks, key=lambda r: _SEVERITY_RANK.get(r.severity, 0)).severity.value
            if risks
            else None
        )
        entry: dict[str, Any] = {
            "bom_ref": neutralize(comp.bom_ref),
            "name": neutralize(comp.name),
            "component_type": comp.component_type.value,
            "assurance_level": comp.assurance_level.value,
            "evidence": ev,
            "inventory_claims": claims,
            "finding_count": len(risks) + len(additional),
            "highest_finding_severity": RiskSeverity.CRITICAL.value if observed else hi,
            "missing_evidence": [k for k, v in ev.items() if not v],
        }
        if observed:
            entry["integrity_findings"] = [
                {"category": category, "severity": RiskSeverity.CRITICAL.value}
                for category in sorted(observed)
            ]
        if isinstance(comp, m.ModelComponent) and comp.signing_status:
            entry["declared_signing_status"] = neutralize(comp.signing_status)
        entries.append(entry)
    return {
        "schema": EVIDENCE_PROFILE_SCHEMA,
        "policy_loaded": report is not None,
        "policy_verified": bool(
            report and verified and not report.issues and not report.issues_omitted
        ),
        "component_count": len(entries),
        "components": entries,
    }
