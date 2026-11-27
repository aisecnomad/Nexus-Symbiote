"""Offline Kubernetes/cluster CycloneDX ML-BOM vs static AgentBOM drift check.

Reads one static native AgentBOM and one or more already-collected CycloneDX
runtime BOM JSON files (for example cluster ``k8s-aibom`` snapshots). Performs
zero network I/O and spawns zero subprocesses. Every finding from cluster BOMs is
tagged ``reported`` assurance: cluster snapshots reflect what the cluster
reporting pipeline emitted and cannot prove absence.
"""

from __future__ import annotations

import errno
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.aibom import AIBOM, parse_native_bytes
from nexus_symbiote.core.content_digest import inventory_content_digest
from nexus_symbiote.core.enums import ComponentType, RiskSeverity
from nexus_symbiote.core.hashing import (
    canonical_json,
    hash_bytes,
    hash_canonical,
    json_nesting_exceeds,
    open_regular_file,
    parse_json_strict,
)
from nexus_symbiote.core.models import (
    A2AServerComponent,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
)
from nexus_symbiote.sbom_import import (
    MAX_FOREIGN_SBOM_BYTES,
    _extract_cdx_entries,
    _is_ai_package_name,
    _norm_pkg,
)
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize

FORMAT = "nexus-symbiote-k8s-drift-v1"
ASSURANCE = "reported"
MAX_RUNTIME_BOMS = 32
MAX_RUNTIME_DEPTH = 128
MAX_DRIFT_ITEMS = 5_000
MAX_TEXT_FIELD = 512

_SUPPORTED_CDX_VERSIONS = frozenset({"1.4", "1.5", "1.6", "1.7"})
_SHA256_DIGEST_RE = re.compile(r"^(?:sha256:)?([0-9a-fA-F]{64})$", re.ASCII)
_MUTABLE_IMAGE_TAGS = frozenset({"latest", "main", "master", "dev", "nightly", "edge", "canary"})
_MUTABLE_PURL_RE = re.compile(r"^pkg:(?:oci|docker)/[^@#?]+(?:@([^?#]+))?(?:\?.*)?$", re.ASCII)


class RuntimeBOMInputError(ValueError):
    """A runtime CycloneDX BOM file could not be opened, parsed, or validated."""


def _clean(value: object, *, limit: int = MAX_TEXT_FIELD) -> str:
    text = neutralize(redact_text(str(value)))
    return text if len(text) <= limit else text[: limit - 3] + "..."


def _normalize_sha256(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    match = _SHA256_DIGEST_RE.fullmatch(value.strip())
    if match is None:
        return None
    return f"sha256:{match.group(1).lower()}"


def _normalize_endpoint(raw_url: str) -> str | None:
    cleaned = raw_url.strip()
    if not cleaned:
        return None
    parsed = urlsplit(cleaned if "://" in cleaned else f"https://{cleaned}")
    host = (parsed.hostname or "").strip().lower()
    if not host:
        return None
    port = parsed.port
    if port is None and parsed.scheme in {"http", "ws"}:
        port = 80
    elif port is None and parsed.scheme in {"https", "wss", ""}:
        port = 443
    path = parsed.path.rstrip("/")
    base = f"{host}:{port}" if port is not None else host
    return f"{base}{path}" if path else base


def _open_error(path: Path, exc: OSError) -> str:
    label = _clean(path.name)
    if exc.errno in {errno.ELOOP, errno.ENOTDIR}:
        return f"Runtime BOM {label} is reached through a symbolic link; pass the real file path."
    if exc.errno is None:
        return (
            f"Runtime BOM {label} is not a regular file; directories, links and FIFOs are refused."
        )
    if exc.errno == errno.ENOENT:
        return f"Runtime BOM {label} does not exist."
    if exc.errno in {errno.EACCES, errno.EPERM}:
        return f"Runtime BOM {label} cannot be read: permission denied."
    return f"Runtime BOM {label} exceeds bounds or cannot be read."


def _read_runtime_document(path: Path) -> tuple[dict[str, Any], str]:
    try:
        with open_regular_file(path) as handle:
            raw_bytes = handle.read(MAX_FOREIGN_SBOM_BYTES + 1)
    except OSError as exc:
        raise RuntimeBOMInputError(_open_error(path, exc)) from None

    if len(raw_bytes) > MAX_FOREIGN_SBOM_BYTES:
        raise RuntimeBOMInputError(
            f"Runtime BOM {_clean(path.name)} exceeds {MAX_FOREIGN_SBOM_BYTES} byte limit."
        )

    try:
        text = raw_bytes.decode("utf-8")
    except UnicodeDecodeError:
        raise RuntimeBOMInputError(f"Runtime BOM {_clean(path.name)} is not valid UTF-8.") from None

    try:
        if json_nesting_exceeds(text, MAX_RUNTIME_DEPTH):
            raise RuntimeBOMInputError(
                f"Runtime BOM {_clean(path.name)} exceeds JSON nesting limit ({MAX_RUNTIME_DEPTH})."
            )
        doc = parse_json_strict(text, max_bytes=MAX_FOREIGN_SBOM_BYTES)
    except RuntimeBOMInputError:
        raise
    except (ValueError, RecursionError):
        raise RuntimeBOMInputError(
            f"Runtime BOM {_clean(path.name)} contains invalid JSON or duplicate keys."
        ) from None

    if not isinstance(doc, dict):
        raise RuntimeBOMInputError(f"Runtime BOM {_clean(path.name)} root must be a JSON object.")
    if doc.get("bomFormat") != "CycloneDX":
        raise RuntimeBOMInputError(
            f"Runtime BOM {_clean(path.name)} must set bomFormat='CycloneDX'."
        )
    spec_version = doc.get("specVersion")
    if not isinstance(spec_version, str) or spec_version not in _SUPPORTED_CDX_VERSIONS:
        raise RuntimeBOMInputError(
            f"Runtime BOM {_clean(path.name)} has unsupported CycloneDX specVersion."
        )
    return doc, hash_bytes(raw_bytes)


def _extract_k8s_properties(node: Mapping[str, Any]) -> dict[str, str]:
    props = node.get("properties")
    if not isinstance(props, list):
        return {}
    context: dict[str, str] = {}
    for item in props:
        if not isinstance(item, Mapping):
            continue
        pname = item.get("name")
        pval = item.get("value")
        if not isinstance(pname, str) or not isinstance(pval, str):
            continue
        if pname.startswith(("k8s.", "cdx:k8s:", "container.")):
            context[_clean(pname, limit=128)] = _clean(pval, limit=256)
            if len(context) >= 16:
                break
    return context


def _check_container_mutability(name: str, version: str | None, purl: str | None) -> str | None:
    if purl:
        if "@sha256:" in purl.lower() and re.search(r"@sha256:[0-9a-f]{64}", purl.lower()):
            return None
        match = _MUTABLE_PURL_RE.fullmatch(purl.strip())
        if match is not None:
            ref_tag = (match.group(1) or "").strip().lower()
            if not ref_tag:
                return "unpinned OCI/Docker PURL without digest or version"
            if ref_tag in _MUTABLE_IMAGE_TAGS:
                return f"mutable container tag ':{_clean(ref_tag)}'"
            return "container PURL omits immutable @sha256 digest"
    ver = (version or "").strip()
    if ver:
        if re.search(r"(?:^|@)sha256:[0-9a-f]{64}$", ver.lower()):
            return None
        lowered = ver.lstrip(":").lower()
        if lowered in _MUTABLE_IMAGE_TAGS:
            return f"mutable container tag ':{_clean(lowered)}'"
        return None
    if ":" in name:
        tag = name.rsplit(":", 1)[1].strip().lower()
        if tag in _MUTABLE_IMAGE_TAGS:
            return f"mutable container tag ':{_clean(tag)}'"
    return "container workload has no immutable digest or version"


@dataclass(frozen=True)
class _RuntimeObservation:
    kind: str  # "model" | "service" | "container" | "package"
    key: str
    name: str
    version: str | None
    purl: str | None
    sha256: str | None
    endpoints: tuple[str, ...]
    mutable_reason: str | None
    source_files: tuple[str, ...]
    cluster_context: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "kind": self.kind,
            "name": _clean(self.name),
            "version": _clean(self.version) if self.version else None,
            "purl": _clean(self.purl) if self.purl else None,
            "sha256": self.sha256,
            "assurance": ASSURANCE,
            "source_files": list(self.source_files),
        }
        if self.endpoints:
            payload["endpoints"] = [_clean(ep) for ep in self.endpoints]
        if self.mutable_reason:
            payload["mutable_tag_reason"] = _clean(self.mutable_reason)
        if self.cluster_context:
            payload["cluster_context"] = dict(self.cluster_context)
        return payload


@dataclass
class _MutableObsAcc:
    kind: str
    name: str
    version: str | None
    purl: str | None
    sha256: str | None
    endpoints: set[str] = field(default_factory=set)
    mutable_reason: str | None = None
    source_files: set[str] = field(default_factory=set)
    cluster_context: dict[str, str] = field(default_factory=dict)


def _model_keys(name: str) -> set[str]:
    clean = name.strip().lower()
    keys = {clean}
    if "/" in clean:
        keys.add(clean.rsplit("/", 1)[-1])
    if ":" in clean:
        keys.add(clean.split(":", 1)[0])
    return {k for k in keys if k}


def _collect_observations(
    runtime_paths: Sequence[Path],
    static_pkg_keys: set[str],
) -> tuple[list[_RuntimeObservation], list[dict[str, str]], dict[str, int]]:
    inputs_meta: list[dict[str, str]] = []
    acc_map: dict[tuple[str, str, str], _MutableObsAcc] = {}
    stats = {
        "runtime_boms_read": 0,
        "cyclonedx_entries_read": 0,
        "non_ai_packages_ignored": 0,
    }

    for path in runtime_paths:
        doc, sha = _read_runtime_document(path)
        stats["runtime_boms_read"] += 1
        file_label = _clean(path.name)
        inputs_meta.append(
            {
                "file": file_label,
                "sha256": sha,
                "spec_version": str(doc["specVersion"]),
            }
        )
        entries = _extract_cdx_entries(doc)
        stats["cyclonedx_entries_read"] += len(entries)
        doc_ctx = _extract_k8s_properties(
            doc.get("metadata", {}) if isinstance(doc.get("metadata"), Mapping) else {}
        )

        for entry in entries:
            raw_entry = entry["raw_entry"]
            raw_type = str(entry["type"]).lower()
            name = str(entry["name"]).strip()
            version = entry.get("version")
            purl = entry.get("purl")
            sha256 = _normalize_sha256(entry.get("sha256"))

            is_container = raw_type == "container" or (
                isinstance(purl, str) and purl.lower().startswith(("pkg:oci/", "pkg:docker/"))
            )
            if raw_type == "machine-learning-model":
                kind = "model"
                norm_key = name.lower()
            elif raw_type == "service":
                kind = "service"
                norm_key = name.lower()
            elif is_container:
                kind = "container"
                base_name = (
                    name.rsplit(":", 1)[0]
                    if ":" in name and not name.startswith("sha256:")
                    else name
                )
                norm_key = base_name.lower()
            elif raw_type in {"library", "framework", "application"}:
                pkg_key = _norm_pkg(name)
                if not (_is_ai_package_name(name) or pkg_key in static_pkg_keys):
                    stats["non_ai_packages_ignored"] += 1
                    continue
                kind = "package"
                norm_key = pkg_key
            else:
                stats["non_ai_packages_ignored"] += 1
                continue

            ver_key = (version or "").strip().lower()
            map_key = (kind, norm_key, ver_key)
            if map_key not in acc_map:
                mutable_reason = (
                    _check_container_mutability(name, version, purl)
                    if kind == "container"
                    else None
                )
                ctx = {**doc_ctx, **_extract_k8s_properties(raw_entry)}
                acc_map[map_key] = _MutableObsAcc(
                    kind=kind,
                    name=name,
                    version=version.strip()
                    if isinstance(version, str) and version.strip()
                    else None,
                    purl=purl.strip() if isinstance(purl, str) and purl.strip() else None,
                    sha256=sha256,
                    mutable_reason=mutable_reason,
                    cluster_context=ctx,
                )
            acc = acc_map[map_key]
            acc.source_files.add(file_label)
            if sha256 and not acc.sha256:
                acc.sha256 = sha256
            raw_eps = raw_entry.get("endpoints")
            if isinstance(raw_eps, list):
                for ep in raw_eps:
                    if isinstance(ep, str):
                        norm_ep = _normalize_endpoint(ep)
                        if norm_ep:
                            acc.endpoints.add(norm_ep)

    observations = [
        _RuntimeObservation(
            kind=key[0],
            key=key[1],
            name=acc.name,
            version=acc.version,
            purl=acc.purl,
            sha256=acc.sha256,
            endpoints=tuple(sorted(acc.endpoints)),
            mutable_reason=acc.mutable_reason,
            source_files=tuple(sorted(acc.source_files)),
            cluster_context=acc.cluster_context,
        )
        for key, acc in sorted(acc_map.items())
    ]
    return (
        observations[:MAX_DRIFT_ITEMS],
        sorted(inputs_meta, key=lambda item: (item["file"], item["sha256"])),
        stats,
    )


@dataclass
class _StaticCatalog:
    models: dict[str, list[ModelComponent]]
    services: dict[str, list[MCPServerComponent | A2AServerComponent]]
    endpoints: dict[str, list[MCPServerComponent | A2AServerComponent]]
    packages: dict[str, list[RegistryEntryComponent]]
    package_keys: set[str]


def _index_static_bom(bom: AIBOM) -> _StaticCatalog:
    models: dict[str, list[ModelComponent]] = {}
    services: dict[str, list[MCPServerComponent | A2AServerComponent]] = {}
    endpoints: dict[str, list[MCPServerComponent | A2AServerComponent]] = {}
    packages: dict[str, list[RegistryEntryComponent]] = {}

    for comp in bom.components:
        if isinstance(comp, ModelComponent):
            for key in _model_keys(comp.name):
                models.setdefault(key, []).append(comp)
            if comp.requested_alias:
                for key in _model_keys(comp.requested_alias):
                    models.setdefault(key, []).append(comp)
        elif isinstance(comp, MCPServerComponent | A2AServerComponent):
            services.setdefault(comp.name.strip().lower(), []).append(comp)
            if comp.endpoint_url:
                ep = _normalize_endpoint(comp.endpoint_url)
                if ep:
                    endpoints.setdefault(ep, []).append(comp)
        elif isinstance(comp, RegistryEntryComponent):
            packages.setdefault(_norm_pkg(comp.name), []).append(comp)
            if comp.package_url and "/" in comp.package_url:
                tail = comp.package_url.rsplit("/", 1)[-1].split("@", 1)[0].split("?", 1)[0]
                if tail:
                    packages.setdefault(_norm_pkg(tail), []).append(comp)
    return _StaticCatalog(
        models=models,
        services=services,
        endpoints=endpoints,
        packages=packages,
        package_keys=set(packages),
    )


def _static_sha256(comp: Any) -> str | None:
    hashes = getattr(comp, "hashes", None)
    if not isinstance(hashes, Mapping):
        return None
    for alg, digest in hashes.items():
        if str(alg).strip().lower().replace("-", "") == "sha256":
            normalized = _normalize_sha256(digest)
            if normalized:
                return normalized
    return None


def _static_purl_digest(purl: str | None) -> str | None:
    if not isinstance(purl, str) or "@sha256:" not in purl.lower():
        return None
    tail = purl.lower().split("@", 1)[1].split("?", 1)[0]
    return _normalize_sha256(tail)


def collect(
    inventory_path: Path,
    runtime_paths: Sequence[Path],
    *,
    fail_on: str = "undeclared",
) -> dict[str, Any]:
    """Compare runtime CycloneDX cluster BOMs against a static native AgentBOM."""
    if not runtime_paths or len(runtime_paths) > MAX_RUNTIME_BOMS:
        raise RuntimeBOMInputError(
            f"Pass between 1 and {MAX_RUNTIME_BOMS} runtime CycloneDX BOM files."
        )
    bom, inv_bytes = AIBOM.load_with_bytes(inventory_path)
    inv_sha = hash_bytes(inv_bytes)
    try:
        raw_doc = parse_native_bytes(inv_bytes)
        content_digest = inventory_content_digest(raw_doc) if isinstance(raw_doc, dict) else None
    except (ValueError, RecursionError):
        content_digest = None

    catalog = _index_static_bom(bom)
    observations, runtime_inputs, stats = _collect_observations(runtime_paths, catalog.package_keys)

    matched: list[dict[str, Any]] = []
    drifted: list[dict[str, Any]] = []
    mutable_tags: list[dict[str, Any]] = []
    undeclared: list[dict[str, Any]] = []
    seen_static_refs: set[str] = set()

    for obs in observations:
        static_matches: list[Any] = []
        if obs.kind == "model":
            for mk in _model_keys(obs.name):
                static_matches.extend(catalog.models.get(mk, ()))
        elif obs.kind == "service":
            static_matches.extend(catalog.services.get(obs.key, ()))
            for ep in obs.endpoints:
                static_matches.extend(catalog.endpoints.get(ep, ()))
        else:
            static_matches.extend(catalog.packages.get(_norm_pkg(obs.name), ()))
            if obs.kind == "container":
                static_matches.extend(catalog.packages.get(_norm_pkg(obs.key), ()))
                static_matches.extend(catalog.services.get(obs.key, ()))

        # Deduplicate matched components cleanly preserving declaration order
        deduped_matches = list({c.bom_ref: c for c in static_matches}.values())
        obs_dict = obs.to_dict()

        if not deduped_matches:
            if obs.mutable_reason:
                obs_dict["mutable_image_tag"] = True
            undeclared.append(obs_dict)
            continue

        for comp in deduped_matches:
            seen_static_refs.add(comp.bom_ref)

        drift_reasons: list[str] = []
        # Version drift check against matching static component declarations
        static_versions = {
            c.version.strip() for c in deduped_matches if getattr(c, "version", None)
        }
        if obs.version and static_versions and obs.version not in static_versions:
            drift_reasons.append("version_mismatch")

        # Digest drift check
        static_digests = {
            d
            for c in deduped_matches
            for d in (_static_sha256(c), _static_purl_digest(getattr(c, "package_url", None)))
            if d
        }
        if obs.sha256 and static_digests and obs.sha256 not in static_digests:
            drift_reasons.append("digest_mismatch")

        # Service endpoint drift check
        if obs.kind == "service" and obs.endpoints:
            static_eps = {
                norm
                for c in deduped_matches
                if getattr(c, "endpoint_url", None)
                for norm in (_normalize_endpoint(str(c.endpoint_url)),)
                if norm
            }
            if static_eps and not (set(obs.endpoints) & static_eps):
                drift_reasons.append("endpoint_mismatch")

        obs_dict["inventory_refs"] = [_clean(c.bom_ref) for c in deduped_matches]
        if static_versions:
            obs_dict["declared_versions"] = [_clean(v) for v in sorted(static_versions)]

        if drift_reasons:
            obs_dict["drift_reasons"] = drift_reasons
            drifted.append(obs_dict)
        if obs.mutable_reason:
            mutable_tags.append(obs_dict)
        elif not drift_reasons:
            matched.append(obs_dict)

    unobserved: list[dict[str, str]] = []
    relevant_types = {
        ComponentType.MODEL,
        ComponentType.MCP_SERVER,
        ComponentType.A2A_SERVER,
        ComponentType.REGISTRY_ENTRY,
    }
    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        if comp.component_type in relevant_types and comp.bom_ref not in seen_static_refs:
            unobserved.append(
                {
                    "bom_ref": _clean(comp.bom_ref),
                    "component_type": comp.component_type.value,
                    "name": _clean(comp.name),
                }
            )

    reasons: list[str] = []
    if stats["cyclonedx_entries_read"] == 0:
        reasons.append("runtime CycloneDX BOMs recorded 0 components or services")
    if fail_on in {"undeclared", "drift"} and undeclared:
        reasons.append(f"{len(undeclared)} undeclared runtime component(s) or service(s)")
    if fail_on == "drift" and drifted:
        reasons.append(f"{len(drifted)} runtime version, digest, or endpoint drift mismatch(es)")
    if fail_on == "drift" and mutable_tags:
        reasons.append(f"{len(mutable_tags)} runtime container(s) using mutable or unpinned tags")

    passed = fail_on == "none" or not reasons

    return {
        "format": FORMAT,
        "assurance": ASSURANCE,
        "inputs": {
            "inventory": {
                "file": _clean(inventory_path.name),
                "sha256": inv_sha,
                "content_digest": content_digest,
            },
            "runtime_boms": runtime_inputs,
        },
        "coverage": {
            **stats,
            "observed_distinct": len(observations),
            "note": (
                "Runtime cluster BOM evidence reflects reported container/service state and "
                "cannot prove absence."
            ),
        },
        "observed": [obs.to_dict() for obs in observations],
        "reconciliation": {
            "matched": matched,
            "drifted": drifted,
            "mutable_tags": mutable_tags,
            "undeclared": undeclared,
            "unobserved": unobserved,
        },
        "gate": {
            "fail_on": fail_on,
            "passed": passed,
            "reasons": reasons,
        },
    }


def render(document: Mapping[str, Any]) -> str:
    """Deterministic canonical JSON output for a cluster drift reconciliation document."""
    return canonical_json(dict(document))


def _sarif_hash(payload: Mapping[str, Any]) -> str:
    return hash_canonical(dict(payload)).split(":", 1)[1]


def sarif_document(document: Mapping[str, Any], anchor: str) -> dict[str, Any]:
    """Emit schema-valid SARIF 2.1.0 findings from a cluster BOM reconciliation document."""
    from nexus_symbiote import __version__
    from nexus_symbiote.generators.sarif import (
        GITHUB_MAX_RESULTS,
        SEVERITY_TO_SARIF,
        SRCROOT,
        SARIFGenerator,
        plain_text,
    )
    from nexus_symbiote.generators.validation import require_valid

    rec = document["reconciliation"]
    rules_map: dict[str, dict[str, Any]] = {}
    findings: dict[tuple[str, str], dict[str, Any]] = {}

    specs: list[tuple[str, RiskSeverity, str, Mapping[str, Any]]] = [
        ("runtime_undeclared", RiskSeverity.HIGH, "undeclared", item)
        for item in rec.get("undeclared", [])
    ]
    specs.extend(
        ("data_integrity", RiskSeverity.HIGH, "drifted", item) for item in rec.get("drifted", [])
    )
    specs.extend(
        ("mutable_image_tag", RiskSeverity.MEDIUM, "mutable_tag", item)
        for item in rec.get("mutable_tags", [])
    )

    for category, severity, status, item in specs:
        rule_id = f"nexus_symbiote/{category}/{severity.value}"
        rules_map.setdefault(rule_id, SARIFGenerator._rule(rule_id, category, severity))
        name = item.get("name", "unknown")
        kind = item.get("kind", "component")
        if status == "undeclared":
            raw_msg = (
                f"Runtime CycloneDX BOM reports {kind} '{name}', which is absent from the "
                "static AgentBOM."
            )
        elif status == "drifted":
            reasons = ", ".join(item.get("drift_reasons", ()))
            raw_msg = f"Runtime {kind} '{name}' drifted from static AgentBOM ({reasons})."
        else:
            raw_msg = (
                f"Runtime {kind} '{name}' uses a mutable or unpinned image reference "
                f"({item.get('mutable_tag_reason', 'unpinned')})."
            )
        fp = _sarif_hash(
            {
                "rule": rule_id,
                "status": status,
                "kind": kind,
                "name": name,
                "ver": item.get("version"),
            }
        )
        props: dict[str, Any] = {
            "assurance": ASSURANCE,
            "kind": plain_text(kind),
            "status": status,
        }
        if item.get("version"):
            props["version"] = plain_text(item["version"])
        findings.setdefault(
            (rule_id, fp),
            {
                "ruleId": rule_id,
                "level": SEVERITY_TO_SARIF[severity],
                "message": {"text": plain_text(redact_text(raw_msg))},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": anchor, "uriBaseId": SRCROOT}
                        }
                    }
                ],
                "partialFingerprints": {
                    "nexus_symbiote/v1": fp,
                    "primaryLocationLineHash": fp[:16] + ":1",
                },
                "properties": props,
            },
        )

    ordered_rules = [rules_map[rid] for rid in sorted(rules_map)]
    index = {rule["id"]: pos for pos, rule in enumerate(ordered_rules)}
    results = [{**res, "ruleIndex": index[res["ruleId"]]} for res in findings.values()]
    notes = [
        {
            "level": "note",
            "message": {
                "text": (
                    "Runtime cluster BOM evidence reflects reported state; missing items "
                    "cannot prove absence."
                )
            },
        }
    ]
    if len(results) > GITHUB_MAX_RESULTS:
        notes.append(
            {
                "level": "warning",
                "message": {
                    "text": (
                        f"Run produced {len(results)} results; GitHub code scanning keeps at "
                        f"most {GITHUB_MAX_RESULTS}."
                    )
                },
            }
        )
    sarif: dict[str, Any] = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nexus-symbiote",
                        "version": __version__,
                        "informationUri": "https://github.com/aisecnomad/Nexus-Symbiote",
                        "rules": ordered_rules,
                    }
                },
                "results": results,
                "invocations": [{"executionSuccessful": True, "toolExecutionNotifications": notes}],
                "properties": {
                    "assurance": ASSURANCE,
                    "evidence_format": FORMAT,
                    "inventory_sha256": document["inputs"]["inventory"]["sha256"],
                },
            }
        ],
    }
    require_valid(sarif, "sarif")
    return sarif
