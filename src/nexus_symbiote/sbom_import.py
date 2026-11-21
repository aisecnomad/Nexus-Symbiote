"""Foreign SBOM import, nested manifest walker, pinning_state, and unread_shapes census (R1.2-2)."""

from __future__ import annotations

import configparser
import hashlib
import hmac
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any, Final

from packageurl import PackageURL
from packaging.requirements import InvalidRequirement, Requirement
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes, open_regular_file, parse_json_strict
from nexus_symbiote.core.models import (
    AnyComponent,
    ClaimEvidence,
    CompletenessClaim,
    DataSourceComponent,
    MCPServerComponent,
    ModelComponent,
    RegistryEntryComponent,
    RiskAssessment,
)
from nexus_symbiote.evidence_profile import is_exact_version, purl_has_exact_version
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.scanners import registry as _reg
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.mcp import _MIN_SOURCE_BINDING_KEY_LENGTH, SOURCE_BINDING_KEY_ENV
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.utils.toml import loads as load_toml

MAX_FOREIGN_SBOM_BYTES: Final[int] = 16 * 1024 * 1024
MAX_FOREIGN_COMPONENTS: Final[int] = 10_000
MAX_NESTED_CDX_DEPTH: Final[int] = 32
MAX_MANIFEST_YAML_BYTES: Final[int] = 512 * 1024
MAX_CONFLICT_SAMPLES: Final[int] = 8
MAX_CONFLICT_SUMMARY: Final[int] = 200
_SUPPORTED_CDX_SPECS: Final[frozenset[str]] = frozenset(["1.4", "1.5", "1.6", "1.7"])
_SUPPORTED_SPDX2_VERSIONS: Final[frozenset[str]] = frozenset(("SPDX-2.2", "SPDX-2.3"))
_SHA256_HEX_RE: Final[re.Pattern[str]] = re.compile(r"[0-9a-fA-F]{64}", re.ASCII)
_REQ_HASH_RE: Final[re.Pattern[str]] = re.compile(r"--hash=sha256:([0-9a-fA-F]{64})", re.ASCII)
_REQ_OPT_RE: Final[re.Pattern[str]] = re.compile(r"(?:^|\s+)--[A-Za-z0-9_-]+(?:=\S+)?")
_HIDDEN_SECRET_DIRS: Final[frozenset[str]] = frozenset(
    (".ssh", ".aws", ".gnupg", ".kube", ".docker")
)
_MODEL_EXTS: Final[frozenset[str]] = frozenset(
    {".safetensors", ".bin", ".gguf", ".onnx", ".pt", ".pth", ".ckpt", ".h5", ".tflite"}
)
_DATA_EXTS: Final[frozenset[str]] = frozenset(
    {".parquet", ".arrow", ".csv", ".jsonl", ".zip", ".tgz", ".gz"}
)
_PKG_EXTS: Final[frozenset[str]] = frozenset({".whl", ".tgz", ".gz", ".zip", ".jar"})
_ALL_ARTIFACT_EXTS: Final[frozenset[str]] = _MODEL_EXTS | _DATA_EXTS | _PKG_EXTS
_NPM_RANGE_RE: Final[re.Pattern[str]] = re.compile(
    r"^([\^~])\s*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?$"
)
_EXTRA_AI_PREFIXES = (
    "candle-",
    "async-openai",
    "rig-",
    "tokenizers",
    "burn-",
    "langchaingo",
    "go-openai",
)
_CONDA_NAMES = frozenset(("environment.yml", "environment.yaml", "conda.yml", "conda.yaml"))
_NESTED_MANIFEST_NAMES = frozenset(
    ("package.json", "pyproject.toml", "setup.cfg", "Cargo.toml", "go.mod", *_CONDA_NAMES)
)


@dataclass(frozen=True)
class UnreadShapeCount:
    shape: str
    count: int
    owner: str = "shadowscan"


@dataclass
class SBOMImportSummary:
    aibom: AIBOM
    source_format: str
    document_sha256: str
    imported_count: int = 0
    bound_local_count: int = 0
    conflict_count: int = 0
    unresolved_conflict_count: int = 0
    conflicts: list[str] = field(default_factory=list)
    scan_failures: list[str] = field(default_factory=list)


@dataclass
class _IdentityBucket:
    versions: dict[str, str] = field(default_factory=dict)
    digests: dict[str, str] = field(default_factory=dict)
    extra_version_conflicts: int = 0
    extra_digest_conflicts: int = 0
    unmarked_peers: list[AnyComponent] = field(default_factory=list)


def _norm_pkg(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name.strip().lower())


def _is_ai_package_name(name: str) -> bool:
    raw = name.strip().lower()
    if raw in _reg.AI_PACKAGE_NAMES or (
        raw.startswith("@") and raw.split("/", 1)[0] in _reg.AI_PACKAGE_SCOPES
    ):
        return True
    lowered = _norm_pkg(raw)
    if lowered in _reg.AI_PACKAGE_NAMES or lowered == "ort":
        return True
    unscoped = lowered.rsplit("/", 1)[-1] if "/" in lowered else lowered
    return any(
        unscoped.startswith(p) for p in (*_reg.AI_PACKAGE_PREFIXES, *_EXTRA_AI_PREFIXES)
    ) or any(kw in lowered for kw in _reg.AI_IMAGE_KEYWORDS)


def _find_sha256(items: Any, alg_key: str, val_key: str) -> str | None:
    if isinstance(items, list):
        for item in items:
            if (
                isinstance(item, dict)
                and isinstance(item.get(alg_key), str)
                and isinstance(item.get(val_key), str)
            ):
                val = item[val_key].strip().removeprefix("sha256:").lower()
                if item[alg_key].strip().upper().replace(
                    "-", ""
                ) == "SHA256" and _SHA256_HEX_RE.fullmatch(val):
                    return f"sha256:{val}"
    return None


def _make_entry(
    raw: dict[str, Any],
    name: str,
    ver: Any,
    purl: Any,
    kind: str,
    sup: Any = None,
    sha: str | None = None,
) -> dict[str, Any]:
    return {
        "raw_entry": raw,
        "name": name,
        "version": ver if isinstance(ver, str) else None,
        "purl": purl if isinstance(purl, str) else None,
        "type": kind,
        "supplier": sup if isinstance(sup, str) else None,
        "sha256": sha,
    }


def _clean_exact_spec(ver: str | None) -> str | None:
    if not ver:
        return None
    s = ver.strip()
    for pfx in ("===", "=="):
        if s.startswith(pfx):
            return s[len(pfx) :].strip()
    return s[1:].strip() if (s.startswith("=") and not s.startswith("=>")) else s


def _spec_to_pep440(spec: str) -> str | None:
    s = spec.strip()
    if s in {"*", "x", "X"}:
        return ">=0"
    if (m := _NPM_RANGE_RE.match(s)) is not None:
        maj, min_i, pat_i = int(m.group(2)), int(m.group(3) or 0), int(m.group(4) or 0)
        if m.group(1) == "~":
            hi = f"{maj}.{min_i + 1}.0" if m.group(3) else f"{maj + 1}.0.0"
            return f">={maj}.{min_i}.{pat_i},<{hi}"
        if maj > 0:
            return f">={maj}.{min_i}.{pat_i},<{maj + 1}.0.0"
        return f">=0.{min_i}.{pat_i},<0.{min_i + 1}.0" if min_i > 0 else f"==0.0.{pat_i}"
    if re.fullmatch(r"(?:==)?v?\d+(?:\.(?:\d+|[*xX]))+", s) and any(w in s for w in "*xX"):
        return "==" + re.sub(r"[xX]", "*", s.removeprefix("==").lstrip("v"))
    return s if any(c in s for c in "><~!*,") else None


def _versions_conflict(peer_ver: str | None, cand_ver: str | None) -> bool:
    if not peer_ver or not cand_ver:
        return False
    p_norm, c_norm = _clean_exact_spec(peer_ver) or "", _clean_exact_spec(cand_ver) or ""
    if p_norm == c_norm or p_norm.lstrip("v") == c_norm.lstrip("v"):
        return False
    for spec_side, exact_side in ((peer_ver.strip(), c_norm), (cand_ver.strip(), p_norm)):
        pep = _spec_to_pep440(spec_side)
        if pep is not None and is_exact_version(exact_side):
            try:
                return not SpecifierSet(pep).contains(
                    Version(exact_side.lstrip("v")), prereleases=True
                )
            except (InvalidSpecifier, InvalidVersion):
                pass
    return True


def _record_bucket_item(
    mapping: dict[str, str], key: str, ref: str, overflow_attr: str, bucket: _IdentityBucket
) -> None:
    if key not in mapping:
        if len(mapping) < MAX_CONFLICT_SAMPLES:
            mapping[key] = ref
        else:
            setattr(bucket, overflow_attr, getattr(bucket, overflow_attr) + 1)


def _extract_cdx_entries(doc: dict[str, Any]) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    stack: list[tuple[dict[str, Any], int, str]] = []
    seen_nodes = 0
    for key_name, kind in (("services", "service"), ("components", "component")):
        raw = doc.get(key_name)
        if raw is not None and not isinstance(raw, list):
            raise ValueError(f"CycloneDX {key_name} field must be a JSON array")
        if isinstance(raw, list):
            if len(raw) > MAX_FOREIGN_COMPONENTS:
                raise ValueError(
                    f"foreign SBOM exceeds maximum component count ({MAX_FOREIGN_COMPONENTS})"
                )
            stack.extend((item, 0, kind) for item in reversed(raw) if isinstance(item, dict))
    meta = doc.get("metadata")
    if isinstance(meta, dict) and isinstance(meta.get("component"), dict):
        stack.append((meta["component"], 0, "root"))

    allowed_root = {"machine-learning-model", "data", "library", "framework", "container"}
    while stack:
        node, depth, kind = stack.pop()
        seen_nodes += 1
        if seen_nodes > MAX_FOREIGN_COMPONENTS:
            raise ValueError(
                f"foreign SBOM exceeds maximum component count ({MAX_FOREIGN_COMPONENTS})"
            )
        if depth > MAX_NESTED_CDX_DEPTH:
            raise ValueError("CycloneDX nested components exceed maximum depth")
        name = node.get("name")
        if isinstance(name, str) and name.strip():
            nt = node.get("type")
            raw_type = nt if isinstance(nt, str) else "library"
            if kind != "root" or raw_type in allowed_root:
                sha = _find_sha256(node.get("hashes"), "alg", "content")
                sup_obj = (
                    node.get("supplier")
                    if isinstance(node.get("supplier"), dict)
                    else node.get("provider")
                )
                sup = sup_obj.get("name") if isinstance(sup_obj, dict) else None
                k = "service" if kind == "service" else raw_type
                entries.append(
                    _make_entry(node, name, node.get("version"), node.get("purl"), k, sup, sha)
                )
        for key_name, child_kind in (("components", "component"), ("services", "service")):
            children = node.get(key_name)
            if isinstance(children, list):
                if seen_nodes + len(children) > MAX_FOREIGN_COMPONENTS:
                    raise ValueError(
                        f"foreign SBOM exceeds maximum component count ({MAX_FOREIGN_COMPONENTS})"
                    )
                stack.extend(
                    (c, depth + 1, child_kind) for c in reversed(children) if isinstance(c, dict)
                )
    return entries


def _extract_spdx_entries(doc: dict[str, Any]) -> tuple[str, list[dict[str, Any]]]:
    entries: list[dict[str, Any]] = []
    if isinstance(doc.get("@graph"), list):
        ctx, graph = doc.get("@context"), doc["@graph"]
        has_ctx = (isinstance(ctx, str) and "spdx.org/rdf/3." in ctx) or (
            isinstance(ctx, list)
            and any(isinstance(x, str) and "spdx.org/rdf/3." in x for x in ctx)
        )
        if not has_ctx and not any(
            isinstance(n, dict) and ("spdxId" in n or n.get("type") == "CreationInfo")
            for n in graph[:20]
        ):
            raise ValueError("unrecognized SPDX @graph document (missing SPDX 3.x @context/spdxId)")
        if len(graph) > MAX_FOREIGN_COMPONENTS:
            raise ValueError(
                f"foreign SPDX @graph exceeds maximum element count ({MAX_FOREIGN_COMPONENTS})"
            )
        type_map = {
            "ai_AIPackage": "machine-learning-model",
            "dataset_DatasetPackage": "data",
            "software_Package": "library",
        }
        for node in graph:
            if not isinstance(node, dict):
                continue
            kind = node.get("type")
            if kind is not None and not isinstance(kind, str):
                raise ValueError("unsupported SPDX element type (expected a string)")
            if (
                isinstance(kind, str)
                and kind in type_map
                and isinstance(node.get("name"), str)
                and node["name"]
            ):
                sha = _find_sha256(node.get("verifiedUsing"), "algorithm", "hashValue")
                entries.append(
                    _make_entry(
                        node,
                        node["name"],
                        node.get("software_packageVersion"),
                        node.get("software_packageUrl"),
                        type_map[kind],
                        None,
                        sha,
                    )
                )
        return "spdx-3.0.1", entries

    if isinstance(doc.get("packages"), list):
        spdx_ver = doc.get("spdxVersion")
        if not isinstance(spdx_ver, str) or spdx_ver not in _SUPPORTED_SPDX2_VERSIONS:
            raise ValueError(
                "unrecognized SPDX JSON version (expected spdxVersion SPDX-2.2 or SPDX-2.3)"
            )
        packages = doc["packages"]
        if len(packages) > MAX_FOREIGN_COMPONENTS:
            raise ValueError(
                f"foreign SPDX packages exceeds maximum count ({MAX_FOREIGN_COMPONENTS})"
            )
        for pkg in packages:
            if not isinstance(pkg, dict) or not isinstance(pkg.get("name"), str):
                continue
            refs = pkg["externalRefs"] if isinstance(pkg.get("externalRefs"), list) else []
            purl_val = next(
                (
                    r["referenceLocator"]
                    for r in refs
                    if isinstance(r, dict)
                    and r.get("referenceType") == "purl"
                    and isinstance(r.get("referenceLocator"), str)
                ),
                None,
            )
            sha = _find_sha256(pkg.get("checksums"), "algorithm", "checksumValue")
            entries.append(
                _make_entry(
                    pkg, pkg["name"], pkg.get("versionInfo"), purl_val, "library", None, sha
                )
            )
        return spdx_ver.lower(), entries

    raise ValueError("unrecognized foreign SBOM format (expected CycloneDX or SPDX JSON)")


def _digest_index(
    project_root: Path | None, wanted: bool
) -> tuple[dict[str, list[str]], list[str]]:
    by_digest: dict[str, list[str]] = {}
    failures: list[str] = []
    if project_root is None:
        return by_digest, failures
    cap, total = limits.bound("model-bytes"), limits.bound("model-total-bytes")
    with ConfinedCollection(project_root, failures, max_total_bytes=total) as files:
        for rel_path in files.iter_files():
            rel_posix = rel_path.as_posix()
            p = PurePosixPath(rel_posix)
            if p.suffix.lower() not in _ALL_ARTIFACT_EXTS or credential_shaped(rel_posix):
                continue
            if not wanted or any(part.lower() in _HIDDEN_SECRET_DIRS for part in p.parts[:-1]):
                continue
            found = files.regular_file(rel_posix)
            if found is None or found[0] != rel_path or found[1] < 8:
                continue
            if found[1] > cap.value:
                files._fail(rel_posix, f"exceeds {cap.name}; not hashed, so left unbound")
            elif digest := files.hash_file(rel_posix, max_bytes=cap):
                by_digest.setdefault(digest, []).append(rel_posix)
    return by_digest, failures


def _purl_eco(p: str | None) -> str | None:
    return p[4:].split("/", 1)[0].lower() if p and p.startswith("pkg:") and "/" in p else None


def _identity_binding(key: bytes | None, value: str) -> str:
    payload = b"nexus-symbiote/sbom-identity/v1:" + value.encode("utf-8")
    return (
        hmac.digest(key, payload, "sha256").hex()
        if key is not None
        else hashlib.sha256(payload).hexdigest()
    )


def _identity_tokens(
    name: str, purl: str | None, eco: str, key: bytes | None, *, lookup: bool
) -> list[str]:
    scopes = (("*",) if eco == "any" else (eco, "any")) if lookup else (eco, "*")
    values = [
        f"name:{e}:{_norm_pkg(name) if e == 'pypi' else name.strip().casefold()}" for e in scopes
    ]
    if purl:
        try:
            package = PackageURL.from_string(purl)
            identity = PackageURL(
                type=package.type,
                namespace=package.namespace,
                name=package.name,
                qualifiers=package.qualifiers,
                subpath=package.subpath,
            )
            values.append("purl:" + identity.to_string())
        except ValueError:
            pass
    return [_identity_binding(key, v) for v in values]


def _comp_eco(c: AnyComponent) -> str:
    if isinstance(c, (ModelComponent, DataSourceComponent)):
        return "model" if isinstance(c, ModelComponent) else "data"
    if isinstance(c, RegistryEntryComponent):
        rt = (
            c.registry_type.lower()
            if c.registry_type and c.registry_type != "foreign-sbom"
            else None
        )
        return _purl_eco(c.package_url) or rt or "any"
    return "any"


_ENTRY_ECO_MAP = {"machine-learning-model": "model", "data": "data", "service": "cyclonedx-service"}
_KIND_EXT_MAP = {"machine-learning-model": _MODEL_EXTS, "data": _DATA_EXTS}


def _conflict_risk(detail: str, rec: str) -> RiskAssessment:
    return RiskAssessment(
        severity=RiskSeverity.MEDIUM, category="source_conflict", detail=detail, recommendation=rec
    )


def import_foreign_sbom(
    bom_path: Path,
    *,
    target_aibom: AIBOM | None = None,
    project_root: Path | None = None,
    reveal_names: bool = False,
    shareable: bool = False,
) -> SBOMImportSummary:
    """Import a CycloneDX (1.4–1.7) or SPDX (2.2/2.3/3.0.1) JSON BOM as DECLARED evidence."""
    raw_k = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if raw_k and len(raw_k) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise ValueError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least {_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )
    key = raw_k.encode("utf-8") if raw_k else None
    if shareable and (
        key is None or reveal_names or project_root is not None or target_aibom is not None
    ):
        raise ValueError(
            "Shareable supplier export requires a binding key and a standalone hidden-name import"
        )
    with open_regular_file(bom_path) as handle:
        raw_bytes = handle.read(MAX_FOREIGN_SBOM_BYTES + 1)
    if len(raw_bytes) > MAX_FOREIGN_SBOM_BYTES:
        raise ValueError("foreign SBOM exceeds maximum size limit (16 MiB)")

    doc_sha256 = (
        "hmac-sha256:"
        + hmac.digest(key, b"nexus-symbiote/sbom-document/v1:" + raw_bytes, "sha256").hex()
        if shareable and key is not None
        else hash_bytes(raw_bytes)
    )
    parsed = parse_json_strict(raw_bytes, max_bytes=MAX_FOREIGN_SBOM_BYTES)
    if not isinstance(parsed, dict):
        raise ValueError("foreign SBOM must be a JSON object")

    if parsed.get("bomFormat") == "CycloneDX":
        spec_val = parsed.get("specVersion")
        if not isinstance(spec_val, str) or spec_val not in _SUPPORTED_CDX_SPECS:
            raise ValueError("unsupported CycloneDX specVersion (expected 1.4, 1.5, 1.6, or 1.7)")
        source_format, entries = f"cyclonedx-{spec_val}", _extract_cdx_entries(parsed)
    else:
        source_format, entries = _extract_spdx_entries(parsed)

    bom = target_aibom.model_copy(deep=True) if target_aibom is not None else AIBOM()
    hashed = any(e["sha256"] for e in entries)
    digest_index, local_failures = _digest_index(project_root, hashed)
    existing_refs = {c.bom_ref for c in bom.components}
    matches: dict[tuple[str, frozenset[str]], tuple[str | None, bool]] = {}

    buckets: dict[str, _IdentityBucket] = {}
    context = _identity_binding(key, "context")
    incomplete_identity = False
    for existing in bom.components:
        purl = existing.package_url if isinstance(existing, RegistryEntryComponent) else None
        keys_for_existing = _identity_tokens(
            existing.name, purl, _comp_eco(existing), key, lookup=False
        )
        if "imported_source_format" in existing.properties:
            stored = existing.properties.get("identity_bindings")
            if (
                existing.properties.get("identity_context") == context
                and isinstance(stored, list)
                and 1 <= len(stored) <= 3
                and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in stored)
            ):
                keys_for_existing = stored
            elif existing.properties.get("name_hashed"):
                # Old exports preserve only the display pseudonym. It cannot establish
                # that a differently spelled name or versionless PURL did not match.
                incomplete_identity = True
                keys_for_existing = ["legacy:" + existing.name]
        for k in dict.fromkeys(keys_for_existing):
            b = buckets.setdefault(k, _IdentityBucket())
            if existing.version:
                _record_bucket_item(
                    b.versions, existing.version, existing.bom_ref, "extra_version_conflicts", b
                )
            sha = existing.hashes.get("sha256") or existing.properties.get("declared_sha256")
            if isinstance(sha, str) and sha:
                _record_bucket_item(b.digests, sha, existing.bom_ref, "extra_digest_conflicts", b)
            if not existing.bom_ref.startswith("sbom:"):
                b.unmarked_peers.append(existing)

    summary = SBOMImportSummary(
        aibom=bom,
        source_format=source_format,
        document_sha256=doc_sha256,
        scan_failures=list(local_failures),
    )
    clean_cache: dict[str, str] = {}
    safe_short_re = re.compile(r"[0-9A-Za-z.+_-]{1,15}", re.ASCII)

    def _clean_str(val: str) -> str:
        if (cached := clean_cache.get(val)) is not None:
            return cached
        res = val if safe_short_re.fullmatch(val) else neutralize(redact_text(val))
        if len(clean_cache) < 4096:
            clean_cache[val] = res
        return res

    prefix_map = {"machine-learning-model": "sbom:model:", "data": "sbom:data:"}
    for index, entry in enumerate(entries):
        raw_name: str = entry["name"]
        clean_ver = _clean_str(entry["version"])[:128] if entry["version"] else None
        if shareable and clean_ver and not re.fullmatch(r"v?[0-9]+(?:\.[0-9]+){1,3}", clean_ver):
            clean_ver = None
        ref_hash = hashlib.sha256(f"{doc_sha256}:{index}".encode()).hexdigest()[:16]
        comp_ref = f"{prefix_map.get(entry['type'], 'sbom:pkg:')}{ref_hash}"
        if comp_ref in existing_refs:
            continue

        entry_bytes = json.dumps(
            entry["raw_entry"], sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        entry_sha256 = (
            "hmac-sha256:"
            + hmac.new(
                key, b"nexus-symbiote/sbom-entry/v1:" + entry_bytes, hashlib.sha256
            ).hexdigest()
            if key is not None
            else hash_bytes(entry_bytes)
        )
        cleaned_nm = _clean_str(raw_name.strip()) if reveal_names else ""
        if reveal_names and cleaned_nm:
            shown_name, hash_mode = cleaned_nm[:200], "plain"
        elif key is not None:
            nm_hex = hmac.new(
                key, b"nexus-symbiote/sbom-name/v1:" + raw_name.strip().encode(), hashlib.sha256
            ).hexdigest()[:16]
            shown_name, hash_mode = f"imported-{nm_hex}", "hmac-sha256"
        else:
            nm_hex = hashlib.sha256(raw_name.strip().encode()).hexdigest()[:16]
            shown_name, hash_mode = f"imported-{nm_hex}", "unsalted-sha256"
        clean_purl = _clean_str(entry["purl"])[:512] if entry["purl"] else None
        sha256_val: str | None = entry["sha256"]
        eco = _ENTRY_ECO_MAP.get(entry["type"]) or _purl_eco(clean_purl) or "any"
        cand_keys = _identity_tokens(raw_name, entry["purl"], eco, key, lookup=True)
        rec_keys = _identity_tokens(raw_name, entry["purl"], eco, key, lookup=False)
        if incomplete_identity and not reveal_names:
            cand_keys.append("legacy:" + shown_name)

        allowed_exts = _KIND_EXT_MAP.get(entry["type"], _PKG_EXTS)
        bound_target, ambiguous_match = None, False
        if sha256_val:
            match_key = (sha256_val, allowed_exts)
            if match_key not in matches:
                compatible = (
                    path
                    for path in digest_index.get(sha256_val, [])
                    if PurePosixPath(path).suffix.lower() in allowed_exts
                )
                first = next(compatible, None)
                ambiguous = next(compatible, None) is not None
                matches[match_key] = (None if ambiguous else first, ambiguous)
            bound_target, ambiguous_match = matches[match_key]
        if bound_target is not None:
            summary.bound_local_count += 1

        conflict_msgs: list[str] = []
        seen_peer: set[tuple[str, str]] = set()
        overflow = 0
        for k in cand_keys:
            bucket = buckets.setdefault(k, _IdentityBucket())
            if clean_ver:
                for p_ver, p_ref in bucket.versions.items():
                    if (p_ref, "ver") not in seen_peer and _versions_conflict(p_ver, clean_ver):
                        seen_peer.add((p_ref, "ver"))
                        if len(conflict_msgs) < 3:
                            conflict_msgs.append(
                                f"version disagrees with {neutralize(p_ref)} ({_clean_str(p_ver)} vs {clean_ver})"
                            )
                        else:
                            overflow += 1
                overflow += bucket.extra_version_conflicts
            if sha256_val:
                for p_sha, p_ref in bucket.digests.items():
                    if (p_ref, "sha") not in seen_peer and p_sha != sha256_val:
                        seen_peer.add((p_ref, "sha"))
                        if len(conflict_msgs) < 3:
                            conflict_msgs.append(f"digest disagrees with {neutralize(p_ref)}")
                        else:
                            overflow += 1
                overflow += bucket.extra_digest_conflicts

        risks: list[RiskAssessment] = []
        if conflict_msgs:
            summary.conflict_count += 1
            joined = "; ".join(conflict_msgs) + (f" (+{overflow} more)" if overflow > 0 else "")
            if len(summary.conflicts) < MAX_CONFLICT_SUMMARY:
                summary.conflicts.append(f"{comp_ref}: {joined}")
            risks.append(
                _conflict_risk(
                    f"Imported SBOM entry '{shown_name}' conflicts with existing inventory declaration ({neutralize(joined)}); both records are retained.",
                    "Reconcile the supplier SBOM with repository lockfiles and manifests.",
                )
            )
            for k in cand_keys:
                bucket = buckets[k]
                while bucket.unmarked_peers:
                    lp = bucket.unmarked_peers.pop()
                    peer_risks = getattr(lp, "risks", None)
                    if isinstance(peer_risks, list) and not any(
                        r.category == "source_conflict" for r in peer_risks
                    ):
                        peer_risks.append(
                            _conflict_risk(
                                f"Component '{neutralize(redact_text(lp.name))}' conflicts with imported SBOM {doc_sha256[:19]} ({neutralize(joined)}).",
                                "Reconcile repository manifest or lockfile with imported SBOM.",
                            )
                        )

        elif overflow or incomplete_identity:
            summary.unresolved_conflict_count += 1
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="source_conflict_unresolved",
                    detail="Prior package identities or the complete set of versions and digests cannot be reconciled.",
                    recommendation="Reconcile the complete supplier and repository component records.",
                )
            )

        for k in rec_keys:
            bucket = buckets.setdefault(k, _IdentityBucket())
            if clean_ver:
                _record_bucket_item(
                    bucket.versions, clean_ver, comp_ref, "extra_version_conflicts", bucket
                )
            if sha256_val:
                _record_bucket_item(
                    bucket.digests, sha256_val, comp_ref, "extra_digest_conflicts", bucket
                )

        clm = ClaimEvidence(
            assurance=AssuranceLevel.DECLARED,
            method=f"sbom-import:{source_format}",
            scope="external-sbom",
            locator=f"supplier-entry:{index}"
            if shareable
            else f"{neutralize(bom_path.name)}#{index}",
        )
        exact_ver = is_exact_version(clean_ver) or (
            clean_ver is None and purl_has_exact_version(clean_purl)
        )
        props: dict[str, Any] = {
            (
                "imported_document_hmac_sha256" if shareable else "imported_document_sha256"
            ): doc_sha256,
            "identity_bindings": rec_keys,
            "identity_context": context,
            "imported_entry_sha256": entry_sha256,
            "imported_source_format": source_format,
            "name_hashed": not reveal_names,
            "name_hash_mode": hash_mode,
            "pinning_state": "pinned-version" if exact_ver else "unpinned",
        }
        if sha256_val:
            props["declared_sha256"] = sha256_val
        if bound_target is not None:
            props["declared_digest_local_match"] = bound_target

        if ambiguous_match:
            props["declared_digest_local_match_ambiguous"] = True

        sup = (
            neutralize(redact_text(entry["supplier"]))[:200]
            if (reveal_names and entry["supplier"])
            else None
        )
        kw: dict[str, Any] = {
            "bom_ref": comp_ref,
            "name": shown_name,
            "version": clean_ver,
            "assurance_level": AssuranceLevel.DECLARED,
            "trust_tier": TrustTier.UNKNOWN,
            "properties": props,
            "claims": {"imported.sbom": clm},
            "risks": risks,
        }
        if entry["type"] == "machine-learning-model":
            comp: AnyComponent = ModelComponent(supplier=sup, **kw)
        elif entry["type"] == "data":
            comp = DataSourceComponent(supplier=sup, **kw)
        else:
            props["version_pinned"] = exact_ver
            reg_t = eco if eco in {"pypi", "npm", "cyclonedx-service"} else "foreign-sbom"
            comp = RegistryEntryComponent(
                registry_type=reg_t, package_url=clean_purl if reveal_names else None, **kw
            )
        bom.components.append(comp)
        existing_refs.add(comp_ref)
        summary.imported_count += 1

    if bom.metadata.completeness is None:
        unobs = [
            "effective-authorization",
            "effective-identity",
            "filesystem",
            "live-tools",
            "network",
            "runtime",
        ]
        bom.metadata.completeness = CompletenessClaim(
            scope="sbom-imported",
            scan_failures=list(local_failures),
            source_report_status="incomplete",
            source_projection_limitations=[f"foreign-sbom:{source_format}:{doc_sha256}"],
            unobserved_surfaces=unobs,
        )
    elif local_failures:
        for fail in local_failures:
            if fail not in bom.metadata.completeness.scan_failures:
                bom.metadata.completeness.scan_failures.append(fail)
    return summary


def unread_shape_census_with_failures(
    project_root: Path,
) -> tuple[list[UnreadShapeCount], list[str]]:
    failures: list[str] = []
    counts = {"*.ipynb": 0, "n8n/*.json": 0, "*.tf": 0, "Chart.yaml": 0}
    with ConfinedCollection(project_root, failures) as files:
        for rel in files.iter_files():
            posix, name = rel.as_posix(), rel.name
            if name.endswith(".ipynb"):
                counts["*.ipynb"] += 1
            elif name.endswith(".tf"):
                counts["*.tf"] += 1
            elif name == "Chart.yaml":
                counts["Chart.yaml"] += 1
            elif name.endswith(".json") and ("n8n/" in posix or posix.startswith("workflows/")):
                raw = files.read_text(posix, missing_ok=True)
                if raw and '"nodes"' in raw and '"connections"' in raw:
                    counts["n8n/*.json"] += 1
    return [
        UnreadShapeCount(shape=s, count=c) for s, c in sorted(counts.items()) if c > 0
    ], failures


def unread_shape_census(project_root: Path) -> list[UnreadShapeCount]:
    return unread_shape_census_with_failures(project_root)[0]


def _npm_lock_packages(
    files: ConfinedCollection, prefix: str, path_set: set[str], manifest: dict[str, Any]
) -> dict[str, Any]:
    # Workspace layouts and multiple package managers can select a different lock.
    manager = manifest.get("packageManager")
    if (
        manifest.get("workspaces")
        or manifest.get("overrides")
        or (
            manager is not None and (not isinstance(manager, str) or not manager.startswith("npm@"))
        )
        or (
            manager is None
            and any(
                prefix + name in path_set
                for name in ("pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb")
            )
        )
    ):
        return {}
    for name in ("npm-shrinkwrap.json", "package-lock.json"):
        before = files.failures_recorded, files.exclusions_recorded
        raw = files.read_bytes(prefix + name, missing_ok=True)
        if raw is None:
            if (files.failures_recorded, files.exclusions_recorded) != before:
                return {}
            continue
        lock = parse_json_strict(raw, max_bytes=files.max_file_bytes)
        if (
            isinstance(lock, dict)
            and type(lock.get("lockfileVersion")) is int
            and lock["lockfileVersion"] in (2, 3)
        ):
            packages = lock.get("packages")
            if isinstance(packages, dict):
                return packages
        return {}
    return {}


def _enclosing_manifest(rel: str, paths: set[str], filenames: tuple[str, ...]) -> bool:
    return any(
        (parent / name).as_posix() in paths
        for parent in Path(rel).parents[1:]
        for name in filenames
    )


def _direct_toml_lock(
    files: ConfinedCollection, prefix: str, filename: str, project: Any
) -> dict[str, str]:
    if not isinstance(project, str) or not project:
        return {}
    raw = files.read_text(prefix + filename, missing_ok=True)
    if raw is None:
        return {}
    doc = load_toml(raw)
    packages = doc.get("package")
    if not isinstance(packages, list) or not all(isinstance(p, dict) for p in packages):
        return {}
    by_name: dict[str, list[dict[str, Any]]] = {}
    uv = filename == "uv.lock"
    for item in packages:
        name = item.get("name")
        if isinstance(name, str):
            by_name.setdefault(_norm_pkg(name) if uv else name, []).append(item)
    roots = by_name.get(_norm_pkg(project) if uv else project, [])
    if len(roots) != 1:
        return {}
    root = roots[0]
    if uv and root.get("source") not in ({"virtual": "."}, {"editable": "."}):
        return {}
    if not uv and "source" in root:
        return {}
    deps = root.get("dependencies")
    if not isinstance(deps, list):
        return {}
    resolved = {}
    for dep in deps:
        if uv and isinstance(dep, dict) and dep.keys() == {"name"} and isinstance(dep["name"], str):
            name = _norm_pkg(dep["name"])
        elif not uv and isinstance(dep, str):
            name = dep
        else:
            continue
        candidates = by_name.get(name, [])
        if len(candidates) != 1:
            continue
        entry = candidates[0]
        source = entry.get("source")
        if uv:
            if (
                not isinstance(source, dict)
                or source.keys() != {"registry"}
                or not isinstance(source["registry"], str)
            ):
                continue
        elif source != "registry+https://github.com/rust-lang/crates.io-index":
            continue
        if isinstance(entry.get("version"), str):
            resolved[name] = entry["version"]
    return resolved


def _cargo_lock_agrees(spec: str | None, version: str) -> bool:
    # Cargo's bare version is a caret constraint. Only model stable full triples.
    if (
        not spec
        or not re.fullmatch(r"[=^~]?[0-9]+\.[0-9]+\.[0-9]+", spec)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
    ):
        return False
    if spec.startswith("="):
        return spec[1:] == version
    return not _versions_conflict(spec if spec[0] in "^~" else "^" + spec, version)


def _join_continued_lines(text: str) -> list[str]:
    out, buf = [], ""
    for raw_line in text.splitlines():
        code = raw_line.split("#", 1)[0].rstrip()
        if code.endswith("\\"):
            buf += code[:-1] + " "
        else:
            buf += code
            if buf.strip():
                out.append(buf.strip())
            buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out


def _py_req_item(
    raw_req: str, py_locks: dict[str, str] | None = None
) -> tuple[str, str | None, str, str, dict[str, str]] | None:
    try:
        req = Requirement(raw_req)
    except InvalidRequirement:
        return None
    if not _is_ai_package_name(req.name):
        return None
    if (
        py_locks
        and not req.marker
        and not req.url
        and (locked := py_locks.get(_norm_pkg(req.name)))
    ):
        try:
            if req.specifier.contains(Version(locked)):
                return (req.name, locked, "pypi", "locked", {})
        except InvalidVersion:
            pass
    spec_s = str(req.specifier) or None
    st = "pinned-version" if is_exact_version(spec_s) else "manifest-only"
    return (req.name, spec_s, "pypi", st, {})


def _parse_nested_manifest(
    rel_posix: str,
    text: str,
    files: ConfinedCollection,
    path_set: set[str],
) -> list[RegistryEntryComponent]:
    name, parent_dir = Path(rel_posix).name, str(Path(rel_posix).parent)
    prefix = "" if parent_dir == "." else f"{parent_dir}/"
    found: list[tuple[str, str | None, str, str, dict[str, str]]] = []

    if name == "package.json":
        parsed = parse_json_strict(text)
        if isinstance(parsed, dict):
            try:
                npm_locks = _npm_lock_packages(files, prefix, path_set, parsed)
            except (ValueError, RecursionError):
                files._fail(rel_posix, "invalid nested npm lockfile")
                npm_locks = {}
            declared: dict[str, list[tuple[str, str]]] = {}
            # npm loads root dependency edges in this order. A later section wins.
            for section in ("dependencies", "optionalDependencies", "devDependencies"):
                deps = parsed.get(section)
                if isinstance(deps, dict):
                    for pkg_name, spec in deps.items():
                        if (
                            isinstance(pkg_name, str)
                            and isinstance(spec, str)
                            and _is_ai_package_name(pkg_name)
                        ):
                            declared.setdefault(pkg_name, []).append((section, spec.strip()))
            for pkg_name, specs in declared.items():
                spec = specs[-1][1]
                record = npm_locks.get("node_modules/" + pkg_name)
                version = record.get("version") if isinstance(record, dict) else None
                if (
                    isinstance(record, dict)
                    and record.get("link") is not True
                    and record.get("name", pkg_name) == pkg_name
                    and _reg.RegistryScanner._npm_spec(spec)[0] == "registry"
                    and _reg.RegistryScanner._lock_root_agrees(npm_locks, pkg_name, specs)
                    and isinstance(version, str)
                    and len(version) <= 128
                    and _reg._npm_exact(version)
                    and not _versions_conflict(spec, version)
                ):
                    found.append((pkg_name, version, "npm", "locked", {}))
                elif all(item == spec for _, item in specs) and is_exact_version(spec):
                    found.append((pkg_name, spec, "npm", "pinned-version", {}))
                else:
                    found.append((pkg_name, spec, "npm", "manifest-only", {}))
    elif name.startswith("requirements") and name.endswith(".txt"):
        for logical in _join_continued_lines(text):
            if not logical or logical.startswith("-"):
                continue
            sha_matches = _REQ_HASH_RE.findall(logical)
            try:
                req = Requirement(_REQ_OPT_RE.sub(" ", logical).strip())
            except InvalidRequirement:
                continue
            if _is_ai_package_name(req.name):
                spec_str = str(req.specifier) or None
                exact = (
                    len(req.specifier) == 1
                    and next(iter(req.specifier)).operator in {"==", "==="}
                    and "*" not in str(req.specifier)
                )
                hashes = (
                    {"sha256": f"sha256:{sha_matches[0].lower()}"}
                    if (exact and sha_matches)
                    else {}
                )
                st = "digest-pinned" if hashes else ("pinned-version" if exact else "manifest-only")
                found.append((req.name, spec_str, "pypi", st, hashes))
    elif name == "pyproject.toml":
        parsed_toml = load_toml(text)
        proj_section = parsed_toml.get("project")
        uv_settings = parsed_toml.get("tool")
        py_locks = {}
        if (
            isinstance(proj_section, dict)
            and (not isinstance(uv_settings, dict) or "uv" not in uv_settings)
            and prefix + "uv.lock" in path_set
            and prefix + "poetry.lock" not in path_set
            and prefix + "uv.toml" not in path_set
            and not _enclosing_manifest(
                rel_posix, path_set, ("pyproject.toml", "uv.toml", "uv.lock")
            )
        ):
            py_locks = _direct_toml_lock(files, prefix, "uv.lock", proj_section.get("name"))
        proj = parsed_toml.get("project")
        if isinstance(proj, dict) and isinstance(proj.get("dependencies"), list):
            for item in proj["dependencies"]:
                if isinstance(item, str) and (entry := _py_req_item(item, py_locks)):
                    found.append(entry)
    elif name == "setup.cfg":
        parser = configparser.ConfigParser(interpolation=None)
        parser.read_string(text)
        if parser.has_option("options", "install_requires"):
            for line in parser.get("options", "install_requires").splitlines():
                if line.strip() and (entry := _py_req_item(line.strip())):
                    found.append(entry)
    elif name == "Cargo.toml":
        parsed_cargo = load_toml(text)
        manifest_package = parsed_cargo.get("package")
        cargo_locks = {}
        if (
            isinstance(manifest_package, dict)
            and not {"workspace", "patch", "replace"} & parsed_cargo.keys()
            and prefix + "Cargo.lock" in path_set
            and not _enclosing_manifest(
                rel_posix,
                path_set,
                ("Cargo.toml", "Cargo.lock", ".cargo/config.toml", ".cargo/config"),
            )
            and not any(
                prefix + name in path_set for name in (".cargo/config.toml", ".cargo/config")
            )
        ):
            cargo_locks = _direct_toml_lock(
                files, prefix, "Cargo.lock", manifest_package.get("name")
            )
        for sec in ("dependencies", "dev-dependencies"):
            deps = parsed_cargo.get(sec)
            if isinstance(deps, dict):
                for crate, spec in deps.items():
                    if isinstance(crate, str) and _is_ai_package_name(crate):
                        raw_v = (
                            spec
                            if isinstance(spec, str)
                            else (spec.get("version") if isinstance(spec, dict) else None)
                        )
                        ver = raw_v if isinstance(raw_v, str) else None
                        lv = cargo_locks.get(crate)
                        if (
                            not lv
                            or not _cargo_lock_agrees(ver, lv)
                            or isinstance(spec, dict)
                            and not spec.keys()
                            <= {"version", "features", "optional", "default-features"}
                        ):
                            lv = None
                        found.append(
                            (crate, lv or ver, "cargo", "locked" if lv else "manifest-only", {})
                        )
    elif name == "go.mod":
        in_require = False
        for line in text.splitlines():
            parts = line.split("//", 1)[0].strip().split()
            if parts == ["require", "("]:
                in_require = True
                continue
            if parts == [")"]:
                in_require = False
                continue
            if len(parts) == 3 and parts[0] == "require":
                parts = parts[1:]
            elif not (in_require and len(parts) == 2):
                continue
            module, version = parts
            if _is_ai_package_name(module):
                # go.mod records minimum versions; go.sum is a checksum list.
                found.append((module, version, "golang", "manifest-only", {}))
    elif name in _CONDA_NAMES:
        if len(text.encode("utf-8")) > MAX_MANIFEST_YAML_BYTES:
            raise ValueError("conda manifest exceeds size limit")
        parsed_conda = parse_yaml_mapping(text, max_nodes=4096)
        if isinstance(parsed_conda.get("dependencies"), list):
            for dep in parsed_conda["dependencies"]:
                if isinstance(dep, str):
                    pkg, _, ver = dep.partition("=")
                    if _is_ai_package_name(pkg):
                        found.append(
                            (pkg.strip(), ver.strip() or None, "conda", "manifest-only", {})
                        )
    elif name in {"devcontainer.json", ".devcontainer.json"}:
        parsed_dev = parse_json_strict(text)
        if isinstance(parsed_dev, dict) and isinstance(parsed_dev.get("image"), str):
            img = parsed_dev["image"].strip()
            if _is_ai_package_name(img):
                st = (
                    "digest-pinned"
                    if re.fullmatch(r"[^@\s]+@sha256:[0-9a-f]{64}", img)
                    else "manifest-only"
                )
                found.append((img, None, "oci", st, {}))

    out: list[RegistryEntryComponent] = []
    for pkg_name, spec, ecosystem, pin_state, hashes in found:
        clean_ver = spec.lstrip("=") if spec and spec.startswith("==") else spec
        exact = is_exact_version(clean_ver) or pin_state == "digest-pinned"
        ref_id = hashlib.sha256(f"{rel_posix}:{ecosystem}:{pkg_name}".encode()).hexdigest()[:16]
        nested_props: dict[str, Any] = {
            "manifest_path": rel_posix,
            "pinning_state": pin_state,
            "version_pinned": exact and pin_state != "manifest-only",
        }
        if hashes.get("sha256"):
            nested_props["declared_sha256"] = hashes["sha256"]
        clm = ClaimEvidence(
            assurance=AssuranceLevel.DECLARED,
            method="nested-manifest-walk",
            scope="nested-manifest",
            collector="registry",
            locator=rel_posix,
        )
        ver_out = neutralize(redact_text(clean_ver))[:128] if clean_ver else None
        out.append(
            RegistryEntryComponent(
                bom_ref=f"registry:nested:{ref_id}",
                name=neutralize(redact_text(pkg_name))[:200],
                version=ver_out,
                registry_type=ecosystem,
                assurance_level=AssuranceLevel.DECLARED,
                trust_tier=TrustTier.UNKNOWN,
                properties=nested_props,
                claims={"manifest": clm},
            )
        )
    return out


def walk_nested_manifests(project_root: Path) -> tuple[list[RegistryEntryComponent], list[str]]:
    failures: list[str] = []
    components: list[RegistryEntryComponent] = []
    with ConfinedCollection(project_root, failures) as files:
        all_paths = [p.as_posix() for p in files.iter_files()]
        path_set = set(all_paths)
        for posix in all_paths:
            rel = Path(posix)
            is_root, name = rel.parent == Path("."), rel.name
            is_req = name.startswith("requirements") and name.endswith(".txt")
            if is_root and (name in {"package.json", "pyproject.toml"} or is_req):
                continue
            is_dev = (
                posix.endswith(".devcontainer/devcontainer.json") or posix == ".devcontainer.json"
            )
            if not (name in _NESTED_MANIFEST_NAMES or is_req or is_dev):
                continue
            if (text := files.read_text(posix, missing_ok=True)) is not None:
                try:
                    components.extend(_parse_nested_manifest(posix, text, files, path_set))
                except (ValueError, PolicyError, configparser.Error, RecursionError) as exc:
                    failures.append(
                        f"{neutralize(posix)}: manifest parse failed ({type(exc).__name__})"
                    )
    return components, failures


def classify_pinning_state(aibom: AIBOM, *, only_refs: set[str] | None = None) -> dict[str, str]:
    states: dict[str, str] = {}
    for comp in aibom.components:
        if isinstance(comp.properties.get("pinning_state"), str):
            states[comp.bom_ref] = comp.properties["pinning_state"]
            continue
        if only_refs is not None and comp.bom_ref not in only_refs:
            continue
        if isinstance(comp, RegistryEntryComponent):
            exact_ver = is_exact_version(comp.version) or purl_has_exact_version(comp.package_url)
            if comp.hashes and exact_ver:
                state = "locked"
            elif exact_ver or (
                comp.properties.get("version_pinned") is True and comp.version is None
            ):
                state = "pinned-version"
            else:
                state = "manifest-only"
            comp.properties["pinning_state"] = state
            states[comp.bom_ref] = state
        elif isinstance(comp, MCPServerComponent):
            state = (
                "digest-pinned"
                if comp.hashes
                else ("pinned-version" if comp.version_pinned else "unpinned")
            )
            comp.properties["pinning_state"] = state
            states[comp.bom_ref] = state
    return states
