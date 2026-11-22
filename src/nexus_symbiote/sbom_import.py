"""Foreign SBOM import, nested manifest walker, pinning_state, and unread_shapes census (R1.2-2)."""

from __future__ import annotations

import configparser
import hashlib
import hmac
import json
import operator
import os
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any, Final, TypeVar
from urllib.parse import quote, unquote, urlsplit, urlunsplit

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
from nexus_symbiote.offline_advisories import _semver_key
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.scanners import registry as _reg
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.mcp import _MIN_SOURCE_BINDING_KEY_LENGTH, SOURCE_BINDING_KEY_ENV
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text, secret_like
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.utils.toml import loads as load_toml

MAX_FOREIGN_SBOM_BYTES: Final[int] = 16 * 1024 * 1024
MAX_FOREIGN_COMPONENTS: Final[int] = 10_000
MAX_NESTED_CDX_DEPTH: Final[int] = 32
MAX_MANIFEST_YAML_BYTES: Final[int] = 512 * 1024
MAX_CONFLICT_SAMPLES: Final[int] = 8
MAX_CONFLICT_SUMMARY: Final[int] = 200
MAX_IDENTITY_BINDINGS: Final[int] = 7
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
    versions: dict[tuple[str | None, str], str] = field(default_factory=dict)
    digests: dict[str, str] = field(default_factory=dict)
    extra_version_conflicts: int = 0
    extra_digest_conflicts: int = 0
    unmarked_peers: list[AnyComponent] = field(default_factory=list)
    provenance_ids: set[str] = field(default_factory=set)
    matched_lock_ids: set[str] | None = None
    has_unspecified_provenance: bool = False
    has_unknown_qualifiers: bool = False
    has_ambiguous_provenance: bool = False
    has_unverified_redirect: bool = False


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
        if m.group(3) is None:
            return ">=0.0.0,<1.0.0"
        if min_i > 0 or m.group(4) is None:
            return f">=0.{min_i}.{pat_i},<0.{min_i + 1}.0"
        return f"==0.0.{pat_i}"
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


def _nested_version_ecosystem(component: AnyComponent) -> str | None:
    """Find declarations whose version grammar depends on the package manager."""
    if (
        not isinstance(component, RegistryEntryComponent)
        or not component.properties.get("manifest_path")
        or component.properties.get("pinning_state") != "manifest-only"
    ):
        return None
    return component.registry_type if component.registry_type in {"conda", "cargo", "npm"} else None


_VersionKey = tuple[int, int, int, int, tuple[tuple[int, int | str], ...]]
_VersionCore = tuple[int, int, int]
_SemverBounds = tuple[tuple[str, _VersionKey], ...]
_SemverGroup = tuple[_SemverBounds, frozenset[_VersionCore]]
_WILDCARDS = frozenset({"x", "X", "*"})
_VERSION_COMPARATORS = {
    "<": operator.lt,
    "<=": operator.le,
    ">": operator.gt,
    ">=": operator.ge,
    "==": operator.eq,
    "!=": operator.ne,
}
_SEMVER_TERM = re.compile(
    r"(\^|~|<=|>=|==|=|<|>)?(v?(?:0|[1-9][0-9]*|[xX*])"
    r"(?:\.(?:0|[1-9][0-9]*|[xX*])){0,2})"
    r"(-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


@lru_cache(maxsize=512)
def _semver_parts(raw: str) -> tuple[str, _VersionKey, int, bool] | None:
    match = _SEMVER_TERM.fullmatch(raw)
    if match is None:
        return None
    operation, core, prerelease = match.groups()
    pieces = core.removeprefix("v").split(".")
    size = next((i for i, part in enumerate(pieces) if part in _WILDCARDS), len(pieces))
    wildcard = size < len(pieces)
    if any(piece not in _WILDCARDS for piece in pieces[size:]):
        return None
    if prerelease and (
        size != 3
        or any(
            identifier.isdecimal() and len(identifier) > 1 and identifier.startswith("0")
            for identifier in prerelease[1:].split(".")
        )
    ):
        return None
    literal = ".".join([*pieces[:size], *(["0"] * (3 - size))])
    parsed = _semver_key(literal + (prerelease or ""))
    assert parsed is not None
    return operation or "", parsed, size, wildcard


def _bump_semver(version: _VersionKey, position: int) -> _VersionKey:
    parts = [version[0], version[1], version[2]]
    parts[position] += 1
    parts[position + 1 :] = [0] * (2 - position)
    return (parts[0], parts[1], parts[2], 0, ((0, 0),))


def _semver_bounds(operation: str, version: _VersionKey, precision: int) -> _SemverBounds:
    if precision == 0:
        return ()
    if operation in {"^", "~"}:
        if operation == "^":
            position = next((i for i in range(precision) if version[i]), precision - 1)
        else:
            position = min(1, precision - 1)
        return ((">=", version), ("<", _bump_semver(version, position)))
    if precision == 3:
        return (((operation if operation in {">", ">=", "<", "<="} else "=="), version),)
    upper = _bump_semver(version, precision - 1)
    if operation == ">":
        return ((">=", (*upper[:3], 1, ())),)
    if operation == "<=":
        return (("<", upper),)
    if operation in {">=", "<"}:
        boundary = (*version[:3], 0, ((0, 0),)) if operation == "<" else version
        return ((operation, boundary),)
    return ((">=", version), ("<", upper))


@lru_cache(maxsize=512)
def _semver_requirements(ecosystem: str, raw: str) -> tuple[_SemverGroup, ...] | None:
    if not raw.strip() or len(raw) > 128:
        return None
    npm = ecosystem == "npm"
    alternatives = raw.split("||") if npm else [raw]
    parsed: list[_SemverGroup] = []
    for form in alternatives:
        hyphen = re.fullmatch(r"(\S+)\s+-\s+(\S+)", form.strip()) if npm else None
        if hyphen:
            terms = [">=" + hyphen[1], "<=" + hyphen[2]]
        elif npm:
            terms = re.sub(r"(?<=[<>=~^])\s+", "", form).split()
        else:
            terms = [re.sub(r"(?<=[<>=~^])\s+", "", term.strip()) for term in form.split(",")]
        bounds: list[tuple[str, _VersionKey]] = []
        pre_cores: set[_VersionCore] = set()
        for term in terms:
            info = _semver_parts(term)
            if info is None:
                return None
            operation, version, precision, wildcard = info
            if not precision and operation not in {"", "=", "=="}:
                return None
            if not npm and not operation and not wildcard:
                operation = "^"
            if version[3] == 0:
                pre_cores.add(version[:3])
            bounds.extend(_semver_bounds(operation, version, precision))
        parsed.append((tuple(bounds), frozenset(pre_cores)))
    return tuple(parsed)


_CondaTerms = tuple[tuple[str, Version], ...]


@lru_cache(maxsize=512)
def _conda_requirement(raw: str) -> tuple[_CondaTerms, bool] | None:
    if not raw.strip() or len(raw) > 128:
        return None
    text = raw.strip()
    build = re.fullmatch(r"(={0,2}[0-9][^=,|]*)=([A-Za-z0-9_.+*?-]+)", text)
    if build is None:
        build = re.fullmatch(r"([0-9]\S*)\s+([A-Za-z0-9_.+*?-]+)", text)
    if build:
        text = build[1]
        if text.startswith("=") and not text.startswith("==") and not text.endswith("*"):
            text = "=" + text
    comparisons: list[tuple[str, Version]] = []
    for term in text.split(","):
        match = re.fullmatch(r"(<=|>=|==|!=|=|<|>)?\s*([0-9]\S*)", term.strip())
        if match is None:
            return None
        operation, literal = match[1] or "==", match[2]
        if operation == "=" or literal.endswith("*"):
            if operation not in {"=", "==", "!="}:
                return None
            if literal.endswith("*"):
                literal = literal[:-1].removesuffix(".")
            if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)*", literal):
                return None
            operation = "not-prefix" if operation == "!=" else "prefix"
        try:
            comparisons.append((operation, Version(literal)))
        except InvalidVersion:
            return None
    return tuple(comparisons), build is not None


def _satisfies_conda_requirement(requirement: str, version: str) -> bool | None:
    parsed = _conda_requirement(requirement)
    if parsed is None:
        return None
    try:
        installed = Version(version)
    except InvalidVersion:
        return None
    comparisons, has_build = parsed
    for operation, boundary in comparisons:
        if operation in {"prefix", "not-prefix"}:
            width = len(boundary.release)
            prefix = (installed.release + (0,) * width)[:width]
            matched = prefix == boundary.release and installed.epoch == boundary.epoch
            if matched != (operation == "prefix"):
                return False
        elif not _VERSION_COMPARATORS[operation](installed, boundary):
            return False
    # A version can rule out a version-and-build pin. It cannot confirm the build.
    return None if has_build else True


def _satisfies_nested_requirement(ecosystem: str, requirement: str, version: str) -> bool | None:
    if not version or len(version) > 128:
        return None
    if ecosystem == "conda":
        return _satisfies_conda_requirement(requirement, version)
    alternatives = _semver_requirements(ecosystem, requirement)
    info = _semver_parts(version.strip())
    if alternatives is None or info is None:
        return None
    operation, installed, precision, wildcard = info
    if operation or precision != 3 or wildcard:
        return None
    return any(
        (installed[3] == 1 or installed[:3] in allowed_pre)
        and all(_VERSION_COMPARATORS[comparison](installed, bound) for comparison, bound in terms)
        for terms, allowed_pre in alternatives
    )


_BucketKey = TypeVar("_BucketKey", str, tuple[str | None, str])


def _record_bucket_item(
    mapping: dict[_BucketKey, str],
    key: _BucketKey,
    ref: str,
    overflow_attr: str,
    bucket: _IdentityBucket,
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


_PURL_METADATA_QUALIFIERS = frozenset(
    {"arch", "checksum", "download_url", "file_name", "tag", "vcs_url"}
)


def _repository_identity(value: str, ecosystem: str | None) -> str:
    if not value.isascii() or "\\" in value or any(ch <= " " or ch == "\x7f" for ch in value):
        return value
    try:
        parts = urlsplit(value)
        port = parts.port
    except ValueError:
        return value
    default_port = {"http": 80, "https": 443}.get(parts.scheme)
    if default_port is None or not parts.hostname or parts.username is not None:
        return value
    host = parts.hostname
    if ":" in host:
        host = f"[{host}]"
    if port is not None and port != default_port:
        host += f":{port}"
    url = urlunsplit((parts.scheme, host, parts.path.rstrip("/"), parts.query, parts.fragment))
    if ecosystem == "npm" and _reg._DEFAULT_NPM_REGISTRY.fullmatch(url):
        return "https://registry.npmjs.org"
    if ecosystem == "pypi" and (
        url in _reg._PYPI_ORIGINS or _reg._DEFAULT_PYPI_INDEX.fullmatch(url)
    ):
        return _reg._PYPI_ORIGIN
    return url


@dataclass(frozen=True)
class _PurlIdentity:
    stem: str
    identity: str
    qualified: bool
    unknown_qualifiers: bool
    version: str | None = None
    repository: str | None = None

    @property
    def ambiguous(self) -> bool:
        return self.unknown_qualifiers and not self.qualified


def _purl_identity(purl: str | None, *, lock_origin: str | None = None) -> _PurlIdentity | None:
    if not purl:
        return None
    path, _, query = purl.partition("#")[0].partition("?")
    keys: set[str] = set()
    ambiguous = False
    if query:
        for field in query.split("&"):
            key, equals, value = field.partition("=")
            key = key.strip().lower()
            if not key or not equals or not value.strip() or key in keys:
                ambiguous = True
                break
            keys.add(key)
    try:
        package = PackageURL.from_string(path if ambiguous else purl)
    except ValueError:
        ambiguous = True
        try:
            package = PackageURL.from_string(path)
        except ValueError:
            parent, separator, name = path.rpartition("/")
            stem = (parent + separator + name.partition("@")[0]).lower()
            return _PurlIdentity(stem, stem, False, True)
    stem = PackageURL(type=package.type, namespace=package.namespace, name=package.name).to_string()
    if ambiguous:
        return _PurlIdentity(stem, stem, False, True, package.version)
    qualifiers = {
        name: _repository_identity(value, package.type) if name == "repository_url" else value
        for name, value in (package.qualifiers or {}).items()
        if name not in _PURL_METADATA_QUALIFIERS
    }
    if lock_origin and package.type in {"npm", "pypi"}:
        qualifiers.setdefault("repository_url", _repository_identity(lock_origin, package.type))
    identity = PackageURL(
        type=package.type, namespace=package.namespace, name=package.name, qualifiers=qualifiers
    ).to_string()
    return _PurlIdentity(
        stem,
        identity,
        bool(qualifiers),
        bool(qualifiers.keys() - {"repository_url"}),
        package.version,
        qualifiers.get("repository_url"),
    )


def _public_purl_value(value: str, *, locator: bool = False) -> bool:
    for _ in range(4):
        decoded = unquote(value)
        if decoded == value:
            if locator or "://" in value:
                try:
                    url = value if "://" in value or value.startswith("//") else "//" + value
                    if urlsplit(url).username is not None:
                        return False
                except ValueError:
                    return False
            return redact_text(value) == value
        value = decoded
    return False


def _display_purl(raw: str | None) -> str | None:
    """Keep locator credentials out of the displayed PURL without changing its identity."""
    if not raw:
        return None
    try:
        package = PackageURL.from_string(raw)
    except ValueError:
        return raw if _public_purl_value(raw) else None
    if not all(
        _public_purl_value(value)
        for value in (package.namespace, package.name, package.version, package.subpath)
        if value
    ):
        return None
    qualifiers = package.qualifiers or {}
    public = {
        key: value
        for key, value in qualifiers.items()
        if not secret_like(key, value)
        and _public_purl_value(value, locator=key in {"repository_url", "download_url", "vcs_url"})
    }
    if public == qualifiers:
        return raw
    return PackageURL(
        type=package.type,
        namespace=package.namespace,
        name=package.name,
        version=package.version,
        qualifiers=public,
        subpath=package.subpath,
    ).to_string()


def _identity_tokens(
    name: str, purl: _PurlIdentity | None, eco: str, key: bytes | None, *, lookup: bool
) -> list[str]:
    scopes = (("*",) if eco == "any" else (eco, "any")) if lookup else (eco, "*")
    values = [
        f"name:{e}:{_norm_pkg(name) if e == 'pypi' else name.strip().casefold()}" for e in scopes
    ]
    if eco in {"pypi", "any"}:
        # Ecosystem-free records can name a PyPI package with its original separators.
        values.extend(f"pypi-name:{e}:{_norm_pkg(name)}" for e in scopes if e in {"*", "any"})
    if purl is not None:
        values.append("purl:" + purl.identity)
        suffix = "qualified" if purl.qualified != lookup else "unspecified"
        values.append(f"purl-{suffix}:{purl.stem}")
        # A common package may still have different registries or qualifiers.
        values.append("purl-base:" + purl.stem)
    return [_identity_binding(key, v) for v in values]


_Provenance = tuple[str, str | None, bool]


def _purl_provenance(purl: _PurlIdentity | None, key: bytes | None) -> _Provenance | None:
    if purl is None:
        return None
    base = _identity_binding(key, "purl-base:" + purl.stem)
    qualified = (
        _identity_binding(key, "purl-provenance:" + purl.identity) if purl.qualified else None
    )
    return base, qualified, purl.unknown_qualifiers


def _legacy_public_registries(
    suppliers: list[_PurlIdentity | None], key: bytes | None
) -> dict[str, str]:
    """Recognize an older hidden inventory that bound a public registry's other spelling."""
    aliases = {
        "https://registry.npmjs.org": ("https://registry.yarnpkg.com",),
        _reg._PYPI_ORIGIN: ("https://files.pythonhosted.org", "https://pypi.org/simple"),
    }
    bindings: dict[str, str] = {}
    for purl in suppliers:
        if purl is None or not purl.repository or purl.repository not in aliases:
            continue
        package = PackageURL.from_string(purl.identity)
        if (package.type, purl.repository) not in {
            ("npm", "https://registry.npmjs.org"),
            ("pypi", _reg._PYPI_ORIGIN),
        }:
            continue
        canonical = _identity_binding(key, "purl-provenance:" + purl.identity)
        for alias in aliases[purl.repository]:
            old = PackageURL(
                type=package.type,
                namespace=package.namespace,
                name=package.name,
                qualifiers={**(package.qualifiers or {}), "repository_url": alias},
            )
            bindings[_identity_binding(key, "purl-provenance:" + old.to_string())] = canonical
    return bindings


def _selected_repository_url(comp: RegistryEntryComponent, lock: dict[str, Any]) -> str | None:
    """Recover the repository of the exact recorded package, solely for comparison."""
    source = comp.source_path
    locator = comp.properties.get("lockfile_record")
    if not isinstance(locator, str) or not source or not comp.version:
        return None
    if source in _reg.RegistryScanner._NPM_LOCKFILES:
        packages = lock.get("packages")
        key = comp.properties.get("npm_alias", comp.name)
        if not isinstance(key, str) or not isinstance(packages, dict):
            return None
        if locator != source + "#/packages/" + _reg._pointer_token("node_modules/" + key):
            return None
        row = packages.get("node_modules/" + key)
        if (
            not isinstance(row, dict)
            or row.get("name", key) != comp.name
            or row.get("version") != comp.version
        ):
            return None
        url = row.get("resolved")
        if not isinstance(url, str) or _reg._index_origin(url) is None:
            return None
        parts = urlsplit(url)
        directory, separator, archive = parts.path.rpartition("/-/")
        if not separator or archive != f"{comp.name.rsplit('/', 1)[-1]}-{comp.version}.tgz":
            return None
        for spelling in (comp.name, quote(comp.name, safe="@")):
            package_dir = "/" + spelling
            if directory.endswith(package_dir):
                return urlunsplit(parts._replace(path=directory.removesuffix(package_dir)))
        return None
    entries = lock.get("package")
    prefix = source + "#/package/"
    if not locator.startswith(prefix):
        return None
    slot = locator.removeprefix(prefix)
    if (
        not isinstance(entries, list)
        or not re.fullmatch(r"[0-9]{1,8}", slot)
        or int(slot) >= len(entries)
    ):
        return None
    row = entries[int(slot)]
    if not isinstance(row, dict) or not isinstance(row.get("name"), str):
        return None
    if _norm_pkg(row["name"]) != _norm_pkg(comp.name) or row.get("version") != comp.version:
        return None
    metadata = row.get("source")
    if not isinstance(metadata, dict):
        return None
    value = metadata.get("registry" if source == "uv.lock" else "url")
    return value if isinstance(value, str) else None


def _plain_repository_path(url: str) -> bool:
    if _reg._index_origin(url) is None:
        return False
    parts = urlsplit(url)
    return (
        parts.username is None
        and not parts.query
        and not parts.fragment
        and bool(parts.path.strip("/"))
        and "//" not in parts.path
        and all(
            part not in {".", ".."} and re.fullmatch(r"[A-Za-z0-9._~+-]+", part) is not None
            for part in parts.path.strip("/").split("/")
        )
    )


def _matched_lock_repositories(
    root: Path | None,
    components: list[AnyComponent],
    suppliers: list[_PurlIdentity | None],
    key: bytes | None,
    failures: list[str],
) -> dict[int, str]:
    """Allow a specific supplier path only when the same lock bytes and package name it."""
    wanted = {
        (p.stem, p.repository): _identity_binding(key, "purl-provenance:" + p.identity)
        for p in suppliers
        if p and p.repository and not p.unknown_qualifiers and _plain_repository_path(p.repository)
    }
    if root is None or not wanted:
        return {}
    wanted_stems = {stem for stem, _ in wanted}
    names = {"uv.lock", "poetry.lock", *_reg.RegistryScanner._NPM_LOCKFILES}
    pending: dict[str, list[tuple[RegistryEntryComponent, _PurlIdentity, str]]] = {}
    for comp in components:
        if not isinstance(comp, RegistryEntryComponent) or comp.source_path not in names:
            continue
        if "imported_source_format" in comp.properties:
            continue
        if comp.registry_type != (
            "npm" if comp.source_path in _reg.RegistryScanner._NPM_LOCKFILES else "pypi"
        ):
            continue
        if (
            comp.properties.get("collection_mode") != "lockfile-resolution-claim"
            or not comp.registry_uri
        ):
            continue
        digest = comp.properties.get("lockfile_sha256")
        purl = _purl_identity(comp.package_url, lock_origin=comp.registry_uri)
        if (
            purl
            and purl.stem in wanted_stems
            and not purl.unknown_qualifiers
            and purl.repository == _repository_identity(comp.registry_uri, comp.registry_type)
            and isinstance(digest, str)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", digest)
        ):
            pending.setdefault(comp.source_path, []).append((comp, purl, digest))
    matches: dict[int, str] = {}
    with ConfinedCollection(root, failures) as files:
        for name, records in pending.items():
            try:
                # Lock corroboration never follows a link, including a replaced
                # leaf between inventory collection and this later import.
                with files.open_regular(name) as stream:
                    raw = b"".join(iter(lambda: stream.read(128 * 1024), b""))
            except OSError:
                continue
            digest = hash_bytes(raw)
            recorded = [(comp, p) for comp, p, expected in records if expected == digest]
            if not recorded:
                continue
            try:
                doc = (
                    parse_json_strict(raw, max_bytes=files.max_file_bytes)
                    if name in _reg.RegistryScanner._NPM_LOCKFILES
                    else load_toml(raw.decode("utf-8"))
                )
            except (ValueError, RecursionError):
                continue
            if not isinstance(doc, dict):
                continue
            for comp, purl in recorded:
                url = _selected_repository_url(comp, doc)
                if url and _plain_repository_path(url):
                    canonical = _repository_identity(url, comp.registry_type)
                    if (
                        _repository_identity(_reg._index_origin(url) or "", comp.registry_type)
                        == purl.repository
                        and (matched := wanted.get((purl.stem, canonical))) is not None
                    ):
                        matches[id(comp)] = matched
    return matches


def _stored_provenance(value: object, bindings: list[str]) -> _Provenance | None:
    if not isinstance(value, list) or len(value) != 3:
        return None
    base, qualified, unknown = value
    if (
        not isinstance(base, str)
        or base not in bindings
        or (
            qualified is not None
            and (not isinstance(qualified, str) or not re.fullmatch(r"[0-9a-f]{64}", qualified))
        )
        or not isinstance(unknown, bool)
    ):
        return None
    return base, qualified, unknown


def _record_provenance(
    buckets: dict[str, _IdentityBucket], record: _Provenance | None, matched_lock: str | None = None
) -> None:
    if record is None:
        return
    base, qualified, unknown = record
    bucket = buckets.setdefault(base, _IdentityBucket())
    if qualified is None:
        bucket.has_unspecified_provenance = True
        bucket.has_ambiguous_provenance |= unknown
    elif matched_lock is not None:
        allowed = {qualified, matched_lock}
        if bucket.matched_lock_ids is None:
            bucket.matched_lock_ids = allowed
        else:
            bucket.matched_lock_ids.intersection_update(allowed)
    elif len(bucket.provenance_ids) < 2:
        # Two distinct values suffice to detect disagreement with any qualifier.
        bucket.provenance_ids.add(qualified)
    bucket.has_unknown_qualifiers |= unknown


def _provenance_disagrees(
    buckets: dict[str, _IdentityBucket], candidate: _Provenance | None
) -> bool:
    if candidate is None:
        return False
    base, qualified, unknown = candidate
    bucket = buckets.get(base)
    if bucket is None:
        return False
    if bucket.has_unverified_redirect and (qualified is not None or unknown):
        return True
    if bucket.has_ambiguous_provenance or (qualified is None and unknown):
        return True
    if qualified is None:
        return bucket.has_unknown_qualifiers
    if bucket.matched_lock_ids is not None and qualified not in bucket.matched_lock_ids:
        return True
    return any(peer != qualified for peer in bucket.provenance_ids) or (
        unknown and bucket.has_unspecified_provenance
    )


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
    supplier_purls = [_purl_identity(entry["purl"]) for entry in entries]
    public_aliases = _legacy_public_registries(supplier_purls, key)
    matched_locks = _matched_lock_repositories(
        project_root, bom.components, supplier_purls, key, local_failures
    )
    context = _identity_binding(key, "context-v4")
    incomplete_identity = False
    for existing in bom.components:
        lock_origin = (
            existing.registry_uri
            if isinstance(existing, RegistryEntryComponent)
            and existing.properties.get("collection_mode") == "lockfile-resolution-claim"
            else None
        )
        purl = _purl_identity(
            existing.package_url if isinstance(existing, RegistryEntryComponent) else None,
            lock_origin=lock_origin,
        )
        provenance = _purl_provenance(purl, key)
        keys_for_existing = _identity_tokens(
            existing.name, purl, _comp_eco(existing), key, lookup=False
        )
        if "imported_source_format" in existing.properties:
            stored = existing.properties.get("identity_bindings")
            if (
                existing.properties.get("identity_context") == context
                and isinstance(stored, list)
                and 1 <= len(stored) <= MAX_IDENTITY_BINDINGS
                and all(isinstance(v, str) and re.fullmatch(r"[0-9a-f]{64}", v) for v in stored)
            ):
                keys_for_existing = stored
                provenance = _stored_provenance(existing.properties.get("purl_provenance"), stored)
                if provenance and provenance[1] in public_aliases:
                    base_id, old_id, unknown = provenance
                    assert old_id is not None
                    provenance = (base_id, public_aliases[old_id], unknown)
            elif existing.properties.get("name_hashed"):
                # Old exports preserve only the display pseudonym. It cannot establish
                # that a differently spelled name or versionless PURL did not match.
                incomplete_identity = True
                keys_for_existing = ["legacy:" + existing.name]
                provenance = None
        if (
            isinstance(existing, RegistryEntryComponent)
            and existing.registry_type in {"npm", "pypi"}
            and not existing.package_url
            and existing.properties.get("package_sources")
            and "imported_source_format" not in existing.properties
        ):
            # The scanner withheld the installed identity because settings can redirect
            # it. Match the ecosystem and name for this uncertainty only. A saved lock
            # URL does not establish which configured registry supplied the package.
            safe = "/" if existing.registry_type == "npm" else ""
            raw = f"pkg:{existing.registry_type}/{quote(existing.name, safe=safe)}"
            record = _purl_provenance(_purl_identity(raw), key)
            if record is not None:
                buckets.setdefault(record[0], _IdentityBucket()).has_unverified_redirect = True
        _record_provenance(buckets, provenance, matched_locks.get(id(existing)))
        version_ecosystem = _nested_version_ecosystem(existing)
        comparison_version = existing.version or (purl.version if purl is not None else None)
        if version_ecosystem == "conda" and comparison_version:
            declared = existing.properties.get("manifest_version_specifier")
            if isinstance(declared, str):
                comparison_version = declared
            elif re.fullmatch(r"=?[0-9]+(?:\.[0-9]+){0,2}", comparison_version):
                # Earlier Conda inventories dropped the first equals sign.
                comparison_version = "=" + comparison_version
        for k in dict.fromkeys(keys_for_existing):
            b = buckets.setdefault(k, _IdentityBucket())
            if comparison_version:
                _record_bucket_item(
                    b.versions,
                    (version_ecosystem, comparison_version),
                    existing.bom_ref,
                    "extra_version_conflicts",
                    b,
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
    for index, (entry, purl) in enumerate(zip(entries, supplier_purls, strict=True)):
        raw_name: str = entry["name"]
        raw_version = entry["version"] or (purl.version if purl is not None else None)
        clean_ver = _clean_str(raw_version)[:128] if raw_version else None
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
        display_purl = (
            _display_purl(entry["purl"]) if reveal_names and purl and not purl.ambiguous else None
        )
        clean_purl = _clean_str(display_purl)[:512] if display_purl else None
        sha256_val: str | None = entry["sha256"]
        eco = _ENTRY_ECO_MAP.get(entry["type"]) or _purl_eco(entry["purl"]) or "any"
        provenance = _purl_provenance(purl, key)
        cand_keys = _identity_tokens(raw_name, purl, eco, key, lookup=True)
        rec_keys = _identity_tokens(raw_name, purl, eco, key, lookup=False)
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
        unresolved_versions = False
        for k in cand_keys:
            bucket = buckets.setdefault(k, _IdentityBucket())
            if clean_ver:
                for (p_eco, p_ver), p_ref in bucket.versions.items():
                    if (p_ref, "ver") in seen_peer:
                        continue
                    if p_eco:
                        satisfies = _satisfies_nested_requirement(p_eco, p_ver, clean_ver)
                        if satisfies is None:
                            unresolved_versions = True
                            continue
                        conflict = not satisfies
                    else:
                        conflict = _versions_conflict(p_ver, clean_ver)
                    if conflict:
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

        elif (
            overflow
            or incomplete_identity
            or unresolved_versions
            or _provenance_disagrees(buckets, provenance)
        ):
            summary.unresolved_conflict_count += 1
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="source_conflict_unresolved",
                    detail="Package identities, registry provenance, manifest ranges or the complete set of versions and digests cannot be reconciled.",
                    recommendation="Reconcile the complete supplier and repository component records.",
                )
            )

        for k in rec_keys:
            bucket = buckets.setdefault(k, _IdentityBucket())
            if clean_ver:
                _record_bucket_item(
                    bucket.versions, (None, clean_ver), comp_ref, "extra_version_conflicts", bucket
                )
            if sha256_val:
                _record_bucket_item(
                    bucket.digests, sha256_val, comp_ref, "extra_digest_conflicts", bucket
                )
        _record_provenance(buckets, provenance)

        clm = ClaimEvidence(
            assurance=AssuranceLevel.DECLARED,
            method=f"sbom-import:{source_format}",
            scope="external-sbom",
            locator=f"supplier-entry:{index}"
            if shareable
            else f"{neutralize(bom_path.name)}#{index}",
        )
        exact_ver = is_exact_version(clean_ver) or (
            clean_ver is None and purl_has_exact_version(entry["purl"])
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
        if provenance is not None:
            props["purl_provenance"] = list(provenance)
        if sha256_val and not shareable:
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
    files: ConfinedCollection,
    prefix: str,
    rel_posix: str,
    path_set: set[str],
    manifest: dict[str, Any],
) -> dict[str, Any]:
    # Workspace layouts, .npmrc overrides, and multiple package managers can select a different lock.
    manager = manifest.get("packageManager")
    if (
        manifest.get("workspaces")
        or manifest.get("overrides")
        or prefix + ".npmrc" in path_set
        or _enclosing_manifest(
            rel_posix,
            path_set,
            ("package.json", "package-lock.json", "npm-shrinkwrap.json", ".npmrc"),
        )
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
    try:
        doc = load_toml(raw)
    except (ValueError, PolicyError, RecursionError):
        files._fail(prefix + filename, "invalid nested lockfile")
        return {}
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
        dep_version: str | None = None
        if uv and isinstance(dep, dict) and dep.keys() == {"name"} and isinstance(dep["name"], str):
            name = _norm_pkg(dep["name"])
        elif not uv and isinstance(dep, str):
            parts = dep.split()
            if not parts:
                continue
            name = parts[0]
            dep_version = parts[1] if len(parts) >= 2 else None
        else:
            continue
        candidates = by_name.get(name, [])
        if dep_version is not None:
            candidates = [c for c in candidates if c.get("version") == dep_version]
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
    # Cargo's bare version is a caret constraint, including abbreviated versions.
    if (
        not spec
        or not re.fullmatch(r"[=^~]?[0-9]+(?:\.[0-9]+){0,2}", spec)
        or not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version)
    ):
        return False
    if spec.startswith("="):
        exact = spec[1:]
        return version == exact or (exact.count(".") < 2 and version.startswith(exact + "."))
    return not _versions_conflict(spec if spec[0] in "^~" else "^" + spec, version)


def _npm_lock_agrees(spec: str, version: str) -> bool:
    # A bare major or major.minor is a range in npm, and excludes prereleases.
    if re.fullmatch(r"v?[0-9]+(?:\.[0-9]+)?", spec):
        expected = spec.removeprefix("v") + "."
        return re.fullmatch(
            r"v?[0-9]+\.[0-9]+\.[0-9]+", version
        ) is not None and version.removeprefix("v").startswith(expected)
    return _satisfies_nested_requirement("npm", spec, version) is True


def _valid_nested_npm_record(record: Any, pkg_name: str, version: Any) -> bool:
    if (
        not isinstance(record, dict)
        or record.get("link") is True
        or record.get("inBundle") is True
        or record.get("name", pkg_name) != pkg_name
        or not isinstance(version, str)
        or len(version) > 128
        or not _reg._npm_exact(version)
    ):
        return False
    integrity = record.get("integrity")
    if integrity is not None and not _reg.RegistryScanner._validate_sri_integrity(integrity):
        return False
    resolved = record.get("resolved")
    if resolved is not None:
        parsed_url = _reg.RegistryScanner._https_resolution(resolved)
        if parsed_url is None or not _reg.RegistryScanner._tarball_matches(
            parsed_url[0], parsed_url[1], pkg_name, version
        ):
            return False
    return True


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
            # An invalid lock version cannot corroborate the manifest requirement.
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
                npm_locks = _npm_lock_packages(files, prefix, rel_posix, path_set, parsed)
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
                all_registry = all(
                    _reg.RegistryScanner._npm_spec(item)[0] == "registry" for _, item in specs
                )
                if (
                    all_registry
                    and _valid_nested_npm_record(record, pkg_name, version)
                    and isinstance(version, str)
                    and _reg.RegistryScanner._lock_root_agrees(npm_locks, pkg_name, specs)
                    and _npm_lock_agrees(spec, version)
                ):
                    found.append((pkg_name, version, "npm", "locked", {}))
                elif (
                    all_registry
                    and all(item == spec for _, item in specs)
                    and _reg._npm_exact(spec)
                ):
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
            if parts in (["require", "("], ["require("]):
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
                    package = re.match(r"[A-Za-z0-9_.-]+", dep.strip())
                    if package is not None and _is_ai_package_name(package[0]):
                        requirement = dep.strip()[package.end() :].strip()
                        found.append(
                            (package[0], requirement or None, "conda", "manifest-only", {})
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
    seen_records: set[tuple[str, str | None, str, str, tuple[tuple[str, str], ...]]] = set()
    used_refs: set[str] = set()
    for pkg_name, spec, ecosystem, pin_state, hashes in found:
        clean_ver = spec.lstrip("=") if spec and spec.startswith("==") else spec
        dedup_key = (pkg_name, clean_ver, ecosystem, pin_state, tuple(sorted(hashes.items())))
        if dedup_key in seen_records:
            continue
        seen_records.add(dedup_key)
        exact = is_exact_version(clean_ver) or pin_state == "digest-pinned"
        ref_id = hashlib.sha256(f"{rel_posix}:{ecosystem}:{pkg_name}".encode()).hexdigest()[:16]
        bom_ref = f"registry:nested:{ref_id}"
        if bom_ref in used_refs:
            salt = hashlib.sha256(
                f"{rel_posix}:{ecosystem}:{pkg_name}:{clean_ver or ''}:{pin_state}".encode()
            ).hexdigest()[:8]
            bom_ref = f"registry:nested:{ref_id}:{salt}"
            suffix_idx = 2
            while bom_ref in used_refs:
                bom_ref = f"registry:nested:{ref_id}:{salt}:{suffix_idx}"
                suffix_idx += 1
        used_refs.add(bom_ref)
        nested_props: dict[str, Any] = {
            "manifest_path": rel_posix,
            "pinning_state": pin_state,
            "version_pinned": exact and pin_state != "manifest-only",
        }
        if ecosystem == "conda" and spec:
            requirement = neutralize(redact_text(spec))
            nested_props["manifest_version_specifier"] = (
                requirement if len(requirement) <= 128 else "[over version limit]"
            )
            clean_ver = spec.removeprefix("=").strip() or None
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
                bom_ref=bom_ref,
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
