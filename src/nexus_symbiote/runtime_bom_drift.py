"""Offline Kubernetes/cluster CycloneDX ML-BOM vs static AgentBOM drift check.

Reads one static native AgentBOM and one or more already-collected CycloneDX
runtime BOM JSON files (for example cluster ``k8s-aibom`` snapshots). Performs
zero network I/O and spawns zero subprocesses. Every finding from cluster BOMs is
tagged ``reported`` assurance: cluster snapshots reflect what the cluster
reporting pipeline emitted and cannot prove absence.
"""

from __future__ import annotations

import errno
import os
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from packageurl import PackageURL

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
    _PURL_METADATA_QUALIFIERS,
    MAX_FOREIGN_SBOM_BYTES,
    _clean_exact_spec,
    _display_purl,
    _extract_cdx_entries,
    _is_ai_package_name,
    _is_sha256_alg,
    _norm_pkg,
    _repository_identity,
)
from nexus_symbiote.scanners.registry import parse_image_reference
from nexus_symbiote.utils.secrets import REDACTED, redact_keyed_text, redact_text
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
_ORIGIN_ONLY_COLLECTION_MODES = frozenset(
    {"static-config", "static-agent-card", "static-syntax-reference"}
)


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


def _normalize_endpoint(raw_url: str, *, origin_only: bool = False) -> str | None:
    cleaned = raw_url.strip()
    if not cleaned:
        return None
    try:
        parsed = urlsplit(cleaned if "://" in cleaned else f"https://{cleaned}")
        host = (parsed.hostname or "").strip().lower()
        port = parsed.port
    except ValueError:
        raise RuntimeBOMInputError("Service endpoint has an invalid host or port.") from None
    if not host:
        return None
    if port is None and parsed.scheme in {"http", "ws"}:
        port = 80
    elif port is None and parsed.scheme in {"https", "wss", ""}:
        port = 443
    if ":" in host:
        host = f"[{host}]"
    base = f"{parsed.scheme}://{host}" + (f":{port}" if port is not None else "")
    if origin_only:
        return base
    path = parsed.path
    if not path and parsed.scheme in {"http", "https", "ws", "wss"}:
        path = "/"  # Empty paths denote "/" (RFC 9110 §4.2.3; RFC 6455 §3).
    query = f"?{parsed.query}" if parsed.query else ""
    return f"{base}{path}{query}"


def _is_origin_only_endpoint(comp: MCPServerComponent | A2AServerComponent) -> bool:
    if not comp.endpoint_url or comp.endpoint_url.strip() in {"", "[redacted]"}:
        return False
    if comp.properties.get("collection_mode") not in _ORIGIN_ONLY_COLLECTION_MODES:
        return False
    raw = comp.endpoint_url.strip()
    parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    return parsed.path in {"", "/"} and not parsed.query


def _endpoint_has_detail(endpoint: str) -> bool:
    parsed = urlsplit(endpoint)
    return parsed.path not in {"", "/"} or bool(parsed.query)


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
            if os.fstat(handle.fileno()).st_nlink != 1:
                raise RuntimeBOMInputError("Runtime BOM must be a single-link regular file.")
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
            safe = redact_keyed_text(pname, pval)
            for segment in re.finditer(r"[^.:]+", pname):
                if safe == REDACTED:
                    break
                safe = redact_keyed_text(segment.group(), pval, redacted=safe)
            context[_clean(pname, limit=128)] = _clean(safe, limit=256)
            if len(context) >= 16:
                break
    return context


def _parse_purl(value: str | None) -> PackageURL | None:
    if not value:
        return None
    try:
        if "?" in value:
            query = value.partition("#")[0].partition("?")[2]
            pairs = parse_qsl(query, keep_blank_values=True, strict_parsing=True, errors="strict")
            keys = [k.lower() for k, _ in pairs]
            if len(keys) != len(set(keys)) or any(not v.strip() for _, v in pairs):
                raise ValueError("ambiguous qualifiers")
        return PackageURL.from_string(value)
    except ValueError:
        raise RuntimeBOMInputError("Invalid package URL in comparison input.") from None


def _image_pin(name: str, version: str | None, purl: str | None) -> str | None:
    reference = parse_image_reference(name)
    package = _parse_purl(purl)
    pins = set()
    for value in (
        reference.digest if reference else None,
        version,
        package.version if package else None,
    ):
        if value and ":" in value:
            pinned = parse_image_reference(f"image@{value}")
            if pinned and pinned.pinned:
                pins.add(value)
    if len(pins) > 1:
        raise RuntimeBOMInputError("Container description has conflicting digest pins.")
    return next(iter(pins), None)


def _check_container_mutability(name: str, version: str | None, purl: str | None) -> str | None:
    if _image_pin(name, version, purl):
        return None
    reference = parse_image_reference(name)
    tag = (version or (reference.tag if reference else None) or "").lstrip(":").lower()
    if tag in _MUTABLE_IMAGE_TAGS:
        return f"mutable container tag ':{_clean(tag)}'"
    if purl:
        return "container PURL without digest pin"
    return "container workload has no immutable digest"


def _names_repository(value: str, repository: str) -> bool:
    reference = parse_image_reference(value)
    return (
        reference is not None
        and reference.digest is None
        and reference.tag is None
        and reference.repository.lower() == repository.lower()
    )


def _image_key(name: str, version: str | None = None, purl: str | None = None) -> str:
    reference = parse_image_reference(name)
    package = _parse_purl(purl)
    if package is not None:
        if package.type not in {"oci", "docker"} or reference is None:
            raise RuntimeBOMInputError("Container image name and package URL repository disagree.")
        expected_leaf = reference.path.rsplit("/", 1)[-1]
        purl_leaf = package.name
        if ":" in package.name:
            base, ptag = package.name.split(":", 1)
            known_tags = {t for t in (reference.tag, version) if isinstance(t, str) and t}
            if base == expected_leaf and ptag in known_tags:
                purl_leaf = base
        if purl_leaf.lower() != expected_leaf.lower():
            raise RuntimeBOMInputError("Container image name and package URL repository disagree.")
        repo_url = package.qualifiers.get("repository_url")
        if repo_url is not None:
            candidates = [repo_url]
            if package.type == "docker":
                # A docker repository_url names the registry; namespace and name the path.
                path = "/".join(part for part in (package.namespace, purl_leaf) if part)
                candidates.append(f"{repo_url.rstrip('/')}/{path}")
            if not any(_names_repository(value, reference.repository) for value in candidates):
                raise RuntimeBOMInputError(
                    "Container image name and package URL repository disagree."
                )
        if package.namespace:
            ns_repo = f"{package.namespace}/{purl_leaf}".lower()
            if ns_repo not in {reference.path.lower(), reference.repository.lower()}:
                raise RuntimeBOMInputError(
                    "Container image name and package URL repository disagree."
                )
        tag_q = package.qualifiers.get("tag")
        if tag_q is not None and reference.tag is not None and tag_q != reference.tag:
            raise RuntimeBOMInputError("Container image tag and package URL tag disagree.")
    return reference.repository if reference else name


def _package_identity(name: str, purl: str | None, ecosystem: str | None = None) -> tuple[str, str]:
    package = _parse_purl(purl)
    if package:
        ecosystem = package.type
        name = "/".join(part for part in (package.namespace, package.name) if part)
    return ecosystem or "", _norm_pkg(name) if ecosystem == "pypi" else name


def _package_repository(
    ecosystem: str, purl: str | None, registry_uri: str | None = None
) -> str | None:
    package = _parse_purl(purl)
    purl_repo = package.qualifiers.get("repository_url") if package else None
    if registry_uri is not None and not registry_uri.strip():
        raise RuntimeBOMInputError("Static package has an empty registry URI.")
    norm_purl = _repository_identity(purl_repo.strip(), ecosystem) if purl_repo else None
    norm_uri = _repository_identity(registry_uri.strip(), ecosystem) if registry_uri else None
    if norm_purl and norm_uri and norm_purl != norm_uri:
        raise RuntimeBOMInputError("Package registry URI and package URL repository disagree.")
    explicit = norm_purl or norm_uri
    if explicit:
        return explicit
    if ecosystem == "pypi":
        return _repository_identity("https://pypi.org", "pypi")
    if ecosystem == "npm":
        return _repository_identity("https://registry.npmjs.org", "npm")
    return None


def _package_qualifiers(purl: str | None) -> tuple[str, dict[str, str]]:
    package = _parse_purl(purl)
    if package is None:
        return "", {}
    quals = {
        k.lower(): v
        for k, v in (package.qualifiers or {}).items()
        if k.lower() != "repository_url" and k.lower() not in _PURL_METADATA_QUALIFIERS
    }
    return package.subpath or "", quals


def _package_source_matches(obs: _RuntimeObservation, comp: RegistryEntryComponent) -> bool:
    comp_eco, _ = _package_identity(comp.name, comp.package_url, comp.registry_type)
    if obs.repository != _package_repository(comp_eco, comp.package_url, comp.registry_uri):
        return False
    obs_sub, obs_quals = _package_qualifiers(obs.purl)
    comp_sub, comp_quals = _package_qualifiers(comp.package_url)
    if obs_sub != comp_sub:
        return False
    return not ((obs_quals or comp_quals) and obs_quals != comp_quals)


@dataclass(frozen=True)
class _RuntimeObservation:
    kind: str  # "model" | "service" | "container" | "package"
    key: str
    name: str
    version: str | None
    purl: str | None
    sha256: str | None
    provider: str
    supplier: str
    endpoints: tuple[str, ...]
    mutable_reason: str | None
    source_files: set[str]
    cluster_context: dict[str, str]
    repository: str | None = None

    def to_dict(self) -> dict[str, Any]:
        safe_purl = (_display_purl(self.purl) or self.purl) if self.purl else None
        payload: dict[str, Any] = {
            "kind": self.kind,
            "name": _clean(self.name),
            "version": _clean(self.version) if self.version else None,
            "purl": _clean(safe_purl) if safe_purl else None,
            "sha256": self.sha256,
            "assurance": ASSURANCE,
            "source_files": sorted(self.source_files),
        }
        if self.provider:
            payload["provider"] = _clean(self.provider)
        if self.supplier:
            payload["supplier"] = _clean(self.supplier)
        if self.repository:
            payload["repository"] = _clean(self.repository)
        if self.endpoints:
            payload["endpoints"] = [_clean(ep) for ep in self.endpoints]
        if self.mutable_reason:
            payload["mutable_tag_reason"] = _clean(self.mutable_reason)
        if self.cluster_context:
            payload["cluster_context"] = dict(self.cluster_context)
        return payload


def _model_keys(name: str) -> set[str]:
    clean = name.strip().lower()
    key = clean.rsplit(":", 1)[0] if ":" in clean.rsplit("/", 1)[-1] else clean
    return {clean, key} - {""}


def _model_sources(node: Mapping[str, Any]) -> tuple[str, str]:
    """CycloneDX supplier.name and the producer's native model-provider extension."""
    entity = node.get("supplier", {})
    if not isinstance(entity, dict) or not isinstance(entity.get("name", ""), str):
        raise RuntimeBOMInputError("Model supplier must be an organization with an optional name.")
    supplier = entity.get("name", "").strip()
    providers = set()
    properties = node.get("properties", [])
    if not isinstance(properties, list):
        raise RuntimeBOMInputError("Model properties must be an array.")
    for prop in properties:
        if isinstance(prop, dict) and prop.get("name") == "nexus-symbiote:provider":
            value = prop.get("value")
            if not isinstance(value, str) or not value.strip():
                raise RuntimeBOMInputError("Model provider property requires a nonempty name.")
            providers.add(value.strip())
    if len(providers) > 1:
        raise RuntimeBOMInputError("Model has conflicting provider declarations.")
    return next(iter(providers), ""), supplier


def _model_source_matches(obs: _RuntimeObservation, comp: ModelComponent) -> bool:
    if (
        obs.supplier
        and comp.supplier
        and obs.supplier.casefold() != comp.supplier.strip().casefold()
    ):
        return False
    # Third-party snapshots can supply only the organization. Compare it with the
    # native provider if the static declaration supplies no separate supplier.
    provider = obs.provider or (obs.supplier if not comp.supplier else "")
    return (
        not provider or not comp.provider or provider.casefold() == comp.provider.strip().casefold()
    )


def _collect_observations(
    runtime_paths: Sequence[Path],
    static_pkg_keys: set[str],
) -> tuple[list[_RuntimeObservation], list[dict[str, str]], dict[str, int]]:
    inputs_meta: list[dict[str, str]] = []
    acc_map: dict[
        tuple[
            str,
            str,
            str,
            str,
            str,
            str,
            str,
            str,
            str,
            tuple[str, ...],
            tuple[tuple[str, str], ...],
        ],
        _RuntimeObservation,
    ] = {}
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
        try:
            entries = _extract_cdx_entries(doc, strict=True)
        except ValueError as exc:
            raise RuntimeBOMInputError(f"Invalid runtime CycloneDX structure: {exc}") from exc
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
            provider = supplier = ""
            repository: str | None = None
            if raw_type == "machine-learning-model":
                kind = "model"
                provider, supplier = _model_sources(raw_entry)
                qualifier = provider or supplier
                norm_key = (
                    f"{qualifier}/{name}" if qualifier and "/" not in name else name
                ).lower()
            elif raw_type == "service":
                kind = "service"
                norm_key = name.lower()
            elif is_container:
                kind = "container"
                norm_key = _image_key(name, version, purl)
                reference = parse_image_reference(name)
                if not version and reference:
                    version = reference.tag
                pin = _normalize_sha256(_image_pin(name, version, purl))
                if sha256 and pin and sha256 != pin:
                    raise RuntimeBOMInputError("Container hash and reference digest disagree.")
                sha256 = sha256 or pin
            elif raw_type in {"library", "framework", "application"}:
                ecosystem, package_name = _package_identity(name, purl)
                if not (
                    _is_ai_package_name(name)
                    or _is_ai_package_name(package_name)
                    or _norm_pkg(package_name) in static_pkg_keys
                ):
                    stats["non_ai_packages_ignored"] += 1
                    continue
                kind = "package"
                norm_key = f"{ecosystem}:{package_name}"
                repository = _package_repository(ecosystem, purl)
            else:
                stats["non_ai_packages_ignored"] += 1
                continue

            context = {**doc_ctx, **_extract_k8s_properties(raw_entry)}
            endpoints = set()
            for ep in raw_entry.get("endpoints") or []:
                endpoint = _normalize_endpoint(ep)
                if not endpoint:
                    raise RuntimeBOMInputError("Service endpoint has no host.")
                endpoints.add(endpoint)
            if kind == "package" and (package := _parse_purl(purl)) is not None and package.version:
                if version and version != package.version:
                    raise RuntimeBOMInputError("Runtime package version and package URL disagree.")
                version = package.version
            map_key = (
                kind,
                norm_key,
                version or "",
                name,
                purl or "",
                repository or "",
                sha256 or "",
                provider,
                supplier,
                tuple(sorted(endpoints)),
                tuple(sorted(context.items())),
            )
            if map_key not in acc_map:
                if len(acc_map) >= MAX_DRIFT_ITEMS:
                    raise RuntimeBOMInputError(
                        f"Runtime BOMs exceed the distinct observation limit ({MAX_DRIFT_ITEMS}); comparison incomplete."
                    )
                acc_map[map_key] = _RuntimeObservation(
                    kind=kind,
                    key=norm_key,
                    source_files=set(),
                    name=name,
                    version=version,
                    purl=purl,
                    sha256=sha256,
                    provider=provider,
                    supplier=supplier,
                    endpoints=tuple(sorted(endpoints)),
                    mutable_reason=_check_container_mutability(name, version, purl)
                    if kind == "container"
                    else None,
                    cluster_context=context,
                    repository=repository,
                )
            acc_map[map_key].source_files.add(file_label)

    observations = [acc_map[key] for key in sorted(acc_map)]
    return (
        observations,
        sorted(inputs_meta, key=lambda item: (item["file"], item["sha256"])),
        stats,
    )


@dataclass
class _StaticCatalog:
    models: dict[str, list[ModelComponent]]
    services: dict[str, list[MCPServerComponent | A2AServerComponent]]
    endpoints: dict[str, list[MCPServerComponent | A2AServerComponent]]
    endpoint_origins: dict[str, list[MCPServerComponent | A2AServerComponent]]
    packages: dict[str, list[RegistryEntryComponent]]
    package_keys: set[str]
    images: dict[str, list[RegistryEntryComponent]]
    digests: dict[int, str]


def _index_static_bom(bom: AIBOM) -> _StaticCatalog:
    models: dict[str, list[ModelComponent]] = {}
    services: dict[str, list[MCPServerComponent | A2AServerComponent]] = {}
    endpoints: dict[str, list[MCPServerComponent | A2AServerComponent]] = {}
    endpoint_origins: dict[str, list[MCPServerComponent | A2AServerComponent]] = {}
    packages: dict[str, list[RegistryEntryComponent]] = {}

    images: dict[str, list[RegistryEntryComponent]] = {}
    package_names: set[str] = set()
    digests: dict[int, str] = {}
    for comp in bom.components:
        digest = _static_sha256(comp)
        if digest is not None:
            digests[id(comp)] = digest
        if isinstance(comp, ModelComponent):
            keys = set()
            for name in (comp.name, comp.requested_alias):
                if not name:
                    continue
                keys.update(_model_keys(name))
                if "/" not in name:
                    for source in (comp.provider, comp.supplier):
                        if source:
                            keys.update(_model_keys(f"{source.strip()}/{name}"))
            for key in keys:
                models.setdefault(key, []).append(comp)
        elif isinstance(comp, MCPServerComponent | A2AServerComponent):
            services.setdefault(comp.name.strip().lower(), []).append(comp)
            if comp.endpoint_url and comp.endpoint_url.strip() != "[redacted]":
                if _is_origin_only_endpoint(comp):
                    origin_ep = _normalize_endpoint(comp.endpoint_url, origin_only=True)
                    if origin_ep:
                        endpoint_origins.setdefault(origin_ep, []).append(comp)
                else:
                    ep = _normalize_endpoint(comp.endpoint_url)
                    if ep:
                        endpoints.setdefault(ep, []).append(comp)
        elif isinstance(comp, RegistryEntryComponent):
            package = _parse_purl(comp.package_url)
            if comp.registry_type in {"docker-hub", "oci"} or (
                package and package.type in {"oci", "docker"}
            ):
                images.setdefault(_image_key(comp.name, comp.version, comp.package_url), []).append(
                    comp
                )
                norm_static_pin = _normalize_sha256(
                    _image_pin(comp.name, comp.version, comp.package_url)
                )
                if digest and norm_static_pin and digest != norm_static_pin:
                    raise RuntimeBOMInputError(
                        "Static container hash and reference digest disagree."
                    )
                if norm_static_pin and digest is None:
                    digests[id(comp)] = norm_static_pin
            else:
                if comp.registry_type and package and comp.registry_type != package.type:
                    raise RuntimeBOMInputError("Static package ecosystem and package URL disagree.")
                eco, name = _package_identity(comp.name, comp.package_url, comp.registry_type)
                if package is not None:
                    pkg_name = _norm_pkg(name) if eco == "pypi" else name.strip()
                    comp_name = _norm_pkg(comp.name) if eco == "pypi" else comp.name.strip()
                    if pkg_name != comp_name:
                        raise RuntimeBOMInputError("Static package name and package URL disagree.")
                _package_repository(eco, comp.package_url, comp.registry_uri)
                packages.setdefault(f"{eco}:{name}", []).append(comp)
                package_names.add(_norm_pkg(name))
    return _StaticCatalog(
        models=models,
        services=services,
        endpoints=endpoints,
        endpoint_origins=endpoint_origins,
        packages=packages,
        package_keys=package_names,
        images=images,
        digests=digests,
    )


def _static_sha256(comp: Any) -> str | None:
    hashes = getattr(comp, "hashes", None)
    if not isinstance(hashes, Mapping):
        return None
    digests: set[str] = set()
    for alg, digest in hashes.items():
        if _is_sha256_alg(str(alg)):
            normalized = _normalize_sha256(digest)
            if not normalized:
                raise RuntimeBOMInputError("Static component has an invalid SHA-256 digest.")
            digests.add(normalized)
    if len(digests) > 1:
        raise RuntimeBOMInputError("Static component has conflicting SHA-256 digests.")
    return next(iter(digests), None)


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

    def digest_key(obs: _RuntimeObservation) -> tuple[str, str, str | None, str, str]:
        return obs.kind, obs.key, obs.version, obs.provider.casefold(), obs.supplier.casefold()

    observed_digests: dict[tuple[str, str, str | None, str, str], set[str]] = {}
    for obs in observations:
        if obs.sha256:
            observed_digests.setdefault(digest_key(obs), set()).add(obs.sha256)

    for obs in observations:
        static_matches: list[Any] = []
        if obs.kind == "model":
            for mk in _model_keys(obs.key):
                static_matches.extend(
                    comp for comp in catalog.models.get(mk, ()) if _model_source_matches(obs, comp)
                )
        elif obs.kind == "service":
            static_matches.extend(catalog.services.get(obs.key, ()))
            if not static_matches:
                for ep in obs.endpoints:
                    static_matches.extend(catalog.endpoints.get(ep, ()))
                if not static_matches:
                    for ep in obs.endpoints:
                        origin_ep = _normalize_endpoint(ep, origin_only=True)
                        if origin_ep:
                            static_matches.extend(catalog.endpoint_origins.get(origin_ep, ()))
        elif obs.kind == "container":
            static_matches.extend(catalog.images.get(obs.key, ()))
        else:
            static_matches.extend(
                comp
                for comp in catalog.packages.get(obs.key, ())
                if _package_source_matches(obs, comp)
            )

        deduped_matches = list({c.bom_ref: c for c in static_matches}.values())
        obs_dict = obs.to_dict()

        if not deduped_matches:
            if obs.mutable_reason:
                obs_dict["mutable_image_tag"] = True
            undeclared.append(obs_dict)
            continue

        # Evaluate version, digest and endpoints against the same declaration.
        matching = []
        reasons_by_candidate = []
        static_versions = set()
        for comp in sorted(deduped_matches, key=lambda c: c.bom_ref):
            candidate_reasons = []
            version = comp.version
            if isinstance(comp, RegistryEntryComponent):
                package = _parse_purl(comp.package_url)
                version = (package.version if package else None) or _clean_exact_spec(version)
            digest = catalog.digests.get(id(comp))
            different_pin = False
            observed_version = obs.version
            if obs.kind == "container":
                static_pin = _image_pin(comp.name, comp.version, comp.package_url)
                runtime_pin = _image_pin(obs.name, obs.version, obs.purl)
                different_pin = bool(static_pin and runtime_pin and static_pin != runtime_pin)
                if not version or version == static_pin:
                    reference = parse_image_reference(comp.name)
                    version = reference.tag if reference else None
                if observed_version == runtime_pin:
                    reference = parse_image_reference(obs.name)
                    observed_version = reference.tag if reference else None
            if version:
                static_versions.add(version)
                if observed_version and version != observed_version:
                    candidate_reasons.append("version_mismatch")
            if different_pin or (digest and obs.sha256 and obs.sha256 != digest):
                candidate_reasons.append("digest_mismatch")
            if obs.kind == "service":
                if comp.endpoint_url and comp.endpoint_url.strip() == "[redacted]":
                    candidate_reasons.append("endpoint_mismatch")
                elif _is_origin_only_endpoint(comp):
                    declared_origin = _normalize_endpoint(comp.endpoint_url, origin_only=True)
                    observed_origins = {
                        origin_ep
                        for ep in obs.endpoints
                        if (origin_ep := _normalize_endpoint(ep, origin_only=True)) is not None
                    }
                    if observed_origins != ({declared_origin} if declared_origin else set()):
                        candidate_reasons.append("endpoint_mismatch")
                else:
                    declared = _normalize_endpoint(comp.endpoint_url) if comp.endpoint_url else None
                    if set(obs.endpoints) != ({declared} if declared else set()):
                        candidate_reasons.append("endpoint_mismatch")
            if not candidate_reasons:
                matching.append(comp)
            reasons_by_candidate.append(candidate_reasons)
        drift_reasons = (
            []
            if matching
            else [
                reason
                for reason in ("version_mismatch", "digest_mismatch", "endpoint_mismatch")
                if any(reason in reasons for reasons in reasons_by_candidate)
            ]
        )
        if len(observed_digests.get(digest_key(obs), ())) > 1:
            drift_reasons.append("conflicting_reported_digests")
        refs = sorted({c.bom_ref for c in (matching or deduped_matches)})
        seen_static_refs.update(refs)
        obs_dict["inventory_refs"] = [_clean(ref) for ref in refs]
        if static_versions:
            obs_dict["declared_versions"] = [_clean(v) for v in sorted(static_versions)]
        if obs.kind == "service":
            pool = matching or deduped_matches
            origin_only_match = bool(pool) and all(_is_origin_only_endpoint(c) for c in pool)
            obs_dict["endpoint_comparison"] = "origin-only" if origin_only_match else "full"
            if origin_only_match and any(_endpoint_has_detail(ep) for ep in obs.endpoints):
                obs_dict["endpoint_path_query_unverified"] = True

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
                "purl": item.get("purl"),
                "sha256": item.get("sha256"),
                "endpoints": item.get("endpoints"),
                "context": item.get("cluster_context"),
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
