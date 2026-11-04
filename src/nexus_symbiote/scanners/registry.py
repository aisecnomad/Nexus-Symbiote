"""Offline registry references collected from bounded local manifests.

These declarations do not establish registry authenticity, resolved artifacts,
installed versions, or cryptographic verification.
"""

from __future__ import annotations

import base64
import binascii
import re
import tomllib
from pathlib import Path
from typing import Any
from urllib.parse import quote

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name

from nexus_symbiote.core.enums import AssuranceLevel, RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import extract_version_pin, hash_bytes, parse_json_strict
from nexus_symbiote.core.models import ClaimEvidence, RegistryEntryComponent, RiskAssessment
from nexus_symbiote.scanners.base import (
    Scanner,
    ScanResult,
    sanitized_origin,
    toml_exceeds_limits,
)
from nexus_symbiote.utils.secrets import redact_text

AI_PACKAGE_PATTERNS = [
    re.compile(r"(?:^|/)@modelcontextprotocol/", re.I),
    re.compile(r"(?:^|/)mcp[-_]", re.I),
    re.compile(r"(?:^|/)(?:langchain|llama[-_]index|crewai|autogen|openai|anthropic|cohere)", re.I),
    re.compile(r"(?:^|/)(?:transformers|torch|tensorflow|safetensors|tokenizers)", re.I),
    re.compile(r"(?:^|/)(?:chromadb|pinecone|qdrant|weaviate|pgvector|faiss)", re.I),
    re.compile(r"(?:^|/)(?:guardrails|nemo[-_]guardrails|rebuff)", re.I),
]


class RegistryScanner(Scanner):
    name = "registry"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            result.components.extend(self._scan_npm(files.root, result))
            result.components.extend(self._scan_pip(files.root, result))
            result.components.extend(self._scan_docker(files.root, result))
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("registry (no AI-related dependencies found)")
        return result

    def _read(self, path: Path, result: ScanResult) -> str | None:
        if self._files is None:
            raise RuntimeError("_read called outside a _collection context")
        content = self._files.read_text(path, missing_ok=True)
        if content is not None:
            result.surfaces_scanned.append(str(path))
        return content

    def _scan_npm(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        if self._files is None:
            raise RuntimeError("_scan_npm called outside a _collection context")
        path = root / "package.json"
        data = self._files.read_json(path, missing_ok=True)
        if data is None:
            return []
        result.surfaces_scanned.append(str(path))
        if not isinstance(data, dict):
            result.scan_failures.append("package.json: expected an object")
            return []
        all_deps: dict[str, str] = {}
        for key in ("dependencies", "devDependencies", "optionalDependencies"):
            deps = data.get(key, {})
            if not isinstance(deps, dict) or not all(
                isinstance(value, str) for value in deps.values()
            ):
                result.scan_failures.append(f"package.json: invalid {key} map")
                continue
            all_deps.update(deps)
        # Parse and bind the same bounded bytes; a second open for hashing could
        # associate a swapped lockfile with a previously parsed resolution.
        lock_path = root / "package-lock.json"
        lock_bytes = self._files.read_bytes(lock_path, missing_ok=True)
        resolutions: dict[str, Any] = {}
        lock_digest = None
        if lock_bytes is not None:
            result.surfaces_scanned.append("package-lock.json")
            try:
                lock = parse_json_strict(lock_bytes)
                if (
                    not isinstance(lock, dict)
                    or not isinstance(lock.get("packages"), dict)
                    or (
                        lock.get("lockfileVersion") is not None
                        and (
                            type(lock["lockfileVersion"]) is not int
                            or lock["lockfileVersion"] not in (2, 3)
                        )
                    )
                ):
                    raise ValueError("unsupported npm lockfile structure")
                resolutions = lock["packages"]
                lock_digest = hash_bytes(lock_bytes)
            except (ValueError, TypeError, UnicodeError, RecursionError):
                result.scan_failures.append("package-lock.json: invalid or unsupported lockfile")
        components: list[RegistryEntryComponent] = []
        for raw_name, raw_spec in sorted(all_deps.items()):
            if not self._is_ai_package(raw_name):
                continue
            name, spec = redact_text(raw_name), redact_text(raw_spec)
            properties: dict[str, Any] = {
                "collection_mode": "manifest-reference",
                "registry_origin_verified": False,
                "requested_version": spec,
            }
            claims: dict[str, ClaimEvidence] = {}
            version = spec
            registry_origin = None
            source = str(path)
            key = "node_modules/" + raw_name
            record = resolutions.get(key)
            if record is not None:
                if not isinstance(record, dict):
                    result.scan_failures.append(
                        "package-lock.json: invalid selected package record"
                    )
                elif record.get("name", raw_name) != raw_name:
                    result.surfaces_excluded.append(
                        "package-lock.json: aliased package identity is unresolved"
                    )
                elif record.get("link") is True:
                    result.surfaces_excluded.append(
                        "package-lock.json: local link resolution is unverified"
                    )
                else:
                    resolved_version = record.get("version")
                    if (
                        isinstance(resolved_version, str)
                        and len(resolved_version) <= 128
                        and re.fullmatch(
                            r"\d+\.\d+\.\d+(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
                            resolved_version,
                        )
                    ):
                        version = resolved_version
                    else:
                        result.scan_failures.append(
                            "package-lock.json: selected package lacks an exact version"
                        )
                    locator = "package-lock.json#/packages/" + key.replace("~", "~0").replace(
                        "/", "~1"
                    )
                    # Keep only source origin; paths, credentials and signed URLs
                    # are not needed to identify this declared registry reference.
                    url = record.get("resolved")
                    if isinstance(url, str) and url.startswith(("https://", "http://")):
                        origin = sanitized_origin(url)
                        registry_origin = origin if origin != "[redacted]" else None
                    properties.update(
                        {
                            "collection_mode": "lockfile-resolution-claim",
                            "lockfile_sha256": lock_digest,
                            "lockfile_record": locator,
                            "artifact_verified": False,
                        }
                    )
                    claims["package_resolution"] = ClaimEvidence(
                        assurance=AssuranceLevel.DECLARED,
                        method="npm-lockfile",
                        scope="dependency-resolution",
                        collector="registry",
                        locator=locator,
                    )
                    source = "package-lock.json"
                    integrity = record.get("integrity")
                    if integrity is not None:
                        try:
                            if not isinstance(integrity, str) or len(integrity) > 1024:
                                raise ValueError("invalid integrity")
                            algorithm, encoded = integrity.split("-", 1)
                            size = {"sha256": 32, "sha384": 48, "sha512": 64}.get(algorithm)
                            if (
                                size is None
                                or len(base64.b64decode(encoded, validate=True)) != size
                            ):
                                raise ValueError("invalid integrity")
                        except (ValueError, binascii.Error):
                            result.scan_failures.append(
                                "package-lock.json: invalid selected package integrity"
                            )
                        else:
                            properties["lockfile_integrity"] = integrity
            risks: list[RiskAssessment] = []
            if not re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", raw_spec):
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.MEDIUM,
                        category="version_pinning",
                        detail=f"npm package '{name}' has a nonexact declared reference: {spec}",
                        recommendation="Resolve and verify an immutable artifact with lockfile integrity evidence.",
                    )
                )
            components.append(
                RegistryEntryComponent(
                    bom_ref=f"registry:npm/{name}",
                    name=name,
                    version=version,
                    package_url=(
                        f"pkg:npm/{quote(name, safe='/')}@{quote(version, safe='')}"
                        if re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][a-zA-Z0-9.-]+)?", version)
                        else None
                    ),
                    registry_type="npm",
                    registry_uri=registry_origin,
                    source_path=source,
                    trust_tier=TrustTier.UNKNOWN,
                    assurance_level=AssuranceLevel.DECLARED,
                    risks=risks,
                    properties=properties,
                    claims=claims,
                )
            )
        return components

    def _pip_component(
        self, line: str, path: Path, result: ScanResult | None = None
    ) -> RegistryEntryComponent | None:
        reference = line.strip().split(" #", 1)[0].strip()
        match = re.match(r"^([a-zA-Z0-9_.-]+)", reference)
        if not match or not self._is_ai_package(match.group(1)):
            return None
        name = str(canonicalize_name(match.group(1)))
        invalid = False
        try:
            requirement = Requirement(reference)
        except InvalidRequirement:
            invalid = True
            spec = redact_text(reference[len(match.group(1)) :].strip())
            if result is not None:
                result.scan_failures.append(f"{path.name}: invalid or unsupported PyPI requirement")
        else:
            name = str(canonicalize_name(requirement.name))
            # Retain markers and URLs as declared, unresolved conditions; they
            # must not silently turn into an unconditional exact package URL.
            spec = str(requirement.specifier)
            if requirement.url:
                spec = "@ " + requirement.url
            if requirement.marker:
                spec += "; " + str(requirement.marker)
            spec = redact_text(spec)
        version = extract_version_pin(reference, ecosystem="python") if not invalid else None
        risks = (
            []
            if version is not None
            else [
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="version_pinning",
                    detail=f"PyPI package '{name}' has an unresolved or nonexact declared reference.",
                    recommendation="Resolve the declared conditions, pin the version and verify artifact hashes.",
                )
            ]
        )
        return RegistryEntryComponent(
            bom_ref=f"registry:pypi/{name}",
            name=name,
            version=spec or None,
            package_url=(
                f"pkg:pypi/{quote(name, safe='')}@{quote(version, safe='')}"
                if version is not None
                else None
            ),
            registry_type="pypi",
            registry_uri="https://pypi.org",
            source_path=str(path),
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties={
                "collection_mode": "manifest-reference",
                "registry_origin_verified": False,
                "requested_requirement": redact_text(reference),
            },
        )

    def _scan_pip(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []
        for filename in ("requirements.txt", "requirements-dev.txt", "requirements-ml.txt"):
            path = root / filename
            content = self._read(path, result)
            if content is None:
                continue
            for line in content.splitlines():
                if not line.strip() or line.lstrip().startswith(("#", "-")):
                    continue
                component = self._pip_component(line, path, result)
                if component:
                    components.append(component)
        path = root / "pyproject.toml"
        content = self._read(path, result)
        if content is None:
            return components
        if toml_exceeds_limits(content):
            result.scan_failures.append("pyproject.toml: TOML size or structure limit exceeded")
            return components
        try:
            data = tomllib.loads(content)
        except (ValueError, RecursionError):
            result.scan_failures.append("pyproject.toml: invalid TOML")
            return components
        declarations: list[str] = []
        project = data.get("project", {})
        if not isinstance(project, dict):
            result.scan_failures.append("pyproject.toml: invalid project table")
            return components
        deps = project.get("dependencies", [])
        if isinstance(deps, list) and all(isinstance(value, str) for value in deps):
            declarations.extend(deps)
        else:
            result.scan_failures.append("pyproject.toml: invalid project dependencies")
        optional = project.get("optional-dependencies", {})
        if isinstance(optional, dict):
            for values in optional.values():
                if isinstance(values, list) and all(isinstance(value, str) for value in values):
                    declarations.extend(values)
                else:
                    result.scan_failures.append("pyproject.toml: invalid optional dependencies")
        tool = data.get("tool", {})
        poetry: Any = tool.get("poetry", {}) if isinstance(tool, dict) else {}
        poetry_deps = poetry.get("dependencies", {}) if isinstance(poetry, dict) else {}
        if isinstance(poetry_deps, dict):
            for name, value in poetry_deps.items():
                if isinstance(value, str):
                    declarations.append(f"{name}{value}")
                elif isinstance(value, dict) and isinstance(value.get("version"), str):
                    declarations.append(f"{name}{value['version']}")
        for declaration in declarations:
            component = self._pip_component(declaration, path, result)
            if component and not any(item.name == component.name for item in components):
                components.append(component)
        return components

    def _scan_docker(self, root: Path, result: ScanResult) -> list[RegistryEntryComponent]:
        components: list[RegistryEntryComponent] = []
        for filename in (
            "Dockerfile",
            "Dockerfile.agent",
            "docker-compose.yml",
            "docker-compose.yaml",
        ):
            path = root / filename
            content = self._read(path, result)
            if content is None:
                continue
            # One whitespace quantifier only: two adjacent ones backtrack quadratically
            # when a file ends in "image:" followed by a long run of whitespace.
            for raw_image in re.findall(r"(?:FROM|image:)\s*([^\s]+)", content):
                if not any(
                    word in raw_image.lower()
                    for word in ("vllm", "ollama", "triton", "tgi", "llama", "model")
                ):
                    continue
                image = redact_text(raw_image)
                has_digest = bool(re.search(r"@sha256:[0-9a-fA-F]{64}$", raw_image))
                has_tag = ":" in raw_image.rsplit("/", 1)[-1] and not raw_image.endswith(":latest")
                risks: list[RiskAssessment] = []
                if not has_digest:
                    risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.MEDIUM if has_tag else RiskSeverity.HIGH,
                            category="mutable_image_tag" if has_tag else "version_pinning",
                            detail=f"Docker image '{image}' lacks an immutable digest pin.",
                            recommendation="Pin to a SHA256 artifact digest and verify its provenance.",
                        )
                    )
                components.append(
                    RegistryEntryComponent(
                        bom_ref=f"registry:docker/{image}",
                        name=image,
                        registry_type="docker-hub",
                        source_path=str(path),
                        trust_tier=TrustTier.UNKNOWN,
                        risks=risks,
                        properties={
                            "collection_mode": "manifest-reference",
                            "registry_origin_verified": False,
                        },
                    )
                )
        return components

    def _is_ai_package(self, name: str) -> bool:
        return any(pattern.search(name) for pattern in AI_PACKAGE_PATTERNS)
