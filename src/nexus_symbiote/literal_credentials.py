"""Vendor-shaped literals in files a collector already named as a source.

MCP launch positions stay with the MCP collector. Credential-shaped stores
(``.env``, key files, ``secrets/``) are not read. A match is recorded by its
location and the SHA-256 of its raw text. The literal is not stored, logged, or
placed in a finding. More than ``MAX_LITERALS`` matches in one file is a
collection failure and produces no finding from that file.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.mcp_credentials import placeholder
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import TOKEN_SHAPE, holds_token_shape
from nexus_symbiote.utils.terminal import neutralize

MAX_LITERALS = 32
_CONFIG_SUFFIXES = frozenset({".json", ".jsonc", ".yaml", ".yml", ".toml"})
_TEXT_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".mts",
        ".cts",
        ".md",
        ".mdc",
        ".markdown",
        ".sh",
        ".bash",
    }
)
_DOCKER_NAMES = frozenset({"dockerfile", "containerfile"})


def _eligible(path: str) -> bool:
    """Source, image, or instruction text. Not a config the MCP collector already read."""
    if credential_shaped(path) or "://" in path:
        return False
    name = PurePosixPath(path).name
    suffix = PurePosixPath(path).suffix.lower()
    if suffix in _CONFIG_SUFFIXES:
        return False
    if name.lower() in _DOCKER_NAMES or name.lower().startswith("dockerfile"):
        return True
    return suffix in _TEXT_SUFFIXES


def _owner(components: list[Any]) -> Any:
    return min(components, key=lambda component: str(getattr(component, "bom_ref", "")))


def apply_literal_credential_findings(
    aibom: AIBOM,
    root: Path | None = None,
    *,
    exclude_paths: Iterable[str | Path] = (),
    failures: list[str] | None = None,
    exclusions: list[str] | None = None,
) -> int:
    """Append one ``credential_exposure`` per non-placeholder vendor token shape.

    ``root`` is the scan root. Without a directory, nothing is read. Findings are
    added to one component that already names the file, the lowest ``bom_ref``, so
    two components of one file do not double-count it.
    """
    if root is None or not root.is_dir():
        return 0
    owners: dict[str, list[Any]] = {}
    for component in aibom.components:
        path = getattr(component, "source_path", None)
        if isinstance(path, str) and _eligible(path):
            owners.setdefault(path, []).append(component)
    if not owners:
        return 0
    added = 0
    own_failures: list[str] = []
    own_exclusions: list[str] = []
    with ConfinedCollection(
        root, own_failures, own_exclusions, exclude_paths=exclude_paths
    ) as files:
        for rel_path in sorted(owners):
            if files.excluded(rel_path) or files.is_directory(rel_path):
                continue
            raw = files.read_bytes(rel_path, missing_ok=True)
            if raw is None:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                own_failures.append(
                    f"{neutralize(rel_path)}: literal credentials were not read (not UTF-8)"
                )
                continue
            found: list[tuple[int, str]] = []
            refused = False
            for line_no, line in enumerate(text.splitlines(), start=1):
                for match in TOKEN_SHAPE.finditer(line):
                    literal = match.group()
                    if not holds_token_shape(literal) or placeholder(literal):
                        continue
                    digest = hashlib.sha256(literal.encode("utf-8")).hexdigest()
                    found.append((line_no, digest))
                    if len(found) > MAX_LITERALS:
                        own_failures.append(
                            f"{neutralize(rel_path)}: more than {MAX_LITERALS} vendor token "
                            "shapes in one file; not collected"
                        )
                        refused = True
                        break
                if refused:
                    break
            if refused or not found:
                continue
            component = _owner(owners[rel_path])
            risks = getattr(component, "risks", None)
            if not isinstance(risks, list):
                own_failures.append(
                    f"{neutralize(rel_path)}: literal credential has no component to record it"
                )
                continue
            for line_no, digest in found:
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.HIGH,
                        category="credential_exposure",
                        detail=(
                            f"{neutralize(rel_path)}:{line_no}: a vendor token shape is "
                            f"committed (sha256:{digest})."
                        ),
                        recommendation=(
                            "Remove the literal, rotate the credential, and pass it by an "
                            "environment reference."
                        ),
                    )
                )
                added += 1
    if failures is not None:
        failures.extend(own_failures)
    if exclusions is not None:
        exclusions.extend(own_exclusions)
    return added
