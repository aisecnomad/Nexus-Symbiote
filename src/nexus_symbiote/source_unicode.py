"""Homoglyphs and hidden characters in source a collector already opened.

Instruction files are already rated by the prompt collector. This pass reads
code and Dockerfiles those collectors named, and records a mixed-script word or
a hidden character with the file, the line, and a SHA-256 of that line. The
line itself is not copied into the finding. More than ``MAX_FINDINGS`` hits in
one file is a collection failure and produces no finding from that file.
"""

from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.identifiers import mixed_scripts, raw_digest
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.prompt import detect_invisible_characters
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.terminal import neutralize

MAX_FINDINGS = 32
_CODE_SUFFIXES = frozenset(
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
        ".sh",
        ".bash",
    }
)
_DOCKER_NAMES = frozenset({"dockerfile", "containerfile"})


def _eligible(path: str) -> bool:
    if credential_shaped(path) or "://" in path:
        return False
    name = PurePosixPath(path).name.lower()
    if name in _DOCKER_NAMES or name.startswith("dockerfile"):
        return True
    return PurePosixPath(path).suffix.lower() in _CODE_SUFFIXES


def _already_named(components: list[Any], line: str) -> bool:
    """A component name neutralized on its own is not reported again as this line."""
    stripped = line.strip()
    for component in components:
        if getattr(component, "name", None) != stripped:
            continue
        risks = getattr(component, "risks", ())
        if any(getattr(risk, "category", "") == "identifier_characters" for risk in risks):
            return True
    return False


def apply_source_unicode_findings(
    aibom: AIBOM,
    root: Path | None = None,
    *,
    exclude_paths: Iterable[str | Path] = (),
    failures: list[str] | None = None,
    exclusions: list[str] | None = None,
) -> int:
    """Append hidden-character and mixed-script findings for collected source files."""
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
                    f"{neutralize(rel_path)}: source characters were not read (not UTF-8)"
                )
                continue
            group = owners[rel_path]
            found: list[RiskAssessment] = []
            refused = False
            for line_no, line in enumerate(text.splitlines(), start=1):
                if line.isascii() or _already_named(group, line):
                    continue
                where = f"{neutralize(rel_path)}:{line_no}"
                scripts = mixed_scripts(line)
                if scripts:
                    found.append(
                        RiskAssessment(
                            severity=RiskSeverity.HIGH,
                            category="identifier_characters",
                            detail=(
                                f"{where} mixes the {', '.join(scripts)} scripts "
                                f"(sha256:{raw_digest(line)})."
                            ),
                            recommendation=(
                                "Rewrite the identifier in one script so it cannot be "
                                "mistaken for another name."
                            ),
                        )
                    )
                found.extend(detect_invisible_characters(line, where))
                if len(found) > MAX_FINDINGS:
                    own_failures.append(
                        f"{neutralize(rel_path)}: more than {MAX_FINDINGS} disguised source "
                        "lines; not collected"
                    )
                    refused = True
                    break
            if refused or not found:
                continue
            component = min(group, key=lambda item: str(getattr(item, "bom_ref", "")))
            risks = getattr(component, "risks", None)
            if not isinstance(risks, list):
                own_failures.append(
                    f"{neutralize(rel_path)}: disguised source text has no component to record it"
                )
                continue
            risks.extend(found)
            added += len(found)
    # A file a collector already read can carry the same case-variant failure. List it once.
    for target_list, own in ((failures, own_failures), (exclusions, own_exclusions)):
        if target_list is None:
            continue
        known = set(target_list)
        for msg in own:
            if msg not in known:
                target_list.append(msg)
                known.add(msg)
    return added
