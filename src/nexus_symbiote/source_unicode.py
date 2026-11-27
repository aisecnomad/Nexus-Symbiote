"""Homoglyphs and hidden characters in source a collector already opened.

Instruction files are already rated by the prompt collector. This pass reads
code and Dockerfiles those collectors named. Findings locate hidden characters
and mixed-script Python, JavaScript and TypeScript identifiers by file and line.
More than ``MAX_FINDINGS`` hits in a file cause an explicit collection failure.
"""

from __future__ import annotations

import io
import tokenize
from collections.abc import Iterable, Iterator
from pathlib import Path, PurePosixPath

from nexus_symbiote import limits
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.collection import is_imported
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.identifiers import mixed_scripts
from nexus_symbiote.core.models import AnyComponent, RiskAssessment
from nexus_symbiote.scanners.credential_files import credential_gap, credential_shaped
from nexus_symbiote.scanners.prompt import detect_invisible_characters
from nexus_symbiote.scanners.ts_tools import SCRIPT_SUFFIXES, typescript_identifiers
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.terminal import neutralize

MAX_FINDINGS = 32
_PYTHON_SUFFIXES = frozenset({".py", ".pyi"})
_CODE_SUFFIXES = SCRIPT_SUFFIXES | _PYTHON_SUFFIXES | {".sh", ".bash"}
_DOCKER_NAMES = frozenset({"dockerfile", "containerfile"})


def _eligible(path: str) -> bool:
    if credential_shaped(path) or "://" in path:
        return False
    name = PurePosixPath(path).name.lower()
    if name in _DOCKER_NAMES or name.startswith("dockerfile"):
        return True
    return PurePosixPath(path).suffix.lower() in _CODE_SUFFIXES


def _identifiers(text: str, suffix: str) -> Iterator[tuple[int, str]]:
    if suffix in _PYTHON_SUFFIXES:
        for token in tokenize.generate_tokens(io.StringIO(text).readline):
            if token.type == tokenize.NAME:
                yield token.start[0], token.string
    elif suffix in SCRIPT_SUFFIXES:
        yield from typescript_identifiers(text.encode("utf-8"), suffix)


def _mixed_identifier_lines(
    text: str, path: str, byte_size: int, failures: list[str]
) -> dict[int, set[str]]:
    suffix = PurePosixPath(path).suffix.lower()
    if suffix not in _PYTHON_SUFFIXES and suffix not in SCRIPT_SUFFIXES:
        return {}
    syntax = limits.bound("syntax-bytes")
    if byte_size > syntax.value:
        failures.append(f"{neutralize(path)}: {syntax.exceeded()}")
        return {}
    by_line: dict[int, set[str]] = {}
    try:
        for line, name in _identifiers(text, suffix):
            if not name.isascii() and (scripts := mixed_scripts(name)):
                by_line.setdefault(line, set()).update(scripts)
    except (ImportError, SyntaxError, tokenize.TokenError, ValueError, RecursionError):
        # Parser diagnostics can contain source text. Keep the independent format-
        # character check active and report the incomplete identifier check.
        failures.append(f"{neutralize(path)}: source identifiers could not be read")
        return {}
    return by_line


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
    owners: dict[str, list[AnyComponent]] = {}
    for component in aibom.components:
        path = component.source_path
        if path and not is_imported(component) and _eligible(path):
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
            raw = files.read_bytes(rel_path, missing_ok=True, target_gap=credential_gap)
            if raw is None:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                own_failures.append(
                    f"{neutralize(rel_path)}: source characters were not read (not UTF-8)"
                )
                continue
            if text.isascii():
                continue
            text = text.replace("\r\n", "\n").replace("\r", "\n")
            identifier_lines = _mixed_identifier_lines(text, rel_path, len(raw), own_failures)
            group = owners[rel_path]
            named = {
                component.name
                for component in group
                if any(risk.category == "identifier_characters" for risk in component.risks)
            }
            found: list[RiskAssessment] = []
            refused = False
            for line_no, line in enumerate(io.StringIO(text), start=1):
                if line.isascii():
                    continue
                where = f"{neutralize(rel_path)}:{line_no}"
                scripts = identifier_lines.get(line_no)
                if scripts and line.strip() not in named:
                    found.append(
                        RiskAssessment(
                            severity=RiskSeverity.HIGH,
                            category="identifier_characters",
                            detail=f"{where} mixes the {', '.join(sorted(scripts))} scripts.",
                            recommendation=(
                                "Rewrite the identifier in one script so it cannot be "
                                "mistaken for another name."
                            ),
                        )
                    )
                found.extend(detect_invisible_characters(line, where, at_start=line_no == 1))
                if len(found) > MAX_FINDINGS:
                    own_failures.append(
                        f"{neutralize(rel_path)}: more than {MAX_FINDINGS} source Unicode "
                        "findings; not collected"
                    )
                    refused = True
                    break
            if refused or not found:
                continue
            owner = min(group, key=lambda item: item.bom_ref)
            owner.risks.extend(found)
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
