"""Credential findings for ``.env`` files. Values are not stored or hashed.

A ``.env`` store is often a low-entropy password. Publishing its unsalted SHA-256
would let a reader attack the value. The finding names the path, line, key and
vendor type. ``.env.example``, ``.env.sample`` and ``.env.template`` are not
stores: they get the same vendor-shape check as other files, including the
SHA-256 of a high-entropy token and never the token.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.credential_allowlist import bind_credential_path, credential_suppressed
from nexus_symbiote.literal_credentials import MAX_LITERALS, _commitment
from nexus_symbiote.scanners.mcp_credentials import normalize_credential
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import TOKEN_SHAPE, holds_token_shape
from nexus_symbiote.utils.terminal import neutralize

MAX_ENV_BYTES = 1_048_576
MAX_ENV_LINES = 10_000
MAX_ENV_LINE_CHARS = 8_192
_TEMPLATE_SUFFIXES = frozenset({".example", ".sample", ".template"})
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_PREFIXES = (
    ("github_pat_", "github"),
    ("ghp_", "github"),
    ("gho_", "github"),
    ("ghu_", "github"),
    ("ghs_", "github"),
    ("ghr_", "github"),
    ("glpat-", "gitlab"),
    ("xoxb-", "slack"),
    ("xoxa-", "slack"),
    ("xoxp-", "slack"),
    ("xox", "slack"),
    ("sk-proj-", "openai"),
    ("sk-", "openai"),
    ("hf_", "huggingface"),
    ("AIza", "google"),
    ("AKIA", "aws"),
    ("ASIA", "aws"),
    ("npm_", "npm"),
    ("pypi-", "pypi"),
)


def _kind(name: str) -> str | None:
    """``store`` for a ``.env*`` value file, ``template`` for the three sample names."""
    lowered = name.lower()
    if not lowered.startswith(".env"):
        return None
    suffix = PurePosixPath(lowered).suffix
    if suffix in _TEMPLATE_SUFFIXES:
        return "template"
    if suffix in {".py", ".js", ".ts", ".sh", ".md"}:
        return None
    return "store"


def _vendor(value: str) -> str:
    token = TOKEN_SHAPE.search(normalize_credential(value))
    if token is None:
        return "unspecified"
    spelling = token.group()
    for prefix, label in _PREFIXES:
        if spelling.startswith(prefix):
            return label
    return "vendor-token"


def _assignment(line: str) -> tuple[str, str] | None:
    body = line.strip()
    if not body or body.startswith("#"):
        return None
    if body.startswith("export ") and "=" in body:
        body = body[7:].lstrip()
    if "=" not in body:
        return None
    key, _, value = body.partition("=")
    key = key.strip()
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        value = value[1:-1]
    if not _KEY.fullmatch(key) or TOKEN_SHAPE.search(key):
        key = "a key name"
    return key, value


def _owner(components: list[Any], path: str) -> Any | None:
    named = [
        component
        for component in components
        if getattr(component, "source_path", None) == path
        and isinstance(getattr(component, "risks", None), list)
    ]
    pool = named or [
        component for component in components if isinstance(getattr(component, "risks", None), list)
    ]
    if not pool:
        return None
    return min(pool, key=lambda component: str(getattr(component, "bom_ref", "")))


def apply_env_credential_findings(
    aibom: AIBOM,
    root: Path | None = None,
    *,
    exclude_paths: Iterable[str | Path] = (),
    failures: list[str] | None = None,
    exclusions: list[str] | None = None,
) -> int:
    """Record ``.env`` assignments and vendor shapes in ``.env`` templates."""
    if root is None or not root.is_dir():
        return 0
    added = 0
    own_failures: list[str] = []
    own_exclusions: list[str] = []
    with ConfinedCollection(
        root, own_failures, own_exclusions, exclude_paths=exclude_paths
    ) as files:
        paths = sorted(
            (path.as_posix() for path in files.iter_files() if _kind(path.name) is not None),
        )
        for rel_path in paths:
            kind = _kind(PurePosixPath(rel_path).name)
            raw = files.read_bytes(rel_path, missing_ok=True, report_coexisting_variants=False)
            if raw is None:
                continue
            if len(raw) > MAX_ENV_BYTES:
                own_failures.append(
                    f"{neutralize(rel_path)}: env file exceeds {MAX_ENV_BYTES} bytes; not collected"
                )
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                own_failures.append(
                    f"{neutralize(rel_path)}: env credentials were not read (not UTF-8)"
                )
                continue
            lines = text.splitlines()
            if len(lines) > MAX_ENV_LINES or any(len(line) > MAX_ENV_LINE_CHARS for line in lines):
                own_failures.append(
                    f"{neutralize(rel_path)}: env file exceeds the line bound; not collected"
                )
                continue
            component = _owner(list(aibom.components), rel_path)
            if component is None:
                own_failures.append(
                    f"{neutralize(rel_path)}: env credential has no component to record it"
                )
                continue
            with bind_credential_path(rel_path):
                risks = _line_risks(rel_path, lines, kind == "template", own_failures)
            if risks is None:
                continue
            component.risks.extend(risks)
            added += len(risks)
    for target_list, own in ((failures, own_failures), (exclusions, own_exclusions)):
        if target_list is None:
            continue
        known = set(target_list)
        for msg in own:
            if msg not in known:
                target_list.append(msg)
                known.add(msg)
    return added


def _line_risks(
    rel_path: str,
    lines: list[str],
    template: bool,
    failures: list[str],
) -> list[RiskAssessment] | None:
    found: list[RiskAssessment] = []
    where = neutralize(rel_path)
    for line_no, line in enumerate(lines, start=1):
        parsed = _assignment(line)
        if parsed is None:
            continue
        key, value = parsed
        if credential_suppressed(value):
            continue
        if template:
            normalized = normalize_credential(value)
            match = TOKEN_SHAPE.search(normalized)
            if match is None or not holds_token_shape(match.group()):
                continue
            detail = (
                f"{where}:{line_no}: a vendor token shape is committed "
                f"({_commitment(rel_path, line_no, match.group())})."
            )
        else:
            vendor = _vendor(value)
            article = "an" if vendor[:1] in "aeiou" else "a"
            detail = f"{where}:{line_no}: {key} holds {article} {vendor} credential."
        if len(value) >= 16 and value not in {key, "a key name"} and value in detail:
            failures.append(f"{where}: env finding would have copied a value; not collected")
            return None
        found.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="credential_exposure",
                detail=detail,
                recommendation=(
                    "Remove the value from the repository and pass it by an environment reference."
                ),
            )
        )
        if len(found) > MAX_LITERALS:
            failures.append(f"{where}: more than {MAX_LITERALS} env credentials; not collected")
            return None
    return found
