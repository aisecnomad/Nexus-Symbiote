"""Credential findings for ``.env`` files. Values are not stored or hashed.

A ``.env`` store is often a low-entropy password. Publishing its unsalted SHA-256
would let a reader attack the value. The finding names the path, line, key and
vendor type. Templates use the same keyed or unbound commitment as source findings.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.credential_allowlist import bind_credential_path, credential_suppressed
from nexus_symbiote.literal_credentials import MAX_LITERALS, _commitment
from nexus_symbiote.scanners.base import KnownValues, declared_server_name
from nexus_symbiote.scanners.mcp_credentials import normalize_credential
from nexus_symbiote.utils.confined import ConfinedCollection, LimitExceededError
from nexus_symbiote.utils.secrets import TOKEN_SHAPE, holds_token_shape
from nexus_symbiote.utils.terminal import neutralize

MAX_ENV_BYTES = 1_048_576
MAX_ENV_LINES = 10_000
MAX_ENV_LINE_CHARS = 8_192
_TEMPLATE_SUFFIXES = frozenset({".example", ".sample", ".template"})
_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_QUOTED_VALUE = re.compile(r"""(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')\s*(?:#.*)?""")
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
    if quoted := _QUOTED_VALUE.fullmatch(value):
        value = quoted[1] if quoted[1] is not None else quoted[2]
    elif not value.startswith(('"', "'")):
        value = re.split(r"(?<=\s)#", value, maxsplit=1)[0].rstrip()
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


def _read_env(files: ConfinedCollection, path: str, failures: list[str]) -> bytes | None:
    entry = files.regular_file(path)
    if entry is None:
        failures.append(f"{neutralize(path)}: env file unavailable during collection")
        return None
    target, size = entry
    if _kind(target.name) != _kind(PurePosixPath(path).name):
        failures.append(f"{neutralize(path)}: env symlink crosses the file's credential policy")
        return None
    if size > MAX_ENV_BYTES:
        failures.append(
            f"{neutralize(path)}: env file exceeds {MAX_ENV_BYTES} bytes; not collected"
        )
        return None
    try:
        with files.open_regular(
            path,
            max_bytes=min(files.max_file_bytes, MAX_ENV_BYTES),
            expected_link_target=target if target.as_posix() != path else None,
        ) as stream:
            return b"".join(iter(lambda: stream.read(65536), b""))
    except (OSError, LimitExceededError):
        # The confined reader records the reason and checks the target through the read.
        return None


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
    known = KnownValues()
    pending: list[tuple[Any, str, list[_EnvFinding]]] = []
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
            raw = _read_env(files, rel_path, own_failures)
            if raw is None:
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
                findings = _line_findings(rel_path, lines, kind == "template", own_failures, known)
            if findings:
                pending.append((component, rel_path, findings))
    # A key can repeat a value declared later, even in another file or an allowed entry.
    # If collection was incomplete we cannot establish which keys are safe to export.
    if own_failures:
        known.refuse()
    for component, rel_path, findings in pending:
        component.risks.extend(finding.assessment(rel_path, known) for finding in findings)
    for target_list, own in ((failures, own_failures), (exclusions, own_exclusions)):
        if target_list is None:
            continue
        recorded = set(target_list)
        for msg in own:
            if msg not in recorded:
                target_list.append(msg)
                recorded.add(msg)
    return sum(len(findings) for _, _, findings in pending)


@dataclass(frozen=True)
class _EnvFinding:
    line: int
    key: str | None
    description: str

    def assessment(self, path: str, known: KnownValues) -> RiskAssessment:
        subject = "a vendor token shape"
        if self.key is not None:
            subject = declared_server_name(self.key, known) or "a key name"
        return RiskAssessment(
            severity=RiskSeverity.HIGH,
            category="credential_exposure",
            detail=f"{neutralize(path)}:{self.line}: {subject} {self.description}",
            recommendation="Remove the value from the repository and pass it by an environment reference.",
        )


def _line_findings(
    rel_path: str,
    lines: list[str],
    template: bool,
    failures: list[str],
    known: KnownValues,
) -> list[_EnvFinding] | None:
    found: list[_EnvFinding] = []
    where = neutralize(rel_path)
    for line_no, line in enumerate(lines, start=1):
        parsed = _assignment(line)
        if parsed is None:
            continue
        key, value = parsed
        known.add((value,))
        if credential_suppressed(value):
            continue
        if template:
            normalized = normalize_credential(value)
            match = TOKEN_SHAPE.search(normalized)
            if match is None or not holds_token_shape(match.group()):
                continue
            finding = _EnvFinding(
                line_no, None, f"is committed ({_commitment(rel_path, line_no, match.group())})."
            )
        else:
            vendor = _vendor(value)
            article = "an" if vendor[:1] in "aeiou" else "a"
            finding = _EnvFinding(line_no, key, f"holds {article} {vendor} credential.")
        if len(value) >= 16 and value in where:
            failures.append("env finding path would have copied a value; not collected")
            return None
        found.append(finding)
        if len(found) > MAX_LITERALS:
            failures.append(f"{where}: more than {MAX_LITERALS} env credentials; not collected")
            return None
    return found
