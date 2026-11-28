"""Credential findings for ``.env`` files. Values are not stored or hashed.

A ``.env`` store is often a low-entropy password. Publishing its unsalted SHA-256
would let a reader attack the value. The finding names the path, line, key and
vendor type. Templates use the same keyed or unbound commitment as source findings.
"""

from __future__ import annotations

import io
import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.credential_allowlist import credential_path_suppressed, credential_suppressed
from nexus_symbiote.literal_credentials import MAX_LITERALS, _commitment
from nexus_symbiote.scanners.base import KnownValues, declared_server_name
from nexus_symbiote.scanners.mcp_credentials import CredentialScrubber, normalize_credential
from nexus_symbiote.utils.confined import ConfinedCollection, LimitExceededError
from nexus_symbiote.utils.secrets import TOKEN_SHAPE, holds_token_shape, redact_text
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


def _assignment(line: str) -> tuple[str, str, str | None] | None:
    """Key, value, and the quote a value opens without closing on this line."""
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
    opened = None
    if value.startswith(('"', "'", "`")):
        quote = value[0]
        end = _quote_end(value, quote, 1)
        if end is None:
            opened = quote
        elif not value[end + 1 :].strip() or value[end + 1 :].lstrip().startswith("#"):
            value = value[1:end]
    else:
        value = re.split(r"(?<=\s)#", value, maxsplit=1)[0].rstrip()
    if not _KEY.fullmatch(key) or TOKEN_SHAPE.search(key):
        key = "a key name"
    return key, value, opened


def _quote_end(text: str, quote: str, start: int = 0) -> int | None:
    """The index of the first ``quote`` at or after ``start`` that no backslash escapes."""
    if quote == "'":
        end = text.find(quote, start)
        return end if end >= 0 else None
    escaped = False
    for index in range(start, len(text)):
        char = text[index]
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == quote:
            return index
    return None


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


class _EnvValues:
    """Bound the comparison index and withhold labels if it cannot hold every value."""

    def __init__(self) -> None:
        self.names = KnownValues()
        self.values: set[str] = set()
        self.byte_count = 0
        self.incomplete = False

    def add(self, value: str) -> None:
        if self.incomplete or not value or value in self.values:
            return
        size = len(value.encode("utf-8"))
        if len(self.values) >= MAX_ENV_LINES or self.byte_count + size > MAX_ENV_BYTES:
            self.refuse()
            return
        self.values.add(value)
        self.byte_count += size
        self.names.add((value, normalize_credential(value)))

    def refuse(self) -> None:
        self.incomplete = True
        self.values.clear()
        self.names.refuse()


def _display_text(text: str, scrubber: CredentialScrubber | None, fallback: str) -> str:
    if scrubber is not None and redact_text(text, scrubber) == text:
        display = neutralize(text)
        if not scrubber.contains(display):
            return display
    return fallback


def _read_env(files: ConfinedCollection, path: str, failures: list[str]) -> bytes | None:
    entry = files.regular_file(path)
    if entry is None:
        failures.append("env file unavailable during collection")
        return None
    target, size = entry
    if _kind(target.name) != _kind(PurePosixPath(path).name):
        failures.append("env symlink crosses the file's credential policy")
        return None
    if size > MAX_ENV_BYTES:
        failures.append(f"env file exceeds {MAX_ENV_BYTES} bytes; not collected")
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
    prior_failures: Iterable[str] = (),
) -> int:
    """Record ``.env`` assignments and vendor shapes in ``.env`` templates."""
    if root is None or not root.is_dir():
        return 0
    known = _EnvValues()
    pending: list[tuple[Any, str, list[_EnvFinding]]] = []
    read_failures: list[str] = []
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
            raw = _read_env(files, rel_path, read_failures)
            if raw is None:
                continue
            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                read_failures.append("env credentials were not read (not UTF-8)")
                continue
            # dotenv ends a line only at a newline. str.splitlines also splits at U+2028,
            # NEL and form feed, which moved value text after "=" into the key position.
            lines = [line.removesuffix("\n") for line in io.StringIO(text, newline=None)]
            if len(lines) > MAX_ENV_LINES or any(len(line) > MAX_ENV_LINE_CHARS for line in lines):
                read_failures.append("env file exceeds the line bound; not collected")
                continue
            component = _owner(list(aibom.components), rel_path)
            if component is None:
                read_failures.append("env credential has no component to record it")
                continue
            findings = _line_findings(rel_path, lines, kind == "template", read_failures, known)
            if findings:
                pending.append((component, rel_path, findings))
    # A location or key can contain an assignment from a later file, including an
    # allowlisted assignment. Only project-controlled fields use the scrubber.
    if own_failures or read_failures:
        known.refuse()
    scrubber = None if known.incomplete else CredentialScrubber(known.values)
    for component, rel_path, findings in pending:
        display = _display_text(rel_path, scrubber, "an env file")
        component.risks.extend(finding.assessment(display, known.names) for finding in findings)

    # Confined collection summaries may include several paths, even in the reason.
    # Their contents cannot be displayed when the set of values is incomplete.
    diagnostics = [f"an env file: {reason}" for reason in read_failures]
    # Scan shares the failure sink across collectors. Replay has a separate sink
    # and supplies the failures its local collectors actually observed. Compare
    # before masking so two different paths cannot silently hide each other.
    if set(own_failures).difference(prior_failures, failures or ()):
        diagnostics.append("env collection could not safely read every path")
    gaps = [
        _display_text(message, scrubber, "env path excluded during collection")
        for message in own_exclusions
    ]
    for target_list, own in ((failures, diagnostics), (exclusions, gaps)):
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
            detail=f"{path}:{self.line}: {subject} {self.description}",
            recommendation="Remove the value from the repository and pass it by an environment reference.",
        )


def _line_findings(
    rel_path: str,
    lines: list[str],
    template: bool,
    failures: list[str],
    known: _EnvValues,
) -> list[_EnvFinding] | None:
    path_allowed = credential_path_suppressed(rel_path)
    found: list[_EnvFinding] = []
    index = 0
    while index < len(lines):
        line_no = index + 1
        parsed = _assignment(lines[index])
        index += 1
        if parsed is None:
            continue
        key, value, quote = parsed
        if quote is not None:
            # dotenv reads a quoted value to its closing quote. The lines it spans are
            # value text: read as assignments, their text before "=" became the key.
            parts = [value[1:]]
            while index < len(lines) and (end := _quote_end(lines[index], quote)) is None:
                parts.append(lines[index])
                index += 1
            if index == len(lines):
                failures.append("env file has an unterminated quoted value; not collected")
                return None
            parts.append(lines[index][:end])
            index += 1
            value = "\n".join(parts)
        known.add(value)
        if path_allowed:
            continue
        if template:
            normalized = normalize_credential(value)
            match = TOKEN_SHAPE.search(normalized)
            if (
                match is None
                or not holds_token_shape(match.group())
                or credential_suppressed(match.group(), rel_path=rel_path)
            ):
                continue
            finding = _EnvFinding(
                line_no, None, f"is committed ({_commitment(rel_path, line_no, match.group())})."
            )
        else:
            vendor = _vendor(value)
            article = "an" if vendor[:1] in "aeiou" else "a"
            finding = _EnvFinding(line_no, key, f"holds {article} {vendor} credential.")
        found.append(finding)
        if len(found) > MAX_LITERALS:
            failures.append(f"more than {MAX_LITERALS} env credentials; not collected")
            return None
    return found
