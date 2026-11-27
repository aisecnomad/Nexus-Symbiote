"""Vendor-shaped literals in files a collector already named as a source.

MCP launch positions stay with the MCP collector. Credential-shaped stores
(``.env``, key files, ``secrets/``) are not read. A match is recorded by its
path and line. With ``NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`` set, the finding also
carries a keyed HMAC of the normalized spelling. Without that key it says the
value is unbound. An unkeyed digest is not recorded. The literal is not stored,
logged, or placed in a finding. More than ``MAX_LITERALS`` matches in one file is a
collection failure and produces no finding from that file.
"""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.scanners.credential_files import credential_shaped
from nexus_symbiote.scanners.mcp_credentials import normalize_credential, placeholder
from nexus_symbiote.scanners.source_binding import BindingError, value_binding
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.secrets import TOKEN_SHAPE, holds_token_shape
from nexus_symbiote.utils.terminal import neutralize

MAX_LITERALS = 32
_JOIN_LINES = 8
_JOIN_CHARS = 2048
# A vendor prefix left at the end of a window the cap cut is not a completed token.
_OPEN_PREFIX = re.compile(
    r"(?:sk-|ghp_|gho_|ghu_|ghs_|ghr_|hf_|github_pat_|glpat-|xox[abeoprs]-)[\w-]*$"
)
_PLUS_JOIN = re.compile(r"""(?s)(['"])\s*\+\s*\1""")
_ADJACENT_QUOTES = re.compile(r"""(?s)(['"])\s*\1""")
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
_TOKEN_CHAR = re.compile(r"[\w-]")
# A prefix a space may interrupt. The match itself still has to satisfy the shape table.
_SPLIT_PREFIX = re.compile(
    r"(?<![\w-])(?:"
    r"sk-(?:proj-|svcacct-|admin-|ant-|or-v1-|lf-)?"
    r"|github_pat_|gh[oprsu]_|glpat-|xox[abeoprs]-|hf_|npm_|AIza|(?:AKIA|ASIA)"
    r")"
)
_BINDING_PROFILE = "vendor-token"


def _visible(text: str) -> str:
    """NFKC, then drop format characters and variation selectors. Whitespace stays.

    ``normalize_credential`` also drops spaces, which glues a token to the words
    around it. That form is only for a space or mark inside the token's own body.
    """
    folded = unicodedata.normalize("NFKC", text)
    kept: list[str] = []
    for char in folded:
        code = ord(char)
        if unicodedata.category(char) == "Cf":
            continue
        if 0xFE00 <= code <= 0xFE0F or 0xE0100 <= code <= 0xE01EF:
            continue
        kept.append(char)
    return "".join(kept)


def _split_bodies(visible: str, covered: list[tuple[int, int]]) -> list[str]:
    """Tokens whose body is split by whitespace, not tokens separated from prose."""
    found: list[str] = []
    for prefix in _SPLIT_PREFIX.finditer(visible):
        if any(start <= prefix.start() < end for start, end in covered):
            continue
        chars: list[str] = []
        index = prefix.end()
        limit = min(len(visible), prefix.start() + 256)
        while index < limit:
            char = visible[index]
            if char.isspace():
                nxt = index + 1
                while nxt < limit and visible[nxt].isspace():
                    nxt += 1
                if holds_token_shape(prefix.group() + "".join(chars)):
                    break
                if nxt >= limit or _TOKEN_CHAR.fullmatch(visible[nxt]) is None:
                    break
                index = nxt
                continue
            if _TOKEN_CHAR.fullmatch(char) is None:
                break
            chars.append(char)
            index += 1
        candidate = normalize_credential(prefix.group() + "".join(chars))
        if holds_token_shape(candidate) and TOKEN_SHAPE.fullmatch(candidate):
            found.append(candidate)
    return found


def _literals(visible: str) -> list[str]:
    found: list[str] = []
    covered: list[tuple[int, int]] = []
    for match in TOKEN_SHAPE.finditer(visible):
        literal = match.group()
        if not holds_token_shape(literal):
            continue
        found.append(normalize_credential(literal))
        covered.append(match.span())
    found.extend(_split_bodies(visible, covered))
    return list(dict.fromkeys(found))


def _commitment(rel_path: str, line_no: int, literal: str) -> str:
    """A keyed binding when the operator key is set, otherwise location-only."""
    try:
        binding = value_binding(
            _BINDING_PROFILE,
            {"path": rel_path, "line": line_no, "token": literal},
        )
    except BindingError:
        return "value unbound"
    if not binding:
        return "value unbound"
    return f"{binding['static_value_binding']} key_id={binding['static_value_binding_key_id']}"


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


def _quotes_open(line: str) -> bool:
    """Whether an unescaped double quote is still open at the end of ``line``."""
    count = 0
    escaped = False
    for char in line:
        if escaped:
            escaped = False
        elif char == "\\":
            escaped = True
        elif char == '"':
            count += 1
    return count % 2 == 1


def _window_continues(parts: list[str]) -> bool:
    stripped = parts[-1].rstrip()
    return stripped.endswith(("\\", "+")) or _quotes_open("\n".join(parts))


def _collapse_joins(text: str) -> str:
    """Drop backslash newlines and the quotes around ``"a" + "b"``. One pass each."""
    pieces: list[str] = []
    index = 0
    length = len(text)
    while index < length:
        if text[index] == "\\" and index + 1 < length and text[index + 1] == "\n":
            index += 2
            continue
        pieces.append(text[index])
        index += 1
    collapsed = "".join(pieces)
    collapsed = _PLUS_JOIN.sub("", collapsed)
    return _ADJACENT_QUOTES.sub("", collapsed)


def _cut_off_token(visible: str) -> bool:
    """Whether ``visible`` ends in a vendor prefix the window did not finish."""
    found = _OPEN_PREFIX.search(visible.rstrip())
    return found is not None and not holds_token_shape(found.group())


def _literal_windows(text: str) -> Iterable[tuple[int, str, bool]]:
    """``(first line, normalized text, truncated)`` for each continued span.

    Hidden characters are removed and whitespace is kept, so a token in prose stays
    a separate word. A space or mark inside the token body is joined afterwards.
    """
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        parts = [lines[index]]
        start = index + 1
        truncated = False
        while _window_continues(parts):
            if (
                len(parts) >= _JOIN_LINES
                or sum(len(part) for part in parts) >= _JOIN_CHARS
                or index + 1 >= len(lines)
            ):
                truncated = index + 1 < len(lines) and _window_continues(parts)
                break
            index += 1
            parts.append(lines[index])
        normalized = _visible(_collapse_joins("\n".join(parts)))
        yield start, normalized, truncated
        index += 1


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
            for line_no, normalized, truncated in _literal_windows(text):
                if truncated and _cut_off_token(normalized):
                    own_failures.append(
                        f"{neutralize(rel_path)}: a vendor token continues past the "
                        f"{_JOIN_LINES}-line window; not collected"
                    )
                    refused = True
                    break
                for literal in _literals(normalized):
                    if placeholder(literal):
                        continue
                    found.append((line_no, literal))
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
            for line_no, literal in found:
                risks.append(
                    RiskAssessment(
                        severity=RiskSeverity.HIGH,
                        category="credential_exposure",
                        detail=(
                            f"{neutralize(rel_path)}:{line_no}: a vendor token shape is "
                            f"committed ({_commitment(rel_path, line_no, literal)})."
                        ),
                        recommendation=(
                            "Remove the literal, rotate the credential, and pass it by an "
                            "environment reference."
                        ),
                    )
                )
                added += 1
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
