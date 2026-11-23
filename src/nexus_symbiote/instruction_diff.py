"""Confined CommonMark instruction-tree diff (`R1.1-10`).

Compares two directory trees (``BASE_TREE`` and ``HEAD_TREE``) through
:class:`ConfinedCollection` no-symlink/single-in-root-symlink reads matching the
``prompt`` collector's surface set and classifies security-relevant instruction changes into
five classes:

- ``tool_grant_changed``
- ``import_added``
- ``url_or_path_added``
- ``hidden_markup_added``
- ``scope_widened``

Unreadable, escaped, oversized, malformed-frontmatter, or limit-exceeded instruction
surfaces are recorded as failures and fail closed rather than silently yielding 0 changes.
By default, instruction text is withheld; when ``--show-text`` is passed, every changed
block is redacted whole-block (including multi-line PEM private keys) and
terminal-neutralized before output.
"""

from __future__ import annotations

import json
import re
from bisect import bisect_right
from collections import Counter, deque
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath
from typing import Any

import click
import yaml

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.scanner_catalog import INSTRUCTION_DIRECTORIES, SKILL_DIRECTORIES
from nexus_symbiote.scanners.credential_files import (
    MARKDOWN_SUFFIXES,
    credential_gap,
    credential_shaped,
)
from nexus_symbiote.scanners.prompt import (
    _CODEX_SPELLINGS,
    _DECLARATION_SUFFIXES,
    _FOLDED_NESTED_NAMES,
    _IMPORT,
    _IMPORTING_NAMES,
    _MAX_IMPORT_DEPTH,
    _RESOURCE_DIRECTORIES,
    _TRAILING,
    INSTRUCTION_FILES,
    NESTED_INSTRUCTION_NAMES,
    _hidden_counts,
    _import_names,
    _import_readings,
    _import_tokens,
    _line_separator_counts,
    _prompt_candidate,
    _resolve_import,
)
from nexus_symbiote.utils.confined import ConfinedCollection, fold_name
from nexus_symbiote.utils.markdown import (
    commonmark_block_readings,
    front_matter_candidates,
    hidden_text,
)
from nexus_symbiote.utils.secrets import redact_metadata, redact_text
from nexus_symbiote.utils.terminal import echo_line, json_text, neutralize
from nexus_symbiote.utils.toml import loads as toml_loads

FORMAT = "nexus-symbiote/instruction-diff/v1"
MAX_FILES = 2000
# Prompt templates are ordinary repository content and can far outnumber instruction files,
# so they have their own budget, and those past it are coverage gaps, not a refusal.
MAX_PROMPT_TEMPLATES = 2000
MAX_FRONTMATTER_NODES = 4096
MAX_SHOW_TEXT_CHARS = 4096
# One block holds many URLs, and each change repeats the block, so the text shown is bounded
# for the whole report: without it a 4 MiB file asks for more than a gigabyte of output.
MAX_SHOW_TEXT_TOTAL = 1024 * 1024
TEXT_WITHHELD = "[text withheld: --show-text output limit reached]"
# Longest tool argument or MCP tool name kept as written; a longer one is kept as the digest of
# its whole text. The bare tool name hid every later change to it, and the digest keeps a secret
# in a grant out of memory and output.
_MAX_GRANT_CHARS = 512

_URL_RE = re.compile(r"(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,31}://[^\s<>\"'`\)\]]+")
_PATH_RE = re.compile(
    r"(?<![A-Za-z0-9_/:])"
    r"(?:~/|\.\./|\$\{?HOME\}?/|[A-Za-z]:\\"
    r"|/(?:etc|var|usr|opt|tmp|root|home|Users|srv|mnt|private|bin|sbin|dev|proc|sys|run)/)"
    r"[^\s<>\"'`\)\],;]+"
)
_INCLUDE_RE = re.compile(r"<!--\s*include\s*:\s*([^\s>]+)\s*-->", re.IGNORECASE)

_PARAM_TOOLS = (
    "Bash|Shell|Read|Write|Edit|MultiEdit|NotebookEdit|NotebookRead|"
    "Glob|Grep|LS|Task|Agent|WebFetch|WebSearch|TodoWrite|TodoRead|Skill"
)
_UNAMBIGUOUS_BARE_TOOLS = (
    "Bash|Glob|Grep|MultiEdit|NotebookEdit|NotebookRead|WebFetch|WebSearch|TodoWrite|TodoRead"
)
_CONTEXT_BARE_TOOLS = "Read|Write|Edit|Shell|Task|Agent|LS|Skill"
_GRANT_VERB_PREFIX = (
    r"(?:allow|allows|allowed|grant|grants|enable|enables|use|call|tools?|permissions?|[:,\[])\s+"
)
_TOOL_GRANT_RE = re.compile(
    rf"\b(?P<tool>{_PARAM_TOOLS})(?=\()"
    r"|\bmcp__(?P<mcp>[A-Za-z0-9_.-]+)"
    r"|\bmcp__"
    r"|^[ \t]*allowed[-_]tools[ \t]*:[ \t]*(?P<list>.+)$"
    rf"|(?<![A-Za-z0-9_])(?:{_UNAMBIGUOUS_BARE_TOOLS})(?![A-Za-z0-9_])"
    rf"|`(?P<quoted>{_CONTEXT_BARE_TOOLS})`"
    rf"|(?i:{_GRANT_VERB_PREFIX})(?P<verb>{_CONTEXT_BARE_TOOLS})\b"
    rf"|\b(?P<noun>{_CONTEXT_BARE_TOOLS})\s+(?i:tools?|permissions?)\b",
    re.MULTILINE,
)

_TRAILING_REF_PUNCT = ".,;:!?\"'"
_TOOL_FRONTMATTER_KEYS = (
    "allowed-tools",
    "allowed_tools",
    "tools",
    "disallowedTools",
)
_POLICY_FRONTMATTER_KEYS = (
    "permissionMode",
    "permission_mode",
    "hooks",
    "mcpServers",
    "mcp_servers",
)
_PEM_BEGIN_RE = re.compile(r"-----BEGIN [A-Z0-9 _-]*PRIVATE KEY-----")
_PEM_END_RE = re.compile(r"-----END [A-Z0-9 _-]*PRIVATE KEY-----")
_NL_RE = re.compile(r"\r?\n")
_PAREN_RE = re.compile(r"[()]")


class InstructionChangeClass(StrEnum):
    TOOL_GRANT_CHANGED = "tool_grant_changed"
    IMPORT_ADDED = "import_added"
    URL_OR_PATH_ADDED = "url_or_path_added"
    HIDDEN_MARKUP_ADDED = "hidden_markup_added"
    SCOPE_WIDENED = "scope_widened"


@dataclass(frozen=True)
class InstructionChange:
    change_class: InstructionChangeClass
    file: str
    block_index: int | None
    summary: str
    text: str | None = None

    def to_dict(self, *, show_text: bool) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "class": self.change_class.value,
            "file": self.file,
            "block_index": self.block_index,
            "summary": self.summary,
        }
        if show_text and self.text is not None:
            payload["text"] = self.text
        return payload


_RULE_DIRECTORIES = frozenset(
    d for d, kind in INSTRUCTION_DIRECTORIES.items() if kind == "rules-file"
)
# Each host honours only its own scoping key; another host's key leaves the rule global.
_HOST_SCOPE_KEYS = {
    ".claude/rules/": ("paths",),
    ".cursor/rules/": ("globs",),
    ".github/instructions/": ("applyTo",),
}


def _scope_keys(rel_path: str) -> tuple[str, ...]:
    for prefix, keys in _HOST_SCOPE_KEYS.items():
        if rel_path.startswith(prefix):
            return keys
    return ("globs", "applyTo", "paths")


@dataclass(frozen=True)
class _ParsedInstruction:
    rel_path: str
    content: str
    globs: frozenset[str]
    path_scoped: bool
    always_apply: bool
    frontmatter_grants: frozenset[str]
    blocks: tuple[tuple[str, str], ...]
    hidden_signatures: Counter[str]
    hidden_unicode: Mapping[str, int]
    inline_tools: tuple[frozenset[str], dict[str, list[tuple[int, int]]]]
    imports: tuple[frozenset[str], dict[str, list[tuple[int, int]]]]
    refs: tuple[frozenset[str], dict[str, list[tuple[int, int]]]]
    signal_readings: dict[str, tuple[frozenset[str], frozenset[str]]]
    always_apply_false: bool = False


def _mask_multiline_pem_spans(content: str, *, start_in_pem: bool = False) -> tuple[str, bool]:
    """Replace any spanning BEGIN..END PRIVATE KEY lines even across blank paragraphs."""
    if not start_in_pem and ("-----BEGIN" not in content or "PRIVATE KEY" not in content):
        return content, False
    out_lines: list[str] = []
    in_pem = start_in_pem
    for line in content.splitlines():
        if _PEM_BEGIN_RE.search(line):
            in_pem = True
            if _PEM_END_RE.search(line):
                in_pem = False
            out_lines.append("***")
            continue
        if in_pem:
            if _PEM_END_RE.search(line):
                in_pem = False
            out_lines.append("***")
            continue
        out_lines.append(line)
    return "\n".join(out_lines), in_pem


def _file_pem_masked_blocks(blocks: tuple[tuple[str, str], ...]) -> dict[int, str]:
    """Carry PEM private-key masking state linearly across all blocks of a file."""
    masked: dict[int, str] = {}
    in_pem = False
    for idx, (_kind, content) in enumerate(blocks):
        if in_pem or ("-----BEGIN" in content and "PRIVATE KEY" in content):
            cleaned, in_pem = _mask_multiline_pem_spans(content, start_in_pem=in_pem)
            masked[idx] = cleaned
    return masked


def _truncate_cached_text(
    cached_full: str,
    cached_lines: list[str],
    line_hint: int | None,
) -> str:
    """Return an O(1) bounded snippet from an already sanitized/redacted block."""
    if len(cached_full) <= MAX_SHOW_TEXT_CHARS:
        return cached_full
    if line_hint is not None and 0 <= line_hint < len(cached_lines):
        return cached_lines[line_hint][:MAX_SHOW_TEXT_CHARS] + "\n... [truncated]"
    return cached_full[:MAX_SHOW_TEXT_CHARS] + "\n... [truncated]"


def _normalize_glob(pattern: str) -> str:
    cleaned = pattern.strip().strip("\"'")
    if cleaned.startswith("./"):
        cleaned = cleaned[2:]
    return cleaned


def _canonical(value: Any) -> str:
    """One comparable, redacted line for a front-matter value of any YAML type."""

    def plain(item: Any) -> Any:
        return sorted(map(str, item)) if isinstance(item, (set, frozenset)) else str(item)

    return neutralize(json.dumps(redact_metadata(value), sort_keys=True, default=plain))


def _glob_list(value: Any) -> frozenset[str]:
    if value is None:
        return frozenset()
    if isinstance(value, str):
        items = [_normalize_glob(part) for part in value.split(",")]
    elif isinstance(value, list):
        items = [_normalize_glob(str(item)) for item in value]
    else:
        items = [_canonical(value)]
    return frozenset(item for item in items if item)


def _tool_list(value: Any) -> frozenset[str]:
    if isinstance(value, str):
        return frozenset(
            neutralize(redact_text(part.strip()))
            for part in re.split(r"[,\s]+", value)
            if part.strip()
        )
    if isinstance(value, list):
        return frozenset(
            neutralize(redact_text(str(item).strip())) for item in value if str(item).strip()
        )
    # A value of a type no host documents still changed the grant: compare it, never drop it.
    return frozenset() if value is None else frozenset({_canonical(value)})


def _fallback_frontmatter_fields(raw_yaml: str) -> dict[str, Any]:
    """Best-effort line parser used ONLY after strict YAML failure so unquoted Cursor globs
    (e.g. ``globs: **/*``) and adjacent fields still surface signals alongside the failure."""
    meta: dict[str, Any] = {}
    current_list_key: str | None = None
    for line in raw_yaml.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("- ") and current_list_key is not None:
            val = stripped[2:].strip().strip("\"'")
            existing = meta.get(current_list_key)
            if isinstance(existing, list):
                existing.append(val)
            continue
        if ":" in stripped:
            key_part, _, val_part = stripped.partition(":")
            key = key_part.strip()
            val = val_part.strip()
            current_list_key = None
            if not val:
                if key in {
                    "globs",
                    "applyTo",
                    "paths",
                    "tools",
                    "allowed-tools",
                    "allowed_tools",
                    "disallowedTools",
                }:
                    current_list_key = key
                    meta[key] = []
                elif key in {"hooks", "mcpServers", "mcp_servers"}:
                    meta[key] = {"<unparsed>": True}
            elif val.lower() == "true" and key == "alwaysApply":
                meta[key] = True
            elif val.startswith("[") and val.endswith("]"):
                inner = val[1:-1]
                meta[key] = [p.strip().strip("\"'") for p in inner.split(",") if p.strip()]
            else:
                meta[key] = val.strip("\"'")
    return meta


def _uses_frontmatter(rel_path: str) -> bool:
    posix = PurePosixPath(rel_path)
    suffix = posix.suffix.lower()
    return (
        suffix in MARKDOWN_SUFFIXES
        or not posix.suffix
        or rel_path in INSTRUCTION_FILES
        or posix.name in NESTED_INSTRUCTION_NAMES
    )


def _parse_frontmatter_payload(language: str, raw: str) -> dict[str, Any]:
    if language == "toml":
        parsed = toml_loads(raw)
        if not isinstance(parsed, dict):
            raise PolicyError("TOML front matter must be a mapping")
        return parsed
    return parse_yaml_mapping(raw, max_nodes=MAX_FRONTMATTER_NODES)


def _parse_frontmatter(
    rel_path: str, content: str, failures: list[str]
) -> tuple[list[dict[str, Any]], str]:
    if not _uses_frontmatter(rel_path):
        return [], content
    candidates = front_matter_candidates(content)
    if not candidates:
        return [], content
    language, raw_fm, body = candidates[0]
    metas: list[dict[str, Any]] = []
    primary_ok = True
    if raw_fm.strip():
        try:
            metas.append(_parse_frontmatter_payload(language, raw_fm))
        except (PolicyError, ValueError, yaml.YAMLError, RecursionError):
            # Fall back to alternate candidate or line-level field extraction below.
            primary_ok = False
    if len(candidates) == 2:
        alt_lang, alt_raw, alt_body = candidates[1]
        if alt_raw.strip():
            try:
                metas.append(_parse_frontmatter_payload(alt_lang, alt_raw))
                if not primary_ok:
                    return metas, alt_body
            except (PolicyError, ValueError, yaml.YAMLError, RecursionError):
                if primary_ok:
                    alt_fallback = _fallback_frontmatter_fields(alt_raw)
                    if alt_fallback:
                        metas.append(alt_fallback)
    if not primary_ok:
        label = language.upper() if language in {"toml", "json"} else "YAML"
        failures.append(f"{rel_path}: invalid {label} front matter")
        metas.append(_fallback_frontmatter_fields(raw_fm))
    return metas, body


_IGNORED_SIGNAL_FRONTMATTER_KEYS = frozenset(
    {*_POLICY_FRONTMATTER_KEYS, *_TOOL_FRONTMATTER_KEYS, "globs", "applyTo", "paths", "alwaysApply"}
)


def _frontmatter_text_leaves(metas: list[dict[str, Any]]) -> list[str]:
    """Collect string leaves from non-policy frontmatter keys so URLs/paths/markup are diffed."""
    leaves: list[str] = []
    pending: list[object] = []
    for meta in metas:
        for key, value in meta.items():
            if key not in _IGNORED_SIGNAL_FRONTMATTER_KEYS:
                pending.append(value)
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if item.strip():
                leaves.append(item)
        elif isinstance(item, Mapping):
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return leaves


def _frontmatter_grants(meta: Mapping[str, Any]) -> frozenset[str]:
    grants: set[str] = set()
    for key in _TOOL_FRONTMATTER_KEYS:
        prefix = "disallowed" if key == "disallowedTools" else "tool"
        for item in _tool_list(meta.get(key)):
            grants.add(f"{prefix}:{item}")
    for key in _POLICY_FRONTMATTER_KEYS:
        val = meta.get(key)
        if val is None or val == {} or val == []:
            continue
        serialized = _canonical(val)
        canonical_key = {
            "permission_mode": "permissionMode",
            "mcp_servers": "mcpServers",
        }.get(key, key)
        grants.add(f"{canonical_key}:{serialized}")
    return frozenset(grants)


def _grant_digest(text: str) -> str:
    return hash_bytes(text.encode("utf-8", "surrogatepass"))


def _grant_part(text: str, limit: int, opening: str, closing: str) -> str:
    return text if len(text) <= limit else f"{opening}{_grant_digest(text)}{closing}"


def _grant_argument(text: str, start: int, line_end: int) -> int:
    """End of the argument opened at ``start``: its balanced ``)``, else the end of the line.

    A ``$(...)`` or other nested group does not end the grant, and an argument left open by
    an unbalanced ``(`` runs to the end of the line, so no text that may belong to it goes
    unread. The scan consumes what it reads, so each character is read once.
    """
    depth = 0
    for paren in _PAREN_RE.finditer(text, start, line_end):
        depth += 1 if paren.group() == "(" else -1
        if depth == 0:
            return paren.end()
    return line_end - 1 if text[line_end - 1 : line_end] == "\r" else line_end


def _extract_block_signals(
    blocks: tuple[tuple[str, str], ...],
) -> tuple[
    tuple[frozenset[str], dict[str, list[tuple[int, int]]]],
    tuple[frozenset[str], dict[str, list[tuple[int, int]]]],
    tuple[frozenset[str], dict[str, list[tuple[int, int]]]],
]:
    """Extract inline tool grants, @/# imports, and URLs/paths in a single pass over blocks."""
    tools: set[str] = set()
    tool_locs: dict[str, list[tuple[int, int]]] = {}
    imports: set[str] = set()
    import_locs: dict[str, list[tuple[int, int]]] = {}
    refs: set[str] = set()
    ref_locs: dict[str, list[tuple[int, int]]] = {}

    for idx, (kind, block_text) in enumerate(blocks):
        line_starts = [0]
        if "\n" in block_text:
            for nl in _NL_RE.finditer(block_text):
                line_starts.append(nl.end())

        def _line_of(pos: int, _starts: list[int] = line_starts) -> int:
            return bisect_right(_starts, pos) - 1

        pos = 0
        line_end = -1
        while (match := _TOOL_GRANT_RE.search(block_text, pos)) is not None:
            loc = (idx, _line_of(match.start()))
            pos = match.end()
            if match.group("list") is not None:
                for tok in _tool_list(match.group("list")):
                    tools.add(tok)
                    tool_locs.setdefault(tok, []).append(loc)
                continue
            name = match.group("tool") or match.group("mcp")
            if name is not None:
                if pos > line_end:
                    line_end = block_text.find("\n", pos)
                    if line_end < 0:
                        line_end = len(block_text)
                argument = ""
                if block_text.startswith("(", pos):
                    end = _grant_argument(block_text, pos, line_end)
                    argument = _grant_part(block_text[pos:end], _MAX_GRANT_CHARS + 2, "(", ")")
                    pos = end
                elif match.group("mcp") is not None:
                    name = name.rstrip(".-")
                if match.group("tool") is not None:
                    tok = f"{name}{argument}"
                else:
                    tok = f"mcp__{_grant_part(name, _MAX_GRANT_CHARS, '<', '>')}{argument}"
            else:
                tok = match.group("quoted") or match.group("verb") or match.group("noun")
                if tok is None:
                    tok = match.group(0).strip()
            tools.add(tok)
            tool_locs.setdefault(tok, []).append(loc)

        if kind not in {"fence", "indented"}:
            import_tokens = _IMPORT.findall if kind == "literal" else _import_tokens
            at_tokens = import_tokens(block_text)
            token_line_map: dict[str, int] = {}
            if at_tokens and len(block_text) > MAX_SHOW_TEXT_CHARS:
                wanted = {tok.rstrip(_TRAILING) for tok in at_tokens}
                for l_no, l_text in enumerate(block_text.splitlines()):
                    if "@" not in l_text:
                        continue
                    for cand in import_tokens(l_text):
                        c = cand.rstrip(_TRAILING)
                        if c in wanted and c not in token_line_map:
                            token_line_map[c] = l_no
            for tok in at_tokens:
                cleaned = tok.rstrip(_TRAILING)
                if cleaned:
                    imports.add(cleaned)
                    import_locs.setdefault(cleaned, []).append(
                        (idx, token_line_map.get(cleaned, 0))
                    )
            for inc_match in _INCLUDE_RE.finditer(block_text):
                cleaned = inc_match.group(1).strip()
                if cleaned:
                    imports.add(cleaned)
                    import_locs.setdefault(cleaned, []).append((idx, _line_of(inc_match.start())))

        for match in _URL_RE.finditer(block_text):
            cleaned = match.group(0).rstrip(_TRAILING_REF_PUNCT)
            if cleaned:
                refs.add(cleaned)
                ref_locs.setdefault(cleaned, []).append((idx, _line_of(match.start())))
        for match in _PATH_RE.finditer(block_text):
            cleaned = match.group(0).rstrip(_TRAILING_REF_PUNCT)
            if cleaned:
                refs.add(cleaned)
                ref_locs.setdefault(cleaned, []).append((idx, _line_of(match.start())))

    return (
        (frozenset(tools), tool_locs),
        (frozenset(imports), import_locs),
        (frozenset(refs), ref_locs),
    )


def _hidden_unicode_map(content: str) -> dict[str, int]:
    """Per-character hidden-Unicode map using ``scanners.prompt`` (covers Cf, tags, fillers)."""
    counts, tags = _hidden_counts(content, at_start=True)
    result = dict(counts)
    if tags:
        result["__TAG__"] = tags
    for sep, sep_count in _line_separator_counts(content).items():
        result[sep] = sep_count
    return result


def _parse_instruction(rel_path: str, content: str, failures: list[str]) -> _ParsedInstruction:
    metas, body = _parse_frontmatter(rel_path, content, failures)
    globs: set[str] = set()
    always_apply = False
    always_apply_false = False
    fm_grants_set: set[str] = set()
    for meta in metas:
        for key in ("globs", "applyTo", "paths"):
            globs.update(_glob_list(meta.get(key)))
        raw_aa = meta.get("alwaysApply")
        if raw_aa is not None:
            aa_norm = str(raw_aa).strip().lower()
            if aa_norm == "true":
                always_apply = True
            elif aa_norm == "false":
                always_apply_false = True
        fm_grants_set.update(_frontmatter_grants(meta))
    fm_grants = frozenset(fm_grants_set)

    readings = commonmark_block_readings(body)
    hidden = hidden_text(body)
    if _uses_frontmatter(rel_path):
        candidates = front_matter_candidates(content)
        if len(candidates) == 2 and body == candidates[0][2]:
            dash_body = candidates[1][2]
            for dash_name, dash_blocks in commonmark_block_readings(dash_body).items():
                readings[f"frontmatter-dash-{dash_name}"] = dash_blocks
            dash_hidden = hidden_text(dash_body)
            hidden = type(hidden)(
                tuple((Counter(hidden.definitions) | Counter(dash_hidden.definitions)).elements()),
                tuple((Counter(hidden.html) | Counter(dash_hidden.html)).elements()),
            )
    fm_leaves = _frontmatter_text_leaves(metas)
    hidden_unicode = _hidden_unicode_map(content)
    if fm_leaves:
        # A host decodes front matter, so an escaped hidden character counts as a raw one.
        for char, count in _hidden_unicode_map("\n".join(fm_leaves)).items():
            hidden_unicode[char] = max(hidden_unicode.get(char, 0), count)
    blocks = (
        tuple(readings["common"])
        if len(readings) == 1 and "common" in readings
        else tuple(dict.fromkeys(block for reading in readings.values() for block in reading))
    )
    comments: list[str] = []
    for text_part in (body, *fm_leaves):
        pos = 0
        while (start := text_part.find("<!--", pos)) != -1:
            end = text_part.find("-->", start + 4)
            stop = len(text_part) if end == -1 else end + 3
            comments.append(text_part[start:stop])
            pos = stop
    hidden_sigs = Counter([*comments, *hidden.definitions, *hidden.html])
    inline_tools, imports, refs = _extract_block_signals(blocks)
    if fm_leaves:
        fm_blocks = tuple(("paragraph", leaf) for leaf in fm_leaves)
        fm_tools, fm_imports, fm_refs = _extract_block_signals(fm_blocks)
        inline_tools = (inline_tools[0] | fm_tools[0], inline_tools[1])
        imports = (imports[0] | fm_imports[0], imports[1])
        refs = (refs[0] | fm_refs[0], refs[1])
    # The same path can be prose under one dialect and a fenced example under
    # another. Keep the evidence for each reading comparable across revisions.
    signals = {(blocks): (inline_tools[0], imports[0])}
    signal_readings = {}
    for name, reading in readings.items():
        all_blocks = tuple(reading)
        prose = tuple(b for b in reading if b[0] not in {"fence", "indented"})
        # A blank line may end raw HTML and expose an instruction in prose.
        # Keep the raw HTML signals too, since a host may act on them.
        inline = tuple(b for b in prose if b[0] in {"paragraph", "heading"})
        for suffix, selected in (("", all_blocks), ("-prose", prose), ("-inline", inline)):
            if selected not in signals:
                tool_signals, import_signals, _ = _extract_block_signals(selected)
                signals[selected] = (tool_signals[0], import_signals[0])
            names = ("ascii", "unicode") if name == "common" else (name,)
            for dialect in names:
                signal_readings[dialect + suffix] = signals[selected]
    return _ParsedInstruction(
        rel_path=rel_path,
        content=content,
        globs=frozenset(globs),
        path_scoped=any(
            not g.startswith("!")
            for meta in metas
            for key in _scope_keys(rel_path)
            for g in _glob_list(meta.get(key))
        ),
        always_apply=always_apply,
        frontmatter_grants=fm_grants,
        blocks=blocks,
        hidden_signatures=hidden_sigs,
        hidden_unicode=hidden_unicode,
        inline_tools=inline_tools,
        imports=imports,
        refs=refs,
        signal_readings=signal_readings,
        always_apply_false=always_apply_false and not always_apply,
    )


def _read_confined_file(
    path: str,
    files: ConfinedCollection,
    failures: list[str],
    excluded: list[str],
    *,
    context: str = "",
    missing_ok: bool = False,
    variants_read: Collection[str] = (),
    fail_on_credential: bool = False,
    report_coexisting_variants: bool = True,
) -> str | None:
    linked = None if credential_shaped(path) else files.in_root_target(path)
    reason = credential_gap(path, None if linked is None else linked.as_posix())
    if reason is not None:
        if fail_on_credential:
            failures.append(f"{path}: {context}{reason}; not read")
        else:
            excluded.append(f"{path}: {context}{reason}; not read or inventoried")
        return None
    raw = files.read_bytes(
        path,
        missing_ok=missing_ok,
        variants_read=variants_read,
        report_coexisting_variants=report_coexisting_variants,
    )
    followed = files.link_target(path)
    if raw is None:
        return None
    if followed is not None and credential_shaped(followed):
        failures.append(f"{path}: file changed during collection")
        return None
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        failures.append(f"{path}: invalid UTF-8 instruction")
        return None


def _read_confined_tree(root: Path) -> tuple[dict[str, _ParsedInstruction], list[str], list[str]]:
    if root.is_symlink() or not root.is_dir():
        raise click.ClickException(
            f"instruction tree '{neutralize(str(root))}' must be a non-symlink directory"
        )
    failures: list[str] = []
    excluded: list[str] = []
    records: dict[str, _ParsedInstruction] = {}
    texts: dict[str, str] = {}
    importers: list[str] = []
    variants: list[tuple[Path, Path]] = []
    reported_skipped: set[Path] = set()
    templates: set[str] = set()

    def _add_record(rel_path: str, text: str) -> None:
        if len(records) - len(templates) >= MAX_FILES:
            raise click.ClickException(f"instruction tree exceeds maximum file limit ({MAX_FILES})")
        records[rel_path] = _parse_instruction(rel_path, text, failures)
        texts[rel_path] = text

    def _note_skipped(skipped: list[Path]) -> None:
        for skipped_path in skipped:
            if skipped_path not in reported_skipped:
                reported_skipped.add(skipped_path)
                excluded.append(
                    f"{skipped_path.as_posix()}: default-excluded name inside an agent "
                    "configuration directory; not collected"
                )

    with ConfinedCollection(root, failures) as files:
        # 1. Fixed root instruction files
        for rel_path in INSTRUCTION_FILES:
            if rel_path in INSTRUCTION_DIRECTORIES and files.is_directory(rel_path):
                continue
            spellings = _CODEX_SPELLINGS if rel_path in _CODEX_SPELLINGS else ()
            text = _read_confined_file(
                rel_path,
                files,
                failures,
                excluded,
                missing_ok=True,
                variants_read=spellings,
                fail_on_credential=True,
                report_coexisting_variants=False,
            )
            if text is None:
                continue
            variants.extend(
                (variant, Path(rel_path))
                for variant in files.case_variants(rel_path)
                if variant.as_posix() not in spellings and not files.excluded(variant)
            )
            _add_record(rel_path, text)
            if PurePosixPath(rel_path).name in _IMPORTING_NAMES:
                importers.append(rel_path)

        # 2. Nested instruction files and prompt templates anywhere in the tree
        for path in sorted(files.iter_files()):
            relative = path.as_posix()
            nested = path.name in NESTED_INSTRUCTION_NAMES
            if not nested and len(path.parts) > 1:
                canonical = _FOLDED_NESTED_NAMES.get(fold_name(path.name))
                if canonical is not None:
                    variants.append((path, path.with_name(canonical)))
            prompt_template = _prompt_candidate(path)
            if (
                ((not nested or len(path.parts) < 2) and not prompt_template)
                or relative in INSTRUCTION_FILES
                or relative in records
            ):
                continue
            if prompt_template and len(templates) >= MAX_PROMPT_TEMPLATES:
                excluded.append(
                    f"{relative}: prompt template beyond the first {MAX_PROMPT_TEMPLATES}; "
                    "not collected"
                )
                continue
            text = _read_confined_file(
                relative, files, failures, excluded, fail_on_credential=not prompt_template
            )
            if text is None:
                continue
            if prompt_template:
                templates.add(relative)
            _add_record(relative, text)
            if nested and path.name in _IMPORTING_NAMES:
                importers.append(relative)

        # 3. Rule, prompt, steering, output-style, and subagent directories
        for directory in INSTRUCTION_DIRECTORIES:
            if directory in INSTRUCTION_FILES and not files.is_directory(directory):
                continue
            skipped: list[Path] = []
            for path in sorted(files.iter_files(directory, skipped=skipped)):
                relative = path.as_posix()
                if relative in records:
                    continue
                text = _read_confined_file(
                    relative, files, failures, excluded, fail_on_credential=True
                )
                if text is not None:
                    _add_record(relative, text)
            _note_skipped(skipped)

        # 4. Skill and command declaration files
        for skill_dir in SKILL_DIRECTORIES:
            if skill_dir in _RESOURCE_DIRECTORIES:
                continue
            skipped = []
            for path in sorted(files.iter_files(skill_dir, skipped=skipped)):
                relative = path.as_posix()
                if relative in records or path.suffix.lower() not in _DECLARATION_SUFFIXES:
                    continue
                text = _read_confined_file(
                    relative, files, failures, excluded, fail_on_credential=True
                )
                if text is not None:
                    _add_record(relative, text)
            _note_skipped(skipped)

        # 5. Any canonical-name case variant spelling of importing files
        for var_path, canon_path in variants:
            rel_var = var_path.as_posix()
            if (
                canon_path.name in _IMPORTING_NAMES
                and rel_var in texts
                and rel_var not in importers
            ):
                importers.append(rel_var)

        # 6. Recursive @path and <!-- include: --> imports (up to _MAX_IMPORT_DEPTH hops)
        pending = deque((path, 0) for path in importers)
        followed_imports = set(importers)
        looked_up: set[str] = set()
        lookups = limits.bound("import-lookups")
        spent = 0

        def _spend(importer: str) -> bool:
            nonlocal spent
            if spent >= lookups.value:
                failures.append(
                    f"{importer}: @path imports past this file are not inventoried; "
                    + lookups.exceeded()
                )
                return False
            spent += 1
            return True

        while pending:
            importer, depth = pending.popleft()
            include_tokens = [
                inc.strip()
                for inc in _INCLUDE_RE.findall(texts[importer])
                if inc.strip() and "://" not in inc
            ]
            own, host, overflow = _import_readings(texts[importer])
            references, too_many = _import_names([*own, *include_tokens], host, overflow)
            if not references:
                continue
            if too_many:
                failures.append(f"{importer}: too many @path imports to inspect")
                continue
            if importer not in looked_up and not _spend(importer):
                break
            # Each target, and whether only a name Claude Code may read leads to it.
            targets: dict[str, bool] = {}
            outside = too_long = exhausted = False
            importer_dir = PurePosixPath(importer).parent.parts
            for token, speculative in references.items():
                resolved_named, leaves, long = _resolve_import(importer_dir, token)
                for target in resolved_named:
                    targets[target] = targets.get(target, True) and speculative
                outside |= leaves
                too_long |= long
            for target, speculative in targets.items():
                if target in records:
                    if target not in followed_imports and depth + 1 <= _MAX_IMPORT_DEPTH:
                        followed_imports.add(target)
                        pending.append((target, depth + 1))
                    continue
                if target in looked_up:
                    continue
                if not _spend(importer):
                    exhausted = True
                    break
                looked_up.add(target)
                # A name only Claude Code's reading gives is looked up exactly and is
                # silent when it names nothing, so its credential or case-variant checks
                # cannot report a file no host loads.
                if (
                    speculative
                    and not files.excluded(target)
                    and files.regular_file(target) is None
                ):
                    continue
                if len(PurePosixPath(target).parts) > files.max_depth + 1:
                    excluded.append(
                        f"{target}: imported by {importer} below the collection depth limit "
                        "and not inventoried"
                    )
                    continue
                if files.excluded(target):
                    excluded.append(
                        f"{target}: imported by {importer} but excluded from collection"
                    )
                    continue
                if files.is_directory(target):
                    continue
                if credential_shaped(target):
                    excluded.append(
                        f"{target}: imported by {importer} but its name says it holds "
                        "credentials; not read or inventoried"
                    )
                    continue
                text = _read_confined_file(
                    target,
                    files,
                    failures,
                    excluded,
                    context=f"imported by {importer} but ",
                    missing_ok=True,
                )
                if text is None:
                    continue
                if depth + 1 > _MAX_IMPORT_DEPTH:
                    excluded.append(
                        f"{target}: imported more than {_MAX_IMPORT_DEPTH} hops from a memory "
                        "file and not inventoried"
                    )
                    continue
                _add_record(target, text)
                followed_imports.add(target)
                pending.append((target, depth + 1))
            if exhausted:
                break
            if outside:
                excluded.append(
                    f"{importer}: imports a file outside the project root, which is not inventoried"
                )
            if too_long:
                excluded.append(
                    f"{importer}: imports a path exceeding safe name/path bounds, not inventoried"
                )

        # Report active case variants that were not inventoried
        for var_entry, canon_entry in variants:
            if var_entry.as_posix() not in records:
                files.report_case_variant(var_entry, canon_entry)

    safe_failures = [neutralize(redact_text(msg)) for msg in failures]
    safe_excluded = [neutralize(redact_text(msg)) for msg in excluded]
    return records, safe_failures, safe_excluded


_BROAD_GLOB_RE = re.compile(r"(?:\*{1,2}/)*\*{1,2}")


def _broad_glob(pattern: str) -> bool:
    """Whether ``pattern`` activates on every path, as ``**``, ``**/*`` or ``**/**`` do."""
    return _BROAD_GLOB_RE.fullmatch(pattern) is not None


def _glob_covered_by(candidate: str, existing: frozenset[str]) -> bool:
    if candidate in existing:
        return True
    if ".." in re.split(r"[\\/]", candidate):
        return False
    if any(_broad_glob(pat) for pat in existing):
        return True
    for pat in existing:
        for suffix in ("/**/*", "/**"):
            if pat.endswith(suffix):
                prefix = pat[: -len(suffix)]
                if candidate == prefix or candidate.startswith(prefix + "/"):
                    return True
        if "/**/" in pat:
            prefix, tail = pat.split("/**/", 1)
            if not prefix or candidate.startswith(prefix + "/"):
                stem = tail.lstrip("*")
                # Without a leading star the tail names whole path segments.
                if candidate.endswith(stem if stem != tail else "/" + tail) or (
                    not prefix and candidate == tail
                ):
                    return True
    return False


def _changed_block_indices(
    base_blocks: tuple[tuple[str, str], ...],
    head_blocks: tuple[tuple[str, str], ...],
) -> list[int]:
    """Head blocks that pair with no equal base block, in one pass.

    Both sides are untrusted, and an alignment such as ``difflib`` takes quadratic time
    on blocks that repeat; the indices only choose which block a change points at.
    """
    remaining = Counter(re.sub(r"\s+", " ", content).strip() for _, content in base_blocks)
    indices: list[int] = []
    for index, (_, content) in enumerate(head_blocks):
        key = re.sub(r"\s+", " ", content).strip()
        if remaining[key] > 0:
            remaining[key] -= 1
        else:
            indices.append(index)
    return indices


def _pick_loc(
    occurrences: dict[str, list[tuple[int, int]]],
    changed_indices: list[int],
    changed_set: set[int],
    needle: str,
) -> tuple[int | None, int | None]:
    locs = occurrences.get(needle)
    if locs:
        for blk_idx, line_idx in locs:
            if blk_idx in changed_set:
                return blk_idx, line_idx
        return locs[0]
    return (changed_indices[0], None) if changed_indices else (None, None)


def diff_instruction_trees(
    base_tree: Path,
    head_tree: Path,
    *,
    show_text: bool = False,
) -> dict[str, Any]:
    """Compare instruction files across ``base_tree`` and ``head_tree``."""
    base_records, base_failures, base_excluded = _read_confined_tree(base_tree)
    head_records, head_failures, head_excluded = _read_confined_tree(head_tree)
    changes: list[InstructionChange] = []
    shown = 0

    for rel_path in sorted(head_records):
        head = head_records[rel_path]
        base = base_records.get(rel_path)
        safe_path = neutralize(rel_path)
        base_blocks = base.blocks if base is not None else ()
        changed_indices = _changed_block_indices(base_blocks, head.blocks)
        changed_set = set(changed_indices)
        sanitized_cache: dict[int, tuple[str, list[str]]] = {}
        pem_masked: dict[int, str] | None = None

        def _get_text(
            blk: int | None,
            line_hint: int | None = None,
            *,
            _head: _ParsedInstruction = head,
            _cache: dict[int, tuple[str, list[str]]] = sanitized_cache,
        ) -> str | None:
            nonlocal pem_masked, shown
            if not show_text or blk is None:
                return None
            entry = _cache.get(blk)
            if entry is None:
                if pem_masked is None and "PRIVATE KEY" in _head.content:
                    pem_masked = _file_pem_masked_blocks(_head.blocks)
                raw_block = (
                    pem_masked[blk]
                    if pem_masked is not None and blk in pem_masked
                    else _head.blocks[blk][1]
                )
                redacted = redact_text(raw_block)
                cached_lines = [neutralize(ln) for ln in redacted.splitlines()]
                cached_full = "\n".join(cached_lines)
                entry = (cached_full, cached_lines)
                _cache[blk] = entry
            snippet = _truncate_cached_text(entry[0], entry[1], line_hint)
            if shown + len(snippet) > MAX_SHOW_TEXT_TOTAL:
                return TEXT_WITHHELD
            shown += len(snippet)
            return snippet

        # 1. scope_widened
        if base is None:
            in_rule_dir = any(rel_path.startswith(d + "/") for d in _RULE_DIRECTORIES)
            # Only Cursor reads alwaysApply; other hosts load an unscoped rule file always.
            opted_out = head.always_apply_false and rel_path.startswith(".cursor/rules/")
            if (
                head.always_apply
                or any(_broad_glob(g) for g in head.globs)
                or (in_rule_dir and not head.path_scoped and not opted_out)
            ):
                changes.append(
                    InstructionChange(
                        change_class=InstructionChangeClass.SCOPE_WIDENED,
                        file=safe_path,
                        block_index=None,
                        summary=f"new instruction file '{safe_path}' activates broadly",
                    )
                )
        else:
            if not base.always_apply and head.always_apply:
                changes.append(
                    InstructionChange(
                        change_class=InstructionChangeClass.SCOPE_WIDENED,
                        file=safe_path,
                        block_index=None,
                        summary=f"'{safe_path}' changed alwaysApply from false to true",
                    )
                )
            if base.path_scoped and not head.path_scoped:
                changes.append(
                    InstructionChange(
                        change_class=InstructionChangeClass.SCOPE_WIDENED,
                        file=safe_path,
                        block_index=None,
                        summary=f"'{safe_path}' dropped its paths and now loads unconditionally",
                    )
                )
            widened_globs = sorted(
                {
                    g
                    for g in head.globs
                    if not g.startswith("!") and not _glob_covered_by(g, base.globs)
                }
                | {g for g in base.globs - head.globs if g.startswith("!")}
            )
            if widened_globs:
                changes.append(
                    InstructionChange(
                        change_class=InstructionChangeClass.SCOPE_WIDENED,
                        file=safe_path,
                        block_index=None,
                        summary=(
                            f"'{safe_path}' widened activation globs: "
                            + neutralize(redact_text(", ".join(widened_globs)))
                        ),
                    )
                )

        # 2. tool_grant_changed (frontmatter + inline)
        base_fm = base.frontmatter_grants if base is not None else frozenset()
        if base_fm != head.frontmatter_grants:
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.TOOL_GRANT_CHANGED,
                    file=safe_path,
                    block_index=None,
                    summary=f"'{safe_path}' front-matter tool grants changed",
                )
            )
        base_inline_tools = base.inline_tools[0] if base is not None else frozenset()
        head_inline_tools, head_tool_locs = head.inline_tools
        diff_tools = set(base_inline_tools ^ head_inline_tools)
        base_imports = base.imports[0] if base is not None else frozenset()
        head_imports, head_import_locs = head.imports
        added_imports = set(head_imports - base_imports)
        if base is not None:
            for name in base.signal_readings.keys() & head.signal_readings.keys():
                old_tools, old_imports = base.signal_readings[name]
                new_tools, new_imports = head.signal_readings[name]
                diff_tools.update(old_tools ^ new_tools)
                added_imports.update(new_imports - old_imports)
        if diff_tools:
            blk, line_no = _pick_loc(head_tool_locs, changed_indices, changed_set, min(diff_tools))
            txt = _get_text(blk, line_no)
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.TOOL_GRANT_CHANGED,
                    file=safe_path,
                    block_index=blk,
                    summary=f"'{safe_path}' inline tool grants changed",
                    text=txt,
                )
            )

        # 3. import_added
        for imp in sorted(added_imports):
            blk, line_no = _pick_loc(head_import_locs, changed_indices, changed_set, imp)
            txt = _get_text(blk, line_no)
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.IMPORT_ADDED,
                    file=safe_path,
                    block_index=blk,
                    summary=f"'{safe_path}' added import '{neutralize(redact_text(imp))}'",
                    text=txt,
                )
            )

        # 4. url_or_path_added
        base_refs = base.refs[0] if base is not None else frozenset()
        head_refs, head_ref_locs = head.refs
        for ref in sorted(head_refs - base_refs):
            blk, line_no = _pick_loc(head_ref_locs, changed_indices, changed_set, ref)
            txt = _get_text(blk, line_no)
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.URL_OR_PATH_ADDED,
                    file=safe_path,
                    block_index=blk,
                    summary=f"'{safe_path}' added URL or path '{neutralize(redact_text(ref))}'",
                    text=txt,
                )
            )

        # 5. hidden_markup_added (per-codepoint/category comparison avoids ZWSP->tag swaps)
        base_hidden = base.hidden_signatures if base is not None else Counter()
        base_uni = base.hidden_unicode if base is not None else {}
        new_markup = any(
            cnt > base_hidden.get(sig, 0) for sig, cnt in head.hidden_signatures.items()
        )
        new_unicode = any(cnt > base_uni.get(ch, 0) for ch, cnt in head.hidden_unicode.items())
        if new_markup or new_unicode:
            blk = changed_indices[0] if changed_indices else None
            txt = _get_text(blk)
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.HIDDEN_MARKUP_ADDED,
                    file=safe_path,
                    block_index=blk,
                    summary=f"'{safe_path}' added hidden markup or invisible Unicode",
                    text=txt,
                )
            )

    for rel_path in sorted(base_records.keys() - head_records.keys()):
        removed = base_records[rel_path]
        if removed.frontmatter_grants or removed.inline_tools[0]:
            changes.append(
                InstructionChange(
                    change_class=InstructionChangeClass.TOOL_GRANT_CHANGED,
                    file=neutralize(rel_path),
                    block_index=None,
                    summary=f"'{neutralize(rel_path)}' is gone, with its tool grants or limits",
                )
            )

    by_class: dict[str, int] = {}
    for item in changes:
        by_class[item.change_class.value] = by_class.get(item.change_class.value, 0) + 1
    total_failures = len(base_failures) + len(head_failures)
    total_excluded = len(base_excluded) + len(head_excluded)

    return {
        "format": FORMAT,
        "base_tree": neutralize(base_tree.name or str(base_tree)),
        "head_tree": neutralize(head_tree.name or str(head_tree)),
        "files_scanned": {"base": len(base_records), "head": len(head_records)},
        "failures": {"base": base_failures, "head": head_failures},
        "excluded": {"base": base_excluded, "head": head_excluded},
        "changes": [c.to_dict(show_text=show_text) for c in changes],
        "summary": {
            "total_changes": len(changes),
            "total_failures": total_failures,
            "total_excluded": total_excluded,
            "by_class": by_class,
        },
    }


@click.command("diff-instructions")
@click.argument(
    "base_tree",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.argument(
    "head_tree",
    type=click.Path(exists=True, file_okay=False, path_type=Path),
)
@click.option(
    "--show-text",
    is_flag=True,
    help="Include redacted, terminal-neutralized changed block text (withheld by default).",
)
@click.option("--json-output", is_flag=True, help="Print the instruction diff as JSON.")
@click.option(
    "--fail-on-change",
    is_flag=True,
    help="Exit with status 1 if any security-relevant instruction change is detected.",
)
def diff_instructions(
    base_tree: Path,
    head_tree: Path,
    show_text: bool,
    json_output: bool,
    fail_on_change: bool,
) -> None:
    """Compare instruction files between BASE_TREE and HEAD_TREE for security-relevant changes."""
    report = diff_instruction_trees(base_tree, head_tree, show_text=show_text)
    if json_output:
        click.echo(json_text(json.dumps(report, indent=2)))
    else:
        total = report["summary"]["total_changes"]
        total_failures = report["summary"]["total_failures"]
        echo_line(
            "Instruction diff: ",
            f"{total} change(s), {total_failures} failure(s) across "
            f"{report['files_scanned']['head']} head file(s).",
        )
        for side in ("base", "head"):
            for failure in report["failures"][side]:
                echo_line(f"  [failure:{side}] ", failure)
            for excluded in report["excluded"][side]:
                echo_line(f"  [excluded:{side}] ", excluded)
        for item in report["changes"]:
            loc = f" [block {item['block_index']}]" if item["block_index"] is not None else ""
            echo_line(f"  [{item['class']}]{loc} ", item["summary"])
            if show_text and item.get("text"):
                for line in str(item["text"]).splitlines():
                    echo_line("    | ", line)
    base_excluded_set = set(report["excluded"]["base"])
    new_head_excluded = [e for e in report["excluded"]["head"] if e not in base_excluded_set]
    if report["summary"]["total_failures"] > 0 or (
        fail_on_change and (report["summary"]["total_changes"] > 0 or bool(new_head_excluded))
    ):
        raise click.exceptions.Exit(1)


def register_instruction_diff_commands(main: click.Group) -> None:
    main.add_command(diff_instructions)
