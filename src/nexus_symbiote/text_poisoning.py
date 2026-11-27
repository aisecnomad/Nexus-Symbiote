"""Deterministic linear-time text-poisoning and prompt-injection rules.

Runs offline over the text of collected components: tool descriptions and schemas,
agent cards, and the instruction, skill, tool and configuration files that the
selected collectors recorded as component sources. It reads no other file. Every
rule is a bounded lexical scan, so the pass is O(N) in the scanned text. Default-
ignorable code points are removed and the rest is NFKC-normalized before matching,
with a map back to UTF-8 byte offsets. JSON, JSONC, YAML and TOML sources and Markdown
front matter are also read as the strings they decode to. Findings are appended to the owning existing
components; matched payload text and secret values are never written into them.
"""

from __future__ import annotations

import io
import json
import re
import sys
import tokenize
import unicodedata
from bisect import bisect_left, bisect_right
from collections import Counter, deque
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field, replace
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import MAX_JSON_NESTING, json_nesting_exceeds
from nexus_symbiote.core.models import (
    A2AServerComponent,
    AgentComponent,
    IDEAgentComponent,
    MCPServerComponent,
    PromptComponent,
    RiskAssessment,
    SkillPackageComponent,
    ToolComponent,
)
from nexus_symbiote.scanners.base import YAML_TOKEN_LIMIT
from nexus_symbiote.scanners.prompt import HIDDEN_CHARACTERS
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.jsonc import strip_jsonc
from nexus_symbiote.utils.markdown import front_matter_candidates
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.utils.toml import loads as toml_loads

RULE_PACK_VERSION = "1.1.0"

CATEGORY_TOOL_POISONING = "tool_description_poisoning"
CATEGORY_INSTRUCTION_INJECTION = "instruction_injection"

_RULE_REFERENCE_PREFIX = "rule:"

_MAX_TAG_BODY_CHARS = 800
_MAX_COMMENT_BODY_CHARS = 1_200
_MAX_WHERE_CHARS = 160
_MAX_UNRESOLVED_RISKS_PER_SURFACE = 16
_MAX_OVERFLOW_LOCATIONS = 12
_JSON_STRING_RE = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)

# Skill resources other than text declarations (scripts, images) are files the skill may
# use, not text loaded as instructions; every other collected source is scanned.
_TEXT_DECLARATION_SUFFIXES = frozenset(
    {".md", ".mdc", ".markdown", ".txt", ".json", ".yaml", ".yml", ".toml", ".prompt"}
)
# JSON pointer segments printed in findings: indexes and these field names. Any other
# key is printed as "*", since a key can hold a value as sensitive as a secret.
_POINTER_FIELDS = frozenset(
    {
        "mcpServers",
        "servers",
        "mcp_servers",
        "tools",
        "function",
        "inputSchema",
        "input_schema",
        "parameters",
        "properties",
        "items",
        "additionalProperties",
        "anyOf",
        "oneOf",
        "allOf",
        "$defs",
        "definitions",
        "description",
        "title",
        "name",
        "skills",
        "annotations",
        "instructions",
        "prompt",
        "args",
        "command",
        "examples",
        "default",
        "enum",
    }
)
_SIDE_CHANNEL_PARAM_NAMES = frozenset(
    {
        "note",
        "notes",
        "debug",
        "telemetry",
        "meta",
        "metadata",
        "audit",
        "query",
        "context",
        "extra",
        "extras",
        "callback",
        "webhook",
        "reason",
        "comment",
    }
)
# Typographic apostrophes fold to ASCII so that "Don’t tell" reads as "Don't tell".
_APOSTROPHES = {"‘": "'", "’": "'"}
# A host passes a model the strings these formats, and the YAML front matter of a Markdown
# file, decode to, where an escape such as \u0049 spells "I"; the rules read those strings
# as well as the raw text.
_DECODED_FORMATS = {".jsonc": "JSON", ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML"}
_MARKDOWN_SUFFIXES = frozenset({".md", ".mdc", ".markdown"})
_CODE_SOURCE_SUFFIXES = frozenset(
    {".py", ".pyi", ".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs"}
)
# The bounds the prompt collector parses YAML and TOML within: the parsers are pure Python,
# and PyYAML's cost grows with flow nesting. Past them, escapes are decoded by pattern.
_MAX_PARSED_CHARS = 65_536
_MAX_YAML_FLOW_DEPTH = 64
_FLOW_BRACKETS_RE = re.compile(r"[\[\]{}]")
# Every escape a JSON, YAML, TOML, Python or JS/TS string can hold, a line continuation
# and YAML's ''. Decoding them anywhere, inside a literal string or a comment too, only
# adds findings.
_ESCAPE_RE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|u\{([0-9A-Fa-f]++)\}"
    r"|[ \t]*\r?\n\s*|(.))|''",
    re.S,
)
_NAMED_ESCAPES = {
    "n": "\n",
    "t": "\t",
    "r": "\r",
    "b": "\b",
    "f": "\f",
    "v": "\v",
    "a": "\a",
    "0": "\0",
    "e": "\x1b",
    "L": "\u2028",
    "P": "\u2029",
    "N": "\x85",
    "_": "\xa0",
}
# A comment opener left open hides nothing past the paragraph it opens in.
_BLANK_LINE_RE = re.compile(r"\n[ \t]*\r?\n")
# Fences and code spans as generously as any reader finds them, inside quotes and list
# items too: a "<!--" taken for code is not masked, which can only add findings.
_FENCE_OPEN_RE = re.compile(r"^[ \t>*+\-.)0-9]*?((?>`{3,})(?![^\n]*`)|~{3,})", re.M)
_FENCE_CLOSE_RE = re.compile(r"^[ \t>]*(`{3,}|~{3,})[ \t]*\r?$", re.M)
_BACKTICK_RUN_RE = re.compile(r"`+")

_DIRECTIVE_TAG_OPEN_RE = re.compile(
    r"<((?:important|system|instructions?|hidden|secret|override)[\w-]{0,40})\b[^>]{0,120}>",
    re.IGNORECASE,
)
_CLOSE_TAG_RE = re.compile(r"</\s*([\w-]{1,60})\s*>")
_DESTRUCTIVE = (
    r"\b(?:drop\s+table|delete\s+from\s+(?!(?:the|a|an|any|this|that|your|my)\b)[\w.`\"]+|"
    r"delete\s+from\s+the\s+[\w.`\"]+\s+table|"
    r"truncate\s+table|alter\s+table|rm\s+-rf)\b"
)
# "ignore" or "disregard" right after a negation is advice, not an override.
_NOT_NEGATED = r"(?<!not )(?<!never )(?<!n't )"

_TAG_EXFIL_ACTION_RE = re.compile(
    r"(?:"
    r"never\s+tell|do\s+not\s+tell|don't\s+tell|"
    r"do\s+not\s+mention|don't\s+mention|without\s+telling|"
    r"hide\s+(?:this|it)\s+from|"
    rf"{_NOT_NEGATED}ignore\s+(?:read[- ]only|all\s+(?:previous|prior|above|safety|"
    r"(?!(?:files|folders|directories|tests|warnings|paths)\b)\w+s\b)|"
    r"previous|prior|above|safety)|"
    rf"{_NOT_NEGATED}disregard\s+(?:all|previous|prior|above)|"
    rf"{_DESTRUCTIVE}|"
    r"--export-tokens|"
    r"\b(?:read|include|pass|send|forward|upload|post|exfiltrate|export)\b.{0,80}"
    r"(?:\.ssh\b|~/\.aws|\bid_(?:rsa|dsa|ecdsa|ed25519)\b|credentials|\.netrc|\.npmrc|\.pypirc|"
    r"\.env)|"
    # A URL is a destination only for a sending verb; "read the guide at https://..." is not.
    r"\b(?:send|forward|upload|post|exfiltrate|export)\b.{0,80}https?://|"
    r"\b(?:pass|include)\b[^.]{0,40}\b(?:conversation|history|messages?|contents?|file|output|"
    r"transcript)\b.{0,60}https?://"
    r")",
    re.IGNORECASE | re.DOTALL,
)

_COMMENT_ATTACK_RE = re.compile(
    r"(?:"
    r"\b(?:ignore|disregard)\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|system)\s+"
    r"(?:instructions?|directives?|rules?|constraints?|prompts?)\b|"
    r"\bapprove\s+every\b|"
    r"\bbypass\s+(?:all\s+|any\s+)?(?:approval|check|validation|review|safety)\b|"
    r"\b(?:forward|send|exfiltrate|export|upload)\s+(?:(?:every|all|any|each|the)\s+)?"
    r"(?:user'?s?\s+)?"
    r"(?:quer(?:y|ies)|prompts?|messages?|conversations?|sessions?|tokens?|credentials?|secrets?|"
    r"keys?|inputs?|it|files?|contents?|outputs?|history|transcripts?)\b.{0,80}https?://|"
    r"--export-tokens|"
    r"\b(?:read|copy|include|pass)\b.{0,60}(?:\.ssh\b|~/\.aws|\bid_rsa\b|credentials)|"
    rf"{_DESTRUCTIVE}|"
    r"\b(?:never\s+tell|do\s+not\s+mention(?:\s+this)?)\b.{0,40}\busers?\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)

_CONCEAL_RE = re.compile(
    r"\b(?:"
    r"never\s+tell|"
    r"do\s+not\s+tell|don't\s+tell|"
    r"do\s+not\s+mention(?:\s+this|\s+that|\s+it)?|don't\s+mention(?:\s+this|\s+that|\s+it)?|"
    r"do\s+not\s+inform|don't\s+inform|"
    r"without\s+telling|without\s+informing|"
    r"hide\s+(?:this|it)\s+from"
    r")\s+(?:to\s+)?(?:the\s+)?(?:end[- ]?)?users?\b"
    # "Never tell the user to ..." gives the user advice; it hides nothing from them.
    r"(?!\s+to\b|\s+(?:any\s+|their\s+|our\s+|your\s+)?"
    r"(?:private|secret|sensitive|confidential|credential|credentials|key|keys|token|tokens|password|passwords|secrets)\b)",
    re.IGNORECASE,
)

_CRED_PATH_RE = re.compile(
    r"(?:[/\\]\.ssh(?![\w-])(?![/\\](?:known_hosts|authorized_keys|config)\b)(?:[/\\][\w.-]+)?|[/\\]\.aws[/\\]credentials\b|"
    r"\bid_(?:rsa|dsa|ecdsa|ed25519)\b(?:\.pub\b)?|\.netrc\b|\.git-credentials\b|"
    r"\.pypirc\b|\.npmrc\b)",
    re.IGNORECASE,
)
# The path must be read or relayed by a verb earlier in its own sentence ("Read the
# user's ~/.ssh/id_rsa and pass it ..."). A line break inside a sentence is whitespace.
_SENTENCE_BREAK_RE = re.compile(r"[.!?]+(?=\s)|\n[ \t]*\n")
_CRED_VERB_RE = re.compile(
    r"\b(?:read|cat|open|load|copy|include|pass|send|forward|upload|post|append|exfiltrate|"
    r"export|embed|attach|dump|print|grab|fetch|get|retrieve|access|collect|extract)\b",
    re.IGNORECASE,
)
# A prohibition negates the verb itself: "never read", "must not read or include",
# "refuse any request to read", "never, under any circumstances, read", with only adverbs
# or a coordinated verb between. "Don't worry, read", "do not forget to read" and "why
# not read" do not.
_VERB_NEGATED_RE = re.compile(
    r"(?<!why )(?<!you )\b(?:never|not|n't|cannot|refuse(?:\s+any)?(?:\s+requests?)?\s+to|"
    r"decline\s+to)(?:\s*,\s*(?:under\s+any\s+circumstances|for\s+any\s+reason|ever)\s*,)?"
    r"(?:\s+(?:ever|just|simply|directly|even))*"
    r"(?:\s+(?:read|open|copy|include|pass|send|forward|upload|post|cat)\s+(?:or|nor))?\s*$",
    re.IGNORECASE,
)
_SENTENCE_LOOKBACK = 240

_CRED_RELAY_WINDOW_RE = re.compile(
    r"(?:"
    r"\b(?:pass|include|send|forward|upload|post|append|exfiltrate|export|embed)\b"
    r".{0,90}\b(?:parameter|param|field|query|note|body|header|payload|contents?|arguments?|args|https?://)\b|"
    r"\bbefore\s+calling\b.{0,80}\bread\b"
    r")",
    re.IGNORECASE | re.DOTALL,
)

_EXFIL_URL_RE = re.compile(
    r"(?:"
    r"--export-tokens\b.{0,120}(?:https?://|--to\b)|"
    r"\b(?:forward|send|exfiltrate|post|upload|relay)\s+"
    r"(?:every|all|any|each|user|session|incoming|prompt|query)\s+"
    r"(?:[a-z_-]{1,24}\s+){0,3}to\s+https?://"
    r")",
    re.IGNORECASE,
)
# Network sinks and the commands that read a credential path into a pipe.
# Order does not matter: ``cat file | curl`` and ``base64 file | curl`` are the
# same finding. A sentence that only mentions both is not a pipeline.
# Names are the command word; ``/dev/tcp`` and ``/dev/udp`` are bash redirections.
_SHELL_SINK_NAMES = (
    "curl",
    "wget",
    "nc",
    "scp",
    "rsync",
    "sftp",
    "ftp",
    "socat",
    "ncat",
    "telnet",
    "ssh",
)
_SHELL_SINKS = frozenset(_SHELL_SINK_NAMES)
_DEV_NET_REDIRECTS = ("/dev/tcp", "/dev/udp")
# ``~``, ``$HOME`` and ``${HOME}`` become this marker so every spelling of a home
# path contains ``/.ssh`` the credential-path rule already matches.
_HOME_MARKER = "/home"
_SHELL_READERS = frozenset(
    {"cat", "base64", "xxd", "gzip", "openssl", "od", "dd", "head", "tail", "cut"}
)
_SHELL_TOKEN_RE = re.compile(r"\S+")
_PLAIN_WORD_RE = re.compile(r"[A-Za-z]{2,}")
_SHELL_PLAIN_WORDS = 1
# A continued command or a substitution longer than this is a finding, not a miss.
_SHELL_WINDOW_CHARS = 4096
_SHELL_WINDOW_LINES = 32
_SUBST_CHARS = 4096

_OVERRIDE_RE = re.compile(
    rf"\b{_NOT_NEGATED}(?:"
    r"ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|system)\s+"
    r"(?:(?:safety|security|guardrail)\s+)?(?:instructions?|directives?|rules?|constraints?|prompts?)|"
    r"disregard\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|above|earlier|preceding|system)\s+"
    r"(?:(?:safety|security|guardrail)\s+)?(?:instructions?|directives?|rules?|constraints?|prompts?)|"
    r"forget\s+(?:all\s+|everything\s+)?(?:you\s+were\s+told|previous\s+instructions?|prior\s+instructions?)|"
    r"override\s+(?:all\s+|the\s+)?(?:system\s+prompt|safety\s+rules?|approval\s+checks?)"
    r")\b",
    re.IGNORECASE,
)

_READONLY_OVERRIDE_RE = re.compile(
    r"\bignore\s+read[- ]only\b.{0,120}\b"
    rf"(?:{_DESTRUCTIVE}|insert\s+into|update\s+)",
    re.IGNORECASE | re.DOTALL,
)

_SUBJECT = r"(?:this\s+|the\s+)?(?:repository|repo|codebase|project|agent|it)"
_VERDICT = r"(?:compliant|clean|safe|benign|low[- ]risk|passing)"
_AUDITOR_DECEIT_RE = re.compile(
    r"\b(?:"
    # A note to reviewers is deception only when it tells them what to conclude.
    r"note\s+to\s+(?:any\s+)?(?:automated\s+)?(?:auditor|auditors|reviewer|reviewers|ai\s+reviewer|"
    r"scanner|scanners|security\s+tool)\b.{0,160}?\b(?:compliant|clean|safe|benign|passing|"
    r"contains\s+no|report|mark|treat|classify|declare|suppress|hide|omit|skip|approved?|"
    r"pre-approved|stop|verified|no\s+need)|"
    rf"(?:report|classify|declare)\s+{_SUBJECT}\s+as\s+{_VERDICT}|"
    r"this\s+(?:repository|repo|project|codebase)\s+contains\s+no\s+"
    r"(?:mcp\s+servers?|models?|secrets?|vulnerabilities|risks)\b.{0,120}\b(?:report|compliant|safe|clean)"
    r")\b",
    re.IGNORECASE | re.DOTALL,
)
# Directives that ordinary build instructions also use ("suppress warnings in CI logs")
# count only when an auditor or scanner is addressed near them.
_AUDITOR_DIRECTIVE_RE = re.compile(
    rf"\b(?:(?:mark|treat)\s+{_SUBJECT}\s+as\s+{_VERDICT}|"
    r"(?:suppress|hide|omit|skip)\s+(?:all\s+|any\s+)?(?:security\s+)?"
    r"(?:findings|warnings|risks|alerts|vulnerabilities|mcp\s+servers?))\b",
    re.IGNORECASE,
)
_AUDITOR_ADDRESSEE_RE = re.compile(
    r"\b(?:auditors?|reviewers?|scanners?|security\s+tools?)\b", re.IGNORECASE
)
_ADDRESSEE_WINDOW = 120

_NEGATED_PREFIX_RE = re.compile(
    r"\b(?:never|do\s+not|don't|not\s+to|prohibit|forbid)\s*[\"']?\s*$",
    re.IGNORECASE,
)

_TOOL_NAME_CALL_TEMPLATES = (
    '.tool("{name}"',
    ".tool('{name}'",
    "def {name}(",
    'name": "{name}"',
    "name': '{name}'",
    '"{name}"',
    "'{name}'",
    ".{name}]",
    "[{name}]",
)
_YAML_PLAIN_NAME = re.compile(r"""(?m)^[ \t]*(?:-[ \t]+)?name:[ \t]+([^\s#,'"}\]]+)[ \t]*(?=#|$)""")

_RULE_DESCRIPTIONS: dict[str, str] = {
    "TP-TAG-001": "coercive directive XML-style tag containing override, secret-read, or exfiltration action",
    "TP-CMT-001": "hidden HTML comment containing override, secret-read, or exfiltration directive",
    "TP-CRED-002": "credential/sensitive file read or exfiltration URL directive",
    "TP-CONCEAL-003": "user-concealment directive instructing agent not to inform user",
    "II-OVR-001": "prompt-injection instruction override directive",
    "II-AUD-002": "automated-auditor or scanner deception directive",
    "TP-SIDENOTE-004": "side-channel parameter targeting or read-only annotation contradiction",
}


@dataclass(frozen=True)
class TextPoisoningHit:
    """Single deterministic finding produced by the text-poisoning rule pack.

    ``byte_offset`` counts UTF-8 bytes from the start of the scanned text: the file,
    or, when ``where`` names a JSON pointer or component field, that string.
    """

    rule_id: str
    category: str
    severity: RiskSeverity
    byte_offset: int
    surface: str
    summary: str
    where: str = ""
    unresolved_declaration: int = 0


ComponentWithRisks = (
    AgentComponent
    | MCPServerComponent
    | ToolComponent
    | PromptComponent
    | SkillPackageComponent
    | A2AServerComponent
    | IDEAgentComponent
)
_COMPONENT_KINDS = (
    AgentComponent,
    MCPServerComponent,
    ToolComponent,
    PromptComponent,
    SkillPackageComponent,
    A2AServerComponent,
    IDEAgentComponent,
)
_INSTRUCTION_KINDS = (PromptComponent, SkillPackageComponent)
_ATTRIBUTION_PRIORITY = (
    ToolComponent,
    PromptComponent,
    SkillPackageComponent,
    A2AServerComponent,
    MCPServerComponent,
    IDEAgentComponent,
)


def _utf8_width(ch: str) -> int:
    # A JSON value can hold a lone surrogate ("\ud800"), which str.encode refuses.
    code = ord(ch)
    if code < 0x80:
        return 1
    if code < 0x800:
        return 2
    if code < 0x10000:
        return 3
    return 4


MAX_LEXICAL_NORMALIZED_CHARS = 8 * 1024 * 1024


def normalize_for_lexical_scan(text: str) -> tuple[str, list[int]]:
    """Remove default-ignorable code points and NFKC-fold the rest in one O(N) pass.

    Each character is folded on its own, so fullwidth or compatibility forms of
    markup (``＜IMPORTANT＞``) read as ASCII. Returns the folded string plus a list
    mapping each of its characters back to the UTF-8 byte offset in ``text`` of the
    character it came from.
    """
    cap = max(
        min(len(text) + 65_536, MAX_LEXICAL_NORMALIZED_CHARS),
        min(max(4 * len(text), 262_144), 4 * 1024 * 1024),
    )
    folded: list[str] = []
    byte_offsets: list[int] = []
    byte_pos = 0
    for ch in text:
        if ch < "\x80":
            if len(folded) >= cap:
                raise ValueError("lexical normalization expansion limit exceeded")
            folded.append(ch)
            byte_offsets.append(byte_pos)
        elif unicodedata.category(ch) != "Cf" and HIDDEN_CHARACTERS.match(ch) is None:
            for part in _APOSTROPHES.get(ch) or unicodedata.normalize("NFKC", ch):
                if len(folded) >= cap:
                    raise ValueError("lexical normalization expansion limit exceeded")
                folded.append(part)
                byte_offsets.append(byte_pos)
        byte_pos += _utf8_width(ch)
    return "".join(folded), byte_offsets


def _byte_offset_at(byte_offsets: list[int], char_index: int) -> int:
    if not byte_offsets:
        return 0
    return byte_offsets[min(max(char_index, 0), len(byte_offsets) - 1)]


def _has_negated_prefix(text: str, pos: int) -> bool:
    window = text[max(0, pos - 40) : pos]
    return _NEGATED_PREFIX_RE.search(window[window.rfind("\n") + 1 :]) is not None


def _default_category(is_tool_surface: bool) -> str:
    return CATEGORY_TOOL_POISONING if is_tool_surface else CATEGORY_INSTRUCTION_INJECTION


def _directive_tag_hits(normalized: str) -> Iterator[int]:
    """Yield the start of each directive tag whose body holds a coercive action, in O(N).

    A body ends at its matching close tag or after ``_MAX_TAG_BODY_CHARS``. A tag that
    opens inside a body extends it, so neither a decoy tag inside a body nor one shortly
    before a tag can cut the text short. Each such chain is searched once, from its
    first unnegated tag, and close tags are found in one pass, so the work is linear.
    Tag names are compared on the short names alone, never by lowercasing the text,
    which can change its length.
    """
    closes: dict[str, deque[int]] = {}
    for close in _CLOSE_TAG_RE.finditer(normalized):
        closes.setdefault(close.group(1).lower(), deque()).append(close.start())
    chain: tuple[int, int] | None = None
    chain_end = pos = 0
    while True:
        opened = _DIRECTIVE_TAG_OPEN_RE.search(normalized, pos)
        if chain is not None and (opened is None or opened.start() >= chain_end):
            if _TAG_EXFIL_ACTION_RE.search(normalized, chain[1], chain_end) is not None:
                yield chain[0]
            chain = None
        if opened is None:
            return
        start = pos = opened.end()
        end = min(len(normalized), start + _MAX_TAG_BODY_CHARS)
        pending = closes.get(opened.group(1).lower(), deque())
        while pending and pending[0] < start:
            pending.popleft()
        if pending and pending[0] < end:
            end = pending[0]
        if chain is not None:
            chain_end = max(chain_end, end)
        elif not _has_negated_prefix(normalized, opened.start()):
            chain, chain_end = (opened.start(), start), end


def _verb_is_negated(text: str, verb_start: int) -> bool:
    """Whether a prohibition ends at ``verb_start``, as the credential-path rule reads it.

    A substitution opener (``$(`` or a backtick) sitting on the verb is not a word, so
    the prohibition is read at the opener: ``must not $(cat`` is still a prohibition.
    """
    end = verb_start
    if text[max(0, verb_start - 2) : verb_start] == "$(":
        end = verb_start - 2
    elif verb_start > 0 and text[verb_start - 1] == "`":
        end = verb_start - 1
    start = max(0, end - 80)
    if _VERB_NEGATED_RE.search(text, start, end) is not None:
        return True
    return _has_negated_prefix(text, end)


def _expand_home(fragment: str) -> str:
    """Expand a leading ``~`` and every ``$HOME`` / ``${HOME}`` to one marker."""
    if fragment.startswith("~") and (len(fragment) == 1 or fragment[1] == "/"):
        fragment = _HOME_MARKER + fragment[1:]
    return fragment.replace("${HOME}", _HOME_MARKER).replace("$HOME", _HOME_MARKER)


def _shell_word(token: str) -> str:
    """The command word of a token, ignoring a glued ``$(`` or a closing paren."""
    word = _expand_home(token).lower().strip("$#@()|;<>\"'")
    if "/" in word:
        word = word.rsplit("/", 1)[-1].strip("$#@()|;<>\"'")
    return word


def _is_network_sink(token: str) -> bool:
    if _shell_word(token) in _SHELL_SINKS:
        return True
    lowered = token.lower()
    return any(redirect in lowered for redirect in _DEV_NET_REDIRECTS)


def _credential_path(token: str) -> re.Match[str] | None:
    found = _CRED_PATH_RE.search(_expand_home(token.strip("\"'")))
    if found is None or found.group().lower().endswith(".pub"):
        return None
    return found


def _matching_quote(text: str, open_at: int, end: int) -> int | None:
    """Index of the closer for the quote at ``open_at``, or None when it never closes.

    Double quotes treat a backslash as an escape. The scan is one forward pass and
    stops at ``end``, which is already the window cap.
    """
    quote = text[open_at]
    index = open_at + 1
    while index < end:
        if quote == '"' and text[index] == "\\" and index + 1 < end:
            index += 2
            continue
        if text[index] == quote:
            return index
        index += 1
    return None


def _line_ends_continued(text: str, line_start: int, line_end: int) -> bool:
    end = line_end
    while end > line_start and text[end - 1] in " \t\r":
        end -= 1
    if end > line_start and text[end - 1] == "\\":
        return True
    tail = text[line_start:end].rstrip(" \t")
    return tail.endswith(("|", ";", "&&", "||"))


def _next_starts_continued(text: str, index: int) -> bool:
    if index >= len(text):
        return False
    while index < len(text) and text[index] in " \t":
        index += 1
    return text.startswith(("|", "&&", "||"), index)


def _next_is_lone_path(text: str, index: int) -> bool:
    if index >= len(text):
        return False
    line_end = text.find("\n", index)
    if line_end < 0:
        line_end = len(text)
    tokens = _SHELL_TOKEN_RE.findall(text[index:line_end])
    return len(tokens) == 1 and _credential_path(tokens[0]) is not None


def _window_has_verb(text: str, start: int, end: int) -> bool:
    for token in _SHELL_TOKEN_RE.findall(text[start:end]):
        if _is_network_sink(token) or _shell_word(token) in _SHELL_READERS:
            return True
    return False


def _logical_windows(text: str) -> Iterator[tuple[int, int, bool]]:
    """Continued shell lines as ``(start, end, truncated)``. One forward pass.

    A backslash, a trailing or leading pipe, ``&&`` / ``||`` / ``;``, or a path
    that occupies the next line by itself extends the window. Past the character
    or line cap the window is truncated and the caller fails closed.
    """
    length = len(text)
    index = 0
    while index < length:
        start = index
        end = text.find("\n", index)
        if end < 0:
            end = length
        lines = 1
        truncated = False
        while end < length:
            line_start = text.rfind("\n", start, end) + 1
            lone_path = _window_has_verb(text, start, end) and _next_is_lone_path(text, end + 1)
            if not (
                _line_ends_continued(text, line_start, end)
                or _next_starts_continued(text, end + 1)
                or lone_path
            ):
                break
            nxt = text.find("\n", end + 1)
            if nxt < 0:
                nxt = length
            if lines >= _SHELL_WINDOW_LINES or nxt - start > _SHELL_WINDOW_CHARS:
                truncated = True
                break
            end = nxt
            lines += 1
        yield start, end, truncated
        index = end + 1 if end < length else length


def _shell_stages(text: str, start: int, end: int) -> list[list[tuple[int, str]]]:
    """Stages of one command, split on ``|``, ``||``, ``&&`` and ``;``.

    Single and double quotes are removed and ``~``, ``$HOME`` and ``${HOME}``
    expand to one home marker, so ``cat "$HOME/.ssh/id_rsa" | "curl"`` is the
    same pair of words as the unquoted command. An unbalanced quote does not
    swallow the rest: the raw remainder is tokenised. Bytes inside ``$(...)``
    or a one-backtick substitution are left to the substitution scan. A
    backslash-newline is whitespace. The walk is one pass.
    """
    stages: list[list[tuple[int, str]]] = [[]]
    index = start
    subst = 0
    tick = False
    word_at: int | None = None
    parts: list[str] = []

    def flush() -> None:
        nonlocal word_at
        if parts:
            stages[-1].append((word_at if word_at is not None else index, "".join(parts)))
            parts.clear()
            word_at = None

    while index < end:
        char = text[index]
        if char == "\\" and index + 1 < end and text[index + 1] == "\n":
            index += 2
            continue
        if tick:
            if char == "`":
                tick = False
            index += 1
            continue
        if text.startswith("$(", index) and subst == 0 and not parts:
            subst += 1
            index += 2
            continue
        if char == "(" and subst:
            subst += 1
            index += 1
            continue
        if char == ")" and subst:
            subst -= 1
            index += 1
            continue
        if subst:
            index += 1
            continue
        if char == "`":
            run = index + 1
            while run < end and text[run] == "`":
                run += 1
            if run - index != 1:
                flush()
                index = run
                continue
            tick = True
            index += 1
            continue
        if char in "\"'":
            close = _matching_quote(text, index, end)
            if close is None:
                # The quote never closes. Keep the following bytes in the raw scan.
                index += 1
                continue
            if word_at is None:
                word_at = index
            parts.append(_expand_home(text[index + 1 : close]))
            index = close + 1
            continue
        if text.startswith(("&&", "||"), index) or char in "|;":
            flush()
            stages.append([])
            index += 2 if text.startswith(("&&", "||"), index) else 1
            continue
        if char.isspace():
            flush()
            index += 1
            continue
        if word_at is None:
            word_at = index
        token_end = index + 1
        while (
            token_end < end and not text[token_end].isspace() and text[token_end] not in "|;`'\"()"
        ):
            if text.startswith(("&&", "||"), token_end):
                break
            token_end += 1
        parts.append(_expand_home(text[index:token_end]))
        index = token_end
    flush()
    return stages


def _plain_between(tokens: list[tuple[int, str]], left: int, right: int) -> int:
    lo, hi = sorted((left, right))
    return sum(1 for index in range(lo + 1, hi) if _PLAIN_WORD_RE.fullmatch(tokens[index][1]))


def _stage_reads(tokens: list[tuple[int, str]]) -> int | None:
    """Offset of a credential path this stage reads, or None.

    The reader and the path have to be near each other, so ``cat the manual and
    mention ~/.ssh/id_rsa`` is prose. A redirect or an ``@path`` argument is a read
    on its own.
    """
    readers = [i for i, (_, token) in enumerate(tokens) if _shell_word(token) in _SHELL_READERS]
    paths: list[tuple[int, int, str]] = []
    for index, (pos, token) in enumerate(tokens):
        found = _credential_path(token)
        if found is not None:
            paths.append((index, pos + found.start(), token))
    for index, absolute, token in paths:
        previous = tokens[index - 1][1] if index else ""
        if token.startswith(("@", "<")) or previous == "<":
            return absolute
        if any(_plain_between(tokens, reader, index) <= _SHELL_PLAIN_WORDS for reader in readers):
            return absolute
    return None


def _stage_sink(tokens: list[tuple[int, str]]) -> bool:
    return any(_is_network_sink(token) for _, token in tokens)


def _sink_near_path(tokens: list[tuple[int, str]]) -> int | None:
    """A sink and a credential-path token with at most one plain word between them."""
    sinks = [i for i, (_, token) in enumerate(tokens) if _is_network_sink(token)]
    paths = [
        (i, pos + found.start())
        for i, (pos, token) in enumerate(tokens)
        if (found := _credential_path(token)) is not None
    ]
    for sink in sinks:
        for path_index, absolute in paths:
            if _plain_between(tokens, sink, path_index) <= _SHELL_PLAIN_WORDS:
                return absolute
    return None


def _first_shell_verb(text: str, start: int, end: int) -> int | None:
    for pos, token in (token for stage in _shell_stages(text, start, end) for token in stage):
        if _is_network_sink(token) or _shell_word(token) in _SHELL_READERS:
            return pos
    index = start
    while index < end:
        if text[index] == "`":
            run = index + 1
            while run < end and text[run] == "`":
                run += 1
            if run - index != 1:
                index = run
                continue
        if text.startswith("$(", index) or text[index] == "`":
            opener = 2 if text.startswith("$(", index) else 1
            body = index + opener
            cap = min(end, index + _SUBST_CHARS)
            while body < cap and text[body] not in " \t\n|;`'\"()":
                body += 1
            word = _shell_word(text[index + opener : body])
            if word in _SHELL_SINKS or word in _SHELL_READERS or _is_network_sink(word):
                return index + opener
        index += 1
    return None


def _pipeline_offset(text: str, start: int, end: int) -> int | None:
    """A pipeline or list where one stage reads a credential path and one is a sink."""
    stages = _shell_stages(text, start, end)
    reads = [found for stage in stages if (found := _stage_reads(stage)) is not None]
    sinks = any(_stage_sink(stage) for stage in stages)
    if reads and sinks:
        return reads[0]
    for stage in stages:
        found = _sink_near_path(stage)
        if found is not None:
            return found
    return None


def _substitution_offsets(text: str, start: int, end: int) -> Iterator[int]:
    """Command substitutions in ``text[start:end]``. An unclosed body past the cap is a hit."""
    index = start
    while index < end:
        if text[index] == "`":
            run = index + 1
            while run < end and text[run] == "`":
                run += 1
            # A fence or double backtick is Markdown, not a one-backtick substitution.
            if run - index != 1:
                index = run
                continue
        if not text.startswith("$(", index) and text[index] != "`":
            index += 1
            continue
        dollar = text.startswith("$(", index)
        opener = 2 if dollar else 1
        closer = ")" if dollar else "`"
        body = index + opener
        cap = min(end, index + _SUBST_CHARS)
        depth = 1
        while body < cap and depth:
            if dollar and text.startswith("$(", body):
                depth += 1
                body += 2
                continue
            if text[body] == closer:
                depth -= 1
                if depth == 0:
                    break
            body += 1
        if depth:
            # The cap hid the rest of the substitution. Fail closed.
            yield index
            index = body
            continue
        fragment = text[index + opener : body]
        verb = None
        path_at: int | None = None
        for token in _SHELL_TOKEN_RE.finditer(fragment):
            if _shell_word(token.group()) in _SHELL_READERS and verb is None:
                verb = token.start()
            if _credential_path(token.group()) is not None and path_at is None:
                path_at = token.start()
        if (
            verb is not None
            and path_at is not None
            and not _verb_is_negated(text, index + opener + verb)
        ):
            yield index + opener + path_at
        index = body + 1


def _window_interesting(text: str, start: int, end: int) -> bool:
    if "$(" in text[start:end] or _CRED_PATH_RE.search(text[start:end]) is not None:
        return True
    return _window_has_verb(text, start, end)


def _shell_exfil_offsets(normalized: str) -> Iterator[int]:
    """Offsets of a shell read of a credential path that reaches a network sink.

    A pipeline or command list hits when any stage reads the path (``cat``,
    ``base64``, ``xxd``, ``gzip``, ``openssl`` and the other readers, or a
    redirect) and any stage is ``curl``, ``wget`` or ``nc``, in either order.
    Continuations, including a backslash newline, are one bounded window. A
    substitution is scanned in full up to its cap; a body the cap cuts off is a
    hit rather than a miss. A prohibition and a sentence that only mentions the
    command stay quiet. A ``.pub`` path stays public. The walk is one pass.
    """
    reported: set[int] = set()
    for start, end, truncated in _logical_windows(normalized):
        verb = _first_shell_verb(normalized, start, end)
        if verb is not None and _verb_is_negated(normalized, verb):
            continue
        found = _pipeline_offset(normalized, start, end)
        if found is not None:
            reported.add(found)
        reported.update(_substitution_offsets(normalized, start, end))
        if truncated and _window_interesting(normalized, start, end):
            reported.add(start)
    yield from sorted(reported)


def scan_text_block(
    text: str,
    *,
    surface: str,
    is_tool_surface: bool = False,
    max_hits: int = 64,
    where: str = "",
) -> list[TextPoisoningHit]:
    """Scan a single text string using deterministic O(N) lexical rules."""
    if not text:
        return []

    normalized, byte_offsets = normalize_for_lexical_scan(text)
    if not normalized:
        return []

    hits: list[TextPoisoningHit] = []
    base_category = _default_category(is_tool_surface)

    def record(rule_id: str, category: str, char_index: int) -> None:
        if len(hits) < max_hits:
            hits.append(
                TextPoisoningHit(
                    rule_id=rule_id,
                    category=category,
                    severity=RiskSeverity.HIGH,
                    byte_offset=_byte_offset_at(byte_offsets, char_index),
                    surface=surface,
                    summary=_RULE_DESCRIPTIONS[rule_id],
                    where=where,
                )
            )

    # 1. TP-TAG-001: Directive tags containing coercive/exfiltration/override payload
    for tag_start in _directive_tag_hits(normalized):
        record("TP-TAG-001", base_category, tag_start)

    # 2. TP-CMT-001: HTML comments carrying override, exfil, or secret-read directives
    search_pos = 0
    while (cmt_start := normalized.find("<!--", search_pos)) != -1:
        # Read a possible body when the opener and closer overlap. Markdown masking
        # handles short empty comments separately so subsequent text stays visible.
        body_start = cmt_start + 4
        cmt_end = normalized.find("-->", body_start, body_start + _MAX_COMMENT_BODY_CHARS)
        stop = (
            cmt_end + 3
            if cmt_end != -1
            else min(len(normalized), body_start + _MAX_COMMENT_BODY_CHARS)
        )
        if _COMMENT_ATTACK_RE.search(normalized[body_start:stop]) is not None:
            record("TP-CMT-001", base_category, cmt_start)
        search_pos = stop

    # 3. TP-CRED-002: Sensitive credential path relay or exfiltration URL directive
    # Sentence breaks, verbs and negations are each read once, front to back.
    breaks = _SENTENCE_BREAK_RE.finditer(normalized)
    verbs = _CRED_VERB_RE.finditer(normalized)
    brk = verb = None
    sentence, last_verb = 0, -1
    for cred_match in _CRED_PATH_RE.finditer(normalized):
        at = cred_match.start()
        while (brk := brk or next(breaks, None)) is not None and brk.end() <= at:
            sentence, brk = brk.end(), None
        while (verb := verb or next(verbs, None)) is not None and verb.end() <= at:
            last_verb, verb = verb.start(), None
        start = max(sentence, at - _SENTENCE_LOOKBACK)
        if (
            cred_match.group().lower().endswith(".pub")
            or last_verb < start
            or _VERB_NEGATED_RE.search(normalized, max(start, last_verb - 40), last_verb)
        ):
            continue
        win_start = max(0, cred_match.start() - 120)
        win_end = min(len(normalized), cred_match.end() + 120)
        if _CRED_RELAY_WINDOW_RE.search(normalized, win_start, win_end) is not None:
            record("TP-CRED-002", base_category, cred_match.start())

    for exfil_match in _EXFIL_URL_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, exfil_match.start()):
            record("TP-CRED-002", base_category, exfil_match.start())

    for at in _shell_exfil_offsets(normalized):
        record("TP-CRED-002", base_category, at)

    # 4. TP-CONCEAL-003: Concealment instructions ("never tell the user", "do not mention this to the user")
    for conceal_match in _CONCEAL_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, conceal_match.start()):
            record("TP-CONCEAL-003", base_category, conceal_match.start())

    # 5. II-OVR-001: Instruction override or ignore read-only + destructive command
    for ovr_re in (_OVERRIDE_RE, _READONLY_OVERRIDE_RE):
        for ovr_match in ovr_re.finditer(normalized):
            if not _has_negated_prefix(normalized, ovr_match.start()):
                record("II-OVR-001", base_category, ovr_match.start())

    # 6. II-AUD-002: Auditor/scanner deception directives
    for aud_match in _AUDITOR_DECEIT_RE.finditer(normalized):
        if not _has_negated_prefix(normalized, aud_match.start()):
            record("II-AUD-002", CATEGORY_INSTRUCTION_INJECTION, aud_match.start())
    for aud_match in _AUDITOR_DIRECTIVE_RE.finditer(normalized):
        addressed = _AUDITOR_ADDRESSEE_RE.search(
            normalized,
            max(0, aud_match.start() - _ADDRESSEE_WINDOW),
            aud_match.end() + _ADDRESSEE_WINDOW,
        )
        if addressed is not None and not _has_negated_prefix(normalized, aud_match.start()):
            record("II-AUD-002", CATEGORY_INSTRUCTION_INJECTION, aud_match.start())

    return hits


def extract_json_text_entries(
    data: object,
    *,
    max_depth: int = 32,
    max_entries: int = 4_096,
) -> list[tuple[str, str]]:
    """Iteratively extract ``(dotted_field_path, string_value)`` pairs from parsed JSON."""
    results: list[tuple[str, str]] = []
    queue: deque[tuple[str, object, int]] = deque([("", data, 0)])
    while queue and len(results) < max_entries:
        prefix, node, depth = queue.popleft()
        if depth > max_depth:
            continue
        if isinstance(node, str):
            if node.strip():
                results.append((prefix or "$", node))
        elif isinstance(node, dict):
            for key, val in node.items():
                if not isinstance(key, str):
                    continue
                child = f"{prefix}.{key}" if prefix else key
                queue.append((child, val, depth + 1))
        elif isinstance(node, list):
            for idx, item in enumerate(node):
                child = f"{prefix}[{idx}]"
                queue.append((child, item, depth + 1))
    return results


@dataclass(frozen=True)
class _SourceOwner:
    name: str
    node: dict[str, Any]
    kind: str
    server: str | None


_SERVER_COLLECTIONS = frozenset({"mcpServers", "servers", "mcp_servers", "context_servers", "mcp"})


def _pointer_segment(key: str | tuple[str, int]) -> str:
    if isinstance(key, tuple):
        return f"{_pointer_segment(key[0])}#{key[1]}"
    return key if key in _POINTER_FIELDS else "*"


def _json_strings_with_owners(
    data: object, names: Iterable[str], *, keys: bool = False
) -> Iterator[tuple[str, str, _SourceOwner | None, bool]]:
    """``(JSON pointer, string, owner, is_key)`` for every nonblank string, and with
    ``keys`` every nonblank key at the pointer of its value, in O(size).

    The owner is the innermost enclosing object whose ``name`` names a component in
    ``names``; failing that, the innermost one stored under a key that does (as in
    ``mcpServers.<name>``). A ``name`` wins over a key, so a key spelled like a sibling's
    name inside a tool cannot move the tool's text onto that sibling. Pointers print
    indexes and known field names only, and stop growing past the printed length.
    """
    known = frozenset(names)
    queue: deque[tuple[str, object, _SourceOwner | None, _SourceOwner | None, str, str | None]] = (
        deque([("", data, None, None, "", None)])
    )
    while queue:
        pointer, node, by_name, by_key, slot, server = queue.popleft()
        if isinstance(node, str):
            if node.strip():
                yield pointer, node, by_name or by_key, False
            continue
        long = len(pointer) > _MAX_WHERE_CHARS
        if isinstance(node, dict):
            label = node.get("name")
            inherited = by_name or by_key
            inside_tool = (
                inherited is not None and inherited.kind == "tool" and inherited.node is not node
            )
            keyed_server = slot == "server" and by_key is not None and by_key.node is node
            if not inside_tool and slot == "server" and not keyed_server:
                if isinstance(label, str) and label and (label in known or server is None):
                    server = label
                elif server is None:
                    server = ""
            if not inside_tool and not keyed_server and isinstance(label, str) and label in known:
                by_name = _SourceOwner(label, node, slot, server)
            elif (
                not inside_tool
                and slot == "server"
                and server is not None
                and by_name is None
                and by_key is None
            ):
                by_name = _SourceOwner(server, node, "server", server)
            for key, val in node.items():
                child = pointer if long else f"{pointer}/{_pointer_segment(key)}"
                text = key[0] if isinstance(key, tuple) else key
                if keys and isinstance(text, str) and text.strip():
                    yield child, text, by_name or by_key, True
                if inside_tool:
                    queue.append((child, val, by_name, by_key, "", server))
                    continue
                kind, host = "", server
                if slot == "servers":
                    kind, host = "server", text
                elif slot == "tools" or text == "function":
                    kind = "tool"
                elif text in _SERVER_COLLECTIONS:
                    kind = "servers"
                elif text == "tools":
                    kind = "tools"
                inner = by_key
                if isinstance(val, dict) and (text in known or slot == "servers"):
                    inner = _SourceOwner(text, val, kind, host)
                queue.append(
                    (
                        child,
                        val,
                        None if slot in ("servers", "tools") else by_name,
                        inner,
                        kind,
                        host,
                    )
                )
        elif isinstance(node, list):
            kind = {"servers": "server", "tools": "tool"}.get(slot, "")
            for idx, item in enumerate(node):
                queue.append(
                    (pointer if long else f"{pointer}/{idx}", item, by_name, by_key, kind, server)
                )


def _keep_duplicates(pairs: list[tuple[str, Any]]) -> dict[str | tuple[str, int], Any]:
    # A duplicate key must not hide the value before it, so the n-th one is kept under
    # (key, n), a key no JSON text can spell.
    result: dict[str | tuple[str, int], Any] = {}
    seen: dict[str, int] = {}
    for key, value in pairs:
        n = seen[key] = seen.get(key, 0) + 1
        result[key if n == 1 else (key, n)] = value
    return result


def _parse_json_leniently(text: str) -> object:
    """Every string value of JSON or JSONC: duplicates kept, any integer, lone surrogates."""
    if json_nesting_exceeds(text, MAX_JSON_NESTING):
        raise RecursionError("JSON nesting exceeds the depth limit")
    for candidate in (text, None):
        try:
            return json.loads(
                strip_jsonc(text) if candidate is None else candidate,
                object_pairs_hook=_keep_duplicates,
                parse_int=lambda _digits: 0,
            )
        except ValueError:
            if candidate is None:
                raise
    raise AssertionError("unreachable")


def _joined_surrogates(text: str) -> str:
    # A UTF-16 reader joins the halves of a pair that YAML spells as two escapes.
    if not any("\ud800" <= ch <= "\udfff" for ch in text):
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "surrogatepass")


def _yaml_tree(text: str, raw_matches: _RawMatches | None = None, start: int = 0) -> object:
    """The documents of ``text`` as dicts, lists, strings and booleans, built from at most
    ``YAML_TOKEN_LIMIT`` parser events in O(N). An alias is not expanded, a duplicate
    key is kept as ``_keep_duplicates`` keeps it, and a key that is not a string is
    kept with its value under a key no string can spell."""
    import yaml

    documents: list[object] = []
    stack: list[tuple[bool, bool, list[object]]] = []
    flows = 0
    for count, event in enumerate(yaml.parse(text, Loader=yaml.SafeLoader), start=1):
        if count > YAML_TOKEN_LIMIT:
            raise ValueError("too many YAML events")
        node: object
        if isinstance(event, yaml.CollectionStartEvent):
            flow = bool(event.flow_style)
            flows += flow
            if flows > _MAX_YAML_FLOW_DEPTH:
                raise ValueError("YAML nested too deep")
            stack.append((isinstance(event, yaml.MappingStartEvent), flow, []))
            continue
        if isinstance(event, yaml.CollectionEndEvent):
            is_mapping, flow, children = stack.pop()
            flows -= flow
            node = children
            if is_mapping:
                mapping: dict[str | tuple[object, int], object] = {}
                seen: dict[str, int] = {}
                for index in range(0, len(children) - 1, 2):
                    key, value = children[index], children[index + 1]
                    if isinstance(key, str):
                        n = seen[key] = seen.get(key, 0) + 1
                        mapping[key if n == 1 else (key, n)] = value
                    else:
                        mapping[(None, index)] = [key, value]
                node = mapping
        elif isinstance(event, yaml.ScalarEvent):
            node = _joined_surrogates(event.value)
            if (
                raw_matches is not None
                and event.start_mark is not None
                and event.end_mark is not None
            ):
                raw_matches.bind(start + event.start_mark.index, start + event.end_mark.index, node)
            # MCP annotations distinguish boolean true from the quoted string "true".
            lower = event.value.lower() if len(event.value) <= 5 else ""
            if lower in yaml.SafeLoader.bool_values and (
                event.tag == "tag:yaml.org,2002:bool"
                or (
                    event.tag is None
                    and event.implicit[0]
                    and event.value in (lower, lower.capitalize(), lower.upper())
                )
            ):
                node = yaml.SafeLoader.bool_values[lower]
        elif isinstance(event, yaml.AliasEvent):
            node = None
        else:
            continue
        (stack[-1][2] if stack else documents).append(node)
    return documents[0] if len(documents) == 1 else documents


def _flow_depth(text: str) -> int:
    # Counts brackets in strings and comments too: a cheap first bound on PyYAML's work.
    depth = deepest = 0
    for match in _FLOW_BRACKETS_RE.finditer(text):
        depth = depth + 1 if match.group() in "[{" else max(depth - 1, 0)
        deepest = max(deepest, depth)
    return deepest


_FM_LINE_END_RE = re.compile(r"\r\n|\r|\n")
_FM_DASH_OPENER_RE = re.compile(r"-{3,}[ \t]*([A-Za-z]*)")
_FM_FORMATS = {"toml": "TOML", "json": "JSON"}


def _extra_front_matter_candidates(text: str) -> list[tuple[str, tuple[int, int]]]:
    """Linear-time fallback for Hugo ``+++`` TOML and for fences a strict reader skips:
    leading blank lines or spaces before the opener, a wider ``----`` opener or closer,
    and a ``...`` YAML closer. Decoding one a host does not read only adds findings."""
    stripped = text.removeprefix("\ufeff")
    offset = len(text) - len(stripped)
    pos = offset
    end = len(text)
    while pos < end and text[pos] in " \t\r\n":
        pos += 1
    nl = _FM_LINE_END_RE.search(text, pos)
    if nl is None:
        return []
    first = text[pos : nl.start()].rstrip(" \t")
    literal_closers: tuple[str, ...]
    if first == "+++":
        kind, literal_closers, dash_closer = "TOML", ("+++",), False
    elif (opener := _FM_DASH_OPENER_RE.fullmatch(first)) is not None:
        kind = _FM_FORMATS.get(opener.group(1).lower(), "YAML")
        literal_closers, dash_closer = (("...",) if kind == "YAML" else ()), True
    else:
        return []
    body_start = nl.end()
    cur = body_start
    while cur < end:
        nxt = _FM_LINE_END_RE.search(text, cur)
        line_end = end if nxt is None else nxt.start()
        next_pos = end if nxt is None else nxt.end()
        line = text[cur:line_end].strip(" \t")
        if line in literal_closers or (dash_closer and len(line) >= 3 and not line.strip("-")):
            return [(kind, (body_start, cur))]
        cur = next_pos
    return []


def _decoded_sources(
    rel_path: str, text: str, *, raw_matches: _RawMatches | None = None
) -> tuple[list[object], list[tuple[int, int]]]:
    """What a host decodes a JSONC, YAML, TOML, code source, or Markdown front matter to.

    Returns ``(trees, spans)`` where each parsed tree is scanned structurally and each
    span is escape-decoded by pattern when parsing is bypassed, unsupported, or failed.
    """
    suffix = PurePosixPath(rel_path).suffix.lower()
    if suffix in _CODE_SOURCE_SUFFIXES:
        return [], [(0, len(text))] if "\\" in text else []
    kind = _DECODED_FORMATS.get(suffix)
    candidates: list[tuple[str, tuple[int, int]]] = []
    if kind is not None:
        candidates.append((kind, (0, len(text))))
    elif suffix in _MARKDOWN_SUFFIXES:
        # Each candidate's raw text starts right after the opener line, which is the
        # first line of the text.
        first_nl = _FM_LINE_END_RE.search(text)
        fm_start = first_nl.end() if first_nl is not None else 0
        for fm_lang, fm_raw, _body in front_matter_candidates(text):
            if fm_raw:
                fm_kind = _FM_FORMATS.get(fm_lang, "YAML")
                candidates.append((fm_kind, (fm_start, fm_start + len(fm_raw))))
        if not candidates:
            candidates.extend(_extra_front_matter_candidates(text))
    if not candidates:
        return [], []
    import yaml

    trees: list[object] = []
    spans: list[tuple[int, int]] = []
    for cand_kind, span in candidates:
        body = text[span[0] : span[1]]
        has_escapes = "\\" in body or (cand_kind == "YAML" and "''" in body)
        if not (has_escapes or raw_matches is not None):
            continue
        try:
            if cand_kind == "JSON":
                parsed = _parse_json_leniently(body)
                if raw_matches is not None:
                    json_at = span[0]

                    # Raw hits sit at file offsets, so a token's body offsets shift by the span.
                    def _bind_json(a: int, b: int, _at: int = json_at) -> None:
                        raw_matches.bind(_at + a, _at + b, text, "JSON")

                    try:
                        strip_jsonc(body, on_string=_bind_json)
                    except ValueError:
                        # _parse_json_leniently succeeded while strip_jsonc refused U+2028/U+2029,
                        # so body is valid strict JSON with no comments and every quoted token is a string.
                        for match in _JSON_STRING_RE.finditer(body):
                            raw_matches.bind(
                                span[0] + match.start(), span[0] + match.end(), text, "JSON"
                            )
                trees.append(parsed)
                continue
            if len(body) <= _MAX_PARSED_CHARS:
                if cand_kind == "TOML":
                    if raw_matches is not None:
                        toml_at = span[0]

                        def _bind_toml(a: int, b: int, _at: int = toml_at) -> None:
                            raw_matches.bind(_at + a, _at + b, text, "TOML")

                        trees.append(toml_loads(body, on_string=_bind_toml))
                    else:
                        trees.append(toml_loads(body))
                    continue
                if _flow_depth(body) <= _MAX_YAML_FLOW_DEPTH:
                    if raw_matches is not None:
                        trees.append(_yaml_tree(body, raw_matches, span[0]))
                    else:
                        trees.append(_yaml_tree(body))
                    continue
        except (ValueError, OverflowError, RecursionError, yaml.YAMLError):
            # Malformed input still needs the same escape inspection as input over a parse limit.
            if has_escapes:
                spans.append(span)
            continue
        if has_escapes:
            spans.append(span)
    return trees, spans


def _decoded_source(
    rel_path: str, text: str, *, raw_matches: _RawMatches | None = None
) -> tuple[object | None, tuple[int, int] | None]:
    """Single-reading view of :func:`_decoded_sources` for direct callers and tests."""
    trees, spans = _decoded_sources(rel_path, text, raw_matches=raw_matches)
    return (trees[0] if trees else None), (spans[0] if spans else None)


def _escape_decoded(text: str, start: int, end: int) -> tuple[str, list[int]]:
    """``text[start:end]`` with every escape decoded and each surrogate pair joined, and
    for each character of the result the index in ``text`` it came from."""
    chars: list[str] = []
    origins: list[int] = []
    pos = start
    for match in _ESCAPE_RE.finditer(text, start, end):
        chars.extend(text[pos : match.start()])
        origins.extend(range(pos, match.start()))
        pos = match.end()
        digits = match.group(1) or match.group(2) or match.group(3) or match.group(4)
        if digits is not None:
            stripped = digits.lstrip("0") or "0"
            code = int(stripped, 16) if len(stripped) <= 6 else sys.maxunicode + 1
            decoded = chr(code) if code <= sys.maxunicode else match.group()
        elif match.group() == "''":
            decoded = "'"
        elif match.group(5) is None:
            decoded = ""
        else:
            decoded = _NAMED_ESCAPES.get(match.group(5), match.group(5))
        for ch in decoded:
            if "\udc00" <= ch <= "\udfff" and chars and "\ud800" <= chars[-1] <= "\udbff":
                chars[-1] = _joined_surrogates(chars[-1] + ch)
            else:
                chars.append(ch)
                origins.append(match.start())
    chars.extend(text[pos:end])
    origins.extend(range(pos, end))
    return "".join(chars), origins


def _escape_decoded_hits(
    text: str, span: tuple[int, int], rel_path: str, is_tool_surface: bool
) -> list[TextPoisoningHit]:
    """Hits in ``text[span]`` with its escapes decoded, at their byte offsets in ``text``."""
    decoded, origins = _escape_decoded(text, *span)
    hits = scan_text_block(decoded, surface=rel_path, is_tool_surface=is_tool_surface)
    if not hits:
        return []
    origin_at: dict[int, int] = {}
    byte_pos = 0
    for ch, origin in zip(decoded, origins, strict=True):
        origin_at[byte_pos] = origin
        byte_pos += _utf8_width(ch)
    return [
        replace(
            hit,
            byte_offset=len(text[: origin_at[hit.byte_offset]].encode("utf-8", "surrogatepass")),
        )
        for hit in hits
    ]


def _collect_schema_property_names(schema: dict[str, Any] | None) -> set[str]:
    if not isinstance(schema, dict):
        return set()
    names: set[str] = set()
    queue: deque[dict[str, Any]] = deque([schema])
    while queue:
        node = queue.popleft()
        props = node.get("properties")
        if isinstance(props, dict):
            for k, v in props.items():
                if isinstance(k, str):
                    names.add(k)
                if isinstance(v, dict):
                    queue.append(v)
        for combiner in ("items", "additionalProperties"):
            sub = node.get(combiner)
            if isinstance(sub, dict):
                queue.append(sub)
        for list_key in ("anyOf", "oneOf", "allOf"):
            items = node.get(list_key)
            if isinstance(items, list):
                queue.extend(item for item in items if isinstance(item, dict))
    return names


def check_sidenote_tool_schema(
    schema: dict[str, Any] | None,
    combined_text: str,
    annotations: dict[str, Any] | None,
    *,
    surface: str,
    existing_hits: list[TextPoisoningHit],
) -> list[TextPoisoningHit]:
    """Detect Sidenote cross-property escalation on tool schemas and annotations.

    Both checks need a tool-poisoning hit in the tool's own text; destructive keywords
    alone are not one, since a read-only tool may list the statements it rejects.
    Flags:
    1) A tool declaring ``readOnlyHint=True`` or ``destructiveHint=False`` whose text
       carries a poisoning directive.
    2) A declared side-channel parameter (``note``, ``debug``, ``query``, ``context``,
       ``metadata`` ...) that the tool's text names beside such a directive.
    The finding is located at the poisoning hit that triggered it.
    """
    poison = next((h for h in existing_hits if h.category == CATEGORY_TOOL_POISONING), None)
    if poison is None:
        return []
    ann = annotations or {}
    flagged = ann.get("readOnlyHint") is True or ann.get("destructiveHint") is False
    if not flagged:
        normalized, _ = normalize_for_lexical_scan(combined_text)
        flagged = any(
            re.search(rf"\b{re.escape(prop)}\b", normalized, re.IGNORECASE) is not None
            for prop in sorted(_collect_schema_property_names(schema))
            if prop.lower() in _SIDE_CHANNEL_PARAM_NAMES
        )
    if not flagged:
        return []
    return [
        TextPoisoningHit(
            rule_id="TP-SIDENOTE-004",
            category=CATEGORY_TOOL_POISONING,
            severity=RiskSeverity.HIGH,
            byte_offset=poison.byte_offset,
            surface=surface,
            summary=_RULE_DESCRIPTIONS["TP-SIDENOTE-004"],
            where=poison.where,
        )
    ]


def _priority_key(component: ComponentWithRisks) -> tuple[int, str]:
    rank = next(
        (i for i, kind in enumerate(_ATTRIBUTION_PRIORITY) if isinstance(component, kind)),
        len(_ATTRIBUTION_PRIORITY),
    )
    return rank, component.bom_ref


def _fallback_component(
    candidates: list[ComponentWithRisks], root_agent: ComponentWithRisks | None
) -> ComponentWithRisks | None:
    """The owner of text that no single tool in a shared source can be shown to own.

    Such text never goes to one of several tools, which would blame a sibling.
    """
    if len(candidates) == 1:
        return candidates[0]
    others = [c for c in candidates if not isinstance(c, ToolComponent)]
    return min(others, key=_priority_key) if others else root_agent


def _shared_names(candidates: list[ComponentWithRisks]) -> set[str]:
    counts = Counter(comp.name for comp in candidates)
    return {name for name, count in counts.items() if count > 1}


def _declaration_index(
    candidates: list[ComponentWithRisks],
) -> dict[tuple[str, str, str | None], ComponentWithRisks | None]:
    """Index unique owners by name, declaration kind and the collected MCP edges."""
    owners: dict[tuple[str, str, str | None], ComponentWithRisks | None] = {}
    servers = {c.bom_ref: c for c in candidates if isinstance(c, MCPServerComponent)}
    parents: dict[str, set[str]] = {}
    for server in servers.values():
        for tool_ref in server.tool_refs:
            parents.setdefault(tool_ref, set()).add(server.bom_ref)
    for comp in candidates:
        keys: list[tuple[str, str, str | None]] = [(comp.name, "", None)]
        if isinstance(comp, MCPServerComponent):
            keys.append((comp.name, "server", None))
        if isinstance(comp, ToolComponent):
            keys.append((comp.name, "tool", None))
            links = parents.get(comp.bom_ref, set()).copy()
            if comp.mcp_server_ref:
                links.add(comp.mcp_server_ref)
            if len(links) == 1 and (host := servers.get(next(iter(links)))) is not None:
                keys.append((comp.name, "tool", host.name))
        for key in keys:
            owners[key] = comp if key not in owners else None
    return owners


def _file_level_owner(
    candidates: list[ComponentWithRisks], root_agent: AgentComponent | None
) -> ComponentWithRisks | None:
    if root_agent is not None:
        return root_agent
    containers = [component for component in candidates if not isinstance(component, ToolComponent)]
    return containers[0] if len(containers) == 1 else None


def _attribute_source_component(
    content: str,
    raw_bytes: bytes,
    byte_offset: int,
    candidates: list[ComponentWithRisks],
    fallback: ComponentWithRisks | None,
    *,
    yaml_names: bool = False,
) -> ComponentWithRisks | None:
    """Pick the most specific component owning ``byte_offset`` inside a multi-entity source."""
    if not candidates:
        return fallback
    if len(candidates) == 1:
        return candidates[0]

    char_pos = len(raw_bytes[:byte_offset].decode("utf-8", errors="ignore"))
    prefix = content[max(0, char_pos - 600) : char_pos]
    plain_names = (
        {m.group(1): m.start(1) for m in _YAML_PLAIN_NAME.finditer(prefix)} if yaml_names else {}
    )
    best: ComponentWithRisks | None = None
    best_idx = -1
    # The candidate declared nearest before the hit owns it: a tool's call or definition,
    # or a server's table or key. Ties go to tools, which sort first.
    for candidate in sorted(candidates, key=_priority_key):
        plain = plain_names.get(candidate.name, -1)
        if plain > best_idx:
            best_idx, best = plain, candidate
        for tmpl in _TOOL_NAME_CALL_TEMPLATES:
            found = prefix.rfind(tmpl.format(name=candidate.name))
            if found > best_idx:
                best_idx, best = found, candidate
    return best if best is not None else _fallback_component(candidates, fallback)


# A whole-line reference definition with a "#" or "<>" destination and at most a title;
# anything else on the line makes it visible text.
_MD_COMMENT_LINE_RE = re.compile(
    r"^[ \t]{0,3}\[[^\]\n]{1,120}\]:[ \t]*(?:#|<>)"
    r"(?:[ \t]+(?:\"[^\"\n]*\"|'[^'\n]*'|\([^)\n]*\)))?[ \t]*$",
    re.MULTILINE,
)


def _code_spans(text: str, start: int, end: int) -> Iterator[tuple[int, int]]:
    """Code spans of ``text[start:end]``: backtick runs paired with the next run of the
    same length in their paragraph, in O(N)."""
    paragraphs: list[list[tuple[int, int]]] = [[]]
    blanks = _BLANK_LINE_RE.finditer(text, start, end)
    blank = next(blanks, None)
    for run in _BACKTICK_RUN_RE.finditer(text, start, end):
        while blank is not None and blank.end() <= run.start():
            paragraphs.append([])
            blank = next(blanks, None)
        paragraphs[-1].append(run.span())
    for runs in paragraphs:
        later: dict[int, deque[int]] = {}
        for index, (run_start, run_end) in enumerate(runs):
            later.setdefault(run_end - run_start, deque()).append(index)
        index = 0
        while index < len(runs):
            same = later[runs[index][1] - runs[index][0]]
            while same and same[0] <= index:
                same.popleft()
            if same:
                yield runs[index][0], runs[same[0]][1]
                index = same.popleft()
            index += 1


def _code_regions(text: str) -> list[tuple[int, int]]:
    """Sorted ``(start, end)`` spans of ``text`` that a Markdown reader may show as code:
    fenced blocks, an unclosed one running to the end, and code spans, in O(N)."""
    regions: list[tuple[int, int]] = []
    pos = 0
    while (fence := _FENCE_OPEN_RE.search(text, pos)) is not None:
        regions.extend(_code_spans(text, pos, fence.start()))
        marker = fence.group(1)
        pos = len(text)
        for close in _FENCE_CLOSE_RE.finditer(text, fence.end()):
            run = close.group(1)
            if run[0] == marker[0] and len(run) >= len(marker):
                pos = close.end()
                break
        regions.append((fence.start(), pos))
    regions.extend(_code_spans(text, pos, len(text)))
    return regions


def _mask_hidden_markdown_markup(text: str) -> str:
    """Blank hidden HTML/PI/reference comments, keeping every UTF-8 byte offset.

    Each masked character becomes as many spaces as it has UTF-8 bytes, so offsets
    measured in the masked text are offsets in the file.
    """
    masked = bytearray(len(text))
    code = _code_regions(text)
    code_starts = [region[0] for region in code]

    def in_code(index: int) -> bool:
        at = bisect_right(code_starts, index) - 1
        return at >= 0 and index < code[at][1]

    for open_tok, close_tok in (("<!--", "-->"), ("<?", "?>")):
        pos = 0
        while (start := text.find(open_tok, pos)) != -1:
            # Short HTML comments can close with a delimiter overlapping the opener.
            end = text.find(close_tok, start + 2, start + 4096)
            if in_code(start) or (end == -1 and open_tok == "<?"):
                # Code is shown as written, and only a closed processing instruction is
                # hidden from rendered views.
                pos = start + len(open_tok)
                continue
            if end != -1:
                stop = end + len(close_tok)
            else:
                blank = _BLANK_LINE_RE.search(text, start, start + 4096)
                stop = blank.start() if blank is not None else min(len(text), start + 4096)
            masked[start:stop] = b"\x01" * (stop - start)
            pos = stop
    for match in _MD_COMMENT_LINE_RE.finditer(text):
        if not in_code(match.start()):
            masked[match.start() : match.end()] = b"\x01" * (match.end() - match.start())
    return "".join(
        " " * _utf8_width(ch) if flag else ch for ch, flag in zip(text, masked, strict=True)
    )


def _format_hit_location(hit: TextPoisoningHit) -> str:
    return f"{hit.rule_id} at byte_offset={hit.byte_offset}" + (
        f" of {neutralize(hit.where)[:_MAX_WHERE_CHARS]}" if hit.where else ""
    )


def _hit_sort_key(hit: TextPoisoningHit) -> tuple[str, int, bool, str]:
    return (hit.where, hit.byte_offset, hit.rule_id == "TP-SIDENOTE-004", hit.rule_id)


def _append_consolidated_risks(
    component: ComponentWithRisks,
    hits: list[TextPoisoningHit],
) -> int:
    """Keep separate file-level risks for unresolved declarations up to a bounded cap."""
    resolved: dict[tuple[str, str], list[TextPoisoningHit]] = {}
    unresolved_by_surface: dict[tuple[str, str], dict[int, list[TextPoisoningHit]]] = {}
    for hit in hits:
        surface_key = (hit.category, hit.surface)
        if hit.unresolved_declaration:
            unresolved_by_surface.setdefault(surface_key, {}).setdefault(
                hit.unresolved_declaration, []
            ).append(hit)
        else:
            resolved.setdefault(surface_key, []).append(hit)

    recommendation = (
        "Remove coercive tags, override directives, hidden instructions, or credential-relay "
        "guidance from untrusted tool metadata, agent cards, or prompt files before loading into LLM context."
    )
    added = 0

    def emit(
        category: str,
        surface: str,
        order: list[TextPoisoningHit],
        owner: str,
        *,
        overflow_locations: list[TextPoisoningHit] | None = None,
        total_locations: int | None = None,
    ) -> None:
        nonlocal added
        shown_hits = order if overflow_locations is None else overflow_locations
        located = [_format_hit_location(h) for h in shown_hits]
        omitted = 0 if total_locations is None else max(0, total_locations - len(shown_hits))
        extra = f" (+{omitted} more locations)" if omitted else ""
        first = order[0]
        detail = (
            f"Surface '{neutralize(surface)}' ({owner}) matched "
            f"{'; '.join(located)}{extra} (pack={RULE_PACK_VERSION}): {first.summary}. "
            "Matched payload text is withheld."
        )
        references = list(dict.fromkeys(f"{_RULE_REFERENCE_PREFIX}{hit.rule_id}" for hit in order))
        component.risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category=category,
                detail=detail,
                recommendation=recommendation,
                references=references,
            )
        )
        added += 1

    all_keys = sorted(resolved.keys() | unresolved_by_surface.keys())
    for category, surface in all_keys:
        if (category, surface) in resolved:
            # The first location of each rule, so each offset is that of the rule printed beside
            # it; TP-SIDENOTE-004 shares its trigger's location and is listed after it.
            order = sorted(resolved[(category, surface)], key=_hit_sort_key)
            emit(category, surface, order, neutralize(component.name))
        by_decl = unresolved_by_surface.get((category, surface))
        if not by_decl:
            continue

        def unresolved_order(hit: TextPoisoningHit) -> tuple[bool, int, tuple[str, int, bool, str]]:
            return (
                hit.unresolved_declaration < 0,
                abs(hit.unresolved_declaration),
                _hit_sort_key(hit),
            )

        sorted_groups = sorted(
            (sorted(group, key=_hit_sort_key) for group in by_decl.values()),
            key=lambda g: unresolved_order(g[0]),
        )
        if len(sorted_groups) <= _MAX_UNRESOLVED_RISKS_PER_SURFACE:
            for order in sorted_groups:
                emit(category, surface, order, "component ownership unresolved")
            continue
        keep = _MAX_UNRESOLVED_RISKS_PER_SURFACE - 1
        for order in sorted_groups[:keep]:
            emit(category, surface, order, "component ownership unresolved")
        overflow_groups = sorted_groups[keep:]
        all_overflow = sorted(
            (hit for group in overflow_groups for hit in group),
            key=unresolved_order,
        )
        # Keep the earliest occurrence of every distinct rule in the overflow summary,
        # then fill up to _MAX_OVERFLOW_LOCATIONS with the earliest remaining locations.
        first_by_rule: dict[str, TextPoisoningHit] = {}
        for hit in all_overflow:
            first_by_rule.setdefault(hit.rule_id, hit)
        shown = list(first_by_rule.values())
        seen_ids = {id(h) for h in shown}
        for hit in all_overflow:
            if len(shown) >= _MAX_OVERFLOW_LOCATIONS:
                break
            if id(hit) not in seen_ids:
                shown.append(hit)
                seen_ids.add(id(hit))
        shown.sort(key=unresolved_order)
        emit(
            category,
            surface,
            all_overflow,
            f"component ownership unresolved across {len(overflow_groups)} additional declarations",
            overflow_locations=shown,
            total_locations=len(all_overflow),
        )
    return added


def _scan_component_fields(comp: ComponentWithRisks) -> list[TextPoisoningHit]:
    if isinstance(comp, ToolComponent):
        surface = comp.source_path or comp.name
        hits: list[TextPoisoningHit] = []
        parts: list[str] = []
        fields = [("description", comp.description_text), ("description", comp.description)]
        fields += [
            (f"input_schema.{path}", val)
            for path, val in extract_json_text_entries(
                comp.input_schema, max_depth=sys.maxsize, max_entries=sys.maxsize
            )
        ]
        for field, text in fields:
            if text:
                parts.append(text)
                hits.extend(
                    scan_text_block(text, surface=surface, is_tool_surface=True, where=field)
                )
        return hits + check_sidenote_tool_schema(
            comp.input_schema,
            "\n".join(parts),
            comp.annotations,
            surface=surface,
            existing_hits=hits,
        )
    if isinstance(comp, A2AServerComponent):
        surface = comp.source_path or comp.agent_card_path or comp.name
        texts = [("description", comp.description)]
        texts += [(f"skills_declared[{i}]", s) for i, s in enumerate(comp.skills_declared)]
        return [
            hit
            for field, text in texts
            if text
            for hit in scan_text_block(text, surface=surface, is_tool_surface=True, where=field)
        ]
    if comp.description:
        return scan_text_block(
            comp.description,
            surface=comp.source_path or comp.name,
            is_tool_surface=isinstance(comp, MCPServerComponent),
            where="description",
        )
    return []


_SourceFindings = list[tuple[ComponentWithRisks | None, list[TextPoisoningHit]]]


class _RawMatches:
    """Reconcile raw and parsed evidence only inside the same source string token."""

    def __init__(self, source: bytes, hits: list[TextPoisoningHit]) -> None:
        self.at: dict[int, list[TextPoisoningHit]] = {}
        self.by_value: dict[tuple[str, str], set[tuple[str, int]]] = {}
        self.covered_owners: dict[tuple[str, int], set[tuple[str | None, int]]] = {}
        char = byte = 0
        for hit in sorted(hits, key=lambda h: h.byte_offset):
            char += len(source[byte : hit.byte_offset].decode("utf-8"))
            byte = hit.byte_offset
            self.at.setdefault(char, []).append(hit)
        self.positions = sorted(self.at)

    def bind(self, start: int, end: int, text: str, syntax: str = "YAML") -> None:
        positions = self.positions[
            bisect_left(self.positions, start) : bisect_left(self.positions, end)
        ]
        if not positions:
            return
        value = text
        if syntax == "JSON":
            value = json.loads(text[start:end])
        elif syntax == "TOML":
            value = toml_loads("v=" + text[start:end])["v"]
        for pos in positions:
            for hit in self.at[pos]:
                self.by_value.setdefault((value, hit.rule_id), set()).add(
                    (hit.rule_id, hit.byte_offset)
                )

    def record(
        self,
        value: str,
        hits: list[TextPoisoningHit],
        *,
        owner_ref: str | None,
        unresolved: int,
    ) -> None:
        owner = (owner_ref, unresolved)
        for hit in hits:
            for raw_key in self.by_value.get((value, hit.rule_id), ()):
                self.covered_owners.setdefault(raw_key, set()).add(owner)


@dataclass
class _DeclarationFindings:
    target: ComponentWithRisks | None
    node: dict[str, Any] | None
    has_tool_schema: bool
    unresolved: bool
    hits: list[TextPoisoningHit] = field(default_factory=list)
    text_values: list[str] = field(default_factory=list)
    matched_values: list[tuple[str, list[TextPoisoningHit]]] = field(default_factory=list)


def _scan_structured_source(
    rel_path: str,
    parsed: object,
    comps: list[ComponentWithRisks],
    root_agent: AgentComponent | None,
    *,
    include_keys: bool = False,
    tool_context: bool | None = None,
    raw_matches: _RawMatches | None = None,
) -> _SourceFindings:
    """Scan a parsed configuration and evaluate each tool's text alongside its own schema.

    A string belongs to the innermost enclosing object whose ``name`` (or key) names a
    component recorded for this file. The declaration kind and server's tool references
    disambiguate shared names. Only unresolved declarations stay at file scope.
    """
    owners = _declaration_index(comps)
    known_names = {comp.name for comp in comps}
    collected_servers = {comp.name for comp in comps if isinstance(comp, MCPServerComponent)}
    linked_names = {name for name, kind, host in owners if kind == "tool" and host is not None}
    tool_names = {comp.name for comp in comps if isinstance(comp, ToolComponent)}
    file_owner = _file_level_owner(comps, root_agent)
    fallback = _fallback_component(comps, root_agent) if comps else root_agent
    groups: dict[tuple[str | None, int], _DeclarationFindings] = {}
    for pointer, value, owner, is_key in _json_strings_with_owners(
        parsed, known_names, keys=include_keys
    ):
        target, node, ambiguous = fallback, None, False
        if owner is not None:
            node = owner.node
            typed_key = (owner.name, owner.kind, None)
            scoped_key = (owner.name, owner.kind, owner.server)
            if owner.kind == "tool" and owner.server is not None:
                if owner.name in linked_names:
                    target = owners.get(scoped_key)
                elif collected_servers and owner.server not in collected_servers:
                    target = None
                else:
                    target = owners.get(typed_key)
            elif owner.kind == "server":
                if collected_servers or owner.name in known_names:
                    target = owners.get(typed_key)
                else:
                    target = fallback
            elif owner.kind == "tool":
                target = owners.get(typed_key)
            else:
                target = owners.get((owner.name, "", None))
            ambiguous = target is None
            if ambiguous:
                target = file_owner
        if target is None:
            ambiguous = True
        has_tool_schema = isinstance(target, ToolComponent) or (
            ambiguous and owner is not None and owner.kind != "server" and owner.name in tool_names
        )
        is_tool = (
            has_tool_schema
            or isinstance(target, (A2AServerComponent, MCPServerComponent))
            or (target is None and bool(tool_names))
            if tool_context is None
            else tool_context
        )
        group_key = (None if target is None else target.bom_ref, id(node))
        group = groups.get(group_key)
        if group is None:
            group = groups[group_key] = _DeclarationFindings(
                target, node, has_tool_schema, ambiguous
            )
        hits = scan_text_block(
            value,
            surface=rel_path,
            is_tool_surface=is_tool,
            where=pointer or ("$" if include_keys else ""),
        )
        group.hits.extend(hits)
        if raw_matches is not None and hits:
            group.matched_values.append((value, hits))
        if has_tool_schema and not is_key:
            group.text_values.append(value)
    results: _SourceFindings = []
    for ordinal, group in enumerate(groups.values(), start=1):
        target, hits = group.target, group.hits
        if group.has_tool_schema and hits:
            declaration = group.node or {}
            explicit_tool = target if isinstance(target, ToolComponent) else None
            schema = next(
                (
                    declaration[k]
                    for k in ("inputSchema", "input_schema", "parameters")
                    if k in declaration
                ),
                explicit_tool.input_schema if explicit_tool is not None else None,
            )
            ann = declaration.get(
                "annotations", explicit_tool.annotations if explicit_tool is not None else None
            )
            hits = hits + check_sidenote_tool_schema(
                schema if isinstance(schema, dict) else None,
                "\n".join(group.text_values),
                ann if isinstance(ann, dict) else None,
                surface=rel_path,
                existing_hits=hits,
            )
        unresolved = ordinal if group.unresolved else 0
        if raw_matches is not None and group.matched_values:
            owner_ref = None if target is None else target.bom_ref
            for value, matched in group.matched_values:
                raw_matches.record(value, matched, owner_ref=owner_ref, unresolved=unresolved)
        if group.unresolved:
            hits = [replace(hit, unresolved_declaration=ordinal) for hit in hits]
        results.append((target, hits))
    return results


def _scan_text_source(
    rel_path: str,
    raw_text: str,
    comps: list[ComponentWithRisks],
    root_agent: AgentComponent | None,
) -> _SourceFindings:
    suffix = PurePosixPath(rel_path).suffix.lower()
    is_tool_ctx = any(
        isinstance(c, (ToolComponent, A2AServerComponent, MCPServerComponent)) for c in comps
    )
    scan_input = raw_text
    if (
        not is_tool_ctx
        and suffix in _MARKDOWN_SUFFIXES
        and any(
            r.category == "hidden_markup" and r.severity == RiskSeverity.HIGH
            for comp in comps
            for r in comp.risks
        )
    ):
        scan_input = _mask_hidden_markdown_markup(raw_text)
    hits = scan_text_block(scan_input, surface=rel_path, is_tool_surface=is_tool_ctx)
    shared_names = _shared_names(comps)
    structured_attribution = bool(shared_names) or (is_tool_ctx and suffix in _DECODED_FORMATS)
    raw_bytes = raw_text.encode("utf-8") if hits else b""
    raw_matches = _RawMatches(raw_bytes, hits) if structured_attribution and hits else None
    trees, spans = _decoded_sources(rel_path, raw_text, raw_matches=raw_matches)
    if spans:
        located = {(h.rule_id, h.byte_offset) for h in hits}
        for span in spans:
            for h in _escape_decoded_hits(raw_text, span, rel_path, is_tool_ctx):
                key = (h.rule_id, h.byte_offset)
                if key not in located:
                    located.add(key)
                    hits.append(h)
    file_owner = _file_level_owner(comps, root_agent) if shared_names else None
    if hits and not raw_bytes:
        raw_bytes = raw_text.encode("utf-8")
    decoded_groups: list[tuple[ComponentWithRisks | None, list[TextPoisoningHit]]] = []
    for tree in trees:
        decoded_groups.extend(
            _scan_structured_source(
                rel_path,
                tree,
                comps,
                root_agent,
                include_keys=True,
                tool_context=is_tool_ctx,
                raw_matches=raw_matches,
            )
        )
    by_target: dict[str | None, tuple[ComponentWithRisks | None, list[TextPoisoningHit]]] = {}
    for h in hits:
        chosen = _attribute_source_component(
            raw_text,
            raw_bytes,
            h.byte_offset,
            comps,
            root_agent,
            yaml_names=suffix in (".yaml", ".yml"),
        )
        if shared_names and (chosen is None or chosen is root_agent or chosen.name in shared_names):
            chosen = file_owner
            h = replace(h, unresolved_declaration=-(h.byte_offset + 1))
        chosen_ref = None if chosen is None else chosen.bom_ref
        if raw_matches is not None:
            covered = raw_matches.covered_owners.get((h.rule_id, h.byte_offset))
            if covered and (shared_names or covered != {(chosen_ref, 0)}):
                continue
        if chosen is not None or shared_names:
            by_target.setdefault(chosen_ref, (chosen, []))[1].append(h)
    if decoded_groups:
        # A decoded string is reported at its pointer, as in a JSON source, unless the raw
        # text already gave its owner the same rule.
        found = {
            (ref, h.rule_id, h.unresolved_declaration)
            for ref, (_, group) in by_target.items()
            for h in group
        }
        for target, decoded in decoded_groups:
            ref = None if target is None else target.bom_ref
            extra = [h for h in decoded if (ref, h.rule_id, h.unresolved_declaration) not in found]
            if extra:
                by_target.setdefault(ref, (target, []))[1].extend(extra)
    return list(by_target.values())


def _source_candidates(
    components_by_path: dict[str, list[ComponentWithRisks]],
) -> Iterator[str]:
    for rel_path, comps in sorted(components_by_path.items()):
        suffix = PurePosixPath(rel_path).suffix.lower()
        if suffix not in _TEXT_DECLARATION_SUFFIXES and any(
            isinstance(c, SkillPackageComponent) and c.skill_type == "skill-resource" for c in comps
        ):
            continue
        yield rel_path


def apply_text_poisoning_rules(
    aibom: AIBOM,
    root: Path | None = None,
    *,
    exclude_paths: Iterable[str | Path] = (),
    failures: list[str] | None = None,
    exclusions: list[str] | None = None,
    surfaces: list[str] | None = None,
) -> int:
    """Run deterministic text-poisoning & injection rules across an assembled AIBOM.

    Inspects in-memory component descriptions and schemas and, when ``root`` is given,
    the repository files that collected components name as their source or agent card,
    read through confined descriptor-relative opens. No other file is read, so a
    collector that was not selected adds no surface. Findings are appended to existing
    components; no component is created and no hash changes. A surface the rules cannot
    process is recorded in ``failures``, never raised.
    """
    components: list[ComponentWithRisks] = [
        c for c in aibom.components if isinstance(c, _COMPONENT_KINDS)
    ]
    components_by_path: dict[str, list[ComponentWithRisks]] = {}
    for comp in components:
        paths = [comp.source_path]
        if isinstance(comp, A2AServerComponent):
            paths.append(comp.agent_card_path)
        for path in dict.fromkeys(paths):
            if path and "://" not in path:
                components_by_path.setdefault(path, []).append(comp)
    agents = [c for c in components if isinstance(c, AgentComponent)]
    root_agent = min(agents, key=lambda a: a.bom_ref) if agents else None
    located_hits: dict[str, dict[tuple[str, str, str, int], TextPoisoningHit]] = {}
    own_failures: list[str] = []
    own_exclusions: list[str] = []
    scanned_rel_paths: set[str] = set()
    added = 0

    def failed(subject: str, reason: str) -> None:
        own_failures.append(
            f"{neutralize(subject)}: text-poisoning rules could not be applied ({reason})"
        )

    def remember(target: ComponentWithRisks, hits: list[TextPoisoningHit]) -> None:
        if not hits:
            return
        # Source passes come first. Keep their locations for shared rules while
        # admitting additional rules derived from component fields afterwards.
        firsts: dict[tuple[str, str, str, int], TextPoisoningHit] = {}
        for hit in hits:
            key = (hit.category, hit.surface, hit.rule_id, hit.unresolved_declaration)
            previous = firsts.get(key)
            if previous is None or (hit.where, hit.byte_offset) < (
                previous.where,
                previous.byte_offset,
            ):
                firsts[key] = hit
        saved = located_hits.setdefault(target.bom_ref, {})
        for key, hit in firsts.items():
            saved.setdefault(key, hit)

    # Source files first: their findings carry file byte offsets or JSON pointers, which
    # the in-memory fields scanned after them cannot give for the same component.
    if root is not None and root.is_dir():
        with ConfinedCollection(
            root, own_failures, own_exclusions, exclude_paths=exclude_paths
        ) as files:
            for rel_path in _source_candidates(components_by_path):
                # A collector may record a directory of rules; its files are their own sources.
                if files.excluded(rel_path) or files.is_directory(rel_path):
                    continue
                raw = files.read_bytes(rel_path, missing_ok=True)
                if raw is None:
                    continue
                encoding = "utf-8"
                if rel_path.endswith(".py"):
                    # Python honours a coding declaration, and so must the rules.
                    try:
                        encoding = tokenize.detect_encoding(io.BytesIO(raw).readline)[0]
                    except SyntaxError:
                        pass
                try:
                    raw_text = raw.decode(encoding)
                except (UnicodeDecodeError, LookupError):
                    # Replacement characters could split a payload's words; the text is
                    # still scanned, but the surface is incomplete.
                    failed(rel_path, "not UTF-8")
                    raw_text = raw.decode("utf-8", errors="replace")
                scanned_rel_paths.add(rel_path)
                comps = components_by_path[rel_path]
                try:
                    parsed: object = None
                    if rel_path.lower().endswith(".json"):
                        try:
                            parsed = _parse_json_leniently(raw_text)
                        except (ValueError, RecursionError):
                            # The raw text is still scanned, but escaped text in it is not
                            # read. An instruction file named .json is text to its readers.
                            if not all(isinstance(c, _INSTRUCTION_KINDS) for c in comps):
                                failed(rel_path, "not JSON")
                    owned = (
                        _scan_structured_source(rel_path, parsed, comps, root_agent)
                        if isinstance(parsed, (dict, list))
                        else _scan_text_source(rel_path, raw_text, comps, root_agent)
                    )
                    for target, hits in owned:
                        if target is not None:
                            remember(target, hits)
                        elif hits:
                            failed(rel_path, "finding has no unambiguous component owner")
                            if failures is None:
                                # The library caller has no diagnostics sink. Carry the
                                # explicitly file-level risk on a stable existing record.
                                remember(min(comps, key=_priority_key), hits)
                except (ValueError, RecursionError) as exc:
                    failed(rel_path, type(exc).__name__)

    for comp in components:
        try:
            remember(comp, _scan_component_fields(comp))
        except (ValueError, RecursionError) as exc:
            failed(comp.bom_ref, type(exc).__name__)
        if comp.bom_ref in located_hits:
            added += _append_consolidated_risks(comp, list(located_hits.pop(comp.bom_ref).values()))

    if surfaces is not None:
        surfaces.extend(sorted(scanned_rel_paths))
    for target_list, own in ((failures, own_failures), (exclusions, own_exclusions)):
        if target_list is not None:
            known = set(target_list)
            for msg in own:
                if msg not in known:
                    target_list.append(msg)
                    known.add(msg)
    return added
