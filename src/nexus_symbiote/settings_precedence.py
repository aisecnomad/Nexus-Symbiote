"""Settings-as-security-events precedence and oversight evaluation (``R0.3.0-2``).

Evaluates declared project and local host settings already merged from repository
config (``permissions.allow``, ``permissions.ask``, ``permissions.deny``,
``alwaysAllow``, subagent/rule front matter, and ``defaultMode`` / ``approval_policy``)
to resolve per-tool ``HumanInTheLoop`` state, detect ``oversight_gap`` on
auto-approved destructive or unbounded tools, extract normalized ``activation`` scope
and ``sandbox.network.allowedDomains``, and flag ``subagent_inline_mcp_server``.

Note: user-level, managed-policy, workspace-trust, and CLI-flag layers outside the
repository are not observed during static scans and are outside this model.
"""

from __future__ import annotations

import fnmatch
import hashlib
import re
from bisect import bisect_right
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

from nexus_symbiote.core.enums import HumanInTheLoop, RiskSeverity
from nexus_symbiote.core.hashing import canonical_json
from nexus_symbiote.core.models import RiskAssessment
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.utils.markdown import front_matter_candidates
from nexus_symbiote.utils.secrets import REDACTED, redact_text
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.utils.toml import loads as toml_loads

MAX_RECORDED_DENY_RULES = 512
MAX_RECORDED_DOMAINS = 512
MAX_RECORDED_TOOL_STATES = 512
MAX_OVERSIGHT_GAP_FINDINGS = 64
MAX_INDEXED_PERMISSION_RULES = 65536
MAX_FRONTMATTER_YAML_NODES = 4096
MAX_ACTIVATION_GLOBS = 256
MAX_INLINE_MCP_SERVER_NAMES = 64

_DESTRUCTIVE_VERBS_RE = re.compile(
    r"(?:^|[_:/\s*-])(?:delete|destroy|drop|rm|rmdir|remove|purge|truncate|wipe|reset|"
    r"shred|mkfs|force[_-]?push|exec|shell|bash|run[_-]?command|kill|pkill|killall|"
    r"shutdown|reboot|terminate)(?:$|[_:/\s*-])",
    re.IGNORECASE,
)
_EXACT_DESTRUCTIVE_TOOLS = frozenset({"bash", "shell", "exec", "sh", "zsh", "powershell", "cmd"})
_EDIT_TOOL_NAMES = frozenset({"edit", "write", "multiedit", "notebookedit"})

_COMMAND_RUNNERS = frozenset(
    {
        "sh",
        "bash",
        "zsh",
        "dash",
        "fish",
        "ksh",
        "csh",
        "tcsh",
        "ash",
        "busybox",
        "node",
        "nodejs",
        "deno",
        "bun",
        "perl",
        "ruby",
        "php",
        "lua",
        "osascript",
        "pwsh",
        "powershell",
        "cmd",
        "eval",
        "exec",
        "command",
        "env",
        "sudo",
        "doas",
        "su",
        "xargs",
        "nohup",
        "timeout",
        "nice",
        "ionice",
        "setsid",
        "script",
        "watch",
        "docker",
        "podman",
        "nerdctl",
        "npx",
        "bunx",
        "uvx",
        "uv",
        "pipx",
    }
)
_VERSIONED_INTERPRETER = re.compile(r"(?:python|pypy|ruby|php|perl|node)[0-9.]*|py")
_SHELL_META_RE = re.compile(r"(?:&&|\|\||[;|`]|\$\()")
# Names a glob in a rule's program word is matched against: the runners, and the common
# spellings of the versioned interpreters, which `_VERSIONED_INTERPRETER` reads exactly.
_RUNNER_NAMES = tuple(
    sorted(
        _COMMAND_RUNNERS
        | {"python", "python3", "python3.12", "python3.13", "pypy", "pypy3", "py", "node22"}
    )
)
_GLOB_CHARACTERS = frozenset("*?[")
# A program glob longer than this is not compiled and is read as a runner, failing closed.
_MAX_PROGRAM_GLOB = 64
_FORCE_FLAG_RE = re.compile(
    r"(?:^|[\s:])--force(?:[\s:=]|$)|(?:^|[\s:])-rf(?:[\s:]|$)", re.IGNORECASE
)
_SHELL_OPERATORS_RE = re.compile(r"([;|&$`(){}<>\n]+)")
_SCHEME_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")

_AUTO_POLICIES = frozenset({"never", "auto", "bypasspermissions"})
_CONDITIONAL_POLICIES = frozenset({"on-failure"})
_REQUIRED_POLICIES = frozenset({"on-request", "untrusted", "default", "plan", "dontask"})

_STATE_PRIORITY = {
    HumanInTheLoop.NONE.value: 0,
    HumanInTheLoop.CONDITIONAL.value: 1,
    HumanInTheLoop.REQUIRED.value: 2,
    "unknown": 3,
}


def _url_scheme_pieces(text: str) -> list[str]:
    """Split ``text`` before each URL scheme so adjacent option names cannot mask secrets."""
    cuts: list[int] = []
    floor = 0
    idx = text.find("://")
    while idx != -1:
        start = idx
        while start > floor and text[start - 1] in _SCHEME_CHARS:
            start -= 1
        while start < idx and not ("a" <= text[start].lower() <= "z"):
            start += 1
        if start < idx:
            cuts.append(start)
        floor = idx + 3
        idx = text.find("://", floor)
    bounds = [0, *cuts, len(text)]
    parts = [text[b:e] for b, e in zip(bounds, bounds[1:], strict=False) if b < e]
    return parts or [text]


def _safe_settings_text(value: str) -> str:
    """Redact and neutralize a settings string with scheme-boundary splitting."""
    pieces = _SHELL_OPERATORS_RE.split(value)
    for idx in range(0, len(pieces), 2):
        parts = _url_scheme_pieces(pieces[idx])
        pieces[idx] = " ".join(redact_text(part) for part in parts)
    return neutralize("".join(pieces))


def _normalize_patterns(raw: Any) -> tuple[str, ...]:
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.split(",") if p.strip()]
        return tuple(parts)
    if isinstance(raw, Iterable) and not isinstance(raw, (bytes, Mapping)):
        out: list[str] = []
        for item in raw:
            if isinstance(item, str) and item.strip():
                out.append(item.strip())
        return tuple(out)
    return ()


def _is_blanket_specifier(base: str, spec: str) -> bool:
    """Return True only when a parenthesis specifier imposes zero path or command narrowing."""
    compact = "".join(spec.split())
    if compact in {"", "*", ":*", "**", "*:*"}:
        return True
    return base.lower() == "webfetch" and compact.lower() in {"domain:*", "domain:"}


def _parse_rule(pattern: str) -> tuple[str, str | None, bool] | None:
    """Parse ``pattern`` into ``(base_tool, normalized_specifier, is_blanket)``."""
    pat = pattern.strip()
    if not pat:
        return None
    if pat == "*":
        return ("*", None, True)
    if "(" in pat:
        base, _, rest = pat.partition("(")
        base = base.strip()
        if not base:
            return None
        spec = rest[:-1].strip() if rest.endswith(")") else rest.strip()
        if _is_blanket_specifier(base, spec):
            return (base, None, True)
        return (base, spec, False)
    return (pat, None, True)


class _SortedPrefixes:
    """Compact prefix matcher using a sorted minimal prefix-free stem list and binary search."""

    __slots__ = ("_dirty", "_raw", "_stems")

    def __init__(self) -> None:
        self._raw: list[str] = []
        self._stems: list[str] = []
        self._dirty = False

    def insert(self, prefix: str) -> None:
        self._raw.append(prefix)
        self._dirty = True

    def _compile(self) -> None:
        kept: list[str] = []
        for candidate in sorted(self._raw):
            if kept and candidate.startswith(kept[-1]):
                continue
            kept.append(candidate)
        self._stems = kept
        self._raw.clear()
        self._dirty = False

    def matches_any_prefix_of(self, text: str) -> bool:
        if self._dirty:
            self._compile()
        stems = self._stems
        if not stems:
            return False
        if stems[0] == "":
            return True
        idx = bisect_right(stems, text)
        return idx > 0 and text.startswith(stems[idx - 1])


def _narrow_spec_prefix(spec: str) -> str | None:
    """Return stem when a narrow rule ends in ``:*`` or `` *`` prefix wildcard."""
    if spec.endswith((":*", " *")) and len(spec) > 2:
        return spec[:-2]
    return None


@dataclass(slots=True)
class _RuleBucket:
    has_star: bool = False
    blanket_exact: set[str] = field(default_factory=set)
    blanket_prefixes: _SortedPrefixes = field(default_factory=_SortedPrefixes)
    narrow_by_base: dict[str, set[str]] = field(default_factory=dict)
    narrow_spec_prefixes_by_base: dict[str, _SortedPrefixes] = field(default_factory=dict)
    narrow_star_specs: set[str] = field(default_factory=set)
    narrow_star_spec_prefixes: _SortedPrefixes = field(default_factory=_SortedPrefixes)
    narrow_prefix_specs: dict[str, _SortedPrefixes] = field(default_factory=dict)

    def add(self, pattern: str) -> tuple[str, str | None, bool] | None:
        parsed = _parse_rule(pattern)
        if parsed is None:
            return None
        base, spec, is_blanket = parsed
        if is_blanket:
            if base == "*":
                self.has_star = True
            elif base.endswith("*"):
                self.blanket_prefixes.insert(base[:-1])
            else:
                self.blanket_exact.add(base)
        elif spec is not None:
            stem = _narrow_spec_prefix(spec)
            trailing_glob = (
                spec[:-1] if stem is None and spec.endswith("*") and len(spec) > 1 else None
            )
            if base == "*":
                self.narrow_star_specs.add(spec)
                if stem is not None:
                    self.narrow_star_specs.add(stem)
                    self.narrow_star_spec_prefixes.insert(stem + " ")
                    self.narrow_star_spec_prefixes.insert(stem + ":")
                elif trailing_glob is not None:
                    self.narrow_star_spec_prefixes.insert(trailing_glob)
            elif base.endswith("*"):
                trie = self.narrow_prefix_specs.setdefault(spec, _SortedPrefixes())
                trie.insert(base[:-1])
            else:
                specs = self.narrow_by_base.setdefault(base, set())
                specs.add(spec)
                if stem is not None:
                    specs.add(stem)
                    strie = self.narrow_spec_prefixes_by_base.setdefault(base, _SortedPrefixes())
                    strie.insert(stem + " ")
                    strie.insert(stem + ":")
                elif trailing_glob is not None:
                    strie = self.narrow_spec_prefixes_by_base.setdefault(base, _SortedPrefixes())
                    strie.insert(trailing_glob)
        return parsed

    def matches_blanket(self, base: str) -> bool:
        if self.has_star:
            return True
        if base == "*":
            return False
        if base.endswith("*"):
            return self.blanket_prefixes.matches_any_prefix_of(base[:-1])
        return base in self.blanket_exact or self.blanket_prefixes.matches_any_prefix_of(base)

    def matches_narrow(self, base: str, spec: str) -> bool:
        if self.matches_blanket(base):
            return True
        if spec in self.narrow_star_specs or self.narrow_star_spec_prefixes.matches_any_prefix_of(
            spec
        ):
            return True
        trie = self.narrow_prefix_specs.get(spec)
        if base.endswith("*"):
            return trie is not None and trie.matches_any_prefix_of(base[:-1])
        if spec in self.narrow_by_base.get(base, ()):
            return True
        strie = self.narrow_spec_prefixes_by_base.get(base)
        if strie is not None and strie.matches_any_prefix_of(spec):
            return True
        return trie is not None and trie.matches_any_prefix_of(base)


def _spec_runs_arbitrary_command(spec: str) -> bool:
    if _SHELL_META_RE.search(spec):
        return True
    from nexus_symbiote.scanners.ide_agents import _rule_program

    program_raw, _ = _rule_program(spec)
    program = program_raw.lower()
    if not program:
        words = spec.split(":", 1)[0].split()
        if not words:
            return False
        program = words[0].rsplit("/", 1)[-1].lower()
    if program.startswith("*"):
        return True
    stripped = program.rstrip("*")
    if stripped in _COMMAND_RUNNERS or _VERSIONED_INTERPRETER.fullmatch(stripped):
        return True
    if not _GLOB_CHARACTERS.intersection(program):
        return False
    # Claude Code matches `*` anywhere in a Bash rule, so `ba*` or `b?sh` approves bash
    # as surely as `bash:*` does.
    if len(program) > _MAX_PROGRAM_GLOB:
        return True
    return any(fnmatch.fnmatchcase(name, program) for name in _RUNNER_NAMES)


def _base_matches_destructive_tool(base: str) -> bool:
    # A glob in the tool name of an allow rule (`Ba*`, `*`) is skipped by Claude Code and
    # approves nothing, so only an exact destructive tool name can carry a grant.
    return base.strip().lower() in _EXACT_DESTRUCTIVE_TOOLS


def _narrow_spec_is_destructive(base: str, spec: str) -> bool:
    """Return True when a narrow allow specifier grants destructive or runner capability."""
    if _base_matches_destructive_tool(base) and _spec_runs_arbitrary_command(spec):
        return True
    if _FORCE_FLAG_RE.search(spec):
        return True
    lowered = spec.strip().lower()
    return lowered.rstrip("*") in _EXACT_DESTRUCTIVE_TOOLS or bool(
        _DESTRUCTIVE_VERBS_RE.search(lowered)
    )


class _RuleIndex:
    """Compiled precedence index supporting O(log R) per-tool resolution with flat memory."""

    __slots__ = (
        "_seen_candidates",
        "_seen_narrow_allows",
        "allow",
        "approval_policy",
        "ask",
        "candidate_narrow_allows",
        "candidates",
        "deny",
        "host_modelled",
        "rules_truncated",
    )

    def __init__(
        self,
        *,
        permissions: Mapping[str, Any] | None = None,
        always_allow: Iterable[str] = (),
        frontmatter_tools: Mapping[str, Any] | None = None,
        approval_policy: str | None = None,
        host_modelled: bool = True,
        max_indexed_rules: int = MAX_INDEXED_PERMISSION_RULES,
    ) -> None:
        self.deny = _RuleBucket()
        self.ask = _RuleBucket()
        self.allow = _RuleBucket()
        self.approval_policy = approval_policy
        self.host_modelled = host_modelled
        self.candidates: list[str] = []
        self._seen_candidates: set[str] = set()
        self.candidate_narrow_allows: dict[str, list[str]] = {}
        self._seen_narrow_allows: dict[str, set[str]] = {}
        self.rules_truncated = False

        perms = permissions if isinstance(permissions, Mapping) else {}
        fm = frontmatter_tools if isinstance(frontmatter_tools, Mapping) else {}
        indexed = 0

        for bucket, raw_groups in (
            (
                self.deny,
                (_normalize_patterns(perms.get("deny")), _normalize_patterns(fm.get("deny"))),
            ),
            (self.ask, (_normalize_patterns(perms.get("ask")), _normalize_patterns(fm.get("ask")))),
            (
                self.allow,
                (
                    _normalize_patterns(perms.get("allow")),
                    _normalize_patterns(fm.get("allow")),
                    _normalize_patterns(always_allow),
                ),
            ),
        ):
            for group in raw_groups:
                for pat in group:
                    if indexed >= max_indexed_rules:
                        self.rules_truncated = True
                        break
                    parsed = bucket.add(pat)
                    if parsed is None:
                        continue
                    indexed += 1
                    base, spec, is_blanket = parsed
                    if base not in self._seen_candidates:
                        self._seen_candidates.add(base)
                        self.candidates.append(base)
                    if bucket is self.allow and not is_blanket and spec is not None:
                        seen_specs = self._seen_narrow_allows.setdefault(base, set())
                        if spec not in seen_specs:
                            seen_specs.add(spec)
                            self.candidate_narrow_allows.setdefault(base, []).append(spec)
                if self.rules_truncated:
                    break
            if self.rules_truncated:
                break

    def _policy_resolution(self, base: str) -> HumanInTheLoop | None:
        if self.approval_policy is None:
            return None
        norm = self.approval_policy.strip().lower()
        if norm in _AUTO_POLICIES:
            return HumanInTheLoop.NONE
        if norm in _CONDITIONAL_POLICIES:
            return HumanInTheLoop.CONDITIONAL
        if norm == "acceptedits":
            return (
                HumanInTheLoop.NONE
                if base.lower() in _EDIT_TOOL_NAMES
                else HumanInTheLoop.CONDITIONAL
            )
        if norm in _REQUIRED_POLICIES:
            return HumanInTheLoop.REQUIRED
        return None

    def resolve(self, tool_name: str) -> HumanInTheLoop | None:
        if not self.host_modelled:
            return None
        parsed = _parse_rule(tool_name)
        if parsed is None:
            return None
        base, spec, q_blanket = parsed

        if not q_blanket and spec is not None:
            if self.deny.matches_narrow(base, spec) or self.ask.matches_narrow(base, spec):
                return HumanInTheLoop.REQUIRED
            if self.allow.matches_narrow(base, spec):
                return HumanInTheLoop.NONE
            return self._policy_resolution(base)

        if self.deny.matches_blanket(base) or self.ask.matches_blanket(base):
            return HumanInTheLoop.REQUIRED
        if self.allow.matches_blanket(base):
            return HumanInTheLoop.NONE

        policy = self._policy_resolution(base)
        if policy == HumanInTheLoop.NONE:
            return HumanInTheLoop.NONE

        narrow_allows = self.candidate_narrow_allows.get(base)
        if narrow_allows:
            has_uncovered_allow = any(
                not self.deny.matches_narrow(base, nspec)
                and not self.ask.matches_narrow(base, nspec)
                for nspec in narrow_allows
            )
            if has_uncovered_allow:
                return HumanInTheLoop.CONDITIONAL
            if policy is None:
                return HumanInTheLoop.REQUIRED

        if policy is not None:
            return policy

        if base in self.deny.narrow_by_base or base in self.ask.narrow_by_base:
            return HumanInTheLoop.CONDITIONAL
        return None

    def uncovered_destructive_narrow_allow(self, base: str) -> bool:
        """True if ``base`` has an un-suppressed narrow allow naming a destructive/runner spec."""
        for nspec in self.candidate_narrow_allows.get(base, ()):
            if (
                not self.deny.matches_narrow(base, nspec)
                and not self.ask.matches_narrow(base, nspec)
                and _narrow_spec_is_destructive(base, nspec)
            ):
                return True
        return False


def _tool_pattern_matches(pattern: str, tool_name: str) -> bool:
    """Match a permission rule pattern against a concrete tool name or rule."""
    parsed_pat = _parse_rule(pattern)
    parsed_query = _parse_rule(tool_name)
    if parsed_pat is None or parsed_query is None:
        return False
    _, _, p_blanket = parsed_pat
    q_base, q_spec, q_blanket = parsed_query
    bucket = _RuleBucket()
    bucket.add(pattern)
    if not q_blanket and q_spec is not None:
        return bucket.matches_narrow(q_base, q_spec)
    if p_blanket:
        return bucket.matches_blanket(q_base)
    return False


def is_destructive_tool(tool_name: str, annotations: Mapping[str, Any] | None = None) -> bool:
    """Return True when annotations, wildcards, or tool name indicate destructive or shell reach."""
    if annotations is not None and annotations.get("destructiveHint") is True:
        return True
    lowered = tool_name.strip().lower()
    if not lowered:
        return False
    if lowered == "*" or lowered.endswith("*"):
        return True
    if lowered in _EXACT_DESTRUCTIVE_TOOLS:
        return True
    return bool(_DESTRUCTIVE_VERBS_RE.search(lowered))


def resolve_tool_approval(
    tool_name: str,
    *,
    permissions: Mapping[str, Any] | None = None,
    always_allow: Iterable[str] = (),
    frontmatter_tools: Mapping[str, Any] | None = None,
    approval_policy: str | None = None,
    host_modelled: bool = True,
) -> HumanInTheLoop | None:
    """Resolve per-tool ``HumanInTheLoop`` from intra-settings precedence, or ``None`` if unknown.

    Precedence within the merged project/local settings:
    1. Blanket ``deny`` (and matching narrow ``deny``) -> ``HumanInTheLoop.REQUIRED``
    2. Blanket ``ask`` (and matching narrow ``ask``) -> ``HumanInTheLoop.REQUIRED``
    3. Blanket ``allow`` / ``alwaysAllow`` -> ``HumanInTheLoop.NONE`` (narrow deny/ask never
       suppresses a blanket allow for unrelated invocations)
    4. Narrow ``allow`` not suppressed by ``deny``/``ask`` -> ``HumanInTheLoop.CONDITIONAL``
    5. Host ``approval_policy`` / ``defaultMode`` when modelled (including ``acceptEdits``)
    6. ``None`` (unknown) for unmodelled hosts or absent rules
    """
    if not host_modelled:
        return None
    index = _RuleIndex(
        permissions=permissions,
        always_allow=always_allow,
        frontmatter_tools=frontmatter_tools,
        approval_policy=approval_policy,
        host_modelled=host_modelled,
    )
    return index.resolve(tool_name)


def oversight_gap_assessments(
    permissions: Mapping[str, Any] | None,
    *,
    always_allow: Iterable[str] = (),
    frontmatter_tools: Mapping[str, Any] | None = None,
    approval_policy: str | None = None,
    host_modelled: bool = True,
    source_name: str = "settings",
    text_formatter: Callable[[str], str] | None = None,
) -> tuple[dict[str, str], list[RiskAssessment]]:
    """Compute bounded per-tool ``human_in_the_loop`` map and ``oversight_gap`` findings."""
    tool_states, assessments, _, _ = evaluate_tool_oversight(
        permissions,
        always_allow=always_allow,
        frontmatter_tools=frontmatter_tools,
        approval_policy=approval_policy,
        host_modelled=host_modelled,
        source_name=source_name,
        text_formatter=text_formatter,
    )
    return tool_states, assessments


def evaluate_tool_oversight(
    permissions: Mapping[str, Any] | None,
    *,
    always_allow: Iterable[str] = (),
    frontmatter_tools: Mapping[str, Any] | None = None,
    approval_policy: str | None = None,
    host_modelled: bool = True,
    source_name: str = "settings",
    text_formatter: Callable[[str], str] | None = None,
    max_indexed_rules: int = MAX_INDEXED_PERMISSION_RULES,
) -> tuple[dict[str, str], list[RiskAssessment], int, bool]:
    """Compute bounded per-tool ``human_in_the_loop`` map, findings, total tool count, and truncation flag."""
    index = _RuleIndex(
        permissions=permissions,
        always_allow=always_allow,
        frontmatter_tools=frontmatter_tools,
        approval_policy=approval_policy,
        host_modelled=host_modelled,
        max_indexed_rules=max_indexed_rules,
    )
    fmt = text_formatter or _safe_settings_text
    raw_states: dict[str, str] = {}
    gap_tools: list[str] = []
    seen_gap_tools: set[str] = set()
    safe_source = neutralize(source_name)

    for tool_name in index.candidates:
        resolved = index.resolve(tool_name)
        state = resolved.value if resolved is not None else "unknown"
        safe_tool = neutralize(fmt(tool_name))
        prev = raw_states.get(safe_tool)
        if prev is None or _STATE_PRIORITY[state] < _STATE_PRIORITY[prev]:
            raw_states[safe_tool] = state

        has_gap = (
            resolved == HumanInTheLoop.NONE and is_destructive_tool(tool_name)
        ) or index.uncovered_destructive_narrow_allow(tool_name)
        if has_gap and safe_tool not in seen_gap_tools:
            seen_gap_tools.add(safe_tool)
            gap_tools.append(safe_tool)

    total_tools = len(raw_states)
    truncated = total_tools > MAX_RECORDED_TOOL_STATES or index.rules_truncated
    if total_tools > MAX_RECORDED_TOOL_STATES:
        ordered = sorted(raw_states.items(), key=lambda kv: (_STATE_PRIORITY.get(kv[1], 3), kv[0]))
        tool_states = dict(ordered[:MAX_RECORDED_TOOL_STATES])
    else:
        tool_states = raw_states

    assessments: list[RiskAssessment] = []
    if index.rules_truncated and host_modelled:
        # Rules past the cap may hold the allow that auto-approves a destructive tool.
        assessments.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="oversight_gap",
                detail=(
                    f"'{safe_source}' declares more than {max_indexed_rules} permission rules; "
                    "the rules past that limit were not evaluated, so a destructive or shell "
                    "tool may resolve to auto-approval without human-in-the-loop."
                ),
                recommendation=(
                    f"Reduce the permission rules to at most {max_indexed_rules} so that "
                    "every allow, ask and deny rule is evaluated."
                ),
            )
        )
    for safe_tool in gap_tools[:MAX_OVERSIGHT_GAP_FINDINGS]:
        assessments.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="oversight_gap",
                detail=(
                    f"Destructive or shell tool '{safe_tool}' resolves to auto-approval "
                    f"without human-in-the-loop in '{safe_source}'."
                ),
                recommendation=(f"Move '{safe_tool}' from allow/alwaysAllow to ask or deny rules."),
            )
        )
    overflow = len(gap_tools) - MAX_OVERSIGHT_GAP_FINDINGS
    if overflow > 0:
        assessments.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="oversight_gap",
                detail=(
                    f"{overflow} additional destructive or shell tools also resolve to "
                    f"auto-approval without human-in-the-loop in '{safe_source}'."
                ),
                recommendation="Move destructive tools from allow/alwaysAllow to ask or deny rules.",
            )
        )
    return tool_states, assessments, total_tools, truncated


def _default_rule_redactor(rule: str) -> str:
    """Safely scrub standalone rule specifiers so unredacted arguments never persist."""
    parsed = _parse_rule(rule)
    if parsed is None:
        return _safe_settings_text(rule)
    base, spec, is_blanket = parsed
    safe_base = _safe_settings_text(base)
    if is_blanket:
        if "(" in rule:
            _, _, rest = rule.partition("(")
            inner = rest[:-1].strip() if rest.endswith(")") else rest.strip()
            return f"{safe_base}({_safe_settings_text(inner)})"
        return safe_base
    if spec is None:
        return safe_base
    first_word = spec.split(None, 1)[0] if spec.split() else ""
    if (
        not first_word
        or "://" in first_word
        or "=" in first_word
        or any(op in first_word for op in (";", "&", "|", "`", "$", "(", ")", "'", '"'))
    ):
        return f"{safe_base}({REDACTED})"
    return f"{safe_base}({_safe_settings_text(first_word)})"


def extract_deny_rules(
    merged_settings: Mapping[str, Any],
    *,
    rule_formatter: Callable[[str], str] | None = None,
) -> list[str]:
    """Return bounded, redacted ``permissions.deny`` patterns from merged host settings."""
    rules, _, _, _ = extract_bounded_deny_rules(merged_settings, rule_formatter=rule_formatter)
    return rules


def extract_bounded_deny_rules(
    merged_settings: Mapping[str, Any],
    *,
    rule_formatter: Callable[[str], str] | None = None,
    max_rules: int = MAX_RECORDED_DENY_RULES,
) -> tuple[list[str], int, str | None, bool]:
    """Return ``(recorded_rules, total_count, full_digest, truncated)`` for ``permissions.deny``."""
    perms = merged_settings.get("permissions")
    if not isinstance(perms, Mapping):
        return [], 0, None, False
    fmt = rule_formatter or _default_rule_redactor
    formatted = sorted(
        {neutralize(fmt(rule)) for rule in _normalize_patterns(perms.get("deny")) if rule}
    )
    total = len(formatted)
    if total <= max_rules:
        return formatted, total, None, False
    digest = "sha256:" + hashlib.sha256(canonical_json(formatted).encode("utf-8")).hexdigest()
    return formatted[:max_rules], total, digest, True


def extract_sandbox_allowed_domains(
    merged_settings: Mapping[str, Any],
    *,
    text_formatter: Callable[[str], str] | None = None,
) -> list[str]:
    """Return sorted ``sandbox.network.allowedDomains`` entries from merged settings."""
    domains, _, _, _ = extract_bounded_sandbox_domains(
        merged_settings, text_formatter=text_formatter
    )
    return domains


def extract_bounded_sandbox_domains(
    merged_settings: Mapping[str, Any],
    *,
    max_domains: int = MAX_RECORDED_DOMAINS,
    text_formatter: Callable[[str], str] | None = None,
) -> tuple[list[str], int, str | None, bool]:
    """Return ``(recorded_domains, total_count, full_digest, truncated)`` for allowed domains."""
    sandbox = merged_settings.get("sandbox")
    if not isinstance(sandbox, Mapping):
        return [], 0, None, False
    network = sandbox.get("network")
    if not isinstance(network, Mapping):
        return [], 0, None, False
    fmt = text_formatter or _safe_settings_text
    domains = sorted(
        {neutralize(fmt(d)) for d in _normalize_patterns(network.get("allowedDomains"))}
    )
    total = len(domains)
    if total <= max_domains:
        return domains, total, None, False
    digest = "sha256:" + hashlib.sha256(canonical_json(domains).encode("utf-8")).hexdigest()
    return domains[:max_domains], total, digest, True


def extract_activation_scope(frontmatter: Mapping[str, Any]) -> dict[str, Any] | None:
    """Extract normalized ``activation`` scope (``always_apply`` and ``globs``)."""
    globs: set[str] = set()
    for key in ("globs", "applyTo", "paths"):
        for item in _normalize_patterns(frontmatter.get(key)):
            globs.add(_safe_settings_text(item))
    always_apply = frontmatter.get("alwaysApply") is True
    if not globs and not always_apply:
        return None
    sorted_globs = sorted(globs)
    scope: dict[str, Any] = {
        "always_apply": always_apply,
        "globs": sorted_globs[:MAX_ACTIVATION_GLOBS],
    }
    if len(sorted_globs) > MAX_ACTIVATION_GLOBS:
        scope["globs_truncated"] = True
        scope["globs_total"] = len(sorted_globs)
        scope["globs_digest"] = (
            "sha256:" + hashlib.sha256(canonical_json(sorted_globs).encode("utf-8")).hexdigest()
        )
    return scope


def extract_subagent_inline_mcp_servers(
    frontmatter: Mapping[str, Any], source_name: str
) -> list[RiskAssessment]:
    """Flag inline ``mcpServers`` declarations inside subagent front matter."""
    raw = frontmatter.get("mcpServers")
    if not raw:
        return []
    server_names: list[str] = []
    if isinstance(raw, Mapping):
        server_names = sorted(_safe_settings_text(str(k)) for k in raw)
    elif isinstance(raw, list):
        for item in raw:
            if isinstance(item, str) and item.strip():
                server_names.append(_safe_settings_text(item.strip()))
            elif isinstance(item, Mapping) and item.get("name"):
                server_names.append(_safe_settings_text(str(item["name"])))
    if not server_names and not isinstance(raw, (Mapping, list)):
        return []
    safe_source = neutralize(source_name)
    if len(server_names) > MAX_INLINE_MCP_SERVER_NAMES:
        shown = server_names[:MAX_INLINE_MCP_SERVER_NAMES]
        listed = f"{', '.join(shown)} (and {len(server_names) - MAX_INLINE_MCP_SERVER_NAMES} more)"
    elif server_names:
        listed = ", ".join(server_names)
    else:
        listed = "inline declaration"
    return [
        RiskAssessment(
            severity=RiskSeverity.MEDIUM,
            category="subagent_inline_mcp_server",
            detail=(
                f"Subagent '{safe_source}' declares inline mcpServers ({listed}), "
                "granting MCP tool access outside the top-level .mcp.json inventory."
            ),
            recommendation="Move MCP server definitions into a reviewed .mcp.json and pin versions.",
        )
    ]


def _parse_frontmatter_mapping(language: str, raw: str) -> dict[str, Any]:
    if language == "toml":
        parsed = toml_loads(raw)
        if not isinstance(parsed, dict):
            raise PolicyError("TOML front matter must be a mapping")
        return parsed
    return parse_yaml_mapping(raw, max_nodes=MAX_FRONTMATTER_YAML_NODES)


def _try_parse_frontmatter(language: str, raw: str) -> dict[str, Any] | None:
    try:
        return _parse_frontmatter_mapping(language, raw)
    except (PolicyError, ValueError, TypeError, RecursionError, MemoryError):
        return None


_DOTS_LINE_RE = re.compile(r"\.\.\.[ \t]*(?:\r\n|\r|\n|\Z)")


def _parse_frontmatter_candidates(
    candidates: list[tuple[str, str, str]],
) -> tuple[list[dict[str, Any]], bool, bool]:
    """Parse the `...` reading, the `---` reading and, failing that, the tail after `...`.

    Returns ``(metas, primary_ok, tail_ok)``. ``tail_ok`` is false when the `---` reading
    does not parse and the text after its `...` line does not parse on its own either.
    Such a file is reported as invalid, as a `---`-only parser refuses it, rather than
    read as if the tail were absent: the tail is where a smuggled server or activation
    would sit.
    """
    metas: list[dict[str, Any]] = []
    first_lang, first_raw, _ = candidates[0]
    if not first_raw.strip():
        primary_ok = True
    else:
        parsed = _try_parse_frontmatter(first_lang, first_raw)
        primary_ok = parsed is not None
        if parsed is not None:
            metas.append(parsed)
    tail_ok = True
    if len(candidates) == 2:
        alt_lang, alt_raw, _ = candidates[1]
        if alt_raw.strip():
            alt_meta = _try_parse_frontmatter(alt_lang, alt_raw)
            if alt_meta is not None:
                metas.append(alt_meta)
                primary_ok = True
            elif primary_ok and len(alt_raw) > len(first_raw):
                dots = _DOTS_LINE_RE.match(alt_raw, len(first_raw))
                after_dots = None if dots is None else alt_raw[dots.end() :]
                if after_dots is None:
                    tail_ok = False
                elif after_dots.strip():
                    tail_meta = _try_parse_frontmatter(alt_lang, after_dots)
                    if tail_meta is None:
                        tail_ok = False
                    else:
                        metas.append(tail_meta)
            else:
                tail_ok = False
    return metas, primary_ok, tail_ok


def scan_subagent_and_rule_frontmatter(
    files: Any,
    base: str,
    risks: list[RiskAssessment],
    properties: dict[str, Any],
    *,
    ide_type: str = "claude-code",
    scan_failures: list[str] | None = None,
    surfaces_excluded: list[str] | None = None,
    credential_check: Callable[[str, str | None], str | None] | None = None,
) -> None:
    """Inspect host-appropriate agent/rule Markdown front matter via ConfinedCollection."""
    prefix = f"{base}/" if base else ""
    subdirs: tuple[tuple[str, bool], ...]
    if ide_type == "claude-code":
        subdirs = ((f"{prefix}.claude/agents", True), (f"{prefix}.claude/rules", False))
    elif ide_type == "cursor" and not base:
        subdirs = ((".cursor/rules", False),)
    else:
        return

    activation_scopes: dict[str, dict[str, Any]] = {}
    for subdir, is_agent in subdirs:
        if not files.is_directory(subdir):
            continue
        suffixes = (".md",) if is_agent else (".mdc", ".md")
        for rel_path in sorted(files.iter_files(subdir)):
            rel = rel_path.as_posix()
            if not rel.endswith(suffixes):
                continue
            if credential_check is not None:
                target = files.in_root_target(rel_path)
                target_str = (
                    target.as_posix() if target is not None and target != rel_path else None
                )
                reason = credential_check(rel, target_str)
                if reason is not None:
                    if surfaces_excluded is not None:
                        surfaces_excluded.append(
                            f"{neutralize(rel)}: {reason}; not read or inventoried"
                        )
                    continue
            text = files.read_text(rel, missing_ok=True)
            if not text:
                continue
            if credential_check is not None:
                followed = files.link_target(rel)
                if followed is not None and credential_check(rel, followed) is not None:
                    if scan_failures is not None:
                        scan_failures.append(f"{neutralize(rel)}: file changed during collection")
                    continue
            candidates = front_matter_candidates(text)
            if not candidates:
                continue
            first_lang = candidates[0][0]
            metas, primary_ok, tail_ok = _parse_frontmatter_candidates(candidates)
            if not primary_ok or not tail_ok:
                if scan_failures is not None:
                    label = first_lang.upper() if first_lang in {"toml", "json"} else "YAML"
                    scan_failures.append(f"{neutralize(rel)}: invalid {label} front matter")
                continue
            if not metas:
                continue
            merged_meta: dict[str, Any] = {}
            for meta in metas:
                if is_agent:
                    risks.extend(extract_subagent_inline_mcp_servers(meta, rel))
                merged_meta.update(meta)
            if any(meta.get("alwaysApply") is True for meta in metas):
                merged_meta["alwaysApply"] = True
            if len(metas) > 1:
                for key in ("globs", "applyTo", "paths"):
                    combined_globs: list[str] = []
                    for meta in metas:
                        combined_globs.extend(_normalize_patterns(meta.get(key)))
                    if combined_globs:
                        merged_meta[key] = combined_globs
            scope = extract_activation_scope(merged_meta)
            if scope is not None:
                activation_scopes[neutralize(rel)] = scope
    if activation_scopes:
        properties["activation"] = activation_scopes
