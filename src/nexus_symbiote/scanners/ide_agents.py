"""IDE coding agent configuration scanner.

Discovers configurations for IDE-integrated AI coding agents:
  - Claude Code (.claude/, CLAUDE.md, .claude/settings.json)
  - Codex (.codex/, codex.md, .codex/config.toml)
  - Cursor (.cursor/, .cursorrules, .cursor/mcp.json, .cursor/hooks.json)
  - Gemini CLI (GEMINI.md, .gemini/settings.json)
  - Antigravity (.antigravity/)
  - XAI IDE agent configs
  - Windsurf (.windsurfrules, .windsurf/)
  - Cline (.clinerules, .cline/)
  - GitHub Copilot (.github/copilot-instructions.md)

Markers and settings are read at fixed paths beneath the project root; the tree is
walked only for the `.claude` settings of subdirectories. Every settings file a record
recognizes, JSON or TOML, is digested whole, so a changed value changes the record,
except, without the operator key, a value the redaction withholds from a file digested
after it; only some values are interpreted. Instruction files and directories among
the markers are inventoried by the `prompt` collector.
"""

from __future__ import annotations

import base64
import binascii
import fnmatch
import os
import re
from collections.abc import Callable, Iterable
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import canonical_json, hash_canonical, parse_json_strict
from nexus_symbiote.core.models import (
    IDEAgentComponent,
    ModelComponent,
    RiskAssessment,
    VerifiedExtensionComponent,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.credential_files import credential_gap
from nexus_symbiote.scanners.mcp import (
    _CODE_LOADING_ENVIRONMENT,
    SOURCE_BINDING_KEY_ENV,
    _exported_function,
)
from nexus_symbiote.scanners.source_binding import BindingError, value_binding
from nexus_symbiote.settings_precedence import (
    evaluate_tool_oversight,
    extract_bounded_deny_rules,
    extract_bounded_sandbox_domains,
    scan_subagent_and_rule_frontmatter,
)
from nexus_symbiote.utils.confined import ConfinedCollection, fold_name
from nexus_symbiote.utils.jsonc import strip_jsonc
from nexus_symbiote.utils.secrets import REDACTED, redact_keyed_text, redact_text
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.utils.toml import loads as load_toml

IDE_AGENT_CONFIGS: dict[str, dict[str, Any]] = {
    "claude-code": {
        "markers": [
            ".claude/settings.json",
            ".claude/settings.local.json",
            "CLAUDE.md",
            ".claude/CLAUDE.md",
            "CLAUDE.local.md",
            ".claude/commands",
            ".claude/skills",
            ".claude/agents",
            ".claude/rules",
            ".claude-plugin/plugin.json",
            ".claude-plugin/marketplace.json",
        ],
        "mcp_config": [".claude/mcp.json", ".mcp.json"],
    },
    "codex": {
        "markers": [
            ".codex/config.toml",
            ".codex/config.json",
            "codex.md",
            "CODEX.md",
            ".codex/instructions.md",
        ],
        "mcp_config": [],
    },
    "cursor": {
        "markers": [
            ".cursorrules",
            ".cursor/rules",
            ".cursor/settings.json",
            ".cursor/cli.json",
            ".cursor/hooks.json",
        ],
        "mcp_config": [".cursor/mcp.json"],
    },
    "gemini": {
        "markers": ["GEMINI.md", ".gemini/settings.json"],
        "mcp_config": [],
    },
    "antigravity": {
        "markers": [
            ".antigravity/config.json",
            ".antigravity/settings.json",
        ],
        "mcp_config": [],
    },
    "xai": {
        "markers": [
            ".xai/config.json",
            ".xai/settings.json",
        ],
        "mcp_config": [],
    },
    "windsurf": {
        "markers": [
            ".windsurfrules",
            ".windsurf/settings.json",
            ".windsurf/rules",
        ],
        "mcp_config": [".windsurf/mcp.json"],
    },
    "cline": {
        "markers": [
            ".clinerules",
            ".cline/settings.json",
        ],
        "mcp_config": [".cline/mcp.json"],
    },
    "copilot": {
        "markers": [
            ".github/copilot-instructions.md",
            ".github/copilot-extensions.json",
            ".github/instructions",
        ],
        "mcp_config": [],
    },
}
_CODEX_SPELLINGS = frozenset({"codex.md", "CODEX.md"})
CLAUDE_SETTINGS = [".claude/settings.json", ".claude/settings.local.json"]
_FOLDED_SETTINGS_NAMES = {
    fold_name(name): name for name in ("settings.json", "settings.local.json")
}
# A Claude Code plugin repository's own manifests; its root hooks/hooks.json is the
# plugin's hook configuration only when one of them is present.
CLAUDE_PLUGIN_MANIFESTS = [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"]
CLAUDE_PLUGIN_HOOKS = "hooks/hooks.json"
# The `agent.permissionMode` key read for these hosts is a project convention that
# vendor documentation does not describe; the files are read for it, and digested.
_AGENT_MODE_SETTINGS = {
    "cursor": [".cursor/settings.json"],
    "windsurf": [".windsurf/settings.json"],
    "cline": [".cline/settings.json"],
    "codex": [".codex/config.json"],
}
# Settings files whose values no record interprets. Each is read as editors read JSON,
# with comments and trailing commas, only to be digested.
_DIGESTED_SETTINGS = {
    "cursor": [".cursor/cli.json"],
    "antigravity": [".antigravity/config.json", ".antigravity/settings.json"],
    "xai": [".xai/config.json", ".xai/settings.json"],
    "copilot": [".github/copilot-extensions.json"],
}
# The keyed binding of every settings file an IDE record digests in `settings_hashes`.
SETTINGS_VALUE_BINDING_PROFILE = "nexus-symbiote/ide-settings-values/v1"
# What every `settings_hashes` digest covers, with or without the key: the file as
# `_projection` redacts it. Records without it come from releases that digested most
# files as read, so a file the redaction changes has another digest there.
SETTINGS_DIGEST_PROFILE = "nexus-symbiote/ide-settings-redacted/v1"
# Claude Code settings whose value is a command that runs to obtain credentials: an API
# key, AWS or Google Cloud credentials or OpenTelemetry headers. The command may hold one in a form the
# redaction does not recognise.
_CREDENTIAL_HELPER_KEYS = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
)
# Claude Code settings whose `{"type": "command", "command": ...}` value runs without an
# agent event, as a hook command does, and how the finding names each. Any settings file
# may declare them, and the same gates turn both off.
_AUTO_RUN_SETTINGS = {
    "statusLine": "a status line command that runs automatically",
    "fileSuggestion": "a file suggestion command that runs automatically when the user types @",
}
# Settings `env` applies to the session and every process it starts. These names send
# the API key, prompts or telemetry to another endpoint, proxy or trust store, add
# headers to API requests, replace the credential, or switch the session to a cloud
# provider (Amazon Bedrock and its Mantle endpoint, Google Cloud, Microsoft Foundry,
# Claude Platform on AWS) and to the account, project or key it sends prompts to. Only
# names are rated; values are never reported.
_REDIRECTING_ENVIRONMENT = re.compile(
    r"[A-Z0-9_]*_(?:BASE_URL|API_URL)|ANTHROPIC_(?:AUTH_TOKEN|API_KEY|CUSTOM_HEADERS)"
    r"|OTEL_EXPORTER_OTLP(?:_[A-Z]+)?_(?:ENDPOINT|HEADERS)|AWS_ENDPOINT_URL(?:_[A-Z0-9_]+)?"
    r"|(?:HTTPS?|ALL)_PROXY"
    r"|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|SSL_CERT_(?:FILE|DIR)"
    r"|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE"
    r"|CLAUDE_CODE_USE_(?:BEDROCK|MANTLE|VERTEX|FOUNDRY|ANTHROPIC_AWS|ANTHROPIC_GOOGLE_CLOUD)"
    r"|AWS_(?:BEARER_TOKEN_BEDROCK|ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN|PROFILE"
    r"|SHARED_CREDENTIALS_FILE|CONFIG_FILE)|GOOGLE_APPLICATION_CREDENTIALS"
    r"|ANTHROPIC_(?:VERTEX_PROJECT_ID|GOOGLE_CLOUD_PROJECT|FOUNDRY_(?:RESOURCE|API_KEY|AUTH_TOKEN)"
    r"|AWS_API_KEY|FEDERATION_RULE_ID|ORGANIZATION_ID)"
)
# Beyond the names the MCP collector treats as code loading: where programs are found,
# the git settings that run a program, and Claude Code's own shell, the prefix that wraps
# every command it runs, the script it runs before each Bash command, and plugin
# directories it loads.
_SETTINGS_CODE_ENVIRONMENT = re.compile(
    r"PATH|GIT_(?:SSH|SSH_COMMAND|EXEC_PATH|ASKPASS|TEMPLATE_DIR|CONFIG_[A-Z0-9_]+)|SSH_ASKPASS"
    r"|CLAUDE_CODE_(?:SHELL|SHELL_PREFIX|GIT_BASH_PATH|PLUGIN_DIRS)|CLAUDE_ENV_FILE"
)
CODEX_CONFIG = ".codex/config.toml"
CURSOR_HOOKS = ".cursor/hooks.json"
GEMINI_SETTINGS = ".gemini/settings.json"
_PERMISSION_MODES = frozenset(
    {
        "default",
        "manual",
        "plan",
        "acceptEdits",
        "bypassPermissions",
        "dontAsk",
        "ask",
        "auto",
        "read-only",
        "workspace-write",
        "full-access",
        "danger-full-access",
        "untrusted",
        "on-failure",
        "on-request",
        "never",
        "always",
    }
)
_MAX_SETTINGS_DEPTH = 64
# Tools whose unscoped grant gives a whole capability class, by Claude Code's names.
_SCOPED_TOOL_CLASSES = {
    "bash": "shell commands",
    "edit": "file edits",
    "write": "file edits",
    "multiedit": "file edits",
    "notebookedit": "file edits",
    "read": "file reads",
    "webfetch": "web fetches",
}
# A specifier made only of these characters names everything: Bash(*), Bash(:*),
# Edit(//**), Read(~/**), Edit(./**).
_WILDCARD_SPECIFIER = re.compile(r"[\s*:/~.]*")
_PWSH_EXEC_FLAG = (
    r"[-/](?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?"
    r"|e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?)"
)
_SUBSHELL_SPECIFIER = re.compile(
    r"(?i)\A(?:(?:/++(?:[A-Za-z0-9._-]++/++)*+)?env(?:\s++(?:-[A-Za-z0-9-]++|[A-Za-z_][A-Za-z0-9_]*+=\S*+))*+\s++)?"
    r"(?:/++(?:[A-Za-z0-9._-]++/++)*+)?"
    r"(?:"
    r"(?:(?:ba|z|da|k|a|c|tc)?sh|busybox|toybox)"
    r"(?::[\s\S]*|\s++(?:\*|:[\s\S]*|-[A-Za-z]*[cs]\b[\s\S]*|--command\b[\s\S]*))"
    r"|(?:python[0-9.]*+|node|nodejs|perl|ruby|cmd(?:\.exe)?)"
    r"(?::[\s\S]*|\s++(?:\*|:[\s\S]*|(?:-[ce]|/c)\b[\s\S]*))"
    r"|(?:pwsh|powershell)(?:\.exe)?"
    r"(?::[\s\S]*|\s++(?:\*|:[\s\S]*|" + _PWSH_EXEC_FLAG + r"\b[\s\S]*))"
    r")\Z"
)
_EXTENSION_ID = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z0-9][a-zA-Z0-9._-]*")
# Conservatively flag wildcard Bash rules naming these command runners. A fixed script
# with wildcard arguments also matches; this does not resolve the rule's effective scope.
# An interpreter is matched by its name with any version suffix.
_COMMAND_RUNNERS = frozenset(
    {
        "sh", "bash", "zsh", "dash", "fish", "ksh", "csh", "tcsh", "ash", "busybox",
        "node", "nodejs", "deno", "bun", "perl", "ruby", "php", "lua", "osascript",
        "pwsh", "powershell", "cmd",
        "eval", "exec", "command", "env", "sudo", "doas", "su", "xargs", "nohup",
        "timeout", "nice", "ionice", "setsid", "script", "watch",
        "docker", "podman", "nerdctl", "npx", "bunx", "uvx", "uv", "pipx",
    }
)  # fmt: skip
_VERSIONED_INTERPRETER = re.compile(r"(?:python|pypy|ruby|php|perl|node)[0-9.]*")


_RULE_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=\S*")
_WINDOWS_SUFFIX = re.compile(r"\.(?:exe|cmd|bat|com)\Z", re.IGNORECASE)


_QUOTED_RULE_PROGRAM = re.compile(r"""(?:"([^"]*)"|'([^']*)')(?=\s|:|\Z)""")
_EVAL_ARGUMENT = re.compile(r"\s+(?:-c|-e|/c|--?command)(?=\s|:|\Z)", re.IGNORECASE)


def _rule_program(specifier: str) -> tuple[str, str]:
    """Separate the bare program name from its Bash permission rule arguments."""
    words = specifier.split()
    index = 0
    while index < len(words) - 1 and _RULE_ASSIGNMENT.fullmatch(words[index]):
        index += 1
    if index >= len(words):
        return "", ""
    command = " ".join(words[index:])
    quoted = _QUOTED_RULE_PROGRAM.match(command)
    if quoted:
        path = quoted[1] if quoted[1] is not None else quoted[2]
        program = re.split(r"[/\\]", path)[-1]
        return _WINDOWS_SUFFIX.sub("", program), command[quoted.end() :]

    # Preserve the existing recognition of an unquoted Windows path with spaces.
    end = index + 1
    while "\\" in words[index] and end < len(words) and "\\" in words[end]:
        end += 1
    path = " ".join(words[index:end]).strip("\"'")
    arguments = " " + " ".join(words[end:]) if words[end:] else ""
    drive_end = 2 if re.match(r"[A-Za-z]:[\\/]", path) else 0
    separator = path.find(":", drive_end)
    if separator >= 0:
        prefix = re.split(r"[/\\]", path[:separator])[-1]
        runner = _WINDOWS_SUFFIX.sub("", prefix)
        scoped = path[separator:] + arguments
        if _runs_any_command(runner, scoped):
            return runner, scoped
    program = re.split(r"[/\\]", path)[-1]
    name, colon, pattern = program.partition(":")
    return _WINDOWS_SUFFIX.sub("", name), colon + pattern + arguments


def _runs_any_command(program: str, arguments: str, wildcard: bool = False) -> bool:
    """Whether a wildcard Bash rule names a known command runner or interpreter.

    `wildcard` is set when the `*` is in the program's directory, which the program
    name no longer holds, as in `Bash(*/bash)`.
    """
    if not wildcard and "*" not in program and "*" not in arguments:
        return False
    name = program.lower()
    if " " in name and _EVAL_ARGUMENT.match(arguments):
        # A locally named interpreter such as "my python.exe" with an evaluation switch.
        name = name.rsplit(" ", 1)[-1]
    return name in _COMMAND_RUNNERS or _VERSIONED_INTERPRETER.fullmatch(name) is not None


def _broad_grants(allowed: list[str]) -> list[str]:
    """Capability classes that the allow list grants without a narrowing specifier."""
    classes: set[str] = set()
    for value in allowed:
        rule = value.strip()
        if rule == "*":
            classes.add("every tool")
            continue
        tool, opened, rest = rule.partition("(")
        tool = tool.strip()
        specifier = None
        if opened:
            if not rest.endswith(")"):
                continue
            specifier = rest[:-1].strip()
        key = tool.lower()
        if key.startswith("mcp__"):
            server = key.removeprefix("mcp__")
            whole_server = "__" not in server or server.endswith("__*")
            if server in {"", "*"} or (whole_server and specifier in (None, "", "*")):
                classes.add("MCP server tools")
            continue
        broad = specifier is None or bool(_WILDCARD_SPECIFIER.fullmatch(specifier))
        if key == "bash" and specifier is not None:
            program, arguments = _rule_program(specifier)
            broad |= _runs_any_command(program, arguments, "*" in specifier) or bool(
                _SUBSHELL_SPECIFIER.fullmatch(program + arguments)
            )
        if key == "webfetch" and specifier is not None:
            # `domain:**` and `domain:*.*` match every host, as `domain:*` does.
            domain = specifier.replace(" ", "")
            broad |= domain.startswith("domain:") and not domain[7:].strip("*.")
        if key == "read" and specifier is None:
            # A bare Read grant covers the working directory, as reading does by default.
            continue
        if broad and key in _SCOPED_TOOL_CLASSES:
            classes.add(_SCOPED_TOOL_CLASSES[key])
    return sorted(classes)


# Text is redacted piece by piece between these shell operators, which are kept, so a
# URL ends at the first of them: a command, a host or an operator glued to a URL or to a
# credential assignment stays covered while the URL's path and the value are withheld.
# A piece is also cut before each URL scheme after its first one, so every URL keeps its
# own host whatever separates it from the text before it.
_SHELL_OPERATORS = re.compile(r"([;|&$`(){}<>\n]+)")
_SCHEME_CHARACTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+.-")
# A URL authority that URL parsers read differently: urlsplit takes the host after the
# last "@", WHATWG parsers end the authority at a backslash and, for special schemes,
# skip any number of slashes, so the redaction could keep a host the client never uses.
_URL_AUTHORITY = re.compile(r"(?<![a-zA-Z0-9+.-])([a-zA-Z0-9+.-]+)://([^/?#\s\"'<>]*)")
_SPECIAL_SCHEMES = frozenset({"http", "https", "ws", "wss", "ftp"})


class AmbiguousURLError(ValueError):
    """A settings URL whose host the redaction cannot keep as clients read it."""


def _ambiguous_authority(text: str) -> bool:
    return any(
        "\\" in authority or (not authority and scheme.lower() in _SPECIAL_SCHEMES)
        for scheme, authority in _URL_AUTHORITY.findall(text)
    )


def _url_pieces(text: str) -> list[str]:
    """``text`` cut before each URL scheme, in linear time.

    Cutting before the first scheme too keeps the host of a URL assigned to a
    credential-named option (``--token-url=URL``) out of the assignment the redaction
    removes whole; userinfo, path and query stay redacted.
    """
    cuts: list[int] = []
    floor = 0
    index = text.find("://")
    while index != -1:
        start = index
        while start > floor and text[start - 1] in _SCHEME_CHARACTERS:
            start -= 1
        while start < index and not ("a" <= text[start].lower() <= "z"):
            start += 1
        if start < index:
            cuts.append(start)
        floor = index + 3
        index = text.find("://", floor)
    bounds = [0, *cuts, len(text)]
    parts = [text[begin:end] for begin, end in zip(bounds, bounds[1:], strict=False)]
    return [part for part in parts if part] or [text]


def _projected_text(value: str, *, unkeyed: bool) -> str:
    pieces = _SHELL_OPERATORS.split(value)
    for index in range(0, len(pieces), 2):
        parts = _url_pieces(pieces[index])
        if unkeyed and any(_ambiguous_authority(part) for part in parts):
            raise AmbiguousURLError("a URL authority is ambiguous")
        # A white space ends a redacted URL, so no host can absorb the next part's text.
        pieces[index] = " ".join(redact_text(part) for part in parts)
    return "".join(pieces)


# Free text that settings pass to a program: a command, its arguments or an HTTP header
# value. The redaction does not recognise a credential written there as an ordinary
# word, such as `--password 482913` or `X-Pin: 482913`, so the digest keeps only its
# shape: the program each command runs and the origin of each URL.
_COMMAND_KEYS = frozenset({"command", "args", "notify", "headershelper"})
_HEADER_MAPS = frozenset({"headers", "httpheaders", "http_headers", "env_http_headers"})
# A command word kept by shape: a path or name, quoted or not, that may refer to a
# variable by name but expands nothing else, so `${PIN:-482913}` is not kept. Every
# quantifier is possessive: `$aa$aa…!` must fail once, not once per way to split it.
_PROGRAM_WORD = re.compile(r"(?:[\w./~+@%:,*?\[\]-]|\$\w++|\$\{\w++\})++")
_ASSIGNMENT = re.compile(r"[A-Za-z_]\w*(?:\[[^\]]*\])?\+?=")
_BLANKS = frozenset(" \t")
_SEPARATORS = frozenset(";&|\n")


class _CommandShape:
    """A shell command line split into text runs and operators, read conservatively.

    A word is kept as a program only where a shell runs it as a command: first in the
    value or after `;`, `&`, `|`, a newline, `(`, `$(` or an opening backtick, after
    any `NAME=value` assignments and file descriptor numbers. Quoted text, an escaped or
    continued line (`\\` before a newline), a comment, a redirection target, arithmetic
    (`((...))`, `$((...))`), an array assignment and a `[[ ... ]]` test start no command.
    Everything after `case`, whose patterns follow command separators, and from a here
    document or here-string operator (`<<`, `<<-`, `<<<`) to the end of the value, whose
    body the operator does not end, keeps no word.
    """

    def __init__(self, value: str, *, program: bool, unkeyed: bool) -> None:
        self.value = value
        self.unkeyed = unkeyed
        self.out: list[str] = []
        self.run: list[str] = []
        self.word: list[str] = []
        self.program: str | None = None
        self.start = program
        self.programs = program
        self.redirect = False
        self.quiet = 0
        self.test = False
        self.backtick = False

    def _end_word(self, following: str) -> None:
        if not self.word:
            return
        word = "".join(self.word)
        self.word.clear()
        if self.test:
            self.test = word != "]]"
            return
        if self.redirect:
            self.redirect = False
            return
        if not self.start or self.quiet:
            return
        if word.isdigit() and following in "<>":
            return
        if _ASSIGNMENT.match(word):
            return
        self.start = False
        bare = word.replace('"', "").replace("'", "")
        if self.program is None and "://" not in word and _PROGRAM_WORD.fullmatch(bare):
            self.program = word
        if word == "case":
            self.programs = False
        elif word == "[[":
            self.test = True

    def _flush(self) -> None:
        text = "".join(self.run)
        self.run.clear()
        parts = _url_pieces(text)
        if self.unkeyed and any(_ambiguous_authority(part) for part in parts):
            raise AmbiguousURLError("a URL authority is ambiguous")
        kept = redact_text(self.program).split()[:1] if self.program else []
        for part in parts:
            words = redact_text(part).split()
            if "://" in part[:64] and _URL_AUTHORITY.match(part) and words:
                # Text glued to the origin by a quote, as in `https://a.example"482913"`,
                # is not part of it.
                origin = _URL_AUTHORITY.match(words[0])
                kept.append(origin.group(0) if origin else words[0])
        self.program = None
        self.out.append(" ".join(kept) if kept else (REDACTED if text.strip() else ""))

    def _operator(self, text: str, index: int, *, starts: bool = False) -> int:
        self._end_word(text[0])
        self._flush()
        self.out.append(text)
        self.redirect = False
        if starts:
            self.start = self.programs and not self.quiet and not self.test
        return index + len(text)

    def _quoted(self, index: int, close: str, *, escapes: bool) -> int:
        end = index + 1
        while end < len(self.value) and self.value[end] != close:
            end += 2 if escapes and self.value[end] == "\\" else 1
        end = min(end + 1, len(self.value))
        self.word.append(self.value[index:end])
        self.run.append(self.value[index:end])
        return end

    def shape(self) -> str:
        value, index = self.value, 0
        while index < len(value):
            char, following = value[index], value[index + 1 : index + 2]
            if char in _BLANKS:
                self._end_word(char)
                self.run.append(char)
                index += 1
            elif char == "\\":
                # A backslash before LF or CRLF continues the line, as a shell reads it
                # whichever line ending the settings file was saved with.
                width = 3 if value[index + 1 : index + 3] == "\r\n" else 2
                if value[index + 1 : index + width] not in ("\n", "\r\n"):
                    self.word.append(value[index : index + width])
                self.run.append(value[index : index + width])
                index += width
            elif char == "'":
                index = self._quoted(index, "'", escapes=False)
            elif char == '"':
                index = self._quoted(index, '"', escapes=True)
            elif char == "$" and following == "'":
                self.word.append("$")
                self.run.append("$")
                index = self._quoted(index + 1, "'", escapes=True)
            elif char == "#" and not self.word:
                end = value.find("\n", index)
                index = len(value) if end == -1 else end
            elif char == "<" and following == "<":
                operator = value[index : index + 3]
                if operator not in ("<<<", "<<-"):
                    operator = "<<"
                self._operator(operator, index)
                if value[index + len(operator) :].strip():
                    self.out.append(REDACTED)
                return "".join(self.out)
            elif char in "<>" or (char == "&" and following == ">"):
                operator = char + following if following in "<>&|" else char
                if operator == "&>" and value[index + 2 : index + 3] == ">":
                    operator += ">"
                index = self._operator(operator, index)
                self.redirect = True
            elif char in _SEPARATORS:
                index = self._operator(char, index, starts=True)
            elif char == "`":
                self.backtick = not self.backtick
                index = self._operator(char, index, starts=self.backtick)
                self.start = self.start and self.backtick
            elif char == "(" or (char == "$" and following == "("):
                array = not self.quiet and self.word[-1:] == ["="]
                operator = "$(" if char == "$" else "("
                arithmetic = value[index + len(operator) : index + len(operator) + 1] == "("
                if arithmetic:
                    operator += "("
                index = self._operator(operator, index, starts=not array and not arithmetic)
                if self.quiet or array or arithmetic:
                    self.quiet += operator.count("(")
                    self.start = False
            elif char == ")":
                index = self._operator(char, index)
                self.quiet = max(self.quiet - 1, 0)
                self.start = False
            else:
                self.word.append(char)
                self.run.append(char)
                index += 1
        self._end_word("")
        self._flush()
        return "".join(self.out)


def _free_text(value: str, *, program: bool, unkeyed: bool) -> str:
    """``value`` by shape: every URL origin and, when ``program``, the program word of
    each command (``_CommandShape``); operators are kept, other words are not."""
    return _CommandShape(value, program=program, unkeyed=unkeyed).shape()


# Lists of permission rules such as `Bash(mysql -p482913 db:*)`, by the key that holds
# them and, where the name alone is too common, the key above it. A rule keeps its tool
# name and the shape of its specifier, so the words of a command it names stay out of
# the digest; a hook `matcher` is read the same way.
_RULE_LISTS = frozenset({"excludetools", "coretools", "allowedtools"})
_NESTED_RULE_LISTS = {
    "permissions": frozenset({"allow", "ask", "deny"}),
    "tools": frozenset({"exclude", "core", "allowed"}),
}
# Maps whose values are environment variable values or URL parameters: they keep their
# names only, as `env` does. Codex sets a command's environment in
# `shell_environment_policy.set` and a provider's query parameters in `query_params`.
_NAMES_ONLY_MAPS = frozenset({"env", "query_params"})
_NESTED_NAMES_ONLY_MAPS = {"shell_environment_policy": frozenset({"set"})}
# Values that hold a credential under their own name, withheld like a credential helper.
_CREDENTIAL_VALUE_KEYS = frozenset({"experimental_bearer_token", "clientsecret"})
_RULE = re.compile(r"([^()]*)\((.*)\)", re.DOTALL)


def _rule_text(value: str, *, unkeyed: bool) -> str:
    """A permission rule or hook matcher with its specifier reduced to its shape."""
    match = _RULE.fullmatch(value)
    if match is None:
        return _projected_text(value, unkeyed=unkeyed)
    tool, specifier = match.groups()
    shape = _free_text(specifier, program=True, unkeyed=unkeyed)
    return f"{_projected_text(tool, unkeyed=unkeyed)}({shape})"


def _safe_rule_shape(rule: str) -> str:
    """Format a permission rule by its unkeyed projection shape for inventory properties."""
    try:
        return neutralize(_rule_text(rule, unkeyed=True))
    except AmbiguousURLError:
        base, sep, _ = rule.partition("(")
        safe_base = neutralize(redact_text(base.strip())) or REDACTED
        return f"{safe_base}({REDACTED})" if sep else safe_base


def _safe_projected_text(value: str) -> str:
    """Format a settings string by its unkeyed projection for inventory properties."""
    try:
        return neutralize(_projected_text(value, unkeyed=True))
    except AmbiguousURLError:
        return REDACTED


def _command_projection(value: Any, depth: int, *, unkeyed: bool, program: bool) -> Any:
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    if isinstance(value, str):
        return _free_text(value, program=program, unkeyed=unkeyed)
    if isinstance(value, list):
        return [
            _command_projection(item, depth + 1, unkeyed=unkeyed, program=program and not index)
            for index, item in enumerate(value)
        ]
    return _projection(value, depth + 1, unkeyed=unkeyed)


def _projection(
    value: Any,
    depth: int = 0,
    *,
    env: bool = False,
    headers: bool = False,
    unkeyed: bool = True,
    parent: str = "",
    key: str | None = None,
) -> Any:
    """Settings as a redacted `settings_hashes` digest covers them.

    The standard redaction is applied to the text between shell operators, cut again
    before each URL scheme, a text value is also redacted by the ``key`` it is held
    under, as a header or an assignment in one string would be, environment variables
    keep their names only, and each credential helper of ``_CREDENTIAL_HELPER_KEYS``,
    such as `apiKeyHelper`, keeps its key but not its command, so the digest cannot
    confirm a guess of a value the redaction removes, and does not change with one; only
    the keyed binding covers those values. A command, its arguments, the value of an HTTP
    header and the specifier of a permission rule or hook matcher keep only their shape
    (``_free_text``), since they can hold a credential the redaction does not recognise.
    Maps of environment values or URL parameters keep their names only, and a value named
    as a credential, such as Codex's `experimental_bearer_token`, is withheld.
    ``unkeyed`` raises ``AmbiguousURLError`` for a URL whose authority URL parsers read
    differently, since its redacted origin could hide a change of host that no keyed
    binding covers.
    """
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    if isinstance(value, dict):
        if env:
            return sorted(_projected_text(str(field), unkeyed=unkeyed) for field in value)
        projected: dict[str, Any] = {}
        merged: dict[str, list[Any]] = {}
        for field, item in value.items():
            text = _projected_text(str(field), unkeyed=unkeyed)
            name = str(field).lower()
            entry: Any
            rules = name in _RULE_LISTS or name in _NESTED_RULE_LISTS.get(parent, ())
            if (
                field in _CREDENTIAL_HELPER_KEYS
                or name in _CREDENTIAL_VALUE_KEYS
                or (headers and isinstance(item, str))
            ):
                entry = REDACTED
            elif headers or name in _COMMAND_KEYS or name.endswith("command"):
                entry = _command_projection(
                    item, depth + 1, unkeyed=unkeyed, program=not headers and name != "args"
                )
            elif name == "matcher" and isinstance(item, str):
                entry = _rule_text(item, unkeyed=unkeyed)
            elif rules and isinstance(item, list):
                entry = [
                    _rule_text(rule, unkeyed=unkeyed)
                    if isinstance(rule, str)
                    else _projection(rule, depth + 2, unkeyed=unkeyed)
                    for rule in item
                ]
            else:
                entry = _projection(
                    item,
                    depth + 1,
                    env=name in _NAMES_ONLY_MAPS or name in _NESTED_NAMES_ONLY_MAPS.get(parent, ()),
                    headers=name in _HEADER_MAPS,
                    unkeyed=unkeyed,
                    parent=name,
                    key=str(field),
                )
            merged.setdefault(text, []).append(entry)
            projected[text] = entry
        # Keys the redaction makes equal keep every value, in canonical order, so no
        # value the redaction leaves in place drops out of the digest.
        for text, entries in merged.items():
            if len(entries) > 1:
                projected[text] = sorted(entries, key=canonical_json)
        return projected
    if isinstance(value, list):
        if headers:
            # A header list such as `["X-Pin: 482913"]` keeps each header's name.
            return [
                _header_line(item, unkeyed=unkeyed)
                if isinstance(item, str)
                else _projection(item, depth + 1, unkeyed=unkeyed)
                for item in value
            ]
        return [_projection(item, depth + 1, unkeyed=unkeyed) for item in value]
    if isinstance(value, str):
        text = _projected_text(value, unkeyed=unkeyed)
        return text if key is None else redact_keyed_text(key, value, redacted=text)
    return value


def _header_line(value: str, *, unkeyed: bool) -> str:
    name, colon, _ = value.partition(":")
    return f"{_projected_text(name, unkeyed=unkeyed)}: {REDACTED}" if colon else REDACTED


# Command words are read once per segment. A name must end its path: in
# `./bash/process.py` or `tools/sh/lint` it is a directory. `${IFS}` and `$IFS`
# are both an empty insertion (`c${IFS}url`) and a split (`bash${IFS}/dev/stdin`).
_SHELL_NAMES = frozenset(
    {"powershell", "pwsh", "bash", "dash", "zsh", "ksh", "ash", "fish", "sh", "csh", "tcsh", "cmd"}
)
_EVAL_NAMES = frozenset({"eval", "source", "."})
_IEX_NAMES = frozenset({"iex", "invoke-expression"})
_PYTHON_NAMES = frozenset({"python", "python2", "python3", "py"})
_DOWNLOAD_NAMES = frozenset(
    {"curl", "wget", "iwr", "irm", "invoke-webrequest", "invoke-restmethod"}
)
_STDOUT_NAMES = frozenset({"", "-", "/dev/stdout", "/dev/stderr", "/dev/fd/1", "/dev/fd/2"})
# `python3.12`, `lua5.4` or `php8.2` is that interpreter.
_VERSIONED_NAME = re.compile(r"(python|ruby|php|perl|lua|nodejs|node)[0-9][0-9.]*")
# Each matcher runs once per pipeline segment, so a command of repeated near
# misses costs linear time whatever its length.
_SEGMENT_BOUNDARY = re.compile(r"[\n|;&]")
_PREFIX_REDIR = re.compile(r"\d*(?:<<-|<<<|<<|<>|>>|>&|&>|[<>])")
# `base64` decodes with `-d` or `-D`, alone or in a bundle such as `-di`, or `--decode`,
# which GNU getopt also takes abbreviated, anywhere among its arguments. The letters
# before the flag's leave it out, so a long bundle that ends in another character is
# read once, not once for each `d` in it. A letter after it that takes a value (GNU's
# `-w`, macOS's `-b`, `-i` and `-o`) ends the bundle with any value: `-dw+76`.
_BASE64_DECODE = re.compile(
    r"-[A-CE-Za-ce-z0-9]*[dD][A-Za-z0-9]*(?:[biow][\s\S]*)?"
    r"|(?i:--d(?:e(?:c(?:o(?:de?)?)?)?)?)"
)
# `sudo -s`, `-i`, alone or in a bundle such as `-Es`, or their long forms; the letters
# before the flag's leave it out for the same reason.
# sudo takes any unambiguous prefix of a long option: `--sh` is `--shell`; `--login`
# has none, since `--login-class` shares every shorter one.
_SUDO_SHELL_FLAG = re.compile(r"--sh(?:e(?:ll?)?)?|--login|-[A-Za-hj-rt-z]*[si][A-Za-z]*")
_SCRIPT_FLAG = re.compile(r"(?i)-c(?:ommand(?:withargs)?)?\Z|-[A-Za-z]*c\Z")
# An interpreter's flag that takes its program as the next argument: `-e`, `-E`, `-p`,
# `-r` (PHP only: node and ruby load a module with it) and the long `--eval` and
# `--print`, alone or after other short flags.
_CODE_FLAG = re.compile(r"-[A-Za-z]*[eEp]\Z|--(?:eval|print)\Z")
_PHP_CODE_FLAG = re.compile(r"-[A-Za-z]*[eEpr]\Z")
# Where a flag's name ends when its value is attached: `--eval="$(...)"`, `-c"$(...)"`.
_FLAG_NAME = re.compile(r"-[^\s|&;<>=\"'$`]*")
_POWERSHELL = re.compile(r"\b(?:powershell|pwsh)(?:\.exe)?\b", re.IGNORECASE)
_POWERSHELL_FILE_NAMES = ("pwsh", "pwsh.exe", "powershell", "powershell.exe")
# PowerShell takes -, en dash, em dash or horizontal bar before a parameter name. A shell
# removes quotes and escapes before PowerShell reads the argument. The console host reads
# `-e`, `-ec` and every prefix of `-EncodedCommand` as that parameter
# (CommandLineParameterParser: MatchSwitch(key, "encodedcommand", "e") or "ec");
# -ExecutionPolicy needs at least `-ex`, and the host has no -ErrorAction switch.
_ENCODED_PREFIX = (
    "e(?:c|n(?:c(?:o(?:d(?:e(?:d(?:c(?:o(?:m(?:m(?:a(?:n(?:d)?)?)?)?)?)?)?)?)?)?)?)?)?"
)
# The console host also takes `/` before a parameter name, as in `/enc`; that form must
# end the argument, so that a script path such as `/e.ps1` is not read as one.
_ENCODED_COMMAND = re.compile(
    rf"(?<!\S)[\"'\u2018-\u201e\\^`]*"
    rf"(?:[-\u2013\u2014\u2015]{_ENCODED_PREFIX}\b|/{_ENCODED_PREFIX}(?![^\s\"'\u2018-\u201e]))",
    re.IGNORECASE,
)
_ARGUMENT = re.compile(r"\S+")
# Letters, digits and punctuation that sh, bash, zsh, cmd and PowerShell all pass on as
# written, as one argument, with a backslash only between them. Any other argument may
# be expanded, unquoted, joined to the next one or dropped, as a redirection is.
_PLAIN = re.compile(r"[\w.+:=#~/\u2013\u2014\u2015-]+(?:\\+[\w.+:=#~/\u2013\u2014\u2015-]+)*")
# A shell or PowerShell expansion, which may be empty or `-`. One left open runs to the
# end of the argument, so each `$` is matched once.
_EXPANSION = re.compile(
    r"\$(?:\{[^}]*\}?|\([^)]*\)?|'[^']*'?|\w+(?::\w+)?|.?)|`[^`]*`|%[^%]*%|![^!]*!"
)
_SCRIPT_CHARACTER = re.compile(r"[\w/.]")
_REDIRECTION = re.compile(r"[<>]")


def _abbreviations(*parameters: tuple[str, int]) -> frozenset[str]:
    """Each parameter name and its abbreviations down to the shortest one accepted."""
    return frozenset(
        name[:end] for name, shortest in parameters for end in range(shortest, len(name) + 1)
    )


# PowerShell passes every argument after -Command or -CommandWithArgs to the command, and
# every argument after -File <script> to the script, as it does after a first positional
# argument, which pwsh reads as -File and Windows PowerShell as -Command. -File - reads
# commands from standard input and goes on reading parameters. Only abbreviations both
# editions accept count: `-c` and `-com` to `-command`, but not `-co`, which may be
# -ConfigurationName.
_POWERSHELL_COMMAND = _abbreviations(("c", 1), ("command", 3), ("commandwithargs", 15), ("cwa", 3))
_POWERSHELL_FILE = _abbreviations(("file", 1))
# Switches that take no value in either edition. Any other parameter may take the next
# argument as its value, even one that starts with `-`.
_POWERSHELL_SWITCHES = _abbreviations(
    ("noprofile", 3), ("nologo", 3), ("noninteractive", 4), ("noexit", 3), ("sta", 3), ("mta", 3)
)
_HOOK_URL = re.compile(r"https?://", re.IGNORECASE)
# A host name or IPv4 address, with an optional port, before a path: what curl and wget
# fetch over HTTP when the URL has no scheme.
_HOST_PATH = re.compile(r"(?:[A-Za-z0-9-]+\.)+[A-Za-z0-9-]+(?::[0-9]+)?/")
_SEVERITY_RANK = {severity: index for index, severity in enumerate(RiskSeverity)}


_GROUP_KEYWORDS = {"if": "fi", "while": "done", "until": "done", "for": "done"}
_GROUP_KEYWORDS |= {"select": "done", "case": "esac"}
_GROUP_ENDS = frozenset(_GROUP_KEYWORDS.values())
# Reserved words that open a compound command's next part; the command after one is
# the next word, as after `{`, `(` and `!`.
_RESERVED_PREFIXES = frozenset({"if", "while", "until", "then", "do", "else", "elif"})


def _command_pipelines(command: str, *, piped_groups: bool = False) -> list[list[str]]:
    """Pipelines in ``command``.

    ``|`` and ``|&`` separate segments of one pipeline. A newline after either stays
    in that pipeline, as the shell reads it. ``||`` does not: it is a logical or, as
    ``&&``, ``;``, a newline elsewhere and a background ``&`` are command separators.
    ``>&``, ``<&`` and ``&>`` stay inside a segment.

    With ``piped_groups``, a group or compound command that a pipe feeds (`{ ...; }`,
    `( ... )`, `if`/`while`/`until`/`for`/`select`/`case`) passes the pipe to every
    command inside it, so those commands stay later segments of the same pipeline
    instead of starting new ones: `curl x | { true; sh; }` runs the download in `sh`.
    The group is read lexically, so this view can only add segments after a pipe.
    """
    pipelines: list[list[str]] = []
    segments: list[str] = []
    buf: list[str] = []
    length = len(command)
    index = 0
    # Open groups, innermost last: (closer, whether a pipe feeds it). "$(" and the
    # process substitutions are pushed as ")" too, so their ")" is not a group's.
    groups: list[tuple[str, bool]] = []

    # Where the current segment starts in `command`, for a bounded look back.
    segment_start = [0, False]

    def at_command_start() -> bool:
        # Constant work per call: at most 40 characters back, a word of at most 6.
        floor = max(segment_start[0], index - 40)
        back = index
        while back > floor and command[back - 1] in " \t\r\n":
            back -= 1
        if back == segment_start[0]:
            return True
        word_end = back
        while back > floor and command[back - 1] not in " \t\r\n;&|":
            back -= 1
        if word_end - back > 6 or (back == floor and back != segment_start[0]):
            return False
        return command[back:word_end] in _RESERVED_PREFIXES | {"{", "(", "!"}

    def word_at(position: int) -> str:
        end = position
        while end < length and command[end] not in " \t\r\n;&|()<>":
            end += 1
        return command[position:end]

    # A count of the open groups a pipe feeds keeps each separator O(1); scanning the
    # stack instead made `{ { { ...; ...; ...` quadratic.
    fed = [0]

    def piped() -> bool:
        return fed[0] > 0

    def push(closer: str, feeds: bool) -> None:
        groups.append((closer, feeds))
        fed[0] += feeds

    def pop() -> None:
        fed[0] -= groups.pop()[1]

    def flush_segment() -> None:
        segments.append("".join(buf))
        buf.clear()
        segment_start[1] = True

    def flush_command() -> None:
        flush_segment()
        if any(segment.strip() for segment in segments):
            pipelines.append(segments.copy())
        segments.clear()

    while index < length:
        if segment_start[1]:
            segment_start[0], segment_start[1] = index, False
        char = command[index]
        nxt = command[index + 1] if index + 1 < length else ""
        if piped_groups:
            if char == "$" and nxt == "(" or char in "<>" and nxt == "(":
                push(")", False)
                buf.append(command[index : index + 2])
                index += 2
                continue
            if char == ")" and groups and groups[-1][0] == ")":
                pop()
            elif char == "(" and nxt != "(" and at_command_start():
                push(")", bool(segments) or piped())
            elif at_command_start() and (index == 0 or command[index - 1] in " \t\r\n;&|({"):
                word = word_at(index)
                if word == "{" or word in _GROUP_KEYWORDS:
                    closer = "}" if word == "{" else _GROUP_KEYWORDS[word]
                    push(closer, bool(segments) or piped())
                elif groups and word == groups[-1][0] and word in _GROUP_ENDS | {"}"}:
                    pop()
        if (
            piped_groups
            and piped()
            and (char == "|" and nxt == "|" or char == "&" and nxt == "&" or char in ";\n")
        ):
            # Inside a group a pipe feeds, the next command reads the same pipe.
            flush_segment()
            index += 2 if char in "|&" else 1
            continue
        if char == "|" and nxt == "|":
            flush_command()
            index += 2
            continue
        if char == "|" and nxt == "&":
            flush_segment()
            index = _skip_pipe_gap(command, index + 2)
            continue
        if char == "|":
            flush_segment()
            index = _skip_pipe_gap(command, index + 1)
            continue
        if char == "&" and nxt == "&":
            flush_command()
            index += 2
            continue
        if char in "><" and nxt == "&":
            buf.append(f"{char}&")
            index += 2
            continue
        if char == ">" and nxt == "|":
            # `>|` writes a file even under noclobber; it is not a pipe.
            buf.append(">|")
            index += 2
            continue
        if char == "&" and nxt == ">":
            buf.append("&>")
            index += 2
            continue
        if char == "\\" and (nxt == "\n" or command.startswith("\r\n", index + 1)):
            # A line continuation joins the two lines into one command.
            index += 2 if nxt == "\n" else 3
            continue
        if char in "&;\n":
            flush_command()
            index += 1
            continue
        buf.append(char)
        index += 1
    flush_command()
    return pipelines


def _skip_pipe_gap(command: str, index: int) -> int:
    """Whitespace, including newlines, that a pipe may have before its next command."""
    length = len(command)
    while index < length and command[index] in " \t\r\n":
        index += 1
    return index


def _shell_word_spans(segment: str) -> list[tuple[int, int]]:
    """Word spans. Quotes and backslashes keep spaces inside one word."""
    spans: list[tuple[int, int]] = []
    start: int | None = None
    index = 0
    length = len(segment)
    quote = ""
    while index < length:
        char = segment[index]
        if quote == "$'":
            # In bash's ANSI-C quoting a backslash escapes the closing quote: `$'\''`.
            index += 2 if char == "\\" else 1
            quote = "" if char == "'" else quote
            continue
        if quote:
            if char == quote:
                quote = ""
            elif quote == '"' and char == "\\" and index + 1 < length:
                index += 2
                continue
            index += 1
            continue
        if char == "$" and segment.startswith("$'", index):
            if start is None:
                start = index
            quote = "$'"
            index += 2
            continue
        if char in "'\"":
            if start is None:
                start = index
            quote = char
            index += 1
            continue
        if char == "\\" and index + 1 < length:
            if start is None:
                start = index
            index += 2
            continue
        if char == "(" and start is None and (index == 0 or segment[index - 1] not in "<>"):
            # `(X=1 sh)` and `(2>/dev/null sh)` open a subshell as `( X=1 sh )` does;
            # `<(` and `>(` stay process substitutions.
            spans.append((index, index + 1))
            index += 1
            continue
        if char in "<>":
            if start is not None:
                spans.append((start, index))
                start = None
            index += 1
            continue
        if char.isspace():
            if start is not None:
                spans.append((start, index))
                start = None
            index += 1
            continue
        if start is None:
            start = index
        index += 1
    if start is not None:
        spans.append((start, length))
    return spans


def _shell_words(segment: str) -> list[str]:
    return [segment[start:end] for start, end in _shell_word_spans(segment)]


_NAMED_FD = re.compile(r"\{[A-Za-z_][A-Za-z0-9_]*(?:\[[^\]]*\])?\}")


def _is_zero_fd(word: str) -> bool:
    return bool(word) and word.isdigit() and set(word) == {"0"}


# Arguments that name standard input as the program, or as a file to read.
_STDIN_PROGRAMS = frozenset({"-", "/dev/stdin", "/dev/fd/0", "/proc/self/fd/0"})


def _fd_key(word: str) -> str:
    """A descriptor number as bash reads it: `00` is 0, and `0-` (move) still names 0."""
    word = word.removesuffix("-") if len(word) > 1 else word
    return str(int(word)) if word.isdigit() else word


def _redirections(segment: str, spans: list[tuple[int, int]]) -> list[str]:
    """For each word, the redirection it belongs to: `<` for the target of a stdin
    (FD 0) input redirection (`<`, `0<`, `<>`, `<<<`, `<&N` for non-zero `N`), `>` for
    an output or non-stdin-replacing redirection (`>`, `2>`, `&>`, `3<`, `<&0`), `&` for
    the descriptor (`2`, `0`, `&`, `{fd}`) written against one, and `""` otherwise.
    """
    marks: list[str] = []
    previous = 0
    continued = ""
    count = len(spans)
    aliases = {"0"}
    words = [segment[s:e] for s, e in spans]
    through = -1
    for idx, (start, end) in enumerate(spans):
        word = segment[start:end]
        if idx <= through:
            # The splitter breaks a target's `$(...)`, backticks or `$((...))` at their
            # spaces; every piece belongs to the same redirection.
            marks.append(marks[-1])
            previous = end
            continued = ""
            continue
        gap = segment[previous:start].rstrip(" \t")
        if gap.endswith(("<", "<>")):
            prev_is_non_stdin_fd = (
                bool(marks)
                and marks[-1] == "&"
                and not _is_zero_fd(segment[spans[idx - 1][0] : spans[idx - 1][1]])
            )
            decoded = _decode_word(word, drop_ifs=False)
            following = (
                _decode_word(segment[spans[idx + 1][0] : spans[idx + 1][1]], drop_ifs=False)
                if word == "&"
                and idx + 1 < count
                and not segment[end : spans[idx + 1][0]].rstrip(" \t")
                else ""
            )
            self_dup_stdin = (
                not gap.endswith(("<<", "<>"))
                and start > 0
                and segment[start - 1] == "<"
                and (
                    (decoded.startswith("&") and _fd_key(decoded[1:]) in aliases)
                    or (word == "&" and _fd_key(following) in aliases)
                )
            )
            # `</dev/stdin` and `<>/dev/fd/0` reopen the pipe the command already reads,
            # and `<<<"$(cat)"` hands the command what the pipe carried.
            reopens_stdin = (not gap.endswith("<<") and decoded in _STDIN_PROGRAMS - {"-"}) or (
                gap.endswith("<<<") and _reads_piped_stdin(word)
            )
            if prev_is_non_stdin_fd:
                fd_word = segment[spans[idx - 1][0] : spans[idx - 1][1]]
                fd = _fd_key(fd_word) if fd_word.isdigit() else ""
                source = decoded[1:] if decoded.startswith("&") else following
                if fd and (_fd_key(source) in aliases or reopens_stdin):
                    aliases.add(fd)
                elif fd:
                    aliases.discard(fd)
            mark = ">" if (prev_is_non_stdin_fd or self_dup_stdin or reopens_stdin) else "<"
        elif gap.endswith(">"):
            mark = ">"
        else:
            # `>|`, `>&`, and `<&` leave `|` or `&` as a word whose target may follow after a space.
            mark = "" if gap else continued
        continued = (
            mark
            if mark in {">", "<"}
            and word in {"|", "&"}
            and start > 0
            and segment[start - 1] in "<>"
            else ""
        )
        if (
            not mark
            and segment.startswith(("<", ">"), end)
            and (word.isdigit() or word == "&" or _NAMED_FD.fullmatch(word) is not None)
        ):
            mark = "&"
        marks.append(mark)
        previous = end
        if mark in {"<", ">"}:
            through = _assignment_end(words, idx) - 1
    return marks


def _unredirected(
    segment: str, spans: list[tuple[int, int]], start: int, *, inputs: bool = False
) -> list[str]:
    """The words of `segment` from the `start`th on that no redirection takes. With
    `inputs`, the file an input redirection reads stays, as a word the command reads."""
    marks = _redirections(segment, spans)
    kept = ("", "<") if inputs else ("",)
    return [
        segment[s:e]
        for (s, e), mark in zip(spans[start:], marks[start:], strict=True)
        if mark in kept
    ]


def _ifs_at(word: str, index: int) -> int:
    """Length of an unquoted `${IFS}` or `$IFS`, or 0 when this is not one."""
    if word.startswith("${IFS}", index):
        return 6
    if word.startswith("$IFS", index):
        after = index + 4
        if after == len(word) or not (word[after].isalnum() or word[after] == "_"):
            return 4
    return 0


_ANSI_C_ESCAPE = re.compile(r"\\(x[0-9A-Fa-f]{1,2}|[0-7]{1,3}|.)", re.DOTALL)
_ANSI_C_NAMED = {"a": "\a", "b": "\b", "e": "\x1b", "E": "\x1b", "f": "\f", "n": "\n"}
_ANSI_C_NAMED |= {"r": "\r", "t": "\t", "v": "\v"}


def _ansi_c(body: str) -> str:
    """The text bash makes of `$'body'`."""

    def one(match: re.Match[str]) -> str:
        code = match.group(1)
        if code[0] == "x":
            return chr(int(code[1:], 16))
        if code[0] in "01234567":
            return chr(int(code, 8) & 0xFF)
        return _ANSI_C_NAMED.get(code, code)

    return _ANSI_C_ESCAPE.sub(one, body)


def _decode_word(word: str, *, drop_ifs: bool) -> str:
    """Remove quotes and backslash escapes. Optionally delete `${IFS}` / `$IFS`.

    Inside single quotes a backslash and `${IFS}` are literal. Outside them,
    deleting `${IFS}` is the reading where IFS is empty and the letters join.
    """
    out: list[str] = []
    index = 0
    quote = ""
    while index < len(word):
        char = word[index]
        if quote == "'":
            if char == "'":
                quote = ""
            else:
                out.append(char)
            index += 1
            continue
        if not quote and word.startswith("$'", index):
            end = index + 2
            while end < len(word) and word[end] != "'":
                end += 2 if word[end] == "\\" else 1
            out.append(_ansi_c(word[index + 2 : end]))
            index = end + 1
            continue
        if not quote and word.startswith('$"', index):
            index += 1
            continue
        if char == "'" and not quote:
            quote = "'"
            index += 1
            continue
        if char == '"' and quote == '"':
            quote = ""
            index += 1
            continue
        if char == '"' and not quote:
            quote = '"'
            index += 1
            continue
        if char == "\\" and quote != "'":
            if index + 1 < len(word):
                if word[index + 1] != "\n":
                    out.append(word[index + 1])
                index += 2
                continue
        if drop_ifs and quote != "'":
            skipped = _ifs_at(word, index)
            if skipped:
                index += skipped
                continue
        out.append(char)
        index += 1
    return "".join(out)


def _ifs_pieces(word: str) -> list[str]:
    """Pieces split on `${IFS}` / `$IFS` outside single quotes."""
    parts: list[str] = []
    buf: list[str] = []
    index = 0
    quote = ""
    while index < len(word):
        char = word[index]
        if quote == "'":
            buf.append(char)
            if char == "'":
                quote = ""
            index += 1
            continue
        if char == "'" and not quote:
            quote = "'"
            buf.append(char)
            index += 1
            continue
        if char == '"' and quote == '"':
            quote = ""
        elif char == '"' and not quote:
            quote = '"'
        if quote != "'":
            skipped = _ifs_at(word, index)
            if skipped:
                parts.append("".join(buf))
                buf = []
                index += skipped
                continue
        buf.append(char)
        index += 1
    parts.append("".join(buf))
    return [part for part in parts if part]


def _command_basename(word: str) -> str:
    word = word.strip().strip("(){};")
    word = word.replace("\\", "/")
    if "/" in word:
        word = word.rsplit("/", 1)[-1]
    if word.lower().endswith(".exe"):
        word = word[: -len(".exe")]
    return word.lower()


def _name_variants(word: str) -> set[str]:
    """Names this word can be: IFS deleted, or the field before an IFS split.

    A shell prefix at a word boundary counts, so `bash-static` is `bash` and
    `shellcheck` is not `sh`.
    """
    names: set[str] = set()
    candidates = [_command_basename(_decode_word(word, drop_ifs=True))]
    candidates.extend(
        _command_basename(_decode_word(part, drop_ifs=False)) for part in _ifs_pieces(word)
    )
    for name in candidates:
        if not name:
            continue
        names.add(name)
        versioned = _VERSIONED_NAME.fullmatch(name)
        if versioned is not None:
            names.add(versioned.group(1))
        for shell in _SHELL_NAMES:
            if not name.startswith(shell) or len(name) == len(shell):
                continue
            nxt = name[len(shell)]
            if not (nxt.isalnum() or nxt == "_"):
                names.add(shell)
    return names


_SHELL_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\+?=")


# How many words one assignment's substitution is followed across.
_MAX_ASSIGNMENT_WORDS = 32


def _assignment_end(words: list[str], index: int) -> int:
    """Index after the assignment at `index` and the words its substitutions span.

    The word splitter breaks `X=$(id -u)`, backticks and `${A:-a b}` at their spaces, so
    the command after them is found only once each `$(`, `${` and backtick is closed. A
    substitution not closed within the bound ends at its own word, so the next word is
    still read as the possible command.
    """
    closers: list[str] = []
    quotes: list[str] = []
    quote = ""
    for end in range(index, min(len(words), index + _MAX_ASSIGNMENT_WORDS)):
        word = words[end]
        position = 0
        while position < len(word):
            char = word[position]
            if quote == "'":
                if char == "'":
                    quote = ""
            elif char == "\\":
                position += 1
            elif closers and char == closers[-1] and not quote:
                closers.pop()
                quote = quotes.pop()
            elif word.startswith(("$(", "${"), position):
                quotes.append(quote)
                closers.append(")" if word[position + 1] == "(" else "}")
                quote = ""
                position += 1
            elif char == "`":
                quotes.append(quote)
                closers.append("`")
                quote = ""
            elif quote == '"':
                if char == '"':
                    quote = ""
            elif char in "'\"":
                quote = char
            elif closers and closers[-1] == ")" and char == "(":
                quotes.append(quote)
                closers.append(")")
            position += 1
        if not closers:
            return end + 1
    return index + 1


_ENV_LONG_VALUES = frozenset({"--unset", "--chdir", "--split-string"})


def _skip_env(words: list[str], index: int) -> int:
    while index < len(words):
        word = _decode_word(words[index], drop_ifs=True)
        if word == "--":
            index += 1
            break
        if word in {"-i", "--ignore-environment", "-0", "--null", "-v", "--debug"}:
            index += 1
            continue
        if word in {"-u", "-C", "-S"}:
            index += 2
            continue
        if (
            word.startswith("--")
            and "=" in word
            and _long_value_option(word.partition("=")[0], _ENV_LONG_VALUES)
        ):
            index += 1
            continue
        if _long_value_option(word, _ENV_LONG_VALUES):
            index += 2
            continue
        if word.startswith("-"):
            return index
        break
    # env splits assignments at the first equals sign; they are argv data,
    # not shell assignments. Option parsing ends at the first operand.
    while index < len(words) and _decode_word(words[index], drop_ifs=True).find("=") > 0:
        index += 1
    return index


def _skip_sudo(words: list[str], index: int, *, assignments: bool) -> int:
    arg_options = {
        "-u",
        "-g",
        "-h",
        "-p",
        "-U",
        "-C",
        "-D",
        "-R",
        "-T",
        "-r",
        "-t",
        "-a",
        "--user",
        "--group",
        "--host",
        "--prompt",
        "--chdir",
        "--role",
        "--type",
        "--command-timeout",
        "--close-from",
    }
    while index < len(words):
        word = _decode_word(words[index], drop_ifs=True)
        if word == "--":
            return index + 1
        if any(word.startswith(f"{flag}=") for flag in arg_options if flag.startswith("--")):
            index += 1
            continue
        if word in arg_options:
            index += 2
            continue
        if word.startswith("-"):
            # `-iu root`: a bundle whose value letter ends it takes the next word.
            bundle = re.match(r"-([A-Za-z]*?)([ughpUCDRTrta])", word)
            index += 2 if bundle is not None and bundle.end() == len(word) else 1
            continue
        if assignments and word.find("=") > 0:
            index += 1
            continue
        return index
    return index


def _skip_exec(words: list[str], index: int) -> int:
    while index < len(words):
        word = _decode_word(words[index], drop_ifs=True)
        if word == "--":
            return index + 1
        if word in {"-a", "--argv0"}:
            index += 2
            continue
        if word.startswith("-"):
            index += 1
            continue
        return index
    return index


# Programs that run the command after their options and a fixed number of operands:
# the options that take a value, and how many operands come before the command.
_WRAPPERS: dict[str, tuple[frozenset[str], int]] = {
    "nohup": (frozenset(), 0),
    "setsid": (frozenset(), 0),
    "time": (frozenset({"-f", "--format", "-o", "--output"}), 0),
    "nice": (frozenset({"-n", "--adjustment"}), 0),
    "ionice": (frozenset({"-c", "--class", "-n", "--classdata", "-t"}), 0),
    "stdbuf": (frozenset({"-i", "-o", "-e", "--input", "--output", "--error"}), 0),
    "timeout": (frozenset({"-s", "--signal", "-k", "--kill-after"}), 1),
    "chroot": (frozenset({"--userspec", "--groups"}), 1),
    "flock": (frozenset({"-w", "--timeout", "-E", "--conflict-exit-code"}), 1),
    "taskset": (frozenset(), 1),
    "unshare": (
        frozenset(
            {"-S", "--setuid", "-G", "--setgid", "-R", "--root", "-w", "--wd"}
            | {"--map-user", "--map-group", "--map-users", "--map-groups", "--propagation"}
        ),
        0,
    ),
    "xargs": (
        frozenset({"-a", "--arg-file", "-d", "--delimiter", "-E", "-I", "-L", "-n", "-P", "-s"}),
        0,
    ),
}


def _long_value_option(word: str, with_value: frozenset[str]) -> bool:
    """Whether ``word`` is GNU getopt_long's abbreviation of a value-taking long option.

    getopt_long takes any unambiguous prefix, so `timeout --sig KILL 5 sh` gives `--signal`
    the value `KILL`. A prefix that another option shares is refused by the program, so
    reading it as the value option can only over-rate.
    """
    return (
        word.startswith("--")
        and len(word) > 2
        and "=" not in word
        and any(option.startswith(word) for option in with_value if option.startswith("--"))
    )


def _skip_wrapper(words: list[str], index: int, name: str) -> int:
    with_value, operands = _WRAPPERS[name]
    while index < len(words):
        word = _decode_word(words[index], drop_ifs=True)
        if word == "--":
            index += 1
            break
        if not word.startswith("-") or word == "-":
            break
        index += 2 if word in with_value or _long_value_option(word, with_value) else 1
    return index + operands


# Programs that run a command given as an option's value (`su -c sh`, `script -qc sh`)
# or, after `runuser -u <user>`, as an operand: the options that take a value, and the
# short flags that may come before `c` in one word. A word naming one of them with no
# such command is itself the program, as `./script` may be.
_COMMAND_OPTION_RUNNERS: dict[str, tuple[frozenset[str], str]] = {
    "su": (frozenset({"-s", "--shell", "-g", "--group", "-G", "--supp-group", "-w"}), "lmpfP"),
    "runuser": (
        frozenset({"-s", "--shell", "-g", "--group", "-G", "--supp-group", "-w"}),
        "lmpfP",
    ),
    "script": (
        frozenset({"-E", "--echo", "-I", "--log-in", "-O", "--log-out", "-B", "--log-io"})
        | {"-T", "--log-timing", "-m", "--logging-format"},
        "aefqkw",
    ),
}


def _option_command(words: list[str], index: int, runner: str) -> int | None:
    """Index of the command `runner` runs from its `-c` value or `-u` operand, if any.

    A value attached to the option (`--command=sh`, `-csh`, `-qcsh`) replaces that word
    in `words`, so the caller reads it as the command.
    """
    with_value, bundled = _COMMAND_OPTION_RUNNERS[runner]
    user = False
    while index < len(words):
        word = _decode_word(words[index], drop_ifs=True)
        if (
            word in {"-c", "--command"}
            or _long_value_option(word, frozenset({"--command"}))
            or (
                len(word) > 2
                and word[0] == "-"
                and word[-1] == "c"
                and set(word[1:-1]) <= set(bundled)
            )
        ):
            return index + 1
        attached = re.match(rf"--co(?:m(?:m(?:a(?:nd?)?)?)?)?=|-[{bundled}]*c(?=.)", word)
        if attached is not None:
            words[index] = word[attached.end() :]
            return index
        if word == "--":
            index += 1
            if user:
                return index
            continue
        if word in {"-u", "--user"}:
            user = True
            index += 2
            continue
        if word in with_value:
            index += 2
            continue
        if word.startswith("-"):
            index += 1
            continue
        if user:
            return index
        index += 1
    return None


def _executable_index(
    words: list[str], marks: list[str] | None = None, *, skip_inputs: bool = False
) -> int | None:
    """Index of the command `words` run, after wrappers and grouping. None if not run."""

    def _redirection_skip(pos: int) -> int:
        if marks is None:
            return 0
        mark = marks[pos]
        if mark == ">" or (skip_inputs and mark == "<"):
            return 1
        if (
            mark == "&"
            and pos + 1 < len(marks)
            and (marks[pos + 1] == ">" or (skip_inputs and marks[pos + 1] == "<"))
        ):
            return 2
        return 0

    index = 0
    while index < len(words):
        step = _redirection_skip(index)
        if step:
            index += step
            continue
        raw = _decode_word(words[index], drop_ifs=True).strip()
        if raw in {"(", "{", ")", "}"} or words[index] == "!" or words[index] in _RESERVED_PREFIXES:
            index += 1
            continue
        if words[index] == "time" and (
            index + 1 == len(words)
            or words[index + 1] == "-p"
            or not words[index + 1].startswith("-")
        ):
            index += 1
            if index < len(words) and words[index] == "-p":
                index += 1
            continue
        # bash reads a word as an assignment only when its name is unquoted and valid;
        # `1=/bin/sh`, `a.b=/bin/sh` and `"X"=/bin/sh` are commands, run by path.
        if _SHELL_ASSIGNMENT.match(words[index]):
            index = _assignment_end(words, index)
            continue
        break

    # Redirections may appear anywhere in a simple command, including between a wrapper
    # and its options or target (`env 2>/dev/null sh`, `sudo >/dev/null sh`). Filter
    # skippable redirection words out of the wrapper argv view while mapping back to the
    # original `words` indices.
    if marks is not None:
        argv: list[str] = []
        orig: list[int] = []
        pos = index
        while pos < len(words):
            step = _redirection_skip(pos)
            if step:
                pos += step
                continue
            argv.append(words[pos])
            orig.append(pos)
            pos += 1
    else:
        argv = words[index:]
        orig = list(range(index, len(words)))

    # A wrapper consumes a program from its own argv. Shell assignment syntax
    # does not apply again after that command word.
    cur = 0
    while cur < len(argv):
        names = _name_variants(argv[cur])
        if "env" in names:
            cur = _skip_env(argv, cur + 1)
            continue
        wrapper = next(iter(names & _WRAPPERS.keys()), None)
        if wrapper is not None:
            cur = _skip_wrapper(argv, cur + 1, wrapper)
            continue
        if names & {"sudo", "doas"}:
            cur = _skip_sudo(argv, cur + 1, assignments="sudo" in names)
            continue
        runner = next(iter(sorted(names & _COMMAND_OPTION_RUNNERS.keys())), None)
        if runner is not None:
            found = _option_command(argv, cur + 1, runner)
            if found is None:
                target = orig[cur]
                words[target] = argv[cur]
                return target
            cur = found
            continue
        if "command" in names:
            nxt = cur + 1
            if nxt < len(argv) and _decode_word(argv[nxt], drop_ifs=True) in {"-v", "-V"}:
                return None
            while nxt < len(argv) and _decode_word(argv[nxt], drop_ifs=True) in {"-p", "--"}:
                nxt += 1
            cur = nxt
            continue
        if "exec" in names:
            cur = _skip_exec(argv, cur + 1)
            continue
        if "busybox" in names:
            cur += 1
            if cur < len(argv) and _decode_word(argv[cur], drop_ifs=True) == "--":
                cur += 1
            continue
        target = orig[cur]
        words[target] = argv[cur]
        return target
    return None


# Interpreters that run a program read from standard input when given no script: the
# short flags whose letter takes the program from the command line or a module instead,
# or only checks syntax or prints a version or help, the long ones that do, and the
# options that take the next argument as their value. `perl -c` still runs BEGIN blocks.
# Python's `-V` and `--version` are read as running stdin, as the released classifier
# read them, so no Python form is rated lower than it was.
_NODE_LONG = frozenset({"--eval", "--print", "--check", "--version", "--help"})
_NODE_WITH_VALUE = frozenset(
    {"-r", "--require", "--import", "-C", "--conditions", "--input-type", "--env-file"}
    | {"--title", "--inspect-port", "--loader", "--experimental-loader"}
)
_STDIN_INTERPRETERS: dict[str, tuple[str, frozenset[str], frozenset[str]]] = {
    **{
        name: ("cm", frozenset(), frozenset({"-W", "-X", "--check-hash-based-pycs"}))
        for name in _PYTHON_NAMES
    },
    "perl": ("eE", frozenset(), frozenset({"-I"})),
    "node": ("epcvh", _NODE_LONG, _NODE_WITH_VALUE),
    "nodejs": ("epcvh", _NODE_LONG, _NODE_WITH_VALUE),
    "ruby": ("ecvh", frozenset({"--version", "--help"}), frozenset({"-r", "-I", "-C", "-E"})),
    "php": ("rfBRFElvihm", frozenset({"--version", "--help"}), frozenset({"-c", "-d", "-z"})),
    "lua": ("ev", frozenset(), frozenset({"-l"})),
}
# Options known to take no value, and short flags whose value is the rest of their word
# (`perl -Mstrict`, `ruby -W2`). Any other option may take the next word as its value,
# so the word after that may be the program.
_NO_VALUE: dict[str, tuple[str, str, frozenset[str]]] = {
    **{
        name: ("bBdEhiIOPqRsSuvVx", "", frozenset({"--version", "--help", "--help-all"}))
        for name in _PYTHON_NAMES
    },
    "perl": ("acnpsStTuUvwWXh", "0CdDiIlmMFx", frozenset()),
    "ruby": ("adlnpsSUvwy", "0FiWxK", frozenset({"--verbose", "--yjit", "--jit", "--copyright"})),
    "php": ("aCnqswHe", "", frozenset()),
    "lua": ("iEW", "", frozenset()),
    **{
        name: (
            "i",
            "",
            frozenset({"--trace-warnings", "--trace-deprecation", "--trace-uncaught"})
            | {"--no-warnings", "--no-deprecation", "--throw-deprecation", "--expose-gc"}
            | {"--enable-source-maps", "--preserve-symlinks", "--inspect", "--inspect-brk"}
            | {"--experimental-vm-modules", "--abort-on-uncaught-exception", "--watch"}
            | {"--test", "--interactive", "--experimental-strip-types", "--no-addons"},
        )
        for name in ("node", "nodejs")
    },
}
# Python modules that only read their arguments as data. Any other `-m` module, such as
# `runpy`, `pdb`, `cProfile` or `trace`, may run a later argument as a program.
_DATA_MODULES = frozenset(
    {"json.tool", "http.server", "venv", "zipfile", "tarfile", "gzip", "base64"}
    | {"py_compile", "compileall", "tabnanny"}
)
# Interpreters whose `-i` reads standard input as code after the program has run, as
# `python3 -ic0` and `node -i -e 0` do, and the Python modules that do: its consoles.
_INSPECT_INTERPRETERS = _PYTHON_NAMES | {"node", "nodejs", "lua"}
_CONSOLE_MODULES = frozenset({"code", "asyncio"})
# Suffixes an interpreter tries for a program or module named without one: node runs
# `node a` and `node -r ./a` from a.js, and ruby loads `ruby -r ./a` from a.rb.
_RESOLVED_SUFFIXES = {
    **dict.fromkeys(("node", "nodejs"), (".js", ".cjs", ".mjs")),
    "ruby": (".rb",),
}


def _reads_stdin(interpreter: str, args: list[str]) -> bool:
    """True when the interpreter may read its program from stdin, as `python3 -` does.

    An option not known to take no value may take the next word as its value, so both
    readings are followed: stdin is the program when either ends without one. Perl and
    ruby letters that take only an attached value (`perl -l`, `ruby -W`) take none when
    alone. `-i`, a console module and perl's debugger read stdin after the program.
    """
    if interpreter == "perl" and _perl_debugger(args):
        return True
    letters, long_code, with_value = _STDIN_INTERPRETERS[interpreter]
    plain, attached_value, plain_long = _NO_VALUE[interpreter]
    reached = [True] + [False] * len(args)
    for index, raw in enumerate(args):
        if not reached[index]:
            continue
        word = _decode_word(raw, drop_ifs=True)
        if word in _STDIN_PROGRAMS:
            return True
        if word == "--":
            following = args[index + 1 : index + 2]
            if not following or _decode_word(following[0], drop_ifs=True) in _STDIN_PROGRAMS:
                return True
            continue
        if word.startswith("--"):
            option, equals, _ = word.partition("=")
            if option == "--interactive" and interpreter in _INSPECT_INTERPRETERS:
                return True
            if option in long_code:
                continue
            known = bool(equals) or option in plain_long
        elif word.startswith("-"):
            # Walk a bundle letter by letter, as _interpreter_program does: `-ne`,
            # `-pe` and `-uc` take the program from the command line.
            known, code, valued = True, False, False
            for position in range(1, len(word)):
                # Only the walk's last letter slices the word, so a bundle costs its length.
                letter, rest = word[position], position + 1 < len(word)
                if letter in letters:
                    if letter == "m" and interpreter in _PYTHON_NAMES:
                        following = args[index + 1 : index + 2]
                        module = word[position + 1 :] or (following[0] if following else "")
                        if _decode_word(module, drop_ifs=True) in _CONSOLE_MODULES:
                            return True
                    code = True
                    break
                if f"-{letter}" in with_value:
                    valued = not rest
                    break
                if letter in plain:
                    if letter == "i" and interpreter in _INSPECT_INTERPRETERS:
                        return True
                    continue
                if letter in attached_value:
                    break
                known = False
                break
            if code:
                continue
            if valued:
                reached[min(index + 2, len(args))] = True
                continue
        else:
            continue
        steps = (2,) if word in with_value else (1,) if known else (1, 2)
        for step in steps:
            reached[min(index + step, len(args))] = True
    return reached[-1]


def _perl_debugger(args: list[str]) -> bool:
    """Whether perl's switches, which it reads on past `-e`, hold `-d`: with no terminal
    the debugger reads its commands, which are Perl, from stdin."""
    plain = _NO_VALUE["perl"][0]
    skip = False
    for raw in args:
        if skip:
            skip = False
            continue
        word = _decode_word(raw, drop_ifs=True)
        if word in {"-", "--"} or not word.startswith("-"):
            return False
        for position in range(1, len(word)):
            letter = word[position]
            if letter == "d":
                return True
            if letter in "eEI":
                skip = position + 1 == len(word)
                break
            if letter not in plain:
                break
    return False


def _segment_executes(segment: str) -> bool:
    """Whether this pipeline segment runs a shell, `iex`, or an interpreter on stdin."""
    spans = _shell_word_spans(segment)
    words = [segment[start:end] for start, end in spans]
    index = _executable_index(words, _redirections(segment, spans))
    if index is None:
        return _sudo_shell(words)
    names = _name_variants(words[index])
    # `su`, `runuser` or `script` left as the command has no `-c`: each runs the user's
    # shell on standard input.
    if names & (_SHELL_NAMES | _IEX_NAMES | {"su", "runuser", "script"}):
        return True
    interpreter = next(iter(sorted(names & _STDIN_INTERPRETERS.keys())), None)
    # An output redirection's words, as in `python3 2>/dev/null`, are not the program,
    # nor is the `)` that closes a subshell, as in `( python3 )`.
    args = _unredirected(segment, spans, index + 1, inputs=True)
    while args and args[-1] == ")":
        args.pop()
    if names & {".", "source"}:
        # `source /dev/stdin` runs what the pipe carries in this shell.
        return bool(args) and _decode_word(args[0], drop_ifs=True) in _STDIN_PROGRAMS - {"-"}
    if "eval" in names:
        # `eval sh` runs a shell on the pipe; `eval "$(cat)"` runs the pipe's text.
        operands = [word for word in args if word != "--"]
        return any(
            _name_variants(word) & _SHELL_NAMES or _reads_piped_stdin(word) for word in operands
        )
    return interpreter is not None and _reads_stdin(interpreter, args)


# A command substitution whose output is what it reads from standard input.
_PIPED_STDIN_TEXT = re.compile(
    r"""["']?(?:\$\(\s*(?:cat(?:\s+(?:-|/dev/stdin|/dev/fd/0))?|<\s*/dev/stdin)\s*\)"""
    r"""|`\s*cat(?:\s+(?:-|/dev/stdin|/dev/fd/0))?\s*`)["']?"""
)


def _reads_piped_stdin(word: str) -> bool:
    return _PIPED_STDIN_TEXT.fullmatch(word) is not None


def _sudo_shell(words: list[str]) -> bool:
    """Whether `sudo -s`, `sudo -i` or `doas -s`, given no command, runs a shell on stdin."""
    for index, word in enumerate(words):
        if _name_variants(word) & {"sudo", "doas"}:
            return any(
                _SUDO_SHELL_FLAG.fullmatch(_decode_word(w, drop_ifs=True))
                for w in words[index + 1 : index + 33]
            )
    return False


def _segment_downloads(segment: str) -> bool:
    return any(_name_variants(word) & _DOWNLOAD_NAMES for word in _shell_words(segment))


def _segment_fetches(segment: str) -> bool:
    """Whether a word downloads, or `base64` is given a decode flag among its arguments."""
    decoder = False
    for word in _shell_words(segment):
        names = _name_variants(word)
        if names & _DOWNLOAD_NAMES:
            return True
        if decoder and _BASE64_DECODE.fullmatch(_decode_word(word, drop_ifs=True)):
            return True
        decoder = decoder or "base64" in names
    return False


def _file_keys(word: str) -> set[str]:
    # Parentheses are grouping or substitution, as in `(cat a) | sh` or `sh <(cat a)`.
    decoded = _decode_word(word, drop_ifs=True).strip("()")
    if decoded.startswith("./"):
        decoded = decoded[2:]
    base = decoded.rsplit("/", 1)[-1]
    keys = {decoded, base}
    return {
        item for item in keys if item and item not in _STDOUT_NAMES and not item.startswith("-")
    }


# curl's short options that take a value: in a cluster such as `-sLo/tmp/x`, the first
# of them takes the rest of the cluster, or the next argument.
_CURL_VALUE_FLAGS = frozenset("AbcCdDeEFHKmoPQrTtuUwxXyYz")


def _curl_output(word: str, args: list[str], index: int) -> tuple[str | None, int]:
    if word in {"-o", "--output"} and index + 1 < len(args):
        return _decode_word(args[index + 1], drop_ifs=True), 2
    if word.startswith("--output="):
        return word.split("=", 1)[1], 1
    if word.startswith("-") and not word.startswith("--"):
        for position in range(1, len(word)):
            flag = word[position]
            if flag == "o":
                if position + 1 < len(word):
                    return word[position + 1 :], 1
                if index + 1 < len(args):
                    return _decode_word(args[index + 1], drop_ifs=True), 2
                return None, 1
            if flag in _CURL_VALUE_FLAGS:
                break
        # The released reading is kept: a cluster that ends in `o` names its output in the
        # next argument. An earlier `o` takes the rest of the cluster, as curl reads it, so
        # `-sozo` and `-fo/tmp/foo`, which the released reading took as naming the next
        # argument, are rated by the file curl writes.
        if word.endswith("o") and index + 1 < len(args):
            return _decode_word(args[index + 1], drop_ifs=True), 2
    return None, 1


def _curl_remote_name(word: str) -> bool:
    """Whether a curl argument saves under the URL's own file name: `-O`, `-LO`."""
    if word in {"--remote-name", "--remote-name-all"}:
        return True
    if not word.startswith("-") or word.startswith("--"):
        return False
    for flag in word[1:]:
        if flag == "O":
            return True
        if flag in _CURL_VALUE_FLAGS:
            return False
    return False


def _url_file_names(url: str, default: str | None) -> set[str]:
    """The names curl `-O` or wget without `-O` save a URL's download under.

    The last path segment, with and without its query; wget names an empty one `default`.
    """
    rest = url.split("://", 1)[-1]
    _authority, slash, path = rest.partition("/")
    with_query = path.split("#", 1)[0].rsplit("/", 1)[-1] if slash else ""
    names = {name for name in (with_query, with_query.split("?", 1)[0]) if name}
    return names or ({default} if default else set())


def _wget_output(word: str, args: list[str], index: int) -> tuple[str | None, int]:
    if word in {"-O", "--output-document"} and index + 1 < len(args):
        return _decode_word(args[index + 1], drop_ifs=True), 2
    if word.lower().startswith("--output-document="):
        return word.split("=", 1)[1], 1
    if word.startswith("-") and not word.startswith("--") and "O" in word[1:]:
        after = word.split("O", 1)[1]
        if after:
            return after, 1
        if index + 1 < len(args):
            return _decode_word(args[index + 1], drop_ifs=True), 2
    return None, 1


def _iwr_output(word: str, args: list[str], index: int) -> tuple[str | None, int]:
    low = word.lower()
    if low.startswith("-outfile"):
        if "=" in word:
            return word.split("=", 1)[1], 1
        if index + 1 < len(args):
            return _decode_word(args[index + 1], drop_ifs=True), 2
    return None, 1


def _downloader_name(names: set[str]) -> str | None:
    if "curl" in names:
        return "curl"
    if "wget" in names:
        return "wget"
    if names & {"iwr", "irm", "invoke-webrequest", "invoke-restmethod"}:
        return "iwr"
    return None


# Standard output written to a file: `>`, `>>`, `>|`, `1>` and `&>`, not `2>` or `>&2`.
_OUTPUT_REDIRECTION = re.compile(
    r"(?:(?<![0-9&>])1?>>?\|?|&>>?)(?!&)[ \t]*(?P<target>[^\s<>|;&()]+)"
)


def _saved_names(segment: str) -> tuple[set[str], set[str], set[str]]:
    """Explicit output, URL-derived filenames and redirected output in this segment.

    Standard output is excluded. One forward pass: a segment of repeated downloaders must
    not rescan its tail.
    """
    words = _shell_words(segment)
    saved: set[str] = set()
    inferred: set[str] = set()
    # A later downloader name in the same command, such as `-U curl` or a URL ending in
    # `/wget`, is an argument: the words after it are read with every named tool's
    # options, so it cannot switch which tool's output flags are read.
    tools: set[str] = set()
    # The URLs, and whether wget names its output and curl saves under the URL's name.
    urls: list[str] = []
    named = remote = False
    cursor = 0
    readers = {"curl": _curl_output, "wget": _wget_output, "iwr": _iwr_output}

    while cursor < len(words):
        detected = _downloader_name(_name_variants(words[cursor]))
        if not tools:
            if detected is not None:
                tools.add(detected)
            cursor += 1
            continue
        if detected is not None:
            tools.add(detected)
        word = _decode_word(words[cursor], drop_ifs=True)
        step = len(words)
        found_any = False
        for tool in sorted(tools):
            found, taken = readers[tool](word, words, cursor)
            step = min(step, taken)
            if found:
                found_any = True
                named = named or tool == "wget"
                saved.update(_file_keys(found))
        remote = remote or ("curl" in tools and _curl_remote_name(word))
        if not found_any and step == 1 and ("://" in word or _HOST_PATH.match(word)):
            urls.append(word)
        cursor += step
    if ("wget" in tools and not named) or ("curl" in tools and remote):
        for url in urls:
            for name in _url_file_names(url, "index.html" if "wget" in tools else None):
                inferred.update(_file_keys(name))
    redirected: set[str] = set()
    if tools or _segment_fetches(segment):
        for redirection in _OUTPUT_REDIRECTION.finditer(segment):
            redirected.update(_file_keys(redirection.group("target")))
    return saved, inferred, redirected


# Runners the released classifier counted a file a downloader's output option wrote as
# run wherever it appeared in their arguments. They keep that rule, so no form is rated
# lower than it was. Shells count any download that way except one saved under its URL's
# name, which was not tracked then; that one and a decoded file count only as the
# script, and for Python and Perl a download saved another way only as the program.
_ANY_ARGUMENT_RUNNERS = _SHELL_NAMES | _PYTHON_NAMES | _IEX_NAMES | _EVAL_NAMES | {"perl"}
# How deep a `-c` script, `eval` or `su -c` command line inside another is read.
_MAX_SCRIPT_DEPTH = 4


class _Saved:
    """Files earlier segments saved, by how, and the unions of them that segments read.

    `outputs` holds files a downloader's output option wrote, `downloaded` files a
    download wrote otherwise, and `decoded` those only `base64 -d` wrote. `programs`
    adds to `decoded` the files a download saved under its URL's name, which a shell
    runs only as its script: the name is also what a data file fetched for a script's
    argument is saved as, as in `wget URL/data.csv && sh load.sh data.csv`. The unions grow
    with them: rebuilding one for each segment cost time in proportion to every file
    saved before it, which made a long chain of saves quadratic.
    """

    def __init__(self) -> None:
        self.outputs: set[str] = set()
        self.downloaded: set[str] = set()
        self.decoded: set[str] = set()
        self.programs: set[str] = set()
        self.fetched: set[str] = set()
        self.every: set[str] = set()

    def add_outputs(self, names: set[str]) -> None:
        self.outputs |= names
        self.fetched |= names
        self.every |= names
        self.decoded -= names

    def add_downloaded(self, names: set[str]) -> None:
        self.downloaded |= names
        self.fetched |= names
        self.every |= names
        self.decoded -= names

    def add_named_by_url(self, names: set[str]) -> None:
        self.programs |= names
        self.fetched |= names
        self.every |= names

    def add_decoded(self, names: set[str]) -> None:
        names = names - self.downloaded
        self.decoded |= names
        self.programs |= names
        self.every |= names


def _inline_scripts(command: str, names: set[str], args: list[str]) -> list[str]:
    """Command lines a segment runs from its own words: a whole command given as one word,
    as to `su -c`, `eval`'s arguments, or a shell's `-c` script."""
    whole = _decode_word(command, drop_ifs=False)
    if whole.strip() and any(blank in whole for blank in " \t"):
        return [whole]
    if "eval" in names:
        return [" ".join(_decode_word(word, drop_ifs=False) for word in args)]
    if names & _SHELL_NAMES:
        for position, word in enumerate(args[:-1]):
            if _SCRIPT_FLAG.fullmatch(_decode_word(word, drop_ifs=True)):
                return [_decode_word(args[position + 1], drop_ifs=False)]
    return []


def _executes_saved(segment: str, saved: _Saved, depth: int = 0) -> bool:
    """Whether this segment runs a saved file with a shell, an interpreter, or directly."""
    if not saved.every:
        return False
    spans = _shell_word_spans(segment)
    words = [segment[start:end] for start, end in spans]
    index = _executable_index(words, _redirections(segment, spans), skip_inputs=True)
    if index is None:
        return False
    names = _name_variants(words[index])
    interpreters = _SHELL_NAMES | _STDIN_INTERPRETERS.keys()
    if _file_keys(words[index]) & saved.every and not (names & interpreters):
        return True
    args = words[index + 1 :]
    # `sh -c 'sh a'` and `su -c 'sh a'` name the file in a script of their own.
    if depth < _MAX_SCRIPT_DEPTH and any(
        _executes_saved(script, saved, depth + 1) or _runs_saved_input(script, saved)
        for script in _inline_scripts(words[index], names, args)
    ):
        return True
    if not (names & (interpreters | _IEX_NAMES | _EVAL_NAMES | {"busybox"})):
        return False
    # An output redirection's words, as in `python3 2>/dev/null a`, are never the program.
    program = _unredirected(segment, spans, index + 1, inputs=True)
    interpreter = next(iter(sorted(names & _STDIN_INTERPRETERS.keys())), None)
    if not names & _ANY_ARGUMENT_RUNNERS:
        if interpreter is None:
            return _any_argument(args, saved.every)
        return _interpreter_program(interpreter, program, saved.every)
    if _any_argument(args, saved.outputs):
        return True
    if interpreter is not None:
        return _interpreter_program(interpreter, program, saved.every)
    if _any_argument(args, saved.downloaded):
        return True
    if names & _SHELL_NAMES:
        return _shell_program(
            program,
            lambda word: bool(_file_keys(word) & saved.programs),
            lambda rest: _any_argument(rest, saved.programs),
        )
    return _any_argument(args, saved.programs)


def _any_argument(args: list[str], saved: set[str]) -> bool:
    """Whether any argument other than a `-c` script names one of `saved`."""
    cursor = 0
    while cursor < len(args):
        word = _decode_word(args[cursor], drop_ifs=True)
        if _SCRIPT_FLAG.fullmatch(word):
            cursor += 2
            continue
        if _file_keys(args[cursor]) & saved:
            return True
        cursor += 1
    return False


# Shell options that take the next argument; `--rcfile` and `--init-file` run it.
_SHELL_WITH_VALUE = frozenset({"-o", "+o", "-O", "+O", "--rcfile", "--init-file"})


def _shell_program(
    args: list[str], hit: Callable[[str], bool], scripted: Callable[[list[str]], bool]
) -> bool:
    """Whether a shell runs a word `hit` accepts as its script, not as a later argument.

    The script is the first operand after the options and `--` or `-`. With `-c`, also
    with its script attached, `scripted` reads the words from the flag on, since the
    script may source `$1`. Each `o` or `O` in a bundle takes one following word as its
    value (`-eou pipefail a`, `-oo pipefail errexit a`); those values and the word after
    them are tested too, which fails closed on an option this does not know.
    """
    index = 0
    while index < len(args):
        word = _decode_word(args[index], drop_ifs=True)
        if word in {"--", "-"}:
            index += 1
            break
        if not word.startswith(("-", "+")) or word in _STDOUT_NAMES:
            break
        if _SCRIPT_FLAG.fullmatch(word) or re.match(r"-[A-Za-z]*c", word):
            return scripted(args[index:])
        if re.fullmatch(r"[-+][A-Za-z]+", word):
            values = sum(letter in "oO" for letter in word[1:])
        else:
            values = 1 if word in _SHELL_WITH_VALUE else 0
        if any(hit(item) for item in args[index + 1 : index + values + 2]):
            return True
        index += 1 + values
    return index < len(args) and hit(args[index])


def _interpreter_program(interpreter: str, args: list[str], saved: set[str]) -> bool:
    """Whether the interpreter's program, not a later data argument, is one of `saved`.

    The program is the first operand after the options, or the value of a flag that
    takes it from the command line (`-c`, `-e`, `php -f`); the arguments after it are
    the program's own, as in `node build.js data.json`. An option's value counts too,
    since `node -r`, `ruby -r` and `php -z` load and run the file they name. Where the
    program's position is uncertain this fails closed: after `-` or `/dev/stdin` any
    later word counts, and the word after an option not known to take no value may be
    that option's value or the program, so it is tested and the reading goes on after it.
    """
    letters, long_code, with_value = _STDIN_INTERPRETERS[interpreter]
    plain, attached_value, plain_long = _NO_VALUE[interpreter]
    suffixes = _RESOLVED_SUFFIXES.get(interpreter, ())

    def named(values: list[str]) -> bool:
        for value in values:
            bare = bool(value) and "." not in value.rsplit("/", 1)[-1]
            tried = ("", *suffixes) if bare else ("",)
            if any(_file_keys(value + suffix) & saved for suffix in tried):
                return True
        return False

    index = 0
    while index < len(args):
        word = _decode_word(args[index], drop_ifs=True)
        following = args[index + 1 : index + 2]
        # After an unknown option the next word is tested, then skipped as its value.
        option_next = not following or _decode_word(following[0], drop_ifs=True).startswith("-")
        skip = 1 if option_next else 2
        if word == "--":
            index += 1
            break
        if word in _STDIN_PROGRAMS:
            return named(args[index + 1 :])
        if not word.startswith("-"):
            break
        if word.startswith("--"):
            option, equals, attached = word.partition("=")
            if option in long_code:
                return named([attached] if equals else following)
            if equals or option in plain_long:
                if named([attached]):
                    return True
                index += 1
                continue
            if named(following):
                return True
            index += 2 if option in with_value else skip
            continue
        step = 1
        for position in range(1, len(word)):
            letter = word[position]
            # A plain letter goes on without slicing, so a bundle costs its length.
            if letter in plain and letter not in letters and f"-{letter}" not in with_value:
                continue
            rest = word[position + 1 :]
            if letter == "m" and interpreter in _PYTHON_NAMES:
                module = rest or (_decode_word(following[0], drop_ifs=True) if following else "")
                if module not in _DATA_MODULES:
                    # `python3 -m a` runs a.py from the working directory.
                    return named([rest, *args[index + 1 :], module.replace(".", "/") + ".py"])
            if letter in letters:
                return named([rest] if rest else following)
            if f"-{letter}" in with_value:
                if named([rest] if rest else following):
                    return True
                step = 1 if rest else 2
                break
            if letter in plain:
                continue
            if letter in attached_value:
                break
            if named([rest, *following]):
                return True
            step = 1 if rest else skip
            break
        index += step
    return index < len(args) and named(args[index : index + 1])


def _relayed_names(segment: str) -> set[str]:
    """Files a segment fed a download writes: `tee`/`sponge` operands, `dd of=`, redirections."""
    spans = _shell_word_spans(segment)
    words = [segment[start:end] for start, end in spans]
    relayed: set[str] = set()
    index = _executable_index(words, _redirections(segment, spans))
    names = _name_variants(words[index]) if index is not None else set()
    if index is not None and names & {"tee", "sponge"}:
        for word in words[index + 1 : index + 65]:
            relayed.update(_file_keys(word))
    elif index is not None and names & {"cp", "install"}:
        # `cp /dev/stdin a` and `install /dev/stdin a` copy what they are fed.
        operands = words[index + 1 : index + 65]
        if any(_decode_word(word, drop_ifs=True) in _STDIN_PROGRAMS for word in operands):
            for word in operands:
                relayed.update(_file_keys(word))
    elif index is not None and "dd" in names:
        for word in words[index + 1 : index + 65]:
            decoded = _decode_word(word, drop_ifs=True)
            if decoded.startswith("of="):
                relayed.update(_file_keys(decoded[3:]))
    for redirection in _OUTPUT_REDIRECTION.finditer(segment):
        relayed.update(_file_keys(redirection.group("target")))
        if len(relayed) >= 64:
            break
    return relayed


# Commands that copy a file they name to their destination or output: a copy of a saved
# file holds what it holds. The last operand of these is the file or directory written.
_COPIERS = frozenset({"cat", "cp", "ln", "dd", "tee", "install", "mv", "rsync", "sponge"})
_DESTINATION_COPIERS = frozenset({"cp", "ln", "install", "mv", "rsync"})
# Standard input read from a file: `<`, `0<` and `<>`, not `<<`, `<<<`, `<(` or `<&`.
_INPUT_REDIRECTION = re.compile(r"(?<![0-9<>&])0?<>?(?![<>&(])[ \t]*(?P<target>[^\s<>|;&()]+)")


def _operand_keys(words: list[str]) -> set[str]:
    """File keys of `words`, reading `dd`'s `if=` and `of=` operands as their files."""
    keys: set[str] = set()
    for word in words:
        decoded = _decode_word(word, drop_ifs=True)
        keys |= _file_keys(decoded[3:] if decoded.startswith(("if=", "of=")) else word)
    return keys


def _copies_saved(segment: str, saved: set[str]) -> set[str] | None:
    """What a copier that names one of `saved` writes; None when this is no such copier.

    A copy is written to the destination of `cp`, `mv`, `ln`, `install` or `rsync`, to
    `dd of=`, to a `tee` or `sponge` operand and to a redirection. Other operands are
    read, as `header.txt` is in `cat header.txt a > out`, and keep what they held.
    """
    spans = _shell_word_spans(segment)
    words = [segment[start:end] for start, end in spans]
    index = _executable_index(words, _redirections(segment, spans), skip_inputs=True)
    if index is None:
        return None
    names = _name_variants(words[index])
    if not names & _COPIERS or not _operand_keys(words[index + 1 : index + 65]) & saved:
        return None
    written = _relayed_names(segment)
    if names & _DESTINATION_COPIERS:
        for word in reversed(_unredirected(segment, spans, index + 1)):
            if not _decode_word(word, drop_ifs=True).startswith("-"):
                written |= _file_keys(word)
                break
    return written


def _substitution_reads(word: str, saved: set[str]) -> bool:
    """Whether `word` holds a `$(...)`, backtick or `<(...)` that reads one of `saved`,
    with a copier or as `$(< a)`, which is bash's `$(cat a)`."""
    for match in re.finditer(r"[$<]\(([^()]*)\)|`([^`]*)`", word):
        body = match.group(1) if match.group(1) is not None else match.group(2)
        inner = _shell_words(body)
        if body.lstrip().startswith("<") and _operand_keys(inner) & saved:
            return True
        if inner and _name_variants(inner[0]) & _COPIERS and _operand_keys(inner[1:]) & saved:
            return True
    return False


def _shell_substitution(
    segment: str, spans: list[tuple[int, int]], index: int, saved: _Saved
) -> bool:
    """Whether a shell runs a saved file that a substitution in its arguments reads.

    A download counts wherever the substitution is, as a shell's download argument does.
    A decoded file counts as `_shell_program` reads its name: as the script, in or after a
    `-c` script, and on stdin as `bash <<< "$(cat a)"` gives it, not as a later argument.
    """
    words = [segment[start:end] for start, end in spans[index + 1 : index + 65]]
    if any(_substitution_reads(word, saved.fetched) for word in words):
        return True

    def reads(word: str) -> bool:
        return _substitution_reads(word, saved.decoded)

    marks = _redirections(segment, spans)[index + 1 : index + 65]
    if any(mark == "<" and reads(word) for word, mark in zip(words, marks, strict=True)):
        return True
    program = [word for word, mark in zip(words, marks, strict=True) if not mark]
    return _shell_program(program, reads, lambda rest: any(map(reads, rest)))


def _runs_saved_input(segment: str, saved: _Saved) -> bool:
    """Whether this segment runs a saved file given on stdin or by substitution.

    `sh < a`, `sh 0< a`, `bash run.sh < a`, `sh -c "$(cat a)"`, `bash <<< "$(cat a)"`
    and `eval "$(cat a)"` run `a` as `cat a | sh` does. Python and Perl keep the released
    rule for a file a downloader's output option wrote, which counted any file they were
    given, stdin included; any other saved file counts for them only as the program.
    """
    if not saved.every:
        return False
    spans = _shell_word_spans(segment)
    words = [segment[start:end] for start, end in spans]
    index = _executable_index(words, _redirections(segment, spans), skip_inputs=True)
    if index is None:
        return False
    names = _name_variants(words[index])
    if names & _SHELL_NAMES and _shell_substitution(segment, spans, index, saved):
        return True
    if names & (_EVAL_NAMES | _IEX_NAMES) and any(
        _substitution_reads(word, saved.every) for word in words[index + 1 : index + 65]
    ):
        return True
    stdin = set()
    for match in _INPUT_REDIRECTION.finditer(segment):
        stdin |= _file_keys(match.group("target"))
    if not stdin & saved.every:
        return False
    if names & (_PYTHON_NAMES | {"perl"}) and stdin & saved.outputs:
        return True
    return _segment_executes(_INPUT_REDIRECTION.sub(" ", segment))


def _download_then_run(pipelines: list[list[str]]) -> bool:
    """Whether a later command runs a file an earlier download saved (`curl -o a && bash a`).

    A file written by a later segment of the downloader's pipeline, as by `curl x | tee a`
    or `curl x | cat > a`, holds the download too, as does a copy of a saved file and
    a file decoded from a download.
    """
    saved = _Saved()
    for segments in pipelines:
        fetched: str | None = None
        reads_saved = False
        for segment in segments:
            if _executes_saved(segment, saved) or _runs_saved_input(segment, saved):
                return True
            # A saved file read into a pipeline (`cat a | sh`) is a fetch for its later segments.
            if reads_saved and (
                _segment_executes(segment) or _output_substitution_executes(segment)
            ):
                return True
            names = _operand_keys(_shell_words(segment))
            if not reads_saved and saved.every:
                reads_saved = bool(names & saved.every)
            copied = _copies_saved(segment, saved.every)
            # A copy or decoding of a download, or a relay after one, holds the download.
            source = (
                "download" if names & saved.fetched else "decode" if copied is not None else None
            )
            options, inferred, written = _saved_names(segment)
            saved.add_outputs(options)
            saved.add_named_by_url(inferred)
            if fetched:
                written |= _relayed_names(segment)
            written |= copied or set()
            if fetched == "download" or source == "download" or _segment_downloads(segment):
                saved.add_downloaded(written)
            else:
                saved.add_decoded(written)
            if fetched != "download" and (_segment_fetches(segment) or copied is not None):
                download = _segment_downloads(segment) or source == "download"
                fetched = "download" if download else "decode"
    return False


def _opens_substitution(command: str, index: int) -> bool:
    return (
        command.startswith("$(", index)
        or command.startswith("<(", index)
        or (index < len(command) and command[index] == "`")
    )


def _substitution_downloads(command: str, index: int) -> bool:
    """Whether the substitution that opens at `index` starts by downloading or decoding."""
    if command.startswith("$(", index) or command.startswith("<(", index):
        index += 2
    elif index < len(command) and command[index] == "`":
        index += 1
    else:
        return False
    while index < len(command) and command[index] in " \t":
        index += 1
    end = index
    while end < len(command) and command[end] not in " \t\n)|&;":
        end += 1
    names = _name_variants(command[index:end])
    if names & _DOWNLOAD_NAMES:
        return True
    if "base64" not in names:
        return False
    # Its arguments up to the end of the substitution's command; past 64 of them a decode
    # flag may still follow, so this fails closed.
    for _ in range(64):
        while end < len(command) and command[end] in " \t":
            end += 1
        if end >= len(command) or command[end] in "\n)|&;`":
            return False
        start = end
        while end < len(command) and command[end] not in " \t\n)|&;`":
            end += 1
        if _BASE64_DECODE.fullmatch(_decode_word(command[start:end], drop_ifs=True)):
            return True
    return True


def _substitution_at(command: str, index: int, interpreter: str | None = None) -> bool:
    """Whether the script after a shell word is a download substitution.

    Accepts a command flag (`-c`, `-lc`, `-Command`), also with its value attached
    (`-c"$(...)"`, `--eval=$(...)`), quotes, and redirections (`sh < <(curl ...)`,
    `bash <<< $(curl ...)`). A substitution later in a longer script is not the script
    itself, nor is the value of an interpreter option such as `node -r`.
    """
    with_value = _STDIN_INTERPRETERS[interpreter][2] if interpreter else frozenset()
    code_flag = _PHP_CODE_FLAG if interpreter == "php" else _CODE_FLAG
    length = len(command)
    for _ in range(16):
        while index < length and command[index] in " \t":
            index += 1
        if index >= length or command[index] in "\n|&;":
            return False
        probe = index
        while probe < length and command[probe] in "'\"":
            probe += 1
        if _opens_substitution(command, probe):
            return _substitution_downloads(command, probe)
        redir = _PREFIX_REDIR.match(command, index)
        if redir is not None and not command.startswith("<(", index):
            index = redir.end()
            continue
        if command[index] == "-":
            end = index + 1
            while end < length and command[end] not in " \t\n|&;<>":
                end += 1
            matched = _FLAG_NAME.match(command, index)
            name_end = matched.end() if matched is not None else end
            flag = command[index:name_end]
            if flag in with_value:
                # The option's value, attached or the next word, is not the program.
                index = end
                if name_end == end:
                    while index < length and command[index] in " \t":
                        index += 1
                    while index < length and command[index] not in " \t\n|&;<>":
                        index += 1
                continue
            if _SCRIPT_FLAG.fullmatch(flag) or code_flag.fullmatch(flag):
                index = name_end
                if flag.startswith("--") and command.startswith("=", index):
                    index += 1
                while index < length and command[index] in " \t":
                    index += 1
                while index < length and command[index] in "'\"":
                    index += 1
                if _opens_substitution(command, index):
                    return _substitution_downloads(command, index)
                return False
            index = end
            continue
        return False
    return False


def _substitution_exec(pipelines: list[list[str]]) -> bool:
    """Whether a shell, `eval`, `source` or a bare substitution runs a download.

    Every segment of a pipeline counts: in `true | bash -c "$(curl ...)"` the shell's
    script is the download whatever is piped to it.
    """
    for segment in (segment for segments in pipelines for segment in segments):
        stripped = segment.lstrip(" \t")
        if _opens_substitution(stripped, 0) and _substitution_downloads(stripped, 0):
            return True
        spans = _shell_word_spans(segment)
        words = [segment[start:end] for start, end in spans]
        index = _executable_index(words, _redirections(segment, spans), skip_inputs=True)
        if index is None:
            continue
        # The command a wrapper or `su -c` runs may itself be the download.
        command = words[index].lstrip("'\"")
        if _opens_substitution(command, 0) and _substitution_downloads(command, 0):
            return True
        names = _name_variants(words[index])
        if not (names & (_SHELL_NAMES | _EVAL_NAMES | _IEX_NAMES | _STDIN_INTERPRETERS.keys())):
            continue
        interpreter = next(iter(sorted(names & _STDIN_INTERPRETERS.keys())), None)
        if _substitution_at(segment, spans[index][1], interpreter):
            return True
    return False


def _fetch_exec(command: str) -> bool:
    """Whether a command runs a download or a decoded payload in a shell.

    A pipeline is rated as a whole: a downloader or ``base64 -d`` in any segment and
    a shell, ``iex``, or a stdin interpreter in any later segment. Segments are
    visited once, so repeated near misses never make the earlier text be rescanned.
    A command or process substitution that itself downloads is the same shape
    without a pipe, as is saving the download and running that file later.
    """
    pipelines = _command_pipelines(command)
    if _substitution_exec(pipelines) or _download_then_run(pipelines):
        return True
    # A group a pipe feeds passes it on to every command inside it.
    for segments in [*pipelines, *_command_pipelines(command, piped_groups=True)]:
        # One forward pass: a fetch and an executor later in the same pipeline.
        fetched = False
        for segment in segments:
            if fetched and _segment_executes(segment):
                return True
            if _segment_fetches(segment):
                fetched = True
            if fetched and _output_substitution_executes(segment):
                return True
    return _encoded_powershell(command)


def _output_substitution_executes(segment: str) -> bool:
    """Whether a `>(...)` here, which reads what is written to it, starts a shell or
    interpreter on it, as `curl x | tee >(sh)` and `curl x > >(sh)` do."""
    start = segment.find(">(")
    for _ in range(16):
        if start == -1:
            return False
        end = segment.find(")", start + 2)
        pipelines = _command_pipelines(segment[start + 2 : end if end != -1 else None])
        if pipelines and any(_segment_executes(part) for part in pipelines[0]):
            return True
        start = segment.find(">(", start + 2)
    return start != -1


def _encoded_powershell(command: str) -> bool:
    """Whether a segment passes PowerShell an encoded command as its own parameter."""
    if _encoded_in_segments(command):
        return True
    if "\n" not in command or _ENCODED_COMMAND.search(command) is None:
        return False
    # Quoted newlines can belong to one base64 argument. Preserve the existing
    # segment reading and check that additional reading only when it differs.
    parts: list[str] = []
    last = 0
    for start, end in _shell_word_spans(command):
        word = command[start:end]
        if "\n" in word:
            parts.extend((command[last:start], word.replace("\n", " ")))
            last = end
    return bool(parts) and _encoded_in_segments("".join((*parts, command[last:])))


def _encoded_in_segments(command: str) -> bool:
    start = 0
    for boundary in _SEGMENT_BOUNDARY.finditer(command):
        if _encoded_segment(command[start : boundary.start()]):
            return True
        start = boundary.end()
    return _encoded_segment(command[start:])


def _encoded_segment(segment: str) -> bool:
    """Read the arguments after each PowerShell name the way PowerShell reads its own.

    The name may follow any wrapper, such as `cmd /c` or `start`. An `-e` after the
    script or command that PowerShell runs is that script's or command's argument, and
    when the name is itself an argument, as in `grep -rn pwsh . -e foo`, the plain
    argument after it ends what PowerShell would read as its parameters. Where an
    argument may be either a parameter or the previous parameter's value, both readings
    are kept. Only a plain argument can end the parameters: after one that the shell may
    rewrite while they are read, every later encoded flag in the segment counts.
    """
    dynamic = _computed_powershell(segment)
    if (
        dynamic is None
        and _POWERSHELL.search(segment) is None
        and _POWERSHELL.search(_decode_word(segment, drop_ifs=True)) is None
    ):
        return False
    # parameter: the next argument is read as a parameter, or else as the script or
    # command. value: the next argument may instead be the previous parameter's value.
    # script: the next argument may be -File's script, and `-` continues the parameters.
    # Nothing before the first PowerShell name can be its parameter.
    parameter = value = script = False
    for argument in _ARGUMENT.finditer(segment):
        word = argument.group()
        plain = _PLAIN.fullmatch(word) is not None
        if parameter or value or script:
            # After -File alone, `/e` is the script at the root, not the parameter.
            slash_script = (
                script and not (parameter or value) and word.lstrip("\"'").startswith("/")
            )
            if not slash_script and _ENCODED_COMMAND.match(segment, argument.start()):
                return True
            if not plain and (parameter or value or not _script_path(word)):
                return _ENCODED_COMMAND.search(segment, argument.end()) is not None
        if _powershell_name(word, plain) or argument.start() == dynamic:
            parameter, value, script = True, False, False
            continue
        name = _parameter_name(word) if plain else None
        if name is None:
            parameter, value, script = value, False, False
        elif parameter or value or script:
            # -File always takes the next argument as its script.
            option = parameter or value
            switch = name in _POWERSHELL_SWITCHES
            file = name in _POWERSHELL_FILE
            last = switch or file or name in _POWERSHELL_COMMAND
            parameter, value, script = (
                (option and switch) or value or (script and word == "-"),
                option and not last,
                option and file,
            )
    return False


def _script_path(token: str) -> bool:
    """Whether an argument the shell may rewrite still names a script, never `-`.

    A letter, digit, `/` or `.` outside an expansion stays in the word, as in
    `"$CLAUDE_PROJECT_DIR/x.ps1"` or `"My Scripts\\x.ps1"`; a redirection is not one.
    """
    if _REDIRECTION.search(token):
        return False
    return _SCRIPT_CHARACTER.search(_EXPANSION.sub("", token)) is not None


def _powershell_name(token: str, plain: bool) -> bool:
    """Whether a token names PowerShell: in its last path component when it is plain.

    The shell may rewrite any other token, so PowerShell's name anywhere in it counts.
    """
    start = max(token.rfind("/"), token.rfind("\\")) + 1 if plain else 0
    if _POWERSHELL.search(token, start) is not None:
        return True
    # The shell removes quotes and escapes first, so `p'w'sh` and `p\\wsh` run pwsh.
    decoded = _decode_word(token, drop_ifs=True)
    start = decoded.rfind("/") + 1 if plain else 0
    return decoded != token and _POWERSHELL.search(decoded, start) is not None


def _computed_powershell(segment: str) -> int | None:
    """Offset of the command word when the shell computes a name that may be PowerShell.

    A variable or glob can select PowerShell. `-e`, `-ec`, `-en` and `-E` are shared by
    other programs (`$SED -En`, `$SHELL -ec`), so require a program-name hint, `-enc` or
    a longer prefix of `-EncodedCommand`, or an argument encoding UTF-16LE text.
    """
    spans = _shell_word_spans(segment)
    words = [segment[start:end] for start, end in spans]
    index = _executable_index(words, _redirections(segment, spans), skip_inputs=True)
    if index is None:
        return None
    word = words[index]
    pattern = _EXPANSION.sub("*", re.split(r"[/\\]", word)[-1])
    if not any(char in pattern for char in "*?["):
        return None
    pattern = re.sub(r"\*+", "*", _decode_word(pattern, drop_ifs=True).lower())
    stem = _WINDOWS_SUFFIX.sub("", pattern)
    # `[^][]` keeps the scan linear on a run of `[`.
    literal = re.sub(r"\[[^][]*\]", "", stem)
    if re.search(r"[a-z]{2}", literal) is None and not any(
        len(flag.group().lstrip("\"'‘’“”\\^`-/–—―")) > 2
        or (position + 1 < len(words) and _encoded_payload(words[position + 1]))
        for position in range(index + 1, len(words))
        if (flag := _ENCODED_COMMAND.match(segment, spans[position][0])) is not None
    ):
        return None
    # A longer pattern is mostly bracket expressions; it is not matched, so as not to
    # compile hostile globs, and is read as PowerShell.
    if len(pattern) > 64 or any(
        fnmatch.fnmatchcase(name, pattern) for name in _POWERSHELL_FILE_NAMES
    ):
        return spans[index][0]
    return None


# An -EncodedCommand value: base64 of UTF-16LE text, so a whole number of quads.
_BASE64_PAYLOAD = re.compile(r"(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?")


_ASCII_TEXT_RUN = re.compile(r"[\t\r\n -~]{8,}")
_TEXT_PREFIX = re.compile(r"[A-Za-z][A-Za-z0-9_.-]{2,}[ \t\r\n]")
_BASE64_SPACING = str.maketrans("", "", " \t\r\n")


def _encoded_payload(word: str) -> bool:
    """Whether a computed program's ambiguous short switch has UTF-16LE text evidence."""
    encoded = _decode_word(word, drop_ifs=True).translate(_BASE64_SPACING)
    if not _BASE64_PAYLOAD.fullmatch(encoded):
        return False
    try:
        text = base64.b64decode(encoded, validate=True).decode("utf-16-le", errors="replace")
    except binascii.Error:
        return False
    # A UTF-16 byte-order mark or a quoted string can be mostly non-ASCII.
    # For an unmarked operand, a single printable unit in unrelated binary
    # data is weak evidence. Count ordinary text and shell whitespace together.
    if text.startswith("\ufeff"):
        return len(text) > 1
    if not text:
        return False
    if len(text) == 1:
        return "!" <= text <= "~"
    if text[0] in {"'", '"'}:
        end_quote = text.find(text[0], 1)
        if end_quote >= 1 and text[1:end_quote].isprintable():
            return True
    if _TEXT_PREFIX.match(text.lstrip()):
        return True
    # A multilingual comment or string elsewhere in the operand cannot
    # dilute a whole run of UTF-16 text. Whitespace alone supplies no evidence.
    if any(run.group().strip() for run in _ASCII_TEXT_RUN.finditer(text)):
        return True
    graphic = sum("!" <= char <= "~" for char in text)
    ordinary = graphic + sum(char in " \t\r\n" for char in text)
    return graphic > 0 and ordinary >= 2 and ordinary * 2 >= len(text)


def _parameter_name(token: str) -> str | None:
    """A PowerShell parameter's lowercase name without its dash or `/`; else None.

    A dash may be doubled, as in `--noprofile`, and an en dash, em dash or horizontal
    bar counts as one.
    """
    if token[0] in "-\u2013\u2014\u2015":
        return token[2 if token[1:2] == token[0] else 1 :].lower()
    if token.startswith("/") and token[1:].isalpha():
        return token[1:].lower()
    return None


def _command_severity(command: str) -> RiskSeverity:
    """How dangerous a hook command is, without keeping its text."""
    if _fetch_exec(command):
        return RiskSeverity.CRITICAL
    if _HOOK_URL.search(command) or _downloads_from_host(command):
        return RiskSeverity.HIGH
    return RiskSeverity.MEDIUM


def _downloads_from_host(command: str) -> bool:
    """Whether a downloader is given a host without a scheme, as in `curl evil.example/x`."""
    for segments in _command_pipelines(command):
        for segment in segments:
            words = _shell_words(segment)
            if any(_name_variants(word) & _DOWNLOAD_NAMES for word in words) and any(
                _HOST_PATH.match(_decode_word(word, drop_ifs=True)) for word in words
            ):
                return True
    return False


def _worse(current: RiskSeverity | None, candidate: RiskSeverity | None) -> RiskSeverity | None:
    if candidate is None:
        return current
    if current is None or _SEVERITY_RANK[candidate] < _SEVERITY_RANK[current]:
        return candidate
    return current


def _hook_command_severity(value: Any, depth: int = 0) -> RiskSeverity | None:
    """The strongest severity among hook commands. The commands themselves are not returned."""
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    found: RiskSeverity | None = None
    if isinstance(value, dict):
        command = value.get("command")
        if isinstance(command, str):
            found = _command_severity(command)
        for item in value.values():
            found = _worse(found, _hook_command_severity(item, depth + 1))
    elif isinstance(value, list):
        for item in value:
            found = _worse(found, _hook_command_severity(item, depth + 1))
    return found


def _severity_clause(severity: RiskSeverity) -> str:
    if severity is RiskSeverity.CRITICAL:
        return (
            ", including a command that pipes a download or a decoded payload into a shell"
            " or runs encoded PowerShell."
        )
    if severity is RiskSeverity.HIGH:
        return ", including a command that contacts a network address."
    return "."


def _hook_detail(count: int, severity: RiskSeverity, ide: str, settings: Iterable[str] = ()) -> str:
    parts = [f"{count} hook command(s) that run automatically on agent events"] if count else []
    parts += [_AUTO_RUN_SETTINGS[key] for key in settings]
    return f"IDE agent '{ide}' declares {_series(parts)}" + _severity_clause(severity)


def _environment_risk(documents: dict[str, dict[str, Any]]) -> RiskAssessment | None:
    """Rate the names of settings `env` that redirect the agent or load code."""
    redirecting: set[str] = set()
    loading: set[str] = set()
    for data in documents.values():
        environment = data.get("env")
        if not isinstance(environment, dict):
            continue
        for name, value in environment.items():
            if not isinstance(name, str):
                continue
            upper = name.upper()
            if _REDIRECTING_ENVIRONMENT.fullmatch(upper):
                redirecting.add(name)
            elif (
                upper in _CODE_LOADING_ENVIRONMENT
                or _SETTINGS_CODE_ENVIRONMENT.fullmatch(upper)
                or _exported_function(name, value)
            ):
                loading.add(name)
    if not (redirecting or loading):
        return None
    parts = []
    if redirecting:
        parts.append(
            f"{_series(sorted(map(redact_text, redirecting)))}, which can send the API key and "
            "prompts to another endpoint or proxy, or replace the credential"
        )
    if loading:
        parts.append(
            f"{_series(sorted(map(redact_text, loading)))}, which can load code into the "
            "session or the commands it runs"
        )
    return RiskAssessment(
        severity=RiskSeverity.HIGH if redirecting else RiskSeverity.MEDIUM,
        category="settings_environment",
        detail=f"IDE agent 'claude-code' sets environment {'; and '.join(parts)}.",
        recommendation="Remove these variables from project settings, or approve each value.",
    )


def _hook_commands(value: Any, depth: int = 0) -> int:
    if depth > _MAX_SETTINGS_DEPTH:
        raise ValueError("settings nested too deeply")
    if isinstance(value, dict):
        own = 1 if isinstance(value.get("command"), str) else 0
        return own + sum(_hook_commands(item, depth + 1) for item in value.values())
    if isinstance(value, list):
        return sum(_hook_commands(item, depth + 1) for item in value)
    return 0


def _declared_hooks(hooks: object) -> dict[str, int]:
    """Count handlers per event for the reader; the settings digest is what binds them.

    Commands may carry secrets and stay unrecorded. A shape this does not know
    is left to the digest rather than guessed at.
    """
    counts: dict[str, int] = {}
    if not isinstance(hooks, dict):
        return counts
    for event, matchers in hooks.items():
        if not isinstance(event, str) or not isinstance(matchers, list):
            continue
        handlers = [matcher.get("hooks") for matcher in matchers if isinstance(matcher, dict)]
        counts[redact_text(event)] = sum(len(h) for h in handlers if isinstance(h, list))
    return counts


def _count(value: Any) -> int:
    return len(value) if isinstance(value, (list, dict)) else 0


# Declared starting modes beyond the two named in _starting_mode_risk that run
# without approval prompts, and what each runs that way. Unsandboxed full access is
# high and the rest medium, as the Codex TOML path rates `danger-full-access`,
# `never` and `on-failure`. Claude Code's dontAsk is not one: it denies a tool that
# is not pre-approved instead of prompting for it.
_PROMPT_SKIPPING_MODES: dict[str, tuple[RiskSeverity, str]] = {
    "danger-full-access": (RiskSeverity.HIGH, "runs without approval prompts"),
    "full-access": (RiskSeverity.HIGH, "runs without approval prompts"),
    "never": (RiskSeverity.MEDIUM, "runs without approval prompts"),
    "auto": (RiskSeverity.MEDIUM, "runs without approval prompts"),
    "on-failure": (RiskSeverity.MEDIUM, "runs commands without approval prompts unless they fail"),
}
# Codex approval policies that run commands without asking first. `on-failure` asks
# only to rerun a command that failed in the sandbox, outside it.
_UNPROMPTED_APPROVALS = {
    "never": "that commands never ask for approval",
    "auto": "that commands run without interactive approval",
    "on-failure": "that commands run without asking for approval unless they fail",
}


def _series(names: list[str]) -> str:
    """Names as prose: ``a``, ``a and b`` or ``a, b and c``."""
    return " and ".join([", ".join(names[:-1]), names[-1]] if len(names) > 1 else names)


def _starting_mode_risk(ide_type: str, mode: str | None) -> RiskAssessment | None:
    """The finding for a declared starting mode that skips approval prompts."""
    if mode in {"bypassPermissions", "always", "full-access", "danger-full-access"}:
        return RiskAssessment(
            severity=RiskSeverity.HIGH,
            category="permission_scope",
            detail=(
                f"IDE agent '{ide_type}' declares a starting mode ('{mode}') that skips "
                "permission prompts or sandbox confinement; effective approval remains unverified."
            ),
            recommendation=(
                "Remove the project-level bypass mode, or confine the agent to "
                "an isolated environment with no credentials it should not use."
            ),
        )
    if mode == "acceptEdits":
        return RiskAssessment(
            severity=RiskSeverity.MEDIUM,
            category="permission_scope",
            detail=(
                f"IDE agent '{ide_type}' declares a starting mode that accepts file edits "
                "without a prompt; effective approval remains unverified."
            ),
            recommendation=(
                "Use the default or plan mode in project settings; grant narrow allow "
                "rules instead."
            ),
        )
    skipping = _PROMPT_SKIPPING_MODES.get(mode or "")
    if skipping is not None:
        severity, runs = skipping
        return RiskAssessment(
            severity=severity,
            category="permission_scope",
            detail=(
                f"IDE agent '{ide_type}' declares starting mode '{mode}', which {runs}; "
                "effective approval remains unverified."
            ),
            recommendation=(
                "Use a default or sandboxed mode in project settings and approve "
                "actions explicitly."
            ),
        )
    return None


def _overridden(files: list[str]) -> str:
    """Attribution for a finding a file declares and a later settings file overrides.

    The committed file's declaration still holds wherever the later file, such as an
    uncommitted settings.local.json, is absent, so the override never drops the finding.
    """
    return (
        f" Declared in {_series([repr(name) for name in files])}; the effective merged value "
        "differs because a later settings file overrides it."
    )


def _layered_mode_risk(
    risk: RiskAssessment | None,
    documents: dict[str, dict[str, Any]],
    effective: str | None,
    base: str,
) -> RiskAssessment | None:
    """The worse of the effective starting mode's finding and each settings file's own."""
    for name in CLAUDE_SETTINGS:
        relative = f"{base}/{name}" if base else name
        permissions = documents.get(relative, {}).get("permissions")
        declared = permissions.get("defaultMode") if isinstance(permissions, dict) else None
        if not isinstance(declared, str) or declared == effective:
            continue
        candidate = _starting_mode_risk("claude-code", declared)
        current = risk.severity if risk is not None else None
        if candidate is None or _worse(current, candidate.severity) == current:
            continue
        risk = candidate.model_copy(
            update={
                "detail": candidate.detail
                + f" Declared in '{relative}'; the effective merged starting mode is "
                f"'{effective or 'default'}'."
            }
        )
    return risk


class IDEAgentScanner(Scanner):
    name = "ide_agents"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            for ide_type, config in IDE_AGENT_CONFIGS.items():
                found: list[str] = []
                for marker in config["markers"]:
                    evidence = self._marker(files, marker)
                    if evidence is not None:
                        found.append(marker)
                        result.surfaces_scanned.append(evidence)
                if found:
                    result.components.append(
                        self._agent(files, result, ide_type, found, config["mcp_config"])
                    )
            # A host started in a subdirectory, such as one package of a monorepo, reads
            # that directory's .claude settings as its project settings, and on a
            # case-insensitive file system those of another spelling of either name.
            nested: dict[str, list[str]] = {}
            links: list[Path] = []
            for path in files.iter_files(directory_links=links):
                if len(path.parts) <= 2 or fold_name(path.parts[-2]) != ".claude":
                    continue
                name = _FOLDED_SETTINGS_NAMES.get(fold_name(path.name))
                if name is None:
                    continue
                if path.parts[-2] != ".claude" or path.name != name:
                    files.report_case_variant(path, Path(*path.parts[:-2], ".claude", name))
                    continue
                nested.setdefault(Path(*path.parts[:-2]).as_posix(), []).append(path.as_posix())
            for link in links:
                self._linked_settings(files, link, nested)
            for base, paths in sorted(nested.items()):
                result.surfaces_scanned.extend(sorted(paths))
                result.components.append(
                    self._agent(files, result, "claude-code", sorted(paths), [], base=base)
                )
            self._scan_extensions(files, result)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("ide-agents (no IDE agent configs found)")
        return result

    def _agent(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        ide_type: str,
        found: list[str],
        mcp_config: list[str],
        *,
        base: str = "",
    ) -> IDEAgentComponent:
        """One agent's record; ``base`` names the subdirectory of nested settings."""
        risks: list[RiskAssessment] = []
        properties: dict[str, Any] = {"settings_directory": base} if base else {}
        # Every settings file the record reads, as read; each is digested.
        documents: dict[str, dict[str, Any]] = {}
        if ide_type == "claude-code":
            settings = self._claude_settings(result, risks, properties, documents, base=base)
        else:
            settings = self._agent_mode_settings(ide_type, result, documents)
        if ide_type == "codex":
            self._codex_settings(files, result, risks, properties, documents)
        elif ide_type == "gemini":
            self._gemini_settings(files, result, documents)
        elif ide_type == "cursor":
            self._cursor_hooks(files, result, risks, properties, documents)
        for relative in _DIGESTED_SETTINGS.get(ide_type, []):
            data = self._read_jsonc(files, relative, result)
            if data is not None:
                documents[relative] = data
        self._bind_settings(ide_type, documents, result, risks, properties)
        if ide_type in {"claude-code", "cursor"}:
            scan_subagent_and_rule_frontmatter(
                files,
                base,
                risks,
                properties,
                ide_type=ide_type,
                scan_failures=result.scan_failures,
                surfaces_excluded=result.surfaces_excluded,
                credential_check=credential_gap,
            )
        mode = self._extract_permission_mode(settings or {}, ide_type, result)
        toml_mode = False
        if ide_type == "codex" and mode is None:
            # _codex_settings already rated the TOML approval and sandbox modes.
            mode = properties.get("approval_policy")
            toml_mode = True
        broad = self._broad_permissions(settings or {}, ide_type, result)
        if broad:
            risks.insert(
                0,
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="permission_scope",
                    detail=(
                        f"IDE agent '{ide_type}' declares unscoped tool allowances "
                        f"({', '.join(broad)}); effective approval remains unverified."
                    ),
                    recommendation=(
                        "Review deny/ask rules, workspace trust, user and managed "
                        "settings, and runtime controls; enforce resource-scoped authority."
                    ),
                ),
            )
        starting_mode = None if toml_mode else _starting_mode_risk(ide_type, mode)
        if ide_type == "claude-code":
            starting_mode = _layered_mode_risk(starting_mode, documents, mode, base)
        if starting_mode is not None:
            risks.insert(0, starting_mode)
        layered = (
            ide_type == "claude-code" and {"CLAUDE.md", ".claude/CLAUDE.md"}.issubset(found)
        ) or (ide_type == "cursor" and {".cursorrules", ".cursor/rules"}.issubset(found))
        if layered:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="instruction_layering",
                    detail=f"IDE agent '{ide_type}' has multiple declared instruction locations.",
                    recommendation="Document loading order, modification authority and approved digests.",
                )
            )
        mcp_configs = []
        for config_name in mcp_config:
            data = self._read_mapping(Path(config_name), result)
            if data is not None:
                mcp_configs.append(config_name)
        # Markers and settings read through an in-root symlink, with the file that held them.
        links = {
            path: target
            for path in (*found, *documents)
            if (target := files.link_target(path)) is not None
        }
        if links:
            properties["symlink_targets"] = dict(sorted(links.items()))
        # Configuration locators are not component references. The MCP
        # collector binds actual client/server components separately.
        return IDEAgentComponent(
            bom_ref=f"ide-agent:{ide_type}" + (f"@{base}" if base else ""),
            name=ide_type + (f" ({base})" if base else ""),
            ide_type=ide_type,
            config_files=found,
            mcp_server_refs=[],
            permission_mode=mode,
            source_path=found[0],
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
            properties={
                "collection_mode": "static-project-configuration",
                "mcp_config_paths": mcp_configs,
                "permission_evidence": "declaration-only",
                "effective_authorization_verified": False,
                "permission_policy_limitations": [
                    (
                        "User and managed settings, workspace trust, per-session "
                        "flags and runtime controls were not observed."
                    ),
                    "Deny and ask rules may narrow declared allow rules.",
                    (
                        "Project/local starting-mode declarations may be ignored "
                        "by the host or version."
                    ),
                ],
                **properties,
            },
        )

    @staticmethod
    def _linked_settings(
        files: ConfinedCollection, link: Path, nested: dict[str, list[str]]
    ) -> None:
        """Nested settings below a ``.claude`` directory symlink, which the walk skips.

        The walk covers the target under its own name, where the settings files are not
        recognised, so they are looked up through the link as a host started there would.
        """
        if len(link.parts) < 2 or fold_name(link.name) != ".claude":
            return
        for name in _FOLDED_SETTINGS_NAMES.values():
            path = link / name
            if files.regular_file(path) is None:
                # Records a refused link, or another spelling below the link.
                files.read_bytes(path, missing_ok=True)
            elif link.name != ".claude":
                files.report_case_variant(path, link.with_name(".claude") / name)
            else:
                nested.setdefault(link.parent.as_posix(), []).append(path.as_posix())

    @staticmethod
    def _marker(files: ConfinedCollection, marker: str) -> str | None:
        """The path that shows a marker exists: the file, or a file in the directory."""
        if files.is_directory(marker):
            for path in files.iter_files(marker):
                return path.as_posix()
            return None
        variants = _CODEX_SPELLINGS if marker in _CODEX_SPELLINGS else ()
        if files.regular_file(marker) is None:
            # Existence is a stat, charged to no budget; the read records a refused link
            # or another spelling of the name, and reads nothing when the file is absent.
            files.read_bytes(marker, missing_ok=True, variants_read=variants)
            return None
        return marker

    def _claude_settings(
        self,
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
        documents: dict[str, dict[str, Any]],
        *,
        base: str = "",
    ) -> dict[str, Any] | None:
        """Merge permission layers and count what the settings and plugin files declare.

        Every file is bound by its digest, so a changed hook, rule, helper, plugin or
        marketplace changes the record. The merged summary does not resolve effective
        permissions across trust, user or managed policy, flags or product versions.
        """
        merged: dict[str, Any] = {}
        layers: dict[str, dict[str, Any]] = {}
        for relative in (f"{base}/{name}" if base else name for name in CLAUDE_SETTINGS):
            data = self._read_mapping(Path(relative), result)
            if data is None:
                continue
            documents[relative] = data
            layers[relative] = data
            hooks = _declared_hooks(data.get("hooks"))
            if hooks:
                properties.setdefault("declared_hooks", {})[relative] = hooks
            if "permissions" in data:
                permissions = data["permissions"]
                if not isinstance(permissions, dict):
                    result.scan_failures.append(f"{relative}: invalid permission settings object")
                    # The file's other declarations still count.
                    merged.update({key: item for key, item in data.items() if key != "permissions"})
                    continue
                previous = merged.get("permissions", {})
                combined = {**previous, **permissions}
                for key in ("allow", "ask", "deny"):
                    earlier, current = previous.get(key, []), permissions.get(key, [])
                    if not all(
                        isinstance(values, list) and all(isinstance(value, str) for value in values)
                        for values in (earlier, current)
                    ):
                        result.scan_failures.append(
                            f"{relative}: invalid declared permission {key}-list"
                        )
                        combined.pop(key, None)
                    else:
                        combined[key] = list(dict.fromkeys([*earlier, *current]))
                data = {**data, "permissions": combined}
            merged.update(data)
        plugins: dict[str, dict[str, Any]] = {}
        for relative in CLAUDE_PLUGIN_MANIFESTS if not base else ():
            data = self._read_mapping(Path(relative), result)
            if data is not None:
                plugins[relative] = data
        if plugins:
            hooks_file = self._read_mapping(Path(CLAUDE_PLUGIN_HOOKS), result)
            if hooks_file is not None:
                plugins[CLAUDE_PLUGIN_HOOKS] = hooks_file
                hooks = _declared_hooks(hooks_file.get("hooks"))
                if hooks:
                    properties.setdefault("declared_hooks", {})[CLAUDE_PLUGIN_HOOKS] = hooks
            properties["plugin_manifests"] = sorted(plugins)
        # Only settings files merge into the permission summary; every file is bound.
        documents.update(plugins)
        if not documents:
            return None
        declared_permissions = merged.get("permissions")
        rules: dict[str, Any] = (
            declared_permissions if isinstance(declared_permissions, dict) else {}
        )
        counts = {
            key: len(rules[key])
            for key in ("allow", "ask", "deny")
            if isinstance(rules.get(key), list)
        }
        if counts:
            properties["declared_permission_rule_counts"] = counts
        deny_rules, deny_total, deny_digest, deny_trunc = extract_bounded_deny_rules(
            merged, rule_formatter=_safe_rule_shape
        )
        if deny_rules:
            properties["deny_rules"] = deny_rules
        if deny_trunc:
            properties["deny_rules_total"] = deny_total
            properties["deny_rules_truncated"] = True
            properties["deny_rules_digest"] = deny_digest
        sandbox_domains, dom_total, dom_digest, dom_trunc = extract_bounded_sandbox_domains(
            merged, text_formatter=_safe_projected_text
        )
        if sandbox_domains:
            properties["sandbox_allowed_domains"] = sandbox_domains
        if dom_trunc:
            properties["sandbox_allowed_domains_total"] = dom_total
            properties["sandbox_allowed_domains_truncated"] = True
            properties["sandbox_allowed_domains_digest"] = dom_digest
        default_mode = (
            rules.get("defaultMode") if isinstance(rules.get("defaultMode"), str) else None
        )
        raw_always = merged.get("alwaysAllow") or rules.get("alwaysAllow")
        always_allow: Iterable[str] = raw_always if isinstance(raw_always, (str, list)) else ()
        tool_states, oversight_risks, tool_total, tool_trunc = evaluate_tool_oversight(
            rules,
            always_allow=always_allow,
            approval_policy=default_mode,
            source_name=f"{base}/.claude/settings.json" if base else ".claude/settings.json",
            text_formatter=_safe_projected_text,
        )
        if tool_states:
            properties["tool_human_in_the_loop"] = tool_states
        if tool_trunc:
            properties["tool_human_in_the_loop_total"] = tool_total
            properties["tool_human_in_the_loop_truncated"] = True
        risks.extend(oversight_risks)
        hook_commands = 0
        hook_severity: RiskSeverity | None = None
        # Auto-run settings and credential helpers run without an agent event, as hooks do.
        auto_run: set[str] = set()
        helper_severity = RiskSeverity.MEDIUM
        for relative, data in documents.items():
            body = data if relative == CLAUDE_PLUGIN_HOOKS else data.get("hooks")
            try:
                hook_commands += _hook_commands(body)
                hook_severity = _worse(hook_severity, _hook_command_severity(body))
            except ValueError:
                result.scan_failures.append(f"{relative}: settings cannot be canonicalized")
            if relative == CLAUDE_PLUGIN_HOOKS:
                continue
            for key in _AUTO_RUN_SETTINGS:
                setting = data.get(key)
                if isinstance(setting, dict) and isinstance(setting.get("command"), str):
                    auto_run.add(key)
                    hook_severity = _worse(hook_severity, _command_severity(setting["command"]))
            for key in _CREDENTIAL_HELPER_KEYS:
                helper = data.get(key)
                if isinstance(helper, str):
                    helper_severity = min(
                        helper_severity, _command_severity(helper), key=_SEVERITY_RANK.__getitem__
                    )
        declared = {
            "additional_directories": _count(rules.get("additionalDirectories")),
            "enabled_plugins": _count(merged.get("enabledPlugins")),
            "extra_known_marketplaces": _count(merged.get("extraKnownMarketplaces")),
            "enabled_mcpjson_servers": _count(merged.get("enabledMcpjsonServers")),
            "disabled_mcpjson_servers": _count(merged.get("disabledMcpjsonServers")),
            "env_variables": _count(merged.get("env")),
            "api_key_helper": merged.get("apiKeyHelper") is not None,
            "enable_all_project_mcp_servers": merged.get("enableAllProjectMcpServers") is True,
        }
        properties["settings_declarations"] = declared
        if hook_commands or auto_run:
            risks.append(
                RiskAssessment(
                    severity=hook_severity or RiskSeverity.MEDIUM,
                    category="hook_commands",
                    detail=_hook_detail(
                        hook_commands,
                        hook_severity or RiskSeverity.MEDIUM,
                        "claude-code",
                        [key for key in _AUTO_RUN_SETTINGS if key in auto_run],
                    ),
                    recommendation="Review this setting and approve its exact value.",
                )
            )
        environment_risk = _environment_risk(
            {key: value for key, value in documents.items() if key != CLAUDE_PLUGIN_HOOKS}
        )
        if environment_risk is not None:
            risks.append(environment_risk)
        # Findings come from each file's own declarations; `declared` is the merged value.
        helpers = [
            key
            for key in _CREDENTIAL_HELPER_KEYS
            if any(data.get(key) is not None for data in layers.values())
        ]
        commands = "a command that runs" if len(helpers) == 1 else "commands that run"
        approving = [
            relative
            for relative, data in layers.items()
            if data.get("enableAllProjectMcpServers") is True
        ]
        approval_note = (
            _overridden(approving)
            if approving and not declared["enable_all_project_mcp_servers"]
            else ""
        )
        overridden_helpers = [
            relative
            for relative, data in layers.items()
            if any(data.get(key) is not None and merged.get(key) is None for key in helpers)
        ]
        helper_note = _overridden(overridden_helpers) if overridden_helpers else ""
        for category, severity, present, detail in (
            (
                "mcp_auto_approval",
                RiskSeverity.MEDIUM,
                bool(approving),
                "approves every MCP server in the project's .mcp.json without a prompt",
            ),
            (
                "credential_helper",
                helper_severity,
                bool(helpers),
                f"declares {_series(helpers)}, {commands} to obtain credentials"
                + _severity_clause(helper_severity)[:-1],
            ),
            (
                "plugin_sources",
                RiskSeverity.LOW,
                bool(declared["enabled_plugins"] or declared["extra_known_marketplaces"]),
                "enables plugins or registers plugin marketplaces, which can add commands, "
                "agents, hooks and MCP servers",
            ),
            (
                "additional_directories",
                RiskSeverity.LOW,
                bool(declared["additional_directories"]),
                "grants access to directories outside the project",
            ),
        ):
            if present:
                note = {"mcp_auto_approval": approval_note, "credential_helper": helper_note}
                risks.append(
                    RiskAssessment(
                        severity=severity,
                        category=category,
                        detail=f"IDE agent 'claude-code' {detail}.{note.get(category, '')}",
                        recommendation="Review this setting and approve its exact value.",
                    )
                )
        return merged

    @staticmethod
    def _bind_settings(
        ide_type: str,
        documents: dict[str, dict[str, Any]],
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
    ) -> None:
        """Digest each settings file into `settings_hashes`; bind their values with the key.

        Every digest, with or without the operator key, covers the file after the
        redaction, under ``SETTINGS_DIGEST_PROFILE``, so the inventory never carries an
        unkeyed digest of a value the redaction removes, such as a settings `env` map or
        a credential helper command: anyone holding the inventory could otherwise confirm
        guesses of those values offline. With the key an HMAC covers every file as
        read. A file that has no RFC 8785 form, such as TOML with a date, is a failure
        that names it, and leaves the record's values unbound. Without the key, so is a
        redacted file that holds a URL whose authority URL parsers read differently,
        and a redacted digest that leaves out a value is a low completeness finding.
        """
        if not documents:
            return
        keyed = bool(os.environ.get(SOURCE_BINDING_KEY_ENV))
        hashes: dict[str, str] = {}
        withheld: list[str] = []
        for relative, data in documents.items():
            try:
                projected = _projection(data, unkeyed=not keyed)
                digest = hash_canonical(projected)
                if keyed:
                    # The keyed binding covers the file as read, not only its projection.
                    canonical_json(data)
                elif projected != data:
                    withheld.append(relative)
            except AmbiguousURLError:
                result.scan_failures.append(
                    f"{relative}: a URL authority is ambiguous, so its host cannot be bound"
                )
            except (TypeError, ValueError, RecursionError):
                result.scan_failures.append(f"{relative}: settings cannot be canonicalized")
            else:
                hashes[relative] = digest
        if hashes:
            properties["settings_hashes"] = hashes
            properties["settings_hashes_profile"] = SETTINGS_DIGEST_PROFILE
        if withheld:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=(
                        f"IDE agent '{ide_type}' settings values not bound in this inventory: "
                        f"the redacted values of {', '.join(withheld)}."
                    ),
                    recommendation=(
                        f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to "
                        "these values."
                    ),
                )
            )
        if len(hashes) < len(documents):
            properties["source_values_bound"] = False
            return
        try:
            binding = value_binding(SETTINGS_VALUE_BINDING_PROFILE, documents)
        except BindingError as exc:
            result.scan_failures.append(f"{next(iter(documents))}: {exc}")
            return
        properties["source_values_bound"] = bool(binding)
        properties.update(binding)

    def _codex_settings(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
        documents: dict[str, dict[str, Any]],
    ) -> None:
        """Read the approval and sandbox modes; the whole file is digested.

        The ``mcp`` collector inventories the MCP servers it declares.
        """
        text = files.read_text(CODEX_CONFIG, missing_ok=True)
        if text is None:
            return
        try:
            config = load_toml(text)
        except (ValueError, RecursionError, MemoryError):
            result.scan_failures.append(f"{CODEX_CONFIG}: invalid TOML")
            return
        documents[CODEX_CONFIG] = config
        approval, sandbox = config.get("approval_policy"), config.get("sandbox_mode")
        if approval is not None and (
            not isinstance(approval, str) or approval not in _PERMISSION_MODES
        ):
            result.scan_failures.append(f"{CODEX_CONFIG}: unsupported approval_policy")
            approval = None
        if sandbox is not None and (
            not isinstance(sandbox, str) or sandbox not in _PERMISSION_MODES
        ):
            result.scan_failures.append(f"{CODEX_CONFIG}: unsupported sandbox_mode")
            sandbox = None
        properties["approval_policy"] = approval
        properties["sandbox_mode"] = sandbox
        codex_model = config.get("model")
        if isinstance(codex_model, str) and codex_model.strip():
            clean_model = _safe_projected_text(codex_model.strip())[:512].strip()
            if clean_model:
                properties["model"] = clean_model
                model_ref = f"model:{clean_model}"
                if not any(comp.bom_ref == model_ref for comp in result.components):
                    result.components.append(
                        ModelComponent(
                            bom_ref=model_ref,
                            name=clean_model,
                            properties={"source": CODEX_CONFIG},
                        )
                    )
        full_access = sandbox in {"danger-full-access", "full-access"} or approval == "always"
        declared = (
            "an unsandboxed full-access mode"
            if full_access
            else _UNPROMPTED_APPROVALS.get(approval or "")
        )
        if declared is not None:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH if full_access else RiskSeverity.MEDIUM,
                    category="permission_scope",
                    detail=(
                        f"IDE agent 'codex' declares {declared}; "
                        "effective approval remains unverified."
                    ),
                    recommendation="Keep the workspace-write sandbox and on-request approval.",
                )
            )

    def _gemini_settings(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        documents: dict[str, dict[str, Any]],
    ) -> None:
        """Read Gemini CLI project settings for their digest.

        The ``mcp`` collector inventories the MCP servers they declare.
        """
        data = self._read_jsonc(files, GEMINI_SETTINGS, result)
        if data is None:
            return
        documents[GEMINI_SETTINGS] = data

    def _cursor_hooks(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        risks: list[RiskAssessment],
        properties: dict[str, Any],
        documents: dict[str, dict[str, Any]],
    ) -> None:
        """Count the commands that Cursor project hooks run on agent events."""
        data = self._read_jsonc(files, CURSOR_HOOKS, result)
        if data is None:
            return
        documents[CURSOR_HOOKS] = data
        try:
            hooks = _hook_commands(data.get("hooks"))
        except ValueError:
            result.scan_failures.append(f"{CURSOR_HOOKS}: settings cannot be canonicalized")
            return
        properties["hook_commands"] = hooks
        if hooks:
            try:
                severity = _hook_command_severity(data.get("hooks")) or RiskSeverity.MEDIUM
            except ValueError:
                severity = RiskSeverity.MEDIUM
            risks.append(
                RiskAssessment(
                    severity=severity,
                    category="hook_commands",
                    detail=_hook_detail(hooks, severity, "cursor"),
                    recommendation="Review this setting and approve its exact value.",
                )
            )

    @staticmethod
    def _read_jsonc(
        files: ConfinedCollection, relative: str, result: ScanResult
    ) -> dict[str, Any] | None:
        """A JSON object that may hold comments and trailing commas, as editors accept."""
        text = files.read_text(relative, missing_ok=True)
        if text is None:
            return None
        try:
            data = parse_json_strict(strip_jsonc(text), max_bytes=files.max_file_bytes)
        except (ValueError, RecursionError):
            result.scan_failures.append(f"{relative}: invalid JSON or duplicate keys")
            return None
        if not isinstance(data, dict):
            result.scan_failures.append(f"{relative}: expected a mapping")
            return None
        return data

    def _agent_mode_settings(
        self, ide_type: str, result: ScanResult, documents: dict[str, dict[str, Any]]
    ) -> dict[str, Any] | None:
        merged: dict[str, Any] = {}
        for relative in _AGENT_MODE_SETTINGS.get(ide_type, []):
            data = self._read_mapping(Path(relative), result)
            if data is not None:
                documents[relative] = data
                merged.update(data)
        return merged or None

    def _extract_permission_mode(
        self, settings: dict[str, Any], ide_type: str, result: ScanResult
    ) -> str | None:
        key = "permissions" if ide_type == "claude-code" else "agent"
        mode_key = "defaultMode" if ide_type == "claude-code" else "permissionMode"
        values = settings.get(key, {})
        if not isinstance(values, dict):
            result.scan_failures.append(f"{ide_type}: invalid permission settings object")
            return None
        mode = values.get(mode_key)
        if mode is None:
            return None
        if not isinstance(mode, str):
            result.scan_failures.append(f"{ide_type}: invalid declared permission mode")
            return None
        if mode not in _PERMISSION_MODES:
            result.scan_failures.append(f"{ide_type}: unsupported declared permission mode")
            return None
        return mode

    def _broad_permissions(
        self, settings: dict[str, Any], ide_type: str, result: ScanResult
    ) -> list[str]:
        if ide_type != "claude-code":
            return []
        permissions = settings.get("permissions", {})
        if not isinstance(permissions, dict):
            return []
        allowed = permissions.get("allow", [])
        if not isinstance(allowed, list) or not all(isinstance(value, str) for value in allowed):
            result.scan_failures.append(f"{ide_type}: invalid declared permission allow-list")
            return []
        return _broad_grants(allowed)

    def _scan_extensions(self, files: ConfinedCollection, result: ScanResult) -> None:
        relative = ".vscode/extensions.json"
        data = self._read_jsonc(files, relative, result)
        if data is None:
            return
        result.surfaces_scanned.append(relative)
        recommendations = data.get("recommendations", [])
        if not isinstance(recommendations, list) or len(recommendations) > 1000:
            result.scan_failures.append("extensions.json: invalid or oversized recommendation list")
            return
        ai_patterns = (
            "anthropic",
            "claude",
            "copilot",
            "codeium",
            "cursor",
            "tabnine",
            "codex",
            "openai",
            "ai-",
            "agent",
        )
        for extension in recommendations:
            if not isinstance(extension, str) or not _EXTENSION_ID.fullmatch(extension):
                result.scan_failures.append("extensions.json: invalid extension identifier")
                continue
            if any(pattern in extension.lower() for pattern in ai_patterns):
                extension = redact_text(extension)
                result.components.append(
                    VerifiedExtensionComponent(
                        bom_ref=f"verified-extension:vscode/{extension}",
                        name=extension,
                        extension_type="ide-extension",
                        publisher=extension.split(".", 1)[0],
                        publisher_verified=False,
                        attestation_status="unverified",
                        source_path=relative,
                        trust_tier=TrustTier.UNKNOWN,
                        properties={
                            "collection_mode": "recommended-extension",
                            "installation_observed": False,
                        },
                        risks=[
                            RiskAssessment(
                                severity=RiskSeverity.LOW,
                                category="attestation",
                                detail=f"Recommended VS Code AI extension '{extension}' has no verified attestation.",
                                recommendation="Verify installed extension identity, publisher and artifact evidence separately.",
                            )
                        ],
                    )
                )
