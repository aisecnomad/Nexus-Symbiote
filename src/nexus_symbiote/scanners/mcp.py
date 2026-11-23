"""MCP server and tool scanner.

Discovers MCP server configurations in the project-level client files listed in
``MCP_DIALECTS`` (Claude Code, Claude Desktop, Cursor, VS Code, Gemini CLI, Roo Code,
Kiro, Amazon Q, Windsurf, Cline, Codex, Zed, opencode, Continue and Junie), in the
configuration names of ``MCP_CONFIG_NAMES`` anywhere below the root, and MCP server
source written in the supported SDK forms. Each client's own server shape is
normalised to one form before parsing (``_normalized_server``), so every launch
command is classified without being executed (``scanners/mcp_launch.py``) and every
environment value is redacted the same way; declared tools are fingerprinted;
unpinned packages, redirected package sources, launch context and endpoint transport
are reported. Servers whose launch a client file does not hold, and launchers or
endpoints that cannot be classified, are coverage gaps rather than silence.
"""

from __future__ import annotations

import bisect
import copy
import hmac
import ipaddress
import json
import math
import os
import posixpath
import re
import shlex
from array import array
from bisect import bisect_left
from collections.abc import Callable, Collection, Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import date
from itertools import chain, pairwise
from pathlib import Path
from typing import Any, Literal
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from packaging.utils import canonicalize_name

from nexus_symbiote.core.enums import (
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    canonical_json,
    hash_canonical,
    hash_tool_definition,
    tool_definition_extensions,
)
from nexus_symbiote.core.models import (
    UNBOUND_VALUES_DETAIL,
    CapabilityDeclaration,
    MCPClientComponent,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.scanners.base import (
    KnownValues,
    Scanner,
    ScanResult,
    SourceBudget,
    sanitized_origin,
    source_collection_bytes,
)
from nexus_symbiote.scanners.mcp_credentials import (
    NAMED_CLASS,
    SCHEME_CLASS,
    SHAPE_CLASS,
    Hit,
    WrappedKeySearchLimitError,
    assignment_hits,
    credential_name,
    endpoint_hits,
    literal_value,
    name_words,
    placeholder,
    private_key_forms,
    public_value,
    rewrapped_key_literals,
    strongest,
    value_hits,
)
from nexus_symbiote.scanners.mcp_launch import (
    NPM_CONFIG_FLAGS,
    NPM_CONFIG_VALUES,
    Launch,
    Package,
    analyze,
    expands,
    known_executable,
    origin,
)
from nexus_symbiote.utils.confined import (
    AGENT_DEFAULT_EXCLUDE_REASON,
    DEFAULT_EXCLUDE_REASON,
    ConfinedCollection,
    fold_name,
)
from nexus_symbiote.utils.jsonc import strip_jsonc
from nexus_symbiote.utils.secrets import (
    MIN_SECRET_LENGTH,
    REDACTED,
    TOKEN_SHAPE,
    SecretScrubber,
    credential_shaped,
    is_reference,
    redact_descriptor,
    redact_text,
    scheme_credentials,
    secret_like,
    secret_values,
)
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.utils.toml import loads as load_toml


@dataclass(frozen=True)
class McpDialect:
    """An MCP client file: where it is, how it is written and how it nests servers.

    The client that reads it is named from its path by ``_detect_host_from_config``.
    """

    path: str
    syntax: str
    maps: tuple[str, ...]
    url_transport: str | None = None
    # Settings that hold one command line the client starts as the server ``mcp``.
    server_commands: tuple[tuple[str, ...], ...] = ()
    # The client's own server shape, which ``_normalized_server`` reads into the
    # common form; ``map`` is a map of server objects in that form already.
    shape: str = "map"
    # Set on a directory the client reads one server file at a time: the suffixes of
    # the files it reads there, each a document in the dialect's syntax.
    members: tuple[str, ...] = ()
    # The suffixes of files below such a directory that the client may read and the
    # collector does not read there: in a deeper directory, or not among ``members``.
    member_gaps: tuple[str, ...] = ()
    # The client whose file this is, when no host directory or file name names it.
    host: str | None = None


# Every MCP configuration file is read for both server maps, whichever its client
# reads; a server named in both is a failure. Gemini CLI settings and Codex
# configuration hold other settings too, so only their own map is read there.
_SERVER_MAPS = ("mcpServers", "servers")
MCP_DIALECTS = (
    McpDialect(".mcp.json", "json", _SERVER_MAPS),
    McpDialect("mcp.json", "json", _SERVER_MAPS),
    McpDialect("claude_desktop_config.json", "json", _SERVER_MAPS),
    McpDialect(".cursor/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".claude/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".vscode/mcp.json", "jsonc", _SERVER_MAPS),
    McpDialect(
        ".gemini/settings.json",
        "jsonc",
        ("mcpServers",),
        "sse",
        (("mcpServerCommand",), ("mcp", "serverCommand")),
    ),
    McpDialect(".roo/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".kiro/settings/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".amazonq/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".windsurf/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".cline/mcp.json", "json", _SERVER_MAPS),
    McpDialect(".codex/config.toml", "toml", ("mcp_servers",)),
    McpDialect(".zed/settings.json", "jsonc", ("context_servers",), shape="zed", host="zed"),
    # opencode reads comments and trailing commas in both names.
    McpDialect("opencode.json", "jsonc", ("mcp",), shape="opencode"),
    McpDialect("opencode.jsonc", "jsonc", ("mcp",), shape="opencode"),
    McpDialect(".continue/config.yaml", "yaml", ("mcpServers",), shape="continue", host="continue"),
    McpDialect(
        ".continue/mcpServers",
        "yaml",
        ("mcpServers",),
        shape="continue",
        members=(".yaml", ".yml"),
        member_gaps=(".json", ".yaml", ".yml"),
        host="continue",
    ),
    # Continue's local agent configurations, each in the config.yaml format; the
    # assistants and configs directories are the names it also reads them from.
    *(
        McpDialect(
            f".continue/{name}",
            "yaml",
            ("mcpServers",),
            shape="continue",
            members=(".yaml", ".yml"),
            member_gaps=(".yaml", ".yml"),
            host="continue",
        )
        for name in ("agents", "assistants", "configs")
    ),
    McpDialect(".junie/mcp/mcp.json", "json", _SERVER_MAPS, host="junie"),
    # Continue merges a workspace .continuerc.json onto its global config.json, whose
    # experimental.modelContextProtocolServers the collector does not read: a gap.
    McpDialect(".continuerc.json", "jsonc", (), shape="continuerc", host="continue"),
)
MCP_CONFIG_FILES = [dialect.path for dialect in MCP_DIALECTS if not dialect.members]
MCP_CONFIG_DIRECTORIES = [dialect.path for dialect in MCP_DIALECTS if dialect.members]
_ROOT_CLIENT_FILES = frozenset(MCP_CONFIG_FILES)

# The same names below the root: a package's own configuration, and the files
# other hosts read (.vscode/mcp.json, .windsurf/mcp_config.json, ...).
MCP_CONFIG_NAMES = frozenset(
    {
        ".mcp.json",
        "mcp.json",
        "mcp-config.json",
        "mcp_config.json",
        "mcp-servers.json",
        "claude_desktop_config.json",
        "cline_mcp_settings.json",
    }
)
_HOST_DIRECTORIES = {
    ".claude": "claude-code",
    ".cursor": "cursor",
    ".vscode": "vscode",
    ".windsurf": "windsurf",
    ".roo": "roo",
    ".amazonq": "amazon-q",
    ".kiro": "kiro",
    ".cline": "cline",
    ".gemini": "gemini-cli",
    ".codex": "codex",
}
# A file with one of these names names its client; any other names it from a host
# directory above it.
_CLIENTS_BY_NAME = {
    ".mcp.json": "claude-code",
    "claude_desktop_config.json": "claude-desktop",
    "cline_mcp_settings.json": "cline",
    "opencode.json": "opencode",
    "opencode.jsonc": "opencode",
}
_FOLDED_CONFIG_NAMES = {fold_name(name): name for name in MCP_CONFIG_NAMES}
_FOLDED_HOST_DIRECTORIES = {fold_name(name): name for name in _HOST_DIRECTORIES}
# Longest first, so the first match is the dialect _template picks for the exact spelling.
_FOLDED_TEMPLATES = sorted(
    (
        (
            tuple(fold_name(part) for part in dialect.path.split("/")),
            dialect.path.split("/"),
            dialect.members,
        )
        for dialect in MCP_DIALECTS
    ),
    key=lambda template: -len(template[0]),
)
# Files below a server directory that the client does not read there, or whose reading
# there is not confirmed, are gaps rather than silence.
_DIRECTORY_DIALECTS = {
    tuple(fold_name(part) for part in dialect.path.split("/")): dialect
    for dialect in MCP_DIALECTS
    if dialect.members
}
_DIRECTORY_GAP = "file below an MCP server directory that the collector does not read there"


def _client_spelling(path: Path) -> str | None:
    """The client file a host opens as the walked ``path`` on a case-insensitive file
    system, or ``None`` when it is none the collector reads.

    That is a name that folds to one of ``MCP_CONFIG_NAMES``, a dialect path such as
    ``.gemini/settings.json``, or a member of a server directory such as
    ``.continue/mcpServers/x.yaml``, at the root or nested as :func:`_template` reads
    it. The dialect path it ends in, the host directories just above a name that ends
    none, and any host directory above a name that does not name its client take the
    spelling the collector reads: they decide the dialect, launch directory and client
    of the exact spelling (:func:`_template`, :func:`_launch_directory`,
    ``_detect_host_from_config``). A member keeps its own name: the client reads every
    file of the suffix.
    """
    parts = list(path.parts)
    folded = [fold_name(part) for part in parts]
    name = _FOLDED_CONFIG_NAMES.get(folded[-1])
    for template, spelling, members in _FOLDED_TEMPLATES:
        size = len(template)
        if members:
            if (
                size < len(parts)
                and tuple(folded[-size - 1 : -1]) == template
                and folded[-1].endswith(members)
            ):
                parts[-size - 1 : -1] = spelling
                break
        elif size <= len(parts) and tuple(folded[-size:]) == template:
            parts[-size:] = spelling
            break
    else:
        if name is None:
            return None
        parts[-1] = name
        index = len(parts) - 1
        while index > 0 and (host := _FOLDED_HOST_DIRECTORIES.get(folded[index - 1])):
            index -= 1
            parts[index] = host
    if parts[-1] not in _CLIENTS_BY_NAME:
        for index, part in enumerate(folded[:-1]):
            if (host := _FOLDED_HOST_DIRECTORIES.get(part)) is not None:
                parts[index] = host
    return "/".join(parts)


def _directory_gap(path: Path) -> bool:
    """Whether the walked ``path``, which names no client file, is a gap below a server
    directory: a file of a suffix the client may read, deeper than the directory or of
    a suffix the collector does not read there, in any spelling of the directory."""
    name = path.name.lower()
    folded = tuple(fold_name(part) for part in path.parts[:-1])
    return any(
        name.endswith(dialect.member_gaps) and folded[start : start + len(template)] == template
        for template, dialect in _DIRECTORY_DIALECTS.items()
        for start in range(len(folded) - len(template) + 1)
    )


def _directory_members(
    files: ConfinedCollection, directory: Path, dialect: McpDialect
) -> tuple[list[Path], list[Path]]:
    """The files a client reads in a linked server ``directory``, and the gaps below it.

    The walk lists a linked directory under its target's name, so each file is named
    back under the link, through which the read follows one symlink.
    """
    found: list[Path] = []
    gaps: list[Path] = []
    target = Path(files.link_target(directory) or directory)
    for path in files.iter_files(directory):
        try:
            relative = path.relative_to(target)
        except ValueError:
            continue
        if len(relative.parts) == 1 and fold_name(relative.name).endswith(dialect.members):
            found.append(directory / relative)
        elif relative.name.lower().endswith(dialect.member_gaps):
            gaps.append(directory / relative)
    return found, gaps


def _linked_client_files(
    files: ConfinedCollection, links: list[Path]
) -> tuple[list[Path], list[Path]]:
    """Client files a host opens through a directory symlink that the walk met, and the
    gaps below a linked server directory.

    The walk covers a linked directory under its target's name, where a path such as
    ``pkg/.gemini/settings.json`` names no client file, so each one is looked up
    through the link: the rest of every client path whose leading directories the
    link's name ends, every client name below a linked host directory, and the members
    of a server directory the link is or holds.
    """
    found: list[Path] = []
    gaps: list[Path] = []
    for link in links:
        folded = tuple(fold_name(part) for part in link.parts)
        candidates: dict[Path, McpDialect | None] = {}
        if folded[-1] in _FOLDED_HOST_DIRECTORIES:
            candidates.update((link / name, None) for name in MCP_CONFIG_NAMES)
        for template, spelling, members in _FOLDED_TEMPLATES:
            for size in range(1, len(template) + (1 if members else 0)):
                if folded[-size:] == template[:size]:
                    candidates[link.joinpath(*spelling[size:])] = (
                        _DIRECTORY_DIALECTS[template] if members else None
                    )
        for path, directory in sorted(candidates.items(), key=lambda item: item[0]):
            if directory is not None:
                if files.is_directory(path):
                    files_found, files_gaps = _directory_members(files, path, directory)
                    found.extend(files_found)
                    gaps.extend(files_gaps)
                    continue
            elif files.regular_file(path) is not None:
                found.append(path)
                continue
            # Records a refused link, or another spelling below the link.
            files.read_bytes(path, missing_ok=True)
    return found, gaps


def _is_dialect_file(dialect: McpDialect, path: str) -> bool:
    """Whether ``path`` is the dialect's file, or a member of its directory, at the root
    or below it."""
    if dialect.members:
        path, _, name = path.rpartition("/")
        if not fold_name(name).endswith(dialect.members):
            return False
    return path == dialect.path or path.endswith("/" + dialect.path)


def _template(path: str) -> McpDialect | None:
    """The dialect whose file ``path`` is, at the root or below it; the longest match wins."""
    matches = [dialect for dialect in MCP_DIALECTS if _is_dialect_file(dialect, path)]
    return max(matches, key=lambda dialect: len(dialect.path)) if matches else None


def _dialect(path: str) -> McpDialect:
    """How to read the client file at ``path``, a root dialect or one of its nested copies.

    A nested copy of a dialect's file (``packages/api/.vscode/mcp.json``) is read as
    that dialect; any other configuration name is a generic server map.
    """
    template = _template(path)
    return (
        McpDialect(path, "json", _SERVER_MAPS) if template is None else replace(template, path=path)
    )


def _launch_directory(path: str) -> str:
    """The directory, relative to the root, that a client starts the file's servers in.

    A root dialect file's servers start at the root; a nested copy's start where it
    is, as Claude Code and VS Code start them in the directory they were opened in.
    A client directory such as ``.windsurf`` names no project directory of its own.
    """
    template = _template(path)
    if template is not None:
        if template.members:
            path = path.rpartition("/")[0]
        return path[: -len(template.path)].rstrip("/")
    parts = path.split("/")[:-1]
    while parts and parts[-1] in _HOST_DIRECTORIES:
        parts.pop()
    return "/".join(parts)


_SPACE = re.compile(r"\s*")
# Gemini CLI splits a server command with shell-quote, which also substitutes
# environment variables, expands globs and reads quotes and operators; only words
# whose split cannot depend on that are inventoried.
_PLAIN_COMMAND = re.compile(r"[A-Za-z0-9_@%+=:,./-]+(?:[ \t]+[A-Za-z0-9_@%+=:,./-]+)*")
_CAMEL_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")
# Fixed width on purpose: "HTTPServer" splits before the capital that starts "Server".
_ACRONYM_BOUNDARY = re.compile(r"([A-Z])([A-Z][a-z])")
_WORD = re.compile(r"[a-z0-9]+")
_WORD_ENDINGS = ("s", "es", "ed", "d", "ing")


_JS_INTERESTING = re.compile(r"""["'`\n]|/[/*]""")


def _without_js_comments_quoted(text: str) -> str:
    kept: list[str] = []
    size = len(text)
    emitted = pos = 0
    ws_start: int | None = 0
    no_more_blocks = False
    while pos < size:
        if ws_start is not None:
            indent = _SPACE.match(text, pos)
            if indent:
                pos = indent.end()
                if pos >= size:
                    break
        ch = text[pos]
        if ch in "\"'`":
            ws_start = None
            end = pos + 1
            terminators = ("`",) if ch == "`" else (ch, "\n", "\r")
            while end < size and text[end] not in terminators:
                end += 2 if text[end] == "\\" else 1
            if end < size and text[end] == ch:
                end += 1
            pos = end
            continue
        if ch == "/":
            if text.startswith("//", pos):
                newline = text.find("\n", pos + 2)
                stop = size if newline < 0 else newline
                if ws_start is not None:
                    kept.append(text[emitted:ws_start])
                    emitted = stop
                pos = stop
                ws_start = None
                continue
            if not no_more_blocks and text.startswith("/*", pos):
                close = text.find("*/", pos + 2)
                if close < 0:
                    no_more_blocks = True
                else:
                    kept.append(text[emitted:pos])
                    emitted = pos = close + 2
                    ws_start = None
                    continue
        if ch == "\n":
            pos += 1
            ws_start = pos
            continue
        ws_start = None
        nxt = _JS_INTERESTING.search(text, pos + 1)
        pos = size if nxt is None else nxt.start()
    kept.append(text[emitted:])
    return "".join(kept)


def without_js_comments(text: str) -> str:
    """Drop block comments and whole-line ``//`` comments in one linear pass.

    The pattern this replaces rescanned every run of blank lines from each of its
    lines, so a file of newlines within the size limit took minutes.
    """
    if "/*" not in text and "//" not in text:
        return text
    if any(q in text for q in ('"', "'", "`")):
        return _without_js_comments_quoted(text)
    kept: list[str] = []
    size = len(text)
    emitted = position = line_from = 0
    block = text.find("/*")
    close = -1
    line: tuple[int, int] | None = None
    while position < size:
        if 0 <= block < position:
            block = text.find("/*", position)
        # The first "*/" after an earlier opener is also the first after a later one
        # that precedes it, so each stretch of text is searched for a close only once.
        if block >= 0 and close < block + 2:
            close = text.find("*/", block + 2)
            if close < 0:
                block = -1
        if line is None or line[0] < position:
            line = None
            start = max(position, line_from)
            if start and text[start - 1] != "\n":
                newline = text.find("\n", start)
                start = size if newline < 0 else newline + 1
            while start < size:
                indent = _SPACE.match(text, start)
                content = indent.end() if indent else start
                newline = text.find("\n", content)
                if text.startswith("//", content):
                    line = (start, size if newline < 0 else newline)
                    break
                start = size if newline < 0 else newline + 1
            line_from = start
        if block >= 0 and (line is None or block <= line[0]):
            begin, end = block, close + 2
        elif line is not None:
            begin, end = line
        else:
            break
        kept.append(text[emitted:begin])
        emitted = position = end
        if end == begin:
            position += 1
    kept.append(text[emitted:])
    return "".join(kept)


@dataclass(frozen=True)
class _Normalized:
    """A server in the common form, the reason its launcher is unknown, and a problem
    that refuses it; the form is as complete as the shape allows either way, so the
    file's credential values are scrubbed even from a refused server."""

    config: dict[str, Any]
    unknown: str | None = None
    problem: str | None = None


@dataclass(frozen=True)
class _Entries:
    """One file's servers by name, with the problems and unknown launchers of its shape,
    and the entries its shape drops before naming them, whose credential values the
    file's servers may still repeat."""

    servers: list[tuple[str, Any]]
    problems: dict[str, str]
    unknown: dict[str, str]
    dropped: tuple[Any, ...] = ()


_INVALID_SERVER = "invalid server configuration"
# Zed's ``settings`` object under a name of its own, so the field stays one the
# collector does not interpret in every other client's file.
_EXTENSION_SETTINGS = "settings (zed extension)"
# opencode's ``"oauth": false``, which turns off OAuth detection for a remote server.
_OAUTH_DISABLED = "oauth (disabled)"
# Fields a client's own shape is read into, uninterpreted in any other client's file.
_SHAPE_FIELDS = {_EXTENSION_SETTINGS: "zed", _OAUTH_DISABLED: "opencode"}
_DECLARED_FIELDS = {_EXTENSION_SETTINGS: "settings", _OAUTH_DISABLED: "oauth"}


def _interpreted(field: str, shape: str) -> bool:
    """Whether ``field`` may be read in a file of ``shape``: a shape's own field is not
    read in another client's file, where it stays a field the collector does not
    interpret."""
    return _SHAPE_FIELDS.get(field, shape) == shape


_ZED_EXTENSION = "provided by a Zed extension; the client file holds no launch"
_NO_LAUNCH = "declares neither a command nor an endpoint; the client file holds no launch"
# Fields that mark a Continue server file whose top level is a server, a shape the
# collector does not confirm, rather than a block holding a server list.
_SERVER_FIELDS = ("command", "args", "url", "type")


def _zed_server(config: dict[str, Any]) -> _Normalized:
    """Zed's ``context_servers`` entry in the common form.

    Older settings nest the launch as ``{"command": {"path", "args", "env"}}``; newer
    ones declare it beside ``"source": "custom"``. A ``"source": "extension"`` entry,
    and an entry with no source and neither a command nor an endpoint, is a server the
    editor's extension starts from its own code, so its launcher is unknown and its
    ``settings`` are the extension's, scrubbed as environment values are; a custom
    entry without a launch holds none, as in any other client file. Zed reads ``env``
    as optional, so a null one is absent.
    """
    config = {key: value for key, value in config.items() if key != "env" or value is not None}
    problem = _INVALID_SERVER if _EXTENSION_SETTINGS in config else None
    if "settings" in config:
        config[_EXTENSION_SETTINGS] = config.pop("settings")
    source = config.get("source")
    if source in ("custom", "extension"):
        del config["source"]
    command = config.get("command")
    if isinstance(command, dict):
        config["command"] = command.get("path")
        for key, value in command.items():
            if key == "path" or (key == "env" and value is None):
                continue
            if key in ("args", "env"):
                if key in config:
                    problem = f"MCP server declares {key} both in and beside its command object"
                    config[f"command.{key}"] = value
                else:
                    config[key] = value
            else:
                config[f"command.{key}"] = value
    launched = bool(config.get("command")) or any(config.get(field) for field in _ENDPOINT_FIELDS)
    unknown = _ZED_EXTENSION if source == "extension" or (source is None and not launched) else None
    if source == "extension" and launched:
        problem = "MCP server declares a launch beside an extension source"
    return _Normalized(config, unknown, problem)


# opencode replaces {env:NAME} and {file:PATH} in its configuration text when it loads it.
_OPENCODE_SUBSTITUTION = re.compile(r"(?<!\$)\{((?:env|file):[^}]+)\}")


def _opencode_text(value: Any) -> Any:
    """``value`` with each opencode substitution spelled as the reference ``${...}``,
    which every reader treats as unresolved; other values are returned unchanged."""
    if not isinstance(value, str):
        return value
    # Past the last closing brace nothing can match, and an opening there would scan
    # to the end of the text, so a run of unclosed openings would read in quadratic time.
    end = value.rfind("}") + 1
    return _OPENCODE_SUBSTITUTION.sub(r"${\1}", value[:end]) + value[end:]


_OPENCODE_OPENING = re.compile(r"\{(?:env|file):")
_JSONC_TOKEN = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"|//[^\n]*|/\*.*?\*/', re.S)
_JSONC_SPACE = re.compile(r"(?:\s+|//[^\n]*|/\*.*?\*/)*", re.S)


def _opencode_substitution_outside_values(text: str) -> bool:
    """Whether opencode, which substitutes in the raw text of a parsed JSONC file, may
    replace text that is not inside one string value: an opening ``{env:`` or ``{file:``
    in a comment or a key, or one whose closing brace is not in the same string.

    Such a substitution can join, split or add the strings the per-value reading sees.
    """
    openings = [match.start() for match in _OPENCODE_OPENING.finditer(text)]
    # opencode reads the raw text, so an escape such as a JSON unicode escape for the
    # closing brace names a different variable from the decoded value we read.
    escapes = [match.start() for match in re.finditer(r"\\", text)]
    index = 0
    close = -1
    for token in _JSONC_TOKEN.finditer(text):
        if index == len(openings):
            return False
        start, end = token.span()
        if openings[index] < start:
            return True
        if openings[index] >= end:
            continue
        gap = _JSONC_SPACE.match(text, end)
        if text[start] != '"' or (gap is not None and text.startswith(":", gap.end())):
            return True
        while index < len(openings) and openings[index] < end:
            if close < openings[index]:
                close = text.find("}", openings[index])
            if not openings[index] < close < end - 1:
                return True
            escape = bisect.bisect_left(escapes, openings[index])
            if escape < len(escapes) and escapes[escape] < close:
                return True
            index += 1
    return index < len(openings)


def _opencode_server(config: dict[str, Any]) -> _Normalized:
    """opencode's ``mcp`` entry in the common form.

    A local server's ``command`` is a list of words and its environment is
    ``environment``; a remote server's ``type`` is ``remote``, whose transport the
    endpoint decides, as for a client file that declares none, and which is
    Streamable HTTP when it declares no endpoint. A substitution in a
    value, or in a word or value one level below, is an unresolved reference.
    """
    config = {
        key: (
            [_opencode_text(item) for item in value]
            if isinstance(value, list)
            else {name: _opencode_text(item) for name, item in value.items()}
            if isinstance(value, dict)
            else _opencode_text(value)
        )
        for key, value in config.items()
    }
    problem = _INVALID_SERVER if _OAUTH_DISABLED in config else None
    if config.get("oauth") is False:
        del config["oauth"]
        config[_OAUTH_DISABLED] = True
    command = config.get("command")
    if isinstance(command, list):
        if not command or not all(isinstance(word, str) for word in command):
            # Keep the refused words for sibling redaction. Validation rejects the list.
            problem = _INVALID_SERVER
        else:
            config["command"] = command[0]
            if "args" in config:
                problem = "MCP server declares args beside a command list"
                if command[1:]:
                    config["command.args"] = command[1:]
            else:
                config["args"] = command[1:]
    if "environment" in config:
        if "env" in config:
            problem = "MCP server declares both environment and env"
        else:
            config["env"] = config.pop("environment")
    if config.get("type") == "remote":
        if any(field in config for field in _ENDPOINT_FIELDS):
            del config["type"]
        else:
            # opencode starts no command for a remote server, so one without an endpoint
            # keeps a remote type and a command beside it reads as transport ambiguity.
            config["type"] = "streamable-http"
    return _Normalized(config, None, problem)


def _normalized_server(shape: str, config: dict[str, Any]) -> _Normalized:
    """``config`` read from the client's own ``shape`` into the common server form."""
    if shape == "zed":
        return _zed_server(config)
    if shape == "opencode":
        return _opencode_server(config)
    return _Normalized(config)


MAX_SERVERS_PER_FILE = 1000
# Credential values of all servers in one file, each scrubbed from every server's text.
MAX_SECRETS_PER_FILE = 4096
MAX_TOOLS_PER_SERVER = 1000
MAX_TOOLS_PER_FILE = 5000
MAX_ARGUMENTS = 1024
MAX_ENVIRONMENT = 256
MAX_HEADERS = 64
MAX_LIST_ENTRIES = 1000
MAX_TOOL_NODES = 20_000
MAX_TOOL_DEPTH = 64
MAX_FILE_NODES = 200_000
# These runners install the named package, then resolve its dependencies from the
# network at launch. An exact top-level version does not pin that tree.
_TRANSITIVE_RUNNERS = frozenset(
    {
        "npx",
        "npm exec",
        "bunx",
        "bun x",
        "pnpm dlx",
        "yarn dlx",
        "uvx",
        "uv tool run",
        "pipx run",
    }
)

# Exported bindings must not be computable from secret values: an unkeyed digest
# over credentials lets anyone holding the BOM confirm guesses offline. The
# structure digest covers only fields the inventory already exports in clear.
# Values are bound by an HMAC under an operator key that never enters the BOM.
# A change to either preimage requires a new profile and new test vectors.
STATIC_CONFIG_HASH_PROFILE = "nexus-symbiote/mcp-static-config/v4"
STATIC_VALUE_BINDING_PROFILE = "nexus-symbiote/mcp-static-values/v3"
SOURCE_BINDING_KEY_ENV = "NEXUS_SYMBIOTE_SOURCE_BINDING_KEY"
_MIN_SOURCE_BINDING_KEY_LENGTH = 32


def _names(words: str) -> frozenset[str]:
    return frozenset(words.split())


class SourceBindingKeyError(ValueError):
    """The operator's source binding key cannot be used; the message names the variable."""


def source_binding_key() -> bytes | None:
    """The operator key from the environment, validated once per collection."""
    key = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
    if not key:
        return None
    if len(key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
        raise SourceBindingKeyError(
            f"{SOURCE_BINDING_KEY_ENV} must contain at least "
            f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
        )
    try:
        return key.encode("utf-8")
    except UnicodeError:
        raise SourceBindingKeyError(f"{SOURCE_BINDING_KEY_ENV} must be valid UTF-8 text") from None


_HEADER_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_-]{1,63}")
_CLI_FLAG = re.compile(r"-{1,2}[A-Za-z][A-Za-z0-9_-]{0,63}")
_HEADER_FLAGS = frozenset({"-h", "--header"})
_HEADER_PREFIXES = ("--header=", "-h=")
# The character before a requirement's version (pkg==1.2, pkg>=1.2, pkg~=1.2, pkg!=1.2).
_REQUIREMENT_OPERATORS = frozenset("<>!~=")
# OAuth parameters that travel in clear (RFC 6749 and its extensions), compared without
# case, "-" or "_": identifiers that names may repeat, not credentials.
_PUBLIC_AUTH_FIELDS = _names(
    "type clientid scope scopes audience audiences resource granttype responsetype "
    "redirecturi issuer"
)
_TOOL_APPROVAL_FIELDS = ("alwaysAllow", "autoApprove")
_TOOL_FILTER_FIELDS = (
    "includeTools",
    "excludeTools",
    "enabled_tools",
    "disabled_tools",
    "disabledTools",
)
_TOOL_LIST_FIELDS = (*_TOOL_APPROVAL_FIELDS, *_TOOL_FILTER_FIELDS)


def _scheme_secrets(value: str) -> list[str]:
    """``value`` and its bare credential when it is an auth scheme word and a credential."""
    credentials = scheme_credentials(value)
    if credentials and len(value) >= MIN_SECRET_LENGTH:
        return [value, *credentials]
    return credentials


def _shape_secrets(value: str) -> list[str]:
    """Credentials a value holds by its shape, whatever names it."""
    return [
        *_scheme_secrets(value),
        *(match.group() for match in TOKEN_SHAPE.finditer(value)),
        *private_key_forms(value),
        *_header_line_secrets(value),
        *_url_secrets(value),
    ]


def _url_secrets(value: str) -> list[str]:
    """Credentials in URL user information or in credential-named query parameters.

    A password counts on its own only when it reads as a credential, so the default
    ``postgres:postgres`` is not taken out of a server named ``postgres``; a user name
    without a password counts only in a known token format (``https://ghp_...@host``).
    The whole value is still scrubbed wherever its name or user information marks it.
    """
    found: list[str] = []
    for locator in _locators(value):
        try:
            parsed = urlsplit(locator)
            password, username = parsed.password, parsed.username
        except ValueError:
            # Malformed URLs contribute no parsed userinfo or query fields.
            continue
        if password is not None:
            found.extend(
                candidate
                for candidate in dict.fromkeys((password, unquote(password)))
                if len(candidate) >= MIN_SECRET_LENGTH
                and credential_shaped(candidate)
                and not is_reference(candidate)
            )
        if username is not None:
            for candidate in dict.fromkeys((username, unquote(username))):
                found.extend(match.group() for match in TOKEN_SHAPE.finditer(candidate))
        for query_name, query_value in parse_qsl(parsed.query.replace(";", "&")):
            if not is_reference(query_value):
                if secret_like(query_name, query_value):
                    found.append(query_value)
                found.extend(scheme_credentials(query_value))
    return found


def _header_line(text: str) -> tuple[str, str] | None:
    """The name and value of an inline ``Header-Name: value`` string, or None."""
    candidate = text.strip()
    lowered = candidate.lower()
    for prefix in _HEADER_PREFIXES:
        if lowered.startswith(prefix):
            candidate = candidate[len(prefix) :].strip()
            break
    else:
        if candidate.startswith("-H") and len(candidate) > 2 and not candidate.startswith("-H="):
            candidate = candidate[2:].strip()
    if ":" not in candidate:
        return None
    hdr_name, _, hdr_val = candidate.partition(":")
    hdr_name = hdr_name.strip(" \"'")
    if hdr_val.startswith("//") or not _HEADER_NAME.fullmatch(hdr_name):
        return None
    hdr_val = hdr_val.strip(" \"'")
    return (hdr_name, hdr_val) if hdr_val else None


def _header_line_secrets(text: str) -> list[str]:
    """Credentials in an inline ``Header-Name: value`` string such as ``Authorization: Bearer ...``."""
    header = _header_line(text)
    if header is None:
        return []
    hdr_name, hdr_val = header
    if is_reference(hdr_val):
        return []
    found: list[str] = []
    if secret_like(hdr_name, hdr_val):
        found.append(hdr_val)
    found.extend(_scheme_secrets(hdr_val))
    found.extend(_url_secrets(hdr_val))
    return found


def _auth_object_secrets(settings: dict[str, Any]) -> list[str]:
    """Credentials an ``oauth`` or ``auth`` object declares, at any depth.

    The field names a credential, so each string in it counts as the value of a
    variable named ``AUTH`` would, under any key (``value``, ``credentials.value``),
    except the OAuth parameters that travel in clear. _server_problem bounds the
    object, so every node is read.
    """
    found: list[str] = []
    pending: list[tuple[str, Any]] = [("", settings)]
    while pending:
        key, current = pending.pop()
        if isinstance(current, str):
            public = key.replace("-", "").replace("_", "").lower() in _PUBLIC_AUTH_FIELDS
            if not is_reference(current) and secret_like(key if public else "auth", current):
                found.append(current)
            found.extend(_shape_secrets(current))
        elif isinstance(current, dict):
            pending.extend((str(name), item) for name, item in current.items())
        elif isinstance(current, list):
            pending.extend((key, item) for item in current)
    return found


def _settings_secrets(settings: dict[str, Any]) -> list[str]:
    """Credentials an object such as a Zed extension's ``settings`` holds, at any depth.

    Each string is read as the value of the key that names it, as an environment
    value is, and by its shape. _server_problem bounds an extension's object, and the
    file's size and parse depth bound a shape's credential fields, so every node is read.
    """
    found: list[str] = []
    pending: list[tuple[str, Any]] = [("", settings)]
    while pending:
        key, current = pending.pop()
        if isinstance(current, str):
            if not is_reference(current) and secret_like(key, current):
                found.append(current)
            found.extend(_shape_secrets(current))
        elif isinstance(current, dict):
            pending.extend((str(name), item) for name, item in current.items())
        elif isinstance(current, list):
            pending.extend((key, item) for item in current)
    return found


# Credential fields of a client's own shape that the collector does not interpret: a
# refused opencode server's environment beside env, and Continue's apiKey, request
# options and hub block inputs. Their values are scrubbed from every server of the file
# all the same.
_SHAPE_CREDENTIALS = {
    "zed": ("command.env", "command.args"),
    "opencode": ("environment", "command.args"),
    "continue": ("apiKey", "requestOptions", "with"),
}


def _shape_credentials(config: dict[str, Any], shape: str) -> list[str]:
    """Credential values ``config`` holds in its shape's uninterpreted credential fields."""
    found: list[str] = []
    fields: dict[str, Any] = {}
    for field in _SHAPE_CREDENTIALS.get(shape, ()):
        if field not in config:
            continue
        if field in {"command.args", "command.env"}:
            found.extend(_malformed_values(config[field], field))
        else:
            fields[field] = config[field]
    if fields:
        found.extend(_settings_secrets(fields))
    return found


def _launch_words(texts: Iterable[str]) -> list[str]:
    """Each text and, when it holds white space (a command line, an inline script), its words.

    Words also end at the shell and cmd operators ``&&``, ``;`` and ``|``, so cmd's
    ``set API_TOKEN=Bearer <token>&& npx ...`` leaves the token as a word of its own.
    """
    words: list[str] = []
    for text in texts:
        words.append(text)
        if any(char.isspace() for char in text):
            lexer = shlex.shlex(text, posix=True, punctuation_chars=True)
            lexer.whitespace_split = True
            lexer.commenters = ""
            try:
                parts = list(lexer)
            except ValueError:
                # An unclosed quote still leaves the whitespace-delimited words.
                parts = text.split()
            words.extend(parts)
    return words


def _requirement(name: str, value: str) -> bool:
    """Whether ``name=value`` is a requirement such as ``pkg==1.2`` or ``pkg>=1.2``."""
    return not name.startswith("-") and (
        value.startswith("=") or name[-1:] in _REQUIREMENT_OPERATORS
    )


def _launch_secrets(launch: Launch, args: Sequence[str] = (), command: str = "") -> list[str]:
    # Earlier assignments remain private even when a later value shadows them.
    values: list[str] = []
    for name, value in launch.environment:
        if secret_like(name, value):
            values.append(value)
        values.extend(_shape_secrets(value))
    for _, source_value in launch.sources:
        values.extend(_url_secrets(source_value))
    cmd = bool(command) and posixpath.basename(command.replace("\\", "/")).casefold() in {
        "cmd",
        "cmd.exe",
    }
    # Each text is split once here: its own words are also the ones a pairing is read from.
    arguments = [_launch_words([a]) for a in args if isinstance(a, str)]
    words = [*(_launch_words([command]) if command else []), *chain.from_iterable(arguments)]
    for _, *inner in arguments:
        values.extend(_withheld_scheme_operands(inner, cmd=cmd))
    for index, word in enumerate(words):
        values.extend(_shape_secrets(word))
        following = words[index + 1] if index + 1 < len(words) else None
        in_set = False
        if cmd and following is not None:
            prev = words[index - 1] if index > 0 else None
            raw_before = words[index - 2] if index > 1 else None
            before = (
                None
                if raw_before is not None and any(c.isspace() for c in raw_before)
                else raw_before
            )
            in_set = _cmd_set_word(prev, before)
        name, equals, value = word.partition("=")
        if equals and not _requirement(name, value):
            name = name.lstrip("-").strip(" \"'")
            value = value.strip(" \"'")
            if name and value and not is_reference(value):
                if name.lower() not in {"h", "header"} and secret_like(name, value):
                    values.append(value)
                values.extend(_shape_secrets(value))
                # cmd's `set API_TOKEN=Bearer <token>` leaves the credential in the next word.
                if following is not None and secret_like(name, f"{value} {following}"):
                    variable = not word.startswith("-")
                    if value.lower() in _ASSIGNMENT_SCHEMES:
                        values.extend(
                            literal
                            for _, literal in _assignment_word_hits(word, following, in_set=in_set)
                        )
                    elif _scheme_assignment_name(name, variable=variable):
                        values.extend(scheme_credentials(f"{value} {following}"))
                    # Withholding fails closed. The rules above choose what raises a
                    # finding; an operand they leave unflagged still stays out of exports
                    # unless it is positively a public launch word.
                    if not _public_scheme_following(
                        name, value, following, variable=variable, in_set=in_set
                    ):
                        values.extend(scheme_credentials(f"{value} {following}"))
        if index > 0:
            flag = words[index - 1]
            if (
                _CLI_FLAG.fullmatch(flag)
                and flag.lower() not in _HEADER_FLAGS
                and not word.startswith("-")
                and not is_reference(word)
                and secret_like(flag, word)
            ):
                values.append(word)
                values.extend(scheme_credentials(word))
    return list(dict.fromkeys(values))


# One finding lists this many positions and counts the rest; collection for one server
# stops at the larger bound, so the finding stays small however many values a file holds.
LISTED_CREDENTIAL_POSITIONS = 12
MAX_CREDENTIAL_POSITIONS = 64
_ENDPOINT_QUERY_POSITION = "endpoint URL query"
_ASSIGNMENT_FLAGS = frozenset({"env", "e", "build-arg"})
# The scheme words _AUTH reads, after which cmd's `set NAME=<scheme> <credential>` splits.
_ASSIGNMENT_SCHEMES = frozenset({"bearer", "basic", "token", "bot", "apikey", "api-key"})
_SCHEME_DESCRIPTORS = frozenset({"type", "mode", "scheme", "method", "transport", "strategy"})
_PUBLIC_TOKEN_SELECTORS = frozenset({"format", "source", "profile", "output", "kind"})
# These common switches can follow a credential binding in a launch declaration.
# Normalize spelling only for the comparison; exports keep the original text.
_PUBLIC_SCHEME_SWITCHES = _names(
    "transport stateless privileged verbose readonly dryrun version debug help quiet "
    "interactive stdio json enablelogging color nocolor noprompt watch force loglevel "
    "allowhttp insecure noprofile outputformat noninteractive headless detached sandboxed "
    "production telemetry recursive localhost maxconcurrentrequests enableautomaticupdates"
)
_LOWER_LONG_OPTION = re.compile(r"--[a-z][a-z0-9]*(?:-[a-z0-9]+)*")
_LOWER_CLI_DIGIT_SEGMENT = re.compile(r"(?:[a-z]{1,10}[0-9]{1,3}|[a-z][0-9]{1,2}[a-z])")
_CAMEL_SWITCH = re.compile(r"[A-Za-z][a-z]+(?:[A-Z][a-z]+)+")
_CLI_ACRONYMS = (
    r"(?:HTTPS|HTTP[23]|HTTP|TLS1[23]|TLS|MTLS|SSL|SSH|URL|URI|JSONL|JSON|YAML|TOML|XML|CSV|"
    r"SQL|SSE|MCP|GRPC|RPC|REST|API|SDK|CLI|TTY|ANSI|UTF16|UTF8|UTF|DNS|TCP|UDP|IPC|PID|"
    r"CORS|CSRF|OIDC|SAML|JWKS|JWK|JWT|PEM|DER|AWS|GCP|IAM|KMS|HSM|IP[Vv][46]|IP|IO|FS|DB|UI|"
    r"OS|CA|SNI|ALPN|UUID|ID|EOF|HTML|DOM|WASM|GPU|CPU|RAM|LLM|RAG|A2A|SBOM|VEX|OAuth2|OAuth)"
)
_ACRONYM_CLI_SWITCH = re.compile(
    rf"(?:[a-z]{{2,}}(?:[A-Z][a-z]+)*{_CLI_ACRONYMS}(?:[A-Z][a-z]+)*"
    rf"|{_CLI_ACRONYMS}(?:[A-Z][a-z]+)+)"
)
# A short public version or date label after a mode selector (e.g. Workspace2,
# Workspace10, WorkspaceV2, OpenAPI3, OpenAPI3.1, 20250618). Mixed-case tokens
# or random alphanumeric runs stay private.
_MODE_LABEL = re.compile(
    r"(?:(?:[A-Z][a-z]{2,10}|OpenAPI|OAuth|HTTP|TLS|SAML|OIDC|GraphQL|JSON|YAML|GRPC)"
    r"[Vv]?[0-9]{1,2}(?:\.[0-9]{1,2})?|[0-9]{8})"
)
_BENIGN_ENV_KEY = re.compile(r"[A-Z]{2,15}(?:_[A-Z0-9]{1,15}){0,4}")
_PUBLIC_UUID = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)
_RELEASE_VERSION_SEGMENT = re.compile(r"[0-9]{1,2}(?:\.[0-9]{1,2})?[a-z]?|(?:19|20)[0-9]{2}")
_SCHEME_NUMBER = re.compile(r"[+]?[0-9]+(?:[.][0-9]+)?")
_SCHEME_ASSIGNMENT_OPERAND = re.compile(r"[A-Za-z0-9_-]+=[A-Za-z0-9_+=-]+")
# curl's `-u user:password`, also in a cluster of short flags (`-su`), and httpie's `-a`
# (`--auth`) only under a fetcher. Under another command (docker -u www-data:www-data) the
# part after the colon counts only when it reads as a literal under a non-password name.
_USER_FLAG = re.compile(r"--user|--auth|-a|-[A-Za-z]{0,4}u")
_FETCHERS = frozenset({"curl", "wget", "http", "https", "httpie"})
# Words of letters, or capitals and digits in a name with a capital: GH_TOKEN_2, not oauth2-x.
_NAME_FORM = re.compile(
    r"(?=.*[A-Z]|\D*\Z)(?:[A-Za-z]+|[A-Z][A-Z0-9]*)"
    r"(?:[._-](?:[A-Za-z]+|[A-Z0-9]+))*"
)
_PLAIN_ASSIGNMENT = re.compile(r"-{0,2}[A-Za-z_][\w.-]{0,63}=[^,;\"'&|:]*")
# Past this length an argument's words are split at white space only: shell quoting is
# read one character at a time, and its cost grows faster than the argument.
_SHELL_SPLIT_LIMIT = 65536


def _header_line_hits(text: str, *, explicit: bool) -> list[Hit]:
    """The hits of ``text`` read as an inline ``Header-Name: value`` line.

    Prose such as ``Authentication: handled by the gateway`` reads like one, so a
    text is a header line only after ``-H`` or ``--header`` or when the header name
    itself names a credential (Authorization, Cookie, X-Api-Key).
    """
    header = _header_line(text)
    if header is None or not (explicit or credential_name(header[0])):
        return []
    return value_hits(*header, header=True)


def _explicit_header(previous: str | None, word: str) -> bool:
    """Whether ``word`` is a header by its flag: after ``-H``, or ``--header=`` or ``-H``."""
    stripped = word.strip()
    return (
        (previous is not None and previous.lower() in _HEADER_FLAGS)
        or stripped.lower().startswith(_HEADER_PREFIXES)
        or (stripped.startswith("-H") and len(stripped) > 2)
    )


_SCHEME_AUTH_WORDS = frozenset(
    {
        "auth",
        "authorization",
        "authentication",
        "authz",
        "oauth",
        "bearer",
        "bot",
        "conn",
        "session",
    }
)

_SchemeAssignmentKind = Literal["credential_binding", "mode_selector", "public_selector"]


def _scheme_assignment_name(name: str, *, variable: bool = True) -> bool:
    words = name_words(name)
    if not words or words[-1] in _SCHEME_DESCRIPTORS:
        return False
    # CLI flags such as --auth=token, --authentication=bearer, and --auth-header=bearer
    # select an authentication mode or header rather than binding a credential in the next arg.
    if not variable and (
        words[-1] == "header"
        or words[-1] in _PUBLIC_TOKEN_SELECTORS
        or tuple(words) in {("auth",), ("authentication",)}
    ):
        return False
    return (
        credential_name(name)
        or words[-1] in _SCHEME_AUTH_WORDS
        or (words[-1] == "header" and not _SCHEME_AUTH_WORDS.isdisjoint(words[:-1]))
    )


def _classify_scheme_assignment(
    name: str, scheme: str, *, variable: bool, in_set: bool
) -> _SchemeAssignmentKind:
    """Distinguish a credential binding from an authentication-mode or public selector."""
    if in_set or _scheme_assignment_name(name, variable=variable):
        return "credential_binding"
    words = name_words(name)
    if (
        not variable
        and scheme.lower() == "token"
        and words
        and words[-1] in _PUBLIC_TOKEN_SELECTORS
        and not credential_name(name)
        and not any(credential_name(word) for word in words[:-1])
        and _SCHEME_AUTH_WORDS.isdisjoint(words[:-1])
    ):
        return "public_selector"
    return "mode_selector"


def _is_valid_iso_date(digits: str) -> bool:
    if len(digits) != 8 or not digits.isdecimal():
        return False
    try:
        date.fromisoformat(digits)
    except ValueError:
        return False
    return True


def _public_mode_label(word: str) -> bool:
    """Whether ``word`` is a short public version or ISO date label after a mode selector."""
    if len(word) > 12 or _MODE_LABEL.fullmatch(word) is None:
        return False
    return _is_valid_iso_date(word) if word.isdecimal() else True


def _public_release_identifier(value: str) -> bool:
    """Whether ``value`` is a structured model or release identifier (e.g. claude-sonnet-4-20250514)."""
    if len(value) >= 48 or "-" not in value or not value.isascii():
        return False
    segments = value.split("-")
    if not (2 <= len(segments) <= 6):
        return False
    has_word = False
    for segment in segments:
        if not segment or len(segment) > 15:
            return False
        if segment.isalpha() and segment.islower():
            if len(segment) >= 3:
                has_word = True
            continue
        if _RELEASE_VERSION_SEGMENT.fullmatch(segment) or _is_valid_iso_date(segment):
            continue
        return False
    return has_word


def _benign_delimited_option(segments: list[str]) -> bool:
    """Whether lowercase segments of a ``--foo-bar`` or ``--foo_bar`` option are normal CLI words."""
    digit_segments = 0
    has_word = False
    for segment in segments:
        if not segment:
            return False
        if segment.isalpha() and segment.islower():
            if len(segment) >= 2:
                has_word = True
            continue
        if _LOWER_CLI_DIGIT_SEGMENT.fullmatch(segment):
            digit_segments += 1
            if digit_segments > 1:
                return False
            continue
        return False
    return has_word


def _benign_cli_option_name(key: str, body: str, *, bare: bool) -> bool:
    """Whether ``--<body>`` reads as an ordinary CLI option name rather than an opaque secret."""
    if not (2 <= len(body) < 32) or not body.isascii():
        return False
    if "-" in body:
        if "_" in body or _LOWER_LONG_OPTION.fullmatch(key) is None:
            return False
        return _benign_delimited_option(body.split("-"))
    if "_" in body:
        max_len = 16 if bare else 24
        if len(body) >= max_len or not body.islower():
            return False
        return _benign_delimited_option(body.split("_"))
    if _ACRONYM_CLI_SWITCH.fullmatch(body):
        return True
    if body.isalpha():
        if _CAMEL_SWITCH.fullmatch(body):
            return True
        if len(body) < 16 and (body.islower() or (body[0].isupper() and body[1:].islower())):
            return True
    return False


def _benign_env_assignment_after_selector(key: str, argument: str) -> bool:
    """Whether ``KEY=value`` after a mode selector is a separate non-credential env assignment."""
    if (
        not (3 <= len(key) < 32)
        or _BENIGN_ENV_KEY.fullmatch(key) is None
        or credential_name(key)
        or _scheme_assignment_name(key, variable=True)
    ):
        return False
    return (
        not literal_value(argument)
        or _PUBLIC_UUID.fullmatch(argument) is not None
        or _public_release_identifier(argument)
    )


_OperandKind = Literal["credential", "public", "unclassified"]


def _scheme_operand_kind(word: str, *, credential_binding: bool) -> _OperandKind:
    """How the argument following an authentication scheme reads.

    ``credential`` may be the scheme's literal value and raises a finding. ``public`` is
    positively a launch word of its own: a known switch, an ordinary option or setting,
    a label. ``unclassified`` is neither. It raises no finding, but an unfamiliar, weak
    or placeholder shape is not evidence that a value is public, so it stays out of
    exports wherever the scheme rule withholds it.
    """
    if len(word) < MIN_SECRET_LENGTH or is_reference(word):
        return "public"
    key, equals, argument = word.partition("=")
    if word.startswith("--") and _CLI_FLAG.fullmatch(key):
        body = key[2:]
        if equals and argument not in {"", "="}:
            if not credential_binding and _benign_cli_option_name(key, body, bare=False):
                # Separate CLI option (e.g. --model=..., --tenant-id=...); its own word
                # inspection still checks credential flag names and embedded token shapes.
                return "public"
            return (
                "credential" if literal_value(body) or literal_value(argument) else "unclassified"
            )
        if (
            not equals
            and body.casefold().replace("-", "").replace("_", "") in _PUBLIC_SCHEME_SWITCHES
        ):
            return "public"
        if equals:
            if len(body) < MIN_SECRET_LENGTH:
                return "public" if argument == "" else "unclassified"
            if argument == "=":
                return "credential"
            if not credential_binding and _benign_cli_option_name(key, body, bare=True):
                return "public"
            return "credential" if "-" not in body or literal_value(body) else "unclassified"
        if len(body) < MIN_SECRET_LENGTH:
            return "public"
        if not credential_binding and _benign_cli_option_name(key, body, bare=True):
            return "public"
        return "unclassified" if placeholder(body) else "credential"
    # Padding belongs to the operand. Only a genuine option assignment has a
    # non-credential key and a nonempty value with no further equals sign.
    if (
        argument
        and "=" not in argument
        and _SCHEME_ASSIGNMENT_OPERAND.fullmatch(word)
        and not literal_value(key)
    ):
        if not credential_binding and _benign_env_assignment_after_selector(key, argument):
            return "public"
        return "credential" if literal_value(argument) else "unclassified"
    if _SCHEME_NUMBER.fullmatch(word):
        return "credential"
    if placeholder(word):
        # A launcher's own package (@example/server@1.0.0) holds a placeholder word too.
        return "public" if not credential_binding and public_value(word) else "unclassified"
    if word.isascii() and word.isalpha():
        if credential_binding or len(word) >= 16:
            return "credential"
        unusual_case = (
            any(char.isupper() for char in word[1:])
            and _CAMEL_SWITCH.fullmatch(word) is None
            and not word.isupper()
        )
        return "credential" if unusual_case else "public"
    if credential_binding:
        return "credential"
    if (
        word.isascii()
        and any(char.isupper() for char in word)
        and any(char.islower() for char in word)
        and any(char.isdigit() for char in word)
        and word.isalnum()
    ):
        return "credential"
    if literal_value(word):
        return "credential"
    return "public" if public_value(word) else "unclassified"


def _scheme_operand(word: str, *, credential_binding: bool) -> bool:
    """Whether the argument following an authentication scheme may be its literal value."""
    return _scheme_operand_kind(word, credential_binding=credential_binding) == "credential"


def _public_scheme_following(
    name: str, scheme: str, following: str, *, variable: bool, in_set: bool
) -> bool:
    """Whether the word after ``NAME=<scheme>`` is positively a public launch word.

    A variable whose name ends in ``header`` (``HEADER``, ``CUSTOM_HEADER``) holds a whole
    header value, so its operand is read as a binding's for withholding, whatever the
    finding rules call it. A flag of that name (``--auth-header=bearer``) selects a header
    mode, and a switch, an option, a setting, a label or a locator after it stays public;
    a bare word after it is withheld, since a mode name does not make one public.
    """
    words = name_words(name)
    header = bool(words) and words[-1] == "header"
    binding = (header and variable) or (
        _classify_scheme_assignment(name, scheme, variable=variable, in_set=in_set)
        == "credential_binding"
    )
    if not binding and _public_mode_label(following):
        return True
    if _scheme_operand_kind(following, credential_binding=binding) != "public":
        return False
    if not header or variable or binding:
        return True
    return (
        following.startswith("-")
        or "=" in following
        or _PUBLIC_UUID.fullmatch(following) is not None
        or public_value(following)
    )


def _assigned(word: str) -> tuple[str, str, bool] | None:
    """The name and value of a ``NAME=value`` word, and whether the name is a variable.

    ``--env=NAME=value`` and its kin name the variable inside the flag's value.
    """
    name, equals, value = word.partition("=")
    if not equals or _requirement(name, value):
        return None
    variable = not name.startswith("-")
    name = name.lstrip("-").strip(" \"'")
    if name.lower() in _ASSIGNMENT_FLAGS and "=" in value:
        variable = True
        name, _, value = value.strip(" \"'").partition("=")
        name = name.strip(" \"'")
        if _requirement(name, value):
            return None
    value = value.strip(" \"'")
    if not name or not value or name.lower() in {"h", "header"}:
        return None
    return name, value, variable


def _withheld_scheme_operands(words: Sequence[str], *, cmd: bool) -> Iterator[str]:
    """What the pairing rule reads after each ``NAME=<scheme>`` word of one command line.

    ``_assignment_word_hits`` narrows the pairing to operands that read as credentials,
    which decides the finding. Withholding fails closed: an operand it leaves unflagged
    stays out of exports unless it is positively a public launch word. ``words`` are the
    shell words of one argument, as ``_argument_hits`` pairs them.
    """
    for index in range(len(words) - 1):
        assigned = _assigned(words[index])
        if assigned is None:
            continue
        name, value, variable = assigned
        if value.lower() not in _ASSIGNMENT_SCHEMES:
            continue
        in_set = cmd and _cmd_set_word(
            words[index - 1] if index else None, words[index - 2] if index > 1 else None
        )
        following = words[index + 1]
        if not _public_scheme_following(name, value, following, variable=variable, in_set=in_set):
            yield from (literal for _, literal in value_hits(name, f"{value} {following}"))


def _assignment_word_hits(word: str, following: str | None, *, in_set: bool = False) -> list[Hit]:
    """The hits of a ``NAME=value`` word, ``--name=value`` and ``--env=NAME=value`` included.

    cmd's ``set API_TOKEN=Bearer <token>`` leaves the credential in the next word.
    """
    assigned = _assigned(word)
    if assigned is None:
        return []
    name, value, variable = assigned
    hits = value_hits(name, value)
    if following is None or value.lower() not in _ASSIGNMENT_SCHEMES:
        return hits
    kind = _classify_scheme_assignment(name, value, variable=variable, in_set=in_set)
    if kind == "public_selector":
        return hits
    if in_set:
        # cmd's SET takes the rest of the assignment, including a literal
        # spelled like an option. The lexer supplies operators as separate words.
        if (
            len(following) >= MIN_SECRET_LENGTH
            and re.fullmatch(r"[-A-Za-z0-9._~+/]+=*", following)
            and not placeholder(following)
            and not is_reference(following)
        ):
            hits.extend(value_hits(name, f"{value} {following}") or [(SCHEME_CLASS, following)])
            return hits
    credential_binding = kind == "credential_binding"
    # Only a mode selector can explain a short date or version label. An unfamiliar
    # switch or an ordinary alphabetic word can itself be a bearer credential.
    if not credential_binding and _public_mode_label(following):
        return hits
    if is_reference(following):
        hits.extend(value_hits(name if credential_binding else "token", following))
        return hits
    if _scheme_operand(following, credential_binding=credential_binding):
        paired = value_hits(name, f"{value} {following}")
        hits.extend(paired or [(SCHEME_CLASS, following)])
    return hits


def _flag_value(flag: str, word: str) -> bool:
    """Whether ``word`` is the value of a non-header ``flag`` such as ``--token``."""
    return (
        _CLI_FLAG.fullmatch(flag) is not None
        and flag.lower() not in _HEADER_FLAGS
        and not word.startswith("-")
    )


def _user_hits(previous: str | None, word: str, fetcher: bool) -> list[Hit]:
    """The password of ``-u user:password``."""
    if previous is None or _USER_FLAG.fullmatch(previous) is None:
        return []
    user, colon, password = word.partition(":")
    fetched = fetcher or not previous.endswith(("-a", "auth"))
    if not (user and colon and fetched and literal_value(password, password=fetcher)):
        return []
    return [(NAMED_CLASS, password)]


def _cmd_set_word(previous: str | None, before_previous: str | None) -> bool:
    """Whether the preceding word starts a SET command in a cmd command line."""
    return (
        previous is not None
        and previous.casefold() in {"set", "@set"}
        and (
            before_previous is None
            or before_previous.casefold() in {"/c", "/k", "&", "&&", "|", "||", "("}
        )
    )


def _word_hits(
    previous: str | None,
    word: str,
    following: str | None,
    fetcher: bool = False,
    *,
    in_set: bool = False,
) -> list[Hit]:
    """The hits of one argument or shell word, given the words around it."""
    flagged = previous is not None and _flag_value(previous, word)
    hits = value_hits(previous if flagged and previous else "", word)
    if ":" in word:
        hits.extend(_header_line_hits(word, explicit=_explicit_header(previous, word)))
    if "=" in word:
        hits.extend(_assignment_word_hits(word, following, in_set=in_set))
    if (":" in word or "=" in word) and _PLAIN_ASSIGNMENT.fullmatch(word) is None:
        hits.extend(assignment_hits(word))
    hits.extend(_user_hits(previous, word, fetcher))
    return hits


def _argument_hits(
    previous: str | None,
    argument: str,
    fetcher: bool = False,
    following: str | None = None,
    *,
    cmd: bool = False,
    before_previous: str | None = None,
) -> list[Hit]:
    """The hits of a launch argument.

    An argument without white space is one word, read with the argument before it as
    its flag and the one after it as the rest of ``NAME=<scheme>``. One with white space
    (a command line, an inline script) is read whole for what holds whatever names it,
    as a header line, for credential-named assignments and as its flag's value; its
    shell words are then read one by one, so ``-c "API_TOKEN=${API_TOKEN} exec ..."``
    is never a ``NAME=value`` or a literal.
    """
    if not any(char.isspace() for char in argument):
        return _word_hits(
            previous,
            argument,
            following,
            fetcher,
            in_set=cmd and _cmd_set_word(previous, before_previous),
        )
    flagged = previous is not None and _flag_value(previous, argument)
    hits = value_hits(previous if flagged and previous else "", argument)
    hits.extend(_header_line_hits(argument, explicit=_explicit_header(previous, argument)))
    hits.extend(assignment_hits(argument, spaced=True))
    long = len(argument) > _SHELL_SPLIT_LIMIT
    words = argument.split() if long else _launch_words([argument])[1:]
    fetcher = fetcher or not _FETCHERS.isdisjoint(map(posixpath.basename, words))
    around: list[str | None] = [None, *words, None]
    for index, word in enumerate(words, start=1):
        start = cmd and _cmd_set_word(around[index - 1], around[index - 2] if index > 1 else None)
        hits.extend(_word_hits(around[index - 1], word, around[index + 1], fetcher, in_set=start))
    return hits


def _name_hits(name: str) -> list[Hit]:
    return [(SHAPE_CLASS, match.group()) for match in TOKEN_SHAPE.finditer(name)]


def _credential_hits(
    env: dict[str, Any],
    args: list[Any],
    header_maps: Sequence[dict[str, Any]],
    endpoints: Sequence[Any],
    command: Any = "",
) -> Iterator[tuple[str, str, list[Hit]]]:
    """Each launch position, as its kind and name, with the literal credentials it holds.

    A header value with a line break injects a header line after it: each following
    line is read as one, at the position of the header that carries it.
    """
    words = [word for word in (command, *args) if isinstance(word, str)]
    fetcher = not _FETCHERS.isdisjoint(map(posixpath.basename, words))
    for name in sorted(env):
        value = env[name]
        hits = _name_hits(name)
        if isinstance(value, str):
            hits.extend(value_hits(name, value))
            hits.extend(_header_line_hits(value, explicit=False))
        yield ("env", name, hits)
    cmd = isinstance(command, str) and posixpath.basename(
        command.replace("\\", "/")
    ).casefold() in {"cmd", "cmd.exe"}
    before_previous: str | None = None
    previous: str | None = None
    for index, argument in enumerate(args, start=1):
        if isinstance(argument, str):
            after = args[index] if index < len(args) else None
            following = after if isinstance(after, str) else None
            yield (
                "argument",
                str(index),
                _argument_hits(
                    previous, argument, fetcher, following, cmd=cmd, before_previous=before_previous
                ),
            )
        before_previous, previous = previous, argument if isinstance(argument, str) else None
    headers = [item for mapping in header_maps for item in mapping.items()]
    for name, value in sorted(headers, key=lambda item: item[0]):
        hits = _name_hits(name)
        if isinstance(value, str):
            hits.extend(value_hits(name, value, header=True))
            for line in [value, *value.splitlines()[1:]]:
                hits.extend(_header_line_hits(line, explicit=False))
        yield ("header", name, hits)
    for endpoint in endpoints:
        if isinstance(endpoint, str):
            yield ("endpoint", "", endpoint_hits(endpoint))


PositionHits = list[tuple[str, str, list[Hit]]]


def _literals(positions: PositionHits) -> list[str]:
    """Every literal credential the launch positions hold, as the finding reads them."""
    return [literal for _, _, hits in positions for _, literal in hits if literal]


def _credential_positions(hits: PositionHits, names: _Names | None = None) -> list[tuple[str, str]]:
    """Each launch position holding a literal credential, with its pattern class.

    Positions are named as the inventory exports them: a name it withholds, such as one holding
    a literal of the same file, is not named here, and no value is. A name in a known token shape
    is itself a literal credential. A credential-named query parameter of an endpoint URL is the
    position "endpoint URL query"; its user information stays with transport_security. At most
    MAX_CREDENTIAL_POSITIONS are collected from ``hits``, the positions _server_hits read.
    """
    names = names or _Names(_literals(hits)).scoped()
    positions: dict[tuple[str, str], None] = {}
    for kind, name, found_hits in hits:
        found = strongest(found_hits)
        if found is None:
            continue
        if kind == "env":
            label = f"env {name}" if names.shown(name, finding=True) else "an env key"
        elif kind == "header":
            shown = f"header {redact_text(name, identifier=True)}"
            label = shown if names.shown(name, finding=True) else "a header"
        elif kind == "argument":
            label = f"argument {name}"
        else:
            label = _ENDPOINT_QUERY_POSITION
        positions[(label, found)] = None
        if len(positions) >= MAX_CREDENTIAL_POSITIONS:
            break
    return list(positions)


def _server_hits(config: dict[str, Any]) -> PositionHits:
    """Each launch position of one server with the literal credentials it holds."""
    endpoints = [config[field] for field in _ENDPOINT_FIELDS if config.get(field)]
    return list(
        _credential_hits(
            config.get("env", {}),
            config.get("args", []),
            [config.get("headers", {}), config.get("http_headers", {})],
            endpoints,
            config.get("command", ""),
        )
    )


def _declared_hits(config: dict[str, Any]) -> PositionHits:
    """The hits of a refused server's env, arguments, headers and endpoints."""
    env, args = config.get("env"), config.get("args")
    maps = [m for m in (config.get("headers"), config.get("http_headers")) if isinstance(m, dict)]
    endpoints = [
        value for field in _ENDPOINT_FIELDS if isinstance(value := config.get(field), str) and value
    ]
    args = args if isinstance(args, list) else []
    return list(
        _credential_hits(
            env if isinstance(env, dict) else {}, args, maps, endpoints, config.get("command", "")
        )
    )


def _malformed_values(node: Any, field: str = "") -> Iterator[str]:
    """Select credentials by their field or value even when a server is refused."""
    pending = [(field, node, False)]
    while pending:
        name, item, inferred = pending.pop()
        if isinstance(item, dict):
            credential_label = any(
                isinstance(item.get(key), str) and _scheme_assignment_name(item[key])
                for key in ("name", "key")
            )
            unlabelled = not {"name", "key"}.intersection(item)
            value_record = credential_label or (
                unlabelled
                and (
                    name.lower() in {"auth", "oauth", "headers", "http_headers"}
                    or _scheme_assignment_name(name)
                )
            )
            for key, value in item.items():
                # A refused record supplies context, but a public package name
                # can also occupy its value slot. Preserve explicit metadata labels.
                use_shape = (value_record and key in {"value", "values"}) or (
                    unlabelled and (inferred or credential_name(name))
                )
                pending.append((str(key), value, use_shape))
        elif isinstance(item, list):
            if name in {"", "args", "command", "command.args"}:
                for index, word in enumerate(item):
                    if isinstance(word, str):
                        previous = item[index - 1] if index else None
                        following = item[index + 1] if index + 1 < len(item) else None
                        yield from (
                            literal
                            for _, literal in _argument_hits(
                                previous if isinstance(previous, str) else None,
                                word,
                                following=following if isinstance(following, str) else None,
                            )
                        )
            if len(item) == 2 and isinstance(item[0], str) and _scheme_assignment_name(item[0]):
                pending.extend(((name, item[0], False), (item[0], item[1], True)))
            else:
                pending.extend((name, value, inferred) for value in item)
        elif isinstance(item, str):
            if is_reference(item):
                yield from (literal for _, literal in value_hits(name or "secret", item))
                continue
            if secret_like(name, item) or (
                (inferred or _scheme_assignment_name(name)) and literal_value(item)
            ):
                yield item
            yield from _text_credentials(item)
            yield from _shape_secrets(item)
            yield from (literal for _, literal in _argument_hits(None, item))


def _server_literals(config: dict[str, Any], hits: PositionHits) -> list[str]:
    """What no name may hold: the finding's literals, an auth object's and a URL password."""
    found = _literals(hits)
    for field in ("oauth", "auth"):
        if isinstance(settings := config.get(field), dict):
            found.extend(_auth_object_secrets(settings))
    for field in _ENDPOINT_FIELDS:
        if isinstance(endpoint := config.get(field), str):
            found.extend(_url_secrets(endpoint))
    return found


def _server_launch(config: dict[str, Any]) -> Launch:
    """The server's launcher as analyze reads it; raises as analyze does."""
    command = config.get("command", "")
    return analyze(command, config.get("args", [])) if command else Launch()


def _server_secrets(
    config: dict[str, Any], launch: Launch, hits: PositionHits | None = None
) -> list[str]:
    """Credential values one server declares: env, headers, auth, endpoints and launcher.

    Every literal credential the finding reads counts too, so a server name, a tool's
    text or a name that repeats one is scrubbed or withheld as a scrubbed value is.
    """
    values: list[str] = []
    for field in ("env", "headers", "http_headers"):
        mapping = config.get(field)
        if isinstance(mapping, dict):
            values.extend(secret_values(mapping))
            for item in mapping.values():
                if isinstance(item, str):
                    values.extend(_shape_secrets(item))
    for field in ("oauth", "auth"):
        settings = config.get(field)
        if isinstance(settings, dict):
            values.extend(_auth_object_secrets(settings))
    extension = config.get(_EXTENSION_SETTINGS)
    if isinstance(extension, dict):
        values.extend(_settings_secrets(extension))
    for field in (*_ENDPOINT_FIELDS, "gallery"):
        endpoint = config.get(field)
        if isinstance(endpoint, str):
            values.extend(_shape_secrets(endpoint))
    args = config.get("args", [])
    command = config.get("command", "")
    values.extend(
        _launch_secrets(
            launch,
            args if isinstance(args, list) else [],
            command if isinstance(command, str) else "",
        )
    )
    values.extend(_literals(_server_hits(config) if hits is None else hits))
    return list(dict.fromkeys(values))


def _value_binding(
    config: dict[str, Any], resolver: list[list[str]] | None = None
) -> tuple[str, str] | None:
    """The keyed binding of one server object and its key identifier, or None without a key."""
    key = source_binding_key()
    if key is None:
        return None
    binding = _keyed_binding(key, config, resolver or [])
    return binding["static_value_binding"], binding["static_value_binding_key_id"]


def _keyed_binding(key: bytes, config: dict[str, Any], resolver: list[list[str]]) -> dict[str, str]:
    try:
        message = canonical_json(
            {"profile": STATIC_VALUE_BINDING_PROFILE, "configuration": config, "resolver": resolver}
        )
    except (TypeError, ValueError) as exc:
        raise SourceBindingKeyError(
            f"{SOURCE_BINDING_KEY_ENV} binding needs RFC 8785 JSON values"
        ) from exc
    key_id = hmac.new(key, b"nexus-symbiote/source-binding-key-id", "sha256").hexdigest()
    return {
        "static_value_binding": "hmac-sha256:"
        + hmac.new(key, message.encode(), "sha256").hexdigest(),
        "static_value_binding_key_id": key_id[:32],
        "static_value_binding_profile": STATIC_VALUE_BINDING_PROFILE,
    }


def _has_userinfo(url: str) -> bool:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return False
    return parsed.username is not None or parsed.password is not None


def _has_path_or_query(url: object) -> bool:
    if not isinstance(url, str):
        return False
    try:
        parsed = urlsplit(url)
    except ValueError:
        return True
    return parsed.path not in {"", "/"} or bool(parsed.query)


_STRING_FIELDS = _names(
    "command url endpoint serverUrl httpUrl type transport transportType cwd envFile "
    "description name version bearer_token_env_var"
)
_LIST_FIELDS = _names(
    "args alwaysAllow autoApprove includeTools excludeTools enabled_tools disabled_tools "
    "disabledTools env_vars watchPaths"
)
_MAP_FIELDS = frozenset({"env", "headers", "http_headers", "env_http_headers"})
_BOOL_FIELDS = frozenset({"disabled", "trust", "enabled", _OAUTH_DISABLED})
_NUMBER_FIELDS = _names("timeout startup_timeout_sec startup_timeout_ms tool_timeout_sec")
_OBJECT_FIELDS = frozenset({"oauth", "auth", "dev", _EXTENSION_SETTINGS})
_KNOWN_FIELDS = (
    _STRING_FIELDS
    | _LIST_FIELDS
    | _MAP_FIELDS
    | _BOOL_FIELDS
    | _NUMBER_FIELDS
    | _OBJECT_FIELDS
    | {"tools", "gallery"}
)
_ENDPOINT_FIELDS = ("url", "endpoint", "serverUrl", "httpUrl")
# A field such as Claude Code's headersHelper names a command the client runs.
_COMMAND_FIELD = re.compile(r"(?i).*(?:helper|command|cmd|script|hooks?)")
_FIELD_NAME = re.compile(r"[A-Za-z0-9_.$-]{1,64}")
_SAFE_NAME = re.compile(r"[a-z0-9][a-z0-9._+-]{0,63}")
_TRANSPORT_TYPES = {
    "stdio": "stdio",
    "local": "stdio",
    "http": "streamable-http",
    "streamable-http": "streamable-http",
    "streamablehttp": "streamable-http",
    "sse": "sse",
    "ws": "websocket",
    "websocket": "websocket",
}
# Login shells, zsh, fish and Python's user site also load code from HOME, ZDOTDIR,
# XDG_CONFIG_HOME and PYTHONUSERBASE.
_CODE_LOADING_ENVIRONMENT = _names(
    "LD_PRELOAD LD_LIBRARY_PATH LD_AUDIT DYLD_INSERT_LIBRARIES DYLD_LIBRARY_PATH "
    "DYLD_FRAMEWORK_PATH NODE_OPTIONS NODE_PATH PYTHONPATH PYTHONSTARTUP PYTHONHOME "
    "PERL5OPT PERL5LIB RUBYOPT RUBYLIB JAVA_TOOL_OPTIONS _JAVA_OPTIONS JDK_JAVA_OPTIONS "
    "BASH_ENV ENV NPM_CONFIG_NODE_OPTIONS NPM_CONFIG_SCRIPT_SHELL SHELLOPTS BASHOPTS PS4 "
    "HOME ZDOTDIR XDG_CONFIG_HOME PYTHONUSERBASE"
)
# Environment names that make a package runner resolve from another registry, index,
# cache, proxy, trust store or engine. npm reads npm_config_<key> for every .npmrc key.
_NPM_REDIRECT = (
    r"(?:npm|pnpm)_config_(?:(?:@[^:]+:)?registry|userconfig|globalconfig|prefix|cache"
    r"|offline|prefer[-_]offline|proxy|https[-_]proxy|strict[-_]ssl|ca|cafile"
    r"|replace[-_]registry[-_]host|store[-_]dir)"
)
# Caches and tool directories count too: a prepared one in the checkout is used as is.
_UV_REDIRECT = (
    r"uv_(?:index|index_url|default_index|extra_index_url|find_links|config_file"
    r"|insecure_host|python_install_mirror|pypy_install_mirror|cache_dir|tool_dir)"
)
_REDIRECT_ENVIRONMENT = {
    "npm": _NPM_REDIRECT,
    "bun": rf"bun_config_registry|bun_install_cache_dir|bun_install|{_NPM_REDIRECT}",
    "yarn": (
        r"yarn_(?:npm_registry_server|registry|rc_filename|cache_folder|enable_strict_ssl"
        r"|https_proxy|http_proxy|ca_file_path|global_folder|npm_scopes)"
    ),
    "deno": rf"jsr_url|deno_cert|deno_dir|{_NPM_REDIRECT}",
    "uv-tool": _UV_REDIRECT,
    "uv-project": _UV_REDIRECT,
    "pip": (
        r"pip_(?:index|index_url|extra_index_url|find_links|config_file|trusted_host|proxy|cert"
        r"|cache_dir)|pipx_home|pipx_shared_libs"
    ),
    "go": (
        r"goproxy|goflags|gonosumdb|gonosumcheck|gosumdb|goprivate|gonoproxy|goinsecure"
        r"|gomodcache|gopath"
    ),
    "oci": (
        r"docker_(?:host|context|config|cert_path|tls_verify)|container_(?:host|connection)"
        r"|containers_(?:conf|registries_conf|storage_conf)|containerd_address"
    ),
}
_NODE_TRUST = r"node_extra_ca_certs|node_tls_reject_unauthorized"
_PYTHON_TRUST = r"ssl_cert_file|ssl_cert_dir|requests_ca_bundle|curl_ca_bundle"
# Environment names that add a trusted CA or disable TLS verification for a runner.
_TRUST_ENVIRONMENT = {
    "npm": _NODE_TRUST,
    "bun": _NODE_TRUST,
    "yarn": _NODE_TRUST,
    "deno": r"deno_tls_ca_store|ssl_cert_file",
    "uv-tool": _PYTHON_TRUST,
    "uv-project": _PYTHON_TRUST,
    "pip": _PYTHON_TRUST,
    "go": r"ssl_cert_file|ssl_cert_dir",
}
_PROXY_ENVIRONMENT = r"https?_proxy|all_proxy"
# Where a runner finds its user and global configuration, caches and programs: npm
# reads ~/.npmrc and <prefix>/etc/npmrc, uv and pip ~/.config, go $GOENV and
# ~/.config/go/env, docker ~/.docker, shells their profiles. No file there is read.
_LOCATION_ENVIRONMENT = _names(
    "HOME XDG_CONFIG_HOME XDG_CONFIG_DIRS XDG_CACHE_HOME XDG_DATA_HOME ZDOTDIR PYTHONUSERBASE"
)
# Read only on Windows, where a drive, UNC or rooted path is absolute.
_WINDOWS_LOCATION_ENVIRONMENT = _names("USERPROFILE APPDATA LOCALAPPDATA")
_LOCATION_LISTS = frozenset({"PATH", "XDG_CONFIG_DIRS"})
_NPM_LOCATION_ENVIRONMENT = _names("PREFIX DESTDIR")
_RUNNER_LOCATION_ENVIRONMENT = {
    "npm": _NPM_LOCATION_ENVIRONMENT,
    "bun": _NPM_LOCATION_ENVIRONMENT,
    "yarn": _NPM_LOCATION_ENVIRONMENT,
    "deno": _NPM_LOCATION_ENVIRONMENT,
    "go": _names("GOENV"),
}
# The environment forms of --overrides, --constraints and -r replace or add packages.
_UV_REPLACEMENT_ENVIRONMENT = _names("UV_OVERRIDE UV_CONSTRAINT UV_BUILD_CONSTRAINT")
_REPLACEMENT_ENVIRONMENT = {
    "uv-tool": _UV_REPLACEMENT_ENVIRONMENT,
    "uv-project": _UV_REPLACEMENT_ENVIRONMENT,
    "pip": _names("PIP_CONSTRAINT PIP_REQUIREMENT PIP_BUILD_CONSTRAINT"),
}


def _prefixes(*prefixes: str) -> tuple[tuple[re.Pattern[str], str], ...]:
    return tuple((re.compile(re.escape(prefix) + ".+", re.DOTALL), prefix) for prefix in prefixes)


# Each runner reads every setting from its own namespace, matched upper-cased as
# Windows reads names. go's settings have no underscore, so GOOGLE_API_KEY is not one.
_COREPACK_NAMESPACE = _prefixes("COREPACK_")
_UV_NAMESPACE = _prefixes("UV_")
_NAMESPACE_ENVIRONMENT = {
    "npm": _COREPACK_NAMESPACE,
    "yarn": _prefixes("YARN_") + _COREPACK_NAMESPACE,
    "bun": _prefixes("BUN_"),
    "deno": _prefixes("DENO_"),
    "uv-tool": _UV_NAMESPACE,
    "uv-project": _UV_NAMESPACE,
    "pip": _prefixes("PIP_", "PIPX_"),
    "go": ((re.compile(r"GO[A-Z0-9]+"), "GO"),),
    "oci": _prefixes("DOCKER_", "CONTAINER_", "CONTAINERS_", "CONTAINERD_", "PODMAN_", "NERDCTL_"),
}
# Settings in those namespaces that change only what the runner displays.
_DISPLAY_ENVIRONMENT = _names(
    "UV_NO_PROGRESS PIP_QUIET PIP_VERBOSE PIP_PROGRESS_BAR PIP_NO_COLOR PIPX_USE_EMOJI"
    " YARN_SILENT YARN_ENABLE_PROGRESS_BARS YARN_PROGRESS_BAR_STYLE YARN_ENABLE_COLORS"
    " BUN_CONFIG_VERBOSE_FETCH DOCKER_CLI_HINTS COREPACK_ENABLE_DOWNLOAD_PROMPT"
)
_RELOCATED = "environment relocates resolver configuration into the project"
_SEARCHED = "PATH may search the project for the runner"
_REPLACED = "environment replaces or constrains the launched package"
# bash imports BASH_FUNC_<name>%% (BASH_FUNC_<name>() on some distributions, and
# __BASH_FUNC<name>() in Apple's bash) as a function that replaces the program <name> in
# every bash the launch starts, the package runner included. bash from before 2014 did
# so for any variable whose value starts with "() {".
_EXPORTED_FUNCTION = re.compile(r"(?:__)?BASH_FUNC[_<]", re.IGNORECASE)
_FUNCTION_REPLACED = "environment defines a shell function that can replace the launched program"
# A non-interactive bash sources BASH_ENV before its script, and an interactive POSIX
# shell sources ENV; a file that may lie in the project can replace the runner.
_STARTUP_ENVIRONMENT = "BASH_ENV"
_INTERACTIVE_STARTUP_ENVIRONMENT = "ENV"
_STARTUP_IN_PROJECT = "environment names a shell startup file that may lie in the project"
# A shell tracing its commands expands PS4 before each one; an arithmetic or command
# expansion there can set PATH or run project code before the runner starts.
_TRACE_PROMPT = "environment sets a trace prompt the shell expands before the runner starts"
_TRACE_EXPANSION = re.compile(r"[$`]")
# /proc/self/cwd and its kin resolve to the working directory, the project; /dev/fd is a
# link into /proc, and a .. after any link can lead there too.
_PROC = re.compile(r"/+(?:proc|dev/+fd)(?:/|$)")
_PARENT = re.compile(r"(?:^|/)\.\.(?:/|$)")
_WINDOWS_ROOT = re.compile(r"[A-Za-z]:[\\/]|[\\/]")
_SCHEME_LETTERS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")
_SCHEME_CHARACTERS = _SCHEME_LETTERS | frozenset("0123456789+.-")
_LOCATOR_STOPS = frozenset(",;\"'")
_NPM_PURL_NAME = re.compile(r"(?:@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*")
_CONTEXT_HIGH = {
    "privileged": "privileged mode",
    "runtime_socket_mount": "a container runtime socket mount",
    "runtime_credentials_forwarded": "forwarded client credentials",
    "host_root_mount": "a host root mount",
    "security_options_disabled": "disabled confinement",
    "dangerous_capabilities": "a host-level capability",
}
_CONTEXT_MEDIUM = {
    "host_namespaces": "a host namespace",
    "added_capabilities": "added capabilities",
    "devices": "host devices",
    "broad_host_mount": "a broad host directory mount",
    "preload_module": "a preloaded module",
    "code_loading_option": "an option that loads local code",
    "code_loading_environment": "environment that changes code loading",
    "code_loading_setting": "a package manager setting that loads local code",
    "container_environment_file": "container environment from a file the inventory does not read",
    "container_command": "a health-check command the engine runs in the container",
    "custom_security_profile": "a seccomp profile from a file",
}


def _declared_type(config: dict[str, Any]) -> Any:
    return config.get("type", config.get("transport", config.get("transportType")))


def _declared_transport(config: dict[str, Any]) -> str | None:
    """The transport a server declares, normalised; None when it declares none it names."""
    declared = _declared_type(config)
    if not isinstance(declared, str):
        return None
    return _TRANSPORT_TYPES.get(declared.strip().lower().replace("_", "-"))


def _locators(value: str) -> list[str]:
    """Each ``scheme://rest`` locator in a value, left to right, in time linear in its length.

    A scheme is an ASCII letter followed by letters, digits, ``+``, ``.`` and ``-``, and
    the rest runs to white space or one of ``,;"'``: the matches that
    ``re.findall(r"[A-Za-z][A-Za-z0-9+.-]*://[^\\s,;\"']+", value)`` returns. That
    expression takes time quadratic in a long run of scheme characters, and a project
    file such as .npmrc can hold one.
    """
    found: list[str] = []
    position = 0
    while (mark := value.find("://", position)) >= 0:
        start = mark
        while start > position and value[start - 1] in _SCHEME_CHARACTERS:
            start -= 1
        while start < mark and value[start] not in _SCHEME_LETTERS:
            start += 1
        end = mark + 3
        if start < mark:
            while end < len(value) and not (value[end].isspace() or value[end] in _LOCATOR_STOPS):
                end += 1
        if end > mark + 3:
            found.append(value[start:end])
            position = end
        else:
            position = mark + 1
    return found


def _origin_label(value: str) -> list[str]:
    """Exported locations of a package source value: origins, never paths or credentials."""
    if expands(value):
        return ["[unresolved]"]
    found = [origin(match) or "[redacted]" for match in _locators(value)]
    if found:
        return sorted(set(found))
    return ["[local]"] if value.strip() else []


_TOKEN_RUN = re.compile(r"[A-Za-z0-9]{24,}")


def _exportable_name(name: str) -> bool:
    """Whether a configuration name may be exported: a plain field name, not token-shaped.

    A secret pasted as a key ("ghp_..." as a field, header or environment name) must not
    reach the inventory, so a name that matches a known token shape, or holds a run of 24
    or more letters and digits that mixes both, is withheld.
    """
    if not _FIELD_NAME.fullmatch(name) or TOKEN_SHAPE.search(name):
        return False
    return not any(
        any(c.isdigit() for c in run) and any(c.isalpha() for c in run)
        for run in _TOKEN_RUN.findall(name)
    )


def _folded(text: str) -> set[str]:
    return {(low := text.casefold()).replace("-", "_"), re.sub("[-_.]", "", low)} - {""}


class _Parts:
    """Strings found in a name by its windows' 64-bit hashes, where a collision withholds it: whole
    if ``exact``, else folded, and one of 16 or more characters by any 16 in a row (23 past 4,096)."""

    def __init__(self, texts: Iterable[str], *, exact: bool = False) -> None:
        self.exact, self.sizes = exact, set[int]()
        found = [array("q") for _ in range(256)]
        for text in texts if exact else (form for item in texts for form in _folded(item)):
            self.sizes.add(size := len(text) if exact else min(len(text), 16))
            for start in range(0, len(text) - size + 1, 1 if len(text) <= 4096 else 8):
                found[(part := hash(text[start : start + size])) & 255].append(part)
        self.parts = [array("q", sorted(set(parts))) for parts in found]

    def find(self, name: str) -> Iterator[tuple[int, int]]:
        for text in (name,) if self.exact else _folded(name):
            for size in self.sizes:
                for start in range(len(text) - size + 1):
                    parts = self.parts[(part := hash(text[start : start + size])) & 255]
                    if part in parts[(at := bisect_left(parts, part)) : at + 1]:
                        yield start, start + size


class _Names:
    """Which env, header and field names may be shown, each name's verdict reached once a file.

    A name holding a literal is withheld: whole, or by 16 characters in a row, in any case, with
    "-" for "_" and with or without "-", "_" and ".". In the inventory only a credential-shaped literal of the scan counts, or
    any of the server's own; the finding never names one holding any literal of the scan.
    Another value the file's scrubber holds withholds it whole, or as a credential-shaped part,
    unless that is a credential's name (OPENAI_API_KEY, also in AZURE_OPENAI_API_KEY).
    """

    def __init__(self, literals: Sequence[str]) -> None:
        shaped = set(filter(credential_shaped, literals))
        self.every, self.shaped = _Parts(set(literals) - shaped), _Parts(shaped)
        self.values = self.own = _Parts((), exact=True)
        self.verdicts: dict[str, tuple[bool, bool]] = {}

    def scoped(self, values: Iterable[str] | None = None, own: Iterable[str] = ()) -> _Names:
        """These names in a file whose scrubber holds ``values``, or in a server that reads ``own``."""
        names = copy.copy(self)
        if values is not None:
            names.values, names.verdicts = _Parts(values, exact=True), {}
        names.own = _Parts(own)
        return names

    def shown(self, name: str, *, finding: bool = False) -> bool:
        if name not in self.verdicts:
            plain = _exportable_name(name) and not any(self.shaped.find(name))
            self.verdicts[name] = (plain and self._named(name), not any(self.every.find(name)))
        plain, clear = self.verdicts[name]
        return plain and (clear if finding else not any(self.own.find(name)))

    def _named(self, name: str) -> bool:
        covered = bytearray(len(name))
        for start, end in self.values.find(name):
            covered[start:end] = b"\x01" * (end - start)
        spans = [run.span() for run in re.finditer(rb"\x01+", covered)]
        whole = spans == [(0, len(name))]
        held = [name[a:b] for a, b in spans if whole or credential_shaped(name[a:b])]
        return all(_NAME_FORM.fullmatch(part) and credential_name(part) for part in held)


def _exported_names(names: Iterable[str], shown: _Names | None = None) -> list[str]:
    """Sorted names with every withheld one as "[redacted]", one marker per name."""
    return sorted(
        redact_text(name, identifier=True) if (shown or _Names(())).shown(name) else "[redacted]"
        for name in names
    )


def _exported_environment(env: dict[str, Any], names: _Names | None = None) -> dict[str, str]:
    """The environment's names with masked values; withheld names get numbered markers."""
    shown: dict[str, str] = {}
    withheld = 0
    for name in sorted(env):
        if (names or _Names(())).shown(name):
            shown[name] = "***"
        else:
            withheld += 1
            shown[f"[redacted-{withheld}]"] = "***"
    return shown


def _field_names(config: dict[str, Any], shape: str, names: _Names | None = None) -> list[str]:
    """The fields a server declares, each read from the client's shape by the name the
    client file gives it."""
    fields = [
        _DECLARED_FIELDS[field] if field in _SHAPE_FIELDS and _interpreted(field, shape) else field
        for field in config
    ]
    return _exported_names(fields, names)


def _json_shape(value: Any, budget: int) -> tuple[int, int]:
    """Count nodes, keys included, and depth iteratively, stopping past ``budget``."""
    nodes = depth = 0
    pending = [(value, 1)]
    while pending and nodes <= budget and depth <= MAX_TOOL_DEPTH:
        item, level = pending.pop()
        nodes += 1
        depth = max(depth, level)
        if isinstance(item, dict):
            nodes += len(item)
            pending.extend((child, level + 1) for child in item.values())
        elif isinstance(item, list):
            pending.extend((child, level + 1) for child in item)
    return nodes, depth


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


_MAX_JSONC_DEPTH = 256


def _reject_constant(value: str) -> Any:
    raise ValueError("nonfinite JSON")


def _finite_float(text: str) -> float:
    # json.loads and tomllib read 1e400 and inf as infinity, which no export can carry.
    value = float(text)
    if not math.isfinite(value):
        raise ValueError("nonfinite number")
    return value


def _check_jsonc_depth(text: str) -> None:
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
        elif ch in "{[":
            depth += 1
            if depth > _MAX_JSONC_DEPTH:
                raise RecursionError("JSONC nesting limit exceeded")
        elif ch in "}]" and depth > 0:
            depth -= 1


def _load_jsonc(text: str) -> Any:
    cleaned = strip_jsonc(text)
    _check_jsonc_depth(cleaned)
    return json.loads(
        cleaned,
        object_pairs_hook=_unique_pairs,
        parse_constant=_reject_constant,
        parse_float=_finite_float,
    )


def _purl(package: Package) -> str | None:
    """An exact npm or PyPI package URL, the form advisory lookups accept."""
    if not package.pinned or package.name is None or package.version is None:
        return None
    if package.ecosystem == "npm" and _NPM_PURL_NAME.fullmatch(package.name):
        return f"pkg:npm/{quote(package.name, safe='/')}@{quote(package.version, safe='')}"
    if package.ecosystem == "pypi":
        return f"pkg:pypi/{quote(package.name, safe='')}@{quote(package.version, safe='')}"
    return None


# String.prototype.trim whitespace: npm's ini reader trims keys and values with it.
_JS_SPACE = (
    "\t\n\v\f\r \u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007"
    "\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
)
_INI_COMMENT = re.compile(f"[{_JS_SPACE}]*[;#]")
_INI_SECTION = re.compile(f"\\[[^\\]]*\\][{_JS_SPACE}]*")
_NPMRC_AUTH = re.compile(
    r"//.*|_auth|_authToken|_password|username|password|email|certfile|keyfile"
    r"|always-auth|otp",
    re.S,
)
# Keys that change where package bytes come from or how their transport is trusted.
_NPMRC_SOURCES = frozenset(
    {
        "cache",
        "proxy",
        "https-proxy",
        "http-proxy",
        "ca",
        "cafile",
        "userconfig",
        "globalconfig",
        "replace-registry-host",
        "prefix",
        "store-dir",
        "cache-dir",
        "workspace",
    }
)
# npm configuration that decides what npm exec runs: `call` runs a shell command and
# `package` installs another package; either way the declared package does not
# establish what runs (npm reads both from every configuration layer).
_NPM_IDENTITY_SETTINGS = frozenset({"call", "package"})
# Configuration that names local code npm, pnpm or a lifecycle script runs.
_NPM_CODE_SETTINGS = _names(
    "script-shell node-options shell git node-gyp editor browser viewer init-module init.module"
    " onload-script pnpmfile global-pnpmfile npm-path"
)
# Settings known to change neither what runs nor where package bytes come from. npm
# passes every other setting to lifecycle scripts, whose installers read binary
# mirrors and hosts from them, so an unknown setting is a package source.
_NPM_INERT_SETTINGS = (
    (NPM_CONFIG_FLAGS | NPM_CONFIG_VALUES | {"color", "always-auth", "certfile", "keyfile"})
    - _NPM_IDENTITY_SETTINGS
    - _NPM_CODE_SETTINGS
    - _NPMRC_SOURCES
) | _names(
    "auto-install-peers shamefully-hoist strict-peer-dependencies node-linker"
    " link-workspace-packages prefer-workspace-packages public-hoist-pattern hoist-pattern hoist"
    " hoist-workspace-packages enable-pre-post-scripts resolution-mode dedupe-peer-dependents"
    " side-effects-cache side-effects-cache-readonly lockfile prefer-frozen-lockfile"
    " frozen-lockfile use-lockfile-v6 git-checks publish-branch recursive-install"
    " child-concurrency network-concurrency package-import-method symlink enable-modules-dir"
    " shared-workspace-lockfile save-workspace-protocol ignore-workspace-root-check"
    " disallow-workspace-cycles dedupe-direct-deps dedupe-injected-deps"
    " exclude-links-from-lockfile resolve-peers-from-workspace-root peers-suffix-max-length"
    " optimistic-repeat-install package-manager-strict package-manager-strict-version use-stderr"
    " reporter strict-dep-builds ignore-compatibility-db deploy-all-files extend-node-path"
    " ignore-pnpmfile ignore-dep-scripts only-built-dependencies never-built-dependencies"
    " minimum-release-age use-node-version node-version manage-package-manager-versions"
    " unsafe-perm"
)
_SCOPED_REGISTRY = re.compile(r"@[^:]+:(?:registry|npmRegistryServer)", re.DOTALL)
_NPM_SCOPE = re.compile(r"@[a-z0-9][a-z0-9._-]{0,63}")
_NPM_ENVIRONMENT = re.compile(r"(?:npm|pnpm)_config_(.+)", re.IGNORECASE | re.DOTALL)
_UV_SETTINGS = (
    "index-url",
    "extra-index-url",
    "find-links",
    "index",
    "allow-insecure-host",
    "python-install-mirror",
    "pypy-install-mirror",
)
# Yarn settings that replace or extend yarn with local code, and that redirect or
# relax where packages come from (.yarnrc.yml for Yarn 2+, .yarnrc for Yarn 1).
_YARN_CODE_SETTINGS = frozenset({"yarnPath", "plugins", "yarn-path"})
_YARN_CODE_ENVIRONMENT = {"YARN_YARN_PATH": "yarnPath", "YARN_PLUGINS": "plugins"}
_YARN_SOURCE_SETTINGS = _names(
    "httpProxy httpsProxy caFilePath enableStrictSsl cacheFolder globalFolder networkSettings"
    " unsafeHttpWhitelist checksumBehavior enableOfflineMode injectEnvironmentFiles"
    " packageExtensions"
)
_BUN_IDENTITY_SETTINGS = frozenset({"preload", "run.preload"})
_BUN_CODE_SETTINGS = frozenset({"run.shell"})
_BUN_SOURCE_SETTINGS = frozenset({"install.ca", "install.cafile"})
_DENO_SOURCE_SETTINGS = frozenset({"importMap", "imports", "scopes"})
_RESOLVER_FILES = {
    "npm": (".npmrc",),
    "deno": (".npmrc", "deno.json", "deno.jsonc"),
    "bun": (".npmrc", "bunfig.toml"),
    "yarn": (".yarnrc.yml", ".yarnrc", ".env.yarn"),
    "uv-project": ("uv.toml", "pyproject.toml"),
    "uv-tool": ("uv.toml", "pyproject.toml"),
}
# Setting names exported in clear: fixed vocabularies, never a name taken from input.
_KNOWN_SETTINGS = (
    _NPM_INERT_SETTINGS
    | _NPMRC_SOURCES
    | _NPM_IDENTITY_SETTINGS
    | _NPM_CODE_SETTINGS
    | _YARN_CODE_SETTINGS
    | _YARN_SOURCE_SETTINGS
    | _BUN_IDENTITY_SETTINGS
    | _BUN_CODE_SETTINGS
    | _BUN_SOURCE_SETTINGS
    | _DENO_SOURCE_SETTINGS
    | frozenset(_UV_SETTINGS)
    | {"registry", "npmRegistryServer", "offline", "prefer-offline", "strict-ssl", "environment"}
)


def _environment_label(variable: str, launched: Iterable[str] = ()) -> str:
    """A package source label for an environment variable, never a token-shaped name.

    Every name comes from a fixed vocabulary but the scope of an npm scoped registry,
    which is named only as ``_setting_name`` names it, as the npm resolver view does.
    """
    if TOKEN_SHAPE.search(variable):
        return "env:[redacted]"
    key = _npm_key(variable)
    if (
        key is not None
        and _SCOPED_REGISTRY.fullmatch(key)
        and _setting_name(key, launched) == "[other]"
    ):
        return "env:npm_config_[other]"
    return f"env:{variable}"


def _absolute(value: str, *, windows: bool = False) -> bool:
    """Whether a location names an absolute directory; any other may lie in the project.

    An empty, relative or ``~`` value is relative to the working directory, and an
    expansion such as ``${workspaceFolder}`` or ``%USERPROFILE%`` may name the project.
    """
    if not value or expands(value):
        return False
    if windows:
        return bool(_WINDOWS_ROOT.match(value))
    return (
        value.startswith("/")
        and _PARENT.search(value) is None
        and _PROC.match(posixpath.normpath(value)) is None
    )


def _exported_function(variable: str, value: object) -> bool:
    """Whether bash imports the variable as a function that replaces a program."""
    return _EXPORTED_FUNCTION.match(variable) is not None or (
        isinstance(value, str) and value.startswith("() {")
    )


def _absolute_list(value: str) -> bool:
    """Whether every entry of a directory list is absolute however it is split.

    POSIX splits at ``:`` and searches the working directory for an empty entry, so a
    Windows list such as ``C:\\bin`` names relative directories there; Windows splits
    at ``;``.
    """
    return all(_absolute(entry) for entry in value.split(":")) and all(
        _absolute(entry, windows=True) for entry in value.split(";") if entry
    )


def _runner_environment(
    family: str,
    environment: list[tuple[str, str]],
    *,
    interactive: bool = False,
    xtrace: bool = False,
) -> tuple[list[tuple[str, str]], list[str]]:
    """Package sources a runner's environment adds, and why it leaves the identity unknown.

    A location the runner reads its configuration, caches or programs from, a
    replacement of the package and any non-display setting of the runner's own
    namespace are sources. A location that may lie in the project, or a replacement,
    also makes the identity unknown: no file there is read, so a change would go
    unseen. A PATH of absolute directories is the operator's own and adds nothing.
    """
    sources: list[tuple[str, str]] = []
    reasons: list[str] = []
    explicit = _REDIRECT_ENVIRONMENT.get(family)
    # bash also turns tracing on from SHELLOPTS in the environment.
    traced = xtrace or any(
        variable.upper() == "SHELLOPTS" and isinstance(value, str) and "xtrace" in value.lower()
        for variable, value in environment
    )
    for variable, value in environment if family else ():
        name = variable.upper()
        windows = name in _WINDOWS_LOCATION_ENVIRONMENT
        if _exported_function(variable, value):
            reasons.append(_FUNCTION_REPLACED)
        elif name == _STARTUP_ENVIRONMENT or (
            interactive and name == _INTERACTIVE_STARTUP_ENVIRONMENT
        ):
            if not _absolute(value):
                reasons.append(_STARTUP_IN_PROJECT)
        elif name == "PS4":
            if traced and isinstance(value, str) and _TRACE_EXPANSION.search(value):
                reasons.append(_TRACE_PROMPT)
        elif name == "PATH":
            if not _absolute_list(value):
                sources.append((_environment_label(variable), value))
                reasons.append(_SEARCHED)
        elif (
            windows
            or name in _LOCATION_ENVIRONMENT
            or name in _RUNNER_LOCATION_ENVIRONMENT.get(family, ())
        ):
            sources.append((_environment_label(variable), value))
            inside = (
                not _absolute_list(value)
                if name in _LOCATION_LISTS
                else not _absolute(value, windows=windows)
            )
            if inside:
                reasons.append(_RELOCATED)
        elif name in _REPLACEMENT_ENVIRONMENT.get(family, ()):
            sources.append((_environment_label(variable), value))
            reasons.append(_REPLACED)
        elif name not in _DISPLAY_ENVIRONMENT and not (
            explicit is not None and re.fullmatch(explicit, variable, re.IGNORECASE)
        ):
            prefix = next(
                (
                    label
                    for pattern, label in _NAMESPACE_ENVIRONMENT.get(family, ())
                    if pattern.fullmatch(name)
                ),
                None,
            )
            if prefix is not None:
                # A name taken from input is never exported: only its namespace is.
                sources.append((f"env:{prefix}[other]", value))
    return sources, reasons


class _Launched(frozenset[str]):
    """A server's launched package names, with their npm scopes computed once."""

    scopes: frozenset[str]

    def __new__(cls, names: Iterable[str]) -> _Launched:
        launched = super().__new__(cls, names)
        launched.scopes = frozenset(name.partition("/")[0] for name in launched if "/" in name)
        return launched

    @classmethod
    def of(cls, names: Iterable[str]) -> _Launched:
        return names if isinstance(names, _Launched) else cls(names)


def _setting_name(key: str, launched: Iterable[str], *, selected: bool = False) -> str:
    """A resolver setting name safe to export; a name from no vocabulary is ``[other]``.

    A token pasted on its own .npmrc line is read by npm as ``<token>=true``, so
    a key name is input and may be a secret. So may the scope of a scoped registry,
    which is named only when it is a launched package's scope, or the registry npm
    ``selected`` for one through the ``scope`` setting.
    """
    if key in _KNOWN_SETTINGS:
        return key
    scope, _, rest = key.partition(":")
    if (
        _SCOPED_REGISTRY.fullmatch(key)
        and _NPM_SCOPE.fullmatch(scope)
        and not TOKEN_SHAPE.search(scope)
        and (selected or scope in _Launched.of(launched).scopes)
    ):
        return f"{scope}:{rest}"
    if key.startswith("sources.") and key[8:] in launched:
        return key
    return "[other]"


def _option_label(option: str, launched: Iterable[str]) -> str:
    """A runner option's source label; a scoped registry names only a launched scope."""
    if option.startswith("--@") and option.endswith(":registry"):
        return f"--{_setting_name(option[2:], launched)}"
    return option


def _npm_key(variable: str) -> str | None:
    """The npm configuration key an environment variable sets, as npm reads it."""
    match = _NPM_ENVIRONMENT.fullmatch(variable)
    if match is None:
        return None
    key = match.group(1)
    return key if key.startswith("//") else (key[:1] + key[1:].replace("_", "-")).lower()


def _npm_setting(key: str, value: str) -> str:
    """What an npm setting does to an npm exec launch: identity, code, registry, source or inert."""
    if key in _NPM_IDENTITY_SETTINGS:
        return "identity"
    if key in _NPM_CODE_SETTINGS:
        return "code"
    if key == "registry" or _SCOPED_REGISTRY.fullmatch(key):
        return "registry"
    if key in {"offline", "prefer-offline"}:
        return "inert" if value == "false" else "source"
    if key == "strict-ssl":
        return "inert" if value == "true" else "source"
    if key in _NPMRC_SOURCES:
        return "source"
    if key in _NPM_INERT_SETTINGS or key.startswith("//") or _NPMRC_AUTH.fullmatch(key):
        return "inert"
    return "source"


_YARNRC_LINE = re.compile(r'(?:"((?:[^"\\]|\\.)*)"|([^\s"]+))\s*(.*)', re.DOTALL)


def _yarnrc(text: str) -> tuple[tuple[str, str], ...]:
    """Top-level ``key value`` lines of a Yarn 1 .yarnrc, keys without leading dashes."""
    settings: dict[str, str] = {}
    for line in re.split(r"[\r\n]+", text):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _YARNRC_LINE.fullmatch(stripped)
        if match is None:
            continue
        key = (match.group(1) if match.group(1) is not None else match.group(2)).lstrip("-")
        value = match.group(3).strip()
        if len(value) >= 2 and value[0] == value[-1] == '"':
            value = value[1:-1]
        settings[key] = value
    return tuple(settings.items())


def _file_setting(path: str, family: str, key: str, value: str, launched: Collection[str]) -> str:
    """What a project resolver file setting does: identity, code, source or inert.

    Registry entries are inert here; they apply per package scope.
    """
    if path == ".npmrc":
        if family != "npm":
            return "source" if _npmrc_source(key, value) else "inert"
        kind = _npm_setting(key, value)
        return "inert" if kind == "registry" else kind
    if path in {".yarnrc.yml", ".yarnrc"}:
        if key in _YARN_CODE_SETTINGS:
            return "identity"
        if path != ".yarnrc.yml" or key not in _YARN_SOURCE_SETTINGS:
            return "inert"
        relaxed = {
            "enableStrictSsl": "true",
            "checksumBehavior": "throw",
            "enableOfflineMode": "false",
        }
        return "inert" if relaxed.get(key) == value else "source"
    if path == "bunfig.toml":
        if key in _BUN_IDENTITY_SETTINGS:
            return "identity"
        if key in _BUN_CODE_SETTINGS:
            return "code"
        return "source" if key in _BUN_SOURCE_SETTINGS else "inert"
    if path in {"deno.json", "deno.jsonc"}:
        return "source" if key in _DENO_SOURCE_SETTINGS else "inert"
    if path in {"uv.toml", "pyproject.toml"}:
        return "source" if not key.startswith("sources.") or key[8:] in launched else "inert"
    return "unresolved" if path == ".env.yarn" else "inert"


# Working directories that are the scan root; any other one may hold other resolver files.
_ROOT_DIRECTORIES = frozenset({"", ".", "./", "${workspaceFolder}", "${workspaceFolder}/"})


def _ini_text(raw: str) -> str:
    """npm's ini ``unsafe``: trim, decode quoted text as JSON, else cut at ``;`` or ``#``."""
    text = raw.strip(_JS_SPACE)
    if text[:1] in {'"', "'"} and text.endswith(text[0]):
        inner = text[1:-1] if text[0] == "'" else text
        try:
            decoded = json.loads(inner)
        except (ValueError, RecursionError):
            # A value nested beyond the parser's limit is text, as any other that is
            # not JSON; it must not escape as an error attributed to every server.
            return inner if text[0] == "'" else text
        return decoded if isinstance(decoded, str) else json.dumps(decoded)
    kept: list[str] = []
    escaped = False
    for char in text:
        if escaped:
            kept.append(char if char in ";#\\" else "\\" + char)
            escaped = False
        elif char in ";#":
            break
        elif char == "\\":
            escaped = True
        else:
            kept.append(char)
    if escaped:
        kept.append("\\")
    return "".join(kept).strip(_JS_SPACE)


@dataclass(frozen=True)
class _ResolverFile:
    """Effective settings of one project resolver file; auth settings are left out."""

    settings: tuple[tuple[str, str], ...] = ()
    unresolved: bool = False
    binding_settings: tuple[tuple[str, str], ...] | None = None


def _npmrc(text: str) -> _ResolverFile:
    """Top-level .npmrc settings exactly as npm's ini reader and config loader see them.

    Keys are trimmed, JSON-decoded when quoted and cut at ``;`` or ``#`` otherwise;
    a key that holds ``${...}`` depends on the environment and is unresolved. Keys
    after the first section header are not top-level settings and npm ignores them.
    """
    settings: dict[str, str] = {}
    unresolved = False
    for line in re.split(r"[\r\n]+", text):
        if not line.strip(_JS_SPACE) or _INI_COMMENT.match(line):
            continue
        if _INI_SECTION.fullmatch(line):
            break
        raw_key, equals, raw_value = line.partition("=")
        if not raw_key or (equals and ("\u2028" in raw_value or "\u2029" in raw_value)):
            continue
        key = _ini_text(raw_key)
        if len(key) > 2 and key.endswith("[]"):
            key = key[:-2]
        if "${" in key:
            unresolved = True
        elif key != "__proto__" and not _NPMRC_AUTH.fullmatch(key):
            settings[key] = _ini_text(raw_value) if equals else "true"
    return _ResolverFile(tuple(settings.items()), unresolved)


def _npmrc_source(key: str, value: str) -> bool:
    """A setting other than a registry that changes where packages come from."""
    if key in {"offline", "prefer-offline"}:
        return value != "false"
    if key == "strict-ssl":
        return value != "true"
    return key in _NPMRC_SOURCES


def _uv_settings(settings: dict[str, Any]) -> _ResolverFile:
    found: list[tuple[str, str]] = []
    for key in _UV_SETTINGS:
        values = settings.get(key)
        for item in values if isinstance(values, list) else [values]:
            url = item.get("url") if isinstance(item, dict) else item
            if isinstance(url, str):
                found.append((key, url))
    sources = settings.get("sources")
    if isinstance(sources, dict):
        for name, source in sources.items():
            locations = source if isinstance(source, list) else [source]
            for location in locations:
                if isinstance(location, dict):
                    value = next(
                        (
                            str(location[field])
                            for field in ("git", "url", "path", "index", "workspace")
                            if field in location
                        ),
                        "",
                    )
                    found.append((f"sources.{canonicalize_name(str(name))}", value))
    return _ResolverFile(tuple(found))


class _Resolvers:
    """Project-root package resolver settings, read once per collection when needed."""

    def __init__(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        read_mapping: Callable[[Path, ScanResult], dict[str, Any] | None],
    ) -> None:
        self._files = files
        self._result = result
        self._read_mapping = read_mapping
        self._loaded: dict[str, _ResolverFile] = {}

    def entries(self, path: str) -> _ResolverFile:
        if path not in self._loaded:
            self._loaded[path] = self._read(path)
        return self._loaded[path]

    def _text(self, path: str) -> str | None:
        text = self._files.read_text(path, missing_ok=True)
        if text is not None:
            self._result.surfaces_scanned.append(path)
        return text

    def _toml(self, path: str) -> dict[str, Any]:
        text = self._text(path)
        if text is None:
            return {}
        try:
            return load_toml(text)
        except (ValueError, RecursionError, MemoryError):
            self._result.scan_failures.append(f"{path}: invalid TOML")
            return {}

    def _read(self, path: str) -> _ResolverFile:
        if path == ".npmrc":
            return _npmrc(self._text(path) or "")
        if path == ".yarnrc":
            return _ResolverFile(_yarnrc(self._text(path) or ""))
        if path == ".env.yarn":
            # Yarn 4 loads .env.yarn into its environment by default (injectEnvironmentFiles).
            text = self._text(path)
            return _ResolverFile((("environment", text),) if text is not None else ())
        if path == ".yarnrc.yml":
            settings = self._read_mapping(Path(path), self._result) or {}
            if settings:
                self._result.surfaces_scanned.append(path)
            entries = _registries(settings, "npmRegistryServer", "npmScopes")
            entries += [
                (str(key), value if isinstance(value, str) else json.dumps(value, default=str))
                for key, value in settings.items()
                if key in _YARN_CODE_SETTINGS or key in _YARN_SOURCE_SETTINGS
            ]
            return _ResolverFile(tuple(entries))
        if path in {"deno.json", "deno.jsonc"}:
            text = self._text(path)
            if text is None:
                return _ResolverFile()
            try:
                data = _load_jsonc(text)
            except (ValueError, RecursionError):
                self._result.scan_failures.append(f"{path}: invalid JSON or duplicate keys")
                return _ResolverFile()
            if not isinstance(data, dict):
                self._result.scan_failures.append(f"{path}: expected a JSON object")
                return _ResolverFile()
            if "importMap" in data:
                self._result.surfaces_excluded.append(
                    f"{path}: referenced Deno import map is not collected"
                )
            imports = data.get("imports", {})
            scopes = data.get("scopes", {})
            if (
                not isinstance(imports, dict)
                or any(not isinstance(target, str) for target in imports.values())
                or not isinstance(scopes, dict)
                or any(
                    not isinstance(mapping, dict)
                    or any(not isinstance(target, str) for target in mapping.values())
                    for mapping in scopes.values()
                )
            ):
                self._result.surfaces_excluded.append(f"{path}: unsupported Deno import-map shape")
            try:
                binding = tuple(
                    (key, canonical_json(data[key]))
                    for key in sorted(_DENO_SOURCE_SETTINGS)
                    if key in data
                )
            except (TypeError, ValueError, RecursionError):
                self._result.scan_failures.append(f"{path}: invalid JSON values")
                return _ResolverFile()
            deno_entries: list[tuple[str, str]] = []
            import_map = data.get("importMap")
            if isinstance(import_map, str) and import_map:
                deno_entries.append(("importMap", import_map))
            imports = data.get("imports")
            if isinstance(imports, dict):
                for target in imports.values():
                    if isinstance(target, str):
                        deno_entries.append(("imports", target))
                    elif isinstance(target, list):
                        # The import-maps standard accepts only string addresses, but an
                        # early draft allowed arrays of fallbacks: record each one, so such
                        # an entry never leaves a launcher looking pinned.
                        for fallback in target:
                            if isinstance(fallback, str):
                                deno_entries.append(("imports", fallback))
            scopes = data.get("scopes")
            if isinstance(scopes, dict) and scopes:
                deno_entries.append(("scopes", json.dumps(scopes, sort_keys=True, default=str)))
            # Source labels intentionally omit import specifiers. The private HMAC
            # must retain their associations, including scopes and fallback order.
            return _ResolverFile(tuple(deno_entries), binding_settings=binding)
        settings = self._toml(path)
        if path == "bunfig.toml":
            install = settings.get("install")
            install_map = install if isinstance(install, dict) else {}
            bun_entries = _registries(install_map, "registry", "scopes")
            for ca_key in ("ca", "cafile"):
                if ca_key in install_map and install_map[ca_key]:
                    bun_entries.append(
                        (
                            f"install.{ca_key}",
                            install_map[ca_key]
                            if isinstance(install_map[ca_key], str)
                            else json.dumps(install_map[ca_key], default=str),
                        )
                    )
            if settings.get("preload"):
                bun_entries.append(
                    (
                        "preload",
                        settings["preload"]
                        if isinstance(settings["preload"], str)
                        else json.dumps(settings["preload"], default=str),
                    )
                )
            run_cfg = settings.get("run")
            if isinstance(run_cfg, dict):
                for run_key in ("preload", "shell"):
                    if run_cfg.get(run_key):
                        bun_entries.append(
                            (
                                f"run.{run_key}",
                                run_cfg[run_key]
                                if isinstance(run_cfg[run_key], str)
                                else json.dumps(run_cfg[run_key], default=str),
                            )
                        )
            return _ResolverFile(tuple(bun_entries))
        if path == "pyproject.toml":
            tool = settings.get("tool")
            uv = tool.get("uv") if isinstance(tool, dict) else None
            settings = uv if isinstance(uv, dict) else {}
        return _uv_settings(settings)


class _ResolverView:
    """What project resolver files and package manager environment mean for one launcher."""

    __slots__ = ("binding", "code", "environment", "identity", "names", "sources", "unresolved")

    def __init__(self) -> None:
        self.sources: list[tuple[str, str]] = []
        self.unresolved: list[str] = []
        self.binding: list[list[str]] = []
        self.names: list[str] = []
        # Settings that change what runs (fixed-vocabulary reasons) or load local code.
        self.identity: list[str] = []
        self.code = 0
        # The package manager's own environment settings were read here.
        self.environment = False


def npm_registry_settings(
    settings: Mapping[str, str], package: str, default: str, scope: str | None = None
) -> list[str]:
    """The settings that may name the registry npm fetches a package from.

    A setting for the package's own scope wins. npm then uses the registry of a
    configured ``scope`` for a package whose own scope has none, unscoped packages
    included (npm-registry-fetch), and otherwise the file's default registry setting.
    npm fills in ``${...}`` in a ``scope`` from the environment, so such a scope may
    name any scope: ``scope`` itself is then returned, with the default registry
    setting, which applies when the scope it names has no registry. A caller passes
    such a scope only when the file has a registry setting for some scope
    (:func:`npm_scope_registry`).
    """
    own = package.split("/", 1)[0] if package.startswith("@") else None
    if own is not None and f"{own}:{default}" in settings:
        return [f"{own}:{default}"]
    found: list[str] = []
    if scope and expands(scope):
        found.append("scope")
    elif scope:
        fallback = f"{scope if scope.startswith('@') else '@' + scope}:registry"
        if fallback in settings:
            return [fallback]
    if default in settings:
        found.append(default)
    return found


def npm_scope_registry(key: str) -> bool:
    """Whether an .npmrc key is one a ``scope`` setting can select: npm looks up
    ``@<scope>:registry`` exactly, whatever characters the scope holds."""
    return key.startswith("@") and key.endswith(":registry")


def _registry_url(value: Any) -> str | None:
    if isinstance(value, dict):
        value = value.get("url", value.get("npmRegistryServer"))
    return value if isinstance(value, str) else None


def _registries(settings: dict[str, Any], default: str, scopes_key: str) -> list[tuple[str, str]]:
    """The default and per-scope registry URLs of a bunfig or yarnrc mapping."""
    pairs: list[tuple[str, str | None]] = [(default, _registry_url(settings.get(default)))]
    scopes = settings.get(scopes_key)
    if isinstance(scopes, dict):
        pairs += [
            (f"@{str(scope).lstrip('@')}:{default}", _registry_url(value))
            for scope, value in scopes.items()
        ]
    return [(key, value) for key, value in pairs if value is not None]


@dataclass
class _Identity:
    """Identity fields computed from raw configuration before any scrubbing."""

    name: str
    command: str | None
    executable: str | None
    endpoint: str | None
    endpoint_gap: str | None
    packages: list[dict[str, Any]]
    package_identities: list[str]
    sources: list[str]
    withheld: list[str]


_DIAGNOSTIC_NODES = 4096
# `NAME=value`, as `cross-env` or `env` take it, or docker's `--env=NAME=value`.
_INLINE_ASSIGNMENT = re.compile(r"(?:--env=)?([A-Za-z_][A-Za-z0-9_]*)=(.+)", re.DOTALL)


def _user_info(locator: str) -> list[str]:
    """The user name and password of a URL, as written and percent-decoded.

    A WHATWG client, as most MCP clients use, ends the authority of a special scheme
    at a backslash as at a slash; urlsplit does not, so both readings count.
    """
    found: list[str] = []
    for reading in {locator, locator.replace("\\", "/")}:
        try:
            parts = urlsplit(reading)
            username, password = parts.username, parts.password
        except ValueError:
            continue
        # A short user name such as `git` is a locator that ordinary names repeat; a
        # long one is often a token. A password is one at any length.
        for value, counted in (
            (username, username is not None and len(username) >= MIN_SECRET_LENGTH),
            (password, True),
        ):
            if value and counted:
                found.extend({value, unquote(value)})
    return found


def _diagnostic_values(config: dict[str, Any]) -> list[str] | None:
    """User information in this server's URLs, and credentials its fields and `NAME=value`
    arguments hold.

    Every field but `tools` is read: a large tool list, which is often what failed,
    cannot use up the walk, while any field a client may read can hold a credential.
    ``None`` when the fields exceed the bounded walk: a server that failed validation
    can be any shape, and its name is then not shown, as it never was before.
    """
    values: list[str] = []
    pending: list[Any] = [item for field, item in config.items() if field != "tools"]
    visited = 0
    while pending:
        visited += 1
        if visited > _DIAGNOSTIC_NODES:
            return None
        node = pending.pop()
        if isinstance(node, dict):
            # As for `env`: only a credential name's value, or a credential-shaped one.
            values.extend(secret_values(node))
            pending.extend(node.values())
        elif isinstance(node, list):
            pending.extend(node)
        elif isinstance(node, str):
            values.extend(_text_credentials(node))
    return values


def _text_credentials(text: str) -> list[str]:
    """URL user information in ``text``, or the credential of a `NAME=value` argument."""
    values: list[str] = []
    if "@" in text and "://" in text:
        for locator in _locators(text):
            if "@" in locator:
                values.extend(_user_info(locator))
    inline = _INLINE_ASSIGNMENT.fullmatch(text)
    if inline is not None:
        values.extend(secret_values({inline.group(1): inline.group(2)}))
    return values


# Nodes of one configuration document read for the values a declared name must not hold.
_KNOWN_VALUE_NODES = 1 << 17
# Maps whose values a client passes to a server or sends with its requests, and which
# no record publishes: environments (opencode's `environment` too), headers and Codex's
# query parameters and `shell_environment_policy.set`.
_VALUE_MAPS = frozenset({"env", "environment", "headers", "http_headers", "query_params", "set"})
# Settings whose `env` the host applies to every process it starts, MCP servers too.
_HOST_SETTINGS = frozenset(
    {(".claude", "settings.json"), (".claude", "settings.local.json"), (".cursor", "settings.json")}
)


def _configured_values(document: Any) -> list[str] | None:
    """Values of a configuration document that a server name declared in source must not hold.

    Beyond what a server's parsing collects: a credential-named value in any field, as
    Codex's `experimental_bearer_token` or a server's own `apiKey`, URL user
    information, `NAME=value` and `--flag value` arguments, and every value of at least
    ``MIN_SECRET_LENGTH`` characters in an environment, header or parameter map, none
    of which the inventory shows. The whole document is read, a server map that is not
    collected too. ``None`` past ``_KNOWN_VALUE_NODES`` nodes.
    """
    values: list[str] = []
    pending: list[tuple[object, Any]] = [(None, document)]
    visited = 0
    while pending:
        visited += 1
        if visited > _KNOWN_VALUE_NODES:
            return None
        key, node = pending.pop()
        if isinstance(node, dict):
            values.extend(secret_values(node))
            if key in _VALUE_MAPS:
                values.extend(
                    item
                    for item in node.values()
                    if isinstance(item, str) and len(item) >= MIN_SECRET_LENGTH
                )
            pending.extend(node.items())
        elif isinstance(node, list):
            pending.extend((None, item) for item in node)
            for flag, word in pairwise(node):
                if (
                    isinstance(flag, str)
                    and isinstance(word, str)
                    and _CLI_FLAG.fullmatch(flag)
                    and secret_like(flag, word)
                ):
                    values.append(word)
        elif isinstance(node, str):
            values.extend(_text_credentials(node))
    return values


def _policy_exclusions(files: ConfinedCollection, result: ScanResult) -> int:
    """Exclusions the walk recorded that leave the source search incomplete.

    A default-excluded entry such as ``.git``, ``venv`` or ``__pycache__`` is reported
    as a gap and handed to the search as unvisited, where it keeps the modules beside
    it uncertain, so it does not make the walk incomplete; an explicit collection-policy
    exclusion does, and so does any exclusion past the listing bound, which cannot be
    told apart. A collection that counts policy exclusions itself is asked instead.
    """
    recorded: int | None = getattr(files, "policy_exclusions_recorded", None)
    if recorded is not None:
        return recorded
    listed = result.surfaces_excluded
    policy = sum(
        1
        for entry in listed
        if not entry.endswith(DEFAULT_EXCLUDE_REASON)
        and not entry.endswith(AGENT_DEFAULT_EXCLUDE_REASON)
    )
    return policy + max(0, files.exclusions_recorded - len(listed))


class MCPScanner(Scanner):
    name = "mcp"
    _resolvers: _Resolvers | None = None

    def scan(self, project_root: Path, *, config_only: bool = False) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found_any = False
        walk_complete = False
        clients: dict[str, MCPClientComponent] = {}

        # Source text read while looking for SDK references is charged to this
        # collection too, so its byte limit leaves room for the source budget.
        with self._collection(
            project_root, result, max_total_bytes=source_collection_bytes()
        ) as files:
            links: list[Path] = []
            skipped: list[Path] = []
            sources = list(files.iter_files(directory_links=links, observed_excludes=skipped))
            walk_complete = files.failures_recorded == 0 and _policy_exclusions(files, result) == 0
            linked, linked_gaps = _linked_client_files(files, links)
            nested, directory_gaps = self._nested_client_files(files, [*sources, *linked])
            directory_gaps.update(path.as_posix() for path in linked_gaps)
            try:
                key, key_error = source_binding_key(), None
            except SourceBindingKeyError as exc:
                key, key_error = None, str(exc)
            self._resolvers = _Resolvers(files, result, self._read_mapping)
            known = None if config_only else KnownValues()
            launched: list[tuple[str, str, dict[str, Any]]] = []
            try:
                found_any = self._scan_dialects(
                    files,
                    result,
                    (*MCP_CONFIG_FILES, *nested),
                    key,
                    key_error,
                    clients,
                    known,
                    launched,
                )
            finally:
                self._resolvers = None
            result.components.extend(clients.values())
            result.surfaces_excluded.extend(
                f"{path}: {_DIRECTORY_GAP}" for path in sorted(directory_gaps)
            )
            if known is not None:
                self._read_host_settings(files, sources, links, known)
                self._scan_code_mcp_clients(
                    result, sources, known, [*links, *skipped], walk_complete, launched
                )

        if not found_any and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("mcp-config (no config files found)")

        return result

    @staticmethod
    def _nested_client_files(
        files: ConfinedCollection, sources: list[Path]
    ) -> tuple[list[str], set[str]]:
        """The walked client files that are not fixed root paths, in a stable order, and
        the walked files below a server directory that the collector does not read.

        Another spelling of one is a failure, beside the exact spelling too: a
        case-insensitive checkout holds one file for both names, with the content of
        whichever it wrote last.
        """
        nested: set[str] = set()
        gaps: set[str] = set()
        for path in sources:
            spelling = _client_spelling(path)
            if spelling is None:
                if _directory_gap(path):
                    gaps.add(path.as_posix())
            elif spelling != path.as_posix():
                files.report_case_variant(path, spelling)
            elif spelling not in _ROOT_CLIENT_FILES:
                nested.add(spelling)
        return sorted(nested), gaps

    def _scan_dialects(
        self,
        files: ConfinedCollection,
        result: ScanResult,
        paths: tuple[str, ...],
        key: bytes | None,
        key_error: str | None,
        clients: dict[str, MCPClientComponent],
        known: KnownValues | None,
        launched: list[tuple[str, str, dict[str, Any]]] | None = None,
    ) -> bool:
        """Read each client file in ``paths``; whether any of them was present.

        ``known`` gains the values of every file read that a name declared in source
        must not publish, also of a file or server map that is not collected.
        ``launched`` gains each collected file's raw server entries, so the source
        search can read what they start before their arguments are redacted.
        """
        found_any = False
        # Server references per host, sorted once at the end: sorting the union after
        # every file would cost the square of the number of nested client files.
        pending_refs: dict[str, set[str]] = {}
        parsed: dict[str, tuple[Any, list[str]]] = {}
        collected: list[tuple[McpDialect, dict[str, Any], _Entries, SecretScrubber, dict[int, Any]]]
        collected, literals = [], []
        for path in paths:
            dialect = _dialect(path)
            data = self._read_dialect(files, dialect, result, parsed, known)
            if data is None:
                continue
            found_any = True
            result.surfaces_scanned.append(dialect.path)
            if known is not None:
                configured = _configured_values(data)
                if configured is None:
                    known.refuse()
                else:
                    known.add(configured)
            if not isinstance(data, dict):
                result.scan_failures.append(f"{dialect.path}: expected a configuration object")
                continue
            read = self._server_entries(dialect, data, result)
            if read is None:
                continue
            entries = read.servers
            server_hits: dict[int, PositionHits] = {}
            values = self._file_secrets(
                [*entries, *(("", config) for config in read.dropped)], dialect.shape, server_hits
            )
            # Retain values from refused files when withholding names declared in source.
            if known is not None:
                known.add(values)
            if key_error is not None and entries:
                result.scan_failures.append(f"{dialect.path}: {key_error}")
                continue
            configs = {id(config): config for config in [*(c for _, c in entries), *read.dropped]}
            for server, hits in server_hits.items():
                literals.extend(_server_literals(configs[server], hits))
            unique = set(filter(None, values))
            wrapped_found: list[str] = []
            if len(unique) <= MAX_SECRETS_PER_FILE:
                try:
                    for wrapped in rewrapped_key_literals(data, tuple(unique)):
                        unique.add(wrapped)
                        wrapped_found.append(wrapped)
                        if len(unique) > MAX_SECRETS_PER_FILE:
                            break
                except WrappedKeySearchLimitError:
                    if known is not None:
                        known.refuse()
                    result.scan_failures.append(
                        f"{dialect.path}: wrapped credential comparison limit reached; not collected"
                    )
                    continue
            if len(unique) > MAX_SECRETS_PER_FILE:
                if known is not None:
                    known.refuse()
                result.scan_failures.append(
                    f"{dialect.path}: more than {MAX_SECRETS_PER_FILE} credential values in one "
                    "file; not collected"
                )
                continue
            if known is not None and wrapped_found:
                known.add(wrapped_found)
            file_secrets = SecretScrubber(unique)
            collected.append((dialect, data, read, file_secrets, server_hits))
        # A name may repeat a literal of any client file, so every file is read first.
        names = _Names(literals)
        for dialect, data, read, file_secrets, server_hits in collected:
            file_names = names.scoped(file_secrets.values)
            server_refs: list[str] = []
            if launched is not None:
                directory = _launch_directory(dialect.path)
                launched.extend(
                    (dialect.path, directory, config)
                    for config in [*(config for _, config in read.servers), *read.dropped]
                    if isinstance(config, dict)
                )
            for server_name, server_config in read.servers:
                problem = read.problems.get(server_name) or (
                    self._server_problem(server_config, dialect.shape)
                    if isinstance(server_config, dict)
                    else "invalid server configuration"
                )
                if problem is not None:
                    result.scan_failures.append(f"{dialect.path}: {problem}")
                    continue
                try:
                    mcp_comp, tool_comps = self._parse_server(
                        server_name,
                        server_config,
                        dialect,
                        key,
                        result,
                        file_secrets,
                        server_hits.get(id(server_config)),
                        file_names,
                        launcher_unknown=read.unknown.get(server_name),
                    )
                except SourceBindingKeyError as exc:
                    result.scan_failures.append(f"{dialect.path}: {exc}")
                    continue
                except (TypeError, ValueError, RecursionError):
                    # The whole server record is dropped with its risk findings, so the
                    # failure must say which server a reviewer no longer sees.
                    shown = self._diagnostic_server_name(server_name, server_config, file_secrets)
                    result.scan_failures.append(
                        f"{dialect.path}: invalid tool definition for server '{shown}'; "
                        "the server and its risks are not inventoried"
                    )
                    continue
                result.components.append(mcp_comp)
                result.components.extend(tool_comps)
                server_refs.append(mcp_comp.bom_ref)
            host = self._detect_host_from_config(dialect.path)
            if host and (any(key in data for key in dialect.maps) or server_refs):
                if host not in clients:
                    clients[host] = MCPClientComponent(
                        bom_ref=f"mcp-client:{host}",
                        name=f"{host} MCP client",
                        host_application=host,
                        server_refs=[],
                        config_path=dialect.path,
                        source_path=dialect.path,
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        properties={"collection_mode": "static-config", "config_paths": []},
                    )
                client = clients[host]
                pending_refs.setdefault(host, set(client.server_refs)).update(server_refs)
                client.properties["config_paths"].append(dialect.path)
        for host, refs in pending_refs.items():
            clients[host].server_refs = sorted(refs)
        return found_any

    @classmethod
    def _file_secrets(
        cls,
        entries: list[tuple[str, Any]],
        shape: str,
        server_hits: dict[int, PositionHits] | None = None,
    ) -> list[str]:
        """Credential values of every server in a file, inline launcher values included.

        One server's tool text or name may repeat a value that another server's
        environment, headers or launcher holds, so the file's values are scrubbed
        from each. A server that _server_problem refuses is never parsed, but every value
        _server_secrets reads for a parsed one still counts: refusing it must not publish
        what its siblings repeat. Only its launcher is not analysed, and the arguments of
        one past an argument limit are read only for the names they withhold. Each server's
        launch positions are read once, into ``server_hits`` by the server's identity.
        """
        values: list[str] = []
        for _, config in entries:
            if not isinstance(config, dict):
                values.extend(_malformed_values(config))
                continue
            values.extend(_shape_credentials(config, shape))
            if cls._server_problem(config, shape) is not None:
                hits = _declared_hits(config)
                declared, read = config, hits
                args = config.get("args")
                if isinstance(args, list) and len(args) > min(MAX_ARGUMENTS, MAX_LIST_ENTRIES):
                    # A server refused for its argument count must not fill the file's
                    # credential limit and so withhold every sibling from the inventory.
                    declared = {field: item for field, item in config.items() if field != "args"}
                    read = [hit for hit in hits if hit[0] != "argument"]
                for field, value in cls._invalid_field_values(declared, shape):
                    values.extend(_malformed_values(value, field))
                values.extend(_server_secrets(declared, Launch(), read))
                if server_hits is not None:
                    server_hits[id(config)] = hits
                continue
            try:
                launch = _server_launch(config)
            except (TypeError, ValueError, RecursionError):
                # The server's normal parsing path reports this failure.
                launch = Launch()
            hits = _server_hits(config)
            if server_hits is not None:
                server_hits[id(config)] = hits
            values.extend(_server_secrets(config, launch, hits))
        return list(dict.fromkeys(values))

    @staticmethod
    def _diagnostic_server_name(
        name: str, config: dict[str, Any], file_secrets: SecretScrubber | None = None
    ) -> str:
        """The server's name for a failure, redacted as a parsed server's name is.

        The file's prepared values hold this server's own values too; without a file
        context the server's environment, header and inline launcher values are
        collected as _parse_server collects them.
        """
        try:
            launch = _server_launch(config)
        except (TypeError, ValueError, RecursionError):
            return "[withheld]"
        scrubber = (
            file_secrets
            if file_secrets is not None
            else SecretScrubber(_server_secrets(config, launch))
        )
        # A name may repeat what only this server's text holds and no rule reads as a
        # credential: URL user information, or `NAME=value` passed to a launcher such
        # as `cross-env`, which the launch analysis does not unwrap.
        own = _diagnostic_values(config)
        if own is None:
            return "[withheld]"
        scrubber = scrubber.extended(own)
        # Clipping first can truncate a token so its recognizable shape is lost.
        return neutralize(redact_text(name, scrubber)[:256])

    def _read_dialect(
        self,
        files: ConfinedCollection,
        dialect: McpDialect,
        result: ScanResult,
        parsed: dict[str, tuple[Any, list[str]]],
        known: KnownValues | None = None,
    ) -> Any:
        if dialect.syntax == "json":
            return files.read_json(dialect.path, missing_ok=True)
        text = files.read_text(dialect.path, missing_ok=True)
        if text is None:
            return None
        if dialect.syntax == "yaml":
            # The bounded reader: an empty document holds no servers; anchors, aliases,
            # tags and a non-mapping are failures where a server could be declared.
            # A file read through several directory links is parsed once.
            names = (*dialect.maps, *(_SERVER_FIELDS if dialect.members else ()))
            cache_key = f"{names!r}\0{text}"
            if cache_key not in parsed:
                scratch = ScanResult(self.name)
                data = self._parse_yaml_mapping(
                    Path(dialect.path), text, scratch, inert_without=frozenset(names)
                )
                prefix = f"{Path(dialect.path).as_posix()}: "
                reasons = [failure.removeprefix(prefix) for failure in scratch.scan_failures]
                parsed[cache_key] = (data, reasons)
            data, reasons = parsed[cache_key]
            result.scan_failures.extend(f"{dialect.path}: {reason}" for reason in reasons)
            return data
        try:
            if dialect.syntax == "toml":
                return load_toml(text, parse_float=_finite_float)
            data = _load_jsonc(text)
        except (ValueError, RecursionError, MemoryError):
            syntax = "TOML" if dialect.syntax == "toml" else "JSON or duplicate keys"
            result.scan_failures.append(f"{dialect.path}: invalid {syntax}")
            return None
        if dialect.shape == "opencode" and _opencode_substitution_outside_values(text):
            # Parsed but not read: its values are unknown, so no source name may be published.
            if known is not None:
                known.refuse()
            result.scan_failures.append(
                f"{dialect.path}: opencode substitution outside one string value; the "
                "configuration depends on the environment and is not inventoried"
            )
            return None
        return data

    @staticmethod
    def _server_entries(
        dialect: McpDialect, data: dict[str, Any], result: ScanResult
    ) -> _Entries | None:
        entries: dict[str, Any] = {}
        problems: dict[str, str] = {}
        unknown: dict[str, str] = {}
        dropped: list[Any] = []
        experimental = data.get("experimental")
        if (
            dialect.shape == "continuerc"
            and isinstance(experimental, dict)
            and experimental.get("modelContextProtocolServers")
        ):
            result.surfaces_excluded.append(
                f"{dialect.path}: Continue workspace MCP servers "
                "(experimental.modelContextProtocolServers) not inventoried"
            )
        for key in dialect.maps:
            servers = data.get(key)
            if servers is None:
                continue
            if dialect.shape == "continue":
                if not isinstance(servers, list) or len(servers) > MAX_SERVERS_PER_FILE:
                    result.scan_failures.append(
                        f"{dialect.path}: invalid server list or MCP server limit "
                        f"({MAX_SERVERS_PER_FILE} per file) exceeded"
                    )
                    return None
                repeated: set[str] = set()
                for index, config in enumerate(servers, 1):
                    name = config.get("name") if isinstance(config, dict) else None
                    if not isinstance(name, str) or not name or name in entries or name in repeated:
                        dropped.append(config)
                    if isinstance(config, dict) and "uses" in config and name is None:
                        # The slug is not shown: it is the checkout's text, not an identity.
                        result.surfaces_excluded.append(
                            f"{dialect.path}: MCP server entry {index} references a hub block "
                            "whose launch is not resolved offline; not inventoried"
                        )
                    elif not isinstance(name, str) or not name:
                        result.scan_failures.append(
                            f"{dialect.path}: MCP server entry {index} declares no name and is "
                            "not inventoried"
                        )
                    elif name in entries or name in repeated:
                        repeated.add(name)
                    else:
                        entries[name] = config
                for name in sorted(repeated):
                    # Which entry the client keeps is not confirmed, so neither is read.
                    dropped.append(entries.pop(name))
                    result.scan_failures.append(
                        f"{dialect.path}: MCP server declared more than once; not inventoried"
                    )
                continue
            if not isinstance(servers, dict) or len(servers) + len(entries) > MAX_SERVERS_PER_FILE:
                result.scan_failures.append(
                    f"{dialect.path}: invalid server map or MCP server limit "
                    f"({MAX_SERVERS_PER_FILE} per file) exceeded"
                )
                return None
            for name, config in servers.items():
                if name in entries:
                    result.scan_failures.append(
                        f"{dialect.path}: MCP server declared under more than one server map"
                    )
                    if isinstance(config, dict):
                        config = _normalized_server(dialect.shape, config).config
                    dropped.append(config)
                    continue
                if dialect.shape != "map" and isinstance(config, dict):
                    normalized = _normalized_server(dialect.shape, config)
                    config = normalized.config
                    if normalized.problem is not None:
                        problems[name] = normalized.problem
                    if normalized.unknown is not None:
                        unknown[name] = normalized.unknown
                entries[name] = config
        if (
            dialect.members
            and not any(key in data for key in dialect.maps)
            and any(field in data for field in _SERVER_FIELDS)
        ):
            result.surfaces_excluded.append(
                f"{dialect.path}: MCP server file of unconfirmed shape; not inventoried"
            )
        commands: list[Any] = []
        for keys in dialect.server_commands:
            value: Any = data
            for key in keys:
                value = value.get(key) if isinstance(value, dict) else None
            # The client skips an empty command as it skips an absent one.
            if value is not None and value != "":
                commands.append(value)
        if len(commands) > 1:
            for cmd_item in commands:
                dropped.append({"command": cmd_item})
            result.scan_failures.append(
                f"{dialect.path}: MCP server command declared under more than one setting"
            )
        elif commands and not isinstance(commands[0], str):
            dropped.append({"command": commands[0]})
            result.scan_failures.append(f"{dialect.path}: invalid MCP server command")
        elif commands and _PLAIN_COMMAND.fullmatch(commands[0].strip(" \t")) is None:
            dropped.append({"command": commands[0]})
            result.scan_failures.append(
                f"{dialect.path}: MCP server command 'mcp' is not plain words and is not "
                "inventoried"
            )
        elif commands:
            command, *arguments = commands[0].split()
            # The client replaces a server map entry of the same name.
            if (replaced := entries.get("mcp")) is not None:
                dropped.append(replaced)
            entries["mcp"] = {"command": command, "args": arguments}
        tools = [
            tool
            for config in entries.values()
            if isinstance(config, dict) and isinstance(config.get("tools"), list)
            for tool in config["tools"]
        ]
        if len(tools) > MAX_TOOLS_PER_FILE:
            result.scan_failures.append(
                f"{dialect.path}: MCP tool limit ({MAX_TOOLS_PER_FILE} per file) exceeded"
            )
            return None
        nodes = 0
        for tool in tools:
            nodes += _json_shape(tool, MAX_FILE_NODES)[0]
            if nodes > MAX_FILE_NODES:
                result.scan_failures.append(
                    f"{dialect.path}: MCP tool definition limit ({MAX_FILE_NODES} nodes per file) "
                    "exceeded"
                )
                return None
        return _Entries(sorted(entries.items()), problems, unknown, tuple(dropped))

    @staticmethod
    def _invalid_field_values(config: dict[str, Any], shape: str) -> Iterator[tuple[str, Any]]:
        """Values whose type prevents an interpreted server field from being read."""
        for field, value in config.items():
            if not _interpreted(field, shape):
                continue
            if field in _STRING_FIELDS:
                valid = isinstance(value, str)
            elif field in _LIST_FIELDS:
                valid = isinstance(value, list) and all(isinstance(item, str) for item in value)
            elif field in _MAP_FIELDS:
                valid = isinstance(value, dict) and all(
                    isinstance(item, str) for item in value.values()
                )
            elif field in _BOOL_FIELDS:
                valid = isinstance(value, bool)
            elif field in _NUMBER_FIELDS:
                valid = isinstance(value, (int, float)) and not isinstance(value, bool)
            elif field in _OBJECT_FIELDS:
                valid = isinstance(value, dict)
            elif field == "gallery":
                valid = isinstance(value, (str, bool))
            elif field == "tools":
                valid = isinstance(value, list) and all(isinstance(tool, dict) for tool in value)
            else:
                continue
            if not valid:
                yield field, value

    @classmethod
    def _server_problem(cls, config: dict[str, Any], shape: str) -> str | None:
        """A type or size problem in a server entry; unknown fields are gaps, not failures."""
        if any(True for _ in cls._invalid_field_values(config, shape)):
            return "invalid server configuration"
        limits = (
            ("args", MAX_ARGUMENTS, "argument"),
            ("env", MAX_ENVIRONMENT, "environment variable"),
            ("headers", MAX_HEADERS, "header"),
            ("http_headers", MAX_HEADERS, "header"),
            ("tools", MAX_TOOLS_PER_SERVER, "tool"),
        )
        for field, limit, label in limits:
            if len(config.get(field, ())) > limit:
                return f"MCP server {label} limit ({limit}) exceeded"
        if any(len(config.get(field, ())) > MAX_LIST_ENTRIES for field in _LIST_FIELDS):
            return f"MCP server list limit ({MAX_LIST_ENTRIES} entries) exceeded"
        for tool in config.get("tools", ()):
            nodes, depth = _json_shape(tool, MAX_TOOL_NODES)
            if nodes > MAX_TOOL_NODES or depth > MAX_TOOL_DEPTH:
                return (
                    f"MCP tool definition limit ({MAX_TOOL_NODES} nodes, "
                    f"{MAX_TOOL_DEPTH} levels) exceeded"
                )
        # Every credential an authentication or extension settings object holds is
        # scrubbed, so all of it is read; one past the bound is refused, never read in part.
        for field, label in (
            ("oauth", "authentication"),
            ("auth", "authentication"),
            (_EXTENSION_SETTINGS, "extension"),
        ):
            if field in config and _interpreted(field, shape):
                nodes, depth = _json_shape(config[field], MAX_TOOL_NODES)
                if nodes > MAX_TOOL_NODES or depth > MAX_TOOL_DEPTH:
                    return (
                        f"MCP server {label} settings limit ({MAX_TOOL_NODES} nodes, "
                        f"{MAX_TOOL_DEPTH} levels) exceeded"
                    )
        return None

    def _parse_server(
        self,
        name: str,
        config: dict[str, Any],
        dialect: McpDialect,
        key: bytes | None,
        result: ScanResult,
        file_secrets: SecretScrubber | None = None,
        credential_hits: PositionHits | None = None,
        names: _Names | None = None,
        *,
        launcher_unknown: str | None = None,
    ) -> tuple[MCPServerComponent, list[ToolComponent]]:
        config_scope = dialect.path
        command = config.get("command", "")
        args = config.get("args", [])
        env = config.get("env", {})
        headers = {**config.get("headers", {}), **config.get("http_headers", {})}
        header_names = sorted({*headers, *config.get("env_http_headers", {})})
        endpoints = [config[field] for field in _ENDPOINT_FIELDS if config.get(field)]
        endpoint_url = endpoints[0] if endpoints else None
        launch = _server_launch(config)
        transport, transport_gap = self._transport(config, dialect, bool(command))
        server_ref = (
            "mcp-server:" + hash_canonical({"config": config_scope, "name": name}).split(":", 1)[1]
        )
        # Launch arguments are opaque executable inputs. Only the launcher's own
        # grammar is read; argument and environment values never leave.
        # The file's prepared values cover this server and its siblings, inline launcher
        # values included: this server's free text may repeat a value one of them holds.
        # Without a file context, _server_secrets collects them as _file_secrets does,
        # shadowed inline assignments included.
        if credential_hits is None:
            credential_hits = _server_hits(config)
        scrubber = file_secrets
        if scrubber is None:
            scrubber = SecretScrubber(_server_secrets(config, launch, credential_hits))
        own = _server_literals(config, credential_hits)
        names = (names or _Names(own).scoped(scrubber.values)).scoped(own=own)
        cwd = config.get("cwd")
        nested = _launch_directory(dialect.path) != ""
        # Clients do not trim a cwd: " ." is a directory the checkout can create.
        relocated = (
            launch.relocated or (isinstance(cwd, str) and cwd not in _ROOT_DIRECTORIES) or nested
        )
        environment = [*env.items(), *launch.environment]
        runner_sources, runner_reasons = _runner_environment(
            launch.family or "",
            environment,
            interactive=launch.interactive,
            xtrace=launch.xtrace,
        )
        environment_file = "envFile" in config or launch.injected_environment
        view = self._resolver_view(launch, relocated, environment, environment_file)
        identity = self._identity(
            name, config, launch, endpoint_url, env, scrubber, view, runner_sources
        )
        gaps: list[str] = []
        for gap in (identity.endpoint_gap, transport_gap):
            if gap:
                gaps.append(gap)
        if len(set(endpoints)) > 1:
            gaps.append("declares more than one endpoint field")
        unknown_fields = [
            field
            for field in config
            if field not in _KNOWN_FIELDS or not _interpreted(field, dialect.shape)
        ]
        command_fields = [field for field in unknown_fields if _COMMAND_FIELD.fullmatch(field)]
        if unknown_fields:
            count = len(unknown_fields)
            gaps.append(
                f"declares {count} field{'s' if count > 1 else ''} the collector does not interpret"
            )
        identity_unknown = self._identity_unknown(launch) or next(
            iter([*view.identity, *runner_reasons]), None
        )
        if launch.script_shell:
            # npm runs a configured call in place of its script shell.
            identity_unknown = next(
                (reason for reason in view.identity if reason.startswith("npm call setting")),
                identity_unknown,
            )
        if identity_unknown is None:
            identity_unknown = launcher_unknown
        if identity_unknown is None and not command and not endpoints:
            identity_unknown = _NO_LAUNCH
        if identity_unknown:
            gaps.append(f"launcher identity unknown ({identity_unknown})")
        if identity.withheld:
            gaps.append("identity withheld by environment-value redaction")
        raw_tool_names = [
            str(tool.get("name", "")) for tool in config.get("tools", []) if isinstance(tool, dict)
        ]
        if any(scrubber.contains(tool_name) for tool_name in raw_tool_names):
            gaps.append("tool name withheld by environment-value redaction")
        tool_lists, tool_lists_redacted = self._tool_lists(config, scrubber)
        if key is None and tool_lists_redacted:
            gaps.append("tool list entries withheld by redaction")
        name = identity.name
        tool_names = sorted(self._tool_name(tool_name, scrubber) for tool_name in raw_tool_names)
        packages = launch.packages
        # uv tool run and pipx name one tool package; --with adds dependencies to it.
        primary = (
            packages[0]
            if len(packages) == 1 or (packages and launch.family in {"uv-tool", "pip"})
            else None
        )
        launcher_package = (
            identity.package_identities[0]
            if primary is not None and primary.registry and not identity.sources
            else None
        )
        if launcher_package == "[withheld]":
            launcher_package = None
        version = (
            primary.version
            if primary is not None and identity.packages[0]["identity"] != "[withheld]"
            else None
        )
        version_pinned: bool | None = None
        if identity_unknown:
            version_pinned = False
        elif packages:
            version_pinned = all(package.pinned for package in packages)
        # An exact package URL claims what the server is; not while its launch is unknown.
        package_url = (
            _purl(primary)
            if primary is not None and launcher_package is not None and not identity_unknown
            else None
        )
        settings = self._client_settings(config, tool_lists, dialect.shape)
        context = dict(launch.context)
        loading = [
            variable
            for variable, value in environment
            if variable.upper() in _CODE_LOADING_ENVIRONMENT
            or _exported_function(variable, value)
            or _npm_key(variable) in _NPM_CODE_SETTINGS
        ]
        if loading:
            context["code_loading_environment"] = len(loading)
        if command_fields:
            context["command_fields"] = len(command_fields)
        if view.code:
            context["code_loading_setting"] = view.code

        risks = self._server_risks(
            name,
            launch=launch,
            credentials=_credential_positions(credential_hits, names),
            transport=transport,
            command=command,
            endpoint_url=endpoint_url,
            safe_endpoint=identity.endpoint,
            endpoint_gap=identity.endpoint_gap,
            identity_unknown=identity_unknown,
            sources=identity.sources,
            context=context,
            settings=settings,
            withheld=identity.withheld,
            endpoints=endpoints,
            remote_type=_declared_transport(config) not in (None, "stdio"),
        )
        resolver = sorted(view.binding)
        # The launcher package and its version are recorded; every other argument
        # (a served directory, a mount, a flag) is a redacted position.
        recorded = (
            {"-y", "--yes", *(package.spec for package in packages)} if launcher_package else set()
        )
        unbound = self._unbound_values(
            args,
            env,
            headers,
            endpoint_url,
            command,
            launch,
            recorded,
            identity,
            multiple_endpoints=len(endpoints) > 1,
        )
        unbound.extend(
            self._unbound_client_values(
                config, dialect.shape, nested=nested, redacted=tool_lists_redacted
            )
        )
        if resolver:
            unbound.append("project resolver settings")
        if unbound and key is None:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"MCP server '{name}' {UNBOUND_VALUES_DETAIL}: {'; '.join(unbound)}.",
                    recommendation=(
                        f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to "
                        "these values."
                    ),
                )
            )
        fields = _field_names(config, dialect.shape, names)
        launcher_properties: dict[str, Any] = {}
        if launch.launcher:
            launcher_properties["launcher"] = launch.launcher
        if launch.wrappers:
            launcher_properties["launcher_wrappers"] = list(launch.wrappers)
        if identity.executable and identity.executable != identity.command:
            launcher_properties["launcher_command"] = identity.executable
        if identity.packages:
            launcher_properties["packages"] = identity.packages
        if identity.sources:
            launcher_properties["package_sources"] = identity.sources
        # Repeated "[other]" names stay, so adding an unnamed setting changes the digest.
        resolver_names = sorted(
            "[redacted]" if scrubber.contains(label) or TOKEN_SHAPE.search(label) else label
            for label in view.names
        )
        if resolver_names:
            launcher_properties["resolver_settings"] = resolver_names
        if context:
            launcher_properties["launch_context"] = context
        if header_names:
            launcher_properties["header_names"] = _exported_names(header_names, names)
        if settings:
            launcher_properties["client_settings"] = settings
        source_config_hash = hash_canonical(
            {
                "profile": STATIC_CONFIG_HASH_PROFILE,
                "structure": {
                    "fields": fields,
                    "command": identity.command,
                    "launcher": launch.launcher,
                    "launcher_wrappers": launch.wrappers,
                    "launcher_command": identity.executable,
                    "packages": identity.packages,
                    "package_sources": identity.sources,
                    "resolver_settings": resolver_names,
                    "launch_context": context,
                    "transport": transport,
                    "endpoint": identity.endpoint,
                    "argument_count": len(args),
                    "environment_names": _exported_names(env, names),
                    "header_names": launcher_properties.get("header_names", []),
                    "client_settings": settings,
                    "tool_names": tool_names,
                },
            }
        )
        binding = _keyed_binding(key, config, resolver) if key is not None else {}

        server_comp = MCPServerComponent(
            bom_ref=server_ref,
            name=name,
            version=version,
            transport=transport,
            launcher_package=launcher_package,
            package_url=package_url,
            command=identity.command,
            args=[REDACTED for _ in args],
            env=_exported_environment(env, names),
            endpoint_url=identity.endpoint,
            version_pinned=version_pinned,
            source_path=config_scope,
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
            properties={
                "collection_mode": "static-config",
                "launch_arguments_redacted": bool(args),
                "endpoint_credentials_omitted": bool(endpoint_url),
                "declared_fields": fields,
                **launcher_properties,
                "source_values_bound": key is not None,
                "static_config_hash": source_config_hash,
                "static_config_hash_profile": STATIC_CONFIG_HASH_PROFILE,
                **binding,
            },
        )

        tools = self._extract_tools(
            name, config, scrubber, server_ref=server_ref, config_path=config_scope
        )
        server_comp.tool_count = len(tools)
        server_comp.tool_refs = [tool.bom_ref for tool in tools]
        result.surfaces_excluded.extend(
            f"{config_scope}: MCP server '{name}' {gap}" for gap in gaps
        )
        return server_comp, tools

    def _identity(
        self,
        name: str,
        config: dict[str, Any],
        launch: Launch,
        endpoint_url: str | None,
        env: dict[str, str],
        scrubber: SecretScrubber,
        view: _ResolverView,
        runner_sources: list[tuple[str, str]],
    ) -> _Identity:
        """Compute identity fields from raw values; withhold one that holds a secret value."""
        withheld: list[str] = []
        # Known values and the identifier rules are matched in the same raw name.
        shown_name = redact_text(name, scrubber, identifier=True)
        if scrubber.contains(name):
            withheld.append("name")
        command = self._safe_name(launch.command)
        if launch.command and scrubber.contains(launch.command):
            command = "[redacted-command]"
            withheld.append("command")
        # The effective command can come from the arguments, whose values never
        # leave; only a recognised runner, wrapper or interpreter name is exported.
        executable = launch.executable if known_executable(launch.executable) else None
        endpoint, endpoint_gap = (None, None)
        if endpoint_url:
            endpoint, endpoint_gap = self._endpoint(endpoint_url)
            if scrubber.contains(endpoint):
                endpoint = "[redacted]"
                withheld.append("endpoint")
        packages: list[dict[str, Any]] = []
        identities: list[str] = []
        for package in launch.packages:
            # A credential in the package position is withheld as _safe_name withholds
            # a token-shaped command; the name may be a normalised form of the spec.
            hidden = scrubber.contains(package.spec) or any(
                TOKEN_SHAPE.search(text) for text in (package.spec, package.name) if text
            )
            if hidden:
                withheld.append("launcher package")
            entry_identity = "[withheld]" if hidden else package.identity
            identities.append(entry_identity)
            packages.append(
                {
                    "identity": entry_identity,
                    "version": None if hidden else package.version,
                    "pinned": package.pinned,
                    "pin": package.pin,
                }
            )
        sources = self._package_sources(launch, env, scrubber, withheld, view, runner_sources)
        return _Identity(
            name=shown_name,
            command=command,
            executable=executable,
            endpoint=endpoint,
            endpoint_gap=endpoint_gap,
            packages=packages,
            package_identities=identities,
            sources=sources,
            withheld=sorted(set(withheld)),
        )

    @staticmethod
    def _safe_name(value: str | None) -> str | None:
        if value is None:
            return None
        if _SAFE_NAME.fullmatch(value) and not TOKEN_SHAPE.search(value):
            return value
        return "[redacted-command]"

    def _package_sources(
        self,
        launch: Launch,
        env: dict[str, str],
        scrubber: SecretScrubber,
        withheld: list[str],
        view: _ResolverView,
        runner_sources: list[tuple[str, str]],
    ) -> list[str]:
        """Exported sources that redirect package resolution: label and origin only."""
        launched = _Launched(str(package.name) for package in launch.packages if package.registry)
        found: list[tuple[str, str]] = [
            (_option_label(option, launched), value) for option, value in launch.sources
        ]
        found.extend(runner_sources)
        family = launch.family or ""
        environment = [*env.items(), *launch.environment]
        pattern = _REDIRECT_ENVIRONMENT.get(family)
        if pattern is not None and not view.environment:
            for variable, value in environment:
                if re.fullmatch(pattern, variable, re.IGNORECASE):
                    found.append((_environment_label(variable, launched), value))
        trust_pattern = _TRUST_ENVIRONMENT.get(family)
        if trust_pattern is not None:
            # An added CA or disabled TLS verification lets a proxy or another
            # host serve registry content; a proxy alone cannot.
            trust = [
                (variable, value)
                for variable, value in environment
                if re.fullmatch(trust_pattern, variable, re.IGNORECASE)
                and (variable.upper() != "NODE_TLS_REJECT_UNAUTHORIZED" or value.strip() == "0")
            ]
            if trust:
                trust += [
                    (variable, value)
                    for variable, value in environment
                    if re.fullmatch(_PROXY_ENVIRONMENT, variable, re.IGNORECASE)
                ]
            found.extend((_environment_label(variable), value) for variable, value in trust)
        found.extend(view.sources)
        sources: set[str] = {f"{label}=[unresolved]" for label in view.unresolved}
        for label, value in found:
            if scrubber.contains(label) or TOKEN_SHAPE.search(label):
                label = "[redacted]"
                withheld.append("package source")
            for location in _origin_label(value) or ["[set]"]:
                if scrubber.contains(location):
                    location = "[redacted]"
                    withheld.append("package source")
                sources.add(f"{label}={location}")
        return sorted(sources)

    def _resolver_view(
        self,
        launch: Launch,
        relocated: bool,
        environment: list[tuple[str, str]],
        environment_file: bool,
    ) -> _ResolverView:
        """Project resolver settings and package manager environment for registry packages."""
        view = _ResolverView()
        packages = [package for package in launch.packages if package.registry]
        if not packages:
            return view
        family = launch.family or ""
        if environment_file:
            # Variables from an environment file or secret store may redirect or
            # replace what the runner fetches; their names are not visible here.
            view.unresolved.append("environment-file")
        launched = _Launched(str(package.name) for package in packages)
        # The label and value of a `scope` from the environment, which wins over .npmrc.
        environment_scope: tuple[str, str] | None = None
        if family == "npm":
            view.environment = True
            for variable, value in environment:
                key = _npm_key(variable)
                if key is None or value == "":
                    continue
                if key == "scope":
                    environment_scope = (_environment_label(variable, launched), value)
                kind = _npm_setting(key, value)
                if kind == "identity":
                    view.identity.append(f"npm {key} setting from the environment")
                elif kind in {"source", "registry"}:
                    known = _setting_name(key, launched) != "[other]"
                    view.sources.append(
                        (
                            _environment_label(variable, launched)
                            if known
                            else "env:npm_config_[other]",
                            value,
                        )
                    )
        if family == "yarn":
            # Yarn reads every setting from YARN_<NAME> variables, yarnPath included.
            for variable, value in environment:
                setting = _YARN_CODE_ENVIRONMENT.get(variable.upper())
                if setting is not None and value:
                    view.identity.append(f"yarn {setting} setting from the environment")
        files = _RESOLVER_FILES.get(family, ())
        if self._resolvers is None or not files:
            return view
        if relocated:
            # Another working directory may hold its own resolver files.
            view.unresolved.append("working-directory")
        for path in files:
            file = self._resolvers.entries(path)
            if file.unresolved:
                view.unresolved.append(f"{path}:key")
            settings = dict(file.settings)
            binding = file.settings if file.binding_settings is None else file.binding_settings
            view.binding.extend([f"{path}:{key}", value] for key, value in binding)
            for key, value in file.settings:
                label = f"{path}:{_setting_name(key, launched)}"
                kind = _file_setting(path, family, key, value, launched)
                if kind == "identity":
                    if path == ".npmrc":
                        view.identity.append(f"npm {key} setting from {path}")
                    elif path == "bunfig.toml":
                        view.identity.append(f"{path} {key} preloads local code")
                    else:
                        view.identity.append(f"{path} {key} replaces or extends yarn")
                elif kind == "code":
                    view.code += 1
                elif kind == "source":
                    view.sources.append((label, value))
                elif kind == "unresolved":
                    view.unresolved.append(label)
            registry_packages = (
                []
                if path in {"uv.toml", "pyproject.toml", ".env.yarn", "deno.json", "deno.jsonc"}
                else packages
            )
            selected_keys: set[str] = set()
            default = "npmRegistryServer" if path == ".yarnrc.yml" else "registry"
            scope_label, scope = (
                environment_scope or (f"{path}:scope", settings.get("scope", ""))
                if path == ".npmrc"
                else ("", "")
            )
            if expands(scope) and not any(npm_scope_registry(key) for key in settings):
                # Whatever scope the environment names, no setting here is its registry.
                scope = ""
            for package in registry_packages:
                name = package.name or ""
                chosen = npm_registry_settings(settings, name, default, scope)
                if launch.launcher not in {"npx", "npm exec"}:
                    # pnpm and Bun ignore `scope` and take the default registry, so for a
                    # launcher other than npm's both settings count.
                    chosen += npm_registry_settings(settings, name, default)
                for selected in dict.fromkeys(chosen):
                    selected_keys.add(selected)
                    view.sources.append(
                        (scope_label, scope)
                        if selected == "scope"
                        else (
                            f"{path}:{_setting_name(selected, launched, selected=True)}",
                            settings[selected],
                        )
                    )
            view.names.extend(
                f"{path}:{_setting_name(key, launched, selected=key in selected_keys)}"
                for key, _value in file.settings
            )
        return view

    @staticmethod
    def _identity_unknown(launch: Launch) -> str | None:
        """Why a launcher's identity or pin cannot be established, from a fixed vocabulary."""
        if launch.unknown is not None:
            return launch.unknown
        reasons = {
            "git": "git source without a full commit",
            "url": "URL source",
            "path": "local path or archive source",
            "unknown": "unparsed package reference",
        }
        for package in launch.packages:
            if package.ecosystem == "git" and package.pinned:
                continue
            if package.ecosystem in reasons:
                return reasons[package.ecosystem]
        return None

    @staticmethod
    def _tool_name(name: str, scrubber: SecretScrubber) -> str:
        return redact_text(name, scrubber, identifier=True)

    def _transport(
        self, config: dict[str, Any], dialect: McpDialect, has_command: bool
    ) -> tuple[str, str | None]:
        declared = _declared_transport(config)
        gap = (
            "declares an unrecognised transport type"
            if declared is None and isinstance(_declared_type(config), str)
            else None
        )
        # Gemini CLI chooses the transport from command, url and httpUrl, not a type.
        if declared is not None and not (has_command and dialect.url_transport):
            return declared, None
        if has_command:
            return "stdio", gap
        if config.get("httpUrl"):
            return "streamable-http", gap
        url = next((config[field] for field in _ENDPOINT_FIELDS if config.get(field)), None)
        if url is None:
            return "stdio", gap
        if dialect.url_transport and config.get("url"):
            return dialect.url_transport, gap
        try:
            parsed = urlsplit(url)
        except ValueError:
            return "streamable-http", gap
        if parsed.scheme.lower() in {"ws", "wss"}:
            return "websocket", gap
        return ("sse" if "sse" in parsed.path.split("/") else "streamable-http"), gap

    @staticmethod
    def _endpoint(url: str) -> tuple[str, str | None]:
        """Export an origin only for an authority every URL parser reads the same way."""
        if expands(url):
            return "[redacted]", "endpoint depends on environment expansion"
        if any(char.isspace() or ord(char) < 32 for char in url):
            return "[redacted]", "endpoint URL cannot be parsed"
        try:
            parsed = urlsplit(url)
            hostname = parsed.hostname
            _ = parsed.port
        except ValueError:
            return "[redacted]", "endpoint URL cannot be parsed"
        if (
            not parsed.scheme
            or not hostname
            or "\\" in parsed.netloc
            or origin(url) is None
            or any(char.isspace() or ord(char) < 32 for char in parsed.netloc)
        ):
            return "[redacted]", "endpoint authority is ambiguous"
        return sanitized_origin(url), None

    @classmethod
    def _tool_lists(
        cls, config: dict[str, Any], scrubber: SecretScrubber
    ) -> tuple[dict[str, list[str]], bool]:
        """Each approval and filter field's sorted names as exported, and whether one changed.

        Every entry is redacted once here: against a file's values that is the costly
        step. A known value in an entry is always replaced, so a change covers it.
        """
        lists: dict[str, list[str]] = {}
        changed = False
        for field in _TOOL_LIST_FIELDS:
            entries = config.get(field)
            if not entries:
                continue
            shown = [cls._tool_name(entry, scrubber) for entry in entries]
            changed = changed or shown != entries
            lists[field] = sorted(shown)
        return lists, changed

    @staticmethod
    def _client_settings(
        config: dict[str, Any], tool_lists: dict[str, list[str]], shape: str
    ) -> dict[str, Any]:
        """Client behaviour switches as booleans and counts, and the tool names they name.

        Tool names are identifiers, not values: swapping which tool is auto-approved or
        filtered keeps every count, so the names must be exported for diff to see it.
        """
        settings: dict[str, Any] = {}
        # Clients read only one of these fields, so a tool moved between them changes
        # what is approved without changing the merged list.
        approved = {
            field: tool_lists[field] for field in _TOOL_APPROVAL_FIELDS if field in tool_lists
        }
        if config.get("trust") is True:
            settings["auto_approve"] = "all"
        elif approved:
            settings["auto_approve"] = sum(len(names) for names in approved.values())
        if approved:
            settings["auto_approved_tools"] = approved
        if config.get("disabled") is True or config.get("enabled") is False:
            settings["disabled"] = True
        if config.get(_OAUTH_DISABLED) is True and _interpreted(_OAUTH_DISABLED, shape):
            settings["oauth_disabled"] = True
        for field, label in (
            ("cwd", "working_directory"),
            ("envFile", "environment_file"),
            ("oauth", "oauth"),
            ("auth", "authentication"),
            ("watchPaths", "watch_paths"),
            ("bearer_token_env_var", "bearer_token_variable"),
            ("dev", "development_mode"),
            (_EXTENSION_SETTINGS, "extension_settings"),
        ):
            if field in config and _interpreted(field, shape):
                settings[label] = True
        filters = {field: tool_lists[field] for field in _TOOL_FILTER_FIELDS if field in tool_lists}
        if filters:
            settings["tool_filters"] = sum(len(names) for names in filters.values())
            settings["tool_filter_names"] = filters
        return settings

    @staticmethod
    def _unbound_values(
        args: list[str],
        env: dict[str, str],
        headers: dict[str, str],
        endpoint_url: str | None,
        command: str,
        launch: Launch,
        recorded: set[str],
        identity: _Identity,
        *,
        multiple_endpoints: bool = False,
    ) -> list[str]:
        """Values only the keyed binding covers, named by kind."""
        unbound = []
        if command and (re.search(r"[\\/]", command) or launch.wrappers):
            unbound.append("command path")
        elif command and identity.command != command.strip(" \t\r\n\f\v"):
            # A redacted command, or one exported case-folded or without its Windows
            # suffix: MCPServer and mcpserver are different files on POSIX.
            unbound.append("command")
        if identity.endpoint == "[redacted]" or multiple_endpoints:
            unbound.append("endpoint")
        if any(arg not in recorded for arg in args):
            unbound.append("launch arguments")
        if any(env.values()):
            unbound.append("environment values")
        if headers:
            unbound.append("header values")
        if endpoint_url and (
            _has_path_or_query(endpoint_url) or "#" in endpoint_url or _has_userinfo(endpoint_url)
        ):
            unbound.append("endpoint path and query")
        return unbound

    @staticmethod
    def _unbound_client_values(
        config: dict[str, Any], shape: str, *, nested: bool, redacted: bool
    ) -> list[str]:
        """Client settings exported only as present or redacted, whose values only the key covers.

        A nested file's servers start in its own directory, which "." and
        "${workspaceFolder}" name differently, so there any cwd is unbound.
        """
        unbound = []
        if "cwd" in config:
            cwd = config.get("cwd")
            if nested or not (isinstance(cwd, str) and cwd in _ROOT_DIRECTORIES):
                unbound.append("working directory")
        for label, fields in (
            ("environment file", ("envFile",)),
            ("watch paths", ("watchPaths",)),
            ("authentication settings", ("oauth", "auth")),
            ("development settings", ("dev",)),
            ("extension settings", (_EXTENSION_SETTINGS,)),
            (
                "forwarded environment variable names",
                ("env_vars", "bearer_token_env_var", "env_http_headers"),
            ),
        ):
            if any(config.get(field) and _interpreted(field, shape) for field in fields):
                unbound.append(label)
        if redacted:
            unbound.append("redacted tool list entries")
        return unbound

    def _server_risks(
        self,
        name: str,
        *,
        launch: Launch,
        transport: str,
        command: str,
        endpoint_url: str | None,
        safe_endpoint: str | None,
        endpoint_gap: str | None,
        identity_unknown: str | None,
        sources: list[str],
        context: dict[str, int],
        settings: dict[str, Any],
        withheld: list[str],
        endpoints: list[str],
        remote_type: bool,
        credentials: list[tuple[str, str]],
    ) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []

        def add(severity: RiskSeverity, category: str, detail: str, advice: str) -> None:
            risks.append(
                RiskAssessment(
                    severity=severity, category=category, detail=detail, recommendation=advice
                )
            )

        floating = [p for p in launch.packages if p.registry and not p.pinned]
        if any(p.ecosystem != "oci" for p in floating):
            add(
                RiskSeverity.HIGH,
                "version_pinning",
                f"MCP server '{name}' uses an unpinned package reference (arguments omitted).",
                "Pin to an exact version and store a hash of the tool schema.",
            )
        if any(p.ecosystem == "oci" and p.pin != "tag" for p in floating):
            add(
                RiskSeverity.HIGH,
                "version_pinning",
                f"MCP server '{name}' container image has neither a digest nor a release tag.",
                "Pin to a SHA256 artifact digest and verify its provenance.",
            )
        if (
            launch.unknown is None
            and launch.launcher in _TRANSITIVE_RUNNERS
            and any(
                package.pinned and package.pin == "version" and package.registry
                for package in launch.packages
            )
        ):
            add(
                RiskSeverity.MEDIUM,
                "transitive_resolution",
                (
                    f"MCP server '{name}' pins its package but resolves dependencies at launch "
                    "without a lockfile."
                ),
                "Vendor a lockfile-installed server, or launch an image by digest.",
            )
        if any(p.ecosystem == "oci" and p.pin == "tag" for p in floating):
            add(
                RiskSeverity.MEDIUM,
                "mutable_image_tag",
                f"MCP server '{name}' container image lacks an immutable digest pin.",
                "Pin to a SHA256 artifact digest and verify its provenance.",
            )
        if identity_unknown:
            add(
                RiskSeverity.HIGH,
                "launcher_identity",
                f"MCP server '{name}' launcher identity and pin are unknown: {identity_unknown}.",
                "Launch a registry package pinned to an exact version, or an image pinned by "
                "digest, in a form the inventory classifies.",
            )
        if sources:
            labels = sorted({source.split("=", 1)[0] for source in sources})
            add(
                RiskSeverity.MEDIUM,
                "package_source",
                f"MCP server '{name}' resolves packages through a non-default source "
                f"({', '.join(labels)}); package name and version do not establish identity.",
                "Review that registry or index, and pin an artifact digest or integrity hash.",
            )
        # A client may start the command whatever transport the server declares.
        if command:
            add(
                RiskSeverity.MEDIUM,
                "local_process",
                f"MCP server '{name}' uses stdio transport (local process)."
                if transport == "stdio"
                else f"MCP server '{name}' declares a launch command (local process) and a "
                "remote transport.",
                "Ensure the command binary is integrity-checked.",
            )
        if endpoint_url and _has_userinfo(endpoint_url):
            add(
                RiskSeverity.HIGH,
                "transport_security",
                f"MCP server '{name}' endpoint URL embeds credentials: {safe_endpoint}",
                "Supply the credential through a header or environment reference.",
            )
        elif endpoint_url and endpoint_gap is None and not self._secure_endpoint(endpoint_url):
            # An origin withheld for a credential value is still a literal URL.
            add(
                RiskSeverity.HIGH,
                "transport_security",
                f"MCP server '{name}' endpoint is not HTTPS: {safe_endpoint}",
                "Use HTTPS for all remote MCP server connections.",
            )
        if any(
            _has_userinfo(url)
            or (self._endpoint(url)[1] is None and not self._secure_endpoint(url))
            for url in endpoints
            if url != endpoint_url
        ):
            # A client may connect to any of them: Gemini CLI prefers httpUrl to url.
            add(
                RiskSeverity.HIGH,
                "transport_security",
                f"MCP server '{name}' declares another endpoint that is not HTTPS or embeds "
                "credentials.",
                "Declare one HTTPS endpoint, with credentials in a header or environment "
                "reference.",
            )
        if endpoint_url and endpoint_gap:
            dynamic = expands(endpoint_url)
            add(
                RiskSeverity.MEDIUM if dynamic else RiskSeverity.HIGH,
                "endpoint_identity",
                f"MCP server '{name}' endpoint depends on the environment."
                if dynamic
                else f"MCP server '{name}' endpoint host cannot be established from its URL.",
                "Declare a literal https:// URL whose host every URL parser reads the same way.",
            )
        if command and (endpoints or remote_type):
            add(
                RiskSeverity.LOW,
                "transport_ambiguity",
                f"MCP server '{name}' declares both a launch command and an endpoint."
                if endpoints
                else f"MCP server '{name}' declares a launch command and a remote transport type.",
                "Declare either a command or an endpoint, and an explicit transport type.",
            )
        high = [label for flag, label in _CONTEXT_HIGH.items() if context.get(flag)]
        if context.get("command_fields"):
            high.append("a command-valued field")
        if high:
            add(
                RiskSeverity.HIGH,
                "launch_context",
                f"MCP server '{name}' has high-risk launch settings: {', '.join(high)}.",
                "Remove host-level privileges and command-valued fields, or isolate the server.",
            )
        medium = [label for flag, label in _CONTEXT_MEDIUM.items() if context.get(flag)]
        if medium:
            add(
                RiskSeverity.MEDIUM,
                "launch_context",
                f"MCP server '{name}' launch widens its execution context: {', '.join(medium)}.",
                "Review the launch options and environment before approving this server.",
            )
        if context.get("shell_wrapper") and not identity_unknown:
            add(
                RiskSeverity.LOW,
                "launch_context",
                f"MCP server '{name}' is launched through a shell or wrapper.",
                "Launch the server executable directly.",
            )
        approve = settings.get("auto_approve")
        if approve:
            scope = (
                "all tools are trusted" if approve == "all" else f"{approve} tools auto-approved"
            )
            add(
                RiskSeverity.MEDIUM,
                "auto_approval",
                f"MCP server '{name}' tools run without per-call approval: {scope}.",
                "Require human approval for tool calls with side effects.",
            )
        if credentials:
            listed = "; ".join(
                f"{position} ({kind})"
                for position, kind in credentials[:LISTED_CREDENTIAL_POSITIONS]
            )
            if (more := len(credentials) - LISTED_CREDENTIAL_POSITIONS) > 0:
                # Collection stops at the bound, so past it the count is a floor.
                least = "at least " if len(credentials) >= MAX_CREDENTIAL_POSITIONS else ""
                listed += f"; and {least}{more} more position{'s' if more > 1 else ''}"
            add(
                RiskSeverity.HIGH,
                "credential_exposure",
                f"MCP server '{name}' records a literal credential in its launch: {listed}.",
                "Replace each literal with an environment reference such as ${NAME}, and "
                "rotate the credential: it is committed.",
            )
        if withheld:
            add(
                RiskSeverity.MEDIUM,
                "completeness",
                f"MCP server '{name}' identity fields are withheld because environment or header "
                f"values occur in them: {', '.join(withheld)}.",
                f"Keep credentials out of names, hosts and package references, and set "
                f"{SOURCE_BINDING_KEY_ENV} during collection.",
            )
        return risks

    def _extract_tools(
        self,
        server_name: str,
        config: dict[str, Any],
        secrets: SecretScrubber | None = None,
        *,
        server_ref: str,
        config_path: str,
    ) -> list[ToolComponent]:
        # Deferred: the prompt collector imports this module for the binding key's name.
        from nexus_symbiote.scanners.prompt import definition_text_risks

        tools_config = config.get("tools", [])
        tool_comps = []
        seen_refs: set[str] = set()
        scrubber = secrets if secrets is not None else SecretScrubber()

        if isinstance(tools_config, list):
            for tool_def in tools_config:
                if isinstance(tool_def, dict):
                    t_name = tool_def.get("name", "unknown")
                    t_desc = tool_def.get("description", "")
                    t_schema = tool_def.get("inputSchema", tool_def.get("input_schema"))
                    t_annotations = tool_def.get("annotations", {})
                    if (
                        not isinstance(t_name, str)
                        or not isinstance(t_desc, str)
                        or not isinstance(t_annotations, dict)
                        or (t_schema is not None and not isinstance(t_schema, dict))
                    ):
                        raise ValueError("invalid tool fields")

                    def_hash = hash_tool_definition(
                        t_name,
                        t_desc,
                        t_schema,
                        t_annotations,
                        **tool_definition_extensions(tool_def),
                    )
                    tool_ref = (
                        "tool:"
                        + hash_canonical({"server": server_ref, "name": t_name}).split(":", 1)[1]
                    )
                    if tool_ref in seen_refs:
                        raise ValueError("duplicate tool name")
                    seen_refs.add(tool_ref)

                    side_effect = self._classify_side_effects(t_annotations, t_name)
                    conflict = self._read_only_conflict(t_annotations, side_effect)
                    caps = self._infer_capabilities(t_name, t_desc, t_annotations)
                    safe = redact_descriptor(
                        {
                            "name": t_name,
                            "description": t_desc,
                            "inputSchema": t_schema,
                            "annotations": t_annotations,
                        },
                        scrubber,
                    )
                    t_name = self._tool_name(t_name, scrubber)
                    display_hash = hash_tool_definition(
                        t_name, safe["description"], safe["inputSchema"], safe["annotations"]
                    )

                    # Read before redaction: text shaped like a credential is withheld from
                    # the record, and a host still shows the model what it hid.
                    risks = definition_text_risks(tool_def, f"{config_path}: tool {t_name}")
                    if side_effect in (
                        SideEffectProfile.DESTRUCTIVE,
                        SideEffectProfile.FINANCIAL_TRANSACTION,
                    ):
                        risks.append(
                            RiskAssessment(
                                severity=RiskSeverity.HIGH,
                                category="capability_scope",
                                detail=f"Tool '{t_name}' has {side_effect.value} side effects.",
                                recommendation="Ensure human-in-the-loop approval for destructive operations.",
                            )
                        )
                    if conflict:
                        risks.append(
                            RiskAssessment(
                                severity=RiskSeverity.MEDIUM,
                                category="capability_scope",
                                detail=f"Tool '{t_name}' is declared read-only but named for a destructive operation.",
                                recommendation="Verify the tool's effects before relying on its readOnlyHint.",
                            )
                        )

                    tool_comps.append(
                        ToolComponent(
                            bom_ref=tool_ref,
                            name=t_name,
                            mcp_server_ref=server_ref,
                            source_path=config_path,
                            description_text=safe["description"],
                            input_schema=safe["inputSchema"],
                            definition_hash=def_hash,
                            redacted_definition_hash=display_hash
                            if display_hash != def_hash
                            else None,
                            definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
                            annotations=safe["annotations"],
                            capabilities=CapabilityDeclaration(
                                capabilities=caps,
                                side_effect_profile=side_effect,
                            ),
                            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                            risks=risks,
                            properties={
                                "collection_mode": "static-config",
                                "capability_evidence": "unverified-declaration-and-name-heuristic",
                                "definition_hash_subject": "original-declared-descriptor",
                                "descriptor_output_may_be_redacted": True,
                            },
                        )
                    )
        return tool_comps

    @staticmethod
    def _secure_endpoint(url: str) -> bool:
        """Classify HTTPS or WSS, or exact loopback HTTP or WS, without connecting."""
        try:
            parsed = urlsplit(url)
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                return False
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return False
            if parsed.scheme in {"https", "wss"}:
                return True
            if parsed.scheme not in {"http", "ws"}:
                return False
            if parsed.hostname.lower() == "localhost":
                return True
            try:
                return ipaddress.ip_address(parsed.hostname).is_loopback
            except ValueError:
                return False
        except ValueError:
            return False

    @staticmethod
    def _detect_host_from_config(config_name: str) -> str | None:
        template = _template(config_name)
        if template is not None and template.host is not None:
            return template.host
        path = Path(config_name)
        return _CLIENTS_BY_NAME.get(path.name) or next(
            (host for part in path.parts[:-1] if (host := _HOST_DIRECTORIES.get(part))), None
        )

    @staticmethod
    def _read_host_settings(
        files: ConfinedCollection, sources: list[Path], links: list[Path], known: KnownValues
    ) -> None:
        """Add the values of Claude Code and Cursor settings, whose `env` reaches servers.

        The IDE agent collector reports these files and their failures; a file it may
        not read whole leaves every declared name unread here instead.
        """
        paths = [path for path in sources if tuple(path.parts[-2:]) in _HOST_SETTINGS]
        paths.extend(
            link / name
            for link in links
            for directory, name in sorted(_HOST_SETTINGS)
            if link.name == directory and files.regular_file(link / name) is not None
        )
        for path in paths:
            found = files.regular_file(path)
            if found is None or found[1] > files.max_file_bytes:
                known.refuse()
                continue
            raw = files.read_bytes(path, missing_ok=True)
            try:
                configured = None if raw is None else _configured_values(_load_jsonc(raw.decode()))
            except (UnicodeDecodeError, ValueError, RecursionError, MemoryError):
                configured = None
            if configured is None:
                known.refuse()
            else:
                known.add(configured)

    def _scan_code_mcp_clients(
        self,
        result: ScanResult,
        sources: list[Path],
        known: KnownValues,
        unvisited: list[Path],
        walk_complete: bool,
        launched: list[tuple[str, str, dict[str, Any]]],
    ) -> None:
        if self._files is None:
            raise RuntimeError("_scan_code_mcp_clients called outside a _collection context")
        from nexus_symbiote.scanners.mcp_sources import collect_source_references

        budget = SourceBudget("MCP source references", result)
        collect_source_references(
            self._files,
            result,
            sources,
            budget,
            known,
            unvisited=unvisited,
            walk_complete=walk_complete,
            launched=launched,
        )

    @staticmethod
    def _tokenize_identifier(text: str) -> set[str]:
        """Words of a tool name or description, each also without a plural or verb ending.

        Descriptions come from the checkout and may be megabytes long, so every
        pattern here is linear: a repeated capital class before the acronym
        boundary rescanned each run of capitals from every position in it.
        """
        expanded = _ACRONYM_BOUNDARY.sub(r"\1 \2", _CAMEL_BOUNDARY.sub(r"\1 \2", text))
        words = set(_WORD.findall(expanded.lower()))
        forms = set(words)
        for word in words:
            for ending in _WORD_ENDINGS:
                if len(word) <= len(ending) + 1 or not word.endswith(ending):
                    continue
                stem = word[: -len(ending)]
                forms.add(stem)
                if ending in {"ed", "ing"}:
                    forms.add(stem + "e")
                    if stem[-1] == stem[-2]:
                        forms.add(stem[:-1])
                elif ending == "es" and stem.endswith("i"):
                    forms.add(stem[:-1] + "y")
        return forms

    def _classify_side_effects(
        self, annotations: dict[str, Any], tool_name: str
    ) -> SideEffectProfile:
        """Profile from boolean hints and name words; a read-only hint never hides harm."""
        tokens = self._tokenize_identifier(tool_name)
        money = bool(tokens & _MONEY_VERBS) or (
            bool(tokens & {"transfer", "send"}) and bool(tokens & _MONEY_NOUNS)
        )
        harmful = (
            SideEffectProfile.FINANCIAL_TRANSACTION
            if money
            else SideEffectProfile.DESTRUCTIVE
            if tokens & _DESTRUCTIVE
            else None
        )
        if annotations.get("destructiveHint") is True:
            return SideEffectProfile.DESTRUCTIVE
        if annotations.get("readOnlyHint") is True:
            return harmful or SideEffectProfile.READ_ONLY
        if harmful:
            return harmful
        if tokens & _STATE_CHANGING:
            return SideEffectProfile.STATE_MODIFYING
        if tokens & _READING:
            return SideEffectProfile.READ_ONLY
        return SideEffectProfile.UNKNOWN

    @staticmethod
    def _read_only_conflict(annotations: dict[str, Any], side_effect: SideEffectProfile) -> bool:
        """A read-only hint on a tool whose name reads destructive or financial."""
        return (
            annotations.get("readOnlyHint") is True
            and annotations.get("destructiveHint") is not True
            and side_effect in _HARMFUL
        )

    def _infer_capabilities(
        self, tool_name: str, description: str, annotations: dict[str, Any]
    ) -> list[CapabilityClass]:
        caps = []
        tokens = self._tokenize_identifier(f"{tool_name} {description}")
        if tokens & {
            "file",
            "filename",
            "filepath",
            "filesystem",
            "directory",
            "folder",
            "path",
            "fs",
            "disk",
        }:
            caps.append(CapabilityClass.FILESYSTEM)
        if tokens & {"http", "https", "url", "fetch", "request", "api", "endpoint", "web"}:
            caps.append(CapabilityClass.NETWORK)
        if tokens & {
            "exec",
            "execute",
            "executable",
            "run",
            "shell",
            "command",
            "bash",
            "terminal",
            "script",
        }:
            caps.append(CapabilityClass.EXECUTE)
        if tokens & (_MONEY_VERBS | _MONEY_NOUNS | {"billing", "transfer"}):
            caps.append(CapabilityClass.PAYMENT)
        if tokens & {
            "credential",
            "secret",
            "token",
            "password",
            "passwd",
            "passphrase",
            "key",
            "apikey",
            "auth",
            "oauth",
            "authenticate",
            "authentication",
            "authorize",
            "authorization",
        }:
            caps.append(CapabilityClass.CREDENTIALS)
        if tokens & (_STATE_CHANGING | _DESTRUCTIVE):
            caps.append(CapabilityClass.WRITE)
        elif tokens & _READING:
            caps.append(CapabilityClass.READ)
        return caps


# Whole words of _tokenize_identifier, each also matched without a plural or verb
# ending: "compute_stats" does not read as "put", nor "dropdown" as "drop". "patch"
# and "upload" are left out: the stem rule makes "monkey patch" and "the uploaded
# executable" in a description read as writes.
_DESTRUCTIVE = _names(
    "delete remove drop destroy purge truncate wipe erase kill terminate uninstall revoke "
    "unlink rmdir"
)
_MONEY_VERBS = _names("pay payout refund charge purchase checkout withdraw withdrawal deposit wire")
_MONEY_NOUNS = _names("funds fund money payment balance cash invoice crypto coins usd eur")
_STATE_CHANGING = _names(
    "create update write send post put insert modify edit set add append move rename commit "
    "push publish deploy merge approve"
)
_READING = _names("get list read search query fetch find lookup describe show view count inspect")
_HARMFUL = frozenset({SideEffectProfile.DESTRUCTIVE, SideEffectProfile.FINANCIAL_TRANSACTION})
