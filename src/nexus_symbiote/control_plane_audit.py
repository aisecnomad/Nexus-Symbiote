"""Control-plane hook targets, CI/hosted tools, steering surfaces, bridges, and identity reachability."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import posixpath
import re
import shlex
from bisect import bisect_left, bisect_right
from collections import deque
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from functools import cached_property
from typing import TYPE_CHECKING, Any
from urllib.parse import urlsplit

import yaml

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge, Relationship
from nexus_symbiote.core.enums import AssuranceLevel, ComponentType, RiskSeverity
from nexus_symbiote.core.hashing import open_regular_file, parse_json_strict
from nexus_symbiote.core.models import (
    AgentComponent,
    CapabilityDeclaration,
    IDEAgentComponent,
    MCPServerComponent,
    ModelComponent,
    SkillPackageComponent,
    ToolComponent,
)
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.scanners.credential_files import credential_gap, credential_shaped
from nexus_symbiote.scanners.mcp_launch import npm_spec, python_spec
from nexus_symbiote.utils.confined import ConfinedCollection
from nexus_symbiote.utils.jsonc import strip_jsonc
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize

if TYPE_CHECKING:
    from pathlib import Path


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _contains_secret(text: str) -> bool:
    return redact_text(text) != text


def _words(text: str) -> frozenset[str]:
    return frozenset(text.split())


def _tup(text: str) -> tuple[str, ...]:
    return tuple(text.split())


def _rec(**kw: Any) -> dict[str, Any]:
    return kw


def _as_list(val: Any) -> list[Any]:
    return val if isinstance(val, list) else []


def _as_dict(val: Any) -> dict[str, Any]:
    return val if isinstance(val, dict) else {}


BRIDGE_PACKAGES = _words("mcp-remote supergateway mcp-proxy @modelcontextprotocol/server-proxy")
_SHELL_RUNNERS = _words("sh bash zsh dash ksh ash")
NODE_SCRIPT_RUNNERS = _words(
    "node nodejs bun tsx ts-node ts-node-esm ts-node-script ts-node-cwd "
    "esno esmo jiti vite-node babel-node @babel/node"
)
RUNTIME_LAUNCHERS = (
    _words("node python python3 deno bun uvx npx") | _SHELL_RUNNERS | NODE_SCRIPT_RUNNERS
)
PACKAGE_RUNNERS = _words("npx uvx")
RUNNER_VALUE_OPTIONS = _words(
    "-p --package --from --with --with-editable --with-requirements --python"
)
SCRIPT_VALUE_OPTIONS = _words(
    "--tsconfig --env-file -X -W --output-dir --config --db-path --credentials --tls-key"
)
NODE_SCRIPT_SWITCHES = _words("--inspect --inspect-brk --experimental-strip-types")
PRELOAD_OPTIONS = _words("-r --require --import --loader --experimental-loader --preload")
SCRIPT_ARGUMENT_OPTIONS = SCRIPT_VALUE_OPTIONS | PRELOAD_OPTIONS
SCRIPT_SWITCHES = _words(
    "--watch --quiet --verbose --no-warnings --no-deprecation -u -B -A -I -E -S -s -O -P"
)
INSTALLED_BIN_DIRS = _tup("node_modules/.bin/ .venv/bin/ venv/bin/")
SCRIPT_SUFFIXES = _tup(".sh .py .js .mjs .cjs .jsx .ts .mts .cts .tsx .rb .pl")
CODE_EXEC_HOSTED_TOOLS = _words("code_interpreter computer_use bash local_shell code_execution")
UNTRUSTED_CI_TRIGGERS = _words("issue_comment discussion_comment pull_request_target workflow_run")
STEERING_PREFIXES = _tup(".claude .cursor CLAUDE.md AGENTS.md .mcp.json mcp.json")
_STEERING_PREFIXES_FOLDED = tuple(p.casefold() for p in STEERING_PREFIXES)
HOOK_CONFIG_FILES = _tup(
    ".claude/settings.json .claude/settings.local.json .cursor/hooks.json .claude/hooks.json"
)
MCP_CONFIG_FILES = _tup(
    ".mcp.json mcp.json .cursor/mcp.json .vscode/mcp.json "
    ".claude/mcp.json .claude/settings.json .claude/settings.local.json"
)
JSONC_FILES = _tup(".vscode/mcp.json")
PERMISSION_CONFIG_FILES = _tup(".claude/settings.json .claude/settings.local.json .cursor/cli.json")
_SUMMARY_KEYS = _tup(
    "hook_targets skill_preambles preamble_targets launcher_targets hosted_tools ci_agents "
    "framework_agents identities steering_surfaces bridged_servers hook_commands reach_alerts gaps"
)
_MAX_BRIDGE_DEPTH = 4
_MAX_BRIDGE_EXPANSIONS = 64  # per top-level server declaration
_MAX_SYMLINK_HOPS = 8
_MAX_STEERING_COMPONENTS = 256
_SPLIT_SEPARATORS = _words("&& || ; | & ( )") | frozenset({"\n"})
_SPLIT_CHAR_SET = frozenset(";|&()\n")
_REDIR_OP_RE = re.compile(r"^(?:[0-9]+)?(?:>>?|<<?<?|>&|<&|&>>?|>\||<>)$")
_SELF_CONTAINED_REDIR_RE = re.compile(r"^(?:[0-9]+)?(?:>&|<&)(?:[0-9]+|-)$")
_DANGEROUS_ENV_VARS = _words(
    "NODE_OPTIONS BASH_ENV ENV LD_PRELOAD DYLD_INSERT_LIBRARIES PYTHONSTARTUP NODE_PATH"
)

_EGRESS_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|axios\.|requests\.(?:get|post|put|request)|httpx\.|urllib\.request)\b"
    r"|\bfetch\s*\(",
    re.IGNORECASE,
)
_SETTINGS_TARGET_RE = re.compile(
    r"(?:\.claude/settings|\.cursor/mcp\.json|\.cursor/hooks|\.claude\.json|CLAUDE\.md|AGENTS\.md)"
)
_WRITE_OP_RE = re.compile(
    r"(?:>>|>|\btee\b|write_text|write_bytes|writeFileSync|appendFileSync|open\([^)\n]{0,200}['\"][wa]['\"])"
)
_AUTO_APPROVE_RE = re.compile(
    r"""(?:permissionDecision|permission_decision)["'\s:=]+["']?allow\b|"decision"["'\s:]+"approve\"""",
    re.IGNORECASE,
)
_PREAMBLE_RE = re.compile(r"^\s*!(?:`([^`]+)`\s*|\s+(.+))$")
_INLINE_PREAMBLE_RE = re.compile(r"!`([^`]+)`")
_HEX_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_ON_KEY_RE = re.compile(r"(?m)^([ \t]*)on([ \t]*:)")
_PROJECT_DIR_RE = re.compile(r"^(?:\$\{?CLAUDE_PROJECT_DIR\}?|\$\{workspace(?:Folder|Root)\})/")
_QUOTED_LEADING_VAR_RE = re.compile(r"""^(['"])(\$\{?[^'"]+\}?)\1""")
_STEERING_ROOT_VAR_RE = re.compile(
    r"^(?:\$\{(?:CLAUDE_PROJECT_DIR|PWD|workspaceFolder|workspaceRoot)(?::?[-=+]([^}]*))?\}|"
    r"\$(?:CLAUDE_PROJECT_DIR|PWD))(?:/(.*))?$"
)
_UNRESOLVED_VAR_RE = re.compile(r"\$\{[^}$]*\}|\$[A-Za-z_][A-Za-z0-9_]*")
_ENV_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VERSIONED_PYTHON_RE = re.compile(r"^python[0-9]+(?:\.[0-9]+)?$")
# A bare Node import can name a package and subpath. Relative paths, schemes,
# environment expansions and parent segments cannot be classified this way.
_NODE_PACKAGE_IMPORT = re.compile(
    r"((?:@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*)(?:/[A-Za-z0-9_][\w.-]*)*", re.ASCII
)
_SPIFFE_RE = re.compile(r"^spiffe://[a-z0-9.-]+/[A-Za-z0-9._/-]+$")


def _clean(val: Any) -> str:
    if val is None:
        return ""
    raw = str(val).strip()
    if raw.startswith("spiffe://") and not _contains_secret(raw.split("://", 1)[-1]):
        return neutralize(raw)
    return neutralize(redact_text(raw))


def _parse_yaml(text: str) -> dict[str, Any]:
    try:
        for index, _token in enumerate(yaml.scan(text, Loader=yaml.SafeLoader)):
            if index >= 20_000:
                raise ValueError("YAML exceeds 20,000 tokens")
    except yaml.YAMLError:
        raise ValueError("invalid YAML") from None
    return parse_yaml_mapping(text)


def _origin_only(url_text: str) -> str:
    try:
        parsed = urlsplit(url_text.strip())
        port_part = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        return ""
    if parsed.scheme in {"http", "https"} and parsed.hostname:
        return f"{parsed.scheme}://{parsed.hostname}{port_part}"
    return ""


def _read_confined_bytes(files: ConfinedCollection, rel_path: str, gaps: list[str]) -> bytes | None:
    if credential_shaped(rel_path):
        gaps.append(f"{rel_path}: excluded credential-shaped path")
        return None
    try:
        named = rel_path.startswith(INSTALLED_BIN_DIRS)
        raw = files.read_named(rel_path) if named else files.read_bytes(rel_path, missing_ok=True)
        gap = credential_gap(rel_path, files.link_target(rel_path))
    except (OSError, ValueError):
        gaps.append(f"{rel_path}: read refused")
        return None
    if gap is not None:
        gaps.append(f"{rel_path}: {gap}")
        return None
    return raw


def _read_confined_text(files: ConfinedCollection, rel_path: str, gaps: list[str]) -> str | None:
    raw = _read_confined_bytes(files, rel_path, gaps)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


class _GapList(list[str]):
    """A gap list whose membership test is amortized constant; direct appends count too."""

    def __init__(self) -> None:
        super().__init__()
        self._seen, self._synced = set[str](), 0

    def __contains__(self, message: object) -> bool:
        if len(self) < self._synced:
            self._seen, self._synced = set(), 0
        self._seen.update(self[self._synced :])
        self._synced = len(self)
        return message in self._seen


def _add_gap(gaps: list[str], message: str) -> None:
    if message not in gaps:
        gaps.append(message)


def _load_json_docs(
    files: ConfinedCollection, all_paths: list[str], candidates: tuple[str, ...], gaps: list[str]
) -> list[tuple[str, dict[str, Any]]]:
    docs: list[tuple[str, dict[str, Any]]] = []
    path_set = set(all_paths)
    for rel_path in candidates:
        if rel_path not in path_set:
            continue
        text = _read_confined_text(files, rel_path, gaps)
        if text is None:
            continue
        try:
            parsed = parse_json_strict(strip_jsonc(text) if rel_path in JSONC_FILES else text)
        except (ValueError, RecursionError):
            _add_gap(gaps, f"{rel_path}: invalid JSON")
            continue
        if isinstance(parsed, dict):
            docs.append((rel_path, parsed))
        else:
            _add_gap(gaps, f"{rel_path}: configuration must be a JSON object")
    return docs


def _classify_script_body(body: str) -> tuple[bool, bool, bool]:
    return (
        bool(_EGRESS_RE.search(body)),
        bool(_SETTINGS_TARGET_RE.search(body) and _WRITE_OP_RE.search(body)),
        bool(_AUTO_APPROVE_RE.search(body)),
    )


def _normalize_rel_candidate(token: str, *, allow_any_file: bool = False) -> str | None:
    cleaned = _PROJECT_DIR_RE.sub("./", token.strip().strip("'\""))
    if not cleaned or cleaned.startswith("-") or "://" in cleaned:
        return None
    had_dot_slash = cleaned.startswith("./")
    if had_dot_slash:
        cleaned = cleaned[2:]
    if not cleaned or cleaned.startswith("/") or ".." in cleaned.split("/"):
        return None
    if allow_any_file or had_dot_slash or "/" in cleaned or cleaned.endswith(SCRIPT_SUFFIXES):
        return cleaned
    return None


@dataclass
class _CheckoutScripts:
    files: ConfinedCollection
    paths: frozenset[str]

    @cached_property
    def local_node_packages(self) -> set[str] | None:
        """Read the root manifest once, and only for audits that see bare Node preloads."""
        if "package.json" not in self.paths:
            return set()
        manifest = self.files.read_json("package.json")
        if not isinstance(manifest, dict) or manifest.get("workspaces"):
            return None
        local: set[str] = set()
        name = manifest.get("name")
        if isinstance(name, str) and "exports" in manifest:
            local.add(name)
        for section in (
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ):
            for package, spec in _as_dict(manifest.get(section)).items():
                if isinstance(spec, str) and (
                    spec in {".", ".."}
                    or spec.startswith(
                        ("file:", "link:", "workspace:", "portal:", "./", "../", "/", "~")
                    )
                ):
                    local.add(package)
        return local


@dataclass
class _RunnerEvidence:
    checkout: _CheckoutScripts | None = None
    preloads: list[str] = field(default_factory=list)
    gaps: set[str] = field(default_factory=set)

    def _dependency_import(self, value: str) -> bool:
        match = _NODE_PACKAGE_IMPORT.fullmatch(value)
        if match is None:
            return False
        if self.checkout is None:
            return True
        local = self.checkout.local_node_packages
        return local is not None and match[1] not in local

    def option_value(self, option: str, value: str, *, node_imports: bool) -> None:
        if option in PRELOAD_OPTIONS:
            path = _normalize_rel_candidate(value, allow_any_file=True)
            if (
                path
                and (value.startswith("./") or _PROJECT_DIR_RE.match(value))
                and "$" not in path
                and not path.startswith("~")
            ):
                self.preloads.append(posixpath.normpath(path))
            elif not (node_imports and self._dependency_import(value)):
                self.gaps.add("preload target is unresolved")
        elif option in {"-p", "--package", "--from", "--with", "--with-editable"} and (
            value in {".", ".."} or value.startswith(("./", "../", "/", "file:", "~", "$"))
        ):
            self.gaps.add("local package entry point is unresolved")


def _is_runtime_launcher(base: str) -> bool:
    return base in RUNTIME_LAUNCHERS or bool(_VERSIONED_PYTHON_RE.match(base))


def _package_runner_target(
    runner: str,
    operands: list[str],
    project_paths: frozenset[str],
    files: ConfinedCollection | None,
    evidence: _RunnerEvidence,
    *,
    depth: int = 0,
) -> str | None:
    """Distinguish a package or runtime launcher's script from value-taking and preload options."""
    package_seen = False
    script_runner = True
    node_imports = runner in NODE_SCRIPT_RUNNERS
    shell_runner = runner in _SHELL_RUNNERS
    deno_or_bun = runner in {"deno", "bun"}
    bun = runner == "bun"
    pending_option: str | None = None
    skip_inline_arg = False
    pending_shell_c = False
    inline_code = False
    unknown_option = False
    parse_options = True
    fallback: str | None = None
    for arg in operands:
        follows_unknown, unknown_option = unknown_option, False
        if pending_option is not None:
            evidence.option_value(pending_option, arg, node_imports=node_imports)
            pending_option = None
            continue
        if pending_shell_c:
            pending_shell_c = False
            inline_code = True
            shell_targets = _extract_shell_c_targets(
                arg, project_paths, files, evidence, depth=depth
            )
            if shell_targets and fallback is None:
                fallback = shell_targets[0]
                for extra in shell_targets[1:]:
                    if extra not in evidence.preloads:
                        evidence.preloads.append(extra)
            continue
        if skip_inline_arg:
            skip_inline_arg = False
            continue
        if parse_options and arg == "--":
            parse_options = False
            continue
        if parse_options and arg.startswith("-"):
            option, equal, value = arg.partition("=")
            if shell_runner and (
                option == "-c"
                or (not equal and option[1:2] != "-" and "c" in option[1:] and option[1:].isalpha())
            ):
                if equal:
                    inline_code = True
                    shell_targets = _extract_shell_c_targets(
                        value, project_paths, files, evidence, depth=depth
                    )
                    if shell_targets and fallback is None:
                        fallback = shell_targets[0]
                else:
                    pending_shell_c = True
                continue
            if deno_or_bun and option in {"-c", "--config"}:
                if equal:
                    evidence.option_value("--config", value, node_imports=node_imports)
                elif not bun:
                    pending_option = "--config"
                continue
            if option in {"-c", "-m"} or (option == "-e" and not shell_runner):
                if node_imports and option == "-e":
                    inline_code = True
                    skip_inline_arg = not equal
                    continue
                return None
            if node_imports and option in {"--eval", "-p", "--print"}:
                inline_code = True
                skip_inline_arg = not equal
                continue
            if package_seen and not equal and arg.startswith("-r") and len(arg) > 2:
                evidence.option_value("-r", arg[2:], node_imports=node_imports)
                continue
            if not package_seen and not equal and arg.startswith("-p") and len(arg) > 2:
                evidence.option_value("-p", arg[2:], node_imports=node_imports)
                continue
            if option in (SCRIPT_ARGUMENT_OPTIONS if package_seen else RUNNER_VALUE_OPTIONS):
                if equal:
                    evidence.option_value(option, value, node_imports=node_imports)
                else:
                    pending_option = option
            elif package_seen and equal and option not in SCRIPT_SWITCHES:
                val_local = _normalize_rel_candidate(value, allow_any_file=True)
                val_path = posixpath.normpath(val_local) if val_local is not None else None
                if (
                    value.startswith("./")
                    or value.endswith(SCRIPT_SUFFIXES)
                    or (val_path is not None and val_path in project_paths)
                ):
                    evidence.gaps.add("option arity leaves the script target unresolved")
            elif (
                package_seen
                and not equal
                and runner in PACKAGE_RUNNERS
                and option not in SCRIPT_SWITCHES
                and not (node_imports and option in NODE_SCRIPT_SWITCHES)
                and not (shell_runner and re.fullmatch(r"-[efuvx]+", option))
                and not (deno_or_bun and option.startswith(("--allow-", "--no-", "--unstable")))
            ):
                unknown_option = True
            continue
        if inline_code:
            continue
        local = _normalize_rel_candidate(arg, allow_any_file=True)
        path = posixpath.normpath(local) if local is not None else None
        if path is not None and (path.startswith("~") or "$" in path):
            if runner not in PACKAGE_RUNNERS and "$" in path and not path.startswith("~"):
                return path
            evidence.gaps.add("script target is unresolved")
            continue
        explicit = arg.startswith("./") or bool(_PROJECT_DIR_RE.match(arg))
        scripted = arg.endswith(SCRIPT_SUFFIXES)
        path_like = explicit or "/" in arg or scripted
        listed = path in project_paths
        if follows_unknown:
            if scripted or (
                (path_like or listed) and (script_runner or not posixpath.splitext(arg)[1])
            ):
                evidence.gaps.add("option arity leaves the script target unresolved")
            continue
        if not package_seen:
            package_seen = True
            parse_options = True
            if arg in {".", "..", "./", "../"} or arg.startswith(("../", "/", "file:")):
                evidence.gaps.add("local package entry point is unresolved")
                continue
            reference = python_spec(arg, shorthand=True) if runner == "uvx" else npm_spec(arg)
            name = reference.name
            node_imports = runner != "uvx" and name in NODE_SCRIPT_RUNNERS
            shell_runner = shell_runner or name in _SHELL_RUNNERS
            deno_or_bun = deno_or_bun or name in {"deno", "bun"}
            bun = bun or name == "bun"
            script_runner = (
                reference.ecosystem not in {"npm", "pypi"}
                or node_imports
                or (name is not None and _is_runtime_launcher(name))
                or name in {"ipython", "pypy", "pypy3"}
            )
            if (
                runner == "npx"
                and (
                    arg == "@modelcontextprotocol/server-filesystem"
                    or arg.startswith("@modelcontextprotocol/server-filesystem@")
                )
                and name == "@modelcontextprotocol/server-filesystem"
            ):
                # The registry reference server accepts filesystem roots as data operands.
                return None
            # The first operand names the package. A bare name is resolved from the
            # registry, so a project file of that name (a decoy `tsx`) is not the script.
            if (
                path is not None
                and not arg.startswith("@")
                and (explicit or scripted or ("/" in arg and listed))
            ):
                if f"{path}/" in project_paths or (files is not None and files.is_directory(path)):
                    evidence.gaps.add("local package entry point is unresolved")
                    return None
                return path
            continue
        if path is None:
            continue
        if (
            runner == "npx"
            and arg.startswith("@")
            and not (listed or scripted)
            and npm_spec(arg).ecosystem == "npm"
        ):
            if not script_runner or files is None:
                continue
            if files.regular_file(path) is None:
                evidence.gaps.add("scoped script target is unresolved")
                continue
        if path_like:
            if f"{path}/" in project_paths or (files is not None and files.is_directory(path)):
                if script_runner:
                    evidence.gaps.add("directory entry point is unresolved")
                continue
            return path
        if fallback is None and listed and "." not in path:
            fallback = path
    if pending_option in PRELOAD_OPTIONS:
        evidence.gaps.add("preload target is unresolved")
    return fallback if (not inline_code or shell_runner) else None


def _is_separator_token(tok: str) -> bool:
    return bool(tok) and (tok in _SPLIT_SEPARATORS or all(ch in _SPLIT_CHAR_SET for ch in tok))


def _split_token_segments(tokens: list[str]) -> list[list[str]]:
    segments: list[list[str]] = []
    current: list[str] = []
    idx = 0
    while idx < len(tokens):
        tok = tokens[idx]
        if _is_separator_token(tok):
            if current:
                segments.append(current)
                current = []
            idx += 1
            continue
        if _SELF_CONTAINED_REDIR_RE.match(tok):
            idx += 1
            continue
        if tok.isdigit() and idx + 1 < len(tokens) and _REDIR_OP_RE.match(tokens[idx + 1]):
            idx += 1
            tok = tokens[idx]
        if _REDIR_OP_RE.match(tok):
            idx += 1
            if idx < len(tokens) and not _is_separator_token(tokens[idx]):
                # A launcher fed by stdin or a here-string runs the redirect target, and a
                # substitution inside any target runs a command.
                target = tokens[idx]
                if _SUBST_CMD_RE.search(target.translate(_UNMASK_OPERATORS)) or (
                    tok.lstrip("0123456789") in {"<", "<<<"}
                    and (cmd := _unwrap_command_tokens(current))
                    and _is_runtime_launcher(cmd[0].rsplit("/", 1)[-1])
                ):
                    current.append(target)
                idx += 1
            continue
        current.append(tok)
        idx += 1
    if current:
        segments.append(current)
    return segments


_OPERATOR_CHARS = ";|&()\n><"
_MASKED_OPERATORS = {ch: chr(0xE000 + i) for i, ch in enumerate(_OPERATOR_CHARS)}
_UNMASK_OPERATORS = str.maketrans({v: k for k, v in _MASKED_OPERATORS.items()})


def _mask_quoted_operators(text: str) -> str:
    """Hide operator characters that quotes or a backslash make literal from the lexer."""
    out: list[str] = []
    quote, escaped = "", False
    for ch in text:
        if escaped or quote:
            out.append(_MASKED_OPERATORS.get(ch, ch))
            if escaped:
                escaped = False
            elif ch == quote:
                quote = ""
            elif ch == "\\" and quote == '"':
                escaped = True
            continue
        if ch == "\\":
            escaped = True
        elif ch in "'\"":
            quote = ch
        out.append(ch)
    return "".join(out)


def _split_shell_commands(command: str) -> list[list[str]]:
    """Split a shell command string into individual command token segments."""
    # A private-use character in the input would unmask as an operator, so it is dropped.
    text = command.strip().translate(dict.fromkeys(range(0xE000, 0xE000 + len(_OPERATOR_CHARS))))
    if not text:
        return []
    try:
        lexer = shlex.shlex(_mask_quoted_operators(text), posix=True, punctuation_chars=";|&()\n><")
        lexer.whitespace = " \t\r"
        lexer.whitespace_split = True
        lexer.commenters = ""
        raw_tokens = list(lexer)
    except ValueError:
        raw_tokens = text.split()
    segments = _split_token_segments(raw_tokens)
    return [[tok.translate(_UNMASK_OPERATORS) for tok in seg] for seg in segments]


_SIMPLE_WRAPPERS: dict[str, tuple[frozenset[str], int]] = {
    "exec": (_words("-a"), 0),
    "command": (frozenset(), 0),
    "nohup": (frozenset(), 0),
    "setsid": (frozenset(), 0),
    "time": (frozenset(), 0),
    "nice": (_words("-n --adjustment"), 0),
    "timeout": (_words("-k -s --kill-after --signal"), 1),
    "stdbuf": (_words("-i -o -e --input --output --error"), 0),
    "sudo": (_words("-u -g -h -p -C -D --user --group --chdir"), 0),
}


def _split_shlex_safe(text: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError:
        return text.split()


def _record_env_assignment(
    token: str,
    evidence: _RunnerEvidence | None,
) -> None:
    if evidence is None:
        return
    var, _, val = token.partition("=")
    if var not in _DANGEROUS_ENV_VARS:
        return
    if var == "NODE_OPTIONS":
        opts = _split_shlex_safe(val)
        i = 0
        while i < len(opts):
            opt, eq, opt_val = opts[i].partition("=")
            if opt in PRELOAD_OPTIONS:
                if eq:
                    evidence.option_value(opt, opt_val, node_imports=True)
                elif i + 1 < len(opts):
                    evidence.option_value(opt, opts[i + 1], node_imports=True)
                    i += 1
            elif not eq and opt.startswith("-r") and len(opt) > 2:
                evidence.option_value("-r", opt[2:], node_imports=True)
            i += 1
    else:
        local = _normalize_rel_candidate(val)
        if local is not None and not local.startswith(("~", "$")):
            norm = posixpath.normpath(local)
            if norm not in evidence.preloads:
                evidence.preloads.append(norm)
    evidence.gaps.add(f"environment override '{var}' may inject execution")


def _unwrap_env_tokens(
    cur: list[str],
    evidence: _RunnerEvidence | None = None,
) -> list[str]:
    """Strip GNU/POSIX ``env`` options (including attached/bundled ``-S``, ``-u``, ``-C``) and assignments."""
    idx = 1
    split_extra: list[str] = []
    while idx < len(cur):
        arg = cur[idx]
        if arg == "--":
            idx += 1
            break
        if arg in {"-S", "--split-string"} and idx + 1 < len(cur):
            split_extra = _split_shlex_safe(cur[idx + 1])
            idx += 2
            break
        if arg.startswith("--split-string="):
            split_extra = _split_shlex_safe(arg.split("=", 1)[1])
            idx += 1
            break
        if arg in {"-C", "--chdir"} and idx + 1 < len(cur):
            if evidence is not None:
                evidence.gaps.add("wrapper changes working directory; target path may differ")
            idx += 2
            continue
        if arg.startswith("--chdir="):
            if evidence is not None:
                evidence.gaps.add("wrapper changes working directory; target path may differ")
            idx += 1
            continue
        if arg in {"-u", "--unset", "-a", "--argv0"} and idx + 1 < len(cur):
            idx += 2
            continue
        if arg.startswith(("--unset=", "--argv0=")):
            idx += 1
            continue
        if arg.startswith("-") and not arg.startswith("--") and len(arg) > 1:
            pos = 1
            handled = False
            while pos < len(arg):
                flag = arg[pos]
                if flag in {"i", "0", "v"}:
                    pos += 1
                    continue
                if flag == "S":
                    rest = arg[pos + 1 :]
                    if rest:
                        split_extra = _split_shlex_safe(rest)
                        idx += 1
                    elif idx + 1 < len(cur):
                        split_extra = _split_shlex_safe(cur[idx + 1])
                        idx += 2
                    else:
                        idx += 1
                    return split_extra + cur[idx:]
                if flag in {"u", "C", "a"}:
                    if flag == "C" and evidence is not None:
                        evidence.gaps.add(
                            "wrapper changes working directory; target path may differ"
                        )
                    rest = arg[pos + 1 :]
                    idx += 1 if rest else (2 if idx + 1 < len(cur) else 1)
                    handled = True
                    break
                break
            if not handled:
                idx += 1
            continue
        if _ENV_ASSIGN_RE.match(arg):
            _record_env_assignment(arg, evidence)
            idx += 1
            continue
        if arg.startswith("-"):
            idx += 1
            continue
        break
    return split_extra + cur[idx:]


def _unwrap_command_tokens(
    tokens: list[str],
    evidence: _RunnerEvidence | None = None,
) -> list[str]:
    """Strip leading shell assignments and standard OS command wrappers (never local paths)."""
    cur = list(tokens)
    for _ in range(8):
        pos = 0
        while pos < len(cur):
            tok = cur[pos]
            if tok in {"{", "}", "!", "("}:
                pos += 1
                continue
            if _ENV_ASSIGN_RE.match(tok):
                _record_env_assignment(tok, evidence)
                pos += 1
                continue
            break
        if pos:
            cur = cur[pos:]
        if not cur:
            return []
        first = cur[0].strip()
        if "/" in first and not first.startswith("/"):
            return cur
        base = first.rsplit("/", 1)[-1]
        if base == "env":
            cur = _unwrap_env_tokens(cur, evidence)
            continue
        spec = _SIMPLE_WRAPPERS.get(base)
        if spec is None:
            return cur
        value_opts, skip_pos = spec
        idx = 1
        while idx < len(cur) and cur[idx].startswith("-"):
            arg = cur[idx]
            if base == "command" and arg in {"-v", "-V"}:
                return []
            if arg == "--":
                idx += 1
                break
            if arg in value_opts or (base == "exec" and arg.endswith("a") and len(arg) > 1):
                idx += 2
            else:
                idx += 1
        cur = cur[idx + skip_pos :]
    if evidence is not None and cur:
        first = cur[0].strip()
        base = first.rsplit("/", 1)[-1]
        if base == "env" or base in _SIMPLE_WRAPPERS or _ENV_ASSIGN_RE.match(first):
            evidence.gaps.add("command wrapper nesting exceeded limit")
    return cur


_SUBST_CMD_RE = re.compile(r"\$\(([^()]{1,400})\)|`([^`]{1,400})`")


def _extract_shell_c_targets(
    script: str,
    project_paths: frozenset[str],
    files: ConfinedCollection | None,
    evidence: _RunnerEvidence,
    *,
    depth: int = 0,
) -> list[str]:
    if depth >= 2:
        evidence.gaps.add("nested shell -c command leaves script target unresolved")
        return []
    found_targets: list[str] = []
    for seg in _split_shell_commands(script):
        found = _extract_single_target(seg, project_paths, files, evidence, depth=depth + 1)
        if found is not None and found not in found_targets:
            found_targets.append(found)
    return found_targets


def _extract_single_target(
    tokens: list[str],
    project_paths: frozenset[str],
    files: ConfinedCollection | None,
    evidence: _RunnerEvidence,
    *,
    depth: int = 0,
) -> str | None:
    unwrapped = _unwrap_command_tokens(tokens, evidence)
    if not unwrapped:
        return None
    if depth < 2:
        for tok in tokens:
            for m in _SUBST_CMD_RE.finditer(tok):
                inner = (m.group(1) or m.group(2) or "").strip()
                if inner:
                    for sub_target in _extract_shell_c_targets(
                        inner, project_paths, files, evidence, depth=depth + 1
                    ):
                        if sub_target not in evidence.preloads:
                            evidence.preloads.append(sub_target)
    first = unwrapped[0].strip()
    if first in {".", "source"} and len(unwrapped) > 1:
        sourced = _normalize_rel_candidate(unwrapped[1], allow_any_file=True)
        return posixpath.normpath(sourced) if sourced is not None else None
    base = first.split("/")[-1]
    direct = _normalize_rel_candidate(first)
    explicit_local = first.startswith("./") and not first[2:].startswith(INSTALLED_BIN_DIRS)
    if direct is not None and (explicit_local or not _is_runtime_launcher(base)):
        if explicit_local and _is_runtime_launcher(base):
            # A repo-local wrapper named like a launcher runs its operand as one would.
            operand = _package_runner_target(
                base, [base, *unwrapped[1:]], project_paths, files, evidence, depth=depth
            )
            if operand is not None and operand not in evidence.preloads:
                evidence.preloads.append(operand)
        return direct
    if base in PACKAGE_RUNNERS:
        return _package_runner_target(
            base, unwrapped[1:], project_paths, files, evidence, depth=depth
        )
    if _is_runtime_launcher(base):
        return _package_runner_target(
            base, [base, *unwrapped[1:]], project_paths, files, evidence, depth=depth
        )
    return None


def _extract_local_script_target(
    tokens: list[str],
    project_paths: frozenset[str] = frozenset(),
    *,
    files: ConfinedCollection | None = None,
    evidence: _RunnerEvidence | None = None,
) -> str | None:
    if not tokens:
        return None
    runner_evidence = evidence or _RunnerEvidence()
    segments = (
        _split_token_segments(tokens)
        if any(_is_separator_token(tok) for tok in tokens)
        else [tokens]
    )
    primary: str | None = None
    for segment in segments:
        found = _extract_single_target(segment, project_paths, files, runner_evidence)
        if primary is None and found is not None:
            primary = found
    return primary


def _audit_command_segments(
    segments: list[list[str]],
    checkout: _CheckoutScripts,
    gaps: list[str],
    source_file: str,
    role: str,
    *,
    evidence: _RunnerEvidence | None = None,
) -> tuple[str | None, list[str]]:
    runner_evidence = evidence or _RunnerEvidence(checkout=checkout)
    primaries: list[str] = []
    for segment in segments:
        found = _extract_single_target(segment, checkout.paths, checkout.files, runner_evidence)
        if found is not None:
            primaries.append(found)
    gaps.extend(f"{source_file}: {role} {reason}" for reason in sorted(runner_evidence.gaps))
    targets = primaries + runner_evidence.preloads
    return (primaries[0] if primaries else None), list(dict.fromkeys(targets))


def _tokenize_command(command: Any, args: Any = None) -> list[str]:
    tokens: list[str] = []
    if isinstance(command, str) and command.strip():
        try:
            tokens.extend(shlex.split(command.strip()))
        except ValueError:
            tokens.extend(command.strip().split())
    for a in _as_list(args):
        if isinstance(a, (str, int, float)):
            tokens.append(str(a))
    return tokens


@dataclass
class ControlPlaneAuditSummary:
    """Consolidated audit summary for R1.1-3, R1.1-7, R1.2-3, R1.3-3, and R1.4-3."""

    bom: AIBOM = field(default_factory=AIBOM)
    findings: list[dict[str, Any]] = field(default_factory=list)
    hook_targets: list[dict[str, Any]] = field(default_factory=list)
    skill_preambles: list[dict[str, Any]] = field(default_factory=list)
    preamble_targets: list[dict[str, Any]] = field(default_factory=list)
    launcher_targets: list[dict[str, Any]] = field(default_factory=list)
    hosted_tools: list[dict[str, Any]] = field(default_factory=list)
    ci_agents: list[dict[str, Any]] = field(default_factory=list)
    framework_agents: list[dict[str, Any]] = field(default_factory=list)
    identities: list[dict[str, Any]] = field(default_factory=list)
    steering_surfaces: list[dict[str, Any]] = field(default_factory=list)
    bridged_servers: list[dict[str, Any]] = field(default_factory=list)
    hook_commands: list[dict[str, Any]] = field(default_factory=list)
    reach_alerts: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=_GapList)

    def flag(
        self,
        category: str,
        severity: RiskSeverity,
        description: str,
        file_path: str | None = None,
        component_name: str | None = None,
    ) -> None:
        self.findings.append(
            _rec(
                category=category,
                severity=severity.value,
                description=_clean(description),
                file_path=file_path,
                component_name=component_name,
            )
        )

    def edge(self, src: str, dst: str, rel: Relationship, evidence_file: str | None = None) -> None:
        self.bom.add_dependency(
            DependencyEdge(
                source_ref=src, target_ref=dst, relationship=rel, conditions=evidence_file
            )
        )

    def add_ctrl(
        self,
        name: str,
        kind: str,
        file_path: str | None,
        props: dict[str, Any],
        assurance: AssuranceLevel = AssuranceLevel.OBSERVED,
    ) -> None:
        clean_name = neutralize(name)
        base_kw: dict[str, Any] = _rec(
            bom_ref=f"agent-control:{clean_name}",
            name=clean_name,
            source_path=file_path,
            assurance_level=assurance,
            properties=props,
        )
        if kind == "ide-agent":
            comp: Any = IDEAgentComponent(
                ide_type=str(props.get("host") or "github-actions"), **base_kw
            )
        elif kind == "framework-agent":
            caps = CapabilityDeclaration(
                filesystem_paths=list(_as_list(props.get("filesystem_paths"))),
                egress_domains=list(_as_list(props.get("egress_domains"))),
            )
            comp = AgentComponent(
                framework=str(props.get("framework") or "custom"), capabilities=caps, **base_kw
            )
        else:
            comp = SkillPackageComponent(skill_type=kind, **base_kw)
        self.add(comp)

    def add(self, comp: Any) -> None:
        prior = self.bom.get_component(comp.bom_ref)
        if prior is None:
            self.bom.add_component(comp)
            return
        for key, val in comp.properties.items():
            old = prior.properties.setdefault(key, val)
            if old != val:
                olds = old if isinstance(old, list) else [old]
                news = val if isinstance(val, list) else [val]
                prior.properties[key] = olds + [v for v in news if v not in olds]

    def add_mcp(
        self,
        name: str,
        file_path: str | None,
        command: str | None,
        args: list[str],
        *,
        transport: str = "stdio",
        endpoint_url: str | None = None,
        registry_source: str | None = None,
        props: dict[str, Any] | None = None,
        assurance: AssuranceLevel = AssuranceLevel.OBSERVED,
    ) -> None:
        bom_ref, clean_name = _safe_mcp_ref(name)
        self.add(
            MCPServerComponent(
                bom_ref=bom_ref,
                name=clean_name,
                source_path=file_path,
                command=command,
                args=args,
                transport=transport,
                endpoint_url=endpoint_url,
                registry_source=registry_source,
                assurance_level=assurance,
                properties=props or {},
            )
        )

    def to_dict(self) -> dict[str, Any]:
        out = {k: getattr(self, k) for k in _SUMMARY_KEYS}
        out["gaps"] = [_clean(g) for g in self.gaps]
        out["security_flags"] = self.findings
        out["relationships"] = [
            _rec(
                source_ref=r.source_ref,
                target_ref=r.target_ref,
                relationship_type=r.relationship,
                evidence_file=r.conditions,
            )
            for r in self.bom.dependencies
        ]
        return out


def _bind_script_target(
    files: ConfinedCollection,
    summary: ControlPlaneAuditSummary,
    *,
    owner_ref: str,
    target_path: str,
    source_file: str,
    role: str,
    event_or_server: str,
) -> dict[str, Any] | None:
    before_gaps = len(summary.gaps)
    installed = target_path.startswith(INSTALLED_BIN_DIRS)
    if (
        "$" in target_path
        or "\x00" in target_path
        or (files.excluded(target_path) and not installed)
    ):
        summary.gaps.append(f"{target_path}: {role} target is unresolved or excluded")
        return None
    raw = _read_confined_bytes(files, target_path, summary.gaps)
    if raw is None:
        if len(summary.gaps) == before_gaps:
            summary.flag(
                "hook_target_missing",
                RiskSeverity.MEDIUM,
                f"Referenced {role} script '{target_path}' in {source_file} does not exist.",
                source_file,
                target_path,
            )
        return None
    digest = _sha256_hex(raw)
    has_egress, has_settings, has_approve = _classify_script_body(
        raw.decode("utf-8", errors="replace")
    )
    checks = (
        (
            has_egress,
            "egress",
            "hook_network_egress",
            "contains outbound network egress primitives",
        ),
        (
            has_settings,
            "settings_write",
            "hook_settings_mutation",
            "writes to agent control-plane settings",
        ),
        (
            has_approve,
            "auto_approve_bypass",
            "hook_auto_approve_bypass",
            "emits permissionDecision: allow (F19)",
        ),
    )
    classes: list[str] = []
    for hit, cls_name, flag_cat, detail in checks:
        if hit:
            classes.append(cls_name)
            summary.flag(
                flag_cat,
                RiskSeverity.HIGH,
                f"Resolved {role} target '{target_path}' {detail}.",
                target_path,
                target_path,
            )
    comp_name = f"{role}:{target_path}"
    props = _rec(
        launch_target=digest,
        target_path=target_path,
        classifications=classes,
        source_file=source_file,
        bound_to=event_or_server,
    )
    summary.add_ctrl(comp_name, role, target_path, props)
    summary.edge(owner_ref, f"agent-control:{comp_name}", "invokes", source_file)
    return _rec(
        owner_ref=owner_ref,
        target_path=target_path,
        launch_target_sha256=digest,
        classifications=classes,
        source_file=source_file,
        context=event_or_server,
    )


def _iter_hook_commands(doc: dict[str, Any]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for event_name, entries in _as_dict(doc.get("hooks")).items():
        for entry in _as_list(entries):
            if isinstance(entry, str):
                out.append((str(event_name), entry))
            elif isinstance(entry, dict):
                if isinstance(entry.get("command"), str):
                    out.append((str(event_name), entry["command"]))
                for sub in _as_list(entry.get("hooks")):
                    if isinstance(sub, dict) and isinstance(sub.get("command"), str):
                        out.append((str(event_name), sub["command"]))
    return out


def _inspect_hooks_and_preambles(
    files: ConfinedCollection,
    all_paths: list[str],
    checkout: _CheckoutScripts,
    summary: ControlPlaneAuditSummary,
) -> None:
    for cfg_path, doc in _load_json_docs(files, all_paths, HOOK_CONFIG_FILES, summary.gaps):
        for raw_event, cmd_str in _iter_hook_commands(doc):
            event_name = _clean(raw_event)
            summary.hook_commands.append(
                _rec(
                    source_file=cfg_path,
                    event=event_name,
                    command_digest=_sha256_hex(cmd_str.encode()),
                )
            )
            _, targets = _audit_command_segments(
                _split_shell_commands(cmd_str), checkout, summary.gaps, cfg_path, "hook"
            )
            for target in targets:
                rec = _bind_script_target(
                    files,
                    summary,
                    owner_ref="agent:repository",
                    target_path=target,
                    source_file=cfg_path,
                    role="hook-target",
                    event_or_server=event_name,
                )
                if rec is not None:
                    summary.hook_targets.append(rec)

    for skill_path in [
        p for p in all_paths if p == "SKILL.md" or p.endswith(("/SKILL.md", ".skill.md"))
    ]:
        text = _read_confined_text(files, skill_path, summary.gaps)
        if text is None:
            continue
        skill_ref = f"skill:{skill_path}"
        for line_no, raw_line in enumerate(text.splitlines(), start=1):
            match = _PREAMBLE_RE.match(raw_line)
            cmds = [(match.group(1) or match.group(2) or "").strip()] if match else []
            cmds += [m.group(1).strip() for m in _INLINE_PREAMBLE_RE.finditer(raw_line)]
            for cmd_body in [c for c in dict.fromkeys(cmds) if c]:
                cmd_digest = _sha256_hex(cmd_body.encode())
                has_egress, _, _ = _classify_script_body(cmd_body)
                summary.skill_preambles.append(
                    _rec(
                        skill_path=skill_path,
                        line=line_no,
                        command_digest=cmd_digest,
                        has_egress=has_egress,
                    )
                )
                summary.edge(
                    skill_ref,
                    f"skill-preamble:{skill_path}:{cmd_digest[:12]}",
                    "invokes",
                    skill_path,
                )
                summary.flag(
                    "skill_shell_preamble",
                    RiskSeverity.HIGH,
                    f"Skill file '{skill_path}' line {line_no} contains a '!' shell execution preamble (digest {cmd_digest[:12]}).",
                    skill_path,
                    skill_ref,
                )
                _, targets = _audit_command_segments(
                    _split_shell_commands(cmd_body),
                    checkout,
                    summary.gaps,
                    skill_path,
                    "preamble",
                )
                for target in targets:
                    rec = _bind_script_target(
                        files,
                        summary,
                        owner_ref=skill_ref,
                        target_path=target,
                        source_file=skill_path,
                        role="preamble-target",
                        event_or_server=f"line:{line_no}",
                    )
                    if rec is not None:
                        summary.preamble_targets.append(rec)


def _safe_mcp_ref(name: str) -> tuple[str, str]:
    """Return a bounded, collision-resistant ``(bom_ref, clean_name)`` pair."""
    clean = neutralize(name)
    if clean != name or len(clean) > 256:
        digest = _sha256_hex(name.encode("utf-8", errors="replace"))[:12]
        clean = f"{clean[:240]}:{digest}"
    return f"mcp-server:{clean}", clean


def _extract_mcp_servers(doc: dict[str, Any]) -> list[tuple[str, dict[str, Any]]]:
    # Every map is read, as hosts differ in which one they use; a name in two is audited twice.
    return [
        (str(k), v)
        for key in ("mcpServers", "servers", "context_servers")
        for k, v in _as_dict(doc.get(key)).items()
        if isinstance(v, dict)
    ]


def _find_bridge_package(tokens: list[str]) -> tuple[str, int] | None:
    for idx, tok in enumerate(tokens):
        cleaned = tok.strip()
        base = cleaned.split("/")[-1] if not cleaned.startswith("@") else cleaned
        if not cleaned.startswith("@") and "@" in base:
            base = base.split("@", 1)[0]
        elif cleaned.startswith("@") and cleaned.count("@") >= 2:
            base = "@" + cleaned[1:].split("@", 1)[0]
        if base in BRIDGE_PACKAGES:
            return base, idx
    return None


def _is_http_url(url: str) -> bool:
    return url.lower().startswith(("http://", "https://", "ws://", "wss://"))


def _insecure_http_url(url: str, *, loopback_ok: bool = False) -> bool | None:
    """Plain HTTP/WS, credentials or no host is insecure; ``None`` when urlsplit refuses it."""
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    host = parsed.hostname
    if not host or parsed.username is not None or parsed.password is not None:
        return True
    if parsed.scheme.lower() not in {"http", "ws"}:
        return "@" in parsed.netloc
    try:
        return not loopback_ok or (
            host.lower() != "localhost" and not ipaddress.ip_address(host).is_loopback
        )
    except ValueError:
        return True


def _flag_transport(
    summary: ControlPlaneAuditSummary, kind: str, cfg_path: str, srv_name: str, url: str
) -> None:
    insecure = _insecure_http_url(url, loopback_ok=kind == "server")
    if insecure is None:
        _add_gap(summary.gaps, f"{cfg_path}: {kind} '{_clean(srv_name)}' endpoint URL is malformed")
    elif insecure:
        summary.flag(
            "transport_security",
            RiskSeverity.HIGH,
            f"MCP {kind} '{srv_name}' uses insecure HTTP or embedded credentials in URL (F21).",
            cfg_path,
            srv_name,
        )


_BridgedSteeringEntry = tuple[str, str, dict[str, Any], str, str, bool]


def _audit_mcp_server(
    files: ConfinedCollection,
    checkout: _CheckoutScripts,
    summary: ControlPlaneAuditSummary,
    live_versions: dict[str, str],
    cfg_path: str,
    srv_name: str,
    srv_cfg: dict[str, Any],
    bridged_steering: list[_BridgedSteeringEntry],
    *,
    host: str,
    client_server_name: str,
    inherited_auto: bool,
    visited_configs: frozenset[str],
    seen_expansions: set[tuple[str, str, str, str]],
    expansion_budget: list[int],
    depth: int = 0,
    top_names: frozenset[str] = frozenset(),
) -> None:
    cmd = srv_cfg.get("command")
    args = _as_list(srv_cfg.get("args"))
    env_map = _as_dict(srv_cfg.get("env"))
    tokens = _tokenize_command(cmd, args)
    str_args = [str(a) for a in args if isinstance(a, (str, int, float))]
    srv_ref, _ = _safe_mcp_ref(srv_name)
    my_auto = (
        inherited_auto
        or bool(srv_cfg.get("autoApprove"))
        or len(_as_list(srv_cfg.get("alwaysAllow"))) > 0
    )

    reg_origin = ""
    for idx, tok in enumerate(tokens):
        if tok == "--registry" and idx + 1 < len(tokens):
            reg_origin = _origin_only(tokens[idx + 1])
        elif tok.startswith("--registry="):
            reg_origin = _origin_only(tok.split("=", 1)[1])
    if not reg_origin and isinstance(env_map.get("npm_config_registry"), str):
        reg_origin = _origin_only(env_map["npm_config_registry"])

    bridge_hit = _find_bridge_package(tokens)
    if bridge_hit is not None:
        bridge_pkg, b_idx = bridge_hit
        endpoint_url: str | None = None
        config_arg: str | None = None
        for j in range(b_idx + 1, len(tokens)):
            tok = tokens[j]
            if _is_http_url(tok) and endpoint_url is None:
                endpoint_url = tok
            elif tok == "--config" and j + 1 < len(tokens):
                config_arg = tokens[j + 1]
            elif tok.startswith("--config="):
                config_arg = tok.split("=", 1)[1]

        sub_entries: list[tuple[str, dict[str, Any]]] = []
        norm_cfg: str | None = None
        canonical_cfg: str | None = None
        if config_arg is not None:
            raw_norm = _normalize_rel_candidate(config_arg, allow_any_file=True)
            norm_cfg = posixpath.normpath(raw_norm) if raw_norm is not None else None
            if norm_cfg is None or norm_cfg == ".." or norm_cfg.startswith("../"):
                norm_cfg = None
                _add_gap(
                    summary.gaps,
                    f"{cfg_path}: bridge '{_clean(srv_name)}' config '{_clean(config_arg)}' is outside project root",
                )
                cfg_body = None
            else:
                target_file = files.in_root_target(norm_cfg)
                canonical_cfg = target_file.as_posix() if target_file is not None else norm_cfg
                if canonical_cfg in visited_configs or depth >= _MAX_BRIDGE_DEPTH:
                    _add_gap(summary.gaps, f"{norm_cfg}: cyclic or deeply nested bridge config")
                    cfg_body = None
                else:
                    cfg_body = _read_confined_text(files, norm_cfg, summary.gaps)
            if cfg_body is not None and norm_cfg is not None:
                try:
                    sub_doc = parse_json_strict(cfg_body)
                except (ValueError, RecursionError):
                    _add_gap(summary.gaps, f"{norm_cfg}: invalid JSON")
                    sub_doc = None
                if sub_doc is not None and not isinstance(sub_doc, dict):
                    _add_gap(summary.gaps, f"{norm_cfg}: configuration must be a JSON object")
                elif isinstance(sub_doc, dict):
                    sub_entries = _extract_mcp_servers(sub_doc)
            if not sub_entries:
                summary.flag(
                    "proxied_servers_unresolved",
                    RiskSeverity.MEDIUM,
                    f"MCP bridge '{srv_name}' config '{config_arg}' could not be resolved inside project.",
                    cfg_path,
                    srv_name,
                )
        elif endpoint_url is None:
            summary.flag(
                "proxied_servers_unresolved",
                RiskSeverity.MEDIUM,
                f"MCP bridge '{srv_name}' declares neither an endpoint URL nor a readable in-root config.",
                cfg_path,
                srv_name,
            )

        if endpoint_url is not None:
            summary.flag(
                "endpoint_identity",
                RiskSeverity.MEDIUM,
                f"MCP bridge '{srv_name}' connects to remote endpoint via {bridge_pkg}.",
                cfg_path,
                srv_name,
            )
            _flag_transport(summary, "bridge", cfg_path, srv_name, endpoint_url)

        proxied = [sub_name for sub_name, _ in sub_entries]
        resolved_ver = live_versions.get(bridge_pkg) or live_versions.get(srv_name)
        props: dict[str, Any] = _rec(
            bridge_package=bridge_pkg,
            proxied_servers=proxied,
            registry_origin=reg_origin or None,
            resolved_version=resolved_ver,
        )
        if resolved_ver:
            props["version_assurance"] = "reported"
        clean_ep = endpoint_url and (_origin_only(endpoint_url) or _clean(endpoint_url))
        # Register the parent bridge before recursing so a child with the same name
        # cannot overwrite the bridge component's transport and command fields.
        summary.add_mcp(
            srv_name,
            cfg_path,
            str(cmd) if cmd else None,
            str_args,
            transport="stdio-bridged",
            endpoint_url=clean_ep,
            registry_source=reg_origin or None,
            props=props,
        )
        summary.bridged_servers.append(
            _rec(
                server_name=srv_name,
                endpoint_url=clean_ep,
                transport="stdio-bridged",
                config_path=config_arg and _clean(config_arg),
                source_file=cfg_path,
                **props,
            )
        )
        if sub_entries and norm_cfg is not None and canonical_cfg is not None:
            next_visited = visited_configs | {canonical_cfg}
            for sub_name, sub_cfg in sub_entries:
                if sub_name in top_names:
                    # A backend named like a top-level server is recorded under its gateway.
                    sub_name = f"{srv_name}/{sub_name}"
                sub_ref, _ = _safe_mcp_ref(sub_name)
                exp_key = (canonical_cfg, sub_name, host, client_server_name)
                summary.edge(srv_ref, sub_ref, "delegates-to", norm_cfg)
                if exp_key in seen_expansions:
                    continue
                if expansion_budget[0] >= _MAX_BRIDGE_EXPANSIONS:
                    _add_gap(
                        summary.gaps,
                        f"{norm_cfg}: MCP bridge expansion limit ({_MAX_BRIDGE_EXPANSIONS}) reached",
                    )
                    continue
                seen_expansions.add(exp_key)
                expansion_budget[0] += 1
                bridged_steering.append(
                    (norm_cfg, sub_name, sub_cfg, host, client_server_name, my_auto)
                )
                _audit_mcp_server(
                    files,
                    checkout,
                    summary,
                    live_versions,
                    norm_cfg,
                    sub_name,
                    sub_cfg,
                    bridged_steering,
                    host=host,
                    client_server_name=client_server_name,
                    inherited_auto=my_auto,
                    visited_configs=next_visited,
                    seen_expansions=seen_expansions,
                    expansion_budget=expansion_budget,
                    depth=depth + 1,
                    top_names=top_names,
                )
        return

    direct_url = next(
        (
            str(srv_cfg[k]).strip()
            for k in ("url", "serverUrl", "httpUrl")
            if isinstance(srv_cfg.get(k), str) and _is_http_url(str(srv_cfg[k]).strip())
        ),
        None,
    )
    if direct_url is not None:
        _flag_transport(summary, "server", cfg_path, srv_name, direct_url)
    if not cmd and direct_url is not None:
        summary.add_mcp(
            srv_name,
            cfg_path,
            None,
            str_args,
            transport="http",
            endpoint_url=_origin_only(direct_url) or _clean(direct_url),
            registry_source=reg_origin or None,
            props={"registry_origin": reg_origin} if reg_origin else {},
        )
        return

    segments = (_split_shell_commands(cmd) if isinstance(cmd, str) else []) or [[]]
    segments[-1].extend(str_args)
    primary, targets = _audit_command_segments(
        segments, checkout, summary.gaps, cfg_path, "launcher"
    )
    props = {"registry_origin": reg_origin} if reg_origin else {}
    for target in targets:
        rec = _bind_script_target(
            files,
            summary,
            owner_ref=srv_ref,
            target_path=target,
            source_file=cfg_path,
            role="launcher-target",
            event_or_server=srv_name,
        )
        if rec is not None:
            if target == primary:
                props["launch_target"] = rec["launch_target_sha256"]
            summary.launcher_targets.append(
                _rec(
                    server_name=srv_name,
                    target_path=target,
                    launch_target_sha256=rec["launch_target_sha256"],
                    classifications=rec["classifications"],
                    source_file=cfg_path,
                )
            )
    summary.add_mcp(
        srv_name,
        cfg_path,
        str(cmd) if cmd else None,
        str_args,
        registry_source=reg_origin or None,
        props=props,
    )


def _inspect_mcp_launchers_and_bridges(
    files: ConfinedCollection,
    all_paths: list[str],
    checkout: _CheckoutScripts,
    summary: ControlPlaneAuditSummary,
    live_versions: dict[str, str],
) -> list[_BridgedSteeringEntry]:
    bridged_steering: list[_BridgedSteeringEntry] = []
    seen_expansions: set[tuple[str, str, str, str]] = set()
    docs = _load_json_docs(files, all_paths, MCP_CONFIG_FILES, summary.gaps)
    top_names = frozenset(name for _, doc in docs for name, _ in _extract_mcp_servers(doc))
    for cfg_path, doc in docs:
        host = _steering_host(cfg_path)
        for srv_name, srv_cfg in _extract_mcp_servers(doc):
            _audit_mcp_server(
                files,
                checkout,
                summary,
                live_versions,
                cfg_path,
                srv_name,
                srv_cfg,
                bridged_steering,
                host=host,
                client_server_name=srv_name,
                inherited_auto=False,
                visited_configs=frozenset({cfg_path}),
                seen_expansions=seen_expansions,
                expansion_budget=[0],
                top_names=top_names,
            )
    return bridged_steering


def _is_steering_rel(rel: str) -> bool:
    folded = rel.casefold()
    return any(
        folded == pref or folded.startswith(pref + "/") or pref.startswith(folded + "/")
        for pref in _STEERING_PREFIXES_FOLDED
    )


def _resolve_steering_symlinks(
    raw_rel: str, files: ConfinedCollection, unresolved: list[str] | None = None
) -> bool:
    """Walk ``raw_rel`` component-by-component, resolving in-root symlinks before ``..``.

    Each step inspects the prefix walked so far, so the walk is bounded by component
    count: every collection lookup costs the prefix's length, and an unbounded root would
    cost quadratic time. A root that exceeds the bound, or that enters a directory the
    collection excludes (whose symlinks are never resolved), is reported through
    ``unresolved`` and returns ``False`` so the caller records a coverage gap.
    """
    queue: deque[str] = deque(seg for seg in raw_rel.split("/") if seg and seg != ".")
    resolved: list[str] = []
    above = 0
    hops = 0
    steps = 0
    while queue:
        steps += 1
        if steps > _MAX_STEERING_COMPONENTS:
            if unresolved is not None:
                unresolved.append(f"more than {_MAX_STEERING_COMPONENTS} path components")
            return False
        seg = queue.popleft()
        if seg == "..":
            if resolved:
                resolved.pop()
            else:
                above += 1
            continue
        if above > 0:
            resolved.append(seg)
            continue
        candidate = "/".join([*resolved, seg])
        if files.excluded(candidate):
            # A root that is an excluded directory names that tree. A root below one
            # names an entry the collection never inspects, which may be a link.
            if queue:
                if unresolved is not None:
                    unresolved.append(
                        "lies below an excluded directory, whose links are not resolved"
                    )
                return False
            resolved.append(seg)
            continue
        if files.is_directory(candidate):
            dir_target = files.link_target(candidate)
            if dir_target is not None:
                hops += 1
                if hops > _MAX_SYMLINK_HOPS:
                    return True
                resolved = []
                if dir_target != ".":
                    for part in reversed(dir_target.split("/")):
                        if part and part != ".":
                            queue.appendleft(part)
                continue
            resolved.append(seg)
            continue
        file_target = files.in_root_target(candidate)
        if file_target is not None:
            target_posix = file_target.as_posix()
            if target_posix != candidate:
                hops += 1
                if hops > _MAX_SYMLINK_HOPS:
                    return True
                resolved = []
                for part in reversed(target_posix.split("/")):
                    if part and part != ".":
                        queue.appendleft(part)
                continue
            resolved.append(seg)
            continue
        if files.path_identity(candidate) is not None:
            # Symlink refused by ConfinedCollection (escapes root, loops, or points to root).
            return True
        resolved.append(seg)
    if above > 0:
        return False
    final = "/".join(resolved)
    return not final or _is_steering_rel(final)


def _covers_steering_path(
    root_arg: str,
    project_roots: tuple[str, ...],
    *,
    files: ConfinedCollection | None = None,
    unresolved: list[str] | None = None,
) -> bool:
    cleaned = _QUOTED_LEADING_VAR_RE.sub(r"\2", root_arg.strip().replace("\\", "/")).strip("'\"")
    if not cleaned or cleaned == "~" or cleaned.startswith("~/"):
        return True
    if "\x00" in cleaned:
        if unresolved is not None:
            unresolved.append("contains a NUL byte")
        return False
    # Every reading of a placeholder counts: the literal text, the project root it names
    # and its `:-` default, so a `..` after the placeholder cannot hide a steering path.
    readings = [cleaned]
    var_match = _STEERING_ROOT_VAR_RE.match(cleaned)
    if var_match is not None:
        rest = (var_match.group(2) or "").lstrip("/")
        readings.append(rest or ".")
        if var_match.group(1):
            readings.append(posixpath.join(var_match.group(1), rest))
    if any(_reading_covers_steering(r, project_roots, files, unresolved) for r in readings):
        return True
    if unresolved is not None and not unresolved and _UNRESOLVED_VAR_RE.search(readings[-1]):
        unresolved.append("uses unresolved variable expansion")
    return False


def _reading_covers_steering(
    cleaned: str,
    project_roots: tuple[str, ...],
    files: ConfinedCollection | None,
    unresolved: list[str] | None,
) -> bool:
    if cleaned.startswith("//"):
        # POSIX leaves a leading `//` implementation-defined; Linux reads it as `/`.
        cleaned = "/" + cleaned.lstrip("/")
    # Absolute and parent-relative roots are placed against the audited project root.
    rel_candidates: list[str] = []
    raw_rel_candidates: list[str] = []
    if not cleaned.startswith("/"):
        raw_rel_candidates.append(cleaned)
    for project in project_roots:
        proj_prefix = project.rstrip("/") + "/"
        if cleaned.startswith(proj_prefix):
            raw_rel_candidates.append(cleaned[len(proj_prefix) :])
        joined = posixpath.normpath(posixpath.join(project, cleaned))
        if joined == project or project.startswith(joined.rstrip("/") + "/"):
            return True
        if joined.startswith(proj_prefix):
            rel = joined[len(proj_prefix) :]
            if _is_steering_rel(rel):
                return True
            rel_candidates.append(rel)
    if files is not None:
        for raw_rel in dict.fromkeys(raw_rel_candidates + rel_candidates):
            if _resolve_steering_symlinks(raw_rel, files, unresolved):
                return True
    return False


def _steering_host(path: str) -> str:
    if path.startswith(".claude/") or path == ".mcp.json":
        return "claude"
    return path.split("/", 1)[0]


def _claude_mcp_prefix(server: str) -> str:
    # The client replaces each non-identifier UTF-16 code unit when naming tools.
    normalized = re.sub(
        r"[^a-zA-Z0-9_-]", lambda match: "__" if ord(match[0]) > 0xFFFF else "_", server
    )
    if server.startswith("claude.ai "):
        normalized = re.sub(r"_+", "_", normalized).strip("_")
    return "mcp__" + normalized


def _allows_mcp_server(rules: list[str], prefix: str) -> bool:
    exact = bisect_left(rules, prefix)
    # A bare rule is parsed at the first double underscore. For ambiguous server
    # names Claude requires the tool-qualified form, including the whole name.
    bare_address = "__" not in prefix[5:] and not prefix.endswith("_")
    if bare_address and exact < len(rules) and rules[exact] == prefix:
        return True
    scoped = f"{prefix}__"
    index = bisect_right(rules, scoped)  # A tool-qualified address needs a nonempty tool.
    return index < len(rules) and rules[index].startswith(scoped)


def _claude_unconditional_rule(rule: str) -> str | None:
    if "(" not in rule and ")" not in rule:
        return rule
    # Only a tool name that failed MCP namespace parsing can use the client's
    # literal-name fallback. An ordinary MCP call rule with parentheses is invalid.
    if rule.endswith("(*)"):
        literal = rule[:-3]
        mcp_namespace = literal.startswith("mcp__") and literal[5:].partition("__")[0]
        if not mcp_namespace and "(" not in literal and ")" not in literal:
            return literal
    return None


def _claude_mcp_allow(rule: str) -> str | None:
    """Return the client's unconditional MCP rule, preserving literal tool names."""
    normalized = _claude_unconditional_rule(rule)
    if normalized is None:
        return None
    rule = normalized
    if not rule.startswith("mcp__") or any(c.isspace() for c in rule):
        return None
    server, separator, tool = rule[5:].partition("__")
    if not server:
        # A leading delimiter makes the client's namespace parser fall back to
        # exact full-tool equality. Such a name cannot authorize a wildcard.
        return rule if separator and tool and "*" not in tool else None
    return rule if "*" not in server and (not separator or tool) else None


def _claude_deny_rule(rule: str) -> str | None:
    literal = _claude_unconditional_rule(rule)
    if not literal or not re.fullmatch(r"[a-zA-Z0-9_*-]+", literal):
        return None
    if "_" not in literal and literal[0].islower():
        return None
    return re.sub(r"\*+", "*", literal)


_CLAUDE_DENY_GLOB_WORK = 4_000_000


class _ClaudeServerDenies:
    """Look up exact namespaces and prefix globs before considering general globs."""

    def __init__(self, rules: set[str]) -> None:
        self.rules = rules
        self.prefixes: list[str] = []
        self.globs: list[str] = []
        for rule in sorted(rules):
            if not rule.endswith("*"):
                continue
            prefix = rule[:-1]
            if "*" in prefix:
                self.globs.append(rule)
            elif not self.prefixes or not prefix.startswith(self.prefixes[-1]):
                self.prefixes.append(prefix)
        # A project controls both the glob set and the number of servers.
        self.remaining_glob_work = _CLAUDE_DENY_GLOB_WORK

    def covers(self, server: str) -> bool:
        address = server + "__"
        parsed_server = address[5:].partition("__")[0]
        if (len(server) > 5 and server in self.rules) or (
            parsed_server and "mcp__" + parsed_server in self.rules
        ):
            return True
        index = bisect_right(self.prefixes, address) - 1
        if index >= 0 and address.startswith(self.prefixes[index]):
            return True
        for glob in self.globs:
            work = len(glob) * len(address)
            if self.remaining_glob_work < work:
                self.remaining_glob_work = -1
                return False
            self.remaining_glob_work -= work
            # A terminal star can consume every possible tool suffix if the
            # pattern already matches the fixed namespace through its delimiter.
            if fnmatchcase(address, glob):
                return True
        return False


def _inspect_steering_surfaces(
    files: ConfinedCollection,
    all_paths: list[str],
    summary: ControlPlaneAuditSummary,
    bridged_steering: list[_BridgedSteeringEntry] | None = None,
) -> None:
    modes: dict[str, list[str]] = {}
    claude_allows: dict[str, list[str]] = {}
    claude_denies: set[str] = set()
    claude_prompting = False
    for s_path, doc in _load_json_docs(files, all_paths, PERMISSION_CONFIG_FILES, summary.gaps):
        host = _steering_host(s_path)
        auto_edit_modes = modes.setdefault(host, [])
        perms = _as_dict(doc.get("permissions"))
        mode = perms.get("defaultMode") or perms.get("mode")
        if mode in ("acceptEdits", "bypassPermissions", "auto"):
            auto_edit_modes.append(f"{s_path}:{mode}")
        allow = [r for r in _as_list(perms.get("allow")) if isinstance(r, str)]
        if host == "claude":
            # The client does not trim permission rules before matching them.
            allow = [rule for rule in allow if rule == rule.strip()]
        else:
            allow = [rule.strip() for rule in allow]
        if any(
            rule in {"Edit", "Write"}
            or (
                host != "claude"
                and (rule == "*" or (not rule.startswith("mcp__") and "filesystem" in rule))
            )
            for rule in allow
        ):
            auto_edit_modes.append(f"{s_path}:write-allowance")
        if host == "claude":
            claude_allows[s_path] = sorted(
                normalized for rule in allow if (normalized := _claude_mcp_allow(rule)) is not None
            )
            # Only committed project settings can clear a committed steering surface;
            # developer-local overrides (.claude/settings.local.json) must not suppress
            # findings that still trigger on fresh checkouts.
            if s_path.rsplit("/", 1)[-1] != "settings.local.json":
                claude_prompting |= mode in ("default", "plan")
                claude_denies.update(
                    normalized
                    for rule in _as_list(perms.get("deny"))
                    if isinstance(rule, str) and (normalized := _claude_deny_rule(rule)) is not None
                )
        if doc.get("approvalPolicy") in ("never", "auto-edit"):
            auto_edit_modes.append(f"{s_path}:{doc['approvalPolicy']}")

    project_roots = (files.root.as_posix(), files.root.resolve().as_posix())
    server_denies = _ClaudeServerDenies(claude_denies)

    entries: list[_BridgedSteeringEntry] = [
        (cfg_path, srv_name, srv_cfg, _steering_host(cfg_path), srv_name, False)
        for cfg_path, doc in _load_json_docs(files, all_paths, MCP_CONFIG_FILES, summary.gaps)
        for srv_name, srv_cfg in _extract_mcp_servers(doc)
    ]
    if bridged_steering:
        entries.extend(bridged_steering)

    for cfg_path, srv_name, srv_cfg, host, client_name, inherited_auto in entries:
        cmd = str(srv_cfg.get("command") or "")
        args = [str(a) for a in _as_list(srv_cfg.get("args")) if isinstance(a, (str, int, float))]
        joined = " ".join([cmd, *args]).lower()
        if "filesystem" not in srv_name.lower() and "server-filesystem" not in joined:
            continue
        # For bridged servers, the host client enforces allow/deny/autoApprove against
        # the top-level client-facing gateway name, not the internal proxied backend name.
        prefix = _claude_mcp_prefix(client_name)
        # A future or custom server can publish additional write tools. Only the
        # owning client's deny of the whole server covers this open-ended surface.
        deny_covered = host == "claude" and server_denies.covers(prefix)
        srv_auto = (
            inherited_auto
            or bool(srv_cfg.get("autoApprove"))
            or len(_as_list(srv_cfg.get("alwaysAllow"))) > 0
        )
        eff_modes = list(modes.get(host, ()))
        if host == "claude":
            eff_modes.extend(
                f"{source}:mcp-allowance"
                for source, rules in claude_allows.items()
                if _allows_mcp_server(rules, prefix)
            )
        if srv_auto:
            eff_modes.append(f"{cfg_path}:{client_name}:alwaysAllow")
        writable = bool(eff_modes) and not deny_covered
        approval_status = "preapproved" if writable else "unverified"
        if deny_covered:
            approval_status = "denied"
        elif not writable and host == "claude" and claude_prompting:
            approval_status = "prompting"
        roots = [
            a
            for a in args
            if not a.startswith("-")
            and "server-filesystem" not in a
            and a not in {"-y", "npx", "uvx"}
        ] or ["."]
        for raw_root in roots:
            # MCP stdio has no standard readOnly field or CLI switch. Positional
            # launcher text is not an access-control decision by a filesystem.
            r_arg = raw_root.removesuffix(":ro")
            unresolved: list[str] = []
            if not _covers_steering_path(r_arg, project_roots, files=files, unresolved=unresolved):
                if unresolved:
                    _add_gap(
                        summary.gaps,
                        f"{cfg_path}: filesystem server '{_clean(srv_name)}' root "
                        f"'{_clean(r_arg)[:120]}' could not be resolved: {unresolved[0]}",
                    )
                continue
            summary.steering_surfaces.append(
                _rec(
                    server_name=srv_name,
                    root_path=r_arg,
                    permission_modes=eff_modes,
                    approval_status=approval_status,
                    read_only=False,
                    deny_covered=deny_covered,
                    writable=writable,
                    source_file=cfg_path,
                )
            )
            if writable:
                summary.flag(
                    "steering_surface_writable",
                    RiskSeverity.CRITICAL,
                    f"Filesystem server '{srv_name}' rooted at '{r_arg}' can modify steering files under {', '.join(eff_modes)} (F20).",
                    cfg_path,
                    srv_name,
                )
            elif approval_status == "unverified":
                summary.flag(
                    "steering_surface_unverified",
                    RiskSeverity.MEDIUM,
                    f"Write approval for filesystem server '{srv_name}' rooted at '{r_arg}' "
                    "could not be established from the declaring client's configuration.",
                    cfg_path,
                    srv_name,
                )

    if server_denies.remaining_glob_work < 0:
        summary.gaps.append("Claude deny rules: namespace wildcard comparison limit reached")


def _record_hosted_tool(
    summary: ControlPlaneAuditSummary,
    item: dict[str, Any],
    source_file: str,
    assurance: AssuranceLevel,
) -> None:
    provider = _clean(item.get("provider") or "unknown")
    tool_type = _clean(item.get("tool_type") or item.get("type") or "mcp")
    name = _clean(item.get("name") or item.get("server_label") or f"{provider}-{tool_type}")
    approval = str(item.get("require_approval") or item.get("approval_mode") or "always").lower()
    origin = _origin_only(str(item.get("server_url") or item.get("server_origin") or ""))
    token_names = [_clean(t) for t in _as_list(item.get("token_names")) if str(t).strip()]
    if isinstance(item.get("token_name"), str) and item["token_name"].strip():
        token_names.append(_clean(item["token_name"]))
    has_literal = bool(item.get("token_literal"))
    for hdr_key in ("authorization", "api_key", "access_token", "token"):
        raw_val = item.get(hdr_key)
        if isinstance(raw_val, str) and raw_val.strip():
            token_names.append(hdr_key)
            if not raw_val.strip().startswith("${") and (
                _contains_secret(raw_val) or len(raw_val.strip()) >= 16
            ):
                has_literal = True
    for hk, hv in _as_dict(item.get("headers")).items():
        token_names.append(_clean(hk))
        if (
            isinstance(hv, str)
            and not hv.strip().startswith("${")
            and (_contains_secret(hv) or "bearer " in hv.lower())
        ):
            has_literal = True

    props = _rec(
        provider=provider,
        tool_type=tool_type,
        approval_mode=approval,
        server_origin=origin or None,
        token_names=sorted(set(token_names)),
    )
    summary.add_ctrl(name, "hosted-tool", source_file, props, assurance=assurance)
    summary.hosted_tools.append(
        _rec(
            name=name,
            has_literal_token=has_literal,
            source_file=source_file,
            assurance=assurance.value,
            **props,
        )
    )
    for hit, cat, msg in (
        (
            approval in {"never", "auto", "false"},
            "hosted_mcp_auto_approved",
            f"Provider-hosted tool '{name}' sets require_approval='{approval}'.",
        ),
        (
            has_literal,
            "hosted_mcp_token_literal",
            f"Provider-hosted tool '{name}' embeds a literal credential or bearer token (F16).",
        ),
        (
            tool_type.lower() in CODE_EXEC_HOSTED_TOOLS,
            "provider_code_execution",
            f"Provider-hosted tool '{name}' enables remote code/shell execution ('{tool_type}').",
        ),
    ):
        if hit:
            summary.flag(cat, RiskSeverity.HIGH, msg, source_file, name)


def _record_ci_agent(
    summary: ControlPlaneAuditSummary,
    *,
    action_ref: str,
    triggers: list[str],
    skip_perms: bool,
    mcp_config_raw: str | None,
    source_file: str,
    assurance: AssuranceLevel,
) -> None:
    action_slug = action_ref.split("@", 1)[0].strip()
    ref_pin = action_ref.split("@", 1)[1].strip() if "@" in action_ref else ""
    pinned = bool(_HEX_40_RE.match(ref_pin))
    short_name = action_slug.split("/")[-1] or action_slug
    comp_name = f"ci.{short_name}:{_sha256_hex(f'{source_file}:{action_ref}'.encode())[:8]}"
    host_id = f"github-actions:{action_slug}"
    inline_servers: list[str] = []

    if isinstance(mcp_config_raw, str) and mcp_config_raw.strip():
        try:
            mcp_doc = parse_json_strict(mcp_config_raw)
        except (ValueError, RecursionError):
            summary.gaps.append(f"{source_file}: invalid inline mcp_config")
            mcp_doc = None
        if isinstance(mcp_doc, dict):
            for s_name, s_cfg in _extract_mcp_servers(mcp_doc):
                inline_servers.append(s_name)
                if _contains_secret(json.dumps(s_cfg)):
                    summary.flag(
                        "hosted_mcp_token_literal",
                        RiskSeverity.HIGH,
                        f"CI agent '{comp_name}' inline mcp_config server '{s_name}' contains a literal secret (F16).",
                        source_file,
                        comp_name,
                    )
                if s_cfg.get("autoApprove") or s_cfg.get("require_approval") == "never":
                    summary.flag(
                        "hosted_mcp_auto_approved",
                        RiskSeverity.HIGH,
                        f"CI agent '{comp_name}' inline mcp_config server '{s_name}' is auto-approved.",
                        source_file,
                        comp_name,
                    )
                summary.add_mcp(
                    f"inline:{s_name}",
                    source_file,
                    str(s_cfg.get("command") or ""),
                    [
                        str(a)
                        for a in _as_list(s_cfg.get("args"))
                        if isinstance(a, (str, int, float))
                    ],
                    props=_rec(inline_host=host_id),
                    assurance=assurance,
                )

    props = _rec(
        host=host_id,
        action=action_slug,
        ref=ref_pin or "unpinned",
        pinned=pinned,
        triggers=sorted(set(triggers)),
        skip_permissions=skip_perms,
        inline_mcp_servers=inline_servers,
    )
    summary.add_ctrl(comp_name, "ide-agent", source_file, props, assurance=assurance)
    summary.ci_agents.append(
        _rec(name=comp_name, source_file=source_file, assurance=assurance.value, **props)
    )
    bad_triggers = sorted(set(triggers) & UNTRUSTED_CI_TRIGGERS)
    for hit, cat, msg in (
        (
            not pinned,
            "ci_agent_action_unpinned",
            f"CI agent action '{action_ref}' is not pinned to a 40-character commit SHA.",
        ),
        (
            bool(bad_triggers),
            "ci_agent_untrusted_trigger",
            f"CI agent '{comp_name}' runs on untrusted trigger(s): {', '.join(bad_triggers)} (F18).",
        ),
        (
            skip_perms,
            "ci_agent_skip_permissions",
            f"CI agent '{comp_name}' disables permission prompts (--dangerously-skip-permissions) (F18).",
        ),
    ):
        if hit:
            summary.flag(cat, RiskSeverity.HIGH, msg, source_file, comp_name)


def _inspect_workflows_and_claims(
    files: ConfinedCollection,
    all_paths: list[str],
    summary: ControlPlaneAuditSummary,
    decl_sources: list[tuple[str, dict[str, Any], AssuranceLevel]],
) -> None:
    for wf_path in [
        p for p in all_paths if p.startswith(".github/workflows/") and p.endswith((".yml", ".yaml"))
    ]:
        text = _read_confined_text(files, wf_path, summary.gaps)
        if text is None:
            continue
        try:
            doc = _parse_yaml(_ON_KEY_RE.sub(r'\1"on"\2', text))
        except (PolicyError, ValueError, RecursionError):
            summary.gaps.append(f"{wf_path}: invalid YAML")
            continue
        on_block = doc.get("on")
        if isinstance(on_block, str):
            triggers = [on_block]
        elif isinstance(on_block, (list, dict)):
            triggers = [str(t) for t in on_block]
        else:
            triggers = []

        for job_cfg in _as_dict(doc.get("jobs")).values():
            for step in _as_list(_as_dict(job_cfg).get("steps")):
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses") or "").strip()
                if not any(
                    k in uses.lower()
                    for k in ("claude-code-action", "codex-action", "gemini-cli", "agent-action")
                ):
                    continue
                with_blk = _as_dict(step.get("with"))
                joined_with = " ".join(str(v) for v in with_blk.values()).lower()
                skip_perms = (
                    "--dangerously-skip-permissions" in joined_with
                    or "dangerously_skip_permissions: true" in joined_with
                    or with_blk.get("dangerously_skip_permissions") is True
                    or str(with_blk.get("approval_policy") or "").lower() == "never"
                )
                mcp_val = with_blk.get("mcp_config")
                mcp_cfg = str(mcp_val) if isinstance(mcp_val, str) else None
                _record_ci_agent(
                    summary,
                    action_ref=uses,
                    triggers=triggers,
                    skip_perms=skip_perms,
                    mcp_config_raw=mcp_cfg,
                    source_file=wf_path,
                    assurance=AssuranceLevel.OBSERVED,
                )

    for src_file, doc, assurance in decl_sources:
        for ht in _as_list(doc.get("hosted_tools")):
            if isinstance(ht, dict):
                _record_hosted_tool(summary, ht, str(ht.get("file") or src_file), assurance)
        for ca in _as_list(doc.get("ci_agents")):
            if isinstance(ca, dict) and isinstance(ca.get("action"), str):
                raw_trigs = ca.get("triggers")
                trigs = (
                    [str(t) for t in raw_trigs]
                    if isinstance(raw_trigs, list)
                    else ([str(ca["trigger"])] if ca.get("trigger") else [])
                )
                raw_mcp = ca.get("mcp_config")
                _record_ci_agent(
                    summary,
                    action_ref=ca["action"],
                    triggers=trigs,
                    skip_perms=bool(ca.get("skip_permissions")),
                    mcp_config_raw=raw_mcp if isinstance(raw_mcp, str) else None,
                    source_file=str(ca.get("file") or src_file),
                    assurance=assurance,
                )
        for ac in _as_list(doc.get("agent_constructors")):
            if not isinstance(ac, dict):
                continue
            fw = _clean(ac.get("framework") or "langgraph")
            ag_name = _clean(ac.get("name") or f"{fw}-agent")
            ag_file = str(ac.get("file") or src_file)
            raw_models = _as_list(ac.get("models")) or ([ac["model"]] if ac.get("model") else [])
            models = [_clean(m) for m in raw_models if str(m).strip()]
            tools = [_clean(t) for t in _as_list(ac.get("tools")) if str(t).strip()]
            fs_paths = [_clean(p) for p in _as_list(ac.get("filesystem_paths"))]
            egress = [_clean(d) for d in _as_list(ac.get("egress_domains"))]
            reg_src = _origin_only(str(ac.get("registry_source") or "")) or None
            props = _rec(
                framework=fw,
                bound_models=models,
                bound_tools=tools,
                filesystem_paths=fs_paths,
                egress_domains=egress,
                registry_source=reg_src,
                reachability_tier=AssuranceLevel.DECLARED.value,
            )
            summary.add_ctrl(
                ag_name, "framework-agent", ag_file, props, assurance=AssuranceLevel.DECLARED
            )
            ag_ref = f"agent-control:{ag_name}"
            for m_name in models:
                m_comp = ModelComponent(
                    bom_ref=f"model:{m_name}",
                    name=m_name,
                    source_path=ag_file,
                    assurance_level=AssuranceLevel.DECLARED,
                )
                summary.add(m_comp)
                summary.edge(ag_ref, m_comp.bom_ref, "uses-model", ag_file)
            for t_name in tools:
                t_comp = ToolComponent(
                    bom_ref=f"tool:{t_name}",
                    name=t_name,
                    source_path=ag_file,
                    assurance_level=AssuranceLevel.DECLARED,
                )
                summary.add(t_comp)
                summary.edge(ag_ref, t_comp.bom_ref, "provides-tool", ag_file)
            summary.framework_agents.append(_rec(agent_name=ag_name, source_file=ag_file, **props))


def _inspect_identities_and_authority(
    summary: ControlPlaneAuditSummary,
    decl_sources: list[tuple[str, dict[str, Any], AssuranceLevel]],
) -> None:
    svc_usage: dict[str, list[str]] = {}
    for src_file, doc, _ in decl_sources:
        for entry in _as_list(doc.get("identities")):
            if not isinstance(entry, dict):
                continue
            p_id = _clean(entry.get("id") or entry.get("spiffe_id") or entry.get("name"))
            if not p_id:
                continue
            default_kind = "spiffe" if p_id.startswith("spiffe://") else "service-identity"
            kind = _clean(entry.get("kind") or default_kind)
            scopes = [_clean(s) for s in _as_list(entry.get("scopes")) if str(s).strip()]
            audience = _clean(entry.get("audience") or "")
            delegates = [_clean(d) for d in _as_list(entry.get("delegates_to")) if str(d).strip()]
            bound_from = [
                _clean(b) for b in _as_list(entry.get("bound_components")) if str(b).strip()
            ]

            broad_oauth = kind == "oauth-grant" and (
                not audience
                or audience == "*"
                or any(s in {"*", "admin", "cloud-platform", "full_access"} for s in scopes)
            )
            for hit, cat, sev, msg in (
                (
                    kind == "spiffe" and not _SPIFFE_RE.match(p_id),
                    "invalid_spiffe_id",
                    RiskSeverity.MEDIUM,
                    f"Declared SPIFFE ID '{p_id}' is not a valid spiffe://trust-domain/path URI.",
                ),
                (
                    broad_oauth,
                    "broad_oauth_scope",
                    RiskSeverity.HIGH,
                    f"OAuth grant '{p_id}' has over-broad scope or unconstrained audience.",
                ),
                (
                    bool(delegates and not scopes and not audience),
                    "unconstrained_delegation",
                    RiskSeverity.HIGH,
                    f"Identity '{p_id}' delegates authority to {', '.join(delegates)} without scope or audience constraints.",
                ),
            ):
                if hit:
                    summary.flag(cat, sev, msg, src_file, p_id)
            if kind == "service-identity":
                svc_usage.setdefault(p_id, []).extend(bound_from or ["agent:repository"])

            id_ref = f"agent-control:{p_id}"
            props = _rec(
                identity_kind=kind,
                audience=audience or None,
                scopes=scopes,
                delegates_to=delegates,
            )
            summary.add_ctrl(p_id, "identity", src_file, props, assurance=AssuranceLevel.DECLARED)
            for b_ref in bound_from:
                summary.edge(b_ref, id_ref, "acts-as-identity", src_file)
            for d_target in delegates:
                summary.edge(id_ref, f"agent-control:{d_target}", "delegates-to", src_file)
            summary.identities.append(
                _rec(
                    principal_id=p_id,
                    bound_components=bound_from,
                    reachable_identities=sorted({p_id, *delegates}),
                    source_file=src_file,
                    **props,
                )
            )

    for svc_id, holders in svc_usage.items():
        uniq_holders = sorted(set(holders))
        if len(uniq_holders) > 1:
            summary.flag(
                "shared_service_identity",
                RiskSeverity.HIGH,
                f"Service identity '{svc_id}' is shared across multiple principals: {', '.join(uniq_holders)}.",
                "agent.yaml",
                svc_id,
            )


def compute_identity_blast_radius(
    summary: ControlPlaneAuditSummary, compromised_ref: str
) -> list[str]:
    """Return all identity principals a compromised tool or server can act as."""
    id_names = {item["principal_id"] for item in summary.identities}
    forward: dict[str, set[str]] = {}
    for rel in summary.bom.dependencies:
        forward.setdefault(rel.source_ref, set()).add(rel.target_ref)
    visited: set[str] = set()
    queue = [compromised_ref]
    reached_ids: set[str] = set()
    while queue:
        curr = queue.pop(0)
        if curr in visited:
            continue
        visited.add(curr)
        short = curr.split(":", 1)[-1]
        if short in id_names:
            reached_ids.add(short)
        for nxt in forward.get(curr, set()):
            if nxt not in visited:
                queue.append(nxt)
    return sorted(reached_ids)


def _backward_affected_refs(summary: ControlPlaneAuditSummary, target_ref: str) -> list[str]:
    rev: dict[str, set[str]] = {}
    for rel in summary.bom.dependencies:
        rev.setdefault(rel.target_ref, set()).add(rel.source_ref)
    visited: set[str] = set()
    queue = [target_ref]
    while queue:
        curr = queue.pop(0)
        for prev in rev.get(curr, set()):
            if prev not in visited and prev != target_ref:
                visited.add(prev)
                queue.append(prev)
    return sorted(visited)


def diff_control_plane_audits(
    baseline: ControlPlaneAuditSummary,
    current: ControlPlaneAuditSummary,
    *,
    trace_reported_refs: frozenset[str] = frozenset(),
    live_observed_refs: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Compute reach-rated diff alerts consolidating backward blast-radius affected_refs."""
    alerts: list[dict[str, Any]] = []

    def _emit(root_cause: str, sev: RiskSeverity, changed_ref: str, detail: str) -> None:
        affected = _backward_affected_refs(current, changed_ref)
        pool = {changed_ref, *affected}
        tier = (
            "observed"
            if pool & live_observed_refs
            else ("reported" if pool & trace_reported_refs else "declared")
        )
        alert_id = _sha256_hex(f"{root_cause}:{changed_ref}".encode())[:16]
        alerts.append(
            _rec(
                alert_id=alert_id,
                root_cause=root_cause,
                severity=sev.value,
                reachability_tier=tier,
                changed_ref=changed_ref,
                affected_refs=affected,
                description=neutralize(detail),
            )
        )

    def _target_map(s: ControlPlaneAuditSummary) -> dict[str, str]:
        out = {f"hook-target:{h['target_path']}": h["launch_target_sha256"] for h in s.hook_targets}
        out.update(
            {
                f"launcher-target:{lt['target_path']}": lt["launch_target_sha256"]
                for lt in s.launcher_targets
            }
        )
        out.update(
            {
                f"preamble-target:{pt['target_path']}": pt["launch_target_sha256"]
                for pt in s.preamble_targets
            }
        )
        return out

    base_targets = _target_map(baseline)
    curr_targets = _target_map(current)
    for key, curr_sha in sorted(curr_targets.items()):
        base_sha = base_targets.get(key)
        if base_sha is None:
            _emit(
                "launch_target_added",
                RiskSeverity.CRITICAL,
                f"agent-control:{key}",
                f"Launch target '{key}' (digest {curr_sha[:12]}) is not in the baseline.",
            )
        elif base_sha != curr_sha:
            _emit(
                "launch_target_changed",
                RiskSeverity.CRITICAL,
                f"agent-control:{key}",
                f"Launch target '{key}' digest changed from {base_sha[:12]} to {curr_sha[:12]}.",
            )
    for key, base_sha in sorted(base_targets.items()):
        if key not in curr_targets:
            _emit(
                "launch_target_removed",
                RiskSeverity.CRITICAL,
                f"agent-control:{key}",
                f"Launch target '{key}' (baseline digest {base_sha[:12]}) was removed.",
            )

    def _hook_keys(s: ControlPlaneAuditSummary) -> set[tuple[str, str, str]]:
        return {(h["source_file"], h["event"], h["command_digest"]) for h in s.hook_commands}

    base_hooks = _hook_keys(baseline)
    curr_hooks = _hook_keys(current)
    for src, event, digest in sorted(curr_hooks - base_hooks):
        _emit(
            "hook_command_changed",
            RiskSeverity.CRITICAL,
            f"hook-command:{src}:{event}:{digest[:12]}",
            f"Hook command for '{event}' in {src} (digest {digest[:12]}) is not in the baseline.",
        )
    for src, event, digest in sorted(base_hooks - curr_hooks):
        _emit(
            "hook_command_removed",
            RiskSeverity.CRITICAL,
            f"hook-command:{src}:{event}:{digest[:12]}",
            f"Hook command for '{event}' in {src} (baseline digest {digest[:12]}) was removed.",
        )

    def _preamble_keys(s: ControlPlaneAuditSummary) -> set[tuple[str, str]]:
        return {(p["skill_path"], p["command_digest"]) for p in s.skill_preambles}

    base_preambles = _preamble_keys(baseline)
    curr_preambles = _preamble_keys(current)
    for skill_path, digest in sorted(curr_preambles - base_preambles):
        _emit(
            "skill_preamble_changed",
            RiskSeverity.CRITICAL,
            f"skill-preamble:{skill_path}:{digest[:12]}",
            f"Skill shell preamble in {skill_path} (digest {digest[:12]}) is not in the baseline.",
        )
    for skill_path, digest in sorted(base_preambles - curr_preambles):
        _emit(
            "skill_preamble_removed",
            RiskSeverity.CRITICAL,
            f"skill-preamble:{skill_path}:{digest[:12]}",
            f"Skill shell preamble in {skill_path} (baseline digest {digest[:12]}) was removed.",
        )

    base_writable = {s["server_name"] for s in baseline.steering_surfaces if s.get("writable")}
    for s in current.steering_surfaces:
        if s.get("writable") and s["server_name"] not in base_writable:
            srv_ref, _ = _safe_mcp_ref(str(s["server_name"]))
            _emit(
                "steering_surface_opened",
                RiskSeverity.CRITICAL,
                srv_ref,
                f"Steering surface became writable via server '{s['server_name']}' at '{s['root_path']}'.",
            )

    base_id_del = {
        i["principal_id"]: set(_as_list(i.get("delegates_to"))) | set(_as_list(i.get("scopes")))
        for i in baseline.identities
    }
    for i in current.identities:
        pid = i["principal_id"]
        curr_set = set(_as_list(i.get("delegates_to"))) | set(_as_list(i.get("scopes")))
        if pid not in base_id_del:
            _emit(
                "identity_added",
                RiskSeverity.HIGH,
                f"agent-control:{pid}",
                f"Identity '{pid}' is not in the baseline.",
            )
        elif not curr_set.issubset(base_id_del[pid]):
            _emit(
                "delegation_widened",
                RiskSeverity.HIGH,
                f"agent-control:{pid}",
                f"Identity '{pid}' widened scopes or delegation targets.",
            )

    return alerts


def audit_project_control_plane(
    project_root: Path,
    *,
    claims_path: Path | None = None,
    baseline_root: Path | None = None,
    live_versions: dict[str, str] | None = None,
    trace_reported_refs: frozenset[str] = frozenset(),
    live_observed_refs: frozenset[str] = frozenset(),
) -> ControlPlaneAuditSummary:
    """Run confined control-plane audit across hook targets, bridges, steering, CI, and identities."""
    summary = ControlPlaneAuditSummary()
    decl_sources: list[tuple[str, dict[str, Any], AssuranceLevel]] = []
    if claims_path is not None:
        try:
            with open_regular_file(claims_path) as stream:
                raw_claims = stream.read(4_194_304 + 1)
            if len(raw_claims) > 4_194_304:
                raise ValueError("claims exceed byte budget")
            parsed = parse_json_strict(raw_claims.decode("utf-8"), max_bytes=4_194_304)
            if not isinstance(parsed, dict):
                summary.gaps.append(
                    f"{neutralize(claims_path.name)}: claims file is not a JSON object"
                )
            else:
                for section in ("hosted_tools", "ci_agents", "agent_constructors", "identities"):
                    if section in parsed and (
                        not isinstance(parsed[section], list)
                        or not all(isinstance(item, dict) for item in parsed[section])
                    ):
                        summary.gaps.append(f"claims: invalid {section} collection")
                decl_sources.append(("shadowscan:claims", parsed, AssuranceLevel.DECLARED))
        except (OSError, ValueError, RecursionError):
            summary.gaps.append(f"{neutralize(claims_path.name)}: invalid JSON")

    with ConfinedCollection(project_root, summary.gaps) as files:
        all_paths = sorted(p.as_posix() for p in files.iter_files())
        # Directories carry a trailing '/', so an operand naming one is not read as a script.
        project_paths = frozenset(all_paths).union(
            p[: i + 1] for p in all_paths for i, c in enumerate(p) if c == "/"
        )
        for decl_path in ("agent.yaml", "agent.yml"):
            if decl_path in all_paths:
                text = _read_confined_text(files, decl_path, summary.gaps)
                if text is not None:
                    try:
                        decl_sources.append((decl_path, _parse_yaml(text), AssuranceLevel.DECLARED))
                    except (PolicyError, ValueError, RecursionError):
                        summary.gaps.append(f"{decl_path}: invalid YAML")
        checkout = _CheckoutScripts(files, project_paths)
        _inspect_hooks_and_preambles(files, all_paths, checkout, summary)
        bridged_steering = _inspect_mcp_launchers_and_bridges(
            files, all_paths, checkout, summary, live_versions or {}
        )
        _inspect_steering_surfaces(files, all_paths, summary, bridged_steering)
        _inspect_workflows_and_claims(files, all_paths, summary, decl_sources)
        _inspect_identities_and_authority(summary, decl_sources)

    if baseline_root is not None:
        base_summary = audit_project_control_plane(baseline_root, claims_path=claims_path)
        # An unreadable baseline hides what changed, so its gaps fail the gate too.
        summary.gaps.extend(f"baseline: {gap}" for gap in base_summary.gaps)
        summary.reach_alerts = diff_control_plane_audits(
            base_summary,
            summary,
            trace_reported_refs=trace_reported_refs,
            live_observed_refs=live_observed_refs,
        )

    for comp in summary.bom.components:
        if comp.component_type in {ComponentType.MCP_SERVER, ComponentType.TOOL}:
            reached = compute_identity_blast_radius(summary, comp.bom_ref)
            if reached:
                comp.properties["reachable_identities"] = reached

    return summary
