"""MCP server and tool scanner.

Discovers MCP server configurations from:
  - .mcp.json (project-level MCP config)
  - claude_desktop_config.json
  - mcp.json
  - .codex/config.toml at the project root and in subdirectories (declared settings)
  - .cursor/mcp.json
  - package.json (mcp-related dependencies)

For each server, extracts tool definitions, computes canonical hashes,
and detects unpinned versions, missing transport security, and rug-pull risk.
"""

from __future__ import annotations

import ast
import ipaddress
import re
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from packaging.requirements import InvalidRequirement, Requirement
from packaging.utils import canonicalize_name
from packaging.version import InvalidVersion, Version

from nexus_symbiote.core.enums import (
    CapabilityClass,
    RiskSeverity,
    SideEffectProfile,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    SOURCE_BINDING_KEY_ENV as SOURCE_BINDING_KEY_ENV,
)
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    SourceBindingKeyError,
    SourceBindingValueError,
    bind_source_values,
    extract_version_pin,
    hash_canonical,
    hash_tool_definition,
)
from nexus_symbiote.core.models import (
    CapabilityDeclaration,
    MCPClientComponent,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.core.textsafety import HiddenKind, hidden_character_kinds
from nexus_symbiote.scanners.base import Scanner, ScanResult, case_variants, sanitized_origin
from nexus_symbiote.utils.secrets import REDACTED, redact_descriptor, redact_text

CODEX_CONFIG = ".codex/config.toml"
# Codex loads a .codex/config.toml from every directory between the project root
# and its working directory, so each one in the tree is a configuration layer.
MAX_CODEX_LAYERS = 16
_CODEX_APPROVAL_MODES = frozenset({"auto", "prompt", "writes", "approve"})
# Launchers named in clear; any other command is a local path or name that may be private.
_SHOWN_COMMANDS = frozenset({"npx", "bunx", "uvx", "pipx", "docker", "node", "python", "python3"})
# Each recorded string of a server is redacted against every secret value of that
# server, and a nested Codex layer can merge an ancestor's server in a few bytes.
# Each check scans the whole string, so a string weighs its length plus a fixed cost
# per check. Bound the weighted strings-by-secrets product over the collection:
# about a second of work.
_REDACTION_CHECK_COST = 100
MAX_CODEX_REDACTION_WORK = 400_000_000
_CODEX_REDACTION_LIMIT = "Codex configuration: MCP server redaction work limit exceeded"
_JSON_REDACTION_LIMIT = "MCP configuration: MCP server redaction work limit exceeded"
_KEY_FAILURE = (
    f"{SOURCE_BINDING_KEY_ENV} is not valid random key material; "
    "MCP server declarations were not bound"
)


class _NameCollisionError(ValueError):
    """Distinct declared names of one Codex server field redact to the same text."""


def is_codex_config(path: str) -> bool:
    return path == CODEX_CONFIG or path.endswith("/" + CODEX_CONFIG)


def codex_config_layers(paths: Iterable[str], result: ScanResult) -> list[str]:
    """Root-relative Codex configuration layers, ancestors before descendants."""
    layers = sorted(filter(is_codex_config, paths), key=lambda path: (path.count("/"), path))
    if len(layers) > MAX_CODEX_LAYERS:
        result.scan_failures.append(
            f"Codex configuration: {MAX_CODEX_LAYERS}-layer collection limit exceeded"
        )
    return layers[:MAX_CODEX_LAYERS]


def codex_scope(layer: str) -> PurePosixPath:
    """The project directory a Codex layer applies to, with every directory below it."""
    return PurePosixPath(layer).parent.parent


def codex_applies(layer_scope: PurePosixPath, directory: PurePosixPath) -> bool:
    """Whether Codex loads a layer for a session in `directory`; siblings never merge."""
    return layer_scope == directory or layer_scope in directory.parents


def merge_codex(earlier: Any, later: Any) -> Any:
    """Merge a later Codex layer's value over an earlier one, table by table.

    Codex merges its project layers this way and validates only the merged
    configuration, so a layer may override a single field of a table above it.
    A value of any other type replaces what came before.
    """
    if not (isinstance(earlier, dict) and isinstance(later, dict)):
        return later
    merged = dict(earlier)
    for key, value in later.items():
        merged[key] = merge_codex(merged[key], value) if key in merged else value
    return merged


def _weight(strings: Iterable[Any]) -> int:
    """The cost of checking each string against one secret value."""
    return sum(_REDACTION_CHECK_COST + len(value) for value in strings if isinstance(value, str))


def _codex_redaction_work(name: str, config: dict[str, Any]) -> int:
    """The names a validated Codex server record redacts, weighted by length, times
    its secret values."""
    names = [name, *(config.get(k) for k in ("command", "url", "cwd", "bearer_token_env_var"))]
    names += [config.get("http_headers_helper")]
    for key in ("tools", "enabled_tools", "disabled_tools", "scopes", "args"):
        names += list(config.get(key, ()))
    for item in config.get("env_vars", ()):
        names += [item] if isinstance(item, str) else [item["name"], item.get("source")]
    for header, variable in config.get("env_http_headers", {}).items():
        names += [header, variable]
    secrets = len(config.get("env", {})) + len(config.get("http_headers", {}))
    return (4 * _REDACTION_CHECK_COST + _weight(names)) * max(secrets, 1)


def _json_redaction_work(name: str, config: dict[str, Any]) -> int:
    """The strings a JSON server record redacts, weighted by length, times its
    distinct secret values.

    Without secrets, redaction costs only time linear in the bounded input.
    """
    strings: list[Any] = [name, *(config.get(key) for key in ("command", "url", "endpoint"))]
    strings += config.get("args", [])
    work = 4 * _REDACTION_CHECK_COST
    pending: list[Any] = [config.get("tools", [])]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            work += _weight(value)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str):
            work += _weight((value,))
    work += _weight(strings)
    return work * len({value for value in config.get("env", {}).values() if value})


def _redacted_names(
    names: Iterable[tuple[str, ...]], secrets: list[str]
) -> dict[tuple[str, ...], tuple[str, ...]]:
    """Redact each distinct declared name, refusing names that redaction would merge.

    A merged entry would hide a change to either name from the unkeyed binding.
    """
    redacted = {name: tuple(redact_text(part, secrets) for part in name) for name in set(names)}
    if len(set(redacted.values())) < len(redacted):
        raise _NameCollisionError
    return redacted


def _codex_server_policy(config: dict[str, Any], secrets: list[str]) -> dict[str, Any]:
    """Tool approval, forwarded host-environment names, OAuth scopes, the working
    directory and the header helper's shape. Secret values never appear."""
    policy: dict[str, Any] = {}
    # As for launcher identities, short values are flags such as "1", not credentials;
    # redacting names against them would rewrite and merge ordinary names.
    identity_secrets = [s for s in secrets if len(s) >= _MIN_IDENTITY_SECRET_LENGTH]
    approvals = {
        name: entry["approval_mode"]
        for name, entry in config.get("tools", {}).items()
        if "approval_mode" in entry
    }
    names = _redacted_names(((name,) for name in approvals), identity_secrets)
    if approvals:
        policy["tool_approval_modes"] = dict(
            sorted((names[(name,)][0], mode) for name, mode in approvals.items())
        )
    if "default_tools_approval_mode" in config:
        policy["default_tools_approval_mode"] = config["default_tools_approval_mode"]
    for key in ("enabled_tools", "disabled_tools", "scopes"):
        if key in config:
            names = _redacted_names(((name,) for name in config[key]), identity_secrets)
            policy[key] = sorted(name for (name,) in names.values())
    if "env_vars" in config:
        names = _redacted_names(
            (
                (item, "local")
                if isinstance(item, str)
                else (item["name"], item.get("source", "local"))
                for item in config["env_vars"]
            ),
            identity_secrets,
        )
        policy["env_vars"] = [
            {"name": name, "source": source} for name, source in sorted(names.values())
        ]
    if "env_http_headers" in config:
        names = _redacted_names(config["env_http_headers"].items(), identity_secrets)
        policy["env_http_headers"] = [
            {"header": header, "env_var": variable} for header, variable in sorted(names.values())
        ]
    if "bearer_token_env_var" in config:
        policy["bearer_token_env_var"] = redact_text(
            config["bearer_token_env_var"], identity_secrets
        )
    if "cwd" in config:
        policy["cwd"] = redact_text(config["cwd"], identity_secrets)
    if "http_headers_helper" in config:
        # A local shell command line, which may carry an inline credential. Like a
        # stdio command, only a known launcher is named; the keyed binding covers the rest.
        words = config["http_headers_helper"].split()
        policy["http_headers_helper"] = {
            "command": words[0] if words[0] in _SHOWN_COMMANDS else "[redacted-command]",
            "argument_count": len(words) - 1,
        }
    return policy


def _member(value: Any, allowed: frozenset[str]) -> bool:
    return isinstance(value, str) and value in allowed


MCP_CONFIG_FILES = [
    ".mcp.json",
    "mcp.json",
    "claude_desktop_config.json",
    ".cursor/mcp.json",
    ".claude/mcp.json",
    CODEX_CONFIG,
]
# Claude Code opens .mcp.json by name, which a case-insensitive file system resolves
# to a name such as .MCP.json.
_OPENED_BY_NAME = {".mcp.json"}

_NPM_NAME = r"(?:@[A-Za-z0-9][\w.-]*/)?[A-Za-z0-9][\w.-]*"
_OCI_REPOSITORY = (
    r"(?:[A-Za-z0-9][A-Za-z0-9.-]*(?::[0-9]+)?/)?"
    r"[a-z0-9][a-z0-9._-]*(?:/[a-z0-9][a-z0-9._-]*)*"
)

# Exported bindings must not be computable from secret values: an unkeyed digest
# over credentials lets anyone holding the BOM confirm guesses offline. The
# structure digest covers only fields the inventory already exports in clear.
# Values are bound by an HMAC under an operator key that never enters the BOM.
STATIC_CONFIG_HASH_PROFILE = "nexus-symbiote/mcp-static-config/v2"
STATIC_VALUE_BINDING_PROFILE = "nexus-symbiote/mcp-static-values/v1"


def _value_binding(config: dict[str, Any]) -> tuple[str, str] | None:
    return bind_source_values(config, profile=STATIC_VALUE_BINDING_PROFILE)


# Index, registry and find-links options decide where a launcher fetches its package.
# Without credentials they are not secret, so the unkeyed digest binds them.
_SOURCE_OPTIONS = frozenset(
    {
        "-i",
        "-f",
        "--index",
        "--default-index",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--registry",
    }
)


def _package_sources(args: list[str], secrets: list[str]) -> list[str]:
    sources = []
    for index, arg in enumerate(args):
        name, separator, value = arg.partition("=")
        if name not in _SOURCE_OPTIONS:
            continue
        if not separator:
            value = args[index + 1] if index + 1 < len(args) else ""
        if "://" in value:
            parts = urlsplit(value)
            try:
                port = f":{parts.port}" if parts.port else ""
            except ValueError:
                # Never hash an unparsed authority: it may hold credentials.
                sources.append(f"{name}=[unparsed]")
                continue
            value = f"{parts.scheme}://{parts.hostname or ''}{port}{parts.path}"
        sources.append(f"{name}={redact_text(value, secrets)}")
    return sorted(sources)


# Short environment values are flags such as "1" or "true", not credentials. Matching
# them against package names would silently discard ordinary launcher identities.
_MIN_IDENTITY_SECRET_LENGTH = 8
# npm resolves these specs to a local directory or tarball, not a registry package.
_NPM_LOCAL_SPEC = re.compile(r"(?:^|@)\.|\.(?:tgz|tar|tar\.gz)$", re.IGNORECASE)
# Options that make uvx or pipx resolve the package from somewhere other than PyPI.
_PYTHON_SOURCE_OPTIONS = frozenset(
    {
        "-i",
        "-f",
        "--index",
        "--default-index",
        "--index-url",
        "--extra-index-url",
        "--find-links",
        "--pip-args",
    }
)
_PACKAGE_LAUNCHERS = frozenset({"npx", "bunx", "uvx", "pipx", "docker"})
_WINDOWS_EXECUTABLE_SUFFIXES = frozenset({"exe", "cmd", "bat", "ps1"})


def _launcher(command: str) -> tuple[str, bool]:
    """Return the command's file name for classification and whether a path selected it.

    A directory, drive or Windows executable suffix does not change which launcher
    runs, so it must not hide the package reference from the pinning checks.
    """
    parts = re.split(r"[\\/:]", command)
    stem, dot, suffix = parts[-1].rpartition(".")
    name = stem if dot and suffix.lower() in _WINDOWS_EXECUTABLE_SUFFIXES else parts[-1]
    return name.lower(), len(parts) > 1


# Same categories and severities as the instruction-file checks in scanners/prompt.py.
_HIDDEN_TEXT_FINDINGS: dict[HiddenKind, tuple[RiskSeverity, str, str]] = {
    "bidi": (
        RiskSeverity.CRITICAL,
        "bidi_override",
        "Bidirectional control characters in tool fields: {}. "
        "Displayed text can differ from what the model reads.",
    ),
    "tag": (
        RiskSeverity.CRITICAL,
        "tag_characters",
        "Unicode tag characters in tool fields: {}. "
        "They are invisible and can carry hidden instructions.",
    ),
    "invisible": (
        RiskSeverity.HIGH,
        "invisible_characters",
        "Invisible or format characters in tool fields: {}. "
        "They can hide text from reviewers and split words that name checks match.",
    ),
}


def _hidden_text_risks(fields: dict[str, object]) -> list[RiskAssessment]:
    """Name the affected fields only: the text itself may carry the hidden payload."""
    found = {field: hidden_character_kinds(value) for field, value in fields.items()}
    return [
        RiskAssessment(
            severity=severity,
            category=category,
            detail=detail.format(", ".join(field for field in fields if kind in found[field])),
            recommendation="Remove the hidden characters, then review the visible tool text.",
        )
        for kind, (severity, category, detail) in _HIDDEN_TEXT_FINDINGS.items()
        if any(kind in kinds for kinds in found.values())
    ]


class MCPScanner(Scanner):
    name = "mcp"

    def scan(self, project_root: Path, *, config_only: bool = False) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        found_any = False
        clients: dict[str, MCPClientComponent] = {}

        with self._collection(project_root, result) as files:
            # One walk: every walk of a collection draws on the same entry budget.
            sources = [] if config_only else list(files.iter_files())
            layers = codex_config_layers((path.as_posix() for path in sources), result)
            nested = [layer for layer in layers if layer != CODEX_CONFIG]
            # Server tables of the Codex layers read so far, ancestors first.
            codex_tables: list[tuple[str, PurePosixPath, dict[str, Any]]] = []
            codex_work = 0
            json_work = 0
            configs = [
                (config_name, relative)
                for config_name in [*MCP_CONFIG_FILES, *nested]
                for relative in (
                    case_variants(files, config_name, result.scan_failures)
                    if config_name in _OPENED_BY_NAME
                    else [config_name]
                )
            ]
            for config_name, relative in configs:
                config_path = files.root / relative
                codex = is_codex_config(config_name)
                data = (
                    self._read_mapping(config_path, result)
                    if codex
                    else files.read_json(relative, missing_ok=True)
                )
                if data is None:
                    continue
                found_any = True
                result.surfaces_scanned.append(str(config_path))
                if not isinstance(data, dict):
                    result.scan_failures.append(f"{relative}: expected a configuration object")
                    continue
                if codex and "mcp_servers" not in data:
                    continue
                servers = (
                    data["mcp_servers"]
                    if codex
                    else data.get("mcpServers", data.get("servers", {}))
                )
                if not isinstance(servers, dict) or len(servers) > 1000:
                    result.scan_failures.append(f"{relative}: invalid or oversized server map")
                    continue
                inherited: list[tuple[str, dict[str, Any]]] = []
                if codex:
                    scope = codex_scope(config_name)
                    inherited = [
                        (label, table)
                        for label, layer_scope, table in codex_tables
                        if codex_applies(layer_scope, scope)
                    ]
                    codex_tables.append((config_name, scope, servers))
                server_refs: list[str] = []
                for server_name, declared in sorted(servers.items()):
                    # A layer may override single fields of a server declared above it.
                    contributions = [
                        (label, table[server_name])
                        for label, table in inherited
                        if server_name in table
                    ]
                    server_config: Any = None
                    for _, value in [*contributions, (config_name, declared)]:
                        server_config = merge_codex(server_config, value)
                    if not isinstance(server_config, dict) or not self._valid_server(
                        server_config, codex=codex
                    ):
                        result.scan_failures.append(f"{relative}: invalid server configuration")
                        continue
                    if codex:
                        codex_work += _codex_redaction_work(server_name, server_config)
                        over, limit = codex_work, _CODEX_REDACTION_LIMIT
                    else:
                        json_work += _json_redaction_work(server_name, server_config)
                        over, limit = json_work, _JSON_REDACTION_LIMIT
                    if over > MAX_CODEX_REDACTION_WORK:
                        if limit not in result.scan_failures:
                            result.scan_failures.append(limit)
                        continue
                    try:
                        mcp_comp, tool_comps = self._parse_server(
                            server_name,
                            server_config,
                            config_path,
                            inherited_from=[label for label, _ in contributions],
                        )
                    except _NameCollisionError:
                        result.scan_failures.append(
                            f"{config_name}: Codex MCP server names collide after secret redaction"
                        )
                        continue
                    except (TypeError, ValueError, RecursionError):
                        result.scan_failures.append(f"{config_name}: invalid tool definition")
                        continue
                    # Bound after parsing, so a value that cannot be hashed for export
                    # still fails as an invalid definition with or without the key.
                    try:
                        value_binding = _value_binding(server_config)
                    except SourceBindingKeyError:
                        # A configuration error, not a property of this server: report it
                        # once and keep the inventory unbound.
                        if _KEY_FAILURE not in result.scan_failures:
                            result.scan_failures.append(_KEY_FAILURE)
                        value_binding = None
                    except SourceBindingValueError:
                        result.scan_failures.append(
                            f"{config_name}: MCP server declaration cannot be canonicalized "
                            "for binding"
                        )
                        continue
                    if value_binding:
                        mcp_comp.properties.update(
                            {
                                "static_value_binding": value_binding[0],
                                "static_value_binding_key_id": value_binding[1],
                                "static_value_binding_profile": STATIC_VALUE_BINDING_PROFILE,
                            }
                        )
                    result.components.append(mcp_comp)
                    result.components.extend(tool_comps)
                    server_refs.append(mcp_comp.bom_ref)
                host = self._detect_host_from_config(config_name)
                if host:
                    if host not in clients:
                        clients[host] = MCPClientComponent(
                            bom_ref=f"mcp-client:{host}",
                            name=f"{host} MCP client",
                            host_application=host,
                            server_refs=[],
                            config_path=str(config_path),
                            source_path=str(config_path),
                            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                            properties={"collection_mode": "static-config", "config_paths": []},
                        )
                    client = clients[host]
                    client.server_refs = sorted({*client.server_refs, *server_refs})
                    client.properties["config_paths"].append(str(config_path))
            result.components.extend(clients.values())
            if not config_only:
                self._scan_code_mcp_clients(files.root, result, sources)

        if not found_any and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("mcp-config (no config files found)")

        return result

    def _valid_server(self, config: dict[str, Any], *, codex: bool = False) -> bool:
        tools = config.get("tools", {} if codex else [])
        if codex:
            # Codex tools entries are approval overrides, never served descriptions.
            if (
                bool(config.get("url")) == bool(config.get("command"))
                or not isinstance(config.get("enabled", True), bool)
                or not isinstance(tools, dict)
            ):
                return False
            headers = config.get("http_headers", {})
            if not isinstance(headers, dict) or not all(
                isinstance(v, str) for v in headers.values()
            ):
                return False
            if not all(
                isinstance(entry, dict)
                and entry.keys() <= {"approval_mode", "output_token_limit"}
                and _member(entry.get("approval_mode", "auto"), _CODEX_APPROVAL_MODES)
                and type(entry.get("output_token_limit", 1)) is int
                and entry.get("output_token_limit", 1) > 0
                for entry in tools.values()
            ) or not _member(
                config.get("default_tools_approval_mode", "auto"), _CODEX_APPROVAL_MODES
            ):
                return False
            for key in ("enabled_tools", "disabled_tools"):
                names = config.get(key, [])
                if not isinstance(names, list) or not all(isinstance(n, str) for n in names):
                    return False
            forwarded = config.get("env_vars", [])
            if not isinstance(forwarded, list) or not all(
                isinstance(item, str)
                or (
                    isinstance(item, dict)
                    and item.keys() <= {"name", "source"}
                    and isinstance(item.get("name"), str)
                    and _member(item.get("source", "local"), frozenset({"local", "remote"}))
                )
                for item in forwarded
            ):
                return False
            env_headers = config.get("env_http_headers", {})
            scopes = config.get("scopes", [])
            helper = config.get("http_headers_helper", "helper")
            if (
                not isinstance(env_headers, dict)
                or not all(isinstance(name, str) for name in env_headers.values())
                or not isinstance(scopes, list)
                or not all(isinstance(scope, str) for scope in scopes)
                or not all(
                    isinstance(config.get(k, ""), str) for k in ("bearer_token_env_var", "cwd")
                )
                # Codex refuses a blank helper command.
                or not isinstance(helper, str)
                or not helper.strip()
            ):
                return False
        elif not isinstance(tools, list) or not all(isinstance(tool, dict) for tool in tools):
            return False
        return (
            isinstance(config.get("command", ""), str)
            and isinstance(config.get("args", []), list)
            and all(isinstance(arg, str) for arg in config.get("args", []))
            and isinstance(config.get("env", {}), dict)
            and all(isinstance(value, str) for value in config.get("env", {}).values())
            and all(isinstance(config.get(key, ""), str) for key in ("url", "endpoint"))
            and len(tools) <= 1000
        )

    def _parse_server(
        self,
        name: str,
        config: dict[str, Any],
        config_path: Path,
        *,
        inherited_from: list[str] | None = None,
    ) -> tuple[MCPServerComponent, list[ToolComponent]]:
        command = config.get("command", "")
        args = config.get("args", [])
        env = config.get("env", {})
        transport = self._detect_transport(config)
        endpoint_url = config.get("url") or config.get("endpoint")
        # Launch arguments are opaque executable inputs. Rather than attempting
        # to enumerate every application's secret flags, retain positions only.
        # Environment names remain credential references; values never leave.
        secrets = [value for value in env.values() if isinstance(value, str) and value]
        if self._files is None:
            raise RuntimeError("_parse_server called outside a _collection context")
        config_scope = config_path.relative_to(self._files.root).as_posix()
        codex = is_codex_config(config_scope)
        if codex:
            secrets.extend(value for value in config.get("http_headers", {}).values() if value)
        server_ref = (
            "mcp-server:" + hash_canonical({"config": config_scope, "name": name}).split(":", 1)[1]
        )
        name = redact_text(name, secrets)
        safe_endpoint = (
            redact_text(sanitized_origin(endpoint_url), secrets) if endpoint_url else None
        )
        shown_command = (
            command if command in _SHOWN_COMMANDS else ("[redacted-command]" if command else None)
        )
        tool_names = sorted(
            redact_text(str(tool.get("name", "")), secrets)
            for tool in config.get("tools", [])
            if isinstance(tool, dict)
        )
        codex_policy = _codex_server_policy(config, secrets) if codex else {}
        codex_properties: dict[str, Any] = (
            {"declared_enabled": config.get("enabled", True), **codex_policy} if codex else {}
        )
        if codex and inherited_from:
            # The recorded server is the merge of these layers, ancestors first.
            codex_properties["codex_merged_layers"] = [*inherited_from, config_scope]
        structure = {
            "fields": sorted(config),
            "command": shown_command,
            "transport": transport,
            "endpoint": safe_endpoint,
            "argument_count": len(args),
            "environment_names": sorted(env),
            "tool_names": tool_names,
            "package_sources": _package_sources(args, secrets),
        }
        if codex:
            structure["codex_tool_policy"] = codex_policy
        source_config_hash = hash_canonical(
            {"profile": STATIC_CONFIG_HASH_PROFILE, "structure": structure}
        )

        launcher, path_qualified = _launcher(command)
        package_ref = self._extract_package_ref(launcher, args)
        # An explicit path can name any executable, so it never identifies a registry package.
        launcher_package = (
            self._launcher_package(launcher, package_ref)
            if package_ref and not path_qualified
            else None
        )
        if launcher_package and launcher in {"uvx", "pipx"}:
            if any(arg.split("=", 1)[0] in _PYTHON_SOURCE_OPTIONS for arg in args):
                launcher_package = None
        if launcher_package:
            package_name = launcher_package.split(":", 1)[1]
            if any(
                len(secret) >= _MIN_IDENTITY_SECRET_LENGTH and secret in package_name
                for secret in secrets
            ):
                launcher_package = None
        version_pinned: bool | None = None
        version = None
        if package_ref:
            if launcher in {"uvx", "pipx"}:
                version = extract_version_pin(package_ref, ecosystem="python")
            elif launcher == "docker":
                version = extract_version_pin(package_ref, ecosystem="oci")
            else:
                version = extract_version_pin(package_ref, ecosystem="npm")
            version_pinned = version is not None

        risks: list[RiskAssessment] = []

        if not version_pinned and package_ref:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="version_pinning",
                    detail=f"MCP server '{name}' uses an unpinned package reference (arguments omitted).",
                    recommendation="Pin to an exact version and store a hash of the tool schema.",
                )
            )

        if transport == "stdio" and command:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="transport_security",
                    detail=f"MCP server '{name}' uses stdio transport (local process).",
                    recommendation="Ensure the command binary is integrity-checked.",
                )
            )

        if endpoint_url and not self._secure_endpoint(endpoint_url):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"MCP server '{name}' endpoint is not HTTPS: {safe_endpoint}",
                    recommendation="Use HTTPS for all remote MCP server connections.",
                )
            )

        server_comp = MCPServerComponent(
            bom_ref=server_ref,
            name=name,
            version=version,
            transport=transport,
            launcher_package=launcher_package,
            command=shown_command,
            args=[REDACTED for _ in args],
            env=dict.fromkeys(env, "***"),
            endpoint_url=safe_endpoint,
            version_pinned=version_pinned,
            source_path=str(config_path),
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
            properties={
                "collection_mode": "static-config",
                **codex_properties,
                "launch_arguments_redacted": bool(args),
                "endpoint_credentials_omitted": bool(endpoint_url),
                "static_config_hash": source_config_hash,
                "static_config_hash_profile": STATIC_CONFIG_HASH_PROFILE,
                **(
                    {"launcher": launcher, "launcher_path_qualified": path_qualified}
                    if launcher in _PACKAGE_LAUNCHERS and launcher != command
                    else {}
                ),
            },
        )

        tools = self._extract_tools(
            name, config, secrets, server_ref=server_ref, config_path=config_path
        )
        server_comp.tool_count = len(tools)
        server_comp.tool_refs = [tool.bom_ref for tool in tools]
        return server_comp, tools

    def _detect_transport(self, config: dict[str, Any]) -> str:
        if config.get("url") or config.get("endpoint"):
            url = config.get("url", config.get("endpoint", ""))
            if "/sse" in urlsplit(url).path:
                return "sse"
            return "streamable-http"
        return "stdio"

    def _extract_package_ref(self, command: str, args: list[str]) -> str | None:
        if command in {"uvx", "pipx", "npx", "bunx"}:
            values = args[1:] if command == "pipx" and args[:1] == ["run"] else args
            for index, arg in enumerate(values):
                if arg in {"-y", "--yes", "--no", "-n"}:
                    continue
                if (command == "uvx" and arg == "--from") or (
                    command == "pipx" and arg == "--spec"
                ):
                    return (
                        self._python_package_ref(command, values[index + 1])
                        if index + 1 < len(values)
                        else None
                    )
                # Unknown options may consume a secret in the next position.
                if arg.startswith("-"):
                    return None
                if command in {"uvx", "pipx"}:
                    return self._python_package_ref(command, arg)
                return (
                    arg
                    if len(arg) <= 2048 and re.fullmatch(rf"{_NPM_NAME}(?:@.+)?", arg, re.ASCII)
                    else None
                )
        if command == "docker" and args and args[0] == "run":
            for arg in args[1:]:
                if arg in {"--rm", "-i", "-t", "-it", "-d", "--detach"}:
                    continue
                if arg.startswith("-"):
                    return None
                return (
                    arg
                    if len(arg) <= 2048
                    and re.fullmatch(r"[A-Za-z0-9][\w./:-]*(?:@sha256:[a-fA-F0-9]{64})?", arg)
                    else None
                )
        return None

    @staticmethod
    def _launcher_package(command: str, reference: str) -> str | None:
        """Keep only a declared registry name. Never copy arbitrary launcher arguments."""
        if command in {"uvx", "pipx"}:
            requirement = Requirement(reference)  # Validated by _python_package_ref.
            if requirement.url:
                return None
            return "pypi:" + canonicalize_name(requirement.name)
        if command == "docker":
            image = re.fullmatch(
                rf"({_OCI_REPOSITORY})(?::[A-Za-z0-9_][A-Za-z0-9_.-]{{0,127}})?"
                r"(?:@sha256:[a-fA-F0-9]{64})?",
                reference,
            )
            return "oci:" + image[1].lower() if image else None
        # A tag or range may follow the name. An alias, URL or path can point to
        # a different package, so its nominal name does not identify the target.
        package = re.fullmatch(rf"({_NPM_NAME})(?:@[A-Za-z0-9.*^~<>=|+ -]+)?", reference, re.ASCII)
        if package is None or _NPM_LOCAL_SPEC.search(reference):
            return None
        return "npm:" + package[1]

    @staticmethod
    def _python_package_ref(command: str, value: str) -> str | None:
        if len(value) > 2048 or any(c in value for c in "\r\n\x00"):
            return None
        try:
            requirement = Requirement(value)
        except InvalidRequirement:
            return None
        # uvx supports package@version shorthand; pipx follows PEP 508 URLs.
        if command == "uvx" and requirement.url and not requirement.marker:
            try:
                Version(requirement.url)
            except InvalidVersion:
                pass
            else:
                return requirement.name + "==" + requirement.url
        return value

    def _extract_tools(
        self,
        server_name: str,
        config: dict[str, Any],
        secrets: list[str] | None = None,
        *,
        server_ref: str,
        config_path: Path,
    ) -> list[ToolComponent]:
        tools_config = config.get("tools", [])
        tool_comps = []

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

                    def_hash = hash_tool_definition(t_name, t_desc, t_schema, t_annotations)
                    tool_ref = (
                        "tool:"
                        + hash_canonical({"server": server_ref, "name": t_name}).split(":", 1)[1]
                    )

                    side_effect = self._classify_side_effects(t_annotations, t_name)
                    caps = self._infer_capabilities(t_name, t_desc, t_annotations)
                    hidden_text = _hidden_text_risks(
                        {
                            "name": t_name,
                            "description": t_desc,
                            "inputSchema": t_schema,
                            "annotations": t_annotations,
                        }
                    )
                    safe = redact_descriptor(
                        {
                            "name": t_name,
                            "description": t_desc,
                            "inputSchema": t_schema,
                            "annotations": t_annotations,
                        },
                        secrets or [],
                    )
                    t_name = safe["name"]
                    display_hash = hash_tool_definition(
                        t_name, safe["description"], safe["inputSchema"], safe["annotations"]
                    )

                    risks: list[RiskAssessment] = []
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
                    risks.extend(hidden_text)

                    tool_comps.append(
                        ToolComponent(
                            bom_ref=tool_ref,
                            name=t_name,
                            mcp_server_ref=server_ref,
                            source_path=str(config_path),
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
        """Classify exact HTTP loopback or HTTPS declarations without connecting."""
        try:
            parsed = urlsplit(url)
            if not parsed.hostname or parsed.username is not None or parsed.password is not None:
                return False
            if parsed.port is not None and not 1 <= parsed.port <= 65535:
                return False
            if parsed.scheme == "https":
                return True
            if parsed.scheme != "http":
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
        if is_codex_config(config_name):
            return "codex"
        return {
            ".mcp.json": "claude-code",
            ".claude/mcp.json": "claude-code",
            "claude_desktop_config.json": "claude-desktop",
            ".cursor/mcp.json": "cursor",
        }.get(config_name)

    def _scan_code_mcp_clients(self, root: Path, result: ScanResult, sources: list[Path]) -> None:
        if self._files is None:
            raise RuntimeError("_scan_code_mcp_clients called outside a _collection context")
        from nexus_symbiote.scanners.python_tools import collect_python_tools
        from nexus_symbiote.scanners.ts_tools import collect_typescript

        collect_typescript(self._files, result, sources)
        detected: list[str] = []
        for suffix in (".py", ".ts", ".js"):
            paths = [
                path
                for path in sources
                if path.suffix == suffix
                and (
                    len(path.parts) == 1
                    or suffix == ".py"
                    and not {"tests", "test", "dist", "build"}.intersection(path.parts)
                )
            ]
            if suffix == ".py":
                paths.sort(key=lambda path: len(path.parts) > 1)
            limit = 50 if suffix == ".py" else 10
            if len(paths) > limit:
                result.scan_failures.append(
                    f"MCP {suffix} references: {limit}-file collection limit exceeded"
                )
            for path in paths[:limit]:
                content = self._files.read_text(path)
                if content is None:
                    continue
                if suffix == ".py" and len(path.parts) > 1 and "mcp" not in content:
                    continue
                result.surfaces_scanned.append(str(root / path))
                if len(content.encode("utf-8")) > 262_144:
                    result.scan_failures.append(f"{path}: syntax collection size limit exceeded")
                    continue
                if suffix == ".py":
                    try:
                        tree = ast.parse(content)
                    except (SyntaxError, ValueError, RecursionError):
                        result.scan_failures.append(f"{path}: invalid Python syntax")
                        continue
                    collect_python_tools(tree, content, path, result)
                    found = any(
                        isinstance(node, ast.ImportFrom)
                        and node.module is not None
                        and node.module.split(".")[0] == "mcp"
                        and any("Client" in alias.name for alias in node.names)
                        for node in ast.walk(tree)
                    ) or any(
                        isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Name)
                        and node.func.id == "MCPClient"
                        for node in ast.walk(tree)
                    )
                else:
                    # A bounded syntax hint, never a claim that an SDK is installed
                    # or deployed. Strip comments and require the SDK import path.
                    content = re.sub(r"/\*.*?\*/|(?m:^\s*//[^\n]*$)", "", content, flags=re.S)
                    found = bool(
                        re.search(
                            r"(?:\bfrom\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"']|"
                            r"\brequire\s*\(\s*[\"']@modelcontextprotocol/sdk(?:/[^\"']*)?[\"'])",
                            content,
                        )
                    )
                if found:
                    detected.append(str(root / path))
        if detected:
            result.components.append(
                MCPClientComponent(
                    bom_ref="mcp-client:sdk",
                    name="MCP SDK client (code-detected)",
                    host_application="sdk",
                    source_path=detected[0],
                    trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                    properties={
                        "collection_mode": "static-source-reference",
                        "source_paths": detected,
                    },
                )
            )

    def _classify_side_effects(
        self, annotations: dict[str, Any], tool_name: str
    ) -> SideEffectProfile:
        """Infer the profile from the name; a self-declared hint may only raise it.

        The tool's own readOnlyHint is an unverified claim. It must not hide a
        destructive name from the capability-scope finding or narrow an unknown profile.
        """
        if annotations.get("destructiveHint"):
            return SideEffectProfile.DESTRUCTIVE
        name_lower = tool_name.lower()
        if any(w in name_lower for w in ("delete", "remove", "drop", "destroy", "purge")):
            return SideEffectProfile.DESTRUCTIVE
        if any(w in name_lower for w in ("create", "update", "write", "send", "post", "put")):
            return SideEffectProfile.STATE_MODIFYING
        if any(w in name_lower for w in ("get", "list", "read", "search", "query", "fetch")):
            return SideEffectProfile.READ_ONLY
        return SideEffectProfile.UNKNOWN

    def _infer_capabilities(
        self, tool_name: str, description: str, annotations: dict[str, Any]
    ) -> list[CapabilityClass]:
        caps = []
        combined = f"{tool_name} {description}".lower()
        if any(w in combined for w in ("file", "directory", "path", "fs", "disk")):
            caps.append(CapabilityClass.FILESYSTEM)
        if any(w in combined for w in ("http", "url", "fetch", "request", "api", "endpoint")):
            caps.append(CapabilityClass.NETWORK)
        if any(w in combined for w in ("exec", "run", "shell", "command", "bash", "terminal")):
            caps.append(CapabilityClass.EXECUTE)
        if any(w in combined for w in ("pay", "transfer", "invoice", "charge", "billing")):
            caps.append(CapabilityClass.PAYMENT)
        if any(w in combined for w in ("credential", "secret", "token", "password", "key", "auth")):
            caps.append(CapabilityClass.CREDENTIALS)
        if any(w in combined for w in ("write", "create", "update", "delete", "send", "post")):
            caps.append(CapabilityClass.WRITE)
        elif any(w in combined for w in ("read", "get", "list", "search", "query")):
            caps.append(CapabilityClass.READ)
        return caps
