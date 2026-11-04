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
from pathlib import Path
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
from nexus_symbiote.scanners.base import Scanner, ScanResult, sanitized_origin
from nexus_symbiote.utils.secrets import REDACTED, redact_descriptor, redact_text

CODEX_CONFIG = ".codex/config.toml"
# Codex loads a .codex/config.toml from every directory between the project root
# and its working directory, so each one in the tree is a configuration layer.
MAX_CODEX_LAYERS = 16
_CODEX_APPROVAL_MODES = frozenset({"auto", "prompt", "writes", "approve"})


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


def _codex_server_policy(config: dict[str, Any], secrets: list[str]) -> dict[str, Any]:
    """Tool approval and host-environment forwarding; names only, never values."""
    policy: dict[str, Any] = {}
    modes = {
        redact_text(name, secrets): entry["approval_mode"]
        for name, entry in config.get("tools", {}).items()
        if "approval_mode" in entry
    }
    if modes:
        policy["tool_approval_modes"] = dict(sorted(modes.items()))
    if "default_tools_approval_mode" in config:
        policy["default_tools_approval_mode"] = config["default_tools_approval_mode"]
    for key in ("enabled_tools", "disabled_tools"):
        if key in config:
            policy[key] = sorted({redact_text(name, secrets) for name in config[key]})
    if "env_vars" in config:
        forwarded = {
            (redact_text(item, secrets), "local")
            if isinstance(item, str)
            else (redact_text(item["name"], secrets), item.get("source", "local"))
            for item in config["env_vars"]
        }
        policy["env_vars"] = [
            {"name": name, "source": source} for name, source in sorted(forwarded)
        ]
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
            for config_name in [*MCP_CONFIG_FILES, *nested]:
                config_path = files.root / config_name
                codex = is_codex_config(config_name)
                data = (
                    self._read_mapping(config_path, result)
                    if codex
                    else files.read_json(config_name, missing_ok=True)
                )
                if data is None:
                    continue
                found_any = True
                result.surfaces_scanned.append(str(config_path))
                if not isinstance(data, dict):
                    result.scan_failures.append(f"{config_name}: expected a configuration object")
                    continue
                if codex and "mcp_servers" not in data:
                    continue
                servers = (
                    data["mcp_servers"]
                    if codex
                    else data.get("mcpServers", data.get("servers", {}))
                )
                if not isinstance(servers, dict) or len(servers) > 1000:
                    result.scan_failures.append(f"{config_name}: invalid or oversized server map")
                    continue
                server_refs: list[str] = []
                for server_name, server_config in sorted(servers.items()):
                    if not isinstance(server_config, dict) or not self._valid_server(
                        server_config, codex=codex
                    ):
                        result.scan_failures.append(f"{config_name}: invalid server configuration")
                        continue
                    try:
                        mcp_comp, tool_comps = self._parse_server(
                            server_name, server_config, config_path
                        )
                    except (TypeError, ValueError, RecursionError):
                        result.scan_failures.append(f"{config_name}: invalid tool definition")
                        continue
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
            command
            if command in {"npx", "bunx", "uvx", "pipx", "docker", "node", "python", "python3"}
            else ("[redacted-command]" if command else None)
        )
        tool_names = sorted(
            redact_text(str(tool.get("name", "")), secrets)
            for tool in config.get("tools", [])
            if isinstance(tool, dict)
        )
        codex_policy = _codex_server_policy(config, secrets) if codex else {}
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
        value_binding = _value_binding(config)

        package_ref = self._extract_package_ref(command, args)
        launcher_package = self._launcher_package(command, package_ref) if package_ref else None
        if launcher_package and command in {"uvx", "pipx"}:
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
            if command in {"uvx", "pipx"}:
                version = extract_version_pin(package_ref, ecosystem="python")
            elif command == "docker":
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
            command=(
                command
                if command in {"npx", "bunx", "uvx", "pipx", "docker", "node", "python", "python3"}
                else ("[redacted-command]" if command else None)
            ),
            args=[REDACTED for _ in args],
            env=dict.fromkeys(env, "***"),
            endpoint_url=safe_endpoint,
            version_pinned=version_pinned,
            source_path=str(config_path),
            trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
            risks=risks,
            properties={
                "collection_mode": "static-config",
                **(
                    {"declared_enabled": config.get("enabled", True), **codex_policy}
                    if codex
                    else {}
                ),
                "launch_arguments_redacted": bool(args),
                "endpoint_credentials_omitted": bool(endpoint_url),
                "static_config_hash": source_config_hash,
                "static_config_hash_profile": STATIC_CONFIG_HASH_PROFILE,
                **(
                    {
                        "static_value_binding": value_binding[0],
                        "static_value_binding_key_id": value_binding[1],
                        "static_value_binding_profile": STATIC_VALUE_BINDING_PROFILE,
                    }
                    if value_binding
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
        if annotations.get("destructiveHint"):
            return SideEffectProfile.DESTRUCTIVE
        if annotations.get("readOnlyHint"):
            return SideEffectProfile.READ_ONLY
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
