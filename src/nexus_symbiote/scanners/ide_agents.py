"""IDE coding agent configuration scanner.

Discovers configurations for IDE-integrated AI coding agents:
  - Claude Code (.claude/, CLAUDE.md, .claude/settings.json)
  - Codex (.codex/, codex.md)
  - Cursor (.cursor/, .cursorrules, .cursor/mcp.json)
  - Antigravity (.antigravity/)
  - XAI IDE agent configs
  - Windsurf (.windsurfrules, .windsurf/)
  - Cline (.clinerules, .cline/)
  - GitHub Copilot (.github/copilot-instructions.md)
"""

from __future__ import annotations

import io
import ipaddress
import json
import os
import re
import shlex
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from rfc8785 import CanonicalizationError

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import (
    SOURCE_BINDING_KEY_ENV,
    SourceBindingKeyError,
    SourceBindingValueError,
    bind_source_values,
    canonical_json,
)
from nexus_symbiote.core.models import IDEAgentComponent, RiskAssessment, VerifiedExtensionComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult, folded_name
from nexus_symbiote.scanners.mcp import (
    CODEX_CONFIG,
    codex_applies,
    codex_config_layers,
    codex_scope,
    is_codex_config,
    merge_codex,
)
from nexus_symbiote.utils.confined import DEFAULT_EXCLUDES, ConfinedCollection
from nexus_symbiote.utils.secrets import redact_text

CODEX_BUILT_IN_PROFILES = {
    ":read-only": "read-only",
    ":workspace": "workspace-write",
    ":danger-full-access": "danger-full-access",
}
_CODEX_SANDBOX_MODES = frozenset(CODEX_BUILT_IN_PROFILES.values())
# Codex refuses a profile that extends any other built-in, such as :danger-full-access.
_CODEX_EXTENSIBLE_PARENTS = frozenset({":read-only", ":workspace"})
_CODEX_PROFILE_NAME = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}")
_CODEX_PROFILE_KEYS = frozenset(
    {"description", "extends", "filesystem", "network", "workspace_roots"}
)
_CODEX_ACCESS = {"read": "read", "write": "write", "deny": "deny", "none": "deny"}
_CODEX_WORKSPACE_PATHS = frozenset({":workspace_roots", ":project_roots"})
_CODEX_TEMPORARY_PATHS = frozenset({":tmpdir", ":slash_tmp"})
_CODEX_SPECIAL_PATHS = _CODEX_WORKSPACE_PATHS | _CODEX_TEMPORARY_PATHS | {":root", ":minimal"}
_CODEX_WORKSPACE_WRITE_KEYS = ("network_access", "exclude_tmpdir_env_var", "exclude_slash_tmp")
_CODEX_APPROVAL_POLICIES = frozenset({"on-request", "on-failure", "untrusted", "never"})
_CODEX_GRANULAR_REQUIRED = frozenset({"sandbox_approval", "rules", "mcp_elicitations"})
_CODEX_GRANULAR_KEYS = _CODEX_GRANULAR_REQUIRED | {"request_permissions", "skill_approval"}
# auto_review instructs the automatic approver, hooks can answer permission requests
# and apps set connector tool approval. None is interpreted, so declaring one leaves
# coverage unknown; with the operator key their values are bound.
_CODEX_UNINTERPRETED = ("apps", "auto_review", "hooks")
CODEX_HOOKS = ".codex/hooks.json"
CODEX_UNINTERPRETED_BINDING_PROFILE = "nexus-symbiote/codex-uninterpreted/v1"
_KEY_FAILURE = (
    f"{SOURCE_BINDING_KEY_ENV} is not valid random key material; Codex settings were not bound"
)
_HOST_PATH = re.compile(r"[/\\~]|[A-Za-z]:")
_FULL_ACCESS = (RiskSeverity.HIGH, "Codex declares unrestricted filesystem access.")
_OUTSIDE = (RiskSeverity.HIGH, "Codex declares writable paths outside the workspace.")
_NETWORK = (RiskSeverity.MEDIUM, "Codex declares sandbox network access.")
_UNPROMPTED = (
    RiskSeverity.MEDIUM,
    "Codex declares workspace writes with no interactive escalation prompts.",
)
_UNOBSERVED_ROOT = (
    "Codex writable or workspace root passes through an excluded directory; coverage is unknown"
)
# Resolving a profile copies the grants it inherits, and checking one iterates them.
# Each directory resolves an ancestor profile once, but grants that grow along a long
# `extends` chain, or a large profile selected in every layer, still multiply that
# work. Bound the grant entries handled over the collection: well under a second.
MAX_CODEX_PROFILE_WORK = 2_000_000
_PROFILE_WORK_LIMIT = "Codex configuration: permission profile work limit exceeded"


class _ProfileWorkError(Exception):
    """Permission-profile resolution exceeded the collection's work limit."""


def _spend(budget: list[int], work: int) -> None:
    budget[0] -= work
    if budget[0] < 0:
        raise _ProfileWorkError


def _copy_cost(earlier: Any, later: Any) -> int:
    """The entries merge_codex copies when it merges `later` over `earlier`."""
    if not (isinstance(earlier, dict) and isinstance(later, dict)):
        return 0
    return len(earlier) + sum(_copy_cost(earlier[k], v) for k, v in later.items() if k in earlier)


def _resolve_root(path: str, base: PurePosixPath) -> str | None:
    """Lexically resolve a declared root against a project directory.

    Returns "outside" for host-absolute and home paths and for paths that leave
    the project, and "unobserved" for a path through a directory the collection
    never enters. Codex binds the target of a symlinked root, and the confined walk
    fails on a symlink anywhere else in the project, so only those can hide one.
    """
    if not path or _HOST_PATH.match(path):
        return "outside"
    parts = list(base.parts)
    unobserved = False
    for part in re.split(r"[/\\]", path):
        if part == "..":
            if not parts:
                return "outside"
            parts.pop()
        elif part not in {"", "."}:
            parts.append(part)
            # Case-insensitive filesystems resolve NODE_MODULES to node_modules.
            unobserved |= part.lower() in DEFAULT_EXCLUDES
    return "unobserved" if unobserved else None


_Resolved = tuple[str | None, dict[str, Any]]


def _resolve_profile(
    name: str, catalog: dict[str, Any], memo: dict[str, _Resolved], budget: list[int]
) -> _Resolved:
    """Return a custom profile's built-in base and its grants merged along `extends`.

    `memo` holds the profiles already resolved against the same catalog, so each
    ancestor of a long `extends` chain is merged once.
    """
    chain: list[str] = []
    seen: set[str] = set()
    base: str | None = None
    grants: dict[str, Any] = {}
    while name not in memo:
        if name in _CODEX_EXTENSIBLE_PARENTS:
            base = name
            break
        if name in seen or name not in catalog:
            raise ValueError("undefined or cyclic permission profile")
        seen.add(name)
        chain.append(name)
        parent = catalog[name].get("extends")
        if parent is None:
            break
        name = parent
    else:
        base, grants = memo[name]
    for item in reversed(chain):
        own = {k: v for k, v in catalog[item].items() if k != "extends"}
        _spend(budget, 1 + _copy_cost(grants, own))
        grants = merge_codex(grants, own)
        memo[item] = (base, grants)
    return base, grants


def _profile_writes(
    grants: dict[str, Any], directory: PurePosixPath, budget: list[int]
) -> tuple[bool, set[str]]:
    """Report whether profile grants allow any writes, and how their roots resolve."""
    writes = False
    places: set[str | None] = set()
    filesystem = grants.get("filesystem", {})
    roots = grants.get("workspace_roots", {})
    _spend(
        budget,
        1
        + len(roots)
        + sum(len(access) if isinstance(access, dict) else 1 for access in filesystem.values()),
    )
    for path, access in filesystem.items():
        if path == "glob_scan_max_depth":
            continue
        for subpath, mode in access.items() if isinstance(access, dict) else [(".", access)]:
            if mode != "write":
                continue
            writes = True
            if path in _CODEX_WORKSPACE_PATHS:
                if subpath != ".":
                    places.add(_resolve_root(subpath, PurePosixPath()))
            elif path not in _CODEX_TEMPORARY_PATHS:
                places.add("outside")
    for root, on in grants.get("workspace_roots", {}).items():
        if on:
            places.add(_resolve_root(root, directory))
    return writes, {place for place in places if place is not None}


def _codex_catalog(chain: list[tuple[str, PurePosixPath, dict[str, Any]]]) -> dict[str, Any]:
    catalog: dict[str, Any] = {}
    for _, _, values in chain:
        catalog = merge_codex(catalog, values.get("permission_profiles", {}))
    return catalog


def _codex_approval(chain: list[tuple[str, PurePosixPath, dict[str, Any]]]) -> Any:
    """The approval policy Codex merges for a directory, or None when none is declared."""
    approval: Any = None
    for _, _, values in chain:
        if "approval_policy" in values:
            approval = merge_codex(approval, values["approval_policy"])
    return approval


def _valid_approval(approval: Any) -> bool:
    """Whether Codex accepts a merged policy; each layer's values were checked already."""
    if not isinstance(approval, dict):
        return True
    return (
        approval.keys() == {"granular"} and approval["granular"].keys() >= _CODEX_GRANULAR_REQUIRED
    )


def _codex_scope_mode(
    chain: list[tuple[str, PurePosixPath, dict[str, Any]]],
    catalog: dict[str, Any],
    memo: dict[str, _Resolved],
    budget: list[int],
    approval: Any,
    findings: set[tuple[RiskSeverity, str]],
) -> str | None:
    """Select the permission syntax as Codex does: the last layer declaring one wins,
    and within a layer `default_permissions` takes precedence over `sandbox_mode`."""
    mode = None
    # Project layers load only for trusted projects, where Codex defaults to :workspace;
    # user config and Windows without its sandbox are not observed.
    writes = True
    for _, _, values in chain:
        if "sandbox_mode" in values:
            mode = values["sandbox_mode"]
            writes = mode == "workspace-write"
        selected = values.get("default_permissions")
        if selected in CODEX_BUILT_IN_PROFILES:
            mode = CODEX_BUILT_IN_PROFILES[selected]
            writes = selected == ":workspace"
        elif selected is not None:
            base, grants = _resolve_profile(selected, catalog, memo, budget)
            mode = f"profile:{selected}"
            writes = base == ":workspace" or _profile_writes(grants, PurePosixPath(), budget)[0]
    unprompted = approval == "never" or (
        isinstance(approval, dict) and not any(approval["granular"].values())
    )
    if writes and unprompted:
        findings.add(_UNPROMPTED)
    return mode


def _codex_declarations(label: str, data: dict[str, Any], result: ScanResult) -> dict[str, Any]:
    """Validate the permission-bearing keys of one Codex layer; unknown is not safe."""
    values: dict[str, Any] = {}
    sandbox = data.get("sandbox_mode")
    if sandbox is not None:
        if isinstance(sandbox, str) and sandbox in _CODEX_SANDBOX_MODES:
            values["sandbox_mode"] = sandbox
        else:
            result.scan_failures.append(f"{label}: invalid declared sandbox mode")
    approval = data.get("approval_policy")
    if approval is not None:
        if isinstance(approval, str) and approval in _CODEX_APPROVAL_POLICIES:
            values["approval_policy"] = approval
        elif isinstance(approval, dict) and approval.keys() <= {"granular"}:
            granular = approval.get("granular", {})
            # A layer may set only some prompts over an inherited table, so the
            # required prompts are checked on each directory's merged policy.
            if (
                isinstance(granular, dict)
                and granular.keys() <= _CODEX_GRANULAR_KEYS
                and all(isinstance(value, bool) for value in granular.values())
            ):
                values["approval_policy"] = {key: dict(granular) for key in approval}
            else:
                result.scan_failures.append(f"{label}: invalid granular approval policy")
        else:
            result.scan_failures.append(f"{label}: unsupported declared approval policy")
    reviewer = data.get("approvals_reviewer")
    if reviewer is not None:
        if isinstance(reviewer, str) and reviewer in {
            "user",
            "auto_review",
            "guardian_subagent",
        }:
            # guardian_subagent is Codex's legacy alias for auto_review.
            values["approvals_reviewer"] = "user" if reviewer == "user" else "auto_review"
        else:
            result.scan_failures.append(f"{label}: unsupported declared approvals reviewer")
    selected = data.get("default_permissions")
    if selected is not None:
        if isinstance(selected, str) and (
            selected in CODEX_BUILT_IN_PROFILES or _CODEX_PROFILE_NAME.fullmatch(selected)
        ):
            values["default_permissions"] = selected
        else:
            result.scan_failures.append(f"{label}: unsupported declared permission profile")
    if "permissions" in data:
        profiles = data["permissions"]
        if not isinstance(profiles, dict):
            result.scan_failures.append(f"{label}: invalid permission profile declaration")
        else:
            values["permission_profiles"] = {}
            for name, profile in profiles.items():
                grants = _codex_profile(label, name, profile, result)
                if grants is None:
                    result.scan_failures.append(f"{label}: invalid permission profile declaration")
                else:
                    values["permission_profiles"][name] = grants
    if "sandbox_workspace_write" in data:
        workspace = data["sandbox_workspace_write"]
        roots = workspace.get("writable_roots", []) if isinstance(workspace, dict) else None
        if (
            isinstance(workspace, dict)
            and workspace.keys() <= {"writable_roots", *_CODEX_WORKSPACE_WRITE_KEYS}
            and isinstance(roots, list)
            and all(isinstance(path, str) for path in roots)
            and all(isinstance(workspace.get(k, False), bool) for k in _CODEX_WORKSPACE_WRITE_KEYS)
        ):
            values["sandbox_workspace_write"] = {
                key: list(value) if key == "writable_roots" else value
                for key, value in workspace.items()
            }
        else:
            result.scan_failures.append(f"{label}: invalid sandbox_workspace_write declaration")
    for key in _CODEX_UNINTERPRETED:
        if key in data:
            _codex_unknown(label, key, result)
    return values


def _codex_profile(
    label: str, name: Any, profile: Any, result: ScanResult
) -> dict[str, Any] | None:
    """Normalize one [permissions] profile, or None when Codex would reject it."""
    if (
        not isinstance(name, str)
        or not _CODEX_PROFILE_NAME.fullmatch(name)
        or not isinstance(profile, dict)
        or not profile.keys() <= _CODEX_PROFILE_KEYS
        or not isinstance(profile.get("description", ""), str)
    ):
        return None
    grants: dict[str, Any] = {}
    parent = profile.get("extends")
    if parent is not None:
        if not isinstance(parent, str) or not (
            parent in CODEX_BUILT_IN_PROFILES or _CODEX_PROFILE_NAME.fullmatch(parent)
        ):
            return None
        grants["extends"] = parent
    filesystem = profile.get("filesystem")
    if filesystem is not None:
        if not isinstance(filesystem, dict):
            return None
        entries: dict[str, Any] = {}
        for path, access in filesystem.items():
            if path == "glob_scan_max_depth":
                if type(access) is not int or access < 1:
                    return None
                entries[path] = access
                continue
            if isinstance(access, str) and access in _CODEX_ACCESS:
                mapped: Any = _CODEX_ACCESS[access]
            elif isinstance(access, dict) and all(
                isinstance(mode, str) and mode in _CODEX_ACCESS for mode in access.values()
            ):
                mapped = {subpath: _CODEX_ACCESS[mode] for subpath, mode in access.items()}
            else:
                return None
            if path.startswith(":") and path not in _CODEX_SPECIAL_PATHS:
                _codex_unknown(label, "permission profile path", result)
                continue
            entries[path] = mapped
        grants["filesystem"] = entries
    network = profile.get("network")
    if network is not None:
        if not isinstance(network, dict) or not isinstance(network.get("enabled", False), bool):
            return None
        if "enabled" in network:
            grants["network_enabled"] = network["enabled"]
        if network.keys() - {"enabled"}:
            _codex_unknown(label, "permission profile network", result)
    roots = profile.get("workspace_roots")
    if roots is not None:
        if not isinstance(roots, dict) or not all(isinstance(on, bool) for on in roots.values()):
            return None
        grants["workspace_roots"] = dict(roots)
    return grants


def _codex_uninterpreted(data: dict[str, Any]) -> dict[str, Any]:
    """The raw values of the settings in one layer that the collector does not interpret.

    They may hold credentials, such as a proxy URL, so they are only ever bound by HMAC.
    """
    subtrees = {key: data[key] for key in _CODEX_UNINTERPRETED if key in data}
    profiles = data.get("permissions")
    for name, profile in profiles.items() if isinstance(profiles, dict) else []:
        if not isinstance(profile, dict):
            continue
        own: dict[str, Any] = {}
        network = profile.get("network")
        if isinstance(network, dict) and network.keys() - {"enabled"}:
            own["network"] = {k: v for k, v in network.items() if k != "enabled"}
        filesystem = profile.get("filesystem")
        if isinstance(filesystem, dict):
            special = {
                path: access
                for path, access in filesystem.items()
                if path.startswith(":") and path not in _CODEX_SPECIAL_PATHS
            }
            if special:
                own["filesystem"] = special
        if own:
            subtrees.setdefault("permissions", {})[name] = own
    return subtrees


def _codex_uninterpreted_binding(
    uninterpreted: dict[str, dict[str, Any]], result: ScanResult
) -> dict[str, Any]:
    """Bind uninterpreted settings so that edits to them fail the drift gate."""
    bound: dict[str, Any] = {}
    try:
        for label, subtrees in uninterpreted.items():
            try:
                bind_source_values(
                    {"layers": {label: subtrees}}, profile=CODEX_UNINTERPRETED_BINDING_PROFILE
                )
            except SourceBindingValueError:
                result.scan_failures.append(
                    f"{label}: Codex settings cannot be canonicalized for binding"
                )
                continue
            bound[label] = subtrees
        binding = (
            bind_source_values({"layers": bound}, profile=CODEX_UNINTERPRETED_BINDING_PROFILE)
            if bound
            else None
        )
    except SourceBindingKeyError:
        if _KEY_FAILURE not in result.scan_failures:
            result.scan_failures.append(_KEY_FAILURE)
        return {}
    if binding is None:
        return {}
    return {
        "codex_uninterpreted_binding": binding[0],
        "codex_uninterpreted_binding_key_id": binding[1],
        "codex_uninterpreted_binding_profile": CODEX_UNINTERPRETED_BINDING_PROFILE,
    }


def _codex_unknown(label: str, setting: str, result: ScanResult) -> None:
    message = f"{label}: Codex {setting} settings are not interpreted; coverage is unknown"
    if message not in result.surfaces_excluded:
        result.surfaces_excluded.append(message)


IDE_AGENT_CONFIGS: dict[str, dict[str, Any]] = {
    "claude-code": {
        "markers": [
            ".claude/settings.json",
            ".claude/settings.local.json",
            "CLAUDE.md",
            ".claude/CLAUDE.md",
            ".claude/commands",
            ".claude/skills",
        ],
        "mcp_config": [".claude/mcp.json", ".mcp.json"],
    },
    "codex": {
        "markers": [
            CODEX_CONFIG,
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
        ],
        "mcp_config": [".cursor/mcp.json"],
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
        ],
        "mcp_config": [],
    },
}

# Hook types that act without the model. Claude Code reads an HTTP response or MCP tool
# result like command output, so either can also allow, block or rewrite a tool call.
CLAUDE_HOOK_RISKS: dict[str, tuple[RiskSeverity, str, str]] = {
    "command": (RiskSeverity.HIGH, "agent-hook-command", "runs hook command '{command_basename}'"),
    "http": (RiskSeverity.HIGH, "agent-hook-http", "sends hook event data to '{url_origin}'"),
    "mcp_tool": (
        RiskSeverity.MEDIUM,
        "agent-hook-mcp-tool",
        "sends hook event data to tool '{mcp_tool}' of MCP server '{mcp_server}'",
    ),
}
CLAUDE_HOOK_BINDING_PROFILE = "nexus-symbiote/claude-code-hooks/v2"
# Settings that turn hooks off, or bound the URLs HTTP hooks reach and the environment
# variables their headers may carry. A project false overrides a user true.
CLAUDE_HOOK_SETTINGS = ("disableAllHooks", "allowedHttpHookUrls", "httpHookAllowedEnvVars")
# Settings whose shell command line Claude Code runs, like a hook, without asking: helpers
# are strings, and the others are objects with a command.
CLAUDE_SETTINGS_HELPERS = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "gcpAuthRefresh",
    "otelHeadersHelper",
)
CLAUDE_SETTINGS_COMMAND_OBJECTS = ("statusLine", "fileSuggestion", "subagentStatusLine")
CLAUDE_SETTINGS_FILES = (".claude/settings.json", ".claude/settings.local.json")
# Hook and settings records of a Claude Code agent. A fresh scan omits them when no settings
# file declares anything they cover, so reconciliation must treat a missing one as a change.
CLAUDE_SETTINGS_RECORDS = (
    "declared_hooks",
    "declared_hook_settings",
    "declared_setting_commands",
    "declared_settings_env",
)
# Claude Code writes settings env into its own environment, which every Bash command, hook,
# settings command and stdio MCP server it starts inherits.
CLAUDE_SETTINGS_ENV = "env"
# Variables that load code into, or choose, what those processes run: dynamic loaders,
# interpreter options and search paths, shell startup files, the shell itself, PATH, git's
# ssh, askpass, pager and config commands, and the config roots and helper commands from which
# git, editors, pagers, cloud CLIs and package managers run commands. A denylist cannot be
# complete; other names are recorded and their changes are drift.
_EXEC_ENV = frozenset(
    {
        "HOME",
        "XDG_CONFIG_HOME",
        "SHELLOPTS",
        "BASHOPTS",
        "PS4",
        "GIT_DIR",
        "GIT_COMMON_DIR",
        "GIT_WORK_TREE",
        "GIT_SEQUENCE_EDITOR",
        "EDITOR",
        "VISUAL",
        "PAGER",
        "MANPAGER",
        "LESSOPEN",
        "LESSCLOSE",
        "BROWSER",
        "GCONV_PATH",
        "PYTHONWARNINGS",
        "PYTHONBREAKPOINT",
        "PERL5DB",
        "AWS_CONFIG_FILE",
        "KUBECONFIG",
        "DOCKER_CONFIG",
        "RUSTC_WRAPPER",
        "CARGO_HOME",
        "BASH_ENV",
        "ENV",
        "PATH",
        "SHELL",
        "PROMPT_COMMAND",
        "ZDOTDIR",
        "NODE_OPTIONS",
        "NODE_PATH",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "PYTHONHOME",
        "PYTHONUSERBASE",
        "PERL5OPT",
        "PERL5LIB",
        "PERLLIB",
        "RUBYOPT",
        "RUBYLIB",
        "JAVA_TOOL_OPTIONS",
        "_JAVA_OPTIONS",
        "JDK_JAVA_OPTIONS",
        "DOTNET_STARTUP_HOOKS",
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_EXEC_PATH",
        "GIT_EXTERNAL_DIFF",
        "GIT_PAGER",
        "GIT_EDITOR",
        "GIT_PROXY_COMMAND",
        "GIT_TEMPLATE_DIR",
        "CLAUDE_CODE_SHELL",
        "CLAUDE_CODE_SHELL_PREFIX",
        "CLAUDE_CODE_GIT_BASH_PATH",
        "CLAUDE_ENV_FILE",
    }
)
# Bash imports BASH_FUNC_<name>%% as a function that replaces the command <name>.
_EXEC_ENV_PREFIXES = ("LD_", "DYLD_", "GIT_CONFIG", "NPM_CONFIG_", "PIP_", "BASH_FUNC_")
# Variables that choose where Claude Code sends the conversation, or exports it as telemetry,
# and with which credentials, headers, proxy or certificate trust, including those of the
# cloud CLIs and tools it starts.
_ENDPOINT_ENV = frozenset(
    {
        "CLAUDE_CODE_ENABLE_TELEMETRY",
        "CLAUDE_CODE_ENHANCED_TELEMETRY_BETA",
        "ENABLE_ENHANCED_TELEMETRY_BETA",
        "ENABLE_BETA_TRACING_DETAILED",
        "BETA_TRACING_ENDPOINT",
        "CLAUDE_CODE_OAUTH_TOKEN",
        "CLAUDE_CODE_OAUTH_REFRESH_TOKEN",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "AWS_SESSION_TOKEN",
        "AWS_PROFILE",
        "AWS_SHARED_CREDENTIALS_FILE",
        "AWS_CA_BUNDLE",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "REQUESTS_CA_BUNDLE",
        "CURL_CA_BUNDLE",
        "GIT_SSL_CAINFO",
        "GIT_SSL_NO_VERIFY",
        "ANTHROPIC_API_KEY",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_CUSTOM_HEADERS",
        "ANTHROPIC_FOUNDRY_API_KEY",
        "ANTHROPIC_FOUNDRY_AUTH_TOKEN",
        "ANTHROPIC_FOUNDRY_RESOURCE",
        "ANTHROPIC_AWS_API_KEY",
        "ANTHROPIC_VERTEX_PROJECT_ID",
        "AWS_BEARER_TOKEN_BEDROCK",
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "CLAUDE_CODE_USE_MANTLE",
        "CLAUDE_CODE_EXTRA_BODY",
        "CLAUDE_CODE_CERT_STORE",
        "CLAUDE_CODE_CLIENT_CERT",
        "CLAUDE_CODE_CLIENT_KEY",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "NO_PROXY",
        "NODE_EXTRA_CA_CERTS",
        "NODE_TLS_REJECT_UNAUTHORIZED",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
    }
)
_ENDPOINT_ENV_PATTERN = re.compile(
    r"ANTHROPIC_\w*BASE_URL|CLAUDE_CODE_SKIP_\w*AUTH|AWS_ENDPOINT_URL\w*"
    r"|OTEL_LOG_\w+|OTEL_\w*EXPORTER\w*"
)
# Both are high: an endpoint or proxy receives every prompt, file and tool result in the
# conversation and writes the replies that become tool calls, as an HTTP hook would see them.
_ENV_FINDINGS = {
    "agent-settings-env-exec": "can inject code into or redirect the commands it runs",
    "agent-settings-env-endpoint": (
        "can redirect its model endpoint, credentials, network proxy or TLS trust, "
        "or export the conversation as telemetry"
    ),
}
_MAX_ENV_FINDING_NAMES = 8
UNPARSED_NAME = "[unparsed]"
_HOOK_EVENT = re.compile(r"[A-Za-z][A-Za-z0-9]{0,63}")
_SAFE_NAME = re.compile(r"[\w.+-][\w.+:-]{0,127}", re.ASCII)
_ENV_ASSIGNMENT = re.compile(r"[A-Za-z_][A-Za-z0-9_]*=")
_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,127}")
# An RFC 9110 token.
_HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}")
# Documented values of handler fields that decide how a hook runs.
_HANDLER_CHOICES = {"shell": ("bash", "powershell"), "onFailure": ("continue", "block")}
# shlex grows each token one character at a time, which is quadratic in its length.
# The executable comes first, so only a bounded prefix is lexed.
_COMMAND_LEX_LIMIT = 4096
# Every hook record repeats its matcher, and every settings file read is merged with the
# earlier ones, so these bound the inventory and the work that a repository can demand.
_MATCHER_LIMIT = 512
_MAX_HOOK_DECLARATIONS = 1000
# Header and environment variable names are up to 128 characters, so without these bounds
# two 4 MiB settings files produced a BOM larger than any command would load.
_MAX_NAMES = 64
_MAX_HOOK_NAMES = 2048
_MAX_CLAUDE_SETTINGS_FILES = 8
# Printable ASCII without spaces or backslashes after an http(s) scheme and two slashes.
_PLAIN_HTTP_URL = re.compile(r"(?i:https?)://[!-\[\]-~]+")
_URL_HOST = re.compile(r"[a-z0-9_.-]+")


_CLAUDE_SETTINGS_LAYERS = {
    folded_name(name): index for index, name in enumerate(CLAUDE_SETTINGS_FILES)
}


def _claude_settings_paths(available: set[str]) -> list[str]:
    """Files Claude Code may open as project, then local, settings; exact names first.

    Claude Code joins fixed names, so a case-insensitive file system also opens
    .Claude/Settings.json for .claude/settings.json.
    """
    matches = []
    for path in available:
        layer = _CLAUDE_SETTINGS_LAYERS.get(folded_name(path)) if path.count("/") == 1 else None
        if layer is not None:
            matches.append((layer, path != CLAUDE_SETTINGS_FILES[layer], path))
    return [path for *_, path in sorted(matches)]


def _claude_marker_variant(marker: str, available: set[str]) -> tuple[str, str] | None:
    """A marker's name as a case-insensitive file system opens it, and a file proving it.

    For the marker .claude/commands this may be .Claude/Commands and a file beneath it.
    """
    depth, target = marker.count("/") + 1, folded_name(marker)
    for path in sorted(available):
        name = "/".join(path.split("/")[:depth])
        if folded_name(name) == target:
            return name, path
    return None


def _safe_name(value: str) -> str:
    return redact_text(value) if _SAFE_NAME.fullmatch(value) else UNPARSED_NAME


def _exportable_matcher(matcher: str) -> bool:
    """Whether a matcher can be exported as written.

    Lone surrogates break UTF-8 exports, and control or format characters can disguise a
    matcher. Tool names and the patterns that match them are printable ASCII.
    """
    return len(matcher) <= _MATCHER_LIMIT and matcher.isascii() and matcher.isprintable()


def _http_origin(url: str) -> str | None:
    """A plain http(s) URL's origin, or None where URL parsers may disagree on the host.

    Claude Code posts HTTP hooks from Node, whose WHATWG parser reads a backslash as a path
    separator and accepts "https:host" without slashes; urlsplit does neither. So
    https://attacker.example\\@hooks.example posts to attacker.example, not hooks.example.
    """
    if not _PLAIN_HTTP_URL.fullmatch(url):
        return None
    try:
        parsed = urlsplit(url)
        port = parsed.port
        host = parsed.hostname or ""
        # Python before 3.11.4 accepts any bracketed host, such as [hooks.example].
        if "[" in parsed.netloc:
            host = f"[{ipaddress.IPv6Address(host)}]"
        elif not _URL_HOST.fullmatch(host):
            return None
    except ValueError:
        return None
    return f"{parsed.scheme}://{host}" + ("" if port is None else f":{port}")


def _order_free(hooks: Any) -> Any:
    """Matching hooks run in parallel, so bind matcher groups and handlers in canonical order."""
    if not isinstance(hooks, dict):
        return hooks
    ordered: dict[str, Any] = {}
    for event, groups in hooks.items():
        if isinstance(groups, list):
            groups = sorted(
                (
                    {**group, "hooks": sorted(group["hooks"], key=canonical_json)}
                    if isinstance(group, dict) and isinstance(group.get("hooks"), list)
                    else group
                    for group in groups
                ),
                key=canonical_json,
            )
        ordered[event] = groups
    return ordered


def _within_budget(budget: list[int], relative: str, result: ScanResult) -> bool:
    """Count one hook declaration; past the limit, record one failure and stop."""
    budget[0] -= 1
    if budget[0] == -1:
        result.scan_failures.append(
            f"{relative}: more than {_MAX_HOOK_DECLARATIONS} hook declarations; "
            "the rest not inventoried"
        )
    return budget[0] >= 0


def _command_basename(command: str, *, exec_form: bool) -> str:
    """The executable's file name. Assignments, directories and arguments are never kept.

    A backslash in a leading assignment, where a POSIX shell could escape the space that
    ends the value, gives UNPARSED_NAME.
    """
    token = command
    if not exec_form:
        head = io.StringIO(command[:_COMMAND_LEX_LIMIT])
        lexer = shlex.shlex(head, posix=True)
        lexer.whitespace_split = True
        lexer.commenters = ""
        # A backslash is literal in PowerShell and Windows paths. As a POSIX escape it would
        # join directory names into the executable name, such as C:Usersalicehook.exe.
        lexer.escape = ""
        token = ""
        try:
            for word in lexer:
                # "&" is the PowerShell call operator; assignments only set the environment.
                if word != "&" and not _ENV_ASSIGNMENT.match(word):
                    token = word
                    break
                # Up to the first backslash, this lexer splits words as a POSIX shell does.
                # In API_KEY=sk\ live ./hook.sh the shell escapes the space, so the word
                # after the assignment is part of its value, not the executable.
                if "\\" in word:
                    return UNPARSED_NAME
        except ValueError:
            # Splitting unbalanced quotes on whitespace could export part of a quoted secret.
            return UNPARSED_NAME
        if len(command) > _COMMAND_LEX_LIMIT and head.tell() >= _COMMAND_LEX_LIMIT:
            return UNPARSED_NAME
    return _safe_name(token.replace("\\", "/").rsplit("/", 1)[-1])


def _hook_target(handler: Any) -> dict[str, str] | None:
    """A documented hook handler's type and secret-free target, or None if unrecognized."""
    if not isinstance(handler, dict):
        return None
    kind = handler.get("type")
    if not isinstance(kind, str):
        return None
    if kind == "command":
        command, args = handler.get("command"), handler.get("args")
        if not isinstance(command, str) or not command.strip():
            return None
        if args is not None and not (
            isinstance(args, list) and all(isinstance(arg, str) for arg in args)
        ):
            return None
        basename = _command_basename(command, exec_form=args is not None)
        return {"type": kind, "command_basename": basename}
    if kind == "http":
        url = handler.get("url")
        if not isinstance(url, str):
            return None
        return {"type": kind, "url_origin": _http_origin(url) or UNPARSED_NAME}
    if kind == "mcp_tool":
        server, tool = handler.get("server"), handler.get("tool")
        if not isinstance(server, str) or not isinstance(tool, str):
            return None
        return {"type": kind, "mcp_server": _safe_name(server), "mcp_tool": _safe_name(tool)}
    if kind in {"prompt", "agent"} and isinstance(handler.get("prompt"), str):
        return {"type": kind}
    return None


def _names(
    value: Any,
    pattern: re.Pattern[str],
    subject: str,
    result: ScanResult,
    budget: list[int] | None = None,
) -> list[str] | str:
    """Sorted unique names from a list of names matching pattern, within the bounds.

    Anything else is recorded as UNPARSED_NAME with a failure naming the subject. A budget
    is shared by every name list it is passed to and spent by those recorded.
    """
    if not (
        isinstance(value, list)
        and all(isinstance(item, str) and pattern.fullmatch(item) for item in value)
    ):
        reason = "is not a documented value"
    elif len(names := sorted(set(value))) > _MAX_NAMES:
        reason = f"lists more than {_MAX_NAMES} names"
    elif budget is not None and len(names) > budget[0]:
        reason = f"would pass {_MAX_HOOK_NAMES} names across hook handlers"
    else:
        if budget is not None:
            budget[0] -= len(names)
        return names
    result.scan_failures.append(f"{subject} {reason}; recorded as {UNPARSED_NAME}")
    return UNPARSED_NAME


def _handler_options(
    handler: dict[str, Any], relative: str, event: str, result: ScanResult, names: list[int]
) -> dict[str, Any]:
    """Declared fields that decide when, how and with what access a hook runs.

    Only names and documented values are kept; header values can hold credentials.
    """
    options: dict[str, Any] = {}

    def unparsed(field: str) -> str:
        result.scan_failures.append(
            f"{relative}: hooks.{event} handler {field} is not a documented value; "
            f"recorded as {UNPARSED_NAME}"
        )
        return UNPARSED_NAME

    if "if" in handler:
        condition = handler["if"]
        options["if"] = (
            redact_text(condition)
            if isinstance(condition, str) and _exportable_matcher(condition)
            else unparsed("if")
        )
    for field, allowed in _HANDLER_CHOICES.items():
        if field in handler:
            options[field] = handler[field] if handler[field] in allowed else unparsed(field)
    for field in ("async", "asyncRewake"):
        if field in handler:
            options[field] = handler[field] if isinstance(handler[field], bool) else unparsed(field)
    if "timeout" in handler:
        timeout = handler["timeout"]
        valid = isinstance(timeout, (int, float)) and not isinstance(timeout, bool)
        # Also excludes NaN and infinities, which have no JSON form.
        options["timeout"] = timeout if valid and 0 < timeout <= 2**53 else unparsed("timeout")
    if handler["type"] == "command" and handler.get("args") is not None:
        # With args, the command runs without a shell.
        options["exec_form"] = True
    if handler["type"] == "http":
        subject = f"{relative}: hooks.{event} handler"
        if "allowedEnvVars" in handler:
            options["allowedEnvVars"] = _names(
                handler["allowedEnvVars"], _ENV_NAME, f"{subject} allowedEnvVars", result, names
            )
        if "headers" in handler:
            headers = handler["headers"]
            options["header_names"] = _names(
                list(headers) if isinstance(headers, dict) else None,
                _HEADER_NAME,
                f"{subject} header names",
                result,
                names,
            )
    return options


def _hook_settings_record(
    relative: str, declared: dict[str, Any], result: ScanResult
) -> dict[str, Any]:
    """A settings file's hook switch and allowlists; URL patterns are only counted."""
    record: dict[str, Any] = {"settings_file": relative}

    def unparsed(field: str) -> str:
        result.scan_failures.append(
            f"{relative}: {field} is not a documented value; recorded as {UNPARSED_NAME}"
        )
        return UNPARSED_NAME

    if "disableAllHooks" in declared:
        disabled = declared["disableAllHooks"]
        record["disableAllHooks"] = (
            disabled if isinstance(disabled, bool) else unparsed("disableAllHooks")
        )
    if "allowedHttpHookUrls" in declared:
        patterns = declared["allowedHttpHookUrls"]
        record["allowedHttpHookUrls_count"] = (
            len(patterns)
            if isinstance(patterns, list) and all(isinstance(item, str) for item in patterns)
            else unparsed("allowedHttpHookUrls")
        )
    if "httpHookAllowedEnvVars" in declared:
        record["httpHookAllowedEnvVars"] = _names(
            declared["httpHookAllowedEnvVars"],
            _ENV_NAME,
            f"{relative}: httpHookAllowedEnvVars",
            result,
        )
    return record


def _env_category(name: str) -> str | None:
    """The finding a settings env variable raises, if any; Windows ignores name case."""
    upper = name.upper()
    if upper in _EXEC_ENV or upper.startswith(_EXEC_ENV_PREFIXES):
        return "agent-settings-env-exec"
    if upper in _ENDPOINT_ENV or _ENDPOINT_ENV_PATTERN.fullmatch(upper):
        return "agent-settings-env-endpoint"
    return None


def _settings_env_record(
    relative: str, env: Any, result: ScanResult, risks: list[RiskAssessment]
) -> dict[str, Any]:
    """A settings file's env variable names, never values, and findings for risky names.

    Names Claude Code may still apply count even when the record is unparsed.
    """
    valid = isinstance(env, dict) and all(isinstance(value, str) for value in env.values())
    names = _names(list(env) if valid else None, _ENV_NAME, f"{relative}: env", result)
    flagged: dict[str, list[str]] = {}
    if isinstance(env, dict):
        for name in env:
            if not isinstance(name, str):
                continue
            if name.upper().startswith("BASH_FUNC_"):
                # The name holds the replaced command and %%, which are not shown.
                flagged.setdefault("agent-settings-env-exec", []).append("BASH_FUNC_*")
            elif _ENV_NAME.fullmatch(name) and (category := _env_category(name)):
                flagged.setdefault(category, []).append(name)
    for category, action in _ENV_FINDINGS.items():
        if not (matched := sorted(set(flagged.get(category, [])))):
            continue
        shown = ", ".join(matched[:_MAX_ENV_FINDING_NAMES])
        if len(matched) > _MAX_ENV_FINDING_NAMES:
            shown += f" and {len(matched) - _MAX_ENV_FINDING_NAMES} more"
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category=category,
                detail=f"IDE agent 'claude-code' settings env sets {shown}, which {action}.",
                recommendation=(
                    "Review the variables and their values. Claude Code applies settings env "
                    "to every session and the commands it starts, and -p and SDK sessions "
                    "never ask for workspace trust."
                ),
            )
        )
    return {"settings_file": relative, "names": names}


def _setting_command_records(
    relative: str, declared: dict[str, Any], result: ScanResult
) -> list[dict[str, Any]]:
    """The executable name of each settings command a file declares."""
    records = []
    for setting in (*CLAUDE_SETTINGS_HELPERS, *CLAUDE_SETTINGS_COMMAND_OBJECTS):
        if setting not in declared:
            continue
        value = declared[setting]
        if setting in CLAUDE_SETTINGS_COMMAND_OBJECTS:
            value = value.get("command") if isinstance(value, dict) else None
        if isinstance(value, str) and value.strip():
            basename = _command_basename(value, exec_form=False)
        else:
            result.scan_failures.append(
                f"{relative}: {setting} is not a documented command; recorded as {UNPARSED_NAME}"
            )
            basename = UNPARSED_NAME
        records.append(
            {"settings_file": relative, "setting": setting, "command_basename": basename}
        )
    return records


def _claude_hook_records(
    relative: str, hooks: Any, result: ScanResult, budget: list[int], names: list[int]
) -> list[dict[str, Any]]:
    """Every handler under event -> matcher groups -> hooks; other shapes are failures."""
    if not isinstance(hooks, dict):
        result.scan_failures.append(f"{relative}: hooks is not an object; not inventoried")
        return []
    records: list[dict[str, Any]] = []
    for event, groups in hooks.items():
        if not _within_budget(budget, relative, result):
            return records
        if not _HOOK_EVENT.fullmatch(event):
            result.scan_failures.append(f"{relative}: unrecognized hook event; not inventoried")
            continue
        if not isinstance(groups, list):
            result.scan_failures.append(f"{relative}: hooks.{event} is not a list; not inventoried")
            continue
        for group in groups:
            if not _within_budget(budget, relative, result):
                return records
            handlers = group.get("hooks") if isinstance(group, dict) else None
            matcher = group.get("matcher") if isinstance(group, dict) else None
            if not isinstance(handlers, list) or not (matcher is None or isinstance(matcher, str)):
                result.scan_failures.append(
                    f"{relative}: unrecognized hooks.{event} matcher group; not inventoried"
                )
                continue
            if matcher is not None and not _exportable_matcher(matcher):
                result.scan_failures.append(
                    f"{relative}: hooks.{event} matcher is not printable ASCII of at most "
                    f"{_MATCHER_LIMIT} characters; recorded as {UNPARSED_NAME}"
                )
                matcher = UNPARSED_NAME
            for handler in handlers:
                if not _within_budget(budget, relative, result):
                    return records
                target = _hook_target(handler)
                if target is None:
                    result.scan_failures.append(
                        f"{relative}: unrecognized hooks.{event} handler; not inventoried"
                    )
                    continue
                if target.get("url_origin") == UNPARSED_NAME:
                    # The destination is what an HTTP hook finding reports, so unlike an
                    # unparsed command name, an unparsed URL leaves coverage unknown.
                    result.scan_failures.append(
                        f"{relative}: hooks.{event} HTTP hook URL is not a plain http(s) URL "
                        f"with an ASCII host; recorded as {UNPARSED_NAME}"
                    )
                records.append(
                    {
                        "settings_file": relative,
                        "event": event,
                        "matcher": None if matcher is None else redact_text(matcher),
                        **target,
                        **_handler_options(handler, relative, event, result, names),
                    }
                )
    return records


class IDEAgentScanner(Scanner):
    name = "ide_agents"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            available = {path.as_posix() for path in files.iter_files()}
            nested_codex = [
                layer for layer in codex_config_layers(available, result) if layer != CODEX_CONFIG
            ]
            # Codex reads hooks.json from every project .codex folder, even without config.toml.
            nested_codex += sorted(
                path
                for path in available
                if path == CODEX_HOOKS or path.endswith("/" + CODEX_HOOKS)
            )
            for ide_type, config in IDE_AGENT_CONFIGS.items():
                found: list[str] = []
                for marker in [*config["markers"], *(nested_codex if ide_type == "codex" else [])]:
                    evidence = (
                        marker
                        if marker in available
                        else next(
                            (path for path in sorted(available) if path.startswith(marker + "/")),
                            None,
                        )
                    )
                    name = marker
                    if (
                        evidence is None
                        and ide_type == "claude-code"
                        and marker not in CLAUDE_SETTINGS_FILES
                    ):
                        name, evidence = _claude_marker_variant(marker, available) or (marker, None)
                    if evidence and files.read_bytes(evidence) is not None:
                        found.append(name)
                        result.surfaces_scanned.append(str(files.root / evidence))
                if ide_type == "claude-code":
                    self._claude_settings_variants(files, available, found, result)
                if not found:
                    continue
                settings = self._read_ide_settings(files.root, ide_type, result, available) or {}
                mode = self._extract_permission_mode(settings, ide_type, result)
                risks: list[RiskAssessment] = []
                codex_policy: dict[str, Any] = {}
                mcp_configs: list[str] = []
                layers = [path for path in found if is_codex_config(path)]
                hooks = [path for path in found if path.endswith(CODEX_HOOKS)]
                if ide_type == "codex" and (layers or hooks):
                    codex_policy, codex_mode, mcp_configs = self._codex_policy(
                        files.root, layers, hooks, result, risks
                    )
                    mode = codex_mode or mode
                if self._has_broad_permissions(settings, ide_type, result):
                    risks.append(
                        RiskAssessment(
                            severity=RiskSeverity.MEDIUM,
                            category="permission_scope",
                            detail=(
                                f"IDE agent '{ide_type}' declares unscoped tool allowances; "
                                "effective approval remains unverified."
                            ),
                            recommendation=(
                                "Review deny/ask rules, workspace trust, user and managed "
                                "settings, and runtime controls; enforce resource-scoped authority."
                            ),
                        )
                    )
                hook_properties = (
                    self._claude_code_hooks(
                        settings.get("hooks"), settings.get("hook_settings"), result, risks
                    )
                    if ide_type == "claude-code"
                    else {}
                )
                layered = (
                    ide_type == "claude-code"
                    and {"claude.md", ".claude/claude.md"} <= {folded_name(f) for f in found}
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
                for config_name in config.get("mcp_config", []):
                    if config_name in available:
                        data = self._read_mapping(files.root / config_name, result)
                        if data is not None:
                            mcp_configs.append(config_name)
                # Configuration locators are not component references. The MCP
                # collector binds actual client/server components separately.
                result.components.append(
                    IDEAgentComponent(
                        bom_ref=f"ide-agent:{ide_type}",
                        name=ide_type,
                        ide_type=ide_type,
                        config_files=found,
                        mcp_server_refs=[],
                        permission_mode=mode,
                        source_path=str(files.root / found[0]),
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        risks=risks,
                        properties={
                            **codex_policy,
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
                            **hook_properties,
                        },
                    )
                )
            self._scan_extensions(files.root, result, available)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("ide-agents (no IDE agent configs found)")
        return result

    def _read_ide_settings(
        self, root: Path, ide_type: str, result: ScanResult, available: set[str]
    ) -> dict[str, Any] | None:
        settings_paths = {
            "cursor": [".cursor/settings.json"],
            "windsurf": [".windsurf/settings.json"],
            "cline": [".cline/settings.json"],
            "codex": [".codex/config.json"],
        }
        merged: dict[str, Any] = {}
        # Keep declared allowances from every collected Claude settings layer.
        # This summary does not resolve effective permissions across trust,
        # user/managed policy, ask/deny rules, flags or product versions.
        relatives = (
            _claude_settings_paths(available)[:_MAX_CLAUDE_SETTINGS_FILES]
            if ide_type == "claude-code"
            else settings_paths.get(ide_type, [])
        )
        for relative in relatives:
            if relative in available:
                data = self._read_mapping(root / relative, result)
                if data is not None:
                    if ide_type == "claude-code" and "hooks" in data:
                        # Claude Code runs the hooks of every settings layer; none overrides.
                        merged["hooks"] = {**merged.get("hooks", {}), relative: data.pop("hooks")}
                    declared = (
                        {
                            key: data.pop(key)
                            for key in (
                                *CLAUDE_HOOK_SETTINGS,
                                *CLAUDE_SETTINGS_HELPERS,
                                *CLAUDE_SETTINGS_COMMAND_OBJECTS,
                                CLAUDE_SETTINGS_ENV,
                            )
                            if key in data
                        }
                        if ide_type == "claude-code"
                        else {}
                    )
                    if declared:
                        merged["hook_settings"] = {
                            **merged.get("hook_settings", {}),
                            relative: declared,
                        }
                    if ide_type == "claude-code" and "permissions" in data:
                        permissions = data["permissions"]
                        if not isinstance(permissions, dict):
                            result.scan_failures.append(
                                f"{relative}: invalid permission settings object"
                            )
                            continue
                        previous = merged.get("permissions", {})
                        combined = {**previous, **permissions}
                        for key in ("allow", "ask", "deny"):
                            earlier, current = previous.get(key, []), permissions.get(key, [])
                            if not all(
                                isinstance(values, list)
                                and all(isinstance(value, str) for value in values)
                                for values in (earlier, current)
                            ):
                                result.scan_failures.append(
                                    f"{relative}: invalid declared permission {key}-list"
                                )
                                combined.pop(key, None)
                            else:
                                combined[key] = list(dict.fromkeys([*earlier, *current]))
                        data = {**data, "permissions": combined}
                    if ide_type == "codex":
                        # Only the legacy agent.permissionMode field comes from JSON;
                        # _codex_policy reads the TOML layers.
                        if "agent" in data:
                            merged["agent"] = data["agent"]
                    else:
                        merged.update(data)
        return merged or None

    def _codex_policy(
        self,
        root: Path,
        layers: list[str],
        hooks: list[str],
        result: ScanResult,
        risks: list[RiskAssessment],
    ) -> tuple[dict[str, Any], str | None, list[str]]:
        """Interpret Codex TOML layers; return root declarations, root mode and MCP layers.

        Codex merges every layer from the project root down to its working
        directory, so each directory scope is evaluated with its ancestors.
        """
        declared: list[tuple[str, PurePosixPath, dict[str, Any]]] = []
        mcp_configs: list[str] = []
        uninterpreted: dict[str, dict[str, Any]] = {}
        for label in layers:
            data = self._read_mapping(root / label, result)
            if data is None:
                continue
            if "mcp_servers" in data:
                mcp_configs.append(label)
            values = _codex_declarations(label, data, result)
            declared.append((label, codex_scope(label), values))
            if subtrees := _codex_uninterpreted(data):
                uninterpreted[label] = subtrees
        for label in hooks:
            _codex_unknown(label, "hooks", result)
            hook_data = self._read_mapping(root / label, result)
            if hook_data is not None:
                uninterpreted[label] = hook_data
        findings: set[tuple[RiskSeverity, str]] = set()
        root_mode: str | None = None
        budget = [MAX_CODEX_PROFILE_WORK]
        try:
            for index, (label, directory, values) in enumerate(declared):
                chain = [
                    layer for layer in declared[: index + 1] if codex_applies(layer[1], directory)
                ]
                catalog = _codex_catalog(chain)
                memo: dict[str, _Resolved] = {}
                # How each declared writable or workspace root resolves: see _resolve_root.
                places: set[str | None] = set()
                profiles = values.get("permission_profiles", {})
                for name in list(profiles):
                    try:
                        _, grants = _resolve_profile(name, catalog, memo, budget)
                    except ValueError:
                        result.scan_failures.append(
                            f"{label}: invalid permission profile declaration"
                        )
                        del profiles[name]
                        continue
                    places |= _profile_writes(grants, directory, budget)[1]
                    if grants.get("network_enabled") is True:
                        findings.add(_NETWORK)
                if not profiles:
                    values.pop("permission_profiles", None)
                # An override that broke a profile was removed above; resolve the rest.
                catalog = _codex_catalog(chain)
                memo = {}
                selected = values.get("default_permissions")
                if selected is not None and selected not in CODEX_BUILT_IN_PROFILES:
                    try:
                        _resolve_profile(selected, catalog, memo, budget)
                    except ValueError:
                        result.scan_failures.append(
                            f"{label}: unsupported declared permission profile"
                        )
                        del values["default_permissions"]
                workspace = values.get("sandbox_workspace_write", {})
                # Codex resolves a layer's relative writable roots against its .codex folder.
                places.update(
                    _resolve_root(path, directory / ".codex")
                    for path in workspace.get("writable_roots", [])
                )
                if "outside" in places:
                    findings.add(_OUTSIDE)
                if "unobserved" in places:
                    message = f"{label}: {_UNOBSERVED_ROOT}"
                    if message not in result.surfaces_excluded:
                        result.surfaces_excluded.append(message)
                if workspace.get("network_access") is True:
                    findings.add(_NETWORK)
                if "danger-full-access" in {
                    values.get("sandbox_mode"),
                    CODEX_BUILT_IN_PROFILES.get(values.get("default_permissions", "")),
                }:
                    findings.add(_FULL_ACCESS)
                approval = _codex_approval(chain)
                if not _valid_approval(approval):
                    # Codex refuses the merged policy, so no session runs with it here.
                    if "approval_policy" in values:
                        kind = (
                            "invalid granular" if "granular" in approval else "unsupported declared"
                        )
                        result.scan_failures.append(f"{label}: {kind} approval policy")
                    approval = None
                mode = _codex_scope_mode(chain, catalog, memo, budget, approval, findings)
                if directory == PurePosixPath():
                    root_mode = mode
        except _ProfileWorkError:
            result.scan_failures.append(_PROFILE_WORK_LIMIT)
        for severity, detail in sorted(findings, key=lambda finding: finding[1]):
            risks.append(
                RiskAssessment(
                    severity=severity,
                    category="permission_scope",
                    detail=detail,
                    recommendation=(
                        "Review project trust and enforce sandbox and approval constraints "
                        "at the host."
                    ),
                )
            )
        properties: dict[str, Any] = {}
        nested: dict[str, Any] = {}
        for label, directory, values in declared:
            if directory == PurePosixPath():
                properties.update(values)
            elif values:
                nested[label] = values
        if nested:
            properties["nested_config_layers"] = nested
        properties.update(_codex_uninterpreted_binding(uninterpreted, result))
        return properties, root_mode, mcp_configs

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
        if mode not in {
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
            "untrusted",
            "on-request",
            "never",
            "always",
        }:
            result.scan_failures.append(f"{ide_type}: unsupported declared permission mode")
            return None
        return mode

    def _has_broad_permissions(
        self, settings: dict[str, Any], ide_type: str, result: ScanResult
    ) -> bool:
        if ide_type != "claude-code":
            return False
        permissions = settings.get("permissions", {})
        if not isinstance(permissions, dict):
            return False
        allowed = permissions.get("allow", [])
        if not isinstance(allowed, list) or not all(isinstance(value, str) for value in allowed):
            result.scan_failures.append(f"{ide_type}: invalid declared permission allow-list")
            return False
        return any(
            value in allowed
            for value in ("Bash", "Edit", "Write", "Bash(*)", "Edit(*)", "Write(*)", "*")
        )

    @staticmethod
    def _claude_settings_variants(
        files: ConfinedCollection, available: set[str], found: list[str], result: ScanResult
    ) -> None:
        """Add Claude settings files whose names differ from the markers only in case."""
        paths = _claude_settings_paths(available)
        if len(paths) > _MAX_CLAUDE_SETTINGS_FILES:
            result.scan_failures.append(
                f"claude-code: more than {_MAX_CLAUDE_SETTINGS_FILES} files open as Claude Code "
                "settings; the rest not read"
            )
        for evidence in paths[:_MAX_CLAUDE_SETTINGS_FILES]:
            if evidence in CLAUDE_SETTINGS_FILES or evidence in found:
                continue
            if files.read_bytes(evidence) is not None:
                found.append(evidence)
                result.surfaces_scanned.append(str(files.root / evidence))

    @staticmethod
    def _claude_code_hooks(
        sources: Any, hook_settings: Any, result: ScanResult, risks: list[RiskAssessment]
    ) -> dict[str, Any]:
        """Record each settings file's hooks, settings commands and env, and flag those that run.

        hook_settings holds each file's hook switches, allowlists, settings commands and env.
        """
        sources, hook_settings = sources or {}, hook_settings or {}
        if not sources and not hook_settings:
            return {}
        budget, names = [_MAX_HOOK_DECLARATIONS], [_MAX_HOOK_NAMES]
        failures = len(result.scan_failures)
        records = sorted(
            (
                record
                for relative, hooks in sources.items()
                for record in _claude_hook_records(relative, hooks, result, budget, names)
            ),
            key=lambda record: json.dumps(list(record.values())),
        )
        if not records and not hook_settings and len(result.scan_failures) == failures:
            # Nothing runs, so keep the inventory that predates hook collection.
            return {}
        commands = sorted(
            (
                record
                for relative, declared in hook_settings.items()
                for record in _setting_command_records(relative, declared, result)
            ),
            key=lambda record: json.dumps(list(record.values())),
        )
        env = [
            _settings_env_record(relative, declared[CLAUDE_SETTINGS_ENV], result, risks)
            for relative, declared in hook_settings.items()
            if CLAUDE_SETTINGS_ENV in declared
        ]
        for command in commands:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="agent-settings-command",
                    detail=(
                        f"IDE agent 'claude-code' runs settings command "
                        f"'{command['command_basename']}' from {command['setting']} "
                        "without per-call approval."
                    ),
                    recommendation=(
                        "Review the command. Claude Code runs settings helper commands "
                        "automatically, and -p and SDK sessions never ask for workspace trust."
                    ),
                )
            )
        for record in records:
            if record["type"] not in CLAUDE_HOOK_RISKS:
                continue
            severity, category, action = CLAUDE_HOOK_RISKS[record["type"]]
            risks.append(
                RiskAssessment(
                    severity=severity,
                    category=category,
                    detail=(
                        f"IDE agent 'claude-code' {action.format(**record)} on "
                        f"{record['event']} without per-call approval."
                    ),
                    recommendation=(
                        "Review the hook and its target. Claude Code runs project hooks "
                        "automatically, and -p and SDK sessions never ask for workspace trust."
                    ),
                )
            )
        # Arguments, header values and inputs can hold credentials, so only an operator-keyed
        # binding may cover them; an unkeyed digest would let secrets be guessed offline.
        # Ordering canonicalizes values, which can fail, so order only what a key will bind.
        order = _order_free if os.environ.get(SOURCE_BINDING_KEY_ENV) else (lambda hooks: hooks)
        try:
            binding = bind_source_values(
                {
                    relative: {
                        **({"hooks": order(sources[relative])} if relative in sources else {}),
                        **hook_settings.get(relative, {}),
                    }
                    for relative in {**sources, **hook_settings}
                },
                profile=CLAUDE_HOOK_BINDING_PROFILE,
            )
        except SourceBindingKeyError:
            result.scan_failures.append(
                f"{SOURCE_BINDING_KEY_ENV} is not valid random key material; "
                "Claude Code hooks were not bound"
            )
            binding = None
        except (CanonicalizationError, SourceBindingValueError, UnicodeEncodeError, RecursionError):
            # Lone surrogates, numbers outside I-JSON and deep nesting have no RFC 8785 form;
            # rfc8785 sorts keys by UTF-16, which raises UnicodeEncodeError on a surrogate key.
            result.scan_failures.append(
                "claude-code: hook values have no canonical JSON form; not bound"
            )
            binding = None
        return {
            "declared_hooks": records,
            "declared_hook_settings": [
                _hook_settings_record(relative, declared, result)
                for relative, declared in hook_settings.items()
                if not declared.keys().isdisjoint(CLAUDE_HOOK_SETTINGS)
            ],
            "declared_setting_commands": commands,
            # Only when declared, so baselines from before env was collected still reconcile.
            **({"declared_settings_env": env} if env else {}),
            **(
                {
                    "hook_value_binding": binding[0],
                    "hook_value_binding_key_id": binding[1],
                    "hook_value_binding_profile": CLAUDE_HOOK_BINDING_PROFILE,
                }
                if binding
                else {}
            ),
        }

    def _scan_extensions(self, root: Path, result: ScanResult, available: set[str]) -> None:
        relative = ".vscode/extensions.json"
        if relative not in available:
            return
        path = root / relative
        data = self._read_mapping(path, result)
        if data is None:
            return
        result.surfaces_scanned.append(str(path))
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
            if not isinstance(extension, str) or not re.fullmatch(
                r"[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z0-9][a-zA-Z0-9._-]*", extension
            ):
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
                        source_path=str(path),
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
