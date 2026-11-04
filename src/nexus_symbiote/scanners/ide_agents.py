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

import re
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import (
    SOURCE_BINDING_KEY_ENV,
    SourceBindingKeyError,
    SourceBindingValueError,
    bind_source_values,
)
from nexus_symbiote.core.models import IDEAgentComponent, RiskAssessment, VerifiedExtensionComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.mcp import (
    CODEX_CONFIG,
    codex_applies,
    codex_config_layers,
    codex_scope,
    is_codex_config,
    merge_codex,
)
from nexus_symbiote.utils.confined import DEFAULT_EXCLUDES
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
                    if evidence and files.read_bytes(evidence) is not None:
                        found.append(marker)
                        result.surfaces_scanned.append(str(files.root / evidence))
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
            "claude-code": [".claude/settings.json", ".claude/settings.local.json"],
            "cursor": [".cursor/settings.json"],
            "windsurf": [".windsurf/settings.json"],
            "cline": [".cline/settings.json"],
            "codex": [".codex/config.json"],
        }
        merged: dict[str, Any] = {}
        # Keep declared allowances from every collected Claude settings layer.
        # This summary does not resolve effective permissions across trust,
        # user/managed policy, ask/deny rules, flags or product versions.
        for relative in settings_paths.get(ide_type, []):
            if relative in available:
                data = self._read_mapping(root / relative, result)
                if data is not None:
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
