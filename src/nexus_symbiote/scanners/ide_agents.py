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
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import IDEAgentComponent, RiskAssessment, VerifiedExtensionComponent
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.secrets import redact_text

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
            # These files have executable and authorization settings that this
            # collector does not bind. A mode-only observation is not complete.
            for path in sorted(
                available.intersection(
                    {
                        ".claude/settings.json",
                        ".claude/settings.local.json",
                        ".cursor/settings.json",
                        ".windsurf/settings.json",
                        ".cline/settings.json",
                        ".codex/config.json",
                        ".codex/config.toml",
                    }
                )
            ):
                result.surfaces_excluded.append(f"{path}: IDE settings only partially inventoried")
            for ide_type, config in IDE_AGENT_CONFIGS.items():
                found: list[str] = []
                for marker in config["markers"]:
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
                settings = self._read_ide_settings(files.root, ide_type, result, available)
                mode = self._extract_permission_mode(settings or {}, ide_type, result)
                risks: list[RiskAssessment] = []
                if self._has_broad_permissions(settings or {}, ide_type, result):
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
                mcp_configs = []
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
