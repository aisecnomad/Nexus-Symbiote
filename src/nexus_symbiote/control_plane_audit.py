"""Control-plane hook targets, CI/hosted tools, steering surfaces, bridges, and identity reachability."""

from __future__ import annotations

import hashlib
import json
import posixpath
import re
import shlex
from bisect import bisect_left
from dataclasses import dataclass, field
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
RUNTIME_LAUNCHERS = _words("node python python3 sh bash zsh deno bun tsx uvx npx")
PACKAGE_RUNNERS = _words("npx uvx")
INSTALLED_BIN_DIRS = _tup("node_modules/.bin/ .venv/bin/ venv/bin/")
SCRIPT_SUFFIXES = _tup(".sh .py .js .mjs .cjs .ts .rb .pl")
CODE_EXEC_HOSTED_TOOLS = _words("code_interpreter computer_use bash local_shell code_execution")
UNTRUSTED_CI_TRIGGERS = _words("issue_comment discussion_comment pull_request_target workflow_run")
STEERING_PREFIXES = _tup(".claude .cursor CLAUDE.md AGENTS.md .mcp.json mcp.json")
HOOK_CONFIG_FILES = _tup(
    ".claude/settings.json .claude/settings.local.json .cursor/hooks.json .claude/hooks.json"
)
MCP_CONFIG_FILES = _tup(
    ".mcp.json mcp.json .cursor/mcp.json .vscode/mcp.json .claude/settings.json"
)
JSONC_FILES = _tup(".vscode/mcp.json")
PERMISSION_CONFIG_FILES = _tup(".claude/settings.json .claude/settings.local.json .cursor/cli.json")
_SUMMARY_KEYS = _tup(
    "hook_targets skill_preambles launcher_targets hosted_tools ci_agents framework_agents "
    "identities steering_surfaces bridged_servers hook_commands reach_alerts gaps"
)

_EGRESS_RE = re.compile(
    r"\b(?:curl|wget|nc|ncat|fetch\s*\(|axios\.|requests\.(?:get|post|put|request)|httpx\.|urllib\.request)\b",
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
_PREAMBLE_RE = re.compile(r"^\s*!(?:`([^`]+)`|\s+(.+))$")
_HEX_40_RE = re.compile(r"^[0-9a-fA-F]{40}$")
_ON_KEY_RE = re.compile(r"(?m)^([ \t]*)on([ \t]*:)")
_PROJECT_DIR_RE = re.compile(r"^(?:\$\{?CLAUDE_PROJECT_DIR\}?|\$\{workspace(?:Folder|Root)\})/")
_SPIFFE_RE = re.compile(r"^spiffe://[a-z0-9.-]+/[A-Za-z0-9._/-]+$")


def _clean(val: Any) -> str:
    if val is None:
        return ""
    raw = str(val).strip()
    if raw.startswith("spiffe://") and not _contains_secret(raw.split("://", 1)[-1]):
        return neutralize(raw)
    return neutralize(redact_text(raw))


def _yaml_error_text(exc: yaml.YAMLError) -> str:
    # PyYAML's message quotes the offending source line, which can hold a secret.
    if isinstance(exc, yaml.MarkedYAMLError) and exc.problem_mark is not None:
        mark = exc.problem_mark
        problem = redact_text(exc.problem or "syntax error")
        return f"invalid YAML: {problem} at line {mark.line + 1}, column {mark.column + 1}"
    return f"invalid YAML ({type(exc).__name__})"


def _parse_yaml(text: str) -> dict[str, Any]:
    try:
        for index, _token in enumerate(yaml.scan(text)):
            if index >= 20_000:
                raise ValueError("YAML exceeds 20,000 tokens")
    except yaml.YAMLError as exc:
        raise ValueError(_yaml_error_text(exc)) from exc
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
    except (OSError, ValueError) as exc:
        gaps.append(f"{rel_path}: {neutralize(str(exc))}")
        return None
    if gap is not None:
        gaps.append(f"{rel_path}: {gap}")
        return None
    return raw


def _read_confined_text(files: ConfinedCollection, rel_path: str, gaps: list[str]) -> str | None:
    raw = _read_confined_bytes(files, rel_path, gaps)
    return raw.decode("utf-8", errors="replace") if raw is not None else None


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
        except (ValueError, RecursionError) as exc:
            gaps.append(f"{rel_path}: invalid JSON ({neutralize(str(exc))})")
            continue
        if isinstance(parsed, dict):
            docs.append((rel_path, parsed))
        else:
            gaps.append(f"{rel_path}: configuration must be a JSON object")
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


def _extract_local_script_target(tokens: list[str]) -> str | None:
    if not tokens:
        return None
    first = tokens[0].strip()
    base = first.split("/")[-1]
    direct = _normalize_rel_candidate(first)
    if direct is not None and base not in RUNTIME_LAUNCHERS:
        return direct
    if base in RUNTIME_LAUNCHERS:
        for arg in tokens[1:]:
            if arg in {"-c", "-e", "-m"}:
                return None
            # A package runner takes registry package specifiers, not project paths.
            if base in PACKAGE_RUNNERS and not arg.startswith("./"):
                continue
            if not arg.startswith(("-", "@")):
                cand = _normalize_rel_candidate(arg)
                if cand is not None:
                    return cand
    return None


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
    launcher_targets: list[dict[str, Any]] = field(default_factory=list)
    hosted_tools: list[dict[str, Any]] = field(default_factory=list)
    ci_agents: list[dict[str, Any]] = field(default_factory=list)
    framework_agents: list[dict[str, Any]] = field(default_factory=list)
    identities: list[dict[str, Any]] = field(default_factory=list)
    steering_surfaces: list[dict[str, Any]] = field(default_factory=list)
    bridged_servers: list[dict[str, Any]] = field(default_factory=list)
    hook_commands: list[dict[str, Any]] = field(default_factory=list)
    reach_alerts: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)

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
        clean_name = neutralize(name)
        self.add(
            MCPServerComponent(
                bom_ref=f"mcp-server:{clean_name}",
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
    if "$" in target_path or (files.excluded(target_path) and not installed):
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
    files: ConfinedCollection, all_paths: list[str], summary: ControlPlaneAuditSummary
) -> None:
    for cfg_path, doc in _load_json_docs(files, all_paths, HOOK_CONFIG_FILES, summary.gaps):
        for event_name, cmd_str in _iter_hook_commands(doc):
            summary.hook_commands.append(
                _rec(
                    source_file=cfg_path,
                    event=event_name,
                    command_digest=_sha256_hex(cmd_str.encode()),
                )
            )
            target = _extract_local_script_target(_tokenize_command(cmd_str))
            if target is not None:
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
            if not match:
                continue
            cmd_body = (match.group(1) or match.group(2) or "").strip()
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
            summary.flag(
                "skill_shell_preamble",
                RiskSeverity.HIGH,
                f"Skill file '{skill_path}' line {line_no} contains a '!' shell execution preamble (digest {cmd_digest[:12]}).",
                skill_path,
                skill_ref,
            )
            target = _extract_local_script_target(_tokenize_command(cmd_body))
            if target is not None:
                _bind_script_target(
                    files,
                    summary,
                    owner_ref=skill_ref,
                    target_path=target,
                    source_file=skill_path,
                    role="preamble-target",
                    event_or_server=f"line:{line_no}",
                )


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


def _inspect_mcp_launchers_and_bridges(
    files: ConfinedCollection,
    all_paths: list[str],
    summary: ControlPlaneAuditSummary,
    live_versions: dict[str, str],
) -> None:
    for cfg_path, doc in _load_json_docs(files, all_paths, MCP_CONFIG_FILES, summary.gaps):
        for srv_name, srv_cfg in _extract_mcp_servers(doc):
            cmd = srv_cfg.get("command")
            args = _as_list(srv_cfg.get("args"))
            env_map = _as_dict(srv_cfg.get("env"))
            tokens = _tokenize_command(cmd, args)
            str_args = [str(a) for a in args if isinstance(a, (str, int, float))]
            srv_ref = f"mcp-server:{srv_name}"

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
                    if tok.startswith(("http://", "https://")) and endpoint_url is None:
                        endpoint_url = tok
                    elif tok == "--config" and j + 1 < len(tokens):
                        config_arg = tokens[j + 1]
                    elif tok.startswith("--config="):
                        config_arg = tok.split("=", 1)[1]

                proxied: list[str] = []
                if config_arg is not None:
                    norm_cfg = _normalize_rel_candidate(config_arg, allow_any_file=True)
                    cfg_body = (
                        _read_confined_text(files, norm_cfg, summary.gaps)
                        if norm_cfg is not None
                        else None
                    )
                    if cfg_body is not None and norm_cfg is not None:
                        try:
                            sub_doc = parse_json_strict(cfg_body)
                        except (ValueError, RecursionError) as exc:
                            summary.gaps.append(f"{norm_cfg}: invalid JSON ({exc})")
                            sub_doc = None
                        if isinstance(sub_doc, dict):
                            for sub_name, _sub_cfg in _extract_mcp_servers(sub_doc):
                                proxied.append(sub_name)
                                summary.edge(
                                    srv_ref, f"mcp-server:{sub_name}", "delegates-to", norm_cfg
                                )
                    if not proxied:
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
                    if endpoint_url.startswith("http://") or "@" in endpoint_url.split("//", 1)[-1]:
                        summary.flag(
                            "transport_security",
                            RiskSeverity.HIGH,
                            f"MCP bridge '{srv_name}' uses insecure HTTP or embedded credentials in URL (F21).",
                            cfg_path,
                            srv_name,
                        )

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
                continue

            target = _extract_local_script_target(tokens)
            props = {"registry_origin": reg_origin} if reg_origin else {}
            if target is not None:
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


def _covers_steering_path(root_arg: str, project_roots: tuple[str, ...]) -> bool:
    cleaned = root_arg.strip().strip("'\"")
    if not cleaned:
        return True
    # Absolute and parent-relative roots are placed against the audited project root.
    for project in project_roots:
        joined = posixpath.normpath(posixpath.join(project, cleaned))
        if joined == project or project.startswith(joined.rstrip("/") + "/"):
            return True
        if joined.startswith(project.rstrip("/") + "/"):
            rel = joined[len(project.rstrip("/")) + 1 :]
            if any(
                rel == pref or rel.startswith(pref + "/") or pref.startswith(rel + "/")
                for pref in STEERING_PREFIXES
            ):
                return True
    return False


def _steering_host(path: str) -> str:
    if path.startswith(".claude/") or path == ".mcp.json":
        return "claude"
    return path.split("/", 1)[0]


def _allows_mcp_server(rules: list[str], prefix: str) -> bool:
    exact = bisect_left(rules, prefix)
    if exact < len(rules) and rules[exact] == prefix:
        return True
    scoped = f"{prefix}__"
    index = bisect_left(rules, scoped)
    return index < len(rules) and rules[index].startswith(scoped)


def _inspect_steering_surfaces(
    files: ConfinedCollection, all_paths: list[str], summary: ControlPlaneAuditSummary
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
        allow = [r.strip() for r in _as_list(perms.get("allow")) if isinstance(r, str)]
        if any(
            rule in {"*", "Edit", "Write"}
            or (not rule.startswith("mcp__") and "filesystem" in rule)
            for rule in allow
        ):
            auto_edit_modes.append(f"{s_path}:write-allowance")
        if host == "claude":
            claude_prompting |= mode in ("default", "plan")
            claude_allows[s_path] = sorted(rule for rule in allow if rule.startswith("mcp__"))
            claude_denies.update(
                r.strip() for r in _as_list(perms.get("deny")) if isinstance(r, str)
            )
        if doc.get("approvalPolicy") in ("never", "auto-edit"):
            auto_edit_modes.append(f"{s_path}:{doc['approvalPolicy']}")

    project_roots = (files.root.as_posix(), files.root.resolve().as_posix())

    for cfg_path, doc in _load_json_docs(files, all_paths, MCP_CONFIG_FILES, summary.gaps):
        for srv_name, srv_cfg in _extract_mcp_servers(doc):
            cmd = str(srv_cfg.get("command") or "")
            args = [
                str(a) for a in _as_list(srv_cfg.get("args")) if isinstance(a, (str, int, float))
            ]
            joined = " ".join([cmd, *args]).lower()
            if "filesystem" not in srv_name.lower() and "server-filesystem" not in joined:
                continue
            host = _steering_host(cfg_path)
            prefix = f"mcp__{srv_name}"
            # A future or custom server can publish additional write tools. Only the
            # owning client's deny of the whole server covers this open-ended surface.
            deny_covered = host == "claude" and bool(claude_denies & {prefix, f"{prefix}__*"})
            srv_auto = (
                bool(srv_cfg.get("autoApprove")) or len(_as_list(srv_cfg.get("alwaysAllow"))) > 0
            )
            eff_modes = list(modes.get(host, ()))
            if host == "claude":
                eff_modes.extend(
                    f"{source}:mcp-allowance"
                    for source, rules in claude_allows.items()
                    if _allows_mcp_server(rules, prefix)
                )
            if srv_auto:
                eff_modes.append(f"{cfg_path}:{srv_name}:alwaysAllow")
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
                if not _covers_steering_path(r_arg, project_roots):
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
        except (ValueError, RecursionError) as exc:
            summary.gaps.append(f"{source_file}: invalid inline mcp_config ({exc})")
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
        except (PolicyError, ValueError, RecursionError) as exc:
            summary.gaps.append(f"{wf_path}: {neutralize(str(exc))}")
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
        return out

    base_targets = _target_map(baseline)
    for key, curr_sha in sorted(_target_map(current).items()):
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

    def _hook_keys(s: ControlPlaneAuditSummary) -> set[tuple[str, str, str]]:
        return {(h["source_file"], h["event"], h["command_digest"]) for h in s.hook_commands}

    for src, event, digest in sorted(_hook_keys(current) - _hook_keys(baseline)):
        _emit(
            "hook_command_changed",
            RiskSeverity.CRITICAL,
            f"hook-command:{src}:{event}:{digest[:12]}",
            f"Hook command for '{event}' in {src} (digest {digest[:12]}) is not in the baseline.",
        )

    base_writable = {s["server_name"] for s in baseline.steering_surfaces if s.get("writable")}
    for s in current.steering_surfaces:
        if s.get("writable") and s["server_name"] not in base_writable:
            _emit(
                "steering_surface_opened",
                RiskSeverity.CRITICAL,
                f"mcp-server:{s['server_name']}",
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
            summary.gaps.append(
                f"{neutralize(claims_path.name)}: claims file unreadable, over 4 MiB, or invalid UTF-8 JSON object"
            )

    with ConfinedCollection(project_root, summary.gaps) as files:
        all_paths = sorted(p.as_posix() for p in files.iter_files())
        for decl_path in ("agent.yaml", "agent.yml"):
            if decl_path in all_paths:
                text = _read_confined_text(files, decl_path, summary.gaps)
                if text is not None:
                    try:
                        decl_sources.append((decl_path, _parse_yaml(text), AssuranceLevel.DECLARED))
                    except (PolicyError, ValueError, RecursionError) as exc:
                        summary.gaps.append(f"{decl_path}: {neutralize(str(exc))}")
        _inspect_hooks_and_preambles(files, all_paths, summary)
        _inspect_mcp_launchers_and_bridges(files, all_paths, summary, live_versions or {})
        _inspect_steering_surfaces(files, all_paths, summary)
        _inspect_workflows_and_claims(files, all_paths, summary, decl_sources)
        _inspect_identities_and_authority(summary, decl_sources)

    if baseline_root is not None:
        base_summary = audit_project_control_plane(baseline_root)
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
