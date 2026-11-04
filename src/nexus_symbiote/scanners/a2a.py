"""Bounded offline A2A card, client configuration and SDK-reference collection."""

from __future__ import annotations

import ast
import re
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import (
    SOURCE_BINDING_KEY_ENV,
    bind_source_values,
    canonical_json,
)
from nexus_symbiote.core.models import A2AClientComponent, A2AServerComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult, sanitized_origin
from nexus_symbiote.utils.secrets import redact_text

AGENT_CARD_FILES = [
    ".well-known/agent.json",
    ".well-known/agent-card.json",
    "agent.json",
    "agent-card.json",
    "a2a/agent.json",
]
A2A_CONFIG_FILES = ["a2a.json", "a2a.yaml", "a2a.yml", "a2a_config.json"]
A2A_SOURCE_BINDING_PROFILE = "nexus-symbiote/a2a-static-values/v1"
A2A_SOURCE_BINDING_FIELDS = (
    "a2a_source_binding",
    "a2a_source_binding_key_id",
    "a2a_source_binding_profile",
)
A2A_STATIC_MODES = {"static-agent-card", "static-config"}


def has_a2a_source_binding(component: A2AClientComponent | A2AServerComponent) -> bool:
    properties = component.properties
    return (
        properties.get("a2a_source_binding_profile") == A2A_SOURCE_BINDING_PROFILE
        and isinstance(properties.get("a2a_source_binding"), str)
        and re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", properties["a2a_source_binding"]) is not None
        and isinstance(properties.get("a2a_source_binding_key_id"), str)
        and re.fullmatch(r"[0-9a-f]{32}", properties["a2a_source_binding_key_id"]) is not None
    )


def _source_binding(data: dict[str, Any], kind: str) -> dict[str, Any]:
    binding = bind_source_values(
        {"kind": kind, "declaration": data}, profile=A2A_SOURCE_BINDING_PROFILE
    )
    return {
        "a2a_source_binding_profile": A2A_SOURCE_BINDING_PROFILE,
        **(
            {"a2a_source_binding": binding[0], "a2a_source_binding_key_id": binding[1]}
            if binding
            else {}
        ),
    }


def _authentication_required(
    data: dict[str, Any], v1_requirements: list[dict[str, list[str]]] | None
) -> bool | None:
    """Combine every declared requirement form; any form permitting anonymous use wins."""
    declared: list[bool | None] = []
    if "security" in data:
        requirements = data["security"]
        if not isinstance(requirements, list) or len(requirements) > 1000:
            raise ValueError("invalid security requirements")
        for requirement in requirements:
            if not isinstance(requirement, dict):
                raise ValueError("invalid security requirement")
            for scopes in requirement.values():
                if not isinstance(scopes, list):
                    raise ValueError("invalid security scopes")
                _strings(scopes)
        # Requirements are OR alternatives; an empty alternative permits anonymous use.
        declared.append(bool(requirements) and all(bool(item) for item in requirements))
    if v1_requirements is not None:
        declared.append(bool(v1_requirements) and all(v1_requirements))
    authentication = data.get("authentication")
    if authentication is not None:
        if not isinstance(authentication, dict):
            raise ValueError("invalid legacy authentication")
        if "schemes" in authentication:
            declared.append(bool(_strings(authentication["schemes"])))
        else:
            declared.append(None if authentication else False)
    # A client may use any declared form, so one anonymous form makes authentication
    # optional; an unsupported form leaves the requirement unknown.
    if not declared or False in declared:
        return False
    return None if None in declared else True


def _strings(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if (
        not isinstance(value, list)
        or len(value) > 1000
        or not all(isinstance(item, str) for item in value)
    ):
        raise ValueError("invalid string-list declaration")
    return [redact_text(item) for item in value]


def _proto_fields(data: dict[str, Any], *names: str) -> dict[str, Any]:
    """Accept both ProtoJSON field spellings and reject ambiguous duplicates."""
    normalized = data.copy()
    for name in names:
        snake = re.sub(r"(?=[A-Z])", "_", name).lower()
        if snake in data:
            if name in data:
                raise ValueError("duplicate A2A protocol field")
            normalized[name] = normalized.pop(snake)
    return normalized


def _interfaces(value: Any) -> list[dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(value) <= 1000:
        raise ValueError("invalid supportedInterfaces")
    interfaces = []
    for item in value:
        if not isinstance(item, dict):
            raise ValueError("invalid A2A interface")
        item = _proto_fields(item, "protocolBinding", "protocolVersion")
        url, binding, version = (
            item.get("url"),
            item.get("protocolBinding"),
            item.get("protocolVersion"),
        )
        if not isinstance(url, str) or not isinstance(binding, str) or not binding.strip():
            raise ValueError("invalid A2A interface URL or binding")
        if not isinstance(version, str) or not re.fullmatch(
            r"[0-9]+\.[0-9]+(?:\.[0-9]+)?", version
        ):
            raise ValueError("invalid A2A interface protocol version")
        origin = sanitized_origin(url)
        if origin == "[redacted]" or any(char.isspace() or ord(char) < 32 for char in url):
            raise ValueError("invalid A2A interface origin")
        # Paths, userinfo, queries, fragments and opaque tenant routing values
        # can contain credentials. Compare only the exported origins and bindings.
        interfaces.append(
            {
                "origin": origin,
                "protocol_binding": redact_text(binding),
                "protocol_version": version,
            }
        )
    return interfaces


def _security_requirements(value: Any) -> list[dict[str, list[str]]]:
    """Collect v1 SecurityRequirement.schemes, whose scope values are StringList objects."""
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("invalid security requirements")
    requirements = []
    for requirement in value:
        if not isinstance(requirement, dict) or requirement.keys() - {"schemes"}:
            raise ValueError("invalid security requirement")
        schemes = requirement.get("schemes", {})
        if not isinstance(schemes, dict) or len(schemes) > 1000:
            raise ValueError("invalid security schemes")
        alternative = {}
        for name, scope_list in schemes.items():
            if not name or not isinstance(scope_list, dict) or scope_list.keys() - {"list"}:
                raise ValueError("invalid named security requirement")
            scopes = scope_list.get("list", [])
            if not isinstance(scopes, list):
                raise ValueError("invalid scope list")
            safe_name = redact_text(name)
            if safe_name in alternative:
                raise ValueError("ambiguous redacted security scheme")
            alternative[safe_name] = sorted(set(_strings(scopes)))
        requirements.append(alternative)
    return sorted(requirements, key=canonical_json)


class A2AScanner(Scanner):
    name = "a2a"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        with self._collection(project_root, result) as files:
            for relative in AGENT_CARD_FILES:
                path = files.root / relative
                data = self._read_mapping(path, result)
                if data is None:
                    continue
                result.surfaces_scanned.append(str(path))
                try:
                    component = self._parse_agent_card(data, relative, path)
                    result.components.append(component)
                    self._record_binding_gap(component, relative, result)
                except (TypeError, ValueError):
                    result.scan_failures.append(f"{relative}: invalid A2A card field types")
            for relative in A2A_CONFIG_FILES:
                path = files.root / relative
                data = self._read_mapping(path, result)
                if data is None:
                    continue
                result.surfaces_scanned.append(str(path))
                clients = data.get("clients", data.get("remoteAgents", []))
                if not isinstance(clients, list) or len(clients) > 1000:
                    result.scan_failures.append(f"{relative}: invalid or oversized A2A client list")
                    continue
                for client in clients:
                    try:
                        if not isinstance(client, dict):
                            raise ValueError("invalid client")
                        client_component = self._parse_a2a_client(client, path)
                        result.components.append(client_component)
                        self._record_binding_gap(client_component, relative, result)
                    except (TypeError, ValueError):
                        result.scan_failures.append(f"{relative}: invalid A2A client field types")
            self._scan_code_patterns(files.root, result)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("a2a (no A2A configurations found)")
        return result

    @staticmethod
    def _record_binding_gap(
        component: A2AClientComponent | A2AServerComponent, relative: str, result: ScanResult
    ) -> None:
        if not has_a2a_source_binding(component):
            result.surfaces_excluded.append(
                f"{relative}: A2A declaration values are unbound; configure "
                f"{SOURCE_BINDING_KEY_ENV} before relying on drift or reconciliation"
            )
        if isinstance(component, A2AServerComponent) and component.authentication_required is None:
            result.surfaces_excluded.append(
                f"{relative}: A2A authentication requirement semantics are unknown"
            )

    def _parse_agent_card(
        self, data: dict[str, Any], rel_path: str, card_path: Path
    ) -> A2AServerComponent:
        declaration = data
        data = _proto_fields(data, "supportedInterfaces", "securityRequirements")
        name, version = data.get("name", "unnamed-agent"), data.get("version")
        endpoint = data.get("url") or data.get("endpoint")
        if (
            not isinstance(name, str)
            or (version is not None and not isinstance(version, str))
            or (endpoint is not None and not isinstance(endpoint, str))
        ):
            raise ValueError("invalid card identity")
        name = redact_text(name)
        protocols = _strings(data.get("protocols", []))
        properties: dict[str, Any] = {
            "collection_mode": "static-agent-card",
            "authentication_evidence": "declaration-only",
        }
        origins = [sanitized_origin(endpoint)] if endpoint else []
        if "supportedInterfaces" in data:
            interfaces = _interfaces(data["supportedInterfaces"])
            properties["supported_interfaces"] = interfaces
            origins = [item["origin"] for item in interfaces]
            protocols = list(dict.fromkeys(item["protocol_binding"] for item in interfaces))
        declared_skills = data.get("skills", [])
        if not isinstance(declared_skills, list) or len(declared_skills) > 1000:
            raise ValueError("invalid skills")
        skills = []
        for skill in declared_skills:
            if isinstance(skill, dict):
                skill = _proto_fields(skill, "securityRequirements")
                if "securityRequirements" in skill:
                    skill_id = skill.get("id")
                    if not isinstance(skill_id, str) or not skill_id:
                        raise ValueError("missing skill identifier for security requirements")
                    declarations = properties.setdefault("skill_security_requirements", {})
                    safe_id = redact_text(skill_id)
                    if safe_id in declarations:
                        raise ValueError("duplicate skill security identifier")
                    declarations[safe_id] = _security_requirements(skill["securityRequirements"])
                skill = skill.get("name", skill.get("id", "unknown"))
            if not isinstance(skill, str):
                raise ValueError("invalid skill name")
            skills.append(redact_text(skill))
        # This records declarations only; neither a card nor this collector proves
        # that an endpoint actually enforces authentication.
        requirements = None
        if "securityRequirements" in data:
            requirements = _security_requirements(data["securityRequirements"])
            properties["security_requirements"] = requirements
        auth_required = _authentication_required(data, requirements)
        risks: list[RiskAssessment] = []
        if any(not origin.startswith("https://") for origin in origins):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A agent '{name}' declares an endpoint without HTTPS.",
                    recommendation="Use authenticated HTTPS transport for agent endpoints.",
                )
            )
        if not auth_required:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A agent '{name}' does not declare mandatory authentication for all access alternatives.",
                    recommendation="Declare and independently verify endpoint authentication requirements.",
                )
            )
        if not skills:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.LOW,
                    category="completeness",
                    detail=f"A2A agent '{name}' declares no skills in its agent card.",
                    recommendation="Document declared skills and separately verify effective capabilities.",
                )
            )
        return A2AServerComponent(
            bom_ref=f"a2a-server:{name}",
            name=name,
            version=redact_text(version) if version else None,
            agent_card_path=rel_path,
            endpoint_url=origins[0] if origins else None,
            supported_protocols=protocols,
            skills_declared=skills,
            authentication_required=auth_required,
            source_path=str(card_path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
            properties={**properties, **_source_binding(declaration, "agent-card")},
        )

    def _parse_a2a_client(self, config: dict[str, Any], config_path: Path) -> A2AClientComponent:
        name = config.get("name", config.get("agentName", "unnamed-client"))
        card_url = config.get("agentCardUrl", config.get("url", config.get("endpoint")))
        auth_methods = config.get("authMethods", config.get("authentication", []))
        if isinstance(auth_methods, dict):
            auth_methods = list(auth_methods)
        auth_methods = _strings(auth_methods)
        if not isinstance(name, str) or (card_url is not None and not isinstance(card_url, str)):
            raise ValueError("invalid client identity")
        name = redact_text(name)
        risks = []
        if card_url and not card_url.lower().startswith("https://"):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A client '{name}' declares an insecure endpoint transport.",
                    recommendation="Use authenticated HTTPS for agent card retrieval.",
                )
            )
        if not auth_methods:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A client '{name}' has no authentication method declared.",
                    recommendation="Configure and independently verify remote-agent authentication.",
                )
            )
        return A2AClientComponent(
            bom_ref=f"a2a-client:{name}",
            name=name,
            agent_card_url=sanitized_origin(card_url) if card_url else None,
            authentication_methods=auth_methods,
            source_path=str(config_path),
            trust_tier=TrustTier.UNKNOWN,
            risks=risks,
            properties={
                "collection_mode": "static-config",
                "remote_agent_contacted": False,
                **_source_binding(config, "client"),
            },
        )

    def _scan_code_patterns(self, root: Path, result: ScanResult) -> None:
        if self._files is None:
            raise RuntimeError("_scan_code_patterns called outside a _collection context")
        sources = [
            path
            for path in self._files.iter_files()
            if path.suffix == ".py"
            and (len(path.parts) == 1 or (len(path.parts) == 2 and path.parts[0] == "src"))
        ]
        if len(sources) > 20:
            result.scan_failures.append("a2a code references: 20-file collection limit exceeded")
        for path in sources[:20]:
            content = self._files.read_text(path)
            if content is None:
                continue
            result.surfaces_scanned.append(str(root / path))
            if len(content) > 262_144:
                result.scan_failures.append(f"{path}: syntax collection size limit exceeded")
                continue
            try:
                tree = ast.parse(content)
            except (SyntaxError, ValueError, RecursionError):
                result.scan_failures.append(f"{path}: invalid Python syntax")
                continue
            detected = any(
                (
                    isinstance(node, ast.ImportFrom)
                    and node.module is not None
                    and node.module.split(".")[0] == "a2a"
                )
                or (
                    isinstance(node, ast.Import)
                    and any(alias.name.split(".")[0] == "a2a" for alias in node.names)
                )
                or (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Name)
                    and node.func.id in {"A2AClient", "AgentCard"}
                )
                for node in ast.walk(tree)
            )
            if detected and not any(
                component.bom_ref.startswith("a2a-") for component in result.components
            ):
                result.components.append(
                    A2AClientComponent(
                        bom_ref="a2a-client:code-detected",
                        name="a2a-client (code-detected)",
                        source_path=str(root / path),
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        properties={"collection_mode": "static-syntax-reference"},
                        risks=[
                            RiskAssessment(
                                severity=RiskSeverity.INFO,
                                category="detection_method",
                                detail="A2A SDK reference detected in Python syntax; deployment not verified.",
                                recommendation="Add explicit client configuration and deployment evidence.",
                            )
                        ],
                    )
                )
