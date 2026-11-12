"""Bounded offline A2A card, client configuration and SDK-reference collection."""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Any

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.models import A2AClientComponent, A2AServerComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult, parse_python, sanitized_origin
from nexus_symbiote.utils.secrets import redact_text

AGENT_CARD_FILES = [
    ".well-known/agent.json",
    ".well-known/agent-card.json",
    "agent.json",
    "agent-card.json",
    "a2a/agent.json",
]
A2A_CONFIG_FILES = ["a2a.json", "a2a.yaml", "a2a.yml", "a2a_config.json"]


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


def _authentication_required(data: dict[str, Any]) -> bool:
    if "security" in data:
        requirements = data["security"]
        if not isinstance(requirements, list) or len(requirements) > 1000:
            raise ValueError("invalid security requirements")
        for requirement in requirements:
            if not isinstance(requirement, dict) or len(requirement) > 1000:
                raise ValueError("invalid security requirement")
            for name, scopes in requirement.items():
                if (
                    not isinstance(name, str)
                    or not name.strip()
                    or not isinstance(scopes, list)
                    or len(scopes) > 1000
                    or not all(isinstance(scope, str) and scope.strip() for scope in scopes)
                ):
                    raise ValueError("invalid security scheme requirement")
        # A2A's OpenAPI requirements are OR alternatives. An empty object allows
        # an anonymous request, even when other alternatives require credentials.
        return bool(requirements) and all(requirements)
    authentication = data.get("authentication")
    if authentication is None:
        return False
    if not isinstance(authentication, dict):
        raise ValueError("invalid legacy authentication declaration")
    schemes = authentication.get("schemes")
    if (
        not isinstance(schemes, list)
        or len(schemes) > 1000
        or not all(isinstance(scheme, str) and scheme.strip() for scheme in schemes)
    ):
        raise ValueError("invalid legacy authentication schemes")
    return bool(schemes)


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
                    result.components.append(self._parse_agent_card(data, relative, path))
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
                        result.components.append(self._parse_a2a_client(client, path))
                    except (TypeError, ValueError):
                        result.scan_failures.append(f"{relative}: invalid A2A client field types")
            self._scan_code_patterns(files.root, result)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("a2a (no A2A configurations found)")
        return result

    def _parse_agent_card(
        self, data: dict[str, Any], rel_path: str, card_path: Path
    ) -> A2AServerComponent:
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
        auth_required = _authentication_required(data)
        declared_skills = data.get("skills", [])
        if not isinstance(declared_skills, list) or len(declared_skills) > 1000:
            raise ValueError("invalid skills")
        skills = []
        for skill in declared_skills:
            if isinstance(skill, dict):
                skill = skill.get("name", skill.get("id", "unknown"))
            if not isinstance(skill, str):
                raise ValueError("invalid skill name")
            skills.append(redact_text(skill))
        # This records declarations only; neither a card nor this collector proves
        # that an endpoint actually enforces authentication.
        risks: list[RiskAssessment] = []
        if endpoint and not endpoint.lower().startswith("https://"):
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
                    detail=f"A2A agent '{name}' does not declare authentication as required for every alternative.",
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
            endpoint_url=sanitized_origin(endpoint) if endpoint else None,
            supported_protocols=protocols,
            skills_declared=skills,
            authentication_required=auth_required,
            source_path=str(card_path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
            properties={
                "collection_mode": "static-agent-card",
                "authentication_evidence": "declaration-only",
            },
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
            properties={"collection_mode": "static-config", "remote_agent_contacted": False},
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
                tree = parse_python(content)
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
