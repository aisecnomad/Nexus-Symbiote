"""Bounded offline A2A card, client configuration and SDK-reference collection."""

from __future__ import annotations

import ast
import ipaddress
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import (
    SOURCE_BINDING_KEY_ENV,
    SourceBindingKeyError,
    SourceBindingValueError,
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
A2A_CLIENT_LISTS = ("clients", "remoteAgents")
A2A_SOURCE_BINDING_PROFILE = "nexus-symbiote/a2a-static-values/v1"
A2A_SOURCE_BINDING_FIELDS = (
    "a2a_source_binding",
    "a2a_source_binding_key_id",
    "a2a_source_binding_profile",
)
A2A_STATIC_MODES = {"static-agent-card", "static-config"}
UNRECOGNIZED_AUTHENTICATION = "[unrecognized]"

_KEY_FAILURE = (
    f"{SOURCE_BINDING_KEY_ENV} is not valid random key material; A2A declarations were not bound"
)
_ANONYMOUS_SCHEMES = frozenset({"", "none", "public", "anonymous", "noauth", "unauthenticated"})
_CLIENT_SCHEMES = frozenset(
    {"bearer", "basic", "digest", "apikey", "oauth2", "openidconnect", "oidc", "mutualtls", "mtls"}
)
_SCHEME_TYPES = frozenset({"apiKey", "http", "oauth2", "openIdConnect", "mutualTLS"})
_SCHEME_VARIANTS = {
    "apiKeySecurityScheme": "apiKey",
    "api_key_security_scheme": "apiKey",
    "httpAuthSecurityScheme": "http",
    "http_auth_security_scheme": "http",
    "oauth2SecurityScheme": "oauth2",
    "oauth2_security_scheme": "oauth2",
    "openIdConnectSecurityScheme": "openIdConnect",
    "open_id_connect_security_scheme": "openIdConnect",
    "mtlsSecurityScheme": "mutualTLS",
    "mtls_security_scheme": "mutualTLS",
}
_HOST_LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
_HOSTNAME = re.compile(rf"{_HOST_LABEL}(?:\.{_HOST_LABEL})*")

Requirements = list[dict[str, list[str]]]


def has_a2a_source_binding(component: A2AClientComponent | A2AServerComponent) -> bool:
    properties = component.properties
    return (
        properties.get("a2a_source_binding_profile") == A2A_SOURCE_BINDING_PROFILE
        and isinstance(properties.get("a2a_source_binding"), str)
        and re.fullmatch(r"hmac-sha256:[0-9a-f]{64}", properties["a2a_source_binding"]) is not None
        and isinstance(properties.get("a2a_source_binding_key_id"), str)
        and re.fullmatch(r"[0-9a-f]{32}", properties["a2a_source_binding_key_id"]) is not None
    )


def _scheme_token(value: str) -> str:
    return re.sub(r"[\s_-]+", "", value).lower()


def _anonymous(scheme: str) -> bool:
    return _scheme_token(scheme) in _ANONYMOUS_SCHEMES


def _string_list(value: Any) -> list[str] | None:
    if not isinstance(value, list) or len(value) > 1000:
        return None
    if not all(isinstance(item, str) for item in value):
        return None
    return list(value)


def _v03_requirements(value: Any) -> Requirements | None:
    """Return A2A 0.3 OR-alternatives of AND-ed scheme names, or None for another shape."""
    if not isinstance(value, list) or len(value) > 1000:
        return None
    alternatives: Requirements = []
    for requirement in value:
        if not isinstance(requirement, dict) or len(requirement) > 1000:
            return None
        alternative: dict[str, list[str]] = {}
        for name, scopes in requirement.items():
            scope_list = _string_list(scopes)
            if not isinstance(name, str) or scope_list is None:
                return None
            alternative[name] = scope_list
        alternatives.append(alternative)
    return alternatives


def _supported_scheme(definition: Any) -> bool:
    """Accept A2A 0.3 typed or v1 ProtoJSON scheme definitions that require credentials."""
    if not isinstance(definition, dict):
        return False
    kind = definition.get("type")
    if kind is None:
        variants = [key for key in definition if key in _SCHEME_VARIANTS]
        if len(variants) != 1 or not isinstance(definition[variants[0]], dict):
            return False
        kind = _SCHEME_VARIANTS[variants[0]]
        definition = definition[variants[0]]
    if not isinstance(kind, str) or kind not in _SCHEME_TYPES:
        return False
    if kind == "http":
        scheme = definition.get("scheme")
        return isinstance(scheme, str) and not _anonymous(scheme)
    return True


def _requirement_semantics(alternatives: Requirements, schemes: Any) -> bool | None:
    """Requirements are OR alternatives; an empty alternative permits anonymous use."""
    if not alternatives or not all(alternatives):
        return False
    if isinstance(schemes, dict) and all(
        _supported_scheme(schemes.get(name)) for alternative in alternatives for name in alternative
    ):
        return True
    # An undeclared, anonymous or unsupported scheme definition has unknown semantics.
    return None


def _legacy_authentication(value: Any) -> bool | None:
    """Interpret pre-0.3 AgentAuthentication; anonymous scheme names permit anonymous use."""
    if not isinstance(value, dict):
        return None
    schemes = value.get("schemes")
    if schemes is None:
        return None if any(item is not None for item in value.values()) else False
    schemes = _string_list([schemes] if isinstance(schemes, str) else schemes)
    if schemes is None:
        return None
    return bool(schemes) and not any(_anonymous(scheme) for scheme in schemes)


def _authentication_required(
    data: dict[str, Any], v1_requirements: Requirements | None
) -> bool | None:
    """Combine the card-level requirement forms; any form permitting anonymous use wins."""
    declared: list[bool | None] = []
    if data.get("security") is not None:
        alternatives = _v03_requirements(data["security"])
        declared.append(
            None
            if alternatives is None
            else _requirement_semantics(alternatives, data.get("securitySchemes"))
        )
    if v1_requirements is not None:
        declared.append(_requirement_semantics(v1_requirements, data.get("securitySchemes")))
    if data.get("authentication") is not None:
        declared.append(_legacy_authentication(data["authentication"]))
    # A client may use any declared form, so one anonymous form makes authentication
    # optional; an unsupported form leaves the requirement unknown. A card that declares
    # no card-level form requires nothing. Skill-level forms only add requirements for a
    # skill: the card-level requirement applies to every request (A2A 0.3 section 4.4).
    combined = declared or [False]
    if False in combined:
        return False
    return None if None in combined else True


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


def _redacted(alternatives: Requirements) -> Requirements:
    """Redact requirement names and scopes for export, rejecting ambiguous redactions."""
    records = []
    for alternative in alternatives:
        record: dict[str, list[str]] = {}
        for name, scopes in alternative.items():
            safe_name = redact_text(name)
            if safe_name in record:
                raise ValueError("ambiguous redacted security scheme")
            record[safe_name] = sorted({redact_text(scope) for scope in scopes})
        records.append(record)
    return records


def _canonical(alternatives: Requirements) -> Requirements:
    return sorted(
        {canonical_json(item): item for item in alternatives}.values(), key=canonical_json
    )


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


def _grpc_authority(address: str) -> str:
    """Accept the authority-only ``host:port`` form that A2A v1 specifies for gRPC."""
    try:
        parsed = urlsplit("//" + address)
        port = parsed.port
    except ValueError:
        raise ValueError("invalid gRPC address") from None
    host = parsed.hostname
    if parsed.netloc != address or "@" in address or not host or not port:
        raise ValueError("invalid gRPC address")
    if ":" in host:
        host = f"[{ipaddress.IPv6Address(host)}]"
    elif len(host) > 253 or not _HOSTNAME.fullmatch(host):
        raise ValueError("invalid gRPC host")
    return f"grpc://{host}:{port}"


def _interface(url: str, binding: str, field: str) -> dict[str, str]:
    """Return the exported origin and binding of an interface URL."""
    # urlsplit silently drops tabs and line breaks, which would record another host.
    if any(char.isspace() or not char.isprintable() for char in url):
        raise ValueError("invalid A2A interface URL")
    if binding.strip().upper() == "GRPC" and "://" not in url:
        # The address does not say whether the channel uses TLS. Unlike an explicit
        # grpc:// URL, which declares plaintext, it is exported as undeclared.
        return {"origin": _grpc_authority(url), field: redact_text(binding), "tls": "undeclared"}
    return {"origin": sanitized_origin(url), field: redact_text(binding)}


def _transport_security(interface: dict[str, str]) -> bool | None:
    if interface.get("tls") == "undeclared":
        return None
    scheme = interface["origin"].partition("://")[0]
    binding = interface.get("protocol_binding", interface.get("transport", ""))
    # grpcs:// is the gRPC convention for TLS. An HTTP binding needs an https:// URL.
    return scheme == "https" or (scheme == "grpcs" and binding.strip().upper() == "GRPC")


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
        interface = _interface(url, binding, "protocol_binding")
        if interface["origin"] == "[redacted]":
            raise ValueError("invalid A2A interface origin")
        # Paths, userinfo, queries, fragments and opaque tenant routing values
        # can contain credentials. Compare only the exported origins and bindings.
        interfaces.append({**interface, "protocol_version": version})
    return interfaces


def _legacy_interfaces(data: dict[str, Any], endpoint: str | None) -> list[dict[str, str]]:
    """Origins of the A2A 0.3 url and additionalInterfaces, which 0.3 clients route on."""
    declared: list[Any] = []
    if endpoint:
        transport = data.get("preferredTransport") or "JSONRPC"
        declared.append({"url": endpoint, "transport": transport})
    additional = data.get("additionalInterfaces")
    if additional is not None:
        if not isinstance(additional, list) or len(additional) > 1000:
            raise ValueError("invalid additionalInterfaces")
        declared.extend(additional)
    interfaces = []
    for item in declared:
        if not isinstance(item, dict):
            raise ValueError("invalid A2A interface")
        url, transport = item.get("url"), item.get("transport")
        if not isinstance(url, str) or not isinstance(transport, str) or not transport.strip():
            raise ValueError("invalid A2A interface URL or transport")
        interfaces.append(_interface(url, transport, "transport"))
    return interfaces


def _v1_requirements(value: Any) -> Requirements:
    """Parse v1 SecurityRequirement.schemes, whose scope values are StringList objects."""
    if not isinstance(value, list) or len(value) > 1000:
        raise ValueError("invalid security requirements")
    alternatives: Requirements = []
    for requirement in value:
        if not isinstance(requirement, dict) or requirement.keys() - {"schemes"}:
            raise ValueError("invalid security requirement")
        schemes = requirement.get("schemes", {})
        if not isinstance(schemes, dict) or len(schemes) > 1000:
            raise ValueError("invalid security schemes")
        alternative: dict[str, list[str]] = {}
        for name, scope_list in schemes.items():
            if not name or not isinstance(scope_list, dict) or scope_list.keys() - {"list"}:
                raise ValueError("invalid named security requirement")
            scopes = _string_list(scope_list.get("list", []))
            if scopes is None:
                raise ValueError("invalid scope list")
            alternative[name] = scopes
        alternatives.append(alternative)
    return alternatives


def _skill_security(
    skill: dict[str, Any], schemes: Any
) -> tuple[list[bool | None], Requirements | None]:
    """Evaluate and record a skill's A2A 0.3 security and v1 securityRequirements."""
    semantics: list[bool | None] = []
    recorded: Requirements | None = None
    if skill.get("security") is not None:
        alternatives = _v03_requirements(skill["security"])
        if alternatives is None:
            semantics.append(None)
        else:
            semantics.append(_requirement_semantics(alternatives, schemes))
            recorded = _canonical(_redacted(alternatives))
    if skill.get("securityRequirements") is not None:
        requirements = _v1_requirements(skill["securityRequirements"])
        semantics.append(_requirement_semantics(requirements, schemes))
        recorded = _canonical([*(recorded or []), *_redacted(requirements)])
    return semantics, recorded


def _client_method(item: Any) -> str:
    if (
        isinstance(item, str)
        and len(item) <= 64
        and item.isascii()
        and _scheme_token(item) in _CLIENT_SCHEMES | _ANONYMOUS_SCHEMES
    ):
        return item
    return UNRECOGNIZED_AUTHENTICATION


def _client_authentication(config: dict[str, Any]) -> list[str]:
    """Export only allowlisted scheme identifiers; credentials stay in the keyed input."""
    declared: list[Any] = []
    for field in ("authMethods", "authentication"):
        value = config.get(field)
        if isinstance(value, dict):
            schemes = value.get("schemes")
            value = [key for key in value if key != "schemes"] if schemes is None else schemes
        if isinstance(value, str):
            value = [value]
        if isinstance(value, list) and len(value) <= 1000:
            declared.extend(value)
        elif value is not None:
            declared.append(None)
    return list(dict.fromkeys(_client_method(item) for item in declared))


def _failure(relative: str, label: str, error: Exception) -> str:
    if isinstance(error, SourceBindingValueError):
        return f"{relative}: A2A declaration cannot be canonicalized for binding"
    return f"{relative}: invalid A2A {label} field types"


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
                    binding = self._source_binding(data, "agent-card", result)
                    component = self._parse_agent_card(data, relative, path, binding)
                except (TypeError, ValueError, RecursionError) as error:
                    result.scan_failures.append(_failure(relative, "card", error))
                    continue
                result.components.append(component)
                self._record_binding_gap(component, relative, result)
            for relative in A2A_CONFIG_FILES:
                path = files.root / relative
                data = self._read_mapping(path, result)
                if data is None:
                    continue
                result.surfaces_scanned.append(str(path))
                if any(
                    value is not None for key, value in data.items() if key not in A2A_CLIENT_LISTS
                ):
                    result.surfaces_excluded.append(
                        f"{relative}: unrecognized A2A client configuration fields "
                        "are unknown coverage"
                    )
                for field in A2A_CLIENT_LISTS:
                    clients = data.get(field)
                    if clients is None:
                        continue
                    if not isinstance(clients, list) or len(clients) > 1000:
                        result.scan_failures.append(
                            f"{relative}: invalid or oversized A2A client list"
                        )
                        continue
                    for client in clients:
                        try:
                            if not isinstance(client, dict):
                                raise ValueError("invalid client")
                            binding = self._source_binding(client, "client", result)
                            client_component = self._parse_a2a_client(client, path, binding)
                        except (TypeError, ValueError, RecursionError) as error:
                            result.scan_failures.append(_failure(relative, "client", error))
                            continue
                        result.components.append(client_component)
                        self._record_binding_gap(client_component, relative, result)
            self._scan_code_patterns(files.root, result)
        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("a2a (no A2A configurations found)")
        return result

    @staticmethod
    def _source_binding(
        declaration: dict[str, Any], kind: str, result: ScanResult
    ) -> dict[str, Any]:
        properties: dict[str, Any] = {"a2a_source_binding_profile": A2A_SOURCE_BINDING_PROFILE}
        try:
            binding = bind_source_values(
                {"kind": kind, "declaration": declaration}, profile=A2A_SOURCE_BINDING_PROFILE
            )
        except SourceBindingKeyError:
            # A configuration error, not a property of this declaration: report it once
            # and keep the inventory, which stays partial coverage without a binding.
            if _KEY_FAILURE not in result.scan_failures:
                result.scan_failures.append(_KEY_FAILURE)
            return properties
        if binding is not None:
            properties["a2a_source_binding"], properties["a2a_source_binding_key_id"] = binding
        return properties

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
        if isinstance(component, A2AServerComponent) and component.properties.get(
            "skill_security_unknown"
        ):
            result.surfaces_excluded.append(
                f"{relative}: A2A skill security requirement semantics are unknown"
            )
        if (
            isinstance(component, A2AClientComponent)
            and UNRECOGNIZED_AUTHENTICATION in component.authentication_methods
        ):
            result.surfaces_excluded.append(
                f"{relative}: A2A client authentication semantics are unknown"
            )

    def _parse_agent_card(
        self, data: dict[str, Any], rel_path: str, card_path: Path, binding: dict[str, Any]
    ) -> A2AServerComponent:
        # a2a-python 0.3 accepts field names as well as aliases and routes on either
        # spelling of preferredTransport and additionalInterfaces.
        data = _proto_fields(
            data,
            "supportedInterfaces",
            "securityRequirements",
            "securitySchemes",
            "additionalInterfaces",
            "preferredTransport",
        )
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
        # A2A 0.3 clients route on url and additionalInterfaces even when a card also
        # declares v1 supportedInterfaces, so their origins stay recorded and checked.
        legacy = _legacy_interfaces(data, endpoint)
        declared = list(legacy)
        endpoint_url = legacy[0]["origin"] if endpoint else None
        if "supportedInterfaces" in data:
            interfaces = _interfaces(data["supportedInterfaces"])
            properties["supported_interfaces"] = interfaces
            endpoint_url = interfaces[0]["origin"]
            declared = [*interfaces, *declared]
            protocols = list(dict.fromkeys(item["protocol_binding"] for item in interfaces))
        if legacy:
            properties["legacy_interfaces"] = legacy
        declared_skills = data.get("skills", [])
        if not isinstance(declared_skills, list) or len(declared_skills) > 1000:
            raise ValueError("invalid skills")
        skills = []
        unknown_skills: list[str] = []
        for skill in declared_skills:
            if isinstance(skill, dict):
                skill = _proto_fields(skill, "securityRequirements")
                semantics, requirements = _skill_security(skill, data.get("securitySchemes"))
                if None in semantics:
                    unknown_skills.append(redact_text(str(skill.get("id", "unknown"))))
                if requirements is not None:
                    skill_id = skill.get("id")
                    if not isinstance(skill_id, str) or not skill_id:
                        raise ValueError("missing skill identifier for security requirements")
                    declarations = properties.setdefault("skill_security_requirements", {})
                    safe_id = redact_text(skill_id)
                    if safe_id in declarations:
                        raise ValueError("duplicate skill security identifier")
                    declarations[safe_id] = requirements
                skill = skill.get("name", skill.get("id", "unknown"))
            if not isinstance(skill, str):
                raise ValueError("invalid skill name")
            skills.append(redact_text(skill))
        # This records declarations only; neither a card nor this collector proves
        # that an endpoint actually enforces authentication.
        requirements = None
        if data.get("securityRequirements") is not None:
            requirements = _v1_requirements(data["securityRequirements"])
            properties["security_requirements"] = _canonical(_redacted(requirements))
        auth_required = _authentication_required(data, requirements)
        if unknown_skills:
            properties["skill_security_unknown"] = sorted(set(unknown_skills))
        risks: list[RiskAssessment] = []
        transport = [_transport_security(interface) for interface in declared]
        if False in transport:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="transport_security",
                    detail=f"A2A agent '{name}' declares an endpoint without HTTPS.",
                    recommendation="Use authenticated HTTPS transport for agent endpoints.",
                )
            )
        elif None in transport:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="transport_security",
                    detail=f"A2A agent '{name}' declares a gRPC address without declaring TLS.",
                    recommendation="Declare a TLS endpoint and verify the channel independently.",
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
            endpoint_url=endpoint_url,
            supported_protocols=protocols,
            skills_declared=skills,
            authentication_required=auth_required,
            source_path=str(card_path),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
            properties={**properties, **binding},
        )

    def _parse_a2a_client(
        self, config: dict[str, Any], config_path: Path, binding: dict[str, Any]
    ) -> A2AClientComponent:
        name = config.get("name", config.get("agentName", "unnamed-client"))
        card_url = config.get("agentCardUrl", config.get("url", config.get("endpoint")))
        if not isinstance(name, str) or (card_url is not None and not isinstance(card_url, str)):
            raise ValueError("invalid client identity")
        name = redact_text(name)
        auth_methods = _client_authentication(config)
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
        # Every declared method is an alternative the client may use, so an anonymous or
        # unrecognized one means authentication is not established as mandatory.
        if not auth_methods or any(
            method == UNRECOGNIZED_AUTHENTICATION or _anonymous(method) for method in auth_methods
        ):
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="authentication",
                    detail=f"A2A client '{name}' does not declare a mandatory, recognized authentication method.",
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
                **binding,
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
