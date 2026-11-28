"""Risk classes: what one component's recorded evidence says it may do.

``classify`` restates fields an inventory records as up to five classes (code-exec,
write-capable, exfil-capable, network-egress, secret-access), each with the field and
value that produced it. The evidence is mostly declared, or inferred by a collector from tool
names and descriptions or from the calls a source-declared tool body names (a tool's
``capability_evidence`` property says which). A class
therefore does not establish what a component can do at run time, and no class does not
establish that it cannot. A component whose record holds nothing these rules read is
unassessed: unknown, not safe. Nothing here is written to the inventory.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from enum import StrEnum
from urllib.parse import urlsplit

from nexus_symbiote.core.enums import CapabilityClass, SerializationSafety, SideEffectProfile
from nexus_symbiote.core.models import (
    AnyComponent,
    CapabilityDeclaration,
    IDEAgentComponent,
    MCPServerComponent,
    ModelComponent,
)


class RiskClass(StrEnum):
    CODE_EXEC = "code-exec"
    EXFIL_CAPABLE = "exfil-capable"
    NETWORK_EGRESS = "network-egress"
    SECRET_ACCESS = "secret-access"  # noqa: S105 - a class name, not a credential
    WRITE_CAPABLE = "write-capable"


@dataclass(frozen=True)
class RiskClassification:
    """Sorted classes, the sorted evidence that produced them, and whether any was read."""

    classes: tuple[RiskClass, ...]
    basis: tuple[str, ...]
    assessed: bool


_DECLARED: dict[CapabilityClass, RiskClass] = {
    CapabilityClass.EXECUTE: RiskClass.CODE_EXEC,
    CapabilityClass.WRITE: RiskClass.WRITE_CAPABLE,
    CapabilityClass.DESTRUCTIVE: RiskClass.WRITE_CAPABLE,
    CapabilityClass.PAYMENT: RiskClass.WRITE_CAPABLE,
    CapabilityClass.NETWORK: RiskClass.NETWORK_EGRESS,
    CapabilityClass.CREDENTIALS: RiskClass.SECRET_ACCESS,
}
_SIDE_EFFECTS: dict[SideEffectProfile, RiskClass] = {
    SideEffectProfile.STATE_MODIFYING: RiskClass.WRITE_CAPABLE,
    SideEffectProfile.DESTRUCTIVE: RiskClass.WRITE_CAPABLE,
    SideEffectProfile.FINANCIAL_TRANSACTION: RiskClass.WRITE_CAPABLE,
}
# What a component holds that it could send out once it can reach the network.
_EXFIL_SOURCES = frozenset(
    {CapabilityClass.READ, CapabilityClass.FILESYSTEM, CapabilityClass.CREDENTIALS}
)
# Both values mean that loading or rendering the model can run code (finding catalog:
# serialization_format), and the risk gate treats them alike.
_CODE_LOADING = frozenset(
    {SerializationSafety.UNSAFE_CODE_EXECUTION, SerializationSafety.UNSAFE_TEMPLATE_INJECTION}
)
# Only settings whose meaning the host documents and the ide_agents collector rates in a
# permission_scope finding: a Claude Code mode that skips every prompt or accepts edits
# without one, and Codex approval that never asks before a command. Other values leave
# effective approval to unrecorded allow, ask and deny rules, user and managed settings
# and session flags, so they are not read.
_CLAUDE_MODES: dict[str, tuple[RiskClass, ...]] = {
    "bypassPermissions": (RiskClass.CODE_EXEC, RiskClass.WRITE_CAPABLE),
    "acceptEdits": (RiskClass.WRITE_CAPABLE,),
}
_CODEX_APPROVALS: dict[str, tuple[RiskClass, ...]] = {"never": (RiskClass.CODE_EXEC,)}
# The mcp collector exports an environment name that is token-shaped, or not a plain
# field name, only as this numbered marker (scanners/mcp.py _exported_environment).
_WITHHELD_ENVIRONMENT_NAME = re.compile(r"\[redacted-[1-9][0-9]{0,5}\]")
# A host is read only from an authority that a WHATWG parser (what Node-based MCP
# clients use) and urlsplit read alike: an ASCII host name or IP literal and a port.
# Userinfo, a backslash, a percent-escape or non-ASCII text can make them name different
# hosts: for WHATWG, http://evil.example\@localhost/ is a request to evil.example.
_URL_SCHEMES = frozenset({"http", "https", "ws", "wss"})
_PLAIN_AUTHORITY = re.compile(r"(?:[A-Za-z0-9_.-]+|\[[0-9A-Fa-f:.]+\])(?::[0-9]{1,5})?")
# Explicit networks: interpreters disagree on whether an IPv4-mapped address is loopback.
_LOOPBACK_NETWORKS = (ipaddress.ip_network("127.0.0.0/8"), ipaddress.ip_network("::1/128"))

BASIS: frozenset[str] = frozenset(
    {
        *(f"capabilities:{capability.value}" for capability in CapabilityClass),
        *(f"side_effect_profile:{profile.value}" for profile in _SIDE_EFFECTS),
        "egress_domains:declared",
        "endpoint_url:remote",
        "endpoint_url:unresolved",
        "env:withheld-name",
        *(f"serialization_safety:{safety.value}" for safety in _CODE_LOADING),
        "trust_remote_code:true",
        *(f"permission_mode:{mode}" for mode in _CLAUDE_MODES),
        *(f"approval_policy:{policy}" for policy in _CODEX_APPROVALS),
    }
)
"""Every basis string ``classify`` can return."""


def classify(component: AnyComponent) -> RiskClassification:
    """The risk classes one component's record supports, with the evidence for each."""
    classes: set[RiskClass] = set()
    basis: set[str] = set()
    assessed = False
    declaration = getattr(component, "capabilities", None)
    if isinstance(declaration, CapabilityDeclaration):
        assessed |= _declared(declaration, classes, basis)
    if isinstance(component, MCPServerComponent):
        assessed |= _server(component, classes, basis)
    elif isinstance(component, ModelComponent):
        assessed |= _model(component, classes, basis)
    elif isinstance(component, IDEAgentComponent):
        assessed |= _ide_agent(component, classes, basis)
    return RiskClassification(
        classes=tuple(sorted(classes)), basis=tuple(sorted(basis)), assessed=assessed
    )


def _declared(declaration: CapabilityDeclaration, classes: set[RiskClass], basis: set[str]) -> bool:
    capabilities = set(declaration.capabilities)
    for capability in capabilities & _DECLARED.keys():
        classes.add(_DECLARED[capability])
        basis.add(f"capabilities:{capability.value}")
    profile = declaration.side_effect_profile
    if profile in _SIDE_EFFECTS:
        classes.add(_SIDE_EFFECTS[profile])
        basis.add(f"side_effect_profile:{profile.value}")
    if declaration.egress_domains:
        classes.add(RiskClass.NETWORK_EGRESS)
        basis.add("egress_domains:declared")
    sources = capabilities & _EXFIL_SOURCES
    if sources and (CapabilityClass.NETWORK in capabilities or declaration.egress_domains):
        classes.add(RiskClass.EXFIL_CAPABLE)
        basis.update(f"capabilities:{capability.value}" for capability in sources)
    return bool(
        capabilities or declaration.egress_domains or profile is not SideEffectProfile.UNKNOWN
    )


def plain_authority(netloc: str) -> bool:
    """Whether every URL parser reads this authority alike: a host and an optional port.

    User information, a backslash or a percent escape can make Python and the WHATWG
    parser of the client that connects name different hosts.
    """
    return _PLAIN_AUTHORITY.fullmatch(netloc) is not None


def _endpoint_host(url: str) -> str:
    """``loopback`` or ``remote`` for a host every URL parser reads alike, else ``unresolved``."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname
        _ = parsed.port
    except ValueError:
        return "unresolved"
    if not host or parsed.scheme.lower() not in _URL_SCHEMES or not plain_authority(parsed.netloc):
        return "unresolved"
    if host in {"localhost", "localhost."}:
        return "loopback"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return "remote"
    return "loopback" if any(address in network for network in _LOOPBACK_NETWORKS) else "remote"


def _server(server: MCPServerComponent, classes: set[RiskClass], basis: set[str]) -> bool:
    """A server's own transport and environment; its tools are classified as tools."""
    assessed = False
    if server.endpoint_url:
        assessed = True
        host = _endpoint_host(server.endpoint_url)
        if host != "loopback":
            classes.add(RiskClass.NETWORK_EGRESS)
            basis.add(f"endpoint_url:{host}")
    if any(_WITHHELD_ENVIRONMENT_NAME.fullmatch(name) for name in server.env):
        assessed = True
        classes.add(RiskClass.SECRET_ACCESS)
        basis.add("env:withheld-name")
    return assessed


def _model(model: ModelComponent, classes: set[RiskClass], basis: set[str]) -> bool:
    if model.serialization_safety in _CODE_LOADING:
        classes.add(RiskClass.CODE_EXEC)
        basis.add(f"serialization_safety:{model.serialization_safety.value}")
    if model.trust_remote_code is True:
        classes.add(RiskClass.CODE_EXEC)
        basis.add("trust_remote_code:true")
    return (
        model.serialization_safety is not SerializationSafety.UNKNOWN
        or model.trust_remote_code is not None
    )


def _ide_agent(agent: IDEAgentComponent, classes: set[RiskClass], basis: set[str]) -> bool:
    granted: tuple[RiskClass, ...] = ()
    mode = agent.permission_mode
    if agent.ide_type == "claude-code" and mode in _CLAUDE_MODES:
        granted = _CLAUDE_MODES[mode]
        basis.add(f"permission_mode:{mode}")
    approval = agent.properties.get("approval_policy")
    if agent.ide_type == "codex" and isinstance(approval, str) and approval in _CODEX_APPROVALS:
        granted = (*granted, *_CODEX_APPROVALS[approval])
        basis.add(f"approval_policy:{approval}")
    classes.update(granted)
    return bool(granted)
