"""Compare approved inventory with descriptors served by operator-pinned stdio launchers.

verify-live starts only pinned stdio launchers. A server reached over HTTP, one with
a remote transport label, no recorded launch command and no launch policy entry, is
reported as not verifiable here, without making the stdio verification fail; observe
it with ``discover-mcp --record`` and compare the inventories with ``diff``. A remote
label never overrides the operator's pin: a server the policy names is verified
through its launcher, and one that records a launch command but has no entry fails.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Any

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_canonical,
    hash_tool_definition,
    normalize_digest,
    tool_definition_extensions,
)
from nexus_symbiote.core.models import ClaimEvidence, MCPServerComponent, ToolComponent
from nexus_symbiote.graph import validate_graph
from nexus_symbiote.live import pinned_process, stdio
from nexus_symbiote.live.stdio import (
    LaunchPolicyError,
    PinnedObservation,
    SessionDeadlineError,
    StdioProtocolError,
    observe_pinned,
)
from nexus_symbiote.scanners.live_mcp import (
    DECLARATION_PROFILE,
    IDENTITY_PROFILE,
    CheckedDescriptor,
    DiscoveryError,
    check_listed_item,
    check_served_tool,
    check_server_hello,
    declaration_hash,
)
from nexus_symbiote.utils.secrets import redact_text

# Fixed, nonsecret explanations; reports never carry exception text or server data.
REASONS: dict[str, str] = {
    "missing-launch-policy": "No operator launch policy entry names this server reference.",
    "invalid-launch-policy": (
        "The launch policy entry is not exactly an absolute command and a SHA-256 pin."
    ),
    "launcher-unavailable": (
        "The pinned launcher is missing, not a regular file, a symbolic link, or too large."
    ),
    "launcher-digest-mismatch": "The launcher bytes differ from the SHA-256 pin in the policy.",
    "launcher-start-failed": "The pinned launcher could not be started.",
    "isolation-unavailable": (
        "Kernel PID containment is unavailable; the pinned launcher was not executed. "
        "Use an independently isolated worker or, on Linux only, explicitly accept "
        "--no-isolation."
    ),
    "isolation-teardown-failed": (
        "The pinned launcher's processes could not be confirmed ended after the session "
        "(its PID namespace, or under --no-isolation its wrapper's tree); a process it "
        "started may still be running on this worker."
    ),
    "deadline": (
        "The pinned server's bounded MCP exchange and the checks of its descriptors did "
        "not finish before the deadline."
    ),
    "unsupported-protocol-version": (
        "The pinned server negotiated an MCP protocol version this client does not speak."
    ),
    "protocol": (
        "The pinned server's MCP messages were invalid, out of order or over protocol limits."
    ),
    "invalid-descriptor": (
        "A served tool, prompt or resource template is invalid or exceeds the validation budget."
    ),
    "ambiguous-approved-tools": "The inventory approves two tools with one name for this server.",
    "remote-transport": (
        "Remote MCP server: verify-live starts only pinned stdio launchers. Observe it with "
        "discover-mcp --record and compare the inventories with diff."
    ),
    "ambiguous-transport": (
        "The inventory labels this server with a remote transport but records a launch "
        "command, which a client may start, and no operator launch policy entry names it."
    ),
    "unsupported-transport": (
        "The inventory names a transport that is neither stdio nor a remote MCP transport "
        "(sse, streamable-http, http), so the server cannot be verified."
    ),
    "invalid-transport-evidence": (
        "Supplied transport evidence is not a complete live MCP endpoint observation for this server."
    ),
    "internal-error": "The pinned observation stopped on an unexpected internal error.",
}

# Off Linux the isolation opt-out is refused as well, so the remedy there names no option.
ISOLATION_UNAVAILABLE_OFF_LINUX = (
    "Kernel PID containment is unavailable on this platform, and so is running without it; "
    "the pinned launcher was not executed. Run verify-live on Linux, in an independently "
    "isolated worker."
)


def reason_message(reason: str) -> str:
    """The error a result shows for ``reason``, true for the platform it runs on."""
    if reason == "isolation-unavailable" and not pinned_process.opt_out_supported():
        return ISOLATION_UNAVAILABLE_OFF_LINUX
    return REASONS[reason]


# Transport labels of servers reached over the network; discover-mcp observes them.
REMOTE_TRANSPORTS = frozenset({"sse", "streamable-http", "http"})


class _RefusedError(Exception):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass
class LiveToolFinding:
    name: str
    definition_hash: str | None
    status: str  # "match" | "changed" | "new" | "missing" | "unverifiable"

    descriptor: dict[str, Any] | None = field(default=None, repr=False)
    previous_hash: str | None = None
    display_differs: bool = False
    observed_hash: str | None = field(default=None, repr=False)
    unprofiled_fields: tuple[str, ...] = ()
    remote_claim: ClaimEvidence | None = field(default=None, repr=False)


@dataclass
class ServerVerifyResult:
    server_name: str
    server_ref: str
    reachable: bool = False
    error: str | None = None
    transport: str | None = None
    tool_findings: list[LiveToolFinding] = field(default_factory=list)
    live_schema_hash: str | None = None
    reason: str | None = None
    status: str = "failed"  # "verified" | "failed" | "not-verifiable"
    protocol_version: str | None = None
    launcher_sha256: str | None = None
    declaration_hash: str | None = None
    declaration_status: str | None = None  # "match" | "changed" | "new"
    declaration: dict[str, Any] | None = field(default=None, repr=False)
    identity_hash: str | None = None
    identity_status: str | None = None  # "match" | "changed" | "unrecorded"
    transport_evidence: dict[str, str] | None = None
    # "confirmed" only for a verified server whose cleanup could list what the launcher
    # started; None otherwise, so a result never claims a teardown that was not checked.
    teardown: str | None = None  # "confirmed"

    @property
    def rug_pull_detected(self) -> bool:
        return (
            any(f.status != "match" for f in self.tool_findings)
            or self.declaration_status in {"changed", "new"}
            or self.identity_status == "changed"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server_name,
            "server_ref": self.server_ref,
            "status": self.status,
            "reachable": self.reachable,
            "reason": self.reason,
            "error": self.error,
            "transport": self.transport,
            "protocol_version": self.protocol_version,
            "launcher_sha256": self.launcher_sha256,
            "rug_pull_detected": self.rug_pull_detected,
            "live_schema_hash": self.live_schema_hash,
            "declaration_hash": self.declaration_hash,
            "declaration_status": self.declaration_status,
            "identity_hash": self.identity_hash,
            "identity_status": self.identity_status,
            **({"transport_evidence": self.transport_evidence} if self.transport_evidence else {}),
            "teardown": self.teardown,
            "tools": [
                {
                    "name": f.name,
                    "definition_hash": f.definition_hash,
                    "status": f.status,
                    **({"previous_definition_hash": f.previous_hash} if f.previous_hash else {}),
                    **({"display_differs": True} if f.display_differs else {}),
                    **(
                        {"fields_outside_profile": list(f.unprofiled_fields)}
                        if f.unprofiled_fields
                        else {}
                    ),
                }
                for f in self.tool_findings
            ],
        }


@dataclass
class LiveVerifyReport:
    servers_checked: int = 0
    servers_reachable: int = 0
    servers_skipped: int = 0
    results: list[ServerVerifyResult] = field(default_factory=list)
    inputs: dict[str, str] = field(default_factory=dict)

    @property
    def has_drift(self) -> bool:
        return any(r.rug_pull_detected for r in self.results)

    @property
    def complete(self) -> bool:
        return (
            self.servers_checked > 0
            and self.servers_checked == self.servers_reachable
            and all(
                finding.status != "unverifiable"
                for result in self.results
                for finding in result.tool_findings
            )
        )

    @property
    def origin_bound(self) -> list[ServerVerifyResult]:
        binding = [(r, (r.transport_evidence or {}).get("endpoint_binding")) for r in self.results]
        return [r for r, b in binding if r.status == "verified" and b == "origin"]

    @property
    def all_servers_verified(self) -> bool:
        return self.complete and self.servers_skipped == 0 and not self.has_drift

    @property
    def verification_scope(self) -> str:
        if not self.complete:
            return "incomplete"
        if self.has_drift:
            return "drifted"
        if self.servers_skipped == 0:
            return "all-servers"
        has_stdio_verified = any(
            r.status == "verified" and r.transport in ("stdio", None) for r in self.results
        )
        has_remote_verified = any(
            r.status == "verified" and r.transport in REMOTE_TRANSPORTS for r in self.results
        )
        return (
            "partial-stdio-only" if (has_stdio_verified and not has_remote_verified) else "partial"
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "all_servers_verified": self.all_servers_verified,
            "verification_scope": self.verification_scope,
            "servers_checked": self.servers_checked,
            "servers_reachable": self.servers_reachable,
            "servers_skipped": self.servers_skipped,
            "origin_bound_servers": len(self.origin_bound),
            "has_drift": self.has_drift,
            "inputs": dict(self.inputs),
            "results": [r.to_dict() for r in self.results],
        }


def _launcher(entry: Any) -> tuple[str, str]:
    if entry is None:
        raise LaunchPolicyError("missing-launch-policy", "no launch policy entry")
    if (
        not isinstance(entry, dict)
        or set(entry) != {"command", "sha256"}
        or not isinstance(entry["command"], str)
        or not isinstance(entry["sha256"], str)
    ):
        raise LaunchPolicyError("invalid-launch-policy", "invalid operator launch policy")
    return entry["command"], entry["sha256"]


def list_tools_stdio(
    command: str, args: list[str], *, expected_sha256: str | None = None
) -> list[dict[str, Any]]:
    """Caller must supply a trusted binary digest. Only standalone launchers are supported."""
    if args or not expected_sha256:
        raise LaunchPolicyError(
            "invalid-launch-policy", "a pinned standalone executable without arguments is required"
        )
    return observe_pinned(command, expected_sha256).tools


def fetch_observation(trusted_launcher: Any) -> PinnedObservation:
    """Observe the launcher an independent operator policy names; project config confers nothing."""
    command, pin = _launcher(trusted_launcher)
    return observe_pinned(command, pin)


def fetch_tools_from_config(
    server_name: str, config: dict[str, Any], *, trusted_launcher: dict[str, str] | None = None
) -> tuple[str, list[dict[str, Any]]]:
    """Legacy project config conveys no authority to start a process."""
    return "stdio", fetch_observation(trusted_launcher).tools


@dataclass
class _Declaration:
    version: str
    shown: dict[str, Any]
    instructions: str | None
    lists: dict[str, dict[str, str] | None]
    identity: str


def _declaration(observation: PinnedObservation) -> _Declaration:
    """Validate the session's server declarations and prepare their redacted display."""
    try:
        version, server_info, capabilities, instructions, identity = check_server_hello(
            observation.hello
        )
    except DiscoveryError as exc:
        raise _RefusedError("protocol") from exc
    declaration = _Declaration(
        version,
        {"protocol_version": version, "server_info": server_info, "capabilities": capabilities},
        instructions,
        {},
        identity,
    )
    if instructions is not None:
        declaration.shown["instructions"] = redact_text(instructions)
        declaration.shown["instructions_hash"] = hash_canonical({"instructions": instructions})
    for key, identity, items in (
        ("prompts", "name", observation.prompts),
        ("resource_templates", "uriTemplate", observation.resource_templates),
    ):
        if items is None:
            declaration.lists[key] = None
            continue
        digests: dict[str, str] = {}
        shown = []
        for raw in items:
            item = check_listed_item(raw, identity)
            digests[item.identity] = item.digest
            shown.append(
                {
                    "identity": redact_text(item.identity),
                    "digest": item.digest,
                    "descriptor": item.descriptor,
                }
            )
        declaration.lists[key] = digests
        declaration.shown[key] = sorted(
            shown, key=lambda entry: (entry["identity"], entry["digest"])
        )
    return declaration


def _canonical_https_origin(url: str | None) -> tuple[str, str, int] | None:
    from urllib.parse import urlsplit

    if (
        not isinstance(url, str)
        or not url
        or "\\" in url
        or any(ch <= " " or ch == "\x7f" for ch in url)
    ):
        return None
    try:
        parts = urlsplit(url)
        scheme = parts.scheme.lower()
        host = parts.hostname
        port = parts.port
    except ValueError:
        return None
    if scheme != "https" or not host or parts.username is not None or parts.password is not None:
        return None
    return scheme, host.lower(), (443 if port is None else port)


def _named_endpoint_hash(url: str | None) -> str | None:
    """discover-mcp's digest of an endpoint that names a path; "" if discover-mcp refuses it."""
    from urllib.parse import urlsplit

    from nexus_symbiote.scanners.live_mcp import _endpoint

    if not isinstance(url, str):
        return None
    try:
        parts = urlsplit(url)
        if parts.path in ("", "/") and not parts.query:
            return None
        origin, _, _, path = _endpoint(url.split("#", 1)[0])
    except ValueError:
        return ""
    return hash_canonical({"observed_endpoint": origin + path})


def _recent(observed_at: datetime, max_age: timedelta | None) -> bool:
    now = datetime.now(UTC)
    if observed_at.tzinfo is None or observed_at > now + timedelta(minutes=5):
        return False
    return max_age is None or now - max_age <= observed_at


def _refuse(result: ServerVerifyResult, reason: str) -> bool:
    result.reason, result.error = reason, REASONS[reason]
    return False


def _valid_digest(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        alg, digest = normalize_digest(value, "sha256")
    except ValueError:
        return None
    return f"{alg}:{digest}"


def _is_valid_endpoint_observation_bom(evidence_bom: AIBOM) -> bool:
    from nexus_symbiote.core.enums import AssuranceLevel

    if validate_graph(evidence_bom):
        return False
    completeness = evidence_bom.metadata.completeness
    if (
        completeness is None
        or completeness.scope != "mcp-endpoint-observation"
        or completeness.assurance_level != AssuranceLevel.OBSERVED
        or completeness.scanner_status.get("live-mcp") != "complete"
    ):
        return False
    servers = [c for c in evidence_bom.components if isinstance(c, MCPServerComponent)]
    return len(servers) == 1


def _reconstruct_observed_descriptor(obs_tool: ToolComponent) -> dict[str, Any]:
    desc: dict[str, Any] = {
        "name": obs_tool.name,
        "description": obs_tool.description_text or "",
        "inputSchema": obs_tool.input_schema
        if isinstance(obs_tool.input_schema, dict)
        else {"type": "object"},
    }
    if obs_tool.annotations:
        desc["annotations"] = dict(obs_tool.annotations)
    for prop_name, field_name in (
        ("mcp_title", "title"),
        ("mcp_output_schema", "outputSchema"),
        ("mcp_meta", "_meta"),
    ):
        if prop_name in obs_tool.properties:
            desc[field_name] = obs_tool.properties[prop_name]
    return desc


def _verify_remote_evidence(
    bom: AIBOM,
    server: MCPServerComponent,
    observed_bom: AIBOM,
    observed_server: MCPServerComponent,
    result: ServerVerifyResult,
    max_age: timedelta | None = None,
    require_full_url: bool = False,
) -> bool:
    """Compare an approved remote server against a recorded discover-mcp observation."""
    from nexus_symbiote.core.enums import AssuranceLevel

    server_claim = observed_server.claims.get("server_declaration")
    if (
        observed_server.assurance_level != AssuranceLevel.OBSERVED
        or observed_server.properties.get("collection_mode") != "live-observation"
        or server_claim is None
        or server_claim.assurance != AssuranceLevel.OBSERVED
        or server_claim.collector != "live-mcp"
        or server_claim.method != "https-mcp-initialize"
        or server_claim.observed_at is None
        or not _recent(server_claim.observed_at, max_age)
    ):
        return _refuse(result, "invalid-transport-evidence")
    obs_origin = _canonical_https_origin(observed_server.endpoint_url)
    endpoint_hash = _valid_digest(observed_server.properties.get("observed_endpoint_hash"))
    # The bom_ref does not change with the URL, and the scanner withholds an endpoint it
    # cannot read unambiguously ("[redacted]"), so only the inventory's own origin, and
    # its recorded full-URL digest when present, bind the evidence to this server.
    # An inventory endpoint that names a path binds the full URL as observed.
    expected_ep_hash = server.properties.get("observed_endpoint_hash")
    named_ep_hash = _named_endpoint_hash(server.endpoint_url)
    if (
        obs_origin is None
        or _canonical_https_origin(server_claim.locator) != obs_origin
        or _canonical_https_origin(server.endpoint_url) != obs_origin
        or endpoint_hash is None
        or (require_full_url and expected_ep_hash is None and named_ep_hash is None)
        or (expected_ep_hash is not None and _valid_digest(expected_ep_hash) != endpoint_hash)
        or (named_ep_hash is not None and named_ep_hash != endpoint_hash)
    ):
        return _refuse(result, "invalid-transport-evidence")
    approved = [
        t
        for t in bom.components
        if isinstance(t, ToolComponent) and t.mcp_server_ref == server.bom_ref
    ]
    by_name = {t.name: t for t in approved}
    if len(by_name) != len(approved):
        return _refuse(result, "ambiguous-approved-tools")
    observed_tools = [
        t
        for t in observed_bom.components
        if isinstance(t, ToolComponent) and t.mcp_server_ref == observed_server.bom_ref
    ]
    obs_by_name = {t.name: t for t in observed_tools}
    if len(obs_by_name) != len(observed_tools):
        return _refuse(result, "invalid-descriptor")
    decl_hash = _valid_digest(observed_server.properties.get("observed_declaration_hash"))
    ident_hash = _valid_digest(observed_server.properties.get("observed_identity_hash"))
    if decl_hash is None or ident_hash is None:
        return _refuse(result, "invalid-transport-evidence")
    fingerprints: dict[str, str] = {}
    for name, obs_tool in sorted(obs_by_name.items()):
        tool_claim = obs_tool.claims.get("tool_definition")
        fp = _valid_digest(obs_tool.definition_hash)
        if (
            obs_tool.assurance_level != AssuranceLevel.OBSERVED
            or obs_tool.properties.get("collection_mode") != "live-observation"
            or tool_claim is None
            or tool_claim.assurance != AssuranceLevel.OBSERVED
            or tool_claim.collector != "live-mcp"
            or tool_claim.method != "https-mcp-tools-list"
            or tool_claim.observed_at is None
            or not _recent(tool_claim.observed_at, max_age)
            or obs_tool.definition_hash_version != TOOL_DEFINITION_HASH_VERSION
            or fp is None
        ):
            return _refuse(result, "invalid-descriptor")
        fingerprints[name] = fp
    result.reachable, result.status = True, "verified"
    result.transport_evidence = {
        "endpoint_binding": (
            "origin" if expected_ep_hash is None and named_ep_hash is None else "full-url"
        ),
        "observed_endpoint_hash": endpoint_hash,
        "observed_at": server_claim.observed_at.isoformat(),
    }
    proto = observed_server.properties.get("observed_protocol_version")
    result.protocol_version = proto if isinstance(proto, str) else None
    result.declaration_hash = decl_hash
    result.declaration = {
        key: observed_server.properties[f"observed_{key}"]
        for key in _SHOWN_DECLARATION_KEYS
        if f"observed_{key}" in observed_server.properties
    }
    recorded = server.properties.get("observed_declaration_hash")
    if recorded is not None:
        result.declaration_status = "match" if recorded == decl_hash else "changed"
    elif any(
        observed_server.properties.get(f"observed_{key}")
        for key in ("instructions", "prompts", "resource_templates")
    ) or any(t.properties.get("descriptor_fields_outside_profile") for t in observed_tools):
        result.declaration_status = "new"
    else:
        result.declaration_status = "match"
    result.identity_hash = ident_hash
    recorded_identity = server.properties.get("observed_identity_hash")
    if recorded_identity is None:
        result.identity_status = "unrecorded"
    else:
        result.identity_status = "match" if recorded_identity == ident_hash else "changed"
    for name, obs_tool in sorted(obs_by_name.items()):
        fp = fingerprints[name]
        old = by_name.get(name)
        previous = None
        if old is None:
            status = "new"
        elif old.definition_hash_version != TOOL_DEFINITION_HASH_VERSION or not old.definition_hash:
            status = "unverifiable"
        else:
            try:
                old_alg, old_digest = normalize_digest(old.definition_hash, "sha256")
                previous = f"{old_alg}:{old_digest}"
                status = "match" if previous == fp else "changed"
            except ValueError:
                status = "unverifiable"
        unprofiled = obs_tool.properties.get("descriptor_fields_outside_profile") or ()
        result.tool_findings.append(
            LiveToolFinding(
                name,
                fp,
                status,
                descriptor=_reconstruct_observed_descriptor(obs_tool),
                previous_hash=previous if status == "changed" else None,
                display_differs=bool(obs_tool.properties.get("displayed_descriptor_differs")),
                observed_hash=obs_tool.properties.get("observed_descriptor_hash"),
                unprofiled_fields=tuple(str(x) for x in unprofiled)
                if isinstance(unprofiled, list | tuple)
                else (),
                remote_claim=ClaimEvidence(
                    assurance=AssuranceLevel.OBSERVED,
                    method="https-mcp-tools-list",
                    scope="served-descriptor",
                    collector="live-mcp",
                    observed_at=obs_tool.claims["tool_definition"].observed_at,
                ),
            )
        )
    for old in approved:
        if old.name not in obs_by_name:
            result.tool_findings.append(LiveToolFinding(old.name, old.definition_hash, "missing"))
    result.live_schema_hash = hash_canonical(
        {
            "profile": TOOL_DEFINITION_HASH_VERSION,
            "tools": dict(sorted(fingerprints.items())),
        }
    )
    return True


def verify_mcp_servers(
    bom: AIBOM,
    config_lookup: dict[str, dict[str, Any]] | None = None,
    *,
    trusted_launchers: dict[str, dict[str, str]] | None = None,
    transport_evidence: list[AIBOM] | tuple[AIBOM, ...] = (),
    require_transport_evidence: bool = False,
    max_evidence_age: timedelta | None = None,
    require_full_url_binding: bool = False,
) -> LiveVerifyReport:
    """Bind collection to the exact server reference in an independent launch policy."""
    report = LiveVerifyReport()
    if validate_graph(bom):
        report.results.append(
            ServerVerifyResult(
                server_name="[inventory]",
                server_ref="[inventory]",
                error="Inventory relationships are invalid",
            )
        )
        return report
    launchers = trusted_launchers or {}
    evidence_by_ref: dict[str, tuple[AIBOM, MCPServerComponent]] = {}
    duplicate_evidence_refs: set[str] = set()
    for evidence_bom in transport_evidence:
        if not _is_valid_endpoint_observation_bom(evidence_bom):
            report.results.append(
                ServerVerifyResult(
                    server_name="[transport-evidence]",
                    server_ref="[transport-evidence]",
                    reason="invalid-transport-evidence",
                    error=REASONS["invalid-transport-evidence"],
                )
            )
            return report
        for comp in evidence_bom.components:
            if isinstance(comp, MCPServerComponent):
                if comp.bom_ref in evidence_by_ref:
                    duplicate_evidence_refs.add(comp.bom_ref)
                else:
                    evidence_by_ref[comp.bom_ref] = (evidence_bom, comp)
    for server in bom.components:
        if not isinstance(server, MCPServerComponent):
            continue
        result = ServerVerifyResult(
            server_name=server.name, server_ref=server.bom_ref, transport=server.transport
        )
        report.results.append(result)
        remote = server.transport in REMOTE_TRANSPORTS
        # The label comes from the checkout; the operator's pin and a recorded command do not.
        pinned = server.bom_ref in launchers
        if remote and not server.command and not pinned:
            if server.bom_ref in duplicate_evidence_refs:
                report.servers_checked += 1
                result.status, result.reason = "failed", "invalid-transport-evidence"
                result.error = REASONS["invalid-transport-evidence"]
                continue
            if server.bom_ref in evidence_by_ref:
                report.servers_checked += 1
                obs_bom, obs_server = evidence_by_ref[server.bom_ref]
                if _verify_remote_evidence(
                    bom,
                    server,
                    obs_bom,
                    obs_server,
                    result,
                    max_evidence_age,
                    require_full_url_binding,
                ):
                    report.servers_reachable += 1
                continue
            if require_transport_evidence:
                report.servers_checked += 1
                result.status, result.reason = "failed", "remote-transport"
                result.error = REASONS["remote-transport"]
                continue
            result.status, result.reason = "not-verifiable", "remote-transport"
            result.error = REASONS["remote-transport"]
            report.servers_skipped += 1
            continue
        report.servers_checked += 1
        if remote and not pinned:
            result.reason = "ambiguous-transport"
        elif not remote and server.transport not in ("stdio", None):
            result.reason = "unsupported-transport"
        if result.reason is not None:
            result.error = reason_message(result.reason)
            continue
        deadline = time.monotonic() + stdio.DEADLINE_SECONDS
        try:
            observation = fetch_observation(launchers.get(server.bom_ref))
            result.launcher_sha256 = observation.launcher_sha256
            declared = _declaration(observation)
            checked: dict[str, CheckedDescriptor] = {}
            for tool in observation.tools:
                if time.monotonic() > deadline:
                    raise SessionDeadlineError("descriptor checks exceeded the deadline")
                descriptor = check_served_tool(tool)
                shown_name = descriptor.display["name"]
                if shown_name in checked:
                    raise _RefusedError("invalid-descriptor")
                checked[shown_name] = descriptor
            approved = [
                t
                for t in bom.components
                if isinstance(t, ToolComponent) and t.mcp_server_ref == server.bom_ref
            ]
            by_name = {t.name: t for t in approved}
            if len(by_name) != len(approved):
                raise _RefusedError("ambiguous-approved-tools")
            if observation.teardown_confirmed:
                result.teardown = "confirmed"
        except (LaunchPolicyError, SessionDeadlineError, StdioProtocolError) as exc:
            result.reason = exc.reason
        except _RefusedError as exc:
            result.reason = exc.reason
        except DiscoveryError:
            result.reason = "invalid-descriptor"
        except Exception:
            result.reason = "internal-error"
        if result.reason is not None:
            result.error = reason_message(result.reason)
            continue
        result.reachable, result.status = True, "verified"
        result.protocol_version = declared.version
        report.servers_reachable += 1
        extensions = {
            item.name: item.unprofiled_hash
            for item in checked.values()
            if item.unprofiled_hash is not None
        }
        result.declaration_hash = declaration_hash(
            instructions=declared.instructions,
            tool_extensions=extensions,
            prompts=declared.lists["prompts"],
            resource_templates=declared.lists["resource_templates"],
        )
        result.declaration = declared.shown
        recorded = server.properties.get("observed_declaration_hash")
        if recorded is not None:
            result.declaration_status = (
                "match" if recorded == result.declaration_hash else "changed"
            )
        elif (
            declared.instructions is not None
            or extensions
            or declared.lists["prompts"]
            or declared.lists["resource_templates"]
        ):
            # Model-visible server text that no inventory approved is drift, like a new tool.
            result.declaration_status = "new"
        else:
            result.declaration_status = "match"
        result.identity_hash = declared.identity
        recorded_identity = server.properties.get("observed_identity_hash")
        if recorded_identity is None:
            result.identity_status = "unrecorded"
        else:
            result.identity_status = (
                "match" if recorded_identity == declared.identity else "changed"
            )
        for name, item in checked.items():
            old = by_name.get(name)
            previous = None
            if old is None:
                status = "new"
            elif (
                old.definition_hash_version != TOOL_DEFINITION_HASH_VERSION
                or not old.definition_hash
            ):
                status = "unverifiable"
            else:
                try:
                    algorithm, expected = normalize_digest(old.definition_hash, "sha256")
                    previous = f"{algorithm}:{expected}"
                    status = "match" if previous == item.fingerprint else "changed"
                except ValueError:
                    status = "unverifiable"
            result.tool_findings.append(
                LiveToolFinding(
                    item.display["name"],
                    item.fingerprint,
                    status,
                    item.display,
                    previous_hash=previous if status == "changed" else None,
                    display_differs=item.display_differs,
                    observed_hash=item.observed_hash,
                    unprofiled_fields=item.unprofiled_fields,
                )
            )
        for old in approved:
            if old.name not in checked:
                result.tool_findings.append(
                    LiveToolFinding(old.name, old.definition_hash, "missing")
                )
        result.live_schema_hash = hash_canonical(
            {
                "profile": TOOL_DEFINITION_HASH_VERSION,
                "tools": {name: item.fingerprint for name, item in sorted(checked.items())},
            }
        )
    return report


def record_candidate(
    bom: AIBOM, report: LiveVerifyReport, *, remote_attestations: dict[str, str] | None = None
) -> None:
    """Update a separate unsigned candidate; observations confer no authority."""
    from urllib.parse import quote

    from nexus_symbiote.core.aibom import DependencyEdge
    from nexus_symbiote.core.enums import AssuranceLevel

    if not report.complete or any(
        finding.status == "missing" for result in report.results for finding in result.tool_findings
    ):
        raise ValueError("incomplete inventory; candidate cannot be emitted")
    attestation_digests = remote_attestations or {}
    if any(
        result.status == "verified"
        and result.transport_evidence
        and (
            _valid_digest(attestation_digests.get(result.server_ref)) is None
            or any(finding.remote_claim is None for finding in result.tool_findings)
        )
        for result in report.results
    ):
        raise ValueError("remote candidate requires verified attestation provenance")
    for result in report.results:
        if result.status != "verified":
            continue
        seen_names: set[str] = set()
        for finding in result.tool_findings:
            if finding.name in seen_names:
                raise ValueError("colliding redacted tool names in candidate")
            seen_names.add(finding.name)
            descriptor = finding.descriptor
            if descriptor is None:
                raise ValueError("candidate requires an observed descriptor")
            tool = next(
                (
                    component
                    for component in bom.components
                    if isinstance(component, ToolComponent)
                    and component.mcp_server_ref == result.server_ref
                    and component.name == finding.name
                ),
                None,
            )
            if tool is None:
                tool = ToolComponent(
                    bom_ref=f"tool:{quote(result.server_ref, safe='')}/{quote(finding.name, safe='')}",
                    name=finding.name,
                    mcp_server_ref=result.server_ref,
                )
                bom.add_component(tool)
                bom.add_dependency(
                    DependencyEdge(
                        source_ref=result.server_ref,
                        target_ref=tool.bom_ref,
                        relationship="provides-tool",
                        assurance_level="observed",
                        conditions="served descriptor observed; backend behavior and authorization unverified",
                    )
                )
            tool.definition_hash = finding.definition_hash
            tool.definition_hash_version = TOOL_DEFINITION_HASH_VERSION
            tool.description_text = descriptor.get("description", "")
            tool.input_schema = descriptor["inputSchema"]
            tool.annotations = descriptor.get("annotations") or {}
            display_hash = hash_tool_definition(
                tool.name,
                tool.description_text or "",
                tool.input_schema,
                tool.annotations,
                **tool_definition_extensions(descriptor),
            )
            tool.redacted_definition_hash = (
                display_hash if display_hash != finding.definition_hash else None
            )
            # Members the server no longer serves must not stay displayed: the digest
            # check binds every displayed extension, under either property spelling.
            for stale in (
                "previous_definition_hash",
                "displayed_descriptor_differs",
                "mcp_title",
                "title",
                "mcp_output_schema",
                "output_schema",
                "mcp_meta",
                "meta",
                "observed_descriptor_hash",
                "descriptor_fields_outside_profile",
            ):
                tool.properties.pop(stale, None)
            tool.properties.update(
                observed_tool_properties(
                    descriptor,
                    observed_hash=finding.observed_hash,
                    unprofiled_fields=finding.unprofiled_fields,
                    previous_hash=finding.previous_hash,
                    display_differs=finding.display_differs,
                )
            )
            tool.assurance_level = AssuranceLevel.OBSERVED
            if finding.remote_claim is not None:
                tool.claims["tool_definition"] = finding.remote_claim.model_copy(
                    update={"evidence_refs": [attestation_digests[result.server_ref]]}
                )
            else:
                tool.claims["tool_definition"] = ClaimEvidence(
                    assurance=AssuranceLevel.OBSERVED,
                    method="operator-pinned-stdio-tools-list",
                    scope="served-descriptor",
                    collector="nexus-symbiote-live-stdio",
                    observed_at=datetime.now(UTC),
                )
        server = bom.get_component(result.server_ref)
        if isinstance(server, MCPServerComponent):
            server.schema_hash = result.live_schema_hash
            server.tool_refs = [
                component.bom_ref
                for component in bom.components
                if isinstance(component, ToolComponent)
                and component.mcp_server_ref == result.server_ref
            ]
            server.tool_count = len(server.tool_refs)
            # Instructions, prompts and templates the server stopped serving go too.
            for stale in _OBSERVED_SERVER_PROPERTIES:
                server.properties.pop(stale, None)
            server.properties.update(
                observed_server_properties(
                    result.declaration or {}, result.declaration_hash, result.identity_hash
                )
            )
            if result.transport_evidence:
                # Later evidence then binds the full URL, not only the origin.
                endpoint_hash = result.transport_evidence["observed_endpoint_hash"]
                server.properties["observed_endpoint_hash"] = endpoint_hash


def observed_tool_properties(
    descriptor: dict[str, Any],
    *,
    observed_hash: str | None,
    unprofiled_fields: tuple[str, ...] | list[str] = (),
    previous_hash: str | None = None,
    display_differs: bool = False,
) -> dict[str, Any]:
    """Display the fingerprinted members that ToolComponent has no field for."""
    shown: dict[str, Any] = {
        "collection_mode": "live-observation",
        "definition_hash_subject": "served-descriptor",
        "descriptor_output_may_be_redacted": True,
    }
    for key, name in (
        ("title", "mcp_title"),
        ("outputSchema", "mcp_output_schema"),
        ("_meta", "mcp_meta"),
    ):
        if key in descriptor:
            shown[name] = descriptor[key]
    if observed_hash:
        shown["observed_descriptor_hash"] = observed_hash
    if unprofiled_fields:
        # Their values are bound by observed_descriptor_hash and the server declaration digest.
        shown["descriptor_fields_outside_profile"] = list(unprofiled_fields)
    if previous_hash:
        shown["previous_definition_hash"] = previous_hash
    if display_differs:
        shown["displayed_descriptor_differs"] = True
    return shown


_SHOWN_DECLARATION_KEYS = (
    "protocol_version",
    "server_info",
    "capabilities",
    "instructions",
    "instructions_hash",
    "prompts",
    "resource_templates",
)
_OBSERVED_SERVER_PROPERTIES = (
    "observed_declaration_hash",
    "observed_declaration_hash_profile",
    "observed_identity_hash",
    "observed_identity_hash_profile",
    *(f"observed_{key}" for key in _SHOWN_DECLARATION_KEYS),
)


def observed_server_properties(
    shown: dict[str, Any], digest: str | None, identity: str | None
) -> dict[str, Any]:
    """Record the server declaration and identity digests and their redacted display."""
    properties: dict[str, Any] = {
        "observed_declaration_hash": digest,
        "observed_declaration_hash_profile": DECLARATION_PROFILE,
        "observed_identity_hash": identity,
        "observed_identity_hash_profile": IDENTITY_PROFILE,
    }
    for key in _SHOWN_DECLARATION_KEYS:
        if key in shown:
            properties[f"observed_{key}"] = shown[key]
    return properties
