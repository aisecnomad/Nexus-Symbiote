"""Compare approved inventory with descriptors served by operator-pinned stdio launchers."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from jsonschema import Draft202012Validator
from jsonschema.exceptions import SchemaError

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_canonical,
    hash_tool_definition,
    normalize_digest,
)
from nexus_symbiote.core.models import MCPServerComponent, ToolComponent
from nexus_symbiote.graph import validate_graph
from nexus_symbiote.live.stdio import list_pinned_tools
from nexus_symbiote.scanners.live_mcp import SCHEMA_FORMAT_CHECKER
from nexus_symbiote.utils.secrets import redact_descriptor


@dataclass
class LiveToolFinding:
    name: str
    definition_hash: str | None
    status: str  # "match" | "changed" | "new" | "missing" | "unverifiable"

    descriptor: dict[str, Any] | None = field(default=None, repr=False)


@dataclass
class ServerVerifyResult:
    server_name: str
    server_ref: str
    reachable: bool = False
    error: str | None = None
    transport: str | None = None
    tool_findings: list[LiveToolFinding] = field(default_factory=list)
    live_schema_hash: str | None = None

    @property
    def rug_pull_detected(self) -> bool:
        return any(f.status != "match" for f in self.tool_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "server": self.server_name,
            "server_ref": self.server_ref,
            "reachable": self.reachable,
            "error": self.error,
            "transport": self.transport,
            "rug_pull_detected": self.rug_pull_detected,
            "live_schema_hash": self.live_schema_hash,
            "tools": [
                {"name": f.name, "definition_hash": f.definition_hash, "status": f.status}
                for f in self.tool_findings
            ],
        }


@dataclass
class LiveVerifyReport:
    servers_checked: int = 0
    servers_reachable: int = 0
    results: list[ServerVerifyResult] = field(default_factory=list)

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

    def to_dict(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "servers_checked": self.servers_checked,
            "servers_reachable": self.servers_reachable,
            "has_drift": self.has_drift,
            "results": [r.to_dict() for r in self.results],
        }


def list_tools_stdio(
    command: str, args: list[str], *, expected_sha256: str | None = None
) -> list[dict[str, Any]]:
    """Caller must supply a trusted binary digest. Only standalone launchers are supported."""
    if args or not expected_sha256:
        raise OSError("a pinned standalone executable without arguments is required")
    return list_pinned_tools(command, expected_sha256)


def fetch_tools_from_config(
    server_name: str, config: dict[str, Any], *, trusted_launcher: dict[str, str] | None = None
) -> tuple[str, list[dict[str, Any]]]:
    """Legacy project config conveys no authority to start a process."""
    if not isinstance(trusted_launcher, dict) or set(trusted_launcher) != {"command", "sha256"}:
        raise OSError("missing or invalid operator launch policy for this server reference")
    command, pin = trusted_launcher["command"], trusted_launcher["sha256"]
    if not isinstance(command, str) or not isinstance(pin, str):
        raise OSError("invalid operator launch policy")
    return "stdio", list_tools_stdio(command, [], expected_sha256=pin)


def verify_mcp_servers(
    bom: AIBOM,
    config_lookup: dict[str, dict[str, Any]] | None = None,
    *,
    trusted_launchers: dict[str, dict[str, str]] | None = None,
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
    for server in bom.components:
        if not isinstance(server, MCPServerComponent):
            continue
        result = ServerVerifyResult(
            server_name=server.name, server_ref=server.bom_ref, transport=server.transport
        )
        report.servers_checked += 1
        report.results.append(result)
        try:
            if server.transport not in ("stdio", None):
                raise ValueError("unsupported transport")
            _, tools = fetch_tools_from_config(
                server.name, {}, trusted_launcher=(trusted_launchers or {}).get(server.bom_ref)
            )
            live = {}
            for tool in tools:
                if set(tool) - {"name", "description", "inputSchema", "annotations"}:
                    raise ValueError("tool fields exceed the approved fingerprint version")
                desc, annotations = tool.get("description", ""), tool.get("annotations")
                if not isinstance(desc, str) or (
                    annotations is not None and not isinstance(annotations, dict)
                ):
                    raise ValueError("invalid descriptor")
                schema = tool.get("inputSchema")
                if not isinstance(schema, dict) or schema.get("type") != "object":
                    raise ValueError("MCP tools require an object input schema")
                Draft202012Validator.check_schema(schema, format_checker=SCHEMA_FORMAT_CHECKER)
                for hint in ("readOnlyHint", "destructiveHint", "idempotentHint", "openWorldHint"):
                    if annotations and hint in annotations and type(annotations[hint]) is not bool:
                        raise ValueError("invalid MCP annotation hint")
                live[tool["name"]] = hash_tool_definition(
                    tool["name"], desc, tool["inputSchema"], annotations or None
                )
            approved = [
                t
                for t in bom.components
                if isinstance(t, ToolComponent) and t.mcp_server_ref == server.bom_ref
            ]
            by_name = {t.name: t for t in approved}
            if len(by_name) != len(approved):
                raise ValueError("ambiguous tool references")
        except (OSError, ValueError, TypeError, RecursionError, SchemaError):
            result.error = "Pinned MCP discovery refused or incomplete; review launch policy and protocol limits"
            continue
        result.reachable = True
        report.servers_reachable += 1
        for tool in tools:
            name = tool["name"]
            old = by_name.get(name)
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
                    status = "match" if f"{algorithm}:{expected}" == live[name] else "changed"
                except ValueError:
                    status = "unverifiable"
            safe = redact_descriptor(tool)
            result.tool_findings.append(LiveToolFinding(safe["name"], live[name], status, safe))
        for old in approved:
            if old.name not in live:
                result.tool_findings.append(
                    LiveToolFinding(old.name, old.definition_hash, "missing")
                )
        result.live_schema_hash = hash_canonical(
            {"profile": TOOL_DEFINITION_HASH_VERSION, "tools": dict(sorted(live.items()))}
        )
    return report


def record_candidate(bom: AIBOM, report: LiveVerifyReport) -> None:
    """Update a separate unsigned candidate; observations confer no authority."""
    from datetime import UTC, datetime
    from urllib.parse import quote

    from nexus_symbiote.core.aibom import DependencyEdge
    from nexus_symbiote.core.enums import AssuranceLevel
    from nexus_symbiote.core.models import ClaimEvidence

    if not report.complete or any(
        finding.status == "missing" for result in report.results for finding in result.tool_findings
    ):
        raise ValueError("incomplete inventory; candidate cannot be emitted")
    for result in report.results:
        for finding in result.tool_findings:
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
                tool.name, tool.description_text or "", tool.input_schema, tool.annotations
            )
            tool.redacted_definition_hash = (
                display_hash if display_hash != finding.definition_hash else None
            )
            tool.assurance_level = AssuranceLevel.OBSERVED
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
