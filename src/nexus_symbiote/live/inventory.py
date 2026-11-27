"""Turn one complete HTTPS MCP observation into a native inventory that ``diff`` compares.

Two observations of the same endpoint differ only in collection times unless the
served tools, the server declaration (instructions, prompts, resource templates
and descriptor members outside the tool fingerprint profile), the server
identity or the negotiated protocol changed. The inventory carries observed,
redacted declarations and their digests; it grants no authority and says
nothing about backend behavior.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.aibom import AIBOM, DependencyEdge
from nexus_symbiote.core.enums import AssuranceLevel, TrustTier
from nexus_symbiote.core.hashing import (
    TOOL_DEFINITION_HASH_VERSION,
    hash_canonical,
    hash_tool_definition,
    tool_definition_extensions,
)
from nexus_symbiote.core.models import (
    ClaimEvidence,
    CompletenessClaim,
    MCPServerComponent,
    RiskAssessment,
    ToolComponent,
)
from nexus_symbiote.live.verify import observed_server_properties, observed_tool_properties
from nexus_symbiote.scanners.live_mcp import DiscoveryResult

COLLECTOR = "live-mcp"
_SERVER_REF = re.compile(r"[!-~]{1,256}")


def default_server_ref(endpoint: str) -> str:
    """A stable reference per endpoint; the path is digested because it can hold a secret."""
    return "mcp-server:" + hash_canonical({"observed_endpoint": endpoint}).split(":", 1)[1]


def endpoint_evidence(endpoint: str) -> dict[str, str]:
    """The origin and a digest of the full URL: what evidence shows of an endpoint."""
    parts = urlsplit(endpoint)
    return {
        "endpoint": f"{parts.scheme}://{parts.netloc}",
        "observed_endpoint_hash": hash_canonical({"observed_endpoint": endpoint}),
    }


def observation_inventory(result: DiscoveryResult, *, server_ref: str | None = None) -> AIBOM:
    """Build the inventory of a complete observation; refuse an incomplete one."""
    if not result.complete or result.failures or result.declaration_hash is None:
        raise ValueError("the observation is incomplete; no inventory was built")
    ref = server_ref if server_ref is not None else default_server_ref(result.endpoint)
    if not _SERVER_REF.fullmatch(ref):
        raise ValueError("server reference must be 1 to 256 printable ASCII characters")
    shown_endpoint = endpoint_evidence(result.endpoint)
    origin = shown_endpoint["endpoint"]
    observed_at = datetime.fromisoformat(result.observed_at)
    bom = AIBOM()
    bom.metadata.timestamp = observed_at
    claim = ClaimEvidence(
        assurance=AssuranceLevel.OBSERVED,
        method="https-mcp-initialize",
        scope="served-server-declaration",
        collector=COLLECTOR,
        locator=origin,
        observed_at=observed_at,
    )
    names: set[str] = set()
    fingerprints: dict[str, str] = {}
    tools: list[ToolComponent] = []
    for observed in result.tools:
        if observed.fingerprint is None or observed.name in names:
            raise ValueError("observed tools lack fingerprints or collide after redaction")
        names.add(observed.name)
        fingerprints[observed.name] = observed.fingerprint
        descriptor = observed.descriptor
        description = descriptor.get("description", "")
        annotations = descriptor.get("annotations") or {}
        display_hash = hash_tool_definition(
            observed.name,
            description,
            descriptor["inputSchema"],
            annotations,
            **tool_definition_extensions(descriptor),
        )
        tools.append(
            ToolComponent(
                bom_ref="tool:"
                + hash_canonical({"server": ref, "name": observed.name}).split(":", 1)[1],
                name=observed.name,
                mcp_server_ref=ref,
                description_text=description,
                input_schema=descriptor["inputSchema"],
                annotations=annotations,
                definition_hash=observed.fingerprint,
                definition_hash_version=TOOL_DEFINITION_HASH_VERSION,
                redacted_definition_hash=(
                    display_hash if display_hash != observed.fingerprint else None
                ),
                trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
                assurance_level=AssuranceLevel.OBSERVED,
                risks=[RiskAssessment.model_validate(item) for item in observed.text_risks],
                claims={
                    "tool_definition": claim.model_copy(
                        update={"method": "https-mcp-tools-list", "scope": "served-descriptor"}
                    )
                },
                properties=observed_tool_properties(
                    descriptor,
                    observed_hash=observed.definition_hash,
                    unprofiled_fields=observed.unprofiled_fields,
                    display_differs=observed.display_differs,
                ),
            )
        )
    shown: dict[str, Any] = {
        "protocol_version": result.protocol_version,
        "server_info": result.server_info,
        "capabilities": result.server_capabilities,
    }
    server_risks: list[RiskAssessment] = [
        RiskAssessment.model_validate(item) for item in result.server_text_risks
    ]
    if result.instructions_hash is not None:
        shown["instructions"] = result.instructions
        shown["instructions_hash"] = result.instructions_hash
    for key, items in (
        ("prompts", result.prompts),
        ("resource_templates", result.resource_templates),
    ):
        if items is not None:
            shown[key] = sorted(
                (
                    {
                        "identity": item.identity,
                        "digest": item.digest,
                        "descriptor": item.descriptor,
                    }
                    for item in items
                ),
                key=lambda entry: (entry["identity"], entry["digest"]),
            )
            for item in items:
                server_risks.extend(RiskAssessment.model_validate(r) for r in item.text_risks)
    server_info = result.server_info or {}
    version = server_info.get("version")
    server = MCPServerComponent(
        bom_ref=ref,
        name=origin,
        version=version if isinstance(version, str) else None,
        transport="streamable-http",
        endpoint_url=origin,
        tool_count=len(tools),
        tool_refs=[tool.bom_ref for tool in tools],
        schema_hash=hash_canonical(
            {"profile": TOOL_DEFINITION_HASH_VERSION, "tools": fingerprints}
        ),
        trust_tier=TrustTier.THIRD_PARTY_UNSIGNED,
        assurance_level=AssuranceLevel.OBSERVED,
        risks=server_risks,
        claims={"server_declaration": claim},
        properties={
            "collection_mode": "live-observation",
            "observed_endpoint_hash": shown_endpoint["observed_endpoint_hash"],
            **observed_server_properties(shown, result.declaration_hash, result.identity_hash),
        },
    )
    bom.add_component(server)
    for tool in tools:
        bom.add_component(tool)
        bom.add_dependency(
            DependencyEdge(
                source_ref=ref,
                target_ref=tool.bom_ref,
                relationship="provides-tool",
                assurance_level="observed",
                conditions="served descriptor observed; backend behavior and authorization unverified",
            )
        )
    from nexus_symbiote.text_poisoning import (
        TextPoisoningHit,
        _append_consolidated_risks,
        _hit_sort_key,
        check_sidenote_tool_schema,
        extract_json_text_entries,
        scan_text_block,
    )

    def _dedupe_distinct_hits(
        raw_hits: list[TextPoisoningHit], max_per_group: int = 16
    ) -> list[TextPoisoningHit]:
        seen_exact: set[tuple[str, str, str, str, int]] = set()
        counts: dict[tuple[str, str], int] = {}
        unique: list[TextPoisoningHit] = []
        for hit in sorted(raw_hits, key=_hit_sort_key):
            exact = (hit.category, hit.surface, hit.rule_id, hit.where, hit.byte_offset)
            if exact in seen_exact:
                continue
            seen_exact.add(exact)
            group = (hit.category, hit.surface)
            if counts.get(group, 0) >= max_per_group:
                continue
            counts[group] = counts.get(group, 0) + 1
            unique.append(hit)
        return unique

    server_hits: list[TextPoisoningHit] = []
    if isinstance(result.instructions, str) and result.instructions:
        server_hits.extend(
            scan_text_block(
                result.instructions,
                surface=origin,
                is_tool_surface=True,
                where="instructions",
            )
        )
    if isinstance(result.server_info, dict):
        for path, text in extract_json_text_entries(
            result.server_info, max_depth=16, max_entries=256
        ):
            if text:
                server_hits.extend(
                    scan_text_block(
                        text,
                        surface=origin,
                        is_tool_surface=True,
                        where=f"serverInfo.{path}",
                    )
                )
    for surface_label, items in (
        ("prompts", result.prompts),
        ("resourceTemplates", result.resource_templates),
    ):
        if items:
            for item_idx, item in enumerate(items):
                for path, text in extract_json_text_entries(
                    item.descriptor, max_depth=32, max_entries=512
                ):
                    if text:
                        server_hits.extend(
                            scan_text_block(
                                text,
                                surface=origin,
                                is_tool_surface=True,
                                where=f"{surface_label}[{item_idx}].{path}",
                            )
                        )
    if server_hits:
        _append_consolidated_risks(server, _dedupe_distinct_hits(server_hits))

    for observed, tool_comp in zip(result.tools, tools, strict=True):
        tool_hits: list[TextPoisoningHit] = []
        matched_values: list[tuple[str, list[TextPoisoningHit]]] = []
        parts: list[str] = []
        tool_fields: list[tuple[str, str | None]] = [
            ("description", tool_comp.description_text),
            ("description", tool_comp.description),
        ]
        tool_fields.extend(
            (f"input_schema.{path}", val)
            for path, val in extract_json_text_entries(
                tool_comp.input_schema, max_depth=64, max_entries=2048
            )
        )
        extra_fields = {
            k: v
            for k, v in observed.descriptor.items()
            if k not in {"name", "description", "inputSchema"}
        }
        tool_fields.extend(extract_json_text_entries(extra_fields, max_depth=64, max_entries=1024))
        for field_where, field_text in tool_fields:
            if field_text:
                parts.append(field_text)
                fh = scan_text_block(
                    field_text,
                    surface=tool_comp.name,
                    is_tool_surface=True,
                    where=field_where,
                )
                tool_hits.extend(fh)
                if fh:
                    matched_values.append((field_text, fh))
        tool_hits.extend(
            check_sidenote_tool_schema(
                tool_comp.input_schema,
                "\n".join(parts),
                tool_comp.annotations,
                surface=tool_comp.name,
                existing_hits=tool_hits,
                matched_values=matched_values,
            )
        )
        if tool_hits:
            _append_consolidated_risks(tool_comp, _dedupe_distinct_hits(tool_hits))
    surfaces = ["initialize", "tools/list"]
    if result.prompts is not None:
        surfaces.append("prompts/list")
    if result.resource_templates is not None:
        surfaces.append("resources/templates/list")
    bom.metadata.completeness = CompletenessClaim(
        scope="mcp-endpoint-observation",
        surfaces_scanned=[f"mcp-endpoint {origin}: {', '.join(surfaces)}"],
        timestamp=observed_at,
        assurance_level=AssuranceLevel.OBSERVED,
        collectors_requested=[COLLECTOR],
        collectors_completed=[COLLECTOR],
        scanner_status={COLLECTOR: "complete"},
        unobserved_surfaces=[
            "tool-implementation",
            "backend-behavior",
            "authorization",
            "resources-list",
            "resource-contents",
            "prompt-messages",
            "changes-after-observation",
        ],
    )
    return bom
