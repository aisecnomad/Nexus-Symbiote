"""Offline read-only stdio JSON-RPC 2.0 MCP query server for AgentBOM inventories.

Exposes one loaded native AgentBOM (and an optional SHA-256-bound advisory report)
over standard input/output with zero network sockets, zero subprocesses, bounded
JSON framing, strict schema checks on tool arguments, secret redaction, and
terminal neutralization.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import IO, Any, Literal

from nexus_symbiote import __version__
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.coverage import assess_coverage
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.hashing import json_nesting_exceeds, parse_json_strict
from nexus_symbiote.crosswalk import references as crosswalk_references
from nexus_symbiote.evidence_profile import build_evidence_profile
from nexus_symbiote.graph import blast_radius as compute_blast_radius
from nexus_symbiote.minimum_elements import assess as assess_minimum_elements
from nexus_symbiote.risk_classes import classify
from nexus_symbiote.trifecta import TrifectaReport, analyze_trifecta
from nexus_symbiote.utils.secrets import redact_text
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.vex_decisions import LoadedAdvisoryReport

MAX_FRAME_BYTES = 512 * 1024
MAX_HEADER_BYTES = 8 * 1024
MAX_HEADER_LINES = 16
MAX_FRAME_DEPTH = 32
MAX_REQUEST_ID_CHARS = 256
MAX_FILTER_CHARS = 512
DEFAULT_MAX_ITEMS = 200
DEFAULT_LIST_LIMIT = 50
MAX_OFFSET = 100_000
DEFAULT_MAX_REQUESTS = 10_000
MAX_ALLOWED_REQUESTS = 100_000
# 2025-03-26 is not offered: it obliges a server to accept JSON-RPC batches, which this
# server refuses; a client asking for it is answered with the latest version, per the spec.
SUPPORTED_PROTOCOL_VERSIONS = ("2025-06-18", "2024-11-05")

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}
_CONTENT_LENGTH_RE = re.compile(r"^content-length:\s*(\d+)$", re.IGNORECASE | re.ASCII)

_READ_ONLY_ANNOTATIONS: dict[str, bool] = {
    "readOnlyHint": True,
    "destructiveHint": False,
    "idempotentHint": True,
    "openWorldHint": False,
}

_TOOLS: tuple[dict[str, Any], ...] = (
    {
        "name": "inventory_summary",
        "description": (
            "Summarize AgentBOM component types, finding severities, coverage status, "
            "trifecta counts, and loaded advisory counts."
        ),
        "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        "annotations": dict(_READ_ONLY_ANNOTATIONS),
    },
    {
        "name": "list_components",
        "description": (
            "List components in the AgentBOM with risk classes, versions, assurance levels, "
            "and highest severities."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "component_type": {
                    "type": "string",
                    "maxLength": MAX_FILTER_CHARS,
                    "description": "Optional exact ComponentType filter (e.g. mcp-server, model).",
                },
                "name_contains": {
                    "type": "string",
                    "maxLength": MAX_FILTER_CHARS,
                    "description": "Case-insensitive substring filter on component name.",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "assurance_level": {
                    "type": "string",
                    "enum": ["declared", "observed", "verified"],
                },
                "offset": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET},
                "limit": {"type": "integer", "minimum": 1, "maximum": DEFAULT_MAX_ITEMS},
            },
            "additionalProperties": False,
        },
        "annotations": dict(_READ_ONLY_ANNOTATIONS),
    },
    {
        "name": "get_findings",
        "description": (
            "Query findings in the AgentBOM with OWASP LLM/ASI, MITRE ATLAS, NIST AI RMF, "
            "EU AI Act, ISO 42001, and CWE crosswalk references."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "category": {
                    "type": "string",
                    "maxLength": MAX_FILTER_CHARS,
                    "description": "Optional exact finding category filter.",
                },
                "component_ref": {
                    "type": "string",
                    "maxLength": MAX_FILTER_CHARS,
                    "description": "Optional exact component bom_ref filter.",
                },
                "offset": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET},
                "limit": {"type": "integer", "minimum": 1, "maximum": DEFAULT_MAX_ITEMS},
            },
            "additionalProperties": False,
        },
        "annotations": dict(_READ_ONLY_ANNOTATIONS),
    },
    {
        "name": "get_advisories",
        "description": (
            "Query matched advisories from an attached --advisories report or embedded "
            "component advisory metadata, including KEV and EPSS fields when present."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "component_ref": {
                    "type": "string",
                    "maxLength": MAX_FILTER_CHARS,
                    "description": "Optional exact component bom_ref filter.",
                },
                "min_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "kev_only": {"type": "boolean"},
                "offset": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET},
                "limit": {"type": "integer", "minimum": 1, "maximum": DEFAULT_MAX_ITEMS},
            },
            "additionalProperties": False,
        },
        "annotations": dict(_READ_ONLY_ANNOTATIONS),
    },
    {
        "name": "blast_radius",
        "description": (
            "Compute repository association blast radius for a component (affected agents, "
            "reachable components, shared credential env names, and reachable advisories)."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "component_ref": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_FILTER_CHARS,
                    "description": "Target component bom_ref.",
                }
            },
            "required": ["component_ref"],
            "additionalProperties": False,
        },
        "annotations": dict(_READ_ONLY_ANNOTATIONS),
    },
    {
        "name": "trifecta_flows",
        "description": (
            "Query lethal-trifecta, chained toxic-flow, and cross-server tool-shadowing findings."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "min_severity": {
                    "type": "string",
                    "enum": ["critical", "high", "medium", "low", "info"],
                },
                "include_shadowing": {"type": "boolean"},
                "offset": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET},
                "limit": {"type": "integer", "minimum": 1, "maximum": DEFAULT_MAX_ITEMS},
            },
            "additionalProperties": False,
        },
        "annotations": dict(_READ_ONLY_ANNOTATIONS),
    },
    {
        "name": "evidence_profile",
        "description": (
            "Inspect per-component pinning, digest, signature, and claim evidence status "
            "without synthetic trust scores."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "component_ref": {
                    "type": "string",
                    "maxLength": MAX_FILTER_CHARS,
                    "description": "Optional exact component bom_ref filter.",
                },
                "offset": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET},
                "limit": {"type": "integer", "minimum": 1, "maximum": DEFAULT_MAX_ITEMS},
            },
            "additionalProperties": False,
        },
        "annotations": dict(_READ_ONLY_ANNOTATIONS),
    },
    {
        "name": "minimum_elements",
        "description": (
            "Evaluate G7 AI SBOM minimum-element coverage of the AgentBOM CycloneDX 1.7 export."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "offset": {"type": "integer", "minimum": 0, "maximum": MAX_OFFSET},
                "limit": {"type": "integer", "minimum": 1, "maximum": 100},
            },
            "additionalProperties": False,
        },
        "annotations": dict(_READ_ONLY_ANNOTATIONS),
    },
)
_TOOL_SCHEMAS: dict[str, dict[str, Any]] = {tool["name"]: tool["inputSchema"] for tool in _TOOLS}


class FrameError(ValueError):
    """Malformed or oversized JSON-RPC frame on the stdio transport."""

    def __init__(self, code: int, message: str, *, fatal: bool = False) -> None:
        super().__init__(message)
        self.code = code
        self.fatal = fatal


def _clean_text(value: object) -> str:
    return neutralize(redact_text(str(value)))


def _clean_value(value: Any, *, depth: int = 0) -> Any:
    """Recursively redact secrets and neutralize terminal escapes inside bounded depth."""
    if depth > MAX_FRAME_DEPTH:
        return "<depth-truncated>"
    if isinstance(value, str):
        return _clean_text(value)
    if isinstance(value, Mapping):
        return {_clean_text(k): _clean_value(v, depth=depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple):
        return [_clean_value(item, depth=depth + 1) for item in value]
    return value


def _severity_rank(severity: object) -> int:
    return _SEVERITY_ORDER.get(str(severity).lower(), -1) if isinstance(severity, str) else -1


def _highest_sev(risks: list[Any]) -> str | None:
    best: str | None = None
    best_rank = -1
    for risk in risks:
        sev = risk.severity.value
        rank = _SEVERITY_ORDER.get(sev, -1)
        if rank > best_rank:
            best_rank = rank
            best = sev
    return best


def _validate_tool_args(tool_name: str, args: Mapping[str, Any]) -> str | None:
    schema = _TOOL_SCHEMAS.get(tool_name)
    if schema is None:
        return "Unknown tool"
    props: dict[str, dict[str, Any]] = schema.get("properties", {})
    if any(key not in props for key in args):
        return "Unexpected tool argument"
    for req in schema.get("required", ()):
        if req not in args or args[req] is None:
            return f"Missing required argument: {req}"
    for key, value in args.items():
        spec = props[key]
        expected = spec.get("type")
        if expected == "string":
            if not isinstance(value, str):
                return f"Argument '{key}' must be a string"
            min_len = spec.get("minLength", 0)
            max_len = spec.get("maxLength", MAX_FILTER_CHARS)
            if len(value) < min_len or len(value) > max_len:
                return f"Argument '{key}' length must be between {min_len} and {max_len}"
            allowed = spec.get("enum")
            if allowed is not None and value not in allowed:
                return f"Argument '{key}' must be one of: {', '.join(allowed)}"
        elif expected == "integer":
            if type(value) is not int:
                return f"Argument '{key}' must be an integer"
            minimum = spec.get("minimum", 0)
            maximum = spec.get("maximum", DEFAULT_MAX_ITEMS)
            if value < minimum or value > maximum:
                return f"Argument '{key}' must be between {minimum} and {maximum}"
        elif expected == "boolean" and type(value) is not bool:
            return f"Argument '{key}' must be a boolean"
    return None


@dataclass(frozen=True)
class _AdvisoryEntry:
    advisory_id: str
    component_ref: str
    severity: str
    aliases: tuple[str, ...]
    package: str
    version: str
    ecosystem: str
    source: str
    summary: str | None
    fixed_versions: tuple[str, ...]
    in_kev: bool | None
    epss_score: float | None

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "id": _clean_text(self.advisory_id),
            "component_ref": _clean_text(self.component_ref),
            "severity": self.severity,
            "aliases": [_clean_text(a) for a in self.aliases],
            "package": _clean_text(self.package),
            "version": _clean_text(self.version),
            "ecosystem": _clean_text(self.ecosystem),
            "source": self.source,
            "in_kev": self.in_kev,
        }
        if self.summary:
            payload["summary"] = _clean_text(self.summary)
        if self.fixed_versions:
            payload["fixed_versions"] = [_clean_text(v) for v in self.fixed_versions]
        if self.epss_score is not None:
            payload["epss_score"] = self.epss_score
        return payload


def _normalize_advisory_row(
    raw: Mapping[str, Any],
    *,
    component_ref: str,
    source: str,
    lacks_kev_catalog: bool = False,
) -> _AdvisoryEntry | None:
    adv_id = raw.get("advisory_id") or raw.get("id")
    if not isinstance(adv_id, str) or not adv_id.strip():
        return None
    sev_raw = raw.get("severity")
    severity = sev_raw.lower() if isinstance(sev_raw, str) else "unknown"
    kev = raw.get("in_kev")
    aliases_raw = raw.get("aliases")
    aliases = (
        tuple(sorted({a.strip() for a in aliases_raw if isinstance(a, str) and a.strip()}))
        if isinstance(aliases_raw, list)
        else ()
    )
    fixed_raw = raw.get("fixed_versions")
    if not isinstance(fixed_raw, list) and isinstance(raw.get("fixed"), list):
        fixed_raw = raw.get("fixed")
    fixed_versions = (
        tuple(sorted({f.strip() for f in fixed_raw if isinstance(f, str) and f.strip()}))
        if isinstance(fixed_raw, list)
        else ()
    )
    epss_raw = raw.get("epss_score")
    epss_score = (
        float(epss_raw)
        if isinstance(epss_raw, int | float)
        and not isinstance(epss_raw, bool)
        and 0 <= epss_raw <= 1
        else None
    )
    summary_raw = raw.get("summary")
    summary = summary_raw.strip() if isinstance(summary_raw, str) and summary_raw.strip() else None
    return _AdvisoryEntry(
        advisory_id=adv_id.strip(),
        component_ref=component_ref,
        severity=severity if severity in _SEVERITY_ORDER else "unknown",
        aliases=aliases,
        package=str(raw.get("package", "")).strip(),
        version=str(raw.get("version", "")).strip(),
        ecosystem=str(raw.get("ecosystem", "")).strip(),
        source=source,
        summary=summary,
        fixed_versions=fixed_versions,
        in_kev=kev if isinstance(kev, bool) and not lacks_kev_catalog else None,
        epss_score=epss_score,
    )


def _collect_advisories(bom: AIBOM, report: LoadedAdvisoryReport | None) -> list[_AdvisoryEntry]:
    deduped: dict[tuple[str, str], _AdvisoryEntry] = {}
    if report is not None:
        for row in report.advisories:
            comp_ref = row.get("bom_ref") or row.get("component_ref")
            if not isinstance(comp_ref, str) or not comp_ref.strip():
                continue
            parsed = _normalize_advisory_row(
                row,
                component_ref=comp_ref.strip(),
                source="advisory-report",
                lacks_kev_catalog=report.lacks_kev_catalog,
            )
            if parsed is not None:
                deduped[(parsed.component_ref, parsed.advisory_id)] = parsed
    for comp in sorted(bom.components, key=lambda c: c.bom_ref):
        embedded = comp.properties.get("advisories")
        if not isinstance(embedded, list):
            continue
        for row in embedded:
            if not isinstance(row, Mapping):
                continue
            parsed = _normalize_advisory_row(
                row, component_ref=comp.bom_ref, source="embedded-component"
            )
            if parsed is not None:
                deduped.setdefault((parsed.component_ref, parsed.advisory_id), parsed)
    return sorted(
        deduped.values(),
        key=lambda e: (
            not e.in_kev,
            -(e.epss_score if e.epss_score is not None else -1.0),
            -_severity_rank(e.severity),
            e.advisory_id,
            e.component_ref,
        ),
    )


class OfflineMCPServer:
    """Offline read-only JSON-RPC 2.0 MCP server over one loaded AgentBOM."""

    def __init__(
        self,
        bom: AIBOM,
        *,
        advisory_report: LoadedAdvisoryReport | None = None,
        inventory_sha256: str | None = None,
        content_digest: str | None = None,
    ) -> None:
        self.bom = bom
        self.advisory_report = advisory_report
        self.inventory_sha256 = inventory_sha256
        self.content_digest = content_digest
        self._advisories = _collect_advisories(bom, advisory_report)
        self._advisories_by_ref: dict[str, list[_AdvisoryEntry]] = {}
        for item in self._advisories:
            self._advisories_by_ref.setdefault(item.component_ref, []).append(item)
        self._trifecta_cache: TrifectaReport | None = None

    def _trifecta(self) -> TrifectaReport:
        if self._trifecta_cache is None:
            self._trifecta_cache = analyze_trifecta(self.bom)
        return self._trifecta_cache

    def handle_message(self, message: Mapping[str, Any]) -> dict[str, Any] | None:
        """Process one JSON-RPC 2.0 request or notification and return reply or ``None``."""
        if message.get("jsonrpc") != "2.0":
            return self._error(None, -32600, "Invalid JSON-RPC version; expected '2.0'")
        method = message.get("method")
        if not isinstance(method, str) or not method:
            return self._error(None, -32600, "Invalid JSON-RPC request method")

        if "id" not in message:
            return None

        req_id = message["id"]
        if not (
            type(req_id) is int
            or (
                isinstance(req_id, str)
                and len(req_id) <= MAX_REQUEST_ID_CHARS
                and _clean_text(req_id) == req_id
            )
        ):
            return self._error(None, -32600, "Invalid JSON-RPC request id")

        params = message.get("params")
        if method == "initialize":
            if params is not None and not isinstance(params, Mapping):
                return self._error(req_id, -32602, "initialize params must be an object")
            requested = params.get("protocolVersion") if isinstance(params, Mapping) else None
            negotiated = (
                requested
                if isinstance(requested, str) and requested in SUPPORTED_PROTOCOL_VERSIONS
                else SUPPORTED_PROTOCOL_VERSIONS[0]
            )
            return self._result(
                req_id,
                {
                    "protocolVersion": negotiated,
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {
                        "name": "nexus-symbiote-offline-mcp",
                        "version": __version__,
                    },
                    "instructions": (
                        "Read-only offline AgentBOM security query server. Secret values are "
                        "redacted, text is neutralized, and graph paths reflect static repository "
                        "associations rather than proven runtime reachability."
                    ),
                },
            )

        if method == "ping":
            return self._result(req_id, {})

        if method == "tools/list":
            if params is not None and not isinstance(params, Mapping):
                return self._error(req_id, -32602, "tools/list params must be an object")
            return self._result(req_id, {"tools": [dict(t) for t in _TOOLS]})

        if method == "tools/call":
            if not isinstance(params, Mapping):
                return self._error(req_id, -32602, "tools/call requires object params")
            name = params.get("name")
            raw_args = params.get("arguments")
            if raw_args is None:
                arguments: Mapping[str, Any] = {}
            elif isinstance(raw_args, Mapping):
                arguments = raw_args
            else:
                return self._error(req_id, -32602, "tools/call arguments must be an object")
            if not isinstance(name, str) or not name:
                return self._error(req_id, -32602, "tools/call requires non-empty string name")
            return self._dispatch_tool(req_id, name, arguments)

        return self._error(req_id, -32601, "Unsupported method")

    def _dispatch_tool(self, req_id: Any, name: str, args: Mapping[str, Any]) -> dict[str, Any]:
        validation_error = _validate_tool_args(name, args)
        if validation_error is not None:
            code = -32601 if name not in _TOOL_SCHEMAS else -32602
            return self._error(req_id, code, validation_error)
        try:
            if name == "inventory_summary":
                payload = self._tool_inventory_summary()
            elif name == "list_components":
                payload = self._tool_list_components(args)
            elif name == "get_findings":
                payload = self._tool_get_findings(args)
            elif name == "get_advisories":
                payload = self._tool_get_advisories(args)
            elif name == "blast_radius":
                payload = self._tool_blast_radius(args)
            elif name == "trifecta_flows":
                payload = self._tool_trifecta_flows(args)
            elif name == "evidence_profile":
                payload = self._tool_evidence_profile(args)
            else:
                payload = self._tool_minimum_elements(args)
        except (ValueError, RecursionError) as exc:
            return self._tool_result(req_id, {"error": _clean_text(exc)}, is_error=True)
        return self._tool_result(req_id, payload, is_error=False)

    def _tool_inventory_summary(self) -> dict[str, Any]:
        by_type: dict[str, int] = {}
        sev_counts: dict[str, int] = dict.fromkeys(_SEVERITY_ORDER, 0)
        for comp in self.bom.components:
            tname = comp.component_type.value
            by_type[tname] = by_type.get(tname, 0) + 1
            for risk in getattr(comp, "risks", []):
                sev = risk.severity.value
                sev_counts[sev] = sev_counts.get(sev, 0) + 1
        claim = self.bom.metadata.completeness
        cov = assess_coverage(claim)
        trifecta = self._trifecta()
        advisory_meta: dict[str, Any] = {
            "total": len(self._advisories),
            "kev": sum(1 for item in self._advisories if item.in_kev is True),
            "kev_unknown": sum(1 for item in self._advisories if item.in_kev is None),
        }
        if self.advisory_report is not None:
            advisory_meta["report"] = {
                "sha256": self.advisory_report.sha256,
                "coverage": self.advisory_report.coverage,
                "checked": self.advisory_report.checked,
                "skipped": self.advisory_report.skipped,
                "excluded": self.advisory_report.excluded,
                "errors": self.advisory_report.errors,
            }
        return {
            "spec_version": self.bom.metadata.spec_version,
            "inventory_sha256": self.inventory_sha256,
            "content_digest": self.content_digest,
            "total_components": len(self.bom.components),
            "total_dependencies": len(self.bom.dependencies),
            "coverage": cov.status.value,
            "surfaces_scanned_count": len(claim.surfaces_scanned) if claim else 0,
            "surfaces_excluded_count": len(claim.surfaces_excluded) if claim else 0,
            "scan_failures_count": len(claim.scan_failures) if claim else 0,
            "components_by_type": dict(sorted(by_type.items())),
            "findings_by_severity": sev_counts,
            "advisories": advisory_meta,
            "trifecta": {
                "scopes_evaluated": trifecta.scopes_evaluated,
                "finding_count": len(trifecta.findings),
                "has_critical": trifecta.has_critical,
                "shadowed_count": len(trifecta.shadowed_refs),
            },
            "limitations": [
                "Offline read-only view of a supplied AgentBOM; no live collection ran.",
                "Absence of findings reflects recorded evidence only, not proven benignness.",
            ],
        }

    def _tool_list_components(self, args: Mapping[str, Any]) -> dict[str, Any]:
        type_filter = args.get("component_type")
        name_filter = args.get("name_contains")
        min_sev = args.get("min_severity")
        assurance_filter = args.get("assurance_level")
        offset = args.get("offset", 0)
        limit = args.get("limit", DEFAULT_LIST_LIMIT)
        min_rank = _severity_rank(min_sev)

        matched: list[dict[str, Any]] = []
        for comp in sorted(self.bom.components, key=lambda c: c.bom_ref):
            if isinstance(type_filter, str) and comp.component_type.value != type_filter:
                continue
            if isinstance(assurance_filter, str) and comp.assurance_level.value != assurance_filter:
                continue
            if (
                isinstance(name_filter, str)
                and name_filter.lower() not in _clean_text(comp.name).lower()
            ):
                continue
            risks = list(getattr(comp, "risks", []))
            highest = _highest_sev(risks)
            if min_rank >= 0 and _severity_rank(highest) < min_rank:
                continue
            cls = classify(comp)
            purl = getattr(comp, "package_url", None)
            matched.append(
                {
                    "bom_ref": _clean_text(comp.bom_ref),
                    "name": _clean_text(comp.name),
                    "component_type": comp.component_type.value,
                    "version": _clean_text(comp.version) if comp.version else None,
                    "package_url": _clean_text(purl) if isinstance(purl, str) else None,
                    "assurance_level": comp.assurance_level.value,
                    "trust_tier": comp.trust_tier.value,
                    "risk_classes": [c.value for c in cls.classes],
                    "finding_count": len(risks),
                    "highest_severity": highest,
                    "advisory_count": len(self._advisories_by_ref.get(comp.bom_ref, ())),
                }
            )
        page = matched[offset : offset + limit]
        return {
            "total": len(matched),
            "offset": offset,
            "count": len(page),
            "truncated": offset + len(page) < len(matched),
            "components": page,
        }

    def _tool_get_findings(self, args: Mapping[str, Any]) -> dict[str, Any]:
        sev_filter = args.get("severity")
        cat_filter = args.get("category")
        ref_filter = args.get("component_ref")
        offset = args.get("offset", 0)
        limit = args.get("limit", DEFAULT_LIST_LIMIT)

        items: list[tuple[int, str, str, dict[str, Any]]] = []
        for comp in sorted(self.bom.components, key=lambda c: c.bom_ref):
            if isinstance(ref_filter, str) and comp.bom_ref != ref_filter:
                continue
            for risk in getattr(comp, "risks", []):
                if isinstance(sev_filter, str) and risk.severity.value != sev_filter:
                    continue
                if isinstance(cat_filter, str) and risk.category != cat_filter:
                    continue
                refs = crosswalk_references(risk.category, RiskSeverity(risk.severity.value))
                entry: dict[str, Any] = {
                    "component_ref": _clean_text(comp.bom_ref),
                    "component_name": _clean_text(comp.name),
                    "severity": risk.severity.value,
                    "category": _clean_text(risk.category),
                    "detail": _clean_text(risk.detail),
                    "recommendation": (
                        _clean_text(risk.recommendation) if risk.recommendation else None
                    ),
                    "frameworks": [{"framework": r.framework, "entry": r.entry} for r in refs],
                }
                items.append(
                    (-_severity_rank(risk.severity.value), comp.bom_ref, risk.category, entry)
                )
        items.sort(key=lambda row: (row[0], row[1], row[2], row[3]["detail"]))
        matched = [row[3] for row in items]
        page = matched[offset : offset + limit]
        return {
            "total": len(matched),
            "offset": offset,
            "count": len(page),
            "truncated": offset + len(page) < len(matched),
            "findings": page,
        }

    def _tool_get_advisories(self, args: Mapping[str, Any]) -> dict[str, Any]:
        ref_filter = args.get("component_ref")
        min_sev = args.get("min_severity")
        kev_only = args.get("kev_only") is True
        offset = args.get("offset", 0)
        limit = args.get("limit", DEFAULT_LIST_LIMIT)
        min_rank = _severity_rank(min_sev)

        matched = [
            entry.to_dict()
            for entry in self._advisories
            if (not isinstance(ref_filter, str) or entry.component_ref == ref_filter)
            and (min_rank < 0 or _severity_rank(entry.severity) >= min_rank)
            and (not kev_only or entry.in_kev is True)
        ]
        page = matched[offset : offset + limit]
        result: dict[str, Any] = {
            "total": len(matched),
            "offset": offset,
            "count": len(page),
            "truncated": offset + len(page) < len(matched),
            "advisories": page,
        }
        if self.advisory_report is not None:
            result["report"] = {
                "sha256": self.advisory_report.sha256,
                "coverage": self.advisory_report.coverage,
            }
        return result

    def _tool_blast_radius(self, args: Mapping[str, Any]) -> dict[str, Any]:
        component_ref = args["component_ref"]
        if all(comp.bom_ref != component_ref for comp in self.bom.components):
            # The graph error quotes the reference; tool errors never echo client input.
            raise ValueError("Unknown component_ref")
        raw = compute_blast_radius(self.bom, component_ref)
        reachable_set = {component_ref, *raw.get("reachable_components", [])}
        reachable_advisories = [
            entry.to_dict() for entry in self._advisories if entry.component_ref in reachable_set
        ]
        cleaned = _clean_value(raw)
        cleaned["reachable_advisories"] = reachable_advisories[:DEFAULT_MAX_ITEMS]
        cleaned["reachable_advisories_total"] = len(reachable_advisories)
        return dict(cleaned)

    def _tool_trifecta_flows(self, args: Mapping[str, Any]) -> dict[str, Any]:
        min_sev = args.get("min_severity")
        include_shadowing = args.get("include_shadowing", True)
        offset = args.get("offset", 0)
        limit = args.get("limit", DEFAULT_LIST_LIMIT)
        min_rank = _severity_rank(min_sev)

        report = self._trifecta()
        matched: list[dict[str, Any]] = []
        for finding in report.findings:
            if not include_shadowing and finding.kind == "tool_shadowing":
                continue
            if min_rank >= 0 and _severity_rank(finding.severity.value) < min_rank:
                continue
            matched.append(_clean_value(finding.to_dict()))
        page = matched[offset : offset + limit]
        return {
            "scopes_evaluated": report.scopes_evaluated,
            "has_critical": report.has_critical,
            "shadowed_refs": [_clean_text(ref) for ref in report.shadowed_refs],
            "total": len(matched),
            "offset": offset,
            "count": len(page),
            "truncated": offset + len(page) < len(matched),
            "findings": page,
        }

    def _tool_evidence_profile(self, args: Mapping[str, Any]) -> dict[str, Any]:
        ref_filter = args.get("component_ref")
        offset = args.get("offset", 0)
        limit = args.get("limit", DEFAULT_LIST_LIMIT)
        selected = self.bom
        if isinstance(ref_filter, str):
            selected = AIBOM(
                components=[comp for comp in self.bom.components if comp.bom_ref == ref_filter]
            )
        profile = build_evidence_profile(selected)
        components = profile["components"]
        page = components[offset : offset + limit]
        return {
            "schema": profile.get("schema"),
            "total": len(components),
            "offset": offset,
            "count": len(page),
            "truncated": offset + len(page) < len(components),
            "components": _clean_value(page),
        }

    def _tool_minimum_elements(self, args: Mapping[str, Any]) -> dict[str, Any]:
        offset = args.get("offset", 0)
        limit = args.get("limit", 25)
        report = assess_minimum_elements(self.bom)
        doc = report.to_dict()
        non_present = [
            _clean_value(el)
            for el in doc.get("elements", [])
            if isinstance(el, Mapping) and el.get("status") != "present"
        ]
        page = non_present[offset : offset + limit]
        return {
            "format": doc.get("format"),
            "edition": doc.get("edition"),
            "coverage": doc.get("coverage"),
            "counts": doc.get("counts"),
            "clusters": doc.get("clusters"),
            "non_present_total": len(non_present),
            "offset": offset,
            "count": len(page),
            "non_present_elements": page,
        }

    @staticmethod
    def _result(req_id: Any, payload: Mapping[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": req_id, "result": dict(payload)}

    @staticmethod
    def _tool_result(req_id: Any, payload: Mapping[str, Any], *, is_error: bool) -> dict[str, Any]:
        text = json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False)
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "content": [{"type": "text", "text": text}],
                "structuredContent": dict(payload),
                "isError": is_error,
            },
        }

    @staticmethod
    def _error(req_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {"code": code, "message": _clean_text(message)},
        }


def _read_exact(stream: IO[bytes], count: int) -> bytes:
    chunks: list[bytes] = []
    remaining = count
    while remaining > 0:
        piece = stream.read(remaining)
        if not piece:
            raise FrameError(-32700, "Truncated Content-Length frame body", fatal=True)
        chunks.append(piece)
        remaining -= len(piece)
    return b"".join(chunks)


def _read_content_length_frame(first_line: bytes, client_in: IO[bytes]) -> bytes:
    header_bytes = len(first_line)
    header_lines = 1
    content_length: int | None = None
    lines = [first_line]
    while True:
        stripped = lines[-1].rstrip(b"\r\n")
        if not stripped:
            break
        try:
            text = stripped.decode("ascii")
        except UnicodeDecodeError as exc:
            raise FrameError(-32700, "Invalid non-ASCII header in MCP frame", fatal=True) from exc
        match = _CONTENT_LENGTH_RE.fullmatch(text.strip())
        if match is not None:
            if content_length is not None:
                raise FrameError(-32700, "Duplicate Content-Length header", fatal=True)
            digits = match.group(1).lstrip("0")
            maximum = str(MAX_FRAME_BYTES)
            if not digits or (len(digits), digits) > (len(maximum), maximum):
                raise FrameError(
                    -32600,
                    f"Content-Length outside allowed range (1..{MAX_FRAME_BYTES})",
                    fatal=True,
                )
            content_length = int(digits)
        header_lines += 1
        if header_lines > MAX_HEADER_LINES:
            raise FrameError(-32700, "Too many headers before JSON-RPC body", fatal=True)
        nxt = client_in.readline(MAX_HEADER_BYTES + 1)
        header_bytes += len(nxt)
        if not nxt or header_bytes > MAX_HEADER_BYTES:
            raise FrameError(-32700, "Malformed or oversized header block", fatal=True)
        lines.append(nxt)
    if content_length is None:
        raise FrameError(-32700, "Missing Content-Length header", fatal=True)
    return _read_exact(client_in, content_length)


def _next_frame(client_in: IO[bytes]) -> tuple[bytes, Literal["ndjson", "content-length"]] | None:
    while True:
        line = client_in.readline(MAX_FRAME_BYTES + 1)
        if not line:
            return None
        if len(line) > MAX_FRAME_BYTES and not line.endswith(b"\n"):
            raise FrameError(
                -32600, f"JSON-RPC frame exceeds {MAX_FRAME_BYTES} byte limit", fatal=True
            )
        if not line.strip():
            continue
        lower = line.lstrip().lower()
        if lower.startswith(b"content-length:"):
            if len(line) > MAX_HEADER_BYTES:
                raise FrameError(-32700, "Header line exceeds byte limit", fatal=True)
            body = _read_content_length_frame(line, client_in)
            return body, "content-length"
        if len(line) > MAX_FRAME_BYTES:
            raise FrameError(
                -32600, f"JSON-RPC frame exceeds {MAX_FRAME_BYTES} byte limit", fatal=False
            )
        return line, "ndjson"


def _write_reply(
    client_out: IO[bytes], reply: Mapping[str, Any], framing: Literal["ndjson", "content-length"]
) -> None:
    payload = json.dumps(reply, separators=(",", ":"), sort_keys=True).encode("ascii")
    if framing == "content-length":
        header = f"Content-Length: {len(payload)}\r\n\r\n".encode("ascii")
        client_out.write(header + payload)
    else:
        client_out.write(payload + b"\n")
    client_out.flush()


def run_mcp_server_streams(
    server: OfflineMCPServer,
    *,
    client_in: IO[bytes],
    client_out: IO[bytes],
    max_requests: int = DEFAULT_MAX_REQUESTS,
) -> None:
    """Serve bounded synchronous JSON-RPC 2.0 MCP traffic over binary streams."""
    if type(max_requests) is not int or not 1 <= max_requests <= MAX_ALLOWED_REQUESTS:
        raise ValueError(f"max_requests must be between 1 and {MAX_ALLOWED_REQUESTS}")
    last_framing: Literal["ndjson", "content-length"] = "ndjson"
    processed = 0
    while processed < max_requests:
        try:
            nxt = _next_frame(client_in)
        except FrameError as exc:
            _write_reply(
                client_out,
                OfflineMCPServer._error(None, exc.code, str(exc)),
                last_framing,
            )
            if exc.fatal:
                break
            processed += 1
            continue
        if nxt is None:
            break
        raw_frame, framing = nxt
        last_framing = framing
        processed += 1
        try:
            text = raw_frame.decode("utf-8")
            if json_nesting_exceeds(text, MAX_FRAME_DEPTH):
                reply: dict[str, Any] | None = OfflineMCPServer._error(
                    None, -32600, f"JSON-RPC request exceeds depth limit ({MAX_FRAME_DEPTH})"
                )
            else:
                parsed = parse_json_strict(text, max_bytes=MAX_FRAME_BYTES)
                if not isinstance(parsed, dict):
                    reply = OfflineMCPServer._error(
                        None, -32600, "JSON-RPC message must be a JSON object"
                    )
                else:
                    reply = server.handle_message(parsed)
        except (ValueError, RecursionError, UnicodeError):
            reply = OfflineMCPServer._error(None, -32700, "Parse error")
        if reply is not None:
            _write_reply(client_out, reply, framing)
