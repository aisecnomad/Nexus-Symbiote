"""Reconcile the runtime use that traces report with what a native inventory declares.

Telemetry is a report by the agent's own instrumentation (see ``otlp``). The evidence
names the tools, models, agents and MCP endpoints, skills, data sources, memory stores
and prompts that the traces report, and whether the inventory declares each one under
fixed, conservative matching rules. Its assurance is ``reported``: never ``observed`` or
``verified``. A span shows at most that the instrumentation reported an operation; a
declaration no span mentions may still be used; matching is by name and reported
endpoint, not by cryptographic identity. The inventory is read, never changed.
"""

from __future__ import annotations

import heapq
import json
from collections import Counter, defaultdict
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from itertools import islice
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from nexus_symbiote.core.aibom import AIBOM, MAX_NATIVE_BYTES
from nexus_symbiote.core.collection import SOURCE_REFERENCE_MODE
from nexus_symbiote.core.content_digest import INVENTORY_CONTENT_PROFILE, inventory_content_digest
from nexus_symbiote.core.hashing import (
    hash_bytes,
    hash_canonical,
    normalize_digest,
    parse_json_strict,
)
from nexus_symbiote.core.identifiers import name_key, recorded_name_key
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    MCPServerComponent,
    ModelComponent,
    ToolComponent,
)
from nexus_symbiote.graph import INFERRED_AGENT_REF, _repository_agent_ref
from nexus_symbiote.otlp import (
    GENAI_OPERATIONS,
    MAX_ATTRIBUTES,
    MAX_IDENTIFIER_CHARS,
    MCP_METHODS,
    SPAN_KIND_CLIENT,
    Identifier,
    Span,
    TraceInputError,
    TraceReader,
    Unreadable,
    file_name,
)
from nexus_symbiote.risk_classes import plain_authority
from nexus_symbiote.scanners.source_references import split_route

FORMAT = "nexus-symbiote/trace-evidence/v1"
ASSURANCE = "reported"
CATEGORY = "runtime_undeclared"
FAIL_ON = ("undeclared", "none")
LISTED_CANDIDATES = 10
MAX_DISTINCT_IDENTIFIERS = 100_000
GATING_KINDS = frozenset({"agent", "mcp-endpoint", "model", "tool"})
LIMITATIONS = (
    "Telemetry is emitted by the agent's own instrumentation: it is a report, not an "
    "independent observation.",
    "Traces can be incomplete, sampled or forged by the code they describe.",
    "A span proves at most that the instrumentation reported an operation.",
    "Absence of a span proves nothing: a declaration that no span mentions may still be used.",
    "Matching is by name and reported endpoint, not by cryptographic identity.",
    "A trace cannot attribute stdio MCP activity to a configured server.",
    "Span events, links and log records are not read, so content they carry is not counted.",
)
_FIELDS = {
    "agent": ("id", "name"),
    "data-source": ("id",),
    "mcp-endpoint": ("host", "port"),
    "memory-store": ("id",),
    "model": ("provider", "model"),
    "prompt": ("name",),
    "skill": ("name",),
    "tool": ("name", "host", "port", "transport"),
}
_DETAILS = {
    "agent": "versions",
    "mcp-endpoint": "protocol_versions",
    "model": "resolved_models",
    "tool": "tool_types",
}
_NAMED = (
    ("skill", "gen_ai.skill.name"),
    ("data-source", "gen_ai.data_source.id"),
    ("memory-store", "gen_ai.memory.store.id"),
    ("prompt", "gen_ai.prompt.name"),
)
_NAMED_TYPES = {
    "skill-package": "skill",
    "rag-source": "data-source",
    "data-source": "data-source",
    "memory-store": "memory-store",
    "prompt-template": "prompt",
}
SARIF_HELP = (
    "The result comes from the agent's own telemetry, not from the inventory: its "
    "instrumentation reported the use (assurance reported), which was not observed or "
    "verified. Status undeclared means that no inventory entry matches the reported name "
    "and endpoint; status unidentified means that an identifier could not be read, so "
    "whether the inventory declares the component is unknown. A missing span proves "
    "nothing, and a result does not establish exploitability."
)
SARIF_HELP_URI = (
    "https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/trace-evidence.md#sarif"
)
_LOCAL_TRANSPORTS = ("pipe", "unix")
# Names that instrumentations and model routers give a provider, to the one OpenTelemetry's
# gen_ai.provider.name gives it, so that each side's spelling finds the other.
_PROVIDER_ALIASES = {
    "aws-bedrock": "aws.bedrock", "az.ai.openai": "azure.ai.openai", "azure": "azure.ai.openai",
    "azure-openai": "azure.ai.openai", "bedrock": "aws.bedrock", "gemini": "gcp.gemini",
    "google-vertex-ai": "gcp.vertex_ai", "mistral": "mistral_ai", "vertex_ai": "gcp.vertex_ai",
    "watsonx": "ibm.watsonx.ai", "xai": "x_ai",
}  # fmt: skip
_DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}
_TRIM = " \t\r\n"
_EPOCH = datetime(1970, 1, 1, tzinfo=UTC)
_RECONCILIATION = (
    "matched",
    "undeclared",
    "unidentified",
    "ambiguous",
    "unobserved",
    "unmatched_identifiers",
)

Values = tuple[Identifier | None, ...]


@dataclass
class _Item:
    kind: str
    values: Values
    spans: int = 0
    first: int | None = None
    last: int | None = None
    files: set[int] = field(default_factory=set)
    operations: set[str] = field(default_factory=set)
    services: set[str] = field(default_factory=set)
    details: set[str] = field(default_factory=set)
    workload_identities: set[str] = field(default_factory=set)
    caller_identities: set[str] = field(default_factory=set)
    definition_hashes: set[str] = field(default_factory=set)
    runtime_pairs: set[tuple[str, str]] = field(default_factory=set)
    unreadable_workload_identities: int = 0
    unreadable_definition_hashes: int = 0


def _enum_name(value: Identifier, members: frozenset[str]) -> str:
    return value if isinstance(value, str) and value in members else "other"


def _host(address: Identifier) -> Identifier:
    if isinstance(address, Unreadable):
        return address
    host = address.lower()
    return host[1:-1] if host.startswith("[") and host.endswith("]") else host


def _endpoint_text(host: str | None, port: str | None) -> str | None:
    if host is None:
        return None
    shown = f"[{host}]" if ":" in host else host
    return shown if port is None else f"{shown}:{port}"


class Observations:
    """Spans folded into one item per kind and identity, with extraction counters.

    Every item and every distinct service, version or resolved model it records counts
    against ``MAX_DISTINCT_IDENTIFIERS``, so memory stays bounded whatever the traces
    name; exceeding it refuses the traces rather than dropping what they report.
    """

    def __init__(self) -> None:
        self.items: dict[tuple[str, Values], _Item] = {}
        self.distinct = 0
        self.operation_names: Counter[str] = Counter()
        self.mcp_method_names: Counter[str] = Counter()
        self.legacy_system = 0
        self.mcp_clients: Counter[str] = Counter()
        self.without_identifier: Counter[str] = Counter()
        self.unclassified = 0
        self.first: int | None = None
        self.last: int | None = None

    def add(self, span: Span) -> None:
        values = span.attributes
        operation = values.get("gen_ai.operation.name")
        method = values.get("mcp.method.name")
        # A value that decides what a span is, and that could not be read, may hide a
        # tool or agent call, or the remote endpoint of one.
        unclassified = isinstance(operation, Unreadable) or isinstance(method, Unreadable)
        names: set[str] = set()
        if operation is not None:
            names.add(_enum_name(operation, GENAI_OPERATIONS))
            self.operation_names[_enum_name(operation, GENAI_OPERATIONS)] += 1
        if method is not None:
            names.add(_enum_name(method, MCP_METHODS))
            self.mcp_method_names[_enum_name(method, MCP_METHODS)] += 1
        if span.start is not None:
            self.first = span.start if self.first is None else min(self.first, span.start)
            self.last = span.start if self.last is None else max(self.last, span.start)
        transport = values.get("network.transport")
        address = values.get("server.address")
        local = transport if transport in _LOCAL_TRANSPORTS else None
        # A tool call that reports a server address is compared only with the tools served
        # there, whatever the span's kind, unless its transport is pipe or unix: the address
        # may name another server.
        host: Identifier | None = None
        port: Identifier | None = None
        if address is not None and local is None:
            host, port = _host(address), values.get("server.port")
        if method is not None and span.kind == SPAN_KIND_CLIENT:
            if local is not None:
                self.mcp_clients["stdio"] += 1
            elif isinstance(transport, Unreadable) and address is not None:
                self.mcp_clients["unattributed"] += 1
                unclassified = True
            elif host is not None:
                self.mcp_clients["attributed"] += 1
                version = values.get("mcp.protocol.version")
                self._observe(span, names, "mcp-endpoint", (host, port), version)
            else:
                self.mcp_clients["unattributed"] += 1
        # A span that names a tool reports a call to it whatever it calls its operation:
        # instrumentation may omit the operation name or use a value of its own.
        tool = values.get("gen_ai.tool.name")
        if tool is not None or operation == "execute_tool" or method == "tools/call":
            if tool is None:
                self.without_identifier["tool"] += 1
            else:
                # Read, the transport could make this a call over a pipe or unix socket,
                # which the tools of a server with only a remote endpoint do not serve.
                unclassified = unclassified or isinstance(transport, Unreadable)
                kind = values.get("gen_ai.tool.type")
                self._observe(span, names, "tool", (tool, host, port, local), kind)
        if unclassified:
            self.unclassified += 1
        requested = values.get("gen_ai.request.model")
        response = values.get("gen_ai.response.model")
        if requested is not None or response is not None:
            provider = values.get("gen_ai.provider.name")
            if provider is None and values.get("gen_ai.system") is not None:
                provider = values["gen_ai.system"]
                self.legacy_system += 1
            resolved = (
                response
                if isinstance(requested, str)
                and isinstance(response, str)
                and response != requested
                else None
            )
            model = requested if requested is not None else response
            self._observe(span, names, "model", (provider, model), resolved)
        ident = values.get("gen_ai.agent.id")
        name = values.get("gen_ai.agent.name")
        named = ident is not None or name is not None
        standalone_agent = (
            operation is None
            and method is None
            and tool is None
            and requested is None
            and response is None
            and all(values.get(k) is None for _, k in _NAMED)
        )
        # Spans of other known operations may carry the name of the agent they run in, so
        # only an operation name outside the convention (or a standalone agent span) reports one.
        custom = (
            isinstance(operation, str) and operation not in GENAI_OPERATIONS
        ) or standalone_agent
        if operation in ("create_agent", "invoke_agent") or (custom and named):
            if not named:
                self.without_identifier["agent"] += 1
            else:
                version = values.get("gen_ai.agent.version")
                self._observe(span, names, "agent", (ident, name), version)
        for kind, key in _NAMED:
            value = values.get(key)
            if value is not None:
                self._observe(span, names, kind, (value,))

    def _observe(
        self,
        span: Span,
        names: set[str],
        kind: str,
        values: Values,
        detail: Identifier | None = None,
    ) -> None:
        item = self.items.get((kind, values))
        if item is None:
            self._record(span)
            item = self.items[(kind, values)] = _Item(kind, values)
        item.spans += 1
        item.files.add(span.file)
        item.operations.update(names)
        if isinstance(span.service, str) and span.service not in item.services:
            self._record(span)
            item.services.add(span.service)
        if isinstance(detail, str) and detail not in item.details:
            self._record(span)
            item.details.add(detail)
        # A CLIENT or PRODUCER span names the component it calls: its own (and its
        # resource's) spiffe.id is the caller's, reported apart, and only peer.identity
        # is compared as the callee's. An unreadable identity gates on every kind.
        client, own = span.kind in (3, 4), span.attributes.get("spiffe.id")
        callee_id = span.attributes.get("peer.identity") if client else own
        for w_id, seen in (
            (callee_id, item.workload_identities),
            (own if client else None, item.caller_identities),
        ):
            if isinstance(w_id, Unreadable):
                item.unreadable_workload_identities += 1
            elif isinstance(w_id, str) and w_id not in seen:
                self._record(span)
                seen.add(w_id)
        if kind == "tool":
            t_hash = span.attributes.get("gen_ai.tool.definition_hash")
            if isinstance(t_hash, Unreadable):
                item.unreadable_definition_hashes += 1
            elif isinstance(t_hash, str):
                if t_hash not in item.definition_hashes:
                    self._record(span)
                    item.definition_hashes.add(t_hash)
                if isinstance(callee_id, str) and (callee_id, t_hash) not in item.runtime_pairs:
                    self._record(span)
                    item.runtime_pairs.add((callee_id, t_hash))
        if span.start is not None:
            item.first = span.start if item.first is None else min(item.first, span.start)
            item.last = span.start if item.last is None else max(item.last, span.start)

    def _record(self, span: Span) -> None:
        self.distinct += 1
        if self.distinct > MAX_DISTINCT_IDENTIFIERS:
            raise TraceInputError(
                span.file,
                f"exceeds the bound of {MAX_DISTINCT_IDENTIFIERS:,} distinct identifiers "
                "recorded across all trace files",
            )


def _identity(kind: str, values: Values) -> dict[str, Any]:
    """An item's kind and identifying fields; unreadable ones are null and named apart."""
    named = dict(zip(_FIELDS[kind], values, strict=True))
    unreadable = {
        key: value.reason for key, value in named.items() if isinstance(value, Unreadable)
    }
    shown = {key: None if isinstance(value, Unreadable) else value for key, value in named.items()}
    if kind == "tool":
        local = shown["transport"]
        shown = {"name": shown["name"], "endpoint": _endpoint_text(shown["host"], shown["port"])}
        if local is not None:
            shown["transport"] = local
    entry: dict[str, Any] = {"kind": kind, **shown}
    if unreadable:
        entry["unreadable"] = unreadable
    return entry


def _time(nanoseconds: int | None) -> str | None:
    if nanoseconds is None:
        return None
    seconds, fraction = divmod(nanoseconds, 1_000_000_000)
    moment = _EPOCH + timedelta(seconds=seconds)
    return moment.strftime("%Y-%m-%dT%H:%M:%S") + f".{fraction:09d}Z"


def _provider_key(provider: str) -> str:
    lowered = provider.lower()
    return _PROVIDER_ALIASES.get(lowered, lowered)


def _trimmed(value: str | None) -> str | None:
    text = value.strip(_TRIM) if value is not None else ""
    return text or None


def _endpoint(url: str | None) -> tuple[str, int | None] | None:
    """The host and port a declared URL names, when every URL parser reads them alike.

    An inventory is supplied, so its URL may be one that Python and the client that
    connects read differently, such as ``https://approved\\@other.example``; such a URL
    declares no host for a span to match. A URL that states no port and has no default
    one declares its host only.
    """
    if not url or "\\" in url or any(ch <= " " or ch == "\x7f" for ch in url):
        return None
    try:
        parts = urlsplit(url)
        host, port = parts.hostname, parts.port
    except ValueError:
        return None
    if not parts.scheme or not host or not plain_authority(parts.netloc) or port == 0:
        return None
    return host, port if port is not None else _DEFAULT_PORTS.get(parts.scheme.lower())


def _inferred(agent: AgentComponent) -> bool:
    """The repository agent assembled without a manifest: it names no runtime agent."""
    source = agent.properties.get("identity_source")
    return source == "repository-path" or (
        source != "agent.yaml" and agent.bom_ref == INFERRED_AGENT_REF
    )


def _text(value: Identifier | None) -> str | None:
    # Items with an unreadable identifier never reach matching.
    assert not isinstance(value, Unreadable)
    return value


def _ref(component: AnyComponent) -> str:
    return component.bom_ref


_NONE: list[AnyComponent] = []
Candidates = list[tuple[list[AnyComponent], str]]


class _Inventory:
    """The inventory indexed once: each candidate set is one or two prebuilt sorted lists.

    A lookup costs the same whatever the inventory's size, a bounded number of candidates
    is listed from the heads of the lists, and the lists belong to the index, so marking
    them as mentioned costs the inventory's size once, not once per observed item.
    """

    def __init__(self, bom: AIBOM) -> None:
        groups: dict[str, dict[Any, list[AnyComponent]]] = defaultdict(lambda: defaultdict(list))
        endpoints: dict[str, tuple[str, int | None]] = {}
        remote_only: set[str] = set()
        tools: list[tuple[tuple[str, str], ToolComponent]] = []
        self.declared: list[tuple[str, AnyComponent]] = []
        for component in bom.components:
            trimmed = _trimmed(component.name)
            # Names are compared by raw text: a name collection neutralized is keyed by
            # the digest it recorded, never by the text it reads as now.
            name = None if trimmed is None else recorded_name_key(component, trimmed)
            if isinstance(component, MCPServerComponent):
                self.declared.append(("mcp-server", component))
                endpoint = _endpoint(component.endpoint_url)
                local = component.command is not None or _trimmed(component.transport) == "stdio"
                # An endpoint the collector withheld as [redacted] is still a remote endpoint.
                if _trimmed(component.endpoint_url) is not None and not local:
                    remote_only.add(component.bom_ref)
                if endpoint is not None:
                    host, port = endpoints[component.bom_ref] = endpoint
                    groups["servers_on"][host].append(component)
                    if port is None:
                        groups["servers_open"][host].append(component)
                    else:
                        groups["servers_at"][(host, port)].append(component)
            elif isinstance(component, ToolComponent):
                self.declared.append(("tool", component))
                if name is not None:
                    groups["tools"][name].append(component)
                    tools.append((name, component))
            elif isinstance(component, ModelComponent):
                if component.model_type == "hosted":
                    self.declared.append(("model", component))
                provider = _trimmed(component.provider)
                keys = {name} if name is not None else set()
                alias = _trimmed(component.requested_alias)
                if alias is not None:
                    keys.add(name_key(alias))
                aliases = component.properties.get("requested_aliases")
                if (
                    component.properties.get("collection_mode") == SOURCE_REFERENCE_MODE
                    and provider is not None
                    and isinstance(aliases, list)
                ):
                    # A property only contributes alternative routes to this declared model.
                    for route in aliases:
                        if (
                            isinstance(route, str)
                            and len(route) <= MAX_IDENTIFIER_CHARS
                            and split_route(route) == (component.name, provider)
                        ):
                            keys.add(name_key(route))
                for key in keys:
                    groups["models"][key].append(component)
                    if provider is None:
                        groups["models_open"][key].append(component)
                    else:
                        groups["models_for"][(key, _provider_key(provider))].append(component)
            elif isinstance(component, AgentComponent) and not _inferred(component):
                self.declared.append(("agent", component))
                # A manifest that declares an id derives the agent's reference from it.
                bound = (
                    component.properties.get("identity_source") == "agent.yaml"
                    and component.bom_ref != INFERRED_AGENT_REF
                )
                if bound:
                    groups["agent_ids"][component.bom_ref].append(component)
                if name is not None:
                    groups["agents"][name].append(component)
                    if not bound:
                        groups["agents_unbound"][name].append(component)
            elif component.component_type.value in _NAMED_TYPES and name is not None:
                groups[_NAMED_TYPES[component.component_type.value]][name].append(component)
        for name, tool in tools:
            if tool.mcp_server_ref not in remote_only:
                groups["tools_local"][name].append(tool)
            served = endpoints.get(tool.mcp_server_ref or "")
            if served is not None:
                host, port = served
                groups["tools_on"][(name, host)].append(tool)
                if port is None:
                    groups["tools_open"][(name, host)].append(tool)
                else:
                    groups["tools_at"][(name, host, port)].append(tool)
        self.index = {
            table: {key: sorted(found, key=_ref) for key, found in group.items()}
            for table, group in groups.items()
        }

    def _get(self, table: str, key: object) -> list[AnyComponent]:
        return self.index.get(table, {}).get(key, _NONE)

    def candidates(self, kind: str, values: Values) -> Candidates:
        """The candidate lists for one item, each with the basis a match on it has."""
        texts = [_text(value) for value in values]
        if kind == "tool":
            raw, host, port, local = texts
            name = None if raw is None else name_key(raw)
            if local is not None:
                # A pipe or unix socket cannot reach a server that has only a remote endpoint.
                return [(self._get("tools_local", name), "name")]
            if host is None:
                return [(self._get("tools", name), "name")]
            # A call to a reported endpoint matches only tools that a server there declares:
            # the same name declared on another server is a different tool (shadowing).
            # Without a port on one side, only the host was compared, and the basis says so.
            ladder: list[tuple[str, object, str]] = (
                [
                    ("tools_at", (name, host, int(port)), "name-and-endpoint"),
                    ("tools_open", (name, host), "name-and-host"),
                ]
                if port is not None
                else [("tools_on", (name, host), "name-and-host")]
            )
            for table, key, basis in ladder:
                if found := self._get(table, key):
                    return [(found, basis)]
            return []
        if kind == "mcp-endpoint":
            host, port = texts
            if port is None:
                return [(self._get("servers_on", host), "host")]
            if exact := self._get("servers_at", (host, int(port))):
                return [(exact, "host-and-port")]
            return [(self._get("servers_open", host), "host")]
        if kind == "model":
            provider, raw = texts
            model = None if raw is None else name_key(raw)
            if provider is None:
                return [(self._get("models", model), "name")]
            if exact := self._get("models_for", (model, _provider_key(provider))):
                return [(exact, "name-and-provider")]
            return [(self._get("models_open", model), "name")]
        if kind == "agent":
            ident, agent = texts
            if ident is not None and (
                exact := self._get("agent_ids", _repository_agent_ref(ident))
            ):
                return [(exact, "id")]
            if agent is not None:
                # When both sides state an id, the ids decide.
                table = "agents" if ident is None else "agents_unbound"
                return [(self._get(table, name_key(agent)), "name")]
            return []
        named = texts[0]
        return [(self._get(kind, None if named is None else name_key(named)), "name")]


def _order(entry: Mapping[str, Any]) -> tuple[str, str]:
    return str(entry["kind"]), json.dumps(entry, sort_keys=True)


def _normalized_sha256(value: str) -> str | None:
    try:
        alg, dig = normalize_digest(value.strip(_TRIM), "sha256")
    except ValueError:
        return None
    return f"{alg}:{dig}"


def _is_mismatched(entry: Mapping[str, Any]) -> bool:
    return (
        entry.get("workload_identity_matched") is False
        or entry.get("definition_hash_matched") is False
    )


@dataclass(frozen=True)
class _RuntimeSummary:
    """What the runtime checks read from a candidate list, computed once per list.

    An ambiguous item's candidates are the index's own lists, which many items share, so
    summarizing each list once keeps a lookup's cost independent of the inventory's size.
    """

    identities: frozenset[str]
    every_identity_declared: bool
    tool_count: int
    every_tool_hashed: bool
    tool_hashes: frozenset[str]
    tool_tuples: frozenset[tuple[str | None, str | None]] = frozenset()


def _declared_workload_identity(
    comp: AnyComponent, server_identities: Mapping[str, str]
) -> str | None:
    own = getattr(comp, "workload_identity", None)
    if isinstance(own, str) and (trimmed := _trimmed(own)):
        return trimmed
    prop = comp.properties.get("workload_identity")
    if isinstance(prop, str) and (trimmed := _trimmed(prop)):
        return trimmed
    if isinstance(comp, ToolComponent) and comp.mcp_server_ref:
        return server_identities.get(comp.mcp_server_ref)
    return None


def _summarize_runtime(
    candidates: Sequence[AnyComponent],
    server_identities: Mapping[str, str] | None = None,
) -> _RuntimeSummary:
    lookup = server_identities or {}
    identities: set[str] = set()
    every_identity_declared = True
    tool_count = 0
    every_tool_hashed = True
    tool_hashes: set[str] = set()
    tool_tuples: set[tuple[str | None, str | None]] = set()
    for comp in candidates:
        declared = _declared_workload_identity(comp, lookup)
        if declared is None:
            every_identity_declared = False
        else:
            identities.add(declared)
        if isinstance(comp, ToolComponent):
            tool_count += 1
            norm_hash: str | None = None
            if not comp.definition_hash:
                every_tool_hashed = False
            else:
                norm_hash = _normalized_sha256(comp.definition_hash)
                if norm_hash:
                    tool_hashes.add(norm_hash)
                else:
                    # Malformed declared hash must fail closed (never wildcard-match None).
                    norm_hash = ""
            tool_tuples.add((declared, norm_hash))
    return _RuntimeSummary(
        frozenset(identities),
        every_identity_declared,
        tool_count,
        every_tool_hashed,
        frozenset(tool_hashes),
        frozenset(tool_tuples),
    )


def _merge_runtime(summaries: Iterable[_RuntimeSummary]) -> _RuntimeSummary:
    identities: set[str] = set()
    every_identity_declared = True
    tool_count = 0
    every_tool_hashed = True
    tool_hashes: set[str] = set()
    tool_tuples: set[tuple[str | None, str | None]] = set()
    for summary in summaries:
        identities |= summary.identities
        every_identity_declared = every_identity_declared and summary.every_identity_declared
        tool_count += summary.tool_count
        every_tool_hashed = every_tool_hashed and summary.every_tool_hashed
        tool_hashes |= summary.tool_hashes
        tool_tuples |= summary.tool_tuples
    return _RuntimeSummary(
        frozenset(identities),
        every_identity_declared,
        tool_count,
        every_tool_hashed,
        frozenset(tool_hashes),
        frozenset(tool_tuples),
    )


def _apply_runtime_checks(entry: dict[str, Any], item: _Item, summary: _RuntimeSummary) -> None:
    """Attach workload-identity and tool-definition-hash match checks for candidate components."""
    if item.workload_identities or item.unreadable_workload_identities:
        entry["reported_workload_identities"] = sorted(item.workload_identities)
        if item.unreadable_workload_identities:
            entry["unreadable_workload_identities"] = item.unreadable_workload_identities
            entry["workload_identity_matched"] = False
        elif summary.every_identity_declared:
            entry["workload_identity_matched"] = item.workload_identities <= summary.identities
        else:
            entry["workload_identity_matched"] = None
    if (item.definition_hashes or item.unreadable_definition_hashes) and summary.tool_count:
        entry["reported_definition_hashes"] = sorted(item.definition_hashes)
        reported_norm = {_normalized_sha256(h) for h in item.definition_hashes}
        if item.unreadable_definition_hashes:
            entry["unreadable_definition_hashes"] = item.unreadable_definition_hashes
            entry["definition_hash_matched"] = False
        elif None in reported_norm:
            entry["definition_hash_matched"] = False
        elif summary.every_tool_hashed:
            entry["definition_hash_matched"] = (
                bool(summary.tool_hashes) and reported_norm <= summary.tool_hashes
            )
        else:
            entry["definition_hash_matched"] = None
    if item.runtime_pairs and summary.tool_tuples and not _is_mismatched(entry):
        for obs_wid, raw_hash in item.runtime_pairs:
            obs_hash = _normalized_sha256(raw_hash)
            if obs_hash is None or not any(
                (c_wid is None or c_wid == obs_wid) and (c_hash is None or c_hash == obs_hash)
                for c_wid, c_hash in summary.tool_tuples
            ):
                entry["workload_identity_matched"] = False
                entry["definition_hash_matched"] = False
                break
    if _is_mismatched(entry):
        entry["span_count"] = item.spans


def reconcile(observations: Observations, bom: AIBOM) -> dict[str, list[dict[str, Any]]]:
    """Sort every observed item into one reconciliation list, and list unmentioned declarations.

    An item with an unreadable identifier is ``unidentified``. Otherwise one candidate is a
    match, several are ``ambiguous`` (neither matched nor undeclared; at most
    ``LISTED_CANDIDATES`` are listed), and none makes a tool, model, agent or MCP endpoint
    ``undeclared`` and any other kind an ``unmatched_identifier``. Declared tools, MCP
    servers, hosted models and named agents that no item names are ``unobserved``.
    """
    inventory = _Inventory(bom)
    server_identities: dict[str, str] = {}
    for comp in bom.components:
        if isinstance(comp, MCPServerComponent):
            raw_wid = comp.properties.get("workload_identity")
            if isinstance(raw_wid, str) and (wid := _trimmed(raw_wid)):
                server_identities[comp.bom_ref] = wid
    result: dict[str, list[dict[str, Any]]] = {name: [] for name in _RECONCILIATION}
    mentioned: set[str] = set()
    marked: set[int] = set()
    summaries: dict[int, _RuntimeSummary] = {}
    merges: dict[tuple[int, ...], _RuntimeSummary] = {}
    for item in observations.items.values():
        identity = _identity(item.kind, item.values)
        if "unreadable" in identity:
            result["unidentified"].append({**identity, "span_count": item.spans})
            continue
        parts = inventory.candidates(item.kind, item.values)
        for found, _basis in parts:
            if id(found) not in marked:
                marked.add(id(found))
                mentioned.update(component.bom_ref for component in found)
        count = sum(len(found) for found, _basis in parts)
        if count == 1:
            component, basis = next((found[0], basis) for found, basis in parts if found)
            matched_entry: dict[str, Any] = {
                **identity,
                "inventory_ref": component.bom_ref,
                "basis": basis,
            }
            if item.caller_identities:
                matched_entry["caller_workload_identities"] = sorted(item.caller_identities)
            _apply_runtime_checks(
                matched_entry, item, _summarize_runtime((component,), server_identities)
            )
            result["matched"].append(matched_entry)
            server = getattr(component, "mcp_server_ref", None)
            if isinstance(server, str):
                mentioned.add(server)
        elif count:
            heads = heapq.merge(*(found for found, _basis in parts), key=_ref)
            listed = [component.bom_ref for component in islice(heads, LISTED_CANDIDATES)]
            ambiguous_entry: dict[str, Any] = {
                **identity,
                "candidates": listed,
                "candidates_omitted": count - len(listed),
            }
            if (
                item.workload_identities
                or item.unreadable_workload_identities
                or item.definition_hashes
                or item.unreadable_definition_hashes
            ):
                part_summaries: list[_RuntimeSummary] = []
                for found, _basis in parts:
                    summary = summaries.get(id(found))
                    if summary is None:
                        summary = summaries[id(found)] = _summarize_runtime(
                            found, server_identities
                        )
                    part_summaries.append(summary)
                # A merge copies every identity and hash, so it is made once per
                # combination of lists, not once per item.
                key = tuple(id(found) for found, _basis in parts)
                merged = part_summaries[0] if len(part_summaries) == 1 else merges.get(key)
                if merged is None:
                    merged = merges[key] = _merge_runtime(part_summaries)
                _apply_runtime_checks(ambiguous_entry, item, merged)
            result["ambiguous"].append(ambiguous_entry)
        elif item.kind in GATING_KINDS:
            result["undeclared"].append({**identity, "span_count": item.spans})
        else:
            result["unmatched_identifiers"].append({**identity, "span_count": item.spans})
    result["unobserved"] = [
        {"kind": kind, "inventory_ref": component.bom_ref, "name": component.name}
        for kind, component in inventory.declared
        if component.bom_ref not in mentioned
    ]
    return {name: sorted(entries, key=_order) for name, entries in result.items()}


def _observed(observations: Observations) -> list[dict[str, Any]]:
    entries = []
    for item in observations.items.values():
        entry = {
            **_identity(item.kind, item.values),
            "span_count": item.spans,
            "first_seen": _time(item.first),
            "last_seen": _time(item.last),
            "trace_files": sorted(item.files),
            "operations": sorted(item.operations),
            "services": sorted(item.services),
        }
        if item.kind in _DETAILS:
            entry[_DETAILS[item.kind]] = sorted(item.details)
        if item.workload_identities:
            entry["workload_identities"] = sorted(item.workload_identities)
        if item.definition_hashes:
            entry["definition_hashes"] = sorted(item.definition_hashes)
        entries.append(entry)
    return sorted(entries, key=_order)


def _coverage(reader: TraceReader, observations: Observations) -> dict[str, Any]:
    first, last = _time(observations.first), _time(observations.last)
    return {
        "trace_files": len(reader.files),
        "records": sum(record.records for record in reader.files),
        "resource_spans": reader.resource_spans,
        "spans_read": reader.spans,
        "genai_or_mcp_spans": reader.semantic_spans,
        "spans_ignored": reader.spans - reader.semantic_spans,
        "operation_names": dict(sorted(observations.operation_names.items())),
        "mcp_method_names": dict(sorted(observations.mcp_method_names.items())),
        "legacy_attributes": {"gen_ai.system": observations.legacy_system},
        "spans_with_content_attributes": reader.content_spans,
        "attribute_lists_over_bound": reader.lists_over_bound,
        "unreadable_identifiers": {
            reason: reader.unreadable[reason] for reason in ("invalid", "oversized", "withheld")
        },
        "spans_without_identifier": {
            kind: observations.without_identifier[kind] for kind in ("agent", "tool")
        },
        "spans_unclassified": observations.unclassified,
        "mcp_client_spans": {
            kind: observations.mcp_clients[kind] for kind in ("attributed", "stdio", "unattributed")
        },
        "time_range": None if first is None else {"first": first, "last": last},
    }


def _gate(
    reconciliation: Mapping[str, list[dict[str, Any]]], coverage: Mapping[str, Any], fail_on: str
) -> dict[str, Any]:
    reasons: list[str] = []
    if fail_on == "undeclared":
        undeclared = len(reconciliation["undeclared"])
        unidentified = sum(
            1 for entry in reconciliation["unidentified"] if entry["kind"] in GATING_KINDS
        )
        mismatched = sum(
            1
            for bucket in ("matched", "ambiguous")
            for entry in reconciliation[bucket]
            if _is_mismatched(entry)
        )
        if undeclared:
            reasons.append(
                f"{undeclared} reported tool, model, agent or MCP endpoint "
                f"{'item is' if undeclared == 1 else 'items are'} not declared in the inventory"
            )
        if unidentified:
            reasons.append(
                f"{unidentified} reported tool, model, agent or MCP endpoint "
                f"{'item has' if unidentified == 1 else 'items have'} an identifier that could "
                "not be read, so it cannot be compared with the inventory"
            )
        if mismatched:
            reasons.append(
                f"{mismatched} reconciled {'item reports' if mismatched == 1 else 'items report'} "
                "a conflicting or unreadable workload identity or tool definition hash"
            )
        unclassified = coverage["spans_unclassified"]
        if unclassified:
            reasons.append(
                f"{unclassified} {'span has' if unclassified == 1 else 'spans have'} an "
                "operation name, MCP method or MCP transport that could not be read, so what "
                f"{'it reports' if unclassified == 1 else 'they report'} cannot be compared "
                "with the inventory"
            )
        missing = coverage["spans_without_identifier"]
        for kind in ("tool", "agent"):
            count = missing[kind]
            if count:
                reasons.append(
                    f"{count} {kind} {'span names' if count == 1 else 'spans name'} no {kind}, "
                    f"so what {'it' if count == 1 else 'they'} called cannot be compared with "
                    "the inventory"
                )
        over = coverage["attribute_lists_over_bound"]
        if over:
            reasons.append(
                f"{over} attribute {'list has' if over == 1 else 'lists have'} more than "
                f"{MAX_ATTRIBUTES} entries, so what the entries after the first {MAX_ATTRIBUTES} "
                "report cannot be compared with the inventory"
            )
        if not coverage["genai_or_mcp_spans"]:
            reasons.append(
                "no span carries GenAI or MCP semantics, so these traces cannot show undeclared use"
            )
    return {"fail_on": fail_on, "passed": not reasons, "reasons": reasons}


def _inventory_input(path: Path, raw: bytes) -> dict[str, Any]:
    # The bytes passed native validation, so they parse; a document without metadata or
    # components has no content digest under the profile.
    document = parse_json_strict(raw.decode("utf-8"), max_bytes=MAX_NATIVE_BYTES)
    try:
        content: str | None = inventory_content_digest(document)
    except ValueError:
        content = None
    return {
        "name": file_name(path),
        "size": len(raw),
        "sha256": hash_bytes(raw),
        "content_digest": content,
        "content_profile": INVENTORY_CONTENT_PROFILE,
    }


def collect(
    inventory: Path, traces: Sequence[Path], *, fail_on: str = "undeclared"
) -> dict[str, Any]:
    """Read the inventory and the trace files and build the evidence document.

    Raises ``NativeFormatError`` for the inventory and ``TraceInputError`` for a trace
    file; neither message quotes input.
    """
    if fail_on not in FAIL_ON:
        raise ValueError("fail_on must be 'undeclared' or 'none'")
    bom, raw = AIBOM.load_with_bytes(inventory)
    reader = TraceReader()
    observations = Observations()
    for path in traces:
        for span in reader.read(path):
            observations.add(span)
    reconciliation = reconcile(observations, bom)
    coverage = _coverage(reader, observations)
    return {
        "format": FORMAT,
        "assurance": ASSURANCE,
        "limitations": list(LIMITATIONS),
        "inputs": {
            "inventory": _inventory_input(inventory, raw),
            "trace_files": [
                {
                    "index": record.index,
                    "name": record.name,
                    "size": record.size,
                    "sha256": record.sha256,
                    "form": record.form,
                    "records": record.records,
                    "spans": record.spans,
                }
                for record in reader.files
            ],
        },
        "coverage": coverage,
        "observed": _observed(observations),
        "reconciliation": reconciliation,
        "gate": _gate(reconciliation, coverage, fail_on),
    }


def render(document: Mapping[str, Any]) -> str:
    """The evidence as deterministic JSON text: sorted keys, two-space indentation."""
    return json.dumps(document, indent=2, sort_keys=True) + "\n"


def describe(entry: Mapping[str, Any]) -> str:
    """A one-line description of a reconciliation entry; unreadable fields are named."""
    unreadable: Mapping[str, str] = entry.get("unreadable", {})

    def shown(name: str) -> str:
        if name in unreadable:
            return f"<{name} {unreadable[name]}>"
        return f"'{entry.get(name)}'"

    kind = entry["kind"]
    if kind == "tool":
        endpoint = entry.get("endpoint")
        if "host" in unreadable:
            endpoint = shown("host")
        if "port" in unreadable:
            endpoint = f"{endpoint} port {shown('port')}"
        text = f"tool {shown('name')}" + (f" on MCP endpoint {endpoint}" if endpoint else "")
        return text + (f" over {entry['transport']}" if entry.get("transport") else "")
    if kind == "model":
        stated = entry.get("provider") is not None or "provider" in unreadable
        return f"model {shown('model')}" + (f" from provider {shown('provider')}" if stated else "")
    if kind == "agent":
        parts = [
            f"{label} {shown(name)}"
            for label, name in (("named", "name"), ("with id", "id"))
            if entry.get(name) is not None or name in unreadable
        ]
        return "agent " + " ".join(parts)
    if kind == "mcp-endpoint":
        if not unreadable:
            return f"MCP endpoint {_endpoint_text(entry['host'], entry['port'])}"
        host = shown("host") if "host" in unreadable else _endpoint_text(entry["host"], None)
        port = shown("port") if "port" in unreadable else entry.get("port")
        return f"MCP endpoint {host}" + (f" port {port}" if port else "")
    return f"{kind} {shown(_FIELDS[kind][0])}"


def coverage_notes(document: Mapping[str, Any]) -> list[tuple[str, str]]:
    """Coverage gaps as (level, text): what the traces could not show or were not read for."""
    coverage = document["coverage"]
    unreadable = coverage["unreadable_identifiers"]
    clients = coverage["mcp_client_spans"]
    missing = coverage["spans_without_identifier"]
    notes: list[tuple[str, str]] = []
    if not coverage["genai_or_mcp_spans"]:
        notes.append(
            ("warning", "No span carries GenAI or MCP semantics: these traces cannot show any use.")
        )
    if coverage["spans_with_content_attributes"]:
        notes.append(
            (
                "warning",
                "Spans with message, prompt or tool-call content attributes: "
                f"{coverage['spans_with_content_attributes']}. Protect these trace files.",
            )
        )
    if any(unreadable.values()):
        notes.append(
            (
                "warning",
                f"Identifier values not used: {sum(unreadable.values())} (invalid: "
                f"{unreadable['invalid']}, longer than {MAX_IDENTIFIER_CHARS} characters: "
                f"{unreadable['oversized']}, withheld as credential-shaped: "
                f"{unreadable['withheld']}).",
            )
        )
    if coverage["spans_unclassified"]:
        notes.append(
            (
                "warning",
                "Spans whose operation name, MCP method or MCP transport could not be read: "
                f"{coverage['spans_unclassified']}. What they report cannot be compared with "
                "the inventory.",
            )
        )
    if coverage["attribute_lists_over_bound"]:
        notes.append(
            (
                "warning",
                f"Attribute lists with more than {MAX_ATTRIBUTES} entries: "
                f"{coverage['attribute_lists_over_bound']}. The entries after the first "
                f"{MAX_ATTRIBUTES} were not read.",
            )
        )
    if clients["stdio"]:
        notes.append(
            (
                "note",
                f"MCP client spans over a pipe or unix socket: {clients['stdio']}. A trace "
                "cannot attribute local activity to a configured server.",
            )
        )
    if clients["unattributed"]:
        notes.append(
            (
                "note",
                "MCP client spans without a server address, or whose transport could not be "
                f"read: {clients['unattributed']}. Their endpoint is not attributed.",
            )
        )
    if any(missing.values()):
        notes.append(
            (
                "note",
                f"Tool spans that name no tool: {missing['tool']}; agent spans that name no "
                f"agent: {missing['agent']}.",
            )
        )
    if coverage["legacy_attributes"]["gen_ai.system"]:
        notes.append(
            (
                "note",
                "Spans that name their provider with the legacy gen_ai.system attribute: "
                f"{coverage['legacy_attributes']['gen_ai.system']}.",
            )
        )
    return notes


def _findings(document: Mapping[str, Any]) -> Iterable[tuple[str, dict[str, Any]]]:
    reconciliation = document["reconciliation"]
    for entry in reconciliation["undeclared"]:
        yield "undeclared", entry
    for entry in reconciliation["unidentified"]:
        if entry["kind"] in GATING_KINDS:
            yield "unidentified", entry
    for bucket in ("matched", "ambiguous"):
        for entry in reconciliation[bucket]:
            if _is_mismatched(entry):
                yield "mismatched", entry


def sarif_document(document: Mapping[str, Any], anchor: str) -> dict[str, Any]:
    """SARIF 2.1.0 results for undeclared, unidentified and mismatched runtime use, anchored at ``anchor``.

    Unobserved declarations are not findings and are not emitted. Text taken from the
    traces is neutralized as the inventory's SARIF export neutralizes inventory text.
    """
    from nexus_symbiote import __version__
    from nexus_symbiote.core.enums import RiskSeverity
    from nexus_symbiote.generators.sarif import (
        GITHUB_MAX_RESULTS,
        SEVERITY_TO_SARIF,
        SRCROOT,
        SARIFGenerator,
        plain_text,
    )
    from nexus_symbiote.generators.validation import require_valid

    severity = RiskSeverity.HIGH
    rule_id = f"nexus_symbiote/{CATEGORY}/{severity.value}"
    results = []
    for status, entry in _findings(document):
        identity = {key: value for key, value in entry.items() if key != "span_count"}
        fingerprint = hash_canonical(
            {"rule": f"nexus_symbiote/{CATEGORY}", "status": status, **identity}
        ).split(":", 1)[1]
        if status == "undeclared":
            message = f"The traces report {describe(entry)}, which the inventory does not declare."
        elif status == "mismatched":
            message = (
                f"The traces report {describe(entry)} with a conflicting or unreadable "
                "workload identity or tool definition hash."
            )
        else:
            message = (
                f"The traces report {describe(entry)}; it cannot be compared with the "
                "inventory because its identifier could not be read."
            )
        properties: dict[str, Any] = {
            "assurance": ASSURANCE,
            "kind": entry["kind"],
            "status": status,
            "span_count": entry["span_count"],
        }
        for key, value in identity.items():
            if key != "kind" and isinstance(value, str):
                properties[key] = plain_text(value)
        if "unreadable" in identity:
            properties["unreadable"] = dict(identity["unreadable"])
        results.append(
            {
                "ruleId": rule_id,
                "ruleIndex": 0,
                "level": SEVERITY_TO_SARIF[severity],
                "message": {"text": plain_text(message)},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": anchor, "uriBaseId": SRCROOT}
                        }
                    }
                ],
                "partialFingerprints": {
                    "nexus_symbiote/v1": fingerprint,
                    "primaryLocationLineHash": fingerprint[:16] + ":1",
                },
                "properties": properties,
            }
        )
    notes = coverage_notes(document)
    if len(results) > GITHUB_MAX_RESULTS:
        notes.append(
            (
                "warning",
                f"This run has {len(results)} results; GitHub code scanning keeps at most "
                f"{GITHUB_MAX_RESULTS} per run.",
            )
        )
    notifications = [
        {"level": level, "message": {"text": plain_text(text)}} for level, text in notes
    ]
    notifications.append(
        {
            "level": "note",
            "message": {
                "text": "Telemetry is a report by the agent's own instrumentation; a span that "
                "is missing proves nothing."
            },
        }
    )
    sarif: dict[str, Any] = {
        "$schema": "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "nexus-symbiote",
                        "version": __version__,
                        "informationUri": "https://github.com/aisecnomad/Nexus-Symbiote",
                        "rules": [
                            SARIFGenerator._rule(
                                rule_id,
                                CATEGORY,
                                severity,
                                help_text=SARIF_HELP,
                                help_uri=SARIF_HELP_URI,
                            )
                        ]
                        if results
                        else [],
                    }
                },
                "results": results,
                "invocations": [
                    {"executionSuccessful": True, "toolExecutionNotifications": notifications}
                ],
                "properties": {
                    "assurance": ASSURANCE,
                    "evidence_format": FORMAT,
                    "inventory_sha256": document["inputs"]["inventory"]["sha256"],
                },
            }
        ],
    }
    require_valid(sarif, "sarif")
    return sarif
