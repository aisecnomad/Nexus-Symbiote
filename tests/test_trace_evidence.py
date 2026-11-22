"""Trace evidence: bounded, allowlisted OTLP/JSON reading and conservative reconciliation."""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote import otlp
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.core.content_digest import inventory_content_digest
from nexus_symbiote.core.hashing import hash_bytes, parse_json_strict
from nexus_symbiote.core.models import (
    AgentComponent,
    AnyComponent,
    DataSourceComponent,
    MCPServerComponent,
    MemoryStoreComponent,
    ModelComponent,
    PromptComponent,
    RAGSourceComponent,
    SkillPackageComponent,
    ToolComponent,
)
from nexus_symbiote.generators.validation import validate_sarif
from nexus_symbiote.graph import INFERRED_AGENT_REF, _repository_agent_ref
from nexus_symbiote.otlp import TraceInputError, TraceReader, is_content
from nexus_symbiote.trace_evidence import (
    Observations,
    collect,
    coverage_notes,
    describe,
    reconcile,
    render,
    sarif_document,
)
from tests.support import otlp_export, otlp_span, scaling_ratio

MARKER = "MARKER-7f3e9a"
CLIENT = 3
SERVER = 2
SPAN = ("resourceSpans", 0, "scopeSpans", 0, "spans", 0)


def _inventory(tmp_path: Path, *components: AnyComponent) -> Path:
    path = tmp_path / "bom.json"
    path.write_text(AIBOM(components=list(components)).to_native_json())
    return path


def _trace(tmp_path: Path, document: object, name: str = "trace.json") -> Path:
    path = tmp_path / name
    path.write_text(json.dumps(document, indent=2))
    return path


def _evidence(
    tmp_path: Path,
    components: list[AnyComponent],
    *spans: dict[str, Any],
    resource: dict[str, object] | None = None,
) -> dict[str, Any]:
    trace = _trace(tmp_path, otlp_export(*spans, resource=resource))
    return collect(_inventory(tmp_path, *components), [trace])


def _read(path: Path) -> tuple[TraceReader, list[otlp.Span]]:
    reader = TraceReader()
    return reader, list(reader.read(path))


def _tool(name: str, **extra: object) -> dict[str, Any]:
    return otlp_span({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": name, **extra})


def _mcp_tool(name: str, address: str, port: object = 443) -> dict[str, Any]:
    attributes = {
        "mcp.method.name": "tools/call",
        "gen_ai.tool.name": name,
        "network.transport": "tcp",
        "server.address": address,
        "server.port": port,
    }
    return otlp_span(attributes, kind=CLIENT)


def _entries(evidence: dict[str, Any], status: str, kind: str | None = None) -> list[dict]:
    return [
        entry
        for entry in evidence["reconciliation"][status]
        if kind is None or entry["kind"] == kind
    ]


def _server(ref: str, name: str, url: str | None = None) -> MCPServerComponent:
    return MCPServerComponent(bom_ref=ref, name=name, endpoint_url=url)


def _declared_tool(ref: str, name: str, server: str | None = None) -> ToolComponent:
    return ToolComponent(bom_ref=ref, name=name, mcp_server_ref=server)


def _hosted(ref: str, alias: str, provider: str | None = "openai") -> ModelComponent:
    return ModelComponent(
        bom_ref=ref, name=alias, requested_alias=alias, provider=provider, model_type="hosted"
    )


def _agent(ref: str, name: str, source: str | None = "agent.yaml") -> AgentComponent:
    properties = {} if source is None else {"identity_source": source}
    return AgentComponent(bom_ref=ref, name=name, properties=properties)


# Reading: forms, structure and bounds


def test_one_object_and_json_lines_read_the_same_spans(tmp_path):
    first = otlp_export(otlp_span({"gen_ai.request.model": "m1"}))
    second = otlp_export(otlp_span({"gen_ai.request.model": "m2"}))
    merged = {"resourceSpans": first["resourceSpans"] + second["resourceSpans"]}
    files = {
        "compact.json": json.dumps(merged) + "\n",
        "pretty.json": json.dumps(merged, indent=2),
        "lines.jsonl": "\n" + json.dumps(first) + "\r\n\n" + json.dumps(second) + "\n\n",
    }
    read = {}
    for name, text in files.items():
        path = tmp_path / name
        path.write_text(text)
        reader, spans = _read(path)
        record = reader.files[0]
        read[name] = (
            record.form,
            record.records,
            [s.attributes["gen_ai.request.model"] for s in spans],
        )
        assert record.sha256 == hash_bytes(path.read_bytes())
        assert record.size == len(path.read_bytes())
    assert read == {
        "compact.json": ("json", 1, ["m1", "m2"]),
        "pretty.json": ("json", 1, ["m1", "m2"]),
        "lines.jsonl": ("json-lines", 2, ["m1", "m2"]),
    }


@pytest.mark.parametrize(
    "content",
    [
        b"",
        b" \n\t\r\n",
        b"[]",
        b'"MARKER-7f3e9a"',
        b'{"resource_spans": []}',
        b'{"resourceSpans": {"MARKER-7f3e9a": 1}}',
        b'{"resourceSpans": [], "MARKER-7f3e9a": "\xff"}',
        '\ufeff{"resourceSpans": []}'.encode(),
        b'{"resourceSpans": [], "resourceSpans": ["MARKER-7f3e9a"]}',
        b'{"resourceSpans": [], "x": NaN}',
        b'{"resourceSpans": [], "x": 1152921504606846976}',
        b'{"resourceSpans": [], "x": "\\ud800"}',
        b"[" * 100_000 + b"]" * 100_000,
        b'{"resourceSpans": []}\n{"MARKER-7f3e9a" ',
        b'{"resourceSpans": []}\n["MARKER-7f3e9a"]',
        b'{"resourceSpans": [] }  {"resourceSpans": []}',
    ],
)
def test_files_that_are_not_strict_otlp_json_are_refused_without_quoting(tmp_path, content):
    path = tmp_path / "trace.json"
    path.write_bytes(content)
    with pytest.raises(TraceInputError) as raised:
        _read(path)
    message = str(raised.value)
    assert message.startswith("trace file 1 ")
    assert MARKER not in message


def _valid() -> dict[str, Any]:
    span = otlp_span({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "lookup"})
    return otlp_export(span, resource={"service.name": "billing"})


def _replace(document: Any, path: tuple[object, ...], value: object) -> None:
    for step in path[:-1]:
        document = document[step]
    document[path[-1]] = value


@pytest.mark.parametrize(
    ("path", "value", "problem"),
    [
        (("resourceSpans", 0), MARKER, "resourceSpans[0] must be an object"),
        (("resourceSpans", 0, "resource"), MARKER, "resourceSpans[0].resource must be an object"),
        (
            ("resourceSpans", 0, "resource", "attributes"),
            {MARKER: 1},
            "resource.attributes must be an array",
        ),
        (
            ("resourceSpans", 0, "scopeSpans"),
            MARKER,
            "resourceSpans[0].scopeSpans must be an array",
        ),
        (("resourceSpans", 0, "scopeSpans", 0), 7, "scopeSpans[0] must be an object"),
        (
            ("resourceSpans", 0, "scopeSpans", 0, "spans"),
            MARKER,
            "scopeSpans[0].spans must be an array",
        ),
        (SPAN, [MARKER], "spans[0] must be an object"),
        ((*SPAN, "attributes"), MARKER, "spans[0].attributes must be an array"),
        ((*SPAN, "attributes", 0), MARKER, "spans[0].attributes[0] must be an object"),
        ((*SPAN, "attributes", 0), {"value": {"stringValue": MARKER}}, "attributes[0].key must be"),
        ((*SPAN, "attributes", 0, "key"), 5, "attributes[0].key must be a string"),
        ((*SPAN, "attributes", 0, "value"), MARKER, "attributes[0].value must be an object"),
        (
            (*SPAN, "attributes", 1, "value"),
            {"stringValue": MARKER, "intValue": "1"},
            "attributes[1].value sets more than one type",
        ),
        (
            (*SPAN, "attributes", 1),
            {"key": "gen_ai.operation.name", "value": {"stringValue": MARKER}},
            "spans[0].attributes repeats an attribute key",
        ),
        ((*SPAN, "kind"), "SPAN_KIND_CLIENT", "spans[0].kind must be an integer"),
        ((*SPAN, "kind"), True, "spans[0].kind must be an integer"),
        ((*SPAN, "kind"), 1.5, "spans[0].kind must be an integer"),
        ((*SPAN, "startTimeUnixNano"), "-5", "startTimeUnixNano must be a decimal number"),
        ((*SPAN, "startTimeUnixNano"), MARKER, "startTimeUnixNano must be a decimal number"),
        ((*SPAN, "startTimeUnixNano"), 1.5, "startTimeUnixNano must be a decimal number"),
        ((*SPAN, "startTimeUnixNano"), False, "startTimeUnixNano must be a decimal number"),
        ((*SPAN, "startTimeUnixNano"), str(2**64), "startTimeUnixNano must be a decimal number"),
        ((*SPAN, "startTimeUnixNano"), -1, "startTimeUnixNano must be a decimal number"),
    ],
)
def test_a_malformed_structure_is_named_by_its_path_never_by_its_value(
    tmp_path, path, value, problem
):
    document = _valid()
    _replace(document, path, value)
    with pytest.raises(TraceInputError) as raised:
        _read(_trace(tmp_path, document))
    message = str(raised.value)
    assert message.startswith("trace file 1 is malformed: ")
    assert problem in message
    assert MARKER not in message


@pytest.mark.parametrize(
    "key", ["scope_spans", "instrumentationLibrarySpans", "instrumentation_library_spans"]
)
def test_spans_under_a_container_the_reader_does_not_read_are_refused(tmp_path, key):
    # Beside an entry the reader does read, skipped spans would let the gate pass.
    hidden = otlp_span({"gen_ai.operation.name": "execute_tool", "gen_ai.tool.name": "shell"})
    document = _valid()
    document["resourceSpans"].append({key: [{"spans": [hidden]}]})
    with pytest.raises(TraceInputError, match=rf"resourceSpans\[1\] holds {key}, which is not"):
        _read(_trace(tmp_path, document))


def test_a_second_resource_spans_array_under_the_proto_name_is_refused(tmp_path):
    document = _valid()
    document["resource_spans"] = copy.deepcopy(document["resourceSpans"])
    with pytest.raises(TraceInputError, match="the document holds resource_spans"):
        _read(_trace(tmp_path, document))


def test_json_lines_problems_name_the_line(tmp_path):
    good = json.dumps(_valid())
    path = tmp_path / "trace.jsonl"
    cases = {
        "\n".join(["", good, good, json.dumps({"resourceSpans": [MARKER]})]): (
            "trace file 1 is malformed at line 4: resourceSpans[0] must be an object"
        ),
        good + "\n" + json.dumps([MARKER]): (
            "trace file 1 is malformed at line 2: the object has no resourceSpans array"
        ),
        good
        + "\n\n"
        + "{"
        + MARKER: "trace file 1 line 3 is not strict JSON: one OTLP/JSON object",
    }
    for text, message in cases.items():
        path.write_text(text)
        with pytest.raises(TraceInputError) as raised:
            _read(path)
        assert str(raised.value).startswith(message)
        assert MARKER not in str(raised.value)


def test_a_line_or_file_over_its_bound_is_refused(tmp_path, monkeypatch):
    small = json.dumps(otlp_export())
    large = json.dumps(_valid())
    monkeypatch.setattr(otlp, "MAX_LINE_BYTES", len(small) + 10)
    path = tmp_path / "trace.jsonl"
    path.write_text(small + "\n" + large + "\n")
    with pytest.raises(TraceInputError, match="line 2 exceeds the 0 MiB JSON Lines bound"):
        _read(path)
    path.write_text(large + "\n" + small + "\n")
    with pytest.raises(TraceInputError, match="its first line exceeds the 0 MiB JSON Lines bound"):
        _read(path)
    # One object on one line is a one-object file, bounded by the file bound only.
    path.write_text(large + "\n")
    assert len(_read(path)[1]) == 1
    monkeypatch.setattr(otlp, "MAX_TRACE_FILE_BYTES", len(large))
    path.write_text(large + "\n")
    with pytest.raises(TraceInputError, match="exceeds the 0 MiB trace file bound"):
        _read(path)


def test_the_span_and_file_bounds_hold_across_all_trace_files(tmp_path, monkeypatch):
    two = _trace(tmp_path, otlp_export(_tool("a"), _tool("b")))
    monkeypatch.setattr(otlp, "MAX_SPANS", 3)
    reader = TraceReader()
    assert len(list(reader.read(two))) == 2
    with pytest.raises(TraceInputError, match="trace file 2 exceeds the bound of 3 spans across"):
        list(reader.read(two))
    monkeypatch.setattr(otlp, "MAX_TRACE_FILES", 1)
    reader = TraceReader()
    list(reader.read(_trace(tmp_path, otlp_export(), "empty.json")))
    with pytest.raises(TraceInputError, match="trace file 2 exceeds the bound of 1 trace files"):
        list(reader.read(two))


def test_identifiers_longer_than_the_bound_are_counted_and_never_matched(tmp_path):
    inside, beyond = "t" * otlp.MAX_IDENTIFIER_CHARS, "u" * (otlp.MAX_IDENTIFIER_CHARS + 1)
    evidence = _evidence(tmp_path, [_declared_tool("tool:u", beyond)], _tool(inside), _tool(beyond))
    assert [entry["name"] for entry in _entries(evidence, "undeclared", "tool")] == [inside]
    assert _entries(evidence, "unidentified") == [
        {
            "kind": "tool",
            "name": None,
            "endpoint": None,
            "span_count": 1,
            "unreadable": {"name": "oversized"},
        }
    ]
    assert evidence["coverage"]["unreadable_identifiers"]["oversized"] == 1
    assert evidence["gate"]["passed"] is False
    assert len(evidence["gate"]["reasons"]) == 2


def test_attributes_after_the_bound_are_counted_and_not_read(tmp_path):
    filler = {f"custom.attribute.{i}": "x" for i in range(otlp.MAX_ATTRIBUTES - 2)}
    within = _tool("inside", **filler)
    beyond = otlp_span(
        {
            "gen_ai.operation.name": "execute_tool",
            **filler,
            "custom.last": "x",
            "gen_ai.tool.name": "beyond",
        }
    )
    evidence = _evidence(tmp_path, [], within, beyond)
    assert [entry["name"] for entry in evidence["observed"]] == ["inside"]
    coverage = evidence["coverage"]
    assert coverage["attribute_lists_over_bound"] == 1
    assert coverage["spans_without_identifier"]["tool"] == 1
    assert "beyond" not in render(evidence)
    assert evidence["gate"]["passed"] is False


def _hidden_call(count: int) -> dict[str, Any]:
    # ``count`` attributes, the identifying ones last, as a span that buries a call would.
    call = {
        "gen_ai.operation.name": "execute_tool",
        "mcp.method.name": "tools/call",
        "network.transport": "tcp",
        "server.address": "evil.example.net",
        "server.port": 443,
        "gen_ai.tool.name": "exfiltrate",
    }
    filler = {f"app.filler.{i:03d}": "x" for i in range(count - len(call))}
    return otlp_span({**filler, **call}, kind=CLIENT)


def test_a_list_at_the_attribute_bound_is_read_whole(tmp_path):
    evidence = _evidence(tmp_path, [], _hidden_call(otlp.MAX_ATTRIBUTES))
    assert evidence["coverage"]["attribute_lists_over_bound"] == 0
    assert {entry["kind"] for entry in evidence["reconciliation"]["undeclared"]} == {
        "mcp-endpoint",
        "tool",
    }
    assert evidence["gate"]["passed"] is False


@pytest.mark.parametrize("where", ["span", "resource"])
def test_a_list_over_the_attribute_bound_fails_the_gate(tmp_path, where):
    declared = _server("mcp:t", "tickets", "https://mcp.example.com")
    if where == "span":
        evidence = _evidence(
            tmp_path, [declared], _mcp_tool("x", "mcp.example.com"), _hidden_call(129)
        )
    else:
        resource: dict[str, object] = {f"app.filler.{i:03d}": "x" for i in range(129)}
        evidence = _evidence(
            tmp_path, [declared], _mcp_tool("x", "mcp.example.com"), resource=resource
        )
    assert evidence["coverage"]["attribute_lists_over_bound"] == 1
    assert "exfiltrate" not in render(evidence)
    gate = evidence["gate"]
    assert gate["passed"] is False
    assert gate["reasons"][-1] == (
        "1 attribute list has more than 128 entries, so what the entries after the first 128 "
        "report cannot be compared with the inventory"
    )
    loose = collect(_inventory(tmp_path, declared), [tmp_path / "trace.json"], fail_on="none")
    assert loose["gate"] == {"fail_on": "none", "passed": True, "reasons": []}


# Reading: what is and is not read


# Written out, so that a key dropped from the reader's list fails a test, with examples of
# the prefixed (gen_ai.prompt.variable.*, gen_ai.prompt.N.*, gen_ai.completion.N.*,
# gen_ai.retrieval.*) and suffixed (gen_ai.*_ref) forms.
CONTENT = [
    "gen_ai.input.messages",
    "gen_ai.output.messages",
    "gen_ai.system_instructions",
    "gen_ai.tool.definitions",
    "gen_ai.tool.call.arguments",
    "gen_ai.tool.call.result",
    "gen_ai.tool.description",
    "gen_ai.agent.description",
    "gen_ai.main_agent.description",
    "gen_ai.skill.description",
    "gen_ai.memory.records",
    "gen_ai.memory.query.text",
    "gen_ai.evaluation.explanation",
    "gen_ai.prompt",
    "gen_ai.completion",
    "gen_ai.prompt.variable.user_name",
    "gen_ai.prompt.0.content",
    "gen_ai.completion.0.content",
    "gen_ai.retrieval.documents",
    "gen_ai.retrieval.query.text",
    "gen_ai.input.messages_ref",
    "gen_ai.output.messages_ref",
    "gen_ai.system_instructions_ref",
    "gen_ai.tool.definitions_ref",
]


def test_every_content_attribute_the_reader_lists_is_tested():
    assert set(CONTENT) >= otlp.CONTENT_ATTRIBUTES


@pytest.mark.parametrize("key", CONTENT)
def test_each_content_attribute_alone_makes_its_span_count(tmp_path, key):
    spans = [otlp_span({key: f"{MARKER} {key}"}), otlp_span({"gen_ai.operation.name": "chat"})]
    evidence = _evidence(tmp_path, [], *spans)
    assert evidence["coverage"]["spans_with_content_attributes"] == 1
    assert MARKER not in render(evidence)


def test_content_attributes_of_a_resource_count_every_span_beneath_it(tmp_path):
    spans = [
        otlp_span({"gen_ai.operation.name": "chat"}),
        otlp_span({"http.request.method": "GET"}),
    ]
    evidence = _evidence(tmp_path, [], *spans, resource={"gen_ai.system_instructions": MARKER})
    assert evidence["coverage"]["spans_with_content_attributes"] == 2
    assert MARKER not in render(evidence)


def test_content_attributes_are_counted_and_their_values_never_reach_any_output(tmp_path):
    content: dict[str, object] = {key: f"{MARKER} {key}" for key in CONTENT}
    content["gen_ai.output.messages"] = {"arrayValue": {"values": [{"stringValue": MARKER}]}}
    span = _mcp_tool("lookup", "mcp.example.com", 443)
    span["attributes"] += otlp_export(otlp_span(content))["resourceSpans"][0]["scopeSpans"][0][
        "spans"
    ][0]["attributes"]
    unread = otlp_span(
        {"user.email": MARKER, "mcp.session.id": MARKER, "gen_ai.conversation.id": MARKER}
    )
    evidence = _evidence(tmp_path, [], span, unread, resource={"deployment.secret": MARKER})
    outputs = render(evidence) + json.dumps(sarif_document(evidence, "bom.json"))
    assert MARKER not in outputs
    assert evidence["coverage"]["spans_with_content_attributes"] == 1
    assert _entries(evidence, "undeclared", "tool")[0]["name"] == "lookup"


@pytest.mark.parametrize(
    "key",
    ["gen_ai.prompt.name", "gen_ai.prompt.version", "gen_ai.retrieval.top_k", "gen_ai.tool.name"],
)
def test_identifiers_beside_content_prefixes_are_not_content(key):
    assert not is_content(key)


TOKEN = "ghp_" + "a1B2c3D4e5" * 4


@pytest.mark.parametrize(
    ("span", "kind", "field"),
    [
        (_tool(TOKEN), "tool", "name"),
        (otlp_span({"gen_ai.request.model": "sk-" + "x" * 24}), "model", "model"),
        (
            otlp_span(
                {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.id": "token=s3cr3tvalue"}
            ),
            "agent",
            "id",
        ),
        (
            otlp_span({"gen_ai.data_source.id": "https://docs.example.com/notes?sig=abc"}),
            "data-source",
            "id",
        ),
        (_mcp_tool("lookup", "https://admin:hunter2@mcp.example.com"), "mcp-endpoint", "host"),
        (
            otlp_span({"gen_ai.request.model": "m", "gen_ai.provider.name": "Bearer abcdef123456"}),
            "model",
            "provider",
        ),
    ],
)
def test_credential_shaped_identifiers_are_withheld(tmp_path, span, kind, field):
    evidence = _evidence(tmp_path, [], span)
    [entry] = _entries(evidence, "unidentified", kind)
    assert entry["unreadable"] == {field: "withheld"}
    assert entry[field] is None
    assert evidence["coverage"]["unreadable_identifiers"]["withheld"] == 1
    outputs = render(evidence) + json.dumps(sarif_document(evidence, "bom.json"))
    for secret in (TOKEN, "s3cr3tvalue", "sig=abc", "hunter2", "abcdef123456", "x" * 24):
        assert secret not in outputs
    assert evidence["gate"]["passed"] is (kind not in {"tool", "model", "agent", "mcp-endpoint"})


@pytest.mark.parametrize(
    ("value", "port"),
    [({"intValue": "443"}, "443"), ({"intValue": 443}, "443"), ({"stringValue": "0443"}, "443")],
)
def test_server_port_may_be_an_int_value_written_as_a_string_or_a_number(tmp_path, value, port):
    evidence = _evidence(tmp_path, [], _mcp_tool("lookup", "MCP.Example.com", value))
    [endpoint] = [entry for entry in evidence["observed"] if entry["kind"] == "mcp-endpoint"]
    assert (endpoint["host"], endpoint["port"]) == ("mcp.example.com", port)
    [tool] = [entry for entry in evidence["observed"] if entry["kind"] == "tool"]
    assert tool["endpoint"] == f"mcp.example.com:{port}"


@pytest.mark.parametrize(
    "value",
    [
        {"intValue": "abc"},
        {"intValue": 0},
        {"intValue": 70000},
        {"boolValue": True},
        {"doubleValue": 443.5},
        {},
    ],
)
def test_an_invalid_server_port_makes_the_endpoint_unidentified(tmp_path, value):
    evidence = _evidence(tmp_path, [], _mcp_tool("lookup", "mcp.example.com", value))
    [entry] = _entries(evidence, "unidentified", "mcp-endpoint")
    assert entry == {
        "kind": "mcp-endpoint",
        "host": "mcp.example.com",
        "port": None,
        "span_count": 1,
        "unreadable": {"port": "invalid"},
    }
    assert evidence["coverage"]["unreadable_identifiers"]["invalid"] == 1


def test_only_remote_mcp_client_spans_name_an_endpoint(tmp_path):
    base = {"mcp.method.name": "tools/call", "gen_ai.tool.name": "lookup"}
    remote = {"server.address": "[2001:DB8::1]", "server.port": 8443}
    spans = [
        otlp_span({**base, "network.transport": "pipe"}, kind=CLIENT),
        otlp_span({**base, "network.transport": "tcp", **remote}, kind=SERVER),
        otlp_span({**base, "network.transport": "tcp"}, kind=CLIENT),
        otlp_span(
            {**base, "network.transport": "unix", "server.address": "/run/mcp.sock"}, kind=CLIENT
        ),
        otlp_span({**base, "network.transport": "quic", **remote}, kind=CLIENT),
    ]
    evidence = _evidence(tmp_path, [], *spans)
    assert evidence["coverage"]["mcp_client_spans"] == {
        "attributed": 1,
        "stdio": 2,
        "unattributed": 1,
    }
    observed = {
        (e["kind"], e.get("endpoint") or e.get("host"), e.get("transport")): e["span_count"]
        for e in evidence["observed"]
    }
    # The server span names no endpoint item, but its tool is the one served at its address.
    assert observed == {
        ("mcp-endpoint", "2001:db8::1", None): 1,
        ("tool", None, None): 1,
        ("tool", None, "pipe"): 1,
        ("tool", None, "unix"): 1,
        ("tool", "[2001:db8::1]:8443", None): 2,
    }


def _shadow_inventory(endpoint: str = "https://mcp.example.com") -> list[AnyComponent]:
    return [
        MCPServerComponent(
            bom_ref="mcp:tickets",
            name="tickets",
            transport="streamable-http",
            endpoint_url=endpoint,
        ),
        _declared_tool("tool:delete_all", "delete_all", "mcp:tickets"),
    ]


@pytest.mark.parametrize(
    ("transport", "kind"),
    [
        ("tcp", CLIENT),
        (None, CLIENT),
        ("http", CLIENT),
        ("TCP", CLIENT),
        ("tcp", 1),
        ("tcp", SERVER),
    ],
)
def test_a_reported_address_never_matches_a_tool_served_elsewhere(tmp_path, transport, kind):
    attributes: dict[str, object] = {
        "mcp.method.name": "tools/call",
        "gen_ai.tool.name": "delete_all",
        "server.address": "evil.example.net",
        "server.port": 443,
    }
    if transport is not None:
        attributes["network.transport"] = transport
    evidence = _evidence(tmp_path, _shadow_inventory(), otlp_span(attributes, kind=kind))
    reconciliation = evidence["reconciliation"]
    assert reconciliation["matched"] == []
    assert {
        "kind": "tool",
        "name": "delete_all",
        "endpoint": "evil.example.net:443",
        "span_count": 1,
    } in reconciliation["undeclared"]
    endpoint = {"kind": "mcp-endpoint", "host": "evil.example.net", "port": "443", "span_count": 1}
    assert (endpoint in reconciliation["undeclared"]) is (kind == CLIENT)
    assert [entry["inventory_ref"] for entry in reconciliation["unobserved"]] == [
        "mcp:tickets",
        "tool:delete_all",
    ]
    assert evidence["gate"]["passed"] is False


@pytest.mark.parametrize("transport", ["pipe", "unix"])
def test_a_local_call_never_matches_a_tool_of_a_remote_only_server(tmp_path, transport):
    span = otlp_span(
        {
            "mcp.method.name": "tools/call",
            "gen_ai.tool.name": "delete_all",
            "network.transport": transport,
        },
        kind=CLIENT,
    )
    evidence = _evidence(tmp_path, _shadow_inventory(), span)
    reconciliation = evidence["reconciliation"]
    assert reconciliation["matched"] == []
    assert reconciliation["undeclared"] == [
        {
            "kind": "tool",
            "name": "delete_all",
            "endpoint": None,
            "transport": transport,
            "span_count": 1,
        }
    ]
    assert len(reconciliation["unobserved"]) == 2
    assert describe(reconciliation["undeclared"][0]) == f"tool 'delete_all' over {transport}"
    local = [
        MCPServerComponent(
            bom_ref="mcp:local", name="local", transport="stdio", endpoint_url="http://h"
        ),
        _declared_tool("tool:local", "delete_all", "mcp:local"),
        *_shadow_inventory(),
    ]
    matched = _evidence(tmp_path, local, span)["reconciliation"]["matched"]
    assert [(entry["inventory_ref"], entry["basis"]) for entry in matched] == [
        ("tool:local", "name")
    ]


def test_a_local_call_never_matches_a_tool_of_a_server_whose_endpoint_was_withheld(tmp_path):
    # The mcp collector records an environment-dependent or ambiguous URL as [redacted].
    span = _tool("delete_all", **{"network.transport": "pipe"})
    evidence = _evidence(tmp_path, _shadow_inventory("[redacted]"), span)
    reconciliation = evidence["reconciliation"]
    assert reconciliation["matched"] == []
    assert [(e["name"], e["transport"]) for e in reconciliation["undeclared"]] == [
        ("delete_all", "pipe")
    ]
    assert evidence["gate"]["passed"] is False


def test_resource_attributes_apply_beneath_each_span(tmp_path):
    resource = {
        "service.name": "billing-agent",
        "gen_ai.agent.name": "planner",
        "gen_ai.provider.name": "openai",
    }
    spans = [
        otlp_span({"gen_ai.operation.name": "invoke_agent"}),
        otlp_span({"gen_ai.operation.name": "create_agent", "gen_ai.agent.name": "reviewer"}),
        otlp_span({"gen_ai.request.model": "m", "service.name": MARKER}),
    ]
    evidence = _evidence(tmp_path, [], *spans, resource=resource)
    observed = {(e["kind"], e.get("name") or e.get("model")): e for e in evidence["observed"]}
    assert set(observed) == {("agent", "planner"), ("agent", "reviewer"), ("model", "m")}
    assert observed[("model", "m")]["provider"] == "openai"
    assert {tuple(e["services"]) for e in observed.values()} == {("billing-agent",)}
    assert MARKER not in render(evidence)


def test_the_legacy_provider_attribute_is_used_only_without_the_current_one(tmp_path):
    spans = [
        otlp_span({"gen_ai.request.model": "m1", "gen_ai.system": "openai"}),
        otlp_span(
            {
                "gen_ai.request.model": "m2",
                "gen_ai.system": "openai",
                "gen_ai.provider.name": "anthropic",
            }
        ),
    ]
    evidence = _evidence(tmp_path, [], *spans)
    assert {(e["model"], e["provider"]) for e in evidence["observed"]} == {
        ("m1", "openai"),
        ("m2", "anthropic"),
    }
    assert evidence["coverage"]["legacy_attributes"] == {"gen_ai.system": 1}


def test_operation_names_are_counted_by_convention_value_or_as_other(tmp_path):
    spans = [
        otlp_span({"gen_ai.operation.name": "chat"}),
        otlp_span({"gen_ai.operation.name": "chat"}),
        otlp_span({"gen_ai.operation.name": "custom_operation"}),
        otlp_span({"gen_ai.operation.name": MARKER}),
        otlp_span({"mcp.method.name": "tools/list"}, kind=CLIENT),
        otlp_span({"mcp.method.name": MARKER}),
        otlp_span({"http.request.method": "GET"}),
    ]
    evidence = _evidence(tmp_path, [], *spans)
    coverage = evidence["coverage"]
    assert coverage["operation_names"] == {"chat": 2, "other": 2}
    assert coverage["mcp_method_names"] == {"other": 1, "tools/list": 1}
    assert (coverage["spans_read"], coverage["genai_or_mcp_spans"], coverage["spans_ignored"]) == (
        7,
        6,
        1,
    )
    assert coverage["mcp_client_spans"]["unattributed"] == 1
    assert MARKER not in render(evidence)


def test_times_come_from_the_spans_and_cover_only_spans_that_state_one(tmp_path):
    spans = [
        otlp_span({"gen_ai.request.model": "m"}, start=2_000_000_000_000_000_007),
        otlp_span({"gen_ai.request.model": "m"}, start=1_000_000_000_000_000_000),
        otlp_span({"gen_ai.request.model": "m"}, start=None),
        otlp_span({"gen_ai.request.model": "m"}, start=0),
        otlp_span({"gen_ai.request.model": "late"}, start=None),
    ]
    evidence = _evidence(tmp_path, [], *spans)
    assert evidence["coverage"]["time_range"] == {
        "first": "2001-09-09T01:46:40.000000000Z",
        "last": "2033-05-18T03:33:20.000000007Z",
    }
    observed = {
        e["model"]: (e["first_seen"], e["last_seen"], e["span_count"]) for e in evidence["observed"]
    }
    assert observed == {
        "late": (None, None, 1),
        "m": ("2001-09-09T01:46:40.000000000Z", "2033-05-18T03:33:20.000000007Z", 4),
    }


def test_no_span_with_genai_or_mcp_semantics_fails_the_gate(tmp_path):
    evidence = _evidence(tmp_path, [], otlp_span({"http.request.method": "GET"}))
    assert evidence["gate"] == {
        "fail_on": "undeclared",
        "passed": False,
        "reasons": [
            "no span carries GenAI or MCP semantics, so these traces cannot show undeclared use"
        ],
    }
    report_only = collect(_inventory(tmp_path), [_trace(tmp_path, otlp_export())], fail_on="none")
    assert report_only["gate"] == {"fail_on": "none", "passed": True, "reasons": []}
    with pytest.raises(ValueError, match="fail_on"):
        collect(_inventory(tmp_path), [], fail_on="never")


def test_resource_attributes_never_make_a_span_carry_genai_semantics(tmp_path):
    # Set for the whole process, they remain when the GenAI instrumentation is lost; the
    # spans beneath carry none.
    resource = {
        "service.name": "agent",
        "gen_ai.agent.name": "support",
        "gen_ai.data_source.id": "notes",
    }
    spans = [otlp_span({"http.request.method": "GET"}), otlp_span({"http.request.method": "POST"})]
    evidence = _evidence(tmp_path, [], *spans, resource=resource)
    coverage = evidence["coverage"]
    assert (coverage["spans_read"], coverage["genai_or_mcp_spans"], coverage["spans_ignored"]) == (
        2,
        0,
        2,
    )
    assert evidence["observed"] == []
    assert evidence["gate"]["reasons"] == [
        "no span carries GenAI or MCP semantics, so these traces cannot show undeclared use"
    ]


PADDED = " " * otlp.MAX_IDENTIFIER_CHARS


@pytest.mark.parametrize(
    "attributes",
    [
        {"gen_ai.operation.name": "execute_tool" + PADDED, "gen_ai.tool.name": "delete_all"},
        {"gen_ai.operation.name": "Bearer abcdef123456", "gen_ai.tool.name": "delete_all"},
        {"gen_ai.operation.name": {"intValue": "7"}, "gen_ai.tool.name": "delete_all"},
        {
            "mcp.method.name": "tools/call" + PADDED,
            "gen_ai.tool.name": "delete_all",
            "network.transport": "tcp",
            "server.address": "mcp.example.com",
            "server.port": 443,
        },
        # Read, the transport would make this a call to an undeclared endpoint, whose
        # tool another server's declaration of "search" must not cover.
        {
            "mcp.method.name": "tools/call",
            "gen_ai.tool.name": "search",
            "network.transport": "tcp" + PADDED,
            "server.address": "evil.example",
            "server.port": 443,
        },
    ],
)
def test_a_span_whose_operation_method_or_transport_cannot_be_read_fails_the_gate(
    tmp_path, attributes
):
    components = [
        _server("mcp:t", "tickets", "https://mcp.example.com"),
        _declared_tool("tool:s", "search", "mcp:t"),
    ]
    evidence = _evidence(tmp_path, components, otlp_span(attributes, kind=CLIENT))
    assert [e for e in evidence["reconciliation"]["matched"] if e["kind"] == "tool"] == []
    # The tool the span names is reported whatever became of its operation or method.
    address = attributes.get("server.address")
    assert evidence["reconciliation"]["undeclared"] == [
        {
            "kind": "tool",
            "name": attributes["gen_ai.tool.name"],
            "endpoint": f"{address}:443" if address else None,
            "span_count": 1,
        }
    ]
    assert evidence["coverage"]["spans_unclassified"] == 1
    assert evidence["gate"]["reasons"][-1] == (
        "1 span has an operation name, MCP method or MCP transport that could not be read, so "
        "what it reports cannot be compared with the inventory"
    )
    note = (
        "Spans whose operation name, MCP method or MCP transport could not be read: 1. What "
        "they report cannot be compared with the inventory."
    )
    assert ("warning", note) in coverage_notes(evidence)
    sarif = sarif_document(evidence, "bom.json")
    assert validate_sarif(sarif) == []
    notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
    assert {"level": "warning", "message": {"text": note}} in notifications


@pytest.mark.parametrize(
    ("attributes", "kind"),
    [
        ({"mcp.method.name": "tools/call"}, CLIENT),
        ({"gen_ai.operation.name": "execute_tool"}, 1),
        (
            {
                "gen_ai.operation.name": "execute_tool",
                "server.address": "mcp.example.com",
                "server.port": 443,
            },
            1,
        ),
    ],
)
def test_a_tool_call_whose_transport_cannot_be_read_fails_the_gate(tmp_path, attributes, kind):
    # Read as pipe, the transport would keep the remote-only server's tool from matching.
    base = {**attributes, "gen_ai.tool.name": "delete_all"}
    for transport, matched in (("pipe", []), ("pipe" + PADDED, ["tool:delete_all"])):
        span = otlp_span({**base, "network.transport": transport}, kind=kind)
        evidence = _evidence(tmp_path, _shadow_inventory(), span)
        refs = [e["inventory_ref"] for e in _entries(evidence, "matched", "tool")]
        assert refs == matched
        assert evidence["coverage"]["spans_unclassified"] == (1 if matched else 0)
        assert evidence["gate"]["passed"] is False


@pytest.mark.parametrize(
    "attributes",
    [
        {"gen_ai.tool.name": "delete_all"},
        {"gen_ai.operation.name": "run_tool", "gen_ai.tool.name": "delete_all"},
        {"gen_ai.operation.name": "EXECUTE_TOOL", "gen_ai.tool.name": "delete_all"},
        {"gen_ai.operation.name": "chat", "gen_ai.tool.name": "delete_all"},
        {"mcp.method.name": "TOOLS/CALL", "gen_ai.tool.name": "delete_all"},
    ],
)
def test_a_tool_named_under_any_operation_is_reported(tmp_path, attributes):
    evidence = _evidence(tmp_path, [_declared_tool("tool:s", "search")], otlp_span(attributes))
    assert _entries(evidence, "undeclared") == [
        {"kind": "tool", "name": "delete_all", "endpoint": None, "span_count": 1}
    ]
    assert evidence["gate"]["passed"] is False


@pytest.mark.parametrize("operation", ["run_agent", "INVOKE_AGENT"])
def test_an_agent_named_under_an_operation_outside_the_convention_is_reported(tmp_path, operation):
    attributes = {"gen_ai.operation.name": operation, "gen_ai.agent.name": "shadow-planner"}
    evidence = _evidence(tmp_path, [_agent("agent:p", "planner")], otlp_span(attributes))
    assert [(e["kind"], e["name"]) for e in _entries(evidence, "undeclared")] == [
        ("agent", "shadow-planner")
    ]
    assert evidence["gate"]["passed"] is False


def test_a_declared_tool_named_under_another_operation_still_matches(tmp_path):
    span = otlp_span({"gen_ai.operation.name": "run_tool", "gen_ai.tool.name": "search"})
    evidence = _evidence(tmp_path, [_declared_tool("tool:s", "search")], span)
    assert [e["inventory_ref"] for e in _entries(evidence, "matched")] == ["tool:s"]
    assert evidence["gate"]["passed"] is True


def test_unreadable_details_and_transports_that_attribute_nothing_are_only_counted(tmp_path):
    components = [
        _server("mcp:t", "tickets", "https://mcp.example.com"),
        _declared_tool("tool:s", "search", "mcp:t"),
        _hosted("model:m", "gpt-4o-mini"),
    ]
    spans = [
        otlp_span({"mcp.method.name": "ping", "network.transport": "tcp" + PADDED}, kind=CLIENT),
        _tool("search", **{"gen_ai.tool.type": "function" + PADDED}),
        otlp_span(
            {
                "gen_ai.request.model": "gpt-4o-mini",
                "gen_ai.response.model": "gpt-4o-mini-2024-07-18" + PADDED,
            }
        ),
        otlp_span(
            {
                "mcp.method.name": "initialize",
                "mcp.protocol.version": "2025-06-18" + PADDED,
                "network.transport": "tcp",
                "server.address": "mcp.example.com",
                "server.port": 443,
            },
            kind=CLIENT,
        ),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    coverage = evidence["coverage"]
    assert (coverage["spans_unclassified"], coverage["unreadable_identifiers"]["oversized"]) == (
        0,
        4,
    )
    assert evidence["gate"]["passed"] is True


# Reconciliation


def test_tools_match_by_name_and_a_reported_endpoint_must_agree(tmp_path):
    components = [
        _server("mcp:a", "a", "https://a.example"),
        _server("mcp:b", "b", "http://b.example:8080"),
        _server("mcp:c", "c", "tcp://c.example"),
        _server("mcp:d", "d", "https://d.example"),
        _declared_tool("tool:a", "search", "mcp:a"),
        _declared_tool("tool:b", "search", "mcp:b"),
        _declared_tool("tool:c", "search", "mcp:c"),
        _declared_tool("tool:only", "lookup", "mcp:a"),
    ]
    spans = [
        _tool("lookup"),
        _tool("search"),
        _mcp_tool("search", "A.example", 443),
        _mcp_tool("search", "b.example", 8080),
        _mcp_tool("search", "c.example", 7000),
        otlp_span(
            {
                "mcp.method.name": "tools/call",
                "gen_ai.tool.name": "search",
                "network.transport": "tcp",
                "server.address": "b.example",
            },
            kind=CLIENT,
        ),
        # A declared server that does not declare the tool: another server's tool of the
        # same name must not cover the call.
        _mcp_tool("search", "d.example", 443),
        _mcp_tool("search", "unknown.example", 443),
        _tool("missing"),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    matched = {
        (e["name"], e["endpoint"]): (e["inventory_ref"], e["basis"])
        for e in _entries(evidence, "matched", "tool")
    }
    # Host and port compared: name-and-endpoint. No port on one side: name-and-host.
    assert matched == {
        ("lookup", None): ("tool:only", "name"),
        ("search", "a.example:443"): ("tool:a", "name-and-endpoint"),
        ("search", "b.example:8080"): ("tool:b", "name-and-endpoint"),
        ("search", "b.example"): ("tool:b", "name-and-host"),
        ("search", "c.example:7000"): ("tool:c", "name-and-host"),
    }
    [ambiguous] = _entries(evidence, "ambiguous", "tool")
    assert (ambiguous["endpoint"], ambiguous["candidates"], ambiguous["candidates_omitted"]) == (
        None,
        ["tool:a", "tool:b", "tool:c"],
        0,
    )
    assert [(e["name"], e["endpoint"]) for e in _entries(evidence, "undeclared", "tool")] == [
        ("search", "d.example:443"),
        ("search", "unknown.example:443"),
        ("missing", None),
    ]
    assert [e["host"] for e in _entries(evidence, "undeclared", "mcp-endpoint")] == [
        "unknown.example"
    ]
    endpoints = sorted(e["inventory_ref"] for e in _entries(evidence, "matched", "mcp-endpoint"))
    assert endpoints == ["mcp:a", "mcp:b", "mcp:b", "mcp:c", "mcp:d"]


def test_without_a_reported_port_an_endpoint_is_compared_by_host_alone_and_says_so(tmp_path):
    components = [
        _server("mcp:t", "tickets", "https://mcp.example.com"),
        _declared_tool("tool:s", "search", "mcp:t"),
    ]
    portless = otlp_span(
        {
            "mcp.method.name": "tools/call",
            "gen_ai.tool.name": "search",
            "network.transport": "tcp",
            "server.address": "mcp.example.com",
        },
        kind=CLIENT,
    )
    evidence = _evidence(tmp_path, components, portless)
    assert {(e["kind"], e["inventory_ref"], e["basis"]) for e in _entries(evidence, "matched")} == {
        ("mcp-endpoint", "mcp:t", "host"),
        ("tool", "tool:s", "name-and-host"),
    }
    # The same call with its port reported is told apart from the declared server.
    evidence = _evidence(tmp_path, components, _mcp_tool("search", "mcp.example.com", 8443))
    assert evidence["reconciliation"]["matched"] == []
    assert {
        (e["kind"], e.get("endpoint") or e.get("port")) for e in _entries(evidence, "undeclared")
    } == {
        ("mcp-endpoint", "8443"),
        ("tool", "mcp.example.com:8443"),
    }


def test_ws_and_wss_endpoints_take_their_scheme_default_ports(tmp_path):
    components = [
        _server("mcp:wss", "secure", "wss://socket.example"),
        _server("mcp:ws", "plain", "ws://socket.example/mcp"),
    ]
    spans = [_mcp_tool("t", "socket.example", 443), _mcp_tool("t", "socket.example", 80)]
    evidence = _evidence(tmp_path, components, *spans)
    matched = {
        e["port"]: (e["inventory_ref"], e["basis"])
        for e in _entries(evidence, "matched", "mcp-endpoint")
    }
    assert matched == {"443": ("mcp:wss", "host-and-port"), "80": ("mcp:ws", "host-and-port")}


def test_mcp_endpoints_match_host_and_port_with_default_ports(tmp_path):
    components = [
        _server("mcp:tickets", "tickets", "https://mcp.example.com"),
        _server("mcp:alt", "alt", "http://mcp.example.com:8080/mcp"),
        _server("mcp:twin-1", "twin-1", "https://twin.example"),
        _server("mcp:twin-2", "twin-2", "https://twin.example:443/v2"),
        _server("mcp:stdio", "local"),
        _server("mcp:bad", "bad", "https://bad.example:99999"),
    ]
    spans = [
        _mcp_tool("t", "mcp.example.com", 443),
        _mcp_tool("t", "mcp.example.com", 8080),
        _mcp_tool("t", "mcp.example.com", 9999),
        _mcp_tool("t", "93.184.216.34", 443),
        _mcp_tool("t", "twin.example", 443),
        otlp_span(
            {
                "mcp.method.name": "initialize",
                "network.transport": "tcp",
                "server.address": "mcp.example.com",
            },
            kind=CLIENT,
        ),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    endpoints = {
        status: {
            (e["host"], e["port"]): e.get("inventory_ref", e.get("candidates"))
            for e in _entries(evidence, status, "mcp-endpoint")
        }
        for status in ("matched", "ambiguous", "undeclared")
    }
    assert endpoints["matched"] == {
        ("mcp.example.com", "443"): "mcp:tickets",
        ("mcp.example.com", "8080"): "mcp:alt",
    }
    assert endpoints["ambiguous"] == {
        ("mcp.example.com", None): ["mcp:alt", "mcp:tickets"],
        ("twin.example", "443"): ["mcp:twin-1", "mcp:twin-2"],
    }
    assert set(endpoints["undeclared"]) == {("mcp.example.com", "9999"), ("93.184.216.34", "443")}
    unobserved = {e["inventory_ref"] for e in _entries(evidence, "unobserved")}
    assert unobserved == {"mcp:stdio", "mcp:bad"}


def test_a_hosted_model_matches_by_its_requested_alias_when_its_name_differs(tmp_path):
    pinned = ModelComponent(
        bom_ref="model:pinned",
        name="gpt-4o-2024-08-06",
        requested_alias="gpt-4o",
        provider="openai",
        model_type="hosted",
    )
    spans = [
        otlp_span({"gen_ai.request.model": "gpt-4o", "gen_ai.provider.name": "openai"}),
        otlp_span({"gen_ai.request.model": "gpt-4o"}),
    ]
    evidence = _evidence(tmp_path, [pinned], *spans)
    matched = {
        (e["provider"], e["model"]): (e["inventory_ref"], e["basis"])
        for e in _entries(evidence, "matched", "model")
    }
    assert matched == {
        ("openai", "gpt-4o"): ("model:pinned", "name-and-provider"),
        (None, "gpt-4o"): ("model:pinned", "name"),
    }
    assert _entries(evidence, "undeclared", "model") == []


def test_models_match_by_alias_or_name_and_providers_must_agree(tmp_path):
    components = [
        _hosted("model:gpt", "gpt-4o-mini", "OpenAI"),
        ModelComponent(bom_ref="model:local", name="llama3", model_type="foundation"),
        _hosted("model:any", "claude-x", None),
        _hosted("model:twin-1", "mistral-large", "mistral"),
        _hosted("model:twin-2", "mistral-large", "azure.ai.inference"),
        _hosted("model:unused", "unused-model"),
    ]
    spans = [
        otlp_span(
            {
                "gen_ai.request.model": " gpt-4o-mini ",
                "gen_ai.provider.name": "openai",
                "gen_ai.response.model": "gpt-4o-mini-2024-07-18",
            }
        ),
        otlp_span(
            {"gen_ai.request.model": "gpt-4o-mini", "gen_ai.provider.name": "azure.ai.openai"}
        ),
        otlp_span({"gen_ai.request.model": "llama3"}),
        otlp_span({"gen_ai.response.model": "claude-x", "gen_ai.provider.name": "anthropic"}),
        otlp_span({"gen_ai.request.model": "mistral-large"}),
        otlp_span({"gen_ai.request.model": "mistral-large", "gen_ai.provider.name": "mistral"}),
        otlp_span({"gen_ai.request.model": "GPT-4O-MINI", "gen_ai.provider.name": "openai"}),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    matched = {
        (e["provider"], e["model"]): (e["inventory_ref"], e["basis"])
        for e in _entries(evidence, "matched", "model")
    }
    assert matched == {
        ("openai", "gpt-4o-mini"): ("model:gpt", "name-and-provider"),
        (None, "llama3"): ("model:local", "name"),
        ("anthropic", "claude-x"): ("model:any", "name"),
        ("mistral", "mistral-large"): ("model:twin-1", "name-and-provider"),
    }
    assert [(e["provider"], e["model"]) for e in _entries(evidence, "ambiguous", "model")] == [
        (None, "mistral-large")
    ]
    assert {(e["provider"], e["model"]) for e in _entries(evidence, "undeclared", "model")} == {
        ("azure.ai.openai", "gpt-4o-mini"),
        ("openai", "GPT-4O-MINI"),
    }
    [resolved] = [
        e
        for e in evidence["observed"]
        if e.get("provider") == "openai" and e["model"] == "gpt-4o-mini"
    ]
    assert resolved["resolved_models"] == ["gpt-4o-mini-2024-07-18"]
    assert [e["inventory_ref"] for e in _entries(evidence, "unobserved", "model")] == [
        "model:unused"
    ]


def test_a_reported_provider_is_compared_without_regard_to_case(tmp_path):
    span = otlp_span({"gen_ai.request.model": "gpt-4o-mini", "gen_ai.provider.name": "OpenAI"})
    evidence = _evidence(tmp_path, [_hosted("model:gpt", "gpt-4o-mini", "openai")], span)
    [entry] = _entries(evidence, "matched", "model")
    assert (entry["provider"], entry["inventory_ref"], entry["basis"]) == (
        "OpenAI",
        "model:gpt",
        "name-and-provider",
    )


def test_inventory_names_are_compared_after_trimming(tmp_path):
    components = [
        _declared_tool("tool:padded", " search\t"),
        _hosted("model:padded", " gpt-4o-mini\n", " openai "),
        _agent("agent:padded", "  planner "),
    ]
    spans = [
        _tool("search"),
        otlp_span({"gen_ai.request.model": "gpt-4o-mini", "gen_ai.provider.name": "openai"}),
        otlp_span({"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "planner"}),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    assert {(e["kind"], e["inventory_ref"]) for e in evidence["reconciliation"]["matched"]} == {
        ("tool", "tool:padded"),
        ("model", "model:padded"),
        ("agent", "agent:padded"),
    }
    assert evidence["reconciliation"]["undeclared"] == []


def test_agents_match_by_declared_name_or_id_and_ids_decide(tmp_path):
    declared_ref = _repository_agent_ref("support-agent-7")
    components = [
        _agent(declared_ref, "support"),
        _agent("agent:supplied", "triage", source=None),
        _agent(INFERRED_AGENT_REF, "repository", source="repository-path"),
        _agent("agent:idle", "idle"),
    ]
    invoke = {"gen_ai.operation.name": "invoke_agent"}
    spans = [
        otlp_span({**invoke, "gen_ai.agent.name": "support"}),
        otlp_span({**invoke, "gen_ai.agent.id": "support-agent-7", "gen_ai.agent.name": "renamed"}),
        otlp_span({**invoke, "gen_ai.agent.id": "other-id", "gen_ai.agent.name": "support"}),
        otlp_span({**invoke, "gen_ai.agent.id": "any", "gen_ai.agent.name": "triage"}),
        otlp_span({**invoke, "gen_ai.agent.name": "repository"}),
        otlp_span({**invoke, "gen_ai.agent.id": "."}),
        otlp_span({"gen_ai.operation.name": "create_agent"}),
        otlp_span({"gen_ai.operation.name": "chat", "gen_ai.agent.name": "not-an-agent-span"}),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    matched = {
        (e["id"], e["name"]): (e["inventory_ref"], e["basis"])
        for e in _entries(evidence, "matched", "agent")
    }
    assert matched == {
        (None, "support"): (declared_ref, "name"),
        ("support-agent-7", "renamed"): (declared_ref, "id"),
        ("any", "triage"): ("agent:supplied", "name"),
    }
    assert {(e["id"], e["name"]) for e in _entries(evidence, "undeclared", "agent")} == {
        ("other-id", "support"),
        (None, "repository"),
        (".", None),
    }
    assert evidence["coverage"]["spans_without_identifier"]["agent"] == 1
    assert [e["inventory_ref"] for e in _entries(evidence, "unobserved", "agent")] == ["agent:idle"]


def test_skills_data_sources_memory_stores_and_prompts_are_informational(tmp_path):
    components = [
        SkillPackageComponent(bom_ref="skill:pdf", name="pdf-tools"),
        RAGSourceComponent(bom_ref="rag:notes", name="product-notes"),
        DataSourceComponent(bom_ref="data:train", name="training-set"),
        MemoryStoreComponent(bom_ref="memory:a", name="shared"),
        MemoryStoreComponent(bom_ref="memory:b", name="shared"),
        PromptComponent(bom_ref="prompt:a", name="system_prompt.md"),
    ]
    spans = [
        otlp_span({"gen_ai.skill.name": "pdf-tools"}),
        otlp_span({"gen_ai.data_source.id": "product-notes"}),
        otlp_span({"gen_ai.data_source.id": "training-set"}),
        otlp_span({"gen_ai.memory.store.id": "shared"}),
        otlp_span({"gen_ai.prompt.name": "analyze-code"}),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    assert {(e["kind"], e["inventory_ref"]) for e in evidence["reconciliation"]["matched"]} == {
        ("skill", "skill:pdf"),
        ("data-source", "rag:notes"),
        ("data-source", "data:train"),
    }
    assert [e["candidates"] for e in evidence["reconciliation"]["ambiguous"]] == [
        ["memory:a", "memory:b"]
    ]
    assert evidence["reconciliation"]["unmatched_identifiers"] == [
        {"kind": "prompt", "name": "analyze-code", "span_count": 1}
    ]
    assert evidence["reconciliation"]["undeclared"] == []
    assert evidence["gate"]["passed"] is True


def test_unobserved_declarations_are_listed_and_a_used_tool_marks_its_server(tmp_path):
    components = [
        _server("mcp:used", "used"),
        _server("mcp:idle", "idle"),
        _declared_tool("tool:used", "lookup", "mcp:used"),
        _declared_tool("tool:idle", "write", "mcp:idle"),
        _hosted("model:idle", "unused-model"),
        ModelComponent(bom_ref="model:file", name="weights.safetensors"),
        _agent(INFERRED_AGENT_REF, "repository", source="repository-path"),
    ]
    evidence = _evidence(tmp_path, components, _tool("lookup"))
    assert evidence["reconciliation"]["unobserved"] == [
        {"inventory_ref": "mcp:idle", "kind": "mcp-server", "name": "idle"},
        {"inventory_ref": "model:idle", "kind": "model", "name": "unused-model"},
        {"inventory_ref": "tool:idle", "kind": "tool", "name": "write"},
    ]
    assert evidence["gate"]["passed"] is True


def test_ambiguous_candidates_are_listed_up_to_the_bound_and_the_rest_counted(tmp_path):
    components = [_declared_tool(f"tool:{index:03d}", "search") for index in range(15)]
    evidence = _evidence(tmp_path, components, _tool("search"))
    [entry] = evidence["reconciliation"]["ambiguous"]
    assert entry["candidates"] == [f"tool:{index:03d}" for index in range(10)]
    assert entry["candidates_omitted"] == 5
    assert evidence["reconciliation"]["unobserved"] == []


# The document


def test_inputs_bind_the_bytes_that_were_read(tmp_path):
    inventory = _inventory(tmp_path, _declared_tool("tool:a", "lookup"))
    trace = _trace(tmp_path, otlp_export(_tool("lookup")), "run\x1b[2J.json")
    evidence = collect(inventory, [trace])
    raw = inventory.read_bytes()
    assert evidence["inputs"]["inventory"] == {
        "name": "bom.json",
        "size": len(raw),
        "sha256": hash_bytes(raw),
        "content_digest": inventory_content_digest(json.loads(raw)),
        "content_profile": "nexus-symbiote/inventory-content/v1",
    }
    [record] = evidence["inputs"]["trace_files"]
    assert record["name"] == "run\ufffd[2J.json"
    assert (record["index"], record["form"], record["records"], record["spans"]) == (
        1,
        "json",
        1,
        1,
    )
    assert record["sha256"] == hash_bytes(trace.read_bytes())
    assert AIBOM.load_with_bytes(inventory)[1] == raw


def test_file_names_that_are_not_utf8_keep_the_evidence_i_json(tmp_path, monkeypatch):
    from nexus_symbiote.core import hashing

    # The file system decodes the bytes 0xff and 0xfe of a name to lone surrogates. The
    # files are served from memory, because some file systems refuse such names.
    inventory = tmp_path / "inventory-\udcff.json"
    trace = tmp_path / "trace-\udcff\udcfe.json"
    served = {
        inventory.name: _inventory(tmp_path).read_bytes(),
        trace.name: json.dumps(otlp_export(_tool("lookup"))).encode(),
    }

    def serve(path: Path) -> io.BytesIO:
        return io.BytesIO(served[path.name])

    monkeypatch.setattr(hashing, "open_regular_file", serve)
    monkeypatch.setattr(otlp, "open_regular_file", serve)
    evidence = collect(inventory, [trace])
    assert evidence["inputs"]["inventory"]["name"] == "inventory-\ufffd.json"
    assert evidence["inputs"]["trace_files"][0]["name"] == "trace-\ufffd\ufffd.json"
    assert parse_json_strict(render(evidence)) == evidence


def test_an_inventory_without_metadata_is_read_as_one_with_empty_metadata(tmp_path):
    trace = _trace(tmp_path, otlp_export(_tool("a")))
    found = {}
    for name, text in (
        ("bare", '{"components": []}'),
        ("empty", '{"metadata": {}, "components": []}'),
    ):
        inventory = tmp_path / f"{name}.json"
        inventory.write_text(text)
        found[name] = collect(inventory, [trace])["inputs"]["inventory"]["content_digest"]
    assert found["bare"] is not None
    assert found["bare"] == found["empty"]


def test_the_document_is_deterministic_and_independent_of_span_order(tmp_path):
    spans = [
        _tool("b"),
        _mcp_tool("a", "mcp.example.com"),
        otlp_span({"gen_ai.request.model": "m"}),
    ]
    inventory = _inventory(tmp_path, _declared_tool("tool:a", "a"))
    forward = _trace(tmp_path, otlp_export(*spans), "forward.json")
    backward = _trace(tmp_path, otlp_export(*reversed(spans)), "backward.json")
    first = collect(inventory, [forward])
    assert render(first) == render(collect(inventory, [forward]))
    second = collect(inventory, [backward])
    for key in ("observed", "reconciliation", "coverage", "gate"):
        assert second[key] == first[key]
    assert json.loads(render(first)) == first
    assert render(first).endswith("}\n")


def test_sarif_reports_undeclared_and_unidentified_use_only(tmp_path):
    components = [
        _server("mcp:t", "tickets", "https://mcp.example.com"),
        _server("mcp:idle", "idle"),
    ]
    spans = [
        _mcp_tool("search_tickets", "mcp.example.com"),
        _tool(TOKEN),
        otlp_span({"gen_ai.skill.name": "unmatched-skill"}),
        otlp_span({"gen_ai.skill.name": TOKEN}),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    sarif = sarif_document(evidence, "inventory/bom.json")
    assert validate_sarif(sarif) == []
    run = sarif["runs"][0]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [
        "nexus_symbiote/runtime_undeclared/high"
    ]
    results = run["results"]
    assert [(r["properties"]["kind"], r["properties"]["status"]) for r in results] == [
        ("tool", "undeclared"),
        ("tool", "unidentified"),
    ]
    assert {r["level"] for r in results} == {"error"}
    assert {r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results} == {
        "inventory/bom.json"
    }
    assert "search_tickets" in results[0]["message"]["text"]
    assert results[1]["properties"]["unreadable"] == {"name": "withheld"}
    assert TOKEN not in json.dumps(sarif)
    assert run["properties"]["assurance"] == "reported"
    fingerprints = [r["partialFingerprints"]["nexus_symbiote/v1"] for r in results]
    again = sarif_document(evidence, "inventory/bom.json")["runs"][0]["results"]
    assert fingerprints == [r["partialFingerprints"]["nexus_symbiote/v1"] for r in again]
    assert len(set(fingerprints)) == 2


def test_the_sarif_rule_describes_reported_runtime_use_for_both_statuses(tmp_path):
    evidence = _evidence(tmp_path, [], _tool("undeclared_tool"), _tool(TOKEN))
    rule = sarif_document(evidence, "bom.json")["runs"][0]["tool"]["driver"]["rules"][0]
    assert (
        rule["shortDescription"]["text"] == "Runtime component not matched to the inventory (high)"
    )
    description = rule["fullDescription"]["text"]
    assert "could not be read" in description and "not in the inventory" not in description
    help_text = rule["help"]["text"]
    assert help_text.startswith(description + " ")
    assert "comes from the agent's own telemetry, not from the inventory" in help_text
    assert "assurance reported" in help_text and "status unidentified" in help_text
    assert "recommendation" not in help_text and "declarations in the repository" not in help_text
    assert rule["helpUri"].endswith("/docs/trace-evidence.md#sarif")


def test_sarif_without_findings_still_validates(tmp_path):
    evidence = _evidence(tmp_path, [_declared_tool("tool:a", "a")], _tool("a"))
    sarif = sarif_document(evidence, ".nexus-symbiote.yaml")
    assert validate_sarif(sarif) == []
    assert (sarif["runs"][0]["results"], sarif["runs"][0]["tool"]["driver"]["rules"]) == ([], [])


@pytest.mark.parametrize(
    ("entry", "text"),
    [
        ({"kind": "tool", "name": "t", "endpoint": None}, "tool 't'"),
        (
            {"kind": "tool", "name": None, "endpoint": "h:1", "unreadable": {"name": "oversized"}},
            "tool <name oversized> on MCP endpoint h:1",
        ),
        (
            {
                "kind": "tool",
                "name": "t",
                "endpoint": "h",
                "unreadable": {"port": "invalid"},
            },
            "tool 't' on MCP endpoint h port <port invalid>",
        ),
        (
            {"kind": "tool", "name": "t", "endpoint": None, "unreadable": {"host": "withheld"}},
            "tool 't' on MCP endpoint <host withheld>",
        ),
        ({"kind": "model", "provider": None, "model": "m"}, "model 'm'"),
        (
            {
                "kind": "model",
                "provider": None,
                "model": "m",
                "unreadable": {"provider": "withheld"},
            },
            "model 'm' from provider <provider withheld>",
        ),
        ({"kind": "agent", "id": "i", "name": "n"}, "agent named 'n' with id 'i'"),
        ({"kind": "mcp-endpoint", "host": "::1", "port": "8443"}, "MCP endpoint [::1]:8443"),
        (
            {
                "kind": "mcp-endpoint",
                "host": None,
                "port": None,
                "unreadable": {"host": "withheld", "port": "invalid"},
            },
            "MCP endpoint <host withheld> port <port invalid>",
        ),
        (
            {
                "kind": "mcp-endpoint",
                "host": "::1",
                "port": None,
                "unreadable": {"port": "invalid"},
            },
            "MCP endpoint [::1] port <port invalid>",
        ),
        (
            {
                "kind": "mcp-endpoint",
                "host": None,
                "port": "443",
                "unreadable": {"host": "withheld"},
            },
            "MCP endpoint <host withheld> port 443",
        ),
        ({"kind": "memory-store", "id": "s"}, "memory-store 's'"),
    ],
)
def test_entries_are_described_with_unreadable_fields_named(entry, text):
    assert describe(entry) == text


def test_trace_work_grows_linearly_with_spans_and_inventory(tmp_path):
    def inputs(scale: int) -> tuple[Path, Path]:
        directory = tmp_path / str(scale)
        directory.mkdir()
        count = 300 * scale
        components: list[AnyComponent] = [
            _server("mcp:shared", "shared", "https://mcp.example.com")
        ]
        components += [_declared_tool(f"tool:{i}", f"tool-{i}", "mcp:shared") for i in range(count)]
        components += [_declared_tool(f"tool:same-{i}", "same", "mcp:shared") for i in range(count)]
        spans = [_mcp_tool(f"tool-{i * 2}", "mcp.example.com", 443 + i) for i in range(count)]
        spans += [_mcp_tool("same", f"h{i}.example") for i in range(count)]
        return _inventory(directory, *components), _trace(directory, otlp_export(*spans))

    prepared = {scale: inputs(scale) for scale in (1, 4)}
    assert scaling_ratio(lambda scale: collect(prepared[scale][0], [prepared[scale][1]])) < 10


def test_reconciliation_marks_a_candidate_list_shared_by_many_items_once():
    # Every item below finds the same long list: many agent ids under one unbound name,
    # many ports on a host whose servers state none, and one model name from many
    # providers against providerless declarations. Marking each list as mentioned once
    # keeps reconciliation linear; marking it once per item would make it quadratic.
    def inputs(scale: int) -> tuple[Observations, AIBOM]:
        count = 400 * scale
        components: list[AnyComponent] = []
        for i in range(count):
            components += [
                _agent(f"agent:{i}", "twin", source=None),
                _server(f"mcp:{i}", f"server-{i}", "tcp://portless.example"),
                _declared_tool(f"tool:{i}", "same", f"mcp:{i}"),
                ModelComponent(bom_ref=f"model:{i}", name="m", model_type="hosted"),
            ]
        observations = Observations()
        for i in range(count):
            attributes: dict[str, otlp.Identifier] = {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.id": f"id-{i}",
                "gen_ai.agent.name": "twin",
                "mcp.method.name": "tools/call",
                "gen_ai.tool.name": "same",
                "network.transport": "tcp",
                "server.address": "portless.example",
                "server.port": str(1000 + i),
                "gen_ai.request.model": "m",
                "gen_ai.provider.name": f"provider-{i}",
            }
            observations.add(otlp.Span(1, CLIENT, None, attributes, None))
        return observations, AIBOM(components=components)

    prepared = {scale: inputs(scale) for scale in (1, 4)}
    reconciliation = reconcile(*prepared[1])
    assert len(reconciliation["ambiguous"]) == 4 * 400
    assert reconciliation["unobserved"] == []
    assert scaling_ratio(lambda scale: reconcile(*prepared[scale])) < 10


def test_a_reader_refuses_links_and_special_files(tmp_path):
    target = _trace(tmp_path, otlp_export())
    link = tmp_path / "link.json"
    link.symlink_to(target)
    with pytest.raises(TraceInputError, match="symbolic link"):
        _read(link)
    with pytest.raises(TraceInputError, match="not a regular file"):
        _read(tmp_path)
    with pytest.raises(TraceInputError, match="does not exist"):
        _read(tmp_path / "missing.json")


def test_distinct_withheld_names_fold_into_one_unidentified_item(tmp_path):
    other = "ghp_" + "Z9y8X7w6V5" * 4
    evidence = _evidence(tmp_path, [], _tool(TOKEN), _tool(other), _tool(TOKEN))
    assert _entries(evidence, "unidentified") == [
        {
            "kind": "tool",
            "name": None,
            "endpoint": None,
            "span_count": 3,
            "unreadable": {"name": "withheld"},
        }
    ]
    assert evidence["coverage"]["unreadable_identifiers"]["withheld"] == 3
    assert other not in render(evidence)


def test_an_item_with_a_copied_span_counts_both(tmp_path):
    span = _tool("lookup")
    evidence = _evidence(tmp_path, [], span, copy.deepcopy(span))
    assert [e["span_count"] for e in evidence["observed"]] == [2]


@pytest.mark.parametrize(
    ("error", "problem"),
    [
        (PermissionError(13, "denied"), "cannot be read: permission denied"),
        (OSError(36, "name too long"), "cannot be opened for reading"),
    ],
)
def test_open_failures_are_named_by_their_class(tmp_path, monkeypatch, error, problem):
    def refuse(path: Path) -> None:
        raise error

    monkeypatch.setattr(otlp, "open_regular_file", refuse)
    with pytest.raises(TraceInputError) as raised:
        _read(tmp_path / "trace.json")
    assert str(raised.value) == f"trace file 1 {problem}"


def test_one_document_may_have_a_first_line_longer_than_the_line_bound(tmp_path, monkeypatch):
    document = otlp_export(_tool("lookup"))
    text = json.dumps(document, indent=2).replace("{\n", "{" + " " * 400 + "\n", 1)
    monkeypatch.setattr(otlp, "MAX_LINE_BYTES", 300)
    path = tmp_path / "trace.json"
    path.write_text(text)
    reader, spans = _read(path)
    assert reader.files[0].form == "json"
    assert [span.attributes["gen_ai.tool.name"] for span in spans] == ["lookup"]


def test_a_span_without_a_kind_is_not_an_mcp_client(tmp_path):
    span = _mcp_tool("lookup", "mcp.example.com")
    del span["kind"]
    evidence = _evidence(tmp_path, [], span)
    assert [entry["kind"] for entry in evidence["observed"]] == ["tool"]
    assert evidence["coverage"]["mcp_client_spans"] == {
        "attributed": 0,
        "stdio": 0,
        "unattributed": 0,
    }


@pytest.mark.parametrize(
    "value",
    [{"intValue": "7"}, {"stringValue": "  \t "}, {"stringValue": None}, {"arrayValue": {}}],
)
def test_an_identifier_that_is_not_a_nonblank_string_is_invalid(tmp_path, value):
    evidence = _evidence(tmp_path, [], _tool("placeholder", **{"gen_ai.tool.name": value}))
    assert _entries(evidence, "unidentified") == [
        {
            "kind": "tool",
            "name": None,
            "endpoint": None,
            "span_count": 1,
            "unreadable": {"name": "invalid"},
        }
    ]
    assert evidence["coverage"]["unreadable_identifiers"]["invalid"] == 1


def test_blank_inventory_names_match_nothing_and_unbound_agents_match_by_name(tmp_path):
    components = [
        _declared_tool("tool:blank", "  "),
        _agent("agent:blank", " "),
        _agent(INFERRED_AGENT_REF, "manifest-agent"),
        _agent("agent:twin-1", "twin"),
        _agent("agent:twin-2", "twin", source=None),
    ]
    invoke = {"gen_ai.operation.name": "invoke_agent"}
    spans = [
        _tool("blank"),
        otlp_span({**invoke, "gen_ai.agent.id": "some-id", "gen_ai.agent.name": "manifest-agent"}),
        otlp_span({**invoke, "gen_ai.agent.name": "twin"}),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    assert [e["inventory_ref"] for e in _entries(evidence, "matched", "agent")] == [
        INFERRED_AGENT_REF
    ]
    assert [e["candidates"] for e in _entries(evidence, "ambiguous", "agent")] == [
        ["agent:twin-1", "agent:twin-2"]
    ]
    assert [e["name"] for e in _entries(evidence, "undeclared", "tool")] == ["blank"]


def test_every_coverage_gap_has_a_note(tmp_path):
    filler = {f"custom.attribute.{i}": "x" for i in range(otlp.MAX_ATTRIBUTES + 1)}
    spans = [
        otlp_span(filler),
        otlp_span({"gen_ai.operation.name": "execute_tool", "gen_ai.input.messages": MARKER}),
        otlp_span({"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "a" * 600}),
        otlp_span({"mcp.method.name": "ping", "network.transport": "pipe"}, kind=CLIENT),
        otlp_span({"mcp.method.name": "ping", "network.transport": "tcp"}, kind=CLIENT),
        otlp_span({"gen_ai.request.model": "m", "gen_ai.system": "openai"}),
        otlp_span({"gen_ai.operation.name": "chat" + PADDED}),
        otlp_span({"mcp.method.name": {"boolValue": True}}),
    ]
    evidence = _evidence(tmp_path, [], *spans)
    assert (
        "2 spans have an operation name, MCP method or MCP transport that could not be read, so "
        "what they report cannot be compared with the inventory"
    ) in evidence["gate"]["reasons"]
    assert coverage_notes(evidence) == [
        (
            "warning",
            "Spans with message, prompt or tool-call content attributes: 1. Protect these trace files.",
        ),
        (
            "warning",
            "Identifier values not used: 3 (invalid: 1, longer than 512 characters: 2, withheld "
            "as credential-shaped: 0).",
        ),
        (
            "warning",
            "Spans whose operation name, MCP method or MCP transport could not be read: 2. What "
            "they report cannot be compared with the inventory.",
        ),
        (
            "warning",
            "Attribute lists with more than 128 entries: 1. The entries after the first 128 were "
            "not read.",
        ),
        (
            "note",
            "MCP client spans over a pipe or unix socket: 1. A trace cannot attribute local "
            "activity to a configured server.",
        ),
        (
            "note",
            "MCP client spans without a server address, or whose transport could not be read: 1. "
            "Their endpoint is not attributed.",
        ),
        ("note", "Tool spans that name no tool: 1; agent spans that name no agent: 0."),
        ("note", "Spans that name their provider with the legacy gen_ai.system attribute: 1."),
    ]
    empty = _evidence(tmp_path, [], otlp_span({}))
    assert coverage_notes(empty) == [
        ("warning", "No span carries GenAI or MCP semantics: these traces cannot show any use.")
    ]


@pytest.mark.parametrize(
    ("content", "problem"),
    [
        (
            b'{"resourceSpans": [], "x": ' + b"[" * 100_000 + b"]" * 100_000 + b"}",
            "is nested too deeply to read",
        ),
        (b'{"resourceSpans": [], "x": "\xc3\x28"}', "is not UTF-8 text"),
        (
            b'{"resourceSpans": []}\n{"x": ' + b"[" * 100_000 + b"]" * 100_000 + b"}",
            "line 2 is nested too deeply to read",
        ),
        (b'{"resourceSpans": []}\n{"x": "\xff"}', "line 2 is not UTF-8 text"),
    ],
)
def test_nesting_and_encoding_problems_are_named(tmp_path, content, problem):
    path = tmp_path / "trace.json"
    path.write_bytes(content)
    with pytest.raises(TraceInputError) as raised:
        _read(path)
    assert str(raised.value) == f"trace file 1 {problem}"


def test_the_distinct_identifier_bound_refuses_the_traces_instead_of_dropping_items(
    tmp_path, monkeypatch
):
    from nexus_symbiote import trace_evidence

    monkeypatch.setattr(trace_evidence, "MAX_DISTINCT_IDENTIFIERS", 4)
    resource = {"service.name": "svc"}
    fits = _trace(tmp_path, otlp_export(_tool("a"), _tool("a"), _tool("b"), resource=resource))
    evidence = collect(_inventory(tmp_path), [fits])
    assert [e["span_count"] for e in evidence["observed"]] == [2, 1]
    over = _trace(
        tmp_path, otlp_export(_tool("a"), _tool("b"), _tool("c"), resource=resource), "over.json"
    )
    with pytest.raises(
        TraceInputError, match="trace file 1 exceeds the bound of 4 distinct identifiers"
    ):
        collect(_inventory(tmp_path), [over])


def test_sarif_warns_when_github_would_drop_results(tmp_path, monkeypatch):
    from nexus_symbiote.generators import sarif

    monkeypatch.setattr(sarif, "GITHUB_MAX_RESULTS", 1)
    evidence = _evidence(tmp_path, [], _tool("a"), _tool("b"))
    notifications = sarif_document(evidence, "bom.json")["runs"][0]["invocations"][0][
        "toolExecutionNotifications"
    ]
    assert {
        "level": "warning",
        "message": {
            "text": "This run has 2 results; GitHub code scanning keeps at most 1 per run."
        },
    } in notifications


def test_spiffe_workload_identity_and_tool_definition_hash_correlation(tmp_path):
    from click.testing import CliRunner

    from nexus_symbiote.cli import main

    tool_hash = "sha256:" + "ab" * 32
    components = [
        ToolComponent(
            bom_ref="tool:search",
            name="search",
            definition_hash=tool_hash,
        ),
        AgentComponent(
            bom_ref="agent:support",
            name="support",
            workload_identity="spiffe://example.org/ns/prod/sa/support-agent",
            properties={"identity_source": "agent.yaml"},
        ),
    ]
    spans = [
        otlp_span(
            {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "search",
                "gen_ai.tool.definition_hash": "AB" * 32,
                "spiffe.id": "spiffe://example.org/ns/prod/sa/support-agent",
            }
        ),
        otlp_span(
            {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.name": "support",
                "spiffe.id": "spiffe://example.org/ns/prod/sa/support-agent",
            }
        ),
    ]
    evidence = _evidence(tmp_path, components, *spans)
    matched = {e["inventory_ref"]: e for e in evidence["reconciliation"]["matched"]}
    assert matched["tool:search"]["definition_hash_matched"] is True
    assert matched["tool:search"]["reported_definition_hashes"] == ["AB" * 32]
    assert "span_count" not in matched["tool:search"]
    assert matched["agent:support"]["workload_identity_matched"] is True
    assert matched["agent:support"]["reported_workload_identities"] == [
        "spiffe://example.org/ns/prod/sa/support-agent"
    ]
    assert evidence["gate"]["passed"] is True

    # Conflicting or unreadable spiffe.id / definition_hash sets *_matched=False, fails gate,
    # lists Mismatched in summary, and emits SARIF results.
    conflict_spans = [
        *spans,
        otlp_span(
            {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "search",
                "gen_ai.tool.definition_hash": "sha256:" + "cd" * 32,
            }
        ),
        otlp_span(
            {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.name": "support",
                "spiffe.id": "spiffe://evil.example/ns/prod/sa/rogue",
            }
        ),
    ]
    inv_path = _inventory(tmp_path, *components)
    trace_path = _trace(tmp_path, otlp_export(*conflict_spans), "conflict-trace.json")
    sarif_out = tmp_path / "conflict.sarif"
    cli = CliRunner().invoke(
        main, ["trace-diff", str(inv_path), str(trace_path), "--sarif", str(sarif_out)]
    )
    assert cli.exit_code == 1
    assert "Mismatched:" in cli.output
    assert "conflicting or unreadable workload identity or tool definition hash" in cli.output
    sarif = json.loads(sarif_out.read_text(encoding="utf-8"))
    assert validate_sarif(sarif) == []
    statuses = [r["properties"]["status"] for r in sarif["runs"][0]["results"]]
    assert statuses == ["mismatched", "mismatched"]

    # Unreadable gen_ai.tool.definition_hash, malformed hex, or credential-shaped spiffe.id
    # fails closed; unrecorded inventory identity/hash reports None without failing the gate.
    unreadable_ev = _evidence(
        tmp_path,
        components,
        otlp_span(
            {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "search",
                "gen_ai.tool.definition_hash": {"intValue": "99"},
            }
        ),
        otlp_span(
            {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.name": "support",
                "spiffe.id": "spiffe://example.org/token/sk-ant-api03-" + "a" * 95,
            }
        ),
    )
    unreadable_matched = {e["inventory_ref"]: e for e in unreadable_ev["reconciliation"]["matched"]}
    assert unreadable_matched["tool:search"]["definition_hash_matched"] is False
    assert unreadable_matched["agent:support"]["workload_identity_matched"] is False
    assert unreadable_ev["gate"]["passed"] is False

    bad_hex_ev = _evidence(
        tmp_path,
        components,
        otlp_span(
            {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "search",
                "gen_ai.tool.definition_hash": "not-a-valid-sha256",
            }
        ),
    )
    bad_hex_matched = {e["inventory_ref"]: e for e in bad_hex_ev["reconciliation"]["matched"]}
    assert bad_hex_matched["tool:search"]["definition_hash_matched"] is False
    assert bad_hex_ev["gate"]["passed"] is False

    unpinned_components = [
        ToolComponent(bom_ref="tool:plain", name="plain"),
        AgentComponent(
            bom_ref="agent:plain",
            name="plain",
            properties={"identity_source": "agent.yaml"},
        ),
    ]
    unpinned_ev = _evidence(
        tmp_path,
        unpinned_components,
        otlp_span(
            {
                "gen_ai.operation.name": "execute_tool",
                "gen_ai.tool.name": "plain",
                "gen_ai.tool.definition_hash": "ab" * 32,
            }
        ),
        otlp_span(
            {
                "gen_ai.operation.name": "invoke_agent",
                "gen_ai.agent.name": "plain",
                "peer.identity": "spiffe://example.org/ns/prod/sa/plain",
            },
            kind=3,
        ),
    )
    unpinned_matched = {e["inventory_ref"]: e for e in unpinned_ev["reconciliation"]["matched"]}
    assert unpinned_matched["tool:plain"]["definition_hash_matched"] is None
    assert unpinned_matched["agent:plain"]["workload_identity_matched"] is None
    assert unpinned_ev["gate"]["passed"] is True


def test_a_caller_span_does_not_lend_its_identity_to_the_agent_it_invokes(tmp_path):
    declared = "spiffe://example.org/sa/support"
    agent = AgentComponent(
        bom_ref="agent:support",
        name="support",
        workload_identity=declared,
        properties={"identity_source": "agent.yaml"},
    )
    own = {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "support"}
    document = otlp_export(otlp_span({**own, "spiffe.id": declared}, kind=2))
    caller = otlp_export(
        otlp_span(own, kind=3),
        resource={"service.name": "orchestrator", "spiffe.id": "spiffe://example.org/sa/orch"},
    )
    document["resourceSpans"] += caller["resourceSpans"]
    evidence = collect(_inventory(tmp_path, agent), [_trace(tmp_path, document)])
    [entry] = evidence["reconciliation"]["matched"]
    assert entry["reported_workload_identities"] == [declared]
    assert entry["workload_identity_matched"] is True
    assert evidence["gate"]["passed"] is True

    mtls = {**own, "spiffe.id": declared, "peer.identity": "spiffe://example.org/sa/orch"}
    server_side = _evidence(tmp_path, [agent], otlp_span(mtls, kind=2))
    assert server_side["reconciliation"]["matched"][0]["workload_identity_matched"] is True
    callee = _evidence(
        tmp_path,
        [agent],
        otlp_span({**own, "peer.identity": "spiffe://x.example/sa/rogue"}, kind=3),
    )
    assert callee["reconciliation"]["matched"][0]["workload_identity_matched"] is False
    assert callee["gate"]["passed"] is False


@pytest.mark.parametrize("kind", [0, 1, 2, 5, 9])
def test_a_span_the_agent_emits_is_gated_on_its_own_identity(tmp_path, kind):
    agent = _agent("agent:support", "support").model_copy(
        update={"workload_identity": "spiffe://example.org/sa/support"}
    )
    own = {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "support"}
    rogue = {**own, "spiffe.id": "spiffe://example.org/sa/rogue"}
    evidence = _evidence(tmp_path, [agent], otlp_span(rogue, kind=kind))
    assert evidence["reconciliation"]["matched"][0]["workload_identity_matched"] is False
    assert evidence["gate"]["passed"] is False


@pytest.mark.parametrize("kind", [3, 4])
def test_a_caller_span_reports_its_own_identity_and_gates_an_unreadable_one(tmp_path, kind):
    agent = _agent("agent:support", "support").model_copy(
        update={"workload_identity": "spiffe://example.org/sa/support"}
    )
    own = {"gen_ai.operation.name": "invoke_agent", "gen_ai.agent.name": "support"}
    caller = otlp_export(
        otlp_span(own, kind=kind), resource={"spiffe.id": "spiffe://example.org/sa/rogue"}
    )
    evidence = collect(_inventory(tmp_path, agent), [_trace(tmp_path, caller)])
    [entry] = evidence["reconciliation"]["matched"]
    assert entry["caller_workload_identities"] == ["spiffe://example.org/sa/rogue"]
    assert "workload_identity_matched" not in entry
    secret = "spiffe://example.org/token/sk-ant-api03-" + "a" * 95
    hidden = _evidence(tmp_path, [agent], otlp_span({**own, "spiffe.id": secret}, kind=kind))
    assert hidden["reconciliation"]["matched"][0]["workload_identity_matched"] is False
    assert hidden["gate"]["passed"] is False
