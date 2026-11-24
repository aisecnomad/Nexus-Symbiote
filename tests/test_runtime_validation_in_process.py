"""The schema validation worker's code, run in the test process so coverage can see it.

Audit 2026-11-14 T3: the worker runs as ``python -I`` with ``PATH`` alone, which coverage
does not trace, so the dialect loader, the ECMA-262 self-check, the evaluation and the
worker protocol measured as untested however many subprocess tests drove them. These
tests run the same functions in-process. ``_load_dialects`` rebinds ``re`` on four private
jsonschema modules, as the worker does; ``monkeypatch`` restores them after each test.

Every case is also sent through the real isolated worker and must get the same answer,
so the in-process path stays a faithful stand-in for it.
"""

from __future__ import annotations

import io
import json
import re
import resource
import sys
from typing import Any

import jsonschema._format
import jsonschema._keywords
import jsonschema._legacy_keywords
import jsonschema._utils
import pytest

import nexus_symbiote.runtime_validation as validation

PATCHED = (
    jsonschema._format,
    jsonschema._keywords,
    jsonschema._legacy_keywords,
    jsonschema._utils,
)
WORDS = {validation._VALID: "valid", validation._INVALID: "arguments-invalid"}
WORDS[validation._SCHEMA] = "schema-invalid"
DRAFT_07 = "http://json-schema.org/draft-07/schema#"
DRAFT_2019 = "https://json-schema.org/draft/2019-09/schema"


@pytest.fixture
def dialects(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    for module in PATCHED:
        monkeypatch.setattr(module, "re", module.re)
    return validation._load_dialects()


def in_process(dialects: dict[str, Any], schema: dict[str, Any], arguments: Any) -> str:
    return WORDS[validation._evaluate(dialects, schema, arguments)]


def isolated(schema: dict[str, Any], arguments: dict[str, Any]) -> str:
    try:
        validation.validate_arguments(schema, arguments)
    except validation.ValidationBudgetError as exc:
        return exc.reason
    return "valid"


def string(pattern: str, **extra: Any) -> dict[str, Any]:
    return {"type": "object", "properties": {"v": {"type": "string", "pattern": pattern}}, **extra}


CASES = [
    # ECMA-262 pattern meaning, through each translation branch.
    ("anchor", string("^a$"), {"v": "a\n"}, "arguments-invalid"),
    ("ascii-digit", string(r"^\d+$"), {"v": "\u0663"}, "arguments-invalid"),
    ("ascii-word", string(r"^\w+$"), {"v": "caf\xe9"}, "arguments-invalid"),
    ("dot", string("^.+$"), {"v": "a\u2028b"}, "arguments-invalid"),
    ("space", string(r"^\s$"), {"v": "\ufeff"}, "valid"),
    ("not-space", string(r"^\S+$"), {"v": "a\xa0b"}, "arguments-invalid"),
    ("class-escape", string(r"^[\d-]+$"), {"v": "12-34"}, "valid"),
    ("class-complement", string(r"^[^\S]+$"), {"v": " \t"}, "valid"),
    ("class-range", string(r"^[a-z-\d]+$"), {"v": "A"}, "arguments-invalid"),
    (
        "named-backreference",
        string(r"^(?<y>\d{4})-\k<y>$"),
        {"v": "2026-2027"},
        "arguments-invalid",
    ),
    ("numbered-backreference", string(r"^(a)\1$"), {"v": "aa"}, "valid"),
    ("unicode-escape", string(r"^\u0041$"), {"v": "A"}, "valid"),
    ("surrogate-pair", string(r"^\ud83d\ude00$"), {"v": "\U0001f600"}, "valid"),
    ("lookbehind", string(r"(?<=a)b"), {"v": "ab"}, "valid"),
    ("negative-lookahead", string(r"^(?!x).$"), {"v": "x"}, "arguments-invalid"),
    ("quantifier", string(r"^a{2,3}$"), {"v": "aaaa"}, "arguments-invalid"),
    ("python-only-quantifier", string(r"^a{,2}$"), {"v": "a{,2}"}, "schema-invalid"),
    ("identity-escape", string(r"^\/$"), {"v": "/"}, "valid"),
    ("invalid-pattern", string("(unclosed"), {"v": "x"}, "schema-invalid"),
    (
        "pattern-properties",
        {"type": "object", "patternProperties": {"^a$": {}}, "additionalProperties": False},
        {"a\n": 0},
        "arguments-invalid",
    ),
    (
        "unevaluated-properties",
        {"type": "object", "patternProperties": {"^a$": {}}, "unevaluatedProperties": False},
        {"a": 0},
        "valid",
    ),
    # Dialects and keywords evaluation would skip.
    (
        "draft-07",
        {"$schema": DRAFT_07, "type": "object", "required": ["v"]},
        {},
        "arguments-invalid",
    ),
    (
        "unknown-dialect",
        {"$schema": "https://example.test/schema", "type": "object"},
        {},
        "schema-invalid",
    ),
    ("dialect-not-a-string", {"$schema": 7, "type": "object"}, {}, "schema-invalid"),
    # A keyword of another dialect is refused; a name no dialect defines is ignored,
    # as JSON Schema specifies (see the audit status note on lookalike keywords).
    (
        "other-dialect-keyword",
        {"type": "object", "dependencies": {"a": ["b"]}},
        {},
        "schema-invalid",
    ),
    ("undefined-keyword", {"type": "object", "maxProperites": 1}, {"a": 1, "b": 2}, "valid"),
    (
        "homoglyph-keyword",
        {"type": "object", "properties": {"v": {"type": "string", "maxL\u0435ngth": 1}}},
        {"v": "ab"},
        "schema-invalid",
    ),
    (
        "invisible-keyword",
        {"type": "object", "additionalPropert\u200bies": False},
        {"a": 1},
        "schema-invalid",
    ),
    (
        "whitespace-keyword",
        {"type": "object", "maxProperties ": 0},
        {"a": 1},
        "schema-invalid",
    ),
    (
        "unicode-property-name-allowed",
        {"type": "object", "properties": {"caf\u00e9": {"type": "string", "maxLength": 2}}},
        {"caf\u00e9": "abc"},
        "arguments-invalid",
    ),
    (
        "optional-false",
        {"type": "object", "properties": {"v": {"optional": False}}},
        {},
        "schema-invalid",
    ),
    (
        "ref-sibling-draft-07",
        {
            "$schema": DRAFT_07,
            "definitions": {"s": {"type": "string"}},
            "properties": {"v": {"$ref": "#/definitions/s", "maxLength": 1}},
        },
        {"v": "ab"},
        "schema-invalid",
    ),
    (
        "ref-within-schema",
        {
            "$defs": {"s": {"type": "string", "maxLength": 1}},
            "properties": {"v": {"$ref": "#/$defs/s"}},
        },
        {"v": "ab"},
        "arguments-invalid",
    ),
    (
        "ref-outside-schema",
        {"properties": {"v": {"$ref": "https://example.test/s"}}},
        {},
        "schema-invalid",
    ),
    ("ref-missing-target", {"properties": {"v": {"$ref": "#/$defs/none"}}}, {}, "schema-invalid"),
    (
        "nested-id",
        {"properties": {"v": {"$id": "https://example.test/v", "type": "string"}}},
        {},
        "schema-invalid",
    ),
    (
        "nested-dialect",
        {"properties": {"v": {"$schema": DRAFT_07, "type": "string"}}},
        {},
        "schema-invalid",
    ),
    (
        "contains-meets-unevaluated-items",
        {
            "$schema": DRAFT_2019,
            "properties": {
                "v": {"type": "array", "contains": {"type": "string"}, "unevaluatedItems": False}
            },
        },
        {"v": ["a"]},
        "schema-invalid",
    ),
    ("invalid-schema", {"type": 5}, {}, "schema-invalid"),
    ("valid", {"type": "object", "properties": {"v": {"type": "integer"}}}, {"v": 1}, "valid"),
]


@pytest.mark.parametrize(
    ("schema", "arguments", "expected"),
    [case[1:] for case in CASES],
    ids=[case[0] for case in CASES],
)
def test_in_process_evaluation_matches_the_isolated_worker(dialects, schema, arguments, expected):
    assert in_process(dialects, schema, arguments) == expected
    assert isolated(schema, arguments) == expected


def test_the_self_check_holds_and_notices_python_regex_semantics(dialects):
    assert validation._ecma_semantics_hold(dialects)
    for module in (jsonschema._keywords, jsonschema._utils):
        patched, module.re = module.re, re
        try:
            assert not validation._ecma_semantics_hold(dialects)
        finally:
            module.re = patched


def test_the_translating_regex_delegates_other_attributes(dialects):
    regex = jsonschema._keywords.re
    assert isinstance(regex, validation._EcmaRegex)
    assert regex.compile("^a$").search("a\n") is None
    assert regex.search("^a$", "a") is not None
    assert regex.escape("a.b") == re.escape("a.b")


def test_the_dialect_loader_is_undone_after_each_test():
    # Runs after the fixture-using tests: the suite's other jsonschema users see re.
    assert all(module.re is re for module in PATCHED)


class _Streams:
    def __init__(self, data: bytes) -> None:
        self.stdin = type("In", (), {"buffer": io.BytesIO(data)})()
        self.stdout = type("Out", (), {"buffer": io.BytesIO()})()


def run_worker(monkeypatch: pytest.MonkeyPatch, wire: bytes) -> tuple[int, bytes]:
    """``_worker`` in-process: no rlimits on the test process, no module blocking."""
    for module in PATCHED:
        monkeypatch.setattr(module, "re", module.re)
    monkeypatch.setattr(validation, "_apply_worker_limits", lambda: None)
    monkeypatch.setattr(validation, "_disable_unused_format_checkers", lambda: None)
    monkeypatch.setattr(resource, "setrlimit", lambda *_: None)
    streams = _Streams(wire)
    monkeypatch.setattr(sys, "stdin", streams.stdin)
    monkeypatch.setattr(sys, "stdout", streams.stdout)
    code = validation._worker()
    return code, streams.stdout.buffer.getvalue()


def request(schema: Any, arguments: Any) -> bytes:
    return json.dumps({"schema": schema, "arguments": arguments}).encode()


def test_the_worker_answers_a_well_formed_request(monkeypatch):
    code, out = run_worker(monkeypatch, request({"type": "object"}, {}))
    assert (code, out) == (0, validation._READY + validation._VALID)


@pytest.mark.parametrize(
    "wire",
    [
        b"[]",
        json.dumps({"schema": {}}).encode(),
        json.dumps({"schema": {}, "arguments": {}, "extra": 1}).encode(),
        request([], {}),
        request({}, []),
        request({"type": "object"}, {"v": "x" * (validation.MAX_ARGUMENT_BYTES + 1)}),
        b"{" * 10,
        b" " * (validation.MAX_SCHEMA_BYTES + validation.MAX_ARGUMENT_BYTES + 65),
    ],
    ids=[
        "not-an-object",
        "missing-arguments",
        "extra-key",
        "schema-not-an-object",
        "arguments-not-an-object",
        "arguments-over-budget",
        "not-json",
        "over-the-byte-limit",
    ],
)
def test_the_worker_refuses_a_malformed_request_without_an_answer(monkeypatch, wire):
    code, out = run_worker(monkeypatch, wire)
    assert (code, out) == (1, validation._READY)


def test_the_worker_does_not_start_when_the_self_check_fails(monkeypatch):
    monkeypatch.setattr(validation, "_ecma_semantics_hold", lambda _: False)
    code, out = run_worker(monkeypatch, request({"type": "object"}, {}))
    assert (code, out) == (1, b"")


def test_the_worker_refuses_outside_posix(monkeypatch):
    monkeypatch.setattr(validation.os, "name", "nt")
    assert validation._worker() == 2


@pytest.mark.parametrize(
    ("pattern", "message"),
    [
        ("(?<name", "unterminated group name"),
        ("(?<n>a)(?<n>b)", "duplicate group name"),
        ("a)", "unbalanced parenthesis"),
    ],
)
def test_ecma_pattern_refuses_malformed_groups(pattern, message):
    # A pattern ECMA-262 rejects must not reach the worker as a different Python regex.
    with pytest.raises(re.error, match=message):
        validation.ecma_pattern(pattern)


@pytest.mark.parametrize("pattern", ["a+?b", "a??", "a{1,2}?"])
def test_ecma_pattern_keeps_a_lazy_quantifier(pattern):
    assert validation.ecma_pattern(pattern) == pattern


def test_a_schema_that_is_not_an_object_is_refused_before_the_worker():
    with pytest.raises(validation.ValidationBudgetError) as caught:
        validation.validate_arguments(["not", "an", "object"], {})
    assert caught.value.reason == "schema-invalid"
