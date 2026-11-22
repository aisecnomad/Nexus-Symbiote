"""Admission of ordinary structured outputs at production and scaled limits."""

import pytest

from nexus_symbiote import runtime_validation as validation
from tests.test_runtime_validation_in_process import dialects as dialects


def _row(fields):
    names = [f"field_{i}" for i in range(fields)]
    schema = {
        "type": "object",
        "properties": {name: {"type": "integer"} for name in names},
        "required": names,
        "additionalProperties": False,
    }
    return schema, dict.fromkeys(names, 1)


@pytest.mark.parametrize("kind", ["list", "map", "enum", "tagged", "tree"])
def test_common_collections_are_admitted_and_validate(dialects, kind):
    row, value = _row(20)
    definitions = {"Row": row}
    ref = {"$ref": "#/$defs/Row"}
    if kind == "list":
        field, data = {"type": "array", "items": ref}, [value, value]
    elif kind == "map":
        field, data = {"type": "object", "additionalProperties": ref}, {"sample": value}
    elif kind == "enum":
        choices = [f"region_{i}" for i in range(50)]
        field, data = {"type": "array", "items": {"enum": choices}}, choices[:3]
    elif kind == "tree":
        row["properties"]["children"] = {"type": "array", "items": ref}
        field, data = ref, {**value, "children": [value]}
    else:
        arms = []
        for i in range(8):
            name = f"Label{i}"
            definitions[name] = {
                "type": "object",
                "required": ["kind", "title"],
                "properties": {"kind": {"const": name}, "title": {"type": "string"}},
            }
            arms.append({"$ref": f"#/$defs/{name}"})
        field = {"type": "array", "items": {"oneOf": arms}}
        data = [{"kind": "Label1", "title": "sample"}]
    schema = {"$defs": definitions, "type": "object", "properties": {"data": field}}
    assert validation._evaluate(dialects, schema, None) == validation._VALID
    assert validation._evaluate(dialects, schema, {"data": data}) == validation._VALID
    assert validation._evaluate(dialects, schema, {"data": 17}) == validation._INVALID


@pytest.mark.parametrize("kind", ["items", "properties", "prefix"])
def test_small_collection_bounds_accumulate_across_entries(monkeypatch, dialects, kind):
    monkeypatch.setattr(validation, "_MAX_OUTPUT_REPEATED_STEPS", 32)
    part = {"oneOf": [{"const": x} for x in (1, 2, 3, 4)]}

    def rows(size):
        if kind == "items":
            inner = {"type": "array", "maxItems": size, "items": part}
            return {"type": "array", "maxItems": 3, "items": inner}
        if kind == "properties":
            return {"properties": {f"field_{i}": part for i in range(size * 3)}}
        return {"prefixItems": [part] * (size * 3)}

    assert validation._evaluate(dialects, rows(1), None) == validation._VALID
    assert validation._evaluate(dialects, rows(4), None) == validation._SCHEMA


@pytest.mark.parametrize("kind", ["unique", "patterns"])
def test_comparison_work_respects_the_declared_cardinality(monkeypatch, dialects, kind):
    monkeypatch.setattr(validation, "_MAX_OUTPUT_REPEATED_STEPS", 4)
    if kind == "unique":
        rule = {"type": "array", "items": {"type": "object"}, "uniqueItems": True}
        bound = "maxItems"
    else:
        rule = {"type": "object", "patternProperties": {"^a": True, "^b": True}}
        bound = "maxProperties"
    assert validation._evaluate(dialects, {**rule, bound: 2}, None) == validation._VALID
    assert validation._evaluate(dialects, {**rule, bound: 80}, None) == validation._SCHEMA


def test_integer_valued_json_bounds_work_for_sortable_unique_ids(dialects):
    schema = {"type": "array", "items": {"type": "string"}, "uniqueItems": True, "maxItems": 4.0}
    assert validation._evaluate(dialects, schema, None) == validation._VALID
    assert validation._evaluate(dialects, schema, ["desk", "lamp"]) == validation._VALID
    assert validation._evaluate(dialects, schema, ["desk", "desk"]) == validation._INVALID


def test_closed_collection_annotation_work_is_bounded_before_dispatch(monkeypatch, dialects):
    # Compare preflight only under a lowered static budget. No result is dispatched.
    monkeypatch.setattr(validation, "_MAX_OUTPUT_APPLICATOR_STEPS", 32)
    record = {"type": "object", "additionalProperties": {"$ref": "#/$defs/record"}}
    schema = {"$defs": {"record": record}, "properties": {"account": {"$ref": "#/$defs/record"}}}
    assert validation._evaluate(dialects, schema, None) == validation._VALID
    record["unevaluatedProperties"] = False
    assert validation._evaluate(dialects, schema, None) == validation._SCHEMA


@pytest.mark.parametrize(
    ("schema", "expected"),
    [
        (
            {"uniqueItems": True, "type": "array", "items": {"type": "string"}},
            validation._SCHEMA,
        ),
        (
            {"type": "array", "items": {"type": "string"}, "uniqueItems": True, "maxItems": 1000},
            validation._SCHEMA,
        ),
        (
            {"type": "array", "items": {"type": "string"}, "uniqueItems": True, "maxItems": 200},
            validation._VALID,
        ),
    ],
)
def test_unique_items_requires_quadratic_bound_even_for_scalar_items(dialects, schema, expected):
    assert validation._evaluate(dialects, schema, None) == expected


@pytest.mark.parametrize(
    "wrapper", ["contains-footprint", "contains-branching", "anyOf", "not", "if"]
)
def test_fallible_branches_cannot_use_conforming_footprint_to_bypass_budget(dialects, wrapper):
    expensive = {
        "anyOf": [{"type": "string", "minLength": i} for i in range(40)],
        "type": "array",
        "minItems": 2000,
    }
    if wrapper == "contains-footprint":
        schema = {"type": "array", "contains": expensive}
    elif wrapper == "contains-branching":
        schema = {
            "type": "array",
            "contains": {"anyOf": [{"type": "string", "minLength": i} for i in range(20)]},
        }
    elif wrapper == "anyOf":
        schema = {"type": "array", "items": {"anyOf": [expensive, {"type": "integer"}]}}
    elif wrapper == "not":
        schema = {"type": "array", "items": {"not": expensive}}
    else:
        schema = {"type": "array", "items": {"if": expensive, "then": True, "else": True}}
    assert validation._evaluate(dialects, schema, None) == validation._SCHEMA


def test_simple_and_bounded_contains_remain_admitted(dialects):
    simple = {"type": "array", "contains": {"type": "string", "pattern": "^ticket-"}}
    bounded = {
        "type": "array",
        "maxItems": 10,
        "contains": {"anyOf": [{"type": "string", "minLength": i} for i in range(20)]},
    }
    assert validation._evaluate(dialects, simple, None) == validation._VALID
    assert validation._evaluate(dialects, bounded, None) == validation._VALID
