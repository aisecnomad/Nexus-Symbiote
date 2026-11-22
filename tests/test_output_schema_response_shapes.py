"""Check offline admission of normal response shapes and scaled work limits."""

import pytest

from nexus_symbiote import runtime_validation as val
from tests.test_runtime_validation_in_process import dialects as dialects


def _admitted(dialects, schema):
    return val._evaluate(dialects, schema, None) == val._VALID


@pytest.mark.parametrize("form", ["optional", "wrapped", "json-value"])
def test_small_recursive_response_types_can_be_admitted(dialects, form):
    ref = {"$ref": "#/$defs/entry"}
    entry = {"type": "object", "properties": {"next": {"anyOf": [ref, {"type": "null"}]}}}
    if form == "wrapped":
        entry = {"allOf": [entry]}
    elif form == "json-value":
        entry = {
            "anyOf": [
                {"type": "string"},
                {"type": "null"},
                {"type": "array", "items": ref},
                {"type": "object", "additionalProperties": ref},
            ]
        }
    schema = {"$defs": {"entry": entry}, "type": "object", "properties": {"data": ref}}
    assert _admitted(dialects, schema)
    assert val._evaluate(dialects, schema, {"data": {"next": None}}) == val._VALID


def _union(n):
    return {
        "oneOf": [
            {"type": "object", "required": ["kind"], "properties": {"kind": {"const": i}}}
            for i in range(n)
        ]
    }


@pytest.mark.parametrize("container", ["plain", "closed", "optional", "composed"])
def test_cheap_wrappers_preserve_the_bounded_union_allowance(monkeypatch, dialects, container):
    monkeypatch.setattr(val, "_MAX_OUTPUT_APPLICATOR_STEPS", 16)
    monkeypatch.setattr(val, "_MAX_OUTPUT_UNION_STEPS", 128)
    union = _union(17)
    node = {
        "plain": union,
        "closed": {**union, "unevaluatedProperties": False},
        "optional": {"anyOf": [union, {"type": "null"}]},
        "composed": {"allOf": [{"type": "object"}, union]},
    }[container]
    assert _admitted(dialects, {"type": "object", "properties": {"data": node}})


@pytest.mark.parametrize("field", ["properties", "required", "enum", "patternProperties"])
def test_shared_wide_rules_cost_more_than_a_single_lookup(monkeypatch, dialects, field):
    monkeypatch.setattr(val, "_MAX_OUTPUT_APPLICATOR_STEPS", 64)
    monkeypatch.setattr(val, "_MAX_OUTPUT_UNION_STEPS", 128)
    names = [f"field{i}" for i in range(12)]
    value = dict.fromkeys(names, True) if field in ("properties", "patternProperties") else names
    schema = {
        "type": "object",
        "$defs": {"base": {field: value}},
        "oneOf": [{"$ref": "#/$defs/base"} for _ in range(17)],
    }
    assert not _admitted(dialects, schema)


def test_collection_bound_controls_work_of_a_repeated_union(monkeypatch, dialects):
    monkeypatch.setattr(val, "MAX_JSON_NODES", 1600)
    children = {"type": "array", "items": _union(48)}
    assert not _admitted(dialects, {"type": "object", "properties": {"rows": children}})
    children["maxItems"] = 4
    assert _admitted(dialects, {"type": "object", "properties": {"rows": children}})


def test_annotation_walk_charges_inner_applicators_at_each_level(monkeypatch):
    monkeypatch.setattr(val, "_MAX_OUTPUT_APPLICATOR_STEPS", 48)
    inner = {"type": "object"}
    for _ in range(2):
        for _ in range(5):
            inner = {"allOf": [inner]}
        inner = {"allOf": [inner], "unevaluatedProperties": False}
    assert val._in_place_evaluation_exceeds_budget(inner, None)


def test_static_union_has_an_absolute_ceiling():
    # Only examine the schema graph, without supplying any result for validation.
    arms = [{"type": "string"} for _ in range(4095)]
    assert not val._in_place_evaluation_exceeds_budget({"anyOf": arms}, None)
    arms.append({"type": "null"})
    assert val._in_place_evaluation_exceeds_budget({"anyOf": arms}, None)


def test_union_with_a_costly_arm_uses_the_ordinary_ceiling(monkeypatch):
    monkeypatch.setattr(val, "_MAX_OUTPUT_APPLICATOR_STEPS", 80)
    variants = [{"type": "string"} for _ in range(48)]
    variants.append({"enum": list(range(32))})
    assert not val._in_place_evaluation_exceeds_budget({"oneOf": variants}, None)
    variants[-1]["enum"].append(32)
    assert val._in_place_evaluation_exceeds_budget({"oneOf": variants}, None)
