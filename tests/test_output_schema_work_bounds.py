"""Static preflight accounts for annotation work, value depth and ordinary unions."""

import threading
from concurrent.futures import ThreadPoolExecutor

from nexus_symbiote import runtime_validation as validation


def preflight(schema):
    return validation._evaluate(validation._load_dialects(), schema, None)


def test_annotation_pass_counts_its_applicator_children(monkeypatch):
    monkeypatch.setattr(validation, "_MAX_OUTPUT_APPLICATOR_STEPS", 2)
    schema = {"type": "object", "allOf": [{"type": "object"}]}
    assert preflight(schema) == validation._VALID
    schema["unevaluatedProperties"] = False
    assert preflight(schema) == validation._SCHEMA


def test_instance_descent_does_not_reset_the_call_stack(monkeypatch):
    monkeypatch.setattr(validation, "_MAX_OUTPUT_APPLICATOR_DEPTH", 3)
    leaf = {"allOf": [{"type": "string"}]}
    child = {"type": "object", "properties": {"name": leaf}}
    assert preflight(child) == validation._VALID
    assert preflight({"type": "object", "allOf": [child]}) == validation._SCHEMA


def test_composed_union_for_ordinary_tagged_responses():
    schema = {
        "type": "object",
        "$defs": {"base": {"type": "object"}},
        "oneOf": [
            {
                "allOf": [
                    {"$ref": "#/$defs/base"},
                    {"properties": {"kind": {"const": name}}, "required": ["kind"]},
                ]
            }
            for name in range(275)
        ],
    }
    dialects = validation._load_dialects()
    assert validation._evaluate(dialects, schema, None) == validation._VALID
    assert validation._evaluate(dialects, schema, {"kind": 24}) == validation._VALID


def test_static_linear_limits_match_the_published_contract():
    # These exercise only the bounded graph walk, with no result evaluation or tool.
    chain = {"type": "object"}
    for _ in range(95):
        chain = {"allOf": [chain]}
    assert not validation._in_place_evaluation_exceeds_budget(chain, None)
    assert validation._in_place_evaluation_exceeds_budget({"allOf": [chain]}, None)
    branches = [{"type": "object"} for _ in range(1023)]
    assert not validation._in_place_evaluation_exceeds_budget({"allOf": branches}, None)
    branches.append({"type": "object"})
    assert validation._in_place_evaluation_exceeds_budget({"allOf": branches}, None)


def test_releasing_a_worker_wakes_the_waiting_output(monkeypatch):
    condition = threading.Condition()
    entered = threading.Event()
    wait_for = condition.wait_for

    def wait_until_ready(predicate, timeout=None):
        entered.set()
        return wait_for(predicate, timeout)

    monkeypatch.setattr(condition, "wait_for", wait_until_ready)
    monkeypatch.setattr(validation, "_WORKER_AVAILABILITY", condition)
    monkeypatch.setattr(validation, "_WORKER_SLOTS", threading.BoundedSemaphore(1))
    monkeypatch.setattr(validation, "_OUTPUT_WAIT_SECONDS", 4)

    def output():
        with validation._validation_slot(wait_for_output=True):
            return True

    with ThreadPoolExecutor(1) as pool:
        with validation._validation_slot():
            future = pool.submit(output)
            assert entered.wait(2)
        assert future.result(timeout=2)
