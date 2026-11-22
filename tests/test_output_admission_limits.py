"""Output validation must admit a supported description before accepting an action."""

import json
import sqlite3
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import closing

import pytest

from nexus_symbiote import runtime_validation as validation
from nexus_symbiote.live.session import invoke_pinned_stdio
from nexus_symbiote.runtime import AuthorizationError
from tests import test_runtime_validation_in_process as in_process_tests
from tests.test_runtime_authorization import fixture
from tests.test_runtime_stdio_session import launcher, launcher_log, signed_inputs

dialects = in_process_tests.dialects
pytestmark = pytest.mark.usefixtures("nonisolated_pinned_fixtures")


@pytest.mark.parametrize("bound", ["depth", "steps", "cycle"])
def test_output_description_must_pass_preflight_before_dispatch_or_nonce(
    tmp_path, monkeypatch, bound, dialects
):
    schema = {"type": "object", "allOf": [{"type": "object"}, {"type": "object"}]}
    if bound == "cycle":
        # Check only the preflight refusal of this same-value reference.
        schema = {"type": "object", "$ref": "#"}
    else:
        # Tiny limits exercise the same decision with ordinary, inexpensive schemas.
        monkeypatch.setattr(
            validation,
            "_MAX_OUTPUT_APPLICATOR_DEPTH" if bound == "depth" else "_MAX_OUTPUT_APPLICATOR_STEPS",
            1 if bound == "depth" else 2,
        )

        def evaluate(wire):
            request = json.loads(wire)
            return validation._evaluate(dialects, request["schema"], request["arguments"])

        monkeypatch.setattr(validation, "_run_worker", evaluate)
    values = fixture(tmp_path)
    path, pin, log = launcher(tmp_path, output_schema=schema, tool_result={"structuredContent": {}})
    signed = signed_inputs(values, pin, output_schema=schema)
    with pytest.raises(AuthorizationError) as denied:
        invoke_pinned_stdio(values[0], values[1], command=str(path), sha256=pin, **signed)
    assert denied.value.reason == "schema-invalid"
    assert [event[0] for event in launcher_log(log)] == ["tools/list"]
    with closing(sqlite3.connect(tmp_path / "state.sqlite")) as db:
        assert db.execute("SELECT COUNT(*) FROM tenant_nonces").fetchone() == (0,)


def test_shared_schema_work_is_counted_once_per_application(monkeypatch, dialects):
    schema = {
        "type": "object",
        "$defs": {"shape": {"type": "object"}},
        "allOf": [{"$ref": "#/$defs/shape"}, {"$ref": "#/$defs/shape"}],
    }
    monkeypatch.setattr(validation, "_MAX_OUTPUT_APPLICATOR_STEPS", 5)
    assert validation._evaluate(dialects, schema, None) == validation._VALID
    monkeypatch.setattr(validation, "_MAX_OUTPUT_APPLICATOR_STEPS", 4)
    assert validation._evaluate(dialects, schema, None) == validation._SCHEMA
    assert validation._evaluate(dialects, schema, {}) == validation._VALID


def test_a_waiting_output_gets_the_next_worker(monkeypatch):
    slots = threading.BoundedSemaphore(1)
    assert slots.acquire(blocking=False)
    monkeypatch.setattr(validation, "_WORKER_SLOTS", slots)
    condition = validation._WORKER_AVAILABILITY
    wait_for = condition.wait_for
    waiting = threading.Event()

    def queued(predicate, timeout=None):
        waiting.set()
        return wait_for(predicate, timeout)

    monkeypatch.setattr(condition, "wait_for", queued)

    def output():
        with validation._validation_slot(wait_for_output=True):
            return True

    with ThreadPoolExecutor(1) as executor:
        future = executor.submit(output)
        assert waiting.wait(timeout=5)
        with condition:
            slots.release()
            # The output waiter cannot reacquire the condition yet. A fresh input
            # observes a free semaphore and still yields priority to that waiter.
            with (
                pytest.raises(validation.ValidationBudgetError) as denied,
                validation._validation_slot(),
            ):
                pytest.fail("an input displaced a waiting output")
            assert denied.value.reason == "validation-capacity"
            condition.notify_all()
        assert future.result(timeout=5)
    with validation._validation_slot():
        assert not slots.acquire(blocking=False)
