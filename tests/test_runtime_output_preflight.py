"""Output preparation checks the schema graph and leaves input workers available."""

import json
from contextlib import ExitStack

import pytest

from nexus_symbiote import runtime_validation as validation
from nexus_symbiote.live.session import ExecutionOutcomeUnknown, PinnedStdioSession
from tests.test_runtime_authorization import fixture
from tests.test_runtime_stdio_session import launcher

pytestmark = pytest.mark.usefixtures("nonisolated_pinned_fixtures")


def test_a_cycle_in_same_value_evaluation_is_denied(monkeypatch):
    root, branch = {}, {}
    monkeypatch.setattr(
        validation, "_applied_in_place", lambda node, _: [branch] if node is root else [root]
    )
    assert validation._in_place_evaluation_exceeds_budget(root, None)


def test_recursion_can_follow_child_values():
    tree = {
        "type": "object",
        "properties": {"children": {"type": "array", "items": {"$ref": "#"}}},
    }
    with validation.prepare_output_validation(tree) as validate:
        validate({"children": [{"children": []}]})


def test_pending_outputs_do_not_occupy_input_validation_workers():
    schema = {"type": "object"}
    with ExitStack() as pending:
        for _ in range(validation.OUTPUT_RESERVATIONS):
            pending.enter_context(validation.prepare_output_validation(schema))
        validation.check_worker()
        with pytest.raises(validation.ValidationBudgetError) as exhausted:
            pending.enter_context(validation.prepare_output_validation(schema))
        assert exhausted.value.reason == "validation-capacity"
    with validation.prepare_output_validation(schema) as validate:
        validate({"count": 1})


@pytest.mark.parametrize("reason", ["validation-timeout", "validation-failed"])
def test_unavailable_result_validation_reports_an_unknown_execution(tmp_path, monkeypatch, reason):
    run_worker = validation._run_worker

    def check_request(wire: bytes) -> bytes:
        if json.loads(wire)["arguments"] is None:
            return run_worker(wire)
        if reason == "validation-timeout":
            raise validation.ValidationBudgetError("validation timed out", reason=reason)
        return b""

    monkeypatch.setattr(validation, "_run_worker", check_request)
    call = fixture(tmp_path)[1]
    path, pin, _ = launcher(
        tmp_path, output_schema={"type": "object"}, tool_result={"structuredContent": {"count": 1}}
    )
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        session.describe("server:mail", "send")
        with pytest.raises(ExecutionOutcomeUnknown) as failure:
            session.execute(call)
    cause = failure.value.__cause__
    assert isinstance(cause, validation.ValidationBudgetError)
    assert cause.reason == reason


def test_result_without_output_schema_keeps_existing_error_flag_handling(tmp_path):
    call = fixture(tmp_path)[1]
    result = {"isError": None, "content": []}
    path, pin, _ = launcher(tmp_path, tool_result=result)
    with PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail") as session:
        session.describe("server:mail", "send")
        assert session.execute(call) == result
