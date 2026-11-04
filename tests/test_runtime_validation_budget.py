"""Availability regressions for approved schemas and caller-controlled arguments."""

from __future__ import annotations

import os
import subprocess
import sys

import pytest

import nexus_symbiote.runtime as runtime
import nexus_symbiote.runtime_validation as validation
from tests.test_runtime_authorization import fixture, invoke


def test_valid_schema_and_arguments_execute_through_gateway(tmp_path):
    values = fixture(tmp_path)
    assert invoke(values) == "executed"
    assert len(values[-1]) == 1


def test_worker_ignores_project_module_and_pythonpath(tmp_path, monkeypatch):
    marker = tmp_path / "executed"
    (tmp_path / "nexus_symbiote.py").write_text(
        f"from pathlib import Path\nPath({str(marker)!r}).touch()\n"
    )
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PYTHONPATH", str(tmp_path))
    validation.validate_arguments({"type": "object"}, {})
    assert not marker.exists()


def test_pathological_approved_regex_is_terminated_outside_gateway_process():
    # The outer deadline also protects the test runner if worker isolation is
    # accidentally removed and the gateway returns to inline regex validation.
    source = """
from nexus_symbiote.runtime import AuthorizationError, _validate_arguments
schema = {"type": "object", "properties": {
    "payload": {"type": "string", "pattern": "^(a+)+$"}
}}
try:
    _validate_arguments(schema, {"payload": "a" * 30 + "!"})
except AuthorizationError:
    print("denied")
else:
    raise SystemExit("unsafe schema input accepted")
"""
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", source],
        capture_output=True,
        env={"PATH": os.defpath},
        timeout=5,
        check=False,
    )
    assert result.returncode == 0, result.stderr.decode(errors="replace")
    assert result.stdout == b"denied\n"


def test_missing_approval_is_denied_before_schema_evaluation(tmp_path, monkeypatch):
    def unexpected(*_):
        pytest.fail("schema evaluation must not run without required approval")

    monkeypatch.setattr(runtime, "_validate_arguments", unexpected)
    values = fixture(tmp_path)
    with pytest.raises(runtime.AuthorizationError, match="operation-bound approval required"):
        invoke(values, approval=None)
    assert values[-1] == []


def test_revoked_tool_is_denied_before_schema_evaluation(tmp_path, monkeypatch):
    def unexpected(*_):
        pytest.fail("schema evaluation must not run for a revoked tool")

    monkeypatch.setattr(runtime, "_validate_arguments", unexpected)
    values = list(fixture(tmp_path))
    values[4] = values[4].model_copy(
        update={"revoked_tools": (values[3].tools[0].definition_digest,)}
    )
    with pytest.raises(runtime.AuthorizationError, match="revoked"):
        invoke(values)
    assert values[-1] == []


def test_validation_failure_preserves_approval_for_retry(tmp_path, monkeypatch):
    values = fixture(tmp_path)

    def unavailable(*_):
        raise validation.ValidationBudgetError("worker unavailable")

    with monkeypatch.context() as patch:
        patch.setattr(runtime, "validate_arguments", unavailable)
        with pytest.raises(runtime.AuthorizationError, match="offline input schema"):
            invoke(values)
    assert values[-1] == []
    assert invoke(values) == "executed"


@pytest.mark.parametrize("kind", ["arguments", "schema", "depth", "nodes", "cycle"])
def test_oversized_or_overcomplex_json_is_denied_before_worker_start(kind, monkeypatch):
    def unexpected(*_, **__):
        pytest.fail("budget violation must not start a worker")

    monkeypatch.setattr(validation.subprocess, "run", unexpected)
    schema = {"type": "object"}
    arguments = {}
    if kind == "arguments":
        arguments["payload"] = "a" * validation.MAX_ARGUMENT_BYTES
    elif kind == "schema":
        schema["description"] = "a" * validation.MAX_SCHEMA_BYTES
    elif kind == "depth":
        nested = {}
        arguments["payload"] = nested
        for _ in range(validation.MAX_JSON_DEPTH + 1):
            child = {}
            nested["child"] = child
            nested = child
    elif kind == "nodes":
        arguments["payload"] = [0] * validation.MAX_JSON_NODES
    else:
        arguments["payload"] = arguments
    with pytest.raises(validation.ValidationBudgetError):
        validation.validate_arguments(schema, arguments)


@pytest.mark.parametrize(
    ("returncode", "stdout"), [(-9, b""), (1, b"valid\n"), (0, b""), (0, b"valid\nextra")]
)
def test_worker_crash_or_invalid_protocol_fails_closed(returncode, stdout, monkeypatch):
    monkeypatch.setattr(
        validation.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess([], returncode, stdout=stdout),
    )
    with pytest.raises(validation.ValidationBudgetError):
        validation.validate_arguments({"type": "object"}, {})


def test_worker_timeout_fails_closed_and_releases_capacity(monkeypatch):
    def timed_out(*_, **__):
        raise subprocess.TimeoutExpired("worker", validation.WORKER_TIMEOUT_SECONDS)

    with monkeypatch.context() as patch:
        patch.setattr(validation.subprocess, "run", timed_out)
        with pytest.raises(validation.ValidationBudgetError, match="timed out"):
            validation.validate_arguments({"type": "object"}, {})
    validation.validate_arguments({"type": "object"}, {})


def test_concurrent_worker_capacity_exhaustion_denies_without_waiting():
    acquired = 0
    try:
        while validation._WORKER_SLOTS.acquire(blocking=False):
            acquired += 1
        with pytest.raises(validation.ValidationBudgetError, match="capacity unavailable"):
            validation.validate_arguments({"type": "object"}, {})
    finally:
        for _ in range(acquired):
            validation._WORKER_SLOTS.release()


def test_worker_blocks_every_optional_format_checker_jsonschema_imports():
    # A new optional checker in jsonschema must be reviewed here: an expensive one
    # spends the CPU budget meant for the untrusted schema and arguments.
    import ast
    import importlib.util

    spec = importlib.util.find_spec("jsonschema._format")
    assert spec is not None and spec.origin is not None
    with open(spec.origin, encoding="utf-8") as stream:
        tree = ast.parse(stream.read())
    optional = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.Try, ast.With)):
            for child in ast.walk(node):
                if isinstance(child, ast.Import):
                    optional.update(alias.name.split(".")[0] for alias in child.names)
                elif isinstance(child, ast.ImportFrom) and child.module and not child.level:
                    optional.add(child.module.split(".")[0])
    optional -= {"jsonschema"}
    assert optional
    assert optional <= set(validation._UNUSED_FORMAT_MODULES)


def test_worker_import_skips_format_checkers_and_fits_the_cpu_budget():
    probe = (
        "import resource, sys\n"
        "from nexus_symbiote.runtime_validation import _UNUSED_FORMAT_MODULES, "
        "_disable_unused_format_checkers\n"
        "_disable_unused_format_checkers()\n"
        "from jsonschema import Draft202012Validator\n"
        "Draft202012Validator({'type': 'object'}).validate({})\n"
        "loaded = [n for n in _UNUSED_FORMAT_MODULES if sys.modules.get(n) is not None]\n"
        "usage = resource.getrusage(resource.RUSAGE_SELF)\n"
        "print(loaded, usage.ru_utime + usage.ru_stime)\n"
    )
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", probe],
        capture_output=True,
        text=True,
        env={"PATH": os.defpath},
        timeout=60,
        check=True,
    )
    loaded, cpu = result.stdout.rsplit(" ", 1)
    assert loaded == "[]"
    # The worker's RLIMIT_CPU is 1 second; startup and imports must leave most of it.
    assert float(cpu) < 0.5


def _cyclic() -> list[object]:
    value: list[object] = []
    value.append(value)
    return value


@pytest.mark.parametrize(
    ("value", "reason"),
    [
        (float("nan"), "outside the JSON domain"),
        (float("inf"), "outside the JSON domain"),
        (2**53, "integer exceeds canonical JSON domain"),
        (-(2**53), "integer exceeds canonical JSON domain"),
        (b"bytes", "outside the JSON domain"),
        ({"set": {1}}, "outside the JSON domain"),
        ({1: "non-string key"}, "invalid or oversized JSON object key"),
        ({"k" * 65: "oversized key"}, "invalid or oversized JSON object key"),
        ("x" * 65, "budget"),
        ([0] * (validation.MAX_JSON_NODES + 1), "budget"),
        (dict.fromkeys(map(str, range(validation.MAX_JSON_NODES + 1)), 0), "budget"),
    ],
    ids=[
        "nan",
        "infinity",
        "integer-above-safe-range",
        "integer-below-safe-range",
        "bytes",
        "set",
        "non-string-key",
        "oversized-key",
        "oversized-string",
        "oversized-array",
        "oversized-object",
    ],
)
def test_budget_rejects_values_outside_the_canonical_json_domain(value, reason):
    # Agent-supplied tool-call arguments reach this check before any worker starts;
    # each rejection is a separate guard and needs its own regression.
    with pytest.raises(validation.ValidationBudgetError, match=reason):
        validation.check_json_budget(value, maximum=64)


def test_cyclic_arguments_exhaust_the_depth_budget_instead_of_recursing():
    with pytest.raises(validation.ValidationBudgetError, match="complexity"):
        validation.check_json_budget(_cyclic(), maximum=validation.MAX_ARGUMENT_BYTES)


def test_budget_accepts_the_edges_of_the_canonical_json_domain():
    for value in (2**53 - 1, -(2**53 - 1), 0.5, True, None, "x" * 62):
        validation.check_json_budget(value, maximum=64)
    validation.check_json_budget({"k" * 64: 0}, maximum=128)
