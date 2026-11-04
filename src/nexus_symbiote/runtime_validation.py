"""Bound offline JSON Schema work outside the authorization process.

Approved descriptors can still contain expensive regular expressions or schema
combinations. Only a short fixed result crosses this worker boundary; schemas
never select executable code, network retrieval or worker limits.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
import threading
from typing import Any

MAX_SCHEMA_BYTES = 256 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20_000
WORKER_TIMEOUT_SECONDS = 2.0
_WORKER_SLOTS = threading.BoundedSemaphore(4)
_VALID = b"valid\n"
# Optional checkers jsonschema imports whenever they are installed, for example
# through cyclonedx-python-lib's jsonschema[format-nongpl] requirement.
_UNUSED_FORMAT_MODULES = (
    "fqdn",
    "idna",
    "isoduration",
    "jsonpointer",
    "rfc3339_validator",
    "rfc3986_validator",
    "rfc3987",
    "rfc3987_syntax",
    "uri_template",
    "webcolors",
)


class ValidationBudgetError(ValueError):
    """Validation was invalid, incomplete, or outside the supported budget."""


def check_json_budget(value: Any, *, maximum: int) -> None:
    """Check size and complexity iteratively before recursive serialization.

    Count escaped JSON string sizes as well as values. A cyclic or repeatedly
    aliased container exhausts the same depth/node budget as expanded JSON.
    """
    pending = [(value, 0)]
    nodes = 0
    size = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > MAX_JSON_DEPTH or nodes > MAX_JSON_NODES:
            raise ValidationBudgetError("JSON complexity exceeds validation budget")
        if isinstance(item, dict):
            if len(item) > MAX_JSON_NODES:
                raise ValidationBudgetError("JSON complexity exceeds validation budget")
            size += 2 + 2 * len(item)
            for key, child in item.items():
                if not isinstance(key, str) or len(key) > maximum:
                    raise ValidationBudgetError("invalid or oversized JSON object key")
                size += len(json.dumps(key, ensure_ascii=True))
                pending.append((child, depth + 1))
        elif isinstance(item, (list, tuple)):
            if len(item) > MAX_JSON_NODES:
                raise ValidationBudgetError("JSON complexity exceeds validation budget")
            size += 2 + len(item)
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > maximum:
                raise ValidationBudgetError("JSON exceeds validation byte budget")
            size += len(json.dumps(item, ensure_ascii=True))
        elif item is None or isinstance(item, bool):
            size += 5
        elif isinstance(item, int):
            if not -(2**53 - 1) <= item <= 2**53 - 1:
                raise ValidationBudgetError("integer exceeds canonical JSON domain")
            size += 24
        elif isinstance(item, float) and math.isfinite(item):
            size += 24
        else:
            raise ValidationBudgetError("value is outside the JSON domain")
        if size > maximum or len(pending) + nodes > MAX_JSON_NODES:
            raise ValidationBudgetError("JSON exceeds validation budget")


def validate_arguments(schema: Any, arguments: dict[str, Any]) -> None:
    """Validate in a disposable, CPU/memory/wall-time-bounded Python process.

    Isolated Python ignores the working directory and PYTHONPATH. The worker
    uses the installed trusted package and an empty reference retrieval registry.
    Capacity exhaustion, unavailable POSIX limits, crashes, malformed replies and
    timeouts deny the operation. No approval nonce is consumed here.
    """
    if not isinstance(schema, dict):
        raise ValidationBudgetError("served tool requires an object input schema")
    check_json_budget(schema, maximum=MAX_SCHEMA_BYTES)
    check_json_budget(arguments, maximum=MAX_ARGUMENT_BYTES)
    wire = json.dumps(
        {"schema": schema, "arguments": arguments},
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    if len(wire) > MAX_SCHEMA_BYTES + MAX_ARGUMENT_BYTES + 64:
        raise ValidationBudgetError("validation request exceeds byte budget")
    if not _WORKER_SLOTS.acquire(blocking=False):
        raise ValidationBudgetError("validation worker capacity unavailable")
    try:
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-I", "-m", "nexus_symbiote.runtime_validation"],
            input=wire,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.defpath},
            timeout=WORKER_TIMEOUT_SECONDS,
            check=False,
        )
        if result.returncode != 0 or result.stdout != _VALID:
            raise ValidationBudgetError("offline input schema validation failed or exceeded budget")
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationBudgetError("offline input schema worker unavailable or timed out") from exc
    finally:
        _WORKER_SLOTS.release()


def _disable_unused_format_checkers() -> None:
    """Keep optional format checkers out of the worker before jsonschema loads.

    Meta-validation checks only "regex" and argument validation asserts no format,
    so these modules cannot change a result. Some do expensive import-time work
    (rfc3987-syntax compiles a grammar), which would spend the CPU budget meant for
    the untrusted input.
    """
    for name in _UNUSED_FORMAT_MODULES:
        sys.modules[name] = None  # type: ignore[assignment]


def _worker() -> int:
    """Internal fixed-protocol worker; failure details never echo input values."""
    try:
        if os.name != "posix":
            return 1
        import resource

        resource.setrlimit(resource.RLIMIT_CPU, (1, 1))
        resource.setrlimit(resource.RLIMIT_AS, (256 * 1024 * 1024, 256 * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        _disable_unused_format_checkers()
        from jsonschema import Draft202012Validator, FormatChecker
        from referencing import Registry

        maximum = MAX_SCHEMA_BYTES + MAX_ARGUMENT_BYTES + 64
        wire = sys.stdin.buffer.read(maximum + 1)
        if len(wire) > maximum:
            return 1
        request = json.loads(wire)
        if not isinstance(request, dict) or set(request) != {"schema", "arguments"}:
            return 1
        schema, arguments = request["schema"], request["arguments"]
        if not isinstance(schema, dict) or not isinstance(arguments, dict):
            return 1
        check_json_budget(schema, maximum=MAX_SCHEMA_BYTES)
        check_json_budget(arguments, maximum=MAX_ARGUMENT_BYTES)
        Draft202012Validator.check_schema(schema, format_checker=FormatChecker(formats=("regex",)))
        Draft202012Validator(schema, registry=Registry()).validate(arguments)
        sys.stdout.buffer.write(_VALID)
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(_worker())
