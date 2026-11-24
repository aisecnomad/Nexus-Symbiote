"""Bound offline JSON Schema work outside the authorization process.

Approved descriptors can still contain expensive regular expressions or schema
combinations. Only a short fixed result crosses this worker boundary; schemas
never select executable code, network retrieval or worker limits.
"""

from __future__ import annotations

import json
import math
import os
import re
import selectors
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

MAX_SCHEMA_BYTES = 256 * 1024
MAX_ARGUMENT_BYTES = 1024 * 1024
MAX_JSON_DEPTH = 32
MAX_JSON_NODES = 20_000
# Each same-value applicator consumes several interpreter frames. Limit the
# longest path and total expansion before dispatching an output-validated call.
_MAX_OUTPUT_IN_PLACE_DEPTH = 96
_MAX_OUTPUT_APPLICATOR_DEPTH = 160
_MAX_OUTPUT_APPLICATOR_STEPS = 1024
_MAX_OUTPUT_UNION_STEPS = 4096
_MAX_OUTPUT_REPEATED_STEPS = 32768
_MIN_SHARED_MULTIPLICITY = 32
MAX_SAFE_INTEGER = 2**53 - 1
# Interpreter start-up and imports get their own budget, so a slow or throttled
# host does not spend the evaluation budget before the untrusted input arrives.
WORKER_STARTUP_SECONDS = 10.0
WORKER_STARTUP_CPU_SECONDS = 10
WORKER_TIMEOUT_SECONDS = 2.0
WORKER_CPU_SECONDS = 1
WORKER_MEMORY_BYTES = 256 * 1024 * 1024
WORKER_SLOTS = 4
_WORKER_SLOTS = threading.BoundedSemaphore(WORKER_SLOTS)
_WORKER_AVAILABILITY = threading.Condition()
_WAITING_OUTPUTS = 0
OUTPUT_RESERVATIONS = 4
_OUTPUT_RESERVATIONS = threading.BoundedSemaphore(OUTPUT_RESERVATIONS)
_OUTPUT_WAIT_SECONDS = WORKER_STARTUP_SECONDS + WORKER_TIMEOUT_SECONDS
_WORKER_COMMAND = (sys.executable, "-I", "-m", "nexus_symbiote.runtime_validation")
_READY = b"ready\n"
_VALID = b"valid\n"
_INVALID = b"invalid\n"
_SCHEMA = b"schema\n"
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
# A schema without "$schema" is read as 2020-12, the MCP default. Draft 3 and
# unknown dialects are refused rather than read under another dialect's keywords.
DIALECTS = (
    "http://json-schema.org/draft-04/schema",
    "http://json-schema.org/draft-06/schema",
    "http://json-schema.org/draft-07/schema",
    "https://json-schema.org/draft/2019-09/schema",
    "https://json-schema.org/draft/2020-12/schema",
)


class ValidationBudgetError(ValueError):
    """Validation was invalid, incomplete, or outside the supported budget.

    ``reason`` is a stable code from ``nexus_symbiote.runtime.REASONS``.
    """

    def __init__(self, message: str, *, reason: str = "validation-failed") -> None:
        super().__init__(message)
        self.reason = reason


def check_json_budget(
    value: Any,
    *,
    maximum: int,
    max_depth: int = MAX_JSON_DEPTH,
    max_nodes: int = MAX_JSON_NODES,
    strict_integral_floats: bool = False,
) -> None:
    """Check size and complexity iteratively before recursive serialization.

    Count escaped JSON string sizes as well as values. A cyclic or repeatedly
    aliased container exhausts the same depth/node budget as expanded JSON.
    Integers must lie in the I-JSON range of +/-(2**53 - 1); floats must be finite,
    and when ``strict_integral_floats`` is set, integral floats must also lie in I-JSON.
    """
    pending = [(value, 0)]
    nodes = 0
    size = 0
    while pending:
        item, depth = pending.pop()
        nodes += 1
        if depth > max_depth or nodes > max_nodes:
            raise ValidationBudgetError(
                "JSON complexity exceeds validation budget", reason="json-budget-exceeded"
            )
        if isinstance(item, dict):
            if len(item) > max_nodes:
                raise ValidationBudgetError(
                    "JSON complexity exceeds validation budget", reason="json-budget-exceeded"
                )
            size += 2 + 2 * len(item)
            for key, child in item.items():
                if not isinstance(key, str):
                    raise ValidationBudgetError("invalid JSON object key", reason="json-invalid")
                if len(key) > maximum:
                    raise ValidationBudgetError(
                        "oversized JSON object key", reason="json-budget-exceeded"
                    )
                size += len(json.dumps(key, ensure_ascii=True))
                pending.append((child, depth + 1))
        elif isinstance(item, (list, tuple)):
            if len(item) > max_nodes:
                raise ValidationBudgetError(
                    "JSON complexity exceeds validation budget", reason="json-budget-exceeded"
                )
            size += 2 + len(item)
            pending.extend((child, depth + 1) for child in item)
        elif isinstance(item, str):
            if len(item) > maximum:
                raise ValidationBudgetError(
                    "JSON exceeds validation byte budget", reason="json-budget-exceeded"
                )
            size += len(json.dumps(item, ensure_ascii=True))
        elif item is None or isinstance(item, bool):
            size += 5
        elif isinstance(item, int):
            if not -MAX_SAFE_INTEGER <= item <= MAX_SAFE_INTEGER:
                raise ValidationBudgetError(
                    "integer outside the I-JSON range", reason="json-number-out-of-range"
                )
            size += 24
        elif isinstance(item, float) and math.isfinite(item):
            if (
                strict_integral_floats
                and item.is_integer()
                and not -MAX_SAFE_INTEGER <= item <= MAX_SAFE_INTEGER
            ):
                raise ValidationBudgetError(
                    "integral float outside the I-JSON range", reason="json-number-out-of-range"
                )
            size += 24
        else:
            raise ValidationBudgetError("value is outside the JSON domain", reason="json-invalid")
        if size > maximum or len(pending) + nodes > max_nodes:
            raise ValidationBudgetError(
                "JSON exceeds validation budget", reason="json-budget-exceeded"
            )


def validate_arguments(schema: Any, arguments: dict[str, Any]) -> None:
    """Validate in a disposable, CPU/memory/wall-time-bounded Python process.

    Isolated Python ignores the working directory and PYTHONPATH. The worker
    uses the installed trusted package and an empty reference retrieval registry.
    Start-up has its own deadline; the evaluation budget starts when the worker
    reports that it is ready. Capacity exhaustion, unavailable POSIX limits,
    crashes, malformed replies and timeouts deny the operation with a stable
    reason code; crashes and malformed replies share one. No approval nonce is
    consumed here.
    """
    if not isinstance(arguments, dict):
        raise ValidationBudgetError("tool arguments must be an object")
    wire = _validation_request(schema, arguments)
    with _validation_slot():
        _validate(wire)


@contextmanager
def prepare_output_validation(schema: Any) -> Iterator[Callable[[dict[str, Any]], None]]:
    """Check schema support and reserve one pending response without holding a worker."""
    preflight = _validation_request(schema, None)

    def validate(result: dict[str, Any]) -> None:
        wire = _validation_request(schema, result)
        with _validation_slot(wait_for_output=True):
            _validate(wire)

    if not _OUTPUT_RESERVATIONS.acquire(blocking=False):
        raise ValidationBudgetError(
            "pending output validation capacity unavailable", reason="validation-capacity"
        )
    try:
        with _validation_slot():
            _validate(preflight)
        yield validate
    finally:
        _OUTPUT_RESERVATIONS.release()


def _validation_request(schema: Any, instance: dict[str, Any] | None) -> bytes:
    if not isinstance(schema, dict):
        raise ValidationBudgetError("served tool schema must be an object", reason="schema-invalid")
    check_json_budget(schema, maximum=MAX_SCHEMA_BYTES)
    if instance is not None:
        check_json_budget(instance, maximum=MAX_ARGUMENT_BYTES)
    wire = json.dumps(
        {"schema": schema, "arguments": instance},
        ensure_ascii=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("ascii")
    if len(wire) > MAX_SCHEMA_BYTES + MAX_ARGUMENT_BYTES + 64:
        raise ValidationBudgetError(
            "validation request exceeds byte budget", reason="json-budget-exceeded"
        )
    return wire


@contextmanager
def _validation_slot(*, wait_for_output: bool = False) -> Iterator[None]:
    global _WAITING_OUTPUTS
    with _WORKER_AVAILABILITY:
        if wait_for_output:
            _WAITING_OUTPUTS += 1
            try:
                acquired = _WORKER_AVAILABILITY.wait_for(
                    lambda: _WORKER_SLOTS.acquire(blocking=False), timeout=_OUTPUT_WAIT_SECONDS
                )
            finally:
                _WAITING_OUTPUTS -= 1
        else:
            # Once the tool has run, an arriving input must not displace a
            # waiting response from a worker released in the meantime.
            acquired = not _WAITING_OUTPUTS and _WORKER_SLOTS.acquire(blocking=False)
    if not acquired:
        raise ValidationBudgetError(
            "validation worker capacity unavailable", reason="validation-capacity"
        )
    try:
        yield
    finally:
        with _WORKER_AVAILABILITY:
            _WORKER_SLOTS.release()
            _WORKER_AVAILABILITY.notify_all()


def _validate(wire: bytes) -> None:
    result = _run_worker(wire)
    if result == _VALID:
        return
    if result == _INVALID:
        raise ValidationBudgetError(
            "tool arguments do not satisfy the offline input schema", reason="arguments-invalid"
        )
    if result == _SCHEMA:
        raise ValidationBudgetError(
            "offline input schema is invalid, unsupported or not resolvable offline",
            reason="schema-invalid",
        )
    raise ValidationBudgetError(
        "offline input schema validation failed or exceeded budget", reason="validation-failed"
    )


def check_worker() -> None:
    """Validate a trivial schema once; call at start-up or from a readiness probe."""
    validate_arguments({"type": "object"}, {})


def _run_worker(wire: bytes) -> bytes:
    try:
        process = subprocess.Popen(  # noqa: S603
            list(_WORKER_COMMAND),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env={"PATH": os.defpath},
            close_fds=True,
            start_new_session=True,
        )
    except OSError as exc:
        raise ValidationBudgetError(
            "offline input schema worker could not start", reason="validation-unavailable"
        ) from exc
    try:
        try:
            ready = process.stdout is not None and _read_ready(process.stdout.fileno()) == _READY
        except OSError:
            ready = False
        if not ready:
            raise ValidationBudgetError(
                "offline input schema worker did not start within its budget",
                reason="validation-unavailable",
            )
        try:
            stdout, _ = process.communicate(wire, timeout=WORKER_TIMEOUT_SECONDS)
        except subprocess.TimeoutExpired as exc:
            raise ValidationBudgetError(
                "offline input schema worker timed out", reason="validation-timeout"
            ) from exc
        except OSError as exc:
            raise ValidationBudgetError(
                "offline input schema worker stopped before reading the request",
                reason="validation-failed",
            ) from exc
        return stdout if process.returncode == 0 else b""
    finally:
        if process.returncode is None:
            process.kill()
            try:
                process.communicate()
            except (OSError, ValueError):
                process.wait()


def _read_ready(fd: int) -> bytes:
    deadline = time.monotonic() + WORKER_STARTUP_SECONDS
    data = b""
    with selectors.DefaultSelector() as selector:
        selector.register(fd, selectors.EVENT_READ)
        while len(data) < len(_READY):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                break
            chunk = os.read(fd, len(_READY) - len(data))
            if not chunk:
                break
            data += chunk
    return data


def _disable_unused_format_checkers() -> None:
    """Keep optional format checkers out of the worker before jsonschema loads.

    The worker never asserts "format" (no FormatChecker), so these modules cannot
    change a result. Some do expensive import-time work (rfc3987-syntax compiles a
    grammar), which would spend the CPU budget meant for the untrusted input.
    """
    for name in _UNUSED_FORMAT_MODULES:
        sys.modules[name] = None  # type: ignore[assignment]


def _apply_worker_limits() -> None:
    """Apply the start-up limits; ``_worker`` lowers RLIMIT_CPU once imports are done."""
    import resource

    resource.setrlimit(
        resource.RLIMIT_CPU,
        (WORKER_STARTUP_CPU_SECONDS, WORKER_STARTUP_CPU_SECONDS),
    )
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    try:
        resource.setrlimit(resource.RLIMIT_AS, (WORKER_MEMORY_BYTES, WORKER_MEMORY_BYTES))
    except (ValueError, OSError):
        # macOS kernels reject RLIMIT_AS lowering; fail closed on Linux/other POSIX.
        if sys.platform != "darwin":
            raise


# ECMA-262 WhiteSpace and LineTerminator code points, which "\s" matches there.
_ECMA_SPACE = r"\t\n\x0b\x0c\r \xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_CLASS_ESCAPES = {"d": "0-9", "w": "A-Za-z0-9_", "s": _ECMA_SPACE}
_ESCAPES = {
    "d": "[0-9]",
    "D": "[^0-9]",
    "w": "[A-Za-z0-9_]",
    "W": "[^A-Za-z0-9_]",
    "s": f"[{_ECMA_SPACE}]",
    "S": f"[^{_ECMA_SPACE}]",
}
_ANY = r"[^\n\r\u2028\u2029]"
_GROUPS = ("(?:", "(?=", "(?!", "(?<=", "(?<!")
_LOOKAROUNDS = frozenset(_GROUPS[1:])
_LOOKBEHINDS = frozenset(_GROUPS[3:])
_COMPLEMENTS = {"D": "0-9", "W": "A-Za-z0-9_", "S": _ECMA_SPACE}
_QUANTIFIER = re.compile(r"\{[0-9]+(?:,[0-9]*)?\}")
# Python reads "{,n}" and "{,}" as quantifiers; ECMA-262 reads the braces literally
# or, with the u flag, rejects them.
_PYTHON_QUANTIFIER = re.compile(r"\{,[0-9]*\}")
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")
# The characters that ECMA-262 lets an escape quote with the u flag.
_IDENTITY_ESCAPES = frozenset("^$\\.*+?()[]{}|/")
_ESCAPE_TOKEN = re.compile(r"\\(?:u([0-9a-fA-F]{4})|.)", re.S)


def ecma_pattern(pattern: str) -> str:
    """Translate an ECMA-262 pattern into a Python pattern with the same meaning.

    JSON Schema patterns are ECMA-262 expressions, read here as with the ``u`` flag
    that JSON Schema recommends. Python's ``$`` also matches before a final newline,
    and its ``\\d``, ``\\w`` and ``.`` differ for non-ASCII input, so a value the
    author excluded could pass. Syntax that ECMA-262 rejects or reads differently
    and that has no translation, such as inline flags, possessive quantifiers, a
    class escape as a range bound or a backreference to a group that may not take
    part, raises ``re.error`` and makes the schema invalid. A pattern that is valid
    only without the ``u`` flag (Annex B) is read with the ``u`` flag's code-point
    semantics, so ``.`` and negated classes match one character outside the BMP
    where Annex B would count two UTF-16 code units.
    """
    # Without the u flag, ECMA-262 Annex B accepts more syntax and counts UTF-16 code
    # units, which Python cannot. A pattern that names a character outside the BMP
    # or a surrogate must therefore be valid with the u flag.
    strict = _names_astral(pattern)
    out: list[str] = []
    captures = _Captures()
    # The last token: "atom", "assertion", "quantifier", "lazy", or "" at the start
    # of the pattern, a group or an alternative. Only an atom can be repeated.
    previous = ""
    index = 0
    while index < len(pattern):
        char = pattern[index]
        # A quantifier repeats the captures of a group that has just closed.
        repeated, captures.repeated = captures.repeated, None
        quantifier = _QUANTIFIER.match(pattern, index) if char == "{" else None
        if char in "*+?" or quantifier is not None:
            if char == "?" and previous == "quantifier":
                out.append("?")
                index += 1
                previous = "lazy"
                continue
            if previous != "atom":
                raise re.error("quantifier does not follow a repeatable atom")
            if repeated is not None:
                captures.conditional.append(repeated)
            text = char if quantifier is None else quantifier.group()
            out.append(text)
            index += len(text)
            previous = "quantifier"
            continue
        if char == "{" and _PYTHON_QUANTIFIER.match(pattern, index):
            raise re.error("quantifier without a minimum has no ECMA-262 meaning")
        if char == "[":
            text, index = _character_class(pattern, index, strict)
            out.append(text)
            previous = "atom"
            continue
        if char == "\\":
            text, index, previous = _escape_outside_class(pattern, index, strict, captures)
            out.append(text)
            continue
        if char == "(":
            prefix = _group_prefix(pattern, index)
            index += len(prefix)
            name = None
            if prefix == "(?<":
                end = pattern.find(">", index)
                if end < 0:
                    raise re.error("unterminated group name")
                name, index = pattern[index:end], end + 1
            captures.open(prefix, name)
            out.append(prefix if name is None else f"(?P<{name}>")
            previous = ""
            continue
        if strict and char in "]{}":
            raise re.error("a lone bracket or brace is not valid with the u flag")
        if char == ")":
            previous = "assertion" if captures.close() else "atom"
        elif char in "^$":
            previous = "assertion"
        elif char == "|":
            captures.alternative()
            previous = ""
        else:
            previous = "atom"
        out.append(_ANY if char == "." else r"\Z" if char == "$" else char)
        index += 1
    captures.finish()
    return "".join(out)


class _Group:
    """An open group: its capture number (0 if none), prefix and first inner capture.

    The captures inside a group are numbered contiguously, so a range describes them.
    """

    def __init__(self, number: int, prefix: str, first: int) -> None:
        self.number = number
        self.prefix = prefix
        self.first = first
        self.alternative = False


class _Captures:
    """The capture groups of one pattern, to keep only backreferences with one meaning.

    In ECMA-262 a reference to a group that did not take part matches the empty
    string, and a loop resets the captures inside it on each iteration; Python fails
    such a reference and keeps the captures of earlier iterations. Both agree only
    when the group always takes part, once, before the reference: when no quantifier,
    alternative or lookaround encloses it. The bookkeeping is linear in the pattern.
    """

    def __init__(self) -> None:
        self.count = 0
        self.names: dict[str, int] = {}
        self.closed: set[int] = set()
        # Ranges of capture numbers that may not take part.
        self.conditional: list[tuple[int, int]] = []
        self.referenced: set[int] = set()
        # The captures of the group that closed last, which a quantifier repeats.
        self.repeated: tuple[int, int] | None = None
        self.lookbehinds = 0
        self.groups = [_Group(0, "", 1)]

    def open(self, prefix: str, name: str | None) -> None:
        number = 0
        if prefix in ("(", "(?<"):
            self.count += 1
            number = self.count
        if name is not None:
            if name in self.names:
                raise re.error("duplicate group name")
            self.names[name] = number
        self.lookbehinds += prefix in _LOOKBEHINDS
        self.groups.append(_Group(number, prefix, self.count + 1))

    def alternative(self) -> None:
        self.groups[-1].alternative = True

    def close(self) -> bool:
        """Close the innermost group; return whether it was a lookaround."""
        if len(self.groups) == 1:
            raise re.error("unbalanced parenthesis")
        group = self.groups.pop()
        lookaround = group.prefix in _LOOKAROUNDS
        self.lookbehinds -= group.prefix in _LOOKBEHINDS
        if group.alternative or lookaround:
            self.conditional.append((group.first, self.count))
        if group.number:
            self.closed.add(group.number)
        self.repeated = (group.number or group.first, self.count)
        return lookaround

    def reference(self, number: int) -> None:
        # Python reads \100 and above as octal escapes, not references.
        if number not in self.closed or number > 99:
            raise re.error("a backreference must follow the group it names")
        if self.lookbehinds:
            raise re.error("a backreference inside a lookbehind is not supported")
        self.referenced.add(number)

    def finish(self) -> None:
        if len(self.groups) > 1:
            raise re.error("missing ), unterminated subpattern")
        if self.groups[0].alternative:
            self.conditional.append((1, self.count))
        # Count the conditional ranges that cover each capture number.
        covered = [0] * (self.count + 2)
        for low, high in self.conditional:
            if low <= high:
                covered[low] += 1
                covered[high + 1] -= 1
        depth = 0
        for number in range(1, self.count + 1):
            depth += covered[number]
            if depth and number in self.referenced:
                raise re.error("a backreference names a group that may not take part")


def _group_prefix(pattern: str, index: int) -> str:
    if not pattern.startswith("(?", index):
        return "("
    for prefix in (*_GROUPS, "(?<"):
        if pattern.startswith(prefix, index):
            return prefix
    raise re.error("group syntax is not ECMA-262")


def _names_astral(pattern: str) -> bool:
    """Whether a pattern names a character outside the BMP or a UTF-16 surrogate."""
    if any(ord(char) > 0xFFFF or 0xD800 <= ord(char) <= 0xDFFF for char in pattern):
        return True
    codes = (escape.group(1) for escape in _ESCAPE_TOKEN.finditer(pattern))
    return any(code is not None and 0xD800 <= int(code, 16) <= 0xDFFF for code in codes)


def _escape(pattern: str, index: int, *, in_class: bool, strict: bool) -> tuple[str, int]:
    """Return the character escape at ``index`` unchanged and the index after it."""
    if index + 1 >= len(pattern):
        raise re.error("pattern ends with a backslash")
    escaped = pattern[index + 1]
    end = index + 2
    if escaped in "xu":
        width = 2 if escaped == "x" else 4
        if end + width > len(pattern) or not _HEX_DIGITS.issuperset(pattern[end : end + width]):
            raise re.error("incomplete hexadecimal escape")
        end += width
        point = _surrogate_pair(pattern, index, end)
        if point is not None:
            return f"\\U{point:08x}", end + 6
    elif escaped in "0123456789":
        octal = escaped != "0" or (end < len(pattern) and pattern[end] in "0123456789")
        if strict and octal and (in_class or escaped == "0"):
            raise re.error("an octal escape is not valid with the u flag")
        if in_class and escaped in "01234567":
            # Up to three octal digits, as Python and Annex B read them. Emit a fixed-width
            # escape so the digits of a following \d expansion cannot join it.
            while end < min(len(pattern), index + 4) and pattern[end] in "01234567":
                end += 1
            value = int(pattern[index + 1 : end], 8)
            if value > 0xFF:
                raise re.error("octal escape is out of range")
            return f"\\x{value:02x}", end
    elif escaped.isascii() and escaped.isalpha():
        if escaped not in "bfnrtv":
            raise re.error("escape is not an ECMA-262 escape")
    elif strict and escaped not in _IDENTITY_ESCAPES and not (in_class and escaped == "-"):
        raise re.error("an identity escape is not valid with the u flag")
    return pattern[index:end], end


def _surrogate_pair(pattern: str, index: int, end: int) -> int | None:
    """Return the code point of an escaped surrogate pair starting at ``index``.

    With the u flag, ``\\uD83D\\uDE00`` is one code point; Python would read two lone
    surrogates that no argument contains.
    """
    high = int(pattern[index + 2 : end], 16)
    low = pattern[end : end + 6]
    if not 0xD800 <= high <= 0xDBFF or len(low) != 6 or not low.startswith("\\u"):
        return None
    if not _HEX_DIGITS.issuperset(low[2:]) or not 0xDC00 <= int(low[2:], 16) <= 0xDFFF:
        return None
    return 0x10000 + (high - 0xD800) * 0x400 + int(low[2:], 16) - 0xDC00


def _escape_outside_class(
    pattern: str, index: int, strict: bool, captures: _Captures
) -> tuple[str, int, str]:
    """Translate the escape at ``index``; return it, the index after it and its token."""
    escaped = pattern[index + 1 : index + 2]
    if escaped in _ESCAPES:
        return _ESCAPES[escaped], index + 2, "atom"
    if escaped == "b":
        return "\\b", index + 2, "assertion"
    if escaped == "B":
        # Python's \B never matches an empty string; ECMA-262's does.
        return r"(?:\B|^\Z)", index + 2, "assertion"
    if escaped == "k":
        end = pattern.find(">", index + 3)
        if not pattern.startswith("<", index + 2) or end < 0:
            raise re.error("invalid named backreference")
        name = pattern[index + 3 : end]
        if name not in captures.names:
            raise re.error("a backreference must follow the group it names")
        captures.reference(captures.names[name])
        return f"(?P={name})", end + 1, "atom"
    if escaped and escaped in "123456789":
        # ECMA-262 reads every following digit as part of the group number.
        end = index + 2
        while end < len(pattern) and pattern[end] in "0123456789":
            end += 1
        number = int(pattern[index + 1 : end])
        captures.reference(number)
        return f"(?:\\{number})", end, "atom"
    text, end = _escape(pattern, index, in_class=False, strict=strict)
    return text, end, "atom"


def _class_atom(pattern: str, index: int, strict: bool) -> tuple[str, str, int]:
    """Return one class atom as Python class text, its kind and the index after it.

    The kind is "char" for one character, "set" for ``\\d``, ``\\w`` and ``\\s``,
    and "complement" for ``\\D``, ``\\W`` and ``\\S``, whose text is the set they
    exclude.
    """
    if pattern[index] != "\\":
        return pattern[index], "char", index + 1
    escaped = pattern[index + 1 : index + 2]
    if escaped in _CLASS_ESCAPES:
        return _CLASS_ESCAPES[escaped], "set", index + 2
    if escaped in _COMPLEMENTS:
        return _COMPLEMENTS[escaped], "complement", index + 2
    if escaped == "B":
        raise re.error("\\B has no meaning inside a character class")
    text, end = _escape(pattern, index, in_class=True, strict=strict)
    return text, "char", end


def _character_class(pattern: str, index: int, strict: bool) -> tuple[str, int]:
    """Translate the class that starts at ``index``; return it and the index after it."""
    index += 1
    negated = pattern.startswith("^", index)
    if negated:
        index += 1
    if pattern.startswith("]", index):
        raise re.error("empty or ambiguous character class")
    members: list[str] = []
    complements: list[str] = []
    while not pattern.startswith("]", index):
        if index >= len(pattern):
            raise re.error("unterminated character class")
        low, kind, index = _class_atom(pattern, index, strict)
        if pattern.startswith("-", index) and pattern[index + 1 : index + 2] not in ("", "]"):
            high, high_kind, index = _class_atom(pattern, index + 1, strict)
            if kind != "char" or high_kind != "char":
                # Annex B reads [%-\w] as a union and the u flag rejects it; Python
                # would read the expansion as a wider range, so refuse it.
                raise re.error("a class escape cannot bound a character range")
            members.append(f"{low}-{high}")
        elif kind == "complement":
            complements.append(low)
        else:
            members.append(low)
    index += 1
    positive = "".join(members)
    if not complements:
        return ("[^" if negated else "[") + positive + "]", index
    # Python classes cannot hold a complement, so express the class with
    # alternatives and lookaheads that each test the same single character.
    positive = "\\" + positive if positive.startswith("^") else positive
    if not negated:
        options = [f"[{positive}]"] if positive else []
        options.extend(f"[^{excluded}]" for excluded in complements)
        # Every alternative matches the same one character, so an atomic group keeps
        # the meaning and stops overlapping members ([\s\W]) from backtracking
        # exponentially.
        return "(?>" + "|".join(options) + ")", index
    guard = f"(?![{positive}])" if positive else ""
    guard += "".join(f"(?=[{excluded}])" for excluded in complements[:-1])
    return f"(?:{guard}[{complements[-1]}])", index


class _EcmaRegex:
    """The part of the ``re`` module jsonschema uses, with ECMA-262 pattern meaning."""

    error = re.error

    def __init__(self) -> None:
        self._compiled: dict[str, re.Pattern[str]] = {}

    def compile(self, pattern: str, flags: int = 0) -> re.Pattern[str]:
        if flags:
            raise re.error("pattern flags are not supported")
        compiled = self._compiled.get(pattern)
        if compiled is None:
            try:
                compiled = re.compile(ecma_pattern(pattern), re.ASCII)
            except RecursionError as exc:
                raise re.error("pattern nests too deeply") from exc
            except (OverflowError, ValueError) as exc:
                # Valid ECMA-262 numbers that Python cannot hold: a repetition count
                # above its limit, or more digits than int() converts.
                raise re.error("pattern holds a number too large to compile") from exc
            self._compiled[pattern] = compiled
        return compiled

    def search(self, pattern: str, string: str, flags: int = 0) -> re.Match[str] | None:
        return self.compile(pattern, flags).search(string)

    def __getattr__(self, name: str) -> Any:
        return getattr(re, name)


def _load_dialects() -> dict[str, Any]:
    import jsonschema._format
    import jsonschema._keywords
    import jsonschema._legacy_keywords
    import jsonschema._utils
    from jsonschema import (
        Draft4Validator,
        Draft6Validator,
        Draft7Validator,
        Draft201909Validator,
        Draft202012Validator,
    )

    # jsonschema evaluates "pattern", "patternProperties" and the keywords that
    # consult them with re.search; route every such call through ECMA semantics.
    regex = _EcmaRegex()
    for module in (
        jsonschema._format,
        jsonschema._keywords,
        jsonschema._legacy_keywords,
        jsonschema._utils,
    ):
        module.re = regex  # type: ignore[attr-defined]
    validators = (
        Draft4Validator,
        Draft6Validator,
        Draft7Validator,
        Draft201909Validator,
        Draft202012Validator,
    )
    return dict(zip(DIALECTS, validators, strict=True))


# Each schema rejects its instance only when patterns have ECMA-262 meaning, through
# each place jsonschema evaluates one: pattern, patternProperties, and the
# additionalProperties and unevaluatedProperties checks that consult it.
_SELF_CHECKS: tuple[tuple[dict[str, Any], Any], ...] = (
    ({"pattern": "^a$"}, "a\n"),
    ({"pattern": "^\\d$"}, "\u0663"),
    ({"patternProperties": {"^\\s$": {"type": "string"}}}, {"\ufeff": 0}),
    ({"patternProperties": {"^a$": {}}, "additionalProperties": False}, {"a\n": 0}),
    ({"patternProperties": {"^a$": {}}, "unevaluatedProperties": False}, {"a\n": 0}),
)


def _ecma_semantics_hold(dialects: dict[str, Any]) -> bool:
    """Confirm that every dialect evaluates patterns through the ECMA-262 translation.

    The translation is installed on private jsonschema modules. A release that moved
    a regex call would silently bring back Python semantics, so the worker then
    refuses to start and every call fails closed.
    """
    from jsonschema.exceptions import SchemaError
    from referencing import Registry

    for validator in dialects.values():
        try:
            validator.check_schema({"pattern": "(?i)a"})
        except SchemaError:
            # Expected: ECMA-262 regex semantics must reject Python inline flags.
            pass
        else:
            return False
        for schema, instance in _SELF_CHECKS:
            if not set(schema) <= set(validator.VALIDATORS):
                continue
            if validator(schema, registry=Registry()).is_valid(instance):
                return False
    return True


# Keywords whose values hold subschemas in some supported dialect, by shape.
_SUBSCHEMA = frozenset(
    {
        "additionalItems",
        "additionalProperties",
        "contains",
        "contentSchema",
        "else",
        "if",
        "items",
        "not",
        "propertyNames",
        "then",
        "unevaluatedItems",
        "unevaluatedProperties",
    }
)
_SUBSCHEMA_LISTS = frozenset({"allOf", "anyOf", "items", "oneOf", "prefixItems"})
_SUBSCHEMA_MAPS = frozenset(
    {"$defs", "definitions", "dependencies", "dependentSchemas", "patternProperties", "properties"}
)


# The assertion and applicator keywords each supported dialect defines, from its
# specification. jsonschema applies some inside another keyword (draft-04's boolean
# exclusiveMinimum inside minimum, then inside if, minContains inside contains), so
# its VALIDATORS tables alone are not the vocabulary.
_DRAFT_04_KEYWORDS = frozenset(
    {
        "$ref",
        "additionalItems",
        "additionalProperties",
        "allOf",
        "anyOf",
        "dependencies",
        "enum",
        "exclusiveMaximum",
        "exclusiveMinimum",
        "format",
        "items",
        "maxItems",
        "maxLength",
        "maxProperties",
        "maximum",
        "minItems",
        "minLength",
        "minProperties",
        "minimum",
        "multipleOf",
        "not",
        "oneOf",
        "pattern",
        "patternProperties",
        "properties",
        "required",
        "type",
        "uniqueItems",
    }
)
_DRAFT_06_KEYWORDS = _DRAFT_04_KEYWORDS | {"const", "contains", "propertyNames"}
_DRAFT_07_KEYWORDS = _DRAFT_06_KEYWORDS | {"if", "then", "else"}
_DRAFT_2019_KEYWORDS = (_DRAFT_07_KEYWORDS - {"dependencies"}) | {
    "$recursiveRef",
    "dependentRequired",
    "dependentSchemas",
    "maxContains",
    "minContains",
    "unevaluatedItems",
    "unevaluatedProperties",
}
_DRAFT_2020_KEYWORDS = (_DRAFT_2019_KEYWORDS - {"$recursiveRef", "additionalItems"}) | {
    "$dynamicRef",
    "prefixItems",
}
# Assertion and applicator keywords that only drafts before draft-04 define: draft-03's
# divisibleBy, disallow and extends, and draft-01 and draft-02's requires, maxDecimal,
# minimumCanEqual and maximumCanEqual. No supported dialect applies them.
_RETIRED_KEYWORDS = frozenset(
    {
        "disallow",
        "divisibleBy",
        "extends",
        "maxDecimal",
        "maximumCanEqual",
        "minimumCanEqual",
        "requires",
    }
)
VOCABULARIES = dict(
    zip(
        DIALECTS,
        (
            _DRAFT_04_KEYWORDS,
            _DRAFT_06_KEYWORDS,
            _DRAFT_07_KEYWORDS,
            _DRAFT_2019_KEYWORDS,
            _DRAFT_2020_KEYWORDS,
        ),
        strict=True,
    )
)
_EVERY_KEYWORD = frozenset().union(*VOCABULARIES.values(), _RETIRED_KEYWORDS)
# Keywords that jsonschema evaluates inside another keyword rather than on their own.
_APPLIED_INSIDE = frozenset(
    {"else", "exclusiveMaximum", "exclusiveMinimum", "maxContains", "minContains", "then"}
)
_REFERENCES = ("$ref", "$dynamicRef", "$recursiveRef")
_SUPPORTED_VOCABULARIES: dict[str, frozenset[str]] = {
    DIALECTS[3]: frozenset(
        {
            "https://json-schema.org/draft/2019-09/vocab/core",
            "https://json-schema.org/draft/2019-09/vocab/applicator",
            "https://json-schema.org/draft/2019-09/vocab/validation",
            "https://json-schema.org/draft/2019-09/vocab/meta-data",
        }
    ),
    DIALECTS[4]: frozenset(
        {
            "https://json-schema.org/draft/2020-12/vocab/core",
            "https://json-schema.org/draft/2020-12/vocab/applicator",
            "https://json-schema.org/draft/2020-12/vocab/unevaluated",
            "https://json-schema.org/draft/2020-12/vocab/validation",
            "https://json-schema.org/draft/2020-12/vocab/meta-data",
            "https://json-schema.org/draft/2020-12/vocab/format-annotation",
        }
    ),
}


def _unsupported_vocabulary(node: dict[str, Any], dialect: str, *, is_root: bool) -> bool:
    """Whether ``node`` declares a ``$vocabulary`` whose required semantics are not asserted."""
    if "$vocabulary" not in node:
        return False
    allowed = _SUPPORTED_VOCABULARIES.get(dialect)
    declared = node["$vocabulary"]
    if not is_root or allowed is None or not isinstance(declared, dict):
        return True
    for uri, required in declared.items():
        if not isinstance(uri, str) or type(required) is not bool:
            return True
        if required and uri not in allowed:
            return True
    return False


def _ignores_a_keyword(
    schema: dict[str, Any], dialect: str, validator: Any, *, preflight: bool = False
) -> bool:
    """Whether evaluation would skip a constraint that whoever approves the schema reads.

    That is a keyword the declared dialect does not define or jsonschema does not
    apply, including those of drafts before draft-04; an assertion next to "$ref" in
    draft-04 to draft-07, which ignore the siblings of "$ref"; a 2019-09
    "unevaluatedItems" that would pass the items "contains" matched; a "$vocabulary"
    requiring an unasserted vocabulary (such as format-assertion or content); and a
    subschema that jsonschema would read in another dialect (its own "$schema") or
    against another base URI (its own "$id", or "id" in draft-04). References must be
    JSON Pointers within the schema ("#" or "#/..."); they are resolved with
    jsonschema's own resolver and their targets checked too. "format" is never
    asserted here.
    """
    from referencing import Registry
    from referencing.jsonschema import specification_with

    known = VOCABULARIES[dialect] & (frozenset(validator.VALIDATORS) | _APPLIED_INSIDE)
    legacy = dialect in DIALECTS[:3]
    identifier = "id" if dialect == DIALECTS[0] else "$id"
    resource = specification_with(dialect).create_resource(schema)
    resolver = Registry().resolver_with_root(resource)
    pending: list[Any] = [schema]
    seen: set[int] = set()
    nodes: list[dict[str, Any]] = []
    regex = _EcmaRegex() if preflight else None
    while pending:
        node = pending.pop()
        if not isinstance(node, dict) or id(node) in seen:
            continue
        seen.add(id(node))
        nodes.append(node)
        if any(
            not isinstance(key, str)
            or not key.isascii()
            or any(ch.isspace() or ord(ch) < 32 or ord(ch) == 127 for ch in key)
            for key in node
        ):
            return True
        used = _EVERY_KEYWORD.intersection(node)
        # Draft-01 and draft-02 require every property whose schema does not say
        # "optional": true. That value asks for what every supported dialect does.
        if (
            used - known
            or node.get("optional", True) is not True
            or (legacy and "$ref" in node and used - {"$ref", "format"})
            or _unsupported_vocabulary(node, dialect, is_root=node is schema)
        ):
            return True
        if node is not schema and _redeclares(node, dialect, identifier):
            return True
        if regex is not None:
            if isinstance(node.get("pattern"), str):
                regex.compile(node["pattern"])
            for pattern in node.get("patternProperties", {}):
                regex.compile(pattern)
        for keyword, value in node.items():
            if keyword in _SUBSCHEMA_MAPS and isinstance(value, dict):
                pending.extend(value.values())
            elif keyword in _SUBSCHEMA_LISTS and isinstance(value, list):
                pending.extend(value)
            elif keyword in _SUBSCHEMA:
                pending.append(value)
        for keyword in _REFERENCES:
            if keyword in node:
                target = _reference_target(resolver, keyword, node[keyword])
                if not isinstance(target, (dict, bool)):
                    return True
                pending.append(target)
    if preflight and _in_place_evaluation_exceeds_budget(schema, resolver):
        return True
    return dialect == DIALECTS[3] and _contains_meets_unevaluated_items(nodes, resolver)


def _in_place_evaluation_exceeds_budget(schema: dict[str, Any], resolver: Any) -> bool:
    """Bound the evaluator stack and repeated same-value work before dispatch."""
    pending = [schema]
    graph: dict[int, list[int]] = {}
    descends: dict[int, list[int]] = {}
    nodes: dict[int, dict[str, Any]] = {}
    annotations: set[int] = set()
    alternatives: set[int] = set()
    widths: dict[int, int] = {}
    value_keywords = {
        "additionalItems",
        "additionalProperties",
        "contains",
        "items",
        "prefixItems",
        "propertyNames",
        "unevaluatedItems",
        "unevaluatedProperties",
        "contentSchema",
    }
    while pending:
        node = pending.pop()
        if not isinstance(node, dict) or id(node) in graph:
            continue
        nodes[id(node)] = node
        applied = _applied_in_place(node, resolver)
        in_place = [child for child in applied if isinstance(child, dict)]
        # A repeated reference repeats the keyword's width too. Checking a
        # singleton property or tag lists no more entries than one graph visit.
        widths[id(node)] = (
            1
            + sum(isinstance(child, bool) for child in applied)
            + sum(
                max(0, len(value) - 1)
                for keyword in ("properties", "patternProperties", "required", "enum")
                if isinstance(value := node.get(keyword), (list, dict))
            )
        )
        graph[id(node)] = [id(child) for child in in_place]
        pending.extend(in_place)
        if "unevaluatedItems" in node or "unevaluatedProperties" in node:
            annotations.add(id(node))
        # A wide list of explicitly written alternatives can do more linear work
        # than a compact repeated reference. Keep a separate absolute ceiling.
        variants = node.get("oneOf", node.get("anyOf"))
        if (
            isinstance(variants, list)
            and len(variants) >= 16
            and len(variants) == len(in_place)
            and all(a is b for a, b in zip(variants, in_place, strict=True))
        ):
            alternatives.add(id(node))
        subvalues: list[Any] = []
        for keyword, value in node.items():
            if keyword in {"properties", "patternProperties"} and isinstance(value, dict):
                subvalues.extend(value.values())
            elif keyword in value_keywords:
                subvalues.extend(value if isinstance(value, list) else [value])
        value_schemas = [child for child in subvalues if isinstance(child, dict)]
        descends[id(node)] = [id(child) for child in value_schemas]
        pending.extend(value_schemas)

    incoming = dict.fromkeys(graph, 0)
    for edges in graph.values():
        for child_id in edges:
            incoming[child_id] += 1
    ready = [node_id for node_id, count in incoming.items() if count == 0]
    topological = []
    while ready:
        current = ready.pop()
        topological.append(current)
        for child_id in graph[current]:
            incoming[child_id] -= 1
            if incoming[child_id] == 0:
                ready.append(child_id)
    if len(topological) != len(graph):
        return True
    depths: dict[int, int] = {}
    steps: dict[int, int] = {}
    limits: dict[int, int] = {}
    validation_steps: dict[int, int] = {}
    annotation_steps: dict[int, int] = {}
    for current in reversed(topological):
        children = graph[current]
        depth = 1 + max((depths[c] for c in children), default=0)
        # Each reference can evaluate the shared child again. Saturate by
        # refusing as soon as a subproblem exceeds the budget.
        # Collecting evaluated locations can visit the same applicators again.
        visits = sum(steps[c] for c in children)
        work = widths[current] + (2 if current in annotations else 1) * visits
        limit = _MAX_OUTPUT_APPLICATOR_STEPS
        if current in alternatives and all(steps[c] <= 32 for c in children):
            limit = _MAX_OUTPUT_UNION_STEPS
        else:
            unions = [c for c in children if limits[c] > _MAX_OUTPUT_APPLICATOR_STEPS]
            if len(unions) == 1 and visits - steps[unions[0]] <= 32:
                limit = _MAX_OUTPUT_UNION_STEPS
        if depth > _MAX_OUTPUT_IN_PLACE_DEPTH or work > limit:
            return True
        # Collecting evaluated locations can validate a branch and then walk its
        # annotations. Keep that walk separate so a chain between two annotated
        # nodes is charged to every caller. Saturate unused estimates on a DAG.
        validation = widths[current] + sum(validation_steps[c] for c in children)
        annotation = validation + sum(annotation_steps[c] for c in children)
        if current in annotations:
            validation += annotation
        if validation > 4 * limit:
            return True
        validation_steps[current] = validation
        annotation_steps[current] = min(annotation, 4 * _MAX_OUTPUT_UNION_STEPS + 1)
        depths[current], steps[current] = depth, work
        limits[current] = limit
    # Recursion through a child of the instance is permitted. Account for the
    # frames it adds across every possible level of the bounded JSON input.
    # Keep headroom for the worker and the validator's helper frames. Ordinary
    # recursive records need more total hops than the limit at one location.
    stack_limit = min(_MAX_OUTPUT_APPLICATOR_DEPTH, (sys.getrecursionlimit() - 128) // 5)
    # An unevaluated-location collector can validate an additional property or
    # matching item again, including through a reference or an allOf wrapper.
    annotation_levels = dict.fromkeys(graph, 0)
    for _ in range(MAX_JSON_DEPTH):
        previous, prior_levels = depths, annotation_levels
        depths, annotation_levels = {}, {}
        rechecked: dict[int, int] = {}
        below: dict[int, int] = {}
        for current in reversed(topological):
            at_value = max((depths[c] for c in graph[current]), default=0)
            below_value = max((previous[c] for c in descends[current]), default=0)
            depths[current] = 1 + max(at_value, below_value)
            if depths[current] > stack_limit:
                return True
            rechecked[current] = max((rechecked[c] for c in graph[current]), default=0)
            below[current] = max(
                max((below[c] for c in graph[current]), default=-1),
                max((prior_levels[c] for c in descends[current]), default=-1),
            )
            # To collect a composition's annotations the validator can first
            # validate the successful arm, including its child instances.
            for kw in ("allOf", "anyOf", "oneOf"):
                for arm in nodes[current].get(kw, []):
                    if isinstance(arm, dict):
                        rechecked[current] = max(rechecked[current], 1 + below[id(arm)])
            for keyword in (
                "additionalProperties",
                "contains",
                "unevaluatedItems",
                "unevaluatedProperties",
            ):
                child = nodes[current].get(keyword)
                if isinstance(child, dict):
                    rechecked[current] = max(rechecked[current], 1 + prior_levels[id(child)])
            annotation_levels[current] = max(
                rechecked[current] if current in annotations else 0,
                max((annotation_levels[c] for c in graph[current]), default=0),
                max((prior_levels[c] for c in descends[current]), default=0),
            )
            if 2 ** annotation_levels[current] > _MAX_OUTPUT_APPLICATOR_STEPS:
                return True
        if depths == previous and annotation_levels == prior_levels:
            break
    return _collection_work_exceeds_budget(id(schema), nodes, graph, topological)


def _collection_work_exceeds_budget(
    root: int, nodes: dict[int, dict[str, Any]], graph: dict[int, list[int]], order: list[int]
) -> bool:
    """Estimate repeated validation on conforming results, bounded by their JSON nodes."""
    work: dict[int, int] = {}
    footprint: dict[int, int] = {}
    branching: dict[int, bool] = {}
    for current in reversed(order):
        node = nodes[current]
        enum = node.get("enum", [])
        # Name lookups and comparisons of scalar constants are cheaper than
        # descending into a validator. The per-location budget still counts
        # every property, required name and enum candidate individually.
        width = 1 + (len(node.get("properties", {})) + len(node.get("required", []))) // 8
        width += (
            (len(enum) + 7) // 8
            if all(not isinstance(x, (list, dict)) for x in enum)
            else len(enum)
        )
        children = graph[current]
        work[current] = width + sum(work[c] for c in children)
        branching[current] = any(branching[c] for c in children)
        for keyword in ("oneOf", "anyOf"):
            arms = node.get(keyword, [])
            # A JSON-value union uses disjoint primitive types. At most one of
            # its array and object branches can recurse at the current value.
            kinds = {
                x["type"]
                for x in arms
                if isinstance(x, dict)
                and isinstance(x.get("type"), str)
                and x.keys() <= {"type", "items", "additionalProperties"}
            }
            if len(kinds) < len(arms) or {"integer", "number"} <= kinds:
                branching[current] = True
        size = 1
        if node.get("type") == "object":
            size += max(len(node.get("required", [])), node.get("minProperties", 0))
        elif node.get("type") == "array":
            size += node.get("minItems", 0)
        # A reference or allOf constrains the same value. Alternative or
        # conditional branches cannot impose a common minimum individually.
        if any(k in node for k in _REFERENCES) and len(children) == 1:
            size = max(size, footprint[children[0]])
        size = max(
            size,
            max(
                (footprint[id(x)] for x in node.get("allOf", []) if isinstance(x, dict)), default=1
            ),
        )
        for key in ("anyOf", "oneOf"):
            if options := node.get(key):
                size = max(
                    size, min(footprint[id(x)] if isinstance(x, dict) else 1 for x in options)
                )
        footprint[current] = int(min(size, MAX_JSON_NODES))

    # Keep each level separate. A recursive reference through a child advances
    # one level, while all in-place callers are processed before their targets.
    # Track per-value duplication separately for object vs array parent slots
    # (a single JSON value cannot simultaneously be an object property and an
    # array element) and preserve exact slot keys whenever a key repeats across
    # containers or enters an in-place branching subgraph (allOf/anyOf/oneOf).
    counts = {root: 1}
    # The largest count any single parent hands a node. Sums count every path, which
    # separate sibling values (a tree's left and right) would compound per level; one
    # value reaches a node at most ``max_dup`` times, so the sum is capped there.
    peaks = {root: 1}
    nested: set[int] = set()
    fallible: set[int] = set()
    step_cap = _MAX_OUTPUT_REPEATED_STEPS + 1

    max_dup = _max_single_value_multiplicity(root, order, graph, nodes, step_cap)
    if max_dup is None:
        return True

    for _ in range(MAX_JSON_DEPTH + 1):
        following: dict[int, int] = {}
        following_peaks: dict[int, int] = {}
        nested_following: set[int] = set()
        fallible_following: set[int] = set()
        for current in order:
            count = counts.get(current, 0)
            if not count:
                continue
            multiplicity = max(1, max_dup.get(current, 1))
            count = min(count, peaks.get(current, count) * multiplicity)
            # A value reaches a shared definition once per in-place path, so its
            # multiplicity stays within the schema's own size unless paths compound:
            # a chain of allOf arms that doubles per level reaches 2**depth from a
            # few dozen nodes. The raw count is not capped; a shared definition
            # multiplies the visits of every element, and a bound on the product
            # refused ordinary unions whose variants share a list.
            if multiplicity > max(_MIN_SHARED_MULTIPLICITY, len(order)):
                return True
            dup = min(step_cap, multiplicity)
            node = nodes[current]
            # Only schemas that abort collection validation on a non-conforming
            # value can bound repetitions by a conforming value's node footprint.
            # Branches under contains/anyOf/oneOf/not/if can fail repeatedly on
            # single-node values without stopping collection evaluation.
            distinct_limit = (
                MAX_JSON_NODES if current in fallible else MAX_JSON_NODES // footprint[current]
            )
            count = min(count, distinct_limit * dup)
            costly = work[current] > 32 or (current in nested and branching[current])
            if costly and count * work[current] > _MAX_OUTPUT_REPEATED_STEPS:
                return True
            fallible_children: set[int] = set()
            for kw in ("not", "if"):
                if isinstance(node.get(kw), dict):
                    fallible_children.add(id(node[kw]))
            for kw in ("anyOf", "oneOf"):
                for arm in node.get(kw, ()):
                    if isinstance(arm, dict):
                        fallible_children.add(id(arm))
            for child in graph[current]:
                counts[child] = min(step_cap, counts.get(child, 0) + count)
                peaks[child] = max(peaks.get(child, 0), count)
                if current in nested:
                    nested.add(child)
                if current in fallible or child in fallible_children:
                    fallible.add(child)
            items = int(min(node.get("maxItems", MAX_JSON_NODES), MAX_JSON_NODES))
            properties = int(min(node.get("maxProperties", MAX_JSON_NODES), MAX_JSON_NODES))
            patterns = node.get("patternProperties", {})
            comparisons = len(patterns) * min(count * properties, MAX_JSON_NODES)
            if node.get("uniqueItems") and items:
                # jsonschema evaluates uniqueItems independently of items and falls
                # back to quadratic comparisons on unhashable or mixed-type arrays.
                entries = min(count * items, MAX_JSON_NODES)
                unique_comparisons = entries * (items - 1) // 2
                if unique_comparisons > _MAX_OUTPUT_REPEATED_STEPS:
                    return True
                comparisons += unique_comparisons
            if comparisons > 16 * _MAX_OUTPUT_REPEATED_STEPS:
                return True

            fixed_costs: list[int] = []
            for keyword, value in node.items():
                if (
                    keyword == "properties"
                    or keyword in ("prefixItems", "items")
                    and isinstance(value, list)
                ):
                    entries_list = (
                        list(value.values()) if isinstance(value, dict) else value[:items]
                    )
                    cardinality = 1
                    costs = [
                        work[id(x)]
                        for x in entries_list
                        if isinstance(x, dict) and (branching[id(x)] or work[id(x)] > 32)
                    ]
                    if isinstance(value, dict) and len(costs) > properties:
                        costs.sort(reverse=True)
                        del costs[properties:]
                    fixed_costs.extend(costs)
                elif keyword == "patternProperties":
                    entries_list = list(value.values())
                    cardinality = properties
                    matching_work = sum(
                        work[id(part)] for part in entries_list if isinstance(part, dict)
                    )
                    if (
                        len(value) > 1
                        and min(count * properties, MAX_JSON_NODES) * matching_work
                        > _MAX_OUTPUT_REPEATED_STEPS
                    ):
                        return True
                elif keyword in ("items", "contains", "additionalItems", "unevaluatedItems"):
                    entries_list, cardinality = [value], items
                elif keyword in ("additionalProperties", "unevaluatedProperties", "propertyNames"):
                    entries_list, cardinality = [value], properties
                else:
                    continue
                for part in entries_list:
                    if isinstance(part, dict):
                        child = id(part)
                        following[child] = min(
                            step_cap, following.get(child, 0) + count * cardinality
                        )
                        following_peaks[child] = max(
                            following_peaks.get(child, 0), min(step_cap, count * cardinality)
                        )
                        if (
                            current in nested
                            or keyword == "contains"
                            or (count > 1 and cardinality > 1)
                        ):
                            nested_following.add(child)
                        if current in fallible or keyword == "contains":
                            fallible_following.add(child)
            if len(fixed_costs) > 1 and count * sum(fixed_costs) > _MAX_OUTPUT_REPEATED_STEPS:
                return True
        if not following or (
            following == counts and nested_following == nested and fallible_following == fallible
        ):
            break
        counts, peaks, nested, fallible = (
            following,
            following_peaks,
            nested_following,
            fallible_following,
        )
    return False


_MAX_PATH_STATES = 4096
_MAX_PATH_TRANSITIONS = 16384


def _max_single_value_multiplicity(
    root: int,
    order: list[int],
    graph: dict[int, list[int]],
    nodes: dict[int, dict[str, Any]],
    step_cap: int,
) -> dict[int, int] | None:
    """Upper bound on how many times a single JSON value can reach each schema node."""
    closure: dict[int, dict[int, int]] = {}
    for current in reversed(order):
        acc: dict[int, int] = {current: 1}
        for child in graph[current]:
            for target, mult in closure[child].items():
                nxt = acc.get(target, 0) + mult
                if nxt >= step_cap:
                    return None
                acc[target] = nxt
        closure[current] = acc

    def _close(seed: dict[int, int]) -> dict[int, int] | None:
        closed: dict[int, int] = {}
        total = 0
        for u, weight in seed.items():
            for target, mult in closure[u].items():
                add = weight * mult
                nxt = closed.get(target, 0) + add
                total += add
                if nxt >= step_cap or total >= step_cap:
                    return None
                closed[target] = nxt
        return closed

    init = _close({root: 1})
    if init is None:
        return None
    max_dup: dict[int, int] = dict(init)
    init_key = tuple(sorted(init))
    frontier: dict[tuple[int, ...], dict[int, int]] = {init_key: init}
    seen: dict[tuple[int, ...], dict[int, int]] = {init_key: dict(init)}
    expansions = 0
    transitions = 0

    def _record(
        seed: dict[int, int],
        target_frontier: dict[tuple[int, ...], dict[int, int]],
    ) -> bool:
        nonlocal transitions
        transitions += 1
        if transitions > _MAX_PATH_TRANSITIONS:
            return False
        if not seed:
            return True
        closed = _close(seed)
        if closed is None:
            return False
        for nid, m in closed.items():
            if m > max_dup.get(nid, 0):
                max_dup[nid] = m
        key = tuple(sorted(closed))
        prev = seen.get(key)
        if prev is not None and all(closed[nid] <= prev[nid] for nid in key):
            return True
        seen[key] = (
            {nid: max(prev[nid], closed[nid]) for nid in key} if prev is not None else dict(closed)
        )
        existing = target_frontier.get(key)
        target_frontier[key] = (
            closed if existing is None else {nid: max(existing[nid], closed[nid]) for nid in key}
        )
        return True

    for _ in range(MAX_JSON_DEPTH):
        if not frontier:
            break
        next_frontier: dict[tuple[int, ...], dict[int, int]] = {}

        for active in frontier.values():
            expansions += 1
            if expansions > _MAX_PATH_STATES:
                return None

            propname_seed: dict[int, int] = {}
            obj_wild_base: dict[int, int] = {}
            obj_key_nodes: dict[str, list[tuple[int, int]]] = {}
            arr_wild_base: dict[int, int] = {}
            arr_idx_nodes: dict[int, list[tuple[int, str, int]]] = {}

            for u, mult in active.items():
                node = nodes[u]
                if isinstance(node.get("propertyNames"), dict):
                    cid = id(node["propertyNames"])
                    propname_seed[cid] = min(step_cap, propname_seed.get(cid, 0) + mult)
                props = node.get("properties")
                if isinstance(props, dict):
                    for k in props:
                        obj_key_nodes.setdefault(k, []).append((u, mult))
                patterns = node.get("patternProperties")
                if isinstance(patterns, dict):
                    for psub in patterns.values():
                        if isinstance(psub, dict):
                            cid = id(psub)
                            obj_wild_base[cid] = min(step_cap, obj_wild_base.get(cid, 0) + mult)
                for kw in ("additionalProperties", "unevaluatedProperties"):
                    sub = node.get(kw)
                    if isinstance(sub, dict):
                        cid = id(sub)
                        obj_wild_base[cid] = min(step_cap, obj_wild_base.get(cid, 0) + mult)
                for kw in ("prefixItems", "items"):
                    tuple_kw = node.get(kw)
                    if isinstance(tuple_kw, list):
                        for idx in range(len(tuple_kw)):
                            arr_idx_nodes.setdefault(idx, []).append((u, kw, mult))
                for kw in ("items", "additionalItems", "contains", "unevaluatedItems"):
                    sub = node.get(kw)
                    if isinstance(sub, dict):
                        cid = id(sub)
                        arr_wild_base[cid] = min(step_cap, arr_wild_base.get(cid, 0) + mult)

            if propname_seed and not _record(propname_seed, next_frontier):
                return None
            if obj_wild_base and not _record(obj_wild_base, next_frontier):
                return None
            for k, holders in obj_key_nodes.items():
                seed = dict(obj_wild_base)
                for u, mult in holders:
                    node = nodes[u]
                    addl = node.get("additionalProperties")
                    if isinstance(addl, dict):
                        aid = id(addl)
                        rem = seed.get(aid, 0) - mult
                        if rem <= 0:
                            seed.pop(aid, None)
                        else:
                            seed[aid] = rem
                    sub = node["properties"][k]
                    if isinstance(sub, dict):
                        cid = id(sub)
                        seed[cid] = min(step_cap, seed.get(cid, 0) + mult)
                if not _record(seed, next_frontier):
                    return None
            if arr_wild_base and not _record(arr_wild_base, next_frontier):
                return None
            for idx, arr_holders in arr_idx_nodes.items():
                seed = dict(arr_wild_base)
                for u, kw, mult in arr_holders:
                    node = nodes[u]
                    tail_kw = "items" if kw == "prefixItems" else "additionalItems"
                    tail_sub = node.get(tail_kw)
                    if isinstance(tail_sub, dict):
                        aid = id(tail_sub)
                        rem = seed.get(aid, 0) - mult
                        if rem <= 0:
                            seed.pop(aid, None)
                        else:
                            seed[aid] = rem
                    sub = node[kw][idx]
                    if isinstance(sub, dict):
                        cid = id(sub)
                        seed[cid] = min(step_cap, seed.get(cid, 0) + mult)
                if not _record(seed, next_frontier):
                    return None
        frontier = next_frontier
    return max_dup


def _contains_meets_unevaluated_items(nodes: list[dict[str, Any]], resolver: Any) -> bool:
    """Whether "contains" applies where a 2019-09 "unevaluatedItems" does.

    jsonschema's 2019-09 "unevaluatedItems" then treats the items "contains" matched
    as evaluated, as 2020-12 specifies. In 2019-09 "contains" makes no annotation,
    so the declared dialect still applies "unevaluatedItems" to them. The subschemas
    of allOf, anyOf, oneOf, not, if, then, else and dependentSchemas, and the targets
    of "$ref" and "$recursiveRef", apply where the schema holding them applies. The
    search follows those links back from each "contains", in time linear in the schema.
    """
    callers: dict[int, list[dict[str, Any]]] = {}
    for node in nodes:
        for child in _applied_in_place(node, resolver):
            if isinstance(child, dict):
                callers.setdefault(id(child), []).append(node)
    pending = [node for node in nodes if "contains" in node]
    reached = {id(node) for node in pending}
    while pending:
        node = pending.pop()
        if "unevaluatedItems" in node:
            return True
        for caller in callers.get(id(node), ()):
            if id(caller) not in reached:
                reached.add(id(caller))
                pending.append(caller)
    return False


def _applied_in_place(node: dict[str, Any], resolver: Any) -> list[Any]:
    """The applicable subschemas that evaluate the same instance location as ``node``."""
    children = [node["not"]] if "not" in node else []
    if "if" in node:
        children.extend(node[keyword] for keyword in ("if", "then", "else") if keyword in node)
    for keyword in ("allOf", "anyOf", "oneOf"):
        if isinstance(node.get(keyword), list):
            children.extend(node[keyword])
    for keyword in ("dependencies", "dependentSchemas"):
        if isinstance(node.get(keyword), dict):
            children.extend(node[keyword].values())
    children.extend(
        _reference_target(resolver, keyword, node[keyword])
        for keyword in _REFERENCES
        if keyword in node
    )
    return children


def _redeclares(node: dict[str, Any], dialect: str, identifier: str) -> bool:
    """Whether a subschema declares another dialect or a base URI of its own."""
    if "$schema" in node:
        declared = node["$schema"]
        if not isinstance(declared, str) or declared.removesuffix("#") != dialect:
            return True
    if identifier not in node:
        return False
    value = node[identifier]
    # Draft-04 to draft-07 read an identifier that starts with "#" as a plain-name
    # anchor, which changes no base URI.
    return not (dialect in DIALECTS[:3] and isinstance(value, str) and value.startswith("#"))


def _reference_target(resolver: Any, keyword: str, reference: Any) -> Any:
    """Resolve a JSON Pointer reference as jsonschema does; anything else gives None."""
    from referencing.exceptions import Unresolvable

    if keyword == "$recursiveRef":
        # 2019-09 resolves "$recursiveRef" as "#" whatever it names.
        reference = reference if reference == "#" else None
    if not isinstance(reference, str) or not (reference == "#" or reference.startswith("#/")):
        return None
    try:
        return resolver.lookup(reference).contents
    except (Unresolvable, LookupError, TypeError, ValueError):
        return None


def _evaluate(dialects: dict[str, Any], schema: dict[str, Any], arguments: Any) -> bytes:
    from jsonschema.exceptions import SchemaError
    from jsonschema.exceptions import ValidationError as SchemaValidationError
    from referencing import Registry
    from referencing.exceptions import Unresolvable

    declared = schema.get("$schema", DIALECTS[-1])
    if not isinstance(declared, str):
        return _SCHEMA
    dialect = declared.removesuffix("#")
    validator = dialects.get(dialect)
    if validator is None:
        return _SCHEMA
    try:
        validator.check_schema(schema)
        preflight = arguments is None
        if _ignores_a_keyword(schema, dialect, validator, preflight=preflight):
            return _SCHEMA
        if not preflight:
            validator(schema, registry=Registry()).validate(arguments)
    except SchemaValidationError:
        return _INVALID
    except (SchemaError, Unresolvable, re.error):
        return _SCHEMA
    except RecursionError:
        # Cyclic references can exhaust Python recursion within the worker's
        # existing CPU, memory and wall-time limits. Report an invalid schema
        # when that exception arrives before a resource limit ends the worker.
        return _SCHEMA
    return _VALID


def _worker() -> int:
    """Internal fixed-protocol worker; failure details never echo input values."""
    try:
        if os.name != "posix":
            return 2
        import resource

        _apply_worker_limits()
        _disable_unused_format_checkers()
        dialects = _load_dialects()
        if not _ecma_semantics_hold(dialects):
            return 1
        # RLIMIT_CPU counts the whole process, so measure start-up and grant the
        # evaluation at least WORKER_CPU_SECONDS within the startup+eval hard ceiling.
        usage = resource.getrusage(resource.RUSAGE_SELF)
        budget = min(
            WORKER_STARTUP_CPU_SECONDS,
            math.ceil(usage.ru_utime + usage.ru_stime) + WORKER_CPU_SECONDS,
        )
        resource.setrlimit(resource.RLIMIT_CPU, (budget, budget))
        sys.stdout.buffer.write(_READY)
        sys.stdout.buffer.flush()
        maximum = MAX_SCHEMA_BYTES + MAX_ARGUMENT_BYTES + 64
        wire = sys.stdin.buffer.read(maximum + 1)
        if len(wire) > maximum:
            return 1
        request = json.loads(wire)
        if not isinstance(request, dict) or set(request) != {"schema", "arguments"}:
            return 1
        schema, arguments = request["schema"], request["arguments"]
        if not isinstance(schema, dict) or (
            arguments is not None and not isinstance(arguments, dict)
        ):
            return 1
        check_json_budget(schema, maximum=MAX_SCHEMA_BYTES)
        if arguments is not None:
            check_json_budget(arguments, maximum=MAX_ARGUMENT_BYTES)
        sys.stdout.buffer.write(_evaluate(dialects, schema, arguments))
        return 0
    except Exception:
        return 1


if __name__ == "__main__":
    raise SystemExit(_worker())
