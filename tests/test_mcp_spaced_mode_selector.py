"""The operand after a mode selector whose scheme is a separate word (``--auth bearer <x>``)."""

import hashlib
import json

import pytest

from nexus_symbiote.generators.sarif import SARIFGenerator
from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

# A generated fixture word of bearer-token length; it is not, and never was, a credential.
TOKEN = "fx" + hashlib.sha256(b"spaced mode selector fixture").hexdigest()[:30]
# The `--port=3000` before the selector keeps the whole command line from reading as one
# `node server.js --auth=...` assignment, so the shell and cmd cases reach the pairing rule.
_PREFIX = "node server.js --port=3000"
LAYOUTS = ["array", "sh", "cmd"]


def _launch(selector: list[str], word: str, layout: str) -> dict:
    if layout == "array":
        return {"command": "node", "args": ["server.js", "--port=3000", *selector, word]}
    line = f"{_PREFIX} {' '.join(selector)} {word}"
    if layout == "sh":
        return {"command": "sh", "args": ["-c", line]}
    return {"command": "cmd", "args": ["/c", line]}


def _observed(tmp_path, selector: list[str], word: str, layout: str):
    result, inventory = _scan(
        tmp_path, {"source": _launch(selector, word, layout), "sibling": _echo(word)}
    )
    documents = (*exports(inventory), json.dumps(SARIFGenerator().generate(inventory)))
    return result, tuple(word in document for document in documents)


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize(
    "selector",
    [
        ["--auth-type", "bearer"],
        ["--auth", "bearer"],
        ["--auth", "Bearer"],
        ["--auth", "token"],
        ["--auth-scheme", "dpop"],
        ["--auth-header", "bearer"],
    ],
)
@pytest.mark.parametrize("word", [TOKEN, "Summer24"])
def test_operand_after_a_spaced_mode_is_withheld_and_flagged(tmp_path, selector, word, layout):
    result, present = _observed(tmp_path, selector, word, layout)
    assert not result.scan_failures
    assert has_exposure(result)
    assert not any(present)


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize("word", ["sunshine", "db.internal.example"])
def test_unflagged_operand_after_a_spaced_mode_is_still_withheld(tmp_path, word, layout):
    result, present = _observed(tmp_path, ["--auth", "bearer"], word, layout)
    assert not result.scan_failures
    assert not has_exposure(result)
    assert not any(present)


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize(
    ("selector", "word"),
    [
        (["--auth", "bearer", "--port"], "8080"),
        (["--auth", "bearer"], "--port=8080"),
        (["--auth", "bearer"], "api.github.com"),
        (["--auth", "token"], "production"),
        (["--auth", "bearer"], "required"),
        (["--auth", "bearer"], "Workspace10"),
        (["--auth", "bearer"], "20250618"),
        (["--auth", "bearer"], "PORT=8080"),
    ],
)
def test_public_words_stay_public_after_a_spaced_mode(tmp_path, selector, word, layout):
    result, present = _observed(tmp_path, selector, word, layout)
    assert not has_exposure(result)
    assert all(present[:3])


_PAIRS = [
    ("--auth", "bearer"),
    ("--auth-type", "basic"),
    ("--auth-header", "bearer"),
    ("--api-key", "bearer"),
    ("--type", "bearer"),
]
# A public selector chooses a value, not a mode. Within one shell word list the `=` form
# of one is read more strictly than across launch arguments, so it is compared only there.
_PUBLIC_SELECTOR_PAIRS = [("--format", "token"), ("--source", "token")]


@pytest.mark.parametrize(
    ("flag", "scheme", "layout"),
    [
        *((flag, scheme, layout) for flag, scheme in _PAIRS for layout in ("array", "sh")),
        *((flag, scheme, "array") for flag, scheme in _PUBLIC_SELECTOR_PAIRS),
    ],
)
@pytest.mark.parametrize(
    "word", [TOKEN, "Summer24", "sunshine", "api.github.com", "production", "${TOKEN}"]
)
def test_spaced_and_equals_forms_read_the_operand_alike(tmp_path, flag, scheme, word, layout):
    spaced_result, spaced = _observed(tmp_path, [flag, scheme], word, layout)
    equals_result, equals = _observed(tmp_path, [f"{flag}={scheme}"], word, layout)
    assert has_exposure(spaced_result) is has_exposure(equals_result)
    assert spaced == equals


def test_a_trailing_spaced_mode_without_an_operand_is_read(tmp_path):
    result, _ = _scan(
        tmp_path, {"source": {"command": "node", "args": ["server.js", "--auth", "bearer"]}}
    )
    assert not result.scan_failures
    assert not has_exposure(result)
