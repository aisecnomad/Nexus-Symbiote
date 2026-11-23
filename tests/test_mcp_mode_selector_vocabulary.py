"""Which words after an authentication mode selector are exported as public labels."""

import json

import pytest

from nexus_symbiote.generators.sarif import SARIFGenerator
from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

# The `--port=3000` before the selector keeps the whole command line from reading as one
# `node server.js --auth=...` assignment, so the shell and cmd cases reach the pairing rule.
_PREFIX = "node server.js --port=3000"


def _launch(selector: str, word: str, layout: str) -> dict:
    if layout == "array":
        return {"command": "node", "args": ["server.js", "--port=3000", selector, word]}
    if layout == "sh":
        return {"command": "sh", "args": ["-c", f"{_PREFIX} {selector} {word}"]}
    return {"command": "cmd", "args": ["/c", f"{_PREFIX} {selector} {word}"]}


def _documents(inventory) -> tuple[str, ...]:
    return (*exports(inventory), json.dumps(SARIFGenerator().generate(inventory)))


LAYOUTS = ["array", "sh", "cmd"]


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize(
    ("selector", "word"),
    [
        ("--auth=token", "Summer24"),
        ("--auth-type=bearer", "Welcome12"),
        ("--auth-header=bearer", "Summer24"),
    ],
)
def test_capitalized_word_and_digits_is_a_credential_after_a_mode(tmp_path, selector, word, layout):
    result, inventory = _scan(
        tmp_path, {"source": _launch(selector, word, layout), "sibling": _echo(word)}
    )
    assert has_exposure(result)
    assert all(word not in document for document in _documents(inventory))


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize(
    ("selector", "word"),
    [
        ("--auth=token", "sunshine"),
        ("--auth-type=bearer", "Sunshine"),
        ("--auth=token", "db.internal.example"),
        ("--auth-type=bearer", "vault.corp"),
        ("--auth-header=bearer", "db.internal.example"),
    ],
)
def test_dictionary_word_or_private_host_is_withheld_after_a_mode(tmp_path, selector, word, layout):
    result, inventory = _scan(
        tmp_path, {"source": _launch(selector, word, layout), "sibling": _echo(word)}
    )
    assert not result.scan_failures
    assert all(word not in document for document in _documents(inventory))


@pytest.mark.parametrize("layout", LAYOUTS)
@pytest.mark.parametrize(
    "word",
    [
        "Workspace10",
        "WorkspaceV10",
        "OpenAPI3.1",
        "OAuth2.1",
        "20250618",
        "production",
        "localhost",
        "api.github.com",
        "mcp.service.de",
        "worker.mjs",
        "db.internal.example:5432",
        "https://db.internal.example",
    ],
)
def test_mode_vocabulary_switches_and_locators_stay_public(tmp_path, word, layout):
    result, inventory = _scan(
        tmp_path, {"source": _launch("--auth=token", word, layout), "sibling": _echo(word)}
    )
    assert not has_exposure(result)
    assert all(word in document for document in exports(inventory))
