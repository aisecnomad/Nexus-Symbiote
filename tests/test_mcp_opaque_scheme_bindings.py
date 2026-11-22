"""Check that a credential binding takes precedence over a public-looking operand."""

import hashlib

import pytest

from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

_DIGEST = hashlib.sha256(b"generated operand for inventory comparison").hexdigest()
_LETTERS = "".join(chr(97 + int(nibble, 16)) for nibble in _DIGEST)
_MIXED = _LETTERS[:4] + _LETTERS[4:8].upper() + _LETTERS[8:12]


@pytest.mark.parametrize("binding", ["API_TOKEN", "AUTHORIZATION", "API_KEY", "AUTH_TYPE"])
@pytest.mark.parametrize("layout", ["args", "shell", "cmd"])
@pytest.mark.parametrize(
    "operand",
    [_LETTERS[:12], _MIXED, "--" + _LETTERS[:10], "--" + _MIXED, "--" + _LETTERS[:10].upper()],
)
def test_opaque_words_after_a_credential_binding_are_withheld(tmp_path, binding, layout, operand):
    assignment = binding + "=Bearer"
    if layout == "args":
        source = {"command": "node", "args": ["--env=" + assignment, operand]}
    elif layout == "shell":
        source = {"command": "sh", "args": ["-c", f"node notes.js --env={assignment} {operand}"]}
    else:
        source = {"command": "cmd", "args": ["/c", f"set {assignment} {operand}&& node notes.js"]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(operand)})
    assert has_exposure(result)
    assert all(operand not in output for output in exports(inventory))


@pytest.mark.parametrize("name", ["--auth", "--authentication", "--auth-type", "AUTH_TYPE"])
@pytest.mark.parametrize("size", [13, 31, 45])
def test_long_letter_digit_operand_never_looks_like_a_short_version(tmp_path, name, size):
    value = (_MIXED + _LETTERS)[: size - 3] + "123"
    source = {"command": "node", "args": [name + "=Bearer", value]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(value)})
    assert has_exposure(result)
    assert all(value not in output for output in exports(inventory))


@pytest.mark.parametrize("value", ["20250618", "Workspace2", "StageView123"])
@pytest.mark.parametrize("name", ["--auth", "--auth-mode"])
def test_short_label_needs_a_mode_name_to_remain_public(tmp_path, name, value):
    source = {"command": "node", "args": [name + "=Bearer", value]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(value)})
    assert has_exposure(result) is (name == "--auth")
    assert all((value in output) is (name == "--auth-mode") for output in exports(inventory))


@pytest.mark.parametrize("binding", ["--auth", "--authentication", "API_TOKEN"])
def test_compound_flag_shape_does_not_clear_a_named_binding(tmp_path, binding):
    value = "--" + _LETTERS[:6] + "-" + _LETTERS[6:18]
    source = {"command": "node", "args": [binding + "=Bearer", value]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(value)})
    assert has_exposure(result)
    assert all(value not in output for output in exports(inventory))
