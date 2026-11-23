"""Check that a credential binding takes precedence over a public-looking operand."""

import hashlib

import pytest

from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

_DIGEST = hashlib.sha256(b"generated operand for inventory comparison").hexdigest()
_LETTERS = "".join(chr(97 + int(nibble, 16)) for nibble in _DIGEST)
_MIXED = _LETTERS[:4] + _LETTERS[4:8].upper() + _LETTERS[8:12]


@pytest.mark.parametrize("binding", ["API_TOKEN", "AUTHORIZATION", "API_KEY"])
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


@pytest.mark.parametrize(
    "operand",
    [_LETTERS[:12], _MIXED, "--" + _LETTERS[:10], "--" + _MIXED, "--" + _LETTERS[:10].upper()],
)
def test_cmd_set_auth_type_withholds_all_operands(tmp_path, operand):
    source = {"command": "cmd", "args": ["/c", f"set AUTH_TYPE=Bearer {operand}&& node notes.js"]}
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


@pytest.mark.parametrize("value", ["20250618", "Workspace2", "OpenAPI3"])
@pytest.mark.parametrize("name", ["--api-token", "--auth", "--auth-mode"])
def test_short_label_needs_a_mode_name_to_remain_public(tmp_path, name, value):
    source = {"command": "node", "args": [name + "=Bearer", value]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(value)})
    assert has_exposure(result) is (name == "--api-token")
    assert all((value in output) is (name != "--api-token") for output in exports(inventory))


@pytest.mark.parametrize("binding", ["--api-token", "--authorization", "API_TOKEN"])
def test_compound_flag_shape_does_not_clear_a_named_binding(tmp_path, binding):
    value = "--" + _LETTERS[:6] + "-" + _LETTERS[6:18]
    source = {"command": "node", "args": [binding + "=Bearer", value]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(value)})
    assert has_exposure(result)
    assert all(value not in output for output in exports(inventory))


@pytest.mark.parametrize(
    ("selector", "following"),
    [
        ("--auth-type=bearer", "--allowWrite"),
        ("--auth-header=bearer", "--no-cache"),
        ("--auth=token", "readonly"),
        ("--auth-type=bearer", "--persistent"),
        ("--auth-type=bearer", "--incognito"),
        ("--auth-type=bearer", "--no-sandbox"),
        ("--auth-type=bearer", "--workspace-root"),
        ("--auth-type=bearer", "required"),
        ("--auth-type=bearer", "workspace"),
        ("--auth-type=bearer", "Production"),
    ],
)
def test_selector_flags_do_not_raise_false_highs_on_cli_switches_or_words(
    tmp_path, selector, following
):
    source = {"command": "npx", "args": ["@example/mcp-server@1.0.0", selector, following]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(following)})
    assert not has_exposure(result)
    assert all(following in output for output in exports(inventory))


@pytest.mark.parametrize(
    ("selector", "token"),
    [
        ("--auth-type=bearer", _MIXED[:8] + "50"),
        ("--auth-type=bearer", _LETTERS[:4].capitalize() + _LETTERS[4:8].upper() + "526"),
        ("--auth-type=bearer", "--" + _LETTERS[:6] + "123" + _LETTERS[6:11]),
        ("--auth-type=bearer", "--" + _LETTERS[:4] + "12-" + _LETTERS[4:8] + "34"),
        ("--auth=Token", "91575382"),
        ("--auth=Bearer", _LETTERS[:32] + _LETTERS[:8]),
    ],
)
def test_selector_still_withholds_credential_shaped_short_and_dash_tokens(
    tmp_path, selector, token
):
    source = {"command": "node", "args": [selector, token]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(token)})
    assert has_exposure(result)
    assert all(token not in output for output in exports(inventory))
