"""Check static handling of public launch syntax and synthetic value boundaries."""

import hashlib

import pytest

from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

_LABEL = hashlib.sha256(b"ordinary offline unit test").hexdigest()
_NUMBER = str(77_000_000 + int(_LABEL[:4], 16))


@pytest.mark.parametrize("name", ["AUTH_TYPE", "MODE", "X_CONFIG"])
@pytest.mark.parametrize("layout", ["assignment", "cmd"])
def test_eight_digit_value_without_a_calendar_interpretation_stays_private(tmp_path, name, layout):
    if layout == "cmd":
        command, args = "cmd", ["/c", f"set {name}=Bearer {_NUMBER}"]
    else:
        command, args = "node", [name + "=Bearer", _NUMBER]
    result, inventory = _scan(
        tmp_path, {"source": {"command": command, "args": args}, "notes": _echo(_NUMBER)}
    )
    assert has_exposure(result)
    assert all(_NUMBER not in text for text in exports(inventory))


@pytest.mark.parametrize("selector", ["AUTH_TYPE", "MODE", "X_CONFIG"])
@pytest.mark.parametrize("label", ["FieldNotes2", "--headless", "--no-cache"])
def test_cmd_set_keeps_the_rest_of_its_assignment_private(tmp_path, selector, label):
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "cmd", "args": ["/c", f"set {selector}=Bearer {label}"]},
            "notes": _echo(label),
        },
    )
    assert has_exposure(result)
    assert all(label not in text for text in exports(inventory))


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("cmd.exe", ["/C", "SET", "MODE=Bearer", "--headless"]),
        (r"C:\Windows\System32\cmd.exe", ["/k", "@set MODE=Bearer --headless"]),
    ],
)
@pytest.mark.parametrize("refused", [False, True])
def test_windows_shell_identifies_set_from_its_launch(tmp_path, command, args, refused):
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": command, "args": [*args, *([None] if refused else [])]},
            "notes": _echo("--headless"),
        },
    )
    if refused:
        assert result.scan_failures
    else:
        assert has_exposure(result)
    assert all("--headless" not in text for text in exports(inventory))


@pytest.mark.parametrize(
    ("command", "args"),
    [
        ("node", ["set", "MODE=Bearer", "--headless"]),
        ("cmd", ["/c", "node notes.js set MODE=Bearer --headless"]),
        ("sh", ["-c", "node notes.js set MODE=Bearer --headless"]),
    ],
)
def test_ordinary_program_argument_named_set_does_not_report_credential(tmp_path, command, args):
    result, inventory = _scan(
        tmp_path, {"source": {"command": command, "args": args}, "notes": _echo("--headless")}
    )
    assert not has_exposure(result)
    if command == "node":
        assert all("--headless" in text for text in exports(inventory))
