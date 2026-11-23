"""Check when a mode declaration is followed by an option or public version."""

import hashlib

import pytest

from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

DIGEST = hashlib.sha256(b"synthetic selector comparison").hexdigest()


@pytest.mark.parametrize(
    "setting",
    [
        "--auth-type=bearer",
        "--auth=token",
        "--auth-mode=basic",
        "--env=AUTH_TYPE=Bearer",
        "--env=MODE=Basic",
    ],
)
@pytest.mark.parametrize(
    "public",
    [
        "--headless",
        "--detached",
        "--sandboxed",
        "--production",
        "--telemetry",
        "--recursive",
        "--localhost",
        "--maxConcurrentRequests",
        "20250618",
        "Workspace2",
        "OpenAPI3",
    ],
)
def test_named_mode_keeps_public_launch_words(tmp_path, setting, public):
    result, inventory = _scan(
        tmp_path,
        {"source": {"command": "node", "args": [setting, public]}, "sibling": _echo(public)},
    )
    assert not has_exposure(result)
    assert all(public in doc for doc in exports(inventory))


@pytest.mark.parametrize("setting", ["PROFILE=token", "--env=PROFILE=token"])
def test_standalone_profile_variable_keeps_workspace_label(tmp_path, setting):
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "args": [setting, "WorkspaceV2"]},
            "sibling": _echo("WorkspaceV2"),
        },
    )
    assert not has_exposure(result)
    assert all("WorkspaceV2" in doc for doc in exports(inventory))


@pytest.mark.parametrize(
    "setting",
    [
        "--env=AUTH_PROFILE=Token",
        "--env=TOKEN_SOURCE=Bearer",
        "--api-token=Basic",
        "--auth-mode=basic",
    ],
)
@pytest.mark.parametrize(
    "private",
    [
        DIGEST[:27],
        str(int(DIGEST[:18], 16)),
        "--" + "".join(chr(97 + int(v, 16)) for v in DIGEST[:24]),
    ],
)
def test_long_generated_value_remains_private_after_a_mode(tmp_path, setting, private):
    result, inventory = _scan(
        tmp_path,
        {"source": {"command": "node", "args": [setting, private]}, "sibling": _echo(private)},
    )
    assert has_exposure(result)
    assert all(private not in doc for doc in exports(inventory))


@pytest.mark.parametrize("assignment", ["AUTH=bearer", "--env=API_TOKEN=Token"])
@pytest.mark.parametrize("option", ["--headless", "--maxConcurrentRequests"])
def test_bare_option_after_a_binding_keeps_its_identity(tmp_path, assignment, option):
    result, inventory = _scan(
        tmp_path,
        {"source": {"command": "node", "args": [assignment, option]}, "sibling": _echo(option)},
    )
    assert not has_exposure(result)
    assert all(option in doc for doc in exports(inventory))


def test_short_decimal_value_after_a_credential_binding_stays_private(tmp_path):
    value = "20250618"
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "args": ["--env=API_TOKEN=Bearer", value]},
            "sibling": _echo(value),
        },
    )
    assert has_exposure(result)
    assert all(value not in doc for doc in exports(inventory))
