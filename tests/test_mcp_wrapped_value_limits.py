"""Opaque credential arguments and bounded searches for publicly generated sample values."""

import base64
import hashlib
import json
import textwrap

import pytest

from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.scanners import mcp, mcp_credentials
from nexus_symbiote.scanners.mcp_credentials import rewrapped_key_literals
from tests.test_mcp_redaction_boundaries import _echo, _scan


@pytest.mark.parametrize("padding", ["", "=", "=="])
def test_option_shaped_scheme_value_is_withheld_in_every_inventory(tmp_path, padding):
    digest = hashlib.sha256(b"public option-shaped test marker").hexdigest()
    marker = "--Q" + digest[:31] + padding
    source = {"command": "sh", "args": ["-c", "node local.js --env=API_TOKEN=Bearer " + marker]}
    result, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(marker)})
    assert any(
        r.category == "credential_exposure" and r.severity == "high"
        for component in result.components
        for r in component.risks
    )
    for exported in (
        inventory.to_json(),
        json.dumps(CycloneDXGenerator().generate(inventory)),
        json.dumps(SPDXGenerator().generate(inventory)),
    ):
        assert digest[:31] not in exported


@pytest.mark.parametrize("flag", ["--port=8080", "--enable-automatic-updates=", "--debug"])
def test_real_options_remain_public_after_a_scheme(flag):
    assert not mcp._assignment_word_hits("API_TOKEN=Bearer", flag)


def test_rewrapping_is_skipped_for_an_already_refused_file(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp, "MAX_SECRETS_PER_FILE", 2)

    def unexpected(*_args):
        raise AssertionError("expanded a file already over its value limit")

    monkeypatch.setattr(mcp, "rewrapped_key_literals", unexpected)
    markers = {f"API_TOKEN_{n}": hashlib.sha256(str(n).encode()).hexdigest() for n in range(4)}
    result, inventory = _scan(tmp_path, {"demo": {"command": "node", "env": markers}})
    assert any("more than 2 credential values" in failure for failure in result.scan_failures)
    assert all(value not in inventory.to_json() for value in markers.values())


@pytest.mark.parametrize("separator", ["\r\n", "\u00a0", "\u2028", "\u200b"])
def test_differently_wrapped_known_public_value_is_recognized(separator):
    samples = [
        base64.b64encode(
            json.dumps({"private_key": "public example " + str(i) * 35}).encode()
        ).decode()
        for i in range(22)
    ]
    wrapped = separator.join(textwrap.wrap(samples[-1], 13))
    document = {"description": "Fixture: " + wrapped + " / end", "other": ["ordinary prose"] * 10}
    assert wrapped in set(rewrapped_key_literals(document, samples))


def test_incomplete_wrapping_search_withholds_the_file(tmp_path, monkeypatch):
    monkeypatch.setattr(mcp_credentials, "_WRAP_COMPARISON_FACTOR", 0)
    public = json.dumps({"private_key": "publicly documented schema example"})
    encoded = base64.b64encode(public.encode()).decode()
    wrapped = "\n".join(textwrap.wrap(encoded, 17))
    result, inventory = _scan(
        tmp_path,
        {"source": {"command": "node", "env": {"CONFIG": encoded}}, "copy": _echo(wrapped)},
    )
    assert any("wrapped credential comparison limit reached" in f for f in result.scan_failures)
    assert all(component.name != "copy" for component in inventory.components)
