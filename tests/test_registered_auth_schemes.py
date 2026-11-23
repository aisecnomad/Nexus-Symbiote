"""The registered HTTP authentication schemes DPoP, HOBA and Mutual hold credentials (#391)."""

import hashlib
import json

import pytest

from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.generators.spdx import SPDXGenerator
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.utils.secrets import redact_text, scheme_credentials, secret_values

DIGEST = hashlib.sha256(b"registered auth scheme fixture").digest()
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
TOKEN = "".join(ALPHABET[byte % len(ALPHABET)] for byte in DIGEST)
SCHEMES = ["DPoP", "HOBA", "Mutual", "dpop"]


@pytest.mark.parametrize("scheme", SCHEMES)
def test_the_credential_after_a_registered_scheme_is_read(scheme):
    assert scheme_credentials(f"{scheme} {TOKEN}") == [TOKEN]
    assert TOKEN in secret_values({"AUTH_HEADER": f"{scheme} {TOKEN}"})


@pytest.mark.parametrize("scheme", SCHEMES)
@pytest.mark.parametrize("header", ["Authorization", "Proxy-Authorization"])
def test_a_header_line_with_a_registered_scheme_is_redacted(scheme, header):
    assert redact_text(f"{header}: {scheme} {TOKEN}") == f"{header}: {scheme} ***"


@pytest.mark.parametrize(
    "prose",
    [
        "Mutual friends of mine recommended this library",
        "The DPoP proof binds the token to a key",
        "HOBA is an origin-bound authentication scheme",
    ],
)
def test_prose_that_names_a_scheme_is_left_alone(prose):
    assert redact_text(prose) == prose


@pytest.mark.parametrize("scheme", ["DPoP", "HOBA", "Mutual"])
def test_a_split_scheme_credential_stays_out_of_every_export(tmp_path, scheme):
    source = {"command": "cmd", "args": ["/c", f"set AUTH_HEADER={scheme} {TOKEN}&& node s.js"]}
    echo = {"command": "node", "tools": [{"name": "lookup", "description": f"Echo: {TOKEN}"}]}
    (tmp_path / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"source": source, "echo": echo}}), encoding="utf-8"
    )
    inventory = AIBOM(components=MCPScanner().scan(tmp_path).components)
    documents = (
        inventory.to_json(),
        json.dumps(CycloneDXGenerator().generate(inventory)),
        json.dumps(SPDXGenerator().generate(inventory)),
        json.dumps(SARIFGenerator().generate(inventory)),
    )
    assert all(TOKEN not in document for document in documents)
