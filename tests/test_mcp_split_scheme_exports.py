"""Keep synthetic split authentication values out of serialized inventories."""

import base64
import hashlib
import json

import pytest

from nexus_symbiote.generators.sarif import SARIFGenerator
from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

DIGEST = hashlib.sha256(b"generated inventory privacy control").digest()
PADDED = base64.b64encode(DIGEST[:16]).decode("ascii")
BASIC = base64.b64encode(b"fixture:" + DIGEST.hex()[:8].encode("ascii")).decode("ascii")
DIGITS = str(int.from_bytes(DIGEST[:9]))
LETTERS = "".join(chr(97 + n % 26) for n in DIGEST[:22])


def _arguments(assignment, operand, layout):
    if layout == "array":
        return "node", [assignment, operand]
    if layout == "shell":
        return "sh", ["-c", "node notes.js " + assignment + " " + operand]
    return "cmd", ["/c", "set " + assignment.removeprefix("--env=") + " " + operand]


@pytest.mark.parametrize("layout", ["array", "shell", "cmd"])
@pytest.mark.parametrize(
    ("assignment", "marker"),
    [
        ("--env=API_TOKEN=Bearer", PADDED),
        ("--env=MODE=Bearer", PADDED),
        ("--env=API_TOKEN=Basic", BASIC),
        ("--env=TOKEN_SOURCE=Basic", PADDED),
        ("--env=AUTH_PROFILE=Basic", DIGEST.hex()[:29]),
        ("--env=TOKEN_SOURCE=Token", DIGEST.hex()[:24]),
        ("--env=AUTH_OUTPUT=Token", DIGITS),
        ("--env=AUTH_TYPE=Bearer", DIGITS),
        ("--env=X_CONFIG=ApiKey", "--" + LETTERS),
        ("--env=MODE=Bot", "--" + LETTERS[:7] + "_" + LETTERS[7:]),
    ],
)
def test_assignment_redacts_sibling_exports_for_each_layout(tmp_path, assignment, marker, layout):
    command, args = _arguments(assignment, marker, layout)
    result, inventory = _scan(
        tmp_path, {"source": {"command": command, "args": args}, "sibling": _echo(marker)}
    )
    assert has_exposure(result)
    documents = (*exports(inventory), json.dumps(SARIFGenerator().generate(inventory)))
    assert all(marker not in document for document in documents)


@pytest.mark.parametrize("assignment", ["--auth-type=bearer", "AUTH=bearer", "SESSION=token"])
@pytest.mark.parametrize(
    "flag", ["--Verbose", "--readOnly", "--dry_run", "--transport", "--version", "--debug"]
)
def test_public_switches_remain_usable_after_a_scheme(tmp_path, assignment, flag):
    result, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "args": [assignment, flag, "stdio"]},
            "sibling": _echo(flag),
        },
    )
    assert not has_exposure(result)
    assert all(flag in document for document in exports(inventory))
