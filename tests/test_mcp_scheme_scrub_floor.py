"""Withholding after ``NAME=<scheme>`` never depends on the finding rules alone.

The rules that decide whether the word after a scheme raises a finding may narrow, but a
word they leave unflagged still stays out of every export unless it is positively a public
launch word. Each withheld case here is withheld on the tree before the scheme rules were
split, so it must never reach an export again.
"""

import hashlib
import json

import pytest

from nexus_symbiote.generators.sarif import SARIFGenerator
from nexus_symbiote.scanners import mcp
from tests.test_mcp_redaction_boundaries import _echo, _scan
from tests.test_mcp_scheme_context import exports, has_exposure

DIGEST = hashlib.sha256(b"scheme scrub floor fixture").digest()
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
OPAQUE = "".join(ALPHABET[byte % len(ALPHABET)] for byte in (DIGEST + DIGEST)[:40])
LOWER = "".join(chr(97 + byte % 26) for byte in DIGEST[:10])
WEAK_PAIR = f"{LOWER[:4]}={LOWER[4:]}"


def _documents(inventory):
    return (*exports(inventory), json.dumps(SARIFGenerator().generate(inventory)))


def _withheld(tmp_path, source, marker):
    _, inventory = _scan(tmp_path, {"source": source, "sibling": _echo(marker)})
    return [document.count(marker) for document in _documents(inventory)]


@pytest.mark.parametrize(
    "source",
    [
        {"command": "cmd", "args": ["/c", f"set AUTH_TYPE=Digest {OPAQUE}&& node srv.js"]},
        {"command": "cmd", "args": ["/c", f"set HEADER=Bearer {OPAQUE}&& node srv.js"]},
        {"command": "cmd", "args": ["/c", f"set PROXY_HEADER=Negotiate {OPAQUE}&& node srv.js"]},
        {"command": "cmd", "args": ["/c", f"set X_HEADER=Digest {OPAQUE}&& node srv.js"]},
        {"command": "mcp-remote", "args": ["--env", "CUSTOM_HEADER=AWS4-HMAC-SHA256", OPAQUE]},
        {"command": "npx", "args": ["mcp-remote", "--env", "CUSTOM_HEADER=Negotiate", OPAQUE]},
    ],
    ids=["auth-type-digest", "header-bearer", "proxy-negotiate", "x-digest", "aws4", "npx"],
)
def test_opaque_word_after_any_scheme_is_withheld_whatever_the_name(tmp_path, source):
    assert _withheld(tmp_path, source, OPAQUE) == [0, 0, 0, 0]


@pytest.mark.parametrize(
    "source",
    [
        {"command": "node", "args": ["--auth=token", WEAK_PAIR]},
        {"command": "node", "args": ["--auth-type=bearer", WEAK_PAIR]},
        {"command": "sh", "args": ["-c", f"node srv.js --env=AUTH_TYPE=Bearer {WEAK_PAIR}"]},
    ],
    ids=["auth-token", "auth-type-bearer", "shell-env-flag"],
)
def test_weak_pair_after_a_mode_selector_is_withheld(tmp_path, source):
    assert _withheld(tmp_path, source, WEAK_PAIR) == [0, 0, 0, 0]


@pytest.mark.parametrize("value", ["changeme123", "test12345678"])
@pytest.mark.parametrize("assignment", ["API_TOKEN=Bearer", "--auth=token"])
def test_placeholder_after_a_scheme_is_withheld_without_a_finding(tmp_path, assignment, value):
    result, inventory = _scan(
        tmp_path,
        {"source": {"command": "node", "args": [assignment, value]}, "sibling": _echo(value)},
    )
    assert not has_exposure(result)
    assert all(value not in document for document in _documents(inventory))


@pytest.mark.parametrize(
    ("word", "binding", "kind"),
    [
        (OPAQUE, False, "credential"),
        ("--" + LOWER + LOWER, False, "credential"),
        ("changeme123", True, "unclassified"),
        ("changeme123", False, "unclassified"),
        (WEAK_PAIR, False, "unclassified"),
        ("--verbose", True, "public"),
        ("--no-http2", False, "public"),
        ("--http2-only", False, "public"),
        ("--http2-only", True, "unclassified"),
        ("PORT=8080", False, "public"),
        ("workspace", False, "public"),
        ("@example/mcp-server@1.0.0", False, "public"),
        ("@example/mcp-server@1.0.0", True, "unclassified"),
        ("./config/server.json", False, "public"),
    ],
)
def test_operand_kind_separates_public_words_from_unflagged_ones(word, binding, kind):
    assert mcp._scheme_operand_kind(word, credential_binding=binding) == kind
    # The finding rule reads the same classification, so the two cannot drift.
    assert mcp._scheme_operand(word, credential_binding=binding) is (kind == "credential")


@pytest.mark.parametrize(
    ("name", "scheme", "following", "public"),
    [
        ("auth-type", "bearer", "Workspace10", True),
        ("api-token", "bearer", "Workspace10", False),
        ("auth", "digest", "@example/mcp-server@1.0.0", True),
        ("HEADER", "Bearer", OPAQUE, False),
        ("AUTH_TYPE", "Digest", OPAQUE, False),
    ],
)
def test_only_a_positively_public_word_escapes_withholding(name, scheme, following, public):
    assert (
        mcp._public_scheme_following(name, scheme, following, variable=False, in_set=False)
        is public
    )


SPLIT_LITERALS = ["SuperSecretKey", "Summer24", "Zq4Rt8Lm2Xw9${SUFFIX}"]


@pytest.mark.parametrize("literal", SPLIT_LITERALS)
@pytest.mark.parametrize(
    "args",
    [
        ["-y", "srv@1.0.0", "HEADER=Bearer"],
        ["mcp-remote", "https://mcp.example/mcp", "--env", "CUSTOM_HEADER=AWS4-HMAC-SHA256"],
    ],
    ids=["header-variable", "env-flag-header"],
)
def test_a_header_named_operand_in_split_arguments_is_withheld(tmp_path, args, literal):
    source = {"command": "npx", "args": [*args, literal]}
    assert _withheld(tmp_path, source, literal) == [0, 0, 0, 0]


# `Summer24` reads as a mode label (`Workspace10`) after a header-mode flag, which this
# pull request keeps public by design, so only the shapes no label explains are pinned.
@pytest.mark.parametrize("literal", ["SuperSecretKey", "Zq4Rt8Lm2Xw9${SUFFIX}"])
def test_a_bare_word_after_an_auth_header_flag_is_withheld(tmp_path, literal):
    source = {"command": "node", "args": ["s.js", "--auth-header=bearer", literal]}
    assert _withheld(tmp_path, source, literal) == [0, 0, 0, 0]


@pytest.mark.parametrize("switch", ["--no-cache", "--verbose", "--readOnly"])
def test_a_switch_after_an_auth_header_flag_stays_public(tmp_path, switch):
    _, inventory = _scan(
        tmp_path,
        {
            "source": {"command": "node", "args": ["--auth-header=bearer", switch]},
            "sibling": _echo(switch),
        },
    )
    assert all(switch in document for document in exports(inventory))
