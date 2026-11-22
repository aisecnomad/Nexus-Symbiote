"""Compare ordinary lookup patterns and inert output text in static hook manifests."""

import base64
import hashlib

import pytest

from nexus_symbiote.scanners.ide_agents import _encoded_payload
from tests.test_hook_wrapper_environment_and_text import _gate

DIGESTS = [hashlib.sha256(f"document {n}".encode()).hexdigest().upper() for n in range(72)]


@pytest.mark.parametrize("pattern", ["CONTAINS", "RACE", *DIGESTS])
def test_search_arguments_are_distinct_from_encoded_text(tmp_path, pattern):
    result = _gate(tmp_path, "${GREP:-grep} -e " + pattern + " notes.md")
    assert result.exit_code == 0, result.output


@pytest.mark.parametrize(
    "text",
    [
        "x",
        "Write-Output sample",
        "Write-Output 'пример рабочего документа'",
        "'日本語の資料'",
        "'日本語の資料'\u200b",
        "'日本語の資料'\t",
        "\ufeff日本語",
        "Write-Output an\u200bnotated",
    ],
)
def test_known_inert_unicode_text_has_encoding_evidence(tmp_path, text):
    encoded = base64.b64encode(text.encode("utf-16-le")).decode("ascii")
    assert _encoded_payload(encoded)
    result = _gate(tmp_path, "$VIEWER -e '" + encoded + "'")
    assert result.exit_code == 1, result.output


@pytest.mark.parametrize("n", range(48, 65))
def test_binary_counters_are_not_evidence_of_an_encoded_script(n):
    encoded = base64.b64encode(n.to_bytes(8, "little")).decode("ascii")
    assert not _encoded_payload(encoded)
