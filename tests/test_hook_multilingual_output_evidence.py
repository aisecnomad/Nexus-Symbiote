"""Classify inert multilingual expression declarations without executing them."""

import base64
import hashlib

import pytest

from nexus_symbiote.scanners.ide_agents import _encoded_payload
from tests.test_hook_wrapper_environment_and_text import _gate


def _encoded(text):
    return base64.b64encode(text.encode("utf-16-le")).decode("ascii")


@pytest.mark.parametrize("note", ["日本語の記録", "Обычная запись", "ملاحظات عامة"])
@pytest.mark.parametrize("size", [16, 96])
@pytest.mark.parametrize(
    "form",
    [
        lambda note: "(1 + 2 + 3) # " + note,
        lambda note: "# " + note + "\n(1 + 2 + 3)",
        lambda note: "('" + note + "').Length + 1",
        lambda note: "& { Write-Output '" + note + "' }",
    ],
)
def test_local_text_evidence_survives_multilingual_content(tmp_path, note, size, form):
    operand = _encoded(form(note * size))
    assert _encoded_payload(operand)
    result = _gate(tmp_path, "$VIEWER -e '" + operand + "'")
    assert result.exit_code == 1, result.output


@pytest.mark.parametrize("suffix", [8, 12, 24, 32])
def test_binary_with_a_single_accidental_ascii_unit_is_not_script_evidence(suffix):
    digest = hashlib.sha256(b"ordinary document digest").digest()
    raw = digest[:suffix] + "X".encode("utf-16-le") + digest[:suffix]
    assert not _encoded_payload(base64.b64encode(raw).decode("ascii"))
