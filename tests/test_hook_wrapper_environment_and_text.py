"""Audit inert wrapper declarations and printable output expressions without running hooks."""

import base64
import json

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners import ide_agents


def _encode(data):
    return base64.b64encode(data).decode("ascii")


def _gate(tmp_path, command):
    folder = tmp_path / ".claude"
    folder.mkdir()
    (folder / "settings.json").write_text(
        json.dumps(
            {"hooks": {"PostToolUse": [{"hooks": [{"type": "command", "command": command}]}]}}
        )
    )
    return CliRunner().invoke(main, ["scan", str(tmp_path), "--no-project-policy", "--check"])


@pytest.mark.parametrize("prefix", [["env"], ["env", "-i"], ["sudo", "-n"], ["busybox", "env"]])
@pytest.mark.parametrize("setting", ["LABEL+=one", "LABEL-OTHER=two"])
def test_wrapper_environment_assignment_preserves_the_benign_program_at_the_gate(
    tmp_path, prefix, setting
):
    encoded = _encode("Write-Output sample".encode("utf-16-le"))
    words = [*prefix, setting, "$VIEWER", "-e", encoded]
    assert ide_agents._executable_index(words) == len(prefix) + 1
    result = _gate(tmp_path, " ".join(words))
    assert result.exit_code == 1, result.output
    assert "critical" in result.output.lower()


@pytest.mark.parametrize(
    ("words", "program"),
    [
        (["env", "--", "-LABEL=sample", "echo"], "echo"),
        (["env", "LABEL=sample", "-SECOND=sample", "echo"], "echo"),
        (["sudo", "--", "LABEL+=sample", "echo"], "LABEL+=sample"),
        (["doas", "LABEL+=sample", "echo"], "LABEL+=sample"),
        (["doas", "LABEL=sample", "echo"], "LABEL=sample"),
        (["command", "LABEL+=sample", "echo"], "LABEL+=sample"),
        (["env", "=sample", "echo"], "=sample"),
    ],
)
def test_wrapper_end_of_options_and_literal_program_operands(words, program):
    assert words[ide_agents._executable_index(words)] == program


@pytest.mark.parametrize(
    "tail",
    [
        "\u200b".encode("utf-16-le"),
        "\u00a0".encode("utf-16-le"),
        "\u2028".encode("utf-16-le"),
        "\f".encode("utf-16-le"),
        "\0".encode("utf-16-le"),
        b"\x00\xd8",
        b"\x41",
    ],
)
def test_declarative_encoded_text_with_an_unusual_code_unit_reaches_the_gate(tmp_path, tail):
    text = "Write-Output sample # note".encode("utf-16-le") + tail
    result = _gate(tmp_path, "$VIEWER -e " + _encode(text))
    assert result.exit_code == 1, result.output
    assert "critical" in result.output.lower()


@pytest.mark.parametrize("space", [" ", "\t", "\r", "\n"])
def test_quoted_base64_whitespace_is_part_of_one_operand(tmp_path, space):
    token = _encode("Write-Output sample".encode("utf-16-le"))
    wrapped = token[:3] + space + token[3:]
    result = _gate(tmp_path, "$VIEWER -ec '" + wrapped + "'")
    assert result.exit_code == 1, result.output
    assert "critical" in result.output.lower()


@pytest.mark.parametrize("value", ["Makefile", "Version1", "sample", "ab%cd", "AAAA"])
def test_benign_option_arguments_lack_encoded_script_evidence(tmp_path, value):
    result = _gate(tmp_path, "$FILTER -e " + value)
    assert result.exit_code == 0, result.output
