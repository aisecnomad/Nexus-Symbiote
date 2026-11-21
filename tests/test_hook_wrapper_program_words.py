"""Static hook parser checks. The sample programs and arguments are never executed."""

import base64

import pytest

from nexus_symbiote.scanners import ide_agents


@pytest.mark.parametrize(
    "wrapper",
    [
        ["command"],
        ["exec", "--"],
        ["nohup"],
        ["timeout", "5"],
        ["sudo", "--"],
        ["busybox", "--"],
        ["MODE=preview", "command"],
        ["env", "MODE=preview", "nohup"],
    ],
)
@pytest.mark.parametrize("word", ["FORMAT=/fixture/formatter", "FORMAT+=/fixture/formatter"])
def test_wrapper_preserves_assignment_shaped_program_word(wrapper, word):
    words = [*wrapper, word, "argument"]
    assert ide_agents._executable_index(words) == len(wrapper)


@pytest.mark.parametrize(
    "prefix",
    [
        ["MODE=preview"],
        ["!", "MODE=preview"],
        ["time", "-p", "MODE=preview"],
        ["{", "MODE=preview"],
        ["env", "--", "MODE=preview"],
    ],
)
def test_shell_and_env_consume_their_own_assignment_prefix(prefix):
    assert ide_agents._executable_index([*prefix, "formatter"]) == len(prefix)


@pytest.mark.parametrize(
    "command",
    [
        "$SED -e s/TODO/DONE/ notes.md",
        "${GREP:-grep} -rn -e PASSWORD src",
        "$FILTER -E Makefile",
        "$FILTER -ec Version1",
    ],
)
def test_ordinary_arguments_are_not_encoded_commands(command):
    assert not ide_agents._encoded_powershell(command)


def test_encoded_text_and_a_program_name_hint_are_recognized():
    payload = base64.b64encode("Write-Output 'café'".encode("utf-16-le")).decode("ascii")
    assert ide_agents._encoded_powershell("$READER -e " + payload)
    assert ide_agents._encoded_powershell("pwsh -e Makefile")


@pytest.mark.parametrize("script", ["1", "42", "\ufeffπ"])
def test_short_or_bom_marked_encoded_text_is_recognized(script):
    payload = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    assert ide_agents._encoded_powershell("$READER -e " + payload)
