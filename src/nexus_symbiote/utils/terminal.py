"""Render untrusted text as one inert line of terminal output."""

from __future__ import annotations

import re
import sys
import unicodedata
from typing import Any, TextIO

# Controls (Cc) move the cursor, rewrite earlier output or break the line; in CI a
# line that starts with "::" is a workflow command. Format characters (Cf), such as
# bidirectional overrides, zero-width and tag characters, disguise text. Line and
# paragraph separators (Zl, Zp) end a line, and lone surrogates (Cs) from undecodable
# file names cannot be encoded for output. Tab is kept; it cannot start a new line.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
# Hangul fillers and the combining grapheme joiner render as nothing but are not Cf.
_INVISIBLE = frozenset("\u034f\u115f\u1160\u3164\uffa0")


# The GitHub Actions runner also parses the legacy "##[command]" syntax anywhere
# in a line, not only at its start. Rich drops an escaping backslash before "[",
# so "##" followed by backslashes and "[" can render as the command as well.
_LEGACY_COMMAND = "##["
_LEGACY_COMMAND_SOURCE = re.compile(r"##(?=\\*\[)")


def one_line(value: object) -> str:
    """Replace every control, line-break, format and invisible filler character."""
    text = "".join(
        "\ufffd"
        if character != "\t"
        and (unicodedata.category(character) in _UNSAFE_CATEGORIES or character in _INVISIBLE)
        else character
        for character in str(value)
    )
    return _LEGACY_COMMAND_SOURCE.sub("##\ufffd", text)


def inert_json(text: str) -> str:
    """Remove workflow-command syntax from serialized JSON without changing its data.

    "##[" can only occur inside a JSON string, where the escape for "[" decodes to
    the same value. Indented JSON lines start with whitespace and a quote or bracket,
    so no line can start with "::".
    """
    return text.replace(_LEGACY_COMMAND, "##\\u005b")


class InertStream:
    """Write to the current stdout or stderr without emitting "##[" in rendered text.

    Rich renders markup before writing, so this catches the command syntax however a
    rendered line was assembled. The stream is looked up at each write, so a test
    runner or a redirect that replaces sys.stderr keeps working.
    """

    def __init__(self, name: str) -> None:
        self._name = name

    @property
    def _stream(self) -> TextIO:
        stream: TextIO = getattr(sys, self._name)
        return stream

    def write(self, text: str) -> int:
        self._stream.write(text.replace(_LEGACY_COMMAND, "##\ufffd["))
        return len(text)

    def __getattr__(self, name: str) -> Any:
        return getattr(self._stream, name)
