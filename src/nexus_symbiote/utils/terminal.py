"""Render untrusted text as one inert line of terminal output."""

from __future__ import annotations

import unicodedata

# Controls (Cc) move the cursor, rewrite earlier output or break the line; in CI a
# line that starts with "::" is a workflow command. Format characters (Cf), such as
# bidirectional overrides, zero-width and tag characters, disguise text. Line and
# paragraph separators (Zl, Zp) end a line, and lone surrogates (Cs) from undecodable
# file names cannot be encoded for output. Tab is kept; it cannot start a new line.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Cs", "Zl", "Zp"})
# Hangul fillers and the combining grapheme joiner render as nothing but are not Cf.
_INVISIBLE = frozenset("\u034f\u115f\u1160\u3164\uffa0")


def one_line(value: object) -> str:
    """Replace every control, line-break, format and invisible filler character."""
    return "".join(
        "\ufffd"
        if character != "\t"
        and (unicodedata.category(character) in _UNSAFE_CATEGORIES or character in _INVISIBLE)
        else character
        for character in str(value)
    )
