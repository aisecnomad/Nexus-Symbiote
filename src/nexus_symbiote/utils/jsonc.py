"""JSON with comments and trailing commas (JSONC), as editors read settings files.

One reader for every collector: VS Code, Cursor and Gemini CLI settings and MCP
client files are all read with it.
"""

from __future__ import annotations

import re
from collections.abc import Callable

_JSONC_EVENT = re.compile(r'"|//|/\*|[,\]}\[{:]')
_JSON_STRING = re.compile(r'"(?:[^"\\]|\\.)*"', re.DOTALL)


def strip_jsonc(text: str, *, on_string: Callable[[int, int], None] | None = None) -> str:
    """Remove comments and trailing commas outside strings in one linear pass.

    Readers disagree about where a line comment ends: VS Code also ends one at a
    lone carriage return and at U+2028 or U+2029, other JSONC readers only at a
    line feed. Text that depends on the difference is rejected, never guessed.
    An optional callback receives original character ranges of string tokens.
    """
    if "\u2028" in text or "\u2029" in text:
        raise ValueError("line or paragraph separator")
    parts: list[str] = []
    position = 0
    comma = -1
    can_trail = False
    while (event := _JSONC_EVENT.search(text, position)) is not None:
        start = event.start()
        if text[position:start].strip():
            comma = -1
            can_trail = True
        parts.append(text[position:start])
        mark = event.group()
        if mark == '"':
            string = _JSON_STRING.match(text, start)
            if string is None:
                raise ValueError("unterminated string")
            if on_string is not None:
                on_string(start, string.end())
            parts.append(string.group())
            comma, can_trail, position = -1, True, string.end()
        elif mark == "//":
            newline = text.find("\n", start)
            position = len(text) if newline < 0 else newline
            if "\r" in text[start:position].removesuffix("\r"):
                raise ValueError("carriage return inside a line comment")
        elif mark == "/*":
            close = text.find("*/", start + 2)
            if close < 0:
                raise ValueError("unterminated comment")
            parts.append(" ")
            position = close + 2
        elif mark in "[{:":
            parts.append(mark)
            comma, can_trail, position = -1, False, start + 1
        elif mark == ",":
            parts.append(",")
            comma = len(parts) - 1 if can_trail else -1
            can_trail = False
            position = start + 1
        else:
            if comma >= 0:
                parts[comma] = ""
            parts.append(mark)
            comma, can_trail, position = -1, True, start + 1
    parts.append(text[position:])
    return "".join(parts)
