"""Pre-parse structural bounds for untrusted, size-bounded TOML text."""

from __future__ import annotations

import re
import tomllib
from collections.abc import Callable
from typing import Any

# tomllib retains every dotted-key prefix, making allocation quadratic in its parts,
# and recurses on nested inline tables and arrays. Fixed bounds keep pre-parse
# verification strictly linear in the bounded source size.
_MAX_DOTTED_KEY = 16
_MAX_BRACKET_DEPTH = 64


class TOMLBoundsError(ValueError):
    """The input exceeds the structural bounds before parsing."""


_TOML_SPECIAL = re.compile(r"""[#"'.=,{}\[\]\n]""")
_TOML_STOPS = {
    ('"', False): re.compile(r'["\\\n]'),
    ("'", False): re.compile(r"['\n]"),
    ('"', True): re.compile(r'["\\]'),
    ("'", True): re.compile(r"'"),
}


def _toml_string_end(text: str, position: int, quote_char: str) -> int:
    """Where a TOML string that opened just before position ends.

    A basic string skips the character after a backslash. A multi-line string ends
    at the last three quotes of the first run of three or more, since up to two
    may end its content; a single-line one also ends at a line break.
    """
    multiline = text.startswith(quote_char * 2, position)
    if multiline:
        position += 2
    stops = _TOML_STOPS[quote_char, multiline]
    while True:
        found = stops.search(text, position)
        if found is None:
            return len(text)
        if found.group() == "\\":
            position = found.end() + 1
            continue
        if found.group() == "\n":
            return found.start()
        if not multiline:
            return found.end()
        run = found.end()
        while run < len(text) and text[run] == quote_char:
            run += 1
        if run - found.start() >= 3:
            return run
        position = run


def _scan_toml_bounds(
    text: str, on_string: Callable[[int, int], None] | None = None
) -> tuple[int, int]:
    """Return ``(longest_dotted_key, max_bracket_depth)`` outside strings and comments
    in one linear pass.

    A string is skipped without ending a dotted-key count, since a quoted part such as
    "" or 'a' is still one part of a dotted key.
    """
    longest = dots = depth = max_depth = 0
    position = 0
    while True:
        found = _TOML_SPECIAL.search(text, position)
        if found is None:
            return max(longest, dots), max_depth
        char, position = found.group(), found.end()
        if char == ".":
            dots += 1
        elif char in "\"'":
            position = _toml_string_end(text, position, char)
            if on_string is not None:
                on_string(found.start(), position)
        else:
            longest, dots = max(longest, dots), 0
            if char == "#":
                newline = text.find("\n", position)
                position = len(text) if newline < 0 else newline
            elif char in "[{":
                depth += 1
                if depth > max_depth:
                    max_depth = depth
            elif char in "]}" and depth > 0:
                depth -= 1


def _longest_dotted_key(text: str, on_string: Callable[[int, int], None] | None = None) -> int:
    return _scan_toml_bounds(text, on_string)[0]


def loads(
    text: str,
    *,
    parse_float: Callable[[str], Any] = float,
    on_string: Callable[[int, int], None] | None = None,
) -> dict[str, Any]:
    """Parse TOML only after bounding dotted keys and bracket/brace nesting depth.

    ``parse_float`` is passed to ``tomllib``, so a caller can refuse nonfinite numbers.
    """
    longest_dotted, max_depth = _scan_toml_bounds(text, on_string)
    if longest_dotted > _MAX_DOTTED_KEY:
        raise TOMLBoundsError("dotted key exceeds the length limit")
    if max_depth > _MAX_BRACKET_DEPTH:
        raise TOMLBoundsError("TOML nesting exceeds the depth limit")
    return tomllib.loads(text, parse_float=parse_float)
