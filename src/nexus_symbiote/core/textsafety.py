"""Find characters that can hide, reorder or smuggle text past a reviewer."""

from __future__ import annotations

import re
import unicodedata
from typing import Literal

HiddenKind = Literal["bidi", "tag", "invisible"]

# Embeddings, overrides and isolates reorder displayed text ("Trojan Source").
_BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")
# Default-ignorable code points outside the Cc and Cf categories also render as nothing.
_IGNORABLE = frozenset("\u034f\u115f\u1160\u17b4\u17b5\u2065\u3164\uffa0")
# Joiners and variation selectors are normal in emoji and other scripts, so their
# position decides whether they hide anything.
_CONTEXTUAL = re.compile("[\u200d\u180b-\u180d\u180f\ufe00-\ufe0f\U000e0100-\U000e01ef]")
_NOT_A_BASE = frozenset({"Cc", "Cf", "Zs", "Zl", "Zp"})
_ASCII_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ZWJ = "\u200d"
_VS16 = "\ufe0f"


def _context_free_kind(char: str) -> HiddenKind | None:
    code = ord(char)
    if char in _BIDI_CONTROLS:
        return "bidi"
    if 0xE0000 <= code <= 0xE007F:
        return "tag"
    if _CONTEXTUAL.match(char) or char in "\t\n\r":
        return None
    if (
        unicodedata.category(char) in ("Cc", "Cf")
        or char in _IGNORABLE
        or 0xFFF0 <= code <= 0xFFF8
        or 0xE0080 <= code <= 0xE0FFF
    ):
        return "invisible"
    return None


def _pictographic(char: str) -> bool:
    code = ord(char)
    return 0x1F000 <= code <= 0x1FFFD or (
        0x7F < code <= 0xFFFF and unicodedata.category(char) in ("So", "Sm")
    )


def _normal_in_context(text: str, index: int) -> bool:
    previous = text[index - 1] if index else ""
    if text[index] == _ZWJ:
        if previous == _VS16 and index > 1:
            previous = text[index - 2]
        following = text[index + 1 : index + 2]
        return bool(previous and following) and _pictographic(previous) and _pictographic(following)
    # A selector picks a variant of the character before it. A run of selectors, or
    # one with nothing to modify, can encode arbitrary bytes.
    return (
        bool(previous)
        and not _CONTEXTUAL.match(previous)
        and unicodedata.category(previous) not in _NOT_A_BASE
    )


def _hidden_in_text(text: str) -> set[HiddenKind]:
    if text.isascii():
        return {"invisible"} if _ASCII_CONTROLS.search(text) else set()
    kinds = {kind for char in set(text) if (kind := _context_free_kind(char)) is not None}
    if any(not _normal_in_context(text, m.start()) for m in _CONTEXTUAL.finditer(text)):
        kinds.add("invisible")
    return kinds


def hidden_character_kinds(value: object) -> set[HiddenKind]:
    """Classify hidden characters in a string or in every key and string of a JSON value.

    Bidirectional controls and tag characters have their own kinds. Other format,
    control and default-ignorable characters are "invisible", except tab and line
    breaks, a zero-width joiner between emoji, and a single variation selector after
    a visible character.
    """
    kinds: set[HiddenKind] = set()
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            kinds |= _hidden_in_text(item)
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)
    return kinds
