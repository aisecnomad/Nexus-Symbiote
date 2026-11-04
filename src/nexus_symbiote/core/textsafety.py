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
_ASCII_CONTROLS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_ZWJ = "\u200d"
_VS16 = "\ufe0f"
_KEYCAP = "\u20e3"
# The characters below U+10000 that have emoji variation sequences
# (emoji-variation-sequences.txt). Since Unicode 17.0 they are also exactly the
# Extended_Pictographic characters there.
_BMP_EMOJI = re.compile(
    "[\xa9\xae\u203c\u2049\u2122\u2139\u2194-\u2199\u21a9\u21aa\u231a\u231b\u2328\u23cf"
    "\u23e9-\u23f3\u23f8-\u23fa\u24c2\u25aa\u25ab\u25b6\u25c0\u25fb-\u25fe\u2600-\u2604"
    "\u260e\u2611\u2614\u2615\u2618\u261d\u2620\u2622\u2623\u2626\u262a\u262e\u262f"
    "\u2638-\u263a\u2640\u2642\u2648-\u2653\u265f\u2660\u2663\u2665\u2666\u2668\u267b"
    "\u267e\u267f\u2692-\u2697\u2699\u269b\u269c\u26a0\u26a1\u26a7\u26aa\u26ab"
    "\u26b0\u26b1\u26bd\u26be\u26c4\u26c5\u26c8\u26ce\u26cf\u26d1\u26d3\u26d4\u26e9\u26ea"
    "\u26f0-\u26f5\u26f7-\u26fa\u26fd\u2702\u2705\u2708-\u270d\u270f\u2712\u2714\u2716"
    "\u271d\u2721\u2728\u2733\u2734\u2744\u2747\u274c\u274e\u2753-\u2755\u2757"
    "\u2763\u2764\u2795-\u2797\u27a1\u27b0\u27bf\u2934\u2935\u2b05-\u2b07\u2b1b\u2b1c"
    "\u2b50\u2b55\u3030\u303d\u3297\u3299]"
)
# Egyptian hieroglyph signs that render as empty space.
_EGYPTIAN_BLANKS = frozenset("\U00013441\U00013442")


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
    return 0x1F000 <= ord(char) <= 0x1FFFD or _BMP_EMOJI.match(char) is not None


def _unified_ideograph(char: str) -> bool:
    # Compatibility ideographs decompose to unified ones, except twelve that are unified.
    name = unicodedata.name(char, "")
    return name.startswith(("CJK UNIFIED IDEOGRAPH-", "CJK COMPATIBILITY IDEOGRAPH-")) and (
        not unicodedata.decomposition(char)
    )


def _defines_variant(base: str, selector: int, following: str) -> bool:
    """Whether Unicode defines variants of the base for this kind of selector.

    Anywhere else a selector changes nothing visible, so it can only carry data.
    """
    code = ord(base)
    if selector >= 0xE0100:  # ideographic variation sequences
        return _unified_ideograph(base)
    if selector <= 0x180F:  # Mongolian free variation selectors
        return 0x1820 <= code <= 0x18AA
    if selector >= 0xFE0E:  # text and emoji presentation
        if base in "#*0123456789":
            # Only a keycap sequence gives these characters an emoji form.
            return following == _KEYCAP
        return _pictographic(base)
    # Standardized variants (StandardizedVariants.txt) of compatibility ideographs,
    # hieroglyphs, mathematical operators and a few other scripts.
    if _unified_ideograph(base):
        return selector <= 0xFE02
    if 0x13000 <= code <= 0x143FF:
        return (
            selector <= 0xFE06
            and unicodedata.category(base) == "Lo"
            and base not in _EGYPTIAN_BLANKS
        )
    return selector == 0xFE00 and (
        (0x2200 <= code <= 0x2AFF and unicodedata.category(base) == "Sm")
        or unicodedata.name(base, "").startswith(("MYANMAR ", "PHAGS-PA ", "MANICHAEAN "))
    )


def _normal_in_context(text: str, index: int) -> bool:
    previous = text[index - 1] if index else ""
    following = text[index + 1 : index + 2]
    if text[index] == _ZWJ:
        if previous == _VS16 and index > 1:
            previous = text[index - 2]
        return bool(previous and following) and _pictographic(previous) and _pictographic(following)
    # A selector picks a variant of the character before it, so a run of selectors can
    # only carry data.
    if not previous or _CONTEXTUAL.match(previous):
        return False
    return _defines_variant(previous, ord(text[index]), following)


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
    breaks, a zero-width joiner between emoji, and a single variation selector after a
    character that has variants of that kind: emoji and keycap sequences, CJK
    ideographs, Mongolian letters, and the standardized variants of mathematical
    operators, Egyptian hieroglyphs and the Myanmar, Phags-pa and Manichaean scripts.
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
