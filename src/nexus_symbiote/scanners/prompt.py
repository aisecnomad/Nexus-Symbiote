"""System prompt, instruction file, rule file, and skill definition scanner."""

from __future__ import annotations

import bisect
import codecs
import hashlib
import re
import sys
import unicodedata
from collections import deque
from collections.abc import Collection
from pathlib import Path, PurePosixPath
from typing import Any

from nexus_symbiote import limits
from nexus_symbiote.core.enums import RiskSeverity, TrustTier
from nexus_symbiote.core.hashing import hash_bytes
from nexus_symbiote.core.models import (
    UNBOUND_VALUES_DETAIL,
    PromptComponent,
    RiskAssessment,
    SkillPackageComponent,
)
from nexus_symbiote.scanner_catalog import INSTRUCTION_DIRECTORIES, SKILL_DIRECTORIES
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.credential_files import MARKDOWN_SUFFIXES as _MARKUP_SUFFIXES
from nexus_symbiote.scanners.credential_files import credential_gap as _credential_gap
from nexus_symbiote.scanners.credential_files import credential_shaped as _credential_shaped
from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV
from nexus_symbiote.scanners.mcp_sources import SOURCE_SEARCH_SKIPPED
from nexus_symbiote.scanners.source_binding import BindingError, value_binding
from nexus_symbiote.utils.confined import CollectionError, ConfinedCollection, fold_name
from nexus_symbiote.utils.markdown import (
    front_matter_candidates,
    hidden_text,
    text_outside_code,
)
from nexus_symbiote.utils.terminal import neutralize
from nexus_symbiote.utils.toml import loads as toml_loads

INVISIBLE_CHARS: dict[str, str] = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u2060": "WORD JOINER",
    "\u00ad": "SOFT HYPHEN",
}

BIDI_OVERRIDES: dict[str, str] = {
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# Marks that set the direction of neutral characters; ordinary in right-to-left text.
DIRECTIONAL_MARKS: dict[str, str] = {
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u061c": "ARABIC LETTER MARK",
}

TAG_CHAR_RANGE = re.compile(r"[\U000e0000-\U000e007f]")
# Code points that Unicode reserves as default-ignorable but has not assigned (property
# Other_Default_Ignorable_Code_Point, category Cn). Renderers draw nothing for them, and
# unicodedata exposes no property that identifies them, so they are listed; U+E0000 and
# U+E0002 to U+E001F, which are of the same kind, lie in the tag range above.
_UNASSIGNED_IGNORABLE = "\u2065\ufff0-\ufff8\U000e0080-\U000e00ff\U000e01f0-\U000e0fff"
_UNASSIGNED = re.compile(f"[{_UNASSIGNED_IGNORABLE}]")
# The plane-14 part lies beside the tag characters and variation selectors that
# encodings of hidden text use, and like them it has no legitimate use in instructions.
_UNASSIGNED_PLANE_14 = re.compile(r"[\U000e0080-\U000e00ff\U000e01f0-\U000e0fff]")

# Every default-ignorable code point of Unicode 15.1, assigned or not, every format
# character (category Cf) and the blank Braille pattern. The scan also checks each
# distinct character's category, so format characters added in later versions are
# found too.
_HIDDEN = re.compile(
    "[\u00ad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891\u08e2\u115f\u1160"
    "\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f"
    "\u2800\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff9-\ufffb\U000110bd\U000110cd"
    "\U00013430-\U0001343f\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    f"\U000e0000-\U000e007f\U000e0100-\U000e01ef{_UNASSIGNED_IGNORABLE}]"
)
# The text-poisoning rules remove these before matching.
HIDDEN_CHARACTERS = _HIDDEN
_ZWJ = "\u200d"
_PRESENTATION_SELECTORS = frozenset({"\ufe0e", "\ufe0f"})
_SKIN_TONES = range(0x1F3FB, 0x1F400)
# The three subdivision flags that are recommended emoji: England, Scotland and Wales.
_FLAG_SEQUENCE = re.compile(
    "\U0001f3f4\U000e0067\U000e0062(?:\U000e0065\U000e006e\U000e0067"
    "|\U000e0073\U000e0063\U000e0074|\U000e0077\U000e006c\U000e0073)\U000e007f"
)
# Characters of a large text file counted at once when no newline ends a segment sooner.
_MAX_SEGMENT = 1 << 20
# In a file with a NUL byte that is not UTF-8, which is binary, only runs this long count:
# random bytes form a hidden character now and then, but not runs of them, and text
# hidden in such characters takes one character per byte.
_BINARY_RUN = 4
_HIDDEN_RUN = re.compile(f"(?:{_HIDDEN.pattern}){{{_BINARY_RUN},}}")
# Plane-14 characters, which tag and variation selector encodings of hidden text use,
# all count in a binary file once this many of them lie within a window of this many
# characters, whatever separates them. Random bytes form one about once per MiB, so a
# count over the whole file would grow with its size; hidden text needs one per letter.
_BINARY_PLANE_14 = 16
_BINARY_PLANE_14_WINDOW = 4096
_PLANE_14 = re.compile("[\U000e0000-\U000e0fff]")
# Byte-order marks after which readers decode UTF-32 or UTF-16; UTF-32 LE first, since
# its mark starts with that of UTF-16 LE.
_BYTE_ORDER_MARKS = (
    (codecs.BOM_UTF32_LE, "utf-32"),
    (codecs.BOM_UTF32_BE, "utf-32"),
    (codecs.BOM_UTF16_LE, "utf-16"),
    (codecs.BOM_UTF16_BE, "utf-16"),
)


def _pictographic(char: str) -> bool:
    """Whether ``char`` is in a block of pictographs or is one of the other characters
    that Unicode's emoji-variation-sequences.txt lets a presentation selector follow;
    unicodedata has no emoji properties, so the blocks and characters are listed."""
    point = ord(char)
    return (
        0x1F000 <= point <= 0x1FAFF
        or 0x2190 <= point <= 0x21FF
        or 0x2300 <= point <= 0x23FF
        or 0x25A0 <= point <= 0x27BF
        or 0x2900 <= point <= 0x297F
        or 0x2B00 <= point <= 0x2BFF
        or point
        in {0xA9, 0xAE, 0x203C, 0x2049, 0x2122, 0x2139, 0x24C2, 0x3030, 0x303D, 0x3297, 0x3299}
    )


def _emoji_context(content: str, index: int) -> bool:
    """Whether a joiner or presentation selector at ``index`` belongs to an emoji."""
    char = content[index]
    before = index - 1
    if char == _ZWJ:
        while before >= 0 and (
            content[before] in _PRESENTATION_SELECTORS or ord(content[before]) in _SKIN_TONES
        ):
            before -= 1
        after = index + 1
        return (
            before >= 0
            and after < len(content)
            and _pictographic(content[before])
            and _pictographic(content[after])
        )
    if before < 0:
        return False
    previous = content[before]
    # Only a character that takes a presentation selector makes it ordinary: after a
    # space, a dash or kana a run of them encodes hidden bits.
    return _pictographic(previous) or previous in "#*0123456789"


def _character_name(char: str) -> str:
    unnamed = (
        "UNASSIGNED DEFAULT-IGNORABLE CODE POINT"
        if _UNASSIGNED.match(char)
        else "UNNAMED FORMAT CHARACTER"
    )
    return unicodedata.name(char, unnamed)


_LINE_SEPARATORS = ("\u2028", "\u2029")


def _line_separator_counts(content: str) -> dict[str, int]:
    if "\u2028" not in content and "\u2029" not in content:
        return {}
    return {char: content.count(char) for char in _LINE_SEPARATORS if char in content}


def _line_separator_risks(counts: dict[str, int], source_name: str) -> list[RiskAssessment]:
    if not counts:
        return []
    names = {
        "\u2028": "LINE SEPARATOR",
        "\u2029": "PARAGRAPH SEPARATOR",
    }
    shown = ", ".join(
        f"{names[char]} (U+{ord(char):04X}) x{count}"
        for char, count in sorted(counts.items(), key=lambda item: ord(item[0]))
    )
    return [
        RiskAssessment(
            severity=RiskSeverity.LOW,
            category="line_separators",
            detail=(
                f"'{neutralize(source_name)}' contains line or paragraph separators: {shown}. "
                "They can split a line in some renderers."
            ),
            recommendation="Replace them with ordinary newline characters.",
        )
    ]


def detect_invisible_characters(
    content: str, source_name: str, *, decoded: str | None = None
) -> list[RiskAssessment]:
    """Detect invisible Unicode characters that could be used for prompt trojans.

    Every format character (category Cf), variation selector, blank-rendering filler
    and unassigned default-ignorable code point is reported. Bidirectional
    embeddings, overrides and isolates, tag characters and the unassigned code points
    of plane 14 are critical; directional marks, which right-to-left text uses, are
    medium; the others are high. A zero-width joiner inside an emoji sequence, a
    presentation selector after a pictograph, a byte-order mark that starts the text
    and the England, Scotland and Wales flag sequences are ordinary text.

    ``decoded`` holds what a prompt template's escapes, or those in the front matter of a
    Markdown file, decode to (see ``_escaped_text``), where an escape spells a character
    its raw text does not hold; each character counts as often as the text that holds it
    more often, so one written raw counts once.
    """
    counts, tags = _hidden_counts(content, at_start=True)
    separators = _line_separator_counts(content)
    if decoded is not None:
        escaped, escaped_tags = _hidden_counts(decoded, at_start=False)
        for char, count in escaped.items():
            counts[char] = max(counts.get(char, 0), count)
        tags = max(tags, escaped_tags)
        for char, count in _line_separator_counts(decoded).items():
            separators[char] = max(separators.get(char, 0), count)
    return [
        *_hidden_character_risks(counts, tags, source_name),
        *_line_separator_risks(separators, source_name),
    ]


def definition_text_risks(
    definition: object, source_name: str, *, include_name: bool = False
) -> list[RiskAssessment]:
    """Rate the hidden characters in a tool definition as in an instruction file.

    A host puts a tool's description and schema text in front of the model as it does an
    instruction file, so the same characters hide the same text. Every string and key
    of the definition is read except the tool's own name, which is reported as an
    identifier unless ``include_name`` is set, as for a served descriptor whose name a
    host shows the model unredacted. A byte-order mark is never ordinary here: no
    string of a definition starts a file.
    """
    counts: dict[str, int] = {}
    separators: dict[str, int] = {}
    tags = 0
    if isinstance(definition, dict):
        pending = [
            item
            for key, value in definition.items()
            if include_name or key != "name"
            for item in (key, value)
        ]
    else:
        pending = [definition]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            pending.extend(value)
            pending.extend(value.values())
        elif isinstance(value, list):
            pending.extend(value)
        elif isinstance(value, str) and not value.isascii():
            found, found_tags = _hidden_counts(value, at_start=False)
            tags += found_tags
            for char, count in found.items():
                counts[char] = counts.get(char, 0) + count
            for char, count in _line_separator_counts(value).items():
                separators[char] = separators.get(char, 0) + count
    return [
        *_hidden_character_risks(counts, tags, source_name),
        *_line_separator_risks(separators, source_name),
    ]


def _hidden_counts(content: str, *, at_start: bool) -> tuple[dict[str, int], int]:
    """Count the hidden characters of ``content``, and its tag characters outside a flag.

    ``at_start`` says whether ``content`` begins the text, where a byte-order mark is
    ordinary.
    """
    counts: dict[str, int] = {}
    if content.isascii():
        return counts, 0
    for match in _HIDDEN.finditer(content):
        char = match.group()
        if (char == _ZWJ or char in _PRESENTATION_SELECTORS) and _emoji_context(
            content, match.start()
        ):
            continue
        if char == "\ufeff" and at_start and match.start() == 0:
            continue
        counts[char] = counts.get(char, 0) + 1
    for char in set(content) - set(counts):
        if not char.isascii() and unicodedata.category(char) == "Cf" and not _HIDDEN.match(char):
            counts[char] = content.count(char)
    tags = len(TAG_CHAR_RANGE.findall(_FLAG_SEQUENCE.sub("", content)))
    for char in [char for char in counts if TAG_CHAR_RANGE.match(char)]:
        del counts[char]
    return counts, tags


class _HiddenCharacterStream:
    """The hidden-character counts of a file's text, read in chunks.

    The text is decoded as an agent's reader decodes it: as UTF-32 or UTF-16 after
    that byte-order mark, otherwise as UTF-8 with U+FFFD for an invalid sequence, so a
    stray byte or a UTF-16 file does not hide what the rest of it says. When the bytes
    are not UTF-8 and hold a NUL byte, without such a mark, the file is binary and only
    runs of ``_BINARY_RUN`` or more hidden characters count, and every plane-14 hidden
    character once ``_BINARY_PLANE_14`` of them lie within ``_BINARY_PLANE_14_WINDOW``
    characters.

    The text is counted in segments that end after a newline, which no emoji or flag
    sequence crosses, so the counts equal those of the whole text. A segment that
    reaches ``_MAX_SEGMENT`` characters without one is cut there; a cut can only add
    findings, never hide one, except that it can split a run in a binary file.
    """

    def __init__(self) -> None:
        self._decoder: codecs.IncrementalDecoder | None = None
        self._utf8 = True
        self._strict: codecs.IncrementalDecoder | None = None
        self._nul = False
        self._pending = ""
        self._at_start = True
        self._counts: dict[str, int] = {}
        self._tags = 0
        self._run_counts: dict[str, int] = {}
        self._run_tags = 0
        self._offset = 0
        self._plane_14: deque[int] = deque(maxlen=_BINARY_PLANE_14)
        self._dense_plane_14 = False
        self._line_seps: dict[str, int] = {}

    @property
    def binary(self) -> bool:
        """Bytes that are not UTF-8, hold a NUL byte and declare no other encoding."""
        return self._nul and self._strict is None

    @property
    def counts(self) -> dict[str, int]:
        if not self.binary:
            return self._counts
        if not self._dense_plane_14:
            return self._run_counts
        plane_14 = {char: n for char, n in self._counts.items() if _PLANE_14.match(char)}
        return {**self._run_counts, **plane_14}

    @property
    def tags(self) -> int:
        if not self.binary:
            return self._tags
        return self._tags if self._dense_plane_14 else self._run_tags

    @property
    def line_separators(self) -> dict[str, int]:
        """U+2028 and U+2029. A binary file does not report them."""
        if self.binary:
            return {}
        return self._line_seps

    def feed(self, chunk: bytes, *, final: bool = False) -> None:
        if self._decoder is None:
            if not chunk and not final:
                return
            encoding = next(
                (name for mark, name in _BYTE_ORDER_MARKS if chunk.startswith(mark)), None
            )
            self._decoder = codecs.getincrementaldecoder(encoding or "utf-8")("replace")
            self._utf8 = encoding is None
            if self._utf8:
                self._strict = codecs.getincrementaldecoder("utf-8")()
        if self._utf8:
            self._nul = self._nul or b"\0" in chunk
        if self._strict is not None:
            try:
                self._strict.decode(chunk, final)
            except UnicodeDecodeError:
                self._strict = None
        text = self._pending + self._decoder.decode(chunk, final)
        end = len(text) if final else text.rfind("\n", len(self._pending)) + 1
        if not end and len(text) >= _MAX_SEGMENT:
            end = len(text)
        if not end:
            self._pending = text
            return
        segment = text[:end]
        for char, count in _line_separator_counts(segment).items():
            self._line_seps[char] = self._line_seps.get(char, 0) + count
        counts, tags = _hidden_counts(segment, at_start=self._at_start)
        self._tags += tags
        for char, count in counts.items():
            self._counts[char] = self._counts.get(char, 0) + count
        if counts or tags:
            runs = "\n".join(_HIDDEN_RUN.findall(segment))
            counts, tags = _hidden_counts(runs, at_start=False)
            self._run_tags += tags
            for char, count in counts.items():
                self._run_counts[char] = self._run_counts.get(char, 0) + count
            for match in _PLANE_14.finditer(segment):
                self._plane_14.append(self._offset + match.start())
                if len(self._plane_14) == _BINARY_PLANE_14 and (
                    self._plane_14[-1] - self._plane_14[0] < _BINARY_PLANE_14_WINDOW
                ):
                    self._dense_plane_14 = True
        self._offset += end
        self._pending, self._at_start = text[end:], False


def _hidden_character_risks(
    counts: dict[str, int], tags: int, source_name: str
) -> list[RiskAssessment]:
    risks: list[RiskAssessment] = []
    shown = neutralize(source_name)
    # Counted, not listed: there are 3,728 of them, and they are rated with tag characters.
    plane_14 = sum(count for char, count in counts.items() if _UNASSIGNED_PLANE_14.match(char))
    invisible = [
        f"{INVISIBLE_CHARS.get(char) or _character_name(char)} (U+{ord(char):04X}) x{count}"
        for char, count in sorted(counts.items(), key=lambda item: ord(item[0]))
        if char not in BIDI_OVERRIDES
        and char not in DIRECTIONAL_MARKS
        and not _UNASSIGNED_PLANE_14.match(char)
    ]
    if invisible:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.HIGH,
                category="invisible_characters",
                detail=(
                    f"'{shown}' contains invisible Unicode characters: "
                    f"{', '.join(invisible)}. "
                    "These are invisible in most editors and may alter LLM behavior."
                ),
                recommendation="Remove all zero-width characters or document their purpose.",
            )
        )

    found_bidi = [
        f"{name} (U+{ord(char):04X}) x{counts[char]}"
        for char, name in BIDI_OVERRIDES.items()
        if char in counts
    ]
    if found_bidi:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="bidi_override",
                detail=(
                    f"'{shown}' contains bidirectional override characters: "
                    f"{', '.join(found_bidi)}. "
                    "Bidi overrides can make malicious instructions appear as benign text."
                ),
                recommendation="Remove all bidirectional override characters immediately.",
            )
        )

    marks = [
        f"{name} (U+{ord(char):04X}) x{counts[char]}"
        for char, name in DIRECTIONAL_MARKS.items()
        if char in counts
    ]
    if marks:
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.MEDIUM,
                category="directional_marks",
                detail=(
                    f"'{shown}' contains invisible directional marks: {', '.join(marks)}. "
                    "They are ordinary in right-to-left text but can reorder neutral characters."
                ),
                recommendation="Confirm that each directional mark belongs to right-to-left text.",
            )
        )

    if tags or plane_14:
        found = []
        removed = "tag characters"
        if tags:
            found.append(
                f"{tags} deprecated Unicode tag characters (U+E0000–U+E007F) outside a flag emoji"
            )
        if plane_14:
            found.append(
                f"{plane_14} unassigned default-ignorable code points of plane 14 "
                "(U+E0080–U+E00FF, U+E01F0–U+E0FFF)"
            )
            removed = "tag characters and unassigned code points"
        risks.append(
            RiskAssessment(
                severity=RiskSeverity.CRITICAL,
                category="tag_characters",
                detail=(
                    f"'{shown}' contains {' and '.join(found)}. These are "
                    "invisible and have no legitimate use in prompt files."
                ),
                recommendation=f"Remove all {removed} — likely a prompt trojan.",
            )
        )
    return risks


# Notes say `run` too (`Run make docs`, `dry-run`, `last run:`), so it counts only when
# the next word names what to run: a path, a script or executable file, a shell, or a
# command that executes code, reads secrets or deletes files. Any punctuation that a path
# cannot contain may come first, so `Run: ./x.sh`, `run (bash)` and `run **./x.sh**`
# count, as do an arrow or a bullet (`->`, `- `), a prompt (`$ `), an HTML tag, also with
# attributes (`<code class="sh">`), an environment assignment (`FOO=bar `), a code
# fence's language and `_` emphasis. A hyphen joined to a word before it (`dry-run`) makes
# a noun, except in `re-run`; `<!--run` does not. A separator is never a path character,
# so a path's scan stops at the next `run`'s separator and stays linear.
_PATH_CHARACTER = r"[\w.~$%+@-]"
_PUNCTUATION = r"[^\w.~$%+@/\\-]"
_RUN_SEPARATOR = (
    rf"(?:{_PUNCTUATION}|[-$]++(?={_PUNCTUATION})|<[a-z]++(?:[ \t][^<>\n]{{0,256}}+)?>"
    rf"|(?<=```)[\w+-]++(?=[ \t]*\n))"
)
_RUN = rf"(?<!\w)(?:(?<=\bre-)|(?<!\w-))run{_RUN_SEPARATOR}+_{{0,2}}"
# A name ends where a word does, or where underscores close emphasis (`_bash_`).
_NAME_END = r"(?:\b|(?=_+(?!\w)))"
_SHELL = rf"(?:(?:ba|z|da)?sh|pwsh|powershell){_NAME_END}"
# A command joined to a word by a hyphen (`go-live`, `cat-food`) is a different word.
_COMMAND = (
    r"(?:python3?|py|node|deno|bun|ruby|perl|php|java|osascript"
    r"|npx|uvx|pipx|pip3?|npm|pnpm|yarn|uv|poetry|cargo|go|brew|apt-get|apt|gem"
    r"|sudo|doas|su|env|exec|eval|source|curl|wget|iwr|cat|cp|mv|rm|dd|chmod|chown"
    r"|ssh|scp|nc|base64|xargs|docker|kubectl|git|iex|irm|iwr"
    rf"|invoke-(?:expression|restmethod|webrequest))(?!-\w){_NAME_END}"
)
_PATH_START = (
    r"[/\\]\S"
    rf"|(?:[a-z_.~$%]{_PATH_CHARACTER}*|[a-z]:|\$env:\w+|\$\{{[\w:]+\}})[/\\]"
)
_SCRIPT = rf"{_PATH_CHARACTER}+\.(?:sh|bash|zsh|ps1|bat|cmd|exe|py){_NAME_END}"
_RUN_TARGET = rf"{_RUN}(?:{_PATH_START}|{_SCRIPT}|{_SHELL}|{_COMMAND})"
_HIDDEN_INSTRUCTION = re.compile(
    r"https?://|~/"
    r"|\b(?:ignore|disregard|exfiltrate|execute|download|upload|send|steal|override|"
    rf"bypass|curl|wget|fetch|eval|install)\b|{_RUN_TARGET}",
    re.IGNORECASE,
)
# `run this`, `run the following`, `run these` and `run it` point at what comes later in
# the same comment. Each target starts where a word or path does, so the scan is linear.
_RUN_REFERENCE = re.compile(rf"{_RUN}(?:this|these|it|the\s+following)\b", re.IGNORECASE)
_LATER_TARGET = re.compile(
    rf"(?<![\w.~$%+@/\\<-])(?:{_PATH_START})"
    rf"|(?<!{_PATH_CHARACTER})(?:{_SCRIPT})"
    rf"|(?<![\w.-])(?:{_SHELL}|{_COMMAND})",
    re.IGNORECASE,
)
# `run` also counts when a target later in the same sentence starts a command: at the
# start of a line or list item, or after `:`, `;`, `&`, `|`, `then`, `command(s)`,
# `script`, or an example abbreviation directly after the verb. Whitespace, quotes,
# brackets and emphasis may intervene. So
# `run the command `rm -rf /``, `run as root: rm -rf /`, `run make test && rm -rf /`, `run
# i.e. bash` and `run tests, then cat .env` count, while `run them with python` does not.
# A sentence ends at `.`, `!` or `?` before whitespace, except after a digit, as in a `1.`
# list marker, and in `e.g.` and `i.e.`.
_RUN_VERB = re.compile(_RUN, re.IGNORECASE)
_ASSIGNMENT_TOKEN = re.compile(r"[^\s<>]++")
_ASSIGNMENT_START = re.compile(r"(?<![\w=])[A-Za-z_]\w*+=", re.IGNORECASE)
_SENTENCE_END = re.compile(r"(?<!\d)(?<!\b[eE]\.[gG])(?<!\b[iI]\.[eE])[.!?](?=\s)")
_COMMAND_SKIP = frozenset(" \t`'\"([*_>-\u201c\u2018$")
_COMMAND_DELIMITER = frozenset(":;&|\n")
_COMMAND_WORD = re.compile(r"(?<!\w)(?:then|commands?|script)\Z", re.IGNORECASE)
_EXAMPLE_WORD = re.compile(r"(?<!\w)(?:e\.g\.|i\.e\.)\Z", re.IGNORECASE)


def _starts_command(text: str, start: int, position: int) -> bool:
    """Whether the target at ``position`` begins a command after ``run`` at ``start``.

    The backward scan crosses only the skippable characters directly before this target,
    which no other target's scan crosses, so the scans of one sentence stay linear.
    """
    index = position
    while index > start and text[index - 1] in _COMMAND_SKIP:
        index -= 1
    if index <= start or text[index - 1] in _COMMAND_DELIMITER:
        return True
    if text[index - 1] in ".)" and text[index - 2 : index - 1].isdigit():
        index -= 1
        while index > start and text[index - 1].isdigit():
            index -= 1
        while index > start and text[index - 1] in " \t":
            index -= 1
        return index <= start or text[index - 1] == "\n"
    if _COMMAND_WORD.search(text, max(start, index - 8), index) is not None:
        return True
    example = _EXAMPLE_WORD.search(text, max(start, index - 5), index)
    if example is None:
        return False
    index = example.start()
    while index > start and text[index - 1] in _COMMAND_SKIP:
        index -= 1
    return index == start


def _run_starts_later_command(text: str) -> bool:
    verbs = iter(_RUN_VERB.finditer(text))
    verb = next(verbs, None)
    while verb is not None:
        latest_end = verb.end()
        end = _SENTENCE_END.search(text, latest_end)
        sentence_end = len(text) if end is None else end.start()
        verb = next(verbs, None)
        # Scan complete targets once. A variable or path may itself contain a verb.
        for target in _LATER_TARGET.finditer(text, latest_end, sentence_end):
            while verb is not None and verb.end() <= target.start():
                latest_end = verb.end()
                verb = next(verbs, None)
            if _starts_command(text, latest_end, target.start()):
                return True
        while verb is not None and verb.end() <= sentence_end:
            verb = next(verbs, None)
    return False


def _instruction_in_text(text: str) -> bool:
    if _HIDDEN_INSTRUCTION.search(text) is not None:
        return True
    reference = _RUN_REFERENCE.search(text)
    if reference is not None and _LATER_TARGET.search(text, reference.end()) is not None:
        return True
    return _run_starts_later_command(text)


def _comment_is_instruction(text: str) -> bool:
    """An imperative, a URL, or a home-directory path inside hidden text."""
    if _instruction_in_text(text):
        return True
    if "=" not in text:
        return False

    def omit_assignment(token: re.Match[str]) -> str:
        # Only a horizontal space ends an assignment separator. Scan each word once,
        # so a long value with many '=' characters cannot repeatedly scan its suffix.
        if token.end() < len(text) and text[token.end()] in " \t":
            start = _ASSIGNMENT_START.search(text, token.start(), token.end())
            if start is not None:
                return text[token.start() : start.start()]
        return token.group()

    without_assignments = _ASSIGNMENT_TOKEN.sub(omit_assignment, text)
    return without_assignments != text and _instruction_in_text(without_assignments)


def detect_hidden_markup(content: str, source_name: str) -> list[RiskAssessment]:
    """Report HTML and Markdown comments, which renderers hide but agents read.

    Markdown comments are the link reference definitions that no link uses, that repeat
    a label or that are written as comments, and the footnotes that nothing references;
    HTML comments include the other markup that HTML parsers read as comments, counted
    once when it is inside one; see :func:`hidden_text`.
    Only counts and lengths are reported, never the hidden text. A comment that carries
    an imperative (``run`` only when a path, a script, a shell or a listed command
    follows, possibly after punctuation or markup, or when ``this``, ``these``, ``it``
    or ``the following`` follows and one of those comes later in the comment, or when
    one of those starts a command later in the same sentence), a URL or a path under
    ``~/`` is high; other comments stay low.
    """
    count = length = 0
    instructive = False
    position = 0
    while (start := content.find("<!--", position)) != -1:
        end = content.find("-->", start + 4)
        stop = len(content) if end == -1 else end + 3
        count += 1
        length += stop - start
        instructive = instructive or _comment_is_instruction(content[start:stop])
        position = stop
    hidden = hidden_text(content)
    for part in (*hidden.definitions, *hidden.html):
        count += 1
        instructive = instructive or _comment_is_instruction(part)
    length += sum(map(len, hidden.html))
    if not count:
        return []
    severity = RiskSeverity.HIGH if instructive else RiskSeverity.LOW
    qualifier = (
        " At least one comment contains an instruction, a URL or a home-directory path."
        if instructive
        else ""
    )
    return [
        RiskAssessment(
            severity=severity,
            category="hidden_markup",
            detail=(
                f"'{neutralize(source_name)}' contains {count} HTML or Markdown comment(s) "
                f"({length} characters of HTML comments) that rendered views hide and agents read."
                f"{qualifier}"
            ),
            recommendation="Review comment text in the raw file; move notes out of agent instructions.",
        )
    ]


INSTRUCTION_FILES: dict[str, str] = {
    "CLAUDE.md": "system-prompt",
    ".claude/CLAUDE.md": "system-prompt",
    "CLAUDE.local.md": "system-prompt",
    "AGENTS.md": "system-prompt",
    "AGENTS.override.md": "system-prompt",
    "GEMINI.md": "system-prompt",
    "CODEX.md": "system-prompt",
    "codex.md": "system-prompt",
    ".cursorrules": "rules-file",
    ".clinerules": "rules-file",
    ".windsurfrules": "rules-file",
    ".github/copilot-instructions.md": "instruction",
    ".github/AGENTS.md": "instruction",
    ".codex/instructions.md": "instruction",
    "system_prompt.txt": "system-prompt",
    "system_prompt.md": "system-prompt",
}
# Both spellings are read; neither is a case variant of the other.
_CODEX_SPELLINGS = frozenset({"CODEX.md", "codex.md"})

# Instruction files a host loads from below the root: per-directory memory and context
# files, and the rules file of a project opened at that directory.
NESTED_INSTRUCTION_NAMES = {
    "CLAUDE.md": "system-prompt",
    "AGENTS.md": "system-prompt",
    "GEMINI.md": "system-prompt",
    ".cursorrules": "rules-file",
}
# Another spelling of one of them is the file a case-insensitive file system opens in
# its place, as at the root, so it is a failure wherever the walk meets it, unless a
# walk inventories it under its own name.
_FOLDED_NESTED_NAMES = {fold_name(name): name for name in NESTED_INSTRUCTION_NAMES}

# Subagent definitions and rule or prompt directories. Every file in them is inventoried
# by digest, and each directory is walked on its own, so a directory symlink out of one
# is followed. `.clinerules` is either a single rules file or a directory of them.
_INSTRUCTION_DIRECTORY_PARTS = tuple(
    PurePosixPath(directory).parts for directory in INSTRUCTION_DIRECTORIES
)

# Prompt files a project names as such, at any depth: every text file under a directory
# named `prompts`, and a file whose name ends in one of these suffixes.
PROMPT_DIRECTORY_NAME = "prompts"
PROMPT_FILE_SUFFIXES = (".prompt.md", ".prompt.yaml", ".prompt.yml")
# A prompts directory also holds code, images and editor files, which no host loads as a
# prompt; only these suffixes, or a name with no suffix that is not a dotfile, are read.
PROMPT_TEXT_SUFFIXES = frozenset(
    {
        *(".md", ".mdc", ".mdx", ".markdown", ".txt", ".yaml", ".yml", ".json", ".toml"),
        *(".j2", ".jinja", ".jinja2", ".tmpl", ".tpl", ".hbs", ".mustache", ".prompt"),
    }
)
PROMPT_TEMPLATE_TYPE = "template"
# Test, build output, documentation, example, dependency and vendored trees hold prompts
# that illustrate or ship with something else; the mcp collector's source search skips
# the same names.
PROMPT_SEARCH_SKIPPED = frozenset({*SOURCE_SEARCH_SKIPPED, "node_modules", "vendor"})

# No agent reads these as instructions: every file is a resource, checked only for
# hidden characters.
_RESOURCE_DIRECTORIES = frozenset({".claude/hooks", ".cursor/hooks"})
_SKILL_PARTS = tuple(PurePosixPath(directory).parts for directory in SKILL_DIRECTORIES)

# Skill and command declarations, read as text, which must be UTF-8; every other file of
# a skill or command directory, such as a bundled script, is a resource bound by digest.
_DECLARATION_SUFFIXES = frozenset(
    {".md", ".mdc", ".markdown", ".txt", ".yaml", ".yml", ".json", ".toml"}
)
# Claude Code memory files and Gemini CLI context files import others with @path.
_IMPORTING_NAMES = frozenset({"CLAUDE.md", "CLAUDE.local.md", "GEMINI.md"})
_MAX_IMPORT_DEPTH = 5
_MAX_IMPORTS = 1000
# The keyed binding that covers a recorded file, imported or found by a walk, that the
# unkeyed content hash must not.
IMPORT_CONTENT_BINDING_PROFILE = "nexus-symbiote/prompt-import-content/v1"


def _markdown(path: str) -> bool:
    return PurePosixPath(path).suffix.lower() in _MARKUP_SUFFIXES


def _prompt_named(name: str) -> bool:
    return name.lower().endswith(PROMPT_FILE_SUFFIXES)


def _prompt_text(name: str) -> bool:
    suffix = PurePosixPath(name).suffix.lower()
    return suffix in PROMPT_TEXT_SUFFIXES or (not suffix and not name.startswith("."))


def _outside_other_walks(parts: tuple[str, ...]) -> bool:
    return not any(
        parts[: len(directory)] == directory
        for directory in (*_INSTRUCTION_DIRECTORY_PARTS, *_SKILL_PARTS)
    )


def _linked_prompt_gaps(
    links: list[Path], tree: list[Path], claimed: Collection[str], files: ConfinedCollection
) -> list[str]:
    """A gap for each directory symlink under which a file is a prompt template that no
    walk or import inventories under any name.

    The root walk reads the directory a symlink leads to once, under that directory's
    own name, where such a file is not a prompt template: ``agent/prompts/a.md`` under
    ``agent -> examples/agent`` is read as ``examples/agent/prompts/a.md``, which is
    skipped. A file that is a prompt template, or another kind, under its own name is
    inventoried there.
    """
    gaps: list[str] = []
    unclaimed = sorted(path.parts for path in tree if path.as_posix() not in claimed)
    for link in links:
        target = files.link_target(link) if files.is_directory(link) else None
        if target is None:
            continue
        base = PurePosixPath(target).parts
        for parts in unclaimed[bisect.bisect_left(unclaimed, base) :]:
            if parts[: len(base)] != base:
                break
            alias = PurePosixPath(*link.parts, *parts[len(base) :])
            if _prompt_candidate(alias):
                gaps.append(
                    f"{link.as_posix()}: directory symlink to {target}; prompt templates under "
                    f"it, such as {alias.as_posix()}, are not inventoried, because the walk "
                    f"reads their files only under {target}, where they are not prompt templates"
                )
                break
    return gaps


# A JSON, YAML or TOML prompt file passes a host the strings it decodes to, where an
# escape such as \udb40\udc49 or "\U000E0049" spells a hidden character in ASCII.
_ESCAPED_FORMATS = {".json": "JSON", ".yaml": "YAML", ".yml": "YAML", ".toml": "TOML"}
# The token budget the other collectors give a YAML file they parse.
_MAX_YAML_EVENTS = 20_000
# The YAML and TOML parsers are pure Python; a longer file is decoded by pattern.
_MAX_PARSED_CHARACTERS = 65_536
# PyYAML's cost grows with flow nesting depth, past 20 s for 20,000 brackets; YAML nested
# deeper is decoded by pattern.
_MAX_YAML_FLOW_DEPTH = 64
_FLOW_BRACKETS = re.compile(r"[\[\]{}]")
# A backslash that ends a line continues a YAML double-quoted or TOML basic string on the
# next line, past its indentation, so an escape there joins the one before it.
_ESCAPE = re.compile(
    r"\\(?:x([0-9A-Fa-f]{2})|u([0-9A-Fa-f]{4})|U([0-9A-Fa-f]{8})|([LPN_e])"
    r"|([ \t]*+(?:(?:\r\n|\r|\n)[ \t]*+)+)|.)",
    re.S,
)
_NAMED_ESCAPES = {"L": "\u2028", "P": "\u2029", "N": "\x85", "_": "\xa0", "e": "\x1b"}
_FRONT_MATTER_FORMATS = {"toml": "TOML", "json": "JSON"}
_SURROGATE = re.compile("[\ud800-\udfff]")


def _decode_escaped_payload(relative: str, kind: str, what: str, body: str, gaps: list[str]) -> str:
    if (
        kind != "JSON"
        and len(body) <= _MAX_PARSED_CHARACTERS
        and (kind == "TOML" or _flow_depth(body) <= _MAX_YAML_FLOW_DEPTH)
    ):
        import yaml

        try:
            strings = _string_values(toml_loads(body)) if kind == "TOML" else _yaml_scalars(body)
        except (ValueError, RecursionError, yaml.YAMLError):
            pass
        else:
            return _joined_surrogates("\n".join(strings))
    if kind != "JSON":
        gaps.append(
            f"{relative}: {what} that does not parse or is past the parse bounds has its "
            "escapes decoded by pattern, which may not decode them as a host does"
        )
    return _joined_surrogates(_ESCAPE.sub(_unescape, body))


def _escaped_text(relative: str, text: str, gaps: list[str]) -> str | None:
    """What a JSON, YAML or TOML prompt file, or the front matter of a Markdown
    one, decodes to, or ``None`` when it holds no backslash.

    YAML of at most ``_MAX_YAML_EVENTS`` events and ``_MAX_YAML_FLOW_DEPTH`` nested flow
    collections and TOML within the dotted-key bound, each up to ``_MAX_PARSED_CHARACTERS``,
    give the strings they parse to, one per line. JSON, which a host may read leniently,
    with comments, duplicate keys or lone surrogates, and YAML or TOML that does not
    parse or is past those bounds, give the text with
    each escape that an odd run of backslashes starts decoded: ``\\xXX``, ``\\uXXXX``,
    ``\\UXXXXXXXX``, YAML's ``\\L``, ``\\P``, ``\\N`` and ``\\_``, and ``\\e``. That
    also decodes YAML and TOML escapes in a literal string or a comment, which only
    adds findings. A backslash that ends a line is removed with the line break and the
    indentation after it, as YAML and TOML continue a string. A surrogate pair is joined,
    as a UTF-16 reader joins it. YAML or TOML decoded by pattern is a gap in ``gaps``.
    """
    body = text.removeprefix("\ufeff")
    if "\\" not in body:
        return None
    kind = _ESCAPED_FORMATS.get(PurePosixPath(relative).suffix.lower())
    if kind is not None:
        return _decode_escaped_payload(relative, kind, kind, body, gaps)
    if not _markup(relative):
        return None
    candidates = front_matter_candidates(text)
    if not candidates:
        return None
    lang, first_raw, _ = candidates[0]
    fm_kind = _FRONT_MATTER_FORMATS.get(lang, "YAML")
    what = f"{fm_kind} front matter"
    decoded: list[str] = []
    if "\\" in first_raw:
        decoded.append(_decode_escaped_payload(relative, fm_kind, what, first_raw, gaps))
    if len(candidates) == 2:
        wider_raw = candidates[1][1]
        if "\\" in wider_raw[len(first_raw) :]:
            decoded.append(_decode_escaped_payload(relative, fm_kind, what, wider_raw, gaps))
    return "\n".join(decoded) if decoded else None


def _flow_depth(text: str) -> int:
    """The deepest bracket nesting in ``text``, counting brackets in strings and comments
    too: a cheap first check, which ``_yaml_scalars`` repeats on the collections it parses."""
    depth = deepest = 0
    for match in _FLOW_BRACKETS.finditer(text):
        if match.group() in "[{":
            depth += 1
            deepest = max(deepest, depth)
        else:
            depth = max(depth - 1, 0)
    return deepest


def _unescape(match: re.Match[str]) -> str:
    digits = match.group(1) or match.group(2) or match.group(3)
    if digits is not None:
        code = int(digits, 16)
        return chr(code) if code <= sys.maxunicode else match.group()
    named = match.group(4)
    if named is not None:
        return _NAMED_ESCAPES[named]
    return "" if match.group(5) is not None else match.group()


def _joined_surrogates(text: str) -> str:
    if _SURROGATE.search(text) is None:
        return text
    return text.encode("utf-16-le", "surrogatepass").decode("utf-16-le", "replace")


def _string_values(value: Any) -> list[str]:
    strings: list[str] = []
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            strings.append(item)
        elif isinstance(item, dict):
            for key, child in item.items():
                pending.extend((key, child))
        elif isinstance(item, list):
            pending.extend(item)
    return strings


def _yaml_scalars(text: str) -> list[str]:
    import yaml

    strings: list[str] = []
    flows: list[bool] = []
    depth = 0
    for count, event in enumerate(yaml.parse(text), start=1):
        if count > _MAX_YAML_EVENTS:
            raise ValueError("too many YAML events")
        if isinstance(event, yaml.ScalarEvent):
            strings.append(event.value)
        elif isinstance(event, yaml.CollectionStartEvent):
            flows.append(bool(event.flow_style))
            depth += flows[-1]
            # ``_flow_depth`` also counts brackets in quoted strings, where a closing one
            # hides an opening one from it.
            if depth > _MAX_YAML_FLOW_DEPTH:
                raise ValueError("YAML nested too deep")
        elif isinstance(event, yaml.CollectionEndEvent) and flows:
            depth -= flows.pop()
    return strings


def _prompt_surface(parts: tuple[str, ...]) -> bool:
    """Whether the walk records the file at ``parts`` as a prompt template: a text file
    under a ``prompts`` directory or a file named ``*.prompt.md``, ``*.prompt.yaml`` or
    ``*.prompt.yml``, outside the trees ``PROMPT_SEARCH_SKIPPED`` names and outside the
    rule, prompt, subagent, skill and command directories, whose own walks inventory their
    files. A walk of one of those directories through a symlink reaches files outside
    them too; ``scan`` leaves those to that walk.
    """
    directories = parts[:-1]
    if PROMPT_SEARCH_SKIPPED.intersection(directories) or not _outside_other_walks(parts):
        return False
    if _prompt_named(parts[-1]):
        return True
    return PROMPT_DIRECTORY_NAME in directories and _prompt_text(parts[-1])


def _prompt_candidate(path: PurePosixPath | Path) -> bool:
    """Whether ``path`` is a prompt template under its own name: another spelling of a
    nested instruction name, such as ``prompts/claude.md``, stays the failure it is
    anywhere else, because a case-insensitive host opens it as that name."""
    return (
        path.name not in NESTED_INSTRUCTION_NAMES
        and (len(path.parts) < 2 or fold_name(path.name) not in _FOLDED_NESTED_NAMES)
        and path.as_posix() not in INSTRUCTION_FILES
        and _prompt_surface(path.parts)
    )


def _read_unless_credential(
    path: str,
    files: ConfinedCollection,
    result: ScanResult | None,
    *,
    context: str = "",
    missing_ok: bool = False,
    variants_read: Collection[str] = (),
) -> bytes | None:
    """The bytes of the file at ``path``, or None when it is absent, unreadable or a gap.

    A file that ``_credential_gap`` names is a gap and is not read, so no unkeyed digest
    of it can reach the inventory, and a symlink replaced between that check and the
    read, so that the read followed it to such a file, is a failure. ``context`` goes
    before the reason for the gap. Without ``result`` neither is recorded: a walk that
    inventories the file records it.
    """
    linked = None if _credential_shaped(path) else files.in_root_target(path)
    reason = _credential_gap(path, None if linked is None else linked.as_posix())
    if reason is not None:
        if result is not None:
            result.surfaces_excluded.append(f"{path}: {context}{reason}; not read or inventoried")
        return None
    content = files.read_bytes(path, missing_ok=missing_ok, variants_read=variants_read)
    followed = files.link_target(path)
    if content is None or followed is None or not _credential_shaped(followed):
        return content
    # The symlink was replaced after the check above.
    if result is not None:
        result.scan_failures.append(f"{path}: file changed during collection")
    return None


# Paths the one finding for unbound prompt templates names before it counts the rest.
_MAX_NAMED_UNBOUND = 12


def _unbound_templates_risk(components: list[PromptComponent]) -> RiskAssessment:
    names = [f"'{neutralize(component.source_path or '')}'" for component in components]
    shown = ", ".join(names[:_MAX_NAMED_UNBOUND])
    more = len(names) - _MAX_NAMED_UNBOUND
    count = f"{len(names)} prompt template{'s have' if len(names) != 1 else ' has'}"
    return RiskAssessment(
        severity=RiskSeverity.LOW,
        category="completeness",
        detail=(
            f"{count} {UNBOUND_VALUES_DETAIL}: the content of each, which is not an "
            f"instruction file and carries no unkeyed digest: {shown}"
            + (f" and {more} more" if more > 0 else "")
            + "."
        ),
        recommendation=(
            f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to these files."
        ),
    )


def _found_by_name(path: str, prompt_type: str | None, directory: object = None) -> bool:
    """Whether a walk recorded ``path`` because a host loads a file of that name, a
    prompt template is named ``*.prompt.md``, ``*.prompt.yaml`` or ``*.prompt.yml``, or
    a rule, prompt or subagent file of that directory has no suffix at all, such as
    ``.clinerules/style``, which the collector reads as Markdown.

    ``directory`` names the rule, prompt or subagent directory whose walk reached
    ``path`` through a directory symlink, such as ``.cursor/rules`` linked to
    ``shared/r``, where the file is recorded under the path it resolves to.
    """
    if prompt_type == "imported-instruction":
        return False
    parts = PurePosixPath(path).parts
    if not parts:
        return False  # A supplied record without a path names no file.
    if path in INSTRUCTION_FILES or (len(parts) > 1 and parts[-1] in NESTED_INSTRUCTION_NAMES):
        return True
    if prompt_type == PROMPT_TEMPLATE_TYPE and _prompt_named(parts[-1]):
        return True
    if isinstance(directory, str) and directory in INSTRUCTION_DIRECTORIES and "." not in parts[-1]:
        return True
    return "." not in parts[-1] and any(
        parts[: len(directory)] == directory and len(parts) > len(directory)
        for directory in _INSTRUCTION_DIRECTORY_PARTS
    )


def _instruction_content(
    path: str, prompt_type: str | None, link_target: object, directory: object = None
) -> bool:
    """Whether a recorded file keeps an unkeyed content hash: the bytes read are those of
    an instruction file.

    The path must be Markdown, or an instruction file a walk found by its name, such as
    ``.cursorrules`` or a rule file without a suffix; and the file a symlink there leads
    to, if any, must be Markdown, the one test an @import of that target passes. Any other
    file, such as an import of ``config/app.json``, a rule directory's ``x.json``, or
    ``AGENTS.md`` linked to ``config/app.json`` or ``config/.windsurfrules``, is named by
    the checkout, not by a host, so its exact bytes may hold configuration or secrets.
    """
    named = _markdown(path) or _found_by_name(path, prompt_type, directory)
    return named and (
        link_target is None or (isinstance(link_target, str) and _markdown(link_target))
    )


def withholds_content_hash(component: PromptComponent) -> bool:
    """Whether the collector withholds the unkeyed content hash of ``component`` by design.

    Such a file is bound only by the operator key, so validation verifies that binding,
    or counts the component as unbound, instead of reporting a missing hash.
    """
    return bool(component.properties.get("content_hash_withheld")) and not (
        _instruction_content(
            component.source_path or "",
            component.prompt_type,
            component.properties.get("symlink_target"),
            component.properties.get("instruction_directory"),
        )
    )


# Path characters that the `imports` and `imported_by` lists of one collection hold
# together. One reference can name a 4 KiB path, so a count of references alone would
# not bound the inventory.
_MAX_LISTED_IMPORT_CHARACTERS = 256 * 1024
_IMPORT = re.compile(r"(?<!\S)@(\S+)")
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")
# Sentence punctuation after a reference; the file is inventoried without it.
_TRAILING = ".,;:!?)]}\"'"
# Common file systems refuse longer names and paths, but a host on another one may open
# them, so a resolved import beyond these limits is a coverage gap, not a lookup.
_MAX_NAME_BYTES = 255
_MAX_PATH_BYTES = 4096


def _markup(path: str) -> bool:
    suffix = PurePosixPath(path).suffix.lower()
    return suffix in _MARKUP_SUFFIXES or not suffix


def _resolve_import(directory: tuple[str, ...], token: str) -> tuple[list[str], bool, bool]:
    """The in-root paths an @path import in ``directory`` names, whether it leaves the
    root, and whether it names a path too long to look up.

    A token is resolved as hosts resolve it, collapsing ``.``, ``..`` and repeated
    separators, before any limit applies. A Windows host reads a backslash as a
    separator and a POSIX host as part of a name, so a token with one names both forms.
    Home-relative, absolute and drive paths, and paths that climb above the root, leave
    it. A token with a NUL character names no file any host can open.
    """
    if "\x00" in token or not token.strip("/\\"):
        return [], False, False
    forms = [token, token.replace("\\", "/")] if "\\" in token else [token]
    targets: list[str] = []
    outside = too_long = False
    for form in forms:
        if form.startswith(("~", "/")) or _DRIVE.match(form):
            outside = True
            continue
        parts = list(directory)
        for part in form.split("/"):
            if part in ("", "."):
                continue
            if part == "..":
                if not parts:
                    outside = True
                    break
                parts.pop()
            else:
                parts.append(part)
        else:
            path = "/".join(parts)
            if len(path.encode()) > _MAX_PATH_BYTES or any(
                len(part.encode()) > _MAX_NAME_BYTES for part in parts
            ):
                too_long = True
            elif parts and path not in targets:
                targets.append(path)
    return targets, outside, too_long


def _import_tokens(text: str) -> list[str]:
    """@path references in the text of a Markdown file, outside its code as CommonMark
    reads it."""
    return [token for part in text_outside_code(text) for token in _IMPORT.findall(part)]


class _ImportListing:
    """The @path import references one collection lists on the files it records.

    A file's ``imports``, and the ``imported_by`` of a file that others import, are
    listed in full while all lists together hold at most
    ``_MAX_LISTED_IMPORT_CHARACTERS`` characters of paths. A list that does not fit is
    replaced by its count, and ``imports`` also by a digest of the paths, so a change to
    it is still drift. Every imported file is still inventoried and every importer still
    binds what it imports, and ``imported_by`` is the inverse of those sets, so counting
    a list loses no coverage and is not a failure.
    """

    def __init__(self) -> None:
        self._remaining = _MAX_LISTED_IMPORT_CHARACTERS
        self._importers: dict[str, list[str]] = {}
        self._counts: dict[str, int] = {}
        self._overflowed: dict[str, None] = {}
        self._leaves: dict[str, bytes] = {}

    def add(self, importer: str, targets: Collection[str], component: PromptComponent) -> None:
        """Record that ``importer`` imports ``targets``, given in the order it names them."""
        if self._take(sum(map(len, targets))):
            component.properties["imports"] = sorted(targets)
        else:
            component.properties["imports_count"] = len(targets)
            component.properties["imports_digest"] = self._digest(targets)
        for target in targets:
            self._counts[target] = self._counts.get(target, 0) + 1
            if target in self._overflowed:
                continue
            if self._take(len(importer)):
                self._importers.setdefault(target, []).append(importer)
            else:
                self._importers.pop(target, None)
                self._overflowed[target] = None

    def finish(self, recorded: dict[str, PromptComponent]) -> None:
        for target, importers in self._importers.items():
            recorded[target].properties["imported_by"] = sorted(importers)
        for target in self._overflowed:
            recorded[target].properties["imported_by_count"] = self._counts[target]

    def _take(self, characters: int) -> bool:
        if characters > self._remaining:
            return False
        self._remaining -= characters
        return True

    def _digest(self, targets: Collection[str]) -> str:
        """SHA-256 over the sorted SHA-256 digests of the paths; each path is hashed once."""
        leaves = self._leaves
        for target in targets:
            if target not in leaves:
                leaves[target] = hashlib.sha256(target.encode()).digest()
        return hash_bytes(b"".join(sorted(leaves[target] for target in targets)))


def _report_skipped(skipped: list[Path], reported: set[Path], files: ConfinedCollection) -> None:
    """A coverage gap for each entry that a walk of an agent configuration directory
    skipped because its name, such as ``venv`` or ``node_modules``, is excluded by
    default. A host reads such a skill or subagent file like any other, so it is not
    a dependency tree to leave out silently. Each path is reported once. A generic
    collection gap for the same path, including one recorded through a directory
    symlink's target, is replaced by this one.
    """
    for path in skipped:
        if path not in reported:
            reported.add(path)
            files.report_agent_default_exclude(path)


class PromptScanner(Scanner):
    name = "prompt"

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)

        with self._collection(project_root, result) as files:
            recorded: dict[str, PromptComponent] = {}
            texts: dict[str, str] = {}
            importers: list[str] = []
            # Other spellings of instruction names, each with the path it stands for; they
            # are reported once every walk has run.
            variants: list[tuple[Path, Path]] = []
            for rel_path, prompt_type in INSTRUCTION_FILES.items():
                if rel_path in INSTRUCTION_DIRECTORIES and files.is_directory(rel_path):
                    continue
                spellings = _CODEX_SPELLINGS if rel_path in _CODEX_SPELLINGS else ()
                content = _read_unless_credential(
                    rel_path, files, result, missing_ok=True, variants_read=spellings
                )
                if content is None:
                    continue
                # A case-insensitive checkout holds one file for the name and another
                # spelling beside it, with the content of whichever it wrote last.
                variants.extend(
                    (variant, Path(rel_path))
                    for variant in files.case_variants(rel_path)
                    if variant.as_posix() not in spellings and not files.excluded(variant)
                )
                component = self._record(rel_path, prompt_type, content, files, result)
                if component is not None:
                    recorded[rel_path] = component
                    texts[rel_path] = content.decode("utf-8")
                    if PurePosixPath(rel_path).name in _IMPORTING_NAMES:
                        importers.append(rel_path)

            # Instruction files below the root, found by name; a name takes precedence
            # over the directory that holds the file. A host that loads a nested CLAUDE.md
            # or GEMINI.md, as it does in a session started in that directory, expands its
            # imports too. Dependency trees and other default-excluded names stay skipped.
            # Prompt files are recorded once the directory walks below and the imports
            # have claimed theirs.
            prompt_candidates: list[str] = []
            links: list[Path] = []
            tree = sorted(files.iter_files(directory_links=links))
            for path in tree:
                relative = path.as_posix()
                nested_type = NESTED_INSTRUCTION_NAMES.get(path.name)
                canonical = None
                if nested_type is None and len(path.parts) > 1:
                    canonical = _FOLDED_NESTED_NAMES.get(fold_name(path.name))
                    if canonical is not None:
                        variants.append((path, path.with_name(canonical)))
                if _prompt_candidate(path):
                    prompt_candidates.append(relative)
                if (
                    nested_type is None
                    or len(path.parts) < 2
                    or relative in INSTRUCTION_FILES
                    or relative in recorded
                ):
                    continue
                content = _read_unless_credential(relative, files, result)
                if content is None:
                    continue
                component = self._record(relative, nested_type, content, files, result)
                if component is not None:
                    recorded[relative] = component
                    texts[relative] = content.decode("utf-8")
                    if path.name in _IMPORTING_NAMES:
                        importers.append(relative)

            reported: set[Path] = set()
            # Files a rule, prompt, subagent, skill or command directory walk reaches, also
            # through a directory symlink, keep the kind that walk gives them.
            walked: set[str] = set()
            for directory, prompt_type in INSTRUCTION_DIRECTORIES.items():
                if directory in INSTRUCTION_FILES and not files.is_directory(directory):
                    continue
                skipped: list[Path] = []
                for path in files.iter_files(directory, skipped=skipped):
                    relative = path.as_posix()
                    walked.add(relative)
                    if relative in recorded:
                        continue
                    content = _read_unless_credential(relative, files, result)
                    if content is None:
                        continue
                    # A directory symlink there leads the walk to the path it resolves to.
                    inside = path.parts[: len(Path(directory).parts)] == Path(directory).parts
                    component = self._record(
                        relative,
                        prompt_type,
                        content,
                        files,
                        result,
                        directory=None if inside else directory,
                    )
                    if component is not None:
                        recorded[relative] = component
                        texts[relative] = content.decode("utf-8")
                _report_skipped(skipped, reported, files)

            skill_listing = self._list_skills(files)
            skill_paths = {path.as_posix() for _, paths, _ in skill_listing for path in paths}
            walked.update(skill_paths)
            importers += self._variant_importers(
                variants, texts, set(importers), skill_paths, files
            )
            imported: set[str] = set()
            self._follow_imports(importers, texts, recorded, files, result, imported)
            self._scan_skills(skill_listing, files, result, reported)
            # An import keeps the identity it had before prompt templates were collected,
            # also when it names the file through a directory symlink. Templates are read
            # last, so they spend no part of the total-bytes budget that skills had.
            claimed = {*recorded, *walked, *imported}
            self._record_prompt_templates(
                [path for path in prompt_candidates if path not in claimed],
                recorded,
                files,
                result,
            )
            claimed.update(recorded, prompt_candidates)
            result.surfaces_excluded.extend(_linked_prompt_gaps(links, tree, claimed, files))
            # A spelling that a walk inventories is recorded and checked under its own
            # name; any other is a file the collector does not read.
            inventoried = {component.source_path for component in result.components}
            for variant, named in variants:
                if variant.as_posix() not in inventoried:
                    files.report_case_variant(variant, named)

        if not result.components and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("prompts (no instruction files found)")

        return result

    @staticmethod
    def _variant_importers(
        variants: list[tuple[Path, Path]],
        texts: dict[str, str],
        importers: set[str],
        skill_paths: set[str],
        files: ConfinedCollection,
    ) -> list[str]:
        """The spellings of CLAUDE.md and GEMINI.md that a walk inventories, whose imports
        a host that opens one under that name expands, and that are not importers yet.

        A subagent, rule or prompt directory walk has recorded its text already. A skill
        or command directory walk records its file after imports are followed, so the
        text is read here; a file that cannot be read is that walk's failure. A skill walk
        that follows a directory symlink reaches the file under the path it resolves to,
        so ``skill_paths``, the paths those walks reach, are matched as well as the skill
        directories.
        """
        found: dict[str, None] = {}
        for variant, canonical in variants:
            relative = variant.as_posix()
            if canonical.name not in _IMPORTING_NAMES or relative in found or relative in importers:
                continue
            if relative not in texts:
                if relative not in skill_paths and not any(
                    variant.parts[: len(parts)] == parts for parts in _SKILL_PARTS
                ):
                    continue
                content = _read_unless_credential(relative, files, None)
                if content is None:
                    continue
                try:
                    texts[relative] = content.decode("utf-8")
                except UnicodeDecodeError:
                    continue
            found[relative] = None
        return list(found)

    def _record(
        self,
        rel_path: str,
        prompt_type: str,
        content: bytes,
        files: ConfinedCollection,
        result: ScanResult,
        directory: str | None = None,
        *,
        escapes: bool = False,
    ) -> PromptComponent | None:
        """Record the instruction file read from ``rel_path``, or None.

        ``directory`` names the rule, prompt or subagent directory whose walk reached the
        file through a directory symlink; the record keeps it. With ``escapes``, what a
        prompt template's escapes decode to is checked for hidden characters too, and
        without it what the escapes in the front matter of a Markdown file decode to.

        Every walk reads through ``_read_unless_credential``; the check is repeated on
        the symlink the read followed, so no walk, and no import of a file a walk
        recorded, can bring an unkeyed digest of a credential file into the inventory.
        """
        target = files.link_target(rel_path)
        reason = _credential_gap(rel_path, target)
        if reason is not None:
            result.surfaces_excluded.append(f"{rel_path}: {reason}; not read or inventoried")
            return None
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            result.scan_failures.append(f"{rel_path}: invalid UTF-8 instruction")
            return None
        result.surfaces_scanned.append(rel_path)
        component = self._scan_instruction_file(
            Path(rel_path),
            rel_path,
            prompt_type,
            content,
            text,
            decoded=(
                _escaped_text(rel_path, text, result.surfaces_excluded)
                if escapes
                or _markup(rel_path)
                or PurePosixPath(rel_path).suffix.lower() in _ESCAPED_FORMATS
                else None
            ),
        )
        if target is not None:
            component.properties["symlink_target"] = target
        if directory is not None:
            component.properties["instruction_directory"] = directory
        if not _instruction_content(rel_path, prompt_type, target, directory):
            self._bind_content(rel_path, prompt_type, content, component, result)
        result.components.append(component)
        return component

    def _follow_imports(
        self,
        importers: list[str],
        texts: dict[str, str],
        recorded: dict[str, PromptComponent],
        files: ConfinedCollection,
        result: ScanResult,
        imported: set[str],
    ) -> None:
        """Inventory in-root files that memory files import with @path, to five hops.

        A host expands the imports of every file it loads this way, including a file
        the collector records under its own name, such as an imported AGENTS.md or a
        nested CLAUDE.md. Each target looked up, and each file whose imports are
        followed, counts against the operator's ``import-lookups`` limit, so at most that
        many times ``_MAX_IMPORTS`` references are resolved. Each lookup of a missing file
        lists the directories on its path for case variants, so file content must not be
        able to ask for an unbounded number of either.
        """
        pending = deque((path, 0) for path in importers)
        followed = set(importers)
        looked_up: set[str] = set()
        # Each path is one object that every reference to it shares.
        paths = {path: path for path in recorded}
        listing = _ImportListing()
        lookups = limits.bound("import-lookups")
        spent = 0

        def spend(importer: str) -> bool:
            nonlocal spent
            if spent >= lookups.value:
                result.scan_failures.append(
                    f"{importer}: @path imports past this file are not inventoried; "
                    + lookups.exceeded()
                )
                return False
            spent += 1
            return True

        while pending:
            importer, depth = pending.popleft()
            tokens = _import_tokens(texts[importer])
            if not tokens:
                continue
            if len(set(tokens)) > _MAX_IMPORTS:
                result.scan_failures.append(f"{importer}: too many @path imports to inventory")
                continue
            # A file found by a lookup was counted when it was looked up.
            if importer not in looked_up and not spend(importer):
                break
            imports: dict[str, None] = {}
            targets: list[str] = []
            outside = too_long = exhausted = False
            directory = PurePosixPath(importer).parent.parts
            for token in dict.fromkeys(token.rstrip(_TRAILING) for token in tokens):
                named, leaves, long = _resolve_import(directory, token)
                targets.extend(named)
                outside |= leaves
                too_long |= long
            for target in dict.fromkeys(targets):
                known = paths.get(target)
                if known is not None:
                    imports[known] = None
                    if known not in followed and depth + 1 <= _MAX_IMPORT_DEPTH:
                        followed.add(known)
                        pending.append((known, depth + 1))
                    continue
                if target in looked_up:
                    continue
                if not spend(importer):
                    exhausted = True
                    break
                looked_up.add(target)
                if _credential_shaped(target):
                    imported.add(target)
                    result.surfaces_excluded.append(
                        f"{target}: imported by {importer} but its name says it holds "
                        "credentials; not read or inventoried"
                    )
                    continue
                content = self._read_import(importer, target, files, result)
                if content is None:
                    imported.add(target)
                    if (real := files.link_target(target)) is not None:
                        imported.add(real)
                    continue
                if depth + 1 > _MAX_IMPORT_DEPTH:
                    result.surfaces_excluded.append(
                        f"{target}: imported more than {_MAX_IMPORT_DEPTH} hops from a memory "
                        "file and not inventoried"
                    )
                    continue
                # ``imported`` holds the file under each name, recorded or a failure, so the
                # prompt walk neither inventories nor reports it again.
                names = {target, files.link_target(target) or target}
                imported |= names
                component = self._record(
                    target,
                    "imported-instruction",
                    content,
                    files,
                    result,
                    escapes=any(_prompt_candidate(PurePosixPath(name)) for name in names),
                )
                if component is None:
                    continue
                component.bom_ref = f"prompt:import:{target}"
                recorded[target] = component
                paths[target] = target
                texts[target] = content.decode("utf-8")
                imports[target] = None
                followed.add(target)
                pending.append((target, depth + 1))
            if exhausted:
                break
            if outside:
                result.surfaces_excluded.append(
                    f"{importer}: imports a file outside the project root, which is not inventoried"
                )
            if too_long:
                result.surfaces_excluded.append(
                    f"{importer}: imports a path longer than {_MAX_PATH_BYTES} bytes or with a "
                    f"name longer than {_MAX_NAME_BYTES} bytes, which is not inventoried"
                )
            if imports and importer in recorded:
                listing.add(importer, imports, recorded[importer])
        listing.finish(recorded)

    @staticmethod
    def _bind_content(
        path: str,
        prompt_type: str,
        content: bytes,
        component: PromptComponent,
        result: ScanResult,
    ) -> None:
        """Bind the content of a file that is not an instruction file with the key, never
        an unkeyed digest.

        A Markdown file, or an instruction file a walk found by its name, is an
        instruction surface and keeps the unkeyed ``content_hash`` every instruction file
        carries, unless a symlink there leads to a file that is not Markdown (see
        ``_instruction_content``). Any other file, imported with @path, found in a rule,
        prompt or subagent directory, or behind such a symlink, is named by the checkout,
        so its exact bytes may hold configuration or secrets: an unkeyed digest of them
        would let anyone holding the inventory confirm guesses offline (see
        ``source_binding``). Its hash is withheld; with the operator key an HMAC binds
        the content, and without one the component says the content is unbound; prompt
        templates say so together, in one finding (see ``_record_prompt_templates``).
        """
        imported = prompt_type == "imported-instruction"
        subject = "Imported file" if imported else "File"
        component.content_hash = None
        component.properties["content_hash_withheld"] = (
            f"{subject.lower()} is not a Markdown instruction file; an unkeyed digest of its "
            "exact bytes could confirm guesses of secret values offline"
        )
        try:
            binding = value_binding(
                IMPORT_CONTENT_BINDING_PROFILE,
                {"path": path, "content": content.decode("utf-8")},
            )
        except BindingError as exc:
            result.scan_failures.append(f"{path}: {exc}")
            return
        if binding:
            component.properties.update(binding)
            return
        if prompt_type == PROMPT_TEMPLATE_TYPE:
            return
        component.risks.append(
            RiskAssessment(
                severity=RiskSeverity.LOW,
                category="completeness",
                detail=(
                    f"{subject} '{neutralize(path)}' {UNBOUND_VALUES_DETAIL}: its content, "
                    "which is not an instruction file and carries no unkeyed digest."
                ),
                recommendation=(
                    f"Set {SOURCE_BINDING_KEY_ENV} during collection to detect changes to "
                    "this file."
                ),
            )
        )

    @staticmethod
    def _read_import(
        importer: str, target: str, files: ConfinedCollection, result: ScanResult
    ) -> bytes | None:
        """An imported file's bytes, or None when it is absent, a directory or a gap.

        A symlink that leads to a file named as one that holds credentials is a gap
        whatever name imports it, so a Markdown name cannot bring the content hash of
        such a file into the inventory (see ``_read_unless_credential``).
        """
        if len(PurePosixPath(target).parts) > files.max_depth + 1:
            result.surfaces_excluded.append(
                f"{target}: imported by {importer} below the collection depth limit "
                "and not inventoried"
            )
            return None
        if files.excluded(target):
            # A host still loads it, as it would a dependency's instructions.
            result.surfaces_excluded.append(
                f"{target}: imported by {importer} but excluded from collection"
            )
            return None
        if files.is_directory(target):
            return None
        return _read_unless_credential(
            target, files, result, context=f"imported by {importer} but ", missing_ok=True
        )

    def _record_prompt_templates(
        self,
        candidates: list[str],
        recorded: dict[str, PromptComponent],
        files: ConfinedCollection,
        result: ScanResult,
    ) -> None:
        """Record each prompt file no other walk or import inventories, up to
        ``prompt-files``.

        Like a rule file, one that is not UTF-8 is a failure. Each is also checked for
        the hidden characters its escapes spell (see ``_escaped_text``). Without the
        operator key, the templates whose content is unbound share one low completeness
        finding, on the first of them, so a library of templates costs one point.
        """
        bound = limits.bound("prompt-files")
        unbound: list[PromptComponent] = []
        for count, relative in enumerate(candidates, start=1):
            if count > bound.value:
                result.scan_failures.append(
                    f"{relative}: prompt files from this one on are not inventoried; "
                    + bound.exceeded()
                )
                break
            content = _read_unless_credential(relative, files, result)
            if content is None:
                continue
            component = self._record(
                relative, PROMPT_TEMPLATE_TYPE, content, files, result, escapes=True
            )
            if component is None:
                continue
            recorded[relative] = component
            properties = component.properties
            if "content_hash_withheld" in properties and "static_value_binding" not in properties:
                unbound.append(component)
        if unbound:
            unbound[0].risks.append(_unbound_templates_risk(unbound))

    @staticmethod
    def _list_skills(
        files: ConfinedCollection,
    ) -> list[tuple[str, list[Path], list[Path]]]:
        """Each skill and command directory with the files its walk reaches and the
        default-excluded names it skipped, listed before prompt templates are recorded so
        a directory symlink to a ``prompts`` tree leaves those files to the skill walk.
        """
        listing: list[tuple[str, list[Path], list[Path]]] = []
        for directory in SKILL_DIRECTORIES:
            skipped: list[Path] = []
            listing.append((directory, list(files.iter_files(directory, skipped=skipped)), skipped))
        return listing

    def _scan_skills(
        self,
        listing: list[tuple[str, list[Path], list[Path]]],
        files: ConfinedCollection,
        result: ScanResult,
        reported: set[Path],
    ) -> None:
        seen: set[str] = set()
        for skill_dir, paths, skipped in listing:
            for path in paths:
                relative = path.as_posix()
                if relative in seen:
                    continue
                seen.add(relative)
                declaration = (
                    skill_dir not in _RESOURCE_DIRECTORIES
                    and path.suffix.lower() in _DECLARATION_SUFFIXES
                )
                read = self._skill_file(path, files, result, declaration=declaration)
                if read is None:
                    continue
                digest, risks = read
                result.surfaces_scanned.append(relative)
                result.components.append(
                    SkillPackageComponent(
                        bom_ref=f"skill:{relative}",
                        name=relative,
                        skill_type="skill" if declaration else "skill-resource",
                        hashes={"sha256": digest},
                        source_path=relative,
                        trust_tier=TrustTier.INTERNAL_UNVERIFIED,
                        risks=risks,
                    )
                )
            _report_skipped(skipped, reported, files)
        if not seen and not result.scan_failures and not result.surfaces_excluded:
            result.surfaces_scanned.append("skills (no skill or command files found)")

    @staticmethod
    def _skill_file(
        path: Path, files: ConfinedCollection, result: ScanResult, *, declaration: bool
    ) -> tuple[str, list[RiskAssessment]] | None:
        """A bundle file's digest and the hidden-character findings of its text.

        A file that ``_credential_gap`` names, by its own name or the name of the in-root
        file a symlink there leads to, is a gap and is not read, so the inventory carries
        no unkeyed digest of it; the bundle's other files are inventoried as usual. A
        symlink replaced after that check, so that the read followed it to such a file,
        is a failure.
        """
        relative = path.as_posix()
        text_file = declaration
        found = None if _credential_shaped(relative) else files.regular_file(path)
        reason = _credential_gap(relative, None if found is None else found[0].as_posix())
        if reason is not None:
            result.surfaces_excluded.append(f"{relative}: {reason}; not read or inventoried")
            return None
        if found is not None and found[1] > files.max_file_bytes and not text_file:
            # A large asset, such as a sample PDF, is streamed within the collection's
            # byte budget instead of being read whole: digested, and checked for hidden
            # characters when it is UTF-8 text, such as instructions SKILL.md points to.
            # The stream opens the file checked above, without following a symlink.
            return PromptScanner._stream_skill_file(found[0], relative, files)
        content = files.read_bytes(path)
        if content is None:
            return None
        followed = files.link_target(path)
        if followed is not None and _credential_shaped(followed):
            # The symlink was replaced after the check above.
            result.scan_failures.append(f"{relative}: file changed during collection")
            return None
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            if text_file:
                result.scan_failures.append(f"{relative}: invalid UTF-8 skill declaration")
                return None
            # An agent's reader still decodes such a file; check the text it would read.
            stream = _HiddenCharacterStream()
            stream.feed(content, final=True)
            return hash_bytes(content), [
                *_hidden_character_risks(stream.counts, stream.tags, relative),
                *_line_separator_risks(stream.line_separators, relative),
            ]
        markup = declaration and path.suffix.lower() in _MARKUP_SUFFIXES
        # A host reads a skill's front matter or structured JSON/YAML/TOML declarations decoded.
        decoded = (
            _escaped_text(relative, text, result.surfaces_excluded)
            if markup or path.suffix.lower() in _ESCAPED_FORMATS
            else None
        )
        risks = detect_invisible_characters(text, relative, decoded=decoded)
        if markup:
            risks.extend(detect_hidden_markup(text, relative))
        return hash_bytes(content), risks

    @staticmethod
    def _stream_skill_file(
        target: Path, relative: str, files: ConfinedCollection
    ) -> tuple[str, list[RiskAssessment]] | None:
        digest = hashlib.sha256()
        text = _HiddenCharacterStream()
        try:
            with files.open_regular(target, max_bytes=limits.bound("total-bytes")) as stream:
                while chunk := stream.read(65536):
                    digest.update(chunk)
                    text.feed(chunk)
        except (OSError, CollectionError):
            return None
        text.feed(b"", final=True)
        return f"sha256:{digest.hexdigest()}", [
            *_hidden_character_risks(text.counts, text.tags, relative),
            *_line_separator_risks(text.line_separators, relative),
        ]

    def _scan_instruction_file(
        self,
        path: Path,
        rel_path: str,
        prompt_type: str,
        raw: bytes,
        text: str,
        *,
        decoded: str | None = None,
    ) -> PromptComponent:
        content_hash = hash_bytes(raw)
        file_size = len(raw)
        risks: list[RiskAssessment] = []

        if file_size > 50_000:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.MEDIUM,
                    category="prompt_size",
                    detail=f"'{neutralize(rel_path)}' is {file_size:,} bytes — large prompts increase injection surface.",
                    recommendation="Review for unnecessary content.",
                )
            )

        risks.extend(detect_invisible_characters(text, rel_path, decoded=decoded))
        if _markup(rel_path):
            risks.extend(detect_hidden_markup(text, rel_path))

        return PromptComponent(
            bom_ref=f"prompt:{rel_path}",
            name=rel_path,
            prompt_type=prompt_type,
            content_hash=content_hash,
            source_path=path.as_posix(),
            trust_tier=TrustTier.INTERNAL_UNVERIFIED,
            risks=risks,
        )
