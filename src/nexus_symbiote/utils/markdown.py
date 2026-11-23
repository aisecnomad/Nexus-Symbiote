"""The text of a Markdown file outside its code, as CommonMark reads it.

A host that loads instructions written in Markdown, such as a Claude Code memory file,
takes ``@path`` imports from its text and not from its code. Which is which is decided
by the block structure of the whole file and by how backticks pair across the lines of
a paragraph, so a reader that looks at one line at a time can be led to take text for
code.

:func:`text_outside_code` reads blocks as commonmark.js, the reference implementation
of CommonMark 0.31.2, reads them: lines end only at CR, LF or CRLF, and block quotes,
list items, fenced and indented code, HTML blocks, headings and paragraphs start and
end where it starts and ends them. Code spans pair as CommonMark pairs them, with
backslash escapes. Where readers that hosts use, such as markdown-it and marked, read
the same text another way, or the reading turns on what is not modelled here, the
text is left as written, so that nothing a host may read as text is taken for code:
the rest of a paragraph after a bracket that can close a link and is followed by a
link label or by a destination that is not plain, or after a ``<`` that could open an
autolink or raw HTML holding a backtick or closing bracket; a paragraph that can open with a link
reference definition; and the whole file where such a definition, a lazy line indented
four columns or a form feed after a list marker can change the block structure, or
where containers nest or match past a bound. Indented code and HTML blocks are
returned as written too.

:func:`hidden_text` reads the same blocks for what a rendered view shows nothing of:
the link reference definitions that no link uses or that are written as comments, the
footnotes that nothing references or that repeat a label, and the raw HTML that HTML
parsers read as comments.
It errs the other way, toward reporting: a reference counts as a use only where every
reader, GitHub's included, makes a link of it that shows.
"""

from __future__ import annotations

import re
from bisect import bisect_left
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from itertools import groupby

_LINE_END = re.compile(r"\r\n|\r|\n")
# Containers nested this deep, or more container lines matched than the text has
# characters plus this many, make the whole text be returned: each blank line matches
# every open list item again.
_MAX_NESTING = 64
_SPARE_MATCHES = 4096
# Longer lines that could open an HTML block of kind 7 are read as ambiguous.
_MAX_OPEN_TAG_LINE = 4096
_CODE_INDENT = 4
_SPACE_OR_TAB = (" ", "\t")
_MAYBE_SPECIAL = re.compile(r"[#`~*+_=<>0-9-]")
_ATX_HEADING = re.compile(r"#{1,6}(?:[ \t]+|$)")
_OPENING_FENCE = re.compile(r"(?>`{3,})(?!.*`)|~{3,}")
_CLOSING_FENCE = re.compile(r"(?:`{3,}|~{3,})(?=[ \t]*$)")
_MARKED_FENCE_TAIL = re.compile(r"[~`]* *$")
_MARKED_FENCE_BREAK = re.compile(r" *(?:```|~~~)")
_MARKED_HTML_DISAGREES = re.compile(
    r"</(?:script|pre|style|textarea)|<(?:script|pre|style|textarea)[\w-]|</?meta\b", re.I
)
_THEMATIC_BREAK = re.compile(r"(?:(?:\*[ \t]*){3,}|(?:_[ \t]*){3,}|(?:-[ \t]*){3,})$")
_SETEXT_UNDERLINE = re.compile(r"(?:=+|-+)[ \t]*$")
_LIST_MARKER = re.compile(r"[*+-]|(\d{1,9})[.)]")
_LIST_STARTS = frozenset("*+-0123456789")
_NON_SPACE = re.compile(r"[^ \t\f\v\r\n]")
# Whitespace as the JavaScript readers that hosts use match it in HTML.
_JS_WHITESPACE = "\t\n\x0b\x0c\r \xa0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff"
_WHITESPACE = f"[{_JS_WHITESPACE}]"
_BLOCK_TAG_NAMES = (
    "address|article|aside|base|basefont|blockquote|body|caption|center|col|colgroup|dd"
    "|details|dialog|dir|div|dl|dt|fieldset|figcaption|figure|footer|form|frame|frameset"
    "|h[1-6]|head|header|hr|html|iframe|legend|li|link|main|menu|menuitem|nav|noframes|ol"
    "|optgroup|option|p|param|search|section|summary|table|tbody|td|tfoot|th|thead|title"
    "|tr|track|ul"
)


def _html_block_starts(
    whitespace: str, tag_names: str, declaration: str
) -> tuple[re.Pattern[str], ...]:
    open_tag = (
        rf"<[A-Za-z][A-Za-z0-9-]*(?:{whitespace}+[a-zA-Z_:][a-zA-Z0-9:._-]*"
        rf"(?:{whitespace}*={whitespace}*(?:[^\"'=<>`\x00-\x20]+|'[^']*'|\"[^\"]*\"))?)*"
        rf"{whitespace}*/?>"
    )
    close_tag = rf"</[A-Za-z][A-Za-z0-9-]*{whitespace}*>"
    return (
        re.compile(rf"<(?:pre|script|style|textarea)(?:{whitespace}|>|$)", re.I),
        re.compile(r"<!--"),
        re.compile(r"<\?"),
        re.compile(declaration),
        re.compile(r"<!\[CDATA\["),
        re.compile(rf"</?(?:{tag_names})(?:{whitespace}|/?>|$)", re.I),
        re.compile(rf"(?:{open_tag}|{close_tag}){whitespace}*$"),
    )


# The seven start conditions of an HTML block, and the end conditions of the first five;
# the last two end at a blank line.
_HTML_BLOCK_STARTS = _html_block_starts(_WHITESPACE, _BLOCK_TAG_NAMES, r"<![A-Za-z]")
# The same conditions as cmark-gfm 0.29, which GitHub renders with, reads them: only ASCII
# whitespace ends a tag name, `search` is no block tag, and a declaration starts with an
# upper-case letter, as markdown-it also reads it. Where the two readings start different
# blocks, a definition, footnote or import one of them hides can be text to the other.
_ASCII_HTML_BLOCK_STARTS = _html_block_starts(
    "[ \t\n\x0b\x0c\r]", _BLOCK_TAG_NAMES.replace("|search", ""), r"<![A-Z]"
)
_HTML_BLOCK_ENDS: tuple[re.Pattern[str] | str, ...] = (
    re.compile(r"</(?:pre|script|style|textarea)>", re.I),
    "-->",
    "?>",
    ">",
    "]]>",
)
"""End conditions of HTML block types 1 to 5; types 2 to 5 end at a literal string."""


def _ascii_html_block_agrees(kind: int, line: str, at: int, parent: str, lazy: bool) -> bool:
    """Whether cmark-gfm starts an HTML block of the same kind at ``at``: one that ends
    where a block of ``kind`` ends, the last two kinds both at a blank line."""
    for ascii_kind, start in enumerate(_ASCII_HTML_BLOCK_STARTS, 1):
        if start.match(line, at) and (ascii_kind < 7 or (parent != "paragraph" and not lazy)):
            return ascii_kind == kind or min(ascii_kind, kind) >= 6
    return False


def _html_block_end(kind: int, line: str, offset: int) -> tuple[int, int] | None:
    """Where the end condition of an HTML block of ``kind`` is met on ``line``, if it is."""
    end = _HTML_BLOCK_ENDS[kind - 1]
    if isinstance(end, str):
        found = line.find(end, offset)
        return None if found < 0 else (found, found + len(end))
    closing = end.search(line, offset)
    return None if closing is None else closing.span()


def _marked_html_block_starts() -> tuple[re.Pattern[str], ...]:
    """The HTML block starts of the marked lexer Claude Code bundles, read one line at a
    time: only spaces separate a tag name from its attributes, and a line end is ``$``.

    A closing tag whose ``>`` is on a later line also counts, since marked's white space
    there spans lines.
    """
    flags = re.I | re.A
    attribute = (
        r"(?: +[a-zA-Z:_][\w.:-]*"
        rf"(?: *= *\"[^\"]*\"| *= *'[^']*'| *= *[^{_JS_WHITESPACE}\"'=<>`]+)?)"
    )
    raw = "script|pre|style|textarea"
    return (
        re.compile(rf"<(?:{raw})(?:[{_JS_WHITESPACE}>]|$)", flags),
        re.compile(r"<!--"),
        re.compile(r"<\?"),
        re.compile(r"<![A-Z]", flags),
        re.compile(r"<!\[CDATA\["),
        re.compile(rf"</?(?:{_BLOCK_TAG_NAMES}|meta)(?: +|/?>|$)", flags),
        re.compile(
            rf"(?:<(?!{raw})[a-z][\w-]*{attribute}*? */?>(?=[ \t]*$)"
            rf"|</(?!{raw})[a-z][\w-]*[{_JS_WHITESPACE}]*(?:>[ \t]*)?$)",
            flags,
        ),
    )


_MARKED_HTML_BLOCK_STARTS = _marked_html_block_starts()
# What ends a paragraph in marked: only these, and only at the start of a line.
# marked's paragraph rule matches these without its block rules' `i` flag, so an
# upper-case `<DIV>` stays in the paragraph, where a code span may end before an import.
_MARKED_HTML_INTERRUPTS = re.compile(
    rf"</?(?:{_BLOCK_TAG_NAMES}|meta)(?: +|/?>|$)|<(?:script|pre|style|textarea|!--)",
    re.A,
)
_HTML_TAG_NAME = re.compile(r"</?([A-Za-z]+)")


def _marked_html_kind(line: str, at: int, interrupts: bool, indented: bool) -> int:
    """The kind of HTML block marked starts at ``at``, 0 for none, or -1 where it only
    ends the paragraph there and starts another."""
    if interrupts and (indented or not _MARKED_HTML_INTERRUPTS.match(line, at)):
        return 0
    for kind, start in enumerate(_MARKED_HTML_BLOCK_STARTS, 1):
        if start.match(line, at):
            return kind
    return -1 if interrupts else 0


# Inline: what pairs backticks, and what can take one out of a code span.
_INLINE_SPECIAL = re.compile(r"[\\`\[\]<]")
_BACKTICKS = re.compile(r"`+")
_IMPORT_FILENAME = re.compile(r"@\S+")
_ESCAPABLE = frozenset("!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~")
_DEFINITION = re.compile(r"\[(?:[^\\\[\]]|\\.){0,1000}\]:", re.S)
# After a link reference definition commonmark.js reads a line as part of its paragraph,
# while markdown-it and marked start a new block there: a line that is lazy, indented
# four columns, or that starts with one of these, can then start a different block.
_AFTER_DEFINITION = frozenset("<0123456789-*+=")
_TITLE_OPENERS = ('"', "'", "(")
# A destination that holds nothing a link could take out of a code span, read the same
# whether or not the brackets before it form a link.
_PLAIN_DESTINATION = re.compile(r"\([^\s()<>\[\]\\`\"']*\)")
# What an autolink or raw HTML would take from the text if a reader found one, which
# readers that follow different versions of CommonMark do not agree on.
_TAKEN = re.compile(r"[`\]]")


# Front matter, which hosts take out of a file before they read the rest as Markdown: a
# `---` line that opens the file, possibly naming a language, to the next closing delimiter
# line. Where a reader keeps it, YAML in it can open a code fence that runs to the end.
_FRONT_MATTER_OPEN = re.compile(r"\ufeff?---[ \t]*+(?:([A-Za-z]++)[ \t]*+)?(?:\r\n|\r|\n)")
_FRONT_MATTER_LINE_END = re.compile(r"\r\n|\r|\n")


class _AmbiguousError(Exception):
    """The block structure turns on what the reader does not model."""


class _HTMLDisagreementError(_AmbiguousError):
    """CommonMark and cmark-gfm recognize different HTML block starts."""


@dataclass(slots=True)
class _Block:
    kind: str
    lines: list[str] = field(default_factory=list)
    children: int = 0
    definitions: int = 0
    definition: bool = False
    marker: str = ""
    width: int = 0
    fence: str = ""
    fence_offset: int = 0
    html: int = 0
    html_tag: str = ""
    interrupted: bool = False
    suspects: list[int] = field(default_factory=list)
    after_code: bool = False


def front_matter_candidates(text: str) -> list[tuple[str, str, str]]:
    """Return ``(language, raw_front_matter, body)`` candidates for leading front matter.

    TOML and JSON front matter close only on ``---`` so a ``...`` line inside a multiline
    string cannot end them early. YAML front matter closes on ``---`` or ``...``; when
    ``...`` appears before a later ``---``, both readings are returned so neither a
    YAML-stream parser nor a ``---``-only parser (such as gray-matter) can hide content.
    """
    opened = _FRONT_MATTER_OPEN.match(text)
    if opened is None:
        return []
    language = (opened.group(1) or "").lower()
    allow_dots = language not in {"toml", "json"}
    candidates: list[tuple[str, str, str]] = []
    pos = opened.end()
    end = len(text)
    while pos < end:
        nl = _FRONT_MATTER_LINE_END.search(text, pos)
        line_end = end if nl is None else nl.start()
        next_pos = end if nl is None else nl.end()
        line = text[pos:line_end]
        if line.startswith("---") and not line[3:].strip(" \t"):
            candidates.append((language, text[opened.end() : pos], text[next_pos:]))
            break
        if allow_dots and not candidates and line.startswith("...") and not line[3:].strip(" \t"):
            candidates.append((language, text[opened.end() : pos], text[next_pos:]))
        pos = next_pos
    return candidates


def _union(first: tuple[str, ...] | list[str], second: tuple[str, ...] | list[str]) -> list[str]:
    """``first``, then each item of ``second`` that it holds fewer times than ``second``."""
    missing = Counter(second)
    missing.subtract(first)
    merged = list(first)
    for item in second:
        if missing[item] > 0:
            missing[item] -= 1
            merged.append(item)
    return merged


def _read_html_dialects(
    lines: list[str], size: int, *, include_fence: bool = False, marked: bool = False
) -> Iterator[_Reader]:
    """Preserve each complete, bounded block reading when the HTML dialects differ."""
    for ascii_html in (False, True):
        reader = _Reader(
            size + _SPARE_MATCHES, include_fence=include_fence, ascii_html=ascii_html, marked=marked
        )
        try:
            for line in lines:
                reader.read(line)
            reader.finish()
        except _AmbiguousError:
            # A nesting or work bound may end one paragraph's reading. Keep
            # the raw file and independently read the blank-delimited sections
            # so that this cannot discard evidence in later ordinary prose.
            reader.parts.clear()
            reader.blocks.clear()
            reader.recovered_blocks = True
            for nonblank, section in groupby(lines, key=lambda line: bool(line.strip(" \t"))):
                if not nonblank:
                    continue
                fragment = list(section)
                local = _Reader(
                    sum(map(len, fragment)) + len(fragment) + _SPARE_MATCHES,
                    include_fence=include_fence,
                    ascii_html=ascii_html,
                    marked=marked,
                )
                try:
                    for line in fragment:
                        local.read(line)
                    local.finish()
                except _AmbiguousError:
                    literal = "\n".join(fragment)
                    reader.parts.append(literal)
                    reader.blocks.append(("literal", literal))
                else:
                    reader.parts.extend(local.parts)
                    reader.blocks.extend(local.blocks)
        yield reader


def _only_html_disagrees(exc: _AmbiguousError, readers: list[_Reader]) -> bool:
    return (
        isinstance(exc, _HTMLDisagreementError)
        and len(readers) == 2
        and not any(r.recovered_blocks for r in readers)
    )


def _adjacent_container_imports(lines: list[str], eligible: set[str] | None = None) -> list[str]:
    """Recover only paired spans spanning consecutive prose lines with container marks."""
    parts: list[str] = []
    group: list[str] = []

    def finish() -> None:
        if len(group) > 1:
            content = "\n".join(group)
            if "`@" in content:
                paired = _outside_spans(content, import_boundaries_only=True)
                if paired != content:
                    parts.append(paired)
        group.clear()

    for line in lines:
        mark = _CONTAINER_MARKS.match(line)
        if mark is not None and mark[0].strip():
            bare = line[mark.end() :]
            if bare.strip() and (eligible is None or bare in eligible):
                # A new list item starts its own prose. A lone tick in the
                # previous item cannot close a code example in this one.
                if (
                    _LIST_MARKER.search(mark[0])
                    and group
                    and not (group[-1].startswith("`") and group[-1].strip("` \t"))
                ):
                    finish()
                group.append(bare)
                continue
        finish()
    finish()
    return parts


# A bullet or a `1.` item, which end a paragraph in marked.
_MARKED_ITEM_START = re.compile(r"(?<![0-9])(?:[*+-]|1[.)])(?=[ \t])")


def _marked_paragraph_imports(lines: list[str]) -> list[str]:
    """The code span boundaries of each run of lines that marked may read as one
    paragraph where CommonMark reads HTML: up to a blank line, or a bullet or a ``1.``
    item, which end a paragraph in marked. A code span can pair across the lines of a
    run and end right before an import."""
    parts: list[str] = []
    group: list[str] = []
    for line in (*lines, ""):
        mark = _CONTAINER_MARKS.match(line)
        text = line if mark is None else line[mark.end() :]
        if not text.strip(" \t") or (mark is not None and _MARKED_ITEM_START.search(mark[0])):
            content = "\n".join(group)
            if len(group) > 1 and "`@" in content:
                inline = _outside_spans(content, import_boundaries_only=True)
                if inline != content:
                    parts.append(inline)
            group.clear()
        if text.strip(" \t"):
            group.append(text)
    return parts


def _import_boundaries(
    blocks: list[tuple[str, str]], lines: list[str], *, containers: bool = False
) -> list[str]:
    if not any("`@" in line for line in lines):
        return []
    parts = []
    eligible: set[str] = set()
    for kind, content in blocks:
        if kind not in {"paragraph", "heading"}:
            continue
        if containers:
            eligible.update(content.split("\n"))
        if "`@" not in content:
            continue
        inline = _outside_spans(content, import_boundaries_only=True)
        if inline != content:
            parts.append(inline)
    if containers:
        parts.extend(_adjacent_container_imports(lines, eligible))
    return parts


def text_outside_code(text: str) -> list[str]:
    """The parts of ``text`` that a CommonMark reader does not read as code.

    Each paragraph and heading is one part, with its code spans replaced by a space;
    an HTML block or indented code line is returned as written, and fenced code is left
    out. A difference confined to HTML uses both complete block readings. Other
    ambiguities retain the whole file and container and inline-code boundaries. A file that opens
    with front matter is read both whole and without it, and the parts of either
    reading are returned. What Claude Code's marked reads as text is kept too: list item
    text as written, and the whole file where marked may read its blocks differently.
    """
    parts = _text_outside_code(text)
    for _, _, body in front_matter_candidates(text):
        parts = _union(parts, _text_outside_code(body))
    if (last := _unterminated_fence(text)) is not None:
        parts.append(last)
    return parts


def _unterminated_fence(text: str) -> str | None:
    """A last line with no line end that opens a fence and holds an @, as written.

    marked opens no fence there after a paragraph and reads the line as its text.
    """
    last = text[text.rfind("\n") + 1 :]
    if "@" in last and "\r" not in last:
        bare = _CONTAINER_MARKS.sub("", last, count=1).lstrip(" \t")
        if bare.startswith(("```", "~~~")):
            return last
    return None


def _text_outside_code(text: str) -> list[str]:
    lines = _LINE_END.split(text)
    if text.endswith("\n"):
        lines.pop()
    reader = _Reader(len(text) + _SPARE_MATCHES, marked=True)
    try:
        for line in lines:
            reader.read(line)
        reader.finish()
    except _AmbiguousError as exc:
        readers = list(_read_html_dialects(lines, len(text), marked=True))
        if _only_html_disagrees(exc, readers):
            # Both readings completed. Each keeps the prose and raw HTML it
            # sees, so a fence agreed by both cannot supply a real import.
            parts: list[str] = []
            for alternative in readers:
                parts = _union(
                    parts,
                    _union(
                        alternative.parts,
                        _import_boundaries(alternative.blocks, lines, containers=True),
                    ),
                )
            return parts
        # A quote marker or a closing code span can put an import at the start of
        # rendered text even when the raw file has no whitespace before its @.
        # Raw HTML has no inline code spans, unless marked reads it as text. A
        # repeated line that another reading places in prose must keep its possible
        # inline boundaries.
        marked_html = any(alt.marked_html for alt in readers)
        html_lines = (
            set()
            if marked_html
            else set.intersection(
                *(
                    {
                        line
                        for kind, block in alt.blocks
                        if kind == "html"
                        for line in block.split("\n")
                        if "`@" in line
                    }
                    for alt in readers
                )
            )
        )
        if html_lines:
            html_lines.difference_update(
                line
                for alt in readers
                for kind, block in alt.blocks
                if kind in {"paragraph", "heading", "literal"}
                for line in block.split("\n")
                if "`@" in line
            )
        alternatives = [text]
        for line in lines:
            if "@" in line:
                bare = _CONTAINER_MARKS.sub("", line, count=1)
                if bare != line:
                    alternatives.append(bare)
                if "`@" in bare and line not in html_lines and bare not in html_lines:
                    inline = _outside_spans(bare, import_boundaries_only=True)
                    if inline != bare:
                        alternatives.append(inline)
                        rendered = _outside_spans(bare)
                        if rendered != inline:
                            alternatives.append(rendered)
        if marked_html:
            alternatives.extend(_marked_paragraph_imports(lines))
        for alternative in readers:
            alternatives = _union(
                alternatives,
                _union(
                    alternative.parts,
                    _import_boundaries(alternative.blocks, lines, containers=True),
                ),
            )
        return alternatives
    return _union(reader.parts, _import_boundaries(reader.blocks, lines))


def commonmark_block_readings(text: str) -> dict[str, list[tuple[str, str]]]:
    """Each bounded reading with its own code and container boundaries."""
    lines = _LINE_END.split(text)
    if text.endswith("\n"):
        lines.pop()
    reader = _Reader(len(text) + _SPARE_MATCHES, include_fence=True, marked=True)
    try:
        for line in lines:
            reader.read(line)
        reader.finish()
    except _AmbiguousError as exc:
        # The raw reading keeps unmodeled evidence. A fenced example in that
        # reading must not hide a new prose instruction in another reading.
        readers = list(_read_html_dialects(lines, len(text), include_fence=True, marked=True))
        readings: dict[str, list[tuple[str, str]]] = {}
        if not _only_html_disagrees(exc, readers):
            readings["source"] = [("paragraph", "\n".join(lines))]
            bare = "\n".join(_CONTAINER_MARKS.sub("", line, count=1) for line in lines)
            # Removing container marks can join unrelated list items. Keep
            # the resulting text literal rather than pairing its ticks again.
            readings["containers"] = [("literal", bare)]
        for alternative in readers:
            readings["ascii" if alternative.ascii_html else "unicode"] = alternative.blocks
        return readings
    if (last := _unterminated_fence(text)) is not None:
        return {"common": [*reader.blocks, ("literal", last)]}
    return {"common": reader.blocks}


class _Reader:
    """commonmark.js block parsing, keeping only what decides code from text."""

    def __init__(
        self,
        matches: int,
        *,
        include_fence: bool = False,
        ascii_html: bool | None = None,
        marked: bool = False,
    ) -> None:
        self.matches = matches
        # Also keep what Claude Code's marked reads as text, for @path imports.
        self.marked = marked
        self.include_fence = include_fence
        self.ascii_html = ascii_html
        self.recovered_blocks = False
        self.parts: list[str] = []
        # Each paragraph, heading and HTML block as written, with its kind, in order.
        self.blocks: list[tuple[str, str]] = []
        # The paragraphs, setext headings and HTML blocks that cannot interrupt a paragraph
        # that start right after a line of text in indented code, in no container opened
        # on their line. Where that code continues a footnote, cmark-gfm reads it as a
        # paragraph and these blocks as its lazy lines.
        self.after_code: set[int] = set()
        self.code_text = self.after_code_text = self.opened = False
        self.prior_text = self.after_text = self.marked_item = self.marked_html = False
        self.marked_margin = -1
        self.marked_width = 1
        self.stack = [_Block("document")]
        self.line = ""
        self.offset = self.column = 0
        self.next_nonspace = self.next_column = self.indent = 0
        self.blank = self.indented = self.partial = False
        self.all_closed = True
        self.matched = 0
        # The first nonspace character after the offset, and its column; columns count
        # from the start of the line, so it stays found while the offset stays before it.
        self.found = (-1, 0)

    def _block_disagreement(self) -> None:
        """Keep raw evidence alongside a complete CommonMark reading."""
        if self.ascii_html is None:
            raise _AmbiguousError
        self.recovered_blocks = True

    def read(self, line: str) -> None:
        prior_text, self.prior_text = self.prior_text, bool(line.strip(" \t"))
        self.after_text = prior_text
        self.line = line
        self.offset = self.column = 0
        self.blank = self.partial = self.opened = False
        self.after_code_text, self.code_text = self.code_text, False
        self.found = (-1, 0)
        stack = self.stack
        old_tip = len(stack) - 1
        self.matches -= old_tip
        if self.matches < 0:
            raise _AmbiguousError
        container = 0
        for depth in range(1, len(stack)):
            self._find_next_nonspace()
            outcome = self._continue(stack[depth], depth == old_tip)
            if outcome == 2:
                return
            if outcome == 1:
                break
            container = depth
        self.all_closed = container == old_tip
        self.matched = container
        if (
            self.marked
            and self.ascii_html is not True
            and prior_text
            and self.prior_text
            and stack[-1].kind == "html"
            and any(b.kind == "quote" for b in stack[container + 1 :])
        ):
            # marked's block quote takes this line lazily where CommonMark ends the quote
            # and the HTML block in it.
            self.marked_html = True
            self._block_disagreement()
        # marked keeps the lines after a list item in it where CommonMark ends the item,
        # up to a blank line and then while lines are indented to the item's content,
        # unless a line opens a fence at the margin of the last item opened, when that
        # item is outside any container.
        if self.prior_text and not prior_text:
            self.marked_item &= len(line) - len(line.lstrip(" ")) >= self.marked_width
        if prior_text and self.prior_text and any(b.kind == "item" for b in stack[container + 1 :]):
            self.marked_item = True
        if (
            self.marked_item
            and (fence_break := _MARKED_FENCE_BREAK.match(line)) is not None
            and fence_break.end() - 3 <= self.marked_margin
        ):
            self.marked_item = False
        leaf = stack[container].kind in ("fence", "indented", "html")
        while not leaf:
            self._find_next_nonspace()
            if not self.indented and not _MAYBE_SPECIAL.match(line, self.next_nonspace):
                self._advance_next_nonspace()
                break
            started = self._start(container)
            if not started:
                self._advance_next_nonspace()
                break
            self.opened = self.opened or started == 1
            container = len(stack) - 1
            leaf = started == 2
        if not self.all_closed and not self.blank and stack[-1].kind == "paragraph":
            # markdown-it measures a lazy line's indentation from the content of the
            # container it left, where it can start a block.
            if stack[-1].definition or self.indented:
                self._block_disagreement()
            self._add_line()
            return
        self._close_unmatched()
        block = stack[container]
        if block.definition and (
            self.indented or self._peek(self.next_nonspace) in _AFTER_DEFINITION
        ):
            # Ambiguous only where the line is not part of a definition, such as its
            # title, which is known when the paragraph ends.
            block.suspects.append(len(block.lines))
        if block.kind in ("paragraph", "fence", "indented", "html"):
            if (
                self.marked
                and self.ascii_html is not True
                and block.interrupted
                and not self.indented
                and _SETEXT_UNDERLINE.match(line, self.next_nonspace)
            ):
                # marked reads the paragraph this block interrupted, and the block, as the
                # text of a setext heading.
                self.marked_html = True
                self._block_disagreement()
            self._add_line()
            if (
                1 <= block.html <= 5
                and (close := _html_block_end(block.html, line, self.offset)) is not None
            ):
                if (
                    self.marked
                    and self.ascii_html is not True
                    and self._marked_ends_elsewhere(block, line, close)
                ):
                    self.marked_html = True
                    self._block_disagreement()
                self._finalize()
        elif self.offset < len(line) and not self.blank:
            self._add_child("paragraph").after_code = self.after_code_text and not self.opened
            self._advance_next_nonspace()
            self._add_line()

    def finish(self) -> None:
        while len(self.stack) > 1:
            self._finalize()

    @staticmethod
    def _marked_ends_elsewhere(block: _Block, line: str, close: tuple[int, int]) -> bool:
        """Whether marked ends this HTML block at another place than CommonMark.

        marked ends a raw block only at the closing tag it opened with, and a processing
        instruction, declaration or CDATA section right after it closes, reading the rest
        of that line as a new block.
        """
        if block.html == 1:
            name = _HTML_TAG_NAME.match(line, close[0])
            return name is None or name.group(1).lower() != block.html_tag
        return block.html >= 3 and bool(line[close[1] :].strip(" \t"))

    def _peek(self, index: int) -> str:
        return self.line[index : index + 1]

    def _find_next_nonspace(self) -> None:
        index, column = self.found
        if index < self.offset:
            line, index, column = self.line, self.offset, self.column
            while index < len(line):
                char = line[index]
                if char == " ":
                    column += 1
                elif char == "\t":
                    column += 4 - column % 4
                else:
                    break
                index += 1
            self.found = (index, column)
        self.blank = index == len(self.line)
        self.next_nonspace, self.next_column = index, column
        self.indent = column - self.column
        self.indented = self.indent >= _CODE_INDENT

    def _advance_next_nonspace(self) -> None:
        self.offset, self.column, self.partial = self.next_nonspace, self.next_column, False

    def _advance(self, count: int, *, columns: bool) -> None:
        line = self.line
        while count > 0 and self.offset < len(line):
            if line[self.offset] == "\t":
                to_tab = 4 - self.column % 4
                if columns:
                    self.partial = to_tab > count
                    step = min(count, to_tab)
                    self.column += step
                    self.offset += 0 if self.partial else 1
                    count -= step
                else:
                    self.partial = False
                    self.column += to_tab
                    self.offset += 1
                    count -= 1
            else:
                self.partial = False
                self.offset += 1
                self.column += 1
                count -= 1

    def _continue(self, block: _Block, last: bool) -> int:
        """0 when ``block`` continues on this line, 1 when it does not, and 2 when the
        line closes a fence and holds nothing more."""
        kind = block.kind
        if kind == "quote":
            if self.indented and self._peek(self.next_nonspace) == ">":
                # markdown-it continues a block quote at a marker indented four columns.
                self._block_disagreement()
            if self.indented or self._peek(self.next_nonspace) != ">":
                return 1
            self._advance_next_nonspace()
            self._advance(1, columns=False)
            if self._peek(self.offset) in _SPACE_OR_TAB:
                self._advance(1, columns=True)
        elif kind == "item":
            if self.blank:
                if not block.children:
                    return 1
                if last and block.children == block.definitions:
                    # commonmark.js drops a paragraph that held only link reference
                    # definitions, after which a blank line ends an empty item.
                    self._block_disagreement()
                    return 1
                self._advance_next_nonspace()
            elif self.indent >= block.width:
                self._advance(block.width, columns=True)
            else:
                return 1
        elif kind == "fence":
            if self.indent <= 3 and self._peek(self.next_nonspace) == block.fence[0]:
                closing = _CLOSING_FENCE.match(self.line, self.next_nonspace)
                if closing is not None and len(closing.group()) >= len(block.fence):
                    self._finalize()
                    return 2
                if (
                    self.marked
                    and self.line.startswith(block.fence, self.next_nonspace)
                    and _MARKED_FENCE_TAIL.match(self.line, self.next_nonspace + len(block.fence))
                ):
                    # Claude Code's marked also closes on the opening run followed by any
                    # ~ or backticks, as in ```~, where CommonMark keeps reading code.
                    self._block_disagreement()
            skip = block.fence_offset
            while skip > 0 and self._peek(self.offset) in _SPACE_OR_TAB:
                self._advance(1, columns=True)
                skip -= 1
        elif kind == "indented":
            if self.indent >= _CODE_INDENT:
                self._advance(_CODE_INDENT, columns=True)
            elif self.blank:
                self._advance_next_nonspace()
            else:
                return 1
        elif kind == "html":
            return 1 if self.blank and block.html >= 6 else 0
        elif kind == "paragraph":
            return 1 if self.blank else 0
        elif kind in ("heading", "break"):
            return 1
        return 0

    def _start(self, container: int) -> int:
        """0 when no block starts here, 1 for a container and 2 for a leaf."""
        line, at = self.line, self.next_nonspace
        char = self._peek(at)
        parent = self.stack[container]
        if not self.indented:
            if char == ">":
                self._advance_next_nonspace()
                self._advance(1, columns=False)
                if self._peek(self.offset) in _SPACE_OR_TAB:
                    self._advance(1, columns=True)
                self._close_unmatched()
                self._add_child("quote")
                return 1
            heading = _ATX_HEADING.match(line, at) if char == "#" else None
            if heading is not None:
                self._advance_next_nonspace()
                self._advance(len(heading.group()), columns=False)
                self._close_unmatched()
                self._add_child("heading")
                self.parts.append(_outside_spans(line[self.offset :]))
                self.blocks.append(("heading", line[self.offset :]))
                self.offset = len(line)
                return 2
            fence = _OPENING_FENCE.match(line, at) if char in ("`", "~") else None
            if fence is not None:
                if self.marked and ("\t" in line[:at] or self.marked_item):
                    # marked widens each leading tab to four spaces, so it may read
                    # indented code here, or it may read this fence in a list item that
                    # ends it, and prose in what CommonMark fences.
                    self._block_disagreement()
                self._close_unmatched()
                block = self._add_child("fence")
                block.fence = fence.group()
                block.fence_offset = self.indent
                self._advance_next_nonspace()
                self._advance(len(block.fence), columns=False)
                return 2
            if char == "<":
                if (
                    self.marked
                    and self.ascii_html is not True
                    and _MARKED_HTML_DISAGREES.match(line, at)
                ):
                    # marked, which matches JavaScript's white space, reads these tags as
                    # text, or meta as a block, where CommonMark does the opposite.
                    self.marked_html = True
                    self._block_disagreement()
                lazy = not self.all_closed and not self.blank and self.stack[-1].kind == "paragraph"
                interrupts = parent.kind == "paragraph" or lazy
                starts = _ASCII_HTML_BLOCK_STARTS if self.ascii_html else _HTML_BLOCK_STARTS
                kind = next(
                    (kind for kind, start in enumerate(starts[:6], 1) if start.match(line, at)),
                    0,
                )
                if not kind and not interrupts:
                    if not self.ascii_html and len(line) - at > _MAX_OPEN_TAG_LINE:
                        # Unicode spaces are also unquoted-value characters, so the
                        # tag pattern backtracks quadratically over a long line.
                        raise _AmbiguousError
                    if starts[6].match(line, at):
                        kind = 7
                if self.marked and self.ascii_html is not True:
                    # marked's block quote continues on any line its paragraph rule takes,
                    # whatever block the quote holds.
                    quoted = (
                        not interrupts
                        and not self.all_closed
                        and self.after_text
                        and any(b.kind == "quote" for b in self.stack[self.matched + 1 :])
                    )
                    marked = _marked_html_kind(line, at, interrupts or quoted, at > self.offset)
                    if min(kind, 6) != min(marked, 6) or (kind == 3 and line.startswith("<?>", at)):
                        # marked starts another block here than CommonMark, or none: after
                        # a tab in a tag, at an indented start after a paragraph, or at a
                        # tag name with an underscore. The code spans of what it reads as
                        # text may end right before an import.
                        self.marked_html = True
                        self._block_disagreement()
                if kind:
                    if self.ascii_html is None and not _ascii_html_block_agrees(
                        kind, line, at, parent.kind, lazy
                    ):
                        raise _HTMLDisagreementError
                    self._close_unmatched()
                    block = self._add_child("html")
                    block.html = kind
                    block.after_code = kind == 7 and self.after_code_text and not self.opened
                    block.interrupted = interrupts
                    if kind == 1 and (name := _HTML_TAG_NAME.match(line, at)) is not None:
                        block.html_tag = name.group(1).lower()
                    return 2
            if (
                char in ("=", "-")
                and parent.kind == "paragraph"
                and _SETEXT_UNDERLINE.match(line, at)
            ):
                self._close_unmatched()
                content = "\n".join(parent.lines)
                if _DEFINITION.match(content) or _FOOTNOTE.search(content):
                    # A paragraph of nothing but definitions is no heading, and cmark-gfm
                    # ends the paragraph at a footnote. Retain the raw reading and the
                    # complete CommonMark heading reading of the rest of the file.
                    self._block_disagreement()
                self.parts.append(_outside_spans(content))
                if parent.after_code:
                    self.after_code.add(len(self.blocks))
                self.blocks.append(("heading", content))
                parent.kind, parent.lines = "heading", []
                self.offset = len(line)
                return 2
            if char in ("*", "_", "-") and _THEMATIC_BREAK.match(line, at):
                self._close_unmatched()
                self._add_child("break")
                self.offset = len(line)
                return 2
        if (
            char in _LIST_STARTS
            and (not self.indented or parent.kind == "list")
            and self._list_item(parent)
        ):
            return 1
        if self.indented and self.stack[-1].kind != "paragraph" and not self.blank:
            self._advance(_CODE_INDENT, columns=True)
            self._close_unmatched()
            self._add_child("indented")
            return 2
        return 0

    def _list_item(self, parent: _Block) -> bool:
        line, at = self.line, self.next_nonspace
        if self.indent >= _CODE_INDENT:
            return False
        marker = _LIST_MARKER.match(line, at)
        if marker is None:
            return False
        ordered = marker.group(1)
        if ordered is not None and parent.kind == "paragraph" and int(ordered) != 1:
            return False
        end = marker.end()
        if self._peek(end) not in ("", " ", "\t"):
            return False
        if parent.kind == "paragraph" and not _NON_SPACE.search(line, end):
            if line[end:].strip(" \t"):
                # A form feed or vertical tab is blank to commonmark.js, not to others.
                self._block_disagreement()
            return False
        self._advance_next_nonspace()
        self._advance(end - at, columns=True)
        spaces_column, spaces_offset = self.column, self.offset
        while True:
            self._advance(1, columns=True)
            if not (self.column - spaces_column < 5 and self._peek(self.offset) in _SPACE_OR_TAB):
                break
        spaces = self.column - spaces_column
        if spaces >= 5 or spaces < 1 or self._peek(self.offset) == "":
            padding = end - at + 1
            self.column, self.offset = spaces_column, spaces_offset
            if self._peek(self.offset) in _SPACE_OR_TAB:
                self._advance(1, columns=True)
        else:
            padding = end - at + spaces
        kind = ("ordered" + line[end - 1]) if ordered is not None else ("bullet" + line[at])
        self._close_unmatched()
        tip = self.stack[-1]
        if tip.kind != "list" or tip.marker != kind:
            self._add_child("list").marker = kind
        item = self._add_child("item")
        item.marker, item.width = kind, self.indent + padding
        # marked measures a tab after the marker differently.
        top = len(self.stack) == 3 and "\t" not in line[: self.offset]
        self.marked_margin = min(3, item.width - 1) if top else -1
        self.marked_width = item.width if top else 1
        return True

    def _add_line(self) -> None:
        tip = self.stack[-1]
        content = self.line[self.offset :]
        if tip.kind == "paragraph":
            if not tip.lines:
                tip.definition = _may_open_with_definition(content)
            tip.lines.append(content)
            if self.marked and self.marked_item and "`" in content and "@" in content:
                # The raw text of the list item marked still reads, as in _finalize.
                self.parts.append(content)
                self.blocks.append(("literal", content))
        elif tip.kind in ("indented", "html"):
            self.parts.append(content)
            tip.lines.append(content)
            self.code_text = tip.kind == "indented" and bool(content.strip(" \t"))
        elif self.include_fence and tip.kind == "fence":
            tip.lines.append(content)

    def _add_child(self, kind: str) -> _Block:
        while not _can_contain(self.stack[-1].kind, kind):
            self._finalize()
        if len(self.stack) > _MAX_NESTING:
            raise _AmbiguousError
        self.stack[-1].children += 1
        block = _Block(kind)
        self.stack.append(block)
        return block

    def _close_unmatched(self) -> None:
        if not self.all_closed:
            while len(self.stack) - 1 > self.matched:
                self._finalize()
            self.all_closed = True

    def _finalize(self) -> None:
        block = self.stack.pop()
        if block.after_code and block.kind in ("paragraph", "html"):
            self.after_code.add(len(self.blocks))
        if block.kind == "paragraph":
            content = "\n".join(block.lines)
            if block.suspects:
                leading = _leading_definitions_end(content, _definition_spans(content))
                starts = [0]
                for line in block.lines:
                    starts.append(starts[-1] + len(line) + 1)
                if any(starts[index] >= leading for index in block.suspects):
                    self._block_disagreement()
            if _DEFINITION.match(content):
                self.stack[-1].definitions += 1
            self.parts.append(_outside_spans(content))
            self.blocks.append(("paragraph", content))
            if (
                self.marked
                and "`" in content
                and "@" in content
                and any(b.kind == "item" for b in self.stack)
            ):
                # Claude Code reads imports from a list item's raw text, code spans and
                # all, where CommonMark and GitHub show code.
                self.parts.append(content)
                self.blocks.append(("literal", content))
        elif block.kind in ("html", "indented") or (self.include_fence and block.kind == "fence"):
            content = "\n".join(block.lines)
            self.blocks.append((block.kind, content))
            if (
                self.marked
                and block.kind == "html"
                and "`@" in content
                and (self.marked_item or any(b.kind == "item" for b in self.stack))
            ):
                # marked may read this as list item text, whose code spans can end
                # right before an import.
                inline = _outside_spans(content, import_boundaries_only=True)
                self.parts.append(inline)
                self.blocks.append(("literal", inline))


def _may_open_with_definition(line: str) -> bool:
    """Whether a paragraph whose first line is ``line`` may open with a definition: a
    label, then nothing, or a destination and nothing or what may open a title."""
    found = _DEFINITION.match(line)
    if found is None:
        return line.startswith("[") and "]" not in line
    rest = line[found.end() :].lstrip(" \t")
    close = rest.find(">") if rest.startswith("<") else -1
    if close >= 0:
        tail = rest[close + 1 :].lstrip(" \t")
        if not tail or tail.startswith(_TITLE_OPENERS):
            return True
    parts = rest.split(None, 1)
    return len(parts) < 2 or parts[1].startswith(_TITLE_OPENERS)


def _can_contain(parent: str, child: str) -> bool:
    if parent == "list":
        return child == "item"
    return parent in ("document", "quote", "item") and child != "item"


def _outside_spans(text: str, *, import_boundaries_only: bool = False) -> str:
    """``text`` with each code span replaced by a space, as CommonMark pairs backticks.

    A backslash escapes a backtick. What follows is left as written where a reader
    could take a backtick or a closing bracket into an autolink or raw HTML, every
    one of which ends at a ``>``; after a bracket that can close a link followed by a
    link label or by a destination that is not plain; and in a paragraph that can open
    with a link reference definition.
    """
    position = 0
    if _DEFINITION.match(text):
        if not import_boundaries_only:
            return text
        position = _leading_definitions_end(text, _definition_spans(text))
    runs: dict[int, list[int]] = {}
    for found_run in _BACKTICKS.finditer(text):
        runs.setdefault(found_run.end() - found_run.start(), []).append(found_run.start())
    last_close = text.rfind(">")
    taken = -1
    kept: list[str] = []
    copied = brackets = literal_end = 0
    positions = None
    while (found := _INLINE_SPECIAL.search(text, position)) is not None:
        position = found.start()
        char = text[position]
        if char == "\\":
            position += 2 if text[position + 1 : position + 2] in _ESCAPABLE else 1
        elif char == "`":
            run = _BACKTICKS.match(text, position)
            end = position + 1 if run is None else run.end()
            starts = runs.get(end - position, [])
            index = bisect_left(starts, end)
            if index == len(starts):
                position = end
            else:
                span_end = starts[index] + end - position
                # A real closing span may introduce an import. Keep any backticks
                # in that raw filename, and mask every unrelated span in this reading.
                keep_to = max(position, min(span_end, literal_end))
                kept.append(text[copied:keep_to])
                if keep_to < span_end:
                    kept.append(" ")
                copied = span_end
                if import_boundaries_only and span_end >= literal_end:
                    filename = _IMPORT_FILENAME.match(text, span_end)
                    if filename is not None:
                        literal_end = filename.end()
                position = span_end
        elif char == "<":
            position += 1
            if text[position : position + 1].strip():
                if taken < position:
                    after = _TAKEN.search(text, position)
                    taken = len(text) if after is None else after.start()
                if taken < last_close:
                    if not import_boundaries_only:
                        break
                    if positions is None:
                        positions = _Positions(text)
                    position = max(position, _html_end(positions, position - 1))
        elif char == "[":
            brackets += 1
            position += 1
        else:
            position += 1
            if brackets:
                brackets -= 1
                following = text[position : position + 1]
                if following == "[" or (
                    following == "(" and not _PLAIN_DESTINATION.match(text, position)
                ):
                    if not import_boundaries_only:
                        break
                    syntax = _LINK_LABEL if following == "[" else _LENIENT_INLINE_LINK
                    if (match := syntax.match(text, position)) is not None:
                        position = match.end()
    if import_boundaries_only and not literal_end:
        return text
    kept.append(text[copied:])
    return "".join(kept)


@dataclass(frozen=True, slots=True)
class HiddenText:
    """What a rendered view of a Markdown text shows nothing of, as written in it."""

    definitions: tuple[str, ...]
    """Link reference definitions that no link uses, every later one of a label, those
    written as comments, and footnotes that nothing references or that repeat a label."""
    html: tuple[str, ...]
    """Processing instructions, declarations, CDATA sections and, in HTML blocks, the
    other markup that HTML parsers read as comments; not ``<!--`` comments."""


@dataclass(slots=True)
class _Footnote:
    keys: tuple[str, str]
    text: list[str]
    reading: list[str]


def hidden_text(text: str) -> HiddenText:
    """The link reference definitions, footnotes and raw HTML of ``text`` that render
    as nothing.

    Blocks are read as :func:`text_outside_code` reads them, so code is left out. A
    definition is taken from the start of any line of a paragraph, with spaces or tabs
    between its parts, a title read as CommonMark reads it or, failing that, as running
    to the next line that ends with its closing quote or parenthesis, so that a reader
    that takes more definitions than commonmark.js does cannot hide one. A definition
    is visible only as the destination of the links that use it, so it is returned
    unless a reference that every reader takes for a link, with text that shows, names
    its label: references in code, raw HTML, autolinks, GitHub's extended autolinks and
    link destinations do not count, nor do those after a link this cannot settle. A
    definition written as a comment, with a ``#`` or ``<>`` destination, is returned
    wherever it is outside code, used or not and in HTML blocks too. A footnote, which
    GitHub drops when nothing references it, is returned with its continuation, as
    cmark-gfm reads it, unless a reference outside it, or in a footnote that is
    referenced, names it: its lazy lines, the indented code after it and the lines right
    after that code that start no block. HTML comments are left to the caller. A file
    whose blocks this cannot settle is read line by line, inside every container and
    code block, and each of its definitions and footnotes is returned, a footnote with
    each later run of lines that starts indented four columns. A file that opens with
    front matter is read both whole and without it, and what either reading hides is
    returned, each as often as the reading that holds it more often.
    """
    hidden = _hidden_text(text)
    for _, _, body in front_matter_candidates(text):
        in_body = _hidden_text(body)
        hidden = HiddenText(
            tuple(_union(hidden.definitions, in_body.definitions)),
            tuple(_union(hidden.html, in_body.html)),
        )
    return hidden


def _hidden_text(text: str) -> HiddenText:
    lines = _LINE_END.split(text)
    if text.endswith("\n"):
        lines.pop()
    reader = _Reader(len(text) + _SPARE_MATCHES)
    try:
        for line in lines:
            reader.read(line)
        reader.finish()
    except _AmbiguousError:
        return _hidden_in_whole(_LINE_END.sub("\n", text))
    spans: list[tuple[str, str]] = []
    comments: list[str] = []
    html: list[str] = []
    readings: list[str] = []
    notes: list[_Footnote] = []
    # cmark-gfm continues a footnote in the indented code after it, and in the lines
    # right after that code that start no block, as lazy lines of a paragraph.
    after_note = after_note_code = False
    for number, (kind, content) in enumerate(reader.blocks):
        lazy = after_note_code and number in reader.after_code
        after_note_code = False
        if kind == "indented":
            if after_note:
                notes[-1].text.append(content)
                try:
                    _collect_footnote_continuation(content, notes[-1], spans, comments, html)
                except _AmbiguousError:
                    return _hidden_in_whole(_LINE_END.sub("\n", text))
                after_note_code = True
            after_note = False
            continue
        after_note = lazy
        if kind == "html":
            if lazy:
                notes[-1].text.append(content)
            html += _hidden_html(content, block=True)
            comments += [
                content[start:end]
                for start, end, _, _ in _definition_spans(content)
                if _COMMENT_DEFINITION.match(content, start)
            ]
            continue
        if kind == "heading":
            html += _hidden_html(_outside_spans(content), block=False)
            if lazy:
                notes[-1].text.append(content)
                notes[-1].reading.append(content)
            else:
                readings.append(content)
            continue
        starts = [found.start() for found in _FOOTNOTE.finditer(content)]
        pieces = list(zip([0, *starts], [*starts, len(content)], strict=True))
        for index, (start, end) in enumerate(pieces):
            piece = content[start:end]
            marker = _FOOTNOTE.match(piece) if index else None
            if marker is not None:
                piece = " " * marker.end() + piece[marker.end() :]
            found, inline, reading = _read_paragraph(piece)
            spans += found
            html += _hidden_html(_outside_spans(inline), block=False)
            if marker is None and lazy:
                notes[-1].text.append(piece)
                notes[-1].reading.append(reading)
            elif marker is None:
                readings.append(reading)
            else:
                keys = _label_keys("^" + marker.group(1))
                notes.append(_Footnote(keys, [content[start:end].strip("\n")], [reading]))
        after_note = lazy or len(pieces) > 1
    defined = [_label_keys(label) for _, label in spans]
    folded = {keys[0] for keys in defined}
    lowered = {keys[1] for keys in defined}

    def is_defined(label: str) -> bool:
        keys = _label_keys(label)
        return keys[0] in folded or keys[1] in lowered

    used_folded: set[str] = set()
    used_lowered: set[str] = set()
    unreferenced: dict[str, list[_Footnote]] = {}
    # GitHub renders only the first footnote of a label, so each later one is hidden
    # whatever references it, and its own references are no uses.
    repeated: list[_Footnote] = []
    noted_folded: set[str] = set()
    noted_lowered: set[str] = set()
    for note in notes:
        fold, lower = note.keys
        if fold in noted_folded or lower in noted_lowered:
            repeated.append(note)
        else:
            unreferenced.setdefault(fold, []).append(note)
        noted_folded.add(fold)
        noted_lowered.add(lower)
    queue = readings[::-1]
    while queue:
        for label in _references(queue.pop(), is_defined):
            fold, lower = _label_keys(label)
            used_folded.add(fold)
            used_lowered.add(lower)
            waiting = unreferenced.get(fold)
            if waiting:
                queue += ["\n".join(note.reading) for note in waiting if note.keys[1] == lower]
                unreferenced[fold] = [note for note in waiting if note.keys[1] != lower]
    hidden: list[str] = []
    seen_folded: set[str] = set()
    seen_lowered: set[str] = set()
    for (definition, _), (fold, lower) in zip(spans, defined, strict=True):
        if (
            fold in seen_folded
            or lower in seen_lowered
            or fold not in used_folded
            or lower not in used_lowered
            or _COMMENT_DEFINITION.match(definition)
        ):
            hidden.append(definition)
        seen_folded.add(fold)
        seen_lowered.add(lower)
    hidden += comments
    hidden += ["\n".join(note.text) for waiting in unreferenced.values() for note in waiting]
    hidden += ["\n".join(note.text) for note in repeated]
    return HiddenText(tuple(hidden), tuple(html))


def _read_paragraph(content: str) -> tuple[list[tuple[str, str]], str, str]:
    """The definitions of the paragraph ``content`` with their labels, its inline text
    after the definitions that open it, and the text whose references count as uses."""
    found = _definition_spans(content)
    spans = [(content[start:end], label) for start, end, label, _ in found]
    leading = _leading_definitions_end(content, found)
    later = [(start, end) for start, end, _, _ in found if start >= leading]
    if any(_TAKEN_BY_INLINE.search(content, start, end) for start, end in later):
        return spans, content[leading:], ""
    cuts = [leading, *(edge for span in later for edge in span), len(content)]
    pairs = zip(cuts[::2], cuts[1::2], strict=True)
    return spans, content[leading:], "\n".join(content[a:b] for a, b in pairs)


def _collect_footnote_continuation(
    content: str,
    note: _Footnote,
    spans: list[tuple[str, str]],
    comments: list[str],
    html: list[str],
) -> None:
    """Collect definitions, hidden HTML and inline references from an indented footnote block."""
    sub = _Reader(len(content) + _SPARE_MATCHES)
    for line in content.split("\n"):
        sub.read(line)
    sub.finish()
    for sub_kind, sub_content in sub.blocks:
        if sub_kind == "html":
            html += _hidden_html(sub_content, block=True)
            comments += [
                sub_content[start:end]
                for start, end, _, _ in _definition_spans(sub_content)
                if _COMMENT_DEFINITION.match(sub_content, start)
            ]
        elif sub_kind == "heading":
            html += _hidden_html(_outside_spans(sub_content), block=False)
            note.reading.append(sub_content)
        elif sub_kind == "paragraph":
            found, inline, reading = _read_paragraph(sub_content)
            spans += found
            html += _hidden_html(_outside_spans(inline), block=False)
            note.reading.append(reading)


_ASCII_WHITESPACE = " \t\n\r\x0b\x0c"
_ASCII_SPACE_RUN = re.compile(f"[{_ASCII_WHITESPACE}]+")
_PUNCTUATION = re.escape("".join(sorted(_ESCAPABLE)))
# Labels longer than this make no link in commonmark.js.
_MAX_LABEL = 999
# What can open a code span or raw HTML that runs past the end of a definition or link,
# when a reader reads that definition or link as text.
_TAKEN_BY_INLINE = re.compile(r"[`<]")
_DESTINATION_STOP = re.compile(rf"[\\(){_ASCII_WHITESPACE}]")
# Markdown-it reads no definition with one of these destinations.
_REFUSED_SCHEME = re.compile(r"<?[ \t]*(?:javascript|vbscript|file|data):", re.I)
# A definition as a reader that takes one from any line of a paragraph reads it: a label
# on one line, then a destination on that line or the next, pointy or not.
_LENIENT_LABEL = re.compile(r"\[((?:[^\\\[\]\n]|\\[^\n])*+)\]:[ \t]*+\n?[ \t]*+")
_LENIENT_DESTINATIONS = (re.compile(r"<[^<>\n]*>"), re.compile(r"\S++"))
_BLANK_REST = re.compile(r"[ \t]*+(?=\n|\Z)")
_LINE_CLOSE = re.compile(r"([\"')])[ \t]*+(?=\n|\Z)")
# The comment idiom, `[//]: # (...)`, and any definition whose destination is `#` or `<>`.
_COMMENT_DEFINITION = re.compile(
    r"\[(?:(?://|comment|#)\]:[ \t]*+\n?[ \t]*+(?:#|<>)"
    r"|(?:[^\\\[\]]|\\.)*+\]:[ \t]*+\n?[ \t]*+(?:#|<#?>)(?=[ \t\n\"'(]|\Z))",
    re.I | re.S,
)
# A GitHub footnote definition, which can interrupt a paragraph.
_FOOTNOTE = re.compile(r"^[ \t]*+\[\^([^\]\s]++)\]:", re.M)


def _label_keys(label: str) -> tuple[str, str]:
    """``label`` as cmark folds it, and as the JavaScript readers fold it."""
    return (
        _ASCII_SPACE_RUN.sub(" ", label).strip(" ").casefold(),
        " ".join(label.split()).lower().upper(),
    )


def _escaped(text: str, index: int) -> bool:
    run = index
    while run > 0 and text[run - 1] == "\\":
        run -= 1
    return (index - run) % 2 == 1


class _Positions:
    """Searches of one text for the next occurrence of a string, each remembered, so
    that searches from later starts do not read the same text again."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.found: dict[tuple[str, bool], tuple[int, int]] = {}
        self.closes: dict[str, list[int]] | None = None

    def next(self, target: str, start: int, *, unescaped: bool = False) -> int:
        """The next ``target`` at or after ``start``; with ``unescaped``, the next that no
        backslash escapes."""
        key = (target, unescaped)
        known = self.found.get(key)
        if known is not None and known[0] <= start and (known[1] < 0 or start <= known[1]):
            return known[1]
        text = self.text
        index = text.find(target, start)
        while unescaped and index > 0 and _escaped(text, index):
            index = text.find(target, index + 1)
        self.found[key] = (start, index)
        return index

    def next_line_close(self, closer: str, start: int) -> int:
        """The next ``closer`` at or after ``start`` that ends its line, or -1."""
        if self.closes is None:
            self.closes = {char: [] for char in "\"')"}
            for found in _LINE_CLOSE.finditer(self.text):
                self.closes[found.group(1)].append(found.start())
        found_at = self.closes[closer]
        index = bisect_left(found_at, start)
        return found_at[index] if index < len(found_at) else -1


def _skip_gap(text: str, index: int, spaces: str) -> int:
    """Past the spaces at ``index``, at most one line ending and the spaces after it."""
    while index < len(text) and text[index] in spaces:
        index += 1
    if text.startswith("\n", index):
        index += 1
        while index < len(text) and text[index] in spaces:
            index += 1
    return index


def _line_end(text: str, index: int, spaces: str) -> int:
    while index < len(text) and text[index] in spaces:
        index += 1
    return index if index == len(text) or text[index] == "\n" else -1


def _destination_end(text: str, start: int) -> int:
    """The end of a destination that does not start with ``<``, or -1."""
    depth = 0
    index = start
    while (stop := _DESTINATION_STOP.search(text, index)) is not None:
        index = stop.start()
        char = text[index]
        if char == "\\":
            index += 2 if text[index + 1 : index + 2] in _ESCAPABLE else 1
            continue
        if char == "(":
            depth += 1
        elif char != ")" or not depth:
            break
        else:
            depth -= 1
        index += 1
    else:
        index = len(text)
    return -1 if index == start or depth else index


def _commonmark_end(positions: _Positions, colon: int, spaces: str) -> int:
    """The end of the definition whose label ends at ``colon``, as CommonMark reads it
    with ``spaces`` between its parts, or -1."""
    text = positions.text
    start = _skip_gap(text, colon + 1, spaces)
    if text.startswith("<", start):
        close = positions.next(">", start + 1, unescaped=True)
        if (
            close < 0
            or 0 <= positions.next("<", start + 1, unescaped=True) < close
            or 0 <= positions.next("\n", start + 1) < close
        ):
            return -1
        after = close + 1
    else:
        after = _destination_end(text, start)
        if after < 0:
            return -1
    title = _skip_gap(text, after, spaces)
    if after < title < len(text) and text[title] in "\"'(":
        closer = ")" if text[title] == "(" else text[title]
        close = positions.next(closer, title + 1, unescaped=True)
        if close >= 0 and not (
            closer == ")" and 0 <= positions.next("(", title + 1, unescaped=True) < close
        ):
            end = _line_end(text, close + 1, spaces)
            if end >= 0:
                return end
    return _line_end(text, after, spaces)


def _lenient_end(positions: _Positions, start: int) -> tuple[int, str]:
    """The end and label of the definition at ``start`` as the most lenient reader
    takes it, or -1: cmark-gfm takes a destination with unbalanced parentheses, and
    markdown-it a title right after a pointy destination; a title runs to the next line
    that ends with its closing quote or parenthesis."""
    text = positions.text
    head = _LENIENT_LABEL.match(text, start)
    if head is None:
        return -1, ""
    end = -1
    for pattern in _LENIENT_DESTINATIONS:
        destination = pattern.match(text, head.end())
        if destination is None:
            continue
        after = destination.end()
        title = _skip_gap(text, after, " \t")
        if title < len(text) and text[title] in "\"'(":
            closer = ")" if text[title] == "(" else text[title]
            close = positions.next_line_close(closer, title + 1)
            if close >= 0:
                end = max(end, _line_end(text, close + 1, " \t"))
        blank = _BLANK_REST.match(text, after)
        if blank is not None:
            end = max(end, blank.end())
    return end, head.group(1)


def _definition_spans(text: str) -> list[tuple[int, int, str, bool]]:
    """The start, end and label of each definition that starts a line of the paragraph
    ``text``, and whether commonmark.js and markdown-it both read it so."""
    positions = _Positions(text)
    spans = []
    line = 0
    while True:
        start = line
        while start < len(text) and text[start] in " \t":
            start += 1
        if text.startswith("[", start):
            close = positions.next("]", start + 1, unescaped=True)
            commonmark = -1
            if (
                close >= 0
                and text.startswith(":", close + 1)
                and not 0 <= positions.next("[", start + 1, unescaped=True) < close
            ):
                commonmark = _commonmark_end(positions, close + 1, " \t")
            lenient, lenient_label = _lenient_end(positions, start)
            end = max(commonmark, lenient)
            if end >= 0:
                label = text[start + 1 : close] if commonmark >= 0 else lenient_label
                agreed = (
                    commonmark == end
                    and len(label) <= _MAX_LABEL
                    and bool(label.strip(_ASCII_WHITESPACE))
                    and _commonmark_end(positions, close + 1, " ") == end
                    and not _REFUSED_SCHEME.match(text, _skip_gap(text, close + 2, " \t"))
                )
                spans.append((start, end, label, agreed))
                line = end
        newline = text.find("\n", line)
        if newline < 0:
            return spans
        line = newline + 1


def _leading_definitions_end(text: str, spans: list[tuple[int, int, str, bool]]) -> int:
    """The end of the definitions that open the paragraph ``text``, which every reader
    takes out of it before reading the rest as inline text."""
    end = 0
    for start, span_end, _, agreed in spans:
        if not agreed or text[end:start].strip(" \t") != ("\n" if end else ""):
            break
        end = span_end
    return end


_HTML_OPENER = re.compile(r"<(?:!--|\?|!\[CDATA\[|![A-Za-z])")
# In an HTML block, HTML parsers also read `<!` and `</` followed by what opens no
# comment, declaration or end tag as a comment that ends at the next `>`.
_BLOCK_HTML_OPENER = re.compile(r"<(?:!--|\?|!\[CDATA\[|!|/(?![A-Za-z>]))")
_HTML_CLOSERS = {"<?": "?>", "<![CDATA[": "]]>"}


def _hidden_html(text: str, *, block: bool) -> list[str]:
    """The processing instructions, declarations and CDATA sections in ``text``, and in
    an HTML ``block`` the other forms HTML parsers read as comments, outside the
    ``<!--`` comments that the caller counts, each ended where the caller ends it. In
    an HTML block one runs to the end of the block when it is not closed, and a
    backslash escapes nothing."""
    positions = _Positions(text)
    found = []
    position = 0
    opener_pattern = _BLOCK_HTML_OPENER if block else _HTML_OPENER
    while (opener := opener_pattern.search(text, position)) is not None:
        start = opener.start()
        if opener.group() == "<!--":
            close = positions.next("-->", start + 4)
            position = len(text) if close < 0 else close + 3
            continue
        closer = _HTML_CLOSERS.get(opener.group(), ">")
        close = positions.next(closer, opener.end())
        if not block and (close < 0 or _escaped(text, start)):
            position = start + 1
            continue
        stop = len(text) if close < 0 else close + len(closer)
        found.append(text[start:stop])
        position = stop
    return found


_DESTINATION_CHARACTER = rf"[^{_ASCII_WHITESPACE}()\\]|\\[{_PUNCTUATION}]|\\"
_LINK_TITLE = r"(?:\"(?:[^\"\\]|\\.)*+\"|'(?:[^'\\]|\\.)*+'|\((?:[^()\\]|\\.)*+\))"


def _inline_link(spaces: str) -> re.Pattern[str]:
    gap = f"{spaces}*+(?:\n{spaces}*+)?"
    destination = (
        r"(?><(?:[^<>\n\\]|\\[^\n])*+>"
        f"|(?!<)(?:{_DESTINATION_CHARACTER}|\\((?:{_DESTINATION_CHARACTER})*+\\))*+)"
    )
    title = f"(?:{gap}(?<=[{_ASCII_WHITESPACE}]){_LINK_TITLE})?+"
    return re.compile(f"\\({gap}{destination}{title}{gap}\\)", re.S)


# An inline link as commonmark.js reads one, nesting parentheses in its destination
# once; and as markdown-it reads one, which also takes tabs between its parts.
_INLINE_LINK = _inline_link(" ")
_LENIENT_INLINE_LINK = _inline_link("[ \t]")
_LINK_LABEL = re.compile(r"\[(?:[^\\\[\]]|\\.)*+\]", re.S)
_REFERENCE_SPECIAL = re.compile(r"[\\`\[\]<]")
_TAG_STOP = re.compile(r"[<>\"']")
_TAG_NAME = re.compile(r"[A-Za-z][A-Za-z0-9-]*")
_CLOSING_TAG = re.compile(rf"</[A-Za-z][A-Za-z0-9-]*[{_ASCII_WHITESPACE}]*+>")
_URI_AUTOLINK = re.compile(r"<[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\x00-\x20<>]*+>")
_EMAIL_AUTOLINK = re.compile(
    r"<[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]++@"
    r"(?>[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)"
    r"(?>\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*+>"
)
# GitHub's extended autolinks, which take the brackets in them out of the text: a URL
# after anything but a letter, or `www.` after a space, `*`, `_`, `~` or `(`, up to a
# space or `<`.
_EXTENDED_AUTOLINK = re.compile(r"(?:(?<![A-Za-z\[])(?:https?|ftp)://|(?<![^\s*_~(])www\.)[^\s<]*")
_ENTITY_OR_TAG = re.compile(
    r"&(?:#[0-9]{1,7}|#[xX][0-9a-fA-F]{1,6}|[A-Za-z][A-Za-z0-9]{0,31});|<[^<>]*>"
)


def _shows(text: str) -> bool:
    """Whether the text of a link shows anything but spaces and ASCII punctuation."""
    return any(
        not char.isspace() and char not in _ESCAPABLE for char in _ENTITY_OR_TAG.sub("", text)
    )


def _html_end(positions: _Positions, start: int) -> int:
    """The end of the raw HTML or autolink that may start at ``start``, or -1.

    An open tag runs to the first ``>`` outside its quoted values, so this ends at or
    after the end of any tag a reader finds there.
    """
    text = positions.text
    autolink = _URI_AUTOLINK.match(text, start) or _EMAIL_AUTOLINK.match(text, start)
    if autolink is not None:
        return autolink.end()
    if text.startswith("<!--", start):
        close = positions.next("-->", start + 2)
        if 0 <= close < start + 4:
            # Readers before CommonMark 0.31.2 do not close a comment with `<!-->`.
            close = max(close, positions.next("-->", start + 4))
        return close + 3 if close >= 0 else -1
    for opener, closer in _HTML_CLOSERS.items():
        if text.startswith(opener, start):
            close = positions.next(closer, start + len(opener))
            return close + len(closer) if close >= 0 else -1
    second = text[start + 1 : start + 2]
    third = text[start + 2 : start + 3]
    if second == "!" and third.isascii() and third.isalpha():
        close = positions.next(">", start + 2)
        return close + 1 if close >= 0 else -1
    if second == "/":
        closing = _CLOSING_TAG.match(text, start)
        return closing.end() if closing is not None else -1
    if not (second.isascii() and second.isalpha()):
        return -1
    name = _TAG_NAME.match(text, start + 1)
    following = "" if name is None else text[name.end() : name.end() + 1]
    if following and not following.isspace() and following not in "/>":
        return -1
    index = start + 1
    while (stop := _TAG_STOP.search(text, index)) is not None:
        char = stop.group()
        if char == ">":
            return stop.end()
        if char == "<":
            return -1
        close = positions.next(char, stop.end())
        if close < 0:
            return -1
        index = close + 1
    return -1


def _references(text: str, defined: Callable[[str], bool]) -> list[str]:
    """The labels that the references in the inline ``text`` name, as CommonMark pairs
    brackets after code spans, raw HTML and autolinks.

    A label counts only where every reader makes a link of it that shows: not in the
    text of an inline link, of a full reference or of a resolved image, not in a GitHub
    extended autolink, not with a ``|``, which a table cell can split, not as a link
    whose text shows only spaces and punctuation, and nothing after a link whose extent
    this cannot settle the same for every reader.
    """
    runs: dict[int, list[int]] = {}
    for found_run in _BACKTICKS.finditer(text):
        runs.setdefault(found_run.end() - found_run.start(), []).append(found_run.start())
    autolinks = [
        (found.start(), found.end())
        for found in _EXTENDED_AUTOLINK.finditer(text)
        if "[" in found.group() or "]" in found.group()
    ]
    autolink_starts = [start for start, _ in autolinks]
    positions = _Positions(text)
    entries: list[tuple[int, str]] = []
    openers: list[int] = []
    last_closed = -1

    def name(opened_at: int, label: str) -> None:
        if len(label) <= _MAX_LABEL and "|" not in label and label.strip(_ASCII_WHITESPACE):
            entries.append((opened_at, label))

    def drop_inside(opened_at: int) -> None:
        while entries and entries[-1][0] > opened_at:
            entries.pop()

    # Code, raw HTML and inline link destinations the scan skipped, in which no extended
    # autolink starts.
    skipped: list[int] = []

    def in_autolink(index: int) -> bool:
        found = bisect_left(autolink_starts, index + 1) - 1
        if found < 0 or index >= autolinks[found][1]:
            return False
        inside = bisect_left(skipped, autolink_starts[found] + 1)
        return inside % 2 == 0

    position = 0
    while (found := _REFERENCE_SPECIAL.search(text, position)) is not None:
        position = found.start()
        char = text[position]
        if char == "\\":
            position += 2 if text[position + 1 : position + 2] in _ESCAPABLE else 1
        elif char == "`":
            run = _BACKTICKS.match(text, position)
            end = position + 1 if run is None else run.end()
            starts = runs.get(end - position, [])
            index = bisect_left(starts, end)
            if index < len(starts):
                skipped += [position, starts[index] + end - position]
            position = end if index == len(starts) else starts[index] + end - position
        elif char == "<":
            end = _html_end(positions, position)
            if end < 0:
                position += 1
            elif "`" in text[position:end]:
                break
            else:
                skipped += [position, end]
                position = end
        elif autolinks and in_autolink(position):
            position += 1
        elif char == "[":
            openers.append(position)
            position += 1
        else:
            position += 1
            if not openers:
                continue
            opened = openers.pop()
            innermost = last_closed < opened
            last_closed = opened
            is_image = opened > 0 and text[opened - 1] == "!" and not _escaped(text, opened - 1)
            following = text[position : position + 1]
            if following == "(":
                link = _INLINE_LINK.match(text, position) if (innermost or is_image) else None
                if link is None:
                    link = _LENIENT_INLINE_LINK.match(text, position)
                    if link is None or _TAKEN_BY_INLINE.search(link.group()):
                        break
                if is_image:
                    drop_inside(opened)
                skipped += [position, link.end()]
                position = link.end()
                continue
            span_len = (position - 1) - (opened + 1)
            if following != "[":
                if innermost and span_len <= _MAX_LABEL:
                    label = text[opened + 1 : position - 1]
                    if is_image or _shows(label):
                        name(opened, label)
                continue
            reference = _LINK_LABEL.match(text, position)
            if reference is None:
                # Markdown-it takes balanced brackets here for a label, which names
                # nothing, where commonmark.js reads a shortcut reference.
                continue
            target = reference.group()[1:-1]
            if not innermost and not is_image:
                # Brackets around a link are text to commonmark.js, which then reads
                # the label after them as brackets of its own; markdown-it reads a
                # full reference.
                continue
            if not target:
                if is_image and not innermost:
                    drop_inside(opened)
                    position = reference.end()
                    continue
                if span_len <= _MAX_LABEL:
                    label = text[opened + 1 : position - 1]
                    if is_image or _shows(label):
                        name(opened, label)
            elif not defined(target):
                # Brackets followed by a label that names nothing are not a shortcut
                # reference either; the label is read again as brackets of its own.
                continue
            elif _TAKEN_BY_INLINE.search(target):
                break
            elif is_image:
                drop_inside(opened)
                name(opened, target)
            elif _shows(text[opened + 1 : position - 1]):
                name(opened, target)
            position = reference.end()
    return [label for _, label in entries]


_CONTAINER_MARKS = re.compile(r"^[ \t]*+(?:(?:>|[-*+](?=[ \t])|\d{1,9}[.)](?=[ \t]))[ \t]*+)*+")
# Block quote marks, each with the space after it that belongs to the mark.
_QUOTE_MARKS = re.compile(r"^(?:[ \t]*+> ?)*+")


def _chunks(text: str) -> list[tuple[bool, str]]:
    """The runs of lines of ``text`` between blank lines, each without its container
    marks, and whether its first line is indented four columns past its block quote
    marks, a tab counting as four."""
    chunks: list[tuple[bool, str]] = []
    lines: list[str] = []
    indented = False
    for line in text.split("\n"):
        bare = _CONTAINER_MARKS.sub("", line, count=1)
        if not bare:
            if lines:
                chunks.append((indented, "\n".join(lines)))
                lines = []
            continue
        if not lines:
            rest = _QUOTE_MARKS.sub("", line, count=1)
            indent = rest[: len(rest) - len(rest.lstrip(" \t"))]
            indented = "\t" in indent or len(indent) >= _CODE_INDENT
        lines.append(bare)
    if lines:
        chunks.append((indented, "\n".join(lines)))
    return chunks


def _hidden_in_whole(text: str) -> HiddenText:
    """Every definition and footnote at the start of a line, past any container marks,
    and all the hidden HTML of ``text`` read as one HTML block. A footnote runs to the
    next footnote or blank line, and on through each run of lines after that whose first
    line is indented four columns, as cmark-gfm continues it."""
    definitions: list[list[str]] = []
    note = -1
    for indented, chunk in _chunks(text):
        if note >= 0 and indented:
            definitions[note].append(chunk)
        else:
            note = -1
        definitions += [[chunk[start:end]] for start, end, _, _ in _definition_spans(chunk)]
        starts = [marker.start() for marker in _FOOTNOTE.finditer(chunk)]
        ends = [*starts[1:], len(chunk)] if starts else []
        for start, end in zip(starts, ends, strict=True):
            definitions.append([chunk[start:end]])
            note = len(definitions) - 1
    return HiddenText(
        tuple("\n\n".join(parts) for parts in definitions),
        tuple(_hidden_html(text, block=True)),
    )
