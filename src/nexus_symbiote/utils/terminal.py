"""Neutralize untrusted text and report output failures for the command-line tools."""

from __future__ import annotations

import errno
import os
import re
from pathlib import Path

import click

from nexus_symbiote.utils.files import OutputRefusedError, write_output_file

# C0/C1 controls move the cursor or rewrite earlier output; bidirectional and
# invisible format characters (every Unicode format character, category Cf, as of
# Unicode 15.1) disguise text, and so does every other default-ignorable code point
# (Default_Ignorable_Code_Point, assigned or not), which renders as nothing or as a
# blank: variation selectors, which encode hidden bytes as U+E0100 + b, Hangul and
# Khmer fillers, the combining grapheme joiner and U+2065, U+FFF0 to U+FFF8 and
# U+E0000 to U+E0FFF. Inventory and checkout data may contain any of them.
# Line breaks are included: a file name or component name containing one could
# forge whole output lines, and in CI a line starting with "::" is a workflow command.
# Such text must not start a line either; safe_line() gives every line a fixed prefix.
# Every noncharacter is included, U+FDD0 to U+FDEF and the last two code points of each
# plane: unassigned for ever, some terminals drop them. Private-use characters are not:
# a font draws them as some visible glyph, and they cannot move the cursor or hide text.
# A tab (U+0009) is not either: it becomes one space (neutralize), so a name stays
# readable but cannot line text up under a later column.
UNSAFE_TEXT = re.compile(
    r"[\x00-\x08\x0a-\x1f\x7f-\x9f\xad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891"
    r"\u08e2\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028\u2029\u202a-\u202e"
    r"\u2060-\u206f\u3164\ufdd0-\ufdef\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\ufff9-\ufffb"
    r"\ufffe\uffff\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3"
    r"\U0001d173-\U0001d17a\U000e0000-\U000e0fff"
    r"\U0001fffe\U0001ffff\U0002fffe\U0002ffff\U0003fffe\U0003ffff\U0004fffe\U0004ffff"
    r"\U0005fffe\U0005ffff\U0006fffe\U0006ffff\U0007fffe\U0007ffff\U0008fffe\U0008ffff"
    r"\U0009fffe\U0009ffff\U000afffe\U000affff\U000bfffe\U000bffff\U000cfffe\U000cffff"
    r"\U000dfffe\U000dffff\U000efffe\U000effff\U000ffffe\U000fffff\U0010fffe\U0010ffff]"
)

OUTPUT_REFUSED = (
    "Cannot write the output file: its directory must exist, no directory on the path "
    "may be a symbolic link, and an existing output must not be a directory, device, "
    "FIFO or socket, or a link to one."
)
DASH_OUTPUT = (
    "An output path of '-' is not standard output: leave out the output option to print "
    "to standard output, or give an absolute path to write a file named '-'."
)


# CI runners act on a "##name[" introducer anywhere in a line, not only at its start:
# GitHub Actions' legacy "##[command]" form, Azure Pipelines' "##vso[" and TeamCity's
# "##teamcity[". A replacement character after the "##" breaks each one visibly.
LOG_COMMAND = re.compile(r"##(?=[A-Za-z]*\[)")
_JSON_LOG_COMMAND = re.compile(r"(##[A-Za-z]*)\[")


def neutralize(value: object) -> str:
    """Replace every character that can rewrite or disguise terminal and CI output.

    Apply it to a whole output line, not to its pieces: two harmless pieces, such as a
    name ending in "##" and a following "[", can join into a CI log command. A tab
    becomes one space, every other such character U+FFFD.
    """
    return LOG_COMMAND.sub("##\ufffd", UNSAFE_TEXT.sub("\ufffd", str(value).replace("\t", " ")))


def safe_line(prefix: str, *values: object) -> str:
    """One neutralized output line that starts with a fixed, visible prefix.

    Inventory and checkout text must never begin a line: GitHub Actions treats a line
    that starts with "::", after leading white space, as a workflow command.
    """
    if not prefix.strip():
        raise ValueError("an output line needs a visible fixed prefix")
    return neutralize(prefix + "".join(map(str, values)))


def echo_line(prefix: str, *values: object, err: bool = False) -> None:
    """Print safe_line(prefix, *values) as plain text, without markup or wrapping.

    Plain text is printed as it is, so untrusted text never passes through a markup
    parser, a highlighter or a line wrapper, any of which can rewrite it, split it onto
    a new line or take time quadratic in its length.
    """
    click.echo(safe_line(prefix, *values), err=err)


_JSON_UNSAFE_TEXT = re.compile(
    r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\xad\u034f\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891"
    r"\u08e2\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2028\u2029\u202a-\u202e"
    r"\u2060-\u206f\u3164\ufdd0-\ufdef\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufff8\ufff9-\ufffb"
    r"\ufffe\uffff\U000110bd\U000110cd\U00013430-\U0001343f\U0001bca0-\U0001bca3"
    r"\U0001d173-\U0001d17a\U000e0000-\U000e0fff"
    r"\U0001fffe\U0001ffff\U0002fffe\U0002ffff\U0003fffe\U0003ffff\U0004fffe\U0004ffff"
    r"\U0005fffe\U0005ffff\U0006fffe\U0006ffff\U0007fffe\U0007ffff\U0008fffe\U0008ffff"
    r"\U0009fffe\U0009ffff\U000afffe\U000affff\U000bfffe\U000bffff\U000cfffe\U000cffff"
    r"\U000dfffe\U000dffff\U000efffe\U000effff\U000ffffe\U000fffff\U0010fffe\U0010ffff]"
)


def _json_escape_char(match: re.Match[str]) -> str:
    point = ord(match.group(0))
    if point <= 0xFFFF:
        return f"\\u{point:04x}"
    offset = point - 0x10000
    high = 0xD800 + (offset >> 10)
    low = 0xDC00 + (offset & 0x3FF)
    return f"\\u{high:04x}\\u{low:04x}"


def json_text(text: str) -> str:
    """JSON text in which no CI runner can find a "##name[" log command or hidden control.

    In valid JSON, "##" and non-whitespace format/control code points occur only inside
    strings, where RFC 8259 ``\\uXXXX`` escapes stand for the exact same characters.
    """
    escaped = _JSON_UNSAFE_TEXT.sub(_json_escape_char, text)
    return _JSON_LOG_COMMAND.sub(lambda match: match.group(1) + "\\u005b", escaped)


# What the output rules themselves produce: a missing directory, a link or file on
# the path (O_NOFOLLOW gives ELOOP, ENOTDIR or, on BSD, EMLINK), or a directory as
# the target; a special file is OutputRefusedError. Anything else, such as EACCES, ENOSPC
# or a kernel EINVAL, is reported by its system message.
_REFUSALS = frozenset({errno.ENOENT, errno.ELOOP, errno.EMLINK, errno.ENOTDIR, errno.EISDIR})


def output_failure(exc: BaseException) -> click.ClickException:
    """A plain command error for an output that was not written; never names the path."""
    if (
        isinstance(exc, OSError)
        and not isinstance(exc, OutputRefusedError)
        and exc.errno is not None
        and exc.errno not in _REFUSALS
    ):
        return click.ClickException(f"Cannot write the output file: {os.strerror(exc.errno)}.")
    return click.ClickException(OUTPUT_REFUSED)


def refuse_dash_output(path: Path | str) -> None:
    """Refuse ``-``, which here would name a file, not standard output."""
    if Path(path) == Path("-"):
        raise click.ClickException(DASH_OUTPUT)


def write_cli_output(path: Path, data: str, *, overwrite: bool = True) -> None:
    """Write a selected output file, turning any failure into a plain command error."""
    refuse_dash_output(path)
    try:
        write_output_file(path, data, overwrite=overwrite)
    except (OSError, ValueError) as exc:
        raise output_failure(exc) from exc
