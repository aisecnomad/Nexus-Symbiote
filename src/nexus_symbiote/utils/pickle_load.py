"""An abstract interpreter of ``pickle.load`` that never imports, calls or builds objects.

``load_segment`` reads one pickle from a byte sample the way ``pickle.load`` reads it
from ``io.BytesIO``, as the C unpickler (``"c"``) or the pure-Python one (``"py"``)
does: the same reads and frame handling, the same stack, MARK and memo rules and the
same errors, opcode by opcode. ``find_class`` imports the module before it looks the
name up, and ``importlib`` imports a file of any name, so it fails only for a module no
finder can name (empty, with a NUL, or with a ``/`` in a dotted part); otherwise it
returns an opaque object, which
a real import may make any module attribute: a class, a function, ``os.environ``,
``builtins.__dict__``. Every opcode that hands that object to anything but the stack
and the memo ends the walk as a call: calling it, ``__new__``, BUILD, SETITEM(S),
APPEND(S) and ADDITEMS on it, hashing it as a key or set item, iterating or testing it
as arguments or state, and the type checks a builtin of the right type would pass. A
call is ``certain`` when a class that records each of its methods would record one
there, and not certain when only an object of another type gets past the check.
``persistent_load``, which ``torch.load`` defines, returns an inert object for a
storage, which runs nothing it is given, and, as its legacy format's does for a
``("module", obj, ...)`` id, ``obj`` itself, whatever the pickle resolved. Builtin
values are modelled by what decides the loader's next step: their type, length, whether
they hash, and the strings ``STACK_GLOBAL`` takes.

The sample may be a prefix of the file: a read past its end, or past the opcode and
MARK budget, ends the walk as unread, since the loader's behaviour is not decided.
A read past the end of the file is decided without the bytes it misses, and so is a
text argument that the sample cuts short when what it shows already fails, such as a
STRING that opens with no quote: text that is no pickle ends or fails long before
either bound, while a pickle padded to reach one is left undecided.

The loader that reads the file may run on any supported CPython, 3.11 to 3.14, and the
unpicklers differ between them (``VERSION_DIFFERENCES``). Where they do, each flavor
takes the step that any version takes and that goes further: it accepts what one
version accepts and another rejects, so a call that one version reaches is rated
whatever version the scan runs on. ``Segment.differs`` names each such step a walk
took, where the running version may stop or go on. Where the next step depends on the
file object as well, as when the C unpickler of 3.11 or 3.12 reads past the end of a
frame, ``load_segments`` follows each way.
"""

from __future__ import annotations

import codecs
import re
import struct
import sys
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Literal, cast

Flavor = Literal["c", "py"]
FLAVORS: tuple[Flavor, ...] = ("c", "py")
Outcome = Literal["stop", "error", "unread", "called"]
_HIGHEST_PROTOCOL = 5

# Where the unpicklers of the supported CPython versions part, by the CPython branches'
# Lib/pickle.py (``_Unpickler``) and Modules/_pickle.c. Each key names a step that
# ``Segment.differs`` reports. The interpreter takes the behaviour that goes further.
VERSION_DIFFERENCES: dict[str, str] = {
    "int-base": (
        "INT and LONG read their text in base 0 up to 3.13 and in base 10 from 3.14:"
        " pickle.py load_int int(data, 0) -> int(data), load_long int(val, 0) ->"
        " int(val); _pickle.c load_int strtol(s, &endptr, 0) and"
        " PyLong_FromString(s, NULL, 0) -> base 10, load_long PyLong_FromString(s,"
        " NULL, 0) -> base 10. So 'I017' fails the pure-Python unpickler up to 3.13,"
        " is 15 to the C one up to 3.13 and 17 to both from 3.14; '0x1f' is read up to"
        " 3.13 only. Either reading is accepted; of two values, the C one in base 0,"
        " the smaller, passes every index and byte check the other passes."
    ),
    "frame-bounds": (
        "The C unpickler of the 3.11 and 3.12 branches only reads a FRAME into its"
        " buffer (_pickle.c load_frame: _Unpickler_Read(self, &s, frame_len), then"
        " rewinds), and a FRAME may start inside another; a read past the buffer's"
        " end drops what is left of it and reads on from the file"
        " (_Unpickler_ReadImpl, _Unpickler_Readline: _Unpickler_ReadFromFile), which"
        " is the frame's end when the file was read() (io.BytesIO) and where the"
        " pickle stands when the frame came from peek() (a buffered file). From the"
        " 3.13 branch it caps the input at frame_end, and a read that crosses it fails"
        " (_Unpickler_LeaveFrame: 'pickle exhausted before end of frame'), as does a"
        " FRAME before it ('beginning of a new frame before end of current frame')."
        " The pure-Python _Unframer fails both in every version. The C flavor reads"
        " on, both from the frame's end and from where it stands."
    ),
    "binstring-count": (
        "The C unpickler's BINSTRING reads its count unsigned in 3.11 and 3.12"
        " (_pickle.c load_counted_binstring: calc_binsize) and fails a negative one"
        " from 3.13 (calc_binint: 'BINSTRING pickle has negative byte count'); the"
        " pure-Python load_binstring fails a negative one in every version. The C"
        " flavor reads the unsigned count."
    ),
    "string-encoding": (
        "Not a version but a loader argument: STRING, BINSTRING and SHORT_BINSTRING"
        " decode their bytes by the Unpickler's encoding, 'ASCII' by default, which"
        " fails a byte over 0x7f; torch.load passes 'utf-8', np.load and"
        " pandas.read_pickle 'latin1', and 'bytes' keeps them as bytes. The value is"
        " read as latin-1, which decodes any byte, and READONLY_BUFFER takes it as"
        " the bytes that 'bytes' leaves."
    ),
    "int-digits": (
        "Not a version but a loader setting: int() and PyLong_FromString refuse a"
        " decimal literal longer than the process's int_max_str_digits (4,300 by"
        " default, 640 at least, 0 for none: PYTHONINTMAXSTRDIGITS, -X"
        " int_max_str_digits, sys.set_int_max_str_digits). INT, LONG, GET and PUT"
        " text is read as a loader with no limit reads it, whatever limit the scan"
        " runs under. Past 640 significant digits, an INT or LONG value stands for a"
        " number past every bound, which is all a walk reads of it, and a GET or PUT"
        " index keys the memo by its sign and significant digits."
    ),
}
# Differences that change no step here: find_class resolves a dotted name through
# _getattribute / get_dotted_path in 3.14, without the '<locals>' check of 3.11-3.13,
# and any module a finder can name resolves here; the C unpickler looks persistent_load up
# once per load from 3.13 (_pickle.c load) instead of at construction.


def _unimportable(module: str) -> bool:
    """Whether ``__import__(module)`` fails before any module code can run.

    On CPython 3.11-3.12, ``FrozenImporter`` matches frozen stdlib modules (``os``, ``io``,
    ``runpy``, ...) via C-string comparison, truncating ``module`` at the first ``\\x00``.
    """
    head = module.split("\x00", 1)[0]
    return not head or any("/" in part for part in head.split("."))


class _LoadError(Exception):
    """The loader raises here: ``pickle.load`` stops."""


class _UnreadError(Exception):
    """The loader's next step depends on bytes or opcodes past the inspection bounds."""


class _CallError(Exception):
    """The loader hands an object that ``find_class`` returned to code that uses it."""

    def __init__(self, certain: bool = True) -> None:
        super().__init__()
        self.certain = certain


class _Opaque:
    """An object that ``find_class`` returned: any attribute of an importable module."""

    __slots__ = ()


class _String(str):
    """A STRING, BINSTRING or SHORT_BINSTRING value: a str, or bytes under ``encoding="bytes"``."""

    __slots__ = ()


class _Persistent:
    """What ``persistent_load`` returned: an object the loader made, such as a storage."""

    __slots__ = ()


class _Tuple:
    """A tuple, with what ``hash()`` of it does, which cannot change once it is built.

    Tuples that share items, as DUP then TUPLE2 builds them, form a graph whose paths
    double with each level: walking it at each hash would take exponential time for a
    pickle of a few dozen bytes, and a deep one would exhaust the recursion limit.
    """

    __slots__ = ("hashed", "items")

    def __init__(self, items: tuple[object, ...]) -> None:
        self.items = items
        self.hashed = _hash_outcome(items)


class _Sized:
    """A list, dict, set, frozenset, bytearray or read-only view of one, by its length."""

    __slots__ = ("kind", "length", "string_keys")

    def __init__(self, kind: str, length: int = 0) -> None:
        self.kind = kind
        self.length = length
        self.string_keys = True


_NO_KWARGS = object()
_ITERABLE = (str, bytes, _Tuple, _Sized)


def _use(value: object, *, certain: bool = True) -> None:
    """The loader hands ``value`` to code: a resolved object makes that a call."""
    if isinstance(value, _Opaque):
        raise _CallError(certain)


_HashOutcome = Literal["call", "unhashable"] | None


def _hash_outcome(items: tuple[object, ...]) -> _HashOutcome:
    """What ``hash()`` of a tuple of ``items`` meets first, hashing them in order: a
    resolved object, whose hash runs (``"call"``), an unhashable item, or neither.

    A nested tuple contributes its own outcome, computed when it was built, so this is
    linear in ``items``. A ``_Sized`` keeps its kind for life, so the outcome holds.
    """
    for item in items:
        if isinstance(item, _Opaque):
            return "call"
        if isinstance(item, _Tuple):
            if item.hashed is not None:
                return item.hashed
        elif isinstance(item, _Sized) and item.kind not in ("frozenset", "view"):
            return "unhashable"
    return None


def _hash(value: object) -> None:
    """``hash(value)``: a tuple hashes its items in order; a resolved object runs its hash."""
    _use(value)
    if isinstance(value, _Tuple):
        if value.hashed == "call":
            raise _CallError(True)
        if value.hashed == "unhashable":
            raise _LoadError  # unhashable type
    elif isinstance(value, _Sized) and value.kind not in ("frozenset", "view"):
        raise _LoadError  # unhashable type


def _kind(value: object, kind: str) -> bool:
    return isinstance(value, _Sized) and value.kind == kind


def _truth(value: object) -> bool:
    if isinstance(value, (type(None), bool, int, float)):
        return bool(value)
    if isinstance(value, (str, bytes)):
        return bool(value)
    if isinstance(value, _Tuple):
        return bool(value.items)
    if isinstance(value, _Sized):
        return value.length > 0
    return True


def _byte(value: object) -> None:
    _use(value)  # __index__
    if not isinstance(value, int) or not 0 <= value < 256:
        raise _LoadError


@dataclass
class Budget:
    """Opcodes and MARKs left for every pickle of one sample."""

    opcodes: int
    marks: int


@dataclass(frozen=True)
class Segment:
    """How one ``pickle.load`` ends.

    ``resolved`` says whether it reached ``find_class`` and ``named`` whether a call
    of it returned, for a module that a finder can name. A ``called``
    pickle is ``certain`` unless only an object of the right type gets that far. After
    a STOP, ``resumes`` holds where the next ``pickle.load`` starts: where the loader
    left ``io.BytesIO``, then, when different, right after the STOP, as the C
    unpickler leaves a buffered file it peeked ahead in. ``differs`` names the
    ``VERSION_DIFFERENCES`` the walk relied on, and ``crossings`` counts the frame ends
    the C unpickler read past, where ``load_segment``'s ``jumps`` choose how.
    """

    outcome: Outcome
    resolved: bool
    named: bool = False
    resumes: tuple[int, ...] = ()
    certain: bool = True
    differs: frozenset[str] = frozenset()
    crossings: int = 0


_Valid = Callable[[bytes], bool]
_NUMBER_TEXT = re.compile(rb"[ \t\v\f\r\x1c-\x1f]*[0-9A-Za-z_.+\-]*[ \t\v\f\r\x1c-\x1f]*")


def _numeric_text(part: bytes) -> bool:
    """Whether INT, LONG, FLOAT, GET or PUT text that starts with ``part`` may parse.

    Before a NUL, which ends the C unpickler's text, one token of bytes that some
    ``int()``, ``float()`` or ``strtol`` syntax takes (``1_0``, ``0x1f``, ``-inf``),
    with white space only around it.
    """
    return _NUMBER_TEXT.fullmatch(part.split(b"\x00")[0]) is not None


def _utf8_text(part: bytes) -> bool:
    """Whether a GLOBAL line that starts with ``part`` may decode as UTF-8.

    The unpicklers decode the module and the name and then import the module before
    they look the name up. ``importlib`` imports a file whose name is no identifier,
    such as ``ev-il.py``, so only text that cannot decode fails before the import. A
    multi-byte character that the sample cuts short may still complete.
    """
    try:
        part.decode("utf-8")
    except UnicodeDecodeError as error:
        return error.reason == "unexpected end of data" and error.end == len(part)
    return True


def _quoted_text(part: bytes) -> bool:
    """Whether a STRING argument that starts with ``part`` may open with its quote."""
    return part[:1] in (b"", b'"', b"'")


def _ascii_text(part: bytes) -> bool:
    return part.isascii()


_STRTOL = {
    0: re.compile(rb"[ \t\n\v\f\r]*[+-]?(?:0[xX][0-9a-fA-F]+|0[0-7]*|[1-9][0-9]*)"),
    10: re.compile(rb"[ \t\n\v\f\r]*[+-]?[0-9]+"),
}
_LONG_MIN, _LONG_MAX = -(2**63), 2**63 - 1
_LONG_DIGITS = 22  # octal digits of 2**64; no C long needs more in base 8 or 10


def _c_int(data: bytes, base: int) -> int | None:
    """The C unpickler's INT: ``strtol`` up to a newline or NUL, else ``PyLong_FromString``."""
    text = data.split(b"\x00")[0]  # a C string
    match = _STRTOL[base].match(text)
    end = match.end() if match else 0  # no digits: strtol stops where it started, at 0
    value = 0
    if match:
        signed = match.group().strip()
        digits = signed.lstrip(b"+-")
        if base == 0 and digits[1:2] in (b"x", b"X"):
            value = int(digits[2:], 16)
        else:
            # strtol takes any run of leading zeros, but int() refuses a decimal literal
            # longer than sys.get_int_max_str_digits(): 4,301 zeros load in the C
            # unpickler and must not end the walk. More significant digits than any C
            # long holds overflow strtol, so PyLong_FromString (_py_int) decides.
            significant = digits.lstrip(b"0") or b"0"
            if len(significant) > _LONG_DIGITS:
                value = _LONG_MAX + 1
            else:
                value = int(significant, 8 if base == 0 and digits[:1] == b"0" else 10)
        value = -value if signed[:1] == b"-" else value
    if text[end : end + 1] in (b"", b"\n") and _LONG_MIN <= value <= _LONG_MAX:
        return value
    return _py_int(text, base)


_DIGIT_FLOOR = 640  # the lowest int_max_str_digits CPython accepts
_BEYOND = 10**_DIGIT_FLOOR  # above every memo index, byte, length and C long


def _decimal_literal(data: bytes, base: int) -> tuple[bool, bytes] | None:
    """A decimal literal as int() reads one, as its sign and significant digits.

    ASCII whitespace around, a sign, digits with single underscores between them, and in
    base 0 no leading zero unless all are. Base 0's 0x, 0o and 0b literals have
    power-of-two bases, which no digit limit applies to, so int() decides those.
    """
    if base not in (0, 10):
        return None
    text = data.strip(b" \t\n\v\f\r")
    sign = text[:1] if text[:1] in (b"+", b"-") else b""
    body = text[len(sign) :]
    digits = body.replace(b"_", b"")
    if (
        not digits.isdigit()
        or body[:1] == b"_"
        or body[-1:] == b"_"
        or b"__" in body
        or (base == 0 and digits[:1] == b"0" and digits.strip(b"0"))
    ):
        return None  # not a literal: refused under any limit
    significant = digits.lstrip(b"0") or b"0"
    return sign == b"-" and significant != b"0", significant


def _py_int(data: bytes, base: int) -> int | None:
    """``int(data, base)`` as a loader with no ``int_max_str_digits`` limit reads it."""
    try:
        return int(data, base)
    except ValueError:
        pass
    literal = _decimal_literal(data, base)
    if literal is None:
        return None
    negative, significant = literal
    # An INT or LONG value is read only for its sign, whether it is zero and whether it
    # fits a bound (a byte, an index, a C long), so a literal past the floor stands for
    # one past every bound: no conversion, which C-flavour walks would repeat at each
    # frame end. A memo index is keyed by _memo_key instead.
    value = _BEYOND if len(significant) > _DIGIT_FLOOR else int(significant)
    return -value if negative else value


MemoKey = int | tuple[bool, bytes]


def _memo_key(data: bytes) -> MemoKey | None:
    """GET and PUT text as both unpicklers key the memo, with no digit limit.

    Both read it in base 10 (pickle.py int(), _pickle.c PyLong_FromString). Up to the
    floor the key is the exact integer; past it, the sign and the significant digits,
    which name the same integer however it is written, so two different indexes never
    share a key. No int() is tried first: a long index costs no conversion on any walk.
    """
    literal = _decimal_literal(data, 10)
    if literal is None:
        return None
    negative, significant = literal
    if len(significant) > _DIGIT_FLOOR:
        return negative, significant
    value = int(significant)
    return -value if negative else value


def _digit_limited(data: bytes) -> bool:
    """Whether some loader's ``int_max_str_digits`` can refuse this INT, LONG or memo text."""
    return len(data) - len(data.translate(None, b"0123456789")) > _DIGIT_FLOOR


_C_FLOAT = re.compile(
    rb"[+-]?(?:(?:[0-9]+\.?[0-9]*|\.[0-9]+)(?:[eE][+-]?[0-9]+)?|inf(?:inity)?|nan)"
    rb"(?:\x00[^\n]*)?\n",
    re.IGNORECASE,
)


class _Machine:
    """One ``Unpickler(stream).load()`` from ``start``.

    Both read a FRAME as a unit that ends at ``self.frame``: a read that crosses its end
    fails, and one that starts at its end reads on from the file. The C unpickler also
    wants the whole frame, every byte a read asks for and a newline after each line;
    before 3.13 it reads on past the frame's end (``_cross_frame``).
    """

    def __init__(
        self,
        sample: bytes,
        size: int,
        start: int,
        flavor: Flavor,
        budget: Budget,
        jumps: tuple[bool, ...] = (),
    ) -> None:
        self.sample = sample
        self.whole = len(sample) >= size
        self.size = size
        self.pos = start
        self.frame: int | None = None
        self.c = flavor == "c"
        self.budget = budget
        self.stack: list[object] = []
        self.marks: list[int] = []
        self.memo: dict[MemoKey, object] = {}
        self.resolved = False
        self.named = False
        self.differs: set[str] = set()
        self.jumps = jumps
        self.crossings = 0

    # -- reads -----------------------------------------------------------------------

    def _take(self, start: int, end: int) -> bytes:
        """File bytes ``start:end``; past the sample, unread, or short at the file's end.

        A read that ends past the file's end is decided without the bytes it misses: the
        C unpickler fails it as truncated, and the pure-Python one reads short and then
        meets the end of the file, so nothing after it runs.
        """
        if end > len(self.sample) and not self.whole:
            if end > self.size:
                raise _LoadError  # pickle data was truncated, or EOFError after it
            raise _UnreadError
        return self.sample[start:end]

    def _cross_frame(self) -> None:
        """A read past the frame's end, which the C unpickler reads on from before 3.13.

        The ``crossings``-th one reads on from the frame's end when ``jumps`` says so,
        and from where it stands otherwise.
        """
        if not self.c:
            raise _LoadError  # pickle exhausted before end of frame
        self.differs.add("frame-bounds")
        if self.crossings < len(self.jumps) and self.jumps[self.crossings]:
            assert self.frame is not None
            self.pos = self.frame
        self.crossings += 1
        self.frame = None

    def read(self, count: int) -> bytes:
        if self.frame is not None:
            if self.pos >= self.frame and count:
                self.frame = None
            elif self.frame - self.pos < count:
                self._take(self.pos, self.frame)
                self._cross_frame()
        data = self._take(self.pos, self.pos + count)
        if self.c and len(data) < count:
            raise _LoadError  # pickle data was truncated
        self.pos += len(data)
        return data

    def _line(self, end: int, valid: _Valid | None = None) -> bytes | None:
        """The line from ``pos`` if it ends before ``end``; ``None`` if it does not.

        A line that runs past the sample fails when ``valid`` rejects what it shows, as
        the opcode rejects any line that starts so.
        """
        newline = self.sample.find(b"\n", self.pos, end)
        if newline < 0:
            if valid is not None and not self.whole and not valid(self.sample[self.pos :]):
                raise _LoadError
            self._take(self.pos, end)
            return None
        data = self.sample[self.pos : newline + 1]
        self.pos = newline + 1
        return data

    def readline(self, valid: _Valid | None = None) -> bytes:
        if self.frame is not None and self.pos < self.frame:
            data = self._line(self.frame)
            if data is not None:
                return data
            self._cross_frame()
        self.frame = None
        # Not inside a frame, where the C unpickler of 3.11 and 3.12 may read on elsewhere.
        data = self._line(len(self.sample) + 1, valid)
        if data is None:
            if self.c:
                raise _LoadError  # pickle data was truncated
            data = self.sample[self.pos :]
            self.pos = len(self.sample)
        return data

    def line(self, valid: _Valid | None = None) -> bytes:
        """A text argument without its newline; the C unpickler wants a character too."""
        data = self.readline(valid)
        if self.c and len(data) < 2:
            raise _LoadError
        return data[:-1]

    def number(self, width: int, form: str) -> int:
        data = self.read(width)
        if len(data) < width:
            raise _LoadError
        value: int = struct.unpack(form, data)[0]
        return value

    # -- stack -----------------------------------------------------------------------

    def _floor(self) -> int:
        return self.marks[-1] if self.marks else 0

    def push(self, value: object) -> None:
        self.stack.append(value)

    def pop(self) -> object:
        if len(self.stack) <= self._floor():
            raise _LoadError  # stack underflow
        return self.stack.pop()

    def top(self) -> object:
        if len(self.stack) <= self._floor():
            raise _LoadError
        return self.stack[-1]

    def pop_mark(self) -> list[object]:
        if not self.marks:
            raise _LoadError  # could not find MARK
        floor = self.marks.pop()
        items = self.stack[floor:]
        del self.stack[floor:]
        return items

    def _marked(self) -> list[object] | None:
        """The C unpickler's items to add after a MARK, or ``None`` when there are none.

        The item they are added to sits below the MARK, inside any enclosing one.
        """
        if not self.marks:
            raise _LoadError
        if self.marks[-1] <= (self.marks[-2] if len(self.marks) > 1 else 0):
            raise _LoadError
        return self.pop_mark() or None

    def resolve(self, module: str, name: str) -> None:
        """``find_class(module, name)``, which imports ``module`` before it reads ``name``.

        ``importlib`` imports a file of any name, such as ``ev-il.py`` or ``e x.py``, and
        a module's ``__getattr__`` answers any name, so neither has to be an identifier.
        Only a module that no finder can name fails before an import runs: an empty
        one, one holding a NUL, or one with a ``/`` in a dotted part, which no file or
        directory name holds.
        """
        self.resolved = True
        if _unimportable(module):
            raise _LoadError  # ValueError or ModuleNotFoundError, before any import runs
        self.named = True
        self.push(_Opaque())

    # -- the loop --------------------------------------------------------------------

    def run(self) -> Segment:
        try:
            while True:
                key = self.read(1)
                if not key:
                    raise _LoadError  # EOFError
                handler = _DISPATCH.get(key[0])
                if handler is None:
                    raise _LoadError  # invalid load key
                if self.budget.opcodes <= 0:
                    raise _UnreadError
                self.budget.opcodes -= 1
                if handler is _Machine.op_stop:
                    self.pop()
                    return self._segment("stop", self._resumes())
                handler(self)
        except _CallError as call:
            return self._segment("called", certain=call.certain)
        except (_UnreadError, RecursionError):
            # No step here recurses on the input; should one, what the loader does next
            # is not decided, which is not the same as the loader stopping.
            return self._segment("unread")
        except (_LoadError, ValueError, UnicodeError, OverflowError, struct.error):
            return self._segment("error")

    def _segment(
        self, outcome: Outcome, resumes: tuple[int, ...] = (), certain: bool = True
    ) -> Segment:
        return Segment(
            outcome,
            self.resolved,
            self.named,
            resumes,
            certain,
            frozenset(self.differs),
            self.crossings,
        )

    def _resumes(self) -> tuple[int, ...]:
        if self.frame is None or self.frame <= self.pos:
            return (self.pos,)
        return (self.frame, self.pos) if self.c else (self.frame,)

    # -- opcodes ---------------------------------------------------------------------

    def op_stop(self) -> None:  # pragma: no cover - run() handles STOP
        raise AssertionError

    def op_proto(self) -> None:
        if self.number(1, "<B") > _HIGHEST_PROTOCOL:
            raise _LoadError

    def op_frame(self) -> None:
        size = self.number(8, "<Q")
        if size > sys.maxsize:
            raise _LoadError
        if self.frame is not None and self.frame > self.pos:
            # beginning of a new frame before end of current frame, from 3.13 in C;
            # before, one that the current frame holds is read from it as it stands.
            if self.c and self.pos + size <= self.frame:
                self.differs.add("frame-bounds")
                return
            self._cross_frame()
        if self.c and self.pos + size > self.size:
            raise _LoadError  # pickle data was truncated
        self.frame = min(self.pos + size, max(self.size, len(self.sample)))

    def op_persid(self) -> None:
        self.readline(_ascii_text)[:-1].decode("ascii")
        self.push(_Persistent())

    def op_binpersid(self) -> None:
        # torch.load's persistent_load indexes the id it is given.
        saved = self.pop()
        _use(saved, certain=False)
        if (
            isinstance(saved, _Tuple)
            and len(saved.items) > 1
            and saved.items[0] in ("module", b"module")
        ):
            # torch's legacy persistent_load returns the object a "module" id carries.
            self.push(saved.items[1])
        else:
            self.push(_Persistent())

    def op_none(self) -> None:
        self.push(None)

    def op_true(self) -> None:
        self.push(True)

    def op_false(self) -> None:
        self.push(False)

    def _number_text(self, data: bytes, parse: Callable[[bytes, int], int | None]) -> int:
        """INT or LONG text, read in base 0 (up to 3.13) or base 10 (from 3.14)."""
        old, new = parse(data, 0), parse(data, 10)
        if old != new:
            self.differs.add("int-base")
        if _digit_limited(data):
            self.differs.add("int-digits")
        value = old if old is not None else new
        if value is None:
            raise _LoadError  # invalid literal for int()
        return value

    def op_int(self) -> None:
        data = self.readline(_numeric_text)
        if self.c and len(data) < 2:
            raise _LoadError
        if data in (b"00\n", b"01\n"):
            self.push(data == b"01\n")
        else:
            self.push(self._number_text(data, _c_int if self.c else _py_int))

    def op_binint(self) -> None:
        self.push(self.number(4, "<i"))

    def op_binint1(self) -> None:
        self.push(self.number(1, "<B"))

    def op_binint2(self) -> None:
        self.push(self.number(2, "<H"))

    def op_long(self) -> None:
        data = self.line(_numeric_text)
        if data.endswith(b"L"):
            data = data[:-1]
        if self.c:
            data = data.split(b"\x00")[0]  # PyLong_FromString reads a C string
        self.push(self._number_text(data, _py_int))

    def op_long1(self) -> None:
        self.push(int.from_bytes(self.read(self.number(1, "<B")), "little", signed=True))

    def op_long4(self) -> None:
        count = self.number(4, "<i")
        if count < 0:
            raise _LoadError
        self.push(int.from_bytes(self.read(count), "little", signed=True))

    def op_float(self) -> None:
        data = self.readline(_numeric_text)
        if not self.c:
            self.push(float(data[:-1]))
            return
        if len(data) < 2 or not _C_FLOAT.fullmatch(data):
            raise _LoadError  # could not convert string to float
        head = data.split(b"\x00", 1)[0]
        value = float(head)
        if value in (float("inf"), float("-inf")) and b"inf" not in head.lower():
            raise _LoadError  # OverflowError
        self.push(value)

    def op_binfloat(self) -> None:
        self.push(float(self.number(8, ">d")))

    def op_string(self) -> None:
        data = self.line(_quoted_text)
        if len(data) < 2 or data[0] != data[-1] or data[0] not in b"\"'":
            raise _LoadError  # the STRING opcode argument must be quoted
        self._string(cast(bytes, codecs.escape_decode(data[1:-1])[0]))

    def _string(self, data: bytes) -> None:
        if not data.isascii():
            self.differs.add("string-encoding")
        self.push(_String(data.decode("latin-1")))

    def op_binstring(self) -> None:
        count = self.number(4, "<i")
        if count < 0:
            if not self.c:
                raise _LoadError  # negative BINSTRING length
            self.differs.add("binstring-count")
            count += 1 << 32
        self._string(self.read(count))

    def op_short_binstring(self) -> None:
        self._string(self.read(self.number(1, "<B")))

    def op_binbytes(self) -> None:
        self.push(self.read(self.number(4, "<I")))

    def op_short_binbytes(self) -> None:
        self.push(self.read(self.number(1, "<B")))

    def _long_count(self) -> int:
        count = self.number(8, "<Q")
        if count > sys.maxsize:
            raise _LoadError
        return count

    def op_binbytes8(self) -> None:
        self.push(self.read(self._long_count()))

    def op_bytearray8(self) -> None:
        count = self._long_count()
        self.read(count)
        self.push(_Sized("bytearray", count))

    def op_unicode(self) -> None:
        self.push(str(self.readline()[:-1], "raw-unicode-escape"))

    def _utf8(self, data: bytes) -> None:
        self.push(str(data, "utf-8", "surrogatepass"))

    def op_short_binunicode(self) -> None:
        self._utf8(self.read(self.number(1, "<B")))

    def op_binunicode(self) -> None:
        self._utf8(self.read(self.number(4, "<I")))

    def op_binunicode8(self) -> None:
        self._utf8(self.read(self._long_count()))

    def op_next_buffer(self) -> None:
        raise _LoadError  # no out-of-band buffers

    def op_readonly_buffer(self) -> None:
        value = self.top()
        _use(value, certain=False)  # memoryview() of an object with the buffer protocol
        if isinstance(value, _Sized) and value.kind == "bytearray":
            self.stack[-1] = _Sized("view", value.length)
        elif isinstance(value, _String):
            self.differs.add("string-encoding")
            self.stack[-1] = value.encode("latin-1")
        elif not isinstance(value, bytes) and not _kind(value, "view"):
            raise _LoadError  # memoryview() of something without the buffer protocol

    # -- tuples, lists, dicts and sets -----------------------------------------------

    def op_tuple(self) -> None:
        self.push(_Tuple(tuple(self.pop_mark())))

    def op_empty_tuple(self) -> None:
        self.push(_Tuple(()))

    def _tuple(self, count: int) -> None:
        if len(self.stack) - self._floor() < count:
            raise _LoadError
        items = tuple(self.stack[-count:])
        del self.stack[-count:]
        self.push(_Tuple(items))

    def op_tuple1(self) -> None:
        self._tuple(1)

    def op_tuple2(self) -> None:
        self._tuple(2)

    def op_tuple3(self) -> None:
        self._tuple(3)

    def op_empty_list(self) -> None:
        self.push(_Sized("list"))

    def op_empty_dict(self) -> None:
        self.push(_Sized("dict"))

    def op_empty_set(self) -> None:
        self.push(_Sized("set"))

    def op_list(self) -> None:
        self.push(_Sized("list", len(self.pop_mark())))

    def op_dict(self) -> None:
        items = self.pop_mark()
        if self.c and len(items) % 2:
            raise _LoadError  # odd number of items for DICT
        made = _Sized("dict")
        for index in range(0, len(items), 2):
            if index + 1 >= len(items):
                raise _LoadError
            self._key(made, items[index])
        self.push(made)

    def op_frozenset(self) -> None:
        items = self.pop_mark()
        for item in items:
            _hash(item)
        self.push(_Sized("frozenset", len(items)))

    def _key(self, target: _Sized, key: object) -> None:
        _hash(key)
        target.length += 1
        target.string_keys = target.string_keys and isinstance(key, str)

    def _setitem(self, target: object, key: object, value: object) -> None:
        _use(target)  # target[key] = value
        if _kind(target, "dict"):
            self._key(cast(_Sized, target), key)
            return
        if not isinstance(target, (str, bytes, _Tuple, _Sized)) or _kind(target, "view"):
            raise _LoadError  # no __setitem__, or read-only memory
        # PyObject_SetItem takes the key's __index__ for any type with sequence methods,
        # sets included, before it refuses one that takes no item assignment.
        _use(key)
        if not (_kind(target, "list") or _kind(target, "bytearray")):
            raise _LoadError  # does not support item assignment
        if not isinstance(key, int):
            raise _LoadError  # indices must be integers
        assert isinstance(target, _Sized)
        if target.kind == "bytearray":
            _byte(value)  # before the size check
        if not -target.length <= key < target.length:
            raise _LoadError  # assignment index out of range

    def op_setitem(self) -> None:
        value = self.pop()
        key = self.pop()
        self._setitem(self.top(), key, value)

    def op_setitems(self) -> None:
        if self.c:
            items = self._marked()
            if items is None:
                return
            if len(items) % 2:
                raise _LoadError  # odd number of items for SETITEMS
        else:
            items = self.pop_mark()
        target = self.top()
        for index in range(0, len(items), 2):
            if index + 1 >= len(items):
                raise _LoadError
            self._setitem(target, items[index], items[index + 1])

    def _extend(self, target: object, items: list[object]) -> None:
        _use(target)  # target.extend(items), or target.append(item)
        if _kind(target, "bytearray"):
            for item in items:
                _byte(item)
        elif not _kind(target, "list"):
            raise _LoadError  # no extend() or append()
        assert isinstance(target, _Sized)
        target.length += len(items)

    def op_append(self) -> None:
        value = self.pop()
        self._extend(self.top(), [value])

    def op_appends(self) -> None:
        items = self._marked() if self.c else self.pop_mark()
        if items is not None:
            self._extend(self.top(), items)

    def op_additems(self) -> None:
        items = self._marked() if self.c else self.pop_mark()
        if items is None:
            return
        target = self.top()
        if items or self.c:
            _use(target)  # target.add(item)
        if isinstance(target, _Opaque):
            return  # the pure-Python unpickler looks add() up and calls it for no item
        if not _kind(target, "set"):
            raise _LoadError  # no add()
        for item in items:
            _hash(item)
        assert isinstance(target, _Sized)
        target.length += len(items)

    # -- what resolves or calls ------------------------------------------------------

    def op_global(self) -> None:
        module = self.line(_utf8_text).decode("utf-8")
        self.resolve(module, self.line(_utf8_text).decode("utf-8"))

    def op_stack_global(self) -> None:
        name = self.pop()
        module = self.pop()
        if not isinstance(name, (str, _Opaque)) or not isinstance(module, (str, _Opaque)):
            raise _LoadError  # STACK_GLOBAL requires str
        _use(name, certain=False)  # a resolved str names another global
        _use(module, certain=False)
        self.resolve(cast(str, module), cast(str, name))

    def _ext(self, width: int, form: str) -> None:
        self.number(width, form)
        raise _LoadError  # no extension code is registered

    def op_ext1(self) -> None:
        self._ext(1, "<B")

    def op_ext2(self) -> None:
        self._ext(2, "<H")

    def op_ext4(self) -> None:
        self._ext(4, "<i")

    def _instantiate(self, klass: object) -> None:
        if isinstance(klass, _Opaque):
            raise _CallError  # klass(*args), or klass.__new__(klass) without arguments
        raise _LoadError  # a builtin value is not callable

    def op_inst(self) -> None:
        if self.c and not self.marks:
            raise _LoadError  # could not find MARK
        module = self.line(_ascii_text).decode("ascii")
        self.resolve(module, self.line(_ascii_text).decode("ascii"))
        klass = self.stack.pop()
        self.pop_mark()
        self._instantiate(klass)

    def op_obj(self) -> None:
        if self.c and (not self.marks or len(self.stack) <= self.marks[-1]):
            raise _LoadError
        args = self.pop_mark()
        if not args:
            raise _LoadError
        self._instantiate(args[0])

    def _arguments(self, args: object) -> bool:
        """Whether ``args`` may be an argument tuple; ``*args`` iterates a resolved object."""
        if isinstance(args, _Opaque):
            if not self.c:
                _use(args)
            return True  # the C unpickler's tuple check, which a resolved tuple passes
        if not isinstance(args, _Tuple if self.c else _ITERABLE):
            raise _LoadError  # the argument list must be a tuple, or iterable
        return False

    def op_reduce(self) -> None:
        args = self.pop()
        func = self.top()
        if self.c and isinstance(args, _Opaque) and not isinstance(func, _Opaque):
            raise _LoadError  # a builtin value is not callable
        uncertain = self._arguments(args)
        _use(func, certain=not uncertain)
        raise _LoadError  # a builtin value is not callable

    def _new(self, kwargs: object) -> None:
        args = self.pop()
        klass = self.pop()
        if self.c and not isinstance(klass, _Opaque):
            raise _LoadError  # class argument must be a type
        uncertain = self._arguments(args)
        if isinstance(kwargs, _Opaque):
            if not self.c:
                _use(kwargs)  # **kwargs calls keys() on what is no dict
            uncertain = True
        elif kwargs is not _NO_KWARGS and not (
            isinstance(kwargs, _Sized) and kwargs.kind == "dict" and kwargs.string_keys
        ):
            raise _LoadError  # keywords must be strings in a dict
        _use(klass, certain=not uncertain)  # klass.__new__(klass, *args, **kwargs)
        raise _LoadError  # a builtin value has no __new__ that takes itself

    def op_newobj(self) -> None:
        self._new(_NO_KWARGS)

    def op_newobj_ex(self) -> None:
        self._new(self.pop())

    def op_build(self) -> None:
        state = self.pop()
        inst = self.top()
        if isinstance(inst, _Opaque):
            raise _CallError  # inst.__setstate__(state)
        split = isinstance(state, _Tuple) and len(state.items) == 2
        slots: object = None
        if isinstance(state, _Tuple) and split:
            state, slots = state.items
        if not self.c:
            for value in (state, slots):
                _use(value)  # if state: ... if slotstate: ...
                if _truth(value):
                    raise _LoadError  # a builtin value has no __dict__ and takes no attributes
        elif state is not None:
            raise _LoadError  # state is not a dictionary, or a builtin value has no __dict__
        elif split and isinstance(slots, _Opaque):
            raise _CallError(certain=False)  # an empty resolved dict sets no attribute
        elif split and not (isinstance(slots, _Sized) and slots.kind == "dict"):
            raise _LoadError  # slot state is not a dictionary
        elif split and _truth(slots):
            raise _LoadError  # a builtin value takes no attributes

    # -- stack and memo --------------------------------------------------------------

    def op_pop(self) -> None:
        if len(self.stack) > self._floor():
            self.stack.pop()
        else:
            self.pop_mark()

    def op_pop_mark(self) -> None:
        self.pop_mark()

    def op_dup(self) -> None:
        self.push(self.top())

    def op_mark(self) -> None:
        if self.budget.marks <= 0:
            raise _UnreadError
        self.budget.marks -= 1
        self.marks.append(len(self.stack))

    def _memo_index(self) -> MemoKey:
        data = self.line(_numeric_text)
        if self.c:
            data = data.split(b"\x00", 1)[0]  # PyLong_FromString reads a C string
        key = _memo_key(data)
        # A key past the floor is past LONG_MAX (or below LONG_MIN): PyLong_AsSsize_t fails.
        if key is None or (self.c and (isinstance(key, tuple) or key > _LONG_MAX)):
            raise _LoadError
        if _digit_limited(data):
            self.differs.add("int-digits")
        return key

    def _get(self, index: MemoKey) -> None:
        if index not in self.memo:
            raise _LoadError  # Memo value not found
        self.push(self.memo[index])

    def op_get(self) -> None:
        self._get(self._memo_index())

    def op_binget(self) -> None:
        self._get(self.number(1, "<B"))

    def op_long_binget(self) -> None:
        self._get(self.number(4, "<I"))

    def _put(self, index: MemoKey) -> None:
        if index[0] if isinstance(index, tuple) else index < 0:
            raise _LoadError  # negative PUT argument
        self.memo[index] = self.top()

    def op_put(self) -> None:
        self._put(self._memo_index())

    def op_binput(self) -> None:
        self._put(self.number(1, "<B"))

    def op_long_binput(self) -> None:
        self._put(self.number(4, "<I"))

    def op_memoize(self) -> None:
        self.memo[len(self.memo)] = self.top()


_DISPATCH: dict[int, Callable[[_Machine], None]] = {
    ord(code): handler
    for code, handler in {
        "(": _Machine.op_mark,
        ".": _Machine.op_stop,
        "0": _Machine.op_pop,
        "1": _Machine.op_pop_mark,
        "2": _Machine.op_dup,
        "B": _Machine.op_binbytes,
        "C": _Machine.op_short_binbytes,
        "F": _Machine.op_float,
        "G": _Machine.op_binfloat,
        "I": _Machine.op_int,
        "J": _Machine.op_binint,
        "K": _Machine.op_binint1,
        "L": _Machine.op_long,
        "M": _Machine.op_binint2,
        "N": _Machine.op_none,
        "P": _Machine.op_persid,
        "Q": _Machine.op_binpersid,
        "R": _Machine.op_reduce,
        "S": _Machine.op_string,
        "T": _Machine.op_binstring,
        "U": _Machine.op_short_binstring,
        "V": _Machine.op_unicode,
        "X": _Machine.op_binunicode,
        "]": _Machine.op_empty_list,
        "a": _Machine.op_append,
        "b": _Machine.op_build,
        "c": _Machine.op_global,
        "d": _Machine.op_dict,
        "e": _Machine.op_appends,
        "g": _Machine.op_get,
        "h": _Machine.op_binget,
        "i": _Machine.op_inst,
        "j": _Machine.op_long_binget,
        "l": _Machine.op_list,
        "o": _Machine.op_obj,
        "p": _Machine.op_put,
        "q": _Machine.op_binput,
        "r": _Machine.op_long_binput,
        "s": _Machine.op_setitem,
        "t": _Machine.op_tuple,
        "u": _Machine.op_setitems,
        "}": _Machine.op_empty_dict,
        ")": _Machine.op_empty_tuple,
        "\x80": _Machine.op_proto,
        "\x81": _Machine.op_newobj,
        "\x82": _Machine.op_ext1,
        "\x83": _Machine.op_ext2,
        "\x84": _Machine.op_ext4,
        "\x85": _Machine.op_tuple1,
        "\x86": _Machine.op_tuple2,
        "\x87": _Machine.op_tuple3,
        "\x88": _Machine.op_true,
        "\x89": _Machine.op_false,
        "\x8a": _Machine.op_long1,
        "\x8b": _Machine.op_long4,
        "\x8c": _Machine.op_short_binunicode,
        "\x8d": _Machine.op_binunicode8,
        "\x8e": _Machine.op_binbytes8,
        "\x8f": _Machine.op_empty_set,
        "\x90": _Machine.op_additems,
        "\x91": _Machine.op_frozenset,
        "\x92": _Machine.op_newobj_ex,
        "\x93": _Machine.op_stack_global,
        "\x94": _Machine.op_memoize,
        "\x95": _Machine.op_frame,
        "\x96": _Machine.op_bytearray8,
        "\x97": _Machine.op_next_buffer,
        "\x98": _Machine.op_readonly_buffer,
    }.items()
}


def load_segment(
    sample: bytes,
    size: int,
    start: int,
    flavor: Flavor,
    budget: Budget,
    jumps: tuple[bool, ...] = (),
) -> Segment:
    """How ``pickle.load`` ends reading the pickle at ``start`` of a file of ``size`` bytes.

    ``sample`` holds the file's first bytes; ``budget`` is charged for every opcode and
    MARK read and is shared by the pickles of one sample. ``jumps`` picks where the C
    unpickler reads on from at each frame end it crosses (``Segment.crossings``).
    """
    return _Machine(sample, size, start, flavor, budget, jumps).run()


def load_segments(
    sample: bytes, size: int, start: int, flavor: Flavor, budget: Budget
) -> Iterator[Segment]:
    """Each way ``pickle.load`` may end reading the pickle at ``start``.

    One for each choice of where to read on at the frame ends a walk crosses; every
    walk is charged to ``budget``, which bounds them.
    """
    pending: list[tuple[bool, ...]] = [()]
    while pending:
        jumps = pending.pop()
        segment = load_segment(sample, size, start, flavor, budget, jumps)
        yield segment
        for index in range(len(jumps), segment.crossings):
            pending.append((*jumps, *(False,) * (index - len(jumps)), True))
