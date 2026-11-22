"""Bounded local collection with descriptor-relative, no-symlink reads.

This is an offline collector boundary, not a process sandbox. It requires POSIX
``dir_fd`` and ``O_NOFOLLOW`` support and fails closed where unavailable. Its
size, entry and depth bounds are the operator limits in ``nexus_symbiote.limits``
unless a caller passes a fixed bound for a particular input.
"""

from __future__ import annotations

import errno
import hashlib
import io
import json
import math
import os
import stat
import unicodedata
from collections.abc import Collection, Iterable, Iterator
from contextlib import contextmanager
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, NoReturn, Self, cast

from nexus_symbiote import limits
from nexus_symbiote.core.hashing import descriptor_binding, open_directory_nofollow, stat_input_file
from nexus_symbiote.core.identifiers import reference_text
from nexus_symbiote.limits import Bound
from nexus_symbiote.scanner_catalog import INSTRUCTION_DIRECTORIES, SKILL_DIRECTORIES

# Defaults only: a collection reads the operator's current limits when it is created.
MAX_FILE_BYTES = limits.DEFAULTS.file_bytes
MAX_ENTRIES = limits.DEFAULTS.entries
MAX_DEPTH = limits.DEFAULTS.depth
MAX_TOTAL_BYTES = limits.DEFAULTS.total_bytes
MAX_HASH_BYTES = limits.DEFAULTS.model_bytes
DEFAULT_EXCLUDES = frozenset({".git", "node_modules", "__pycache__", ".venv", "venv"})
ROOT_GIT_METADATA = "root:.git"
DEFAULT_EXCLUDE_ACCEPTANCE = DEFAULT_EXCLUDES | {ROOT_GIT_METADATA}
DEFAULT_EXCLUDE_REASON = "default collection exclude; not collected"
AGENT_DEFAULT_EXCLUDE_REASON = (
    "default-excluded name inside an agent configuration directory; not collected"
)
# A walk, a search of every source file, or a collector reading file after file can
# fail once per entry. Past these bounds a collection, and a collector's own list of
# failures or gaps, counts further ones instead of listing them, so a tree that
# reaches its limits still yields an inventory that loads and names them.
MAX_LISTED_FAILURES = 1_000
MAX_LISTED_FAILURE_CHARACTERS = 64 * 1024
# Reasons that one summary of the failures past the bounds names one line each.
_MAX_SUMMARIZED_REASONS = 64
_MAX_CHUNK_BYTES = 4 * 1024 * 1024


class CollectionError(ValueError):
    """A collection input exceeded the supported safe boundary."""


class LimitExceededError(CollectionError):
    """A read would pass one of the collection's bounds."""

    def __init__(self, bound: Bound) -> None:
        super().__init__(bound.exceeded())
        self.bound = bound


def _bound(value: int | Bound | None, name: str) -> Bound:
    if value is None:
        return limits.bound(name)
    if isinstance(value, Bound):
        return value
    return Bound(value, name, configurable=False)


class ByteBudget:
    """Bytes read so far against one named total bound."""

    def __init__(self, bound: Bound) -> None:
        self.bound = bound
        self.used = 0
        self.exhausted = False

    def remaining(self) -> int:
        return self.bound.value - self.used

    def refuse(self) -> LimitExceededError:
        self.exhausted = True
        return LimitExceededError(self.bound)

    def charge(self, count: int) -> None:
        self.used += count
        if self.used > self.bound.value:
            raise self.refuse()


class _LinkRefusedError(CollectionError):
    """A symlink that cannot be covered through an in-root target; the reason is recorded."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class _VariantSearchStoppedError(Exception):
    """The case-variant search of one path ends here; a failure names the reason."""


class _MessageLog:
    """Lists messages in a caller's list once each, at constant cost per message.

    A walk can record one message per entry, so a membership test on the list
    itself would make a large tree quadratic. Entries the caller appends to the
    list directly are taken into account before the next message. A bounded log
    lists at most ``MAX_LISTED_FAILURES`` messages or ``MAX_LISTED_FAILURE_CHARACTERS``
    characters of them, and once one does not fit, none does. A message that is not
    listed is not kept either: the caller sums it up, or the log counts it in one line
    at the end of the list that names the first such message. ``recorded`` counts every
    message, listed, counted or already listed, so it grows when the list does not.
    """

    def __init__(
        self,
        messages: list[str],
        *,
        bounded: bool = True,
        noun: str = "failure",
        bind_omitted: bool = False,
    ) -> None:
        self.messages = messages
        self._seen = set(messages)
        self._synced = len(messages)
        self._recorded = len(messages)
        self._bounded = bounded
        self._noun = noun
        self._lines = 0
        self._characters = 0
        self._full = False
        # The line that counts messages not listed: its index, first message and count.
        self._end: int | None = None
        self._first = ""
        self._counted = 0
        self._omitted_digest = hashlib.sha256() if bind_omitted else None

    def _sync(self) -> None:
        if len(self.messages) < self._synced:
            self._seen = set(self.messages)
        else:
            self._seen.update(self.messages[self._synced :])
            self._recorded += len(self.messages) - self._synced
        self._synced = len(self.messages)

    @property
    def recorded(self) -> int:
        """Messages recorded so far, including those not listed; it never decreases."""
        self._sync()
        return self._recorded

    def tally(self) -> None:
        """Count one message as recorded, whether or not it is listed."""
        self._sync()
        self._recorded += 1

    def __contains__(self, message: str) -> bool:
        self._sync()
        return message in self._seen

    def fits(self, message: str) -> bool:
        """Charge ``message`` to the listing bounds if it fits; once one does not, none does."""
        if not self._bounded:
            return True
        if (
            self._full
            or self._lines >= MAX_LISTED_FAILURES
            or self._characters + len(message) > MAX_LISTED_FAILURE_CHARACTERS
        ):
            self._full = True
            return False
        self._lines += 1
        self._characters += len(message)
        return True

    def put(self, message: str) -> None:
        """List ``message`` without charging it, before the line that counts the rest."""
        self._sync()
        if self._end is None:
            list.append(self.messages, message)
        else:
            list.insert(self.messages, self._end, message)
            self._end += 1
        self._seen.add(message)
        self._synced = len(self.messages)

    def count(self, message: str) -> None:
        """Count ``message`` as not listed, in the line at the end that names the first."""
        self._sync()
        self._counted += 1
        if self._omitted_digest is not None:
            # The directory walk is sorted. Frame each path so names containing
            # newlines or other delimiters cannot share another listing's digest.
            data = os.fsencode(message)
            self._omitted_digest.update(len(data).to_bytes(8, "big"))
            self._omitted_digest.update(data)
        if self._end is None:
            self._first, self._end = message, len(self.messages)
            list.append(self.messages, message)
        else:
            more = self._counted - 1
            noun = self._noun if more == 1 else self._noun + "s"
            line = f"{self._first} (and {more} more {noun} not listed)"
            if self._omitted_digest is not None:
                line += f" [sha256:{self._omitted_digest.hexdigest()}]"
            list.__setitem__(self.messages, self._end, line)
        self._synced = len(self.messages)

    def record(self, message: str) -> None:
        """List ``message`` within the bounds, or count it."""
        self.tally()
        if self.fits(message):
            self.put(message)
        else:
            self.count(message)

    def add(self, message: str) -> bool:
        """Record ``message`` unless it is already listed; say whether it was new."""
        if message in self:
            self.tally()
            return False
        self.record(message)
        return True

    def prefer(self, specific: str, generic: str) -> None:
        """Upgrade a listed reason without moving the bounded log's overflow row."""
        if specific in self:
            return
        if generic in self:
            growth = len(specific) - len(generic)
            if not self._bounded or self._characters + growth <= MAX_LISTED_FAILURE_CHARACTERS:
                self.messages[self.messages.index(generic)] = specific
                self._seen.remove(generic)
                self._seen.add(specific)
                if self._bounded:
                    self._characters += growth
                return
        self.add(specific)


class BoundedRecords(list[str]):
    """A collector's failures or gaps, listed within the listing bounds.

    A collector can record one line for every file it meets. Past the bounds a line
    is counted instead, in one line at the end that names the first line not listed
    and how many more there were, so the inventory still loads and still fails the
    gates. A confined collection over the list lists its own failures within the same
    bounds and sums up the rest by reason, before that line.
    """

    def __init__(
        self, records: Iterable[str] = (), *, noun: str = "failure", bind_omitted: bool = False
    ) -> None:
        super().__init__()
        self.log = _MessageLog(self, noun=noun, bind_omitted=bind_omitted)
        self.extend(records)

    def append(self, record: str, /) -> None:
        self.log.record(record)

    def extend(self, records: Iterable[str], /) -> None:
        for record in records:
            self.log.record(record)

    def __iadd__(self, records: Iterable[str], /) -> Self:  # type: ignore[override,misc]
        self.extend(records)
        return self

    @property
    def recorded(self) -> int:
        """Records taken so far, listed or not; compare it, not ``len``, to tell whether
        an operation recorded one, because past the listing bounds the length stops."""
        return self.log.recorded


def recorded_count(records: list[str]) -> int:
    """How many records ``records`` has taken, including those past the listing bounds."""
    return records.recorded if isinstance(records, BoundedRecords) else len(records)


class _Unlisted:
    """Failures past the listing bounds: per reason, the first and how many there were.

    Reasons are told apart by a key that names no path, so that one line sums up, for
    example, every case variant. Only ``_MAX_SUMMARIZED_REASONS`` reasons get a line
    of their own; one more line counts the failures for the others.
    """

    def __init__(self) -> None:
        self._first: dict[str, str] = {}
        self._count: dict[str, int] = {}

    def add(self, message: str, key: str) -> None:
        if key not in self._count and len(self._first) < _MAX_SUMMARIZED_REASONS:
            self._first[key] = message
        self._count[key] = self._count.get(key, 0) + 1

    def lines(self) -> Iterator[str]:
        for key, first in self._first.items():
            more = self._count[key] - 1
            yield first + (f" (and {more} more not listed)" if more else "")
        others = [count for key, count in self._count.items() if key not in self._first]
        if others:
            failures = "failure" if sum(others) == 1 else "failures"
            reasons = "reason" if len(others) == 1 else "reasons"
            yield f"{sum(others)} more {failures} for {len(others)} other {reasons} not listed"


class _WalkScope:
    """One ``iter_files`` walk: its top directory, the directories it walks through
    symlinks, the lists that collect the directory symlinks it met and the entries it
    skipped by a default-excluded name, and the failures it met past the collection's
    listing bounds."""

    def __init__(
        self,
        top: Path,
        links: list[Path] | None,
        unlisted: _Unlisted,
        skipped: list[Path] | None = None,
    ) -> None:
        self.top = top
        self.walked = {top}
        self.links = links
        self.unlisted = unlisted
        self.skipped = skipped

    def covers(self, target: Path) -> bool:
        """Whether the walk reaches ``target`` already, under its own name."""
        return target in self.walked or any(parent in self.walked for parent in target.parents)


# An O_NOFOLLOW open reports a symlink as ELOOP (EMLINK on FreeBSD), and a symlinked
# parent opened with O_DIRECTORY as ENOTDIR.
_LINK_ERRNOS = frozenset({errno.ELOOP, errno.EMLINK, errno.ENOTDIR})
_MAX_CASE_VARIANTS = 16
_DIRECTORY, _LINK, _OTHER = "directory", "link", "other"
# Case-variant failures name the path asked for; past the listing bounds they are
# summed up as one reason.
_CASE_VARIANT = "case variant of another path"
# The format characters HFS+ ignores when it compares names.
_IGNORED_IN_NAMES = dict.fromkeys(
    [*range(0x200C, 0x2010), *range(0x202A, 0x202F), *range(0x206A, 0x2070), 0xFEFF]
)


def fold_name(name: str) -> str:
    """A file name as case-insensitive file systems compare it.

    Case and Unicode normalisation are folded, as on APFS, HFS+ and NTFS; so are the
    format characters HFS+ ignores and the trailing dots and spaces Windows drops.
    """
    if name.isascii():
        return name.lower().rstrip(". ")
    folded = unicodedata.normalize("NFD", unicodedata.normalize("NFD", name).casefold())
    return folded.translate(_IGNORED_IN_NAMES).rstrip(". ")


def _default_excluded(name: str) -> bool:
    """Whether a path component is one of ``DEFAULT_EXCLUDES``, in any spelling a
    case-insensitive file system treats as the same name."""
    return name in DEFAULT_EXCLUDES or fold_name(name) in DEFAULT_EXCLUDES


def _under_agent_configuration_directory(relative: Path) -> bool:
    """Use the prompt collector's coverage reason for paths it would also report."""
    parent = relative.parent.as_posix()
    if parent == ".":
        return False
    for directory in (*INSTRUCTION_DIRECTORIES, *SKILL_DIRECTORIES):
        if parent == directory or parent.startswith(directory + "/"):
            return True
    return False


def _lexical_target(directory: Path, text: str) -> Path:
    """Resolve a link's text against its directory without following anything.

    ``..`` may only lead the text: the directory holds no symlink, so leading parent
    steps resolve as the kernel resolves them, while one after a name could pass
    through a symlink and reach a different file than this lexical answer. A target
    name that is not valid UTF-8 could be written to no inventory, so its link is
    refused, as a walk refuses such a name.
    """
    if not text:
        raise _LinkRefusedError("symlink target is empty")
    if os.path.isabs(text):
        raise _LinkRefusedError("symlink target is absolute")
    if _undecodable(text):
        raise _LinkRefusedError("symlink target name is not valid UTF-8; not collected")
    parts = list(directory.parts)
    named = False
    for part in PurePosixPath(text).parts:
        if part == "..":
            if named:
                raise _LinkRefusedError("symlink target is not a plain relative path")
            if not parts:
                raise _LinkRefusedError("symlink target is outside the collection root")
            parts.pop()
        elif part != ".":
            named = True
            parts.append(part)
    return Path(*parts)


def _undecodable(name: str) -> bool:
    return any("\ud800" <= character <= "\udfff" for character in name)


def _escaped(name: str) -> str:
    """Show the bytes a non-UTF-8 name was decoded from, without lone surrogates."""
    return "".join(
        f"\\x{ord(character) - 0xDC00:02x}"
        if "\udc80" <= character <= "\udcff"
        else f"\\u{ord(character):04x}"
        if "\ud800" <= character <= "\udfff"
        else character
        for character in name
    )


def _refuse_constant(_: str) -> Any:
    raise CollectionError("nonfinite JSON")


def _finite_float(text: str) -> float:
    value = float(text)
    if not math.isfinite(value):
        raise CollectionError("nonfinite JSON")
    return value


def hash_confined_file(root: Path, source_path: str | Path, algorithm: str = "sha256") -> str:
    """Compatibility hash API for a BOM-supplied path beneath a caller root."""
    if algorithm not in {"sha256", "sha384", "sha512"}:
        raise OSError("unsupported security hash algorithm")
    model_bytes = limits.bound("model-bytes")
    try:
        with (
            ConfinedCollection(root, [], max_total_bytes=model_bytes) as files,
            files.open_regular(source_path, max_bytes=model_bytes) as stream,
        ):
            digest = hashlib.new(algorithm)
            while chunk := stream.read(65536):
                digest.update(chunk)
            return f"{algorithm}:{digest.hexdigest()}"
    except (CollectionError, ValueError) as exc:
        raise OSError("confined artifact hash refused") from exc


class _BoundedReader(io.RawIOBase):
    """Explicit-size reads only; enforce both stream and collection budgets."""

    def __init__(
        self, fd: int, owner: ConfinedCollection, path: Path, limit: Bound, budget: ByteBudget
    ) -> None:
        self._fd = fd
        self._owner = owner
        self._path = path
        self._limit = limit
        self._budget = budget
        self._read = 0

    def readable(self) -> bool:
        return True

    def fileno(self) -> int:
        return self._fd

    def read(self, size: int = -1) -> bytes:
        if self.closed:
            raise ValueError("read of closed collection stream")
        if not 0 <= size <= _MAX_CHUNK_BYTES:
            raise CollectionError("explicit bounded read size required")
        try:
            raw = os.read(self._fd, min(size, self._limit.value + 1 - self._read))
        except OSError:
            self._owner._fail(self._path, "stream read failed (I/O error)")
            raise
        self._read += len(raw)
        try:
            if self._read > self._limit.value:
                raise LimitExceededError(self._limit)
            self._budget.charge(len(raw))
        except LimitExceededError as exc:
            self._owner._fail(self._path, exc.bound.exceeded())
            raise
        return raw

    def reread(self, offset: int, size: int) -> bytes:
        """Read again ``size`` bytes at ``offset`` from the bytes this stream has read.

        They were charged to the budget when they were first read, so reading them again
        is not charged; a range past them is refused. The caller bounds how often it
        reads a range again.
        """
        if self.closed:
            raise ValueError("read of closed collection stream")
        if offset < 0 or not 0 <= size <= _MAX_CHUNK_BYTES or offset + size > self._read:
            raise CollectionError("re-read outside the bytes already read")
        try:
            return os.pread(self._fd, size, offset)
        except OSError:
            self._owner._fail(self._path, "stream read failed (I/O error)")
            raise

    def close(self) -> None:
        if not self.closed:
            os.close(self._fd)
        super().close()


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise CollectionError("duplicate JSON key")
        result[key] = value
    return result


class ConfinedCollection:
    """Read regular files beneath a pinned root without following symlinks.

    Limits cover individual file bytes, the bytes read in total, directory entries
    across walks and exact-name checks, and directory depth. A limit left unset is the
    operator's current one (``nexus_symbiote.limits``); an integer is a fixed bound
    for this input. Reaching any limit records a failure that names it. A
    directory exceeding the entry budget is not partially returned. Within those
    bounds traversal is lexical and deterministic.

    Mount boundaries are decided on directories only: a directory, or a directory a
    symlink names, whose ``st_dev`` differs from the root's is a mount point and is
    refused, so nothing beneath it is read or walked. A regular file, or a symlink
    to one, is not refused for its ``st_dev`` alone: overlayfs without ``xino``
    reports every directory on the overlay device but every non-directory on the
    device of the layer that holds it, so a device check on leaves would exclude
    every file in such a container. A file reached this way is still opened without
    following links, beneath directories that passed the mount check.
    """

    def __init__(
        self,
        root: Path,
        failures: list[str],
        exclusions: list[str] | None = None,
        *,
        exclude_paths: Iterable[str | Path] = (),
        accept_default_excludes: bool | tuple[str, ...] = False,
        accepted_default_exclusions: list[str] | None = None,
        max_file_bytes: int | Bound | None = None,
        max_entries: int | Bound | None = None,
        max_depth: int | Bound | None = None,
        max_total_bytes: int | Bound | None = None,
    ) -> None:
        requested = Path(root)
        # Kept unnormalized so ".." is walked through the real parent, as the kernel
        # resolves it, instead of being collapsed textually past a symlink.
        self._requested_root = requested if requested.is_absolute() else Path.cwd() / requested
        self.root = Path(os.path.abspath(self._requested_root))
        self.failures = failures
        self.exclusions = exclusions if exclusions is not None else []
        # A collector's own lists share their bounds with what the collection records.
        self._failure_log = (
            failures.log if isinstance(failures, BoundedRecords) else _MessageLog(failures)
        )
        self._exclusion_log = (
            self.exclusions.log
            if isinstance(self.exclusions, BoundedRecords)
            else _MessageLog(self.exclusions, bounded=False)
        )
        # Failures past the listing bounds that no walk or bounded block sums up are
        # summed up when the collection ends.
        self._unlisted = _Unlisted()
        self._block: _Unlisted | None = None
        self._variants_reported: set[Path] = set()
        self._file_bound = _bound(max_file_bytes, "file-bytes")
        self._entry_bound = _bound(max_entries, "entries")
        self._depth_bound = _bound(max_depth, "depth")
        self._budget = ByteBudget(_bound(max_total_bytes, "total-bytes"))
        self.max_file_bytes = self._file_bound.value
        self.max_entries = self._entry_bound.value
        self.max_depth = self._depth_bound.value
        self.max_total_bytes = self._budget.bound.value
        self._entry_budget = [self.max_entries]
        self._entries_exhausted = False
        self._root_fd: int | None = None
        self._root_dev: int | None = None
        self._links: dict[str, str] = {}
        self._listings: dict[Path, dict[str, list[tuple[str, str]]] | None] = {}
        self._exact_names: dict[
            tuple[int, int], tuple[tuple[int, int, int, int, int, int], frozenset[str]]
        ] = {}
        self._case_sensitive_dirs: set[tuple[int, int]] = set()
        self._root_folds = False
        self._folded_excluded: set[tuple[str, ...]] | None = None
        self._variant_budget = self.max_entries
        self._variants_stopped = False
        self._excluded: set[tuple[str, ...]] = set()
        self._invalid_policy = False
        self._lifted: frozenset[str] = frozenset()
        self._accepted_default_names = (
            DEFAULT_EXCLUDES
            if accept_default_excludes is True
            else frozenset(accept_default_excludes or ())
        )
        self._accepted_default_exclusions = accepted_default_exclusions
        self.accepted_default_names: set[str] = set()
        root_text = str(self.root)
        prefix = root_text.rstrip(os.sep) + os.sep
        for value in exclude_paths:
            # String operations keep a long exclusion list linear and cheap to load.
            candidate = os.path.abspath(os.path.join(root_text, os.fspath(value)))
            if candidate == root_text:
                self._excluded.add(())
            elif candidate.startswith(prefix):
                self._excluded.add(tuple(candidate[len(prefix) :].split(os.sep)))
            else:
                self._fail(".", "excluded path is outside collection root")
                self._invalid_policy = True

    def __enter__(self) -> ConfinedCollection:
        if self._invalid_policy:
            return self
        if not hasattr(os, "O_NOFOLLOW") or os.open not in os.supports_dir_fd:
            self._fail(".", "no-follow descriptor-relative collection unsupported")
            return self
        try:
            self._root_fd = open_directory_nofollow(self._requested_root)
            self._root_dev = os.fstat(self._root_fd).st_dev
            self._root_folds = self._detect_root_folding()
        except OSError:
            if self._root_fd is not None:
                os.close(self._root_fd)
                self._root_fd = None
            self._fail(".", "root unavailable or contains a symlink")
        return self

    def _detect_root_folding(self) -> bool:
        """Whether the root's file system folds case on directory lookups."""
        if self._root_fd is None:
            return False
        try:
            root_stat = os.fstat(self._root_fd)
        except OSError:
            return False
        for candidate in (self.root, *self.root.parents):
            name = candidate.name
            if not name:
                break
            swapped = name.swapcase()
            if swapped == name:
                continue
            try:
                exact = os.stat(candidate, follow_symlinks=False)
                if exact.st_dev != root_stat.st_dev:
                    break
                alt = os.stat(candidate.parent / swapped, follow_symlinks=False)
                return (alt.st_dev, alt.st_ino) == (exact.st_dev, exact.st_ino)
            except FileNotFoundError:
                return False
            except OSError:
                continue
        return False

    def __exit__(self, *args: object) -> None:
        if self._root_fd is not None:
            os.close(self._root_fd)
            self._root_fd = None
        self._root_dev = None
        unlisted, self._unlisted = self._unlisted, _Unlisted()
        self._summarize(unlisted)

    @property
    def failures_recorded(self) -> int:
        """Failures recorded so far, including those past the listing bounds and repeats.

        It only grows, so comparing it before and after a read tells whether the read
        failed; the length of the failure list stops changing once the bounds are full.
        """
        return self._failure_log.recorded

    @property
    def exclusions_recorded(self) -> int:
        """Coverage gaps recorded so far, counted as ``failures_recorded`` counts failures."""
        return self._exclusion_log.recorded

    @property
    def bytes_exhausted(self) -> bool:
        """Whether the collection's total byte budget is spent, so no further read succeeds.

        A file refused because it does not fit in what remains does not spend it.
        """
        return self._budget.exhausted

    def _fail(self, path: str | Path, reason: str, *, key: str | None = None) -> None:
        self._record(path, reason, self._unlisted if self._block is None else self._block, key)

    def _record(
        self, path: str | Path, reason: str, unlisted: _Unlisted, key: str | None = None
    ) -> None:
        """List a failure once within the listing bounds; past them ``unlisted`` counts it.

        ``key`` names the reason for a summary when the reason names a path.
        """
        message = f"{path!s}: {reason}"
        self._failure_log.tally()
        if message in self._failure_log:
            return
        if self._failure_log.fits(message):
            self._failure_log.put(message)
        else:
            unlisted.add(message, reason if key is None else key)

    def _summarize(self, unlisted: _Unlisted) -> None:
        for line in unlisted.lines():
            if line not in self._failure_log:
                self._failure_log.put(line)

    @contextmanager
    def bounded_failures(self) -> Iterator[None]:
        """Sum up when the block ends the failures it records past the listing bounds.

        For work that can fail once per file, such as searching every source file.
        Every failure a collection records is listed only within its listing bounds:
        once it has listed ``MAX_LISTED_FAILURES`` failures or
        ``MAX_LISTED_FAILURE_CHARACTERS`` of them, later ones are counted by reason.
        Such a block, like a walk, ends with one line per reason that names the first
        path not listed and how many more there were; others are summed up when the
        collection ends. Every reason is still recorded.
        """
        if self._block is not None:
            yield
            return
        block = self._block = _Unlisted()
        try:
            yield
        finally:
            self._block = None
            self._summarize(block)

    def _relative(self, path: str | Path) -> Path:
        if "\x00" in str(path):
            # os.open would raise ValueError, which no caller treats as a refused read.
            raise CollectionError("path contains a NUL character")
        candidate = Path(path)
        if candidate.is_absolute():
            try:
                candidate = candidate.relative_to(self.root)
            except ValueError as exc:
                raise CollectionError("path is outside collection root") from exc
        if ".." in candidate.parts:
            raise CollectionError("parent traversal is not allowed")
        return candidate

    def excluded(self, path: str | Path) -> bool:
        relative = self._relative(path)
        parts = relative.parts
        # Dependency caches, virtual environments and Git internals are outside
        # the documented static scope. The BOM records these patterns. Any
        # further omission within that scope is a blocking coverage gap.
        if any(_default_excluded(part) and fold_name(part) not in self._lifted for part in parts):
            return True
        denied = bool(self._excluded) and any(
            parts[:index] in self._excluded for index in range(len(parts) + 1)
        )
        if not denied and self._excluded and self._root_folds:
            if self._folded_excluded is None:
                self._folded_excluded = {
                    tuple(fold_name(item) for item in entry) for entry in self._excluded
                }
            folded = tuple(fold_name(part) for part in parts)
            denied = any(
                folded[:index] in self._folded_excluded for index in range(len(folded) + 1)
            )
        if denied:
            self._exclusion_log.add(f"{relative}: excluded by collection policy")
        return denied

    def _default_exclude_occupied(self, directory_fd: int, name: str) -> bool:
        """Whether a default-excluded entry holds something collection would have read.

        An empty directory is not a gap. A regular file, a symlink, any other
        non-directory, a directory that cannot be listed, and a directory with at
        least one entry are. The check does not follow a symlink and does not
        charge the entry budget: it stops at the first entry.
        """
        try:
            metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError:
            return True
        if not stat.S_ISDIR(metadata.st_mode):
            return True
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
        try:
            child_fd = os.open(name, flags, dir_fd=directory_fd)
        except OSError:
            return True
        try:
            with os.scandir(child_fd) as stream:
                return next(stream, None) is not None
        except OSError:
            return True
        finally:
            os.close(child_fd)

    def _is_git_metadata(self, directory_fd: int, child: Path) -> bool:
        """Recognize Git metadata without resolving a gitdir or a HEAD ref."""
        root = child.parts == (".git",)
        if child.name != ".git" or (not root and ".git" not in self._accepted_default_names):
            return False
        metadata_fd = None
        try:
            entry = self._stat_exact_no_follow(directory_fd, ".git")
            is_directory = stat.S_ISDIR(entry.st_mode)
            if is_directory:
                if not root:
                    return False
                metadata_fd = self._open_dir_part(directory_fd, ".git")
                parent, name = metadata_fd, "HEAD"
            elif stat.S_ISREG(entry.st_mode):
                parent, name = directory_fd, ".git"
            else:
                return False
            if not stat.S_ISREG(self._stat_exact_no_follow(parent, name).st_mode):
                return False
            fd = self._open_leaf_no_follow(parent, name)
            try:
                info = os.fstat(fd)
                if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 4096:
                    return False
                data = os.read(fd, info.st_size + 1)
                if (
                    len(data) != info.st_size
                    or descriptor_binding(info) != descriptor_binding(os.fstat(fd))
                    or not os.path.samestat(info, self._stat_exact_no_follow(parent, name))
                    or not os.path.samestat(entry, self._stat_exact_no_follow(directory_fd, ".git"))
                ):
                    return False
            finally:
                os.close(fd)
        except (OSError, CollectionError):
            return False
        finally:
            if metadata_fd is not None:
                os.close(metadata_fd)
        value = data.removesuffix(b"\n").removesuffix(b"\r")
        if any(char in value for char in (b"\n", b"\r", b"\x00")):
            return False
        if is_directory:
            return (
                value.startswith(b"ref: refs/") and bool(value[len(b"ref: refs/") :].strip())
            ) or (len(value) in (40, 64) and all(c in b"0123456789abcdefABCDEF" for c in value))
        return value.startswith(b"gitdir: ") and bool(value[len(b"gitdir: ") :].strip())

    def _has_exact_name(self, directory_fd: int, name: str) -> bool:
        """Whether ``directory_fd`` holds an entry whose exact spelling is ``name``."""
        info = os.fstat(directory_fd)
        dir_key = (info.st_dev, info.st_ino)
        simple_ascii = name.isascii() and not name.endswith((".", " "))
        if simple_ascii and dir_key in self._case_sensitive_dirs:
            return True
        if simple_ascii:
            swapped = name.swapcase()
            if swapped != name:
                try:
                    os.stat(swapped, dir_fd=directory_fd, follow_symlinks=False)
                except FileNotFoundError:
                    self._case_sensitive_dirs.add(dir_key)
                    return True
                except OSError:
                    # Any other failure decides nothing; the listing below does.
                    pass
        stamp = descriptor_binding(info)
        cached = self._exact_names.get(dir_key)
        if cached is None or cached[0] != stamp:
            if self._entries_exhausted:
                raise LimitExceededError(self._entry_bound)
            dup_fd = os.dup(directory_fd)
            try:
                found: set[str] = set()
                with os.scandir(dup_fd) as stream:
                    for entry in stream:
                        if self._entry_budget[0] <= 0:
                            # Metadata-only callers also need a blocking failure; they
                            # otherwise return no observation when opening is refused.
                            self._entries_exceeded(Path("."))
                            raise LimitExceededError(self._entry_bound)
                        self._entry_budget[0] -= 1
                        found.add(entry.name)
                names = frozenset(found)
            finally:
                os.close(dup_fd)
            cached = (stamp, names)
            self._exact_names[dir_key] = cached
        return name in cached[1]

    def _open_dir_part(self, directory_fd: int, part: str) -> int:
        try:
            child_fd = os.open(
                part,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            raise
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS and not self._has_exact_name(directory_fd, part):
                raise FileNotFoundError(errno.ENOENT, "exact entry not found") from exc
            raise
        try:
            if self._root_dev is not None and os.fstat(child_fd).st_dev != self._root_dev:
                raise CollectionError("path crosses a filesystem mount boundary")
            exact = self._has_exact_name(directory_fd, part)
        except BaseException:
            os.close(child_fd)
            raise
        if not exact:
            os.close(child_fd)
            raise FileNotFoundError(errno.ENOENT, "exact entry not found")
        return child_fd

    def _open_leaf_no_follow(self, directory_fd: int, name: str) -> int:
        try:
            fd = os.open(
                name,
                os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0),
                dir_fd=directory_fd,
            )
        except FileNotFoundError:
            raise
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS and not self._has_exact_name(directory_fd, name):
                raise FileNotFoundError(errno.ENOENT, "exact entry not found") from exc
            raise
        try:
            if self._root_dev is not None:
                # Only a directory marks a mount point; see the class docstring.
                leaf = os.fstat(fd)
                if stat.S_ISDIR(leaf.st_mode) and leaf.st_dev != self._root_dev:
                    raise CollectionError("path crosses a filesystem mount boundary")
            exact = self._has_exact_name(directory_fd, name)
        except BaseException:
            os.close(fd)
            raise
        if not exact:
            os.close(fd)
            raise FileNotFoundError(errno.ENOENT, "exact entry not found")
        return fd

    def _stat_exact_no_follow(self, directory_fd: int, name: str) -> os.stat_result:
        info = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not self._has_exact_name(directory_fd, name):
            raise FileNotFoundError(errno.ENOENT, "exact entry not found")
        return info

    def _open_parent(self, relative: Path) -> int:
        if self._root_fd is None:
            raise CollectionError("collection root unavailable")
        fd = os.dup(self._root_fd)
        try:
            for part in relative.parts[:-1]:
                next_fd = self._open_dir_part(fd, part)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def read_bytes(
        self, path: str | Path, *, missing_ok: bool = False, variants_read: Collection[str] = ()
    ) -> bytes | None:
        """Read a confined regular file, through at most one in-root symlink.

        A symlink whose lexical target is a regular file beneath the root, not
        excluded and reached without a further symlink is read through its target
        (``link_target`` names it); any other symlink is a recorded failure. With
        ``missing_ok`` an absent file is not a failure, but a case or normalisation
        variant of its name is, unless the caller reads it separately and names it
        in ``variants_read``: case-insensitive file systems open that variant.
        """
        relative: Path | str = str(path)
        try:
            relative = self._relative(path)
            if self.excluded(relative):
                return None
            if not relative.parts:
                raise CollectionError("expected a regular file")
            fd, opened = self._open_file(relative)
            try:
                before = stat_input_file(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise CollectionError("not a regular file")
                limit = self._file_bound
                budget = self._budget
                if before.st_size > limit.value:
                    raise LimitExceededError(limit)
                if before.st_size > budget.remaining():
                    raise LimitExceededError(budget.bound)
                chunks: list[bytes] = []
                length = 0
                while length <= limit.value:
                    chunk = os.read(fd, min(65536, limit.value + 1 - length))
                    if not chunk:
                        break
                    chunks.append(chunk)
                    length += len(chunk)
                    budget.charge(len(chunk))
                if length > limit.value:
                    raise LimitExceededError(limit)
                after = os.fstat(fd)
                if descriptor_binding(before) != descriptor_binding(after) or not (
                    self._resolves_to(opened, after) and self._same_link(relative, opened)
                ):
                    raise CollectionError("file changed during collection")
                return b"".join(chunks)
            finally:
                os.close(fd)
        except FileNotFoundError:
            if not missing_ok:
                self._fail(relative, "file unavailable during collection")
            elif isinstance(relative, Path):
                self._report_case_variants(relative, variants_read)
        except _LinkRefusedError as exc:
            self._fail(relative, exc.reason)
        except LimitExceededError as exc:
            self._fail(relative, exc.bound.exceeded())
        except (OSError, CollectionError):
            # Do not echo exception payloads: malformed input may contain secrets.
            self._fail(relative, "read refused (symlink, nonregular file or I/O error)")
        return None

    def read_named(self, path: str | Path) -> bytes | None:
        """``read_bytes`` lifting the default excludes but ``.git``, link targets included."""
        self._lifted = DEFAULT_EXCLUDES - {".git"}
        try:
            return self.read_bytes(path, missing_ok=True)
        finally:
            self._lifted = frozenset()

    def read_text(
        self, path: str | Path, *, missing_ok: bool = False, variants_read: Collection[str] = ()
    ) -> str | None:
        raw = self.read_bytes(path, missing_ok=missing_ok, variants_read=variants_read)
        if raw is None:
            return None
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError:
            self._fail(self._relative(path), "invalid UTF-8")
            return None

    @contextmanager
    def open_regular(
        self, path: str | Path, *, max_bytes: int | Bound | None = None
    ) -> Iterator[BinaryIO]:
        """Yield a confined regular stream or raise OSError after recording failure.

        ``max_bytes`` bounds the artifact size and bytes read; reads require an
        explicit chunk size (at most four MiB). Collection-wide budget still
        applies. The trusted consumer must not bypass read() with fileno().
        """
        named: Path | str = str(path)
        limit = self._file_bound if max_bytes is None else _bound(max_bytes, "file-bytes")
        reason = "stream refused (symlink, nonregular file or I/O error)"
        try:
            relative = named = self._relative(path)
            if self.excluded(relative):
                reason = "stream refused (excluded by policy)"
                raise CollectionError(reason)
            if not relative.parts:
                raise CollectionError("expected a regular file")
            parent = self._open_parent(relative)
            try:
                fd = self._open_leaf_no_follow(parent, relative.name)
            finally:
                os.close(parent)
            try:
                before = stat_input_file(fd)
                if not stat.S_ISREG(before.st_mode):
                    raise CollectionError("nonregular file")
                if before.st_size > limit.value:
                    raise LimitExceededError(limit)
            except BaseException:
                os.close(fd)
                raise
        except LimitExceededError as exc:
            self._fail(named, exc.bound.exceeded())
            raise OSError("confined stream unavailable") from exc
        except (OSError, CollectionError) as exc:
            self._fail(named, reason)
            raise OSError("confined stream unavailable") from exc
        stream = _BoundedReader(fd, self, relative, limit, self._budget)
        try:
            yield cast(BinaryIO, stream)
            after = os.fstat(fd)
            if descriptor_binding(before) != descriptor_binding(after) or not self._resolves_to(
                relative, after
            ):
                self._fail(relative, "file changed during collection")
                raise OSError("artifact changed during collection")
        finally:
            stream.close()

    def path_identity(self, path: str | Path) -> tuple[int, int] | None:
        """Return the device and inode a confined pathname resolves to now.

        Resolution is descriptor-relative from the pinned root and never follows
        a symlink, so a symlink at the pathname reports its own identity and
        cannot match a stream opened with ``O_NOFOLLOW``. ``None`` means the
        pathname is unavailable, excluded by policy or outside the collection
        boundary; treat it as a failed observation, never as a match.
        """
        try:
            relative = self._relative(path)
            if self.excluded(relative) or not relative.parts:
                return None
            parent = self._open_parent(relative)
            try:
                info = self._stat_exact_no_follow(parent, relative.name)
            finally:
                os.close(parent)
        except (OSError, CollectionError):
            return None
        return (info.st_dev, info.st_ino)

    def _resolves_to(self, relative: Path, info: os.stat_result) -> bool:
        # The descriptor's own status cannot reveal a replaced inode that is never
        # unlinked (an overlayfs lower layer) or an A-B-A swap during the read.
        return self.path_identity(relative) == (info.st_dev, info.st_ino)

    def hash_file(self, path: str | Path, *, max_bytes: int | Bound | None = None) -> str | None:
        """Stream SHA-256 beneath the root, with explicit individual/total bounds.

        Model collectors can choose a larger per-file limit while retaining the
        collection-wide byte budget. No artifact is deserialized or imported.
        """
        relative: Path | str = str(path)
        limit = self._file_bound if max_bytes is None else _bound(max_bytes, "file-bytes")
        try:
            relative = self._relative(path)
            if self.excluded(relative):
                return None
            parent = self._open_parent(relative)
            try:
                fd = self._open_leaf_no_follow(parent, relative.name)
            finally:
                os.close(parent)
            try:
                before = stat_input_file(fd)
                budget = self._budget
                if not stat.S_ISREG(before.st_mode):
                    raise CollectionError("nonregular file")
                if before.st_size > limit.value:
                    raise LimitExceededError(limit)
                if before.st_size > budget.remaining():
                    raise LimitExceededError(budget.bound)
                digest = hashlib.sha256()
                length = 0
                while length <= limit.value:
                    chunk = os.read(fd, min(65536, limit.value + 1 - length))
                    if not chunk:
                        break
                    length += len(chunk)
                    if length > limit.value:
                        raise LimitExceededError(limit)
                    budget.charge(len(chunk))
                    digest.update(chunk)
                after = os.fstat(fd)
                if descriptor_binding(before) != descriptor_binding(after) or not self._resolves_to(
                    relative, after
                ):
                    raise CollectionError("file changed during collection")
                return "sha256:" + digest.hexdigest()
            finally:
                os.close(fd)
        except LimitExceededError as exc:
            self._fail(relative, exc.bound.exceeded())
            return None
        except (OSError, CollectionError):
            self._fail(relative, "hash refused (symlink, nonregular file or I/O error)")
            return None

    def read_json(
        self, path: str | Path, *, missing_ok: bool = False, variants_read: Collection[str] = ()
    ) -> Any:
        from nexus_symbiote.core.hashing import MAX_JSON_NESTING, json_nesting_exceeds

        content = self.read_text(path, missing_ok=missing_ok, variants_read=variants_read)
        if content is None:
            return None
        try:
            if json_nesting_exceeds(content, MAX_JSON_NESTING):
                raise ValueError("JSON nesting exceeds depth limit")
            value = json.loads(
                content,
                object_pairs_hook=_unique_object,
                parse_constant=_refuse_constant,
                parse_float=_finite_float,
            )
        except (ValueError, RecursionError):
            self._fail(self._relative(path), "invalid JSON or duplicate keys")
            return None
        if value is None:
            self._fail(self._relative(path), "JSON document is null")
        return value

    def root_entries(self) -> list[str]:
        """Sorted names directly beneath the pinned root; nothing is opened or followed.

        The listing is charged to the same entry budget as a walk.
        """
        if self._root_fd is None:
            return []
        names: list[str] = []
        if self._entries_exhausted:
            return []
        try:
            with os.scandir(self._root_fd) as stream:
                for entry in stream:
                    if self._entry_budget[0] <= 0:
                        self._entries_exceeded(Path("."))
                        return []
                    self._entry_budget[0] -= 1
                    names.append(entry.name)
        except OSError:
            self._fail(".", "root directory cannot be listed")
            return []
        return sorted(names)

    def _entries_exceeded(self, relative: Path) -> None:
        # One failure names where the walk stopped; later listings stop silently.
        self._fail(relative, self._entry_bound.exceeded())
        self._entry_budget[0] = 0
        self._entries_exhausted = True

    def iter_files(
        self,
        directory: str | Path = ".",
        *,
        directory_links: list[Path] | None = None,
        skipped: list[Path] | None = None,
    ) -> Iterator[Path]:
        """Yield root-relative file paths, never through more than one symlink.

        A ``directory`` reached through one in-root symlink is walked under its
        target's name. Inside a walk that did not start through a symlink, a symlink
        to a regular file beneath the root is yielded under its own name and read
        through its target. A symlink to a directory inside the walked one is skipped,
        because that directory is walked under its own name; one to a directory
        elsewhere beneath the root is walked once under its target's name, as a host
        reading the walked directory would read it, and one to the root or to a
        directory that holds the walked one is a failure. Within a directory walked
        through a symlink, whether ``directory`` itself or a directory symlink met
        during the walk, every symlink, including one to a regular file, is a failure
        recorded as reached through another symlink and is not yielded: reading it
        would follow a second link. ``directory_links`` collects the directory
        symlinks the walk met, and ``skipped`` the entries it neither entered nor
        yielded because their name is one of ``DEFAULT_EXCLUDES``, in any spelling a
        case-insensitive file system treats as that name. A non-empty one of those
        entries is also a coverage gap, unless the collection was told to accept
        default excludes or ``skipped`` is set so the caller reports it. An empty
        directory is not a gap. Every other symlink is a recorded
        failure. A directory whose
        ``st_dev`` differs from the root's is a mount point, recorded as excluded and
        not entered; regular files are not refused for their device alone. Past the
        collection's listing bounds, the walk's per-entry failures end it as one line
        per reason.
        """
        try:
            relative = self._relative(directory)
        except CollectionError:
            self._fail(
                directory, "directory is outside collection root or not a plain relative path"
            )
            return
        if self.excluded(relative) or self._root_fd is None:
            return
        try:
            fd, walked = self._open_directory(relative)
        except FileNotFoundError:
            if relative.parts:
                self._report_case_variants(relative, ())
            return
        except _LinkRefusedError as exc:
            self._fail(relative, exc.reason)
            return
        except (OSError, CollectionError):
            self._fail(relative, "directory unavailable or contains a symlink")
            return
        # Each walk ends with its own summary lines, so a caller comparing the failure
        # count before and after a walk sees every walk that met a failure. Once the
        # entry budget is spent, a later walk lists nothing and records nothing: the
        # one failure that spent it names where collection stopped.
        scope = _WalkScope(walked, directory_links, _Unlisted(), skipped)
        try:
            yield from self._walk(
                fd, walked, 0, self._entry_budget, scope, followed=walked != relative
            )
        finally:
            os.close(fd)
            self._summarize(scope.unlisted)

    def _walk(
        self,
        directory_fd: int,
        relative: Path,
        depth: int,
        budget: list[int],
        scope: _WalkScope,
        *,
        followed: bool = False,
    ) -> Iterator[Path]:
        if depth > self.max_depth:
            self._record(relative, self._depth_bound.exceeded(), scope.unlisted)
            return
        if self._entries_exhausted:
            return
        entries: list[str] = []
        try:
            with os.scandir(directory_fd) as stream:
                for entry in stream:
                    if budget[0] <= 0:
                        self._entries_exceeded(relative)
                        return
                    budget[0] -= 1
                    entries.append(entry.name)
            for name in sorted(entries):
                if _undecodable(name):
                    # A surrogate-escaped name cannot be written to, or read back from,
                    # an inventory; the entry and anything beneath it are a gap.
                    self._record(
                        relative / _escaped(name),
                        "name is not valid UTF-8; not collected",
                        scope.unlisted,
                    )
                    continue
                child = relative / name
                if self.excluded(child):
                    if scope.skipped is not None and _default_excluded(name):
                        scope.skipped.append(child)
                    # A caller that collects skipped reports the entry itself.
                    if (
                        scope.skipped is None
                        and _default_excluded(name)
                        and self._default_exclude_occupied(directory_fd, name)
                    ):
                        in_agent_config = _under_agent_configuration_directory(child)
                        canonical = fold_name(name)
                        accepted = canonical in self._accepted_default_names or (
                            canonical == ".git"
                            and ROOT_GIT_METADATA in self._accepted_default_names
                        )
                        if (
                            not in_agent_config
                            and accepted
                            and (canonical != ".git" or self._is_git_metadata(directory_fd, child))
                        ):
                            self.accepted_default_names.add(canonical)
                            if self._accepted_default_exclusions is not None:
                                self._accepted_default_exclusions.append(
                                    reference_text(child.as_posix())
                                )
                        else:
                            reason = (
                                AGENT_DEFAULT_EXCLUDE_REASON
                                if in_agent_config
                                else DEFAULT_EXCLUDE_REASON
                            )
                            self._exclusion_log.add(f"{child.as_posix()}: {reason}")
                    continue
                metadata = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
                if (
                    self._root_dev is not None
                    and stat.S_ISDIR(metadata.st_mode)
                    and metadata.st_dev != self._root_dev
                ):
                    self._record(child, "cross-filesystem mount excluded", scope.unlisted)
                    continue
                if stat.S_ISLNK(metadata.st_mode):
                    if followed:
                        self._record(
                            child, "symlink reached through another symlink", scope.unlisted
                        )
                        continue
                    try:
                        target = self._walked_link(directory_fd, child)
                        follow = target is not None and self._follows(child, target, scope)
                    except _LinkRefusedError as exc:
                        self._record(child, exc.reason, scope.unlisted)
                        continue
                    except LimitExceededError:
                        # The listing that spent the entry budget recorded it once.
                        return
                    if target is None:
                        yield child
                    elif follow:
                        yield from self._walk_target(target, depth + 1, budget, scope)
                elif stat.S_ISDIR(metadata.st_mode):
                    if child in scope.walked:
                        # Walked already, through a symlink that named it.
                        continue
                    child_fd = os.open(
                        name,
                        os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0),
                        dir_fd=directory_fd,
                    )
                    try:
                        if (
                            self._root_dev is not None
                            and os.fstat(child_fd).st_dev != self._root_dev
                        ):
                            self._record(child, "cross-filesystem mount excluded", scope.unlisted)
                            continue
                        yield from self._walk(
                            child_fd, child, depth + 1, budget, scope, followed=followed
                        )
                    finally:
                        os.close(child_fd)
                elif stat.S_ISREG(metadata.st_mode):
                    yield child
                else:
                    self._record(child, "nonregular file excluded", scope.unlisted)
        except OSError:
            self._record(relative, "directory changed or could not be read", scope.unlisted)

    def _follows(self, link: Path, target: Path, scope: _WalkScope) -> bool:
        """Whether a walk goes on into the directory a walked symlink names."""
        follow = not scope.covers(target)
        if follow:
            if not target.parts:
                raise _LinkRefusedError("symlink target is the collection root")
            if target in scope.top.parents:
                raise _LinkRefusedError("symlink target holds the walked directory")
            scope.walked.add(target)
        if scope.links is not None:
            scope.links.append(link)
        return follow

    def _walk_target(
        self, target: Path, depth: int, budget: list[int], scope: _WalkScope
    ) -> Iterator[Path]:
        try:
            fd = self._open_directory_no_follow(target)
        except LimitExceededError:
            return
        except (OSError, CollectionError):
            self._record(target, "directory changed or could not be read", scope.unlisted)
            return
        try:
            yield from self._walk(fd, target, depth, budget, scope, followed=True)
        finally:
            os.close(fd)

    def link_target(self, path: str | Path) -> str | None:
        """The in-root target that a read of ``path`` followed, or ``None``."""
        try:
            return self._links.get(self._relative(path).as_posix())
        except CollectionError:
            return None

    def in_root_target(self, path: str | Path) -> Path | None:
        """The regular file ``path`` names, through at most one in-root symlink.

        Returns the root-relative path that holds the bytes, which is ``path`` itself
        when no symlink is involved, or ``None`` when no such regular file exists.
        Ordinary path refusals are silent; a spent listing budget is a failure and a
        path excluded by policy is recorded as a coverage gap.
        """
        found = self.regular_file(path)
        return None if found is None else found[0]

    def regular_file(self, path: str | Path) -> tuple[Path, int] | None:
        """``in_root_target`` with the file's size, so a caller can choose how to read it."""
        try:
            relative = self._relative(path)
            if self._root_fd is None or not relative.parts or self.excluded(relative):
                return None
            fd, opened = self._open_file(relative)
        except (OSError, CollectionError):
            return None
        try:
            info = os.fstat(fd)
            return (opened, info.st_size) if stat.S_ISREG(info.st_mode) else None
        finally:
            os.close(fd)

    def is_directory(self, path: str | Path) -> bool:
        """Whether ``path`` is a directory, reached through at most one in-root symlink.

        Ordinary path refusals are silent; a spent listing budget is a failure and a
        path excluded by policy is recorded as a coverage gap. A caller that goes on
        to read or walk the path records any other refusal then.
        """
        try:
            relative = self._relative(path)
            if self._root_fd is None or not relative.parts or self.excluded(relative):
                return False
            fd, _ = self._open_directory(relative)
        except (OSError, CollectionError):
            return False
        os.close(fd)
        return True

    def _open_no_follow(self, relative: Path) -> int:
        parent = self._open_parent(relative)
        try:
            return self._open_leaf_no_follow(parent, relative.name)
        finally:
            os.close(parent)

    def _open_file(self, relative: Path) -> tuple[int, Path]:
        """Open a file without following links, or through one in-root symlink."""
        try:
            return self._open_no_follow(relative), relative
        except OSError as exc:
            if exc.errno not in _LINK_ERRNOS:
                raise
            resolved = self._link_target(relative)
            if resolved is None:
                raise
        target, below = resolved
        try:
            fd = self._open_no_follow(target)
        except FileNotFoundError as exc:
            if below and self._linked_directory_exists(target, below):
                raise
            raise _LinkRefusedError("symlink target is unavailable") from exc
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS:
                raise _LinkRefusedError(
                    "symlink target is or passes through another symlink or a non-directory"
                ) from exc
            raise
        self._links[relative.as_posix()] = target.as_posix()
        return fd, target

    def _open_directory(self, relative: Path) -> tuple[int, Path]:
        """Open a directory without following links, or through one in-root symlink."""
        if self._root_fd is None:
            raise CollectionError("collection root unavailable")
        try:
            return self._open_directory_no_follow(relative), relative
        except OSError as exc:
            if exc.errno not in _LINK_ERRNOS:
                raise
            resolved = self._link_target(relative)
            if resolved is None:
                raise
        target, below = resolved
        try:
            fd = self._open_directory_no_follow(target)
        except FileNotFoundError as exc:
            if below and self._linked_directory_exists(target, below):
                raise
            raise _LinkRefusedError("symlink target is unavailable") from exc
        except OSError as exc:
            if exc.errno in _LINK_ERRNOS:
                raise _LinkRefusedError(
                    "symlink target is not a directory, or is or passes through another symlink"
                ) from exc
            raise
        self._links[relative.as_posix()] = target.as_posix()
        return fd, target

    def _open_directory_no_follow(self, relative: Path) -> int:
        assert self._root_fd is not None
        fd = os.dup(self._root_fd)
        try:
            for part in relative.parts:
                next_fd = self._open_dir_part(fd, part)
                os.close(fd)
                fd = next_fd
            return fd
        except BaseException:
            os.close(fd)
            raise

    def _linked_directory_exists(self, target: Path, below: int) -> bool:
        """Whether the directory a symlink names exists, ``below`` components above ``target``."""
        try:
            fd = self._open_directory_no_follow(Path(*target.parts[: len(target.parts) - below]))
        except (OSError, CollectionError):
            return False
        os.close(fd)
        return True

    def _link_target(self, relative: Path) -> tuple[Path, int] | None:
        """Lexically resolve the first symlink on a confined path, or ``None`` if none.

        Returns the resolved path and how many components of ``relative`` follow the
        link. Every component before the link is a directory opened without following
        links, so the link's own directory holds no symlink. Raises
        ``_LinkRefusedError`` when the link cannot be covered through a target beneath
        the root.
        """
        if self._root_fd is None:
            return None
        fd = os.dup(self._root_fd)
        try:
            for index, part in enumerate(relative.parts):
                info = self._stat_exact_no_follow(fd, part)
                if stat.S_ISLNK(info.st_mode):
                    text = os.readlink(part, dir_fd=fd)
                    target = _lexical_target(Path(*relative.parts[:index]), text)
                    if not target.parts:
                        # Through such a link the root's own entries, such as a root
                        # Settings.json, would stand for the names below it.
                        raise _LinkRefusedError("symlink target is the collection root")
                    target = target.joinpath(*relative.parts[index + 1 :])
                    self._check_target_depth(target)
                    if self.excluded(target):
                        raise _LinkRefusedError("symlink target is excluded from collection")
                    return target, len(relative.parts) - index - 1
                if index + 1 == len(relative.parts) or not stat.S_ISDIR(info.st_mode):
                    return None
                next_fd = self._open_dir_part(fd, part)
                os.close(fd)
                fd = next_fd
            return None
        except FileNotFoundError:
            return None
        finally:
            os.close(fd)

    def _check_target_depth(self, target: Path) -> None:
        # Each component of a target is opened, for every read and walk that meets it.
        if len(target.parts) > self.max_depth + 1:
            raise _LinkRefusedError("symlink target is too deep; " + self._depth_bound.exceeded())

    def _same_link(self, relative: Path, opened: Path) -> bool:
        """Whether a followed link still names the target that was read."""
        if opened == relative:
            return True
        resolved = self._link_target(relative)
        return resolved is not None and resolved[0] == opened

    def _walked_link(self, directory_fd: int, child: Path) -> Path | None:
        """The directory a walked symlink names, or ``None`` when it names a regular file.

        Raises ``_LinkRefusedError`` for a symlink that is not covered through an in-root
        regular file or directory reached without a further symlink.
        """
        target = _lexical_target(child.parent, os.readlink(child.name, dir_fd=directory_fd))
        if not target.parts:
            return target
        self._check_target_depth(target)
        if self.excluded(target):
            raise _LinkRefusedError("symlink target is excluded from collection")
        try:
            parent = self._open_parent(target)
            try:
                info = self._stat_exact_no_follow(parent, target.name)
            finally:
                os.close(parent)
        except FileNotFoundError as exc:
            raise _LinkRefusedError("symlink target is unavailable") from exc
        except LimitExceededError:
            # The entry budget is spent. Wrapping it as a refused link lets the
            # walk continue and record a second failure for the same limit.
            raise
        except CollectionError as exc:
            raise _LinkRefusedError(str(exc)) from exc
        except OSError as exc:
            raise _LinkRefusedError("symlink target passes through another symlink") from exc
        if stat.S_ISREG(info.st_mode):
            return None
        if stat.S_ISDIR(info.st_mode):
            if self._root_dev is not None and info.st_dev != self._root_dev:
                raise _LinkRefusedError("symlink target crosses a filesystem mount boundary")
            return target
        if stat.S_ISLNK(info.st_mode):
            raise _LinkRefusedError("symlink target is another symlink")
        raise _LinkRefusedError("symlink target is not a regular file or directory")

    def _folded(self, directory: Path) -> dict[str, list[tuple[str, str]]] | None:
        """A directory's entries and their kinds by folded name, listed once per collection.

        Case-variant searches share one budget of ``max_entries`` per collection, which
        each listing spends on the directory and its entries, as a walk would; the
        listing that would exceed it stops every further search. A directory that cannot
        be opened without following a symlink has no listing: the read that missed
        records why.
        """
        if directory in self._listings:
            return self._listings[directory]
        index: dict[str, list[tuple[str, str]]] | None = None
        try:
            fd = self._open_directory_no_follow(directory)
        except LimitExceededError:
            # The spent entry budget is recorded once, where it was spent.
            raise _VariantSearchStoppedError from None
        except (OSError, CollectionError):
            self._listings[directory] = None
            return None
        try:
            entries: list[tuple[str, str]] = []
            with os.scandir(fd) as stream:
                for entry in stream:
                    if len(entries) + 1 >= self._variant_budget:
                        self._stop_variant_searches(directory)
                    kind = (
                        _LINK
                        if entry.is_symlink()
                        else _DIRECTORY
                        if entry.is_dir(follow_symlinks=False)
                        else _OTHER
                    )
                    entries.append((entry.name, kind))
            self._variant_budget -= len(entries) + 1
            index = {}
            for name, kind in entries:
                index.setdefault(fold_name(name), []).append((name, kind))
        except OSError:
            self._fail(directory, "directory changed or could not be read")
        finally:
            os.close(fd)
        self._listings[directory] = index
        return index

    def _stop_variant_searches(self, at: Path) -> NoReturn:
        """Record the spent case-variant budget once; no later path is searched."""
        self._variant_budget = 0
        self._variants_stopped = True
        self._fail(at, self._entry_bound.exceeded())
        raise _VariantSearchStoppedError

    def case_variants(self, path: str | Path) -> list[Path]:
        """Existing paths that differ from ``path`` only by case or normalisation.

        Case-insensitive file systems, the default on macOS and Windows, open such a
        variant when ``path`` itself is absent. Listings are descriptor-relative and
        indexed by folded name once per collection. An exact-named directory symlink
        on the path is resolved as a read resolves it, lexically and once, and the
        search goes on in its target; a symlinked variant is reported as found.
        """
        return [logical for logical, _ in self._variants(path)]

    def _variants(self, path: str | Path) -> list[tuple[Path, Path]]:
        """Each case variant as the path a host opens and the path that holds it.

        The search of a path stops when it has found ``_MAX_CASE_VARIANTS`` variants or
        meets more spellings of one name than that in a directory, which is a failure;
        once the collection's budget is spent no further path is searched, and one
        failure covers them: the search that spent it records it, or, when a listing
        spent it exactly, the first search that finds nothing left.
        """
        try:
            relative = self._relative(path)
        except CollectionError:
            return []
        if self._root_fd is None or not relative.parts:
            return []
        if self._variant_budget <= 0:
            if not self._variants_stopped:
                self._variants_stopped = True
                self._fail(relative, self._entry_bound.exceeded())
            return []
        found: list[tuple[Path, Path]] = []
        parts = relative.parts

        def descend(real: Path, logical: tuple[str, ...], exact: bool, followed: bool) -> None:
            if not exact:
                # Only another spelling branches the search, so only those visits are
                # counted; a search along the requested spelling takes one per component.
                if self._variant_budget <= 1:
                    self._stop_variant_searches(Path(*logical))
                self._variant_budget -= 1
            index = len(logical)
            spellings = (self._folded(real) or {}).get(fold_name(parts[index]), [])
            if len(spellings) > _MAX_CASE_VARIANTS:
                self._fail(
                    Path(*logical, parts[index]),
                    f"more than {_MAX_CASE_VARIANTS} names in its directory differ from it "
                    "only by case or normalisation and are not checked",
                )
                raise _VariantSearchStoppedError
            for name, kind in spellings:
                same = exact and name == parts[index]
                here = (*logical, name)
                if index + 1 == len(parts):
                    if not same:
                        found.append((Path(*here), real / name))
                elif kind == _DIRECTORY:
                    descend(real / name, here, same, followed)
                elif kind == _LINK and not same:
                    rest = parts[index + 1 :]
                    found.append((Path(*here, *rest), real.joinpath(name, *rest)))
                elif kind == _LINK and not followed:
                    target = self._directory_link(real, name)
                    if target is not None:
                        descend(target, here, True, True)
                if len(found) >= _MAX_CASE_VARIANTS:
                    raise _VariantSearchStoppedError

        try:
            descend(Path(), (), True, False)
        except _VariantSearchStoppedError:
            # Bounded case-variant search reached _MAX_CASE_VARIANTS; return collected variants.
            pass
        return found

    def _directory_link(self, directory: Path, name: str) -> Path | None:
        """The lexical in-root target of the symlink ``name`` in ``directory``, or ``None``."""
        try:
            fd = self._open_directory_no_follow(directory)
            try:
                text = os.readlink(name, dir_fd=fd)
            finally:
                os.close(fd)
            target = _lexical_target(directory, text)
        except (OSError, CollectionError):
            return None
        if not target.parts or len(target.parts) > self.max_depth or self.excluded(target):
            return None
        return target

    def report_agent_default_exclude(self, path: Path) -> None:
        relative = path.as_posix()
        self._exclusion_log.prefer(
            f"{relative}: {AGENT_DEFAULT_EXCLUDE_REASON}", f"{relative}: {DEFAULT_EXCLUDE_REASON}"
        )

    def report_case_variant(self, variant: str | Path, path: str | Path) -> None:
        """Record ``variant``, another spelling of ``path`` found by a walk, as a failure.

        A variant is reported once per collection, however many paths lead to it.
        """
        self._report_variant(Path(variant), Path(variant), Path(path))

    def _report_variant(self, variant: Path, real: Path, path: Path) -> None:
        """Report the variant that ``real`` holds, under the path a host opens it by."""
        if real in self._variants_reported:
            # Every directory symlink to one directory of spellings would list them again.
            return
        self._variants_reported.add(real)
        self._fail(
            variant,
            f"case variant of {path.as_posix()} is the active file on "
            "case-insensitive file systems and is not inventoried",
            key=_CASE_VARIANT,
        )

    def _report_case_variants(self, relative: Path, variants_read: Collection[str]) -> None:
        for variant, real in self._variants(relative):
            if variant.as_posix() in variants_read or self.excluded(variant) or self.excluded(real):
                continue
            self._report_variant(variant, real, relative)
