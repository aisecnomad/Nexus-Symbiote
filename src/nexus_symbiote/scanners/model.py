"""Model weight collector.

Discovers model files in a project and classifies serialization format safety
without loading anything. It binds by digest the other files a loader reads
with the weights: ONNX external data, SavedModel variables and assets, shard
indexes, configuration, tokenizer files, chat templates and declared custom
code. Weight files count as signed only under an operator signature policy.
"""

from __future__ import annotations

import ast
import hashlib
import hmac
import io
import json
import os
import pickletools
import re
import tokenize
import warnings
import zlib
from collections import deque
from collections.abc import Callable, Iterable, Mapping, Sequence
from contextlib import nullcontext
from dataclasses import dataclass, field, replace
from functools import partial
from pathlib import Path, PurePath, PurePosixPath
from typing import Any, BinaryIO, NamedTuple, cast

from nexus_symbiote import limits
from nexus_symbiote.core.enums import (
    AssuranceLevel,
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import (
    descriptor_binding,
    hash_bytes,
    hash_canonical,
    open_regular_file,
)
from nexus_symbiote.core.models import (
    NAMED_FORMAT_PROPERTY,
    ClaimEvidence,
    ModelComponent,
    RiskAssessment,
)
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.scanners.credential_files import credential_gap, credential_shaped
from nexus_symbiote.scanners.shadowscan import REPORT_PATHS
from nexus_symbiote.utils import pickle_load
from nexus_symbiote.utils.confined import MAX_ENTRIES, ConfinedCollection
from nexus_symbiote.utils.crypto import (
    POLICY_REF_PREFIX,
    SIGNING_EVIDENCE_CLAIM,
    SIGSTORE_MISSING,
    VERIFIED_SIGNING_STATUSES,
    ArtifactPolicy,
    DigestPinPolicy,
    SigningStatus,
    SigstoreArtifactPolicy,
    VerificationResult,
    policy_entries,
    verify_sigstore_bundle,
)
from nexus_symbiote.utils.model_formats import (
    GGUF_LIMIT,
    GGUF_MAGIC,
    FormatError,
    InspectionBudget,
    gguf_metadata,
    onnx_external_data,
    template_escape_markers,
)
from nexus_symbiote.utils.tensors import HeaderLimitError, fingerprint_stream, read_header
from nexus_symbiote.utils.terminal import neutralize

MODEL_EXTENSIONS = {
    ".safetensors": ("safetensors", "safe-tensors"),
    ".onnx": ("onnx", "onnx"),
    ".pt": ("pt", "pytorch"),
    ".pth": ("pth", "pytorch"),
    ".bin": ("bin", "pytorch-legacy"),
    ".pickle": ("pickle", "pickle"),
    ".pkl": ("pickle", "pickle"),
    ".pck": ("pickle", "pickle"),
    ".dill": ("pickle", "dill"),
    ".joblib": ("joblib", "scikit-learn"),
    ".gguf": ("gguf", "llama.cpp"),
    ".ggml": ("ggml", "llama.cpp-legacy"),
    ".ckpt": ("ckpt", "pytorch-checkpoint"),
    ".pdparams": ("pdparams", "paddlepaddle"),
    ".h5": ("hdf5", "keras-hdf5"),
    ".hdf5": ("hdf5", "keras-hdf5"),
    ".keras": ("keras", "keras"),
    ".tflite": ("tflite", "tensorflow-lite"),
    ".mlmodel": ("mlmodel", "core-ml"),
    ".pte": ("pte", "executorch"),
}
# Generic protobuf files are not models; only the SavedModel graph names are.
NAMED_MODEL_FILES = {
    "saved_model.pb": ("pb", "tensorflow-savedmodel"),
    "saved_model.pbtxt": ("pbtxt", "tensorflow-savedmodel"),
}
# The formats whose header a bounded reader checks. A file named as one is recorded
# with that format and a model type only when its header is the format's; the other
# formats have no such check and are recorded from the name.
_HEADER_CHECKED = frozenset({"safetensors", "gguf"})

MODEL_CONFIG_FILES = [
    "config.json",
    "model_config.json",
    "adapter_config.json",
    "tokenizer_config.json",
    "generation_config.json",
    "quantize_config.json",
    "preprocessor_config.json",
    "processor_config.json",
    "chat_template.json",
]
TOKENIZER_FILES = [
    "tokenizer.json",
    "tokenizer.model",
    "spiece.model",
    "sentencepiece.bpe.model",
    "vocab.json",
    "vocab.txt",
    "merges.txt",
    "special_tokens_map.json",
    "added_tokens.json",
]
CHAT_TEMPLATE_FILES = ["chat_template.jinja", "chat_template.jinja2"]
CHAT_TEMPLATE_DIRECTORY = "additional_chat_templates"
SAVEDMODEL_DIRECTORIES = ["variables", "assets", "assets.extra"]
SAVEDMODEL_FILES = ["fingerprint.pb", "keras_metadata.pb"]

SIGNING_FILES = [
    "model.sig",
    "model.sigstore",
    ".sigstore",
    "signature.json",
    "model.intoto.jsonl",
]
SIGNING_SUFFIXES = [".sig", ".sigstore", ".sigstore.json"]

MAX_MODEL_HEADER_BYTES = 1024 * 1024
# The most a content check reads from where a pickle or a NumPy array header starts:
# a pickle sample, or an array header, which no version 1 header exceeds.
MAX_PICKLE_INSPECTION_BYTES = 65536
# Opcodes read from a pickle sample, which bounds the work, and the well-formed
# binary opcodes after PROTO that recognize a pickle whatever follows them.
MAX_PICKLE_OPCODES = 4096
MAX_PICKLE_MARKS = 64
MIN_PICKLE_OPCODES = 16
# A ZIP central directory is listed from the archive's end; a longer one is not read.
MAX_ZIP_DIRECTORY_BYTES = MAX_MODEL_HEADER_BYTES
_ZIP_END_RECORD_BYTES = 22 + 65_535 + 20 + 56
_ZIP_TAIL_BYTES = MAX_ZIP_DIRECTORY_BYTES + _ZIP_END_RECORD_BYTES
# How far from the end miniz finds an end record: it searches back in 4 KiB reads past
# the 65,535-byte comment, so a record up to this far back is one it can take.
_MINIZ_END_SEARCH = 69_584
ZIP_PICKLE_MEMBER = "ZIP archive with a pickle member; torch.load unpickles it"
ZIP_OBJECT_ARRAY = (
    "ZIP archive with a NumPy object-dtype array member; np.load(allow_pickle=True) unpickles it"
)
ZIP_WITHOUT_PICKLE = (
    "ZIP archive whose directory lists no pickle member; no bounded structural validator "
    "for this format/loader"
)
ZIP_DIRECTORY_UNREAD = (
    "ZIP archive whose directory is malformed or over the inspection limit; no bounded "
    "structural validator for this format/loader"
)
ZIP_MEMBER_UNREAD = (
    "ZIP archive with a member that could not be inspected (overlapping, compressed by "
    "another method or with an array header past the inspection limits); no bounded "
    "structural validator for this format/loader"
)
# ZIP verdicts that leave the rating unknown; each read the archive to its end.
_ZIP_UNRATED = frozenset({ZIP_WITHOUT_PICKLE, ZIP_DIRECTORY_UNREAD, ZIP_MEMBER_UNREAD})
NUMPY_OBJECT_ARRAY = "NumPy object-dtype array; np.load(allow_pickle=True) unpickles it"
NUMPY_HEADER_UNREAD = (
    "NumPy array whose header is past the inspection limits; no bounded structural "
    "validator for this format/loader"
)
PICKLE_UNREAD = (
    "pickle opcode stream that names no callable before the inspection limits; "
    "no bounded structural validator for this format/loader"
)
PICKLE_NAME_UNCALLED = (
    "pickle opcode stream that resolves an importable name and, within the inspection "
    "limits, never uses it; no bounded structural validator for this format/loader"
)
PICKLE_FRAME_TAIL = (
    "pickle opcode stream with bytes after a STOP inside its frame, where loaders resume "
    "at different offsets; no bounded structural validator for this format/loader"
)
INSPECTION_FAILED = (
    "Artifact could not be read or its content inspected; no bounded structural "
    "validator for this format/loader"
)
GGUF_MISMATCH = (
    "Named as GGUF, but the content does not start with the GGUF magic; "
    "the format was not established"
)
GGUF_TOO_SHORT = (
    "Named as GGUF, but too short to hold the GGUF magic; the format was not established"
)
PICKLE_NAME_UNREADABLE = "Potential code-executing loader format (artifact could not be inspected)"
PICKLE_NAME_UNEVIDENCED = "Named pickle-family format; no pickle evidence in the inspected prefix"
PICKLE_NAME_EMPTY = "empty file"
PICKLE_NAME_WRAPPED = (
    "Potential code-executing loader format (compressed or archived stream; decompressed "
    "content not inspected)"
)
PICKLE_NAME_GGUF = (
    "Potential code-executing loader format (GGUF content under a pickle-family name; its "
    "chat templates are not inspected under this name)"
)
_UNVALIDATED = "; no bounded structural validator for this format/loader"
# Compression and archive magic that pandas, joblib and torch unwrap before unpickling.
_WRAPPER_MAGIC = (
    b"\x1f\x8b",
    b"BZh",
    b"\xfd7zXZ\x00",
    b"\x28\xb5\x2f\xfd",
    b"\x04\x22\x4d\x18",
    b"ZF",
    b"\x78\x01",
    b"\x78\x5e",
    b"\x78\x9c",
    b"\x78\xda",
)
_TAR_MAGIC_OFFSET = 257
_TAR_MAGIC = b"ustar"
_TAR_BLOCK = 512
_TAR_CHECKSUM = slice(148, 156)
# mode, uid, gid, size, mtime, devmajor and devminor, which tarfile parses in every header.
_TAR_NUMBERS = (
    slice(100, 108),
    slice(108, 116),
    slice(116, 124),
    slice(124, 136),
    slice(136, 148),
    slice(329, 337),
    slice(337, 345),
)
_LZMA_ALONE_HEADER = 13
_LZMA_JOBLIB_PREFIX = b"\x5d\x00"
# Content that a bound left unread: a file no model name rates is inventoried for it.
_CONTENT_UNREAD = frozenset(
    {
        ZIP_DIRECTORY_UNREAD,
        ZIP_MEMBER_UNREAD,
        NUMPY_HEADER_UNREAD,
        PICKLE_UNREAD,
        PICKLE_NAME_UNCALLED,
        PICKLE_FRAME_TAIL,
    }
)
_NUMPY_MAGIC = b"\x93NUMPY"
# Dtype names that make an object dtype: the type code, with the sizes NumPy accepted,
# and the names that NumPy and its earlier releases accept.
_OBJECT_TYPE = re.compile(r"O\d*|[Oo]bject\w*")
ZIP_NOT_GGUF = "the file is a ZIP archive"
# Chat templates a finding names; it counts the rest.
_LISTED_TEMPLATES = 3
_UNSAFE_SUFFIXES = {
    ".pickle",
    ".pkl",
    ".pck",
    ".dill",
    ".pt",
    ".pth",
    ".bin",
    ".joblib",
    ".ckpt",
    ".pdparams",
}
# Archive and compression suffixes do not change what a pickle loader unpickles.
_PICKLE_WRAPPERS = {".tar", ".gz", ".bz2", ".xz", ".lzma", ".zst"}
_TEXT_PICKLE_START = frozenset(b"(cNILFSV}])KJMUTX")
# Bytes that start an opcode: pickle.load reads a pickle that starts with any of them.
_OPCODE_BYTES = frozenset(opcode.code.encode("latin-1")[0] for opcode in pickletools.opcodes)
_INDEX = re.compile(r"(?P<base>.+?)\.index(?:\.[A-Za-z0-9_-]+)?\.json", re.IGNORECASE)
# transformers reads ``repository--module.Class``; a repository need not name an owner.
_CODE_REFERENCE = re.compile(
    r"(?:[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)?--)?"
    r"(?:[A-Za-z_][A-Za-z0-9_]*\.)+[A-Za-z_][A-Za-z0-9_]*"
)
_CREDENTIAL_PYTHON_STEM = re.compile(
    r"(?i)(?:^|[_.-])(?:secrets?|credentials?|tokens?|passwords?|passphrases?"
    r"|api[_-]?keys?|private[_-]?keys?)(?:$|[_.-])"
)
_HUB_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}(?:/[A-Za-z0-9][A-Za-z0-9._-]{0,95})?")
_CONFIG_STRING_FIELDS = ("peft_type", "quantization_method", "quant_method")
SIGSTORE_METHOD = "sigstore-message-signature"
OMS_DSSE_METHOD = "openssf-model-signing-dsse"
DIGEST_PIN_METHOD = "digest-pin"
DOCUMENTATION = "https://github.com/aisecnomad/Nexus-Symbiote/blob/main/docs/model-integrity.md"
UNUSED_ENTRY = "signature policy entry names no collected model weight file"
REPORT_ENTRY_KIND = (
    "the ShadowScan report needs a sigstore-message-signature entry; "
    "a digest pin does not authenticate its producer"
)
UNREAD_REPORT_ENTRY = (
    "signature policy entry names a ShadowScan report location that the importer does not read"
)
OUTSIDE_ENTRY = "signature policy entry names an artifact outside the root"
BUDGET_EXHAUSTED = "validation byte budget exhausted"
# Real checkpoints keep one shard index per format and variant in a directory.
MAX_SHARD_INDEXES = 16
# Every file one walk may list, charged once as a shard-index entry and once more
# when it is bound to a model: twice the entries limit. These two values are the
# defaults; each scan and validation charges twice the operator's limit in force.
MAX_WEIGHT_FILE_BINDINGS = 2 * MAX_ENTRIES
# Each model records the configuration, tokenizer, chat template and custom-code
# digests of its directory, so those records are bounded across one scan as well.
MAX_SHARED_DIGESTS = 2 * MAX_ENTRIES
TOO_MANY_INDEXES = "model directory holds more shard indexes than one directory may bind"
INDEX_UNBOUND = (
    "a shard index beside this file could not be read, parsed or bound; "
    "what it makes a loader open is unknown"
)
BINDINGS_EXHAUSTED = (
    "weight files bound to models exceed what one collection records; "
    "the bound files of this and later models are unknown"
)
SHARED_DIGESTS_EXHAUSTED = (
    "configuration, tokenizer, chat template and custom code digests exceed what one "
    "scan records; those of this and later models are not recorded"
)

Verify = Callable[..., VerificationResult]


# A file no model name rates is checked by its content under these names and suffixes.
_MODEL_DIR_NAMES = frozenset({"models", "model", "weights", "checkpoints", "checkpoint"})
_CONTENT_SUFFIXES = frozenset({".dat", ".npy", ".npz"})
# A model directory's own readers open these, and no loader unpickles source code.
_DIRECTORY_FILES = frozenset([*MODEL_CONFIG_FILES, *TOKENIZER_FILES, *CHAT_TEMPLATE_FILES])
_SOURCE_SUFFIXES = frozenset({".py", ".jinja", ".jinja2"})


def _pickle_family(path: PurePath) -> bool:
    suffixes = [suffix.lower() for suffix in path.suffixes]
    if suffixes and suffixes[-1] in _UNSAFE_SUFFIXES:
        return True
    return (
        len(suffixes) > 1 and suffixes[-1] in _PICKLE_WRAPPERS and suffixes[-2] in _UNSAFE_SUFFIXES
    )


def _content_candidate(path: Path) -> bool:
    """Whether a file no model name rates is inventoried when its content is a payload.

    ``.npy``, ``.npz`` and the generic ``.dat`` are candidates anywhere; any other name
    is one below a ``model``, ``models``, ``weights``, ``checkpoint`` or ``checkpoints``
    directory, where a pickle renamed off the suffix list is kept. A model directory's
    configuration, tokenizer and chat template files, which its own readers open once,
    and Python and Jinja sources, which no loader unpickles, are not candidates.
    """
    if model_format(path) is not None:
        return False
    suffix = path.suffix.lower()
    if path.name in _DIRECTORY_FILES or suffix in _SOURCE_SUFFIXES:
        return False
    return suffix in _CONTENT_SUFFIXES or any(
        part.lower() in _MODEL_DIR_NAMES for part in path.parts[:-1]
    )


def _content_format(explanation: str) -> tuple[str, str]:
    """The (format key, format name) of a file inventoried by what its content is."""
    if explanation in (NUMPY_OBJECT_ARRAY, NUMPY_HEADER_UNREAD):
        return "npy", "numpy"
    if explanation in (ZIP_PICKLE_MEMBER, ZIP_OBJECT_ARRAY) or explanation in _ZIP_UNRATED:
        return "zip", "zip-archive"
    return "pickle", "pickle"


def model_format(path: Path) -> tuple[str, str] | None:
    """Return the (format key, format name) of a supported model file, or ``None``."""
    detected = MODEL_EXTENSIONS.get(path.suffix.lower()) or NAMED_MODEL_FILES.get(path.name.lower())
    if detected is None and _pickle_family(path):
        return ("pickle", "pickle-archive")
    return detected


def _index_base(path: Path) -> Path | None:
    """The weight file a shard index such as ``model.safetensors.index.json`` describes."""
    match = _INDEX.fullmatch(path.name)
    if match is None or model_format(Path(match["base"])) is None:
        return None
    return path.with_name(match["base"])


def manifest_digest(entries: Iterable[tuple[str, str]]) -> str:
    """SHA-256 of RFC 8785 ``{"files": [{"path": p, "sha256": d}, ...]}``, sorted by path."""
    return hash_canonical(
        {"files": [{"path": path, "sha256": digest} for path, digest in sorted(entries)]}
    )


def _recognized_pickle(
    stream: BinaryIO, prefix: bytes, size: int, *, by_content: bool = False
) -> tuple[SerializationSafety, str] | None:
    """Rate what ``pickle.load`` does with a pickle sample, without loading objects.

    The sample is read as ``pickle.load`` reads it, in a loop, as ``torch.load`` reads
    the legacy format's header pickles before the one that rebuilds the tensors: by the
    C and the pure-Python unpicklers both (``utils.pickle_load``), as any supported
    CPython reads it, within the inspection bounds. A pickle that hands what it resolved to anything but the stack
    and the memo (calls it, sets items on it, appends to it, hashes it...) is a
    payload, wherever it starts. One that the bounds cut short before the loader's
    behaviour is decided is rated unknown (``PICKLE_NAME_UNCALLED`` when it resolved an
    importable name, else ``PICKLE_UNREAD``), and so is one that resolves an importable
    name and ends in a STOP or a flaw without using it; one that ends before
    ``find_class`` returns calls nothing, as the loader stops at the flaw. A STOP inside
    a FRAME with bytes left in it is rated unknown at least, and the next pickle is read
    both after the frame, as ``io.BytesIO`` gives it, and after the STOP, as a buffered
    file gives it to the C unpickler.

    A pickle that the bounds cut short is rated unknown wherever it starts, in a file
    found ``by_content`` too: harmless padding, such as NONE and POP repeated or a
    string longer than the sample, would otherwise hide a call after it. Text ends or
    fails before a bound, as a read past the end of the file and an argument whose
    visible part already fails are decided (``utils.pickle_load``). A file found
    ``by_content``, which no pickle-family name rates, is not rated unknown by a
    text-protocol first pickle that names something before a flaw: on its own it is
    as likely prose. Under a model name, a sample is also
    recognized by its shape, as before content was read past a STOP: a binary stream
    of PROTO and ``MIN_PICKLE_OPCODES`` well-formed opcodes, or a stream that passes
    static opcode/stack checks to STOP within the limits.
    """
    if not prefix or prefix[0] not in _OPCODE_BYTES:
        return None
    sample = prefix + stream.read(max(0, min(size, MAX_PICKLE_INSPECTION_BYTES) - len(prefix)))
    binary = len(prefix) >= 2 and prefix[0] == 0x80 and 2 <= prefix[1] <= 5
    shaped = binary or prefix[0] in _TEXT_PICKLE_START
    worst = _pickle_shape(sample, binary) if shaped and not by_content else None
    for flavor in pickle_load.FLAVORS:
        if worst is not None and worst[0] is SerializationSafety.UNSAFE_CODE_EXECUTION:
            break
        worst = _worse(worst, _pickle_loads(sample, size, flavor, by_content=by_content))
    return worst


def _pickle_shape(sample: bytes, binary: bool) -> tuple[SerializationSafety, str] | None:
    """A pickle by its opcodes alone: what a model name is rated by."""
    seen = marks = 0
    try:
        for opcode, _, _ in pickletools.genops(sample):
            seen += 1
            marks += opcode.name == "MARK"
            if seen > MAX_PICKLE_OPCODES or marks > MAX_PICKLE_MARKS:
                break
        else:
            # dis() only checks opcode stack/memo consistency; it never resolves
            # globals, imports artifact code, invokes reducers or constructs objects.
            pickletools.dis(sample, out=io.StringIO())
            return _recognized(binary)
    except (ValueError, UnicodeError, OverflowError, RecursionError, IndexError):
        # A truncated or malformed stream is judged by the opcodes read before it failed.
        pass
    return _recognized(binary) if binary and seen >= MIN_PICKLE_OPCODES else None


def _recognized(binary: bool) -> tuple[SerializationSafety, str]:
    kind = "binary" if binary else "text-protocol"
    return (
        SerializationSafety.UNSAFE_CODE_EXECUTION,
        f"Recognized {kind} pickle opcode stream; object loading can execute code",
    )


def _pickle_loads(
    sample: bytes, size: int, flavor: pickle_load.Flavor, *, by_content: bool
) -> tuple[SerializationSafety, str] | None:
    """Rate the pickles one unpickler reads from ``sample`` in a loop.

    Each start is read once: a later walk from it has less budget left, so it reaches
    nothing the first did not, and paths that meet again, as the two resumes after a
    STOP inside a frame can, would otherwise double the walks after them.
    """
    budget = pickle_load.Budget(MAX_PICKLE_OPCODES, MAX_PICKLE_MARKS)
    pending = [0]
    visited: set[int] = set()
    worst: tuple[SerializationSafety, str] | None = None
    while pending:
        start = pending.pop()
        if start in visited:
            continue
        visited.add(start)
        binary = sample[start : start + 1] == b"\x80"
        for segment in pickle_load.load_segments(sample, size, start, flavor, budget):
            if segment.outcome == "called":
                return _recognized(binary)
            if segment.outcome == "unread":
                unread = PICKLE_NAME_UNCALLED if segment.named else PICKLE_UNREAD
                worst = _worse(worst, (SerializationSafety.UNKNOWN, unread))
            elif segment.named and (segment.outcome == "stop" or binary or not by_content):
                # Text found by content that names something before a flaw is as likely
                # prose; a pickle that returns what it resolved, or a PROTO one, is not.
                worst = _worse(worst, (SerializationSafety.UNKNOWN, PICKLE_NAME_UNCALLED))
            if len(segment.resumes) > 1:
                worst = _worse(worst, (SerializationSafety.UNKNOWN, PICKLE_FRAME_TAIL))
            pending.extend(reversed(segment.resumes))
    return worst


def _worse(
    first: tuple[SerializationSafety, str] | None, second: tuple[SerializationSafety, str] | None
) -> tuple[SerializationSafety, str] | None:
    """The rating that ranks higher: code execution, then unknown, then none."""
    if second is None:
        return first
    if first is None or (
        second[0] is SerializationSafety.UNSAFE_CODE_EXECUTION
        and first[0] is not SerializationSafety.UNSAFE_CODE_EXECUTION
    ):
        return second
    return first


def _pickle_member(name: bytes) -> bool:
    """Whether a ZIP member's name is a pickle-family file name, wherever the member sits.

    ``torch.load`` unpickles ``data.pkl``; a loader handed the archive can open any other
    member, so a member is rated by its name, as a file on disk is. The name is matched
    as text, not split into suffixes, so ``.pkl`` and ``archive/.pkl``, which
    ``PurePath`` reads as names without a suffix, count as ``zipfile`` opens them.
    ``zipfile`` cuts a name at its first NUL, so that name is matched as well.
    """
    for text in {name.decode("latin-1").lower(), name.split(b"\0")[0].decode("latin-1").lower()}:
        if text.endswith(tuple(_UNSAFE_SUFFIXES)) or any(
            text.endswith(unsafe + wrapper)
            for unsafe in _UNSAFE_SUFFIXES
            for wrapper in _PICKLE_WRAPPERS
        ):
            return True
    return False


def _little(data: bytes, offset: int, width: int) -> int:
    return int.from_bytes(data[offset : offset + width], "little")


class _ZipMember(NamedTuple):
    """One central directory entry: what a loader reads a member by."""

    name: bytes
    method: int
    size: int
    offset: int


def _zip_directory(
    stream: BinaryIO, consumed: int, size: int, read: bytes = b""
) -> tuple[list[tuple[list[_ZipMember], int]], bool] | None:
    """The members each central directory a ZIP reader can locate lists, and its offset.

    Readers locate it differently, so a decoy directory that one reads must not hide the
    one another reads. A reader that follows the specification reads the directory at
    the offset its end record stores. ``zipfile``, which ``np.load`` uses, reads the
    directory that ends where its end record starts and moves every member's offset by
    the difference. When a ZIP64 locator precedes the end record, ``zipfile`` reads a
    ZIP64 record whatever the classic record holds: the one at the locator's offset,
    taking the bytes up to the locator as extensible data, and only when no record
    starts there the one right before the locator. miniz, which ``torch.load`` uses,
    reads the record at the locator's offset wherever it lies in the archive, also after
    the locator. Every reading that lists members is returned, with the offset its
    directory starts at, its members' offsets as that reader moves them, and whether
    some reader's directory was not decided. A directory that cannot be decided does not
    hide what another reading lists: the caller rates the archive by every reading.

    The rest of the stream is read in bounded chunks, keeping only the tail that can
    hold the directory within ``MAX_ZIP_DIRECTORY_BYTES``, the end-of-central-directory
    record with its comment and the ZIP64 records. ``read`` holds the bytes that end at
    ``consumed``, already read from the stream; from offset 0, a small archive is held
    whole. A directory is not decided when it lies within the archive beyond that bound
    or runs past its end record, as it may list what the others do not, or when a ZIP64
    locator stores an offset before that tail. ``None`` when no directory can be read,
    when the locator itself would lie before that tail, or when the stream ends before
    ``size``.
    """
    tail: deque[bytes] = deque([read])
    held = len(read)
    remaining = size - consumed
    while remaining > 0:
        chunk = stream.read(min(65536, remaining))
        if not chunk:
            return None
        remaining -= len(chunk)
        tail.append(chunk)
        held += len(chunk)
        while held - len(tail[0]) >= _ZIP_TAIL_BYTES:
            held -= len(tail.popleft())
    data = b"".join(tail)
    start = size - len(data)
    # zipfile takes the last 22 bytes as the end record when they hold one without a
    # comment, before it searches back, so a signature in its count fields is not one.
    end_record = len(data) - 22
    if end_record < 0 or data[end_record : end_record + 4] != b"PK\x05\x06" or data[-2:] != b"\0\0":
        # The last signature with a whole record after it, as far back as miniz, which
        # torch.load uses, searches: past zipfile's 65,557 bytes, and skipping a
        # truncated signature at the end, both of which zipfile refuses. The last one
        # within zipfile's reach is still the one zipfile takes.
        end_record = data.rfind(
            b"PK\x05\x06", max(0, len(data) - _MINIZ_END_SEARCH), len(data) - 18
        )
    if end_record < 0 or end_record + 22 > len(data):
        return None
    if start > 0 and end_record < 76:
        # The locator and the ZIP64 record before it would lie in bytes not held.
        return None
    # (where the directory ends, its size, its stored offset) for each record a reader takes
    records = [(end_record, _little(data, end_record + 12, 4), _little(data, end_record + 16, 4))]
    locator = end_record - 20
    # Where readers look for a ZIP64 record, and where one was found.
    looked: set[int] = set()
    found: set[int] = set()
    undecided = False
    if locator >= 0 and data[locator : locator + 4] == b"PK\x06\x07":
        stored = _little(data, locator + 8, 8) - start
        # zipfile reads the record there over the one before the locator; when the
        # tail does not hold it, what zipfile lists is not decided, but what the other
        # readings list still counts.
        undecided = stored < 0
        looked = {locator - 56, stored}
        for record in sorted(looked):
            # miniz, which torch.load uses, reads the record at the stored offset anywhere
            # in the archive, also after the locator, where a patched zipfile refuses it.
            if (
                record >= 0
                and record + 56 <= len(data)
                and data[record : record + 4] == b"PK\x06\x06"
            ):
                found.add(record)
                records.append(
                    (record, _little(data, record + 40, 8), _little(data, record + 48, 8))
                )
    if (
        found
        and found == looked
        and (_little(data, end_record + 10, 2) == 0xFFFF or 0xFFFFFFFF in records[0][1:])
    ):
        # Every reader takes a ZIP64 record over a saturated classic one, but only where
        # it looks: miniz falls back to the classic record when the stored offset holds
        # none, and zipfile without the CVE-2025-8291 fix when the record before the
        # locator is missing.
        del records[0]
    readings: dict[tuple[int, int, int], tuple[list[_ZipMember], int]] = {}
    for directory_end, directory_size, directory_offset in records:
        for begin in (directory_offset, start + directory_end - directory_size):
            key = (begin, directory_size, begin - directory_offset)
            if key in readings:
                continue
            members = _directory_members(data, begin - start, directory_size, directory_end)
            if members is None and (
                (
                    0 <= begin <= start + directory_end - directory_size
                    and (
                        begin < start
                        or directory_size > MAX_ZIP_DIRECTORY_BYTES
                        or data[begin - start : begin - start + 4] == b"PK\x01\x02"
                    )
                )
                or (
                    directory_size > 0
                    and start + directory_end - directory_size < begin <= size - directory_size
                    and (begin < start or data[begin - start : begin - start + 4] == b"PK\x01\x02")
                )
            ):
                # A directory past the bound, or one that starts but cannot be read,
                # may list what a decoy the other reading takes does not. One that starts
                # at its stored offset and runs past its end record no writer produces,
                # and miniz still reads it; a stored offset that starts no entry, as in an
                # archive cut out of a larger file, is one only zipfile's reading finds.
                undecided = True
                continue
            if members is not None:
                shift = begin - directory_offset
                readings[key] = (
                    [m._replace(offset=m.offset + shift) if m.offset >= 0 else m for m in members],
                    begin,
                )
    if not readings and not undecided:
        return None
    return list(readings.values()), undecided


def _directory_members(data: bytes, begin: int, size: int, end: int) -> list[_ZipMember] | None:
    """Walk the central directory entries that ``data`` holds from ``begin`` to ``end``.

    A pickle member is rated by its name, as the directory lists it, whatever another
    entry holds: an entry's own lengths lead to the next one even when its ZIP64 field
    cannot locate its data, and a loader that reads past that field still unpickles
    the member. ``None`` when the walk cannot go on or a member that is not a pickle
    cannot be located, and no pickle member is listed.
    """
    if size > MAX_ZIP_DIRECTORY_BYTES or begin < 0 or begin + size > end:
        return None
    members: list[_ZipMember] = []
    unlocated = False
    position = begin
    # zipfile reads the directory into a buffer of its stated size, so a name, extra
    # field or comment that runs past it is cut where the directory ends.
    data = data[: begin + size]
    while position < begin + size:
        if position + 46 > begin + size or data[position : position + 4] != b"PK\x01\x02":
            return _listed(members, complete=False)
        name_length = _little(data, position + 28, 2)
        extra_length = _little(data, position + 30, 2)
        extra_at = position + 46 + name_length
        name = _listed_name(
            data[position + 46 : extra_at], data[extra_at : extra_at + extra_length]
        )
        method = _little(data, position + 10, 2)
        located = _zip64_location(
            data[extra_at : extra_at + extra_length],
            _little(data, position + 24, 4),
            _little(data, position + 20, 4),
            _little(data, position + 42, 4),
        )
        if located is not None:
            members.append(_ZipMember(name, method, *located))
        elif _pickle_member(name):
            members.append(_ZipMember(name, method, 0, -1))
        else:
            unlocated = True
        position = extra_at + extra_length + _little(data, position + 32, 2)
    return _listed(members, complete=not unlocated)


def _listed_name(name: bytes, extra: bytes) -> bytes:
    """The name a loader may open a member by: ``name``, or a pickle-family name that an
    Info-ZIP Unicode Path field (0x7075) gives it.

    ``zipfile`` from Python 3.12 lists a member under a version-1 Unicode Path field's
    name when the field's CRC32 matches the stored name, and 3.11 under the stored name,
    so a pickle name either way rates the member.
    """
    position = 0
    while position + 4 <= len(extra):
        length = _little(extra, position + 2, 2)
        field = extra[position + 4 : position + 4 + length]
        if (
            _little(extra, position, 2) == 0x7075
            and len(field) >= 5
            and field[0] == 1
            and _little(field, 1, 4) == zlib.crc32(name)
            and _pickle_member(field[5:])
        ):
            return field[5:]
        position += 4 + length
    return name


def _listed(members: list[_ZipMember], *, complete: bool) -> list[_ZipMember] | None:
    """``members`` when they can be rated: every member read, or a pickle member listed."""
    return members if complete or any(_pickle_member(m.name) for m in members) else None


def _zip64_location(
    extra: bytes, uncompressed: int, compressed: int, offset: int
) -> tuple[int, int] | None:
    """A member's compressed size and local header offset, from ZIP64 when they overflow.

    The ZIP64 extra field holds, in this order, each of the uncompressed size, the
    compressed size and the offset whose 32-bit field is 0xFFFFFFFF. ``None`` when the
    field is there but too short for them, which ``zipfile`` refuses as a corrupt
    archive. Without the field, ``zipfile`` keeps the 32-bit values as written and reads
    the archive, so they are kept here too.
    """
    if 0xFFFFFFFF not in (uncompressed, compressed, offset):
        return compressed, offset
    position = 0
    while position + 4 <= len(extra):
        length = _little(extra, position + 2, 2)
        if _little(extra, position, 2) == 1:
            field = extra[position + 4 : position + 4 + length]
            values = [uncompressed, compressed, offset]
            cursor = 0
            for index, value in enumerate(values):
                if value == 0xFFFFFFFF:
                    if cursor + 8 > len(field):
                        return None
                    values[index] = _little(field, cursor, 8)
                    cursor += 8
            return values[1], values[2]
        position += 4 + length
    return compressed, offset


def _reread(stream: BinaryIO, offset: int, size: int) -> bytes:
    """``size`` bytes at ``offset`` of what ``stream`` has read, read again.

    A confined or hashing stream re-reads from its own descriptor without charging the
    bytes again; a plain file is read at that offset.
    """
    reread = getattr(stream, "reread", None)
    if reread is not None:
        data: bytes = reread(offset, size)
        return data
    return os.pread(stream.fileno(), size, offset)


class _MemberData:
    """The data of one ZIP member, read again from the archive, inflated if DEFLATE.

    Compressed input is read again in growing chunks, so a member costs about what its
    array header needs; it never reads past the member's compressed size.
    """

    def __init__(self, stream: BinaryIO, start: int, size: int, *, deflated: bool) -> None:
        self._stream = stream
        self._position = start
        self._remaining = size
        self._inflater = zlib.decompressobj(wbits=-zlib.MAX_WBITS) if deflated else None
        self._pending = b""
        self._chunk = 512

    def _input(self, size: int) -> bytes:
        data = _reread(self._stream, self._position, min(size, self._remaining))
        self._position += len(data)
        self._remaining -= len(data)
        return data

    def read(self, size: int) -> bytes:
        if self._inflater is None:
            return self._input(size)
        out = bytearray()
        while len(out) < size and not self._inflater.eof:
            if not self._pending:
                if self._remaining <= 0:
                    break
                self._pending = self._input(self._chunk)
                self._chunk = min(2 * self._chunk, 65536)
            out += self._inflater.decompress(self._pending, size - len(out))
            self._pending = self._inflater.unconsumed_tail
        return bytes(out)


def _members_hold_object_array(
    stream: BinaryIO, members: list[_ZipMember], directory: int, budget: InspectionBudget
) -> bool | None:
    """Whether a member of a ZIP archive is a NumPy array with an object dtype.

    ``np.load`` reads every member that starts with the NumPy magic as an array,
    whatever its name, so every member is checked from its local header and the start
    of its data, stored or raw DEFLATE, read again from the stream that read the
    archive to its end. As ``zipfile`` does, members are taken in offset order and a
    member whose data runs past the next local header or into the directory is not
    read, so the bytes read again are at most the archive's. Each array header is
    charged to ``budget`` before it is read or inflated: DEFLATE expands about a
    thousandfold, so a small archive could otherwise make many members inflate and parse
    a full header. ``None`` when a member could not be checked: its data overlaps, it
    is compressed by another method, or its array header is longer than
    ``MAX_PICKLE_INSPECTION_BYTES`` or than the budget left.
    """
    ordered = sorted(members, key=lambda member: member.offset)
    unread = False
    for index, member in enumerate(ordered):
        end = min(ordered[index + 1].offset, directory) if index + 1 < len(ordered) else directory
        found = _member_holds_object_array(stream, member, end, budget)
        if found:
            return True
        unread = unread or found is None
    return None if unread else False


def _member_holds_object_array(
    stream: BinaryIO, member: _ZipMember, end: int, budget: InspectionBudget
) -> bool | None:
    if member.size == 0:
        return False
    if member.offset < 0 or member.offset + 30 > end:
        return None
    header = _reread(stream, member.offset, 30)
    if header[:4] != b"PK\x03\x04":
        # zipfile refuses a member without a local header; np.load cannot read it.
        return False
    start = member.offset + 30 + _little(header, 26, 2) + _little(header, 28, 2)
    if start + member.size > end:
        return None
    if member.method not in (0, 8):
        return None
    data = _MemberData(stream, start, member.size, deflated=member.method == 8)
    try:
        return _object_array(b"", data.read, budget)
    except zlib.error:
        # zipfile raises the same error when it inflates the member.
        return False


def _object_array(
    start: bytes, more: Callable[[int], bytes], budget: InspectionBudget
) -> bool | None:
    """Whether a NumPy array that begins with ``start``, continued by ``more``, holds objects.

    ``more(n)`` returns up to the next ``n`` bytes. A version 1, 2 or 3 header is read
    whole up to ``MAX_PICKLE_INSPECTION_BYTES``, which a version 1 header never exceeds,
    however it is padded. Each header byte read or inflated is a unit of ``budget``,
    which the format readers of one scan share, charged as it arrives, so a header that
    claims more than it holds costs only what it holds. ``None`` when the header is
    longer than that bound or than what is left of ``budget``; ``False`` for anything
    ``np.load`` does not read as an array.
    """
    if len(start) < 12:
        start += more(12 - len(start))
    if len(start) < 10 or start[:6] != _NUMPY_MAGIC or start[7] != 0 or start[6] not in (1, 2, 3):
        return False
    preamble = 10 if start[6] == 1 else 12
    if len(start) < preamble:
        return False
    length = _little(start, 8, preamble - 8)
    if length > MAX_PICKLE_INSPECTION_BYTES:
        return None
    header = bytearray(start[preamble : preamble + length])
    try:
        budget.charge(len(header), NUMPY_HEADER_UNREAD)
        while len(header) < length:
            chunk = more(min(4096, length - len(header)))
            if not chunk:
                return False
            budget.charge(len(chunk), NUMPY_HEADER_UNREAD)
            header += chunk
    except FormatError:
        return None
    return _declares_object(bytes(header), start[6])


def _declares_object(header: bytes, major: int) -> bool:
    """Whether a NumPy header, a dict literal, declares a dtype with an object field.

    It is parsed as ``np.load`` parses it, with ``ast.literal_eval``, and again without
    the ``L`` that Python 2 wrote after an integer when that alone fails. Only the
    ``descr`` value is examined, so a field name is never taken for a type.
    """
    try:
        text = header.decode("utf-8" if major == 3 else "latin-1")
    except UnicodeDecodeError:
        return False
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            try:
                parsed = ast.literal_eval(text)
            except SyntaxError:
                parsed = ast.literal_eval(_without_long_suffixes(text))
        except (
            SyntaxError,
            ValueError,
            TypeError,
            MemoryError,
            RecursionError,
            tokenize.TokenError,
        ):
            return False
    return isinstance(parsed, dict) and _descr_has_object(parsed.get("descr"))


def _without_long_suffixes(text: str) -> str:
    """``text`` without an ``L`` token after a number, as NumPy filters Python 2 headers."""
    tokens: list[tokenize.TokenInfo] = []
    after_number = False
    for token in tokenize.generate_tokens(io.StringIO(text).readline):
        if after_number and token.type == tokenize.NAME and token.string == "L":
            continue
        tokens.append(token)
        after_number = token.type == tokenize.NUMBER
    return tokenize.untokenize(tokens)


def _descr_has_object(descr: object) -> bool:
    """Whether a NumPy ``descr`` names an object dtype anywhere, as ``np.load`` reads it.

    A string is a dtype string. A tuple is a subarray of its first item. Any other
    container lists fields, each unpacked as ``(name, descr)`` or
    ``(name, descr, shape)``, so its second item is the field's type, nested to any
    depth. A set field's items have no order, so each is checked.
    """
    pending: list[object] = [descr]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            if _object_dtype_string(item):
                return True
        elif isinstance(item, tuple):
            pending.extend(item[:1])
        elif isinstance(item, list | dict | set):
            for entry in item:
                if isinstance(entry, str | tuple | list | dict | set) and len(entry) in (2, 3):
                    unpacked = list(entry)
                    pending.extend(unpacked if isinstance(entry, set) else unpacked[1:2])
    return False


def _object_dtype_string(text: str) -> bool:
    """Whether a dtype string such as ``|O``, ``object`` or ``i4,(2,)O`` has an object part.

    Each comma-separated part is read without its byte order and shape prefix.
    """
    return any(
        _OBJECT_TYPE.fullmatch(part.strip().lstrip("<>|=()0123456789, ").strip())
        for part in text.split(",")
    )


def _recognized_code_container(
    stream: BinaryIO, prefix: bytes, size: int, budget: InspectionBudget, *, by_content: bool
) -> tuple[SerializationSafety, str] | None:
    """A verdict on content a loader can run code from, or ``None`` for content not recognized.

    A pickle, a NumPy array with an object dtype, and a ZIP archive with a pickle-family
    member or such an array as a member are recognized. ``torch.save`` writes
    ``data.pkl``, usually first, so the first local header is read forward before the
    directory at the end of the archive, which lists every member, is read.
    """
    if prefix[:6] == _NUMPY_MAGIC:
        array = _object_array(prefix, stream.read, budget)
        if array is None:
            return SerializationSafety.UNKNOWN, NUMPY_HEADER_UNREAD
        return (SerializationSafety.UNSAFE_CODE_EXECUTION, NUMPY_OBJECT_ARRAY) if array else None
    # np.load hands zipfile a file that starts with an end record too, as an empty
    # archive does; zipfile reads the archive whose end record ends the file.
    if prefix[:4] not in (b"PK\x03\x04", b"PK\x05\x06"):
        return _recognized_pickle(stream, prefix, size, by_content=by_content)
    # Every byte read so far is kept for the directory search. In a small archive the
    # first local header and its name can hold the ZIP64 locator or record, and zipfile
    # and miniz read them there; an end record at offset 0 is all an empty archive holds.
    kept = prefix
    if prefix[:4] == b"PK\x03\x04":
        header = prefix + stream.read(22)
        first = b""
        if len(header) == 30:
            name_length = int.from_bytes(header[26:28], "little")
            if 0 < name_length <= 4096:
                first = stream.read(name_length)
        kept = header + first
        if _pickle_member(first):
            return SerializationSafety.UNSAFE_CODE_EXECUTION, ZIP_PICKLE_MEMBER
    directory = _zip_directory(stream, len(kept), size, kept)
    if directory is None:
        return SerializationSafety.UNKNOWN, ZIP_DIRECTORY_UNREAD
    readings, undecided = directory
    # A member any reading lists counts, even when another reader's directory is not
    # decided: a locator or directory that cannot be read must not hide one that can.
    if any(_pickle_member(member.name) for members, _ in readings for member in members):
        return SerializationSafety.UNSAFE_CODE_EXECUTION, ZIP_PICKLE_MEMBER
    arrays: bool | None = False
    for members, offset in readings:
        found = _members_hold_object_array(stream, members, offset, budget)
        if found:
            return SerializationSafety.UNSAFE_CODE_EXECUTION, ZIP_OBJECT_ARRAY
        if found is None:
            arrays = None
    if undecided:
        return SerializationSafety.UNKNOWN, ZIP_DIRECTORY_UNREAD
    return SerializationSafety.UNKNOWN, ZIP_WITHOUT_PICKLE if arrays is False else ZIP_MEMBER_UNREAD


def inspect_model_format(
    path: Path, *, stream: BinaryIO | None = None, budget: InspectionBudget | None = None
) -> tuple[SerializationSafety, str]:
    """Inspect bounded structure without deserializing a model or running code.

    A file that cannot be read, or whose content check fails, is unknown: a SafeTensors
    one as malformed SafeTensors, any other as ``INSPECTION_FAILED``, except a
    pickle-family name, which keeps the code-executing rating its loader implies. A
    file named as GGUF whose content is not recognized as anything else is unknown as
    ``GGUF_MISMATCH`` without the GGUF magic, or ``GGUF_TOO_SHORT`` when shorter than it.

    A pickle-family name is rated by its inspected content, not by the name alone: it
    keeps the code-executing rating when the content is a recognized pickle, a NumPy
    object-dtype array, a ZIP archive with a pickle member or such an array, content a
    bound left unread, or a compressed or archived stream (by a wrapper suffix, its
    magic or its header), whose decompressed content is not inspected, or GGUF content,
    whose chat templates are inspected only under a ``.gguf`` name. A ZIP archive read
    whole with no pickle member keeps that unknown verdict; anything else is unknown
    with ``PICKLE_NAME_UNEVIDENCED`` (``PICKLE_NAME_EMPTY`` for a zero-length file),
    which keeps the high unknown-format finding.

    ``budget`` is shared with the other files of one scan; NumPy array headers spend it.
    A file that no model name rates is inspected for what it holds, so the collector
    and validation reach the same verdict on it.

    SAFE means the checked file has a supported non-executable tensor container
    layout. It is not a claim about model behavior, parser vulnerabilities,
    adjacent repository code, or the safety of the eventual loader.
    """
    pickle_family = _pickle_family(path)
    safetensors = path.suffix.lower() == ".safetensors"
    try:
        context = nullcontext(stream) if stream is not None else open_regular_file(path)
        with context as source:
            head = _HeadReader(source) if pickle_family else None
            opened = cast(BinaryIO, head) if head is not None else source
            size = os.fstat(opened.fileno()).st_size
            prefix = opened.read(8)
            length = int.from_bytes(prefix, "little")
            tensor_candidate = (
                safetensors
                and len(prefix) == 8
                and 2 <= length <= min(MAX_MODEL_HEADER_BYTES, size - 8)
            )
            if not tensor_candidate:
                container = _recognized_code_container(
                    opened,
                    prefix,
                    size,
                    budget or InspectionBudget(),
                    by_content=model_format(path) is None,
                )
                # 'G' is an opcode byte, so GGUF content can parse as a pickle stream; the
                # name rating says what the file is.
                if container is not None and (
                    container[0] is SerializationSafety.UNSAFE_CODE_EXECUTION
                    and not (pickle_family and prefix.startswith(GGUF_MAGIC))
                    or not (safetensors or pickle_family)
                ):
                    return container
            if head is not None:
                return _pickle_name_rating(path, head, size, container)
            if not safetensors:
                if path.suffix.lower() == ".gguf" and not prefix.startswith(GGUF_MAGIC):
                    return (
                        SerializationSafety.UNKNOWN,
                        GGUF_TOO_SHORT if len(prefix) < len(GGUF_MAGIC) else GGUF_MISMATCH,
                    )
                return (
                    SerializationSafety.UNKNOWN,
                    "No bounded structural validator for this format/loader",
                )
            read_header(opened, size, prefix=prefix, max_header_bytes=MAX_MODEL_HEADER_BYTES)
        return SerializationSafety.SAFE, "Bounded SafeTensors header, shapes and offsets checked"
    except HeaderLimitError:
        return SerializationSafety.UNKNOWN, "SafeTensors header exceeds the inspection limit"
    except (OSError, ValueError, RecursionError, UnicodeError):
        if safetensors:
            return SerializationSafety.UNKNOWN, "Malformed or unsupported SafeTensors structure"
        if pickle_family:
            return SerializationSafety.UNSAFE_CODE_EXECUTION, PICKLE_NAME_UNREADABLE
        return SerializationSafety.UNKNOWN, INSPECTION_FAILED


def _pickle_name_rating(
    path: Path,
    head: _HeadReader,
    size: int,
    container: tuple[SerializationSafety, str] | None,
) -> tuple[SerializationSafety, str]:
    """Rate a pickle-family name whose inspected content showed no code-bearing container.

    Content a bound left unread, and a compressed or archived stream, which its loader
    unwraps before it unpickles, keep the code-executing rating the name implies. So
    does GGUF content: llama.cpp opens a model by its magic, not its name, and its chat
    templates are inspected only under a ``.gguf`` name.
    """
    if size == 0:
        return SerializationSafety.UNKNOWN, PICKLE_NAME_EMPTY
    start = head.start(min(size, _TAR_BLOCK))
    if (
        path.suffixes[-1].lower() in _PICKLE_WRAPPERS
        or start.startswith(_WRAPPER_MAGIC)
        or _lzma_alone_header(start)
        or start[_TAR_MAGIC_OFFSET : _TAR_MAGIC_OFFSET + len(_TAR_MAGIC)] == _TAR_MAGIC
        or _tar_header(start)
    ):
        return SerializationSafety.UNSAFE_CODE_EXECUTION, PICKLE_NAME_WRAPPED
    if start.startswith(GGUF_MAGIC):
        return SerializationSafety.UNSAFE_CODE_EXECUTION, PICKLE_NAME_GGUF
    if container is not None and container[1] in _CONTENT_UNREAD:
        return SerializationSafety.UNSAFE_CODE_EXECUTION, _loader_rated(container[1])
    if container is not None:
        return container
    return SerializationSafety.UNKNOWN, PICKLE_NAME_UNEVIDENCED


def _lzma_alone_header(start: bytes) -> bool:
    """Whether ``start`` opens an LZMA-alone stream that joblib detects and unwraps.

    joblib takes content that starts ``5d 00``, its encoder's properties byte and the
    low byte of a dictionary size, for LZMA-alone. The uncompressed size is unknown (all
    ones) or below 2**63, and the range coder's first byte, after the header, is always
    zero. Other properties bytes reach ``lzma`` only through a loader that asks for it.
    """
    if len(start) <= _LZMA_ALONE_HEADER or not start.startswith(_LZMA_JOBLIB_PREFIX):
        return False
    unpacked = start[5:_LZMA_ALONE_HEADER]
    return (unpacked == b"\xff" * 8 or unpacked[-1] <= 0x7F) and start[_LZMA_ALONE_HEADER] == 0


def _tar_header(start: bytes) -> bool:
    """Whether ``start`` opens with a tar header that tarfile reads, ustar or not.

    ``torch.load`` opens a legacy checkpoint with tarfile, which reads a first block
    whatever its name and type when its checksum field holds the sum of the other bytes,
    unsigned or signed, plus eight spaces for the field itself, and its numeric fields
    parse. A type-specific field tarfile also parses is not checked, which only widens
    the rating.
    """
    if len(start) < _TAR_BLOCK:
        return False
    stored = _tar_number(start[_TAR_CHECKSUM])
    if stored is None or any(_tar_number(start[field]) is None for field in _TAR_NUMBERS):
        return False
    rest = start[: _TAR_CHECKSUM.start] + start[_TAR_CHECKSUM.stop : _TAR_BLOCK]
    unsigned = 256 + sum(rest)
    return stored in (unsigned, unsigned - 256 * sum(byte > 0x7F for byte in rest))


def _tar_number(field: bytes) -> int | None:
    """A tar header's number field as ``tarfile.nti`` reads it: octal text or base-256."""
    if field[0] in (0x80, 0xFF):
        return int.from_bytes(field[1:], "big") - (
            256 ** (len(field) - 1) if field[0] == 0xFF else 0
        )
    try:
        return int(field.split(b"\0", 1)[0].decode("ascii").strip() or "0", 8)
    except ValueError:
        return None


def _loader_rated(evidence: str) -> str:
    """The rating of a pickle-family name whose content the bounds left unrated."""
    return f"Potential code-executing loader format ({evidence.removesuffix(_UNVALIDATED)})"


class _HeadReader:
    """Keep the first bytes read from ``stream``, where a wrapper's header sits."""

    def __init__(self, stream: BinaryIO) -> None:
        self._stream = stream
        self._head = bytearray()

    def fileno(self) -> int:
        return self._stream.fileno()

    def read(self, size: int) -> bytes:
        data = self._stream.read(size)
        self._head.extend(data[: max(0, _TAR_BLOCK - len(self._head))])
        return data

    def reread(self, offset: int, size: int) -> bytes:
        return _reread(self._stream, offset, size)

    def start(self, length: int) -> bytes:
        """The first ``length`` bytes, reading on past what inspection read if needed."""
        while len(self._head) < length and self.read(length - len(self._head)):
            pass
        return bytes(self._head[:length])


class _HashingModelReader:
    """Hash the inspected prefix and remaining bytes from one pinned stream."""

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.digest = hashlib.sha256()
        self.bytes_read = 0
        self.prefix = bytearray()
        self.limit = limits.current().model_bytes

    def fileno(self) -> int:
        return self.stream.fileno()

    def read(self, size: int) -> bytes:
        if self.bytes_read > self.limit:
            raise OSError("model artifact exceeds the hash byte limit")
        content = self.stream.read(min(size, self.limit + 1 - self.bytes_read))
        self.bytes_read += len(content)
        if self.bytes_read > self.limit:
            raise OSError("model artifact exceeds the hash byte limit")
        self.digest.update(content)
        self.prefix.extend(content[: max(0, MAX_MODEL_HEADER_BYTES + 8 - len(self.prefix))])
        return content

    def reread(self, offset: int, size: int) -> bytes:
        """Read again bytes already hashed; the digest and the byte count are unchanged."""
        if offset < 0 or size < 0 or offset + size > self.bytes_read:
            raise OSError("re-read past the bytes inspected")
        return _reread(self.stream, offset, size)


class _ReplayReader:
    """Re-read from the start of a hashed stream: the inspected prefix, then the rest."""

    def __init__(self, observed: _HashingModelReader) -> None:
        if observed.bytes_read > len(observed.prefix):
            raise OSError("inspection consumed more than the retained prefix")
        self._replay = bytes(observed.prefix[: observed.bytes_read])
        self._observed = observed

    def read(self, size: int) -> bytes:
        if self._replay:
            data, self._replay = self._replay[:size], self._replay[size:]
            return data
        return self._observed.read(size)


@dataclass(frozen=True)
class ModelArtifactObservation:
    """One bounded, non-executing observation of one opened model artifact."""

    safety: SerializationSafety
    explanation: str
    digest: str
    fingerprint: dict[str, str] = field(default_factory=dict)
    external_data: tuple[str, ...] | None = None
    onnx_error: str | None = None
    chat_templates: tuple[tuple[str, str], ...] = ()
    gguf_architecture: str | None = None
    gguf_error: str | None = None
    # For a name in ``_HEADER_CHECKED``: whether the header is that format's, which is
    # a SafeTensors header that validates or the GGUF magic.
    header_matched: bool = False


def observe_model_artifact(
    path: Path, *, stream: BinaryIO, budget: InspectionBudget | None = None
) -> ModelArtifactObservation:
    """Bind structural inspection, format metadata and SHA-256 to one opened artifact.

    The caller must hold a confined regular-file context.
    A pathname replacement cannot substitute different bytes between inspection
    and hashing because neither operation reopens that pathname. The confined
    stream also refuses the observation unless the pathname still resolves to
    this descriptor when the caller's read ends, so the verdict and digest are
    never attributed to a pathname that now names other bytes.
    """
    budget = budget or InspectionBudget()
    return _complete_observation(path, stream, _inspect_opened(path, stream, budget), budget)


def observe_content(
    path: Path, *, stream: BinaryIO, budget: InspectionBudget | None = None
) -> ModelArtifactObservation | None:
    """Observe a file that no model name rates when its content makes it a model artifact.

    That content is a pickle whose inspected opcodes name a callable, a NumPy array with an object dtype, a ZIP archive with a
    pickle-family member or such an array as a member, or a pickle, NumPy array or ZIP
    archive that a bound left unread. For other content ``None`` is returned once the inspection
    has read what it needed, which for a ZIP archive is all of it. An artifact is
    observed from the same stream, so every byte is read, and charged, once. The caller
    holds a confined regular-file context, as for ``observe_model_artifact``.
    """
    budget = budget or InspectionBudget()
    inspected = _inspect_opened(path, stream, budget)
    if (
        inspected.safety != SerializationSafety.UNSAFE_CODE_EXECUTION
        and inspected.explanation not in _CONTENT_UNREAD
    ):
        return None
    return _complete_observation(path, stream, inspected, budget)


class _Inspected(NamedTuple):
    before: os.stat_result
    reader: _HashingModelReader
    safety: SerializationSafety
    explanation: str


def _inspect_opened(path: Path, stream: BinaryIO, budget: InspectionBudget) -> _Inspected:
    before = os.fstat(stream.fileno())
    if before.st_size > limits.current().model_bytes:
        raise OSError("model artifact exceeds the hash byte limit")
    observed = _HashingModelReader(stream)
    safety, explanation = inspect_model_format(path, stream=cast(BinaryIO, observed), budget=budget)
    return _Inspected(before, observed, safety, explanation)


def _complete_observation(
    path: Path, stream: BinaryIO, inspected: _Inspected, budget: InspectionBudget
) -> ModelArtifactObservation:
    """Complete an inspection with format metadata and the SHA-256 of every byte."""
    before, observed, safety, explanation = inspected
    detected = model_format(path)
    key = detected[0] if detected is not None else None
    extra: dict[str, Any] = {}
    if safety == SerializationSafety.SAFE:
        extra["fingerprint"] = fingerprint_stream(
            io.BytesIO(bytes(observed.prefix)),
            artifact_size=before.st_size,
            max_header_bytes=MAX_MODEL_HEADER_BYTES,
        )
    elif key in ("onnx", "gguf") and explanation in _ZIP_UNRATED:
        # The directory was read from the archive's end, past the prefix a format
        # reader replays; an archive holds no ONNX external data and no GGUF metadata,
        # which is what the readers found before the directory was read.
        if key == "onnx":
            extra["external_data"] = ()
        else:
            extra["gguf_error"] = ZIP_NOT_GGUF
    elif safety != SerializationSafety.UNSAFE_CODE_EXECUTION and key == "onnx":
        try:
            extra["external_data"] = onnx_external_data(_ReplayReader(observed).read, budget)
        except FormatError as exc:
            extra["onnx_error"] = str(exc)
    elif safety != SerializationSafety.UNSAFE_CODE_EXECUTION and key == "gguf":
        try:
            metadata = gguf_metadata(_ReplayReader(observed).read, budget)
        except FormatError as exc:
            extra["gguf_error"] = str(exc)
        else:
            extra["gguf_architecture"] = metadata.architecture
            extra["chat_templates"] = tuple(
                (f"{path.as_posix()}#{name}", hash_bytes(text))
                for name, text in metadata.chat_templates
            )
            if any(template_escape_markers(text) for _, text in metadata.chat_templates):
                safety = SerializationSafety.UNSAFE_TEMPLATE_INJECTION
                explanation = (
                    "Embedded chat template contains a potential Python-internals "
                    "access pattern; actual behavior depends on the renderer"
                )
    while observed.read(65536):
        pass
    after = os.fstat(stream.fileno())
    if descriptor_binding(before) != descriptor_binding(after):
        raise OSError("model artifact changed during inspection and hashing")
    return ModelArtifactObservation(
        safety,
        explanation,
        "sha256:" + observed.digest.hexdigest(),
        # Only a SafeTensors header that validates is rated safe. The GGUF magic before
        # content rated as code that runs on load is a disguise, not a GGUF file.
        header_matched=safety == SerializationSafety.SAFE
        or (
            key == "gguf"
            and safety != SerializationSafety.UNSAFE_CODE_EXECUTION
            and observed.prefix.startswith(GGUF_MAGIC)
        ),
        **extra,
    )


def inspect_model_artifact(
    path: Path, *, stream: BinaryIO, metadata: dict[str, str] | None = None
) -> tuple[SerializationSafety, str, str]:
    """Bind structural inspection and SHA-256 to the same opened artifact."""
    observation = observe_model_artifact(path, stream=stream)
    if metadata is not None:
        metadata.update(observation.fingerprint)
    return observation.safety, observation.explanation, observation.digest


def safetensors_fingerprint(
    path: Path, *, root: Path, expected_digest: str | None = None
) -> dict[str, str]:
    """Bind metadata and complete-file hash to one confined artifact observation."""
    metadata: dict[str, str] = {}
    model_bytes = limits.bound("model-bytes")
    with (
        ConfinedCollection(root, [], max_total_bytes=model_bytes) as files,
        files.open_regular(path, max_bytes=model_bytes) as stream,
    ):
        safety, _, digest = inspect_model_artifact(path, stream=stream, metadata=metadata)
    if safety != SerializationSafety.SAFE or not metadata:
        raise ValueError("SafeTensors metadata could not be corroborated")
    if expected_digest is not None and expected_digest != digest:
        raise ValueError("Tensor metadata belongs to different artifact bytes")
    return metadata


def _report_variants(files: ConfinedCollection, path: Path) -> None:
    """Fail each other spelling of an absent fixed name, which case-insensitive hosts open."""
    for variant in files.case_variants(path):
        if not files.excluded(variant):
            files.report_case_variant(variant, path)


class ModelTree:
    """Root-relative files from one confined walk, indexed by directory."""

    def __init__(self, files: Iterable[Path]) -> None:
        self.files = tuple(files)
        self.paths = frozenset(self.files)
        self.children: dict[Path, list[Path]] = {}
        self._subdirs: dict[Path, set[Path]] = {}
        for path in self.files:
            self.children.setdefault(path.parent, []).append(path)
            child = path.parent
            while child != child.parent:
                siblings = self._subdirs.setdefault(child.parent, set())
                if child in siblings:
                    break
                siblings.add(child)
                child = child.parent

    def below(self, directory: Path) -> list[Path]:
        found = list(self.children.get(directory, ()))
        for subdirectory in sorted(self._subdirs.get(directory, ())):
            found.extend(self.below(subdirectory))
        return found


def _json_document(raw: bytes) -> Any:
    """Configuration JSON as loaders read it: UTF-8, unique keys, no NaN or Infinity literals."""

    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        document: dict[str, Any] = {}
        for key, value in pairs:
            if key in document:
                raise ValueError("duplicate JSON key")
            document[key] = value
        return document

    def nonfinite(_: str) -> None:
        raise ValueError("nonfinite JSON number")

    return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=nonfinite)


def _local_reference(directory: Path, reference: str) -> Path | None:
    """A forward-slash reference that stays inside ``directory``, or ``None``."""
    if not reference or "\\" in reference or "\0" in reference or reference.startswith("/"):
        return None
    parts = PurePosixPath(reference).parts
    if not parts or ".." in parts:
        return None
    return directory.joinpath(*parts)


class BindingBudget:
    """What files shared by many models add to each of them, bounded per scan or validation.

    The weight-file budget charges each distinct entry of a shard index once when
    the index is read and each candidate file once more for every model it is bound
    to; the scan's shared-digest budget charges each directory digest once for every
    model that records it. So files that many models share cannot multiply the work
    or the inventory. Once a charge is refused, every later nonzero charge is too:
    what is recorded never depends on the sizes of later models. Only the first
    refusal records a failure (``reason``); later ones are kept in ``refused``.
    """

    def __init__(self, units: int | None = None, *, reason: str = BINDINGS_EXHAUSTED) -> None:
        self.remaining = 2 * limits.current().entries if units is None else units
        self.reason = reason
        self.refused: set[Path] = set()
        # Shard indexes, and directories with too many, that bound none of their shards.
        self.unbound: set[Path] = set()

    def charge(self, path: Path, units: int, fail: Callable[[str], None]) -> bool:
        """Spend ``units`` for ``path``, or refuse it and spend nothing."""
        if units and (self.refused or units > self.remaining):
            if not self.refused:
                fail(self.reason)
            self.refused.add(path)
            return False
        self.remaining -= units
        return True


def index_references(
    files: ConfinedCollection,
    tree: ModelTree,
    directory: Path,
    digests: dict[Path, str | None],
    budget: BindingBudget,
    read: Callable[[Path], bytes | None] | None = None,
) -> tuple[dict[Path, list[Path]], list[Path]]:
    """Map each weight file to the shard indexes in ``directory`` that list it.

    A shard index decides which files a loader opens, so a reference to a missing
    file, a file outside the directory or a file that is not a collected model
    file is a collection failure, not an omission. A directory with more shard
    indexes than ``MAX_SHARD_INDEXES`` binds none of them and fails, and the
    entries of each index are charged to ``budget`` before they are examined.
    ``read`` replaces the collection's own bounded read. Also returns the indexes
    considered, which are the ones read.
    """
    references: dict[Path, list[Path]] = {}
    indexes = [path for path in tree.children.get(directory, ()) if _index_base(path) is not None]
    if len(indexes) > MAX_SHARD_INDEXES:
        files._fail(directory, TOO_MANY_INDEXES)
        budget.unbound.add(directory)
        return references, []
    for index in indexes:
        raw = (read or files.read_bytes)(index)
        if raw is None:
            budget.unbound.add(index)
            continue
        digests[index] = hash_bytes(raw)
        try:
            document = _json_document(raw)
        except (ValueError, RecursionError):
            files._fail(index, "invalid JSON or duplicate keys")
            budget.unbound.add(index)
            continue
        weight_map = document.get("weight_map") if isinstance(document, dict) else None
        if not isinstance(weight_map, dict) or not all(
            isinstance(value, str) for value in weight_map.values()
        ):
            files._fail(index, "model index must map tensor names to weight files")
            budget.unbound.add(index)
            continue
        names = set(weight_map.values())
        if not budget.charge(index, len(names), partial(files._fail, index)):
            continue
        bound = False
        for name in sorted(names):
            shard = _local_reference(directory, name)
            if (
                shard is None
                or shard.parent != directory
                or shard not in tree.paths
                or model_format(shard) is None
            ):
                files._fail(
                    index,
                    "model index references a missing, unrecognised or out-of-directory "
                    "weight file",
                )
                continue
            references.setdefault(shard, []).append(index)
            bound = True
        if not bound:
            # An index that names no collected weight file binds no shard, so what it
            # makes a loader open is unknown, as for one that could not be parsed.
            budget.unbound.add(index)
    return references, indexes


def _savedmodel(path: Path) -> bool:
    detected = model_format(path)
    return detected is not None and detected[1] == "tensorflow-savedmodel"


def savedmodel_files(files: ConfinedCollection, tree: ModelTree, directory: Path) -> list[Path]:
    """The files beside a SavedModel graph in ``directory`` that its loader reads.

    The walk lists a directory symlink's files under its target's name only, so they
    are listed under the names a loader opens, through the link. When one of these
    names is absent, another spelling of it is a failure, because case-insensitive
    file systems open it.
    """
    found: list[Path] = []
    for name in SAVEDMODEL_DIRECTORIES:
        below = directory / name
        listed = tree.below(below)
        if listed:
            found.extend(listed)
        elif not files.is_directory(below):
            _report_variants(files, below)
        elif (target := files.link_target(below)) is not None:
            found.extend(below / path.relative_to(target) for path in tree.below(Path(target)))
    for name in SAVEDMODEL_FILES:
        if directory / name in tree.paths:
            found.append(directory / name)
        else:
            _report_variants(files, directory / name)
    return found


def bound_weight_files(
    tree: ModelTree,
    path: Path,
    observation: ModelArtifactObservation | None,
    index_refs: Mapping[Path, Sequence[Path]],
    savedmodel: Sequence[Path],
    fail: Callable[[str], None],
    budget: BindingBudget,
) -> list[Path]:
    """Return the other files a loader reads as this model's weights.

    ``savedmodel`` lists the directory's SavedModel files once for all of its models
    (``savedmodel_files``); only a SavedModel graph binds them. Every candidate is
    charged to ``budget`` before it is examined. When the budget refuses them,
    nothing is bound: the model's weight files are unknown, and the refusal is
    recorded in ``budget.refused``.
    """
    directory = path.parent
    if observation is not None and observation.onnx_error is not None:
        fail(observation.onnx_error)
    indexes = index_refs.get(path, ())
    locations = (observation.external_data if observation is not None else None) or ()
    if not _savedmodel(path):
        savedmodel = ()
    if not budget.charge(path, len(indexes) + len(locations) + len(savedmodel), fail):
        return []
    bound: set[Path] = set(indexes)
    for location in locations:
        target = _local_reference(directory, location)
        if target is None or target not in tree.paths:
            fail("ONNX external data reference is missing or outside the model directory")
            continue
        bound.add(target)
    bound.update(savedmodel)
    bound.discard(path)
    return sorted(bound)


@dataclass(frozen=True)
class ModelPackage:
    """A model file's observation and its weight files, the main file first."""

    observation: ModelArtifactObservation | None
    weight_files: tuple[tuple[Path, str | None], ...]
    complete: bool
    budget_exhausted: bool = False
    trust_remote_code: bool | None = None
    loading_config_complete: bool = True


def memoized(verify: Verify, results: dict[tuple[Any, ...], VerificationResult]) -> Verify:
    """``verify`` that runs once per policy entry while ``results`` lives.

    Several models can bind one weight file, so without this one shared file
    would be read and verified again for every model that names it.
    """

    def cached(
        artifact: Path,
        bundle: Path,
        identity: str | None,
        issuer: str | None,
        *,
        allow_oms_dsse: bool = False,
        rekor_root_hash: str | None = None,
        minimum_rekor_tree_size: int | None = None,
    ) -> VerificationResult:
        key = (
            artifact,
            bundle,
            identity,
            issuer,
            allow_oms_dsse,
            rekor_root_hash,
            minimum_rekor_tree_size,
        )
        if key not in results:
            if allow_oms_dsse or rekor_root_hash is not None or minimum_rekor_tree_size is not None:
                results[key] = verify(
                    artifact,
                    bundle,
                    identity,
                    issuer,
                    allow_oms_dsse=allow_oms_dsse,
                    rekor_root_hash=rekor_root_hash,
                    minimum_rekor_tree_size=minimum_rekor_tree_size,
                )
            else:
                results[key] = verify(artifact, bundle, identity, issuer)
        return results[key]

    return cached


def _read_model_configs(
    files: ConfinedCollection,
    tree: ModelTree,
    model_dir: Path,
    read: Callable[[ConfinedCollection, Path], bytes | None],
) -> tuple[list[tuple[Path, dict[str, Any]]], list[tuple[Path, str]]]:
    """Read this directory's model configs under the caller's shared byte budget."""
    configs: list[tuple[Path, dict[str, Any]]] = []
    config_files: list[tuple[Path, str]] = []
    for name in MODEL_CONFIG_FILES:
        path = model_dir / name
        if path not in tree.paths:
            _report_variants(files, path)
            continue
        raw = read(files, path)
        if raw is None:
            continue
        if (followed := files.link_target(path)) is not None and credential_shaped(followed):
            # The symlink was replaced after the check above.
            files._fail(path, "file changed during collection")
            continue
        config_files.append((path, hash_bytes(raw)))
        try:
            data = _json_document(raw)
        except (ValueError, RecursionError):
            files._fail(path, "invalid JSON or duplicate keys")
            continue
        if not isinstance(data, dict):
            files._fail(path, "model configuration must be an object")
            continue
        configs.append((path, _checked_config(files, path, data)))

    return configs, config_files


def _remote_code_setting(configs: list[tuple[Path, dict[str, Any]]]) -> bool | None:
    values = [
        data["trust_remote_code"]
        for _, data in configs
        if isinstance(data.get("trust_remote_code"), bool)
    ]
    return any(values) if values else None


class ModelPackages:
    """Re-observe model files and their bound weight files beneath one root, as a scan does.

    One instance serves one validation. Each directory is walked once, each file
    is inspected or hashed once, each model is bound once, every read is charged
    to one byte budget the size of a scan's and every binding to one binding
    budget the size of a scan's, so a BOM that lists many models, or many models
    that share one weight file, cannot multiply the work of the scan that
    produced it.
    """

    def __init__(
        self, root: Path, *, byte_budget: int | None = None, binding_budget: int | None = None
    ) -> None:
        self.root = root
        self.covered: set[Path] = set()
        self.verified: dict[tuple[Any, ...], VerificationResult] = {}
        # The scan's aggregate budget for the same files.
        self._remaining = limits.current().model_total_bytes if byte_budget is None else byte_budget
        self._refused: set[Path] = set()
        self._budget = InspectionBudget()
        self._bindings = BindingBudget(binding_budget)
        self._trees: dict[Path, tuple[ModelTree, bool]] = {}
        self._indexes: dict[Path, tuple[dict[Path, list[Path]], list[Path], bool]] = {}
        self._savedmodels: dict[Path, tuple[list[Path], bool]] = {}
        self._observations: dict[Path, ModelArtifactObservation | None] = {}
        self._digests: dict[Path, str | None] = {}
        self._packages: dict[Path, ModelPackage] = {}
        self._loading_configs: dict[Path, tuple[bool | None, bool]] = {}

    def observe(self, path: Path) -> ModelPackage:
        """Observe root-relative ``path`` and every weight file a loader reads with it."""
        if path in self._packages:
            return self._packages[path]
        failures: list[str] = []
        directory = path.parent
        with ConfinedCollection(
            self.root, failures, max_total_bytes=limits.bound("model-total-bytes")
        ) as files:
            tree, walked = self._tree(files, directory)
            observation = self._observe(files, path)
            index_refs, indexes, indexed = self._index_references(files, tree, directory)
            savedmodel, listed = (
                self._savedmodel_files(files, tree, directory) if _savedmodel(path) else ([], True)
            )
            weights = [(path, observation.digest if observation is not None else None)]
            for companion in bound_weight_files(
                tree,
                path,
                observation,
                index_refs,
                savedmodel,
                lambda reason: files._fail(path, reason),
                self._bindings,
            ):
                weights.append((companion, self._hash(files, companion)))
            weight_reads_complete = not failures
            if directory not in self._loading_configs:
                before = files.failures_recorded
                configs, _ = _read_model_configs(files, tree, directory, self._read_loading_config)
                self._loading_configs[directory] = (
                    _remote_code_setting(configs),
                    files.failures_recorded == before,
                )
        remote_code, config_complete = self._loading_configs[directory]
        self.covered.update(weight for weight, _ in weights)
        read = {weight for weight, _ in weights}.union(indexes)
        exhausted = bool(read & self._refused or read & self._bindings.refused)
        package = ModelPackage(
            observation,
            tuple(weights),
            walked
            and indexed
            and listed
            and not exhausted
            and weight_reads_complete
            and all(digest for _, digest in weights),
            exhausted,
            remote_code,
            config_complete,
        )
        self._packages[path] = package
        return package

    def _read_loading_config(self, files: ConfinedCollection, path: Path) -> bytes | None:
        linked = files.in_root_target(path)
        reason = credential_gap(path.as_posix(), None if linked is None else linked.as_posix())
        if reason:
            files._fail(path, reason)
            return None
        return self._read(files, path, expected_link_target=linked if linked != path else None)

    def observation(self, path: Path) -> ModelArtifactObservation | None:
        """The observation of root-relative ``path``, made now unless already made."""
        if path not in self._observations:
            with ConfinedCollection(
                self.root, [], max_total_bytes=limits.bound("model-total-bytes")
            ) as files:
                self._observe(files, path)
        return self._observations.get(path)

    def _tree(self, files: ConfinedCollection, directory: Path) -> tuple[ModelTree, bool]:
        # A walk of an ancestor that met no failure lists exactly what a walk of
        # ``directory`` would; a walk with failures says nothing about this one.
        for ancestor in (directory, *directory.parents):
            cached = self._trees.get(ancestor)
            if cached is not None and (ancestor == directory or cached[1]):
                return cached
        before = files.failures_recorded
        tree = ModelTree(files.iter_files(directory))
        self._trees[directory] = (tree, files.failures_recorded == before)
        return self._trees[directory]

    def _charge(self, files: ConfinedCollection, path: Path, stream: BinaryIO) -> None:
        size = os.fstat(stream.fileno()).st_size
        if size > self._remaining:
            self._refused.add(path)
            files._fail(path, BUDGET_EXHAUSTED)
            raise OSError(BUDGET_EXHAUSTED)
        self._remaining -= size

    def _observe(self, files: ConfinedCollection, path: Path) -> ModelArtifactObservation | None:
        if path not in self._observations:
            observation: ModelArtifactObservation | None = None
            try:
                with files.open_regular(path, max_bytes=limits.bound("model-bytes")) as stream:
                    self._charge(files, path, stream)
                    observed = observe_model_artifact(path, stream=stream, budget=self._budget)
                # Commit only after the confined stream confirmed the pathname still
                # names the bytes that were read. Validation reads no chat template,
                # so none is kept for the rest of the run.
                observation = replace(observed, chat_templates=())
                self._digests[path] = observed.digest
            except (OSError, ValueError):
                files._fail(path, "model inspection or hashing failed")
            self._observations[path] = observation
        return self._observations[path]

    def _read(
        self, files: ConfinedCollection, path: Path, *, expected_link_target: Path | None = None
    ) -> bytes | None:
        try:
            with files.open_regular(path, expected_link_target=expected_link_target) as stream:
                self._charge(files, path, stream)
                content = bytearray()
                while chunk := stream.read(65536):
                    content += chunk
        except (OSError, ValueError):
            files._fail(path, "read refused")
            return None
        return bytes(content)

    def _hash(self, files: ConfinedCollection, path: Path) -> str | None:
        if path not in self._digests:
            digest: str | None = None
            try:
                with files.open_regular(path, max_bytes=limits.bound("model-bytes")) as stream:
                    self._charge(files, path, stream)
                    hasher = hashlib.sha256()
                    while chunk := stream.read(65536):
                        hasher.update(chunk)
                digest = "sha256:" + hasher.hexdigest()
            except (OSError, ValueError):
                files._fail(path, "hash refused")
            self._digests[path] = digest
        return self._digests[path]

    def _index_references(
        self, files: ConfinedCollection, tree: ModelTree, directory: Path
    ) -> tuple[dict[Path, list[Path]], list[Path], bool]:
        """The directory's shard references, its index files and whether all were read."""
        if directory not in self._indexes:
            before = files.failures_recorded
            references, indexes = index_references(
                files,
                tree,
                directory,
                self._digests,
                self._bindings,
                read=lambda index: self._read(files, index),
            )
            self._indexes[directory] = (references, indexes, files.failures_recorded == before)
        return self._indexes[directory]

    def _savedmodel_files(
        self, files: ConfinedCollection, tree: ModelTree, directory: Path
    ) -> tuple[list[Path], bool]:
        """The directory's SavedModel files and whether listing them met no failure."""
        if directory not in self._savedmodels:
            before = files.failures_recorded
            found = savedmodel_files(files, tree, directory)
            self._savedmodels[directory] = (found, files.failures_recorded == before)
        return self._savedmodels[directory]


def unused_policy_entries(
    files: ConfinedCollection, policies: Mapping[Path, ArtifactPolicy], covered: Iterable[Path]
) -> list[tuple[str, str]]:
    """Operator entries that no check verifies, as (root-relative path, reason) pairs.

    The model checks verify the weight files in ``covered`` (root-relative, from a
    walk that follows no symlink). The discovery producer check verifies the
    ShadowScan report the importer reads, the first of its locations that exists,
    and only under a Sigstore entry.
    """
    if not policies:
        return []
    used = {files.root / path for path in covered}
    locations = [files.path_identity(location) for location in REPORT_PATHS]
    found = [identity for identity in locations if identity is not None]
    report = found[0] if found else None
    unused: list[tuple[str, str]] = []
    for key, policy in sorted(policies.items()):
        if key in used:
            continue
        try:
            relative = key.relative_to(files.root)
        except ValueError:
            unused.append((".", OUTSIDE_ENTRY))
            continue
        identity = files.path_identity(relative)
        if identity is not None and identity == report:
            if isinstance(policy, SigstoreArtifactPolicy) and not policy.allow_oms_dsse:
                continue
            unused.append((relative.as_posix(), REPORT_ENTRY_KIND))
        elif identity is not None and identity in found:
            unused.append((relative.as_posix(), UNREAD_REPORT_ENTRY))
        else:
            unused.append((relative.as_posix(), UNUSED_ENTRY))
    return unused


@dataclass(frozen=True)
class WeightVerification:
    """The operator-policy outcome for all weight files of one model."""

    status: SigningStatus | None
    identity: str | None
    evidence: ClaimEvidence | None
    issues: tuple[tuple[str, str, str], ...]
    signatures_checked: int
    signatures_verified: int
    pins_verified: int


def _label(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def verify_weight_files(
    weight_files: Sequence[tuple[Path, str | None]],
    root: Path,
    policies: Mapping[Path, ArtifactPolicy],
    *,
    verify: Verify,
    unbound: str | None = None,
) -> WeightVerification:
    """Verify every weight file against its operator policy entry, main file first.

    ``weight_files`` pairs root-relative paths with the SHA-256 observed through
    the confined reader. A file verifies when its digest pin matches, or when its
    Sigstore bundle verifies over exactly that digest under the entry's identity
    and issuer (and its ``expected_sha256``, if set). The model counts as signed
    only when every weight file verifies, and never when ``unbound`` gives the reason
    its other weight files are unknown. ``policies`` is keyed by resolved path
    and ``root`` must be resolved: the paths come from a confined walk, which
    follows no symlink, so none is resolved again.
    """
    if not policies:
        return WeightVerification(None, None, None, (), 0, 0, 0)
    methods: dict[Path, str] = {}
    refs: set[str] = set()
    failures: list[str] = []
    issues: list[tuple[str, str, str]] = []
    uncovered: list[str] = []
    attempted: list[str] = []
    unavailable = rejected = False
    checked = signatures = pins = 0
    for path, digest in weight_files:
        label = path.as_posix()
        policy = policies.get(root / path)
        if policy is None:
            uncovered.append(label)
            continue
        if policy.policy_digest is not None:
            refs.add(POLICY_REF_PREFIX + policy.policy_digest)
        entry_method = (
            DIGEST_PIN_METHOD
            if isinstance(policy, DigestPinPolicy)
            else (OMS_DSSE_METHOD if policy.allow_oms_dsse else SIGSTORE_METHOD)
        )
        attempted.append(entry_method)
        if digest is None:
            rejected = True
            reason = "Artifact could not be hashed through the confined reader"
            failures.append(f"{label}: {reason}")
            issues.append(("signature_verification_failed", reason, "error"))
            continue
        if isinstance(policy, DigestPinPolicy):
            if hmac.compare_digest(digest, policy.expected_sha256):
                pins += 1
                methods[path] = DIGEST_PIN_METHOD
                refs.add(f"{DIGEST_PIN_METHOD}:{label}@{digest}")
            else:
                rejected = True
                reason = "Artifact differs from the operator digest pin"
                failures.append(f"{label}: {reason}")
                issues.append(("signature_verification_failed", reason, "error"))
            continue
        checked += 1
        if (
            policy.allow_oms_dsse
            or policy.rekor_root_hash is not None
            or policy.minimum_rekor_tree_size is not None
        ):
            result = verify(
                policy.artifact_path,
                policy.bundle_path,
                policy.expected_identity,
                policy.expected_issuer,
                allow_oms_dsse=policy.allow_oms_dsse,
                rekor_root_hash=policy.rekor_root_hash,
                minimum_rekor_tree_size=policy.minimum_rekor_tree_size,
            )
        else:
            result = verify(
                policy.artifact_path,
                policy.bundle_path,
                policy.expected_identity,
                policy.expected_issuer,
            )
        details = result.details or {}
        if result.error == SIGSTORE_MISSING:
            unavailable = True
            failures.append(f"{label}: {SIGSTORE_MISSING}")
            issues.append(("signature_verification_failed", SIGSTORE_MISSING, "error"))
            continue
        pinned = policy.expected_sha256 is None or hmac.compare_digest(
            digest, policy.expected_sha256
        )
        if (
            result.verified
            and result.identity == policy.expected_identity
            and result.issuer == policy.expected_issuer
            and details.get("artifact_digest") == digest
            and pinned
        ):
            signatures += 1
            methods[path] = entry_method
            refs.update(
                {
                    f"{entry_method}:{label}@{digest}",
                    f"identity:{policy.expected_identity}",
                    f"issuer:{policy.expected_issuer}",
                }
            )
            if policy.rekor_root_hash is not None:
                refs.add(f"rekor-root:{policy.rekor_root_hash}")
            if policy.minimum_rekor_tree_size is not None:
                refs.add(f"rekor-min-tree-size:{policy.minimum_rekor_tree_size}")
            bundle_digest = details.get("bundle_digest")
            if isinstance(bundle_digest, str):
                refs.add(f"bundle:{_label(policy.bundle_path, root)}@{bundle_digest}")
            continue
        rejected = True
        reason = (
            "Signed artifact differs from the operator digest pin"
            if result.verified and not pinned
            else result.error or "Signature verification failed"
        )
        failures.append(f"{label}: {reason}")
        issues.append(("signature_verification_failed", reason, "error"))
    if not attempted:
        return WeightVerification(None, None, None, (), 0, 0, 0)
    main = weight_files[0][0]
    status: SigningStatus
    if rejected:
        status = SigningStatus.VERIFICATION_FAILED
    elif unavailable:
        status = SigningStatus.VERIFICATION_UNAVAILABLE
    elif uncovered:
        status = SigningStatus.PARTIALLY_VERIFIED
        issues.extend(
            (
                "unverified_signature",
                f"No trusted signer policy entry covers weight file {label}",
                "unknown",
            )
            for label in uncovered
        )
    elif methods.get(main) in {SIGSTORE_METHOD, OMS_DSSE_METHOD}:
        status = SigningStatus.SIGSTORE_SIGNED
    else:
        status = SigningStatus.DIGEST_PINNED
    if unbound is not None and status.value in VERIFIED_SIGNING_STATUSES:
        status = SigningStatus.PARTIALLY_VERIFIED
        failures.append(f"{main.as_posix()}: {unbound}")
        issues.append(("unverified_signature", unbound, "unknown"))
    verified = status.value in VERIFIED_SIGNING_STATUSES
    reasons = failures + [f"{label}: no signer policy entry" for label in uncovered]
    evidence = ClaimEvidence(
        assurance=AssuranceLevel.VERIFIED if verified else AssuranceLevel.OBSERVED,
        method=methods.get(main, attempted[0]),
        scope="operator-signature-policy",
        collector="model",
        locator=main.as_posix(),
        evidence_refs=sorted(refs),
        unknown_reason=None if verified else "; ".join(sorted(reasons)),
    )
    policy = policies.get(root / main)
    identity = (
        policy.expected_identity
        if status == SigningStatus.SIGSTORE_SIGNED and isinstance(policy, SigstoreArtifactPolicy)
        else None
    )
    return WeightVerification(status, identity, evidence, tuple(issues), checked, signatures, pins)


@dataclass
class _DirectoryContext:
    config: dict[str, Any]
    trust_remote_code: bool | None
    config_files: list[tuple[Path, str]]
    tokenizer_files: list[tuple[Path, str]]
    chat_templates: list[tuple[str, str]]
    custom_code: dict[str, Any] | None
    index_refs: dict[Path, list[Path]]
    base_model: str | None
    # The sources of the directory's Hugging Face chat templates that carry the
    # attribute access Jinja sandbox escapes use.
    template_escapes: list[str] = field(default_factory=list)
    savedmodel: list[Path] = field(default_factory=list)


def _checked_config(files: ConfinedCollection, path: Path, data: dict[str, Any]) -> dict[str, Any]:
    invalid_fields = [
        key
        for key in _CONFIG_STRING_FIELDS
        if data.get(key) is not None and not isinstance(data[key], str)
    ]
    if data.get("trust_remote_code") is not None and not isinstance(
        data["trust_remote_code"], bool
    ):
        invalid_fields.append("trust_remote_code")
    if invalid_fields:
        files._fail(
            path,
            "invalid model configuration field type: " + ", ".join(sorted(invalid_fields)),
        )
        # Retain the artifact inventory while refusing the invalid
        # claims. Diagnostics contain schema field names only.
        data = {k: v for k, v in data.items() if k not in invalid_fields}
    return data


def _code_references(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """Whether a configuration declares repository code, and its well-formed references."""
    declared = False
    references: list[str] = []
    auto_map = data.get("auto_map")
    if auto_map is not None and auto_map != {}:
        declared = True
        for value in auto_map.values() if isinstance(auto_map, dict) else ():
            for item in value if isinstance(value, list) else [value]:
                if isinstance(item, str) and _CODE_REFERENCE.fullmatch(item):
                    references.append(item)
    pipelines = data.get("custom_pipelines")
    if pipelines is not None and pipelines != {}:
        declared = True
        for spec in pipelines.values() if isinstance(pipelines, dict) else ():
            impl = spec.get("impl") if isinstance(spec, dict) else None
            if isinstance(impl, str) and _CODE_REFERENCE.fullmatch(impl):
                references.append(impl)
    return declared, references


class ModelScanner(Scanner):
    name = "model"

    def __init__(
        self,
        signature_policies: Sequence[SigstoreArtifactPolicy] = (),
        *,
        digest_pins: Sequence[DigestPinPolicy] = (),
    ) -> None:
        self._policies: dict[Path, ArtifactPolicy] = {
            policy.artifact_path.resolve(): policy
            for policy in policy_entries(signature_policies, digest_pins)
        }
        self._tree = ModelTree(())
        self._digests: dict[Path, str | None] = {}
        self._read: set[Path] = set()
        self._bound_content: dict[Path, ModelArtifactObservation] = {}
        self._gaps: list[str] = []
        self._budget = InspectionBudget()
        self._bindings = BindingBudget()
        self._shared = BindingBudget(reason=SHARED_DIGESTS_EXHAUSTED)
        self._verified: dict[tuple[Any, ...], VerificationResult] = {}

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        # One deterministic walk and one aggregate budget for all model/config
        # reads. Large weights are streamed; metadata stays under the file-bytes limit.
        with self._collection(
            project_root, result, max_total_bytes=limits.bound("model-total-bytes")
        ) as files:
            self._tree = tree = ModelTree(files.iter_files())
            self._digests, self._read, self._budget = {}, set(), InspectionBudget()
            self._gaps, self._bound_content = [], {}
            self._bindings, self._verified = BindingBudget(), {}
            self._shared = BindingBudget(reason=SHARED_DIGESTS_EXHAUSTED)
            named = sorted(
                {
                    path.parent
                    for path in tree.files
                    if model_format(path) is not None or _index_base(path) is not None
                }
            )
            contexts: dict[Path, _DirectoryContext] = {}
            covered: set[Path] = set()
            for model_dir in named:
                context = contexts[model_dir] = self._directory_context(files, model_dir)
                for path in tree.children.get(model_dir, ()):
                    detected = model_format(path)
                    if detected is not None:
                        component, weight_files = self._scan_model_file(
                            files, path, detected, context
                        )
                        result.components.append(component)
                        covered.update(weight_files)
            # A file no name rates is a model artifact by its content. It is checked after
            # the files that the models above bind and their directories configure, and
            # only if none of them is it, so no byte is read twice.
            # A file a model binds is rated by its content too, from the read that hashed it.
            found = dict(self._bound_content)
            for path in tree.files:
                if path not in self._read and _content_candidate(path):
                    observation = self._content_artifact(files, path)
                    if observation is not None:
                        found[path] = observation
            if not (named or found or result.scan_failures or result.surfaces_excluded):
                result.surfaces_scanned.append("model-weights (no model files found)")
            for model_dir in sorted({path.parent for path in found}):
                context = (
                    contexts[model_dir]
                    if model_dir in contexts
                    else self._directory_context(files, model_dir)
                )
                # A SavedModel binds a linked directory's files under the link's name.
                linked = sorted(p for p in found if p.parent == model_dir and p not in tree.paths)
                for path in [*tree.children.get(model_dir, ()), *linked]:
                    observation = found.get(path)
                    if observation is not None:
                        component, weight_files = self._scan_model_file(
                            files,
                            path,
                            _content_format(observation.explanation),
                            context,
                            observation=observation,
                        )
                        result.components.append(component)
                        covered.update(weight_files)
            # An operator entry that no check verifies must not look enforced.
            for label, reason in unused_policy_entries(files, self._policies, covered):
                files._fail(label, reason)
            result.surfaces_scanned.extend(sorted(path.as_posix() for path in self._read))
            result.surfaces_excluded.extend(self._gaps)
        return result

    def _content_artifact(
        self, files: ConfinedCollection, path: Path
    ) -> ModelArtifactObservation | None:
        """The observation of a file no model name rates, when its content is an artifact."""
        try:
            with files.open_regular(path, max_bytes=limits.bound("model-bytes")) as stream:
                observed = observe_content(path, stream=stream, budget=self._budget)
        except (OSError, ValueError):
            files._fail(path, "model inspection or hashing failed")
            return None
        # Only now has the confined stream confirmed the pathname still names those bytes.
        return observed

    def _digest(self, files: ConfinedCollection, path: Path) -> str | None:
        if path not in self._digests:
            self._read.add(path)
            self._digests[path] = files.hash_file(path, max_bytes=limits.bound("model-bytes"))
        return self._digests[path]

    def _unbound_reason(self, path: Path) -> str | None:
        """Why the files a loader opens with ``path`` are unknown, or ``None`` when known.

        A shard index the budget refused, or one that could not be read, parsed or
        bound, binds none of its shards, which then charge nothing, so the gap is the
        shard's too: what its index makes a loader open is unknown.
        """
        bindings = self._bindings
        indexes = [
            index
            for index in self._tree.children.get(path.parent, ())
            if _index_base(index) is not None
        ]
        if path in bindings.refused or any(index in bindings.refused for index in indexes):
            return bindings.reason
        if path.parent in bindings.unbound or any(index in bindings.unbound for index in indexes):
            return INDEX_UNBOUND
        return None

    def _companion_digest(self, files: ConfinedCollection, path: Path) -> str | None:
        """The digest of a file a model binds, observed for its content when a file of
        that name is a content candidate; a payload is kept for its own component."""
        if path in self._digests or not _content_candidate(path):
            return self._digest(files, path)
        self._read.add(path)
        self._digests[path] = None
        try:
            with files.open_regular(path, max_bytes=limits.bound("model-bytes")) as stream:
                observed = observe_model_artifact(path, stream=stream, budget=self._budget)
        except (OSError, ValueError):
            files._fail(path, "model inspection or hashing failed")
            return None
        self._digests[path] = observed.digest
        if (
            observed.safety == SerializationSafety.UNSAFE_CODE_EXECUTION
            or observed.explanation in _CONTENT_UNREAD
        ):
            self._bound_content[path] = observed
        return observed.digest

    def _credential_file(self, files: ConfinedCollection, path: Path) -> bool:
        """Whether ``path``, or the in-root file a symlink there leads to, is named as
        holding credentials, such as ``config.json -> ../.env``; it is then a recorded gap
        and is not read, so no unkeyed digest of it reaches the inventory."""
        linked = files.in_root_target(path)
        reason = credential_gap(path.as_posix(), None if linked is None else linked.as_posix())
        if reason is None:
            return False
        self._gaps.append(f"{path.as_posix()}: {reason}; not read or inventoried")
        return True

    def _directory_context(self, files: ConfinedCollection, model_dir: Path) -> _DirectoryContext:
        tree = self._tree

        def read_config(files: ConfinedCollection, path: Path) -> bytes | None:
            if self._credential_file(files, path):
                return None
            self._read.add(path)
            return files.read_bytes(path)

        configs, config_files = _read_model_configs(files, tree, model_dir, read_config)
        merged: dict[str, Any] = {}
        templates: list[tuple[str, str]] = []
        escapes: list[str] = []
        declared_in: list[str] = []
        references: list[str] = []
        base_model: str | None = None
        for path, data in configs:
            for key in _CONFIG_STRING_FIELDS:
                if key not in merged and isinstance(data.get(key), str):
                    merged[key] = data[key]
            nested = data.get("quantization_config")
            if isinstance(nested, dict) and isinstance(nested.get("quant_method"), str):
                merged.setdefault("quant_method", nested["quant_method"])
            if data.get("adapter_config"):
                merged.setdefault("adapter_config", True)
            declared, found = _code_references(data)
            if declared:
                declared_in.append(path.as_posix())
                references.extend(found)
            candidate = data.get("base_model_name_or_path")
            if path.name == "adapter_config.json" and isinstance(candidate, str):
                base_model = candidate if _HUB_ID.fullmatch(candidate) else None
            # Bounded already: the configuration was read within the file-bytes limit.
            for source, template in self._config_templates(files, path, data.get("chat_template")):
                templates.append((source, hash_bytes(template)))
                if template_escape_markers(template):
                    escapes.append(source)

        for name in CHAT_TEMPLATE_FILES:
            if model_dir / name in tree.paths:
                self._template_file(files, model_dir / name, templates, escapes)
            else:
                _report_variants(files, model_dir / name)
        for path in self._template_directory(files, model_dir):
            if path.suffix.lower() in {".jinja", ".jinja2"}:
                self._template_file(files, path, templates, escapes)

        tokenizer_files: list[tuple[Path, str]] = []
        for name in TOKENIZER_FILES:
            path = model_dir / name
            if path not in tree.paths:
                _report_variants(files, path)
            elif self._credential_file(files, path):
                continue
            elif (digest := self._digest(files, path)) is not None:
                tokenizer_files.append((path, digest))
        custom_code = None
        if declared_in:
            referenced_modules: set[str] = set()
            for reference in references:
                if "--" in reference:
                    continue
                mod_parts = reference.split(".")[:-1]
                if mod_parts:
                    referenced_modules.add("/".join(mod_parts).lower() + ".py")
                    for idx in range(1, len(mod_parts)):
                        referenced_modules.add("/".join(mod_parts[:idx]).lower() + "/__init__.py")
            python_files = []
            for path in tree.below(model_dir):
                if path.suffix.lower() != ".py" or not (
                    path.parent == model_dir
                    or path.relative_to(model_dir).as_posix().lower() in referenced_modules
                ):
                    continue
                if _CREDENTIAL_PYTHON_STEM.search(path.stem):
                    # Not digested, so a change to it raises no drift alert: a gap.
                    self._gaps.append(
                        f"{path.as_posix()}: custom code module named as holding "
                        "credentials; not read or inventoried"
                    )
                elif (digest := self._digest(files, path)) is not None:
                    python_files.append({"path": path.as_posix(), "sha256": digest})
            custom_code = {
                "declared_in": declared_in,
                "references": sorted(set(references)),
                "cross_repository": any("--" in reference for reference in references),
                "python_files": python_files,
            }
        index_refs, indexes = index_references(
            files, tree, model_dir, self._digests, self._bindings
        )
        self._read.update(indexes)
        savedmodel = (
            savedmodel_files(files, tree, model_dir)
            if any(_savedmodel(path) for path in tree.children.get(model_dir, ()))
            else []
        )
        return _DirectoryContext(
            config=merged,
            trust_remote_code=_remote_code_setting(configs),
            config_files=config_files,
            tokenizer_files=tokenizer_files,
            chat_templates=templates,
            custom_code=custom_code,
            index_refs=index_refs,
            base_model=base_model,
            template_escapes=escapes,
            savedmodel=savedmodel,
        )

    def _template_directory(self, files: ConfinedCollection, model_dir: Path) -> list[Path]:
        """The files of ``additional_chat_templates`` under the names a loader opens.

        The walk lists a directory symlink's files under its target's name only, so
        they are looked up through the link, where a read follows it.
        """
        directory = model_dir / CHAT_TEMPLATE_DIRECTORY
        listed = self._tree.children.get(directory)
        if listed is not None:
            return listed
        if not files.is_directory(directory):
            _report_variants(files, directory)
            return []
        target = files.link_target(directory)
        if target is None:
            return []
        return [directory / path.name for path in self._tree.children.get(Path(target), ())]

    @staticmethod
    def _config_templates(
        files: ConfinedCollection, path: Path, value: object
    ) -> list[tuple[str, bytes]]:
        """Chat templates from a configuration: one string, or a list of named templates."""
        if value is None:
            return []
        locator = f"{path.as_posix()}#chat_template"
        if isinstance(value, str):
            return [(locator, value.encode("utf-8", "surrogatepass"))]
        if isinstance(value, list) and all(
            isinstance(item, dict) and isinstance(item.get("template"), str) for item in value
        ):
            return [
                (f"{locator}/{index}", item["template"].encode("utf-8", "surrogatepass"))
                for index, item in enumerate(value)
            ]
        files._fail(path, "chat_template must be a string or a list of named templates")
        return []

    def _template_file(
        self,
        files: ConfinedCollection,
        path: Path,
        templates: list[tuple[str, str]],
        escapes: list[str],
    ) -> None:
        """Digest a chat template file and check its text for sandbox-escape shapes.

        A template is read whole within the file-bytes limit. A larger one is streamed
        for its digest only, and is a coverage gap because its text was not checked.
        """
        source = path.as_posix()
        if self._credential_file(files, path):
            return
        found = files.regular_file(path)
        if found is not None and found[1] <= files.max_file_bytes:
            self._read.add(path)
            raw = files.read_bytes(path)
            if raw is None:
                self._digests[path] = None
                return
            digest = self._digests[path] = hash_bytes(raw)
            templates.append((source, digest))
            if template_escape_markers(raw):
                escapes.append(source)
            return
        streamed = self._digest(files, path)
        if streamed is None:
            return
        templates.append((source, streamed))
        reason = (
            limits.bound("file-bytes").exceeded()
            if found is not None
            else "the file could not be read whole"
        )
        files.exclusions.append(f"{source}: chat template not inspected: {reason}")

    def _scan_model_file(
        self,
        files: ConfinedCollection,
        path: Path,
        detected: tuple[str, str],
        context: _DirectoryContext,
        *,
        observation: ModelArtifactObservation | None = None,
    ) -> tuple[ModelComponent, list[Path]]:
        """A component for ``path``; a file inventoried by content comes with its observation."""
        fmt_key, fmt_name = detected
        self._read.add(path)
        if observation is None:
            try:
                with files.open_regular(path, max_bytes=limits.bound("model-bytes")) as stream:
                    observed = observe_model_artifact(path, stream=stream, budget=self._budget)
                # Commit only after the confined stream confirmed the pathname still
                # names the bytes that were read.
                observation = observed
            except (OSError, ValueError):
                files._fail(path, "model inspection or hashing failed")
        if observation is not None:
            safety, format_evidence = observation.safety, observation.explanation
            weight_hash: str | None = observation.digest
        elif _pickle_family(path):
            # Content rates these formats; an unreadable file keeps the loader's rating.
            safety = SerializationSafety.UNSAFE_CODE_EXECUTION
            format_evidence = (
                "Potential code-executing loader format (artifact could not be hashed)"
            )
            weight_hash = None
        else:
            safety, format_evidence = SerializationSafety.UNKNOWN, "Artifact could not be inspected"
            weight_hash = None
        self._digests[path] = weight_hash
        # A GGUF template is the artifact's own; the directory's Hugging Face templates
        # apply to every model in it, and each gets its finding. They overrule only a
        # safe rating: the unverified-SafeTensors and unknown-format findings derive
        # from an unknown one, and a code-executing one is worse.
        embedded = safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION
        if context.template_escapes and safety == SerializationSafety.SAFE:
            safety = SerializationSafety.UNSAFE_TEMPLATE_INJECTION

        companions = bound_weight_files(
            self._tree,
            path,
            observation,
            context.index_refs,
            context.savedmodel,
            lambda reason: files._fail(path, reason),
            self._bindings,
        )
        weight_files = [
            (path, weight_hash),
            *((c, self._companion_digest(files, c)) for c in companions),
        ]
        verification = verify_weight_files(
            weight_files,
            files.root,
            self._policies,
            verify=memoized(verify_sigstore_bundle, self._verified),
            unbound=self._unbound_reason(path),
        )
        status = verification.status or self._unverified_status(path)
        if status == SigningStatus.VERIFICATION_UNAVAILABLE:
            files._fail(path, SIGSTORE_MISSING)
        trust_tier = {
            SigningStatus.SIGSTORE_SIGNED: TrustTier.THIRD_PARTY_SIGNED,
            SigningStatus.DIGEST_PINNED: TrustTier.INTERNAL_VERIFIED,
        }.get(status, TrustTier.UNKNOWN)

        gguf_templates = observation.chat_templates if observation is not None else ()
        custom_code = context.custom_code
        # Every model records its directory's digests, so they are charged per model.
        recorded = self._shared.charge(
            path,
            len(context.config_files)
            + len(context.tokenizer_files)
            + len(context.chat_templates)
            + len(gguf_templates)
            + (
                len(custom_code["references"]) + len(custom_code["python_files"])
                if custom_code is not None
                else 0
            ),
            lambda reason: files._fail(path, reason),
        )
        templates = [*context.chat_templates, *gguf_templates] if recorded else []
        properties: dict[str, Any] = {"format_inspection": format_evidence}
        # A header that was not read, or is not the format's, establishes neither the
        # format the name claims nor a model type; the record says what the name claims.
        established = fmt_key not in _HEADER_CHECKED or (
            observation is not None and observation.header_matched
        )
        if not established:
            properties[NAMED_FORMAT_PROPERTY] = fmt_name
        if companions:
            properties["weight_files"] = [
                {"path": companion.as_posix(), "sha256": digest}
                for companion, digest in weight_files[1:]
                if digest is not None
            ]
        if recorded and context.config_files:
            properties["config_files"] = [
                {"path": config.as_posix(), "sha256": digest}
                for config, digest in context.config_files
            ]
        if recorded and context.tokenizer_files:
            properties["tokenizer_files"] = [
                {"path": tokenizer.as_posix(), "sha256": digest}
                for tokenizer, digest in context.tokenizer_files
            ]
        if templates:
            properties["chat_templates"] = [
                {"source": source, "sha256": digest} for source, digest in sorted(templates)
            ]
        if recorded and custom_code is not None:
            properties["custom_code"] = custom_code
        if context.base_model is not None:
            properties["base_model"] = context.base_model
        if observation is not None and observation.gguf_architecture is not None:
            properties["gguf_architecture"] = observation.gguf_architecture
        if observation is not None and observation.gguf_error is not None:
            properties["gguf_metadata"] = f"not inspected: {observation.gguf_error}"
            if observation.gguf_error == GGUF_LIMIT:
                # A template behind more metadata than the bounds allow was not checked.
                gap = f"{path.as_posix()}: GGUF chat templates not inspected: {GGUF_LIMIT}"
                if gap not in files.exclusions:
                    files.exclusions.append(gap)

        config = context.config
        name = path.as_posix()
        component = ModelComponent(
            bom_ref=f"model:{name}",
            name=name,
            serialization_format=fmt_name if established else None,
            serialization_safety=safety,
            signing_status=status.value,
            signing_identity=verification.identity,
            properties=properties,
            model_type=self._infer_model_type(config, path) if established else None,
            derivation_type=config.get("peft_type"),
            quantization_method=config.get("quantization_method") or config.get("quant_method"),
            trust_remote_code=context.trust_remote_code,
            tokenizer_hash=(
                manifest_digest((p.as_posix(), d) for p, d in context.tokenizer_files)
                if recorded and context.tokenizer_files
                else None
            ),
            chat_template_hash=manifest_digest(templates) if templates else None,
            tensor_inventory_hash=(
                observation.fingerprint.get("tensor_inventory_sha256") if observation else None
            ),
            safetensors_header_hash=(
                observation.fingerprint.get("safetensors_header_sha256") if observation else None
            ),
            hashes={"sha256": weight_hash} if weight_hash else {},
            source_path=name,
            trust_tier=trust_tier,
            risks=self._assess_model_risks(
                path,
                fmt_key,
                safety,
                status.value,
                context,
                embedded=embedded,
                established=established,
            ),
            claims=(
                {SIGNING_EVIDENCE_CLAIM: verification.evidence}
                if verification.evidence is not None
                else {}
            ),
        )
        return component, [weight for weight, _ in weight_files]

    def _unverified_status(self, artifact: Path) -> SigningStatus:
        adjacent = [artifact.parent / name for name in SIGNING_FILES]
        adjacent += [artifact.with_name(artifact.name + suffix) for suffix in SIGNING_SUFFIXES]
        # An adjacent file is a discovery fact, never proof of a signature.
        if any(path in self._tree.paths for path in adjacent):
            return SigningStatus.SIGNATURE_PRESENT_UNVERIFIED
        # A directory-local search cannot prove the absence of external signatures.
        return SigningStatus.SIGNATURE_NOT_FOUND

    def _infer_model_type(self, config: dict[str, Any], path: Path) -> str:
        if config.get("peft_type") or config.get("adapter_config"):
            return "adapter"
        if config.get("quantization_method") or config.get("quant_method"):
            return "quantized"
        name_lower = path.name.lower()
        if "adapter" in name_lower or "lora" in name_lower:
            return "adapter"
        if "embed" in name_lower:
            return "embedding"
        return "foundation"

    def _assess_model_risks(
        self,
        path: Path,
        fmt_key: str,
        safety: SerializationSafety,
        signing_status: str,
        context: _DirectoryContext,
        *,
        embedded: bool,
        established: bool,
    ) -> list[RiskAssessment]:
        risks: list[RiskAssessment] = []

        if safety == SerializationSafety.UNSAFE_CODE_EXECUTION:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="serialization_format",
                    detail=f"Model '{path.name}' has evidence of a potentially code-executing serialization or loader.",
                    recommendation="Convert to SafeTensors. Block pickle/pt/pth in production.",
                    references=["https://huggingface.co/blog/safetensors-security-audit"],
                )
            )

        if embedded:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="serialization_format",
                    detail=f"Model '{path.name}' embeds a chat template with a potential Python-internals access pattern; actual behavior depends on the renderer and its sandbox.",
                    recommendation="Remove the template or replace it with a reviewed one; render templates only in a sandboxed Jinja2 environment that the loader keeps patched.",
                    references=[DOCUMENTATION],
                )
            )

        if context.template_escapes:
            shown = ", ".join(
                neutralize(source) for source in context.template_escapes[:_LISTED_TEMPLATES]
            )
            more = len(context.template_escapes) - _LISTED_TEMPLATES
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="serialization_format",
                    detail=(
                        f"Model '{path.name}' is configured with a chat template containing "
                        f"a potential Python-internals access pattern: {shown}"
                        + (f" and {more} more" if more > 0 else "")
                        + ". Actual behavior depends on the renderer and its sandbox."
                    ),
                    recommendation=(
                        "Remove the template or replace it with a reviewed one; render chat "
                        "templates only in a sandboxed Jinja2 environment."
                    ),
                    references=[DOCUMENTATION],
                )
            )

        if safety == SerializationSafety.UNKNOWN and fmt_key == "safetensors" and not established:
            # Stored, in the words risk derives it in: a build before this record's
            # format derives the finding from serialization_format, which is withheld
            # here, and would pass the gate that fails on it at any score.
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="invalid_safetensors",
                    detail=(
                        "The declared SafeTensors artifact has no corroborated structural safety."
                    ),
                )
            )

        if safety == SerializationSafety.UNKNOWN:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="serialization_format_unknown",
                    detail=f"Model '{path.name}' format/loader safety could not be established.",
                    recommendation="Validate the actual container and the specific loader before admission.",
                )
            )

        if signing_status not in VERIFIED_SIGNING_STATUSES:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail=f"Model '{path.name}' has no verified artifact-bound signature ({signing_status}).",
                    recommendation=(
                        "Pin the SHA-256 of every weight file in an operator signature policy, or "
                        "sign each one with a Sigstore message signature (sigstore sign) and name "
                        "its bundle and signer there. OpenSSF Model Signing (DSSE) bundles are "
                        "not verified yet."
                    ),
                    references=[DOCUMENTATION],
                )
            )

        if context.trust_remote_code is True:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="code_execution",
                    detail="trust_remote_code=True allows arbitrary code from the model repository.",
                    recommendation="Audit remote code or use a model that does not require it.",
                )
            )

        if context.custom_code is not None:
            elsewhere = (
                " Some references name code in another repository."
                if context.custom_code["cross_repository"]
                else ""
            )
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="custom_code",
                    detail=(
                        f"Model '{path.name}' declares custom code (auto_map or custom_pipelines); "
                        "loading it requires trust_remote_code and runs that Python code."
                        + elsewhere
                    ),
                    recommendation=(
                        "Review the declared modules before loading; their digests are recorded "
                        "so a change raises a drift alert."
                    ),
                    references=[DOCUMENTATION],
                )
            )

        return risks
