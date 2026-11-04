"""Model weight scanner.

Discovers ML models in a project, classifies serialization format safety,
checks for model signing, and computes weight hashes.
"""

from __future__ import annotations

import builtins
import hashlib
import io
import json
import os
import pickletools
import zipfile
import zlib
from collections.abc import Sequence
from contextlib import nullcontext
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, cast

from nexus_symbiote import signature_policy
from nexus_symbiote.core.enums import (
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import descriptor_binding, open_regular_file, parse_json_strict
from nexus_symbiote.core.models import ModelComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.confined import MAX_HASH_BYTES, ConfinedCollection
from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy, verify_sigstore_bundle
from nexus_symbiote.utils.tensors import fingerprint_stream

MODEL_EXTENSIONS = {
    ".safetensors": ("safetensors", "safe-tensors"),
    ".onnx": ("onnx", "onnx"),
    ".pt": ("pt", "pytorch"),
    ".pth": ("pth", "pytorch"),
    ".bin": ("bin", "pytorch-legacy"),
    ".pickle": ("pickle", "pickle"),
    ".pkl": ("pickle", "pickle"),
    ".joblib": ("joblib", "scikit-learn"),
    ".gguf": ("gguf", "llama.cpp"),
    ".ggml": ("ggml", "llama.cpp-legacy"),
    ".ckpt": ("ckpt", "pytorch-checkpoint"),
    ".pdparams": ("pdparams", "paddlepaddle"),
    ".h5": ("hdf5", "keras-hdf5"),
    ".hdf5": ("hdf5", "keras-hdf5"),
    ".keras": ("keras", "keras"),
    ".dill": ("dill", "dill"),
}
# Pickle and joblib dumps are often compressed; their loaders decompress and unpickle.
_COMPRESSED_PICKLE_SUFFIXES = frozenset({".gz", ".bz2", ".xz", ".lzma", ".z"})
_COMPRESSIBLE_PICKLE_SUFFIXES = frozenset({".pkl", ".pickle", ".joblib", ".dill"})
# Generic protobuf files are not models; only the SavedModel graph name is.
NAMED_MODEL_FILES = {"saved_model.pb": ("pb", "tensorflow-savedmodel")}

MODEL_CONFIG_FILES = [
    "config.json",
    "model_config.json",
    "adapter_config.json",
    "tokenizer_config.json",
    "generation_config.json",
    "quantize_config.json",
]

SIGNING_FILES = [
    "model.sig",
    "model.sigstore",
    ".sigstore",
    "signature.json",
    "model.intoto.jsonl",
]

MAX_HASH_SIZE = 5 * 1024 * 1024 * 1024

MAX_MODEL_HEADER_BYTES = 1024 * 1024
MAX_PICKLE_INSPECTION_BYTES = 65536
_DTYPE_BYTES = {
    "BOOL": 1,
    "U8": 1,
    "I8": 1,
    "F8_E4M3": 1,
    "F8_E4M3FN": 1,
    "F8_E5M2": 1,
    "I16": 2,
    "U16": 2,
    "F16": 2,
    "BF16": 2,
    "I32": 4,
    "U32": 4,
    "F32": 4,
    "I64": 8,
    "U64": 8,
    "F64": 8,
}
_UNSAFE_SUFFIXES = {
    ".pickle",
    ".pkl",
    ".pt",
    ".pth",
    ".bin",
    ".joblib",
    ".ckpt",
    ".pdparams",
    ".dill",
}
# Formats first inventoried with these keys use the root-relative path as their
# subject: fixed file names (saved_model.pb) and versioned layouts such as
# <model>/<version>/ or lightning_logs/version_N/checkpoints/ would otherwise
# collide on the parent directory's name.
_PATH_SUBJECT_FORMATS = frozenset(
    {"ckpt", "pdparams", "hdf5", "keras", "pb", "dill", "compressed-pickle"}
)
_HDF5_SUFFIXES = frozenset({".h5", ".hdf5"})
_HDF5_SIGNATURE = b"\x89HDF\r\n\x1a\n"
# Keras stores these as HDF5 attribute names. Only a full-model save has a model
# configuration; a weights file has only the weights markers.
_KERAS_MODEL_MARKER = b"model_config"
_KERAS_WEIGHT_MARKERS = (b"keras_version", b"layer_names", b"model_weights")
_KERAS_MARKERS = (_KERAS_MODEL_MARKER, *_KERAS_WEIGHT_MARKERS)
_HDF5_UNMARKED = "HDF5 container without Keras model configuration or weights markers"
_MAX_KERAS_MEMBERS = 10_000
_MAX_KERAS_CONFIG_BYTES = 16 * 1024 * 1024
_MAX_KERAS_CONFIG_NODES = 1_000_000
# A Keras archive holds config.json, metadata.json and the weights. Exceeding these
# bounds on a readable archive is treated as evasion, never as "unknown".
_MAX_KERAS_INSPECTION_BYTES = 24 * 1024 * 1024


def _name_suffix(path: Path) -> str:
    """Return the lowercase suffix, treating a dotfile name such as '.ckpt' as one."""
    name = path.name.lower()
    return path.suffix.lower() or (name if name.startswith(".") and name.count(".") == 1 else "")


def _name_suffixes(path: Path) -> list[str]:
    name = path.name.lower()
    if name.startswith("."):
        return ["." + part for part in name[1:].split(".")]
    return [suffix.lower() for suffix in path.suffixes]


def _compressed_pickle(path: Path) -> bool:
    suffixes = _name_suffixes(path)[-2:]
    return (
        len(suffixes) == 2
        and suffixes[1] in _COMPRESSED_PICKLE_SUFFIXES
        and suffixes[0] in _COMPRESSIBLE_PICKLE_SUFFIXES
    )


def model_format(path: Path) -> tuple[str, str] | None:
    """Return the (format key, format name) of a supported model file, or ``None``."""
    if _compressed_pickle(path):
        return ("compressed-pickle", "compressed-pickle")
    return MODEL_EXTENSIONS.get(_name_suffix(path)) or NAMED_MODEL_FILES.get(path.name.lower())


class _Members(dict[str, Any]):
    """A JSON object that also keeps every member, including duplicate keys."""

    def __init__(self, members: list[tuple[str, Any]]) -> None:
        super().__init__(members)
        self.members = members


_CODE_LAYERS = frozenset({"Lambda", "__lambda__", "TFOpLambda"})
_KERAS_PACKAGES = frozenset({"keras", "tf_keras", "keras_hub", "keras_nlp", "keras_cv"})


def _foreign_function(module: str, names: list[Any]) -> bool:
    if module.split(".", 1)[0] in _KERAS_PACKAGES:
        return False
    if module == "builtins":
        # Keras serializes its own losses and metrics with module "builtins" and resolves
        # them in its namespaces first; only a name defined by Python's builtins module
        # can reach Python code there.
        return not names or any(
            not isinstance(name, str) or hasattr(builtins, name) for name in names
        )
    return True


def _keras_config_executes(document: object) -> bool:
    """Report Keras configuration constructs that carry or reference code to run.

    Lambda layers carry serialized Python code, and a function reference outside the
    Keras packages names arbitrary code for the loader to import (CVE-2025-1550).
    Every value of a duplicated key is examined. Classes are not flagged, so models
    from extension libraries such as KerasHub stay unknown. Oversized configurations
    fail closed.
    """
    pending = [document]
    visited = 0
    while pending:
        node = pending.pop()
        visited += 1
        if visited > _MAX_KERAS_CONFIG_NODES:
            return True
        if isinstance(node, dict):
            members = node.members if isinstance(node, _Members) else list(node.items())
            values: dict[str, list[Any]] = {}
            for key, value in members:
                values.setdefault(key, []).append(value)
            class_names = [name for name in values.get("class_name", []) if isinstance(name, str)]
            if _CODE_LAYERS.intersection(class_names):
                return True
            if "function" in class_names and any(
                _foreign_function(module, values.get("config", []))
                for module in values.get("module", [])
                if isinstance(module, str)
            ):
                return True
            pending.extend(value for _, value in members)
        elif isinstance(node, list):
            pending.extend(node)
    return False


class _InspectionBudgetError(OSError):
    """The archive needs more inspection than any ordinary Keras archive."""


class _ArchiveView(io.RawIOBase):
    """Random access over a pinned stream for bounded archive inspection.

    Positioning uses the same descriptor (an unbuffered confined stream cannot
    seek itself); every byte still comes from the stream's own bounded read(), so
    confined collection budgets keep applying.
    """

    def __init__(self, stream: BinaryIO, budget: int) -> None:
        self._stream = stream
        self._fd = stream.fileno()
        self._budget = budget

    def readable(self) -> bool:
        return True

    def seekable(self) -> bool:
        return True

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        # A buffered stream must reposition itself, or its read-ahead goes stale.
        if self._stream.seekable():
            return self._stream.seek(offset, whence)
        return os.lseek(self._fd, offset, whence)

    def tell(self) -> int:
        return self._stream.tell() if self._stream.seekable() else os.lseek(self._fd, 0, 1)

    def read(self, size: int | None = -1) -> bytes:
        unbounded = size is None or size < 0
        if not unbounded and size is not None and size > self._budget:
            raise _InspectionBudgetError("archive inspection byte limit exceeded")
        wanted = self._budget if unbounded or size is None else size
        chunks = []
        while wanted > 0:
            chunk = self._stream.read(min(wanted, 1024 * 1024))
            if not chunk:
                break
            chunks.append(chunk)
            wanted -= len(chunk)
            self._budget -= len(chunk)
        if unbounded and self._budget == 0 and self._stream.read(1):
            raise _InspectionBudgetError("archive inspection byte limit exceeded")
        return b"".join(chunks)


def _inspect_keras_archive(stream: BinaryIO) -> tuple[SerializationSafety, str]:
    """Inspect a Keras v3 archive's members and configuration without loading it.

    The stream is the pinned descriptor that was hashed, so no pathname is reopened.
    The configuration is parsed exactly as Keras parses it: json.loads on the raw
    bytes, where the last duplicate key wins and NaN or oversized integers are valid.
    """
    over_budget = (
        SerializationSafety.UNSAFE_CODE_EXECUTION,
        "Keras archive exceeds the inspection limits of an ordinary archive; its "
        "configuration cannot be ruled out as code-carrying",
    )
    try:
        view = _ArchiveView(stream, _MAX_KERAS_INSPECTION_BYTES)
        view.seek(0)
        with zipfile.ZipFile(cast(BinaryIO, view)) as archive:
            members = archive.infolist()
            if len(members) > _MAX_KERAS_MEMBERS:
                return over_budget
            names = [member.filename for member in members]
            if len(names) != len(set(names)):
                # zipfile and Keras read the last duplicate; a reviewer may see the first.
                return (
                    SerializationSafety.UNSAFE_CODE_EXECUTION,
                    "Keras archive has duplicate member names; the loaded configuration is ambiguous",
                )
            if any(PurePosixPath(name).suffix.lower() in {".pkl", ".pickle"} for name in names):
                return (
                    SerializationSafety.UNSAFE_CODE_EXECUTION,
                    "Archive contains a pickle member; object loading can execute code",
                )
            if "config.json" not in names:
                return SerializationSafety.UNKNOWN, "Keras archive has no config.json"
            with archive.open("config.json") as member:
                raw = member.read(_MAX_KERAS_CONFIG_BYTES + 1)
        if len(raw) > _MAX_KERAS_CONFIG_BYTES:
            return over_budget
    except _InspectionBudgetError:
        return over_budget
    except (
        OSError,
        ValueError,
        OverflowError,
        RuntimeError,
        NotImplementedError,
        EOFError,
        RecursionError,
        zipfile.BadZipFile,
        zlib.error,
    ):
        return SerializationSafety.UNKNOWN, "Malformed or unsupported Keras archive"
    try:
        document = json.loads(raw, object_pairs_hook=_Members)
    except (ValueError, RecursionError):
        # Keras cannot load a configuration that json.loads rejects.
        return SerializationSafety.UNKNOWN, "Keras configuration is not loadable JSON"
    if _keras_config_executes(document):
        return (
            SerializationSafety.UNSAFE_CODE_EXECUTION,
            "Keras configuration carries a Lambda layer or a function outside Keras; "
            "loading can run that code",
        )
    return (
        SerializationSafety.UNKNOWN,
        "Keras configuration carries no Lambda layer or function outside Keras; loader "
        "behavior remains unverified",
    )


def _classify_hdf5(prefix: bytes, found: set[bytes]) -> tuple[SerializationSafety, str]:
    # Without an HDF5 parser the configuration cannot be read, so even a full model
    # stays unknown; the evidence tells the reviewer which loader question to ask.
    if _KERAS_MODEL_MARKER in found:
        return (
            SerializationSafety.UNKNOWN,
            "Keras HDF5 model configuration; Keras 3.0.0-3.11.2 run Lambda-layer code from it "
            "while loading, even in safe mode (CVE-2025-9905)",
        )
    if found:
        return SerializationSafety.UNKNOWN, "Keras HDF5 weights without a model configuration"
    if prefix.startswith(_HDF5_SIGNATURE):
        return SerializationSafety.UNKNOWN, _HDF5_UNMARKED
    return SerializationSafety.UNKNOWN, "No bounded structural validator for this format/loader"


def _recognized_binary_pickle(stream: BinaryIO, prefix: bytes, size: int) -> bool:
    """Recognize bounded binary pickle instructions without loading objects.

    PROTO alone is insufficient: valid tensor header lengths can have the same
    first byte. Static opcode/stack checks must reach STOP within local limits.
    This intentionally leaves unsupported, truncated and large samples unknown.
    """
    if len(prefix) < 2 or prefix[0] != 0x80 or not 2 <= prefix[1] <= 5:
        return False
    sample = prefix + stream.read(max(0, min(size, MAX_PICKLE_INSPECTION_BYTES) - len(prefix)))
    try:
        marks = 0
        for count, (opcode, _, _) in enumerate(pickletools.genops(sample), start=1):
            marks += opcode.name == "MARK"
            if count > 4096 or marks > 64:
                return False
        # dis() only checks opcode stack/memo consistency; it never resolves
        # globals, imports artifact code, invokes reducers or constructs objects.
        pickletools.dis(sample, out=io.StringIO())
    except (ValueError, UnicodeError, OverflowError, RecursionError):
        return False
    return True


def _tensor_span(entry: object, data_bytes: int) -> tuple[int, int]:
    if not isinstance(entry, dict) or set(entry) != {"dtype", "shape", "data_offsets"}:
        raise ValueError("Invalid tensor descriptor")
    dtype, shape, offsets = entry["dtype"], entry["shape"], entry["data_offsets"]
    if not isinstance(dtype, str) or dtype not in _DTYPE_BYTES:
        raise ValueError("Unsupported tensor dtype")
    if (
        not isinstance(shape, list)
        or len(shape) > 64
        or not all(type(n) is int and n >= 0 for n in shape)
    ):
        raise ValueError("Invalid tensor shape")
    if (
        not isinstance(offsets, list)
        or len(offsets) != 2
        or not all(type(n) is int and 0 <= n <= data_bytes for n in offsets)
    ):
        raise ValueError("Invalid tensor offsets")
    start, end = offsets
    elements = 1
    for dim in shape:
        elements *= dim
    if end < start or end - start != elements * _DTYPE_BYTES[dtype]:
        raise ValueError("Tensor shape and offsets disagree")
    return start, end


def _check_safetensors_header(header: dict[str, object], data_bytes: int) -> None:
    spans: list[tuple[int, int]] = []
    for name, entry in header.items():
        if name == "__metadata__":
            if not isinstance(entry, dict) or not all(
                isinstance(k, str) and isinstance(v, str) for k, v in entry.items()
            ):
                raise ValueError("Invalid SafeTensors metadata")
            continue
        spans.append(_tensor_span(entry, data_bytes))
    cursor = 0
    for start, end in sorted(spans):
        if start != cursor:
            raise ValueError("Tensor buffer contains holes or overlaps")
        cursor = end
    if cursor != data_bytes:
        raise ValueError("Tensor buffer is not fully indexed")


def inspect_model_format(
    path: Path, *, stream: BinaryIO | None = None
) -> tuple[SerializationSafety, str]:
    """Inspect bounded structure without deserializing a model or running code.

    SAFE means the checked file has a supported non-executable tensor container
    layout. It is not a claim about model behavior, parser vulnerabilities,
    adjacent repository code, or the safety of the eventual loader.
    """
    if _name_suffix(path) in _UNSAFE_SUFFIXES or _compressed_pickle(path):
        return SerializationSafety.UNSAFE_CODE_EXECUTION, "Potential code-executing loader format"
    try:
        context = nullcontext(stream) if stream is not None else open_regular_file(path)
        with context as opened:
            size = os.fstat(opened.fileno()).st_size
            prefix = opened.read(8)
            length = int.from_bytes(prefix, "little")
            tensor_candidate = (
                path.suffix.lower() == ".safetensors"
                and len(prefix) == 8
                and 2 <= length <= min(MAX_MODEL_HEADER_BYTES, size - 8)
            )
            if not tensor_candidate and _recognized_binary_pickle(opened, prefix, size):
                return (
                    SerializationSafety.UNSAFE_CODE_EXECUTION,
                    "Recognized binary pickle opcode stream; object loading can execute code",
                )
            if path.suffix.lower() != ".safetensors":
                return (
                    SerializationSafety.UNKNOWN,
                    "No bounded structural validator for this format/loader",
                )
            if len(prefix) != 8:
                raise ValueError("Missing SafeTensors header length")
            if not 2 <= length <= MAX_MODEL_HEADER_BYTES or length > size - 8:
                raise ValueError("Invalid or over-limit SafeTensors header length")
            raw_header = opened.read(length)
            if len(raw_header) != length or not raw_header.startswith(b"{"):
                raise ValueError("Invalid SafeTensors header")
            header = parse_json_strict(raw_header, max_bytes=MAX_MODEL_HEADER_BYTES)
            if not isinstance(header, dict):
                raise ValueError("SafeTensors header must be an object")
            _check_safetensors_header(header, size - 8 - length)
        return SerializationSafety.SAFE, "Bounded SafeTensors header, shapes and offsets checked"
    except (OSError, ValueError, RecursionError, UnicodeError):
        return SerializationSafety.UNKNOWN, "Malformed or unsupported SafeTensors structure"


class _HashingModelReader:
    """Hash the inspected prefix and remaining bytes from one pinned stream."""

    def __init__(self, stream: BinaryIO, markers: Sequence[bytes] = ()) -> None:
        self.stream = stream
        self.digest = hashlib.sha256()
        self.bytes_read = 0
        self.prefix = bytearray()
        self.markers = tuple(markers)
        self.found: set[bytes] = set()
        self._overlap = max((len(marker) for marker in self.markers), default=1) - 1
        self._tail = b""

    def fileno(self) -> int:
        return self.stream.fileno()

    def read(self, size: int) -> bytes:
        if self.bytes_read > MAX_HASH_SIZE:
            raise OSError("model artifact exceeds the hash byte limit")
        content = self.stream.read(min(size, MAX_HASH_SIZE + 1 - self.bytes_read))
        self.bytes_read += len(content)
        if self.bytes_read > MAX_HASH_SIZE:
            raise OSError("model artifact exceeds the hash byte limit")
        self.digest.update(content)
        self.prefix.extend(content[: max(0, MAX_MODEL_HEADER_BYTES + 8 - len(self.prefix))])
        if self.markers and content:
            window = self._tail + content
            self.found.update(marker for marker in self.markers if marker in window)
            self._tail = window[-self._overlap :] if self._overlap else b""
        return content


def inspect_model_artifact(
    path: Path, *, stream: BinaryIO, metadata: dict[str, str] | None = None
) -> tuple[SerializationSafety, str, str]:
    """Bind structural inspection and SHA-256 to the same opened artifact.

    The caller must hold a confined regular-file context.
    A pathname replacement cannot substitute different bytes between inspection
    and hashing because neither operation reopens that pathname. The confined
    stream also refuses the observation unless the pathname still resolves to
    this descriptor when the caller's read ends, so the verdict and digest are
    never attributed to a pathname that now names other bytes.
    """
    before = os.fstat(stream.fileno())
    if before.st_size > MAX_HASH_SIZE:
        raise OSError("model artifact exceeds the hash byte limit")
    suffix = _name_suffix(path)
    observed = _HashingModelReader(stream, _KERAS_MARKERS if suffix in _HDF5_SUFFIXES else ())
    safety, explanation = inspect_model_format(path, stream=cast(BinaryIO, observed))
    while observed.read(65536):
        pass
    if safety == SerializationSafety.UNKNOWN and suffix in _HDF5_SUFFIXES:
        safety, explanation = _classify_hdf5(bytes(observed.prefix[:8]), observed.found)
    elif safety == SerializationSafety.UNKNOWN and suffix == ".keras":
        safety, explanation = _inspect_keras_archive(stream)
    if metadata is not None and safety == SerializationSafety.SAFE:
        metadata.update(
            fingerprint_stream(io.BytesIO(observed.prefix), artifact_size=before.st_size)
        )
    after = os.fstat(stream.fileno())
    if descriptor_binding(before) != descriptor_binding(after):
        raise OSError("model artifact changed during inspection and hashing")
    return safety, explanation, "sha256:" + observed.digest.hexdigest()


def safetensors_fingerprint(
    path: Path, *, root: Path, expected_digest: str | None = None
) -> dict[str, str]:
    """Bind metadata and complete-file hash to one confined artifact observation."""
    metadata: dict[str, str] = {}
    with (
        ConfinedCollection(root, [], max_total_bytes=MAX_HASH_BYTES) as files,
        files.open_regular(path, max_bytes=MAX_HASH_BYTES) as stream,
    ):
        safety, _, digest = inspect_model_artifact(path, stream=stream, metadata=metadata)
    if safety != SerializationSafety.SAFE or not metadata:
        raise ValueError("SafeTensors metadata could not be corroborated")
    if expected_digest is not None and expected_digest != digest:
        raise ValueError("Tensor metadata belongs to different artifact bytes")
    return metadata


class ModelScanner(Scanner):
    name = "model"

    def __init__(self, signature_policies: Sequence[SigstoreArtifactPolicy] = ()) -> None:
        self._signature_policies = {p.artifact_path.resolve(): p for p in signature_policies}
        self._discovered_paths: tuple[Path, ...] = ()
        if len(self._signature_policies) != len(signature_policies):
            raise ValueError("Duplicate artifact signature policies")

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        checked_policies: set[SigstoreArtifactPolicy] = set()
        # One deterministic walk and one aggregate budget for all model/config
        # reads. Large weights are streamed; metadata remains capped at four MiB.
        with self._collection(
            project_root, result, max_total_bytes=MAX_HASH_SIZE + 32 * 1024 * 1024
        ) as files:
            self._discovered_paths = tuple(files.root / path for path in files.iter_files())
            model_dirs = sorted(
                {path.parent for path in self._discovered_paths if model_format(path) is not None}
            )
            if not model_dirs and not result.scan_failures and not result.surfaces_excluded:
                result.surfaces_scanned.append("model-weights (no model files found)")
            for model_dir in model_dirs:
                result.surfaces_scanned.append(str(model_dir))
                result.components.extend(self._scan_model_directory(model_dir, checked_policies))
        result.scan_failures.extend(
            signature_policy.unmatched_policy_entries(
                self._signature_policies.values(), checked_policies
            )
        )
        return result

    def _scan_model_directory(
        self, model_dir: Path, checked_policies: set[SigstoreArtifactPolicy]
    ) -> list[ModelComponent]:
        components: list[ModelComponent] = []
        model_name = model_dir.name

        formats = {
            detected[0]
            for path in self._discovered_paths
            if path.parent == model_dir and (detected := model_format(path)) is not None
        }
        # An HDF5 file is often a dataset; a JSON list beside it is not a model claim.
        config = self._read_model_config(model_dir, strict=formats != {"hdf5"})
        tokenizer_hash = self._hash_tokenizer(model_dir)
        chat_template_hash = self._hash_chat_template(model_dir, config)

        if self._files is None:
            raise RuntimeError("_scan_model_directory called outside a _collection context")
        for path in self._discovered_paths:
            if path.parent != model_dir:
                continue
            detected = model_format(path)
            if detected is None:
                continue

            fmt_key, fmt_name = detected
            fingerprint: dict[str, str] = {}
            try:
                with self._files.open_regular(path, max_bytes=MAX_HASH_SIZE) as stream:
                    safety, format_evidence, weight_hash = inspect_model_artifact(
                        path, stream=stream, metadata=fingerprint
                    )
            except (OSError, ValueError):
                self._files._fail(path, "model inspection or hashing failed")
                safety, format_evidence = (
                    SerializationSafety.UNKNOWN,
                    "Artifact could not be inspected",
                )
                weight_hash = None
                fingerprint.clear()

            signing_status, signing_identity = self._check_signing(
                path, weight_hash, checked_policies
            )
            if signing_status == "verification-failed":
                self._files._fail(
                    path.relative_to(self._files.root),
                    "explicit signature policy verification failed",
                )
            risks = self._assess_model_risks(path, fmt_key, safety, signing_status, config)

            trust_tier = TrustTier.UNKNOWN
            if signing_status == "sigstore-signed":
                trust_tier = TrustTier.THIRD_PARTY_SIGNED

            model_type = self._infer_model_type(config, path)
            derivation = config.get("peft_type") if config else None
            quant = (
                (config.get("quantization_method") or config.get("quant_method"))
                if config
                else None
            )
            configured_remote_code = config.get("trust_remote_code") if config else None
            trust_remote_code = (
                configured_remote_code if isinstance(configured_remote_code, bool) else None
            )

            subject = (
                path.relative_to(self._files.root).as_posix()
                if fmt_key in _PATH_SUBJECT_FORMATS or not path.suffix
                else f"{model_name}/{path.name}"
            )
            comp = ModelComponent(
                bom_ref=f"model:{subject}",
                name=subject,
                serialization_format=fmt_name,
                serialization_safety=safety,
                signing_status=signing_status,
                signing_identity=signing_identity,
                properties={"format_inspection": format_evidence},
                model_type=model_type,
                derivation_type=derivation,
                quantization_method=quant,
                trust_remote_code=trust_remote_code,
                tokenizer_hash=tokenizer_hash,
                chat_template_hash=chat_template_hash,
                tensor_inventory_hash=fingerprint.get("tensor_inventory_sha256"),
                safetensors_header_hash=fingerprint.get("safetensors_header_sha256"),
                hashes={"sha256": weight_hash} if weight_hash else {},
                source_path=str(path),
                trust_tier=trust_tier,
                risks=risks,
            )
            components.append(comp)

        return components

    def _read_model_config(self, model_dir: Path, *, strict: bool = True) -> dict[str, Any] | None:
        if self._files is None:
            raise RuntimeError("_read_model_config called outside a _collection context")
        for cfg_name in MODEL_CONFIG_FILES:
            cfg_path = model_dir / cfg_name
            if cfg_path in self._discovered_paths:
                data = self._files.read_json(cfg_path)
                if data is not None and not isinstance(data, dict):
                    if strict:
                        self._files._fail(cfg_path, "model configuration must be an object")
                    continue
                if isinstance(data, dict):
                    invalid_fields = [
                        key
                        for key in ("peft_type", "quantization_method", "quant_method")
                        if data.get(key) is not None and not isinstance(data[key], str)
                    ]
                    if data.get("trust_remote_code") is not None and not isinstance(
                        data["trust_remote_code"], bool
                    ):
                        invalid_fields.append("trust_remote_code")
                    if invalid_fields:
                        self._files._fail(
                            cfg_path,
                            "invalid model configuration field type: "
                            + ", ".join(sorted(invalid_fields)),
                        )
                        # Retain the artifact inventory while refusing the invalid
                        # claims. Diagnostics contain schema field names only.
                        data = {k: v for k, v in data.items() if k not in invalid_fields}
                    return data
        return None

    def _check_signing(
        self, artifact: Path, weight_hash: str | None, checked_policies: set[SigstoreArtifactPolicy]
    ) -> tuple[str, str | None]:
        policy = self._signature_policies.get(artifact.resolve())
        if policy is not None:
            checked_policies.add(policy)
            if weight_hash is None:
                return "verification-failed", None
            result = verify_sigstore_bundle(
                artifact, policy.bundle_path, policy.expected_identity, policy.expected_issuer
            )
            if (
                result.verified
                and result.identity == policy.expected_identity
                and result.issuer == policy.expected_issuer
                and result.details
                and result.details.get("artifact_digest") == weight_hash
            ):
                return "sigstore-signed", result.identity
            return "verification-failed", None
        # An adjacent file is a discovery fact, never proof of a signature.
        if any(artifact.parent / name in self._discovered_paths for name in SIGNING_FILES):
            return "signature-present-unverified", None
        # A directory-local search cannot prove the absence of external signatures.
        return "signature-not-found", None

    def _hash_tokenizer(self, model_dir: Path) -> str | None:
        for name in ("tokenizer.json", "tokenizer.model", "spiece.model"):
            path = model_dir / name
            if path in self._discovered_paths and self._files is not None:
                return self._files.hash_file(path)
        return None

    def _hash_chat_template(self, model_dir: Path, config: dict[str, Any] | None) -> str | None:
        if config and "chat_template" in config:
            from nexus_symbiote.core.hashing import hash_bytes

            template = config["chat_template"]
            if isinstance(template, str):
                return hash_bytes(template.encode("utf-8"))
        jinja_path = model_dir / "chat_template.jinja2"
        if jinja_path in self._discovered_paths and self._files is not None:
            return self._files.hash_file(jinja_path)
        return None

    def _infer_model_type(self, config: dict[str, Any] | None, path: Path) -> str:
        if config:
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
        config: dict[str, Any] | None,
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

        if safety == SerializationSafety.UNSAFE_TEMPLATE_INJECTION:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="serialization_format",
                    detail=f"Model '{path.name}' uses GGUF; chat template metadata vulnerable to Jinja2 SSTI (CVE-2024-34359).",
                    recommendation="Validate chat template content. Use llama-cpp-python >= 0.2.72.",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2024-34359"],
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

        if signing_status != "sigstore-signed":
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.HIGH,
                    category="signing_status",
                    detail=f"Model '{path.name}' has no verified artifact-bound signature ({signing_status}).",
                    recommendation="Sign with OpenSSF Model Signing (Sigstore).",
                    references=[
                        "https://openssf.org/blog/2025/04/04/launch-of-model-signing-v1-0-openssf-ai-ml-working-group-secures-the-machine-learning-supply-chain/"
                    ],
                )
            )

        if config and config.get("trust_remote_code") is True:
            risks.append(
                RiskAssessment(
                    severity=RiskSeverity.CRITICAL,
                    category="code_execution",
                    detail="trust_remote_code=True allows arbitrary code from the model repository.",
                    recommendation="Audit remote code or use a model that does not require it.",
                )
            )

        return risks
