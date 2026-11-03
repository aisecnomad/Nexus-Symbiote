"""Model weight scanner.

Discovers ML models in a project, classifies serialization format safety,
checks for model signing, and computes weight hashes.
"""

from __future__ import annotations

import hashlib
import io
import os
import pickletools
from collections.abc import Sequence
from contextlib import nullcontext
from pathlib import Path
from typing import Any, BinaryIO, cast

from nexus_symbiote.core.enums import (
    RiskSeverity,
    SerializationSafety,
    TrustTier,
)
from nexus_symbiote.core.hashing import file_invariance, open_regular_file, parse_json_strict
from nexus_symbiote.core.models import ModelComponent, RiskAssessment
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.utils.crypto import SigstoreArtifactPolicy, verify_sigstore_bundle

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
}

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
_UNSAFE_SUFFIXES = {".pickle", ".pkl", ".pt", ".pth", ".bin", ".joblib"}


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
    if path.suffix.lower() in _UNSAFE_SUFFIXES:
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

    def __init__(self, stream: BinaryIO) -> None:
        self.stream = stream
        self.digest = hashlib.sha256()
        self.bytes_read = 0
        self.prefix = bytearray()

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
        return content


def inspect_model_artifact(
    path: Path, *, stream: BinaryIO, metadata: dict[str, str] | None = None
) -> tuple[SerializationSafety, str, str]:
    """Bind structural inspection and SHA-256 to the same opened artifact.

    The caller must hold a confined regular-file context.
    A pathname replacement cannot substitute different bytes between inspection
    and hashing because neither operation reopens that pathname. The pinned
    descriptor's invariance (including link count) is rechecked after hashing:
    on filesystems that do not refresh change time on rename-over, the unlink
    still drops the link count and the substitution is refused.
    """
    before = os.fstat(stream.fileno())
    if before.st_size > MAX_HASH_SIZE:
        raise OSError("model artifact exceeds the hash byte limit")
    observed = _HashingModelReader(stream)
    safety, explanation = inspect_model_format(path, stream=cast(BinaryIO, observed))
    while observed.read(65536):
        pass
    if metadata is not None and safety == SerializationSafety.SAFE:
        from nexus_symbiote.utils.tensors import fingerprint_stream

        metadata.update(
            fingerprint_stream(io.BytesIO(observed.prefix), artifact_size=before.st_size)
        )
    after = os.fstat(stream.fileno())
    if file_invariance(before) != file_invariance(after):
        raise OSError("model artifact changed during inspection and hashing")
    return safety, explanation, "sha256:" + observed.digest.hexdigest()


class ModelScanner(Scanner):
    name = "model"

    def __init__(self, signature_policies: Sequence[SigstoreArtifactPolicy] = ()) -> None:
        self._signature_policies = {p.artifact_path.resolve(): p for p in signature_policies}
        self._discovered_paths: tuple[Path, ...] = ()
        if len(self._signature_policies) != len(signature_policies):
            raise ValueError("Duplicate artifact signature policies")

    def scan(self, project_root: Path) -> ScanResult:
        result = ScanResult(scanner_name=self.name)
        # One deterministic walk and one aggregate budget for all model/config
        # reads. Large weights are streamed; metadata remains capped at four MiB.
        with self._collection(
            project_root, result, max_total_bytes=MAX_HASH_SIZE + 32 * 1024 * 1024
        ) as files:
            self._discovered_paths = tuple(files.root / path for path in files.iter_files())
            model_dirs = sorted(
                {
                    path.parent
                    for path in self._discovered_paths
                    if path.suffix.lower() in MODEL_EXTENSIONS
                }
            )
            if not model_dirs and not result.scan_failures and not result.surfaces_excluded:
                result.surfaces_scanned.append("model-weights (no model files found)")
            for model_dir in model_dirs:
                result.surfaces_scanned.append(str(model_dir))
                result.components.extend(self._scan_model_directory(model_dir))
        return result

    def _scan_model_directory(self, model_dir: Path) -> list[ModelComponent]:
        components: list[ModelComponent] = []
        model_name = model_dir.name

        config = self._read_model_config(model_dir)
        tokenizer_hash = self._hash_tokenizer(model_dir)
        chat_template_hash = self._hash_chat_template(model_dir, config)

        if self._files is None:
            raise RuntimeError("_scan_model_directory called outside a _collection context")
        for path in self._discovered_paths:
            if path.parent != model_dir:
                continue
            ext = path.suffix.lower()
            if ext not in MODEL_EXTENSIONS:
                continue

            fmt_key, fmt_name = MODEL_EXTENSIONS[ext]
            fingerprint: dict[str, str] = {}
            try:
                identity_before = self._files.path_identity(path)
                with self._files.open_regular(path, max_bytes=MAX_HASH_SIZE) as stream:
                    safety, format_evidence, weight_hash = inspect_model_artifact(
                        path, stream=stream, metadata=fingerprint
                    )
                    identity_after = self._files.path_identity(path)
                if identity_before is None or identity_after != identity_before:
                    raise OSError("model artifact replaced or renamed during scanning")
            except (OSError, ValueError):
                self._files._fail(path, "model inspection or hashing failed")
                safety, format_evidence = (
                    SerializationSafety.UNKNOWN,
                    "Artifact could not be inspected",
                )
                weight_hash = None
                fingerprint.clear()

            signing_status, signing_identity = self._check_signing(path, weight_hash)
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

            comp = ModelComponent(
                bom_ref=f"model:{model_name}/{path.name}",
                name=f"{model_name}/{path.name}",
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

    def _read_model_config(self, model_dir: Path) -> dict[str, Any] | None:
        if self._files is None:
            raise RuntimeError("_read_model_config called outside a _collection context")
        for cfg_name in MODEL_CONFIG_FILES:
            cfg_path = model_dir / cfg_name
            if cfg_path in self._discovered_paths:
                data = self._files.read_json(cfg_path)
                if data is not None and not isinstance(data, dict):
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

    def _check_signing(self, artifact: Path, weight_hash: str | None) -> tuple[str, str | None]:
        policy = self._signature_policies.get(artifact.resolve())
        if policy is not None:
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
