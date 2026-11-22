"""GitHub Action entry point: inputs are data, and exports share one collection.

Everything this script prints reaches the job log, where the runner acts on workflow
commands: "::name::" at the start of a line and "##[name]" anywhere in one. Text from
the scanned checkout is therefore printed only inside a stop-commands block with a
random token, neutralized and behind a fixed prefix. Every declared output is written
to GITHUB_OUTPUT before collection starts, and that file is applied after the step,
so a command printed during the step could not set an output in any case.
"""

from __future__ import annotations

import functools
import hashlib
import importlib
import json
import math
import os
import re
import secrets
import subprocess
import sys
import tempfile
from collections.abc import Callable, Iterable, Mapping
from contextlib import suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SCANNERS = frozenset(
    {"shadowscan", "mcp", "model", "prompt", "rag", "registry", "a2a", "ide_agents"}
)
FORMATS = frozenset({"json", "cyclonedx", "spdx", "sarif"})
SIGSTORE_MODULES = (
    "sigstore.hashes",
    "sigstore.models",
    "sigstore.verify",
    "sigstore.verify.policy",
    "sigstore_models.common.v1",
)
GATES = ("collection", "completeness", "integrity", "risk", "drift")
THRESHOLD = re.compile(r"(?:0|[1-9][0-9]{0,2})(?:\.[0-9]{1,4})?")
MAX_BASELINE_BYTES = 16 * 1024 * 1024
MAX_LIMITS_LENGTH = 1024
LIMITS_ENV = "NEXUS_SYMBIOTE_LIMITS"
TRUST_ROOT_ENVS = (
    "NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT",
    "NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256",
)
WITHHELD_ENV = (
    "NEXUS_SYMBIOTE_MODE",
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
    "ACTIONS_RUNTIME_TOKEN",
    "ACTIONS_RUNTIME_URL",
    "ACTIONS_RESULTS_URL",
    "ACTIONS_CACHE_URL",
    "GITHUB_TOKEN",
    "GH_TOKEN",
)
RELAY_PREFIX = "| "


class InputError(ValueError):
    """An invalid Action input. The message is fixed text, safe to print."""


class ActionError(ValueError):
    """A gate that could not be evaluated. The message is fixed text, safe to print."""


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _neutralize(text: object) -> str:
    from nexus_symbiote.utils.terminal import neutralize

    return neutralize(text)


def _command_data(text: object) -> str:
    # The runner decodes %0A and the like in a command's data, so escape them first.
    return _neutralize(text).replace("%", "%25")


def _annotate(kind: str, text: str) -> None:
    _say(f"::{kind} title=Nexus SymBiote::{_command_data(text)}")


def _relay(label: str, lines: Iterable[str]) -> None:
    """Print untrusted lines so that the runner acts on none of them.

    A stop-commands block with an unguessable token disables both workflow command
    forms until the token appears again; neutralization and a fixed prefix hold even
    where a runner ignores the block.
    """
    shown = [RELAY_PREFIX + _neutralize(line) for line in lines]
    if not shown:
        return
    _say(f"{label}:")
    token = secrets.token_hex(16)
    _say(f"::stop-commands::{token}")
    for line in shown:
        _say(line)
    _say(f"::{token}::")


def _process_lines(*streams: str | None) -> list[str]:
    return [line for stream in streams if stream for line in stream.splitlines()]


def _boolean(value: str, name: str) -> bool:
    if value not in {"true", "false"}:
        raise InputError(f"{name} must be true or false")
    return value == "true"


def _within(workspace: Path, value: str, name: str) -> Path:
    if not value or any(c in value for c in "\r\n\x00"):
        raise InputError(f"{name} must be nonempty and contain no newline or NUL")
    path = (workspace / value).absolute()
    if (
        ".." in path.parts
        or not path.is_relative_to(workspace)
        or not path.resolve().is_relative_to(workspace)
    ):
        raise InputError(f"{name} must stay within GITHUB_WORKSPACE")
    if Path(os.path.normpath(path)) != path.resolve():
        # The checkout decides which names inside the workspace are links, so a linked
        # path would let the code under review choose what is collected or written.
        raise InputError(f"{name} must not pass through a symbolic link")
    return path


def _caller_owned(
    workspace: Path, value: str, name: str, limit: int, *, trust_anchor: bool = False
) -> bytes:
    from nexus_symbiote.core.hashing import open_regular_file
    from nexus_symbiote.signature_policy import _repository_roots

    outside = f"{name} must be an absolute path outside GITHUB_WORKSPACE"
    untrusted = [workspace, *_repository_roots(workspace)] if trust_anchor else [workspace]
    path = Path(value)
    if (
        any(c in value for c in "\r\n\x00")
        or not path.is_absolute()
        or ".." in path.parts
        or any(path.is_relative_to(root) for root in untrusted)
    ):
        raise InputError(outside)
    try:
        # No-follow traversal makes the literal path the real one. Comparing its
        # ancestors' device and inode with the workspace also catches aliases
        # that a lexical check misses: case-insensitive names and bind mounts.
        with open_regular_file(path) as stream:
            info = os.fstat(stream.fileno())
            ancestors = {(s.st_dev, s.st_ino) for s in map(os.stat, path.parents)}
            untrusted_ids = {(s.st_dev, s.st_ino) for s in map(os.stat, untrusted)}
            if untrusted_ids & ancestors:
                raise InputError(outside)
            if info.st_nlink != 1:
                raise InputError(
                    f"{name} must not be a hard link, which can alias a workspace file"
                )
            if trust_anchor:
                from nexus_symbiote.utils.crypto import _trust_anchor_error

                if (reason := _trust_anchor_error(path, info)) is not None:
                    raise InputError(f"{name} {reason}")
            content = stream.read(limit + 1)
    except OSError:
        raise InputError(f"{name} must be a regular file reached without symlinks") from None
    if len(content) > limit:
        raise InputError(f"{name} exceeds the byte limit")
    return content


def _require_sigstore() -> None:
    # Without sigstore every signature would fail verification after a full
    # scan, so a supplied policy would silently change nothing.
    try:
        for module in SIGSTORE_MODULES:
            importlib.import_module(module)
    except ImportError:
        raise InputError(
            "signature-policy needs sigstore, which this Action runtime cannot import"
        ) from None


def _default_exclusions(raw: str) -> bool | tuple[str, ...]:
    from nexus_symbiote.utils.confined import DEFAULT_EXCLUDE_ACCEPTANCE

    value = raw.strip().lower()
    if value in {"true", "false"}:
        return value == "true"
    names = tuple(dict.fromkeys(part.strip() for part in value.split(",") if part.strip()))
    if not set(names) <= DEFAULT_EXCLUDE_ACCEPTANCE:
        raise InputError("accept-default-excludes must name only built-in exclusions")
    return names


@dataclass(frozen=True)
class Config:
    workspace: Path
    project: Path
    output: Path
    format: str
    scanners: tuple[str, ...]
    validate: bool
    risk_check: bool
    threshold: float
    sarif: bool
    signature_policy: bytes | None = field(default=None, repr=False)
    integrity: bool = True
    limits: str = ""
    baseline: bytes | None = field(default=None, repr=False)
    allow_unsigned_discovery: bool = False
    accept_default_excludes: bool | tuple[str, ...] = False
    fail_on_severity: str = "high"
    binding_key: str = field(default="", repr=False)
    scratch_parent: Path | None = None
    baseline_attestation: bytes | None = field(default=None, repr=False)
    trusted_verifiers: tuple[Path, ...] = field(default=(), repr=False)
    attest: bool = False
    trusted_verifier_contents: tuple[bytes, ...] = field(default=(), repr=False)

    @classmethod
    def from_env(cls, env: Mapping[str, str]) -> Config:
        try:
            workspace = Path(env["GITHUB_WORKSPACE"]).resolve(strict=True)
        except (KeyError, OSError):
            raise InputError("GITHUB_WORKSPACE must name the checked-out workspace") from None
        project = _within(workspace, env.get("SYMBIOTE_SCAN_PATH", "."), "scan-path")
        if not project.is_dir():
            raise InputError("scan-path must be an existing directory")
        output_value = env.get("SYMBIOTE_OUTPUT_FILE", "nexus-symbiote-aibom.json")
        if any(c in output_value for c in "*?[]!"):
            raise InputError("output-file must be a literal artifact path without glob syntax")
        output = _within(workspace, output_value, "output-file")
        fmt = env.get("SYMBIOTE_FORMAT", "json")
        if fmt not in FORMATS:
            raise InputError("unsupported output format")
        scanners = tuple(
            s.strip() for s in env.get("SYMBIOTE_SCANNERS", "").split(",") if s.strip()
        )
        if len(scanners) != len(set(scanners)) or set(scanners) - SCANNERS:
            raise InputError("scanners must be distinct supported names")
        raw = env.get("SYMBIOTE_RISK_THRESHOLD", "50")
        if not THRESHOLD.fullmatch(raw) or float(raw) > 100:
            raise InputError("risk-threshold must be a decimal number from 0 to 100, such as 50")
        threshold = float(raw)
        severity = env.get("SYMBIOTE_FAIL_ON_SEVERITY", "high")
        if severity not in {"critical", "high", "medium", "low", "info", "none"}:
            raise InputError("fail-on-severity must be critical, high, medium, low, info or none")
        limits = env.get("SYMBIOTE_LIMITS", "")
        if len(limits) > MAX_LIMITS_LENGTH or any(c in limits for c in "\r\n\x00"):
            raise InputError("limits must be one line of NAME=VALUE pairs separated by commas")
        _boolean(env.get("SYMBIOTE_UPLOAD_ARTIFACT", "true"), "upload-artifact")
        attest = _boolean(env.get("SYMBIOTE_ATTEST", "false"), "attest")
        from nexus_symbiote.signature_policy import MAX_POLICY_BYTES

        policy = env.get("SYMBIOTE_SIGNATURE_POLICY", "")
        signers = (
            _caller_owned(
                workspace, policy, "signature-policy", MAX_POLICY_BYTES, trust_anchor=True
            )
            if policy
            else None
        )
        if signers is not None:
            _require_sigstore()
        reviewed = env.get("SYMBIOTE_REVIEWED_BASELINE", "")
        baseline = (
            _caller_owned(
                workspace, reviewed, "reviewed-baseline", MAX_BASELINE_BYTES, trust_anchor=True
            )
            if reviewed
            else None
        )
        raw_attestation = env.get("SYMBIOTE_REVIEWED_BASELINE_ATTESTATION", "")
        raw_verifiers_input = env.get("SYMBIOTE_TRUSTED_KEYS", "")
        if "\x00" in raw_verifiers_input:
            raise InputError("trusted-keys must not contain NUL")
        raw_verifiers = tuple(
            v for part in raw_verifiers_input.replace("\n", ",").split(",") if (v := part.strip())
        )
        if raw_attestation and baseline is None:
            raise InputError("reviewed-baseline-attestation requires reviewed-baseline")
        if raw_verifiers and not raw_attestation:
            raise InputError("trusted-keys requires reviewed-baseline-attestation")
        if raw_attestation and not raw_verifiers:
            raise InputError("reviewed-baseline-attestation requires trusted-keys")
        baseline_attestation: bytes | None = None
        trusted_verifiers: tuple[Path, ...] = ()
        trusted_verifier_contents: tuple[bytes, ...] = ()
        if raw_attestation:
            from nexus_symbiote.attestation import MAX_ENVELOPE_BYTES
            from nexus_symbiote.runtime_cli import MAX_KEY_BYTES

            baseline_attestation = _caller_owned(
                workspace,
                raw_attestation,
                "reviewed-baseline-attestation",
                MAX_ENVELOPE_BYTES,
                trust_anchor=True,
            )
            trusted_verifier_contents = tuple(
                _caller_owned(
                    workspace, verifier_rel, "trusted-keys", MAX_KEY_BYTES, trust_anchor=True
                )
                for verifier_rel in raw_verifiers
            )
            trusted_verifiers = tuple(Path(verifier_rel) for verifier_rel in raw_verifiers)
        from nexus_symbiote.scanners.mcp import (
            _MIN_SOURCE_BINDING_KEY_LENGTH,
            SOURCE_BINDING_KEY_ENV,
        )

        supplied_key = env.get("SYMBIOTE_SOURCE_BINDING_KEY", "")
        inherited_key = env.get(SOURCE_BINDING_KEY_ENV, "")
        if supplied_key and (
            len(supplied_key) < _MIN_SOURCE_BINDING_KEY_LENGTH
            or any(c in supplied_key for c in "\r\n\x00")
        ):
            raise InputError(
                "source-binding-key must be one line of at least "
                f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters"
            )
        effective_key = supplied_key or inherited_key
        if baseline is not None and len(effective_key) < _MIN_SOURCE_BINDING_KEY_LENGTH:
            raise InputError(
                "reviewed-baseline needs a source binding key of at least "
                f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters (source-binding-key or "
                f"{SOURCE_BINDING_KEY_ENV}): without it MCP launch arguments, environment "
                "values and endpoint paths are not compared"
            )
        validate = _boolean(env.get("SYMBIOTE_VALIDATE", "true"), "validate")
        risk_check = _boolean(env.get("SYMBIOTE_RISK_CHECK", "true"), "risk-check")
        if (validate or risk_check) and scanners and set(scanners) != SCANNERS:
            # Either gate fails on partial coverage, so the run could only fail later.
            raise InputError(
                "scanners subset requires validate and risk-check to be false, because "
                "both gates require all built-in collectors"
            )
        # A TMPDIR inside the checkout would put the policy snapshot inside the
        # repository it guards, which the CLI refuses; the runner's own temp is outside.
        runner_temp = Path(env.get("RUNNER_TEMP", ""))
        scratch_parent = runner_temp if runner_temp.is_absolute() and runner_temp.is_dir() else None
        return cls(
            workspace,
            project,
            output,
            fmt,
            scanners,
            validate,
            risk_check,
            threshold,
            _boolean(env.get("SYMBIOTE_SARIF", "false"), "sarif-upload"),
            signers,
            _boolean(env.get("SYMBIOTE_VALIDATE_INTEGRITY", "true"), "validate-integrity"),
            limits,
            baseline,
            _boolean(
                env.get("SYMBIOTE_ALLOW_UNSIGNED_DISCOVERY", "false"), "allow-unsigned-discovery"
            ),
            _default_exclusions(env.get("SYMBIOTE_ACCEPT_DEFAULT_EXCLUDES", "false")),
            severity,
            supplied_key,
            scratch_parent,
            baseline_attestation,
            trusted_verifiers,
            attest,
            trusted_verifier_contents,
        )


def _scratch_parent(config: Config) -> Path | None:
    if (
        config.signature_policy is None
        and getattr(config, "baseline", None) is None
        and getattr(config, "baseline_attestation", None) is None
    ):
        return config.scratch_parent

    from nexus_symbiote.signature_policy import _repository_roots
    from nexus_symbiote.utils.crypto import _trust_anchor_error

    candidates = [config.scratch_parent] if config.scratch_parent is not None else []
    with suppress(OSError):
        candidates.append(Path(tempfile.gettempdir()))
    if os.name == "posix":
        # Apply the same ownership and sticky-bit checks to the system fallback.
        candidates.append(Path("/tmp"))  # noqa: S108
    untrusted = (config.workspace, *_repository_roots(config.workspace))
    for candidate in dict.fromkeys(candidates):
        try:
            directory = candidate.resolve(strict=True)
        except (OSError, RuntimeError):
            continue
        if any(directory.is_relative_to(root) for root in untrusted):
            continue
        if _trust_anchor_error(directory, None) is None and os.access(directory, os.W_OK | os.X_OK):
            return directory
    owner_input = (
        "signature-policy"
        if config.signature_policy is not None
        else (
            "reviewed-baseline-attestation"
            if getattr(config, "baseline_attestation", None) is not None
            else "reviewed-baseline"
        )
    )
    raise ActionError(
        f"{owner_input} needs a writable temporary directory with trusted ancestors outside the project and its repositories"
    )


def _run(
    args: list[str], *, private: Path, limits: str = "", binding_key: str = ""
) -> subprocess.CompletedProcess[str]:
    # Offline Sigstore verification trusts any trusted_root.json in the per-user
    # cache without checking it, and an earlier job or step can plant one there.
    # An empty private home makes sigstore seed it from its hash-locked package.
    env = {
        **os.environ,
        "HOME": str(private),
        "XDG_CACHE_HOME": str(private / "cache"),
        "XDG_DATA_HOME": str(private / "data"),
    }
    # Collection limits come only from the limits input, never from the job environment,
    # and the Sigstore trust root only from the hash-locked sigstore package: an explicit
    # trust root in the job environment would let an earlier step choose the authorities.
    env.pop(LIMITS_ENV, None)
    # These commands run offline whatever NEXUS_SYMBIOTE_MODE says; a job-level value
    # could only fail them. Remove these named runner and OIDC credential variables from
    # children; other variables, including custom secrets and the source-binding key,
    # can remain, and a child running as the same user can still read this process's
    # environment. This filtering is not a process sandbox.
    for name in (*TRUST_ROOT_ENVS, *WITHHELD_ENV):
        env.pop(name, None)
    if limits:
        env[LIMITS_ENV] = limits
    # An explicit input replaces a key inherited from the job. An empty input does not.
    if binding_key:
        from nexus_symbiote.scanners.mcp import SOURCE_BINDING_KEY_ENV

        env[SOURCE_BINDING_KEY_ENV] = binding_key
    # The executable is this interpreter; arguments never pass through a shell.
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-m", "nexus_symbiote", *args],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )


def _write(path: Path, content: str, *, root: Path | None = None) -> None:
    from nexus_symbiote.utils.files import write_output_file

    write_output_file(path, content, root=root, create_parents=True)


def _export(
    native: Path,
    output: Path,
    fmt: str,
    *,
    root: Path | None = None,
    scan_root: Path | None = None,
) -> None:
    if fmt == "json":
        _write(output, native.read_text(encoding="utf-8"), root=root)
        return
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.generators.base import Generator
    from nexus_symbiote.generators.cyclonedx import CycloneDXGenerator
    from nexus_symbiote.generators.sarif import SARIFGenerator
    from nexus_symbiote.generators.spdx import SPDXGenerator

    # SARIF URIs are relative to the workspace; inventory paths to the scanned project.
    generators: dict[str, Generator] = {
        "cyclonedx": CycloneDXGenerator(),
        "sarif": SARIFGenerator(root, scan_root=scan_root),
        "spdx": SPDXGenerator(),
    }
    try:
        document = generators[fmt].generate_json(AIBOM.load(native))
    except (ValueError, RecursionError):
        # Export checks quote inventory values; name the format, never the values.
        raise ActionError(f"the {fmt} export failed its schema or consistency checks") from None
    _write(output, document, root=root)


def _imports_discovery(native: Path) -> bool:
    from nexus_symbiote.core.aibom import AIBOM
    from nexus_symbiote.generators._common import imports_discovery

    try:
        claim = AIBOM.load(native).metadata.completeness
    except (OSError, ValueError, RecursionError):
        raise ActionError("the collected inventory could not be read back") from None
    return claim is not None and imports_discovery(claim)


def _json_object(text: str) -> dict[str, Any] | None:
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return document if isinstance(document, dict) else None


def _gate_reasons(document: Mapping[str, Any] | None) -> list[str]:
    reasons = document.get("gate_reasons") if document is not None else None
    if not isinstance(reasons, list):
        return []
    return [reason for reason in reasons if isinstance(reason, str)]


def _finite_score(document: Mapping[str, Any] | None) -> float | int | None:
    score = document.get("overall_score") if document is not None else None
    if isinstance(score, bool) or not isinstance(score, (int, float)) or not math.isfinite(score):
        return None
    return score


def _report(lines: Iterable[tuple[str, str | None]]) -> list[str]:
    return [text for text, _ in lines]


def _section(document: Mapping[str, Any] | None, key: str, passed: bool) -> str:
    states = {"pass": "passed", "fail": "failed", "unknown": "failed", "skipped": "skipped"}
    section = document.get(key) if document is not None else None
    status = section.get("status") if isinstance(section, Mapping) else None
    return states.get(str(status), "passed" if passed else "failed")


def _markdown(text: object) -> str:
    # Backslash-escape every ASCII punctuation character so that no text becomes markup.
    return re.sub(r"([!-/:-@\[-`{-~])", r"\\\1", _neutralize(text))


class _Outputs:
    def __init__(self, path: Path | None, workspace: Path) -> None:
        self.path = path
        self.workspace = workspace

    def emit(self, **values: str) -> None:
        if self.path is None:
            return
        with self.path.open("a", encoding="utf-8") as stream:
            for name, value in values.items():
                if any(c in value for c in "\r\n"):
                    raise ActionError("invalid multiline Action output")
                stream.write(f"{name}={value}\n")

    def emit_path(self, name: str, path: Path) -> None:
        # Upload steps take these paths as globs; only files in the workspace qualify.
        if not path.resolve().is_relative_to(self.workspace):
            raise ActionError("Action output paths must stay within GITHUB_WORKSPACE")
        self.emit(**{name: str(path)})


def _announce(config: Config) -> None:
    _say("Nexus SymBiote AgentBOM Action")
    _say(f"  scan-path: {_neutralize(config.project.relative_to(config.workspace))}")
    if not config.validate:
        _annotate(
            "warning",
            "validate is 'false': completeness and integrity are not checked, so nothing in "
            "this run compares the inventory with the checkout or verifies a hash",
        )
    elif not config.integrity:
        _annotate(
            "warning",
            "validate-integrity is 'false': only completeness is checked; no model, "
            "instruction or tool hash or signature is verified",
        )
    if not config.risk_check:
        _annotate(
            "warning",
            "risk-check is 'false': no finding, not even a critical one, fails this run",
        )
    elif config.threshold == 0:
        _annotate(
            "notice",
            "risk-threshold is 0: the aggregate score does not fail this run; findings at or "
            f"above fail-on-severity ({config.fail_on_severity}), unverified SafeTensors, "
            "incomplete coverage and missing evidence still do",
        )
    if config.risk_check and config.fail_on_severity == "none":
        _annotate(
            "warning",
            "fail-on-severity is 'none': no finding fails this run by severity",
        )
    if config.allow_unsigned_discovery:
        _annotate(
            "warning",
            "allow-unsigned-discovery is 'true': ShadowScan discovery evidence whose producer "
            "signature was not verified is accepted by validation and the risk gate",
        )
    if config.limits:
        _annotate("notice", "collection limits set by the limits input: " + config.limits)
    if config.baseline is None:
        _say("  drift gate: not configured (set reviewed-baseline to fail on drift)")
        from nexus_symbiote.scanners.mcp import (
            _MIN_SOURCE_BINDING_KEY_LENGTH,
            SOURCE_BINDING_KEY_ENV,
        )

        inherited = os.environ.get(SOURCE_BINDING_KEY_ENV, "")
        if len(config.binding_key or inherited) < _MIN_SOURCE_BINDING_KEY_LENGTH:
            _annotate(
                "warning",
                f"{SOURCE_BINDING_KEY_ENV} is not set to at least "
                f"{_MIN_SOURCE_BINDING_KEY_LENGTH} characters: MCP launch arguments, "
                "environment values and endpoint paths are not bound, so a later diff "
                "cannot see those changes",
            )


def _summary_text(result: str, gates: Mapping[str, str], notes: Iterable[str]) -> str:
    rows = "".join(f"| {gate} | {status} |\n" for gate, status in gates.items())
    body = "".join(f"- {note}\n" for note in notes)
    return (
        f"### Nexus SymBiote gates: {result}\n\n| Gate | Result |\n| --- | --- |\n{rows}\n"
        f"{body}\nReasons and findings are in the job log of this step.\n"
    )


def run(
    config: Config,
    *,
    command: Callable[[list[str]], subprocess.CompletedProcess[str]] | None = None,
    export: Callable[[Path, Path, str], None] | None = None,
    outputs: Path | None = None,
    summary: Path | None = None,
) -> int:
    from nexus_symbiote.reporting import (
        diff_report_lines,
        risk_report_lines,
        validation_report_lines,
    )

    out = _Outputs(outputs, config.workspace)
    gates = dict.fromkeys(GATES, "not-run")
    notes: list[str] = []
    out.emit(
        aibom_path="",
        aibom_digest="",
        sarif_path="",
        risk_score="",
        passed="not-run",
        validation_passed="not-run",
        drift_passed="not-run",
        drift_alerts="",
        gates=json.dumps(gates),
        result="failed",
        signature_policy_digest="",
    )

    def record(gate: str, status: str) -> None:
        gates[gate] = status
        out.emit(gates=json.dumps(gates))

    def finish() -> int:
        result = "passed" if "failed" not in gates.values() else "failed"
        if result == "passed" and gates["collection"] != "passed":
            result = "failed"
        out.emit(gates=json.dumps(gates), result=result)
        if summary is not None:
            with summary.open("a", encoding="utf-8") as stream:
                stream.write(_summary_text(result, gates, notes))
        states = ", ".join(f"{gate} {status}" for gate, status in gates.items())
        _say(f"Nexus SymBiote result: {result} ({states})")
        return 0 if result == "passed" else 1

    def emit_export(native: Path, output: Path, fmt: str) -> None:
        if export is None:
            _export(native, output, fmt, root=config.workspace, scan_root=config.project)
        else:
            export(native, output, fmt)

    _announce(config)
    with tempfile.TemporaryDirectory(
        prefix="nexus-symbiote-action-", dir=_scratch_parent(config)
    ) as created:
        # The CLI refuses symlinked directories, and macOS temp paths contain one.
        scratch = Path(created).resolve(strict=True)
        if command is None:
            private = scratch / "home"
            private.mkdir(mode=0o700)
            command = functools.partial(
                _run, private=private, limits=config.limits, binding_key=config.binding_key
            )
        native = scratch / "native.json"
        signers: list[str] = []
        if config.signature_policy is not None:
            # Collection, validation and risk read one snapshot of the caller's trust root.
            with tempfile.NamedTemporaryFile(
                dir=scratch, prefix="signature-policy-", suffix=".json", delete=False
            ) as snapshot:
                snapshot.write(config.signature_policy)
            signers = ["--signature-policy", snapshot.name]
            digest = hashlib.sha256(config.signature_policy).hexdigest()
            out.emit(signature_policy_digest=f"sha256:{digest}")
        unsigned = ["--allow-unsigned-discovery"] if config.allow_unsigned_discovery else []
        excludes = config.accept_default_excludes
        accepted = (
            ["--accept-default-excludes"]
            if excludes is True
            else [f"--accept-default-exclude={name}" for name in excludes or ()]
        )
        args = [
            "scan",
            "--no-project-policy",
            "--report-only",
            "--format",
            "json",
            "--output",
            str(native),
            *signers,
            *accepted,
        ]
        for scanner in config.scanners:
            args.extend(["--scanner", scanner])
        collected = command([*args, "--", str(config.project)])
        _relay(
            "nexus-symbiote scan (its own gate is reported, not enforced; the Action's gates follow)",
            _process_lines(collected.stdout, collected.stderr),
        )
        if collected.returncode != 0:
            record("collection", "failed")
            _say("Collection did not complete: no inventory was written and no gate ran.")
            return finish()
        imported = config.format == "sarif" or config.sarif
        imported = imported and _imports_discovery(native)
        if imported and config.format == "sarif":
            record("collection", "failed")
            _say(
                "format 'sarif' cannot carry imported ShadowScan discovery coverage; choose "
                "json, cyclonedx or spdx. No artifact was exported and no gate ran."
            )
            return finish()
        try:
            from nexus_symbiote.utils.files import OutputRefusedError

            emit_export(native, config.output, config.format)
        except (OutputRefusedError, OSError):
            record("collection", "failed")
            _say(
                "Collection failed: the output path was refused or could not be written, "
                "so no artifact was exported and no gate ran."
            )
            return finish()
        out.emit_path("aibom_path", config.output)
        export_source = config.output if config.output.is_file() else native
        if export_source.is_file():
            export_digest = hashlib.sha256(export_source.read_bytes()).hexdigest()
            out.emit(aibom_digest=f"sha256:{export_digest}")
        inventory = _json_object(native.read_text(encoding="utf-8")) or {}
        claim = (inventory.get("metadata") or {}).get("completeness") or {}
        failures = claim.get("scan_failures")
        if failures:
            record("collection", "failed")
            records = len(failures)
            distinct = len({str(failure) for failure in failures})
            counted = f"{distinct} distinct collection failure{'' if distinct == 1 else 's'}"
            if records != distinct:
                counted += f" ({records} records)"
            verb = "was" if distinct == 1 else "were"
            _say(
                f"Collection failed: {counted} {verb} recorded (listed above and in the "
                "inventory's metadata.completeness), so no gate ran."
            )
            return finish()
        record("collection", "passed")
        if config.sarif and imported:
            _annotate(
                "warning",
                "SARIF upload skipped: the inventory merges imported ShadowScan discovery, "
                "whose coverage SARIF cannot carry; the evidence artifact keeps it",
            )
            notes.append("SARIF upload skipped: imported discovery cannot be carried in SARIF")
        elif config.sarif:
            sarif = config.output.with_name(config.output.name + ".sarif")
            try:
                emit_export(native, sarif, "sarif")
            except (OutputRefusedError, OSError):
                record("collection", "failed")
                _say(
                    "Collection failed: the SARIF output path was refused or could not be "
                    "written, so no gate ran."
                )
                return finish()
            out.emit_path("sarif_path", sarif)

        if not config.validate:
            record("completeness", "skipped")
            record("integrity", "skipped")
            out.emit(validation_passed="skipped")
        else:
            arguments = [
                "validate",
                "--no-project-policy",
                "--json-output",
                str(native),
                *accepted,
            ]
            arguments += ["--project", str(config.project), *signers, *unsigned]
            if not config.integrity:
                arguments.append("--skip-integrity")
            validated = command(arguments)
            document = _json_object(validated.stdout)
            passed = (
                validated.returncode == 0
                and document is not None
                and document.get("passed", True) is True
            )
            scanned = config.project.relative_to(config.workspace)
            shown = (
                _report(validation_report_lines(document, project=scanned))
                if document is not None
                else []
            )
            _relay("nexus-symbiote validate", [*shown, *_process_lines(validated.stderr)])
            completeness = _section(document, "completeness", passed)
            integrity = _section(document, "integrity", passed) if config.integrity else "skipped"
            if not passed and "failed" not in (completeness, integrity):
                # The discovery producer, assurance and graph checks gate with completeness.
                completeness = "failed"
            record("completeness", completeness)
            record("integrity", integrity)
            out.emit(validation_passed="true" if passed else "false")

        if not config.risk_check:
            record("risk", "skipped")
            out.emit(passed="skipped")
        else:
            arguments = [
                "risk",
                "--no-project-policy",
                str(native),
                "--json-output",
                *unsigned,
                *accepted,
            ]
            # The same reconciliation and signers as validation, whether or not it ran,
            # so a signer policy that verifies the discovery producer counts here too.
            arguments += ["--project", str(config.project), *signers]
            if config.threshold == 0:
                arguments.append("--no-score-threshold")
            else:
                arguments += ["--threshold", str(config.threshold)]
            arguments += ["--fail-on-severity", config.fail_on_severity]
            scored = command(arguments)
            if scored.returncode not in {0, 1}:
                _relay("nexus-symbiote risk", _process_lines(scored.stderr))
                raise ActionError("risk evaluation failed to run")
            report = _json_object(scored.stdout)
            score = _finite_score(report)
            if score is None and scored.returncode == 0:
                raise ActionError("risk evaluation returned no finite numeric score")
            passed = score is not None and scored.returncode == 0
            passed = passed and report is not None and report.get("passed", True) is True
            shown = (
                _report(risk_report_lines({**report, "passed": passed}))
                if report is not None
                else []
            )
            _relay("nexus-symbiote risk", [*shown, *_process_lines(scored.stderr)])
            out.emit(passed="true" if passed else "false")
            record("risk", "passed" if passed else "failed")
            if score is None:
                # The CLI refuses to score unverified discovery evidence in CI and an
                # inventory that does not reconcile with the project.
                _say("The risk gate failed without a score; its reasons are listed above.")
                notes.append("Risk score: not computed")
            else:
                out.emit(risk_score=str(score))
                notes.append(f"Risk score: {float(score):.1f}")
            if not passed:
                reasons = [_markdown(r) for r in _gate_reasons(report)]
                if not reasons and score is None:
                    reasons = ["risk evaluation failed without a score; see the job log"]
                notes.extend(f"Risk gate reason: {reason}" for reason in reasons)

        if config.baseline is None:
            record("drift", "skipped")
            out.emit(drift_passed="skipped")
        else:
            reviewed = scratch / "reviewed-baseline.json"
            reviewed.write_bytes(config.baseline)
            baseline_verified = True
            if config.baseline_attestation is not None:
                envelope = scratch / "reviewed-baseline.att.json"
                envelope.write_bytes(config.baseline_attestation)
                verifier_args: list[str] = []
                if config.trusted_verifier_contents:
                    for key_bytes in config.trusted_verifier_contents:
                        with tempfile.NamedTemporaryFile(
                            dir=scratch, prefix="trusted-key-", suffix=".pem", delete=False
                        ) as snapshot:
                            snapshot.write(key_bytes)
                        verifier_args.extend(["--trusted-key", snapshot.name])
                else:
                    for verifier_path in config.trusted_verifiers:
                        verifier_args.extend(["--trusted-key", str(verifier_path)])
                verified_att = command(
                    [
                        "verify-attestation",
                        str(reviewed),
                        str(envelope),
                        "--purpose",
                        "reviewed",
                        "--json-output",
                        *verifier_args,
                    ]
                )
                _relay(
                    "nexus-symbiote verify-attestation",
                    _process_lines(verified_att.stdout, verified_att.stderr),
                )
                if verified_att.returncode != 0:
                    _say(
                        "The reviewed baseline failed attestation verification, so the drift gate failed."
                    )
                    record("drift", "failed")
                    out.emit(drift_passed="false")
                    notes.append("Reviewed baseline attestation: failed")
                    baseline_verified = False
                else:
                    notes.append("Reviewed baseline attestation: verified")
            if baseline_verified:
                compared = command(
                    ["diff", str(reviewed), str(native), "--fail-on-alert", "--json-output"]
                )
                document = _json_object(compared.stdout)
                if document is None:
                    _relay("nexus-symbiote diff", _process_lines(compared.stderr))
                    _say("The reviewed baseline could not be compared: is it a native AgentBOM?")
                    record("drift", "failed")
                    out.emit(drift_passed="false")
                else:
                    alerts = len(document.get("security_alerts") or [])
                    passed = compared.returncode == 0 and alerts == 0
                    shown = _report(diff_report_lines(document))
                    _relay("nexus-symbiote diff", [*shown, *_process_lines(compared.stderr)])
                    out.emit(drift_passed="true" if passed else "false", drift_alerts=str(alerts))
                    record("drift", "passed" if passed else "failed")
                    notes.append(f"Drift alerts against the reviewed baseline: {alerts}")
    return finish()


def main() -> int:
    try:
        config = Config.from_env(os.environ)
        outputs = os.environ.get("GITHUB_OUTPUT")
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        return run(
            config,
            outputs=Path(outputs) if outputs else None,
            summary=Path(summary) if summary else None,
        )
    except (InputError, ActionError) as exc:
        _say(f"Nexus SymBiote action failed: {exc}")
        return 1
    except Exception as exc:
        # Other messages can quote inventory or checkout text; name only the error class.
        _say(f"Nexus SymBiote action failed: unexpected {type(exc).__name__}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
