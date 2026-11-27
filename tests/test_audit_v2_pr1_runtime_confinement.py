"""Regression tests for PR 1 security audit remediations (runtime, crypto, policy, confinement)."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import shutil
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pydantic import ValidationError

from nexus_symbiote import attestation
from nexus_symbiote.cli import main
from nexus_symbiote.core.hashing import (
    MAX_JSON_NESTING,
    hash_bytes,
    hash_canonical,
    hash_file,
    hash_tool_definition,
    open_directory_nofollow,
    parse_json_strict,
)
from nexus_symbiote.policy import (
    MAX_POLICY_ENTRY_CHARS,
    MAX_POLICY_LIST_ITEMS,
    MAX_POLICY_SUPPRESSIONS,
    MAX_POLICY_YAML_NODES,
    PolicyError,
    load_policy,
    parse_yaml_mapping,
    weakened_settings,
)
from nexus_symbiote.runtime import (
    MAX_STRICT_JSON_DEPTH,
    ActionApproval,
    ApprovedSnapshot,
    AuthorizationError,
    ExecutionContext,
    ReferenceGateway,
    ServedTool,
    SignerScope,
    StateStore,
    ToolCall,
    ToolGrant,
    TrustStatus,
    digest,
    key_id,
    sign_contract,
    strict_json,
)
from nexus_symbiote.runtime_validation import (
    WORKER_CPU_SECONDS,
    WORKER_STARTUP_CPU_SECONDS,
    ValidationBudgetError,
    validate_arguments,
)
from nexus_symbiote.signature_policy import SignaturePolicyError, load_signature_policies
from nexus_symbiote.utils.confined import CollectionError, ConfinedCollection, LimitExceededError
from nexus_symbiote.utils.crypto import (
    DSSE_UNSUPPORTED,
    TRUST_ROOT_ENV,
    TRUST_ROOT_SHA256_ENV,
    _read_explicit_trust_root,
    _read_sigstore_cache,
    verify_sigstore_bundle,
    verify_sigstore_digest,
)
from nexus_symbiote.utils.files import write_output_file
from nexus_symbiote.utils.terminal import json_text

# ---------------------------------------------------------------------------
# NS-AUD-H01 & NS-AUD-I03: Runtime JSON Schema $vocabulary & worker CPU limits
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "vocabulary",
    [
        {
            "https://json-schema.org/draft/2020-12/vocab/core": True,
            "https://json-schema.org/draft/2020-12/vocab/applicator": True,
            "https://json-schema.org/draft/2020-12/vocab/validation": True,
            "https://json-schema.org/draft/2020-12/vocab/format-assertion": True,
        },
        {
            "https://json-schema.org/draft/2020-12/vocab/core": True,
            "https://json-schema.org/draft/2020-12/vocab/content": True,
        },
        {
            "https://json-schema.org/draft/2019-09/vocab/core": True,
            "https://json-schema.org/draft/2019-09/vocab/format": True,
        },
        {
            "https://json-schema.org/draft/2020-12/vocab/core": True,
            "https://attacker.example/vocab/custom": True,
        },
    ],
)
def test_schema_requiring_unasserted_vocabulary_fails_closed(
    vocabulary: dict[str, bool],
) -> None:
    dialect = (
        "https://json-schema.org/draft/2019-09/schema"
        if any("2019-09" in uri for uri in vocabulary)
        else "https://json-schema.org/draft/2020-12/schema"
    )
    schema = {
        "$schema": dialect,
        "$vocabulary": vocabulary,
        "type": "object",
        "properties": {"target": {"type": "string", "format": "ipv4"}},
    }
    with pytest.raises(ValidationBudgetError) as caught:
        validate_arguments(schema, {"target": "not-an-ip"})
    assert caught.value.reason == "schema-invalid"


def test_schema_with_supported_or_optional_vocabulary_passes_and_subschema_vocab_fails() -> None:
    valid_schema = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$vocabulary": {
            "https://json-schema.org/draft/2020-12/vocab/core": True,
            "https://json-schema.org/draft/2020-12/vocab/validation": True,
            "https://json-schema.org/draft/2020-12/vocab/format-annotation": True,
            "https://json-schema.org/draft/2020-12/vocab/format-assertion": False,
        },
        "type": "object",
        "properties": {"name": {"type": "string"}},
        "required": ["name"],
    }
    validate_arguments(valid_schema, {"name": "ok"})

    subschema_vocab = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {
            "nested": {
                "$vocabulary": {"https://json-schema.org/draft/2020-12/vocab/core": True},
                "type": "string",
            }
        },
    }
    with pytest.raises(ValidationBudgetError) as caught:
        validate_arguments(subschema_vocab, {"nested": "x"})
    assert caught.value.reason == "schema-invalid"


@pytest.mark.parametrize(
    ("startup_seconds", "expected"),
    [
        # A slow start-up must not raise the evaluation limit above the start-up
        # ceiling: without the min() cap this would be 104 + WORKER_CPU_SECONDS.
        ((99.0, 5.0), WORKER_STARTUP_CPU_SECONDS),
        # A fast start-up is granted usage plus WORKER_CPU_SECONDS, below the ceiling.
        ((0.2, 0.1), 1 + WORKER_CPU_SECONDS),
    ],
)
def test_worker_evaluation_cpu_budget_is_capped_by_startup_ceiling(
    monkeypatch: pytest.MonkeyPatch, startup_seconds: tuple[float, float], expected: int
) -> None:
    import io

    from nexus_symbiote import runtime_validation

    if os.name != "posix":
        assert runtime_validation._worker() == 1
        return
    import resource

    assert 1 + WORKER_CPU_SECONDS < WORKER_STARTUP_CPU_SECONDS
    recorded: list[tuple[int, tuple[int, int]]] = []
    monkeypatch.setattr(
        resource,
        "getrlimit",
        lambda _kind: (resource.RLIM_INFINITY, resource.RLIM_INFINITY),
    )
    monkeypatch.setattr(
        resource,
        "setrlimit",
        lambda kind, limits_pair: recorded.append((kind, limits_pair)),
    )
    user, system = startup_seconds
    monkeypatch.setattr(
        resource,
        "getrusage",
        lambda _who: type("Usage", (), {"ru_utime": user, "ru_stime": system})(),
    )
    # In-process, _worker would swap jsonschema's regex engine and format checkers for
    # every later test; its own subprocess undoes nothing because it exits.
    import jsonschema._format
    import jsonschema._keywords
    import jsonschema._legacy_keywords
    import jsonschema._utils

    for module in (
        jsonschema._format,
        jsonschema._keywords,
        jsonschema._legacy_keywords,
        jsonschema._utils,
    ):
        monkeypatch.setattr(module, "re", module.re)
    monkeypatch.setattr(runtime_validation, "_disable_unused_format_checkers", lambda: None)
    payload = json.dumps({"schema": {"type": "object"}, "arguments": {}}).encode("utf-8")
    monkeypatch.setattr(sys, "stdin", type("FakeIn", (), {"buffer": io.BytesIO(payload)})())
    monkeypatch.setattr(sys, "stdout", type("FakeOut", (), {"buffer": io.BytesIO()})())
    saved_modules = dict(sys.modules)
    try:
        assert runtime_validation._worker() == 0
    finally:
        sys.modules.clear()
        sys.modules.update(saved_modules)
    cpu_calls = [limits_pair for kind, limits_pair in recorded if kind == resource.RLIMIT_CPU]
    # The start-up limit first, then the evaluation budget _worker derives from usage.
    assert cpu_calls[0] == (WORKER_STARTUP_CPU_SECONDS, WORKER_STARTUP_CPU_SECONDS)
    assert cpu_calls[-1] == (expected, expected)


# ---------------------------------------------------------------------------
# NS-AUD-H10 & NS-AUD-L10: Policy YAML anchors/aliases, root exclusion, venv
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "raw_yaml",
    [
        "a: &anchor [docs]\nexclude_paths: *anchor\n",
        "exclude_paths: &anchor [docs]\n",
        'exclude_paths:\n  - "\\uD800"\n',
        'exclude_paths:\n  - !!int "1:\\uD800"\n',
    ],
)
def test_policy_yaml_rejects_anchors_aliases_and_escaped_surrogates(raw_yaml: str) -> None:
    with pytest.raises(PolicyError):
        parse_yaml_mapping(raw_yaml)
    with pytest.raises(PolicyError, match="YAML complexity exceeds policy budget"):
        parse_yaml_mapping("a: 1\nb: 2\nc: 3\n", max_nodes=3)


@pytest.mark.parametrize(
    "bad_excludes",
    [
        ["."],
        ["./"],
        ["a/.."],
        [f"dir_{i}" for i in range(MAX_POLICY_LIST_ITEMS + 1)],
        ["a" * (MAX_POLICY_ENTRY_CHARS + 1)],
    ],
)
def test_policy_rejects_root_exclusion_and_unbounded_lists(
    tmp_path: Path, bad_excludes: list[str]
) -> None:
    policy_file = tmp_path / ".nexus-symbiote.yaml"
    policy_file.write_text(json.dumps({"scan": {"exclude_paths": bad_excludes}}), encoding="utf-8")
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


def test_policy_venv_exclusion_is_not_flagged_as_weakened(tmp_path: Path) -> None:
    policy_file = tmp_path / ".nexus-symbiote.yaml"
    policy_file.write_text("scan:\n  exclude_paths:\n    - venv\n    - .venv\n", encoding="utf-8")
    loaded = load_policy(tmp_path)
    assert loaded is not None
    assert weakened_settings(loaded) == []


def test_parse_yaml_mapping_sets_no_node_budget_unless_asked() -> None:
    # pnpm lockfiles, scanner YAML and agent manifests are bounded by their callers
    # (bytes and tokens); a large valid document must still parse with no budget,
    # including one above the 250,000 nodes a former global default refused.
    items = 260_000
    document = "packages: [" + ",".join(["p"] * items) + "]\n"
    parsed = parse_yaml_mapping(document)
    assert len(parsed["packages"]) == items
    with pytest.raises(PolicyError, match="YAML complexity exceeds policy budget"):
        parse_yaml_mapping(document, max_nodes=MAX_POLICY_YAML_NODES)


def _maximal_policy_yaml(suppressions: int) -> str:
    """Every setting, both string lists at their maximum and ``suppressions`` entries."""
    lines = [
        'version: "1.0"',
        "scan:",
        '  scanners: ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", '
        '"ide_agents", "source"]',
        "  exclude_paths:",
        *(f"    - generated/dir_{index}" for index in range(MAX_POLICY_LIST_ITEMS)),
        '  failure_mode: "report-only"',
        "risk:",
        "  fail_threshold: 50.0",
        "  warn_threshold: 25.0",
        "  ignore_categories:",
        *(f"    - category_{index}" for index in range(MAX_POLICY_LIST_ITEMS)),
        '  fail_on_severity: "critical"',
        "  suppressions:",
    ]
    for index in range(suppressions):
        lines += [
            f'    - component_ref: "model:fixtures/weights_{index}.bin"',
            '      category: "serialization_format"',
            f'      fingerprint: "sha256:{index:064x}"',
            '      reason: "Reviewed test fixture, never loaded"',
            '      owner: "security@example.test"',
            "      expires: 2099-01-31",
        ]
    lines += [
        "validate:",
        "  require_completeness: true",
        "  require_integrity: true",
        '  minimum_assurance_level: "declared"',
        "  require_discovery_signature: false",
        "output:",
        '  default_format: "json"',
    ]
    return "\n".join(lines) + "\n"


def test_policy_with_every_permitted_suppression_and_list_entry_loads(tmp_path: Path) -> None:
    import yaml

    document = _maximal_policy_yaml(MAX_POLICY_SUPPRESSIONS)

    def count(node: Any) -> int:
        if isinstance(node, yaml.MappingNode):
            return 1 + sum(count(key) + count(value) for key, value in node.value)
        if isinstance(node, yaml.SequenceNode):
            return 1 + sum(count(item) for item in node.value)
        return 1

    # The budget is exactly the largest valid policy: nothing valid is refused for size.
    assert count(yaml.compose(document, Loader=yaml.SafeLoader)) == MAX_POLICY_YAML_NODES
    (tmp_path / ".nexus-symbiote.yaml").write_text(document, encoding="utf-8")
    loaded = load_policy(tmp_path)
    assert loaded is not None
    assert len(loaded.risk.suppressions) == MAX_POLICY_SUPPRESSIONS
    assert len(loaded.scan.exclude_paths) == MAX_POLICY_LIST_ITEMS
    assert len(loaded.risk.ignore_categories) == MAX_POLICY_LIST_ITEMS


@pytest.mark.parametrize(
    ("document", "message"),
    [
        (
            "risk:\n  ignore_categories: [" + ",".join(["c"] * (4 * MAX_POLICY_YAML_NODES)) + "]\n",
            "YAML complexity exceeds policy budget",
        ),
        (
            "a: &a [x, x, x, x, x, x, x, x, x]\n"
            "b: &b [*a, *a, *a, *a, *a, *a, *a, *a, *a]\n"
            "c: [*b, *b, *b, *b, *b, *b, *b, *b, *b]\n",
            "YAML anchors are not supported",
        ),
    ],
    ids=["far-over-budget", "alias-bomb"],
)
def test_policy_far_over_node_budget_or_alias_bomb_is_refused(
    tmp_path: Path, document: str, message: str
) -> None:
    (tmp_path / ".nexus-symbiote.yaml").write_text(document, encoding="utf-8")
    with pytest.raises(PolicyError, match=message):
        load_policy(tmp_path)


def test_policy_one_suppression_over_the_maximum_is_refused(tmp_path: Path) -> None:
    (tmp_path / ".nexus-symbiote.yaml").write_text(
        _maximal_policy_yaml(MAX_POLICY_SUPPRESSIONS + 1), encoding="utf-8"
    )
    with pytest.raises(PolicyError):
        load_policy(tmp_path)


# ---------------------------------------------------------------------------
# NS-AUD-M01, NS-AUD-L03, NS-AUD-L04, NS-AUD-L05: Confinement, hashing, JSON
# ---------------------------------------------------------------------------


def test_open_directory_nofollow_uses_o_path_on_execute_only_intermediate_dir(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    traverse = tmp_path / "exec_only"
    target = traverse / "workspace"
    target.mkdir(parents=True)
    expected_ino = target.stat().st_ino
    real_open = os.open
    o_path = getattr(os, "O_PATH", 0)
    calls: list[tuple[str, int, int | None]] = []

    def _spy_open(
        path: str | os.PathLike[str],
        flags: int,
        mode: int = 0o600,
        *,
        dir_fd: int | None = None,
    ) -> int:
        del mode
        calls.append((os.fsdecode(path), flags, dir_fd))
        if dir_fd is not None:
            return real_open(path, flags, dir_fd=dir_fd)
        return real_open(path, flags)

    # Owner may traverse but not list: the plain O_RDONLY directory open is refused.
    traverse.chmod(0o311)
    try:
        try:
            probe = real_open(traverse, os.O_RDONLY | os.O_DIRECTORY)
        except PermissionError:
            unreadable = True
        else:
            # Privileged callers (CAP_DAC_READ_SEARCH) read it anyway; no fallback runs.
            os.close(probe)
            unreadable = False
        with monkeypatch.context() as patched:
            patched.setattr(os, "open", _spy_open)
            patched.setattr(os, "supports_dir_fd", os.supports_dir_fd | {_spy_open})
            fd = open_directory_nofollow(target)
        try:
            assert os.fstat(fd).st_ino == expected_ino
        finally:
            os.close(fd)
    finally:
        traverse.chmod(0o755)

    exec_only_opens = [(flags, dfd) for name, flags, dfd in calls if name == "exec_only"]
    workspace_opens = [dfd for name, _flags, dfd in calls if name == "workspace"]
    used_o_path = any(o_path and flags & o_path for flags, _dfd in exec_only_opens)
    if unreadable and o_path:
        # The O_PATH branch opened exec_only relative to its parent, and workspace was
        # then opened relative to that O_PATH descriptor.
        assert used_o_path
        assert all(dfd is not None for _flags, dfd in exec_only_opens)
        assert workspace_opens and all(dfd is not None for dfd in workspace_opens)
    elif unreadable:
        # No O_PATH (macOS): the walk falls back to verifying the ancestor with lstat
        # and opens the target by its absolute path.
        assert not used_o_path
        assert any(
            name.endswith("/exec_only/workspace") and dfd is None for name, _flags, dfd in calls
        )
    else:
        assert not used_o_path
        assert workspace_opens and all(dfd is not None for dfd in workspace_opens)


def test_confined_collection_rejects_cross_device_mount_and_two_hop_walk_symlinks(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (tmp_path / "real_target").mkdir()
    (tmp_path / "real_target" / "ok.txt").write_text("ok", encoding="utf-8")
    (tmp_path / "real_target" / "hop2.txt").symlink_to("ok.txt")
    (tmp_path / "hop1").symlink_to("real_target", target_is_directory=True)

    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures) as files:
        walked = [p.as_posix() for p in files.iter_files("hop1")]
    assert walked == ["real_target/ok.txt"]
    assert "real_target/hop2.txt" not in walked
    assert any("symlink reached through another symlink" in item for item in failures)


def test_confined_collection_mount_check_applies_to_directories_not_regular_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # overlayfs without xino reports directories on the overlay device and regular
    # files on their layer's device; only a directory marks a mount point.
    (tmp_path / "real_target").mkdir()
    (tmp_path / "real_target" / "ok.txt").write_text("ok", encoding="utf-8")
    mnt_dir = tmp_path / "mnt_dir"
    mnt_dir.mkdir()
    (mnt_dir / "secret.txt").write_text("x", encoding="utf-8")
    (tmp_path / "layer_file.txt").write_text("y", encoding="utf-8")
    (tmp_path / "link_to_mnt").symlink_to("mnt_dir/secret.txt")
    (tmp_path / "link_to_mnt_dir").symlink_to("mnt_dir", target_is_directory=True)
    (tmp_path / "link_to_leaf").symlink_to("layer_file.txt")
    other_device = {mnt_dir.stat().st_ino, (tmp_path / "layer_file.txt").stat().st_ino}
    real_fstat = os.fstat
    real_stat = os.stat

    class _FakeStat:
        def __init__(self, inner: os.stat_result) -> None:
            self._inner = inner
            self.st_dev = inner.st_dev + 99

        def __getattr__(self, attr: str) -> Any:
            return getattr(self._inner, attr)

    monkeypatch.setattr(
        os,
        "fstat",
        lambda fd: _FakeStat(s) if (s := real_fstat(fd)).st_ino in other_device else s,  # type: ignore[return-value]
    )
    monkeypatch.setattr(
        os,
        "stat",
        lambda *a, **kw: (
            _FakeStat(s)  # type: ignore[return-value]
            if (s := real_stat(*a, **kw)).st_ino in other_device
            else s
        ),
    )
    mount_failures: list[str] = []
    with ConfinedCollection(tmp_path, mount_failures) as files:
        collected = [p.as_posix() for p in files.iter_files()]
        assert files.case_variants(Path("mnt_dir/secret.txt")) == []
        # A regular file on another device is read, directly and through a symlink.
        assert files.read_text("layer_file.txt") == "y", mount_failures
        assert files.read_text("link_to_leaf") == "y"
        assert files.hash_file("layer_file.txt") is not None
        # A directory on another device is refused however it is reached.
        assert files.read_text("mnt_dir/secret.txt") is None
        assert files.read_text("link_to_mnt") is None
        assert files._root_fd is not None
        leaf_fd: int | None = None
        try:
            with pytest.raises(CollectionError, match="mount boundary"):
                leaf_fd = files._open_leaf_no_follow(files._root_fd, "mnt_dir")
        finally:
            if leaf_fd is not None:
                os.close(leaf_fd)
    assert "layer_file.txt" in collected
    assert "link_to_leaf" in collected
    assert "real_target/ok.txt" in collected
    assert not [path for path in collected if "mnt_dir" in path or "link_to_mnt" in path]
    assert any(
        item.startswith("mnt_dir: cross-filesystem mount excluded") for item in mount_failures
    )
    assert any("link_to_mnt_dir" in item and "mount boundary" in item for item in mount_failures)

    # With every directory on another device, nothing beneath the root is entered,
    # while the root's own regular files and links to them are still collected.
    root_failures: list[str] = []
    with ConfinedCollection(tmp_path, root_failures) as files:
        files._root_dev = -999
        assert files.read_text("real_target/ok.txt") is None
        root_level = [p.as_posix() for p in files.iter_files()]
    assert sorted(root_level) == ["layer_file.txt", "link_to_leaf"]
    assert any(
        item.startswith("real_target: cross-filesystem mount excluded") for item in root_failures
    )


def test_confined_has_exact_name_enforces_max_entries(tmp_path: Path) -> None:
    for idx in range(6):
        (tmp_path / f"f{idx}.txt").write_text("x", encoding="utf-8")
    failures: list[str] = []
    with ConfinedCollection(tmp_path, failures, max_entries=3) as files:
        assert files._root_fd is not None
        with pytest.raises(LimitExceededError):
            # Trailing space triggers full directory scan in _has_exact_name
            files._has_exact_name(files._root_fd, "probe ")


def test_hash_functions_reject_weak_algorithms_and_mid_read_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    sample = tmp_path / "artifact.bin"
    sample.write_bytes(b"payload")
    for weak in ("md5", "sha1"):
        with pytest.raises(ValueError, match="Unsupported security hash algorithm"):
            hash_file(sample, algorithm=weak)
        with pytest.raises(ValueError, match="Unsupported security hash algorithm"):
            hash_bytes(b"payload", algorithm=weak)
        with pytest.raises(ValueError, match="Unsupported security hash algorithm"):
            hash_canonical({"a": 1}, algorithm=weak)

    real_open = open_regular_file_target = sample
    from nexus_symbiote.core import hashing as hashing_mod

    orig_open = hashing_mod.open_regular_file

    def swapping_open(path: Path) -> Any:
        stream = orig_open(path)
        replacement = tmp_path / "swapped.bin"
        replacement.write_bytes(b"tampered")
        os.replace(replacement, real_open)
        return stream

    monkeypatch.setattr(hashing_mod, "open_regular_file", swapping_open)
    with pytest.raises(OSError, match="File changed during hashing"):
        hash_file(open_regular_file_target)


def test_json_depth_guards_reject_deep_nesting_before_recursion() -> None:
    deep = "[" * (MAX_JSON_NESTING + 5) + "0" + "]" * (MAX_JSON_NESTING + 5)
    with pytest.raises(RecursionError, match="depth limit"):
        parse_json_strict(deep)

    deep_runtime = "[" * (MAX_STRICT_JSON_DEPTH + 5) + "0" + "]" * (MAX_STRICT_JSON_DEPTH + 5)
    with pytest.raises(AuthorizationError) as auth_err:
        strict_json(deep_runtime)
    assert auth_err.value.reason == "json-invalid"

    deep_native = "[" * (attestation.MAX_NATIVE_DEPTH + 5) + "]" * (
        attestation.MAX_NATIVE_DEPTH + 5
    )
    assert attestation._native_facts(deep_native.encode("utf-8")) is None


def test_write_output_file_fallback_when_hardlinks_unsupported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_hardlink(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EOPNOTSUPP, "Operation not supported")

    monkeypatch.setattr(os, "link", no_hardlink)
    out = tmp_path / "report.json"
    write_output_file(out, '{"ok": true}\n', overwrite=False)
    assert out.read_text(encoding="utf-8") == '{"ok": true}\n'
    with pytest.raises(FileExistsError):
        write_output_file(out, '{"ok": false}\n', overwrite=False)
    assert out.read_text(encoding="utf-8") == '{"ok": true}\n'


def test_write_output_file_fallback_unlinks_when_direct_fsync_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def no_hardlink(*_args: object, **_kwargs: object) -> None:
        raise OSError(errno.EOPNOTSUPP, "Operation not supported")

    real_fsync = os.fsync
    calls = 0

    def fsync_then_fail(fd: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            real_fsync(fd)
            return
        raise OSError(errno.EIO, "Input/output error")

    monkeypatch.setattr(os, "link", no_hardlink)
    monkeypatch.setattr(os, "fsync", fsync_then_fail)
    out = tmp_path / "report.json"
    with pytest.raises(OSError, match="Input/output error"):
        write_output_file(out, '{"ok": true}\n', overwrite=False)
    assert not out.exists()


def test_json_text_escapes_bidi_c1_and_line_separators() -> None:
    payload = chr(0x202E) + chr(0x009B) + chr(0x2028) + chr(0xFE0F) + chr(0xE0020)
    raw = '{"msg":"' + payload + '"}'
    sanitized = json_text(raw)
    for ch in payload:
        assert ch not in sanitized
    assert "\\u202e" in sanitized
    assert "\\u009b" in sanitized
    assert "\\u2028" in sanitized
    assert "\\ufe0f" in sanitized
    assert "\\udb40\\udc20" in sanitized
    assert json.loads(sanitized)["msg"] == payload


# ---------------------------------------------------------------------------
# NS-AUD-M02, NS-AUD-L02, NS-AUD-M14: Real Sigstore verification & trust roots
# ---------------------------------------------------------------------------


def test_real_sigstore_bundle_verification_and_dsse_snake_case_rejection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)

    fixtures = Path(__file__).parent / "fixtures" / "sigstore-python"
    subject = fixtures / "rfc8785-0.1.2-py3-none-any.whl.subject"
    bundle = fixtures / "bundle_v3_github.whl.sigstore"
    identity = (
        "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
    )
    issuer = "https://token.actions.githubusercontent.com"

    verified = verify_sigstore_bundle(subject, bundle, identity, issuer)
    assert verified.verified is True, verified.error

    wrong_signer = verify_sigstore_bundle(
        subject, bundle, "https://attacker.example/workflow", issuer
    )
    assert wrong_signer.verified is False

    tampered = tmp_path / "tampered.whl"
    data = bytearray(subject.read_bytes())
    data[0] ^= 0x01
    tampered.write_bytes(bytes(data))
    assert verify_sigstore_bundle(tampered, bundle, identity, issuer).verified is False

    snake_dsse = verify_sigstore_digest(
        hashlib.sha256(b"x").hexdigest(),
        b'{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json","dsse_envelope":{}}',
        identity,
        issuer,
    )
    assert snake_dsse.verified is False
    assert snake_dsse.error == DSSE_UNSUPPORTED


def test_seeded_sigstore_cache_refreshes_on_embedded_upgrade_without_clobbering_operator_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import sigstore._utils as sigstore_utils

    cache = tmp_path / "cache"
    monkeypatch.setenv("XDG_CACHE_HOME", str(cache))
    monkeypatch.delenv(TRUST_ROOT_ENV, raising=False)
    monkeypatch.delenv(TRUST_ROOT_SHA256_ENV, raising=False)

    monkeypatch.setattr(sigstore_utils, "read_embedded", lambda *_a, **_k: b'{"v": 1}')
    path, content, err = _read_sigstore_cache()
    assert err is None and path is not None and content == b'{"v": 1}'

    monkeypatch.setattr(sigstore_utils, "read_embedded", lambda *_a, **_k: b'{"v": 2}')
    path2, content2, err2 = _read_sigstore_cache()
    assert err2 is None and path2 == path and content2 == b'{"v": 2}'
    assert path.read_bytes() == b'{"v": 2}'

    # Operator-customized root does not match the seeded sidecar and must not be clobbered.
    path.write_bytes(b'{"operator": true}')
    monkeypatch.setattr(sigstore_utils, "read_embedded", lambda *_a, **_k: b'{"v": 3}')
    _, content3, err3 = _read_sigstore_cache()
    assert err3 is None and content3 == b'{"operator": true}'


def test_unpinned_explicit_trust_root_rejects_hardlinks_and_unsafe_ancestors(
    tmp_path: Path,
) -> None:
    priv = tmp_path / "priv"
    priv.mkdir(mode=0o700)
    root = priv / "trusted_root.json"
    root.write_bytes(b"{}")
    root.chmod(0o600)
    hard = tmp_path / "hardlink.json"
    os.link(root, hard)
    _, content, _, error = _read_explicit_trust_root(root, None)
    assert content is None and error is not None and "hard links" in error
    os.unlink(hard)

    shared_anc = tmp_path / "world_writable_no_sticky"
    shared_anc.mkdir()
    shared_anc.chmod(0o777)
    inner = shared_anc / "inner"
    inner.mkdir(mode=0o700)
    nested_root = inner / "trusted_root.json"
    nested_root.write_bytes(b"{}")
    nested_root.chmod(0o600)
    _, content2, _, error2 = _read_explicit_trust_root(nested_root, None)
    assert content2 is None and error2 is not None and "world-writable" in error2


def test_signature_policy_rejects_enclosing_git_tree_and_world_writable_dir(
    tmp_path: Path,
) -> None:
    repo = tmp_path / "monorepo"
    (repo / ".git").mkdir(parents=True)
    project = repo / "services" / "agent"
    project.mkdir(parents=True)
    (project / "model.bin").write_bytes(b"weights")
    sibling_policy = repo / "policies" / "sig-policy.json"
    sibling_policy.parent.mkdir(parents=True)
    digest = "sha256:" + hashlib.sha256(b"weights").hexdigest()
    payload = json.dumps(
        {
            "version": 2,
            "artifacts": [
                {"kind": "digest-pin", "artifact_path": "model.bin", "expected_sha256": digest}
            ],
        }
    )
    sibling_policy.write_text(payload, encoding="utf-8")
    with pytest.raises(SignaturePolicyError, match="outside the scanned project"):
        load_signature_policies(sibling_policy, project)

    world_dir = tmp_path / "world_policy"
    world_dir.mkdir()
    world_dir.chmod(0o777)
    world_policy = world_dir / "sig-policy.json"
    world_policy.write_text(payload, encoding="utf-8")
    with pytest.raises(SignaturePolicyError):
        load_signature_policies(world_policy, project)


def test_verify_attestation_rejects_world_writable_trusted_key(tmp_path: Path) -> None:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from nexus_symbiote.attestation import MAX_NATIVE_DEPTH, build_statement

    # Deeply nested JSON (> MAX_NATIVE_DEPTH and > MAX_JSON_NESTING) returns subject_format 'other'
    for depth in (MAX_NATIVE_DEPTH + 2, MAX_JSON_NESTING + 5):
        stmt = build_statement(
            b"[" * depth + b"]" * depth,
            name="deep.json",
            purpose="reviewed",
            signed_at=datetime(2026, 11, 14, 12, 0, tzinfo=UTC),
            source_revision=None,
        )
        assert stmt["predicate"]["subject_format"] == "other"

    runner = CliRunner()
    keys_dir = tmp_path / "keys"
    keys_dir.mkdir(mode=0o700)
    priv = keys_dir / "signer.key"
    pub = keys_dir / "signer.pub"
    assert (
        runner.invoke(
            main, ["runtime", "keygen", "--private-key", str(priv), "--public-key", str(pub)]
        ).exit_code
        == 0
    )
    work = tmp_path / "work"
    work.mkdir(mode=0o700)
    subject = work / "item.txt"
    subject.write_text("hello\n", encoding="utf-8")
    env = work / "item.att"
    assert (
        runner.invoke(
            main,
            [
                "attest",
                str(subject),
                "--key",
                str(priv),
                "--purpose",
                "reviewed",
                "--out",
                str(env),
            ],
        ).exit_code
        == 0
    )

    def _verify_with(key_path: Path) -> Any:
        return runner.invoke(
            main,
            [
                "verify-attestation",
                str(subject),
                str(env),
                "--trusted-key",
                str(key_path),
                "--purpose",
                "reviewed",
            ],
        )

    pub.chmod(0o666)
    res = _verify_with(pub)
    assert res.exit_code == 1
    assert "permission, or link checks" in res.output
    pub.chmod(0o600)

    ww_dir = tmp_path / "ww_keys"
    ww_dir.mkdir()
    ww_dir.chmod(0o777)
    ww_pub = ww_dir / "signer.pub"
    ww_pub.write_bytes(pub.read_bytes())
    ww_pub.chmod(0o600)
    res_dir = _verify_with(ww_pub)
    assert res_dir.exit_code == 1
    assert "world-writable" in res_dir.output

    oversized_pub = keys_dir / "oversized.pub"
    oversized_pub.write_bytes(b"A" * 70_000)
    oversized_pub.chmod(0o600)
    assert _verify_with(oversized_pub).exit_code == 1

    bad_pub = keys_dir / "bad.pub"
    bad_pub.write_bytes(b"not a pem key")
    bad_pub.chmod(0o600)
    assert _verify_with(bad_pub).exit_code == 1

    ec_key = ec.generate_private_key(ec.SECP256R1()).public_key()
    ec_pub = keys_dir / "ec.pub"
    ec_pub.write_bytes(
        ec_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    ec_pub.chmod(0o600)
    res_ec = _verify_with(ec_pub)
    assert res_ec.exit_code == 1
    assert "Ed25519" in res_ec.output


# ---------------------------------------------------------------------------
# NS-AUD-M02: Runtime SignerScope window, approval_actors, StateStore binding
# ---------------------------------------------------------------------------


def _runtime_fixture(tmp_path: Path) -> tuple[Any, ...]:
    now = datetime(2026, 11, 1, tzinfo=UTC)
    release = Ed25519PrivateKey.generate()
    human = Ed25519PrivateKey.generate()
    trust_key = Ed25519PrivateKey.generate()
    definition = {
        "name": "send",
        "description": "Send a message",
        "inputSchema": {"type": "object"},
    }
    context = ExecutionContext(
        agent_id="agent:triage",
        deployment_id="prod",
        tenant="acme",
        workload_identity="spiffe://acme/triage",
        policy_digest="sha256:" + "a" * 64,
    )
    call = ToolCall(
        server_id="server:mail",
        tool_name="send",
        action="send",
        resource="mailbox:team",
        arguments={"to": "team@example.test"},
    )
    bom = {"agent": "triage", "tools": ["send"]}
    grant = ToolGrant(
        server_id="server:mail",
        endpoint_identity="https://mail.example.test/mcp",
        tool_name="send",
        definition_digest=hash_tool_definition(
            "send", definition["description"], definition["inputSchema"]
        ),
        actions=("send",),
        resources=("mailbox:team",),
    )
    snapshot = ApprovedSnapshot(
        **context.model_dump(),
        serial=1,
        bom_digest=digest(bom),
        tools=(grant,),
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(hours=1),
    )
    statuses = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=30),
    )
    approval = ActionApproval(
        snapshot_digest=digest(snapshot.model_dump(mode="json")),
        context_digest=digest(context.model_dump(mode="json")),
        request_digest=digest(call.model_dump(mode="json")),
        nonce="c3f1b0a7d9e24f6b8a1c5d7e9f0b2a4c",
        actor="approver",
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=1),
    )
    executed: list[ToolCall] = []
    base_kwargs: dict[str, Any] = {
        "snapshot_keys": {key_id(release.public_key()): release.public_key()},
        "approval_keys": {key_id(human.public_key()): human.public_key()},
        "trust_keys": {key_id(trust_key.public_key()): trust_key.public_key()},
        "state": StateStore.initialize(tmp_path / "state.sqlite"),
        "authenticate": lambda: context,
        "describe": lambda *_: ServedTool(
            endpoint_identity=grant.endpoint_identity, definition=definition
        ),
        "execute": lambda c: executed.append(c) or "executed",
        "approval_actors": {key_id(human.public_key()): "approver"},
        "clock": lambda: now,
        "resolve_scope": lambda _c: ("send", "mailbox:team"),
    }
    return (
        now,
        base_kwargs,
        call,
        bom,
        snapshot,
        statuses,
        approval,
        release,
        human,
        trust_key,
        executed,
    )


def test_signer_scope_window_and_final_time_expiry_and_empty_approval_actors(
    tmp_path: Path,
) -> None:
    t0 = datetime(2026, 11, 14, 12, 0, tzinfo=UTC)
    with pytest.raises(ValidationError):
        SignerScope(not_before=t0, not_after=t0)
    with pytest.raises(ValidationError):
        SignerScope(not_before=t0 + timedelta(seconds=10), not_after=t0)

    (
        now,
        base_kwargs,
        call,
        bom,
        snapshot,
        statuses,
        approval,
        release,
        human,
        trust_key,
        executed,
    ) = _runtime_fixture(tmp_path)
    with pytest.raises(AuthorizationError) as actor_err:
        ReferenceGateway(**{**base_kwargs, "approval_actors": {}})
    assert actor_err.value.reason == "configuration-invalid"

    # Clock advances past SignerScope.not_after before StateStore.record check_time runs
    ticks = iter([now, now + timedelta(minutes=2)])
    scoped_gateway = ReferenceGateway(
        **{
            **base_kwargs,
            "clock": lambda: next(ticks, now + timedelta(minutes=2)),
            "signer_scopes": {
                key_id(release.public_key()): SignerScope(
                    tenants=frozenset({"acme"}),
                    not_before=now - timedelta(minutes=1),
                    not_after=now + timedelta(seconds=30),
                )
            },
        }
    )
    with pytest.raises(AuthorizationError) as expired_scope:
        scoped_gateway.invoke(
            call,
            bom=bom,
            snapshot=sign_contract(snapshot, "snapshot", (release,)),
            trust=sign_contract(statuses, "trust", (trust_key,)),
            approval=sign_contract(approval, "approval", (human,)),
        )
    assert expired_scope.value.reason == "signers-out-of-scope"
    assert executed == []


def test_statestore_refuses_symlinked_or_world_writable_parent_and_runtime_symlink_swap(
    tmp_path: Path,
) -> None:
    real_dir = tmp_path / "real_state"
    real_dir.mkdir(mode=0o700)
    linked_dir = tmp_path / "linked_state"
    linked_dir.symlink_to(real_dir, target_is_directory=True)
    with pytest.raises(AuthorizationError) as sym_init:
        StateStore.initialize(linked_dir / "state.sqlite")
    assert sym_init.value.reason == "state-invalid"

    world_dir = tmp_path / "world_state"
    world_dir.mkdir()
    world_dir.chmod(0o777)
    with pytest.raises(AuthorizationError) as world_init:
        StateStore.initialize(world_dir / "state.sqlite")
    assert world_init.value.reason == "state-invalid"

    db_path = real_dir / "state.sqlite"
    store = StateStore.initialize(db_path)
    other_db = real_dir / "other.sqlite"
    shutil.copyfile(db_path, other_db)
    db_path.unlink()
    with pytest.raises(AuthorizationError) as unlinked:
        store._check_path_binding()
    assert unlinked.value.reason == "state-unavailable"
    db_path.symlink_to(other_db)
    from nexus_symbiote.core.hashing import pathname_identity

    assert pathname_identity(db_path) is None
    with pytest.raises(AuthorizationError) as swapped:
        store.record(())
    assert swapped.value.reason == "state-invalid"

    # Concurrent symlink planted on FileExistsError during StateStore.initialize must not chmod victim
    victim = tmp_path / "victim_file.txt"
    victim.write_text("keep", encoding="utf-8")
    victim.chmod(0o644)
    race_parent = tmp_path / "race_parent"

    def _plant_symlink_mkdir(p: str | os.PathLike[str], mode: int = 0o777) -> None:
        Path(p).symlink_to(victim)
        raise FileExistsError(errno.EEXIST, "exists")

    real_mkdir = os.mkdir
    os.mkdir = _plant_symlink_mkdir  # type: ignore[assignment]
    try:
        with pytest.raises(AuthorizationError) as raced:
            StateStore.initialize(race_parent / "state.sqlite")
        assert raced.value.reason == "state-invalid"
    finally:
        os.mkdir = real_mkdir  # type: ignore[assignment]
    assert (victim.stat().st_mode & 0o777) == 0o644


def test_final_time_rechecks_distinct_human_approver_quorum_and_sticky_sig_policy(
    tmp_path: Path,
) -> None:
    (
        now,
        base_kwargs,
        call,
        bom,
        snapshot,
        statuses,
        approval,
        release,
        _human,
        trust_key,
        executed,
    ) = _runtime_fixture(tmp_path)
    alice_k1 = Ed25519PrivateKey.generate()
    alice_k2 = Ed25519PrivateKey.generate()
    bob_k1 = Ed25519PrivateKey.generate()
    ticks = iter([now, now + timedelta(seconds=45)])
    gw = ReferenceGateway(
        **{
            **base_kwargs,
            "approval_threshold": 2,
            "approval_keys": {
                key_id(alice_k1.public_key()): alice_k1.public_key(),
                key_id(alice_k2.public_key()): alice_k2.public_key(),
                key_id(bob_k1.public_key()): bob_k1.public_key(),
            },
            "approval_actors": {
                key_id(alice_k1.public_key()): "alice",
                key_id(alice_k2.public_key()): "alice",
                key_id(bob_k1.public_key()): "bob",
            },
            "signer_scopes": {
                key_id(bob_k1.public_key()): SignerScope(
                    tenants=frozenset({"acme"}),
                    not_before=now - timedelta(minutes=1),
                    not_after=now + timedelta(seconds=20),
                )
            },
            "clock": lambda: next(ticks, now + timedelta(seconds=45)),
        }
    )
    alice_approval = approval.model_copy(update={"actor": "alice"})
    with pytest.raises(AuthorizationError) as quorum_err:
        gw.invoke(
            call,
            bom=bom,
            snapshot=sign_contract(snapshot, "snapshot", (release,)),
            trust=sign_contract(statuses, "trust", (trust_key,)),
            approval=sign_contract(alice_approval, "approval", (alice_k1, alice_k2, bob_k1)),
        )
    assert quorum_err.value.reason == "approval-quorum-not-met"
    assert executed == []

    # Sticky 0o1777 caller-owned directory is accepted for signature policies while unsticky 0o777 fails
    sticky_dir = tmp_path / "sticky_policies"
    sticky_dir.mkdir()
    sticky_dir.chmod(0o1777)
    project = tmp_path / "proj"
    project.mkdir()
    (project / "m.bin").write_bytes(b"abc")
    pol = sticky_dir / "policy.json"
    pol.write_text(
        json.dumps(
            {
                "version": 2,
                "artifacts": [
                    {
                        "kind": "digest-pin",
                        "artifact_path": "m.bin",
                        "expected_sha256": hashlib.sha256(b"abc").hexdigest(),
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    pol.chmod(0o600)
    assert len(load_signature_policies(pol, project).digest_pins) == 1
    sticky_dir.chmod(0o777)
    with pytest.raises(SignaturePolicyError, match="world-writable"):
        load_signature_policies(pol, project)


def test_crypto_ancestor_and_raw_nofollow_failure_paths(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import stat

    from nexus_symbiote.utils import crypto as crypto_mod

    # 1. _trusted_ancestor_uids reads the real /proc files; the overflow uid is never
    #    trusted in a partial user namespace, and missing /proc stays fail-closed.
    orig_read_text = Path.read_text
    monkeypatch.setattr(crypto_mod.sys, "platform", "linux")
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **kw: (
            "1000 1000 1\n"
            if str(self) == "/proc/self/uid_map"
            else "65534\n"
            if str(self) == "/proc/sys/kernel/overflowuid"
            else orig_read_text(self, *a, **kw)
        ),
    )
    assert crypto_mod._trusted_ancestor_uids(1000) == {1000}
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **kw: (
            (_ for _ in ()).throw(OSError("no proc"))
            if str(self).startswith("/proc/")
            else orig_read_text(self, *a, **kw)
        ),
    )
    assert crypto_mod._trusted_ancestor_uids(1000) == {0, 1000}
    assert crypto_mod._trusted_ancestor_uids(65534) == {0}
    monkeypatch.undo()

    # 2. _ancestor_error covers darwin /var -> private/var normalization, lstat error, symlink, and foreign uid
    leaf = tmp_path / "sub" / "cache"
    leaf.mkdir(parents=True)
    orig_lstat = os.lstat

    monkeypatch.setattr(crypto_mod.sys, "platform", "darwin")
    monkeypatch.setattr(os.path, "islink", lambda p: p == "/var")
    monkeypatch.setattr(os, "readlink", lambda p: "private/var" if p == "/var" else "")
    monkeypatch.setattr(
        os,
        "lstat",
        lambda p: (
            (_ for _ in ()).throw(OSError("denied"))
            if str(p) == "/private/var"
            else orig_lstat(tmp_path)
        ),
    )
    err_lstat = crypto_mod._ancestor_error(
        Path("/var/folders/xx/cache"), dir_what="Cache dir", remedy="fix"
    )
    assert err_lstat is not None and "cannot be inspected" in err_lstat
    monkeypatch.undo()

    sym_stat = os.stat_result((stat.S_IFLNK | 0o777, 1, 1, 1, 0, 0, 0, 0, 0, 0))
    monkeypatch.setattr(
        os, "lstat", lambda p: sym_stat if Path(p) == leaf.parent else orig_lstat(p)
    )
    err_sym = crypto_mod._ancestor_error(leaf, dir_what="Cache dir", remedy="fix")
    assert err_sym is not None and "must not be a symlink" in err_sym
    monkeypatch.undo()

    foreign_stat = os.stat_result((stat.S_IFDIR | 0o755, 1, 1, 1, 424242, 0, 0, 0, 0, 0))
    monkeypatch.setattr(crypto_mod, "_current_uid", lambda: 1000)
    monkeypatch.setattr(crypto_mod, "_trusted_ancestor_uids", lambda _u: {0, 1000})
    monkeypatch.setattr(
        os, "lstat", lambda p: foreign_stat if Path(p) == leaf.parent else orig_lstat(p)
    )
    err_uid = crypto_mod._ancestor_error(leaf, dir_what="Cache dir", remedy="fix")
    assert err_uid is not None and "not owned by the current user" in err_uid
    monkeypatch.undo()

    # 3. _write_raw_nofollow cleans up temporary file on write failure and replace failure
    dir_fd = open_directory_nofollow(tmp_path)
    try:
        monkeypatch.setattr(
            os, "write", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("disk full"))
        )
        with pytest.raises(OSError, match="disk full"):
            crypto_mod._write_raw_nofollow(dir_fd, "target.json", b"payload")
        monkeypatch.undo()
        assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []

        monkeypatch.setattr(
            os, "replace", lambda *_a, **_kw: (_ for _ in ()).throw(OSError("replace denied"))
        )
        with pytest.raises(OSError, match="replace denied"):
            crypto_mod._write_raw_nofollow(dir_fd, "target.json", b"payload")
        monkeypatch.undo()
        assert [p.name for p in tmp_path.iterdir() if p.name.endswith(".tmp")] == []
    finally:
        os.close(dir_fd)

    # 4. _refresh_seeded_sigstore_cache returns original bytes on symlink parent, oversized sidecar, or modified root
    sym_parent = tmp_path / "sym_cache"
    sym_parent.symlink_to(leaf, target_is_directory=True)
    assert (
        crypto_mod._refresh_seeded_sigstore_cache(sym_parent / "trusted_root.json", b"custom")
        == b"custom"
    )

    sidecar = leaf / crypto_mod._SEEDED_ROOT_SIDECAR
    sidecar.write_bytes(b"a" * 200)
    assert (
        crypto_mod._refresh_seeded_sigstore_cache(leaf / "trusted_root.json", b"custom")
        == b"custom"
    )

    sidecar.write_text("0" * 64, encoding="ascii")
    assert (
        crypto_mod._refresh_seeded_sigstore_cache(leaf / "trusted_root.json", b"custom")
        == b"custom"
    )


# ---------------------------------------------------------------------------
# Review item 5: the overflow uid hides every unmapped owner and is never trusted
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("uid_map", "uid", "expected"),
    [
        # Initial user namespace: every uid is mapped, so 65534 is a real owner.
        ("         0          0 4294967295\n", 1000, {0, 1000}),
        ("         0          0 4294967295\n", 65534, {0, 65534}),
        # Rootful container namespace that maps 0 but not every uid.
        ("0 100000 65536\n", 1000, {0, 1000}),
        ("0 100000 65536\n", 65534, {0}),
        # Rootless namespace mapping only the caller: 0 is unmapped and host root,
        # like every other unmapped host user, shows as the overflow uid.
        ("      1000       1000          1\n", 1000, {1000}),
        ("1000 1000 1\n2000 200000 10\n", 1000, {1000}),
    ],
    ids=["full", "full-as-overflow", "partial-0", "partial-0-as-overflow", "rootless", "multi"],
)
def test_trusted_ancestor_uids_never_trust_the_overflow_uid_in_a_partial_namespace(
    monkeypatch: pytest.MonkeyPatch, uid_map: str, uid: int, expected: set[int]
) -> None:
    from nexus_symbiote.utils import crypto as crypto_mod

    monkeypatch.setattr(crypto_mod, "_read_uid_map", lambda: uid_map)
    monkeypatch.setattr(crypto_mod, "_overflow_uid", lambda: 65534)
    assert crypto_mod._trusted_ancestor_uids(uid) == expected


@pytest.mark.parametrize("uid_map", [None, "garbage\n", "0 0\n", "0 0 x\n", "0 0 \u0663\n"])
def test_trusted_ancestor_uids_unreadable_or_malformed_map_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch, uid_map: str | None
) -> None:
    from nexus_symbiote.utils import crypto as crypto_mod

    monkeypatch.setattr(crypto_mod, "_read_uid_map", lambda: uid_map)
    monkeypatch.setattr(crypto_mod, "_overflow_uid", lambda: 65534)
    monkeypatch.setattr(crypto_mod.sys, "platform", "linux")
    assert crypto_mod._trusted_ancestor_uids(1000) == {0, 1000}
    assert crypto_mod._trusted_ancestor_uids(65534) == {0}
    # Without user namespaces (macOS) there is no overflow uid to distrust.
    monkeypatch.setattr(crypto_mod.sys, "platform", "darwin")
    assert crypto_mod._trusted_ancestor_uids(65534) == {0, 65534}


@pytest.mark.parametrize(
    ("text", "expected"),
    [("65533\n", 65533), ("not a number\n", 65534), ("-1\n", 65534), ("4294967295\n", 65534)],
)
def test_overflow_uid_reads_the_kernel_value_or_defaults(
    monkeypatch: pytest.MonkeyPatch, text: str, expected: int
) -> None:
    from nexus_symbiote.utils import crypto as crypto_mod

    orig_read_text = Path.read_text
    monkeypatch.setattr(
        Path,
        "read_text",
        lambda self, *a, **kw: (
            text if str(self) == "/proc/sys/kernel/overflowuid" else orig_read_text(self, *a, **kw)
        ),
    )
    assert crypto_mod._overflow_uid() == expected


def test_read_uid_map_returns_none_when_proc_is_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from nexus_symbiote.utils import crypto as crypto_mod

    orig_read_text = Path.read_text

    def _no_proc(self: Path, *args: Any, **kwargs: Any) -> str:
        if str(self) == "/proc/self/uid_map":
            raise FileNotFoundError(errno.ENOENT, "no /proc")
        return orig_read_text(self, *args, **kwargs)

    monkeypatch.setattr(Path, "read_text", _no_proc)
    assert crypto_mod._read_uid_map() is None


def test_foreign_owner_shown_as_overflow_uid_is_refused_above_an_unpinned_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import stat

    from nexus_symbiote.utils import crypto as crypto_mod

    leaf = tmp_path / "sub" / "cache"
    leaf.mkdir(parents=True)
    monkeypatch.setattr(crypto_mod, "_current_uid", lambda: 1000)
    monkeypatch.setattr(crypto_mod, "_overflow_uid", lambda: 65534)

    def owned_by(owner: int) -> Any:
        """An lstat reporting every ancestor as a directory owned by ``owner``."""
        info = os.stat_result((stat.S_IFDIR | 0o755, 1, 1, 1, owner, 0, 0, 0, 0, 0))
        return lambda _path: info

    # Rootless namespace: an ancestor owned by any unmapped host user shows as 65534.
    monkeypatch.setattr(crypto_mod, "_read_uid_map", lambda: "1000 1000 1\n")
    monkeypatch.setattr(os, "lstat", owned_by(65534))
    error = crypto_mod._ancestor_error(leaf, dir_what="Cache dir", remedy="fix")
    assert error is not None and "not owned by the current user" in error
    # Initial namespace: root-owned and caller-owned ancestors are trusted.
    monkeypatch.setattr(crypto_mod, "_read_uid_map", lambda: "0 0 4294967295\n")
    monkeypatch.setattr(os, "lstat", owned_by(0))
    assert crypto_mod._ancestor_error(leaf, dir_what="Cache dir", remedy="fix") is None
    monkeypatch.setattr(os, "lstat", owned_by(1000))
    assert crypto_mod._ancestor_error(leaf, dir_what="Cache dir", remedy="fix") is None
    monkeypatch.setattr(os, "lstat", owned_by(65534))
    error = crypto_mod._ancestor_error(leaf, dir_what="Cache dir", remedy="fix")
    assert error is not None and "not owned by the current user" in error


def test_utf16_dsse_bundle_is_refused_as_unreadable_not_as_dsse() -> None:
    envelope = json.dumps({"dsseEnvelope": {}})
    common = ("sha256:" + "0" * 64, "signer@example.test", "https://issuer.example.test")
    utf8 = verify_sigstore_digest(common[0], envelope.encode("utf-8"), *common[1:])
    assert not utf8.verified and utf8.error == DSSE_UNSUPPORTED
    utf16 = verify_sigstore_digest(common[0], envelope.encode("utf-16"), *common[1:])
    assert not utf16.verified
    assert utf16.error == "Sigstore artifact verification failed (UnicodeDecodeError)"
