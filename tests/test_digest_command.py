"""``nexus-symbiote digest``: one read of a native inventory, three digests, nothing quoted."""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, MAX_NATIVE_BYTES, NativeFormatError
from nexus_symbiote.core.content_digest import (
    INVENTORY_CONTENT_PROFILE,
    inventory_content_digest,
)
from nexus_symbiote.core.inventory_digests import (
    NO_CONTENT_DIGEST,
    OUTSIDE_SNAPSHOT_BUDGET,
    TOO_DEEP_FOR_CONTENT_DIGEST,
    InventoryDigests,
    inventory_digests,
)
from nexus_symbiote.digest_cli import UNAVAILABLE
from nexus_symbiote.runtime import (
    MAX_BOM_BYTES,
    MAX_BOM_DEPTH,
    MAX_BOM_NODES,
    AuthorizationError,
    bom_digest,
)
from tests.support import scaling_ratio

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo-agent"
FIELDS = [
    "file_sha256",
    "canonical_digest",
    "content_digest",
    "content_profile",
    "spec_version",
    "components",
]
HOSTILE = "::error::forged ##[error]forged \x1b[31mred\u202edisguised\u200b <script>x</script>"
HOSTILE_PIECES = ["::error::", "##[error]", "\x1b", "\u202e", "\u200b", "<script>"]


def _digest(path: Path, *extra: str) -> Result:
    return CliRunner().invoke(main, ["digest", str(path), *extra])


def _scanned(
    tmp_path: Path, name: str = "bom.json", *, project: Path = DEMO, epoch: str | None = None
) -> Path:
    output = tmp_path / name
    result = CliRunner().invoke(
        main, ["scan", str(project), "-o", str(output)], env={"SOURCE_DATE_EPOCH": epoch}
    )
    assert result.exit_code == 0, result.output
    return output


def _expected(path: Path, *, undefined: tuple[str, ...] = ()) -> dict[str, Any]:
    """The values computed independently of the command and of ``inventory_digests``.

    Each digest named in ``undefined`` must be refused on its own, and is None.
    """
    raw = path.read_bytes()
    document = json.loads(raw)
    computed: dict[str, str | None] = {}
    for name, compute in (
        ("canonical_digest", bom_digest),
        ("content_digest", inventory_content_digest),
    ):
        if name in undefined:
            with pytest.raises(ValueError):
                compute(document)
            computed[name] = None
        else:
            computed[name] = compute(document)
    return {
        "file_sha256": "sha256:" + hashlib.sha256(raw).hexdigest(),
        **computed,
        "content_profile": "nexus-symbiote/inventory-content/v1",
        "spec_version": document.get("metadata", {}).get("spec_version", "1.0.0"),
        "components": len(document.get("components", [])),
    }


def test_digest_prints_every_field_on_its_own_line(tmp_path):
    inventory = _scanned(tmp_path)
    result = _digest(inventory)
    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    expected = _expected(inventory)
    assert result.stdout.splitlines() == [f"{name}: {expected[name]}" for name in FIELDS]
    assert expected["components"] == 11 and expected["spec_version"] == "1.2.0"


def test_json_output_is_one_object_with_the_same_values(tmp_path):
    inventory = _scanned(tmp_path)
    result = _digest(inventory, "--json-output")
    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    document = json.loads(result.stdout)
    assert list(document) == FIELDS
    assert document == _expected(inventory)


def test_the_output_is_the_same_bytes_every_time(tmp_path):
    inventory = _scanned(tmp_path)
    for flags in ((), ("--json-output",)):
        assert _digest(inventory, *flags).stdout_bytes == _digest(inventory, *flags).stdout_bytes


def test_the_canonical_digest_is_the_one_runtime_snapshots_bind(tmp_path):
    inventory = _scanned(tmp_path)
    runtime = CliRunner().invoke(main, ["runtime", "digest", str(inventory), "--kind", "bom"])
    assert runtime.exit_code == 0, runtime.output
    printed = json.loads(_digest(inventory, "--json-output").stdout)
    assert printed["canonical_digest"] == json.loads(runtime.stdout)["digest"]


def test_two_collections_of_one_project_share_only_the_content_digest(tmp_path):
    copies = [tmp_path / "laptop" / "demo-agent", tmp_path / "ci" / "demo-agent"]
    printed = []
    for index, (project, epoch) in enumerate(zip(copies, (None, "1767225600"), strict=True)):
        shutil.copytree(DEMO, project)
        inventory = _scanned(tmp_path, f"{index}.json", project=project, epoch=epoch)
        printed.append(json.loads(_digest(inventory, "--json-output").stdout))
    first, second = printed
    assert first["content_digest"] == second["content_digest"]
    assert first["file_sha256"] != second["file_sha256"]
    assert first["canonical_digest"] != second["canonical_digest"]
    # Without a recorded collection time, two collections are the same file.
    again = _scanned(tmp_path, "again.json", project=copies[1])
    assert json.loads(_digest(again, "--json-output").stdout) == first


def test_a_format_1_0_0_inventory_is_digested_as_read(tmp_path):
    example = ROOT / "schemas" / "examples" / "minimal-aibom.json"
    result = _digest(example, "--json-output")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == _expected(example)
    undeclared = json.loads(example.read_text())
    del undeclared["metadata"]["spec_version"]
    path = tmp_path / "undeclared.json"
    path.write_text(json.dumps(undeclared))
    printed = json.loads(_digest(path, "--json-output").stdout)
    assert printed["spec_version"] == "1.0.0"
    assert printed == _expected(path)


def _valid() -> dict[str, Any]:
    return {
        "metadata": {"spec_version": "1.1.0", "tool_name": "nexus-symbiote"},
        "components": [
            {"bom_ref": "tool:search", "component_type": "tool", "name": "search"},
        ],
        "dependencies": [],
    }


def _write_text(text: str) -> Callable[[Path], Path]:
    def write(path: Path) -> Path:
        path.write_text(text, encoding="utf-8")
        return path

    return write


def _write_bytes(data: bytes) -> Callable[[Path], Path]:
    def write(path: Path) -> Path:
        path.write_bytes(data)
        return path

    return write


def _symlink(path: Path) -> Path:
    target = path.with_name("target.json")
    target.write_text(json.dumps(_valid()))
    path.symlink_to(target)
    return path


def _fifo(path: Path) -> Path:
    os.mkfifo(path)
    return path


def _directory(path: Path) -> Path:
    path.mkdir()
    return path


def _nested(depth: int) -> str:
    return "[" * depth + "]" * depth


INVALID: dict[str, tuple[Callable[[Path], Path], str]] = {
    "not json": (
        _write_text("{not json"),
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused.",
    ),
    "duplicate keys": (
        _write_text('{"metadata": {}, "metadata": {}, "components": []}'),
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused.",
    ),
    "nonfinite number": (
        _write_text('{"metadata": {}, "components": [], "x": NaN}'),
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused.",
    ),
    "lone surrogate": (
        _write_text('{"metadata": {"tool_name": "\\ud800"}, "components": []}'),
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused.",
    ),
    "unsafe integer": (
        _write_text('{"metadata": {"version": 9007199254740993}, "components": []}'),
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused.",
    ),
    "deep nesting": (
        _write_text(_nested(100_000)),
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused.",
    ),
    "utf-16": (
        _write_bytes(json.dumps(_valid()).encode("utf-16")),
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused.",
    ),
    "utf-8 byte order mark": (
        _write_bytes(b"\xef\xbb\xbf" + json.dumps(_valid()).encode()),
        "It is not strict UTF-8 JSON; duplicate keys and nonfinite numbers are refused.",
    ),
    "wrong schema": (
        _write_text(json.dumps({"metadata": {}, "components": [{"bom_ref": "x"}]})),
        "It does not match the native AgentBOM schema.",
    ),
    "unknown field": (
        _write_text(json.dumps({**_valid(), "signature": HOSTILE})),
        "It does not match the native AgentBOM schema.",
    ),
    "not an object": (
        _write_text(json.dumps([_valid()])),
        "It does not match the native AgentBOM schema.",
    ),
    "unsupported version": (
        _write_text(json.dumps({"metadata": {"spec_version": "1.3.0"}, "components": []})),
        "Native format version 1.3.0 is not supported by this build (supported: 1.0.x, "
        "1.1.x, 1.2.x); upgrade nexus-symbiote or re-collect the inventory.",
    ),
    "hostile version": (
        _write_text(json.dumps({"metadata": {"spec_version": HOSTILE}, "components": []})),
        "Native format an unrecognised version is not supported by this build (supported: "
        "1.0.x, 1.1.x, 1.2.x); upgrade nexus-symbiote or re-collect the inventory.",
    ),
    "oversized": (
        _write_bytes(b" " * MAX_NATIVE_BYTES + b"{}"),
        "It exceeds the 16 MiB native inventory limit.",
    ),
    "symbolic link": (
        _symlink,
        "It is reached through a symbolic link or a path component that is not a "
        "directory; inventories are read without following links, so pass the real path.",
    ),
    "fifo": (
        _fifo,
        "It is not a regular file; FIFOs, devices, directories and standard input are refused.",
    ),
    "directory": (
        _directory,
        "It is not a regular file; FIFOs, devices, directories and standard input are refused.",
    ),
}


@pytest.mark.parametrize("case", sorted(INVALID))
def test_an_invalid_native_file_exits_1_with_the_fixed_reason(tmp_path, case):
    make, reason = INVALID[case]
    path = make(tmp_path / "inventory.json")
    for flags in ((), ("--json-output",)):
        result = _digest(path, *flags)
        assert result.exit_code == 1
        assert result.stdout == ""
        assert result.stderr == f"Error: {path} is not a valid native AIBOM file. {reason}\n"


def _deep_property(depth: int) -> dict[str, Any]:
    nested: Any = "leaf"
    for _ in range(depth):
        nested = {"n": nested}
    document = _valid()
    document["components"][0]["properties"] = {"deep": nested}
    return document


def _listed(value: Any, count: int) -> dict[str, Any]:
    document = _valid()
    document["components"][0]["properties"] = {"values": [value] * count}
    return document


def _described(text: str) -> dict[str, Any]:
    document = _valid()
    document["components"][0]["description"] = text
    return document


REASONS = {"canonical_digest": OUTSIDE_SNAPSHOT_BUDGET, "content_digest": NO_CONTENT_DIGEST}
WITHOUT_DIGESTS: dict[str, tuple[dict[str, Any], tuple[str, ...]]] = {
    "no components": ({"metadata": {"spec_version": "1.1.0"}}, ("content_digest",)),
    "nested beyond the snapshot budget": (_deep_property(61), ("canonical_digest",)),
    "more values than the snapshot budget": (
        _listed("", MAX_BOM_NODES + 1),
        ("canonical_digest",),
    ),
    "neither": (
        {"metadata": {"authors": [""] * (MAX_BOM_NODES + 1)}},
        ("canonical_digest", "content_digest"),
    ),
}


@pytest.mark.parametrize("case", sorted(WITHOUT_DIGESTS))
def test_an_inventory_without_a_digest_prints_the_others_and_exits_1(tmp_path, case):
    document, undefined = WITHOUT_DIGESTS[case]
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(document))
    AIBOM.load(path)
    expected = _expected(path, undefined=undefined)
    error = (
        f"Error: {path} is a valid native AIBOM file, but not every digest is defined for it. "
        + " ".join(REASONS[name] for name in undefined)
        + "\n"
    )
    as_json = _digest(path, "--json-output")
    assert as_json.exit_code == 1
    assert list(json.loads(as_json.stdout)) == FIELDS
    assert json.loads(as_json.stdout) == expected
    assert as_json.stderr == error
    text = _digest(path)
    assert text.exit_code == 1
    assert text.stdout.splitlines() == [
        f"{name}: {UNAVAILABLE if expected[name] is None else expected[name]}" for name in FIELDS
    ]
    assert text.stderr == error


# Each pair straddles one bound of the budget a runtime snapshot binds, while every file
# stays far below the 16 MiB a native inventory may have: the budget counts compact JSON
# with each character outside ASCII escaped and each number as 24 bytes, plus its comma.
BUDGET_BOUNDS: dict[str, tuple[Callable[[int], dict[str, Any]], int]] = {
    "basic multilingual plane": (lambda count: _described("☃" * count), MAX_BOM_BYTES // 6),
    "astral plane": (lambda count: _described("\U0001f600" * count), MAX_BOM_BYTES // 12),
    "numbers": (lambda count: _listed(0, count), MAX_BOM_BYTES // 25),
}


@pytest.mark.parametrize("case", sorted(BUDGET_BOUNDS))
def test_the_snapshot_budget_counts_escaped_json_not_file_bytes(tmp_path, case):
    make, bound = BUDGET_BOUNDS[case]
    under, over = tmp_path / "under.json", tmp_path / "over.json"
    under.write_text(json.dumps(make(bound - 1000), ensure_ascii=False), encoding="utf-8")
    over.write_text(json.dumps(make(bound + 1000), ensure_ascii=False), encoding="utf-8")
    assert over.stat().st_size < 0.6 * MAX_BOM_BYTES
    AIBOM.load(over)
    accepted = _digest(under, "--json-output")
    assert accepted.exit_code == 0, accepted.output
    assert json.loads(accepted.stdout) == _expected(under)
    refused = _digest(over, "--json-output")
    assert refused.exit_code == 1
    assert json.loads(refused.stdout) == _expected(over, undefined=("canonical_digest",))
    assert refused.stderr.endswith(f" {OUTSIDE_SNAPSHOT_BUDGET}\n")


def test_the_snapshot_budget_is_stated_as_runtime_measures_it():
    clause = (
        "runtime snapshot binds a document only when its compact JSON, with every character "
        "outside ASCII escaped and each number counted as 24 bytes, is at most "
        f"{MAX_BOM_BYTES // 2**20} MiB, it holds at most {MAX_BOM_NODES:,} values and no value "
        f"is nested more than {MAX_BOM_DEPTH} levels deep"
    )
    assert clause in OUTSIDE_SNAPSHOT_BUDGET
    for page in ("cli-reference.md", "reproducible-inventories.md"):
        text = " ".join((ROOT / "docs" / page).read_text(encoding="utf-8").split())
        assert clause in text, page


def test_an_inventory_just_inside_the_snapshot_budget_is_digested(tmp_path):
    # Its deepest value sits at depth 64, the last one a snapshot binds; one more is refused.
    path = tmp_path / "inventory.json"
    path.write_text(json.dumps(_deep_property(60)))
    result = _digest(path, "--json-output")
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == _expected(path)


def _hostile_inventory(tmp_path: Path) -> Path:
    document = json.loads(_scanned(tmp_path).read_text())
    for component in document["components"]:
        component["name"] = HOSTILE
        component["properties"]["note"] = HOSTILE
    path = tmp_path / "hostile.json"
    path.write_text(json.dumps(document))
    return path


def test_the_output_never_quotes_the_inventory(tmp_path):
    path = _hostile_inventory(tmp_path)
    text = _digest(path)
    assert text.exit_code == 0, text.output
    assert [line.split(": ", 1)[0] for line in text.stdout.splitlines()] == FIELDS
    as_json = _digest(path, "--json-output")
    assert as_json.exit_code == 0, as_json.output
    assert list(json.loads(as_json.stdout)) == FIELDS
    for result in (text, as_json):
        assert not any(piece in result.output for piece in HOSTILE_PIECES)


def test_an_error_never_quotes_the_inventory(tmp_path):
    path = _hostile_inventory(tmp_path)
    document = json.loads(path.read_text())
    document["components"][0]["trust_tier"] = HOSTILE
    path.write_text(json.dumps(document))
    result = _digest(path)
    assert result.exit_code == 1
    assert not any(piece in result.output for piece in HOSTILE_PIECES)


@pytest.mark.parametrize("content", ["{not json", json.dumps({"metadata": {}})])
def test_a_hostile_file_name_is_neutralized(tmp_path, content):
    """Both errors that name the file: an invalid inventory, and one without a digest."""
    path = tmp_path / "##[error]x\x1b[31m\u202e.json"
    path.write_text(content)
    result = _digest(path)
    assert result.exit_code == 1
    assert result.stderr.startswith("Error: ")
    assert "\x1b" not in result.stderr and "\u202e" not in result.stderr
    assert "##[error]" not in result.stderr and "##�[error]" in result.stderr


@pytest.mark.parametrize("args", [["digest"], ["digest", "missing.json"]])
def test_a_missing_inventory_is_a_usage_error(tmp_path, monkeypatch, args):
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 2
    assert result.stdout == ""


def test_inventory_digests_reads_the_bytes_once_and_names_each_undefined_digest(tmp_path):
    raw = _scanned(tmp_path).read_bytes()
    digests = inventory_digests(raw)
    assert digests == InventoryDigests(
        **{
            name: value
            for name, value in _expected(tmp_path / "bom.json").items()
            if name != "content_profile"
        }
    )
    assert digests.unavailable == ()
    assert INVENTORY_CONTENT_PROFILE == "nexus-symbiote/inventory-content/v1"
    with pytest.raises(NativeFormatError):
        inventory_digests(b"{not json")
    # Without a metadata object a document is read, and digested, as with an empty one.
    bare = json.dumps({"components": []}).encode()
    assert inventory_digests(bare) == InventoryDigests(
        file_sha256="sha256:" + hashlib.sha256(bare).hexdigest(),
        canonical_digest=bom_digest({"components": []}),
        content_digest=inventory_content_digest({"metadata": {}, "components": []}),
        spec_version="1.0.0",
        components=0,
    )
    headless = json.dumps({"metadata": {"spec_version": "1.1.0"}}).encode()
    assert inventory_digests(headless).unavailable == (NO_CONTENT_DIGEST,)
    deep = inventory_digests(json.dumps(_deep_property(70)).encode())
    assert deep.canonical_digest is None
    assert deep.content_digest == inventory_content_digest(_deep_property(70))
    assert deep.unavailable == (OUTSIDE_SNAPSHOT_BUDGET,)


def _raises(error: Exception) -> Callable[..., Any]:
    def fail(*_args: Any, **_kwargs: Any) -> Any:
        raise error

    return fail


def test_only_the_documented_refusals_leave_a_digest_undefined(monkeypatch):
    """Any other refusal is a defect, which the command reports as an internal error."""
    raw = json.dumps(_valid()).encode()
    content = "nexus_symbiote.core.content_digest.hash_canonical"
    with monkeypatch.context() as patch:
        patch.setattr(content, _raises(RecursionError()))
        deep = inventory_digests(raw)
    assert deep.canonical_digest == bom_digest(_valid())
    assert deep.content_digest is None
    assert deep.unavailable == (TOO_DEEP_FOR_CONTENT_DIGEST,)
    with monkeypatch.context() as patch:
        patch.setattr(content, _raises(ValueError("not a refusal of the profile")))
        with pytest.raises(ValueError, match="not a refusal of the profile"):
            inventory_digests(raw)
    with monkeypatch.context() as patch:
        mismatch = AuthorizationError("not the budget", reason="bom-mismatch")
        patch.setattr("nexus_symbiote.runtime.bom_digest", _raises(mismatch))
        with pytest.raises(AuthorizationError, match="not the budget"):
            inventory_digests(raw)


def test_from_native_reads_like_load_and_leaves_the_document_unchanged(tmp_path):
    for document in (json.loads(_scanned(tmp_path).read_text()), {"components": []}):
        before = copy.deepcopy(document)
        path = tmp_path / "copy.json"
        path.write_text(json.dumps(document))
        assert AIBOM.from_native(document) == AIBOM.load(path)
        assert document == before


def test_inventory_digests_work_is_linear():
    def inventory(components: int) -> bytes:
        document = _valid()
        document["components"] = [
            {
                "bom_ref": f"tool:{index}",
                "component_type": "tool",
                "name": f"tool {index}",
                "claims": {
                    "repository_presence": {
                        "method": "filesystem-inventory",
                        "scope": "repository",
                        "observed_at": "2026-01-01T00:00:00Z",
                    }
                },
            }
            for index in range(components)
        ]
        return json.dumps(document).encode()

    inputs = {scale: inventory(400 * scale) for scale in (1, 4)}
    assert scaling_ratio(lambda scale: inventory_digests(inputs[scale])) < 10
