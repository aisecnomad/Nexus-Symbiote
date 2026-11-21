"""Reproducible inventories: the content digest, its known-answer vectors, SOURCE_DATE_EPOCH.

Two collections of one checkout differ only in when, and in which run, they were made. The
content digest leaves exactly that out, wherever the native format records it and nowhere
else, and the serial number is derived from it. Without SOURCE_DATE_EPOCH no collection time
is recorded; with it, that instant is, and every format writes it identically.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
import shutil
import uuid
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner, Result

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM, NO_CONTENT_SERIAL
from nexus_symbiote.core.canonical import NAMESPACE
from nexus_symbiote.core.content_digest import (
    INVENTORY_CONTENT_PROFILE,
    NESTED_TOO_DEEPLY,
    NOT_AN_INVENTORY,
    inventory_content,
    inventory_content_digest,
)
from nexus_symbiote.core.hashing import parse_json_strict
from nexus_symbiote.core.models import AnyComponent, PromptComponent, ToolComponent
from nexus_symbiote.digest_cli import MALFORMED_EPOCH
from nexus_symbiote.scanners.base import Scanner, ScanResult
from nexus_symbiote.validators.risk import RiskScorer
from tests.support import scaling_ratio

ROOT = Path(__file__).resolve().parents[1]
DEMO = ROOT / "examples" / "demo-agent"
SHADOWSCAN_REPORT = ROOT / "tests" / "fixtures" / "shadowscan" / "code-report-0.1.4.json"
VECTORS = json.loads(
    (Path(__file__).parent / "vectors" / "inventory-content-v1.json").read_text(encoding="utf-8")
)
CASES = {case["id"]: case for case in VECTORS["vectors"]}
EPOCH = "1767225600"
PINNED = "2026-01-01T00:00:00Z"
OTHER_SERIAL = "urn:uuid:00000000-0000-4000-8000-000000000000"
TOP_LEVEL = {("metadata",), ("components",)}


def _usage(command: str, arguments: str) -> str:
    return (
        f"Usage: main {command} [OPTIONS] {arguments}\n"
        f"Try 'main {command} --help' for help.\n\nError: {MALFORMED_EPOCH}\n"
    )


def _checkout(tmp_path: Path, *parts: str) -> Path:
    target = tmp_path.joinpath(*parts, "demo-agent")
    shutil.copytree(DEMO, target)
    return target


def _invoke(*args: str, epoch: str | None = EPOCH) -> Result:
    return CliRunner().invoke(main, list(args), env={"SOURCE_DATE_EPOCH": epoch})


def _scan(project: Path, output: Path, *extra: str, epoch: str | None = EPOCH) -> dict[str, Any]:
    result = _invoke("scan", str(project), "-o", str(output), *extra, epoch=epoch)
    assert result.exit_code == 0, result.output
    document: dict[str, Any] = json.loads(output.read_text(encoding="utf-8"))
    return document


def _content_serial(document: dict[str, Any]) -> str:
    return f"urn:uuid:{uuid.uuid5(NAMESPACE, inventory_content_digest(document))}"


def _paths(value: Any, prefix: tuple[Any, ...] = ()) -> Iterator[tuple[Any, ...]]:
    if prefix:
        yield prefix
    if isinstance(value, dict):
        for key, item in value.items():
            yield from _paths(item, (*prefix, key))
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _paths(item, (*prefix, index))


def _is_event(path: tuple[Any, ...]) -> bool:
    return path in {
        ("metadata", "serial_number"),
        ("metadata", "timestamp"),
        ("metadata", "completeness", "timestamp"),
    } or (len(path) == 5 and path[0] == "components" and path[2:5:2] == ("claims", "observed_at"))


def _holder(document: Any, path: tuple[Any, ...]) -> Any:
    for step in path[:-1]:
        document = document[step]
    return document


def _set(document: dict[str, Any], path: tuple[Any, ...], value: Any) -> dict[str, Any]:
    changed = copy.deepcopy(document)
    target: Any = changed
    for step in path[:-1]:
        target = target.setdefault(step, {}) if isinstance(target, dict) else target[step]
    target[path[-1]] = value
    return changed


def _altered(value: Any) -> Any:
    if isinstance(value, bool):
        return not value
    if isinstance(value, int | float):
        return value + 1
    if isinstance(value, str):
        return value + "x"
    if value is None:
        return "x"
    if isinstance(value, list):
        return [*value, "x"]
    return {**value, "x": "x"}


def test_vector_file_names_the_current_profile():
    assert VECTORS["profile"] == INVENTORY_CONTENT_PROFILE == "nexus-symbiote/inventory-content/v1"
    assert VECTORS["subject"] == "nexus_symbiote.core.content_digest.inventory_content_digest"
    assert "new profile version" in VECTORS["note"]
    assert set(CASES) == {"native-1.1.0", "undeclared-1.0.0", "shapes-stay-content"}


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_inventory_content_known_answer(case_id):
    case = CASES[case_id]
    assert inventory_content_digest(case["document"]) == case["digest"]
    # The preimage is pinned too, so a digest cannot match through a shared mistake.
    assert "sha256:" + hashlib.sha256(case["content"].encode("utf-8")).hexdigest() == case["digest"]


def _hand_built_content(case_id: str, document: dict[str, Any]) -> dict[str, Any]:
    """The expected content of each vector, written out without the code under test."""
    expected = copy.deepcopy(document)
    metadata = expected["metadata"]
    if case_id == "native-1.1.0":
        del metadata["serial_number"], metadata["timestamp"]
        del metadata["completeness"]["timestamp"]
        del metadata["completeness"]["source_report_path"]
        server, tool = expected["components"]
        del server["claims"]["repository_presence"]["observed_at"]
        del server["claims"]["operator_review"]["observed_at"]
        del tool["claims"]["repository_presence"]["observed_at"]
    elif case_id == "undeclared-1.0.0":
        del metadata["serial_number"]
    return expected


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_known_answer_matches_an_independent_canonicalization(case_id):
    case = CASES[case_id]
    expected = _hand_built_content(case_id, case["document"])
    # With integer numbers and ASCII keys only, sorted compact JSON is the RFC 8785 text:
    # another canonicalizer and a hand-written removal agree on the pinned preimage.
    independent = json.dumps(expected, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    assert independent == case["content"]
    assert inventory_content(case["document"]) == expected


@pytest.mark.parametrize("case_id", sorted(CASES))
def test_vector_documents_are_native_inventories(case_id):
    bom = AIBOM.from_native(CASES[case_id]["document"])
    assert bom.metadata.spec_version == ("1.0.0" if case_id == "undeclared-1.0.0" else "1.1.0")


def test_two_collections_at_different_paths_and_times_have_one_content_digest(tmp_path):
    first = _scan(_checkout(tmp_path, "laptop"), tmp_path / "first.json", epoch=None)
    second = _scan(_checkout(tmp_path, "ci", "runner"), tmp_path / "second.json", epoch="0")
    third = _scan(_checkout(tmp_path, "renamed"), tmp_path / "third.json", epoch=None)
    assert "timestamp" not in first["metadata"]
    assert second["metadata"]["timestamp"] == "1970-01-01T00:00:00Z"
    assert inventory_content_digest(first) == inventory_content_digest(second)
    assert inventory_content_digest(first) == inventory_content_digest(third)
    # The serial number names the content, so the recorded time does not change it.
    serials = {doc["metadata"]["serial_number"] for doc in (first, second, third)}
    assert serials == {_content_serial(first)}


def test_every_value_outside_the_collection_event_is_content(tmp_path):
    document = _scan(DEMO, tmp_path / "bom.json")
    original = inventory_content_digest(document)
    paths = list(_paths(document))
    for path in paths:
        holder, key = _holder(document, path), path[-1]
        value = holder[key]
        holder[key] = _altered(value)
        # An event field that no longer holds an event value is content again.
        assert inventory_content_digest(document) != original, path
        holder[key] = value
        if isinstance(holder, dict) and not _is_event(path) and path not in TOP_LEVEL:
            del holder[key]
            assert inventory_content_digest(document) != original, path
            holder[key] = value
    assert inventory_content_digest(document) == original
    assert len(paths) > 500
    without_components = {key: value for key, value in document.items() if key != "components"}
    with pytest.raises(ValueError, match=NOT_AN_INVENTORY):
        inventory_content_digest(without_components)
    # Readers fill in an absent metadata object as empty, so the digest does too.
    bare = {key: value for key, value in document.items() if key != "metadata"}
    assert inventory_content_digest(bare) == inventory_content_digest({**bare, "metadata": {}})
    assert inventory_content_digest(bare) != original


def test_collection_event_values_are_left_out_where_the_format_records_them(tmp_path):
    document = _scan(DEMO, tmp_path / "bom.json")
    original = inventory_content_digest(document)
    events = [path for path in _paths(document) if _is_event(path)]
    observed = [
        claim
        for component in document["components"]
        for claim in component["claims"].values()
        if "observed_at" in claim
    ]
    assert len(events) == 3 + len(observed) and len(observed) >= 10
    for path in events:
        holder, key = _holder(document, path), path[-1]
        value = holder[key]
        other = OTHER_SERIAL if key == "serial_number" else "1999-12-31T23:59:59.999999999+14:00"
        for replacement in (other, None):
            holder[key] = replacement
            assert inventory_content_digest(document) == original, path
        del holder[key]
        assert inventory_content_digest(document) == original, path
        holder[key] = value


def _reorder(document: dict[str, Any]) -> None:
    document["components"].reverse()


def _drop_edge(document: dict[str, Any]) -> None:
    document["dependencies"].clear()


def _fail_collection(document: dict[str, Any]) -> None:
    document["metadata"]["completeness"]["scan_failures"].append("mcp: .mcp.json: invalid JSON")


def _set_at(path: tuple[Any, ...], value: Any) -> Any:
    def apply(document: dict[str, Any]) -> None:
        _holder(document, path)[path[-1]] = value

    return apply


CONTENT_CHANGES = {
    "component field": _set_at(("components", 1, "description"), "Search everything"),
    "component property": _set_at(("components", 0, "properties", "note"), "Cafe"),
    "claim evidence": _set_at(
        ("components", 0, "claims", "repository_presence", "locator"), "other.json"
    ),
    "relationship": _set_at(("dependencies", 0, "relationship"), "depends-on"),
    "relationship removed": _drop_edge,
    "coverage record": _fail_collection,
    "collector status": _set_at(("metadata", "completeness", "scanner_status", "mcp"), "partial"),
    "tool_version": _set_at(("metadata", "tool_version"), "0.1.1"),
    "spec_version": _set_at(("metadata", "spec_version"), "1.0.0"),
    "policy_source": _set_at(("metadata", "policy_source"), "project:.nexus-symbiote.yaml"),
    "component order": _reorder,
}


@pytest.mark.parametrize("change", sorted(CONTENT_CHANGES))
def test_a_change_to_recorded_content_changes_the_digest(change):
    document = copy.deepcopy(CASES["native-1.1.0"]["document"])
    original = inventory_content_digest(document)
    CONTENT_CHANGES[change](document)
    assert inventory_content_digest(document) != original


DECOYS = [
    ("components", 0, "properties", "timestamp"),
    ("components", 0, "properties", "observed_at"),
    ("components", 0, "properties", "serial_number"),
    ("components", 0, "properties", "deployment_profile", "observed_at"),
    ("components", 0, "timestamp"),
    ("components", 0, "observed_at"),
    ("components", 0, "serial_number"),
    ("components", 0, "last_indexed_at"),
    ("components", 0, "expires_at"),
    ("components", 0, "claims", "repository_presence", "timestamp"),
    ("components", 0, "claims", "repository_presence", "serial_number"),
    ("metadata", "observed_at"),
    ("metadata", "completeness", "observed_at"),
    ("metadata", "completeness", "serial_number"),
    ("components", 0, "properties", "source_report_path"),
    ("components", 0, "source_report_path"),
    ("components", 0, "claims", "repository_presence", "source_report_path"),
    ("metadata", "source_report_path"),
    ("dependencies", 0, "timestamp"),
    ("dependencies", 0, "observed_at"),
    ("timestamp",),
    ("serial_number",),
]


@pytest.mark.parametrize("path", DECOYS, ids=["/".join(map(str, path)) for path in DECOYS])
def test_an_event_name_anywhere_else_stays_content(path):
    """A change cannot hide behind a key that is merely named like a collection event."""
    document = CASES["native-1.1.0"]["document"]
    original = inventory_content_digest(document)
    first = inventory_content_digest(_set(document, path, "2030-01-01T00:00:00Z"))
    second = inventory_content_digest(_set(document, path, "2030-01-02T00:00:00Z"))
    serial = inventory_content_digest(_set(document, path, OTHER_SERIAL))
    null = inventory_content_digest(_set(document, path, None))
    assert len({original, first, second, serial, null}) == 5


def test_the_import_location_is_left_out_only_when_it_is_text():
    document = CASES["native-1.1.0"]["document"]
    original = inventory_content_digest(document)
    path = ("metadata", "completeness", "source_report_path")
    for location in ("elsewhere/report.json", "", "::error::forged"):
        assert inventory_content_digest(_set(document, path, location)) == original
    without = copy.deepcopy(document)
    del without["metadata"]["completeness"]["source_report_path"]
    assert inventory_content_digest(without) == original
    for other in (None, 7, ["report.json"], {"path": "report.json"}):
        assert inventory_content_digest(_set(document, path, other)) != original, other


def test_the_document_is_not_changed():
    document = copy.deepcopy(CASES["native-1.1.0"]["document"])
    before = copy.deepcopy(document)
    content = inventory_content(document)
    inventory_content_digest(document)
    assert document == before
    assert "serial_number" not in content["metadata"]
    assert document["metadata"]["serial_number"] == before["metadata"]["serial_number"]


NOT_INVENTORIES = {
    "list": [],
    "string": "::error::not an inventory",
    "null": None,
    "number": 3,
    "empty object": {},
    "no components": {"metadata": {}},
    "metadata list": {"metadata": [], "components": []},
    "metadata null": {"metadata": None, "components": []},
    "metadata text": {"metadata": "##[error]x", "components": []},
    "components object": {"metadata": {}, "components": {}},
    "components null": {"metadata": {}, "components": None},
    "components text": {"metadata": {}, "components": "\x1b[31m"},
}


@pytest.mark.parametrize("name", sorted(NOT_INVENTORIES))
def test_a_document_that_is_not_an_inventory_raises_the_fixed_error(name):
    with pytest.raises(ValueError) as raised:
        inventory_content_digest(NOT_INVENTORIES[name])
    assert str(raised.value) == NOT_AN_INVENTORY


def _deep_inventory_text(depth: int) -> str:
    deep = "[" * depth + "]" * depth
    return '{"metadata": {}, "components": [{"properties": {"deep": ' + deep + "}}]}"


def test_a_document_nested_too_deeply_raises_the_fixed_error_not_recursion():
    nested: list[Any] = []
    for _ in range(5000):
        nested = [nested]
    with pytest.raises(ValueError) as raised:
        inventory_content_digest({"metadata": {}, "components": [{"deep": nested}]})
    assert str(raised.value) == NESTED_TOO_DEEPLY
    # The deepest document the strict parser still accepts is digested or refused the same
    # way: a caller that read it never meets a RecursionError here.
    low, high = 1, 5000
    while low < high:
        middle = (low + high + 1) // 2
        try:
            parse_json_strict(_deep_inventory_text(middle))
            low = middle
        except (ValueError, RecursionError):
            high = middle - 1
    for depth in (low - 1, low):
        try:
            digest = inventory_content_digest(parse_json_strict(_deep_inventory_text(depth)))
        except ValueError as exc:
            assert str(exc) == NESTED_TOO_DEEPLY
        else:
            assert digest.startswith("sha256:")


def test_format_1_0_0_inventories_have_a_content_digest():
    path = ROOT / "schemas" / "examples" / "minimal-aibom.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    assert AIBOM.load(path).metadata.spec_version == "1.0.0"
    undeclared = copy.deepcopy(document)
    del undeclared["metadata"]["spec_version"]
    assert AIBOM.from_native(undeclared).metadata.spec_version == "1.0.0"
    digests = {inventory_content_digest(document), inventory_content_digest(undeclared)}
    assert len(digests) == 2
    assert all(digest.startswith("sha256:") and len(digest) == 71 for digest in digests)


def _inventory(components: int, claims: int) -> dict[str, Any]:
    evidence = {"assurance": "observed", "method": "m", "scope": "repository"}
    return {
        "metadata": {"spec_version": "1.1.0", "serial_number": OTHER_SERIAL, "timestamp": PINNED},
        "components": [
            {
                "bom_ref": f"tool:{index}",
                "component_type": "tool",
                "name": f"tool {index}",
                "properties": {"observed_at": PINNED, "values": list(range(4))},
                "claims": {
                    f"claim-{claim}": {**evidence, "observed_at": PINNED} for claim in range(claims)
                },
            }
            for index in range(components)
        ],
        "dependencies": [],
    }


@pytest.mark.parametrize("grows", ["components", "claims"])
def test_content_digest_work_is_linear(grows):
    documents = {
        scale: _inventory(500 * scale, 4) if grows == "components" else _inventory(50, 40 * scale)
        for scale in (1, 4)
    }
    assert scaling_ratio(lambda scale: inventory_content_digest(documents[scale])) < 10


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx", "sarif"])
def test_pinned_scans_of_two_checkouts_are_byte_identical(tmp_path, monkeypatch, output_format):
    outputs = []
    for parts in (("laptop",), ("ci", "runner", "work")):
        project = _checkout(tmp_path, *parts)
        output = tmp_path / f"{len(outputs)}.{output_format}"
        # From inside the checkout, as CI and the pre-commit hooks scan.
        monkeypatch.chdir(project)
        result = _invoke("scan", ".", "-f", output_format, "-o", str(output))
        assert result.exit_code == 0, result.output
        outputs.append(output.read_bytes())
    assert outputs[0] == outputs[1]
    assert PINNED.removesuffix("Z").encode() in outputs[0]


def test_sarif_locations_follow_the_working_directory(tmp_path, monkeypatch):
    """The documented condition: the scanned directory at one path below the working
    directory in both scans, or below it in neither."""
    first, second = _checkout(tmp_path, "one"), _checkout(tmp_path, "two", "x")
    (tmp_path / "elsewhere").mkdir()
    names = iter(range(20))

    def scanned(cwd: Path, project: Path, output_format: str = "sarif") -> str:
        monkeypatch.chdir(cwd)
        output = tmp_path / f"{next(names)}.out"
        result = _invoke("scan", str(project), "-f", output_format, "-o", str(output))
        assert result.exit_code == 0, result.output
        return output.read_text(encoding="utf-8")

    assert scanned(tmp_path, first, "json") == scanned(tmp_path, second, "json")
    below = [scanned(tmp_path, first), scanned(tmp_path, second)]
    assert '"uri": "one/demo-agent/.mcp.json"' in below[0]
    assert '"uri": "two/x/demo-agent/.mcp.json"' in below[1]
    assert scanned(first.parent, first) == scanned(second.parent, second)
    neither = {
        scanned(project_cwd, project)
        for project in (first, second)
        for project_cwd in (project, project / "models", tmp_path / "elsewhere")
    }
    (only,) = neither
    assert '"uri": ".mcp.json"' in only
    condition = (
        "relative to the working directory when the scanned directory lies below it, and "
        "relative to the scanned directory otherwise"
    )
    for page in ("reproducible-inventories.md", "cli-reference.md"):
        text = " ".join((ROOT / "docs" / page).read_text(encoding="utf-8").split())
        assert condition in text, page
        assert "below the working directory in both scans, or below it in neither" in text, page


def test_a_pinned_scan_records_the_instant_and_a_content_serial_number(tmp_path):
    document = _scan(DEMO, tmp_path / "bom.json")
    metadata = document["metadata"]
    assert metadata["timestamp"] == metadata["completeness"]["timestamp"] == PINNED
    stamps = [
        claim["observed_at"]
        for component in document["components"]
        for claim in component["claims"].values()
        if "observed_at" in claim
    ]
    assert len(stamps) >= 10 and set(stamps) == {PINNED}
    assert metadata["serial_number"] == _content_serial(document)
    assert uuid.UUID(metadata["serial_number"].removeprefix("urn:uuid:")).version == 5
    # Another instant changes the time, never the serial number: it names the content.
    later = _scan(DEMO, tmp_path / "later.json", epoch="1767225601")
    assert later["metadata"]["serial_number"] == metadata["serial_number"]
    assert later["metadata"]["timestamp"] == "2026-01-01T00:00:01Z"


def test_without_the_variable_a_scan_records_no_time_and_the_same_serial(tmp_path):
    # The suite removes an ambient value (conftest); the release job exports one.
    assert "SOURCE_DATE_EPOCH" not in os.environ
    first = _scan(DEMO, tmp_path / "first.json", epoch=None)
    _scan(DEMO, tmp_path / "second.json", epoch=None)
    assert (tmp_path / "first.json").read_bytes() == (tmp_path / "second.json").read_bytes()
    metadata = first["metadata"]
    assert "timestamp" not in metadata and "timestamp" not in metadata["completeness"]
    assert not [
        claim
        for component in first["components"]
        for claim in component["claims"].values()
        if "observed_at" in claim
    ]
    assert metadata["serial_number"] == _content_serial(first)
    pinned = _scan(DEMO, tmp_path / "pinned.json")
    assert inventory_content_digest(first) == inventory_content_digest(pinned)
    assert pinned["metadata"]["serial_number"] == metadata["serial_number"]


MALFORMED = [
    "",
    "-1",
    "1.5",
    "0x10",
    "1234567890123",
    # Thirteen digits whose value is 1: only the bound on the number of digits refuses it.
    "0000000000001",
    " 12",
    "12 ",
    "12\n",
    "+12",
    "1e3",
    "1_000",
    "１２",
    "\u202e12",
    "253402300800",
    "999999999999",
    "::error::forged",
    "##[error]forged",
    "\x1b[31m12",
]


@pytest.mark.parametrize("value", MALFORMED, ids=[repr(value) for value in MALFORMED])
def test_a_malformed_epoch_is_a_usage_error_that_does_not_echo_it(tmp_path, value):
    output = tmp_path / "bom.json"
    result = _invoke("scan", str(DEMO), "-o", str(output), epoch=value)
    assert result.exit_code == 2
    assert result.stdout == ""
    # The whole output is fixed text, so the value cannot be in it.
    assert result.stderr == _usage("scan", "[PROJECT_PATH]")
    assert not output.exists()


def test_a_malformed_epoch_is_refused_before_collection_even_without_output(tmp_path):
    result = _invoke("scan", str(DEMO), "--check", epoch="soon")
    assert result.exit_code == 2
    assert result.stderr == _usage("scan", "[PROJECT_PATH]")
    assert "Running" not in result.output


@pytest.mark.parametrize(
    "value,stamp",
    [
        ("0", "1970-01-01T00:00:00Z"),
        ("000000000001", "1970-01-01T00:00:01Z"),
        ("253402300799", "9999-12-31T23:59:59Z"),
    ],
)
def test_the_whole_representable_range_is_accepted(tmp_path, value, stamp):
    project = tmp_path / "project"
    project.mkdir()
    (project / "system_prompt.md").write_text("Answer from the documentation only.\n")
    document = _scan(project, tmp_path / "bom.json", "--report-only", epoch=value)
    assert document["metadata"]["timestamp"] == stamp
    # Every export accepts the instant too, after its own schema validation.
    for output_format in ("cyclonedx", "spdx", "sarif"):
        output = tmp_path / f"bom.{output_format}"
        args = ("scan", str(project), "--report-only", "-f", output_format, "-o", str(output))
        result = _invoke(*args, epoch=value)
        assert result.exit_code == 0, result.output
        assert stamp.removesuffix("Z") in output.read_text(encoding="utf-8")


def test_pinned_baselines_of_two_checkouts_equal_the_pinned_scan(tmp_path):
    files = []
    for parts in (("one",), ("two", "nested")):
        target = tmp_path / f"baseline-{len(files)}.json"
        result = _invoke("baseline", str(_checkout(tmp_path, *parts)), "-o", str(target))
        assert result.exit_code == 0, result.output
        files.append(target.read_bytes())
    _scan(DEMO, tmp_path / "scan.json")
    assert files[0] == files[1] == (tmp_path / "scan.json").read_bytes()


def test_vex_documents_of_pinned_inventories_are_identical(tmp_path):
    texts = []
    for parts in (("one",), ("two", "nested")):
        inventory = tmp_path / f"{len(texts)}.json"
        _scan(_checkout(tmp_path, *parts), inventory)
        result = _invoke("vex", str(inventory), "-o", str(tmp_path / f"{len(texts)}.vex.json"))
        assert result.exit_code == 0, result.output
        texts.append((tmp_path / f"{len(texts)}.vex.json").read_bytes())
    assert texts[0] == texts[1]


def _embedded_native(export: dict[str, Any]) -> dict[str, Any]:
    if "bomFormat" in export:
        properties = {item["name"]: item["value"] for item in export["metadata"]["properties"]}
    else:
        [node] = [node for node in export["@graph"] if node.get("type") == "SpdxDocument"]
        properties = {
            item["extension_cdxPropName"]: item["extension_cdxPropValue"]
            for extension in node["extension"]
            if extension.get("type") == "extension_CdxPropertiesExtension"
            for item in extension["extension_cdxProperty"]
        }
    document: dict[str, Any] = json.loads(properties["nexus-symbiote:document"])
    return document


@pytest.mark.parametrize("epoch", [EPOCH, None])
@pytest.mark.parametrize("output_format", ["cyclonedx", "spdx"])
def test_an_export_embeds_the_native_document_and_carries_its_serial(
    tmp_path, output_format, epoch
):
    """Components and dependencies are written sorted, so the embedded copy is the file."""
    native = _scan(DEMO, tmp_path / "bom.json", epoch=epoch)
    export = tmp_path / f"bom.{output_format}"
    result = _invoke("scan", str(DEMO), "-f", output_format, "-o", str(export), epoch=epoch)
    assert result.exit_code == 0, result.output
    exported = json.loads(export.read_text(encoding="utf-8"))
    embedded = _embedded_native(exported)
    assert embedded == native
    serial = native["metadata"]["serial_number"]
    assert serial == _content_serial(native)
    assert exported.get("serialNumber", serial) == serial
    refs = [component["bom_ref"] for component in native["components"]]
    assert refs == sorted(refs)
    page = " ".join((ROOT / "docs" / "reproducible-inventories.md").read_text("utf-8").split())
    assert "anyone who holds the native JSON file can recompute it from that file" in page


def test_list_order_in_a_document_another_build_wrote_is_content():
    """The documented limit: an unsorted file has another digest than its sorted rewrite."""
    document = copy.deepcopy(CASES["native-1.1.0"]["document"])
    original = inventory_content_digest(document)
    document["components"].reverse()
    assert inventory_content_digest(document) != original
    page = " ".join((ROOT / "docs" / "reproducible-inventories.md").read_text("utf-8").split())
    assert "written by another build" in page


def test_a_malformed_epoch_stops_baseline_and_leaves_nothing_behind(tmp_path):
    directory = tmp_path / "out"
    directory.mkdir()
    result = _invoke("baseline", str(DEMO), "-o", str(directory / "baseline.json"), epoch="x")
    assert result.exit_code == 2
    assert result.stderr.endswith(f"Error: {MALFORMED_EPOCH}\n")
    assert list(directory.iterdir()) == []


@pytest.mark.parametrize("output_format", ["json", "cyclonedx", "spdx"])
def test_pinned_imports_of_a_shadowscan_report_are_byte_identical(tmp_path, output_format):
    files = []
    for name in ("first", "second"):
        target = tmp_path / name / f"bom.{output_format}"
        target.parent.mkdir()
        args = ("import-shadowscan", str(SHADOWSCAN_REPORT), "--report-only", "-f", output_format)
        result = _invoke(*args, "-o", str(target))
        assert result.exit_code == 0, result.output
        files.append(target.read_bytes())
    assert files[0] == files[1]
    if output_format == "json":
        document = json.loads(files[0])
        assert document["metadata"]["timestamp"] == PINNED
        assert document["metadata"]["serial_number"] == _content_serial(document)
        # The producer check ignores the import time and serial number, pinned or not.
        args = ("verify-discovery", str(tmp_path / "first" / "bom.json"), str(SHADOWSCAN_REPORT))
        verified = _invoke(*args, "--projection", epoch=None)
        assert verified.exit_code == 0, verified.output


def test_unpinned_imports_record_no_time_and_are_byte_identical(tmp_path):
    files = []
    for name in ("first", "second"):
        target = tmp_path / name / "bom.json"
        target.parent.mkdir()
        args = ("import-shadowscan", str(SHADOWSCAN_REPORT), "--report-only")
        result = _invoke(*args, "-o", str(target), epoch=None)
        assert result.exit_code == 0, result.output
        files.append(target.read_bytes())
    assert files[0] == files[1]
    document = json.loads(files[0])
    assert "timestamp" not in document["metadata"]
    assert document["metadata"]["serial_number"] == _content_serial(document)


def test_imports_of_one_report_under_two_names_share_the_serial_and_content(tmp_path):
    documents = []
    for name in ("report.json", "renamed-report.json"):
        report = tmp_path / name
        shutil.copyfile(SHADOWSCAN_REPORT, report)
        target = tmp_path / f"{name}.bom.json"
        args = ("import-shadowscan", str(report), "--report-only", "-o", str(target))
        result = _invoke(*args, epoch=None)
        assert result.exit_code == 0, result.output
        documents.append(json.loads(target.read_text(encoding="utf-8")))
    first, second = documents
    paths = [doc["metadata"]["completeness"]["source_report_path"] for doc in documents]
    assert paths == ["report.json", "renamed-report.json"]
    assert inventory_content_digest(first) == inventory_content_digest(second)
    assert first["metadata"]["serial_number"] == second["metadata"]["serial_number"]
    assert first["metadata"]["serial_number"] == _content_serial(first)
    second["metadata"]["completeness"]["source_report_path"] = "report.json"
    assert first == second


def test_a_malformed_epoch_stops_import_shadowscan_before_it_writes(tmp_path):
    target = tmp_path / "bom.json"
    args = ("import-shadowscan", str(SHADOWSCAN_REPORT), "--report-only", "-o", str(target))
    result = _invoke(*args, epoch="-5")
    assert result.exit_code == 2
    assert result.stderr == _usage("import-shadowscan", "REPORT_PATH")
    assert not target.exists()


def _project_with_suppressed_pickle(tmp_path: Path, expires: str) -> Path:
    project = tmp_path / "project"
    (project / "models").mkdir(parents=True)
    (project / "AGENTS.md").write_text("Use read-only tools.\n")
    (project / "models" / "classifier.pkl").write_bytes(b"\x80\x04N.")
    inventory = tmp_path / "unsuppressed.json"
    _invoke("scan", str(project), "--no-project-policy", "--report-only", "-o", str(inventory))
    (fingerprint,) = [
        finding.fingerprint
        for finding in RiskScorer().score(AIBOM.load(inventory)).findings
        if finding.component_ref == "model:models/classifier.pkl"
        and finding.category == "serialization_format"
    ]
    (project / ".nexus-symbiote.yaml").write_text(
        "risk:\n  suppressions:\n"
        '    - component_ref: "model:models/classifier.pkl"\n'
        '      category: "serialization_format"\n'
        f'      fingerprint: "{fingerprint}"\n'
        '      reason: "Test fixture, never loaded"\n'
        '      owner: "security@example.test"\n'
        f"      expires: {expires}\n"
    )
    return project


def test_a_pinned_clock_does_not_revive_an_expired_suppression(tmp_path):
    """SOURCE_DATE_EPOCH, often a commit time an author chooses, never moves a gate's clock."""
    before_expiry = "1748736000"  # 2025-06-01, before the suppression expired on 2026-01-01
    active = _project_with_suppressed_pickle(tmp_path / "active", "2999-12-31")
    passed = _invoke("scan", str(active), "--check", "--accept-project-policy", epoch=before_expiry)
    assert passed.exit_code == 0, passed.output
    expired = _project_with_suppressed_pickle(tmp_path / "expired", "2026-01-01")
    failed = _invoke(
        "scan", str(expired), "--check", "--accept-project-policy", epoch=before_expiry
    )
    assert failed.exit_code == 1
    assert "expired on 2026-01-01" in failed.stderr


def test_the_release_evidence_scan_records_the_commit_time_as_documented():
    """The release build job exports the commit time before it scans for evidence."""
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    steps = yaml.safe_load(workflow)["jobs"]["build"]["steps"]
    runs = [step.get("run", "") for step in steps]
    [exported] = [
        index
        for index, run in enumerate(runs)
        if "SOURCE_DATE_EPOCH=" in run and "%ct" in run and "$GITHUB_ENV" in run
    ]
    [scanned] = [
        index
        for index, run in enumerate(runs)
        if "nexus_symbiote scan" in run and "project.cdx.json" in run
    ]
    assert exported < scanned
    assert "SOURCE_DATE_EPOCH" not in runs[scanned]
    between = steps[exported : scanned + 1]
    assert all("SOURCE_DATE_EPOCH" not in (step.get("env") or {}) for step in between)
    for page, statement in (
        (
            "releasing.md",
            "The build job sets `SOURCE_DATE_EPOCH` to the commit time, so `project.cdx.json` "
            "records that time, not the time of the scan",
        ),
        (
            "reproducible-inventories.md",
            "The release workflow exports the variable, set to the commit time, for its whole "
            "build job.",
        ),
    ):
        text = " ".join((ROOT / "docs" / page).read_text(encoding="utf-8").split())
        assert statement in text, page


def test_the_documented_example_is_reproducible(tmp_path):
    page = (ROOT / "docs" / "reproducible-inventories.md").read_text(encoding="utf-8")
    assert f"$ export SOURCE_DATE_EPOCH={EPOCH}\n" in page
    _scan(DEMO, tmp_path / "first.json")
    printed = _invoke("digest", str(tmp_path / "first.json")).stdout
    stale = "docs/reproducible-inventories.md shows another scan; rerun its example"
    assert printed in page, stale
    unpinned = _scan(DEMO, tmp_path / "now.json", epoch=None)
    assert f'"content_digest": "{inventory_content_digest(unpinned)}",\n' in page, stale
    serial = unpinned["metadata"]["serial_number"]
    assert f'now.json:    "serial_number": "{serial}",\n' in page, stale
    assert f'first.json:    "serial_number": "{serial}",\n' in page, stale


def _undigestible_collector(monkeypatch: pytest.MonkeyPatch, component: AnyComponent) -> None:
    result = ScanResult(scanner_name="fixed", components=[component])

    class Fixed(Scanner):
        name = "fixed"

        def scan(self, project_root: Path) -> ScanResult:
            return result

    monkeypatch.setattr("nexus_symbiote.cli._get_scanners", lambda: {"fixed": Fixed})


def _nested_schema(depth: int) -> dict[str, Any]:
    schema: dict[str, Any] = {}
    for _ in range(depth):
        schema = {"n": schema}
    return schema


UNDIGESTIBLE: dict[str, Callable[[], AnyComponent]] = {
    "lone surrogate": lambda: PromptComponent(
        bom_ref="prompt:a", name="\ud800", content_hash="sha256:" + "0" * 64
    ),
    "deep nesting": lambda: ToolComponent(
        bom_ref="tool:a", name="a", input_schema=_nested_schema(3000)
    ),
}


@pytest.mark.parametrize("epoch", [EPOCH, None])
@pytest.mark.parametrize("output_format", ["json", "cyclonedx"])
@pytest.mark.parametrize("case", sorted(UNDIGESTIBLE))
def test_an_inventory_without_a_content_digest_is_not_written(
    tmp_path, monkeypatch, output_format, case, epoch
):
    _undigestible_collector(monkeypatch, UNDIGESTIBLE[case]())
    output = tmp_path / "bom.json"
    args = ("scan", str(tmp_path), "--scanner", "fixed", "--report-only", "-f", output_format)
    result = _invoke(*args, "-o", str(output), epoch=epoch)
    assert result.exit_code == 1
    assert result.stderr.endswith(f"Error: {NO_CONTENT_SERIAL}\n")
    assert not output.exists()
    # Without output there is no serial number to derive, and the gate decides alone.
    checked = _invoke("scan", str(tmp_path), "--scanner", "fixed", "--report-only", "--check")
    assert checked.exit_code == 0, checked.output
