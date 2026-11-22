"""Project YAML loaders read base-60 integers as text, in time linear in their size.

PyYAML resolves a plain scalar such as ``1:30`` as a YAML 1.1 base-60 integer and builds it
on ever larger integers, so constructing ``x: 1:1:1:...`` took time quadratic in its number
of parts: about a minute for a 1 MiB agent.yaml or project policy, and some twenty minutes
for a 4 MiB RAG configuration. YAML 1.2 reads it as text, which is what every reader of
these files expects. The base-60 float form overflows from 175 parts on; that is an invalid
document, not an internal error.
"""

from __future__ import annotations

import json
import subprocess
import sys
from datetime import date
from pathlib import Path
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.policy import PolicyError, parse_yaml_mapping
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.rag import RAGScanner
from nexus_symbiote.utils.confined import ConfinedCollection
from tests.support import scaling_ratio

RAG_CONFIG = "rag_config.yaml"
INVALID_RAG = (None, [f"{RAG_CONFIG}: invalid YAML"])


def read_rag(root: Path) -> tuple[Any, list[str]]:
    """The RAG collector's own reading of the configuration under ``root``."""
    result = ScanResult(scanner_name="rag")
    with ConfinedCollection(root, result.scan_failures) as files:
        value = RAGScanner()._read_config(Path(RAG_CONFIG), files, result)
    return value, result.scan_failures


def load_rag(root: Path, document: str) -> Any:
    root.mkdir(parents=True, exist_ok=True)
    (root / RAG_CONFIG).write_text(document, encoding="utf-8")
    value, failures = read_rag(root)
    assert failures == []
    return value


LONG = "1:" * 1_000 + "1"
SEXAGESIMAL = {
    "int": ("x: 1:30\n", {"x": "1:30"}),
    "negative": ("x: -1:30\n", {"x": "-1:30"}),
    "signed": ("x: +190:20:30\n", {"x": "+190:20:30"}),
    "underscored": ("x: 1_000:30\n", {"x": "1_000:30"}),
    "sequence": ("x: [12:30, 12:30:45]\n", {"x": ["12:30", "12:30:45"]}),
    "flow key": ("x: {12:30: y}\n", {"x": {"12:30": "y"}}),
    "block key": ("12:30: y\n", {"12:30": "y"}),
    "long": (f"x: {LONG}\n", {"x": LONG}),
}


@pytest.mark.parametrize(("document", "expected"), SEXAGESIMAL.values(), ids=SEXAGESIMAL.keys())
def test_sexagesimal_integers_are_text(tmp_path, document, expected):
    assert parse_yaml_mapping(document) == expected
    assert load_rag(tmp_path, document) == expected


@pytest.mark.parametrize(
    ("document", "expected"),
    [('x: !!int "1:30"\n', "1:30"), ("x: !!int 1:30\n", "1:30"), (f'x: !!int "{LONG}"\n', LONG)],
    ids=["quoted", "plain", "long"],
)
def test_sexagesimal_integers_tagged_as_int_are_text(document, expected):
    # The project policy is the one document parsed without the scan that refuses tags.
    assert parse_yaml_mapping(document) == {"x": expected}


ORDINARY = """\
decimal: 42
negative: -17
positive: +5
zero: 0
underscored: 1_000
octal: 017
hex: 0x1F
binary: 0b101
float: 1.5
exponent: -2.5e+3
fraction: .5
underscored_float: 1_000.5
base60_float: 1:30.5
infinity: .inf
negative_infinity: -.Inf
not_a_number: .NaN
true_word: true
yes_word: yes
off_word: Off
null_word: null
tilde: ~
empty:
date: 2026-11-10
timestamp: 2026-11-10T12:30:00Z
spaced_timestamp: 2001-12-14 21:59:43.10 -5
quoted_time: "12:30"
single_quoted_time: '1:30'
leading_zero_time: 01:30
mac: 00:1a:2b:3c:4d:5e
url: https://example.com:8443/path
version: 1.0
words: plain text
nested: {list: [1, 2.5, "three", {deep: [true, null]}], empty: {}}
"""


def test_ordinary_scalars_construct_as_pyyaml_does(tmp_path):
    # repr tells 1, 1.0, True and "1" apart, which == does not.
    expected = repr(yaml.safe_load(ORDINARY))
    parsed = parse_yaml_mapping(ORDINARY)
    assert repr(parsed) == expected
    assert repr(load_rag(tmp_path, ORDINARY)) == expected
    assert (parsed["octal"], parsed["hex"], parsed["binary"]) == (15, 31, 5)
    assert parsed["base60_float"] == 90.5
    assert parsed["yes_word"] is True and parsed["off_word"] is False
    assert parsed["date"] == date(2026, 11, 10)
    assert parsed["exponent"] == -2500.0 and isinstance(parsed["exponent"], float)
    assert parsed["leading_zero_time"] == "01:30"


@pytest.mark.parametrize(
    "document",
    [
        "a: 1\na: 2\n",
        "x: {a: 1, a: 2}\n",
        # The same key, plain and quoted, once a plain 12:30 was read as 750.
        "12:30: a\n'12:30': b\n",
        "x: {1:30: a, '1:30': b}\n",
    ],
)
def test_duplicate_keys_are_still_refused(tmp_path, document):
    with pytest.raises(PolicyError):
        parse_yaml_mapping(document)
    (tmp_path / RAG_CONFIG).write_text(document, encoding="utf-8")
    assert read_rag(tmp_path) == INVALID_RAG


@pytest.mark.parametrize("document", ["1: x\n", "x: {1.5: y}\n", "[a, b]\n", "x\n"])
def test_policy_documents_still_need_a_mapping_with_text_keys(document):
    with pytest.raises(PolicyError):
        parse_yaml_mapping(document)


@pytest.mark.parametrize(
    "document", [f"x: {LONG}.5\n", f'x: !!float "{LONG}"\n'], ids=["plain", "tagged"]
)
def test_an_overflowing_sexagesimal_float_is_an_invalid_document(tmp_path, document):
    with pytest.raises(PolicyError, match="invalid YAML document"):
        parse_yaml_mapping(document)
    if "!!" not in document:
        (tmp_path / RAG_CONFIG).write_text(document, encoding="utf-8")
        assert read_rag(tmp_path) == INVALID_RAG


def test_an_overflowing_float_is_a_recorded_failure_not_an_internal_error(tmp_path):
    # It escaped as OverflowError: the manifest ended the scan as an internal error and
    # the pnpm lockfile failed the registry collector, dropping its components.
    project = tmp_path / "project"
    project.mkdir()
    for name in ("agent.yaml", "pnpm-lock.yaml"):
        (project / name).write_text(f"x: {LONG}.5\n", encoding="utf-8")
    (project / "package.json").write_text(json.dumps({"dependencies": {"openai": "4.52.0"}}))
    out = tmp_path / "aibom.json"
    scanned = CliRunner().invoke(main, ["scan", "--report-only", "-o", str(out), str(project)])
    assert scanned.exit_code == 0, scanned.output
    inventory = json.loads(out.read_text())
    assert {
        "agent.yaml: does not conform to the agent manifest schema",
        "pnpm-lock.yaml: invalid or unsupported lockfile",
    } <= set(inventory["metadata"]["completeness"]["scan_failures"])
    assert "registry:npm/openai" in {component["bom_ref"] for component in inventory["components"]}


def test_an_overflowing_float_in_the_project_policy_is_an_invalid_policy(tmp_path):
    (tmp_path / ".nexus-symbiote.yaml").write_text(f"x: {LONG}.5\n", encoding="utf-8")
    scanned = CliRunner().invoke(
        main, ["scan", "--report-only", "--check", "--accept-project-policy", str(tmp_path)]
    )
    assert scanned.exit_code == 1
    assert "invalid YAML document" in scanned.output
    assert "internal error" not in scanned.output


PARTS = 50_000


def shapes(parts: int) -> dict[str, str]:
    """Each form of a base-60 scalar of ``parts`` parts."""
    text = "1:" * parts + "1"
    return {
        "int": f"x: {text}\n",
        "tagged int": f'x: !!int "{text}"\n',
        "float": f"x: {text}.5\n",
        "tagged float": f'x: !!float "{text}"\n',
    }


def outcome(document: str) -> object:
    """The value of ``x`` as the project's YAML mapping parser reads it, or its error."""
    try:
        return parse_yaml_mapping(document)["x"]
    except PolicyError as exc:
        return str(exc)


@pytest.mark.parametrize("shape", shapes(1))
def test_policy_parser_work_grows_linearly_with_sexagesimal_parts(shape):
    documents = {scale: shapes(PARTS * scale)[shape] for scale in (1, 4)}
    # Four times the parts: about four times the work if linear, sixteen if quadratic.
    assert scaling_ratio(lambda scale: outcome(documents[scale])) < 10
    integer = "1:" * PARTS + "1"
    assert outcome(documents[1]) == ("invalid YAML document" if "float" in shape else integer)


@pytest.mark.parametrize("shape", ["int", "float"])
def test_rag_reader_work_grows_linearly_with_sexagesimal_parts(tmp_path, shape):
    roots = {}
    for scale in (1, 4):
        roots[scale] = tmp_path / f"scale-{scale}"
        roots[scale].mkdir()
        (roots[scale] / RAG_CONFIG).write_text(shapes(PARTS * scale)[shape])
    assert scaling_ratio(lambda scale: read_rag(roots[scale])) < 10
    integer = ({"x": "1:" * PARTS + "1"}, [])
    assert read_rag(roots[1]) == (INVALID_RAG if shape == "float" else integer)


# Just under 1 MiB, the largest project policy and agent.yaml that are read.
MIB_PAYLOAD = "x: " + "1:" * 524_000 + "1\n"
CPU_SECONDS = 60
LIMITED_CLI = (
    "import resource\n"
    f"resource.setrlimit(resource.RLIMIT_CPU, ({CPU_SECONDS}, {CPU_SECONDS}))\n"
    "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))\n"
    "from nexus_symbiote.cli import main\n"
    "main()\n"
)


def limited_scan(cwd: Path, *arguments: str) -> subprocess.CompletedProcess[str]:
    """A scan in a child whose CPU time is capped; it was quadratic in each payload."""
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", "-c", LIMITED_CLI, "scan", "--report-only", *arguments],
        cwd=cwd,
        capture_output=True,
        text=True,
        timeout=110,
        check=False,
    )


def test_scan_of_collected_payload_files_finishes(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    for name in ("agent.yaml", RAG_CONFIG, "a2a.yaml", "pnpm-lock.yaml"):
        (project / name).write_text(MIB_PAYLOAD, encoding="utf-8")
    (project / "package.json").write_text(json.dumps({"dependencies": {"openai": "4.52.0"}}))
    out = tmp_path / "aibom.json"
    scanned = limited_scan(tmp_path, "--no-project-policy", "-o", str(out), str(project))
    assert scanned.returncode == 0, scanned.stderr[-2000:]
    completeness = json.loads(out.read_text())["metadata"]["completeness"]
    assert {
        "agent.yaml: does not conform to the agent manifest schema",
        "pnpm-lock.yaml: invalid or unsupported lockfile",
    } <= set(completeness["scan_failures"])
    assert {RAG_CONFIG, "a2a.yaml"} <= set(completeness["surfaces_scanned"])


def test_scan_with_payload_project_policy_fails_closed_promptly(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / ".nexus-symbiote.yaml").write_text(MIB_PAYLOAD, encoding="utf-8")
    scanned = limited_scan(
        tmp_path, "--accept-project-policy", "-o", str(tmp_path / "aibom.json"), str(project)
    )
    assert scanned.returncode == 1, scanned.stderr[-2000:]
    assert "invalid or unsupported settings: x" in scanned.stderr
    assert not (tmp_path / "aibom.json").exists()
