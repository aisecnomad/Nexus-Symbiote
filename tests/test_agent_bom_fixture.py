"""The agent BOM regression fixture: integrity, decoys, discovery floors, no disclosure.

``benchmarks/agent-bom-fixture`` is materialized from data, scanned once per export format
and checked with the rule the external benchmark scores by: a component or decoy is found
when one of its identifiers appears in any string of the exports. The floors are what
``main`` collects today, so a collector change that drops a component or reports a decoy
fails here first.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main

ROOT = Path(__file__).resolve().parents[1]
BENCH = ROOT / "benchmarks" / "agent-bom-fixture"
SENTINELS = tuple(f"SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_0{n}" for n in (1, 2, 3))
# Categories main collects completely or nearly so; a regression in any of them fails.
FLOORS = {"mcp_server": 17, "prompt": 12, "skill": 3, "framework": 10}


def _builder() -> Any:
    spec = importlib.util.spec_from_file_location("agent_bom_fixture", BENCH / "build_fixture.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _strings(value: object) -> Iterator[str]:
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield key
            yield from _strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from _strings(item)


@pytest.fixture(scope="module")
def fixture_root(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("agent-bom-fixture") / "acme-support-agents"
    written = _builder().build(out)
    assert len(written) == 81
    return out


@pytest.fixture(scope="module")
def exports(fixture_root: Path, tmp_path_factory: pytest.TempPathFactory) -> str:
    """Every string of the native, CycloneDX and SARIF exports, lowercased and joined."""
    out = tmp_path_factory.mktemp("agent-bom-exports")
    texts: list[str] = []
    for fmt in ("json", "cyclonedx", "sarif"):
        target = out / f"bom.{fmt}"
        result = CliRunner().invoke(
            main,
            [
                "scan",
                str(fixture_root),
                "--no-project-policy",
                "--accept-default-excludes",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(target),
            ],
        )
        assert result.exit_code == 0, result.output
        texts.extend(_strings(json.loads(target.read_text(encoding="utf-8"))))
    return "\n".join(texts).lower()


@pytest.fixture(scope="module")
def ground_truth() -> dict[str, Any]:
    return json.loads((BENCH / "ground_truth.json").read_text(encoding="utf-8"))


def _found(item: dict[str, Any], exports: str) -> bool:
    return any(identifier.lower() in exports for identifier in item.get("identifiers", []))


def test_the_corpus_is_intact_and_holds_no_vendor_shaped_secret() -> None:
    text = (BENCH / "corpus.json").read_text(encoding="utf-8")
    for prefix in ("ghp_", "sk-proj-", "BSAfixture", "AKIA"):
        assert prefix not in text
    assert all(text.count(sentinel) == 1 for sentinel in SENTINELS)
    assert len(_builder().load()) == 81


def test_the_builder_refuses_a_path_that_escapes_the_output(tmp_path: Path) -> None:
    builder = _builder()
    corpus = tmp_path / "corpus.json"
    corpus.write_text(
        json.dumps(
            {
                "files": [
                    {
                        "path": "../escape.txt",
                        "encoding": "utf-8",
                        "content": "x",
                        "sha256": "2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881",
                    }
                ]
            }
        )
    )
    with pytest.raises(builder.CorpusError, match="escapes"):
        builder.build(tmp_path / "out", corpus)
    assert not (tmp_path / "escape.txt").exists()


def test_the_builder_refuses_a_digest_mismatch_and_a_non_empty_output(tmp_path: Path) -> None:
    builder = _builder()
    corpus = tmp_path / "corpus.json"
    corpus.write_text(
        json.dumps(
            {"files": [{"path": "a.txt", "encoding": "utf-8", "content": "x", "sha256": "0" * 64}]}
        )
    )
    with pytest.raises(builder.CorpusError, match="SHA-256"):
        builder.build(tmp_path / "out", corpus)
    occupied = tmp_path / "occupied"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("keep")
    with pytest.raises(builder.CorpusError, match="not an empty directory"):
        builder.build(occupied)


def test_no_decoy_is_reported(exports: str, ground_truth: dict[str, Any]) -> None:
    hit = [trap["id"] for trap in ground_truth["traps"] if _found(trap, exports)]
    assert hit == []


@pytest.mark.parametrize(("category", "floor"), sorted(FLOORS.items()))
def test_discovery_holds_its_floor(
    exports: str, ground_truth: dict[str, Any], category: str, floor: int
) -> None:
    items = [item for item in ground_truth["items"] if item["category"] == category]
    missing = [item["id"] for item in items if not _found(item, exports)]
    assert len(items) - len(missing) >= floor, missing


def test_no_planted_secret_value_reaches_an_export(exports: str) -> None:
    assert not [sentinel for sentinel in SENTINELS if sentinel.lower() in exports]
