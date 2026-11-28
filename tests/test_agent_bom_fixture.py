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
# The one coverage gap main records today, a known limitation; any other gap is new.
KNOWN_GAPS = {
    "acme_agents/billing.py: MCP server launched from application code; launcher not inventoried"
}


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
def native(fixture_root: Path, exports: str) -> dict[str, Any]:
    document: dict[str, Any] = json.loads(
        (fixture_root.parent / "exports" / "bom.json").read_text(encoding="utf-8")
    )
    return document


@pytest.fixture(scope="module")
def exports(fixture_root: Path) -> str:
    """Every string of the native, CycloneDX and SARIF exports, lowercased and joined."""
    out = fixture_root.parent / "exports"
    out.mkdir()
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
        # --report-only keeps the exit at 0 so every export is written; the hard-failure
        # check is test_collection_has_no_hard_failure_and_only_the_known_gap.
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


@pytest.mark.parametrize("paths", [(".",), ("first", "first/nested"), ("first/nested", "first")])
def test_invalid_file_tree_is_rejected_before_writing(
    tmp_path: Path, paths: tuple[str, ...]
) -> None:
    builder = _builder()
    record = json.loads((BENCH / "corpus.json").read_text())["files"][0]
    corpus = tmp_path / "corpus.json"
    corpus.write_text(json.dumps({"files": [record | {"path": name} for name in paths]}))
    out = tmp_path / "out"
    with pytest.raises(builder.CorpusError):
        builder.build(out, corpus)
    assert not out.exists()


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
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(builder.CorpusError, match="already exists"):
        builder.build(existing)


def test_the_builder_refuses_a_parent_another_user_could_change(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    builder = _builder()
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(builder.CorpusError, match="writable only by you"):
        builder.build(shared / "out")
    group = tmp_path / "group"
    group.mkdir()
    group.chmod(0o770)
    with pytest.raises(builder.CorpusError, match="writable only by you"):
        builder.build(group / "out")
    monkeypatch.setattr(builder.os, "geteuid", lambda: 4242)
    with pytest.raises(builder.CorpusError, match="writable only by you"):
        builder.build(tmp_path / "out")
    assert not any((d / "out").exists() for d in (shared, group, tmp_path))


def test_the_builder_accepts_a_sticky_parent(tmp_path: Path) -> None:
    sticky = tmp_path / "sticky"
    sticky.mkdir()
    sticky.chmod(0o1777)
    assert len(_builder().build(sticky / "out")) == 81


def test_the_builder_writes_only_into_the_directory_it_creates(tmp_path: Path) -> None:
    out = tmp_path / "out"
    _builder().build(out)
    assert out.stat().st_mode & 0o777 == 0o700
    assert all(not path.is_symlink() for path in out.rglob("*"))
    assert (out / ".claude/skills/deploy-helper/scripts/deploy.sh").stat().st_mode & 0o777 == 0o755


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


def test_collection_has_no_hard_failure_and_only_the_known_gap(native: dict[str, Any]) -> None:
    claim = native["metadata"]["completeness"]
    assert claim["scan_failures"] == []
    assert set(claim["surfaces_excluded"]) == KNOWN_GAPS


def test_no_planted_secret_value_reaches_an_export(exports: str) -> None:
    assert not [sentinel for sentinel in SENTINELS if sentinel.lower() in exports]
