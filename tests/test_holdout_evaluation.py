"""The holdout evaluator must reject invalid evidence and preserve unknown labels."""

import copy
import hashlib
import importlib.util
from pathlib import Path

import pytest

path = Path(__file__).resolve().parents[1] / "benchmarks/inventory/evaluate_holdout.py"
spec = importlib.util.spec_from_file_location("evaluate_holdout", path)
assert spec and spec.loader
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def inputs(tmp_path):
    source = tmp_path / "source.py"
    source.write_text("example")
    wheel = tmp_path / "scanner.whl"
    wheel.write_bytes(b"scanner")
    sha = hashlib.sha256(source.read_bytes()).hexdigest()
    label = {"name": "tool", "judgments": {"alice": "positive", "bob": "positive"}}
    case = {
        "id": "a",
        "split": "holdout",
        "surface": "mcp-python",
        "reviewers": ["alice", "bob"],
        "source": {
            "repository": "github.com/owner/repo",
            "revision": "a" * 40,
            "path": "source.py",
            "license": "MIT",
            "fixture": "source.py",
            "sha256": sha,
        },
        "labels": [label, {"name": "decoy", "judgments": {"alice": "negative", "bob": "negative"}}],
    }
    manifest = {
        "schema_version": 1,
        "corpus_id": "test",
        "population": "example",
        "selection_criteria": "example",
        "collection_date": "2026-01-01",
        "label_protocol": "example",
        "cases": [case],
    }
    predictions = {
        "schema_version": 1,
        "corpus_id": "test",
        "scanner_sha256": hashlib.sha256(wheel.read_bytes()).hexdigest(),
        "cases": [{"id": "a", "source_sha256": sha, "status": "complete", "predicted": ["tool"]}],
    }
    return manifest, predictions, wheel


def test_complete_and_partial_denominators(tmp_path):
    manifest, predictions, wheel = inputs(tmp_path)
    result = module.evaluate(manifest, predictions, tmp_path, wheel)
    assert result["totals"]["tp"] == 1
    assert result["totals"]["tn"] == 1
    assert result["totals"]["recall_bounds"] == [1.0, 1.0]
    predictions["cases"][0]["status"] = "partial"
    predictions["cases"][0]["predicted"] = ["unexpected"]
    result = module.evaluate(manifest, predictions, tmp_path, wheel)
    assert result["totals"]["unknown_positive"] == 1
    assert result["totals"]["unknown_negative"] == 1
    assert result["totals"]["recall_bounds"] == [0.0, 1.0]
    assert result["totals"]["unlabeled_predictions"] == 1
    assert result["totals"]["precision_bounds"] == [0.0, 1.0]
    assert result["totals"]["fp"] == 0


def test_missing_predictions_are_unknown(tmp_path):
    manifest, predictions, wheel = inputs(tmp_path)
    predictions["cases"] = []
    result = module.evaluate(manifest, predictions, tmp_path, wheel)
    assert result["cases"][0]["status"] == "missing"
    assert result["totals"]["unknown_positive"] == 1
    assert result["totals"]["unknown_negative"] == 1


def test_disagreement_requires_independent_adjudication(tmp_path):
    manifest, predictions, wheel = inputs(tmp_path)
    label = manifest["cases"][0]["labels"][0]
    label["judgments"]["bob"] = "negative"
    with pytest.raises(ValueError, match="adjudication"):
        module.evaluate(manifest, predictions, tmp_path, wheel)
    label["adjudication"] = {"reviewer": "alice", "label": "positive", "rationale": "source"}
    with pytest.raises(ValueError, match="distinct"):
        module.evaluate(manifest, predictions, tmp_path, wheel)
    label["adjudication"]["reviewer"] = "charlie"
    assert module.evaluate(manifest, predictions, tmp_path, wheel)["totals"]["tp"] == 1


def test_rejects_cross_split_duplicates_and_changed_inputs(tmp_path):
    manifest, predictions, wheel = inputs(tmp_path)
    other = copy.deepcopy(manifest["cases"][0])
    other["id"], other["split"] = "other", "development"
    manifest["cases"].append(other)
    with pytest.raises(ValueError, match="both splits"):
        module.evaluate(manifest, predictions, tmp_path, wheel)
    manifest["cases"].pop()
    (tmp_path / "source.py").write_text("changed")
    with pytest.raises(ValueError, match="fixture digest"):
        module.evaluate(manifest, predictions, tmp_path, wheel)
    (tmp_path / "source.py").write_text("example")
    wheel.write_bytes(b"changed")
    with pytest.raises(ValueError, match="artifact digest"):
        module.evaluate(manifest, predictions, tmp_path, wheel)


def test_rejects_escaping_paths_and_duplicate_predictions(tmp_path):
    manifest, predictions, wheel = inputs(tmp_path)
    manifest["cases"][0]["source"]["fixture"] = "../outside"
    with pytest.raises(ValueError, match="relative"):
        module.evaluate(manifest, predictions, tmp_path, wheel)
    manifest["cases"][0]["source"]["fixture"] = "source.py"
    predictions["cases"].append(copy.deepcopy(predictions["cases"][0]))
    with pytest.raises(ValueError, match="duplicate"):
        module.evaluate(manifest, predictions, tmp_path, wheel)


def test_rejects_duplicate_json_keys(tmp_path):
    path = tmp_path / "manifest.json"
    path.write_text('{"schema_version": 1, "schema_version": 2}')
    with pytest.raises(ValueError, match="duplicate JSON key"):
        module.read_json(path)


def test_same_repository_cannot_cross_splits_even_if_files_differ(tmp_path):
    manifest, predictions, wheel = inputs(tmp_path)
    other = copy.deepcopy(manifest["cases"][0])
    other["id"], other["split"] = "other", "development"
    other["source"]["repository"] = "GitHub.com/Owner/Repo.git"
    other["source"]["revision"] = "b" * 40
    other["source"]["path"] = "different.py"
    other["source"]["fixture"] = "different.py"
    (tmp_path / "different.py").write_text("different")
    other["source"]["sha256"] = hashlib.sha256(b"different").hexdigest()
    manifest["cases"].append(other)
    with pytest.raises(ValueError, match="repository appears in both"):
        module.evaluate(manifest, predictions, tmp_path, wheel)


def test_rejects_ambiguous_repository_names(tmp_path):
    manifest, predictions, wheel = inputs(tmp_path)
    for name in (
        "owner/repo",
        "https://github.com/owner/repo",
        "github.com/owner/repo/",
        "github.com/../repo",
    ):
        manifest["cases"][0]["source"]["repository"] = name
        with pytest.raises(ValueError, match="repository"):
            module.evaluate(manifest, predictions, tmp_path, wheel)
