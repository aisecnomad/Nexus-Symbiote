"""Score externally collected, adjudicated inventory predictions.

This evaluator does not collect data or execute the scanner. Its inputs are claims
from an independent evaluation process; their provenance must be verified outside
this script. See heldout-evaluation.md for the protocol and limitations.
"""

import argparse
import hashlib
import json
import re
from collections import Counter
from pathlib import Path

SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")


def digest(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def require_text(value: object, name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a nonempty string")
    return value


def repository_key(value: object) -> str:
    """Normalize an explicit host/path identity for conservative split isolation."""
    repo = require_text(value, "source repository").lower()
    if repo.endswith(".git"):
        repo = repo[:-4]
    # A single host/path form avoids URL, SSH, trailing-slash and user-info aliases.
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*/[a-z0-9_.-]+(?:/[a-z0-9_.-]+)+", repo):
        raise ValueError("repository must use host/owner/name form")
    parts = repo.split("/")
    if any(part in {".", ".."} for part in parts):
        raise ValueError("repository path cannot contain dot segments")
    return repo


def safe_source(root: Path, name: str) -> Path:
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("source path must be relative to the corpus directory")
    resolved = (root / path).resolve(strict=True)
    if not resolved.is_relative_to(root.resolve()) or not resolved.is_file():
        raise ValueError("source path must resolve to a regular file inside the corpus directory")
    return resolved


def evaluate(manifest: dict, predictions: dict, root: Path, scanner: Path) -> dict:
    """Validate input commitments, score the holdout, and preserve unknowns."""
    if manifest.get("schema_version") != 1 or predictions.get("schema_version") != 1:
        raise ValueError("unsupported schema version")
    for field in (
        "corpus_id",
        "population",
        "selection_criteria",
        "collection_date",
        "label_protocol",
    ):
        require_text(manifest.get(field), field)
    scanner_sha = require_text(predictions.get("scanner_sha256"), "scanner_sha256")
    if not SHA256.fullmatch(scanner_sha) or digest(scanner) != scanner_sha:
        raise ValueError("scanner artifact digest mismatch")
    if predictions.get("corpus_id") != manifest["corpus_id"]:
        raise ValueError("prediction corpus_id mismatch")
    cases = manifest.get("cases")
    if not isinstance(cases, list) or not cases:
        raise ValueError("cases must be a nonempty list")
    ids, split_for_digest, split_for_source, split_for_repo, case_by_id = set(), {}, {}, {}, {}
    for case in cases:
        cid = require_text(case.get("id"), "case id")
        if cid in ids:
            raise ValueError("duplicate case id")
        ids.add(cid)
        split = case.get("split")
        if split not in {"development", "holdout"}:
            raise ValueError("case split must be development or holdout")
        source = case.get("source")
        if not isinstance(source, dict):
            raise ValueError("source metadata required")
        for field in ("repository", "path", "license", "fixture"):
            require_text(source.get(field), f"source {field}")
        if not COMMIT.fullmatch(require_text(source.get("revision"), "source revision")):
            raise ValueError("source revision must be a full commit SHA")
        source_sha = require_text(source.get("sha256"), "source sha256")
        if (
            not SHA256.fullmatch(source_sha)
            or digest(safe_source(root, source["fixture"])) != source_sha
        ):
            raise ValueError("source fixture digest mismatch")
        old_split = split_for_digest.setdefault(source_sha, split)
        if old_split != split:
            raise ValueError("a source fixture appears in both splits")
        repo_key = repository_key(source["repository"])
        if split_for_repo.setdefault(repo_key, split) != split:
            raise ValueError("a repository appears in both development and holdout splits")
        source_key = (repo_key, source["revision"], source["path"])
        old_split = split_for_source.setdefault(source_key, split)
        if old_split != split:
            raise ValueError("a source revision and path appear in both splits")
        require_text(case.get("surface"), "surface")
        reviewers = case.get("reviewers")
        if not isinstance(reviewers, list) or len(reviewers) != 2:
            raise ValueError("exactly two reviewers required")
        for reviewer in reviewers:
            require_text(reviewer, "reviewer")
        if reviewers[0] == reviewers[1]:
            raise ValueError("reviewers must be distinct")
        labels = case.get("labels")
        if not isinstance(labels, list) or not labels:
            raise ValueError("case must contain explicit labels")
        label_names = set()
        decisions = {}
        for label in labels:
            name = require_text(label.get("name"), "label name")
            if name in label_names:
                raise ValueError("duplicate label")
            label_names.add(name)
            judgments = label.get("judgments")
            if not isinstance(judgments, dict) or set(judgments) != set(reviewers):
                raise ValueError("each label must have both reviewer judgments")
            if any(value not in ("positive", "negative") for value in judgments.values()):
                raise ValueError("invalid reviewer judgment")
            if len(set(judgments.values())) == 2:
                decision = label.get("adjudication")
                if not isinstance(decision, dict) or decision.get("label") not in (
                    "positive",
                    "negative",
                ):
                    raise ValueError("disagreement requires adjudication")
                adjudicator = require_text(decision.get("reviewer"), "adjudicator")
                if adjudicator in reviewers:
                    raise ValueError("adjudicator must be distinct from both reviewers")
                require_text(decision.get("rationale"), "adjudication rationale")
                decisions[name] = decision["label"]
            else:
                decisions[name] = next(iter(judgments.values()))
        case_by_id[cid] = (case, decisions)
    holdout = {cid for cid, (case, _) in case_by_id.items() if case["split"] == "holdout"}
    if not holdout:
        raise ValueError("at least one holdout case required")
    rows = predictions.get("cases")
    if not isinstance(rows, list):
        raise ValueError("prediction cases must be a list")
    by_case = {}
    for row in rows:
        cid = row.get("id")
        if cid not in holdout or cid in by_case:
            raise ValueError("prediction has duplicate or non-holdout case")
        if row.get("source_sha256") != case_by_id[cid][0]["source"]["sha256"]:
            raise ValueError("prediction source digest mismatch")
        if row.get("status") not in ("complete", "partial", "failed"):
            raise ValueError("invalid collection status")
        names = row.get("predicted")
        if (
            not isinstance(names, list)
            or any(not isinstance(n, str) or not n for n in names)
            or len(names) != len(set(names))
        ):
            raise ValueError("predicted names must be unique nonempty strings")
        by_case[cid] = row
    totals, by_surface, results = Counter(), {}, []
    for cid in sorted(holdout):
        (case, decisions), row = case_by_id[cid], by_case.get(cid)
        status = row["status"] if row else "missing"
        predicted = set(row["predicted"]) if row else set()
        counts = Counter()
        for label in case["labels"]:
            is_positive = decisions[label["name"]] == "positive"
            if label["name"] in predicted:
                counts["tp" if is_positive else "fp"] += 1
            elif status == "complete":
                counts["fn" if is_positive else "tn"] += 1
            else:
                counts["unknown_positive" if is_positive else "unknown_negative"] += 1
        unlabeled = sorted(predicted - {label["name"] for label in case["labels"]})
        counts["unlabeled_predictions"] = len(unlabeled)
        totals.update(counts)
        by_surface.setdefault(case["surface"], Counter()).update(counts)
        results.append(
            {
                "id": cid,
                "surface": case["surface"],
                "status": status,
                "counts": dict(counts),
                "unlabeled_predictions": unlabeled,
            }
        )

    def summarize(counts: Counter) -> dict:
        out = {
            key: counts[key]
            for key in (
                "tp",
                "fp",
                "tn",
                "fn",
                "unknown_positive",
                "unknown_negative",
                "unlabeled_predictions",
            )
        }
        pos = counts["tp"] + counts["fn"] + counts["unknown_positive"]
        neg = counts["tn"] + counts["fp"] + counts["unknown_negative"]
        predicted = counts["tp"] + counts["fp"] + counts["unlabeled_predictions"]
        out["precision_bounds"] = (
            [counts["tp"] / predicted, (counts["tp"] + counts["unlabeled_predictions"]) / predicted]
            if predicted
            else None
        )
        out["recall_bounds"] = (
            [counts["tp"] / pos, (counts["tp"] + counts["unknown_positive"]) / pos] if pos else None
        )
        out["specificity_bounds"] = (
            [counts["tn"] / neg, (counts["tn"] + counts["unknown_negative"]) / neg] if neg else None
        )
        return out

    return {
        "schema_version": 1,
        "corpus_id": manifest["corpus_id"],
        "scanner_sha256": scanner_sha,
        "scope": "explicit labels only; inputs and independence are operator assertions",
        "totals": summarize(totals),
        "surfaces": {s: summarize(c) for s, c in sorted(by_surface.items())},
        "cases": results,
    }


def read_json(path: Path) -> dict:
    def object_without_duplicates(pairs: list[tuple[str, object]]) -> dict:
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"duplicate JSON key: {key}")
            result[key] = value
        return result

    def invalid_constant(value: str) -> None:
        raise ValueError(f"invalid JSON constant: {value}")

    value = json.loads(
        path.read_text(encoding="utf-8"),
        object_pairs_hook=object_without_duplicates,
        parse_constant=invalid_constant,
    )
    if not isinstance(value, dict):
        raise ValueError("JSON document must be an object")
    return value


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("predictions", type=Path)
    parser.add_argument("scanner_artifact", type=Path)
    args = parser.parse_args()
    manifest = read_json(args.manifest)
    predictions = read_json(args.predictions)
    result = evaluate(manifest, predictions, args.manifest.parent, args.scanner_artifact)
    result["manifest_sha256"] = digest(args.manifest)
    result["predictions_sha256"] = digest(args.predictions)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
