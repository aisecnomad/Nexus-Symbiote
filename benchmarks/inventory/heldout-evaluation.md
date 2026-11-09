# Held-out inventory evaluation

`evaluate_holdout.py` scores **externally produced** predictions against a
versioned, independently selected and adjudicated corpus. It does not run the
scanner, select samples, perform blinding, verify review identities, or verify
that the claimed scanner produced the supplied predictions. Inputs and those
claims must be independently authenticated. No representative corpus or
accuracy claim is supplied by this repository.

Before viewing predictions, define the deployment population, selection method,
collection date, labeling protocol and split. Select licensed, pinned source
snapshots across relevant frameworks and surfaces. Two reviewers independently
label each explicit candidate as positive (a tool) or negative (an explicit
non-tool). Record disagreements and a third reviewer's rationale and decision.
Keep the holdout unavailable to developers tuning detection. Record and retain
raw scanner output, exact invocation, environment, scanner wheel, manifest,
source files, predictions and their signatures in your evidence system.

Place the source fixtures beneath the manifest directory. The following shows
one **illustrative schema**, not real benchmark data. Replace every placeholder
and use actual SHA-256 values. Source files must be suitable for retention under
their licenses. The field `path` is the source path at the pinned revision;
`fixture` is the local relative path to the exact bytes.

```json
{
  "schema_version": 1,
  "corpus_id": "evaluation-2026-01",
  "population": "Document the intended deployments",
  "selection_criteria": "Document how samples were selected before predictions",
  "collection_date": "2026-01-01",
  "label_protocol": "Reference the versioned annotation protocol",
  "cases": [{
    "id": "case-1", "split": "holdout", "surface": "mcp-python",
    "source": {"repository": "github.com/owner/repository", "revision": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "path": "src/server.py", "fixture": "snapshots/case-1.py",
      "license": "MIT", "sha256": "REPLACE_WITH_SOURCE_SHA256"},
    "reviewers": ["reviewer-a", "reviewer-b"],
    "labels": [{"name": "search", "judgments": {"reviewer-a": "positive", "reviewer-b": "positive"}},
      {"name": "helper", "judgments": {"reviewer-a": "positive", "reviewer-b": "negative"},
       "adjudication": {"reviewer": "reviewer-c", "label": "negative", "rationale": "Document evidence"}}]
  }]
}
```

Provide predictions as a separate file, independently derived from a fixed
scanner artifact. The `source_sha256` must match the case's source bytes.
Omit a prediction row if collection was not attempted; it will be `missing`.
Use `partial` or `failed` when a collector cannot determine the case's entire
scope. Here `predicted` contains names actually observed; do not insert guessed
names. Names are case-sensitive and must be unique within a case. `complete`
means the specific labeled scope was fully collected, not that the scanner can
recognize every possible declaration. Follow the labeling protocol to decide
whether a scanner's reported status is adequate for that scope.

```json
{
  "schema_version": 1, "corpus_id": "evaluation-2026-01",
  "scanner_sha256": "REPLACE_WITH_SCANNER_ARTIFACT_SHA256",
  "cases": [{"id": "case-1", "source_sha256": "REPLACE_WITH_SOURCE_SHA256",
             "status": "complete", "predicted": ["search"]}]
}
```

Run offline and retain the original files and the output:

```sh
python benchmarks/inventory/evaluate_holdout.py corpus/manifest.json predictions.json scanner.whl > results.json
```

The evaluator checks source-file and scanner-artifact hashes, rejects a source
fixture, source identity or normalized repository identifier reused across
development and holdout splits, and
requires two reviewer judgments and independent adjudication of disagreements.
Repository identifiers use the single `host/owner/name` form (no URL scheme,
SSH form or trailing slash); comparison is case-insensitive and removes an
optional `.git` suffix. The check cannot identify repository renames, mirrors,
forks, semantically related projects, copied source with modifications, or
other split leakage; reviewers must inspect those relationships separately. Counts are label occurrences, not
independent deployments. Unlabeled predictions are listed separately; they are
never silently scored as false positives. Unobserved labels for partial, failed
or missing cases are unknown, not false negatives or true negatives. Recall and
specificity bounds show the best and worst outcomes for unknown labels.
Precision bounds similarly treat each unlabeled prediction as first incorrect,
then correct. These bounds are not statistical confidence intervals. A missing denominator is `null`.

The result includes hashes of the manifest and predictions; authenticate those
inputs and the result with a trusted external signing or attestation workflow.
These checks do not prove the source revision, license, reviewer independence,
representativeness, blinding, or that predictions came from the named scanner.
An attacker able to replace both the manifest and predictions can fabricate a
consistent record. Provenance review remains essential before drawing claims.

The current profile hashes one source file per case. It does not bind a complete
repository checkout, dependencies, configuration, or other scan context; retain
and independently attest those inputs if the scanner uses them. Multi-file and
deployment-level evaluations require a separate profile.
