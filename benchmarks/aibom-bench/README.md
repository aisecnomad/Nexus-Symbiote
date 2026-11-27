# AIBOM-Bench

A benchmark for AI bill-of-materials tools across data, models, tools and
agent components, with the tool's own safety as a scored dimension.

| File | Purpose |
| --- | --- |
| [SPEC.md](SPEC.md) | Dimensions, criteria, weights, evidence labels, hard gates |
| [REPORT.md](REPORT.md) | Graded results for ten tools, with evidence |
| `build_corpus.py` | Materializes the deterministic ground-truth corpus |
| `ground_truth.json` | Expected components, decoys, secrets, digests, pins, findings |
| `corpus.manifest.json` | SHA-256 of every corpus file from the graded run |
| `run_tools.sh` | Runs each tool with strace, a no-network namespace and a corpus diff |
| `cisco_tier1.py` | Drives Cisco AI BOM's Tier-1 scanners without its LLM stage |
| `corpus_delta.py` | Reports files a tool wrote into the corpus |
| `score.py` | Automated scoring; `review_overrides.json` holds reviewer corrections |
| `schemas/`, `SOURCES.json`, `fetch_schemas.py` | The CycloneDX, SARIF and SPDX schemas `score.py` validates against, vendored with their licences and digests so scoring runs offline; `fetch_schemas.py --refresh` compares them with upstream |
| `results/` | Raw outputs per tool and mode (traces omitted), plus `scores.json` |

See [SPEC.md](SPEC.md#running-the-benchmark) for how to run it, and [ROADMAP.md](../../ROADMAP.md) for how benchmark gaps feed into the release train.

## Offline advisory acceptance

With `nexus-symbiote` installed, replay the companion advisory check from this directory.

```bash
result_parent=$(mktemp -d)
python replay_advisories.py --out "$result_parent/advisories"
```

The check scans synthetic PyPI and npm manifests and runs the advisory CLI against an operator-side OSV bundle. It expects two matches and a failing gate for the affected pins, zero matches and a passing gate for the fixed pins, and the exact PyPI package identity diagnostic for a floating version. It verifies the exact package queries in each case and requires each report to bind both the scanned inventory and the advisory bundle by digest. The output includes the fixture inputs, individual reports, and `summary.json`.

The fixture packages and CVE identifiers are synthetic. This check supplements the leaderboard's existing criteria. Set `--operator-dir` when the host's default temporary directory would put the operator feed inside a repository enclosing the output directory.
