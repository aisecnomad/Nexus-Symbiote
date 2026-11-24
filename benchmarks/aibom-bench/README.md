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

See [SPEC.md](SPEC.md#running-the-benchmark) for how to run it.

The active roadmap and release milestones derived from these results are tracked in [ROADMAP.md](../../ROADMAP.md).
