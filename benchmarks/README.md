# Synthetic security regression corpus

This small, committed corpus checks named security conditions and control contracts. It is not a representative sample of production agents, does not estimate population efficacy, and supports no competitive ranking or percentile claim.

Each case has an inspectable label, rationale, task, and SHA-256 manifest of exact inputs. The harness calls the Nexus SymBiote scanners and validators it imports (the checkout's `src` with the command below). Detection outcomes are computed from their outputs, not from the label. Labels are used only after evaluation for confusion counts. No fixture launches a tool, loads a model, or contacts a service. The SafeTensors fixture is a valid single zero-valued F32 tensor, not a trained model; pickle fixtures contain only inert serialized data and are never deserialized.

Run from a reviewed checkout with its dependencies installed:

```bash
PYTHONPATH=src python scripts/benchmark_security.py --out benchmark-results.json
```

The default corpus is `benchmarks/manifest.json`. `--manifest` selects another manifest under the same schema. A file hash mismatch, symlink, undeclared input file, invalid case, or duplicate case ID fails the run instead of quietly modifying the denominator. The output records corpus and runner digests, imported source digests, tool version, source Git revision and dirty state, platform, elapsed time, and Python traced peak allocation. Traced allocation is not whole-process resident memory.

Detection metrics include TP, FP, TN, FN, precision, recall, F1, specificity, and their denominators. A missing prerequisite or incomplete collection yields `unknown`; unknown predictions are excluded explicitly, and the report records their known labels separately so recall cannot conceal abstentions. Metrics are additionally separated by condition kind. Different kinds test different policies and their aggregate is only a regression summary.

Credential disclosure and collection-failure coverage are control contracts, reported separately from detection metrics. Their outcomes must not inflate TP/TN. The plaintext fixture secret is a public synthetic sentinel; tests check that this literal is absent from actual native, CycloneDX, SPDX, and SARIF exports.

The corpus is intentionally finite. Blind spots include real signed provider bundles, undocumented hosted-model revisions, deployed endpoint authentication, runtime revocation races, multi-tenant retrieval ACLs, framework diversity, and adversarial obfuscation beyond these fixtures. Expanding the corpus requires reviewed labels, independent fixture hashes, negative controls, and a documented sampling rationale. A perfect result on this corpus is not a safety or completeness certificate.

## AIBOM-Bench

`aibom-bench/` is a separate, tool-agnostic benchmark for AI bill-of-materials
tools: a generated ground-truth corpus of an agentic project, a scored
specification ([SPEC.md](aibom-bench/SPEC.md)), a runner that traces each
tool, and a graded report of ten tools ([REPORT.md](aibom-bench/REPORT.md)).
Unlike the corpus above, it does compare tools, and its report says for every
score whether it was verified by a run, read from source, or taken from
documentation.

## Agent-to-model ownership

The model-swap replay checks whether two named agents retain the right model
references when they exchange models. It runs the installed CLI offline on a
fixed LangGraph and CrewAI fixture and reports missing and extra bindings.
[Fixtures and replay instructions](agent-model-swap/README.md)
