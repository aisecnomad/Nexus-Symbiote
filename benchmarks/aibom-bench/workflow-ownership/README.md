# Workflow ownership acceptance

Check whether a static inventory records a compiled LangGraph workflow and correctly
attributes its chat model, callable tool, and prompt. The fixture uses the Agent BOM
Benchmark 1.0 LangGraph source. This check specifically requires the compiled
workflow name at its compile site. It also includes an unregistered example to check
that a nearby declaration earns no workflow relationship.

Run with the installed CLI, or provide the path to a candidate executable.

```sh
python benchmarks/aibom-bench/workflow-ownership/replay.py \
  --nexus nexus-symbiote --out /tmp/workflow-ownership.json
```

The replay invokes `scan` offline. It reads the fixture as source and does not import
it or install the SDKs it names. To score a previously captured native inventory, use
`--bom inventory.json` in place of `--nexus`. The score records four criteria, the
resolved source and target references, and the inventory digest. A saved inventory
can be scored independently of how it was collected. Exit 0 means all four
criteria pass and no decoy is attributed to the workflow. Exit 1 means an acceptance
check failed. Exit 2 means the scan failed or the input could not be scored because
it was unreadable, its scored graph was invalid, or it records a collection failure.
`scan --report-only` exits 0 when a collector fails, so the replay reads the failure
from the inventory's `metadata.completeness`.

Check the scorer with the included synthetic known-positive inventory and its negative
controls.

```sh
python -m pytest -q benchmarks/aibom-bench/workflow-ownership/test_replay.py
```

This is a manual acceptance check for the source collector. Nexus SymBiote 0.2.0 is
the released control and scores 0/4 on this fixture. The four checks remain separate
from the published leaderboard scores.
