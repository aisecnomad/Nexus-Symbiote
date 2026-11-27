# Agent-to-model ownership replay

Two agents exchange models while their names, tools and package versions stay fixed. The Python files are static declarations. The replay invokes the installed Nexus CLI with `--offline`; the fixture frameworks and models need no installation.

| Agent | Before | After |
|---|---|---|
| CopperReader · LangGraph | gpt-4o-mini | gpt-4.1-mini |
| VioletCurator · CrewAI | gpt-4.1-mini | gpt-4o-mini |

The SHA-256 manifest covers all six input files. Run `sha256sum -c SHA256SUMS` in this directory to verify them. Run the replay from the repository root with the CLI version you want to grade. The optional output directory must be new.

```sh
python benchmarks/agent-model-swap/replay.py --cli nexus-symbiote --out /tmp/agent-model-swap-evidence
```

A pass requires both agents to name precisely their expected model in both inventories. The four signed changes consist of two removals and two additions. Each binding needs an explicit per-agent model reference or a typed `uses-model` dependency to a model component. Repository-wide model membership alone earns zero. Additional bindings fail even if they persist across the swap. The replay records the native inventories and the machine-readable score. Exit 0 is a pass, exit 1 is an observed mismatch, and exit 2 means the replay could not be graded.

The fixtures come from the unweighted LangGraph/CrewAI probe of the independent November 2026 Agent BOM benchmark. Nexus 0.2.0 produced zero of four signed changes. Each of the three public collector candidates produced four of four on these same inputs. The broader benchmark also measures other entities, relationships, source locations, decoys and repeatability. [Independent cross-run](https://github.com/aisecnomad/Nexus-Symbiote/issues/200#issuecomment-7216201185) · [Collector decision](https://github.com/aisecnomad/Nexus-Symbiote/issues/200#issuecomment-7216681858)
