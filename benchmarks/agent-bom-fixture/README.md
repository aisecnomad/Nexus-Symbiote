# Agent BOM regression fixture

A synthetic customer-support agent monorepo with **109 labelled components in ten
categories** (agents, MCP servers, models, tools, prompts, skills, credentials, data
sources, frameworks, infrastructure) and **ten decoys**: references that are not components,
such as a Django `models.py`, a human `SupportAgent` dataclass, an example MCP config, a
vendored `node_modules` package, a test model stub and a commented-out JSONC server. It also
plants three known-vulnerable pins (`pillow==9.0.0`, `PyYAML==5.3.1`, `lodash@4.17.15`),
dangerous permission settings, hidden-Unicode and skill-injection cases, an unsafe pickle
name and a JSONC file. `ground_truth.json` lists every item, decoy and expectation.

It is the fixture of the external ten-tool Agent BOM benchmark described on the merge
coordination ledger ([#200](https://github.com/aisecnomad/Nexus-Symbiote/issues/200)),
version 1.1, with one change for this repository: the three planted secret values are
public synthetic sentinels (`SYMBIOTE_PUBLIC_SYNTHETIC_SECRET_SENTINEL_01` to `_03`) instead
of fake vendor-shaped tokens, so value-shape detectors do not fire on them. Several
collector heads were developed or measured against this fixture, so it is **not** a blind
corpus for any of them; use it as a regression and decoy check, not as a ranking.

## Why it is stored as data

`corpus.json` holds every file with its SHA-256, and `build_fixture.py` writes them out.
The repository therefore tracks no `requirements.txt`, `package.json` or lockfile that pins
the deliberately vulnerable packages, so dependency scanners raise no alert on the
repository, and no agent or editor configuration that a tool would treat as live. The
pickle is an inert dictionary (no import or call opcodes) and nothing in the fixture is
executed by a scanner that behaves.

```bash
python benchmarks/agent-bom-fixture/build_fixture.py --out /tmp/agent-bom-fixture
nexus-symbiote scan /tmp/agent-bom-fixture --no-project-policy --accept-default-excludes --report-only -o bom.json
```

The output directory must not exist. The builder creates it with mode 0700 and writes every
directory and file relative to descriptors it opened, without following symbolic links or
replacing an existing entry. A path that would leave it, a digest mismatch, an unknown
encoding or an oversized file stops the build before anything is written.

## What the test checks

`tests/test_agent_bom_fixture.py` materializes the fixture, scans it once per export
format (native, CycloneDX, SARIF) and applies the benchmark's rule: an item or decoy is
found when one of its identifiers appears in any string of the exports. It asserts that no
decoy is reported, that MCP servers (17 of 17), prompts (12 of 13), skills (3 of 3) and
frameworks (10 of 10) stay at the level `main` collects today, that the scan records no
hard collection failure and no coverage gap beyond the one known limitation (an MCP server
launched from application code), and that no sentinel reaches an export. Raise a floor when a collector improves; lowering one is a regression to explain.
