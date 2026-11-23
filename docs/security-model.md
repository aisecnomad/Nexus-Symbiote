# Security model

Nexus SymBiote connects an AI agent's inventory to evidence and policy while keeping four trust states strictly separate:

| State | Meaning |
| --- | --- |
| **Declared composition** | A repository, supplier, or configuration states a component is used. |
| **Observed composition** | A named collector directly measured bytes (weight, instruction, skill, or static tool-descriptor digest) in a stated scope. |
| **Approved configuration** | An authorized approver accepted a specific configuration and capability scope. |
| **Mediated execution** | An enforcement adapter verified a runtime action against trusted policy and approval. |

**Core evidence rules:**

- Each component's `assurance_level` records how its identity was obtained (`observed` vs. `declared`), and locally collected components carry a `repository_presence` claim naming the collector.
- Imports (Nexus-ShadowScan reports, CycloneDX/SPDX BOMs, A2A Agent Cards, IDE settings, extension manifests) remain `declared` claims until independently verified—an inventory entry never grants permission or proves benign behavior.
- Collectors preserve coverage gaps, denied reads, unsupported inputs, exclusions, and failures (`unknown` is never treated as verified absence; unsupported surfaces are listed in [known limitations](known-limitations.md)).
- Secrets are recorded as references, never values; raw prompts, retrieved documents, and tool arguments/results are not captured by default.

## Design principles

1. **Never executes what it inspects.** Static collectors parse with `ast`, `tree-sitter`, JSON, safe YAML, and TOML—never importing modules, loading weights, running hooks, or spawning MCP launchers.
2. **Offline by default, enforced at runtime.** A Python audit-hook tripwire fails closed on DNS resolution, non-Unix sockets, and process creation unless `--live` is explicitly requested for one of the three live commands. (Not an OS sandbox—pair with OS/container network isolation for untrusted repos.)
3. **Unknown is not safe.** Failed reads, skipped collectors, and recognized unsupported declarations record explicit gaps and fail default gates. Unrecognized surfaces are skipped without a gap ([known limitations](known-limitations.md)).
4. **Claims are not evidence.** Declared, observed, approved, and mediated states stay separate. Supplier labels or adjacent signatures never upgrade trust on their own, and `--no-project-policy` blocks untrusted checkouts from weakening gates.
5. **Standards first.** One native inventory exports to CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, and VEX. CycloneDX and SPDX embed the full native inventory in a digest-bound extension for lossless recovery; SARIF and VEX project findings only.

### Reconciling supplier inventories against a checkout

When evaluating a supplier-provided inventory alongside its source checkout, run both commands with `--project` and `--no-project-policy`:

```sh
nexus-symbiote validate inventory.json --project /reviewed/checkout --no-project-policy
nexus-symbiote risk inventory.json --project /reviewed/checkout --no-project-policy --json-output
```

- Project reconciliation re-runs supported static collectors and compares security-relevant fields, findings, repository agent profile, and local component relationships (requiring at least one local subject).
- Uncorroborated components, relationships, or claims fail reconciliation if they assert local provenance, `verified` assurance, or `internal-verified` trust; otherwise they are recorded as supplier claims (`project-reconciled-with-supplier-claims`) and never satisfy `validate.minimum_assurance_level: observed`.
- Suppliers cannot inject collector-owned `hashes` or binding/integrity properties (`collection_mode`, `content_hash_withheld`, `identity_source`, `weight_files`, `config_hash`, `static_value_binding*`, `static_config_hash*`, `static_card_hash*`); any mismatch fails reconciliation (`project-reconciliation-failed`, unknown risk level, null score).
- Without `--project`, `risk` scores supplied claims as `supplied-bom`. For operator signature verification, pass a caller-owned `--signature-policy` (in the GitHub Action, outside the workspace; verified against the Action's hash-locked Sigstore trust root).
- **Runtime mediation & hosted surfaces:** Mediated execution requires trusted approvers, snapshot binding, authenticated identities, revocation/rollback checks, and one-use argument-bound approvals—deployments must block unmediated bypass paths. Hosted model aliases are locators (not measured weight identities); retrieval systems must track index versions, ACLs, and invalidation lineage.

## Known false-positive and false-negative classes

These explain how current heuristics classify evidence (what collectors do not read at all is in [known limitations](known-limitations.md)).

### Model format by extension

- **Pickle-family names** (`.pkl`, `.pickle`, `.pck`, `.dill`, `.cloudpickle`, `.pt`, `.pth`, `.bin`, `.joblib`, `.ckpt`, `.pdparams`, including up to two archive/compression wrappers like `.pth.tar`, `.pkl.gz`, `.joblib.z`) are inspected by content, not suffix alone:
  - **Critical** when the inspected prefix shows pickle opcodes, a NumPy object-dtype array, a ZIP archive with a pickle-family/object-dtype member, an unread/truncated/oversized pickle/ZIP/NumPy/compressed/tar wrapper, an unreadable file, or GGUF magic under a pickle-family name (since `llama.cpp` opens by magic while chat-template checks run only on `.gguf`).
  - **Unknown (high)** when the first 64 KiB show none of those (e.g., zero-filled or firmware `.bin` — does not fail the CLI's default `critical` severity gate alone).
- **Unvalidated formats** (`.onnx`, `.gguf`, `.ggml`, `.h5`, `.hdf5`, `.keras`, `.tflite`, `.mlmodel`, `.pte`, `saved_model.pb`) are rated `unknown` (never safe) unless content reveals pickle/object-dtype evidence or a GGUF/configured chat template matches Python-internals heuristics (critical; heuristic matches do not prove exploitability and can miss computed names).
- **Content-discovered files:** `.npy`, `.npz`, `.dat`, or any file under `model`/`models`/`weights`/`checkpoint`/`checkpoints` is inventoried by content (critical if pickle/object-dtype; unknown if bounds cut inspection short). See [model integrity](model-integrity.md#format-and-model-type).

### Risk score scale

- Aggregate risk score is the uncapped sum of weights (critical 10, high 7, medium 4, low 1, info 0), recorded as `gate.score_scale: "unbounded-sum"` in `risk --json-output`. It is not a 0–100 percentage.
- The CLI fails on `critical` by default; the GitHub Action defaults `fail-on-severity` to `high` (and caps `risk-threshold` input at `0–100`; `0` / `--no-score-threshold` disables only the score threshold, leaving severity, `invalid_safetensors`, completeness, and missing-evidence gates active).
- Missing `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` adds low `completeness` findings (+1 each). See the [finding catalog](finding-catalog.md).

### Free-text redaction

- Redaction matches both known collected secret values (including overlapping occurrences) and structural patterns on original and value-masked text simultaneously, replacing union spans with a single marker so adjacent secrets cannot mask header/key delimiters.
- **Patterns scrubbed:** `name=value` / `name: value` pairs for credential key names (`api_key`, `access_key`, `secret_key`, `private_key`, `account_key`, `token`, `password`, `passwd`, `passphrase`, `pwd`, `secret`, `credential`, `sig`, or `*_key`/`*-key`—excluding suffixes like `max_tokens`/`tokenizer`), `Authorization`/`Proxy-Authorization` schemes (`Bearer`, `Basic`, `Token`, `Bot`, `ApiKey`, `Api-Key`, `DPoP`, `HOBA`, `Mutual`, `Negotiate`, `NTLM`), PEM private keys, and vendor token formats (JWTs, `ghp_`/`github_pat_`/`glpat-`, `xox`/`xapp-`, `sk-`, Stripe, `AKIA`/`ASIA`, `AIza`/`ya29.`, `npm_`, `pypi-`, `hf_`, `pcsk_`, `gsk_`, `r8_`, `pplx-`, `xai-`, `lsv2_*`, `tvly-`, `fw_`, `dckr_pat_`, SendGrid `SG.`, Shopify `sh*`, Twilio `SK`, Databricks `dapi`, Postman `PMAK-`, Doppler `dp.*`).
- **Scope & limits:** MCP configs scrub credential-named env/header/launcher/`oauth`/`auth` values (≥8 chars, excluding references and clear OAuth parameters; objects >20,000 nodes or >64 levels fail collection) across sibling free text/tool lists, and withhold token-shaped identity fields as coverage gaps. RAG identifiers containing `:` or non-path `source_uris` redact to `[redacted]`. Free-text URLs and direct VCS/URL dependencies keep only `scheme://host[:port]` (same-origin path/revision changes do not appear in `diff`). Credentials in unrecognized formats can survive redaction.

### Hard links

Hard-linked files inside the scan root are collected like regular files (confinement checks lexical symlink resolution via `dir_fd`/`O_NOFOLLOW`, not inode provenance, so deduplicated `uv`/conda/Nix trees still scan). Run collection with content-author privileges as specified in [security boundaries](../SECURITY.md#security-boundaries).

### Hosted CI

A configured workflow file is not evidence that hosted CI ran or is enforced; see [repository controls](repository-controls.md).

### Hidden characters

- `prompt` and `mcp` (tool definitions and served `verify-live`/`discover-mcp` text, rated before redaction) flag Unicode format chars (`Cf`), variation selectors, blank fillers, and unassigned default-ignorable code points: bidi embeddings/overrides/isolates, tag characters, and unassigned plane-14 code points as **critical**; directional marks (LRM/RLM/ALM) as **medium**; others as **high**. Standard emoji ZWJ/variation sequences, regional flags, and leading BOM are exempted. Right-to-left, Persian, Indic, or Mongolian text can still raise legitimate findings.
- HTML comments/declarations/CDATA and unused/duplicate Markdown link definitions or footnotes raise `hidden_markup` (**high** when containing URLs, `~/` paths, imperatives, or executable `run` targets; **low** otherwise). Shape-based matching can flag benign URL notes as high and rate non-imperative hidden instructions low ([known limitations](known-limitations.md#instructions-and-ide-settings)).

### Hook commands

Hook, `statusLine`, `fileSuggestion`, and credential-helper commands are rated statically from text (never executed): **critical** for download/base64-decode piped, substituted, or saved-and-executed into a shell/interpreter or PowerShell `-EncodedCommand` prefixes (accounting for quoting, escapes, `${IFS}`, wrappers, and argument-boundary heuristics); **high** for URL/downloader-bearing commands; **medium** otherwise. See [finding catalog](finding-catalog.md#detailed-classification-rules) for edge cases and accepted PowerShell `-e` false positives.

### Unsupported surfaces

- Surfaces no collector reads leave no coverage gap and pass all gates silently.
- Values bound only with `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` (MCP launch values, IDE settings values, A2A/RAG URL paths, inline RAG documents, withheld prompt imports/templates) carry a low `completeness` finding (or withheld-hash marker) when collected without the key, causing `diff --fail-on-alert` to raise a **medium** unbound-values alert on every comparison so keyless changes cannot pass silently. Key-only fields on records without that risk (such as A2A skill descriptions) still cannot alert without the key ([known limitations](known-limitations.md)).

## What results do and do not establish

A passing scan is an inventory snapshot, not proof that a model is benign, that a tool backend obeys its description, or that runtime actions are mediated. Always inspect exit codes, coverage, exclusions, and failures (`0` from informational commands, `--report-only`, or skipped gates does not establish approval).

### Collection, policy, and source binding

- **Static scope:** Static collection never executes code, hooks, model loaders, or launchers. `registry` reads root `requirements*.txt` (pip 26.3 rules, reporting includes/constraints/editables/URLs/unknown options/non-UTF-8 as gaps; note `${NAME}` inside option values is unresolved) and Dockerfile `FROM` lines (BuildKit default rules; `ARG`/quoted/escaped images are gaps). `verify-live` and `discover-mcp` are explicit opt-in live operations that never call tools.
- **Policy precedence:** `scan`, `validate --project`, and `risk --project` automatically apply tightening settings from `.nexus-symbiote.yaml`; relaxations require `--accept-project-policy` (bounded by any signed operator policy) and are recorded in `policy_weakened` and stderr warnings. `--no-project-policy` ignores checkout policies entirely ([policy reference](policy-reference.md)).
- **Source binding & reconciliation:** Unkeyed structure digests detect added/removed MCP/A2A/RAG/IDE keys, launchers, pins, origins, and redacted IDE settings shapes; `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` adds HMACs over raw values without exporting secrets. Note that tool `definition_hash` and non-OAuth A2A scheme requirements are unkeyed digests (confirmable by guessing if low-entropy). Non-Markdown prompt imports/targets withhold unkeyed `content_hash` (using keyed HMACs instead), and credential-named non-Markdown files (`.env`, `secrets/*`) are never read ([source binding](verification-source-binding.md#files-named-as-holding-credentials)). Legacy snapshots require recollection.

### Capability evidence summary

| Capability | Evidence and limitation |
| --- | --- |
| ShadowScan integration | Source-report digest (auth) + normalized content digest (drift), mapped components/edges, and explicit unmapped/projection limits. Producer verified only via `verify-discovery --bundle` or `validate`/`risk --project --signature-policy`; authenticates producer, not commit/time; never upgrades trust. |
| MCP and tools | Scoped config references and supported Python/TS/JS source declarations; runtime descriptors and backend behavior require separate evidence. |
| Model integrity | Whole-file hashes of weights (including ONNX external data, SavedModel variables, shard indexes), config/tokenizer/chat-template/custom-code digests, bounded format inspection, SafeTensors header fingerprints, and operator Sigstore/digest pins. Neither format nor signature proves benignness. |
| Instructions and skills | Source-bound artifacts and suspicious-content findings; limited to supported files and patterns. |
| Retrieval and registries | Declared configs, package identities, and lockfile/image lineage; does not prove installation or retrieval ACL enforcement. |
| A2A and IDE declarations | Agent Cards, host settings, and extension declarations; supplier labels and `security` declarations do not prove endpoint identity or enforcement. |
| Runtime contracts | Ed25519-signed snapshots, approvals, and trust statuses in a reference adapter; deployments must prevent unmediated bypass and protect state. |
| Impact analysis & Graph view | Potential graph reachability, risk classes, and ranked exposure paths over recorded evidence; does not prove runtime exploitability, and unclassified is unknown, not safe ([graph view](graph-view.md#what-the-view-shows-and-does-not-show)). |
| Content digest | Confirms identical inventory content across runs/checkouts; does not authenticate the producer ([reproducible inventories](reproducible-inventories.md#the-content-digest)). |
| Inventory attestation | Trusted Ed25519 keys signed exact bytes/content for a stated purpose at signer's clock time; does not prove accuracy, completeness, safety, or freshness ([inventory attestation](inventory-attestation.md#what-an-attestation-establishes)). |
| Trace evidence | Agent-emitted OTLP spans matched by name/endpoint as `reported`; never raises assurance, and missing spans prove nothing ([trace evidence](trace-evidence.md#trust-model-reported-not-observed)). |
| Framework crosswalk & G7 elements | Maps findings to framework entries (not compliance or confirmed attack) and reports G7 CycloneDX field coverage with denominator ([framework crosswalk](framework-crosswalk.md#what-a-reference-means), [minimum elements](minimum-elements.md#limits)). |
| ShadowScan approved inventory | Exports the reviewed repository agent for one resource prefix; does not verify that the prefix matches the repo or its contents ([ShadowScan approval](shadowscan-inventory-export.md#what-the-export-does-not-establish)). |
| GitHub Action | Caller-owned gates, signer policy, and optional SARIF upload; disabled gates warn and report `skipped`; on `pull_request` the workflow belongs to the PR ([known limitations](known-limitations.md#github-action)). |

### Standard exports, confidentiality, and benchmarks

- **Standard exports (CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0, VEX):** Retain the digest-bound native extension in CycloneDX/SPDX for lossless recovery (recovery fails closed on tampered standard fields or stripped `incomplete` compositions). Even without the extension, conditional edges never export as unconditional relationships and coverage is never marked `complete` (`incomplete` when scoped/failed/excluded/imported; `unknown`/`noAssertion` otherwise). SARIF reports reviewable findings (marking failed runs unsuccessful; unavailable for standalone ShadowScan imports); VEX marks findings `in_triage` without asserting exploitability ([standard exports](standard-exports.md)).
- **Artifact confidentiality & diagnostics:** Inventories expose infrastructure, permissions, source paths, and instruction digests—restrict access and review before sharing. IDE records retain permission mode, blanket grants, rule/hook counts, findings, and redacted-file hashes (never raw rules or hook commands), while user/managed policy and session flags stay outside static scope. Failures emit fixed diagnostic codes without raw exception text; `--debug` prints error classes and code locations only.
- **Benchmarks:** The committed security and inventory regression corpora verify finite regression cases and do not establish field accuracy, complete coverage, or percentile rankings.
