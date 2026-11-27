# Known limitations

What Nexus SymBiote does not collect, compare, or verify, by surface, and how each limit affects CI gates. For finding classification trade-offs, see [known false-positive and false-negative classes](security-model.md#known-false-positive-and-false-negative-classes); for `0.1.0` historical limits, see [its security policy](https://github.com/aisecnomad/Nexus-Symbiote/blob/v0.1.0/SECURITY.md#known-limitations-in-010).

Each collector limit has one of three gate effects:

- **Not recorded:** No collector reads the surface. Coverage stays `complete`, so `validate`, `risk`, and `diff --fail-on-alert` pass when it changes — review changes there by other means.
- **Gap:** A collector recognizes the input (or an operator exclusion) but cannot verify its contents. Coverage becomes `partial`, and default `scan`, `validate`, and `risk` gates fail.
- **Failure:** Collection stopped on an unreadable, malformed, escaping, or oversized input. Collector status becomes `failed`, and default gates fail.

Bypassing a documented control in a way not described here warrants a [private vulnerability report](../SECURITY.md#reporting-a-vulnerability).

- [Every collector](#every-collector) · [MCP servers and tools](#mcp-servers-and-tools) · [Models](#models) · [Instructions and IDE settings](#instructions-and-ide-settings) · [Text-poisoning rules](#text-poisoning-rules) · [Registry and containers](#registry-and-containers) · [A2A and RAG](#a2a-and-rag) · [ShadowScan](#shadowscan) · [Signatures](#signatures) · [Attestations](#attestations) · [Exports](#exports) · [Gates and drift](#gates-and-drift) · [Trace evidence](#trace-evidence) · [Graph view](#graph-view) · [G7 minimum elements](#g7-minimum-elements) · [Live mode](#live-mode) · [Runtime gateway](#runtime-gateway) · [GitHub Action](#github-action) · [Resource use](#resource-use)

## Every collector

- **Collection limits & exclusions fail closed.** Exceeding any [collection limit](collection-limits.md) (`--limit NAME=VALUE`, `NEXUS_SYMBIOTE_LIMITS`, or Action `limits`) fails collection; `mcp`, `a2a`, `rag`, `source`, and `shadowscan` cap scanned source text at `source-scan-bytes` (64 MiB default). Operator `scan.exclude_paths` entries and non-empty default-excluded directories (`.git`, `node_modules`, `__pycache__`, `.venv`, `venv`) containing agent files record coverage gaps. Use identical limits across `scan`, `validate --project`, and `risk --project`.
- **Confinement, symlinks & hard links.** Reads use `openat`/`O_NOFOLLOW` beneath the scan root. Escaping, absolute, looping, or special-file symlinks record failures; directory symlinks are not walked as trees (except resolved steering/skill paths). Hard-linked files inside the tree cannot be distinguished from single-link files — scan as an unprivileged user on hosts with `fs.protected_hardlinks=1`.
- **Identifier neutralization & script mixing.** Component `name`, `description`, `supplier`, MCP approval/filter lists, finding details, and failure text replace tabs/breaks with spaces and controls/bidi/format characters with `U+FFFD` (recording `neutralized_raw_sha256` and high `identifier_characters` when identifier fields hold them or intraword mixed-script lookalikes). Emoji `U+FE0F`, ordinary `U+200C` joiners, and whole-word multi-script names (`MCP сервер`) are preserved without findings; raw `source_path` and `surfaces_scanned` strings retain filesystem paths as collected.
- **Repository manifest (`agent.yaml`).** Optional [`agent.yaml`](agent-manifest.md) entries remain `declared` claims (never upgrading assurance); malformed YAML, >64 nesting depth, or escaping instruction paths fail collection.

## MCP servers and tools

- **Launcher classification & pinning.** Package runners (`npx`, `npm exec`, `pnpm dlx`, `yarn dlx`, `bunx`, `uvx`, `uv run`, `uv tool run`, `pipx run`, `deno run`) and container engines (`docker`/`podman`/`nerdctl run`) are classified statically ([collector reference](collectors.md)). Exact registry versions (`pkg@1.2.3`, `pkg==1.2.3`) and `sha256:` image digests mark `version_pinned: true` (emitting medium `transitive_resolution` where transitive dependencies resolve at launch). Checkout-relative commands (`./npx`), shell wrappers, dynamic expansions, local/git/tarball specs, code-loading env vars (`NODE_OPTIONS`, `PYTHONPATH`, in-checkout `BASH_ENV`/`PATH`), and unrecognized launchers mark `version_pinned: false` with `launcher_identity` / `launch_context` findings. Static pinning never proves installed bytes match registry tarballs.
- **Source binding & credential scrubbing.** Static MCP records export structural digests (`mcp-static-config/v4`) and scrub literal credentials across `env`, args, headers, and URLs (`credential_exposure` up to 12 listed / 64 scanned positions per server; URL userinfo raises `transport_security`). Without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, redacted values, endpoint paths/queries, non-root `cwd`, `envFile`, `oauth`/`auth`, and uninterpreted client fields remain unbound — emitting a low `completeness` finding and a medium unbound-values alert on keyless `diff --fail-on-alert`.
- **Client dialects & source-code servers.** Supported client configs (`.mcp.json`, `mcp.json`, Claude, Cursor, VS Code, Windsurf, Cline, Zed, Continue, opencode, Junie, Codex, Gemini CLI, `.claude-plugin/plugin.json`) are parsed with bounded JSON/JSONC/YAML/TOML readers; user `$HOME` configs are unread. Application code starting MCP clients/transports records a gap rather than a component. Static Python (`FastMCP`, `MCPServer`) and TS/JS (`McpServer`) collectors extract module-level tool registrations outside test/build/doc/example directories, recording gaps on low-level `Server`, dynamic imports, reflection, escaped server handles, or unrecognized `.tool` receivers; post-construction mutations, `tsconfig` path aliases, and non-MCP frameworks leave no gap ([TypeScript inventory](typescript-inventory.md)). Plain `http://localhost` loopback endpoints without `command` emit no transport finding.

## Models

- **Format inspection & scope.** Known model extensions (`.safetensors`, `.gguf`, `.onnx`, `.pkl`/`.pt`/`.bin`/`.joblib`/`.cloudpickle`, SavedModel, Keras `.h5`/`.keras`) and content-sniffed files under `model(s)`/`weights`/`checkpoint(s)` are inventoried by SHA-256 and bounded header/opcode inspection (64 KiB pickle prefix, 4,096 opcodes, 1 MiB ZIP directory). SafeTensors validates header structure and trailing polyglot bytes without inspecting tensor values; renamed pickles outside model directories or unsupported formats (`.nemo`, `.mar`, `.sav`, TensorRT engines) are unread unless declared.
- **Chat templates & companion files.** Hugging Face and GGUF chat templates are scanned lexically and via joined-literal analysis for Jinja2 sandbox-escape markers (`__class__`, `attr`, `_globals`, mangled names); dynamic indirect lookups can still evade lexical patterns, and SafeTensors weights retain `safe` serialization beside a template finding ([model integrity](model-integrity.md)).

## Instructions and IDE settings

- **Instruction discovery, `@path` imports & withheld digests.** `prompt` inventories root and nested instruction files (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`, `.cursorrules`), rule/prompt/subagent directories, `prompts/`, and `*.prompt.{md,yaml,yml}` ([collector reference](collectors.md)), following `@path` imports up to 5 hops across CommonMark and `marked` grammars. Non-Markdown imports and rule/prompt templates withhold unkeyed `content_hash` (requiring `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` for drift binding), whereas skill/command resources always record unkeyed `sha256` digests — including a symlink to a withheld import such as `.claude/skills/x/app.json` linked to `config/app.json` — so keep secrets and configuration out of skill directories. Non-Markdown credential-shaped filenames (`.env*`, `.pem`, `.key`, `.npmrc`, SSH keys) are refused as gaps.
- **Hidden characters & hidden markup.** UTF-8 instruction files and decoded YAML/TOML/front-matter strings are checked for invisible/bidi/tag characters and line separators (`U+0085`, `U+2028`, `U+2029`), while `hidden_markup` flags HTML comments/CDATA/PIs and unused or duplicate Markdown definitions/footnotes (rated high when containing URLs, `~/`, or imperative command patterns).
- **IDE settings, hooks & `diff-instructions`.** `ide_agents` rates Claude/Cursor/Codex hooks, `statusLine`, `fileSuggestion`, credential helpers, permission rules, `settings_environment`, and Codex top-level/`[profiles.*]` settings statically by command/rule shape; user/managed host settings, unlisted env vars, and runtime flags remain outside repo scope. `diff-instructions` compares structural grants, imports, URLs/paths, hidden markup, and scope rules — it never judges natural-language prompt prose.

## Text-poisoning rules

- **Bounded lexical matching.** `instruction_injection` and `tool_description_poisoning` run linear-time NFKC-folded (bounded expansion) regex rules over collected component text and decoded JSONC/YAML/TOML/front-matter strings ([finding catalog](finding-catalog.md)). Paraphrased overrides, homoglyphs without Latin context, uncollected files, or payloads past tag/comment window bounds (800 / 1,200 chars; 64 matches per surface) can evade detection, while benign examples quoting `"ignore previous instructions"` or `"never tell the user"` require policy suppression.

## Registry and containers

- **AI-scoped catalog & root manifests.** `registry` inventories packages and base images matching its [AI catalog](registry-collector.md#ai-package-catalog) from root manifests, lockfiles (`npm`, `pnpm`, `yarn`, `uv`, `poetry` — see [lockfile evidence](npm-lockfile-evidence.md)), and Dockerfiles/Compose files; it is not a general-purpose language SBOM (use `import-sbom` for full dependency graphs) and does not read subdirectory requirements, `setup.py`, Helm/K8s manifests, or `postinstall` scripts. Lockfile claims are never fetched over the network.

## A2A and RAG

- **Static declarations & keyed binding.** Static A2A cards (`.well-known/`, root `agent.json`/`agent-card.json`/`a2a/agent.json`), A2A clients, RAG vector stores, and guardrail configs (`promptfooconfig.*`, `guardrails.*`, NeMo `config.yml` + `.co`/`actions.py`/`prompts.yml`) export origin-sanitized URLs and structural hashes. Without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`, same-host path/query edits and inline RAG document changes emit an unbound-values notice (`v1` RAG baselines must be recollected once under `v2`, see [every v1 RAG record drifts once under v2](verification-source-binding.md#rag-sources)). Card auth schemes and signatures are recorded structurally without cryptographic or runtime enforcement verification; no collector emits `memory-store` components.

## Application source

- **Declarations, not behaviour.** The `source` collector records the model identifiers that Python code gives an SDK. Whether that code runs, which branch it takes and what an environment variable holds at run time are not observed, so every record is `declared`.
- **Literal arguments only.** A model identifier is read where it is written as a literal argument of the call. One reached through a name, an environment default, a joined string, a conditional, an attribute, a parameter or another module is a coverage gap, as is a model argument given to a function the project defines. Following those is a later slice of the collector.
- **Known SDKs and unknown callees.** A model keyword is read on a call the collector traces to an SDK in its table, and on a call of an object it cannot tell that is named as SDK calls are; there, a keyword of the same name that holds something else is recorded as a model. A wrapper library the table does not list, and a method of an unknown object named otherwise, are not read. A call of a name the collector cannot tell is read, so such a method bound to a name first is read as one, and a positional model argument is read only for the entry points in its table, not for a client's method such as `ollama.Client().chat("llama3")`. A call of an item of a container, such as a class looked up in a dict and called at once, is not read; bound to a name first, it is. A weights library given a model object and options the collector cannot read, as `Trainer(model=model, **kwargs)` is, is a gap, though it loads no model by name.
- **Links and annotations.** A directory link from the application into a skipped directory is walked under its target's name and not read, with no gap. A parameter annotated with a string, such as `"OpenAI"` under `TYPE_CHECKING`, is an object the collector cannot tell, and one annotated `Optional[...]` or `X | None` holds a value it cannot read. A file that cannot be parsed is a gap when an SDK import appears anywhere in its text, even in a comment.
- **What is skipped.** Directories named `tests`, `test`, `__tests__`, `dist`, `build`, `docs`, `benchmarks` and `examples`, and test modules. Source in other languages, notebooks and configuration files are not read by this collector, nor is an SDK loaded through `importlib` or `__import__`.
- **Providers.** No provider is recorded. An identifier such as `anthropic/claude-sonnet-4-5` is kept as written, routing prefix and all, and the client class, a base URL and a framework's default service are not read.
- **Two records for one model.** A model that a ShadowScan report cites and the collector also reads is two components, one imported and one declared.

## ShadowScan

- **Producer-bound `declared` claims.** Imported [Nexus-ShadowScan](shadowscan-integration.md) reports record Sigstore producer verification (`import-shadowscan --bundle`), failing closed in CI when unsigned unless `--allow-unsigned-discovery` is set. Signatures authenticate the producer (not the git commit or freshness — pin per-repo signer identities or `expected_sha256` and set `SHADOWSCAN_IDENTITY_KEY` across reruns). Only `agent-config` (`coding-agent-config`), `framework-usage` (`project`), and line-confirmed model citations map to components; unmapped secret/infra/runtime findings remain gate-closing coverage gaps. `export-inventory` approves only the root project location (sign exported files with `attest` outside the scanned checkout).

## Signatures

- **Ancestry ownership & Sigstore trust root.** POSIX signer policies, trusted keys, and `--signer-scopes` maps require user/root ownership and non-group/world-writable modes across their directory ancestry (`022` umask; unpinned `--trust-root` inside an untrusted checkout is refused). Offline Sigstore verification validates ownership, non-symlink ancestry, and permissions on the local TUF cache (or uses an explicit `--trust-root` + `--trust-root-sha256`); the GitHub Action seeds an isolated cache from its hash-locked `sigstore` package, so newly rotated or retired Sigstore keys take effect when the Action pin updates.

## Attestations

- **Ed25519 DSSE scope & freshness.** `attest` and `verify-attestation` (`--require-attestation` on `validate`/`risk`, and Action `reviewed-baseline-attestation` / `attest-build-provenance`) use offline Ed25519 keys without transparency logs or automatic revocation — separate keys by purpose (`generated` vs `reviewed`), bound age with `--max-age-days`, and keep trusted public keys outside git checkouts and hard-linked stores. Subjects nested >256 levels deep attest by raw bytes only (`--match file`).

## Exports

- **Coarse standard coverage & projection bounds.** CycloneDX `compositions` and SPDX relationship `completeness` express only `incomplete` or `unknown` (`noAssertion` in SPDX), never `complete`: `incomplete` when a collector failed, was not run or left a gap, a surface or a path beyond the default exclusions was excluded, or discovery was imported, and `unknown` otherwise. Re-serializers that strip `compositions` (e.g., `cyclonedx-python-lib`) break recovery of `incomplete` exports ([standard projection versions](fingerprint-migration.md#standard-projection-versions)).
- **Malformed input stops some exports.** A lone UTF-16 surrogate (such as `\ud800`) carried into a component field has no RFC 8785 content digest or UUIDv5 serial number, causing `scan` and `import-shadowscan` to fail closed (exit `1`) without writing output.
- **Determinism & crosswalk scope.** Native JSON and CycloneDX are byte-identical (SPDX requires `SOURCE_DATE_EPOCH`; SARIF relative URIs depend on `cwd`). Framework crosswalk mappings ([framework crosswalk](framework-crosswalk.md#limits)) are informative project mappings, not legal or auditor certifications.

## Gates and drift

- **Recorded-surface & checkout bounds.** `validate`, `risk`, and `diff --fail-on-alert` evaluate recorded inventory claims (pass `--project` to reconcile against the checkout, and use the same `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` across snapshots). Without an operator signer policy, passing `--project` integrity proves checkout agreement, not artifact provenance ([roadmap](../ROADMAP.md#plan)). Checkout `.nexus-symbiote.yaml` files can tighten gates automatically, while relaxations require `--accept-project-policy` (ignored under `--no-project-policy` and bounded by `--operator-policy`). Native readers reject JSON nested deeper than 128 levels and malformed `SOURCE_DATE_EPOCH` values.

## Trace evidence

- **Self-reported telemetry.** `trace-diff` compares exported OTLP spans (up to 16 files, 64 MiB/file, 1M spans, 128 attributes/span; prefer JSONL for large traces) against one inventory by name, host/port, workload identity, and tool hash ([trace evidence](trace-evidence.md)). Missing or sampled spans prove nothing, and unrecorded remote MCP tools appear undeclared until captured via `discover-mcp --record`.

## Graph view

- **`graph` risk classes & bounds.** `graph` derives risk classes and up to 200 ranked shortest exposure paths from recorded capabilities, transport/pinning flags, model serialization safety, and IDE approval modes ([graph view](graph-view.md)). Unclassified components are `unknown` (not safe), paths show structural association rather than proven exploitability, and dense graphs should use `--focus` or `--format json`.

## G7 minimum elements

- **Field presence, not compliance.** `minimum-elements` evaluates CycloneDX `cyclonedx-1.7/2` field presence against the 50 G7 elements without certifying accuracy ([minimum elements](minimum-elements.md#limits)); eleven elements require producer-supplied metadata, and in-memory schema validation uses ~11 KiB per component (~2.6 GiB near the 16 MiB inventory cap).

## Live mode

- **Declarations & process containment.** `--live` (`discover-mcp`, `verify-live`, `advisories`) disables the Python offline tripwire for that run. Live MCP commands observe handshake/tool declarations rather than backend code; `observed_endpoint_hash` is unsalted SHA-256. On Linux, `verify-live` isolates stdio launchers in an unprivileged PID namespace with `pidfd` teardown (or a subreaper/cgroup wrapper under `--no-isolation`, which root/`CAP_SYS_PTRACE` or external daemon spawners like `systemd-run` can escape; user namespaces mapping `/` to overflow `nobody` refuse launch policies). Always run `verify-live` inside a dedicated container/VM worker, and pass `--exclude` / `--dry-run` on `advisories` when private package names must not reach OSV.

## Runtime gateway

- **Mediated `invoke` boundary.** `ReferenceGateway` enforces signed snapshots, trust statuses, single-use approvals, RFC 8785 canonical arguments (`canonical_arguments=True` default), and offline ECMA-262/JSON Schema 2020-12 validation only for calls routed through `invoke` ([runtime assurance](runtime-assurance.md)). Operators must close unmediated tool paths, provision SQLite state directories mode `0700` shared across replicas, retire superseded snapshots via `runtime register`, and note that macOS validation workers lack `RLIMIT_AS` enforcement.

## GitHub Action

- **Workflow & runner trust boundary.** Because `pull_request` runs execute the merge commit's workflow YAML unless protected by organization rulesets and `CODEOWNERS` on `.github/`, protect the workflow and keep untrusted build/test steps out of the Action job ([drift gate](drift-gate.md#protect-the-gate)). Narrowing `scanners` requires `validate: 'false'` and `risk-check: 'false'`; multiple Action steps in one job require distinct `artifact-name` and `sarif-category` inputs.

## Resource use

- **Size bounds vs. wall-clock time.** Collection limits bound bytes and item counts rather than wall-clock duration (hashing 256 GiB of weights or validating 100,000-component SPDX exports can run for minutes or hours; native JSON outputs cap at 16 MiB, and `validate --project` caps reads at `6 * model-total-bytes`). Tree-sitter TypeScript parsing runs in-process under syntax-byte, node, and 250 ms CPU-time bounds ([collection limits](collection-limits.md#the-typescript-parse-time-limit)); always configure CI job timeouts (`timeout-minutes`).
