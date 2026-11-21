# CLI reference

Every `nexus-symbiote` command and option. `nexus-symbiote --help` and
`nexus-symbiote <command> --help` describe the version you installed and are
authoritative where this page differs; `tests/test_cli_reference.py` fails when a
command, option or environment variable is missing here.

```text
nexus-symbiote [--offline | --live] [--debug] [--limit NAME=VALUE]... [--version] [--help] COMMAND [ARGS]...
```

## Global options

| Option | Description |
|---|---|
| `--offline` | Refuse name resolution, network connections and process creation (the default). |
| `--live` | Allow the network and process steps of `discover-mcp`, `advisories` and `verify-live`. Every other command stays offline. |
| `--debug` | Print where a collector or internal error was raised on standard error: its class and the files, lines and functions of its traceback, without its message, which can quote project or inventory text. Without it, an unexpected error ends the command with `Error: internal error (<error class>)` and exit status 1, and a collector error is recorded by its diagnostic code only. |
| `--limit` `NAME=VALUE` | Set one [collection limit](collection-limits.md) for this command, such as `entries=200000`, `model-bytes=128GiB` or `import-lookups=20000`. Repeatable; overrides `NEXUS_SYMBIOTE_LIMITS` for that name. |
| `--detailed-exit-codes` | Use distinct exit codes for `scan`, `validate`, `risk`, and `diff`: `0` passed, `2` usage error, `3` gate or verification failed, `4` collection/input/internal failure. |
| `--legacy-exit-codes` | Use legacy exit codes (`0` passed, `1` gate or input failure, `2` usage error; default). |
| `--version` | Print the version and exit. |
| `--help` | Print help and exit. |

Every `-o`/`--output` file, and the policy file `init --path` creates, is written
atomically and never through a symbolic link:
its directory must already exist, and no directory on the path may be a symbolic
link (the standard macOS root links `/tmp`, `/var` and `/etc` to `/private` are
the only exception). `..` steps to the
real parent directory, as the operating system resolves it. A refused path ends the
command with an error and writes nothing; any other failure, such as a permission
error, is reported by the operating system's message, without the path.

Every AgentBOM a command reads is opened the same way: neither the file nor any
directory on its path may be a symbolic link (with the same macOS exception), and
FIFOs, devices, directories and `/dev/stdin` are refused. The
error names the reason. Native inventories are limited to 16 MiB for reading and
writing alike.

Mode flags and `--debug` go before the command. Without a flag,
`NEXUS_SYMBIOTE_MODE=offline|live` selects the mode; without either, the mode is
offline. See [offline and live modes](offline-and-live-modes.md).

`--limit` also goes before the command. `NEXUS_SYMBIOTE_LIMITS=NAME=VALUE,NAME=VALUE`
sets limits from the environment, and `--limit` wins for the names it sets. Limits
apply to every command that collects from a project; a project's own files never
change them. See [collection limits](collection-limits.md).

## Commands

| Command | Mode | Purpose |
|---|---|---|
| [`scan`](#scan) | offline | Inventory a project and write an AgentBOM (native JSON, CycloneDX, SPDX or SARIF) |
| [`import-shadowscan`](#import-shadowscan) | offline | Convert a Nexus-ShadowScan report into an AgentBOM of imported claims |
| [`validate`](#validate) | offline | Check an AgentBOM's completeness and integrity, optionally against the project |
| [`risk`](#risk) | offline | Score findings and apply the risk gate |
| [`diff`](#diff) | offline | Compare two AgentBOMs and report security-relevant drift |
| [`diff-instructions`](#diff-instructions) | offline | Compare instruction files between two trees for security-relevant CommonMark changes |
| [`summary`](#summary) | offline | Print component and risk counts |
| [`digest`](#digest) | offline | Print the digest of an AgentBOM's bytes, its canonical digest and its run-independent content digest |
| [`blast-radius`](#blast-radius) | offline | List agents and components associated with one component |
| [`graph`](#graph) | offline | Write a self-contained HTML or JSON view of an inventory's associations, risk classes and exposure paths |
| [`baseline`](#baseline) | offline | Write an unsigned snapshot only if the scan gate passes |
| [`vex`](#vex) | offline | Export schema-validated VEX findings with optional operator decisions, advisories and trace evidence |
| [`trifecta`](#trifecta) | offline | Analyze an inventory offline for lethal trifectas, chained toxic flows and tool shadowing |
| [`crosswalk`](#crosswalk) | offline | Map findings to OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001 and CWE entries |
| [`minimum-elements`](#minimum-elements) | offline | Report which G7 AI SBOM minimum elements an AgentBOM's CycloneDX export carries, and how to supply the missing ones |
| [`verify-artifact`](#verify-artifact) | offline | Check a file's SHA-256, and optionally its Sigstore bundle |
| [`verify-discovery`](#verify-discovery) | offline | Check that a ShadowScan report's bytes match the digest a BOM records; with `--projection` or `--bundle`, also compare the BOM's imported components with the report |
| [`export-inventory`](#export-inventory) | offline | Write the reviewed repository agent as an approved inventory that ShadowScan's `--inventory` accepts |
| [`import-sbom`](#import-sbom) | offline | Import a foreign CycloneDX or SPDX SBOM as DECLARED evidence without picking silent winners |
| [`evidence-profile`](#evidence-profile) | offline | Report concrete evidence attributes per component without a scalar TrustScore |
| [`init`](#init) | offline | Create a `.nexus-symbiote.yaml` policy file |
| [`runtime keygen`](#runtime-keygen) | offline | Create an Ed25519 key pair for runtime contracts |
| [`runtime sign`](#runtime-sign) | offline | Sign a runtime contract |
| [`runtime verify`](#runtime-verify) | offline | Verify a signed runtime contract's purpose, signers and validity window |
| [`runtime digest`](#runtime-digest) | offline | Print the digest a runtime contract, approval or revocation list binds |
| [`runtime key-id`](#runtime-key-id) | offline | Print the key ID of an Ed25519 public key |
| [`runtime register`](#runtime-register) | offline | Make a newly issued runtime snapshot current in a gateway state store |
| [`attest`](#attest) | offline | Sign a file's exact bytes, usually an inventory or a baseline, for a stated purpose |
| [`verify-attestation`](#verify-attestation) | offline | Check that trusted keys attested a file's bytes or inventory content for a purpose |
| [`trace-diff`](#trace-diff) | offline | Compare the runtime use that OpenTelemetry traces report with an AgentBOM |
| [`export-standard`](#export-standard) | offline | Export an AgentBOM to CycloneDX (1.6/1.7) or SPDX 3.0.1 with typed AI projections and producer declarations |
| [`audit-control-plane`](#audit-control-plane) | offline | Audit hook targets, skill preambles, MCP bridges, steering surfaces, CI agents and identities |
| [`discover-mcp`](#discover-mcp) | **live** | List the tools an HTTPS MCP server serves, without calling them |
| [`advisories`](#advisories) | **live** | Query OSV for advisories affecting exact PyPI and npm package versions |
| [`verify-live`](#verify-live) | **live** | Compare an AgentBOM with the tools that operator-pinned stdio servers serve |

## Output and CI logs

Results go to standard output: the reports of `validate`, `risk`, `diff`, `summary`,
`blast-radius`, `digest`, `trace-diff` and `verify-attestation`, the JSON line that
`attest` prints, the inventory that `scan` and `vex` print and the reports that
`crosswalk`, `minimum-elements` and `graph --format json` print without `-o`, and every
`--json-output` document. Progress, notes, warnings and errors go to standard error,
and so do the coverage gate verdict of `minimum-elements`, everything that
`export-inventory` prints, such as the inventory's digests, and the summary that
`graph` prints after it writes a file. `scan` writes its progress and its gate verdict
there too, so that standard output can carry the inventory:
`nexus-symbiote summary bom.json > summary.txt` keeps the summary, and `2>/dev/null`
hides only diagnostics.

An output option given as `-`, or `./-`, is refused rather than written to a file named
`-`: leave out `-o` to print to standard output.

Every command prints text taken from an inventory, a checkout or a live server, such as
names, paths, references and descriptions, literally and inert, in a terminal and in a
CI log:

- control, format and line-break characters, every noncharacter (U+FDD0 to U+FDEF and
  the last two code points of each plane, such as U+FFFE and U+FFFF), and every other
  default-ignorable code point (Unicode's
  Default_Ignorable_Code_Point, such as variation selectors and blank fillers like
  U+3164), are replaced with U+FFFD, so such text cannot move the cursor, rewrite
  earlier output, start a new line or carry text a reader cannot see; a tab is
  replaced with one space, so a name stays readable but cannot line text up under a
  later column; private-use characters are printed as they are, since they cannot move
  the cursor or hide text, though a font may draw them as any symbol;
- a `##` that would introduce a CI log command anywhere in a line (GitHub Actions'
  legacy `##[command]`, Azure Pipelines' `##vso[`, TeamCity's `##teamcity[`) is
  followed by U+FFFD;
- no such text starts an output line: every line opens with fixed text, so a name
  cannot become a `::command::` workflow command;
- nothing is read as markup or emoji codes, and lines are never wrapped.

`crosswalk --format markdown` writes such text Markdown-escaped instead of literally:
every ASCII punctuation character in it follows a backslash, after the replacements
above. `minimum-elements --format markdown` writes the component references it takes
from the inventory as Markdown code spans, after the same replacements.

The JSON that `scan`, `vex`, `crosswalk`, `discover-mcp`, `advisories`,
`minimum-elements` and `graph --format json` print without `-o`, the JSON that
`attest`, `verify-attestation --json-output` and every `runtime` command print, such as
the identities of the snapshot that `runtime register` made current, the candidate
inventory that `verify-live --record` prints, and the `--json-output` documents of
`validate`, `risk`, `diff`, `summary`, `blast-radius`, `digest`, `trace-diff` and
`verify-live`, write a `[` that follows such a `##` as `\u005b`; the document parses to
exactly the same value. Files written with `-o` are not changed.

Colors are used only on a terminal, and `NO_COLOR` turns them off.

## Exit codes

| Exit | Meaning |
|---|---|
| `0` | The command completed and every requested gate passed. |
| `1` | A gate or check failed (risk gate, integrity, digest or signature mismatch, a `diff` security alert, since `--fail-on-alert` is the default and only `--no-fail-on-alert` turns that gate off, incomplete collection or observation), the input could not be read or parsed, `import-shadowscan` ran without `--report-only`, unverified ShadowScan discovery evidence was imported, validated or scored in CI without `--allow-unsigned-discovery`, a project policy that weakens a gate was applied in CI without `--accept-project-policy`, or an unexpected internal error occurred. |
| `2` | Usage error: an unknown command or option, a missing argument or file, a `PROJECT_PATH` of `scan` or `baseline` or a `--project` of `validate`, `risk`, `verify-artifact` or `verify-live` that is a file, a `verify-live` launch policy kept where the [launch policy](#launch-policy) rules forbid, a `verify-attestation` `--trusted-key` kept where the [trusted-key rule](#verify-attestation) forbids or a `runtime verify` or `runtime register` public key kept where the same rule forbids, an invalid value (including a malformed `verify-artifact --sha256` and an incomplete `--bundle`, `--signer-identity` and `--issuer` set), a relative project path that a symbolic link leads outside the working directory, an invalid `NEXUS_SYMBIOTE_MODE` or collection limit, a `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` shorter than 32 characters, a malformed `SOURCE_DATE_EPOCH` for `scan`, `baseline` or `import-shadowscan`, or a live command run without live mode (`advisories --dry-run` contacts nothing and runs in either mode). |

What exit status 1 means for each gate:

| Command | Exits 1 when |
|---|---|
| `scan` | A collector failed or the scan gate failed, unless `--report-only` or a report-only project policy applies. With `--check`, unverified ShadowScan discovery evidence and a failed producer check exit 1 even then. |
| `validate` | Completeness, integrity (including integrity that is only unknown), the discovery producer check, the minimum assurance level or the dependency graph failed, or unverified discovery evidence was gated (see below). |
| `risk` | The risk gate failed, `--project` reconciliation failed, or unverified discovery evidence was gated (see below). |
| `diff` | The diff reports a security alert; `--no-fail-on-alert` turns this gate off. |
| `diff-instructions` | Any instruction surface or front-matter parse fails collection, or `--fail-on-change` is set and a security-relevant change or new excluded coverage gap is detected. |
| `digest` | The file is a valid native inventory, but its canonical or content digest is undefined: the other values are printed, and the missing one as `unavailable` (`null` with `--json-output`). |
| `graph` | The inventory's graph is invalid, `--focus` names no component, or the view would hold more components than `--max-nodes`. |
| `minimum-elements` | `--fail-under` was given and fewer than that percentage of the assessable elements are present, or the inventory's CycloneDX export fails its checks. |
| `baseline` | The scan gate failed, under the project policy or the built-in one. |
| `verify-artifact`, `verify-discovery` | The digest, signature or projection does not match. |
| `verify-attestation` | Too few trusted keys signed the attestation, or it does not cover the file's bytes or content, the purpose or the age limit, or an input could not be read. |
| `verify-live` | A stdio server could not be observed completely (a run with no stdio server observes nothing), or a server's served tools, declarations or identity differ from the inventory; with `--record`, such drift fails unless `--accept-drift` is given. |
| `discover-mcp` | The observation is incomplete; with `--record`, nothing is written. |
| `advisories` | An advisory was found (unless `--no-fail-on-advisory`), or not every package in scope was looked up (`coverage` is `partial` or `none`); with `--dry-run`, only when the report lists an error. |
| `trace-diff` | With the default `--fail-on undeclared`: the traces report a tool, model, agent or MCP endpoint that the inventory does not declare, or one whose identifier could not be read, or a span whose operation name, MCP method or MCP transport could not be read, or a span or resource has more than 128 attributes, or no span carries a GenAI or MCP attribute of its own. An inventory or trace file that cannot be read always exits 1; a missing file or a directory is a usage error (exit 2). |
| `export-inventory` | The inventory holds no repository agent or more than one, its agent's identity is not declared and `--include-unnamed` is absent, or its name or owner cannot be written so that ShadowScan reads it back exactly; nothing is written. |

`--report-only` on `scan` and `import-shadowscan` reports collection failures and
findings without turning them into exit status 1, as a project policy with
`failure_mode: report-only` does for `scan`. It is for exploration, not approval:
`baseline` applies the built-in gate whatever the project policy says.

Unverified ShadowScan discovery evidence is gated separately. `import-shadowscan`
and `scan --check` (including `--report-only` and a report-only project policy, which
never relax this gate), `baseline`, `validate` and `risk` exit 1 on
it when a CI variable is set (see [environment variables](#environment-variables)) or
`--fail-on-unsigned-discovery` is given, unless `--allow-unsigned-discovery` is given.
Only a producer check made in the same run counts as verification; the outcome recorded
in the BOM is not trusted.

## Environment variables

| Variable | Effect |
|---|---|
| `NEXUS_SYMBIOTE_MODE` | `offline` or `live`; selects the mode when no mode flag is given. Any other value is a usage error. |
| `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` | An operator secret of at least 32 characters. `scan`, `validate --project` and `risk --project` then bind MCP, A2A, RAG and IDE settings values with an HMAC under it; the key never enters the inventory. A shorter key is a usage error before any collector runs. See [verification source binding](verification-source-binding.md). |
| `NEXUS_SYMBIOTE_LIMITS` | Raised collection limits for this invocation, as `NAME=VALUE` pairs separated by commas; the CLI validates the names and values. It is read from the environment of the operator, never from a scanned checkout. The GitHub Action sets it only from its `limits` input. |
| `NO_COLOR` | Any nonempty value turns colors off. |
| `XDG_CACHE_HOME`, `HOME` | Where sigstore-python caches the trusted root that offline Sigstore verification uses; see [known limitations](known-limitations.md#signatures). |
| `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` | An explicit Sigstore `trusted_root.json` file, or a directory holding one, for offline Sigstore verification. `--trust-root` overrides it. Without a pinned digest the file and its directory must be owned by the user and not writable by group or others. |
| `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT_SHA256` | The SHA-256 the explicit trust root's bytes must match. `--trust-root-sha256` overrides it; set without a trust root, it is a usage error. |
| `CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `CIRCLECI`, `TF_BUILD`, `JENKINS_URL`, `BUILDKITE`, `DRONE`, `TRAVIS` | Any value other than empty, `0` or `false` marks the run as automated: `import-shadowscan`, `scan --check`, `baseline`, `validate` and `risk` then fail on unverified ShadowScan discovery evidence unless `--allow-unsigned-discovery` is given, and `scan`, `validate` and `risk` fail on a project policy that weakens a gate unless `--no-project-policy` or `--accept-project-policy` is given. |
| `TMPDIR` | Where `verify-live` stages the private copy of a pinned launcher. |
| `_NEXUS_SYMBIOTE_COMPLETE` | Ignored. Shell completion is not offered, because an inherited completion variable would make every command, gates included, exit 0 without running. |
| `SOURCE_DATE_EPOCH` | A whole number of seconds since 1970-01-01T00:00:00Z: 1 to 12 ASCII digits, at most 253402300799. `scan`, `baseline` and `import-shadowscan` then record that instant as the collection time; without it they record none. The serial number is derived from the content digest either way, so the same inputs give byte-identical native JSON and CycloneDX files, and, with the variable set, byte-identical SPDX files too. Any other value is a usage error whose message does not repeat it. Gates still use the clock, for example to decide whether a suppression has expired. See [reproducible inventories](reproducible-inventories.md). |

## File formats

### Signer policy

`--signature-policy` (`scan`, `validate`, `risk`, `baseline`) and the Action's
`signature-policy` input take a strict JSON file, at most 4 MiB and 1,000 artifacts,
written by the operator, never by the checkout. The CLI refuses a policy inside the
scanned project or inside any Git working tree that encloses it, including a
submodule's superproject, also under another name for any of these directories, or
one with other hard links. The Action checks its input only against
`GITHUB_WORKSPACE`: it refuses a path inside the workspace, one that passes through a
symlink, or a hard link. It then copies the policy into a private directory under
`RUNNER_TEMP`, or under the system temporary directory when `RUNNER_TEMP` is unset,
and passes that copy to the CLI, which applies the rules above to the copy; a
temporary directory inside a Git working tree therefore fails the run.

```json
{
  "version": 1,
  "artifacts": [
    {
      "artifact_path": "models/classifier.safetensors",
      "bundle_path": "models/classifier.safetensors.sigstore",
      "expected_identity": "https://github.com/acme/models/.github/workflows/release.yml@refs/tags/v1.0.0",
      "expected_issuer": "https://token.actions.githubusercontent.com"
    }
  ]
}
```

Both paths are relative to the project. In version 1 every record needs exactly these
four fields. Version 2 names a `kind` on every entry: `sigstore-message-signature`
takes these four fields and an optional `expected_sha256`, and `digest-pin` takes only
`artifact_path` and `expected_sha256`; see [model integrity](model-integrity.md#operator-signature-policy).
Unknown fields, duplicate keys or artifacts, symbolic links and missing files are
refused.

Every directory at or above the project with a `.git` entry counts as an enclosing
repository. So neither a trusted base checkout that encloses the pull request's
checkout nor a home directory that is itself a repository (`~/.git`) can hold the
policy for a project below it; keep the policy where no repository encloses it.

### Launch policy

`verify-live --launch-policy` takes a JSON object, outside the project, that maps each
stdio MCP server's `bom_ref` to exactly a `command` and a `sha256`:

```json
{
  "mcp-server:146dd7ec16be91c2b267497bf940d8fa6b2d58909b7e2c15c0dd30d10c7a3a3c": {
    "command": "/opt/mcp/docs-server",
    "sha256": "sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"
  }
}
```

`command` is an absolute path to a standalone executable, and `sha256` is the SHA-256
of its bytes as `sha256:<64 lowercase hexadecimal characters>`. A server without an
entry is not started.

The file must lie outside the project and outside every repository (a directory with
a `.git` entry) that encloses the project or the inventory, including the repository
around a nested checkout such as a submodule. On POSIX
systems it must also be a single-link regular file owned by you or root that only its
owner can write, and every directory above it, up to the file system root, must be
owned by you or root and not writable by others unless it is sticky: whoever can write
an ancestor can rename the directory below it and put another policy in its place. A
policy that breaks these rules is a usage error (exit 2). The checks
catch a misplaced policy; they do not authenticate it.

The ownership rule includes `/`. Inside a user namespace that does not map host root
and keeps the host's file system, such as one made with `unshare -r`, `/` and `/tmp`
appear owned by the overflow user (usually uid 65534), so every launch policy is
refused, and no option overrides the check. Run `verify-live` where `/` and every
directory above the policy are owned by root or by you.

### JSON documents

| Command | Document |
|---|---|
| `validate --json-output` | `passed`; `assessment_basis` (`supplied-bom`, `project-reconciled`, `project-reconciled-with-supplier-claims`, `project-reconciliation-failed`, or `project-not-reconciled` when the project policy skips the completeness check); `verification_mode` (`static-offline`); `policy_source` and `policy_weakened`; `completeness` and `integrity`, each with a `status` (`pass`, `fail`, `unknown` for integrity, or `skipped` with `skipped_by`) and the validator's report (its own `assessment_basis`, issues, `issues_omitted`; for completeness `supplier_claims` and `supplier_claims_omitted`; for integrity `bytes_charged`); optional `attestation` when `--require-attestation` is given; `discovery_producer` (`null` without discovery evidence or a producer check, otherwise a `status` of `verified`, `failed`, `not-applicable` or `not-verified`, with `problems`); `unsigned_discovery` (`null`, or why unverified discovery evidence failed the run); `minimum_assurance_level`, `assurance_errors` and `graph_issues`. |
| `risk --json-output` | `passed`; `overall_score` (`null` when the run is not scored: `--project` reconciliation or the discovery producer check failed, or unverified discovery evidence was gated); `risk_level`; `coverage_status` and `coverage_gaps`; `gate_reasons`; `gate` (the effective thresholds, cutoff, ignored categories and suppression count, each with a `*_source` of `cli`, `project policy` or `built-in`); `findings`, each with its `fingerprint`; `severity_counts`; `category_scores`; `ignored_findings`; `suppressed_findings`, `suppressions_expired`, `suppressions_unused` and `suppressions_stale`; `total_components` and `components_with_risks`; `warning_threshold_exceeded`; `assessment_basis` (`supplied-bom`, `project-reconciled`, `project-reconciled-with-supplier-claims`, `project-reconciliation-failed`, or `unsigned-discovery-evidence` when unverified discovery evidence fails the run); `verification_mode` (`static-offline`); optional `attestation` when `--require-attestation` is given; `supplier_claims` and `supplier_claims_omitted`; `discovery_producer` (`verified`, `failed`, `not-verified` or `not-applicable`); `score_threshold` (`null` with `--no-score-threshold`); `fail_on_severity`; `policy_source` and `policy_weakened`. A failed reconciliation has the same keys, with empty findings. |
| `diff --json-output` | `has_changes`, `total_changes`, `components_added`, `components_removed`, `components_modified`, `dependencies_added`, `dependencies_removed` (each with its `severity` and `conditions`), `security_alerts`, `metadata_changes` and `notes`. |
| `diff-instructions --json-output` | `format` (`nexus-symbiote/instruction-diff/v1`), `base_tree`, `head_tree`, `files_scanned`, `failures` (`base`, `head`), `excluded` (`base`, `head`), `changes` (each with `class`, `file`, `block_index`, `summary` and optional redacted `text`), and `summary` (`total_changes`, `total_failures`, `total_excluded`, `by_class`). |
| `summary --json-output` | `total_components`, `component_types`, `total_dependencies`, `total_risks`, `risk_breakdown` and the inventory's `completeness` claim. |
| `minimum-elements --format json` | `format` (`nexus-symbiote/minimum-elements/v1`), `edition`, `guidance`, `statement`, `evaluated` (the standard, the projection and the tool version), `subjects`, `coverage` (`present`, `assessable` and `percent`), `counts` per status, `gate` (`null` without `--fail-under`), `clusters` and `elements`; see [G7 AI SBOM minimum elements](minimum-elements.md#running-the-command). |
| `blast-radius --json-output` | `subject`, `affected_agents`, `dependent_components`, `reachable_components`, `declared_principals`, `scope`, `effective_authority`, `linked` and `limitations`. |
| `digest --json-output` | `file_sha256`, `canonical_digest`, `content_digest`, `content_profile`, `spec_version` and `components`, in that order; a digest that is undefined for the inventory is `null`. |
| `graph --format json` | `format` (`nexus-symbiote/graph-view/v1`), `inventory`, `focus`, `coverage`, `limitations`, `nodes` (each with its risk classes, `basis`, `assessed`, findings summary and facts), `edges` and `exposure` (sources, sinks and ranked `paths`, with omitted counts); see [graph view](graph-view.md#the-json-document). |
| `crosswalk` | Sorted keys: `format` (`nexus-symbiote/crosswalk/v1`); `meaning`; `policy_source` (`built-in`), `suppressed_findings` and `ignored_findings`; `coverage_status`; `findings`, each with `category`, `severity`, `component_ref` and a neutralized `detail`; `frameworks`, each with `framework`, `name`, `edition`, `source`, `verification`, `note`, `findings_with_reference`, `findings_without_reference` and `entries` (each with `entry`, `title`, `severity_counts`, the referencing `categories` with their `rationale`, and `findings`, positions in the `findings` list); `unmapped_categories`, each with `category`, `findings` and `in_catalog`. |
| `discover-mcp` | The observation: `endpoint` (the origin only, since a path can hold a credential) and `observed_endpoint_hash` (a digest of the full URL, as `--record` stores it), `protocol_version` and `requested_protocol_version`, `collector_id`, `collection_id`, `observed_at`, `completed_at`, `client_info`, `user_agent`, `session_established`, `session_digest`, `server_info`, `server_capabilities`, `instructions` and `instructions_hash`, `declaration_hash` and `identity_hash` with their profiles, `tools` (each with its redacted `descriptor`, `definition_hash`, `fingerprint` and `lints`), `prompts`, `resource_templates`, `failures`, `complete`, `pages_observed`, `bytes_observed` and `coverage`, which names what was not observed. With `--record`, a native AgentBOM instead. |
| `advisories` | `components_checked`, `components_skipped` and `components_excluded`, with the `skipped` and `excluded` entries and their reasons; `queries` (the ecosystem, name and version of each package in scope); `advisories`; `errors`; `coverage` (`complete`, `partial` or `none`) and `complete`; `dry_run`; `checked_at`, `tool_version` and `inventory_sha256`; `scope` and `sent_to_osv`. |
| `verify-live --json-output` | `complete`, `servers_checked`, `servers_reachable`, `servers_skipped`, `has_drift`, `inputs` (the SHA-256 of the inventory and of the launch policy) and `results`: per MCP server, `server`, `server_ref`, `status` (`verified`, `failed` or `not-verifiable`), `reachable`, `reason`, `error`, `transport`, `protocol_version`, `launcher_sha256`, `rug_pull_detected`, `live_schema_hash`, `declaration_hash` and `declaration_status`, `identity_hash` and `identity_status`, and `tools` (each tool's `name`, `definition_hash` and `status`: `match`, `changed`, `new` or `unverifiable`). |
| `runtime keygen` | `key_id` and `encrypted`. |
| `runtime sign` | `out`, `predicate`, `digest`, `signers` and `signed`. |
| `runtime verify` | `contract_verified`, `kind`, `digest`, `accepted_signers` and `invocation_authorized`, which is always `false`: only the gateway authorizes a call. |
| `runtime digest` | `kind` and `digest`. |
| `runtime key-id` | `key_id`. |
| `runtime register` | `registered`, `tenant`, `deployment_id`, `agent_id`, `serial` and `digest`. |
| `attest` | One line: `out`, `subject_sha256`, `subject_format`, `content_digest` (native inventories only), `purpose`, `signers` (key IDs) and `signed`. |
| `verify-attestation --json-output` | `attestation_verified`, `purpose`, `signers`, `match`, `subject_sha256` (the file passed), `attested_sha256` (the file that was signed), `subject_format`, `signed_at`, and, when recorded, `spec_version`, `content_digest`, `content_profile` and `source_revision`. |
| `trace-diff --json-output` | The trace evidence, also written by `-o`: `format` (`nexus-symbiote/trace-evidence/v1`), `assurance` (always `reported`), `limitations`, `inputs`, `coverage`, `observed`, `reconciliation` and `gate`; see [trace evidence](trace-evidence.md#the-evidence-document). |

## Pre-commit hooks

The repository ships two [pre-commit](https://pre-commit.com) hooks. Both run
`nexus-symbiote scan . --no-project-policy --check`: they collect the working tree and
apply the scan gate with the built-in policy, write nothing into the tree, and ignore
the checkout's `.nexus-symbiote.yaml`, so a change cannot relax the gate it is checked
under. `nexus-symbiote-risk` is kept as the same gate so that existing configurations
keep working; configure one of the two.

```yaml
repos:
  - repo: https://github.com/aisecnomad/Nexus-Symbiote
    rev: <reviewed-40-character-commit-sha>
    hooks:
      - id: nexus-symbiote-scan
```

pre-commit installs a hook of `language: python` into its own environment with
`pip install`, which resolves the dependency ranges in `pyproject.toml` from PyPI
without hashes, unlike the hash-locked install the README describes. pre-commit
cannot apply `requirements-ci.lock` itself. For a locked environment, install that
lock in the way the README describes and point pre-commit at the resulting command
with `language: system` instead of using the published `language: python` hooks.
Pin `rev` to a reviewed commit, and treat the hooks as a convenience for your own
tree, not a control: a failing hook can be skipped, and the GitHub Action or a
protected CI job is the gate.

## Command details

### `advisories`

Live: query OSV for exact PyPI/npm package URLs in the inventory.

```text
nexus-symbiote advisories [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the advisory report to this file instead of standard output. |
| `--fail-on-advisory` / `--no-fail-on-advisory` | Exit with status 1 when an advisory is found (default: fail). |
| `--exclude` `NAME` | Never send this package name to OSV; a trailing `*` matches a prefix, and a `*` anywhere else is refused. Names are compared as PyPI normalizes them, and in any case (repeatable). |
| `--exclude-private-origins` | Send only packages whose lockfile resolution records the public PyPI or npm registry. A Python package that no `uv.lock` or `poetry.lock` resolves has no recorded origin, so it is withheld; withhold private names with `--exclude` instead to keep public ones checked. |
| `--dry-run` | List the package identities that would be sent, without contacting OSV (works offline). |
| `--offline-db` `PATH` | Match exact pinned PyPI/npm packages offline against an OSV JSON bundle or directory without contacting `api.osv.dev`; deduplicates alias pairs and records bundle SHA-256 provenance. A directory is read flat, and one with a subdirectory is refused, as is a bundle with no records, with an entry that is not an OSV record, or with two different records under one id. A package whose ecosystem the bundle holds no record for is an error, so the report is not complete, as is a record for the package with malformed `affected` data, an unparsable `introduced`, a range `type` the OSV schema does not define, or a range with no `introduced` event (at most 100 such errors are listed, then a count); a GIT range is skipped, since it is matched by commit, not version. A `fixed`, `last_affected` or `limit` the version parser rejects is not an error: the advisory matches unless the lower bound excludes the version, the version is at or above every `limit` while all limits parse and none is `*`, or a parsable bound does and event order puts no rejected bound in the version's interval, and when no exact `versions` entry or other range decides the match it carries `range_undecidable: true` and up to 16 `undecidable_bounds` (64 characters each). Like any match it fails this command; an operator decision passed to `vex --decisions` records its triage there, and the `vex` export marks it `rangeUndecidable`. Matching stops with one error, and exit status 1, past the [`advisory-matches`](collection-limits.md#limits) limit. |
| `--kev` `PATH` | Offline CISA/ENISA KEV JSON catalog used with `--offline-db` to elevate matched advisories to `critical` with source provenance (repeatable). A catalog with no entries is refused. |
| `--epss` `PATH` | Offline EPSS CSV/JSON catalog used with `--offline-db` to attach EPSS scores and percentiles. A catalog with no entries is refused. |
| `--max-feed-age-days` `INTEGER RANGE` | With `--offline-db`, the report is incomplete (exit 1) when the bundle's newest record, a KEV catalog's `dateReleased` or the EPSS `score_date` is missing or more than this many days old (1 to 36500; default: 30). The check cannot be turned off. |

The command sends each package's ecosystem, normalized name and exact version to
`https://api.osv.dev/v1/querybatch`, including packages resolved from a private
registry unless you exclude them. The registry collector labels a Python package
that no `uv.lock` or `poetry.lock` resolves with the public PyPI origin, which is
assumed, not recorded; for such a package only `--exclude` (previewed with
`--dry-run`) keeps a private name local while public ones are still checked. A
package that a project setting redirects to another registry or index has no
package URL, so it is not sent and is reported as `exact package identity
unavailable`. It exits 1 when an advisory is found, or when
not every package in scope was looked up (`coverage` is `partial` or `none`,
including an inventory with no exact PyPI or npm package). With `--dry-run` it looks
nothing up, so `coverage` is `none`, and it exits 1 only when a package in scope has
no exact identity or more than 500 packages would be sent. A report keeps at most
10,000 advisories per package and 20,000 in total; beyond that, lookups end with an
error and `coverage` is `partial`.

With `--offline-db`, the answer is only as recent as the files you supply, so the
command reads the date each feed states about itself and records it under
`provenance`: `db_newest_record` is the newest `modified` (or, for a record without
one, `published`) among the bundle's records, each `kev_catalogs` entry has the
catalog's `date_released` (its `dateReleased`), and `epss_catalog` has the
`score_date` (the `score_date:` in the CSV's leading `#` comment, or a top-level
`score_date` in the JSON form). A date-only value counts as midnight UTC.
`max_feed_age_days` and `feed_age_evaluated_at` (the system clock, in UTC) record
what the dates were compared with. File modification times are never used, because a
checkout or a copy sets them.

Each feed whose date is more than `--max-feed-age-days` whole UTC days before the
run adds one error, such as `offline advisory DB is 412 days old (newest record
2025-10-04); limit 30`, `KEV catalog kev.json is 412 days old (dateReleased
2025-10-04); limit 30` or `EPSS catalog epss.csv is 412 days old (score_date
2025-10-04); limit 30`. A feed that states no date adds `... carries no ..., so its
age is unknown`, and its provenance date is `null`; a date more than one day after
the run adds `... is in the future`. With any of these errors `complete` is `false`
and the command exits 1, whether or not an advisory matched. A date that is present
but is not an RFC 3339 date or date-time (`2025-10-04`, `2025-10-04T00:00:00Z`, or
with a numeric offset) refuses the feed: the command exits 1 without a report. No
value turns the check off, and 0 is a usage error; to accept an old feed
deliberately, pass a larger number, which the report records. The dates are the
feeds' own unauthenticated statements: they detect a forgotten or outdated file, not
one whose dates were edited, and one recent record makes a bundle count as recent
even when the rest is old. An EPSS JSON file without a top-level `score_date`, or a
KEV catalog without `dateReleased`, counts as undated.

### `attest`

Sign the exact bytes of SUBJECT for one purpose; an explicit operator step.

```text
nexus-symbiote attest [OPTIONS] SUBJECT
```

| Option | Description |
|---|---|
| `--key` `FILE` | Ed25519 private key PEM that you own and that gives group and others no permission; repeat for each signer. (required, repeatable) |
| `--purpose` `generated\|reviewed` | generated: you produced SUBJECT; reviewed: you reviewed SUBJECT as a baseline. (required) |
| `--out` `PATH` | Envelope file to create with mode 0600; must not exist. (required) |
| `--passphrase-file` `PATH` | Passphrase for encrypted private keys, on the first line of this file, which you own and which gives group and others no permission. |
| `--source-revision` `TEXT` | Git commit ID SUBJECT was produced from, 40 or 64 lowercase hexadecimal characters; recorded as your claim and never checked. |

SUBJECT is read once, as a regular file reached without symbolic links, at most
64 MiB. The attestation is a DSSE envelope over an in-toto statement that binds the
SHA-256 of those bytes, the purpose, the signing time in whole seconds and, for a native
inventory this build reads, its format version and content digest. The command prints
one JSON line with `out`, `subject_sha256`, `subject_format`, `content_digest` (native
inventories only), `purpose`, `signers` (key IDs) and `signed`. Each `--key` must be a
different key, and an `--out` that names SUBJECT is a usage error. The attestation
records who signed and why; it does not establish that the file is accurate, complete
or safe. See [inventory attestation](inventory-attestation.md).

### `baseline`

Stage a static snapshot for review; publish it only after the scan gate passes.

```text
nexus-symbiote baseline [OPTIONS] [PROJECT_PATH]
```

| Option | Description |
|---|---|
| `-o`, `--baseline-path` `PATH` | Where to write the unsigned baseline (default: .nexus-symbiote-baseline.json, in the working directory, not the project). |
| `--no-project-policy` | Use built-in policy without reading configuration from the target, as scan does. |
| `--accept-project-policy` | In CI, accept a project policy that weakens the built-in gates explicitly; without it such a policy fails the command there (exit 1). Interactive runs only warn. |
| `--signature-policy` `FILE` | Explicit operator signer policy JSON, kept outside the project, as for scan; also verifies any merged ShadowScan discovery report. |
| `--fail-on-unsigned-discovery` | Exit with status 1 when the snapshot merges unverified ShadowScan discovery evidence. |
| `--allow-unsigned-discovery` | Accept unverified ShadowScan discovery evidence explicitly (still warns); required in CI when no `--signature-policy` verifies the report. |

The snapshot must also pass the built-in gate: a project policy cannot relax it.
When it does not, `baseline` prints each reason and the findings that tripped the gate.

### `blast-radius`

Show repository dependencies potentially affected by a component compromise.

```text
nexus-symbiote blast-radius [OPTIONS] AIBOM_PATH COMPONENT_REF
```

| Option | Description |
|---|---|
| `--json-output` | Output as JSON |

### `crosswalk`

Map findings to OWASP, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO/IEC 42001 and CWE.

```text
nexus-symbiote crosswalk [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--framework` `NAME` | Report only this framework edition: `owasp-llm-2025`, `owasp-llm-2026`, `owasp-asi-2026`, `mitre-atlas-2026.10`, `nist-ai-rmf-1.0`, `eu-ai-act-2024`, `iso-iec-42001-2023` or `cwe`. Repeatable; default: every edition. |
| `--format` `json\|markdown` | Report format (default: `json`). |
| `-o`, `--output` `PATH` | Write the report to this file instead of standard output. A path that names the inventory is a usage error. |

The findings are those that `risk` scores under the built-in policy; no project policy
is read. For each framework edition the report lists every entry that a finding
references, with those findings, and the categories whose findings reference none. A
reference means that a finding records a precondition, a weakness or evidence relevant
to an entry, never that an attack happened, that a control fails or that an obligation
applies. It is a report, not a gate: it exits 0 whatever the findings are, and 1 only
when the inventory cannot be read or the report cannot be written. In Markdown, every
ASCII punctuation character of inventory text is backslash-escaped, so a terminal shows
the backslashes.
[Framework crosswalk](framework-crosswalk.md) describes the report and the catalog.

### `diff`

Compare two AIBOM snapshots for supply-chain drift.

```text
nexus-symbiote diff [OPTIONS] OLD_PATH NEW_PATH
```

| Option | Description |
|---|---|
| `--json-output` | Output as JSON |
| `--report-format` `text\|json\|markdown\|junit` | Gate report format (cannot disagree with `--json-output`; default: `text`). |
| `--step-summary` `PATH` | Append a sanitized Markdown gate summary to this file (for example, `GITHUB_STEP_SUMMARY`). |
| `--expect-upgrade` `FROM_VERSION` | Attribute documented profile/schema transitions from `FROM_VERSION` (`0.1.0` or `0.2.0`) into `tool_upgrade_changes` when `metadata.tool_version` matches; configuration/hash drift still alerts. |
| `--fail-on-alert` / `--no-fail-on-alert` | Exit with status 1 if the diff reports a security alert (default: fail). |
| `--detailed-exit-codes` | Use distinct exit codes (`0` passed, `2` usage, `3` gate failed, `4` input/internal failure). |
| `--legacy-exit-codes` | Use legacy exit codes (`0` passed, `1` gate/input failed, `2` usage). |

The report lists security alerts, notes (`[INFO]` metadata changes, and `[NOTE]` lines
about the comparison itself, also after `No changes detected.`), and added, removed and
modified components, and added and removed relationships, each with its severity and
conditions.

### `diff-instructions`

Compare instruction files between `BASE_TREE` and `HEAD_TREE` across the same instruction, rule, prompt, steering, subagent, and skill declaration surfaces (plus recursive `@path` imports) that the `prompt` collector scans, through confined descriptor-relative reads, and report security-relevant CommonMark and front-matter changes (`tool_grant_changed`, `import_added`, `url_or_path_added`, `hidden_markup_added`, `scope_widened`).

```text
nexus-symbiote diff-instructions [OPTIONS] BASE_TREE HEAD_TREE
```

| Option | Description |
|---|---|
| `--show-text` | Include redacted, terminal-neutralized changed block text (withheld by default). |
| `--json-output` | Print the instruction diff as JSON. |
| `--fail-on-change` | Exit with status 1 if any security-relevant instruction change or new excluded agent-directory gap is detected. |

Escaped, broken, credential-targeted, oversized, invalid UTF-8, or case-variant instruction surfaces, and malformed YAML front matter, are recorded under `failures` and exit 1 (fail closed) rather than silently reporting 0 changes; in-root symlinks to non-credential targets are read through their confined target and diffed. Changed text under `--show-text` masks multi-line PEM private keys and secrets across the whole block before terminal neutralization. A report shows at most 1 MiB of changed text; past that, each further change carries `[text withheld: --show-text output limit reached]` in place of its text. An instruction file that is in `BASE_TREE` only is reported as `tool_grant_changed` when it held tool grants or limits, and a rule that drops its `paths` front matter, or a negated glob, as `scope_widened`. A tool grant's argument, such as `Bash(...)` or `mcp__github__merge(...)`, runs to its balanced closing parenthesis, so a nested `$(...)` does not end it, or to the end of the line when it is not closed. An argument or MCP tool name longer than 512 characters is compared as the SHA-256 digest of its text, so any change to it is `tool_grant_changed` and it is never shown. The command judges no prose and does not recognize scheme-less hosts or UNC paths; see [its limits](known-limitations.md#instructions-and-ide-settings).

### `digest`

Print the file, canonical and content digests of a native inventory.

```text
nexus-symbiote digest [OPTIONS] INVENTORY_PATH
```

| Option | Description |
|---|---|
| `--json-output` | Print the digests as one JSON object. |

`digest` reads the file once, as every command reads an AgentBOM, checks that it is a
native inventory this build reads, and prints one line per value:

- `file_sha256`: the SHA-256 of the file's exact bytes;
- `canonical_digest`: the SHA-256 of the RFC 8785 form of the parsed document, the
  digest a signed runtime snapshot binds (`runtime digest --kind bom` prints the same);
- `content_digest` and `content_profile`: the digest of the document without the
  fields that record the collection event (its serial number, collection times and
  the location an imported report was read from), under the profile `nexus-symbiote/inventory-content/v1`;
- `spec_version` and `components`: the native format version as read and the number
  of components.

Two inventories of the same content have the same content digest, wherever and
whenever each was collected; equal digests say nothing about who produced either file.
A file that is not a valid native inventory prints nothing and exits 1 with the same
reasons as other commands. A valid one can lack a digest. The content digest needs a
components list; a document without a metadata object has the content digest of the
same document with an empty one. For the canonical digest, a runtime snapshot
binds a document only when its compact JSON, with every character outside ASCII
escaped and each number counted as 24 bytes, is at most 16 MiB, it holds at most
1,000,000 values and no value is nested more than 64 levels deep; a file well under
16 MiB with much text outside ASCII, or many numbers, can exceed that. `digest` then
prints `unavailable` for the missing digest (`null` with `--json-output`) and every
other value as usual, names the reason and exits 1. See
[reproducible inventories](reproducible-inventories.md).

### `discover-mcp`

Live: observe tools/list without executing tools or starting local servers.

```text
nexus-symbiote discover-mcp [OPTIONS] ENDPOINT
```

| Option | Description |
|---|---|
| `--allowed-origin` `TEXT` | Exact HTTPS origin explicitly approved by the operator (required, repeatable) |
| `--token-env` `TEXT` | Environment variable holding a bearer token; the token is never written to evidence |
| `-o`, `--output` `PATH` | Write the observation to this file instead of standard output. |
| `--record` | Write a native AgentBOM inventory of a complete observation, for `diff`, instead of the observation report; an incomplete observation writes nothing. |
| `--server-ref` `TEXT` | Component reference of the observed server in the inventory (default: derived from the endpoint). |
| `--client-name` `TEXT` | `clientInfo` name sent in `initialize` (default: `nexus-symbiote-discovery`); use your production host's so the server cannot single out the observer. |
| `--client-version` `TEXT` | `clientInfo` version sent in `initialize` (default: the tool version). |
| `--user-agent` `TEXT` | `User-Agent` header to send; none is sent by default. |
| `--raw-descriptors` `PATH` | Also write the unredacted server info, capabilities, instructions, tool descriptors, prompts and resource templates to this new file (mode 0600) for review; only the bearer token is masked, and a server whose declarations repeat its own session ID (of eight or more characters) ends the observation. |

### `evidence-profile`

Report concrete evidence attributes per component without a scalar TrustScore (`signed_under_policy` is `true` only when `--project` and `--signature-policy` corroborate the artifact; inventory `signing_status` assertions appear separately under `declared_signing_status`).

```text
nexus-symbiote evidence-profile [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the evidence profile report to this file instead of standard output. |
| `--project` `DIRECTORY` | Project root for corroborating artifact signatures and digest pins under `--signature-policy`. |
| `--signature-policy` `FILE` | Explicit operator signer policy JSON outside the project; requires `--project`. |
| `--json-output` | Emit the per-component evidence profile as JSON. |

### `export-inventory`

Offline: write the reviewed repository agent as a ShadowScan approved inventory.

```text
nexus-symbiote export-inventory [OPTIONS] INVENTORY
```

| Option | Description |
|---|---|
| `--format` `shadowscan-simple` | ShadowScan's simple inventory list as JSON (required; the only format). |
| `-o`, `--output` `PATH` | Write the approved inventory to this file, which must end in `.json` (required). |
| `--resource-prefix` `PREFIX` | The exact resource ShadowScan reports for the repository's root project (required): `github:OWNER/REPO`, `gitlab:NAMESPACE/PROJECT`, the label of a `code.filesystem` connector with a single `path` (`LABEL/root-id-ID` with labelled `paths`), or the absolute scan root when it has no label; see [Choose the resource prefix](shadowscan-inventory-export.md#choose-the-resource-prefix). |
| `--include-unnamed` | Also export a repository agent whose `agent.yaml` declares no `id`, under an id derived from the inventory content digest. |
| `--force` | Replace an existing output file. Without it an existing approved inventory, which may be reviewed and attested, is left as it is and the command exits 1. |

The file holds one entry, the repository agent, bound to `PREFIX` as a literal
pattern and limited to ShadowScan's `project` observation on the `code` surface;
it carries no autonomy level and binds no component. Standard error names the
inventory's file SHA-256 and content digest. The command exits 1 when the
inventory is invalid, holds no repository agent or more than one, or its agent
has no declared identity and `--include-unnamed` is absent; see
[Approve agents for ShadowScan reconciliation](shadowscan-inventory-export.md).

### `graph`

Write a view of an inventory's associations, risk classes and exposure paths.

```text
nexus-symbiote graph [OPTIONS] INVENTORY
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the view to this file; required for HTML. JSON goes to standard output without it. |
| `--format` `html\|json` | A self-contained HTML page (default), or the view as a JSON document. |
| `--focus` `REF` | Show only this component's potential blast radius: it, what depends on it, and what it and the components of type `agent` among those reach. |
| `--max-nodes` `INTEGER RANGE` | Fail rather than show more components than this (default: 2000, at most 20000). |

Exposure paths are the shortest recorded paths from agents and IDE agents to
components with a `code-exec`, `exfil-capable`, `write-capable` or `secret-access`
risk class or a high or critical finding: at most 200 agents and IDE agents are
searched, those whose best path ranks highest, and the 200 best paths kept, and the view
reports how many were left out. Edges are static repository
associations; runtime use and effective authority are not observed. The HTML file
loads nothing from outside, pins its one style block and one script with a
Content-Security-Policy hash, and shows inventory text only escaped. A graph larger
than `--max-nodes` fails with exit status 1 instead of being cut. The output may not
be the inventory itself. [Graph view](graph-view.md) gives the risk-class rules, the
ranking and the JSON document.

### `import-sbom`

Import a foreign CycloneDX or SPDX SBOM as DECLARED evidence without picking silent winners. By default component names are hashed (`imported-<16hex>`): keyed HMAC-SHA256 (`hmac-sha256`) when `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` has at least 32 characters, or unsalted SHA-256 (`unsalted-sha256`) otherwise. Local digest matching (`declared_digest_local_match`) checks only non-empty, non-symlink, non-credential artifact files of matching type beneath `--project` and never sets `digest_bound`. The project is always walked, but files are hashed only when the SBOM declares a SHA-256, within the `model-bytes` and `model-total-bytes` limits; a file larger than `model-bytes` is left unbound, warned about and listed in `scan_failures`, while any other limit reached under `--project` ends the import with exit 1. Conflicts are found by purl, and by name within one ecosystem; an entry whose ecosystem is unknown (no purl) is compared with every record of the same name.

```text
nexus-symbiote import-sbom [OPTIONS] FOREIGN_BOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the resulting native AgentBOM JSON to this file (must lie outside `--project`). |
| `--into` `PATH` | Existing native AgentBOM to merge imported SBOM claims into. |
| `--project` `PATH` | Trusted project root for SHA-256 local file binding, nested manifests, and shape census. |
| `--reveal-names` | Retain plain component names from the foreign SBOM instead of hashed names. |
| `--walk-manifests` | Walk nested manifests below `--project` and record manifest-only vs locked pinning state. |
| `--census` | Count unread non-control-plane artifact shapes (`*.ipynb`, `n8n/*.json`, `*.tf`, `Chart.yaml`). |
| `--json-output` | Print a structured JSON summary of imported, bound, and conflicting entries. |

### `import-shadowscan`

Import a Nexus-ShadowScan report and generate an AIBOM of imported claims.

```text
nexus-symbiote import-shadowscan [OPTIONS] REPORT_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Output AIBOM path (required) |
| `-f`, `--format` `json\|cyclonedx\|spdx\|sarif` | Output format (default: json). sarif is refused: it cannot carry imported coverage. |
| `--report-only` | Emit imported claims without failing on incomplete coverage. Unverified discovery evidence still fails in CI unless `--allow-unsigned-discovery` is given. |
| `--bundle` `FILE` | Verify the report producer's Sigstore bundle over the exact report bytes; requires `--signer-identity` and `--issuer`, and records the evidence as verified in the BOM |
| `--signer-identity` `TEXT` | Expected report signer, with `--bundle` and `--issuer` |
| `--issuer` `TEXT` | Expected OIDC issuer, with `--bundle` and `--signer-identity` |
| `--fail-on-unsigned-discovery` | Exit with status 1 when the imported discovery evidence is unverified |
| `--allow-unsigned-discovery` | Accept unverified discovery evidence explicitly (still warns); required in CI |

### `init`

Initialize a .nexus-symbiote.yaml policy configuration.

```text
nexus-symbiote init [OPTIONS]
```

| Option | Description |
|---|---|
| `--force` | Overwrite the existing project policy file (`.nexus-symbiote.yaml`, or `.nexus-symbiote.yml` when that is the only one); refused when both exist |
| `--path` `PATH` | Directory to create the project policy file in |

### `minimum-elements`

Report which G7 AI SBOM minimum elements an inventory's CycloneDX export carries.

```text
nexus-symbiote minimum-elements [OPTIONS] INVENTORY
```

| Option | Description |
|---|---|
| `-f`, `--format` `text\|json\|markdown` | Report format (default: text). |
| `-o`, `--output` `PATH` | Write the report to this file instead of standard output; refused when it names the inventory. |
| `--fail-under` `PERCENT` | Exit with status 1, listing the missing elements, when fewer than `PERCENT` (a decimal number from 0 to 100) of the elements assessable from the BOM are present. Off by default: coverage is not compliance. |

The command generates the inventory's CycloneDX 1.7 export in memory and reports, per
element of the G7 "Software Bill of Materials for AI – Minimum Elements" (12 May 2026),
whether a standard field carries it, on which basis, and how to supply a missing one.
The G7 elements are non-binding, and a present element is recorded, not verified. See
[G7 AI SBOM minimum elements](minimum-elements.md).

### `risk`

Score supply-chain risks in an AIBOM.

```text
nexus-symbiote risk [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--threshold` `FLOAT` | Fail when the aggregate score reaches this positive value (default: from policy, built-in 50). |
| `--no-score-threshold` | Do not gate on the aggregate score. Findings at or above `--fail-on-severity`, unverified SafeTensors, incomplete coverage and missing evidence still fail the gate. Cannot be combined with `--threshold`. |
| `--json-output` | Output as JSON |
| `--project` `DIRECTORY` | Reconcile the supplied BOM against this project's static evidence before scoring; a failed reconciliation reports an unknown risk level and a null score. The only source of a project policy: without it the built-in policy applies |
| `--signature-policy` `FILE` | Explicit operator signer policy for model recollection; requires --project |
| `--fail-on-severity` `critical\|high\|medium\|low\|info\|none` | Fail on any finding at or above this severity (default: from policy, built-in critical); none disables it. |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |
| `--accept-project-policy` | In CI, accept a project policy that weakens the built-in gates explicitly; without it such a policy fails the command there (exit 1). Interactive runs only warn. |
| `--require-discovery-signature` | Require the operator signature policy to verify any ShadowScan report the inventory records or the project contains, whatever the project policy says; requires --project. JSON output reports the result as `discovery_producer` |
| `--fail-on-unsigned-discovery` | Exit with status 1 when the BOM's ShadowScan evidence is unverified |
| `--allow-unsigned-discovery` | Accept unverified discovery evidence explicitly (still warns); required in CI |
| `--report-format` `text\|json\|markdown\|junit` | Gate report format (cannot disagree with `--json-output`; default: `text`). |
| `--step-summary` `PATH` | Append a sanitized Markdown gate summary to this file. |
| `--operator-policy` `FILE` | Signed operator policy YAML outside the scanned checkout; checkout policy may only narrow it. |
| `--operator-policy-attestation` `FILE` | DSSE attestation envelope (`purpose: policy`) over `--operator-policy`. |
| `--operator-policy-key` `FILE` | Trusted Ed25519 public key for `--operator-policy-attestation` (repeatable). |
| `--allow-unsigned-operator-policy` | Accept `--operator-policy` without a verified DSSE signature envelope. |
| `--operator-policy-max-age-days` `INT` | Maximum attestation age in days when `--operator-policy-attestation` is verified (default: `90`; `0` disables). |
| `--require-attestation` `ENVELOPE` | Require a verified DSSE inventory attestation envelope for `AIBOM_PATH`; requires at least one `--trusted-key`. |
| `--trusted-key` `FILE` | Trusted Ed25519 public key PEM for `--require-attestation`; must lie outside every git working tree holding `AIBOM_PATH`, the envelope, `--project` or the current directory (repeatable). |
| `--attestation-purpose` `generated\|reviewed` | Purpose the attestation must have been signed for (default: `reviewed`). |
| `--attestation-threshold` `INTEGER RANGE` | Minimum number of distinct trusted keys that must have signed, 1 to 32 (default: `1`). |
| `--attestation-match` `bytes\|content` | `bytes` (default): `AIBOM_PATH` is the attested file; `content`: same inventory content digest. |
| `--attestation-max-age-days` `INTEGER RANGE` | Refuse an attestation signed more than this many days ago (1 to 36500). |
| `--detailed-exit-codes` | Use distinct exit codes (`0` passed, `2` usage, `3` gate failed, `4` collection/input failure). |
| `--legacy-exit-codes` | Use legacy exit codes (`0` passed, `1` gate/input failed, `2` usage). |

The report gives the score, the assessment basis, coverage, the severity counts and
the top 15 findings, each followed by its `fingerprint:` line (`--json-output` lists all). Under `Gate: PASSED` or
`Gate: FAILED` it lists, one `  - ` line each, every reason, such as
`finding at or above critical` or `collection coverage is unknown or incomplete`, the
findings that tripped the severity cutoff, the score with the threshold it was compared
with, the first 20 distinct collection failures the inventory records (a failure
several collectors recorded, such as a symbolic link leaving the root, is one line
ending in `(recorded N times)`, and the line after the twentieth says how many more
distinct failures `metadata.completeness.scan_failures` holds; see
[known limitations](known-limitations.md#every-collector) for what the grouping cannot
say), its other coverage gaps, among them
one line per state naming the collectors that are not complete, and how many
findings the project policy suppressed, and each suppression that no longer matches
its changed finding. When unsigned ShadowScan evidence was accepted,
the report says `Discovery producer: not verified (unsigned evidence accepted)`.

### `runtime keygen`

Create an Ed25519 key pair without overwriting existing files.

```text
nexus-symbiote runtime keygen [OPTIONS]
```

| Option | Description |
|---|---|
| `--private-key` `PATH` | New PEM private key file, created with mode 0600; must not exist. (required) |
| `--public-key` `PATH` | New PEM public key file, created with mode 0600; must not exist. (required) |
| `--passphrase-file` `PATH` | Encrypt the private key with the passphrase on the first line of this file, which you own and which gives group and others no permission. |

Use one key pair per purpose: snapshot, approval and trust rings must not share keys.
A passphrase is at most 1,023 bytes, and a passphrase file that you do not own, or
that gives its group or others any permission, is refused. If either file cannot be written,
neither key is kept.

### `runtime sign`

Sign an explicit contract; signatures do not establish unmeasured facts.

```text
nexus-symbiote runtime sign [OPTIONS] CONTRACT_PATH
```

| Option | Description |
|---|---|
| `--kind` `snapshot\|approval\|trust\|model` | Contract purpose; a signature is valid only for this purpose. (required) |
| `--key` `PATH` | Ed25519 private key PEM that you own and only you can access; repeat for multiple signers. (required, repeatable) |
| `--out` `PATH` | Signed envelope file to create; must not exist. (required) |
| `--passphrase-file` `PATH` | Passphrase for encrypted private keys, on the first line of this file, which you own and which gives group and others no permission. |

A contract that could never verify, because its validity window is longer than its
purpose allows or has already ended, is refused. The output includes the contract
`digest` that approvals and revocation lists use. A key or passphrase file owned by
another user is refused even when the command runs as root, such as a key mounted
into a container from the host.

### `runtime verify`

Verify purpose, signer, subject and time; invocation uses ReferenceGateway.

```text
nexus-symbiote runtime verify [OPTIONS] ENVELOPE_PATH
```

| Option | Description |
|---|---|
| `--kind` `snapshot\|approval\|trust\|model` | Expected contract purpose; a contract signed for another purpose is rejected. (required) |
| `--public-key` `PATH` | Trusted Ed25519 public key PEM; repeat to build the trusted key ring. It must lie outside every git working tree that holds ENVELOPE_PATH, the --bom file or the current directory, which catches misplacement but does not authenticate the key. (required, repeatable) |
| `--threshold` `INTEGER RANGE` | Minimum number of distinct trusted signatures (default: 1). |
| `--bom` `PATH` | The exact companion BOM; required for snapshot contracts. |

Revocation, signer scopes, approver identities and an approval's bindings are
checked only by the gateway. A failure names its reason code, listed in the
[runtime contract reference](runtime-contract-reference.md#reason-codes). A
`--public-key` file kept where the change under review could write it, or with other
hard links, is a usage error (exit 2), as for
[`verify-attestation`](#verify-attestation).

### `runtime digest`

Print the canonical digest that contracts, approvals and revocations bind.

```text
nexus-symbiote runtime digest [OPTIONS] INPUT_PATH
```

| Option | Description |
|---|---|
| `--kind` `snapshot\|approval\|trust\|model\|context\|request\|tool\|bom` | What the file holds: an unsigned contract, an execution context, a tool call, a served tool descriptor or a companion BOM. (required) |

It verifies nothing and works for contracts that are not yet valid or expired.

### `runtime key-id`

Print the key ID that envelopes, key rings and revocation lists use.

```text
nexus-symbiote runtime key-id [OPTIONS] PUBLIC_KEY
```

### `runtime register`

Make a newly issued snapshot current; gateways sharing the store deny older serials.

```text
nexus-symbiote runtime register [OPTIONS] SNAPSHOT_PATH
```

| Option | Description |
|---|---|
| `--trust` `PATH` | Signed, currently valid trust status for the snapshot's tenant. (required) |
| `--state` `PATH` | Initialized state database that the gateways share. (required) |
| `--snapshot-key` `PATH` | Trusted snapshot-signing public key PEM; repeat to build the ring. (required, repeatable) |
| `--trust-key` `PATH` | Trusted trust-status public key PEM; repeat to build the ring. (required, repeatable) |
| `--approval-key` `PATH` | Approval public key PEM the gateways trust; repeat for each. Only checked, so the gateways' signer scope map can be passed unchanged. (repeatable) |
| `--snapshot-threshold` `INTEGER RANGE` | Minimum number of distinct snapshot signers (default: 1). |
| `--trust-threshold` `INTEGER RANGE` | Minimum number of distinct trust-status signers (default: 1). |
| `--signer-scopes` `PATH` | JSON object mapping key IDs to the signer scopes the gateways use. |
| `--allow-shared-keys` | Accept a key in more than one ring, as gateways built with `allow_shared_keys=True` do. |

The snapshot and trust status are checked as the gateway checks them, except the
workload context and the companion BOM, so pass the rings, quorums, signer scopes
and shared-key setting the gateways use. Pass the approval keys too when the scope
map covers them. A scope entry for a key in no ring, or a key in two rings without
`--allow-shared-keys`, fails with `configuration-invalid` and names the key ID. The
output names the tenant, deployment, agent, serial and contract `digest` that
became current. A `--snapshot-key`, `--trust-key` or `--approval-key` file inside a
git working tree that holds SNAPSHOT_PATH, the `--trust`, `--state` or
`--signer-scopes` file or the current directory, or with other hard links, is a usage
error (exit 2): a key planted there could register a snapshot or trust status at the
highest serial and lock the tenant out of every gateway sharing the store.

### `scan`

Scan a project and generate an AIBOM.

```text
nexus-symbiote scan [OPTIONS] [PROJECT_PATH]
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Output file path (default: standard output) |
| `-f`, `--format` `json\|cyclonedx\|spdx\|sarif` | Output format (default: json, or from .nexus-symbiote.yaml) |
| `--scanner` `TEXT` | Collector to run, once each: mcp, model, prompt, rag, registry, a2a, ide_agents, shadowscan (default: all, or from .nexus-symbiote.yaml). A collector left out makes coverage partial. (repeatable) |
| `--report-only` | Emit findings and collection failures without a CI failure. With `--check`, unverified discovery evidence and a failed producer check still exit 1. |
| `--check` | Collect and apply the scan gate without writing an inventory. Cannot be combined with `-o`. |
| `--signature-policy` `PATH` | Explicit operator signer policy JSON |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |
| `--accept-project-policy` | In CI, accept a project policy that weakens the built-in gates explicitly; without it such a policy fails the command there (exit 1). Interactive runs only warn. |
| `--fail-on-unsigned-discovery` | With `--check`, exit with status 1 when ShadowScan discovery evidence is unverified. |
| `--allow-unsigned-discovery` | With `--check`, accept unverified ShadowScan discovery evidence explicitly (still warns); required in CI when no `--signature-policy` verifies the report. |
| `--operator-policy` `FILE` | Signed operator policy YAML outside the scanned checkout; checkout policy may only narrow it. |
| `--operator-policy-attestation` `FILE` | DSSE attestation envelope (`purpose: policy`) over `--operator-policy`. |
| `--operator-policy-key` `FILE` | Trusted Ed25519 public key for `--operator-policy-attestation` (repeatable). |
| `--allow-unsigned-operator-policy` | Accept `--operator-policy` without a verified DSSE signature envelope. |
| `--operator-policy-max-age-days` `INT` | Maximum attestation age in days when `--operator-policy-attestation` is verified (default: `90`; `0` disables). |
| `--detailed-exit-codes` | Use distinct exit codes (`0` passed, `2` usage, `3` gate failed, `4` collection/input failure). |
| `--legacy-exit-codes` | Use legacy exit codes (`0` passed, `1` gate/input failed, `2` usage). |

`PROJECT_PATH` is resolved before collection, because the collectors refuse a root
reached through a symbolic link. When it resolves through a link, `scan` names the
directory it collects; a relative path without `..` that a link leads outside the
working directory is refused, so a checkout cannot redirect `scan ./my-agent` to
another directory on the machine. `validate --project` and `risk --project` follow the
same rule.

`scan` prints each collector with the number of components it found and, unless
complete, its status. It ends with `Scan gate passed` or `Scan gate failed`, followed
by why, one `  - ` line each: every gate reason, the findings at or above the
severity cutoff, the score and threshold, the collectors that were not run, the first
20 collection failures and the first ten excluded surfaces, each with the collector
(or `agent.yaml`, or the `graph` check) that recorded it. The inventory records them
all under `metadata.completeness` (`scan_failures`, `surfaces_excluded`), and the gate
says how many more it holds; `--check` and `baseline` keep no inventory, so their gate
says to run `scan -o FILE` to see the rest. An export that fails its
schema or consistency checks ends the command with an error that names the format;
rerun with `--debug` for details.

`scan` records no collection time unless `SOURCE_DATE_EPOCH` is set, and then that
instant; the serial number is derived from the content digest either way. Two scans of
the same content therefore write byte-identical native JSON and CycloneDX, and
byte-identical SPDX when the variable is set (without it, SPDX records the export time
as its creation time). An inventory whose content digest cannot be computed is not
written, and `scan` exits 1. SARIF locations are relative to the
working directory when the scanned directory lies below it, and relative to the scanned
directory otherwise, so two SARIF files are identical too when the scanned directory
lies at the same path below the working directory in both scans, or below it in
neither. See [reproducible inventories](reproducible-inventories.md).

### `summary`

Print a summary of an AIBOM.

```text
nexus-symbiote summary [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--json-output` | Print the summary as JSON. |

### `trace-diff`

Compare the runtime use that OpenTelemetry traces report with a native inventory.

```text
nexus-symbiote trace-diff [OPTIONS] INVENTORY TRACE_FILE...
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the evidence document to this file. |
| `--json-output` | Print the evidence document as JSON instead of a summary. |
| `--sarif` `SARIF_PATH` | Also write SARIF 2.1.0 results for undeclared runtime use to this file. |
| `--fail-on` `undeclared\|none` | `undeclared` (default): exit 1 when the traces report a tool, model, agent or MCP endpoint that the inventory does not declare or whose identifier cannot be read, or a span whose operation, MCP method or MCP transport cannot be read, or a span or resource with more than 128 attributes, or when no span carries GenAI or MCP semantics. `none`: report only. |

`INVENTORY` is a native AgentBOM. Each `TRACE_FILE` is an OTLP/JSON trace export the
operator already collected: one `ExportTraceServiceRequest` object, or JSON Lines with
one such object per line, as the OpenTelemetry Collector's `file` exporter writes. The
command runs nothing and contacts nothing. It reads at most 16 trace files (more is a
usage error), each at most 64 MiB, and at most 1,000,000 spans and 100,000 distinct
identifiers in all; a JSON Lines line may hold at most 16 MiB, and traces beyond a bound
are refused. Trace files are opened like inventories: no symbolic link, FIFO, device or
directory. Only identifier attributes are read; message, prompt and tool-call content
attributes are counted, never read, copied or printed. Without
`--json-output` the command prints a summary that lists at most 20 undeclared or
unidentified items and counts the rest; its `--json-output` document writes `[` after
`##` as `\u005b`, like the other JSON documents. An `-o` or `--sarif` path that names the
inventory, a trace file or the other output is a usage error (exit 2).

Exit 0 means that nothing undeclared appeared in these traces, not that the agent is
safe or that the traces are complete. See [trace evidence](trace-evidence.md) for what
is read, the matching rules and the evidence format.

### `validate`

Validate an AIBOM for completeness and integrity.

```text
nexus-symbiote validate [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--project` `DIRECTORY` | Project root for cross-validation. The only source of a project policy: without it the built-in policy applies |
| `--signature-policy` `PATH` | Explicit operator signer policy JSON; requires --project |
| `--no-project-policy` | Use built-in policy without reading configuration from the target. |
| `--accept-project-policy` | In CI, accept a project policy that weakens the built-in gates explicitly; without it such a policy fails the command there (exit 1). Interactive runs only warn. |
| `--skip-integrity` | Check completeness only and report integrity as skipped, for a repository whose models cannot be signed yet. The skip is printed and recorded in `--json-output`. |
| `--json-output` | Print the validation report as JSON. |
| `--require-discovery-signature` | Require the operator signature policy to verify any ShadowScan report the inventory records or the project contains, whatever the project policy says; requires --project |
| `--fail-on-unsigned-discovery` | Exit with status 1 when the BOM's ShadowScan evidence is unverified |
| `--allow-unsigned-discovery` | Accept unverified discovery evidence explicitly (still warns); required in CI |
| `--report-format` `text\|json\|markdown\|junit` | Gate report format (cannot disagree with `--json-output`; default: `text`). |
| `--step-summary` `PATH` | Append a sanitized Markdown gate summary to this file. |
| `--operator-policy` `FILE` | Signed operator policy YAML outside the scanned checkout; checkout policy may only narrow it. |
| `--operator-policy-attestation` `FILE` | DSSE attestation envelope (`purpose: policy`) over `--operator-policy`. |
| `--operator-policy-key` `FILE` | Trusted Ed25519 public key for `--operator-policy-attestation` (repeatable). |
| `--allow-unsigned-operator-policy` | Accept `--operator-policy` without a verified DSSE signature envelope. |
| `--operator-policy-max-age-days` `INT` | Maximum attestation age in days when `--operator-policy-attestation` is verified (default: `90`; `0` disables). |
| `--require-attestation` `ENVELOPE` | Require a verified DSSE inventory attestation envelope for `AIBOM_PATH`; requires at least one `--trusted-key`. |
| `--trusted-key` `FILE` | Trusted Ed25519 public key PEM for `--require-attestation`; must lie outside every git working tree holding `AIBOM_PATH`, the envelope, `--project` or the current directory (repeatable). |
| `--attestation-purpose` `generated\|reviewed` | Purpose the attestation must have been signed for (default: `reviewed`). |
| `--attestation-threshold` `INTEGER RANGE` | Minimum number of distinct trusted keys that must have signed, 1 to 32 (default: `1`). |
| `--attestation-match` `bytes\|content` | `bytes` (default): `AIBOM_PATH` is the attested file; `content`: same inventory content digest. |
| `--attestation-max-age-days` `INTEGER RANGE` | Refuse an attestation signed more than this many days ago (1 to 36500). |
| `--detailed-exit-codes` | Use distinct exit codes (`0` passed, `2` usage, `3` gate failed, `4` collection/input failure). |
| `--legacy-exit-codes` | Use legacy exit codes (`0` passed, `1` gate/input failed, `2` usage). |

Every report states its assessment basis. Without `--project` it is `supplied-bom`:
only the inventory's own claims were checked, its coverage claim and its internal
consistency, and nothing was compared with a project, so a hand-written inventory
can pass. With `--project` the completeness check compares the inventory with a
fresh local collection of that project, and the basis is `project-reconciled`,
`project-reconciled-with-supplier-claims` (the inventory adds claims the collection
cannot confirm; each is listed as a `SUPPLIER-CLAIM` line) or
`project-reconciliation-failed`; `risk --project` uses the same values. When the
project policy sets `validate.require_completeness: false`, `validate --project`
skips that comparison and reports `project-not-reconciled`; `risk --project`
reconciles regardless. The completeness check also prints the completeness validator's own `Basis:`
(`supplied-claims` without `--project`). Integrity is `PASS`, `FAIL` or `UNKNOWN`;
unknown fails the check, and when no issue explains it the report says that no hash
or signature could be verified. When the inventory carries ShadowScan discovery
evidence that no producer check covered, the report says
`Discovery producer: not verified (unsigned evidence accepted)`. The report ends with
`Validation: PASSED` or `Validation: FAILED`.

### `verify-artifact`

Verify a local artifact's digest and optionally its Sigstore bundle.

```text
nexus-symbiote verify-artifact [OPTIONS] ARTIFACT_PATH
```

| Option | Description |
|---|---|
| `--project` `DIRECTORY` | Trusted project root; ARTIFACT_PATH is relative to it, not to the working directory (required) |
| `--sha256` `TEXT` | Expected sha256:<hex> from a trusted source (required) |
| `--bundle` `FILE` | Optional Sigstore bundle |
| `--signer-identity` `TEXT` | Expected Sigstore signing identity |
| `--issuer` `TEXT` | Expected Sigstore OIDC issuer |
| `--trust-root` `PATH` | Explicit Sigstore trusted_root.json file (or directory holding one); overrides `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` and the user cache; requires `--bundle` |
| `--trust-root-sha256` `TEXT` | Pinned SHA-256 (sha256:\<hex\>) the explicit trust root must match; requires `--bundle` |
| `--oms-dsse` | Verify an OpenSSF Model Signing DSSE in-toto Statement/v1 Sigstore bundle. |
| `--rekor-root-hash` `TEXT` | Operator-witnessed Rekor checkpoint root hash (`sha256:<hex>`) that the bundle inclusion proof must match. |
| `--minimum-rekor-tree-size` `INT` | Minimum Rekor transparency log tree size required in the bundle checkpoint. |

A malformed `--sha256`, or a `--bundle`, `--signer-identity` and `--issuer` set that
is incomplete, is a usage error (exit 2).

### `verify-attestation`

Verify that trusted keys attested SUBJECT for a purpose; exit 1 when they did not.

```text
nexus-symbiote verify-attestation [OPTIONS] SUBJECT ENVELOPE
```

| Option | Description |
|---|---|
| `--trusted-key` `FILE` | Trusted Ed25519 public key PEM; repeat to build the ring. It must lie outside every git working tree that holds SUBJECT, ENVELOPE or the current directory, which catches misplacement but does not authenticate the key. (required, repeatable) |
| `--purpose` `generated\|reviewed` | Purpose the attestation must have been signed for. Any trusted key can sign either purpose, so trust only keys that may sign for this one. (required) |
| `--threshold` `INTEGER RANGE` | Minimum number of distinct trusted keys that must have signed, at most the number of distinct trusted keys (default: 1). |
| `--match` `bytes\|content` | bytes (default): SUBJECT is the attested file. content: SUBJECT is a native inventory with the attested content digest, such as a later collection of the same content. |
| `--max-age-days` `INTEGER RANGE` | Refuse an attestation signed more than this many days ago (1 to 36500). |
| `--json-output` | Print the verified facts as JSON. |

A verified attestation is printed as plain lines, or with `--json-output` as a JSON
object with `attestation_verified`, `purpose`, `signers`, `match`, `subject_sha256` (the
file passed), `attested_sha256` (the file that was signed), `subject_format`,
`signed_at`, and, when recorded, `spec_version`, `content_digest`, `content_profile` and
`source_revision`. A failure prints `attestation verification failed:`, a fixed message
and a reason code from [inventory attestation](inventory-attestation.md#reason-codes),
and exits 1; nothing from SUBJECT, ENVELOPE or a key is printed. A `--trusted-key` file
inside a git working tree that holds SUBJECT, ENVELOPE or the current directory, also
under another name for the tree directory itself, or one with other hard links, is a
usage error, as is a `--threshold` above the number of distinct trusted keys. A mount of
a directory or file inside the tree gives the key a location outside it and is not
detected ([trusted keys](inventory-attestation.md#trusted-keys)). Verification
establishes who signed which bytes or content for which purpose and when, by the
signer's clock; it does not establish that SUBJECT is accurate, complete or safe, or that
it is the newest file the signers attested.

### `verify-discovery`

Verify source bytes and optionally their native projection and producer.

```text
nexus-symbiote verify-discovery [OPTIONS] AIBOM_PATH REPORT_PATH
```

| Option | Description |
|---|---|
| `--projection` | Rebuild and compare the direct native import. |
| `--bundle` `FILE` | Verify the report producer's Sigstore bundle and the direct native projection. |
| `--signer-identity` `TEXT` | Expected report signer from operator policy. |
| `--issuer` `TEXT` | Expected OIDC issuer from operator policy. |
| `--trust-root` `PATH` | Explicit Sigstore trusted_root.json file (or directory holding one); overrides `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` and the user cache; requires `--bundle` |
| `--trust-root-sha256` `TEXT` | Pinned SHA-256 (sha256:\<hex\>) the explicit trust root must match; requires `--bundle` |

### `verify-live`

Live: observe independently pinned stdio launchers; optionally emit an unsigned candidate.

```text
nexus-symbiote verify-live [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `--project` `DIRECTORY` | Untrusted project root (required); the launch policy must be outside it and outside every repository that encloses the project or the inventory. |
| `--launch-policy` `FILE` | Operator-owned JSON outside the project: exact server references to absolute commands and SHA-256 pins; see [launch policy](#launch-policy). (required) |
| `--json-output` | Output the verification report as JSON. |
| `--record` | Print an unsigned candidate BOM with the observed descriptors instead of a report; exits 1 when served tools, declarations or the server identity drifted, unless `--accept-drift`. |
| `--accept-drift` | With `--record`, exit 0 although changed or new tools, declarations or server identity were recorded. |
| `--no-isolation` | Explicitly allow execution without a PID namespace; printed as a warning. On Linux the launcher runs in its own process group under a wrapper that stays its parent as a child subreaper and ignores the signals it can, and cleanup kills the wrapper's whole tree, including a `clone(CLONE_PARENT)` child that has called `setsid` and what a launcher that already exited left behind. A launcher that kills its wrapper with SIGKILL can escape, except from a cgroup v2 child where one can be created, which cleanup also kills; the server then fails with `isolation-teardown-failed`, unless the launcher runs as root or holds `CAP_SYS_PTRACE` or `CAP_SYS_ADMIN`, which can hide the escape. Never opt out as root; doing so prints a second warning. Elsewhere cleanup is best effort. This is not a namespace or sandbox. |

By default the launcher must run as pid 1 of a new user and PID namespace
(`unshare --user --map-root-user --pid --fork --kill-child`). That process first
runs a short exec wrapper (the running interpreter with `-I -S`), which waits until
`verify-live` holds a pidfd for it and only then executes the staged launcher with
the same argument, environment and working directory. The launcher therefore cannot
leave the process group, kill `unshare` through it or exit before cleanup can reach
it. When the session ends, cleanup sends the launcher SIGKILL through that pidfd and
waits until the kernel has ended every process in the namespace, including nested
PID namespaces. It does not rely on `--kill-child`, the process group or `unshare`,
which a launcher can defeat by clearing its parent-death signal, calling `setsid` or
`setpgid`, or killing `unshare` with `kill(0, SIGKILL)` from a child left in that
group. If no namespace init appears within 5 seconds, the server fails with
`isolation-unavailable` before the pinned launcher executes. If the namespace has not
ended 5 seconds after the SIGKILL, it fails with `isolation-teardown-failed`. Without
a separately runnable interpreter, as in a frozen build, or where the kernel cannot
open a pidfd, the launcher runs without a pidfd held, and cleanup stops `unshare` so
that it cannot reap the launcher, kills the launcher it finds as `unshare`'s child
and waits in the same way; there a server whose `unshare` was killed by a signal
before cleanup, or did not stop within 1 second, also fails with
`isolation-teardown-failed`, because the launcher may have outlived it. A process
that the launcher has another service start, such as `systemd-run --user`, is
outside the namespace and is not ended, and nothing ends the namespace if
`verify-live` itself is killed before its cleanup runs.
Inside the namespace the launcher sees itself as uid 0
and gid 0, mapped to the invoking user and group; every other uid and gid, including
the owners of the files it reads and its own supplementary groups, appears as
`nobody`/`nogroup` (65534), and `setgroups` is denied. That grants no privilege
outside the namespace, but a launcher that refuses to run as root, inspects its
supplementary groups or changes file ownership behaves differently than under direct
execution. A host that refuses the namespace fails with `isolation-unavailable`
before executing the pinned launcher. Only the explicit operator option
`--no-isolation` permits a launch without this boundary. On that path, on Linux,
a short wrapper (the running interpreter with `-I -S`) sets
`PR_SET_CHILD_SUBREAPER`, forks, and executes the staged launcher in the child with
the same argument, environment, signal dispositions and working directory. The
wrapper stays alive as the launcher's parent, keeps no copy of its streams, reaps
every child and exits with the launcher's status once none is left, repeating the
signal that killed the launcher as `unshare --fork` does. The launcher
leads its own process group in the session the wrapper leads, and the wrapper ignores
every signal it can and is not dumpable, so the launcher cannot end it with a signal
to its group or its parent, or trace it, unless it holds `CAP_SYS_PTRACE`; only
SIGKILL aimed at the wrapper ends it. Every orphan below the wrapper is reparented to
it, so a `setsid` child that double-forks, a `clone(CLONE_PARENT)` child (whose
parent is the wrapper) and the descendants of a launcher that already exited all stay
in the wrapper's tree. Cleanup stops the wrapper and then every process in its tree, so
none can fork or reap a pid the sweep found, kills the tree in repeated passes,
so a helper that a watchdog restarts is found as the wrapper's child, then kills each
child that is still running, including a chain that forks faster than the tree is
scanned, as it is reparented to the stopped wrapper. It lets the wrapper reap them
and kills the wrapper's process group, the processes in its session and a private
cgroup v2 where the current cgroup allows a child. The wrapper reports that it
exited with no child left; when it does not, because the launcher killed it or a
descendant could not be killed (one running as another user, or one that stays in
uninterruptible sleep), or when the wrapper's children cannot be listed, the server fails with `isolation-teardown-failed`, since what
the wrapper had adopted may still be running, outside that cgroup where none exists.
The report counts only when the kernel credits it to the wrapper's pid. A launcher
running as root, or with `CAP_SYS_PTRACE` or `CAP_SYS_ADMIN`, can forge it or trace
the wrapper, so its escape can go unreported; never opt out as root.
A launcher or descendant can still evade cleanup another way, for example by moving
out of the cgroup. On other systems that cleanup is best effort. The option is not a PID namespace,
and neither form is a filesystem or network sandbox.

Servers whose transport is `sse`, `streamable-http` or `http` and that record no
launch command are reported as not verifiable by `verify-live` (reason
`remote-transport`) and do not make the run incomplete; observe them with
`discover-mcp --record` and compare the inventories with `diff`. Such a server that
records a launch command, which a client may start, fails with reason
`ambiguous-transport` unless the launch policy names it; one that the launch policy
names is observed through its pinned launcher. Any transport label other than these
and `stdio`, such as the `websocket` that the `mcp` collector records for a `ws://` or
`wss://` endpoint, fails with reason `unsupported-transport`. The
[launch policy](#launch-policy) section gives the policy's format and where it may be
kept.

### `trifecta`

Analyze an inventory offline for lethal trifectas, chained toxic flows, and tool shadowing.

```text
nexus-symbiote trifecta [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the trifecta and toxic-flow report JSON to this file instead of standard output. |
| `--fail-on-critical` / `--no-fail-on-critical` | Exit with status 1 when a critical lethal-trifecta finding is present (default: fail). |
| `--fail-on-finding` / `--no-fail-on-finding` | Exit with status 1 when any trifecta, toxic-flow, or tool-shadowing finding is present (default: off). |

### `vex`

Export schema-validated VEX findings with optional operator decisions, advisories, and trace evidence.

```text
nexus-symbiote vex [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-o`, `--output` `PATH` | Write the VEX document to this file instead of standard output. |
| `--decisions` `PATH` | Operator-owned VEX decisions YAML/JSON stored outside the scanned project and enclosing git trees; expired decisions revert to `in_triage` against wall-clock UTC time. |
| `--project-root` `PATH` | Scanned project root used to refuse policy and trace files stored inside the checkout. |
| `--advisories` `PATH` | Link matched advisories from a live or offline `advisories` report JSON bound to this AIBOM's SHA-256 into the VEX document. |
| `--trace-evidence` `PATH` | `trace-diff` or execution-evidence JSON bound to this AIBOM's SHA-256 (`unobserved` and `invoked` stay `in_triage`; critical, KEV, and static-execution findings cannot be suppressed without an expiring operator decision). Requires `--trace-attestation` with `--trusted-key` unless `--allow-unsigned-trace-evidence` is set. |
| `--trace-attestation` `PATH` | Ed25519 DSSE attestation envelope authenticating `--trace-evidence`. |
| `--trusted-key` `PATH` | Trusted Ed25519 public key PEM outside the scanned project (repeatable; used with `--trace-attestation`). |
| `--allow-unsigned-trace-evidence` | Explicitly accept unsigned `--trace-evidence` without `--trace-attestation`. |

### `export-standard`

Export a native AgentBOM to CycloneDX (`1.6` or `1.7`) or SPDX `3.0.1` with typed AI and Dataset projections and optional `agent.yaml` 1.1 producer declarations.

```text
nexus-symbiote export-standard [OPTIONS] AIBOM_PATH
```

| Option | Description |
|---|---|
| `-f`, `--format` `cyclonedx\|spdx` | Target standard export format. (required) |
| `-o`, `--output` `PATH` | Write the exported document to this file instead of standard output. |
| `--cyclonedx-projection` `2\|3` | CycloneDX projection version (`3` default emits typed AI relationships, `services`, `modelCard`, `pedigree` and `licenses`). |
| `--spec-version` `1.6\|1.7` | CycloneDX specification version when `--format cyclonedx` is selected (`1.7` default; `1.6` requires `--cyclonedx-projection 3`). |
| `--spdx-projection` `3\|4` | SPDX 3.0.1 projection version (`4` default emits typed AI/Dataset `RelationshipType` values and conditional profile conformance). |
| `--spdx-namespace` `URI` | Explicit HTTPS namespace base URI for SPDX 3.0.1 element IDs. |
| `--author` `TEXT` | Repeatable operator-supplied author name recorded in CycloneDX `metadata.authors` or SPDX `Person` + `CreationInfo.createdBy` (with `--format spdx`, requires `--spdx-projection 4`). |
| `--agent-yaml` `PATH` | Relative path under `--project` to an `agent.yaml` (`1.0` or `1.1`) producer declaration file; recorded at `declared` assurance (`declaration_conflict` on contradiction). |
| `--project` `DIR` | Trusted project root used to confine `--agent-yaml` declarations (requires `--agent-yaml`). |

`--agent-yaml` and `--project` must be passed together; `--project` alone never reads `agent.yaml` implicitly. Producer declarations (`schema_version`, `owner`, `version`, `automation_level`, `licenses`, `data_usage`, `compliance`, `allowed_regions`, `release_time`, `download_location`, `datasets[]`, and `models[]`) never overwrite observed collector fields (`version`, `supplier`, `autonomy_level`, and a dataset's `source_uri` and `license`); on observed components they are recorded under `declared_*` properties with per-field `declaration.<field>` claims, and a conflicting value raises `declaration_conflict` and is not stored. A `models[].training.datasets` entry adds a `trained-on` edge with `assurance_level: declared`, exported as a typed edge (CycloneDX `dependsOn` and `modelCard` datasets, SPDX `trainedOn`) whose native relationship keeps that assurance. Licences that do not parse as SPDX license expressions (listed licence ids with an optional `+`, `LicenseRef-`, `AND`, `OR`, parentheses, and `WITH` a listed exception id) export as SPDX `NoAssertion` and CycloneDX `license.name`; a licence taken from a declaration carries the comment `declared by producer`. A refused declared `download_location`, and an observed `source_uri` left out of the standard download fields (an unsupported scheme, credentials or a secret), are reported on standard error. Passing `--author` or `--agent-yaml` enriches the embedded native inventory inside the exported document, so the recovered inventory's content digest reflects those additions rather than an attestation signed over the unmodified input `AIBOM_PATH`.

```bash
nexus-symbiote scan examples/demo-agent -f json --report-only -o /tmp/demo-aibom.json
nexus-symbiote export-standard /tmp/demo-aibom.json -f spdx --spdx-projection 4 -o /tmp/demo.spdx.json
```

### `audit-control-plane`

Audit hook command targets outside `.claude/hooks` and `.cursor/hooks`, skill `!` shell preambles, in-project MCP launcher targets, MCP bridge packages (`mcp-remote`, `supergateway`, `mcp-proxy`), writable steering surfaces, CI agent workflow actions, provider-hosted tools, workload identities (SPIFFE, OAuth grants, service identities) and reach-rated diff alerts.

```text
nexus-symbiote audit-control-plane [OPTIONS] [PROJECT_PATH]
```

| Option | Description |
|---|---|
| `--claims` `PATH` | Optional imported CR-3/CR-6/CR-7 ShadowScan JSON claims file. |
| `--baseline` `PATH` | Optional baseline project directory for reach-rated control-plane diff alerts. |
| `--compromised-ref` `TEXT` | Component reference (`tool:exec` or `mcp-server:fs`) to compute reachable identities. |
| `-o`, `--output` `PATH` | Write JSON audit report to a file path. |
| `--json-output` | Emit JSON audit summary to standard output. |
| `--fail-on-severity` `critical\|high\|medium\|low\|none` | Exit 1 when a finding or reach-rated diff alert meets or exceeds this severity, or when an input could not be read or parsed (`critical` by default). Unread inputs are printed as `[INCOMPLETE]` lines; `none` never fails. |

