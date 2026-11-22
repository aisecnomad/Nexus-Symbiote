# Policy reference

A project policy selects collectors and sets the thresholds of the `scan`, `validate` and `risk` gates. It lives in the checkout it governs, so treat it as input from whoever can change that checkout.

- [Where the policy comes from](#where-the-policy-comes-from)
- [File format](#file-format)
- [Settings](#settings)
- [Suppressions](#suppressions)
- [What `policy_weakened` reports](#what-policy_weakened-reports)
- [Where the governing policy is recorded](#where-the-governing-policy-is-recorded)
- [Not supported](#not-supported)
- [Common errors](#common-errors)

## Where the policy comes from

| Command | Checkout policy location | Ignore checkout policy |
| --- | --- | --- |
| `scan PATH` | `PATH/.nexus-symbiote.yaml` or `PATH/.nexus-symbiote.yml` | `--no-project-policy` |
| `validate`, `risk` | The directory supplied with `--project` | `--no-project-policy` |
| `baseline` | The scanned directory for collection. The staged inventory is checked against the built-in risk policy. | `--no-project-policy` |

The CLI applies each checkout setting that tightens the governing policy, including in a mixed file. If a setting weakens a gate or changes the output format, the CLI withholds that change and warns on standard error. After reviewing the file, pass `--accept-project-policy` to apply it. A signed operator policy still bounds the result. Omitted settings inherit the operator's values. Use `--no-project-policy` to skip the checkout file entirely. The GitHub Action selects this mode explicitly. CI environment variables have no effect on these choices.

Only a policy in the named project root governs the command. Without `--project`, `validate` and `risk` can name a nearby file in a warning. A malformed, ambiguous or unreadable checkout policy stops the command, including with `--accept-project-policy`. The default exit status is 1. The `scan`, `validate` and `risk` commands return 4 with `--detailed-exit-codes`. This includes an empty file, an unsupported key and a misspelled setting such as `fail_on_severity: High`. Both policy names, a symlink, an oversized file or a listing that reaches the entry limit also cause an error. Click rejects an unreadable project root with exit status 2. Pass `--no-project-policy` to skip the checkout file. `init` requires a single unambiguous target.

When `risk` or `validate` leaves a policy unused, its JSON contains `policy_unapplied` with a `reason` of `not-accepted`, `relaxations-not-accepted` or `project-not-specified`. A file name is included when the CLI can safely identify it. Explicitly ignoring policy suppresses this field and the warning. An applied relaxation appears in `policy_weakened`. A checkout that requests a stricter assurance level and a higher risk threshold gets the stricter assurance level automatically. The threshold stays at its governing value unless the operator accepts the relaxation.

## File format

`nexus-symbiote init` writes the built-in policy with comments. Loading is strict and fails closed:

- Unknown keys, duplicate keys and values of the wrong type are refused, and the error names the setting, for example `invalid or unsupported settings: risk (warn_threshold cannot exceed fail_threshold)`.
- Booleans must be YAML booleans (`true`, `false`); the string `"false"` is refused.
- `version` must be the string `"1.0"`. An unquoted `1.0` is a number and is refused.
- YAML anchors and aliases are refused, and so is a file with more YAML nodes than the largest policy the settings below allow (every list at its maximum length, 1,000 suppressions); the file is also limited to 1 MiB.

```yaml
version: "1.0"
scan:
  scanners: ["mcp", "model", "prompt", "rag", "registry", "shadowscan", "a2a", "ide_agents"]
  exclude_paths: ["node_modules", ".git", "__pycache__", ".venv"]
  failure_mode: "error"
risk:
  fail_threshold: 50.0
  warn_threshold: 25.0
  fail_on_severity: "critical"
  ignore_categories: []
  suppressions: []
validate:
  require_completeness: true
  require_integrity: true
  minimum_assurance_level: "declared"
  require_discovery_signature: false
output:
  default_format: "json"
```

## Settings

| Key | Default | Effect |
| --- | --- | --- |
| `version` | `"1.0"` | Policy format version. Only `"1.0"` exists. |
| `scan.scanners` | all eight collectors | Collectors `scan` runs. A collector left out is recorded as `unknown`, which leaves coverage partial, so the scan and risk gates fail; a subset is reported as weakened. `--scanner` overrides it for one run. |
| `scan.exclude_paths` | `node_modules`, `.git`, `__pycache__`, `.venv` | Root-relative paths not collected. Directories named `.git`, `node_modules`, `__pycache__`, `.venv` or `venv` are always skipped whatever this list says, so the defaults change nothing; inside a skill, command, rule or subagent directory such a name is a coverage gap. Any other entry that matches a file is recorded under `surfaces_excluded`: coverage becomes partial and the scan, validate and risk gates fail. Extra entries are reported as weakened. Absolute paths and `..` are refused. |
| `scan.failure_mode` | `error` | `report-only` makes `scan` exit 0 whatever its gate says, like `--report-only`, except that `scan --check` still exits 1 on unverified ShadowScan discovery evidence and a failed producer check. Reported as weakened. |
| `risk.fail_threshold` | `50.0` | The risk gate fails when the aggregate score is at or above it. The score is the uncapped sum of finding weights (critical 10, high 7, medium 4, low 1, info 0), not a percentage. Must be positive. A higher value is reported as weakened. `risk --threshold` overrides it. The Action's `risk-threshold` input accepts 0 to 100 and passes that value as `--threshold`, or `--no-score-threshold` when it is 0. |
| `risk.warn_threshold` | `25.0`, or `fail_threshold` when that is lower | At or above it, `risk_level` is `high` instead of `moderate`, `warning_threshold_exceeded` is true and `scan` prints a risk warning. It never fails a gate. It may not exceed `fail_threshold`. A higher value is reported as weakened. |
| `risk.fail_on_severity` | `critical` | The risk gate fails on any finding at or above this severity: `critical`, `high`, `medium`, `low` or `info`. `none` disables the severity check and is reported as weakened. `risk --fail-on-severity` overrides it. The GitHub Action's `fail-on-severity` input defaults to `high` and is passed as that flag, so an Action run does not use this built-in `critical` unless the workflow sets `fail-on-severity: critical`. |
| `risk.ignore_categories` | `[]` | Every finding of these exact category names, on every component, is left out of the score and the gates, and counted as `ignored_findings`. Prefer a [suppression](#suppressions). Reported as weakened. |
| `risk.suppressions` | `[]` | Accept one reviewed finding on one component; see [Suppressions](#suppressions). Each entry is reported as weakened. |
| `validate.require_completeness` | `true` | `false` skips the completeness check, including reconciliation with `--project`, in `validate`. `risk --project` reconciles regardless. Reported as weakened. |
| `validate.require_integrity` | `true` | `false` skips the integrity check in `validate`. Reported as weakened. |
| `validate.minimum_assurance_level` | `declared` | `observed` makes `validate` fail unless every component is observed composition: its identity was measured from bytes (a weight, instruction, skill or static tool-descriptor digest), or a named collector observed it in the repository. Components that rest only on a supplier's or a discovery report's declaration, such as hosted-model aliases from `agent.yaml`, fail it; imported discovery claims that reconciliation bound to the local report are exempt. Under `--project`, an observed claim or assurance level only the supplier added to a component the local collection did not observe does not count. `verified` always fails, because offline validation cannot establish it. |
| `validate.require_discovery_signature` | `false` | With `--project`, `validate` and `risk` require the operator signature policy (`--signature-policy`) to verify the ShadowScan report the inventory records, and fail when an inventory omits a report the project contains. Without `--project`, an inventory that carries ShadowScan evidence fails, even with `--allow-unsigned-discovery`, because no report can be verified. Ignored, like the rest of the file, under `--no-project-policy`; pass `--require-discovery-signature` to require it from the command line instead. |
| `output.default_format` | `json` | Output format of `scan` when `--format` is not given: `json`, `cyclonedx`, `spdx` or `sarif`. |

### Category names

`ignore_categories` and suppressions match category names exactly. Read them from the `category` field of `risk --json-output` findings; the [finding catalog](finding-catalog.md) explains each one. This version emits:

`additional_directories`, `attestation`, `authentication`, `auto_approval`, `bidi_override`, `capability_scope`, `code_execution`, `completeness`, `credential_exposure`, `credential_helper`, `custom_code`, `data_integrity`, `detection_method`, `directional_marks`, `endpoint_identity`, `hidden_markup`, `hook_commands`, `instruction_layering`, `invalid_safetensors`, `invisible_characters`, `launch_context`, `launcher_identity`, `local_process`, `lockfile_resolution_mismatch`, `lockfile_unread`, `mcp_auto_approval`, `missing_lockfile_integrity`, `mutable_image_tag`, `nonregistry_source`, `oversight_gap`, `package_alias`, `package_source`, `permission_scope`, `plugin_sources`, `prompt_size`, `rag_discovery`, `registry_origin`, `serialization_format`, `serialization_format_unknown`, `settings_environment`, `shadowscan-heuristic`, `shadowscan-inventory-unmatched`, `signing_status`, `subagent_inline_mcp_server`, `tag_characters`, `transport_ambiguity`, `transport_security` and `version_pinning`. The note that an MCP server runs as a local process is `local_process`; `transport_security` is an insecure or credential-bearing endpoint.

A name that matches no finding is accepted and has no effect.

## Suppressions

A suppression accepts one known false positive without switching off a whole category or gate. It names the finding as it was reviewed, by its fingerprint, so it stops applying when the finding, or the content it was found in, changes:

```yaml
risk:
  suppressions:
    - component_ref: "model:fixtures/firmware.bin"
      category: "serialization_format_unknown"
      fingerprint: "sha256:<the 64 hex digits risk printed for the finding>"
      reason: "Test fixture, never loaded by the agent"
      owner: "security@example.com"
      expires: 2027-01-31
```

| Field | Rule |
| --- | --- |
| `component_ref` | The finding's exact `component_ref`, as `risk --json-output` prints it. No wildcards: `*` is refused. |
| `category` | The finding's exact category. |
| `fingerprint` | The finding's `fingerprint`, as `risk --json-output` prints it, or as human-readable `risk` prints it under each top finding: `sha256:` and 64 lowercase hex digits. Required. |
| `reason` | Why the finding is acceptable. Required. |
| `owner` | Who is accountable for the acceptance. Required. |
| `expires` | A calendar date, `YYYY-MM-DD`, quoted or not. Required: there are no permanent suppressions. |

The fingerprint is a SHA-256 digest of the ASCII JSON, with sorted keys and no whitespace, of an object with the keys `component_ref`, `category`, `severity` and `detail`, which hold the finding's values, and `content`, which holds the component's content digest, or null when the inventory records none. The content digest is a prompt's or dataset's `content_hash`, a tool's `definition_hash`, an MCP server's `schema_hash`, or otherwise the `sha256` entry of its `hashes`, such as a model weight or skill file. For a prompt file whose bytes are not those of an instruction file, such as an `@path` import that is not a Markdown file, whose `content_hash` the collector withholds (`content_hash_withheld`), it is the keyed `static_value_binding` that `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` adds, so a suppression on such a file stops applying when its content, or the binding key, changes. Collectors report each category once per component and put the count, not the content, in the detail, so the content digest is what ties the entry to the bytes that were reviewed: a prompt with one bidirectional override and the same prompt with 31 have different fingerprints, and so does a prompt whose single override now sits in a different instruction. Any change to those bytes, even one unrelated to the finding, retires the entry, and so does the same detail at a new severity. A component without a content digest, such as one whose finding comes from configuration, is bound by its detail alone, except a withheld import collected without the key: nothing records its content, so no suppression applies to its findings: an entry naming it is reported stale while the file still has a finding in that category, and unused otherwise. The same holds for any other prompt file whose `content_hash` the collector withholds, such as `AGENTS.md` linked to a JSON file or `.cursor/rules/x.json`. Each finding may be suppressed once; a component and category with several findings needs one entry per finding. A malformed entry makes the policy invalid, so every command fails and names the setting.

How a suppression applies:

- A finding whose component reference, category and fingerprint all match an entry that has not expired is left out of the score, the severity counts and every gate, including `fail_on_severity`. It is listed under `suppressed_findings` in `risk --json-output` with its severity, fingerprint, reason, owner and expiry, and human-readable `risk` prints how many findings were suppressed.
- The same category on any other component still counts.
- An entry expires at the end of its `expires` date (UTC). An expired entry suppresses nothing and fails the risk gate with the reason `suppression of CATEGORY on REF expired on DATE` until it is renewed or removed; it is listed under `suppressions_expired`.
- An entry whose component and category still have a finding, but none with its fingerprint, suppresses nothing: the finding, or the content it was found in, changed after it was reviewed, and it counts again. The entry is listed under `suppressions_stale` with the `current_fingerprints` of those findings, and human-readable `risk` prints `suppression no longer matches: CATEGORY on REF`. Review the finding again before you copy its new fingerprint. An entry naming a prompt file whose `content_hash` is withheld, such as an `@path` import that is not Markdown, collected without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` never suppresses anything, whatever fingerprint it names: it is reported stale while the file still has a finding in that category, and unused otherwise. Collect with the key to suppress one of its findings.
- An entry that matched no finding is listed under `suppressions_unused`.
- `--no-project-policy` ignores all suppressions, and `baseline` re-gates with the built-in policy, so a suppression cannot promote a baseline.

## What `policy_weakened` reports

`policy_weakened` lists every setting that gates less strictly than the built-in policy or changes reported results:

| Entry | Reported when |
| --- | --- |
| `validate.require_completeness=false`, `validate.require_integrity=false` | the check is switched off |
| `risk.fail_on_severity=none` | the severity check is switched off |
| `risk.fail_threshold=VALUE`, `risk.warn_threshold=VALUE` | raised above the built-in value |
| `risk.ignore_categories=NAMES` | any category is ignored |
| `risk.suppressions: CATEGORY on REF (FINGERPRINT) until DATE (owner OWNER)` | once per suppression |
| `scan.failure_mode=report-only` | collection failures and findings never fail `scan`; unverified discovery evidence under `--check` still does |
| `scan.scanners=NAMES` | fewer collectors than the built-in set |
| `scan.exclude_paths=PATHS` | paths beyond the always-skipped names (`node_modules`, `.git`, `__pycache__`, `.venv` and `venv`) |
| `output.default_format=FORMAT` | the project selects an export format other than `json`, which changes what `scan -o` writes without `-f` |

Stricter values, such as a lower threshold or `fail_on_severity: high`, are not listed. Human-readable `scan`, `validate` and `risk` print the list on stderr as a warning.

## Where the governing policy is recorded

- `scan` writes `policy_source` (`built-in`, `project:.nexus-symbiote.yaml` or `project:.nexus-symbiote.yml`) and `policy_weakened` into the inventory's `metadata`, so the artifact itself shows a weakened gate.
- `risk --json-output` reports `policy_source`, `policy_weakened` and a `gate` object with the effective `fail_threshold`, `warn_threshold`, `fail_on_severity`, `ignore_categories` and number of suppressions, each with its source: `cli`, `project policy` (the policy file sets the key) or `built-in`. A `warn_threshold` the policy file does not set is `built-in`, even when the built-in rule lowered it to the project's `fail_threshold`.
- `validate` prints `Policy:` with the source.

## Not supported

- **Allow and deny rules.** A policy cannot list permitted MCP hosts, registries, transports or model providers, or deny a component. Gate on those with an external policy engine over the native inventory and `risk --json-output`.
- **Wildcards and path globs** in suppressions or `ignore_categories`.
- **An operator-owned policy file.** Use `--no-project-policy` with the caller-side options `--threshold`, `--fail-on-severity`, `--signature-policy` and `--require-discovery-signature`.
- **Accepting an exclusion.** An excluded path is always a coverage gap.

## Common errors

| Message | Cause |
| --- | --- |
| `invalid or unsupported settings: risk (warn_threshold cannot exceed fail_threshold)` | Both thresholds are set and the warning threshold is the higher one. |
| `invalid or unsupported settings: version` | `version: 1.0` without quotes. |
| `invalid or unsupported settings: risk.suppressions.0.expires` | A date that is not `YYYY-MM-DD`, or a date with a time. |
| `invalid or unsupported settings: risk.suppressions.0.fingerprint` | The entry has no fingerprint, as suppressions written before fingerprints were required do not, or it is not `sha256:` and 64 lowercase hex digits. Copy it from the finding in `risk --json-output`. |
| `both .nexus-symbiote.yaml and .nexus-symbiote.yml exist` | Remove one of the two files. |
| `Scan gate failed` after adding `exclude_paths` | Any matched exclusion beyond the defaults is a coverage gap. |
