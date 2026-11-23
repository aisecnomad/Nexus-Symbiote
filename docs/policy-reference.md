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

The CLI applies each checkout setting that tightens the governing policy, including in a mixed file. If a setting weakens a gate or changes the output format, the CLI withholds it and warns on standard error. Pass `--accept-project-policy` after reviewing the file. A signed operator policy still bounds the result. Omitted settings inherit the operator's values.

Use `--no-project-policy` to skip the checkout file entirely. The GitHub Action selects this mode explicitly. CI environment variables have no effect on these choices.

Only a policy in the named project root governs the command. Without `--project`, `validate` and `risk` can name a nearby file in a warning.

A malformed, ambiguous or unreadable checkout policy stops the command, including with `--accept-project-policy`. The default exit status is 1; with `--detailed-exit-codes`, `scan`, `validate` and `risk` return 4. This includes an empty file, an unsupported key, a misspelled setting such as `fail_on_severity: High`, both policy names present, a symlink, an oversized file, or a listing that reaches the entry limit. Click rejects an unreadable project root with exit status 2. `init` requires a single unambiguous target.

When `risk` or `validate` leaves a policy unused, its JSON contains `policy_unapplied` with a `reason` of `not-accepted`, `relaxations-not-accepted` or `project-not-specified`. A file name is included when the CLI can safely identify it. Explicitly ignoring policy suppresses this field and the warning. An applied relaxation appears in `policy_weakened`.

A checkout that requests a stricter assurance level and a higher risk threshold gets the stricter assurance level automatically. The threshold stays at its governing value unless the operator accepts the relaxation.

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
| `version` | `"1.0"` | Policy format version (`"1.0"` only). |
| `scan.scanners` | all 8 collectors | Collectors `scan` runs. Omitted collectors record `unknown` (partial coverage → scan/risk gates fail) and report as weakened. `--scanner` overrides per run. |
| `scan.exclude_paths` | `node_modules`, `.git`, `__pycache__`, `.venv` | Root-relative paths skipped. The built-in names plus `venv` are always skipped (inside a skill/command/rule/subagent dir they record a coverage gap). Extra entries that match files record `surfaces_excluded`, fail gates, and report as weakened. Absolute paths and `..` are refused. |
| `scan.failure_mode` | `"error"` | `"report-only"` exits 0 regardless of scan gate outcome (except `scan --check` still exits 1 on unverified ShadowScan discovery). Reported as weakened. |
| `risk.fail_threshold` | `50.0` | Fails the risk gate when the uncapped weight sum (critical 10, high 7, medium 4, low 1, info 0) reaches this value. Must be positive; higher values report as weakened. Overridden by `risk --threshold` or Action `risk-threshold` (0–100; `0` passes `--no-score-threshold`). |
| `risk.warn_threshold` | `25.0` (capped at `fail_threshold`) | Marks `risk_level: high` and `warning_threshold_exceeded: true` without failing gates. Cannot exceed `fail_threshold`; higher values report as weakened. |
| `risk.fail_on_severity` | `"critical"` | Fails on any finding at or above `critical`, `high`, `medium`, `low`, or `info`. `"none"` disables the check and reports as weakened. Overridden by `risk --fail-on-severity` (GitHub Action defaults to `high`). |
| `risk.ignore_categories` | `[]` | Excludes exact finding category names across all components (`ignored_findings`). Prefer targeted [suppressions](#suppressions). Reported as weakened. |
| `risk.suppressions` | `[]` | Accepts a single reviewed finding by fingerprint; see [Suppressions](#suppressions). Each entry reports as weakened. |
| `validate.require_completeness` | `true` | `false` skips completeness and `--project` reconciliation in `validate` (`risk --project` still reconciles). Reported as weakened. |
| `validate.require_integrity` | `true` | `false` skips integrity verification in `validate`. Reported as weakened. |
| `validate.minimum_assurance_level` | `"declared"` | `"observed"` requires every component to have collector-measured byte identity or local repository presence (supplier-only or hosted-model declarations fail; reconciled ShadowScan reports are exempt). `"verified"` always fails offline. |
| `validate.require_discovery_signature` | `false` | Requires `--signature-policy` to verify ShadowScan reports under `--project` (fails without `--project` whenever ShadowScan evidence is present, even with `--allow-unsigned-discovery`). Use `--require-discovery-signature` when passing `--no-project-policy`. |
| `output.default_format` | `"json"` | Default `scan` output format (`json`, `cyclonedx`, `spdx`, `sarif`) when `--format` is omitted. |

### Category names

`ignore_categories` and suppressions match exact category names from `risk --json-output` (unknown names are accepted with no effect). See the [finding catalog](finding-catalog.md#categories) for the full, test-verified list of categories emitted by this release.

## Suppressions

A suppression accepts one reviewed false positive without disabling an entire category or gate. Each entry binds to the finding's **fingerprint**, so it stops applying automatically if the finding or underlying content changes:

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
| `component_ref` | Exact `component_ref` from `risk --json-output`. Wildcards (`*`) are refused. |
| `category` | Exact finding category name. |
| `fingerprint` | Required `sha256:<64 lowercase hex digits>` printed by `risk` / `risk --json-output`. |
| `reason` | Required explanation of why the finding is accepted. |
| `owner` | Required accountable owner. |
| `expires` | Required calendar date (`YYYY-MM-DD`, UTC end-of-day); permanent suppressions are not supported. |

**How fingerprints bind to content:**

- The fingerprint is the SHA-256 of compact sorted-key ASCII JSON over `{component_ref, category, severity, detail, content}`.
- `content` binds to the component's digest (`content_hash`, `definition_hash`, `schema_hash`, `config_hash`, or `hashes.sha256`). Non-model components without those fall back to collector binding hashes (`static_value_binding`, `static_config_hash`, `static_card_hash`, `config_hash`, `settings_hashes`).
- Prompt files with withheld `content_hash` (e.g., non-Markdown `@path` imports or non-Markdown symlink targets) bind to keyed `static_value_binding` when collected with `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`; without the key, no suppression can match them (reported as stale/unused).
- Any byte change to the underlying file, configuration, or finding severity invalidates the fingerprint. Each finding requires its own entry; any malformed entry invalidates the entire policy.

**Matching & lifecycle:**

- **Active match:** Excludes only that exact `(component_ref, category, fingerprint)` from score, severity counts, and gates; recorded under `suppressed_findings`.
- **Expired:** After `expires` (UTC), suppresses nothing and fails the risk gate (`suppressions_expired`: `suppression of CATEGORY on REF expired on DATE`).
- **Stale / unused:** If the component/category still has findings with a different fingerprint, the entry suppresses nothing and reports under `suppressions_stale` (`current_fingerprints`) so you re-review before updating. Entries matching no finding report under `suppressions_unused`.
- **Bypass protection:** `--no-project-policy` ignores all suppressions, and `baseline` re-gates under the built-in policy so suppressions cannot promote a baseline.

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
