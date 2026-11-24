# Tool fingerprint migration

Current releases compute tool descriptor fingerprints under `definition_hash_version: rfc8785-jcs-v2` (RFC 8785 JSON Canonicalization Scheme; non-finite numbers fail canonicalization rather than coercing to `null`). Absent or `v1` profiles are treated as unverified and must be recollected and re-approved — never migrate a baseline by copying an older `sha256:` digest.

- **Descriptor scope & redaction:** `definition_hash` covers the original `name`, `description`, `inputSchema`, `annotations`, and (when declared) `title`, `outputSchema`, and `_meta`. Exported schemas omit literal `default`, `examples`, `const`, and `enum` values to prevent credential leakage; whenever the exported view differs from the original (including static tools declaring `title`, `outputSchema`, or `_meta`), `redacted_definition_hash` binds the displayed view. Live observations (`discover-mcp --record`) retain safe extension values in `mcp_title`, `mcp_output_schema`, and `mcp_meta` (if legacy aliases are also present, their JSON values must match). Static tool hashes are unkeyed digests over the original descriptor, so treat exported BOMs as sensitive and keep secrets out of tool schemas; corroborate static configs via `validate --project --no-project-policy`.
- **Models & launchers vs. `0.1.0`:** Model references use root-relative paths (`model:<relative path>`) and bind external ONNX data, SavedModel variables, shard indexes, configs, tokenizers (`tokenizer_hash`), chat templates (`chat_template_hash`), and declared custom code ([model integrity](model-integrity.md)). MCP package launchers record `launcher_package` and default-registry `package_url`, require image digests for container pins, and move stdio notes to `local_process`. Recollect `0.1.0` baselines once after upgrading.

## Suppression content digests

A `risk` suppression fingerprint binds the component's content digest (`definition_hash`, `content_hash`, `hashes.sha256`, or collector binding properties: `static_value_binding`, `static_config_hash`, `static_card_hash`, `config_hash`, `settings_hashes`). Components that previously lacked a content digest change fingerprint once on upgrade and appear under `suppressions_stale` with `current_fingerprints`; review each finding before updating `.nexus-symbiote.yaml`.

## MCP resolver binding v3

`nexus-symbiote/mcp-static-values/v3` binds full Deno import-name-to-target and scope mappings in the keyed HMAC preimage (closing a v2 target-swap collision), while flagging explicit Deno `--config`/`-c`/`--no-config`/`--import-map` options and unsupported `importMap` shapes as coverage gaps. Keyed v2 baselines fail `--project` reconciliation and must be recollected under v3.

## MCP static structure v4

`nexus-symbiote/mcp-static-config/v4` digests sorted, redacted tool names per field in `client_settings.auto_approved_tools` and `client_settings.tool_filter_names` (v3 digested counts only). Every static MCP server's `static_config_hash` changes once (`validate --project` marks v3 unknown). Non-root `cwd`, `envFile`, `watchPaths`, `oauth`, `auth`, `dev`, `env_vars`, `bearer_token_env_var`, `env_http_headers`, unknown client fields, and redacted approval/filter names are marked unbound without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` (emitting a low `completeness` finding and a medium unbound-values alert on `diff --fail-on-alert`).

## Pickle-family inspection evidence

Pickle-family artifacts (`.pkl`, `.pt`, `.bin`, etc.) record inspected payload format in `properties.format_inspection` rather than loader name, rating recognized pickles `unsafe-code-execution` (critical `serialization_format`) and unrecognized non-pickle bytes `unknown` (high `serialization_format_unknown`). Recollect earlier baselines once after upgrading.

## Source MCP server names

Source-collected MCP servers use their literal constructor name (`new McpServer({ name: "analytics-mcp" })`, `FastMCP("analytics-mcp")`) as `name` and store the variable in `properties.binding`. TS/JS `bom_ref` values include the literal name (`mcp-source:src%2Fserver.ts:analytics-mcp:2:84`), whereas Python servers keep `mcp-python:<path>:<variable>`. Because every source server gains `properties.binding`, pre-upgrade inventories fail `validate --project` / `risk --project` until recollected.

## MCP client dialects

`.junie/mcp/mcp.json` is inventoried as the root-launched `junie` dialect (gaining default-registry `package_url` and dropping the nested-directory `package_source` finding and client gap). Zed, opencode, Continue, and launch-less server entries are inventoried directly (recording `version_pinned: false` and a `launcher_identity` finding + gap when neither command nor endpoint is declared); recollect earlier baselines once.

## Neutralized identifiers

Component `name`, `description`, `supplier`, MCP `auto_approved_tools`/`tool_filter_names`, finding details, `surfaces_excluded`, and `scan_failures` neutralize control/format characters and CI log-command introducers ([known limitations](known-limitations.md#every-collector)). Components whose identifier fields contained reported characters or intraword mixed-script lookalikes record `neutralized_raw_sha256` and a high `identifier_characters` finding ([finding catalog](finding-catalog.md#categories)). A2A and RAG `bom_ref` values percent-encode neutralized characters (and escape existing `%XX` as `%25XX`) to stay collision-free; suppressions quoting newly neutralized names appear under `suppressions_stale`.

## SARIF rule identifiers

SARIF rules are keyed by `<category>/<severity>` (`nexus_symbiote/<category>/<severity>`) rather than `<category>` alone so one finding cannot inflate sibling rule severities. First upload after upgrading from `0.1.0` closes `0.1.0` code-scanning alerts and opens new ones; downstream matchers should key on the stable `nexus_symbiote/v1` result fingerprint.

## Standard projection versions

CycloneDX and SPDX exports record `nexus-symbiote:projection`, and recovery verifies standard fields strictly against the declared projection ([standard exports](standard-exports.md)):

- **Projection 1 (`0.1.0`, unmarked):** Accepted by recovery (CycloneDX legacy flattened `dependsOn` requires `CycloneDXGenerator.recover(doc, allow_legacy_relationships=True)`; pre-`0.1.0` builds without `compositions` or SPDX `completeness` must be regenerated from native JSON). Note that `cyclonedx-python-lib` drops `compositions` on reserialization, breaking recovery of `incomplete` BOMs.
- **Projection 2 (`cyclonedx-1.7/2`, `spdx-3.0.1/2`):** Places the scan repository agent in `metadata.component`; types packages/containers as `library`/`container` with exact `version` (`requestedVersion` extension for ranges); exports file digests in `hashes`, `source_path` in `evidence.occurrences`, unconditional `depends-on` + `provides-tool` in `dependsOn` (`"conditional": true` on conditional extension edges), `expandedlicensing_NoAssertionLicense` and `urn:uuid:` IRIs in SPDX, validated ecosystem-matching `purl` identifiers, and loss report `nexus-symbiote-export/v2`.
- **SPDX Projection 3 (`spdx-3.0.1/3`):** Neutralizes control, separator, format/bidi, CI-command, and `U+FFFE`/`U+FFFF` characters in SPDX relationship comments using a fixed character table while leaving embedded native conditions unchanged.

## Documentation links in findings

Model-integrity finding recommendations link to `docs/model-integrity.md` under the canonical `aisecnomad/Nexus-Symbiote` URL; re-baseline once if comparing against snapshots produced prior to the namespace transfer.

## Upgrade attribution (`--expect-upgrade`)

`nexus-symbiote diff baseline.json candidate.json --expect-upgrade FROM_VERSION` (`0.1.0` or `0.2.0`) moves alerts caused *exclusively* by documented serializer/profile transitions into `tool_upgrade_changes` while keeping any co-occurring supply-chain change, unbound launch values, or unknown tool fingerprint version in `security_alerts`. Recollect and re-approve the baseline after reviewing the upgrade diff.
