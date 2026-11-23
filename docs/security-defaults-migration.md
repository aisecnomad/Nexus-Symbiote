# Security fields: unknown rather than invented defaults

When evidence is missing, newly constructed native BOMs no longer infer tenant
isolation, encryption at rest, remote-code settings, publisher verification,
execution isolation, human approval, or whether approval is required. These
fields now default to `null` in a full model dump and are absent when
serialization excludes nulls. Both represent **unknown**, not `false` or an
empty permission. Existing explicit `true`, `false`, and enum values retain
their meaning.

`trust_remote_code` read from a local model configuration is only a declared
setting. The actual runtime loader argument can differ, so even an explicit
`false` does not prove remote code was disabled when the model ran. Missing,
null, and non-boolean configuration values are unknown. Assess the effective
runtime setting separately.

The `model` collector applies the same rule to what a model file is. It records
`serialization_format` and `model_type` for a `.gguf` or `.safetensors` file only
when the file's header is that format's; otherwise both are absent, which means
that the format was not established, and `properties.named_format` holds the
format the name claims ([model integrity](model-integrity.md#format-and-model-type)).

Releases up to 0.2.0 recorded both from the suffix, so in an inventory they wrote,
`serialization_format` and `model_type` on a `.gguf` or `.safetensors` record do
not show that the file is of that format. Collect such an inventory again.

For each file whose header is not its format's, `diff` reports the changed fields
and properties as one alert, on which it exits 1 unless `--no-fail-on-alert` is
given, and `validate --project` reports the older record as `Missing or mismatched
local component`. The alert is medium for a `.gguf` file, and for a pickle, a ZIP
that holds a pickle or a NumPy object array under either suffix. It is high for any
other file named as SafeTensors that does not validate, such as an empty or a text
file, and begins `Risk findings added: 1 high (invalid_safetensors).`, because the
finding the collector now stores is new on the record.

The `invalid_safetensors` gate is unchanged: `risk` raises it for either record, and
the collector stores the finding on a record without `serialization_format`, so that
a release up to 0.2.0, which derives it from that field alone, still fails the gate
on an inventory this release wrote.

Consumers must handle unknown values explicitly. In particular, avoid boolean
coercion (`if not value`) when false and unknown have different consequences.
Older BOMs may contain security values created by earlier defaults; those values
do not independently prove that the protections were observed. Recollect the
evidence rather than upgrading their assurance based on the old default.

Agent autonomy also defaults to unknown. Loading an agent with an omitted or null
`autonomy_level` no longer creates an `L2-agent` assertion. An explicitly supplied
autonomy enum is retained as a declaration. Historical snapshots that already
contain `L2-agent` cannot reveal whether it was a producer assertion or an old
constructor default; recollect or review them before relying on that value.

CycloneDX and SPDX preserve explicit false and unknown native values through the
digest-bound native extension and report projection limitations. Standard-only
consumers must account for those limitations. Conditional edges are never
exported as typed SPDX relationships or in the CycloneDX dependency graph. Every
CycloneDX and SPDX inventory export states its coverage in standard fields:
CycloneDX `compositions` and SPDX relationship `completeness` say `incomplete`
or `unknown` (`noAssertion` in SPDX), and the SPDX document `comment` states it
in prose. SARIF reports collection failures as an unsuccessful execution and
lists failures, coverage gaps and collectors that did not run as tool execution
notifications; VEX output states no coverage. A lossless extension round trip
does not authenticate the values or their producer.

Snapshot comparison now covers component semantics, missing integrity evidence,
capabilities, authorization records and dependency conditions or assurance.
Set-like native collections ignore ordering; opaque JSON arrays, command
arguments and tool schemas retain order. Fresh claim observation timestamps do
not alone constitute component drift. The diff remains a comparison of supplied
snapshots; authenticate their provenance and evaluate coverage separately.
