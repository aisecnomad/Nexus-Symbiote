# ShadowScan discovery and Nexus SymBiote verification

Run Nexus-ShadowScan separately with the least privileges needed for the chosen
connectors and save its JSON report. Keep the report under appropriate access and
retention controls. For example, following the ShadowScan version's own CLI help:

```sh
shadowscan code /path/to/repository --format json -o shadowscan.json
nexus-symbiote import-shadowscan shadowscan.json -o agentbom.json --report-only
nexus-symbiote import-shadowscan shadowscan.json --format cyclonedx -o agentbom.cdx.json --report-only
nexus-symbiote verify-discovery agentbom.json shadowscan.json
nexus-symbiote verify-artifact model.safetensors --project /path/to/repository --sha256 "$TRUSTED_SHA256"
nexus-symbiote validate agentbom.json --project /path/to/repository
```

The output path must not exist. An incomplete source produces a partial BOM and
nonzero exit; a malformed or unsupported report is rejected. A locally generated
report digest binds the imported bytes, not the identity of their producer or the
truth of their contents. Verification of signatures, sources and artifacts is a
separate operation; this importer does not perform it. Do not infer production
activity, effective access or authorization from a finding or inventory mismatch.
`verify-discovery` compares exact report bytes with the native BOM's recorded
digest. It does not authenticate either the BOM or the report.
`verify-artifact` hashes a selected local artifact within the project root against
an operator-supplied expected digest. To verify a Sigstore bundle as well, pass
`--bundle`, `--signer-identity`, and `--issuer`. The expected digest and signer
policy must come from a trusted source. This verifies the selected artifact, not
its association with a discovery finding, deployment, or safety.

The importer maps native `agent`, `mcp-server` and `local-model` findings,
including MCP tool observations distinguished by resource type. It
also accepts ShadowScan's CycloneDX 1.6/1.7 components and services, marking the
projection partial. Unmapped entries are counted with source indexes. For
CycloneDX, the index is into components followed by services. The source report
and its scope, timestamps, detailed evidence, identities and full graph remain
the authoritative discovery record. Only supported, mapped-endpoint CycloneDX
dependencies are projected as declared claims; the rest of those fields remain
in the report. This reduces leakage but does not create a complete evidence graph.

All imported components have declared assurance and unknown trust. The importer
does not run ShadowScan, execute tools, fetch endpoints, infer agent autonomy, or
promote a signature filename into verified evidence. ShadowScan risk and shadow
flags remain source-reported heuristics; an inventory mismatch is not proof of
unauthorized activity. Output contains report and source-ID digests and indexes,
not raw source descriptions, locations or snippets. Both artifacts may still be
sensitive and must be handled accordingly.

The projection profile `nexus-symbiote/shadowscan-projection/v3` identifies the
SymBiote mapping, not a ShadowScan report schema or authenticated producer
version. Each projected component records the exact report digest
(`shadowscan:report-sha256`) and a content digest of its own source finding
(`shadowscan:finding-sha256`, see below). CycloneDX `dependsOn` edges are copied
only when both endpoints map to components. They remain declared, source-reported
relationships, with the dependency-array index recorded on the edge; the BOM
metadata binds them to the report digest. Unmapped endpoint
edges are counted as limitations; raw source identifiers are not included. This
does not verify deployment, association or authorization. The native ShadowScan
format has no general dependency graph, and this importer does not infer one from
fields that merely mention a model. Consumers of standards exports must retain
the SymBiote extension to preserve the edge assurance and provenance.

ShadowScan's endpoint connector can report an MCP tool using kind `mcp-server`
and resource type `mcp-tool`. Version 2 projects that exact combination as a
declared, unverified tool rather than as a server. It does not infer a server
association, tool definition hash, endpoint identity or authorization. Conflicting
tool and kind claims remain unmapped. Native JSON uses `resource_type` and
CycloneDX uses the `shadowscan:resource-type` property. This mapping follows the
[ShadowScan endpoint producer at 1a821e5](https://github.com/Hunzee-VC/Nexus-ShadowScan/blob/1a821e5763e9340ea96564b0606d1ab581fde90e/shadowscan/connectors/endpoint/runtime.py)
and its [CycloneDX reporter](https://github.com/Hunzee-VC/Nexus-ShadowScan/blob/1a821e5763e9340ea96564b0606d1ab581fde90e/shadowscan/reporters/cyclonedx.py).
Version 1 projections used the server type for these findings, and version 2
recorded the exact report digest on CycloneDX edges and had no finding digest.
Retain the original importer to reproduce or verify an older projection, then
regenerate and review v3 inventories before comparison or approval. Producer schema and
version changes require compatibility testing; the report remains untrusted.

At present the bridge does not resolve agents across tenants or reports, verify
live MCP identities, or map every ShadowScan finding type, model association or
dependency. A complete ShadowScan run is only complete for its configured scope;
Nexus SymBiote records the imported BOM coverage as partial. SARIF is not available
for imported discovery because its finding projection does not retain complete
coverage and provenance.

## Import and policy gates

The native importer compares reported totals and supplied per-kind and
per-surface counts with the final findings array. A contradictory summary is an
invalid report, including in report-only mode. Individual connector counts can
precede filtering or deduplication and can legitimately differ from the final
array.

Standalone import records partial coverage even when the source reports a completed
scan. It writes the evidence and exits with status 1. Pass `--report-only` to
accept that result for inspection. The command ignores project policy in the
report directory and its ancestors. Incomplete source reports retain their
status in either mode. Each import requires a new output path.

Native JSON, CycloneDX and SPDX preserve report provenance, source status and
unmapped indexes. Portable formats embed a digest-bound native inventory extension;
its round trip preserves the imported limitations without authenticating the
producer. CycloneDX also declares an incomplete composition. SARIF imports remain
unavailable because a finding-only projection does not preserve this evidence.

The importer API returns `ImportedReport`, including `components`, coverage and
provenance, rather than a bare component list. It rejects bare finding arrays that
cannot carry source coverage. Unknown finding kinds remain unmapped. Imported
assets are not automatically linked to the repository agent or asserted present
on the local filesystem.

### Scope of a repository baseline

`scan` and `baseline` assess the supported static files in one repository.
All eight collectors must finish for the default gate to pass. A successful
search can find zero matching files. Git metadata, dependency directories and
virtual environments are outside the built-in scope. The inventory lists those
patterns under `exclusions`. Unreadable files, unsupported declarations and
additional policy exclusions encountered inside the scope keep coverage partial.
A baseline also requires a local subject. The path-inferred repository agent
and imported findings alone provide no evidence of a local agent or artifact.

The collector checks the conventional local ShadowScan report paths. If none
exists, the inventory records that observation. A fully mapped native report
whose source collection completed can accompany a successful repository baseline.
The digest and `source_projection_limitations` record the external evidence
separately. Imported assets retain declared assurance and unknown trust, and
the CycloneDX composition remains incomplete. Incomplete sources, unmapped
entries and lossy CycloneDX inputs keep the default repository gate closed.

Project validation also compares imported dependency endpoints, relationship types,
assurance, provenance and multiplicity against the local report projection. Missing,
modified or additional edges involving imported components fail reconciliation.

### Compare discovery across reruns

The exact report digest changes on every ShadowScan run, because the report
records when the run started and finished. It stays the value that
`verify-discovery`, Sigstore and `validate --project` authenticate. For drift,
the inventory also records `source_report_content_digest` under the profile
`nexus-symbiote/shadowscan-content/v1`: the SHA-256 of the RFC 8785 canonical
JSON of the strictly parsed report without its run-event fields. These are, for
native JSON, the top-level and per-connector `started_at` and `finished_at` and
each finding's `last_seen`; for CycloneDX, `serialNumber` and
`metadata.timestamp`. Each is dropped only when it is null or shaped as an RFC
3339 timestamp written with ASCII digits, or for the serial number a URN UUID. The list is closed. Every
other field or value, including a field a later ShadowScan release adds, counts
as content. `shadowscan:finding-sha256`
applies the same rule to one finding, or to one CycloneDX component or service.

When both inventories carry content digests under the same profile, `diff`
ignores a changed exact digest and records an informational metadata note,
"ShadowScan report regenerated; normalized content unchanged", which is not a
security alert. A changed finding raises a medium alert on its own component,
including when only fields that the BOM does not project changed, and the
changed report content raises the high completeness alert. An inventory
written by an earlier version has no content digests, so the first comparison
after an upgrade raises the high completeness alert and a medium alert for
every imported component, even when the report bytes are unchanged, because the
new inventory adds the content digests, the v3 projection profile and the
per-component finding digests. Later comparisons use the content digests. The content
digests are not authentication; `validate --project` compares them with the
local report as it does the exact digest. Text output prints the note under
Notes; `--json-output` lists it in `metadata_changes`.

Reruns whose reports contain redacted credential findings compare cleanly only
when ShadowScan keys credential identities with a stable key, which the report
records as `collection_scope.credential_identity_scope` `keyed`; reports without
such findings compare cleanly in either scope. In the `run` scope, ShadowScan derives each redacted credential
finding's id from a random per-run key, so those findings get new ids on every
run and `diff` reports them as removed and added components. That fails safe,
as alerts, but configure a stable credential identity key in ShadowScan, by
setting `SHADOWSCAN_IDENTITY_KEY` for every run, before you compare reruns.

### Require a signed report in CI

`validate --project` and `risk --project` can require that the ShadowScan
evidence in a merged `scan` BOM comes from a report signed by the expected
producer. List the report in the operator signature policy passed with
`--signature-policy`, using the path the collector reads:

```json
{"version": 1, "artifacts": [{"artifact_path": ".shadowscan/report.json",
  "bundle_path": ".shadowscan/report.json.sigstore",
  "expected_identity": "https://github.com/acme/infra/.github/workflows/discovery.yml@refs/heads/main",
  "expected_issuer": "https://token.actions.githubusercontent.com"}]}
```

```sh
nexus-symbiote validate agentbom.json --project . --signature-policy /etc/ci/signers.json
nexus-symbiote risk agentbom.json --project . --signature-policy /etc/ci/signers.json
```

A signature policy entry that names one of the conventional report paths turns
the check on. An entry matches the report by path or by file, so another name
for the same file, such as a different case on a case-insensitive filesystem,
counts too. So does `validate.require_discovery_signature: true` in the
project policy, which then fails when no entry names the report. Keep the
signature policy outside the checkout, as the project policy can be changed by
the code it gates. When the BOM carries ShadowScan evidence, the check reads
the report beneath the project root with the collector's confined reader and
requires its digest to equal the BOM's recorded `source_report_digest`. It then
verifies the bundle offline over those exact bytes against the policy's identity
and issuer, and requires the BOM's discovery evidence to match the report's
projection. A missing entry or bundle, another signer or issuer, a bundle over
other bytes, or a report changed since the scan fails the command; `risk` then
reports `project-reconciliation-failed` with the reason. Values recorded in the
BOM are never trusted for this check. A passing check authenticates the
report's producer, not the truth of its findings, and imported components keep
declared assurance. Install the Sigstore extra for this mode.

Without `discovery_context`, this check authenticates the producer only. An old
report or another repository's report signed by that identity can be substituted.
A policy that names the report requires its evidence to be present in the BOM,
even when the project's completeness gate is disabled.

### Bind the report to an expected subject and age

An operator can add the complete `discovery_context` object to the report's
signature policy entry. The signature policy must remain outside the checkout;
expected values must be supplied by a trusted deployment or CI system, not read
from the untrusted report or the code being gated.

```json
{"version": 1, "artifacts": [{
  "artifact_path": ".shadowscan/report.json",
  "bundle_path": ".shadowscan/report.json.sigstore",
  "expected_identity": "https://github.com/acme/infra/.github/workflows/discovery.yml@refs/heads/main",
  "expected_issuer": "https://token.actions.githubusercontent.com",
  "discovery_context": {
    "statement_path": ".shadowscan/statement.json",
    "bundle_path": ".shadowscan/statement.json.sigstore",
    "repository": "acme/agent",
    "revision": "0123456789012345678901234567890123456789",
    "scope": "code:repository",
    "producer_version": "0.1.4",
    "max_age_seconds": 3600
  }
}]}
```

The trusted discovery producer signs the exact report and also signs this
strict JSON statement with the same expected identity and issuer. For example:

```json
{"version": 1,
 "report_sha256": "sha256:<64 lowercase hexadecimal digits of the exact report bytes>",
 "repository": "acme/agent",
 "revision": "0123456789012345678901234567890123456789",
 "scope": "code:repository",
 "producer_version": "0.1.4",
 "produced_at": "2026-11-09T08:00:00Z"}
```

Replace the digest and timestamp with values measured by the trusted producer;
the example is not a valid statement. A producer with the Sigstore CLI and its
OIDC identity can create the two bundles using `python -m sigstore sign --bundle
.shadowscan/report.json.sigstore .shadowscan/report.json` and `python -m sigstore
sign --bundle .shadowscan/statement.json.sigstore .shadowscan/statement.json`.
Place the generated files at the policy paths. The operator sets the expected
full lowercase 40- or 64-hex revision, exact repository, scope and producer
version, and an integer maximum age from 1 to 604800 seconds. The statement's
`produced_at` must be a UTC `Z` timestamp; future timestamps and statements
older than the maximum age fail. Unknown, duplicate, missing or malformed
statement fields fail closed. The statement path and its bundle must be bounded,
regular files beneath the project root. Both the report and the exact statement
bytes are verified before the statement's claims are used. The context object
cannot be attached to an unrelated artifact or an unselected report.

This is a signed producer assertion, not proof that the producer actually scanned
the claimed subject or collected all findings. Protect the producer workflow,
clock, credentials and policy distribution. A signed report can still be replayed
within the permitted age; a trusted signer could also issue a fresh statement for
an old report. Enforce a trusted run identifier or stateful nonce externally if
your deployment requires single-use or immediate replay prevention. Binding does
not prove the safety of a discovered component.

### Verify the native import and its producer

For a BOM written by `import-shadowscan`, reproduce the direct import and compare
the component records, dependencies, coverage, unmapped indexes and metadata.

```sh
nexus-symbiote verify-discovery agentbom.json shadowscan.json --projection
```

For an independently signed report, pass the signing policy from trusted operator
configuration. The bundle must be a Sigstore artifact bundle over the exact
ShadowScan report bytes. Install the Sigstore extra for this mode.

```sh
nexus-symbiote verify-discovery agentbom.json shadowscan.json \
  --bundle shadowscan.json.sigstore --signer-identity "$EXPECTED_IDENTITY" \
  --issuer "$EXPECTED_ISSUER"
```

The signed mode also verifies the direct native projection. Use the same importer
version. The comparison ignores JSON object key ordering and the BOM’s locally
generated timestamp and serial number. Source findings keep their declared
assurance. Merged, enriched and portable BOMs require their own provenance, so
`verify-discovery --bundle` rejects a `scan` BOM; use the CI check above for one.

The offline signature regression uses a public release bundle from
[sigstore-python at 19b8aec](https://github.com/sigstore/sigstore-python/blob/19b8aec7063e62c718efd327f5a45582472c3b3c/test/assets/bundle_v3_github.whl.sigstore).
Its Apache-2.0 license accompanies the fixture. Production report verification
requires your own producer identity, issuer and report bundle.
