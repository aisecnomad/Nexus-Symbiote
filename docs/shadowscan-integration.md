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

The projection profile `nexus-symbiote/shadowscan-projection/v2` identifies the
SymBiote mapping, not a ShadowScan report schema or authenticated producer
version. CycloneDX `dependsOn` edges are copied only when both endpoints map to
components. They remain declared, source-reported relationships, with the exact
report digest and dependency-array index recorded on the edge. Unmapped endpoint
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
Version 1 projections used the server type for these findings; retain the
original importer to reproduce or verify a v1 projection, then regenerate and
review v2 inventories before comparison or approval. Producer schema and
version changes require compatibility testing; the report remains untrusted.

At present the bridge does not resolve agents across tenants or reports, verify
live MCP identities, or map every ShadowScan finding type, model association or
dependency. A complete ShadowScan run is only complete for its configured scope;
Nexus SymBiote records the imported BOM coverage as partial. SARIF is not available
for imported discovery because its finding projection does not retain complete
coverage and provenance.

## Import and policy gates

The native importer compares reported totals and supplied per-kind and
per-surface counts with the final findings array. When the producer supplies
aggregate error counts and incomplete-reason counts, the importer also checks
them against the connector records. A contradictory summary is an
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
assurance. Merged, enriched and portable BOMs require their own provenance.

The offline signature regression uses a public release bundle from
[sigstore-python at 19b8aec](https://github.com/sigstore/sigstore-python/blob/19b8aec7063e62c718efd327f5a45582472c3b3c/test/assets/bundle_v3_github.whl.sigstore).
Its Apache-2.0 license accompanies the fixture. Production report verification
requires your own producer identity, issuer and report bundle.
