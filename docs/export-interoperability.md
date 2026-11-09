# Standard export interoperability

This matrix describes the 0.1.0 CycloneDX 1.7 and SPDX 3.0.1 JSON exporters.
A standard-only consumer is one that ignores or discards SymBiote's extension
properties. The embedded native document is digest-bound for corruption and
projection checks; it does **not** authenticate the exporter or its assertions.
Retain the original native BOM and use an independently trusted signature or
attestation where producer identity matters.

## Field and loss matrix

| Native information | CycloneDX 1.7 standard fields | SPDX 3.0.1 standard fields | When the extension is dropped |
| --- | --- | --- | --- |
| Component name, supported type, version, supplier and description | `components` fields; agent-specific types map to broader standard types | `@graph` element, package and supplier fields; agent-specific types map to broader standard types | Basic identity remains, but exact native component type and all component details cannot be reconstructed from that alone. |
| Package identity and artifact hashes | `purl` when a valid package identifier exists; `hashes` | `externalIdentifier`, `software_packageUrl` for non-files, and `verifiedUsing` | The projected identifier and hash remain; they are declarations, not evidence of a trusted producer or a successful verification. |
| Unconditional `depends-on` edge | `dependencies[].dependsOn` | `Relationship` with `relationshipType: dependsOn` | Projected dependency remains; edge assurance and evidence do not. |
| Other unconditional relationship | Not present in the standard dependency graph | Typed relationships where supported; otherwise `other`, with the native type named in a comment | CycloneDX loses the edge without SymBiote properties. SPDX retains the projected type or comment, but not complete native edge semantics. |
| Conditional relationship | Omitted from `dependsOn`; a SymBiote metadata property records its type and conditional flag | `other` relationship with a bounded comment naming the condition, not an unconditional typed relationship | CycloneDX loses the edge and condition. SPDX retains the comment, which can be truncated; the native condition and assurance are not reliably recoverable. |
| Collector status, exclusions and discovery provenance | `compositions` aggregate is `incomplete` or `unknown`; selected discovery metadata is in properties | Relationship completeness is `incomplete` or `noAssertion`; document comment states the coarse aggregate | Detailed status, exclusions and provenance are unavailable. With no native-edge relationships, SPDX's coverage statement is only a document comment; license relationships do not carry completeness. Neither export claims complete coverage. |
| Agent-specific capabilities, authority, evidence and deployment profile | SymBiote component and document properties | SymBiote extensions | Details cannot be recovered from standard fields alone. |
| Complete native inventory | Embedded in document properties, with digest | Embedded in document extension, with digest | Full-fidelity recovery is impossible. `recover` rejects missing native document properties. |

CycloneDX metadata relationship properties are extensions, not standard dependency
edges. Conditions and assurance remain in the embedded native document. A
standard SPDX comment is readable but should not be treated as a machine-enforced
policy. See [known limitations](../SECURITY.md#known-limitations-in-010) for
other limitations and [tool fingerprint migration](fingerprint-migration.md) for
older exports. Schema validity alone says nothing about the truth, completeness,
authorization or safety of the inventory.

## Consumer compatibility tested in CI

| Consumer | Test and scope | Known result or limitation |
| --- | --- | --- |
| Vendored official schemas | `tests/test_export_conformance.py` validates generated exports against the pinned CycloneDX and SPDX schemas. | Structural conformance is not a guarantee of consumer interoperability. |
| `cyclonedx-python-lib` | `test_cdx_independent_consumer_round_trip` parses and serializes a generated BOM; `test_cdx_partial_coverage_through_independent_consumer` exercises partial coverage. | Version 11.12.0 drops `compositions`; losing an `incomplete` warning causes SymBiote recovery to reject the output. Dropping an `unknown` aggregate removes no completeness assertion. |
| `spdx-python-model` | `test_spdx_independent_consumer_round_trip` parses and serializes JSON-LD; `test_spdx_partial_coverage_through_independent_consumer` checks preservation of incomplete coverage. | The tested fixtures are not a guarantee for other documents or consumer versions. |
| Standard-only views | `tests/test_standard_only_consumer.py` removes extensions, checks relationship and coverage projections, and uses independent reader/validator libraries for selected cases. | Extension loss means the native BOM cannot be recovered, even if the remaining standard document is valid. |

Run the focused checks in the project's locked development environment:

```sh
python -m pytest tests/test_export_conformance.py tests/test_standard_only_consumer.py
```

These tests do not cover every downstream SBOM platform, format conversion, or
consumer version. Qualify each target platform with representative BOMs, including
conditional edges, partial collection, imported discovery and extension retention,
before relying on its output for a gate.
