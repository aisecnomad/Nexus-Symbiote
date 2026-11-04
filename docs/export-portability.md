# Export portability and loss

CycloneDX 1.7 and SPDX 3.0.1 exports contain a standard projection and a
digest-bound `nexus-symbiote:document` property containing the native inventory.
The digest detects inconsistency; it does not authenticate the document or its
producer. A consumer can discard extension properties while keeping a valid
standard document. Do not use such a document as a complete AgentBOM.

| Native information | CycloneDX projection | SPDX projection | Full fidelity |
| --- | --- | --- | --- |
| Component name, version, supplier, valid PURL and supported hashes | Standard component fields when available | Element, external identifier and hash fields when available | Native extension retains original fields, including rejected identifiers |
| Agent, model, data and other component kinds | Mapped to standard component types; kind also in properties | Mapped to SPDX types; kind also in extensions | Native extension retains detailed subtype and fields |
| Unconditional `depends-on` edge | Standard dependency graph | Standard `dependsOn` relationship | Native extension retains the complete edge |
| Other relationships | Typed edge summary in properties, not the standard dependency graph | Mapped relationship where supported, otherwise `other` | Native extension retains the exact relationship and conditions |
| Assurance, claims, authority, coverage and discovery provenance | Selected properties and incomplete composition where applicable | Selected extension properties | Native extension is required for complete semantics |

These rows summarize the current generator, not every individual field or loss.
Each export includes a `nexus-symbiote:lossReport` with selected security-field
paths, normalizations and a source digest. `itemCoverage` explicitly describes
its limited scope. A standard field or extension may carry a claim without
establishing that it is true or authorized.

After an interchange or transformation, check the exact received export:

```sh
nexus-symbiote verify-export --format cyclonedx received.cdx.json
nexus-symbiote verify-export --format spdx received.spdx.json
```

The command checks the pinned schema, required native properties, embedded digest,
and agreement of the supported standard projection with the embedded inventory.
It fails if the extension is missing or conflicting, and does not fall back to
reconstructing a complete inventory from lossy standard fields. This is a
consistency check, not a signature check, field-accuracy assessment or approval.
Independently authenticate the exact received bytes and the producer's policy
before relying on the result. See [security model](security-model.md) and
[ShadowScan integration](shadowscan-integration.md) for source verification.
