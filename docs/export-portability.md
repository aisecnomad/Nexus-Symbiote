# Export portability and loss

CycloneDX 1.7 and SPDX 3.0.1 exports contain a standard projection and a
digest-bound `nexus-symbiote:document` property containing the native inventory.
The digest detects inconsistency; it does not authenticate the document or its
producer. A consumer can discard extension properties while keeping a valid
standard document. Do not use such a document as a complete AgentBOM.

| Native information | CycloneDX projection | SPDX projection | Full fidelity |
| --- | --- | --- | --- |
| Component name, version, supplier, valid PURL and hashes | Standard component fields when available | Element, external identifier and hash fields when available | Native extension retains original fields, including rejected identifiers |
| Agent, model, data and other component kinds | Mapped to standard component types; kind also in properties | Mapped to SPDX types; kind also in extensions | Native extension retains detailed subtype and fields |
| `depends-on` edge without conditions | Standard dependency graph | Standard `dependsOn` relationship | Native extension retains the complete edge |
| `depends-on` edge with conditions | Withheld from the standard dependency graph, which lists only unconditional targets; typed edge summary without conditions in properties | Standard `dependsOn` relationship; the conditions are only in the extension, so an SPDX-only consumer sees an unconditional dependency | Native extension retains the exact edge and conditions |
| Other relationships | Typed edge summary without conditions in properties, not the standard dependency graph | `usesTool`, `trainedOn` or `descendantOf` where supported, otherwise `other`; conditions only in the extension | Native extension retains the exact relationship and conditions |
| Assurance, claims, authority, coverage and discovery provenance | Selected properties and incomplete composition where applicable | Selected extension properties | Native extension is required for complete semantics |

These rows summarize the current generator, not every individual field or loss.
Both formats accept MD5, SHA-1, SHA-256, SHA-384, SHA-512, SHA3-256, SHA3-384 and
SHA3-512 hashes. Any other algorithm, or a malformed digest, makes the export fail;
it is not kept in the extension alone. Each export includes a
`nexus-symbiote:lossReport` with selected security-field paths, normalizations and
a source digest. `itemCoverage` explicitly describes its limited scope. A standard
field or extension may carry a claim without establishing that it is true or
authorized.

## Verifying a received export

After an interchange or transformation, check the exact received export:

```sh
nexus-symbiote verify-export --format cyclonedx received.cdx.json
nexus-symbiote verify-export --format spdx received.spdx.json
```

The command parses the file strictly, rejecting duplicate object keys, recovers
the embedded native inventory and checks its digest. It then regenerates the
standard projection with the installed version, requires the whole received
document to equal it, and validates the document against the pinned schema. Only
these differences are tolerated:

- the order of array entries;
- in CycloneDX, the official 1.7 `$schema` hint and an omitted empty `components`
  or `dependencies` array; in SPDX, an omitted empty `rootElement`;
- in CycloneDX, a dependency row with only a `ref`, as standard SDKs such as
  cyclonedx-python-lib add for components without emitted edges, when it names a
  component of the embedded inventory that has no native `depends-on` edge.

A row with only a `ref` declares that the component has no dependencies. For a
component whose conditional `depends-on` edge was withheld from the standard
graph, the row contradicts the inventory, and verification fails. A round trip
through such an SDK therefore fails for those inventories.

Any other difference fails verification, including standard data that
contradicts nothing, such as an added `vulnerabilities` array. Exports written by
a version whose projection differs from the installed one also fail. For
historical CycloneDX exports that flattened every relationship into `dependsOn`,
the Python API accepts `CycloneDXGenerator.recover(document, allow_legacy_relationships=True)`
(see [fingerprint migration](fingerprint-migration.md)); the command has no
equivalent. It does not fall back to reconstructing an inventory from lossy
standard fields.

This is a consistency check, not a signature check, field-accuracy assessment or
approval. Independently authenticate the exact received bytes and the producer's
policy before relying on the result. See [security model](security-model.md) and
[ShadowScan integration](shadowscan-integration.md) for source verification.

### Verification limits

A received export is untrusted, and checking it is costly. Comparing it with the
projection and validating it take time that grows with its size, and SPDX schema
validation takes up to a few tenths of a second per graph entry. The command
therefore refuses a larger export before comparing or validating it:

| Limit | Value |
| --- | --- |
| File | 16 MiB, a regular UTF-8 file; no part of its absolute path may be a symbolic link |
| JSON nesting | 32 levels of objects and arrays |
| JSON values | 1,000,000 |
| CycloneDX components | 2,000 |
| CycloneDX dependency rows | 2,000 |
| SPDX `@graph` entries | 1,000 |
| Embedded inventory | 2,000 components and 10,000 dependency edges |

`CycloneDXGenerator.recover` and `SPDXGenerator.recover` apply the same limits,
except the file limit, and raise `VerificationLimitError`, a `ValueError`. Larger
exports can be generated but not verified. A document that does not equal the
projection of its embedded inventory is rejected before schema validation, so only
a matching export reaches it. The CycloneDX requirement that components and
dependency rows be unique is checked in time linear in their size, whatever the
order of members in each object. At the limits, verification takes tens of seconds
for CycloneDX and several minutes for SPDX. When verifying exports from untrusted
senders automatically, allow for these durations in the command's timeout, and
treat a timeout as a failed verification.

If the export cannot be verified, the command exits 1 with one of three fixed
messages that never quote the input:

| Message | Cause |
| --- | --- |
| `Cannot read the export: ...` | Not a regular UTF-8 file of at most 16 MiB, or a symbolic link in its path |
| `Export exceeds the verification limits and was not verified` | A limit in the table above |
| `Export or embedded native inventory failed verification` | Any other failure, including a malformed or conflicting document |
