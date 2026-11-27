# Reproducible inventories

Scan one checkout twice and get the same inventory: SymBiote records no collection time
unless asked, writes components and dependencies sorted, and derives the serial number
from the content. This page covers the fields that record the collection event, the
content digest that leaves them out, and how `SOURCE_DATE_EPOCH` records a collection
time while keeping files byte-identical.

- [What differs between two collections](#what-differs-between-two-collections)
- [The content digest](#the-content-digest)
- [The serial number](#the-serial-number)
- [Byte-identical files with `SOURCE_DATE_EPOCH`](#byte-identical-files-with-source_date_epoch)
- [Example](#example)
- [Limits](#limits)

## What differs between two collections

An inventory records paths relative to the scanned directory. Two scans of the same
checkout, with the same tool and settings, differ only in fields that record the
collection event:

| Field | What a scan writes |
|---|---|
| `metadata.serial_number` | `urn:uuid:` and a version 5 UUID of the content digest (see [the serial number](#the-serial-number)) |
| `metadata.timestamp` | Nothing; with `SOURCE_DATE_EPOCH` set, that instant |
| `metadata.completeness.timestamp` | The same as `metadata.timestamp` |
| `components[].claims.<name>.observed_at` | The same, in each claim a collector attached |
| `metadata.completeness.source_report_path` | Only with a ShadowScan report: where it was read from, relative to the scanned directory for `scan`, and its file name for `import-shadowscan` |

`import-shadowscan` writes the serial number, `metadata.timestamp` and the report's
file name; its records carry no collection times.

Two scans of the same checkout therefore write byte-identical native JSON and CycloneDX
files, with the same SHA-256 and canonical digest. SPDX requires a creation time, so
without a recorded one the export writes the current time as `CreationInfo.created`, and
two SPDX files differ in that field only. SARIF writes `endTimeUtc` only when the
inventory records a time; its file locations depend on the working directory
(see [below](#byte-identical-files-with-source_date_epoch)). Two imports of one report
under different file names differ in `source_report_path` but not in their content digest
or serial number.

## The content digest

`nexus-symbiote digest` prints the content digest as `content_digest`, and its profile,
`nexus-symbiote/inventory-content/v1`, as `content_profile`; see the
[CLI reference](cli-reference.md#digest). It is the SHA-256 of the RFC 8785 canonical
JSON of the native document as parsed from the file, with these fields left out:

- `metadata.serial_number`, when it is null or a `urn:uuid:` URN in lower-case
  hexadecimal;
- `metadata.completeness.source_report_path`, when it is a string: where an imported
  report was read from is not part of what it records;
- `metadata.timestamp`, `metadata.completeness.timestamp` and the `observed_at` of each
  component claim, when null or an RFC 3339 timestamp of the form
  `YYYY-MM-DDThh:mm:ss`, with up to nine digits of fractional seconds, and `Z` or a
  `+hh:mm` or `-hh:mm` offset.

A field is left out only at that location, only when the object that holds it is a
JSON object, and only when its value has that shape. Everything else is content:

- a key with one of these names anywhere else, such as in `properties`, in a dependency
  edge or in a deployment profile, so that a change cannot hide behind a field that is
  merely named like a collection event;
- any other value at these locations, such as a timestamp without a time of day;
- the order of every list, `components` and `dependencies` included (this build writes
  both sorted; see [limits](#limits));
- the tool version, the governing policy and its relaxations, and the whole coverage
  record.

The document must be a JSON object with a `components` list. A document without a
`metadata` key is read, as every command reads it, with an empty `metadata` object, so
it has the content digest of the same document with `"metadata": {}`.
The digest covers the document as it is in the file: reading an inventory into the
model and writing it again can fill in defaults and rewrite timestamps, which makes a
different document. A change to what is left out is a new profile version; the
known-answer vectors in `tests/vectors/inventory-content-v1.json` pin this one.

Equal content digests establish that two documents record the same content, field for
field, apart from when and in which run each was collected. They do not establish who
produced either file, that either is genuine or complete, or that what they record is
safe: a forged inventory that copies a genuine one's content has the same content
digest. Compare content digests of inventories from sources you trust, and use the
SHA-256 of the file to name an exact file.

## The serial number

When an inventory is written without a serial number (`scan`, `baseline` and
`import-shadowscan`), SymBiote sets `metadata.serial_number` to `urn:uuid:` followed by
the version 5 UUID of the content digest, as `digest` prints it, in namespace
`ccaa2a43-8ba9-58e6-8f22-f8793a2039d5`. The serial number is not content, so anyone who
holds the native JSON file can recompute it from that file. Two inventories of the same
content have the same serial number, whatever instant each records. CycloneDX and SPDX
exports carry the same serial number. It is a name, not a digest: compare content
digests to compare content.

An inventory whose content digest cannot be computed, because it holds a value outside
the I-JSON domain, such as a lone surrogate, or nests too deeply, has no serial number
and is not written: `scan` and `import-shadowscan` exit 1.

## Byte-identical files with `SOURCE_DATE_EPOCH`

Set `SOURCE_DATE_EPOCH` to a whole number of seconds since 1970-01-01T00:00:00Z (1 to
12 ASCII digits, at most 253402300799). `scan`, `baseline` and `import-shadowscan` then
record that instant as `metadata.timestamp` and, for a scan, in every other time field
above. The serial number does not change: recorded time is not content.

CycloneDX writes that instant as `metadata.timestamp` and SPDX as
`CreationInfo.created`, so the same inputs give byte-identical native JSON, CycloneDX
and SPDX files, and `vex` gives identical documents for them. SARIF records file
locations relative to the working directory when the
scanned directory lies below it, and relative to the scanned directory otherwise. Two
SARIF files are identical when the scanned directory is at one path below the working
directory in both scans, or below it in neither: a scan from inside the scanned
directory (as CI and pre-commit hooks do) and a scan of a directory elsewhere record
the same locations.

Any other value (empty, signed, fractional, hexadecimal, with spaces, over 12 digits,
or past year 9999) is a usage error (exit 2) before anything is collected. Without the
variable, an inventory records no collection time.

No gate and no other command reads the variable:

- Gates keep using the clock. An expired suppression stays expired whatever instant
  the inventory records: `SOURCE_DATE_EPOCH` is often a commit time, which whoever
  makes the commit can choose.
- `discover-mcp --record` and `verify-live --record` record when they observed the
  server.

The release workflow exports the variable, set to the commit time, for its whole build
job. The `project.cdx.json` it publishes as release evidence therefore records the
commit time as its collection time; its serial number is derived from its content; see
[releasing](releasing.md#what-the-pipeline-guarantees).

## Example

From the repository root, without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` in the
environment:

```console
$ demo="$PWD/examples/demo-agent"
$ cd "$(mktemp -d)"
$ export SOURCE_DATE_EPOCH=1767225600
$ cp -R "$demo" first && mkdir -p ci/work && cp -R "$demo" ci/work/second
$ nexus-symbiote scan first -o first.json 2>/dev/null
$ nexus-symbiote scan ci/work/second -o second.json 2>/dev/null
$ cmp first.json second.json && echo identical
identical
$ nexus-symbiote digest first.json
file_sha256: sha256:e8f93b6a16e2e5f81b76c6d7ade0b59d5bb8562c3202266b8fa61729653090a2
canonical_digest: sha256:0b0e7717ef4a93113a6b5e6f121bf71bb855a012b39210b3bdf3df299d693443
content_digest: sha256:bc26815126bdb9db4b6fe47326d0c6b0b555e22a7a75c59d880bf0345364dcea
content_profile: nexus-symbiote/inventory-content/v1
spec_version: 1.1.0
components: 11
```

Without the variable, a scan records no collection time, so its file differs from the
pinned one, but its content digest and serial number are the same, and a second scan
writes the same bytes:

```console
$ unset SOURCE_DATE_EPOCH
$ nexus-symbiote scan "$demo" -o now.json 2>/dev/null
$ cmp -s first.json now.json || echo different
different
$ nexus-symbiote digest now.json --json-output | grep content_digest
  "content_digest": "sha256:bc26815126bdb9db4b6fe47326d0c6b0b555e22a7a75c59d880bf0345364dcea",
$ grep serial_number first.json now.json
first.json:    "serial_number": "urn:uuid:1d14059c-655f-56cc-8ede-30d30f691821",
now.json:    "serial_number": "urn:uuid:1d14059c-655f-56cc-8ede-30d30f691821",
$ nexus-symbiote scan "$demo" -o again.json 2>/dev/null
$ cmp now.json again.json && echo identical
identical
```

These are the digests of this tree's scan of the demo; a release that records anything
differently prints others. `tests/test_reproducible_inventory.py` checks this page
against the current tree.

## Limits

- **Content can change for reasons other than the checkout.** The tool version,
  governing policy, selected collectors (`--scanner`),
  [collection limits](collection-limits.md), and `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`
  ([source binding](verification-source-binding.md)) are
  all content. Take compared inventories the same way; see
  [take both snapshots the same way](drift-gate.md#take-both-snapshots-the-same-way).
- **List order is content.** This build writes components and dependencies sorted, and
  exports embed the native document as written. A document written by another build, or
  edited by hand, with lists in a different order has a different content digest than its
  sorted rewrite; its serial number may also differ.
- **SARIF locations depend on the working directory**, as described above.
- **A document nested deeper than 128 levels is not read by the shared reader.**
  Commands that read through `AIBOM.load` (`diff`, `validate`, `risk`, `summary`,
  `graph`, `digest`, `export-inventory`, etc.) refuse one whose arrays and objects nest
  more than 128 levels, the root counted, with "inventory nests deeper than 128 levels";
  the bound is fixed, so what one reads, every one reads. Four
  commands do not apply the bound: `verify-discovery` and `verify-live` read the
  inventory with the strict JSON parser and the schema, so they read a document at 129
  or 257 levels and refuse one at ~1,000; `attest` records a subject up to 256 levels as
  a native inventory with a content digest, and a deeper one as `other` without one,
  which `verify-attestation` then verifies only by its bytes (`--match content` exits
  with `content-digest-unavailable`). A collected inventory nests far less.
- **A readable inventory can lack a digest.** A document without a `components` list
  has no content digest. A runtime snapshot binds a document only when its compact JSON,
  with every character outside ASCII escaped and each number counted as 24 bytes, is at
  most 16 MiB, it holds at most 1,000,000 values and no value is nested more than 64
  levels deep; otherwise it has no canonical digest. `digest` prints `unavailable` for a
  missing digest and exits 1.
- **File names are input.** An inventory records names as the OS lists them, so a
  checkout whose names differ between machines (e.g. after Unicode normalization) records
  different paths.
- **One collection bound counts time.** The mcp collector holds TypeScript/JavaScript
  parses to 250 ms of processor time. A busy machine does not reach it sooner, but a
  slower one does, so scans on machines of different speed can record different failure
  reasons for unparseable files; neither inventories the file. See
  [the TypeScript parse time limit](collection-limits.md#the-typescript-parse-time-limit).
- **A digest is not a signature.** No digest on this page says who wrote a file.
