# Inventory attestation

`nexus-symbiote attest` signs the exact bytes of a file for a stated purpose.
`nexus-symbiote verify-attestation` checks that signature against public keys you
trust. Inventories and baselines are written unsigned; signing is a separate, explicit
step. This page covers what an attestation establishes, key management, CI usage and
the exact format for interoperability with other DSSE tooling.

- [What an attestation establishes](#what-an-attestation-establishes)
- [Keys](#keys)
- [Walkthrough](#walkthrough)
- [Gate a pull request on an attested baseline](#gate-a-pull-request-on-an-attested-baseline)
- [Trusted keys](#trusted-keys)
- [Format](#format)
- [Verification order](#verification-order)
- [Reason codes](#reason-codes)
- [Limits](#limits)

## What an attestation establishes

A verified attestation establishes three facts:

- **These bytes.** With `--match bytes`, the default, the file has the SHA-256 that
  the attestation records. With `--match content`, the file is a native inventory
  whose [content digest](#content-digest) equals the recorded one: the same content,
  collected at another time or recording another collection time.
- **This purpose.** The signers chose `generated` ("I produced this file", such as a
  CI job signing what it built) or `reviewed` ("I reviewed this file as a
  baseline"). The verifier names the purpose it expects, and an attestation made for
  the other purpose fails.
- **These keys.** At least `--threshold` distinct keys from the set you trust signed
  it.

It also carries `signed_at`, the signing time by the signer's clock, and an optional
`source_revision`, a git commit ID the signer claims the file was produced from. The
source revision is not checked at all; `signed_at` is checked only against the
verifier's clock: it may be at most 5 minutes ahead and, with `--max-age-days`, no
older than that limit.

It does not establish:

- **That the inventory is accurate, complete or safe.** An attestation authenticates
  a file, not its claims (whether claims are declared, observed or verified is in the
  [security model](security-model.md)), and what the collectors cannot see stays unseen
  ([known limitations](known-limitations.md)). An attested inventory of an unsafe agent
  is an inventory of an unsafe agent.
- **That the file is the newest one.** An older file signed for the same purpose still
  verifies; replaying an old attested baseline is possible by design. Bound it with
  `--max-age-days`, record `--source-revision`, and keep
  attested baselines where the change under review cannot choose among them.
- **Who holds a key.** The tool checks signatures against the keys you name; issuing,
  protecting and retiring keys is your process.
- **That the file stays unchanged.** `verify-attestation` and a later command read the
  file separately. Run both in a workspace the change under review cannot write to.

## Keys

Attestations use Ed25519 keys. Create a pair with `runtime keygen` (mode 0600,
never overwrites):

```bash
nexus-symbiote runtime keygen --private-key reviewer.pem --public-key reviewer.pub
```

Add `--passphrase-file FILE` to encrypt the private key with the first line of a file
you own and that gives group and others no permission; `attest` then needs the same flag. `attest` refuses a private key or passphrase file that the user running it does
not own or that its group or others can access, even when running as root: a container
job cannot sign with a key mounted from the host and owned by another user.
`runtime key-id reviewer.pub` prints the key ID (lowercase hex SHA-256 of the DER
SubjectPublicKeyInfo). Use a key pair only for attestations — the runtime rings use one
key per purpose — and keep private keys away from jobs that run code from a pull
request: such code can sign whatever it likes with a key it can read.

The purpose is a signed field, not a property of the key: any trusted key can sign
either purpose. Trust different keys for each. A CI key for `generated` must not be
among the `--trusted-key` files you pass with `--purpose reviewed`, or a compromised
build could sign its own reviewed baseline.

## Walkthrough

From the repository root, this signs a collection of `examples/demo-agent` as
reviewed, verifies it, shows a tampered copy failing, and verifies a later collection
of the same content. It works in a new temporary directory, outside every git working
tree; see [trusted keys](#trusted-keys) for why that matters.

```bash
demo="$PWD/examples/demo-agent"
cd "$(mktemp -d)"
nexus-symbiote runtime keygen --private-key reviewer.pem --public-key reviewer.pub
nexus-symbiote scan "$demo" -o reviewed.json
nexus-symbiote attest reviewed.json --key reviewer.pem --purpose reviewed --out reviewed.json.att
```

`scan` reports its progress on standard error. `runtime keygen` and `attest` each
print one JSON line; key IDs and times differ on every run, and the digests are those
of this tree's scan of the demo:

```text
{"key_id": "5a8e304679c8aa4d4e0de8f09224ecc75b81b3923ef1897d3747ef1b9a614cc4", "encrypted": false}
{"out": "reviewed.json.att", "subject_sha256": "b441c1633703a9331df28dee1f88f3c2ceebffeb4aeda94d62a8d12171673137", "subject_format": "nexus-symbiote-aibom", "content_digest": "sha256:5260acfe902aeb58a16071cfb65b0bc1bdb47c929bbca0993018203470e2d61f", "purpose": "reviewed", "signers": ["5a8e304679c8aa4d4e0de8f09224ecc75b81b3923ef1897d3747ef1b9a614cc4"], "signed": true}
```

Verify it with the public key:

```bash
nexus-symbiote verify-attestation reviewed.json reviewed.json.att --trusted-key reviewer.pub --purpose reviewed
```

```text
Attestation verified: purpose reviewed, 1 trusted key. It does not establish that the file is accurate, complete or safe.
Signer key ID: 5a8e304679c8aa4d4e0de8f09224ecc75b81b3923ef1897d3747ef1b9a614cc4
Subject SHA-256: b441c1633703a9331df28dee1f88f3c2ceebffeb4aeda94d62a8d12171673137
Match: bytes
Subject format: nexus-symbiote-aibom 1.2.0
Content digest: sha256:5260acfe902aeb58a16071cfb65b0bc1bdb47c929bbca0993018203470e2d61f (nexus-symbiote/inventory-content/v1)
Signed at (signer's clock): 2026-11-27T12:22:02Z
```

Change one byte, the inventory's `version` from 1 to 2, and the same check fails with
exit status 1:

```bash
sed 's/"version": 1,/"version": 2,/' reviewed.json > tampered.json
nexus-symbiote verify-attestation tampered.json reviewed.json.att --trusted-key reviewer.pub --purpose reviewed
```

```text
Error: attestation verification failed: file does not match the attested subject (subject-mismatch)
```

A new collection of the unchanged project with the same release and options writes the
same bytes, so `--match bytes` verifies it as well. A collection that records when it
was made, such as one taken with `SOURCE_DATE_EPOCH` set (see
[reproducible inventories](reproducible-inventories.md)), has other bytes, and
`--match bytes` fails on it as on the tampered copy. Its content is the reviewed
content, which `--match content` checks:

```bash
SOURCE_DATE_EPOCH=1767225600 nexus-symbiote scan "$demo" -o candidate.json
nexus-symbiote verify-attestation candidate.json reviewed.json.att --trusted-key reviewer.pub --purpose reviewed --match content
```

```text
Attestation verified: purpose reviewed, 1 trusted key. It does not establish that the file is accurate, complete or safe.
Signer key ID: 5a8e304679c8aa4d4e0de8f09224ecc75b81b3923ef1897d3747ef1b9a614cc4
Subject SHA-256: b4a4fda5e8f928c00c683db76cd83c50127f9cd6d7c19af3b0ab81ef2903e470
Match: content; the attested file's SHA-256 is b441c1633703a9331df28dee1f88f3c2ceebffeb4aeda94d62a8d12171673137
Subject format: nexus-symbiote-aibom 1.2.0
Content digest: sha256:5260acfe902aeb58a16071cfb65b0bc1bdb47c929bbca0993018203470e2d61f (nexus-symbiote/inventory-content/v1)
Signed at (signer's clock): 2026-11-27T12:22:02Z
```

`--json-output` prints the same facts as one JSON object, with `subject_sha256` (the
file you passed), `attested_sha256` (the file that was signed), `subject_format`,
`spec_version`, `content_digest`, `content_profile`, `signed_at` and, when recorded,
`source_revision`.

## Gate a pull request on an attested baseline

The [drift gate](drift-gate.md) is only as strong as the baseline's provenance. An
attestation adds a check that a trusted key holder reviewed exactly that file,
independently of who can write to the branch or store that holds it.

A reviewer signs the baseline on a checkout of the protected base branch with a key
that never reaches CI, then commits both files through a reviewed pull request:

```bash
mkdir -p .nexus-symbiote
nexus-symbiote baseline . --no-project-policy -o .nexus-symbiote/reviewed.json
rm -f .nexus-symbiote/reviewed.json.att
nexus-symbiote attest .nexus-symbiote/reviewed.json --key ~/keys/reviewer.pem --purpose reviewed \
  --source-revision "$(git rev-parse HEAD)" --out .nexus-symbiote/reviewed.json.att
```

The pull-request job takes the reviewer's public key from an operator-controlled
setting (repository or organization variable, never from the checkout), reads the
baseline from the base commit, verifies it, and only then compares:

```bash
printf '%s\n' "$AGENTBOM_REVIEWER_PUBLIC_KEY" > "$RUNNER_TEMP/reviewer.pub"
git show "$BASE_SHA:.nexus-symbiote/reviewed.json" > "$RUNNER_TEMP/reviewed.json"
git show "$BASE_SHA:.nexus-symbiote/reviewed.json.att" > "$RUNNER_TEMP/reviewed.json.att"
nexus-symbiote verify-attestation "$RUNNER_TEMP/reviewed.json" "$RUNNER_TEMP/reviewed.json.att" \
  --trusted-key "$RUNNER_TEMP/reviewer.pub" --purpose reviewed --max-age-days 90
nexus-symbiote scan . --no-project-policy -o "$RUNNER_TEMP/agentbom.json"
nexus-symbiote diff "$RUNNER_TEMP/reviewed.json" "$RUNNER_TEMP/agentbom.json" --fail-on-alert
```

`verify-attestation` exits 1 on mismatch, wrong purpose, insufficient keys or age
over 90 days; a shell that stops at the first failure, such as GitHub's default
`bash -e`, then never runs `diff`. The same steps work for a baseline in an artifact
store. The rules for
[taking both snapshots the same way](drift-gate.md#take-both-snapshots-the-same-way)
still apply, as does protecting the workflow file.

For a stricter gate that fails on any change the inventory records, verify the new
collection against the reviewed attestation by content instead of running `diff`. It
fails on any change at all only when both collections were taken with the same
`NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`: without the key, a change only to a value the
inventory withholds and only the keyed binding covers, such as an `env` value, a
credential helper command, a command argument, an HTTP header value, or the content of
a prompt file whose content hash is withheld, leaves the content digest unchanged
([source binding](verification-source-binding.md)).

```bash
nexus-symbiote verify-attestation "$RUNNER_TEMP/agentbom.json" "$RUNNER_TEMP/reviewed.json.att" \
  --trusted-key "$RUNNER_TEMP/reviewer.pub" --purpose reviewed --match content
```

The content digest covers everything but the collection's serial number and times
(and, for an import, where the report was read from), including the tool version and the policy recorded in the metadata, so take the
reviewed and the new collection with the same release and the same options.

## Trusted keys

A trusted key is a trust anchor: whoever can write it decides which attestations
verify. `verify-attestation` refuses (exit 2) a `--trusted-key` inside a git working
tree (a directory with a `.git` entry, at any level) that also holds SUBJECT, ENVELOPE
or the current directory. The key's path and
device/inode of each parent directory are compared with each working tree, so another
name for the working-tree directory itself, such as symlinks, case variants and bind
mounts of the tree, does not hide the key. A key file with other hard links is refused
too.

A mount of a directory or file inside a working tree is not detected, because the key
then has a location outside the tree: `docker run -v "$PWD/keys:/keys" -v "$PWD:/work" ...`
accepts a committed key as `/keys/trusted.pub`. The rule catches misplacement, not
provenance — it does not authenticate the key. Provision keys from a place the change
under review cannot write, such as a CI variable, a secret store or a directory on the
runner outside the checkout.

On POSIX systems a trusted key must also be safe from replacement: owned by you or
root, group and others cannot write, and every parent directory up to the filesystem
root has the same constraints (sticky directories like `/tmp` are accepted). Whoever
can write a parent directory can swap the key. The same rule applies to `runtime`
public keys, `--operator-policy`, its `--operator-policy-attestation` keys and
`--signature-policy` files. Attestation commands report `key-invalid`; runtime
commands report through their own diagnostics.

Key files are read without following symlinks and with a size limit; FIFOs and devices
are refused. Each distinct key counts once, and `--threshold` may not exceed the
number of distinct keys.

## Format

An attestation is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope with
the same encoding as the [runtime contracts](runtime-contract-reference.md#envelope):
`payloadType` `application/vnd.in-toto+json`, a base64 `payload` (at most 1 MiB
decoded), and up to 32 `signatures`, each a `keyid` hint and `sig` (Ed25519 over the
DSSE pre-authentication encoding):

```text
"DSSEv1" SP "28" SP "application/vnd.in-toto+json" SP <decimal byte length of payload> SP <payload bytes>
```

`attest` writes indented JSON with signatures ordered by key ID.
`verify-attestation` reads at most 2 MiB of strict UTF-8 JSON using exactly the DSSE
member names (`keyid` may be omitted). Base64 accepts the standard or URL-safe
alphabet in canonical padded form only. A `keyid` naming a trusted key is tried with
that key only; others are tried against each trusted key, up to 64 verifications per
envelope.

The payload is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with exactly these members:

| Member | Value |
| --- | --- |
| `_type` | `https://in-toto.io/Statement/v1` |
| `subject` | Exactly one entry: `{"name": <file name>, "digest": {"sha256": <64 lowercase hexadecimal characters>}}` |
| `predicateType` | `https://github.com/Hunzee-VC/Nexus-Symbiote/attestation/inventory/v1` |
| `predicate` | The inventory predicate below |

The subject digest is the SHA-256 of the file's exact bytes. The name is informational:
control characters, format characters, default-ignorable code points and undecodable
bytes become U+FFFD, a U+FFFD after `##` breaks CI log commands, and it is cut to 255
characters. Verification does not compare it with the file name you pass.

Unlike the runtime contracts (whose subject is a contract digest), the subject here is
a file, as generic in-toto tooling expects. The predicate type names Hunzee-VC (the
repository's organization when the type was minted); the runtime contracts name
aisecnomad. Both are stable identifiers, not links, and do not change when the
repository moves.

The predicate:

| Field | Value |
| --- | --- |
| `version` | `"1"` |
| `purpose` | `"generated"` or `"reviewed"` |
| `signed_at` | Signing time in UTC, whole seconds, as `YYYY-MM-DDTHH:MM:SSZ` |
| `subject_format` | `"nexus-symbiote-aibom"` for a native inventory this build reads; `"other"` for anything else, such as a CycloneDX, SPDX or SARIF export |
| `spec_version` | The inventory's native format version, as this build reads it; only for `nexus-symbiote-aibom` |
| `content_digest` | `sha256:` and 64 lowercase hexadecimal characters; only for `nexus-symbiote-aibom` |
| `content_profile` | `"nexus-symbiote/inventory-content/v1"`; only for `nexus-symbiote-aibom` |
| `source_revision` | Optional: a git commit ID of 40 or 64 lowercase hexadecimal characters, the signer's claim |

No other field is accepted. Fields without a value are omitted, not `null`. The
predicate must be in exactly this form (`+00:00` for `Z` is refused), so one
attestation has one predicate encoding. The signer writes RFC 8785 canonical JSON; a
verifier accepts any strict JSON whose predicate matches this form.

### Content digest

The content digest is the SHA-256 of the RFC 8785 canonical JSON of the parsed
inventory without collection-event fields: `metadata.serial_number`,
`metadata.timestamp`, `metadata.completeness.timestamp`,
`metadata.completeness.source_report_path` and each component claim's `observed_at`,
each omitted only when it has the form the native format writes. Two collections of
the same content therefore have the same content digest.

`attest` decides `subject_format` from the bytes it signs: a strict JSON object of at
most 16 MiB, with arrays and objects nested at most 256 levels deep, that has a
`components` list and validates as a native inventory (a missing `metadata` is read as
an empty object) is `nexus-symbiote-aibom`; anything else is `other`. The depth bound
ensures the same bytes get the same answer on every interpreter. For a native subject,
verification recomputes the format version and content digest and requires both to
match.

### Checking an attestation without this tool

Any DSSE implementation can check the signature, and the rest is plain JSON. This
sketch needs only Python and the `cryptography` package; it checks one trusted key, the
statement type, the purpose and the subject digest, but not the other rules on this
page:

```python
import base64
import hashlib
import json

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.serialization import load_pem_public_key

PREDICATE = "https://github.com/Hunzee-VC/Nexus-Symbiote/attestation/inventory/v1"


def check(envelope_path, subject_path, public_key_path, purpose):
    with open(envelope_path, "rb") as stream:
        envelope = json.loads(stream.read().decode("utf-8"))
    if envelope["payloadType"] != "application/vnd.in-toto+json":
        raise ValueError("not an in-toto envelope")
    payload = base64.b64decode(envelope["payload"], validate=True)
    message = b"DSSEv1 28 application/vnd.in-toto+json %d %s" % (len(payload), payload)
    with open(public_key_path, "rb") as stream:
        key = load_pem_public_key(stream.read())
    for signature in envelope["signatures"]:
        try:
            key.verify(base64.b64decode(signature["sig"], validate=True), message)
            break
        except InvalidSignature:
            continue
    else:
        raise ValueError("no signature by the trusted key")
    statement = json.loads(payload)
    if statement["_type"] != "https://in-toto.io/Statement/v1":
        raise ValueError("not an in-toto statement")
    if statement["predicateType"] != PREDICATE or statement["predicate"]["purpose"] != purpose:
        raise ValueError("not an inventory attestation for this purpose")
    [subject] = statement["subject"]
    with open(subject_path, "rb") as stream:
        if subject["digest"]["sha256"] != hashlib.sha256(stream.read()).hexdigest():
            raise ValueError("the file is not the attested file")
    return statement["predicate"]
```

## Verification order

`verify-attestation` and `nexus_symbiote.attestation.verify_attestation` check, in
this order, and stop at the first failure:

1. The configuration: one or more distinct trusted Ed25519 keys, a `--threshold`
   between 1 and their number, a purpose, a match mode and a positive age limit.
2. The envelope: shape, member names and size limits.
3. At least `--threshold` distinct trusted keys signed the pre-authentication encoding
   of the exact payload bytes, before the payload is parsed. A key that signed twice
   counts once.
4. The payload is strict JSON with exactly the four statement members.
5. `_type` and `predicateType` are the values above.
6. The predicate validates and is in canonical form.
7. The subject is exactly one entry whose `digest` has exactly the member `sha256`,
   which equals the file's SHA-256 (`--match bytes`, compared in constant time); or the
   predicate records a content digest and the file is a native inventory with that
   format version and content digest (`--match content`).
8. The purpose is the expected one.
9. `signed_at` is at most 5 minutes after the current time and, with
   `--max-age-days`, at most that many days before it.
10. For a native subject matched by bytes, the format version and content digest
    recomputed from the file equal the recorded ones.

## Reason codes

A refused attestation ends with `attestation verification failed:` (or
`attestation signing failed:`), a fixed message and a code in parentheses (exit 1).
`AttestationError.reason` carries the same codes. Messages never quote files, envelopes
or keys.

| Code | Meaning |
| --- | --- |
| `configuration-invalid` | Signers, trusted keys, threshold, purpose, match mode or age limit are invalid |
| `input-unreadable` | The subject, envelope, key or passphrase file is not a readable regular file reached without symbolic links |
| `input-too-large` | An input file exceeds its limit: 64 MiB for a subject, 2 MiB for an envelope, 64 KiB for a key, 4 KiB for a passphrase file |
| `key-invalid` | A key or passphrase file was refused, for example a private key that the user running the command does not own or that gives its group or others any permission, an encrypted key without `--passphrase-file`, or a key that is not Ed25519 |
| `envelope-invalid` | The envelope is not a DSSE envelope in the form above |
| `statement-too-large` | The statement exceeds 1 MiB |
| `signers-insufficient` | Fewer than `--threshold` distinct trusted keys signed the payload |
| `statement-invalid` | The payload is not strict JSON, or not a statement with exactly the members and one subject above |
| `statement-purpose-mismatch` | The statement is not an inventory attestation, such as a runtime contract |
| `predicate-invalid` | The predicate does not validate |
| `predicate-not-canonical` | The predicate is not in canonical form |
| `subject-mismatch` | The file's bytes, or with `--match content` its content, differ from the attested ones |
| `subject-not-inventory` | The file is not a native inventory this build reads, but the check needs its content |
| `purpose-mismatch` | The attestation was signed for the other purpose |
| `attestation-not-yet-valid` | `signed_at` is more than 5 minutes after the current time |
| `attestation-expired` | `signed_at` is more than `--max-age-days` days before the current time |
| `content-digest-unavailable` | `--match content` was requested, but the attestation records no content digest |

Usage errors exit 2: missing or unknown options, nonexistent files, `--threshold`
above distinct key count, malformed `--source-revision`, duplicate signing keys,
`--out` naming the subject, and a trusted key in a [forbidden location](#trusted-keys).
An existing `--out` is refused (exit 1); nothing is written.

## Limits

- **Ed25519 keys only.** PEM key files. KMS/HSM signers use `sign_statement` with the
  `ContractSigner` interface.
- **No transparency log, no keyless signing.** Sigstore and OIDC-based signing are not
  supported.
- **No revocation list.** Retire a key by removing it from the trusted set; every
  attestation it made then stops verifying wherever that set is used.
- **No freshness.** An older attested file still verifies. Use `--max-age-days`,
  `source_revision` and your review process.
- **Separate reads.** Verification and later commands read the file separately.
- **Signer's clock.** `signed_at` comes from the signer; backdating is possible.
- **Format compatibility.** Verification recomputes format version and content digest,
  even with `--match bytes`. A build that cannot read the format refuses with
  `subject-not-inventory`.
- **Deeply nested inventories are `other`.** Over 256 levels of nesting means no
  content digest and no `--match content`.
- **Trusted-key rule checks placement only.** It does not authenticate keys or follow
  keys mounted out of the checkout.
- **The GitHub Action does not sign or verify attestations yet.** Run the commands in
  a workflow step.
- **POSIX only.** Owner/mode checks and no-symlink reads need POSIX file APIs.
