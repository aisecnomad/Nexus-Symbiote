# Inventory attestation

`nexus-symbiote attest` signs the exact bytes of a file, usually an inventory or a
reviewed baseline, for a purpose you state, and `nexus-symbiote verify-attestation`
checks that signature against public keys you trust. Inventories and baselines are
still written unsigned; signing is a separate, explicit step that a key holder takes.
This page says what an attestation establishes and what it does not, how to make keys,
how to use attestations in CI, and the exact format, so that other DSSE tooling can
check one.

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
  a file. The claims inside keep the assurance they were recorded with (declared,
  observed or verified; see the [security model](security-model.md)), and what the
  collectors cannot see stays unseen ([known limitations](known-limitations.md)).
  An attested inventory of an unsafe agent is an inventory of an unsafe agent.
- **That the file is the newest one.** An older file that the same keys signed for
  the same purpose still verifies; replaying an old attested baseline is possible
  by design. Bound it with `--max-age-days`, record `--source-revision`, and keep
  attested baselines where the change under review cannot choose among them.
- **Who holds a key.** The tool checks signatures against the keys you name; issuing,
  protecting and retiring keys is your process.
- **That the file stays unchanged.** `verify-attestation` and a later command, such
  as `diff`, read the file separately. Run both in a workspace that the change under
  review cannot write between the two steps.

## Keys

Attestations use Ed25519 keys. Create a pair with `runtime keygen`; both files are
created with mode 0600, and existing files are never overwritten:

```bash
nexus-symbiote runtime keygen --private-key reviewer.pem --public-key reviewer.pub
```

Add `--passphrase-file FILE` to encrypt the private key with the first line of a file
you own and that gives group and others no permission; `attest` then needs the same `--passphrase-file`.
`attest` refuses a private key or passphrase file that the user running it does not
own, or that its group or others can access, also when it runs as root: a container
job cannot sign with a key mounted from the host and owned by another user.
`runtime key-id reviewer.pub` prints the key ID, the lowercase hexadecimal SHA-256 of
the key's DER SubjectPublicKeyInfo, which `attest` and `verify-attestation` print. Use
a key pair only for attestations, as the runtime rings use one key per purpose, and
keep private keys away from jobs that run code from a pull request: such code can sign
whatever it likes with a key it can read.

The purpose is a signed field, not a property of the key: any key you trust can sign
either purpose. Trust different keys for each. A key that CI holds to sign what it
`generated` must not be among the `--trusted-key` files you pass with
`--purpose reviewed`, or a compromised build could sign its own reviewed baseline.

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
{"key_id": "04dd7d9aae8c50a5198c1d0afb768051addeda362dfcdf2d795fd36258205f39", "encrypted": false}
{"out": "reviewed.json.att", "subject_sha256": "106b5dee4516a7e8f2ffc109c9baa0f9cce61f6edddfbadf60d8c802caffaa6c", "subject_format": "nexus-symbiote-aibom", "content_digest": "sha256:f17c7343b1217b4908030a5a088ad1f2b20918cd495431fda5ce0e9f253a1231", "purpose": "reviewed", "signers": ["04dd7d9aae8c50a5198c1d0afb768051addeda362dfcdf2d795fd36258205f39"], "signed": true}
```

Verify it with the public key:

```bash
nexus-symbiote verify-attestation reviewed.json reviewed.json.att --trusted-key reviewer.pub --purpose reviewed
```

```text
Attestation verified: purpose reviewed, 1 trusted key. It does not establish that the file is accurate, complete or safe.
Signer key ID: 04dd7d9aae8c50a5198c1d0afb768051addeda362dfcdf2d795fd36258205f39
Subject SHA-256: 106b5dee4516a7e8f2ffc109c9baa0f9cce61f6edddfbadf60d8c802caffaa6c
Match: bytes
Subject format: nexus-symbiote-aibom 1.1.0
Content digest: sha256:f17c7343b1217b4908030a5a088ad1f2b20918cd495431fda5ce0e9f253a1231 (nexus-symbiote/inventory-content/v1)
Signed at (signer's clock): 2026-11-12T11:09:57Z
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
Signer key ID: 04dd7d9aae8c50a5198c1d0afb768051addeda362dfcdf2d795fd36258205f39
Subject SHA-256: 32c56688a31252e03188d7d1b1f04387c85f2a3000f7316031fbc9a0693a0a02
Match: content; the attested file's SHA-256 is 106b5dee4516a7e8f2ffc109c9baa0f9cce61f6edddfbadf60d8c802caffaa6c
Subject format: nexus-symbiote-aibom 1.1.0
Content digest: sha256:f17c7343b1217b4908030a5a088ad1f2b20918cd495431fda5ce0e9f253a1231 (nexus-symbiote/inventory-content/v1)
Signed at (signer's clock): 2026-11-12T11:09:57Z
```

`--json-output` prints the same facts as one JSON object, with `subject_sha256` (the
file you passed), `attested_sha256` (the file that was signed), `subject_format`,
`spec_version`, `content_digest`, `content_profile`, `signed_at` and, when recorded,
`source_revision`.

## Gate a pull request on an attested baseline

The [drift gate](drift-gate.md) compares a reviewed baseline with a new collection,
and is only as strong as the place the baseline comes from. An attestation adds a
check that a key holder you trust reviewed exactly that file, independently of who
can write to the branch or store that holds it.

A reviewer approves a baseline on a checkout of the protected base branch and signs it
with a key that never reaches CI, then commits both files through a reviewed pull
request:

```bash
mkdir -p .nexus-symbiote
nexus-symbiote baseline . --no-project-policy -o .nexus-symbiote/reviewed.json
rm -f .nexus-symbiote/reviewed.json.att
nexus-symbiote attest .nexus-symbiote/reviewed.json --key ~/keys/reviewer.pem --purpose reviewed \
  --source-revision "$(git rev-parse HEAD)" --out .nexus-symbiote/reviewed.json.att
```

The pull-request job takes the reviewer's public key from an operator-controlled
setting, such as a repository or organization variable, never from the checkout. It
reads the baseline and its attestation from the base commit, verifies them, and only
then compares:

```bash
printf '%s\n' "$AGENTBOM_REVIEWER_PUBLIC_KEY" > "$RUNNER_TEMP/reviewer.pub"
git show "$BASE_SHA:.nexus-symbiote/reviewed.json" > "$RUNNER_TEMP/reviewed.json"
git show "$BASE_SHA:.nexus-symbiote/reviewed.json.att" > "$RUNNER_TEMP/reviewed.json.att"
nexus-symbiote verify-attestation "$RUNNER_TEMP/reviewed.json" "$RUNNER_TEMP/reviewed.json.att" \
  --trusted-key "$RUNNER_TEMP/reviewer.pub" --purpose reviewed --max-age-days 90
nexus-symbiote scan . --no-project-policy -o "$RUNNER_TEMP/agentbom.json"
nexus-symbiote diff "$RUNNER_TEMP/reviewed.json" "$RUNNER_TEMP/agentbom.json" --fail-on-alert
```

`verify-attestation` exits 1 when the baseline is not the attested file, was signed
for another purpose, by too few trusted keys or more than 90 days ago; a shell that
stops at the first failure, such as GitHub's default `bash -e`, then never runs
`diff`. The same steps work for a baseline kept in an artifact store. The rules for
taking both snapshots the same way still apply
([take both snapshots the same way](drift-gate.md#take-both-snapshots-the-same-way)),
and so does protecting the workflow file itself.

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
verify. `verify-attestation` therefore refuses, as a usage error with exit status 2, a
`--trusted-key` file that lies inside a git working tree (a directory with a `.git`
entry, at any level) that also holds SUBJECT, ENVELOPE or the current directory. The
key's path, and the device and inode of each directory above it, are compared with each
such working tree, so another name for the working-tree directory itself, such as a
symbolic link, a case variant or a bind mount of the tree, does not hide the key, and a
key file with other hard links is refused too. A mount of a directory or file inside a
working tree is not detected, because the key then has a location outside the tree:
with `docker run -v "$PWD/keys:/keys" -v "$PWD:/work" ...`, a key committed under
`keys/` reaches the job as `/keys/trusted.pub` and is accepted. The rule catches
misplacement, such as a key committed to the repository under review and passed by its
path in the checkout; it does not authenticate the key, and it cannot follow a key
copied or mounted out of the checkout. Provision keys from a place the change under
review cannot write, such as a CI variable, a secret store or a directory on the runner
outside the checkout.

On POSIX systems a trusted key must also be one that no other user can replace: a file
owned by you or root that its group and others cannot write, in directories, up to the
file system root, that are owned by you or root and that their group and others cannot
write unless the directory is sticky, as `/tmp` is. Whoever can write a directory above
the key can rename the directory below it away and put another key in its place. The
same rule applies to `runtime` public keys, `--operator-policy`, its
`--operator-policy-attestation` keys and `--signature-policy` files. A key that breaks it
fails verification with the `key-invalid` reason.

Like every input, a key file is read without following symbolic links and with a size
limit; FIFOs and devices are refused. Each distinct key counts once: two copies of the
same key are one trusted key, and `--threshold` may not exceed the number of distinct
keys.

## Format

An attestation is a [DSSE](https://github.com/secure-systems-lab/dsse) envelope with
the same encoding as the runtime contracts' ([envelope](runtime-contract-reference.md#envelope)):
`payloadType` `application/vnd.in-toto+json`, a base64 `payload` of at most 1 MiB once
decoded, and up to 32 `signatures`, each a `keyid` (a hint: the key ID above) and a
`sig`, the base64 Ed25519 signature over the DSSE pre-authentication encoding:

```text
"DSSEv1" SP "28" SP "application/vnd.in-toto+json" SP <decimal byte length of payload> SP <payload bytes>
```

`attest` writes the envelope as indented JSON with signatures ordered by key ID.
`verify-attestation` reads at most 2 MiB of strict UTF-8 JSON that uses exactly the
DSSE member names `payloadType`, `payload`, `signatures`, `keyid` and `sig` (`keyid`
may be omitted). Base64 may use the standard or the URL-safe alphabet, in canonical
padded form only. A signature whose `keyid` names a trusted key is tried with that key
only; any other is tried against each trusted key, and a verifier stops after 64
signature verifications per envelope, as for the runtime contracts.

The payload is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with exactly these members:

| Member | Value |
| --- | --- |
| `_type` | `https://in-toto.io/Statement/v1` |
| `subject` | Exactly one entry: `{"name": <file name>, "digest": {"sha256": <64 lowercase hexadecimal characters>}}` |
| `predicateType` | `https://github.com/Hunzee-VC/Nexus-Symbiote/attestation/inventory/v1` |
| `predicate` | The inventory predicate below |

The subject digest is the SHA-256 of the file's exact bytes, and it is the binding. The
name is the file's base name for information only: characters that could rewrite or
disguise terminal or CI output (controls, line breaks, format characters and every other
default-ignorable code point, such as variation selectors and blank fillers) and
undecodable bytes are replaced with U+FFFD, a U+FFFD after the `##` breaks a
`##name[` CI log command, and it is cut to 255 characters. Verification does not compare
it with the file name you pass. Unlike the runtime contracts, whose subject is a
contract digest, the subject here is a file, as generic in-toto tooling expects. The
predicate type names the Hunzee-VC organization, which owned the repository when the
type was minted; the runtime contracts' predicate types name aisecnomad. Both are
stable type identifiers, not links, and do not change when the repository moves.

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

No other field is accepted, a field without a value is omitted rather than `null`, and
the predicate must be in exactly this form: another spelling of the same time, such as
`+00:00` for `Z`, is refused, so one attestation has one predicate encoding. The signer
writes the payload as RFC 8785 canonical JSON; a verifier accepts any strict JSON
serialization (no duplicate keys, `NaN` or `Infinity`) whose predicate is in this form.

### Content digest

The content digest is the SHA-256 of the RFC 8785 canonical JSON of the parsed
inventory without the fields that record the collection event:
`metadata.serial_number`, `metadata.timestamp`, `metadata.completeness.timestamp`,
`metadata.completeness.source_report_path` and the `observed_at` of each component
claim, each left out only when it has the form the native format writes. Two collections of the same content therefore have the same
content digest. `attest` decides `subject_format` from the bytes it signs: a strict
JSON object of at most 16 MiB, with arrays and objects nested at most 256 levels deep,
that has a `components` list and validates as a native inventory is
`nexus-symbiote-aibom` (a missing `metadata` is read as an empty object, as every
command reads it); anything else, including a native format version this build
cannot read, is `other`. The depth bound is part of the rule so that the same bytes get
the same answer on every interpreter and through every entry point; a more deeply
nested inventory that other commands still read is `other` here. For a native subject,
verification recomputes the format version and the content digest from the file and
requires both to equal the recorded ones.

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

A refused attestation or input ends with `attestation verification failed:` (or
`attestation signing failed:`), a fixed message and one of these codes in parentheses,
with exit status 1; usage errors and an `--out` that cannot be written are reported as
for every command, as described below the table. `AttestationError.reason` carries the
same codes. The message never quotes the file, the envelope or a key.

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

Usage errors exit with status 2: a missing or unknown option, a SUBJECT, ENVELOPE or key
file that does not exist, a `--threshold` above the number of distinct trusted keys, a
malformed `--source-revision`, the same signing key given twice, an `attest --out`
that names the subject, and a trusted key kept where the [trusted keys](#trusted-keys)
rule forbids. An `--out` that already exists is refused with exit status 1, and
nothing is written.

## Limits

- **Ed25519 keys only.** The commands load PEM key files. A KMS or HSM signer can be
  used through the library's `sign_statement`, which accepts any object with the
  runtime contracts' `ContractSigner` methods.
- **No transparency log, no keyless signing.** Attestations are not recorded in a
  public log, and Sigstore or other OIDC-based signing is not supported.
- **No revocation list.** Retire a key by removing it from the trusted set; every
  attestation it made then stops verifying wherever that set is used.
- **No freshness.** Nothing binds an attestation to the newest inventory or to a
  serial, so an older attested file for the same purpose still verifies. Use
  `--max-age-days`, `source_revision` and your review process.
- **Separate reads.** Verification and a later command read the file separately; see
  [what an attestation establishes](#what-an-attestation-establishes).
- **The signing time is the signer's.** `signed_at` comes from the signer's clock; a
  signer can date an attestation in the past.
- **The verifying build must read the inventory's format.** An attestation of a native
  inventory records its format version and content digest, and verification
  recomputes both, even with `--match bytes`. A build that cannot read that format
  version refuses the attestation with `subject-not-inventory`; verify it with a build
  that reads the format.
- **Deeply nested inventories are `other`.** An inventory whose arrays and objects nest
  more than 256 levels deep is attested by its bytes only, without a content digest,
  so `--match content` cannot be used for it; see [content digest](#content-digest).
- **The trusted-key rule checks placement only.** It does not authenticate a key, and
  it cannot follow a key copied or mounted out of the checkout; see
  [trusted keys](#trusted-keys).
- **The GitHub Action does not sign or verify attestations yet.** Run the commands in
  a workflow step.
- **POSIX only.** The owner and mode checks on private keys and the reads that follow
  no symbolic link need POSIX file APIs.
