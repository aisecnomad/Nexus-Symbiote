# Runtime contract reference

This page specifies the signed runtime contracts that `nexus_symbiote.runtime`
issues and checks: the envelope and statement format, every contract field, the
digests that bind contracts together, the order in which `ReferenceGateway` checks
evidence, every reason code, the state store, the key lifecycle, and what an
integrator must build to mediate tool calls. A second implementation can be
written from this page and checked against the known-answer vectors in
[`tests/vectors/runtime/contracts.json`](../tests/vectors/runtime/contracts.json).
[Runtime assurance](runtime-assurance.md) describes the security boundary and how
to operate the gateway.

- [Envelope](#envelope)
- [Statement](#statement)
- [Canonical form and digests](#canonical-form-and-digests)
- [Contracts](#contracts)
- [Endpoint identities](#endpoint-identities)
- [Tool definition digest](#tool-definition-digest)
- [Input schema evaluation](#input-schema-evaluation)
- [Verification order](#verification-order)
- [Reason codes](#reason-codes)
- [Gateway configuration](#gateway-configuration)
- [State store](#state-store)
- [Key lifecycle](#key-lifecycle)
- [What an integrator must provide](#what-an-integrator-must-provide)
- [Worked example](#worked-example)
- [Compatibility](#compatibility)

## Envelope

Every contract travels in a DSSE envelope, serialized as JSON:

| Field | Value |
| --- | --- |
| `payloadType` | Always `application/vnd.in-toto+json` |
| `payload` | Base64 of the statement bytes, at most 1 MiB once decoded |
| `signatures` | 0 to 32 entries, each `{"keyid": ..., "sig": ...}` |
| `signatures[].keyid` | Optional hint: the key ID of the signing key, as defined below |
| `signatures[].sig` | Base64 of a 64-byte Ed25519 signature |

`payload` and `sig` accept the standard or the URL-safe base64 alphabet, as DSSE
allows, but only in canonical, padded form: one alphabet per value, no line
breaks, and zero padding bits. Parsing normalizes both to the standard alphabet,
so one signed payload has exactly one envelope encoding per signature set.

Each signature covers the DSSE pre-authentication encoding of the payload:

```text
"DSSEv1" SP "28" SP "application/vnd.in-toto+json" SP <decimal byte length of payload> SP <payload bytes>
```

A key ID is the lowercase hexadecimal SHA-256 of the key's DER-encoded
SubjectPublicKeyInfo (`runtime key-id key.pub` prints it). A verifier tries a
signature whose `keyid` names a trusted key with that key only; a signature
without a `keyid`, or with a hint the ring does not contain, is tried against
each trusted key, so signatures from DSSE tools with another key ID convention
still verify. A verifier stops after 64 signature verifications per envelope,
and each trusted key counts once towards a quorum however often it signed.

## Statement

The payload is an [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md)
with exactly these four members; any other member is rejected:

| Member | Value |
| --- | --- |
| `_type` | `https://in-toto.io/Statement/v1` |
| `predicateType` | The predicate type of the contract's purpose, below |
| `subject` | Exactly `[{"name": <purpose>, "digest": {"sha256": <hex of the contract digest>}}]` |
| `predicate` | The contract, in canonical contract form |

The purpose is one of `snapshot`, `approval`, `trust` and `model`. The predicate
types end in `/approved-snapshot/v1`, `/action-approval/v1`, `/trust-status/v1`
and `/hosted-model/v1`. The prefix is the project's original GitHub namespace,
kept because every signature binds it; the identifiers do not resolve to
documents. `nexus_symbiote.runtime.PREDICATES` holds the exact strings and the
vector file shows each one in a signed statement. The payload must be strict
JSON: duplicate keys, `NaN` and `Infinity` are rejected. The signer here emits
RFC 8785 bytes; a verifier accepts any strict serialization whose predicate is in
canonical contract form.

## Canonical form and digests

A digest is `sha256:` followed by the lowercase hexadecimal SHA-256 of the
[RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JSON Canonicalization Scheme)
serialization of a JSON value. Values must stay inside the I-JSON domain:
integers between -(2^53 - 1) and 2^53 - 1, finite numbers, and strings without
lone surrogates. In RFC 8785, `1` and `1.0` are the same number.

The canonical contract form is the JSON form of the contract model with every
field present, defaults included, and timestamps in UTC written as
`YYYY-MM-DDTHH:MM:SSZ`, or with six fractional digits when there are
microseconds. A predicate in any other form, such as a `+00:00` offset or an
omitted default, is rejected, so one contract has exactly one digest.
`sign_contract` refuses a contract object that is not in canonical form, such as
a `model_copy` that holds a non-UTC timestamp; `runtime sign` reads JSON,
validates it and signs the canonical form.

| Digest | Preimage | Command | Python |
| --- | --- | --- | --- |
| Contract digest | The canonical contract | `runtime digest FILE --kind snapshot` (or `approval`, `trust`, `model`) | `contract_digest(contract)` |
| Context digest | The `ExecutionContext` | `runtime digest FILE --kind context` | `contract_digest(context)` |
| Request digest | The `ToolCall`, arguments included | `runtime digest FILE --kind request` | `request_digest(call)` |
| BOM digest | The companion AgentBOM document | `runtime digest FILE --kind bom` | `bom_digest(bom)` |
| Tool definition digest | The served descriptor, see below | `runtime digest FILE --kind tool` | `tool_definition_digest(descriptor)` |

`runtime digest` verifies nothing and works for contracts that are not yet valid
or have expired. `runtime sign` and `runtime verify` print the contract digest
too. A companion BOM is bounded to 16 MiB of JSON, 1,000,000 values and 64
levels before it is hashed.

## Contracts

Every contract has a validity window: `not_before` and `not_after` must carry a
timezone and are stored in UTC; `not_after` must follow `not_before`. A contract
is valid when `not_before <= now < not_after`, and its window may not exceed the
maximum lifetime of its purpose. Unknown fields are rejected everywhere.

| Purpose | Contract | Maximum lifetime |
| --- | --- | --- |
| `snapshot` | `ApprovedSnapshot` | 24 hours |
| `trust` | `TrustStatus` | 1 hour |
| `approval` | `ActionApproval` | 5 minutes |
| `model` | `HostedModelAttestation` | 24 hours |

### ApprovedSnapshot

| Field | Type and constraint | Meaning |
| --- | --- | --- |
| `not_before`, `not_after` | Timestamps | Validity window |
| `version` | `"1"` | Contract version |
| `kind` | `"approved"` | Contract kind |
| `agent_id` | Non-empty string | Agent the grants are for |
| `deployment_id` | Non-empty string | Deployment the agent runs in |
| `tenant` | Non-empty string | Tenant that owns the agent |
| `workload_identity` | Non-empty string | Authenticated workload identity, such as a SPIFFE ID |
| `serial` | Integer from 1 to 2^53 - 1 | Generation for this tenant, deployment and agent; a higher serial supersedes a lower one |
| `bom_digest` | Digest | Digest of the companion AgentBOM |
| `policy_digest` | Digest | Digest of the policy the agent runs under |
| `tools` | List of `ToolGrant` | Grants; at most one per `server_id` and `tool_name` |

### ToolGrant

| Field | Type and constraint | Meaning |
| --- | --- | --- |
| `definition_profile` | `"rfc8785-jcs-v2"` | Profile of `definition_digest` |
| `server_id` | Non-empty string | Server name the caller uses |
| `endpoint_identity` | Endpoint identity, below | Authenticated endpoint the tool must be served from |
| `tool_name` | Non-empty string | Tool name |
| `definition_digest` | Digest | Tool definition digest of the approved descriptor |
| `actions` | Non-empty list of strings | Actions the scope resolver may derive |
| `resources` | Non-empty list of strings | Resources the scope resolver may derive |
| `require_approval` | Boolean, default `true` | Whether each call needs an `ActionApproval` |

### TrustStatus

| Field | Type and constraint | Meaning |
| --- | --- | --- |
| `not_before`, `not_after` | Timestamps | Validity window |
| `version` | `"1"` | Contract version |
| `tenant` | Non-empty string | Tenant the status applies to |
| `serial` | Integer from 1 to 2^53 - 1 | Generation; a higher serial supersedes a lower one |
| `revoked_snapshots` | List of contract digests | Revoked snapshots |
| `revoked_tools` | List of tool definition digests | Revoked tool definitions |
| `revoked_endpoints` | List of endpoint identities | Revoked endpoints |
| `revoked_signers` | List of key IDs | Revoked signing keys, of any purpose |

Revocation entries are compared verbatim, so each list accepts only the canonical
form of its entries: `sha256:` and 64 lowercase hexadecimal digits for digests,
64 lowercase hexadecimal digits for key IDs, and the endpoint identity grammar.
Any other form is rejected when the status is signed or verified.

### ActionApproval

| Field | Type and constraint | Meaning |
| --- | --- | --- |
| `not_before`, `not_after` | Timestamps | Validity window |
| `version` | `"1"` | Contract version |
| `snapshot_digest` | Digest | Contract digest of the snapshot the call runs under |
| `context_digest` | Digest | Context digest of the authenticated execution context |
| `request_digest` | Digest | Request digest of the exact call |
| `nonce` | String, 16 to 256 characters | Single use per tenant and state store; draw it from a secure generator with at least 128 bits of entropy, for example `secrets.token_hex(16)` |
| `actor` | Non-empty string | Approver named as responsible; must be one of the approvers who signed |

### HostedModelAttestation

| Field | Type and constraint | Meaning |
| --- | --- | --- |
| `not_before`, `not_after` | Timestamps | Validity window |
| `provider` | String | Provider that issued the statement |
| `endpoint` | String | Endpoint the statement covers |
| `requested_alias` | String | Model alias the client requested |
| `resolved_revision` | Non-empty string | Revision the provider says served it |

The version of this predicate is carried by its predicate type.

### Unsigned inputs

`ExecutionContext` is built by the integrator's authentication adapter and is
compared with the snapshot, never signed:

| Field | Type | Meaning |
| --- | --- | --- |
| `agent_id`, `deployment_id`, `tenant`, `workload_identity` | Strings | Must equal the snapshot's fields |
| `policy_digest` | Digest | Must equal the snapshot's `policy_digest` |

`ToolCall` is the request: `server_id`, `tool_name`, `action`, `resource` and an
`arguments` object. `action` and `resource` are labels the caller claims; the
gateway admits a call only when the scope resolver derives the same pair from the
arguments. Arguments are bounded to 1 MiB, 32 levels and 20,000 values, and must
stay in the I-JSON domain (both integers and integral floats must lie between
-(2^53 - 1) and 2^53 - 1; pass a larger integer, such as a 64-bit ID, as a
string). By default (`canonical_arguments=True`), `resolve_scope` and `execute`
receive the exact RFC 8785 canonical form that the request digest binds: keys
in RFC 8785 order and integral floats in `[-(2^53 - 1), 2^53 - 1]` converted to
integers. Constructing the gateway with `canonical_arguments=False` forwards the
caller's original key order and float-vs-integer Python distinction while still
enforcing the I-JSON safe-integer bounds.

`ServedTool` is what the description adapter returns: `endpoint_identity`, the
authenticated identity of the endpoint that served the tool, and `definition`,
the served descriptor object, bounded to 256 KiB.

## Endpoint identities

`ToolGrant.endpoint_identity` and `TrustStatus.revoked_endpoints` accept exactly
one spelling per endpoint:

- `stdio+launcher:sha256:` followed by 64 lowercase hexadecimal digits: a pinned
  standalone launcher, as `invoke_pinned_stdio` reports it.
- A URL `scheme://host[:port][path]` with a lowercase scheme and host (a DNS
  name, an IPv4 address or a bracketed IPv6 address), no user information,
  query or fragment, a port only when it is not the scheme's default (443 for
  `https` and `wss`, 80 for `http` and `ws`), no `.` or `..` path segments,
  uppercase percent-encoding only for characters that need it, and an empty
  path for the root: `https://mcp.example.test`, not `https://mcp.example.test/`.
  An IP address has one spelling, whatever the Python version: a dotted quad
  without leading zeros (`127.0.0.1`, not `127.000.000.001`, `127.1` or
  `2130706433`) and an IPv6 address in RFC 5952 form, lowercase hexadecimal with
  the first longest run of zero groups written as `::` (`[::1]` and
  `[2001:db8::1]`, not `[0:0:0:0:0:0:0:1]` or `[64:ff9b::1.2.3.4]`). IPv4-mapped
  and IPv4-compatible IPv6 addresses, such as `[::ffff:7f00:1]`,
  `[::ffff:127.0.0.1]` and `[::7f00:1]`, are refused: use the IPv4 address. A host
  whose last label is a number, which URL parsers read as an IPv4 address, must be
  such a dotted quad.

A misspelled revocation entry is therefore rejected when the status is signed
instead of silently matching nothing. The gateway compares the identity the
description adapter reports with the grant byte for byte.

## Tool definition digest

Profile `rfc8785-jcs-v2` is the inventory's tool fingerprint
(`hash_tool_definition`). Its preimage is a JSON object with:

- `name`: the tool name;
- `description`: the description, or `""` when absent;
- `inputSchema`: the input schema, only when present and not null;
- `annotations`: the annotations object, where absent, null and `{}` are equal;
- `title`, `outputSchema` and `_meta`: only when present and not null.

The digest is the RFC 8785 SHA-256 of that object. A served descriptor with any
other top-level member, such as `icons` or `execution`, is refused
(`descriptor-unsupported`) rather than approved without it, and so is a `title`
or `description` that is not a string, an `outputSchema` or `_meta` that is not an
object, which an inventory refuses too, and an `inputSchema` or `annotations` that is
neither null nor an object, so that `false` or `[]` cannot pass for no annotations. `_meta` is covered, so a server that writes volatile
data there, such as a timestamp, is denied until its grant is re-approved; strip
such data in the description adapter only if your approval process reviews the
descriptor the adapter returns.

## Input schema evaluation

Step 10 below validates the arguments against the approved descriptor's
`inputSchema` in a separate, bounded worker. The schema's `$schema` names its
dialect: draft-04, draft-06, draft-07, 2019-09 or 2020-12, with or without a
trailing `#`. Without `$schema` the dialect is 2020-12, and any other value makes
the schema invalid (`schema-invalid`). So does a constraint that evaluation would
skip:

- an assertion or applicator keyword that the dialect's specification does not
  define but another supported dialect does, such as `const` in draft-04, or
  `minContains` and `maxContains` before 2019-09 (draft-04's boolean
  `exclusiveMinimum` and `exclusiveMaximum` are draft-04 keywords and apply);
- in any dialect, a keyword that only drafts before draft-04 define:
  `divisibleBy`, `disallow`, `extends`, `requires`, `maxDecimal`,
  `minimumCanEqual` and `maximumCanEqual`, and an `optional` whose value is not
  `true` (drafts 01 and 02 require every property not marked `"optional": true`);
- in 2019-09, an `unevaluatedItems` that applies where a `contains` does, in the
  same subschema or through `allOf`, `anyOf`, `oneOf`, `not`, `if`, `then`,
  `else`, `dependentSchemas`, `$ref` or `$recursiveRef`: jsonschema would treat
  the items `contains` matched as evaluated, as only 2020-12 specifies;
- in draft-04 to draft-07, an assertion next to `$ref`;
- a subschema whose `$schema` differs from the root's, where evaluation would
  switch dialect, draft-03 included;
- a subschema with its own base URI: `$id` below the root, or `id` in draft-04,
  except the plain-name anchors of draft-04 to draft-07 such as `"$id": "#node"`;
- a reference that is not a JSON Pointer within the schema (`#` or `#/...`), such
  as a URI, a relative reference or an anchor; a `$recursiveRef` other than `#`;
  and a pointer that resolves to nothing or to a value that is not a schema.

Reference targets are checked by the same rules wherever they are in the
document. A keyword that no supported dialect defines, including a misspelling
such as `maxlength`, is an annotation: it is ignored, not refused. `format`,
`contentEncoding`, `contentMediaType` and `contentSchema` are never asserted, so a
string declared as JSON is not checked against its `contentSchema`.

`pattern` and `patternProperties` are ECMA-262 regular expressions read with the
`u` flag. Syntax that the `u` flag rejects and that would otherwise be read
differently is `schema-invalid`: inline flags and other Python-only groups,
possessive quantifiers (`a*+`), quantifiers without a minimum (`{,n}`), quantified
assertions, and `\d`, `\w` or `\s` as a range bound (`[%-\w]`). The empty
classes `[]` and `[^]` are refused too, as is a pattern nested too deeply for
Python to compile or with a repetition count too large for it (`a{4294967296}`).
So is a backreference (`\1` or
`\k<name>`) unless its group always takes part, once, before the reference:
ECMA-262 reads a reference to a group that did not take part as the empty string
and resets the captures of a loop on each iteration, while Python fails the
reference and keeps earlier captures. A reference to a group inside a quantifier
(`?` included), an alternative or a lookaround, a reference before or inside its
group or inside a lookbehind, and a reference to group 100 or above are refused:
`^(['"]).*\1$` is accepted, `^(['"])?\w+\1$` is not. An escaped surrogate pair
such as `\uD83D\uDE00` is one code point. Annex B syntax that the `u` flag
rejects, such as `\-` outside a class or an octal escape in a class, is accepted
and read with the `u` flag's code-point semantics: `.`, negated classes and
`\D`, `\S` and `\W` match one character outside the Basic Multilingual Plane,
where Annex B would count two UTF-16 code units. A pattern that names a character
outside the Basic Multilingual Plane or a surrogate must be valid with the `u`
flag.

## Verification order

`ReferenceGateway.invoke(call, snapshot=..., trust=..., bom=..., approval=...)`
checks evidence in this order and stops at the first failure. Every authorization
denial raises `AuthorizationError`, whose `reason` is a code from the table below. Exceptions
raised by the integrator's adapters (`authenticate`, `describe`, `resolve_scope`,
`execute`) propagate unchanged. A failure before admission prevents the gateway
from calling `execute`.
After admission, `execute` may have performed an external action before raising;
the result is an admitted attempt whose execution outcome needs reconciliation.
Neither an exception nor its type proves that no action occurred. Keep the
admission decision and the executor's outcome separate, and use the executor's
idempotency or reconciliation mechanism before retrying. The approval remains
consumed; a fresh approval does not establish that a retry is safe.

1. Copy the call and check its arguments against the budget and the I-JSON
   domain (`arguments-too-large`, `arguments-number-out-of-range`,
   `arguments-not-json`). The initial clock reading applies to the initial checks;
   the clock is read again before each trust or snapshot state transition and at
   final admission.
2. Authenticate the workload (`authenticate()`).
3. Trust status: verify signatures with the trust ring and quorum
   (`signers-insufficient` and the envelope and statement codes), the validity
   window (`trust-*`), the tenant (`trust-tenant-mismatch`), the signers that the
   status itself revokes (`trust-signer-revoked`), the signers' scopes
   (`signers-out-of-scope`), and the transition from the recorded status
   (`trust-signer-revoked` for a signer that the recorded status revokes,
   `trust-rollback`, `trust-fork`, `trust-restore-required`). An accepted newer
   status is recorded even if the call is denied later. A new status's validity
   and scoped signer quorum are rechecked under the state lock before it is recorded.
4. Snapshot: signatures with the snapshot ring and quorum, validity window
   (`snapshot-*`), equality with the authenticated context (`context-mismatch`),
   revocation of the snapshot and of its signers (`snapshot-revoked`,
   `signer-revoked`; trust-status signers were checked in step 3) and signer scopes. The snapshot then
   becomes the agent's current one: a lower serial for the same tenant,
   deployment and agent is denied from then on (`snapshot-superseded`), and the
   same serial with other content is a fork (`snapshot-fork`). This happens even
   if the call is denied later. Advancing the snapshot atomically checks that the
   trust head remains the checked one and rechecks both contracts and signer scopes.
5. Companion BOM digest (`bom-too-large`, `bom-mismatch`).
6. Scope: the resolver gets an independent copy of the call; a resolver that
   modifies it is refused (`resolver-modified-request`), and the derived action
   and resource must equal the call's labels (`scope-mismatch`).
7. Grant: the snapshot must grant the server and tool (`tool-not-granted`), the
   action and the resource (`capability-denied`), and neither the definition nor
   the endpoint may be revoked (`tool-revoked`, `endpoint-revoked`).
8. Descriptor: `describe(server_id, tool_name)` must report the granted endpoint
   (`endpoint-mismatch`) and tool name (`descriptor-name-mismatch`), and the
   descriptor's digest must equal the grant's (`descriptor-unsupported`,
   `descriptor-too-large`, `descriptor-not-json`, `descriptor-changed`). The
   bounded descriptor is copied once; hashing and schema validation use that copy.
9. Approval, when the grant requires one (`approval-required`): signatures with
   the approval ring and quorum, validity window (`approval-*`), revoked approvers
   (`approver-revoked`), signer scopes, approvers (`approval-actor-unbound`,
   `approval-quorum-not-met`) and the three bindings
   (`approval-snapshot-mismatch`, `approval-context-mismatch`,
   `approval-request-mismatch`).
10. Arguments against the approved input schema in a bounded worker
    (`arguments-invalid`, `schema-invalid`, `validation-capacity`,
    `validation-timeout`, `validation-unavailable`, `validation-failed`).
11. Authenticate again; the context must be unchanged (`identity-changed`).
12. In one state transaction: the recorded trust status and snapshot must still
    be the ones checked (`trust-superseded`, `snapshot-superseded`), the approval
    nonce is consumed (`approval-replayed`), and every contract and signer scope
    is checked against the clock again, including the distinct approver quorum.
    The commit admits the call.
13. Report the decision to `on_decision`, then call `execute(call)`.

`ReferenceGateway.register_snapshot(snapshot, trust=...)` runs steps 3 and 4 for
the snapshot's own tenant, deployment and agent, without a workload context or a
companion BOM, so an operator can retire older snapshots as soon as a new one is
issued. `ReferenceGateway.registrar(snapshot_keys=..., trust_keys=..., state=...)`
returns a gateway without adapters that can only register snapshots, and
`runtime register` runs the same checks from the command line.

Steps 3 and 4 read the recorded heads first. A trust status or snapshot that is
older than the recorded one, or that has the recorded serial with other content,
is refused from that read, without the store's write lock; heads only move
forward, so the later transaction would refuse it too.

`runtime verify` checks only signatures, purpose, subject, canonical form,
validity window and, for a snapshot, the companion BOM. Revocation, signer
scopes, approvers and an approval's bindings are checked only by the gateway.

## Reason codes

`AuthorizationError.reason` and the `runtime` commands use these codes. They are
stable; the message text is not. `validation-capacity`, `validation-timeout` and
a locked store (`state-unavailable`) can clear when the call is retried, and a
`-not-yet-valid` code clears once the contract's `not_before` is reached; every
other code is permanent for the evidence presented.

| Code | Meaning |
| --- | --- |
| `denied` | Authorization evidence is incomplete or invalid (used by adapters that raise without a code) |
| `configuration-invalid` | Gateway, signer or quorum configuration is invalid |
| `json-invalid` | Input is not strict JSON |
| `json-not-object` | Input must be a JSON object (`runtime` commands) |
| `json-out-of-domain` | Value is outside the canonical JSON domain |
| `json-budget-exceeded` | JSON exceeds the supported size or complexity |
| `json-number-out-of-range` | JSON contains an integer outside the I-JSON range |
| `envelope-invalid` | Signed envelope is malformed |
| `statement-too-large` | Signed statement exceeds 1 MiB |
| `signers-insufficient` | Too few distinct trusted signers |
| `signers-out-of-scope` | Too few signers are authorized for this tenant, deployment, agent or tool |
| `statement-invalid` | Payload is not a valid in-toto statement |
| `statement-purpose-mismatch` | Statement was signed for another purpose |
| `contract-invalid` | Contract does not validate |
| `contract-not-canonical` | Contract is not in canonical form |
| `subject-mismatch` | Statement subject does not match its predicate |
| `snapshot-not-yet-valid` | Snapshot is not yet valid |
| `snapshot-expired` | Snapshot has expired |
| `snapshot-lifetime-exceeds-policy` | Snapshot validity exceeds 24 hours |
| `trust-not-yet-valid` | Trust status is not yet valid |
| `trust-expired` | Trust status has expired |
| `trust-lifetime-exceeds-policy` | Trust status validity exceeds 1 hour |
| `approval-not-yet-valid` | Approval is not yet valid |
| `approval-expired` | Approval has expired |
| `approval-lifetime-exceeds-policy` | Approval validity exceeds 5 minutes |
| `model-not-yet-valid` | Hosted-model attestation is not yet valid |
| `model-expired` | Hosted-model attestation has expired |
| `model-lifetime-exceeds-policy` | Hosted-model attestation validity exceeds 24 hours |
| `contract-not-yet-valid` | Contract is not yet valid (helpers that check a window without a purpose) |
| `contract-expired` | Contract has expired |
| `contract-lifetime-exceeds-policy` | Contract validity exceeds local policy |
| `trust-tenant-mismatch` | Trust status is for another tenant |
| `trust-signer-revoked` | A trust-status signer is revoked |
| `trust-rollback` | Trust status is older than the recorded one |
| `trust-fork` | Another trust status with this serial was recorded |
| `trust-restore-required` | Restore the recorded trust status before advancing |
| `trust-superseded` | A newer trust status was recorded during authorization |
| `context-mismatch` | Workload, deployment, tenant, agent or policy differs from the snapshot |
| `snapshot-revoked` | Snapshot is revoked |
| `signer-revoked` | A snapshot signer is revoked |
| `snapshot-superseded` | A newer snapshot is recorded for this agent |
| `snapshot-fork` | Another snapshot with this serial was recorded for this agent |
| `bom-required` | Snapshot verification requires its companion BOM |
| `bom-mismatch` | Companion BOM does not match the approved digest |
| `bom-too-large` | Companion BOM exceeds the supported JSON budget |
| `arguments-too-large` | Tool arguments exceed the supported JSON budget |
| `arguments-number-out-of-range` | Tool arguments contain an integer outside the I-JSON range |
| `arguments-not-json` | Tool call is outside the canonical JSON domain |
| `resolver-modified-request` | Scope resolver modified the request |
| `scope-mismatch` | Operation labels do not match the actual tool arguments |
| `tool-not-granted` | Snapshot does not grant this tool |
| `capability-denied` | Action or resource is outside the approved capability |
| `tool-revoked` | Tool definition is revoked |
| `endpoint-revoked` | Endpoint is revoked |
| `endpoint-mismatch` | Authenticated endpoint differs from the grant |
| `descriptor-name-mismatch` | Served tool name differs from the requested tool |
| `descriptor-unsupported` | Served descriptor has fields outside the digest profile |
| `descriptor-too-large` | Served descriptor exceeds the supported JSON budget |
| `descriptor-not-json` | Served descriptor is outside the canonical JSON domain |
| `descriptor-changed` | Served descriptor changed since approval |
| `approval-required` | Operation requires a signed approval |
| `approver-revoked` | An approval signer is revoked |
| `approval-actor-unbound` | Approval actor is not bound to its signing keys |
| `approval-quorum-not-met` | Approval needs more distinct approvers |
| `approval-snapshot-mismatch` | Approval was given for another snapshot |
| `approval-context-mismatch` | Approval was given for another execution context |
| `approval-request-mismatch` | Approval was given for another request |
| `approval-replayed` | Approval nonce has already been used |
| `arguments-invalid` | Tool arguments do not satisfy the input schema |
| `schema-invalid` | Input schema is invalid, unsupported or not resolvable offline |
| `validation-capacity` | Schema validation capacity is exhausted; retry later |
| `validation-timeout` | Schema validation timed out; retry later |
| `validation-unavailable` | Schema validation worker is unavailable |
| `validation-failed` | Schema validation failed or exceeded its budget |
| `identity-changed` | Execution identity changed during authorization |
| `state-missing` | State database does not exist or is not initialized |
| `state-invalid` | State database path is unsafe or already exists |
| `state-unavailable` | State database is unavailable or locked |
| `adapter-error` | An adapter raised an exception other than `AuthorizationError` before admission (decision records only) |

`invoke_pinned_stdio`'s pinned session raises its refusals without a code, so they
are recorded as `denied`. A session deadline or protocol error before `tools/call` is
sent is recorded as `adapter-error`. In both cases `tools/call` is never sent. This
includes a launcher that cannot be read or differs from its pin and a failed
`initialize` handshake, which happen at the descriptor step (step 8), when the
gateway first calls `describe`; their records carry the facts verified up to that
step. Launcher settings that `PinnedStdioSession` refuses, such as a relative path or
a malformed pin, are refused before the gateway runs; their records hold only the
time, the call labels and `store_id`.

The `runtime` commands print the code in parentheses at the end of the error,
next to their own codes: `runtime-input-error` for a contract that does not
validate (naming fields and contract rules, never values), `runtime-input-too-large`
for an input file over its size limit, `runtime-key-error` for a key path, key or
passphrase that cannot be used, `runtime-io-error` for a file that cannot be read
or written safely, and `runtime-contract-error` for any other failure.

## Gateway configuration

`ReferenceGateway` takes only keyword arguments:

| Argument | Meaning |
| --- | --- |
| `snapshot_keys`, `approval_keys`, `trust_keys` | Purpose rings mapping key IDs to Ed25519 public keys. An entry whose key ID does not match its key is ignored. A key in more than one ring is refused unless `allow_shared_keys=True`. |
| `snapshot_threshold`, `approval_threshold`, `trust_threshold` | Quorums from 1 to 32 (default 1), never more than the distinct keys in the ring |
| `approval_actors` | Maps each approval key ID to the person who holds it |
| `signer_scopes` | Maps key IDs to a `SignerScope`; every named key must be in a ring |
| `allow_shared_keys` | Permit one key in several purpose rings (default `False`) |
| `state` | A `StateStore` |
| `authenticate`, `describe`, `resolve_scope`, `execute` | The integrator's adapters, below |
| `clock` | Returns the current time as an aware `datetime` (default: system UTC time) |
| `on_decision` | Called with a `Decision` for every admitted or denied call |
| `canonical_arguments` | Give `resolve_scope` and `execute` the RFC 8785 canonical form of the arguments that the approval binds instead of the caller's non-canonical form (default `True`) |

An approval quorum counts people, not keys: the signers' `approval_actors` must
include at least `approval_threshold` distinct names, and the approval's `actor`
must be one of them. Two keys enrolled for one person are one approval, so a
two-person rule is `approval_threshold=2` with each person's keys mapped to their
own name. A quorum above one that the approval ring's distinct approvers cannot
meet is refused when the gateway is constructed.

A `SignerScope` limits one key; an omitted field leaves that dimension open:

| Field | Meaning |
| --- | --- |
| `tenants` | Tenants the key may sign for |
| `deployments` | Deployments the key may sign for |
| `agents` | Agents the key may sign for |
| `tools` | `(server_id, tool_name)` pairs: every grant of a snapshot, or the call of an approval, must be listed |
| `not_before`, `not_after` | When the key may sign; use them to stage a rotation |

Signers outside their scope do not count towards a quorum, so a contract that has
too few in-scope signers is denied with `signers-out-of-scope`. A trust status
covers a whole tenant, so only keys without deployment, agent or tool
restrictions count for it. When one gateway serves several tenants, give every
key a `tenants` scope, or run one gateway configuration per tenant; otherwise any
ring key can sign for any tenant.

A `Decision` holds `admitted`, `reason` (`admitted` or the denial code), `time`,
the call's `server_id`, `tool_name`, `action` and `resource`, the context fields,
`request_digest`, the trust status and snapshot serials and digests, the
approval digest and actor, the key IDs that signed each contract, and the state
store's `store_id`. It never holds argument values. The call labels come from the
caller, so treat them as untrusted text. On an admitted call each list of key IDs
names the signers whose authority counted: unrevoked, within their scope and, for an
approval, bound to an actor. An extra signature by a revoked or out-of-scope key does
not stop a valid quorum and is not listed. A denial may list every verified signature
of the contract it refused. An exception raised by `on_decision`
propagates; after admission it prevents execution and the approval stays
consumed.

An `admitted` decision records authorization, not successful execution. An
exception from `execute` leaves that decision intact and the approval consumed;
the gateway does not emit a second denial or an execution-outcome record.

`ReferenceGateway.registrar(...)` takes the rings, quorums, signer scopes,
`allow_shared_keys`, `clock` and `state` above, without adapters, and returns a
gateway whose only use is `register_snapshot`; `invoke` on it is refused with
`configuration-invalid`. `approval_keys` is optional and only checked, so the
gateways' scope map can be reused.

`bind_adapters(describe=..., execute=..., prepare=...)` returns a gateway with
the same policy and state. The optional `prepare` callback receives the verified
descriptor after input validation and before approval is recorded. The pinned
stdio adapter uses it to prepare output validation. `check_validation_worker()`
runs one trivial schema validation and raises the worker's reason code. Call it
at start-up or from a readiness probe.

## State store

`StateStore.initialize(path)` creates a new store: the parent directory with mode
0700 if it does not exist, and the file with mode 0600, refusing an existing file
or a symbolic link. `StateStore(path)` opens an existing store. It refuses a
missing file or a database without a store's tables (`state-missing`), a symbolic
link or anything but a regular file (`state-invalid`), and a file that is not an
SQLite database (`state-unavailable`), and it restricts a group- or
world-accessible file to 0600. A store removed while a gateway runs makes every
call fail with `state-unavailable`; it is never recreated empty. Each store has a
random `store_id`.

The store records, per tenant, the accepted trust status (serial, digest and
revoked signer IDs); per tenant, deployment and agent, the current snapshot
(serial and digest); and the consumed approval nonces. A nonce is kept for at
least seven days after its approval expires, which also covers gateways whose
clocks disagree by less than that.

One-use approvals and rollback protection hold per state file. Gateways that
serve the same tenants must share one store; SQLite needs the file on one host or
a filesystem with working locks, so a fleet on several hosts needs its own shared
state backend that implements the same checks. Back up the store and restore it
only as a whole: an older copy reopens replay and rollback for every contract
still valid. If a mistaken or hostile contract recorded a serial so high that no
later contract can follow it, stop the gateways, delete that scope's row from
the `heads` table with the SQLite shell, and present a fresh status or register a
fresh snapshot before restarting.

## Key lifecycle

- **Generate** one key pair per purpose: `runtime keygen` writes both files with
  mode 0600 and, with `--passphrase-file`, encrypts the private key with the
  file's first line, at most 1,023 bytes. `runtime sign` refuses a private key
  file, and both commands refuse a passphrase file, that the user running the
  command does not own or that gives its group or others any permission. Root is no
  exception: a job that runs as root, such as a container job, cannot use a key
  mounted from the host and owned by another user; give the file to the user
  that runs the command. A key held in a KMS, an HSM or an agent can sign
  through `sign_contract` by implementing `ContractSigner`: `sign(data) -> bytes`
  and `public_key()`.
- **Distribute** public keys to every gateway's rings and give each approval key
  its holder in `approval_actors`. Trust statuses expire after an hour and
  snapshots after a day, so their signing keys must be available to automation;
  keep them in a KMS or HSM rather than on the automation host's disk.
- **Rotate** by adding the new key to the ring (optionally with a `SignerScope`
  whose `not_before` starts its use), signing new contracts with it, and removing
  the old key once every contract it signed has expired: 24 hours for snapshots,
  1 hour for trust statuses, 5 minutes for approvals. A `not_after` in the old
  key's scope ends its use on schedule.
- **Revoke** a compromised key by listing its key ID in `revoked_signers` of a
  trust status signed by another trust key; every snapshot, trust status and
  approval that key signed is then denied. Remove it from every gateway's rings as
  well, because a revocation binds only tenants whose statuses list it. Keep a
  separately protected recovery trust key, and do not pre-sign trust statuses for
  later windows: a presenter could withhold the newest one until the older ones
  expire.
- **Supersede** a snapshot by issuing a higher serial and registering it on
  every store with `runtime register` or `register_snapshot`; to retire it on
  stores you cannot reach, list its digest in `revoked_snapshots` of the next
  status.

## What an integrator must provide

The gateway authorizes only calls routed through `invoke`. An integration that
mediates tool calls must supply:

- **Workload authentication.** `authenticate()` returns the `ExecutionContext` of
  the authenticated caller from the transport (mTLS, SPIFFE, a signed token),
  never from request fields the caller controls.
- **Descriptor observation bound to execution.** `describe(server_id, tool_name)`
  returns the descriptor the endpoint actually serves and the endpoint's
  authenticated identity, over the same session `execute` will use.
- **Scope resolution.** `resolve_scope(call)` derives the action and resource
  from the arguments the executor will use, and rejects ambiguous calls.
- **Execution.** `execute(call)` sends exactly the admitted call to the checked
  endpoint with credentials no broader than the grant.
- **Evidence distribution.** Snapshots, trust statuses and the companion BOM
  come from an operator-controlled channel, not from the mediated agent. Refresh
  trust statuses well within their hour, and register each new snapshot with
  `runtime register` or `ReferenceGateway.registrar`.
- **Approval issuance.** A reviewer sees the request, and an approval service
  signs an `ActionApproval` with `request_digest(call)`, the snapshot's
  `contract_digest` and the context's digest, a fresh nonce and the reviewer's
  name, using that reviewer's key.
- **State.** One initialized store shared by every gateway for the same tenants,
  protected against modification, deletion and rollback, and backed up whole.
- **Operations.** A fast local clock, an audit sink for `on_decision`, rate
  limits and an end-to-end deadline per call, a readiness probe that calls
  `check_validation_worker()`, and network and credential policy that leaves the
  agent no path to the tools except through the gateway.

The package ships one integration, `invoke_pinned_stdio`, for operator-pinned
standalone stdio launchers. Other enforcement points have to be built on the same
gateway: for example a proxy in front of streamable-HTTP MCP servers that
authenticates the agent, calls `invoke` and forwards only admitted calls; a
pre-tool-use hook for a coding agent that denies a call unless `invoke` admits
it; or an exporter that turns snapshot grants into data for an existing policy
engine, which then has to reproduce the checks above.

## Worked example

This example runs as written; a test executes it. It keeps keys in memory and
the state store in a temporary directory; a deployment keeps keys in a KMS or
HSM and the store at a persistent, protected path. The executor below only
records a synthetic action in a list; it sends no messages. Its timeout shows why
an execution error cannot be treated as an authorization denial.

```python
import secrets
import tempfile
from datetime import UTC, datetime, timedelta
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.runtime import (
    ActionApproval,
    ApprovedSnapshot,
    AuthorizationError,
    ExecutionContext,
    ReferenceGateway,
    ServedTool,
    StateStore,
    ToolCall,
    ToolGrant,
    TrustStatus,
    bom_digest,
    contract_digest,
    key_id,
    request_digest,
    sign_contract,
    tool_definition_digest,
)

release, approver, trust_issuer = (Ed25519PrivateKey.generate() for _ in range(3))
now = datetime.now(UTC)
context = ExecutionContext(
    agent_id="agent:triage",
    deployment_id="prod",
    tenant="acme",
    workload_identity="spiffe://acme.example/ns/prod/sa/triage",
    policy_digest="sha256:" + "a" * 64,
)
descriptor = {
    "name": "send",
    "description": "Send a message",
    "inputSchema": {
        "type": "object",
        "properties": {"to": {"type": "string"}},
        "required": ["to"],
    },
}
bom = {"metadata": {"name": "triage"}, "components": []}
snapshot = ApprovedSnapshot(
    **context.model_dump(),
    serial=1,
    bom_digest=bom_digest(bom),
    tools=(
        ToolGrant(
            server_id="server:mail",
            endpoint_identity="https://mail.example.test/mcp",
            tool_name="send",
            definition_digest=tool_definition_digest(descriptor),
            actions=("send",),
            resources=("mailbox:team",),
        ),
    ),
    not_before=now - timedelta(seconds=5),
    not_after=now + timedelta(hours=8),
)
status = TrustStatus(
    tenant="acme",
    serial=1,
    not_before=now - timedelta(seconds=5),
    not_after=now + timedelta(minutes=30),
)
call = ToolCall(
    server_id="server:mail",
    tool_name="send",
    action="send",
    resource="mailbox:team",
    arguments={"to": "team@example.test"},
)
approval = ActionApproval(
    snapshot_digest=contract_digest(snapshot),
    context_digest=contract_digest(context),
    request_digest=request_digest(call),
    nonce=secrets.token_hex(16),
    actor="alice",
    not_before=now - timedelta(seconds=5),
    not_after=now + timedelta(minutes=2),
)


def scope(requested: ToolCall) -> tuple[str, str]:
    internal = requested.arguments["to"].endswith("@example.test")
    return "send", "mailbox:team" if internal else "mailbox:external"


decisions = []
gateway = ReferenceGateway(
    snapshot_keys={key_id(release.public_key()): release.public_key()},
    approval_keys={key_id(approver.public_key()): approver.public_key()},
    trust_keys={key_id(trust_issuer.public_key()): trust_issuer.public_key()},
    approval_actors={key_id(approver.public_key()): "alice"},
    state=StateStore.initialize(Path(tempfile.mkdtemp()) / "state.sqlite"),
    authenticate=lambda: context,
    describe=lambda server, tool: ServedTool(
        endpoint_identity="https://mail.example.test/mcp", definition=descriptor
    ),
    resolve_scope=scope,
    execute=lambda admitted: {"sent_to": admitted.arguments["to"]},
    on_decision=decisions.append,
)
gateway.check_validation_worker()

evidence = {
    "snapshot": sign_contract(snapshot, "snapshot", (release,)),
    "trust": sign_contract(status, "trust", (trust_issuer,)),
    "bom": bom,
    "approval": sign_contract(approval, "approval", (approver,)),
}
assert gateway.invoke(call, **evidence) == {"sent_to": "team@example.test"}

try:
    gateway.invoke(call, **evidence)
except AuthorizationError as denied:
    assert denied.reason == "approval-replayed"
else:
    raise AssertionError("The consumed approval was accepted")

execution_attempts = []


def execute_then_timeout(admitted: ToolCall) -> None:
    execution_attempts.append({"sent_to": admitted.arguments["to"]})
    raise TimeoutError("The remote outcome must be reconciled")


failing_gateway = gateway.bind_adapters(
    describe=gateway.describe, execute=execute_then_timeout
)
fresh_approval = approval.model_copy(update={"nonce": secrets.token_hex(16)})
fresh_evidence = {
    **evidence,
    "approval": sign_contract(fresh_approval, "approval", (approver,)),
}
try:
    failing_gateway.invoke(call, **fresh_evidence)
except TimeoutError:
    assert decisions[-1].admitted
    assert decisions[-1].reason == "admitted"
    assert execution_attempts == [{"sent_to": "team@example.test"}]
else:
    raise AssertionError("The executor's timeout did not propagate")

try:
    failing_gateway.invoke(call, **fresh_evidence)
except AuthorizationError as denied:
    assert denied.reason == "approval-replayed"
    assert execution_attempts == [{"sent_to": "team@example.test"}]
else:
    raise AssertionError("The failed execution's approval was accepted again")

newer = snapshot.model_copy(update={"serial": 2})
gateway.register_snapshot(sign_contract(newer, "snapshot", (release,)), trust=evidence["trust"])
try:
    gateway.invoke(call, **evidence)
except AuthorizationError as denied:
    assert denied.reason == "snapshot-superseded"
else:
    raise AssertionError("The superseded snapshot was accepted")

assert [decision.reason for decision in decisions] == [
    "admitted",
    "approval-replayed",
    "admitted",
    "approval-replayed",
    "snapshot-superseded",
]
```

## Compatibility

The known-answer vectors pin the envelope, statement, contract and digest bytes
for a published test key. A change that alters any of them needs a new predicate
type or digest profile version, not regenerated vectors. Deliberate differences
from generic DSSE and in-toto tooling: the predicate must be in canonical
contract form, unknown statement members are rejected instead of ignored, and the
subject is the contract digest rather than the artifact the contract is about.
The Python model field names (`payload_type`, `key_id`, `signature`) are also
accepted when an envelope is parsed; write the DSSE names.
