# Runtime assurance integration

The `nexus_symbiote` package is the compatibility baseline. Runtime contracts add an
explicit approval boundary to its inventory model. The experimental parallel
foundation package is not a dependency of this implementation.

## Security boundary

`ReferenceGateway` mediates calls made through its `invoke` method. The operator
must provide authenticated workload and endpoint adapters, a trusted scope
resolver, an executor, purpose-specific public keys and protected state storage.
It does not intercept other network requests, sandbox a process, or establish
that an unchanged tool backend is benign. Restrict bypass paths through the
surrounding runtime, credentials, sandbox and network policy.

The gateway copies the request before scope resolution and rejects a resolver
that modifies its copy during resolution. A resolver retaining that copy cannot
change the request subsequently submitted to the executor. The resolver remains
trusted to derive the correct scope, and the executor remains trusted to send
the authorized call over the same authenticated session used for observation.

Four signed contracts have distinct predicate types and schemas:

| Contract | Purpose | Maximum validity |
| --- | --- | --- |
| Approved snapshot | Bind an exact companion BOM, deployment, workload, tenant, policy and tool grants | 24 hours |
| Trust status | Publish tenant-scoped tool, endpoint, signer and snapshot revocations | 1 hour |
| Action approval | Bind an authorized approver key to one snapshot, execution context, exact request and single-use nonce | 5 minutes |
| Hosted model attestation | Bind a trusted provider statement to endpoint, requested alias and resolved revision | 24 hours |

Approval nonces are single-use within a tenant; draw each one from a cryptographically secure generator with at least 128 bits of entropy (for example `secrets.token_hex(16)`), never from a counter.

Signatures authenticate the claims of authorized issuers. They do not prove
human presence, model safety, complete discovery, or the truth of a provider's
statement. The operator owns the signer-to-role and approver-key-to-actor maps.

## Signing and verification

Create operator-owned Ed25519 keys outside scanned repositories:

```sh
nexus-symbiote runtime keygen --private-key approval.pem --public-key approval.pub
nexus-symbiote runtime sign approved-snapshot.json --kind snapshot --key approval.pem --out snapshot.dsse.json
nexus-symbiote runtime verify snapshot.dsse.json --kind snapshot --public-key approval.pub --bom agentbom.json
```

The sign command accepts an explicit contract rather than granting authority
to a scan result automatically. Outputs use DSSE pre-authentication encoding and
in-toto statements. Complete companion content is digest-bound; selective
disclosure is not supported by this profile. Existing files are not overwritten.
Verification requires the expected purpose, an authorized key set, distinct
signers, subject consistency, schema validity and current validity window.
The CLI reports contract verification separately from invocation authorization.

`ReferenceGateway` accepts independent `snapshot_threshold`, `approval_threshold`
and `trust_threshold` keyword arguments. Each defaults to `1`; set a larger value
when the operator policy requires multiple distinct authorized signers for that
purpose. Values must be integers from 1 through 32 and cannot exceed the number
of distinct, correctly identified public keys in that purpose's key ring.
Booleans and duplicate aliases do not establish a quorum. An empty key ring is
allowed only with the default threshold and disables verification for that
purpose; it never approves an unsigned contract. The pinned stdio adapter carries
the gateway's thresholds into the same-process invocation. Multi-signer action
approvals still bind every accepted signer to the contract's authorized actor.

Runtime CLI contract and key inputs must be bounded regular files. Symlinks and
FIFOs are rejected rather than followed or waited on.

## Gateway adapters

Construct `ReferenceGateway` with these callbacks:

- `authenticate()` returns the current `ExecutionContext` from the runtime's
  authenticated session. Do not construct it from caller-controlled request fields.
- `describe(server_id, tool_name)` returns the actual served definition and
  authenticated endpoint identity. Bind discovery and execution to the same
  authenticated session/version where the upstream protocol supports it.
- `resolve_scope(call)` derives the effective action and resource from the exact
  operation arguments. Reject ambiguous operations; do not trust the request's
  action/resource labels. For example, derive a mailbox resource from the mailbox
  argument that the executor actually uses.
- `execute(call)` performs only that normalized operation against the checked
  endpoint. It must not add unapproved destinations or use broader credentials.

The gateway checks exact grants, endpoint identity, descriptor digest, offline
input-schema validity, request-bound approval and revocation before execution.
Unsupported descriptor fields fail closed until the digest profile is upgraded.
Arguments are copied before checking; schema references cannot trigger network
retrieval. Identities and validity are checked again immediately before execution.

Schema validity does not bound validation cost. Approved tool schemas and hostile
arguments are checked in disposable isolated Python workers, with a two-second
wall deadline, one CPU second and 256 MiB address-space limit. Validation requires
POSIX resource limits and fails closed if a worker cannot start, crashes, times
out or returns an invalid result. At most four validations run concurrently in
one gateway process; additional requests fail closed. JSON input is bounded to
32 levels and 20,000 nodes per value, 256 KiB per served descriptor/schema and
1 MiB per argument object. Deployments must also rate-limit requests and bound
the trusted authentication, description, scope and execution adapters.
Workers load the reviewed package installed in the gateway's Python environment
using isolated mode; a source tree available only through `PYTHONPATH` is
insufficient and fails closed.

Revocation and required operation approvals are checked before schema evaluation.
The worker cannot retrieve schema references from the network. Validation failure
does not consume an approval nonce or advance snapshot state.

### Pinned stdio integration

`nexus_symbiote.live.session.invoke_pinned_stdio` is an opt-in POSIX adapter that
starts a private copy of an independently pinned standalone launcher, enumerates
its tools, authorizes the requested operation, and sends `tools/call` through the
same still-running process and streams. The approved `ToolGrant.endpoint_identity`
must be `stdio+launcher:sha256:<64 lowercase hex characters>` for that launcher.
The pin and launcher path come from operator-controlled configuration, not the
scanned project. The adapter refuses arguments, project environment and working
directory, reconnects, repeated calls, invalid JSON-RPC and list pagination beyond
its limits. Protocol reads and writes share a deadline starting after launcher
staging and process startup. This does not bound staging, authentication,
scope resolution, state storage or other synchronous gateway work. Operators
must impose an external end-to-end deadline on the invocation and its adapters.

Use `invoke_pinned_stdio(gateway, call, command=..., sha256=..., snapshot=...,
trust=..., bom=..., approval=...)`. It ignores the gateway's separate `describe`
and `execute` callbacks and uses the same process for both steps. Authenticate
the workload and derive scope using trusted gateway callbacks. Keep all other
network and process paths from bypassing this gateway.

Same-process binding does not establish that a server's implementation or
remote backend is immutable, safe or honest; a server can change behavior between
listing and invocation, including during a tool call. The pin covers launcher
bytes only, not interpreters, shared libraries or dependencies. A launcher is
executed before the authorization check, so only operator-approved launchers may
be used. Run it in an externally provisioned sandbox with restricted identity,
filesystem and egress. The adapter does not create that sandbox or mediate other
calls. `PinnedStdioSession` is a transport primitive and must not be invoked
directly as an authorization decision.

The SQLite `StateStore` atomically records snapshot and trust-status high-water
marks and consumes approval nonces. Fresh authenticated revocation knowledge is
retained even when the current operation is denied. Failed signature or binding
checks cannot advance snapshot state. After the final identity check, the gateway
takes the database write lock, confirms the current trust head, and checks validity
against its clock before committing the snapshot head and nonce. The commit admits
the call. A newer trust status committed before admission denies the stale call
and preserves its nonce. A later revocation applies to subsequent admissions.
Cancellation of work already admitted requires executor support. Execution failure
after admission consumes the approval. Use a fast, local clock for the validity check.

Each tenant's accepted trust status records its revoked signer IDs in the same
transaction as the serial and digest. The gateway checks the signers on the next
status against both the prior revocations and the proposed list. To reinstate a
key, a still-authorized trust issuer must sign a higher serial that removes the
key from the list. Remove a compromised key from the configured trust ring on
every gateway. Keep a separately protected recovery issuer available.

Before upgrading an existing gateway fleet, stop writers to the shared database,
back it up, and retain each tenant's last accepted trust predicate. Older databases
contain only the serial and digest. The upgraded gateway can recover the revoked
signer IDs by replaying the exact, still-valid signed status. For an expired
status, load the archived predicate with
`StateStore(path).restore_trust_status(TrustStatus.model_validate(predicate))`.
This matches the tenant, serial and canonical digest already on disk and restores
only its signer list. A currently valid signed status is required to authorize a
call. If the archive is missing, restore it from a trusted backup before advancing
that tenant. Preserve the original database and its consumed nonces throughout
the migration.

Protect the database against modification, deletion and rollback, and place it
outside scanned repositories. Database backup/restore must preserve monotonic
state. The adapter must refresh signed trust status; a cached list cannot prove
that no newer revocation exists. The enforced validity window bounds staleness.

## Hosted identity and mutable data

`HostedModelIdentity` records alias-only, provider-reported and provider-attested
identity separately. Deserializing an attestation claim cannot establish verified
identity. `verify_attestation` authenticates the signed provider contract and
checks its complete subject, observation time and expiry. Changing a copied
identity invalidates the cached verification. Behavioral canaries are drift
signals and never establish immutable model identity.

`LineageIndex` records tenant-local source, chunk, index, cache and memory versions.
Retrieval requires current ACL evidence across the ancestry and records returned
version identifiers, content digests, principal, time and read watermark. Source
withdrawal cascades to derived records; source ACL revocation blocks subsequent
retrieval of derived records. Connect these helpers to the actual datastore's
transaction/snapshot and ACL enforcement APIs. They do not by themselves delete
remote content or authorize access to a live vector database.

## Verification evidence

`tests/test_runtime_authorization.py` exercises signature thresholds, tampering,
wrong identities, changed arguments, schema references, revocation replay,
approval replay, scope mismatches, expiry during adapter execution and durable
rollback/fork rejection. `tests/test_lineage.py` covers source withdrawal,
cross-tenant rejection, ACL revocation and hosted identity verification boundaries.
These fixtures establish local contract behavior, not a production penetration
test or a comparative security benchmark.
