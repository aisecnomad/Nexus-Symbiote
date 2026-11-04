# Reconcile a BOM with its MCP and A2A declarations

`validate --project` checks a supplied inventory against freshly collected local
evidence. Static MCP server records carry two kinds of source binding.

`static_config_hash` (profile `nexus-symbiote/mcp-static-config/v2`) is an RFC 8785
digest of the server's structure: configuration field names, the displayed
launcher, transport, endpoint origin, argument count, environment variable names
and declared tool names. It covers only information the inventory already exports
in clear, so it reveals nothing about secret values. It detects added or removed
arguments, environment variables, fields and tools, and changed endpoint origins.

Values are bound only when the operator sets `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` to
a secret of at least 32 characters during collection and validation. Records then
also carry `static_value_binding`, an HMAC-SHA256 under that key over the original
server object (profile `nexus-symbiote/mcp-static-values/v1`), and a key
identifier. This detects a different package with the same version, changed
arguments, environment values, endpoint paths and opaque launchers. The key never
enters the BOM; without it, the binding cannot be used to test guesses for a
secret. Keep the key in the CI secret store, use the same key for a baseline and
its candidates, and rotate it by recollecting both. A keyed BOM validated without
the key, or with a different key, fails reconciliation.

Profile v1 records (an unkeyed digest over raw configuration, including secret
values) let anyone holding the BOM confirm guesses for low-entropy secrets. They
fail reconciliation as unknown and require recollection; treat existing v1 exports
as sensitive and replace them. Neither binding authenticates a publisher,
identifies the installed executable or establishes that a tool backend is benign.
JSON object-key ordering and whitespace do not change either binding.

Configured tool entries retain their configuration source path and static
collection mode. Validation compares their descriptor digest, fingerprint
version and server reference with a fresh collection. Recomputing the digest of
an edited supplied descriptor establishes only self-consistency and cannot make
it match a different local declaration. An asserted live-observation claim does
not substitute for the static configuration evidence.

## Upgrade existing snapshots

Older static MCP snapshots lack the source binding and configured tool locators.
They cannot establish this stronger reconciliation contract. Missing or unknown
binding profiles fail validation and require recollection; copying a newly
calculated digest into an old approved snapshot is not a migration.

```sh
nexus-symbiote scan /path/to/project --no-project-policy --report-only -o candidate.json
nexus-symbiote validate candidate.json --no-project-policy --project /path/to/project
nexus-symbiote diff reviewed.json candidate.json --json-output --fail-on-alert
```

`--report-only` allows collection of a candidate despite policy findings. It does
not approve that candidate. Review the diff and coverage, resolve failed or
unknown checks, and independently authenticate any replacement approval.

Static configuration and served descriptors are separate observation scopes.
Live candidates whose served descriptors differ from the declaration need their
own authenticated review; passing one scope does not establish the other.

The regression cases in `tests/test_mcp_source_binding.py` cover changed source,
edited supplied descriptors, missing legacy evidence, redaction and canonical
object-key ordering. These cases test the stated contract, not detection efficacy
across an independently sampled population of agent deployments.

## A2A cards and clients

Static A2A cards and client entries bind their entire original declaration using
RFC 8785 and HMAC-SHA256 under `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`. The profile is
`nexus-symbiote/a2a-static-values/v1`; the HMAC input includes the declaration kind
(`agent-card` or `client`). Endpoints continue to expose only their origin.
Authentication declarations, endpoint paths, queries, fragments, credentials,
scheme definitions and skill metadata stay inside the keyed input. Object-key
ordering and whitespace are insignificant; array order is retained conservatively.
The binding is a measurement for comparison, not a publisher signature or evidence
of effective endpoint authentication.

Use the same operator key for the reviewed baseline, candidates and project-backed
validation/risk checks. The key must have at least 32 characters and stay outside
the scanned checkout. A short key fails collection. Without a key, inventory
output remains available but A2A value coverage is partial and default gates fail;
use `--report-only` for inspection. `diff --fail-on-alert` requires review even
when both unbound snapshots look identical. Missing legacy bindings, malformed
values, incompatible profiles and key rotation require recollection and review.
They cannot establish an unchanged A2A declaration.

The collector interprets legacy `authentication.schemes` and the A2A 0.3
[`security` alternatives](https://a2a-protocol.org/v0.3.0/specification/#55-agentcard-object-structure).
An empty alternative permits anonymous use and does not establish required
authentication. Unsupported authentication forms remain unknown coverage. This
collector is not a complete A2A protocol conformance validator.

`tests/test_a2a_source_binding.py` exercises the CLI gates, same-origin path and
authentication changes, canonicalization, redaction, key loss/rotation and legacy
snapshots. These cases are also required against the installed release wheel.
