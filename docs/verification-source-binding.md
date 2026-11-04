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
[random key material](#the-operator-binding-key) during collection and validation.
Records then also carry `static_value_binding`, an HMAC-SHA256 under a key
[derived from that key](#the-operator-binding-key) over the original server object
(profile `nexus-symbiote/mcp-static-values/v1`), and a key identifier. This detects a different package with the same version, changed
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

## The operator binding key

MCP and A2A collection read the same key from `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`.
It must be random key material written as hexadecimal, two digits per byte: at
least 64 digits for 32 or more bytes. Generate it; never compose one or use a
passphrase:

```sh
python -c 'import secrets; print(secrets.token_hex(32))'
```

`openssl rand -hex 32` works as well. Letter case does not matter: the key is the
bytes that the hexadecimal digits encode.

Every BOM carries the key identifier, and a binding over a public agent card is
computed from known input, so either one lets anyone holding the BOM test guesses
for the key offline. A recovered key would then confirm guesses for secrets inside
the bound declarations and forge bindings. Two measures make guessing harder, and
neither makes a guessable key safe:

- Collection rejects keys that are not hexadecimal, including base64, base64url and
  passphrases typed as text; fewer than 64 hexadecimal digits or an odd number of
  them; and surrounding whitespace or line breaks. It also rejects decoded bytes that are
  evidently not random: UTF-8 text, such as a hex-encoded passphrase; fewer than 20
  distinct byte values; a repeated 8-byte block; or 8 bytes that change by a
  constant step, like a counter. Together these rules reject fewer than one random
  32-byte key in a billion. They cannot recognize every non-random key: the
  SHA-256 hash of a passphrase, for example, passes.
- Bindings and the key identifier use a key derived from the operator key with
  PBKDF2-HMAC-SHA256 and 600,000 iterations, computed once per process. Each
  offline guess therefore costs that derivation instead of a single HMAC, which
  slows a search but still confirms a passphrase from a short list of likely
  candidates.

An invalid key fails collection with a message that names the variable and never
contains the key. The A2A and MCP collectors each report it once and keep the
unbound declarations, servers and tools in the inventory:

```text
NEXUS_SYMBIOTE_SOURCE_BINDING_KEY is not valid random key material; A2A declarations were not bound
NEXUS_SYMBIOTE_SOURCE_BINDING_KEY is not valid random key material; MCP server declarations were not bound
```

Moving from an older key to a new one changes every binding: recollect the
baseline and its candidates with the new key. Earlier builds used the key without
deriving one from it, so their snapshots carry a different key identifier and
need recollection as well.

## Upgrade existing snapshots

Older static MCP snapshots lack the source binding and configured tool locators.
They cannot establish this stronger reconciliation contract. Missing or unknown
binding profiles fail validation and require recollection; copying a newly
calculated digest into an old approved snapshot is not a migration. The same
applies to A2A snapshots without a binding, and to snapshots bound under a key
that collection no longer accepts.

```sh
nexus-symbiote scan /path/to/project --no-project-policy --report-only -o candidate.json
nexus-symbiote validate candidate.json --no-project-policy --project /path/to/project
nexus-symbiote diff reviewed.json candidate.json --json-output --fail-on-alert
```

`scan` writes the candidate whether or not its gate passes; `--report-only` only
returns exit status 0 instead of 1, so a script that stops on failure continues
to `validate` and `diff`. It does not approve that candidate. Review the diff and
coverage, resolve failed or unknown checks, and independently authenticate any
replacement approval.

Static configuration and served descriptors are separate observation scopes.
Live candidates whose served descriptors differ from the declaration need their
own authenticated review; passing one scope does not establish the other.

The regression cases in `tests/test_mcp_source_binding.py` cover changed source,
edited supplied descriptors, missing legacy evidence, redaction and canonical
object-key ordering. These cases test the stated contract, not detection efficacy
across an independently sampled population of agent deployments.

## A2A cards and clients

Static A2A cards and client entries bind their entire original declaration using
RFC 8785 and HMAC-SHA256 under the key derived from
`NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`. The profile is
`nexus-symbiote/a2a-static-values/v1`; the HMAC input includes the declaration kind
(`agent-card` or `client`). Endpoints continue to expose only their origin.
Credentials and other authentication values, endpoint paths, queries, fragments,
scheme definitions and skill metadata are covered only by the keyed input; the
export keeps origins, recognized scheme identifiers, requirement names and scopes.
Object-key ordering and whitespace are insignificant; array order is retained
conservatively. The binding is a measurement for comparison, not a publisher
signature or evidence of effective endpoint authentication.

Use the same operator key for the reviewed baseline, candidates and project-backed
validation/risk checks; `diff` itself does not read the key. The key must be
[random key material](#the-operator-binding-key) and stay outside the scanned
checkout. Without a valid key, inventory output remains available but A2A value
coverage is partial and default gates fail; use `--report-only` for inspection.
`diff --fail-on-alert` requires review even when both unbound snapshots look
identical. Missing legacy bindings, malformed values, incompatible profiles and
key rotation require recollection and review. They cannot establish an unchanged
A2A declaration.

Keyed binding canonicalizes each declaration with RFC 8785, which accepts I-JSON
only. A YAML date or timestamp, an integer beyond 2^53, a YAML `.nan` or `.inf`, a
JSON number too large for a double such as `1e400`, or JSON nesting too deep to
canonicalize, in a card or client entry, fails that declaration alone, and the
other cards and clients are still collected:

```text
<file>: A2A declaration cannot be canonicalized for binding
```

A file that cannot be parsed fails as a whole, with every entry in it, with or
without the key: JSON with a `NaN` or `Infinity` literal, a duplicate key or
nesting too deep to parse, and YAML with a non-string or duplicate key, an
anchor, alias or tag, more than 20,000 tokens or nesting too deep to parse. Each
card file and client configuration is read separately, so the entries in other
files are still collected.
The MCP collector does the same for a server declaration, such as one with a
lone surrogate in an environment value or an infinite Codex timeout; the other
servers are still collected:
```text
<file>: MCP server declaration cannot be canonicalized for binding
```
Client configurations (`a2a.json`, `a2a.yaml`, `a2a.yml`, `a2a_config.json`) may
list entries under `clients`, `remoteAgents` or both. Every entry in either list
is collected and bound separately. Any other top-level field with a value is
recorded as unknown coverage, because the collector cannot tell how it changes
the clients. An entry names its agent with `name` or `agentName` and its endpoint
with `agentCardUrl`, `url` or `endpoint`; a `null` client field counts as absent.
A client may use any of these URLs, so each one is checked: a URL that is not
`https://` raises a high transport finding, and the origin of the first one is
exported as `agent_card_url`. A client exports only recognized authentication
scheme identifiers, compared without regard to case, spaces, hyphens or
underscores: `bearer`, `basic`, `digest`, `apiKey`, `oauth2`, `openIdConnect`
(`oidc`), `mutualTLS` (`mtls`), and the anonymous forms `none`, `public`,
`anonymous`, `noauth`, `unauthenticated` and the empty string. Any other value,
such as a token, is exported as `[unrecognized]` and recorded as unknown
coverage; the value itself stays inside the keyed input. A missing, anonymous or
unrecognized method raises an authentication finding.

The collector interprets legacy `authentication.schemes`, the A2A 0.3
[`security` alternatives](https://a2a-protocol.org/v0.3.0/specification/#55-agentcard-object-structure)
and A2A v1 `securityRequirements`. An empty list or an empty alternative permits
anonymous use and does not establish required authentication, and so does a
legacy scheme named `none`, `public`, `anonymous`, `noauth`, `unauthenticated` or
the empty string, compared without regard to case, spaces, hyphens or
underscores. Only these names are anonymous: any other legacy scheme name, and
any other `scheme` of an `http` definition, such as `guest` or `anon`, counts as
requiring credentials. Client methods are checked against an allowlist instead,
so an unrecognized one is unknown coverage. Applying that allowlist to legacy and
`http` scheme names would make every unlisted name unknown coverage and fail the
default gates; whether to do so remains a maintainer decision. A card can declare
several of these forms for different clients: if any card-level form permits
anonymous use, authentication is not required. A card that declares no
card-level form does not require authentication. Card-level requirements of both
versions are recorded together in `security_requirements`. Skill-level
requirements of either version add requirements for that skill; the card-level
requirement applies to every request, so they never relax it. They are recorded
in `skill_security_requirements`, keyed by skill identifier, so a skill that
declares requirements needs a unique `id`, and an unsupported skill-level form is
recorded as unknown coverage.

An unsupported form leaves the requirement unknown coverage: an A2A 0.3 or v1
requirement that names a scheme missing from `securitySchemes`, or a scheme
whose definition is not one of `apiKey`, `http` with a non-anonymous scheme,
`oauth2`, `openIdConnect` or `mutualTLS` (in the 0.3 `type` form or the v1
ProtoJSON form); a legacy `authentication` value that is not a mapping, has other
fields but no scheme list, or lists something other than strings; and a
`security` value of any other shape. Such cards stay in the inventory. Scheme
definitions are checked for their type, not for completeness: an `oauth2`
definition without `flows`, or an `apiKey` definition without `in` and `name`,
counts as requiring credentials. Recording an incomplete definition as unknown
coverage instead remains a maintainer decision. This collector is not a complete
A2A protocol conformance validator.

A `null` optional or authentication field counts as absent: `version`, `url`,
`additionalInterfaces`, `preferredTransport`, `security`, `securityRequirements`,
`securitySchemes` and `authentication` on a card, and `id`, `security` and
`securityRequirements` on a skill. A `null` card `name`, `skills`, `protocols` or
`supportedInterfaces`, or a `null` skill `name`, fails collection of the card. A
card that uses both spellings of one field fails collection even when one of them
is `null`.

The origins and transports of a card's A2A 0.3 `url` (with `preferredTransport`)
and `additionalInterfaces` are recorded in `legacy_interfaces`, also when the card
declares v1 `supportedInterfaces`, because 0.3 clients still route on them. They
are part of the HTTPS check, and a change raises a high-severity drift alert, like
a change to `supported_interfaces`. a2a-python 0.3 also accepts and routes on the
field names `additional_interfaces` and `preferred_transport`, so either spelling
is read, as for the ProtoJSON spellings of v1 fields; a card that uses both
spellings of one field fails collection. A gRPC interface may use the `host:port`
address form that A2A v1 specifies. The address does not say whether the channel
uses TLS, so it is exported as `grpc://host:port` with `"tls": "undeclared"` and
raises a medium transport finding. Otherwise only an `https://` URL, or a
`grpcs://` URL on a gRPC binding, counts as TLS; any other URL raises a high
transport finding. An explicit `grpc://` URL conventionally means plaintext, and
an HTTP binding such as `JSONRPC` or `HTTP+JSON` needs an `https://` URL.
Interface and client URLs containing whitespace or control characters fail
collection of their card or client entry, because URL parsing would silently drop
them and record a different host.

`tests/test_a2a_source_binding.py` exercises the CLI gates, same-origin path and
authentication changes, both client lists, client authentication export,
canonicalization, redaction, key requirements and stretching, loss and rotation,
and legacy snapshots. `tests/test_a2a_v1_cards.py` covers v1 and legacy
interfaces in both spellings and the authentication requirement forms, including
v1 requirements checked against `securitySchemes`. The cases in both files are
also required against the installed release wheel.
