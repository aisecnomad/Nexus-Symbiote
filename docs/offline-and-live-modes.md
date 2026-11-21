# Offline and live modes

Nexus SymBiote runs **offline by default**. Three commands can observe something
outside your local files, and only when you ask for **live mode** explicitly.

## Why

- **Inventory runs on untrusted input.** A scan reads repositories, model files and
  reports that an attacker may control. If collection could resolve a host name or
  open a connection, a crafted file could turn a scan into DNS or HTTP exfiltration
  from your CI runner. Offline-by-default removes that path.
- **Air-gapped and regulated environments need a statement they can rely on.**
  "This command makes no network connections and starts no processes" is enforced
  at run time and covered by tests rather than asserted only in documentation.
- **Some evidence only exists live.** The tools an MCP server actually serves, and
  the advisories published today, cannot be read from a checkout. Live mode makes
  those observations available without making them implicit.

## What

| | Offline (default) | Live (`--live` or `NEXUS_SYMBIOTE_MODE=live`) |
|---|---|---|
| Name resolution, network connections | Refused | Allowed for the three live commands only |
| Starting processes | Refused | Not guarded for the three live commands; only `verify-live` is designed to start processes (its pinned launchers) |
| `discover-mcp`, `advisories`, `verify-live` | Refused with exit 2 and a hint | Run |
| Every other command | Runs | Runs, **still offline** |

The three live commands, and what each one contacts:

| Command | What it reaches | Safeguards (in addition to live mode) |
|---|---|---|
| `discover-mcp` | The HTTPS MCP endpoint you name | Exact `--allowed-origin` match; HTTPS only; destination pinned to one public IP address (private, loopback, link-local, site-local, NAT64, 6to4, Teredo, documentation and other special-purpose addresses are refused by an explicit list, whatever the Python version's address tables say); no proxies or redirects; `SSLKEYLOGFILE` is ignored, so no TLS session secrets are written; bounded size and time; never calls a tool; the bearer token is read from `--token-env` and never written to evidence; the report and `--record` inventory show the endpoint as its origin and a digest of the full URL, and only the `--raw-descriptors` review file holds the path |
| `advisories` | `https://api.osv.dev/v1/querybatch` | Same pinned HTTPS transport; exact `pkg:pypi`/`pkg:npm` package URLs only; sends each package's ecosystem, normalized name and exact version and nothing else, including packages resolved from a private registry unless you exclude them: `--exclude` withholds names, `--exclude-private-origins` sends only packages whose lockfile records a public registry (the PyPI origin of a Python package that no `uv.lock` or `poetry.lock` resolves is assumed, not recorded, so it withholds every such package; to keep public packages checked, withhold private names with `--exclude` instead), `--dry-run` previews; at most 500 packages, 10,000 advisories per package and 20,000 in total, and a 120-second total budget that is also checked while a reply is read; no response text copied into the report |
| `verify-live` | The operator-pinned stdio launchers in `--launch-policy` | The policy file must live outside the project and outside every repository that encloses the project or the inventory, including the repository around a nested checkout such as a submodule, be a single-link file owned by you or root that only its owner can write, in directories up to the file system root owned by you or root that others cannot write unless they are sticky ([launch policy](cli-reference.md#launch-policy)); each launcher is an absolute path with a SHA-256 pin; a private copy is executed with an environment that holds only a default `PATH`, no project arguments and no project working directory; 20-second deadline; never calls a tool; servers reached over HTTP are reported as not verifiable here |

**Mode selection.** A `--offline` or `--live` flag (placed before the command) wins;
otherwise `NEXUS_SYMBIOTE_MODE` decides; otherwise the mode is offline. An
unrecognized value such as `NEXUS_SYMBIOTE_MODE=LIVE` is an error (exit 2), not a
fallback, so a typo can neither enable live mode nor hide a request for it. Passing
both flags is also an error. A project's `.nexus-symbiote.yaml` can never select the
mode, because it is part of the checkout being inventoried.

## How

### Use it

```bash
nexus-symbiote scan . -o agentbom.json             # offline, the default
nexus-symbiote --offline scan . -o agentbom.json   # the same, stated explicitly

nexus-symbiote --live advisories agentbom.json -o advisories.json
nexus-symbiote --live discover-mcp https://mcp.example.com/mcp \
  --allowed-origin https://mcp.example.com --token-env MCP_TOKEN -o observed.json

export NEXUS_SYMBIOTE_MODE=live                    # for a CI job that runs live steps
nexus-symbiote advisories agentbom.json -o advisories.json
```

`advisories --dry-run` lists the package identities it would send and contacts
nothing, so it also runs offline.

Mode flags go **before** the command. Running a live command offline exits with
status 2 and tells you how to enable live mode:

```text
$ nexus-symbiote advisories agentbom.json
Error: advisories is a live command: it queries the OSV vulnerability API (api.osv.dev)
over HTTPS. Commands run offline by default. Re-run with --live before the command
(nexus-symbiote --live advisories ...) or set NEXUS_SYMBIOTE_MODE=live.
```

The GitHub Action runs `scan`, `validate`, `risk` and, with `reviewed-baseline`,
`diff`; the pre-commit hooks run `scan --check`. These commands are always offline,
so they need no configuration.

### Detect drift on a remote MCP server

A remote server can change its tools without any change to your repository, so a
static scan cannot see it. `discover-mcp --record` turns one complete observation
into a native AgentBOM inventory, and `diff` compares two of them:

```bash
# Once: record a baseline, review it, and keep it where the change under review cannot edit it.
nexus-symbiote --live discover-mcp https://mcp.example.com/mcp \
  --allowed-origin https://mcp.example.com --token-env MCP_TOKEN \
  --record -o tickets.baseline.json

# On a schedule: observe again and fail on drift.
nexus-symbiote --live discover-mcp https://mcp.example.com/mcp \
  --allowed-origin https://mcp.example.com --token-env MCP_TOKEN \
  --record -o tickets.today.json
nexus-symbiote diff tickets.baseline.json tickets.today.json --fail-on-alert
```

The inventory holds one `mcp-server` component for the endpoint (its `bom_ref` is
derived from the endpoint, or set with `--server-ref`) and one `tool` component per
served tool, all with `observed` assurance. The server records the negotiated
protocol version, the server's name and version, its declared capabilities and a
digest of its whole `serverInfo` and capabilities (`observed_identity_hash`), its
`instructions` (redacted for display) and a digest of them, and, when the server
declares them, its prompts and resource templates. Each tool carries the same
`rfc8785-jcs-v2` fingerprint that static collection uses, which covers `title`,
`outputSchema` and `_meta` when the server sends them.

`diff` raises a **critical** alert when a tool definition changes, when the served
tool set changes, and when the instructions, a prompt, a resource template or a
descriptor member outside the fingerprint profile (such as `icons`) changes. A new
server version or capability set is a high alert, because it changes the identity
digest (`observed_identity_hash`), and a new protocol version alone is a medium
alert; both fail `--fail-on-alert`. An incomplete observation writes no inventory and
exits 1, so a scheduled job cannot record a partial result as a baseline. When a
tool's displayed descriptor omits schema literals or reduces URLs that the
fingerprint covers, the command names the tool on standard error: inspect the
server's original descriptor before you approve that baseline.
`--raw-descriptors review.json` writes that original content (server info,
capabilities, instructions, tool descriptors, prompts and resource templates, with
only the bearer token masked) to a new file readable only by you; it
can hold credentials the server embeds, so keep it out of the baseline and delete it
after review. The server chooses its session ID, so the ID is never masked: a
declaration that repeats a session ID of eight or more characters ends the
observation, while a shorter session ID that the server repeats is exported in the
inventory and in the review copy. The check matches exact text, so the ID repeated in
another case or as a JSON number is not caught. A scheduled GitHub Actions job is a `schedule:` workflow that runs the
two commands above against a baseline committed after review, with the token in a
repository secret.

### Verify pinned stdio servers

Before running `verify-live`, unset the cloud, registry or API credential variables
named in its refusal. The launcher starts with a cleared environment. On an
operator-controlled host, `--allow-host-credentials` acknowledges the credentials
still held by the parent process. The launch policy and isolation checks still apply.

`verify-live` starts each stdio server that the inventory names, but only through
an operator launch policy: a JSON object that maps the server's `bom_ref` in the
inventory to an absolute launcher path and its SHA-256 pin.

```json
{"mcp-server:3f6c...": {"command": "/opt/mcp/weather-server", "sha256": "sha256:9b1e..."}}
```

Find the references with
`jq '.components[] | select(.component_type == "mcp-server") | {bom_ref, name, transport}' agentbom.json`.
`--project` names the untrusted checkout and is required. Servers whose transport
is `sse`, `streamable-http` or `http` and that record no launch command are listed as
`not-verifiable` with reason `remote-transport` and do not make the run fail; use
`discover-mcp --record` for them. Such a server that records a launch command, which
a client may start, fails with reason `ambiguous-transport` unless the launch policy
names it; one that the launch policy names is verified through its pinned launcher. A
server with any other transport label fails with reason `unsupported-transport`. A
run with no stdio server verifies nothing and exits 1. Each failed server carries a
reason: `missing-launch-policy`, `invalid-launch-policy`, `launcher-unavailable`,
`launcher-digest-mismatch`, `launcher-start-failed`, `isolation-unavailable`,
`isolation-teardown-failed`, `deadline`, `unsupported-protocol-version`, `protocol`,
`invalid-descriptor`, `ambiguous-approved-tools`, `ambiguous-transport`,
`unsupported-transport` or `internal-error`. The 20-second deadline covers each server's MCP exchange and the
checks of the descriptors it served. The JSON report also records the SHA-256 of
the inventory and of the launch policy, and each launcher's pin.

The server's instructions, prompts, resource templates and descriptor members
outside the fingerprint profile are compared with the digest that a previous
`--record` stored on the server (`observed_declaration_hash`); when the inventory
has no such digest and the server serves any of them, they are reported as `new`
drift, like an unapproved tool. The server's whole `serverInfo` (name, version and
any other member) and its declared capabilities are compared with the identity
digest a previous `--record` stored (`observed_identity_hash`): a difference is
drift (`identity_status: changed`); without a stored digest the status is
`unrecorded`. `--record` prints an unsigned candidate inventory with the observed
descriptors. When tools or declarations changed or are new, or the server identity
changed, it names them on standard error, stores each replaced fingerprint as
`previous_definition_hash`, and exits 1 unless you pass `--accept-drift`, so a
scripted baseline refresh cannot silently absorb a rug pull.

### What a live observation does not cover

An observation is a point-in-time declaration by the server, not proof of what the
tools do. Neither live command observes tool implementations or backend behavior,
`resources/list` entries or resource contents, prompt messages (`prompts/get`),
authorization metadata, or changes after the session. A server can tell an observer
apart and answer it differently: `discover-mcp` sends no `User-Agent` and the
`clientInfo` name `nexus-symbiote-discovery` unless you set `--client-name`,
`--client-version` and `--user-agent` to match your production host, and
`verify-live` starts launchers with no arguments, a private working directory and an
environment that holds only a default `PATH`. Both negotiate MCP 2025-11-25,
2025-06-18, 2025-03-26 or 2024-11-05 through `initialize`; a server that offers
none of them, or only a revision without `initialize`, is reported as refused.
Server-sent event replies may use chunked transfer coding; one event line may use
the whole 1 MiB response limit. Streams that the server closes before the reply
(SSE resumption) are not resumed and end the observation as incomplete. A served
descriptor must fit a 256 KiB, 32-level, 20,000-node budget before its JSON Schema
is checked. `type`, `required`, `dependentRequired` and `dependencies` arrays
longer than 64 items that hold anything other than strings are refused before
checking, because the check would compare their items pairwise, and each object in
a `dependencies` map is checked on its own, so an invalid schema is refused at its
first error.

### How offline mode is enforced

For the duration of an offline command, the CLI replaces these Python entry points
with functions that raise `OfflineViolation`:

- `socket.socket` methods: `connect`, `connect_ex`, `listen`, `sendto`, `sendmsg`;
- name resolution: `getaddrinfo`, `gethostbyname`, `gethostbyname_ex`,
  `gethostbyaddr` and `getnameinfo`, in both `socket` and `_socket`;
- `socket.create_connection` and `socket.create_server`;
- process creation: `subprocess`, `os.system`, `os.fork`, `os.forkpty`,
  `os.posix_spawn`, `os.posix_spawnp`, `os.execv`, `os.execve`, and
  `_posixsubprocess.fork_exec` together with the reference that `subprocess`
  keeps to it;
- subinterpreter creation (`_interpreters.create`, named `_xxsubinterpreters.create`
  on Python 3.12), because a subinterpreter has its own audit hooks and modules and
  would escape the guard.

`OfflineViolation` derives from `BaseException`, so a collector's broad
`except Exception` cannot turn it into a recorded, soft failure. The command stops
with exit status 1 and asks you to report a defect; a scan stops before it writes
its inventory. The original functions are restored when the command ends.

The C socket type (`_socket.socket`, also named `socket.SocketType`) is immutable
and cannot be patched, so a CPython audit hook raises the same `OfflineViolation`
while an offline command runs. It refuses creating any socket other than a
Unix-domain socket. An internet socket therefore cannot be opened during the
command, and the name resolution that `connect`, `sendto` and `bind` perform for a
host-name address never starts on one. Creating Unix-domain sockets and socket
pairs is allowed, so asyncio's event loop and `send` and `recv` on a socket pair keep
working, but `connect`, `listen`, `sendto` and `sendmsg` are refused for every
socket family, Unix-domain included. When urllib3 is installed, the CLI imports
`urllib3.util.connection` before the guard starts: that import tries to bind an IPv6
socket to `::1` to detect IPv6 support, reaches no network, and would otherwise stop
Sigstore's offline verifier, which imports urllib3. The hook also refuses the
`socket.connect`, `socket.sendto` and `socket.sendmsg` events, the name resolution
events and the process creation events. CPython raises these events inside the C
implementations, so they also cover references to those functions captured before
the command started. `_posixsubprocess.fork_exec` raises no audit event: only its
two module attributes listed above are replaced, so another reference to it
captured earlier is not covered. An audit hook cannot be removed, so it stays
installed and is inert outside an offline command.

The test suite runs every static command through the CLI with this guard in place,
and checks that Sigstore's offline verifier (used for signature checks) loads its
embedded trust root without network access.

### Limits

The guard is a tripwire for this package and its Python dependencies, **not a
sandbox**. Native code that calls the operating system directly bypasses it, and
a process started by `verify-live` is not covered at all. Live mode removes the
whole guard for the three live commands, although `advisories` and `discover-mcp`
never need a process and the `verify-live` parent never needs the network. A socket
created before the command started is not affected by the creation check: code that
holds one can still accept or use an existing connection, because `listen`, `accept`,
`send` and `recv` raise no audit event, and its `bind`, `connect` or `sendto` on a
host-name address still resolves the name before any refused event fires. A
descriptor opened earlier can also be wrapped during the command by declaring a
Unix-domain family. No code from the scanned project runs inside the process, so
these limits concern deliberate in-process evasion, not crafted input. Where you need
a hard boundary, add an operating-system control as well: a network namespace (for
example `unshare --net --map-root-user`), a container started with
`--network none`, or a deny-all egress policy. Run `verify-live` launchers under an
isolated identity with a restricted filesystem and egress, as described in the
[security model](security-model.md).

### Try it without network access

The repository contains a synthetic agent project at
[`examples/demo-agent`](../examples/demo-agent) and a recorded ShadowScan report.
From a checkout:

```bash
nexus-symbiote scan examples/demo-agent -o demo.aibom.json
nexus-symbiote summary demo.aibom.json
nexus-symbiote import-shadowscan tests/fixtures/shadowscan/code-report-0.1.4.json \
  --report-only -o imported.aibom.json
```

See [`examples/README.md`](../examples/README.md) for the full walkthrough.
