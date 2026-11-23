# Security policy

Nexus SymBiote is alpha Agent Bill of Materials (AgentBOM) tooling (not related to the 2022 Linux malware *Symbiote*). Inventory, signature verification, and policy decisions are distinct: a clean scan or low risk score never proves that an agent, model, dataset, or tool is benign.

## Reporting a vulnerability

Report security defects privately through GitHub's **Security → Report a vulnerability** form: [open a private advisory](https://github.com/aisecnomad/Nexus-Symbiote/security/advisories/new). Never place credentials, private inventories, exploit details, or customer data in a public issue.

- **Include:** Affected commit or package version, OS and Python version, minimal synthetic reproduction steps, expected vs. observed behavior, and the trust boundary crossed.
- **Timelines (best effort, single maintainer):** Acknowledgement target of 7 days; coordinated disclosure default of 90 days (or earlier upon fix release, or another mutually agreed date). Fixes ship as a new version named in the advisory.
- **Fallback if unanswered:** No second security contact exists yet ([continuity](GOVERNANCE.md#continuity)). If a report goes unacknowledged for 7 days (or the form is unavailable), open a public issue titled `"Security report awaiting acknowledgement"` with only the report date and zero technical details.
- **In scope:** Any bypass of a documented guarantee — a gate passing when it must fail, collection executing code / reaching the network / reading outside the scan root, secret leakage into inventories/logs/exports, or terminal/CI log injection. New bypass consequences of public [known limitations](docs/known-limitations.md) are also in scope.

## Supported versions

| Version | Supported |
| --- | --- |
| Latest release on PyPI and `main` HEAD | Yes — security fixes ship as the next release |
| Earlier releases | No — upgrade to the newest release |

Only the latest alpha revision is maintained (no LTS window). Verify release attestations and source revisions before installing published distributions.

## Security boundaries

### Static collection and confinement

- **No execution:** Static collectors never execute project code, model loaders, repository hooks, or MCP launchers. Treat repositories, model files, tool metadata, lockfiles, imported BOMs, attestations, and OTLP traces as hostile input; run scans read-only without deployment or publication credentials.
- **Fail-closed limits:** Every [collection limit](docs/collection-limits.md) is operator-controlled (`--limit` or `NEXUS_SYMBIOTE_LIMITS`) and fails closed when exceeded; checked-in project files cannot raise limits.
- **Native parsing:** TypeScript/JavaScript files referencing the MCP SDK are parsed in-process with `tree-sitter` under size, node, and time bounds. Because native parser memory-safety bugs would run with scan privileges, scan untrusted repositories in an isolated worker.
- **POSIX confinement & hard links:** Confined reads require POSIX descriptor-relative (`dir_fd`) and `O_NOFOLLOW` primitives and fail closed where unavailable ([platforms](#platforms)). Hard links inside the scan root are regular files and are hashed normally; run collection with content-author privileges (never root) on hosts with `fs.protected_hardlinks=1`, and unpack untrusted archives with link-safe extractors (GNU `tar` or Python `tarfile` with `filter='data'`).

### Imported discovery evidence

Treat ShadowScan reports, foreign CycloneDX/SPDX imports, A2A cards, IDE settings, and extension manifests as untrusted declarations. Never grant deployment or publication credentials to import jobs.

- Require signed ShadowScan reports via an out-of-checkout operator signature policy passed to `validate --project` / `risk --project` ([ShadowScan CI guide](docs/shadowscan-integration.md#require-a-signed-report-in-ci)) or `validate.require_discovery_signature: true`.
- Without same-run producer verification, `import-shadowscan`, `validate`, and `risk` treat discovery evidence as unverified — warning locally and failing in CI (`CI` / `GITHUB_ACTIONS`) unless `--allow-unsigned-discovery` is explicitly passed.
- Offline Sigstore verification trusts only a user-private cached trust root or an explicit `--trust-root` / `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT` (optionally SHA-256 pinned; see [signature limits](docs/known-limitations.md#signatures)).

### Live verification isolation (`verify-live`)

`verify-live` explicitly executes operator-approved stdio MCP launchers and never invokes tools:

- **Operator launch policy:** Must reside outside the scanned project and any enclosing repository, be owner-writable only, and pin exact executable SHA-256 digests ([launch policy](docs/cli-reference.md#launch-policy)). Approved bytes are staged privately with cleared environment (default `PATH` only), private working directory, and no project arguments.
- **Default PID-namespace containment (Linux):** Runs the launcher as PID 1 inside `unshare --user --map-root-user --pid --fork --kill-child`, synchronized via a minimal `-I -S` exec wrapper so cleanup holds a `pidfd` before launcher code runs. Teardown sends `SIGKILL` through the `pidfd` and waits (5 s timeout) for the entire namespace tree to exit, failing with `isolation-unavailable` or `isolation-teardown-failed` otherwise. Inside the namespace the launcher sees uid/gid 0 mapped to the caller (no extra host privilege); hosts blocking unprivileged user namespaces (e.g., Ubuntu 24.04 AppArmor restrictions) fail closed with `isolation-unavailable`.
- **Linux opt-out (`--no-isolation` / `isolation_off()`):** Uses a Linux-only `PR_SET_CHILD_SUBREAPER` wrapper (non-dumpable, signals ignored) to adopt and kill all descendants (including `setsid` double-forks and `CLONE_PARENT` children) via `/proc` tree sweeps and, where available, a private cgroup v2, failing with `isolation-teardown-failed` if containment cannot be confirmed. Refused off Linux (`isolation-unavailable`).
- **Residual boundaries:** Neither mode is a filesystem, network, or credential sandbox, nor does it terminate processes spawned via external host services (`systemd-run --user`, `at`, D-Bus) or verify the OS/interpreter/shared libraries. Always run `verify-live` in an externally isolated worker. HTTP servers are out of scope for `verify-live`; observe them via `discover-mcp --record` and gate with `diff`.

### Signatures and evidence confidentiality

- A valid signature proves authorized key material signed specific bytes under the verifier's policy — never that content is accurate or safe. Matching tool descriptors never prove backend behavior. Enforcement adapters govern only mediated calls.
- Inventories can expose infrastructure topology, permissions, endpoints, and instruction digests. Restrict access to exported BOMs and keep raw credentials out of BOMs, logs, and issue reports.

## Platforms

| Platform | Status |
| --- | --- |
| **Linux** | Supported. `Verified CI` runs the full test suite on Ubuntu across Python 3.11–3.14. |
| **macOS** | Supported for static collection and gates (`Verified CI` runs the full suite on macOS 15, Python 3.12). `verify-live` and pinned stdio runtime execution fail closed (`isolation-unavailable`), including with `--no-isolation`, because Linux PID-namespace / subreaper containment is absent. |
| **Windows** | Unsupported by design; fails closed. |

Windows lacks POSIX `dir_fd` and `O_NOFOLLOW` primitives needed to prevent symlink/rename TOCTOU races. Every CLI command (except `--help` and `--version`) exits with status `1` (`unsupported platform`) before reading files when POSIX confinement primitives are unavailable. On Windows, run the Linux [container image](docs/container-image.md) (WSL 2 runs Linux but is not tested in CI).

## Known limitations

<a id="known-limitations-in-010"></a>

Gates and `diff` evaluate only what collectors record. Key limits are summarized below; see [known limitations](docs/known-limitations.md) for the complete surface-by-surface catalog:

- **Unrecognized surfaces pass silently.** Files or indirections no collector recognizes (e.g., external tsconfig `paths` aliases, `.vscode/settings.json`, host-level user/managed settings, nested `CLAUDE.local.md`) produce no gap and pass every gate.
- **Value drift requires `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`.** Without it, `diff` cannot detect value-only changes in redacted MCP arguments/env/headers, redacted IDE settings values, or same-host URL paths; keyless inventories raise medium unbound-values alerts instead.
- **Named launcher classification only.** Unclassified commands are recorded as local programs; scripts they invoke are not parsed.
- **Opt-in verification scope.** OpenSSF Model Signing bundles are not verified; ShadowScan producer checks require a bundle or signer policy (failing in CI unless `--allow-unsigned-discovery` is set) and do not bind commit or time; `validate`/`risk` without `--project` check only the inventory's own claims.
- **PR self-weakening risk.** A pull request can edit `.nexus-symbiote.yaml` or its own workflow file. Pass `--no-project-policy` and protect workflows via organization rulesets or code-owner review of `.github/`.
- **0.1.0 baseline migration.** Re-collect baselines generated by 0.1.0; `diff --fail-on-alert` against them fails on format/binding changes.
- **Size bounds, not wall-clock bounds.** Always set CI job timeouts; crafted projects within size limits (especially SPDX exports) can still run for extended periods.
