# Security policy

Nexus SymBiote is an Agent Bill of Materials toolkit. It is not related to Symbiote, the Linux malware of the same name reported in 2022.

Nexus SymBiote is alpha security tooling. Inventory, signature verification, and policy decisions have different meanings. A successful scan or low risk score does not establish that an agent, model, dataset, or tool is benign.

## Reporting a vulnerability

Report security-sensitive defects through the repository's **Security > Report a vulnerability** feature: [open a private report](https://github.com/aisecnomad/Nexus-Symbiote/security/advisories/new). Private vulnerability reporting is enabled for this repository; the report reaches the repository's administrators and stays private until an advisory is published. Do not put credentials, private BOMs, exploit details, or customer data in a public issue.

Include the affected commit or distribution version, platform and Python version, reproduction steps with synthetic inputs, expected and observed behavior, and the trust boundary crossed. Keep real credentials and sensitive agent context out of reproduction artifacts.

**What to expect.** The project has one maintainer and offers best effort, not a service level: an acknowledgement within 7 days, and coordinated disclosure 90 days after the report by default, or earlier once a fixed version is published. The reporter and the maintainer can agree on another date. Fixes ship as a new version, and the advisory names the affected and fixed versions.

**If nobody answers.** There is no second security contact yet ([continuity](GOVERNANCE.md#continuity)). If a private report has no acknowledgement after 7 days, open a public issue titled "Security report awaiting acknowledgement" that gives the report's date and nothing about its content. If the form itself is unavailable, open such an issue asking for a private channel instead; never put details in it.

**Scope.** A way to make a documented guarantee fail is in scope: a gate that passes when it should fail, collection that reads, executes or reaches the network where the documentation says it does not, a secret that reaches an inventory, log or export, or terminal or CI output an input can steer. The [known limitations](docs/known-limitations.md) are tracked publicly; a new consequence of one, such as a bypass the entry does not describe, is still worth a private report.

## Supported versions

| Version | Supported |
| --- | --- |
| The newest release on PyPI, and `main` at its head | Yes: security fixes ship as the next release |
| Any earlier release | No: upgrade to the newest release |

Only the latest reviewed alpha revision is developed. There is no long-term support commitment or established production support window. Confirm release provenance and the matching source revision before installing a published distribution.

## Imported discovery evidence

Treat ShadowScan reports, CycloneDX imports, A2A cards, IDE settings, and extension manifests as untrusted inputs. A discovery record does not grant authority or authenticate the discovered endpoint. Verify the expected subject, signer, tenant, time, and policy before upgrading a claim. Never grant deployment or publication credentials to the import job merely to parse a report.

To require that a merged inventory's ShadowScan evidence comes from a signed report, name the report in an operator signature policy kept outside the checkout and pass it to `validate --project` or `risk --project` ([require a signed report in CI](docs/shadowscan-integration.md#require-a-signed-report-in-ci)). Setting `validate.require_discovery_signature: true` in the project policy also turns the check on. The content digest that `diff` compares detects drift; it does not authenticate a report. Without a producer check in the same run, `import-shadowscan`, `validate` and `risk` treat discovery evidence as unverified: they warn, and fail when a CI variable such as `CI` or `GITHUB_ACTIONS` is set, unless `--allow-unsigned-discovery` is given. The verification outcome the BOM records is unsigned, so it is reported and never trusted. Offline Sigstore verification trusts the cached trust root only when its directories and file are private to the user, or uses an explicit one (`--trust-root`, `NEXUS_SYMBIOTE_SIGSTORE_TRUST_ROOT`), optionally pinned by SHA-256 ([known limitations](docs/known-limitations.md#signatures)).

## Security boundaries

Static collection must not execute project modules, model loaders, repository hooks, or MCP launch commands. Treat repositories, model files, tool metadata, registry records, imported BOMs, attestation envelopes and OpenTelemetry trace files as hostile input. Run scans with read-only access and without deployment or publication credentials.

### Collection confinement

Every bound on what a scan reads fails closed. The [collection limits](docs/collection-limits.md) are operator settings, changed only with `--limit` or `NEXUS_SYMBIOTE_LIMITS`; nothing in the scanned checkout can change them. TypeScript and JavaScript files that name the MCP SDK are parsed inside the scanning process by tree-sitter, which is native code. Size, node and time bounds limit that parse but do not isolate it, so a memory-safety defect in the parser would run with the scan's privileges.

Confined file operations and pinned stdio launchers require POSIX descriptor-relative and no-follow primitives. Unsupported platforms fail closed rather than weakening those checks. Hard links are regular files: a hard-linked file inside the scanned root is read and hashed like any other, so an inventory can describe an inode that also has a name outside the root. Run static collection with the content author's privileges rather than as root, on hosts with `fs.protected_hardlinks=1`, and extract untrusted archives with a tool that refuses link targets outside the destination (GNU tar, or Python `tarfile` with `filter='data'`). Which platforms qualify is under [platforms](#platforms).

### Live verification isolation

`verify-live` is an explicit execution operation. Its operator-owned [launch policy](docs/cli-reference.md#launch-policy) must lie outside the scanned project and every repository that encloses it, be writable only by its owner, and bind exact server references to independently obtained executable SHA-256 pins. It stages the approved bytes privately, passes no project arguments, clears inherited environment variables and sets only a default `PATH`, and uses a private working directory.

By default, it requires the launcher to run as pid 1 of a new user and PID namespace (`unshare --user --map-root-user --pid --fork --kill-child`). That process first runs a short exec wrapper (the running interpreter with `-I -S`, a fixed program and the fixed environment) that waits until `verify-live` holds a pidfd for it and only then executes the staged launcher, so no launcher code runs before cleanup can reach it. When the session ends, cleanup sends the launcher SIGKILL through that pidfd and waits until the kernel has ended every process in the namespace, including nested PID namespaces. It does not rely on `--kill-child`, on the process group or on `unshare`, because the launcher can clear that parent-death signal, leave its group with `setsid` or `setpgid`, and kill `unshare` from a child it leaves in the group. If no namespace init appears within 5 seconds, the server fails with `isolation-unavailable` before the pinned launcher executes; if the namespace has not ended 5 seconds after the SIGKILL, it fails with `isolation-teardown-failed`.

Without a separately runnable interpreter or a kernel that opens pidfds, no pidfd is held, and cleanup stops `unshare` and kills its child instead; a server whose `unshare` was killed by a signal before cleanup, or did not stop within 1 second, then fails with `isolation-teardown-failed`, because the launcher may have outlived it. Only processes in the namespace are ended: one that the launcher has another service start, for example through `systemd-run --user`, `at` or D-Bus activation, is not, and nothing ends the namespace if the calling process is killed before its cleanup runs. Inside that namespace the launcher sees itself as uid 0 and gid 0, which map to the invoking user and group; every other uid and gid, including the owners of the files it reads and its own supplementary groups, appears as the overflow id `nobody`/`nogroup` (65534), and `setgroups` is denied. This grants no privilege outside the namespace, but a launcher that refuses to run as root, inspects its supplementary groups or changes file ownership behaves differently than it did when executed directly. A host that refuses the namespace, including Ubuntu 24.04 with AppArmor's unprivileged-user-namespace restriction, fails with `isolation-unavailable` before the pinned launcher executes. **Without namespace isolation.** The explicit operator option `--no-isolation` permits execution without this boundary and prints a warning; the corresponding library opt-out is `isolation_off()` from `nexus_symbiote.live.pinned_process`.

On that path, on Linux, a short wrapper (the running interpreter with `-I -S`, a fixed program and the fixed environment) sets `PR_SET_CHILD_SUBREAPER`, forks and executes the staged launcher in its child, in its own process group and with the signal dispositions it would otherwise have had, so no Python runs between fork and exec in the calling process. The wrapper ignores every signal it can and is not dumpable, so the launcher can end it only with SIGKILL aimed at it, or by tracing it with `CAP_SYS_PTRACE`. While the wrapper is alive, the launcher's descendants stay in its process tree, including a `setsid` child that double-forks. Cleanup stops the wrapper first, so it stays alive to adopt every orphan, and then every process in its tree, so that none can fork or reap during the sweep; it then kills every descendant it finds, scanning the tree again until a scan finds no new one, so a helper that a watchdog restarts is found as the wrapper's child, then kills each child still running as it is reparented to the stopped wrapper, which also ends a chain that forks faster than the tree is scanned, and kills the wrapper's process group last. The wrapper stays alive as the launcher's parent, so a descendant that outlives the launcher, and a `clone(CLONE_PARENT)` child of it, are adopted by the wrapper and killed with its tree. The wrapper reports that it exited with no child left, then exits with the launcher's status, repeating the signal that killed the launcher as `unshare --fork` does, so a launcher that crashed is not a teardown failure.

When it does not report, because the launcher killed it or a descendant could not be killed, or when cleanup cannot list the wrapper's children, the server fails with `isolation-teardown-failed`: what the wrapper had adopted may still be running, and only a private cgroup v2, where the launch could join one, still reaches it. The report counts only when the kernel credits it to the wrapper's own pid, so a process of the same user that copied the wrapper's end cannot forge it; a launcher running as root, or with `CAP_SYS_PTRACE` or `CAP_SYS_ADMIN`, can, and can also trace the wrapper, so its escape can go unreported. A launcher or descendant can still evade cleanup another way, for example by moving out of that cgroup, and a descendant running as another user cannot be signalled. **Off Linux.** The opt-out is refused: without the wrapper and the `/proc` sweep only the launcher's process group could be killed, so a child that called `setsid` would outlive a session reported as a success. There `--no-isolation` prints that it is refused, and every server fails with `isolation-unavailable` before its launcher executes, as does a launch inside `isolation_off()`.

**Scope limits.** The opt-out is not a PID namespace, and neither form is a filesystem, network or credential sandbox. It invokes no tools. Launcher pins do not authenticate the OS, interpreter, linked libraries or other host dependencies. Execute launchers in an externally isolated worker with resource limits and restricted filesystem, identity and network access. **Recording.** `--record` emits a separate unsigned candidate, not an approval or admission decision; incomplete observations and missing tools fail closed, and changed or new tools, server declarations or server identity make it exit 1 unless `--accept-drift` is given. `verify-live` does not verify servers reached over HTTP; observe them with `discover-mcp --record` and compare the inventories with `diff`.

### Signatures and evidence

A signature proves that authorized key material signed particular bytes under the verifier's policy. It does not prove that the content is accurate or safe. A matching tool descriptor cannot prove that the backend behaves as declared. Enforcement integrations govern only calls actually mediated by those integrations.

### Evidence confidentiality

Agent inventories can expose infrastructure, permissions, endpoints, and instruction fingerprints. Restrict access to exported evidence and review its contents before sharing it. Keep raw credentials out of BOMs, logs, and issue reports.

## Platforms

| Platform | Status |
| --- | --- |
| Linux | Supported. `Verified CI` runs the full suite on Ubuntu with Python 3.11 through 3.14. |
| macOS | Supported. `Verified CI` runs the full suite on macOS 15 with Python 3.12. `verify-live` and pinned runtime execution have no PID namespace there, so they refuse to start the launcher ("kernel PID containment is unavailable"). The opt-out is refused too: `verify-live --no-isolation`, and a launch inside `isolation_off()` in the Python API, fail with `isolation-unavailable` before any launcher executes ([security boundaries](#security-boundaries)). |
| Windows | Not supported, by decision, and failing closed. |

Windows is not supported because confinement opens every path component relative to its parent's descriptor with `O_NOFOLLOW`, and Windows offers neither; emulating them with path strings would reopen the link and rename races those opens close. So that no read, digest or write proceeds with weaker checks, every `nexus-symbiote` command exits with status 1 and `unsupported platform` before it reads anything on a host where `os.name` is not `posix` or `O_NOFOLLOW`, `O_DIRECTORY` or descriptor-relative `open` is missing. `nexus-symbiote --help` and `--version` still answer. The refusal is the CLI's: a program that imports the package on such a host gets failed collections from the confined reader, but no refusal from the package's other file reads. On Windows, run the [container image](docs/container-image.md), which is the Linux build; WSL 2 is Linux too, but no CI job runs there.

## Known limitations

<a id="known-limitations-in-010"></a>

Gates and `diff` compare what the collectors record. These limits matter most; the [known limitations](docs/known-limitations.md) list every limit by surface, with what to do about each.

- **What no collector reads passes every gate.** An MCP server whose source reaches the SDK through an alias resolved outside the file, such as a tsconfig `paths` entry or a `#` subpath import, a settings file the `ide_agents` collector does not recognize, such as `.vscode/settings.json` or a host's user or managed settings, or an instruction file under a name the `prompt` collector does not read, such as a nested `CLAUDE.local.md`, is not a coverage gap. `validate`, `risk` and `diff --fail-on-alert` pass when it changes.
- **Changed values need `NEXUS_SYMBIOTE_SOURCE_BINDING_KEY`.** Without it, `diff` does not alert on a changed MCP argument, environment or header value, on a value the redaction removes from Codex `config.toml`, `.cursor/cli.json` or the Antigravity, xAI and Copilot settings files, such as a token, an environment value or a URL path, query or userinfo on the same host in a `notify` command (a command or operator glued to such a value does alert, and so does a host glued to it after an operator or another URL scheme, such as `https://a.example/n,https://b.example`), or on a URL path changed on the same host: any MCP endpoint path, and an A2A or RAG path of the same depth.
- **MCP launchers are classified only in named shapes.** Other commands are recorded as local programs, and what a local program or project script runs is not read.
- **Some claims are not verified.** OpenSSF Model Signing signatures are not verified, and ShadowScan producer verification needs a bundle or a signer policy (in CI, unverified discovery evidence fails unless `--allow-unsigned-discovery` is passed) and does not bind a report to a commit or time. Without `--project`, `validate` and `risk` check only the inventory's own claims.
- **A pull request can weaken its own gate** through `.nexus-symbiote.yaml` or the workflow file. Pass `--no-project-policy`, and require the workflow through an organization ruleset or require code-owner review of `.github/`.
- **Inventories written by 0.1.0 need a new baseline.** On an unchanged project, `diff --fail-on-alert` against one fails.
- **Limits bound size, not time.** Set a job timeout: within the collection limits, an SPDX export of a crafted project can run for hours.
