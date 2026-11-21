# Threat model

Nexus SymBiote reads hostile input and makes decisions that other people rely on.
This page states what it protects, from whom, and which control answers each
threat, so that a change can be checked against it. The
[architecture](architecture.md) shows where each boundary sits. What the controls
do not cover is in the [security policy](../SECURITY.md#known-limitations) and, in
full, the [known limitations](known-limitations.md).

## Assets

1. **Gate decisions.** The exit status of `scan`, `validate`, `risk`, `baseline`,
   `diff --fail-on-alert`, `verify-attestation`, `trace-diff` and `verify-live`, and
   the GitHub Action's `result`. A wrong pass is the most damaging failure.
2. **Inventory fidelity.** The components, findings and coverage records an
   inventory holds, and the absence of claims it cannot support.
3. **The scanning host.** A checkout must not be able to run code, reach the network
   or make a command read files outside the scan root.
4. **Secrets.** Credentials in configuration files and the environment must not
   reach inventories, exports, logs or messages. The binding key never enters an
   inventory.
5. **Release integrity.** The published wheel and sdist, their attestations, and
   the Action's source.

## Adversaries

| Adversary | Controls | Wants |
| --- | --- | --- |
| Author of the scanned change | Every file in the checkout, including names, sizes, links and the project policy; on `pull_request`, the workflow file too | A passing gate for a malicious change, code execution or network access during a scan, files read from outside the checkout, content hidden from reviewers |
| Supplier of an inventory or report | A native AgentBOM, an export or a ShadowScan report | A document that passes `validate` or `risk` while it misstates the project |
| Network peer in live mode | A remote MCP server's responses, or a DNS answer | Requests to internal addresses, resource exhaustion, a clean tool list for the observer and another one for agents |
| Agent that emits the telemetry | Its own spans, and the trace files exported from them | A `trace-diff` that passes while the agent uses undeclared tools, models or endpoints |
| Holder of stale runtime evidence | Old snapshots, approvals or trust statuses | A tool call after revocation or supersession, or a second use of an approval |
| Dependency or toolchain compromise | A package in the locked environment, a CI action or a release step | Code execution in CI or a modified release |

## Threats and controls

STRIDE letters: spoofing (S), tampering (T), information disclosure (I), denial of
service (D), elevation of privilege (E).

| Threat | Example | Control | Residual risk |
| --- | --- | --- | --- |
| Gate weakened by project policy (T) | A pull request raises `fail_threshold` in `.nexus-symbiote.yaml` | The file is not applied unless `--accept-project-policy` is passed; otherwise the built-in policy is used and a present file is warned about. `--no-project-policy` selects the built-in policy without that warning. When the file is applied, every relaxation is listed in `policy_weakened` and warned about. The Action and the pre-commit hooks pass `--no-project-policy`, and `baseline` re-gates the staged inventory with the built-in policy | On `pull_request`, the workflow file belongs to the pull request; require the check through an organization ruleset or code-owner review of `.github/`, and never check out the pull request head in a `pull_request_target` workflow ([GitHub Action](known-limitations.md#github-action)) |
| Gate weakened by baseline (T) | A pull request regenerates the reviewed baseline with its change | The Action's `reviewed-baseline` must be outside the workspace; read baselines from the protected branch ([trust anchor](drift-gate.md#the-trust-anchor-is-the-baseline)); `verify-attestation` before `diff` checks that trusted keys signed exactly the reviewed file ([inventory attestation](inventory-attestation.md)) | Baselines and inventories are written unsigned, and `diff` checks no signature; an attestation authenticates a file on request, not that it is the newest one, and the Action neither signs nor verifies |
| Planted trusted key (S) | A pull request commits a public key that the job passes to `verify-attestation --trusted-key`, `runtime verify --public-key` or a `runtime register` ring | A trusted key inside a git working tree that holds the subject, the envelope, another input of the command or the current directory, also under another name for that tree, or a key file with other hard links, is a usage error ([trusted keys](inventory-attestation.md#trusted-keys)) | The check catches misplacement and authenticates no key: a key copied or mounted out of the checkout, or kept in a checkout without a `.git` entry, is accepted ([attestations](known-limitations.md#attestations)) |
| Evasion by unrecognized form (T) | An MCP server declared in a file or launcher shape the collectors do not read | A recognized input that cannot be collected is a gap, and the default gates fail; a known runner the collector cannot classify, inline code or a nested launch is a high `launcher_identity` finding and a gap; a server that application code starts or reaches through a launcher class the collector knows is a gap | What no collector recognizes, such as an SDK import through an alias resolved outside the file or a settings file the `ide_agents` collector does not recognize, passes every gate, and any other command is recorded as a local program whose launches are not read ([known limitations](known-limitations.md#mcp-servers-and-tools)) |
| Evasion by relocation (T) | `claude.md` instead of `CLAUDE.md`, or configuration behind a symbolic link | When a fixed name is absent, a case or normalization variant of it is a failure; a symbolic link is read only when it is relative and leads to a regular file or directory inside the root, and is a failure otherwise | A hard link inside the root is read like any other file |
| Reading outside the root (I) | `../` paths, absolute paths, symbolic links | Descriptor-relative reads with `O_NOFOLLOW` on every component; link targets resolved lexically and confined to the root; output files never written through a symbolic link | Run collection with the content author's privileges ([security boundaries](../SECURITY.md#security-boundaries)) |
| Code execution (E) | A pickle model, a Python module, a hook or an MCP launch command in the checkout | Collectors parse statically (`ast`, tree-sitter, JSON, YAML's safe loader, TOML) and never import, load or launch; the offline guard refuses process creation | Decided for 1.0.0: tree-sitter stays in-process under file-byte and AST-node bounds so the offline guard's refusal of process creation holds without exception; a memory-safety defect in native parsing code runs with the scan's privileges, so scan untrusted repositories in an isolated worker |
| Network access (I) | A dependency that resolves a host during an offline command | The offline guard refuses name resolution, sockets other than Unix sockets, and process creation for the whole command | Native code that calls the operating system directly; add a network boundary where one is required ([offline and live modes](offline-and-live-modes.md#limits)) |
| Secret disclosure (I) | A token in an MCP `env` block, a URL or a connection string | Environment and header values recorded by name, URLs as origins, free text redacted by pattern, other values bound only by an HMAC under the operator's key; failures reported by fixed codes, not exception text | Credentials in unrecognized shapes survive redaction; unkeyed digests, such as tool `definition_hash` values, let a holder of the inventory confirm guesses of low-entropy values |
| CI log injection (T) | A file named `::warning::x` or `##[set-output name=x]y` | Untrusted text is made inert and never starts an output line; the Action relays child output inside a `stop-commands` block with a random token and writes every output before collection starts | None known |
| Markup in reports (T) | A component name holding `<script>` or an event handler in the `graph.html` a reviewer opens, or a Markdown link in a `crosswalk` report | The `graph` page cuts, neutralizes and HTML-escapes every inventory string and shows it only as element text or an `aria-label` or `data-name` value; its Content-Security-Policy allows only its one style block and one script, each pinned by SHA-256, and `data:` images, and it loads nothing from outside ([graph view](graph-view.md#how-the-page-is-made-safe-to-open)); `crosswalk` Markdown backslash-escapes inventory text, and `minimum-elements` Markdown quotes it as code spans | `crosswalk` Markdown escapes markup, not a renderer's text filters, such as GitHub mentions and emoji codes ([exports](known-limitations.md#exports)) |
| Resource exhaustion (D) | Huge files, deep nesting, many files, crafted lockfiles | [Collection limits](collection-limits.md) and fixed per-format bounds fail closed and name the bound | Limits bound size, not time: some parsing takes minutes within them, and an SPDX export of a crafted project takes hours; set a job timeout ([resource use](known-limitations.md#resource-use)) |
| Forged inventory (S, T) | A supplied AgentBOM that claims complete coverage or verified signatures | `validate --project` and `risk --project` collect the checkout again and compare; without `--project` the result is labeled `supplied-bom`; an inventory's own `verified` labels are not trusted | Without `--project`, only the inventory's own claims are checked |
| Forged discovery report (S) | A ShadowScan report replaced before the scan | The report's digest is recorded; with an operator signer policy entry for the report, `validate --project` and `risk --project` verify its producer | Producer verification is opt-in and does not bind a report to a commit or time ([ShadowScan](known-limitations.md#shadowscan)) |
| Partial or forged telemetry (S, T) | An agent's instrumentation leaves a tool call out of its traces, or reports a declared name for another tool | `trace-diff` records traces as `reported` evidence that never raises assurance, reads identifier attributes only, and fails on undeclared, unreadable or unclassifiable reports ([trace evidence](trace-evidence.md#trust-model-reported-not-observed)) | A missing span proves nothing, and matching is by name and reported endpoint, not by identity |
| Request forgery in live mode (S, I) | A remote server or DNS answer pointing at an internal address | Live mode only; HTTPS only, to the origins the operator approves or to the OSV API; resolution pinned to public addresses; no redirects or proxies; bounded responses; tools never called | A server can answer the observer differently from agents ([live mode](known-limitations.md#live-mode)) |
| Hostile launcher (E) | `verify-live` starts a modified server executable | Operator launch policy outside the project and its repository; SHA-256 pin checked on a private copy; no inherited environment, only a default `PATH`; process-group termination | Pins do not cover the interpreter, libraries or operating system; run launchers in an isolated worker |
| Replay or rollback of runtime evidence (S, T) | An old snapshot or a spent approval presented to the gateway | Purpose-specific signatures and validity windows, revocation in trust statuses, supersession through `runtime register`, rollback protection and one-use approvals in the state store | Guarantees hold per SQLite state file; calls that bypass the gateway are not governed ([runtime gateway](known-limitations.md#runtime-gateway)) |
| Release compromise (T) | A modified wheel or Action | Pinned actions, hash-locked dependencies, OIDC trusted publishing, build attestations, a 24-hour soak and a signed tag before PyPI (enforced from 0.2.0; [0.1.0 was published without them](releasing.md#release-record)); the README's verified install checks the attestation | One maintainer approves releases ([governance](../GOVERNANCE.md#review-policy-while-there-is-one-maintainer)); a plain `pip install` verifies nothing |

## Out of scope

Nexus SymBiote does not establish that a model, tool or agent is benign, that a
tool's backend matches its description, or that every action was mediated.
Runtime enforcement covers only calls routed through an integration. See
[what results do and do not establish](security-model.md#what-results-do-and-do-not-establish).

## Using this page

When you change a collector, a gate, an export or the Action, name the boundary and
the threat your change touches in the pull request, as
[security changes](../CONTRIBUTING.md#security-changes) asks, and add a regression
test that fails on the vulnerable behavior. A way around a control that this page or
the known limitations do not describe is worth a
[private report](../SECURITY.md#reporting-a-vulnerability).
