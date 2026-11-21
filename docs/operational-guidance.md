# Operational guidance

This page collects the practices that keep a Nexus SymBiote deployment inside the guarantees the security model and known limitations actually provide. It is written for operators and CI owners. Read the [security model](security-model.md), [threat model](threat-model.md) and [known limitations](known-limitations.md) first.

## Required practices

- **A checkout policy is opt-in.** A pull request can change `.nexus-symbiote.yaml` or the workflow file. `scan`, `validate`, `risk` and `baseline` apply that file only with `--accept-project-policy`. Without the flag they use the built-in policy and, when a file is present, warn. `--no-project-policy` selects the built-in policy and does not warn. The Action and the pre-commit hooks pass `--no-project-policy`. A CI variable is not a trust signal. See [policy reference](policy-reference.md) and [GitHub Action](known-limitations.md#github-action).
- **Set job timeouts.** Collection limits bound size, not time. Within the defaults an SPDX export of a crafted project can run for hours. Set a timeout on every CI job and local invocation that scans untrusted input. See [resource use](known-limitations.md#resource-use).
- **Sandbox untrusted scans.** The offline guard is a tripwire for this package and its Python dependencies, not a sandbox. Native code (tree-sitter) and any code that calls the OS directly can bypass it. Run scans of untrusted repositories in a network-restricted sandbox or container with no deployment credentials. See [security boundaries](../SECURITY.md#security-boundaries) and [offline and live modes](offline-and-live-modes.md).
- **Keep operator-owned inputs out of the pull request's reach.** The signer policy and the launch policy must live outside the scanned project, and the launch policy must be writable only by its owner; the commands refuse either one inside the project. Supply the source-binding key from a secret, never from a file in the checkout. Read the reviewed baseline from the base commit or from a store only maintainers can write, never from the pull request; the Action accepts it only from outside the workspace. See [model integrity](model-integrity.md#operator-signature-policy), [launch policy](cli-reference.md#launch-policy) and [drift gate](drift-gate.md).
- **Treat results as inventory evidence.** A passing gate does not establish that a model is benign, that a tool backend matches its description, or that every agent action is mediated. Surfaces no collector reads pass every gate. See [what results do and do not establish](security-model.md#what-results-do-and-do-not-establish).

## Recommended practices

- Run collection with the content author's privileges, not as root, on hosts with `fs.protected_hardlinks=1`. Extract untrusted archives with a tool that refuses link targets outside the destination.
- For `verify-live`, execute the pinned launchers in an externally isolated worker with resource limits and restricted filesystem, identity and network access. Pins do not cover the interpreter, libraries or operating system.
- Require the CI gate through an organization ruleset, or require code-owner review of `.github/` and the reviewed baseline, so a pull request cannot weaken its own check. See [protect the gate](drift-gate.md#protect-the-gate).
- Sign the reviewed baseline with `attest --purpose reviewed` and check it with `verify-attestation`, using a public key from outside the checkout, before `diff`. An attestation does not show that a baseline is the newest one, so bound its age with `--max-age-days`. See [gate a pull request on an attested baseline](inventory-attestation.md#gate-a-pull-request-on-an-attested-baseline).
- Review changes to instruction files, launcher commands and unrecognized surfaces by other means; the collectors record only the forms they support.
- Prefer the verified install path in the README (attestation + exact commit lock) over a plain `pip install`.

## Continuity

The project currently has a single maintainer. Organizations with supplier-continuity requirements should treat that as an unresolved risk until a second administrator is added to the repository, the PyPI project and the security contacts. See [governance](../GOVERNANCE.md#continuity).

## Larger engineering items (not yet implemented)

The following are not implemented and are not part of the current guarantees. The [roadmap](../ROADMAP.md) records what is planned:

- Broader collector coverage for high-value unrecognized forms (or explicit gaps).
- Optional tighter time budgets or progressive timeout signaling.
- Sandboxed or pure-Python alternative for the tree-sitter TypeScript parser.
- An attestation required by the `validate` and `risk` gates, and attestation in the GitHub Action. Signing and verifying an inventory by hand is implemented; see [inventory attestation](inventory-attestation.md).
- Additional runtime mediation adapters beyond the reference gateway.

These do not change the current security model. A way around a documented control remains a private vulnerability report.