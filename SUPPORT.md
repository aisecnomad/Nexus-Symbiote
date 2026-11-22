# Support

Nexus SymBiote is alpha security tooling maintained by one developer. This guide routes questions and explains common collection and verification outcomes.

## Where to go

| I need to… | Go to |
| --- | --- |
| Report a security vulnerability | [SECURITY.md](SECURITY.md): use private vulnerability reporting, never a public issue |
| Report a bug or request a feature | [GitHub Issues](https://github.com/aisecnomad/Nexus-Symbiote/issues) |
| Find any guide | [Documentation hub](docs/README.md), organized by why, what and how |
| Install a release or develop from reviewed source | [Install a verified release](README.md#install-a-verified-release) · [Install from reviewed source](README.md#install-from-reviewed-source) · [CONTRIBUTING.md](CONTRIBUTING.md) |
| Understand evidence and trust | [Security model](docs/security-model.md) · [Runtime assurance](docs/runtime-assurance.md) |
| Import discovery | [ShadowScan integration](docs/shadowscan-integration.md) |
| Review controls and releases | [Repository controls](docs/repository-controls.md) · [Releasing](docs/releasing.md) |

Keep credentials, private inventories and customer data out of public reports. Use a minimal synthetic reproduction and include the source revision, Python/platform version, command, exit status and relevant redacted coverage information.

## Installation and platform requirements

Use Python 3.11 to 3.14 on Linux in an isolated environment and follow the [verified-release installation](README.md#install-a-verified-release) or the [source-first installation](README.md#install-from-reviewed-source). A package-index install that skips attestation verification is not a verification path.

Confined file operations and pinned stdio launchers require POSIX descriptor-relative and no-follow primitives. Unsupported platforms fail closed. CI runs the full suite on Ubuntu with Python 3.11–3.14 and on macOS with Python 3.12; on Windows every command exits with status 1 ([platforms](SECURITY.md#platforms)). A platform classifier or a successful package import is not evidence that all security primitives work on that platform.

If an optional integration is missing, source extras are `.[sigstore]`, `.[cyclonedx]` and `.[all]`. The locked development environment installs the reviewed optional test/integration dependencies:

```bash
python -m pip install --require-hashes --only-binary=:all: -r requirements-ci.lock
python -m pip install --no-deps --no-build-isolation -e .
```

Run these commands only from the reviewed checkout inside your virtual environment. Fresh extra resolution can select different dependency versions within the declared ranges. If binary wheel installation fails, check Python/platform compatibility and the build error before installing additional compilers or changing the dependency policy.

## No supported assets collected

Check the project path and the supported file/configuration scope. A completed static search may find no matching files; this does not prove there are no agents or deployments. A repository-path-inferred agent alone is not a supported local baseline subject.

Inspect `metadata.completeness.scanner_status`, exclusions, unobserved surfaces and scan failures. Unsupported or dynamic declarations and failed reads remain visible as partial or failed collection. `--scanner` deliberately narrows the requested collector set and leaves other collectors unknown.

For an untrusted checkout, use caller-owned policy:

```bash
nexus-symbiote scan /path/to/project --no-project-policy -o candidate.json
nexus-symbiote validate candidate.json --project /path/to/project --no-project-policy
nexus-symbiote risk candidate.json --no-project-policy --threshold 50
```

A command can write an inventory while returning a failing status. `--report-only` explicitly permits inspection without a successful gate; do not turn it on to make a deployment approval appear green. The trusted GitHub Action ignores checkout-supplied policy, and disabled Action gates are reported as skipped rather than successful verification.

## A collection limit was exceeded

A scan failure such as `vendor: entries limit of 100000 exceeded; raise it with --limit entries=N` means a collector stopped at one of the [collection limits](docs/collection-limits.md), so its coverage is incomplete and the gates fail. Check first that the path belongs in the scan; otherwise raise the named limit with `--limit NAME=VALUE` before the command or with `NEXUS_SYMBIOTE_LIMITS`. Settings in the scanned project never change a limit.

## ShadowScan import returns a failing status

Standalone import remains partial even for a completed source scan. It writes evidence and normally exits nonzero. Use `--report-only` explicitly for inspection, with a fresh output path. In CI, unverified discovery evidence fails even with `--report-only`: verify the producer with `--bundle`, `--signer-identity` and `--issuer`, or accept the report explicitly with `--allow-unsigned-discovery`. The command ignores project policy beside the report and in parent directories. Malformed input is rejected; unsupported entries and lossy projections remain limitations.

A matching source digest binds bytes, not the producer or the truth of the report. Producer verification needs an independently configured signer and issuer. See [ShadowScan integration](docs/shadowscan-integration.md).

## Integrity or standards validation fails

Supply independent expected digests and signer policies; an adjacent signature file or supplier-provided trust label cannot establish verification. Check that the project still contains the exact recorded subject and that the inventory's supported schema and fingerprint versions match the verifier.

The package validates exports against pinned vendored schemas. The `cyclonedx` extra installs the CycloneDX Python library, which only the test suite uses to cross-check exports; the tool does not import it, so installing it changes no validation or output. Inspect the selected-field loss report and preserve the native extension when downstream recovery is required.

## Local development checks

From the locked development environment:

```bash
python -m pytest -n auto --dist worksteal
ruff check src tests scripts
ruff format --check src tests scripts
mypy src/nexus_symbiote scripts
python scripts/check_workflows.py
python scripts/check_repository_hygiene.py
python scripts/check_security_regressions.py --out security-regressions.json
python -m pytest -n auto --dist worksteal --cov=nexus_symbiote --cov=scripts --cov-branch --cov-report=json:coverage.json
python scripts/check_coverage.py coverage.json
```

These are local checks. They do not apply GitHub protection, qualify another platform, establish a successful hosted workflow or publish a package. The remaining enforcement steps are in the [repository controls runbook](docs/repository-controls.md#operator-prerequisites); [issue #74](https://github.com/aisecnomad/Nexus-Symbiote/issues/74) records the remediation history.

## Response expectations

There are no guaranteed response times, production SLAs or long-term support commitments. Security reports are prioritized, and other requests are addressed as maintainer capacity allows.
