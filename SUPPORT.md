# Support

Nexus SymBiote is alpha security tooling maintained by a single developer on a best-effort basis (no production SLA or LTS commitment). Security reports are prioritized.

## Where to go

| Need | Destination |
| --- | --- |
| Report a security vulnerability | [SECURITY.md](SECURITY.md) — use private vulnerability reporting, never a public issue |
| Report a bug or request a feature | [GitHub Issues](https://github.com/aisecnomad/Nexus-Symbiote/issues) |
| Browse guides and references | [Documentation hub](docs/README.md) |
| Install or contribute | [Verified release](README.md#install-a-verified-release) · [Reviewed source](README.md#install-from-reviewed-source) · [CONTRIBUTING.md](CONTRIBUTING.md) |
| Understand trust model & limits | [Security model](docs/security-model.md) · [Known limitations](docs/known-limitations.md) · [Runtime assurance](docs/runtime-assurance.md) |
| Import ShadowScan discovery | [ShadowScan integration](docs/shadowscan-integration.md) |
| Release & repository controls | [Releasing](docs/releasing.md) · [Repository controls](docs/repository-controls.md) |

> Never include credentials, private inventories, or customer data in public issues. Provide minimal synthetic reproductions with the version/commit, OS, Python version, exact command, exit code, and redacted coverage summary.

## Common issues

### Platform or installation errors

- **Unsupported platform (exit 1):** Confined file reads require POSIX `dir_fd` and `O_NOFOLLOW`. Linux (Python 3.11–3.14) and macOS (static commands; `verify-live` fails closed) are supported; Windows fails closed by design. On Windows, use the Linux [container image](docs/container-image.md).
- **Missing optional integrations:** Install extras from a reviewed source checkout with `.[sigstore]`, `.[cyclonedx]`, or `.[all]`, or use `make install-locked` for the full development environment. Note that the `cyclonedx` extra is only used by the test suite for cross-checking; runtime exports always validate against pinned vendored schemas.

### Scan returns no assets or fails coverage

- Inspect `metadata.completeness` (`scanner_status`, `exclusions`, `surfaces_excluded`, `scan_failures`). Zero matches for a collector is valid coverage; unreadable files, unsupported recognized forms, and omitted `--scanner` collectors fail closed.
- For untrusted checkouts, always pass `--no-project-policy` (and `--accept-default-exclude root:.git` for git working trees):

```bash
nexus-symbiote scan /path/to/project --no-project-policy --accept-default-exclude root:.git -o candidate.json
nexus-symbiote validate candidate.json --project /path/to/project --no-project-policy --accept-default-exclude root:.git
nexus-symbiote risk candidate.json --no-project-policy --threshold 50
```

- Use `--report-only` only for inspection — never to make an approval gate appear green.

### Collection limit exceeded

Errors like `entries limit of 100000 exceeded` mean a collector stopped at an operator [collection limit](docs/collection-limits.md). Confirm the directory belongs in the scan; if so, raise the specific limit with `--limit NAME=VALUE` before the command or via `NEXUS_SYMBIOTE_LIMITS` (project files can never change limits).

### ShadowScan import exits non-zero

Standalone `import-shadowscan` writes partial-coverage evidence and exits `1` by default because imported claims never establish complete local verification. Use `--report-only` with a fresh output path for local inspection. In CI, verify the producer (`--bundle`, `--signer-identity`, `--issuer`) or explicitly pass `--allow-unsigned-discovery`. See [ShadowScan integration](docs/shadowscan-integration.md).

### Integrity or schema validation fails

Supply independent expected digests and an out-of-checkout operator signer policy; adjacent signature files and supplier trust labels never upgrade trust. Confirm the inventory's format and fingerprint versions match the verifier ([migration guides](docs/README.md#upgrade-existing-inventories)).
