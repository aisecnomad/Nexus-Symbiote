# Lockfile evidence

The [registry collector](registry-collector.md) binds declared AI-package lockfile resolutions as `declared` claims (`trust: unknown` — lockfiles are never fetched or executed, and URL userinfo, query tokens, and raw paths are stripped from recorded origins and locators). When multiple competing lockfiles of the same ecosystem exist (`pnpm-lock.yaml` + `yarn.lock`, or `uv.lock` + `poetry.lock`), no resolution is bound and the conflict is recorded as an exclusion. `bun.lock`, `bun.lockb`, `Pipfile.lock`, and `pdm.lock` are unread and emit a low `lockfile_unread` finding.

## npm (`npm-shrinkwrap.json`, `package-lock.json`)

Reads direct AI dependencies from `package.json` (`peerDependencies`, `dependencies`, `optionalDependencies`, `devDependencies`) and binds their `packages["node_modules/<name>"]` entry (`npm-shrinkwrap.json` takes precedence; an unreadable shrinkwrap fails collection rather than falling back):

- **Validation (fail-closed):** Non-HTTPS or WHATWG-ambiguous `resolved` hosts (whitespace, controls, backslashes, non-ASCII, `%`), non-exact SemVer `version`, malformed or SHA-1-only `integrity`, non-canonical/colliding `packages` keys, missing `packages[""]`, or root specs contradicting `package.json` fail collection.
- **Findings & gaps:** Missing `integrity` (`missing_lockfile_integrity`), non-default registries (`registry_origin`, recorded via `repository_url` `purl` qualifier), and mismatched tarball names/versions raise findings; a `package.json` version range drops its `version_pinning` finding only when bound to a SHA-256/384/512 SRI hash and consistent tarball URL. Local `link:`/`file:` entries and mismatched inner `name` fields remain coverage gaps (`npm:` aliases resolve against their target package).

## pnpm (`pnpm-lock.yaml`) and Yarn (`yarn.lock` v1 & Berry)

Read when a single manager's lockfile is present at the project root:

- **pnpm (5.x `/<name>/<ver>`, 6.x `/<name>@<ver>(peers)`, 9.x `<name>@<ver>` + `snapshots`):** Binds the root importer's exact version, SRI integrity, and tarball origin when importer specifiers match `package.json` (or top-level `pnpm.overrides`/`resolutions`). Unsupported lockfile versions, 5.x peer-suffixed importer refs, workspace/selector overrides, missing importers, cross-format duplicate spellings, or conflicting section versions fail collection or record ambiguity exclusions. Peer suffixes with non-exact or credential-shaped text redact to `(***)`.
- **Yarn 1 & Berry:** Tokenizes Yarn 1 and Berry (`__metadata`) strictly, rejecting malformed indentation, ambiguous multi-stanza selectors, cross-range Yarn 1 same-version stanzas with differing `resolved`/`integrity`, Berry duplicate-locator stanzas, and scope/name hash collisions (`@op/enai` vs `openai`). Yarn 1 requires SHA-256+ `integrity` (`sha1-` fails; Yarn 1 `checksum` is ignored). Yarn Berry requires a 128-hex SHA-512 `checksum` under Yarn 4's `10c0` cache key (`cacheKey: 8`, platform `conditions`, non-Yarn-4 `packageManager`/`devEngines`, or `.yarnrc.yml` altering `checksumBehavior`/`compressionLevel`/`enableGlobalCache`/`globalFolder`/`yarnPath` raise `missing_lockfile_integrity`). Non-registry resolutions (`workspace:`, `link:`, `file:`, `git`, `patch:`, `portal:`) record exclusions.
- **Patched packages:** Any package named in `pnpm.patchedDependencies`, `pnpm-workspace.yaml` `patchedDependencies`, `(patch_hash=...)`, `patched: true`, or root `patchedDependencies` records a `patched dependency is unverified` exclusion (plus medium `nonregistry_source` when declared in `package.json`) and withholds `purl`/lockfile binding.

## Python (`uv.lock`, `poetry.lock`)

Supplies exact version, index origin, record locator, and lockfile SHA-256 for root `requirements*.txt` and `pyproject.toml` AI declarations (`[build-system]` excluded):

- **Validation & sources:** Versions incompatible with any root declaration fail collection. Local, git, or direct-URL sources bind no registry resolution. In `uv.lock`, `sdist` and `wheels` artifact URLs and hashes are checked against the declared registry source. In `poetry.lock`, a record with `source.reference` binds only when `pyproject.toml` declares that source at a matching index origin (otherwise recorded as an exclusion with no `purl`).
