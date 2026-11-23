# Registry collector

The `registry` collector records the AI-related packages and container images a project declares in its root manifests. It reads files only: it runs no package manager, builds no image and fetches nothing. A record is a declaration with unknown trust, not proof of what is installed.

It inventories only packages and images in the [AI package catalog](#ai-package-catalog) below. Every other dependency, including a malicious package outside the catalog or a look-alike name such as `langchian`, produces no component and no finding: the collector does not detect typosquats and is not a full SBOM. "registry (no AI-related dependencies found)" means no declaration matched the catalog, not that the project has no dependencies. The catalog changes between releases, so a newer release can inventory packages an older baseline left out.

## What it reads

All paths are relative to the scan root, and the inventory records them that way, so the same tree gives the same inventory wherever it is checked out.

| Ecosystem | Files and fields |
| --- | --- |
| npm | `package.json`: `peerDependencies`, `dependencies`, `optionalDependencies` and `devDependencies`, in that order of precedence, as npm reads them; a name declared differently in more than one section is recorded with every spec, and its spec counts as a pin only when pnpm, which takes `optionalDependencies`, then `dependencies`, `devDependencies` and `peerDependencies`, takes the same one; otherwise it has a `version_pinning` finding and no package URL. Resolution evidence from one lockfile: `npm-shrinkwrap.json` when it exists, which npm installs from instead of `package-lock.json`, and otherwise `package-lock.json` (lockfile versions 2 and 3), `pnpm-lock.yaml` or `yarn.lock` (v1 and Berry). With the lockfiles of more than one package manager no evidence is bound; see [lockfile evidence](npm-lockfile-evidence.md) |
| PyPI | Root `requirements*.txt` files, read by pip 26.3's rules. `pyproject.toml`: `[project]` dependencies and optional dependencies, `[dependency-groups]` (PEP 735), `[build-system]` requires, `[tool.uv]` dev-dependencies, `[tool.pdm.dev-dependencies]`, and Poetry's `dependencies`, `dev-dependencies` and `group.*.dependencies` tables translated to PEP 508. Resolution evidence from `uv.lock` or `poetry.lock`, unless both exist |
| Containers | `Dockerfile`, `Dockerfile.agent` and `Containerfile`, read as BuildKit reads them. The Compose files Compose reads by default: `compose.yaml`, `compose.yml`, `docker-compose.yml` and `docker-compose.yaml`, and the override files it merges, `compose.override.yml`, `compose.override.yaml`, `docker-compose.override.yml` and `docker-compose.override.yaml`. Each is parsed as YAML: the `image` of every service, with YAML merge keys and aliases followed, the `FROM` lines of a `build.dockerfile_inline`, and the `model` of every top-level model, which Docker Model Runner pulls (recorded with `artifact_type` `model`, whatever its name). A value is read as written only when it is untagged or tagged `!!str` or with Compose's `!override`; `!reset` and null hold no value. A root `.env` is read only for the name `COMPOSE_FILE`; nothing in it is recorded |

A name is matched in its normal form, as PEP 503 normalises a PyPI name, so `llama.index.core`, `LLAMA_INDEX_CORE` and `llama-index-core` are one package with one component. An npm dependency declared as an alias, `"app-utils": "npm:@anthropic-ai/sdk@0.30.1"`, is classified and recorded by the package it installs, with the alias in the `npm_alias` property; a lockfile record whose `name` is an AI package also brings the dependency into the inventory. The same image named in several files is one component whose `source_paths` property lists them all.

The collector also reads the project's [registry and index settings](#registry-and-index-settings), which can send a package to another registry or index.

## Registry and index settings

A project file can redirect a package manager to a non-default registry or index, where the same name and version need not be the public package. For every inventoried npm package fetched from a registry, and every inventoried PyPI package not declared only by URL, the collector reads these settings from the project root:

| Ecosystem | File | Settings |
| --- | --- | --- |
| npm | `.npmrc`, which npm, pnpm, Yarn 1 and Bun read | `registry`, `@scope:registry`, and `scope`, whose registry npm uses for every package whose own scope has no registry; pnpm, Yarn 1 and Bun ignore `scope`. It is read with the MCP collector's reader: top-level settings only, as npm reads them, and never an authentication setting |
| npm | `.yarnrc` (Yarn 1) | `registry` and `@scope:registry` |
| npm | `.yarnrc.yml` (Yarn 2 and later) | `npmRegistryServer` and `npmScopes.<scope>.npmRegistryServer` |
| npm | `bunfig.toml` (Bun) | `registry` and `scopes` in `[install]`, each a URL or a table with a `url` |
| PyPI | Root `requirements*.txt` files | `--index-url` (also `-i` and `--pypi-url`), `--extra-index-url` and `--find-links` (`-f`) on an option line. pip ignores them on a requirement line, and so does the collector |
| PyPI | `pip.conf` and `pip.ini` | `index-url` (also `pypi-url`), `extra-index-url` and `find-links` in any section, read as pip's configparser reads the file, with `_` for `-` and a leading `--` accepted and an empty value ignored, as pip does. pip reads such a file when `PIP_CONFIG_FILE` names it or when the project root is the virtual environment it runs in |
| PyPI | `pyproject.toml` and `uv.toml` | uv's `index-url`, `extra-index-url`, `find-links` and every index that is not `explicit` (`[[tool.uv.index]]`, or `[[index]]` in `uv.toml`), also in uv's `pip` table; every `[[tool.poetry.source]]` except an `explicit` one; every `[[tool.pdm.source]]` |

Each setting that points elsewhere is listed on the package in its `package_sources` property, as `<file>:<setting>=<origin>`. The package gets a low `registry_origin` finding and no `package_url`, because its name and version no longer identify what is installed, and a PyPI package that no lockfile resolves loses the `registry_uri` that assumed PyPI. For this project:

```text
package.json   {"dependencies": {"openai": "4.0.0"}}
.npmrc         registry=https://deploy:s3cret@npm.example.com/repository/npm/
```

the `openai` entry that `nexus-symbiote scan . --scanner registry --report-only -o agentbom.json` writes has no `package_url` and records:

```json
"package_sources": [
  ".npmrc:registry=https://npm.example.com"
]
```

with the finding "npm package 'openai' may resolve from a registry that the project configures (.npmrc:registry), not the default npm registry; its name and version do not establish identity."

- **Which settings apply.** An npm package takes, from each file, the registry of its own scope. A package without one takes the file's default registry, except that npm takes, from `.npmrc`, the registry of the scope that `scope` names when that scope has one; pnpm, Yarn 1 and Bun ignore `scope`. Which package manager installs is not known, so every file counts, and in `.npmrc` both the `scope` registry and the default one count; an empty setting selects nothing, as npm reads it. npm fills in a `scope` such as `${NPM_SCOPE}` from the environment, so it may name any scope: when the file gives some scope a registry other than the default one, the package records `.npmrc:scope=[unresolved]`. A PyPI setting applies to every PyPI package of the project: pip applies index options and its configuration to every package of the run that reads them, uv, Poetry and PDM apply their indexes and sources to every package they resolve, and which files one install reads is not known. An explicit uv index or Poetry source serves only the packages that name it, which are [gaps](#coverage-gaps) already.
- **What is not a redirect.** The default registries, `https://registry.npmjs.org/` and `https://registry.yarnpkg.com/` for npm and `https://pypi.org/simple/` for PyPI, with or without the final `/` and port 443, and with their scheme and host in any case of their ASCII letters. Every other value is a redirect, including plain `http://`, another path on a default host, a host that only starts with a default one and a host with a letter from another script, such as a dotless `ı`, that Unicode case folding would equate with an ASCII one.
- **What is exported.** Only a value's origins: scheme, host and port, never user information, a path, a query or a token. A value that depends on the environment, such as `${NPM_REGISTRY}`, is `[unresolved]`, a path is `[local]`, a value longer than 4,096 characters is `[not parsed]`, and a host that cannot be read without ambiguity is `[redacted]`. A package lists at most 32 sources and then one entry that counts the rest, and its finding names at most eight settings.
- **When the files are read.** `.npmrc`, `.yarnrc`, `.yarnrc.yml` and `bunfig.toml` are read only when an inventoried npm package is fetched from a registry, and `pip.conf`, `pip.ini` and `uv.toml` only when an inventoried PyPI package is declared other than by URL, so a project without such a package never fails on them.

## Coverage gaps

These gaps make the collector partial, so `scan`, `validate` and `risk` fail by default. Gaps never name the causing value, which can hold a credential.

| Gap | Cause |
| --- | --- |
| `package.json: dependency override not translated` | `overrides` (npm), `resolutions` (yarn) or `pnpm.overrides` names an inventoried package, or installs an AI package as an alias |
| `package.json: workspaces not followed` | `workspaces` lists member packages, whose manifests are not read |
| `package.json: git, URL or path dependency not classified` | A dependency outside the catalog by name, or a package that `overrides`, `resolutions` or `pnpm.overrides` replaces, comes from git, a URL or a path, and no lockfile record names the package it holds |
| `pnpm-workspace.yaml: workspace settings not read` | A `pnpm-workspace.yaml` exists: pnpm reads workspace packages, overrides and version catalogs from it. Only its `patchedDependencies` is read, when `package.json` declares an inventoried npm package |
| `package.json: patched dependency is unverified`, `pnpm-workspace.yaml: patched dependency is unverified`, `pnpm-lock.yaml: patched dependency is unverified` | A patch names an inventoried npm package, or the package an alias installs, by a key that gives any version or range, or none (names are compared in lower case): `pnpm.patchedDependencies` (pnpm) or `patchedDependencies` (Bun) in `package.json`, or `patchedDependencies` in `pnpm-workspace.yaml` (pnpm 10) or `pnpm-lock.yaml`. Or the root importer's version of the package holds a `patch_hash=` outside the groups of its peers, or its lockfile v6 record has `patched: true`. The package manager applies the patch to the registry artifact at install, so the package binds no lockfile record, integrity value or package URL from any lockfile, as a Yarn `patch:` resolution binds none, and it has a medium `nonregistry_source` finding. A key in any of these maps that names a catalogued AI package `package.json` does not declare, such as one an inventoried package depends on, is the gap with no finding: no component binds that package, and those that depend on it keep their records. In `package.json` and `pnpm-workspace.yaml`, a map that is not one, holds more than 10,000 entries or has a key that names no package, and a `pnpm-workspace.yaml` that is not read, count for every inventoried npm package, and such a map in `package.json` is the gap even when it declares none |
| `multiple npm lockfiles present (<files>); resolution is ambiguous` | More than one of `npm-shrinkwrap.json` or `package-lock.json`, `pnpm-lock.yaml` and `yarn.lock` exists, so no lockfile evidence is bound. `npm-shrinkwrap.json` beside `package-lock.json` is not ambiguous: npm installs from it |
| `<npm lockfile>: aliased package identity is unresolved` | A lockfile record names a different package than `package.json` declares, or a pnpm or Yarn lockfile resolves an `npm:` alias, which only `npm-shrinkwrap.json` and `package-lock.json` records resolve, or has a Yarn Berry stanza of a package whose name Yarn 4 hashes as it hashes the alias key |
| `<npm lockfile>: selected non-registry source for <package> is unverified` | The effective pnpm or Yarn declaration selects a non-registry dependency. The collector withholds the registry identity and records a coverage gap. |
| `<npm lockfile>: local link resolution is unverified`, `local or non-registry resolution is unverified`, `multiple package resolutions for <package> are ambiguous` | A lockfile resolves a package from a link, a workspace, a directory, git or another non-registry source, a Yarn Berry resolution names anything but the registry package and version of its record, or a pnpm or Yarn lockfile resolves it to more than one version, or names its selector in more than one `yarn.lock` stanza, or a Yarn 1 lockfile has a stanza of another range with the same version and another resolved URL, integrity or checksum, which Yarn 1 may install instead, or a Yarn Berry lockfile has a second stanza with its record's `resolution`, or a stanza of a package whose name Yarn 4 hashes alike, such as `@op/enai` for `openai`, which Yarn 4 installs instead |
| `multiple Python lockfiles present (uv.lock and poetry.lock); resolution is ambiguous`, `<Python lockfile>: non-registry package source for <package> is unverified`, `multiple package resolutions for <package> are ambiguous` | Both Python lockfiles exist, also when one of them is withheld as a credential file or cannot be read, or the lockfile resolves a package from a local, git or URL source, or more than once. The package then has no package URL and no registry origin. A record is checked the same way for a package declared only under environment markers, and its index origin is recorded, but it names no package URL; nor does a record for a package that a declaration resolves through a source, override or conflict that is not translated, and its PyPI origin is not taken |
| `<file>: its name says it holds credentials; not read or inventoried`, `<file>: a symlink leads to <target>, whose name says it holds credentials; not read or inventoried` | A registry input, such as a requirements file, lockfile, `package.json` or Compose file, is named as a credential store, or is an in-root symlink to one, such as `requirements-dev.txt -> .env` or `-> prod.env`: it is not read, so no value in it reaches a component. `.npmrc` and `.env` are read on purpose, for their registry settings and `COMPOSE_FILE` only, and record no value, unless they are symlinks to another credential file, such as `.npmrc -> .env`. A withheld `.npmrc` leaves its registry settings unread, as an absent one would |
| `poetry.lock: package source reference is unverified` | A `poetry.lock` record's `reference` names no source that `pyproject.toml` declares, or one at another index origin than the record's `url`; Poetry downloads from the source the reference names |
| `<Python lockfile>: package index of the selected record is not a plain http(s) URL; its origin is unverified` | The selected record's index is not a URL with a lower-case `http://` or `https://` scheme whose authority every URL parser reads the same way: a path, a `file://` or `ftp://` URL, no host, a value that is not text, a backslash, a percent-escape or a control character |
| `pyproject.toml: uv source not translated` | `[tool.uv.sources]` replaces an inventoried package with a git, URL, path, workspace or index source |
| `pyproject.toml: uv override or constraint not followed`, `uv.toml: uv override or constraint not followed` | `override-dependencies` or `constraint-dependencies` in `[tool.uv]` or in a root `uv.toml` names an inventoried package, also after leading whitespace, which uv skips |
| `pip.conf:<key>: requirements include not followed`, `constraints file not followed` or `editable install not followed`, and the same for `pip.ini` | The configuration sets `requirement`, `constraint` or `editable`, which `pip install` applies as it applies `-r`, `-c` or `-e`; no package keeps a package URL |
| `pyproject.toml: PDM override not followed` | `[tool.pdm.resolution.overrides]` names an inventoried package |
| `pyproject.toml: uv workspace members not followed` | `[tool.uv.workspace]` lists members, whose manifests uv installs from |
| `Pipfile: dependencies not read` | A `Pipfile` exists; pipenv installs what it declares |
| `.env: COMPOSE_FILE not followed` | The root `.env` contains `COMPOSE_FILE`, in any letter case: Compose reads the files a `COMPOSE_FILE` setting lists instead of the default ones, and takes them from the environment when the name has no value. Compose's dotenv parser reads statements, not lines (it skips any Unicode space before a name and before `=`, and a statement can follow a closing quote on the same line), so any mention counts, including one in a comment or a value |
| `<compose file>: include not followed`, `extends not followed`, `build context not followed` | Compose reads another file, or builds from a Dockerfile the collector does not read: a context or `dockerfile` other than the project root and a root `Dockerfile`, `Dockerfile.agent` or `Containerfile`, including an absolute path such as `/`, one with a backslash and one longer than 4,096 characters. Also a build that names contexts, in `additional_contexts` or in the `contexts` of `x-bake`, which `docker buildx bake` reads from the same file: BuildKit uses a named context in place of the image that a `FROM` line of that name pulls |
| `<compose file>: image substitution not resolved` | An image contains `$`; Compose fills it in from the environment |
| `<compose file>: image not parsed`, `build not followed`, `tagged image value not resolved` | An empty, null or `!reset` `dockerfile_inline`, or an `image`, `model`, `build` or `dockerfile_inline` value that is not text: a YAML tag other than `!!str`, `!override` and `!reset`, such as `!!binary`, which Compose decodes from base64, `!!null` on a value, or a scalar YAML reads as another type, such as a number |
| `<compose file>: dockerfile_inline <Dockerfile gap>` | An inline Dockerfile has one of the [Dockerfile gaps](#dockerfiles) |
| `<compose file>: YAML merge key cycle not followed` | A mapping merges itself |
| `<file>: image reference not parsed` | An image that matches the catalog is not a valid image reference |
| `.npmrc: a setting name depends on the environment; registries not resolved` | A `.npmrc` setting name holds `${...}`, which npm fills in from the environment, so it can be any registry setting |
| `pip.conf: not read as pip reads it; index settings not resolved`, and the same for `pip.ini` | configparser, and so pip, refuses the file: text before the first section, a line that is neither a section nor a `key = value` or `key: value` setting, or a section or setting given twice |

### Requirements files

Requirements files are read by pip 26.3's rules, without following includes, constraints files, editable installs or URL, VCS and path requirements. These are gaps: an include, constraints file or editable install that reaches beyond the root `requirements*.txt` files or the project itself; a URL, VCS, archive or path requirement without a package name, other than the project itself; an option pip 26.3 does not know, on an option line; and a `${NAME}` variable in a requirement's name or in an option line's option place. A declared encoding other than UTF-8 is a failure.

Recorded without a gap: a `name @ URL` requirement, under its name and URL origin, or as written when the URL has no `//`, unless pip could read its text as a path in the project. Options after a requirement on the same line are not checked, except `-e` and `--hash`; `--hash` values are recorded. A variable inside an option's value is neither resolved nor reported.

### Dockerfiles

Dockerfiles are read as BuildKit reads them: the instruction word in any case, `--flag` words skipped, continued lines joined and trimmed, comment lines and heredoc bodies skipped, and `FROM` lines that name an earlier build stage left out. These are gaps: an `ARG` substitution, quotes or escapes in the image, a `FROM` line or heredoc that cannot be parsed, and an escape directive other than a backslash.

### Collection failures

A file that cannot be read or parsed, such as invalid TOML, JSON or YAML, a Compose file with a repeated key, a key tagged `!!binary` or with a tag outside YAML's own `tag:yaml.org,2002:` types, or a non-mapping service, or a requirement that packaging cannot parse, is a collection failure, which fails the collector. So is a [registry or index settings](#registry-and-index-settings) file that cannot be read, such as a `.npmrc` that is a symbolic link out of the project, a FIFO, not UTF-8 or larger than `file-bytes`, a `bunfig.toml` or `uv.toml` that is not valid TOML, a `.yarnrc.yml` that is not a YAML mapping, a `pnpm-workspace.yaml` that is not a YAML mapping, repeats a key or holds an anchor, alias or tag, when `package.json` declares an inventoried npm package (`pnpm-workspace.yaml: invalid or unsupported workspace file`), and a Poetry or PDM source list that is not a list of tables each with a `url` (`pyproject.toml: invalid Poetry source`, `pyproject.toml: invalid PDM source`); a Poetry source named `PyPI` needs no `url`.

## Findings

| Category | Severity | Raised when |
| --- | --- | --- |
| `version_pinning` | medium | A package has no exact pin: no `==` pin in any PyPI declaration, a PyPI range or bare name that the reported pin does not satisfy, under any marker or group, or an npm range or tag that no consistent `npm-shrinkwrap.json` or `package-lock.json` record with a strong integrity value resolves (a pnpm or Yarn record binds the version and leaves the finding, and so does a `uv.lock` or `poetry.lock` record for a PyPI range). Also two PyPI declarations that cannot both hold |
| `version_pinning` | low | Every PyPI pin has an environment marker, such as `; sys_platform == "linux"` |
| `nonregistry_source` | high or medium | A package comes from a URL, VCS or path instead of a registry; high for a VCS reference without a full commit, or a plain `http://` URL. Medium for an npm package that a patch may change at install (the `patched dependency is unverified` [gap](#coverage-gaps)) |
| `package_alias` | low | An npm dependency installs a package under another name |
| `missing_lockfile_integrity` | medium | An npm, pnpm or Yarn 1 lockfile record has no `integrity` value, or a Yarn Berry record no `checksum` that Yarn 4 checks: a SHA-512 digest under the cache key `10c0`, in a record without `conditions`, with `.yarnrc.yml` settings that keep the check (no `yarnPath` and no `plugins`, which Yarn loads as code) and a `package.json` that names no other Yarn release ([lockfile evidence](npm-lockfile-evidence.md)). A Yarn 1 `checksum` and a Berry `integrity` do not count. An integrity value with only SHA-1, in any npm, pnpm or Yarn 1 lockfile, is a collection failure |
| `lockfile_resolution_mismatch` | high | An npm, pnpm or Yarn record's tarball URL names another package or version than the record |
| `registry_origin` | high or low | An npm, pnpm or Yarn lockfile record resolves from a registry other than `registry.npmjs.org` and `registry.yarnpkg.com`; a `uv.lock` or `poetry.lock` record resolves from an index other than `https://pypi.org`, which is high when that index is plain `http://`; or a project setting sends the package to another registry or index ([registry and index settings](#registry-and-index-settings)) |
| `lockfile_unread` | low | `Pipfile.lock` or `pdm.lock` (PyPI), or `bun.lock` or `bun.lockb` (npm) exists: the package manager resolves the package from a file the collector does not read. Coverage stays complete, because the declarations are read |
| `version_pinning`, `mutable_image_tag` | high, medium | An image has no digest Docker pulls, which is `sha256`, `sha384` or `sha512` in lower-case hex of that algorithm's length: high without a tag or with `latest`, medium with another tag |

A PyPI package's rating follows from all its declarations across every file, in any read order. The first exact pin without a marker is the reported version, and it resolves every range it satisfies in any root file, under any marker or group, as a compiled `requirements.txt` resolves `pyproject.toml` ranges. An unsatisfied range is a `version_pinning` finding; declarations under the same markers and group that cannot both hold are a conflict; a URL declaration anywhere is a finding.

The collector cannot tell which file is installed, so a pin in `requirements-docs.txt` also resolves a range in `requirements.txt`; the `declarations` property lists every declaration with its file.

## Identities

| Field | PyPI | npm | Images |
| --- | --- | --- | --- |
| `bom_ref` | `registry:pypi/<normal name>` | `registry:npm/<name in package.json>` | `registry:docker/<reference as written>` |
| `name` | PEP 503 normal name | The package npm installs: the alias target for an alias | The reference as written |
| `package_url` | `pkg:pypi/...` only when every exact pin names the same version, every other declaration admits it, and nothing is a URL, untranslated or in conflict; or the version a `uv.lock` or `poetry.lock` record resolves, with `repository_url` when the record names an index other than PyPI, unless a declaration of the package is a URL or does not admit that version. None when a project setting redirects the package | `pkg:npm/...` from a consistent npm, pnpm or Yarn lockfile record, with `repository_url` when it resolves from another registry, or from an exact spec when the root has no npm lockfile or the one read has no record of the package. None when a project setting redirects the package or a patch may change it | `pkg:oci/...` with `repository_url` and `tag` when the reference has a digest Docker pulls |
| `registry_uri` | `https://pypi.org`; the URL origin when every declaration is a URL with that origin; none when declarations mix a URL with others, a uv, PDM or Poetry source or override replaces the package, or a project setting redirects it; the index origin a `uv.lock` or `poetry.lock` record names | The lockfile record's origin | `https://docker.io`, or `https://` and the registry host |
| `registry_type` | `pypi` | `npm` | `docker-hub` for Docker Hub, `oci` for another registry, none for a reference kept as written because of a substitution or quotes |

PyPI components record their hash pins as `requirement_hashes`, so a changed or removed `--hash` value is drift. Components a lockfile resolves keep the digest of the whole lockfile in `lockfile_sha256`: it is the only drift signal for the transitive dependencies the collector does not inventory. Images record their normalised repository, such as `docker.io/library/ollama`, as `image_repository`.

## Limits

| Input | Limit | Beyond it |
| --- | --- | --- |
| Root `requirements*.txt` files | 4 MiB of text, and 100,000 logical lines, together | Collection failure |
| Option text with a quote or backslash, on one requirement line | 16 KiB | `option line not parsed` gap |
| `pyproject.toml`, `bunfig.toml` and `uv.toml` | 256 KiB each | Collection failure |
| A dotted key or table name in `pyproject.toml`, `bunfig.toml`, `uv.toml`, `uv.lock` or `poetry.lock` | 16 dots, quoted parts included | Collection failure |
| `uv.lock` or `poetry.lock` | 10,000 packages | Collection failure |
| `pnpm-lock.yaml` and `pnpm-workspace.yaml` | 1,000,000 YAML tokens each, and no anchors, aliases or tags | Collection failure |
| `yarn.lock` | 100,000 lines | Collection failure |
| A Compose file | 20,000 YAML tokens and 100,000 merge-key steps | Collection failure |
| A Compose build `context` or `dockerfile` | 4,096 characters, Linux's `PATH_MAX` | `build context not followed` gap, even for a path that names the project root |
| npm `overrides`, `resolutions` and `pnpm.overrides` together | 10,000 entries, nested 32 deep | `dependency override not translated` gap, also for every inventoried npm package |
| One `patchedDependencies` map | 10,000 entries | In `package.json` or `pnpm-workspace.yaml`, the `patched dependency is unverified` gap, which counts for every inventoried npm package; in `pnpm-lock.yaml`, a collection failure |
| An image reference | 520 characters, docker/distribution's limit | `image reference not parsed` gap when it matches the catalog |
| The value of one registry or index setting | 4,096 characters | Still a redirect, recorded as `[not parsed]` without its origins |
| Package sources listed on one package, and settings named in its finding | 32 and 8 | One more entry, or the end of the detail, counts the rest |

## AI package catalog

One catalog serves PyPI and npm. A name is compared in its normal form, in which runs of -, _ and . are one hyphen and letters are lower case, as PEP 503 normalises a PyPI name; an npm scope is kept. A name matches when it is listed, when its npm scope is listed, or when the part after any scope starts with a listed prefix or has a listed word among its hyphen-separated words. A prefix without a trailing hyphen also matches longer names. A name listed for one registry also matches in the other, so an unrelated package of that name there is inventoried too.

### Packages

- Names: `@aws-sdk/client-bedrock-agent-runtime`, `@aws-sdk/client-bedrock-runtime`, `@browserbasehq/stagehand`, `@google-cloud/aiplatform`, `@google-cloud/vertexai`, `@google/adk`, `@google/genai`, `@google/generative-ai`, `accelerate`, `ag2`, `agno`, `ai`, `ai21`, `bitsandbytes`, `browser-use`, `camel-ai`, `ctransformers`, `deepspeed`, `dspy`, `e2b`, `farm-haystack`, `fireworks-ai`, `flash-attn`, `flax`, `gguf`, `griptape`, `groq`, `groq-sdk`, `haystack-ai`, `instructor`, `jax`, `jaxlib`, `js-tiktoken`, `lancedb`, `letta`, `mastra`, `mcp`, `mem0ai`, `mlx`, `node-llama-cpp`, `onnx`, `optimum`, `paddlepaddle`, `pyautogen`, `pymilvus`, `redisvl`, `replicate`, `sentencepiece`, `together`, `trl`, `vertexai`, `voyageai`, `xformers`
- npm scopes, every package of which matches: `@a2a-js`, `@ai-sdk`, `@anthropic-ai`, `@huggingface`, `@lancedb`, `@langchain`, `@llamaindex`, `@mastra`, `@mistralai`, `@mlc-ai`, `@modelcontextprotocol`, `@openai`, `@pinecone-database`, `@qdrant`, `@smithery`, `@tensorflow`, `@tensorflow-models`, `@xenova`, `@zilliz`
- Prefixes: `a2a-sdk`, `agno-`, `anthropic`, `autogen`, `chromadb`, `claude-agent-sdk`, `claude-code-sdk`, `cohere`, `crewai`, `diffusers`, `dspy-`, `e2b-`, `faiss`, `fastmcp`, `google-adk`, `google-cloud-aiplatform`, `google-genai`, `google-generativeai`, `guardrails`, `huggingface`, `keras`, `langchain`, `langgraph`, `langsmith`, `letta-`, `litellm`, `llama-cpp`, `llama-index`, `llamaindex`, `mcp-`, `mistralai`, `mlx-`, `nemo-guardrails`, `nemoguardrails`, `ollama`, `onnxruntime`, `openai`, `peft`, `pgvector`, `pinecone`, `pydantic-ai`, `qdrant`, `rebuff`, `safetensors`, `semantic-kernel`, `sentence-transformers`, `smolagents`, `strands-agents`, `tensorflow`, `tiktoken`, `tokenizers`, `torch`, `transformers`, `vllm`, `weaviate`
- Words: `llm`, `mcp`

### Container images

An image is inventoried when its reference, in lower case, contains one of `chroma`, `huggingface`, `litellm`, `llama`, `lmdeploy`, `localai`, `milvus`, `model`, `ollama`, `onnxruntime`, `pgvector`, `pytorch`, `qdrant`, `sglang`, `tensorflow`, `text-embeddings-inference`, `text-generation-inference`, `tgi`, `triton`, `vllm` or `weaviate`, or has `mcp` or `tei` as one of its parts, such as Docker's MCP catalog images under mcp/. These are substrings: an unrelated image whose name contains one of them is inventoried too.

## Not read

These declare or change what is installed but are not read and leave no gap. Review them by other means.

- Manifests outside the project root: workspace members (a gap when `workspaces`, a `pnpm-workspace.yaml` or `[tool.uv.workspace]` lists them), other `package.json` files, `requirements*.txt` files in subdirectories and pip-tools `*.in` files.
- `setup.py`, `setup.cfg` and dependencies declared dynamic in `pyproject.toml`; conda `environment.yml`; `[tool.hatch.envs]` environments.
- Registry and index settings outside the project root, such as user and global `.npmrc`, pip and uv configuration, in the environment, such as `npm_config_registry`, `PIP_INDEX_URL` and `UV_INDEX_URL`, or on a command line; `pnpm-workspace.yaml` settings are a gap.
- Settings that change how a registry is reached without naming another, such as `--trusted-host`, `strict-ssl=false`, proxies and certificate settings, and uv's `allow-insecure-host`.
- `bundleDependencies`, which npm installs from `dependencies` anyway.
- Code an install runs that can change installed packages other than by a declared patch: lifecycle scripts, such as `patch-package` run from `postinstall`, and pnpm's `.pnpmfile.cjs` hooks. The content of a patch file is not read either.
- Kubernetes manifests, Helm charts and `.devcontainer` configuration.
- Compose provider services (`provider:`), including `type: model`; Compose files that `COMPOSE_FILE` selects when it is set in the environment Compose runs in rather than in `.env`, or that `-f` or `--env-file` select.
- `docker buildx bake` files, such as `docker-bake.hcl` and `docker-bake.json`; in a Compose file, bake's `x-bake` field is read only for its `contexts`.
