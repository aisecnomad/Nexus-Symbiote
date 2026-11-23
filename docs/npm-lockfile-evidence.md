# Lockfile evidence

The registry collector reads direct AI-related dependencies from `package.json` (`peerDependencies`, `dependencies`, `optionalDependencies` and `devDependencies`) and, when present, their exact `node_modules/<name>` records in the `packages` map of the lockfile npm installs from: `npm-shrinkwrap.json` when it exists, otherwise `package-lock.json` (versions 2 and 3, or a compatible map without a version field). An unreadable `npm-shrinkwrap.json` is a collection failure, never replaced by `package-lock.json`.

Which packages count as AI-related, and the findings below, are described in [the registry collector](registry-collector.md).

From a record the collector retains the requested range, the lockfile-declared
version, the sanitized origin of its `resolved` URL, the record's JSON pointer, a
validated SRI integrity value (one or several hashes, at least one of them SHA-256,
SHA-384 or SHA-512), and the SHA-256 of the exact lockfile bytes parsed. The package
URL names the registry with a `repository_url` qualifier when the record resolves
from a host other than `registry.npmjs.org` and `registry.yarnpkg.com`. A record is
checked before it is taken:

- A `resolved` value that is not an `https` URL with a host, or that holds
  whitespace, a control character, a backslash, a non-ASCII character or a percent sign
  in the host, is a collection failure. A WHATWG URL parser, which npm uses, can read
  such a value as another host than Python does.
- A version that is not an exact SemVer version, an integrity value that does not
  decode to its algorithm's length or has only SHA-1, and a version that differs
  from an exact version in `package.json` (which `npm ci` refuses) are collection
  failures. So is a lockfile whose root entry (`packages[""]`) records another spec
  for the package than `package.json`, section by section, or that has no root
  entry, which npm writes in every lockfile with `packages`: `npm ci` refuses it, and
  `npm install` resolves again, so the record is not what installs. A name
  `optionalDependencies` also lists is compared without its `dependencies` copy, which
  npm drops before writing the lockfile. A record whose
  version the recorded spec does not admit is not detected; `npm ci` refuses that
  lockfile too.
- A missing integrity value, a registry other than the default, and a tarball URL
  that names another package or version are findings.
  A range in `package.json` is resolved, with no `version_pinning` finding, only by a
  record with a SHA-256 or stronger integrity value and a consistent tarball URL.
- Local links, and records whose `name` differs from the package `package.json`
  declares, remain unresolved coverage gaps. An `npm:` alias is resolved against the
  package it names.

`pnpm-lock.yaml` and `yarn.lock` (v1 and Berry) are read when one of them is the only
lockfile in the project root (`npm-shrinkwrap.json` and `package-lock.json` count as
npm's one), for each package that `package.json` declares from a registry: the exact
version, SRI integrity and tarball origin of the root importer's record, or of the
stanza for the spec `package.json` declares. A record that only another package's
dependency left, such as a stanza for another range, is not taken, and neither is a
record of a git, URL or path dependency. A pnpm record is the one the lockfile format
reads: `/<name>/<version>` in a 5.x lockfile, `/<name>@<version>` with its peers in
6.x and `<name>@<version>` without them in 9.x, whose peers are in `snapshots`;
another lockfile version is a collection failure, and a record of the same package and
version under another of these spellings that only another lockfile format writes,
which pnpm never reads, makes the resolution ambiguous. Records of one version in
several peer contexts, which 6.x lockfiles hold, are siblings, and the importer's own
is taken. A 5.x importer reference with peers, such as `4.52.0_zod@3.23.8`, is not
parsed: it is a collection failure, and nothing is bound. An importer `specifier` (a
5.x `specifiers` entry) other than the spec pnpm takes from `package.json` (from
`optionalDependencies`, then `dependencies`, `devDependencies` and
`peerDependencies`), or the spec `pnpm.overrides` or `resolutions` gives the whole
name, which pnpm writes in its place, is a stale lockfile, which `pnpm install
--frozen-lockfile` refuses: a collection failure, and nothing is bound. So is an
importer that records no specifier. An override with a range or a parent in its
selector, or one in `pnpm-workspace.yaml`, is not resolved, so a lockfile resolved
through one is reported stale. pnpm lists the root's dependencies in every lockfile
format (5.x at the top level, with `specifiers`), so a lockfile with neither
`importers` nor top-level dependency maps records no specifier: a record found there
by name is stale and binds nothing. Their records are checked as an npm record is: the
`resolved` or `tarball` URL, the exact version, an exact `package.json` version it
contradicts and the integrity value are collection failures as above (so a Yarn v1
`sha1-` value is one), and a tarball URL that names another package or version is a
finding. A missing integrity value is a `missing_lockfile_integrity` finding and
another registry a `registry_origin` one, as for an npm record, and a range they
resolve keeps its `version_pinning` finding. With the lockfiles of
more than one package manager no lockfile evidence is bound, and the conflict is
reported as an exclusion. Workspace, link, file and git resolutions (and Yarn
`patch:` and `portal:` ones), `npm:` aliases, which only npm's own records resolve,
and more than one resolution for the same package are reported as exclusions too.
So is a Yarn Berry `resolution` other than the registry package and version the
record names (`openai@npm:4.52.0` for a record of `openai` 4.52.0): Berry fetches
what the resolution names, a tarball URL or a git repository among them, and records
no URL to check.

The record's position, `lockfile_record` and the `package_resolution` claim's
`locator`, holds no text of a lockfile key but the package name, spec and version
that the inventory records, and the names and exact versions of a pnpm record's
peers. An npm key is written as the package name is recorded, redacted
(`package-lock.json#/packages/node_modules~1openai`). A Yarn record is named by the
selector that the declared spec matched, `yarn.lock#/openai@4.0.0`, or
`yarn.lock#/openai@npm:4.0.0` in a Berry lockfile, whose one key lists every
descriptor of the stanza; another selector of the stanza, which may be a tarball
URL with a token in it, is never recorded. A credential-shaped selected locator is
reduced to the lockfile name. A private resolved version is redacted and its package
URL is withheld. A pnpm package key is recorded whole when
its peer suffix names only packages with exact versions, and patch hashes, in
balanced parentheses as pnpm writes them
(`pnpm-lock.yaml#/packages/~1openai@4.0.0(react@18.2.0)`). A suffix that holds
anything else, such as a URL, a path, a credential-shaped name or unbalanced
parentheses, is recorded as `(***)`: `pnpm-lock.yaml#/packages/~1openai@4.0.0(***)`
no longer points at the key, which the root importer's `version`, or the lockfile's
only record of the package, names.

`yarn.lock` is tokenized as Yarn 1 reads it: a quoted key, selector or value is a
JSON string and is decoded, so `"resolved" "https://..."` and `"\u006fpenai@4.0.0":`
bind the record Yarn installs from. A selector in more than one stanza, which Yarn 1
installs from the last of, is reported as `multiple package resolutions for <package>
are ambiguous` and binds neither stanza; so is a declared spec that one stanza spells
`openai@4.0.0` and another `openai@npm:4.0.0`, since Yarn 1 looks up the first
spelling and Yarn Berry the second. So is, in a Yarn 1 lockfile, a stanza of another
range of the package, such as `openai@^4.0.0`, with the same `version` as the declared
spec's stanza and another `resolved`, `integrity` or `checksum`: Yarn 1 reuses the
first record it resolves with that version, so when a dependency listed earlier in
`package.json` depends on the other range, Yarn installs the other stanza.

When `package.json` declares a package in more than one section with different
specs, Yarn 1 takes the first that is neither `""` nor `*`, in the order
`optionalDependencies`, `dependencies`, `devDependencies`, and that spec's stanza is
the one bound, not the stanza of npm's last-section spec. Which spec Yarn Berry takes
is not resolved here, so a Berry lockfile binds neither and reports `multiple package
resolutions for <package> are ambiguous`. So does a pnpm root importer that resolves
the package to different versions in two of its sections.

So is, in a Yarn Berry lockfile, a second stanza whose `resolution` names the
declared spec's locator, under any key (`openai@npm:^4.0.0` or `zzz@npm:1.0.0` with
`resolution: "openai@npm:4.0.0"`). Yarn writes one stanza per locator, and Yarn 4
keeps the last one it reads, with its `conditions`, and the last `checksum` of any of
them, so a second stanza with `checksum: 9/<digest>` lets a mismatching archive in
unchecked. So is a stanza that names a package Yarn 4 hashes as it hashes the
declared one, in its key or its `resolution`. Yarn hashes a scope and a name joined
with nothing between them, so it reads `@op/enai@npm:4.0.0` as `openai@npm:4.0.0`: a
stanza keyed by it replaces the declared spec's resolution, and a resolution that
names it replaces the package Yarn fetches for the locator, each with another
package's archive. An `npm:` alias whose key Yarn hashes as it hashes a name in the
lockfile is an `aliased package identity is unresolved` exclusion. Yarn refuses these
lockfiles in an immutable install, its default in CI, but installs from them with
`enableImmutableInstalls: false` or outside CI.

Each Yarn reads one digest field. A Yarn 1 `checksum` is not an integrity value, since
Yarn 1 does not read it, so a v1 record with one and no `integrity` has a
`missing_lockfile_integrity` finding. Neither is a Berry `integrity`, which Berry does
not read: it is not recorded and not exported as a hash. A Berry `checksum` counts
only when Yarn 4 checks the archive it fetches against it, and otherwise the record
has a `missing_lockfile_integrity` finding. Yarn checks a checksum that names the
cache key it computes, `10c0` at its default compression level, and accepts an
archive unchecked when the key differs. So the checksum must be a 128-character
hexadecimal SHA-512 digest whose key, its own prefix (`10c0/<digest>`) or else the
lockfile's `__metadata.cacheKey`, is `10c0`, and the lockfile's `cacheKey` must be
`10c0` too. A lockfile that Yarn 2 or 3 wrote, with `cacheKey: 8`, records no checksum
that counts. Nor does a record with `conditions`, for a package Yarn installs on some
platforms only: Yarn does not check its archive when it is an optional dependency.
Nor does any checksum when the root `.yarnrc.yml` sets `checksumBehavior`
to another value than `throw`, `compressionLevel` to another value than 0,
`enableGlobalCache` to another value than `true`, `globalFolder` or `yarnPath`: Yarn
then accepts a mismatching archive, computes another key, may take the archive from a
cache folder the project supplies, or runs a Yarn release the project supplies. A
`.yarnrc.yml` that cannot be read counts as one that sets them. Nor does any checksum
when `package.json` names a release other than Yarn 4 for Corepack to run, which
computes another cache key: a `packageManager` other than `yarn@4.<version>`, or a
`devEngines.packageManager` other than one object named `yarn` whose `version`, if
any, is a Yarn 4 version or a `^` or `~` range of one. The Berry checksum itself is not
recorded; it is the digest of the archive Yarn stores, not of the registry's tarball.

A line that Yarn 1, or the YAML reader Yarn Berry uses for a lockfile that starts with
`__metadata` (unquoted or as a JSON string), reads differently or not at all fails the
lockfile as `yarn.lock: invalid or unsupported lockfile`: a single quote, a tab, a
comment after text or indented, an odd or deeper indentation than an object opens, an
indented line after an empty or comment line (after one empty line Yarn 1 keeps
reading the stanza, and after more it stops reading the lockfile), a whitespace-only
line, a word Yarn 1 splits into a number or `true`/`false` and a string (such as an
unquoted `4.0.0`), an invalid escape, more than one value, a duplicate key, a selector
with surrounding spaces or other whitespace (Berry splits a key at each comma and the
spaces around it, and keeps a tab or any other whitespace in the descriptor), a
carriage return that is not followed by a line feed (Yarn 1 ends the line there but
reads the spaces after it as no indentation), a `yarn lockfile v<N>` comment with `N`
above 1 (Yarn 1 refuses it and re-reads the whole file as YAML, where a stanza can be
a string that names another), a stanza key without a package name, a Berry field
without a colon, and a `version`, `resolved`, `integrity`, `resolution`, `checksum`,
`linkType`, `conditions` or `cacheKey` that is not a string. A Berry value is a JSON
string or a YAML plain scalar as Berry writes one, inner spaces included
(`react: ^16.8.0 || ^17.0.0`, `conditions: os=linux & cpu=x64`); a plain value that
starts with a YAML indicator such as `>` or `|`, or contains `:`, `#`, `,`, a bracket,
a brace or a quote, fails the lockfile.

Some constructs that Yarn reads but never writes also fail the lockfile, as
unsupported, not because Yarn reads them differently: an empty stanza or nested map, a nested map
in a Yarn 1 stanza other than the `dependencies`, `optionalDependencies`,
`permissions` and `prebuiltVariants` that Yarn 1 writes, or one inside them, a
`resolution`, `languageName` or `linkType` field in a Yarn 1 stanza (a dependency of
that name is read), a quoted Yarn 1 selector that holds a comma list, unless the file
has a `# yarn lockfile v1` comment and every part names the same package without a
Berry protocol such as `npm:`, a bracket or brace inside a word, a `yarn lockfile`
comment in a lockfile that starts with `__metadata`, and a space before the colon of
a stanza header.

A package that a patch may change at install binds no record from any lockfile, and
an exact version in `package.json` names no package URL for it: a lockfile's integrity
value is that of the unpatched tarball. pnpm applies the patches that
`pnpm.patchedDependencies` in `package.json` or `patchedDependencies` in
`pnpm-workspace.yaml` name, and records them in `pnpm-lock.yaml` as
`patchedDependencies`, a `(patch_hash=...)` group after the importer's version, or
`patched: true` on a lockfile v6 record; Bun applies those of a top-level
`patchedDependencies`. Any of them naming the package, whatever version it gives, is
the `patched dependency is unverified` exclusion, with a medium `nonregistry_source`
finding on the package, as described with the
[coverage gaps](registry-collector.md#coverage-gaps). A hash in a peer's group, as in
the `@langchain/core` version `0.3.0(openai@4.104.0(patch_hash=...))`, is the peer's,
not the package's. A patch of a catalogued AI package that `package.json` does not
declare, such as that `openai`, is the same exclusion with no finding:
`@langchain/core` keeps its record, and no component binds the patched package.

For Python, `uv.lock` or `poetry.lock` in the project root supplies the exact
version and the index origin of each AI package declared in `requirements*.txt` or
`pyproject.toml`, the lockfile record's position, and the SHA-256 of the lockfile.
Artifact digests in the lockfile are not recorded. With both lockfiles present, for
a package with a local, git or URL source in the lockfile, or for one that a root
file declares from a URL, no resolution is bound. A version that a declaration of
the package does not admit, in any root file and under any marker or group, is a
collection failure, as for npm: the lockfile is stale, or the file is not installed
from it. A `poetry.lock` record with a `reference` is bound only when the reference
names a source `pyproject.toml` declares, explicit sources included, at the record's
index origin (PyPI for Poetry's own `PyPI`): Poetry downloads from the source the
reference names, whatever `url` the record shows. Otherwise the record is an
exclusion and no package URL is bound. `[build-system]` requires are not compared, because neither lockfile locks
them.

These are declared resolution claims with unknown trust. The collector does not fetch packages, establish their presence, verify registry ownership or publisher identity, or prove that package bytes match the lockfile. Raw download paths, userinfo, tokens and signed URL parameters are omitted from both recorded origins and record positions.

A manifest without a supported lock record does not establish a registry origin. An exact version in `package.json` names a package URL without a record only when the project root has no npm lockfile, or the one read has no record of the package: a lockfile that is ambiguous, refused or not parsed may install it from elsewhere. `bun.lock`, `bun.lockb`, `Pipfile.lock` and `pdm.lock` are not read; when one exists, each package of its ecosystem gets a low `lockfile_unread` finding.
