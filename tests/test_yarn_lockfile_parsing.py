"""yarn.lock is read as Yarn reads it, or not at all."""

import base64
import json

import pytest

from nexus_symbiote.scanners.registry import RegistryScanner

SHA512 = "sha512-" + base64.b64encode(b"w" * 64).decode()
# A checksum Yarn 4 checks: its default cache key and a SHA-512 hex digest.
CHECKSUM = "10c0/" + "ab" * 64
PUBLIC = "https://registry.yarnpkg.com/openai/-/openai-4.0.0.tgz"
EVIL = "https://evil.example/openai.tgz"
UNREAD = ["yarn.lock: invalid or unsupported lockfile"]
AMBIGUOUS = ["yarn.lock: multiple package resolutions for openai are ambiguous"]
PINNED = {"openai": "4.0.0"}


def scan(tmp_path, lock):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.0.0"}}')
    (tmp_path / "yarn.lock").write_text(lock, newline="")
    result = RegistryScanner().scan(tmp_path)
    (comp,) = result.components
    return result, comp


def stanza(header, resolved, integrity=True):
    lines = [f"{header}:", '  version "4.0.0"', f'  resolved "{resolved}"']
    if integrity:
        lines.append(f"  integrity {SHA512}")
    return "\n".join(lines) + "\n"


def assert_unbound(comp):
    assert comp.package_url is None and comp.registry_uri is None
    assert "package_resolution" not in comp.claims


@pytest.mark.parametrize(
    "lock",
    [
        # Yarn 1 keeps the last stanza of a repeated selector and installs from it.
        stanza("openai@4.0.0", PUBLIC) + "\n" + stanza("openai@4.0.0", EVIL, integrity=False),
        stanza("openai@4.0.0", EVIL, integrity=False) + "\n" + stanza("openai@4.0.0", PUBLIC),
        stanza('"openai@4.0.0", "openai@^4.0.0"', PUBLIC)
        + "\n"
        + stanza('"openai@4.0.0"', EVIL, integrity=False),
        stanza("openai@4.0.0", PUBLIC) + "\n" + stanza('"openai@4.0.0"', EVIL),
        stanza("openai@4.0.0", PUBLIC) + "\n" + stanza('"\\u006fpenai@4.0.0"', EVIL),
    ],
    ids=["legit-first", "legit-last", "multi-selector", "quoted-repeat", "escaped-repeat"],
)
def test_a_selector_in_more_than_one_stanza_binds_neither(tmp_path, lock):
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == []
    assert result.surfaces_excluded == AMBIGUOUS
    assert_unbound(comp)


def test_a_repeated_selector_of_another_spec_does_not_block_the_declared_one(tmp_path):
    lock = (
        stanza("openai@4.0.0", PUBLIC)
        + "\n"
        + stanza("openai@^3.0.0", PUBLIC)
        + "\n"
        + stanza("openai@^3.0.0", PUBLIC)
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


@pytest.mark.parametrize(
    "other",
    [
        stanza("openai@^4.0.0", EVIL, integrity=False),
        stanza("openai@^4.0.0", EVIL),
        stanza("openai@^4.0.0", PUBLIC, integrity=False),
        stanza('"openai@npm:^4.0.0"', EVIL),
    ],
    ids=["evil-url", "evil-url-with-integrity", "no-integrity", "npm-range"],
)
def test_another_range_with_the_same_version_and_another_source_binds_neither(tmp_path, other):
    # Yarn 1 reuses the first pattern it resolved with that version, so a dependency
    # earlier in package.json on `openai@^4.0.0` makes it install the other stanza.
    for lock in (
        stanza("openai@4.0.0", PUBLIC) + "\n" + other,
        other + "\n" + stanza("openai@4.0.0", PUBLIC),
    ):
        result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
        assert result.scan_failures == []
        assert result.surfaces_excluded == AMBIGUOUS
        assert_unbound(comp)


def test_another_range_with_another_version_does_not_block_the_declared_one(tmp_path):
    lock = (
        stanza("openai@4.0.0", PUBLIC)
        + "\n"
        + stanza("openai@^4.0.0", EVIL).replace('"4.0.0"', '"4.1.0"')
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert comp.registry_uri == "https://registry.yarnpkg.com"


def test_a_yarn_1_checksum_is_not_integrity(tmp_path):
    lock = stanza("openai@4.0.0", PUBLIC, integrity=False) + '  checksum "x"\n'
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert [r.category for r in comp.risks] == ["missing_lockfile_integrity"]


@pytest.mark.parametrize(
    "lock",
    [
        # Yarn decodes quoted keys and selectors as JSON strings.
        f'openai@4.0.0:\n  version "4.0.0"\n  "resolved" "{EVIL}"\n  integrity {SHA512}\n',
        f'openai@4.0.0:\n  "version" "4.0.0"\n  "resolved": "{EVIL}"\n',
        f'"\\u006fpenai@4.0.0":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'"openai@^3.0.0", "openai@4.0.0":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'openai@^3.0.0,openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        'openai@4.0.0:\n  version "4.0.0"\n  resolved "https:\\/\\/evil.example/openai.tgz"\n',
        f'openai@4.0.0:\r\n  version "4.0.0"\r\n  resolved "{EVIL}"\r\n',
    ],
    ids=[
        "quoted-key",
        "quoted-keys-colon",
        "escaped-selector",
        "quoted-list",
        "unspaced-list",
        "escaped-value",
        "crlf",
    ],
)
def test_the_record_yarn_installs_is_the_one_bound(tmp_path, lock):
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.registry_uri == "https://evil.example"
    assert comp.properties["lockfile_record"] == "yarn.lock#/openai@4.0.0"
    # The tarball path is not the npm layout for the package, so no identity is claimed.
    assert comp.package_url is None
    categories = [r.category for r in comp.risks]
    assert "registry_origin" in categories and "lockfile_resolution_mismatch" in categories


@pytest.mark.parametrize(
    "lock",
    [
        # Each is a line the tokenizer reads differently, or not at all.
        f"openai@4.0.0:\n  version '4.0.0'\n  resolved \"{EVIL}\"\n",
        f'openai@4.0.0:\n  version "4.0.0"\n\t"resolved" "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n   resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n    resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n# c\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  # c\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n    \n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version 4.0.0\n  resolved "{EVIL}"\n',
        'openai@4.0.0:\n  version "4.0.0"\n  resolved "https://evil.example\\@x/o.tgz"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}" "x"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}" # c\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved\n  integrity {SHA512}\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved, integrity "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  "" "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved:\n    url "{EVIL}"\n',
        f'"openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'@scope/x@1, openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'" openai@4.0.0":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'openai@4.0.0 "x":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\u2028x\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  truex "{EVIL}"\n',
        f'openai@4.0.0:\n  version "4.0.0"\n  resolved:"{EVIL}"\n',
        f'openai@4.0.0:\n  version 4\n  resolved "{PUBLIC}"\n',
        'openai@4.0.0:\n  version "4.0.0"\n  resolved true\n',
        # Yarn 1 ends a line at a lone CR and reads the next line as a top-level key.
        stanza("openai@4.0.0", PUBLIC)
        + "\nzzpad@1.0.0:\r  openai@4.0.0:\n"
        + f'  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'zzpad@1.0.0:\r  openai@4.0.0:\n  version "4.0.0"\n  resolved "{EVIL}"\n',
        f'openai@4.0.0:\r  version "4.0.0"\r  resolved "{EVIL}"\r',
    ],
    ids=[
        "single-quote",
        "tab",
        "odd-indent",
        "over-indent",
        "blank-then-field",
        "comment-then-field",
        "indented-comment",
        "whitespace-line",
        "bare-dotted-number",
        "invalid-escape",
        "extra-token",
        "trailing-comment",
        "key-without-value",
        "key-list",
        "empty-key",
        "object-field",
        "unterminated-header",
        "bare-at-selector",
        "padded-selector",
        "header-value",
        "line-separator",
        "boolean-prefix",
        "unspaced-colon",
        "number-value",
        "boolean-value",
        "lone-cr-hides-repeat",
        "lone-cr-hides-stanza",
        "lone-cr-only",
    ],
)
def test_a_line_the_parser_does_not_understand_fails_the_lockfile(tmp_path, lock):
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


def test_an_ordinary_yarn_lockfile_with_dependencies_is_bound(tmp_path):
    lock = (
        "# THIS IS AN AUTOGENERATED FILE. DO NOT EDIT THIS FILE DIRECTLY.\n"
        "# yarn lockfile v1\n\n\n"
        '"@types/node@*", "@types/node@^18.0.0":\n'
        '  version "18.19.0"\n'
        '  resolved "https://registry.yarnpkg.com/@types/node/-/node-18.19.0.tgz"\n'
        f"  integrity {SHA512}\n"
        "  dependencies:\n"
        '    undici-types "~5.26.4"\n\n'
        "openai@4.0.0:\n"
        '  version "4.0.0"\n'
        f'  resolved "{PUBLIC}#0123abc"\n'
        f"  integrity {SHA512}\n"
        "  dependencies:\n"
        '    "@types/node" "^18.0.0"\n'
        '    abort-controller "^3.0.0"\n'
        "  optionalDependencies:\n"
        '    fsevents "~2.3.2"\n'
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert comp.properties["lockfile_record"] == "yarn.lock#/openai@4.0.0"


def test_a_berry_lockfile_with_nested_metadata_is_bound(tmp_path):
    lock = (
        '# This file is generated by running "yarn install" inside your project.\n'
        "# Manual changes might be lost - proceed with caution!\n\n"
        "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
        '"openai@npm:4.0.0, openai@npm:^4.0.0":\n'
        "  version: 4.0.0\n"
        '  resolution: "openai@npm:4.0.0"\n'
        "  dependencies:\n"
        '    "@types/node": "npm:^18.11.18"\n'
        "  dependenciesMeta:\n"
        "    fsevents:\n"
        "      optional: true\n"
        f"  checksum: {CHECKSUM}\n"
        "  languageName: node\n"
        "  linkType: hard\n"
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert comp.risks == []


BERRY_HEAD = "__metadata:\n  version: 8\n  cacheKey: 10c0\n\n"
BERRY_OPENAI = (
    '"openai@npm:4.0.0":\n  version: 4.0.0\n  resolution: "openai@npm:4.0.0"\n'
    f"  checksum: {CHECKSUM}\n  languageName: node\n  linkType: hard\n"
)


@pytest.mark.parametrize(
    "extra",
    [
        '"use-sync-external-store@npm:^1.2.0":\n  version: 1.2.0\n'
        "  peerDependencies:\n    react: ^16.8.0 || ^17.0.0 || ^18.0.0\n",
        '"@rollup/rollup-linux-x64-gnu@npm:4.24.0":\n  version: 4.24.0\n'
        "  conditions: os=linux & cpu=x64 & libc=glibc\n",
        '"x@npm:1.0.0":\n  version: 1.0.0\n  peerDependencies:\n    react: ">=16"\n',
    ],
    ids=["peer-range", "conditions", "quoted-range"],
)
def test_berry_plain_scalars_with_spaces_are_read(tmp_path, extra):
    result, comp = scan(tmp_path, BERRY_HEAD + BERRY_OPENAI + "\n" + extra)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert comp.risks == []


@pytest.mark.parametrize(
    "line",
    [
        # Each is a value a YAML reader reads differently, or not as one string.
        "    react: >=16",
        "    react: ^16 # c",
        "    react: a: b",
        "    react: ^16 ",
        "    react: [16]",
        "    react: |16",
        "    react: ",
        "    react:^16",
    ],
    ids=[
        "block-indicator",
        "comment",
        "nested-colon",
        "trailing-space",
        "flow",
        "pipe",
        "empty",
        "unspaced",
    ],
)
def test_a_berry_value_yaml_reads_otherwise_fails_the_lockfile(tmp_path, line):
    extra = '"x@npm:1.0.0":\n  version: 1.0.0\n  peerDependencies:\n' + line + "\n"
    result, comp = scan(tmp_path, BERRY_HEAD + BERRY_OPENAI + "\n" + extra)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


@pytest.mark.parametrize(
    "lock",
    [
        # Without __metadata, Yarn 1 reads a quoted list as one selector.
        f'"openai@^3.0.0, openai@4.0.0":\n  version "4.0.0"\n  resolved "{EVIL}"\n',
    ],
)
def test_a_quoted_comma_list_is_one_yarn_v1_selector(tmp_path, lock):
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.registry_uri is None and comp.source_path == "package.json"


def test_a_berry_field_line_without_a_colon_fails_the_lockfile(tmp_path):
    lock = (
        "__metadata:\n  version: 8\n\n"
        '"openai@npm:4.0.0":\n  version: 4.0.0\n  resolution "openai@npm:4.0.0"\n'
    )
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


def test_a_json_string_is_decoded_as_json(tmp_path):
    header = json.dumps("openai@4.0.0")
    lock = f'{header}:\n  version "4.0.0"\n  resolved {json.dumps(PUBLIC)}\n'
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


# The first stanza as one folded YAML plain scalar: the key a string alias points to.
# Its `uid` gives the alias target a package name, which the version check alone refuses.
FOLDED = json.dumps(f'version "4.0.0" resolved "{PUBLIC}" integrity {SHA512} uid "x@y"')


@pytest.mark.parametrize(
    "comment",
    ["# yarn lockfile v9", "#yarn lockfile v2", "#   yarn lockfile v0010  "],
)
def test_a_version_comment_above_1_fails_the_lockfile(tmp_path, comment):
    # Yarn 1 refuses it and re-reads the file as YAML, where the first stanza is a
    # string that aliases the second stanza's key.
    lock = (
        stanza("openai@4.0.0", PUBLIC)
        + '  uid "x@y"\n'
        + f"\n{comment}\n\n{FOLDED}:\n"
        + f'  version: "4.0.0"\n  resolved: "{EVIL}"\n'
    )
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


@pytest.mark.parametrize("comment", ["# yarn lockfile v1", "# yarn lockfile v0", "# lockfile v9"])
def test_a_version_comment_yarn_accepts_is_read(tmp_path, comment):
    result, comp = scan(tmp_path, f"{comment}\n\n" + stanza("openai@4.0.0", PUBLIC))
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


@pytest.mark.parametrize("header", ["foo", '"version \\"4.0.0\\""', '"@scope"', "openai@4.0.0, x"])
def test_a_selector_without_a_package_name_fails_the_lockfile(tmp_path, header):
    lock = stanza("openai@4.0.0", PUBLIC) + "\n" + stanza(header, EVIL)
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


@pytest.mark.parametrize(
    "lock",
    [
        # Yarn 1 looks up `openai@4.0.0` as package.json spells it.
        "# yarn lockfile v1\n\n"
        + stanza('"openai@npm:4.0.0"', PUBLIC)
        + "\n"
        + stanza("openai@4.0.0", EVIL, integrity=False),
        "# yarn lockfile v1\n\n"
        + stanza("openai@4.0.0", PUBLIC)
        + "\n"
        + stanza('"openai@npm:4.0.0"', EVIL, integrity=False),
        # Berry normalizes the declared `4.0.0` to `openai@npm:4.0.0`.
        BERRY_HEAD
        + '"openai@4.0.0":\n  version: 4.0.0\n  resolution: "openai@npm:4.0.0"\n'
        + "  checksum: 10c0/abab\n  languageName: node\n  linkType: hard\n\n"
        + '"openai@npm:4.0.0":\n  version: 4.0.0\n'
        + f'  resolution: "openai@{EVIL}"\n  languageName: node\n  linkType: hard\n',
    ],
    ids=["v1-npm-first", "v1-bare-first", "berry-bare-first"],
)
def test_a_spec_and_its_npm_spelling_in_two_stanzas_bind_neither(tmp_path, lock):
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == []
    assert result.surfaces_excluded == AMBIGUOUS
    assert_unbound(comp)


def test_one_stanza_with_a_spec_and_its_npm_spelling_is_bound(tmp_path):
    lock = stanza('"openai@4.0.0", "openai@npm:4.0.0"', PUBLIC)
    result, comp = scan(tmp_path, "# yarn lockfile v1\n\n" + lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


@pytest.mark.parametrize("meta_header", ['"__metadata":', '"\\u005f_metadata":'])
def test_quoted_berry_metadata_enables_berry_parsing_and_comma_splitting(tmp_path, meta_header):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"^4.0.0"}}')
    lock = (
        f"{meta_header}\n  version: 8\n  cacheKey: 10c0\n\n"
        '"other@npm:^1.0.0, openai@npm:^4.0.0":\n'
        "  version: 4.0.0\n"
        f'  resolution: "openai@{EVIL}"\n'
        f"  checksum: {CHECKSUM}\n"
        "  languageName: node\n"
        "  linkType: hard\n"
    )
    (tmp_path / "yarn.lock").write_text(lock, newline="")
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert result.surfaces_excluded == ["yarn.lock: local or non-registry resolution is unverified"]
    (comp,) = result.components
    assert_unbound(comp)


@pytest.mark.parametrize(
    "lock",
    [
        '"other@npm:^1.0.0, openai@npm:4.0.0":\n'
        '  version: "4.0.0"\n'
        f'  resolution: "openai@{EVIL}"\n',
        '# yarn lockfile v1\n\n"other@npm:^1.0.0, openai@npm:4.0.0":\n'
        '  version "4.0.0"\n'
        f'  resolved "{EVIL}"\n',
        '# yarn lockfile v1\n\n"other@^1.0.0, openai@4.0.0":\n'
        '  version "4.0.0"\n'
        f'  resolved "{EVIL}"\n',
        '# yarn lockfile v1\n\n"__metadata":\n  version: 8\n\n' + BERRY_OPENAI,
    ],
    ids=["yaml-without-meta", "v1-berry-protocol", "v1-cross-pkg-comma", "v1-comment-with-meta"],
)
def test_disguised_or_mixed_berry_selectors_fail_the_lockfile(tmp_path, lock):
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


@pytest.mark.parametrize(
    "lock",
    [
        "# yarn lockfile v1\n\nempty@1.0.0:\n" + stanza("openai@4.0.0", PUBLIC),
        "# yarn lockfile v1\n\nempty@1.0.0:\n\n" + stanza("openai@4.0.0", PUBLIC),
        "# yarn lockfile v1\n\n" + stanza("openai@4.0.0", PUBLIC) + "\nempty@1.0.0:\n",
        "# yarn lockfile v1\n\n" + stanza("openai@4.0.0", PUBLIC) + "  dependencies:\n",
        "# yarn lockfile v1\n\n"
        'openai@4.0.0:\n  version "4.0.0"\n  dependencies:\n'
        f'  resolved "{PUBLIC}"\n',
        "# yarn lockfile v1\n\n" + stanza("openai@4.0.0", PUBLIC) + '  custom:\n    foo "1.0.0"\n',
        "# yarn lockfile v1\n\n"
        + stanza("openai@4.0.0", PUBLIC)
        + '  dependencies:\n    nested:\n      foo "1.0.0"\n',
        "# yarn lockfile v1\n\n"
        'openai@4.0.0:\n  version "4.0.0"\n  resolved ' + f'"{PUBLIC}"\n  integrity {{a}}\n',
        "# yarn lockfile v1\n\n"
        'openai@4.0.0:\n  version "4.0.0"\n  resolved ' + f'"{PUBLIC}"\n  integrity [a]\n',
        "__metadata:\n\n" + BERRY_OPENAI,
        BERRY_HEAD + '"empty@npm:1.0.0":\n\n' + BERRY_OPENAI,
    ],
    ids=[
        "empty-stanza-adjacent",
        "empty-stanza-blank",
        "empty-stanza-eof",
        "empty-dependencies-eof",
        "empty-dependencies-dedent",
        "v1-unknown-nested-map",
        "v1-deep-nested-map",
        "v1-flow-brace",
        "v1-flow-bracket",
        "empty-berry-metadata",
        "empty-berry-stanza",
    ],
)
def test_empty_stanzas_and_maps_yarn_does_not_write_fail_the_lockfile(tmp_path, lock):
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


@pytest.mark.timeout(30)
def test_a_berry_key_with_a_long_run_of_spaces_is_split_in_linear_time():
    # Splitting at \s*,\s* backtracked over a run of spaces that no comma follows:
    # 1.7 seconds for 40,000 spaces, growing with the square of the run, so this key
    # took about twenty minutes and the test ran out of time.
    from nexus_symbiote.scanners.registry import _yarn_lockfile_stanzas

    key = "a@npm:1.0.0" + " " * (1024 * 1024) + "b@npm:1.0.0"
    lock = BERRY_HEAD + f'"{key}":\n  version: 1.0.0\n'
    metadata, stanzas = _yarn_lockfile_stanzas(lock)
    assert metadata == {"version": "8", "cacheKey": "10c0"}
    assert [selectors for selectors, _ in stanzas] == [[key]]
    padded = "other@npm:1.0.0" + " " * (1024 * 1024) + ", openai@npm:4.0.0"
    _, stanzas = _yarn_lockfile_stanzas(BERRY_HEAD + f'"{padded}":\n  version: 4.0.0\n')
    assert stanzas[0][0] == ["other@npm:1.0.0", "openai@npm:4.0.0"]


def berry_record(*fields):
    return (
        '"openai@npm:4.0.0":\n  version: 4.0.0\n  resolution: "openai@npm:4.0.0"\n'
        + "".join(f"  {field}\n" for field in fields)
        + "  languageName: node\n  linkType: hard\n"
    )


HEX = "ab" * 64


@pytest.mark.parametrize(
    ("head", "fields", "checked"),
    [
        (BERRY_HEAD, [f"checksum: 10c0/{HEX}"], True),
        # Yarn prefixes a checksum without a cache key with the lockfile's.
        (BERRY_HEAD, [f"checksum: {HEX}"], True),
        (BERRY_HEAD, [], False),
        (BERRY_HEAD, ["checksum: x"], False),
        (BERRY_HEAD, ["checksum: 10c0/abab"], False),
        (BERRY_HEAD, ["checksum: 10c0/" + "zz" * 64], False),
        (BERRY_HEAD, [f"checksum: /{HEX}"], False),
        # Yarn accepts an archive unchecked when the checksum names another cache key
        # than the one it computes, 10c0 for Yarn 4 at its default compression level.
        (BERRY_HEAD, [f"checksum: 10/{HEX}"], False),
        (BERRY_HEAD, [f"checksum: 9/{HEX}"], False),
        (BERRY_HEAD, [f"checksum: 8/{HEX}"], False),
        (BERRY_HEAD, [f"checksum: 10c1/{HEX}"], False),
        (BERRY_HEAD, [f"checksum: ffff/{HEX}"], False),
        (BERRY_HEAD, [f"checksum: 10/c0/{HEX}"], False),
        (BERRY_HEAD, [f"checksum: 10c0/10c0/{HEX}"], False),
        ("__metadata:\n  version: 8\n\n", [f"checksum: {HEX}"], False),
        ("__metadata:\n  version: 8\n\n", [f"checksum: 10c0/{HEX}"], False),
        ("__metadata:\n  version: 6\n  cacheKey: 8\n\n", [f"checksum: {HEX}"], False),
        ("__metadata:\n  version: 8\n  cacheKey: 8\n\n", [f"checksum: 10c0/{HEX}"], False),
        # Yarn does not check the archive of a conditional package that is optional.
        (BERRY_HEAD, [f"checksum: 10c0/{HEX}", "conditions: os=linux"], False),
    ],
)
def test_a_berry_checksum_counts_only_when_yarn_checks_it(tmp_path, head, fields, checked):
    result, comp = scan(tmp_path, head + berry_record(*fields))
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    missing = [r.category for r in comp.risks] == ["missing_lockfile_integrity"]
    assert missing is not checked and (missing or comp.risks == [])
    assert "lockfile_integrity" not in comp.properties


@pytest.mark.parametrize(
    ("yarnrc", "checked"),
    [
        ("checksumBehavior: throw\ncompressionLevel: 0\nenableGlobalCache: true\n", True),
        ('compressionLevel: "0"\n', True),
        ('npmRegistryServer: "https://registry.yarnpkg.com"\n', True),
        ("checksumBehavior: ignore\n", False),
        ("checksumBehavior: update\n", False),
        ("checksumBehavior: reset\n", False),
        ('checksumBehavior: "${BEHAVIOR}"\n', False),
        # The cache key becomes 10c1, or 10 for mixed, which a 10c0 checksum does not name.
        ("compressionLevel: 1\n", False),
        ("compressionLevel: mixed\n", False),
        ("compressionLevel: false\n", False),
        # The project's own cache folder may hold an archive that matches the checksum.
        ("enableGlobalCache: false\n", False),
        ("globalFolder: ./.yarn/global\n", False),
        # Yarn runs the release the checkout supplies, which may compute another key.
        ("yarnPath: .yarn/releases/yarn-3.8.7.cjs\n", False),
        ("yarnPath: .yarn/releases/yarn-4.9.2.cjs\n", False),
    ],
)
def test_yarnrc_settings_that_skip_the_checksum_check_leave_no_integrity(tmp_path, yarnrc, checked):
    (tmp_path / ".yarnrc.yml").write_text(yarnrc)
    result, comp = scan(tmp_path, BERRY_HEAD + BERRY_OPENAI)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert result.surfaces_scanned.count(".yarnrc.yml") == 1
    assert ("missing_lockfile_integrity" in {r.category for r in comp.risks}) is not checked


def test_an_unreadable_yarnrc_fails_once_and_leaves_no_integrity(tmp_path):
    (tmp_path / ".yarnrc.yml").write_text("- not\n- a mapping\n")
    result, comp = scan(tmp_path, BERRY_HEAD + BERRY_OPENAI)
    assert result.scan_failures == [".yarnrc.yml: YAML mapping parse failed or unsupported"]
    assert [r.category for r in comp.risks] == ["missing_lockfile_integrity"]


def test_an_excluded_yarnrc_leaves_berry_checksum_unverified(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.0.0"}}')
    (tmp_path / ".yarnrc.yml").write_text("checksumBehavior: ignore\n")
    (tmp_path / "yarn.lock").write_text(BERRY_HEAD + BERRY_OPENAI, newline="")
    scanner = RegistryScanner()
    scanner.configure(exclude_paths=(".yarnrc.yml",))
    result = scanner.scan(tmp_path)
    assert any(".yarnrc.yml" in entry for entry in result.surfaces_excluded)
    (comp,) = result.components
    assert [r.category for r in comp.risks] == ["missing_lockfile_integrity"]


def test_saturated_scan_failures_still_detect_unreadable_yarnrc(tmp_path, monkeypatch):
    from nexus_symbiote.utils import confined

    monkeypatch.setattr(confined, "MAX_LISTED_FAILURES", 1)
    (tmp_path / ".yarnrc.yml").write_text("- not\n- a mapping\n")
    scanner = RegistryScanner()
    orig_lock = scanner._npm_lock

    def prefill_and_lock(result):
        result.scan_failures.append("prefilled-1")
        result.scan_failures.append("prefilled-2")
        return orig_lock(result)

    monkeypatch.setattr(scanner, "_npm_lock", prefill_and_lock)
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"4.0.0"}}')
    (tmp_path / "yarn.lock").write_text(BERRY_HEAD + BERRY_OPENAI, newline="")
    result = scanner.scan(tmp_path)
    (comp,) = result.components
    assert [r.category for r in comp.risks] == ["missing_lockfile_integrity"]


@pytest.mark.parametrize(
    "fields",
    [
        [f"integrity: {SHA512}"],
        [f"integrity: {SHA512}", "checksum: x"],
        [f"integrity: {SHA512}", f"checksum: 9/{HEX}"],
    ],
    ids=["integrity-only", "integrity-and-invalid-checksum", "integrity-and-unchecked-checksum"],
)
def test_a_berry_integrity_field_is_not_integrity(tmp_path, fields):
    # Yarn Berry does not read `integrity`, so it is neither evidence nor an exported hash.
    from nexus_symbiote.generators._common import standard_hashes

    result, comp = scan(tmp_path, BERRY_HEAD + berry_record(*fields))
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert [r.category for r in comp.risks] == ["missing_lockfile_integrity"]
    assert "lockfile_integrity" not in comp.properties
    assert standard_hashes(comp) == []


def test_a_berry_integrity_field_beside_a_checked_checksum_is_not_exported(tmp_path):
    result, comp = scan(
        tmp_path, BERRY_HEAD + berry_record(f"integrity: {SHA512}", f"checksum: {CHECKSUM}")
    )
    assert result.scan_failures == [] and comp.risks == []
    assert "lockfile_integrity" not in comp.properties


@pytest.mark.parametrize(
    ("manifest", "checked"),
    [
        ({"packageManager": "yarn@4.9.2"}, True),
        ({"packageManager": "yarn@4.9.2+sha512." + "ab" * 64}, True),
        ({"devEngines": {"packageManager": {"name": "yarn", "version": "^4.0.0"}}}, True),
        ({"devEngines": {"packageManager": {"name": "yarn"}}}, True),
        ({"devEngines": {"runtime": {"name": "node"}}}, True),
        # Corepack runs another release, which computes another cache key.
        ({"packageManager": "yarn@3.8.7"}, False),
        ({"packageManager": "yarn@1.22.22"}, False),
        ({"packageManager": "yarn@40.0.0"}, False),
        ({"packageManager": "pnpm@9.0.0"}, False),
        ({"packageManager": ["yarn@4.9.2"]}, False),
        ({"devEngines": {"packageManager": {"name": "yarn", "version": "^3.0.0"}}}, False),
        ({"devEngines": {"packageManager": {"name": "yarn", "version": ">=4"}}}, False),
        ({"devEngines": {"packageManager": [{"name": "yarn", "version": "^4.0.0"}]}}, False),
        ({"devEngines": {"packageManager": {"name": "npm"}}}, False),
        ({"devEngines": None}, False),
    ],
)
def test_a_package_manager_other_than_yarn_4_leaves_no_integrity(tmp_path, manifest, checked):
    (tmp_path / "package.json").write_text(json.dumps({**manifest, "dependencies": PINNED}))
    (tmp_path / "yarn.lock").write_text(BERRY_HEAD + BERRY_OPENAI)
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (comp,) = result.components
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert ("missing_lockfile_integrity" in {r.category for r in comp.risks}) is not checked


def berry_stanza(key, resolution, *fields, version="4.0.0"):
    return (
        f'\n"{key}":\n  version: {version}\n  resolution: "{resolution}"\n'
        + "".join(f"  {field}\n" for field in fields)
        + "  languageName: node\n  linkType: hard\n"
    )


@pytest.mark.parametrize(
    "lock",
    [
        # Yarn writes one record of a locator and keeps the last one it reads, checksum
        # and conditions included: a second one with a checksum under another cache key
        # let a mismatching archive in unchecked, under another range or another key.
        BERRY_OPENAI + berry_stanza("openai@npm:^4.0.0", "openai@npm:4.0.0", f"checksum: 9/{HEX}"),
        BERRY_OPENAI + berry_stanza("zzz@npm:1.0.0", "openai@npm:4.0.0", f"checksum: 9/{HEX}"),
        berry_stanza("openai@npm:^4.0.0", "openai@npm:4.0.0", f"checksum: 9/{HEX}")
        + "\n"
        + BERRY_OPENAI,
        BERRY_OPENAI + berry_stanza("openai@npm:^4.0.0", "openai@npm:4.0.0"),
        BERRY_OPENAI
        + berry_stanza("openai@npm:^4.0.0", "openai@npm:4.0.0", f"checksum: {CHECKSUM}"),
        BERRY_OPENAI
        + berry_stanza(
            "openai@npm:^4.0.0", "openai@npm:4.0.0", f"checksum: {CHECKSUM}", "conditions: os=linux"
        ),
        # Yarn hashes `@op/enai` as it hashes `openai`: a resolution `@op/enai@npm:4.0.0`
        # replaces the locator's package, and a key `@op/enai@npm:4.0.0` the declared
        # descriptor's resolution, so Yarn fetched another package for `openai`. Any
        # record of a name hashed alike binds none.
        BERRY_OPENAI + berry_stanza("@op/enai@npm:4.0.0", "@op/enai@npm:4.0.0"),
        BERRY_OPENAI + berry_stanza("zzz@npm:1.0.0", "@op/enai@npm:4.0.0", f"checksum: {CHECKSUM}"),
        BERRY_OPENAI + berry_stanza("@op/enai@npm:4.0.0", "zzz@npm:1.0.0", version="1.0.0"),
        BERRY_OPENAI + berry_stanza("zzz@npm:1.0.0, @op/enai@npm:^9.0.0", "zzz@npm:1.0.0"),
        berry_stanza("@op/enai@npm:4.0.0", "openai@npm:4.0.0", f"checksum: {CHECKSUM}"),
    ],
    ids=[
        "other-range",
        "other-package",
        "other-first",
        "no-checksum",
        "same-checksum",
        "conditions",
        "alike-locator",
        "alike-resolution",
        "alike-descriptor",
        "alike-other-range",
        "alike-only",
    ],
)
def test_a_second_berry_record_of_the_bound_package_binds_neither(tmp_path, lock):
    result, comp = scan(tmp_path, BERRY_HEAD + lock)
    assert result.scan_failures == []
    assert result.surfaces_excluded == AMBIGUOUS
    assert_unbound(comp)
    assert comp.risks == []


def test_an_alias_whose_key_yarn_hashes_alike_is_unresolved(tmp_path):
    (tmp_path / "package.json").write_text('{"dependencies":{"openai":"npm:@openai/x@4.0.0"}}')
    lock = BERRY_HEAD + berry_stanza("@op/enai@npm:@openai/x@4.0.0", "zzz@npm:1.0.0")
    (tmp_path / "yarn.lock").write_text(lock)
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert result.surfaces_excluded == ["yarn.lock: aliased package identity is unresolved"]
    (comp,) = result.components
    assert comp.package_url is None


@pytest.mark.parametrize(
    "lock",
    [
        BERRY_HEAD
        + BERRY_OPENAI
        + berry_stanza("@openai/agents@npm:1.0.0", "@openai/agents@npm:1.0.0", version="1.0.0")
        + berry_stanza("openai@npm:^3.0.0", "openai@npm:3.0.0", version="3.0.0"),
        # Yarn 1 keys stanzas by their text, not by a hash.
        "# yarn lockfile v1\n\n"
        + stanza("openai@4.0.0", PUBLIC)
        + "\n"
        + stanza('"@op/enai@4.0.0"', "https://registry.yarnpkg.com/@op/enai/-/enai-4.0.0.tgz"),
    ],
    ids=["berry", "yarn-1"],
)
def test_records_of_other_packages_and_locators_do_not_block_the_declared_one(tmp_path, lock):
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"


V1_HEAD = "# yarn lockfile v1\n\n\n"
V1_OPENAI = f'openai@4.0.0:\n  version "4.0.0"\n  resolved "{PUBLIC}#abc"\n  integrity {SHA512}\n'


@pytest.mark.parametrize(
    "extra",
    [
        # Yarn 1 writes these nested maps: permissions holds booleans.
        '  prebuiltVariants:\n    openai-linux-x64 "0123456789abcdef"\n',
        "  permissions:\n    scripts true\n",
        # A dependency's name is any package's name, `resolution` included.
        '  dependencies:\n    resolution "^1.0.5"\n    linkType "^1.0.0"\n',
        '  dependencies:\n    "abort-controller": "^3.0.0"\n',
    ],
    ids=["prebuilt-variants", "permissions", "dependency-named-resolution", "colon-dependency"],
)
def test_nested_maps_yarn_1_writes_are_read(tmp_path, extra):
    result, comp = scan(tmp_path, V1_HEAD + V1_OPENAI + extra)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert comp.properties["lockfile_integrity"] == SHA512


def test_a_yarn_1_colon_field_is_read_without_a_version_comment(tmp_path):
    # Yarn 1 reads `key: value` as `key value`, with or without the comment.
    lock = f'openai@4.0.0:\n  version "4.0.0"\n  "resolved": "{EVIL}"\n  integrity {SHA512}\n'
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert comp.registry_uri == "https://evil.example"
    assert "registry_origin" in {r.category for r in comp.risks}


@pytest.mark.parametrize(
    "lock",
    [
        V1_HEAD + 'openai@4.0.0 :\n  version "4.0.0"\n',
        V1_HEAD + V1_OPENAI + "  uid a{b\n",
        V1_HEAD + V1_OPENAI + '  resolution "openai@npm:4.0.0"\n',
        V1_HEAD + V1_OPENAI + "  linkType hard\n",
        V1_HEAD + V1_OPENAI + "  languageName node\n",
        V1_HEAD + V1_OPENAI + "  dependencies:",
        V1_HEAD + '"openai@npm:^4.0.0, openai@npm:4.0.0":\n  version "4.0.0"\n',
        BERRY_HEAD + "# yarn lockfile v1\n" + BERRY_OPENAI,
        BERRY_HEAD + BERRY_OPENAI.replace('"openai@npm:4.0.0":', '"openai@npm:4.0.0 ":'),
        BERRY_HEAD + BERRY_OPENAI.replace('"openai@npm:4.0.0":', '" openai@npm:4.0.0":'),
        BERRY_HEAD
        + BERRY_OPENAI.replace('"openai@npm:4.0.0":', '"openai@npm:4.0.0\\t, x@npm:1.0.0":'),
        BERRY_HEAD
        + BERRY_OPENAI.replace('"openai@npm:4.0.0":', '"x@npm:1.0.0,\\u00a0openai@npm:4.0.0":'),
        "__metadata:\n  version: 8\n  cacheKey:\n    a: b\n\n" + BERRY_OPENAI,
        BERRY_HEAD + BERRY_OPENAI + "  conditions:\n    os: linux\n",
    ],
    ids=[
        "v1-spaced-header-colon",
        "v1-brace-in-word",
        "v1-resolution-field",
        "v1-link-type-field",
        "v1-language-name-field",
        "v1-empty-map-at-eof-without-newline",
        "v1-berry-protocol-comma-list",
        "v1-comment-after-metadata",
        "berry-trailing-space",
        "berry-leading-space",
        "berry-tab-before-comma",
        "berry-no-break-space-after-comma",
        "berry-cache-key-map",
        "berry-conditions-map",
    ],
)
def test_constructs_yarn_does_not_write_fail_the_lockfile(tmp_path, lock):
    result, comp = scan(tmp_path, lock)
    assert result.scan_failures == UNREAD
    assert_unbound(comp)


DECOY_V1 = (
    "# yarn lockfile v1\n\n"
    + stanza("openai@4.20.0", "https://registry.yarnpkg.com/openai/-/openai-4.20.0.tgz").replace(
        '"4.0.0"', '"4.20.0"'
    )
    + "\n"
    + stanza("openai@^4.0.0", EVIL, integrity=False).replace('"4.0.0"', '"4.19.0"')
)


@pytest.mark.parametrize(
    "sections",
    [
        {"dependencies": {"openai": "^4.0.0"}, "devDependencies": {"openai": "4.20.0"}},
        {"optionalDependencies": {"openai": "^4.0.0"}, "devDependencies": {"openai": "4.20.0"}},
        {"dependencies": {"openai": "^4.0.0"}, "optionalDependencies": {"openai": "*"}},
    ],
    ids=["dev-decoy", "optional-first", "trivial-optional-skipped"],
)
def test_yarn_1_binds_the_spec_yarn_takes_not_npm_s(tmp_path, sections):
    # Yarn 1 keeps the first spec that is neither "" nor "*", in the order optional,
    # dependencies, dev; npm's last-section spec named the decoy stanza.
    (tmp_path / "package.json").write_text(json.dumps(sections))
    (tmp_path / "yarn.lock").write_text(DECOY_V1, newline="")
    result = RegistryScanner().scan(tmp_path)
    (comp,) = result.components
    assert result.scan_failures == []
    assert comp.version == "4.19.0"
    assert comp.properties["lockfile_record"] == "yarn.lock#/openai@^4.0.0"
    assert comp.registry_uri == "https://evil.example"
    assert {"missing_lockfile_integrity", "registry_origin"} <= {r.category for r in comp.risks}


def test_berry_with_specs_that_differ_by_section_binds_neither(tmp_path):
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"openai": "^4.0.0"}, "devDependencies": {"openai": "4.0.0"}})
    )
    (tmp_path / "yarn.lock").write_text(BERRY_HEAD + BERRY_OPENAI, newline="")
    result = RegistryScanner().scan(tmp_path)
    (comp,) = result.components
    assert result.surfaces_excluded == AMBIGUOUS
    assert_unbound(comp)


def test_yarn_plugins_refuse_the_checksum_claim_as_yarn_path_does(tmp_path):
    (tmp_path / ".yarnrc.yml").write_text("plugins:\n  - path: .yarn/plugins/x.cjs\n")
    result, comp = scan(tmp_path, BERRY_HEAD + BERRY_OPENAI)
    assert "missing_lockfile_integrity" in {r.category for r in comp.risks}
