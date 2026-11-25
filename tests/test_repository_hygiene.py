"""Offline hygiene checks retain provenance and reject merge and documentation regressions."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "repository_hygiene", Path(__file__).parents[1] / "scripts/check_repository_hygiene.py"
)
assert SPEC and SPEC.loader
hygiene = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hygiene)


def test_committed_merge_conflicts_are_reported(tmp_path):
    path = tmp_path / "source.py"
    path.write_text("<<<<<<< HEAD\na = 1\n=======\na = 2\n>>>>>>> feature\n")
    assert "merge conflict" in hygiene.source_issues(tmp_path, [Path("source.py")])[0]


def test_local_links_resolve_from_document_and_ignore_examples_and_web(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "README.md").write_text("# Anchor\n")
    doc = tmp_path / "docs" / "guide.md"
    doc.write_text(
        "[root](../README.md#anchor)\n[web](https://example.invalid/unfetched)\n"
        "```md\n[example](nonexistent.md)\n```\n"
    )
    assert hygiene.source_issues(tmp_path, [Path("docs/guide.md")]) == []
    doc.write_text("[broken](missing.md)\n[escape](../../outside.md)\n")
    assert len(hygiene.source_issues(tmp_path, [Path("docs/guide.md")])) == 2


def test_image_wrapped_and_reference_links_are_checked_too(tmp_path):
    (tmp_path / "docs").mkdir()
    doc = tmp_path / "docs" / "guide.md"
    doc.write_text("[![badge](../README.md)](missing.md)\n[ref]: also-missing.md\n")
    (tmp_path / "README.md").write_text("# Anchor\n")
    issues = hygiene.source_issues(tmp_path, [Path("docs/guide.md")])
    assert len(issues) == 2 and all("missing" in issue for issue in issues)


def test_heading_anchors_follow_github_slugs():
    text = (
        "# Install from `source`\n## Why: offline, by default\n## FAQ\n## FAQ\n"
        "### [Linked](https://example.invalid) **bold** heading ###\n"
        '<a id="explicit"></a>\n```md\n# Not a heading\n```\n'
    )
    assert hygiene.heading_anchors(text) == {
        "install-from-source",
        "why-offline-by-default",
        "faq",
        "faq-1",
        "linked-bold-heading",
        "explicit",
    }


def test_link_fragments_must_name_an_existing_heading(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n## Install from source\n")
    page = tmp_path / "README.md"
    page.write_text(
        "## Usage\n[same](#usage) [other](docs/guide.md#install-from-source)\n"
        '<a href="#usage">html</a> [line](docs/guide.md#L2) [code](scripts/x.py#main)\n'
    )
    (tmp_path / "scripts").mkdir()
    (tmp_path / "scripts" / "x.py").write_text("")
    assert hygiene.source_issues(tmp_path, [Path("README.md")]) == []
    page.write_text(
        '[a](#missing) [b](docs/guide.md#install) <a href="#gone">c</a>\n```md\n[d](#x)\n```\n'
    )
    issues = hygiene.source_issues(tmp_path, [Path("README.md")])
    assert len(issues) == 3 and all("missing heading" in issue for issue in issues)


def test_absolute_links_into_this_repository_must_resolve(tmp_path):
    _project(tmp_path)
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "guide.md").write_text("# Guide\n## Install\n")
    (tmp_path / "docs" / "banner.jpg").write_bytes(b"\xff\xd8")
    base = "https://github.com/canonical-org/widget"
    readme = tmp_path / "README.md"
    readme.write_text(
        f"[guide]({base}/blob/main/docs/guide.md#install) [dir]({base}/tree/main/docs)\n"
        '<img src="https://raw.githubusercontent.com/Canonical-Org/Widget/main/docs/banner.jpg">\n'
        f"[issue]({base}/issues/1) [other](https://github.com/other/widget/blob/main/x.md)\n"
    )
    files = [Path("README.md")]
    assert hygiene.self_link_issues(tmp_path, files) == []
    readme.write_text(
        f"[gone]({base}/blob/main/docs/missing.md) [anchor]({base}/blob/main/docs/guide.md#nope)\n"
        "![raw](https://raw.githubusercontent.com/Canonical-Org/Widget/main/missing.png)\n"
        f"[escape]({base}/blob/main/../outside.md)\n"
    )
    issues = hygiene.self_link_issues(tmp_path, files)
    assert len(issues) == 4
    assert sum("missing heading" in issue for issue in issues) == 1


@pytest.mark.parametrize(
    "readme", ['"README.md"', '{file = "README.md", content-type = "text/markdown"}']
)
def test_package_index_readme_links_must_be_absolute(tmp_path, readme):
    tmp_path.joinpath("pyproject.toml").write_text(f"[project]\nreadme = {readme}\n")
    page = tmp_path / "README.md"
    page.write_text(
        "[docs](https://example.invalid/docs.md) [top](#usage) [mail](mailto:a@example.invalid)\n"
        '<img src="https://example.invalid/banner.jpg">\n```md\n[local](docs/guide.md)\n```\n'
    )
    assert hygiene.readme_link_issues(tmp_path) == []
    page.write_text('[docs](docs/guide.md) <img src="banner.jpg"> ![logo](img/logo.png)\n')
    issues = hygiene.readme_link_issues(tmp_path)
    assert len(issues) == 3 and all("package index" in issue for issue in issues)
    page.write_text("[![logo](https://example.invalid/l.png)](docs/guide.md)\n[ref]: docs/a.md\n")
    issues = hygiene.readme_link_issues(tmp_path)
    assert len(issues) == 2 and all("package index" in issue for issue in issues)


def test_undeclared_package_index_readme_fails_closed(tmp_path):
    tmp_path.joinpath("pyproject.toml").write_text('[project]\nname = "widget"\n')
    assert hygiene.readme_link_issues(tmp_path) == [
        "package-index README could not be determined or read"
    ]


def test_source_symlink_is_not_read(tmp_path):
    outside = tmp_path.parent / (tmp_path.name + "-outside")
    outside.write_text("source")
    (tmp_path / "source.py").symlink_to(outside)
    assert "unsafe" in hygiene.source_issues(tmp_path, [Path("source.py")])[0]


def test_declared_versions_match_without_importing_project_code(tmp_path):
    package = tmp_path / "src/nexus_symbiote"
    package.mkdir(parents=True)
    marker = tmp_path / "executed"
    (package / "__init__.py").write_text(
        f'__version__ = "0.1.0"\nraise RuntimeError({str(marker)!r})\n'
    )
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n')
    (tmp_path / "CITATION.cff").write_text('version: 0.1.0\ndate-released: "2026-11-08"\n')
    assert hygiene.version_issues(tmp_path) == [] and not marker.exists()
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.2.0"\n')
    assert hygiene.version_issues(tmp_path)


@pytest.mark.parametrize(
    "citation",
    [
        'version: 0.0.9\ndate-released: "2026-11-08"\n',
        "version: 0.1.0\n",
        'version: 0.1.0\ndate-released: "soon"\n',
        "- not a mapping\n",
        None,
    ],
)
def test_the_citation_must_name_the_released_version_and_its_date(tmp_path, citation):
    package = tmp_path / "src/nexus_symbiote"
    package.mkdir(parents=True)
    (package / "__init__.py").write_text('__version__ = "0.1.0"\n')
    (tmp_path / "pyproject.toml").write_text('[project]\nversion = "0.1.0"\n')
    if citation is not None:
        (tmp_path / "CITATION.cff").write_text(citation)
    assert any("CITATION.cff" in issue for issue in hygiene.version_issues(tmp_path))
    (tmp_path / "CITATION.cff").write_text("version: 0.1.0\ndate-released: 2026-11-08\n")
    assert hygiene.version_issues(tmp_path) == []


@pytest.mark.parametrize("mutation", ["modified", "unlisted", "duplicate", "traversal"])
def test_vendored_schema_provenance_cannot_silently_drift(tmp_path, mutation):
    vendor = tmp_path / hygiene.VENDOR
    vendor.mkdir(parents=True)
    schema = b'{"type":"object"}'
    (vendor / "example.json").write_bytes(schema)
    record = {"file": "example.json", "sha256": hashlib.sha256(schema).hexdigest()}
    manifest = {"files": [record]}
    source = vendor / "SOURCES.json"
    source.write_text(json.dumps(manifest))
    assert hygiene.vendor_issues(tmp_path) == []
    if mutation == "modified":
        (vendor / "example.json").write_text('{"type":"string"}')
    elif mutation == "unlisted":
        (vendor / "extra.json").write_text("{}")
    elif mutation == "duplicate":
        manifest["files"].append(record)
    else:
        record["file"] = "../outside.json"
    source.write_text(json.dumps(manifest))
    assert hygiene.vendor_issues(tmp_path)


@pytest.mark.parametrize(
    "dockerfile,accepted",
    [
        ('LABEL org.opencontainers.image.licenses="MIT AND Apache-2.0"\n', True),
        ('LABEL a="b" \\\n      org.opencontainers.image.licenses="MIT AND Apache-2.0"\n', True),
        ('LABEL org.opencontainers.image.licenses="MIT"\n', False),
        ("LABEL org.opencontainers.image.licenses=MIT\n", False),
        ("FROM scratch\n", False),
        ('LABEL org.opencontainers.image.licenses="MIT AND Apache-2.0"\n' * 2, False),
        (None, False),
    ],
)
def test_the_image_license_label_is_the_distribution_license_expression(
    tmp_path, dockerfile, accepted
):
    (tmp_path / "pyproject.toml").write_text('[project]\nlicense = "MIT AND Apache-2.0"\n')
    if dockerfile is not None:
        (tmp_path / "Dockerfile").write_text(dockerfile)
    issues = hygiene.image_license_issues(tmp_path)
    assert (issues == []) == accepted
    assert len(issues) <= 1
    (tmp_path / "pyproject.toml").write_text("[project]\n")
    assert len(hygiene.image_license_issues(tmp_path)) == 1


def test_the_tracked_image_license_label_matches_the_tracked_project():
    assert hygiene.image_license_issues(Path(__file__).parents[1]) == []


def _project(root: Path, homepage: str = "https://github.com/Canonical-Org/Widget") -> None:
    root.joinpath("pyproject.toml").write_text(
        f'[project]\nname = "widget"\nversion = "1.0.0"\n[project.urls]\nHomepage = "{homepage}"\n'
    )


def test_stale_owner_links_to_this_repository_are_reported(tmp_path):
    _project(tmp_path)
    tmp_path.joinpath("SUPPORT.md").write_text(
        "[issues](https://github.com/old-owner/Widget/issues)\n"
    )
    issues = hygiene.owner_issues(tmp_path, [Path("SUPPORT.md")])
    assert issues == ["SUPPORT.md: links to old-owner/Widget instead of Canonical-Org/Widget"]


def test_canonical_owner_and_unrelated_repositories_are_accepted(tmp_path):
    _project(tmp_path)
    tmp_path.joinpath("README.md").write_text(
        "[canonical](https://github.com/Canonical-Org/Widget/blob/main/X.md)\n"
        "[case](https://github.com/canonical-org/widget)\n"
        "[sibling](https://github.com/old-owner/OtherProject)\n"
        "[profile](https://github.com/old-owner)\n"
        "[pypi](https://pypi.org/p/Widget)\n"
    )
    assert hygiene.owner_issues(tmp_path, [Path("README.md")]) == []


def test_stale_owner_slug_outside_a_url_is_reported(tmp_path):
    _project(tmp_path)
    tmp_path.joinpath("docs.md").write_text("    gh attestation verify x --repo old-owner/widget\n")
    assert len(hygiene.owner_issues(tmp_path, [Path("docs.md")])) == 1


@pytest.mark.parametrize(
    "text",
    [
        "git clone https://github.com/old-owner/Widget.git\n",
        "See https://github.com/old-owner/Widget.\n",
        "    gh api repos/old-owner/Widget/branches/main/protection\n",
        "![banner](https://raw.githubusercontent.com/old-owner/Widget/main/a.png)\n",
        "[score](https://scorecard.dev/viewer/?uri=github.com/old-owner/Widget)\n",
        "![license](https://img.shields.io/github/license/old-owner/Widget)\n",
        "    --repo old-owner/Widget.git\n",
    ],
)
def test_a_stale_owner_in_any_spelling_of_the_slug_is_reported(tmp_path, text):
    _project(tmp_path)
    tmp_path.joinpath("docs.md").write_text(text)
    assert hygiene.owner_issues(tmp_path, [Path("docs.md")]) == [
        "docs.md: links to old-owner/Widget instead of Canonical-Org/Widget"
    ]


@pytest.mark.parametrize(
    "text",
    [
        "[x](https://github.com/old-owner/Widget.gitx)\n",
        "    python old-owner/Widget.py\n",
        "git clone https://github.com/Canonical-Org/Widget.git\n",
        "    gh api repos/Canonical-Org/Widget/rulesets\n",
    ],
)
def test_other_names_and_the_canonical_slug_are_not_stale(tmp_path, text):
    _project(tmp_path)
    tmp_path.joinpath("docs.md").write_text(text)
    assert hygiene.owner_issues(tmp_path, [Path("docs.md")]) == []


def test_project_urls_other_than_the_homepage_are_checked(tmp_path):
    _project(tmp_path)
    with tmp_path.joinpath("pyproject.toml").open("a") as stream:
        stream.write('Issues = "https://github.com/old-owner/Widget/issues"\n')
    assert hygiene.owner_issues(tmp_path, [Path("pyproject.toml")]) == [
        "pyproject.toml: links to old-owner/Widget instead of Canonical-Org/Widget"
    ]


def test_dated_audits_keep_the_owner_recorded_at_the_time(tmp_path):
    _project(tmp_path)
    audit = tmp_path / "docs" / "audits"
    audit.mkdir(parents=True)
    audit.joinpath("a.md").write_text("[run](https://github.com/old-owner/Widget/actions/runs/1)\n")
    assert hygiene.owner_issues(tmp_path, [Path("docs/audits/a.md")]) == []


def test_a_stable_type_identifier_keeps_the_owner_it_was_minted_under(tmp_path):
    _project(tmp_path)
    identifier = "https://github.com/old-owner/Widget/attestation/inventory/v1"
    source = tmp_path / "src" / "nexus_symbiote"
    source.mkdir(parents=True)
    source.joinpath("attestation.py").write_text(f'PREDICATE_TYPE = "{identifier}"\n')
    tmp_path.joinpath("guide.md").write_text(f"| `predicateType` | `{identifier}` |\n")
    assert hygiene.owner_issues(tmp_path, [Path("guide.md")]) == []
    tmp_path.joinpath("guide.md").write_text(
        f"`{identifier}`, [issues](https://github.com/old-owner/Widget/issues)\n"
    )
    assert hygiene.owner_issues(tmp_path, [Path("guide.md")]) == [
        "guide.md: links to old-owner/Widget instead of Canonical-Org/Widget"
    ]


def test_without_the_identifier_source_a_quoted_identifier_is_stale(tmp_path):
    _project(tmp_path)
    tmp_path.joinpath("guide.md").write_text(
        "`https://github.com/old-owner/Widget/attestation/inventory/v1`\n"
    )
    assert len(hygiene.owner_issues(tmp_path, [Path("guide.md")])) == 1


def _verify_block(wheel: str) -> str:
    return (
        "```bash\n"
        f"gh attestation verify dist/{wheel} --repo Hunzee-VC/Nexus-Symbiote \\\n"
        "  --signer-workflow Hunzee-VC/Nexus-Symbiote/.github/workflows/release.yml\n"
        "```\n"
    )


STALE = "links to Hunzee-VC/Nexus-Symbiote instead of aisecnomad/Nexus-Symbiote"


def test_the_signed_release_identity_is_accepted_only_in_the_readme(tmp_path):
    _project(tmp_path, homepage="https://github.com/aisecnomad/Nexus-Symbiote")
    block = _verify_block("nexus_symbiote-0.1.0-py3-none-any.whl")
    for name in ("README.md", "guide.md"):
        tmp_path.joinpath(name).write_text(block)
    assert hygiene.owner_issues(tmp_path, [Path("README.md")]) == []
    assert hygiene.owner_issues(tmp_path, [Path("guide.md")]) == [f"guide.md: {STALE}"]
    tmp_path.joinpath("README.md").write_text(
        block + "git clone https://github.com/Hunzee-VC/Nexus-Symbiote.git\n"
    )
    assert len(hygiene.owner_issues(tmp_path, [Path("README.md")])) == 1
    tmp_path.joinpath("README.md").write_text(
        "~~~\n" + _verify_block("nexus_symbiote-0.1.0-py3-none-any.whl") + "~~~\n"
    )
    assert hygiene.owner_issues(tmp_path, [Path("README.md")]) == []


@pytest.mark.parametrize(
    "text",
    [
        _verify_block("nexus_symbiote-0.2.0-py3-none-any.whl"),
        _verify_block("nexus_symbiote-0.1.0-py3-none-any.whl.sig"),
        _verify_block("nexus_symbiote-0.1.0-py3-none-any.whl").strip("`bash\n") + "\n",
        "```bash\necho nexus_symbiote-0.1.0-py3-none-any.whl\n```\n"
        "```bash\ngh attestation verify w.whl --repo Hunzee-VC/Nexus-Symbiote\n```\n",
        _verify_block("nexus_symbiote-0.1.0-py3-none-any.whl").rsplit("```", 1)[0],
        _verify_block("nexus_symbiote-0.1.0-py3-none-any.whl")
        .replace("```\n", "", 1)
        .rsplit("```", 1)[0]
        + _verify_block("nexus_symbiote-0.2.0-py3-none-any.whl").replace("```bash\n", ""),
        "```bash\n# verifies nexus_symbiote-0.1.0-py3-none-any.whl\n"
        + _verify_block("nexus_symbiote-0.2.0-py3-none-any.whl").replace("```bash\n", ""),
        "~~~\n"
        + _verify_block("nexus_symbiote-0.1.0-py3-none-any.whl")
        + "gh attestation verify w.whl --repo Hunzee-VC/Nexus-Symbiote\n~~~\n",
    ],
    ids=[
        "later-release",
        "other-artifact",
        "outside-a-fence",
        "other-block",
        "unterminated",
        "second-command-in-the-block",
        "comment-names-the-wheel",
        "nested-fence",
    ],
)
def test_the_signed_release_identity_is_stale_outside_the_release_verify_block(tmp_path, text):
    _project(tmp_path, homepage="https://github.com/aisecnomad/Nexus-Symbiote")
    tmp_path.joinpath("README.md").write_text(text)
    assert hygiene.owner_issues(tmp_path, [Path("README.md")]) == [f"README.md: {STALE}"]


def test_unparseable_homepage_fails_closed(tmp_path):
    _project(tmp_path, homepage="https://example.invalid/widget")
    assert hygiene.owner_issues(tmp_path, [Path("README.md")]) == [
        "canonical repository owner could not be determined"
    ]


def test_invisible_characters_in_source_and_documentation_are_reported(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src/module.py").write_text('NAME = "safe\u202eedoc"\nBOM = "\ufeff"\n', "utf-8")
    (tmp_path / "guide.md").write_text("ordinary\nzero\u200bwidth\nline\u2028separator\n", "utf-8")
    issues = hygiene.hidden_character_issues(tmp_path, [Path("src/module.py"), Path("guide.md")])
    assert issues == [
        "src/module.py:1: invisible character U+202E; write it as an escape",
        "src/module.py:2: invisible character U+FEFF; write it as an escape",
        "guide.md:2: invisible character U+200B; write it as an escape",
        "guide.md:3: invisible character U+2028; write it as an escape",
    ]


def test_escaped_invisible_characters_and_detection_data_are_accepted(tmp_path):
    for directory in ("src", "tests/fixtures/py", "benchmarks/fixtures/case", "benchmarks/r"):
        (tmp_path / directory).mkdir(parents=True)
    (tmp_path / "src/module.py").write_text(
        'RLO = "\\u202e"\nTEXT = "caf\u00e9 \u00a0 \u2014"\n', "utf-8"
    )
    (tmp_path / "tests/fixtures/py/server.py").write_text('SAMPLE = "\u202e"\n', "utf-8")
    (tmp_path / "benchmarks/fixtures/case/CLAUDE.md").write_text("hidden\u200b\n", "utf-8")
    (tmp_path / "benchmarks/r/bom.json").write_text('{"n": "\u200b"}\n', "utf-8")
    files = [
        Path("src/module.py"),
        Path("tests/fixtures/py/server.py"),
        Path("benchmarks/fixtures/case/CLAUDE.md"),
        Path("benchmarks/r/bom.json"),
    ]
    assert hygiene.hidden_character_issues(tmp_path, files) == []


def test_code_ci_runs_and_files_that_do_not_decode_are_checked(tmp_path):
    # Test and benchmark Python runs in CI; build and ownership files steer it.
    for directory in ("tests", "benchmarks/inventory", ".github", "examples"):
        (tmp_path / directory).mkdir(parents=True)
    hidden = {
        "tests/conftest.py": 'X = "a\u200db"\n',
        "benchmarks/inventory/evidence.py": "# \u202e\n",
        "benchmarks/run_tools.sh": "echo \u200b\n",
        "examples/Dockerfile.agent": "FROM x\u202e\n",
        "Dockerfile": "FROM x\u2060\n",
        "Makefile": "all:\u200b\n",
        ".github/CODEOWNERS": "* @owner\u200c\n",
        ".editorconfig": "root = true\u200b\n",
        ".gitattributes": "* text=auto\u202e\n",
        ".gitignore": "*.pyc\u2060\n",
        "requirements-ci.lock": "a==1\u00ad\n",
        "config.json": '{"k": "\ufe0f"}\n',
    }
    for name, text in hidden.items():
        (tmp_path / name).write_text(text, "utf-8")
    (tmp_path / "setup.cfg").write_bytes("[x]\nk = \u202e".encode() + b"\xff\n")
    issues = hygiene.hidden_character_issues(tmp_path, [*map(Path, hidden), Path("setup.cfg")])
    assert sorted(issue.split(":", 1)[0] for issue in issues) == sorted([*hidden, "setup.cfg"])
    assert "setup.cfg: not valid UTF-8; invisible characters were not checked" in issues


def test_wall_clock_cost_bound_hygiene_rejects_unmarked_cost_bounds_and_allows_deadlines(tmp_path):
    tests_dir = tmp_path / "tests"
    tests_dir.mkdir()
    sample = tests_dir / "test_sample.py"
    sample.write_text(
        "import time\n\n"
        "def test_parser_stays_fast():\n"
        "    started = time.monotonic()\n"
        "    assert time.monotonic() - started < 5\n\n"
        "def test_query_runs_linearly():\n"
        "    t0 = time.perf_counter()\n"
        "    elapsed = time.perf_counter() - t0\n"
        "    assert elapsed < 2.0\n\n"
        "def test_reversed_bound_scales():\n"
        "    started = time.monotonic()\n"
        "    assert 5 > time.monotonic() - started\n\n"
        "def test_chained_bound_scaling():\n"
        "    started = time.monotonic()\n"
        "    elapsed = time.monotonic() - started\n"
        "    assert 0 <= elapsed < 2.0\n\n"
        "def test_timeout_is_bounded():\n"
        "    started = time.monotonic()\n"
        "    assert time.monotonic() - started < 3  # deadline check\n\n"
        "def test_stalled_peer_bounded_by_deadline():\n"
        "    started = time.monotonic()\n"
        "    assert time.monotonic() - started < 10\n\n"
        "def test_relative_ratio_stays_linear():\n"
        "    t0 = time.perf_counter()\n"
        "    small = time.perf_counter() - t0\n"
        "    t1 = time.perf_counter()\n"
        "    large = time.perf_counter() - t1\n"
        "    assert large < small * 20\n",
        encoding="utf-8",
    )
    issues = hygiene.wall_clock_cost_bound_issues(tmp_path, [Path("tests/test_sample.py")])
    assert len(issues) == 4
    assert "test_parser_stays_fast" in issues[0]
    assert "test_query_runs_linearly" in issues[1]
    assert "test_reversed_bound_scales" in issues[2]
    assert "test_chained_bound_scaling" in issues[3]


def test_tracked_repository_passes_its_own_owner_check():
    root = Path(__file__).parents[1]
    if not (root / ".git").exists():
        pytest.skip("needs a Git checkout; an unpacked sdist has no tracked-file list")
    listing = subprocess.run(  # noqa: S603 - fixed read-only Git operation
        [shutil.which("git") or "git", "-C", str(root), "ls-files", "-z"],
        capture_output=True,
        check=True,
        timeout=10,
    )
    files = [Path(value) for value in listing.stdout.decode().split("\0") if value]
    assert hygiene.owner_issues(root, files) == []
    assert hygiene.hidden_character_issues(root, files) == []
    assert hygiene.wall_clock_cost_bound_issues(root, files) == []
