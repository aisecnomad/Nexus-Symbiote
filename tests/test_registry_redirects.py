"""Project settings that send an inventoried npm or PyPI package to another registry or
index: recorded on the package by origin only, with its package URL withheld and a
registry_origin finding; a redirect file that cannot be read fails or is a gap."""

from __future__ import annotations

import json
import os
from dataclasses import replace
from pathlib import Path

import pytest
from click.testing import CliRunner
from hypothesis import given, settings
from hypothesis import strategies as st

from nexus_symbiote import limits
from nexus_symbiote.cli import main
from nexus_symbiote.core.enums import RiskSeverity
from nexus_symbiote.core.models import MCPServerComponent, RegistryEntryComponent
from nexus_symbiote.scanners.base import ScanResult
from nexus_symbiote.scanners.mcp import MCPScanner
from nexus_symbiote.scanners.registry import (
    _PIP_INDEX_KEYS,
    _PIP_INDEX_OPTIONS,
    RegistryScanner,
    _pip_config,
)
from tests.support import scaling_ratio

NPM = '{"dependencies": {"openai": "4.0.0", "@anthropic-ai/sdk": "0.30.1"}}'
PYPI = "openai==1.0.0\n"
PYPROJECT = '[project]\nname = "app"\nversion = "1"\ndependencies = ["langchain>=0.1"]\n'
NPM_GAP = ".npmrc: a setting name depends on the environment; registries not resolved"
# Every long name of pip's --index-url, --extra-index-url and --find-links options, which
# pip also reads as configuration keys; pinned to pip's own option table below.
PIP_INDEX_KEYS = frozenset({"index-url", "pypi-url", "extra-index-url", "find-links"})


def _project(root: Path, files: dict[str, str]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AGENTS.md").write_text("Keep receipts.\n")
    for name, text in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return root


def _collect(
    root: Path, files: dict[str, str]
) -> tuple[ScanResult, dict[str, RegistryEntryComponent]]:
    result = RegistryScanner().scan(_project(root, files))
    entries = {c.name: c for c in result.components if isinstance(c, RegistryEntryComponent)}
    return result, entries


def _redirects(component: RegistryEntryComponent) -> list[str]:
    return [r.detail for r in component.risks if r.category == "registry_origin"]


def _sources(component: RegistryEntryComponent) -> list[str] | None:
    sources: list[str] | None = component.properties.get("package_sources")
    return sources


def test_an_npmrc_registry_redirects_packages_without_a_scope_registry(tmp_path):
    _, plain = _collect(tmp_path / "plain", {"package.json": NPM})
    assert plain["openai"].package_url == "pkg:npm/openai@4.0.0"
    assert _sources(plain["openai"]) is None and _redirects(plain["openai"]) == []
    result, entries = _collect(
        tmp_path / "redirected",
        {"package.json": NPM, ".npmrc": "registry=https://npm.evil.example/\n"},
    )
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert ".npmrc" in result.surfaces_scanned
    for name in ("openai", "@anthropic-ai/sdk"):
        entry = entries[name]
        assert entry.package_url is None
        assert _sources(entry) == [".npmrc:registry=https://npm.evil.example"]
        [risk] = [r for r in entry.risks if r.category == "registry_origin"]
        assert risk.severity == RiskSeverity.LOW
        assert risk.detail == (
            f"npm package '{name}' may resolve from a registry that the project configures "
            "(.npmrc:registry), not the default npm registry; its name and version do not "
            "establish identity."
        )


def test_a_scope_registry_redirects_only_its_scope(tmp_path):
    _, entries = _collect(
        tmp_path,
        {
            "package.json": NPM,
            ".npmrc": "@anthropic-ai:registry=https://npm.corp.example/\n@other:registry=https://o.example/\n",
        },
    )
    assert _sources(entries["@anthropic-ai/sdk"]) == [
        ".npmrc:@anthropic-ai:registry=https://npm.corp.example"
    ]
    assert entries["@anthropic-ai/sdk"].package_url is None
    assert _sources(entries["openai"]) is None
    assert entries["openai"].package_url == "pkg:npm/openai@4.0.0"


def test_the_scope_setting_chooses_the_registry_of_unscoped_packages(tmp_path):
    _, entries = _collect(
        tmp_path,
        {
            "package.json": NPM,
            ".npmrc": "scope=corp\n@corp:registry=https://npm.corp.example/\n",
        },
    )
    assert _sources(entries["openai"]) == [".npmrc:@corp:registry=https://npm.corp.example"]
    assert _sources(entries["@anthropic-ai/sdk"]) == [
        ".npmrc:@corp:registry=https://npm.corp.example"
    ]


@pytest.mark.parametrize(
    "scope_registry, sources",
    [
        # npm takes the scope's registry, pnpm, Yarn 1 and Bun the default one.
        ("https://registry.npmjs.org/", [".npmrc:registry=https://npm.evil.example"]),
        (
            "https://npm.corp.example/",
            [
                ".npmrc:@corp:registry=https://npm.corp.example",
                ".npmrc:registry=https://npm.evil.example",
            ],
        ),
    ],
)
def test_the_default_registry_counts_beside_the_scope_setting(tmp_path, scope_registry, sources):
    npmrc = f"scope=corp\n@corp:registry={scope_registry}\nregistry=https://npm.evil.example/\n"
    _, entries = _collect(tmp_path, {"package.json": NPM, ".npmrc": npmrc})
    for name in ("openai", "@anthropic-ai/sdk"):
        assert _sources(entries[name]) == sources
        assert entries[name].package_url is None
        [detail] = _redirects(entries[name])
        assert ".npmrc:registry" in detail


def test_a_scope_without_a_registry_leaves_the_default_registry(tmp_path):
    npmrc = "scope=corp\nregistry=https://npm.evil.example/\n"
    _, entries = _collect(tmp_path, {"package.json": NPM, ".npmrc": npmrc})
    for name in ("openai", "@anthropic-ai/sdk"):
        assert _sources(entries[name]) == [".npmrc:registry=https://npm.evil.example"]


def test_a_package_scope_registry_wins_over_the_scope_setting_and_the_default(tmp_path):
    npmrc = (
        "scope=corp\n@corp:registry=https://npm.corp.example/\n"
        "registry=https://npm.evil.example/\n@anthropic-ai:registry=https://registry.npmjs.org/\n"
    )
    _, entries = _collect(tmp_path, {"package.json": NPM, ".npmrc": npmrc})
    sdk = entries["@anthropic-ai/sdk"]
    assert _sources(sdk) is None and _redirects(sdk) == []
    assert sdk.package_url == "pkg:npm/%40anthropic-ai/sdk@0.30.1"
    assert len(_sources(entries["openai"]) or []) == 2


@pytest.mark.parametrize(
    "npmrc, sources",
    [
        (
            "scope=${NPM_SCOPE}\n@corp:registry=https://npm.evil.example/\n",
            [".npmrc:scope=[unresolved]"],
        ),
        (
            "scope=${NPM_SCOPE}\n@a:b:registry=https://npm.evil.example/\n",
            [".npmrc:scope=[unresolved]"],
        ),
        (
            "scope=@${NPM_SCOPE}\n@corp:registry=https://npm.evil.example/\n"
            "registry=https://npm.other.example/\n",
            [".npmrc:registry=https://npm.other.example", ".npmrc:scope=[unresolved]"],
        ),
        # Whatever scope the environment names, its registry here is the default one.
        ("scope=${NPM_SCOPE}\n@corp:registry=https://registry.npmjs.org/\n", None),
        ("scope=${NPM_SCOPE}\nregistry=https://registry.npmjs.org/\n", None),
        ("scope=${NPM_SCOPE}\n@corp:REGISTRY=https://npm.evil.example/\n", None),
    ],
)
def test_a_scope_from_the_environment_may_select_any_scope_registry(tmp_path, npmrc, sources):
    result, entries = _collect(tmp_path, {"package.json": NPM, ".npmrc": npmrc})
    assert result.scan_failures == [] and result.surfaces_excluded == []
    for name in ("openai", "@anthropic-ai/sdk"):
        assert _sources(entries[name]) == sources
        assert (entries[name].package_url is None) is (sources is not None)
    if sources is not None:
        [detail] = _redirects(entries["openai"])
        assert ".npmrc:scope" in detail
        assert "NPM_SCOPE" not in json.dumps(entries["openai"].model_dump(mode="json"))


def test_a_scope_from_the_environment_leaves_a_package_scope_registry_alone(tmp_path):
    npmrc = (
        "scope=${NPM_SCOPE}\n@corp:registry=https://npm.evil.example/\n"
        "@anthropic-ai:registry=https://npm.anthropic.example/\n"
    )
    _, entries = _collect(tmp_path, {"package.json": NPM, ".npmrc": npmrc})
    assert _sources(entries["@anthropic-ai/sdk"]) == [
        ".npmrc:@anthropic-ai:registry=https://npm.anthropic.example"
    ]
    assert _sources(entries["openai"]) == [".npmrc:scope=[unresolved]"]


def test_an_alias_is_redirected_by_the_package_it_installs(tmp_path):
    _, entries = _collect(
        tmp_path,
        {
            "package.json": '{"dependencies": {"utils": "npm:@anthropic-ai/sdk@0.30.1"}}',
            ".npmrc": "@anthropic-ai:registry=https://npm.corp.example/\n",
        },
    )
    assert _sources(entries["@anthropic-ai/sdk"]) == [
        ".npmrc:@anthropic-ai:registry=https://npm.corp.example"
    ]


@pytest.mark.parametrize(
    "value",
    [
        "https://registry.npmjs.org/",
        "https://registry.npmjs.org",
        "HTTPS://Registry.NPMJS.org/",
        "https://registry.npmjs.org:443/",
        "https://registry.yarnpkg.com/",
        "",
    ],
)
def test_the_default_registry_is_not_a_redirect(tmp_path, value):
    result, entries = _collect(tmp_path, {"package.json": NPM, ".npmrc": f"registry={value}\n"})
    assert _sources(entries["openai"]) is None and _redirects(entries["openai"]) == []
    assert entries["openai"].package_url == "pkg:npm/openai@4.0.0"
    assert result.scan_failures == [] and result.surfaces_excluded == []


@pytest.mark.parametrize(
    "value, origin",
    [
        ("http://registry.npmjs.org/", "http://registry.npmjs.org"),
        ("https://registry.npmjs.org.evil.example/", "https://registry.npmjs.org.evil.example"),
        ("https://registry.npmjs.org@evil.example/", "https://evil.example"),
        ("https://evil.example\\@registry.npmjs.org/", "[redacted]"),
        ("https://registry.npmjs.org/other/", "https://registry.npmjs.org"),
        ("https://registry.npmjs.org:8443/", "https://registry.npmjs.org:8443"),
        ("${NPM_REGISTRY}", "[unresolved]"),
        ("npm.evil.example", "[local]"),
        ("https://" + "a" * 5_000, "[not parsed]"),
    ],
)
def test_other_registries_and_look_alikes_are_redirects(tmp_path, value, origin):
    _, entries = _collect(tmp_path, {"package.json": NPM, ".npmrc": f"registry={value}\n"})
    assert _sources(entries["openai"]) == [f".npmrc:registry={origin}"]


@pytest.mark.parametrize(
    "files",
    [
        # Unicode case folding equates these with ASCII letters; IDNA does not, or maps
        # them only sometimes, so none of them names the default registry for sure.
        {".npmrc": "registry=https://regıstry.npmjs.org/\n"},
        {".npmrc": "registry=https://regİstry.npmjs.org/\n"},
        {".npmrc": "registry=https://regiſtry.npmjs.org/\n"},
        {".npmrc": "registry=https://registry.yarnpKg.com/\n"},
        {"requirements.txt": PYPI + "-i https://pуpi.org/simple\n"},
        {"requirements.txt": PYPI + "-i https://pypı.org/simple\n"},
    ],
)
def test_unicode_look_alikes_of_a_default_host_are_redirects(tmp_path, files):
    base = {"package.json": NPM} if ".npmrc" in files else {}
    _, entries = _collect(tmp_path, {**base, **files})
    assert entries["openai"].package_url is None
    assert len(_redirects(entries["openai"])) == 1


def test_credentials_paths_and_tokens_never_leave_the_settings(tmp_path):
    project = _project(
        tmp_path / "project",
        {
            "package.json": NPM,
            ".npmrc": (
                "registry=https://alice:S3CR1@npm.evil.example/S3CR2/?token=S3CR3#S3CR4\n"
                "//npm.evil.example/:_authToken=S3CR5\n"
                "@ghp_S3CR6aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:registry=https://scope.example/\n"
            ),
            "requirements.txt": "openai==1.0.0\n--extra-index-url https://bob:S3CR7@pypi.evil.example/S3CR8\n",
            "pip.conf": "[global]\nindex-url = https://carol:S3CR9@mirror.example/simple\n",
        },
    )
    for fmt in ("json", "cyclonedx", "spdx", "sarif"):
        out = tmp_path / f"out.{fmt}"
        result = CliRunner().invoke(
            main,
            [
                "scan",
                str(project),
                "--no-project-policy",
                "--report-only",
                "-f",
                fmt,
                "-o",
                str(out),
            ],
        )
        assert result.exit_code == 0, result.output
        text = out.read_text(encoding="utf-8") + result.output
        assert "S3CR" not in text and "alice" not in text and "carol" not in text, fmt
    document = json.loads((tmp_path / "out.json").read_text())
    by_ref = {c["bom_ref"]: c["properties"] for c in document["components"]}
    assert by_ref["registry:npm/openai"]["package_sources"] == [
        ".npmrc:registry=https://npm.evil.example"
    ]
    assert by_ref["registry:npm/@anthropic-ai/sdk"]["package_sources"] == [
        ".npmrc:registry=https://npm.evil.example"
    ]
    assert by_ref["registry:pypi/openai"]["package_sources"] == [
        "pip.conf:index-url=https://mirror.example",
        "requirements.txt:--extra-index-url=https://pypi.evil.example",
    ]


def test_npm_and_pypi_entries_of_one_name_are_redirected_by_their_own_files(tmp_path):
    result, _ = _collect(
        tmp_path,
        {
            "package.json": NPM,
            ".npmrc": "registry=https://npm.evil.example/\n",
            "requirements.txt": "openai==1.0.0\n-i https://pypi.evil.example/simple\n",
        },
    )
    by_ref = {c.bom_ref: c for c in result.components if isinstance(c, RegistryEntryComponent)}
    assert _sources(by_ref["registry:npm/openai"]) == [".npmrc:registry=https://npm.evil.example"]
    assert _sources(by_ref["registry:pypi/openai"]) == [
        "requirements.txt:--index-url=https://pypi.evil.example"
    ]
    assert by_ref["registry:pypi/openai"].registry_uri is None


def test_a_setting_name_from_the_environment_is_a_gap(tmp_path):
    result, entries = _collect(
        tmp_path, {"package.json": NPM, ".npmrc": "${SCOPE}:registry=https://x.example/\n"}
    )
    assert result.surfaces_excluded == [NPM_GAP]
    assert _sources(entries["openai"]) is None
    code = (
        CliRunner()
        .invoke(
            main, ["scan", str(tmp_path), "--no-project-policy", "-o", str(tmp_path / "o.json")]
        )
        .exit_code
    )
    assert code == 1


@pytest.mark.parametrize(
    "name, text, expected",
    [
        (
            "bunfig.toml",
            '[install]\nregistry = "https://bun.example/"\n',
            {"*": ["bunfig.toml:registry=https://bun.example"]},
        ),
        (
            "bunfig.toml",
            '[install]\nregistry = { url = "https://u:T0K3N@bun.example/", token = "T0K3N" }\n',
            {"*": ["bunfig.toml:registry=https://bun.example"]},
        ),
        (
            "bunfig.toml",
            '[install.scopes]\nanthropic-ai = "https://scoped.example/"\n',
            {"@anthropic-ai/sdk": ["bunfig.toml:@anthropic-ai:registry=https://scoped.example"]},
        ),
        (
            ".yarnrc.yml",
            'npmRegistryServer: "https://yarn.example"\n',
            {"*": [".yarnrc.yml:npmRegistryServer=https://yarn.example"]},
        ),
        (
            ".yarnrc.yml",
            'npmScopes:\n  anthropic-ai:\n    npmRegistryServer: "https://scoped.example"\n',
            {
                "@anthropic-ai/sdk": [
                    ".yarnrc.yml:@anthropic-ai:npmRegistryServer=https://scoped.example"
                ]
            },
        ),
        (
            ".yarnrc",
            'registry "https://yarn1.example/"\n',
            {"*": [".yarnrc:registry=https://yarn1.example"]},
        ),
    ],
)
def test_bun_and_yarn_registry_settings(tmp_path, name, text, expected):
    result, entries = _collect(tmp_path, {"package.json": NPM, name: text})
    assert result.scan_failures == [] and name in result.surfaces_scanned
    # A default registry serves every package that no scope registry claims.
    for package in ("openai", "@anthropic-ai/sdk"):
        assert _sources(entries[package]) == expected.get(package, expected.get("*"))
    assert "T0K3N" not in json.dumps([c.model_dump(mode="json") for c in result.components])


@pytest.mark.parametrize(
    "name, make, failure",
    [
        (".npmrc", lambda p: p.symlink_to("/etc/hostname"), ".npmrc: symlink target is absolute"),
        (".npmrc", os.mkfifo, ".npmrc: read refused"),
        (".npmrc", lambda p: p.write_bytes(b"registry=\xff\n"), ".npmrc: invalid UTF-8"),
        ("bunfig.toml", lambda p: p.write_text("[install\n"), "bunfig.toml: invalid TOML"),
        (
            ".yarnrc.yml",
            lambda p: p.write_text("a: [unclosed\n"),
            ".yarnrc.yml: YAML mapping parse failed or unsupported",
        ),
        ("pip.conf", lambda p: p.symlink_to("../outside.conf"), "pip.conf: symlink target"),
    ],
)
def test_a_redirect_file_that_cannot_be_read_fails_the_collector(tmp_path, name, make, failure):
    project = _project(tmp_path / "project", {"package.json": NPM, "requirements.txt": PYPI})
    make(project / name)
    result = RegistryScanner().scan(project)
    assert any(item.startswith(failure) for item in result.scan_failures), result.scan_failures


def test_an_oversized_redirect_file_names_the_limit(tmp_path):
    project = _project(tmp_path, {"package.json": NPM, ".npmrc": "registry=https://x/\n" * 100})
    with limits.applied(replace(limits.DEFAULTS, file_bytes=1_000)):
        result = RegistryScanner().scan(project)
    assert result.scan_failures == [
        ".npmrc: file-bytes limit of 1000 bytes exceeded; raise it with --limit file-bytes=N"
    ]


def test_redirect_files_are_read_only_for_inventoried_packages(tmp_path):
    project = _project(
        tmp_path,
        {"package.json": '{"dependencies": {"left-pad": "1.0.0"}}', "requirements.txt": "six\n"},
    )
    os.mkfifo(project / ".npmrc")
    os.mkfifo(project / "pip.conf")
    (project / "bunfig.toml").write_text("[install\n")
    result = RegistryScanner().scan(project)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert not {".npmrc", "pip.conf", "bunfig.toml"} & set(result.surfaces_scanned)


@pytest.mark.parametrize(
    "spec",
    [
        "github:openai/openai-node#" + "a" * 40,
        "https://files.example/openai-4.0.0.tgz",
        "file:../openai",
    ],
)
def test_sources_outside_a_registry_are_not_redirected(tmp_path, spec):
    _, entries = _collect(
        tmp_path,
        {
            "package.json": json.dumps({"dependencies": {"openai": spec}}),
            ".npmrc": "registry=https://npm.evil.example/\n",
        },
    )
    assert _sources(entries["openai"]) is None and _redirects(entries["openai"]) == []


def test_a_lockfile_record_keeps_its_origin_but_not_the_package_url(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"openai": "4.0.0"}},
            "node_modules/openai": {
                "version": "4.0.0",
                "resolved": "https://registry.npmjs.org/openai/-/openai-4.0.0.tgz",
                "integrity": "sha512-" + "A" * 86 + "==",
            },
        },
    }
    files = {
        "package.json": '{"dependencies": {"openai": "4.0.0"}}',
        "package-lock.json": json.dumps(lock),
    }
    _, plain = _collect(tmp_path / "plain", files)
    assert plain["openai"].package_url == "pkg:npm/openai@4.0.0"
    _, entries = _collect(
        tmp_path / "redirected", {**files, ".npmrc": "registry=https://npm.evil.example/\n"}
    )
    entry = entries["openai"]
    assert entry.package_url is None
    assert entry.registry_uri == "https://registry.npmjs.org"
    assert entry.properties["lockfile_record"] == plain["openai"].properties["lockfile_record"]
    assert _sources(entry) == [".npmrc:registry=https://npm.evil.example"]


@pytest.mark.parametrize(
    "line, source",
    [
        ("--index-url https://idx.example/simple", "--index-url=https://idx.example"),
        ("-i https://idx.example/simple", "--index-url=https://idx.example"),
        ("--index-url=https://idx.example/simple", "--index-url=https://idx.example"),
        ("--index https://idx.example/simple", "--index-url=https://idx.example"),
        ("--pypi-url https://idx.example/simple", "--pypi-url=https://idx.example"),
        ("--extra-index-url https://idx.example/simple", "--extra-index-url=https://idx.example"),
        ("--find-links https://idx.example/wheels", "--find-links=https://idx.example"),
        ("-f ./wheels", "--find-links=[local]"),
        ("--extra-index-url ${PIP_EXTRA}", "--extra-index-url=[unresolved]"),
        ("--pre -i https://idx.example/simple", "--index-url=https://idx.example"),
    ],
)
def test_requirements_index_options_redirect_every_pypi_package(tmp_path, line, source):
    result, entries = _collect(
        tmp_path,
        {
            "requirements.txt": PYPI,
            "requirements-dev.txt": f"{line}\n",
            "pyproject.toml": PYPROJECT,
        },
    )
    assert result.surfaces_excluded == [] and result.scan_failures == []
    for name in ("openai", "langchain"):
        entry = entries[name]
        assert _sources(entry) == [f"requirements-dev.txt:{source}"]
        assert entry.package_url is None and entry.registry_uri is None
        [detail] = _redirects(entry)
        label = source.split("=", 1)[0]
        assert detail == (
            f"PyPI package '{name}' may resolve from an index or location that the project "
            f"configures (requirements-dev.txt:{label}); its name and version do not "
            "establish identity."
        )


@pytest.mark.parametrize(
    "files",
    [
        {"requirements.txt": "openai==1.0.0 --index-url https://idx.example/simple\n"},
        {"requirements.txt": PYPI + "--index-url https://pypi.org/simple\n"},
        {"requirements.txt": PYPI + "-i https://PYPI.org/simple/\n"},
        {"requirements.txt": PYPI, "pip.conf": "[global]\nindex-url = https://pypi.org/simple\n"},
        {"requirements.txt": PYPI, "pip.conf": "[global]\ntimeout = 60\n"},
        {"requirements.txt": PYPI, "pip.conf": "[global]\nindex-url =\n\n# none\n"},
        {"requirements.txt": PYPI + "--trusted-host idx.example --no-index\n"},
    ],
)
def test_settings_that_keep_pypi_are_not_redirects(tmp_path, files):
    result, entries = _collect(tmp_path, files)
    assert _sources(entries["openai"]) is None and _redirects(entries["openai"]) == []
    assert entries["openai"].package_url == "pkg:pypi/openai@1.0.0"
    assert entries["openai"].registry_uri == "https://pypi.org"
    assert result.surfaces_excluded == []


@pytest.mark.parametrize(
    "name, text, sources",
    [
        (
            "pip.conf",
            "[global]\nindex-url = https://m.example/simple\n",
            ["pip.conf:index-url=https://m.example"],
        ),
        (
            "pip.conf",
            "[global]\npypi-url = https://m.example/simple\n",
            ["pip.conf:pypi-url=https://m.example"],
        ),
        (
            "pip.ini",
            "[install]\npypi_url = https://m.example/simple\n",
            ["pip.ini:pypi-url=https://m.example"],
        ),
        (
            "pip.conf",
            "[download]\n--pypi-url = https://m.example\n",
            ["pip.conf:pypi-url=https://m.example"],
        ),
        (
            "pip.ini",
            "[DEFAULT]\nPYPI-URL: https://m.example\n",
            ["pip.ini:pypi-url=https://m.example"],
        ),
        (
            "pip.ini",
            "[install]\nindex_url: https://m.example/simple\n",
            ["pip.ini:index-url=https://m.example"],
        ),
        (
            "pip.conf",
            "[global]\n--extra-index-url = https://m.example\n",
            ["pip.conf:extra-index-url=https://m.example"],
        ),
        (
            "pip.conf",
            "[install]\nextra-index-url =\n    https://a.example/simple\n\n    https://b.example/simple\n",
            [
                "pip.conf:extra-index-url=https://a.example",
                "pip.conf:extra-index-url=https://b.example",
            ],
        ),
        (
            "pip.conf",
            "[DEFAULT]\nfind-links = /srv/wheels\n[global]\n",
            ["pip.conf:find-links=[local]"],
        ),
        (
            "pip.conf",
            "# comment\n[freeze]\n; another\nINDEX-URL = https://m.example\n",
            ["pip.conf:index-url=https://m.example"],
        ),
    ],
)
def test_pip_configuration_files(tmp_path, name, text, sources):
    result, entries = _collect(tmp_path, {"requirements.txt": PYPI, name: text})
    assert result.surfaces_excluded == [] and name in result.surfaces_scanned
    assert _sources(entries["openai"]) == sources


def test_pypi_url_in_a_pip_configuration_withholds_the_pypi_identity(tmp_path):
    project = _project(
        tmp_path / "project",
        {
            "requirements.txt": PYPI,
            "pip.conf": "[global]\npypi-url = https://evil.example/simple\n",
        },
    )
    out = tmp_path / "out.json"
    result = CliRunner().invoke(main, ["scan", str(project), "--no-project-policy", "-o", str(out)])
    assert result.exit_code == 0, result.output
    [entry] = [
        c
        for c in json.loads(out.read_text())["components"]
        if c["bom_ref"] == "registry:pypi/openai"
    ]
    assert entry.get("package_url") is None and entry.get("registry_uri") is None
    assert entry["properties"]["package_sources"] == ["pip.conf:pypi-url=https://evil.example"]
    assert [r["category"] for r in entry["risks"]] == ["registry_origin"]


def test_the_configuration_keys_are_every_long_name_of_pip_index_options():
    # pip looks a configuration key up as the long option --<key>, in every command.
    try:
        from pip._internal.commands import commands_dict, create_command
    except ImportError:
        if os.environ.get("CI"):
            raise
        pytest.skip("pip is not importable here; CI, which installs with pip, runs this test")
    names: set[str] = set()
    for command in commands_dict:
        for option in create_command(command).parser._get_all_options():
            if option.dest in {"index_url", "extra_index_urls", "find_links"}:
                names.update(option._long_opts)
    assert names == _PIP_INDEX_OPTIONS
    assert {name.removeprefix("--") for name in names} == PIP_INDEX_KEYS == _PIP_INDEX_KEYS


@pytest.mark.parametrize(
    "text",
    [
        "index-url = https://m.example\n",
        "[global]\nindex-url = https://a.example\nindex-url = https://b.example\n",
        "[global]\nindex-url = https://a.example\nINDEX-URL = https://b.example\n",
        "[global]\n[global]\n",
        "[global]\nnot a setting\n",
        "[global]\n= https://m.example\n",
        "\ufeff[global]\nindex-url = https://m.example\n",
    ],
)
def test_a_pip_configuration_pip_would_refuse_is_a_gap(tmp_path, text):
    result, entries = _collect(tmp_path, {"requirements.txt": PYPI, "pip.conf": text})
    assert result.surfaces_excluded == [
        "pip.conf: not read as pip reads it; index settings not resolved"
    ]
    assert _sources(entries["openai"]) is None


@pytest.mark.parametrize(
    "name, text, sources",
    [
        (
            "pyproject.toml",
            PYPROJECT + '[[tool.uv.index]]\nname = "corp"\nurl = "https://uv.example/simple"\n',
            ["pyproject.toml:tool.uv.index=https://uv.example"],
        ),
        (
            "pyproject.toml",
            PYPROJECT
            + '[[tool.uv.index]]\nname = "cu"\nurl = "https://cu.example"\nexplicit = true\n',
            None,
        ),
        (
            "pyproject.toml",
            PYPROJECT + '[tool.uv]\nextra-index-url = ["https://x.example/simple"]\n',
            ["pyproject.toml:tool.uv.extra-index-url=https://x.example"],
        ),
        (
            "pyproject.toml",
            PYPROJECT + '[tool.uv.pip]\nindex-url = "https://p.example/simple"\n',
            ["pyproject.toml:tool.uv.pip.index-url=https://p.example"],
        ),
        (
            "pyproject.toml",
            PYPROJECT
            + '[[tool.poetry.source]]\nname = "corp"\nurl = "https://po.example/simple"\n',
            ["pyproject.toml:tool.poetry.source=https://po.example"],
        ),
        (
            "pyproject.toml",
            PYPROJECT
            + '[[tool.poetry.source]]\nname = "cu"\nurl = "https://cu.example"\npriority = "explicit"\n'
            + '[[tool.poetry.source]]\nname = "PyPI"\npriority = "primary"\n',
            None,
        ),
        (
            "pyproject.toml",
            PYPROJECT + '[[tool.pdm.source]]\nname = "corp"\nurl = "https://pdm.example/simple"\n',
            ["pyproject.toml:tool.pdm.source=https://pdm.example"],
        ),
        (
            "uv.toml",
            '[[index]]\nname = "corp"\nurl = "https://uvt.example/simple"\ndefault = true\n',
            ["uv.toml:index=https://uvt.example"],
        ),
    ],
)
def test_uv_poetry_and_pdm_sources(tmp_path, name, text, sources):
    files = {"requirements.txt": PYPI, name: text}
    result, entries = _collect(tmp_path, files)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert _sources(entries["openai"]) == sources


@pytest.mark.parametrize(
    "table, failure",
    [
        ('[[tool.poetry.source]]\nname = "corp"\n', "pyproject.toml: invalid Poetry source"),
        ('[tool.poetry]\nsource = "x"\n', "pyproject.toml: invalid Poetry source"),
        ('[[tool.pdm.source]]\nname = "corp"\n', "pyproject.toml: invalid PDM source"),
    ],
)
def test_a_source_list_that_cannot_be_read_is_a_failure(tmp_path, table, failure):
    result, _ = _collect(tmp_path, {"pyproject.toml": PYPROJECT + table})
    assert failure in result.scan_failures


def test_a_lockfile_resolved_pypi_package_keeps_its_recorded_index(tmp_path):
    lock = (
        'version = 1\n[[package]]\nname = "openai"\nversion = "1.0.0"\n'
        'source = { registry = "https://pypi.org/simple" }\n'
    )
    files = {"requirements.txt": "openai>=1\n", "uv.lock": lock}
    _, plain = _collect(tmp_path / "plain", files)
    assert plain["openai"].package_url == "pkg:pypi/openai@1.0.0"
    _, entries = _collect(
        tmp_path / "redirected",
        {**files, "requirements-dev.txt": "--extra-index-url https://x.example/simple\n"},
    )
    entry = entries["openai"]
    assert entry.package_url is None and entry.registry_uri == "https://pypi.org"
    assert "package_resolution" in entry.claims
    assert _sources(entry) == ["requirements-dev.txt:--extra-index-url=https://x.example"]


def test_a_package_declared_only_by_url_is_not_redirected(tmp_path):
    _, entries = _collect(
        tmp_path,
        {
            "requirements.txt": "openai @ https://files.example/openai-1.0.0-py3-none-any.whl\n"
            "langchain==0.1.0\n--index-url https://idx.example/simple\n"
        },
    )
    assert _sources(entries["openai"]) is None
    assert _sources(entries["langchain"]) == ["requirements.txt:--index-url=https://idx.example"]


def test_sources_are_listed_within_a_bound_and_counted(tmp_path):
    lines = "".join(
        f"--extra-index-url https://h{index:04d}.example/simple\n" for index in range(2_000)
    )
    _, entries = _collect(tmp_path, {"requirements.txt": PYPI + lines})
    sources = _sources(entries["openai"])
    assert sources is not None and len(sources) == 33
    assert sources[0] == "requirements.txt:--extra-index-url=https://h0000.example"
    assert sources[-1] == "[1968 more not listed]"
    assert _redirects(entries["openai"])[0].count("requirements.txt:--extra-index-url") == 1


def test_many_files_are_named_within_a_bound(tmp_path):
    files = {
        f"requirements-{index:02d}.txt": "-i https://h.example/simple\n" for index in range(12)
    }
    _, entries = _collect(tmp_path, {"requirements.txt": PYPI, **files})
    [detail] = _redirects(entries["openai"])
    assert "requirements-07.txt:--index-url and 4 more)" in detail
    assert "requirements-08.txt" not in detail


@pytest.mark.parametrize(
    "scope, registry",
    [
        ("", "https://n{}.example/"),
        # A scope from the environment, with registries that may redirect and without.
        ("scope=${NPM_SCOPE}\n", "https://n{}.example/"),
        ("scope=${NPM_SCOPE}\n", "https://registry.npmjs.org/"),
    ],
)
def test_redirect_handling_is_linear(tmp_path, scope, registry):
    def files(scale: int) -> dict[str, str]:
        packages = "".join(f"langchain-x{index}==1.0\n" for index in range(100 * scale))
        lines = "".join(
            f"--extra-index-url https://h{i}.example/simple\n" for i in range(1_000 * scale)
        )
        npm = {f"@ai-sdk/p{index}": "1.0.0" for index in range(100 * scale)}
        npmrc = "".join(
            f"@s{index}:registry={registry.format(index)}\n" for index in range(1_000 * scale)
        )
        return {
            "requirements.txt": packages + lines,
            "package.json": json.dumps({"dependencies": npm}),
            ".npmrc": scope + npmrc + "registry=https://npm.example/\n",
        }

    roots = {scale: _project(tmp_path / f"p{scale}", files(scale)) for scale in (1, 4)}

    def run(scale: int) -> None:
        components = RegistryScanner().scan(roots[scale]).components
        assert len(components) == 200 * scale
        assert all(c.properties.get("package_sources") for c in components)

    assert scaling_ratio(run) < 8


def test_collection_is_deterministic(tmp_path):
    root = _project(
        tmp_path,
        {
            "package.json": NPM,
            ".npmrc": "registry=https://b.example/\n@anthropic-ai:registry=https://a.example/\n",
            "requirements.txt": PYPI
            + "-i https://c.example/simple\n--extra-index-url https://a.example\n",
        },
    )
    dumps = [
        [c.model_dump(mode="json") for c in RegistryScanner().scan(root).components]
        for _ in range(2)
    ]
    assert dumps[0] == dumps[1]


def test_a_redirect_added_later_is_a_drift_alert(tmp_path):
    project = _project(tmp_path / "project", {"package.json": NPM})
    runner = CliRunner()
    scan = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    assert runner.invoke(main, [*scan, str(tmp_path / "before.json")]).exit_code == 0
    (project / ".npmrc").write_text("registry=https://npm.evil.example/\n")
    assert runner.invoke(main, [*scan, str(tmp_path / "after.json")]).exit_code == 0
    diff = runner.invoke(
        main,
        ["diff", str(tmp_path / "before.json"), str(tmp_path / "after.json"), "--fail-on-alert"],
    )
    assert diff.exit_code == 1, diff.output
    assert "registry_origin" in diff.output


def test_the_mcp_collector_reads_the_same_npmrc_as_before(tmp_path):
    project = _project(
        tmp_path,
        {
            ".npmrc": "registry=https://npm.evil.example/\n",
            ".mcp.json": '{"mcpServers": {"lookup": {"command": "npx", "args": ["-y", "lookup-mcp@1.2.3"]}}}',
        },
    )
    [server] = [
        c for c in MCPScanner().scan(project).components if c.component_type.value == "mcp-server"
    ]
    assert server.launcher_package is None and server.package_url is None
    assert server.properties["package_sources"] == [".npmrc:registry=https://npm.evil.example"]
    assert [(r.severity, r.category) for r in server.risks if r.category == "package_source"] == [
        (RiskSeverity.MEDIUM, "package_source")
    ]


def _mcp_server(root: Path, server: dict[str, object], npmrc: str) -> MCPServerComponent:
    project = _project(
        root, {".npmrc": npmrc, ".mcp.json": json.dumps({"mcpServers": {"lookup": server}})}
    )
    [found] = [
        c for c in MCPScanner().scan(project).components if isinstance(c, MCPServerComponent)
    ]
    return found


NPX = {"command": "npx", "args": ["-y", "lookup-mcp@1.2.3"]}


@pytest.mark.parametrize(
    "server, npmrc, sources",
    [
        (NPX, "scope=${USER}\n@runner:registry=https://npm.evil.example/\n", [".npmrc:scope"]),
        (
            {**NPX, "env": {"npm_config_scope": "${NPM_SCOPE}"}},
            "@runner:registry=https://npm.evil.example/\n",
            ["env:npm_config_scope"],
        ),
        (
            {**NPX, "env": {"npm_config_scope": "${NPM_SCOPE}"}},
            "scope=runner\n@runner:registry=https://npm.evil.example/\n",
            ["env:npm_config_scope"],
        ),
    ],
)
def test_the_mcp_collector_withholds_a_package_a_scope_from_the_environment_may_redirect(
    tmp_path, server, npmrc, sources
):
    found = _mcp_server(tmp_path, server, npmrc)
    assert found.package_url is None
    assert found.properties["package_sources"] == [f"{label}=[unresolved]" for label in sources]
    assert ("package_source", RiskSeverity.MEDIUM) in {
        (r.category, r.severity) for r in found.risks
    }


@pytest.mark.parametrize(
    "npmrc",
    ["scope=${USER}\n", "scope=${USER}\nsave-exact=true\n"],
)
def test_a_scope_from_the_environment_without_a_scope_registry_changes_nothing(tmp_path, npmrc):
    found = _mcp_server(tmp_path, NPX, npmrc)
    assert found.package_url == "pkg:npm/lookup-mcp@1.2.3"
    assert "package_sources" not in found.properties


@pytest.mark.parametrize(
    "server, sources",
    [
        # npm reads `scope`; pnpm and Bun take the default registry, which is listed too.
        (NPX, [".npmrc:@corp:registry=https://registry.npmjs.org"]),
        (
            {"command": "pnpm", "args": ["dlx", "lookup-mcp@1.2.3"]},
            [
                ".npmrc:@corp:registry=https://registry.npmjs.org",
                ".npmrc:registry=https://npm.evil.example",
            ],
        ),
        (
            {"command": "bunx", "args": ["lookup-mcp@1.2.3"]},
            [
                ".npmrc:@corp:registry=https://registry.npmjs.org",
                ".npmrc:registry=https://npm.evil.example",
            ],
        ),
    ],
)
def test_the_mcp_collector_lists_the_registry_each_launcher_may_use(tmp_path, server, sources):
    npmrc = "scope=corp\n@corp:registry=https://registry.npmjs.org/\nregistry=https://npm.evil.example/\n"
    found = _mcp_server(tmp_path, server, npmrc)
    assert found.package_url is None
    assert found.properties["package_sources"] == sources


@pytest.mark.parametrize(
    "name, text, failure",
    [
        (
            "bunfig.toml",
            "[install]\n" + "# padding\n" * 30_000,
            "bunfig.toml: exceeds the size limit: not read",
        ),
        (
            "uv.toml",
            ".".join(["a"] * 40) + " = 1\n",
            "uv.toml: dotted key exceeds the length limit: not read",
        ),
    ],
)
def test_toml_redirect_files_keep_the_pyproject_bounds(tmp_path, name, text, failure):
    result, _ = _collect(tmp_path, {"package.json": NPM, "requirements.txt": PYPI, name: text})
    assert result.scan_failures == [failure]


def test_no_index_setting_is_read_when_every_package_comes_from_a_url(tmp_path):
    project = _project(
        tmp_path, {"requirements.txt": "openai @ https://files.example/openai-1.0.0.whl\n"}
    )
    os.mkfifo(project / "pip.conf")
    result = RegistryScanner().scan(project)
    assert result.scan_failures == [] and "pip.conf" not in result.surfaces_scanned


_PIP_CONFIG_LINES = st.sampled_from(
    [
        "[global]",
        "[install]",
        "[DEFAULT]",
        "[ x ]",
        "[a]b]",
        "index-url = https://a.example/simple",
        "index_url: https://b.example",
        "--index-url=https://c.example",
        "Extra-Index-URL =",
        "  https://d.example",
        "\thttps://e.example",
        "find-links = ./w",
        "timeout = 5",
        "# comment",
        "; comment",
        "  # indented comment",
        "",
        "   ",
        "\x0b",
        "\u3000x = 1",
        "key\u00a0= v",
        "\x85",
        "INDEX-URL = https://f.example",
        "index-url=",
        "a:b=c",
        "pypi-url = https://g.example",
        "PYPI_URL: https://h.example",
        "--pypi-url=https://i.example",
    ]
)
# Lines configparser refuses, drawn less often so that most documents are read.
_PIP_CONFIG_ERRORS = st.sampled_from(["[]", "[global", "novalue", "= x", ": y"])


def _configparser_index_settings(text: str) -> set[tuple[str, str]] | None:
    """What pip's own reader takes from a configuration file: configparser over
    universal newlines, keys normalized as pip normalizes them, empty values skipped."""
    import configparser
    import io

    parser = configparser.RawConfigParser()
    try:
        parser.read_file(io.StringIO(text, newline=None))
    except configparser.Error:
        return None
    found = set()
    for table in (parser.defaults(), *(parser._sections[s] for s in parser.sections())):
        for name, value in table.items():
            key = name.replace("_", "-").removeprefix("--")
            if key in PIP_INDEX_KEYS and (value or "").strip():
                found.add((key, value.strip()))
    return found


@settings(max_examples=2_000)
@given(
    st.sampled_from(["", "[global]\n"]),
    st.lists(
        st.tuples(
            st.one_of(*[_PIP_CONFIG_LINES] * 9, _PIP_CONFIG_ERRORS),
            st.sampled_from(["\n", "\r\n", "\r"]),
        ),
        max_size=10,
    ).map(lambda lines: "".join(line + end for line, end in lines)),
)
def test_pip_configuration_is_read_as_configparser_reads_it(head, body):
    text = head + body
    ours = _pip_config(text)
    assert (None if ours is None else set(ours)) == _configparser_index_settings(text)


@pytest.mark.parametrize(
    "files, gap",
    [
        (
            {
                "pyproject.toml": '[project]\nname = "app"\nversion = "1"\n'
                'dependencies = ["openai==1.5.0"]\n[tool.uv]\n'
                'override-dependencies = [" openai @ https://evil.example/o-0.5.0.whl"]\n'
            },
            "pyproject.toml: uv override or constraint not followed",
        ),
        (
            {
                "pyproject.toml": '[project]\nname = "app"\nversion = "1"\n'
                'dependencies = ["openai==1.5.0"]\n[tool.uv]\n'
                'constraint-dependencies = ["\\topenai<1"]\n'
            },
            "pyproject.toml: uv override or constraint not followed",
        ),
        (
            {"requirements.txt": PYPI, "uv.toml": 'override-dependencies = ["openai==0.5.0"]\n'},
            "uv.toml: uv override or constraint not followed",
        ),
    ],
    ids=["tool-uv-override-leading-space", "tool-uv-constraint-leading-tab", "uv-toml-override"],
)
def test_uv_overrides_and_constraints_are_gaps_as_uv_reads_them(tmp_path, files, gap):
    result, _ = _collect(tmp_path, files)
    assert gap in result.surfaces_excluded
    (component,) = [c for c in result.components if c.name == "openai"]
    if "constraint" not in str(files):
        # An override replaces the declaration; a constraint only narrows it.
        assert component.package_url is None


@pytest.mark.parametrize("key", ["requirement", "constraint", "editable", "--Constraint"])
def test_pip_conf_package_settings_are_gaps_named_by_key(tmp_path, key):
    result, _ = _collect(
        tmp_path, {"requirements.txt": PYPI, "pip.conf": f"[install]\n{key} = deps/x.txt\n"}
    )
    name = key.lower().removeprefix("--")
    assert [g for g in result.surfaces_excluded if g.startswith("pip.conf:")] == [
        f"pip.conf:{name}: {RegistryScanner._PACKAGE_OPTIONS['--' + name]}"
    ]
    (component,) = [c for c in result.components if c.name == "openai"]
    assert component.package_url is None
