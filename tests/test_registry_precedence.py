"""Files and fields that decide what is installed are read, or are coverage gaps."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.scanners.registry import RegistryScanner, _ComposeWalk
from tests.support import scaling_ratio

SHA512 = "sha512-" + base64.b64encode(b"x" * 64).decode()


def _write(root: Path, files: dict[str, object]) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "AGENTS.md").write_text("Keep receipts.\n")
    for name, content in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content if isinstance(content, str) else json.dumps(content))
    return root


def _scan(project: Path, out: Path, *extra: str) -> tuple[int, dict]:
    result = CliRunner().invoke(
        main, ["scan", str(project), "--no-project-policy", "-o", str(out), *extra]
    )
    return result.exit_code, json.loads(out.read_text()) if out.exists() else {}


def _lock(resolved: str, version: str = "4.52.0") -> dict:
    record = {"version": version, "resolved": resolved, "integrity": SHA512}
    root = {"dependencies": {"openai": "^4.52.0"}}
    return {"lockfileVersion": 3, "packages": {"": root, "node_modules/openai": record}}


NPMJS = "https://registry.npmjs.org/openai/-/openai-4.52.0.tgz"


def test_npm_shrinkwrap_is_the_lock_source_when_present(tmp_path):
    # npm installs from npm-shrinkwrap.json and ignores package-lock.json.
    project = _write(
        tmp_path / "project",
        {
            "package.json": {"dependencies": {"openai": "^4.52.0"}},
            "package-lock.json": _lock(NPMJS),
        },
    )
    runner = CliRunner()
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    assert runner.invoke(main, [*args, str(tmp_path / "a.json")]).exit_code == 0
    (project / "npm-shrinkwrap.json").write_text(
        json.dumps(_lock("https://evil.example/openai-4.52.0.tgz"))
    )
    result = RegistryScanner().scan(project)
    (component,) = result.components
    assert component.source_path == "npm-shrinkwrap.json"
    assert component.registry_uri == "https://evil.example"
    assert component.properties["lockfile_record"].startswith("npm-shrinkwrap.json#/")
    assert "npm-shrinkwrap.json" in result.surfaces_scanned
    assert "package-lock.json" not in result.surfaces_scanned
    assert runner.invoke(main, [*args, str(tmp_path / "b.json")]).exit_code == 0
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "registry_uri" in diff.output


def test_an_unreadable_shrinkwrap_is_not_replaced_by_package_lock(tmp_path):
    project = _write(
        tmp_path / "project",
        {
            "package.json": {"dependencies": {"openai": "^4.52.0"}},
            "package-lock.json": _lock(NPMJS),
        },
    )
    outside = tmp_path / "outside.json"
    outside.write_text(json.dumps(_lock(NPMJS)))
    (project / "npm-shrinkwrap.json").symlink_to(outside)
    result = RegistryScanner().scan(project)
    assert result.scan_failures
    (component,) = result.components
    assert component.source_path == "package.json"
    assert "lockfile_record" not in component.properties


@pytest.mark.parametrize(
    "fields",
    [
        {"overrides": {"openai": "4.0.0"}},
        {"overrides": {"some-lib": {"openai": "4.0.0"}}},
        {"overrides": {"openai@^4": "npm:@evil/openai@1.0.0"}},
        {"resolutions": {"**/openai": "4.0.0"}},
        {"resolutions": {"some-lib/openai": "4.0.0"}},
        {"pnpm": {"overrides": {"some-lib>openai": "4.0.0"}}},
        {"pnpm": {"overrides": {"openai@<4": "4.0.0"}}},
        # An override that installs an AI package in place of another one.
        {"overrides": {"some-lib": "npm:@anthropic-ai/sdk@1.0.0"}},
    ],
)
def test_overrides_of_inventoried_packages_are_a_coverage_gap(tmp_path, fields):
    project = _write(
        tmp_path / "project",
        {"package.json": {"dependencies": {"openai": "4.52.0", "some-lib": "1.0.0"}, **fields}},
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == ["package.json: dependency override not translated"]
    if "openai" in json.dumps(fields):
        # What npm installs for it is not what package.json declares.
        assert result.components[0].package_url is None
    code, document = _scan(project, tmp_path / "bom.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"


def test_an_override_of_another_package_is_not_a_gap(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {
                "dependencies": {"openai": "4.52.0"},
                "overrides": {"semver": "7.6.0"},
                "resolutions": {"**/lodash": "4.17.21"},
            }
        },
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert result.components[0].package_url == "pkg:npm/openai@4.52.0"


UNCLASSIFIED = ["package.json: git, URL or path dependency not classified"]


@pytest.mark.parametrize(
    "fields",
    [
        # npm installs the source under the overridden name, whatever package it holds.
        {"overrides": {"helper": "github:openai/openai-node"}},
        {"overrides": {"helper@1": "https://evil.example/openai-4.52.0.tgz"}},
        {"overrides": {"helper": {".": "git+https://evil.example/openai.git"}}},
        {"overrides": {"some-lib": {"helper": "file:../vendor/openai"}}},
        {"resolutions": {"**/helper": "github:openai/openai-node"}},
        {"pnpm": {"overrides": {"some-lib>helper": "link:../vendor/openai"}}},
    ],
)
def test_an_override_to_an_unclassified_source_is_a_gap(tmp_path, fields):
    project = _write(
        tmp_path,
        {"package.json": {"dependencies": {"helper": "1.0.0", "some-lib": "1.0.0"}, **fields}},
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == UNCLASSIFIED and result.components == []


def _nested(depth: int) -> dict[str, object]:
    overrides: dict[str, object] = {"helper": "github:openai/openai-node"}
    for _ in range(depth):
        overrides = {"some-lib": overrides}
    return overrides


@pytest.mark.parametrize(
    "overrides",
    [{f"lib-{i}": "1.0.0" for i in range(10_001)} | {"helper": "github:x/y"}, _nested(40)],
)
def test_overrides_too_many_or_too_deep_to_read_are_a_gap(tmp_path, overrides):
    # Even without an inventoried package: an unread override can install one.
    project = _write(
        tmp_path,
        {"package.json": {"dependencies": {"helper": "1.0.0"}, "overrides": overrides}},
    )
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "package.json: dependency override not translated"
    ]


def test_an_override_source_a_lock_record_names_is_classified(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {
                "dependencies": {"helper": "1.0.0"},
                "overrides": {"helper": "github:acme/helper"},
            },
            "package-lock.json": {
                "lockfileVersion": 3,
                "packages": {"node_modules/helper": {"version": "1.0.1", "resolved": "x"}},
            },
        },
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.components == []


def test_workspaces_are_a_coverage_gap(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {"workspaces": ["packages/*"]},
            "packages/agent/package.json": {"dependencies": {"openai": "4.52.0"}},
        },
    )
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "package.json: workspaces not followed"
    ]


@pytest.mark.parametrize(
    "workspace",
    [
        "packages:\n  - 'packages/*'\n",
        "overrides:\n  openai: github:evil/openai\n",
        "catalog:\n  openai: 4.0.0\n",
    ],
)
def test_a_pnpm_workspace_file_is_a_coverage_gap(tmp_path, workspace):
    # pnpm reads workspace packages, overrides and version catalogs from it.
    project = _write(
        tmp_path,
        {
            "package.json": {"dependencies": {"openai": "4.0.0"}},
            "pnpm-workspace.yaml": workspace,
        },
    )
    assert RegistryScanner().scan(project).surfaces_excluded == [
        "pnpm-workspace.yaml: workspace settings not read"
    ]


@pytest.mark.parametrize(("members", "gaps"), [('["packages/*"]', 1), ("[]", 0)])
def test_uv_workspace_members_are_a_coverage_gap(tmp_path, members, gaps):
    project = _write(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "a"\nversion = "1"\n'
            'dependencies = ["openai==1.51.0"]\n'
            f"[tool.uv.workspace]\nmembers = {members}\n",
            "packages/agent/pyproject.toml": '[project]\nname = "agent"\nversion = "1"\n'
            'dependencies = ["anthropic>=0.30"]\n',
        },
    )
    assert RegistryScanner().scan(project).surfaces_excluded == (
        ["pyproject.toml: uv workspace members not followed"] * gaps
    )


@pytest.mark.parametrize(
    ("environment", "gap"),
    [
        ("COMPOSE_FILE=deploy/stack.yml\n", True),
        ("TAG=1\r\nexport COMPOSE_FILE = compose.yaml:deploy/stack.yml\r\n", True),
        # A name without a value takes it from the environment Compose runs in.
        ("COMPOSE_FILE\n", True),
        ("COMPOSE_FILE: deploy/stack.yml\n", True),
        # Compose's dotenv parser reads statements, not lines: it skips any Unicode
        # space before a name and before "=", and a statement can start right after
        # a closing quote.
        ("\u00a0COMPOSE_FILE=deploy/stack.yml\n", True),
        ("\u0085COMPOSE_FILE=deploy/stack.yml\n", True),
        ("\u3000COMPOSE_FILE=deploy/stack.yml\n", True),
        ("COMPOSE_FILE\u00a0=deploy/stack.yml\n", True),
        ('A="x" COMPOSE_FILE=deploy/stack.yml\n', True),
        ("A='x'COMPOSE_FILE=deploy/stack.yml\n", True),
        ('A="x\ny"COMPOSE_FILE=deploy/stack.yml\n', True),
        # Any mention of the name, in any letter case, counts.
        ("# COMPOSE_FILE=deploy/stack.yml\nOPENAI_API_KEY=sk-test\n", True),
        ("MY_COMPOSE_FILE=a\nCOMPOSE_FILES=b\n", True),
        ("compose_file=deploy/stack.yml\n", True),
        ("COMPOSE_PROJECT_NAME=agent\nOPENAI_API_KEY=sk-test\n", False),
    ],
)
def test_a_compose_file_selected_in_dotenv_is_a_coverage_gap(tmp_path, environment, gap):
    # Compose reads the files COMPOSE_FILE names instead of the default ones.
    project = _write(
        tmp_path,
        {
            "compose.yaml": "services:\n  llm:\n    image: ollama/ollama:0.5.7\n",
            "deploy/stack.yml": "services:\n  llm:\n    image: evil.example/ollama:1\n",
        },
    )
    (project / ".env").write_bytes(environment.encode())
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == ([".env: COMPOSE_FILE not followed"] if gap else [])
    assert ".env" in result.surfaces_scanned
    assert "sk-test" not in json.dumps([c.model_dump(mode="json") for c in result.components])


def test_peer_dependencies_are_read_with_npm_precedence(tmp_path):
    # npm 7 and later install peer dependencies; a later section's spec wins.
    project = _write(
        tmp_path,
        {
            "package.json": {
                "peerDependencies": {"openai": "^4.0.0", "@anthropic-ai/sdk": "0.30.1"},
                "devDependencies": {"openai": "4.52.0"},
            }
        },
    )
    by_ref = {c.bom_ref: c for c in RegistryScanner().scan(project).components}
    assert by_ref["registry:npm/@anthropic-ai/sdk"].version == "0.30.1"
    openai = by_ref["registry:npm/openai"]
    assert openai.version == "4.52.0" and openai.risks == []
    assert openai.properties["declarations"] == [
        "devDependencies: 4.52.0",
        "peerDependencies: ^4.0.0",
    ]


@pytest.mark.parametrize(
    "spec,record",
    [
        ("npm:openai@4.52.0", None),
        ("npm:openai@4.52.0", {"name": "openai"}),
        ("npm:@anthropic-ai/sdk@0.30.1", None),
    ],
)
def test_an_ai_package_behind_a_non_ai_alias_is_inventoried_by_its_target(tmp_path, spec, record):
    files: dict[str, object] = {"package.json": {"dependencies": {"app-utils": spec}}}
    target, version = spec[4:].rsplit("@", 1)
    if record is not None:
        tarball = f"https://registry.npmjs.org/{target}/-/{target}-{version}.tgz"
        files["package-lock.json"] = {
            "lockfileVersion": 3,
            "packages": {
                "": {"dependencies": {"app-utils": spec}},
                "node_modules/app-utils": {
                    **record,
                    "version": version,
                    "resolved": tarball,
                    "integrity": SHA512,
                },
            },
        }
    project = _write(tmp_path, files)
    result = RegistryScanner().scan(project)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    assert component.bom_ref == "registry:npm/app-utils"
    assert component.name == target and component.version == version
    assert component.properties["npm_alias"] == "app-utils"
    assert component.package_url is not None and target.replace("@", "%40") in (
        component.package_url
    )
    assert [r.category for r in component.risks] == ["package_alias"]


def test_a_lock_record_naming_an_ai_package_under_another_key_is_visible(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {"dependencies": {"app-utils": "^1.0.0"}},
            "package-lock.json": {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"app-utils": "^1.0.0"}},
                    "node_modules/app-utils": {
                        "name": "openai",
                        "version": "4.52.0",
                        "resolved": NPMJS,
                        "integrity": SHA512,
                    },
                },
            },
        },
    )
    result = RegistryScanner().scan(project)
    assert [c.bom_ref for c in result.components] == ["registry:npm/app-utils"]
    assert result.surfaces_excluded == ["package-lock.json: aliased package identity is unresolved"]


@pytest.mark.parametrize(
    "spec",
    ["github:attacker/openai-node", "attacker/openai-node", "file:../openai", "https://h/x.tgz"],
)
def test_an_unclassified_source_without_a_lock_record_is_a_gap(tmp_path, spec):
    # npm installs the source under the key, whatever package it holds.
    project = _write(tmp_path, {"package.json": {"dependencies": {"app-utils": spec}}})
    result = RegistryScanner().scan(project)
    assert result.components == []
    assert result.surfaces_excluded == ["package.json: git, URL or path dependency not classified"]


def test_a_source_whose_lock_record_names_another_package_is_classified(tmp_path):
    project = _write(
        tmp_path,
        {
            "package.json": {"dependencies": {"app-utils": "github:org/app-utils#v1"}},
            "package-lock.json": {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/app-utils": {
                        "version": "1.0.0",
                        "resolved": "git+ssh://git@github.com/org/app-utils.git#" + "a" * 40,
                    }
                },
            },
        },
    )
    result = RegistryScanner().scan(project)
    assert result.components == [] and result.surfaces_excluded == []


@pytest.mark.parametrize(
    "body,gap",
    [
        (
            '[tool.uv.sources]\nopenai = { git = "https://github.com/attacker/openai-python", '
            'rev = "abc" }\n',
            "pyproject.toml: uv source not translated",
        ),
        (
            '[tool.uv.sources]\nopenai = { index = "pytorch" }\n',
            "pyproject.toml: uv source not translated",
        ),
        (
            '[tool.uv]\noverride-dependencies = ["openai @ https://evil.example/o.whl"]\n',
            "pyproject.toml: uv override or constraint not followed",
        ),
        (
            '[tool.uv]\nconstraint-dependencies = ["openai<2"]\n',
            "pyproject.toml: uv override or constraint not followed",
        ),
        (
            '[tool.pdm.resolution.overrides]\nopenai = "1.0.0"\n',
            "pyproject.toml: PDM override not followed",
        ),
    ],
)
def test_uv_and_pdm_replacements_of_inventoried_packages_are_gaps(tmp_path, body, gap):
    project = _write(
        tmp_path / "project",
        {
            "pyproject.toml": '[project]\nname = "agent"\nversion = "0.1.0"\n'
            'dependencies = ["openai==1.51.0"]\n' + body
        },
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [gap] and result.scan_failures == []
    (component,) = result.components
    if "constraint" not in body:
        # What is installed is not what [project] declares, so no exact identity.
        assert component.package_url is None and component.registry_uri is None
    code, document = _scan(project, tmp_path / "bom.json")
    assert code == 1
    assert document["metadata"]["completeness"]["scanner_status"]["registry"] == "partial"


def test_uv_sources_for_other_packages_are_not_gaps(tmp_path):
    project = _write(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "agent"\nversion = "0.1.0"\n'
            'dependencies = ["openai==1.51.0", "mylib"]\n'
            '[tool.uv.sources]\nmylib = { path = "../mylib" }\n'
        },
    )
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == []
    assert result.components[0].package_url == "pkg:pypi/openai@1.51.0"


def test_dependency_groups_build_requirements_and_tool_dev_dependencies_are_read(tmp_path):
    project = _write(
        tmp_path,
        {
            "pyproject.toml": '[project]\nname = "agent"\nversion = "0.1.0"\ndependencies = []\n'
            '[dependency-groups]\ndev = ["openai==1.51.0", {include-group = "Test"}]\n'
            'test = ["mcp>=1.2"]\n'
            '[build-system]\nrequires = ["torch==2.3.0", "setuptools"]\n'
            '[tool.uv]\ndev-dependencies = ["langgraph==0.2.0"]\n'
            '[tool.pdm.dev-dependencies]\nlint = ["anthropic==0.30.0"]\n'
        },
    )
    result = RegistryScanner().scan(project)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert sorted(c.name for c in result.components) == [
        "anthropic",
        "langgraph",
        "mcp",
        "openai",
        "torch",
    ]


@pytest.mark.parametrize(
    "body",
    [
        '[dependency-groups]\ndev = "openai"\n',
        '[dependency-groups]\ndev = [{include-group = "missing"}]\n',
        "[dependency-groups]\ndev = [1]\n",
    ],
)
def test_invalid_dependency_groups_are_a_failure(tmp_path, body):
    _write(tmp_path, {"pyproject.toml": body})
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "pyproject.toml: invalid dependency groups"
    ]


@pytest.mark.parametrize("value", ['["torch>=2"]', '"torch>=2"', "1"])
def test_optional_dependencies_that_are_not_a_table_are_a_failure(tmp_path, value):
    _write(tmp_path, {"pyproject.toml": f"[project]\noptional-dependencies = {value}\n"})
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "pyproject.toml: invalid optional dependencies"
    ]


@pytest.mark.parametrize(
    "lockfiles,ecosystem",
    [
        (["Pipfile.lock"], "pypi"),
        (["pdm.lock"], "pypi"),
        (["Pipfile.lock", "pdm.lock"], "pypi"),
        (["bun.lock"], "npm"),
        (["bun.lockb"], "npm"),
        (["bun.lock", "bun.lockb"], "npm"),
    ],
)
def test_lockfiles_the_collector_cannot_read_are_a_low_finding(tmp_path, lockfiles, ecosystem):
    # The declarations are read, so coverage stays complete; that the resolution is
    # not is visible on each package it may affect.
    files: dict[str, object] = {
        "requirements.txt": "openai==1.51.0\n",
        "package.json": {"dependencies": {"openai": "4.52.0"}},
    }
    files.update(dict.fromkeys(lockfiles, ""))
    project = _write(tmp_path / "project", files)
    result = RegistryScanner().scan(project)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    for component in result.components:
        findings = [r for r in component.risks if r.category == "lockfile_unread"]
        if component.registry_type == ecosystem:
            (finding,) = findings
            assert finding.severity.value == "low"
            assert all(name in finding.detail for name in lockfiles)
        else:
            assert findings == []
    code, _ = _scan(project, tmp_path / "bom.json")
    assert code == 0


@pytest.mark.parametrize("lockfile", ["uv.lock", "poetry.lock", "yarn.lock", "pnpm-lock.yaml"])
def test_lockfiles_the_collector_reads_are_not_reported_as_unread(tmp_path, lockfile):
    # These resolve packages for the lockfile evidence the collector records, so they
    # are scanned surfaces, and an unreadable one is a failure, never a low finding.
    files: dict[str, object] = {
        "requirements.txt": "openai==1.51.0\n",
        "package.json": {"dependencies": {"openai": "4.52.0"}},
        lockfile: "",
    }
    result = RegistryScanner().scan(_write(tmp_path / "project", files))
    assert lockfile in result.surfaces_scanned
    assert [r for c in result.components for r in c.risks if r.category == "lockfile_unread"] == []


def test_a_pipfile_is_a_coverage_gap(tmp_path):
    _write(tmp_path, {"Pipfile": '[packages]\nopenai = "*"\n'})
    assert RegistryScanner().scan(tmp_path).surfaces_excluded == ["Pipfile: dependencies not read"]


COMPOSE_NAMES = [
    "compose.yaml",
    "compose.yml",
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.override.yml",
    "compose.override.yaml",
    "docker-compose.override.yml",
    "docker-compose.override.yaml",
]


@pytest.mark.parametrize("name", COMPOSE_NAMES)
def test_every_file_compose_reads_by_default_is_read(tmp_path, name):
    _write(tmp_path, {name: "services:\n  llm:\n    image: ollama/ollama:0.5.7\n"})
    result = RegistryScanner().scan(tmp_path)
    assert [(c.name, c.source_path) for c in result.components] == [("ollama/ollama:0.5.7", name)]
    assert name in result.surfaces_scanned


def test_a_compose_override_that_swaps_an_image_is_drift(tmp_path):
    project = _write(
        tmp_path / "project",
        {"docker-compose.yml": "services:\n  llm:\n    image: ollama/ollama:0.5.7\n"},
    )
    runner = CliRunner()
    args = ["scan", str(project), "--no-project-policy", "--report-only", "-o"]
    assert runner.invoke(main, [*args, str(tmp_path / "a.json")]).exit_code == 0
    (project / "compose.override.yaml").write_text(
        "services:\n  llm:\n    image: attacker.example/ollama/ollama:0.5.7\n"
    )
    assert runner.invoke(main, [*args, str(tmp_path / "b.json")]).exit_code == 0
    diff = runner.invoke(
        main, ["diff", str(tmp_path / "a.json"), str(tmp_path / "b.json"), "--fail-on-alert"]
    )
    assert diff.exit_code == 1, diff.output
    assert "attacker.example/ollama/ollama:0.5.7" in diff.output


def test_the_same_image_in_several_files_is_one_component(tmp_path):
    project = _write(
        tmp_path / "project",
        {
            "Dockerfile": "FROM ollama/ollama:0.5.7\n",
            "Dockerfile.agent": "FROM ollama/ollama:0.5.7\n",
            "compose.yaml": "services:\n  llm:\n    image: ollama/ollama:0.5.7\n",
        },
    )
    result = RegistryScanner().scan(project)
    assert result.scan_failures == []
    (component,) = result.components
    assert component.source_path == "Dockerfile"
    assert component.properties["source_paths"] == [
        "Dockerfile",
        "Dockerfile.agent",
        "compose.yaml",
    ]
    code, document = _scan(project, tmp_path / "bom.json")
    assert code == 0, document["metadata"]["completeness"]
    assert not any(
        "conflicting duplicate" in failure
        for failure in document["metadata"]["completeness"]["scan_failures"]
    )


DIGEST = "a" * 64


@pytest.mark.parametrize(
    ("compose", "expected"),
    [
        # Quotes are YAML syntax, not part of the image.
        (f'services:\n  a:\n    image: "vllm/vllm-openai@sha256:{DIGEST}"\n', []),
        ("services:\n  a:\n    image: 'ollama/ollama:latest'\n", ["version_pinning"]),
        ('services:\n  a: {"image": "ollama/ollama:latest"}\n', ["version_pinning"]),
        ("services:\n  a:\n    image : ollama/ollama:0.5.7\n", ["mutable_image_tag"]),
        ("services:\n  a:\n    image: >-\n      ollama/ollama:0.5.7\n", ["mutable_image_tag"]),
        ("services:\n  a:\n    image: !override ollama/ollama:0.5.7\n", ["mutable_image_tag"]),
        (
            "x-base: &base\n  image: ollama/ollama:0.5.7\nservices:\n  a:\n    <<: *base\n",
            ["mutable_image_tag"],
        ),
        (
            "x-base: &base\n  image: ollama/ollama:1\nservices:\n"
            "  a:\n    <<: *base\n    image: ollama/ollama:0.5.7\n",
            ["mutable_image_tag"],
        ),
    ],
)
def test_compose_images_are_read_as_yaml(tmp_path, compose, expected):
    _write(tmp_path, {"docker-compose.yml": compose})
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    (component,) = result.components
    assert '"' not in component.name and "'" not in component.name
    assert component.name in {
        f"vllm/vllm-openai@sha256:{DIGEST}",
        "ollama/ollama:latest",
        "ollama/ollama:0.5.7",
    }
    assert [r.category for r in component.risks] == expected


def test_text_that_is_not_a_service_image_is_not_a_component(tmp_path):
    _write(
        tmp_path,
        {
            "docker-compose.yml": "services:\n  web:\n    image: nginx:1.27\n"
            "    # image: ollama/ollama:old\n"
            "    environment:\n      - SMTP_FROM=model-alerts@corp.example\n"
            '    command: ["FROM", "ollama/ollama:2"]\n'
            "  reset:\n    image: !reset null\n"
            "x-unused:\n  image: ollama/ollama:3\n"
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.components == [] and result.surfaces_excluded == []


@pytest.mark.parametrize(
    ("service", "gap"),
    [
        (
            "image: ollama/ollama:${TAG:-latest}",
            "docker-compose.yml: image substitution not resolved",
        ),
        ("build: ./agent", "docker-compose.yml: build context not followed"),
        (
            "build:\n      context: .\n      dockerfile: docker/Dockerfile",
            "docker-compose.yml: build context not followed",
        ),
        (
            "extends:\n      file: common.yaml\n      service: base",
            "docker-compose.yml: extends not followed",
        ),
        ("image: !custom ollama/ollama:1", "docker-compose.yml: tagged image value not resolved"),
    ],
)
def test_compose_forms_that_are_not_followed_are_gaps(tmp_path, service, gap):
    _write(tmp_path, {"docker-compose.yml": f"services:\n  a:\n    {service}\n"})
    assert RegistryScanner().scan(tmp_path).surfaces_excluded == [gap]


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode()


@pytest.mark.parametrize(
    ("compose", "gap"),
    [
        # Compose decodes !!binary from base64, so the image it pulls is not the text.
        (
            f"services:\n  a:\n    image: !!binary {_b64('ollama/ollama:latest')}\n",
            "tagged image value not resolved",
        ),
        (
            "services:\n  a:\n    image: !<tag:yaml.org,2002:binary> "
            f"{_b64('attacker.example/ollama/ollama:0.5.7')}\n",
            "tagged image value not resolved",
        ),
        (
            "services:\n  a:\n    image: !!null ollama/ollama:latest\n",
            "tagged image value not resolved",
        ),
        ("services:\n  a:\n    image: !!int 7\n", "tagged image value not resolved"),
        (
            f"models:\n  chat:\n    model: !!binary {_b64('ai/smollm2')}\n",
            "tagged image value not resolved",
        ),
        (f"models:\n  chat: !!binary {_b64('ai/smollm2')}\n", "tagged image value not resolved"),
        (
            "services:\n  a:\n    build:\n      dockerfile_inline: !!binary "
            f"{_b64('FROM ollama/ollama:latest')}\n",
            "build not followed",
        ),
        (f"services:\n  a:\n    build: !!binary {_b64('.')}\n", "build not followed"),
        (
            f"services:\n  a:\n    build:\n      context: !!binary {_b64('.')}\n",
            "build context not followed",
        ),
    ],
)
def test_tagged_compose_values_are_gaps(tmp_path, compose, gap):
    _write(tmp_path, {"compose.yaml": compose, "Dockerfile": "FROM node:22\n"})
    result = RegistryScanner().scan(tmp_path)
    assert result.components == [] and result.scan_failures == []
    assert result.surfaces_excluded == [f"compose.yaml: {gap}"]


@pytest.mark.parametrize(
    ("service", "names"),
    [
        ("image: !!str ollama/ollama:0.5.7", ["ollama/ollama:0.5.7"]),
        ("image: !<tag:yaml.org,2002:str> ollama/ollama:0.5.7", ["ollama/ollama:0.5.7"]),
        ("image: !!null", []),
        ("image: !!null null", []),
        ("image: !reset null", []),
        # An override file's reset removes the build; there is nothing to follow.
        ("build: !reset null", []),
        ("build: !reset", []),
    ],
)
def test_text_and_null_tags_are_read_as_compose_reads_them(tmp_path, service, names):
    _write(tmp_path, {"compose.override.yaml": f"services:\n  a:\n    {service}\n"})
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    assert [c.name for c in result.components] == names


def test_a_tagged_compose_key_fails_the_file(tmp_path):
    # Compose would read the key "image" from the base64 text.
    _write(
        tmp_path,
        {"compose.yaml": f"services:\n  a:\n    !!binary {_b64('image')}: ollama/ollama:latest\n"},
    )
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "compose.yaml: YAML mapping parse failed or unsupported"
    ]


@pytest.mark.parametrize(
    "build",
    [
        # Compose would build from the host's root, not the project's Dockerfile.
        "build: /",
        "build:\n      context: /",
        "build:\n      context: //.",
        "build:\n      context: .\n      dockerfile: /Dockerfile",
        "build:\n      context: ./\n      dockerfile: .\\Dockerfile",
        "build:\n      context: [.]",
    ],
)
def test_builds_outside_the_project_root_are_gaps(tmp_path, build):
    _write(
        tmp_path,
        {
            "compose.yaml": f"services:\n  a:\n    {build}\n",
            "Dockerfile": "FROM ollama/ollama:0.5.7\n",
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == ["compose.yaml: build context not followed"]


@pytest.mark.parametrize(
    ("anchor", "make_services"),
    [
        # Every service aliases one service whose build holds the inline Dockerfile.
        (
            "x-agent: &agent\n  build:\n    dockerfile_inline: |\n",
            lambda scale: (
                "services: {" + ", ".join(f"s{i}: *agent" for i in range(500 * scale)) + "}\n"
            ),
        ),
        # Each service has a build of its own, and all alias one inline scalar.
        (
            "x-inline: &inline |\n",
            lambda scale: (
                "services:\n"
                + "".join(
                    f"  s{i}: {{build: {{dockerfile_inline: *inline}}}}\n"
                    for i in range(250 * scale)
                )
            ),
        ),
    ],
)
def test_an_inline_dockerfile_shared_by_many_services_is_parsed_once(
    tmp_path, monkeypatch, anchor, make_services
):
    # Parsing it again for each alias took tens of minutes for one Compose file.
    parsed: list[int] = []
    original = RegistryScanner._dockerfile_images

    def counting(content: str) -> tuple[list[str], list[str]]:
        parsed.append(len(content))
        return original(content)

    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        body = "".join(f"      RUN echo {i}\n" for i in range(7_000 * scale))
        _write(
            root,
            {
                "compose.yaml": anchor
                + "      FROM ollama/ollama:0.5.7\n"
                + body
                + make_services(scale)
            },
        )
        roots[scale] = root
    monkeypatch.setattr(RegistryScanner, "_dockerfile_images", staticmethod(counting))
    result = RegistryScanner().scan(roots[4])
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert [c.name for c in result.components] == ["ollama/ollama:0.5.7"]
    assert len(parsed) == 1 and parsed[0] > 400_000
    monkeypatch.setattr(RegistryScanner, "_dockerfile_images", staticmethod(original))
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10


def _count_path_reads(monkeypatch) -> list[str]:
    read: list[str] = []
    original = _ComposeWalk._local

    def counting(path: str) -> list[str] | None:
        read.append(path)
        return original(path)

    monkeypatch.setattr(_ComposeWalk, "_local", staticmethod(counting))
    return read


LONG_PATH = "ab/" * 140_000 + "ab"


@pytest.mark.parametrize(
    "make_compose",
    [
        # Each service has a build of its own, and all alias one context, one
        # dockerfile, both, or merge one mapping that holds the context.
        lambda scale, path: (
            "x-c: &c "
            + path
            + "\nservices:\n"
            + "".join(f"  s{i}: {{build: {{context: *c}}}}\n" for i in range(250 * scale))
        ),
        lambda scale, path: (
            "x-c: &c "
            + path
            + "\nservices:\n"
            + "".join(f"  s{i}: {{build: {{dockerfile: *c}}}}\n" for i in range(250 * scale))
        ),
        lambda scale, path: (
            "x-c: &c "
            + path
            + "\nservices:\n"
            + "".join(
                f"  s{i}: {{build: {{context: *c, dockerfile: *c}}}}\n" for i in range(250 * scale)
            )
        ),
        lambda scale, path: (
            "x-b: &b {context: "
            + path
            + "}\nservices:\n"
            + "".join(f"  s{i}: {{build: {{<<: *b}}}}\n" for i in range(250 * scale))
        ),
    ],
)
def test_a_build_path_shared_by_many_builds_is_read_once(tmp_path, monkeypatch, make_compose):
    # Splitting it again for each build took minutes for one Compose file.
    roots = {}
    for scale in (1, 4):
        root = tmp_path / f"scale_{scale}"
        path = "ab/" * (35_000 * scale) + "ab"
        _write(
            root,
            {"compose.yaml": make_compose(scale, path), "Dockerfile": "FROM ollama/ollama:0.5.7\n"},
        )
        roots[scale] = root
    original = _ComposeWalk._local
    read = _count_path_reads(monkeypatch)
    result = RegistryScanner().scan(roots[4])
    assert result.scan_failures == []
    assert result.surfaces_excluded == ["compose.yaml: build context not followed"]
    assert [c.name for c in result.components] == ["ollama/ollama:0.5.7"]
    assert [path for path in read if len(path) > 100] == [LONG_PATH]
    monkeypatch.setattr(_ComposeWalk, "_local", staticmethod(original))
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10


def test_a_root_context_shared_by_many_builds_is_split_once(tmp_path, monkeypatch):
    read = _count_path_reads(monkeypatch)
    root = "./" * 2_000 + "."
    _write(
        tmp_path,
        {
            "compose.yaml": f"x-c: &c {root}\nservices:\n"
            + "".join(f"  s{i}: {{build: {{context: *c}}}}\n" for i in range(1_000)),
            "Dockerfile": "FROM ollama/ollama:0.5.7\n",
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert [c.name for c in result.components] == ["ollama/ollama:0.5.7"]
    assert read.count(root) == 1


@pytest.mark.parametrize(
    "build",
    [
        # Each one names the root Dockerfile, but is longer than any path Linux opens.
        "build: " + "./" * 2_100,
        "build:\n      context: " + "./" * 2_100,
        "build:\n      dockerfile: " + "./" * 2_100 + "Dockerfile",
    ],
)
def test_a_build_path_over_the_length_bound_is_a_gap(tmp_path, build):
    _write(
        tmp_path,
        {
            "compose.yaml": f"services:\n  a:\n    {build}\n",
            "Dockerfile": "FROM ollama/ollama:0.5.7\n",
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == []
    assert result.surfaces_excluded == ["compose.yaml: build context not followed"]


@pytest.mark.parametrize(
    "build",
    [
        # BuildKit uses a named context in place of the image a FROM line names.
        (
            'context: .\n      additional_contexts:\n        "python:3.12-slim": '
            "docker-image://ollama/ollama:0.5.7"
        ),
        (
            "context: .\n      additional_contexts:\n"
            '        - "python:3.12-slim=docker-image://ollama/ollama:0.5.7"'
        ),
        (
            'context: .\n      additional_contexts:\n        "python:3.12-slim": '
            "https://github.com/example/ollama-rootfs.git"
        ),
        "context: .\n      additional_contexts:\n        python: ./rootfs",
        (
            "dockerfile_inline: |\n        FROM python:3.12-slim\n      additional_contexts:\n"
            '        "python:3.12-slim": docker-image://vllm/vllm-openai:v0.6.0'
        ),
        (
            "dockerfile_inline: FROM python:3.12-slim\n"
            "      additional_contexts: [python:3.12-slim=docker-image://vllm/vllm-openai:v0.6.0]"
        ),
        # docker buildx bake reads named contexts from x-bake in the same file.
        (
            'context: .\n      x-bake:\n        contexts:\n          "python:3.12-slim": '
            "docker-image://ollama/ollama:0.5.7"
        ),
        "context: .\n      x-bake:\n        <<: {contexts: {python: docker-image://ollama/ollama}}",
    ],
)
def test_named_build_contexts_are_a_gap(tmp_path, build):
    _write(
        tmp_path,
        {
            "compose.yaml": f"services:\n  agent:\n    build:\n      {build}\n",
            "Dockerfile": "FROM python:3.12-slim\n",
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.components == []
    assert result.surfaces_excluded == ["compose.yaml: build context not followed"]


@pytest.mark.parametrize(
    "contexts",
    [
        "additional_contexts: {}",
        "additional_contexts: []",
        "additional_contexts:",
        "additional_contexts: !reset null",
        "x-bake: {tags: [agent:1], contexts: {}}",
    ],
)
def test_a_build_without_named_contexts_stays_covered(tmp_path, contexts):
    _write(
        tmp_path,
        {
            "compose.yaml": f"services:\n  agent:\n    build:\n      context: .\n      {contexts}\n",
            "Dockerfile": "FROM ollama/ollama:0.5.7\n",
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.scan_failures == [] and result.surfaces_excluded == []
    assert [c.name for c in result.components] == ["ollama/ollama:0.5.7"]


def test_compose_include_is_a_gap_and_root_builds_are_covered(tmp_path):
    _write(
        tmp_path,
        {
            "docker-compose.yml": "include:\n  - other.yaml\nservices:\n  a:\n    build: .\n"
            "  b:\n    build:\n      context: ./\n      dockerfile: ./Dockerfile.agent\n",
            "Dockerfile": "FROM ollama/ollama:0.5.7\n",
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == ["docker-compose.yml: include not followed"]
    assert [c.name for c in result.components] == ["ollama/ollama:0.5.7"]


def test_an_inline_dockerfile_is_read(tmp_path):
    _write(
        tmp_path,
        {
            "docker-compose.yml": "services:\n  a:\n    build:\n      dockerfile_inline: |\n"
            "        FROM ghcr.io/huggingface/text-generation-inference:2.0\n"
            "        RUN echo FROM ollama/ollama:1\n"
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert [c.name for c in result.components] == [
        "ghcr.io/huggingface/text-generation-inference:2.0"
    ]


@pytest.mark.parametrize(
    "compose",
    [
        "services: [1, 2]\n",
        "services:\n  a:\n    image: ollama/ollama:1\n    image: ollama/ollama:2\n",
        "services:\n  a:\n    <<: [1]\n",
        "- not a mapping\n",
        "services:\n  a: {image: [ollama, ollama]",
    ],
)
def test_compose_files_that_are_not_readable_mappings_fail(tmp_path, compose):
    _write(tmp_path, {"docker-compose.yml": compose})
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "docker-compose.yml: YAML mapping parse failed or unsupported"
    ]


def test_merge_keys_are_followed_once_per_mapping(tmp_path):
    # Each level merges the previous one twice: expanding every merge would take
    # 2**60 steps.
    levels = "".join(f"a{i}: &a{i} {{<<: [*a{i - 1}, *a{i - 1}]}}\n" for i in range(1, 60))
    _write(
        tmp_path,
        {
            "docker-compose.yml": "a0: &a0 {image: ollama/ollama:0.5.7}\n"
            + levels
            + "services:\n  s:\n    <<: *a59\n"
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert [c.name for c in result.components] == ["ollama/ollama:0.5.7"]


def test_a_mapping_that_merges_itself_is_a_gap(tmp_path):
    _write(
        tmp_path,
        {"docker-compose.yml": "services:\n  s: &s\n    <<: *s\n    image: ollama/ollama:1\n"},
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == ["docker-compose.yml: YAML merge key cycle not followed"]
    assert [c.name for c in result.components] == ["ollama/ollama:1"]


def test_a_compose_file_with_too_many_tokens_fails(tmp_path):
    _write(
        tmp_path,
        {"docker-compose.yml": "services:\n" + "".join(f"  s{i}: {{}}\n" for i in range(9000))},
    )
    assert RegistryScanner().scan(tmp_path).scan_failures == [
        "docker-compose.yml: YAML mapping parse failed or unsupported"
    ]


def test_a_containerfile_is_read_like_a_dockerfile(tmp_path):
    _write(tmp_path, {"Containerfile": "FROM ollama/ollama:0.5.7\n"})
    result = RegistryScanner().scan(tmp_path)
    assert [(c.name, c.source_path) for c in result.components] == [
        ("ollama/ollama:0.5.7", "Containerfile")
    ]


def test_compose_models_are_inventoried_whatever_their_name(tmp_path):
    # Docker Model Runner pulls these as OCI artifacts; none matches an image keyword.
    _write(
        tmp_path,
        {
            "compose.yaml": "models:\n  chat:\n    model: ai/smollm2:360M-Q4_K_M\n"
            "  embed: ai/mxbai-embed-large\n"
            "services:\n  app:\n    image: nginx:1.27\n    models: [chat]\n"
        },
    )
    result = RegistryScanner().scan(tmp_path)
    assert result.surfaces_excluded == [] and result.scan_failures == []
    by_name = {c.name: c for c in result.components}
    assert sorted(by_name) == ["ai/mxbai-embed-large", "ai/smollm2:360M-Q4_K_M"]
    chat = by_name["ai/smollm2:360M-Q4_K_M"]
    assert chat.properties["artifact_type"] == "model"
    assert [r.category for r in chat.risks] == ["mutable_image_tag"]


@pytest.mark.parametrize(("target_name", "inventoried"), [("my-lib", False), ("openai", True)])
def test_a_linked_path_dependency_is_classified_by_the_package_it_links(
    tmp_path, target_name, inventoried
):
    # npm records a file: directory as a link; the entry it links to names the package.
    project = _write(
        tmp_path,
        {
            "package.json": {"dependencies": {"my-lib": "file:packages/my-lib"}},
            "package-lock.json": {
                "lockfileVersion": 3,
                "packages": {
                    "node_modules/my-lib": {"resolved": "packages/my-lib", "link": True},
                    "packages/my-lib": {"name": target_name, "version": "1.0.0"},
                },
            },
        },
    )
    result = RegistryScanner().scan(project)
    assert [c.bom_ref for c in result.components] == (
        ["registry:npm/my-lib"] if inventoried else []
    )
    if inventoried:
        assert result.surfaces_excluded == []
        assert [r.category for r in result.components[0].risks] == ["nonregistry_source"]
    else:
        assert result.surfaces_excluded == [] and result.scan_failures == []
