"""Positive and adversarial regression tests for Bundle F1:
R-HIGH-13, R-HIGH-14, R-MED-19(a) (mcp_launch.py);
R-HIGH-06, R-LOW-03, R-MED-14, Muse I-322-1 (registry.py);
R-MED-05, R-MED-07, Muse E-332-1, E-332-2, E-332-3 (sbom_import.py).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

import pytest

from nexus_symbiote.sbom_import import (
    _cargo_lock_agrees,
    _conda_requirement,
    walk_nested_manifests,
)
from nexus_symbiote.scanners.mcp_launch import analyze, known_executable
from nexus_symbiote.scanners.registry import RegistryScanner
from tests.support import scaling_ratio


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def _flow_depth_exceeded(text: str) -> bool:
    """Scan with the bounded loader: True for the depth refusal, False for a parse error."""
    import yaml

    try:
        for _ in yaml.scan(text, Loader=RegistryScanner._bounded_yaml_loader()):
            pass
    except ValueError:
        return True
    except yaml.YAMLError:
        return False
    return False


# ---------------------------------------------------------------------------
# R-HIGH-13, R-HIGH-14, R-MED-19(a): mcp_launch.py
# ---------------------------------------------------------------------------


def test_r_high_13_container_volume_substitutions() -> None:
    # Non-leading, non-colon, and nested unresolved substitutions fail closed.
    for vol in (
        "/${X:=/}:/host",
        "/var/run/${X:=/}docker.sock:/s",
        "/${X=/}:/host",
        "/${X+/}:/host",
        "/${X?/}:/host",
        "/${X:-${Y:-/}}:/host",
    ):
        res = analyze("docker", ["run", "-v", vol, "alpine@sha256:" + "a" * 64])
        assert res.unknown is not None
        assert "unresolved" in res.unknown

    for mount_spec in (
        "type=bind,source=/${X:=/},target=/host",
        "type=bind,source=/${X=/},target=/host",
        "type=bind,source=/${X:-${Y:-/}},target=/host",
    ):
        mount_res = analyze(
            "docker",
            ["run", "--mount", mount_spec, "alpine@sha256:" + "a" * 64],
        )
        assert mount_res.unknown is not None

    # Container mounted script detection includes versioned lua/ruby/php/perl runners.
    for runner, script in (
        ("lua5.4", "server.lua"),
        ("luajit2.1", "server.lua"),
        ("ruby3.2", "server.rb"),
        ("php8.2", "server.php"),
        ("perl5.38", "server.pl"),
    ):
        c_res = analyze(
            "docker",
            [
                "run",
                "-v",
                "./app:/work",
                "-w",
                "/work",
                "alpine@sha256:" + "a" * 64,
                runner,
                script,
            ],
        )
        assert c_res.context.get("code_loading_option"), (runner, script)

    # Plain ${EMPTY} and ${X-/} expand to host root / socket mount flags.
    root_empty = analyze("docker", ["run", "-v", "/${EMPTY}/:/host", "alpine@sha256:" + "a" * 64])
    assert root_empty.context.get("host_root_mount")

    root_dash = analyze("docker", ["run", "-v", "/${X-/}:/host", "alpine@sha256:" + "a" * 64])
    assert root_dash.context.get("host_root_mount")

    sock_empty = analyze(
        "docker",
        ["run", "-v", "/var/run/${EMPTY}docker.sock:/s", "alpine@sha256:" + "a" * 64],
    )
    assert sock_empty.context.get("runtime_socket_mount")

    # Benign workspaceFolder mount does NOT fail or flag host_root_mount.
    benign = analyze(
        "docker", ["run", "-v", "${workspaceFolder}/app:/app", "alpine@sha256:" + "a" * 64]
    )
    assert benign.unknown is None
    assert not benign.context.get("host_root_mount")


@pytest.mark.parametrize(
    ("cmd", "args"),
    [
        ("lua5.4", ["-e", "os.execute('id')"]),
        ("luajit2.1", ["-e", "os.execute('id')"]),
        ("ruby3.2", ["-e", "system('id')"]),
        ("php8.2", ["-r", "system('id');"]),
        ("perl5.38", ["-e", "system('id')"]),
        ("osascript", ['-edo shell script "id"']),
        ("python3", ["-m", "pdb", "-c", "import os", "app.py"]),
        ("python3", ["-m", "code"]),
        ("python3", ["-m", "asyncio"]),
        ("python3", ["-m", "idlelib"]),
    ],
)
def test_r_high_14_versioned_interpreters_osascript_and_code_modules(
    cmd: str, args: list[str]
) -> None:
    res = analyze(cmd, args)
    assert res.unknown is not None, (cmd, args)


def test_r_high_14_known_executable_includes_versioned_interpreters() -> None:
    for name in ("lua5.4", "luajit2.1", "ruby3.2", "php8.2", "perl5.38"):
        assert known_executable(name)


def test_r_med_19a_launcher_gaps() -> None:
    # 1. docker --security-opt no-new-privileges=0 and =f
    for opt in ("no-new-privileges=0", "no-new-privileges:0", "no-new-privileges=f"):
        res = analyze("docker", ["run", "--security-opt", opt, "alpine@sha256:" + "a" * 64])
        assert res.context.get("security_options_disabled"), opt

    # Benign no-new-privileges=true does NOT flag security_options_disabled.
    ok_sec = analyze(
        "docker", ["run", "--security-opt", "no-new-privileges=true", "alpine@sha256:" + "a" * 64]
    )
    assert not ok_sec.context.get("security_options_disabled")

    # 2. Mounted python3.13t and pypy3 -m in container command
    for py_bin in ("python3.13t", "pypy3"):
        res = analyze(
            "docker",
            [
                "run",
                "-v",
                "./app:/work",
                "-w",
                "/work",
                "alpine@sha256:" + "a" * 64,
                py_bin,
                "-m",
                "srv",
            ],
        )
        assert res.context.get("code_loading_option"), py_bin

    # 3. uv run -m timeit / code / pdb -c
    for uv_args in (
        ["run", "-m", "timeit", "print(1)"],
        ["run", "-m", "code"],
        ["run", "-m", "pdb", "-c", "import os", "app.py"],
    ):
        uv_res = analyze("uv", uv_args)
        assert uv_res.unknown is not None, uv_args

    # Normal uv run -m my_server is NOT rejected as inline python code.
    uv_ok = analyze("uv", ["run", "-m", "my_mcp_server"])
    assert uv_ok.unknown is None

    # 4. deno task -c / --config / --cwd
    for deno_args in (
        ["task", "-c", "sub/deno.json", "serve"],
        ["task", "--config=sub/deno.json", "serve"],
        ["task", "--cwd", "../other", "serve"],
        ["task", "--cwd=../other", "serve"],
        ["task", "--no-config", "serve"],
    ):
        deno_res = analyze("deno", deno_args)
        assert deno_res.unknown is not None, deno_args
        if "sub/" in " ".join(deno_args) or "../other" in " ".join(deno_args):
            assert deno_res.relocated is True, deno_args


# ---------------------------------------------------------------------------
# R-HIGH-06, R-LOW-03, R-MED-14: registry.py
# ---------------------------------------------------------------------------


def test_r_high_06_npm_and_yarn_decoy_devdependencies(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "package.json",
        json.dumps(
            {
                "dependencies": {"openai": "git+https://evil.example/openai.git#main"},
                "devDependencies": {"openai": "4.0.0"},
            }
        ),
    )
    _write(
        tmp_path,
        "package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {
                        "dependencies": {"openai": "git+https://evil.example/openai.git#main"},
                        "devDependencies": {"openai": "4.0.0"},
                    },
                    "node_modules/openai": {
                        "version": "4.0.0",
                        "resolved": "https://registry.npmjs.org/openai/-/openai-4.0.0.tgz",
                        "integrity": "sha512-" + "A" * 86 + "==",
                    },
                },
            }
        ),
    )
    res = RegistryScanner().scan(tmp_path)
    comps = [c for c in res.components if c.name == "openai"]
    assert len(comps) == 1
    comp = comps[0]
    assert any(r.category == "nonregistry_source" for r in comp.risks)
    assert comp.package_url is None
    assert any("conflicting dependency sources" in gap for gap in res.surfaces_excluded)

    # Alias decoy in dependencies hidden behind devDependencies exact version
    alias_dir = tmp_path / "alias_case"
    _write(
        alias_dir,
        "package.json",
        json.dumps(
            {
                "dependencies": {"helper": "npm:openai@4.0.0"},
                "devDependencies": {"helper": "1.0.0"},
            }
        ),
    )
    res_alias = RegistryScanner().scan(alias_dir)
    assert any(c.name == "helper" for c in res_alias.components)
    assert any(r.category == "package_alias" for c in res_alias.components for r in c.risks)

    # Yarn 1 decoy: dependencies has git URL hidden behind devDependencies registry version
    yarn_dir = tmp_path / "yarn_case"
    _write(
        yarn_dir,
        "package.json",
        json.dumps(
            {
                "dependencies": {"openai": "git+https://evil.example/openai.git#main"},
                "devDependencies": {"openai": "4.0.0"},
            }
        ),
    )
    _write(
        yarn_dir,
        "yarn.lock",
        (
            "# yarn lockfile v1\n\n"
            "openai@4.0.0:\n"
            '  version "4.0.0"\n'
            '  resolved "https://registry.yarnpkg.com/openai/-/openai-4.0.0.tgz"\n'
            "  integrity sha512-" + "A" * 86 + "==\n"
        ),
    )
    res_yarn = RegistryScanner().scan(yarn_dir)
    yarn_comp = next(c for c in res_yarn.components if c.name == "openai")
    assert yarn_comp.package_url is None
    assert any(r.category == "nonregistry_source" for r in yarn_comp.risks)
    assert any("yarn.lock" in gap for gap in res_yarn.surfaces_excluded)


def test_r_low_03_docker_env_symlink_withheld(tmp_path: Path) -> None:
    _write(tmp_path, "id_rsa", "COMPOSE_FILE=evil.yml\n-----BEGIN PRIVATE KEY-----\n")
    os.symlink("id_rsa", tmp_path / ".env")
    res = RegistryScanner().scan(tmp_path)
    assert ".env" not in res.surfaces_scanned
    assert not any("COMPOSE_FILE" in g for g in res.surfaces_excluded)
    assert any("credential" in g.lower() or ".env" in g for g in res.surfaces_excluded)

    # Regular .env still works for COMPOSE_FILE detection.
    normal_dir = tmp_path / "normal"
    _write(normal_dir, ".env", "COMPOSE_FILE=custom.yml\n")
    res_ok = RegistryScanner().scan(normal_dir)
    assert ".env" in res_ok.surfaces_scanned
    assert ".env: COMPOSE_FILE not followed" in res_ok.surfaces_excluded


def test_r_med_14_registry_yaml_flow_depth_fast_reject(tmp_path: Path) -> None:
    deep = "[" * 2000 + "]" * 2000
    _write(tmp_path, "compose.yaml", f"services:\n  a:\n    x: {deep}\n")
    _write(tmp_path, "pnpm-workspace.yaml", f"packages: {deep}\n")
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"openai": "^4.0.0"}}))

    pnpm_dir = tmp_path / "pnpm_only"
    _write(pnpm_dir, "package.json", json.dumps({"dependencies": {"openai": "^4.0.0"}}))
    _write(pnpm_dir, "pnpm-lock.yaml", f"lockfileVersion: '9.0'\npackages: {deep}\n")

    res = RegistryScanner().scan(tmp_path)
    res_pnpm = RegistryScanner().scan(pnpm_dir)
    assert any("pnpm-workspace.yaml" in f for f in res.scan_failures)
    assert any("compose.yaml" in f for f in res.scan_failures)
    assert any("pnpm-lock.yaml" in f for f in res_pnpm.scan_failures)

    # Plain-scalar, block-scalar, apostrophe, and inline hash bypasses must all be caught.
    for payload in (
        'a: hello "world\nb: ' + "[" * 2000 + "]" * 2000 + "\n",
        'a: hello :"world\nb: ' + "[" * 2000 + "]" * 2000 + "\n",
        'a: hello -"world\nb: ' + "[" * 2000 + "]" * 2000 + "\n",
        'a: hello ?"world\nb: ' + "[" * 2000 + "]" * 2000 + "\n",
        'a: hello ,"world\nb: ' + "[" * 2000 + "]" * 2000 + "\n",
        'a: |\n  "hello\nb: ' + "[" * 2000 + "]" * 2000 + "\n",
        "a'b: " + "[" * 70 + "]" * 70,
        "a#b: " + "[" * 70 + "]" * 70,
    ):
        assert _flow_depth_exceeded(payload) is True
    assert _flow_depth_exceeded("key: # " + "[" * 70 + "]" * 70) is False
    assert _flow_depth_exceeded("k: 'a''b" + "[" * 70 + "'\n") is False
    assert _flow_depth_exceeded('k: "a\\"b' + "[" * 70 + '"\n') is False


# ---------------------------------------------------------------------------
# R-MED-05, R-MED-07, Muse E-332-1/2/3: sbom_import.py
# ---------------------------------------------------------------------------


def test_r_med_05_nested_npm_lock_hardening(tmp_path: Path) -> None:
    # 1. Enclosing .npmrc / package.json disables nested lock trust
    enc = tmp_path / "enclosing"
    _write(enc, ".npmrc", "registry=https://evil.example/\n")
    _write(enc, "sub/package.json", json.dumps({"dependencies": {"openai": "^4.0.0"}}))
    _write(
        enc,
        "sub/package-lock.json",
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"dependencies": {"openai": "^4.0.0"}},
                    "node_modules/openai": {"version": "4.8.2"},
                },
            }
        ),
    )
    comps, _ = walk_nested_manifests(enc)
    assert comps[0].properties["pinning_state"] == "manifest-only"

    # 2. inBundle / invalid integrity / non-registry resolved / prerelease / decoy devDep
    cases = [
        (
            "in_bundle",
            {"version": "4.8.2", "inBundle": True},
            {"dependencies": {"openai": "^4.0.0"}},
        ),
        (
            "bad_integrity",
            {"version": "4.8.2", "integrity": "md5-notvalid"},
            {"dependencies": {"openai": "^4.0.0"}},
        ),
        (
            "git_resolved",
            {"version": "4.8.2", "resolved": "git+https://evil.example/openai.git"},
            {"dependencies": {"openai": "^4.0.0"}},
        ),
        (
            "tarball_mismatch",
            {
                "version": "4.8.2",
                "resolved": "https://registry.npmjs.org/evil/-/evil-4.8.2.tgz",
            },
            {"dependencies": {"openai": "^4.0.0"}},
        ),
        (
            "prerelease",
            {"version": "4.8.2-rc.1"},
            {"dependencies": {"openai": "^4.0.0"}},
        ),
        (
            "decoy_dev",
            {"version": "4.8.2"},
            {
                "dependencies": {"openai": "git+https://evil.example/openai.git"},
                "devDependencies": {"openai": "^4.0.0"},
            },
        ),
    ]
    for case_name, record, pkg_doc in cases:
        cdir = tmp_path / case_name
        _write(cdir, "sub/package.json", json.dumps(pkg_doc))
        _write(
            cdir,
            "sub/package-lock.json",
            json.dumps(
                {
                    "lockfileVersion": 3,
                    "packages": {
                        "": pkg_doc,
                        "node_modules/openai": record,
                    },
                }
            ),
        )
        found, _ = walk_nested_manifests(cdir)
        assert found[0].properties["pinning_state"] != "locked", case_name


def test_r_med_07_nested_manifest_dedup_and_salted_bom_refs(tmp_path: Path) -> None:
    _write(
        tmp_path,
        "rust/Cargo.toml",
        (
            '[package]\nname = "app"\n'
            '[dependencies]\ncandle-core = "0.8"\n'
            '[dev-dependencies]\ncandle-core = "0.9"\n'
        ),
    )
    _write(
        tmp_path,
        "py/requirements.txt",
        "openai==1.50.0\nopenai==1.50.0\nopenai>=1.40.0\n",
    )
    comps, failures = walk_nested_manifests(tmp_path)
    assert not failures
    bom_refs = [c.bom_ref for c in comps]
    assert len(bom_refs) == len(set(bom_refs))
    cargo_comps = [c for c in comps if c.registry_type == "cargo"]
    assert len(cargo_comps) == 2
    py_comps = [c for c in comps if c.registry_type == "pypi"]
    assert len(py_comps) == 2


def test_muse_e_332_1_2_3_cargo_and_conda_fixes(tmp_path: Path) -> None:
    # E-332-1: Cargo.lock version-qualified dependency string resolves unique crate version
    _write(
        tmp_path,
        "sub/Cargo.toml",
        '[package]\nname = "worker"\n[dependencies]\ncandle-core = "=0.8"\n',
    )
    _write(
        tmp_path,
        "sub/Cargo.lock",
        (
            '[[package]]\nname = "worker"\ndependencies = ["candle-core 0.8.2"]\n'
            '[[package]]\nname = "candle-core"\nversion = "0.7.0"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
            '[[package]]\nname = "candle-core"\nversion = "0.8.2"\n'
            'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        ),
    )
    comps, failures = walk_nested_manifests(tmp_path)
    assert not failures
    assert len(comps) == 1
    assert comps[0].version == "0.8.2"
    assert comps[0].properties["pinning_state"] == "locked"

    # E-332-2: _cargo_lock_agrees supports =1 and =1.2 prefix equality
    assert _cargo_lock_agrees("=1.2", "1.2.5") is True
    assert _cargo_lock_agrees("=1.2", "1.3.0") is False
    assert _cargo_lock_agrees("=1", "1.9.4") is True
    assert _cargo_lock_agrees("=1", "2.0.0") is False
    assert _cargo_lock_agrees("=1.2.3", "1.2.3") is True
    assert _cargo_lock_agrees("=1.2.3", "1.2.4") is False

    # E-332-3: _conda_requirement parses bare version=build without leading '='
    parsed = _conda_requirement("1.2.3=py311_0")
    assert parsed is not None
    assert parsed[1] is True


# ---------------------------------------------------------------------------
# Follow-up audit of Bundle F1 (claims A-I): regressions and open findings
# ---------------------------------------------------------------------------

IMAGE = "alpine@sha256:" + "a" * 64
GIT_SOURCE = "git+https://evil.example/openai.git#main"
INTEGRITY = "sha512-" + "A" * 86 + "=="
CRATES_IO = 'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
CANDLE_RECORDS = (
    '[[package]]\nname = "candle-core"\nversion = "0.8.1"\n'
    + CRATES_IO
    + '[[package]]\nname = "candle-core"\nversion = "0.8.2"\n'
    + CRATES_IO
)
YARN_LOCK = (
    "# yarn lockfile v1\n\nopenai@4.0.0:\n"
    '  version "4.0.0"\n'
    '  resolved "https://registry.yarnpkg.com/openai/-/openai-4.0.0.tgz"\n'
    f"  integrity {INTEGRITY}\n"
)


def _mount(*args: str) -> tuple[str | None, set[str]]:
    res = analyze("docker", ["run", *args, IMAGE])
    flags = ("host_root_mount", "broad_host_mount", "runtime_socket_mount")
    return res.unknown, {flag for flag in flags if res.context.get(flag)}


def _pnpm_lock(section: str, spec: str) -> str:
    return (
        "lockfileVersion: '9.0'\nimporters:\n  .:\n"
        f"    {section}:\n      openai:\n        specifier: {spec}\n        version: 4.0.0\n"
        f"packages:\n  openai@4.0.0:\n    resolution: {{integrity: {INTEGRITY}, "
        "tarball: https://registry.npmjs.org/openai/-/openai-4.0.0.tgz}\n"
        "snapshots:\n  openai@4.0.0: {}\n"
    )


def _cargo_project(root: Path, dependencies: str, packages: str) -> list[Any]:
    _write(
        root, "sub/Cargo.toml", '[package]\nname = "worker"\n[dependencies]\ncandle-core = "0.8"\n'
    )
    _write(
        root,
        "sub/Cargo.lock",
        f'[[package]]\nname = "worker"\ndependencies = [{dependencies}]\n' + packages,
    )
    comps, failures = walk_nested_manifests(root)
    assert not failures
    return comps


def _nested_npm_state(
    root: Path, *, record: dict[str, Any] | None = None, manifest: dict[str, Any] | None = None
) -> str:
    manifest = manifest or {"dependencies": {"openai": "^4.0.0"}}
    record = record or {"version": "4.8.2"}
    _write(root, "sub/package.json", json.dumps(manifest))
    lock = {"lockfileVersion": 3, "packages": {"": manifest, "node_modules/openai": record}}
    _write(root, "sub/package-lock.json", json.dumps(lock))
    comps, _ = walk_nested_manifests(root)
    (comp,) = comps
    state = comp.properties["pinning_state"]
    assert isinstance(state, str)
    return state


@pytest.mark.parametrize(
    ("volume", "flags"),
    [
        ("${workspaceFolder}/:/w", set()),
        ("${workspaceFolder}/etc:/w", set()),
        ("${workspaceFolder}/run:/w", set()),
        ("${workspaceRoot}/:/w", set()),
        ("${PWD}/:/w", set()),
        ("${HOME}/:/w", {"broad_host_mount"}),
        ("${workspaceFolder}/../:/w", {"broad_host_mount"}),
        # An environment variable that may be unset still reads as the host root.
        ("${EMPTY}/:/w", {"host_root_mount"}),
        ("${X-/}:/w", {"host_root_mount"}),
    ],
)
def test_audit_a_directory_variables_never_expand_to_the_host_root(
    volume: str, flags: set[str]
) -> None:
    unknown, found = _mount("-v", volume)
    assert unknown is None
    assert found == flags


@pytest.mark.parametrize(
    "text", ["]" * 2000 + "[" * 2000 + "\n", "}" * 2000 + "{" * 2000 + "\n", "]\n"]
)
def test_audit_b_flow_end_outside_a_collection_is_refused(tmp_path: Path, text: str) -> None:
    import yaml

    with pytest.raises(yaml.YAMLError):
        for _ in yaml.scan(text, Loader=RegistryScanner._bounded_yaml_loader()):
            pass
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"openai": "^4.0.0"}}))
    _write(tmp_path, "pnpm-lock.yaml", text)
    res = RegistryScanner().scan(tmp_path)
    assert any("pnpm-lock.yaml" in failure for failure in res.scan_failures)


def test_audit_b_flow_end_runs_do_not_restore_the_quadratic_scan(tmp_path: Path) -> None:
    roots: dict[int, Path] = {}
    for scale in (1, 4):
        root = roots[scale] = tmp_path / str(scale)
        _write(root, "package.json", json.dumps({"dependencies": {"openai": "^4.0.0"}}))
        _write(root, "pnpm-lock.yaml", "]" * (500 * scale) + "[" * (500 * scale) + "\n")
    assert scaling_ratio(lambda scale: RegistryScanner().scan(roots[scale])) < 10


def test_audit_b_no_dead_depth_guard_remains() -> None:
    assert not hasattr(RegistryScanner, "_yaml_flow_depth_exceeded")


@pytest.mark.parametrize(
    "mount",
    [
        "type=${X:=bind},source=/,target=/host",
        "type=${X},source=/,target=/host",
        "type=${X:-bind},source=/,target=/host",
        "type=bind,${X:=source}=/,target=/host",
    ],
)
def test_audit_c_mount_type_or_field_substitution_is_unresolved(mount: str) -> None:
    unknown, _ = _mount("--mount", mount)
    assert unknown is not None and "unresolved" in unknown


def test_audit_c_unset_only_default_keeps_an_empty_value() -> None:
    # ${X-benign} keeps X when it is set, even to ""; only ${X:-benign} replaces "".
    unknown, flags = _mount("-v", "/${X-benign}:/host")
    assert unknown is None
    assert "host_root_mount" in flags
    unknown, flags = _mount("-v", "/${X:-benign}:/host")
    assert unknown is None
    assert "host_root_mount" not in flags


@pytest.mark.parametrize(
    ("manifest", "lock_name", "lock_text"),
    [
        (
            {"optionalDependencies": {"openai": "4.0.0"}, "dependencies": {"openai": GIT_SOURCE}},
            "pnpm-lock.yaml",
            _pnpm_lock("optionalDependencies", "4.0.0"),
        ),
        (
            {
                "optionalDependencies": {"openai": "4.0.0"},
                "dependencies": {"openai": "npm:evil@1.0.0"},
            },
            "pnpm-lock.yaml",
            _pnpm_lock("optionalDependencies", "4.0.0"),
        ),
        (
            {"peerDependencies": {"openai": GIT_SOURCE}, "dependencies": {"openai": "4.0.0"}},
            "yarn.lock",
            YARN_LOCK,
        ),
        (
            {"peerDependencies": {"openai": "npm:evil@1.0.0"}, "dependencies": {"openai": "4.0.0"}},
            "yarn.lock",
            YARN_LOCK,
        ),
    ],
)
def test_audit_d_conflicting_sections_bind_no_pnpm_or_yarn_record(
    tmp_path: Path, manifest: dict[str, Any], lock_name: str, lock_text: str
) -> None:
    _write(tmp_path, "package.json", json.dumps(manifest))
    _write(tmp_path, lock_name, lock_text)
    res = RegistryScanner().scan(tmp_path)
    (comp,) = [c for c in res.components if c.name == "openai"]
    assert comp.package_url is None
    assert "package_resolution" not in comp.claims
    assert comp.properties["collection_mode"] == "manifest-reference"
    assert any("conflicting dependency sources" in gap for gap in res.surfaces_excluded)


@pytest.mark.parametrize(
    ("lock_name", "lock_text"),
    [("pnpm-lock.yaml", _pnpm_lock("dependencies", "4.0.0")), ("yarn.lock", YARN_LOCK)],
)
def test_audit_d_one_section_still_binds_its_record(
    tmp_path: Path, lock_name: str, lock_text: str
) -> None:
    _write(tmp_path, "package.json", json.dumps({"dependencies": {"openai": "4.0.0"}}))
    _write(tmp_path, lock_name, lock_text)
    (comp,) = RegistryScanner().scan(tmp_path).components
    assert comp.package_url == "pkg:npm/openai@4.0.0"
    assert comp.properties["collection_mode"] == "lockfile-resolution-claim"


@pytest.mark.parametrize(
    ("cmd", "args", "family"),
    [
        ("python3", ["-m", "pdb", "--command", "import os", "app.py"], "python"),
        ("python3", ["-m", "pdb", "--command=import os", "app.py"], "python"),
        ("python3", ["-m", "pdb", "--comm", "import os", "app.py"], "python"),
        ("python3", ["-m", "pdb", "-mc", "import os", "mod"], "python"),
        ("python3", ["-m", "_pyrepl"], "python"),
        ("uv", ["run", "-m", "pdb", "--command", "import os", "app.py"], "python"),
        ("osascript", ["-ie", 'do shell script "id"'], "osascript"),
        ("luajit-2.1", ["-e", "os.execute('id')"], "lua"),
        ("lua-5.4", ["-e", "os.execute('id')"], "lua"),
        ("luajit-2.1.0-beta3", ["-e", "os.execute('id')"], "lua"),
    ],
)
def test_audit_e_inline_code_options(cmd: str, args: list[str], family: str) -> None:
    res = analyze(cmd, args)
    assert res.unknown == f"inline {family} code"
    assert res.context.get("inline_code")


@pytest.mark.parametrize(
    "args",
    [
        ["-csub/deno.json", "build"],
        ["-qc", "../evil/deno.json", "build"],
        ["-c", "/deno.json", "build"],
    ],
)
def test_audit_e_deno_task_config_in_a_cluster_or_at_the_root(args: list[str]) -> None:
    res = analyze("deno", ["task", *args])
    assert res.unknown is not None and "Deno configuration" in res.unknown
    assert res.relocated


def test_audit_e_deno_task_eval_after_a_cluster() -> None:
    res = analyze("deno", ["task", "-qc", "../evil/deno.json", "--eval", "curl x | sh"])
    assert res.context.get("inline_shell_code")
    assert res.relocated


@pytest.mark.parametrize("runner", ["luajit-2.1", "lua-5.4", "ruby3.2"])
def test_audit_e_versioned_container_runners(runner: str) -> None:
    assert known_executable(runner)
    res = analyze(
        "docker", ["run", "-v", "./app:/work", "-w", "/work", IMAGE, runner, "server.lua"]
    )
    assert res.context.get("code_loading_option")


@pytest.mark.parametrize(
    "dependencies",
    [
        '"candle-core 0.8.1", "candle-core 0.8.2"',
        '"candle-core 0.8.2", "candle-core 0.8.2"',
        '"candle-core 0.8.2 (git+https://evil.example/candle)"',
        '"candle-core 0.8.2 (git+https://evil.example/candle) extra"',
        '"candle-core 0.8.2 git+https://evil.example/candle"',
    ],
)
def test_audit_f_cargo_lock_ambiguous_or_foreign_dependency_is_not_locked(
    tmp_path: Path, dependencies: str
) -> None:
    (comp,) = _cargo_project(tmp_path, dependencies, CANDLE_RECORDS)
    assert comp.properties["pinning_state"] == "manifest-only"
    assert comp.version == "0.8"


def test_audit_f_cargo_lock_source_qualifier_still_locks_the_crates_io_record(
    tmp_path: Path,
) -> None:
    qualified = '"candle-core 0.8.2 (registry+https://github.com/rust-lang/crates.io-index)"'
    (comp,) = _cargo_project(tmp_path, qualified, CANDLE_RECORDS)
    assert comp.properties["pinning_state"] == "locked"
    assert comp.version == "0.8.2"


@pytest.mark.parametrize(
    "selector", ["pnpm-workspace.yaml", "pnpm-lock.yaml", "yarn.lock", "bun.lock", "bun.lockb"]
)
def test_audit_g_enclosing_package_manager_files_select_another_lock(
    tmp_path: Path, selector: str
) -> None:
    _write(tmp_path, selector, "")
    assert _nested_npm_state(tmp_path) == "manifest-only"


def test_audit_g_bundled_record_is_not_a_registry_artifact(tmp_path: Path) -> None:
    assert _nested_npm_state(tmp_path / "plain") == "locked"
    bundled = {"version": "4.8.2", "bundled": True}
    assert _nested_npm_state(tmp_path / "bundled", record=bundled) == "manifest-only"


def test_audit_g_unreadable_npmrc_symlink_withholds_the_nested_lock(tmp_path: Path) -> None:
    (tmp_path / "sub").mkdir()
    os.symlink("/etc/hostname", tmp_path / "sub" / ".npmrc")
    assert _nested_npm_state(tmp_path) == "manifest-only"


def test_audit_h_every_section_reports_its_alias_source_and_override(tmp_path: Path) -> None:
    # A second alias target is reported beside the one npm installs.
    aliases = tmp_path / "aliases"
    _write(
        aliases,
        "package.json",
        json.dumps(
            {
                "dependencies": {"helper": "npm:openai@4.0.0"},
                "devDependencies": {"helper": "npm:other-ai@1.0.0"},
            }
        ),
    )
    (comp,) = RegistryScanner().scan(aliases).components
    aliased = [r.detail for r in comp.risks if r.category == "package_alias"]
    assert any("'openai'" in detail for detail in aliased)
    assert any("'other-ai'" in detail for detail in aliased)

    # A registry spec in another section resolves through the project's .npmrc.
    redirected = tmp_path / "redirected"
    _write(
        redirected,
        "package.json",
        json.dumps(
            {"dependencies": {"openai": "4.0.0"}, "devDependencies": {"openai": GIT_SOURCE}}
        ),
    )
    _write(redirected, ".npmrc", "registry=https://evil.example/\n")
    (comp,) = RegistryScanner().scan(redirected).components
    assert {r.category for r in comp.risks} >= {"nonregistry_source", "registry_origin"}

    # Two git specs that read the same raise one finding, not two.
    twice = tmp_path / "twice"
    _write(
        twice,
        "package.json",
        json.dumps(
            {
                "dependencies": {"openai": GIT_SOURCE},
                "devDependencies": {"openai": "git+https://evil.example/openai.git#dev"},
            }
        ),
    )
    (comp,) = RegistryScanner().scan(twice).components
    assert len([r for r in comp.risks if r.category == "nonregistry_source"]) == 1

    # An override of the package another section's alias installs is a gap.
    overridden = tmp_path / "overridden"
    _write(
        overridden,
        "package.json",
        json.dumps(
            {
                "dependencies": {"helper": "npm:openai@4.0.0"},
                "devDependencies": {"helper": "1.0.0"},
                "overrides": {"openai": "3.0.0"},
            }
        ),
    )
    res = RegistryScanner().scan(overridden)
    assert any("override" in gap for gap in res.surfaces_excluded)


@pytest.mark.parametrize(
    "args", [["-m", "pdb", "app.py", "-cfg"], ["-m", "pdb", "app.py", "-c", "x"]]
)
def test_audit_i_pdb_options_end_at_the_script(args: list[str]) -> None:
    res = analyze("python3", args)
    assert res.unknown is None
    assert not res.context.get("inline_code")


@pytest.mark.parametrize(
    "volume", ["/app:/container/${X:=foo}", "/app:/${X:=foo}", "/app:/c:${X:=ro}"]
)
def test_audit_i_container_path_substitution_is_not_a_host_source(volume: str) -> None:
    unknown, flags = _mount("-v", volume)
    assert unknown is None
    assert not flags


def test_audit_i_uv_with_packages_survive_an_inline_failure() -> None:
    res = analyze("uv", ["run", "--with", "evil-pkg", "-m", "timeit", "import os"])
    assert res.unknown == "inline python code"
    assert [package.name for package in res.packages] == ["evil-pkg"]
