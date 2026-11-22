"""Positive and adversarial regression tests for Bundle F1:
R-HIGH-13, R-HIGH-14, R-MED-19(a) (mcp_launch.py);
R-HIGH-06, R-LOW-03, R-MED-14, Muse I-322-1 (registry.py);
R-MED-05, R-MED-07, Muse E-332-1, E-332-2, E-332-3 (sbom_import.py).
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from nexus_symbiote.sbom_import import (
    _cargo_lock_agrees,
    _conda_requirement,
    walk_nested_manifests,
)
from nexus_symbiote.scanners.mcp_launch import analyze, known_executable
from nexus_symbiote.scanners.registry import RegistryScanner


def _write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


# ---------------------------------------------------------------------------
# R-HIGH-13, R-HIGH-14, R-MED-19(a): mcp_launch.py
# ---------------------------------------------------------------------------


def test_r_high_13_container_volume_substitutions() -> None:
    # Non-leading unresolved ${...:...} substitutions fail closed.
    for vol in ("/${X:=/}:/host", "/var/run/${X:=/}docker.sock:/s"):
        res = analyze("docker", ["run", "-v", vol, "alpine@sha256:" + "a" * 64])
        assert res.unknown is not None
        assert "unresolved" in res.unknown

    mount_res = analyze(
        "docker",
        ["run", "--mount", "type=bind,source=/${X:=/},target=/host", "alpine@sha256:" + "a" * 64],
    )
    assert mount_res.unknown is not None

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

    start = time.monotonic()
    res = RegistryScanner().scan(tmp_path)
    res_pnpm = RegistryScanner().scan(pnpm_dir)
    elapsed = time.monotonic() - start
    assert elapsed < 2.0
    assert any("pnpm-workspace.yaml" in f for f in res.scan_failures)
    assert any("compose.yaml" in f for f in res.scan_failures)
    assert any("pnpm-lock.yaml" in f for f in res_pnpm.scan_failures)

    # Apostrophe / inline hash / quoted strings in YAML flow-depth check.
    assert RegistryScanner._yaml_flow_depth_exceeded("a'b: " + "[" * 70 + "]" * 70) is True
    assert RegistryScanner._yaml_flow_depth_exceeded("a#b: " + "[" * 70 + "]" * 70) is True
    assert RegistryScanner._yaml_flow_depth_exceeded("key: # " + "[" * 70 + "]" * 70) is False
    assert RegistryScanner._yaml_flow_depth_exceeded("k: 'a''b" + "[" * 70 + "'\n") is False
    assert RegistryScanner._yaml_flow_depth_exceeded('k: "a\\"b' + "[" * 70 + '"\n') is False


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
