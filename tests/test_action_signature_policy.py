"""The Action's signer policy is a caller-owned trust root, never checkout content."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest
import yaml

from tests.support import trust_anchor_in_layout

ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests/fixtures/sigstore-python"
SPEC = importlib.util.spec_from_file_location(
    "action_signature_policy_runner", ROOT / "scripts/run_action.py"
)
assert SPEC is not None and SPEC.loader is not None
runner = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = runner
SPEC.loader.exec_module(runner)

SUBJECT_SHA256 = "c4e92e9ecc828bef2aa7dba1de8ac983511f7532a0df11c770d39099a25cf201"
SIGNER = "https://github.com/trailofbits/rfc8785.py/.github/workflows/release.yml@refs/tags/v0.1.2"
ISSUER = "https://token.actions.githubusercontent.com"
UNTRUSTED = "No trusted artifact-bound signer policy was supplied"
# The signed stand-in is a wheel, so the model collector rates it as a ZIP archive.
STAND_IN_FORMAT = (
    "ZIP archive whose directory lists no pickle member; no bounded structural validator "
    "for this format/loader"
)


def policy_document(identity: str = SIGNER) -> str:
    record = {
        "artifact_path": "models/signed-model.onnx",
        "bundle_path": "models/signed-model.onnx.sigstore",
        "expected_identity": identity,
        "expected_issuer": ISSUER,
    }
    return json.dumps({"version": 1, "artifacts": [record]})


def test_action_passes_the_policy_only_as_data() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text())
    assert action["inputs"]["signature-policy"]["default"] == ""
    scan = next(step for step in action["runs"]["steps"] if step.get("id") == "scan")
    assert scan["env"]["SYMBIOTE_SIGNATURE_POLICY"] == "${{ inputs.signature-policy }}"
    assert "${{" not in scan["run"] and "signature" not in scan["run"]
    output = action["outputs"]["signature-policy-digest"]
    assert output["value"] == "${{ steps.scan.outputs.signature_policy_digest }}"


@pytest.mark.parametrize("foreign_runner_temp", [False, True])
def test_one_policy_snapshot_reaches_collection_validation_and_risk(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, foreign_runner_temp: bool
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = tmp_path / "caller" / "signers.json"
    policy.parent.mkdir()
    policy.write_text(policy_document())
    local_temp = tmp_path / "local-temp"
    local_temp.mkdir()
    monkeypatch.setattr(tempfile, "gettempdir", lambda: str(local_temp))
    if foreign_runner_temp:
        runner_temp = trust_anchor_in_layout(
            tmp_path, "foreign-owned grandparent", "runner-fixture", b"", monkeypatch
        ).parent
    else:
        runner_temp = tmp_path / "runner-temp"
        runner_temp.mkdir()
    config = runner.Config.from_env(
        {
            "GITHUB_WORKSPACE": str(workspace),
            "RUNNER_TEMP": str(runner_temp),
            "SYMBIOTE_SIGNATURE_POLICY": str(policy),
        }
    )
    policy.write_text(policy_document("https://attacker.invalid/replaced-after-validation"))
    calls: list[list[str]] = []
    seen: list[str] = []

    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if "--signature-policy" in args:
            snapshot = Path(args[args.index("--signature-policy") + 1])
            if os.name == "posix":
                assert snapshot.stat().st_mode & 0o077 == 0
            seen.append(snapshot.read_text())
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, '{"overall_score": 0}', "")

    outputs = tmp_path / "outputs"
    assert runner.run(config, command=command, outputs=outputs) == 0
    scan, validate, risk = calls
    assert [scan[0], validate[0], risk[0]] == ["scan", "validate", "risk"]
    assert scan.count("--signature-policy") == validate.count("--signature-policy") == 1
    assert scan.index("--signature-policy") < scan.index("--")
    snapshot = Path(scan[scan.index("--signature-policy") + 1])
    assert snapshot.is_relative_to((local_temp if foreign_runner_temp else runner_temp).resolve())
    assert validate[validate.index("--signature-policy") + 1] == str(snapshot)
    assert snapshot != policy and not snapshot.is_relative_to(workspace)
    assert not snapshot.exists()
    assert seen == [policy_document()] * 3
    assert risk[risk.index("--signature-policy") + 1] == str(snapshot)
    digest = hashlib.sha256(policy_document().encode()).hexdigest()
    assert f"signature_policy_digest=sha256:{digest}\n" in outputs.read_text()


def test_empty_policy_input_supplies_no_trust_root(tmp_path: Path) -> None:
    config = runner.Config.from_env(
        {"GITHUB_WORKSPACE": str(tmp_path), "SYMBIOTE_SIGNATURE_POLICY": ""}
    )
    calls: list[list[str]] = []

    def command(args: list[str]) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        if args[0] == "scan":
            Path(args[args.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, '{"overall_score": 0}', "")

    outputs = tmp_path / "outputs"
    assert runner.run(config, command=command, outputs=outputs) == 0
    assert len(calls) == 3 and all("--signature-policy" not in args for args in calls)
    # The output is declared, so it is written, and empty, before collection starts.
    digests = [line for line in outputs.read_text().splitlines() if "signature_policy" in line]
    assert digests == ["signature_policy_digest="]


OUTSIDE = "outside GITHUB_WORKSPACE"
NOT_REGULAR = "regular file reached without symlinks"


def _relative(tmp_path: Path, workspace: Path) -> str:
    return "signers.json"


def _in_workspace(tmp_path: Path, workspace: Path) -> str:
    return str(workspace / "signers.json")


def _in_scan_path(tmp_path: Path, workspace: Path) -> str:
    return str(workspace / "agent" / "signers.json")


def _dot_dot_into_workspace(tmp_path: Path, workspace: Path) -> str:
    return f"{tmp_path}/caller/../workspace/signers.json"


def _case_alias_of_workspace(tmp_path: Path, workspace: Path) -> str:
    alias = workspace.with_name(workspace.name.upper())
    if not alias.exists():
        pytest.skip("the file system is case-sensitive, so the alias does not exist")
    return str(alias / "signers.json")


def _double_slash_alias_of_workspace(tmp_path: Path, workspace: Path) -> str:
    return f"/{workspace}/signers.json"


def _newline(tmp_path: Path, workspace: Path) -> str:
    return f"{tmp_path}/caller/signers.json\nSYMBIOTE_VALIDATE=false"


def _nul(tmp_path: Path, workspace: Path) -> str:
    return f"{tmp_path}/caller/signers.json\x00"


def _symlink_into_workspace(tmp_path: Path, workspace: Path) -> str:
    link = tmp_path / "caller" / "link.json"
    link.symlink_to(workspace / "signers.json")
    return str(link)


def _symlink_to_caller_file(tmp_path: Path, workspace: Path) -> str:
    link = tmp_path / "caller" / "link.json"
    link.symlink_to(tmp_path / "caller" / "signers.json")
    return str(link)


def _parent_symlink_into_workspace(tmp_path: Path, workspace: Path) -> str:
    (tmp_path / "alias").symlink_to(workspace, target_is_directory=True)
    return str(tmp_path / "alias" / "signers.json")


def _hard_link_to_workspace_file(tmp_path: Path, workspace: Path) -> str:
    link = tmp_path / "caller" / "hardlink.json"
    os.link(workspace / "signers.json", link)
    return str(link)


def _directory(tmp_path: Path, workspace: Path) -> str:
    return str(tmp_path / "caller")


def _missing(tmp_path: Path, workspace: Path) -> str:
    return str(tmp_path / "caller" / "missing.json")


def _fifo(tmp_path: Path, workspace: Path) -> str:
    if not hasattr(os, "mkfifo"):
        pytest.skip("named pipes are unavailable")
    os.mkfifo(tmp_path / "caller" / "pipe.json")
    return str(tmp_path / "caller" / "pipe.json")


def _oversized(tmp_path: Path, workspace: Path) -> str:
    from nexus_symbiote.signature_policy import MAX_POLICY_BYTES

    big = tmp_path / "caller" / "big.json"
    big.write_bytes(b" " * (MAX_POLICY_BYTES + 1))
    return str(big)


@pytest.mark.parametrize(
    "build,message",
    [
        (_relative, OUTSIDE),
        (_in_workspace, OUTSIDE),
        (_in_scan_path, OUTSIDE),
        (_dot_dot_into_workspace, OUTSIDE),
        (_case_alias_of_workspace, OUTSIDE),
        (_double_slash_alias_of_workspace, OUTSIDE),
        (_newline, OUTSIDE),
        (_nul, OUTSIDE),
        (_symlink_into_workspace, NOT_REGULAR),
        (_symlink_to_caller_file, NOT_REGULAR),
        (_parent_symlink_into_workspace, NOT_REGULAR),
        (_hard_link_to_workspace_file, "must not be a hard link"),
        (_directory, NOT_REGULAR),
        (_missing, NOT_REGULAR),
        (_fifo, NOT_REGULAR),
        (_oversized, "byte limit"),
    ],
)
def test_signature_policy_must_be_a_caller_owned_regular_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, build, message: str
) -> None:
    workspace = tmp_path / "workspace"
    (workspace / "agent").mkdir(parents=True)
    (tmp_path / "caller").mkdir()
    for path in [
        tmp_path / "signers.json",
        tmp_path / "caller" / "signers.json",
        workspace / "signers.json",
        workspace / "agent" / "signers.json",
    ]:
        path.write_text(policy_document())
    monkeypatch.chdir(tmp_path)
    value = build(tmp_path, workspace)
    with pytest.raises(ValueError, match=message):
        runner.Config.from_env(
            {
                "GITHUB_WORKSPACE": str(workspace),
                "SYMBIOTE_SCAN_PATH": "agent",
                "SYMBIOTE_SIGNATURE_POLICY": value,
            }
        )


def _signed_workspace(tmp_path: Path) -> Path:
    subject = (FIXTURES / "rfc8785-0.1.2-py3-none-any.whl.subject").read_bytes()
    assert hashlib.sha256(subject).hexdigest() == SUBJECT_SHA256
    workspace = tmp_path / "workspace"
    models = workspace / "agent" / "models"
    models.mkdir(parents=True)
    (models / "signed-model.onnx").write_bytes(subject)
    shutil.copyfile(
        FIXTURES / "bundle_v3_github.whl.sigstore", models / "signed-model.onnx.sigstore"
    )
    return workspace


def _caller_policy(tmp_path: Path, identity: str = SIGNER) -> Path:
    policy = tmp_path / "caller" / "signers.json"
    policy.parent.mkdir(exist_ok=True)
    policy.write_text(policy_document(identity))
    return policy


@pytest.mark.skipif(os.name != "posix", reason="POSIX trust-anchor permissions")
def test_the_action_rejects_a_group_writable_original_policy(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    policy = _caller_policy(tmp_path)
    policy.chmod(0o664)
    with pytest.raises(runner.InputError, match="group- or world-writable"):
        runner.Config.from_env(
            {"GITHUB_WORKSPACE": str(workspace), "SYMBIOTE_SIGNATURE_POLICY": str(policy)}
        )


def _entry_point(
    tmp_path: Path,
    workspace: Path,
    policy: Path | None,
    *,
    launcher: tuple[str, ...] = (),
    **overrides: str,
) -> subprocess.CompletedProcess[str]:
    env = {
        **os.environ,
        "HOME": str(tmp_path / "home"),
        "GITHUB_WORKSPACE": str(workspace),
        "SYMBIOTE_SCAN_PATH": "agent",
        "SYMBIOTE_SCANNERS": "",
        "SYMBIOTE_FORMAT": "json",
        "SYMBIOTE_VALIDATE": "true",
        "SYMBIOTE_RISK_CHECK": "false",
        "SYMBIOTE_RISK_THRESHOLD": "50",
        "SYMBIOTE_SARIF": "false",
        "SYMBIOTE_OUTPUT_FILE": "result.json",
        "SYMBIOTE_SIGNATURE_POLICY": "" if policy is None else str(policy),
        "GITHUB_OUTPUT": str(tmp_path / "action-outputs"),
        **overrides,
    }
    return subprocess.run(  # noqa: S603
        [sys.executable, "-I", *launcher, str(ROOT / "scripts/run_action.py")],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def _model(native: Path) -> dict:
    [model] = [
        c for c in json.loads(native.read_text())["components"] if c["component_type"] == "model"
    ]
    return model


@pytest.mark.parametrize("mode", ["none", "caller", "wrong-signer", "checkout"])
def test_real_entry_point_verifies_signed_model_only_with_caller_policy(
    tmp_path: Path, mode: str
) -> None:
    pytest.importorskip("sigstore")
    workspace = _signed_workspace(tmp_path)
    policy: Path | None = None
    if mode == "caller":
        policy = _caller_policy(tmp_path)
    elif mode == "wrong-signer":
        policy = _caller_policy(tmp_path, SIGNER.replace("v0.1.2", "v9.9.9"))
    elif mode == "checkout":
        policy = workspace / "agent" / "signers.json"
        policy.write_text(policy_document())
    outputs = tmp_path / "action-outputs"
    result = _entry_point(tmp_path, workspace, policy)
    # The stand-in subject is a wheel, so its format stays unknown even when
    # its signature verifies; only a signed SafeTensors model can pass fully.
    assert result.returncode == 1
    if mode == "checkout":
        assert "signature-policy must be an absolute path outside GITHUB_WORKSPACE" in (
            result.stderr
        )
        assert not (workspace / "result.json").exists()
        assert not outputs.exists()
        return
    # The Action relays the CLI's report lines behind a fixed "| " prefix.
    relayed = [
        line.removeprefix(runner.RELAY_PREFIX).strip() for line in result.stderr.splitlines()
    ]
    findings = [line for line in relayed if line.startswith(("UNKNOWN [", "ERROR [", "CRITICAL ["))]
    model = _model(workspace / "result.json")
    recorded = outputs.read_text()
    if mode == "none":
        assert f"UNKNOWN [{model['bom_ref']}] {UNTRUSTED}" in findings
        assert model["signing_status"] != "sigstore-signed"
        assert "signing_identity" not in model
        assert "signature_policy_digest=sha256:" not in recorded
    elif mode == "caller":
        assert policy is not None
        assert findings == [f"UNKNOWN [{model['bom_ref']}] {STAND_IN_FORMAT}"]
        assert "Hashes verified: 1, failed: 0" in result.stderr
        assert model["signing_status"] == "sigstore-signed"
        assert model["signing_identity"] == SIGNER
        digest = hashlib.sha256(policy.read_bytes()).hexdigest()
        assert f"signature_policy_digest=sha256:{digest}\n" in recorded
    else:
        stand_in, rejected = findings
        assert stand_in == f"UNKNOWN [{model['bom_ref']}] {STAND_IN_FORMAT}"
        assert rejected.startswith(
            f"ERROR [{model['bom_ref']}] Sigstore artifact verification failed"
        )
        assert model["signing_status"] == "verification-failed"
        assert "signing_identity" not in model


def test_policy_without_importable_sigstore_fails_before_collection(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = _signed_workspace(tmp_path)
    policy = _caller_policy(tmp_path)
    with monkeypatch.context() as patched:
        for module in runner.SIGSTORE_MODULES:
            patched.setitem(sys.modules, module, None)
        with pytest.raises(ValueError, match="signature-policy needs sigstore"):
            runner.Config.from_env(
                {"GITHUB_WORKSPACE": str(workspace), "SYMBIOTE_SIGNATURE_POLICY": str(policy)}
            )
        assert runner.Config.from_env({"GITHUB_WORKSPACE": str(workspace)}).signature_policy is None
    blocked = "import runpy, sys; sys.modules.update(sigstore=None, sigstore_models=None); "
    result = _entry_point(
        tmp_path,
        workspace,
        policy,
        launcher=("-c", blocked + "runpy.run_path(sys.argv[1], run_name='__main__')"),
    )
    assert result.returncode == 1
    assert "signature-policy needs sigstore, which this Action runtime cannot import" in (
        result.stderr
    )
    assert not (workspace / "result.json").exists()
    assert not (tmp_path / "action-outputs").exists()


def test_cli_runs_with_an_empty_private_sigstore_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    planted = {
        "HOME": str(tmp_path / "runner-home"),
        "XDG_CACHE_HOME": str(tmp_path / "runner-cache"),
        "XDG_DATA_HOME": str(tmp_path / "runner-data"),
    }
    for name, value in {**planted, "SYMBIOTE_INHERITED_PROBE": "kept"}.items():
        monkeypatch.setenv(name, value)
    homes: list[dict[str, str]] = []

    def invoke(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        env = kwargs["env"]
        assert isinstance(env, dict) and env["SYMBIOTE_INHERITED_PROBE"] == "kept"
        homes.append({name: env[name] for name in planted})
        assert not any(Path(env["HOME"]).iterdir())
        cli = args[args.index("nexus_symbiote") + 1 :]
        if cli[0] == "scan":
            Path(cli[cli.index("--output") + 1]).write_text("{}")
        return subprocess.CompletedProcess(args, 0, '{"overall_score": 0}', "")

    monkeypatch.setattr(runner.subprocess, "run", invoke)
    config = runner.Config.from_env({"GITHUB_WORKSPACE": str(workspace)})
    assert runner.run(config, export=lambda native, output, fmt: None) == 0
    assert len(homes) == 3 and homes.count(homes[0]) == 3
    private = Path(homes[0]["HOME"])
    assert private.parent.name.startswith("nexus-symbiote-action-")
    assert Path(homes[0]["XDG_CACHE_HOME"]).parent == private
    assert Path(homes[0]["XDG_DATA_HOME"]).parent == private
    assert not private.exists()


HOSTILE_TRUSTED_ROOT = {
    "mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1",
    "tlogs": [],
    "certificateAuthorities": [],
    "ctlogs": [],
    "timestampAuthorities": [],
}
TUF_TARGETS = "sigstore-python/tuf/https%3A%2F%2Ftuf-repo-cdn.sigstore.dev/trusted_root.json"


def test_planted_sigstore_cache_cannot_choose_the_trust_root(tmp_path: Path) -> None:
    pytest.importorskip("sigstore")
    workspace = _signed_workspace(tmp_path)
    policy = _caller_policy(tmp_path)
    home = tmp_path / "planted-home"
    planted = {
        "HOME": str(home),
        "XDG_CACHE_HOME": str(home / "xdg-cache"),
        "XDG_DATA_HOME": str(home / "xdg-data"),
    }
    for cache in ("xdg-cache", ".cache", "Library/Caches"):
        root = home / cache / TUF_TARGETS
        root.parent.mkdir(parents=True)
        root.write_text(json.dumps(HOSTILE_TRUSTED_ROOT))
    direct = subprocess.run(  # noqa: S603
        [
            *(sys.executable, "-I", "-m", "nexus_symbiote", "scan", "--no-project-policy"),
            *("--report-only", "--format", "json", "--output", str(tmp_path / "direct.json")),
            *("--signature-policy", str(policy), "--", str(workspace / "agent")),
        ],
        cwd=tmp_path,
        env={**os.environ, **planted},
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    # Control: the CLI on its own takes its offline trust root from that cache.
    assert direct.returncode == 0, direct.stderr
    assert _model(tmp_path / "direct.json")["signing_status"] == "verification-failed"
    result = _entry_point(tmp_path, workspace, policy, **planted)
    assert "Sigstore artifact verification failed" not in result.stderr
    assert "Hashes verified: 1, failed: 0" in result.stderr
    model = _model(workspace / "result.json")
    assert model["signing_status"] == "sigstore-signed"
    assert model["signing_identity"] == SIGNER


def test_entry_point_reaches_its_scratch_without_symlinks(tmp_path: Path) -> None:
    pytest.importorskip("sigstore")
    workspace = _signed_workspace(tmp_path)
    policy = _caller_policy(tmp_path)
    real = tmp_path / "real-tmp"
    real.mkdir()
    (tmp_path / "linked-tmp").symlink_to(real, target_is_directory=True)
    result = _entry_point(tmp_path, workspace, policy, TMPDIR=str(tmp_path / "linked-tmp"))
    assert "symbolic link" not in result.stderr
    assert "Selected signature policy is unavailable" not in result.stderr
    assert _model(workspace / "result.json")["signing_status"] == "sigstore-signed"
    assert not any(real.iterdir())


@pytest.mark.parametrize("runner_temp", [True, False])
def test_policy_snapshot_lives_in_runner_temp_when_tmpdir_is_in_the_checkout(
    tmp_path: Path, runner_temp: bool
) -> None:
    pytest.importorskip("sigstore")
    workspace = _signed_workspace(tmp_path)
    (workspace / ".git").mkdir()
    checkout_tmp = workspace / "tmp"
    checkout_tmp.mkdir()
    overrides = {"TMPDIR": str(checkout_tmp), "RUNNER_TEMP": ""}
    if runner_temp:
        (tmp_path / "runner-temp").mkdir()
        overrides["RUNNER_TEMP"] = str(tmp_path / "runner-temp")
    result = _entry_point(tmp_path, workspace, _caller_policy(tmp_path), **overrides)
    inventory = workspace / "result.json"
    assert inventory.is_file(), result.stderr
    model = _model(inventory)
    assert model["signing_status"] == "sigstore-signed"
    assert model["signing_identity"] == SIGNER
    if runner_temp:
        assert not any((tmp_path / "runner-temp").iterdir())
    assert not any(checkout_tmp.iterdir())


def test_runner_temp_must_be_an_existing_absolute_directory(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    base = {"GITHUB_WORKSPACE": str(workspace)}
    assert runner.Config.from_env(base).scratch_parent is None
    for value in ("relative", str(tmp_path / "missing")):
        assert runner.Config.from_env({**base, "RUNNER_TEMP": value}).scratch_parent is None
    assert runner.Config.from_env({**base, "RUNNER_TEMP": str(tmp_path)}).scratch_parent == (
        tmp_path
    )
