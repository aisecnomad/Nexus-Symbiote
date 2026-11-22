"""Regression tests for Bundle G: trust anchors, policy export, live teardown, and schema bounds."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import click
import pytest
from click.testing import CliRunner

from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.live import pinned_process
from nexus_symbiote.live import session as session_module
from nexus_symbiote.live.pinned_process import PinnedProcessError
from nexus_symbiote.live.session import PinnedStdioSession
from nexus_symbiote.policy import Policy, RiskPolicy, ScanPolicy, ValidatePolicy
from nexus_symbiote.runtime import AuthorizationError
from nexus_symbiote.runtime_cli import _check_key_placement, _verify_outside_checkout
from nexus_symbiote.utils import crypto as crypto_mod
from nexus_symbiote.vex_decisions import VEXDecisionError, _check_operator_directory
from scripts import run_action, verify_staged_policy
from tests.test_pinned_session_outcomes import launcher as make_launcher
from tests.test_runtime_validation_in_process import dialects as dialects

# --- R-HIGH-05: export-policy and crosswalk --accept-default-exclude(s) ---


def test_export_policy_and_crosswalk_accept_default_excludes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    git_dir = project / ".git"
    git_dir.mkdir()
    (git_dir / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
    (project / "CLAUDE.md").write_text("# Sample agent instructions\n", encoding="utf-8")

    monkeypatch.setenv("NEXUS_SYMBIOTE_SOURCE_BINDING_KEY", "k" * 32)
    inventory = tmp_path / "inv.json"
    runner = CliRunner()

    scanned = runner.invoke(
        main,
        [
            "scan",
            "--no-project-policy",
            "--accept-default-exclude",
            "root:.git",
            "--format",
            "json",
            "-o",
            str(inventory),
            str(project),
        ],
    )
    assert scanned.exit_code == 0, scanned.output

    # Without acceptance flags, reconciliation fails on the non-empty .git directory.
    ep_fail = runner.invoke(main, ["export-policy", str(inventory), "--project", str(project)])
    assert ep_fail.exit_code != 0

    # Named and blanket default-exclusion acceptance both succeed on export-policy.
    ep_named = runner.invoke(
        main,
        [
            "export-policy",
            str(inventory),
            "--project",
            str(project),
            "--accept-default-exclude",
            "root:.git",
        ],
    )
    assert ep_named.exit_code == 0, ep_named.output

    ep_all = runner.invoke(
        main,
        ["export-policy", str(inventory), "--project", str(project), "--accept-default-excludes"],
    )
    assert ep_all.exit_code == 0, ep_all.output

    # UsageError when acceptance flags are passed without --project.
    ep_usage = runner.invoke(
        main, ["export-policy", str(inventory), "--include-declared", "--accept-default-excludes"]
    )
    assert ep_usage.exit_code == 2
    assert "require --project" in ep_usage.output

    # crosswalk --include-evidence-pack --project obeys the same acceptance flags.
    cw_fail = runner.invoke(
        main, ["crosswalk", str(inventory), "--include-evidence-pack", "--project", str(project)]
    )
    assert cw_fail.exit_code != 0

    cw_named = runner.invoke(
        main,
        [
            "crosswalk",
            str(inventory),
            "--include-evidence-pack",
            "--project",
            str(project),
            "--accept-default-exclude",
            "root:.git",
        ],
    )
    assert cw_named.exit_code == 0, cw_named.output
    assert (
        json.loads(cw_named.output)["evidence_pack"]["verification_basis"] == "project-reconciled"
    )

    cw_all = runner.invoke(
        main,
        [
            "crosswalk",
            str(inventory),
            "--include-evidence-pack",
            "--project",
            str(project),
            "--accept-default-excludes",
        ],
    )
    assert cw_all.exit_code == 0, cw_all.output

    cw_usage = runner.invoke(
        main, ["crosswalk", str(inventory), "--include-evidence-pack", "--accept-default-excludes"]
    )
    assert cw_usage.exit_code == 2
    assert "require --project" in cw_usage.output


# --- R-HIGH-18: OMS DSSE resource name normalization and relative path derivation ---


def test_verify_oms_statement_preserves_dotfiles_and_rejects_traversal() -> None:
    digest = "a" * 64
    statement = json.dumps(
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicateType": next(iter(crypto_mod.OMS_PREDICATE_TYPES)),
            "subject": [{"name": "model", "digest": {"sha256": "b" * 64}}],
            "predicate": {
                "resources": [
                    {"name": ".weights.safetensors", "algorithm": "sha256", "digest": digest},
                    {"name": "sub/weights.safetensors", "algorithm": "sha256", "digest": digest},
                ]
            },
        }
    ).encode("utf-8")

    # Exact dotfile and ./-prefixed dotfile match cleanly.
    assert (
        crypto_mod._verify_oms_statement(
            "application/vnd.in-toto+json", statement, digest, artifact_name=".weights.safetensors"
        )
        is None
    )
    assert (
        crypto_mod._verify_oms_statement(
            "application/vnd.in-toto+json",
            statement,
            digest,
            artifact_name="././.weights.safetensors",
        )
        is None
    )
    # Parent traversal and absolute paths must be refused rather than stripped by lstrip("./").
    for bad in ("../.weights.safetensors", "/.weights.safetensors", "/sub/weights.safetensors"):
        err = crypto_mod._verify_oms_statement(
            "application/vnd.in-toto+json", statement, digest, artifact_name=bad
        )
        assert err is not None and "invalid" in err.lower(), bad


def test_verify_sigstore_bundle_derives_relative_oms_artifact_name(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    model_dir = tmp_path / "model"
    sub_a = model_dir / "sub_a"
    sub_a.mkdir(parents=True)
    artifact = sub_a / "weights.safetensors"
    artifact.write_bytes(b"weights-a")
    bundle = model_dir / "model.sig"
    bundle.write_bytes(b'{"dsseEnvelope": {}}')

    captured: list[str | None] = []

    def fake_verify_digest(
        digest_hex: str, bundle_json: bytes, identity: str, issuer: str, **kwargs: object
    ) -> crypto_mod.VerificationResult:
        captured.append(kwargs.get("artifact_name"))  # type: ignore[arg-type]
        return crypto_mod.VerificationResult(True, identity=identity, issuer=issuer)

    monkeypatch.setattr(crypto_mod, "verify_sigstore_digest", fake_verify_digest)
    res = crypto_mod.verify_sigstore_bundle(
        artifact,
        bundle,
        "signer@example.test",
        "https://issuer.example.test",
        allow_oms_dsse=True,
    )
    assert res.verified
    assert captured == ["sub_a/weights.safetensors"]

    # Explicit artifact_name override takes precedence.
    captured.clear()
    res_explicit = crypto_mod.verify_sigstore_bundle(
        artifact,
        bundle,
        "signer@example.test",
        "https://issuer.example.test",
        allow_oms_dsse=True,
        artifact_name="custom/weights.safetensors",
    )
    assert res_explicit.verified
    assert captured == ["custom/weights.safetensors"]

    # Bundle in an unrelated sibling directory falls back cleanly without crashing.
    other = tmp_path / "sigs"
    other.mkdir()
    other_bundle = other / "model.sig"
    other_bundle.write_bytes(b'{"dsseEnvelope": {}}')
    captured.clear()
    res_other = crypto_mod.verify_sigstore_bundle(
        artifact,
        other_bundle,
        "signer@example.test",
        "https://issuer.example.test",
        allow_oms_dsse=True,
    )
    assert res_other.verified
    assert captured == ["weights.safetensors"]


# --- R-MED-02, R-CQ-01, R-344-01: unified ancestor & placement checks ---


def test_ancestor_error_rejects_non_sticky_group_writable_ancestor(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root bypasses mode checks")
    group_dir = tmp_path / "shared"
    leaf = group_dir / "cache"
    leaf.mkdir(parents=True)
    group_dir.chmod(0o775)
    try:
        err = crypto_mod._ancestor_error(leaf, dir_what="Cache dir", remedy="make private")
        assert err is not None and "group- or world-writable" in err
        group_dir.chmod(0o1775)
        assert crypto_mod._ancestor_error(leaf, dir_what="Cache dir", remedy="make private") is None
    finally:
        group_dir.chmod(0o700)


def test_trust_anchor_error_accepts_traverse_only_ancestor(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores mode 0o111")
    locked = tmp_path / "outer"
    inner = locked / "inner"
    inner.mkdir(parents=True)
    anchor = inner / "key.pem"
    anchor.write_text("pem", encoding="utf-8")
    anchor.chmod(0o600)
    info = anchor.stat()
    locked.chmod(0o111)
    try:
        assert crypto_mod._trust_anchor_error(anchor, info) is None
    finally:
        locked.chmod(0o700)


def test_vex_operator_directory_rejects_uninspectable_and_normalizes_darwin_root(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    missing_parent = tmp_path / "does_not_exist" / "decisions.json"
    with pytest.raises(VEXDecisionError, match="Cannot safely read operator material ancestor"):
        _check_operator_directory(missing_parent, {0, os.geteuid()})

    # Verify darwin /var -> /private/var normalization flows through _check_trusted_ancestors.
    monkeypatch.setattr(crypto_mod.sys, "platform", "darwin")
    monkeypatch.setattr(os.path, "islink", lambda p: p == "/var")
    monkeypatch.setattr(os, "readlink", lambda p: "private/var" if p == "/var" else "")
    normalized = crypto_mod._absolute_through_root_links(Path("/var/folders/xx/decisions.json"))
    assert normalized == Path("/private/var/folders/xx/decisions.json")


def test_runtime_cli_placement_helpers_share_checks(tmp_path: Path) -> None:
    checkout = tmp_path / "repo"
    checkout.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    good_file = outside / "policy.yaml"
    good_file.write_text("version: '1.0'\n", encoding="utf-8")
    inside_file = checkout / "inside.yaml"
    inside_file.write_text("version: '1.0'\n", encoding="utf-8")

    _verify_outside_checkout(good_file, (checkout,), label="--operator-policy")
    _check_key_placement((good_file,), (checkout,), option="--trusted-key", holders="PROJECT")

    linked = outside / "linked.yaml"
    os.link(good_file, linked)

    with pytest.raises(click.UsageError, match="must lie outside"):
        _verify_outside_checkout(inside_file, (checkout,), label="--operator-policy")
    with pytest.raises(click.UsageError, match="multiple hard links"):
        _verify_outside_checkout(linked, (checkout,), label="--operator-policy")
    with pytest.raises(click.UsageError, match="other hard links"):
        _check_key_placement((linked,), (checkout,), option="--trusted-key", holders="PROJECT")
    with pytest.raises(click.UsageError, match="cannot be inspected"):
        _verify_outside_checkout(outside / "missing.yaml", (checkout,), label="--operator-policy")
    with pytest.raises(click.UsageError, match="cannot be inspected"):
        _check_key_placement(
            (outside / "missing.yaml",), (checkout,), option="--trusted-key", holders="PROJECT"
        )


# --- R-CQ-04: verify_staged_policy.clamp_operator_floor delegates to narrow_policy ---


def test_clamp_operator_floor_delegates_to_narrow_policy() -> None:
    op = Policy(
        scan=ScanPolicy(failure_mode="error", exclude_paths=["node_modules", ".git"]),
        risk=RiskPolicy(fail_threshold=30.0, warn_threshold=15.0, fail_on_severity="high"),
        validate=ValidatePolicy(minimum_assurance_level="observed"),
    )
    proj_weakening = Policy(
        scan=ScanPolicy(
            scanners=["mcp"],
            failure_mode="report-only",
            exclude_paths=["node_modules", ".git", "secret_dir"],
        ),
        risk=RiskPolicy(fail_threshold=90.0, warn_threshold=80.0, fail_on_severity="none"),
        validate=ValidatePolicy(
            require_completeness=False, require_integrity=False, minimum_assurance_level="declared"
        ),
    )
    clamped = verify_staged_policy.clamp_operator_floor(op, proj_weakening)
    assert clamped.scan.failure_mode == "error"
    assert "secret_dir" not in clamped.scan.exclude_paths
    assert len(clamped.scan.scanners) == len(op.scan.scanners)
    assert clamped.risk.fail_threshold == 30.0
    assert clamped.risk.fail_on_severity == "high"
    assert clamped.validation.minimum_assurance_level == "observed"
    assert verify_staged_policy.clamp_operator_floor(op, None) == op


# --- R-HIGH-27: run_action.py trust_anchor=True and verifier key snapshots ---


def test_run_action_enforces_trust_anchor_and_snapshots_trusted_keys(tmp_path: Path) -> None:
    if os.geteuid() == 0:
        pytest.skip("root ignores mode bits")
    workspace = tmp_path / "ws"
    workspace.mkdir()
    outside = tmp_path / "op"
    outside.mkdir(mode=0o700)
    baseline = outside / "baseline.json"
    baseline.write_text(AIBOM().to_native_json(), encoding="utf-8")
    baseline.chmod(0o600)
    att = outside / "baseline.att.json"
    att.write_text("{}", encoding="utf-8")
    att.chmod(0o600)
    key = outside / "trusted.pub"
    key.write_bytes(b"ORIGINAL-KEY-BYTES")
    key.chmod(0o600)

    base_env = {
        "GITHUB_WORKSPACE": str(workspace),
        "SYMBIOTE_REVIEWED_BASELINE": str(baseline),
        "SYMBIOTE_REVIEWED_BASELINE_ATTESTATION": str(att),
        "SYMBIOTE_TRUSTED_KEYS": str(key),
        "SYMBIOTE_SOURCE_BINDING_KEY": "s" * 32,
        "SYMBIOTE_VALIDATE": "false",
        "SYMBIOTE_RISK_CHECK": "false",
    }

    # Each trust anchor rejects group-writable mode 0o660.
    for path, field_name in (
        (baseline, "reviewed-baseline"),
        (att, "reviewed-baseline-attestation"),
        (key, "trusted-keys"),
    ):
        path.chmod(0o660)
        try:
            with pytest.raises(run_action.InputError, match=field_name):
                run_action.Config.from_env(base_env)
        finally:
            path.chmod(0o600)

    config = run_action.Config.from_env(base_env)
    assert config.trusted_verifier_contents == (b"ORIGINAL-KEY-BYTES",)

    # Mutate external key file after Config.from_env; verify-attestation must read snapshot bytes.
    key.write_bytes(b"TAMPERED-KEY-BYTES")
    seen_key_bytes: list[bytes] = []

    def fake_command(args: list[str]) -> subprocess.CompletedProcess[str]:
        if args[0] == "scan":
            out_idx = args.index("--output") + 1
            Path(args[out_idx]).write_text(AIBOM().to_native_json(), encoding="utf-8")
            return subprocess.CompletedProcess(args, 0, "", "")
        if args[0] == "verify-attestation":
            key_idx = args.index("--trusted-key") + 1
            staged_key = Path(args[key_idx])
            assert staged_key != key
            assert (staged_key.stat().st_mode & 0o077) == 0
            seen_key_bytes.append(staged_key.read_bytes())
            return subprocess.CompletedProcess(args, 0, '{"verified": true}', "")
        if args[0] == "diff":
            return subprocess.CompletedProcess(args, 0, '{"security_alerts": []}', "")
        raise AssertionError(f"unexpected command: {args}")

    rc = run_action.run(config, command=fake_command)
    assert rc == 0
    assert seen_key_bytes == [b"ORIGINAL-KEY-BYTES"]

    # _scratch_parent refuses untrusted scratch when baseline_attestation is set.
    bad_config = SimpleNamespace(
        signature_policy=None,
        baseline_attestation=b"{}",
        scratch_parent=workspace,
        workspace=workspace,
    )
    with (
        mock.patch("nexus_symbiote.utils.crypto._trust_anchor_error", return_value="untrusted"),
        pytest.raises(run_action.ActionError, match="reviewed-baseline-attestation"),
    ):
        run_action._scratch_parent(bad_config)  # type: ignore[arg-type]


# --- R-HIGH-25 & C-356-1: pinned_process cgroup teardown ordering ---


def test_teardown_verifiable_removed_and_cgroup_kill_runs_after_wrapper_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert not hasattr(pinned_process, "teardown_verifiable")

    events: list[str] = []
    proc = SimpleNamespace(pid=999999, returncode=0, poll=lambda: 0)
    cgroup_path = Path("/sys/fs/cgroup/fake-nexus")
    r_fd, w_fd = os.pipe()
    os.close(w_fd)
    pinned_process._OPT_OUT[proc.pid] = (None, cgroup_path, r_fd)

    monkeypatch.setattr(pinned_process, "_kill_descendants", lambda _pid: events.append("desc"))
    monkeypatch.setattr(
        pinned_process,
        "_wrapper_contained",
        lambda _pid, _done, _seen, _stop: (events.append("wrapper"), True)[1],
    )
    monkeypatch.setattr(pinned_process, "_cgroup_kill", lambda _cg: events.append("cgroup_kill"))
    monkeypatch.setattr(
        pinned_process, "_remove_cgroup", lambda _cg: events.append("remove_cgroup")
    )
    monkeypatch.setattr(os, "killpg", lambda _pid, _sig: None)

    assert pinned_process.terminate_process_group(proc) is True  # type: ignore[arg-type]
    assert events.index("wrapper") < events.index("cgroup_kill") < events.index("remove_cgroup")

    # If _wrapper_contained raises, finally must still run _cgroup_kill before _remove_cgroup.
    events.clear()
    r_fd2, w_fd2 = os.pipe()
    os.close(w_fd2)
    pinned_process._OPT_OUT[proc.pid] = (None, cgroup_path, r_fd2)

    def boom(_pid: int, _done: int, _seen: int | None, _stop: bool) -> bool:
        events.append("wrapper_boom")
        raise RuntimeError("interrupted")

    monkeypatch.setattr(pinned_process, "_wrapper_contained", boom)
    with pytest.raises(RuntimeError, match="interrupted"):
        pinned_process.terminate_process_group(proc)  # type: ignore[arg-type]
    assert (
        events.index("wrapper_boom") < events.index("cgroup_kill") < events.index("remove_cgroup")
    )


# --- R-MED-17: PinnedStdioSession.__exit__ never swallows PinnedProcessError ---


@pytest.mark.usefixtures("nonisolated_pinned_fixtures")
def test_session_never_swallows_pinned_process_error_when_pre_call_exception_occurs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    terminate = session_module.terminate_process_group

    def fail_teardown(proc: subprocess.Popen[bytes]) -> bool:
        terminate(proc)
        raise PinnedProcessError("isolation-teardown-failed", "orphan survived")

    monkeypatch.setattr(session_module, "terminate_process_group", fail_teardown)
    path, pin, _log = make_launcher(tmp_path, "ok")
    session = PinnedStdioSession(command=str(path), sha256=pin, server_id="server:mail")

    def fail_before_call() -> None:
        raise ValueError("pre-call descriptor rejection")

    with pytest.raises(AuthorizationError, match="orphan survived") as caught, session:
        session.describe("server:mail", "ok")
        fail_before_call()
    assert isinstance(caught.value.__cause__, PinnedProcessError)
    assert isinstance(caught.value.__context__, ValueError)


# --- R-MED-06: runtime_validation DAG multiplicity and unconditional count cap ---


def test_output_schema_preflight_rejects_allof_properties_ref_dag_blowup(dialects: object) -> None:
    from nexus_symbiote import runtime_validation as validation

    # 8-level 4-way allOf -> properties -> $ref DAG: 4^8 = 65,536 evaluations on a tiny object,
    # even though each node has work <= 32.
    defs: dict[str, object] = {"L8": {"type": "string"}}
    for level in range(7, -1, -1):
        target = f"#/$defs/L{level + 1}"
        defs[f"L{level}"] = {
            "type": "object",
            "allOf": [{"properties": {"x": {"$ref": target}}} for _ in range(4)],
        }
    blowup_4way = {"$defs": defs, "$ref": "#/$defs/L0"}
    assert validation._evaluate(dialects, blowup_4way, None) == validation._SCHEMA

    # 8-level 2-way allOf with 2 properties each -> 4^8 = 65,536 visits.
    defs2: dict[str, object] = {"L8": {"type": "string"}}
    for level in range(7, -1, -1):
        target = f"#/$defs/L{level + 1}"
        defs2[f"L{level}"] = {
            "type": "object",
            "allOf": [
                {"properties": {"a": {"$ref": target}, "b": {"$ref": target}}},
                {"properties": {"a": {"$ref": target}, "b": {"$ref": target}}},
            ],
        }
    blowup_binary = {"$defs": defs2, "$ref": "#/$defs/L0"}
    assert validation._evaluate(dialects, blowup_binary, None) == validation._SCHEMA

    # 16-level 2-way allOf with required property x -> 2^16 = 65,536 visits on the same
    # 17-node JSON chain even when footprint > 1 keeps distinct_limit below 32,768 / 2.
    defs_req: dict[str, object] = {"L16": {"type": "string"}}
    for level in range(15, -1, -1):
        target = f"#/$defs/L{level + 1}"
        defs_req[f"L{level}"] = {
            "type": "object",
            "required": ["x"],
            "allOf": [
                {"properties": {"x": {"$ref": target}}},
                {"properties": {"x": {"$ref": target}}},
            ],
        }
    blowup_req = {"$defs": defs_req, "$ref": "#/$defs/L0"}
    assert validation._evaluate(dialects, blowup_req, None) == validation._SCHEMA

    # 16-level 2-way allOf -> UNIQUE property name per level -> $ref DAG: each p{i} appears
    # once in the schema, yet in-place allOf reconvergence duplicates the same value 2^16 times.
    defs_unique: dict[str, object] = {"Leaf": {"type": "integer"}}
    for level in range(16):
        nxt = f"#/$defs/L{level + 1}" if level + 1 < 16 else "#/$defs/Leaf"
        defs_unique[f"L{level}"] = {
            "type": "object",
            "allOf": [{"$ref": f"#/$defs/M{level}"}, {"$ref": f"#/$defs/M{level}"}],
        }
        defs_unique[f"M{level}"] = {
            "type": "object",
            "properties": {f"p{level}": {"$ref": nxt}},
            "required": [f"p{level}"],
        }
    blowup_unique_prop = {"$defs": defs_unique, "$ref": "#/$defs/L0"}
    assert validation._evaluate(dialects, blowup_unique_prop, None) == validation._SCHEMA

    # 16-level 2-way allOf -> unique prefixItems index per level -> $ref DAG: same blowup on arrays.
    defs_tuple: dict[str, object] = {"Leaf": {"type": "integer"}}
    for level in range(16):
        nxt = f"#/$defs/L{level + 1}" if level + 1 < 16 else "#/$defs/Leaf"
        defs_tuple[f"L{level}"] = {
            "type": "array",
            "allOf": [{"$ref": f"#/$defs/M{level}"}, {"$ref": f"#/$defs/M{level}"}],
        }
        defs_tuple[f"M{level}"] = {
            "type": "array",
            "prefixItems": [*([{"type": "null"}] * level), {"$ref": nxt}],
            "minItems": level + 1,
        }
    blowup_tuple = {"$defs": defs_tuple, "$ref": "#/$defs/L0"}
    assert validation._evaluate(dialects, blowup_tuple, None) == validation._SCHEMA

    # 16-level 2-way allOf -> array items wildcard blowup is also rejected.
    defs_arr: dict[str, object] = {"Leaf": {"type": "integer"}}
    for level in range(16):
        nxt = f"#/$defs/L{level + 1}" if level + 1 < 16 else "#/$defs/Leaf"
        defs_arr[f"L{level}"] = {
            "type": "array",
            "allOf": [{"items": {"$ref": nxt}}, {"items": {"$ref": nxt}}],
        }
    blowup_arr_wild = {"$defs": defs_arr, "$ref": "#/$defs/L0"}
    assert validation._evaluate(dialects, blowup_arr_wild, None) == validation._SCHEMA

    # Shallow benign allOf -> properties -> $ref, recursive json-value, and array of objects
    # sharing a $ref (even with a non-reconverging allOf leaf) stay admitted.
    benign = {
        "$defs": {
            "Leaf": {"type": "string"},
            "Mid": {
                "type": "object",
                "allOf": [
                    {"properties": {"a": {"$ref": "#/$defs/Leaf"}}},
                    {"properties": {"b": {"$ref": "#/$defs/Leaf"}}},
                ],
            },
        },
        "$ref": "#/$defs/Mid",
    }
    assert validation._evaluate(dialects, benign, None) == validation._VALID
    assert validation._evaluate(dialects, benign, {"a": "ok", "b": "ok"}) == validation._VALID

    shared_ref_array = {
        "$defs": {"Label": {"allOf": [{"type": "string"}, {"minLength": 1}]}},
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "first": {"$ref": "#/$defs/Label"},
                "second": {"$ref": "#/$defs/Label"},
                "third": {"$ref": "#/$defs/Label"},
            },
        },
    }
    assert validation._evaluate(dialects, shared_ref_array, None) == validation._VALID
    assert (
        validation._evaluate(
            dialects, shared_ref_array, [{"first": "a", "second": "b", "third": "c"}]
        )
        == validation._VALID
    )

    benign_tuple = {
        "type": "array",
        "prefixItems": [{"type": "string"}, {"type": "integer"}],
    }
    assert validation._evaluate(dialects, benign_tuple, None) == validation._VALID
    assert validation._evaluate(dialects, benign_tuple, ["ok", 1]) == validation._VALID

    # F2: Multi-array, multi-map, and nested-object schemas sharing a $ref stay admitted.
    two_arrays = {
        "$defs": {"Item": {"type": "object", "properties": {"id": {"type": "string"}}}},
        "type": "object",
        "properties": {
            "users": {"type": "array", "items": {"$ref": "#/$defs/Item"}},
            "admins": {"type": "array", "items": {"$ref": "#/$defs/Item"}},
        },
    }
    assert validation._evaluate(dialects, two_arrays, None) == validation._VALID

    two_maps = {
        "$defs": {"Val": {"type": "string"}},
        "type": "object",
        "properties": {
            "env": {"type": "object", "additionalProperties": {"$ref": "#/$defs/Val"}},
            "labels": {"type": "object", "additionalProperties": {"$ref": "#/$defs/Val"}},
        },
    }
    assert validation._evaluate(dialects, two_maps, None) == validation._VALID

    shared_prop_across_arrays = {
        "$defs": {"Id": {"type": "string"}},
        "type": "object",
        "properties": {
            "users": {
                "type": "array",
                "items": {"type": "object", "properties": {"id": {"$ref": "#/$defs/Id"}}},
            },
            "orgs": {
                "type": "array",
                "items": {"type": "object", "properties": {"id": {"$ref": "#/$defs/Id"}}},
            },
        },
    }
    assert validation._evaluate(dialects, shared_prop_across_arrays, None) == validation._VALID

    nested_shared_prop = {
        "$defs": {
            "Name": {"type": "string"},
            "Person": {"type": "object", "properties": {"name": {"$ref": "#/$defs/Name"}}},
        },
        "type": "array",
        "items": {
            "type": "object",
            "properties": {
                "author": {"$ref": "#/$defs/Person"},
                "reviewer": {"$ref": "#/$defs/Person"},
            },
        },
    }
    assert validation._evaluate(dialects, nested_shared_prop, None) == validation._VALID


def test_trusted_ancestors_rejects_dotdot_and_handles_directory_mount_anchor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # Unnormalized '..' must be rejected before abspath collapses intermediate directories.
    sub = tmp_path / "sub"
    sub.mkdir()
    assert crypto_mod._check_trusted_ancestors(sub / "..", {os.geteuid()}) is not None

    # Directory anchor '/tmp' (len(parts) == 2) must qualify for is_mount_anchor under ro rootfs.
    if os.name == "posix":
        real_lstat = os.lstat
        real_fstat = os.fstat
        real_stat = os.stat
        tmp_dir = Path("/tmp")  # noqa: S108

        class _StatWrap:
            def __init__(
                self, base: os.stat_result, *, uid: int | None = None, dev: int | None = None
            ) -> None:
                self._base = base
                self.st_mode = base.st_mode
                self.st_uid = base.st_uid if uid is None else uid
                self.st_dev = base.st_dev if dev is None else dev
                self.st_ino = base.st_ino

            def __getattr__(self, name: str) -> object:
                return getattr(self._base, name)

        class _VfsWrap:
            def __init__(self, flag: int) -> None:
                self.f_flag = flag

        root_lstat = real_lstat("/")
        tmp_lstat = real_lstat(tmp_dir)
        monkeypatch.setattr(
            os,
            "lstat",
            lambda p, *a, **kw: (
                _StatWrap(root_lstat, uid=65534, dev=1)
                if Path(p) == Path("/")
                else _StatWrap(tmp_lstat, uid=os.geteuid(), dev=2)
            ),
        )
        monkeypatch.setattr(
            os,
            "fstat",
            lambda fd: (
                _StatWrap(root_lstat, uid=65534, dev=1)
                if real_fstat(fd).st_ino == root_lstat.st_ino
                else _StatWrap(tmp_lstat, uid=os.geteuid(), dev=2)
            ),
        )
        monkeypatch.setattr(os, "fstatvfs", lambda fd: _VfsWrap(os.ST_RDONLY))
        monkeypatch.setattr(
            os,
            "stat",
            lambda p, *a, **kw: (
                _StatWrap(tmp_lstat, uid=os.geteuid(), dev=2)
                if kw.get("dir_fd") is not None
                else real_stat(p, *a, **kw)
            ),
        )
        assert crypto_mod._trust_anchor_error(tmp_dir, None) is None


def test_clamp_operator_floor_preserves_unspecified_operator_risk_and_scan() -> None:
    op = Policy(
        scan=ScanPolicy(failure_mode="error", exclude_paths=["node_modules", ".git", "vendor"]),
        risk=RiskPolicy(
            fail_threshold=80.0,
            warn_threshold=60.0,
            fail_on_severity="none",
            ignore_categories=["low_noise"],
        ),
        validate=ValidatePolicy(minimum_assurance_level="declared"),
    )
    tightening_checkout = Policy.model_validate(
        {
            "scan": {"exclude_paths": []},
            "validate": {"minimum_assurance_level": "observed"},
        }
    )
    clamped = verify_staged_policy.clamp_operator_floor(op, tightening_checkout)
    assert clamped.risk.fail_threshold == 80.0
    assert clamped.risk.fail_on_severity == "none"
    assert clamped.risk.ignore_categories == ["low_noise"]
    assert clamped.validation.minimum_assurance_level == "observed"
    assert clamped.scan == op.scan


def test_oms_resource_name_rejects_non_canonical_and_non_str() -> None:
    for bad in ("sub/weights.bin/", "sub/./weights.bin", "sub//weights.bin", "sub/a\x7fb"):
        assert crypto_mod._clean_oms_resource_name(bad) is None
    err = crypto_mod._verify_oms_statement(
        "application/vnd.in-toto+json",
        json.dumps(
            {
                "_type": "https://in-toto.io/Statement/v1",
                "predicateType": next(iter(crypto_mod.OMS_PREDICATE_TYPES)),
                "subject": [{"name": "m", "digest": {"sha256": "0" * 64}}],
                "predicate": {
                    "resources": [
                        {"name": "weights.bin", "algorithm": "sha256", "digest": "0" * 64}
                    ]
                },
            }
        ).encode(),
        "0" * 64,
        artifact_name=Path("weights.bin"),  # type: ignore[arg-type]
    )
    assert err is not None and "invalid" in err.lower()


def test_inspect_outside_untrusted_rejects_checkout_symlink_pointing_outside(
    tmp_path: Path,
) -> None:
    from nexus_symbiote import runtime_cli

    repo = tmp_path / "repo"
    repo.mkdir()
    outside = tmp_path / "outside.pem"
    outside.write_text("key", encoding="utf-8")
    link = repo / "key.pem"
    link.symlink_to(outside)
    failure, _ = runtime_cli._inspect_outside_untrusted((link,), (repo,))
    assert failure == "inside"


def test_run_action_scratch_parent_validates_baseline_only_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ws = tmp_path / "ws"
    ws.mkdir()
    bad_tmp = ws / "tmp"
    bad_tmp.mkdir()
    cfg = SimpleNamespace(
        signature_policy=None,
        baseline=tmp_path / "baseline.json",
        baseline_attestation=None,
        scratch_parent=bad_tmp,
        workspace=ws,
    )
    monkeypatch.setattr(run_action.tempfile, "gettempdir", lambda: str(bad_tmp))
    monkeypatch.setattr(run_action.os, "name", "nt")
    with pytest.raises(run_action.ActionError, match="reviewed-baseline"):
        run_action._scratch_parent(cfg)  # type: ignore[arg-type]


def test_cgroup_remove_retries_ebusy_and_session_exit_preserves_teardown_reason(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import errno

    calls = 0

    class _FakeCgroup:
        def rmdir(self) -> None:
            nonlocal calls
            calls += 1
            if calls < 3:
                raise OSError(errno.EBUSY, "Device or resource busy")

    monkeypatch.setattr(pinned_process.time, "sleep", lambda _s: None)
    pinned_process._remove_cgroup(_FakeCgroup())  # type: ignore[arg-type]
    assert calls == 3

    class _BadDir:
        def cleanup(self) -> None:
            raise OSError("cleanup failed")

    def _fail_terminate(_proc: object) -> None:
        raise PinnedProcessError("isolation-teardown-failed", "process survived")

    monkeypatch.setattr(session_module, "terminate_process_group", _fail_terminate)
    session = object.__new__(PinnedStdioSession)
    session._process = SimpleNamespace(wait=lambda timeout=5: 0, stdin=None, stdout=None)  # type: ignore[assignment]
    session._directory = _BadDir()  # type: ignore[assignment]
    session._called = False
    with pytest.raises(AuthorizationError) as exc_info:
        session.__exit__(None, None, None)
    assert exc_info.value.reason == "isolation-teardown-failed"

    # Without a PinnedProcessError teardown failure, cleanup OSError still surfaces.
    plain_session = object.__new__(PinnedStdioSession)
    plain_session._process = None
    plain_session._directory = _BadDir()  # type: ignore[assignment]
    plain_session._called = False
    with pytest.raises(OSError, match="cleanup failed"):
        plain_session.__exit__(None, None, None)


def test_single_value_multiplicity_covers_applicator_combinations_and_caps(
    dialects: object, monkeypatch: pytest.MonkeyPatch
) -> None:
    from nexus_symbiote import runtime_validation as validation

    leaf = {"type": "string"}
    combined_obj = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {"Leaf": leaf},
        "allOf": [
            {
                "type": "object",
                "maxProperties": 10,
                "propertyNames": {"minLength": 1},
                "properties": {"a": {"$ref": "#/$defs/Leaf"}},
                "patternProperties": {"^x_": {"$ref": "#/$defs/Leaf"}},
                "additionalProperties": leaf,
            },
            {
                "type": "object",
                "maxProperties": 10,
                "properties": {"b": {"$ref": "#/$defs/Leaf"}},
                "additionalProperties": leaf,
            },
            {
                "type": "object",
                "maxProperties": 10,
                "properties": {"c": {"$ref": "#/$defs/Leaf"}},
                "additionalProperties": {"type": "string"},
            },
        ],
    }
    assert validation._evaluate(dialects, combined_obj, None) == validation._VALID
    assert validation._evaluate(dialects, combined_obj, {"a": "ok", "b": "ok"}) == validation._VALID

    combined_arr = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": {"Leaf": leaf},
        "allOf": [
            {
                "type": "array",
                "maxItems": 10,
                "prefixItems": [{"$ref": "#/$defs/Leaf"}],
                "items": leaf,
            },
            {
                "type": "array",
                "maxItems": 10,
                "prefixItems": [{"$ref": "#/$defs/Leaf"}, {"$ref": "#/$defs/Leaf"}],
                "items": leaf,
            },
            {
                "type": "array",
                "maxItems": 10,
                "prefixItems": [{"$ref": "#/$defs/Leaf"}],
                "items": {"type": "string"},
            },
        ],
    }
    assert validation._evaluate(dialects, combined_arr, None) == validation._VALID
    assert validation._evaluate(dialects, combined_arr, ["a", "b"]) == validation._VALID

    # Exponential in-place allOf DAG trips closure step_cap and fails closed.
    defs: dict[str, object] = {"d0": {"type": "string"}}
    for i in range(1, 20):
        defs[f"d{i}"] = {"allOf": [{"$ref": f"#/$defs/d{i - 1}"}, {"$ref": f"#/$defs/d{i - 1}"}]}
    dag_bomb = {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$defs": defs,
        "$ref": "#/$defs/d19",
    }
    assert validation._evaluate(dialects, dag_bomb, None) == validation._SCHEMA

    # Path-state budget overflow fails closed.
    monkeypatch.setattr(validation, "_MAX_PATH_STATES", 1)
    assert validation._evaluate(dialects, combined_obj, None) == validation._SCHEMA
