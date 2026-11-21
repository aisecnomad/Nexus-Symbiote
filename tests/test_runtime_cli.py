from __future__ import annotations

import errno
import json
import os
import stat
from datetime import UTC, datetime, timedelta

import click
import pytest
from click.testing import CliRunner
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote.runtime import (
    ApprovedSnapshot,
    AuthorizationError,
    ExecutionContext,
    ReferenceGateway,
    StateStore,
    ToolCall,
    ToolGrant,
    TrustStatus,
    bom_digest,
    contract_digest,
    key_id,
    request_digest,
    sign_contract,
    tool_definition_digest,
)
from nexus_symbiote.runtime_cli import register_runtime_commands
from tests.support import REPLACEABLE_ANCHOR_LAYOUTS, trust_anchor_in_layout


def test_cli_sign_verify_and_wrong_purpose(tmp_path):
    main = click.Group()
    register_runtime_commands(main)
    runner = CliRunner()
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    result = runner.invoke(
        main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
    )
    assert result.exit_code == 0, result.output
    now = datetime.now(UTC)
    contract = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=5),
    )
    body, signed = tmp_path / "status.json", tmp_path / "signed.json"
    body.write_text(contract.model_dump_json())
    result = runner.invoke(
        main,
        [
            "runtime",
            "sign",
            str(body),
            "--kind",
            "trust",
            "--key",
            str(private),
            "--out",
            str(signed),
        ],
    )
    assert result.exit_code == 0, result.output
    result = runner.invoke(
        main, ["runtime", "verify", str(signed), "--kind", "trust", "--public-key", str(public)]
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["invocation_authorized"] is False
    result = runner.invoke(
        main, ["runtime", "verify", str(signed), "--kind", "snapshot", "--public-key", str(public)]
    )
    assert result.exit_code != 0
    result = runner.invoke(
        main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
    )
    assert result.exit_code != 0


def test_keygen_creates_both_key_files_owner_only(tmp_path):
    main = click.Group()
    register_runtime_commands(main)
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    previous = os.umask(0)
    try:
        result = CliRunner().invoke(
            main, ["runtime", "keygen", "--private-key", str(private), "--public-key", str(public)]
        )
    finally:
        os.umask(previous)
    assert result.exit_code == 0, result.output
    # Even with a permissive umask, neither file is group- or world-accessible.
    assert stat.S_IMODE(private.stat().st_mode) == 0o600
    assert stat.S_IMODE(public.stat().st_mode) == 0o600


def run(*args):
    main = click.Group()
    register_runtime_commands(main)
    result = CliRunner().invoke(main, ["runtime", *map(str, args)])
    # A refused input ends with a plain error, never a Python traceback.
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    return result


def keypair(tmp_path, name, *extra):
    private, public = tmp_path / f"{name}.pem", tmp_path / f"{name}.pub"
    result = run("keygen", "--private-key", private, "--public-key", public, *extra)
    assert result.exit_code == 0, result.output
    return private, public


def write(tmp_path, name, value):
    path = tmp_path / name
    path.write_text(value if isinstance(value, str) else value.model_dump_json())
    return path


def current_snapshot(bom, **update):
    now = datetime.now(UTC)
    grant = ToolGrant(
        server_id="server:mail",
        endpoint_identity="https://mail.example.test/mcp",
        tool_name="send",
        definition_digest="sha256:" + "0" * 64,
        actions=("send",),
        resources=("mailbox:team",),
    )
    fields = {
        "agent_id": "agent:triage",
        "deployment_id": "prod",
        "tenant": "acme",
        "workload_identity": "spiffe://acme/triage",
        "policy_digest": "sha256:" + "a" * 64,
        "serial": 1,
        "bom_digest": bom_digest(bom),
        "tools": (grant,),
        "not_before": now - timedelta(seconds=1),
        "not_after": now + timedelta(hours=1),
    }
    return ApprovedSnapshot(**{**fields, **update})


def test_snapshot_verification_requires_its_exact_companion_bom(tmp_path):
    private, public = keypair(tmp_path, "snapshot")
    bom = {"components": [{"name": "send"}]}
    snapshot = current_snapshot(bom)
    signed = tmp_path / "snapshot.dsse.json"
    contract = write(tmp_path, "snapshot.json", snapshot)
    result = run("sign", contract, "--kind", "snapshot", "--key", private, "--out", signed)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["digest"] == contract_digest(snapshot)
    matching = write(tmp_path, "bom.json", json.dumps(bom))
    verified = run(
        "verify", signed, "--kind", "snapshot", "--public-key", public, "--bom", matching
    )
    assert verified.exit_code == 0, verified.output
    assert json.loads(verified.stdout)["digest"] == contract_digest(snapshot)
    other = write(tmp_path, "other.json", json.dumps({"components": []}))
    mismatched = run("verify", signed, "--kind", "snapshot", "--public-key", public, "--bom", other)
    assert mismatched.exit_code == 1 and "(bom-mismatch)" in mismatched.output
    missing = run("verify", signed, "--kind", "snapshot", "--public-key", public)
    assert missing.exit_code == 1 and "(bom-required)" in missing.output


def test_threshold_requires_distinct_trusted_signers(tmp_path):
    first, first_pub = keypair(tmp_path, "first")
    second, second_pub = keypair(tmp_path, "second")
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=30)
    )
    contract = write(tmp_path, "status.json", status)
    both, one = tmp_path / "both.json", tmp_path / "one.json"
    assert (
        run(
            "sign", contract, "--kind", "trust", "--key", first, "--key", second, "--out", both
        ).exit_code
        == 0
    )
    assert run("sign", contract, "--kind", "trust", "--key", first, "--out", one).exit_code == 0
    ring = ["--public-key", first_pub, "--public-key", second_pub, "--threshold", "2"]
    accepted = run("verify", both, "--kind", "trust", *ring)
    assert accepted.exit_code == 0, accepted.output
    assert len(json.loads(accepted.stdout)["accepted_signers"]) == 2
    refused = run("verify", one, "--kind", "trust", *ring)
    assert refused.exit_code == 1 and "(signers-insufficient)" in refused.output
    too_many = run("verify", both, "--kind", "trust", *ring[:-1], "33")
    assert too_many.exit_code == 2


def test_verify_names_the_expired_window(tmp_path):
    private, public = keypair(tmp_path, "trust")
    then = datetime.now(UTC) - timedelta(hours=3)
    expired = TrustStatus(
        tenant="acme", serial=1, not_before=then, not_after=then + timedelta(hours=1)
    )
    key = serialization.load_pem_private_key(private.read_bytes(), password=None)
    envelope = sign_contract(expired, "trust", (key,))
    signed = write(tmp_path, "expired.dsse.json", json.dumps(envelope.model_dump(by_alias=True)))
    result = run("verify", signed, "--kind", "trust", "--public-key", public)
    assert result.exit_code == 1 and "(trust-expired)" in result.output


@pytest.mark.parametrize(
    ("kind", "lifetime", "reason"),
    [
        ("snapshot", timedelta(hours=25), "snapshot-lifetime-exceeds-policy"),
        ("trust", timedelta(hours=2), "trust-lifetime-exceeds-policy"),
        ("trust", timedelta(minutes=-90), "trust-expired"),
    ],
)
def test_sign_refuses_contracts_that_can_never_verify(tmp_path, kind, lifetime, reason):
    private, _ = keypair(tmp_path, "key")
    now = datetime.now(UTC)
    if lifetime < timedelta(0):
        window = {"not_before": now + lifetime - timedelta(minutes=30), "not_after": now + lifetime}
    else:
        window = {"not_before": now - timedelta(seconds=1), "not_after": now + lifetime}
    if kind == "snapshot":
        contract = current_snapshot({}, **window)
    else:
        contract = TrustStatus(tenant="acme", serial=1, **window)
    out = tmp_path / "signed.json"
    path = write(tmp_path, "contract.json", contract)
    result = run("sign", path, "--kind", kind, "--key", private, "--out", out)
    assert result.exit_code == 1 and f"({reason})" in result.output
    assert not out.exists()


@pytest.mark.parametrize(
    ("change", "label"),
    [
        ("inverted", "contract rule: validity window"),
        ("duplicate", "contract rule: duplicate tool grant"),
        ("endpoint", "tools.endpoint_identity"),
    ],
)
def test_contract_rule_errors_are_labelled_without_values(tmp_path, change, label):
    private, _ = keypair(tmp_path, "key")
    document = json.loads(current_snapshot({}).model_dump_json())
    if change == "inverted":
        document["not_before"], document["not_after"] = (
            document["not_after"],
            document["not_before"],
        )
    elif change == "duplicate":
        document["tools"] = document["tools"] * 2
    else:
        document["tools"][0]["endpoint_identity"] = "https://SECRET-HOST.example.test/"
    path = write(tmp_path, "contract.json", json.dumps(document))
    result = run("sign", path, "--kind", "snapshot", "--key", private, "--out", tmp_path / "o")
    assert result.exit_code == 1 and "runtime-input-error" in result.output
    assert label in result.output and "unsupported field" not in result.output
    assert "SECRET-HOST" not in result.output


def test_deeply_nested_inputs_end_without_a_traceback(tmp_path):
    private, public = keypair(tmp_path, "key")
    nested = write(tmp_path, "nested.json", "[" * 100_000 + "]" * 100_000)
    for args in (
        ("sign", nested, "--kind", "trust", "--key", private, "--out", tmp_path / "o"),
        ("verify", nested, "--kind", "trust", "--public-key", public),
        ("digest", nested, "--kind", "bom"),
    ):
        result = run(*args)
        assert result.exit_code == 1 and "(json-invalid)" in result.output, args
    snapshot_key, snapshot_pub = keypair(tmp_path, "snapshot")
    signed = tmp_path / "snapshot.dsse.json"
    contract = write(tmp_path, "snapshot.json", current_snapshot({}))
    assert (
        run(
            "sign", contract, "--kind", "snapshot", "--key", snapshot_key, "--out", signed
        ).exit_code
        == 0
    )
    result = run(
        "verify", signed, "--kind", "snapshot", "--public-key", snapshot_pub, "--bom", nested
    )
    assert result.exit_code == 1 and "(json-invalid)" in result.output


def secret(tmp_path, name, value):
    path = write(tmp_path, name, value)
    path.chmod(0o600)
    return path


def test_encrypted_private_keys_need_their_passphrase(tmp_path):
    passphrase = secret(tmp_path, "passphrase.txt", "correct horse battery staple\n")
    private, public = keypair(tmp_path, "key", "--passphrase-file", passphrase)
    assert private.read_bytes().startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----")
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=5)
    )
    contract = write(tmp_path, "status.json", status)
    missing = run("sign", contract, "--kind", "trust", "--key", private, "--out", tmp_path / "a")
    assert missing.exit_code == 1 and "encrypted" in missing.output
    assert "runtime-key-error" in missing.output
    wrong = secret(tmp_path, "wrong.txt", "not the passphrase\n")
    refused = run(
        "sign",
        contract,
        "--kind",
        "trust",
        "--key",
        private,
        "--out",
        tmp_path / "b",
        "--passphrase-file",
        wrong,
    )
    assert refused.exit_code == 1 and "runtime-key-error" in refused.output
    signed = tmp_path / "c"
    accepted = run(
        "sign",
        contract,
        "--kind",
        "trust",
        "--key",
        private,
        "--out",
        signed,
        "--passphrase-file",
        passphrase,
    )
    assert accepted.exit_code == 0, accepted.output
    assert run("verify", signed, "--kind", "trust", "--public-key", public).exit_code == 0


def test_private_key_readable_by_others_is_refused(tmp_path):
    private, _ = keypair(tmp_path, "key")
    private.chmod(0o640)
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=5)
    )
    contract = write(tmp_path, "status.json", status)
    result = run("sign", contract, "--kind", "trust", "--key", private, "--out", tmp_path / "o")
    assert result.exit_code == 1 and "group or others" in result.output


def test_a_root_run_sign_refuses_a_key_another_user_owns(tmp_path, monkeypatch):
    private, _ = keypair(tmp_path, "key")
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=5)
    )
    contract = write(tmp_path, "status.json", status)
    # Run as root with a 0600 key that another uid owns, such as a host-mounted key.
    if os.geteuid() == 0:
        os.chown(private, 4242, 4242)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    out = tmp_path / "o"
    result = run("sign", contract, "--kind", "trust", "--key", private, "--out", out)
    assert result.exit_code == 1
    assert (
        "private key file must be owned by the user running the command (runtime-key-error)"
        in result.output
    )
    assert not out.exists()


def test_a_root_run_keygen_refuses_a_passphrase_file_another_user_owns(tmp_path, monkeypatch):
    passphrase = secret(tmp_path, "passphrase.txt", "correct horse battery staple\n")
    if os.geteuid() == 0:
        os.chown(passphrase, 4242, 4242)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    result = run(
        "keygen", "--private-key", private, "--public-key", public, "--passphrase-file", passphrase
    )
    assert result.exit_code == 1
    assert (
        "passphrase file must be owned by the user running the command (runtime-key-error)"
        in result.output
    )
    assert not private.exists() and not public.exists()


def test_keygen_failure_is_reported_and_leaves_no_partial_pair(tmp_path):
    public = tmp_path / "key.pub"
    result = run(
        "keygen", "--private-key", tmp_path / "missing" / "key.pem", "--public-key", public
    )
    assert result.exit_code == 1 and "runtime-io-error" in result.output
    assert not public.exists()


@pytest.mark.parametrize(
    ("passphrase", "mode", "message"),
    [
        ("x" * 2000, 0o600, "at most 1023 bytes"),
        ("correct horse battery staple", 0o644, "group or others"),
        ("", 0o600, "empty"),
    ],
)
def test_keygen_refuses_an_unusable_passphrase_before_writing_a_key(
    tmp_path, passphrase, mode, message
):
    secret_file = write(tmp_path, "passphrase.txt", passphrase + "\n")
    secret_file.chmod(mode)
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    result = run(
        "keygen", "--private-key", private, "--public-key", public, "--passphrase-file", secret_file
    )
    assert result.exit_code == 1 and "(runtime-key-error)" in result.output
    assert message in result.output
    assert not private.exists() and not public.exists()
    assert keypair(tmp_path, "key")


def test_keygen_removes_the_public_key_when_the_private_key_cannot_be_written(
    tmp_path, monkeypatch
):
    from nexus_symbiote import runtime_cli

    written = []
    write_new = runtime_cli._write_new

    def fail_second(path, content, mode=0o600):
        if written:
            raise ValueError("refused")
        written.append(path)
        write_new(path, content, mode)

    monkeypatch.setattr(runtime_cli, "_write_new", fail_second)
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    result = run("keygen", "--private-key", private, "--public-key", public)
    assert result.exit_code == 1 and written == [public]
    assert not private.exists() and not public.exists()


def fail_stream(monkeypatch, marker, stage):
    """Make the new file that receives ``marker`` fail on write or close, with data on disk."""
    fdopen = os.fdopen

    class Failing:
        def __init__(self, stream):
            self.stream = stream
            self.marked = False

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.stream.close()
            if self.marked and stage == "close":
                raise OSError(errno.EIO, "close failed")

        def write(self, data):
            self.marked = self.marked or marker in data
            if self.marked and stage == "write":
                self.stream.write(data[:16])
                self.stream.flush()
                raise OSError(errno.ENOSPC, "no space left")
            return self.stream.write(data)

    def patched(fd, mode="r", *args, **kwargs):
        stream = fdopen(fd, mode, *args, **kwargs)
        return Failing(stream) if mode == "wb" else stream

    monkeypatch.setattr(os, "fdopen", patched)


@pytest.mark.parametrize("stage", ["write", "close"])
def test_keygen_keeps_neither_key_when_the_private_key_write_fails_part_way(
    tmp_path, monkeypatch, stage
):
    fail_stream(monkeypatch, b"PRIVATE KEY", stage)
    private, public = tmp_path / "key.pem", tmp_path / "key.pub"
    result = run("keygen", "--private-key", private, "--public-key", public)
    assert result.exit_code == 1 and "runtime-io-error" in result.output
    assert not private.exists() and not public.exists()
    monkeypatch.undo()
    assert keypair(tmp_path, "key")


@pytest.mark.parametrize("stage", ["write", "close"])
def test_sign_leaves_no_partial_envelope_when_the_write_fails(tmp_path, monkeypatch, stage):
    private, _ = keypair(tmp_path, "key")
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=5)
    )
    contract, out = write(tmp_path, "status.json", status), tmp_path / "signed.json"
    fail_stream(monkeypatch, b"payload", stage)
    result = run("sign", contract, "--kind", "trust", "--key", private, "--out", out)
    assert result.exit_code == 1 and "runtime-io-error" in result.output
    assert not out.exists()
    monkeypatch.undo()
    assert run("sign", contract, "--kind", "trust", "--key", private, "--out", out).exit_code == 0


def test_keygen_names_existing_paths_with_a_reason_code(tmp_path):
    private, public = keypair(tmp_path, "key")
    again = run("keygen", "--private-key", private, "--public-key", tmp_path / "other.pub")
    assert again.exit_code == 1
    assert "choose distinct, nonexistent key paths (runtime-key-error)" in again.output
    same = tmp_path / "same.pem"
    result = run("keygen", "--private-key", same, "--public-key", same)
    assert result.exit_code == 1 and "(runtime-key-error)" in result.output


@pytest.mark.parametrize("kind", ["snapshot", "context", "request", "tool", "bom"])
def test_digest_of_a_json_value_that_is_not_an_object_says_so(tmp_path, kind):
    path = write(tmp_path, "array.json", "[]")
    result = run("digest", path, "--kind", kind)
    assert result.exit_code == 1
    assert "input must be a JSON object (json-not-object)" in result.output


def test_sign_and_verify_of_a_json_value_that_is_not_an_object_say_so(tmp_path):
    private, public = keypair(tmp_path, "key")
    path = write(tmp_path, "array.json", "[1]")
    signed = run("sign", path, "--kind", "trust", "--key", private, "--out", tmp_path / "o")
    verified = run("verify", path, "--kind", "trust", "--public-key", public)
    for result in (signed, verified):
        assert result.exit_code == 1 and "(json-not-object)" in result.output


def test_oversized_inputs_end_with_a_reason_code(tmp_path):
    large = write(tmp_path, "large.pub", "x" * 70_000)
    result = run("key-id", large)
    assert result.exit_code == 1
    assert "input exceeds its size limit (runtime-input-too-large)" in result.output


def test_digest_and_key_id_commands_match_the_library(tmp_path):
    _, public = keypair(tmp_path, "key")
    bom = {"components": [{"name": "send", "version": 1.0}]}
    snapshot = current_snapshot(
        bom,
        not_before=datetime(2020, 1, 1, tzinfo=UTC),
        not_after=datetime(2020, 1, 1, 1, tzinfo=UTC),
    )
    context = ExecutionContext(
        agent_id="agent:triage",
        deployment_id="prod",
        tenant="acme",
        workload_identity="spiffe://acme/triage",
        policy_digest="sha256:" + "a" * 64,
    )
    call = ToolCall(
        server_id="server:mail",
        tool_name="send",
        action="send",
        resource="mailbox:team",
        arguments={"to": "team@example.test", "n": 1.0},
    )
    tool = {"name": "send", "description": "Send", "inputSchema": {"type": "object"}, "title": "S"}
    cases = [
        ("snapshot", snapshot.model_dump_json(), contract_digest(snapshot)),
        ("context", context.model_dump_json(), contract_digest(context)),
        ("request", call.model_dump_json(), request_digest(call)),
        ("tool", json.dumps(tool), tool_definition_digest(tool)),
        ("bom", json.dumps(bom), bom_digest(bom)),
    ]
    for kind, text, expected in cases:
        result = run("digest", write(tmp_path, f"{kind}.json", text), "--kind", kind)
        assert result.exit_code == 0, result.output
        assert json.loads(result.stdout) == {"kind": kind, "digest": expected}
    unsupported = write(tmp_path, "icons.json", json.dumps({**tool, "icons": []}))
    refused = run("digest", unsupported, "--kind", "tool")
    assert refused.exit_code == 1 and "(descriptor-unsupported)" in refused.output
    loaded = serialization.load_pem_public_key(public.read_bytes())
    assert json.loads(run("key-id", public).stdout) == {"key_id": key_id(loaded)}
    private_as_public = run("key-id", tmp_path / "key.pem")
    assert private_as_public.exit_code == 1 and "runtime-key-error" in private_as_public.output
    assert stat.S_IMODE(os.stat(public).st_mode) == 0o600


def public_file(tmp_path, name, key):
    path = tmp_path / name
    path.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return path


def envelope_file(tmp_path, name, envelope):
    return write(tmp_path, name, json.dumps(envelope.model_dump(mode="json", by_alias=True)))


def test_register_makes_a_new_snapshot_current_without_a_gateway(tmp_path):
    snapshot_key, trust_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=30),
    )
    older, newer = current_snapshot({}), current_snapshot({}, serial=2)
    signed = {
        name: envelope_file(tmp_path, f"{name}.dsse.json", sign_contract(value, kind, (key,)))
        for name, value, kind, key in (
            ("older", older, "snapshot", snapshot_key),
            ("newer", newer, "snapshot", snapshot_key),
            ("trust", status, "trust", trust_key),
        )
    }
    state = tmp_path / "state.sqlite"
    StateStore.initialize(state)
    args = [
        "--trust",
        signed["trust"],
        "--state",
        state,
        "--snapshot-key",
        public_file(tmp_path, "snapshot.pub", snapshot_key),
        "--trust-key",
        public_file(tmp_path, "trust.pub", trust_key),
    ]
    result = run("register", signed["newer"], *args)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout) == {
        "registered": True,
        "tenant": "acme",
        "deployment_id": "prod",
        "agent_id": "agent:triage",
        "serial": 2,
        "digest": contract_digest(newer),
    }
    assert run("register", signed["newer"], *args).exit_code == 0
    superseded = run("register", signed["older"], *args)
    assert superseded.exit_code == 1 and "(snapshot-superseded)" in superseded.output
    # Every gateway that shares the store now denies serial 1.
    gateway = ReferenceGateway.registrar(
        snapshot_keys={key_id(snapshot_key.public_key()): snapshot_key.public_key()},
        trust_keys={key_id(trust_key.public_key()): trust_key.public_key()},
        state=StateStore(state),
    )
    with pytest.raises(AuthorizationError) as denied:
        gateway.register_snapshot(
            sign_contract(older, "snapshot", (snapshot_key,)),
            trust=sign_contract(status, "trust", (trust_key,)),
        )
    assert denied.value.reason == "snapshot-superseded"
    with pytest.raises(AuthorizationError) as refused:
        gateway.invoke(
            ToolCall(server_id="s", tool_name="t", action="a", resource="r"),
            **{
                "snapshot": sign_contract(newer, "snapshot", (snapshot_key,)),
                "trust": sign_contract(status, "trust", (trust_key,)),
                "bom": {},
            },
        )
    assert refused.value.reason == "configuration-invalid"

    snapshot_id = key_id(snapshot_key.public_key())
    other_tenant = write(
        tmp_path, "scopes.json", json.dumps({snapshot_id: {"tenants": ["globex"]}})
    )
    scoped = run("register", signed["newer"], *args, "--signer-scopes", other_tenant)
    assert scoped.exit_code == 1 and "(signers-out-of-scope)" in scoped.output
    unknown = write(tmp_path, "unknown.json", json.dumps({"0" * 64: {"tenants": ["acme"]}}))
    misconfigured = run("register", signed["newer"], *args, "--signer-scopes", unknown)
    assert misconfigured.exit_code == 1 and "(configuration-invalid)" in misconfigured.output
    missing = tmp_path / "missing.sqlite"
    absent = run("register", signed["newer"], *args[:2], "--state", missing, *args[4:])
    assert absent.exit_code == 1 and "(state-missing)" in absent.output
    assert not missing.exists()


def registration(tmp_path, snapshot_key, trust_key):
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=30),
    )
    state = tmp_path / "state.sqlite"
    StateStore.initialize(state)
    snapshot = sign_contract(current_snapshot({}), "snapshot", (snapshot_key,))
    return [
        envelope_file(tmp_path, "snapshot.dsse.json", snapshot),
        "--trust",
        envelope_file(tmp_path, "trust.dsse.json", sign_contract(status, "trust", (trust_key,))),
        "--state",
        state,
    ]


def test_register_takes_the_full_scope_map_the_gateways_use(tmp_path):
    snapshot_key, trust_key, approval_key = (Ed25519PrivateKey.generate() for _ in range(3))
    keys = {"snapshot": snapshot_key, "trust": trust_key, "approval": approval_key}
    scopes = write(
        tmp_path,
        "scopes.json",
        json.dumps({key_id(key.public_key()): {"tenants": ["acme"]} for key in keys.values()}),
    )
    args = [
        *registration(tmp_path, snapshot_key, trust_key),
        "--snapshot-key",
        public_file(tmp_path, "snapshot.pub", snapshot_key),
        "--trust-key",
        public_file(tmp_path, "trust.pub", trust_key),
        "--signer-scopes",
        scopes,
    ]
    # Without the approval ring the scope map names a key in no ring; say which one.
    refused = run("register", *args)
    assert refused.exit_code == 1 and "(configuration-invalid)" in refused.output
    assert key_id(approval_key.public_key()) in refused.output
    approval = public_file(tmp_path, "approval.pub", approval_key)
    result = run("register", *args, "--approval-key", approval)
    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["serial"] == 1


def test_register_refuses_a_key_in_two_rings_unless_shared_keys_are_allowed(tmp_path):
    shared = Ed25519PrivateKey.generate()
    public = public_file(tmp_path, "shared.pub", shared)
    args = [
        *registration(tmp_path, shared, shared),
        "--snapshot-key",
        public,
        "--trust-key",
        public,
    ]
    refused = run("register", *args)
    assert refused.exit_code == 1 and "(configuration-invalid)" in refused.output
    assert key_id(shared.public_key()) in refused.output
    assert "--allow-shared-keys if the gateways allow shared keys" in refused.output
    assert run("register", *args, "--allow-shared-keys").exit_code == 0


def test_register_does_not_echo_a_scope_name_that_is_not_a_key_id(tmp_path):
    snapshot_key, trust_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    scopes = write(tmp_path, "scopes.json", json.dumps({"\x1b[2Jzqxname": {"tenants": ["acme"]}}))
    refused = run(
        "register",
        *registration(tmp_path, snapshot_key, trust_key),
        "--snapshot-key",
        public_file(tmp_path, "snapshot.pub", snapshot_key),
        "--trust-key",
        public_file(tmp_path, "trust.pub", trust_key),
        "--signer-scopes",
        scopes,
    )
    assert refused.exit_code == 1 and "(configuration-invalid)" in refused.output
    assert "\x1b" not in refused.output and "zqxname" not in refused.output


def test_register_prints_contract_text_without_a_ci_log_command(tmp_path):
    # Identities come from a signed snapshot, yet reach standard output only as inert
    # JSON, as every other command's JSON does: the document parses back unchanged.
    snapshot_key, trust_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme",
        serial=1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=30),
    )
    hostile = {
        "agent_id": "##[set-output name=approved]true",
        "deployment_id": "##vso[task.setvariable variable=x]y",
    }
    snapshot = current_snapshot({}, **hostile)
    state = tmp_path / "state.sqlite"
    StateStore.initialize(state)
    result = run(
        "register",
        envelope_file(
            tmp_path, "snapshot.json", sign_contract(snapshot, "snapshot", (snapshot_key,))
        ),
        "--trust",
        envelope_file(tmp_path, "trust.json", sign_contract(status, "trust", (trust_key,))),
        "--state",
        state,
        "--snapshot-key",
        public_file(tmp_path, "snapshot.pub", snapshot_key),
        "--trust-key",
        public_file(tmp_path, "trust.pub", trust_key),
    )
    assert result.exit_code == 0, result.output
    assert "##[" not in result.stdout and "##vso[" not in result.stdout
    document = json.loads(result.stdout)
    assert {key: document[key] for key in hostile} == hostile


MISPLACED = "must lie outside every git working tree"


def test_verify_refuses_a_public_key_in_the_working_tree_of_its_inputs(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    (repo / "keys").mkdir(parents=True)
    (repo / ".git").mkdir()
    operator = tmp_path / "operator"
    operator.mkdir()
    private, public = keypair(operator, "trust")
    now = datetime.now(UTC)
    status = TrustStatus(
        tenant="acme",
        serial=2**53 - 1,
        not_before=now - timedelta(seconds=1),
        not_after=now + timedelta(minutes=30),
    )
    contract = write(operator, "trust.json", status)
    signed = repo / "trust.dsse.json"
    assert (
        run("sign", contract, "--kind", "trust", "--key", private, "--out", signed).exit_code == 0
    )
    inside = repo / "keys" / "trust.pub"
    inside.write_bytes(public.read_bytes())
    refused = run("verify", signed, "--kind", "trust", "--public-key", inside)
    assert refused.exit_code == 2 and MISPLACED in refused.output
    assert "contract_verified" not in refused.output
    mixed = run("verify", signed, "--kind", "trust", "--public-key", public, "--public-key", inside)
    assert mixed.exit_code == 2 and "--public-key" in mixed.output
    # The current directory's tree, although the envelope is outside it.
    outside = operator / "trust.dsse.json"
    outside.write_bytes(signed.read_bytes())
    monkeypatch.chdir(repo)
    assert run("verify", outside, "--kind", "trust", "--public-key", inside).exit_code == 2
    monkeypatch.chdir(tmp_path)
    linked = operator / "linked.pub"
    os.link(public, linked)
    hard = run("verify", signed, "--kind", "trust", "--public-key", linked)
    assert hard.exit_code == 2 and "must not have other hard links" in hard.output
    os.unlink(linked)
    passed = run("verify", signed, "--kind", "trust", "--public-key", public)
    assert passed.exit_code == 0, passed.output
    assert json.loads(passed.stdout)["contract_verified"] is True


def test_verify_refuses_a_key_in_the_tree_that_holds_the_companion_bom(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").write_text("gitdir: elsewhere\n")
    private, public = keypair(tmp_path, "snapshot")
    bom: dict[str, list[str]] = {"components": []}
    signed = tmp_path / "snapshot.dsse.json"
    contract = write(tmp_path, "snapshot.json", current_snapshot(bom))
    signing = run("sign", contract, "--kind", "snapshot", "--key", private, "--out", signed)
    assert signing.exit_code == 0, signing.output
    companion = write(repo, "bom.json", json.dumps(bom))
    inside = repo / "snapshot.pub"
    inside.write_bytes(public.read_bytes())
    args = ["verify", signed, "--kind", "snapshot", "--bom", companion]
    refused = run(*args, "--public-key", inside)
    assert refused.exit_code == 2 and MISPLACED in refused.output
    assert run(*args, "--public-key", public).exit_code == 0


@pytest.mark.parametrize("ring", ["--snapshot-key", "--trust-key", "--approval-key"])
def test_register_refuses_a_ring_key_in_the_working_tree_of_its_inputs(tmp_path, ring):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / ".git").mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    private = dict(
        zip(
            ["--snapshot-key", "--trust-key", "--approval-key"],
            (Ed25519PrivateKey.generate() for _ in range(3)),
            strict=True,
        )
    )

    def ring_args(planted_in):
        return [
            arg
            for option, key in private.items()
            for arg in (
                option,
                public_file(planted_in if option == ring else tmp_path, f"{option[2:]}.pub", key),
            )
        ]

    snapshot, *rest = registration(repo, private["--snapshot-key"], private["--trust-key"])
    refused = run("register", snapshot, *rest, *ring_args(repo))
    assert refused.exit_code == 2 and MISPLACED in refused.output and ring in refused.output
    assert '"registered"' not in refused.output
    # The state database alone in the tree is enough.
    moved = [outside / "snapshot.dsse.json", outside / "trust.dsse.json"]
    for source, target in zip((snapshot, rest[1]), moved, strict=True):
        target.write_bytes(source.read_bytes())
    alone = run("register", moved[0], "--trust", moved[1], "--state", rest[3], *ring_args(repo))
    assert alone.exit_code == 2 and MISPLACED in alone.output
    registered = run("register", snapshot, *rest, *ring_args(outside))
    assert registered.exit_code == 0, registered.output


@pytest.mark.parametrize(
    "layout", [*REPLACEABLE_ANCHOR_LAYOUTS, "world-writable file", "sticky grandparent"]
)
def test_runtime_public_key_that_another_user_could_replace_is_refused(
    tmp_path, monkeypatch, layout
):
    from nexus_symbiote import runtime_cli

    pem = (
        Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    key = trust_anchor_in_layout(tmp_path, layout, "trusted.pub", pem, monkeypatch)
    if layout == "world-writable file":
        key.chmod(0o666)
    if layout == "sticky grandparent":
        assert len(runtime_cli._ring((key,))) == 1
        return
    with pytest.raises(runtime_cli._KeyFileError, match="group- or world-writable"):
        runtime_cli._ring((key,))
