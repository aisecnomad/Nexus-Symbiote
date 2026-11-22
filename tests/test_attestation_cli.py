"""The attest and verify-attestation commands: round trips, refusals, exit codes and output."""

from __future__ import annotations

import base64
import json
import os
import re
import shlex
import shutil
import stat
from datetime import UTC, datetime, timedelta
from pathlib import Path

import click
import pytest
import rfc8785
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ec import SECP256R1, generate_private_key
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from nexus_symbiote import attestation_cli, runtime_cli
from nexus_symbiote.attestation import MAX_NATIVE_DEPTH, build_statement, sign_statement
from nexus_symbiote.cli import main
from nexus_symbiote.core.aibom import AIBOM
from nexus_symbiote.runtime import TrustStatus, key_id

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = (ROOT / "docs" / "inventory-attestation.md").read_text(encoding="utf-8")
VECTORS = json.loads(
    (ROOT / "tests" / "vectors" / "attestation" / "inventory-v1.json").read_text(encoding="utf-8")
)
MARKER = "PWNED"
HOSTILE = f"{MARKER}\x1b[31m\u202e::error::x##[error]y\u200b\n::warning::{MARKER}"
CONTROL = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u200b-\u200f\u202a-\u202e\u2066-\u2069]")


def keypair(directory: Path, name: str):
    key = Ed25519PrivateKey.generate()
    private, public = directory / f"{name}.pem", directory / f"{name}.pub"
    private.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    private.chmod(0o600)
    public.write_bytes(
        key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    return private, public, key


@pytest.fixture
def setup(tmp_path):
    keys, work = tmp_path / "keys", tmp_path / "work"
    keys.mkdir()
    work.mkdir()
    subject = work / "inventory.json"
    subject.write_text(AIBOM().to_json(), encoding="utf-8")
    return {"keys": keys, "work": work, "subject": subject, "a": keypair(keys, "a")}


def invoke(runner, *args):
    result = runner.invoke(main, [str(arg) for arg in args])
    # A refusal ends with a plain error, never a traceback.
    assert result.exception is None or isinstance(result.exception, SystemExit), result.output
    return result


def attest(runner, subject, out, *private, purpose="reviewed", extra=()):
    keys = [option for path in private for option in ("--key", path)]
    return invoke(runner, "attest", subject, *keys, "--purpose", purpose, "--out", out, *extra)


def verify(runner, subject, envelope, *public, purpose="reviewed", extra=()):
    keys = [option for path in public for option in ("--trusted-key", path)]
    return invoke(
        runner, "verify-attestation", subject, envelope, *keys, "--purpose", purpose, *extra
    )


def failed(result, reason, operation="verification"):
    assert result.exit_code == 1, result.output
    assert result.stdout == ""
    [line] = result.stderr.splitlines()
    assert line.startswith(f"Error: attestation {operation} failed: "), line
    assert line.endswith(f" ({reason})"), line
    return line


def pae(payload: bytes) -> bytes:
    return b"DSSEv1 28 application/vnd.in-toto+json %d %s" % (len(payload), payload)


def envelope_file(path: Path, payload: bytes, *keys, hint: str | None = "") -> Path:
    signatures = [
        {
            "keyid": key_id(key.public_key()) if hint == "" else hint,
            "sig": base64.b64encode(key.sign(pae(payload))).decode(),
        }
        for key in keys
    ]
    path.write_text(
        json.dumps(
            {
                "payloadType": "application/vnd.in-toto+json",
                "payload": base64.b64encode(payload).decode(),
                "signatures": signatures,
            }
        )
    )
    return path


def padding_bits(signature: str) -> str:
    """Another encoding of a 64-byte signature: a padding bit set in its last character."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    assert signature.endswith("==") and len(signature) == 88
    last = alphabet[alphabet.index(signature[-3]) ^ 1]
    changed = signature[:-3] + last + "=="
    assert base64.b64decode(changed) == base64.b64decode(signature)
    return changed


def inert(result):
    """Neither stream carries input text, terminal controls or CI log commands."""
    for stream in (result.stdout, result.stderr):
        assert MARKER not in stream
        assert "##[" not in stream
        assert CONTROL.search(stream) is None
        assert not any(line.lstrip().startswith("::") for line in stream.splitlines())


# Round trips


def test_native_inventory_round_trip(runner, setup):
    private, public, key = setup["a"]
    out = setup["work"] / "inventory.json.att"
    result = attest(runner, setup["subject"], out, private, extra=("--source-revision", "a" * 40))
    assert result.exit_code == 0, result.output
    [line] = result.stdout.splitlines()
    signed = json.loads(line)
    assert list(signed) == [
        "out",
        "subject_sha256",
        "subject_format",
        "content_digest",
        "purpose",
        "signers",
        "signed",
    ]
    assert signed["subject_format"] == "nexus-symbiote-aibom"
    assert signed["signers"] == [key_id(key.public_key())]
    assert signed["signed"] is True and signed["purpose"] == "reviewed"
    assert stat.S_IMODE(out.stat().st_mode) == 0o600
    assert set(json.loads(out.read_text())) == {"payloadType", "payload", "signatures"}

    text = verify(runner, setup["subject"], out, public)
    assert text.exit_code == 0, text.output
    lines = text.stdout.splitlines()
    assert lines[:6] == [
        (
            "Attestation verified: purpose reviewed, 1 trusted key. It does not establish "
            "that the file is accurate, complete or safe."
        ),
        f"Signer key ID: {key_id(key.public_key())}",
        f"Subject SHA-256: {signed['subject_sha256']}",
        "Match: bytes",
        "Subject format: nexus-symbiote-aibom 1.1.0",
        f"Content digest: {signed['content_digest']} (nexus-symbiote/inventory-content/v1)",
    ]
    assert re.fullmatch(r"Signed at \(signer's clock\): \d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", lines[6])
    assert lines[7:] == [f"Source revision claimed by the signer, not checked: {'a' * 40}"]
    document = json.loads(
        verify(runner, setup["subject"], out, public, extra=["--json-output"]).stdout
    )
    assert document == {
        "attestation_verified": True,
        "purpose": "reviewed",
        "signers": [key_id(key.public_key())],
        "match": "bytes",
        "subject_sha256": signed["subject_sha256"],
        "attested_sha256": signed["subject_sha256"],
        "subject_format": "nexus-symbiote-aibom",
        "spec_version": "1.1.0",
        "content_digest": signed["content_digest"],
        "content_profile": "nexus-symbiote/inventory-content/v1",
        "signed_at": document["signed_at"],
        "source_revision": "a" * 40,
    }


def test_other_file_round_trip(runner, setup):
    private, public, _ = setup["a"]
    export = setup["work"] / "agentbom.sarif"
    export.write_text('{"version": "2.1.0", "runs": []}\n')
    out = setup["work"] / "agentbom.sarif.att"
    result = attest(runner, export, out, private, purpose="generated")
    assert result.exit_code == 0, result.output
    signed = json.loads(result.stdout)
    assert signed["subject_format"] == "other" and "content_digest" not in signed
    checked = verify(runner, export, out, public, purpose="generated")
    assert checked.exit_code == 0, checked.output
    assert "Subject format: other (no content digest)" in checked.stdout.splitlines()
    failed(
        verify(runner, export, out, public, purpose="generated", extra=["--match", "content"]),
        "content-digest-unavailable",
    )


def test_content_match_across_two_scans_of_the_same_tree(runner, setup, tmp_path):
    private, public, _ = setup["a"]
    project = tmp_path / "project"
    project.mkdir()
    (project / ".mcp.json").write_text(
        json.dumps({"mcpServers": {"docs": {"command": "npx", "args": ["-y", "docs-mcp@1.2.3"]}}})
    )
    (project / "system_prompt.md").write_text("Answer from the documentation only.\n")
    first, second = setup["work"] / "first.json", setup["work"] / "second.json"
    assert invoke(runner, "scan", project, "-o", first, "--report-only").exit_code == 0
    # The second collection records its collection time; the first records none.
    pinned = runner.invoke(
        main,
        ["scan", str(project), "-o", str(second), "--report-only"],
        env={"SOURCE_DATE_EPOCH": "1767225600"},
    )
    assert pinned.exit_code == 0, pinned.output
    assert first.read_bytes() != second.read_bytes()
    out = setup["work"] / "first.json.att"
    assert attest(runner, first, out, private).exit_code == 0
    failed(verify(runner, second, out, public), "subject-mismatch")
    content = verify(runner, second, out, public, extra=["--match", "content", "--json-output"])
    assert content.exit_code == 0, content.output
    document = json.loads(content.stdout)
    assert document["match"] == "content"
    assert document["attested_sha256"] != document["subject_sha256"]
    (project / "system_prompt.md").write_text("Answer from anywhere.\n")
    third = setup["work"] / "third.json"
    assert invoke(runner, "scan", project, "-o", third, "--report-only").exit_code == 0
    failed(verify(runner, third, out, public, extra=["--match", "content"]), "subject-mismatch")


def nested(levels: int) -> bytes:
    """The vector's native inventory, its component properties nested to ``levels`` in all."""
    document = json.loads(VECTORS["attestations"][0]["subject_text"])
    chain: dict[str, object] = {}
    for _ in range(levels - 4):
        chain = {"a": chain}
    document["components"][0]["properties"] = chain
    return json.dumps(document).encode()


@pytest.mark.parametrize("levels", [MAX_NATIVE_DEPTH, MAX_NATIVE_DEPTH + 1])
def test_nesting_bound_decides_the_subject_format(runner, setup, levels):
    private, public, _ = setup["a"]
    subject = setup["work"] / "nested.json"
    subject.write_bytes(nested(levels))
    out = setup["work"] / "nested.json.att"
    result = attest(runner, subject, out, private)
    assert result.exit_code == 0, result.output
    native = levels <= MAX_NATIVE_DEPTH
    expected = "nexus-symbiote-aibom" if native else "other"
    assert json.loads(result.stdout)["subject_format"] == expected
    checked = verify(runner, subject, out, public, extra=["--json-output"])
    assert checked.exit_code == 0, checked.output
    assert json.loads(checked.stdout)["subject_format"] == expected
    content = verify(runner, subject, out, public, extra=["--match", "content"])
    if native:
        assert content.exit_code == 0, content.output
    else:
        failed(content, "content-digest-unavailable")


def test_threshold_two_of_three_with_repeated_keys(runner, setup):
    keys = setup["keys"]
    (a_private, a_public, _), (b_private, b_public, _) = setup["a"], keypair(keys, "b")
    _, c_public, _ = keypair(keys, "c")
    out = setup["work"] / "two.att"
    result = attest(runner, setup["subject"], out, a_private, b_private)
    assert result.exit_code == 0, result.output
    assert len(json.loads(result.stdout)["signers"]) == 2
    trusted = (a_public, b_public, c_public)
    passed = verify(runner, setup["subject"], out, *trusted, extra=["--threshold", "2"])
    assert passed.exit_code == 0, passed.output
    assert passed.stdout.startswith("Attestation verified: purpose reviewed, 2 trusted keys.")
    failed(
        verify(runner, setup["subject"], out, *trusted, extra=["--threshold", "3"]),
        "signers-insufficient",
    )


def test_signing_is_deterministic_for_a_fixed_time_and_any_key_order(runner, setup, monkeypatch):
    class Clock(datetime):
        @classmethod
        def now(cls, tz=None):
            return datetime(2026, 11, 12, 10, 0, 0, 987654, tzinfo=UTC)

    monkeypatch.setattr(attestation_cli, "datetime", Clock)
    a_private = setup["a"][0]
    b_private = keypair(setup["keys"], "b")[0]
    first, second = setup["work"] / "first.att", setup["work"] / "second.att"
    assert attest(runner, setup["subject"], first, a_private, b_private).exit_code == 0
    assert attest(runner, setup["subject"], second, b_private, a_private).exit_code == 0
    assert first.read_bytes() == second.read_bytes()
    payload = json.loads(base64.b64decode(json.loads(first.read_text())["payload"]))
    assert payload["predicate"]["signed_at"] == "2026-11-12T10:00:00Z"
    once = verify(runner, setup["subject"], first, setup["a"][1], extra=["--json-output"])
    again = verify(runner, setup["subject"], first, setup["a"][1], extra=["--json-output"])
    assert once.exit_code == 0 and once.stdout == again.stdout


# Refusals with exit status 1


def test_verification_refusals(runner, setup):
    private, public, _ = setup["a"]
    work = setup["work"]
    out = work / "inventory.json.att"
    assert attest(runner, setup["subject"], out, private).exit_code == 0
    flipped = work / "flipped.json"
    raw = bytearray(setup["subject"].read_bytes())
    raw[len(raw) // 2] ^= 1
    flipped.write_bytes(bytes(raw))
    failed(verify(runner, flipped, out, public), "subject-mismatch")
    _, other_public, _ = keypair(setup["keys"], "other")
    failed(verify(runner, setup["subject"], out, other_public), "signers-insufficient")
    failed(verify(runner, setup["subject"], out, public, purpose="generated"), "purpose-mismatch")
    failed(
        verify(runner, setup["subject"], out, public, other_public, extra=["--threshold", "2"]),
        "signers-insufficient",
    )
    trust = work / "trust.json"
    now = datetime.now(UTC)
    trust.write_text(
        TrustStatus(
            tenant="acme", serial=1, not_before=now, not_after=now + timedelta(minutes=5)
        ).model_dump_json()
    )
    contract = work / "trust.env"
    assert (
        invoke(
            runner, "runtime", "sign", trust, "--kind", "trust", "--key", private, "--out", contract
        ).exit_code
        == 0
    )
    failed(verify(runner, trust, contract, public), "statement-purpose-mismatch")
    runtime = invoke(runner, "runtime", "verify", out, "--kind", "trust", "--public-key", public)
    assert runtime.exit_code == 1
    assert runtime.stderr.rstrip().endswith("(statement-purpose-mismatch)")


def dated(setup, signed_at: datetime) -> Path:
    data = setup["subject"].read_bytes()
    statement = build_statement(
        data, name="inventory.json", purpose="reviewed", signed_at=signed_at
    )
    path = setup["work"] / f"dated-{signed_at:%Y%m%d%H%M%S}.att"
    path.write_text(sign_statement(statement, [setup["a"][2]]).model_dump_json(by_alias=True))
    return path


def test_age_and_future_dates_are_refused(runner, setup):
    public = setup["a"][1]
    now = datetime.now(UTC).replace(microsecond=0)
    old = dated(setup, now - timedelta(days=10))
    assert (
        verify(runner, setup["subject"], old, public, extra=["--max-age-days", "11"]).exit_code == 0
    )
    failed(
        verify(runner, setup["subject"], old, public, extra=["--max-age-days", "9"]),
        "attestation-expired",
    )
    future = dated(setup, now + timedelta(hours=1))
    failed(verify(runner, setup["subject"], future, public), "attestation-not-yet-valid")


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        (lambda w: w.update(payloadType="application/json"), "envelope-invalid"),
        (lambda w: w.update(signatures2=[]), "envelope-invalid"),
        (lambda w: w["signatures"][0].update(keyid=w["signatures"][0]["keyid"].upper()), None),
        (
            lambda w: w["signatures"][0].update(
                sig=base64.urlsafe_b64encode(base64.b64decode(w["signatures"][0]["sig"])).decode()
            ),
            None,
        ),
        (
            lambda w: w["signatures"][0].update(sig=w["signatures"][0]["sig"][:-2]),
            "envelope-invalid",
        ),
        (
            lambda w: w["signatures"][0].update(sig=padding_bits(w["signatures"][0]["sig"])),
            "envelope-invalid",
        ),
        (lambda w: w.update(signatures=[]), "signers-insufficient"),
    ],
    ids=[
        "payload type",
        "extra member",
        "unknown key id hint",
        "url-safe",
        "unpadded",
        "padding bits",
        "unsigned",
    ],
)
def test_envelope_encodings(runner, setup, change, reason):
    private, public, _ = setup["a"]
    out = setup["work"] / "inventory.json.att"
    assert attest(runner, setup["subject"], out, private).exit_code == 0
    wire = json.loads(out.read_text())
    change(wire)
    changed = setup["work"] / "changed.att"
    changed.write_text(json.dumps(wire))
    result = verify(runner, setup["subject"], changed, public)
    if reason is None:
        assert result.exit_code == 0, result.output
    else:
        failed(result, reason)


def test_inputs_must_be_bounded_regular_files(runner, setup):
    private, public, _ = setup["a"]
    work = setup["work"]
    out = work / "inventory.json.att"
    assert attest(runner, setup["subject"], out, private).exit_code == 0
    (work / "link.att").symlink_to(out)
    failed(verify(runner, setup["subject"], work / "link.att", public), "input-unreadable")
    os.mkfifo(work / "fifo.att")
    failed(verify(runner, setup["subject"], work / "fifo.att", public), "input-unreadable")
    os.mkfifo(work / "fifo.json")
    failed(
        attest(runner, work / "fifo.json", work / "f.att", private), "input-unreadable", "signing"
    )
    (work / "link.json").symlink_to(setup["subject"])
    failed(verify(runner, work / "link.json", out, public), "input-unreadable")
    big = work / "big.att"
    big.write_bytes(b" " * (2 * 1024 * 1024 + 1))
    line = failed(verify(runner, setup["subject"], big, public), "input-too-large")
    assert "envelope file" in line
    huge = work / "huge.json"
    with huge.open("wb") as stream:
        stream.truncate(64 * 1024 * 1024 + 1)
    line = failed(attest(runner, huge, work / "h.att", private), "input-too-large", "signing")
    assert "subject file" in line
    failed(verify(runner, huge, out, public), "input-too-large")
    (work / "link.pub").symlink_to(public)
    line = failed(verify(runner, setup["subject"], out, work / "link.pub"), "input-unreadable")
    assert "trusted key file" in line
    (work / "big.pub").write_bytes(b"x" * (64 * 1024 + 1))
    failed(verify(runner, setup["subject"], out, work / "big.pub"), "input-too-large")
    (work / "envelope.att").write_text("[]")
    failed(verify(runner, setup["subject"], work / "envelope.att", public), "envelope-invalid")
    assert not (work / "f.att").exists() and not (work / "h.att").exists()


def test_signing_keys_are_checked(runner, setup, tmp_path):
    private, public, _ = setup["a"]
    work = setup["work"]
    private.chmod(0o640)
    line = failed(
        attest(runner, setup["subject"], work / "x.att", private), "key-invalid", "signing"
    )
    assert "must not be accessible to group or others" in line
    private.chmod(0o600)
    ecdsa = generate_private_key(SECP256R1())
    other = setup["keys"] / "ecdsa.pem"
    other.write_bytes(
        ecdsa.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    other.chmod(0o600)
    failed(attest(runner, setup["subject"], work / "x.att", other), "key-invalid", "signing")
    other_public = setup["keys"] / "ecdsa.pub"
    other_public.write_bytes(
        ecdsa.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    assert attest(runner, setup["subject"], work / "x.att", private).exit_code == 0
    failed(verify(runner, setup["subject"], work / "x.att", other_public), "key-invalid")
    passphrase = tmp_path / "passphrase"
    passphrase.write_text("correct horse battery staple\n")
    passphrase.chmod(0o600)
    encrypted, encrypted_public = setup["keys"] / "enc.pem", setup["keys"] / "enc.pub"
    made = invoke(
        runner,
        "runtime",
        "keygen",
        "--private-key",
        encrypted,
        "--public-key",
        encrypted_public,
        "--passphrase-file",
        passphrase,
    )
    assert made.exit_code == 0, made.output
    line = failed(
        attest(runner, setup["subject"], work / "e.att", encrypted), "key-invalid", "signing"
    )
    assert "--passphrase-file" in line
    extra = ("--passphrase-file", passphrase)
    assert attest(runner, setup["subject"], work / "e.att", encrypted, extra=extra).exit_code == 0
    assert verify(runner, setup["subject"], work / "e.att", encrypted_public).exit_code == 0
    passphrase.chmod(0o644)
    failed(
        attest(runner, setup["subject"], work / "e2.att", encrypted, extra=extra),
        "key-invalid",
        "signing",
    )


def test_a_root_run_attest_refuses_a_key_another_user_owns(runner, setup, monkeypatch):
    private, _, _ = setup["a"]
    # Run as root with a 0600 key that another uid owns, such as a host-mounted key.
    if os.geteuid() == 0:
        os.chown(private, 4242, 4242)
    monkeypatch.setattr(os, "geteuid", lambda: 0)
    out = setup["work"] / "x.att"
    line = failed(attest(runner, setup["subject"], out, private), "key-invalid", "signing")
    assert "private key file must be owned by the user running the command" in line
    assert not out.exists()


def test_more_signing_keys_than_an_envelope_holds_are_refused(runner, setup):
    keys = [keypair(setup["keys"], f"k{index}")[0] for index in range(33)]
    out = setup["work"] / "many.att"
    failed(attest(runner, setup["subject"], out, *keys), "configuration-invalid", "signing")
    assert not out.exists()


# Usage errors with exit status 2


def usage(result, text):
    assert result.exit_code == 2, result.output
    assert text in result.stderr
    assert result.stdout == ""


def test_option_errors_are_usage_errors(runner, setup):
    private, public, _ = setup["a"]
    work, subject = setup["work"], setup["subject"]
    out = work / "inventory.json.att"
    usage(
        attest(runner, subject, out, private, extra=("--source-revision", "HEAD")),
        "--source-revision",
    )
    usage(attest(runner, subject, out, private, extra=("--source-revision", "A" * 40)), "40 or 64")
    usage(
        attest(runner, subject, out, private, private), "each --key must be a different signing key"
    )
    usage(attest(runner, subject, out, private, purpose="approved"), "--purpose")
    usage(attest(runner, subject, subject, private), "must not overwrite the source")
    assert not out.exists()
    assert attest(runner, subject, out, private).exit_code == 0
    copy = setup["keys"] / "copy.pub"
    shutil.copyfile(public, copy)
    usage(
        verify(runner, subject, out, public, copy, extra=["--threshold", "2"]),
        "at most the number of distinct trusted keys (1)",
    )
    for option in (
        ["--threshold", "0"],
        ["--threshold", "33"],
        ["--max-age-days", "0"],
        ["--match", "digest"],
    ):
        usage(verify(runner, subject, out, public, extra=option), option[0])
    usage(verify(runner, work / "missing.json", out, public), "does not exist")


def test_output_must_be_a_new_file(runner, setup):
    private, _, _ = setup["a"]
    work, subject = setup["work"], setup["subject"]
    existing = work / "existing.att"
    existing.write_text("keep")
    result = attest(runner, subject, existing, private)
    assert result.exit_code == 1 and "File exists" in result.stderr
    assert existing.read_text() == "keep"
    (work / "linked").symlink_to(work)
    result = attest(runner, subject, work / "linked" / "new.att", private)
    assert result.exit_code == 1
    assert not (work / "new.att").exists()
    before = subject.read_bytes()
    hard = work / "hard.json"
    os.link(subject, hard)
    usage(attest(runner, subject, hard, private), "must not overwrite the source")
    assert subject.read_bytes() == before


def repository(path: Path, *, git_file: bool = False) -> Path:
    path.mkdir(parents=True)
    if git_file:
        (path / ".git").write_text("gitdir: elsewhere\n")
    else:
        (path / ".git").mkdir()
    return path


def test_trusted_key_inside_a_working_tree_is_a_usage_error(runner, setup, tmp_path, monkeypatch):
    private, public, _ = setup["a"]
    rule = "must lie outside every git working tree"
    repo = repository(tmp_path / "repo")
    subject = repo / "inventory.json"
    shutil.copyfile(setup["subject"], subject)
    envelope = repo / "inventory.json.att"
    assert attest(runner, subject, envelope, private).exit_code == 0
    inside = repo / "keys" / "trusted.pub"
    inside.parent.mkdir()
    shutil.copyfile(public, inside)
    usage(verify(runner, subject, envelope, inside), rule)
    usage(verify(runner, subject, envelope, public, inside), rule)
    # The envelope alone in the tree is enough.
    outside_subject = setup["work"] / "inventory.json"
    shutil.copyfile(subject, outside_subject)
    usage(verify(runner, outside_subject, envelope, inside), rule)
    # Another name for the tree: a symbolic link to its directory.
    (tmp_path / "alias").symlink_to(repo / "keys")
    usage(verify(runner, subject, envelope, tmp_path / "alias" / "trusted.pub"), rule)
    # A tree whose .git is a file, as in a worktree or submodule, and nested trees.
    outer = repository(tmp_path / "outer", git_file=True)
    inner = repository(outer / "inner")
    shutil.copyfile(subject, inner / "inventory.json")
    shutil.copyfile(envelope, inner / "inventory.json.att")
    shutil.copyfile(public, outer / "trusted.pub")
    usage(
        verify(
            runner, inner / "inventory.json", inner / "inventory.json.att", outer / "trusted.pub"
        ),
        rule,
    )
    # The current directory's tree, although SUBJECT and ENVELOPE are outside it.
    shutil.copyfile(envelope, setup["work"] / "inventory.json.att")
    monkeypatch.chdir(repo)
    usage(verify(runner, outside_subject, setup["work"] / "inventory.json.att", inside), rule)
    assert (
        verify(runner, outside_subject, setup["work"] / "inventory.json.att", public).exit_code == 0
    )
    monkeypatch.chdir(tmp_path)
    # A hard link to a key gives it a second name that could lie anywhere.
    linked = setup["keys"] / "linked.pub"
    os.link(public, linked)
    usage(verify(runner, subject, envelope, linked), "must not have other hard links")
    os.unlink(linked)
    passed = verify(runner, subject, envelope, public)
    assert passed.exit_code == 0, passed.output
    help_text = invoke(runner, "verify-attestation", "--help").stdout
    assert "does not authenticate the key" in " ".join(help_text.split())


def test_trusted_key_check_compares_directories_by_identity(setup, tmp_path, monkeypatch):
    repo = repository(tmp_path / "repo")
    key = repo / "trusted.pub"
    shutil.copyfile(setup["a"][1], key)
    alias = tmp_path / "elsewhere"
    alias.symlink_to(repo)
    check = attestation_cli._check_trust_anchors
    # A tree found under a name the path text misses, as a case variant or a bind mount of
    # the tree is.
    monkeypatch.setattr(runtime_cli, "_working_trees", lambda directories: [alias])
    assert not key.resolve().is_relative_to(alias)
    with pytest.raises(click.UsageError, match="must lie outside every git working tree"):
        check((key,), (setup["subject"],))
    monkeypatch.setattr(runtime_cli, "_working_trees", lambda directories: [setup["work"]])
    check((key,), (setup["subject"],))
    gone = tmp_path / "gone"
    monkeypatch.setattr(runtime_cli, "_working_trees", lambda directories: [gone])
    with pytest.raises(click.UsageError, match="cannot be inspected"):
        check((key,), (setup["subject"],))


def test_trusted_key_check_finds_a_mount_of_the_tree_but_not_of_a_directory_inside_it(
    setup, tmp_path, monkeypatch
):
    repo = repository(tmp_path / "repo")
    (repo / "keys").mkdir()
    subject = repo / "inventory.json"
    shutil.copyfile(setup["subject"], subject)
    mounted = tmp_path / "mounted"
    mounted.mkdir()
    key = mounted / "trusted.pub"
    shutil.copyfile(setup["a"][1], key)
    monkeypatch.chdir(tmp_path)
    identity = runtime_cli._identity

    def mount(source: Path) -> None:
        """Make ``mounted`` report the identity of ``source``, as a bind mount does."""
        monkeypatch.setattr(
            runtime_cli,
            "_identity",
            lambda path: identity(source if path == mounted.resolve() else path),
        )

    check = attestation_cli._check_trust_anchors
    # The documented limit: a mount of a directory inside the tree is another location.
    mount(repo / "keys")
    check((key,), (subject,))
    mount(repo)
    with pytest.raises(click.UsageError, match="must lie outside every git working tree"):
        check((key,), (subject,))


def test_documented_trusted_key_rule_states_what_it_does_not_detect():
    reference = (ROOT / "docs" / "cli-reference.md").read_text(encoding="utf-8")
    section = reference.split("### `verify-attestation`", 1)[1].split("\n### ", 1)[0]
    for text in (DOCUMENT, section):
        flat = " ".join(text.split())
        assert "another name for the" in flat and "directory itself" in flat
        assert "mount of a directory or file inside" in flat
        assert "not detected" in flat


def test_cli_reference_shared_rules_name_the_attestation_commands():
    reference = (ROOT / "docs" / "cli-reference.md").read_text(encoding="utf-8")
    output = reference.split("## Output and CI logs", 1)[1].split("\n## ", 1)[0]
    assert "`attest`" in output and "`verify-attestation --json-output`" in output
    [usage_row] = [line for line in reference.splitlines() if line.startswith("| `2` |")]
    assert "`verify-attestation` `--trusted-key`" in usage_row


# Output safety


def test_output_never_contains_subject_or_envelope_content(runner, setup):
    private, public, key = setup["a"]
    work = setup["work"]
    hostile_name = work / HOSTILE
    document = json.loads(AIBOM().to_json())
    document["metadata"]["authors"] = [HOSTILE]
    hostile_name.write_text(json.dumps(document))
    out = work / "hostile.att"
    result = attest(runner, hostile_name, out, private)
    assert result.exit_code == 0, result.output
    inert(result)
    statement = json.loads(base64.b64decode(json.loads(out.read_text())["payload"]))
    assert MARKER in statement["subject"][0]["name"]
    assert CONTROL.search(statement["subject"][0]["name"]) is None
    assert "##[" not in statement["subject"][0]["name"]
    for extra in ([], ["--json-output"], ["--match", "content"]):
        checked = verify(runner, hostile_name, out, public, extra=extra)
        assert checked.exit_code == 0, checked.output
        inert(checked)
    hinted = envelope_file(
        work / "hinted.att",
        base64.b64decode(json.loads(out.read_text())["payload"]),
        key,
        hint=HOSTILE[:200],
    )
    checked = verify(runner, hostile_name, hinted, public)
    assert checked.exit_code == 0, checked.output
    inert(checked)
    base = build_statement(
        hostile_name.read_bytes(),
        name="inventory.json",
        purpose="reviewed",
        signed_at=datetime.now(UTC).replace(microsecond=0),
    )
    variants = {
        "statement-invalid": {
            **base,
            "subject": [{"name": HOSTILE, "digest": base["subject"][0]["digest"]}],
        },
        "statement-purpose-mismatch": {**base, "predicateType": HOSTILE},
        "predicate-invalid": {**base, "predicate": {**base["predicate"], HOSTILE: HOSTILE}},
        "predicate-not-canonical": {
            **base,
            "predicate": {**base["predicate"], "source_revision": None},
        },
    }
    for reason, value in variants.items():
        forged = envelope_file(work / f"{reason}.att", rfc8785.dumps(value), key)
        result = verify(runner, hostile_name, forged, public)
        failed(result, reason)
        inert(result)
    revision = {**base, "predicate": {**base["predicate"], "source_revision": HOSTILE}}
    result = verify(
        runner, hostile_name, envelope_file(work / "rev.att", rfc8785.dumps(revision), key), public
    )
    failed(result, "predicate-invalid")
    inert(result)
    garbage = work / "garbage.att"
    garbage.write_text(json.dumps({HOSTILE: HOSTILE}))
    result = verify(runner, hostile_name, garbage, public)
    failed(result, "envelope-invalid")
    inert(result)


def test_subject_name_that_is_not_utf8_is_replaced(runner, setup):
    private, public, _ = setup["a"]
    work = setup["work"]
    name = os.fsdecode(b"inventory-\xff.json")
    subject = work / name
    try:
        shutil.copyfile(setup["subject"], subject)
    except OSError:
        pytest.skip("file system rejects names that are not UTF-8")
    out = work / "bytes.att"
    result = attest(runner, subject, out, private)
    assert result.exit_code == 0, result.output
    statement = json.loads(base64.b64decode(json.loads(out.read_text())["payload"]))
    assert statement["subject"][0]["name"] == "inventory-\ufffd.json"
    assert verify(runner, subject, out, public).exit_code == 0


# Documentation


def test_documented_check_without_this_tool_accepts_the_vector(tmp_path):
    section = DOCUMENT.split("### Checking an attestation without this tool", 1)[1]
    [code] = re.findall(r"^```python\n(.*?)^```$", section, re.M | re.S)
    namespace: dict[str, object] = {}
    exec(compile(code, "inventory-attestation.md", "exec"), namespace)  # noqa: S102
    check = namespace["check"]
    public = tmp_path / "test.pub"
    public.write_text(VECTORS["key"]["public_key_pem"])
    for vector in VECTORS["attestations"]:
        subject, envelope = tmp_path / vector["subject_name"], tmp_path / "envelope.json"
        subject.write_text(vector["subject_text"], encoding="utf-8")
        envelope.write_text(json.dumps(vector["envelope"]))
        assert (
            check(envelope, subject, public, vector["purpose"]) == vector["statement"]["predicate"]
        )
        with pytest.raises(ValueError, match="not an inventory attestation for this purpose"):
            check(
                envelope,
                subject,
                public,
                "reviewed" if vector["purpose"] == "generated" else "generated",
            )
        subject.write_text(vector["subject_text"] + " ", encoding="utf-8")
        with pytest.raises(ValueError, match="not the attested file"):
            check(envelope, subject, public, vector["purpose"])


def test_documented_output_matches_the_commands(runner, setup):
    private, public, _ = setup["a"]
    out = setup["work"] / "inventory.json.att"
    signed = attest(runner, setup["subject"], out, private)
    documented = re.search(r'^\{"out": .*\}$', DOCUMENT, re.M)
    assert documented is not None
    assert list(json.loads(documented.group(0))) == list(json.loads(signed.stdout))
    first = verify(runner, setup["subject"], out, public).stdout.splitlines()[0]
    assert first in DOCUMENT.splitlines()
    tampered = setup["work"] / "tampered.json"
    tampered.write_bytes(
        setup["subject"].read_bytes().replace(b'"version": 1,', b'"version": 2,', 1)
    )
    line = failed(verify(runner, tampered, out, public), "subject-mismatch")
    assert line in DOCUMENT.splitlines()
    wrong = verify(runner, setup["subject"], out, public, purpose="generated")
    assert "attestation was signed for another purpose" in failed(wrong, "purpose-mismatch")
    for key in ("subject_sha256", "attested_sha256", "content_profile", "source_revision"):
        assert f"`{key}`" in DOCUMENT


def test_documented_reviewer_steps_run_on_a_first_and_a_later_review(
    runner, setup, tmp_path, monkeypatch
):
    section = DOCUMENT.split("## Gate a pull request on an attested baseline", 1)[1]
    block = re.search(r"^```bash\n(.*?)^```$", section, re.M | re.S)
    assert block, "the guide no longer shows the reviewer's commands"
    private, public, _ = setup["a"]
    revision = "0123456789abcdef0123456789abcdef01234567"
    text = block.group(1).replace("\\\n", " ").replace('"$(git rev-parse HEAD)"', revision)
    text = text.replace("~/keys/reviewer.pem", shlex.quote(str(private)))
    commands = [shlex.split(line) for line in text.splitlines() if line.strip()]
    repo = tmp_path / "repo"
    shutil.copytree(ROOT / "examples" / "demo-agent", repo)
    monkeypatch.chdir(repo)
    for _ in range(2):
        for command in commands:
            if command[:2] == ["mkdir", "-p"]:
                Path(command[2]).mkdir(parents=True, exist_ok=True)
            elif command[:2] == ["rm", "-f"]:
                Path(command[2]).unlink(missing_ok=True)
            else:
                assert command[0] == "nexus-symbiote", command
                result = invoke(runner, *command[1:])
                assert result.exit_code == 0, result.output
        checked = verify(
            runner,
            ".nexus-symbiote/reviewed.json",
            ".nexus-symbiote/reviewed.json.att",
            public,
            extra=["--json-output"],
        )
        assert checked.exit_code == 0, checked.output
        assert json.loads(checked.stdout)["source_revision"] == revision
